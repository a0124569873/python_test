/*
 * Copyright 2007-2013 6WIND S.A.
 */

#if defined(__LinuxKernelVNB__) /* __VnbLinuxKernel__ */

#include <linux/version.h>
#include <linux/module.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif /* CONFIG_KMOD */
#include <linux/ctype.h> /* for isdigit */
#include <linux/jhash.h>
#include <netgraph/vnblinux.h>

#elif defined(__FastPath__) /* __FastPath__ */

#include "fp-netgraph.h"
#include "net/fp-ethernet.h"
#include "netinet/fp-in.h"
#include "netinet/fp-ip.h"
#include "fp-main-process.h"

#endif /* __LinuxKernelVNB__ */

#include <netgraph/vnb_in.h>
#include <netgraph/vnb_ip.h>
#include <netgraph/vnb_ip6.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_ethgrp.h>

#ifndef FP_STANDALONE
#define LACP_NOTIF
#endif

#ifdef LACP_NOTIF
#include <netgraph/ieee8023_slowprotocols.h>
#include <netgraph/ieee8023_tlv.h>
#include <netgraph/ieee8023ad_lacp.h>
#include <netgraph/ieee8023ad_marker.h>
#endif

#undef DEBUG_ETH_GRP

#ifndef TRACE
#ifdef DEBUG_ETH_GRP
#define TRACE(fmt, args...) do {\
	log(LOG_INFO, "ng_ethgrp(%d):" fmt "\n", __LINE__, ## args); \
} while (0)
#else
#define TRACE(x...) do {} while(0)
#endif
#endif

#define GOLDEN_RATIO	0x9e3779b9

/* Store each hook's link number in the private field */
typedef union {
	void *s;
	uint16_t linknum;
} hookpriv_p;
#define LINK_NUM(hook)          ((hookpriv_p)(hook)->private).linknum

/* Per-link private data */
struct ng_ethgrp_link {
	hook_p                      hook;           /* netgraph hook */
	int                         linkmode;       /* 0-inactive 1-active */
	u_int32_t                   prio;           /* the lowest, the best */
};

/* Per-node private data */
struct ng_ethgrp_private {
	node_p                   node;          /* netgraph node */
	struct ng_ethgrp_config conf;          /* node configuration */
	struct ng_ethgrp_link   *ethgrp_links[NG_ETH_GRP_MAX_LINKS];
	hook_p                   ethgrp_upper;
	hook_p                   lacp_hook;
	unsigned int             numLinks;       /* num of connected links */
	unsigned int             NBActive;       /* NBActive <= numLinks */
	unsigned int             NBActive_mask;  /* for modulus replacement */
	struct ng_ethgrp_link    ActiveHookTable[NG_ETH_GRP_MAX_LINKS];
	int                      sending_algo;
	unsigned int             last_used;
	unsigned char            node_addr[VNB_ETHER_ADDR_LEN];
	int ActiveLink[NG_ETH_GRP_MAX_LINKS];
};
typedef struct ng_ethgrp_private *priv_p;

struct vlan_header {
	uint8_t	dhost[VNB_ETHER_ADDR_LEN];  /* Destination MAC address */
	uint8_t	shost[VNB_ETHER_ADDR_LEN];  /* Source MAC address */
	uint16_t encap_proto;     /* = htons(ETHERTYPE_VLAN) */
	uint16_t tag;             /* 1 .. 4094 */
	uint16_t proto;           /* = htons(ETHERTYPE_xxx) */
};

struct ng_ethgrp_nl_nodepriv {
	struct ng_ethgrp_config config;
	char node_addr[VNB_ETHER_ADDR_LEN];
	uint32_t sending_algo;
	int ActiveLink[NG_ETH_GRP_MAX_LINKS];	/* store the link id in the order as in ActiveHookTable */
} __attribute__ ((packed));

struct ng_ethgrp_nl_hookpriv {
	uint32_t id;
	uint32_t mode;
	uint32_t priority;
} __attribute__ ((packed));

#define HOOK_MODE(priv, linknum) \
(priv->ethgrp_links[linknum]->linkmode)

static const struct ng_parse_struct_field ng_ethgrp_config_type_fields[]
	= NG_ETH_GRP_CONFIG_TYPE_INFO;
static const struct ng_parse_type ng_ethgrp_config_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_ethgrp_config_type_fields
};

static const struct ng_parse_struct_field ng_ethgrp_set_hook_mode_type_fields[]
	= NG_ETH_GRP_SET_HOOK_MODE_INFO;
static const struct ng_parse_type ng_ethgrp_set_hook_mode_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_ethgrp_set_hook_mode_type_fields
};

static const struct ng_parse_struct_field ng_ethgrp_get_hook_type_fields[]
	= NG_ETH_GRP_GET_HOOK_INFO;
static const struct ng_parse_type ng_ethgrp_get_hook_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_ethgrp_get_hook_type_fields
};

static const struct ng_parse_struct_field ng_ethgrp_get_hook_prio_type_fields[]
	= NG_ETH_GRP_GET_HOOK_PRIO_INFO;
static const struct ng_parse_type ng_ethgrp_set_hook_prio_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_ethgrp_get_hook_prio_type_fields
};

/* Parse type for an Ethernet address */
extern const struct ng_parse_type ng_ether_enaddr_type;

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_ethgrp_cmdlist[] = {
	{
	  NGM_ETH_GRP_COOKIE,
	  NGM_ETH_GRP_SET_CONFIG,
	  "setconfig",
	  &ng_ethgrp_config_type,
	  NULL
	},
	{
	  NGM_ETH_GRP_COOKIE,
	  NGM_ETH_GRP_GET_CONFIG,
	  "getconfig",
	  NULL,
	  &ng_ethgrp_config_type
	},
	{
	  NGM_ETH_GRP_COOKIE,
	  NGM_ETH_GRP_SET_HOOK_MODE,
	  "sethookmode",
	  &ng_ethgrp_set_hook_mode_type,
	  NULL
	},
	{
	  NGM_ETH_GRP_COOKIE,
	  NGM_ETH_GRP_GET_HOOK_MODE,
	  "gethookmode",
	  &ng_ethgrp_get_hook_type,
	  &ng_parse_string_type
	},
	{
	  NGM_ETH_GRP_COOKIE,
	  NGM_ETH_GRP_SET_ALGO,
	  "setalgo",
	  &ng_parse_string_type,
	  NULL
	},
	{
	  NGM_ETH_GRP_COOKIE,
	  NGM_ETH_GRP_GET_ALGO,
	  "getalgo",
	  NULL,
	  &ng_parse_string_type
	},
	{
	  NGM_ETH_GRP_COOKIE,
	  NGM_ETH_GRP_SET_HOOK_PRIO,
	  "sethookprio",
	  &ng_ethgrp_set_hook_prio_type,
	  NULL
	},
	{
	  NGM_ETH_GRP_COOKIE,
	  NGM_ETH_GRP_GET_HOOK_PRIO,
	  "gethookprio",
	  &ng_ethgrp_get_hook_type,
	  &ng_parse_uint32_type
	},
	{
	  NGM_ETH_GRP_COOKIE,
	  NGM_ETH_GRP_GET_ENADDR,
	  "getenaddr",
	  NULL,
	  &ng_ether_enaddr_type
	},
	{
	  NGM_ETH_GRP_COOKIE,
	  NGM_ETH_GRP_SET_ENADDR,
	  "setenaddr",
	  &ng_ether_enaddr_type,
	  NULL
	},
	{ 0, 0, NULL, NULL, NULL }
};

/* Netgraph node methods */
static ng_constructor_t ng_ethgrp_constructor;
static ng_rcvmsg_t      ng_ethgrp_rcvmsg;
static ng_shutdown_t    ng_ethgrp_rmnode;
static ng_newhook_t     ng_ethgrp_newhook;
static ng_disconnect_t  ng_ethgrp_disconnect;
#ifndef __FastPath__
static ng_dumpnode_t    ng_ethgrp_dumpnode;
static ng_dumphook_t    ng_ethgrp_dumphook;
#else
static ng_restorenode_t ng_ethgrp_restorenode;
static ng_restorehook_t ng_ethgrp_restorehook;
#endif

static int ng_ethgrp_xmit_data(hook_p, struct mbuf *, meta_p);
static int ng_ethgrp_recv_lower(hook_p hook, struct mbuf *m, meta_p meta);
static int update_ActiveHookTable(priv_p, int, int);
static void remove_active_hook(priv_p, int);
static struct ng_ethgrp_link* activetag_getbylinkid(priv_p priv, int linkid,
						    unsigned int *tableid);
static void get_best_prio (priv_p priv);

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_ethgrp_typestruct) = {
	.version =      NG_VERSION,
	.name =         NG_ETH_GRP_NODE_TYPE,
	.mod_event =    NULL,
	.constructor =  ng_ethgrp_constructor,
	.rcvmsg =       ng_ethgrp_rcvmsg,
	.shutdown =     ng_ethgrp_rmnode,
	.newhook =      ng_ethgrp_newhook,
	.findhook =     NULL,
	.connect =      NULL,
	.afterconnect = NULL,
	.rcvdata =      NULL,			/* Only specific receive data functions */
	.rcvdataq =     NULL,			/* Only specific receive data functions */
	.disconnect =   ng_ethgrp_disconnect,
	.rcvexception =  NULL,			/* exceptions come here */
#ifndef __FastPath__
	.dumpnode =     ng_ethgrp_dumpnode,
	.restorenode =  NULL,
	.dumphook =     ng_ethgrp_dumphook,
	.restorehook =  NULL,
#else
	.dumpnode =     NULL,
	.restorenode =  ng_ethgrp_restorenode,
	.dumphook =     NULL,
	.restorehook =  ng_ethgrp_restorehook,
#endif
	.cmdlist =      ng_ethgrp_cmdlist,
};
NETGRAPH_INIT(ethgrp, &ng_ethgrp_typestruct);
NETGRAPH_EXIT(ethgrp, &ng_ethgrp_typestruct);

static inline uint32_t get_link(uint32_t links_num, uint32_t links_mask,
	uint32_t a, uint32_t b, uint32_t c)
{
#if defined(__FastPath__)
	fp_jhash_mix(a, b, c);
#else
	__jhash_mix(a, b, c);
#endif

	return (((uint64_t)c * links_num) >> 32);
}

/* Compute the binary mask required by the above function. */
static inline uint32_t get_link_mask(uint32_t links_num)
{
	uint32_t i;

	for (i = 0; (i < links_num); i |= 1)
		i <<= 1;
	/* optimization: right-shift bits if links_num is a power of two */
	if (links_num == ((i >> 1) + 1))
		i >>= 1;
	return i;
}

/******************************************************************
		    NETGRAPH NODE METHODS
******************************************************************/

/*
 * Node constructor
 */

static int
ng_ethgrp_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int error;

	/* Call superclass constructor that mallocs *nodep */
	if ((error = ng_make_node_common_and_priv(&ng_ethgrp_typestruct, nodep,
						  &priv, sizeof(*priv), nodeid))) {
		return (error);
	}
	bzero(priv, sizeof(*priv));

	priv->conf.debugLevel = 1;
	priv->sending_algo = NG_ETH_GRP_ALGO_ROUND_ROBIN;

	NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->node = *nodep;

	/* Done */
	return (0);
}

/*
 * Method for attaching a new hook
 */
static  int
ng_ethgrp_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	/* Check for a link hook */
	if (strncmp(name, NG_ETH_GRP_HOOK_LINK_PREFIX,
	    strlen(NG_ETH_GRP_HOOK_LINK_PREFIX)) == 0) {
		const char *cp;
		char *eptr;
		u_long linkNum;
		hookpriv_p hpriv;

		cp = name + strlen(NG_ETH_GRP_HOOK_LINK_PREFIX);
		if (!isdigit(*cp) || (cp[0] == '0' && cp[1] != '\0'))
			return (EINVAL);
		linkNum = strtoul(cp, &eptr, 10);
		if (*eptr != '\0' || linkNum >= NG_ETH_GRP_MAX_LINKS)
			return (EINVAL);

		if (priv->ethgrp_links[linkNum] != NULL)
			return (EISCONN);
		priv->ethgrp_links[linkNum] = (struct ng_ethgrp_link *)
			ng_malloc(sizeof(*priv->ethgrp_links[linkNum]), M_NOWAIT);
		if (priv->ethgrp_links[linkNum] == NULL)
			return (ENOMEM);
		bzero(priv->ethgrp_links[linkNum], sizeof(*priv->ethgrp_links[linkNum]));
		priv->ethgrp_links[linkNum]->hook = hook;
		hpriv.linknum = linkNum;
		NG_HOOK_SET_PRIVATE(hook, hpriv.s);
		priv->numLinks++;
		priv->ethgrp_links[linkNum]->prio = NG_ETH_GRP_DEFAULT_PRIO;
#ifdef LACP_NOTIF
		/* Send notification message to lacp daemon */
		if (priv->lacp_hook != NULL) {
			;/* store type of data => notification */
		}
#endif
		hook->hook_rcvdata = ng_ethgrp_recv_lower;

		return (0);
	}

	/* We never receive data from this hook */
	if (strncmp(name, NG_ETH_GRP_LACP_HOOK,
	    strlen(NG_ETH_GRP_LACP_HOOK)) == 0) {
		if (priv->lacp_hook != NULL)
			return (EISCONN);
		priv->lacp_hook = hook;

		return (0);
	}

	if (strncmp(name, NG_ETH_GRP_UPPER_HOOK,
	    strlen(NG_ETH_GRP_UPPER_HOOK)) == 0) {
		if (priv->ethgrp_upper != NULL)
			return (EISCONN);
		priv->ethgrp_upper = hook;
		hook->hook_rcvdata = ng_ethgrp_xmit_data;

		return (0);

	}
	/* Unknown hook name */
	return (EINVAL);
}

static void ng_ethgrp_set_config(struct ng_ethgrp_config *conf, const priv_p priv)
{
	memcpy(&priv->conf, conf, sizeof(priv->conf));
}

static void ng_ethgrp_set_enaddr(char *addr, const priv_p priv)
{
	/* store MAC in node priv */
	memcpy(priv->node_addr, addr, VNB_ETHER_ADDR_LEN);
}

static int
ng_ethgrp_set_hookmode(uint32_t linknum, uint32_t mode, priv_p priv,
		int cb(priv_p, int, int))
{
	int error = 0;

	if (priv->ethgrp_links[linknum] == NULL) {
		TRACE("This link(%d) does not exist\n", linknum);
		return EINVAL;
	}

	if (mode != 0 && mode != 1) {
		TRACE("invalid mode (%d)\n", mode);
		return EINVAL;
	}

	HOOK_MODE(priv, linknum) = mode;

	TRACE ("sethook:linknum=%d, mode=%d\n",
	       linknum, mode);

	error = cb(priv, linknum, mode);
	if (error)
		TRACE("update-problem\n");

	return error;
}

static int
ng_ethgrp_set_hookprio(uint32_t linknum, uint32_t prio, priv_p priv)
{
	uint32_t tableid;
	int error = 0;

	if (priv->ethgrp_links[linknum] == NULL) {
		TRACE("This link(%d) does not exist\n", linknum);
		return EINVAL;
	}

	priv->ethgrp_links[linknum]->prio = prio;

	if (activetag_getbylinkid(priv, linknum, &tableid))
		priv->ActiveHookTable[tableid].prio =
			priv->ethgrp_links[linknum]->prio;

	if (priv->sending_algo == NG_ETH_GRP_ALGO_BACKUP)
		get_best_prio(priv);

	return error;
}

/*
 * Receive a control message
 */
static int
ng_ethgrp_rcvmsg(node_p node, struct ng_mesg *msg,
	const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_ETH_GRP_COOKIE:
		switch (msg->header.cmd) {
		case NGM_ETH_GRP_GET_CONFIG:
		    {
			struct ng_ethgrp_config *conf;

			NG_MKRESPONSE(resp, msg,
			    sizeof(struct ng_ethgrp_config), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			conf = (struct ng_ethgrp_config *)resp->data;
			*conf = priv->conf;     /* no sanity checking needed */
			break;
		    }
		case NGM_ETH_GRP_SET_CONFIG:
		    {
			struct ng_ethgrp_config *conf;

			if (msg->header.arglen
			    != sizeof(struct ng_ethgrp_config)) {
				error = EINVAL;
				break;
			}
			conf = (struct ng_ethgrp_config *)msg->data;

			ng_ethgrp_set_config(conf, priv);

			break;
		    }
		case NGM_ETH_GRP_SET_HOOK_MODE:
		    {
			struct ng_ethgrp_set_hook_mode *hkmode;
			int linknum;

			if (msg->header.arglen
			    != sizeof(struct ng_ethgrp_set_hook_mode)) {
				error = EINVAL;
				break;
			}
			hkmode = (struct ng_ethgrp_set_hook_mode *)msg->data;
			linknum = hkmode->id;

			error = ng_ethgrp_set_hookmode(linknum, hkmode->mode, priv, update_ActiveHookTable);
			break;
		    }
		case NGM_ETH_GRP_GET_HOOK_MODE:
		    {
			int linknum;
			struct ng_ethgrp_link *link;
			void *msgdata;

			/* Get link number */
			if (msg->header.arglen != sizeof(u_int32_t)) {
				error = EINVAL;
				break;
			}
			msgdata = (void *)msg->data;
			linknum = *((u_int32_t *)msgdata);
			if (linknum < 0 || linknum >= NG_ETH_GRP_MAX_LINKS) {
				error = EINVAL;
				break;
			}
			if ((link = priv->ethgrp_links[linknum]) == NULL) {
				TRACE("This link(%d) does not exist\n", linknum);
				error = ENOTCONN;
				break;
			}

			NG_MKRESPONSE(resp, msg, NG_ETH_GRP_MODE_NAME_MAX, M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			if (link->linkmode == 0) {
				snprintf ((char *) resp->data, NG_ETH_GRP_MODE_NAME_MAX,
				    "%s", "inactive");
			} else if (link->linkmode == 1) {
				snprintf ((char *) resp->data, NG_ETH_GRP_MODE_NAME_MAX,
				    "%s", "active");
			} else {
				snprintf ((char *) resp->data, NG_ETH_GRP_MODE_NAME_MAX,
				    "%s", "unknown");
			}
			TRACE("gethook:%s\n",(char *) resp->data);
			break;
		    }
		case NGM_ETH_GRP_SET_ALGO:
		    {
			char arg[NG_ETH_GRP_ALGO_NAME_MAX];
			snprintf (arg, NG_ETH_GRP_ALGO_NAME_MAX, "%s", (char *)msg->data);
			if (!strcmp (arg, "rr"))
				priv->sending_algo = NG_ETH_GRP_ALGO_ROUND_ROBIN;
			else if (!strcmp (arg, "xmac"))
				priv->sending_algo = NG_ETH_GRP_ALGO_XOR_MAC;
			else if (!strcmp (arg, "xip"))
				priv->sending_algo = NG_ETH_GRP_ALGO_XOR_IP;
			else if (!strcmp (arg, "xipport"))
				priv->sending_algo = NG_ETH_GRP_ALGO_XOR_IP_PORT;
			else if (!strcmp (arg, "backup")) {
				priv->sending_algo = NG_ETH_GRP_ALGO_BACKUP;
				get_best_prio (priv);
			} else {
				error = EINVAL;
				TRACE ("Distribution algo must be specified!(segalgo:%s)\n",arg);
			}
			TRACE("setalgo:arg=%s,priv->sending_algo=%x\n",arg,priv->sending_algo);
			break;
		    }
		case NGM_ETH_GRP_GET_ALGO:
		    {
			NG_MKRESPONSE(resp, msg, NG_ETH_GRP_ALGO_NAME_MAX, M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			if (priv->sending_algo == NG_ETH_GRP_ALGO_ROUND_ROBIN) {
				snprintf ((char *) resp->data, NG_ETH_GRP_ALGO_NAME_MAX,
				    "%s", "rr");
			} else if (priv->sending_algo == NG_ETH_GRP_ALGO_XOR_MAC) {
				snprintf ((char *) resp->data, NG_ETH_GRP_ALGO_NAME_MAX,
				    "%s", "xmac");
			} else if (priv->sending_algo == NG_ETH_GRP_ALGO_XOR_IP) {
				snprintf ((char *) resp->data, NG_ETH_GRP_ALGO_NAME_MAX,
				    "%s", "xip");
			} else if(priv->sending_algo ==  NG_ETH_GRP_ALGO_BACKUP) {
				snprintf ((char *) resp->data, NG_ETH_GRP_ALGO_NAME_MAX,
				    "%s", "backup");
			} else if (priv->sending_algo == NG_ETH_GRP_ALGO_XOR_IP_PORT) {
				snprintf ((char *) resp->data, NG_ETH_GRP_ALGO_NAME_MAX,
				    "%s", "xipport");
			} else {
				snprintf ((char *) resp->data, NG_ETH_GRP_ALGO_NAME_MAX,
				    "%s", "UnKnown");
			}
			TRACE("getalgo:%s\n",(char *) resp->data);
			break;
		    }
		case NGM_ETH_GRP_SET_HOOK_PRIO:
		    {
			struct  ng_ethgrp_set_hook_prio *hprio;
			unsigned int linknum;

			if (msg->header.arglen !=
				sizeof(struct  ng_ethgrp_set_hook_prio)) {
				error = EINVAL;
				break;
			}
			hprio = (struct  ng_ethgrp_set_hook_prio *)msg->data;
			linknum = hprio->id;

			error = ng_ethgrp_set_hookprio(linknum, hprio->priority, priv);

			break;
		    }
		case NGM_ETH_GRP_GET_HOOK_PRIO:
		    {
			int linknum;
			struct ng_ethgrp_link *link;
			void *msgdata;

			/* Get link number */
			if (msg->header.arglen != sizeof(u_int32_t)) {
				error = EINVAL;
				break;
			}
			msgdata = msg->data;
			linknum = *((u_int32_t *)msgdata);
			if (linknum < 0 || linknum >= NG_ETH_GRP_MAX_LINKS) {
				error = EINVAL;
				break;
			}
			if ((link = priv->ethgrp_links[linknum]) == NULL) {
				TRACE("This link(%d) does not exist\n", linknum);
				error = ENOTCONN;
				break;
			}

			NG_MKRESPONSE(resp, msg, sizeof (u_int32_t), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			msgdata = resp->data;
			*((u_int32_t *) msgdata) = link->prio;
			break;
		    }
		case NGM_ETH_GRP_GET_ENADDR:
			NG_MKRESPONSE(resp, msg, VNB_ETHER_ADDR_LEN, M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			/* get MAC from node priv */
			memcpy(resp->data, priv->node_addr, VNB_ETHER_ADDR_LEN);
			break;
		case NGM_ETH_GRP_SET_ENADDR:
		    {
			if (msg->header.arglen != VNB_ETHER_ADDR_LEN) {
				error = EINVAL;
				break;
			}

			ng_ethgrp_set_enaddr(msg->data, priv);

			break;
		    }
		default:
			error = EINVAL;
			break;
		}
		break;
	default:
		error = EINVAL;
		break;
	}

	/* Done */
	if (rptr)
		*rptr = resp;
	else if (resp != NULL)
		FREE(resp, M_NETGRAPH);
	FREE(msg, M_NETGRAPH);
	return (error);
}

static inline int ng_ethgrp_xor_mac(const priv_p priv, struct mbuf *m)
{
	struct vnb_ether_header *eh;
	uint32_t *ptr;

	/* check that we can read the ethernet header */
	m = m_pullup(m, sizeof(struct vnb_ether_header));
	if (unlikely(m == NULL))
		return -1;

	eh = mtod(m, struct vnb_ether_header *);

	TRACE ("smac[0+]=%02x:%02x:%02x:%02x:%02x:%02x  "
	       "dmac[0+]=%02x:%02x:%02x:%02x:%02x:%02x\n",
	       eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2],
	       eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5],
	       eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
	       eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);

	ptr = (u_int32_t *)eh->ether_dhost;
	return get_link(priv->NBActive, priv->NBActive_mask, ptr[0],
			ptr[1], ptr[2]);
}

static inline int ng_ethgrp_xor_ip(const priv_p priv, struct mbuf *m,
				   int use_ports)
{
	union {
		struct vnb_ether_header *e;
		struct vlan_header *v;
	} hdr;
	size_t size = sizeof(struct vnb_ether_header);
	uint32_t sip, dip, ports;
	uint16_t type;
	uint8_t proto;

	/* check for ethernet header */
	if (unlikely((m = m_pullup(m, size)) == NULL))
		return -1;
	hdr.e = mtod(m, struct vnb_ether_header *);
	type = ntohs(hdr.e->ether_type);
	/* skip VLAN header if any */
	if (unlikely(type == VNB_ETHERTYPE_VLAN)) {
		size = sizeof(struct vlan_header);
		/* check for VLAN header size */
		if (unlikely(MBUF_LENGTH(m) < size))
			return ng_ethgrp_xor_mac(priv, m);
		if (unlikely((m = m_pullup(m, size)) == NULL))
			return -1;
		hdr.v = mtod(m, struct vlan_header *);
		type = ntohs(hdr.v->proto);
	}
	/* check for IPv4 header */
	if (likely(type == VNB_ETHERTYPE_IP)) {
		struct vnb_ip *iphdr;

		size += sizeof(*iphdr);
		/* check for IPv4 header size */
		if (unlikely((m = m_pullup(m, size)) == NULL))
			return -1;
		size -= sizeof(*iphdr);
		iphdr = (struct vnb_ip *)(mtod(m, uint8_t *) + size);
		sip = iphdr->ip_src.s_addr;
		dip = iphdr->ip_dst.s_addr;
		proto = iphdr->ip_p;
		TRACE("saddr: " VNB_NIPQUAD_FMT ", daddr: " VNB_NIPQUAD_FMT,
		      VNB_NIPQUAD(sip), VNB_NIPQUAD(dip));
		if ((likely(!use_ports)) ||
		    ((proto != VNB_IPPROTO_TCP) &&
		     (proto != VNB_IPPROTO_UDP) &&
		     (proto != VNB_IPPROTO_SCTP)))
			/* don't want or can't use the port value */
			return get_link(priv->NBActive, priv->NBActive_mask,
					GOLDEN_RATIO, sip, dip);
		/*
		  check that we can read src/dst ports in the 32 bits word
		  following IP options
		*/
		size += (iphdr->ip_hl * 4);
		if (unlikely((m = m_pullup(m, (size + 4))) == NULL))
			return -1;
		ports = *(uint32_t *)(mtod(m, uint8_t *) + size);
		TRACE("ports raw header: 0x%08x", ports);
		ports ^= GOLDEN_RATIO;
		return get_link(priv->NBActive, priv->NBActive_mask,
				ports, sip, dip);
	}
	/* check for IPv6 header */
	else if (type == VNB_ETHERTYPE_IPV6) {
		struct vnb_ip6_hdr *ip6hdr;

		size += sizeof(*ip6hdr);
		/* check for IPv6 header size */
		if (unlikely((m = m_pullup(m, size)) == NULL))
			return -1;
		size -= sizeof(*ip6hdr);
		ip6hdr = (struct vnb_ip6_hdr *)(mtod(m, uint8_t *) + size);
		sip = ip6hdr->ip6_src.vnb_s6_addr32[0];
		sip ^= ip6hdr->ip6_src.vnb_s6_addr32[1];
		sip ^= ip6hdr->ip6_src.vnb_s6_addr32[2];
		sip ^= ip6hdr->ip6_src.vnb_s6_addr32[3];
		dip = ip6hdr->ip6_dst.vnb_s6_addr32[0];
		dip ^= ip6hdr->ip6_dst.vnb_s6_addr32[1];
		dip ^= ip6hdr->ip6_dst.vnb_s6_addr32[2];
		dip ^= ip6hdr->ip6_dst.vnb_s6_addr32[3];
		TRACE("saddr: " VNB_NIP6_FMT ", daddr: " VNB_NIP6_FMT,
		      VNB_NIP6(ip6hdr->ip6_src), VNB_NIP6(ip6hdr->ip6_dst));
		proto = ip6hdr->ip6_nxt;
		if ((likely(!use_ports)) ||
		    ((proto != VNB_IPPROTO_TCP) &&
		     (proto != VNB_IPPROTO_UDP) &&
		     (proto != VNB_IPPROTO_SCTP)))
			/* don't want or can't use the port value */
			return get_link(priv->NBActive, priv->NBActive_mask,
					GOLDEN_RATIO, sip, dip);
		/* check that we can read src/dst ports in the next 32 bits */
		size += sizeof(*ip6hdr);
		if (unlikely((m = m_pullup(m, (size + 4))) == NULL))
			return -1;
		ports = *(uint32_t *)(mtod(m, uint8_t *) + size);
		TRACE("ports raw header: 0x%08x", ports);
		ports ^= GOLDEN_RATIO;
		return get_link(priv->NBActive, priv->NBActive_mask,
				ports, sip, dip);
	}
	/* use MAC addresses by default */
	return ng_ethgrp_xor_mac(priv, m);
}

static int
ng_ethgrp_xmit_data(hook_p hook, struct mbuf *m, meta_p meta)
{
	int error = 0;
	int32_t choice = 0;
	priv_p priv = hook->node_private;

#if defined(__FastPath__) && defined(LACP_NOTIF)
	struct vnb_ether_header *eh;
#endif
	if (!priv) {
		error = ENOTCONN;
		goto drop;
	}

#if defined(__FastPath__) && defined(LACP_NOTIF)
	/* like in fp_ether_input_novnb : do not check m length with m_pullup */
	eh = mtod(m, struct vnb_ether_header *);
	if (likely(eh->ether_type != htons(VNB_ETHERTYPE_SLOW))) {
		uint32_t link = m_priv(m)->lacp.in_link;
		NG_SEND_DATA(error, priv->ethgrp_links[link]->hook/*priv->ActiveHookTable[choice].hook*/, m, meta);
		return (error);
	}
#endif

	if (unlikely(!priv->NBActive)) {
	     TRACE("no active hook, return\n");
	     goto drop;
	}

	TRACE("Upper, priv->NBActive=%d\n",priv->NBActive);

	/* only one hook */
	if (priv->NBActive == 1) {
		TRACE("xmit:priv->sending_algo=%x, choice=%d\n",
		    priv->sending_algo, choice);
		NG_SEND_DATA(error, priv->ActiveHookTable[0].hook, m, meta);
		return (error);
	}

	/* choose hook depending on algorithm and optimize xor-ip */
	if (likely(priv->sending_algo == NG_ETH_GRP_ALGO_XOR_IP))
		choice = ng_ethgrp_xor_ip(priv, m, 0);
	else {
		switch (priv->sending_algo) {
		case NG_ETH_GRP_ALGO_ROUND_ROBIN:
			if (++priv->last_used >= priv->NBActive)
				priv->last_used = 0;
			choice = priv->last_used;
			break;

		case NG_ETH_GRP_ALGO_BACKUP:
			choice = priv->last_used;
			break;

		case NG_ETH_GRP_ALGO_XOR_MAC:
			choice = ng_ethgrp_xor_mac(priv, m);
			break;

		case NG_ETH_GRP_ALGO_XOR_IP_PORT:
			choice = ng_ethgrp_xor_ip(priv, m, 1);
			break;

		default:
			error = EINVAL;
			goto drop;
		}
	}

	/* The hash function returned an error, in this case, the mbuf
	 * is already freed */
	if (unlikely(choice < 0)) {
		NG_FREE_META(meta);
		return ENOBUFS;
	}

	NG_SEND_DATA(error, priv->ActiveHookTable[choice].hook, m, meta);
	return (error);
drop:
	NG_FREE_DATA(m, meta);
	return (error);

}

static int
ng_ethgrp_recv_lower(hook_p hook, struct mbuf *m, meta_p meta)
{
	int error = 0;
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = hook->node_private;
#ifdef LACP_NOTIF
	struct vnb_ether_header *eh;
	int slowp_mcast_p;
#endif

	if (!priv || !node) {
		error = ENOTCONN;
		goto drop;
	}

	/* Handle the packets coming from the lower links */
	TRACE("hook_lower=%d\n", LINK_NUM(hook));

#ifdef VNB_ETHGRP_HIGHPRIORITY_ONLY
	/* if the packets comes from non lowest priority port, drop it */
	if (priv->sending_algo == NG_ETH_GRP_ALGO_BACKUP) {
		if (hook != priv->ActiveHookTable[priv->last_used].hook) {
			TRACE("receive from not lowest priority port\n");
			NG_FREE_DATA(m, meta);
			return (EINVAL);
		}
	}
#endif

	TRACE("Lower, priv->NBActive=%d\n",priv->NBActive);

#ifdef LACP_NOTIF
	/* like in fp_ether_input_novnb : do not check m length with m_pullup */
	eh = mtod(m, struct vnb_ether_header *);
	if (likely(eh->ether_type != htons(VNB_ETHERTYPE_SLOW))) {
#endif

#ifdef DEBUG_ETH_GRP
		if (priv->ethgrp_upper == NULL) {
			TRACE("error: priv->ethgrp_upper == NULL\n");
		}
#endif
#if defined(__FastPath__) && defined(LACP_NOTIF)
		m_priv(m)->lacp.in_link = LINK_NUM(hook);
#endif
		NG_SEND_DATA(error, priv->ethgrp_upper, m, meta);
		return error;

#ifdef LACP_NOTIF
	}

	/* check lacp pdu flag */
	/* here merge of recv functions control parser + aggregator parser */
	slowp_mcast_p = memcmp(eh->ether_dhost, slowp_mc_addr, VNB_ETHER_ADDR_LEN);

	/* this is a slow protocol packet */
	if (likely(slowp_mcast_p == 0)) {

		uint8_t link_num = LINK_NUM(hook);
		struct lacpdu *lacpdu_p;

		/* check that we can read the LACPDU header */
		m = m_pullup(m, sizeof(struct lacpdu));
		if (unlikely(m == NULL)) {
			error = ENOMEM;
			goto drop;
		}

		lacpdu_p = mtod(m, struct lacpdu *);
		if (lacpdu_p->ldu_sph.sph_subtype == SLOWPROTOCOLS_SUBTYPE_LACP) {

			TRACE("%s:found LACPDU for port %d",__FUNCTION__, link_num);
#if defined(__FastPath__)
			/* if SLOWPROTOCOLS_SUBTYPE_LACP => exception */
			return ng_send_exception(node, hook, VNB2VNB_DATA, 0, m, meta);
#else
			/* if SLOWPROTOCOLS_SUBTYPE_LACP => userland (via lacp hook) */
			if (priv->lacp_hook != NULL) {
				struct ng_lacp_msg* msg;
				int packet_len;

				packet_len = MBUF_LENGTH(m);
				/* store ifindex in eh + type of data => packet */
				M_PREPEND (m,
				           sizeof (struct ng_lacp_msg),
				           M_DONTWAIT);
				msg = mtod (m, struct ng_lacp_msg *);
				msg->ngr_cmd = htons(NGR_RECV_SLOWP_MSG);
				msg->ngr_port = htons((u_int16_t)link_num);
				msg->ngr_len = htons(packet_len);
				strncpy(msg->ngr_name, node->name, NG_NODELEN);
				NG_SEND_DATA(error, priv->lacp_hook, m, meta);
				return (error);
			}
			error = ENOTCONN;
			goto drop;
#endif
		} else if (lacpdu_p->ldu_sph.sph_subtype == SLOWPROTOCOLS_SUBTYPE_MARKER) {
			/* if SLOWPROTOCOLS_SUBTYPE_MARKER => responder */
			TRACE("found MARKER\n");
			error = ieee8023ad_marker_input(m, priv->node_addr);

			if (!error) {
				NG_SEND_DATA(error, priv->ethgrp_links[link_num]->hook, m, meta);
				return (error);
			}
			goto drop;
		} else {
			/* else => drop */
			TRACE("found unknown subtype\n");
			error = EINVAL;
			goto drop;
		}
	}

#endif /* LACP_NOTIF */

drop:
	NG_FREE_DATA(m, meta);
	return (error);
}

/* add timeout for marker TX => only for linux kernel (SP) */

/*
 * Shutdown node
 */
static int
ng_ethgrp_rmnode(node_p node)
{
	node->flags |= NG_INVALID;
	ng_unname(node);
	ng_cutlinks(node);

	NG_NODE_SET_PRIVATE(node, NULL);

	/* Unref node */
	NG_NODE_UNREF(node);
	return (0);
}

static int
ng_ethgrp_disconnect(hook_p hook)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);
	int linkNum;

	if (hook == priv->lacp_hook) {
		priv->lacp_hook = NULL;
	} else if (hook == priv->ethgrp_upper) {
		priv->ethgrp_upper = NULL;
		hook->hook_rcvdata = NULL;
	} else {
		struct ng_ethgrp_link *link;
		/* Get link number */
		linkNum = LINK_NUM(hook);
		NG_KASSERT(linkNum >= 0 && linkNum < NG_ETH_GRP_MAX_LINKS,
		  ("%s: linkNum=%u", __FUNCTION__, linkNum));
		NG_KASSERT(priv->ethgrp_links[linkNum] != NULL,
			("%s: no link", __FUNCTION__));
		remove_active_hook(priv, linkNum);
		/* Will be freed when we are sure that nobody is using it */
		link = priv->ethgrp_links[linkNum];
		priv->ethgrp_links[linkNum] = NULL;
		priv->numLinks--;
		ng_free(link);

		hook->hook_rcvdata = NULL;
#ifdef LACP_NOTIF
		/* Send notification message to lacp daemon */
		if (priv->lacp_hook != NULL) {
			/* malloc mesg */
			;/* store type of data => notification */
		}
#endif
	}

	/* Go away if no longer connected to anything */
	if (node->numhooks == 0)
		ng_rmnode(node);

	return (0);
}

/******************************************************************
		     FUNCTIONS
******************************************************************/
static struct ng_ethgrp_link*
activetag_getbylinkid(priv_p priv, int linkid, unsigned int *tableid)
{
	unsigned int i;
	for (i = 0; i < priv->NBActive; i++){
		if (LINK_NUM(priv->ActiveHookTable[i].hook) == linkid) {
			if (tableid)
				*tableid = i;
			return &priv->ActiveHookTable[i];
		}
	}
	return NULL;
}

static void
remove_active_hook(priv_p priv, int linknum)
{
	unsigned int activetag, i;

	if (activetag_getbylinkid(priv, linknum, &activetag) == NULL) {
		TRACE("link_%d is not in ActiveTable\n", linknum);
		return;
	}
	TRACE("remove:priv->NBActive=%d, linknum=%d\n",priv->NBActive,linknum);
	NG_KASSERT(priv->NBActive > 0 && priv->NBActive < NG_ETH_GRP_MAX_LINKS,
		  ("%s: priv->NBActive=%d", __FUNCTION__, priv->NBActive));
	NG_KASSERT(priv->ActiveHookTable[priv->NBActive - 1].hook != NULL,
		   ("%s: no active link", __FUNCTION__));
	TRACE("activetag=%d\n",activetag);
	if (activetag != (priv->NBActive - 1)) {
	       for (i = activetag; i < priv->NBActive - 1; i++) {
			memmove(&priv->ActiveHookTable[i],
				 &priv->ActiveHookTable[i + 1],
				 sizeof (struct ng_ethgrp_link));
	       }
	}

	priv->NBActive--;
	priv->NBActive_mask = get_link_mask(priv->NBActive);
	priv->ActiveHookTable[priv->NBActive].hook = NULL;

	for (i = 0; i < priv->NBActive; i++){
		TRACE ("remove active table: active[%d]-->link[%d]\n",
		       i, LINK_NUM(priv->ActiveHookTable[i].hook));
	}

	if (priv->sending_algo == NG_ETH_GRP_ALGO_BACKUP)
		get_best_prio (priv);

	return;
}

static int
update_ActiveHookTable(priv_p priv, int linknum, int mode)
{
	unsigned int i;
	if (activetag_getbylinkid(priv, linknum, NULL) == NULL
		&& mode == NG_ETH_GRP_HOOK_ACTIVE) {
		TRACE("Add activ\n");
		priv->ActiveHookTable[priv->NBActive].hook = NULL;
		if (priv->ethgrp_links[linknum] == NULL){
			TRACE("priv->ethgrp_links[%d]==NULL\n",linknum);
			return (ENOMEM);
		}
		memcpy (&priv->ActiveHookTable[priv->NBActive],
			 priv->ethgrp_links[linknum],
			 sizeof (struct ng_ethgrp_link));
		priv->NBActive++;
		priv->NBActive_mask = get_link_mask(priv->NBActive);
		TRACE("add:priv->NBActive=%d\n",priv->NBActive);

		for (i = 0; i < priv->NBActive; i++){
			TRACE ("add active table: active[%d]-->link[%d]\n",
				i,LINK_NUM(priv->ActiveHookTable[i].hook));
		}
		if (priv->sending_algo == NG_ETH_GRP_ALGO_BACKUP)
			get_best_prio (priv);

	} else if (activetag_getbylinkid(priv, linknum, NULL) != NULL
		       && mode == NG_ETH_GRP_HOOK_INACTIVE) {
		TRACE("Remove active\n");
		remove_active_hook(priv, linknum);
	}

	return 0;
}

static void
get_best_prio (priv_p priv)
{
	unsigned int i;

	priv->last_used = 0;

	for (i = 1; i < priv->NBActive; i++) {
		if (priv->ActiveHookTable[i].prio <
		    priv->ActiveHookTable[priv->last_used].prio) {
			    priv->last_used = i;
		}
	}
	TRACE("%s:priv->last_used=%d",__FUNCTION__, priv->last_used);
	return;
}

#ifndef __FastPath__

static struct ng_nl_nodepriv *
ng_ethgrp_dumpnode(node_p node)
{
	struct ng_nl_nodepriv *nlnodepriv;
	const priv_p	priv = NG_NODE_PRIVATE(node);
	struct ng_ethgrp_nl_nodepriv *ethgrp_nlnodepriv;
	int i;

	MALLOC(nlnodepriv, struct ng_nl_nodepriv *,
	       sizeof(*nlnodepriv) + sizeof(*ethgrp_nlnodepriv), M_NETGRAPH, M_NOWAIT | M_ZERO);

	if (!nlnodepriv)
		return NULL;

	ethgrp_nlnodepriv = (struct ng_ethgrp_nl_nodepriv *)nlnodepriv->data;

	nlnodepriv->data_len = sizeof(*ethgrp_nlnodepriv);
	memcpy(&ethgrp_nlnodepriv->config, &priv->conf,
	       sizeof(ethgrp_nlnodepriv->config));
	memcpy(ethgrp_nlnodepriv->node_addr, priv->node_addr,
	       sizeof(ethgrp_nlnodepriv->node_addr));
	ethgrp_nlnodepriv->sending_algo = htonl(priv->sending_algo);
	for (i = 0; i < priv->NBActive; i++)
		ethgrp_nlnodepriv->ActiveLink[i] = htonl(LINK_NUM(priv->ActiveHookTable[i].hook));
	ethgrp_nlnodepriv->ActiveLink[priv->NBActive] = htonl(-1); /* link id should not be -1 */

	return nlnodepriv;
}

static struct ng_nl_hookpriv *
ng_ethgrp_dumphook(node_p node, hook_p hook)
{
	struct ng_nl_hookpriv *nlhookpriv;
	const priv_p	priv = NG_NODE_PRIVATE(node);
	struct ng_ethgrp_nl_hookpriv *ethgrp_nlhookpriv;
	u_long linkNum;

	if (strncmp(hook->name, NG_ETH_GRP_HOOK_LINK_PREFIX,
		    strlen(NG_ETH_GRP_HOOK_LINK_PREFIX)) != 0)
		return NULL;

	MALLOC(nlhookpriv, struct ng_nl_hookpriv *,
	       sizeof(*nlhookpriv) + sizeof(*ethgrp_nlhookpriv), M_NETGRAPH, M_NOWAIT | M_ZERO);

	if (!nlhookpriv)
		return NULL;

	linkNum = LINK_NUM(hook);

	ethgrp_nlhookpriv = (struct ng_ethgrp_nl_hookpriv *)nlhookpriv->data;

	nlhookpriv->data_len = sizeof(*ethgrp_nlhookpriv);
	ethgrp_nlhookpriv->id = htonl(linkNum);
	ethgrp_nlhookpriv->mode = htonl(priv->ethgrp_links[linkNum]->linkmode);
	ethgrp_nlhookpriv->priority = htonl(priv->ethgrp_links[linkNum]->prio);

	return nlhookpriv;
}

#else

static struct ng_ethgrp_link*
activeseq_getbylinkid(priv_p priv, int linkid, unsigned int *tableid)
{
	unsigned int i;
	for (i = 0; i < priv->NBActive; i++)
		if (priv->ActiveLink[i] == linkid)
			break;

	if (i == priv->NBActive) {
		TRACE("the link was not in the ActiveLink table before\n");
		return NULL;
	}
	if (tableid)
		*tableid = i;
	return &priv->ActiveHookTable[i];
}

static int
restore_ActiveHookTable(priv_p priv, int linknum, int mode)
{
	unsigned int i;
	if (activeseq_getbylinkid(priv, linknum, &i) == NULL)
		return (EINVAL);

	if (priv->ActiveHookTable[i].hook == NULL
		&& mode == NG_ETH_GRP_HOOK_ACTIVE) {
		TRACE("Add active\n");
		if (priv->ethgrp_links[linknum] == NULL){
			TRACE("priv->ethgrp_links[%d]==NULL\n",linknum);
			return (ENOMEM);
		}
		memcpy (&priv->ActiveHookTable[i],
			 priv->ethgrp_links[linknum],
			 sizeof (struct ng_ethgrp_link));
		TRACE ("add active table: active[%d]-->link[%d]\n",
				i,LINK_NUM(priv->ActiveHookTable[i].hook));
	}

	return 0;
}

static void
ng_ethgrp_restorenode(struct ng_nl_nodepriv * nlnodepriv, node_p node)
{
	struct ng_ethgrp_nl_nodepriv *ethgrp_nlnodepriv;
	priv_p priv = NG_NODE_PRIVATE(node);
	int sending_algo;
	unsigned int NBActive = 0;
	int linknum;
#ifdef DEBUG_ETH_GRP
	const char *sending_algo_str;
#endif

	if (ntohl(nlnodepriv->data_len) != sizeof(*ethgrp_nlnodepriv)) {
		TRACE("FPVNB: size mismatch (%d instead of %d)",
		      nlnodepriv->data_len,
		      (int) sizeof(*ethgrp_nlnodepriv));
		return;
	}

	ethgrp_nlnodepriv = (struct ng_ethgrp_nl_nodepriv *)nlnodepriv->data;
	sending_algo = ntohl(ethgrp_nlnodepriv->sending_algo);

	ng_ethgrp_set_config(&ethgrp_nlnodepriv->config, priv);
	TRACE("FPVNB:  ethgrp_priv restore config");

	priv->sending_algo = sending_algo;

	while ((linknum = ntohl(ethgrp_nlnodepriv->ActiveLink[NBActive])) != -1)
		priv->ActiveLink[NBActive++] = linknum;
	priv->NBActive = NBActive;
	priv->NBActive_mask = get_link_mask(priv->NBActive);
	priv->last_used = 0;
	TRACE("FPVNB:  ethgrp_priv restore NBActive = %d", NBActive);

#ifdef DEBUG_ETH_GRP
	if (sending_algo == NG_ETH_GRP_ALGO_ROUND_ROBIN)
		sending_algo_str = "rr";
	else if (sending_algo == NG_ETH_GRP_ALGO_XOR_MAC)
		sending_algo_str = "xmac";
	else if (sending_algo == NG_ETH_GRP_ALGO_XOR_IP)
		sending_algo_str = "xip";
	else if(sending_algo ==  NG_ETH_GRP_ALGO_BACKUP)
		sending_algo_str = "backup";
	else if (sending_algo == NG_ETH_GRP_ALGO_XOR_IP_PORT)
		sending_algo_str = "xipport";
	else
		sending_algo_str = "UnKnown";
#endif

	TRACE("FPVNB:  ethgrp_priv sending_algo=%x - %s", sending_algo,
	      sending_algo_str);

	ng_ethgrp_set_enaddr(ethgrp_nlnodepriv->node_addr, priv);
	TRACE("FPVNB:  ethgrp_priv set_enaddr to %02x:%02x:%02x:%02x:%02x:%0x2",
	      (unsigned char)ethgrp_nlnodepriv->node_addr[0],
	      (unsigned char)ethgrp_nlnodepriv->node_addr[1],
	      (unsigned char)ethgrp_nlnodepriv->node_addr[2],
	      (unsigned char)ethgrp_nlnodepriv->node_addr[3],
	      (unsigned char)ethgrp_nlnodepriv->node_addr[4],
	      (unsigned char)ethgrp_nlnodepriv->node_addr[5]);

	return;
}

static void
ng_ethgrp_restorehook(struct ng_nl_hookpriv * nlhookpriv, node_p node, hook_p hook)
{
	struct ng_ethgrp_nl_hookpriv *ethgrp_nlhookpriv;
	priv_p priv = NG_NODE_PRIVATE(node);
	int error;
	uint32_t linknum, prio;
	unsigned int tableid;

	if (ntohl(nlhookpriv->data_len) != sizeof(*ethgrp_nlhookpriv)) {
		TRACE("FPVNB:    bad message size (%d instead of %d)\n",
		      nlhookpriv->data_len, (int) sizeof(*ethgrp_nlhookpriv));
		return;
	}

	ethgrp_nlhookpriv = (struct ng_ethgrp_nl_hookpriv *)nlhookpriv->data;

	error = ng_ethgrp_set_hookmode(ntohl(ethgrp_nlhookpriv->id),
				       ntohl(ethgrp_nlhookpriv->mode),
				       priv, restore_ActiveHookTable);

	(void)error; /* current value can be never read */

	TRACE("FPVNB:    id=%d mode=%d error=%d\n",
	      ntohl(ethgrp_nlhookpriv->id),
	      ntohl(ethgrp_nlhookpriv->mode),
	      error);

	linknum = ntohl(ethgrp_nlhookpriv->id);
	prio = ntohl(ethgrp_nlhookpriv->priority);
	if (priv->ethgrp_links[linknum] == NULL) {
		TRACE("This link(%d) does not exist\n", linknum);
		error = EINVAL;
	}

	priv->ethgrp_links[linknum]->prio = prio;

	if (activeseq_getbylinkid(priv, linknum, &tableid))
		priv->ActiveHookTable[tableid].prio =
			priv->ethgrp_links[linknum]->prio;

	(void)error; /* current value can be never read */

	TRACE("FPVNB:    id=%d prio=%d error=%d\n",
	      ntohl(ethgrp_nlhookpriv->id),
	      ntohl(ethgrp_nlhookpriv->priority),
	      error);

	return;
}

#endif

#if defined(__LinuxKernelVNB__)
module_init(ng_ethgrp_init);
module_exit(ng_ethgrp_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB ETHGRP node");
MODULE_LICENSE("6WIND");
#endif
