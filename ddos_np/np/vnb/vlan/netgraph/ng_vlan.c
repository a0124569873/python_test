/*
 * Copyright 2003-2013 6WIND S.A.
 */

/*
 * VLAN
 * ----
 *
 * Loadable kernel module and netgraph support
 *
 * In order to support the ethernet multicast addresses, the underlying
 * interfaces should be set in promicuous mode.
 *
 */

#if defined(__LinuxKernelVNB__)
#include <linux/module.h>

#include <linux/version.h>
#include <linux/in6.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <netgraph/vnblinux.h>

#elif defined(__FastPath__)
#include "fp-netgraph.h"
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_vlan.h>
#if !defined(__FastPath__) || defined(CONFIG_MCORE_M_TAG)
/* KT_NFMARK_WIDTH and KT_NFMARK_SHIFT can be defined here if needed */
#include <netgraph/nfmark.h>
#endif
#include <netgraph/vnb_ether.h>

#ifdef HAVE_KTABLES
#include <ktables_config.h>
#if defined(__LinuxKernelVNB__)
#include <ktables.h>
#endif
#endif

/*
 * NG_VLAN_STATS    to enable packets / bytes counters
 * NG_VLAN_DEBUG    to enable trace in input / output processing
 */

#if defined(__LinuxKernelVNB__)
#define NG_VLAN_STATS 1
#endif

//#define NG_VLAN_DEBUG 1
//#define NG_VLAN_DEBUG_DSCP 1
//#define NG_VLAN_DEBUG_NFMARK 1

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_VLAN, "ng_vlan", "netgraph VLAN");
#else
#define M_NETGRAPH_VLAN M_NETGRAPH
#endif

#if NG_VLAN_MAX_TAG > 4095
#error The highest tag value is 4095 (12 bits)
#endif

/*
 * Local definitions
 */

/*
 * VLAN header
 */
struct vlan_header {
	uint8_t	dhost[VNB_ETHER_ADDR_LEN];  /* Destination MAC address */
	uint8_t	shost[VNB_ETHER_ADDR_LEN];  /* Source MAC address */
	uint16_t encap_proto;           /* = htons(ETHERTYPE_VLAN) */
	uint16_t tag;                   /* 1 .. 4094 */
	uint16_t proto;                 /* = htons(ETHERTYPE_xxx */
};

struct mini_iphdr {
#if VNB_BYTE_ORDER == VNB_LITTLE_ENDIAN
	uint8_t	ihl:4,
		version:4;
	uint8_t ecn:2,
		dscp:6;
#elif VNB_BYTE_ORDER == VNB_BIG_ENDIAN
	uint8_t	version:4,
		ihl:4;
	uint8_t	dscp:6,
		ecn:2;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
};

struct mini_ip6hdr {
#if VNB_BYTE_ORDER == VNB_LITTLE_ENDIAN
	uint8_t	dscp1:4,
		version:4;
	uint8_t	unused:6,
		dscp2:2;
#elif VNB_BYTE_ORDER == VNB_BIG_ENDIAN
	uint8_t	version:4,
		dscp1:4;
	uint8_t	dscp2:2,
		unused:6;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
};

/* Per-node private data */
struct ng_vlan_private {
	node_p		node;			/* back pointer to node */
#ifdef NG_VLAN_DEBUG
	struct ng_vlan_config	conf;		/* node configuration */
#endif
#ifdef NG_VLAN_STATS
	struct ng_vlan_stats	stats;		/* node stats */
#endif
	hook_p		lower;			/* lower hook connection */
	hook_p		nomatch;		/* nomatch hook connection */
	hook_p		orphans;		/* orphans hook connection */
	hook_p		links[NG_VLAN_MAX_TAG]; /* array of hooks, for each tag */
#if defined(HAVE_KTABLES)
	uint8_t const *kt_p;                     /* Pointer to kernel table */
#endif
};
typedef struct ng_vlan_private *priv_p;

#define DSCP_MAX_SIZE 64
#define NFMARK_MAX_SIZE 16
#if !defined(__FastPath__) || defined(CONFIG_MCORE_M_TAG)
#define NG_VLAN_DSCP_PRIO
#define NG_VLAN_NFMARK_PRIO
#endif

/* Store tag value in private zone of each hook */
struct ng_vlan_hook_private {
	uint16_t tag;
	uint8_t dscp_enable;
	uint8_t nfmark_enable;
#ifdef NG_VLAN_DSCP_PRIO
	uint8_t dscp_to_priority[DSCP_MAX_SIZE];
#endif
#ifdef NG_VLAN_NFMARK_PRIO
	uint8_t nfmark_to_priority[NFMARK_MAX_SIZE];
#endif
};
typedef struct ng_vlan_hook_private* hookpriv_p;

/* fake tag value to recognize orphans and lower hook */
#define NG_VLAN_TAG_LOWER     0
#define NG_VLAN_TAG_NOMATCH   NG_VLAN_MAX_TAG
#define NG_VLAN_TAG_ORPHANS   NG_VLAN_MAX_TAG+1

#ifdef NG_NODE_CACHE
/* Hook cache info: we store node->private */
#endif

#if defined(__FastPath__) && defined(CONFIG_MCORE_M_TAG)
static VNB_DEFINE_SHARED(int32_t, prio_tag_type);
#endif

#define VLAN_VLANOFTAG(tag) ((tag) & 0x0fff)
#define VLAN_PRIOFTAG(tag) (((tag) >> 13) & 0x0007)
#define VLAN_CFIOFTAG(tag) (((tag) >> 12) & 0x0001)

#ifdef NG_VLAN_DSCP_PRIO
#define DSCP_IS_VALID(dscp) ((dscp) < DSCP_MAX_SIZE)
#define VLAN_DSCP_TO_PRIORITY(hpriv, dscp) \
	((uint16_t)(((hpriv->dscp_to_priority[dscp]) << 13 )))
#endif

#ifdef NG_VLAN_NFMARK_PRIO
#define NFMARK_IS_VALID(nfmark) ((nfmark) < NFMARK_MAX_SIZE)
#define VLAN_NFMARK_TO_PRIORITY(hpriv, nfmark) \
	((uint16_t)(((hpriv->nfmark_to_priority[nfmark]) << 13 )))
#endif

/*
 * Netgraph node methods
 */
static ng_constructor_t ng_vlan_constructor;
static ng_rcvmsg_t      ng_vlan_rcvmsg;
static ng_shutdown_t    ng_vlan_rmnode;
static ng_newhook_t     ng_vlan_newhook;
static ng_disconnect_t  ng_vlan_disconnect;

static int ng_vlan_rcv_tag(hook_p hook, struct mbuf *m, meta_p meta);
static int ng_vlan_rcv_lower(hook_p hook, struct mbuf *m, meta_p meta);
static int ng_vlan_rcv_nomatch(hook_p hook, struct mbuf *m, meta_p meta);

/*
 * Local variables
 */

#ifdef NG_VLAN_DEBUG
/* Parse type for struct ng_vlan_config */
static const struct ng_parse_struct_field
	ng_vlan_config_type_fields[] = NG_VLAN_CONFIG_TYPE_INFO;
static const struct ng_parse_type ng_vlan_config_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_vlan_config_type_fields,
};
#endif

#ifdef NG_VLAN_STATS
/* Parse type for struct ng_vlan_stats */
static const struct ng_parse_struct_field
	ng_vlan_stats_type_fields[] = NG_VLAN_STATS_TYPE_INFO;
static const struct ng_parse_type ng_vlan_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_vlan_stats_type_fields
};
#endif

/* Parse type for struct ng_vlan_dscp_table_msg */
static const struct ng_parse_fixedarray_info ng_vlan_dscp_ary_type_info = {
	.elementType = &ng_parse_uint8_type,
	.length = 64
};

static const struct ng_parse_type ng_vlan_dscp_ary_type = {
	.supertype = &ng_parse_fixedarray_type,
	.info  = &ng_vlan_dscp_ary_type_info
};

static const struct ng_parse_struct_field ng_vlan_dscp_table_fields[] =
	NG_VLAN_DSCP_TABLE_MSG_INFO(&ng_vlan_dscp_ary_type);

static const struct ng_parse_type ng_vlan_dscp_table_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_vlan_dscp_table_fields
};

/* Parse type for struct ng_vlan_nfmark_table_msg */
static const struct ng_parse_fixedarray_info ng_vlan_nfmark_ary_type_info = {
	.elementType = &ng_parse_uint8_type,
	.length = 16
};

static const struct ng_parse_type ng_vlan_nfmark_ary_type = {
	.supertype = &ng_parse_fixedarray_type,
	.info  = &ng_vlan_nfmark_ary_type_info
};

static const struct ng_parse_struct_field ng_vlan_nfmark_table_fields[] =
	NG_VLAN_NFMARK_TABLE_MSG_INFO(&ng_vlan_nfmark_ary_type);

static const struct ng_parse_type ng_vlan_nfmark_table_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_vlan_nfmark_table_fields
};


static const struct ng_cmdlist ng_vlan_cmdlist[] = {
#ifdef NG_VLAN_DEBUG
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_SET_CONFIG,
	  "setconfig",
	  .mesgType = &ng_vlan_config_type,
	  .respType = NULL
	},
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_GET_CONFIG,
	  "getconfig",
	  .mesgType = NULL,
	  .respType = &ng_vlan_config_type
	},
#endif
#ifdef NG_VLAN_STATS
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_GET_STATS,
	  "getstats",
	  .mesgType = NULL,
	  .respType = &ng_vlan_stats_type
	},
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_CLR_STATS,
	  "clrstats",
	  .mesgType = NULL,
	  .respType = NULL
	},
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_GETCLR_STATS,
	  "getclrstats",
	  .mesgType = NULL,
	  .respType = &ng_vlan_stats_type
	},
#endif
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_DSCP_ENABLE,
	  "dscp_enable",
	  .mesgType = &ng_parse_uint16_type,
	  .respType = NULL
	},
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_DSCP_DISABLE,
	  "dscp_disable",
	  .mesgType = &ng_parse_uint16_type,
	  .respType = NULL
	},
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_DSCP_GET_TABLE,
	  "dscptable_get",
	  .mesgType = &ng_parse_uint16_type,
	  .respType = &ng_vlan_dscp_table_type
	},
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_DSCP_SET_TABLE,
	  "dscptable_set",
	  .mesgType = &ng_vlan_dscp_table_type,
	  .respType = NULL
	},
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_NFMARK_ENABLE,
	  "nfmark_enable",
	  .mesgType = &ng_parse_uint16_type,
	  .respType = NULL
	},
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_NFMARK_DISABLE,
	  "nfmark_disable",
	  .mesgType = &ng_parse_uint16_type,
	  .respType = NULL
	},
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_NFMARK_GET_TABLE,
	  "nfmarktable_get",
	  .mesgType = &ng_parse_uint16_type,
	  .respType = &ng_vlan_nfmark_table_type
	},
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_NFMARK_SET_TABLE,
	  "nfmarktable_set",
	  .mesgType = &ng_vlan_nfmark_table_type,
	  .respType = NULL
	},
#ifdef HAVE_KTABLES
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_NFMARK_GET_INGRESS_KTABLE,
	  "nfmark_ktable_get",
	  .mesgType = NULL,
	  .respType = &ng_parse_uint32_type
	},
	{
	  NGM_VLAN_COOKIE,
	  NGM_VLAN_NFMARK_SET_INGRESS_KTABLE,
	  "nfmark_ktable_set",
	  .mesgType = &ng_parse_uint32_type,
	  .respType = NULL
	},
#endif
	{ 0, 0, NULL, NULL, NULL }
};

/*
 * Node type descriptor
 */
static VNB_DEFINE_SHARED(struct ng_type, ng_vlan_typestruct) = {
	.version =    NG_VERSION,
	.name =       NG_VLAN_NODE_TYPE,
	.mod_event =  NULL,					/* Module event handler (optional) */
	.constructor =ng_vlan_constructor,	/* Node constructor */
	.rcvmsg =     ng_vlan_rcvmsg,			/* control messages come here */
	.shutdown =   ng_vlan_rmnode,			/* reset, and free resources */
	.newhook =    ng_vlan_newhook,		/* first notification of new hook */
	.findhook =   NULL,					/* only if you have lots of hooks */
	.connect =    NULL,					/* final notification of new hook */
	.rcvdata =    NULL,		/* Only specific receive data functions */
	.rcvdataq =   NULL,		/* Only specific receive data functions */
	.disconnect = ng_vlan_disconnect,	/* notify on disconnect */
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist =    ng_vlan_cmdlist,		/* commands we can convert */
};

#ifdef __FastPath__
int ng_vlan_init(void)
{
        int error;
        void *type = (&ng_vlan_typestruct);

        log(LOG_DEBUG, "VNB: Loading ng_vlan\n");

        if ((error = ng_newtype(type)) != 0) {
                log(LOG_ERR, "VNB: ng_vlan_init failed (%d)\n",error);
                return EINVAL;
        }

#if defined(CONFIG_MCORE_M_TAG)
	prio_tag_type = m_tag_type_register(NG_VLAN_TAG_NAME);
	if (prio_tag_type < 0) {
                log(LOG_ERR, "VNB: ng_vlan_init failed (register mtag)\n");
                return EINVAL;
        }
        error = ng_pkt_mark_init(__FUNCTION__);
        return(error);
#endif
        return(0);
}
#else
NETGRAPH_INIT(vlan, &ng_vlan_typestruct);
NETGRAPH_EXIT(vlan, &ng_vlan_typestruct);
#endif

#if defined(__LinuxKernelVNB__)
/*
 * We need to define a new initialization function to manage module argument
 */
int ng_vlan_init_module(void)
{
        return ng_vlan_init();
}

module_init(ng_vlan_init_module);
module_exit(ng_vlan_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB VLAN node");
MODULE_LICENSE("6WIND");
#endif

/******************************************************************
		    NETGRAPH NODE METHODS
 ******************************************************************/

/*
 * Node constructor
 *
 * Called at splnet()
 */
static int
ng_vlan_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int error;

#ifdef SPLASSERT
	SPLASSERT(net, __FUNCTION__);
#endif

	/* Call superclass constructor that mallocs *nodep */
	if ((error = ng_make_node_common_and_priv(&ng_vlan_typestruct, nodep,
						  &priv, sizeof(*priv), nodeid))) {
		return (error);
	}
	bzero(priv, sizeof(*priv));

#ifdef NG_VLAN_DEBUG
	priv->conf.debug = NG_VLAN_DEBUG_NONE;
#endif
	NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->node = *nodep;

	/* Done */
	return (0);
}

/*
 * Method for attaching a new hook
 * There are four kinds of hook:
 * 	- the links with an index. The index is the VLAN tag.
 * 	- the orphans link.
 * 	- the nomatch link.
 * 	- the lower link.
 */
static	int
ng_vlan_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	/*
	 * Check for a link hook
	 */
	if (strncmp(name, NG_VLAN_HOOK_LINK_PREFIX,
			sizeof(NG_VLAN_HOOK_LINK_PREFIX) - 1) == 0) {

		const char *tag_str;
		char *err_ptr;
		unsigned long tag;
		hookpriv_p hpriv;

		/*
		 * Get the link index
		 * Parse link0xa, link10, ...
		 */
		tag_str = name + sizeof(NG_VLAN_HOOK_LINK_PREFIX) - 1;

		/* Allow decimal and hexadecimal values.
		 * The hexadecimal values must be prefixed by 0x
		 */
		tag = strtoul(tag_str, &err_ptr, 0); /* allow decimal and hexadecimal */
		if ((*err_ptr) != '\0')
			return (EINVAL);

		/*
		 * RFC2674: "Bridge MIB Extensions"
		 * [...] values of 0 and 4095 are not permitted; if the value is
		 * between 1 and 4094 inclusive, it represents an IEEE 802.1Q VLAN-ID
		 * with global scope within a given bridged domain (see VlanId
         * textual convention).
		 * ie. only the tags from 1 to NG_VLAN_MAX_TAG - 1 (4094)
		 * are allowed.
		 *
		 * If you need to support the VLAN extensions, modify the following
		 * lines.
		 */
		if (tag == 0 || tag >= NG_VLAN_MAX_TAG)
			return EINVAL;

		/*
		 * Do not create twice a link hook
		 */
		if (priv->links[tag] != NULL)
			return EISCONN;

		/*
		 * Register the per-link private data
		 */
		hpriv = (hookpriv_p) ng_malloc(sizeof(*hpriv), M_NOWAIT | M_ZERO);
		if (!hpriv)
			return ENOMEM;
		hpriv->dscp_enable = 0;
		hpriv->nfmark_enable = 0;
		hpriv->tag = (uint16_t)tag;

		NG_HOOK_SET_PRIVATE(hook, hpriv);
#ifdef NG_NODE_CACHE
		NG_HOOK_SET_NODE_CACHE(hook, node->private);
#endif

		/*
		 * Initialize the hash entry
		 */
		priv->links[tag] = hook;

		hook->hook_rcvdata = ng_vlan_rcv_tag;

		return 0;

	/*
	 * Check for an orphans hook
	 */
	} else if (strcmp(name, NG_VLAN_HOOK_ORPHANS) == 0) {
		hookpriv_p hpriv;

		/*
		 * Do not connect twice an orphans hook
		 */
		if (priv->orphans != NULL)
			return (EISCONN);

		/* Store we are orphans */
		hpriv = (hookpriv_p) ng_malloc(sizeof(*hpriv), M_NOWAIT | M_ZERO);
		if (!hpriv)
			return ENOMEM;

		hpriv->dscp_enable = 0;
		hpriv->nfmark_enable = 0;
		hpriv->tag = NG_VLAN_TAG_ORPHANS;
		NG_HOOK_SET_PRIVATE(hook, hpriv);
#ifdef NG_NODE_CACHE
		NG_HOOK_SET_NODE_CACHE(hook, node->private);
#endif

		priv->orphans = hook;

		return 0;

	/*
	 * Check for a nomatch hook
	 *
	 */
	} else if (strcmp(name, NG_VLAN_HOOK_NOMATCH) == 0) {
		hookpriv_p hpriv;

		/*
		 * Do not connect twice an nomatch hook
		 */
		if (priv->nomatch != NULL)
			return (EISCONN);

		/* Store we are nomatch */
		hpriv = (hookpriv_p) ng_malloc(sizeof(*hpriv), M_NOWAIT | M_ZERO);
		if (!hpriv)
			return ENOMEM;

		hpriv->dscp_enable = 0;
		hpriv->nfmark_enable = 0;
		hpriv->tag = NG_VLAN_TAG_NOMATCH;
		NG_HOOK_SET_PRIVATE(hook, hpriv);
#ifdef NG_NODE_CACHE
		NG_HOOK_SET_NODE_CACHE(hook, node->private);
#endif

		priv->nomatch = hook;

		hook->hook_rcvdata = ng_vlan_rcv_nomatch;

		return 0;

	/*
	 * Check for a lower hook
	 *
	 */
	} else if (strcmp(name, NG_VLAN_HOOK_LOWER) == 0) {
		hookpriv_p hpriv;

		/*
		 * Do not connect twice a lower hook
		 */
		if (priv->lower != NULL)
			return (EISCONN);

		/* XXX: Do I really need this back pointer ?? */
		priv->lower = hook;

		/* Store we are lower */
		hpriv = (hookpriv_p) ng_malloc(sizeof(*hpriv), M_NOWAIT | M_ZERO);
		if (!hpriv)
			return ENOMEM;

		hpriv->dscp_enable = 0;
		hpriv->nfmark_enable = 0;
		hpriv->tag = NG_VLAN_TAG_LOWER;
		NG_HOOK_SET_PRIVATE(hook, hpriv);
#ifdef NG_NODE_CACHE
		NG_HOOK_SET_NODE_CACHE(hook, node->private);
#endif
		hook->hook_rcvdata = ng_vlan_rcv_lower;

		return 0;
	}

	/* Unknown hook name */
	return (EINVAL);
}

/*
 * Receive a control message from ngctl or the netgraph's API
 */
static int
ng_vlan_rcvmsg(node_p node, struct ng_mesg *msg,
	const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_VLAN_COOKIE:
		switch (msg->header.cmd) {
#ifdef NG_VLAN_DEBUG
		case NGM_VLAN_GET_CONFIG:
		    {
			const priv_p priv = NG_NODE_PRIVATE(node);
			struct ng_vlan_config *conf;

			NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			conf = (struct ng_vlan_config *)resp->data;
			*conf = priv->conf;	/* no sanity checking needed */
			break;
		    }
		case NGM_VLAN_SET_CONFIG:
		    {
			const priv_p priv = NG_NODE_PRIVATE(node);
			struct ng_vlan_config * const conf =
				(struct ng_vlan_config *)msg->data;

			if (msg->header.arglen != sizeof(*conf)) {
				error = EINVAL;
				break;
			}
			priv->conf = *conf;
			break;
		    }
#endif
#ifdef NG_VLAN_STATS
		case NGM_VLAN_GET_STATS:
		case NGM_VLAN_CLR_STATS:
		case NGM_VLAN_GETCLR_STATS:
		    {
			const priv_p priv = NG_NODE_PRIVATE(node);
			if (msg->header.cmd != NGM_VLAN_CLR_STATS) {
				NG_MKRESPONSE(resp, msg,
				    sizeof(priv->stats), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				memcpy(resp->data,
				    &priv->stats, sizeof(priv->stats));
			}
			if (msg->header.cmd != NGM_VLAN_GET_STATS)
				memset(&priv->stats, 0, sizeof(priv->stats));
			break;
		    }
#endif
		/* DSCP Commands */
		case NGM_VLAN_DSCP_ENABLE:
		    {
			const priv_p priv = NG_NODE_PRIVATE(node);
			uint16_t *vlan_tag = (uint16_t *) msg->data;
			hookpriv_p hpriv;
			hook_p link_hook;

			if (*vlan_tag < 1 || *vlan_tag >= NG_VLAN_MAX_TAG) {
#ifdef NG_VLAN_DEBUG_DSCP
				log(LOG_DEBUG, "NGM_VLAN_DSCP_ENABLE: VLAN id %d isn't within [1-4094]\n", *vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			if (msg->header.arglen != sizeof(uint16_t)) {
				error = EINVAL;
				break;
			}

			link_hook = priv->links[*vlan_tag];

			if (!link_hook) {
#ifdef NG_VLAN_DEBUG_DSCP
				log(LOG_DEBUG, "NGM_VLAN_DSCP_ENABLE: No VLAN found with id %d\n", *vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			hpriv = (hookpriv_p)NG_HOOK_PRIVATE(link_hook);

#ifdef NG_VLAN_DEBUG_DSCP
			log(LOG_DEBUG, "NGM_VLAN_DSCP_ENABLE: enabling dscp to priority association on VLAN %d\n",
			    *vlan_tag);
#endif

			hpriv->dscp_enable = 1;
			break;
		    }

		case NGM_VLAN_DSCP_DISABLE:
		    {
			const priv_p priv = NG_NODE_PRIVATE(node);
			uint16_t *vlan_tag = (uint16_t *) msg->data;
			hookpriv_p hpriv;
			hook_p link_hook;

			if (*vlan_tag < 1 || *vlan_tag >= NG_VLAN_MAX_TAG) {
#ifdef NG_VLAN_DEBUG_DSCP
				log(LOG_DEBUG, "NGM_VLAN_DSCP_DISABLE: VLAN id %d isn't within [1-4094]\n", *vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			if (msg->header.arglen != sizeof(uint16_t)) {
				error = EINVAL;
				break;
			}

			link_hook = priv->links[*vlan_tag];
			if (!link_hook) {
#ifdef NG_VLAN_DEBUG_DSCP
				log(LOG_DEBUG, "NGM_VLAN_DSCP_DISABLE: No VLAN found with id %d\n", *vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			hpriv = (hookpriv_p)NG_HOOK_PRIVATE(link_hook);

#ifdef NG_VLAN_DEBUG_DSCP
			log(LOG_DEBUG, "NGM_VLAN_DSCP_DISABLE: disabling dscp to priority association on VLAN %d\n",
			    *vlan_tag);
#endif

			hpriv->dscp_enable = 0;
			break;
		    }

#ifdef NG_VLAN_DSCP_PRIO
		/* Takes the vlan_tag as argument, returns the associated dscp to prio table */
		case NGM_VLAN_DSCP_GET_TABLE:
		    {
			const priv_p priv = NG_NODE_PRIVATE(node);
			struct ng_vlan_dscp_table_msg *dscp_to_prio_table_msg = NULL;
			uint16_t *vlan_tag = (uint16_t *) msg->data;
			hookpriv_p hpriv;
			hook_p link_hook;

			if (*vlan_tag < 1 || *vlan_tag >= NG_VLAN_MAX_TAG) {
#ifdef NG_VLAN_DEBUG_DSCP
				log(LOG_DEBUG, "NGM_VLAN_DSCP_GET_TABLE: VLAN id %d isn't within [1-4094]\n", *vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			if (msg->header.arglen != sizeof(uint16_t)) {
				error = EINVAL;
				break;
			}

			link_hook = priv->links[*vlan_tag];
			if (!link_hook) {
#ifdef NG_VLAN_DEBUG_DSCP
				log(LOG_DEBUG, "NGM_VLAN_DSCP_GET_TABLE: No VLAN found with id %d\n", *vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			hpriv = (hookpriv_p)NG_HOOK_PRIVATE(link_hook);

			NG_MKRESPONSE(resp, msg, sizeof(struct ng_vlan_dscp_table_msg), M_NOWAIT);

			if (resp == NULL) {
				error = ENOMEM;
				break;
			}

			dscp_to_prio_table_msg = (struct ng_vlan_dscp_table_msg*)resp->data;

			dscp_to_prio_table_msg->vlan_tag = *vlan_tag;

			memcpy(&(dscp_to_prio_table_msg->dscp_to_priority),
			       &(hpriv->dscp_to_priority),
			       sizeof(dscp_to_prio_table_msg->dscp_to_priority));

			break;
		    }

		case NGM_VLAN_DSCP_SET_TABLE:
		    {
			const priv_p priv = NG_NODE_PRIVATE(node);
			struct ng_vlan_dscp_table_msg *dscp_to_prio_table_msg =
				(struct ng_vlan_dscp_table_msg *) msg->data;
			hookpriv_p hpriv;
			hook_p link_hook;
#ifdef NG_VLAN_DEBUG_DSCP
			int i;
#endif

			if (dscp_to_prio_table_msg->vlan_tag < 1 || dscp_to_prio_table_msg->vlan_tag >= NG_VLAN_MAX_TAG) {
#ifdef NG_VLAN_DEBUG_DSCP
				log(LOG_DEBUG, "NGM_VLAN_DSCP_SET_TABLE: VLAN id %d isn't within [1-4094]\n", dscp_to_prio_table_msg->vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			if (msg->header.arglen != sizeof(struct ng_vlan_dscp_table_msg)) {
				error = EINVAL;
				break;
			}

			link_hook = priv->links[dscp_to_prio_table_msg->vlan_tag];
			if (!link_hook) {
#ifdef NG_VLAN_DEBUG_DSCP
				log(LOG_DEBUG, "NGM_VLAN_DSCP_SET_TABLE: No VLAN found with id %d\n", dscp_to_prio_table_msg->vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			hpriv = (hookpriv_p)
				NG_HOOK_PRIVATE(link_hook);

			memcpy(&(hpriv->dscp_to_priority),
			       &(dscp_to_prio_table_msg->dscp_to_priority),
			       sizeof(hpriv->dscp_to_priority));
#ifdef NG_VLAN_DEBUG_DSCP
			log(LOG_DEBUG, "NGM_VLAN_DSCP_SET_TABLE: changing dscp to priority table for vlan %d\n",
			    dscp_to_prio_table_msg->vlan_tag);

			log(LOG_DEBUG, "NGM_VLAN_DSCP_SET_TABLE: {\n");

			for(i=0 ; i < 8; i++) {
				int j = i * 8;
				log(LOG_DEBUG, "NGM_VLAN_DSCP_SET_TABLE: %.2d:%d, %.2d:%d, %.2d:%d, %.2d:%d, %.2d:%d, %.2d:%d, %.2d:%d, %.2d:%d\n",
				    j, hpriv->dscp_to_priority[j], j+1 , hpriv->dscp_to_priority[j+1], j+2, hpriv->dscp_to_priority[j+2], j+3, hpriv->dscp_to_priority[j+3],
				    j+4, hpriv->dscp_to_priority[j+4], j+5, hpriv->dscp_to_priority[j+5], j+6, hpriv->dscp_to_priority[j+6], j+7, hpriv->dscp_to_priority[j+7]);
			}
			log(LOG_DEBUG, "NGM_VLAN_DSCP_SET_TABLE: }\n");
#endif
			break;
		    }
#endif

		/* NFMARK Commands */
		case NGM_VLAN_NFMARK_ENABLE:
		    {
			const priv_p priv = NG_NODE_PRIVATE(node);
			uint16_t *vlan_tag = (uint16_t *) msg->data;
			hookpriv_p hpriv;
			hook_p link_hook;

			if (*vlan_tag < 1 || *vlan_tag >= NG_VLAN_MAX_TAG) {
#ifdef NG_VLAN_DEBUG_DSCP
				log(LOG_DEBUG, "NGM_VLAN_NFMARK_ENABLE: VLAN id %d isn't within [1-4094]\n", *vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			if (msg->header.arglen != sizeof(uint16_t)) {
				error = EINVAL;
				break;
			}

			link_hook = priv->links[*vlan_tag];
			if (!link_hook) {
#ifdef NG_VLAN_DEBUG_NFMARK
				log(LOG_DEBUG, "NGM_VLAN_NFMARK_ENABLE: No VLAN found with id %d\n", *vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			hpriv = (hookpriv_p)NG_HOOK_PRIVATE(link_hook);

#ifdef NG_VLAN_DEBUG_NFMARK
			log(LOG_DEBUG, "NGM_VLAN_NFMARK_ENABLE: enabling nfmark to priority association on VLAN %d\n",
			    *vlan_tag);
#endif

			hpriv->nfmark_enable = 1;
			break;
		    }

		case NGM_VLAN_NFMARK_DISABLE:
		    {
			const priv_p priv = NG_NODE_PRIVATE(node);
			uint16_t *vlan_tag = (uint16_t *) msg->data;
			hookpriv_p hpriv;
			hook_p link_hook;

			if (*vlan_tag < 1 || *vlan_tag >= NG_VLAN_MAX_TAG) {
#ifdef NG_VLAN_DEBUG_DSCP
				log(LOG_DEBUG, "NGM_VLAN_NFMARK_DISABLE: VLAN id %d isn't within [1-4094]\n", *vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			if (msg->header.arglen != sizeof(uint16_t)) {
				error = EINVAL;
				break;
			}

			link_hook = priv->links[*vlan_tag];
			if (!link_hook) {
#ifdef NG_VLAN_DEBUG_NFMARK
				log(LOG_DEBUG, "NGM_VLAN_NFMARK_DISABLE: No VLAN found with id %d\n", *vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			hpriv = (hookpriv_p)NG_HOOK_PRIVATE(link_hook);

#ifdef NG_VLAN_DEBUG_NFMARK
			log(LOG_DEBUG, "NGM_VLAN_NFMARK_DISABLE: disabling nfmark to priority association on VLAN %d\n",
			    *vlan_tag);
#endif

			hpriv->nfmark_enable = 0;
			break;
		    }

#ifdef NG_VLAN_NFMARK_PRIO
		/* Takes the vlan_tag as argument, returns the associated nfmark to prio table */
		case NGM_VLAN_NFMARK_GET_TABLE:
		    {
			const priv_p priv = NG_NODE_PRIVATE(node);
			struct ng_vlan_nfmark_table_msg *nfmark_to_prio_table_msg = NULL;
			uint16_t *vlan_tag = (uint16_t *) msg->data;
			hookpriv_p hpriv;
			hook_p link_hook;

			if (*vlan_tag < 1 || *vlan_tag >= NG_VLAN_MAX_TAG) {
#ifdef NG_VLAN_DEBUG_DSCP
				log(LOG_DEBUG, "NGM_VLAN_NFMARK_GET_TABLE: VLAN id %d isn't within [1-4094]\n", *vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			if (msg->header.arglen != sizeof(uint16_t)) {
				error = EINVAL;
				break;
			}

			link_hook = priv->links[*vlan_tag];
			if (!link_hook) {
#ifdef NG_VLAN_DEBUG_NFMARK
				log(LOG_DEBUG, "NGM_VLAN_NFMARK_GET_TABLE: No VLAN found with id %d\n", *vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			hpriv = (hookpriv_p)NG_HOOK_PRIVATE(link_hook);

			NG_MKRESPONSE(resp, msg, sizeof(struct ng_vlan_nfmark_table_msg), M_NOWAIT);

			if (resp == NULL) {
				error = ENOMEM;
				break;
			}

			nfmark_to_prio_table_msg = (struct ng_vlan_nfmark_table_msg*)resp->data;

			nfmark_to_prio_table_msg->vlan_tag = *vlan_tag;

			memcpy(&(nfmark_to_prio_table_msg->nfmark_to_priority),
			       &(hpriv->nfmark_to_priority),
			       sizeof(nfmark_to_prio_table_msg->nfmark_to_priority));

			break;
		    }

		case NGM_VLAN_NFMARK_SET_TABLE:
		    {
			const priv_p priv = NG_NODE_PRIVATE(node);
			struct ng_vlan_nfmark_table_msg *nfmark_to_prio_table_msg =
				(struct ng_vlan_nfmark_table_msg *) msg->data;
			hookpriv_p hpriv;
			hook_p link_hook;
#ifdef NG_VLAN_DEBUG_NFMARK
			int i;
#endif

			if (nfmark_to_prio_table_msg->vlan_tag < 1 || nfmark_to_prio_table_msg->vlan_tag >= NG_VLAN_MAX_TAG) {
#ifdef NG_VLAN_DEBUG_DSCP
				log(LOG_DEBUG, "NGM_VLAN_NFMARK_SET_TABLE: VLAN id %d isn't within [1-4094]\n", nfmark_to_prio_table_msg->vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			if (msg->header.arglen != sizeof(struct ng_vlan_nfmark_table_msg)) {
				error = EINVAL;
				break;
			}

			link_hook = priv->links[nfmark_to_prio_table_msg->vlan_tag];
			if (!link_hook) {
#ifdef NG_VLAN_DEBUG_NFMARK
				log(LOG_DEBUG, "NGM_VLAN_NFMARK_SET_TABLE: No VLAN found with id %d\n", nfmark_to_prio_table_msg->vlan_tag);
#endif
				error = EINVAL;
				break;
			}

			hpriv = (hookpriv_p)
				NG_HOOK_PRIVATE(link_hook);

			memcpy(&(hpriv->nfmark_to_priority),
			       &(nfmark_to_prio_table_msg->nfmark_to_priority),
			       sizeof(hpriv->nfmark_to_priority));
#ifdef NG_VLAN_DEBUG_NFMARK
			log(LOG_DEBUG, "NGM_VLAN_NFMARK_SET_TABLE: changing nfmark to priority table for vlan %d\n",
			    nfmark_to_prio_table_msg->vlan_tag);

			log(LOG_DEBUG, "NGM_VLAN_NFMARK_SET_TABLE: {\n");

			for(i=0 ; i < 2; i++) {
				int j = i * 8;
				log(LOG_DEBUG, "NGM_VLAN_NFMARK_SET_TABLE: %.2d:%d, %.2d:%d, %.2d:%d, %.2d:%d, %.2d:%d, %.2d:%d, %.2d:%d, %.2d:%d\n",
				    j, hpriv->nfmark_to_priority[j], j+1 , hpriv->nfmark_to_priority[j+1], j+2, hpriv->nfmark_to_priority[j+2], j+3, hpriv->nfmark_to_priority[j+3],
				    j+4, hpriv->nfmark_to_priority[j+4], j+5, hpriv->nfmark_to_priority[j+5], j+6, hpriv->nfmark_to_priority[j+6], j+7, hpriv->nfmark_to_priority[j+7]);
			}
			log(LOG_DEBUG, "NGM_VLAN_NFMARK_SET_TABLE: }\n");
#endif

			break;
		    }
#endif /* NG_VLAN_NFMARK_PRIO */

#ifdef HAVE_KTABLES
		case NGM_VLAN_NFMARK_GET_INGRESS_KTABLE:
		    {
			const priv_p	priv = NG_NODE_PRIVATE(node);
			uint32_t	*table;

			NG_MKRESPONSE(resp, msg, sizeof(*table), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				log(LOG_CRIT,
					"NGM_VLAN_NFMARK_GET_INGRESS_KTABLE:"
					" Could not allocate response msg\n");
				break;
			}
			table  = (uint32_t *)resp->data;
			if (priv->kt_p == NULL)
				*table = 0;
			else
				*table = priv->kt_p - ng_get_kt_ptr(0);
			break;
		    }

		case NGM_VLAN_NFMARK_SET_INGRESS_KTABLE:
		    {
			const priv_p	priv   = NG_NODE_PRIVATE(node);
			const uint32_t	*table = (uint32_t *)msg->data;

			if (msg->header.arglen != sizeof(*table)) {
				error = EINVAL;
				break;
			}
			if (*table == 0)
				priv->kt_p = NULL;
			else if (*table < CONFIG_KTABLES_MAX_TABLES)
				priv->kt_p = ng_get_kt_ptr(*table);
			else {
				log(LOG_ERR, "Table value exceed kernel table"
					" size (%d)\n", CONFIG_KTABLES_MAX_TABLES);
				error = EINVAL;
				break;
			}
			break;
		    }
#endif /* HAVE_KTABLES */

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

/*
 * Hook disconnection.
 *
 * If all the hooks are removed, let's free itself.
 */
static int
ng_vlan_disconnect(hook_p hook)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);
	hookpriv_p hpriv;

	hpriv = NG_HOOK_PRIVATE(hook);
	/* Zero out hook pointer */
	if (hook == priv->lower) {
		priv->lower = NULL;
		hook->hook_rcvdata = NULL;
	}
	else if (hook == priv->orphans)
		priv->orphans = NULL;
	else if (hook == priv->nomatch) {
		priv->nomatch = NULL;
		hook->hook_rcvdata = NULL;
	}
	else {
		/*
		 * Clean the hash entry
		 */
		NG_KASSERT(priv->links[hpriv->tag] != NULL,
			("%s: no tag %d", __FUNCTION__, hpriv->tag));

		priv->links[hpriv->tag] = NULL;
		hook->hook_rcvdata = NULL;
	}

	NG_HOOK_SET_PRIVATE(hook, NULL);
	ng_free(hpriv);
	/* Go away if no longer connected to anything */
	if (node->numhooks == 0)
		ng_rmnode(node);

	return (0);
}

/*
 * Shutdown node
 *
 * Free the private data.
 *
 * Called at splnet()
 */
static int
ng_vlan_rmnode(node_p node)
{
#ifdef SPLASSERT
	SPLASSERT(net, __FUNCTION__);
#endif

	node->flags |= NG_INVALID;
	ng_cutlinks(node);
	ng_unname(node);

	NG_NODE_SET_PRIVATE(node, NULL);

	/* Unref node */
	NG_NODE_UNREF(node);

	return (0);
}


#ifdef NG_VLAN_DEBUG
static void print_vlan_header(struct vlan_header *vhdr, const priv_p priv, char *str)
{
	/*
	 * As the buffer has been designed specially for this determinist print
	 * I do not test the return value of sprintf. Furthemore this is only
	 * a debug function.
	 */
	char	buf[60];
	int	buflen = 0;

	/* Ether dst and src */
	buflen += sprintf(buf + buflen,
			"dst %02x:%02x:%02x:%02x:%02x:%02x "
			"src %02x:%02x:%02x:%02x:%02x:%02x ",
			vhdr->dhost[0], vhdr->dhost[1], vhdr->dhost[2],
			vhdr->dhost[3], vhdr->dhost[4], vhdr->dhost[5],
			vhdr->shost[0], vhdr->shost[1], vhdr->shost[2],
			vhdr->shost[3], vhdr->shost[4], vhdr->shost[5]);
	/* TPID */
	buflen += sprintf(buf + buflen, "%04x ", vhdr->encap_proto);
	/* TCI (Priority, CI, VLAN Id) */
	buflen += sprintf(buf + buflen, "%01x ", VLAN_PRIOFTAG(vhdr->tag));
	buflen += sprintf(buf + buflen, "%01x ", VLAN_CFIOFTAG(vhdr->tag));
	buflen += sprintf(buf + buflen, "%04x ", VLAN_VLANOFTAG(vhdr->tag));
	/* Ether type */
	buflen += sprintf(buf + buflen, "%04x ", vhdr->proto);

	log(LOG_DEBUG, "%s: %s %s\n", priv->node->name, str, buf);
}
#endif

/*
 * Receive data from lower layers (mainly ethernet)
 * Consume the mbuf and meta.
 *
 * Called at splnet() or splimp()
 */
static int ng_vlan_rcv_lower(hook_p hook, struct mbuf *m, meta_p meta)
{
	struct vlan_header *vhdr = NULL; /* It is not a const because vhdr->proto
					  * gets vhdr->encap_proto
					  */
	const priv_p priv = hook->node_private;
	hook_p ohook;
	uint16_t vlantag = 0;
	uint16_t vlan_tci = 0;
#if defined(__LinuxKernelVNB__) && defined(CONFIG_NET_SKBUFF_SKTAG)
	uint16_t protocol;
#endif
	int error = 0;

	if (!priv) {
		error = ENOTCONN;
		goto drop;
	}

	/*
	 * Update stats
	 */
#ifdef NG_VLAN_STATS
	priv->stats.recvPackets++;
	priv->stats.recvOctets += MBUF_LENGTH(m);
#endif

#if defined(__LinuxKernelVNB__)
	/*
	 * If vlan module is enabled in kernel (even if not loaded),
	 * or if hw vlan offload is enabled, the vlan tag has already
	 * been stripped off the packet.
	 */
	if (vlan_tx_tag_present(m)) {
		vlan_tci = vlan_tx_tag_get(m);
#ifdef CONFIG_NET_SKBUFF_SKTAG
		protocol = m->protocol;
#endif
		goto got_tag;
	}
#endif

	/*
	 * Check ether type
	 */
	vhdr = mtod(m, struct vlan_header *);
	/* vhdr->encap_proto is safe because inside ethernet header */
	if (unlikely(vhdr->encap_proto != htons(VNB_ETHERTYPE_VLAN))) {
		NG_SEND_DATA(error, priv->nomatch, m, meta);
		return error;
	}

	/*
	 * Get initial header
	 */

	if (unlikely((MBUF_LENGTH(m) < sizeof(*vhdr)))) {
#ifdef NG_VLAN_STATS
		priv->stats.recvRunts++;
#endif
		error = EINVAL;
		goto drop;
	}

#if defined(__LinuxKernelVNB__)
	if (!pskb_may_pull(m, sizeof(*vhdr))) {
#ifdef NG_VLAN_STATS
		priv->stats.memoryFailures++;
#endif
		error = EINVAL;
		goto drop;
	}

	if (skb_shared(m) || skb_cloned(m)) {
		struct sk_buff *nskb = skb_copy(m, GFP_ATOMIC);
		kfree_skb(m);
		m = nskb;
	}
	if(m == NULL) {
		error = EINVAL;
#ifdef NG_VLAN_STATS
		priv->stats.memoryFailures++;
#endif
		goto drop;
	}
	vhdr = mtod(m, struct vlan_header *);

#if defined(__LinuxKernelVNB__) && defined(CONFIG_NET_SKBUFF_SKTAG)
	protocol = vhdr->proto;
#endif
#endif
	vlan_tci = ntohs(vhdr->tag);

#ifdef NG_VLAN_DEBUG
	if (priv->conf.debug & NG_VLAN_DEBUG_HEADER)
		print_vlan_header(vhdr, priv, "get VLAN header");
#endif

#if defined(__LinuxKernelVNB__)
got_tag:
#endif
	vlantag = VLAN_VLANOFTAG(vlan_tci);

	/*
	 * Check if the header has some legal values
	 */
	if (unlikely(vlantag < 1 || vlantag >= NG_VLAN_MAX_TAG)) {
#ifdef NG_VLAN_STATS
		priv->stats.recvInvalid++;
#endif
		error = EINVAL;
		goto drop;
	}

	/*
	 * Get the upper hook
	 */
	ohook = priv->links[vlantag];
	if (unlikely(ohook == NULL)) {
#ifdef NG_VLAN_STATS
		priv->stats.recvUnknownTag++;
#endif

		/* if orphans is not connected,
		 * use nomatch and pass it unmodified
		 */
		ohook = priv->orphans;
		if (ohook == NULL) {
			ohook = priv->nomatch;
			/* if nomatch is not connected,
			 * NG_SEND_DATA returns ENOTCONN
			 */
			goto sendit;
		}
	}

	/* Put the VLAN priority into ancillary data for further use */
#if defined(__LinuxKernelVNB__) && defined(CONFIG_NET_SKBUFF_SKTAG)
	{
		uint8_t prio = VLAN_PRIOFTAG(vlan_tci);
		uint32_t tag = prio;

		if (protocol == htons(IP_ETHER_TYPE))
			skb_add_sktag(m, SOL_SOCKET, IP_TAGINFO, NG_VLAN_TAG_NAME,
				      htonl(tag));

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else if (protocol == htons(IP6_ETHER_TYPE))
			skb_add_sktag(m, SOL_SOCKET, IPV6_TAGINFO, NG_VLAN_TAG_NAME,
				      htonl(tag));
#endif
#ifdef HAVE_KTABLES
		if (priv->kt_p != NULL)
			ng_pkt_set_mark(m, priv->kt_p[prio]);
#endif
	}

#elif defined(__FastPath__) && defined(CONFIG_MCORE_M_TAG)
	{
		uint8_t prio = VLAN_PRIOFTAG(ntohs(vhdr->tag));
		uint32_t tag = prio;
		m_tag_add(m, prio_tag_type, htonl(tag));
#ifdef HAVE_KTABLES
		if (priv->kt_p != NULL)
			ng_pkt_set_mark(m, priv->kt_p[prio]);
#endif
	}
#endif

/* #endif */

	/*
	 * Remove the VLAN's encapsulation
	 * m_pullup is not required because the length of the VLAN's header is greater
	 * than the ethernet header.
	 */
#if defined(__LinuxKernelVNB__)
	/* Remove it only if it was not stripped by the kernel */
	if (!vlan_tx_tag_present(m)) {
		vhdr->encap_proto = vhdr->proto;
		memmove(mtod(m, caddr_t) + NG_VLAN_ENCAPLEN, mtod(m, caddr_t),
			sizeof(struct vnb_ether_header));
		m_adj(m, NG_VLAN_ENCAPLEN);
	}
#else
	{
		struct vnb_ether_header *eh;
		uint16_t *vaddr;
		uint16_t addr[6]; /* 2 ethernet addresses */

		/* dhost is followed by shost */
		vaddr = (uint16_t *)&vhdr->dhost;
		addr[0] = vaddr[0];
		addr[1] = vaddr[1];
		addr[2] = vaddr[2];
		addr[3] = vaddr[3];
		addr[4] = vaddr[4];
		addr[5] = vaddr[5];
		m_adj(m, NG_VLAN_ENCAPLEN);
		eh = mtod(m, struct vnb_ether_header *);
		eh->ether_type = vhdr->proto;
		vaddr = (uint16_t *)&eh->ether_dhost;
		vaddr[0] = addr[0];
		vaddr[1] = addr[1];
		vaddr[2] = addr[2];
		vaddr[3] = addr[3];
		vaddr[4] = addr[4];
		vaddr[5] = addr[5];

	}
#endif

sendit:
#if defined(__LinuxKernelVNB__)
	/*
	 * Show that the vlan header was already processed to next
	 * layers
	 */
	m->vlan_tci = 0;
#endif

	/*
	 * Forward data to the output hook : orphan, nomatch or links
	 * The mbuf and meta are consumed by the nodes of the peers.
	 */

	NG_SEND_DATA(error, ohook, m, meta);

	/*
	 * When NG_SEND_DATA fails, the mbuf and meta do not need to be freed because it has already
	 * been done by the peer's node.
	 */
	return error;

drop:
	NG_FREE_DATA(m, meta);
	return (error);
}

/*
 * Add the VLAN tag, then transmit data to the lower layer (mainly ethernet)
 * Consume the mbuf and meta.
 *
 * Called at splnet() or splimp()
 */
static int ng_vlan_rcv_tag(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p priv = hook->node_private;
	const hookpriv_p  hpriv = (hookpriv_p) NG_HOOK_PRIVATE(hook);
	struct vlan_header *vhdr;
	int error;

	if (!priv) {
		error = ENOTCONN;
		goto drop;
	}

	/* hpriv is valid until we free the hook */
	if (!hpriv) {
		error = ENOTCONN;
		goto drop;
	}

	/* Check max length */
	if (MBUF_LENGTH(m) >= (0x10000 - sizeof(*vhdr)))
	{
#ifdef NG_VLAN_STATS
		priv->stats.xmitDataTooBig++;
#endif
		error = EOVERFLOW;
		goto drop;
	}

#if defined(__LinuxKernelVNB__)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	m = vlan_put_tag(m, hpriv->tag);
#else
	m = vlan_put_tag(m, htons(ETH_P_8021Q), hpriv->tag);
#endif

	if (m == NULL) {
#ifdef NG_VLAN_STATS
		priv->stats.memoryFailures++;
#endif
		error = ENOBUFS;
		goto drop;
	}

	vhdr = mtod(m, struct vlan_header *);
	if (unlikely(hpriv->nfmark_enable)) {
#ifdef NG_VLAN_NFMARK_PRIO
		if (NFMARK_IS_VALID(ng_pkt_get_mark(m)))
			vhdr->tag = htons(hpriv->tag | (VLAN_NFMARK_TO_PRIORITY(hpriv, ng_pkt_get_mark(m))));
		else
#endif
			vhdr->tag = htons(hpriv->tag);
	} else if (unlikely(hpriv->dscp_enable)) {
		if (vhdr->proto == htons(IP_ETHER_TYPE)) {
#ifdef NG_VLAN_DSCP_PRIO
			uint8_t dscp;
			struct mini_iphdr* iphdr = (struct mini_iphdr*)(mtod(m, caddr_t) + sizeof(struct vlan_header));
			dscp = iphdr->dscp;
			if (DSCP_IS_VALID(dscp))
				vhdr->tag = htons(hpriv->tag | (VLAN_DSCP_TO_PRIORITY(hpriv, dscp)));
			else
#endif
				vhdr->tag = htons(hpriv->tag);
		} else if (vhdr->proto == htons(IP6_ETHER_TYPE)) {
#ifdef NG_VLAN_DSCP_PRIO
			uint8_t dscp;
			struct mini_ip6hdr* ip6hdr = (struct mini_ip6hdr*)(mtod(m, caddr_t) + sizeof(struct vlan_header));

			dscp = (uint8_t)((ip6hdr->dscp1) << 2 | ((ip6hdr->dscp2)));

			if (DSCP_IS_VALID(dscp))
				vhdr->tag = htons(hpriv->tag | (VLAN_DSCP_TO_PRIORITY(hpriv, dscp)));
			else
#endif
				vhdr->tag = htons(hpriv->tag);
		} else if (vhdr->proto == htons(VLAN_ETHER_TYPE)) {
			uint16_t* next_vlan_tag = (uint16_t*)(mtod(m, caddr_t) + sizeof(struct vlan_header));

			vhdr->tag = htons(hpriv->tag | ((VLAN_PRIOFTAG(ntohs(*next_vlan_tag))) << 13));
		} else {
			vhdr->tag = htons(hpriv->tag);
		}
	} else {
		vhdr->tag = htons(hpriv->tag);
	}

#elif defined(__FastPath__)
	{
		struct vnb_ether_header *eh;
		uint16_t *vaddr;
		uint16_t addr[6]; /* 2 ethernet addresses */
#ifdef NG_VLAN_NFMARK_PRIO
		uint32_t nfmark = 0;
#endif

		eh = mtod(m, struct vnb_ether_header *);
		/* dhost is followed by shost */
		vaddr = (uint16_t *)&eh->ether_dhost;

		addr[0] = vaddr[0];
		addr[1] = vaddr[1];
		addr[2] = vaddr[2];
		addr[3] = vaddr[3];
		addr[4] = vaddr[4];
		addr[5] = vaddr[5];
		M_PREPEND(m, NG_VLAN_ENCAPLEN, M_DONTWAIT);
		if (m == NULL) {
#ifdef NG_VLAN_STATS
			priv->stats.memoryFailures++;
#endif
			error = ENOBUFS;
			goto drop;
		}
		vhdr = mtod(m, struct vlan_header *);
		vhdr->proto = eh->ether_type;
		vhdr->encap_proto = htons(VNB_ETHERTYPE_VLAN);

		if (unlikely(hpriv->nfmark_enable)) {
#ifdef NG_VLAN_NFMARK_PRIO
#ifdef CONFIG_MCORE_M_TAG
			nfmark = ng_pkt_get_mark(m);
#endif
			if (NFMARK_IS_VALID(nfmark))
				vhdr->tag = htons(hpriv->tag | (VLAN_NFMARK_TO_PRIORITY(hpriv, nfmark)));
			else
#endif
				vhdr->tag = htons(hpriv->tag);
		} else if (unlikely(hpriv->dscp_enable)) {
			if (vhdr->proto == htons(IP_ETHER_TYPE)) {
#ifdef NG_VLAN_DSCP_PRIO
				uint8_t dscp;
				struct mini_iphdr* iphdr = (struct mini_iphdr*)(mtod(m, caddr_t) + sizeof(struct vlan_header));
				dscp = iphdr->dscp;

				if (DSCP_IS_VALID(dscp))
					vhdr->tag = htons(hpriv->tag | (VLAN_DSCP_TO_PRIORITY(hpriv, dscp)));
				else
#endif
					vhdr->tag = htons(hpriv->tag);
			} else if (vhdr->proto == htons(IP6_ETHER_TYPE)) {
#ifdef NG_VLAN_DSCP_PRIO
				uint8_t dscp;
				struct mini_ip6hdr* ip6hdr = (struct mini_ip6hdr*)(mtod(m, caddr_t) + sizeof(struct vlan_header));

				dscp = (uint8_t)((ip6hdr->dscp1) << 2 | ((ip6hdr->dscp2)));

				if (DSCP_IS_VALID(dscp))
					vhdr->tag = htons(hpriv->tag | (VLAN_DSCP_TO_PRIORITY(hpriv, dscp)));
				else
#endif
					vhdr->tag = htons(hpriv->tag);
			} else if (vhdr->proto == htons(VNB_ETHERTYPE_VLAN)) {
				uint16_t* next_vlan_tag = (uint16_t*)(mtod(m, caddr_t) + sizeof(struct vlan_header));

				vhdr->tag = htons(hpriv->tag | ((VLAN_PRIOFTAG(ntohs(*next_vlan_tag))) << 13));
			} else {
				vhdr->tag = htons(hpriv->tag);
			}
		} else {
			vhdr->tag = htons(hpriv->tag);
		}

		vaddr = (uint16_t *)&vhdr->dhost;
		vaddr[0] = addr[0];
		vaddr[1] = addr[1];
		vaddr[2] = addr[2];
		vaddr[3] = addr[3];
		vaddr[4] = addr[4];
		vaddr[5] = addr[5];
	}
#endif

#ifdef NG_VLAN_DEBUG
	if (priv->conf.debug & NG_VLAN_DEBUG_HEADER)
		print_vlan_header(vhdr, priv, "add VLAN header");
#endif

#ifdef NG_VLAN_STATS
	/*
	 * Update stats
	 */
	priv->stats.xmitPackets++;
	priv->stats.xmitOctets += MBUF_LENGTH(m);
#endif
	/*
	 * Send packet
	 * The mbuf and meta are consumed by the nodes of the peers.
	 */
	NG_SEND_DATA(error, priv->lower, m, meta);

	/*
	 * When NG_SEND_DATA fails, the mbuf and meta do not need to be freed because it has already
	 * been done by the peer's node.
	 */
	return error;

drop:
	NG_FREE_DATA(m, meta);
	return (error);
}

/*
 * Receive data from nomatch hook
 */
static int
ng_vlan_rcv_nomatch(hook_p hook, struct mbuf *m, meta_p meta)
{
#ifdef NG_NODE_CACHE
	const priv_p priv = (priv_p)NG_HOOK_NODE_CACHE(hook);
#else
	const priv_p priv = hook->node_private;
#endif
	int error;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	/* from no match, pass it downstream unmodified */
	NG_SEND_DATA(error, priv->lower, m, meta);
	return error;
}
