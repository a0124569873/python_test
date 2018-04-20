/*
 * Copyright 2009-2013 6WIND S.A.
 */

/*
 * -- Description of the node --
 *
 * Hook list:
 *   - mux
 *   - orphans
 *   - * (any other name)
 *
 * This node is used to demultiplex ethernet packet (arriving on mux
 * hook) according to source mac address, and optionally vlan to other
 * hooks. The reverse operation is done. This node is used in case of
 * Ethernet over GRE, see details below.
 *
 * #. From ethernet to GRE
 *
 *    Receive a full ethernet packet with or without VLAN tag, and
 *    find the destination hook according to the source MAC address of
 *    the packet (which should correspond to the "MAC destination
 *    address" of the hook configuration) and VLAN tag (if VLAN
 *    ethertype).
 *
 *    If the lookup finds nothing, try another lookup with a
 *    mac-address set to 0:0:0:0:0:0 + vlan (if ethertype is vlan).
 *
 *    If the lookup finds nothing, retry without vlan.
 *
 *    If the lookup still finds nothing, try the lookup with mac addr
 *    = 0:0:0:0:0:0.
 *
 *    If the lookup finds nothing, drop it, at last :)
 *
 *    If inc_mac_header flag is not set on destination hook, remove
 *    ethernet (and vlan if use_vlan is set) header before sending it
 *    to the GRE hook. The original ethertype is sent through META
 *    data to the GRE node.
 *
 *    Else, if inc_mac_header flag is set, forward the packet "as is",
 *    and send ethertype 0x6558 (ETHoGRE) to the GRE node through META
 *    data.
 *
 * #. From GRE to ethernet
 *
 *    Process an IP, IPv6, ARP, Ethernet, ... on a hook from a GRE
 *    node. The ethertype is received through metadata.
 *
 *    - if inc_mac_header is not set, the node prepend 14 bytes (or 18
 *      bytes if use_vlan is set too), and set the ethertypes in ether
 *      (and optionnaly vlan) header(s) according to the META data
 *      received by the GRE node. Else, it assumes that is was part of
 *      the GRE payload (protocol type 0x6558).
 *
 *    - if write_dst_mac is set, it overrides the dst mac address.
 *
 *    - if write_src_mac is set, it overrides the src mac address.
 *
 *    - if use_vlan is set, it overrides the vlan ID.
 *
 *    Note: when write_src_mac is set, the special source value MAC
 *    0:0:0:0:0:0 can be used; it means that ng_ether must set its own
 *    Ethernet MAC address as a source address. The message
 *    **setautosrc** must be sent to the ng_ether node.
 *
 * Conclusion: the MAC destination address will be selected according
 * to the key, because ng_gre has posted the packet to the
 * ng_etherbridge node according to the value of the key.
 *
 */

#if defined(__LinuxKernelVNB__)
#include <linux/module.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/jhash.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <net/checksum.h>

#include <netgraph/vnblinux.h>

#elif defined(__FastPath__)
#include "fp-netgraph.h"
#include "fpn-cksum.h"
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_ether.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_etherbridge.h>

#include <netgraph/vnb_in.h>
#include <netgraph/vnb_ip.h>
#include <netgraph/vnb_ip6.h>
#include <netgraph/vnb_tcp.h>

#ifndef ETHERTYPE_ETHOGRE
#define ETHERTYPE_ETHOGRE 0x6558
#endif

/*
 * NG_ETHERBRIDGE_STATS    to enable packets / bytes counters
 * NG_ETHERBRIDGE_DEBUG    to enable trace in input / output processing
 */
//#define NG_ETHERBRIDGE_DEBUG

#if defined(__LinuxKernelVNB__)
#define NG_ETHERBRIDGE_STATS
#endif

#ifdef NG_ETHERBRIDGE_DEBUG
#define DEBUG_CONFMSG(args...) do {					\
	if (priv->conf.debugFlag & NG_ETHERBRIDGE_DEBUG_CONFMSG) 	\
			log(LOG_DEBUG, args);				\
	} while(0)
#define DEBUG_RCV_MUX(args...) do {					\
	if (priv->conf.debugFlag & NG_ETHERBRIDGE_DEBUG_RCV_MUX) 	\
			log(LOG_DEBUG, args);				\
	} while(0)
#define DEBUG_RCV_DEMUX(args...) do {					\
	if (priv->conf.debugFlag & NG_ETHERBRIDGE_DEBUG_RCV_DEMUX) 	\
			log(LOG_DEBUG, args);				\
	} while(0)
#else
#define DEBUG_CONFMSG(args...) do {} while(0)
#define DEBUG_RCV_MUX(args...) do {} while(0)
#define DEBUG_RCV_DEMUX(args...) do {} while(0)
#endif

#if defined(CONFIG_VNB_ETHERBRIDGE_HASHTABLE_ORDER)
#define ETHERBRIDGE_HASHTABLE_ORDER	CONFIG_VNB_ETHERBRIDGE_HASHTABLE_ORDER
#else
#define ETHERBRIDGE_HASHTABLE_ORDER 	10
#endif
#define ETHERBRIDGE_HASHTABLE_SIZE  	(1<<ETHERBRIDGE_HASHTABLE_ORDER)
#define ETHERBRIDGE_HASHTABLE_MASK  	(ETHERBRIDGE_HASHTABLE_SIZE-1)

LIST_HEAD(etherbridge_list, ng_etherbridge_link_hook_private);

/* Per-node private data */
struct ng_etherbridge_private {
	node_p node;                            /* back pointer to node */

	hook_p  mux;                            /* lower hook */
	hook_p  orphans;                        /* orphans hook */

	struct ng_etherbridge_config conf;      /* node configuration */

	vnb_spinlock_t hlock;                   /* lock for hashtable modifications */
	struct etherbridge_list htable[ETHERBRIDGE_HASHTABLE_SIZE];
	struct etherbridge_list name_htable[ETHERBRIDGE_HASHTABLE_SIZE];
};

typedef struct ng_etherbridge_private *priv_p;

/* Per-link private data */
struct ng_etherbridge_link_hook_private {
	LIST_ENTRY(ng_etherbridge_link_hook_private) hnext;    /* next in hashtable bucket */
	LIST_ENTRY(ng_etherbridge_link_hook_private) hnext_name;   /* next in name hashtable bucket */
	hook_p hook;               /* pointer to associated hook */

	/* configuration */
	int configured;            /* true if hook is configured, and present in htable */
	int write_dst_mac;         /* overrides dst mac addr at xmit */
	int write_src_mac;         /* overrides src mac addr at xmit */
	int use_vlan;              /* true if we use following vlan */
	int inc_mac_header;        /* true if ethhdr is included on GRE side */
	uint8_t dst_mac[VNB_ETHER_ADDR_LEN]; /* destination mac address to use */
	uint8_t src_mac[VNB_ETHER_ADDR_LEN]; /* source mac address to use */
	uint16_t vlan;             /* vlan ID to use, in network order */

#ifdef NG_ETHERBRIDGE_STATS
	struct ng_etherbridge_stats stats[VNB_NR_CPUS];
#endif
};

typedef struct ng_etherbridge_link_hook_private *hookpriv_p;

/*
 * VLAN header
 */
struct vlan_header {
	uint8_t	dhost[VNB_ETHER_ADDR_LEN];  /* Destination MAC address */
	uint8_t	shost[VNB_ETHER_ADDR_LEN];  /* Source MAC address */
	uint16_t encap_proto;     /* = htons(ETHERTYPE_VLAN) */
	uint16_t tag;             /* 1 .. 4094 */
	uint16_t proto;           /* = htons(ETHERTYPE_xxx) */
};

#if defined(__FastPath__) && defined(CONFIG_MCORE_M_TAG)
static VNB_DEFINE_SHARED(int32_t, proto_tag_type);
#endif


/* Local functions */

/* Netgraph node methods */
static ng_constructor_t ng_etherbridge_constructor;
static ng_rcvmsg_t ng_etherbridge_rcvmsg;
static ng_shutdown_t ng_etherbridge_rmnode;
static ng_newhook_t ng_etherbridge_newhook;
static ng_disconnect_t ng_etherbridge_disconnect;
static ng_findhook_t ng_etherbridge_findhook;

static int ng_etherbridge_send_mux(hook_p hook, struct mbuf *m, meta_p meta);
static int ng_etherbridge_rcv_mux(hook_p hook, struct mbuf *m, meta_p meta);
static int ng_etherbridge_rcv_demux(hook_p hook, struct mbuf *m, meta_p meta);

/* Local variables */

/* Parse type for struct ng_etherbridge_config */
static const struct ng_parse_struct_field
ng_etherbridge_config_type_fields[] = NG_ETHERBRIDGE_CONFIG_TYPE_INFO;
static const struct ng_parse_type ng_etherbridge_config_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_etherbridge_config_type_fields
};

#ifdef NG_ETHERBRIDGE_STATS
/* Parse type for struct ng_etherbridge_stats */
static const struct ng_parse_struct_field
ng_etherbridge_stats_type_fields[] = NG_ETHERBRIDGE_STATS_TYPE_INFO;
static const struct ng_parse_type ng_etherbridge_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_etherbridge_stats_type_fields
};
#endif

/* Parse type for struct ng_etherbridge_hookconfig */
static const struct ng_parse_struct_field
ng_etherbridge_hookconfig_type_fields[] = NG_ETHERBRIDGE_HOOKCONFIG_TYPE_INFO;
static const struct ng_parse_type ng_etherbridge_hookconfig_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_etherbridge_hookconfig_type_fields
};


static const struct ng_cmdlist ng_etherbridge_cmdlist[] = {
	{
		.cookie = NGM_ETHERBRIDGE_COOKIE,
		.cmd = NGM_ETHERBRIDGE_SET_CONFIG,
		.name = "setconfig",
		.mesgType = &ng_etherbridge_config_type,
		.respType = NULL,
	},
	{
		.cookie = NGM_ETHERBRIDGE_COOKIE,
		.cmd = NGM_ETHERBRIDGE_GET_CONFIG,
		.name = "getconfig",
		.mesgType = NULL,
		.respType = &ng_etherbridge_config_type,
	},
#ifdef NG_ETHERBRIDGE_STATS
	{
		.cookie = NGM_ETHERBRIDGE_COOKIE,
		.cmd = NGM_ETHERBRIDGE_GET_STATS,
		.name = "getstats",
		.mesgType = &ng_parse_hookbuf_type,
		.respType = &ng_etherbridge_stats_type,
	},
	{
		.cookie = NGM_ETHERBRIDGE_COOKIE,
		.cmd = NGM_ETHERBRIDGE_CLR_STATS,
		.name = "clrstats",
		.mesgType = &ng_parse_hookbuf_type,
		.respType = NULL,
	},
	{
		.cookie = NGM_ETHERBRIDGE_COOKIE,
		.cmd = NGM_ETHERBRIDGE_GETCLR_STATS,
		.name = "getclrstats",
		.mesgType = &ng_parse_hookbuf_type,
		.respType = &ng_etherbridge_stats_type,
	},
#endif
	{
		.cookie = NGM_ETHERBRIDGE_COOKIE,
		.cmd = NGM_ETHERBRIDGE_GET_HOOK_CONFIG,
		.name = "gethookconfig",
		.mesgType = &ng_parse_hookbuf_type,
		.respType = &ng_etherbridge_hookconfig_type,
	},
	{
		.cookie = NGM_ETHERBRIDGE_COOKIE,
		.cmd = NGM_ETHERBRIDGE_SET_HOOK_CONFIG,
		.name = "sethookconfig",
		.mesgType = &ng_etherbridge_hookconfig_type,
		.respType = NULL,
	},

	{ 0, 0, NULL, NULL, NULL }
};

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_etherbridge_typestruct) = {
	.version = NG_VERSION,
	.name = NG_ETHERBRIDGE_NODE_TYPE,
	.mod_event = NULL,                           /* Module event handler (optional) */
	.constructor = ng_etherbridge_constructor,   /* Node constructor */
	.rcvmsg = ng_etherbridge_rcvmsg,             /* control messages come here */
	.shutdown = ng_etherbridge_rmnode,           /* reset, and free resources */
	.newhook = ng_etherbridge_newhook,           /* first notification of new hook */
	.findhook = ng_etherbridge_findhook,         /* only if you have lots of hooks */
	.connect = NULL,                             /* final notification of new hook */
	.afterconnect = NULL,
	.rcvdata = NULL,                             /* only specific receive data functions */
	.rcvdataq = NULL,                            /* only specific receive data functions */
	.disconnect = ng_etherbridge_disconnect,     /* notify on disconnect */
	.rcvexception = NULL,                       /* exceptions come here */
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist = ng_etherbridge_cmdlist,           /* commands we can convert */
};



/* Local functions */

/* on linux, messages can be received from different contexts
 * (syscall, or softirq). We don't want a syscall to be interrupted
 * during a spinlock (causing a deadlock), so we need to use
 * spinlock_bh() */
#ifdef __LinuxKernelVNB__
#define conf_lock(priv) spin_lock_bh(&priv->hlock);
#define conf_unlock(priv) spin_unlock_bh(&priv->hlock);
#else
#define conf_lock(priv) vnb_spinlock_lock(&priv->hlock);
#define conf_unlock(priv) vnb_spinlock_unlock(&priv->hlock);
#endif

/* nodetype initialization */
#ifdef __FastPath__
int ng_etherbridge_init(void)
{
#if !defined(CONFIG_MCORE_M_TAG)
	log(LOG_ERR, "VNB: ng_etherbridge need M_TAG support\n");
	return EINVAL;
#else
        int error;
        void *type = (&ng_etherbridge_typestruct);

        log(LOG_DEBUG, "VNB: Loading ng_etherbridge\n");

        if ((error = ng_newtype(type)) != 0) {
                log(LOG_ERR, "VNB: ng_etherbridge_init failed (%d)\n",error);
                return EINVAL;
        }

	proto_tag_type = m_tag_type_register(PROTO_TAG_NAME);
	if (proto_tag_type == -1) {
		log(LOG_ERR, "VNB: ng_etherbridge cannot register m_tag\n");
		return EINVAL;
	}

        return(0);
#endif
}
#else
NETGRAPH_INIT(etherbridge, &ng_etherbridge_typestruct);
NETGRAPH_EXIT(etherbridge, &ng_etherbridge_typestruct);
#endif

/* return the hash from the MAC addr + vlan */
static inline uint32_t ng_etherbridge_hash_entry(const uint8_t *etheraddr,
						 uint16_t vlan_id)
{
	uint32_t a, b, c;

	a = *(const uint32_t *)etheraddr;
	b = *(const uint32_t *)(etheraddr + 2);
	c = vlan_id;
#if defined(__FastPath__)
        fp_jhash_mix(a, b, c);
#else
        __jhash_mix(a, b, c);
#endif
	return c & ETHERBRIDGE_HASHTABLE_MASK;
}

/* browse the hashtable and lookup for an entry */
static inline hookpriv_p
ng_etherbridge_lookup_entry(const priv_p priv, const uint8_t *etheraddr,
			    uint16_t vlan_id)
{
	hookpriv_p hpriv;
	uint32_t h = ng_etherbridge_hash_entry(etheraddr, vlan_id);
	struct etherbridge_list *bucket = &priv->htable[h];

	LIST_FOREACH(hpriv, bucket, hnext) {
		const void *mac1, *mac2;

		mac1 = hpriv->dst_mac;
		mac2 = etheraddr;

		/* compare mac addr and vlan */
		if ( (*(const uint32_t *)(mac1) == *(const uint32_t *)(mac2)) &&
		     (*(const uint32_t *)(mac1+2) == *(const uint32_t *)(mac2+2)) &&
		     (hpriv->vlan == vlan_id) )
			break;
	}

	return hpriv;
}

/* return the hash from name */
static inline uint32_t ng_etherbridge_hash_name(const char *name)
{
	uint32_t h = 0;
	const u_char *c;

	for (c = (const u_char *)name; *c; c++)
		h += *c;

	return h & ETHERBRIDGE_HASHTABLE_MASK;
}

/* browse the hashtable and lookup for an entry */
static inline hookpriv_p
ng_etherbridge_lookup_by_name(const priv_p priv, const char *name)
{
	struct etherbridge_list *bucket;
	hookpriv_p hpriv;
	uint32_t h;

	h = ng_etherbridge_hash_name(name);
	bucket = &priv->name_htable[h];

	LIST_FOREACH(hpriv, bucket, hnext_name) {
		if (hpriv->hook && strcmp(name, hpriv->hook->name) == 0)
			break;
	}

	return hpriv;
}

#ifdef NG_ETHERBRIDGE_STATS
#define STATS_ADD(hpriv, name, val) do {			\
		hookpriv_p __hpriv = hpriv;			\
		struct ng_etherbridge_stats *stats;		\
		stats = &__hpriv->stats[VNB_CORE_ID()];		\
		stats->name += (val);				\
	} while(0)
#else
#define STATS_ADD(hpriv, name, val) do { } while(0)
#endif

#define STATS_INC(hpriv, name) STATS_ADD(hpriv, name, 1)

/******************************************************************
			NETGRAPH NODE METHODS
******************************************************************/

/*
 * Method for find a hook
 */
static hook_p
ng_etherbridge_findhook(const node_p node, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	hookpriv_p hpriv;

	if (strcmp(name, NG_ETHERBRIDGE_HOOK_ORPHANS) == 0)
		return priv->orphans;
	else if (strcmp(name, NG_ETHERBRIDGE_HOOK_MUX) == 0)
		return priv->mux;

	hpriv = ng_etherbridge_lookup_by_name(priv, name);
	if (hpriv == NULL)
		return NULL;

	return hpriv->hook;
}

/*
 * Node constructor
 */
static int
ng_etherbridge_constructor(node_p * nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int    error;

	/* Call superclass constructor that mallocs *nodep */
	if ((error = ng_make_node_common_and_priv(&ng_etherbridge_typestruct, nodep,
						  &priv, sizeof(*priv), nodeid))) {
		return (error);
	}

	memset(priv, 0, sizeof(*priv));

#if 0 /* done by memset() above */
	int    i;
	for (i=0; i<ETHERBRIDGE_HASHTABLE_SIZE; i++) {
		LIST_INIT(&priv->htable[i]);
		LIST_INIT(&priv->name_htable[i]);
	}
#endif

	vnb_spinlock_init(&priv->hlock);

	memset(&priv->conf, 0, sizeof(priv->conf));

	NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->node = *nodep;

	/* Done */
	return 0;
}

/*
 * Method for attaching a new hook
 */
static int
ng_etherbridge_newhook(node_p node, hook_p hook, const char *name)
{
	uint32_t h;
	struct etherbridge_list *bucket;
	const priv_p priv = NG_NODE_PRIVATE(node);
	hookpriv_p hpriv;

	hook->hook_rcvdata = ng_etherbridge_rcv_demux;

	/* Check for an orphans hook */
	if (strcmp(name, NG_ETHERBRIDGE_HOOK_ORPHANS) == 0) {
		/* Do not connect twice an orphans hook */
		if (priv->orphans != NULL)
			return EISCONN;
		priv->orphans = hook;
		hook->hook_rcvdata = ng_etherbridge_send_mux;
	}

	/* Check for a mux hook */
	else if (strcmp(name, NG_ETHERBRIDGE_HOOK_MUX) == 0) {
		/* Do not connect twice a lower hook */
		if (priv->mux != NULL)
			return EISCONN;
		priv->mux = hook;
		hook->hook_rcvdata = ng_etherbridge_rcv_mux;
	}

	/* Else, the name can be anything except an existing one */
	else if (ng_findhook(node, name))
		return EISCONN;

	hpriv = ng_malloc(sizeof(*hpriv), M_NOWAIT);

	memset(hpriv, 0, sizeof(*hpriv));

	conf_lock(priv);
	/* add the new entry in name hashtable */
	h = ng_etherbridge_hash_name(name);
	DEBUG_CONFMSG("Add in name hashtable, h=0x%x\n", h);
	bucket = &priv->name_htable[h];
	LIST_INSERT_HEAD(bucket, hpriv, hnext_name);

	hpriv->hook = hook;
	NG_HOOK_SET_PRIVATE(hook, hpriv);
	conf_unlock(priv);

	return 0;
}

/* Receive a control message from ngctl or the netgraph's API */
static int
ng_etherbridge_rcvmsg(node_p node, struct ng_mesg *msg,
		      const char *retaddr, struct ng_mesg ** rptr, struct ng_mesg **nl_msg)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int             error = 0;

	switch (msg->header.typecookie) {
		/* Case node id (COOKIE) is suitable */
	case NGM_ETHERBRIDGE_COOKIE:
		switch (msg->header.cmd) {

		case NGM_ETHERBRIDGE_SET_CONFIG: {
			const priv_p priv = NG_NODE_PRIVATE(node);
			struct ng_etherbridge_config * const conf =
				(struct ng_etherbridge_config *)msg->data;

			DEBUG_CONFMSG("SET_CONFIG arglen=%d\n", msg->header.arglen);

			if (msg->header.arglen != sizeof(*conf)) {
				error = EINVAL;
				break;
			}

			priv->conf = *conf;
			break;
		}
		case NGM_ETHERBRIDGE_GET_CONFIG: {
			struct ng_etherbridge_config *conf;

			DEBUG_CONFMSG("GET_CONFIG arglen=%d\n", msg->header.arglen);

			if (msg->header.arglen != 0) {
				error = EINVAL;
				break;
			}

			NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			conf = (struct ng_etherbridge_config *) resp->data;
			*conf = priv->conf;	/* no sanity checking needed */
			break;
		}

#ifdef NG_ETHERBRIDGE_STATS
		case NGM_ETHERBRIDGE_GET_STATS:
		case NGM_ETHERBRIDGE_CLR_STATS:
		case NGM_ETHERBRIDGE_GETCLR_STATS: {
			char *hookname;
			hook_p hook;
			hookpriv_p hpriv;
			struct ng_etherbridge_stats *stats;
			int i;

			DEBUG_CONFMSG("*_STATS cmd=%d arglen=%d\n", msg->header.cmd,
				      msg->header.arglen);

			if (msg->header.arglen != NG_HOOKLEN + 1) {
				error = EINVAL;
				break;
			}
			hookname = msg->data;
			hookname[NG_HOOKLEN] = '\0';

			hook = ng_findhook(node, hookname);
			if (hook == NULL) {
				error = ENOENT;
				break;
			}
			hpriv = NG_HOOK_PRIVATE(hook);

			if (msg->header.cmd != NGM_ETHERBRIDGE_CLR_STATS) {
				NG_MKRESPONSE(resp, msg, sizeof(*stats), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				stats = (struct ng_etherbridge_stats *) resp->data;
				memset(stats, 0, sizeof(*stats));
				for (i=0; i<VNB_NR_CPUS; i++) {
					stats->recvOctets += hpriv->stats[i].recvOctets;
					stats->recvPackets += hpriv->stats[i].recvPackets;
					stats->recvRunts += hpriv->stats[i].recvRunts;
					stats->recvPrependErr += hpriv->stats[i].recvPrependErr;
					stats->xmitOctets += hpriv->stats[i].xmitOctets;
					stats->xmitPackets += hpriv->stats[i].xmitPackets;
				}
			}

			if (msg->header.cmd != NGM_ETHERBRIDGE_GET_STATS) {
				memset(&hpriv->stats, 0, sizeof(*stats));
			}

			break;
		}
#endif

		case NGM_ETHERBRIDGE_GET_HOOK_CONFIG: {
			struct ng_etherbridge_hookconfig *hconf;
			char *hookname;
			hook_p hook;
			hookpriv_p hpriv;

			DEBUG_CONFMSG("GET_HOOK_CONFIG arglen=%d\n", msg->header.arglen);

			if (msg->header.arglen != NG_HOOKLEN + 1) {
				error = EINVAL;
				break;
			}
			hookname = msg->data;
			hookname[NG_HOOKLEN] = '\0';

			hook = ng_findhook(node, hookname);
			if (hook == NULL) {
				error = ENOENT;
				break;
			}
			hpriv = NG_HOOK_PRIVATE(hook);

			NG_MKRESPONSE(resp, msg, sizeof(*hconf), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}

			hconf = (struct ng_etherbridge_hookconfig *)resp->data;
			memset(hconf, 0, sizeof(*hconf));

			/* copy configuration in resp message */

			/* if a configuration with only "0" is
			 * returned (except hookname), the entry is
			 * not configured. */
			strcpy(hconf->hookname, hookname);
			hconf->write_src_mac = hpriv->write_src_mac;
			hconf->write_dst_mac = hpriv->write_dst_mac;
			hconf->use_vlan = hpriv->use_vlan;
			hconf->inc_mac_header = hpriv->inc_mac_header;
			memcpy(hconf->src_mac, hpriv->src_mac, VNB_ETHER_ADDR_LEN);
			memcpy(hconf->dst_mac, hpriv->dst_mac, VNB_ETHER_ADDR_LEN);
			hconf->vlan = ntohs(hpriv->vlan);

			break;
		}

		case NGM_ETHERBRIDGE_SET_HOOK_CONFIG: {
			struct ng_etherbridge_hookconfig *hconf;
			struct etherbridge_list *bucket;
			hook_p hook;
			hookpriv_p hpriv, hpriv_tmp;
			uint32_t h;
			uint16_t vlan_id = 0;
			uint8_t null_mac[VNB_ETHER_ADDR_LEN] = { 0,0,0,0,0,0 };


			DEBUG_CONFMSG("SET_HOOK_CONFIG arglen=%d\n", msg->header.arglen);

			if (msg->header.arglen != sizeof(*hconf)) {
				error = EINVAL;
				break;
			}
			hconf = (struct ng_etherbridge_hookconfig *)msg->data;
			hconf->hookname[NG_HOOKLEN] = '\0';

			hook = ng_findhook(node, hconf->hookname);
			if (hook == NULL) {
				error = ENOENT;
				break;
			}

			DEBUG_CONFMSG("hook found at %p\n", hook);
			hpriv = NG_HOOK_PRIVATE(hook);

			/* dst mac 0:0:0:0:0:0 in compressed mode is not
			 * allowed */
			if (hconf->inc_mac_header == 0 &&
			    memcmp(hconf->dst_mac, null_mac, VNB_ETHER_ADDR_LEN) == 0) {
				DEBUG_CONFMSG("dst mac 0:0:0:0:0:0 + compressed not allowed\n");
				error = EINVAL;
				break;
			}

			if (hconf->use_vlan) {
				vlan_id = hconf->vlan;
				if (vlan_id == 0 || vlan_id > 4095) {
					DEBUG_CONFMSG("Invalid vlan\n");
					error = EINVAL;
					break;
				}
				vlan_id = htons(vlan_id);
			}

			conf_lock(priv);

			/* try to find the same entry, if it already exist */
			hpriv_tmp = ng_etherbridge_lookup_entry(priv, hconf->dst_mac,
								vlan_id);
			if ((hpriv_tmp != NULL) && (hpriv != hpriv_tmp)) {
				DEBUG_CONFMSG("Found another entry with same conf -> EEXIST\n");
				conf_unlock(priv);
				error = EEXIST;
				break;
			}

			/* unlink the entry from htables, and put it in GC */
			if (hpriv->configured) {
				LIST_REMOVE(hpriv, hnext);
			}
			LIST_REMOVE(hpriv, hnext_name);
			ng_free(hpriv);
			hpriv = ng_malloc(sizeof(*hpriv), M_NOWAIT);
			memset(hpriv, 0, sizeof(*hpriv));

			/* fill hook private with new conf */
			hpriv->configured = 1;
			hpriv->write_src_mac = hconf->write_src_mac;
			hpriv->write_dst_mac = hconf->write_dst_mac;
			hpriv->use_vlan = hconf->use_vlan;
			hpriv->inc_mac_header = hconf->inc_mac_header;
			memcpy(hpriv->src_mac, hconf->src_mac, VNB_ETHER_ADDR_LEN);
			memcpy(hpriv->dst_mac, hconf->dst_mac, VNB_ETHER_ADDR_LEN);
			hpriv->vlan = vlan_id;
			hpriv->hook = hook;
			NG_HOOK_SET_PRIVATE(hook, hpriv);

			/* add the new entry in hashtable */
			h = ng_etherbridge_hash_entry(hconf->dst_mac, vlan_id);
			DEBUG_CONFMSG("Add in hashtable, h=0x%x\n", h);
			bucket = &priv->htable[h];
			LIST_INSERT_HEAD(bucket, hpriv, hnext);

			/* remove and add the new entry in name hashtable */
			h = ng_etherbridge_hash_name(hconf->hookname);
			DEBUG_CONFMSG("Add in name hashtable, h=0x%x\n", h);
			bucket = &priv->name_htable[h];
			LIST_INSERT_HEAD(bucket, hpriv, hnext_name);

			conf_unlock(priv);

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

/*
 * Hook disconnection.
 * If all the hooks are removed, let's free itself.
 */
static int
ng_etherbridge_disconnect(hook_p hook)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);
	hookpriv_p hpriv = NG_HOOK_PRIVATE(hook);

	conf_lock(priv);

	NG_HOOK_SET_PRIVATE(hook, NULL);

	hook->hook_rcvdata = NULL;

	if (hook == priv->mux)
		priv->mux = NULL;
	else if (hook == priv->orphans)
		priv->orphans = NULL;

	/* only demux hooks are in main hashtable */
	if (hpriv->configured) {
		DEBUG_CONFMSG("Disconnect: remove entry from hashtable\n");
		LIST_REMOVE(hpriv, hnext);
	}

	DEBUG_CONFMSG("Disconnect: remove entry from name hashtable\n");
	LIST_REMOVE(hpriv, hnext_name);
	ng_free(hpriv);

	conf_unlock(priv);

	/* Go away if no longer connected to anything */
	if (node->numhooks == 0)
		ng_rmnode(node);

	return (0);
}

/*
 * Shutdown node
 * Free the private data.
 */
static int
ng_etherbridge_rmnode(node_p node)
{
	node->flags |= NG_INVALID;
	ng_cutlinks(node);
	ng_unname(node);

	NG_NODE_SET_PRIVATE(node, NULL);

	/* Unref node */
	NG_NODE_UNREF(node);

	return (0);
}

static inline int
ng_etherbridge_send_orphan(const priv_p priv, struct mbuf *m, meta_p meta)
{
	int error = 0;

	if (priv->orphans == NULL) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	STATS_INC(NG_HOOK_PRIVATE(priv->orphans), xmitPackets);
	STATS_ADD(NG_HOOK_PRIVATE(priv->orphans), xmitOctets, MBUF_LENGTH(m));

	NG_SEND_DATA(error, priv->orphans, m, meta);
	return (error);
}

/* Set the tcpmss in the packet. Return 0 on success, and -1 on error
 * (in this case the packet is freed) */
static int
ng_etherbridge_update_tcpmss(const priv_p priv, struct mbuf *m, uint16_t ethertype)
{
	struct vlan_header *vlhdr;
	struct vnb_ip *ip;
	struct vnb_ip6_hdr *ip6;
	struct vnb_tcphdr *tcph;
	unsigned int ipoff = 0, tcpoff = 0;
	unsigned int tcphdrlen;
	uint8_t *opt;
	uint16_t newmss;

	/* parse ethernet/vlan if it's ethernot over gre */
	if (ethertype == htons(ETHERTYPE_ETHOGRE)) {
		m = m_pullup(m, sizeof(struct vnb_ether_header));
		if (unlikely(m == NULL))
			return -1;
		vlhdr = mtod(m, struct vlan_header *);
		if (ethertype == htons(VNB_ETHERTYPE_VLAN)) {
			m = m_pullup(m, sizeof(struct vlan_header));
			if (unlikely(m == NULL))
				return -1;
			ethertype = vlhdr->proto;
			ipoff = sizeof(struct vlan_header);
		}
		else {
			ethertype = vlhdr->encap_proto;
			ipoff = sizeof(struct vnb_ether_header);
		}
	}
	else if (ethertype == htons(VNB_ETHERTYPE_VLAN)) {
		m = m_pullup(m, 4); /* sizeof vlan header without ethernet */
		if (unlikely(m == NULL))
			return -1;
		ethertype = *mtod(m, uint16_t *); /* proto in vlan hdr */
		ipoff = 4; /* sizeof vlan hdr */
	}

	/* IP or IPv6 header is at ipoff */
	if (ethertype == htons(VNB_ETHERTYPE_IP)) {
		m = m_pullup(m, sizeof(struct vnb_ip) + ipoff);
		if (unlikely(m == NULL))
			return -1;
		ip = (struct vnb_ip *)(mtod(m, void *) + ipoff);
		tcpoff = ip->ip_hl * 4 + ipoff;
		newmss = priv->conf.tcp4mss;
		if (ip->ip_p != VNB_IPPROTO_TCP)
			return 0;
	}
	else if (ethertype == htons(VNB_ETHERTYPE_IPV6)) {
		m = m_pullup(m, sizeof(struct vnb_ip6_hdr) + ipoff);
		if (unlikely(m == NULL))
			return -1;
		ip6 = (struct vnb_ip6_hdr *)(mtod(m, void *) + ipoff);
		/* don't parse packets with extension hdrs */
		if (ip6->ip6_nxt != VNB_IPPROTO_TCP)
			return 0;
		tcpoff = ipoff + sizeof(struct vnb_ip6_hdr);
		newmss = priv->conf.tcp6mss;
	}
	else {
		return 0;
	}

	/* TCP header is at tcpoff */
	m = m_pullup(m, sizeof(struct vnb_tcphdr) + tcpoff);
	if (unlikely(m == NULL))
		return -1;
	tcph = (struct vnb_tcphdr *)(mtod(m, void *) + tcpoff);
	/* only SYN packets */
	if (!(tcph->th_flags & TH_SYN))
		return 0;
	tcphdrlen = tcph->th_off * 4;
	if (tcphdrlen < sizeof(struct vnb_tcphdr))
		return 0;

	/* parse options */
	m = m_pullup(m, tcphdrlen + tcpoff);
	if (unlikely(m == NULL))
		return -1;
	opt = ((u_int8_t *)tcph) + sizeof(struct vnb_tcphdr);
	while (opt < (((u_int8_t *)tcph) + tcphdrlen)) {
		uint8_t type = opt[0];
		uint8_t size = opt[1];
		int odd;
		if (type == 0)
			break;
		if (size <= 1)
			break;
		if (type == VNB_TCPOPT_MSS && size == VNB_TCPOLEN_MSS) {
			u_int16_t oldmss;
			oldmss = ntohs(*(uint16_t *)(opt+2));
			/* don't increase MSS */
			if (oldmss <= newmss)
				return 0;
			*(uint16_t *)(opt+2) = htons(newmss);
			if (((long)opt - (long)tcph) & 1)
				odd = 1;
			else
				odd = 0;

			/* process partial TCP checksum after update
			 * of MSS option */
#ifdef __FastPath__
			tcph->th_sum = fpn_cksum_replace2(tcph->th_sum, htons(oldmss),
							htons(newmss), odd);
#else
			inet_proto_csum_replace2(&tcph->th_sum, m,
						 htons(oldmss), htons(newmss), 0);
			(void)odd;
#endif
			break;
		}
		opt += size;
	}

	return 0;
}

/*
 * Send data on specified demux hook
 */
static inline int
ng_etherbridge_send_demux(const priv_p priv, const hookpriv_p hpriv, struct mbuf *m,
			  meta_p meta, uint16_t ethertype)
{
	hook_p dst_hook;
	int error = 0;

	dst_hook = hpriv->hook;
	if (dst_hook == NULL) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	if (hpriv->inc_mac_header) {
		ethertype = htons(ETHERTYPE_ETHOGRE);
	}
	else {
		if (hpriv->use_vlan)
			m_adj(m, sizeof(struct vlan_header));
		else
			m_adj(m, sizeof(struct vnb_ether_header));
	}

	DEBUG_RCV_MUX("Send ethertype [0x%x] in mtag to hook %s\n", ntohs(ethertype), dst_hook->name);

	/* attach a tag to the packet */
#if defined(__FastPath__) && defined(CONFIG_MCORE_M_TAG)
	if (likely(proto_tag_type >= 0)) {
		uint32_t tag;
		tag = htonl(ntohs(ethertype));
		m_tag_add(m, proto_tag_type, tag);
	}
#elif defined(__LinuxKernelVNB__)
	*(uint32_t *)m->cb = PROTO_CB_MAGIC;
	*(uint16_t *)(m->cb + 4) = ethertype;
#endif

	/* update tcpmss if needed */
	if (priv->conf.tcp4mss || priv->conf.tcp6mss) {
		if (ng_etherbridge_update_tcpmss(priv, m, ethertype)) {
			/* mbuf is already freed */
			NG_FREE_META(meta);
			STATS_INC(hpriv, recvRunts);
			return ENOBUFS;
		}
	}

	STATS_INC(hpriv, xmitPackets);
	STATS_ADD(hpriv, xmitOctets, MBUF_LENGTH(m));

	NG_SEND_DATA(error, dst_hook, m, meta);
	return error;
}

/*
 * Send data on mux
 */
static int
ng_etherbridge_send_mux(hook_p hook, struct mbuf *m, meta_p meta)
{
	int error = 0;
	hook_p dst_hook;
	const priv_p priv = hook->node_private;
	hookpriv_p hpriv, dst_hpriv;

	if (priv == NULL) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	hpriv = NG_HOOK_PRIVATE(hook);
	if (hpriv == NULL) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	STATS_INC(hpriv, recvPackets);
	STATS_ADD(hpriv, recvOctets, MBUF_LENGTH(m));

	dst_hook = priv->mux;
	if (dst_hook == NULL) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	dst_hpriv = NG_HOOK_PRIVATE(dst_hook);
	if (dst_hpriv == NULL) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	STATS_INC(dst_hpriv, xmitPackets);
	STATS_ADD(dst_hpriv, xmitOctets, MBUF_LENGTH(m));

	NG_SEND_DATA(error, dst_hook, m, meta);
	return error;
}

/*
 * Receive data from mux
 */
static int
ng_etherbridge_rcv_mux(hook_p hook, struct mbuf *m, meta_p meta)
{
	struct vlan_header *vlhdr;
	const priv_p priv = hook->node_private;
	hookpriv_p hpriv, dst_hpriv = NULL;
	uint16_t vlan_id = 0;
	uint16_t ethertype, ethertype_vlan;
	uint8_t null_mac[VNB_ETHER_ADDR_LEN] = { 0,0,0,0,0,0 };

	if (priv == NULL) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	hpriv = NG_HOOK_PRIVATE(hook);
	if (hpriv == NULL) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	STATS_INC(hpriv, recvPackets);
	STATS_ADD(hpriv, recvOctets, MBUF_LENGTH(m));

	DEBUG_RCV_MUX("Received a packet on mux\n");

	m = m_pullup(m, sizeof(struct vnb_ether_header));
	if (m == NULL) {
		DEBUG_RCV_MUX("Cannot m_pull()\n");
		NG_FREE_META(meta);
		STATS_INC(hpriv, recvRunts);
		return ENOBUFS;
	}

	vlhdr = mtod(m, struct vlan_header *);
	ethertype = vlhdr->encap_proto;
	if (ethertype == htons(VNB_ETHERTYPE_VLAN)) {
		m = m_pullup(m, sizeof(struct vlan_header));
		if (m == NULL) {
			DEBUG_RCV_MUX("Cannot m_pull()\n");
			/* mbuf is already freed */
			NG_FREE_META(meta);
			STATS_INC(hpriv, recvRunts);
			return ENOBUFS;
		}
		vlan_id = vlhdr->tag & htons(0xFFF);
		DEBUG_RCV_MUX("vlan id = %d\n", ntohs(vlan_id));
		ethertype_vlan = vlhdr->proto;
	}

	/* try with vlan */
	if (vlan_id != 0) {
		dst_hpriv = ng_etherbridge_lookup_entry(priv, vlhdr->shost, vlan_id);
		if (dst_hpriv) {
			DEBUG_RCV_MUX("Destination is demux (mac + vlan)\n");
			return ng_etherbridge_send_demux(priv, dst_hpriv, m, meta,
							 ethertype_vlan);
		}

		/* try with any mac addr */
		dst_hpriv = ng_etherbridge_lookup_entry(priv, null_mac, vlan_id);
		if (dst_hpriv) {
			DEBUG_RCV_MUX("Destination is demux (any mac + vlan)\n");
			return ng_etherbridge_send_demux(priv, dst_hpriv, m, meta,
							 ethertype_vlan);
		}
	}

	/* try without vlan */
	dst_hpriv = ng_etherbridge_lookup_entry(priv, vlhdr->shost, 0);
	if (dst_hpriv) {
		DEBUG_RCV_MUX("Destination is demux (mac, no vlan)\n");
		return ng_etherbridge_send_demux(priv, dst_hpriv, m, meta, ethertype);
	}

	/* try with any mac addr without vlan */
	dst_hpriv = ng_etherbridge_lookup_entry(priv, null_mac, 0);
	if (dst_hpriv) {
		DEBUG_RCV_MUX("Destination is demux (any mac, no vlan)\n");
		return ng_etherbridge_send_demux(priv, dst_hpriv, m, meta, ethertype);
	}

	/* not found, send to orphan hook */
	DEBUG_RCV_MUX("Destination is orphan\n");
	return ng_etherbridge_send_orphan(priv, m, meta);
}

/* Retrieve ethertype stored as metadata attached to the mbuf. It is
 * stored in network order. */
static inline void ng_etherbridge_get_proto_mtag(struct mbuf *m, uint16_t *ethertype)
{
#if defined(__FastPath__) && defined(CONFIG_MCORE_M_TAG)
	uint32_t tag;
	if (m_tag_get(m, proto_tag_type, &tag) == 0) {
		*ethertype = htons(ntohl(tag));
		m_tag_del(m, proto_tag_type);
	}
#elif defined(__LinuxKernelVNB__)
	if (*(uint32_t *)m->cb == PROTO_CB_MAGIC) {
		*ethertype = *(uint16_t *)(m->cb + 4);
		*(uint32_t *)m->cb = 0;
	}
#endif
}

/*
 * Receive data from mux
 */
static int
ng_etherbridge_rcv_demux(hook_p hook, struct mbuf *m, meta_p meta)
{
	uint16_t ethertype = htons(VNB_ETHERTYPE_IP); /* default is IP */
	struct vlan_header *vlhdr;
	const priv_p priv = hook->node_private;
	hookpriv_p hpriv;

	if (priv == NULL) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	hpriv = NG_HOOK_PRIVATE(hook);
	if (hpriv == NULL) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	STATS_INC(hpriv, recvPackets);
	STATS_ADD(hpriv, recvOctets, MBUF_LENGTH(m));

	DEBUG_RCV_MUX("Received a packet on demux\n");

	/* retrieve ethertype from meta data */
	ng_etherbridge_get_proto_mtag(m, &ethertype);

	DEBUG_RCV_MUX("Ethertype is 0x%x\n", ntohs(ethertype));

	/* update tcpmss if needed */
	if (priv->conf.tcp4mss || priv->conf.tcp6mss) {
		if (ng_etherbridge_update_tcpmss(priv, m, ethertype)) {
			/* mbuf is already freed */
			NG_FREE_META(meta);
			STATS_INC(hpriv, recvRunts);
			return ENOBUFS;
		}
	}

	/* prepend a new ether header (optionally vlan) */
	if (hpriv->inc_mac_header == 0) {

		if (hpriv->use_vlan)
			M_PREPEND(m, sizeof(struct vlan_header), M_DONTWAIT);
		else
			M_PREPEND(m, sizeof(struct vnb_ether_header), M_DONTWAIT);

		if (m == NULL) {
			DEBUG_RCV_DEMUX("Cannot prepend\n");
			/* mbuf is already freed */
			NG_FREE_META(meta);
			STATS_INC(hpriv, recvPrependErr);
			return ENOBUFS;
		}

		/* If write_src_mac is 0, we must reset the mac addr
		 * to 0. Dst addr and proto will be overriden in any
		 * case. */
		vlhdr = mtod(m, struct vlan_header *);
		if (!hpriv->write_src_mac) {
			void *shost = vlhdr->shost;
			*(uint32_t *)shost = 0;
			*(uint32_t *)(shost+2) = 0;
		}
	}
	/* else, just check that we can m_pull() */
	else {
		vlhdr = mtod(m, struct vlan_header *);
		if (hpriv->use_vlan)
			m = m_pullup(m, sizeof(struct vlan_header));
		else
			m = m_pullup(m, sizeof(struct vnb_ether_header));
		if (m == NULL) {
			DEBUG_RCV_DEMUX("Cannot m_pull()\n");
			/* mbuf is already freed */
			NG_FREE_META(meta);
			STATS_INC(hpriv, recvRunts);
			return ENOBUFS;
		}
	}

	if (hpriv->write_dst_mac) {
		void *dhost = vlhdr->dhost;
		const void *dst_mac = hpriv->dst_mac;
		*(uint32_t *)dhost = *(const uint32_t *)dst_mac;
		*(uint32_t *)(dhost+2) = *(const uint32_t *)(dst_mac+2);
	}
	if (hpriv->write_src_mac) {
		void *shost = vlhdr->shost;
		const void *src_mac = hpriv->src_mac;
		*(uint32_t *)shost = *(const uint32_t *)src_mac;
		*(uint32_t *)(shost+2) = *(const uint32_t *)(src_mac+2);
	}
	if (hpriv->use_vlan) {
		if (hpriv->inc_mac_header == 0) {
			vlhdr->encap_proto = htons(VNB_ETHERTYPE_VLAN);
			vlhdr->tag = hpriv->vlan;
			vlhdr->proto = ethertype;
		}
	}
	else {
		if (hpriv->inc_mac_header == 0)
			vlhdr->encap_proto = ethertype;
	}

	DEBUG_RCV_MUX("Send on mux\n");
	return ng_etherbridge_send_mux(hook, m, meta);
}

#if defined(__LinuxKernelVNB__)
module_init(ng_etherbridge_init);
module_exit(ng_etherbridge_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB etherbridge node");
MODULE_LICENSE("6WIND");
#endif
