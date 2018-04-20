/*
 * Copyright 2010-2013 6WIND S.A.
 */

#if defined(__LinuxKernelVNB__)
#include <linux/version.h>
#include <linux/module.h>
#include <linux/in6.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <netgraph/vnblinux.h>

#include <linux/ip.h>
#include <linux/udp.h>

#elif defined(__FastPath__)
#include "fp-netgraph.h"
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_gtpu.h>

/* compilation option for using the packet queuing feature */
#define GTPU_PACKET_QUEUES

#if (defined GTPU_PACKET_QUEUES) && (defined __FastPath__)
#include <netgraph/ng_gtpu_pktq.h>

/* example packet queuing configuration */
/* number of possible queues */
#define PKTQ_NUM_QUEUES		(1<<8)
/* maximum age for queued packets (in ms)) */
#define PKTQ_DELAY_MS		(30*1000)
/* number of saved packets in a queue */
#define PKTQ_PKTS_PERQ		(256)
/* periodic interval for draining the packet queues (in sec)) */
#define PKTQ_GC_DELAY		(2)
#endif

#define DEBUG_GTPU 0
#if DEBUG_GTPU >= 1
#ifdef __LinuxKernelVNB__
#define DEBUG(x, y...) do { \
		log(LOG_DEBUG, "%s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#else
/* for now : force DEBUG output */
#define DEBUG(x, y...) do { \
		log(LOG_ERR, "FP %s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#endif
#else
#define DEBUG(x, y...) do {} while(0)
#endif

/* compilation option for using a TEID to upper hook cache */
#define	GTPU_TEID_CACHE

/*
 * Types of hooks connecting with ng_gtpu
 */
enum hook_type_t {
	UPPER_HOOK_TYPE=1,	/* for upper hook */
	LOWER_HOOK_TYPE,	/* for lower_tx */
	LOWER_RX_HOOK_TYPE,	/* for lower_rx */
	NOMATCH_HOOK_TYPE	/* for nomatch */
};

/*
 * combined hashtable size limit : 2K entries
 * this value can be increased (for example : 17 for 128k entries)
 *
 * NB : the same value must be used in the kernel VNB and the fast path VNB
 */
#if defined(CONFIG_VNB_GTPU_MAX_HASH_ORDER)
#define GTPU_MAX_HASH_ORDER	CONFIG_VNB_GTPU_MAX_HASH_ORDER
#else
#define GTPU_MAX_HASH_ORDER	11
#endif

/* UPPER hash used for ng_gtpu_findhook */
#define	UPPER_HASH_ORDER GTPU_MAX_HASH_ORDER
#define	UPPER_HASHSIZE	(1 << UPPER_HASH_ORDER)
#define	UPPER_HASHMASK	(UPPER_HASHSIZE - 1)
/* very simple hash function */
#define	UPPER_HASH(upper_idx)	((upper_idx) & UPPER_HASHMASK)

/* TEID hash used for demultiplexing the incoming encapsulated packets */
#define	TEID_HASH_ORDER	GTPU_MAX_HASH_ORDER
#define	TEID_HASHSIZE	(1 << TEID_HASH_ORDER)
#define	TEID_HASHMASK	(TEID_HASHSIZE - 1)
/* very simple hash function */
#define	TEID_HASH(teid)	((teid) & TEID_HASHMASK)

/*
 * Private config for one tunnel (one upper hook)
 * the same struct used in the hook private and for the hashtable
 */
struct ng_pdp_ctxt_filter {
	LIST_ENTRY(ng_pdp_ctxt_filter) next_hash;
	hook_p		gtpu_upper;    /* pointer to configured upper */
	uint32_t	teid_rx;
	enum hook_type_t type;
	LIST_ENTRY(ng_pdp_ctxt_filter) next_lower;
	hook_p		gtpu_lower_tx; /* [k] lower hook connection => K for the xGSN peers */
	uint32_t	teid_tx;
	uint8_t		tos;
	LIST_ENTRY(ng_pdp_ctxt_filter) next_findhook;
	uint32_t	tag;
	hook_p		self;          /* pointer to self */
	/* seq number : two values for each tunnel */
	uint32_t	seqn_tx;
	uint32_t	seqn_rx;
	/* later : Private stats for each tunnel */
	uint8_t		flags_tx;      /* tunnel flags */
#if (defined GTPU_PACKET_QUEUES) && (defined __FastPath__)
	int		pktq_idx; /* packet queue index, -1 unused */
#endif
};
#ifdef GTPU_TEID_CACHE
struct ng_pdp_ctxt_cache {
	/* bucket cache : store the tag+hook for the head of the linked list */
	hook_p		head_hook;    /* pointer to configured upper */
	uint32_t	head_tag;
};
#endif
/* chained list of pointers to PDP context structs */
LIST_HEAD(filter_head, ng_pdp_ctxt_filter);
struct ng_pdp_ctxt_bucket {
	struct filter_head head;   /* the list of entries for this hash */
	/* later : possible optimization : conf_lock + stats_lock */
	/* bucket lock == tunnel_lock */
	vnb_rwlock_t lock;
};

/*
 * Private config for one Tx socket (one lower_tx hook)
 * the struct contains links to all tunnels (uppers) using this lower_tx
 */
struct lower_tx_private {
	LIST_ENTRY(lower_tx_private) next_lower;
	hook_p		self; /* pointer to self */
	uint32_t	tag;
	struct filter_head head;   /* the list of pdp contexts using this lower_tx */
	vnb_rwlock_t lock;         /* lock for bucket access */
	enum hook_type_t type;
};

/* chained list of pointers to lower_tx */
LIST_HEAD(lower_head, lower_tx_private);
struct ng_lower_bucket {
	struct lower_head head;   /* the list of entries for this hash */
	/* bucket lock == lower_lock */
	vnb_rwlock_t lock;
};

/* Per-node private data */
struct ng_gtpu_private {
	node_p		gtpu_node;     /* back pointer to node */
#ifdef NG_GTPU_STATS
	/*
	 * later : define per-tunnel stats AND per-node stats
	 * later : also define per-CPU stats to avoid locking
	 */
	struct ng_gtpu_stats	stats;		/* node stats */
#endif
	hook_p		gtpu_lower_rx; /* lower hook connection => single, bound on port 2152 */
	hook_p		gtpu_nomatch;  /* hook for incoming packets with unmatched TEID */
	/* req sent : waiting for reply */
	uint32_t	rep_seen;
	/* node_lock in per-node private data */
	vnb_spinlock_t	node_lock;
	/* number of entries in the hashtable == number of tunnels */
	uint32_t	nent;
	/* in node : TEID hash table */
	struct ng_pdp_ctxt_bucket *pdp_hashtable;
#ifdef GTPU_TEID_CACHE
	struct ng_pdp_ctxt_cache  *pdp_cache;
#endif
	/* in node : findhook hash table */
	struct ng_pdp_ctxt_bucket *findhook_hashtable;
	/* linked list of lower_tx */
	struct ng_lower_bucket lower_list;
#if (defined GTPU_PACKET_QUEUES) && (defined __FastPath__)
	gtpu_pktq_cfg_t cfg;
#endif
};
typedef struct ng_gtpu_private *priv_p;

#if (defined GTPU_PACKET_QUEUES) && (defined __FastPath__)
/*
 * the code of this functions is directly derived from
 * ng_gtpu_rcvdata_upper(const hook_p hook, struct mbuf *m, meta_p meta)
 */
static int
gtpu_pktq_cb(void *arg, struct mbuf*m, meta_p meta)
{
	struct ng_pdp_ctxt_filter * hpriv = arg;
	int error = 0;
	struct gtu_v1_hdr *hdr;
	uint16_t length_ori;
#ifdef NG_GTPU_STATS
	priv_p priv = NULL;
#endif

	if (unlikely(!hpriv || !hpriv->gtpu_upper || !m)) {
		log(LOG_ERR, "%s:%d gtpu upper is NULL\n", __func__,__LINE__);
		error = ENOTCONN;
		goto drop;
	}

	length_ori = MBUF_LENGTH(m);
	/* if the tunnel is configured, prepare correct header */
	/* later : variable length for the header : parse the flags_tx */
	M_PREPEND(m, sizeof(struct gtu_v1_hdr), M_DONTWAIT);
	if (unlikely(!m)) {
		log(LOG_ERR, "%s:%d gtpu_upper: no memory\n", __func__,__LINE__);
		error = ENOBUFS;
		goto drop;
	}

	hdr = mtod(m, struct gtu_v1_hdr *);
	/* set message type */
	hdr->message_type = NGM_GTPU_DATA_PACKET;
	hdr->length = htons(length_ori);
	hdr->teid = htonl(hpriv->teid_tx);
	hdr->flags = hpriv->flags_tx; 			/* flags for this tunnel */

#ifdef NG_GTPU_STATS
	priv = hpriv->gtpu_upper->node_private;
	STATS_INC(priv, xmitPackets);
	STATS_ADD(priv, xmitOctets, MBUF_LENGTH(m));
#endif

	/* for tunnels with non-default TOS value */
	if (hpriv->tos) {
		/* TOS change for packets forwarded by the Fastpath */
		m_priv(m)->flags |= M_TOS;
		m_priv(m)->tos = hpriv->tos;
	}
	DEBUG("%d send queue packet mbuf=%p,meta=%p\n",__LINE__,m,meta);
	NG_SEND_DATA(error, hpriv->gtpu_lower_tx, m, meta);

	return 0;

drop:
	NG_FREE_DATA(m, meta);
	return error;
}
#endif

/*
 * Netgraph node methods
 */
static ng_constructor_t ng_gtpu_constructor;
static ng_rcvmsg_t      ng_gtpu_rcvmsg;
static ng_newhook_t     ng_gtpu_newhook;
static ng_shutdown_t    ng_gtpu_rmnode;
static ng_disconnect_t  ng_gtpu_disconnect;
static ng_findhook_t    ng_gtpu_findhook;

static int
ng_gtpu_rcvdata_lower_rx(const hook_p hook, struct mbuf *m, meta_p meta);
static int
ng_gtpu_rcvdata_upper(const hook_p hook, struct mbuf *m, meta_p meta);
static int
ng_gtpu_rcvdata_lower_tx(const hook_p hook, struct mbuf *m, meta_p meta);

#ifdef NG_GTPU_STATS
/* Parse type for struct ng_gtpu_stats */
static const struct ng_parse_struct_field
	ng_gtpu_stats_type_fields[] = NG_GTPU_STATS_TYPE_INFO;
static const struct ng_parse_type ng_gtpu_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_gtpu_stats_type_fields
};
#endif
/* Type for a generic struct pdp_context */
static const struct ng_parse_struct_field
    ng_parse_pdp_context_type_fields[] = NG_GTPU_PDP_CTXT_TYPE_INFO;
static const struct ng_parse_type ng_parse_pdp_context_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_parse_pdp_context_type_fields,
};

static const struct ng_parse_struct_field
    ng_parse_pdp_context_del_fields[] = NG_GTPU_PDP_DEL_INFO;
static const struct ng_parse_type ng_parse_pdp_del_info = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_parse_pdp_context_del_fields,
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_gtpu_cmdlist[] = {
	/* later : request/reply per tunnel */
	{
		.cookie = NGM_GTPU_COOKIE,
		.cmd = NGM_GTPU_SET_REQ,
		.name = "setreq",
		.mesgType = NULL,
		.respType = NULL
	},
	/* later : request/reply per tunnel */
	{
		.cookie = NGM_GTPU_COOKIE,
		.cmd = NGM_GTPU_GET_REPLY,
		.name = "getrep",
		.mesgType = NULL,
		.respType = &ng_parse_uint32_type
	},
#ifdef NG_GTPU_STATS
	/* later : stats per tunnel */
	{
		.cookie = NGM_GTPU_COOKIE,
		.cmd = NGM_GTPU_GET_STATS,
		.name = "getstats",
		.mesgType = NULL,
		.respType = &ng_gtpu_stats_type
	},
	{
		.cookie = NGM_GTPU_COOKIE,
		.cmd = NGM_GTPU_CLR_STATS,
		.name = "clrstats",
		.mesgType = NULL,
		.respType = NULL
	},
	{
		.cookie = NGM_GTPU_COOKIE,
		.cmd = NGM_GTPU_GETCLR_STATS,
		.name = "getclrstats",
		.mesgType = NULL,
		.respType = &ng_gtpu_stats_type
	},
#endif
	/*
	 * command for associating upper[i], outgoing TEID and lower_tx[j]
	 * store info into upper[i]->priv
	 * and for associating incoming TEID and upper[i]
	 * store pointer to info into hashtable in lower_rx
	 */
	{
		.cookie = NGM_GTPU_COOKIE,
		.cmd = NGM_GTPU_ADDPDP_CTXT,
		.name = "addpdp",
		.mesgType = &ng_parse_pdp_context_type,
		.respType = NULL
	},
	{
		.cookie = NGM_GTPU_COOKIE,
		.cmd = NGM_GTPU_DELPDP_CTXT,
		.name = "delpdp",
		.mesgType = &ng_parse_pdp_del_info,
		.respType = NULL
	},
	{
		.cookie = NGM_GTPU_COOKIE,
		.cmd = NGM_GTPU_GET_CONFIG,
		.name = "getpdp",
		.mesgType = &ng_parse_hookbuf_type,
		.respType = &ng_parse_string_type
	},
	{
		.cookie = NGM_GTPU_COOKIE,
		.cmd = NGM_GTPU_UPDPDP_CTXT,
		.name = "updatepdp",
		.mesgType = &ng_parse_pdp_context_type,
		.respType = NULL
	},
	{ 0, 0, NULL, NULL, NULL }
};

/*
 * Node type descriptor
 */
static VNB_DEFINE_SHARED(struct ng_type, ng_gtpu_typestruct) = {
	.version = NG_VERSION,
	.name = NG_GTPU_NODE_TYPE,
	.mod_event = NULL,		    /* module event handler (optional) */
	.constructor = ng_gtpu_constructor, /* node constructor */
	.rcvmsg = ng_gtpu_rcvmsg,           /* control messages come here */
	.shutdown = ng_gtpu_rmnode,         /* reset, and free resources */
	.newhook = ng_gtpu_newhook,         /* first notification of new hook */
	.findhook = ng_gtpu_findhook,       /* TODO : for config only if you have lots of hooks */
	.connect = NULL,		    /* final notification of new hook */
	.afterconnect = NULL,
	.rcvdata = NULL,                    /* Only specific receive data */
	.rcvdataq = NULL,                   /* Only specific receive data */
	.disconnect = ng_gtpu_disconnect,   /* notify on disconnect */
	.rcvexception = NULL,               /* exceptions come here */
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist = ng_gtpu_cmdlist,         /* commands we can convert */
};

/* on linux, messages can be received from different contexts
 * (syscall, or softirq). We don't want a syscall to be interrupted
 * during a spinlock (causing a deadlock), so we need to use
 * spinlock_bh() */
#ifdef __LinuxKernelVNB__
#define node_lock(priv) spin_lock_bh(&priv->node_lock)
#define node_unlock(priv) spin_unlock_bh(&priv->node_lock)
#else
#define node_lock(priv) vnb_spinlock_lock(&priv->node_lock)
#define node_unlock(priv) vnb_spinlock_unlock(&priv->node_lock)
#endif

NETGRAPH_INIT(gtpu, &ng_gtpu_typestruct);
NETGRAPH_EXIT(gtpu, &ng_gtpu_typestruct);

/******************************************************************
			NETGRAPH NODE METHODS
 ******************************************************************/

/* find the upper hook corresponding to a given TEID */
static inline hook_p
ng_gtpu_rx_findentry(const priv_p priv, const uint32_t teid)
{
	struct ng_pdp_ctxt_bucket *const bucket = &priv->pdp_hashtable[TEID_HASH(teid)];
	struct ng_pdp_ctxt_filter *f;
	hook_p hook_tmp;

	vnb_read_lock(&bucket->lock);
	LIST_FOREACH(f, &(bucket->head), next_hash) {
		if (likely(f->teid_rx == teid)) {
			hook_tmp = f->gtpu_upper;
			vnb_read_unlock(&bucket->lock);
			return (hook_tmp);
		}
	}

	vnb_read_unlock(&bucket->lock);
	return (NULL);
}

/* find the upper hook corresponding to a given tag */
static inline hook_p
ng_gtpu_tag_findentry(priv_p priv, uint32_t tag)
{
	struct ng_pdp_ctxt_bucket *bucket = &priv->findhook_hashtable[UPPER_HASH(tag)];
	struct ng_pdp_ctxt_filter *f;

	vnb_read_lock(&bucket->lock);
	LIST_FOREACH(f, &(bucket->head), next_findhook) {
		if (likely(f->tag == tag)) {
			vnb_read_unlock(&bucket->lock);
			return (f->self);
		}
	}

	vnb_read_unlock(&bucket->lock);
	return (NULL);
}

/*
 * Method for finding a hook
 *
 * Race condition exists for finding and creating/deleting hooks
 */
static hook_p
ng_gtpu_findhook(node_p node, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	hook_p hook = NULL;
	const char	*tag_str;
	char		*err_ptr;
	uint32_t	tag;

	DEBUG("%s\n", name);
	if (unlikely(strcmp(name, NG_GTPU_HOOK_LOWER_RX) == 0)) {
		DEBUG("found lower_rx");
		hook = (priv->gtpu_lower_rx);
	} else if (unlikely(strncmp(name, NG_GTPU_HOOK_LOWER_PREFIX,
			sizeof(NG_GTPU_HOOK_LOWER_PREFIX) - 1) == 0)) {
		struct lower_tx_private *p;

		/* Get the link index Parse link_0xa, link_10, ... */
		tag_str = name + sizeof(NG_GTPU_HOOK_LOWER_PREFIX) - 1;
		DEBUG("%s\n",tag_str);

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);
		DEBUG("%d\n", tag);

		if (unlikely((*err_ptr) != '\0'))
		    return (NULL);

		/* walk through local lower_tx list */
		vnb_read_lock(&priv->lower_list.lock);
		LIST_FOREACH(p, &(priv->lower_list.head), next_lower) {
			if (p->tag == tag) {
				vnb_read_unlock(&priv->lower_list.lock);
				return (p->self);
			}
		}
		vnb_read_unlock(&priv->lower_list.lock);
	} else if (likely(strncmp(name, NG_GTPU_HOOK_UPPER_PREFIX,
			sizeof(NG_GTPU_HOOK_UPPER_PREFIX) - 1) == 0)) {
		/* upper : with a known PREFIX */

		/* Get the link index Parse link_0xa, link_10, ... */
		tag_str = name + sizeof(NG_GTPU_HOOK_UPPER_PREFIX) - 1;
		DEBUG("%s\n", tag_str);

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);
		DEBUG("%d\n", tag);

		if (unlikely((*err_ptr) != '\0'))
		    return (NULL);

		hook = ng_gtpu_tag_findentry(priv, tag);
	} else if (unlikely(strcmp(name, NG_GTPU_HOOK_NOMATCH) == 0)) {
		DEBUG("found nomatch");
		hook = (priv->gtpu_nomatch);
	} else {
		log(LOG_ERR, "VNB: %s: unknown hook name: %s\n", __func__, name);
	}

	DEBUG("foundentry\n");
	return hook;
}

/*
 * Node constructor
 */
static int
ng_gtpu_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int i, error = 0;
	struct ng_pdp_ctxt_bucket *bucket;

	/*
	 * Allocate and initialize private info
	 */
	priv = ng_malloc(sizeof(*priv), M_NOWAIT | M_ZERO);
	if (unlikely(priv == NULL))
		return (ENOMEM);

	/* Call superclass constructor that mallocs *nodep */
	error = ng_make_node_common(&ng_gtpu_typestruct, nodep, nodeid);
	if (unlikely((error != 0))) {
		ng_free(priv);
		return (error);
	}

	/* in node : TEID hash table */
	priv->pdp_hashtable = ng_malloc(TEID_HASHSIZE*sizeof(struct ng_pdp_ctxt_bucket),
                       M_NOWAIT | M_ZERO);
	if (unlikely(priv->pdp_hashtable == NULL)) {
		ng_free(priv);
		return (ENOMEM);
	}

#ifdef GTPU_TEID_CACHE
	priv->pdp_cache = ng_malloc(TEID_HASHSIZE*sizeof(struct ng_pdp_ctxt_cache),
                       M_NOWAIT | M_ZERO);
	if (unlikely(priv->pdp_cache == NULL)) {
		ng_free(priv->pdp_hashtable);
		ng_free(priv);
		return (ENOMEM);
	}
#endif

	/* in node : findhook hash table */
	priv->findhook_hashtable = ng_malloc(UPPER_HASHSIZE*sizeof(struct ng_pdp_ctxt_bucket),
                       M_NOWAIT | M_ZERO);
	if (unlikely(priv->findhook_hashtable == NULL)) {
#ifdef GTPU_TEID_CACHE
		ng_free(priv->pdp_cache);
#endif
		ng_free(priv->pdp_hashtable);
		ng_free(priv);
		return (ENOMEM);
	}

	for (i = 0; i < TEID_HASHSIZE; i++) {
		bucket = &priv->pdp_hashtable[i];
		LIST_INIT(&bucket->head);
		vnb_rwlock_init(&bucket->lock);
	}
	for (i = 0; i < UPPER_HASHSIZE; i++) {
		bucket = &priv->findhook_hashtable[i];
		LIST_INIT(&bucket->head);
		vnb_rwlock_init(&bucket->lock);
	}
	LIST_INIT(&priv->lower_list.head);
	vnb_rwlock_init(&priv->lower_list.lock);
	NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->gtpu_node = *nodep;
	vnb_spinlock_init(&priv->node_lock);

#if (defined GTPU_PACKET_QUEUES) && (defined __FastPath__)
	priv->cfg.num_of_queues  = PKTQ_NUM_QUEUES;
	priv->cfg.queue_delay_ms = PKTQ_DELAY_MS;
	priv->cfg.pkts_per_queue = PKTQ_PKTS_PERQ;
	priv->cfg.gc_delay       = PKTQ_GC_DELAY;
	priv->cfg.inter_pktq_cb = (pktq_callback)gtpu_pktq_cb;
	error = gtpu_pktq_init(&priv->cfg);
	if (unlikely(error)) {
		log(LOG_ERR,"%s:%d packet queue init failed\n", __func__, __LINE__);
		return error;
	}
#endif
	return (0);
}

/*
 * Method for attaching a new hook
 * There are four kinds of hook :
 *	- the lower hook which links likely toward a ksocket
 *	- the nomatch hook which links toward an iface (for config debug)
 *	- multiple upper hooks which link likely toward an iface (later nffec ?)
 *		 (like in ng_vlan)
 *	- multiple lower_tx hooks which link toward a ksocket
 */
static int
ng_gtpu_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	hook_p *ph = NULL;
	int found = 0;
	struct ng_pdp_ctxt_filter * hook_pdp_ptr;
	struct lower_tx_private * lower_priv_ptr;
	const char	*tag_str;
	char		*err_ptr;
	uint32_t	tag;

	/* default init for private space */
	DEBUG("entering for (%s)", name);

	NG_HOOK_SET_PRIVATE(hook, NULL);
	/*
	 * Check for a lower hook
	 */
	if (unlikely(strcmp(name, NG_GTPU_HOOK_LOWER_RX) == 0)) {
		DEBUG("found lower_rx");
		ph = &(priv->gtpu_lower_rx);
		hook->hook_rcvdata = ng_gtpu_rcvdata_lower_rx;
	} else if (unlikely(strncmp(name, NG_GTPU_HOOK_LOWER_PREFIX,
			sizeof(NG_GTPU_HOOK_LOWER_PREFIX) - 1) == 0)) {
		struct lower_tx_private *p;

		/* lower_tx : with a known PREFIX */
		DEBUG("found lower");

		/* Get the link index Parse link_0xa, link_10, ... */
		tag_str = name + sizeof(NG_GTPU_HOOK_LOWER_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if (unlikely((*err_ptr) != '\0'))
		    return (EINVAL);

		/* Check single tag value */
		/* walk through local lower_tx list */
		vnb_read_lock(&priv->lower_list.lock);
		LIST_FOREACH(p, &(priv->lower_list.head), next_lower) {
			if (unlikely(p->tag == tag)) {
				vnb_read_unlock(&priv->lower_list.lock);
				return (EISCONN);
			}
		}
		vnb_read_unlock(&priv->lower_list.lock);
		/* add lower_tx_context */
		lower_priv_ptr = ng_malloc(sizeof(* lower_priv_ptr),
		    M_NOWAIT | M_ZERO);
		if (unlikely(lower_priv_ptr == NULL)) {
			log(LOG_ERR, "VNB: %s lower_tx failed: malloc\n", __func__);
			return (ENOMEM);
		}
		lower_priv_ptr->type = LOWER_HOOK_TYPE;
		lower_priv_ptr->tag  = tag;
		lower_priv_ptr->self = hook;
		vnb_rwlock_init(&lower_priv_ptr->lock);
		NG_HOOK_SET_PRIVATE(hook, lower_priv_ptr);

		vnb_write_lock(&priv->lower_list.lock);
		LIST_INSERT_HEAD(
		    &priv->lower_list.head, lower_priv_ptr, next_lower);
		vnb_write_unlock(&priv->lower_list.lock);

		found = 1;
		hook->hook_rcvdata = ng_gtpu_rcvdata_lower_tx;
	} else if (likely(strncmp(name, NG_GTPU_HOOK_UPPER_PREFIX,
			sizeof(NG_GTPU_HOOK_UPPER_PREFIX) - 1) == 0)) {
		/* upper : with a known PREFIX */
		struct ng_pdp_ctxt_bucket * bucket;

		DEBUG("found upper");

		/* Get the link index Parse link_0xa, link_10, ... */
		tag_str = name + sizeof(NG_GTPU_HOOK_UPPER_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if (unlikely((*err_ptr) != '\0'))
		    return (EINVAL);

		/* Check single tag value */
		if (unlikely(ng_gtpu_tag_findentry(priv, tag) != NULL)) {
			log(LOG_ERR, "VNB: %s newhook failed tag: bad value %d\n",
				__func__, (int)tag);
		    return (EISCONN);
		}

		/* add upper_private : pdp_context */
		hook_pdp_ptr = ng_malloc(sizeof(* hook_pdp_ptr),
		    M_NOWAIT | M_ZERO);
		if (unlikely(hook_pdp_ptr == NULL)) {
			log(LOG_ERR, "VNB: %s upper failed: malloc\n", __func__);
			return (ENOMEM);
		}
		hook_pdp_ptr->type = UPPER_HOOK_TYPE;
		hook_pdp_ptr->tag  = tag;
		hook_pdp_ptr->self = hook;
		NG_HOOK_SET_PRIVATE(hook, hook_pdp_ptr);

		/* Register pdp_context in a hash table. */
		bucket = &priv->findhook_hashtable[UPPER_HASH(tag)];
		vnb_write_lock(&bucket->lock);
		LIST_INSERT_HEAD(
		    &bucket->head, hook_pdp_ptr, next_findhook);
		vnb_write_unlock(&bucket->lock);

		found = 1;
		hook->hook_rcvdata = ng_gtpu_rcvdata_upper;
	} else if (unlikely(strcmp(name, NG_GTPU_HOOK_NOMATCH) == 0)) {
		DEBUG("found nomatch");
		ph = &(priv->gtpu_nomatch);
	} else {
		log(LOG_ERR, "VNB: %s: unknown hook name: %s\n", __func__, name);
		return (EINVAL);
	}

	if (unlikely(ph != NULL)) {
		DEBUG("ph != NULL");
		found = 1;
		if (*ph == NULL)
			*ph = hook;
		/* Do not connect twice a hook */
		else {
			log(LOG_ERR, "VNB: %s return (EISCONN)\n", __func__);
			return (EISCONN);
		}
	}
	/*
	 * the check against double creation of "upperYYY" or "lowerZZZ"
	 * is done by base netgraph (same hook name)
	 */

	/* no hook found : bail out */
	if (unlikely(! found))
		return (EINVAL);

	return 0;
}
#ifdef GTPU_TEID_CACHE
/*
 * update the Hash table cache with the first entry of the linked list
 */
static void
upper_cache_update(struct ng_pdp_ctxt_bucket const * bucket, const priv_p priv,
				  struct ng_pdp_ctxt_filter const * hook_pdp_ptr)
{
	if (LIST_FIRST(&bucket->head)) {
		priv->pdp_cache[TEID_HASH(hook_pdp_ptr->teid_rx)].head_hook =
			LIST_FIRST(&bucket->head)->gtpu_upper;
		priv->pdp_cache[TEID_HASH(hook_pdp_ptr->teid_rx)].head_tag =
		LIST_FIRST(&bucket->head)->teid_rx;
	} else {
		priv->pdp_cache[TEID_HASH(hook_pdp_ptr->teid_rx)].head_hook = NULL;
		priv->pdp_cache[TEID_HASH(hook_pdp_ptr->teid_rx)].head_tag = 0;
	}
}
#endif
/*
 * check if upper is valid. return value: 0 means valid, else means invalid
 */
static int
gtpu_check_upper(const char *upper_name, const priv_p priv, hook_p *ret_upper,
	struct ng_pdp_ctxt_filter ** ret_pdp_ctx, int *ret_error, const char *cmdstr)
{
	hook_p upper = NULL;
	int ret = -1;
	struct ng_pdp_ctxt_filter *hook_pdp_ptr = NULL;
	int error = EINVAL;

	/* Sanity check */
	if (unlikely (!upper_name || !priv || !ret_upper || !ret_pdp_ctx || !error || !cmdstr))
		return ret;

	upper = ng_findhook(priv->gtpu_node, upper_name);
	if (unlikely(upper == NULL)) {
		error = ENOENT;
		log(LOG_ERR, "VNB: %s:%d %s failed no upper\n", __func__, __LINE__, cmdstr);
		goto err_out;
	}
	/* And is not one of the special hooks. */
	if (unlikely(upper == priv->gtpu_lower_rx ||
		upper == priv->gtpu_nomatch)) {
		log(LOG_ERR, "VNB: %s:%d %s failed bad upper\n", __func__, __LINE__, cmdstr);
		goto err_out;
	}
	/* And was correctly initialized. */
	hook_pdp_ptr = NG_HOOK_PRIVATE(upper);
	if (unlikely(hook_pdp_ptr == NULL)) {
		log(LOG_ERR, "VNB: %s:%d %s failed upper: NULL private\n", __func__, __LINE__, cmdstr);
		goto err_out;
	}
	/* And is of the correct type */
	if (unlikely(hook_pdp_ptr->type != UPPER_HOOK_TYPE)) {
		log(LOG_ERR, "VNB: %s:%d %s failed upper: bad type %d\n",
			__func__, __LINE__, cmdstr,(int)hook_pdp_ptr->type);
		goto err_out;
	}
	error = 0;
	ret = 0;

err_out:
	*ret_upper = upper;
	*ret_pdp_ctx = hook_pdp_ptr;
	*ret_error = error;
	return ret;
}

/*
 * check if lower is valid. return value: 0 means valid, else means invalid
 */
static int
gtpu_check_lower(const char *lower_name, const priv_p priv, hook_p *ret_lower,
	struct lower_tx_private **ret_lower_priv, int *ret_error, const char *cmdstr)
{
	hook_p lower;
	struct lower_tx_private *lower_priv_ptr = NULL;
	int ret = -1;
	int error = EINVAL;

	/* Sanity check */
	if (unlikely(!lower_name || !priv || !ret_lower || !ret_lower_priv || !error || !cmdstr))
		return ret;

	lower = ng_findhook(priv->gtpu_node, lower_name);
	if (unlikely(lower == NULL)) {
		log(LOG_ERR, "VNB: %s:%d %s failed no lower\n", __func__, __LINE__, cmdstr);
		goto err_out;
	}
	/* And is not one of the special hooks. */
	if (unlikely(lower == priv->gtpu_lower_rx ||
		lower == priv->gtpu_nomatch)) {
		log(LOG_ERR, "VNB: %s:%d %s failed bad lower\n", __func__, __LINE__, cmdstr);
		goto err_out;
	}
	/* And was correctly initialized. */
	lower_priv_ptr = NG_HOOK_PRIVATE(lower);
	if (unlikely(lower_priv_ptr == NULL)) {
		log(LOG_ERR, "VNB: %s:%d %s failed lower: NULL private \n", __func__, __LINE__, cmdstr);
		goto err_out;
	}
	/* And is of the correct type */
	if (unlikely(lower_priv_ptr->type != LOWER_HOOK_TYPE)) {
		log(LOG_ERR, "VNB: %s:%d %s failed lower: bad type %d\n",
			__func__,__LINE__,cmdstr, (int)lower_priv_ptr->type);
		goto err_out;
	}
	error = 0;
	ret = 0;

err_out:
	*ret_lower = lower;
	*ret_lower_priv = lower_priv_ptr;
	*ret_error = error;
	return ret;
}

/*
 * Receive a control message
 */
static int
ng_gtpu_rcvmsg(node_p node, struct ng_mesg *msg,
		const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;
	hook_p upper, lower;
	int i;

	DEBUG("entering - arglen : %d", msg->header.arglen);

	switch (msg->header.typecookie) {

	case NGM_GENERIC_COOKIE:
		switch (msg->header.cmd) {
		case NGM_TEXT_STATUS:
		/* dump the list of current tunnels (PDP contexts) */
		{
			char *arg;
			int res, pos=0;

			NG_MKRESPONSE(resp, msg, sizeof(struct ng_mesg)
			    + NG_TEXTRESPONSE, M_NOWAIT);
			if (unlikely(resp == NULL)) {
				error = ENOMEM;
				break;
			}

			arg = (char *) resp->data;
			pos = snprintf(arg, NG_TEXTRESPONSE, "GTP-U configuration\n");
#if (defined GTPU_PACKET_QUEUES) && (defined __FastPath__)
#ifdef GTPU_PKTQ_STATS
			{
				struct gtpu_pktq_stats gen_err;
				struct gtpu_pktq_cfg_stats *cfg_err = &(priv->cfg.error_stat);

				if (unlikely(gtpu_pktq_get_stat(&priv->cfg, &gen_err)))
					log(LOG_ERR,"%s:%d packet queue get stat failed\n", __func__, __LINE__);
				res = snprintf(arg + pos, (NG_TEXTRESPONSE - pos),
							   "gtpu packet queue error stats:\n"
							   "invalid param failed=%u, ng_malloc failed=%u, "
							   "no free queues failed=%u, queue mismatch failed=%d, "
							   "NULL mbuf error=%u, send pkts failed=%u, general failed=%u\n",
							   gen_err.invalid, cfg_err->malloc, cfg_err->no_free_que,
							   cfg_err->que_mismatch, cfg_err->mbuf,
							   cfg_err->send_fail, cfg_err->general);
				if (res > 0)
					pos += res;
				else {
					log(LOG_ERR, "VNB: %s textstatus snprintf failed\n", __func__);
				}
			}
#endif /* GTPU_PKTQ_STATS */
#endif /* (defined GTPU_PACKET_QUEUES) && (defined __FastPath__) */

			pos += snprintf(arg + pos, (NG_TEXTRESPONSE - pos),
				"Number of existing pdp context: %d\n", priv->nent);
			for (i=0;
					 ((i< TEID_HASHSIZE) && (pos < (NG_TEXTRESPONSE - 100)));
						 i++) {
				struct ng_pdp_ctxt_bucket *bucket = &priv->pdp_hashtable[i];
				struct ng_pdp_ctxt_filter *f, *f_tmp;

				vnb_read_lock(&bucket->lock);
				LIST_FOREACH_SAFE(f, f_tmp, &(bucket->head), next_hash) {
					if (f->gtpu_upper==NULL) {
						log(LOG_ERR, "VNB: %s textstatus NULL upper\n", __func__);
						continue;
					}
					if (f->gtpu_lower_tx==NULL) {
						log(LOG_ERR, "VNB: %s textstatus NULL lower_tx\n", __func__);
						continue;
					}
					res = snprintf(arg + pos, (NG_TEXTRESPONSE - pos),
						"teid_tx: %u teid_rx: %u flags: %u upper: %s lower: %s tos: %d\n",
						f->teid_tx, f->teid_rx, f->flags_tx,
						f->gtpu_upper->name, f->gtpu_lower_tx->name, f->tos);
					if (res < 0)
						continue;
					if (res+pos >= NG_TEXTRESPONSE - 100)
						break;

					pos += res;
				}
				vnb_read_unlock(&bucket->lock);
		    }
			resp->header.arglen = pos + 1;

			break;
		}
		default:
			error = EINVAL;
			break;
		}
		break;

	case NGM_GTPU_COOKIE:
		switch (msg->header.cmd) {
		case NGM_GTPU_SET_REQ:
		{
			/* rework : add a reference to a given PDP context / tunnel */
			node_lock(priv);
			priv->rep_seen = 0;
			node_unlock(priv);

			/* prepare and enqueue req message : m, meta*/
			/* later : NG_SEND_DATA(error, priv->gtpu_lower, m, meta); */
			break;
		}
		/*
		 * XXX we will need a hook to userland
		 * XXX Not done yet since we need to upgrade the fast path framework
		 */
		case NGM_GTPU_GET_REPLY:
		{
			uint32_t *reply_seen;

			NG_MKRESPONSE(resp, msg, sizeof(*reply_seen), M_NOWAIT);
			if (unlikely(resp == NULL)) {
				error = ENOMEM;
				break;
			}
			reply_seen = (uint32_t *)resp->data;
			*reply_seen = 0;

			*reply_seen = priv->rep_seen;

			break;
		}
		/* example only : to be merged into per-tunnel NG_GTPU_STATS */
#ifdef NG_GTPU_STATS
		case NGM_GTPU_CLR_STATS:
		case NGM_GTPU_GET_STATS:
		case NGM_GTPU_GETCLR_STATS:
		{
			node_lock(priv);
			if (msg->header.cmd != NGM_GTPU_CLR_STATS) {
				NG_MKRESPONSE(resp, msg, sizeof(priv->stats), M_NOWAIT);
				if (unlikely(resp == NULL)) {
					error = ENOMEM;
					node_unlock(priv);
					break;
				}
				memcpy(resp->data,
				    &priv->stats, sizeof(priv->stats));
#if (defined GTPU_PACKET_QUEUES) && (defined __FastPath__)
#ifdef GTPU_PKTQ_STATS_NOTYET
				/* the resp struct does not contain fields for the ptkq stats */
				gtpu_pktq_get_stat(&priv->cfg, &gen_err);
#endif
#endif /* (defined GTPU_PACKET_QUEUES) && (defined __FastPath__) */
			}

			if (msg->header.cmd != NGM_GTPU_GET_STATS) {
				memset(&priv->stats, 0, sizeof(priv->stats));
#if (defined GTPU_PACKET_QUEUES) && (defined __FastPath__)
#ifdef GTPU_PKTQ_STATS
				gtpu_pktq_reset_stat(&priv->cfg);
#endif
#endif /* (defined GTPU_PACKET_QUEUES) && (defined __FastPath__) */
			}
			node_unlock(priv);

			break;
		}
#endif
		/*
		 * Add a PDP == create a new tunnel
		 * for each tunnel :
		 * teid_down / teid_up
		 * upper[i] / lower_tx[j]
		 *
		 * for partial config commands : int params == 0 ; string params == ""
		 *
		 * for existing tunnel configs : non-provided parameters are reset to default
		 */
		case NGM_GTPU_ADDPDP_CTXT:
		{
			struct ng_gtpu_pdp_context * pdp_parse_ptr;
			struct ng_pdp_ctxt_filter * hook_pdp_ptr;
			struct ng_pdp_ctxt_bucket * bucket;
			struct lower_tx_private * lower_priv_ptr;
			const char *cmdstr;
			int pdp_exist;
			hook_p upper_check;

addpdp_ctx:
			cmdstr = "addpdp";
			pdp_exist = 0;
			if (unlikely(msg->header.arglen != sizeof(struct ng_gtpu_pdp_context))) {
				log(LOG_ERR, "VNB: %s addpdp failed (%d) (%zd)\n", __func__,
					msg->header.arglen, sizeof(struct ng_gtpu_pdp_context));
				error = EINVAL;
				break;
			}
			node_lock(priv);
			pdp_parse_ptr = (struct ng_gtpu_pdp_context *)msg->data;

			/* Now check if new pdp parameters are valid */
			if (gtpu_check_upper(pdp_parse_ptr->upper, priv, &upper,
					&hook_pdp_ptr, &error, cmdstr)) {
				/* Check 'upper' parameter of new pdp, which is invalid */
				log(LOG_ERR, "VNB: %s addpdp failed upper=%s: bad value\n",
							__func__, pdp_parse_ptr->upper);
				node_unlock(priv);
				break;
			}
			if (hook_pdp_ptr->gtpu_upper || hook_pdp_ptr->gtpu_lower_tx
			     || hook_pdp_ptr->teid_rx || hook_pdp_ptr->teid_tx) {
				/* The old pdp context exists */
				pdp_exist = 1;
			}
			/* Check if the 'teid_rx' field of new pdp parameters is valid */
			if (pdp_parse_ptr->teid_rx) {
				upper_check = ng_gtpu_rx_findentry(priv, pdp_parse_ptr->teid_rx);
				/* Check single teid_rx value */
				if ( (!pdp_exist) || (pdp_parse_ptr->teid_rx != hook_pdp_ptr->teid_rx) ) {
					/* pdp_exist = 0, means old pdp doesn't exist
					   we need to check if new pdp teid_rx is in use */
					/* pdp_exist = 1, means old pdp exists
					   we need to check ng_gtpu_rx_findentry() only if old teid_rx
					   and current pdp teid_rx are different */
					if (unlikely(upper_check != NULL)) {
						log(LOG_ERR, "VNB: %s addpdp failed teid_rx: bad value %d\n",
						__func__, (int)pdp_parse_ptr->teid_rx);
						error = EINVAL;
						node_unlock(priv);
						break;
					}
				}
			}
			/* Check if 'lower' field of new pdp parameters is valid. */
			if (pdp_parse_ptr->lower[0]) {
				/* gtpu_check_lower() check if lower is valid,
				   if so they set lower and lower_priv_ptr pointer */
				if (gtpu_check_lower(pdp_parse_ptr->lower, priv, &lower,
					  &lower_priv_ptr, &error, cmdstr)) {
					log(LOG_ERR, "VNB: %s addpdp failed lower=%s: bad value \n",
						__func__, pdp_parse_ptr->lower);
					node_unlock(priv);
					break;
				}
			} else {
				/* missing parameter: use default value */
				lower = NULL;
				lower_priv_ptr = NULL;
			}

			/* Finish new pdp parameters validation check */
			/* for safety : force removal of old pdp context if it exists */
			if (pdp_exist) {
				struct lower_tx_private * old_lower_priv = NULL;

				/* Now the old pdp has set teid_rx so just remove the old teid_rx  */
				if (hook_pdp_ptr->teid_rx) {
					bucket = &priv->pdp_hashtable[TEID_HASH(hook_pdp_ptr->teid_rx)];
					vnb_write_lock(&bucket->lock);
					LIST_REMOVE(hook_pdp_ptr, next_hash);
#ifdef GTPU_TEID_CACHE
					upper_cache_update(bucket, priv, hook_pdp_ptr);
#endif
					vnb_write_unlock(&bucket->lock);
				}
				/* Now the old pdp has set lower, remove the old */
				if (hook_pdp_ptr->gtpu_lower_tx) {
					old_lower_priv = NG_HOOK_PRIVATE(hook_pdp_ptr->gtpu_lower_tx);

					vnb_write_lock(&old_lower_priv->lock);
					LIST_REMOVE(hook_pdp_ptr, next_lower);
					vnb_write_unlock(&old_lower_priv->lock);
				}
				/* clear old pdp context fields, set them to default value */
				hook_pdp_ptr->teid_tx = hook_pdp_ptr->teid_rx = 0;
				hook_pdp_ptr->flags_tx = hook_pdp_ptr->tos = 0;
				hook_pdp_ptr->gtpu_upper = hook_pdp_ptr->gtpu_lower_tx = NULL;
			}

			/* Now begin to update pdp context value from the new pdp parameters */
			hook_pdp_ptr->teid_tx = pdp_parse_ptr->teid_tx;
			hook_pdp_ptr->teid_rx = pdp_parse_ptr->teid_rx;
			/* set the generic pdp context field (gtpu_upper and flags_tx) */
			hook_pdp_ptr->gtpu_upper = upper;
			if (pdp_parse_ptr->flags_tx)
				hook_pdp_ptr->flags_tx = pdp_parse_ptr->flags_tx;
			else
				/* set default value for flags_tx */
				hook_pdp_ptr->flags_tx = NGM_GTPU_DEFAULT_FLAGS;
			hook_pdp_ptr->tos = pdp_parse_ptr->tos;

			/* The new pdp sets 'lower' field, so set it to pdp context */
			if (pdp_parse_ptr->lower[0] && lower && lower_priv_ptr) {
				hook_pdp_ptr->gtpu_lower_tx = lower;
				/* store back pointer in the lower_tx->priv */
				vnb_write_lock(&lower_priv_ptr->lock);
				LIST_INSERT_HEAD(
					&lower_priv_ptr->head, hook_pdp_ptr, next_lower);
				vnb_write_unlock(&lower_priv_ptr->lock);
			} else
				hook_pdp_ptr->gtpu_lower_tx = NULL;

			/* The new pdp sets teid_rx, so just set pdp context */
			if (pdp_parse_ptr->teid_rx) {
				/* Register pdp_context in a hash table. */
				bucket = &priv->pdp_hashtable[TEID_HASH(hook_pdp_ptr->teid_rx)];
				vnb_write_lock(&bucket->lock);
				LIST_INSERT_HEAD(
					&bucket->head, hook_pdp_ptr, next_hash);
#ifdef GTPU_TEID_CACHE
				upper_cache_update(bucket, priv, hook_pdp_ptr);
#endif
				vnb_write_unlock(&bucket->lock);
			}

			/* increase priv->nent only if pdp context is newly created */
			if (!pdp_exist) {
				priv->nent++;
#if (defined GTPU_PACKET_QUEUES) && (defined __FastPath__)
				hook_pdp_ptr->pktq_idx = -1;
#endif
			}

			node_unlock(priv);

			DEBUG("New pdp context:");
			DEBUG("teid_tx: %u teid_rx: %u flags: %u tos: %u",
				hook_pdp_ptr->teid_tx, hook_pdp_ptr->teid_rx,
					hook_pdp_ptr->flags_tx, hook_pdp_ptr->tos);
			DEBUG("lower: %s upper: %s",
				pdp_parse_ptr->lower, pdp_parse_ptr->upper);

			break;
		}
		case NGM_GTPU_DELPDP_CTXT:
		{
			struct ng_gtpu_pdp_delinfo *delinfo = NULL;
			struct ng_pdp_ctxt_filter * pdp_ptr1 = NULL, *pdp_ptr2 = NULL;
			struct ng_pdp_ctxt_filter * hook_pdp_ptr;
			struct ng_pdp_ctxt_bucket * bucket;
			struct lower_tx_private * lower_priv_ptr;
			const char *cmdstr = "delpdp";

			if (unlikely(msg->header.arglen != sizeof(struct ng_gtpu_pdp_delinfo))) {
				log(LOG_ERR, "VNB: %s delpdp failed: invalid arglen\n", __func__);
				error = EINVAL;
				break;
			}
			delinfo = (struct ng_gtpu_pdp_delinfo *)msg->data;
			if (!delinfo->teid && !delinfo->upper[0]) {
				log(LOG_ERR, "VNB: %s delpdp failed: both upper and teid are empty\n", __func__);
				error = ENOENT;
				break;
			}

			node_lock(priv);
			/* get pdp context from upper parameter */
			if (delinfo->upper[0]) {
				if (gtpu_check_upper(delinfo->upper, priv, &upper,
						&pdp_ptr1, &error, cmdstr)) {
					/* Check 'upper' parameter of new pdp, which is invalid */
					log(LOG_ERR, "VNB: %s delpdp failed upper=%s: bad value\n",
								__func__, delinfo->upper);
					node_unlock(priv);
					break;
				}
			}
			/* get pdp context from teid parameter */
			if (delinfo->teid) {
				upper = ng_gtpu_rx_findentry(priv, delinfo->teid);
				if (!upper) {
					log(LOG_ERR, "VNB: %s delpdp failed upper doesn't exist for teid=%d\n",
						 __func__, delinfo->teid);
					error = EINVAL;
					node_unlock(priv);
					break;
				}
				pdp_ptr2 = NG_HOOK_PRIVATE(upper);
				if (!pdp_ptr2) {
					log(LOG_ERR, "VNB: %s delpdp failed teid=%d doesn't exist\n",
						 __func__, delinfo->teid);
					error = EINVAL;
					node_unlock(priv);
					break;
				}
			}
			/* if both the upper or teid parameters are valid,
			   they should point to a same pdp context (hook_pdp_ptr) */
			if (pdp_ptr1 && pdp_ptr2 && pdp_ptr1 != pdp_ptr2) {
				log(LOG_ERR, "VNB: %s delpdp failed: mismatched upper and teid\n",__func__);
				error = EINVAL;
				node_unlock(priv);
				break;
			}
			if (pdp_ptr1)
				hook_pdp_ptr = pdp_ptr1;
			else
				hook_pdp_ptr = pdp_ptr2;

			lower = hook_pdp_ptr->gtpu_lower_tx;
			if (lower) {
				/* if lower of pdp context exists,
				 * do validation check and save the lower_priv_ptr for removing */
				lower_priv_ptr = NG_HOOK_PRIVATE(lower);
				if (unlikely(lower_priv_ptr == NULL)) {
					log(LOG_ERR, "VNB: %s delpdp failed hook: NULL priv\n", __func__);
					error = EINVAL;
					node_unlock(priv);
					break;
				}
				/* And is of the correct type */
				if (unlikely(lower_priv_ptr->type != LOWER_HOOK_TYPE)) {
					log(LOG_ERR, "VNB: %s delpdp failed lower: bad type %d\n",
						__func__, (int)lower_priv_ptr->type);
					error = EINVAL;
					node_unlock(priv);
					break;
				}
			} else
				lower_priv_ptr = NULL;

			DEBUG("Del pdp context:");
			DEBUG("teid_tx: %u teid_rx: %u flags: %u",
				hook_pdp_ptr->teid_tx, hook_pdp_ptr->teid_rx, hook_pdp_ptr->flags_tx);

			/* rm hashtable entries */
			if (hook_pdp_ptr->teid_rx) {
				/* the teid_rx field of pdp context exists, so remove it */
				/* head to pdp_context LIST in the teid hash table. */
				bucket = &priv->pdp_hashtable[TEID_HASH(hook_pdp_ptr->teid_rx)];
				vnb_write_lock(&bucket->lock);
				DEBUG("Del pdp context: rm hash table");
				LIST_REMOVE(hook_pdp_ptr, next_hash);
#ifdef GTPU_TEID_CACHE
				upper_cache_update(bucket, priv, hook_pdp_ptr);
#endif
				vnb_write_unlock(&bucket->lock);
			}
			if (lower_priv_ptr) {
				/* the gtpu_lower_tx field of pdp context exists, so remove it */
				vnb_write_lock(&lower_priv_ptr->lock);
				DEBUG("Del pdp context: rm lower");
				LIST_REMOVE(hook_pdp_ptr, next_lower);
				vnb_write_unlock(&lower_priv_ptr->lock);
			}

			/* clear old pdp context fields */
			hook_pdp_ptr->teid_tx = hook_pdp_ptr->teid_rx = 0;
			hook_pdp_ptr->flags_tx = hook_pdp_ptr->tos = 0;
			hook_pdp_ptr->gtpu_upper = hook_pdp_ptr->gtpu_lower_tx = NULL;

			priv->nent--;
			node_unlock(priv);

			break;
		}
		case  NGM_GTPU_GET_CONFIG:
		{
			hook_p hook;
			struct ng_pdp_ctxt_filter * pdp_ptr;
			char *arg;
			int res, pos = 0;

			if (unlikely(msg->header.arglen == 0)) {
				log(LOG_ERR, "VNB: %s getpdp invalid arglen\n", __func__);
				error = EINVAL;
				break;
			}
			msg->data[msg->header.arglen - 1] = '\0';
			if (!msg->data[0]) {
				log(LOG_ERR, "VNB: %s getpdp empty msg->data\n", __func__);
				error = EINVAL;
				break;
			}
			hook = ng_findhook(node, msg->data);
			if (unlikely(hook == NULL)) {
				log(LOG_ERR, "VNB: %s getpdp can't find such upper-hook name :%s\n", __func__,msg->data);
				error = ENOENT;
				break;
			}
			node_lock(priv);
			pdp_ptr = NG_HOOK_PRIVATE(hook);
			if (unlikely(pdp_ptr == NULL) ||
				 (pdp_ptr->gtpu_upper != hook)) {
				log(LOG_ERR, "VNB: %s getpdp hook priv failed\n", __func__);
				error = EINVAL;
				node_unlock(priv);
				break;
			}
			NG_MKRESPONSE(resp, msg, sizeof(struct ng_mesg)
			    + NG_TEXTRESPONSE, M_NOWAIT);
			if (unlikely(resp == NULL)) {
				log(LOG_ERR, "VNB: %s getpdp NG_MKRESPONSE failed\n", __func__);
				node_unlock(priv);
				error = ENOMEM;
				break;
			}
			arg = (char *) resp->data;
			pos = snprintf(arg, NG_TEXTRESPONSE, "GTP-U pdp configuration\n");
			res = snprintf(arg + pos, (NG_TEXTRESPONSE - pos),
						"teid_tx: %u teid_rx: %u flags: %u upper: %s lower: %s\n",
						pdp_ptr->teid_tx, pdp_ptr->teid_rx, pdp_ptr->flags_tx,
						pdp_ptr->gtpu_upper?pdp_ptr->gtpu_upper->name:"null",
						pdp_ptr->gtpu_lower_tx?pdp_ptr->gtpu_lower_tx->name:"null");

#if (defined GTPU_PACKET_QUEUES) && (defined __FastPath__)
			if ((res > 0) && (pdp_ptr->pktq_idx != -1)) {
				gtpu_que_tm_t tm;

				pos += res;
				if (unlikely(gtpu_pktq_get_timestamp(&priv->cfg, pdp_ptr,
				  pdp_ptr->pktq_idx, &tm))) {
					log(LOG_ERR,"%s:%d packet queue get timestamp failed\n",
						__func__, __LINE__);
				} else {
					res = snprintf(arg + pos, (NG_TEXTRESPONSE - pos),
								  "start_pkt=%"PRIu64", first_pkt=%"PRIu64
								  ", last_pkt=%"PRIu64", count %d\n",
								  tm.start_pkt, tm.first_pkt, tm.last_pkt, tm.pkt_count);
#ifdef GTPU_PKTQ_STATS
					if (res > 0) {
						struct gtpu_pktq_queue_stats que_err;

						pos += res;
						if (unlikely(gtpu_pktq_queue_get_stat(&priv->cfg, pdp_ptr,
						  pdp_ptr->pktq_idx, &que_err))) {
							log(LOG_ERR,"%s:%d packet queue get stat failed\n",
								__func__, __LINE__);
						} else {
						  res = snprintf(arg + pos, (NG_TEXTRESPONSE - pos),
								  "store_pkts=%u,trans_pkts=%u,drop_pkts=%u\n",
								  que_err.store_pkts, que_err.tran_pkts,
								  que_err.drop_pkts);
						}
					}
#endif /* GTPU_PKTQ_STATS */
				}
			}
#endif /* GTPU_PACKET_QUEUES && __FastPath__ */

			node_unlock(priv);
			if (res <= 0) {
				log(LOG_ERR, "VNB: %s getpdp snprintf failed \n",__func__);
				error = EINVAL;
				break;
			}
			pos += res;
			resp->header.arglen = pos + 1;
			break;
		}
		/*
		 * Update a PDP == update a tunnel
		 *
		 * only change the parameters passed in command
		 * unspecified parameters are kept unchanged
		 */
		case NGM_GTPU_UPDPDP_CTXT:
		{
			struct ng_gtpu_pdp_context * pdp_parse_ptr;
			struct ng_pdp_ctxt_filter * hook_pdp_ptr;
			struct ng_pdp_ctxt_bucket * bucket;
			struct lower_tx_private * lower_priv_ptr;
			const char *cmdstr = "updatepdp";
			hook_p upper_check;

			if (unlikely(msg->header.arglen != sizeof(struct ng_gtpu_pdp_context))) {
				log(LOG_ERR, "VNB: %s:%d updatepdp failed (%d) (%zd)\n", __func__,__LINE__,
					msg->header.arglen, sizeof(struct ng_gtpu_pdp_context));
				error = EINVAL;
				break;
			}
			pdp_parse_ptr = (struct ng_gtpu_pdp_context *)msg->data;
			node_lock(priv);

			/* Validation check for new pdp parameters */
			/* Now check if new pdp parameters are valid */
			if (gtpu_check_upper(pdp_parse_ptr->upper, priv, &upper,
					&hook_pdp_ptr, &error, cmdstr)) {
				/* Check 'upper' parameter of new pdp, which is invalid */
				log(LOG_ERR, "VNB: %s updatepdp failed upper=%s: bad value\n",
							__func__, pdp_parse_ptr->upper);
				node_unlock(priv);
				break;
			}
			if (!hook_pdp_ptr->gtpu_upper) {
				/* This is an unconfigured PDP */
				node_unlock(priv);
				/* XXXX check : behave as if adding a new PDP context */
				goto addpdp_ctx;
			}
			/* on an already configured tunnel, upper hook must not change */
			if (hook_pdp_ptr->gtpu_upper != upper) {
				log(LOG_ERR, "VNB: %s:%d updatepdp failed: upper mismatch old=%s,new=%s\n",
					__func__, __LINE__, hook_pdp_ptr->gtpu_upper->name, upper->name);
				error = EINVAL;
				node_unlock(priv);
				break;
			}
			/* Check if the 'teid_rx' field of new pdp parameters is valid */
			if (pdp_parse_ptr->teid_rx) {
				if (pdp_parse_ptr->teid_rx != hook_pdp_ptr->teid_rx) {
					/* old pdp exists, we need to check ng_gtpu_rx_findentry()
					   only if old teid_rx and current pdp teid_rx are different */
					upper_check = ng_gtpu_rx_findentry(priv, pdp_parse_ptr->teid_rx);
					if (unlikely(upper_check != NULL)) {
						log(LOG_ERR, "VNB: %s updpdp failed teid_rx: existing value %d\n",
							__func__, (int)pdp_parse_ptr->teid_rx);
						error = EINVAL;
						node_unlock(priv);
						break;
					}
				}
			}

			/* The new pdp has set lower parameter or the lower parameter is changed. */
			if (pdp_parse_ptr->lower[0] &&
				  ( !hook_pdp_ptr->gtpu_lower_tx ||
				   strncmp(hook_pdp_ptr->gtpu_lower_tx->name, pdp_parse_ptr->lower,
						  (NG_HOOKLEN + 1)))) {
				/* Now check lower of new pdp and set gtpu_lower_rx of pdp context. */
				/* gtpu_check_lower() check if lower is valid,
				  if so they set lower and lower_priv_ptr pointer */
				if (gtpu_check_lower(pdp_parse_ptr->lower, priv, &lower,
					  &lower_priv_ptr, &error, cmdstr)) {
					log(LOG_ERR, "VNB: %s updpdp failed lower=%s: bad value \n",
						__func__, pdp_parse_ptr->lower);
					node_unlock(priv);
					break;
				}
				/* LIST_REMOVE for existing old lower */
				if (hook_pdp_ptr->gtpu_lower_tx) {
					struct lower_tx_private * old_lower_priv = NULL;

					old_lower_priv = NG_HOOK_PRIVATE(hook_pdp_ptr->gtpu_lower_tx);

					vnb_write_lock(&old_lower_priv->lock);
					DEBUG("updpdp context: rm lower");
					LIST_REMOVE(hook_pdp_ptr, next_lower);
					vnb_write_unlock(&old_lower_priv->lock);
				}
				/* LIST_INSERT for new lower */
				vnb_write_lock(&lower_priv_ptr->lock);
				LIST_INSERT_HEAD(
						&lower_priv_ptr->head, hook_pdp_ptr, next_lower);
				vnb_write_unlock(&lower_priv_ptr->lock);
				hook_pdp_ptr->gtpu_lower_tx = lower;
			}

			/* Now remove old teid_rx hash and add new teid_rx hash */
			if (pdp_parse_ptr->teid_rx && (pdp_parse_ptr->teid_rx != hook_pdp_ptr->teid_rx)) {
				/* The teid_rx is changed */
				/* check correctly configured existing teid_rx */
				if (hook_pdp_ptr->teid_rx != 0) {
					/* Remove old hashtable entry */
					bucket = &priv->pdp_hashtable[TEID_HASH(hook_pdp_ptr->teid_rx)];
					vnb_write_lock(&bucket->lock);
					LIST_REMOVE(hook_pdp_ptr, next_hash);
#ifdef GTPU_TEID_CACHE
					upper_cache_update(bucket, priv, hook_pdp_ptr);
#endif
					vnb_write_unlock(&bucket->lock);
				}
				/* Register new pdp_context in a hash table. */
				hook_pdp_ptr->teid_rx = pdp_parse_ptr->teid_rx;
				bucket = &priv->pdp_hashtable[TEID_HASH(hook_pdp_ptr->teid_rx)];
				vnb_write_lock(&bucket->lock);
				LIST_INSERT_HEAD(&bucket->head, hook_pdp_ptr, next_hash);
#ifdef GTPU_TEID_CACHE
				upper_cache_update(bucket, priv, hook_pdp_ptr);
#endif
				vnb_write_unlock(&bucket->lock);
			}

			if (pdp_parse_ptr->teid_tx)
				hook_pdp_ptr->teid_tx = pdp_parse_ptr->teid_tx;
			if (pdp_parse_ptr->flags_tx)
				hook_pdp_ptr->flags_tx = pdp_parse_ptr->flags_tx;
			if (pdp_parse_ptr->tos)
				hook_pdp_ptr->tos = pdp_parse_ptr->tos;
			node_unlock(priv);

			DEBUG("%d : update pdp context:",__LINE__);
			DEBUG("teid_tx: %u teid_rx: %u flags: %u tos: %u",
				hook_pdp_ptr->teid_tx, hook_pdp_ptr->teid_rx,
					hook_pdp_ptr->flags_tx, hook_pdp_ptr->tos);
			DEBUG("lower: %s upper: %s",
				pdp_parse_ptr->lower, pdp_parse_ptr->upper);

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

	if (rptr)
		*rptr = resp;
	else if (resp)
		FREE(resp, M_NETGRAPH);

	FREE(msg, M_NETGRAPH);
	return (error);
}

/*
 * Check if the input packet can be decapsulated
 */
static inline int
ng_gtpu_check(const priv_p priv, struct mbuf * const m,
		const struct gtu_v1_hdr * const hdr, int * const code_ptr)
{
	/* 0 to 255 : valid message types ; <0 is error */
	const uint16_t min_hdr_len = sizeof(struct gtu_v1_hdr);
	unsigned int hdr_len = 0;

	DEBUG("entering\n");

	/* later : must enable variable header len */
	hdr_len = min_hdr_len;
	if (unlikely(MBUF_LENGTH(m) < htons(hdr->length) + hdr_len)) {
		*code_ptr = -1;
		goto drop;
	}

	/* uint8_t, thus no ntoh needed */
	*code_ptr = hdr->message_type;
	return hdr_len;

drop:
#ifdef NG_GTPU_STATS
	STATS_INC(priv, recvRunts);
#endif
	log(LOG_ERR, "%s: drop error: %d\n", __func__, *code_ptr);
	return (0);
}

/*
 * Handle incoming data frame from below (lower_rx node)
 *
 * Data coming from the lower link are checked. Matching data are
 * sent to one of the upper links.
 */
static int
ng_gtpu_rcvdata_lower_rx(const hook_p hook, struct mbuf *m, meta_p meta)
{
	priv_p priv = hook->node_private;
	int error = EINVAL;
	struct gtu_v1_hdr *hdr;
	int code, hdr_len;
	hook_p upper;

	if (unlikely(!priv)) {
		log(LOG_ERR, "%s: no node->priv\n", __func__);
		error = ENOTCONN;
		goto drop;
	}

	/* check that we can read the GTP-U header */
	m = m_pullup(m, sizeof(struct gtu_v1_hdr));
	if (unlikely(m == NULL)) {
		goto drop;
	}

	hdr = mtod(m, struct gtu_v1_hdr *);
	hdr_len = ng_gtpu_check(priv, m, hdr, &code);
	DEBUG("code: %d", code);

	switch (code) {
		/* decapsulation */
	case NGM_GTPU_DATA_PACKET:
		/* from TEID, find the correct upper hook */
		/* as in ng_cisco for fetching upper hook from header field */
#ifdef GTPU_TEID_CACHE
		/* first check, using the PDP cache */
		if (likely(priv->pdp_cache[TEID_HASH(htonl(hdr->teid))].head_tag ==
					htonl(hdr->teid))) {
			upper = priv->pdp_cache[TEID_HASH(htonl(hdr->teid))].head_hook;
		} else
			/* then, using the full TEID hash table */
#endif
		upper = ng_gtpu_rx_findentry(priv, htonl(hdr->teid));

		if (unlikely(upper == NULL)) {
			log(LOG_ERR, "%s: no upper for %d\n", __func__, htonl(hdr->teid));
			goto nomatch;
		}

		/* data : skip header */
		/* later must enable variable header len
		 * see ng_rfc1483.c::ng_rfc1483_rcvdata()
		 * => ptr / start m_adj(m, ptr - start) */
		/* adjust gtpu header => decapsulate */
		m_adj(m, hdr_len);
#ifdef NG_GTPU_STATS
		STATS_INC(priv, recvPackets);
		STATS_ADD(priv, recvOctets, MBUF_LENGTH(m));
#endif
		DEBUG("sending packet");
		NG_SEND_DATA(error, upper, m, meta);
		break;
	case NGM_GTPU_ECHO_REQ:
		/* echo req : send reply */
		/* change message type */
		hdr->message_type = NGM_GTPU_ECHO_REP;
#ifdef NG_GTPU_STATS
		STATS_INC(priv, recvInvalid); /* later : should be recvReqPackets */
#endif
		/*
		 * NB : gtpu_lower_rx is not a connected socket
		 * lower_rx not completely defined
		 * we can fetch remote IP @ / UDP port in meta
		 * local port is known : use route table for local IP @
		 * then, switch IP addrs UDP ports in meta
		 */
		/* later NG_SEND_DATA(error, priv->gtpu_lower_rx, m, meta); */

		goto nomatch; /* XXX for now */
		break;
	default:
		/* later : add error message and send back to the emitter
		 * reuse present mbuf => do not drop
		 * fetch IP / UDP in meta */
#ifdef NG_GTPU_STATS
		STATS_INC(priv, recvInvalid);
#endif
		log(LOG_ERR,
		    "%s : unknown message type: 0x%x\n", __func__, code);
		goto nomatch;
	}

	return 0;

nomatch:
	if (!priv->gtpu_nomatch) {
		NG_FREE_DATA(m,meta);
		error = EINVAL;
	} else {
		NG_SEND_DATA(error, priv->gtpu_nomatch, m, meta);
	}
	return error;

drop:
	NG_FREE_DATA(m, meta);
	return error;
}

/*
 * Handle outgoing data frame from the upper nodes
 * encapsulation
 *
 * Data coming from one of the upper links are forwarded through one
 * lower link.
 */
static int
ng_gtpu_rcvdata_upper(const hook_p hook, struct mbuf *m, meta_p meta)
{
#if (defined NG_GTPU_STATS) || ((defined GTPU_PACKET_QUEUES) && (defined __FastPath__))
	priv_p priv = hook->node_private;
#endif
	int error = 0;
	struct gtu_v1_hdr *hdr;
	struct ng_pdp_ctxt_filter * hpriv;
	uint16_t length_ori;

#ifdef NG_GTPU_STATS
	if (unlikely(!priv)) {
		log(LOG_ERR, "%s: no node->priv\n", __func__);
		error = ENOTCONN;
		goto drop;
	}
#endif

	hpriv = NG_HOOK_PRIVATE(hook);

	if (unlikely(!hpriv)) {
		error = ENOTCONN;
		goto drop;
	}

	DEBUG("gtpu_upper");

#if (defined GTPU_PACKET_QUEUES) && (defined __FastPath__)
	/* the tunnel is not configured or the packet queue exists : store this mbuf */
	if (unlikely(hpriv->teid_tx == 0 ||
	             hpriv->gtpu_lower_tx == NULL ||
	             hpriv->pktq_idx != -1)) {
		DEBUG("trying to add packet to queue %d\n",hpriv->pktq_idx);
		if ( likely( hpriv->gtpu_upper != NULL ) ) {
			if (unlikely(gtpu_pktq_add_pkt(&priv->cfg, m, meta, hpriv, &hpriv->pktq_idx)))
				log(LOG_ERR,"%s:%d add packet to queue failed\n", __func__, __LINE__);
		}
	}
	if (likely(hpriv->teid_tx != 0 &&
	           hpriv->gtpu_lower_tx != NULL)) {
		/* the tunnel is fully configured, the packet queue exists : send some mbufs out */
		if ( unlikely(hpriv->pktq_idx >= 0) ) {
			DEBUG("trying to send packet from queue\n");
			if (unlikely(gtpu_pktq_send_pkts(&priv->cfg, hpriv, &hpriv->pktq_idx)))
				log(LOG_ERR,"%s:%d send packets in queue failed\n", __func__, __LINE__);
			return EINVAL; /* in this way, we keep the remaining mbufs */
		}
	} else
		/* the tunnel is not configured, we keep the mbufs in the queue */
		return EINVAL;
#else
	/* fetch TEID from hook->priv */
	/* checks for partially configured tunnels */
	if ( unlikely(hpriv->teid_tx == 0) ) {
		log(LOG_ERR, "%s no teid_tx\n", __func__);

		log(LOG_ERR, "teid_tx: %u teid_rx: %u flags: %u self: %s upper: %s lower: %s\n",
				hpriv->teid_tx, hpriv->teid_rx, hpriv->flags_tx,
				hpriv->self?hpriv->self->name:"null",
				hpriv->gtpu_upper?hpriv->gtpu_upper->name:"null",
				hpriv->gtpu_lower_tx?hpriv->gtpu_lower_tx->name:"null");

		error = EINVAL;
		goto drop;
	}
	if ( unlikely(hpriv->gtpu_lower_tx==NULL) ) {
		log(LOG_ERR, "%s no lower_tx\n", __func__);

		log(LOG_ERR, "teid_tx: %u teid_rx: %u flags: %u self: %s upper: %s lower: %s\n",
				hpriv->teid_tx, hpriv->teid_rx, hpriv->flags_tx,
				hpriv->self?hpriv->self->name:"null",
				hpriv->gtpu_upper?hpriv->gtpu_upper->name:"null",
				hpriv->gtpu_lower_tx?hpriv->gtpu_lower_tx->name:"null");

		error = EINVAL;
		goto drop;
	}
#endif /* (defined GTPU_PACKET_QUEUES) && (defined __FastPath__) */
	length_ori = MBUF_LENGTH(m);
	/* if the tunnel is configured, prepare correct header */
	/* later : variable length for the header : parse the flags_tx */
	M_PREPEND(m, sizeof(struct gtu_v1_hdr), M_DONTWAIT);
	if (unlikely(!m)) {
		log(LOG_ERR, "%s no memory\n", __func__);
		error = ENOBUFS;
		goto drop;
	}

	hdr = mtod(m, struct gtu_v1_hdr *);
	/* set message type */
	hdr->message_type = NGM_GTPU_DATA_PACKET;
	hdr->length = htons(length_ori);
	hdr->teid = htonl(hpriv->teid_tx);
	hdr->flags = hpriv->flags_tx; 			/* flags for this tunnel */

#ifdef NG_GTPU_STATS
	STATS_INC(priv, xmitPackets);
	STATS_ADD(priv, xmitOctets, MBUF_LENGTH(m));
#endif

#ifdef __FastPath__
	/* for tunnels with non-default TOS value */
	if (hpriv->tos) {
		/* TOS change for packets forwarded by the Fastpath */
		m_priv(m)->flags |= M_TOS;
		m_priv(m)->tos = hpriv->tos;
	}
#endif

	/* check with MTU before prepending
	   => dump longer packets goto drop; */
	NG_SEND_DATA(error, hpriv->gtpu_lower_tx, m, meta);

	return 0;

drop:
	NG_FREE_DATA(m, meta);
	return error;
}

/*
 * Receive data on a lower tx hook
 *
 * Data coming from the lower link are checked. Matching data are
 * sent to one of the upper links.
 */
static int
ng_gtpu_rcvdata_lower_tx(const hook_p hook, struct mbuf *m, meta_p meta)
{
	priv_p priv = hook->node_private;
	int error = EINVAL;
	struct gtu_v1_hdr *hdr;
	int code;
	struct lower_tx_private *lower_priv_ptr =
		(struct lower_tx_private *) NG_HOOK_PRIVATE(hook);;

	if (unlikely(!priv)) {
		log(LOG_ERR, "%s: no node->priv\n", __func__);
		error = ENOTCONN;
		goto drop;
	}

	if (unlikely(!lower_priv_ptr)) {
		error = ENOTCONN;
		goto drop;
	}

	/* assert correct hook type */
	if (unlikely(lower_priv_ptr->type != LOWER_HOOK_TYPE)) {
		log(LOG_ERR, "%s gtpu_lower_tx: inconsistent type %d\n",
		    __func__, lower_priv_ptr->type);
		goto drop;
	}

	/* check that we can read the GTP-U header */
	m = m_pullup(m, sizeof(struct gtu_v1_hdr));
	if (unlikely(m == NULL)) {
		goto drop;
	}

	hdr = mtod(m, struct gtu_v1_hdr *);
	ng_gtpu_check(priv, m, hdr, &code);
	DEBUG("gtpu_lower_tx");

	/* later : check expected TEID : hpriv->(head)->teid_tx */
	switch (code) {
	case NGM_GTPU_ECHO_REP:
		/* echo reply => keep alive */
		node_lock(priv);
		/* later : date for REP reception */
		priv->rep_seen = 1;
		node_unlock(priv);
		NG_FREE_DATA(m, meta);
		break;
	default:
#ifdef NG_GTPU_STATS
		STATS_INC(priv, recvInvalid);
#endif
		/* later : send an error indication to the remote endpoint
		 * reuse present mbuf => do not drop
		 * fetch remote IP / UDP in meta */
		/* later :	NG_SEND_DATA(error, priv->gtpu_lower_tx, m, meta); */
		log(LOG_ERR,
		    "%s : gtpu_lower_tx: unknown message type: 0x%x\n", __func__, code);
		goto nomatch; /* XXX for now */
	}

	return 0;

nomatch:
	if (!priv->gtpu_nomatch) {
		NG_FREE_DATA(m,meta);
		error = EINVAL;
	} else {
		NG_SEND_DATA(error, priv->gtpu_nomatch, m, meta);
	}
	return error;

drop:
	NG_FREE_DATA(m, meta);
	return error;
}

/*
 * Shutdown processing
 */
static int
ng_gtpu_rmnode(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
#if (defined GTPU_PACKET_QUEUES) && (defined __FastPath__)
	gtpu_pktq_exit(&priv->cfg);
#endif
	node->flags |= NG_INVALID;
	ng_cutlinks(node);
	ng_unname(node);

	/* XXX need locks ? RCU in the fastpath */

	NG_NODE_SET_PRIVATE(node, NULL);

#ifdef GTPU_TEID_CACHE
	ng_free(priv->pdp_cache);
#endif
	ng_free(priv->pdp_hashtable);
	ng_free(priv->findhook_hashtable);

	ng_free(priv);
	NG_NODE_UNREF(node);
	return 0;
}

/*
 * Hook disconnection
 * If all the hooks are removed, let's free itself.
 */
static int
ng_gtpu_disconnect(hook_p hook)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_pdp_ctxt_filter * hook_pdp_ptr;
	struct ng_pdp_ctxt_bucket * bucket, * bucket2;
	struct lower_tx_private * lower_priv_ptr;
	struct ng_pdp_ctxt_filter *f, *f_tmp;
	int i;

	/* XXX need locks ? RCU in the fastpath */

	/* later : stop the timers */

	hook->hook_rcvdata = NULL;

	/* only lower_rx and nomatch have NULL hpriv */
	if (unlikely(NG_HOOK_PRIVATE(hook) == NULL)) {
		/* if lower_rx */
		if (likely((hook == priv->gtpu_lower_rx))) {
			/* also un-configure => all PDP */
			DEBUG("gtpu_lower_rx 1");
			for (i = 0; i < TEID_HASHSIZE; i++) {
				bucket = &priv->pdp_hashtable[i];
				vnb_write_lock(&bucket->lock);
				LIST_FOREACH_SAFE(f, f_tmp, &(bucket->head), next_hash) {

					/* only remove when gtpu_lower_tx exists */
					if (f->gtpu_lower_tx) {
						lower_priv_ptr = NG_HOOK_PRIVATE(f->gtpu_lower_tx);
						if (unlikely(lower_priv_ptr == NULL))
							continue;
						DEBUG("gtpu_lower_rx 2");

						/* also un-configure all lower_rx */
						vnb_write_lock(&lower_priv_ptr->lock);
						LIST_REMOVE(f, next_lower);
						vnb_write_unlock(&lower_priv_ptr->lock);
					}
					DEBUG("gtpu_lower_rx 3");
					/* also un-configure in findhook hashtable */
					bucket2 = &priv->findhook_hashtable[UPPER_HASH(f->tag)];
					vnb_write_lock(&bucket2->lock);
					LIST_REMOVE(f, next_findhook);
					vnb_write_unlock(&bucket2->lock);

					/* cleanup the upper private struct */
					f->teid_tx = f->teid_rx = 0;
					f->gtpu_upper = NULL;
					f->gtpu_lower_tx = NULL;
					f->flags_tx = 0;
					LIST_REMOVE(f, next_hash);
#ifdef GTPU_TEID_CACHE
					upper_cache_update(bucket, priv, f);
#endif
				}
				vnb_write_unlock(&bucket->lock);
			}

		}
		/* Zero out hook pointer */
		if (hook == priv->gtpu_lower_rx) {
			priv->gtpu_lower_rx = NULL;
		}
		if (hook == priv->gtpu_nomatch) {
			priv->gtpu_nomatch = NULL;
		}

	} else if (strncmp(hook->name, NG_GTPU_HOOK_LOWER_PREFIX,
			sizeof(NG_GTPU_HOOK_LOWER_PREFIX) - 1) == 0) {
		/* lower_tx : with a known PREFIX */
		lower_priv_ptr = NG_HOOK_PRIVATE(hook);

		if (!lower_priv_ptr)
			goto cleanup;

		DEBUG("gtpu_lower_tx 4");
		vnb_write_lock(&lower_priv_ptr->lock);
		/* find entry in the list */
		LIST_FOREACH_SAFE(f, f_tmp, &(lower_priv_ptr->head), next_lower) {
			/* also un-configure(upper == tunnels using this ksocket) */
			if (likely(f->teid_rx != 0)) {

				/* also remove hashtable entry */
				DEBUG("gtpu_lower_tx 5");
				bucket = &priv->pdp_hashtable[TEID_HASH(f->teid_rx)];
				vnb_write_lock(&bucket->lock);
				DEBUG("gtpu_lower_tx rm list");
				LIST_REMOVE(f, next_hash);
#ifdef GTPU_TEID_CACHE
				upper_cache_update(bucket, priv, f);
#endif
				vnb_write_unlock(&bucket->lock);

				/* also remove findhook hashtable entry */
				DEBUG("gtpu_lower_tx 5a");
				bucket = &priv->findhook_hashtable[UPPER_HASH(f->tag)];
				vnb_write_lock(&bucket->lock);
				LIST_REMOVE(f, next_findhook);
				vnb_write_unlock(&bucket->lock);

				/* cleanup the upper private struct */
				f->teid_tx = f->teid_rx = 0;
				f->gtpu_upper = NULL;
				f->gtpu_lower_tx = NULL;
				f->flags_tx = 0;
				LIST_REMOVE(f, next_lower);
			}
		}
		/* also unregister from the linked list of lower_tx */
		vnb_write_lock(&priv->lower_list.lock);
		LIST_REMOVE(lower_priv_ptr, next_lower);
		vnb_write_unlock(&priv->lower_list.lock);

		vnb_write_unlock(&lower_priv_ptr->lock);

		/* also remove lower->priv */
		ng_free(lower_priv_ptr);

		NG_HOOK_SET_PRIVATE(hook, NULL);
	} else if (strncmp(hook->name, NG_GTPU_HOOK_UPPER_PREFIX,
			sizeof(NG_GTPU_HOOK_UPPER_PREFIX) - 1) == 0) {
		/* upper : with a known PREFIX */
		hook_pdp_ptr = NG_HOOK_PRIVATE(hook);

		if (!hook_pdp_ptr)
			goto cleanup;

		DEBUG("upper 6");
		/* Att : upper can be *not configured* */
		if (likely(hook_pdp_ptr->teid_rx != 0)) {
			/* also remove hashtable entry */
			DEBUG("upper 7");
			bucket = &priv->pdp_hashtable[TEID_HASH(hook_pdp_ptr->teid_rx)];
			vnb_write_lock(&bucket->lock);
			LIST_REMOVE(hook_pdp_ptr, next_hash);
#ifdef GTPU_TEID_CACHE
			upper_cache_update(bucket, priv, hook_pdp_ptr);
#endif
			vnb_write_unlock(&bucket->lock);
		}

		/* also remove lower_tx->entry */
		if (likely(hook_pdp_ptr->gtpu_lower_tx != NULL)) {
			lower_priv_ptr = NG_HOOK_PRIVATE(hook_pdp_ptr->gtpu_lower_tx);
			DEBUG("upper 8");
			if (lower_priv_ptr) {
				vnb_write_lock(&lower_priv_ptr->lock);
				LIST_REMOVE(hook_pdp_ptr, next_lower);
				vnb_write_unlock(&lower_priv_ptr->lock);
			}
		}

		/* also remove findhook hashtable entry */
		bucket = &priv->findhook_hashtable[UPPER_HASH(hook_pdp_ptr->tag)];
		vnb_write_lock(&bucket->lock);
		LIST_REMOVE(hook_pdp_ptr, next_findhook);
		vnb_write_unlock(&bucket->lock);

		/* remove hpriv */
		ng_free(hook_pdp_ptr);

		NG_HOOK_SET_PRIVATE(hook, NULL);
	}

	/* Go away if no longer connected to anything */
	/* XXX to be discussed : maybe should be kept alive even
	 * with no hooks */
cleanup:
	if (unlikely(node->numhooks == 0))
		ng_rmnode(node);
	return 0;
}

#if defined(__LinuxKernelVNB__)
module_init(ng_gtpu_init);
module_exit(ng_gtpu_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB GTPU node");
MODULE_LICENSE("6WIND");
#endif
