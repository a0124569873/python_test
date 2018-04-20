/*
 * Copyright 2009-2013 6WIND S.A.
 */

/*
 * This node receive packets and route them to the corresponding hook
 * according to nfmark value
 */

#if defined(__LinuxKernelVNB__)

#include <linux/version.h>
#include <linux/module.h>
#include <linux/in6.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netdevice.h>
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
#include <netgraph/ng_nffec.h>
#include <netgraph/nfmark.h>

#include <netgraph/vnb_in.h>
#include <netgraph/vnb_ip.h>
#include <netgraph/vnb_ip6.h>

/* derive flow classifier masks from hash table */
/* mask for the source addresses */
#define NG_NFFEC_FLOW_CL_SORDER 	(NFFEC_HASHTABLE_ORDER/2)
#define NG_NFFEC_FLOW_CL_SSIZE  	(1<<NG_NFFEC_FLOW_CL_SORDER)
#define NG_NFFEC_FLOW_CL_SMASK  	(NG_NFFEC_FLOW_CL_SSIZE-1)

/* mask for the destination addresses : use all remaining bits */
#define NG_NFFEC_FLOW_CL_DORDER 	(NFFEC_HASHTABLE_ORDER - NG_NFFEC_FLOW_CL_SORDER)
#define NG_NFFEC_FLOW_CL_DSIZE  	(1<<NG_NFFEC_FLOW_CL_DORDER)
#define NG_NFFEC_FLOW_CL_DMASK  	(NG_NFFEC_FLOW_CL_DSIZE-1)

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_NFFEC, "ng_nffec",
			  "netgraph NFFEC");
#else
#define M_NETGRAPH_NFFEC M_NETGRAPH
#endif

/*
 * NG_NFFEC_STATS	to enable packets / bytes counters
 * NG_NFFEC_DEBUG	to enable trace in input / output processing
 */
//#define NG_NFFEC_DEBUG
#if defined(__LinuxKernelVNB__)
#define NG_NFFEC_STATS
#endif

#ifdef NG_NFFEC_DEBUG
#ifdef __LinuxKernelVNB__
#define NG_NFFEC_DPRINTF(x, y...) do { \
		log(LOG_DEBUG, "%s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#else
/* for now : force DEBUG output */
#define NG_NFFEC_DPRINTF(x, y...) do { \
		log(LOG_ERR, "FP %s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#endif
#else
#define NG_NFFEC_DPRINTF(args...) do {} while(0)
#endif

#ifdef NG_NFFEC_STATS
#define STATS_ADD(priv, name, val) do {					\
				priv_p __priv = priv;			\
				struct ng_nffec_stats *stats;		\
				stats = &__priv->stats[VNB_CORE_ID()];	\
				stats->name += (val);			\
		} while(0)
#else
#define STATS_ADD(priv, name, val) do { } while(0)
#endif

#define STATS_INC(priv, name) STATS_ADD(priv, name, 1)

/* Local definitions */

/* Per-link private data */
struct ng_nffec_link_hook_private {
	LIST_ENTRY(ng_nffec_link_hook_private) next;	/* next in hashtable */
	hook_p hook;					/* pointer to associated hook */
	uint32_t nfmark;				/* nfmark id */
};

typedef struct ng_nffec_link_hook_private *hookpriv_p;

LIST_HEAD(ng_nffec_private_list, ng_nffec_link_hook_private);
struct nffec_bucket {
	struct ng_nffec_private_list head;  /* the list of entries for this hash */
};

/*
 * nfmark from 1 to 1023 are not stored in hash table
 * instead we use a direct access map to improve performance.
 */
#define NFFEC_DIRECT_HOOK_LINKS 1024

#if defined(CONFIG_VNB_NFFEC_MAX_LOWER_IN)
#define NG_NFFEC_MAX_LOWER_IN CONFIG_VNB_NFFEC_MAX_LOWER_IN
#else
#define NG_NFFEC_MAX_LOWER_IN 64
#endif

/* Per-node private data */
struct ng_nffec_private {
	node_p node;		/* back pointer to node */
	hook_p  mux;		/* lower hook */
	hook_p  lower_in[NG_NFFEC_MAX_LOWER_IN]; /* lower input hooks */
	hook_p  orphans;	/* orphans hook */
	vnb_spinlock_t hlock;	/* lock for hashtable modifications */

#ifdef NG_NFFEC_DEBUG
	struct ng_nffec_config conf;	/* node configuration */
#endif
#ifdef NG_NFFEC_STATS
	struct ng_nffec_stats stats[VNB_NR_CPUS];	/* node stats */
#endif

	struct nffec_bucket bucket[NFFEC_HASHTABLE_SIZE];
	hook_p hook_links[NFFEC_DIRECT_HOOK_LINKS]; /* direct access table for nfmark from 1 to 1023 */
	int nffec_mode;		/* used to enable the Simple Flow Classifier mode */
};

typedef struct ng_nffec_private *priv_p;

/* Local functions */

/* Netgraph node methods */
static ng_constructor_t ng_nffec_constructor;
static ng_rcvmsg_t ng_nffec_rcvmsg;
static ng_shutdown_t ng_nffec_rmnode;
static ng_newhook_t ng_nffec_newhook;
static ng_findhook_t ng_nffec_findhook;
static ng_disconnect_t ng_nffec_disconnect;

/* Local processing */

/* Packets received from lower hook */
static int ng_nffec_rcv_mux(hook_p hook, struct mbuf *m, meta_p meta);
static int ng_nffec_rcvdata_link(hook_p hook, struct mbuf * m, meta_p meta);
static int ng_nffec_rcvdata_orphan(hook_p hook, struct mbuf * m, meta_p meta);

/* Local variables */

#ifdef NG_NFFEC_DEBUG
/* Parse type for struct ng_nffec_config */
static const struct ng_parse_struct_field
	ng_nffec_config_type_fields[] = NG_NFFEC_CONFIG_TYPE_INFO;
static const struct ng_parse_type ng_nffec_config_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_nffec_config_type_fields
};
#endif

#ifdef NG_NFFEC_STATS
/* Parse type for struct ng_nffec_stats */
static const struct ng_parse_struct_field
	   ng_nffec_stats_type_fields[] = NG_NFFEC_STATS_TYPE_INFO;
static const struct ng_parse_type ng_nffec_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_nffec_stats_type_fields
};
#endif

/* Parse type for struct ng_nffec_sfc_mode */
static const struct ng_parse_struct_field
	ng_nffec_sfc_mode_type_fields[] = NG_NFFEC_SFC_TYPE_INFO;
static const struct ng_parse_type ng_nffec_sfc_mode_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_nffec_sfc_mode_type_fields
};

static const struct ng_cmdlist ng_nffec_cmdlist[] = {
#ifdef NG_NFFEC_DEBUG
	{
		NGM_NFFEC_COOKIE,
		NGM_NFFEC_SET_CONFIG,
		"setconfig",
		.mesgType = &ng_nffec_config_type,
		.respType = NULL
	},
	{
		NGM_NFFEC_COOKIE,
		NGM_NFFEC_GET_CONFIG,
		"getconfig",
		.mesgType = NULL,
		.respType = &ng_nffec_config_type
	},
#endif
#ifdef NG_NFFEC_STATS
	{
		NGM_NFFEC_COOKIE,
		NGM_NFFEC_GET_STATS,
		"getstats",
		.mesgType = NULL,
		.respType = &ng_nffec_stats_type
	},
	{
		NGM_NFFEC_COOKIE,
		NGM_NFFEC_CLR_STATS,
		"clrstats",
		.mesgType = NULL,
		.respType = NULL
	},
	{
		NGM_NFFEC_COOKIE,
		NGM_NFFEC_GETCLR_STATS,
		"getclrstats",
		.mesgType = NULL,
		.respType = &ng_nffec_stats_type
	},
#endif
	{
		NGM_NFFEC_COOKIE,
		NGM_NFFEC_SET_MODE,
		"setmode",
		.mesgType = &ng_nffec_sfc_mode_type,
		.respType = NULL
	},
	{
		NGM_NFFEC_COOKIE,
		NGM_NFFEC_GET_MODE,
		"getmode",
		.mesgType = NULL,
		.respType = &ng_nffec_sfc_mode_type
	},

	{ 0, 0, NULL, NULL, NULL }
};

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_nffec_typestruct) = {
	.version = NG_VERSION,
	.name = NG_NFFEC_NODE_TYPE,
	.mod_event = NULL,			/* Module event handler (optional) */
	.constructor = ng_nffec_constructor,	/* Node constructor */
	.rcvmsg = ng_nffec_rcvmsg,		/* control messages come here */
	.shutdown = ng_nffec_rmnode,		/* reset, and free resources */
	.newhook = ng_nffec_newhook,		/* first notification of new hook */
	.findhook = ng_nffec_findhook,		/* only if you have lots of hooks */
	.connect = NULL,			/* final notification of new hook */
	.afterconnect = NULL,
	.rcvdata = NULL,			/* Only specific receive data functions */
	.rcvdataq = NULL,			/* Only specific receive data functions */
	.disconnect = ng_nffec_disconnect,	/* notify on disconnect */
	.rcvexception = NULL,			/* exceptions come here */
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist = ng_nffec_cmdlist,		/* commands we can convert */
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

#ifdef __FastPath__
int ng_nffec_init(void)
{
#if !defined(CONFIG_MCORE_M_TAG)
	log(LOG_ERR, "VNB: ng_nffec need M_TAG support\n");
	return EINVAL;
#else
	int error;
	void *type = (&ng_nffec_typestruct);

	log(LOG_DEBUG, "VNB: Loading ng_nffec\n");

	if ((error = ng_newtype(type)) != 0) {
		log(LOG_ERR, "VNB: ng_nffec_init failed (%d)\n",error);
		return EINVAL;
	}

	error = ng_pkt_mark_init(__FUNCTION__);
	return(error);
#endif
}
#else
NETGRAPH_INIT(nffec, &ng_nffec_typestruct);
NETGRAPH_EXIT(nffec, &ng_nffec_typestruct);
#endif

/******************************************************************
			NETGRAPH NODE METHODS
******************************************************************/

/*
 * Node constructor
 */
static int
ng_nffec_constructor(node_p * nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int	i;
	int	error;

	/* Call superclass constructor that mallocs *nodep */
	if ((error = ng_make_node_common_and_priv(&ng_nffec_typestruct, nodep,
						  &priv, sizeof(*priv), nodeid))) {
		return (error);
	}

	/* Allocate and initialize private info */
	bzero(priv, sizeof(*priv));

	for (i=0; i<NFFEC_HASHTABLE_SIZE; i++) {
		LIST_INIT(&priv->bucket[i].head);
	}

#ifdef NG_NFFEC_DEBUG
	priv->conf.debugFlag = NG_NFFEC_DEBUG_NONE;
#endif

	NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->node = *nodep;

	vnb_spinlock_init(&priv->hlock);

	/* Done */
	return 0;
}

static inline hook_p
ng_get_nffec_hook(struct nffec_bucket *bucket, unsigned int tag)
{
	hookpriv_p hpriv;

	LIST_FOREACH(hpriv, &bucket->head, next) {
		if (likely(hpriv->nfmark == tag))
			return hpriv->hook;
	}

	return NULL;
}

/*
 * Method for attaching a new hook
 */
static int
ng_nffec_newhook(node_p node, hook_p hook, const char *name)
{
	struct nffec_bucket *bucket = NULL;
	const priv_p priv = NG_NODE_PRIVATE(node);

	/* Check for a nhlfe hook */
	if (strncmp(name, NG_NFFEC_HOOK_LINK_PREFIX,
			sizeof(NG_NFFEC_HOOK_LINK_PREFIX) - 1) == 0) {
		const char	 *tag_str;
		char		   *err_ptr;
		unsigned long   tag;
		hookpriv_p	  hpriv;

		/* Get the link index Parse link_0xa, link_10, ... */
		tag_str = name + sizeof(NG_NFFEC_HOOK_LINK_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0')
			return (EINVAL);

		/* nfmark 0 is not allowed */
		if (tag == 0)
			return (EINVAL);

		if (unlikely(tag >= NFFEC_DIRECT_HOOK_LINKS)) {
			conf_lock(priv);

			bucket = NFFEC_BUCKET(tag);
			if (ng_get_nffec_hook(bucket, tag) != NULL) {
				conf_unlock(priv);
				return (EISCONN);
			}
		} else if (priv->hook_links[tag] != NULL)
			return (EISCONN);

		/* Register the per-link private data */
#if !defined(M_ZERO)
		hpriv = ng_malloc(sizeof(*hpriv), M_NOWAIT);
#else
		hpriv = ng_malloc(sizeof(*hpriv), M_NOWAIT | M_ZERO);
#endif
		if (hpriv == NULL) {
			if (unlikely(tag >= NFFEC_DIRECT_HOOK_LINKS))
				conf_unlock(priv);
			return (ENOMEM);
		}

#if !defined(M_ZERO)
		bzero(hpriv, sizeof(*hpriv));
#endif
		hpriv->nfmark = tag;
		NG_HOOK_SET_PRIVATE(hook, hpriv);

		/* Initialize the hash entry */
		hpriv->hook = hook;

		/* add to list */
		if (unlikely(tag >= NFFEC_DIRECT_HOOK_LINKS)) {
			LIST_INSERT_HEAD(&bucket->head, hpriv, next);
			conf_unlock(priv);
		} else
			priv->hook_links[tag] = hook;

		hook->hook_rcvdata = ng_nffec_rcvdata_link;
		return 0;

		/* Check for an orphans hook */
	} else if (strcmp(name, NG_NFFEC_HOOK_ORPHANS) == 0) {
		/* Do not connect twice an orphans hook */
		if (priv->orphans != NULL)
			return (EISCONN);

		priv->orphans = hook;
		hook->hook_rcvdata = ng_nffec_rcvdata_orphan;
		return 0;

		/*
		 * Check for a mux hook
		 */
	} else if (strcmp(name, NG_NFFEC_HOOK_MUX) == 0) {
		/* Do not connect twice a lower hook */
		if (priv->mux != NULL)
			return (EISCONN);

		priv->mux = hook;
		hook->hook_rcvdata = ng_nffec_rcv_mux;
		return 0;
    } else if (strncmp(name, NG_NFFEC_HOOK_LOWER_IN_PREFIX,
		       sizeof (NG_NFFEC_HOOK_LOWER_IN_PREFIX) - 1) == 0) {
	    const char     *tag_str;
	    char           *err_ptr;
	    unsigned long   tag;
	    hookpriv_p      hpriv;

	    /* Get the link index Parse lower_in_0xa, lower_in_10, ... */
	    tag_str = name + sizeof (NG_NFFEC_HOOK_LOWER_IN_PREFIX) - 1;

	    /* Allow decimal and hexadecimal values. The hexadecimal values must
	     * be prefixed by 0x */
	    tag = strtoul(tag_str, &err_ptr, 0);

	    if ((*err_ptr) != '\0')
		    return (EINVAL);

	    if (tag >= NG_NFFEC_MAX_LOWER_IN)
		    return (EINVAL);

	    if (priv->lower_in[tag] != NULL) {
		    return (EISCONN);
	    }

	    /* Register the per-link private data */
#if !defined(M_ZERO)
	    hpriv = ng_malloc(sizeof(*hpriv), M_NOWAIT);
#else
	    hpriv = ng_malloc(sizeof(*hpriv), M_NOWAIT | M_ZERO);
#endif
	    if (hpriv == NULL)
		    return (ENOMEM);

#if !defined(M_ZERO)
	    bzero(hpriv, sizeof(*hpriv));
#endif
	    hpriv->nfmark = tag;

	    hook->hook_rcvdata = ng_nffec_rcv_mux;
	    hook->node_private = priv;

	    NG_HOOK_SET_PRIVATE(hook, hpriv);

	    /* add to list */
	    priv->lower_in[tag] = hook;

	    return 0;
	}

	/* Unknown hook name */
	return (EINVAL);
}

/*
 * Method for finding a hook
 *
 * Race condition exists for finding and creating/deleting hooks
 */
static hook_p
ng_nffec_findhook(node_p node, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct nffec_bucket *bucket;
	hook_p hook = NULL;

	/* Check for a nhlfe hook */
	if (strncmp(name, NG_NFFEC_HOOK_LINK_PREFIX,
				sizeof(NG_NFFEC_HOOK_LINK_PREFIX) - 1) == 0) {
		const char	 *tag_str;
		char		   *err_ptr;
		unsigned long   tag;

		/* Get the link index Parse link_0xa, link_10, ... */
		tag_str = name + sizeof(NG_NFFEC_HOOK_LINK_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0')
			return NULL;

		if (unlikely(tag >= NFFEC_DIRECT_HOOK_LINKS)) {
			/*
			 * Check if a previous nffec bucket exists by matching 10 right bits of nfmark
			 */
			bucket = NFFEC_BUCKET(tag);

			/* Array exist */
			hook = ng_get_nffec_hook(bucket, tag);
		} else
			hook = priv->hook_links[tag];

		/* Check for an orphans hook */
	} else if (strcmp(name, NG_NFFEC_HOOK_ORPHANS) == 0) {
		hook = priv->orphans;

		/*
		 * Check for a mux hook
		 */
	} else if (strcmp(name, NG_NFFEC_HOOK_MUX) == 0) {
		hook = priv->mux;
	} else if (strncmp(name, NG_NFFEC_HOOK_LOWER_IN_PREFIX,
			   sizeof (NG_NFFEC_HOOK_LOWER_IN_PREFIX) - 1) == 0) {
		const char     *tag_str;
		char           *err_ptr;
		unsigned long   tag;

		/* Get the link index Parse lower_in_0xa, lower_in_10, ... */
		tag_str = name + sizeof(NG_NFFEC_HOOK_LOWER_IN_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0')
			return NULL;

		hook = priv->lower_in[tag];
	}

	return hook;
}

/* Receive a control message from ngctl or the netgraph's API */
static int
ng_nffec_rcvmsg(node_p node, struct ng_mesg * msg, const char *retaddr,
		struct ng_mesg ** rptr, struct ng_mesg **nl_msg)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int			 error = 0;

	switch (msg->header.typecookie) {
		/* Case node id (COOKIE) is suitable */
	case NGM_NFFEC_COOKIE:
		switch (msg->header.cmd) {
#ifdef NG_NFFEC_DEBUG
		case NGM_NFFEC_SET_CONFIG:
		{
			struct ng_nffec_config * const conf =
					(struct ng_nffec_config *)msg->data;

			if (msg->header.arglen != sizeof(*conf)) {
				error = EINVAL;
				break;
			}

			priv->conf = *conf;
			break;
		}
		case NGM_NFFEC_GET_CONFIG:
		{
			struct ng_nffec_config *conf;

			NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			conf = (struct ng_nffec_config *) resp->data;
			*conf = priv->conf;		/* no sanity checking needed */
			break;
		}
#endif
#ifdef NG_NFFEC_STATS
		case NGM_NFFEC_GET_STATS:
		case NGM_NFFEC_CLR_STATS:
		case NGM_NFFEC_GETCLR_STATS:
		{
			struct ng_nffec_stats *stats;
			int i;


			if (msg->header.cmd != NGM_NFFEC_CLR_STATS) {
				NG_MKRESPONSE(resp, msg, sizeof(*stats), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				stats = (struct ng_nffec_stats *) resp->data;
				memset(stats, 0, sizeof(*stats));
				for (i=0; i<VNB_NR_CPUS; i++) {
					stats->recvOctets += priv->stats[i].recvOctets;
					stats->recvPackets += priv->stats[i].recvPackets;
					stats->recvRunts += priv->stats[i].recvRunts;
					stats->recvInvalid += priv->stats[i].recvInvalid;
					stats->recvUnknownTag += priv->stats[i].recvUnknownTag;
					stats->xmitOctets += priv->stats[i].xmitOctets;
					stats->xmitPackets += priv->stats[i].xmitPackets;
					stats->memoryFailures += priv->stats[i].memoryFailures;
				}
			}

			if (msg->header.cmd != NGM_NFFEC_GET_STATS) {
				memset(&priv->stats, 0, sizeof(*stats));
			}

			break;
		}
#endif
		case NGM_NFFEC_SET_MODE:
		{
			struct ng_nffec_mode * const conf =
					(struct ng_nffec_mode *)msg->data;

			if (msg->header.arglen != sizeof(*conf)) {
				error = EINVAL;
				break;
			}

			priv->nffec_mode = conf->sfcEnable;
			break;
		}
		case NGM_NFFEC_GET_MODE:
		{
			struct ng_nffec_mode *conf;

			NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			conf = (struct ng_nffec_mode *) resp->data;
			conf->sfcEnable = priv->nffec_mode;		/* no sanity checking needed */
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
ng_nffec_disconnect(hook_p hook)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);

	hook->hook_rcvdata = NULL;
	/* Incoming data hooks */
	if (hook == priv->mux)
		priv->mux = NULL;
	else if (hook == priv->orphans)
		priv->orphans = NULL;
	else {
	/* Out going data hooks */
		hookpriv_p hpriv = NG_HOOK_PRIVATE(hook);

		/* Clean NFFEC_HOOK */
		if ((hpriv->nfmark < NG_NFFEC_MAX_LOWER_IN) && (hook == priv->lower_in[hpriv->nfmark]))
			priv->lower_in[hpriv->nfmark] = NULL;
		else if (unlikely(hpriv->nfmark >= NFFEC_DIRECT_HOOK_LINKS))
			LIST_REMOVE(hpriv, next);
		else
			priv->hook_links[hpriv->nfmark] = NULL;

		NG_HOOK_SET_PRIVATE(hook, NULL);
		ng_free(hpriv);
	}

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
ng_nffec_rmnode(node_p node)
{
	node->flags |= NG_INVALID;		/* inclusif or */
	ng_cutlinks(node);
	ng_unname(node);

	NG_NODE_SET_PRIVATE(node, NULL);
	/* Unref node */
	NG_NODE_UNREF(node);

	return (0);
}

/*
 * Receive data only on orphan hook
 */
static int
ng_nffec_rcvdata_orphan(hook_p hook, struct mbuf * m, meta_p meta)
{
	const priv_p priv = hook->node_private;
	int error = 0;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	/* Update stats */
	STATS_INC(priv, recvPackets);
	STATS_ADD(priv, recvOctets, MBUF_LENGTH(m));

	NG_SEND_DATA(error, priv->mux, m, meta);
	return (error);
}

/*
 * Handle incoming data from link hook
 */
static int ng_nffec_rcvdata_link(hook_p hook, struct mbuf * m, meta_p meta)
{
	const priv_p priv = hook->node_private;
	hookpriv_p hpriv = NG_HOOK_PRIVATE(hook);
	int error = 0;

	NG_NFFEC_DPRINTF("entering\n");

	if (unlikely(!priv)) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	/* Update stats */
	STATS_INC(priv, recvPackets);
	STATS_ADD(priv, recvOctets, MBUF_LENGTH(m));

	if (unlikely(!hpriv)) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}
#if defined(__LinuxKernelVNB__)
	m->mark = hpriv->nfmark;
#elif defined(CONFIG_MCORE_M_TAG)
	m_tag_add(m, vnb_nfm_tag_type, htonl(hpriv->nfmark));
	NG_NFFEC_DPRINTF("VNB: ng_nffec_rcvdata_link, set nfmark to: %u\n",
			 hpriv->nfmark);
#endif
	NG_SEND_DATA(error, priv->mux, m, meta);
	return (error);
}

/*
 * Receive data from mux
 * route pkt to nfm-%x or orphons
 */
static int
ng_nffec_rcv_mux(hook_p hook, struct mbuf *m, meta_p meta)
{
	struct nffec_bucket *bucket;
	hook_p ohook;
	int error = 0;
	uint32_t nfmark = 0;
	const priv_p priv = hook->node_private;
#ifdef NG_NFFEC_DEBUG
	node_p node = NG_HOOK_NODE(hook);
#endif
	struct vnb_ip *ip_hdr;
	uint32_t sip, dip, tmp;
	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	NG_NFFEC_DPRINTF("entering\n");

	/* Update stats */
	STATS_INC(priv, recvPackets);
	STATS_ADD(priv, recvOctets, MBUF_LENGTH(m));

	if (unlikely(priv->nffec_mode == NG_NFFEC_SFC_ENABLE)) {
		/*
		* TODO The following code is only provided as an example,
		* a better design should be made of an independent
		* flow classifier running before ng_nffec and setting
		* the nfmark.
		*/
		/* check for IPv4 header size */
		if (unlikely((m = m_pullup(m, sizeof(*ip_hdr))) == NULL)) {
			error = EINVAL;
			goto drop;
		}
		ip_hdr = mtod(m, struct vnb_ip *);
		if (unlikely((ip_hdr->ip_v != VNB_IPVERSION))) {
			struct vnb_ip6_hdr *ip6_hdr;

			if (unlikely((ip_hdr->ip_v != IP6VERSION))) {
				/* neither IPv4 or IPv6: drop it */
				error = EINVAL;
				goto drop;
			}

			if (unlikely((m = m_pullup(m, sizeof(*ip6_hdr))) == NULL)) {
				error = EINVAL;
				goto drop;
			}
			ip6_hdr = mtod(m, struct vnb_ip6_hdr *);

			sip = ntohl(ip6_hdr->ip6_src.vnb_s6_addr32[3]);
			dip = ntohl(ip6_hdr->ip6_src.vnb_s6_addr32[3]);
		} else {
			sip = ntohl(ip_hdr->ip_src.s_addr);
			dip = ntohl(ip_hdr->ip_dst.s_addr);
		}

		/* hard-coded mark : use some bits from sip/dip */
		/* use specific masks and shifts for source and dest addresses */
		tmp = (sip&NG_NFFEC_FLOW_CL_SMASK) << NG_NFFEC_FLOW_CL_DORDER |
			(dip&NG_NFFEC_FLOW_CL_DMASK);
		/* rotate LSB to MSB */
		nfmark = (tmp>>1) | ((tmp&1) << (NFFEC_HASHTABLE_ORDER-1));
		/*
		 * increment nfmark to not use nfmark==0
		 * As NFFEC_HASHTABLE_ORDER is less than 32,
		 * the incremented value is still a valid nfmark
		 */
		nfmark += 1;
	} else {
#if defined(__LinuxKernelVNB__)
		nfmark = m->mark;
#elif defined(CONFIG_MCORE_M_TAG)
		m_tag_get(m, vnb_nfm_tag_type, &nfmark);
		nfmark = ntohl(nfmark);
#endif
	}

	if (unlikely(nfmark >= NFFEC_DIRECT_HOOK_LINKS)) {
		bucket = NFFEC_BUCKET(nfmark);
		ohook = ng_get_nffec_hook(bucket, nfmark);
	} else
		ohook = priv->hook_links[nfmark];

	if (unlikely(ohook == NULL)) {
		/* No entry for that nfmark */
		STATS_INC(priv, recvUnknownTag);
#ifdef NG_NFFEC_DEBUG
		if (priv->conf.debugFlag & NG_NFFEC_DEBUG_RAW)
			NG_NFFEC_DPRINTF("%s: No entry for that tag\n", node->name);
#endif

		if (priv->orphans == NULL) {
			/* No node connected to orphan : discard packet */
#ifdef NG_NFFEC_DEBUG
			if (priv->conf.debugFlag & NG_NFFEC_DEBUG_RAW)
				NG_NFFEC_DPRINTF("%s: No node connected to orphan\n", node->name);
#endif

			error = ENOTCONN;
			goto drop;
		}

		ohook = priv->orphans;
	}

	NG_SEND_DATA(error, ohook, m, meta);
	return (error);

drop:
	NG_FREE_DATA(m, meta);
	return (error);
}

#if defined(__LinuxKernelVNB__)
module_init(ng_nffec_init);
module_exit(ng_nffec_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB NFFEC node");
MODULE_LICENSE("6WIND");
#endif
