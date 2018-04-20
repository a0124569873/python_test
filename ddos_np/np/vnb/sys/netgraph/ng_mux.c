/*
 * Copyright 2009-2013 6WIND S.A.
 */

/*
 * This node receive packets from in_%d and route them to out hook
 * drop packets from out
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
#include <netgraph/ng_mux.h>

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_MUX, "ng_mux",
	      "netgraph MUX");
#else
#define M_NETGRAPH_MUX M_NETGRAPH
#endif

/*
 * NG_MUX_STATS to enable packets / bytes counters
 * NG_MUX_DEBUG to enable trace in input / output processing
 */
//#define NG_MUX_DEBUG 1
#if defined(__LinuxKernelVNB__)
#define NG_MUX_STATS 1
#endif

/* Local definitions */

/* Per-link private data */
struct ng_mux_link_hook_private {
	LIST_ENTRY(ng_mux_link_hook_private) next;   /* next in hashtable */
	hook_p hook;                                 /* pointer to associated hook */
	uint32_t tag;                                /* in hook tag, used in in_%d */
};

typedef struct ng_mux_link_hook_private *hookpriv_p;

LIST_HEAD(ng_mux_private_list, ng_mux_link_hook_private);
struct in_hook_bucket {
	struct ng_mux_private_list head;   /* the list of entries for this hash */
	vnb_rwlock_t lock;                 /* lock for bucket access */
};

/* Per-node private data */
struct ng_mux_private {
	node_p node;                                  /* back pointer to node */
#ifdef NG_MUX_DEBUG
	struct ng_mux_config conf;                    /* node configuration */
#endif
#ifdef NG_MUX_STATS
	struct ng_mux_stats stats;                    /* node stats */
	vnb_rwlock_t lock;                            /* lock for bucket access */
#endif
	hook_p  out;                                  /* out hook */
	struct in_hook_bucket bucket[HASHTABLE_SIZE]; /* in hooks */
};

typedef struct ng_mux_private *priv_p;

/* Local functions */

/* Netgraph node methods */
static ng_constructor_t ng_mux_constructor;
static ng_rcvmsg_t ng_mux_rcvmsg;
static ng_shutdown_t ng_mux_rmnode;
static ng_newhook_t ng_mux_newhook;
static ng_findhook_t ng_mux_findhook;
static ng_rcvdata_t ng_mux_rcvdata;
static ng_disconnect_t ng_mux_disconnect;

/* Local variables */

#ifdef NG_MUX_DEBUG
/* Parse type for struct ng_mux_config */
static const struct ng_parse_struct_field
ng_mux_config_type_fields[] = NG_MUX_CONFIG_TYPE_INFO;
static const struct ng_parse_type ng_mux_config_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_mux_config_type_fields
};
#endif

#ifdef NG_MUX_STATS
/* Parse type for struct ng_mux_stats */
static const struct ng_parse_struct_field
ng_mux_stats_type_fields[] = NG_MUX_STATS_TYPE_INFO;
static const struct ng_parse_type ng_mux_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_mux_stats_type_fields
};
#endif

static const struct ng_cmdlist ng_mux_cmdlist[] = {
#ifdef NG_MUX_DEBUG
	{
		NGM_MUX_COOKIE,
		NGM_MUX_SET_CONFIG,
		"setconfig",
		.mesgType = &ng_mux_config_type,
		.respType = NULL
	},
	{
		NGM_MUX_COOKIE,
		NGM_MUX_GET_CONFIG,
		"getconfig",
		.mesgType = NULL,
		.respType = &ng_mux_config_type
	},
#endif
#ifdef NG_MUX_STATS
	{
		NGM_MUX_COOKIE,
		NGM_MUX_GET_STATS,
		"getstats",
		.mesgType = NULL,
		.respType = &ng_mux_stats_type
	},
	{
		NGM_MUX_COOKIE,
		NGM_MUX_CLR_STATS,
		"clrstats",
		.mesgType = NULL,
		.respType = NULL
	},
	{
		NGM_MUX_COOKIE,
		NGM_MUX_GETCLR_STATS,
		"getclrstats",
		.mesgType = NULL,
		.respType = &ng_mux_stats_type
	},
#endif

	{ 0, 0, NULL, NULL, NULL }
};

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_mux_typestruct) = {
 .version = NG_VERSION,
 .name = NG_MUX_NODE_TYPE,
 .mod_event = NULL,                   /* Module event handler (optional) */
 .constructor = ng_mux_constructor,   /* Node constructor */
 .rcvmsg = ng_mux_rcvmsg,             /* control messages come here */
 .shutdown = ng_mux_rmnode,           /* reset, and free resources */
 .newhook = ng_mux_newhook,           /* first notification of new hook */
 .findhook = ng_mux_findhook,         /* only if you have lots of hooks */
 .connect = NULL,                     /* final notification of new hook */
 .afterconnect = NULL,
 .rcvdata = ng_mux_rcvdata,           /* date comes here */
 .rcvdataq = ng_mux_rcvdata,          /* or here if being queued */
 .disconnect = ng_mux_disconnect,     /* notify on disconnect */
 .rcvexception = NULL,               /* exceptions come here */
 .dumpnode = NULL,
 .restorenode = NULL,
 .dumphook = NULL,
 .restorehook = NULL,
 .cmdlist = ng_mux_cmdlist,           /* commands we can convert */
};

NETGRAPH_INIT(mux, &ng_mux_typestruct);
NETGRAPH_EXIT(mux, &ng_mux_typestruct);

/******************************************************************
                        NETGRAPH NODE METHODS
******************************************************************/

/*
 * Node constructor
 *
 * Called at splnet()
 */
static int
ng_mux_constructor(node_p * nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int    i;
	int    error;

#ifdef SPLASSERT
	SPLASSERT(net, __FUNCTION__);
#endif

	/* Allocate and initialize private info */
#if !defined(M_ZERO)
	priv = ng_malloc(sizeof(*priv), M_NOWAIT);
#else
	priv = ng_malloc(sizeof(*priv), M_NOWAIT | M_ZERO);
#endif
	if (priv == NULL)
		return (ENOMEM);
#if !defined(M_ZERO)
	bzero(priv, sizeof(*priv));
#endif

	for (i=0; i<HASHTABLE_SIZE; i++) {
		LIST_INIT(&priv->bucket[i].head);
		vnb_rwlock_init(&priv->bucket[i].lock);
	}

#ifdef NG_MUX_DEBUG
	priv->conf.debugFlag = NG_MUX_DEBUG_NONE;
#endif

#ifdef NG_MUX_STATS
	vnb_rwlock_init(&priv->lock);
#endif

	/* Call superclass constructor that mallocs *nodep */
	if ((error = ng_make_node_common(&ng_mux_typestruct, nodep, nodeid))) {
		ng_free(priv);
		return (error);
	}

	NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->node = *nodep;

	/* Done */
	return 0;
}

static inline hook_p
ng_get_mux_hook(struct in_hook_bucket *bucket, unsigned int tag)
{
	hookpriv_p hpriv;

	LIST_FOREACH(hpriv, &bucket->head, next) {
		if (hpriv->tag == tag)
			return hpriv->hook;
	}

	return NULL;
}

/*
 * Method for attaching a new hook
 */
static int
ng_mux_newhook(node_p node, hook_p hook, const char *name)
{
	struct in_hook_bucket *bucket;
	const priv_p priv = NG_NODE_PRIVATE(node);

	/* Check for a nhlfe hook */
	if (strncmp(name, NG_MUX_HOOK_IN_PREFIX,
		    sizeof(NG_MUX_HOOK_IN_PREFIX) - 1) == 0) {
		const char     *tag_str;
		char           *err_ptr;
		unsigned long   tag;
		hookpriv_p      hpriv;

		/* Get the link index Parse link_0xa, link_10, ... */
		tag_str = name + sizeof(NG_MUX_HOOK_IN_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0')
			return (EINVAL);

		/*
		 * Do not create twice a link hook
		 *
		 * Check if a previous mux bucket exists by matching 10 right bits of tag
		 */
		bucket = MUX_BUCKET(tag);

		/* Array exist and memory is reserved */
		vnb_read_lock(&bucket->lock);
		if (ng_get_mux_hook(bucket, tag) != NULL) {
			vnb_read_unlock(&bucket->lock);
			return (ENOMEM);
		}
		vnb_read_unlock(&bucket->lock);

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
		hpriv->tag = tag;
		NG_HOOK_SET_PRIVATE(hook, hpriv);

		/* Initialize the hash entry */
		hpriv->hook = hook;

		vnb_write_lock(&bucket->lock);
		if (ng_get_mux_hook(bucket, tag) != NULL) {
			vnb_write_unlock(&bucket->lock);

			/* free hpriv */
			NG_HOOK_SET_PRIVATE(hook, NULL);
			ng_free(hpriv);
			return (ENOMEM);
		}

		/* add to list */
		LIST_INSERT_HEAD(&bucket->head, hpriv, next);
		vnb_write_unlock(&bucket->lock);

		return 0;

		/*
		 * Check for a out hook
		 */
	} else if (strcmp(name, NG_MUX_HOOK_OUT) == 0) {
		/* Do not connect twice a lower hook */
		if (priv->out != NULL)
			return (EISCONN);

		priv->out = hook;
		return 0;
	}

	/* Unknown hook name */
	return (EINVAL);
}

/*
 * Method for find a hook
 *
 * Race condition exists for finding and creating/deleting hooks
 */
static hook_p
ng_mux_findhook(node_p node, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct in_hook_bucket *bucket;
	hook_p hook = NULL;

	/* Check for a nhlfe hook */
	if (strncmp(name, NG_MUX_HOOK_IN_PREFIX,
		    sizeof(NG_MUX_HOOK_IN_PREFIX) - 1) == 0) {
		const char     *tag_str;
		char           *err_ptr;
		unsigned long   tag;

		/* Get the link index Parse link_0xa, link_10, ... */
		tag_str = name + sizeof(NG_MUX_HOOK_IN_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0')
			return NULL;

		/*
		 * Check if a previous mux bucket exists by matching 10 right bits of tag
		 */
		bucket = MUX_BUCKET(tag);

		/* Array exist and memory is reserved */
		vnb_read_lock(&bucket->lock);
		hook = ng_get_mux_hook(bucket, tag);
		vnb_read_unlock(&bucket->lock);

		/*
		 * Check for a out hook
		 */
	} else if (strcmp(name, NG_MUX_HOOK_OUT) == 0) {
		hook = priv->out;
	}

	return hook;
}

/* Receive a control message from ngctl or the netgraph's API */
static int
ng_mux_rcvmsg(node_p node, struct ng_mesg * msg,
	      const char *retaddr, struct ng_mesg ** rptr, struct ng_mesg **nl_msg)
{
#if defined(NG_MUX_DEBUG) || defined(NG_MUX_STATS)
	const priv_p priv = NG_NODE_PRIVATE(node);
#endif
	struct ng_mesg *resp = NULL;
	int             error = 0;

	switch (msg->header.typecookie) {
		/* Case node id (COOKIE) is suitable */
	case NGM_MUX_COOKIE:
		switch (msg->header.cmd) {
#ifdef NG_MUX_DEBUG
		case NGM_MUX_SET_CONFIG: {
			const priv_p priv = NG_NODE_PRIVATE(node);
			struct ng_mux_config * const conf =
				(struct ng_mux_config *)msg->data;

			if (msg->header.arglen != sizeof(*conf)) {
				error = EINVAL;
				break;
			}

			priv->conf = *conf;
			break;
		}
		case NGM_MUX_GET_CONFIG: {
			struct ng_mux_config *conf;

			NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			conf = (struct ng_mux_config *) resp->data;
			*conf = priv->conf;	/* no sanity checking needed */
			break;
		}
#endif
#ifdef NG_MUX_STATS
		case NGM_MUX_GET_STATS:
		case NGM_MUX_CLR_STATS:
		case NGM_MUX_GETCLR_STATS: {
			if (msg->header.cmd != NGM_MUX_CLR_STATS) {
				NG_MKRESPONSE(resp, msg,
					      sizeof(priv->stats), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				vnb_read_lock(&priv->lock);
				memcpy(resp->data,
				       &priv->stats, sizeof(priv->stats));
				vnb_read_unlock(&priv->lock);
			}

			if (msg->header.cmd != NGM_MUX_GET_STATS) {
				vnb_write_lock(&priv->lock);
				memset(&priv->stats, 0, sizeof(priv->stats));
				vnb_write_unlock(&priv->lock);
			}

			break;
		}
#endif
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
ng_mux_disconnect(hook_p hook)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);

	/* Out going data hooks */
	if (hook == priv->out) {
		priv->out = NULL;
	} else {
		/* Incoming data hooks */
		hookpriv_p hpriv = NG_HOOK_PRIVATE(hook);
		struct in_hook_bucket *bucket = MUX_BUCKET(hpriv->tag);

		/* Clean MUX_HOOK */
		vnb_write_lock(&bucket->lock);
		LIST_REMOVE(hpriv, next);
		vnb_write_unlock(&bucket->lock);

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
 * Called at splnet()
 */
static int
ng_mux_rmnode(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	int i = 0;

#ifdef SPLASSERT
	SPLASSERT(net, __FUNCTION__);
#endif

	node->flags |= NG_INVALID;	/* inclusif or */
	ng_cutlinks(node);
	ng_unname(node);

	/* Free MUX */
	for (i = 0; i < HASHTABLE_SIZE; i++) {
		hookpriv_p hpriv,hpriv2;

		vnb_write_lock(&priv->bucket[i].lock);
		LIST_FOREACH_SAFE(hpriv, hpriv2, &priv->bucket[i].head, next) {
			LIST_REMOVE(hpriv, next);
			ng_free(hpriv);
		}
		vnb_write_unlock(&priv->bucket[i].lock);
	}

	/* Free private data */
	NG_NODE_SET_PRIVATE(node, NULL);
	ng_free(priv);

	/* Unref node */
	NG_NODE_UNREF(node);

	return (0);
}

/*
 * Receive data
 * Handle incoming data on a hook.
 * Called at splnet() or splimp()
 */
static int
ng_mux_rcvdata(hook_p hook, struct mbuf * m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	priv_p priv;
	int error = 0;

	if (!node) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	priv = NG_NODE_PRIVATE(node);
	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

#ifdef NG_MUX_STATS
	/* Update stats */
	vnb_write_lock(&priv->lock);
	priv->stats.recvPackets++;
#if defined(__LinuxKernelVNB__)
	priv->stats.recvOctets += m->len;
#elif defined(__FastPath__)
	priv->stats.recvOctets += m_len(m);
#endif
	vnb_write_unlock(&priv->lock);
#endif

	if (hook == priv->out) {
#ifdef NG_VLAN_STATS
		priv->stats.recvInvalid++;
#endif
		NG_FREE_DATA(m, meta);
		return EINVAL;
	}

	NG_SEND_DATA(error, priv->out, m, meta);
	return (error);
}

#if defined(__LinuxKernelVNB__)
module_init(ng_mux_init);
module_exit(ng_mux_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB MUX node");
MODULE_LICENSE("6WIND");
#endif
