/*
 * Copyright 2005-2013 6WIND S.A.
 */

/*
 * GRE
 * ---
 *
 * Loadable kernel module and netgraph support
 *
 */

#if defined(__LinuxKernelVNB__)

#include <linux/version.h>
#include <linux/module.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/ip.h>

#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <netgraph/vnblinux.h>
#include <linux/ipv6.h>

#elif defined(__FastPath__) /* __FastPath__ */

#include "fp-netgraph.h"
#include "net/fp-ethernet.h"
#include "netinet/fp-in.h"
#include "fp-mbuf-mtag.h"
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_gre.h>

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_GRE, "ng_gre",	"netgraph GRE");
#else
#define M_NETGRAPH_GRE M_NETGRAPH
#endif

/*
 * Local definitions
 */

/*
 * NG_GRE_STATS    to enable packets / bytes counters
 */
#if defined(__LinuxKernelVNB__)
#define NG_GRE_STATS 1
#endif

/*
 * GRE header
 */

/* Structure to represent the gre header */
struct gre_header {
#if VNB_BYTE_ORDER == VNB_LITTLE_ENDIAN
      u_int16_t   	res0:5;        		/* Reserved for future use */
      u_int16_t  	k:1;           		/* Key Present bit  */
      u_int16_t  	res1:1;           	/* Reserved for future use */
      u_int16_t  	c:1;           		/* Checksum Present bit  */
      u_int16_t 	ver:3;         		/* Version Number  */
      u_int16_t   	res2:5;        		/* Reserved for future use */
#elif VNB_BYTE_ORDER == VNB_BIG_ENDIAN
      u_int16_t  	c:1;           		/* Checksum Present bit  */
      u_int16_t  	res0:1;           	/* Reserved for future use */
      u_int16_t  	k:1;           		/* Key Present bit  */
      u_int16_t   	res1:5;        		/* Reserved for future use */
      u_int16_t   	res2:5;        		/* Reserved for future use */
      u_int16_t 	ver:3;         		/* Version Number  */
#else
#error  "Please fix <asm/byteorder.h>"
#endif
      u_int16_t		proto_type;		/* Protocol (ethertype) */
};

struct gre_checksum_header {
      u_int16_t		cksum;			/* Checksum field */
      u_int16_t		res2;			/* Reserved for future use */
};

/*
 * Per-node private data
 */
struct ng_gre_link_hook_private {
	LIST_ENTRY(ng_gre_link_hook_private) next;	/* next in hashtable */
	hook_p		hook;				/* pointer to associated hook */
	uint32_t	key;				/* in hook tag, used in key_%d (in network order) */
};

typedef struct ng_gre_link_hook_private *hookpriv_p;

LIST_HEAD(ng_gre_private_list, ng_gre_link_hook_private);
struct key_hook_bucket {
	vnb_spinlock_t			lock;		/* lock for list access */
	struct ng_gre_private_list	head;		/* the list of entries for this hash */
};

struct ng_gre_private {
	node_p			node;		/* back pointer to node */
	struct ng_gre_config	conf;		/* node configuration */
	hook_p			lower;		/* the lower hook (link) */
	hook_p			nomatch;	/* the nomatch hook */
	struct key_hook_bucket 	bucket[NG_GRE_HASHTABLE_SIZE];	/* key hooks */
#ifdef NG_GRE_STATS
	struct ng_gre_stats stats[VNB_NR_CPUS];
#endif
};

typedef struct ng_gre_private 	*priv_p;

#if defined(__FastPath__) && defined(CONFIG_MCORE_M_TAG)
static VNB_DEFINE_SHARED(int32_t, proto_tag_type);
static VNB_DEFINE_SHARED(int32_t, grekey_tag_type);
#endif

/*
 * Local functions
 */

/*
 * Netgraph node methods
 */
static ng_constructor_t ng_gre_constructor;
static ng_rcvmsg_t      ng_gre_rcvmsg;
static ng_shutdown_t    ng_gre_rmnode;
static ng_newhook_t     ng_gre_newhook;
static ng_findhook_t    ng_gre_findhook;
static ng_disconnect_t  ng_gre_disconnect;
#ifdef __LinuxKernelVNB__
static ng_dumpnode_t    ng_gre_dumpnode;
#else
static ng_restorenode_t ng_gre_restorenode;
#endif

struct ng_gre_nl_nodepriv {
	struct ng_gre_config conf;
} __attribute__ ((packed));

/*
 * Local processing
 */

static int ng_gre_recv(hook_p hook, struct mbuf *m, meta_p meta);
static int ng_gre_xmit(hook_p incoming_hook, struct mbuf *m, meta_p meta);
#ifdef __LinuxKernelVNB__
static int ng_gre_raw_cksum(u_int16_t data_len, const u_int16_t *ck_data,
			    u_int32_t *cksum);
#endif
static u_int16_t ng_gre_cksum(const struct mbuf *m);

/*
 * Local variables
 */

/* Parse type for struct ng_gre_config */
static const struct ng_parse_struct_field
	ng_gre_config_type_fields[] = NG_GRE_CONFIG_TYPE_INFO;

static const struct ng_parse_type ng_gre_config_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_gre_config_type_fields,
};

/* Parse type for struct ng_gre_stats */
static const struct ng_parse_struct_field
	ng_gre_stats_type_fields[] = NG_GRE_STATS_TYPE_INFO;

static const struct ng_parse_type ng_gre_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_gre_stats_type_fields
};

static const struct ng_cmdlist ng_gre_cmdlist[] = {
	{
	  .cookie = NGM_GRE_COOKIE,
	  .cmd = NGM_GRE_SET_CONFIG,
	  .name = "setconfig",
	  .mesgType =  &ng_gre_config_type,
	  .respType =  NULL
	},
	{
	  .cookie = NGM_GRE_COOKIE,
	  .cmd = NGM_GRE_GET_CONFIG,
	  .name = "getconfig",
	  .mesgType =  NULL,
	  .respType =  &ng_gre_config_type
	},
#ifdef NG_GRE_STATS
	{
	  .cookie = NGM_GRE_COOKIE,
	  .cmd = NGM_GRE_GET_STATS,
	  .name = "getstats",
	  .mesgType =  NULL,
	  .respType =  &ng_gre_stats_type
	},
	{
	  .cookie = NGM_GRE_COOKIE,
	  .cmd = NGM_GRE_CLR_STATS,
	  .name = "clrstats",
	  .mesgType =  NULL,
	  .respType =  NULL
	},
	{
	  .cookie = NGM_GRE_COOKIE,
	  .cmd = NGM_GRE_GETCLR_STATS,
	  .name = "getclrstats",
	  .mesgType =  NULL,
	  .respType =  &ng_gre_stats_type
	},
#endif
	{ 0, 0, NULL, NULL, NULL }
};

/*
 * Node type descriptor
 */
static VNB_DEFINE_SHARED(struct ng_type, ng_gre_typestruct) = {
	.version = NG_VERSION,
	.name = NG_GRE_NODE_TYPE,
	.mod_event = NULL,			/* Module event handler (optional) */
	.constructor = ng_gre_constructor,	/* Node constructor */
	.rcvmsg = ng_gre_rcvmsg,		/* control messages come here */
	.shutdown = ng_gre_rmnode,		/* reset, and free resources */
	.newhook = ng_gre_newhook,		/* first notification of new hook */
	.findhook = ng_gre_findhook,		/* only if you have lots of hooks */
	.connect = NULL,			/* final notification of new hook */
	.afterconnect = NULL,
	.rcvdata = NULL,			/* Only specific receive data functions */
	.rcvdataq = NULL,			/* Only specific receive data functions */
	.disconnect = ng_gre_disconnect,	/* notify on disconnect */
	.rcvexception = NULL,			/* exceptions come here */
#ifdef __LinuxKernelVNB__
	.dumpnode = ng_gre_dumpnode,
#else
	.dumpnode = NULL,
#endif
#ifdef __LinuxKernelVNB__
	.restorenode = NULL,
#else
	.restorenode = ng_gre_restorenode,
#endif
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist = ng_gre_cmdlist,		/* commands we can convert */
};

/* Local functions */

#ifdef __FastPath__
int ng_gre_init(void)
{
#if !defined(CONFIG_MCORE_M_TAG)
	log(LOG_ERR, "VNB: ng_gre need M_TAG support\n");
	return EINVAL;
#else
	int error;
	void *type = (&ng_gre_typestruct);

	log(LOG_DEBUG, "VNB: Loading ng_gre\n");

	if ((error = ng_newtype(type)) != 0) {
		log(LOG_ERR, "VNB: ng_gre_init failed (%d)\n",error);
		return EINVAL;
	}

	proto_tag_type = m_tag_type_register(PROTO_TAG_NAME);
	grekey_tag_type = m_tag_type_register(NG_GRE_TAG_NAME);
	if ((proto_tag_type < 0) || (grekey_tag_type < 0)) {
		log(LOG_ERR, "VNB: ng_gre_init failed (mtag register)\n");
		return EINVAL;
	}

	return(0);
#endif
}
#else
NETGRAPH_INIT(gre, &ng_gre_typestruct);
NETGRAPH_EXIT(gre, &ng_gre_typestruct);
#endif

/******************************************************************
		    NETGRAPH NODE METHODS
 ******************************************************************/

/*
 * Node constructor
 */
static int
ng_gre_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p 	priv;
	int 	error;
	int 	i;

#ifdef SPLASSERT
	SPLASSERT(net, __FUNCTION__);
#endif

	/* Generic node creation */
	if ((error = ng_make_node_common_and_priv(&ng_gre_typestruct, nodep,
						  &priv, sizeof(*priv), nodeid))) {
		return (error);
	}

	bzero(priv, sizeof(*priv));

	for (i=0; i<NG_GRE_HASHTABLE_SIZE; i++) {
		vnb_spinlock_init(&priv->bucket[i].lock);
		LIST_INIT(&priv->bucket[i].head);
	}

	priv->conf.debugLevel = NG_GRE_DEBUG_NONE;
	priv->conf.greHasCksum = NG_GRE_CKSUM_ENABLE;

	NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->node = *nodep;

	return (0);
}

/* Return associated hookpriv for a key_N hook. The parameter key is
 * given in network order */
static inline hook_p
ng_get_gre_hook(struct key_hook_bucket *bucket, uint32_t key)
{
    hookpriv_p hpriv;

    vnb_spinlock_lock(&bucket->lock);
    LIST_FOREACH(hpriv, &bucket->head, next) {
	    if (hpriv->key == key) {
		    vnb_spinlock_unlock(&bucket->lock);
		    return hpriv->hook;
	    }
    }
    vnb_spinlock_unlock(&bucket->lock);

    return NULL;
}

/*
 * Method for attaching a new hook
 * There are two kinds of hook:
 * 	- the lower link.
 * 	- the nomatch link.
 */
static	int
ng_gre_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p		priv = NG_NODE_PRIVATE(node);
	struct key_hook_bucket	*bucket;

	if (strncmp(name, NG_GRE_HOOK_KEY_PREFIX,
			sizeof(NG_GRE_HOOK_KEY_PREFIX) - 1) == 0) {
		const char     *tag_str;
		char           *err_ptr;
		unsigned long   tag;
		hookpriv_p      hpriv;

		/* Get the key index Parse key_0xa, key_10, ... */
		tag_str = name + sizeof(NG_GRE_HOOK_KEY_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0')
		    return (EINVAL);

		/*
		 * store the key in network order
		 */
		tag = htonl(tag);
		bucket = GRE_BUCKET(tag);

		/* Register the per-link private data */
#if !defined(M_ZERO)
		hpriv = (hookpriv_p) ng_malloc(sizeof(*hpriv), M_NOWAIT);
#else
		hpriv = (hookpriv_p) ng_malloc(sizeof(*hpriv), M_NOWAIT | M_ZERO);
#endif
		if (hpriv == NULL)
		    return (ENOMEM);

#if !defined(M_ZERO)
		bzero(hpriv, sizeof(*hpriv));
#endif
		hpriv->key = tag;
		NG_HOOK_SET_PRIVATE(hook, hpriv);

		/* Initialize the hash entry */
		hpriv->hook = hook;

		/* add to list (no duplicate because findhook is
		 * already done in ng_base) */
		vnb_spinlock_lock(&bucket->lock);
		LIST_INSERT_HEAD(&bucket->head, hpriv, next);
		vnb_spinlock_unlock(&bucket->lock);

		hook->hook_rcvdata = ng_gre_xmit;

		return 0;

	/* Check for an orphans hook */
        } else if (strcmp(name, NG_GRE_HOOK_LOWER) == 0) {
		/* Do not connect the hook twice */
		if (priv->lower != NULL)
			return (EISCONN);

		priv->lower = hook;
		hook->hook_rcvdata = ng_gre_recv;

	} else if (strcmp(name, NG_GRE_HOOK_NOMATCH) == 0) {
		/* Do not connect the hook twice */
		if (priv->nomatch != NULL)
			return (EISCONN);

		priv->nomatch = hook;
		hook->hook_rcvdata = ng_gre_xmit;

	} else {
		return (EINVAL);	/* Unknown hook name */
	}

	return 0;
}

/*
 * Method for finding a hook
 */
static hook_p
ng_gre_findhook(node_p node, const char *name)
{
	const priv_p	priv = NG_NODE_PRIVATE(node);
	struct key_hook_bucket	*bucket;
	hook_p		hook = NULL;

	/* Check for a key_%d hook */
	if (strncmp(name, NG_GRE_HOOK_KEY_PREFIX,
			sizeof(NG_GRE_HOOK_KEY_PREFIX) - 1) == 0) {
		const char     *tag_str;
		char           *err_ptr;
		unsigned long   tag;

		/* Get the link index Parse key_0xa, link_10, ... */
		tag_str = name + sizeof(NG_GRE_HOOK_KEY_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);
		tag = htonl(tag);

		if ((*err_ptr) != '\0')
		    return NULL;

		/*
		 * Check if a previous gre bucket exists by matching 10 right bits of key
		*/
		bucket = GRE_BUCKET(tag);

		/* Array exist */
		hook = ng_get_gre_hook(bucket, tag);

	/* Check for an lower hook */
	} else if (strcmp(name, NG_GRE_HOOK_LOWER) == 0) {
		hook = priv->lower;

	/*
	 * Check for a nomatch hook
	 */
	} else if (strcmp(name, NG_GRE_HOOK_NOMATCH) == 0) {
		hook = priv->nomatch;
	}

	return hook;
}

static void
ng_gre_config_copy(struct ng_gre_config *dst, struct ng_gre_config *src, int to_network)
{
	dst->debugLevel = src->debugLevel;
	dst->greHasCksum = src->greHasCksum;
	dst->greHasKey = src->greHasKey;
	dst->greRecvAnyKey = src->greRecvAnyKey;
	dst->greKeyMtag = src->greKeyMtag;
	dst->greProtoMtag = src->greProtoMtag;
	dst->greKey = src->greKey;
	if (to_network)
		dst->greKey = htonl(src->greKey);
	else
		dst->greKey = ntohl(src->greKey);
}


/*
 * Receive a control message from ngctl or the netgraph's API
 */
static int
ng_gre_rcvmsg(node_p node, struct ng_mesg *msg,	const char *retaddr,
	      struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const priv_p 	priv = NG_NODE_PRIVATE(node);
	struct ng_mesg 	*resp = NULL;
	int 		error = 0;

	switch (msg->header.typecookie) {
	    case NGM_GRE_COOKIE:
		switch (msg->header.cmd)
		{
		    case NGM_GRE_GET_CONFIG:
		    {
			struct ng_gre_config *conf;

			NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			conf = (struct ng_gre_config *)resp->data;

			ng_gre_config_copy(conf, &priv->conf, 0);

			break;
		    }

		    case NGM_GRE_SET_CONFIG:
		    {
			struct ng_gre_config * const conf =
				(struct ng_gre_config *)msg->data;

			if (msg->header.arglen != sizeof(*conf)) {
				error = EINVAL;
				break;
			}

			ng_gre_config_copy(&priv->conf, conf, 1);
			break;
		    }
#ifdef NG_GRE_STATS
		    case NGM_GRE_GET_STATS:
		    case NGM_GRE_CLR_STATS:
		    case NGM_GRE_GETCLR_STATS:
		    {
			int i;
			struct ng_gre_stats *stats;

			if (msg->header.cmd != NGM_GRE_CLR_STATS) {
				NG_MKRESPONSE(resp, msg, sizeof(*stats), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}

				stats = (struct ng_gre_stats *) resp->data;
				memset(stats, 0, sizeof(*stats));
				for (i=0; i<VNB_NR_CPUS; i++) {
					stats->numPktsEnc += priv->stats[i].numPktsEnc;
					stats->numPktsDec += priv->stats[i].numPktsDec;
					stats->numPktsTooBig += priv->stats[i].numPktsTooBig;
					stats->numMemErr += priv->stats[i].numMemErr;
					stats->numChksmErr += priv->stats[i].numChksmErr;
					stats->numKeyErr += priv->stats[i].numKeyErr;
				}
			}
			if (msg->header.cmd != NGM_GRE_GET_STATS)
				bzero(&priv->stats, sizeof(priv->stats));
			break;
		    }
#endif
		    default:
			error = EINVAL;
			break;
		} /* switch msg->header.cmd */
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
 * If all the hooks are removed, free itself.
 */
static int
ng_gre_disconnect(hook_p hook)
{
	const node_p 	node = NG_HOOK_NODE(hook);
	const priv_p 	priv = NG_NODE_PRIVATE(node);

	if (hook == priv->lower) {
		priv->lower = NULL;
		hook->hook_rcvdata = NULL;
	}
	else if (hook == priv->nomatch)
		priv->nomatch = NULL;
	else {
		hookpriv_p hpriv = NG_HOOK_PRIVATE(hook);
		struct key_hook_bucket *bucket = GRE_BUCKET(hpriv->key);

		/* Clean GRE_HOOK */
		vnb_spinlock_lock(&bucket->lock);
		LIST_REMOVE(hpriv, next);
		vnb_spinlock_unlock(&bucket->lock);

		NG_HOOK_SET_PRIVATE(hook, NULL);
		ng_free(hpriv);
		hook->hook_rcvdata = NULL;
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
ng_gre_rmnode(node_p node)
{
	/* Take down netgraph node */
	node->flags |= NG_INVALID;
	ng_cutlinks(node);
	ng_unname(node);

	NG_NODE_SET_PRIVATE(node, NULL);

	/* Unref node */
	NG_NODE_UNREF(node);

	return (0);
}

/* Retrieve ethertype in network order, stored as metadata attached to
 * the mbuf or in the packet */
static inline uint16_t ng_gre_get_proto(uint8_t use_mtag,
					struct mbuf *m)
{
#if defined(__FastPath__)
	struct fp_ip6_hdr *ip6hdr;

#if defined(CONFIG_MCORE_M_TAG)
	uint32_t tag;
	uint16_t ethertype;

	if (use_mtag) {
		if (m_tag_get(m, proto_tag_type, &tag) == 0) {
			m_tag_del(m, proto_tag_type);
			ethertype = htons(ntohl(tag));
			return ethertype;
		}
	}
#endif

	if ((m_headlen(m) > sizeof(struct fp_ip6_hdr))) {
		ip6hdr = mtod(m, struct fp_ip6_hdr *);
		if ((ip6hdr->ip6_vfc & 0xF0) == 0x60)
			return htons(IP6_PROTO_TYPE);
	}

#elif defined(__LinuxKernelVNB__)
	struct ipv6hdr *ip6hdr;

	if (use_mtag && (*(uint32_t *)m->cb == PROTO_CB_MAGIC)) {
		uint16_t ethertype;
		ethertype = *(uint16_t *)(m->cb + 4);
		*(uint32_t *)m->cb = 0;
		return ethertype;
	}

	if (pskb_may_pull(m, sizeof(struct ipv6hdr))) {
		ip6hdr = mtod(m, struct ipv6hdr *);
		if (ip6hdr->version == 6)
			return htons(IP6_PROTO_TYPE);
	}
#endif
	return  htons(IP_PROTO_TYPE); /* default */;
}

/* Set the gre key in meta-data; key is given in network order. */
static inline void ng_gre_set_key_in_mtag(struct mbuf *m, uint32_t key)
{
#if defined(__LinuxKernelVNB__) && defined(CONFIG_NET_SKBUFF_SKTAG)
	skb_add_sktag(m, SOL_SOCKET, IP_TAGINFO, NG_GRE_TAG_NAME, key);
#elif defined(__FastPath__) && defined(CONFIG_MCORE_M_TAG)
	if (grekey_tag_type >= 0) {
		m_tag_add(m, grekey_tag_type, key);
	}
#endif
}

/*
 * Receive data from lower layers
 */
static int
ng_gre_recv(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p 		priv = hook->node_private;
	struct gre_header	*gredata = NULL;
	hook_p			default_dst_hook;
	hook_p			key_dst_hook = NULL;
	int			gre_hdr_size = sizeof(*gredata);
	int 			error = 0;
	uint32_t		*key;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	default_dst_hook = priv->nomatch;

	/* adjust size depending on options */
	if (!m_pullup(m, sizeof(struct gre_header))) {
#ifdef NG_GRE_STATS
		priv->stats[VNB_CORE_ID()].numMemErr++;
#endif
		/* mbuf is already freed */
		NG_FREE_META(meta);
		return EINVAL;
	}
	gredata = mtod(m, struct gre_header *);

	if (gredata->c) /* checksum */
		gre_hdr_size += sizeof(struct gre_checksum_header);
	if (gredata->k)
		gre_hdr_size += sizeof(uint32_t);

	if (!m_pullup(m, gre_hdr_size)) {
#ifdef NG_GRE_STATS
		priv->stats[VNB_CORE_ID()].numMemErr++;
#endif
		/* mbuf is already freed */
		NG_FREE_META(meta);
		return EINVAL;
	}

	/*
	 * If greHasCksum is set, drop messages that don't have
	 * checksum or have a bad checksum.  If not set, the packet
	 * must not include the cksum in the GRE header,
	 */
	if (likely(priv->conf.greHasCksum)) {

		/* no cksum, drop */
		if (unlikely(!gredata->c))
			goto drop;

		/* bad cksum, drop */
		if (unlikely(ng_gre_cksum(m) != 0))
			goto drop;
	} else if (unlikely(gredata->c)) {
		/* cksum is there but should not, drop */
		goto drop;
	}

	/* if packet has a key, look if a key_%d hook is connected */
	if (unlikely(gredata->k)) {
		struct key_hook_bucket	*bucket;
		uint32_t gre_key;

		/* get the pointer to the key (if it exist) */
		if (likely(gredata->c)) {
			struct gre_checksum_header *grechksm;
			grechksm = (struct gre_checksum_header *)(gredata + 1);
			key = (uint32_t *)(grechksm + 1);
		}
		else {
			key = (uint32_t *)(gredata+1);
		}

		gre_key = *key;
		bucket = GRE_BUCKET(gre_key);
		key_dst_hook = ng_get_gre_hook(bucket, gre_key);

		/* if there is no key_%d hook, look the configuration
		 * of the node */
		if (likely(key_dst_hook == NULL)) {

			/* If the packet has a key and both
			 * priv->conf.greHasKey and
			 * priv->conf.greRecvAnyKey are set to 0, drop
			 * it. */
			if (unlikely(!priv->conf.greHasKey && !priv->conf.greRecvAnyKey)) {
#ifdef NG_GRE_STATS
				priv->stats[VNB_CORE_ID()].numKeyErr++;
#endif
				NG_FREE_DATA(m, meta);
				return EINVAL;
			}

			/*
			 * If greRecvAnyKey is not set, the key must
			 * be the same as the one configured
			 */
			if (unlikely(!priv->conf.greRecvAnyKey && (priv->conf.greKey != *key)))  {
#ifdef NG_GRE_STATS
				priv->stats[VNB_CORE_ID()].numKeyErr++;
#endif
				NG_FREE_DATA(m, meta);
				return EINVAL;
			}

			/*
			 * If greKeyMtag is set, attach mtag/cmsg containing
			 * the key to the mbuf.
			 */
			if (unlikely(priv->conf.greKeyMtag))
				ng_gre_set_key_in_mtag(m, *key);
		}
	}
	else {
		/*
		 * If greHasKey is set, the received packet MUST have
		 * a key.
		 */
		if (priv->conf.greHasKey) {
#ifdef NG_GRE_STATS
			priv->stats[VNB_CORE_ID()].numKeyErr++;
#endif
			NG_FREE_DATA(m, meta);
			return EINVAL;
		}
	}

	/* If greProtoMtag is set, attach the ethertype as metadata (mtag/cb) */
	if ((priv->conf.greProtoMtag == NG_GRE_PROTO_MTAG_ALL_HOOKS) ||
	    (priv->conf.greProtoMtag == NG_GRE_PROTO_MTAG_KEYN_ONLY && key_dst_hook)) {
#if defined(__FastPath__) && defined(CONFIG_MCORE_M_TAG)
		if (likely(proto_tag_type >= 0))
			m_tag_add(m, proto_tag_type, htonl(ntohs(gredata->proto_type)));
#elif defined(__LinuxKernelVNB__)
		*(uint32_t *)m->cb = PROTO_CB_MAGIC;
		*(uint16_t *)(m->cb + 4) = gredata->proto_type;
#endif
	}

	/* Trim mbuf down to internal payload */
	m_adj(m, gre_hdr_size);

	/* Update stats */
#ifdef NG_GRE_STATS
	priv->stats[VNB_CORE_ID()].numPktsDec++;
#endif

	/* Deliver frame to upper layers */
	if (unlikely(key_dst_hook != NULL))
		NG_SEND_DATA(error, key_dst_hook, m, meta);
	else
		NG_SEND_DATA(error, default_dst_hook, m, meta);

	return error;
drop:
#ifdef NG_GRE_STATS
	priv->stats[VNB_CORE_ID()].numChksmErr++;
#endif
	NG_FREE_DATA(m, meta);
	return EINVAL;
}

/* Get the gre key from meta-data. Write it in network order in *key
 * if mtag is found, else do nothing */
static inline int ng_gre_get_key_from_mtag(struct mbuf *m, uint32_t *key)
{
#if defined(__LinuxKernelVNB__) && defined(CONFIG_NET_SKBUFF_SKTAG)
	if (!skb_get_sktag(m, SOL_SOCKET, IP_TAGINFO, NG_GRE_TAG_NAME, key))
		return 0;
#elif defined(__FastPath__) && defined(CONFIG_MCORE_M_TAG)
	if (m_tag_get(m, grekey_tag_type, key) == 0) {
		m_tag_del(m, grekey_tag_type);
		return 0;
	}
#endif
	return -1;
}

/*
 * Transmit data to the lower layer. Note that proto_type is given in
 * network order.
 */
static int
ng_gre_xmit(hook_p incoming_hook, struct mbuf *m, meta_p meta)
{
	const priv_p 		priv = incoming_hook->node_private;
	const hookpriv_p 	incoming_hpriv = NG_HOOK_PRIVATE(incoming_hook);
	int 			error = 0;
	struct gre_header 	*grehdr;
	struct gre_checksum_header *chksmhdr;
	int			gre_hdr_size = sizeof(*grehdr);
	uint32_t		*key;
	uint16_t		proto_type;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	proto_type = ng_gre_get_proto(priv->conf.greProtoMtag, m);

	/* packet will contain a cksum */
	if (priv->conf.greHasCksum)
		gre_hdr_size += sizeof(uint32_t);

	/* packet will contain a key */
	if (priv->conf.greHasKey || incoming_hook != priv->nomatch)
		gre_hdr_size += sizeof(uint32_t);

	/* Prepend GRE header to outgoing frame */
	M_PREPEND(m, gre_hdr_size, M_NOWAIT);
	if (!m) {
		NG_FREE_META(meta);
#ifdef NG_GRE_STATS
		priv->stats[VNB_CORE_ID()].numMemErr++;
#endif
		return ENOBUFS;
	}

	/* Build GRE header */
	grehdr = mtod(m, struct gre_header *);
	*(uint32_t *)(grehdr) = 0;

	grehdr->c = priv->conf.greHasCksum;
	grehdr->k = priv->conf.greHasKey || incoming_hook != priv->nomatch;
	grehdr->ver = NG_GRE_VERSION;
	grehdr->proto_type = proto_type;

	chksmhdr = (struct gre_checksum_header *)(grehdr + 1);
	if (priv->conf.greHasCksum)
		key = (uint32_t *)(chksmhdr + 1);
	else
		key = (uint32_t *)(grehdr + 1);

	/* If packet is coming from keyN hook, force the key in GRE
	 * header. Else, If greHasKey is set, the GRE header will
	 * contain a key.  The key is choosen with this algorithm: If
	 * greKeyMtag is set, look in mtag/cmsg for the key.  Else the
	 * one in config.
	 */
	if (incoming_hook != priv->nomatch) {
		if (incoming_hpriv == NULL) {
			NG_FREE_DATA(m, meta);
			return ENOTCONN;
		}
		*key = incoming_hpriv->key;
	}
	else if (priv->conf.greHasKey) {

		*key = 0; /* default key is 0 */

		/* check key in sktag: it may override *key, else use
		 * the one from node configuration. */
		if (!priv->conf.greKeyMtag || ng_gre_get_key_from_mtag(m, key))
			*key = priv->conf.greKey;
	}

	/* If greHasCksum is set, the checksum is contained in the GRE header */
	if (priv->conf.greHasCksum) {
		*(uint32_t *)chksmhdr = 0;
		chksmhdr->cksum = ng_gre_cksum(m);
	}

	/* Update stats */
#ifdef NG_GRE_STATS
	priv->stats[VNB_CORE_ID()].numPktsEnc++;
#endif

	/* Deliver packet */
	NG_SEND_DATA(error, priv->lower, m, meta);

	return error;
}

#ifdef __LinuxKernelVNB__
/*
 * Checksum word is formed based on data passed
 */
static int
ng_gre_raw_cksum(u_int16_t data_len, const u_int16_t *ck_data, u_int32_t *cksum)
{
	u_int16_t	i = 0;
	u_int8_t	fl_odd_data = data_len % 2;

	/*
	 * make 16 bit words out of every two adjacent 8 bit words in the packet
	 * and add them up
	 */
	for (i=0; i < (data_len - fl_odd_data); i=i+2)
	{
                *cksum += (u_int32_t)((*((u_int8_t *)ck_data + i) << 8) &
			   0xFF00) + (*((u_int8_t *)ck_data + i + 1) & 0xFF);
	}

	if(fl_odd_data)
		*cksum += ((*((u_int8_t *)ck_data + i) << 8) & 0xFF00) + 0x00;

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
#define OLD_KMAP_SKB 1
#endif

#ifdef OLD_KMAP_SKB
#include <netgraph/kmap_skb.h>
#else
#include <linux/highmem.h>
#endif

/*
 * GRE checksum calculation in slowpath
 */
static u_int16_t
ng_gre_cksum(const struct sk_buff *skb)
{
	u_int32_t cksum = 0;

	ng_gre_raw_cksum(skb_headlen(skb),
			 (const u_int16_t *)(skb->data),
			 &cksum);

	if (skb_shinfo(skb)->frag_list) {
		struct sk_buff *frag;

		for (frag = skb_shinfo(skb)->frag_list; frag; frag = frag->next)
			ng_gre_raw_cksum(frag->len, (const u_int16_t *)
				     (frag->data), &cksum);
	}
	if (skb_shinfo(skb)->nr_frags) {
		int i;
		u8 *vaddr;
		skb_frag_t *frag;

		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
			frag = &skb_shinfo(skb)->frags[i];
#ifdef OLD_KMAP_SKB
			vaddr = kmap_skb_frag(frag);
#else
			vaddr = kmap_atomic(skb_frag_page(frag));
#endif
			ng_gre_raw_cksum(frag->size, (const u_int16_t *)
				     (vaddr + frag->page_offset), &cksum);
#ifdef OLD_KMAP_SKB
			kunmap_skb_frag(vaddr);
#else
			kunmap_atomic(vaddr);
#endif
		}
	}

        /* take only 16 bits out of the 32 bit checksum and add up the carries */
        while (cksum >> 16)
                cksum = (cksum & 0xFFFF)+(cksum >> 16);

        /* one's complement the result */
        cksum = ~cksum;

	return htons((u_int16_t)cksum);
}
#else

#include "fpn-cksum.h"

/*
 * GRE checksum calculation in fastpath
 */
static u_int16_t
ng_gre_cksum(const struct mbuf *m)
{
	return fpn_cksum(m, 0);
}
#endif

#ifdef __LinuxKernelVNB__

static struct ng_nl_nodepriv *
ng_gre_dumpnode(node_p node)
{
	struct ng_nl_nodepriv *nlnodepriv;
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_gre_nl_nodepriv *gre_nlnodepriv;
	struct ng_gre_config *conf;

	MALLOC(nlnodepriv, struct ng_nl_nodepriv *,
	       sizeof(*nlnodepriv) + sizeof(*gre_nlnodepriv), M_NETGRAPH, M_NOWAIT | M_ZERO);

	if (!nlnodepriv)
		return NULL;

	gre_nlnodepriv = (struct ng_gre_nl_nodepriv *)nlnodepriv->data;

	conf = &gre_nlnodepriv->conf;

	ng_gre_config_copy(conf, &priv->conf, 0);

	return nlnodepriv;
}

#else

static void
ng_gre_restorenode(struct ng_nl_nodepriv *nlnodepriv, node_p node)
{
	struct ng_gre_nl_nodepriv *gre_nlnodepriv;
	priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_gre_config *conf;

	if (ntohl(nlnodepriv->data_len) != sizeof(*gre_nlnodepriv))
		return;

	gre_nlnodepriv = (struct ng_gre_nl_nodepriv *)nlnodepriv->data;

	conf = &gre_nlnodepriv->conf;

	ng_gre_config_copy(&priv->conf, conf, 1);
}

#endif

#if defined(__LinuxKernelVNB__)
module_init(ng_gre_init);
module_exit(ng_gre_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB GRE node");
MODULE_LICENSE("6WIND");
#endif
