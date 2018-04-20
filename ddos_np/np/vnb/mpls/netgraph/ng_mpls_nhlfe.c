/*
 * Copyright 2003-2013 6WIND S.A.
 */

/*
 * This node can do 3 operations : PUSH, SWAP, or POP a label then
 * transmit packet to a next node
 *
 * RFC used : 3443 and 1141
 */

#if defined(__LinuxKernelVNB__)

#include <linux/version.h>
#include <linux/in6.h>
#include <linux/in.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <linux/ctype.h>
#include <linux/timer.h>
#include <net/sock.h>
#include <asm/uaccess.h>
#include <netgraph/vnblinux.h>

#elif defined(__FastPath__)
#include "fp-netgraph.h"
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/vnb_in.h>
#include <netgraph/vnb_ip.h>
#include <netgraph/vnb_ip6.h>
#include <netgraph/vnb_udp.h>
#include <netgraph/ng_mpls_oam.h>
#include <netgraph/ng_mpls_nhlfe.h>
#include <netgraph/ng_mpls_common.h>

/* KT_NFMARK_WIDTH and KT_NFMARK_SHIFT can be defined here if needed */
#include <netgraph/nfmark.h>
#ifdef HAVE_KTABLES
#include <ktables_config.h>
#if defined(__LinuxKernelVNB__)
#include <ktables.h>
#endif

#endif

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_MPLS_NHLFE, "ng_mpls_nhlfe",
	      "netgraph MPLS");
#else
#define M_NETGRAPH_MPLS_NHLFE M_NETGRAPH
#endif

#ifdef __LinuxKernelVNB__
#define NG_MPLS_NHLFE_STATS
#endif

/* XXX stats should be per-core */
#ifdef NG_MPLS_NHLFE_STATS
#define STATS_ADD(priv, name, val) do {				\
		priv_p __priv = priv;				\
		struct ng_mpls_nhlfe_stats *stats;		\
		stats = &__priv->stats;				\
		stats->name += (val);				\
	} while(0)
#else
#define STATS_ADD(priv, name, val) do { } while(0)
#endif

#define STATS_INC(priv, name) STATS_ADD(priv, name, 1)

// #define NG_MPLS_NHLFE_DEBUG
#ifdef NG_MPLS_NHLFE_DEBUG
#ifdef __LinuxKernelVNB__
#define NG_MPLS_NHLFE_DPRINTF(x, y...) do { \
		log(LOG_DEBUG, "%s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#else
/* for now : force DEBUG output */
#define NG_MPLS_NHLFE_DPRINTF(x, y...) do { \
		FP_LOG(LOG_DEBUG, VNB, "FP %s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#endif
#else
#define NG_MPLS_NHLFE_DPRINTF(args...) do {} while(0)
#endif

/* Global array */
#if defined(__FastPath__)
FPN_DEFINE_PER_CORE(uint64_t, mpls_saved_stack[NG_MPLS_SAVED_WORDS]);
FPN_DEFINE_PER_CORE(char, mpls_input_iface[NG_NODESIZ]);
#endif

/* Per-node private data */
struct ng_mpls_private {
    node_p          node;			/* back pointer to node */
    struct ng_mpls_nhlfe_config conf;		/* node configuration	 */
    hook_p          nhlfe_in;			/* lower hook 		 */
    hook_p          nhlfe_in_push_bottom;	/* lower push hook for first label */
    hook_p          nhlfe_out;			/* upper hook	   	 */
    hook_p          nhlfe_bottom;		/* outgoing hook for the last label */
#if defined(HAVE_KTABLES)
    uint8_t const *kt_p;                        /* Pointer to kernel table */
#endif
    hook_p          oam_ip;			/* MPLS-OAM TTL hook */
#ifdef NG_MPLS_NHLFE_STATS
    struct ng_mpls_nhlfe_stats stats;		/* node stats 		 */
#endif
};

typedef struct ng_mpls_private *priv_p;

/* Pointer used to pass a mbuf reference */
typedef struct mbuf*  P_MBUF;
typedef struct mbuf** PP_MBUF;


/* Local functions */
static int ng_mpls_push(hook_p node, P_MBUF m, meta_p meta);
static int ng_mpls_swap(hook_p node, P_MBUF m, meta_p meta);
static int ng_mpls_pop(hook_p node, P_MBUF m, meta_p meta);
static int ng_mpls_extract_ip_ttl(const priv_p priv, PP_MBUF pm, int *ttl);
static int ng_mpls_extract_mpls_ttl(const priv_p priv, PP_MBUF pm, int *ttl);
static int ng_mpls_update_ip_ttl(const priv_p priv, PP_MBUF pm, int ttl);
static int ng_mpls_update_mpls_ttl(const priv_p priv, PP_MBUF pm, int ttl);

/* REM : pm is used in order to pass an argument as reference.
 * For instance ng_mpls_push() calls extract_ip_ttl(), *pm is
 * modified and might point to a modified mbuf.
 * ng_mpls_push() can continue its execution with *pm modified
 * and **pm point to the correct mbuf structure
 * ex :  pm -> m -> mbuf
 */


/* Netgraph node methods */
static ng_constructor_t ng_mpls_constructor;
static ng_rcvmsg_t ng_mpls_rcvmsg;
static ng_shutdown_t ng_mpls_rmnode;
static ng_newhook_t ng_mpls_newhook;
static ng_disconnect_t ng_mpls_disconnect;


/* Local processing */

/* Packets received from lower hook */
static int
ng_mpls_rcv_nhlfe(hook_p hook, struct mbuf * m, meta_p meta);


/* Local variables */

/* Parse type for struct ng_mpls_nhlfe_config */
static const struct ng_parse_struct_field
                ng_mpls_nhlfe_config_type_fields[] = NG_MPLS_NHLFE_CONFIG_TYPE_INFO;

static const struct ng_parse_type ng_mpls_nhlfe_config_type = {
		.supertype = &ng_parse_struct_type,
		.info = &ng_mpls_nhlfe_config_type_fields
};

#ifdef NG_MPLS_NHLFE_STATS
/* Parse type for struct ng_mpls_nhlfe_stats */
static const struct ng_parse_struct_field
                ng_mpls_nhlfe_stats_type_fields[] = NG_MPLS_NHLFE_STATS_TYPE_INFO;

static const struct ng_parse_type ng_mpls_nhlfe_stats_type = {
		.supertype = &ng_parse_struct_type,
		.info = &ng_mpls_nhlfe_stats_type_fields
};
#endif

static const struct ng_cmdlist ng_mpls_cmdlist[] = {
    {
	NGM_MPLS_NHLFE_COOKIE,
	NGM_MPLS_NHLFE_SET_CONFIG,
	"setconfig",
	.mesgType = &ng_mpls_nhlfe_config_type,
	.respType = NULL
    },
    {
	NGM_MPLS_NHLFE_COOKIE,
	NGM_MPLS_NHLFE_GET_CONFIG,
	"getconfig",
	.mesgType = NULL,
	.respType = &ng_mpls_nhlfe_config_type
    },

#ifdef NG_MPLS_NHLFE_STATS
    {
	NGM_MPLS_NHLFE_COOKIE,
	NGM_MPLS_NHLFE_GET_STATS,
	"getstats",
	.mesgType = NULL,
	.respType = &ng_mpls_nhlfe_stats_type
    },
    {

	NGM_MPLS_NHLFE_COOKIE,
	NGM_MPLS_NHLFE_CLR_STATS,
	"clrstats",
	.mesgType = NULL,
	.respType = NULL
    },
    {
	NGM_MPLS_NHLFE_COOKIE,
	NGM_MPLS_NHLFE_GETCLR_STATS,
	"getclrstats",
	.mesgType = NULL,
	.respType = &ng_mpls_nhlfe_stats_type
    },
#endif
#ifdef HAVE_KTABLES
	{
		NGM_MPLS_NHLFE_COOKIE,
		NGM_MPLS_NHLFE_NFMARK_GET_INGRESS_KTABLE,
		"nfmark_ktable_get",
		.mesgType = NULL,
		.respType = &ng_parse_uint32_type
	},
	{
		NGM_MPLS_NHLFE_COOKIE,
		NGM_MPLS_NHLFE_NFMARK_SET_INGRESS_KTABLE,
		"nfmark_ktable_set",
		.mesgType = &ng_parse_uint32_type,
		.respType = NULL
	},
#endif

    { 0, 0, NULL, NULL, NULL }
};

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_mpls_typestruct) = {
    .version = NG_VERSION,
    .name = NG_MPLS_NHLFE_NODE_TYPE,
    .mod_event = NULL,			/* Module event handler (optional) */
    .constructor = ng_mpls_constructor,	/* Node constructor */
    .rcvmsg = ng_mpls_rcvmsg,		/* control messages come here */
    .shutdown = ng_mpls_rmnode,		/* reset, and free resources */
    .newhook = ng_mpls_newhook,		/* first notification of new hook */
    .findhook = NULL,			/* only if you have lots of hooks */
    .connect = NULL,			/* final notification of new hook */
    .afterconnect = NULL,
    .rcvdata = NULL,			/* Only specific receive data functions */
    .rcvdataq = NULL,			/* Only specific receive data functions */
    .disconnect = ng_mpls_disconnect,	/* notify on disconnect */
    .rcvexception = NULL,		/* exceptions come here */
    .dumpnode = NULL,
    .restorenode = NULL,
    .dumphook = NULL,
    .restorehook = NULL,
    .cmdlist = ng_mpls_cmdlist,		/* commands we can convert */
};

#ifdef __FastPath__
int ng_mpls_nhlfe_init(void)
{
        int error;
        void *type = (&ng_mpls_typestruct);

        log(LOG_DEBUG, "VNB: Loading ng_mpls_ilm2nhlfe\n");

        if ((error = ng_newtype(type)) != 0) {
                log(LOG_ERR, "VNB: ng_mpls_nhlfe_init failed (%d)\n",error);
                return EINVAL;
        }

#if defined(CONFIG_MCORE_M_TAG)
        error = ng_pkt_mark_init(__FUNCTION__);
        return(error);
#endif
        return(0);
}
#else
NETGRAPH_INIT(mpls_nhlfe, &ng_mpls_typestruct);
NETGRAPH_EXIT(mpls_nhlfe, &ng_mpls_typestruct);
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
ng_mpls_constructor(node_p * nodep, ng_ID_t nodeid)
{
    priv_p	priv;
    int		error;

#ifdef SPLASSERT
    SPLASSERT(net, __FUNCTION__);
#endif

    /* Call superclass constructor that mallocs *nodep */
    if ((error = ng_make_node_common_and_priv(&ng_mpls_typestruct, nodep,
					      &priv, sizeof(*priv), nodeid))) {
	return (error);
    }

    bzero(priv, sizeof(*priv));

    /* Definition of default config */
    priv->conf.debugFlag = NG_MPLS_NHLFE_DEFAULT_CONF;
    priv->conf.operation = NG_MPLS_NHLFE_DEFAULT_CONF;
    priv->conf.label = NG_MPLS_NHLFE_DEFAULT_CONF;
    priv->conf.exp = NG_MPLS_NHLFE_DEFAULT_CONF;
    priv->conf.ttl = NG_MPLS_NHLFE_DEFAULT_CONF;

    NG_NODE_SET_PRIVATE(*nodep, priv);
    priv->node = *nodep;

    /* Done */
    return (0);
}

/*
 * Method for attaching a new hook
 * Two possible hooks : nhlfe_in and nhlfe_out
 * to receive and transmit data
 */

static int
ng_mpls_newhook(node_p node, hook_p hook, const char *name)
{
    const priv_p priv = NG_NODE_PRIVATE(node);

    /* Check for a nhlfe_in hook */
    if (strcmp(name, NG_MPLS_NHLFE_HOOK_NHLFE_IN) == 0) {
	/* Do not connect twice a nhlfe_in hook */
	if (priv->nhlfe_in != NULL)
	    return (EISCONN);

	priv->nhlfe_in = hook;
	hook->hook_rcvdata = ng_mpls_rcv_nhlfe;
	return 0;

    /* Check for a nhlfe_in_push hook */
    } else if (strcmp(name, NG_MPLS_NHLFE_HOOK_NHLFE_IN_PUSH) == 0) {
	/* Do not connect twice a nhlfe_in_push hook */
	if (priv->nhlfe_in != NULL)
	    return (EISCONN);

	hook->hook_rcvdata = ng_mpls_push;
	priv->nhlfe_in = hook;
	return 0;

    } else if (strcmp(name, NG_MPLS_NHLFE_HOOK_NHLFE_IN_PUSH_BOTTOM) == 0) {
	/* Do not connect twice a nhlfe_in_push hook */
	if (priv->nhlfe_in_push_bottom != NULL)
	    return (EISCONN);

	hook->hook_rcvdata = ng_mpls_push;
	priv->nhlfe_in_push_bottom = hook;
	return 0;

	/* Check for a nhlfe_in_pop hook */
    } else if (strcmp(name, NG_MPLS_NHLFE_HOOK_NHLFE_IN_POP) == 0) {
	/* Do not connect twice a nhlfe_in_pop hook */
	if (priv->nhlfe_in != NULL)
	    return (EISCONN);

	hook->hook_rcvdata = ng_mpls_pop;
	priv->nhlfe_in = hook;
	return 0;

	/* Check for a nhlfe_in_swap hook */
    } else if (strcmp(name, NG_MPLS_NHLFE_HOOK_NHLFE_IN_SWAP) == 0) {
	/* Do not connect twice a nhlfe_in_swap hook */
	if (priv->nhlfe_in != NULL)
	    return (EISCONN);

	hook->hook_rcvdata = ng_mpls_swap;
	priv->nhlfe_in = hook;
	return 0;

	/* Check for a nhlfe_out hook */
    } else if (strcmp(name, NG_MPLS_NHLFE_HOOK_NHLFE_OUT) == 0) {
	/* Do not connect twice a r hook */
	if (priv->nhlfe_out != NULL)
	    return (EISCONN);

	priv->nhlfe_out = hook;
	return 0;

	/* Check for a nhlfe_bottom hook */
    } else if (strcmp(name, NG_MPLS_NHLFE_HOOK_NHLFE_BOTTOM) == 0) {
	/* Do not connect twice a nhlfe_bottom hook */
	if (priv->nhlfe_bottom != NULL)
	    return (EISCONN);

	priv->nhlfe_bottom = hook;
	return 0;

	/* Check for a nhlfe_bottom hook */
    } else if (strcmp(name, NG_MPLS_NHLFE_HOOK_NHLFE_OAM_IP) == 0) {
	/* Do not connect twice a oam_ttl hook */
	if (priv->oam_ip != NULL)
	    return (EISCONN);

	hook->hook_rcvdata = NULL;
	priv->oam_ip = hook;
	return 0;
    }

    /* Unknown hook name */
    return (EINVAL);
}

/* Receive control message such as node configuration, statistics... */
static int
ng_mpls_rcvmsg(node_p node, struct ng_mesg * msg,
	       const char *retaddr, struct ng_mesg ** rptr, struct ng_mesg **nl_msg)
{
    const priv_p priv = NG_NODE_PRIVATE(node);
    struct ng_mesg *resp = NULL;
    int             error = 0;

    switch (msg->header.typecookie) {
	/* Case node id (COOKIE) is suitable */
    case NGM_MPLS_NHLFE_COOKIE:
	switch (msg->header.cmd) {
	case NGM_MPLS_NHLFE_GET_CONFIG:
	    {
		struct ng_mpls_nhlfe_config *conf;

		NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
		if (resp == NULL) {
		    error = ENOMEM;
		    break;
		}
		conf = (struct ng_mpls_nhlfe_config *) resp->data;
		*conf = priv->conf;	/* no sanity checking needed */
		break;
	    }
	case NGM_MPLS_NHLFE_SET_CONFIG:
	    {
		struct ng_mpls_nhlfe_config *const conf =
		(struct ng_mpls_nhlfe_config *) msg->data;

		if (msg->header.arglen != sizeof(*conf)) {
		    error = EINVAL;
		    break;
		}
		priv->conf = *conf;
		break;
	    }
#ifdef NG_MPLS_NHLFE_STATS
	case NGM_MPLS_NHLFE_GET_STATS:
	case NGM_MPLS_NHLFE_CLR_STATS:
	case NGM_MPLS_NHLFE_GETCLR_STATS:
	    {
		if (msg->header.cmd != NGM_MPLS_NHLFE_CLR_STATS) {
		    NG_MKRESPONSE(resp, msg,
				  sizeof(priv->stats), M_NOWAIT);
		    if (resp == NULL) {
			error = ENOMEM;
			break;
		    }
		    memcpy(resp->data,
			   &priv->stats, sizeof(priv->stats));
		}
		if (msg->header.cmd != NGM_MPLS_NHLFE_GET_STATS)
		    memset(&priv->stats, 0, sizeof(priv->stats));
		break;
	    }
#endif
#ifdef HAVE_KTABLES
		case NGM_MPLS_NHLFE_NFMARK_GET_INGRESS_KTABLE:
		    {
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

		case NGM_MPLS_NHLFE_NFMARK_SET_INGRESS_KTABLE:
		    {
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

/* Modify data from nhlfe_in hook and transmit it to nhlfe_out hook */

static int
ng_mpls_rcv_nhlfe(hook_p hook, P_MBUF m, meta_p meta)
{
    const priv_p priv = hook->node_private;
    struct ng_mpls_nhlfe_config conf;
    hook_p ohook;
    int   error = 0;

    if (unlikely(!priv)) {
        NG_FREE_DATA(m, meta);
        return (ENOTCONN);
    }
    conf = priv->conf;
    ohook = priv->nhlfe_out;

    /*Select action to do and decrement TTL according to RFC 3443 */
    switch (conf.operation) {
    case NG_MPLS_PUSH:
	{
		if ((error = ng_mpls_push(hook, m, meta)) != 0)
			return error;
	    break;
	}
    case NG_MPLS_SWAP:
	{
	    if ((error = ng_mpls_swap(hook, m, meta)) != 0)
		    return error;
	    break;
	}
    case NG_MPLS_POP:
	{
	    if ((error = ng_mpls_pop(hook, m, meta)) != 0)
		    return error;
	    break;
	}
    default:
	/* Default operation : transmit data only */

	    /* Update stats */
	    STATS_INC(priv, recvPackets);
	    STATS_ADD(priv, recvOctets, MBUF_LENGTH(m));
	    STATS_INC(priv, xmitPackets);
	    STATS_ADD(priv, xmitOctets, MBUF_LENGTH(m));

	    /* Send packet The mbuf and meta are consumed by the nodes of the peers. */
	    NG_SEND_DATA(error, ohook, m, meta);

	    /* When NG_SEND_DATA fails, the mbuf and meta do not need to be freed
	     * because it has already been done by the peer's node. */
	    break;
    }

    return error;
}

/* Add a label */

static int
ng_mpls_push(hook_p hook, P_MBUF m, meta_p meta)
{
    const priv_p priv = hook->node_private;
    struct ng_mpls_nhlfe_config conf;
    mpls_header_t *pmhdr, mhdr;
    int error = 0;
    int ttl = NG_MPLS_DEFAULT_TTL;
#ifdef __LinuxKernelVNB__
    mpls_oam_meta_t *lsp_meta;
#endif

    if (unlikely(!priv)) {
	    error = ENOTCONN;
	    goto drop;
    }

    /* Update stats */
    STATS_INC(priv, recvPackets);
    STATS_ADD(priv, recvOctets, MBUF_LENGTH(m));

    conf = priv->conf;
#ifdef __LinuxKernelVNB__
    /* Get the mpls_oam key from meta-data. */
    lsp_meta = (mpls_oam_meta_t *)ng_get_meta_option(meta, NGM_MPLS_OAM_COOKIE,
                                                     NGM_MPLS_OAM_LSP_INFO);
    if (lsp_meta)
        NG_MPLS_NHLFE_DPRINTF("got lsp meta data: exp: %u, ttl_bs: %u, ttl_nobs: %u, ra: %u\n",
                              lsp_meta->oam.exp, lsp_meta->oam.ttl_bs,
                              lsp_meta->oam.ttl_nobs, lsp_meta->oam.ra);
    else
        NG_MPLS_NHLFE_DPRINTF("No lsp meta data");

    /* if lsp meta is present, do not compute a new value for TTL */
    if (lsp_meta == NULL)
#endif
    /* TTL cases */
    switch (conf.uplayer) {
	case NG_NO_UPLAYER :
	{
		/* Unknow upper layer */
		if (conf.ttl != 0) {
			/* Force ttl to config value */
			ttl = conf.ttl;
		}
		break;
	}
	case NG_IP_UPLAYER :
	{
		/* IP upper layer, take IP ttl value as new ttl - 1 */
		if ( (error = ng_mpls_extract_ip_ttl(priv, &m, &ttl) ) != 0 )
			goto drop;
		break;
	}
	case NG_MPLS_UPLAYER :
	{
		/* MPLS upper layer, take MPLS ttl value as new ttl - 1 */
		if ( (error = ng_mpls_extract_mpls_ttl(priv, &m, &ttl)) != 0)
			goto drop;
		break;
	}
    }

    /* Prepend the MPLS header */
    M_PREPEND(m, sizeof(mpls_header_t), M_DONTWAIT);

    /* Prepend or m_pullup have failed */
    if (unlikely(m == NULL)) {
	STATS_INC(priv, memoryFailures);
	error = ENOBUFS;
	goto drop;
    }

    /* Fill new MPLS Header */
    mhdr.mhtag = conf.label;
#ifdef HAVE_KTABLES
    /* Set priority */
    if (priv->kt_p)
        mhdr.mhexp = priv->kt_p[ng_pkt_get_mark(m)] & 0x7;
    else
#endif
        mhdr.mhexp = conf.exp;

#ifdef __LinuxKernelVNB__
    if (lsp_meta && lsp_meta->oam.ra) {
        NG_MPLS_NHLFE_DPRINTF("router alert");
    }
#endif
    if (hook == priv->nhlfe_in_push_bottom) {
	    mhdr.mhbs = 1;
#ifdef __LinuxKernelVNB__
	    if (lsp_meta) {
		NG_MPLS_NHLFE_DPRINTF("tag_bs");
		ttl = lsp_meta->oam.ttl_bs;
		mhdr.mhexp = EXP_BS(lsp_meta->oam.exp);
	    }
#endif
    } else {
	    mhdr.mhbs = 0;
#ifdef __LinuxKernelVNB__
	    if (lsp_meta) {
		NG_MPLS_NHLFE_DPRINTF("tag_nobs");
		ttl = lsp_meta->oam.ttl_nobs;
		mhdr.mhexp = EXP_NOBS(lsp_meta->oam.exp);
	    }
#endif
    }
    mhdr.mhttl = ttl;

    /* Debugging information */
#ifdef NG_MPLS_NHLFE_DEBUG
    if (priv->conf.debugFlag) {
	NG_MPLS_NHLFE_DPRINTF("MPLS header after push = 0x%08x", mhdr.header);
    }
#endif

    /* Little to Big Endian conversion for the new mpls header */
    mhdr.header = htonl(mhdr.header);

    /* Write new header in packet */
    pmhdr = mtod(m, mpls_header_t *);
    *pmhdr = mhdr;

    /* Update stats */
    STATS_INC(priv, xmitPackets);
    STATS_ADD(priv, xmitOctets, MBUF_LENGTH(m));

    /* Send packet The mbuf and meta are consumed by the nodes of the peers. */
    NG_SEND_DATA(error, priv->nhlfe_out, m, meta);

    /* When NG_SEND_DATA fails, the mbuf and meta do not need to be freed
     * because it has already been done by the peer's node. */

    return error;

drop:
    NG_MPLS_NHLFE_DPRINTF("dropping");
    STATS_INC(priv, discarded);
    NG_FREE_DATA(m, meta);
    return error;
}


/* Swap a label to another */

static int
ng_mpls_swap(hook_p hook, P_MBUF m, meta_p meta)
{
    const priv_p priv = hook->node_private;
    struct ng_mpls_nhlfe_config conf;
    mpls_header_t *pmhdr, mhdr;
    int error = 0;

    if (unlikely(!priv)) {
	    error = ENOTCONN;
	    goto drop;
    }

    /* Update stats */
    STATS_INC(priv, recvPackets);
    STATS_ADD(priv, recvOctets, MBUF_LENGTH(m));

    conf = priv->conf;

    /* Check if mbuf is continuous*/
    m = m_pullup(m,sizeof(mpls_header_t));

    /* Check if m_pullup failed */
    if (unlikely(m == NULL)) {
	STATS_INC(priv, memoryFailures);
	error = ENOBUFS;
	goto drop;
    }
    /* Have a pointer on it */
    pmhdr = mtod(m, mpls_header_t *);
    mhdr = *pmhdr;

    /* Big to Little Endian conversion */
    mhdr.header = ntohl(mhdr.header);

    /* SWAP to new label value */
    mhdr.mhtag = conf.label;

    /* Decrement TTL after TTL check value */
    if(unlikely(mhdr.mhttl <= NG_MPLS_TTLDEC)) {
	    error = EINVAL;
	    goto drop;
    }
    mhdr.mhttl-- ;

#ifdef HAVE_KTABLES
    /* Set priority */
    if (priv->kt_p)
        mhdr.mhexp = priv->kt_p[ng_pkt_get_mark(m)] & 0x7;
#endif

    /* Debugging information */
#ifdef NG_MPLS_NHLFE_DEBUG
    if (priv->conf.debugFlag) {
	NG_MPLS_NHLFE_DPRINTF("MPLS header after swap = 0x%08x", mhdr.header);
    }
#endif
    /* Little to Big Endian conversion */
    mhdr.header = htonl(mhdr.header);
    *pmhdr = mhdr;

    /* Update stats */
    STATS_INC(priv, xmitPackets);
    STATS_ADD(priv, xmitOctets, MBUF_LENGTH(m));

    /* Send packet The mbuf and meta are consumed by the nodes of the peers. */
    NG_SEND_DATA(error, priv->nhlfe_out, m, meta);

    /* When NG_SEND_DATA fails, the mbuf and meta do not need to be freed
     * because it has already been done by the peer's node. */

    return error;

drop:
    NG_MPLS_NHLFE_DPRINTF("dropping");
    STATS_INC(priv, discarded);
    NG_FREE_DATA(m, meta);
    return error;
}


static inline int m_may_pull_iphdr(PP_MBUF pm)
{
	struct vnb_ip *iphdr;
	P_MBUF m = *pm;

#if defined(__LinuxKernelVNB__)
	if (unlikely(!pskb_may_pull(m, sizeof(struct vnb_ip6_hdr)))) {
		if (unlikely(pskb_may_pull(m, sizeof(struct vnb_ip)))) {
#elif defined(__FastPath__)
	if (unlikely(m_headlen(m) < sizeof(struct vnb_ip6_hdr))) {
		if (unlikely(m_headlen(m) >= sizeof(struct vnb_ip))) {
#endif
			iphdr = MPLS_MTODV4(m);
			if (MPLS_IS_IPV4(iphdr))
				return 1;
		}

		return 0;
	}

	return 1;
}

/* Delete a label */

static int
ng_mpls_pop(hook_p hook, P_MBUF m, meta_p meta)
{
    const priv_p priv = hook->node_private;
    struct ng_mpls_nhlfe_config conf;
    hook_p ohook;
    mpls_header_t  *mhdr;
    mpls_header_t  mhdr_new;
    int error = 0;
    int ttl = 0;
#if defined(CONFIG_VNB_MPLS_LSP_DIVERT)
    struct vnb_ip *iphdr;
#endif

    if (unlikely(!priv)) {
	    error = ENOTCONN;
	    goto drop;
    }

    /* Update stats */
    STATS_INC(priv, recvPackets);
    STATS_ADD(priv, recvOctets, MBUF_LENGTH(m));

    conf = priv->conf;

    /* Check if mbuf is continuous */
    m = m_pullup(m,sizeof(mpls_header_t));

    /* Check if m_pullup failed */
    if (unlikely(m == NULL)) {
	STATS_INC(priv, memoryFailures);
	error = ENOBUFS;
	goto drop;
    }

    /* Have a pointer on it */
    mhdr = mtod(m, mpls_header_t *);

    /* Big to Little Endian conversion */
    mhdr_new.header = ntohl(mhdr->header);

    /* Record ttl value before popping top label stack */
    ttl = mhdr_new.mhttl;

    ohook = priv->nhlfe_out;
    /* bottom of stack bit is set ? */
    if (mhdr_new.mhbs && priv->nhlfe_bottom)
	    ohook = priv->nhlfe_bottom;

    /* Delete top label stack : reverse endian conversion is unusefull */
    m_adj(m, NG_MPLS_HEADER_ENCAPLEN);

    /* Update ttl following upper layer */
   switch (conf.uplayer) {
	case NG_NO_UPLAYER :
	{
		/* Unknow upper layer */
		break;
	}
	case NG_IP_UPLAYER :
	{
#if defined(CONFIG_VNB_MPLS_LSP_DIVERT)
		/*
		 * Check if mbuf is continuous
		 */
		if (unlikely(!m_may_pull_iphdr(&m))) {
			STATS_INC(priv, memoryFailures);
			error = ENOBUFS;
			goto drop;
		}

		/* Handle mbuf */
		iphdr = MPLS_MTODV4(m);

		/* packets never returned from mplsoam node */
		if (likely(MPLS_IS_IPV4(iphdr) && MPLS_IS_UDP4(iphdr))) {

			NG_MPLS_NHLFE_DPRINTF("found UDPv4");

			m = m_pullup(m, MPLS_IP_HLEN(iphdr)*sizeof(uint32_t) +
				     sizeof(struct vnb_udphdr));
			if (unlikely(m == NULL)) {
				goto drop;
			}

			/* if packet is an OAM packet send to mpls_oam node */
			if (check_lspping_format(iphdr) &&
			    (priv->oam_ip != NULL)) {
				NG_SEND_DATA(error, priv->oam_ip, m, meta);
				return error;
			}
		}
#endif /*defined(CONFIG_VNB_MPLS_LSP_DIVERT)*/

		/* IP upper layer, take IP ttl value as new ttl */
		if ( (error = ng_mpls_update_ip_ttl(priv, &m, ttl)) != 0 )
			goto drop;
		break;
	}
	case NG_MPLS_UPLAYER :
	{
		/* MPLS upper layer, take MPLS ttl value as new ttl */
		if ( (error = ng_mpls_update_mpls_ttl(priv, &m, ttl)) != 0 )
			goto drop;
		break;
	}
    }

    /* Debugging information */
#ifdef NG_MPLS_NHLFE_DEBUG
    if (priv->conf.debugFlag) {
	NG_MPLS_NHLFE_DPRINTF("Next header after pop = 0x%08x", ntohl(mhdr->header));
    }
#endif

    /* Update stats */
    STATS_INC(priv, xmitPackets);
    STATS_ADD(priv, xmitOctets, MBUF_LENGTH(m));

    /* Send packet The mbuf and meta are consumed by the nodes of the peers. */
    NG_SEND_DATA(error, ohook, m, meta);

    /* When NG_SEND_DATA fails, the mbuf and meta do not need to be freed
     * because it has already been done by the peer's node. */

    return error;

drop:
    NG_MPLS_NHLFE_DPRINTF("dropping");
    STATS_INC(priv, discarded);
    NG_FREE_DATA(m, meta);
    return (error);
}

/* Extract TTL from IP layer */
static int
ng_mpls_extract_ip_ttl(priv_p priv, PP_MBUF pm, int *ttl) {
	struct vnb_ip *iphdr;
	struct vnb_ip6_hdr *ip6hdr;
	P_MBUF m = *pm;
	int error = 0;

	/*
	 * Check if mbuf is continuous
	 */
#if defined(__LinuxKernelVNB__) || defined(__FastPath__)
	if (unlikely(!m_may_pull_iphdr(&m))) {
#else
	m = m_pullup(m,sizeof(struct ip));

	/* Check if m_pullup failed */
	if (m == NULL) {
#endif
		STATS_INC(priv, memoryFailures);
		error = ENOBUFS;
		goto end;
	}

	/* Handle mbuf */
	iphdr = MPLS_MTODV4(m);
	ip6hdr = mtod(m, struct ip6_hdr *);

	if (MPLS_IS_IPV4(iphdr)) {
		if (MPLS_IP_TTL(iphdr) <= NG_MPLS_TTLDEC) {
			error = EINVAL;
			goto end;
		}
		*ttl = MPLS_IP_TTL(iphdr) - NG_MPLS_TTLDEC;
	} else if (MPLS_IS_IPV6(ip6hdr)) {
		if (MPLS_IP_HLIM(ip6hdr) < NG_MPLS_TTLDEC) {
			error = EINVAL;
			goto end;
		}
		*ttl = MPLS_IP_HLIM(ip6hdr) - NG_MPLS_TTLDEC;
	} else {
		/* Unknow header */
		error = EINVAL;
	}

	/* Debugging information */
#ifdef NG_MPLS_NHLFE_DEBUG
	if (priv->conf.debugFlag) {
		NG_MPLS_NHLFE_DPRINTF("TTL extracted from IP layer = %d", (int) *ttl);
	}
#endif
end:
	/* Make pm point to the modified mbuf pointer */
	*pm = m;
	return error;
}

/* Update TTL in IP layer */
static int
ng_mpls_update_ip_ttl(priv_p priv, PP_MBUF pm, int ttl) {
	struct vnb_ip *iphdr;
	struct vnb_ip6_hdr *ip6hdr;
	P_MBUF m = *pm;
	int error = 0;

	/*
	 * Check if mbuf is continuous
	 */
#if defined(__LinuxKernelVNB__) || defined(__FastPath__)
	if (unlikely(!m_may_pull_iphdr(&m))) {
#else
	m = m_pullup(m,sizeof(struct ip));

	/* Check if m_pullup failed */
	if (unlikely(m == NULL)) {
#endif
		STATS_INC(priv, memoryFailures);
		error = ENOBUFS;
		goto end;
	}

	/* Handle mbuf */
	iphdr = MPLS_MTODV4(m);
	ip6hdr = mtod(m, struct ip6_hdr *);

	if (MPLS_IS_IPV4(iphdr)) {
		uint32_t sum;
		uint16_t old_ttl;
		void *ip_ttl_ptr;

		/* Check new ttl > 0 */
		ip_ttl_ptr = &(MPLS_IP_TTL(iphdr));
		old_ttl = ntohs(*(uint16_t *)ip_ttl_ptr);
		if (ttl < NG_MPLS_TTLDEC) {
			error = EINVAL;
			goto end;
		}
		MPLS_IP_TTL(iphdr) = (u_char )ttl;

		/* Incrementally change the checksum : algo RFC 1141 */
		sum = old_ttl + (~ntohs(*(uint16_t *)ip_ttl_ptr) & 0xffff);
		sum += ntohs(MPLS_IP_CSUM(iphdr));
	        sum = (sum & 0xffff) + (sum>>16);
		MPLS_IP_CSUM(iphdr) = htons(sum + (sum>>16));
	} else if (MPLS_IS_IPV6(ip6hdr)) {
		/* Check new ttl > 0 */
		if (ttl < NG_MPLS_TTLDEC) {
			error = EINVAL;
			goto end;
		}

		MPLS_IP_HLIM(ip6hdr) = (uint8_t)ttl;
	} else {
		/* Unknown header */
		error = EINVAL;
		goto end;
	}

	/* Debugging information */
#ifdef NG_MPLS_NHLFE_DEBUG
	if (priv->conf.debugFlag) {
		NG_MPLS_NHLFE_DPRINTF("TTL update = %d", ttl);
	}
#endif
end:
	/* Make pm point to the modified mbuf pointer */
	*pm = m;
	return error;
}

/* MPLS upper layer, take MPLS ttl value as new ttl */

static int
ng_mpls_extract_mpls_ttl(priv_p priv, PP_MBUF pm, int *ttl) {
	const mpls_header_t *mhdr;
	mpls_header_t  smhdr;
	P_MBUF m = *pm;
	int error = 0;

	/* Check if mbuf is continuous*/
	m = m_pullup(m,sizeof(mpls_header_t));

	/* Check if m_pullup failed */
	if (unlikely(m == NULL)) {
		STATS_INC(priv, memoryFailures);
		error = ENOBUFS;
		goto end;
	}

	/* Have a pointer on mpls header */
	mhdr = mtod(m, mpls_header_t *);

	/* Copy mpls header to avoid to modify it
	 * and deals with endian conversion
	 */
	smhdr.header = ntohl(mhdr->header);

	/* Check if ttl value is valuable */
	if (unlikely(smhdr.mhttl <= NG_MPLS_TTLDEC)) {
		error = EINVAL;
		goto end;
	}
	*ttl =  smhdr.mhttl - NG_MPLS_TTLDEC;

	/* Debugging information */
#ifdef NG_MPLS_NHLFE_DEBUG
	if (priv->conf.debugFlag) {
		NG_MPLS_NHLFE_DPRINTF("TTL update = %d", (int) *ttl);
	}
#endif
end:
	/* Make pm point to the modified mbuf pointer */
	*pm = m;
	return error;
}

/* Update MPLS TTL */
static int
ng_mpls_update_mpls_ttl(priv_p priv, PP_MBUF pm, int ttl) {
	mpls_header_t *pmhdr, mhdr;
	P_MBUF m = *pm;
	int error = 0;

	/* Check if mbuf is continuous*/
	m = m_pullup(m,sizeof(mpls_header_t));

	/* Check if m_pullup failed */
	if (m == NULL) {
		STATS_INC(priv, memoryFailures);
		error = ENOBUFS;
		goto end;
	}

	/* Get the mpls header */
	pmhdr = mtod(m, mpls_header_t *);
	mhdr = *pmhdr;

	/* Big to Little conversion */
	mhdr.header = ntohl(mhdr.header);

	if (unlikely(ttl < NG_MPLS_TTLDEC)) {
		error = EINVAL;
		goto end;
	}

	mhdr.mhttl = ttl;

	/* Little to Big conversion */
	mhdr.header = ntohl(mhdr.header);

	/* Update packet */
	*pmhdr = mhdr;

	/* Debugging information */
#ifdef NG_MPLS_NHLFE_DEBUG
	if (priv->conf.debugFlag) {
		NG_MPLS_NHLFE_DPRINTF("TTL update = %d", ttl);
	}
#endif
end:
	/* Make pm point to the modified mbuf pointer */
	*pm = m;
	return error;
}




static int
ng_mpls_disconnect(hook_p hook)
{
    const node_p node = NG_HOOK_NODE(hook);
    const priv_p priv = NG_NODE_PRIVATE(node);

    hook->hook_rcvdata = NULL;
    /* Zero out hook pointer */
    if (hook == priv->nhlfe_in)
	priv->nhlfe_in = NULL;
    else if (hook == priv->nhlfe_in_push_bottom)
	priv->nhlfe_in_push_bottom = NULL;
    else if (hook == priv->nhlfe_out)
	priv->nhlfe_out = NULL;
    else if (hook == priv->nhlfe_bottom)
	priv->nhlfe_bottom = NULL;
    else if (hook == priv->oam_ip)
	priv->oam_ip = NULL;
    /* Go away if no longer connected to anything */
    if (node->numhooks == 0)
	ng_rmnode(node);

    return (0);
}

static int
ng_mpls_rmnode(node_p node)
{
#ifdef SPLASSERT
    SPLASSERT(net, __FUNCTION__);
#endif

    node->flags |= NG_INVALID;	/* inclusif or */
    ng_cutlinks(node);
    ng_unname(node);

    NG_NODE_SET_PRIVATE(node, NULL);

    /* Unref node */
    NG_NODE_UNREF(node);

    return (0);

}
