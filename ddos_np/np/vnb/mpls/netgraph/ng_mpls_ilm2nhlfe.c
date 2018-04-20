/*
 * Copyright 2003-2013 6WIND S.A.
 */

/*
 * This node receive mpls packets and forward them to the corresponding hook
 * according to label value
 *
 */

/* In the following code "tag" and "label" are both references to mpls labels */

#if defined(__LinuxKernelVNB__)

#include <linux/version.h>
#include <linux/in6.h>

#include <linux/errno.h>
#include <linux/types.h>
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
#include <netgraph/ng_mpls_ilm2nhlfe.h>
/* KT_NFMARK_WIDTH and KT_NFMARK_SHIFT can be defined here if needed */
#include <netgraph/nfmark.h>
#ifdef HAVE_KTABLES
#include <ktables_config.h>
#if defined(__LinuxKernelVNB__)
#include <ktables.h>
#endif
#endif
#include <netgraph/vnb_in.h>
#include <netgraph/vnb_ip.h>
#include <netgraph/vnb_udp.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_mpls_common.h>

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_MPLS_I2N, "ng_mpls_ilm2nhlfe",
	      "netgraph MPLS");
#else
#define M_NETGRAPH_MPLS_I2N M_NETGRAPH
#endif

#if NG_MPLS_I2N_MAX_TAG > 1048576
#error The highest tag value is 1048576 (20 bits)
#endif

#ifdef __LinuxKernelVNB__
#define NG_MPLS_ILM2NHLFE_STATS
#endif

/* XXX stats should be per-core */
#ifdef NG_MPLS_ILM2NHLFE_STATS
#define STATS_ADD(priv, name, val) do {				\
		priv_p __priv = priv;				\
		struct ng_mpls_stats *stats;			\
		stats = &__priv->stats;				\
		stats->name += (val);				\
	} while(0)
#else
#define STATS_ADD(priv, name, val) do { } while(0)
#endif

#define STATS_INC(priv, name) STATS_ADD(priv, name, 1)

// #define NG_MPLS_ILM2NHLFE_DEBUG
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
#ifdef __LinuxKernelVNB__
#define NG_MPLS_I2N_DPRINTF(x, y...) do { \
		log(LOG_DEBUG, "%s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#else
/* for now : force DEBUG output */
#define NG_MPLS_I2N_DPRINTF(x, y...) do { \
		FP_LOG(LOG_DEBUG, VNB, "FP %s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#endif
#else
#define NG_MPLS_I2N_DPRINTF(args...) do {} while(0)
#endif

/* Local definitions */

/*
 * Define used for direct access table
 * Label must be between 0 and (NG_MPLS_ILM2NHLFE_DIRECT_NHLFE - 1)
 * to be in the direct access table.
 */
#define NG_MPLS_ILM2NHLFE_DIRECT_NHLFE 1024

#if defined(CONFIG_VNB_MPLS_ILM2NHLFE_MAX_ETHER)
#define NG_MPLS_ILM2NHLFE_MAX_ETHER CONFIG_VNB_MPLS_ILM2NHLFE_MAX_ETHER
#else
#define NG_MPLS_ILM2NHLFE_MAX_ETHER 64
#endif
#if defined(CONFIG_VNB_MPLS_ILM2NHLFE_MAX_RAW)
#define NG_MPLS_ILM2NHLFE_MAX_RAW CONFIG_VNB_MPLS_ILM2NHLFE_MAX_RAW
#else
#define NG_MPLS_ILM2NHLFE_MAX_RAW 64
#endif

/* Per-node private data */

struct ng_mpls_private {
    node_p          node;				/* back pointer to node */
    struct ng_mpls_config conf;				/* node configuration	 */
    hook_p  lower_ether[NG_MPLS_ILM2NHLFE_MAX_ETHER];	/* lower hook 		 */
    hook_p  nomatch[NG_MPLS_ILM2NHLFE_MAX_ETHER];	/* nomatch hook (1 by lower_ether hook) */
    hook_p  lower_raw[NG_MPLS_ILM2NHLFE_MAX_RAW];	/* raw hook		 */
    hook_p  orphans;					/* orphans hook 	 */
    hook_p  oam_ra;					/* MPLS-OAM RA hook 	 */
    hook_p  oam_ttl;					/* MPLS-OAM TTL hook 	 */
    hook_p  *nhlfe[NG_THASH_SIZE];			/* hash entries	   	 */
    hook_p  direct_nhlfe[NG_MPLS_ILM2NHLFE_DIRECT_NHLFE]; /* direct access entries */
#ifdef NG_MPLS_ILM2NHLFE_STATS
    struct ng_mpls_stats stats;				/* node stats 		 */
#endif
};

typedef struct ng_mpls_private *priv_p;

/* Per-link private data */
struct ng_mpls_link_hook_private {
    hook_p          hook;	/* back point to hook */
#if defined(HAVE_KTABLES)
    uint8_t const *kt_p;        /* Pointer to kernel table */
#endif
    uint32_t        tag:20;	/* MPLS tag */
    /* TODO: Add per-link and orphans stats support here */
};

typedef struct ng_mpls_link_hook_private *hookpriv_p;


/* Local functions */

/* Netgraph node methods */


static ng_constructor_t ng_mpls_constructor;
static ng_rcvmsg_t ng_mpls_rcvmsg;
static ng_shutdown_t ng_mpls_rmnode;
static ng_newhook_t ng_mpls_newhook;
static ng_findhook_t ng_mpls_findhook;
static ng_disconnect_t ng_mpls_disconnect;


/* Local processing */

/* Packets received from lower hook */
static int
ng_mpls_rcv_ether(hook_p hook, struct mbuf * m, meta_p meta);
static int
ng_mpls_rcv_raw(hook_p hook, struct mbuf * m, meta_p meta);
static int
ng_mpls_rcv_nomatch(hook_p hook, struct mbuf * m, meta_p meta);
static int
ng_mpls_rcv_nhlfe(priv_p priv, mpls_header_t  mhdr, struct mbuf *m, meta_p meta);
static int
ng_mpls_rcv_direct_nhlfe(priv_p priv, mpls_header_t  mhdr, struct mbuf *m, meta_p meta);


/* Local variables */

/* Parse type for struct ng_mpls_config */
static const struct ng_parse_struct_field
	ng_mpls_config_type_fields[] = NG_MPLS_I2N_CONFIG_TYPE_INFO;

static const struct ng_parse_type ng_mpls_config_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_mpls_config_type_fields
};

#ifdef NG_MPLS_ILM2NHLFE_STATS
/* Parse type for struct ng_mpls_stats */
static const struct ng_parse_struct_field
        ng_mpls_stats_type_fields[] = NG_MPLS_I2N_STATS_TYPE_INFO;
static const struct ng_parse_type ng_mpls_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_mpls_stats_type_fields
};
#endif

#ifdef HAVE_KTABLES
/* Parse type for struct ng_mpls_ktable_msg */
static const struct ng_parse_struct_field
        ng_mpls_ktables_type_fields[] = NG_MPLS_I2N_KTABLES_TYPE_INFO;
static const struct ng_parse_type ng_mpls_ktables_type = {
        .supertype = &ng_parse_struct_type,
        .info = &ng_mpls_ktables_type_fields
};
#endif

static const struct ng_cmdlist ng_mpls_cmdlist[] = {
    {
	NGM_MPLS_I2N_COOKIE,
	NGM_MPLS_I2N_SET_CONFIG,
	"setconfig",
	.mesgType = &ng_mpls_config_type,
	.respType = NULL
    },
    {
	NGM_MPLS_I2N_COOKIE,
	NGM_MPLS_I2N_GET_CONFIG,
	"getconfig",
	.mesgType = NULL,
	.respType = &ng_mpls_config_type
    },

#ifdef NG_MPLS_ILM2NHLFE_STATS
    {
	NGM_MPLS_I2N_COOKIE,
	NGM_MPLS_I2N_GET_STATS,
	"getstats",
	.mesgType = NULL,
	.respType = &ng_mpls_stats_type
    },
    {

	NGM_MPLS_I2N_COOKIE,
	NGM_MPLS_I2N_CLR_STATS,
	"clrstats",
	.mesgType = NULL,
	.respType = NULL
    },
    {
	NGM_MPLS_I2N_COOKIE,
	NGM_MPLS_I2N_GETCLR_STATS,
	"getclrstats",
	.mesgType = NULL,
	.respType = &ng_mpls_stats_type
    },
#endif
#ifdef HAVE_KTABLES
	{
		NGM_MPLS_I2N_COOKIE,
		NGM_MPLS_I2N_NFMARK_GET_INGRESS_KTABLE,
		"nfmark_ktable_get",
		.mesgType = &ng_parse_uint32_type,
		.respType = &ng_parse_uint32_type
	},
	{
		NGM_MPLS_I2N_COOKIE,
		NGM_MPLS_I2N_NFMARK_SET_INGRESS_KTABLE,
		"nfmark_ktable_set",
		.mesgType = &ng_mpls_ktables_type,
		.respType = NULL
	},
#endif

    { 0, 0, NULL, NULL, NULL }
};

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_mpls_typestruct) = {
    .version = NG_VERSION,
    .name = NG_MPLS_I2N_NODE_TYPE,
    .mod_event = NULL,			/* Module event handler (optional) */
    .constructor = ng_mpls_constructor,	/* Node constructor */
    .rcvmsg = ng_mpls_rcvmsg,		/* control messages come here */
    .shutdown = ng_mpls_rmnode,		/* reset, and free resources */
    .newhook = ng_mpls_newhook,		/* first notification of new hook */
    .findhook = ng_mpls_findhook,	/* specific findhook function */
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
int ng_mpls_ilm2nhlfe_init(void)
{
        int error;
        void *type = (&ng_mpls_typestruct);

        log(LOG_DEBUG, "VNB: Loading ng_mpls_ilm2nhlfe\n");

        if ((error = ng_newtype(type)) != 0) {
                log(LOG_ERR, "VNB: ng_mpls_ilm2nhlfe_init failed (%d)\n",error);
                return EINVAL;
        }

#if defined(CONFIG_MCORE_M_TAG)
        error = ng_pkt_mark_init(__FUNCTION__);
        return(error);
#endif
        return(0);
}
#else
NETGRAPH_INIT(mpls_ilm2nhlfe, &ng_mpls_typestruct);
NETGRAPH_EXIT(mpls_ilm2nhlfe, &ng_mpls_typestruct);
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
    priv_p priv;
    int    error;

#ifdef SPLASSERT
    SPLASSERT(net, __FUNCTION__);
#endif

    /* Call superclass constructor that mallocs *nodep */
    if ((error = ng_make_node_common_and_priv(&ng_mpls_typestruct, nodep,
					      &priv, sizeof(*priv), nodeid))) {
	return (error);
    }

    bzero(priv, sizeof(*priv));
    priv->conf.debugFlag = NG_MPLS_I2N_DEBUG_NONE;

    NG_NODE_SET_PRIVATE(*nodep, priv);
    priv->node = *nodep;

    /* Done */
    return (0);
}

/* Method for attaching a new hook There are three kinds of hook: - the nhlfe
 * with an index. The index is the MPLS tag. - the orphans link. - the
 * lower_ether link.
 */
static int
ng_mpls_newhook(node_p node, hook_p hook, const char *name)
{
    const priv_p priv = NG_NODE_PRIVATE(node);

    /* Check for a nhlfe hook */
    if (strncmp(name, NG_MPLS_I2N_HOOK_LINK_PREFIX,
		sizeof(NG_MPLS_I2N_HOOK_LINK_PREFIX) - 1) == 0) {

	const char     *tag_str;
	char           *err_ptr;
	unsigned long   tag;
	hookpriv_p      hpriv;


	/* Get the link index Parse link_0xa, link_10, ... */
	tag_str = name + sizeof(NG_MPLS_I2N_HOOK_LINK_PREFIX) - 1;

	/* Allow decimal and hexadecimal values. The hexadecimal values must
	 * be prefixed by 0x */
	tag = strtoul(tag_str, &err_ptr, 0);

	if ((*err_ptr) != '\0')
	    return (EINVAL);

	/*
	 * If tag is not in the correct intervall then display error Value 0
	 * we have to link reserved values with NHLFE (EXPLICIT_NULL,
	 * IMPLICIT_NULL) to perform POP on packets so we have to
	 * accept tags < 15
	 */
	if (tag >= NG_MPLS_I2N_MAX_TAG)
	    return (EINVAL);

	/* Do not create twice a link hook
	 *
	 * Check if a previous nhlfe exists by matching 10 left bits and 10
	 * right bits of mpls tag
         */

	if (unlikely(tag >= NG_MPLS_ILM2NHLFE_DIRECT_NHLFE)) {
		if (NHLFE_ENTRY(tag) != NULL) {
			/* Array exist and memory is reserved */
			if (NHLFE_HOOK(tag) != NULL) {
				return EISCONN;
			}
		} else {
			/* Array doesn't exist, memory reservation is needed
			 * Clean NHLFE_ENTRY
			 */
#if !defined(M_ZERO)

			NHLFE_ENTRY(tag) = ng_malloc(NG_THASH_SIZE * sizeof(hook_p), M_NOWAIT);
#else
			NHLFE_ENTRY(tag) = ng_malloc(NG_THASH_SIZE * sizeof(hook_p), M_NOWAIT | M_ZERO);
#endif
			if (NHLFE_ENTRY(tag) == NULL)
				return (ENOMEM);
#if !defined(M_ZERO)
			bzero(NHLFE_ENTRY(tag), sizeof(hook_p));
#endif
		}
	} else if (priv->direct_nhlfe[tag] != NULL)
		return EISCONN;

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
	if (unlikely(tag >= NG_MPLS_ILM2NHLFE_DIRECT_NHLFE))
		NHLFE_HOOK(tag) = hook;
	else
		priv->direct_nhlfe[tag] = hook;

	return 0;

	/* Check for an MPLS-OAM RA hook */
    } else if (strcmp(name, NG_MPLS_I2N_HOOK_OAM_RA) == 0) {

	/* Do not connect twice an oam RA hook */
	if (priv->oam_ra != NULL)
		return (EISCONN);

	priv->oam_ra = hook;

	/*
	 * return to recv raw also for ether packets :
	 * the Ether hdr has been stripped
	 */
	hook->hook_rcvdata = ng_mpls_rcv_raw;

	return 0;

	/* Check for an MPLS-OAM TTL hook */
    } else if (strcmp(name, NG_MPLS_I2N_HOOK_OAM_TTL) == 0) {

	/* Do not connect twice an oam TTL hook */
	if (priv->oam_ttl != NULL)
		return (EISCONN);

	priv->oam_ttl = hook;

	/*
	 * return to recv raw also for MPLS TTL==1 packets :
	 * the LSP ping format was not found
	 */
	hook->hook_rcvdata = ng_mpls_rcv_raw;

	return 0;

	/* Check for an orphans hook */
    } else if (strcmp(name, NG_MPLS_I2N_HOOK_ORPHANS) == 0) {

	/* Do not connect twice an orphans hook */
	if (priv->orphans != NULL)
	    return (EISCONN);

	priv->orphans = hook;

	return 0;

	/* Check for an orphan hook */
    } else if (strncmp(name, NG_MPLS_I2N_HOOK_NOMATCH_PREFIX,
		       sizeof (NG_MPLS_I2N_HOOK_NOMATCH_PREFIX) - 1) == 0) {
	const char     *tag_str;
	char           *err_ptr;
	unsigned long   tag;
	hookpriv_p      hpriv;

	/* Get the link index Parse link_0xa, link_10, ... */
	tag_str = name + sizeof(NG_MPLS_I2N_HOOK_NOMATCH_PREFIX) - 1;

	/* Allow decimal and hexadecimal values. The hexadecimal values must
	 * be prefixed by 0x */
	tag = strtoul(tag_str, &err_ptr, 0);

	if ((*err_ptr) != '\0')
		return (EINVAL);

	if (tag >= NG_MPLS_ILM2NHLFE_MAX_ETHER)
		return (EINVAL);

	/* Do not connect twice a nomatch hook */
	if (priv->nomatch[tag] != NULL)
	    return (EISCONN);

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

	priv->nomatch[tag] = hook;
	hook->hook_rcvdata = ng_mpls_rcv_nomatch;

	return 0;

	/*
	 * Check for a lower_ether hook
	 */
    } else if (strncmp(name, NG_MPLS_I2N_HOOK_LOWER_ETHER_PREFIX,
		       sizeof (NG_MPLS_I2N_HOOK_LOWER_ETHER_PREFIX) - 1) == 0) {
	const char     *tag_str;
	char           *err_ptr;
	unsigned long   tag;
	hookpriv_p      hpriv;

	/* Get the link index Parse link_0xa, link_10, ... */
	tag_str = name + sizeof(NG_MPLS_I2N_HOOK_LOWER_ETHER_PREFIX) - 1;

	/* Allow decimal and hexadecimal values. The hexadecimal values must
	 * be prefixed by 0x */
	tag = strtoul(tag_str, &err_ptr, 0);

	if ((*err_ptr) != '\0')
		return (EINVAL);

	if (tag >= NG_MPLS_ILM2NHLFE_MAX_ETHER)
		return (EISCONN);

	/* Do not connect twice a lower hook */
	if (priv->lower_ether[tag] != NULL)
	    return (EISCONN);

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

	hook->hook_rcvdata = ng_mpls_rcv_ether;
	priv->lower_ether[tag] = hook;
	return 0;

	/* Check for a lower_raw hook */
    } else if (strncmp(name, NG_MPLS_I2N_HOOK_LOWER_RAW_PREFIX,
		       sizeof (NG_MPLS_I2N_HOOK_LOWER_RAW_PREFIX) - 1) == 0) {
	const char     *tag_str;
	char           *err_ptr;
	unsigned long   tag;
	hookpriv_p      hpriv;

	/* Get the link index Parse link_0xa, link_10, ... */
	tag_str = name + sizeof(NG_MPLS_I2N_HOOK_LOWER_RAW_PREFIX) - 1;

	/* Allow decimal and hexadecimal values. The hexadecimal values must
	 * be prefixed by 0x */
	tag = strtoul(tag_str, &err_ptr, 0);

	if ((*err_ptr) != '\0')
		return (EINVAL);

	if (tag >= NG_MPLS_ILM2NHLFE_MAX_RAW)
		return (EISCONN);

	/* Do not connect twice a lower hook */
	if (priv->lower_raw[tag] != NULL)
	    return (EISCONN);

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

	hook->hook_rcvdata = ng_mpls_rcv_raw;

	priv->lower_raw[tag] = hook;
	return 0;
    }

    /* Unknown hook name */
    return (EINVAL);
}

static hook_p
ng_mpls_findhook(node_p node, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	hook_p hook = NULL;

	if (strncmp(name, NG_MPLS_I2N_HOOK_LINK_PREFIX,
		    sizeof(NG_MPLS_I2N_HOOK_LINK_PREFIX) - 1) == 0) {
		const char     *tag_str;
		char           *err_ptr;
		unsigned long   tag;

		/* Get the link index Parse link_0xa, link_10, ... */
		tag_str = name + sizeof(NG_MPLS_I2N_HOOK_LINK_PREFIX) - 1;

		/*
		 * Only decimal and hexadecimal values are allowed.
		 * The hexadecimal values must be prefixed by 0x
		 */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0')
			return NULL;

		/*
		 * check that tag is not out of bound
		 */
		if (tag >= NG_MPLS_I2N_MAX_TAG)
			return NULL;


		if (unlikely(tag >= NG_MPLS_ILM2NHLFE_DIRECT_NHLFE)) {
			if (NHLFE_ENTRY(tag) != NULL)
				hook = NHLFE_HOOK(tag);
		} else
			hook = priv->direct_nhlfe[tag];


		/* Check for an MPLS-OAM RA hook */
	} else if (strcmp(name, NG_MPLS_I2N_HOOK_OAM_RA) == 0) {

		hook = priv->oam_ra;

		/* Check for an MPLS-OAM TTL hook */
	} else if (strcmp(name, NG_MPLS_I2N_HOOK_OAM_TTL) == 0) {

		hook = priv->oam_ttl;

		/* Check for an orphans hook */
	} else if (strcmp(name, NG_MPLS_I2N_HOOK_ORPHANS) == 0) {

		hook = priv->orphans;

		/* Check for an orphan hook */
	} else if (strncmp(name, NG_MPLS_I2N_HOOK_NOMATCH_PREFIX,
			   sizeof (NG_MPLS_I2N_HOOK_NOMATCH_PREFIX) - 1) == 0) {
		const char     *tag_str;
		char           *err_ptr;
		unsigned long   tag;

		/* Get the link index Parse link_0xa, link_10, ... */
		tag_str = name + sizeof(NG_MPLS_I2N_HOOK_NOMATCH_PREFIX) - 1;

		/*
		 * Only decimal and hexadecimal values are allowed.
		 * The hexadecimal values must be prefixed by 0x
		 */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0')
			return NULL;

		if (tag >= NG_MPLS_ILM2NHLFE_MAX_ETHER)
			return NULL;

		hook = priv->nomatch[tag];

		/*
		 * Check for a lower_ether hook
		 */
	} else if (strncmp(name, NG_MPLS_I2N_HOOK_LOWER_ETHER_PREFIX,
			   sizeof (NG_MPLS_I2N_HOOK_LOWER_ETHER_PREFIX) - 1) == 0) {
		const char     *tag_str;
		char           *err_ptr;
		unsigned long   tag;

		/* Get the link index Parse link_0xa, link_10, ... */
		tag_str = name + sizeof(NG_MPLS_I2N_HOOK_LOWER_ETHER_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0')
			return NULL;

		if (tag >= NG_MPLS_ILM2NHLFE_MAX_ETHER)
			return NULL;

		hook = priv->lower_ether[tag];

		/* Check for a lower_raw hook */
	} else if (strncmp(name, NG_MPLS_I2N_HOOK_LOWER_RAW_PREFIX,
			   sizeof (NG_MPLS_I2N_HOOK_LOWER_RAW_PREFIX) - 1) == 0) {
		const char     *tag_str;
		char           *err_ptr;
		unsigned long   tag;

		/* Get the link index Parse link_0xa, link_10, ... */
		tag_str = name + sizeof(NG_MPLS_I2N_HOOK_LOWER_RAW_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0')
			return NULL;

		if (tag >= NG_MPLS_ILM2NHLFE_MAX_RAW)
			return NULL;

		hook = priv->lower_raw[tag];
	}

	return hook;

}

/* Receive a control message from ngctl or the netgraph's API */
static int
ng_mpls_rcvmsg(node_p node, struct ng_mesg * msg,
	       const char *retaddr, struct ng_mesg ** rptr, struct ng_mesg **nl_msg)
{
    const priv_p priv = NG_NODE_PRIVATE(node);
    struct ng_mesg *resp = NULL;
    int             error = 0;

    switch (msg->header.typecookie) {
	/* Case node id (COOKIE) is suitable */
    case NGM_MPLS_I2N_COOKIE:
	switch (msg->header.cmd) {
	case NGM_MPLS_I2N_GET_CONFIG:
	    {
		struct ng_mpls_config *conf;

		NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
		if (resp == NULL) {
		    error = ENOMEM;
		    break;
		}
		conf = (struct ng_mpls_config *) resp->data;
		*conf = priv->conf;	/* no sanity checking needed */
		break;
	    }
	case NGM_MPLS_I2N_SET_CONFIG:
	    {
		struct ng_mpls_config *const conf =
		(struct ng_mpls_config *) msg->data;

		if (msg->header.arglen != sizeof(*conf)) {
		    error = EINVAL;
		    break;
		}
		priv->conf = *conf;
		break;
	    }
#ifdef NG_MPLS_ILM2NHLFE_STATS
	case NGM_MPLS_I2N_GET_STATS:
	case NGM_MPLS_I2N_CLR_STATS:
	case NGM_MPLS_I2N_GETCLR_STATS:
	    {
		if (msg->header.cmd != NGM_MPLS_I2N_CLR_STATS) {
		    NG_MKRESPONSE(resp, msg,
				  sizeof(priv->stats), M_NOWAIT);
		    if (resp == NULL) {
			error = ENOMEM;
			break;
		    }
		    memcpy(resp->data,
			   &priv->stats, sizeof(priv->stats));
		}
		if (msg->header.cmd != NGM_MPLS_I2N_GET_STATS)
		    memset(&priv->stats, 0, sizeof(priv->stats));
		break;
	    }
#endif
#ifdef HAVE_KTABLES
		case NGM_MPLS_I2N_NFMARK_GET_INGRESS_KTABLE:
		    {
			uint32_t	*table;
			uint32_t	*hookNum;
			hook_p		ohook;
			hookpriv_p	hpriv;

			hookNum = (uint32_t *)msg->data;
			if (msg->header.arglen != sizeof(*hookNum)) {
				error = EINVAL;
				break;
			}
			if (*hookNum >= NG_MPLS_ILM2NHLFE_MAX_ETHER) {
				error = EINVAL;
				log(LOG_ERR, "Unknown node "
					"lower_ether_%u\n", *hookNum);
				break;
			}
			ohook = priv->lower_ether[*hookNum];
			if (ohook == NULL) {
				error = EINVAL;
				log(LOG_ERR, "Unknown hookNum "
					"lower_ether_%u\n", *hookNum);
				break;
			}
			hpriv = NG_HOOK_PRIVATE(ohook);

			NG_MKRESPONSE(resp, msg, sizeof(*table), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				log(LOG_CRIT,
					"GET_INGRESS_KTABLE:"
					" Could not allocate response msg\n");
				break;
			}
			table  = (uint32_t *)resp->data;
			if (hpriv->kt_p == NULL)
				*table = 0;
			else
				*table = hpriv->kt_p - ng_get_kt_ptr(0);
			break;
		    }

		case NGM_MPLS_I2N_NFMARK_SET_INGRESS_KTABLE:
		    {
			hook_p		ohook;
			hookpriv_p	hpriv;
			struct ng_mpls_ktables *const kt =
				(struct ng_mpls_ktables *)msg->data;

			if (msg->header.arglen != sizeof(*kt)) {
				error = EINVAL;
				break;
			}
			if (kt->hookNum >= NG_MPLS_ILM2NHLFE_MAX_ETHER) {
				error = EINVAL;
				log(LOG_ERR, "Unknown hookNum "
					"lower_ether_%u\n", kt->hookNum);
				break;
			}
			ohook = priv->lower_ether[kt->hookNum];
			if (ohook == NULL) {
				error = EINVAL;
				log(LOG_ERR, "Unknown hookNum "
					"lower_ether_%u\n", kt->hookNum);
				break;
			}
			hpriv = NG_HOOK_PRIVATE(ohook);

			if (kt->table == 0)
				hpriv->kt_p = NULL;
			else if (kt->table < CONFIG_KTABLES_MAX_TABLES)
				hpriv->kt_p = ng_get_kt_ptr(kt->table);
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
 * If all the hooks are removed, let's free itself.
 */
static int
ng_mpls_disconnect(hook_p hook)
{
    const node_p node = NG_HOOK_NODE(hook);
    const priv_p priv = NG_NODE_PRIVATE(node);
    hookpriv_p hpriv = NG_HOOK_PRIVATE(hook);

    /* Incoming data hooks */
    if ((hpriv != NULL) && hook == priv->lower_ether[hpriv->tag]) {
	    priv->lower_ether[hpriv->tag] = NULL;
	    NG_HOOK_SET_PRIVATE(hook, NULL);
	    ng_free(hpriv);
	    hook->hook_rcvdata = NULL;
    } else if ((hpriv != NULL) && hook == priv->lower_raw[hpriv->tag]) {
	    priv->lower_raw[hpriv->tag] = NULL;
	    NG_HOOK_SET_PRIVATE(hook, NULL);
	    ng_free(hpriv);
	    hook->hook_rcvdata = NULL;
    } else if (hook == priv->orphans) {
	    priv->orphans = NULL;
    } else if (hook == priv->oam_ra) {
	    priv->oam_ra = NULL;
	    hook->hook_rcvdata = NULL;
    } else if (hook == priv->oam_ttl) {
	    priv->oam_ttl = NULL;
	    hook->hook_rcvdata = NULL;
    } else if ((hpriv != NULL) && hook == priv->nomatch[hpriv->tag]) {
	    priv->nomatch[hpriv->tag] = NULL;
	    NG_HOOK_SET_PRIVATE(hook, NULL);
	    ng_free(hpriv);
    } else if (hpriv != NULL) {
	/* Clean NHLFE_HOOK */
	if (unlikely(hpriv->tag >= NG_MPLS_ILM2NHLFE_DIRECT_NHLFE)) {
		if ( NHLFE_ENTRY(hpriv->tag) != NULL ) {
			if (NHLFE_HOOK(hpriv->tag) != NULL ) {
				int flag=0;
				int i=0;
				void *entry;
				(NHLFE_HOOK(hpriv->tag)) = NULL;
				/* Check if it was the last hook of this entry */
				while(i < NG_THASH_SIZE ) {
					/*TODO optimisation with a chain list of used hooks */
					if ( (NHLFE_ENTRY(hpriv->tag))[i] != NULL) {
						/* Entry always in use */
						flag = 1;
						break;
					}
					i++;
				}
				if (flag == 0) {
					/* Entry not use anymore : free memory and clear it */
					entry = NHLFE_ENTRY(hpriv->tag);
					NHLFE_ENTRY(hpriv->tag) = NULL;
					ng_free(entry);
				}
			}
		}
	} else
		priv->direct_nhlfe[hpriv->tag] = NULL;

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
ng_mpls_rmnode(node_p node)
{
    const priv_p priv = NG_NODE_PRIVATE(node);
    int i=0;
    void *entry;
#ifdef SPLASSERT
    SPLASSERT(net, __FUNCTION__);
#endif

    node->flags |= NG_INVALID;	/* inclusif or */
    ng_cutlinks(node);
    ng_unname(node);

    /* Free NHLFE */
    while(i< NG_THASH_SIZE ) {
	/*TODO optimisation with a chain list of used entries */
	if (priv->nhlfe[i] != NULL) {
		entry = priv->nhlfe[i];
		priv->nhlfe[i] = NULL;
		ng_free(entry);
	}
	i++;
    }
    NG_NODE_SET_PRIVATE(node, NULL);

    /* Unref node */
    NG_NODE_UNREF(node);

    return (0);
}

/*
 * Receive data from lower layers (mainly ethernet) Consume the mbuf and
 * meta.
 * Called at splnet() or splimp()
 * Receive packets and remove ethernet header
 */

static int
ng_mpls_rcv_ether(hook_p hook, struct mbuf * m, meta_p meta)
{
    const priv_p priv = hook->node_private;
    const struct vnb_ether_header *ehdr;
#if defined(CONFIG_VNB_MPLS_LSP_DIVERT)
    mpls_header_t *pmhdr, mhdr;
#endif

    int             error = 0;
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
    node_p node;
#endif

    if (!priv) {
	    NG_FREE_DATA(m, meta);
	    return (ENOTCONN);
    }

#ifdef NG_MPLS_ILM2NHLFE_DEBUG
    node = priv->node;

    if (!node) {
	    NG_MPLS_I2N_DPRINTF("hook is not connected");
	    error = ENOTCONN;
	    goto drop;
    }
#if defined(__LinuxKernelVNB__)
    if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_HEADER)
	log(LOG_DEBUG, "%s: Ethernet header %pM\n", node->name,
	    (struct vnb_ether_header *)m->data);
#endif
#endif

    /* Get initial header */
    /* Check  if packet_size is too small */
    if (MBUF_LENGTH(m) < (sizeof(mpls_header_t) + sizeof(*ehdr))) {
	STATS_INC(priv, recvRunts);
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
	if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_HEADER)
	    NG_MPLS_I2N_DPRINTF("%s: Packet size too small", node->name);
#endif
	error = EINVAL;
	goto drop;
    }

    /* Check if  mbuf_size is big enough to support ether and mpls header */
    m = m_pullup(m, sizeof(mpls_header_t) + sizeof(*ehdr));
    if (m == NULL) {
	STATS_INC(priv, memoryFailures);
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
	if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_HEADER)
	    NG_MPLS_I2N_DPRINTF("%s: Mbuf size too small and m_pullup() failed", node->name);
#endif
	error = ENOMEM;
	goto drop;
    }
    /* Make a pointer ehdr on mbuf ether_header */
    ehdr = mtod(m, const struct vnb_ether_header *);

    /* If packet is not mpls send it back to the ether node */
    if (unlikely(ntohs(ehdr->ether_type) != VNB_ETHERTYPE_MPLS)) {
	    hook_p nomatch;
	    hookpriv_p hpriv = NG_HOOK_PRIVATE(hook);
	    STATS_INC(priv, recvInvalid);

	    if (likely(hpriv != NULL) &&
		((nomatch = priv->nomatch[hpriv->tag]) != NULL)) {
		    NG_SEND_DATA(error, nomatch, m, meta);
		    return error;
	    }
	    error = ENOTCONN;
	    goto drop;
    }

    /* Delete ethernet header */
    m_adj(m, sizeof(struct vnb_ether_header));
#if defined(CONFIG_VNB_MPLS_LSP_DIVERT)
    /* check the name for the input interface */
    if (unlikely(hook->peer->node->name == NULL)) {
	NG_MPLS_I2N_DPRINTF("Unnamed input interface");
	error = EINVAL;
	goto drop;
    }
    /* Get the mpls header */
    pmhdr = mtod(m, mpls_header_t *);
    mhdr = *pmhdr;


    /* Big to Little conversion */
    mhdr.header = ntohl(mhdr.header);
#if defined(__LinuxKernelVNB__)
    /* save MPLS header into skb->cb */
    memcpy((void *)m->cb, (void *)pmhdr, NG_MPLS_SAVED_WORDS * sizeof(uint64_t));
    NG_MPLS_I2N_DPRINTF("MPLS header: 0x%08x", ntohl(*(uint32_t *)m->cb));
    /* also save input interface into skb->cb */
    memcpy((void *)m->cb + NG_MPLS_SAVED_WORDS * sizeof(uint64_t),
		   (void *)hook->peer->node->name, NG_NODESIZ);
    NG_MPLS_I2N_DPRINTF("I/F name: %s",
		   (char*)((void *)m->cb +
		   NG_MPLS_SAVED_WORDS * sizeof(uint64_t)));
#elif defined(__FastPath__)
    /* save MPLS header into mpls_saved_stack[NG_MPLS_SAVED_WORDS] */
    memcpy((void *)FPN_PER_CORE_VAR(mpls_saved_stack), (void *)pmhdr,
		   NG_MPLS_SAVED_WORDS  *sizeof(uint64_t));
    NG_MPLS_I2N_DPRINTF("MPLS header: 0x%08x",
		   ntohl(*(uint32_t *)pmhdr));
    /* also save input interface into mpls_input_iface */
    memcpy((void *)FPN_PER_CORE_VAR(mpls_input_iface),
		   (void *)hook->peer->node->name, NG_NODESIZ);
    NG_MPLS_I2N_DPRINTF("I/F name: %s",
		   FPN_PER_CORE_VAR(mpls_input_iface));
#endif
    /* Router Alert detection */
    if (unlikely(mhdr.mhtag == 1)) {
	if (priv->oam_ra != NULL) {
	    NG_SEND_DATA(error, priv->oam_ra, m, meta);
	    return error;
	}
	error = ENOTCONN;
	goto drop;
    }
    /* MPLS TTL check : is done in ng_mpls_rcv_raw() */
#endif /*defined(CONFIG_VNB_MPLS_LSP_DIVERT)*/

    /* Call ng_mpls_rcv_raw() for general treatment */
    error = ng_mpls_rcv_raw(hook, m, meta);
    return error;

drop:
    NG_FREE_DATA(m, meta);
    return (error);

}

/* Select a hook following tag value */
static int
ng_mpls_rcv_raw(hook_p hook, struct mbuf * m, meta_p meta)
{
    const priv_p priv = hook->node_private;
    mpls_header_t  *nmphdr, mhdr;
    int             error = 0;
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
    node_p node;
#endif
#ifdef HAVE_KTABLES
    hookpriv_p hpriv;
#endif

    if (!priv) {
	    NG_FREE_DATA(m, meta);
	    return (ENOTCONN);
    }

    /* Update stats */
    STATS_INC(priv, recvPackets);
    STATS_ADD(priv, recvOctets, MBUF_LENGTH(m));

#ifdef NG_MPLS_ILM2NHLFE_DEBUG
    node = priv->node;

    if (!node) {
	    NG_MPLS_I2N_DPRINTF("hook is not connected");
	    error = ENOTCONN;
	    goto drop;
    }
#endif

    /* Check  if packet_size is too small */
    if (MBUF_LENGTH(m) < (sizeof(*nmphdr))) {
	STATS_INC(priv, recvRunts);
	error = EINVAL;
	goto drop;
    }

    /* Check if mbuf_size is big enough to support nmphdr */
    m = m_pullup(m, sizeof(*nmphdr));
    if (m == NULL) {
	STATS_INC(priv, memoryFailures);
	error = ENOMEM;
	goto drop;
    }
    /* Have a pointer to mbuf */
    nmphdr = mtod(m, mpls_header_t *);

    /* Big to Little Endian Convertion */
    mhdr.header = ntohl(nmphdr->header);

#ifdef NG_MPLS_ILM2NHLFE_DEBUG
    if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_RAW) {
	NG_MPLS_I2N_DPRINTF("Header =  0x%08x", mhdr.header);
	NG_MPLS_I2N_DPRINTF("TAG : 0x%x", (int)mhdr.mhtag);
	NG_MPLS_I2N_DPRINTF("EXP : 0x%x", (int)mhdr.mhexp);
	NG_MPLS_I2N_DPRINTF("BS  : 0x%x", (int)mhdr.mhbs);
	NG_MPLS_I2N_DPRINTF("TTL : 0x%x", (int)mhdr.mhttl);
    }
#endif

#if defined(__LinuxKernelVNB__)
    /* Trace if an intermediate MPLS header is Router Alert */
    if ( mhdr.mhtag == 1 ) {
	if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_RAW)
	    NG_MPLS_I2N_DPRINTF("%s: Router alert : 0x%x", node->name, (int)mhdr.mhtag);
    } else
#endif
    /* Check if the header has some legal values */
    if ( (mhdr.mhtag < 0)
      || (mhdr.mhtag >= NG_MPLS_I2N_MAX_TAG)
      || (mhdr.mhtag == 3)
	) {
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
	if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_RAW)
	    NG_MPLS_I2N_DPRINTF("%s: Invalid tag : 0x%x", node->name, (int)mhdr.mhtag);
#endif
	STATS_INC(priv, recvInvalid);
	error = EINVAL;
	goto drop;
    }

#ifdef HAVE_KTABLES
#if defined(CONFIG_VNB_MPLS_LSP_DIVERT)
    /*
     * If we come from oam_ttl, we have already do the job.
     * If we come from oam_ra, we can't know which table to use.
     */
    if ((hook != priv->oam_ra) && (hook != priv->oam_ttl)) {
#endif
	    hpriv = NG_HOOK_PRIVATE(hook);
	    if (unlikely(hpriv == NULL))
		    goto drop;
	    /* retrieve priority */
	    if (hpriv->kt_p != NULL)
		    ng_pkt_set_mark(m, hpriv->kt_p[mhdr.mhexp]);
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
	    if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_RAW) {
		    NG_MPLS_I2N_DPRINTF("mark: 0x%x", ng_pkt_get_mark(m));
	    }
#endif
#if defined(CONFIG_VNB_MPLS_LSP_DIVERT)
    }
#endif
#endif

#ifdef NG_MPLS_ILM2NHLFE_DEBUG
    if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_RAW)
	NG_MPLS_I2N_DPRINTF("%s: Tag value = %d(0x%x)", node->name,
	    (int)mhdr.mhtag, (int)mhdr.mhtag);
#endif
    /* check will be done for packets coming back from mplsoam node : RA */
#if defined(CONFIG_VNB_MPLS_LSP_DIVERT)
    /* if (nmphdr->mttl == 1) => mplsoam */
    if (unlikely((hook != priv->oam_ttl) && (mhdr.mhttl == 1))) {
	if (priv->oam_ttl != NULL) {
	    NG_SEND_DATA(error, priv->oam_ttl, m, meta);
	    return error;
	}
	error = ENOTCONN;
	goto drop;
    }
#endif /*defined(CONFIG_VNB_MPLS_LSP_DIVERT)*/

    /* Get the correct upper hook */
    if (unlikely(mhdr.mhtag >= NG_MPLS_ILM2NHLFE_DIRECT_NHLFE))
	    return ng_mpls_rcv_nhlfe(priv, mhdr, m, meta);
    else
	    return ng_mpls_rcv_direct_nhlfe(priv, mhdr, m, meta);

 drop:
	NG_FREE_DATA(m, meta);
	return (error);
}

static int
ng_mpls_rcv_nomatch(hook_p hook, struct mbuf * m, meta_p meta)
{
	const priv_p priv = hook->node_private;
	const hookpriv_p hpriv = NG_HOOK_PRIVATE(hook);
	hook_p lower;
	int error = 0;

	if (unlikely(!priv))
		goto drop;

	STATS_INC(priv, recvNomatchPackets);
	STATS_ADD(priv, recvNomatchOctets, MBUF_LENGTH(m));

	/* Send the packet to the corresponding lower ether hook */
	if (likely(hpriv != NULL) &&
	    ((lower = priv->lower_ether[hpriv->tag]) != NULL)) {
		/* Update stats */
		STATS_INC(priv, NomatchToLowerPackets);
		STATS_ADD(priv, NomatchToLowerOctets, MBUF_LENGTH(m));

		NG_SEND_DATA(error, lower, m, meta);
		return error;
	}

drop:
	NG_FREE_DATA(m, meta);
	return ENOTCONN;


}

/* Hash table hook */
static int
ng_mpls_rcv_nhlfe(priv_p priv, mpls_header_t  mhdr, struct mbuf *m, meta_p meta)
{
	hook_p          ohook = NULL;
	int             error = 0;
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
	node_p node = priv->node;

	if (!node) {
		NG_MPLS_I2N_DPRINTF("%s: hook is not connected", node->name);
		error = ENOTCONN;
		goto drop;
	}
#endif

	if (NHLFE_ENTRY(mhdr.mhtag) == NULL) {
		/* No entry for that tag */
		STATS_INC(priv, recvUnknownTag);
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
		if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_RAW)
			NG_MPLS_I2N_DPRINTF("%s: No entry for that tag1", node->name);
#endif
		if (priv->orphans == NULL) {
			/* No node connected to orphan : discard packet */
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
			if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_RAW)
				NG_MPLS_I2N_DPRINTF("%s: No node connected to orphan1", node->name);
#endif
			error = ENOTCONN;
			goto drop;
		}
		ohook = priv->orphans;
	} else {
		/* Test if a hook matches that tag */
		ohook = (NHLFE_HOOK(mhdr.mhtag));
		if (NHLFE_HOOK(mhdr.mhtag) == NULL) {
			/* No matching hook */
			STATS_INC(priv, recvUnknownTag);
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
			if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_RAW)
				NG_MPLS_I2N_DPRINTF("%s: No entry for that tag2", node->name);
#endif
			if (priv->orphans == NULL) {
				/* No node connected to orphan : discard packet */
				error = ENOTCONN;
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
				if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_RAW)
					NG_MPLS_I2N_DPRINTF("%s: No node connected to orphans2", node->name);
#endif
				goto drop;
			}

#ifdef NG_MPLS_ILM2NHLFE_DEBUG
			if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_RAW)
				NG_MPLS_I2N_DPRINTF("ohook = priv->orphans");
#endif
			ohook = priv->orphans;
		}
	}

	/* Update stats */
	STATS_INC(priv, xmitPackets);
	STATS_ADD(priv, xmitOctets, MBUF_LENGTH(m));

	/*
	 * Forward data to the output hook : orphan or nhlfe
	 * The mbuf and meta are consumed by the nodes of the peers.
	 */
	NG_SEND_DATA(error, ohook, m, meta);

	/* When NG_SEND_DATA fails, the mbuf and meta do not need to be freed
	 * because it has already been done by the peer's node. */
	return (error);

 drop:
	NG_FREE_DATA(m, meta);
	return (error);
}

/* Direct access table hook */
static int
ng_mpls_rcv_direct_nhlfe(priv_p priv, mpls_header_t  mhdr, struct mbuf *m, meta_p meta)
{
	hook_p          ohook = NULL;
	int             error = 0;
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
	node_p node = priv->node;

	if (!node) {
		NG_MPLS_I2N_DPRINTF("%s: hook is not connected", node->name);
		error = ENOTCONN;
		goto drop;
	}
#endif
	ohook = priv->direct_nhlfe[mhdr.mhtag];
	if (ohook == NULL) {
		/* No entry for that tag */
		STATS_INC(priv, recvUnknownTag);
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
		if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_RAW)
			NG_MPLS_I2N_DPRINTF("%s: No entry for that tag1 %d", node->name, mhdr.mhtag);
#endif
		if (priv->orphans == NULL) {
			/* No node connected to orphan : discard packet */
#ifdef NG_MPLS_ILM2NHLFE_DEBUG
			if (priv->conf.debugFlag & NG_MPLS_I2N_DEBUG_RAW)
				NG_MPLS_I2N_DPRINTF("%s: No node connected to orphan1", node->name);
#endif
			error = ENOTCONN;
			goto drop;
		}
		ohook = priv->orphans;
	}

	/* Update stats */
	STATS_INC(priv, xmitPackets);
	STATS_ADD(priv, xmitOctets, MBUF_LENGTH(m));

	/*
	 * Forward data to the output hook : orphan or nhlfe
	 * The mbuf and meta are consumed by the nodes of the peers.
	 */
	NG_SEND_DATA(error, ohook, m, meta);

	/* When NG_SEND_DATA fails, the mbuf and meta do not need to be freed
	 * because it has already been done by the peer's node. */
	return (error);

 drop:
	NG_FREE_DATA(m, meta);
	return (error);
}
