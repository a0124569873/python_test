/*
 * Copyright  2003-2013 6WIND S.A.
 */

/* In the following code tag and label are use both to design mpls labels */

#ifndef _NETGRAPH_NG_MPLS_I2N_H_
#define _NETGRAPH_NG_MPLS_I2N_H_

#ifdef __FastPath__
int ng_mpls_ilm2nhlfe_init(void);
#endif

/* Node type name */
#define NG_MPLS_I2N_NODE_TYPE		"mpls_ilm"
#define NG_MPLS_TYPE			0x8847
#define NGM_MPLS_I2N_COOKIE             31415926	/* node value : pi
							 * number value for
							 * example */

/* Hook names */
#define NG_MPLS_I2N_HOOK_LOWER_ETHER_PREFIX "lower_ether_" /* lower ether hooks */
#define NG_MPLS_I2N_HOOK_NOMATCH_PREFIX     "nomatch_"	   /* the nomatch tags: not MPLS frames */
#define NG_MPLS_I2N_HOOK_LOWER_RAW_PREFIX   "lower_raw_"   /* lower raw hooks */
#define NG_MPLS_I2N_HOOK_LINK_PREFIX   "nhlfe_"		/* append decimal integer */
#define NG_MPLS_I2N_HOOK_LINK_FMT      "nhlfe_%d"	/* for use with
							 * printf(3), %d is the
							 * tag           */
#define NG_MPLS_I2N_HOOK_ORPHANS      "orphans"		/* the unknown tags */
#define NG_MPLS_I2N_HOOK_OAM_RA       "oam_ra"		/* MPLS-OAM Router Alert LSP ping */
#define NG_MPLS_I2N_HOOK_OAM_TTL      "oam_ttl"	/* MPLS-OAM TTl==1 LSP ping */


/* Node configuration structure */

struct ng_mpls_config {
    uint8_t         debugFlag;	/* debug features */
};

#define NG_MPLS_I2N_DEBUG_NONE   0x00
#define NG_MPLS_I2N_DEBUG_HEADER 0x01
#define NG_MPLS_I2N_DEBUG_RAW	 0x02

/* Keep this in sync with the above structure definition */
#define NG_MPLS_I2N_CONFIG_TYPE_INFO {		\
    { "debugFlag", &ng_parse_uint8_type, 0 },	\
    { NULL, NULL, 0 }				\
  }

/* Statistics structure */
struct ng_mpls_stats {
    uint64_t        recvOctets;		/* total octets rec'd */
    uint64_t        recvPackets;	/* total pkts rec'd */
    uint64_t        recvNomatchOctets;		/* total octets rec'd */
    uint64_t        recvNomatchPackets;	/* total pkts rec'd */
    uint64_t        recvRunts;	 	/* pkts rec'd less than mpls's header in bytes */
    uint64_t        recvInvalid;	/* pkts rec'd with bogus header */
    uint64_t        recvUnknownTag;	/* pkts rec'd with unknown tag */
    uint64_t	    xmitOctets;		/* total Octets transmited */
    uint64_t	    xmitPackets;	/* total pkts transmited */
    uint64_t	    NomatchToLowerOctets;	/* total Octets transmited on lower ether hook */
    uint64_t	    NomatchToLowerPackets;	/* total pkts transmited on lower ether hook */
    uint64_t        memoryFailures;	/* times couldn't get mem or mbuf */
};

/* Keep this in sync with the above structure definition */
#define NG_MPLS_I2N_STATS_TYPE_INFO {		                        \
	  { "recvOctets",		&ng_parse_uint64_type,	0	},	\
	  { "recvPackets",		&ng_parse_uint64_type,	0	},	\
	  { "recvNomatchOctets",	&ng_parse_uint64_type,	0	},	\
	  { "recvNomatchPackets",	&ng_parse_uint64_type,	0	},	\
	  { "recvRunts",		&ng_parse_uint64_type,	0	},	\
	  { "recvInvalid",		&ng_parse_uint64_type,	0	},	\
	  { "recvUnknownTag",		&ng_parse_uint64_type,	0	},	\
	  { "xmitOctets",		&ng_parse_uint64_type,	0   	},	\
	  { "xmitPackets",		&ng_parse_uint64_type,	0	},	\
	  { "NomatchToLowerOctets",	&ng_parse_uint64_type,	0   	},	\
	  { "NomatchToLowerPackets",	&ng_parse_uint64_type,	0	},	\
	  { "memoryFailures",		&ng_parse_uint64_type,	0	},	\
	  { NULL,			NULL,			0	}	\
}

/* Ktables config struct for priority mapping */
struct ng_mpls_ktables {
	uint32_t	hookNum;
	uint32_t	table;
};
#define NG_MPLS_I2N_KTABLES_TYPE_INFO {			\
	{ "node",	&ng_parse_uint32_type,	0 },	\
	{ "table",	&ng_parse_uint32_type,	0 },	\
	{ NULL,		NULL,			0 },	\
}

/* Netgraph control messages */
enum {
    /*
     * Node specific commands
     */
    NGM_MPLS_I2N_SET_CONFIG = 0,/* set node configuration */
    NGM_MPLS_I2N_GET_CONFIG,	/* get node configuration */

    NGM_MPLS_I2N_GET_STATS,	/* get node stats */
    NGM_MPLS_I2N_CLR_STATS,	/* clear node stats */
    NGM_MPLS_I2N_GETCLR_STATS,	/* atomically get & clear node stats */
    NGM_MPLS_I2N_NFMARK_GET_INGRESS_KTABLE, /* Get priority mapping table */
    NGM_MPLS_I2N_NFMARK_SET_INGRESS_KTABLE, /* Set priority mapping table */

    /*
     * Link specific commands
     */
    /* [none] */
};

/*************************************************************
 * Constants and definitions specific to MPLS
 *************************************************************/

#define NG_MPLS_I2N_MAX_TAG		1048576	/* 2^20 */
#if defined(CONFIG_VNB_ILM2NHLFE_THASH_ORDER)
#define NG_THASH_ORDER			CONFIG_VNB_ILM2NHLFE_THASH_ORDER
#else
#define NG_THASH_ORDER			10
#endif
#define NG_THASH_SIZE           	(1 << NG_THASH_ORDER)	/* 2^10 entries in nhlfe table */

/* Macro */
#define NG_NHLFE_TAG_L(tag)    	(((tag) & 0xffc00) >> 10)	/* return the 10 first bits */
#define NG_NHLFE_TAG_R(tag)    	((tag) & 0x003ff)		/* return the 10 last  bits */

/* nhlfe[] is a hash table of 1024 entries based on the first 10 label bits
 * with the 10 last bits we match a particular hook
 * These 2 macro deals with it
 */

/* Return a hook according to label value */
#if defined(__LinuxKernelVNB__) || defined(__FastPath__)
#define NHLFE_HOOK(tag)		(priv->nhlfe[NG_NHLFE_TAG_L((tag))][NG_NHLFE_TAG_R((tag))])
#else
#define NHLFE_HOOK(tag)		(hook_p )(priv->nhlfe[NG_NHLFE_TAG_L((tag))][NG_NHLFE_TAG_R((tag))])
#endif

/* Return pointer to an array of hooks according to 10 first label bits */
#if defined(__LinuxKernelVNB__) || defined(__FastPath__)
#define NHLFE_ENTRY(tag) 	(priv->nhlfe[NG_NHLFE_TAG_L((tag))])
#else
#define NHLFE_ENTRY(tag) 	(hook_p *)(priv->nhlfe[NG_NHLFE_TAG_L((tag))])
#endif

#endif
