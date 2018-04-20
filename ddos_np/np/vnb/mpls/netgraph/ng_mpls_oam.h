/*
 * Copyright 2011 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_MPLS_OAM_H_
#define _NETGRAPH_NG_MPLS_OAM_H_

/* Node type name and magic cookie */
#define NG_MPLS_OAM_NODE_TYPE    "mpls_oam"
#define NGM_MPLS_OAM_COOKIE      201112081

#if !defined(__FastPath__)

#define NGM_MPLS_OAM_LSP_INFO    1	/* mpls_oam_meta_t */

/* specific meta used for MPLS-OAM : used in kernel and userland */
typedef struct {
	struct meta_field_header hdr;
	struct {
#define EXP_BS(exp)   ((exp >> 4) & 0x7)
#define EXP_NOBS(exp) (exp & 0x7)
		uint8_t exp;       /* EXP value for BS and non BS label, use above defines */
		uint8_t ttl_bs;    /* TTL to set on BS label */
		uint8_t ttl_nobs;  /* TTL to set on non BS label */
		uint8_t ra;        /* when set mpls_ether node adds a Router Alert MPLS label */
	} oam;
} mpls_oam_meta_t;
#endif

/* Node configuration structure */

struct ng_mpls_oam_config {
	uint8_t         debugFlag;	/* debug features */
};

#define NG_MPLS_OAM_DEBUG_NONE   0x00
#define NG_MPLS_OAM_DEBUG_HEADER 0x01
#define NG_MPLS_OAM_DEBUG_RAW    0x02

/* Keep this in sync with the above structure definition */
#define NG_MPLS_OAM_CONFIG_TYPE_INFO {		\
	{ "debugFlag", &ng_parse_uint8_type, 0 },	\
	{ NULL, NULL, 0 }				\
}

/* Hook names */
#define NG_MPLS_OAM_HOOK_UPPER_LSP "upper_lsp"    /* name for upper hook for LSP packets */
#define NG_MPLS_OAM_HOOK_UPPER_BFD "upper_bfd"    /* name for upper hook for BFD packets */
#define NG_MPLS_OAM_LOWER_PREFIX_RA  "lower_ra_"  /* prefix for lower hook (MPLS RA) */
#define NG_MPLS_OAM_LOWER_PREFIX_TTL "lower_ttl_" /* prefix for lower hook (MPLS TTL == 1) */
#define NG_MPLS_OAM_LOWER_PREFIX_IP "lower_ip_" /* prefix for lower IP hook (IP RA or TTL == 1) */

//#define NG_MPLS_OAM_STATS

/* Statistics structure */
/* later : switch to per core for speed */
struct ng_mpls_oam_stats {
	uint64_t	recvOctets;	/* total octets rec'd */
	uint64_t	xmitOctets;	/* total octets xmit'd */
	uint32_t	recvPackets;	/* total pkts rec'd */
	uint32_t	recvRunts;	/* pkts rec'd less than gtpu's header in bytes */
	uint32_t	recvInvalid;	/* pkts rec'd with bogus teid */
	uint32_t	xmitPackets;	/* total pkts xmit'd */
	uint32_t	memoryFailures;	/* times couldn't get mem or mbuf */
};

/* Keep this in sync with the above structure definition */
#define NG_MPLS_OAM_STATS_TYPE_INFO	{					\
	{ "recvOctets",		&ng_parse_uint64_type, 0	},	\
	{ "xmitOctets",		&ng_parse_uint64_type, 0	},	\
	{ "recvPackets",	&ng_parse_uint32_type, 0	},	\
	{ "recvRunts",		&ng_parse_uint32_type, 0	},	\
	{ "recvInvalid",	&ng_parse_uint32_type, 0	},	\
	{ "xmitPackets",	&ng_parse_uint32_type, 0	},	\
	{ "memoryFailures",	&ng_parse_uint32_type, 0	},	\
	{ NULL, NULL, 0 }						\
}

//#define NG_MPLS_OAM_STATS
/* Netgraph commands */
enum {
    NGM_MPLS_OAM_SET_CONFIG = 1,	/* set node configuration */
    NGM_MPLS_OAM_GET_CONFIG,		/* get node configuration */
#ifdef NG_MPLS_OAM_STATS
	NGM_MPLS_OAM_GET_STATS,    /* error stats for this tunnel */
	NGM_MPLS_OAM_CLR_STATS,    /* error stats for this tunnel */
	NGM_MPLS_OAM_GETCLR_STATS, /* error stats for this tunnel */
#endif
};

/* MPLS_OAM defines : message type, default values for the flags */
#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_MPLS_OAM, "ng_mpls_oam", "netgraph MPLS-OAM");
#else
#define M_NETGRAPH_MPLS_OAM M_NETGRAPH
#endif

/* pre-defined constant UDP ports */
#define LSP_PING_PORT	3503
#define BFD_PORT	3784

#endif /* _NETGRAPH_NG_MPLS_OAM_H_ */
