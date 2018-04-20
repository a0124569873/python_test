/*
 * Copyright 2010-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_GTPU_H_
#define _NETGRAPH_NG_GTPU_H_

/* Node type name and magic cookie */
#define NG_GTPU_NODE_TYPE    "gtpu"
#define NGM_GTPU_COOKIE      201011091

//#define NG_GTPU_STATS

/* Hook names */
#define NG_GTPU_HOOK_UPPER_PREFIX "upper"    /* prefix for upper hook */
#define NG_GTPU_HOOK_LOWER_PREFIX "lower"    /* prefix for Tx lower hook */
#define NG_GTPU_HOOK_LOWER_RX     "lower_rx" /* Rx lower hook */
#define NG_GTPU_HOOK_NOMATCH      "nomatch"  /* the nomatch hook */

/* PDP context structure : for parsing */
struct ng_gtpu_pdp_context {
	char	lower[NG_HOOKLEN + 1];
	char	upper[NG_HOOKLEN + 1];
	uint32_t	teid_tx;
	uint32_t	teid_rx;
	uint8_t	flags_tx;
	uint8_t	tos;
};

/* Keep this in sync with the above structure definition */
#define NG_GTPU_PDP_CTXT_TYPE_INFO { \
	  { "lower",	&ng_parse_hookbuf_type, 0 }, \
	  { "upper",	&ng_parse_hookbuf_type, 0 }, \
	  { "teid_tx",	&ng_parse_uint32_type, 0 }, \
	  { "teid_rx",	&ng_parse_uint32_type, 0 }, \
	  { "flags_tx",	&ng_parse_uint8_type, 0 }, \
	  { "tos",	&ng_parse_uint8_type, 0 }, \
	  { NULL, NULL, 0 } \
}

struct ng_gtpu_pdp_delinfo {
	char	upper[NG_HOOKLEN + 1];
	uint32_t	teid;
};

#define NG_GTPU_PDP_DEL_INFO { \
	  { "upper",	&ng_parse_hookbuf_type, 0 }, \
	  { "teid",	&ng_parse_uint32_type, 0 }, \
	  { NULL, NULL, 0 } \
}

/* Statistics structure */
/* later : switch to per core for speed */
struct ng_gtpu_stats {
	uint64_t	recvOctets;	/* total octets rec'd */
	uint64_t	xmitOctets;	/* total octets xmit'd */
	uint32_t	recvPackets;	/* total pkts rec'd */
	uint32_t	recvRunts;	/* pkts rec'd less than gtpu's header in bytes */
	uint32_t	recvInvalid;	/* pkts rec'd with bogus teid */
	uint32_t	xmitPackets;	/* total pkts xmit'd */
	uint32_t	memoryFailures;	/* times couldn't get mem or mbuf */
};

/* Keep this in sync with the above structure definition */
#define NG_GTPU_STATS_TYPE_INFO	{					\
	{ "recvOctets",		&ng_parse_uint64_type, 0	},	\
	{ "xmitOctets",		&ng_parse_uint64_type, 0	},	\
	{ "recvPackets",	&ng_parse_uint32_type, 0	},	\
	{ "recvRunts",		&ng_parse_uint32_type, 0	},	\
	{ "recvInvalid",	&ng_parse_uint32_type, 0	},	\
	{ "xmitPackets",	&ng_parse_uint32_type, 0	},	\
	{ "memoryFailures",	&ng_parse_uint32_type, 0	},	\
	{ NULL, NULL, 0 }						\
}

#ifdef NG_GTPU_STATS
#define STATS_INC(x, y) do { \
		(x)->stats.y++; \
	} while(0)

#define STATS_ADD(x, y, z) do { \
		(x)->stats.y += z; \
	} while(0)

#endif

/* Netgraph commands */
enum {
	NGM_GTPU_SET_REQ = 1,  /* send ECHO req for this tunnel
				 (implicitly to the other end) */
	NGM_GTPU_GET_REPLY,    /* inquire if ECHO reply has been seen
				  for this tunnel */
#ifdef NG_GTPU_STATS
	NGM_GTPU_GET_STATS,    /* error stats for this tunnel */
	NGM_GTPU_CLR_STATS,    /* error stats for this tunnel */
	NGM_GTPU_GETCLR_STATS, /* error stats for this tunnel */
#endif
	NGM_GTPU_ADDPDP_CTXT,  /* create one tunnel */
	NGM_GTPU_DELPDP_CTXT,  /* delete one tunnel */
	NGM_GTPU_GET_CONFIG,   /* dump config for this tunnel */
	NGM_GTPU_SET_TIMEOUT,  /* delay for request for this tunnel (/node ?) */
	NGM_GTPU_UPDPDP_CTXT,  /* update one tunnel */
	/* later : command to enable echo reply for this tunnel (/node ?) */
};

struct gtu_v1_hdr {
	union {
		uint8_t version:3,
			pt:1,
			o:1,
			e:1,
			s:1,
			pn:1;
		uint8_t flags;
	};
	uint8_t message_type;
	uint16_t length;
	uint32_t teid;
}__attribute__((__packed__));

/* GTPU defines : message type, default values for the flags */
#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_GTPU, "ng_gtpu", "netgraph GTPU");
#else
#define M_NETGRAPH_GTPU M_NETGRAPH
#endif

#define NGM_GTPU_ECHO_REQ      1
#define NGM_GTPU_ECHO_REP      2
#define NGM_GTPU_DATA_PACKET 255

/* default values for GTP-U : Version == 1, PT == 1 */
#define NGM_GTPU_DEFAULT_FLAGS (1 << 5) | (1 << 4)

#endif /* _NETGRAPH_NG_GTPU_H_ */
