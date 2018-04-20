/*
 * Copyright 2009-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_MUX_H
#define _NETGRAPH_NG_MUX_H

/* Node type name */
#define NG_MUX_NODE_TYPE		"mux"
#define NGM_MUX_COOKIE			1253844632

/* Hook names */
#define NG_MUX_HOOK_OUT			"out"     /* the mux hook */
#define NG_MUX_HOOK_IN_PREFIX		"in_"     /* append decimal integer */
#define NG_MUX_HOOK_IN_FMT		"in_%d"   /* for use with printf(3),
						   * %d is the tag */
/* Node configuration structure */
struct ng_mux_config {
    uint8_t         debugFlag;	/* debug features */
};

#define NG_MUX_DEBUG_NONE	0x00
#define NG_MUX_DEBUG_HEADER	0x01
#define NG_MUX_DEBUG_RAW 	0x02

/* Keep this in sync with the above structure definition */
#define NG_MUX_CONFIG_TYPE_INFO {		\
    { "debugFlag", &ng_parse_uint8_type, 0 },	\
    { NULL, NULL, 0 }				\
  }

/* Statistics structure */
struct ng_mux_stats {
	uint64_t recvOctets;     /* total octets rec'd */
	uint64_t recvPackets;    /* total pkts rec'd */
	uint64_t recvRunts;      /* pkts rec'd less than mux's header in bytes */
	uint64_t recvInvalid;    /* pkts rec'd with bogus header */
	uint64_t recvUnknownTag; /* pkts rec'd with unknown tag */
	uint64_t xmitOctets;     /* total Octets transmited */
	uint64_t xmitPackets;    /* total pkts transmited */
	uint64_t memoryFailures; /* times couldn't get mem or mbuf */
};

/* Keep this in sync with the above structure definition */
#define NG_MUX_STATS_TYPE_INFO {		                        \
	  { "recvOctets",	&ng_parse_uint64_type,	0	},	\
	  { "recvPackets",	&ng_parse_uint64_type,	0	},	\
	  { "recvRunts",	&ng_parse_uint64_type,	0	},	\
	  { "recvInvalid",	&ng_parse_uint64_type,	0	},	\
	  { "recvUnknownTag",   &ng_parse_uint64_type,	0	},	\
	  { "xmitOctets",	&ng_parse_uint64_type,	0   	},	\
	  { "xmitPackets",	&ng_parse_uint64_type,	0	},	\
	  { "memoryFailures",  	&ng_parse_uint64_type,	0	},	\
	  { NULL,		NULL,			0	}	\
}

/* Netgraph control messages */
enum {
	/*
	 * Node specific commands
	 */
	NGM_MUX_GET_CONFIG = 1, /* get node configuration */
	NGM_MUX_SET_CONFIG,     /* set node configuration */

	NGM_MUX_GET_STATS,      /* get node stats */
	NGM_MUX_CLR_STATS,      /* clear node stats */
	NGM_MUX_GETCLR_STATS,   /* atomically get & clear node stats */

	/*
	 * Link specific commands
	 */
	/* [none] */
};

/*************************************************************
 * Constants and definitions specific to MUX
 *************************************************************/

#if defined(CONFIG_VNB_MUX_HASHTABLE_ORDER)
#define HASHTABLE_ORDER		CONFIG_VNB_MUX_HASHTABLE_ORDER
#else
#define HASHTABLE_ORDER 	10
#endif
#define HASHTABLE_SIZE  	(1<<HASHTABLE_ORDER)
#define HASHTABLE_MASK  	(HASHTABLE_SIZE-1)

/* return the HASHTABLE_ORDER last bits */
#define NG_MUX_TAG_R(tag)		((tag) & HASHTABLE_MASK)

#define MUX_BUCKET(tag)		(&priv->bucket[NG_MUX_TAG_R((tag))])

#endif
