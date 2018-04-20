/*
 * Copyright 2009-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_NFFEC_H
#define _NETGRAPH_NG_NFFEC_H

#ifdef __FastPath__
int ng_nffec_init(void);
#endif

/* Node type name */
#define NG_NFFEC_NODE_TYPE		"nffec"
#define NGM_NFFEC_COOKIE		1252313143

/* Hook names */
#define NG_NFFEC_HOOK_MUX		"mux"		/* the mux hook */
#define NG_NFFEC_HOOK_LOWER_IN_PREFIX	"lower_in_"	/* lower input hooks */
#define NG_NFFEC_HOOK_LINK_PREFIX	"nfm_"		/* append decimal integer */
#define NG_NFFEC_HOOK_LINK_FMT		"nfm_%d"	/* for use with printf(3),
							 * %d is the tag */
#define NG_NFFEC_HOOK_ORPHANS      	"orphans"	/* the unknown tags */

/* Node configuration structure */
struct ng_nffec_config {
    uint8_t         debugFlag;	/* debug features */
};

#define NG_NFFEC_DEBUG_NONE	0x00
#define NG_NFFEC_DEBUG_HEADER	0x01
#define NG_NFFEC_DEBUG_RAW 	0x02

/* Keep this in sync with the above structure definition */
#define NG_NFFEC_CONFIG_TYPE_INFO {		\
    { "debugFlag", &ng_parse_uint8_type, 0 },	\
    { NULL, NULL, 0 }				\
  }

/* Statistics structure */
struct ng_nffec_stats {
    uint64_t        recvOctets;		/* total octets rec'd */
    uint64_t        recvPackets;	/* total pkts rec'd */
    uint64_t        recvRunts;	 	/* pkts rec'd less than nffec's header in bytes */
    uint64_t        recvInvalid;	/* pkts rec'd with bogus header */
    uint64_t        recvUnknownTag;	/* pkts rec'd with unknown tag */
    uint64_t	    xmitOctets;		/* total Octets transmited */
    uint64_t	    xmitPackets;	/* total pkts transmited */
    uint64_t        memoryFailures;	/* times couldn't get mem or mbuf */
};

/* Keep this in sync with the above structure definition */
#define NG_NFFEC_STATS_TYPE_INFO {		                        \
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

/* Node configuration structure */
struct ng_nffec_mode {
    uint8_t         sfcEnable;	/* enable Simple Flow Classifier */
};

/* Simple flow classifier selection */
#define NG_NFFEC_SFC_DISABLE	0x00
#define NG_NFFEC_SFC_ENABLE	0x01

/* Keep this in sync with the above structure definition */
#define NG_NFFEC_SFC_TYPE_INFO {		\
    { "simpleFlow", &ng_parse_uint8_type, 0 },	\
    { NULL, NULL, 0 }				\
  }

/* Netgraph control messages */
enum {
    /*
     * Node specific commands
     */
    NGM_NFFEC_GET_CONFIG = 1,	/* get node configuration */
    NGM_NFFEC_SET_CONFIG,	/* set node configuration */

    NGM_NFFEC_GET_STATS,	/* get node stats */
    NGM_NFFEC_CLR_STATS,	/* clear node stats */
    NGM_NFFEC_GETCLR_STATS,	/* atomically get & clear node stats */

    NGM_NFFEC_GET_MODE,		/* get node working mode */
    NGM_NFFEC_SET_MODE,		/* set node working mode */
    /*
     * Link specific commands
     */
    /* [none] */
};

/*************************************************************
 * Constants and definitions specific to NFFEC
 *************************************************************/

#if defined(CONFIG_VNB_NFFEC_HASHTABLE_ORDER)
#define NFFEC_HASHTABLE_ORDER 	CONFIG_VNB_NFFEC_HASHTABLE_ORDER
#else
#define NFFEC_HASHTABLE_ORDER 	4
#endif
#define NFFEC_HASHTABLE_SIZE  	(1<<NFFEC_HASHTABLE_ORDER)
#define NFFEC_HASHTABLE_MASK  	(NFFEC_HASHTABLE_SIZE-1)

/* return the HASHTABLE_ORDER last bits */
#define NG_NFFEC_TAG_R(tag)		((tag) & NFFEC_HASHTABLE_MASK)

#define NFFEC_BUCKET(tag)	(&priv->bucket[NG_NFFEC_TAG_R((tag))])

#endif
