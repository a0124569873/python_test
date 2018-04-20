/*
 * Copyright 2005-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_GRE_H_
#define _NETGRAPH_NG_GRE_H_

#ifdef __FastPath__
int ng_gre_init(void);
#endif

/* Magic cookie */
#define NGM_GRE_COOKIE			1627384950

/* Node type name */
#define NG_GRE_NODE_TYPE		"gre"

/* Hook names */
#define NG_GRE_HOOK_LOWER		"lower"    	/* the lower hook */
#define NG_GRE_HOOK_KEY_PREFIX		"key_"		/* append decimal integer */
#define NG_GRE_HOOK_KEY_FMT		"key_%d"	/* for use with printf(3),
								* %d is the tag */
#define NG_GRE_HOOK_NOMATCH      	"nomatch"	/* the nomatch hook */

#define NG_GRE_DEBUG_NONE   		0x00

/* for fastpath, shared by this node and etherbridge node */
#define PROTO_TAG_NAME "proto"

/* for linux, shared by this node and etherbridge node*/
#define PROTO_CB_MAGIC 0x19820526

/*************************************************************
 * Constants and definitions for GRE specific to NETGRAPH
 *************************************************************/

/* Node configuration structure */
struct ng_gre_config {
	uint8_t	debugLevel;	/* debug features */
	uint8_t greHasCksum;    /* GRE checksum bit */
	uint8_t greHasKey;      /* GRE key bit is set */
	uint8_t greRecvAnyKey;  /* rcv the msg even if key is different */
	uint8_t greKeyMtag;     /* Use m_tags/cmsg to carry the key */
	uint8_t greProtoMtag;   /* Use m_tags/cb to carry the ethertype (can be 0, 1 or 2, see below) */
	uint32_t greKey;	/* Value of the key (host order in message, but network order in conf) */
};

/* Configuration info */
#define NG_GRE_CONFIG_TYPE_INFO	{					\
	{ "debugLevel",		&ng_parse_uint8_type, 0	},		\
	{ "greHasCksum",	&ng_parse_uint8_type, 0	},		\
	{ "greHasKey",		&ng_parse_uint8_type, 0	},		\
	{ "greRecvAnyKey",	&ng_parse_uint8_type, 0	},		\
	{ "greKeyMtag",		&ng_parse_uint8_type, 0	},		\
	{ "greProtoMtag",	&ng_parse_uint8_type, 0	},		\
	{ "greKey",		&ng_parse_uint32_type, 0},		\
	{ NULL, NULL, 0 }						\
}

/* Statistics structure */
struct ng_gre_stats {
	uint64_t	numPktsEnc;		/* Number of pkts encapsulated */
	uint64_t	numPktsDec;		/* Number of pkts de-encapsulated */
	uint64_t	numPktsTooBig;		/* Number of packets too big */
	uint64_t	numMemErr;		/* Number of memory errors */
	uint64_t	numChksmErr;		/* Number of checksum errors */
	uint64_t	numKeyErr;		/* Number of bad key received */
};

/* Statistics info */
#define NG_GRE_STATS_TYPE_INFO {					\
	  { "numPktsEnc",	&ng_parse_uint64_type, 0 	},		\
	  { "numPktsDec",	&ng_parse_uint64_type, 0	},		\
	  { "numPktsTooBig",	&ng_parse_uint64_type, 0	},		\
	  { "numMemErr",	&ng_parse_uint64_type, 0	},		\
	  { "numChksmErr",	&ng_parse_uint64_type, 0	},		\
	  { "numKeyErr",	&ng_parse_uint64_type, 0	},		\
	  { NULL, NULL, 0 }							\
}

/* Netgraph control messages */
enum
{
	/* Node specific commands */
	NGM_GRE_SET_CONFIG = 1,			/* set node configuration */
	NGM_GRE_GET_CONFIG,			/* get node configuration */

	NGM_GRE_GET_STATS,			/* get node stats */
	NGM_GRE_CLR_STATS,			/* clear node stats */
	NGM_GRE_GETCLR_STATS,			/* atomically get & clear node stats */

	/* Link specific commands */
	/* [none] */
};

/*************************************************************
 * Constants and definitions specific to GRE
 *************************************************************/

#define NG_GRE_HDRLEN_NOCKSUM		4
#define NG_GRE_VERSION			0

#define NG_GRE_CKSUM_ENABLE		1
#define NG_GRE_CKSUM_DISABLE		0

#define NG_GRE_KEY_ENABLE		1
#define NG_GRE_KEY_DISABLE		0

#define NG_GRE_PROTO_MTAG_DISABLE	0
#define NG_GRE_PROTO_MTAG_KEYN_ONLY	1
#define NG_GRE_PROTO_MTAG_ALL_HOOKS	2

#define IP_PROTO_TYPE   		0x0800
#define IP6_PROTO_TYPE  		0x86DD

#define NG_GRE_TAG_NAME         "grekey"

#ifdef GRE_DEBUGGING
#define HOPE printk(KERN_INFO "Function - %s, Line - %d\n", __FUNCTION__, __LINE__);
#endif

#if defined(CONFIG_VNB_GRE_HASHTABLE_ORDER)
#define NG_GRE_HASHTABLE_ORDER  CONFIG_VNB_GRE_HASHTABLE_ORDER
#else
#define NG_GRE_HASHTABLE_ORDER 	10
#endif
#define NG_GRE_HASHTABLE_SIZE  	(1<<NG_GRE_HASHTABLE_ORDER)
#define NG_GRE_HASHTABLE_MASK  	(NG_GRE_HASHTABLE_SIZE-1)

/* return the HASHTABLE_ORDER last bits */
#define NG_GRE_TAG_R(tag)		((tag) & NG_GRE_HASHTABLE_MASK)

#define GRE_BUCKET(tag)		(&priv->bucket[NG_GRE_TAG_R((tag))])

#endif /* _NETGRAPH_NG_GRE_H_ */
