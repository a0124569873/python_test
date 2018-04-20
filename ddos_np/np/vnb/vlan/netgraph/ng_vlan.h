/*
 * Copyright  2003-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_VLAN_H_
#define _NETGRAPH_NG_VLAN_H_

#ifdef __FastPath__
int ng_vlan_init(void);
#endif

/* Node type name and magic cookie */
#define NG_VLAN_NODE_TYPE		"vlan"
#define NGM_VLAN_COOKIE			1011392491

/* Hook names */
#define NG_VLAN_HOOK_LOWER        "lower"    /* the lower hook */
#define NG_VLAN_HOOK_LINK_PREFIX  "link_"    /* append decimal integer */
#define NG_VLAN_HOOK_LINK_FMT     "link_%d"  /* for use with printf(3),
                                                %d is the tag           */
#define NG_VLAN_HOOK_NOMATCH      "nomatch"  /* the unknown packets */
#define NG_VLAN_HOOK_ORPHANS      "orphans"  /* the unknown tags */

/* Node configuration structure */
struct ng_vlan_config {
	uint8_t		debug;			/* debug features */
};
#define NG_VLAN_DEBUG_NONE   0x00
#define NG_VLAN_DEBUG_HEADER 0x01

/* Keep this in sync with the above structure definition */
#define NG_VLAN_CONFIG_TYPE_INFO {				\
	{ "debugLevel",	&ng_parse_uint8_type, 0	},		\
	{ NULL, NULL, 0 }					\
	}

struct ng_vlan_dscp_table_msg {
	uint16_t 	vlan_tag;
	uint8_t 	dscp_to_priority[64];
};

#define NG_VLAN_DSCP_TABLE_MSG_INFO(ainfo) {		\
	{ "vlan_tag", 	&ng_parse_uint16_type, 0 },	\
	{ "dscp_to_priority", (ainfo), 0 },		\
	{ NULL, NULL, 0 }				\
	}

struct ng_vlan_nfmark_table_msg {
	uint16_t 	vlan_tag;
	uint8_t 	nfmark_to_priority[16];
};

#define NG_VLAN_NFMARK_TABLE_MSG_INFO(ainfo) {		\
	{ "vlan_tag", 	&ng_parse_uint16_type, 0 },	\
	{ "nfmark_to_priority", (ainfo), 0 },		\
	{ NULL, NULL, 0 }				\
	}

/* Statistics structure */
struct ng_vlan_stats {
	uint64_t	recvOctets;		/* total octets rec'd */
	uint64_t	recvPackets;	/* total pkts rec'd */
	uint64_t	recvRunts;		/* pkts rec'd less than vlan's header in bytes */
	uint64_t	recvInvalid;	/* pkts rec'd with bogus header */
	uint64_t	recvUnknownTag;	/* pkts rec'd with unknown tag. They are sent to orphans */
	uint64_t	xmitOctets;		/* total octets xmit'd */
	uint64_t	xmitPackets;	/* total pkts xmit'd */
	uint64_t	xmitDataTooBig;	/* Too bit packet xmit's, greater than 0x10000 */
	uint64_t	memoryFailures;	/* times couldn't get mem or mbuf */
};

/* Keep this in sync with the above structure definition */
#define NG_VLAN_STATS_TYPE_INFO	{						\
	  { "recvOctets",		&ng_parse_uint64_type, 0	},	\
	  { "recvPackets",		&ng_parse_uint64_type, 0	},	\
	  { "recvRunts",		&ng_parse_uint64_type, 0	},	\
	  { "recvInvalid",		&ng_parse_uint64_type, 0	},	\
	  { "recvUnknownTag",		&ng_parse_uint64_type, 0	},	\
	  { "xmitOctets",		&ng_parse_uint64_type, 0	},	\
	  { "xmitPackets",		&ng_parse_uint64_type, 0	},	\
	  { "xmitDataTooBig",		&ng_parse_uint64_type, 0	},	\
	  { "memoryFailures",		&ng_parse_uint64_type, 0	},	\
	  { NULL, NULL, 0 }						\
}

/* Netgraph control messages */
enum {
	/*
	 * Node specific commands
	 */
	NGM_VLAN_SET_CONFIG = 1,	/* set node configuration */
	NGM_VLAN_GET_CONFIG,		/* get node configuration */

	NGM_VLAN_GET_STATS,			/* get node stats */
	NGM_VLAN_CLR_STATS,			/* clear node stats */
	NGM_VLAN_GETCLR_STATS,		/* atomically get & clear node stats */

	/*
	 * Link specific commands
	 */
	NGM_VLAN_DSCP_ENABLE,
	NGM_VLAN_DSCP_DISABLE,
	NGM_VLAN_DSCP_SET_TABLE,
	NGM_VLAN_DSCP_GET_TABLE,
	NGM_VLAN_NFMARK_ENABLE,
	NGM_VLAN_NFMARK_DISABLE,
	NGM_VLAN_NFMARK_SET_TABLE,
	NGM_VLAN_NFMARK_GET_TABLE,
	NGM_VLAN_NFMARK_GET_INGRESS_KTABLE,
	NGM_VLAN_NFMARK_SET_INGRESS_KTABLE};

/*************************************************************
 * Constants and definitions specific to VLAN
 *************************************************************/

#define NG_VLAN_MAX_TAG		4095
#define NG_VLAN_TAG_ANY		0xffff
#define NG_VLAN_ENCAPLEN	4		/* length in bytes of encapsulation */

#define IP_ETHER_TYPE   	0x0800
#define VLAN_ETHER_TYPE   	0x8100
#define IP6_ETHER_TYPE  	0x86dd

#define NG_VLAN_TAG_NAME        "vlanpri"

#endif /* _NETGRAPH_NG_VLAN_H_ */

