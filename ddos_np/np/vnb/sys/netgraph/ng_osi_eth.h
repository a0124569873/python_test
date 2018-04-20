/*
 * Copyright 2007-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_OSI_ETH_H_
#define _NETGRAPH_NG_OSI_ETH_H_

/* Node type name and magic cookie */
#define NG_OSI_ETH_NODE_TYPE               "osi_eth"
#define NGM_OSI_ETH_COOKIE                 249048132

/* Hook names */
#define NG_OSI_ETH_HOOK_LOWER        "lower"    /* the lower hook */
#define NG_OSI_ETH_HOOK_UPPER        "upper"    /* the upper hook */
#define NG_OSI_ETH_HOOK_DAEMON       "daemon"

/* OSI ethertype */
#define NLPID_ES_HELLO		0x82

#define LLC_DSAP		0xfe
#define LLC_SSAP		0xfe
#define LLC_CTRL		0x03
#define LLC_SIZE 		3

/* Netgraph control messages */
enum
{
	/* Node specific commands */
	NGM_OSI_ETH_SET_CONFIG = 1,	/* set node configuration */
	NGM_OSI_ETH_GET_CONFIG,		/* get node configuration */
#ifdef DEBUG_ETH
	NGM_OSI_ETH_SET_DST,		/* Set DST mac @ (test only) */
#endif
	NGM_OSI_ETH_ADD_ES,
	NGM_OSI_ETH_DEL_ES,
	NGM_OSI_ETH_ADD_IS,
	NGM_OSI_ETH_DEL_IS,
	NGM_OSI_ETH_ADD_RD,
	NGM_OSI_ETH_DEL_RD,
};

/* Node configuration structure */
struct ng_osi_eth_config {
        u_char         debug;                  /* debug features */
};
#define NG_OSI_ETH_DEBUG_NONE   0x00
#define NG_OSI_ETH_DEBUG_HEADER 0x01
/* Keep this in sync with the above structure definition */
#define NG_OSI_CONFIG_TYPE_INFO {				\
	{ "debugLevel", &ng_parse_uint8_type    },		\
	{ NULL }						\
}

#ifdef DEBUG_ETH
/* Set MAC addr structure */
struct ng_osi_eth_addr {
    u_char oct0;
    u_char oct1;
    u_char oct2;
    u_char oct3;
    u_char oct4;
    u_char oct5;
} __attribute ((packed));
/* Keep this in sync with the above structure definition */
#define NG_OSI_ETH_ADDR_FIELDS	{				\
	{ "oct0",		&ng_parse_int8_type	},	\
	{ "oct1",		&ng_parse_int8_type	},	\
	{ "oct2",		&ng_parse_int8_type	},	\
	{ "oct3",		&ng_parse_int8_type	},	\
	{ "oct4",		&ng_parse_int8_type	},	\
	{ "oct5",		&ng_parse_int8_type	},	\
	{ NULL }						\
}
#endif

struct ng_osi_eth_osi {
  u_char   ngoe_osi_len;
  u_char   ngoe_osi_val [MAX_OSI_LEN];
} __attribute__((packed));
#define NG_OSI_ETH_OSI_FIELDS {				\
	{ "osilen",		&ng_parse_int8_type	},	\
	{ "osi0",		&ng_parse_int8_type	},	\
	{ "osi1",		&ng_parse_int8_type	},	\
	{ "osi2",		&ng_parse_int8_type	},	\
	{ "osi3",		&ng_parse_int8_type	},	\
	{ "osi4",		&ng_parse_int8_type	},	\
	{ "osi5",		&ng_parse_int8_type	},	\
	{ "osi6",		&ng_parse_int8_type	},	\
	{ "osi7",		&ng_parse_int8_type	},	\
	{ "osi8",		&ng_parse_int8_type	},	\
	{ "osi9",		&ng_parse_int8_type	},	\
	{ "osi10",		&ng_parse_int8_type	},	\
	{ "osi11",		&ng_parse_int8_type	},	\
	{ "osi12",		&ng_parse_int8_type	},	\
	{ "osi13",		&ng_parse_int8_type	},	\
	{ "osi14",		&ng_parse_int8_type	},	\
	{ "osi15",		&ng_parse_int8_type	},	\
	{ "osi16",		&ng_parse_int8_type	},	\
	{ "osi17",		&ng_parse_int8_type	},	\
	{ "osi18",		&ng_parse_int8_type	},	\
	{ "osi19",		&ng_parse_int8_type	},	\
	{ NULL }						\
}

/* Set @mac--@es/@is/@rd mapping */
struct ng_osi_eth_resol {
	u_char ngoe_osi_len;
	u_char ngoe_osi_val[MAX_OSI_LEN];
	u_char ngoe_mac_val[VNB_ETHER_ADDR_LEN];
} __attribute ((packed));
#define NG_OSI_ETH_RESOL_FIELDS {				\
	{ "osilen",		&ng_parse_int8_type	},	\
	{ "osi0",		&ng_parse_int8_type	},	\
	{ "osi1",		&ng_parse_int8_type	},	\
	{ "osi2",		&ng_parse_int8_type	},	\
	{ "osi3",		&ng_parse_int8_type	},	\
	{ "osi4",		&ng_parse_int8_type	},	\
	{ "osi5",		&ng_parse_int8_type	},	\
	{ "osi6",		&ng_parse_int8_type	},	\
	{ "osi7",		&ng_parse_int8_type	},	\
	{ "osi8",		&ng_parse_int8_type	},	\
	{ "osi9",		&ng_parse_int8_type	},	\
	{ "osi10",		&ng_parse_int8_type	},	\
	{ "osi11",		&ng_parse_int8_type	},	\
	{ "osi12",		&ng_parse_int8_type	},	\
	{ "osi13",		&ng_parse_int8_type	},	\
	{ "osi14",		&ng_parse_int8_type	},	\
	{ "osi15",		&ng_parse_int8_type	},	\
	{ "osi16",		&ng_parse_int8_type	},	\
	{ "osi17",		&ng_parse_int8_type	},	\
	{ "osi18",		&ng_parse_int8_type	},	\
	{ "osi19",		&ng_parse_int8_type	},	\
	{ "mac0",		&ng_parse_int8_type	},	\
	{ "mac1",		&ng_parse_int8_type	},	\
	{ "mac2",		&ng_parse_int8_type	},	\
	{ "mac3",		&ng_parse_int8_type	},	\
	{ "mac4",		&ng_parse_int8_type	},	\
	{ "mac5",		&ng_parse_int8_type	},	\
	{ NULL }						\
}
#endif /* _NETGRAPH_NG_OSI_ETH_H_ */

