/*
 * Copyright 2007-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_OSI_TUN_H_
#define _NETGRAPH_NG_OSI_TUN_H_

/* Node type name and magic cookie */
#define NG_OSI_TUN_NODE_TYPE               "osi_tun"
#define NGM_OSI_TUN_COOKIE                 224148831
#define NG_OSI_TUN_MAX_TAG			15

#define CLNP_VID				0x01
#define CLNP_TTL_UNITS				2  /* 500 millisec*/
#define CLNP_TTL				64*CLNP_TTL_UNITS  /*sec*/
#define CLNP_SPI_IP				0xcc
#define CLNP_SEL_OSI				0x01
#define CLNP_SEL_NONOSI				0x00
#define CLNP_CKSUM_OFF				0x07

/* Hook names */
#define NG_OSI_TUN_HOOK_LOWER        "lower"    /* the lower hook */
#define NG_OSI_TUN_HOOK_LINK_PREFIX  "link_"    /* append decimal integer */
#define NG_OSI_TUN_HOOK_LINK_FMT     "link_%d"  /* for use with printf(3)
						%d is the tag */
/* Node configuration structure */
struct ng_osi_tun_config {
        u_char         debug;                  /* debug features */
};
#define NG_OSI_TUN_DEBUG_NONE   0x00
#define NG_OSI_TUN_DEBUG_HEADER 0x01
/* Keep this in sync with the above structure definition */
#define NG_OSI_CONFIG_TYPE_INFO {				\
        { "debugLevel", &ng_parse_uint8_type    },              \
        { NULL } \
}

#define MAX_OSI_LEN				20
struct ng_osi_tun_addr {
	uint8_t tunnel_id;
	u_char len;
	u_char oct[MAX_OSI_LEN];
} __attribute__ ((packed));
#define NG_OSI_TUN_ADDR_FIELDS {				\
        { "tunid", &ng_parse_uint8_type    },              \
        { "osilen", &ng_parse_uint8_type    },              \
        { "osi0", &ng_parse_uint8_type    },              \
        { "osi1", &ng_parse_uint8_type    },              \
        { "osi2", &ng_parse_uint8_type    },              \
        { "osi3", &ng_parse_uint8_type    },              \
        { "osi4", &ng_parse_uint8_type    },              \
        { "osi5", &ng_parse_uint8_type    },              \
        { "osi6", &ng_parse_uint8_type    },              \
        { "osi7", &ng_parse_uint8_type    },              \
        { "osi8", &ng_parse_uint8_type    },              \
        { "osi9", &ng_parse_uint8_type    },              \
        { "osi10", &ng_parse_uint8_type    },              \
        { "osi11", &ng_parse_uint8_type    },              \
        { "osi12", &ng_parse_uint8_type    },              \
        { "osi13", &ng_parse_uint8_type    },              \
        { "osi14", &ng_parse_uint8_type    },              \
        { "osi15", &ng_parse_uint8_type    },              \
        { "osi16", &ng_parse_uint8_type    },              \
        { "osi17", &ng_parse_uint8_type    },              \
        { "osi18", &ng_parse_uint8_type    },              \
        { "osi19", &ng_parse_uint8_type    },              \
        { NULL } \
}

/* Netgraph control messages */
enum
{
	/* Node specific commands */
	NGM_OSI_TUN_SET_CONFIG = 1,      /* set node configuration */
	NGM_OSI_TUN_GET_CONFIG,          /* get node configuration */
	NGM_OSI_TUN_SET_OSI_REMOTE,        /* set osi relote addr */
	NGM_OSI_TUN_SET_OSI_LOCAL,	/* set osi local addr */
};


#endif /* _NETGRAPH_NG_OSI_TUN_H_ */

