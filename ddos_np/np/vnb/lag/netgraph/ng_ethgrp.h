/*
 * Copyright 2007-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_ETH_GRP_H_
#define _NETGRAPH_NG_ETH_GRP_H_

/* Node type name and magic cookie */
#define NG_ETH_GRP_NODE_TYPE             "ethgrp"
#define NGM_ETH_GRP_COOKIE               832617240

/* Hook names */
#define NG_ETH_GRP_HOOK_LINK_PREFIX      "link_"   /* append decimal integer */
#define NG_ETH_GRP_HOOK_LINK_FMT         "link_%d" /* for use with printf(3) */
#define NG_ETH_GRP_LACP_HOOK             "lacp"
#define NG_ETH_GRP_UPPER_HOOK            "upper"

/* Maximum number of supported links */
#define NG_ETH_GRP_MAX_LINKS             32

/* Sending Algo*/
#define NG_ETH_GRP_ALGO_ROUND_ROBIN      0x20001
#define NG_ETH_GRP_ALGO_XOR_MAC          0x20002
#define NG_ETH_GRP_ALGO_XOR_IP           0x20003
#define NG_ETH_GRP_ALGO_BACKUP           0x20004
#define NG_ETH_GRP_ALGO_XOR_IP_PORT      0x20005
#define NG_ETH_GRP_ALGO_NAME_MAX         15
#define NG_ETH_GRP_RATE_NAME_MAX         15

/* Keep this in sync with the above structure definition */
#define NG_ETH_GRP_CONFIG_TYPE_INFO {               \
          { "debugLevel",       &ng_parse_uint8_type,       0 },      \
          { NULL, NULL, 0 }                                           \
}
/* Node configuration structure */
struct ng_ethgrp_config {
        u_char          debugLevel;             /* debug level */
};

#define NG_ETH_GRP_MODE_NAME_MAX        10
#define NG_ETH_GRP_HOOK_INACTIVE         0 /* default mode */
#define NG_ETH_GRP_HOOK_ACTIVE           1
#define NG_ETH_GRP_SET_HOOK_MODE_INFO {\
          { "id",       &ng_parse_uint32_type,       0 },     \
          { "mode",       &ng_parse_uint32_type,       0 },   \
          { NULL, NULL, 0 }                                   \
}
struct ng_ethgrp_set_hook_mode {
        u_int32_t       id;
        u_int32_t       mode;
};

#define NG_ETH_GRP_GET_HOOK_INFO {\
          { "id",       &ng_parse_uint32_type,       0 },      \
          { NULL, NULL, 0 }                                    \
}
struct ng_ethgrp_get_hook {
        u_int32_t          id;
};

/* Priority*/
#define NG_ETH_GRP_DEFAULT_PRIO          32768
#define NG_ETH_GRP_MAX_PRIO              65535
#define NG_ETH_GRP_MIN_PRIO              0
struct ng_ethgrp_set_hook_prio {
        u_int32_t       id;
        u_int32_t       priority;
};

#define NG_ETH_GRP_GET_HOOK_PRIO_INFO {\
          { "id",       &ng_parse_uint32_type,       0 },     \
          { "prio",       &ng_parse_uint32_type,       0 },   \
          { NULL, NULL, 0 }                                   \
}
/* Netgraph control messages */
enum {
        NGM_ETH_GRP_SET_CONFIG = 1,      /* set node configuration */
        NGM_ETH_GRP_GET_CONFIG,          /* get node configuration */
        NGM_ETH_GRP_SET_HOOK_MODE,
        NGM_ETH_GRP_GET_HOOK_MODE,
        NGM_ETH_GRP_SET_ALGO,
        NGM_ETH_GRP_GET_ALGO,
        NGM_ETH_GRP_SET_HOOK_PRIO,
        NGM_ETH_GRP_GET_HOOK_PRIO,
        NGM_ETH_GRP_SET_ENADDR,		/* set Ethernet address */
        NGM_ETH_GRP_GET_ENADDR,		/* get Ethernet address */
};

struct ng_lacp_msg {
	u_int16_t	ngr_cmd;
		/* Packet (LACPDU) from node to daemon */
#		define    NGR_RECV_SLOWP_MSG            0x81
	u_int16_t	ngr_port;
	u_int16_t	ngr_len;	/* Length of data following, if any */

	char		ngr_name[NG_NODELEN + 1];
} __attribute__((packed)) ;

/* in old kernels (< 2.6.17), ETH_P_SLOW is not defined */
#ifndef ETH_P_SLOW
#define ETH_P_SLOW	0x8809
#endif
/* conventional multicast address for slow protocols */
static const unsigned char slowp_mc_addr[VNB_ETHER_ADDR_LEN] = { 0x01,0x80,0xc2,0x00,0x00,0x02 };

#endif /* _NETGRAPH_NG_ETH_GRP_H_ */
