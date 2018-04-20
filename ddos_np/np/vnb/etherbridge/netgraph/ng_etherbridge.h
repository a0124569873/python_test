/*
 * Copyright 2009-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_ETHERBRIDGE_H
#define _NETGRAPH_NG_ETHERBRIDGE_H

#ifdef __FastPath__
int ng_etherbridge_init(void);
#endif

/* Node type name */
#define NG_ETHERBRIDGE_NODE_TYPE	"etherbridge"
#define NGM_ETHERBRIDGE_COOKIE		20090917

/* Hook names. Any other hook name is allowed and is considered as a
 * "demux" hook. */
#define NG_ETHERBRIDGE_HOOK_MUX		"mux"		/* the mux hook */
#define NG_ETHERBRIDGE_HOOK_ORPHANS     "orphans"	/* the unknown tags */

/* for fastpath, shared by this node and gre node */
#define PROTO_TAG_NAME "proto"

/* for linux, shared by this node and gre node*/
#define PROTO_CB_MAGIC 0x19820526

/* Node configuration structure */
struct ng_etherbridge_config {
    uint8_t         debugFlag;	/* debug features */
    uint16_t         tcp4mss;
    uint16_t         tcp6mss;
};

#define NG_ETHERBRIDGE_DEBUG_NONE       0x00
#define NG_ETHERBRIDGE_DEBUG_CONFMSG    0x01
#define NG_ETHERBRIDGE_DEBUG_RCV_MUX    0x02
#define NG_ETHERBRIDGE_DEBUG_RCV_DEMUX  0x04

/* Keep this in sync with the above structure definition */
#define NG_ETHERBRIDGE_CONFIG_TYPE_INFO {		\
	{ "debugFlag", &ng_parse_uint8_type, 0 },	\
	{ "tcp4mss", &ng_parse_uint16_type, 0 },	\
	{ "tcp6mss", &ng_parse_uint16_type, 0 },	\
	{ NULL, NULL, 0 }				\
}


/* Statistics structure */
struct ng_etherbridge_stats {
    uint64_t        recvOctets;		/* total octets rec'd */
    uint64_t        recvPackets;	/* total pkts rec'd */
    uint64_t        recvRunts;	 	/* pkts rec'd less than ether + vlan header in bytes */
    uint64_t        recvPrependErr;	/* pkts rec'd without enough headroom */
    uint64_t	    xmitOctets;		/* total Octets transmited */
    uint64_t	    xmitPackets;	/* total pkts transmited */
};

/* Keep this in sync with the above structure definition */
#define NG_ETHERBRIDGE_STATS_TYPE_INFO {				\
	{ "recvOctets",	    &ng_parse_uint64_type,	0	},	\
	{ "recvPackets",    &ng_parse_uint64_type,	0	},	\
	{ "recvRunts",      &ng_parse_uint64_type,	0	},	\
	{ "recvPrependErr", &ng_parse_uint64_type,	0	},	\
	{ "xmitOctets",     &ng_parse_uint64_type,	0   	},	\
	{ "xmitPackets",    &ng_parse_uint64_type,	0	},	\
	{ NULL,		NULL,			0	}		\
}



struct ng_etherbridge_hookconfig {
	char    hookname[NG_HOOKLEN + 1];  /* hookname */
	uint8_t write_src_mac;     /* overrides src mac addr at xmit */
	uint8_t src_mac[VNB_ETHER_ADDR_LEN]; /* source mac address to use */
	uint8_t write_dst_mac;     /* overrides dst mac addr at xmit */
	uint8_t dst_mac[VNB_ETHER_ADDR_LEN]; /* destination mac address to use */
	uint8_t use_vlan;          /* true if we want to use following vlan */
	uint16_t vlan;             /* vlan ID to use */
	uint8_t inc_mac_header;    /* true if mac header is included on demux side */
};

/* keep it sync with struct above */
#define NG_ETHERBRIDGE_HOOKCONFIG_TYPE_INFO {				\
	{ "hookname", &ng_parse_hookbuf_type, 0 },			\
	{ "write_src_mac", &ng_parse_uint8_type, 0 },			\
	{ "src_mac", 	&ng_ether_enaddr_type, 0 },			\
	{ "write_dst_mac", &ng_parse_uint8_type, 0 },			\
	{ "dst_mac", 	&ng_ether_enaddr_type, 0 },			\
	{ "use_vlan", &ng_parse_uint8_type, 0 },			\
	{ "vlan", &ng_parse_uint16_type, 0 },				\
	{ "inc_mac_header", &ng_parse_uint8_type, 0 },			\
	{ NULL, NULL, 0 }						\
}


/* Netgraph control messages */
enum {
    /*
     * Node specific commands
     */
    NGM_ETHERBRIDGE_GET_CONFIG = 1,	/* get node configuration */
    NGM_ETHERBRIDGE_SET_CONFIG,	/* set node configuration */

    /*
     * Link specific commands
     */

    NGM_ETHERBRIDGE_GET_STATS,	/* get node stats */
    NGM_ETHERBRIDGE_CLR_STATS,	/* clear node stats */
    NGM_ETHERBRIDGE_GETCLR_STATS,	/* atomically get & clear node stats */

    NGM_ETHERBRIDGE_GET_HOOK_CONFIG,
    NGM_ETHERBRIDGE_SET_HOOK_CONFIG,
};

#endif
