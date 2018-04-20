/*
 * Copyright  2003-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_MPLS_ETHER_H_
#define _NETGRAPH_NG_MPLS_ETHER_H_

/* Node type name */
#define NG_MPLS_ETHER_NODE_TYPE		"mpls_ether"
#define NG_MPLS_TYPE                    0x8847
#define NGM_MPLS_ETHER_COOKIE           9424777	/* node value : 3*pi number
						 * value for example */

/* Hook names */
#define NG_MPLS_HOOK_ETHER_IN_PREFIX	"ether_in_"	/* incoming hooks */
#define NG_MPLS_HOOK_ETHER_OUT		"ether_out"	/* outgoing hook */

/*  Node configuration structure
 * Be aware that use of ng_ether_enaddr_type makes impossible
 * to put another field in that structure because of parser
 * try to make it possible !
 */

struct ng_mpls_ether_config {
	u_char  edst[VNB_ETHER_ADDR_LEN];	/* Destination MAC @ */
	u_int16_t mtu;	/* Max transmission unit of mpls tunnel's lower link layer */
};

/* Keep this in sync with the above structure definition */
#define NG_MPLS_ETHER_CONFIG_TYPE_INFO {        	\
	{ "edst",	&ng_ether_enaddr_type, 0 },	\
	{ "mtu",	&ng_parse_uint16_type, 0 },	\
	{ NULL, NULL, 0 }				\
  }

/* Statistics structure */
struct ng_mpls_ether_stats {
	uint64_t        recvOctets;	/* total octets rec'd */
	uint64_t        recvPackets;	/* total pkts rec'd */
	uint64_t        xmitOctets;	/* total octets xmit'd */
	uint64_t        xmitPackets;	/* total pkts xmit'd */
	uint64_t        memoryFailures;	/* prepend failed, etc */
	uint64_t        discarded;	/* Invalid treatment discard packets */
};

/* Keep this in sync with the above structure definition */
#define NG_MPLS_ETHER_STATS_TYPE_INFO {		                        \
	  { "recvOctets",	&ng_parse_uint64_type,	0	},	\
	  { "recvPackets",	&ng_parse_uint64_type,	0	},	\
	  { "xmitOctets",	&ng_parse_uint64_type,	0	},	\
	  { "xmitPackets",	&ng_parse_uint64_type,	0	},	\
	  { "memoryFailures",   &ng_parse_uint64_type,	0	},	\
	  { "discarded",	&ng_parse_uint64_type,	0   	},	\
	  { NULL,		NULL,			0 	}	\
}

/* Netgraph control messages */
enum {
	/* Node specific commands */
	NGM_MPLS_ETHER_GET_ENADDR = 1,	/* get Ethernet address */
	NGM_MPLS_ETHER_SET_ENADDR,	/* set Ethernet address */
	NGM_MPLS_ETHER_GET_MTU,	        /* get Max transmission unit of
					   mpls tunnel's lower link layer */
	NGM_MPLS_ETHER_SET_MTU,	        /* set Max transmission unit of
					   mpls tunnel's lower link layer */
	NGM_MPLS_ETHER_GET_STATS,	/* get node stats */
	NGM_MPLS_ETHER_CLR_STATS,	/* clear node stats */
	NGM_MPLS_ETHER_GETCLR_STATS,	/* atomically get & clear
					 * node stats */
};

#endif
