/*
 * Copyright (c) 2004, 2006, 2013 6WIND
 */

#ifndef __FPC_API__
#define __FPC_API__

#include <netinet/in.h> /* in_addr, in6_addr */
/*
 * Interface name max size.
 * if interface name is shorter, it will be padded with \0
 * MUST be aligned on 4 bytes boundary
 */
#define CM_IFNAMSIZE    16
#define CM_PORTNAMSIZE  CM_IFNAMSIZE
#define CM_MACMAXSIZE   32
#define CM_OPAQUESIZE   32
#define CM_ETHMACSIZE   6

/*
 * interface types
 * see http://www.iana.org/assignments/ianaiftype-mib
 */
#define CM_IFTYPE_OTHER      1 /* unused */
#define CM_IFTYPE_ETH        6
#define CM_IFTYPE_LOOP       24
/* XXX the values are not defined by the IANA yet */
#define CM_IFTYPE_CTU        241
#define CM_IFTYPE_6IN4       CM_IFTYPE_CTU
#define CM_IFTYPE_XIN4       CM_IFTYPE_CTU
#define CM_IFTYPE_STU        242
#define CM_IFTYPE_XIN6       CM_IFTYPE_STU
#define CM_IFTYPE_LOCAL      244
#define CM_IFTYPE_PORT       245
#define CM_IFTYPE_SVTI       246
#define CM_IFTYPE_VTI        248
#define CM_IFTYPE_BRPORT     249
#define CM_IFTYPE_GRE        250

/*
 * interface subtypes
 */

#define CM_IFSUBTYPE_NORMAL    0
#define CM_IFSUBTYPE_NGEIFACE  1
#define CM_IFSUBTYPE_XVRF      2
#define CM_IFSUBTYPE_VXLAN     3
#define CM_IFSUBTYPE_VLAN      4
#define CM_IFSUBTYPE_BRIDGE    5
#define CM_IFSUBTYPE_BONDING   6
#define CM_IFSUBTYPE_MACVLAN   7
#define CM_IFSUBTYPE_VETH      8
#define CM_IFSUBTYPE_GRETAP    9

/*
 * interface flags: MUST be in the lower 12 bits, hence
 * letting upper 4 bits for FP locally defined flags.
 * Keep in sync with fp-if.h
 * used by struct cp_iface_state.cpiface_state
 */
#define CM_CPIFACE_IFF_MASK             0x00ff
#define CM_CPIFACE_IFFUP                0x0001   /* Interface is up      */
#define CM_CPIFACE_IFFRUNNING           0x0002   /* Interface is running */
#define CM_CPIFACE_IFFPREFERRED         0x0004   /* Preferred interface for ECMP */
#define CM_CPIFACE_IFFPROMISC           0x0010   /* Receive all packets  */
#define CM_CPIFACE_IFFFWD_IPV4          0x0020   /* Forward IPv4 packets */
#define CM_CPIFACE_IFFFWD_IPV6          0x0040   /* Forward IPv6 packets */
#define CM_CPIFACE_IFFRPF_IPV4          0x0080   /* IPv4 RPF check */

/*
 * L2 States
 */
#define CM_L2STATE_NONE          1  /* Delete the entry */
#define CM_L2STATE_STALE         2  /* Enter STALE state, i.e hit flag mngt */
#define CM_L2STATE_REACHABLE     3  /* Add/Update the entry */
#define CM_L2STATE_INCOMPLETE    4  /* Enter INCOMPLETE state, resolution is in progress */

/*
 * Next Hop type definition
 */
#define NH_TYPE_BASIC          1 /* Routing prot or static routes */
#define NH_TYPE_CONNECTED      2 /* Connected on an interface     */
#define NH_TYPE_LOCAL_DELIVERY 3 /*
                                  * Send packet to Slow Path, will
                                  * also be used for REJECT routes
                                  */
#define NH_TYPE_BLACK_HOLE     4 /* Drop Packet                   */

#define CM_BULK_MIGRATE_BY_BLADE_ID 1

struct nh_mark {
	u_int32_t        mark;
	u_int32_t        mask;
};

/*
 *==============================================================
 *  UNIX socket "well-known" name
 *==============================================================
 */
#define  CPS_UNIX_PATH       "/tmp/.cpipc"
#define  DEFAULT_CM_PATH_OLD "/var/tmp/.cmgrd"
#define  DEFAULT_CM_PATH     CPS_UNIX_PATH

/*
 *==============================================================
 * Common header for messages sent from the CM
 * to CPDPs on the UNIX socket
 *==============================================================
 */
struct cp_hdr {
	u_int32_t cphdr_type;    /* Message type                              */
	u_int32_t cphdr_report;  /* Desired report                            */
	u_int32_t cphdr_cookie;  /* network order opaque cookie               */
	u_int32_t cphdr_length;  /* This length does NOT include common header*/
};
/*
 * Note: this header is also used to provide error response (if any) from
 *       CPDPs to CM, with the very same command that caused the error
 *       (i.e. with full parameters)
 */

#define  CMCPDP_ERROR_RESEND_MASK      0x10000000
/*
 * TRUE when retransmit
 * FALSE when retransmit is not required
 */
#define  CMCPDP_ERROR_RESEND(error)    ((error) & CMCPDP_ERROR_RESEND_MASK)
#define  CMCPDP_ERROR_ERROR(error)    ((error) & ~CMCPDP_ERROR_RESEND_MASK)


#define  CMD_FAMILY_MASK      0xFFFF0000
#define  CMD_SUBFAMILY_MASK   0xFFFFFF00

/*
 *==============================================================
 * SYSTEM messages
 *==============================================================
 */

#define CMD_SYS_BASE       0x000000

#define CMD_RESET          (CMD_SYS_BASE + 1)
struct cp_reset {
	u_int32_t   cp_reset_appid;  /* Application ID */
	u_int16_t   cp_reset_major;  /* API version, major */
	u_int16_t   cp_reset_minor;  /* API version, minor */
};

/* Application ID */
typedef enum SC_appid {
	Appid_MIN	=	0,
	Appid_NSM,
	Appid_MPLS,
	Appid_MC,
	Appid_ETH,
	Appid_CM,    /* Cache Manager */
	Appid_MAX
} SC_appid_t;

/*
 * Note: VERY SPECIAL COMMAND
 *       MUST be accepted and processed WITHOUT sn checking
 *       no parameter expected
 *       - flush ALL previous information/state
 *       - reset expected sn to 0
 *       ACK is MANDATORY
 */

#define CMD_FLUSH           (CMD_SYS_BASE + 2)

/*
 * Ask the fpm to switch in graceful restart or partial graceful
 * restart mode.
 */

#define CMD_GRACEFUL_RESTART (CMD_SYS_BASE + 3)
#define CMD_GRACEFUL_DONE    (CMD_SYS_BASE + 4)

struct cp_graceful_restart {
#define CM_GR_TYPE_ALL       0xffff
#define CM_GR_TYPE_ROUTE     0x0001
#define CM_GR_TYPE_XFRM      0x0002
#define CM_GR_TYPE_NFTABLES  0x0004
#define CM_GR_TYPE_NFCPE     0x0008
#define CM_GR_TYPE_VNB       0x0010
#define CM_GR_TYPE_BLADE     0x0020
#define CM_GR_TYPE_AUDIT     0x0040
	u_int32_t gr_type; /* bitfield */
};

#define CMD_VRF_DELETE       (CMD_SYS_BASE + 5)

/*
 *==============================================================
 * INTERFACE messages
 *==============================================================
 */

#define CMD_INTERF_BASE       0x010000

/*
 *--------------------------------------------------------------
 * Parameters For All interfaces
 *--------------------------------------------------------------
 */
#define CMD_IF_BASE       CMD_INTERF_BASE  +  0x100

#define CMD_IF_CREATE    (CMD_IF_BASE + 1)
#define CMD_IF_DELETE    (CMD_IF_BASE + 2)
struct cp_iface_create {
	u_int32_t  cpiface_ifuid; /* KERNEL Interface Identifier   */
	u_int32_t  cpiface_vrfid;   /* Interface VRF ID */
	char       cpiface_ifname[CM_IFNAMSIZE]; /* sytem interface name */
	u_int32_t  cpiface_type;
	u_int32_t  cpiface_subtype;
	u_int32_t  cpiface_mtu;        /* Current Interface MTU    */
	union {
		u_int32_t  cpiface_vnb_nodeid; /* ng_ether node ID         */
		u_int8_t   cpiface_vnb_keep_node; /* don't destroy the ng_ether node */
	};
	u_int32_t  cpiface_maclen;  /* MAC address length             */
	u_int8_t   cpiface_mac[CM_MACMAXSIZE];
};

/*
 * Note: This message will be used for any physical interface, and for
 *       loopback interface. Tunnel-like interface have their own creation
 *       message
 */

#define CMD_IF_MTU       (CMD_IF_BASE + 3)
struct cp_iface_mtu {
	u_int32_t   cpiface_ifuid;   /* KERNEL Interface Identifier   */
	u_int32_t   cpiface_mtu;       /* New Interface MTU             */
};

#define CMD_IF_STATE_UPDATE (CMD_IF_BASE + 4)
struct cp_iface_state {
	u_int32_t   cpiface_ifuid;   /* KERNEL Interface Identifier   */
	u_int32_t   cpiface_state;     /* Interface status              */
};

#define CMD_IF_MAC       (CMD_IF_BASE + 5)
struct cp_iface_mac {
	u_int32_t   cpiface_ifuid;   /* KERNEL Interface Identifier   */
	u_int32_t   cpiface_maclen;  /* MAC address length             */
	u_int8_t    cpiface_mac[CM_MACMAXSIZE];
};

#define CMD_IF_BLADEINFO (CMD_IF_BASE + 6)
struct cp_iface_bladeinfo {
	u_int32_t   cpiface_ifuid;     /* local blade CP kernel ifuid */
	u_int8_t    cpiface_blade_id;    /* interface blade id */
};

#define CMD_IF_MASTER    (CMD_IF_BASE + 7)
struct cp_iface_master {
	u_int32_t   cpiface_ifuid;         /* Slave ifuid  */
	u_int32_t   cpiface_master_ifuid;  /* Master ifuid */
};

#define CMD_IF_VETH_PEER (CMD_IF_BASE + 8)
struct cp_iface_veth_peer {
	u_int32_t   cpveth_ifuid;       /* Interface unique identifier      */
	u_int32_t   cpveth_peer_ifuid;  /* peer interface unique identifier */
};

#define CM_BLADE_ALL    0xff
#define CM_BLADE_CP     0xfe

/*
 *--------------------------------------------------------------
 * Addresses For All interfaces
 *--------------------------------------------------------------
 */
#define CMD_IF_ADDR       CMD_INTERF_BASE  +  0x200

#define CMD_INTERFACE_IPV4_ADDR_ADD   (CMD_IF_ADDR + 1)
#define CMD_INTERFACE_IPV4_ADDR_DEL   (CMD_IF_ADDR + 2)
struct cp_iface_ipv4_addr {
	u_int32_t      cpiface_ifuid;/* KERNEL Interface Identifier     */
	struct in_addr cpiface_addr;   /* Address to add on the interface */
	u_int8_t       cpiface_pfxlen; /* Prefix length                   */
	u_int8_t       cpiface_reserved1;
	u_int8_t       cpiface_reserved2;
	u_int8_t       cpiface_reserved3;
};

#define CMD_INTERFACE_IPV6_ADDR_ADD   (CMD_IF_ADDR + 3)
#define CMD_INTERFACE_IPV6_ADDR_DEL   (CMD_IF_ADDR + 4)
struct cp_iface_ipv6_addr {
	u_int32_t       cpiface_ifuid;/* KERNEL Interface Identifier     */
	struct in6_addr cpiface_addr;   /* Address to add on the interface */
	u_int8_t        cpiface_pfxlen; /* Prefix length                   */
	u_int8_t        cpiface_reserved1;
	u_int8_t        cpiface_reserved2;
	u_int8_t        cpiface_reserved3;
};


/*
 *--------------------------------------------------------------
 * For tunnel interfaces
 *--------------------------------------------------------------
 */
#define CMD_TUN_BASE       CMD_INTERF_BASE  +  0x300
#define CMD_TUN_TTL      (CMD_TUN_BASE + 1)
struct cp_iface_ttl {
	u_int32_t   cpiface_ifuid;
	u_int8_t    cpiface_ttl;
#define cpiface_hoplimit cpiface_ttl
	u_int8_t    cpiface_reserved1;
	u_int8_t    cpiface_reserved2;
	u_int8_t    cpiface_reserved3;
};

#define CMD_TUN_TOS      (CMD_TUN_BASE + 2)
struct cp_iface_tos {
	u_int32_t   cpiface_ifuid;
	u_int8_t    cpiface_inh_tos; /* TOS inheritance flag       */
	u_int8_t    cpiface_tos;
	u_int8_t    cpiface_reserved1;
	u_int8_t    cpiface_reserved2;
};


/*
 *==============================================================
 * ROUTING messages
 *==============================================================
 */

#define CMD_ROUTE_BASE       0x020000

#define  CMD_ROUTE4_ADD      (CMD_ROUTE_BASE + 1)
#define  CMD_ROUTE4_DEL      (CMD_ROUTE_BASE + 2)
#define  CMD_ROUTE4_CHG      (CMD_ROUTE_BASE + 3)
struct cp_route4 {
	u_int32_t        cpr4_vrfid;    /* VRF ID                             */
	struct nh_mark   cpr4_nh_mark;  /* Next Hop Mark                      */
	struct in_addr   cpr4_prefix;   /* Destination prefix                 */
	struct in_addr   cpr4_mask;     /* Destination mask                   */
	u_int8_t         cpr4_nhtype;   /* Next Hop type (connected, ...)     */
	u_int8_t         cpr4_reserved1;/* Padding for 32 bit alignment       */
	u_int16_t        cpr4_reserved2;/* Padding for 32 bit alignment       */
	u_int32_t        cpr4_ifuid;  /* KERNEL interface identifier        */
	struct in_addr   cpr4_nexthop;  /* Gateway addr (src@ for Connected)  */
	u_int32_t        cpr4_mtu;      /* interface MTU                      */
};

#define  CMD_ROUTE6_ADD      (CMD_ROUTE_BASE + 4)
#define  CMD_ROUTE6_DEL      (CMD_ROUTE_BASE + 5)
struct cp_route6 {
	u_int32_t        cpr6_vrfid;    /* VRF ID                             */
	struct nh_mark   cpr6_nh_mark;  /* Next Hop Mark                      */
	struct in6_addr  cpr6_prefix;   /* Destination prefix                 */
	u_int8_t         cpr6_pfxlen;   /* Destination prefix len             */
	u_int8_t         cpr6_nhtype;   /* Next Hop type (connected, ...)     */
	u_int16_t        cpr6_reserved; /* Padding                            */
	u_int32_t        cpr6_ifuid;  /* KERNEL interface identifier        */
	struct in6_addr  cpr6_nexthop;  /* Gateway addr (src@ for Connected)  */
	u_int32_t        cpr6_mtu;      /* interface MTU                      */
};

/* _UPDATE is used to ADD and DEL */
#define CMD_ARP_UPDATE       (CMD_ROUTE_BASE + 6)
#define CMD_NDP_UPDATE       (CMD_ROUTE_BASE + 7)
struct cp_l2 {
	u_int32_t        cpl2_ifuid;              /* Interface Ifuid      */
	/*
	 * Not used anymore. The field is kept as placeholder
	 * for API bacwkard compatibility: 0 new API, !=0 old API
	 */
	u_int32_t        cpl2_uid_deprecated;
	u_int8_t         cpl2_state;                /* L2 State. Should be
						     * one among None, Stale
						     * or Reachable
						     */
	u_int8_t         reserved;
	u_int8_t         cpl2_mac[CM_MACMAXSIZE];   /* Mac Address          */
	union {
		struct in6_addr addr6;
		struct in_addr  addr4;
	} cpl2_ipaddr;                              /* IP Address           */
};
#define cpl2_ip4addr cpl2_ipaddr.addr4
#define cpl2_ip6addr cpl2_ipaddr.addr6

/*
 *==============================================================
 * IPv6 TRANSITION messages
 *==============================================================
 */

#define CMD_TRANS_BASE       0x030000

/*
 *--------------------------------------------------------------
 * Configured Tunnels
 *--------------------------------------------------------------
 */
#define  CMD_CFGTUN_BASE     (CMD_TRANS_BASE + 0x0100)

#define  CMD_XIN4_CREATE     (CMD_CFGTUN_BASE + 1)
#define  CMD_XIN4_DELETE     (CMD_CFGTUN_BASE + 2)
#define  CMD_XIN4_UPDATE     (CMD_CFGTUN_BASE + 3)
struct cp_xin4 {
	char             cpxin4_ifname[CM_IFNAMSIZE]; /* sytem interface name */
	u_int32_t        cpxin4_ifuid;      /* KERNEL interface identifier  */
	u_int32_t        cpxin4_vrfid;        /* Interface VRF ID */
	u_int32_t        cpxin4_linkvrfid;    /* Interface LINKVRF ID */
	u_int32_t        cpxin4_mtu;          /* Logical Interface MTU        */
	u_int8_t         cpxin4_ttl;          /* TTL of outer header          */
	u_int8_t         cpxin4_tos;          /* TOS of out header            */
	u_int8_t         cpxin4_inh_tos;      /* TOS inheritance flag         */
	u_int8_t         cpxin4_reserved1;    /* Padding stuff...             */
	struct in_addr   cpxin4_local;        /* Tunnel local address         */
	struct in_addr   cpxin4_remote;       /* Tunnel remote address        */
};

/*
 * Old names, kept for backward compatibility
 */
#define  CMD_6IN4_CREATE     CMD_XIN4_CREATE
#define  CMD_6IN4_DELETE     CMD_XIN4_DELETE
#define cp_6in4            cp_xin4
#define cp6in4_ifname      cpxin4_ifname
#define cp6in4_ifuid     cpxin4_ifuid
#define cp6in4_mtu         cpxin4_mtu
#define cp6in4_ttl         cpxin4_ttl
#define cp6in4_tos         cpxin4_tos
#define cp6in4_inh_tos     cpxin4_inh_tos
#define cp6in4_reserved1   cpxin4_reserved1
#define cp6in4_local       cpxin4_local
#define cp6in4_remote      cpxin4_remote

#define  CMD_XIN6_CREATE     (CMD_CFGTUN_BASE + 4)
#define  CMD_XIN6_DELETE     (CMD_CFGTUN_BASE + 5)
#define  CMD_XIN6_UPDATE     (CMD_CFGTUN_BASE + 6)
struct cp_xin6 {
	char             cpxin6_ifname[CM_IFNAMSIZE]; /* sytem interface name */
	u_int32_t        cpxin6_ifuid;      /* KERNEL interface identifier  */
	u_int32_t        cpxin6_vrfid;        /* Interface VRF ID */
	u_int32_t        cpxin6_linkvrfid;    /* Interface LINKVRF ID */
	u_int32_t        cpxin6_mtu;          /* Logical Interface MTU        */
	u_int8_t         cpxin6_hoplim;       /* Hop Limit of outer header    */
	u_int8_t         cpxin6_tos;          /* TOS of out header            */
	u_int8_t         cpxin6_inh_tos;      /* TOS inheritance flag         */
	u_int8_t         cpxin6_reserved1;    /* Padding stuff...             */
	struct in6_addr  cpxin6_local;        /* Tunnel local address         */
	struct in6_addr  cpxin6_remote;       /* Tunnel remote address        */
};

/*
 * Note: any major parameter change (i.e. not MTU/TOS/TTL) will be
 *       ALWAYS be done using a DELETE/CREATE messages in sequence
 *       any minor change will be done using the interface commands
 *       (CMD_TUN_TTL, ...)
 */


/*
 * Note: any major parameter change (i.e. not MTU/TOS/TTL) will
 *       ALWAYS be done using a STOP/START messages in sequence
 *       any minor change will be done using the interface commands
 *       (CMD_TUN_TTL, ...)
 */



/*
 *==============================================================
 * Multicast messages
 *==============================================================
 */

#define CMD_MCAST_BASE       0x040000

/*
 * ALL messages are both for IPv6 and IPv4 multicast
 * even if IPv4 multicast is not present
 */

#define  CMD_MCAST_ADD_MFC    (CMD_MCAST_BASE + 1)
struct cp_mfc_add {
	u_int8_t   cpmfc_family;          /* IPv6 (AF_INET6) or IPv4     */
	u_int8_t   cpmfc_reserved1;       /* Padding Stuff               */
	u_int8_t   cpmfc_reserved2;       /* Padding Stuff               */
	u_int8_t   cpmfc_reserved3;       /* Padding Stuff               */
	u_int32_t  cpmfc_iif;             /* incoming I/F Kernel index   */
	union {
		struct in6_addr	u_src6;
		struct in_addr	u_src4;
	} cpmfc_source;                   /* S part of (S,G) entry       */
	union {
		struct in6_addr	u_grp6;
		struct in_addr	u_grp4;
	} cpmfc_group;                    /* G part of (S,G) entry       */

#define CM_MAXMIFS         32
	u_int32_t  cpmfc_oif[CM_MAXMIFS];/* outgoing I/F Kernel index   */
};

#define  CMD_MCAST_DEL_MFC    (CMD_MCAST_BASE + 2)
struct cp_mfc_delete {
	u_int8_t   cpmfc_family;          /* IPv6 (AF_INET6) or IPv4     */
	u_int8_t   cpmfc_reserved1;       /* Padding Stuff               */
	u_int8_t   cpmfc_reserved2;       /* Padding Stuff               */
	u_int8_t   cpmfc_reserved3;       /* Padding Stuff               */
	union {
		struct in6_addr	u_src6;
		struct in_addr	u_src4;
	} cpmfc_source;                   /* S part of (S,G) entry       */
	union {
		struct in6_addr	u_grp6;
		struct in_addr	u_grp4;
	} cpmfc_group;                    /* G part of (S,G) entry       */
};
#define cpmfc_src6  cpmfc_source.u_src6
#define cpmfc_src4  cpmfc_source.u_src4
#define cpmfc_grp6  cpmfc_group.u_grp6
#define cpmfc_grp4  cpmfc_group.u_grp4

/*
 *==============================================================
 * Netfilter management messages
 *==============================================================
 */

#define  CMD_NETFILTER_BASE             0x050000

#define  CMD_NF_UPDATE                  (CMD_NETFILTER_BASE + 2)
#define  CMD_NF_CTADD                   (CMD_NETFILTER_BASE + 3)
#define  CMD_NF_CTDELETE                (CMD_NETFILTER_BASE + 4)
#define  CMD_NF6_UPDATE                 (CMD_NETFILTER_BASE + 5)
#define  CMD_NF6_CTADD                  (CMD_NETFILTER_BASE + 6)
#define  CMD_NF6_CTDELETE               (CMD_NETFILTER_BASE + 7)
#define  CMD_NF_CTFLUSH                 (CMD_NETFILTER_BASE + 9)
#define  CMD_NF_CPE_DELETE              (CMD_NETFILTER_BASE + 10)

#define CM_NF_MAXRULES                  1024
#define CM_NF6_MAXRULES                 1024
#define CM_NF_MAXNAMELEN                32
#define CM_NF_IP_NUMHOOKS               5

struct cp_nfrule {
	u_int32_t uid;
	struct {
#define CM_NF_TARGET_TYPE_STANDARD      1
#define CM_NF_TARGET_TYPE_ERROR         2
#define CM_NF_TARGET_TYPE_MARK_V2       3
#define CM_NF_TARGET_TYPE_DSCP          4
#define CM_NF_TARGET_TYPE_REJECT        5
#define CM_NF_TARGET_TYPE_LOG           6
#define CM_NF_TARGET_TYPE_ULOG          7
#define CM_NF_TARGET_TYPE_SNAT          8
#define CM_NF_TARGET_TYPE_DNAT          9
#define CM_NF_TARGET_TYPE_MASQUERADE   10
#define CM_NF_TARGET_TYPE_TCPMSS       11
#define CM_NF_TARGET_TYPE_DEV          12
#define CM_NF_TARGET_TYPE_CHECKSUM     13
		u_int8_t type;
		union {
			struct {
				int verdict;
			} standard;
			struct {
				char errorname[CM_NF_MAXNAMELEN];
			} error;
			struct {
				u_int32_t mark;
				u_int32_t mask;
				u_int32_t accept;
			} mark;
			struct {
				u_int8_t dscp;
			} dscp;
#ifdef CONFIG_PORTS_CACHEMGR_NF_RULE_NAT
			struct {
				u_int32_t min_ip;
				u_int32_t max_ip;

				u_int16_t min_port;
				u_int16_t max_port;
			} nat;
#endif /* CONFIG_PORTS_CACHEMGR_NF_RULE_NAT */
			struct {
#define CM_NF_DEV_FLAG_SET_MARK       0x01
				u_int32_t flags;
				u_int32_t mark;
				char ifname[CM_IFNAMSIZE];
			} dev;
		} data;
	} target;

	union {
		struct {
			u_int32_t src;                          /* Source IP addr */
			u_int32_t dst;                          /* Destination IP addr */
			u_int32_t smsk;                         /* Mask for src IP addr */
			u_int32_t dmsk;                         /* Mask for dest IP addr */
			char iniface[CM_IFNAMSIZE];
			char outiface[CM_IFNAMSIZE];
			unsigned char iniface_mask[CM_IFNAMSIZE];
			unsigned char outiface_mask[CM_IFNAMSIZE];
			u_int16_t proto;                        /* Protocol, 0 = ANY */
			u_int8_t flags;                         /* Flags word */
			u_int8_t invflags;                      /* Inverse flags */
		} ipv4;
	} l2;

	struct {
#define CM_NF_l2OPT_DSCP              0x01
#define CM_NF_l2OPT_RATELIMIT         0x02
#define CM_NF_l2OPT_FRAG              0x04                      /* only for IPv6 */
#define CM_NF_l2OPT_MARK              0x08
#define CM_NF_l2OPT_RPFILTER          0x10
#define CM_NF_l2OPT_MAC               0x20
#define CM_NF_l2OPT_PHYSDEV           0x40
		u_int8_t opt;
		u_int8_t dscp;          	                /* DSCP word */
		u_int8_t invdscp;               	        /* Inverse DSCP */
#define CM_NF_VRFID_UNSPECIFIED       0xFFFF
		u_int32_t vrfid;				/* VRF ID */
#define CM_NF_RPF_LOOSE               0x01
#define CM_NF_RPF_VALID_MARK          0x02
#define CM_NF_RPF_ACCEPT_LOCAL        0x04
#define CM_NF_RPF_INVERT              0x08
		u_int8_t rpf_flags;
		struct {
			u_int32_t cost;
			u_int32_t burst;
		} rateinfo;
		struct {
			u_int32_t mark;
			u_int32_t mask;
			u_int8_t invert;
		} mark;
		struct {
			u_int8_t srcaddr[CM_ETHMACSIZE];
			u_int8_t invert;
		} mac;
		struct {
			char physindev[CM_IFNAMSIZE];
			char physindev_mask[CM_IFNAMSIZE];
			char physoutdev[CM_IFNAMSIZE];
			char physoutdev_mask[CM_IFNAMSIZE];
			u_int8_t invert;
			u_int8_t bitmask;
		} physdev;
	} l2_opt;

	struct {
#define CM_NF_L3_TYPE_UDP        1
#define CM_NF_L3_TYPE_TCP        2
#define CM_NF_L3_TYPE_ICMP       3
#define CM_NF_L3_TYPE_SCTP       4
		u_int8_t type;
		union {
			struct {
				u_int16_t spts[2];              /* Source port range. */
				u_int16_t dpts[2];              /* Destination port range. */
				u_int8_t invflags;              /* Inverse flags */
			} udp;

			struct {
				u_int16_t spts[2];              /* Source port range. */
				u_int16_t dpts[2];              /* Destination port range. */
				u_int8_t option;                /* TCP Option iff non-zero*/
				u_int8_t flg_mask;              /* TCP flags mask byte */
				u_int8_t flg_cmp;               /* TCP flags compare byte */
				u_int8_t invflags;              /* Inverse flags */
			} tcp;

			/* Add sctp rule specific information */
		        struct {
				u_int16_t spts[2];  /* Min, Max */
				u_int16_t dpts[2];  /* Min, Max */
				/* Bit mask of chunks to be matched according to RFC 2960 */
				u_int32_t chunkmap[256 / (sizeof (u_int32_t) * 8)];
#define CM_NF_SCTP_CHUNK_MATCH_ANY      0x01  /* Match if any of the chunk types are present */
#define CM_NF_SCTP_CHUNK_MATCH_ALL      0x02  /* Match if all of the chunk types are present */
#define CM_NF_SCTP_CHUNK_MATCH_ONLY     0x04  /* Match if these are the only chunk types present */
				u_int32_t chunk_match_type;
				struct {
					u_int8_t chunktype;
					u_int8_t flag;
					u_int8_t flag_mask;
#define CM_NF_IPT_NUM_SCTP_FLAGS	4
				} flag_info[CM_NF_IPT_NUM_SCTP_FLAGS];
				int flag_count;
				u_int32_t flags;
				u_int32_t invflags;
			} sctp;

			struct {
				u_int8_t type;                  /* Type to match */
				u_int8_t code[2];               /* Range of code */
				u_int8_t invflags;              /* Inverse flags */
			} icmp;
		} data;
#define CM_NF_L3_STATE_ESTABLISHED	1
#define CM_NF_L3_STATE_EXCEPTION	2
		u_int8_t state;                                /* state of the flow */
	} l3;

	struct {
#define CM_NF_l3OPT_MULTIPORT       0x01
#define CM_NF_l3OPT_IPRANGE         0x02
		u_int8_t opt;
		struct {
#define CM_NF_MULTIPORT_FLAG_SRC 1
#define CM_NF_MULTIPORT_FLAG_DST 2
#define CM_NF_MULTIPORT_FLAG_ANY 3
			u_int8_t flags;                            /* Type of comparison */
			u_int8_t count;                            /* Number of ports */
#define CM_NF_MULTIPORT_SIZE 15
			u_int16_t ports[CM_NF_MULTIPORT_SIZE];     /* Ports */
			u_int8_t pflags[CM_NF_MULTIPORT_SIZE];     /* Port flags */
			u_int8_t invert;                           /* Invert flag */
		} multiport;
		struct {
			union  {
				u_int32_t		all[4];
				u_int32_t		ip;
				u_int32_t		ip6[4];
				struct in_addr	in;
				struct in6_addr	in6;
			}src_min, src_max, dst_min, dst_max;
			u_int8_t flags;
		}iprange;

	} l3_opt;

	uint32_t  dispatch;
	uint32_t  syns;
	uint32_t  speed;
	
#define CM_NF_STRING_MAX_ALGO_NAME_SIZE 16	
#define CM_NF_STRING_MAX_PATTERN_SIZE 128
#define CM_NF_OPT_STRING           0x01

	struct {
		u_int8_t opt;
		struct {
			u_int16_t from_offset;
			u_int16_t to_offset;
			u_int8_t	  algo[CM_NF_STRING_MAX_ALGO_NAME_SIZE];
			u_int8_t 	  pattern[CM_NF_STRING_MAX_PATTERN_SIZE];
			u_int8_t  patlen;
			union {
				struct {
					u_int8_t  invert;
				} v0;

				struct {
					u_int8_t  flags;
				} v1;
			} u;

		} string;
	} string_opt;


};

struct cp_nftable {
	char             cpnftable_name[CM_NF_MAXNAMELEN];         /* A unique name... */
	u_int8_t         cpnftable_family;                         /* AF_INET */
	u_int32_t        cpnftable_vrfid;                          /* vrfid of the table */
	u_int32_t        cpnftable_valid_hooks;                    /* What hooks you will enter on */
	u_int32_t        cpnftable_hook_entry[CM_NF_IP_NUMHOOKS];  /* Hook entry points */
	u_int32_t        cpnftable_underflow[CM_NF_IP_NUMHOOKS];   /* Underflow points */
	u_int32_t	 cpnftable_count;			   /* Number of entries */
	struct cp_nfrule cpnftable_rules[0];          		   /* Associated rules */
};

struct cp_nfct {
	u_int32_t orig_src;
	u_int32_t orig_dst;
	u_int16_t orig_sport;
	u_int16_t orig_dport;
	u_int32_t reply_src;
	u_int32_t reply_dst;
	u_int16_t reply_sport;
	u_int16_t reply_dport;
	u_int32_t vrfid;
	u_int32_t uid;
	u_int8_t  proto;
#define CM_NFCT_FLAG_SNAT	0x01
#define CM_NFCT_FLAG_DNAT	0x02
#define CM_NFCT_FLAG_ASSURED	0x04
#define CM_NFCT_FLAG_FROM_CPE	0x08
#define CM_NFCT_FLAG_TO_CPE	0x10
	u_int8_t flag;
};

struct cp_nfcpe {
	u_int32_t cpeid;
};

struct cp_nf6rule {
	u_int32_t uid;
	struct {
		u_int8_t type;
		union {
			struct {
				int verdict;
			} standard;
			struct {
				char errorname[CM_NF_MAXNAMELEN];
			} error;
			struct {
				u_int32_t mark;
				u_int32_t mask;
				u_int32_t accept;
			} mark;
			struct {
				u_int8_t dscp;
			} dscp;
			struct {
#define CM_NF6_DEV_FLAG_SET_MARK       0x01
				u_int32_t flags;
				u_int32_t mark;
				char ifname[CM_IFNAMSIZE];
			} dev;
		} data;
	} target;

	union {
		struct {
			struct in6_addr src;                    /* Source IPv6 addr */
			struct in6_addr dst;                    /* Destination IPv6 addr */
			struct in6_addr smsk;                   /* Mask for src IPv6 addr */
			struct in6_addr dmsk;                   /* Mask for dest IPv6 addr */
			char iniface[CM_IFNAMSIZE];
			char outiface[CM_IFNAMSIZE];
			unsigned char iniface_mask[CM_IFNAMSIZE];
			unsigned char outiface_mask[CM_IFNAMSIZE];
			u_int16_t proto;                        /* Protocol, 0 = ANY */
			u_int8_t tos;                           /* TOS to match iff flags & FP_NF_IPT_F_TOS */
			u_int8_t flags;                         /* Flags word */
			u_int8_t invflags;                      /* Inverse flags */
		} ipv6;
	} l2;

	struct {
		/* for DSCP and rate limit flags, see above in struct cp_nfrule */
		u_int8_t opt;
		u_int8_t dscp;                                  /* DSCP word */
		u_int8_t invdscp;                               /* Inverse DSCP */
		u_int32_t vrfid;                                /* VRF ID */
		u_int8_t rpf_flags;
		struct {
			u_int32_t cost;
			u_int32_t burst;
		} rateinfo;
		struct {
			u_int32_t ids[2];                       /* Security Parameter Index */
			u_int32_t hdrlen;                       /* Header Length */
			u_int8_t flags;
			u_int8_t invflags;
		} frag;
		struct {
			u_int32_t mark;
			u_int32_t mask;
			u_int8_t invert;
		} mark;
		struct {
			u_int8_t srcaddr[CM_ETHMACSIZE];
			u_int8_t invert;
		} mac;
		struct {
			char physindev[CM_IFNAMSIZE];
			char physindev_mask[CM_IFNAMSIZE];
			char physoutdev[CM_IFNAMSIZE];
			char physoutdev_mask[CM_IFNAMSIZE];
			u_int8_t invert;
			u_int8_t bitmask;
		} physdev;
	} l2_opt;

	struct {
		u_int8_t type;
		union {
			struct {
				u_int16_t spts[2];              /* Source port range. */
				u_int16_t dpts[2];              /* Destination port range. */
				u_int8_t invflags;              /* Inverse flags */
			} udp;

			struct {
				u_int16_t spts[2];              /* Source port range. */
				u_int16_t dpts[2];              /* Destination port range. */
				u_int8_t option;                /* TCP Option iff non-zero*/
				u_int8_t flg_mask;              /* TCP flags mask byte */
				u_int8_t flg_cmp;               /* TCP flags compare byte */
				u_int8_t invflags;              /* Inverse flags */
			} tcp;

			/* Add sctp rule specific information */
			struct {
				u_int16_t spts[2];  /* Min, Max */
				u_int16_t dpts[2];  /* Min, Max */
				/* Bit mask of chunks to be matched according to RFC 2960 */
				u_int32_t chunkmap[256 / (sizeof (u_int32_t) * 8)];
				u_int32_t chunk_match_type;
				struct {
					u_int8_t chunktype;
					u_int8_t flag;
					u_int8_t flag_mask;
				} flag_info[CM_NF_IPT_NUM_SCTP_FLAGS];
				int flag_count;
				u_int32_t flags;
				u_int32_t invflags;
			} sctp;

			struct {
				u_int8_t type;                  /* Type to match */
				u_int8_t code[2];               /* Range of code */
				u_int8_t invflags;              /* Inverse flags */
			} icmp;
		} data;
		u_int8_t state;                                 /* state of the flow */
	} l3;

	struct {
		u_int8_t opt;
		struct {
			u_int8_t flags;                            /* Type of comparison */
			u_int8_t count;                            /* Number of ports */
			u_int16_t ports[CM_NF_MULTIPORT_SIZE];     /* Ports */
			u_int8_t pflags[CM_NF_MULTIPORT_SIZE];     /* Port flags */
			u_int8_t invert;                           /* Invert flag */
		} multiport;
	} l3_opt;
};

struct cp_nf6table {
	char              cpnftable_name[CM_NF_MAXNAMELEN];        /* A unique name... */
	u_int8_t          cpnftable_family;                        /* AF_INET6 */
	u_int32_t         cpnftable_vrfid;                         /* vrfid of the table */
	u_int32_t         cpnftable_valid_hooks;                   /* What hooks you will enter on */
	u_int32_t         cpnftable_hook_entry[CM_NF_IP_NUMHOOKS]; /* Hook entry points */
	u_int32_t         cpnftable_underflow[CM_NF_IP_NUMHOOKS];  /* Underflow points */
	u_int32_t	  cpnftable_count;			   /* Number of entries */
	struct cp_nf6rule cpnftable_rules[0];        		   /* Associated rules */
};

struct cp_nf6ct {
	struct in6_addr orig_src;
	struct in6_addr orig_dst;
	struct in6_addr reply_src;
	struct in6_addr reply_dst;
	u_int16_t orig_sport;
	u_int16_t orig_dport;
	u_int16_t reply_sport;
	u_int16_t reply_dport;
	u_int32_t vrfid;
	u_int32_t uid;
	u_int8_t  proto;
	u_int8_t flag;
};

/*
 *==============================================================
 * IPsec messages
 *==============================================================
 */

#define CMD_IPSEC_BASE       0x070000

/*
 *--------------------------------------------------------------
 * Parameters For SAs (Security Associations)
 *--------------------------------------------------------------
 */
#define CMD_IPSEC_SA_BASE          CMD_IPSEC_BASE  +  0x100

#define CMD_IPSEC_SA_CREATE       (CMD_IPSEC_SA_BASE + 1)
#define CMD_IPSEC_SA_DELETE       (CMD_IPSEC_SA_BASE + 2)
#define CMD_IPSEC_SA_FLUSH        (CMD_IPSEC_SA_BASE + 3)
#define CMD_IPSEC_SA_REPLAYWIN    (CMD_IPSEC_SA_BASE + 4)
#define CMD_IPSEC_SA_MIGRATE      (CMD_IPSEC_SA_BASE + 5)
#define CMD_IPSEC_SA_BULK_MIGRATE (CMD_IPSEC_SA_BASE + 6)
#define CMD_IPSEC_SA_LIFETIME     (CMD_IPSEC_SA_BASE + 7)

typedef union {
	struct in_addr addr4;
	struct in6_addr addr6;
} cp_ipsec_addr_t;

/* For fpm graceful restart simplifications, cp_ipsec_sa_add must be castable to cp_ipsec_sa_del */
struct cp_ipsec_sa_add {
	u_int8_t          family;  /* AF_INET or AF_INET6 */
	u_int8_t          proto;   /* IPPROTO_AH or IPPROTO_ESP */
	u_int8_t          mode;    /* tunnel if set, transport if 0 */
	u_int8_t          reserved;

	u_int32_t         spi;     /* IPsec SPI */
	cp_ipsec_addr_t   daddr;   /* destination address */
	cp_ipsec_addr_t   saddr;   /* source address */
	u_int32_t         vrfid;   /* VRFID */

	u_int32_t         reqid;   /* request ID */
	u_int32_t         xvrfid;  /* XVRFID */

	u_int32_t         svti_ifuid; /* SVTI interface ifuid */

	u_int16_t         sport;   /* (optional), used in NAT-traversal mode */
	u_int16_t         dport;   /* (optional), used in NAT-traversal mode */

	u_int16_t         ekeylen; /* encryption key length */
	u_int16_t         akeylen; /* authentication key length */
	u_int32_t         flags;
#define CM_SA_FLAG_DONT_ENCAPDSCP    0x00000001
#define CM_SA_FLAG_DECAPDSCP    0x00000002
#define CM_SA_FLAG_NOPMTUDISC   0x00000004
#define CM_SA_FLAG_ESN          0x00000008

	u_int8_t          ealgo;   /* encryption algorithm */
	u_int8_t          aalgo;   /* authentication algorithm */
	u_int8_t          calgo;   /* compression algorithm (not yet) */
	u_int8_t          output_blade; /* Fast Path output blade */

	u_int64_t         seq;
	u_int64_t         oseq;
	u_int32_t         replay; /* optional replay window size */

	u_int8_t          keys[0]; /* cryptographic keys */
};

/*
 * total structure size (including keys) is rounded to next 32 bit boundary
 */

#define CM_IPSEC_ALG_UNKNOWN      255

#define CM_IPSEC_AALG_NONE          0
#define CM_IPSEC_AALG_MD5HMAC       2
#define CM_IPSEC_AALG_SHA1HMAC      3
#define CM_IPSEC_AALG_SHA2_256HMAC  5
#define CM_IPSEC_AALG_SHA2_384HMAC  6
#define CM_IPSEC_AALG_SHA2_512HMAC  7
#define CM_IPSEC_AALG_RIPEMD160HMAC 8
#define CM_IPSEC_AALG_AES_XCBC_MAC  9

#define CM_IPSEC_EALG_NONE          0
#define CM_IPSEC_EALG_DESCBC        2
#define CM_IPSEC_EALG_3DESCBC       3
#define CM_IPSEC_EALG_CASTCBC       6
#define CM_IPSEC_EALG_BLOWFISHCBC   7
#define CM_IPSEC_EALG_AESCBC       12
#define CM_IPSEC_EALG_AESGCM       20
#define CM_IPSEC_EALG_NULL_AESGMAC 21
#define CM_IPSEC_EALG_SERPENTCBC  252
#define CM_IPSEC_EALG_TWOFISHCBC  253

#define CM_IPSEC_F_NOECN        0x00000001
#define CM_IPSEC_F_DECAP_DSCP   0x00000002
#define CM_IPSEC_F_NOPMTUDISC   0x00000004

#define CM_IPSEC_STATE_NONE     0
#define CM_IPSEC_STATE_DYING    1

/* For fpm graceful restart simplifications, cp_ipsec_sa_add must be castable to cp_ipsec_sa_del */
struct cp_ipsec_sa_del {
	u_int8_t          family;  /* AF_INET or AF_INET6 */
	u_int8_t          proto;
	u_int8_t          state;
	u_int8_t          reserved;
	u_int32_t         spi;     /* IPsec SPI */
	cp_ipsec_addr_t   daddr;   /* destination address */
	cp_ipsec_addr_t   saddr;   /* source address */
	u_int32_t         vrfid;   /* VRFID */
};

struct cp_ipsec_sa_replaywin {
	u_int8_t          family;  /* AF_INET or AF_INET6 */
	u_int8_t          proto;   /* IPPROTO_AH or IPPROTO_ESP */
	u_int16_t         reserved;
	u_int32_t         vrfid;   /* VRFID */
	cp_ipsec_addr_t   daddr;   /* destination address */
	u_int32_t         spi;     /* IPsec SPI */
	u_int32_t         oseq;    /* highest sent sequence number */
	u_int32_t         seq;     /* highest received sequence number */
	u_int32_t         bitmap;  /* replay window bitmap */
};

struct cp_ipsec_sa_migrate {
	u_int8_t          family;  /* AF_INET or AF_INET6 */
	u_int8_t          proto;   /* IPPROTO_AH or IPPROTO_ESP */
	u_int8_t          output_blade; /* the blade to which we want to migrate the SA */
	u_int8_t          reserved;
	u_int32_t         vrfid;   /* VRFID */
	cp_ipsec_addr_t   daddr;   /* destination address */
	u_int32_t         spi;     /* IPsec SPI */
	u_int32_t         gap;     /* gap in term of SA output sequence number */
};

struct cp_ipsec_sa_bulk_migrate {
	u_int8_t          mig_type;         /* Migration Type, how to interpret the data field */
	u_int8_t          dst_output_blade; /* the blade to which we want to migrate the SA */
	u_int16_t         reserved;

        u_int32_t         gap;              /* gap in term of SA output sequence number */

        char              data[128];        /* a way to identify SAs */
};

typedef struct cp_ipsec_lifetime_s {
	u_int64_t         nb_bytes;   /* SA bytes limit */
	u_int64_t         nb_packets; /* SA packets limit */
} cp_ipsec_lifetime_t;

struct cp_ipsec_sa_lifetime {
	u_int8_t          family;  /* AF_INET or AF_INET6 */
	u_int8_t          proto;   /* IPPROTO_AH or IPPROTO_ESP */
	u_int16_t         reserved;

	u_int32_t         spi;     /* IPsec SPI */
	cp_ipsec_addr_t   daddr;   /* destination address */
	u_int32_t         vrfid;   /* VRFID */

	cp_ipsec_lifetime_t soft;  /* SA soft limits */
	cp_ipsec_lifetime_t hard;  /* SA hard limits */
};

/*
 *--------------------------------------------------------------
 * Parameters For SPs (Security Policies)
 *--------------------------------------------------------------
 */
#define CMD_IPSEC_SP_BASE       CMD_IPSEC_BASE  +  0x200

#define CMD_IPSEC_SP_CREATE    (CMD_IPSEC_SP_BASE + 1)
#define CMD_IPSEC_SP_DELETE    (CMD_IPSEC_SP_BASE + 2)
#define CMD_IPSEC_SP_FLUSH     (CMD_IPSEC_SP_BASE + 3)
#define CMD_IPSEC_SP_UPDATE    (CMD_IPSEC_SP_BASE + 4)

/*
 * IPsec transformation (SA template)
 */
struct cp_ipsec_xfrm {
	u_int8_t          family;  /* AF_INET or AF_INET6 */
	u_int8_t          proto;   /* IPPROTO_AH or IPPROTO_ESP */
	u_int8_t          mode;    /* tunnel if set, transport if 0 */
	u_int8_t          flags;

	cp_ipsec_addr_t   saddr;   /* source address. ignored in transport mode */
	cp_ipsec_addr_t   daddr;   /* destination address. mandatory if tunnel
	                            * mode or if SPI is specified */
	u_int32_t         spi;     /* (optional) */
	u_int32_t         reqid;   /* (optional) request id */
};

/* For fpm graceful restart simplifications, cp_ipsec_sp_add must be castable to cp_ipsec_sp_del */
struct cp_ipsec_sp_add {
	u_int32_t         index;    /* rule unique ID */
	u_int32_t         priority; /* rule priority (order in SPD) */

	/* selector */
	u_int8_t          reserved;
	u_int8_t          family;   /* AF_INET or AF_INET6 */
	u_int8_t          dir;      /* flow direction */
	u_int8_t          proto;    /* L4 protocol */

	cp_ipsec_addr_t   saddr;   /* source address */
	cp_ipsec_addr_t   daddr;   /* destination address */

	u_int16_t         sport;   /* source port */
	u_int16_t         dport;   /* destination port */
	u_int16_t         sportmask;   /* source port mask */
	u_int16_t         dportmask;   /* destination mask */

	u_int32_t         vrfid;
	u_int32_t         svti_ifuid; /* SVTI interface ifuid */

	u_int8_t          spfxlen;   /* source address prefix length */
	u_int8_t          dpfxlen;   /* destination address prefix length */
	u_int8_t          action;      /* clear/discard/ipsec */
	u_int8_t          xfrm_count;  /* nb of transformations in bundle */

	u_int32_t         link_vrfid;
	u_int32_t         flags;

	struct cp_ipsec_xfrm xfrm[0];  /* transformations (SA templates) */
};

#define CM_IPSEC_DIR_INBOUND  1
#define CM_IPSEC_DIR_OUTBOUND 2

#define CM_IPSEC_ACTION_CLEAR   0
#define CM_IPSEC_ACTION_DISCARD 1
#define CM_IPSEC_ACTION_IPSEC   2

#define CM_IPSEC_MODE_TRANSPORT 0
#define CM_IPSEC_MODE_TUNNEL    1

/* protect level use (bypass if no SA) */
#define CM_IPSEC_FLAG_LEVEL_USE 0x01

/*
 * Note: In CMD_IPSEC_SP_DELETE message, the CM sends both the packet selector
 * and the SP index. One of the 2 would be enough.
 * Therefore, the FPM is free to use the selector or the index to identify
 * the SP to delete.
 */
/* For fpm graceful restart simplifications, cp_ipsec_sp_add must be castable to cp_ipsec_sp_del */
struct cp_ipsec_sp_del {

	u_int32_t         index;    /* rule unique ID */
	u_int32_t         priority; /* rule priority (order in SPD) */

	/* selector */
	u_int8_t          reserved;
	u_int8_t          family;   /* AF_INET or AF_INET6 */
	u_int8_t          dir;      /* flow direction */
	u_int8_t          proto;    /* L4 protocol */

	cp_ipsec_addr_t   saddr;   /* source address */
	cp_ipsec_addr_t   daddr;   /* destination address */

	u_int16_t         sport;   /* source port or icmp type */
	u_int16_t         dport;   /* destination port or icmp code */
	u_int16_t         sportmask;   /* source port mask or icmp type mask */
	u_int16_t         dportmask;   /* destination mask or icmp code mask */

	u_int32_t         vrfid;   /* VRFID */
	u_int32_t         svti_ifuid; /* SVTI interface ifuid */

	u_int8_t          spfxlen;   /* source address prefix length */
	u_int8_t          dpfxlen;   /* destination address prefix length */
	u_int8_t          action;    /* clear/discard/ipsec */
	u_int8_t          xfrm_count;  /* nb of transformations in bundle */
};

struct cp_ipsec_sp_flush {
	u_int32_t         vrfid;        /* VRFID */
	u_int32_t         svti_ifuid; /* SVTI interface ifuid */
};

/*
 *--------------------------------------------------------------
 * Parameters For SVTI interfaces (Secure Virtual Tunnel Interfaces)
 *--------------------------------------------------------------
 */
#define CMD_SVTI_BASE       CMD_IPSEC_BASE  +  0x300

#define CMD_SVTI_CREATE    (CMD_SVTI_BASE + 1)
#define CMD_SVTI_DELETE    (CMD_SVTI_BASE + 2)

struct cp_svti {
	char             cpsvti_ifname[CM_IFNAMSIZE]; /* Interface name       */
	u_int32_t        cpsvti_ifuid;        /* Interface unique identifier  */
	u_int32_t        cpsvti_vrfid;        /* Interface vrfid              */
	u_int32_t        cpsvti_linkvrfid;    /* Interface link-vrfid         */
	u_int32_t        cpsvti_mtu;          /* Interface MTU                */
	struct in_addr   cpsvti_local;        /* Tunnel local address         */
	struct in_addr   cpsvti_remote;       /* Tunnel remote address        */
};

/*
 *==============================================================
 * VNB management messages
 *==============================================================
 */

#define CMD_VNB_BASE      0x090000

#define CMD_VNB_MSGHDR    (CMD_VNB_BASE + 1)
#define CMD_VNB_ASCIIMSG  (CMD_VNB_BASE + 2)
#define CMD_VNB_DUMP      (CMD_VNB_BASE + 3)
struct cp_vnb_msghdr {
	u_int32_t vnbh_typecookie;
	u_int32_t vnbh_cmd;
	u_int32_t vnbh_seqnum;
	u_int16_t vnbh_arglen;
	u_int16_t vnbh_pathlen;
	u_int32_t vnbh_cpnodeid;
}; /* followed by cmd data (arglen bytes), path (pathlen) */

/* keep in sync with netfpc_vnbdump_msg structure in netfpc_var.h */
struct cp_vnb_dump_attr {
	uint32_t type;
	uint32_t len;
	char data[];
};

struct cp_vnb_dump_msghdr {
	uint32_t attr_count;
	uint32_t len;
};

enum {
	CMD_VNB_NONE = 0,
	CMD_VNB_NODE,
	CMD_VNB_NODE_PRIV,
	CMD_VNB_STATUS,
	CMD_VNB_HOOK,
	CMD_VNB_HOOK_PRIV,
	CMD_VNB_MAX,
};


/*
 *==============================================================
 * Blades management messages
 *==============================================================
 */

#define  CMD_BLADE_BASE   0x0A0000

#define  CMD_BLADE_CREATE   (CMD_BLADE_BASE + 1)
#define  CMD_BLADE_DELETE   (CMD_BLADE_BASE + 2)

struct cp_blade_create {
	u_int8_t         cpblade_id;    /* blade identifier  */
	u_int8_t         cpblade_flags;
	u_int8_t         cpblade_mac[CM_ETHMACSIZE];
};

#define  CMD_BLADE_FPIB_IF_SET      (CMD_BLADE_BASE + 3)
#define  CMD_BLADE_FPIB_IF_UNSET    (CMD_BLADE_BASE + 4)

struct cp_blade_fpib {
	u_int32_t        fpib_ifuid;  /* inter-blade interface ifuid */
};

/*
 *==============================================================
 * Filter / BPF management messages
 *==============================================================
 */

#define  CMD_BPF_BASE                   0x0B0000

#define  CMD_BPF_CREATE                 (CMD_BPF_BASE + 1)

#define CM_BPF_MAXFILTERS               63

struct cp_bpf_filter {
	u_int16_t code;
	u_int8_t  jt;
	u_int8_t  jf;
	u_int32_t k;
};

struct cp_bpf {
	u_int32_t             ifuid;
	u_int32_t             num;
	struct cp_bpf_filter  filters[CM_BPF_MAXFILTERS];
};

/*
 *==============================================================
 * Ktables messages
 *==============================================================
 */

#define  CMD_KTABLES_BASE                  0x0D0000

#define  CMD_KTABLES_INIT                  (CMD_KTABLES_BASE + 1)
#define  CMD_KTABLES_RESET                 (CMD_KTABLES_BASE + 2)
#define  CMD_KTABLES_SET                   (CMD_KTABLES_BASE + 3)

#define  KTABLES_TABLE_SIZE                8

struct cp_ktables {
	uint8_t         table[KTABLES_TABLE_SIZE];
	uint32_t	n;
};

#define CMD_FPVS_BASE   0x0E0000 /* see fp-vswitch/common/fpvs-cp.h */

/*
 *---------------------------------------------------------------------------
 * Parameters for VXLAN interfaces (Virtual eXtensible Local Area Networking)
 *---------------------------------------------------------------------------
 */
#define CMD_VXLAN_BASE                     0x0F0000

#define CMD_VXLAN_CREATE                   (CMD_VXLAN_BASE + 1)
#define CMD_VXLAN_DELETE                   (CMD_VXLAN_BASE + 2)
#define CMD_VXLAN_FDB_ADD                  (CMD_VXLAN_BASE + 3)
#define CMD_VXLAN_FDB_DEL                  (CMD_VXLAN_BASE + 4)

struct cp_vxlan {
	char             cpvxlan_ifname[CM_IFNAMSIZE]; /* Interface name               */
	u_int32_t        cpvxlan_ifuid;                /* Interface unique identifier  */
	u_int32_t        cpvxlan_vrfid;                /* Interface vrfid              */
	u_int32_t        cpvxlan_mtu;                  /* Interface MTU                */
	u_int32_t        cpvxlan_vni;                  /* VXLAN Network Identifier     */
	u_int32_t        cpvxlan_linkifuid;            /* Default iface gw             */
	union {
		struct in6_addr gw6;
		struct in_addr  gw4;
	} cpvxlan_gw;                                  /* Default gw                   */
	union {
		struct in6_addr saddr6;
		struct in_addr  saddr4;
	} cpvxlan_saddr;                               /* Default source address       */
	u_int32_t        cpvxlan_vnb_nodeid;
	u_int32_t        cpvxlan_maclen;
	u_int8_t         cpvxlan_mac[CM_MACMAXSIZE];
	u_int16_t        cpvxlan_dstport;              /* Destination port             */
	u_int16_t        cpvxlan_srcminport;           /* Source min port              */
	u_int16_t        cpvxlan_srcmaxport;           /* Source max port              */
	u_int8_t         cpvxlan_ttl;
	u_int8_t         cpvxlan_tos;
	u_int8_t         cpvxlan_gwfamily;
	u_int8_t         cpvxlan_saddrfamily;
#define FPM_VXLAN_IFACE_F_LEARN		0x1
	u_int8_t         cpvxlan_flags;
	u_int8_t         reserved;
};

struct cp_vxlan_fdb {
	u_int32_t               fdb_ifuid;          /* corresponding interface */
	u_int32_t               fdb_vni;            /* vxlan id */
	u_int32_t               fdb_output_ifuid;   /* output interface */
	union {
		struct in6_addr addr6;
		struct in_addr  addr4;
	} fdb_addr;                                 /* IP address */
	u_int16_t               fdb_dst_port;       /* destination port */
	u_int8_t                fdb_family;         /* address family */
	u_int8_t                fdb_state;          /* neighbour state */
	u_int8_t                fdb_mac[6];
	u_int8_t                reserved[2];
};

/*
 *-------------------------------------
 * Parameters for linux vlan interfaces
 *-------------------------------------
 */
#define CMD_VLAN_BASE                     0x100000

#define CMD_VLAN_CREATE                   (CMD_VLAN_BASE + 1)
#define CMD_VLAN_DELETE                   (CMD_VLAN_BASE + 2)

struct cp_vlan {
	char             cpvlan_ifname[CM_IFNAMSIZE]; /* Interface name               */
	u_int32_t        cpvlan_ifuid;                /* Interface unique identifier  */
	u_int32_t        cpvlan_vrfid;                /* Interface vrfid              */
	u_int32_t        cpvlan_mtu;                  /* Interface MTU                */
	u_int32_t        cpvlan_lower_ifuid;

	u_int32_t        cpvlan_vnb_nodeid;
	u_int32_t        cpvlan_maclen;
	u_int8_t         cpvlan_mac[CM_MACMAXSIZE];

	u_int16_t        cpvlan_vlanid;
	u_int32_t        cpvlan_flags;
};

/*
 *---------------------------------------
 * Parameters for linux bridge interfaces
 *---------------------------------------
 */
#define CMD_BRIDGE_BASE                    0x200000

#define CMD_BRPORT_UPDATE                  (CMD_BRIDGE_BASE + 1)
#define CMD_BRPORT_DELETE                  (CMD_BRIDGE_BASE + 2)

struct cp_brport {
	u_int32_t        cpbrport_ifuid;            /* Interface unique identifier  */
	u_int32_t        cpbrport_master_ifuid;
#define CP_BRPORT_S_DISABLED            0
#define CP_BRPORT_S_LISTENING           1
#define CP_BRPORT_S_LEARNING            2
#define CP_BRPORT_S_FORWARDING          3
#define CP_BRPORT_S_BLOCKING            4
	u_int8_t         cpbrport_state;
#define CP_BRPORT_F_HAIRPIN_MODE        0x01
#define CP_BRPORT_F_LEARNING            0x02
#define CP_BRPORT_F_UNICASTFLOOD        0x04
	u_int8_t         cpbrport_flags;
};

/*
 *--------------------------------------------------------------
 * Parameters For bonding interfaces
 *--------------------------------------------------------------
 */
#define CMD_BONDING_BASE             0x400000

#define CMD_BONDING_CREATE           (CMD_BONDING_BASE + 1)
#define CMD_BONDING_DELETE           (CMD_BONDING_BASE + 2)
#define CMD_BONDING_UPDATE           (CMD_BONDING_BASE + 3)
#define CMD_BONDING_SLAVE_UPDATE     (CMD_BONDING_BASE + 4)

struct cp_bonding {
	char             cpbonding_ifname[CM_IFNAMSIZE]; /* Interface name              */
	u_int32_t        cpbonding_ifuid;                /* Interface unique identifier */
	u_int32_t        cpbonding_vrfid;                /* Interface vrfid             */
	u_int32_t        cpbonding_mtu;                  /* Interface MTU               */

	u_int32_t        cpbonding_vnb_nodeid;

	u_int32_t        cpbonding_maclen;
	u_int32_t        cpbonding_active_slave_ifuid;
	u_int16_t        cpbonding_ad_info_aggregator;
	u_int16_t        cpbonding_ad_info_num_ports;
#define CP_BOND_MODE_ROUNDROBIN     0
#define CP_BOND_MODE_ACTIVEBACKUP   1
#define CP_BOND_MODE_XOR            2
#define CP_BOND_MODE_BROADCAST      3
#define CP_BOND_MODE_8023AD         4
#define CP_BOND_MODE_TLB            5
#define CP_BOND_MODE_ALB            6
	u_int8_t         cpbonding_mode;
	u_int8_t         cpbonding_mac[CM_MACMAXSIZE];
};

struct cp_bonding_slave {
	u_int32_t        cpbond_s_ifuid;
	u_int32_t        cpbond_s_master_ifuid;
	u_int32_t        cpbond_s_link_failure_count;
	u_int32_t        cpbond_s_queue_id;
	u_int16_t        cpbond_s_aggregator_id;
#define CP_BOND_STATE_UNKNOWN       0
#define CP_BOND_STATE_ACTIVE        1
#define CP_BOND_STATE_BACKUP        2
	u_int8_t         cpbond_s_state;
#define CP_BOND_LINK_UNKNOWN        0
#define CP_BOND_LINK_UP             1
#define CP_BOND_LINK_FAIL           2
#define CP_BOND_LINK_DOWN           3
#define CP_BOND_LINK_BACK           4
	u_int8_t         cpbond_s_link;
	char             cpbond_s_perm_hwaddr[6];
};

/*
 *--------------------------------------------------------------
 * Parameters for GRE interfaces
 *--------------------------------------------------------------
 */
#define CMD_GRE_BASE             0x500000

#define CMD_GRE_CREATE           (CMD_GRE_BASE + 1)
#define CMD_GRE_UPDATE           (CMD_GRE_BASE + 2)
#define CMD_GRE_DELETE           (CMD_GRE_BASE + 3)
#define CMD_GRETAP_DELETE        (CMD_GRE_BASE + 4)

struct cp_gre {
	char		cpgre_ifname[CM_IFNAMSIZE]; /* Interface name               */
	u_int32_t	cpgre_ifuid;                /* Interface unique identifier  */
	u_int32_t	cpgre_mtu;                  /* Interface MTU                */
	u_int32_t	cpgre_vrfid;                /* Interface vrfid              */
	u_int32_t	cpgre_linkvrfid;            /* Interface link-vrfid         */

	u_int32_t	cpgre_linkifuid;
#define CP_GRE_FLAG_CSUM        0x01
#define CP_GRE_FLAG_ROUTING     0x02
#define CP_GRE_FLAG_KEY         0x04
#define CP_GRE_FLAG_SEQ         0x08
#define CP_GRE_FLAG_STRICT      0x10
#define CP_GRE_FLAG_REC         0x20
#define CP_GRE_FLAG_FLAGS       0x40
#define CP_GRE_FLAG_VERSION     0x80
	u_int16_t	cpgre_iflags;
	u_int16_t	cpgre_oflags;
	u_int32_t	cpgre_ikey;
	u_int32_t	cpgre_okey;
	u_int8_t	cpgre_ttl;
	u_int8_t	cpgre_tos;
	u_int8_t	cpgre_inh_tos;
	u_int8_t	cpgre_family;
	union {
		struct in_addr	local;
		struct in6_addr	local6;
	} cpgre_laddr;
	union {
		struct in_addr	remote;
		struct in6_addr	remote6;
	} cpgre_raddr;
	u_int32_t	cpgretap_vnb_nodeid;
	u_int32_t	cpgretap_maclen;
	u_int8_t	cpgretap_mac[CM_MACMAXSIZE];
#define CP_GRE_MODE_IP		0   /* IPv4 0x0800 or IPv6 0x86DD           */
#define CP_GRE_MODE_ETHER	1   /* Transparent Ethernet Bridging 0x6558 */
	u_int8_t	cpgre_mode;
};

/*
 *-------------------------------------
 * Parameters for linux macvlan interfaces
 *-------------------------------------
 */
#define CMD_MACVLAN_BASE                     0x600000

#define CMD_MACVLAN_CREATE                   (CMD_MACVLAN_BASE + 1)
#define CMD_MACVLAN_DELETE                   (CMD_MACVLAN_BASE + 2)
#define CMD_MACVLAN_UPDATE                   (CMD_MACVLAN_BASE + 3)

struct cp_macvlan {
	char             cpmacvlan_ifname[CM_IFNAMSIZE]; /* Interface name               */
	u_int32_t        cpmacvlan_ifuid;                /* Interface unique identifier  */
	u_int32_t        cpmacvlan_vrfid;                /* Interface vrfid              */
	u_int32_t        cpmacvlan_mtu;                  /* Interface MTU                */
	u_int32_t        cpmacvlan_link_ifuid;
	u_int32_t        cpmacvlan_vnb_nodeid;
	u_int32_t        cpmacvlan_maclen;
	u_int8_t         cpmacvlan_mac[CM_MACMAXSIZE];
#define CP_MACVLAN_MODE_UNKNOWN     0
#define CP_MACVLAN_MODE_PRIVATE     1
#define CP_MACVLAN_MODE_VEPA        2
#define CP_MACVLAN_MODE_BRIDGE      4
#define CP_MACVLAN_MODE_PASSTHRU    8
	u_int32_t        cpmacvlan_mode;
#define CP_MACVLAN_FLAGS_NOPROMISC  1
	u_int16_t        cpmacvlan_flags;
};

/*
 *==============================================================
 * Ebtables management messages
 *==============================================================
 */

#define CMD_EBTABLES_BASE               0x700000

#define CMD_EBT_UPDATE                  (CMD_EBTABLES_BASE + 1)

#define CM_EBT_NUMHOOKS                 6
#define CM_EBT_MAXNAMELEN               32

struct cp_ebt_rule {
#define CM_EBT_NOPROTO  	        0x02
#define CM_EBT_802_3    	        0x04
#define CM_EBT_SOURCEMAC	        0x08
#define CM_EBT_DESTMAC  	        0x10
	uint32_t bitmask;

#define CM_EBT_IPROTO     	        0x01
#define CM_EBT_IIN        	        0x02
#define CM_EBT_IOUT       	        0x04
#define CM_EBT_ISOURCE    	        0x08
#define CM_EBT_IDEST      	        0x10
#define CM_EBT_ILOGICALIN 	        0x20
#define CM_EBT_ILOGICALOUT	        0x40
	uint32_t invflags;
	uint16_t ethproto;

	char in[CM_IFNAMSIZE];
	char logical_in[CM_IFNAMSIZE];
	char out[CM_IFNAMSIZE];
	char logical_out[CM_IFNAMSIZE];

	uint8_t sourcemac[CM_ETHMACSIZE];
	uint8_t sourcemsk[CM_ETHMACSIZE];
	uint8_t destmac[CM_ETHMACSIZE];
	uint8_t destmsk[CM_ETHMACSIZE];

	struct {
#define CM_EBT_TARGET_TYPE_STANDARD     1
#define CM_EBT_TARGET_TYPE_ERROR        2
		uint8_t type;
		union {
			struct {
				int verdict;
			} standard;
		} data;
	} target;

#define CM_EBT_L3_TYPE_NONE             0
#define CM_EBT_L3_TYPE_IP               1
#define CM_EBT_L3_TYPE_IP6              2
	uint8_t l3_type;
	union {
		struct {
			uint32_t saddr;
			uint32_t daddr;
			uint32_t smsk;
			uint32_t dmsk;
			uint8_t  tos;
			uint8_t  protocol;
			uint8_t  bitmask;

#define CM_EBT_IP_SOURCE	        0x01
#define CM_EBT_IP_DEST  	        0x02
#define CM_EBT_IP_TOS   	        0x04
#define CM_EBT_IP_PROTO 	        0x08
#define CM_EBT_IP_SPORT 	        0x10
#define CM_EBT_IP_DPORT 	        0x20
			uint8_t  invflags;
			uint16_t sport[2];
			uint16_t dport[2];
		} ipv4;
		struct {
			struct in6_addr saddr;        /* Source IPv6 addr */
			struct in6_addr daddr;        /* Destination IPv6 addr */
			struct in6_addr smsk;         /* Mask for src IPv6 addr */
			struct in6_addr dmsk;         /* Mask for dest IPv6 addr */
			uint8_t  tclass;
			uint8_t  protocol;
			uint8_t  bitmask;

#define CM_EBT_IP6_SOURCE	        0x01
#define CM_EBT_IP6_DEST  	        0x02
#define CM_EBT_IP6_TCLASS	        0x04
#define CM_EBT_IP6_PROTO 	        0x08
#define CM_EBT_IP6_SPORT 	        0x10
#define CM_EBT_IP6_DPORT 	        0x20
#define CM_EBT_IP6_ICMP6 	        0x40
			uint8_t  invflags;
			union {
				uint16_t sport[2];
				uint8_t icmpv6_type[2];
			};
			union {
				uint16_t dport[2];
				uint8_t icmpv6_code[2];
			};

		} ipv6;
	} l3;
};

struct cp_ebt_table {
	char               name[CM_EBT_MAXNAMELEN];      /* A unique name... */
	uint32_t           vrfid;                        /* vrfid of the table */
	uint32_t           valid_hooks;                  /* What hooks you will enter on */
	uint32_t           hook_entry[CM_EBT_NUMHOOKS];  /* Hook entry points */
	uint32_t           underflow[CM_EBT_NUMHOOKS];   /* Underflow points */
	uint32_t           count;                        /* Number of entries */
	struct cp_ebt_rule  rules[0];                     /* Associated rules */
};

#endif
