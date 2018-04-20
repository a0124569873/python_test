/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *
 *                CM 'Public'
 *
 * $Id: cm_pub.h,v 1.70 2010-10-21 14:56:21 dichtel Exp $
 ***************************************************************
 */

#ifndef __CM_PUB_H_
#define __CM_PUB_H_

#include <sys/queue.h>
#include <linux/netlink.h>
#include <endian.h>

#ifndef htonll
#define htonll(x) (uint64_t)htobe64(x)
#endif
#ifndef ntohll
#define ntohll(x) (uint64_t)be64toh(x)
#endif

extern void cm_init (void);
extern void cm_destroy (void);
extern void admin_init (void);
extern void fpm_dump (void);

struct cm_addr6 {
	TAILQ_ENTRY(cm_addr6)   link;
	struct in6_addr         addr;
	uint32_t vrfid;
};
TAILQ_HEAD(cmaddr6, cm_addr6);

extern int cm2cp_reset (u_int16_t, u_int16_t);
extern int cm2cp_flush (void);
extern int cm2cp_graceful_restart (u_int32_t gr_type);
extern int cm2cp_vrf_del(int vrfid);
extern int cm2cp_ipv4_addr (u_int32_t, u_int32_t, u_int32_t, struct in_addr  *, u_int8_t);
extern int cm2cp_ipv6_addr (u_int32_t, u_int32_t, u_int32_t, struct in6_addr *, u_int8_t);


/* interface structure (common parameters)
 * CM allocates size of this struct + size for interface-type specific struct
 */
struct cm_iface {
	TAILQ_ENTRY(cm_iface) link;  /* pointers to chained list */
	LIST_ENTRY(cm_iface) h_ifindex; /* pointers to hlist by ifindex */
	LIST_ENTRY(cm_iface) h_ifuid;   /* pointers to hlist by ifuid   */
	LIST_ENTRY(cm_iface) l_bond;   /* pointers to bonding list      */
	u_int32_t  ifindex;       /* KERNEL Interface Identifier */
	u_int32_t  ifuid;       /* KERNEL Interface ifuid*/
	u_int32_t  vrfid;         /* VRF ID */
	u_int32_t  linkvrfid;     /* Link VRF ID */
	char       ifname[CM_IFNAMSIZE + 1]; /* sytem interface name */
	u_int32_t  type;          /* interface type              */
	u_int32_t  subtype;       /* interface sub-type          */
	u_int32_t  flags;         /* interface flags             */
	u_int32_t  mtu;           /* interface Max Transmit Unit */
	u_int32_t  master_ifuid;  /* interface uid master        */
	u_int32_t  vnb_nodeid;    /* ng_ether node ID            */
	u_int8_t   vnb_keep_node; /* don't destroy ng_ether node */
	u_int8_t   in_l_bond;     /* iface in l_bond list        */
	/* blade management */
	u_int8_t   blade_id;      /* interface blade id                */
};
TAILQ_HEAD(cmiface, cm_iface);
extern struct cm_iface * iflookup (u_int32_t ifindex, u_int32_t vrfid);
extern struct cm_iface * iflookupbyifuid (u_int32_t ifuid);
extern char            * cm_ifuid2name(uint32_t ifuid);
extern u_int32_t cm_ifindex2ifuid (u_int32_t ifindex, u_int32_t vrfid, u_int8_t strict);

#ifdef CONFIG_CACHEMGR_MULTIBLADE
/* FPIB parameters (inter-blade communication) */
struct cm_fpib {
	char       ifname[CM_IFNAMSIZE + 1];
	u_int32_t  ifuid;
};
extern int f_multiblade;
extern struct cm_fpib cm_fpib;
#endif

/* specific parameters for a physical interface */
struct cm_eth_params {
	u_int32_t  maclen;
	u_int8_t   mac[CM_MACMAXSIZE];
};

/* specific parameters for a loopback interface */
struct cm_loop_params {
};

/* specific parameters for a 6in4 interface */
struct cm_6in4_params {
	u_int8_t         ttl;          /* TTL of outer header          */
	u_int8_t         tos;          /* TOS of outer header          */
	u_int8_t         inh_tos;      /* TOS inheritance flag         */
	struct in_addr   local;        /* Tunnel local address         */
	struct in_addr   remote;       /* Tunnel remote address        */
};

/* specific parameters for a Xin6 interface */
struct cm_Xin6_params {
	u_int8_t         hoplim;       /* Hop Limit of outer heade     */
	u_int8_t         tos;          /* TOS of outer header          */
	u_int8_t         inh_tos;      /* TOS inheritance flag         */
	struct in6_addr  local;        /* Tunnel local address         */
	struct in6_addr  remote;       /* Tunnel remote address        */
};

/* specific parameters for a port interface */
struct cm_port_params {
	u_int8_t  opaque[CM_OPAQUESIZE];
};

/* specific parameters for an SVTI interface */
struct cm_svti_params {
};

/* specific parameters for a VTI interface */
struct cm_vti_params {
	struct in_addr   local;        /* Tunnel local address         */
	struct in_addr   remote;       /* Tunnel remote address        */
};

/* specific parameters for a vxlan interface */
struct cm_vxlan_params {
	u_int32_t		vni;		/* vxlan id */
	u_int32_t		link_ifuid;	/* default gw */
	u_int16_t		dst_port;	/* destination port */
	u_int16_t		src_minport;	/* source port */
	u_int16_t		src_maxport;	/* source port */
	u_int8_t		ttl;
	u_int8_t		tos;
#define CP_VXLAN_IFACE_F_LEARN		0x1
	u_int8_t		flags;
	u_int8_t		reserved[3];
	u_int32_t		vnb_nodeid;	/* ng_ether node ID */
	struct in_addr		*gw4;		/* default gw */
	struct in6_addr		*gw6;		/* default gw */
	struct in_addr		*saddr4;	/* default src address */
	struct in6_addr		*saddr6;	/* default src address */
};

struct cm_vxlan_fdb {
	u_int32_t		ifuid;		/* corresponding interface */
	u_int32_t		vni;		/* vxlan id */
	u_int32_t		output_ifuid;	/* output interface */
	u_int16_t		dst_port;	/* destination port */
	u_int8_t		family;		/* address family */
	u_int8_t		state;		/* neighbour state */
	u_int8_t		mac[6];
	u_int8_t		reserved[8];
};

/* specific parameters for a vlan interface */
struct cm_vlan_params {
	u_int32_t	flags;
	u_int32_t	lower_ifuid;
	u_int16_t	vlan_id;
};

/* specific parameters for a macvlan interface */
struct cm_macvlan_params {
	u_int32_t	link_ifuid;
	u_int32_t	mode;
	u_int16_t	flags;
};

/* specific parameters for bridge port interfaces */
struct cm_brport_params {
	u_int8_t		state;
	u_int8_t		flags; /* use flags defined in fpc.h/struct cp_brport */
};

/* specific parameters for bonding slaves interfaces */
struct cm_bonding_params {
	u_int32_t	active_slave_ifuid;
	u_int16_t	ad_info_aggregator;
	u_int16_t	ad_info_num_ports;
	u_int8_t	mode;
};

struct cm_slave_bonding {
	u_int32_t	link_failure_count;
	u_int32_t	queue_id;
	u_int16_t	aggregator_id;
	u_int8_t	state;
	u_int8_t	link;
	char		perm_hwaddr[6];
};

/* specific parameters for GRE interfaces */
struct cm_gre_params {
	u_int32_t	link_ifuid; /* ifuid of the linked iface */
	u_int16_t	iflags;     /* ingoing packet flags      */
	u_int16_t	oflags;     /* outgoing packet flags     */
	u_int32_t	ikey;       /* ingoing packet key        */
	u_int32_t	okey;       /* outgoing packet key       */
	u_int8_t	ttl;
	u_int8_t	tos;
	u_int8_t	inh_tos;
	u_int8_t	family;     /* IP tunnel familly         */
	/* Tunnel local address */
	union {
		struct in_addr	local;
		struct in6_addr	local6;
	};
	/* Tunnel remote address */
	union {
		struct in_addr	remote;
		struct in6_addr	remote6;
	};
	u_int8_t	mode;  /* GRE mode (IP or Ethernet) */
};

struct cm_iface;
struct nlmsghdr;
struct if_set;

typedef struct cm_iface *(*cm_iface_alloc_func_t)(u_int32_t cm_type);
typedef void   (*cm_iface_func_t)(struct cm_iface *, struct nlmsghdr *, struct nlattr **);

struct cm_iface_handler {
	cm_iface_alloc_func_t cm_iface_alloc; /* cm_iface structure alloc */
	cm_iface_func_t cm_iface_create; /* handle nl iface create msg */
	cm_iface_func_t cm_iface_change; /* handle nl iface change msg */
	cm_iface_func_t cm_iface_delete; /* handle nl iface delete msg */
};

const struct cm_iface_handler * cm_iface_handler_lookup(u_int32_t cm_type);

extern int cm2cp_iface_create (u_int32_t, u_int32_t, struct cm_iface *);
extern int cm2cp_svti_create (u_int32_t, u_int32_t, struct cm_iface *);
extern int cm2cp_vti_create (u_int32_t, u_int32_t, struct cm_iface *);
#ifdef CONFIG_CACHEMGR_VXLAN
extern int cm2cp_vxlan_create (u_int32_t, u_int32_t, struct cm_iface *);
extern int cm2cp_fdb(u_int32_t, u_int32_t, struct cm_vxlan_fdb *, void *);
#endif
#ifdef CONFIG_CACHEMGR_VLAN
extern int cm2cp_vlan_create (u_int32_t, u_int32_t, struct cm_iface *);
#endif
#ifdef CONFIG_CACHEMGR_MACVLAN
extern int cm2cp_macvlan_create (u_int32_t, u_int32_t, struct cm_iface *);
#endif
#ifdef CONFIG_CACHEMGR_BRIDGE
extern int cm2cp_brport_update(u_int32_t, u_int32_t, struct cm_iface *);
#endif
#ifdef CONFIG_CACHEMGR_BONDING
extern int cm2cp_bonding_create(u_int32_t, u_int32_t, struct cm_iface *);
extern int cm2cp_slave_bonding_update(u_int32_t, u_int32_t, u_int32_t,
				      struct cm_slave_bonding *);
#ifdef HAVE_IFLA_BOND
struct nlsock;
extern void cm_nl_bonding_dump(int sock, short evtype, void *data);
extern void cm_nl_bonding_init(struct nlsock *cmn);
extern void cm_nl_bonding_destroy(struct nlsock *cmn);
#endif /* HAVE_IFLA_BOND */
#endif /* CONFIG_CACHEMGR_BONDING */
#ifdef CONFIG_CACHEMGR_GRE
extern int cm2cp_gre_create(u_int32_t, u_int32_t, struct cm_iface *, uint8_t mode);
#endif
extern int cm2cp_6in4_create (u_int32_t, u_int32_t, struct cm_iface *);
extern int cm2cp_Xin6_create (u_int32_t, u_int32_t, struct cm_iface *);
extern int cm2cp_iface_state (u_int32_t, u_int32_t, u_int32_t, u_int32_t);
extern int cm2cp_iface_mtu (u_int32_t, u_int32_t, u_int32_t);
extern int cm2cp_iface_master (u_int32_t, u_int32_t, u_int32_t);
extern int cm2cp_iface_mac (u_int32_t, u_int32_t, u_int8_t*, u_int32_t);
extern int cm2cp_iface_bladeinfo(u_int32_t, u_int32_t, u_int8_t);
extern int cm2cp_fpib_change (u_int32_t cookie, struct cm_iface *);
extern int cm2cp_veth_peer (u_int32_t, u_int32_t, u_int32_t);

extern int cm2cp_ipv4_route (u_int32_t, u_int32_t, u_int32_t, u_int32_t, struct in_addr *,
		u_int8_t, struct in_addr *, u_int8_t, u_int32_t, u_int32_t, struct nh_mark *);
extern int cm2cp_ipv4_mroute (u_int32_t, u_int32_t, struct in_addr *,
		u_int32_t, struct in_addr *, u_int32_t, u_int32_t, u_int32_t *);
extern int cm2cp_ipv6_route (u_int32_t, u_int32_t, u_int32_t, struct in6_addr *,
		u_int8_t, struct in6_addr *, u_int8_t, u_int32_t, u_int32_t, struct nh_mark *);
extern int cm2cp_ipv6_mroute (u_int32_t, u_int32_t, struct in6_addr *,
		u_int32_t, struct in6_addr *, u_int32_t, u_int32_t, u_int32_t * );
extern int cm2cp_iface_ttl (u_int32_t, u_int32_t, u_int8_t);
extern int cm2cp_iface_tos (u_int32_t, u_int32_t, u_int8_t, u_int8_t);

extern int cm2cp_l2 (u_int32_t cookie, u_int8_t state, u_int32_t ifindex, u_int8_t family,
		void *addr, struct cm_eth_params *params, u_int32_t uid);


/* IPsec commands */

/* defined in cm_ipsec_pub.h */
struct cm_ipsec_sa;
struct cm_ipsec_sp;

extern int cm2cp_ipsec_sa_create (u_int32_t cookie, struct cm_ipsec_sa *sa);
extern int cm2cp_ipsec_sa_delete (u_int32_t cookie, struct cm_ipsec_sa *sa);
extern int cm2cp_ipsec_sa_flush (u_int32_t cookie, uint32_t vrfid);
extern int cm2cp_ipsec_sa_replaywin (u_int32_t cookie, struct cm_ipsec_sa *sa);

extern int cm2cp_ipsec_sp_create (u_int32_t cookie, struct cm_ipsec_sp *sp, int update);
extern int cm2cp_ipsec_sp_delete (u_int32_t cookie, struct cm_ipsec_sp *sp);
extern int cm2cp_ipsec_sp_flush (u_int32_t cookie, uint32_t vrfid, uint32_t svti);

#define CM_ALIGN(x,a) ((x + a - 1) & ~(a - 1))
#define CM_ALIGN32(a) (1 + (((a) - 1) | (32 - 1)))
#define CM_ALIGNUNIT8(a) ((a + 7) >> 3)

#ifdef CONFIG_CACHEMGR_EBTABLES
extern struct timeval tv_ebt_timer;
extern struct event *ev_ebt_timer;

extern int cm2cp_ebt_update (struct cp_ebt_table *info);
#endif

#define CM_SYSCTL_NFCT_LIBERAL    "/proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_be_liberal"
struct cp_nftable;
struct cp_nf6table;
extern int cm2cp_nf_update (u_int32_t cookie, struct cp_nftable *info);
extern int cm2cp_nf6_update (u_int32_t cookie, struct cp_nf6table *info);

struct cp_nfct;
extern int cm2cp_nfct_create(u_int32_t cookie, struct cp_nfct *nfct);
extern int cm2cp_nfct_delete(u_int32_t cookie, struct cp_nfct *nfct);
extern int cm2cp_nfct_flush(u_int32_t cookie);
struct cp_nf6ct;
extern int cm2cp_nf6ct_create(u_int32_t cookie, struct cp_nf6ct *nf6ct);
extern int cm2cp_nf6ct_delete(u_int32_t cookie, struct cp_nf6ct *nf6ct);
extern int cm2cp_nfcpe_delete(u_int32_t cookie, u_int32_t cpeid);

struct cp_bpf;
extern int cm2cp_bpf_update(u_int32_t cookie, struct cp_bpf *info);
extern int cm2cp_graceful_done(u_int32_t cookie);

#endif /* __CM_PUB_H_ */
