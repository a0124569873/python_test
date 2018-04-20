/*
 * Copyright(c) 2007 6WIND
 */

#ifndef __FP_IF_H__
#define __FP_IF_H__

#include "fp-seqlock.h"

/* volatile statistics */
typedef struct fp_if_stats {
	uint64_t    ifs_ipackets;    /* packets received on interface */

	uint64_t    ifs_ibytes;      /* total number of octets received */

	uint64_t    ifs_opackets;    /* packets sent on interface */

	uint64_t    ifs_obytes;      /* total number of octets sent */

	uint32_t    ifs_ierrors;     /* input errors on interface */
	uint32_t    ifs_imcasts;     /* packets received via multicast */
	uint32_t    ifs_oerrors;     /* output errors on interface */
	uint32_t    ifs_ilasterror;  /* last input error code */

	uint32_t    ifs_idropped;    /* input packets dropped on interface */
	uint32_t    ifs_odropped;    /* output packets dropped on interface */
	uint32_t    ifs_ififoerrors; /* input fifo errors on interface */
	uint32_t    ifs_ofifoerrors; /* output fifo errors on interface */
} __fpn_cache_aligned fp_if_stats_t;

#ifdef FP_IF_STATS_PER_CORE
#define FP_IF_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_IF_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FP_IF_STATS_DEC(st, field)          FP_STATS_PERCORE_DEC(st, field)
#define FP_IF_STATS_SUB(st, field, val)     FP_STATS_PERCORE_SUB(st, field, val)
#define FP_IF_STATS_NUM                     FPN_MAX_CORES
#else
#define FP_IF_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FP_IF_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FP_IF_STATS_DEC(st, field)          FP_STATS_DEC(st, field)
#define FP_IF_STATS_SUB(st, field, val)     FP_STATS_SUB(st, field, val)
#define FP_IF_STATS_NUM                     1
#endif


/* Size of the ports table in shared memory. The index of a port must
 * not be greater or equal than this value. */
#ifdef CONFIG_MCORE_MAX_PORT
#define FP_MAX_PORT CONFIG_MCORE_MAX_PORT
#else
#define FP_MAX_PORT 256
#endif

/* portid is stored as 8-bit : ensure a max value for the port number */
#if FP_MAX_PORT > 256
#error "Please check value of CONFIG_MCORE_MAX_PORT"
#endif

/* ensure that all SDK ports can be handled by fpn-6wind */
#if defined(CONFIG_MCORE_L2_INFRA)
  #if FP_MAX_PORT < FPN_ALL_PORTS
  #error "Not all SDK ports can be managed"
  #endif
#else
  #if FP_MAX_PORT < FPN_MAX_PORTS
  #error "Not all SDK ports can be managed"
  #endif
#endif

/*  Size of the ifnet table in shared memory. The ifnet table contains:
 *    - the physical ports
 *    - the virtual interfaces (bnet, ethgrp, vrrp, gre, ...)
 *    - the loopback interfaces (one per VR)
 *  This value MUST be greater than (port count + max virtual if + max vr).
 *  Remember to increase it when increasing the number of VR. */
#ifdef CONFIG_MCORE_MAX_IFNET
#define FP_MAX_IFNET (CONFIG_MCORE_MAX_IFNET + 1)
#else
#define FP_MAX_IFNET 256
#endif

#define FP_IFNET_VIRTUAL_PORT  FPN_RESERVED_PORTID_VIRT
#define FP_MAX_VIRTUAL_IF (FP_MAX_IFNET - FP_MAX_PORT - FP_MAX_VR)

#if FP_MAX_VIRTUAL_IF < 0
#error "Please check values of FP_MAX_IFNET, FP_MAX_PORT, FP_MAX_VR"
#endif

/* Ifnet hashtable order (the number of buckets in the table is 2 ^
 * order). The maximum value is 16, which corresponds to 65536 buckets
 * in the hashtable. */
#ifdef CONFIG_MCORE_IFNET_HASH_ORDER
#define FP_IFNET_HASH_ORDER         CONFIG_MCORE_IFNET_HASH_ORDER
#else
#define FP_IFNET_HASH_ORDER         8
#endif

/* depends on FP_IFNET_HASH_ORDER */
#define FP_IFNET_HASH_SIZE          (1 << FP_IFNET_HASH_ORDER)
#define FP_IFNET_HASH_MASK          (FP_IFNET_HASH_SIZE -1)
#include "fp-jhash.h"

/* return the hash from name */
/* algorithm taken from ng_base's NG_HOOK_NAMEHASH function */
static inline uint32_t fp_ifnet_hash_name(const char *name)
{
	uint32_t h = 5381;
	const u_char *c;
	for (c = (const u_char *)name; *c; c++)
		h = ((h << 5) + h) + *c;

	return h & FP_IFNET_HASH_MASK;
}

struct fp_ifnet;
struct mbuf;

enum {
	RX_DEV_OPS = 0,
	TX_DEV_OPS,
	IP_OUTPUT_OPS,
	FP_IFNET_MAX_OPS
};

typedef int (rx_dev_ops_t)(struct mbuf *m, struct fp_ifnet *, void *data);
typedef int (tx_dev_ops_t)(struct mbuf *m, struct fp_ifnet *, void *data);
typedef int (ip_output_ops_t)(struct mbuf *m, struct fp_ifnet *, int af,
                              void *data);

#define INVALID_FUNC ((uint64_t) -1)

typedef struct {
	uint64_t func;
	uint64_t data;
	int16_t  mod_uid;
} fp_ifnet_ops_t;

typedef int (*fp_if_add_fn)(uint16_t vrfid, const char* name,
                            const uint8_t *mac, uint32_t mtu, uint32_t ifuid,
                            uint8_t port, uint8_t type);

typedef struct fp_if_notifier {
	FPN_SLIST_ENTRY(fp_if_notifier) next;
	fp_if_add_fn add;
} fp_if_notifier_t;

int fp_if_notifier_register(fp_if_notifier_t *notifier);

#define FP_IFNAMSIZ 16

typedef struct fp_ifnet {
	uint32_t        if_ifuid;         /* interface unique ID, in network order */
	uint16_t        if_flags;
	uint8_t         if_port;
	uint8_t         if_type;

	uint8_t         if_mac[6];     /* MAC address */
	uint8_t         pad[2];

	/* per ifuid hash table chaining */
	fp_hlist_node_t  ifuid_hlist;

#ifdef CONFIG_MCORE_TCP_MSS
	uint32_t        if_tcp4mss; /* Interface tcp4mss */
	uint32_t        if_tcp6mss; /* Interface tcp6mss */
#endif
	uint16_t        if_mtu;
	uint16_t        if_vrfid;
	uint32_t        sub_table_index; /* index in sub-table, if applicable */

	/* per name hash table chaining */
	fp_hlist_node_t name_hlist;

	uint32_t	if_nb_rt4;  /* Nb of IPv4 routes using this interface */
	uint32_t	if_nb_rt6;  /* Nb of IPv6 routes using this interface */

	uint32_t        if_master_ifuid;
	uint8_t         if_blade;      /* blade where physical port lies */
	uint8_t         pad2[2];

	char            if_name[FP_IFNAMSIZ]; /* name, e.g. eth0_0 */

	fp_if_stats_t   if_stats[FP_IF_STATS_NUM];

#ifdef CONFIG_MCORE_IP
	uint32_t        if_addr4_head_index; /* index of the first addr4 in the pool */
	uint32_t        if_nb_addr4;    /* number of ipv4 addresses */
#endif

#ifdef CONFIG_MCORE_IPV6
	uint32_t        if_addr6_head_index; /* index of the first addr6 in the pool */
	uint32_t        if_nb_addr6;    /* number of ipv6 addresses */
#endif

	fp_seqlock_t    seqlock;
	fp_ifnet_ops_t	if_ops[FP_IFNET_MAX_OPS];
} fp_ifnet_t;

typedef struct fp_ifnet_table {
	fp_ifnet_t      table[FP_MAX_IFNET];
	fp_hlist_head_t hash[FP_IFNET_HASH_SIZE];
	fp_hlist_head_t name_hash[FP_IFNET_HASH_SIZE];
} fp_ifnet_table_t;

#ifdef CONFIG_MCORE_VRF
#define ifuid2vrfid(x)   __fp_ifuid2ifnet(x)->if_vrfid
#define ifp2vrfid(i)       (i)->if_vrfid
#else
#define ifuid2vrfid(x)     0
#define ifp2vrfid(i)       0
#endif

/* 8 bits */
#define FP_IFTYPE_LOCAL         2
#define FP_IFTYPE_LOOP          3
#define FP_IFTYPE_XIN4          4
#define FP_IFTYPE_XIN6          5
#define FP_IFTYPE_SVTI          6
#define FP_IFTYPE_GRE           7

/* ethernet types are >= 128 */
#define FP_IFTYPE_MASK_ETHER    0x80
#define FP_IFTYPE_ETHER         128
#define FP_IFTYPE_EIFACE        129
#define FP_IFTYPE_XVRF          130
#define FP_IFTYPE_VXLAN         131
#define FP_IFTYPE_VLAN          132
#define FP_IFTYPE_BRIDGE        133
#define FP_IFTYPE_BONDING       134
#define FP_IFTYPE_MACVLAN       135
#define FP_IFTYPE_VETH          136
#define FP_IFTYPE_GRETAP        137
#define FP_IFTYPE_MAX           137

#define FP_IS_IFTYPE_ETHER(type) ((type) & FP_IFTYPE_MASK_ETHER)

/*
 * This MUST be kept in sync with fpc.h
 */
#define IFF_CP_MASK             0x00ff
#define IFF_CP_UP               0x0001   /* Interface is up      */
#define IFF_CP_RUNNING          0x0002   /* Interface is running */
#define IFF_CP_PREFERRED        0x0004   /* Preferred interface for ECMP */
#define IFF_CP_PROMISC          0x0010   /* Receive all packets  */
#define IFF_CP_IPV4_FWD         0x0020   /* Forward IPv4 packets */
#define IFF_CP_IPV6_FWD         0x0040   /* Forward IPv6 packets */
#define IFF_CP_IPV4_RPF         0x0080   /* IPv4 RPF check */

/*
 * Internal (FP) flags, MUST be in the upper 8 bits
 * to avoid conflicts with Control Plan flags
 */
#define IFF_FP_MASK             0xff00
#define IFF_FP_PREF             0x1000 /* Interface is preferred */
#define IFF_FP_IPV4_FORCE_REASS 0x2000 /* Force reassembly of IPv4 packets on input */
#define IFF_FP_IPV6_FORCE_REASS 0x4000 /* Force reassembly of IPv6 packets on input */
#define IFF_FP_LOCAL_OUT        0x8000 /* The Local flags is used for virtual-port */
#define IFF_FP_IPV6_RPF         0x0100 /* IPv6 RPF check */
#define IFF_FP_IPV4_RPF         0x0200 /* IPv4 RPF check */
#define IFF_FP_IVRRP            0x0400 /* Interface will support Internal VRRP */

/* operative means up and running */
static inline int fp_ifnet_is_operative(fp_ifnet_t *ifp)
{
	return ((ifp->if_flags & (IFF_CP_UP|IFF_CP_RUNNING)) ==
			                 (IFF_CP_UP|IFF_CP_RUNNING));
}

typedef struct fp_ifport {
	uint32_t ifuid;
	union {
		uint64_t u64;
		fp_ifnet_t *ifp;
	} u;
} fp_ifport_t;
#define cached_ifp u.ifp

extern int fp_ifp_is_preferred(const uint32_t ifuid);
extern int fp_setifnet_preferred(fp_ifnet_t *ifp, const int pref);
extern int fp_setifnet_down (fp_ifnet_t *ifp);
extern void fp_rt4_ifscrub (const fp_ifnet_t *ifp);
extern int fp_setifnet_veth_peer(const uint32_t ifuid,
				 const uint32_t peer_ifuid);

void fp_ifnet_ifuid_link(fp_ifnet_t *ifp);
void fp_ifnet_ifuid_unlink(fp_ifnet_t *ifp);


void fp_ifnet_name_link(fp_ifnet_t *ifp);
void fp_ifnet_name_unlink(fp_ifnet_t *ifp);


int fp_ifnet_ops_register(fp_ifnet_t *ifp, int type,
			  uint16_t mod_uid, void *data);
void fp_ifnet_ops_unregister(fp_ifnet_t *ifp, int type);
void *fp_ifnet_ops_cache(fp_ifnet_t *ifp, int type, void **data);

static inline void *fp_ifnet_ops_get_data(fp_ifnet_t *ifp, int type)
{
	return ((void *)(size_t) ifp->if_ops[type].data);
}

static inline void *fp_ifnet_ops_get_func(fp_ifnet_t *ifp, int type)
{
	return ((void *)(size_t) ifp->if_ops[type].func);
}

static inline uint16_t fp_ifnet_ops_get_moduid(fp_ifnet_t *ifp, int type)
{
	return ifp->if_ops[type].mod_uid;
}

static inline void *fp_ifnet_ops_get(fp_ifnet_t *ifp, int type, void **data)
{
	void *func;

	/* If cache is clean, find the correct function to call */
	func = fp_ifnet_ops_get_func(ifp, type);
	if (func == (void *)(size_t) INVALID_FUNC) {
		func = fp_ifnet_ops_cache(ifp, type, data);
	} else
		*data = fp_ifnet_ops_get_data(ifp, type);

	return(func);
}

#ifdef CONFIG_MCORE_VRF
int fp_set_if_vrfid(const char *name, uint16_t vrfid);
#endif

#endif
