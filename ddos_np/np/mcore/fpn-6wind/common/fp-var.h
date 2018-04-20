/*
 * Copyright(c) 2006 6WIND
 */
#ifndef __FP_VAR_H__
#define __FP_VAR_H__

#include "ddos_log.h"
#ifdef CONFIG_MCORE_KTABLES
#include <ktables_config.h>
#endif

#ifdef CONFIG_MCORE_IPSEC
#include "fpn-crypto-algo.h"
#endif

#define FP_CONTINUE     0
#define FP_NONE         1
#define FP_DONE         2
#define FP_DROP         3
#define FP_KEEP         4

/* Maximum number of VR in Fastpath. Note that increasing this value
 * implies to increase the value of CONFIG_MCORE_MAX_IFNET. If this
 * value is set to a high value, you should consider to enable
 * CONFIG_MCORE_RT_IP_BASE8 and CONFIG_MCORE_RT_IPV6_BASE8 to save memory. */
#ifdef CONFIG_MCORE_VRF
#  ifdef CONFIG_MCORE_MAX_VR
#    define FP_MAX_VR CONFIG_MCORE_MAX_VR
#  else
#    if defined(CONFIG_MCORE_RT_IP_BASE8) && \
       (!defined(CONFIG_MCORE_IPV6) || defined(CONFIG_MCORE_RT_IPV6_BASE8))
#      define FP_MAX_VR   16
#    else
#      define FP_MAX_VR   4
#    endif
#  endif
#else
#  define FP_MAX_VR       1
#endif

/*
 *
 * Minimal values are for the following configuration
 *   IPv4 : 2 addresses /24 belonging to the same /16
 *          2 ARP entries belonging to the respective /24
 *          2 /16 routes
 *   IPv6 : 2 addresses /64 belonging to the same /48
 *          2 NDP entries belonging to the respective /64
 *          2 /48 routes belonging to the same /32 as the addresses.
 *
 */

/* Change here the size of each intermediate table */
#ifdef CONFIG_MCORE_RT_IP_BASE8
#	define NB_IPV4_8_MIN_ENTRIES       (FP_MAX_VR * 14)
#	define NB_IPV4_16_TABLE_ENTRIES     0
#else
#	define NB_IPV4_8_MIN_ENTRIES       (FP_MAX_VR * 7)
#	define NB_IPV4_16_TABLE_ENTRIES    FP_MAX_VR
#endif

#ifdef CONFIG_MCORE_IPV4_8_TABLE_ENTRIES
#	if CONFIG_MCORE_IPV4_8_TABLE_ENTRIES < NB_IPV4_8_MIN_ENTRIES
#		error "CONFIG_MCORE_IPV4_8_TABLE_ENTRIES is smaller than min value (NB_IPV4_8_MIN_ENTRIES)"
#	endif
#	define NB_IPV4_8_TABLE_ENTRIES CONFIG_MCORE_IPV4_8_TABLE_ENTRIES
#else
#	define NB_IPV4_8_TABLE_ENTRIES (NB_IPV4_8_MIN_ENTRIES + 10000)
#endif

#ifdef CONFIG_MCORE_IPV6

#ifdef CONFIG_MCORE_RT_IPV6_BASE8
#	define NB_IPV6_8_MIN_ENTRIES      (FP_MAX_VR * 40)
#	define NB_IPV6_16_TABLE_ENTRIES   0
#else
#	define NB_IPV6_8_MIN_ENTRIES      (FP_MAX_VR * 28)
#	define NB_IPV6_16_TABLE_ENTRIES   FP_MAX_VR
#endif

#ifdef CONFIG_MCORE_IPV6_8_TABLE_ENTRIES
#	if CONFIG_MCORE_IPV6_8_TABLE_ENTRIES < NB_IPV6_8_MIN_ENTRIES
#		error "CONFIG_MCORE_IPV6_8_TABLE_ENTRIES is smaller than min value (NB_IPV6_8_MIN_ENTRIES)"
#	endif
#	define NB_IPV6_8_TABLE_ENTRIES CONFIG_MCORE_IPV6_8_TABLE_ENTRIES
#else
#	define NB_IPV6_8_TABLE_ENTRIES (NB_IPV6_8_MIN_ENTRIES + 1000)
#endif

#else /* CONFIG_MCORE_IPV6 */
#define NB_IPV6_8_TABLE_ENTRIES     0
#define NB_IPV6_16_TABLE_ENTRIES    0
#endif /* CONFIG_MCORE_IPV6 */

#define FP_NB_8_TABLE_ENTRIES   (NB_IPV4_8_TABLE_ENTRIES + NB_IPV6_8_TABLE_ENTRIES)
#define FP_NB_16_TABLE_ENTRIES  (NB_IPV4_16_TABLE_ENTRIES + NB_IPV6_16_TABLE_ENTRIES)

#define FP_NB_8_ENTRIES         (FP_NB_8_TABLE_ENTRIES*(1<<8))
#define FP_NB_16_ENTRIES        (FP_NB_16_TABLE_ENTRIES*(1<<16))

/* Change here the size of RT & NH tables */
#ifdef CONFIG_MCORE_IPV4_NBRTENTRIES
#define FP_IPV4_NBRTENTRIES (CONFIG_MCORE_IPV4_NBRTENTRIES + 1)
#else
#define FP_IPV4_NBRTENTRIES     50000   /* maximum # IPv4 routes    */
#endif

#ifdef CONFIG_MCORE_IPV4_NBNHENTRIES
#define FP_IPV4_NBNHENTRIES (CONFIG_MCORE_IPV4_NBNHENTRIES + 1)
#else
#define FP_IPV4_NBNHENTRIES     5000    /* max # IPv4 next hops     */
#endif
#define FP_IPV4_NH_ROUTE_LOCAL      FP_IPV4_NBNHENTRIES
#define FP_IPV4_NH_ROUTE_BLACKHOLE  FP_IPV4_NBNHENTRIES+1

#ifdef CONFIG_MCORE_IPV6
#ifdef CONFIG_MCORE_IPV6_NBRTENTRIES
#define FP_IPV6_NBRTENTRIES (CONFIG_MCORE_IPV6_NBRTENTRIES + 1)
#else
#define FP_IPV6_NBRTENTRIES     50000   /* maximum # IPv6 routes    */
#endif
#define FP_IPV6_NH_ROUTE_LOCAL      FP_IPV6_NBNHENTRIES
#define FP_IPV6_NH_ROUTE_BLACKHOLE  FP_IPV6_NBNHENTRIES+1

#ifdef CONFIG_MCORE_IPV6_NBNHENTRIES
#define FP_IPV6_NBNHENTRIES (CONFIG_MCORE_IPV6_NBNHENTRIES + 1)
#else
#define FP_IPV6_NBNHENTRIES     5000    /* max # IPv6 next hops     */
#endif

#endif /* CONFIG_MCORE_IPV6 */


#ifdef CONFIG_MCORE_MAX_MPATH
#define FP_MAX_MPATH CONFIG_MCORE_MAX_MPATH
#else
#define FP_MAX_MPATH    4
#endif



#ifdef CONFIG_MCORE_RT_IP_BASE8
#if FP_MAX_VR > NB_IPV4_8_TABLE_ENTRIES
#error "Too many VRs"
#endif
#else
#if FP_MAX_VR > NB_IPV4_16_TABLE_ENTRIES
#error "Too many VRs"
#endif
#endif

#ifdef CONFIG_MCORE_IPV6
#ifdef CONFIG_MCORE_RT_IPV6_BASE8
#if FP_MAX_VR > NB_IPV6_8_TABLE_ENTRIES
#error "Too many VRs"
#endif
#else
#if FP_MAX_VR > NB_IPV6_16_TABLE_ENTRIES
#error "Too many VRs"
#endif
#endif
#endif /* CONFIG_MCORE_IPV6 */

#include "netinet/fp-in.h"
#ifdef CONFIG_MCORE_IPV6
#include "netinet/fp-in6.h"

#if (defined(CONFIG_MCORE_RT_IP_BASE8) && defined(CONFIG_MCORE_RT_IPV6_BASE8)) || \
	(!defined(CONFIG_MCORE_RT_IP_BASE8) && !defined(CONFIG_MCORE_RT_IPV6_BASE8))
/*
 * Both protocols use the same table size for per VR first word
 * look-up. IPv4 uses the 1st FP_MAX_VR tables, IPv6 should use
 * the tables from FP_MAX_VR.
 */
#define FP_IPV6_TABLE_START          FP_MAX_VR
#else
/*
 * IPv4 uses the 1st FP_MAX_VR 8-tables and IPv6 uses the 1st
 * FP_MAX_VR 16-tables (or the other way round), so no offset is
 * needed in a shared pool.
 */
#define FP_IPV6_TABLE_START          0
#endif

#ifdef CONFIG_MCORE_RT_IPV6_BASE8
/*
 * Configure a lookup of IPv6 route entries that uses a hard-wired 16-level
 * decompositon of an IPv6 address into 16 successive bytes starting from
 * the left Most Significant Byte (MSB).
 */
#define FP_IPV6_NBLAYERS       16
#define FP_IPV6_LAYER_WIDTH(level) 8

#else
/*
 * Configure a lookup of IPv6 route entries that uses a hard-wired 15-level
 * decompositon of an IPv6 address into one 16-bit word followed by 14
 * successive bytes.
 */
#define FP_IPV6_NBLAYERS       15
#define FP_IPV6_LAYER_WIDTH(level) \
	(((level) == 0) ? 16 : 8)
#endif


#endif /* CONFIG_MCORE_IPV6 */

#include "fp-stats-defs.h"

/*
 * Most fields are for insertion/suppression management
 * and used by FPM.  The few fields used by FP are marked
 * as (FP).
 */

#define FP_VRFID_MASK  0xFFFF

/* Fast Path hash order for IPv4/IPv6 neighbour */
#ifdef CONFIG_MCORE_NEIGH_HASH_ORDER
#define FP_NEIGH_HASH_ORDER     CONFIG_MCORE_NEIGH_HASH_ORDER
#else
#define FP_NEIGH_HASH_ORDER     13
#endif
#define FP_NEIGH_HASH_SIZE      (1 << FP_NEIGH_HASH_ORDER)

/*
 *
 * Next Hop info
 */
typedef struct fp_nh_entry {
	struct {
		uint8_t ether_dhost[6];
		uint8_t ether_shost[6];
		uint16_t ether_type;
	} __attribute__ ((packed)) nh_eth;	/* (FP) Full eth header cache */

	uint8_t    nh_hitflag;			/* RW (FP) and fpm: keep it as plain field */
	uint8_t    nh_priority;

#ifdef CONFIG_MCORE_NEXTHOP_MARKING
	/* Mark to apply to mbuf when matching this nexthop */
	uint32_t   nh_mark;
	uint32_t   nh_mask;
#endif

	uint32_t   nh_ifuid;			/* (FP) if ifuid */
	uint32_t    rt_type        : 8;  /* (FP) Route type */
#define RT_TYPE_EXCEPTION_MASK       0xf0
#define RT_TYPE_ROUTE                0x00
#define RT_TYPE_NEIGH                0x01
#define RT_TYPE_ROUTE_CONNECTED      0x02
#define RT_TYPE_ADDRESS              0xf0
#define RT_TYPE_ROUTE_LOCAL          0xf1
#define RT_TYPE_ROUTE_BLACKHOLE      0xf2
	uint32_t    nh_l2_state    : 2;		/* (FP) l2 state */
#define L2_STATE_NONE       0
#define L2_STATE_INCOMPLETE 1
#define L2_STATE_STALE      2
#define L2_STATE_REACHABLE  3
	uint32_t    nh_type        : 1;		/* GW or IFACE */
#define NH_TYPE_GW          0
#define NH_TYPE_IFACE       1
	uint32_t   nh_refcnt       : 21;	/* refcount usage */
} _fp_nh_entry_t;

extern uint8_t fp_nh_priority (_fp_nh_entry_t *nhe);
#ifdef CONFIG_MCORE_ECMP_PRIO_ADDRESS
#	define FP_ECMP_PRIO_ADDRESS    CONFIG_MCORE_ECMP_PRIO_ADDRESS
#else
#	define FP_ECMP_PRIO_ADDRESS    128
#endif
#ifdef CONFIG_MCORE_ECMP_PRIO_PREFERRED
#	define FP_ECMP_PRIO_PREFERRED   CONFIG_MCORE_ECMP_PRIO_PREFERRED
#else
#	define FP_ECMP_PRIO_PREFERRED   32
#endif
#ifdef CONFIG_MCORE_ECMP_PRIO_NEIGH
#	define FP_ECMP_PRIO_NEIGH	CONFIG_MCORE_ECMP_PRIO_NEIGH
#else
#	define FP_ECMP_PRIO_NEIGH       8
#endif
#ifdef CONFIG_MCORE_ECMP_PRIO_CONNECTED
#	define FP_ECMP_PRIO_CONNECTED    CONFIG_MCORE_ECMP_PRIO_CONNECTED
#else
#	define FP_ECMP_PRIO_CONNECTED    2
#endif
#ifdef CONFIG_MCORE_ECMP_PRIO_BASE
#	define FP_ECMP_PRIO_BASE    CONFIG_MCORE_ECMP_PRIO_BASE
#else
#	define FP_ECMP_PRIO_BASE         1
#endif
#ifdef CONFIG_MCORE_ECMP_PRIO_LOCAL
#	define FP_ECMP_PRIO_LOCAL    CONFIG_MCORE_ECMP_PRIO_LOCAL
#else
#	define FP_ECMP_PRIO_LOCAL        0
#endif
#ifdef CONFIG_MCORE_ECMP_PRIO_BH
#	define FP_ECMP_PRIO_BH    CONFIG_MCORE_ECMP_PRIO_BH
#else
#	define FP_ECMP_PRIO_BH           0
#endif

typedef struct fp_nh4_entry {
	_fp_nh_entry_t nh;
	union {
		uint32_t    nh_gw;		/* gateway@ or neighbor@ */
		uint32_t    nh_src;		/* src@ (connected routes) */
	};
	uint32_t    next;
	uint32_t    prev;
} fp_nh4_entry_t;

#ifdef CONFIG_MCORE_IPV6
typedef struct fp_nh6_entry {
	_fp_nh_entry_t  nh;
	union {
		fp_in6_addr_t   nh_gw;                /* gateway@ or neighbor */
		fp_in6_addr_t   nh_src;               /* src@ (connected routes) */
	};
	uint32_t    next;
	uint32_t    prev;
} fp_nh6_entry_t;
#endif /* CONFIG_MCORE_IPV6 */


/*
 * route entry
 */
typedef struct fp_rt_entry {
	uint8_t    rt_length;    /* (FP) Prefix length */
	uint8_t    rt_nb_nhp;    /* (FP) Number of Preferred NH */
	uint8_t    rt_nb_nh;     /* Number of Next-Hops */
	uint8_t    rt_pad0;      /* unused */

	uint32_t   rt_next_hop[FP_MAX_MPATH]; /* (FP) list of next-hops */

	uint32_t   rt_neigh_index; /* NH index if one next-hop is ARP */

	uint32_t   rt_refcnt;    /* refcount usage */

	/*
	 * rt_chaining is for overlaping routes (same prefix
	 * different prefix length). The "next" is ALWAYS a
	 * route with smaller prefix length
	 */
	uint32_t   rt_next;

	uint16_t   rt_vrfid;
	uint16_t   rt_pad1;
} _fp_rt_entry_t;

typedef struct fp_rt4_entry {
	_fp_rt_entry_t rt;
#ifdef CONFIG_MCORE_RT4_WITH_PREFIX
	uint32_t       rt4_prefix;
#endif
} fp_rt4_entry_t;
extern uint8_t fp_best_nh4_prio (fp_rt4_entry_t* e);
extern uint8_t fp_nh4_neigh_prio (fp_rt4_entry_t* rte, fp_nh4_entry_t *nhe);

#ifdef CONFIG_MCORE_IPV6
typedef struct fp_rt6_entry {
	_fp_rt_entry_t  rt;
} fp_rt6_entry_t;
extern uint8_t fp_best_nh6_prio (fp_rt6_entry_t* e);
#endif /* CONFIG_MCORE_IPV6 */

/* L3 fw table */

typedef struct {
	uint32_t rt       : 2;   /* (FP) is this entry an RT one  */
#define RT_TABLE    0
#define RT_ROUTE    1

	uint32_t index    :30;   /* (FP) indice in RT or L3 table */
#define RT_INDEX_UNUSED  0

} fp_table_entry_t;


typedef struct fp_table {
	uint32_t used     : 2;   /* Allocated / free              */
#define FP_USED_V4 1
#define FP_USED_V6 2
	uint32_t entries  :30;   /* (FP) First entry index        */
	uint16_t vrfid;
	uint16_t pad;
} fp_table_t;


/* ifnet definition */
#include "fp-if.h"

#ifdef CONFIG_MCORE_BRIDGE
/* L2 statistic */
typedef struct fp_l2_stats {
	uint64_t   L2ForwFrames;
#ifdef CONFIG_MCORE_EBTABLES
	uint64_t   L2DroppedFrames;
#endif
}  __fpn_cache_aligned fp_l2_stats_t;

#ifdef FP_L2_STATS_PER_CORE
#define FP_L2_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_L2_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FP_L2_STATS_NUM                     FPN_MAX_CORES
#else
#define FP_L2_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FP_L2_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FP_L2_STATS_NUM                     1
#endif

#endif /* CONFIG_MCORE_BRIDGE */

/* IPv4/IPv6 statistic */
typedef struct fp_ip_stats {
	uint64_t   IpForwDatagrams;
	uint64_t   IpInDelivers;
	uint64_t   IpDroppedNoArp;
	uint64_t   IpDroppedForwarding;
	uint64_t   IpDroppedBlackhole;
	uint64_t   IpDroppedNetfilter;
	uint64_t   IpReasmReqds;
	uint64_t   IpReasmOKs;
	uint64_t   IpReasmFails;
	uint64_t   IpFragOKs;
	uint64_t   IpFragFails;
	uint64_t   IpFragCreates;
	uint32_t   IpInHdrErrors;
	uint32_t   IpInAddrErrors;
	uint32_t   IpDroppedNoMemory;
	uint32_t   IpDroppedIPsec;
	uint32_t   IpDroppedInvalidInterface;
	uint32_t   IpReasmTimeout;
	uint32_t   IpReasmExceptions;
	uint32_t   IpDroppedNoRouteLocal;
}  __fpn_cache_aligned fp_ip_stats_t;

#ifdef FP_IP_STATS_PER_CORE
#define FP_IP_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_IP_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FP_IP_STATS_NUM                     FPN_MAX_CORES
#else
#define FP_IP_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FP_IP_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FP_IP_STATS_NUM                     1
#endif

#ifdef FP_EXCEP_STATS_PER_CORE
#define FP_EXCEP_STATS_INC(st, field)	FP_STATS_PERCORE_INC(st, field)
#define FP_EXCEP_STATS_NUM	FPN_MAX_CORES
#else
#define FP_EXCEP_STATS_INC(st, field)	FP_STATS_INC(st, field)
#define FP_EXCEP_STATS_NUM	1
#endif

/* Global statistics */
typedef struct fp_global_stats {
	uint64_t   fp_dropped;
	uint64_t   fp_droppedOperative;
} __fpn_cache_aligned fp_global_stats_t;

#ifdef FP_GLOBAL_STATS_PER_CORE
#define FP_GLOBAL_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_GLOBAL_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FP_GLOBAL_STATS_NUM                     FPN_MAX_CORES
#else
#define FP_GLOBAL_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FP_GLOBAL_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FP_GLOBAL_STATS_NUM                     1
#endif

/* ARP answerer statistics */
typedef struct fp_arp_stats {
	uint64_t   arp_errors;      /* invalid packet */
	uint64_t   arp_unhandled;   /* not handled by fast path */
	uint64_t   arp_not_found;   /* the fp doesn't have this address */
	uint64_t   arp_replied;     /* successfully replied */
} __fpn_cache_aligned fp_arp_stats_t;

#ifdef FP_ARP_STATS_PER_CORE
#define FP_ARP_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_ARP_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FP_ARP_STATS_NUM                     FPN_MAX_CORES
#else
#define FP_ARP_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FP_ARP_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FP_ARP_STATS_NUM                     1
#endif

#include "fptun.h"

/* exception statistics */
typedef struct fp_exception_stats {
	uint64_t LocalBasicExceptions; /* packets sent to local NPU */
	uint64_t LocalFPTunExceptions; /* packets sent to local NPU w/ FPTUN encaps */
	uint64_t IntraBladeExceptions; /* exceptions to local blade on remote NPU */
#ifdef CONFIG_MCORE_MULTIBLADE
	uint64_t InterBladeExceptions; /* exceptions sent to remote blade */
#endif
#ifdef CONFIG_MCORE_TAP
	uint64_t TapExceptions;        /* packets tapped by FP */
#endif
	uint64_t LocalExceptionClass[FPTUN_EXC_CLASS_MAX+1];
	uint64_t LocalExceptionType[FPTUN_TYPE_MAX+1];
#ifdef CONFIG_MCORE_MULTIBLADE
	uint64_t RemoteExceptionClass[FPTUN_EXC_CLASS_MAX+1];
	uint64_t RemoteExceptionType[FPTUN_TYPE_MAX+1];
#endif
#ifdef CONFIG_MCORE_MULTICAST4
	uint64_t MulticastExceptions;  /* multicast output exception */
#endif
#ifdef CONFIG_MCORE_MULTICAST6
	uint64_t Multicast6Exceptions; /* multicast IPv6 output exception */
#endif
	uint64_t FptunSizeExceedsCpIfThresh;
	uint64_t FptunSizeExceedsFpibThresh;
} __fpn_cache_aligned fp_exception_stats_t;

#ifdef CONFIG_MCORE_MULTIBLADE
/* multi-blade fast path processing statistics */
typedef struct fp_multiblade_stats {
	/* inter-blade frame output requests */
	uint64_t SentRemotePortOutputRequests;
	uint64_t RcvdRemotePortOutputRequests;
	uint64_t SentRemoteIPsecOutputRequests;
	uint64_t RcvdRemoteIPsecOutputRequests;

	/* multiblade errors */
	uint64_t RcvdLocalBladeUnactive;
	uint64_t RcvdLocalConfigErrors;
	uint64_t SentRemoteExceptionErrors;

	/* update requests */
	uint64_t RcvdRemoteHFSyncRequest;
} fp_multiblade_stats_t;

#ifdef FP_MULTIBLADE_STATS_PER_CORE
#define FP_MULTIBLADE_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_MULTIBLADE_STATS_ADD(st, field, val)     \
                                         FP_STATS_PERCORE_ADD(st, field, val)
#define FP_MULTIBLADE_STATS_NUM                     FPN_MAX_CORES
#else
#define FP_MULTIBLADE_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FP_MULTIBLADE_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FP_MULTIBLADE_STATS_NUM                     1
#endif

#endif

#ifdef CONFIG_MCORE_IPSEC
#include "fp-ipsec.h"
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
#include "fp-ipsec6.h"
#endif
#include "fp-blade.h"

#ifdef CONFIG_MCORE_NETFILTER
#include "fp-netfilter.h"
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
#include "fp-netfilter6.h"
#endif

#include "cJSON.h"

#ifdef CONFIG_MCORE_TC
#include "fp-tc-var.h"
#endif
#if defined(CONFIG_MCORE_XIN4) || defined(CONFIG_MCORE_XIN6)
#include "fp-tunnels-var.h"
#endif
#if defined(CONFIG_MCORE_MULTICAST4) || defined(CONFIG_MCORE_MULTICAST6)
#include "fp-mroute.h"
#endif

#ifdef CONFIG_MCORE_VXLAN
#include "fp-vxlan-var.h"
#endif

#ifdef CONFIG_MCORE_BRIDGE
#include "fp-bridge-var.h"
#endif

#ifdef CONFIG_MCORE_HITFLAGS_SYNC
#include "fp-hitflags.h"
#endif
#include "fp-rfps-conf.h"

typedef union {
	uint64_t u64;
	struct {
#define FP_SHARED_MAGIC32    0x19740417
		uint64_t magic:32;
		uint64_t do_netfilter:1;
		uint64_t do_ipsec_output:1;
		uint64_t do_forced_reassembly:1;
		uint64_t do_tap:1;
		uint64_t do_ipsec_once:1;
		uint64_t do_nf_cache:1;
		uint64_t do_tap_global:1;
		uint64_t do_tap_circular_buffer:1;
		uint64_t do_ipsec6_output:1;
		uint64_t do_ipsec_input:1;
		uint64_t do_ipsec6_input:1;
		uint64_t do_arp_reply:1;
		uint64_t do_netfilter6:1;
		uint64_t do_nf6_cache:1;
		uint64_t do_ebtables:1;
		uint64_t reserved:17;
	} s;
	struct {
		uint32_t magic;
		uint32_t do_func;
#if FPN_BYTE_ORDER == FPN_LITTLE_ENDIAN
#define FP_CONF_DO_NETFILTER    0x00000001
#define FP_CONF_DO_IPSEC_OUT    0x00000002
#define FP_CONF_DO_FORCED_REASS 0x00000004
#define FP_CONF_DO_TAP          0x00000008
#define FP_CONF_DO_IPSEC_ONCE   0x00000010
#define FP_CONF_DO_NF_CACHE     0x00000020
#define FP_CONF_DO_TAP_GLOBAL   0x00000040
#define FP_CONF_DO_TAP_CIRC_BUF 0x00000080
#define FP_CONF_DO_IPSEC6_OUT   0x00000100
#define FP_CONF_DO_IPSEC_IN     0x00000200
#define FP_CONF_DO_IPSEC6_IN    0x00000400
#define FP_CONF_DO_ARP_REPLY    0x00000800
#define FP_CONF_DO_NETFILTER6   0x00001000
#define FP_CONF_DO_NF6_CACHE    0x00002000
#define FP_CONF_DO_EBTABLES     0x00004000
#else
#define FP_CONF_DO_NETFILTER    0x80000000
#define FP_CONF_DO_IPSEC_OUT    0x40000000
#define FP_CONF_DO_FORCED_REASS 0x20000000
#define FP_CONF_DO_TAP          0x10000000
#define FP_CONF_DO_IPSEC_ONCE   0x08000000
#define FP_CONF_DO_NF_CACHE     0x04000000
#define FP_CONF_DO_TAP_GLOBAL   0x02000000
#define FP_CONF_DO_TAP_CIRC_BUF 0x01000000
#define FP_CONF_DO_IPSEC6_OUT   0x00800000
#define FP_CONF_DO_IPSEC_IN     0x00400000
#define FP_CONF_DO_IPSEC6_IN    0x00200000
#define FP_CONF_DO_ARP_REPLY    0x00100000
#define FP_CONF_DO_NETFILTER6   0x00080000
#define FP_CONF_DO_NF6_CACHE    0x00040000
#define FP_CONF_DO_EBTABLES     0x00020000
#endif
#define FP_CONF_NO_FAST_FORWARD	(FP_CONF_DO_NETFILTER | FP_CONF_DO_IPSEC_OUT | \
		FP_CONF_DO_FORCED_REASS | \
		FP_CONF_DO_NETFILTER6)
	} w32;
} fp_conf_t;


/* By default, on a non-debug binary, all log with
 * level <= FP_LOG_DEFAULT are displayed. */
#define FP_LOG_DEFAULT FP_LOG_ERR

/* 48 bits are reserved for logtypes in fp_shared->debug */
#define FP_MAX_LOGTYPES 48

/* log name max length, including terminating null character */
#define FP_LOGNAME_MAXLEN 24

/* module name max length, including terminating null character */
#define FP_MODNAME_MAXLEN 32

/* maximum number of modules in fastpath */
#define FP_MAX_MODULES  512

/* plugin name max length, including terminating null character */
#define FP_PLUGINSNAME_MAXLEN 96

/* maximum number of plugins for fp, fpm or fp-cli */
#define FP_MAX_PLUGINS  8

typedef struct {
	char   name[FP_MODNAME_MAXLEN];
	void * if_ops[FP_IFNET_MAX_OPS];
} fp_module_t;

typedef struct {
#define FP_LOGTYPE_MAIN_PROC        UINT64_C(0x000000000001)
#define FP_LOGTYPE_EXC              UINT64_C(0x000000000002)
#define FP_LOGTYPE_IP               UINT64_C(0x000000000004)
#define FP_LOGTYPE_FRAG             UINT64_C(0x000000000008)
#define FP_LOGTYPE_IPSEC_IN         UINT64_C(0x000000000010)
#define FP_LOGTYPE_IPSEC_OUT        UINT64_C(0x000000000020)
#define FP_LOGTYPE_IPSEC_REPL       UINT64_C(0x000000000040)
#define FP_LOGTYPE_NF               UINT64_C(0x000000000080)
#define FP_LOGTYPE_REASS            UINT64_C(0x000000000100)
#define FP_LOGTYPE_TUNNEL           UINT64_C(0x000000000200)
#define FP_LOGTYPE_NETFPC           UINT64_C(0x000000000400)
#define FP_LOGTYPE_CRYPTO           UINT64_C(0x000000000800)
#define FP_LOGTYPE_VNB              UINT64_C(0x000000001000)
#define FP_LOGTYPE_TAP              UINT64_C(0x000000002000)
#define FP_LOGTYPE_NF_CACHE         UINT64_C(0x000000004000)
#define FP_LOGTYPE_IPSEC_LOOKUP     UINT64_C(0x000000008000)
#define FP_LOGTYPE_HF_SYNC          UINT64_C(0x000000010000)
#define FP_LOGTYPE_TRAFFIC_GEN      UINT64_C(0x000000020000)
#define FP_LOGTYPE_IPSEC6_IN        UINT64_C(0x000000040000)
#define FP_LOGTYPE_IPSEC6_OUT       UINT64_C(0x000000080000)
#define FP_LOGTYPE_IPSEC6_LOOKUP    UINT64_C(0x000000100000)
#define FP_LOGTYPE_RFPS             UINT64_C(0x000000200000)
#define FP_LOGTYPE_SOCKET           UINT64_C(0x000000400000)
#define FP_LOGTYPE_PCB              UINT64_C(0x000000800000)
#define FP_LOGTYPE_TCP              UINT64_C(0x000001000000)
#define FP_LOGTYPE_UDP              UINT64_C(0x000002000000)
#define FP_LOGTYPE_ARP              UINT64_C(0x000004000000)
#define FP_LOGTYPE_RPC              UINT64_C(0x000008000000)
#define FP_LOGTYPE_USO              UINT64_C(0x000010000000)
#define FP_LOGTYPE_VXLAN            UINT64_C(0x000020000000)
#define FP_LOGTYPE_VLAN             UINT64_C(0x000040000000)
#define FP_LOGTYPE_BRIDGE           UINT64_C(0x000080000000)
#define FP_LOGTYPE_BONDING          UINT64_C(0x000100000000)
#define FP_LOGTYPE_GRE              UINT64_C(0x000200000000)
#define FP_LOGTYPE_MACVLAN          UINT64_C(0x000400000000)
#define FP_LOGTYPE_EBTABLES         UINT64_C(0x000800000000)
	/* add more logs type here */
#define FP_LOGTYPE_USER             UINT64_C(0x800000000000)
	uint64_t type:48;

#define FP_LOG_EMERG    0  /* system is unusable               */
#define FP_LOG_ALERT    1  /* action must be taken immediately */
#define FP_LOG_CRIT     2  /* critical conditions              */
#define FP_LOG_ERR      3  /* error conditions                 */
#define FP_LOG_WARNING  4  /* warning conditions               */
#define FP_LOG_NOTICE   5  /* normal but significant condition */
#define FP_LOG_INFO     6  /* informational                    */
#define FP_LOG_DEBUG    7  /* debug-level messages             */
	uint64_t level:8;

#define FP_LOG_MODE_CONSOLE 0
#define FP_LOG_MODE_SYSLOG  1
	uint64_t mode:8;
} fp_debug_t;


#ifdef CONFIG_MCORE_TAP_BPF
/* FP_BPF_MAXINSTANCE: max number of tcpdump -i ethX */
#define FP_BPF_MAXINSTANCE         5
/* Max number of bpf filters for an instance */
#define FP_BPF_MAXFILTERS          63 /* 63 to align size of struct fp_bpf_filter */

typedef struct fp_filter {
	uint16_t  code;
	uint8_t   jt;
	uint8_t   jf;
	uint32_t  k;
} fp_filter_t;

typedef struct fp_bpf_filter {
	uint32_t     ifuid;
	uint16_t     num;                         /* if num == 0, filter is unused */
#define BPF_FILTER_CHECK_ACTIVE	0
#define BPF_FILTER_ACTIVE	1
#define BPF_FILTER_PERMANENT	2
	uint16_t     status;
	fp_filter_t  filters[FP_BPF_MAXFILTERS];
} fp_bpf_filter_t;
#endif /* CONFIG_MCORE_TAP_BPF */

#ifdef CONFIG_MCORE_SOCKET
#include "fp-socket-stat.h"
#include "fp-socket-portset.h"
#endif

#ifdef CONFIG_MCORE_IP
#include "fp-addr-list.h"
#endif

#include "fp-key-hash-table.h"
#define  _KEY_HASH_TABLE_SIZE   (1 << 16)

typedef enum
{
	FLOW_IN = 0,
	PKT_IN,
	FLOW_OUT,
	PKT_OUT,
	FLOW_POL,
	MAX_HOST_ITEM_NUM
}HOST_ITEM;


typedef enum
{
	SYN = 0,
	SYN_SS,
	ACK_RST,
	UDP,
	ICMP,
	TCP_CONN_IN,
	TCP_CONN_OUT,
	TCP_CONN_IP,
	TCP_FRE,
	TCP_IDLE,
	UDP_CONN,
	UDP_FRE,
	ICMP_FRE,
	MAX_HOST_PARAM_ITEM_NUM
}HOST_PARAM_ITEM;

typedef enum
{
	STR = 0,
	END,
	ON_OFF,
	ATK_FRE,
	CON_LMT,
	PRO_MODE,
	MAX_TCP_PORT_PROTECT_ITEM_NUM
}TCP_PORT_PROTECT_ITEM;

typedef enum
{
	U_STR = 0,
	U_END,
	U_ON_OFF,
	U_ATK_FRE,
	PKT_FRE,
	U_PRO_MODE,
	MAX_UDP_PORT_PROTECT_ITEM_NUM
}UDP_PORT_PROTECT_ITEM;

#define HOST_MASK 0x1
#define HOST_PARA_MASK 0x2
#define TCP_PORT_PROTECT_MASK 0x4
#define UDP_PORT_PROTECT_MASK 0x8
#define BLACK_WHITE_GROUP_MASK 0x10
#define SERVER_CONFIG_MASK_ALL 0x1f

enum ddos_shm {
	DDOS_SHM_CONFIG = 0,
	DDOS_SHM_STATUS,
	DDOS_SHM_LOG,
	DDOS_SHM_TMP_B_W,
	DDOS_SHM_TOTAL
};

struct ddos_shm_info {

#define MAX_NAME_LEN   32
	char name[MAX_NAME_LEN];

#define MAX_PATH_LEN   32
	char path[MAX_PATH_LEN];  /*arg for ftok*/

	uint32_t id; /*arg for ftok*/

	uint32_t size;  /*shared memory size*/
};

enum total_flow_strategy {
	TOTAL_FLOW_THRESHOLD,
    TOTAL_FLOW_FORWARD,
};
struct total_status {
    uint32_t   server_ip;

    uint32_t   in_ip_threshold;                           // Mbit
    uint64_t   in_latest_pkt_time;                     // the time unit is msec
    uint64_t   in_last_detect_time;

    uint64_t    in_bps;
    uint64_t   in_current_flow;
    uint64_t   in_bps_after_clean;
    uint64_t   in_current_flow_after_clean;

    uint64_t    in_pps;
    uint64_t   in_last_packets;
    uint64_t   in_current_packets;
    uint64_t   in_pps_after_clean;
    uint64_t   in_current_packets_after_clean;

    uint32_t   out_ip_threshold;
    uint64_t   out_latest_pkt_time;
    uint64_t   out_last_detect_time;

    uint64_t   out_bps;
    uint64_t   out_current_flow;
    uint64_t   out_bps_after_clean;
    uint64_t   out_current_flow_after_clean;

    uint64_t   out_pps;
    uint64_t   out_current_packets;
    uint64_t   out_pps__after_clean;
    uint64_t   out_current_packets_after_clean;

}__attribute__((packed));
struct total_server {
    struct total_status  status;
}__attribute__((packed));
//
#define  PRODUCT_SERIAL_CODE_LEN (16 + 1)

struct veda_serial {
	char data[PRODUCT_SERIAL_CODE_LEN];
} __attribute__((packed));

enum licence_status {
    LICENCE_UNINIT,
    LICENCE_VALID,
    LICENCE_MISSING,
    LICENCE_DEVICE_NOT_MATCH,
    LICENCE_MALFORM,
    LICENCE_EXPIRED,
    LICENCE_TYPE_ERROR
};

enum licence_type {
    LICENCE_TYPE_OFFICIAL,
    LICENCE_TYPE_TEST
};

struct veda_licence {
	char id[16+1];
	enum licence_status status;
	enum licence_type   type;
	char   model[100];
	uint32_t   create_time;
	uint32_t   start_time;
	uint32_t   end_time;
	uint32_t   max_hosts;
	uint32_t   max_flows;
	struct {
		uint32_t alive_time;
		uint32_t sys_tick_count;
		uint32_t utc_timestamp;
	} licence_time;
	char user[100];
	char lang[100];
	char licence_owner[400];
	char copy_right[400];
	char desc[400];
	struct veda_serial product_serial;
} __attribute__((packed));

/* We are using static length tables for now.
 * This will need some optimisation */
typedef struct shared_mem {
	fp_conf_t conf __fpn_cache_aligned;

#ifdef CONFIG_MCORE_KTABLES
	uint8_t ktables[CONFIG_KTABLES_MAX_TABLES][8];
#endif
#ifdef CONFIG_MCORE_NETFILTER
	fp_nf_conf_t nf_conf;
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	fp_nf_conf_t nf6_conf;
#endif

	fp_debug_t debug;

	fp_ifport_t            ifport[FP_MAX_PORT];
	fp_ifnet_table_t       ifnet;
#ifdef CONFIG_MCORE_VRF
	uint32_t               fp_xvrf[FP_MAX_VR];
#endif

	/* Statistics */
	fp_ip_stats_t		ip_stats[FP_IP_STATS_NUM];
#ifdef CONFIG_MCORE_IPV6
	fp_ip_stats_t		ip6_stats[FP_IP_STATS_NUM];
#endif /* CONFIG_MCORE_IPV6 */
	fp_global_stats_t	global_stats[FP_GLOBAL_STATS_NUM] __fpn_cache_aligned;
#ifdef CONFIG_MCORE_BRIDGE
	fp_l2_stats_t		l2_stats[FP_L2_STATS_NUM];
#endif
#ifdef CONFIG_MCORE_SOCKET
	fp_tcp_stats_t		tcp_stats[FP_TCP_STATS_NUM];
	fp_udp_stats_t		udp_stats[FP_UDP_STATS_NUM];
#ifdef CONFIG_MCORE_SOCKET_INET6
	fp_udp6_stats_t		udp6_stats[FP_UDP6_STATS_NUM];
#endif
	fp_socket_portset_t	tcp_portset[FP_MAX_VR];
	fp_socket_portset_t	udp_portset[FP_MAX_VR];
#endif
#ifdef CONFIG_MCORE_ARP_REPLY
	fp_arp_stats_t		arp_stats[FP_ARP_STATS_NUM];
#endif

#ifdef CONFIG_MCORE_MULTIBLADE
	fp_multiblade_stats_t	multiblade_stats[FP_MULTIBLADE_STATS_NUM] __fpn_cache_aligned;
#endif /* CONFIG_MCORE_MULTIBLADE */

	fp_exception_stats_t	exception_stats[FP_EXCEP_STATS_NUM] __fpn_cache_aligned;

	/* We have 2 pools of entries & intermediate tables,
	 * for 8bits and 16bits wide layers. These pools are
	 * used by both IPv4 & IPv6 routes.
	 */
	fp_table_entry_t       fp_8_entries[FP_NB_8_ENTRIES];
	fp_table_entry_t       fp_16_entries[FP_NB_16_ENTRIES];
	fp_table_t             fp_8_table[FP_NB_8_TABLE_ENTRIES];
	fp_table_t             fp_16_table[FP_NB_16_TABLE_ENTRIES];

	/* Routes & Neighbours tables are separated for IPv4 & IPv6 */
	fp_rt4_entry_t         fp_rt4_table[FP_IPV4_NBRTENTRIES];
	/* Two addtional dummy entries for Local/Blackhole routes */
	fp_nh4_entry_t         fp_nh4_table[FP_IPV4_NBNHENTRIES + 2];
	/* Neighbour hash table */
	uint32_t               fp_nh4_hash[FP_NEIGH_HASH_SIZE];
	uint32_t               fp_nh4_available_head;
	uint32_t               fp_nh4_available_tail;
#ifdef CONFIG_MCORE_IPV6
	fp_rt6_entry_t         fp_rt6_table[FP_IPV6_NBRTENTRIES];
	/* Two addtional dummy entries for Local/Blackhole routes */
	fp_nh6_entry_t         fp_nh6_table[FP_IPV6_NBNHENTRIES + 2];
	/* Neighbour hash table */
	uint32_t               fp_nh6_hash[FP_NEIGH_HASH_SIZE];
	uint32_t               fp_nh6_available_head;
	uint32_t               fp_nh6_available_tail;
#endif /* CONFIG_MCORE_IPV6 */

	/* Index of last-added entry */
	uint32_t               fp_rt4_last_added;
#ifdef CONFIG_MCORE_IPV6
	uint32_t               fp_rt6_last_added;
	/* Cumulative width of each IPv6 layer */
	uint8_t                fp_cumulative_width6[FP_IPV6_NBLAYERS];

	/* Precalculated tables pointing on the right table depending on the layer */
	uint32_t               fp_table6[FP_IPV6_NBLAYERS];
	uint32_t               fp_entries6[FP_IPV6_NBLAYERS];
#endif /* CONFIG_MCORE_IPV6 */

	uint32_t               fp_reass4_maxq_len;
	uint32_t               fp_reass6_maxq_len;
#define FP_REASS4_DEFAULT_MAXQLEN   10
#define FP_REASS6_DEFAULT_MAXQLEN   10

#ifdef CONFIG_MCORE_IPSEC
	fp_ipsec_t             ipsec;
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_ipsec6_t            ipsec6;
#endif
#ifdef CONFIG_MCORE_IPSEC_SVTI
	/* SVTI interfaces */
	fp_svti_t              svti[FP_MAX_SVTI];
#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
	fp_hlist_head_t        svti_hash[FP_SVTI_HASH_SIZE];
#endif
#endif
	fp_sa_ah_algo_t        sa_ah_algo[FP_MAX_AALGOS];
	fp_sa_esp_algo_t       sa_esp_algo[FP_MAX_EALGOS];
#endif /* CONFIG_MCORE_IPSEC */

#ifdef CONFIG_MCORE_VXLAN
	/* VXLAN interfaces */
	uint32_t               vxlan_magic;
	fp_vxlan_t             vxlan_port[FP_VXLAN_PORT_MAX];
	fp_hlist_head_t        vxlan_port_hash[FP_VXLAN_PORT_HASH_SIZE];
	fp_vxlan_iface_t       vxlan_iface[FP_VXLAN_IFACE_MAX];
	fp_vxlan_fdb_t         vxlan_fdb[FP_VXLAN_FDB_MAX];
	fp_vxlan_fdb_remote_t  vxlan_fdb_remote[FP_VXLAN_FDB_MAX];
	fp_vxlan_fpvs_input_t  vxlan_fpvs_input;
#endif

#ifdef CONFIG_MCORE_BRIDGE
	fp_bridge_t            bridge;
#endif

#ifdef CONFIG_MCORE_MULTIBLADE
	uint32_t               fpib_ifuid;
	fp_blade_t             fp_blades[FP_BLADEID_MAX + 1];
#ifdef CONFIG_MCORE_1CP_XFP
	uint8_t                cp_blade_id;
#endif
#endif /* CONFIG_MCORE_MULTIBLADE */
	uint8_t                active_cpid;
	uint8_t                fp_blade_id;
	uint8_t                cp_if_port;
#define IF_PORT_COLOC 0xFF  /* co-localized Control Plane */
	uint8_t                fp_if_mac[6];
	uint8_t                cp_if_mac[6];
	uint32_t               cp_if_mtu;

#ifdef CONFIG_MCORE_NETFILTER
	/* The following table describes the nf_table priority for each hook */
	int                    fp_nf_hook_prio[2][FP_NF_IP_NUMHOOKS][FP_NF_TABLE_NUM + 1];
	uint8_t                fp_nf_current_hook_prio;
	uint8_t                fp_nf_current_table;
	fp_nftable_t           fp_nf_tables[2][FP_NF_MAX_VR][FP_NF_TABLE_NUM];
	struct fp_nfrule       fp_nf_rules[2][FP_NF_MAXRULES] __fpn_cache_aligned;
#ifdef CONFIG_MCORE_NF_CT
	fp_nfct_t              fp_nf_ct;
#endif
#ifdef CONFIG_MCORE_MULTIBLADE
	uint8_t                fp_nf_ct_bladeid;
#endif
#ifdef CONFIG_MCORE_NETFILTER_CACHE
	fpn_uintptr_t            fp_nf_cache_base_addr;
	fp_nf_rule_cache_entry_t fp_nf_rule_cache[FP_NF_MAX_CACHE_SIZE];
#endif
#endif

#ifdef CONFIG_MCORE_NETFILTER_IPV6
	/* The following table describes the nf6_table priority for each hook */
	int                    fp_nf6_hook_prio[2][FP_NF_IP_NUMHOOKS][FP_NF6_TABLE_NUM + 1];
	uint8_t                fp_nf6_current_hook_prio;
	uint8_t                fp_nf6_current_table;
	fp_nf6table_t          fp_nf6_tables[2][FP_NF_MAX_VR][FP_NF6_TABLE_NUM];
	struct fp_nf6rule      fp_nf6_rules[2][FP_NF6_MAXRULES] __fpn_cache_aligned;
	fp_nf6ct_t             fp_nf6_ct;
#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE
	fpn_uintptr_t             fp_nf6_cache_base_addr;
	fp_nf6_rule_cache_entry_t fp_nf6_rule_cache[FP_NF6_MAX_CACHE_SIZE];
#endif
#endif

#ifdef CONFIG_MCORE_TC
	uint32_t		tc_bitmask; /* TC id in use */
#endif

#if defined(CONFIG_MCORE_XIN4) || defined(CONFIG_MCORE_XIN6)
	fp_tunnel_table_t fp_tunnels __fpn_cache_aligned;
#endif

#ifdef CONFIG_MCORE_TAP_BPF
	fp_bpf_filter_t        fp_bpf_filters[FP_MAX_IFNET][FP_BPF_MAXINSTANCE];
#endif
#ifdef CONFIG_MCORE_TAP_CIRCULAR_BUFFER
	uint64_t cap_buf_size;
	uint64_t cap_buf_offset;
	uint32_t cap_pkt_len;
	uint32_t cap_cookie;
	uint32_t cap_wrap; /* bool: if 0, stop capture when buffer is full */
#endif

#ifdef CONFIG_MCORE_MULTICAST4
	fp_mfc_entry_t         fp_mfc_table[FP_MFC_MAX];
	fp_mcastgrp_t          fp_mcastgrp_table[FP_MCASTGRP_MAX];
	uint8_t                fp_mcastgrp_num;
#define FP_MCASTGRP_OPT_ENABLE       0x01
#define FP_MCASTGRP_OPT_ACCEPT_LL    0x02   /* Accept link local */
	uint8_t                fp_mcastgrp_opt;
#endif
#ifdef CONFIG_MCORE_MULTICAST6
	fp_mfc6_entry_t        fp_mfc6_table[FP_MFC6_MAX];
	fp_mcast6grp_t         fp_mcast6grp_table[FP_MCAST6GRP_MAX];
	uint8_t                fp_mcast6grp_num;
	uint8_t                fp_mcast6grp_opt;
#endif

#ifdef CONFIG_MCORE_HITFLAGS_SYNC
	/* hitflags parameters */
	struct fp_hf_param fp_hf_arp;
#ifdef CONFIG_MCORE_IPV6
	struct fp_hf_param fp_hf_ndp;
#endif
#ifdef CONFIG_MCORE_NETFILTER
#ifdef CONFIG_MCORE_NF_CT
	struct fp_hf_param fp_hf_ct;
#endif
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	struct fp_hf_param fp_hf_ct6;
#endif
#endif /* CONFIG_MCORE_HITFLAGS_SYNC */
#ifdef CONFIG_MCORE_MULTIBLADE
	uint8_t                fp_neigh_bladeid;
#endif

	/* Remote Fast Path Statistics */
	fp_rfps_t fp_rfps;

	uint32_t               cp_if_fptun_size_thresh;
	uint32_t               fpib_fptun_size_thresh;

#ifdef CONFIG_MCORE_CPONLY_PORTMASK
	uint64_t cponly_portmask;
#endif
#ifdef CONFIG_MCORE_IP
	struct fp_pool_addr4 fp_empty_pool_addr4;
#endif
#ifdef CONFIG_MCORE_IPV6
	struct fp_pool_addr6 fp_empty_pool_addr6;
#endif

	fp_module_t fp_modules[FP_MAX_MODULES];

	char fpmplugins[FP_MAX_PLUGINS][FP_PLUGINSNAME_MAXLEN];
	char fpplugins[FP_MAX_PLUGINS][FP_PLUGINSNAME_MAXLEN];
	char fpcliplugins[FP_MAX_PLUGINS][FP_PLUGINSNAME_MAXLEN];

	char logname[FP_MAX_LOGTYPES][FP_LOGNAME_MAXLEN];

	struct veda_serial product_serial;
	struct veda_licence licence;

//	struct key_hash_entry key_hash_table[_KEY_HASH_TABLE_SIZE];
//	struct server_table    server_table[SERVER_TABLE];

	//iptables dispatch configuration
	#define BLACK_IP				0x00000001
	#define WHITE_IP 			        0x00000002
	#define IS_PROTECT_SERVER        0x00000003
	#define TYPEGMAX				0xffffffff
	#define DISPATCH_MAX_NUM 	         65535
	uint32_t dispatch_type[DISPATCH_MAX_NUM];

	//ddos flow detect and clean
	struct total_server total;
	uint32_t   tcp_session_num;
	uint32_t   udp_session_num;
	struct  attack_log  attack_log_table[ATTACK_LOG_TABLE];
	uint32_t  attack_log_start;
	uint32_t  attack_log_end;
	uint32_t  default_detect_cycle;
	uint32_t  white_effect_time;
	uint32_t  black_effect_time;
	uint32_t    over_threshold_delay_time;
	enum total_flow_strategy flow_strategy;

	uint32_t tcp_ack_number;
	uint64_t cpu_hz;
	uint8_t stream_return;

#define MAX_PATH_LEN   32
	struct ddos_shm_info fp_ddos_shm[DDOS_SHM_TOTAL];

#define FP_VERBOSE_MSG_SIZE (4*1024)
	char verbose_msg[FP_VERBOSE_MSG_SIZE];

	//uint32_t defend_mode;  /*0: normal attack and protect mode; 1: Bypass all traffic*/
} shared_mem_t;

static inline void print_size(void)
{
/* quick log2(x) */
#define log2(x) \
	switch (x) { \
	case 1:		 \
	case 2:		 \
	case 4:		 \
	case 8:		 \
	case 16:	 \
	case 32:	 \
	case 64:	 \
	case 128:	 \
	case 256:	 \
	case 512:	 \
	case 1024:	 \
	case 2048:	 \
	case 4096:							  \
		fp_log_common(LOG_DEBUG, "OK\n"); \
		break;							  \
	default:													 \
		/* gcc computes fast offset if power of 2 can be used */		\
		fp_log_common(LOG_DEBUG, "WARNING size is not a power of 2, slow offset\n"); \
		break;															\
}

#define pw(x) fp_log_common(LOG_DEBUG, "sizeof(" #x ") is %d ", (int)sizeof(x)); log2(sizeof(x));
#define p(x) fp_log_common(LOG_DEBUG, "sizeof(" #x ") is %d\n", (int)sizeof(x));

#define p0(x) fp_log_common(LOG_DEBUG, "\tsizeof(" #x ") is %d Bytes (%d KB)\n", \
				(int)sizeof(((shared_mem_t *)0)->x), \
				(int)sizeof(((shared_mem_t *)0)->x)/1024)
#define pa(f, s) do { \
	if ((unsigned long)&(((shared_mem_t *)0)->f) % FPN_CACHELINE_SIZE || \
	    (unsigned long)sizeof(s) % FPN_CACHELINE_SIZE) \
		fp_log_common(LOG_DEBUG, "\tWARNING:\n\t\t" #f " is %s on a cache line\n" \
			      "\t\t" #s " is %s of a cache line\n", \
			      (unsigned long)&(((shared_mem_t *)0)->f) % FPN_CACHELINE_SIZE ? \
			      "NOT ALIGNED" : "aligned", \
			      (unsigned long)sizeof(s) % FPN_CACHELINE_SIZE ? \
			      "NOT A MULTIPLE" : "a multiple"); \
	else \
		fp_log_common(LOG_DEBUG, "\t" #s " " #f " is correctly aligned on a cache line\n"); \
} while (0)

	fp_log_common(LOG_DEBUG, "%s:\n", __FUNCTION__);
	pw(fp_table_entry_t);
	pw(fp_table_t);
	p(_fp_rt_entry_t);
	p(_fp_nh_entry_t);
	pw(fp_rt4_entry_t);
	pw(fp_nh4_entry_t);
#ifdef CONFIG_MCORE_IPV6
	pw(fp_rt6_entry_t);
	pw(fp_nh6_entry_t);
#endif /* CONFIG_MCORE_IPV6 */
	pw(fp_ifport_t);
	pw(fp_ifnet_t);
	pw(fp_ip_stats_t);
#ifdef CONFIG_MCORE_NETFILTER
	// TODO p(fp_nfrule);
	pw(fp_nftable_t);
	pw(struct fp_nfrule);
	pw(struct fp_nfct_entry);
#ifdef CONFIG_MCORE_NF_CT
	pw(fp_nfct_t);
	pw(struct fp_nfct_stats);
	pw(struct fp_nfct_tuple_h);
	pw(union fp_nfct_tuple_id);
#endif
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	// TODO p(fp_nf6rule);
	pw(fp_nf6table_t);
#endif
#ifdef CONFIG_MCORE_NETFILTER_CACHE
	pw(fp_nf_rule_cache_entry_t);
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE
	pw(fp_nf6_rule_cache_entry_t);
#endif
#ifdef CONFIG_MCORE_TAP_BPF
	pw(fp_filter_t);
	pw(fp_bpf_filter_t); /* XXX enforce alignement */
#endif
#ifdef CONFIG_MCORE_MULTICAST4
	pw(fp_mfc_entry_t);
#endif
#ifdef CONFIG_MCORE_IPSEC
	p(fp_sa_entry_t);
	p(fp_sp_entry_t);
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
	p(fp_v6_sa_entry_t);
	p(fp_v6_sp_entry_t);
#endif
	fp_log_common(LOG_DEBUG, "\n");
	p(shared_mem_t);
	p0(conf);
	p0(fp_8_entries);
	p0(fp_16_entries);
	p0(fp_8_table);
	p0(fp_16_table);
	p0(fp_rt4_table);
	p0(fp_nh4_table);
#ifdef CONFIG_MCORE_IPV6
	p0(fp_rt6_table);
	p0(fp_nh6_table);
	p0(fp_table6);
	p0(fp_entries6);
#endif /* CONFIG_MCORE_IPV6 */

	p0(ifport);
	p0(ifnet);
	p0(ip_stats);
#ifdef CONFIG_MCORE_IPV6
	p0(ip6_stats);
#endif
#ifdef CONFIG_MCORE_IPSEC
	p0(ipsec);
	p0(sa_ah_algo);
	p0(sa_esp_algo);
#endif
#ifdef CONFIG_MCORE_MULTIBLADE
	p0(fp_blades);
#endif
	p0(fp_blade_id);
	p0(cp_if_port);
	p0(cp_if_mac);
#ifdef CONFIG_MCORE_NETFILTER
	p0(fp_nf_tables);
#ifdef CONFIG_MCORE_NF_CT
	p0(fp_nf_ct);
#endif
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	p0(fp_nf6_tables);
#endif
#ifdef CONFIG_MCORE_NETFILTER_CACHE
	p0(fp_nf_rule_cache);
#endif
#if defined(CONFIG_MCORE_XIN4) || defined(CONFIG_MCORE_XIN6)
	p0(fp_tunnels);
#endif
#ifdef CONFIG_MCORE_TAP_BPF
	p0(fp_bpf_filters);
#endif
#ifdef CONFIG_MCORE_MULTICAST4
	p0(fp_mfc_table);
#endif
#ifdef CONFIG_MCORE_MULTICAST6
	p0(fp_mfc6_table);
#endif
	fp_log_common(LOG_DEBUG, "Alignment check:\n");
	pa(ifnet.table, fp_ifnet_t);
	pa(ifnet.table[0].if_stats, fp_if_stats_t);
	pa(ip_stats, fp_ip_stats_t);
#ifdef CONFIG_MCORE_IPV6
	pa(ip6_stats, fp_ip_stats_t);
#endif
	pa(global_stats, fp_global_stats_t);
#ifdef CONFIG_MCORE_SOCKET
	pa(tcp_stats, fp_tcp_stats_t);
	pa(udp_stats, fp_udp_stats_t);
#endif
#ifdef CONFIG_MCORE_MULTIBLADE
	pa(multiblade_stats, fp_multiblade_stats_t);
#endif
	pa(exception_stats, fp_exception_stats_t);
#ifdef CONFIG_MCORE_IPSEC
	pa(ipsec.sad.table, fp_sa_entry_t);
	pa(ipsec.sad.table[0].stats, fp_sa_stats_t);
	pa(ipsec.spd_in.table, fp_sp_entry_t);
	pa(ipsec.spd_in.table[0].stats, fp_sp_stats_t);
	pa(ipsec.spd_out.table, fp_sp_entry_t);
	pa(ipsec.spd_out.table[0].stats, fp_sp_stats_t);
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
	pa(ipsec6.sad6.table, fp_v6_sa_entry_t);
	pa(ipsec6.sad6.table[0].stats, fp_v6_sa_stats_t);
	pa(ipsec6.spd6_in.table, fp_v6_sp_entry_t);
	pa(ipsec6.spd6_in.table[0].stats, fp_v6_sp_stats_t);
	pa(ipsec6.spd6_out.table, fp_v6_sp_entry_t);
	pa(ipsec6.spd6_out.table[0].stats, fp_v6_sp_stats_t);
#endif
#ifdef CONFIG_MCORE_NETFILTER
	pa(fp_nf_tables, fp_nftable_t);
	pa(fp_nf_rules[0][0], struct fp_nfrule);
	pa(fp_nf_rules[0][0].stats, fp_nfrule_stats_t);
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	pa(fp_nf6_tables, fp_nf6table_t);
	pa(fp_nf6_rules[0][0], struct fp_nf6rule);
	pa(fp_nf6_rules[0][0].stats, fp_nfrule_stats_t);
#endif

#undef p
#undef pw
#undef p0
#undef pa
#undef log2
}

#endif
