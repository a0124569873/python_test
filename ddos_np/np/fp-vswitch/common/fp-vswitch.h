/*
 * Copyright(c) 2012 6WIND
 */

#ifndef __FP_VSWITCH_H__
#define __FP_VSWITCH_H__

#include "fp.h"
#include "fp-var.h"
#ifdef CONFIG_MCORE_GRE
#include "fp-gre-var.h"
#endif

#include "fpvs-cp.h"

/* FPVS magic number */
#define FP_FPVS_MAGIC32 19710301

#define FPVS_MAX_OVS_PORTS		256

#define FPVS_INVALID_IF_IDX		((unsigned long)-1)
#define fpvs_get_port(ovsport)		\
	(&fpvs_shared->ports[ovsport])
#define fpvs_get_ifnet_idx(ovsport)	\
	(fpvs_get_port(ovsport)->ifp_index)
#define fpvs_get_ifnet(ovsport)						\
	(fpvs_get_ifnet_idx(ovsport) == FPVS_INVALID_IF_IDX ?		\
	NULL : &fp_shared->ifnet.table[fpvs_get_ifnet_idx(ovsport)])

#ifdef FP_VSWITCH_STATS_PER_CORE
#define FP_VSWITCH_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_VSWITCH_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FP_VSWITCH_STATS_NUM                     FPN_MAX_CORES
#else
#define FP_VSWITCH_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FP_VSWITCH_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FP_VSWITCH_STATS_NUM                     1
#endif

typedef struct fp_vswitch_port_stats {
	uint64_t rx_pkts;
	uint64_t tx_pkts;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
} __fpn_cache_aligned fp_vswitch_port_stats_t;

struct fp_ifnet;
typedef struct fp_vswitch_port {
	unsigned long 		ifp_index;
	char 			ifp_name[FP_IFNAMSIZ];
	uint32_t		type;
	void			*priv;
	fp_vswitch_port_stats_t	stats[FP_VSWITCH_STATS_NUM];
} fp_vswitch_port_t;

/* used to decapsulate a packet if matching is successful */
typedef int (*fpvs_tunnel_decap_t) (struct mbuf *, size_t);

int fpvs_set_ovsport(const char* name, uint32_t ovsport, uint32_t type,
		     uint16_t dstport, uint32_t graceful_in_progress);

/* FP-VSWITCH statistics */
typedef struct fpvs_stats {
	uint64_t   flow_not_found;
	uint64_t   flow_pullup_failed;
	uint64_t   flow_pullup_too_small;
	/* Output actions */
	uint64_t   output_ok;
	uint64_t   output_failed_no_mbuf;
	uint64_t   output_failed_no_ifp;
	uint64_t   output_failed;
	uint64_t   output_failed_unknown_type;
	uint64_t   userspace;
	uint64_t   push_vlan;
	uint64_t   pop_vlan;
	uint64_t   push_mpls;
	uint64_t   pop_mpls;
	uint64_t   recirc;
	/* SET actions */
	uint64_t   set_ethernet;
	uint64_t   set_mpls;
	uint64_t   set_priority;
	uint64_t   set_tunnel_id;
	uint64_t   set_ipv4;
	uint64_t   set_ipv6;
	uint64_t   set_tcp;
	uint64_t   set_udp;
	uint64_t   set_sctp;
	uint64_t   unsupported;
} __fpn_cache_aligned fpvs_stats_t;

typedef struct fpvs_shared_mem {
	struct fp_vswitch_port	ports[FPVS_MAX_OVS_PORTS];
	fpvs_stats_t		stats[FP_VSWITCH_STATS_NUM];
	uint32_t    		magic;
	/* Keep in last place, preserved on shared mem initialization */
	uint16_t    		mod_uid;
} fpvs_shared_mem_t;

#endif /* __FP_VSWITCH_H__ */
