/*
 * Copyright(c) 2006 6WIND
 */
#ifndef __FP_H__
#define __FP_H__

#include "fpn.h"

#include "fp-track-debug.h"

#ifdef __FastPath__
#define fp_log_common(l, fmt, args...)  fpn_printf(fmt, ## args)

#else

/* need this header for htons/htonl definition */
#if !defined(__KERNEL__)
#include <netinet/in.h>
#endif

#ifdef FP_LOG_COMMON_PRINTF
#define fp_log_common(l, fmt, args...)  printf(fmt, ## args)
#elif !defined(__KERNEL__)
#include <syslog.h>
#define fp_log_common(l, fmt, args...)  syslog(l, fmt, ## args)
#else
#define fp_log_common(l, fmt, args...)  printk(KERN_DEBUG fmt, ## args)
#endif

#endif /* __FastPath__ */

#ifndef FPN_DECLARE_SHARED
#define FPN_DECLARE_SHARED(t,v) extern t v
#endif
#ifndef FPN_DEFINE_SHARED
#define FPN_DEFINE_SHARED(t,v) __typeof__(t) v
#endif
#ifndef FPN_DECLARE_PER_CORE
#define FPN_DECLARE_PER_CORE(t,v) extern t v
#endif
#ifndef FPN_DEFINE_PER_CORE
#define FPN_DEFINE_PER_CORE(t,v) __typeof__(t) v
#endif
#ifndef FPN_PER_CORE_VAR
#define FPN_PER_CORE_VAR(v) (v)
#endif

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

#define DEFAULT_FP_PLUGINS     "/usr/local/lib/fastpath/*.so"
#define DEFAULT_FP_CLI_PLUGINS "/usr/local/lib/fp-cli/*.so"

#define NIPOCT(addr) \
ntohs(((uint16_t *)&addr)[0]), \
	ntohs(((uint16_t *)&addr)[1]), \
	ntohs(((uint16_t *)&addr)[2]), \
	ntohs(((uint16_t *)&addr)[3]), \
	ntohs(((uint16_t *)&addr)[4]), \
	ntohs(((uint16_t *)&addr)[5]), \
	ntohs(((uint16_t *)&addr)[6]), \
	ntohs(((uint16_t *)&addr)[7])

#ifndef FPN_BIG_ENDIAN
#define FPN_BIG_ENDIAN      4321
#endif
#ifndef FPN_LITTLE_ENDIAN
#define FPN_LITTLE_ENDIAN   1234
#endif

#include "fp-hlist.h"
#include "fp-var.h"

#if (defined(CONFIG_MCORE_ARCH_XLP) && defined(CONFIG_MCORE_FPE_MCEE) && \
	 defined(XLP_FAST_SHM_PTR))
register shared_mem_t *fp_shared __asm__("$28");
#else
FPN_DECLARE_SHARED(shared_mem_t *, fp_shared);
#endif

#ifdef CONFIG_MCORE_IPSEC
static inline fp_spd_t *fp_get_spd_out(void) {
	return &fp_shared->ipsec.spd_out;
}

static inline fp_spd_t *fp_get_spd_in(void) {
	return &fp_shared->ipsec.spd_in;
}

static inline fp_sad_t *fp_get_sad(void) {
	return &fp_shared->ipsec.sad;
}

static inline fp_sa_ah_algo_t *fp_get_sa_ah_algo(const uint8_t i) {
	return &fp_shared->sa_ah_algo[i];
}

static inline fp_sa_esp_algo_t *fp_get_sa_esp_algo(const uint8_t i) {
	return &fp_shared->sa_esp_algo[i];
}
#endif

#ifdef CONFIG_MCORE_IPSEC_IPV6
static inline fp_spd6_t *fp_get_spd6_out(void) {
	return &fp_shared->ipsec6.spd6_out;
}

static inline fp_spd6_t *fp_get_spd6_in(void) {
	return &fp_shared->ipsec6.spd6_in;
}

static inline fp_sad6_t *fp_get_sad6(void) {
	return &fp_shared->ipsec6.sad6;
}

static inline fp_sa_ah_algo_t *fp_get_v6_sa_ah_algo(const uint8_t i) {
	return &fp_shared->sa_ah_algo[i];
}

static inline fp_sa_esp_algo_t *fp_get_v6_sa_esp_algo(const uint8_t i) {
	return &fp_shared->sa_esp_algo[i];
}
#endif

/* Initialize the shared structure */
extern void fp_init(void);
extern uint64_t get_clock_hz(void);

/* Note : these API should only be called from the FPM -
 * the FP is not supposed to change the routes */
/* Interfaces management */
#define FP_ADDIFNET_EXIST     1
#define FP_ADDIFNET_SUCCESS   0
#define FP_ADDIFNET_ERROR    -1
extern int fp_addifnet(uint16_t vrfid, const char* name,
                       const uint8_t *mac, uint32_t mtu,
                       uint32_t ifuid, uint8_t port, uint8_t type);
extern int fp_add_sys_loopback(uint16_t vrfid, const char* name,
                       uint32_t mtu, uint32_t ifuid);
extern int fp_delifnet(uint32_t ifuid);
extern int fp_setifnet_master(const uint32_t slave_ifuid,
			      const uint32_t master_ifuid);
extern int fp_setifnet_mtu(uint32_t ifuid, const uint32_t mtu);
extern int fp_setifnet_mac(uint32_t ifuid, const uint8_t *mac);
extern int fp_setifnet_flags(uint32_t ifuid, const uint16_t flags);
extern int fp_setifnet_bladeinfo(uint32_t ifuid, uint8_t blade_id);
extern int fp_setifnet_tcpmss4(uint32_t ifuid, const uint32_t mss);
extern int fp_setifnet_tcpmss6(uint32_t ifuid, const uint32_t mss);
extern int fp_setifnet_force_reassembly4(uint32_t ifuid, const uint32_t command);
extern int fp_setifnet_force_reassembly6(uint32_t ifuid, const uint32_t command);

extern int fp_svti_add(uint32_t ifuid);
extern int fp_svti_del(uint32_t ifuid);

/* Next hop management */
extern uint32_t fp_add_neighbour4(uint32_t addr, const uint8_t mac[6], uint32_t ifuid,
		uint8_t state);
extern uint32_t fp_delete_neighbour4(uint32_t addr, uint32_t ifuid);

/* Routes management */
extern uint32_t fp_add_route4(uint16_t vrfid, uint32_t addr, uint8_t prefix, uint32_t next, uint32_t ifuid, uint8_t type);

typedef struct fp_nh_mark {
	uint32_t mark;
	uint32_t mask;
} fp_nh_mark_t;
extern uint32_t fp_add_route4_nhmark(uint16_t vrfid, uint32_t addr, uint8_t prefix, uint32_t next, uint32_t ifuid, uint8_t type, fp_nh_mark_t *nh_mark);
extern uint32_t fp_delete_route4_nhmark(uint16_t vrfid, uint32_t addr, uint8_t prefix, uint32_t gw, uint32_t ifuid, uint8_t type, fp_nh_mark_t *nh_mark);
extern uint32_t fp_change_route4_nhmark(uint16_t vrfid, uint32_t addr, uint8_t prefix, uint32_t gw, uint32_t ifuid, uint8_t type, fp_nh_mark_t *nh_mark);
extern void fp_route_flush_per_vrf(uint16_t vrfid);

extern fp_rt4_entry_t *fp_get_exact_route4(uint16_t vrfid, uint32_t prefix, uint8_t len);

/* Rules management */
extern int fp_ipv4_default_rules(uint16_t vrfid, uint32_t ifuid, int del);
#ifdef CONFIG_MCORE_IPV6
extern int fp_ipv6_default_rules(uint16_t vrfid, uint32_t ifuid, int del);
#endif


/* Address management */
extern uint32_t fp_add_address4(uint32_t addr, uint32_t ifuid);
extern uint32_t fp_delete_address4(uint32_t addr, uint32_t ifuid);

#ifdef CONFIG_MCORE_IPV6
/* Next hop management */
extern uint32_t fp_add_neighbour6(fp_in6_addr_t * addr, const uint8_t mac[6], uint32_t ifuid,
		uint8_t state);
extern uint32_t fp_delete_neighbour6(fp_in6_addr_t * addr, uint32_t ifuid);

/* Routes management */
extern uint32_t fp_add_route6_nhmark(uint16_t vrfid, fp_in6_addr_t * addr, uint8_t prefix, fp_in6_addr_t * next, uint32_t ifuid, uint8_t type, fp_nh_mark_t *nh_mark);
extern uint32_t fp_delete_route6_nhmark(uint16_t vrfid, fp_in6_addr_t * addr, uint8_t prefix, fp_in6_addr_t * gw, uint32_t ifuid, uint8_t type, fp_nh_mark_t *nh_mark);
extern fp_rt6_entry_t *fp_get_exact_route6(uint16_t vrfid, fp_in6_addr_t * prefix, uint8_t len);

/* Address management */
extern uint32_t fp_add_address6(fp_in6_addr_t * addr, uint32_t ifuid);
extern uint32_t fp_delete_address6(fp_in6_addr_t * addr, uint32_t ifuid);

#endif /* CONFIG_MCORE_IPV6 */


/* Blade management */
extern uint32_t fp_add_blade(uint8_t id, uint8_t flags, const uint8_t mac[6]);
extern uint32_t fp_delete_blade(uint8_t id, uint8_t flags);
extern uint32_t fp_set_blade_id(uint8_t id, uint8_t cp_id);
extern uint32_t fp_set_cp_info(uint8_t if_port, const uint8_t portmac[6],
		uint32_t mtu, int auto_thresh);
#ifdef CONFIG_MCORE_MULTIBLADE
extern uint32_t fp_set_fpib_ifuid(uint32_t ifuid, int auto_thresh);
#endif

/* Remote Fast Path Statistics management */
extern void fp_set_rfps_ip(uint32_t tx_period, uint32_t max_msg_per_tick,
			   uint32_t min_refresh_period);
extern void fp_set_rfps_if(uint32_t tx_period, uint32_t max_msg_per_tick,
			   uint32_t min_refresh_period);
#ifdef CONFIG_MCORE_IPSEC
void fp_set_rfps_ipsec_sa(uint32_t tx_period, uint32_t max_msg_per_tick,
			  uint32_t min_refresh_period);
void fp_set_rfps_ipsec_sp_in(uint32_t tx_period, uint32_t max_msg_per_tick,
			     uint32_t min_refresh_period);
void fp_set_rfps_ipsec_sp_out(uint32_t tx_period, uint32_t max_msg_per_tick,
			      uint32_t min_refresh_period);
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
void fp_set_rfps_ipsec6_sa(uint32_t tx_period, uint32_t max_msg_per_tick,
			   uint32_t min_refresh_period);
void fp_set_rfps_ipsec6_sp_in(uint32_t tx_period, uint32_t max_msg_per_tick,
			      uint32_t min_refresh_period);
void fp_set_rfps_ipsec6_sp_out(uint32_t tx_period, uint32_t max_msg_per_tick,
			       uint32_t min_refresh_period);
#endif

/* Tunnel management */
#if defined(CONFIG_MCORE_XIN4) || defined(CONFIG_MCORE_XIN6)
#include "fp-tunnels-var.h"
#endif

static inline uint32_t fp_port2ifuid(uint8_t port)
{
  return fp_shared->ifport[port].ifuid;
}

static inline uint16_t fp_ifuid2hash(uint32_t ifuid)
{
	return ifuid & FP_IFNET_HASH_MASK;
}

/* return index of interface in ifnet table */
static inline uint32_t fp_ifuid2idx(const uint32_t ifuid)
{
	uint32_t h;
	uint32_t idx;
	fp_hlist_head_t *head;

	/* try to find interface via the hash table */
	h = fp_ifuid2hash(ifuid);

	/* when possible, the FPM stores an interface in the cell indexed
	 * by its hash value. optimize this case */
	if (likely(h && h < FP_MAX_IFNET && fp_shared->ifnet.table[h].if_ifuid == ifuid))
		return h;

	head = &fp_shared->ifnet.hash[h];
	/* optimize case when first hash entry matches */
	if (likely(((idx = fp_hlist_first(head)) != 0) &&
			(fp_shared->ifnet.table[idx].if_ifuid == ifuid)))
		return idx;

	/* no entry with that hash value */
	if (idx == 0)
		return 0;

	/* lookup through all the hash size line */
	fp_hlist_for_each_continue(idx, head, fp_shared->ifnet.table, ifuid_hlist) {
		if (fp_shared->ifnet.table[idx].if_ifuid == ifuid)
			return idx;
	}

	return 0;
}

static inline fp_ifnet_t *fp_ifuid2ifnet(const uint32_t ifuid)
{
	uint32_t idx = fp_ifuid2idx(ifuid);

	return (idx ? &fp_shared->ifnet.table[idx] : NULL);
}

static inline const char *fp_ifuid2str(const uint32_t ifuid)
{
	fp_ifnet_t *ifp = fp_ifuid2ifnet(ifuid);

	return ifp ? ifp->if_name : "";
}

/* return ifnet by ifuid or a dummy ifnet */
static inline fp_ifnet_t *__fp_ifuid2ifnet(const uint32_t ifuid)
{
	return &fp_shared->ifnet.table[fp_ifuid2idx(ifuid)];
}

#ifdef CONFIG_MCORE_TAP_BPF
static inline fp_bpf_filter_t *fp_ifnet2bpf(const fp_ifnet_t *ifp)
{
	int idx = ifp - &fp_shared->ifnet.table[0];

	return fp_shared->fp_bpf_filters[idx];
}
#endif

/* return TRUE if ifp is NULL or not initialized */
static inline int fp_ifnet_is_invalid(const fp_ifnet_t *ifp)
{
	return (ifp == NULL || ifp->if_ifuid == 0);
}
	
static inline fp_ifnet_t *fp_getifnetbyname(const char *name)
{
	uint32_t h = fp_ifnet_hash_name(name);
	uint32_t idx;
	fp_hlist_head_t *head;
	fp_ifnet_t *ifp;

	head = &fp_shared->ifnet.name_hash[h];

	fp_hlist_for_each(idx, head, fp_shared->ifnet.table, name_hlist) {

		ifp = &fp_shared->ifnet.table[idx];

		if (ifp->if_ifuid != 0 &&
		    strncmp(ifp->if_name, name, FP_IFNAMSIZ) == 0)
			return ifp;
	}

	return NULL;
}

#ifdef __FastPath__
/*
 * same than fp_getifnetbyname, but already knowing:
 *   - the hash of the name
 *   - the len of the string (hence we can use fpn_fast_memcmp() instead of strncmp())
 */
static inline fp_ifnet_t *fp_fast_getifnetbyname(const char *name, uint32_t h, uint32_t len)
{
	uint32_t idx;
	fp_ifnet_t *ifp;
	fp_hlist_head_t *head;

	head = &fp_shared->ifnet.name_hash[h];

	fp_hlist_for_each(idx, head, fp_shared->ifnet.table, name_hlist) {

		ifp = &fp_shared->ifnet.table[idx];

		if (ifp->if_ifuid != 0 &&
		    fpn_fast_memcmp(ifp->if_name, name, len) == 0)
			return ifp;
	}

	return NULL;
}
#endif

/* 
 * call this function when MAC address of iface has changed.
 */
static inline int fp_update_l2_src(const uint8_t src[6], uint32_t ifuid)
{
	fp_nh4_entry_t *nhe4;
	unsigned int i;
#ifdef CONFIG_MCORE_IPV6
	fp_nh6_entry_t *nhe6;
#endif

	if (ifuid == 0)
		return -1;

	/*
	 * This concerns ALL next-hops attached to
	 * this interface	
	 */
	for (i = 1; i < FP_IPV4_NBNHENTRIES; i++) {
		nhe4 = &fp_shared->fp_nh4_table[i];
		if (nhe4->nh.nh_ifuid != ifuid)
			continue;
		memcpy(nhe4->nh.nh_eth.ether_shost, src, 6);
	}

#ifdef CONFIG_MCORE_IPV6
	for (i = 1; i < FP_IPV6_NBNHENTRIES; i++) {
		nhe6 = &fp_shared->fp_nh6_table[i];
		if (nhe6->nh.nh_ifuid != ifuid)
			continue;
		memcpy(nhe6->nh.nh_eth.ether_shost, src, 6);
	}
#endif

	return 0;
}

extern void fp_rt4_nh4_reorder(fp_rt4_entry_t *rte, int refresh, fp_rt4_entry_t *rte_out);
#ifdef CONFIG_MCORE_IPV6
extern void fp_rt6_nh6_reorder(fp_rt6_entry_t *rte, int refresh);
#endif

#ifdef CONFIG_MCORE_IPV6
static inline int fp_in6_is_link_local(fp_in6_addr_t addr)
{
	return ((addr.fp_s6_addr32[0] &htonl(0xffc00000)) == htonl(0xfe800000));
}
#endif

#ifdef CONFIG_MCORE_IPSEC_SVTI
/*
 * return index in SVTI table of an SVTI interface identified by its ifuid
 */
static inline uint32_t __fp_svti_get_index_by_ifuid(uint32_t ifuid)
{
	return __fp_ifuid2ifnet(ifuid)->sub_table_index;
}


/*
 * get pointer on outbound SPD of an SVTI interface identified by its ifuid
 */
static inline fp_hlist_head_t *fp_svti_get_spd_out(uint32_t ifuid)
{
	uint32_t index;

	if (likely((index = __fp_svti_get_index_by_ifuid(ifuid)) != 0))
		return &fp_shared->svti[index].spd_out;

	return NULL;
}

/*
 * get pointer on inbound SPD of an SVTI interface identified by its ifuid
 */
static inline fp_hlist_head_t *fp_svti_get_spd_in(uint32_t ifuid)
{
	uint32_t index;

	if (likely((index = __fp_svti_get_index_by_ifuid(ifuid)) != 0))
		return &fp_shared->svti[index].spd_in;

	return NULL;
}

/*
 * get pointer on SPD of an SVTI interface identified by its ifuid
 */
static inline fp_hlist_head_t *fp_svti_get_spd(uint32_t ifuid, int dir)
{
	if (dir == FP_SPD_IN)
		return fp_svti_get_spd_in(ifuid);
	else
		return fp_svti_get_spd_out(ifuid);
}

#ifdef CONFIG_MCORE_IPSEC_IPV6
/*
 * get pointer on IPV6 outbound SPD of an SVTI interface identified by its ifuid
 */
static inline fp_hlist_head_t *fp_svti6_get_spd_out(uint32_t ifuid)
{
	uint32_t index;

	if (likely((index = __fp_svti_get_index_by_ifuid(ifuid)) != 0))
		return &fp_shared->svti[index].spd6_out;

	return NULL;
}

/*
 * get pointer on IPV6 inbound SPD of an SVTI interface identified by its ifuid
 */
static inline fp_hlist_head_t *fp_svti6_get_spd_in(uint32_t ifuid)
{
	uint32_t index;

	if (likely((index = __fp_svti_get_index_by_ifuid(ifuid)) != 0))
		return &fp_shared->svti[index].spd6_in;

	return NULL;
}

/*
 * get pointer on IPV6 SPD of an SVTI interface identified by its ifuid
 */
static inline fp_hlist_head_t *fp_svti6_get_spd(uint32_t ifuid, int dir)
{
	if (dir == FP_SPD_IN)
		return fp_svti6_get_spd_in(ifuid);
	else
		return fp_svti6_get_spd_out(ifuid);
}
#endif /* CONFIG_MCORE_IPSEC_IPV6 */
#endif /* CONFIG_MCORE_IPSEC_SVTI */

int fp_interface_set_mtu(fp_ifnet_t *ifp, uint32_t mtu);
int fp_interface_set_mac(fp_ifnet_t *ifp, const uint8_t *mac);
int fp_interface_set_flags(fp_ifnet_t *ifp, const uint32_t flags);

#ifndef __FastPath__
int fp_interface_add(uint16_t vrfid, const char *name,
		     const uint8_t *mac, uint32_t mtu, uint32_t ifuid,
		     uint32_t vnb_nodeid, uint8_t port, uint8_t type,
		     int graceful_restart_in_progress);
int fp_interface_del(uint32_t ifuid, uint8_t vnb_keep_node,
		     int graceful_restart_in_progress);
#endif

#endif /* __FP_H__ */
