/*
 * Copyright(c) 2007 6WIND
 */

#if defined (__FastPath__)

#include "fpn.h"
#include "fp-includes.h"

#else

#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include "fp.h"

#endif

#define BSS __attribute__ ((section (".bss")))

typedef struct align16 {
	uint8_t x;
	uint16_t align;
} _align16_t;
typedef struct align32 {
	uint8_t x;
	uint32_t align;
} _align32_t;
typedef struct align64 {
	uint8_t x;
	uint64_t align;
} _align64_t;
typedef void * _ptr_t;

#define p(type) uint8_t _SIZEOF_ ## type[sizeof(type)] BSS
#define ps(type) uint8_t _SIZEOF_STRUCT_ ## type[sizeof(struct type)] BSS
#define pf(type, field) uint8_t _SIZEOF_ ## type ## _FIELD_ ## field[sizeof(((type *)0)->field)] BSS
#if __GNUC__ > 4 || (__GNUC__ >= 4 && __GNUC_MINOR__ >= 6) || !defined (__FastPath__)
/* If we use fpn_offsetof(), we have the following warning with gcc 4.6.1:
 * variably modified ‘_OFFSETOF__align16_t_FIELD_align’*/
/* Must explicitely include stddef.h to get the definition of "offsetof" */
#include <stddef.h>
#define pof(type, field) uint8_t _OFFSETOF_ ## type ## _FIELD_ ## field[offsetof(type, field)] BSS
#else
#define pof(type, field) uint8_t _OFFSETOF_ ## type ## _FIELD_ ## field[fpn_offsetof(type, field)] BSS
#endif
#define psf(type, field) uint8_t _SIZEOF_STRUCT_ ## type ## _FIELD_ ## field[sizeof(((struct type *)0)->field)] BSS
 

	p(shared_mem_t);
	p(fp_table_entry_t);
	p(fp_table_t);
	p(_fp_nh_entry_t);
	p(_fp_rt_entry_t);
	p(fp_rt4_entry_t);
	p(fp_nh4_entry_t);
#ifdef CONFIG_MCORE_IPV6
	p(fp_rt6_entry_t);
	p(fp_nh6_entry_t);
#endif
	p(fp_ifport_t);
	p(fp_ifnet_t);
	p(fp_ip_stats_t);
#ifdef CONFIG_MCORE_NETFILTER
	ps(fp_nfrule);
	p(fp_nftable_t);
	ps(fp_nfct_entry);
	ps(fp_nfct_tuple_h);
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	ps(fp_nf6rule);
	p(fp_nf6table_t);
#endif
#ifdef CONFIG_MCORE_NETFILTER_CACHE
	p(fp_nf_rule_cache_entry_t);
	p(fp_nf_rule_cache_extended_entry_t);
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE
	p(fp_nf6_rule_cache_entry_t);
	p(fp_nf6_rule_cache_extended_entry_t);
#endif
#ifdef CONFIG_MCORE_TAP_BPF
	p(fp_filter_t);
	p(fp_bpf_filter_t);
#endif
#ifdef CONFIG_MCORE_MULTICAST4
	p(fp_mfc_entry_t);
#endif
#ifdef CONFIG_MCORE_MULTICAST6
	p(fp_mfc6_entry_t);
#endif
#ifdef CONFIG_MCORE_VXLAN
	p(fp_vxlan_t);
	p(fp_vxlan_iface_t);
	p(fp_vxlan_fdb_t);
	p(fp_vxlan_fdb_remote_t);
	p(fp_vxlan_fpvs_input_t);
#endif
#ifdef CONFIG_MCORE_BRIDGE
	p(fp_br_port_t);
	p(fp_br_if_t);
	p(fp_br_fdb_t);
	p(fp_bridge_t);
#endif
#ifdef CONFIG_MCORE_PAPI
	pf(shared_mem_t, fp_papi);
#endif
#ifdef CONFIG_MCORE_IPSEC
	p(fp_sa_entry_t);
	p(fp_sp_entry_t);
#endif
	pf(shared_mem_t, conf);
	pf(shared_mem_t, fp_8_entries);
	pf(shared_mem_t, fp_16_entries);
	pf(shared_mem_t, fp_8_table);
	pf(shared_mem_t, fp_16_table);
	pf(shared_mem_t, fp_rt4_table);
#ifdef CONFIG_MCORE_IPV6
	pf(shared_mem_t, fp_rt6_table);
	pf(shared_mem_t, fp_nh6_table);
	pf(shared_mem_t, fp_table6);
	pf(shared_mem_t, fp_entries6);
#endif
	pf(shared_mem_t, fp_nh4_table);

	pf(shared_mem_t, fp_rt4_last_added);

	pf(shared_mem_t, ifport);
	pf(shared_mem_t, ifnet);
	pf(shared_mem_t, ip_stats);
#ifdef CONFIG_MCORE_IPV6
	pf(shared_mem_t, ip6_stats);
#endif
#ifdef CONFIG_MCORE_IPSEC
	pf(shared_mem_t, ipsec);
	pf(shared_mem_t, sa_ah_algo);
	pf(shared_mem_t, sa_esp_algo);
#endif
#ifdef CONFIG_MCORE_MULTICAST4
	pf(shared_mem_t, fp_mfc_table);
#endif
#ifdef CONFIG_MCORE_MULTICAST6
	pf(shared_mem_t, fp_mfc6_table);
#endif
#ifdef CONFIG_MCORE_MULTIBLADE
	pf(shared_mem_t, fp_blades);
#endif
	pf(shared_mem_t, fp_blade_id);
	pf(shared_mem_t, cp_if_port);
	pf(shared_mem_t, cp_if_mac);
#ifdef CONFIG_MCORE_NETFILTER
	pf(shared_mem_t, fp_nf_tables);
#ifdef CONFIG_MCORE_NF_CT
	pf(shared_mem_t, fp_nf_ct);
#endif
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	pf(shared_mem_t, fp_nf6_tables);
#endif
#ifdef CONFIG_MCORE_NETFILTER_CACHE
	pf(shared_mem_t, fp_nf_rule_cache);
#endif
#if defined(CONFIG_MCORE_XIN4) || defined(CONFIG_MCORE_XIN6)
	pf(shared_mem_t, fp_tunnels);
#endif
#ifdef CONFIG_MCORE_TAP_BPF
	pf(shared_mem_t, fp_bpf_filters);
#endif
	pf(shared_mem_t, exception_stats);
#ifdef CONFIG_MCORE_VXLAN
	pf(shared_mem_t, vxlan_port);
	pf(shared_mem_t, vxlan_iface);
	pf(shared_mem_t, vxlan_fdb);
	pf(shared_mem_t, vxlan_fdb_remote);
#endif
#ifdef CONFIG_MCORE_BRIDGE
	pf(fp_bridge_t, iface);
	pf(fp_bridge_t, iface_hash);
	pf(fp_bridge_t, port);
	pf(fp_bridge_t, port_hash);
	pf(fp_bridge_t, fdb);
#endif

#if defined (__FastPath__)
	ps(mbuf);
	p(fp_mbuf_priv_t);
	pof(fp_mbuf_priv_t, end_of_copy);

#ifdef CONFIG_MCORE_ARCH_XLP
	typedef struct mbuf_shared_info mbuf_t;
	pof(mbuf_t, m_priv);
#endif
#endif /* __FastPath__ */

	/* display ABI */
	pof(_align16_t, align);
	pof(_align32_t, align);
	pof(_align64_t, align);
	p(int);
	p(long);
	p(_ptr_t);
	p(fpn_uintptr_t);

#undef p
#undef pf
#undef psf

int main( __fpn_maybe_unused int argc,  __fpn_maybe_unused const char *argv[])
{
	return 0;	
}
