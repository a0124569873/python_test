/*
 * Copyright(c) 2006 6WIND
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "fp.h"

static const _fp_nh_entry_t nh_local = {
	.rt_type = RT_TYPE_ROUTE_LOCAL,
	.nh_type = NH_TYPE_IFACE,
	.nh_refcnt = 1,
	.nh_l2_state = L2_STATE_REACHABLE,
};

static const _fp_nh_entry_t nh_blackhole = {
	.rt_type = RT_TYPE_ROUTE_BLACKHOLE,
	.nh_type = NH_TYPE_IFACE,
	.nh_refcnt = 1,
	.nh_l2_state = L2_STATE_REACHABLE,
};

void fp_init(void)
{
	uint32_t i;
	fp_shared->conf.u64 = 0;
#ifdef CONFIG_MCORE_NETFILTER
	bzero(&fp_shared->nf_conf, sizeof(fp_shared->nf_conf));
#endif /* CONFIG_MCORE_NETFILTER */
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	bzero(&fp_shared->nf6_conf, sizeof(fp_shared->nf6_conf));
#endif /* CONFIG_MCORE_NETFILTER_IPV6 */

	/* all logs >= DEFAULT activated by default */
	fp_shared->debug.level = FP_LOG_DEFAULT;
	fp_shared->debug.type = ~(0);
	fp_shared->debug.mode = FP_LOG_MODE_CONSOLE;
#ifdef CONFIG_MCORE_CPONLY_PORTMASK
	/* CP-only portmask */
	fp_shared->cponly_portmask = 0;
#endif

	/* Shared tables */
	bzero(&fp_shared->fp_8_entries, sizeof(fp_shared->fp_8_entries));
	bzero(&fp_shared->fp_16_entries, sizeof(fp_shared->fp_16_entries));
	bzero(&fp_shared->fp_8_table, sizeof(fp_shared->fp_8_table));
	bzero(&fp_shared->fp_16_table, sizeof(fp_shared->fp_16_table));
	bzero(&fp_shared->fp_nh4_table, sizeof(fp_shared->fp_nh4_table));
	memcpy(&fp_shared->fp_nh4_table[FP_IPV4_NH_ROUTE_LOCAL].nh,
			&nh_local, sizeof(_fp_nh_entry_t));
	memcpy(&fp_shared->fp_nh4_table[FP_IPV4_NH_ROUTE_BLACKHOLE].nh,
			&nh_blackhole, sizeof(_fp_nh_entry_t));
	bzero(&fp_shared->fp_nh4_hash, sizeof(fp_shared->fp_nh4_hash));
	bzero(&fp_shared->fp_rt4_table, sizeof(fp_shared->fp_rt4_table));
	bzero(&fp_shared->ifnet, sizeof(fp_shared->ifnet));
#ifdef CONFIG_MCORE_VRF
	bzero(&fp_shared->fp_xvrf, sizeof(fp_shared->fp_xvrf));
#endif
	bzero(&fp_shared->ifport, sizeof(fp_shared->ifport));
	bzero(&fp_shared->ip_stats, sizeof(fp_shared->ip_stats));
	bzero(&fp_shared->global_stats, sizeof(fp_shared->global_stats));
#ifdef CONFIG_MCORE_ARP_REPLY
	bzero(&fp_shared->arp_stats, sizeof(fp_shared->arp_stats));
#endif
#ifdef CONFIG_MCORE_SOCKET
	bzero(&fp_shared->tcp_stats, sizeof(fp_shared->tcp_stats));
	bzero(&fp_shared->udp_stats, sizeof(fp_shared->udp_stats));
#ifdef CONFIG_MCORE_SOCKET_INET6
	bzero(&fp_shared->udp6_stats, sizeof(fp_shared->udp6_stats));
#endif
#endif
#ifdef CONFIG_MCORE_MULTIBLADE
	bzero(&fp_shared->multiblade_stats, sizeof(fp_shared->multiblade_stats));
#endif
	bzero(&fp_shared->exception_stats, sizeof(fp_shared->exception_stats));
#ifdef CONFIG_MCORE_IPV6
	bzero(&fp_shared->fp_nh6_table, sizeof(fp_shared->fp_nh6_table));
	memcpy(&fp_shared->fp_nh6_table[FP_IPV6_NH_ROUTE_LOCAL].nh,
			&nh_local, sizeof(_fp_nh_entry_t));
	memcpy(&fp_shared->fp_nh6_table[FP_IPV6_NH_ROUTE_BLACKHOLE].nh,
			&nh_blackhole, sizeof(_fp_nh_entry_t));
	bzero(&fp_shared->fp_nh6_hash, sizeof(fp_shared->fp_nh6_hash));
	bzero(&fp_shared->fp_rt6_table, sizeof(fp_shared->fp_rt6_table));
	bzero(&fp_shared->ip6_stats, sizeof(fp_shared->ip6_stats));
#endif /* CONFIG_MCORE_IPV6 */

#ifdef CONFIG_MCORE_NETFILTER
	{
		int vr, t, r, h;
		int hook_prio[FP_NF_IP_NUMHOOKS][FP_NF_TABLE_NUM + 1] = {
			{ FP_NF_TABLE_MANGLE, FP_NF_TABLE_NAT, -1 },       /* FP_NF_IP_PRE_ROUTING */
			{ FP_NF_TABLE_FILTER, FP_NF_TABLE_MANGLE, -1 },    /* FP_NF_IP_LOCAL_IN */
			{ FP_NF_TABLE_MANGLE, FP_NF_TABLE_FILTER, -1 },    /* FP_NF_IP_FORWARD */
			{ FP_NF_TABLE_FILTER, FP_NF_TABLE_MANGLE, FP_NF_TABLE_NAT, -1 },    /* FP_NF_IP_LOCAL_OUT */
			{ FP_NF_TABLE_MANGLE, FP_NF_TABLE_NAT, -1 } };     /* FP_NF_IP_POST_ROUTING */

		memcpy(fp_shared->fp_nf_hook_prio[0], hook_prio, sizeof(hook_prio));
		memcpy(fp_shared->fp_nf_hook_prio[1], hook_prio, sizeof(hook_prio));
		fp_shared->fp_nf_current_hook_prio = 0;

		memset(fp_shared->fp_nf_tables, 0, sizeof(fp_shared->fp_nf_tables));
		memset(fp_shared->fp_nf_rules, 0, sizeof(fp_shared->fp_nf_rules));
		fp_shared->fp_nf_current_table = 0;

		r = 0;
		for (vr = 0; vr < FP_NF_MAX_VR; vr++) {
			for (t = 0; t < FP_NF_TABLE_NUM; t++) {
				fp_nftable_t *tb = &fp_shared->fp_nf_tables[0][vr][t];

				/* Each table must have at least one rule to maintain
				 * a consistent state in the shared memory. */
				for (h = 0; h < FP_NF_IP_NUMHOOKS; h++) {
					tb->fpnftable_hook_entry[h] = r;
					tb->fpnftable_underflow[h] = r;
				}
				fp_shared->fp_nf_rules[0][r].target.type = FP_NF_TARGET_TYPE_ERROR;
				r++;

				tb->fpnftable_rules_count = 1;
			}
		}
	}

#ifdef CONFIG_MCORE_NF_CT
	bzero(&fp_shared->fp_nf_ct, sizeof(fp_shared->fp_nf_ct));
	/* The hash_next starting value is supposed to be 'undefined', represented by FP_NF_CT_MAX */
	for (i = 0; i < FP_NF_CT_MAX; i++) {
		fp_shared->fp_nf_ct.fp_nfct[i].tuple[FP_NF_IP_CT_DIR_ORIGINAL].hash_next.s.index = FP_NF_CT_MAX;
		fp_shared->fp_nf_ct.fp_nfct[i].tuple[FP_NF_IP_CT_DIR_REPLY].hash_next.s.index = FP_NF_CT_MAX;
		fp_shared->fp_nf_ct.fp_nfct[i].next_available = i+1;
#ifdef CONFIG_MCORE_NF_CT_CPEID
		fp_shared->fp_nf_ct.fp_nfct[i].hash_next_cpeid = FP_NF_CT_MAX;
		FP_NF_CT_SET_HASH_PREV_CPEID(fp_shared->fp_nf_ct.fp_nfct[i], FP_NF_CT_MAX);
#endif
	}
	/* The algorithm supposes that hash table is initialized to FP_NF_CT_MAX for all entries */
	for (i = 0; i < FP_NF_CT_HASH_SIZE; i++)
		fp_shared->fp_nf_ct.fp_nfct_hash[i].s.index = FP_NF_CT_MAX;

#ifdef CONFIG_MCORE_NF_CT_CPEID
	for (i = 0; i < FP_NF_CT_HASH_CPEID_SIZE; i++)
		fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[i] = FP_NF_CT_MAX;
#endif
#endif

#endif /* CONFIG_MCORE_NETFILTER */
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	{
		int vr, t, r, h;
		int hook6_prio[FP_NF_IP_NUMHOOKS][FP_NF6_TABLE_NUM + 1] = {
			{ FP_NF_TABLE_MANGLE, -1 },       /* FP_NF_IP_PRE_ROUTING */
			{ FP_NF_TABLE_FILTER, FP_NF_TABLE_MANGLE, -1 },    /* FP_NF_IP_LOCAL_IN */
			{ FP_NF_TABLE_MANGLE, FP_NF_TABLE_FILTER, -1 },    /* FP_NF_IP_FORWARD */
			{ FP_NF_TABLE_FILTER, FP_NF_TABLE_MANGLE, -1 },    /* FP_NF_IP_LOCAL_OUT */
			{ FP_NF_TABLE_MANGLE, -1 } };     /* FP_NF_IP_POST_ROUTING */

		memcpy(fp_shared->fp_nf6_hook_prio[0], hook6_prio, sizeof(hook6_prio));
		memcpy(fp_shared->fp_nf6_hook_prio[1], hook6_prio, sizeof(hook6_prio));
		fp_shared->fp_nf6_current_hook_prio = 0;

		memset(fp_shared->fp_nf6_tables, 0, sizeof(fp_shared->fp_nf6_tables));
		memset(fp_shared->fp_nf6_rules, 0, sizeof(fp_shared->fp_nf6_rules));
		fp_shared->fp_nf6_current_table = 0;

		r = 0;
		for (vr = 0; vr < FP_NF_MAX_VR; vr++) {
			for (t = 0; t < FP_NF6_TABLE_NUM; t++) {
				fp_nf6table_t *tb = &fp_shared->fp_nf6_tables[0][vr][t];

				/* Each table must have at least one rule to maintain
				 * a consistent state in the shared memory. */
				for (h = 0; h < FP_NF_IP_NUMHOOKS; h++) {
					tb->fpnf6table_hook_entry[h] = r;
					tb->fpnf6table_underflow[h] = r;
				}
				fp_shared->fp_nf6_rules[0][r].target.type = FP_NF_TARGET_TYPE_ERROR;
				r++;

				tb->fpnf6table_rules_count = 1;
			}
		}
	}
	bzero(&fp_shared->fp_nf6_ct, sizeof(fp_shared->fp_nf6_ct));

	/* The hash_next starting value is supposed to be 'undefined', represented by FP_NF6_CT_MAX */
	for (i = 0; i < FP_NF6_CT_MAX; i++) {
		fp_shared->fp_nf6_ct.fp_nf6ct[i].tuple[FP_NF_IP_CT_DIR_ORIGINAL].hash_next.s.index = FP_NF6_CT_MAX;
		fp_shared->fp_nf6_ct.fp_nf6ct[i].tuple[FP_NF_IP_CT_DIR_REPLY].hash_next.s.index = FP_NF6_CT_MAX;
		fp_shared->fp_nf6_ct.fp_nf6ct[i].next_available = i+1;
	}
	/* The algorithm supposes that hash table is initialized to FP_NF6_CT_MAX for all entries */
	for (i = 0; i < FP_NF6_CT_HASH_SIZE; i++)
		fp_shared->fp_nf6_ct.fp_nf6ct_hash[i].s.index = FP_NF6_CT_MAX;

#endif /* CONFIG_MCORE_NETFILTER_IPV6 */

	/* Precalculate each link from table_entries to entries */
	for (i = 0; i < FP_NB_8_TABLE_ENTRIES; i++)
		fp_shared->fp_8_table[i].entries = i*(1 << 8);

#if FP_NB_16_TABLE_ENTRIES != 0
	for (i = 0; i < FP_NB_16_TABLE_ENTRIES; i++)
		fp_shared->fp_16_table[i].entries = i*(1 << 16);
#endif

	/* Init ifnet */
	for (i = 0 ; i < sizeof(fp_shared->ifnet.table)/sizeof(fp_ifnet_t); ++i) {
		fp_shared->ifnet.table[i].if_ifuid = 0;
		fp_shared->ifnet.table[i].if_port = FP_IFNET_VIRTUAL_PORT;
	}

	for (i = 0 ; i < sizeof(fp_shared->ifport)/sizeof(fp_ifport_t); ++i) {
		fp_shared->ifport[i].ifuid = 0;
		fp_shared->ifport[i].cached_ifp = 0;
	}

	fp_shared->cp_if_port = 0;
	fp_shared->cp_if_mtu = 0;
	bzero(&fp_shared->cp_if_mac, sizeof(fp_shared->cp_if_mac));
	bzero(&fp_shared->fp_if_mac, sizeof(fp_shared->fp_if_mac));
#ifdef CONFIG_MCORE_MULTIBLADE
	fp_shared->fpib_ifuid = 0;
#endif
	bzero(&fp_shared->ifnet.name_hash, sizeof(fp_shared->ifnet.name_hash));

	/* Init NH entries */
	for (i = 0 ; i < FP_IPV4_NBNHENTRIES; ++i) {
		fp_shared->fp_nh4_table[i].nh.nh_ifuid = 0;
		fp_shared->fp_nh4_table[i].nh.nh_l2_state = L2_STATE_NONE;
	}

	/* Init NH4 hash table */
	fp_shared->fp_nh4_available_head = 1;
	fp_shared->fp_nh4_available_tail = FP_IPV4_NBNHENTRIES - 1;

	for (i = 1; i < FP_IPV4_NBNHENTRIES - 1; i++)
		fp_shared->fp_nh4_table[i].next = i + 1;

	/* Init last-added entry (set arbitrary to 1) */
	fp_shared->fp_rt4_last_added = 1;

	/*
	 * Some tables are reserved as VR entry-points
	 */
	for (i = 0; i < FP_MAX_VR; i++) {
#ifdef CONFIG_MCORE_RT_IP_BASE8
		fp_shared->fp_8_table[i].used = FP_USED_V4;
#else
		fp_shared->fp_16_table[i].used = FP_USED_V4;
#endif
	}

#ifdef CONFIG_MCORE_IPV6
	/*
	 * Some tables are reserved as VR entry-points
	 */
	for (i = FP_IPV6_TABLE_START; i < (FP_IPV6_TABLE_START + FP_MAX_VR); i++) {
#ifdef CONFIG_MCORE_RT_IPV6_BASE8
		fp_shared->fp_8_table[i].used = FP_USED_V6;
#else
		fp_shared->fp_16_table[i].used = FP_USED_V6;
#endif
	}
	/* Init NH entries */
	for (i = 0 ; i < FP_IPV6_NBNHENTRIES; ++i) {
		fp_shared->fp_nh6_table[i].nh.nh_ifuid = 0;
		fp_shared->fp_nh6_table[i].nh.nh_l2_state = L2_STATE_NONE;
	}

	fp_shared->fp_nh6_available_head = 1;
	fp_shared->fp_nh6_available_tail = FP_IPV6_NBNHENTRIES - 1;
	for (i = 1; i < FP_IPV6_NBNHENTRIES - 1; i++)
		fp_shared->fp_nh6_table[i].next = i + 1;

	/* Init fp_cumulative_width6 array */
	fp_shared->fp_cumulative_width6[0] = FP_IPV6_LAYER_WIDTH(0);
	for(i = 1; i < FP_IPV6_NBLAYERS; i++)
		fp_shared->fp_cumulative_width6[i] = 
		   fp_shared->fp_cumulative_width6[i-1]+ FP_IPV6_LAYER_WIDTH(i);

	/* 
	 * Init precalculated tables 
	 * We store the difference between the table & the start of shared memory
	 * to avoid the use of pointers
	 */
	for(i = 0; i < FP_IPV6_NBLAYERS; i++) {
#ifndef CONFIG_MCORE_RT_IPV6_BASE8
		if(FP_IPV6_LAYER_WIDTH(i) == 16) {
			fp_shared->fp_table6[i] = (uint32_t)((void *)fp_shared->fp_16_table - (void *)fp_shared);
			fp_shared->fp_entries6[i] = (uint32_t)((void *)fp_shared->fp_16_entries - (void *)fp_shared);
		} else 
#endif
		{
			fp_shared->fp_table6[i] = (uint32_t)((void *)fp_shared->fp_8_table - (void *)fp_shared);
			fp_shared->fp_entries6[i] = (uint32_t)((void *)fp_shared->fp_8_entries - (void *)fp_shared);
		}
	}
	/* Init last-added entry (set arbitrary to 1) */
	fp_shared->fp_rt6_last_added = 1;
#endif /* CONFIG_MCORE_IPV6 */

#if defined(CONFIG_MCORE_XIN4) || defined(CONFIG_MCORE_XIN6)
	/* index 0 means end of hash list or unconfigured tunnel interface */
	bzero(&fp_shared->fp_tunnels, sizeof(fp_shared->fp_tunnels));
#endif

#ifdef CONFIG_MCORE_MULTICAST4
        for (i = 0; i < FP_MFC_MAX; i++) {
		fp_mfc_entry_t *c = &fp_shared->fp_mfc_table[i];
		c->iif = FP_IIF_UNUSED;
		c->next = FP_NEXT_UNUSED;
        }

	bzero(&fp_shared->fp_mcastgrp_table,
	      sizeof(fp_shared->fp_mcastgrp_table));
	fp_shared->fp_mcastgrp_num = 0;
	fp_shared->fp_mcastgrp_opt = 0;
#endif
#ifdef CONFIG_MCORE_MULTICAST6
        for (i = 0; i < FP_MFC6_MAX; i++) {
                fp_mfc6_entry_t *c = &fp_shared->fp_mfc6_table[i];
                c->iif = FP_IIF_UNUSED;
                c->next = FP_NEXT_UNUSED;
        }

	bzero(&fp_shared->fp_mcast6grp_table,
	      sizeof(fp_shared->fp_mcast6grp_table));
	fp_shared->fp_mcast6grp_num = 0;
	fp_shared->fp_mcast6grp_opt = 0;
#endif

#ifdef CONFIG_MCORE_IPSEC
	fp_ipsec_init();
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_ipsec6_init();
#endif
#ifdef CONFIG_MCORE_IPSEC_SVTI
	fp_svti_init();
#endif
#ifdef CONFIG_MCORE_VXLAN
	fp_vxlan_init_shmem(0);
#endif

	fp_rfps_conf_init();

#ifdef CONFIG_MCORE_MULTIBLADE
	fp_shared->fp_neigh_bladeid = 0;
#ifdef CONFIG_MCORE_NETFILTER
	fp_shared->fp_nf_ct_bladeid = 0;
#endif
#endif

	fp_shared->fp_reass4_maxq_len = FP_REASS4_DEFAULT_MAXQLEN;
	fp_shared->fp_reass6_maxq_len = FP_REASS6_DEFAULT_MAXQLEN;

	fp_shared->cp_if_fptun_size_thresh = 0;
	fp_shared->fpib_fptun_size_thresh = 0;

#ifdef CONFIG_MCORE_IP
	fp_pool_addr_init();
#endif

	/* Set magic when init is finished */
	fp_shared->conf.s.magic = FP_SHARED_MAGIC32;
}
