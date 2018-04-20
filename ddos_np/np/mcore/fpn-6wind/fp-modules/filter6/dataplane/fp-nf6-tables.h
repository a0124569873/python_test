/*
 * Copyright(c) 2009 6WIND, All rights reserved.
 */

#ifndef __FP_NF6_TABLES_H__
#define __FP_NF6_TABLES_H__

int fp_nf6_hook_iterate(struct mbuf *m, int hook, const int *table_list, 
		        const fp_ifnet_t *indev, const fp_ifnet_t *outdev);
void fp_nf6_init(void);
uint8_t fp_nf6ct_update(struct mbuf *m, uint16_t fragoff, uint8_t nexthdr, uint32_t offset);

static inline int fp_nf6_hook(struct mbuf *m, int hook, const fp_ifnet_t *indev, 
			      const fp_ifnet_t *outdev)
{
	int verdict;
	const int *table_list;
#ifdef CONFIG_MCORE_NF_TABLE_PER_VR
	uint16_t nf_vr = m2vrfid(m);
#else
	uint16_t nf_vr = 0;
#endif

	TRACE_NF(FP_LOG_DEBUG, "%s(m=%p, hook=%s, indev=%s, outdev=%s)", __func__,
		 m, hook_names[hook],
		 (indev == NULL) ? "(null)" : indev->if_name,
		 (outdev == NULL) ? "(null)" : outdev->if_name);
	
	/* this hook is not used, return */
	if (fp_shared->nf6_conf.enabled_hook[nf_vr][hook] == 0)
		return FP_CONTINUE;

	table_list = fp_shared->fp_nf6_hook_prio[fp_shared->fp_nf6_current_hook_prio][hook];
	verdict = fp_nf6_hook_iterate(m, hook, table_list, indev, outdev);
	if (verdict == FP_NF_ACCEPT || verdict == FP_NF_STOP) {
		TRACE_NF(FP_LOG_DEBUG, "%s: verdict is ACCEPT or STOP => continue", __func__);
		return FP_CONTINUE;
	}
	else if (verdict == FP_NF_DROP) {
		TRACE_NF(FP_LOG_DEBUG, "%s: verdict is DROP => drop packet", __func__);
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNetfilter);
		return FP_DROP;
	}

	TRACE_NF(FP_LOG_DEBUG, "%s: verdict is EXCEPTION => send packet as exception", __func__);
	/* If verdict is FP_NF_EXCEPTION, we fall is this default case */
	return fp_ip_prepare_exception(m, FPTUN_EXC_NF_FUNC);
}

static inline int fp_nf6ct_get(struct mbuf *m, struct fp_ip6_hdr *ip6,
			       uint8_t proto, uint16_t sport, uint16_t dport)
{
	if (m_priv(m)->fp_nfct_established == FP_NF_CT_MBUF_ESTABLISHED) {
		/* ensure state is valid by checking assured flag */
		if (m_priv(m)->fp_nfct.v6->flag & FP_NFCT_FLAG_ASSURED)
			return 0;
	}

	/* performs a lookup in fp_shared->fp_nf6_ct based on the 6-tuples */
	m_priv(m)->fp_nfct.v6 = fp_nf6ct_lookup(proto, &ip6->ip6_src,
					        &ip6->ip6_dst, sport, dport,
					        m2vrfid(m), &m_priv(m)->fp_nfct_dir);

	/* conntrack found */
	if (m_priv(m)->fp_nfct.v6 != NULL)
		return 0;
	
	return -1;
}

#endif /* __FP_NF6_TABLES_H__ */
