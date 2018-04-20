/*
 *  * Copyright(c) 2014 6WIND
 *   */

/* Assume m->exc_proto is set (0 if link layer is present, ethertype
 * otherwise).
 */

#include "fp-includes.h"

void fp_change_ifnet_packet(struct mbuf *m, fp_ifnet_t *ifp,
			    int incstats, __fpn_maybe_unused int do_tap)
{
#ifdef CONFIG_MCORE_TAP
	if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_TAP) && do_tap)
		fp_tap(m, ifp, m_priv(m)->exc_proto);
#endif
	m_priv(m)->ifuid = ifp->if_ifuid;
	set_mvrfid(m, ifp2vrfid(ifp));
	if (incstats) {
		FP_IF_STATS_INC(ifp->if_stats, ifs_ipackets);
		FP_IF_STATS_ADD(ifp->if_stats, ifs_ibytes, m_len(m));
	}
}
