/*
 * Copyright(c) 2008 6WIND, All rights reserved.
 */

#include "fpn.h"
#include "fp-includes.h"
#include "fp-main-process.h"
#include "fptun.h"
#ifdef CONFIG_MCORE_TAP_BPF
#include "fp-bpf_filter.h"
#endif
#include "fp-log.h"

#define TRACE_TAP(level, fmt, args...) do {			\
		FP_LOG(level, TAP, "%s: " fmt "\n", __FUNCTION__, ## args);		\
} while(0)

void fp_tap_init(void)
{
#ifdef CONFIG_MCORE_TAP_BPF
	fp_bpf_init();
#endif
}

static inline int fp_tap_needed(struct mbuf *m, fp_ifnet_t *ifp)
{
	if (likely(!fp_ifnet_is_invalid(ifp) &&
	           fp_ifnet_is_operative(ifp)))
			return 1;
	return 0;
}

/*
 * If mbuf doesn't contain an hardware header then proto argument
 * must be set to the right ethertype (eg. for XinY tunnels).
 */
void fp_tap(struct mbuf *m, fp_ifnet_t *ifp, int proto)
{
	if (likely(!fp_tap_needed(m, ifp)))
		return;

#ifdef CONFIG_MCORE_TAP_BPF
	fp_bpf_filter_input(m, ifp, proto);
#endif
}

/*
 * Send TAP exception to SP.
 * Packets sent here are duplicated packets, hence no need to return
 * any value.
 */
void fp_prepare_tap_exception(struct mbuf *m, fp_ifnet_t *ifp, int proto)
{
	struct mbuf *m2;

	m2 = m_dup(m);
	if (unlikely(m2 == NULL)) {
		TRACE_TAP(FP_LOG_WARNING, "m_dup() failed");
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_dropped);
		return;
	}

	m_priv(m2)->exc_type = FPTUN_TAP;
	m_priv(m2)->exc_proto = proto;

	if (fp_shared->conf.w32.do_func & FP_CONF_DO_TAP_GLOBAL)
		m_priv(m2)->exc_class = 0;
	else
		m_priv(m2)->exc_class = FPTUN_EXC_TARGET_LOCALCP;

	m_priv(m2)->ifuid = ifp->if_ifuid;
	FP_EXCEP_STATS_INC(fp_shared->exception_stats, TapExceptions);
	fp_process_input_finish(m2, fp_prepare_exception(m2, FPTUN_EXC_TAP));
}
