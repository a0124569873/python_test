/*
 * Copyright(c) 2009 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"
#include "fp-main-process.h"
#include "fp-tc-erl.h"
#include "fptun.h"
#include "fp-mbuf-priv.h"

#define TRACE_EXC(level, fmt, args...) do {			\
		FP_LOG(level, EXC, fmt "\n", ## args);		\
} while(0)
/* Exception rate limit: run TC #0 and accept/reject
 * using color, priority and class.
 * Return -1 if packet is dropped and freed, 0 if accepted.
 */
int fp_tc_erl(struct mbuf *m)
{
	int color;
	unsigned class = (unsigned)m_priv(m)->exc_class;

	color = fpn_tc_input(m, FP_TC_ERL);

	if (unlikely(color >= 0)) {
		switch (FPTUN_EXC_PRIO(class)) {
		case FPTUN_EXC_PRIO_LOW:
			if (color != FPN_QOS_COLOR_GREEN) {
				TRACE_EXC(FP_LOG_DEBUG, "%s: Drop packet"
					   "  packet class: %d, priority LOW",
					   __FUNCTION__, class);
				goto reject;
			}
			break;
		case FPTUN_EXC_PRIO_MED:
			if (color == FPN_QOS_COLOR_RED) {
				TRACE_EXC(FP_LOG_DEBUG, "%s: Drop packet"
					   "  packet class: %d, priority MEDIUM",
					   __FUNCTION__, class);
				goto reject;
			}
			break;
		case FPTUN_EXC_PRIO_HIGH:                         
			TRACE_EXC(FP_LOG_DEBUG, "%s: Packet accepted"
				   "  packet class: %d, priority HIGH",
				   __FUNCTION__, class);
			break;
		default:
			TRACE_EXC(FP_LOG_DEBUG, "%s: Drop packet"
				   "  packet class: %d, priority UNKOWN",
				   __FUNCTION__, class);
			goto reject;
		} 
	}

	return 0;

reject:
	TRACE_EXC(FP_LOG_DEBUG, "%s: Dropped packet", __FUNCTION__);
	FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_dropped);
	m_freem(m);
	return -1;
}
