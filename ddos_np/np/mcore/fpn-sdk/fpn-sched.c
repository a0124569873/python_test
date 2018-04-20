/*
 * Copyright(c) 2007 6WIND
 */

#include "fpn.h"
#include "fpn-egress.h"
#include "fpn-sched.h"

FPN_DEFINE_SHARED(fpn_queue_t, fpn_queue_table[FPN_MAX_OUTPUT_QUEUES]) __fpn_cache_aligned;

static void fpn_sched_reset_common(fpn_queue_t *q)
{
	q->hiWaterMark = 0;
	fpn_atomic_set64(&q->discardBytes[FPN_QOS_COLOR_GREEN], 0);
	fpn_atomic_set64(&q->discardBytes[FPN_QOS_COLOR_YELLOW], 0);
	fpn_atomic_set64(&q->discardBytes[FPN_QOS_COLOR_RED], 0);
	fpn_atomic_set(&q->discardPackets[FPN_QOS_COLOR_GREEN], 0);
	fpn_atomic_set(&q->discardPackets[FPN_QOS_COLOR_YELLOW], 0);
	fpn_atomic_set(&q->discardPackets[FPN_QOS_COLOR_RED], 0);
}

static void fpn_sched_reset_td(fpn_queue_t *q)
{
	fpn_sched_reset_common(q);
}

static void fpn_sched_reset_red(fpn_queue_t *q)
{
	fpn_sched_reset_common(q);
	fpn_atomic_set64(&q->dp.s.red_a.s_avg, 0);
}

static void fpn_sched_set_red_dp(struct fpn_red_params *r,
                                    uint32_t dp_min,
                                    uint32_t dp_max,
                                    uint32_t dp_prob,
                                    uint32_t Wlog)
{
	uint8_t Plog;
	uint32_t interval;

	r->dpProb = dp_prob;
	r->s_min = dp_min << Wlog;
	r->s_max = dp_max << Wlog;

	Plog = dp_prob;
	interval = dp_max - dp_min;
	while (interval > 0) {
		Plog++;
		interval = interval >> 1;
	}
	r->s_random_mask = Plog < 64 ? (uint64_t)((1 << Plog) - 1) : ~0ULL;

	r->nb_prob_pass = -1;

	fpn_sched_debug("set_red: qthmin=%" PRId64 "(%d), max=%" PRId64 "(%d) Plog=%d s_random_mask=%" PRIx64 "\n",
	r->s_min, dp_min, r->s_max, dp_max, Plog, r->s_random_mask);
}
	
static void fpn_sched_set_red_param(fpn_queue_t *q, const struct fpn_queue_params *p)
{
	uint8_t Wlog;

	fpn_sched_reset_red(q);

	Wlog = p->ud.red.movingAverage;
	q->dp.s.red_a.Wlog = Wlog;
	fpn_atomic_set64(&q->dp.s.red_a.s_avg,0);
	q->dp.s.red_a.q_lim = 0xFFFFFFFF >> Wlog;

	fpn_sched_set_red_dp(
			&q->dp.s.red_a.param[FPN_QOS_COLOR_GREEN],
			p->ud.red.dpGmin,
			p->ud.red.dpGmax,
			p->ud.red.dpGprob,
			Wlog);

	fpn_sched_set_red_dp(
			&q->dp.s.red_a.param[FPN_QOS_COLOR_YELLOW],
			p->ud.red.dpYmin,
			p->ud.red.dpYmax,
			p->ud.red.dpYprob,
			Wlog);

	fpn_sched_set_red_dp(
			&q->dp.s.red_a.param[FPN_QOS_COLOR_RED],
			p->ud.red.dpRmin,
			p->ud.red.dpRmax,
			p->ud.red.dpRprob,
			Wlog);
	
}

static void fpn_sched_get_red_param(fpn_queue_t *q, struct fpn_queue_params *p)
{
	uint8_t Wlog = q->dp.s.red_a.Wlog;

	p->ud.red.movingAverage = Wlog;
	p->ud.red.dpGmin = q->dp.s.red_a.param[FPN_QOS_COLOR_GREEN].s_min >> Wlog;
	p->ud.red.dpGmax = q->dp.s.red_a.param[FPN_QOS_COLOR_GREEN].s_max >> Wlog;
	p->ud.red.dpGprob = q->dp.s.red_a.param[FPN_QOS_COLOR_GREEN].dpProb;
	p->ud.red.dpYmin = q->dp.s.red_a.param[FPN_QOS_COLOR_YELLOW].s_min >> Wlog;
	p->ud.red.dpYmax = q->dp.s.red_a.param[FPN_QOS_COLOR_YELLOW].s_max >> Wlog;
	p->ud.red.dpYprob = q->dp.s.red_a.param[FPN_QOS_COLOR_YELLOW].dpProb;
	p->ud.red.dpRmin = q->dp.s.red_a.param[FPN_QOS_COLOR_RED].s_min >> Wlog;
	p->ud.red.dpRmax = q->dp.s.red_a.param[FPN_QOS_COLOR_RED].s_max >> Wlog;
	p->ud.red.dpRprob = q->dp.s.red_a.param[FPN_QOS_COLOR_RED].dpProb;
}

static void fpn_sched_set_td_param(fpn_queue_t *q, const struct fpn_queue_params *p)
{
	fpn_sched_reset_td(q);
	q->dp.s.td_a.param[FPN_QOS_COLOR_GREEN].dp_max = p->ud.taildrop.dpGmax;
	q->dp.s.td_a.param[FPN_QOS_COLOR_YELLOW].dp_max = p->ud.taildrop.dpYmax;
	q->dp.s.td_a.param[FPN_QOS_COLOR_RED].dp_max = p->ud.taildrop.dpRmax;
}

static void fpn_sched_get_td_param(fpn_queue_t *q, struct fpn_queue_params *p)
{
	p->ud.taildrop.dpGmax = q->dp.s.td_a.param[FPN_QOS_COLOR_GREEN].dp_max;
	p->ud.taildrop.dpYmax = q->dp.s.td_a.param[FPN_QOS_COLOR_YELLOW].dp_max;
	p->ud.taildrop.dpRmax = q->dp.s.td_a.param[FPN_QOS_COLOR_RED].dp_max;
}

static void fpn_sched_set_none_param(fpn_queue_t *q, const struct fpn_queue_params *p)
{
	fpn_sched_reset_common(q);
}

void fpn_sched_set_queue(fpn_queue_t *q, const struct fpn_queue_params *p)
{
	if (p->discardAlgorithm == FPN_QOS_DISC_TAILDROP) {
		q->algo = FPN_QOS_DISC_TAILDROP;
		fpn_sched_set_td_param(q, p);
	} else if (p->discardAlgorithm == FPN_QOS_DISC_WRED) {
		q->algo = FPN_QOS_DISC_WRED;
		fpn_sched_set_red_param(q, p);
	} else {
		q->algo = FPN_QOS_DISC_NONE;
		fpn_sched_set_none_param(q, p);
	}
}

int fpn_sched_packet(struct mbuf *m, fpn_queue_t *q, uint32_t qlen)
{
	uint8_t color = m_get_egress_color(m);
	int action;

	if (unlikely(color > FPN_QOS_COLOR_MAX))
		return FPN_SCHED_INVALID_COLOR;

	if (q->algo == FPN_QOS_DISC_TAILDROP)
		action = fpn_sched_get_action_td(&q->dp.s.td_a, color, qlen);
	else if (q->algo == FPN_QOS_DISC_WRED)
		action = fpn_sched_get_action_red(&q->dp.s.red_a, color, qlen);
	else /* FPN_QOS_DISC_NONE case */
		return 0;

	if (action == FPN_SCHED_ACTION_DROP) {
		fpn_sched_debug("fpn_sched_packet: drop it\n");
		fpn_atomic_add(&q->discardPackets[color], 1);
		fpn_atomic_add64(&q->discardBytes[color], m_len(m));
		return FPN_SCHED_ACTION_DROP;
	}

	return FPN_SCHED_ACTION_PASS;
}

int fpn_read_queue_stats(uint16_t queueId, 
                         struct fpn_queue_stats *statsPtr)
{
	fpn_queue_t *q = &fpn_queue_table[queueId];

	if (statsPtr == NULL)
		return -1;

	statsPtr->hiWaterMark = q->hiWaterMark;
	statsPtr->discardBytesG = fpn_atomic_read64(&q->discardBytes[FPN_QOS_COLOR_GREEN]);
	statsPtr->discardBytesY = fpn_atomic_read64(&q->discardBytes[FPN_QOS_COLOR_YELLOW]);
	statsPtr->discardBytesR = fpn_atomic_read64(&q->discardBytes[FPN_QOS_COLOR_RED]);
	statsPtr->discardPacketsG = fpn_atomic_read(&q->discardPackets[FPN_QOS_COLOR_GREEN]);
	statsPtr->discardPacketsY = fpn_atomic_read(&q->discardPackets[FPN_QOS_COLOR_YELLOW]);
	statsPtr->discardPacketsR = fpn_atomic_read(&q->discardPackets[FPN_QOS_COLOR_RED]);
	statsPtr->averageQueLength = (q->algo == FPN_QOS_DISC_WRED) ? fpn_atomic_read64(&q->dp.s.red_a.s_avg) >> q->dp.s.red_a.Wlog : 0;

	return 0;
}
int fpn_reset_queue_stats(uint16_t queueId)
{
	fpn_queue_t *q = &fpn_queue_table[queueId];
	if (q->algo == FPN_QOS_DISC_TAILDROP)
		fpn_sched_reset_td(q);
	else if (q->algo == FPN_QOS_DISC_WRED)
		fpn_sched_reset_red(q);
	else /* FPN_QOS_DISC_NONE case */
		fpn_sched_reset_common(q);

	return 0;
}

int fpn_read_queue_params(uint16_t queueId, struct fpn_queue_params *params)
{
	fpn_queue_t *q = &fpn_queue_table[queueId];

	params->discardAlgorithm = q->algo;
	if (q->algo == FPN_QOS_DISC_TAILDROP)
		fpn_sched_get_td_param(q, params);
	else if (q->algo == FPN_QOS_DISC_WRED)
		fpn_sched_get_red_param(q, params);
	return 0;
}


