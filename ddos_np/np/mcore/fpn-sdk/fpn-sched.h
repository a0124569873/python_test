/*
 * Copyright(c) 2007  6WIND
 */
#ifndef __FPN_SCHED_H__
#define __FPN_SCHED_H__

struct fpn_sched_red_algo {
	fpn_atomic64_t s_avg;          /* average queue length, scaled */
	uint32_t q_lim;                /* limit, MAX32 >> Wlog */

	uint32_t Wlog   :8;            /* log(W), W = forgetting factor */
	uint32_t start_idle:1;
	uint32_t unused:23;

	uint64_t red_last;

	struct fpn_red_params { /* per color */
		uint64_t s_min;            /* min threshold, scaled */
		uint64_t s_max;            /* max threshold, scaled */
		int  nb_prob_pass;         /* Nb packets marked pass since last 
                                    * random number generation. */
		uint64_t s_random;         /* Last random number */
		uint64_t s_random_mask;    /* Mask for random */
		uint32_t dpProb;		   /* Drop prob. from user */
	} param[3];
};

struct fpn_sched_td_algo {
	struct fpn_td_params { /* per color */
		uint32_t dp_max;           /* max threshold */
	} param[3];
};

struct fpn_sched_algo {
	union {
		struct fpn_sched_td_algo td_a;
		struct fpn_sched_red_algo red_a;
	} s;
};

typedef struct {
	int algo;
	struct fpn_sched_algo dp;
	uint32_t hiWaterMark;       /* high water mark for this queue - report the highest usage */
	fpn_atomic64_t discardBytes[3];   /* per color */
	fpn_atomic_t discardPackets[3];   /* per color */
} __fpn_cache_aligned fpn_queue_t;

FPN_DECLARE_SHARED(fpn_queue_t, fpn_queue_table[FPN_MAX_OUTPUT_QUEUES]);

#define FPN_SCHED_ACTION_PASS    0
#define FPN_SCHED_ACTION_DROP    1
#define FPN_SCHED_INVALID_COLOR  2

/* idle period in number of cycles */
#ifndef CONFIG_FPN_SCHED_RED_IC
#define CONFIG_FPN_SCHED_RED_IC (4000000ull) /* closed to 10 ms on Octeon */
#endif

//#define FPN_SCHED_DEBUG
#ifdef FPN_SCHED_DEBUG
#define fpn_sched_debug(fmt, args...) do { fpn_printf(fmt, ## args); } while(0)
#else
#define fpn_sched_debug(fmt, args...)
#endif

static inline void fpn_sched_update_hiWaterMark(fpn_queue_t *q, uint32_t qlen)
{
	if (q->hiWaterMark < qlen)
		q->hiWaterMark = qlen;
}
	
static inline uint64_t fpn_red_get_qavg(struct fpn_sched_red_algo *p,
                                             unsigned int backlog)
{
	uint64_t s_avg =  fpn_atomic_read64(&p->s_avg);
	/* best case first */
	if (backlog + s_avg == 0)
		return 0;

	if (backlog == 0) {
		if (s_avg < p->Wlog) {
			/* queue average is too small, reduce to 0 */
			fpn_sched_debug("RED:reduce qavg to 0\n");
			return 0;
		} else if (p->start_idle == 0) {
			/* queue average is significant, enter idle period */
			fpn_sched_debug("RED:start idle\n");
			p->start_idle = 1;
			p->red_last = fpn_get_clock_cycles();
			return  s_avg + (0 - (s_avg >> p->Wlog));
		} else {
			/* idle period has been started, check how long */
			uint64_t now = fpn_get_clock_cycles();
			if ((now - p->red_last) >= CONFIG_FPN_SCHED_RED_IC) {
				/* long time since last packet, reset queue average */
				fpn_sched_debug("RED:long time, reset qavg\n");
				p->start_idle = 0;
				return 0;
			}
			/* short time since last packet, decrease queue average */
			fpn_sched_debug("RED:short time, hold idle period\n");
			return  s_avg + (0 - (s_avg >> p->Wlog));
		}
	} else if (p->start_idle)
		p->start_idle = 0;

	/*
	 *	Real queue average qavg using forgetting factor W
	 *  qavg = qavg*(1-W) + backlog*W;
	 *  qavg/W  = qavg/W + (backlog - qavg) 
	 *  With p->s_avg = qavg << Wlog = qavg/W, scaled qavg is:
	 */

	return  s_avg + (backlog - (s_avg >> p->Wlog));

}

static inline int fpn_red_drop_early(struct fpn_red_params *dp, uint8_t Wlog,
                                     uint64_t s_avg)
{
	/* dp->s_random is 0..2(Plog), and drop_prob = (max-min) / 2(Plog) */
	return !(((s_avg - dp->s_min) >> Wlog) * dp->nb_prob_pass < dp->s_random);
}

static inline int fpn_sched_get_action_red(struct fpn_sched_red_algo *q,
                                           uint8_t color, uint32_t qlen)
{
	struct fpn_red_params *p = &q->param[color];
	uint64_t s_avg;

	if (unlikely(qlen > q->q_lim)) {
		/* hard drop */
		return FPN_SCHED_ACTION_DROP;
	}

	fpn_atomic_set64(&q->s_avg, fpn_red_get_qavg(q, qlen));
	s_avg = fpn_atomic_read64(&q->s_avg);

	fpn_sched_debug("qavg=%d = min=%d max=%d nb_prob_pass=%d s_random=%"PRIx64"\n",
			(int)(s_avg >> q->Wlog), 
			(int)(p->s_min >> q->Wlog),
			(int)(p->s_max >> q->Wlog),
			p->nb_prob_pass,
			p->s_random);

	if (likely(s_avg < p->s_min)) {
		p->nb_prob_pass = -1;
		return FPN_SCHED_ACTION_PASS;
	}

	if (s_avg < p->s_max) {
		if (++p->nb_prob_pass) {
			fpn_sched_debug("diff=%"PRId64" diff>>Wlog=%d count=%d s_random=%"PRIx64"\n",
					s_avg - p->s_min, 
					(int)(s_avg - p->s_min)>>q->Wlog, 
					p->nb_prob_pass, p->s_random);
			if (fpn_red_drop_early(p, q->Wlog, s_avg)) {
				p->nb_prob_pass = 0;
				p->s_random = fpn_get_pseudo_rnd() & p->s_random_mask;
				return FPN_SCHED_ACTION_DROP;
			}
		} else
			p->s_random = fpn_get_pseudo_rnd() & p->s_random_mask;

		return FPN_SCHED_ACTION_PASS;
	}

	p->nb_prob_pass = -1;
	return FPN_SCHED_ACTION_DROP;
}

static inline int fpn_sched_get_action_td(struct fpn_sched_td_algo *p,
                                          uint8_t color, uint32_t qlen)
{
	struct fpn_td_params *dp = &p->param[color];
	if (qlen < dp->dp_max)
		return FPN_SCHED_ACTION_PASS;
	else
		return FPN_SCHED_ACTION_DROP;
}


extern int fpn_sched_packet(struct mbuf *m, fpn_queue_t *p, uint32_t qlen);
extern void fpn_sched_set_queue(fpn_queue_t *q,
                                const struct fpn_queue_params *p);

#endif
