/*
 * Copyright(c) 2008 6WIND
 */
#include "fpn.h"
#include "fpn-tc.h"

#define FPN_TC_DEBUG 0
#if FPN_TC_DEBUG == 2
#define tc_debug(fmt, args...) do { fpn_printf(fmt, ## args); } while(0)
#define tc_debug2 tc_debug
#elif FPN_TC_DEBUG == 1
#define tc_debug(fmt, args...) do { fpn_printf(fmt, ## args); } while(0)
#define tc_debug2(fmt, args...)
#else
#define tc_debug(fmt, args...)
#define tc_debug2(fmt, args...)
#endif

typedef struct fpn_tc_bucket {
	fpn_spinlock_t lock;

	int64_t  c_tokens; /* scaled */
	uint64_t c_last_cycles;

	int64_t  e_tokens; /* scaled */
	uint64_t e_last_cycles;

	struct {
		uint64_t packets;
		uint64_t bytes;
	} stats[FPN_QOS_COLOR_MAX+1];
} __fpn_cache_aligned fpn_tc_bucket_t;

typedef struct fpn_tc_entry {
	fpn_tc_bucket_t tcb;
	struct { /* values below are scaled */
		uint64_t c_rate;
		uint64_t c_bs;
		uint64_t c_filluptime;
		uint64_t e_rate;
		uint64_t e_bs;
		uint64_t e_filluptime;

		uint32_t flags;
	} param; /* mostly read */
} fpn_tc_entry_t;

static FPN_DEFINE_SHARED(fpn_tc_entry_t, tc[FPN_TC_MAX]);
#define fpn_get_tc(x)   &tc[x]

/*
 * internal representation of token bucket parameters
 * rate: (bytes/secs << 32) / frequency
 * bs: bytes << 32
 */
#define	FPN_TC_SHIFT 32
#define	FPN_TC_SCALE(x)	((int64_t)(x) << FPN_TC_SHIFT)
#define	FPN_TC_UNSCALE(x)	((x) >> FPN_TC_SHIFT)

/*
 * RFC 4115 algorithm
 *
 *  When a green packet of size B arrives at time t, then
 *     o  if Tc(t)- B > 0, the packet is green, and Tc(t) is decremented
 *        by B; else
 *     o  if Te(t)- B > 0, the packet is yellow, and Te(t) is decremented
 *        by B; else
 *     o  the packet is red.
 *  When a yellow packet of size B arrives at time t, then
 *     o  if Te(t)- B > 0, the packet is yellow, and Te(t) is decremented
 *        by B; else
 *     o  the packet is red.
 *  Incoming red packets are not tested against any of the two token
 *  buckets and remain red.
 *  In the color-blind operation, the meter assumes that all incoming
 *  packets are green.
 */

#define FPN_TC_FILLUP(tokens, last_cycles, filluptime, rate, bs)	\
if (tokens <= 0 && rate) {						\
	uint64_t now = fpn_get_clock_cycles();				\
	int64_t interval = now - last_cycles;				\
	tc_debug2("Using interval=%"PRId64" (%u) "#rate"=%"PRIu64"\n",	\
		  interval,						\
		  (unsigned int)fpn_div64_64((interval*1000),		\
					     fpn_get_clock_hz()),	\
		  rate);						\
	if (interval < 0 || (uint64_t)interval >= filluptime) {		\
		tokens = bs;						\
		tc_debug2("interval=%" PRId64 " fill=%"PRIu64"\n",	\
			  interval, filluptime);			\
	} else {							\
		tokens += interval * rate;				\
		tc_debug2("Adding %"PRIu64" tok=%"PRIu64" bs=%"PRIu64"\n", \
			  (interval * rate), tokens, bs);		\
		if (tokens > 0 && (uint64_t)tokens > bs)		\
			tokens = bs;					\
	}								\
	tc_debug2("Fillup " #tokens " =%"PRId64 "(uns=%"PRId64")\n",	\
		  tokens, FPN_TC_UNSCALE(tokens));			\
	last_cycles = now;						\
 }

static int __fpn_tc_input(struct mbuf *m, fpn_tc_entry_t *fp_tce, int lock)
{
	uint32_t flags;
	int color;
	uint64_t token_len;
	int plen = m_len(m);

	color = FPN_QOS_COLOR_GREEN;
	flags = fp_tce->param.flags;
	token_len = flags & FPN_TC_F_BYTE_POLICING ?  FPN_TC_SCALE(plen) :
						      FPN_TC_SCALE(1);
	tc_debug2("token len=%"PRId64" (uns=%"PRId64") c=%"PRId64" e=%"PRId64"\n",
			token_len, FPN_TC_UNSCALE(fp_tce->tcb.c_tokens),
			fp_tce->tcb.c_tokens, fp_tce->tcb.e_tokens);

	if (lock)
		fpn_spinlock_lock(&fp_tce->tcb.lock);

	if (unlikely(flags & FPN_TC_F_COLOR_AWARE)) {
		color = m_get_egress_color(m);
		if (color == FPN_QOS_COLOR_RED)
			goto done;
	}

	FPN_TC_FILLUP(fp_tce->tcb.c_tokens,
			fp_tce->tcb.c_last_cycles,
			fp_tce->param.c_filluptime,
			fp_tce->param.c_rate,
			fp_tce->param.c_bs);

	if (color == FPN_QOS_COLOR_GREEN && fp_tce->tcb.c_tokens > 0) {
		fp_tce->tcb.c_tokens -= token_len;
		tc_debug2("GREEN c_tokens=%"PRId64"\n", fp_tce->tcb.c_tokens);
		goto done;
	}

	if (unlikely(fp_tce->param.e_bs)) {
		FPN_TC_FILLUP(fp_tce->tcb.e_tokens,
				fp_tce->tcb.e_last_cycles,
				fp_tce->param.e_filluptime,
				fp_tce->param.e_rate,
				fp_tce->param.e_bs);

		if (fp_tce->tcb.e_tokens > 0) {
			fp_tce->tcb.e_tokens -= token_len;
			color = FPN_QOS_COLOR_YELLOW;
			tc_debug2("YELLOW c_tokens=%"PRId64"\n", fp_tce->tcb.e_tokens);
			goto done;
		}
	}
	color = FPN_QOS_COLOR_RED;

done:
	fp_tce->tcb.stats[color].packets++;
	fp_tce->tcb.stats[color].bytes += plen;

	if (lock)
		fpn_spinlock_unlock(&fp_tce->tcb.lock);

	return color;
}

static inline int tc_is_disabled(const fpn_tc_entry_t *fp_tce)
{
	return (fp_tce->param.c_bs == 0);
}

int fpn_tc_input_no_lock(struct mbuf *m, uint32_t id)
{
	fpn_tc_entry_t *fp_tce = fpn_get_tc(id);

	if (tc_is_disabled(fp_tce))
		return -1;

	return __fpn_tc_input(m, fp_tce, 0);
}

int fpn_tc_input(struct mbuf *m, uint32_t id)
{
	fpn_tc_entry_t *fp_tce = fpn_get_tc(id);

	if (tc_is_disabled(fp_tce))
		return -1;

	return __fpn_tc_input(m, fp_tce, 1);
}

int fpn_tc_get_params(uint32_t id, fpn_tc_params_t *params)
{
	fpn_tc_entry_t *fp_tce;

	if (id >= FPN_TC_MAX)
		return -1;

	fp_tce = fpn_get_tc(id);
	params->flags = fp_tce->param.flags;
	if (fp_tce->param.flags & FPN_TC_F_BYTE_POLICING) {
		params->cir = FPN_TC_UNSCALE(fp_tce->param.c_rate * 8 * fpn_get_clock_hz());
		params->eir = FPN_TC_UNSCALE(fp_tce->param.e_rate * 8 * fpn_get_clock_hz());
	} else {
		params->cir = FPN_TC_UNSCALE(fp_tce->param.c_rate * fpn_get_clock_hz());
		params->eir = FPN_TC_UNSCALE(fp_tce->param.e_rate  * fpn_get_clock_hz());
	}
	params->ebs = FPN_TC_UNSCALE(fp_tce->param.e_bs);
	params->cbs = FPN_TC_UNSCALE(fp_tce->param.c_bs);

	return 0;
}

int fpn_tc_set_params_no_lock(uint32_t id, fpn_tc_params_t *params)
{
	fpn_tc_entry_t *fp_tce;

	if (id >= FPN_TC_MAX)
		return -1;

	fp_tce = fpn_get_tc(id);

	if (params->cbs == 0) {
		fp_tce->param.c_bs = 0;
		return 0;
	}
	fp_tce->param.flags = params->flags;
	/* Rate is byte/secs or packet/secs */
	if (fp_tce->param.flags & FPN_TC_F_BYTE_POLICING)
		fp_tce->param.c_rate = fpn_div64_64(FPN_TC_SCALE((params->cir + 7) / 8),
						    fpn_get_clock_hz());
	else
		fp_tce->param.c_rate = fpn_div64_64(FPN_TC_SCALE(params->cir),
						    fpn_get_clock_hz());
	fp_tce->param.c_bs = FPN_TC_SCALE(params->cbs);
	if (fp_tce->param.c_rate > 0)
		fp_tce->param.c_filluptime = fpn_div64_64(fp_tce->param.c_bs,
							  fp_tce->param.c_rate);
	else
		fp_tce->param.c_filluptime = 0xffffffffffffffffLL;

	if (params->ebs == 0)
		fp_tce->param.e_bs = 0;
	else {
		fp_tce->param.e_bs = FPN_TC_SCALE(params->ebs);
		if (fp_tce->param.flags & FPN_TC_F_BYTE_POLICING)
			fp_tce->param.e_rate = fpn_div64_64(FPN_TC_SCALE((params->eir + 7) / 8),
							     fpn_get_clock_hz());
		else
			fp_tce->param.e_rate = fpn_div64_64(FPN_TC_SCALE(params->eir),
							     fpn_get_clock_hz());
	}

	if (fp_tce->param.e_rate > 0)
		fp_tce->param.e_filluptime = fpn_div64_64(fp_tce->param.e_bs,
							  fp_tce->param.e_rate);
	else
		fp_tce->param.e_filluptime = 0xffffffffffffffffLL;

	/* Ignore burst size if rate is 0 */
	fp_tce->tcb.c_tokens = fp_tce->param.c_rate ? fp_tce->param.c_bs : 0;
	fp_tce->tcb.e_tokens = fp_tce->param.e_rate ? fp_tce->param.e_bs : 0;
	fp_tce->tcb.c_last_cycles =
		fp_tce->tcb.e_last_cycles = fpn_get_clock_cycles();

#if FPN_TC_DEBUG > 0
	if (fp_tce->param.flags & FPN_TC_F_BYTE_POLICING) {
		tc_debug("c_rate = %u bps\n",(unsigned int)FPN_TC_UNSCALE(fp_tce->param.c_rate * 8 * fpn_get_clock_hz()));
		tc_debug("e_rate = %u bps\n",(unsigned int)FPN_TC_UNSCALE(fp_tce->param.e_rate * 8 * fpn_get_clock_hz()));
	} else {
		tc_debug("c_rate = %u pps\n",(unsigned int)FPN_TC_UNSCALE(fp_tce->param.c_rate * fpn_get_clock_hz()));
		tc_debug("e_rate = %u pps\n",(unsigned int)FPN_TC_UNSCALE(fp_tce->param.e_rate * fpn_get_clock_hz()));
	}
	tc_debug("c_filluptime = %"PRId64" cycles\n",
			fp_tce->param.c_filluptime);
	tc_debug("e_filluptime = %"PRId64" cycles\n",
			fp_tce->param.e_filluptime);
#endif

	return 0;
}

int fpn_tc_set_params(uint32_t id, fpn_tc_params_t *params)
{
	fpn_tc_entry_t *fp_tce;
	int ret = 0;

	if (id >= FPN_TC_MAX)
		return -1;

	fp_tce = fpn_get_tc(id);
	fpn_spinlock_lock(&fp_tce->tcb.lock);
	ret = fpn_tc_set_params_no_lock(id, params);
	fpn_spinlock_unlock(&fp_tce->tcb.lock);

	return ret;
}

int fpn_tc_get_stats(uint32_t id, fpn_tc_bucket_stats_t *stats)
{
	fpn_tc_entry_t *fp_tce = fpn_get_tc(id);

	if (id < FPN_TC_MAX) {
		stats->green_packets = fp_tce->tcb.stats[FPN_QOS_COLOR_GREEN].packets;
		stats->green_bytes = fp_tce->tcb.stats[FPN_QOS_COLOR_GREEN].bytes;
		stats->yellow_packets = fp_tce->tcb.stats[FPN_QOS_COLOR_YELLOW].packets;
		stats->yellow_bytes = fp_tce->tcb.stats[FPN_QOS_COLOR_YELLOW].bytes;
		stats->red_packets = fp_tce->tcb.stats[FPN_QOS_COLOR_RED].packets;
		stats->red_bytes = fp_tce->tcb.stats[FPN_QOS_COLOR_RED].bytes;
		return 0;
	}
	
	return -1;
}

int fpn_tc_clear_stats(uint32_t id)
{
	fpn_tc_entry_t *fp_tce = fpn_get_tc(id);

	if (id < FPN_TC_MAX) {
		memset(&fp_tce->tcb.stats, 0, sizeof(fp_tce->tcb.stats));
		return 0;
	}
	
	return -1;
}

int fpn_tc_init(void)
{
	uint32_t i;
	fpn_tc_entry_t *fp_tce;

	for (i = 0; i < FPN_TC_MAX; i++) {
		fp_tce = fpn_get_tc(i);
		fpn_spinlock_init(&fp_tce->tcb.lock);
		fp_tce->param.c_bs = 0;
		memset(&fp_tce->tcb.stats, 0, sizeof(fp_tce->tcb.stats));
	}
	return 0;
}
