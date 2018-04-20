/*
 * Copyright(c) 2011 6WIND
 */

#ifndef __FP_PROBE_H__
#define __FP_PROBE_H__

#ifdef CONFIG_MCORE_DEBUG_PROBE
/* stats response from answering machine */
struct fp_probe_percore_stats {
	uint64_t enter_cycles;
	uint64_t min_cycles;
	uint64_t max_cycles;
	uint64_t total_cycles;
	uint64_t count;
} __fpn_cache_aligned;

struct fp_probe_stats {
	struct fp_probe_percore_stats stats[FPN_MAX_CORES];
};

#define FP_PROBE_MAX 16
FPN_DECLARE_SHARED(struct fp_probe_stats[FP_PROBE_MAX], fp_probe);
FPN_DECLARE_SHARED(volatile int, fp_probe_running);

/* init fp_probe module */
int fp_probe_init(void);

/* reset statistics */
void fp_probe_reset(void);

void fp_probe_start(void);
void fp_probe_stop(void);

/* dump_stats */
void fp_probe_dump(int dump_per_core);

#define PROBE

/* enter a probing section */
static inline void fp_probe_enter(int id)
{
#ifdef PROBE
	int core;
	core = fpn_get_core_num();

	fp_probe[id].stats[core].enter_cycles = fpn_get_local_cycles();
#endif
}

/* exit from probing section */
static inline void fp_probe_exit(int id)
{
#ifdef PROBE
	int core;
	uint64_t t, diff;

	if (fp_probe_running == 0)
		return;

	core = fpn_get_core_num();
	t = fpn_get_local_cycles();
	diff = t - fp_probe[id].stats[core].enter_cycles;

	fp_probe[id].stats[core].total_cycles += diff;
	fp_probe[id].stats[core].count++;

	if (unlikely(diff < fp_probe[id].stats[core].min_cycles))
		fp_probe[id].stats[core].min_cycles = diff;
	if (unlikely(diff > fp_probe[id].stats[core].max_cycles))
		fp_probe[id].stats[core].max_cycles = diff;
#endif
}
#else
#define fp_probe_enter(x) (void)x
#define fp_probe_exit(x) (void)x
#endif

#endif /* __FP_PROBE_H__ */
