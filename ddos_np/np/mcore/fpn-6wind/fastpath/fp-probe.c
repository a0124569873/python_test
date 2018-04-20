/*
 * Copyright(c) 2011 6WIND
 */

#include "fpn.h"
#include "fp-includes.h"

#include <fp-probe.h>

FPN_DEFINE_SHARED(struct fp_probe_stats[FP_PROBE_MAX], fp_probe);
FPN_DEFINE_SHARED(volatile int, fp_probe_running) = 1;

static const char *names[FP_PROBE_MAX] = {
	"probe0",
	"probe1",
	"probe2",
	"probe3",
	"probe4",
	"probe5",
	"probe6",
	"probe7",
	"probe8",
	"probe9",
	"probe10",
	"probe11",
	"probe12",
	"probe13",
	"probe14",
	"probe15",
};

void fp_probe_reset(void)
{
	int id, core;

	for (id = 0; id < FP_PROBE_MAX; id++) {
		for (core = 0; core < FPN_MAX_CORES; core++) {
			/* set min to an infinite value to avoid a test in
			 * fp_probe_exit() */
			fp_probe[id].stats[core].min_cycles =
				0xFFFFFFFFFFFFFFFFULL;
			fp_probe[id].stats[core].max_cycles = 0;
			fp_probe[id].stats[core].count = 0;
			fp_probe[id].stats[core].total_cycles = 0;
			/* don't update enter_cycles */
		}
	}
}

static void fp_probe_dump_one(int id, int dump_per_core)
{
	struct fp_probe_percore_stats stats;
	uint64_t avg_cycles;
	int core;

	memset(&stats, 0, sizeof(stats));

	for (core = 0; core < FPN_MAX_CORES; core++) {
		avg_cycles = 0;

		/* no stats on this core, skip */
		if (fp_probe[id].stats[core].count == 0) {
			if (dump_per_core)
				fpn_printf("[%2.2d]: id=%d %20s no data\n",
					   core, id, names[id]);
			continue;
		}

		stats.count += fp_probe[id].stats[core].count;
		stats.total_cycles += fp_probe[id].stats[core].total_cycles;

		if (stats.min_cycles == 0 ||
		    stats.min_cycles > fp_probe[id].stats[core].min_cycles)
			stats.min_cycles = fp_probe[id].stats[core].min_cycles;
		if (stats.max_cycles == 0 ||
		    stats.max_cycles < fp_probe[id].stats[core].max_cycles)
			stats.max_cycles = fp_probe[id].stats[core].max_cycles;

		if (dump_per_core) {
			avg_cycles =
				fpn_div64_32(fp_probe[id].stats[core].total_cycles,
					     fp_probe[id].stats[core].count);

			fpn_printf("[%2.2d]: id=%d %20s min=%"PRIu64
				   " max=%"PRIu64" avg=%"PRIu64
				   " cnt=%"PRIu64" total=%"PRIu64"\n",
				   core, id, names[id],
				   fp_probe[id].stats[core].min_cycles,
				   fp_probe[id].stats[core].max_cycles,
				   avg_cycles,
				   fp_probe[id].stats[core].count,
				   fp_probe[id].stats[core].total_cycles);
		}
	}
	if (stats.count != 0) {
		avg_cycles = fpn_div64_32(stats.total_cycles,
					  stats.count);
	}
	fpn_printf("SUM: id=%2.2d %20s min=%"PRIu64" max=%"PRIu64
		   " avg=%"PRIu64" cnt=%"PRIu64" total=%"PRIu64"\n",
		   id, names[id], stats.min_cycles,
		   stats.max_cycles, avg_cycles,
		   stats.count,
		   stats.total_cycles);
}

/* dump_stats */
void fp_probe_dump(int dump_per_core)
{
	int id;

	for (id = 0; id < FP_PROBE_MAX; id++)
		fp_probe_dump_one(id, dump_per_core);
}

void fp_probe_start(void)
{
	fp_probe_running = 1;
}

void fp_probe_stop(void)
{
	fp_probe_running = 0;
}

/* init fp_probe module */
int fp_probe_init(void)
{
	fp_probe_reset();
	return 0;
}
