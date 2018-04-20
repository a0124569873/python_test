/* Copyright 2013 6WIND S.A. */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define unlikely(a) (a)

#include "fpn.h"
#include "shmem/fpn-shmem.h"
#include "fpn-intercore.h"
#include "fpn-cpu-usage.h"

#define DEFAULT_DELAY 200000 /* time delay is us */


/* from fpn-ring.c: dump the status of the ring on the console */
void
fpn_ring_dump(const struct fpn_ring *r)
{
#ifdef FPN_RING_DEBUG
	struct fpn_ring_debug_stats sum;
	unsigned core_id;
#endif

	printf("ring <%s>\n", r->name);
	printf("  size=%"PRIu32"\n", r->prod.size);
	printf("  ct=%"PRIu32"\n", r->cons.tail);
	printf("  ch=%"PRIu32"\n", r->cons.head);
	printf("  pt=%"PRIu32"\n", r->prod.tail);
	printf("  ph=%"PRIu32"\n", r->prod.head);
	printf("  used=%"PRIu32"\n", fpn_ring_count(r));
	printf("  avail=%"PRIu32"\n", fpn_ring_free_count(r));
	if (r->prod.watermark == r->prod.size)
		printf("  watermark=0\n");
	else
		printf("  watermark=%"PRIu32"\n", r->prod.watermark);
	printf("  bulk_default=%"PRIu32"\n", r->prod.bulk_default);

	/* sum and dump statistics */
#ifdef FPN_RING_DEBUG
	memset(&sum, 0, sizeof(sum));
	for (core_id = 0; core_id < FPN_MAX_CORES; core_id++) {
		sum.enq_success_bulk += r->stats[core_id].enq_success_bulk;
		sum.enq_success_objs += r->stats[core_id].enq_success_objs;
		sum.enq_quota_bulk += r->stats[core_id].enq_quota_bulk;
		sum.enq_quota_objs += r->stats[core_id].enq_quota_objs;
		sum.enq_fail_bulk += r->stats[core_id].enq_fail_bulk;
		sum.enq_fail_objs += r->stats[core_id].enq_fail_objs;
		sum.deq_success_bulk += r->stats[core_id].deq_success_bulk;
		sum.deq_success_objs += r->stats[core_id].deq_success_objs;
		sum.deq_fail_bulk += r->stats[core_id].deq_fail_bulk;
		sum.deq_fail_objs += r->stats[core_id].deq_fail_objs;
	}
	printf("  size=%"PRIu32"\n", r->prod.size);
	printf("  enq_success_bulk=%"PRIu64"\n", sum.enq_success_bulk);
	printf("  enq_success_objs=%"PRIu64"\n", sum.enq_success_objs);
	printf("  enq_quota_bulk=%"PRIu64"\n", sum.enq_quota_bulk);
	printf("  enq_quota_objs=%"PRIu64"\n", sum.enq_quota_objs);
	printf("  enq_fail_bulk=%"PRIu64"\n", sum.enq_fail_bulk);
	printf("  enq_fail_objs=%"PRIu64"\n", sum.enq_fail_objs);
	printf("  deq_success_bulk=%"PRIu64"\n", sum.deq_success_bulk);
	printf("  deq_success_objs=%"PRIu64"\n", sum.deq_success_objs);
	printf("  deq_fail_bulk=%"PRIu64"\n", sum.deq_fail_bulk);
	printf("  deq_fail_objs=%"PRIu64"\n", sum.deq_fail_objs);
#else
	printf("  no statistics available\n");
#endif
}

static int dump_intercore(int all)
{
	fpn_intercore_shared_mem_t *shmem;
	uint32_t pid;

	shmem = fpn_shmem_mmap("fpn-intercore-shared", NULL, sizeof(*shmem));
	if (shmem == NULL) {
		fprintf(stderr, "can't map fpn-intercore-shared\n");
		return -1;
	}

	printf("Intercore information\n");
	for (pid = 0; pid < FPN_MAX_CORES; pid++) {
		int in_mask = fpn_cpumask_ismember(&shmem->mask, pid);
		if (!in_mask && !all) continue;
		printf("Core %u%s\n", pid, in_mask == 0 ?  " (NOT IN MASK)" : "");
		fpn_ring_dump(&shmem->rings[pid].r);
	}
	return 0;
}

static int dump_cpu_usage(uint32_t delay)
{
	cpu_usage_shared_mem_t *shmem;
	uint64_t sum_cycles = 0;
	uint64_t sum_fwd = 0;
	int i;

	shmem = fpn_shmem_mmap("cpu-usage-shared", NULL, sizeof(*shmem));
	if (shmem == NULL) {
		fprintf(stderr, "can't map cpu-usage-shared\n");
		return -1;
	}

	/* Make sure to re-initialize the state */
	shmem->do_cpu_usage = 0;
	usleep(delay);
	for (i=0; i<FPN_MAX_CORES; i++)
		shmem->busy_cycles[i].end = 0;

	/* Enable dump-cpu-usage all cores main loop */
	shmem->do_cpu_usage = 1;

	usleep(delay);

	/* Disable dump-cpu-usage all cores main loop */
	shmem->do_cpu_usage = 0;

	/* Make sure all cores have finished */
	usleep(delay);

	printf("Fast path CPU usage:\n");

	printf("cpu: %%busy     cycles   cycles/pkt  cycles/ic pkt\n");

	sum_fwd = 0;
	/* display cpu usage percentage cpu usage */
	for (i=0; i<FPN_MAX_CORES; i++) {
		uint64_t busy, cycles;
		int64_t delta;

		/* Skip vcpu that did not participate */
		if (shmem->busy_cycles[i].end == 0)
			continue;

		sum_fwd += shmem->busy_cycles[i].pkts;

		/* CPU number */
		printf ("%3d:", i);

		delta = shmem->busy_cycles[i].end - shmem->busy_cycles[i].begin;
		if (delta <= 0) {
			printf(" n/a - delta is not positive\n");
			continue;
		}

		cycles = shmem->busy_cycles[i].val;
		/* % busy time */
		busy = (cycles * 100) / delta;
		if ((busy == 0) && cycles)
			printf("   <1%%"); /* display at least 1% if the CPU was used */
		else
			printf(" %4"PRIu64"%%", busy);

		/* cycles */
		printf(" %10"PRIu64, cycles);

		/* cycles / packet */
		printf("   %10"PRIu64,
		       (shmem->busy_cycles[i].pkts == 0) ?
			  0 : cycles / shmem->busy_cycles[i].pkts);

		/* ic cycles / packet */
		printf("     %10"PRIu64"\n",
		       (shmem->busy_cycles[i].intercore_pkts == 0) ?
			  0 : cycles / shmem->busy_cycles[i].intercore_pkts);

		sum_cycles += cycles;
	}

	printf("average cycles/packets received from NIC: ");
	if (sum_fwd)
		printf("%"PRIu64" ", sum_cycles / sum_fwd);
	else
		printf("--- ");
	printf("(%"PRIu64"/%"PRIu64")\n", sum_cycles, sum_fwd);

	printf("ic pkt: packets that went intercore\n");

	return 0;
}

static void usage(char *name)
{
	fprintf(stderr, "%s: [--all]\n", name);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	int all = 0, cpu = 0;
	if (argc > 1) {
		if (!strcmp(argv[1], "--all"))
			all = 1;
		else if (!strcmp(argv[1], "--cpu"))
			cpu = 1;
		else
			usage(argv[0]);
	}

	if (cpu)
		dump_cpu_usage(DEFAULT_DELAY);
	else
		dump_intercore(all);

	return 0;
}
