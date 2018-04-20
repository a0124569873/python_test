/*
 * Copyright(c) 2012 6WIND
 */
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "fpn.h"
#include "shmem/fpn-shmem.h"
#include "fpn-cpu-usage.h"

#define DEFAULT_DELAY 200000 /* time delay is us */

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

	printf("cpu: %%busy     cycles\n");

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
		printf(" %10"PRIu64"\n", cycles);

		sum_cycles += cycles;
	}

	printf("average cycles/packets received from NIC: ");
	if (sum_fwd)
		printf("%"PRIu64" ", sum_cycles / sum_fwd);
	else
		printf("--- ");
	printf("(%"PRIu64"/%"PRIu64")\n", sum_cycles, sum_fwd);

	return 0;
}

int main(int argc, char **argv)
{
	dump_cpu_usage(DEFAULT_DELAY);
	return 0;
}
