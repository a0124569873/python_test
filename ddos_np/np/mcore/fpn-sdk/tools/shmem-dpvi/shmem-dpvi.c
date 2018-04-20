/*
 * Copyright(c) 2014 6WIND
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "fpn.h"
#include "dpvi/fpn-dpvi-ring.h"
#include "shmem/fpn-shmem.h"

static struct fpn_dpvi_shmem *dpvi_shm = NULL;

static int
dpvi_init(void)
{
	dpvi_shm = fpn_shmem_mmap("dpvi-shared", NULL, sizeof(*dpvi_shm));
	if (dpvi_shm == NULL) {
		printf("Could not map dpvi-shared\n");
		return -1;
	}

	return 0;
}


int main(int argc, char *argv[])
{
	int reset = 0;
	int nonzero = 0;
	int ringid = -1; /* all */
	int i = 1;
	int j;
	fpn_cpumask_t * dpvi_mask, * fp_mask;
	struct fpn_dring_list *rl;
	struct fpn_dring *r;

	if (dpvi_init())
		return -1;

	if (argc == 1)
		goto skip;

	if (!strncmp(argv[1], "reset", 5)) {
		reset = 1;
		i++;
	} else if (!strncmp(argv[1], "non-zero", 8)) {
		nonzero = 1;
		i++;
	}

	if (argc > i)
		ringid = atoi(argv[i]);

skip:

	dpvi_mask = &dpvi_shm->dpvi_mask;
	fp_mask = &dpvi_shm->fp_mask;

	for (i = 0 ; i < FPN_DRING_CPU_MAX; i++) {
		if (!fpn_cpumask_ismember(dpvi_mask, i))
			continue;
		if (ringid != -1 && ringid != i)
			continue;
		rl = &dpvi_shm->rx_ring[i];
		for (j = 0; j < FPN_DRING_CPU_MAX; j++) {
			if (!fpn_cpumask_ismember(fp_mask, j))
				continue;
			r = &rl->cpu[j];
			if (!reset && (!nonzero ||
				(r->prod.enqueue + r->cons.dequeue + r->prod.enqueue_err +
				 r->cons.dequeue_err + r->cons.dequeue_copyerr +
				 r->cons.dequeue_no_eop)))
				printf("rx-ring[%02u,%02u] enq=%08"PRIu64" deq=%08"PRIu64" enq_err=%08"PRIu64" deq_err=%08"PRIu64" deq_copyerr=%08"PRIu64" deq_retries=%08"PRIu64"\n",
						i, j,
						r->prod.enqueue,
						r->cons.dequeue,
						r->prod.enqueue_err,
						r->cons.dequeue_err,
						r->cons.dequeue_copyerr,
						r->cons.dequeue_no_eop);
			else {
				r->cons.dequeue = r->cons.dequeue_err = r->prod.enqueue = r->prod.enqueue_err = 0;
				r->cons.dequeue_copyerr = r->cons.dequeue_no_eop = 0;
			}
		}
	}

	for (i = 0 ; i < FPN_DRING_CPU_MAX; i++) {
		if (ringid != -1 && ringid != i)
			continue;
		if (!fpn_cpumask_ismember(fp_mask, i))
			continue;
		rl = &dpvi_shm->tx_ring[i];
		for (j = 0; j < FPN_DRING_CPU_MAX; j++) {
			r = &rl->cpu[j];
			if (!reset && (!nonzero ||
				(r->prod.enqueue + r->cons.dequeue + r->prod.enqueue_err +
				 r->cons.dequeue_err + r->cons.dequeue_copyerr +
				 r->cons.dequeue_no_eop)))
				printf("tx-ring[%02u,%02u] enq=%08"PRIu64" deq=%08"PRIu64" enq_err=%08"PRIu64" deq_err=%08"PRIu64" deq_copyerr=%08"PRIu64" deq_retries=%08"PRIu64"\n",
						i, j,
						r->prod.enqueue,
						r->cons.dequeue,
						r->prod.enqueue_err,
						r->cons.dequeue_err,
						r->cons.dequeue_copyerr,
						r->cons.dequeue_no_eop);
			else {
				r->cons.dequeue = r->cons.dequeue_err = r->prod.enqueue = r->prod.enqueue_err = 0;
				r->cons.dequeue_copyerr = r->cons.dequeue_no_eop = 0;
			}
		}
	}

	return 0;
}
