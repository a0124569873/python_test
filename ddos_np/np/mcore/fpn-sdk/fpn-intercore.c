/*
 * Copyright(c) 2013 6WIND, All rights reserved.
 */

#include "fpn.h"
#include "fpn-intercore.h"
#include "shmem/fpn-shmem.h"

FPN_DEFINE_SHARED(fpn_intercore_shared_mem_t *, fpn_intercore_shared);

int fpn_intercore_init(void)
{
	int i;
	char name[32];

	fpn_shmem_add("fpn-intercore-shared", sizeof(*fpn_intercore_shared));
	fpn_intercore_shared = fpn_shmem_mmap("fpn-intercore-shared",
	                                      NULL,
	                                      sizeof(*fpn_intercore_shared));

	if (!fpn_intercore_shared) {
		fpn_printf("cannot map fpn_intercore_shared size=%"PRIu64"\n",
		           (uint64_t) sizeof(*fpn_intercore_shared));
		return -1;
	}

	memset(fpn_intercore_shared, 0, sizeof(*fpn_intercore_shared));

	for (i = 0; i < FPN_MAX_CORES; i++) {
		snprintf(name, sizeof(name), "fpn_intercore_%d", i);
		fpn_ring_init(&fpn_intercore[i].r, name, FPN_INTERCORE_RING_SIZE, FPN_RING_F_SC_DEQ);
	}

	return 0;
}

int fpn_intercore_drain(unsigned int lcore_id)
{
	struct mbuf *pkts_burst[MAX_PKT_BURST];
	struct mbuf *m;
	unsigned int i, count;

	count = fpn_ring_count(&fpn_intercore[lcore_id].r);
	if (count == 0)
		return count;

	if (count > MAX_PKT_BURST)
		count = MAX_PKT_BURST;

	/*
	 * The ring is single consumer, so we are sure to have at least
	 * "count" mbufs, no need to check ret val.
	 */
	fpn_ring_sc_dequeue_bulk(&fpn_intercore[lcore_id].r,
	                         (void **)&pkts_burst, count);

	for (i = 0; i < count; i++) {
		m = pkts_burst[i];
		FPN_PREFETCH(m);
	}

	for (i = 0; i < count; i++) {
		m = pkts_burst[i];
		m_call_process_fct(m);
	}

	return count;
}

