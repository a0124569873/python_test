/*
 * Copyright(c) 2013 6WIND, All rights reserved.
 */
#ifndef __FPN_INTERCORE_H__
#define __FPN_INTERCORE_H__

#include "fpn-ring.h"
#include "fpn-core.h"

#define FPN_INTERCORE_RING_SIZE 512
struct fpn_intercore_ring {
	struct fpn_ring r __fpn_cache_aligned;
	void *objs[FPN_INTERCORE_RING_SIZE];
} __fpn_cache_aligned;

typedef struct fpn_intercore_shared_mem {
	fpn_cpumask_t mask __fpn_cache_aligned;
	struct fpn_intercore_ring rings[FPN_MAX_CORES];
} fpn_intercore_shared_mem_t;

#ifdef __FastPath__

FPN_DECLARE_SHARED(fpn_intercore_shared_mem_t *, fpn_intercore_shared);
#define fpn_intercore      fpn_intercore_shared->rings
#define fpn_intercore_mask fpn_intercore_shared->mask

int fpn_intercore_init(void);
int fpn_intercore_drain(unsigned int lcore_id);

static inline int fpn_intercore_enqueue(struct mbuf *m, unsigned int lcore_id)
{
	return fpn_ring_mp_enqueue(&fpn_intercore[lcore_id].r, m);
}

#endif
#endif
