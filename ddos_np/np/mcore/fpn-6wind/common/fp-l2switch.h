/*
 * Copyright(c) 2012 6WIND
 */
#ifndef __FP_L2SWITCH_H__
#define __FP_L2SWITCH_H__

#include "shmem/fpn-shmem.h"

enum {
	FP_L2SWITCH_OFF,
	FP_L2SWITCH_ON,
};
enum {
	FP_L2SWITCH_PORT_DROP = FP_MAX_PORT,
	FP_L2SWITCH_PORT_EXCEPTION,
	__FP_L2SWITCH_PORT_VAL_MAX,
};

#define FP_L2SWITCH_PORT_VAL_MAX                  (__FP_L2SWITCH_PORT_VAL_MAX - 1)

#define FP_L2SWITCH_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_L2SWITCH_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FP_L2SWITCH_STATS_NUM                     FPN_MAX_CORES

typedef struct l2switch_stats {
	uint64_t drop;
	uint64_t forward;
	uint64_t exception;
} __fpn_cache_aligned l2switch_stats_t;

typedef struct l2switch_shared_mem {
	uint32_t next_portid[FP_MAX_PORT];
	uint32_t mode;
	l2switch_stats_t stats[FP_MAX_PORT][FP_L2SWITCH_STATS_NUM];
} l2switch_shared_mem_t;

#define L2SWITCH_SHM_NAME "l2switch-shared"

#ifdef __FastPath__
FPN_DECLARE_SHARED(l2switch_shared_mem_t *, l2switch_shared);

void fp_l2switch_input(struct mbuf *m);

void* l2switch_shared_alloc(void);
void fp_l2switch_init(void);
#endif

static inline l2switch_shared_mem_t *get_l2switch_shared_mem(void)
{
	return fpn_shmem_mmap(L2SWITCH_SHM_NAME, NULL,
			      sizeof(l2switch_shared_mem_t));
}

#endif
