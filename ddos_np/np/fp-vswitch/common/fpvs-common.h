/*
 * Copyright 2013 6WIND S.A.
 */

#ifndef _FPVS_COMMON_H
#define _FPVS_COMMON_H

#include "fpvs-netlink.h"

#include "fp-stats-defs.h"
#include "fp-hlist.h"
#include "fpvs-flowops.h"
#include "fp-vswitch.h"

#define FP_LOGTYPE_VSWITCH             UINT64_C(0x400000000000)

#define FP_DPIF_MAGIC32 0x12345678

enum { MAX_PORTS = FPVS_MAX_OVS_PORTS };	/* Maximum number of ports. */
enum {
	MAX_FLOWS = 65536,	/* Maximum number of flows in flow table. */
	MAX_MASKS = 65536/2,
};

#define FPVS_MAX_ACTION_SIZE 2048

#ifdef FP_VSWITCH_STATS_PER_CORE
#define FPVS_FLOW_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FPVS_FLOW_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FPVS_FLOW_STATS_NUM                     FPN_MAX_CORES
#else
#define FPVS_FLOW_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FPVS_FLOW_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FPVS_FLOW_STATS_NUM                     1
#endif

/* Defines an invalid entry to -1 because 0 SHOULD be a valid index. */
#define FPVS_INVALID_ENTRY   ((uint32_t)-1)

#define FP_VSWITCH_FLOW_HASH_ORDER	16
#define FP_VSWITCH_FLOW_HASH_SIZE	(1<<FP_VSWITCH_FLOW_HASH_ORDER)
#define FP_VSWITCH_FLOW_HASH_MASK	(FP_VSWITCH_FLOW_HASH_SIZE-1)

#define FPVS_NB_BLOCK_ALIGN(sz)	\
	(((sz) + (FPVS_FLOW_ALIGNMENT - 1)) / FPVS_FLOW_ALIGNMENT)
#define FPVS_EXPECTED_ALIGN_SZ(sz) \
	(FPVS_NB_BLOCK_ALIGN(sz) * FPVS_FLOW_ALIGNMENT)
#define FPVS_PADDING_COUNT(sz)	\
	FPVS_EXPECTED_ALIGN_SZ(sz) - (sz)

#define FPVS_FLOW_UNSPEC	0
#define FPVS_FLOW_ACTIVE	1

typedef struct fpvs_flow_stats {
	uint64_t pkts;
	uint64_t bytes;
} __fpn_cache_aligned fpvs_flow_stats_t;

struct fp_key_range {
	uint32_t start;
	uint32_t end;
};

struct fpvs_mask {
	struct fp_flow_key	key __attribute__ ((aligned (FPVS_FLOW_ALIGNMENT)));
	struct fp_key_range	range;
	uint32_t		ref_count;
	int			state;
};

typedef struct fpvs_mask_entry {
	struct fpvs_mask	mask;
	uint32_t		next;
} fpvs_mask_entry_t;

struct fpvs_flow {
	struct fp_flow_key	key  __attribute__ ((aligned (FPVS_FLOW_ALIGNMENT)));
	struct nlattr	actions[FPVS_MAX_ACTION_SIZE/NLA_HDRLEN];
	int		actions_len;
	uint32_t	index;
	uint32_t	mask_index;
	uint32_t	hash:30;
	uint32_t	state:2;
	volatile uint32_t age;
	fpvs_flow_stats_t stats[FPVS_FLOW_STATS_NUM];
	/* for dpif */
	uint64_t	used;
	uint8_t		hit;
};

typedef struct fpvs_flow_entry {
	struct fpvs_flow	flow;
	fp_hlist_node_t		node;
	uint32_t		next;
} fpvs_flow_entry_t;

typedef struct fpvs_flow_list {
	fp_hlist_head_t		flow_hash[FP_VSWITCH_FLOW_HASH_SIZE];
	fpvs_flow_entry_t	flow_table[MAX_FLOWS] __attribute__((aligned(FPVS_FLOW_ALIGNMENT)));
	fpvs_mask_entry_t	mask_table[MAX_MASKS] __attribute__((aligned(FPVS_FLOW_ALIGNMENT)));
	uint32_t		flow_index;
	uint32_t		mask_index;
	uint32_t                dpif_magic;
	uint8_t                 flow_max_age;
} fpvs_flow_list_t;

static inline void
fpvs_flow_mask(struct fp_flow_key *dst, const struct fp_flow_key *key,
	       const struct fp_flow_key *mask,
	       unsigned int start, unsigned int end)
{
	const uint64_t *m = (uint64_t *)((char*)mask + start);
	const uint64_t *s = (uint64_t *)((char*)key + start);
	uint64_t *d = (uint64_t *)((char*)dst + start);
	unsigned int i;

	for (i = start; i < end; i += sizeof(uint64_t))
		*d++ = *s++ & *m++;
}

/* Lookup a flow by its key and its mask. */
static inline struct fpvs_flow *
fpvs_lookup_masked_flow(fpvs_flow_list_t *shared_table, uint32_t mask_idx,
			const struct fp_flow_key *mask,
			const struct fp_flow_key *key,
			const struct fp_key_range *range)
{
	struct fpvs_flow *flow;
	uint32_t idx;
	size_t hash;

	hash = fpvs_flow_hash_masked(key, mask, 0,
				     range->start, range->end);
	hash &= FP_VSWITCH_FLOW_HASH_MASK;

	fp_hlist_for_each(idx, &shared_table->flow_hash[hash],
			  shared_table->flow_table, node) {
		flow = &shared_table->flow_table[idx].flow;
		if (flow->state == FPVS_FLOW_ACTIVE &&
		    flow->mask_index == mask_idx &&
		    fpvs_flow_equal_masked(&flow->key, key, mask,
					   range->start,
					   range->end)) {
			return flow;
		}
	}

	return NULL;
}

/* Lookup a flow: for each mask, apply it and search a matching flow */
static inline struct fpvs_flow *
fpvs_lookup_flow(fpvs_flow_list_t* shared_table, const struct fp_flow_key *key)
{
	struct fpvs_mask *mask;
	struct fpvs_flow *flow;
	uint32_t idx;

	for (idx = 0; idx < MAX_MASKS; idx++) {
		mask = &shared_table->mask_table[idx].mask;
		if (mask->state == FPVS_FLOW_UNSPEC)
			continue;

		flow = fpvs_lookup_masked_flow(shared_table, idx,
					       &mask->key, key,
					       &mask->range);

		if (flow)
			return flow;
	}

	return NULL;
}

/* not used by datapath */
static inline uint32_t
fpvs_mask_lookup(fpvs_flow_list_t* shared_table, const struct fp_flow_key *mask_key)
{
	uint32_t idx;
	struct fpvs_mask *mask;

	for (idx = 0; idx < MAX_MASKS; idx++) {
		mask = &shared_table->mask_table[idx].mask;
		if (mask->state == FPVS_FLOW_ACTIVE &&
		    fpvs_flow_equal(&mask->key, mask_key, 0, sizeof(*mask_key)))
			return idx;
	}

	return FPVS_INVALID_ENTRY;
}

static inline void
fpvs_mask_to_range(const struct fp_flow_key *mask,
		   struct fp_key_range *range)
{
	const uint64_t *data = (uint64_t *)mask;
	range->start = 0;

	while (*data == 0 && range->start < sizeof(struct fp_flow_key)) {
		range->start += sizeof(uint64_t);
		data++;
	}

	data = (uint64_t *)((char *)mask + sizeof(struct fp_flow_key) - sizeof(uint64_t));
	range->end = sizeof(struct fp_flow_key);
	while ((*data == 0) && (range->end - sizeof(uint64_t)) > 0) {
		range->end -= sizeof(uint64_t);
		data--;
	}
}

#ifdef __FastPath__
FPN_DECLARE_SHARED(fpvs_flow_list_t*,  shared_table);
FPN_DECLARE_SHARED(fpvs_shared_mem_t *, fpvs_shared);

/* Declared for future extension. The index management will depend on future design choices. */
static inline struct fpvs_flow *
fpvs_lookup_indexed_flow(int index, const struct fp_flow_key *key)
{
	/* We do not support multiple tables right now. */
	FPN_ASSERT(index == 0);
	return fpvs_lookup_flow(shared_table, key);
}
#else
extern fpvs_flow_list_t *shared_table;
extern fpvs_shared_mem_t *fpvs_shared;
#endif

#ifndef __FastPath__
/* for now, both key must be the same, but we could optimize more */
static inline void cp_to_fp_flow_key(struct cp_flow_key *cpkey, struct fp_flow_key *fpkey)
{
	memcpy(fpkey, cpkey, sizeof(*fpkey));
}
#endif
void fpvs_init_shmem(int graceful);
int fpvs_map_shm(void);
int fpvs_insert_flow(fpvs_flow_list_t* shared_table, const struct fp_flow_key *key,
		     const struct fp_flow_key* mask_key, const struct nlattr* actions,
		     int actions_len, const struct fp_key_range* range);
void fpvs_remove_flow(fpvs_flow_list_t* shared_table, struct fpvs_flow *flow);

#endif /* _FPVS_COMMON_H */
