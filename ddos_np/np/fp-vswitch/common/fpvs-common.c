/*
 * Copyright 2013 6WIND S.A.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/time.h>

#include "fpn.h"
#include "fpn-shmem.h"
#include "fp-vswitch.h"
#include "fpvs-common.h"
#include "linux/openvswitch.h"

#ifdef __FastPath__
FPN_DEFINE_SHARED(fpvs_flow_list_t *, shared_table);
FPN_DEFINE_SHARED(fpvs_shared_mem_t *, fpvs_shared);
#else
fpvs_flow_list_t *shared_table;
fpvs_shared_mem_t *fpvs_shared;
#endif

void fpvs_init_shmem(int graceful)
{
	/* Reset if magic number is not here or if force reset mode */
	if ((fpvs_shared->magic != FP_FPVS_MAGIC32) || !graceful) {
		int i;

		/* Clear memory, except mod_uid */
		memset(fpvs_shared, 0, (size_t) &((fpvs_shared_mem_t *)NULL)->mod_uid);

		/* Setup ports */
		for (i = 0; i < FPVS_MAX_OVS_PORTS; i++) {
			fp_vswitch_port_t *port = fpvs_get_port(i);
			port->ifp_index = FPVS_INVALID_IF_IDX;
			port->type = OVS_VPORT_TYPE_UNSPEC;
		}

		/* Setup flows table */
		/* ZERO is reserved so we lose a record. */
		for (i = 1; i < MAX_FLOWS - 1; i++) {
			memset(&shared_table->flow_table[i], 0, sizeof(fpvs_flow_entry_t));
			shared_table->flow_table[i].flow.state = FPVS_FLOW_UNSPEC;
			shared_table->flow_table[i].next = i+1;
		}
		memset(&shared_table->flow_table[MAX_FLOWS - 1], 0, sizeof(fpvs_flow_entry_t));
		shared_table->flow_table[MAX_FLOWS - 1].flow.state = FPVS_FLOW_UNSPEC;
		shared_table->flow_table[MAX_FLOWS - 1].next = FPVS_INVALID_ENTRY;

		for (i = 1; i < MAX_MASKS - 1; i++) {
			memset(&shared_table->mask_table[i], 0, sizeof(fpvs_mask_entry_t));
			shared_table->mask_table[i].mask.state = FPVS_FLOW_UNSPEC;
			shared_table->mask_table[i].mask.ref_count = 0;
			shared_table->mask_table[i].next = i+1;
		}
		memset(&shared_table->mask_table[MAX_MASKS - 1], 0, sizeof(fpvs_mask_entry_t));
		shared_table->mask_table[MAX_MASKS - 1].mask.state = FPVS_FLOW_UNSPEC;
		shared_table->mask_table[MAX_MASKS - 1].mask.ref_count = 0;
		shared_table->mask_table[MAX_MASKS - 1].next = FPVS_INVALID_ENTRY;

		shared_table->dpif_magic = 0;
		shared_table->flow_max_age = 2;

		/* Start at index 1 because 0 has been reserved for obscure reasons. */
		shared_table->flow_index = 1;
		shared_table->mask_index = 1;

		/* Setup magic */
		fpvs_shared->magic = FP_FPVS_MAGIC32;
	}
}

int fpvs_map_shm(void)
{
	const size_t align = FPVS_FLOW_ALIGNMENT - 1;
	const size_t sz = sizeof (fpvs_flow_list_t);
	void* ptr = fpn_shmem_mmap("fpvs_flow_table", NULL, sz + align);
	if (ptr == NULL)
		return -1;

	unsigned long addr = (unsigned long)ptr;
	addr = addr & (align) ? (addr + align) & ~align : addr;
	shared_table = (fpvs_flow_list_t*)addr;

	fpvs_shared = fpn_shmem_mmap("fpvs-shared", NULL, sizeof(fpvs_shared_mem_t));
	if (fpvs_shared == NULL)
		return -1;

	return 0;
}

/* Find next free flow entry in O(1). */
static uint32_t alloc_flow(fpvs_flow_list_t* shared_table)
{
	uint32_t index;
	if (shared_table->flow_index == FPVS_INVALID_ENTRY) {
		return FPVS_INVALID_ENTRY;
	}
	index = shared_table->flow_index;
	shared_table->flow_index = shared_table->flow_table[index].next;
	return index;
}

/* Find next free mask entry in O(1). */
static uint32_t alloc_mask(fpvs_flow_list_t* shared_table)
{
	uint32_t index;
	if (shared_table->mask_index == FPVS_INVALID_ENTRY) {
		return FPVS_INVALID_ENTRY;
	}
	index = shared_table->mask_index;
	shared_table->mask_index = shared_table->mask_table[index].next;
	return index;
}

/* Put back a flow entry in the free flow entry linked list. */
static void free_flow(fpvs_flow_list_t* shared_table, uint32_t index)
{
	fpvs_flow_entry_t* obj = &shared_table->flow_table[index];

	obj->next = shared_table->flow_index;
	shared_table->flow_index = index;
}

/*
 * Remove a mask from the table from its index. It must not be referenced by
 * any flow.
 */
static void fpvs_remove_mask(fpvs_flow_list_t* shared_table, uint32_t idx)
{
	struct fpvs_mask_entry *obj = &shared_table->mask_table[idx];

	obj->mask.state = FPVS_FLOW_UNSPEC;
	obj->mask.ref_count = 0;
	obj->next = shared_table->mask_index;
	shared_table->mask_index = idx;
}

/*
 * Remove a flow from the table. The flow must have been obtained through
 * a lookup in the table.
 */
void fpvs_remove_flow(fpvs_flow_list_t* shared_table, struct fpvs_flow *flow)
{
	flow->state = FPVS_FLOW_UNSPEC;
	fp_hlist_remove(&shared_table->flow_hash[flow->hash],
			shared_table->flow_table, flow->index, node);
	if (shared_table->mask_table[flow->mask_index].mask.ref_count-- == 1)
		fpvs_remove_mask(shared_table, flow->mask_index);
	free_flow(shared_table, flow->index);
}

/* Insert a new flow in the table. */
int fpvs_insert_flow(fpvs_flow_list_t* shared_table, const struct fp_flow_key *key,
		     const struct fp_flow_key* mask_key, const struct nlattr* actions,
		     int actions_len, const struct fp_key_range* range)
{
	size_t hash;
	uint32_t idx, mask_idx;
	struct fpvs_flow* flow;
	struct fpvs_mask* mask;

	if (actions_len > FPVS_MAX_ACTION_SIZE) {
		return -1;
	}

	mask_idx = fpvs_mask_lookup(shared_table, mask_key);

	if (mask_idx == FPVS_INVALID_ENTRY) {
		mask_idx = alloc_mask(shared_table);
		if (mask_idx == FPVS_INVALID_ENTRY)
			return -1;
		mask = &shared_table->mask_table[mask_idx].mask;
		mask->key = *mask_key;
		mask->range.start = range->start;
		mask->range.end = range->end;
		mask->ref_count = 1;
		mask->state = FPVS_FLOW_ACTIVE;
	} else {
		mask = &shared_table->mask_table[mask_idx].mask;
		mask->ref_count++;
	}

	idx = alloc_flow(shared_table);
	if (idx == FPVS_INVALID_ENTRY) {
		return -1;
	}

	flow = &shared_table->flow_table[idx].flow;

	hash = fpvs_flow_hash_masked(key, &mask->key, 0, range->start, range->end);
	hash &= FP_VSWITCH_FLOW_HASH_MASK;

	flow->key = *key;
	flow->mask_index = mask_idx;
	memcpy(flow->actions, actions, actions_len);

	flow->actions_len = actions_len;
	flow->index = idx;
	flow->hash = hash;
	flow->age = 0;
	memset(&flow->stats, 0, sizeof(flow->stats));
	flow->state = FPVS_FLOW_ACTIVE;

	fp_hlist_add_head(&shared_table->flow_hash[hash],
			  shared_table->flow_table, idx, node);

	return 0;
}
