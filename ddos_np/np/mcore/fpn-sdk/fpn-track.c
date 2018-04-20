/*
 * Copyright(c) 2009 6WIND
 */
#include "fpn.h"
#include "shmem/fpn-shmem.h"
#include "fpn-track.h"


FPN_DEFINE_SHARED(fpn_track_shared_mem_t *, fpn_track_shared);
/*
 * This function save the PC and the return address of the caller
 * ra_addr must be the return address of the caller.
 * Line is __LINE__ in the function calling this function.
*/
void fpn_track(void *ra_addr, const char *func_name, size_t line)
{
	struct fpn_tk_s *fpn_tk_table;
	struct fpn_tk_e *tke, *prev;
	void *pc_addr;
	int32_t pid;
	uint32_t index;

	if (fpn_track_shared == NULL)
		return;

	pid = fpn_get_core_num();
	pc_addr = __builtin_return_address(0);

	fpn_tk_table = &fpn_track_shared->fpn_tk_table[pid];

	index = fpn_tk_table->index;

	tke = &fpn_tk_table->entry[index];
	prev = &fpn_tk_table->entry[(index-1) & FPN_TRACK_MASK_INDEX];
	snprintf(tke->pc_addr, ADDR_LEN, "%p", pc_addr);
	snprintf(tke->ra_addr, ADDR_LEN, "%p", ra_addr);
	snprintf(tke->func_name, MAX_FUNC_NAME_LEN, "%s", func_name);
	tke->cycles = (uint32_t)(fpn_get_clock_cycles() - prev->cycles);
	tke->line = line;
	fpn_tk_table->index = (index + 1) & FPN_TRACK_MASK_INDEX;
}

int fpn_track_init(void)
{
	fpn_shmem_add("fpn-track-shared", sizeof(fpn_track_shared_mem_t));
	fpn_track_shared = fpn_shmem_mmap("fpn-track-shared",
					  NULL,
					  sizeof(fpn_track_shared_mem_t));

	if (fpn_track_shared == NULL) {
		fpn_printf("cannot map fpn_track_shared size=%"PRIu64"\n",
			   (uint64_t)sizeof(fpn_track_shared_mem_t));
		return -1;
	}

	memset(fpn_track_shared, 0, sizeof(fpn_track_shared_mem_t));

	return 0;
}
