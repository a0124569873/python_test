/*
 * Copyright(c) 2012 6WIND
 */

#include "fpn.h"
#include "shmem/fpn-shmem.h"
#include "fpn-cpu-usage.h"

FPN_DEFINE_SHARED(cpu_usage_shared_mem_t *, cpu_usage_shared);

int cpu_usage_init(void)
{
	int i;

	fpn_shmem_add("cpu-usage-shared", sizeof(cpu_usage_shared_mem_t));
	cpu_usage_shared = fpn_shmem_mmap("cpu-usage-shared",
					  NULL,
					  sizeof(cpu_usage_shared_mem_t));

	if (cpu_usage_shared == NULL) {
		fpn_printf("cannot map cpu_usage_shared size=%"PRIu64" (%"PRIu64"M)\n",
			   (uint64_t)sizeof(cpu_usage_shared_mem_t),
			   (uint64_t)sizeof(cpu_usage_shared_mem_t) >> 20);
		return -1;
	}

	for (i = 0; i < FPN_MAX_CORES; i++)
		cpu_usage_shared->busy_cycles[i].val = 0;

	return 0;
}
