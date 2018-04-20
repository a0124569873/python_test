/*
 * Copyright(c) 2012 6WIND
 */

#include "fpn.h"
#include "fp-includes.h"
#include "shmem/fpn-shmem.h"
#include "fp-shared.h"

void* fp_shared_alloc(void)
{
	void *addr;

	/* Create fp-shared memory. Ignore error, it may already
	 * exist.
	 */
	fpn_shmem_add("fp-shared", sizeof(shared_mem_t));
	/* map fp_shared */
	addr = fpn_shmem_mmap("fp-shared", NULL, sizeof(shared_mem_t));
	if (addr == NULL) {
		fpn_printf("cannot map fp_shared size=%"PRIu64" (%"PRIu64"M)\n",
			   (uint64_t)sizeof(shared_mem_t),
			   (uint64_t)sizeof(shared_mem_t) >> 20);
		return NULL;
	}
	fpn_printf("Using fp_shared=%p size=%"PRIu64" (%"PRIu64"M)\n",
		   addr, (uint64_t)sizeof(shared_mem_t),
		   (uint64_t)sizeof(shared_mem_t) >> 20);

	return addr;
}
