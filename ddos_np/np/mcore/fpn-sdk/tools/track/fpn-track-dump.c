/* Copyright 2013 6WIND S.A. */

#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "fpn.h"
#include "shmem/fpn-shmem.h"
#include "fpn-track.h"

static int dump_track(void)
{
	fpn_track_shared_mem_t *shmem;
	struct fpn_tk_e *tke;
	uint32_t pid, j, index;

	shmem = fpn_shmem_mmap("fpn-track-shared", NULL, sizeof(*shmem));
	if (shmem == NULL) {
		fprintf(stderr, "can't map fpn-track-shared\n");
		return -1;
	}

	printf("Track information\n");
	for (pid = 0; pid < FPN_MAX_CORES; pid++) {
		printf("Core %u\n", pid);
		index = (shmem->fpn_tk_table[pid].index - 1) & FPN_TRACK_MASK_INDEX;
		for (j = 0; j < FPN_TRACK_MAX_SIZE; j++) {
			tke = &shmem->fpn_tk_table[pid].entry[index];
			if (tke->line)
				printf("\t[%u] PC=%s RA=%s Func=%s:%u cycles=%u\n",
						index, tke->pc_addr, tke->ra_addr, tke->func_name,
						tke->line, tke->cycles);
			index = (index - 1) & FPN_TRACK_MASK_INDEX;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	dump_track();
	return 0;
}
