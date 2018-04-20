/* Copyright 2013 6WIND S.A. */

#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <sysexits.h>

#include "fpn.h"
#include "shmem/fpn-shmem.h"

static void
show_fp_shmem(const char *shm_name)
{
	void *shm;
	int pagesize = getpagesize();

	shm = fpn_shmem_mmap(shm_name, NULL, pagesize);
	if (shm)
		printf("%s\n", shm_name);
	else
		printf("Not found\n");

	return;
}

static void
fp_shmem_usage(const char *cmd)
{
	printf("Usage: %s <name>\n", cmd);
	printf("Check if the shared memory exists\n");

	exit(EX_USAGE);
}

int
main(int argc, char **argv)
{
	if (argc != 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
		fp_shmem_usage(argv[0]);

	show_fp_shmem(argv[1]);
	return 0;
}
