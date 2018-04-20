/*
 * Copyright (c) 2008 6WIND
 */

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fp.h"
#include "libfp_shm.h"
#include "shmem/fpn-shmem.h"

void *get_fp_shared(void)
{
	return fpn_shmem_mmap("fp-shared", NULL, sizeof(shared_mem_t));
}

