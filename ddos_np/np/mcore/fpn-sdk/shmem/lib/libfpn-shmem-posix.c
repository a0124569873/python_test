/*
 * Copyright (c) 2012 6WIND
 */

/* Alternate shared memory using POSIX shm */

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

#include "shmem/fpn-shmem.h"

#define LIBFP_SHM_DEBUG 0

#if LIBFP_SHM_DEBUG == 1
#define TRACE(fmt, args...) syslog(LOG_DEBUG, "libfpn_shmem: " fmt, ##args)
#else
#define TRACE(fmt, args...) do {} while(0)
#endif

#define SHM_PERROR(str) syslog(LOG_ERR, "libfpn_shmem: " str ": %s", strerror(errno))

void *fpn_shmem_mmap(const char *shm_name, void *map_addr, size_t mapsize)
{
	int fd;
	void * p;
	int mapping;

	fd = shm_open(shm_name, O_RDWR, ALLPERMS);
	if (fd < 0) {
		SHM_PERROR("shm_open");
		return NULL;
	}

	mapping = MAP_SHARED;
	if (map_addr != NULL)
		mapping |= MAP_FIXED;
	p = mmap(map_addr, mapsize, PROT_READ|PROT_WRITE,
			mapping, fd, 0);

	close(fd);
	if (p == MAP_FAILED) {
		SHM_PERROR("mmap");
		return NULL;
	}

	return p;
}

int fpn_shmem_add(const char *shm_name, size_t shm_size)
{
	int fd;
	int ret;

	fd = shm_open(shm_name, O_RDWR|O_CREAT, ALLPERMS);

	ret = ftruncate(fd, (off_t) shm_size);
	if (ret < 0) {
		SHM_PERROR("ftruncate");
		return -1;
	}
	close(fd);

	return 0;
}

int fpn_shmem_del(const char *shm_name)
{
	shm_unlink(shm_name);

	return 0;
}
