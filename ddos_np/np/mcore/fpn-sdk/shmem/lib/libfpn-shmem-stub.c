/*
 * Copyright (c) 2012 6WIND
 */

/* Stubbed shmem (uses malloc, cannot be shared) */

#include "fpn.h"
#include "shmem/fpn-shmem.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>

#define LIBFP_SHM_DEBUG 0

#if LIBFP_SHM_DEBUG == 1
#define TRACE(fmt, args...) syslog(LOG_DEBUG, "libfpn_shmem: " fmt, ##args)
#else
#define TRACE(fmt, args...) do {} while(0)
#endif

#define SHM_PERROR(str) syslog(LOG_ERR, "libfpn_shmem: " str ": %s", strerror(errno))

struct shmem_zone {
	FPN_LIST_ENTRY(shmem_zone) next;
	char name[32];
	void *p;
	unsigned len;
};

FPN_LIST_HEAD(shmem_zone_list, shmem_zone);
static struct shmem_zone_list zone_list = FPN_LIST_HEAD_INITIALIZER(zone_list);

static struct shmem_zone *shmem_zone_lookup(const char *name)
{
	struct shmem_zone *shm;

	FPN_LIST_FOREACH(shm, &zone_list, next) {
		if (!strcmp(name, shm->name))
			return shm;
	}
	return NULL;
}

void *fpn_shmem_mmap(const char *shm_name, void *map_addr, size_t mapsize)
{
	struct shmem_zone *shm = NULL;

	shm = shmem_zone_lookup(shm_name);
	if (shm == NULL)
		return NULL;
	if (mapsize > shm->len)
		return NULL;
	/* stub_shm cannot map the same zone at several different addresses */
	if (map_addr != NULL && map_addr != shm->p)
		return NULL;

	return shm->p;
}

int fpn_shmem_add(const char *shm_name, size_t shm_size)
{
	struct shmem_zone *shm = NULL;
	void *p = NULL;
	int ret;

	shm = shmem_zone_lookup(shm_name);
	if (shm != NULL) {
		if (shm_size > shm->len)
			return -1;
		return 0;
	}

	shm = malloc(sizeof(*shm));
	if (shm == NULL)
		goto fail;

	/* the pointer should be cache aligned but we cannot use
	 * FPN_CACHELINE_SIZE as __FastPath__ may not be defined, so use 128 */
	p = memalign(128, shm_size);
	if (p == NULL)
		goto fail;

	memset(shm, 0, sizeof(*shm));
	ret = snprintf(shm->name, sizeof(shm->name), "%s", shm_name);
	if (ret < 0 || ret >= (int)sizeof(shm->name))
		goto fail;

	shm->len = shm_size;
	shm->p = p;
	FPN_LIST_INSERT_HEAD(&zone_list, shm, next);
	return 0;

 fail:
	if (shm != NULL)
		free(shm);
	if (p != NULL)
		free(p);
	return -1;
}

int fpn_shmem_del(const char *shm_name)
{
	struct shmem_zone *shm = NULL;

	shm = shmem_zone_lookup(shm_name);
	if (shm == NULL)
		return -1;

	FPN_LIST_REMOVE(shm, next);
	free(shm->p);
	free(shm);
	return 0;
}
