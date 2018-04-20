/*
 * Copyright(c) 2012 6WIND
 */

#ifndef __FPN_SHMEM_H__
#define __FPN_SHMEM_H__

int fpn_shmem_add(const char *name, size_t size);
int fpn_shmem_del(const char *name);
void *fpn_shmem_mmap(const char *name, void *vardd, size_t size);

#endif
