/*
 * Copyright(c) 2007 6WIND
 */
#ifndef _POOL_H_
#define _POOL_H_

/* get FPN_TRACK macro */
#include "fp-track-debug.h"

struct pool {
	uint32_t nb;
	uint32_t size;
	char *start;
	char *first;
	char *end;
};

#define POOL_OVERHEAD sizeof(uint32_t)

uint32_t pool_init(struct pool *pool, uint32_t size, char *memstart, uint32_t nb);
void *pool_alloc(struct pool *pool);
void pool_free(struct pool *pool, void *p);
unsigned int pool_left(struct pool *pool);

#endif
