/*
 * Copyright(c) 2007 6WIND
 */
#include "fpn.h"
#include "pool.h"

uint32_t pool_init(struct pool *pool, uint32_t size, char *memstart, uint32_t nb)
{
	uint32_t i = 0;
	char *mem;
	uint32_t tsize = (size + sizeof(uint32_t)) * nb;

	pool->start = memstart;
	pool->nb = nb;
	pool->size = size;
	pool->first = pool->start;
	pool->end = memstart + tsize;

	mem = memstart;
	for (i = 0; i < nb; i++, mem += (pool->size + sizeof(uint32_t)))
		*(uint32_t *)(mem + pool->size) = 0;

	return tsize;
}

void *pool_alloc(struct pool *pool)
{
	char *mem;

	for (mem = pool->first; mem < pool->end; mem+= (pool->size + sizeof(uint32_t))) {
		FPN_TRACK();
		if (*(uint32_t *)(mem + pool->size) == 0) {
			memset((void *)mem, 0, pool->size);
			*(uint32_t *)(mem + pool->size) = 1;
			pool->first = mem + (pool->size + sizeof(uint32_t));
			pool->nb--;
			return (void *)mem;
		}
	}

	return NULL;
}

/* Assume pool->start <= p <= pool->end */
void pool_free(struct pool *pool, void *p)
{
	char *mem = (char *)p;
	if (mem < pool->first)
		pool->first = mem;
	*(uint32_t *)(mem + pool->size) = 0;
	pool->nb++;
}

unsigned int pool_left(struct pool *pool)
{
	return pool->nb * (pool->size + sizeof(uint32_t));
}
