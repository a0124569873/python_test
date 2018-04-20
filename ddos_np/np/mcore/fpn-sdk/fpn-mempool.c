/*
 * Copyright(c) 2011 6WIND
 * All rights reserved.
 */

/*-
 * Copyright (c) <2010>, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * - Neither the name of Intel Corporation nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "fpn.h"
#include "fpn-ring.h"
#include "fpn-mempool.h"

#define FPN_MEMPOOL_ERROR(fmt, args...) do {	\
		fpn_printf(fmt "\n", ## args);	\
	} while (0)

FPN_TAILQ_HEAD(fpn_mempool_list, fpn_mempool);

/* global list of mempool (used for debug/dump) */
static FPN_DEFINE_SHARED(struct fpn_mempool_list, mempool_list) =
	FPN_TAILQ_HEAD_INITIALIZER(mempool_list);

/* find next power of 2 */
static uint32_t align32pow2(uint32_t x)
{
     x--;
     x |= x >> 1;
     x |= x >> 2;
     x |= x >> 4;
     x |= x >> 8;
     x |= x >> 16;
     return x + 1;
}

/*
 * When debug is enabled, store some statistics.
 */
#ifdef FPN_MEMPOOL_DEBUG
#define __FPN_MEMPOOL_STAT_ADD(mp, name, n) do {		\
		unsigned __core_id = fpn_get_core_num();	\
		mp->stats[__core_id].name##_objs += n;		\
		mp->stats[__core_id].name##_bulk += 1;		\
	} while(0)
#else
#define __FPN_MEMPOOL_STAT_ADD(mp, name, n) do {} while(0)
#endif

#ifdef FPN_MEMPOOL_DEBUG
/* get header cookie value */
static inline uint64_t __fpn_mempool_read_header_cookie(const void *obj)
{
	return *(const uint64_t *)((const char *)obj - sizeof(uint64_t));
}

/* get trailer cookie value */
static inline uint64_t __fpn_mempool_read_trailer_cookie(const void *obj)
{
	struct fpn_mempool **mpp = __fpn_mempool_from_obj(obj);
	return *(const uint64_t *)((const char *)obj + (*mpp)->elt_size);
}

/* write header cookie value */
static inline void __fpn_mempool_write_header_cookie(void *obj, int free)
{
	uint64_t *cookie_p;
	cookie_p = (uint64_t *)((char *)obj - sizeof(uint64_t));
	if (free == 0)
		*cookie_p = FPN_MEMPOOL_HEADER_COOKIE1;
	else
		*cookie_p = FPN_MEMPOOL_HEADER_COOKIE2;

}

/* write trailer cookie value */
static inline void __fpn_mempool_write_trailer_cookie(void *obj)
{
	uint64_t *cookie_p;
	struct fpn_mempool **mpp = __fpn_mempool_from_obj(obj);
	cookie_p = (uint64_t *)((char *)obj + (*mpp)->elt_size);
	*cookie_p = FPN_MEMPOOL_TRAILER_COOKIE;
}
#endif /* FPN_MEMPOOL_DEBUG */

/*
 * Check and update cookies or panic.
 */
#ifdef FPN_MEMPOOL_DEBUG
static inline void
__fpn_mempool_check_cookies(const struct fpn_mempool *mp,
			    void * const *obj_table_const,
			    unsigned n, int free)
{
	uint64_t cookie;
	void *tmp;
	void *obj;
	void **obj_table;

	/* Force to drop the "const" attribute. This is done only when
	 * DEBUG is enabled */
	tmp = (void *) obj_table_const;
	obj_table = tmp;

	while (n--) {
		obj = obj_table[n];

		if (fpn_mempool_from_obj(obj) != mp)
			fpn_panic("MEMPOOL: object is owned by another "
				  "mempool\n");

		cookie = __fpn_mempool_read_header_cookie(obj);

		if (free == 0) {
			if (cookie != FPN_MEMPOOL_HEADER_COOKIE1) {
				FPN_MEMPOOL_ERROR(
					"obj=%p, mempool=%p, cookie=%"PRIx64"\n",
					obj, mp, cookie);
				fpn_panic("MEMPOOL: bad header cookie (put)\n");
			}
			__fpn_mempool_write_header_cookie(obj, 1);
		}
		else if (free == 1) {
			if (cookie != FPN_MEMPOOL_HEADER_COOKIE2) {
				FPN_MEMPOOL_ERROR(
					"obj=%p, mempool=%p, cookie=%"PRIx64"\n",
					obj, mp, cookie);
				fpn_panic("MEMPOOL: bad header cookie (get)\n");
			}
			__fpn_mempool_write_header_cookie(obj, 0);
		}
		else if (free == 2) {
			if (cookie != FPN_MEMPOOL_HEADER_COOKIE1 &&
			    cookie != FPN_MEMPOOL_HEADER_COOKIE2) {
				FPN_MEMPOOL_ERROR(
					"obj=%p, mempool=%p, cookie=%"PRIx64"\n",
					obj, mp, cookie);
				fpn_panic("MEMPOOL: bad header cookie (audit)\n");
			}
		}
		cookie = __fpn_mempool_read_trailer_cookie(obj);
		if (cookie != FPN_MEMPOOL_TRAILER_COOKIE) {
			FPN_MEMPOOL_ERROR(
				"obj=%p, mempool=%p, cookie=%"PRIx64"\n",
				obj, mp, cookie);
			fpn_panic("MEMPOOL: bad trailer cookie\n");
		}
	}
}
#else
#define __fpn_mempool_check_cookies(mp, obj_table_const, n, free) do {} while(0)
#endif /* FPN_MEMPOOL_DEBUG */

/*
 * Put several objects back in the mempool; used internally.
 */
static inline void
__fpn_mempool_put_bulk(struct fpn_mempool *mp, void * const *obj_table,
		       unsigned n, int is_mp)
{
#if FPN_MEMPOOL_CACHE_MAX_SIZE > 0
	struct fpn_mempool_cache *cache;
	uint32_t cache_len;
	void **cache_objs;
	unsigned core_id = fpn_get_core_num();
	uint32_t cache_size = mp->cache_size;
	uint32_t cache_add_count;
#endif /* FPN_MEMPOOL_CACHE_MAX_SIZE > 0 */

	/* increment stat now, adding in mempool always success */
	__FPN_MEMPOOL_STAT_ADD(mp, put, n);

#if FPN_MEMPOOL_CACHE_MAX_SIZE > 0
	/* cache is not enabled or single producer */
	if (unlikely(cache_size == 0 || is_mp == 0))
		goto ring_enqueue;

	cache = &mp->local_cache[core_id];
	cache_len = cache->len;
	cache_objs = cache->objs;

	/* cache is full and we add many objects: enqueue in ring */
	if (unlikely(cache_len == cache_size && n >= cache_size))
		goto ring_enqueue;

	/*
	 * cache is full and we add few objects: enqueue the content
	 * of the cache in ring
	 */
	if (unlikely(cache_len == cache_size)) {
#ifdef FPN_MEMPOOL_DEBUG
		if (fpn_ring_mp_enqueue_bulk(mp->ring, cache->objs,
					     cache_size) < 0)
			fpn_panic("cannot put objects in mempool\n");
#else
		fpn_ring_mp_enqueue_bulk(mp->ring, cache->objs,
					 cache_size);
#endif
		cache_len = 0;
	}

	/* determine how many objects we can add in cache */
	if (likely(n <= cache_size - cache_len))
		cache_add_count = n;
	else
		cache_add_count = cache_size - cache_len;

	/* add in cache while there is enough room */
	while (likely(cache_add_count > 0)) {
		cache_objs[cache_len] = *obj_table;
		obj_table++;
		cache_len++;
		n--;
		cache_add_count--;
	}

	cache->len = cache_len;

	/* no more object to add, return */
	if (likely(n == 0))
		return;

 ring_enqueue:
#endif /* FPN_MEMPOOL_CACHE_MAX_SIZE > 0 */

	/* push remaining objects in ring */
#ifdef FPN_MEMPOOL_DEBUG
	if (is_mp) {
		if (fpn_ring_mp_enqueue_bulk(mp->ring, obj_table, n) < 0)
			fpn_panic("cannot put objects in mempool\n");
	}
	else {
		if (fpn_ring_sp_enqueue_bulk(mp->ring, obj_table, n) < 0)
			fpn_panic("cannot put objects in mempool\n");
	}
#else
	if (is_mp)
		fpn_ring_mp_enqueue_bulk(mp->ring, obj_table, n);
	else
		fpn_ring_sp_enqueue_bulk(mp->ring, obj_table, n);
#endif
}

/*
 * Put several objects back in the mempool (multi-producers safe).
 */
void
fpn_mempool_mp_put_bulk(struct fpn_mempool *mp, void * const *obj_table,
			unsigned n)
{
	__fpn_mempool_check_cookies(mp, obj_table, n, 0);
	__fpn_mempool_put_bulk(mp, obj_table, n, 1);
}

/*
 * Put several objects back in the mempool (NOT multi-producers safe).
 */
void
fpn_mempool_sp_put_bulk(struct fpn_mempool *mp, void * const *obj_table,
			unsigned n)
{
	__fpn_mempool_check_cookies(mp, obj_table, n, 0);
	__fpn_mempool_put_bulk(mp, obj_table, n, 0);
}

/*
 * Put several objects back in the mempool.
 */
void
fpn_mempool_put_bulk(struct fpn_mempool *mp, void * const *obj_table,
		     unsigned n)
{
	__fpn_mempool_check_cookies(mp, obj_table, n, 0);
	__fpn_mempool_put_bulk(mp, obj_table, n, !(mp->flags & FPN_MEMPOOL_F_SP_PUT));
}

/*
 * Put one object in the mempool (multi-producers safe).
 */
void
fpn_mempool_mp_put(struct fpn_mempool *mp, void *obj)
{
	fpn_mempool_mp_put_bulk(mp, &obj, 1);
}

/*
 * Put one object back in the mempool (NOT multi-producers safe).
 */
void
fpn_mempool_sp_put(struct fpn_mempool *mp, void *obj)
{
	fpn_mempool_sp_put_bulk(mp, &obj, 1);
}

/*
 * Put one object back in the mempool.
 */
void
fpn_mempool_put(struct fpn_mempool *mp, void *obj)
{
	fpn_mempool_put_bulk(mp, &obj, 1);
}

/*
 * Get several objects from the mempool; used internally.
 */
static inline int
__fpn_mempool_get_bulk(struct fpn_mempool *mp, void **obj_table,
		       unsigned n, int is_mc)
{
	int ret;
#ifdef FPN_MEMPOOL_DEBUG
	unsigned n_orig = n;
#endif
#if FPN_MEMPOOL_CACHE_MAX_SIZE > 0
	struct fpn_mempool_cache *cache;
	uint32_t cache_len, cache_len_save = 0;
	void **cache_objs;
	unsigned core_id = fpn_get_core_num();
	uint32_t cache_size = mp->cache_size;
	uint32_t cache_del_count;

	cache = &mp->local_cache[core_id];

	/* cache is not enabled or single consumer */
	if (unlikely(cache_size == 0 || is_mc == 0))
		goto ring_dequeue;

	cache_len = cache->len;
	cache_objs = cache->objs;

	/* cache is empty and we need many objects: dequeue from ring */
	if (unlikely(cache_len == 0 && n >= cache_size))
		goto ring_dequeue;

	/* cache is empty and we dequeue few objects: fill the cache first */
	if (unlikely(cache_len == 0 && n < cache_size)) {
		ret = fpn_ring_mc_dequeue_bulk(mp->ring, cache_objs,
					       cache_size);
		if (unlikely(ret < 0)) {
			__FPN_MEMPOOL_STAT_ADD(mp, get_fail, n_orig);
			return ret;
		}

		cache_len = cache_size;
	}

	if (likely(n <= cache_len))
		cache_del_count = n;
	else
		cache_del_count = cache_len;

	cache_len_save = cache_len;

	/* add in cache only while there is enough room */
	while (likely(cache_del_count > 0)) {
		cache_len--;
		*obj_table = cache_objs[cache_len];
		obj_table++;
		n--;
		cache_del_count--;
	}

	cache->len = cache_len;

	/* no more object to get, return */
	if (likely(n == 0)) {
		__FPN_MEMPOOL_STAT_ADD(mp, get_success, n_orig);
		return 0;
	}

 ring_dequeue:
#endif /* FPN_MEMPOOL_CACHE_MAX_SIZE > 0 */

	/* get remaining objects from ring */
	if (is_mc)
		ret = fpn_ring_mc_dequeue_bulk(mp->ring, obj_table, n);
	else
		ret = fpn_ring_sc_dequeue_bulk(mp->ring, obj_table, n);

#if FPN_MEMPOOL_CACHE_MAX_SIZE > 0
	/*
	 * bad luck, the ring is empty but we already dequeued some
	 * entries from cache, we have to restore them
	 */
	if (unlikely(ret < 0 && cache_len_save != 0))
		cache->len = cache_len_save;
#endif

	if (ret < 0)
		__FPN_MEMPOOL_STAT_ADD(mp, get_fail, n_orig);
	else
		__FPN_MEMPOOL_STAT_ADD(mp, get_success, n_orig);

	return ret;
}

/*
 * Get several objects from the mempool (NOT multi-consumers safe).
 */
int
fpn_mempool_sc_get_bulk(struct fpn_mempool *mp, void **obj_table, unsigned n)
{
	int ret;
	ret = __fpn_mempool_get_bulk(mp, obj_table, n, 0);
	if (ret == 0)
		__fpn_mempool_check_cookies(mp, obj_table, n, 1);
	return ret;
}

/*
 * Get several objects from the mempool (multi-consumers safe).
 */
int
fpn_mempool_mc_get_bulk(struct fpn_mempool *mp, void **obj_table, unsigned n)
{
	int ret;
	ret = __fpn_mempool_get_bulk(mp, obj_table, n, 1);
	if (ret == 0)
		__fpn_mempool_check_cookies(mp, obj_table, n, 1);
	return ret;
}

/*
 * Get several objects from the mempool.
 */
int
fpn_mempool_get_bulk(struct fpn_mempool *mp, void **obj_table, unsigned n)
{
	int ret;
	ret = __fpn_mempool_get_bulk(mp, obj_table, n,
				 !(mp->flags & FPN_MEMPOOL_F_SC_GET));
	if (ret == 0)
		__fpn_mempool_check_cookies(mp, obj_table, n, 1);
	return ret;
}

/*
 * Get one object from the mempool (multi-consumers safe).
 */
int
fpn_mempool_mc_get(struct fpn_mempool *mp, void **obj_p)
{
	return fpn_mempool_mc_get_bulk(mp, obj_p, 1);
}

/*
 * Get one object from the mempool (NOT multi-consumers safe).
 */
int
fpn_mempool_sc_get(struct fpn_mempool *mp, void **obj_p)
{
	return fpn_mempool_sc_get_bulk(mp, obj_p, 1);
}

/*
 * Get one object from the mempool.
 */
int
fpn_mempool_get(struct fpn_mempool *mp, void **obj_p)
{
	return fpn_mempool_get_bulk(mp, obj_p, 1);
}

static unsigned
fpn_mempool_get_header_size(unsigned flags)
{
	unsigned header_size;

	/*
	 * In header, we have at least the pointer to the pool, and
	 * optionaly a 64 bits cookie.
	 */
	header_size = 0;
	header_size += sizeof(struct fpn_mempool *); /* ptr to pool */
#ifdef FPN_MEMPOOL_DEBUG
	header_size += sizeof(uint64_t); /* cookie */
#endif
	if ((flags & FPN_MEMPOOL_F_NO_CACHE_ALIGN) == 0)
		header_size = (header_size + FPN_CACHELINE_MASK) &
			(~FPN_CACHELINE_MASK);

	return header_size;
}

static unsigned
fpn_mempool_get_trailer_size(unsigned flags, unsigned elt_size,
			     unsigned header_size)
{
	unsigned total_elt_size;
	unsigned trailer_size = 0;

#ifdef FPN_MEMPOOL_DEBUG
	trailer_size += sizeof(uint64_t); /* cookie */
#endif

	/* element size is 8 bytes-aligned at least */
	elt_size = (elt_size + 7) & (~7);

	/* expand trailer to next cache line */
	if ((flags & FPN_MEMPOOL_F_NO_CACHE_ALIGN) == 0) {
		total_elt_size = header_size + elt_size + trailer_size;
		trailer_size += ((FPN_CACHELINE_SIZE -
				  (total_elt_size & FPN_CACHELINE_MASK)) &
				 FPN_CACHELINE_MASK);
	}

	return trailer_size;
}

/* get the element size including header and trailer */
static unsigned
fpn_mempool_get_elt_size(unsigned flags, unsigned elt_size,
			 unsigned header_size, unsigned trailer_size)
{
	unsigned total_elt_size;
	(void)flags; /* silent compiler */

	/* element size is 8 bytes-aligned at least */
	elt_size = (elt_size + 7) & (~7);

	/* this is the size of an object, including header and trailer */
	total_elt_size = header_size + elt_size + trailer_size;

	return total_elt_size;
}

/* this function returns the size of the internal ring of the mempool */
size_t
fpn_mempool_get_ring_size(unsigned n)
{
	unsigned rg_size, rg_count;
	rg_count = align32pow2(n+1);
	rg_size = fpn_ring_getsize(rg_count);
	return rg_size;
}

/* this functions returns the size required by a mempool */
size_t
fpn_mempool_size(unsigned n, unsigned elt_size,
		 unsigned private_data_size, unsigned flags)
{
	size_t rg_size, objtab_size, mempool_size;

	/*  private data is cache-aligned */
	rg_size = fpn_mempool_get_ring_size(n);
	objtab_size = fpn_mempool_get_objtab_size(flags, elt_size, n);
	private_data_size = (private_data_size +
			     FPN_CACHELINE_MASK) & (~FPN_CACHELINE_MASK);
	mempool_size = sizeof(struct fpn_mempool) + private_data_size +
		rg_size + objtab_size;

	mempool_size = (mempool_size + FPN_CACHELINE_MASK) & (~FPN_CACHELINE_MASK);

	return mempool_size;

}

/* this function returns the size of the object table depending on
 * flags, element size and count */
size_t
fpn_mempool_get_objtab_size(unsigned flags, unsigned elt_size, unsigned n)
{
	size_t header_size, trailer_size, total_elt_size;

	header_size = fpn_mempool_get_header_size(flags);
	trailer_size = fpn_mempool_get_trailer_size(flags, elt_size,
						    header_size);
	total_elt_size = fpn_mempool_get_elt_size(flags, elt_size,
						  header_size, trailer_size);

	return total_elt_size * n;
}

/* initialize a mempool, the user provides the pointer to the mempool,
 * the ring, and the objtable. */
int
fpn_mempool_init(struct fpn_mempool *mp, struct fpn_ring *r,
		 void *objtable, const char *name, unsigned n,
		 unsigned elt_size, unsigned cache_size,
		 unsigned private_data_size, fpn_mempool_ctor_t *mp_init,
		 void *mp_init_arg, fpn_mempool_obj_ctor_t *obj_init,
		 void *obj_init_arg, unsigned flags)
{
	char rg_name[FPN_RING_NAMESIZE];
	int rg_flags = 0;
	unsigned rg_count;
	unsigned header_size, trailer_size;
	unsigned i;
	void *obj;

	/* compilation-time checks */
	FPN_BUILD_BUG_ON((sizeof(struct fpn_mempool) &
			  FPN_CACHELINE_MASK) != 0);
#if FPN_MEMPOOL_CACHE_MAX_SIZE > 0
	FPN_BUILD_BUG_ON((sizeof(struct fpn_mempool_cache) &
			  FPN_CACHELINE_MASK) != 0);
	FPN_BUILD_BUG_ON((fpn_offsetof(struct fpn_mempool, local_cache) &
			  FPN_CACHELINE_MASK) != 0);
#endif
#ifdef FPN_MEMPOOL_DEBUG
	FPN_BUILD_BUG_ON((sizeof(struct fpn_mempool_debug_stats) &
			  FPN_CACHELINE_MASK) != 0);
	FPN_BUILD_BUG_ON((fpn_offsetof(struct fpn_mempool, stats) &
			  FPN_CACHELINE_MASK) != 0);
#endif

	/* pointers must be cache-aligned */
	if (((long)mp & FPN_CACHELINE_MASK) ||
	    ((long)r & FPN_CACHELINE_MASK) ||
	    ((long)objtable & FPN_CACHELINE_MASK)) {
		FPN_MEMPOOL_ERROR("Pointers must be cache-aligned\n");
		return -1;
	}

	/* asked cache too big */
	if (cache_size > FPN_MEMPOOL_CACHE_MAX_SIZE) {
		FPN_MEMPOOL_ERROR("Per-core mempool objcache is too big\n");
		return -1;
	}

	/* ring flags */
	if (flags & FPN_MEMPOOL_F_SP_PUT)
		rg_flags |= FPN_RING_F_SP_ENQ;
	if (flags & FPN_MEMPOOL_F_SC_GET)
		rg_flags |= FPN_RING_F_SC_DEQ;

	/* get ring size and ring name (the ring is used to store objects) */
	snprintf(rg_name, sizeof(rg_name), "MP_%s", name);
	rg_count = align32pow2(n+1);

	/* get element sizes (+ header and trailer) */
	header_size = fpn_mempool_get_header_size(flags);
	trailer_size = fpn_mempool_get_trailer_size(flags, elt_size,
						    header_size);

	if (fpn_ring_init(r, rg_name, rg_count, rg_flags) < 0) {
		FPN_MEMPOOL_ERROR("Cannot init ring\n");
		return -1;
	}

	/* init the mempool structure */
	memset(mp, 0, sizeof(*mp));
	snprintf(mp->name, sizeof(mp->name), "%s", name);
	mp->ring = r;
	mp->size = n;
	mp->flags = flags;
	mp->bulk_default = 1;
	mp->elt_size = elt_size;
	mp->header_size = header_size;
	mp->trailer_size = trailer_size;
	mp->cache_size = cache_size;
	mp->private_data_size = private_data_size;
	mp->objtable = objtable;

	/* call the initializer */
	if (mp_init)
		mp_init(mp, mp_init_arg);

	/* fill the headers and trailers, and add objects in ring */
	obj = objtable;
	for (i = 0; i < n; i++) {
		struct fpn_mempool **mpp;
		obj = (char *)obj + header_size;

		/* set mempool ptr in header */
		mpp = __fpn_mempool_from_obj(obj);
		*mpp = mp;

#ifdef FPN_MEMPOOL_DEBUG
		__fpn_mempool_write_header_cookie(obj, 1);
		__fpn_mempool_write_trailer_cookie(obj);
#endif
		/* call the initializer */
		if (obj_init)
			obj_init(mp, obj_init_arg, obj, i);

		/* enqueue in ring */
		fpn_ring_sp_enqueue(mp->ring, obj);
		obj = (char *)obj + elt_size + trailer_size;
	}

	FPN_TAILQ_INSERT_TAIL(&mempool_list, mp, next);
	return 0;
}

/*
 * Returns whether the object address belongs to the specified mempool.
 * Warning: does not indicate if the object was gotten from the pool.
 */
int
fpn_mempool_object_is_in_pool(struct fpn_mempool *mp, void *obj)
{
	unsigned total_elt_size;
	uint8_t *obj_start;
	long offset;

	total_elt_size = mp->header_size + mp->elt_size + mp->trailer_size;

	obj_start = (uint8_t*)obj - mp->header_size;

	offset = (obj_start - (uint8_t *)mp->objtable);
	return ((offset % total_elt_size) == 0) &&
		((offset / total_elt_size) < mp->size);
}

/*
 * fpn_mempool_init_linear() does not allocate memory and it assumes that
 * mempool() is a linear memory large enough to map the ring.
 */
int
fpn_mempool_init_linear(struct fpn_mempool *mp, const char *name, unsigned n,
			unsigned elt_size, unsigned cache_size,
			unsigned private_data_size, fpn_mempool_ctor_t *mp_init,
			void *mp_init_arg, fpn_mempool_obj_ctor_t *obj_init,
			void *obj_init_arg, unsigned flags)
{
	size_t rg_size;
	struct fpn_ring *r;
	void *objtable;

	rg_size = fpn_mempool_get_ring_size(n);
	r = (void *)mp + sizeof(struct fpn_mempool) + private_data_size;
	objtable = (void *)r + rg_size;

	if (fpn_mempool_init(mp, r, objtable, name, n, elt_size, cache_size,
			     private_data_size, mp_init, mp_init_arg,
			     obj_init, obj_init_arg, flags) < 0) {
		FPN_MEMPOOL_ERROR("%s(): cannot init mempool\n", __FUNCTION__);
		return -1;
	}

	return 0;
}

/*
 * create the mempool: it contains a mempool structure, followed
 * by its optional private data, then a ring to store the object
 * pointers, then the objects themselves.
 *
 * -----------------------------------------------------------
 * |    |  |          |||||||||||||  |  |  |  |  |  |  |  |  |
 * -----------------------------------------------------------
 * ^    ^  ^          ^            ^
 *  \    \  `- ring    \            `- objects
 *   \   private data   ring object
 *   mempool              pointers
 */
struct fpn_mempool *
fpn_mempool_create(const char *name, unsigned n, unsigned elt_size,
		   unsigned cache_size, unsigned private_data_size,
		   fpn_mempool_ctor_t *mp_init, void *mp_init_arg,
		   fpn_mempool_obj_ctor_t *obj_init, void *obj_init_arg,
		   unsigned flags)
{
	struct fpn_mempool *mp;
	size_t mempool_size;

	/* reserve a memory zone for this mempool: private data is
	 * cache-aligned */
	private_data_size = (private_data_size +
			     FPN_CACHELINE_MASK) & (~FPN_CACHELINE_MASK);
	mempool_size = fpn_mempool_size(n, elt_size, private_data_size, flags);

	mp = fpn_malloc(mempool_size, FPN_CACHELINE_SIZE);
	/* no more memory */
	if (mp == NULL) {
		FPN_MEMPOOL_ERROR("%s(): no memory for %s (size %zd)\n",
			 __FUNCTION__, name, mempool_size);
		return NULL;
	}

	if (fpn_mempool_init_linear(mp, name, n, elt_size, cache_size,
			     private_data_size, mp_init, mp_init_arg,
			     obj_init, obj_init_arg, flags) < 0) {
		fpn_free(mp);
		FPN_MEMPOOL_ERROR("%s(): cannot init mempool for %s\n",
			 __FUNCTION__, name);
		return NULL;
	}

	return mp;
}

/* Return the number of entries in the mempool */
unsigned
fpn_mempool_count(const struct fpn_mempool *mp)
{
	unsigned count;

	count = fpn_ring_count(mp->ring);

#if FPN_MEMPOOL_CACHE_MAX_SIZE > 0
	{
		unsigned core_id;
		if (mp->cache_size == 0)
			return count;

		for (core_id = 0; core_id < FPN_MAX_CORES; core_id++)
			count += mp->local_cache[core_id].len;
	}
#endif

	/*
	 * due to race condition (access to len is not locked), the
	 * total can be greater than size... so fix the result
	 */
	if (count > mp->size)
		return mp->size;
	return count;
}

/* dump the cache status */
static unsigned
fpn_mempool_dump_cache(const struct fpn_mempool *mp)
{
#if FPN_MEMPOOL_CACHE_MAX_SIZE > 0
	unsigned core_id;
	unsigned count = 0;
	unsigned cache_count;

	fpn_printf("  cache infos:\n");
	fpn_printf("    cache_size=%u\n", mp->cache_size);
	for (core_id = 0; core_id < FPN_MAX_CORES; core_id++) {
		cache_count = mp->local_cache[core_id].len;
		fpn_printf("    cache_count[%u]=%u\n", core_id, cache_count);
		count += cache_count;
	}
	fpn_printf("    total_cache_count=%u\n", count);
	return count;
#else
	mp = mp; /* silent the compiler */
	fpn_printf("  cache disabled\n");
	return 0;
#endif
}

#ifdef FPN_MEMPOOL_DEBUG
/* check cookies before and after objects */
static void
mempool_audit_cookies(const struct fpn_mempool *mp)
{
	unsigned i;
	void *obj;
	void * const *obj_table;

	obj = mp->objtable;
	for (i = 0; i < mp->size; i++) {
		obj = (char *)obj + mp->header_size;
		obj_table = &obj;
		__fpn_mempool_check_cookies(mp, obj_table, 1, 2);
		obj = (char *)obj + mp->elt_size + mp->trailer_size;
	}
}
#else
#define mempool_audit_cookies(mp) do {} while(0)
#endif

#if FPN_MEMPOOL_CACHE_MAX_SIZE > 0
/* check cookies before and after objects */
static void
mempool_audit_cache(const struct fpn_mempool *mp)
{
	/* check cache size consistency */
	unsigned core_id;
	for (core_id = 0; core_id < FPN_MAX_CORES; core_id++) {
		if (mp->local_cache[core_id].len > mp->cache_size) {
			FPN_MEMPOOL_ERROR("badness on cache[%u]\n",
				      core_id);
		}
	}
}
#else
#define mempool_audit_cache(mp) do {} while(0)
#endif


/* check the consistency of mempool (size, cookies, ...) */
void
fpn_mempool_audit(const struct fpn_mempool *mp)
{
	mempool_audit_cache(mp);
	mempool_audit_cookies(mp);
}

/* dump the status of the mempool on the console */
void
fpn_mempool_dump(const struct fpn_mempool *mp)
{
#ifdef FPN_MEMPOOL_DEBUG
	struct fpn_mempool_debug_stats sum;
	unsigned core_id;
#endif
	unsigned common_count;
	unsigned cache_count;

	fpn_printf("mempool <%s>@%p\n", mp->name, mp);
	fpn_printf("  flags=%x\n", mp->flags);
	fpn_printf("  ring=<%s>@%p\n", mp->ring->name, mp->ring);
	fpn_printf("  size=%"PRIu32"\n", mp->size);
	fpn_printf("  bulk_default=%"PRIu32"\n", mp->bulk_default);
	fpn_printf("  header_size=%"PRIu32"\n", mp->header_size);
	fpn_printf("  elt_size=%"PRIu32"\n", mp->elt_size);
	fpn_printf("  trailer_size=%"PRIu32"\n", mp->trailer_size);
	fpn_printf("  total_obj_size=%"PRIu32"\n",
		   mp->header_size + mp->elt_size + mp->trailer_size);

	cache_count = fpn_mempool_dump_cache(mp);
	common_count = fpn_ring_count(mp->ring);
	if ((cache_count + common_count) > mp->size)
		common_count = mp->size - cache_count;
	fpn_printf("  total_count=%u\n", common_count + cache_count);
	fpn_printf("  common_pool_count=%u\n", common_count);

	/* sum and dump statistics */
#ifdef FPN_MEMPOOL_DEBUG
	memset(&sum, 0, sizeof(sum));
	for (core_id = 0; core_id < FPN_MAX_CORES; core_id++) {
		sum.put_bulk += mp->stats[core_id].put_bulk;
		sum.put_objs += mp->stats[core_id].put_objs;
		sum.get_success_bulk += mp->stats[core_id].get_success_bulk;
		sum.get_success_objs += mp->stats[core_id].get_success_objs;
		sum.get_fail_bulk += mp->stats[core_id].get_fail_bulk;
		sum.get_fail_objs += mp->stats[core_id].get_fail_objs;
	}
	fpn_printf("  stats:\n");
	fpn_printf("    put_bulk=%"PRIu64"\n", sum.put_bulk);
	fpn_printf("    put_objs=%"PRIu64"\n", sum.put_objs);
	fpn_printf("    get_success_bulk=%"PRIu64"\n", sum.get_success_bulk);
	fpn_printf("    get_success_objs=%"PRIu64"\n", sum.get_success_objs);
	fpn_printf("    get_fail_bulk=%"PRIu64"\n", sum.get_fail_bulk);
	fpn_printf("    get_fail_objs=%"PRIu64"\n", sum.get_fail_objs);
#else
	fpn_printf("  no statistics available\n");
#endif

	fpn_mempool_audit(mp);
}

/* dump the summary of mempool status to the console */
void
fpn_mempool_dump_summary(const struct fpn_mempool *mp)
{
	unsigned common_count;
	unsigned cache_count = 0;

#if FPN_MEMPOOL_CACHE_MAX_SIZE > 0
	unsigned core_id;

	for (core_id = 0; core_id < FPN_MAX_CORES; core_id++) {
		cache_count += mp->local_cache[core_id].len;
	}
#endif

	fpn_printf("mempool <%s>@%p\n", mp->name, mp);
	fpn_printf("  size=%"PRIu32"\n", mp->size);

	common_count = fpn_ring_count(mp->ring);
	if ((cache_count + common_count) > mp->size)
		common_count = mp->size - cache_count;
	fpn_printf("  count=%u\n", common_count + cache_count);
}

/* list all mempools on the console */
void
fpn_mempool_list(void)
{
	const struct fpn_mempool *mp;

	FPN_TAILQ_FOREACH(mp, &mempool_list, next) {
		fpn_printf("<%s>@%p\n", mp->name, mp);
	}
}

/* dump the status of all mempools on the console */
void
fpn_mempool_list_dump(void)
{
	const struct fpn_mempool *mp;

	FPN_TAILQ_FOREACH(mp, &mempool_list, next) {
		fpn_mempool_dump(mp);
	}
}

/* search a mempool from its name */
struct fpn_mempool *
fpn_mempool_lookup(const char *name)
{
	struct fpn_mempool *mp;

	FPN_TAILQ_FOREACH(mp, &mempool_list, next) {
		if (strncmp(name, mp->name, FPN_MEMPOOL_NAMESIZE) == 0)
			break;
	}
	return mp;
}
