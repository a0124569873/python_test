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

#ifndef _FPN_MEMPOOL_H_
#define _FPN_MEMPOOL_H_

// #define FPN_MEMPOOL_DEBUG

/* Keep a maximum of 32 objects in per-core cache */
#define FPN_MEMPOOL_CACHE_MAX_SIZE 32

/**
 * @file
 * FPN Mempool.
 *
 * A memory pool is an allocator of fixed-size object. It is
 * identified by its name, and uses a ring to store free objects. It
 * provides some other optional services, like a per-core object
 * cache, and an alignment helper to ensure that objects are padded
 * to spread them equally on all RAM channels, ranks, and so on.
 *
 * Objects owned by a mempool should never be added in another
 * mempool. When an object is freed using fpn_mempool_put() or
 * equivalent, the object data is not modified; the user can save some
 * meta-data in the object data and retrieve them when allocating a
 * new object.
 *
 * Note: the mempool implementation is not preemptable. In case of
 * userland fastpath, a core must not be interrupted by another task
 * that uses the same mempool, because it uses a ring which is not
 * preemptable. Also, mempool functions must not be used outside the FPN
 * environment: for example, a standard application must not use
 * mempools. This is due to the per-core cache that won't work as
 * fpn_get_core_num() will not return a correct value.
 */

#define FPN_MEMPOOL_HEADER_COOKIE1  0xbadbadbadadd2e55ULL /**< Header cookie. */
#define FPN_MEMPOOL_HEADER_COOKIE2  0xf2eef2eedadd2e55ULL /**< Header cookie. */
#define FPN_MEMPOOL_TRAILER_COOKIE  0xadd2e55badbadbadULL /**< Trailer cookie.*/

#ifdef FPN_MEMPOOL_DEBUG
/**
 * A structure that stores the mempool statistics (per-core).
 */
struct fpn_mempool_debug_stats {
	uint64_t put_bulk;         /**< Number of puts. */
	uint64_t put_objs;         /**< Number of objects successfully put. */
	uint64_t get_success_bulk; /**< Successful allocation number. */
	uint64_t get_success_objs; /**< Objects successfully allocated. */
	uint64_t get_fail_bulk;    /**< Failed allocation number. */
	uint64_t get_fail_objs;    /**< Objects that failed to be allocated. */
} __fpn_cache_aligned;
#endif

#if FPN_MEMPOOL_CACHE_MAX_SIZE > 0
/**
 * A structure that stores a per-core object cache.
 */
struct fpn_mempool_cache {
	unsigned len;
	void *objs[FPN_MEMPOOL_CACHE_MAX_SIZE];
} __fpn_cache_aligned;
#endif /* FPN_MEMPOOL_CACHE_MAX_SIZE > 0 */

#define FPN_MEMPOOL_NAMESIZE 32 /**< Maximum length of a memory pool. */

/**
 * The FPN mempool structure.
 */
struct fpn_mempool {
	FPN_TAILQ_ENTRY(fpn_mempool) next; /**< Next in list. */

	char name[FPN_MEMPOOL_NAMESIZE]; /**< Name of mempool. */
	struct fpn_ring *ring;           /**< Ring to store objects. */
	int flags;                       /**< Flags of the mempool. */
	uint32_t size;                   /**< Size of the mempool. */
	uint32_t bulk_default;           /**< Default bulk count. */
	uint32_t cache_size;             /**< Size of per-core local cache. */

	uint32_t elt_size;               /**< Size of an element. */
	uint32_t header_size;            /**< Size of header (before elt). */
	uint32_t trailer_size;           /**< Size of trailer (after elt). */

	unsigned private_data_size;      /**< Size of private data. */

	void *objtable;                  /**< pointer to objects table */

#if FPN_MEMPOOL_CACHE_MAX_SIZE > 0
	/** Per-core local cache. */
	struct fpn_mempool_cache local_cache[FPN_MAX_CORES];
#endif

#ifdef FPN_MEMPOOL_DEBUG
	/** Per-core statistics. */
	struct fpn_mempool_debug_stats stats[FPN_MAX_CORES];
#endif
} __fpn_cache_aligned;

#define FPN_MEMPOOL_F_NO_CACHE_ALIGN 0x0001 /**< Do not align objs on cache lines.*/
#define FPN_MEMPOOL_F_SP_PUT         0x0002 /**< Default put is "single-producer".*/
#define FPN_MEMPOOL_F_SC_GET         0x0004 /**< Default get is "single-consumer".*/

#define FPN_MEMPOOL_OUT_OF_MEM "No more huge pages left for pastpath initialization"

/**
 * An object constructor callback function for mempool.
 *
 * Arguments are the mempool, the opaque pointer given by the user in
 * fpn_mempool_create(), the pointer to the element and the index of
 * the element in the pool.
 */
typedef void (fpn_mempool_obj_ctor_t)(struct fpn_mempool *, void *,
				      void *, unsigned);

/**
 * A mempool constructor callback function.
 *
 * Arguments are the mempool and the opaque pointer given by the user in
 * fpn_mempool_create().
 */
typedef void (fpn_mempool_ctor_t)(struct fpn_mempool *, void *);

/**
 * Get a pointer to a mempool pointer in the object header.
 * @param obj
 *   Pointer to object.
 * @return
 *   The pointer to the mempool from which the object was allocated.
 */
static inline struct fpn_mempool **__fpn_mempool_from_obj(const void *obj)
{
	struct fpn_mempool **mpp;
	unsigned off;

	off = sizeof(struct fpn_mempool *);
#ifdef FPN_MEMPOOL_DEBUG
	off += sizeof(uint64_t);
#endif
	mpp = (struct fpn_mempool **)((const char *)obj - off);
	return mpp;
}

/**
 * Return a pointer to the mempool owning this object.
 *
 * @param obj
 *   An object that is owned by a pool. If this is not the case,
 *   the behavior is undefined.
 * @return
 *   A pointer to the mempool structure.
 */
static inline struct fpn_mempool *fpn_mempool_from_obj(const void *obj)
{
	struct fpn_mempool * const *mpp;
	mpp = __fpn_mempool_from_obj(obj);
	return *mpp;
}

/**
 * Initialize a mempool object, from user pointers
 *
 * This function does not allocate memory as it is done by
 * fpn_mempool_create(). Therefore, the user has to give the pointers
 * to the objects table, the ring, and the mempool structure.
 *
 * @param mp
 *   The pointer to the mempool structure, followed by at least
 *   'private_data_size' free bytes. The address must be cache-aligned.
 * @param r
 *   The pointer to the ring structure that will be used by the mempool to
 *   store object pointers. The memory should be at least equal to
 *   fpn_mempool_get_ring_size(), called with same 'n' and 'flags'
 *   arguments. The address must be cache-aligned.
 * @param objtable
 *   The pointer to memory area that will store objects. It should be at
 *   least equal to fpn_mempool_get_objtab_size(), called with same
 *   'flags', 'elt_size' and 'n' arguments. The address must be cache-aligned.
 * @param name
 *   The name of the mempool.
 * @param n
 *   The number of elements in the mempool. The optimum size (in terms of
 *   memory usage) for a mempool is when n is a power of two minus one:
 *   n = (2^q - 1).
 * @param elt_size
 *   The size of each element.
 * @param cache_size
 *   If cache_size is non-zero, the fpn_mempool library will try to
 *   limit the accesses to the common lockless pool, by maintaining a
 *   per-core object cache. This argument must be lower or equal to
 *   CONFIG_FPN_MEMPOOL_CACHE_MAX_SIZE. It is advised to choose
 *   cache_size to have "n modulo cache_size == 0": if this is
 *   not the case, some elements will always stay in the pool and will
 *   never be used. The access to the per-core table is of course
 *   faster than the multi-producer/consumer pool. The cache can be
 *   disabled if the cache_size argument is set to 0; it can be useful to
 *   avoid loosing objects in cache. Note that even if not used, the
 *   memory space for cache is always reserved in a mempool structure,
 *   except if CONFIG_FPN_MEMPOOL_CACHE_MAX_SIZE is set to 0.
 * @param private_data_size
 *   The size of the private data appended after the mempool
 *   structure.
 * @param mp_init
 *   A function pointer that is called for initialization of the pool,
 *   before object initialization. The user can initialize the private
 *   data in this function if needed. This parameter can be NULL if
 *   not needed.
 * @param mp_init_arg
 *   An opaque pointer to data that can be used in the mempool
 *   constructor function.
 * @param obj_init
 *   A function pointer that is called for each object at
 *   initialization of the pool. The user can set some meta data in
 *   objects if needed. This parameter can be NULL if not needed.
 *   The obj_init() function takes the mempool pointer, the init_arg,
 *   the object pointer and the object number as parameters.
 * @param obj_init_arg
 *   An opaque pointer to data that can be used as an argument for
 *   each call to the object constructor function.
 * @param flags
 *   The *flags* arguments is an OR of following flags:
 *   - FPN_MEMPOOL_F_NO_CACHE_ALIGN: By default, the returned objects are
 *     cache-aligned. This flag removes this constraint, and no
 *     padding will be present between objects.
 *   - FPN_MEMPOOL_F_SP_PUT: If this flag is set, the default behavior
 *     when using fpn_mempool_put() or fpn_mempool_put_bulk() is
 *     "single-producer". Otherwise, it is "multi-producers".
 *   - FPN_MEMPOOL_F_SC_GET: If this flag is set, the default behavior
 *     when using fpn_mempool_get() or fpn_mempool_get_bulk() is
 *     "single-consumer". Otherwise, it is "multi-consumers".
 * @return
 *   - The pointer to the new allocated mempool, on success.
 *   - NULL (not enough memory), on error.
 */
int
fpn_mempool_init(struct fpn_mempool *mp, struct fpn_ring *r,
		 void *objtable, const char *name, unsigned n,
		 unsigned elt_size, unsigned cache_size,
		 unsigned private_data_size, fpn_mempool_ctor_t *mp_init,
		 void *mp_init_arg, fpn_mempool_obj_ctor_t *obj_init,
		 void *obj_init_arg, unsigned flags);

/**
 * Initialize a mempool object.
 *
 * This function does not allocate memory and it assumes that
 * mempool() is a linear memory large enough to map the ring.
 * See fpn_mempool_init() for parameters and returned value.
 */
int
fpn_mempool_init_linear(struct fpn_mempool *mp, const char *name, unsigned n,
			unsigned elt_size, unsigned cache_size,
			unsigned private_data_size, fpn_mempool_ctor_t *mp_init,
			void *mp_init_arg, fpn_mempool_obj_ctor_t *obj_init,
			void *obj_init_arg, unsigned flags);
/**
 * Creates a new mempool named *name* in memory.
 *
 * This function uses ``fpn_malloc()`` to allocate memory. The
 * pool contains n elements of elt_size. Its size is set to n. By
 * default, bulk_default_count (the default number of elements to
 * get/put in the pool) is set to 1. @see fpn_mempool_set_bulk_count()
 * to modify this valule.
 *
 * @param name
 *   The name of the mempool.
 * @param n
 *   The number of elements in the mempool. The optimum size (in terms of
 *   memory usage) for a mempool is when n is a power of two minus one:
 *   n = (2^q - 1).
 * @param elt_size
 *   The size of each element.
 * @param cache_size
 *   size of per-core cache, refer to fpn_mempool_init() for details
 * @param private_data_size
 *   The size of the private data appended after the mempool
 *   structure.
 * @param mp_init
 *   A function pointer that is called for initialization of the pool,
 *   before object initialization. The user can initialize the private
 *   data in this function if needed. This parameter can be NULL if
 *   not needed.
 * @param mp_init_arg
 *   An opaque pointer to data that can be used in the mempool
 *   constructor function.
 * @param obj_init
 *   A function pointer that is called for each object at
 *   initialization of the pool. The user can set some meta data in
 *   objects if needed. This parameter can be NULL if not needed.
 *   The obj_init() function takes the mempool pointer, the init_arg,
 *   the object pointer and the object number as parameters.
 * @param obj_init_arg
 *   An opaque pointer to data that can be used as an argument for
 *   each call to the object constructor function.
 * @param flags
 *   Mempool flags, refer to fpn_mempool_init() for details
 * @return
 *   - The pointer to the new allocated mempool, on success.
 *   - NULL (not enough memory), on error.
 */
struct fpn_mempool *
fpn_mempool_create(const char *name, unsigned n, unsigned elt_size,
		   unsigned cache_size, unsigned private_data_size,
		   fpn_mempool_ctor_t *mp_init, void *mp_init_arg,
		   fpn_mempool_obj_ctor_t *obj_init, void *obj_init_arg,
		   unsigned flags);

/**
 * Get the size of the object table depending on flags, element size and count
 *
 * This function can be used by a user that wants to allocate the memory
 * to store objects by itself (and calling fpn_mempool_init() instead of
 * fpn_mempool_create().
 *
 * @param flags
 *   Mempool flags, as specified in fpn_mempool_init() or fpn_mempool_create()
 * @param elt_size
 *   The size of each element.
 * @param n
 *   The number of elements in the mempool.
 * @return
 *   The size of the object table
 */
size_t
fpn_mempool_get_objtab_size(unsigned flags, unsigned elt_size, unsigned n);

/**
 * Get the size of the internal ring depending on mempool object count
 *
 * This function can be used by a user that wants to allocate the memory
 * to store objects by itself (and calling fpn_mempool_init() instead of
 * fpn_mempool_create().
 *
 * @param n
 *   The number of elements in the mempool.
 * @return
 *   The size of the object table
 */
size_t
fpn_mempool_get_ring_size( unsigned n);

/**
 * Get the size required by a mempool
 *
 * This function can be used by a user who wants to allocate the memory
 * to store objects by itself (and calling fpn_mempool_init_linear() instead
 * of fpn_mempool_create().
 *
 * @param flags
 *   Mempool flags, as specified in fpn_mempool_init() or fpn_mempool_create()
 * @param elt_size
 *   The size of each element.
 * @param n
 *   The number of elements in the mempool.
 * @return
 *   The size of the object table
 */
size_t
fpn_mempool_size(unsigned n, unsigned elt_size, unsigned private_data_size,
		unsigned flags);


/**
 * Set the default bulk count for put/get.
 *
 * The *count* parameter is the default number of bulk elements to
 * get/put when using ``fpn_mempool_*_{en,de}queue_bulk()``. It must
 * be greater than 0 and less than half of the mempool size.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param count
 *   A new water mark value.
 * @return
 *   - 0: Success; default_bulk_count changed.
 *   - -EINVAL: Invalid count value.
 */
static inline int
fpn_mempool_set_bulk_count(struct fpn_mempool *mp, unsigned count)
{
	if (unlikely(count == 0 || count >= mp->size))
		return -EINVAL;

	mp->bulk_default = count;
	return 0;
}

/**
 * Get the default bulk count for put/get.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @return
 *   The default bulk count for enqueue/dequeue.
 */
static inline unsigned
fpn_mempool_get_bulk_count(struct fpn_mempool *mp)
{
	return mp->bulk_default;
}

/**
 * Dump the status of the mempool to the console.
 *
 * @param mp
 *   A pointer to the mempool structure.
 */
void fpn_mempool_dump(const struct fpn_mempool *mp);

/**
 * Dump the summary of mempool status to the console.
 *
 * @param mp
 *   A pointer to the mempool structure.
 */
void fpn_mempool_dump_summary(const struct fpn_mempool *mp);


/**
 * Put several objects back in the mempool (multi-producers safe).
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to add in the mempool from the obj_table.
 */
void
fpn_mempool_mp_put_bulk(struct fpn_mempool *mp, void * const *obj_table,
			unsigned n);

/**
 * Put several objects back in the mempool (NOT multi-producers safe).
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to add in the mempool from obj_table.
 */
void
fpn_mempool_sp_put_bulk(struct fpn_mempool *mp, void * const *obj_table,
			unsigned n);

/**
 * Put several objects back in the mempool.
 *
 * This function calls the multi-producer or the single-producer
 * version depending on the default behavior that was specified at
 * mempool creation time (see flags).
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to add in the mempool from obj_table.
 */
void
fpn_mempool_put_bulk(struct fpn_mempool *mp, void * const *obj_table,
		     unsigned n);

/**
 * Put one object in the mempool (multi-producers safe).
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj
 *   A pointer to the object to be added.
 */
void
fpn_mempool_mp_put(struct fpn_mempool *mp, void *obj);

/**
 * Put one object back in the mempool (NOT multi-producers safe).
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj
 *   A pointer to the object to be added.
 */
void
fpn_mempool_sp_put(struct fpn_mempool *mp, void *obj);

/**
 * Put one object back in the mempool.
 *
 * This function calls the multi-producer or the single-producer
 * version depending on the default behavior that was specified at
 * mempool creation time (see flags).
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj
 *   A pointer to the object to be added.
 */
void
fpn_mempool_put(struct fpn_mempool *mp, void *obj);


/**
 * Get several objects from the mempool (multi-consumers safe).
 *
 * If cache is enabled, objects will be retrieved first from cache,
 * subsequently from the common pool. Note that it can return -ENOENT when
 * the local cache and common pool are empty, even if cache from other
 * cores are full.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param n
 *   The number of objects to get from mempool to obj_table.
 * @return
 *   - 0: Success; objects got.
 *   - -ENOENT: Not enough entries in the mempool to put; no object is retrieved.
 */
int
fpn_mempool_mc_get_bulk(struct fpn_mempool *mp, void **obj_table, unsigned n);

/**
 * Get several objects from the mempool (NOT multi-consumers safe).
 *
 * If cache is enabled, objects will be retrieved first from cache,
 * subsequently from the common pool. Note that it can return -ENOENT when
 * the local cache and common pool are empty, even if cache from other
 * cores are full.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param n
 *   The number of objects to get from the mempool to obj_table.
 * @return
 *   - 0: Success; objects got.
 *   - -ENOENT: Not enough entries in the mempool to put; no object is
 *     retrieved.
 */
int
fpn_mempool_sc_get_bulk(struct fpn_mempool *mp, void **obj_table, unsigned n);

/**
 * Get several objects from the mempool.
 *
 * This function calls the multi-consumers or the single-consumer
 * version, depending on the default behaviour that was specified at
 * mempool creation time (see flags).
 *
 * If cache is enabled, objects will be retrieved first from cache,
 * subsequently from the common pool. Note that it can return -ENOENT when
 * the local cache and common pool are empty, even if cache from other
 * cores are full.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param n
 *   The number of objects to get from the mempool to obj_table.
 * @return
 *   - 0: Success; objects got.
 *   - -ENOENT: Not enough entries in the mempool to put; no object is retrieved.
 */
int
fpn_mempool_get_bulk(struct fpn_mempool *mp, void **obj_table, unsigned n);

/**
 * Get one object from the mempool (multi-consumers safe).
 *
 * If cache is enabled, objects will be retrieved first from cache,
 * subsequently from the common pool. Note that it can return -ENOENT when
 * the local cache and common pool are empty, even if cache from other
 * cores are full.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_p
 *   A pointer to a void * pointer (object) that will be filled.
 * @return
 *   - 0: Success; objects got.
 *   - -ENOENT: Not enough entries in the mempool to put; no object is retrieved.
 */
int
fpn_mempool_mc_get(struct fpn_mempool *mp, void **obj_p);

/**
 * Get one object from the mempool (NOT multi-consumers safe).
 *
 * If cache is enabled, objects will be retrieved first from cache,
 * subsequently from the common pool. Note that it can return -ENOENT when
 * the local cache and common pool are empty, even if cache from other
 * cores are full.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_p
 *   A pointer to a void * pointer (object) that will be filled.
 * @return
 *   - 0: Success; objects got.
 *   - -ENOENT: Not enough entries in the mempool to put; no object is retrieved.
 */
int
fpn_mempool_sc_get(struct fpn_mempool *mp, void **obj_p);

/**
 * Get one object from the mempool.
 *
 * This function calls the multi-consumers or the single-consumer
 * version, depending on the default behavior that was specified at
 * mempool creation (see flags).
 *
 * If cache is enabled, objects will be retrieved first from cache,
 * subsequently from the common pool. Note that it can return -ENOENT when
 * the local cache and common pool are empty, even if cache from other
 * cores are full.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_p
 *   A pointer to a void * pointer (object) that will be filled.
 * @return
 *   - 0: Success; object got.
 *   - -ENOENT: Not enough entries in the mempool to put; no object is
 *     retrieved.
 */
int
fpn_mempool_get(struct fpn_mempool *mp, void **obj_p);

/**
 * Return the number of entries in the mempool.
 *
 * When cache is enabled, this function has to browse the length of
 * all cores, so it should not be used in a data path, but only for
 * debug purposes.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @return
 *   The number of entries in the mempool.
 */
unsigned fpn_mempool_count(const struct fpn_mempool *mp);

/**
 * Return the number of free entries in the mempool.
 *
 * When cache is enabled, this function has to browse the length of
 * all cores, so it should not be used in a data path, but only for
 * debug purposes.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @return
 *   The number of free entries in the mempool.
 */
static inline unsigned
fpn_mempool_free_count(const struct fpn_mempool *mp)
{
	return mp->size - fpn_mempool_count(mp);
}

/**
 * Test if the mempool is full.
 *
 * When cache is enabled, this function has to browse the length of all
 * cores, so it should not be used in a data path, but only for debug
 * purposes.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @return
 *   - 1: The mempool is full.
 *   - 0: The mempool is not full.
 */
static inline int
fpn_mempool_full(const struct fpn_mempool *mp)
{
	return !!(fpn_mempool_count(mp) == mp->size);
}

/**
 * Test if the mempool is empty.
 *
 * When cache is enabled, this function has to browse the length of all
 * cores, so it should not be used in a data path, but only for debug
 * purposes.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @return
 *   - 1: The mempool is empty.
 *   - 0: The mempool is not empty.
 */
static inline int
fpn_mempool_empty(const struct fpn_mempool *mp)
{
	return !!(fpn_mempool_count(mp) == 0);
}

/**
 * Check the consistency of mempool objects.
 *
 * Verify the coherency of fields in the mempool structure. Also check
 * that the cookies of mempool objects (even the ones that are not
 * present in pool) have a correct value. If not, a panic will occur.
 *
 * @param mp
 *   A pointer to the mempool structure.
 */
void fpn_mempool_audit(const struct fpn_mempool *mp);

/**
 * Return a pointer to the private data in an mempool structure.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @return
 *   A pointer to the private data.
 */
static inline void *fpn_mempool_get_priv(struct fpn_mempool *mp)
{
	return (char *)mp + sizeof(struct fpn_mempool);
}

/**
 * List all mempools on the console
 */
void fpn_mempool_list(void);

/**
 * Dump the status of all mempools on the console
 */
void fpn_mempool_list_dump(void);

/**
 * Search a mempool from its name
 *
 * @param name
 *   The name of the mempool.
 * @return
 *   The pointer to the mempool matching the name, or NULL if not found.
 */
struct fpn_mempool *fpn_mempool_lookup(const char *name);

/**
 * Returns whether the object address belongs to the specified mempool.
 *
 * This function checks that the address is between the beginning and
 * the end of the area where the pool objects are stored. It also
 * verify that the address points to the beginning of an object.
 * Warning: does not indicate if the object is present in the pool.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj
 *   A pointer to the object.
 * @return
 *    TRUE if the object belongs to the pool, FALSE otherwise.
 */
int
fpn_mempool_object_is_in_pool(struct fpn_mempool *mp, void *obj);

#endif /* _FPN_MEMPOOL_H_ */
