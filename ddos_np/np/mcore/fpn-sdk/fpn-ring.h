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

/*
 * Derived from FreeBSD's bufring.h
 *
 **************************************************************************
 *
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. The name of Kip Macy nor the names of other
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ***************************************************************************/

#ifndef _FPN_RING_H_
#define _FPN_RING_H_

/**
 * @file
 * FPN Ring
 *
 * The Ring Manager is a fixed-size queue, implemented as a table of
 * pointers. Head and tail pointers are modified atomically, allowing
 * concurrent access to it. It has the following features:
 *
 * - FIFO (First In First Out)
 * - Maximum size is fixed; the pointers are stored in a table.
 * - Lockless implementation.
 * - Multi- or single-consumer dequeue.
 * - Multi- or single-producer enqueue.
 * - Bulk dequeue.
 * - Bulk enqueue.
 *
 * Note: the ring implementation is not preemptable. A core must not
 * be interrupted by another task that uses the same ring.
 */

#ifdef FPN_RING_DEBUG
/**
 * A structure that stores the ring statistics (per-core).
 */
struct fpn_ring_debug_stats {
	uint64_t enq_success_bulk; /**< Successful enqueues number. */
	uint64_t enq_success_objs; /**< Objects successfully enqueued. */
	uint64_t enq_quota_bulk;   /**< Successful enqueues above watermark. */
	uint64_t enq_quota_objs;   /**< Objects enqueued above watermark. */
	uint64_t enq_fail_bulk;    /**< Failed enqueues number. */
	uint64_t enq_fail_objs;    /**< Objects that failed to be enqueued. */
	uint64_t deq_success_bulk; /**< Successful dequeues number. */
	uint64_t deq_success_objs; /**< Objects successfully dequeued. */
	uint64_t deq_fail_bulk;    /**< Failed dequeues number. */
	uint64_t deq_fail_objs;    /**< Objects that failed to be dequeued. */
} __fpn_cache_aligned;
#endif

#define FPN_RING_NAMESIZE 32 /**< The maximum length of a ring name. */

/**
 * An FPN ring structure.
 *
 * The producer and the consumer have a head and a tail index. The particularity
 * of these index is that they are not between 0 and size(ring). These indexes
 * are between 0 and 2^32, and we mask their value when we access the ring[]
 * field. Thanks to this assumption, we can do subtractions between 2 index
 * values in a modulo-32bit base: that's why the overflow of the indexes is not
 * a problem.
 */
struct fpn_ring {
	FPN_TAILQ_ENTRY(fpn_ring) next;      /**< Next in list. */

	char name[FPN_RING_NAMESIZE];    /**< Name of the ring. */
	void *opaque;                    /**< An opaque pointer for the user */

	/* producer status */
	struct {
		volatile uint32_t bulk_default; /**< Default bulk count. */
		uint32_t watermark;      /**< Maximum items before EDQUOT. */
		uint32_t sp_enqueue;     /**< True, if single producer. */
		uint32_t size;           /**< Size of ring. */
		uint32_t mask;           /**< Mask (size-1) of ring. */
		volatile uint32_t head;  /**< Producer head. */
		volatile uint32_t tail;  /**< Producer tail. */
	} prod __fpn_cache_aligned; /**< Ring producer status. */

	/* consumer status */
	struct {
		volatile uint32_t bulk_default; /**< Default bulk count. */
		uint32_t sc_dequeue;     /**< True, if single consumer. */
		uint32_t size;           /**< Size of the ring. */
		uint32_t mask;           /**< Mask (size-1) of ring. */
		volatile uint32_t head;  /**< Consumer head. */
		volatile uint32_t tail;  /**< Consumer tail. */
	} cons __fpn_cache_aligned; /**< Ring consumer status. */


#ifdef FPN_RING_DEBUG
	struct fpn_ring_debug_stats stats[FPN_MAX_CORES];
#endif

	void *ring[0]; /**< Memory space of ring starts here. */
};

#define FPN_RING_F_SP_ENQ 0x0001 /**< default enqueue is "single-producer". */
#define FPN_RING_F_SC_DEQ 0x0002 /**< default dequeue is "single-consumer". */

/**
 * Initialize a ring object
 *
 * @param r
 *   The empty ring structure to initialize. The ring structure must
 *   point to a large-enough memory area (it should be followed by
 *   enough empty data to store the objects pointers). The pointer must
 *   be cache-aligned. To get the minimum size of memomry to allocate,
 *   use fpn_ring_getsize(). Refer to fpn_ring_create() to get an
 *   example.
 * @param name
 *   The name of the ring.
 * @param count
 *   The size of the ring (must be a power of 2).
 * @param flags
 *   An OR of the following:
 *    - FPN_RING_F_SP_ENQ: If this flag is set, the default behavior when
 *      using ``fpn_ring_enqueue()`` or ``fpn_ring_enqueue_bulk()``
 *      is "single-producer". Otherwise, it is "multi-producers".
 *    - FPN_RING_F_SC_DEQ: If this flag is set, the default behavior when
 *      using ``fpn_ring_dequeue()`` or ``fpn_ring_dequeue_bulk()``
 *      is "single-consumer". Otherwise, it is "multi-consumers".
 * @return
 *   - 0 on success
 *   - -1 on error (not enough memory or count is not a power of two).
 */
int fpn_ring_init(struct fpn_ring *r, const char *name, unsigned count,
		  unsigned flags);

/**
 * Create a new ring named *name* in memory.
 *
 * This function uses ``fpn_malloc()`` to allocate memory. Its size is
 * set to *count*, which must be a power of two. Water marking is
 * disabled by default. The default bulk count is initialized to 1.
 * Note that the real usable ring size is *count-1* instead of
 * *count*.
 *
 * @param name
 *   The name of the ring.
 * @param count
 *   The size of the ring (must be a power of 2).
 * @param flags
 *   An OR of the following:
 *    - FPN_RING_F_SP_ENQ: If this flag is set, the default behavior when
 *      using ``fpn_ring_enqueue()`` or ``fpn_ring_enqueue_bulk()``
 *      is "single-producer". Otherwise, it is "multi-producers".
 *    - FPN_RING_F_SC_DEQ: If this flag is set, the default behavior when
 *      using ``fpn_ring_dequeue()`` or ``fpn_ring_dequeue_bulk()``
 *      is "single-consumer". Otherwise, it is "multi-consumers".
 * @return
 *   - On success, the pointer to the new allocated ring.
 *   - NULL on error (not enough memory or count is not a power of two).
 */
struct fpn_ring *fpn_ring_create(const char *name, unsigned count,
				 unsigned flags);

/**
 * Set user-opaque pointer
 *
 * @param r
 *   A pointer to the ring structure.
 * @param opaque
 *   The opaque pointer to be saved in the ring structure
 */
static inline void fpn_ring_set_opaque(struct fpn_ring *r, void *opaque)
{
	r->opaque = opaque;
}

/**
 * Get user-opaque pointer
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The opaque pointer previously saved in the ring structure
 */
static inline void *fpn_ring_get_opaque(struct fpn_ring *r)
{
	return r->opaque;
}

/**
 * Calculate size of ring depending on the number of objects
 *
 * @param count
 *   The size of the ring (must be a power of 2).
 * @return
 *   The size of the ring in bytes (rounded to a cache line size)
 */
static inline size_t fpn_ring_getsize(unsigned count)
{
	unsigned sz;
	sz = count * sizeof(void *) + sizeof(struct fpn_ring);
	sz = (sz + FPN_CACHELINE_MASK) & (~FPN_CACHELINE_MASK);
	return sz;
}

/**
 * Set the default bulk count for enqueue/dequeue.
 *
 * The parameter *count* is the default number of bulk elements to
 * get/put when using ``fpn_ring_*_{en,de}queue_bulk()``. It must be
 * greater than 0 and less than half of the ring size.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param count
 *   A new water mark value.
 * @return
 *   - 0: Success; default_bulk_count changed.
 *   - -EINVAL: Invalid count value.
 */
static inline int
fpn_ring_set_bulk_count(struct fpn_ring *r, unsigned count)
{
	if (unlikely(count == 0 || count >= r->prod.size))
		return -EINVAL;

	r->prod.bulk_default = r->cons.bulk_default = count;
	return 0;
}

/**
 * Get the default bulk count for enqueue/dequeue.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The default bulk count for enqueue/dequeue.
 */
static inline unsigned
fpn_ring_get_bulk_count(struct fpn_ring *r)
{
	return r->prod.bulk_default;
}

/**
 * Set the default behaviour for enqueue (multi or single producers).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param sp
 *   A boolean value (1 to enable single-producer only, 0 to disable it)
 */
static inline void
fpn_ring_set_sp_enqueue(struct fpn_ring *r, int sp)
{
	r->prod.sp_enqueue = sp;
}

/**
 * Get the default behaviour for enqueue (multi or single producers).
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   1 if single-producer only, 0 if multi-producers enabled
 */
static inline int
fpn_ring_get_sp_enqueue(struct fpn_ring *r)
{
	return r->prod.sp_enqueue;
}

/**
 * Set the default behaviour for dequeue (multi or single consumers).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param sc
 *   A boolean value (1 to enable single-consumer only, 0 to disable it)
 */
static inline void
fpn_ring_set_sc_dequeue(struct fpn_ring *r, int sc)
{
	r->cons.sc_dequeue = sc;
}

/**
 * Get the default behaviour for dequeue (multi or single consumers).
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   1 if single-consumer only, 0 if multi-consumers enabled
 */
static inline int
fpn_ring_get_sc_dequeue(struct fpn_ring *r)
{
	return r->cons.sc_dequeue;
}

/**
 * Change the high water mark.
 *
 * If *count* is 0, water marking is disabled. Otherwise, it is set to the
 * *count* value. The *count* value must be greater than 0 and less
 * than the ring size.
 *
 * This function can be called at any time (not necessarilly at
 * initialization).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param count
 *   The new water mark value.
 * @return
 *   - 0: Success; water mark changed.
 *   - -EINVAL: Invalid water mark value.
 */
int fpn_ring_set_water_mark(struct fpn_ring *r, unsigned count);

/**
 * Dump the status of the ring to the console.
 *
 * @param r
 *   A pointer to the ring structure.
 */
void fpn_ring_dump(const struct fpn_ring *r);

/**
 * Enqueue several objects on a ring.
 *
 * This function calls the multi-producer or the single-producer
 * version depending on the default behavior that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @return
 *   - 0: Success; objects enqueued.
 *   - -EDQUOT: Quota exceeded. The objects have been enqueued, but the
 *     high water mark is exceeded.
 *   - -ENOBUFS: Not enough room in the ring to enqueue; no object is enqueued.
 */
int
fpn_ring_enqueue_bulk(struct fpn_ring *r, void * const *obj_table,
		      unsigned n);

/**
 * Enqueue several objects on the ring (multi-producers safe).
 *
 * This function uses a "compare and set" instruction to move the
 * producer index atomically.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to add in the ring from the obj_table. The
 *   value must be strictly positive.
 * @return
 *   - 0: Success; objects enqueue.
 *   - -EDQUOT: Quota exceeded. The objects have been enqueued, but the
 *     high water mark is exceeded.
 *   - -ENOBUFS: Not enough room in the ring to enqueue, no object is enqueued.
 */
int
fpn_ring_mp_enqueue_bulk(struct fpn_ring *r, void * const *obj_table,
			 unsigned n);

/**
 * Enqueue several objects on a ring (NOT multi-producers safe).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to add in the ring from the obj_table. The
 *   value must be strictly positive.
 * @return
 *   - 0: Success; objects enqueued.
 *   - -EDQUOT: Quota exceeded. The objects have been enqueued, but the
 *     high water mark is exceeded.
 *   - -ENOBUFS: Not enough room in the ring to enqueue; no object is enqueued.
 */
int
fpn_ring_sp_enqueue_bulk(struct fpn_ring *r, void * const *obj_table,
			 unsigned n);

/**
 * Enqueue one object on a ring (multi-producers safe).
 *
 * This function uses a "compare and set" instruction to move the
 * producer index atomically.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj
 *   A pointer to the object to be added.
 * @return
 *   - 0: Success; objects enqueued.
 *   - -EDQUOT: Quota exceeded. The objects have been enqueued, but the
 *     high water mark is exceeded.
 *   - -ENOBUFS: Not enough room in the ring to enqueue; no object is enqueued.
 */
int
fpn_ring_mp_enqueue(struct fpn_ring *r, void *obj);

/**
 * Enqueue one object on a ring (NOT multi-producers safe).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj
 *   A pointer to the object to be added.
 * @return
 *   - 0: Success; objects enqueued.
 *   - -EDQUOT: Quota exceeded. The objects have been enqueued, but the
 *     high water mark is exceeded.
 *   - -ENOBUFS: Not enough room in the ring to enqueue; no object is enqueued.
 */
int
fpn_ring_sp_enqueue(struct fpn_ring *r, void *obj);

/**
 * Enqueue one object on a ring.
 *
 * This function calls the multi-producer or the single-producer
 * version, depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj
 *   A pointer to the object to be added.
 * @return
 *   - 0: Success; objects enqueued.
 *   - -EDQUOT: Quota exceeded. The objects have been enqueued, but the
 *     high water mark is exceeded.
 *   - -ENOBUFS: Not enough room in the ring to enqueue; no object is enqueued.
 */
int
fpn_ring_enqueue(struct fpn_ring *r, void *obj);

/**
 * Dequeue several objects from a ring (multi-consumers safe).
 *
 * This function uses a "compare and set" instruction to move the
 * consumer index atomically.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param n
 *   The number of objects to dequeue from the ring to the obj_table,
 *   must be strictly positive
 * @return
 *   - 0: Success; objects dequeued.
 *   - -ENOENT: Not enough entries in the ring to dequeue; no object is
 *     dequeued.
 */
int
fpn_ring_mc_dequeue_bulk(struct fpn_ring *r, void **obj_table, unsigned n);

/**
 * Dequeue several objects from a ring (NOT multi-consumers safe).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param n
 *   The number of objects to dequeue from the ring to the obj_table,
 *   must be strictly positive.
 * @return
 *   - 0: Success; objects dequeued.
 *   - -ENOENT: Not enough entries in the ring to dequeue; no object is
 *     dequeued.
 */
int
fpn_ring_sc_dequeue_bulk(struct fpn_ring *r, void **obj_table, unsigned n);

/**
 * Dequeue several objects from a ring.
 *
 * This function calls the multi-consumers or the single-consumer
 * version, depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param n
 *   The number of objects to dequeue from the ring to the obj_table.
 * @return
 *   - 0: Success; objects dequeued.
 *   - -ENOENT: Not enough entries in the ring to dequeue, no object is
 *     dequeued.
 */
int
fpn_ring_dequeue_bulk(struct fpn_ring *r, void **obj_table, unsigned n);

/**
 * Dequeue one object from a ring (multi-consumers safe).
 *
 * This function uses a "compare and set" instruction to move the
 * consumer index atomically.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_p
 *   A pointer to a void * pointer (object) that will be filled.
 * @return
 *   - 0: Success; objects dequeued.
 *   - -ENOENT: Not enough entries in the ring to dequeue; no object is
 *     dequeued.
 */
int
fpn_ring_mc_dequeue(struct fpn_ring *r, void **obj_p);

/**
 * Dequeue one object from a ring (NOT multi-consumers safe).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_p
 *   A pointer to a void * pointer (object) that will be filled.
 * @return
 *   - 0: Success; objects dequeued.
 *   - -ENOENT: Not enough entries in the ring to dequeue, no object is
 *     dequeued.
 */
int
fpn_ring_sc_dequeue(struct fpn_ring *r, void **obj_p);

/**
 * Dequeue one object from a ring.
 *
 * This function calls the multi-consumers or the single-consumer
 * version depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_p
 *   A pointer to a void * pointer (object) that will be filled.
 * @return
 *   - 0: Success, objects dequeued.
 *   - -ENOENT: Not enough entries in the ring to dequeue, no object is
 *     dequeued.
 */
int
fpn_ring_dequeue(struct fpn_ring *r, void **obj_p);

/**
 * Test if a ring is full.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   - 1: The ring is full.
 *   - 0: The ring is not full.
 */
static inline int
fpn_ring_full(const struct fpn_ring *r)
{
	uint32_t prod_tail_plus_1 = (r->prod.tail + 1) & r->prod.mask;
	uint32_t cons_tail = r->cons.tail;
	return !!(prod_tail_plus_1 == cons_tail);
}

/**
 * Test if a ring is empty.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   - 1: The ring is empty.
 *   - 0: The ring is not empty.
 */
static inline int
fpn_ring_empty(const struct fpn_ring *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;
	return !!(cons_tail == prod_tail);
}

/**
 * Return the number of entries in a ring.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The number of entries in the ring.
 */
static inline unsigned
fpn_ring_count(const struct fpn_ring *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;
	return ((prod_tail - cons_tail) & r->prod.mask);
}

/**
 * Return the number of free entries in a ring.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The number of free entries in the ring.
 */
static inline unsigned
fpn_ring_free_count(const struct fpn_ring *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;
	return ((cons_tail - prod_tail - 1) & r->prod.mask);
}

/**
 * Peek one object from a ring (not dequeued) (NOT multi-consumers safe).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_p
 *   A pointer to a void * pointer (object) that will be filled.
 * @return
 *   - 0: Success; objects dequeued.
 *   - -ENOENT: Not enough entries in the ring to peek
 */
static inline int
fpn_ring_sc_peek(struct fpn_ring *r, void **obj_p)
{
	if (unlikely(fpn_ring_empty(r)))
		return -ENOENT;
	*obj_p = r->ring[r->cons.head & r->prod.mask];
	return 0;
}

/**
 * Dump the status of all rings on the console
 */
void fpn_ring_list_dump(void);

/**
 * Search a ring from its name
 *
 * @param name
 *   The name of the ring.
 * @return
 *   The pointer to the ring matching the name, or NULL if not found.
 */
struct fpn_ring *fpn_ring_lookup(const char *name);

#endif /* _FPN_RING_H_ */
