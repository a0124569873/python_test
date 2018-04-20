/*
 * Copyright(c) 2011 6WIND
 * All rights reserved.
 */

#ifndef _FPN_RINGPOOL_H_
#define _FPN_RINGPOOL_H_

/**
 * @file
 * FPN Ringpool.
 *
 * A ring pool is a pool of rings.
 * The API is just a wrapper over the mempool API
 */

/**
 * Initialize a ringpool object, from user pointers
 *
 * This function does not allocate memory as it is done by
 * fpn_ringpool_create(). Therefore, the user has to give the pointers to the
 * objects table, the ring, and the ringpool structure.
 *
 * @param mp
 *   The pointer to the mempool structure, followed by at least
 *   'private_data_size' free bytes. The address must be cache-aligned.
 * @param r
 *   The pointer to the ring structure that will be used by the ringpool to
 *   store object pointers. The size of memory should be at least equal to
 *   fpn_ring_getsize(), called with same 'n' and '0 as 'flags'
 *   arguments. The address must be cache-aligned.
 * @param objtable
 *   The pointer to memory area that will store objects. It should be at
 *   least equal to fpn_mempool_get_objtab_size(), called with 0 as 'flags',
 *   the result of fpn_ring_getsize() as 'elt_size' and 'n' arguments.
 *   The address must be cache-aligned.
 * @param name
 *   The name of the ringpool.
 * @param n
 *   The number of elements in the ringpool. The optimum size (in terms of
 *   memory usage) for a ringpool is when n is a power of two minus one:
 *   n = (2^q - 1).
 * @param r_n
 *   Number of element in each ring. This number is subject to the
 *   same requirements as the parameter size of a ring, i.e. be a
 *   power of 2. (refer to ring API)
 * @return
 *   - 0 on success
 *   - -1 on error (not enough memory or r_n is not a power of two).
 */
int
fpn_ringpool_init (struct fpn_mempool *mp, struct fpn_ring *r,
		 void *objtable, const char *name, unsigned n,
		 unsigned r_n);

/**
 * Create a new mempool named *name* in memory.
 * This is a pool of unnamed rings
 *
 * This function uses ``fpn_malloc()`` to allocate memory. The
 * pool contains n rings of r_n elements.
 *
 * All operation on pools such as chaining the bulk_default_count
 * can be performed, refer to the mempool API.
 *
 * @param name
 *   The name of the mempool.
 * @param n
 *   The number of elements in the mempool. The optimum size (in terms of
 *   memory usage) for a mempool is when n is a power of two minus one:
 *   n = (2^q - 1).
 * @param r_n
 *   Number of element in each ring. This number is subject to the
 *   same requirements as the parameter size of a ring, i.e. be a
 *   power of 2. (refer to ring API)
 * @return
 *   - The pointer to the new allocated mempool, on success.
 *   - NULL on error (not enough memory or r_n is not a power of two).
 */
struct fpn_mempool *
fpn_ringpool_create (const char *name, unsigned n, unsigned r_n);

/**
 * Link 2 ringpools together.
 *
 * @param first
 *   ringpool whose successor will be set
 * @param next
 *   ringpool st as successor of the first one
 */
void
fpn_ringpool_link(struct fpn_mempool *first, struct fpn_mempool *next);

#endif

