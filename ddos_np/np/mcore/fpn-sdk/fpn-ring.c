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
 * Derived from FreeBSD's bufring.c
 *
 **************************************************************************
 *
 * Copyright (c) 2007,2008 Kip Macy kmacy@freebsd.org
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

#include "fpn.h"
#include "fpn-ring.h"

#define FPN_RING_ERROR(fmt, args...) do {	\
		fpn_printf(fmt "\n", ## args);	\
	} while (0)

FPN_TAILQ_HEAD(fpn_ring_list, fpn_ring);

/* global list of ring (used for debug/dump) */
static FPN_DEFINE_SHARED(struct fpn_ring_list, ring_list) =
	FPN_TAILQ_HEAD_INITIALIZER(ring_list);

/* true if x is a power of 2 */
#define POWEROF2(x) ((((x)-1) & (x)) == 0)

/*
 * When debug is enabled, store ring statistics.
 */
#ifdef FPN_RING_DEBUG
#define __FPN_RING_STAT_ADD(r, name, n) do {		\
		unsigned __core_id = fpn_get_core_num();\
		r->stats[__core_id].name##_objs += n;	\
		r->stats[__core_id].name##_bulk += 1;	\
	} while(0)
#else
#define __FPN_RING_STAT_ADD(r, name, n) do {} while(0)
#endif

/*
 * Enqueue several objects on the ring (multi-producers safe).
 */
static inline int
__fpn_ring_mp_enqueue_bulk(struct fpn_ring *r, void * const *obj_table,
			   unsigned n)
{
	uint32_t prod_head, prod_next;
	uint32_t cons_tail, free_entries;
	int success;
	unsigned i;
	uint32_t mask = r->prod.mask;
	int ret;

	/* move prod.head atomically */
	do {
		prod_head = r->prod.head;
		cons_tail = r->cons.tail;
		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * prod_head > cons_tail). So 'free_entries' is always between 0
		 * and size(ring)-1. */
		free_entries = (mask + cons_tail - prod_head);

		/* check that we have enough room in ring */
		if (unlikely(n > free_entries)) {
			__FPN_RING_STAT_ADD(r, enq_fail, n);
			return -ENOBUFS;
		}

		prod_next = prod_head + n;
		success = fpn_cmpset32(&r->prod.head, prod_head, prod_next);
	} while (unlikely(success == 0));

	/* write entries in ring */
	for (i = 0; likely(i < n); i++)
		r->ring[(prod_head + i) & mask] = obj_table[i];
	fpn_wmb();

	/* return -EDQUOT if we exceed the watermark */
	if (unlikely(((mask + 1) - free_entries + n) > r->prod.watermark)) {
		ret = -EDQUOT;
		__FPN_RING_STAT_ADD(r, enq_quota, n);
	}
	else {
		ret = 0;
		__FPN_RING_STAT_ADD(r, enq_success, n);
	}

	/*
	 * If there are other enqueues in progress that preceeded us,
	 * we need to wait for them to complete
	 */
	while (unlikely(r->prod.tail != prod_head))
		;

	r->prod.tail = prod_next;
	return ret;
}

/*
 * Enqueue several objects on a ring (NOT multi-producers safe).
 */
static inline int
__fpn_ring_sp_enqueue_bulk(struct fpn_ring *r, void * const *obj_table,
			   unsigned n)
{
	uint32_t prod_head, cons_tail;
	uint32_t prod_next, free_entries;
	unsigned i;
	uint32_t mask = r->prod.mask;
	int ret;

	prod_head = r->prod.head;
	cons_tail = r->cons.tail;
	/* The subtraction is done between two unsigned 32bits value
	 * (the result is always modulo 32 bits even if we have
	 * prod_head > cons_tail). So 'free_entries' is always between 0
	 * and size(ring)-1. */
	free_entries = mask + cons_tail - prod_head;

	/* check that we have enough room in ring */
	if (unlikely(n > free_entries)) {
		__FPN_RING_STAT_ADD(r, enq_fail, n);
		return -ENOBUFS;
	}

	prod_next = prod_head + n;
	r->prod.head = prod_next;

	/* write entries in ring */
	for (i = 0; likely(i < n); i++)
		r->ring[(prod_head + i) & mask] = obj_table[i];
	fpn_wmb();

	/* return -EDQUOT if we exceed the watermark */
	if (unlikely(((mask + 1) - free_entries + n) > r->prod.watermark)) {
		ret = -EDQUOT;
		__FPN_RING_STAT_ADD(r, enq_quota, n);
	}
	else {
		ret = 0;
		__FPN_RING_STAT_ADD(r, enq_success, n);
	}

	r->prod.tail = prod_next;
	return ret;
}

/*
 * Enqueue several objects on the ring (multi-producers safe).
 */
int
fpn_ring_mp_enqueue_bulk(struct fpn_ring *r, void * const *obj_table,
			 unsigned n)
{
	return __fpn_ring_mp_enqueue_bulk(r, obj_table, n);
}

/*
 * Enqueue several objects on a ring (NOT multi-producers safe).
 */
int
fpn_ring_sp_enqueue_bulk(struct fpn_ring *r, void * const *obj_table,
			 unsigned n)
{
	return __fpn_ring_sp_enqueue_bulk(r, obj_table, n);
}

/*
 * Enqueue several objects on a ring.
 */
int
fpn_ring_enqueue_bulk(struct fpn_ring *r, void * const *obj_table,
		      unsigned n)
{
	if (r->prod.sp_enqueue)
		return __fpn_ring_sp_enqueue_bulk(r, obj_table, n);
	else
		return __fpn_ring_mp_enqueue_bulk(r, obj_table, n);
}

/*
 * Enqueue one object on a ring (multi-producers safe).
 */
int
fpn_ring_mp_enqueue(struct fpn_ring *r, void *obj)
{
	return __fpn_ring_mp_enqueue_bulk(r, &obj, 1);
}

/*
 * Enqueue one object on a ring (NOT multi-producers safe).
 */
int
fpn_ring_sp_enqueue(struct fpn_ring *r, void *obj)
{
	return __fpn_ring_sp_enqueue_bulk(r, &obj, 1);
}

/*
 * Enqueue one object on a ring.
 */
int
fpn_ring_enqueue(struct fpn_ring *r, void *obj)
{
	if (r->prod.sp_enqueue)
		return __fpn_ring_sp_enqueue_bulk(r, &obj, 1);
	else
		return __fpn_ring_mp_enqueue_bulk(r, &obj, 1);
}

/*
 * Dequeue several objects from a ring (multi-consumers safe).
 */
static inline int
__fpn_ring_mc_dequeue_bulk(struct fpn_ring *r, void **obj_table, unsigned n)
{
	uint32_t cons_head, prod_tail;
	uint32_t cons_next, entries;
	int success;
	unsigned i;
	uint32_t mask = r->prod.mask;

	/* move cons.head atomically */
	do {
		cons_head = r->cons.head;
		prod_tail = r->prod.tail;
		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * cons_head > prod_tail). So 'entries' is always between 0
		 * and size(ring)-1. */
		entries = (prod_tail - cons_head);

		/* check that we have enough entries in ring */
		if (unlikely(n > entries)) {
			__FPN_RING_STAT_ADD(r, deq_fail, n);
			return -ENOENT;
		}

		cons_next = cons_head + n;
		success = fpn_cmpset32(&r->cons.head, cons_head, cons_next);
	} while (unlikely(success == 0));

	/* copy in table */
	fpn_rmb();
	for (i = 0; likely(i < n); i++) {
		obj_table[i] = r->ring[(cons_head + i) & mask];
	}

	/*
	 * If there are other dequeues in progress that preceeded us,
	 * we need to wait for them to complete
	 */
	while (unlikely(r->cons.tail != cons_head))
		;

	__FPN_RING_STAT_ADD(r, deq_success, n);
	r->cons.tail = cons_next;
	return 0;
}

/*
 * Dequeue several objects from a ring (NOT multi-consumers safe).
 */
static inline int
__fpn_ring_sc_dequeue_bulk(struct fpn_ring *r, void **obj_table, unsigned n)
{
	uint32_t cons_head, prod_tail;
	uint32_t cons_next, entries;
	unsigned i;
	uint32_t mask = r->prod.mask;

	cons_head = r->cons.head;
	prod_tail = r->prod.tail;
	/* The subtraction is done between two unsigned 32bits value
	 * (the result is always modulo 32 bits even if we have
	 * cons_head > prod_tail). So 'entries' is always between 0
	 * and size(ring)-1. */
	entries = prod_tail - cons_head;

	/* check that we have enough entries in ring */
	if (unlikely(n > entries)) {
		__FPN_RING_STAT_ADD(r, deq_fail, n);
		return -ENOENT;
	}

	cons_next = cons_head + n;
	r->cons.head = cons_next;

	/* copy in table */
	fpn_rmb();
	for (i = 0; likely(i < n); i++) {
		obj_table[i] = r->ring[(cons_head + i) & mask];
	}

	__FPN_RING_STAT_ADD(r, deq_success, n);
	r->cons.tail = cons_next;
	return 0;
}

/*
 * Dequeue several objects from a ring (multi-consumers safe).
 */
int
fpn_ring_mc_dequeue_bulk(struct fpn_ring *r, void **obj_table, unsigned n)
{
	return __fpn_ring_mc_dequeue_bulk(r, obj_table, n);
}

/*
 * Dequeue several objects from a ring (NOT multi-consumers safe).
 */
int
fpn_ring_sc_dequeue_bulk(struct fpn_ring *r, void **obj_table, unsigned n)
{
	return __fpn_ring_sc_dequeue_bulk(r, obj_table, n);
}

/*
 * Dequeue several objects from a ring.
 */
int
fpn_ring_dequeue_bulk(struct fpn_ring *r, void **obj_table, unsigned n)
{
	if (r->cons.sc_dequeue)
		return __fpn_ring_sc_dequeue_bulk(r, obj_table, n);
	else
		return __fpn_ring_mc_dequeue_bulk(r, obj_table, n);
}

/*
 * Dequeue one object from a ring (multi-consumers safe).
 */
int
fpn_ring_mc_dequeue(struct fpn_ring *r, void **obj_p)
{
	return __fpn_ring_mc_dequeue_bulk(r, obj_p, 1);
}

/*
 * Dequeue one object from a ring (NOT multi-consumers safe).
 */
int
fpn_ring_sc_dequeue(struct fpn_ring *r, void **obj_p)
{
	return __fpn_ring_sc_dequeue_bulk(r, obj_p, 1);
}

/*
 * Dequeue one object from a ring.
 */
int
fpn_ring_dequeue(struct fpn_ring *r, void **obj_p)
{
	if (r->cons.sc_dequeue)
		return __fpn_ring_sc_dequeue_bulk(r, obj_p, 1);
	else
		return __fpn_ring_mc_dequeue_bulk(r, obj_p, 1);
}

/* initialize ring */
int fpn_ring_init(struct fpn_ring *r, const char *name, unsigned count,
		  unsigned flags)
{
	/* compilation-time checks */
	FPN_BUILD_BUG_ON((sizeof(struct fpn_ring) &
			  FPN_CACHELINE_MASK) != 0);
	FPN_BUILD_BUG_ON((fpn_offsetof(struct fpn_ring, cons) &
			  FPN_CACHELINE_MASK) != 0);
	FPN_BUILD_BUG_ON((fpn_offsetof(struct fpn_ring, prod) &
			  FPN_CACHELINE_MASK) != 0);
#ifdef FPN_RING_DEBUG
	FPN_BUILD_BUG_ON((sizeof(struct fpn_ring_debug_stats) &
			  FPN_CACHELINE_MASK) != 0);
	FPN_BUILD_BUG_ON((fpn_offsetof(struct fpn_ring, stats) &
			  FPN_CACHELINE_MASK) != 0);
#endif

	/* count must be a power of 2 */
	if (!POWEROF2(count)) {
		FPN_RING_ERROR("Requested size is not a power of 2\n");
		return -1;
	}

	if ((long)r & FPN_CACHELINE_MASK) {
		FPN_RING_ERROR("Ring pointer must be cache aligned\n");
		return -1;
	}

	/* init the ring structure */
	memset(r, 0, sizeof(*r));
	snprintf(r->name, sizeof(r->name), "%s", name);
	r->prod.bulk_default = r->cons.bulk_default = 1;
	r->prod.watermark = count;
	r->prod.sp_enqueue = !!(flags & FPN_RING_F_SP_ENQ);
	r->cons.sc_dequeue = !!(flags & FPN_RING_F_SC_DEQ);
	r->prod.size = r->cons.size = count;
	r->prod.mask = r->cons.mask = count-1;
	r->prod.head = r->cons.head = 0;
	r->prod.tail = r->cons.tail = 0;

	FPN_TAILQ_INSERT_TAIL(&ring_list, r, next);
	return 0;
}

struct fpn_ring *
fpn_ring_create(const char *name, unsigned count, unsigned flags)
{
	struct fpn_ring *r;
	size_t ring_size;

	ring_size = fpn_ring_getsize(count);

	/* allocate memory for this ring */
	r = fpn_malloc(ring_size, FPN_CACHELINE_SIZE);
	if (r == NULL)
		return NULL;

	/* intialize all the fields of the ring structure */
	if (fpn_ring_init(r, name, count, flags) < 0) {
		fpn_free(r);
		return NULL;
	}

	return r;
}

/*
 * change the high water mark. If *count* is 0, water marking is
 * disabled
 */
int
fpn_ring_set_water_mark(struct fpn_ring *r, unsigned count)
{
	if (count >= r->prod.size)
		return -EINVAL;

	/* if count is 0, disable the watermarking */
	if (count == 0)
		count = r->prod.size;

	r->prod.watermark = count;
	return 0;
}

/* dump the status of the ring on the console */
void
fpn_ring_dump(const struct fpn_ring *r)
{
#ifdef FPN_RING_DEBUG
	struct fpn_ring_debug_stats sum;
	unsigned core_id;
#endif

	fpn_printf("ring <%s>@%p\n", r->name, r);
	fpn_printf("  size=%"PRIu32"\n", r->prod.size);
	fpn_printf("  ct=%"PRIu32"\n", r->cons.tail);
	fpn_printf("  ch=%"PRIu32"\n", r->cons.head);
	fpn_printf("  pt=%"PRIu32"\n", r->prod.tail);
	fpn_printf("  ph=%"PRIu32"\n", r->prod.head);
	fpn_printf("  used=%"PRIu32"\n", fpn_ring_count(r));
	fpn_printf("  avail=%"PRIu32"\n", fpn_ring_free_count(r));
	if (r->prod.watermark == r->prod.size)
		fpn_printf("  watermark=0\n");
	else
		fpn_printf("  watermark=%"PRIu32"\n", r->prod.watermark);
	fpn_printf("  bulk_default=%"PRIu32"\n", r->prod.bulk_default);

	/* sum and dump statistics */
#ifdef FPN_RING_DEBUG
	memset(&sum, 0, sizeof(sum));
	for (core_id = 0; core_id < FPN_MAX_CORE; core_id++) {
		sum.enq_success_bulk += r->stats[core_id].enq_success_bulk;
		sum.enq_success_objs += r->stats[core_id].enq_success_objs;
		sum.enq_quota_bulk += r->stats[core_id].enq_quota_bulk;
		sum.enq_quota_objs += r->stats[core_id].enq_quota_objs;
		sum.enq_fail_bulk += r->stats[core_id].enq_fail_bulk;
		sum.enq_fail_objs += r->stats[core_id].enq_fail_objs;
		sum.deq_success_bulk += r->stats[core_id].deq_success_bulk;
		sum.deq_success_objs += r->stats[core_id].deq_success_objs;
		sum.deq_fail_bulk += r->stats[core_id].deq_fail_bulk;
		sum.deq_fail_objs += r->stats[core_id].deq_fail_objs;
	}
	fpn_printf("  size=%"PRIu32"\n", r->prod.size);
	fpn_printf("  enq_success_bulk=%"PRIu64"\n", sum.enq_success_bulk);
	fpn_printf("  enq_success_objs=%"PRIu64"\n", sum.enq_success_objs);
	fpn_printf("  enq_quota_bulk=%"PRIu64"\n", sum.enq_quota_bulk);
	fpn_printf("  enq_quota_objs=%"PRIu64"\n", sum.enq_quota_objs);
	fpn_printf("  enq_fail_bulk=%"PRIu64"\n", sum.enq_fail_bulk);
	fpn_printf("  enq_fail_objs=%"PRIu64"\n", sum.enq_fail_objs);
	fpn_printf("  deq_success_bulk=%"PRIu64"\n", sum.deq_success_bulk);
	fpn_printf("  deq_success_objs=%"PRIu64"\n", sum.deq_success_objs);
	fpn_printf("  deq_fail_bulk=%"PRIu64"\n", sum.deq_fail_bulk);
	fpn_printf("  deq_fail_objs=%"PRIu64"\n", sum.deq_fail_objs);
#else
	fpn_printf("  no statistics available\n");
#endif
}

/* dump the status of all rings on the console */
void
fpn_ring_list_dump(void)
{
	const struct fpn_ring *mp;

	FPN_TAILQ_FOREACH(mp, &ring_list, next) {
		fpn_ring_dump(mp);
	}
}

/* search a ring from its name */
struct fpn_ring *
fpn_ring_lookup(const char *name)
{
	struct fpn_ring *r;

	FPN_TAILQ_FOREACH(r, &ring_list, next) {
		if (strncmp(name, r->name, FPN_RING_NAMESIZE) == 0)
			break;
	}
	return r;
}
