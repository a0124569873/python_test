/*
 * Copyright(c) 2011 6WIND
 * All rights reserved.
 */

#include "fpn.h"
#include "fpn-ring.h"
#include "fpn-mempool.h"
#include "fpn-ringqueue.h"


#ifndef FPN_RINGQUEUE_EXTERNAL_LOCK
static inline void
fpn_ringqueue_initlock(struct fpn_ringqueue *q)
{
	fpn_spinlock_init(&q->queue_lock);
}

static inline void
fpn_ringqueue_lock(struct fpn_ringqueue *q)
{
	fpn_spinlock_lock(&q->queue_lock);
}

static inline void
fpn_ringqueue_unlock(struct fpn_ringqueue *q)
{
	fpn_spinlock_unlock(&q->queue_lock);
}
#endif

/*
 * Basic RQ initialization
 */
int
fpn_ringqueue_init(struct fpn_ringqueue *q, struct fpn_mempool *r_pool,
		   uint32_t size, uint32_t flags)
{
	void *tmp_r;
	struct fpn_ring *r;

	/* Allocates a first ring */
	if (fpn_mempool_get(r_pool, &tmp_r) < 0)
		return -ENOMEM;
	r = tmp_r;

	/* Inherits the access property from the queue */
	fpn_ring_set_sp_enqueue(r, !!(flags & FPN_RINGQUEUE_SP_ENQ));
	fpn_ring_set_sc_dequeue(r, !!(flags & FPN_RINGQUEUE_SC_DEQ));
	fpn_ring_set_opaque(r, NULL);

	/* queue internal */
	q->queue_head = r;
	q->queue_tail = r;
	fpn_atomic_clear(&q->queue_nb_elt);
	q->queue_size = size;
	q->queue_flags = flags;
	fpn_ringqueue_initlock(q);

	return 0;
}

/*
 * RQ creation
 */
struct fpn_ringqueue *
fpn_ringqueue_create(struct fpn_mempool *r_pool,
		     uint32_t size, uint32_t flags)
{
	struct fpn_ringqueue *q;

	q = fpn_malloc(sizeof(*q), 0);
	/* no more memory */
	if (q == NULL)
		return NULL;

	if (fpn_ringqueue_init(q, r_pool, size, flags) < 0) {
		fpn_free(q);
		return NULL;
	}

	return q;
}

/*
 * From a ring associated to a queue, get a new ring for that queue,
 * following the pool linkage.
 */
static struct fpn_ring *
ringqueue_get_next_ring(struct fpn_ring *r)
{
	struct fpn_mempool *mp;
	struct fpn_mempool **mpp;
	void *new;

	/* Back from the ring to it's originating pool */
	mp = fpn_mempool_from_obj((const void *)r);
	if (mp == NULL)
		return NULL;

	/* Then go to next pool */
	mpp = (struct fpn_mempool **) fpn_mempool_get_priv(mp);
	mp = *mpp;
	if (mp == NULL)
		return NULL;

	/* Then allocate from that pool */
	if (fpn_mempool_get(mp, &new) < 0)
		return NULL;

	return new;
}

/*
 * This will write in the last ring, i.e. the tail.
 * If it is full, a new ring will be allocated.
 */
int
fpn_ringqueue_enqueue(struct fpn_ringqueue *q, void *obj)
{
	/*
	 * This is an optimistic approach: as several core may
	 * access the same queue, it is possible to go further than
	 * the queue_size, but not much.
	 */
	if (unlikely(fpn_atomic_read(&q->queue_nb_elt) >= q->queue_size))
		return -ENOBUFS;
	fpn_atomic_inc(&q->queue_nb_elt);

	/*
	 * In most cases, the ring access will be successful
	 * error means the ring is full, so we'll have to allocate
	 * a new one
	 */
	while (unlikely(fpn_ring_enqueue(q->queue_tail, obj) < 0)) {
		/*
		 * Ring allocation and linkage needs a lock, but 2 cores
		 * may try the same allocation at the same time, so once
		 * we get the lock, we must check if the work was not
		 * already done
		 */
		fpn_ringqueue_lock(q);
		/*
		 * In the opaque area we find the linkage to the next ring,
		 * if non NULL, another core did the alloc job
		 */
		if (likely(fpn_ring_get_opaque(q->queue_tail) == NULL)) {
			struct fpn_ring *r;

			r = ringqueue_get_next_ring(q->queue_tail);
			if (unlikely(r == NULL)) {
				fpn_ringqueue_unlock(q);
				return -ENOMEM;
			}

			/*
			 * Update the ring properties
			 */
			fpn_ring_set_sp_enqueue(r,
				!!(q->queue_flags & FPN_RINGQUEUE_SP_ENQ));
			fpn_ring_set_sc_dequeue(r,
				!!(q->queue_flags & FPN_RINGQUEUE_SC_DEQ));
			/*
			 * Ring linkage inside the queue
			 */
			fpn_ring_set_opaque(r, NULL);
			fpn_ring_set_opaque(q->queue_tail, r);
			q->queue_tail = r;
		}
		fpn_ringqueue_unlock(q);
	}
	return 0;
}


/*
 * This will read from the first ring, i.e. the head
 * If it is empty, the ring will be released and read will
 * be performed on next ring.
 * Single Consumer version, hence no need for lock/protection
 */
static inline int
fpn_ringqueue_sc_dequeue(struct fpn_ringqueue *q, void **obj_p)
{
	struct fpn_ring *r;

	/* Hopefully there is something to read */
	if (likely(fpn_ring_dequeue(q->queue_head, obj_p) == 0)) {
		fpn_atomic_dec(&q->queue_nb_elt);
		return 0;
	}
	/*
	 * The ONLY ring is empty, so is the ringqueue
	 * Never release the last ring.
	 */
	if (q->queue_head == q->queue_tail)
		return -ENOENT;

	/*
	 * Release the first ring
	 */
	r = q->queue_head;
	q->queue_head = fpn_ring_get_opaque(r);
	fpn_mempool_put(fpn_mempool_from_obj((void *)r), (void *)r);

	/*
	 * The next one MAY be empty
	 */
	if (unlikely(fpn_ring_dequeue(q->queue_head, obj_p)) < 0)
		return -ENOENT;
	fpn_atomic_dec(&q->queue_nb_elt);
	return 0;
}


/*
 * This will read from the first ring, i.e. the head
 * If it is empty, the ring will be released and read will
 * be performed on next ring.
 *
 * Multi Consumer version, simplist design
 */
static inline int
fpn_ringqueue_mc_dequeue(struct fpn_ringqueue *q, void **obj_p)
{
	int res;
	fpn_ringqueue_lock(q);
	res = fpn_ringqueue_sc_dequeue(q, obj_p);
	fpn_ringqueue_unlock(q);
	return res;
}

#if 0
/*
 * This will read from the first ring, i.e. the head
 * If it is empty, the ring will be released and read will
 * be performed on next ring.
 *
 * Multi Consumer version, draft design
 */
static inline int
fpn_ringqueue_mc_dequeue(struct fpn_ringqueue *q, void *obj)
{
	struct fpn_ring *r;

	FPN_RINGQUEUE_ENTER();
	while (1) {
		r = q->queue_head;
		if (likely(fpn_ring_dequeue(r, &obj) == 0)) {
			FPN_RINGQUEUE_LEAVE();
			return 0;
		}
		/*
		 * The ONLY ring is empty, so is the ringqueue
		 */
		if (r == q->queue_tail) {
			FPN_RINGQUEUE_LEAVE();
			return -ENOENT;
		}
		/*
		 * Now we have to release the empty ring, and continue
		 * the read operation on the next one
		 */
		fpn_ringqueue_lock(q);
		/*
		 * Ring de-allocation and unlinkage needs a lock, but 2 cores
		 * may try the same free operation at the same time, so once
		 * we get the lock, we must check if the work was not
		 * already done
		 */
		if (r == q->queue_head) {
			q->queue_head = fpn_ring_get_opaque(r);
			fpn_mempool_defer_put(fpn_mempool_from_obj((void *)r),
					       (void *)r);
		}
		fpn_ringqueue_unlock(q);
	}
	FPN_RINGQUEUE_LEAVE();
	return 0;
}
#endif

/*
 * This will read from the first ring, i.e. the head
 * If it is empty, the ring will be released and read will
 * be performed on next ring.
 *
 * Generic version
 */
int
fpn_ringqueue_dequeue(struct fpn_ringqueue *q, void **obj_p)
{
	if (q->queue_flags & FPN_RINGQUEUE_SC_DEQ)
		return fpn_ringqueue_sc_dequeue(q, obj_p);
	else
		return fpn_ringqueue_mc_dequeue(q, obj_p);
}

/*
 * Dequeue some elements from the ringqueue and store them
 * in a table. It supports only a single consumer access.
 */
int
fpn_ringqueue_sc_dequeue_bulk(struct fpn_ringqueue *q, void **obj_table,
			      unsigned *n)
{
	struct fpn_ring *r, *r_next;
	unsigned total;
	unsigned remain;

	remain = *n;
	total = 0;
	for (r = q->queue_head; r ; r = r_next) {
		unsigned r_count;
		int to_read;

		/* Get ring linkage */
		r_next = fpn_ring_get_opaque(r);

		/* Dequeue from whole ring */
		r_count = fpn_ring_count(r);
		to_read = (r_count > remain) ? remain : r_count;
		if (unlikely(fpn_ring_sc_dequeue_bulk(r, &obj_table[total],
						      to_read) < 0)) {
			/*
			 * Something went wrong, so stop the linearization
			 * and provide the list of what was already dequeued,
			 * but keep the end of the ringqueue untouched
			 */
			q->queue_head = r;
			fpn_atomic_sub(&q->queue_nb_elt, total);
			*n = total;
			return -EINVAL;
		}
		total += to_read;
		remain -= to_read;
		/* Release the ring (unless it's the last one) */
		if (r != q->queue_tail)
			fpn_mempool_put(fpn_mempool_from_obj((void *)r),
							     (void *)r);
		else
			break;
		if (remain == 0)
			break;
	}
	q->queue_head = r;
	fpn_atomic_sub(&q->queue_nb_elt, total);
	*n = total;
	if (remain)
		return -ENOENT;
	return 0;
}

/*
 * Release all elements of a ringqueue
 */
#define FPN_RQ_PURGE_BULK 64
int
fpn_ringqueue_purge(struct fpn_ringqueue *q,
		    ringqueue_free_t *free_it)
{
	void *obj_table[FPN_RQ_PURGE_BULK];
	int res;
	unsigned i;

	do  {
		unsigned n = FPN_RQ_PURGE_BULK;
		res = fpn_ringqueue_sc_dequeue_bulk(q, obj_table, &n);
		if (free_it) {
			for (i = 0; i < n; i++)
				free_it(obj_table[i]);
		}
		if (unlikely(res < 0 && res != -ENOENT))
			return res;
	} while (res == 0);

	/* Release the remaining ring */
	fpn_mempool_put(fpn_mempool_from_obj((void *)q->queue_head),
			(void *)q->queue_head);
	return 0;
}

/*
 * Destroy a ringqueue (and release all its elements)
 */
int
fpn_ringqueue_destroy(struct fpn_ringqueue *q,
		      ringqueue_free_t *free_it)
{
	int res;

	res = fpn_ringqueue_purge(q, free_it);
	if (unlikely(res < 0))
		return res;

	fpn_free(q);
	return 0;
}

/*
 * Redefine the size of the queue
 */
int
fpn_ringqueue_resize(struct fpn_ringqueue *q, int32_t *size)
{
	int32_t cur_size;

	cur_size = fpn_atomic_read(&q->queue_nb_elt);
	q->queue_size = *size;
	if (cur_size > q->queue_size) {
		*size = cur_size - q->queue_size;
		return -EDQUOT;
	}
	return 0;
}

/*
 * Dump the ringqueue and attached rings
 */
void
fpn_ringqueue_dump(struct fpn_ringqueue *q)
{
	struct fpn_ring *r;
	int i=0;

	fpn_printf("#### ringqueue dump");
	fpn_printf("Size: %d, nb_elt:%d", q->queue_size,
		   fpn_atomic_read(&q->queue_nb_elt));
	fpn_printf("r_head: %p, r_tail:%p", q->queue_head, q->queue_tail);
	for (r = q->queue_head; r; ) {
		fpn_printf("--------- ring #%d", i++);
		fpn_ring_dump(r);
		r = fpn_ring_get_opaque(r);
	}
}
