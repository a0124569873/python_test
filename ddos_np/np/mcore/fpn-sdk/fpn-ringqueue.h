/*
 * Copyright(c) 2011 6WIND
 * All rights reserved.
 */

#ifndef _FPN_RINGQUEUE_H_
#define _FPN_RINGQUEUE_H_

/**
 * @file
 * FPN ringqueues
 *
 * The ringqueue is a list of dynamically allocated rings. Those rings are
 * expected to be retrieved from pools.
 *
 */
struct fpn_ringqueue {
	struct fpn_ring       *queue_head;
	struct fpn_ring       *queue_tail;
	fpn_spinlock_t         queue_lock;
	fpn_atomic_t           queue_nb_elt;
	int32_t                queue_size;
	uint32_t               queue_flags;
#define FPN_RINGQUEUE_SP_ENQ  0x01
#define FPN_RINGQUEUE_SC_DEQ  0x02
};

/*
 * Used to retrieve a linearized ringqueue content
 */
struct fpn_ringqueue_list {
	uint64_t  rq_nb;
	void     *rq_list[1];
};

#ifdef FPN_RINGQUEUE_EXTERNAL_LOCK
void fpn_ringqueue_initlock(struct fpn_ringqueue *q);
void fpn_ringqueue_lock(struct fpn_ringqueue *q);
void fpn_ringqueue_unlock(struct fpn_ringqueue *q);
#endif

/**
 * RQ Initialization
 *
 * @param q
 *   pre-allocated queue structure
 * @param r_pool
 *   Pool to get the first ring from
 * @param size
 *   Maximum size for the queue
 * @param flags
 *   Access property of the queue
 * @return
 *   - 0 on success
 *   - -ENOMEM, if the first ring cannot be retrieved
 */
int
fpn_ringqueue_init(struct fpn_ringqueue *q, struct fpn_mempool *r_pool,
		   uint32_t size, uint32_t flags);

/**
 * RQ Creation, including initialization
 *
 * @param r_pool
 *   Pool to get the first ring from
 * @param size
 *   Maximum size for the queue
 * @param flags
 *   Access property of the queue
 * @return
 *   - on success, pointer to the queue
 *   - NULL if any error
 */
struct fpn_ringqueue *
fpn_ringqueue_create(struct fpn_mempool *r_pool, uint32_t size,
		     uint32_t flags);

/**
 * RQ write operation
 *
 * @param q
 *   ringqueue to write to
 * @param obj
 *   object to add to ringqueue
 * @return
 *   - 0 on success
 *   - -ENOBUFS if ringqueueis full
 *   - -ENOMEM in case of any allocation error
 */
int
fpn_ringqueue_enqueue(struct fpn_ringqueue *q, void *obj);

/**
 * RQ read operation
 *
 * @param q
 *   ringqueue to read from
 * @param obj_p
 *   pointer to the pointer of the dequeue object
 * @return
 *   - 0 on success
 *   - -ENOBUFS if ringqueueis full
 *   - -ENOMEM in case of any allocation error
 */
int
fpn_ringqueue_dequeue(struct fpn_ringqueue *q, void **obj_p);

/**
 * Read several objects from a ringqueue (NOT multi-consumers safe).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param *n
 *   The number of objects to read from the ringqueue to the obj_table,
 *   must be strictly positive. On return, will contain the number of
 *   objects really read.
 * @return
 *   - 0: Success; objects dequeued.
 *   - -ENOENT: Not enough entries in the ringqueue to dequeue.
 *   - -EINVAL: internal error during ring access.
 */
int
fpn_ringqueue_sc_dequeue_bulk(struct fpn_ringqueue *q, void **obj_table,
			      unsigned *n);

/**
 * A ringqueue liberation callback function.
 *
 * Arguments are the object stored in the ringpool
 */
typedef void (ringqueue_free_t)(void *);

/**
 * RQ resource liberation
 *
 * The whole ringqueue will be emptied. Each element will be "freed" according
 * to the provided callback.
 *   fpn_ringqueue_purge: this is the only action
 *   fpn_ringqueue_destroy:  the queue itself will be freed
 *
 * @param q
 *   ringqueue to empty
 * @param free_it
 *   callback, called on each element of the ringqueue
 * @return
 *   - 0 on success
 *   - -ENOMEM if allocation of list fails
 *   - -EINVAL if an error occurs in ring operations
 */
int
fpn_ringqueue_purge(struct fpn_ringqueue *q,
		    ringqueue_free_t *free_it);
int
fpn_ringqueue_destroy(struct fpn_ringqueue *q,
		      ringqueue_free_t *free_it);

/**
 * RQ size change
 *
 * This will reduce the queue size. If there are too many elements, a specific
 * return code will be returned, but no specific action will be taken. The
 * number of exceeding elements will be provided.
 *
 * @param q
 *   ringqueue to 'resize'
 * @param size
 *   IN: pointer to the new size
 *   OUT: in case of oversized queue, this will hold the number of
 *        'undue' elements
 * @return
 *  - 0  on success
 *  - -EDQUOT if current size is bigger than the newly defined
 */
int
fpn_ringqueue_resize(struct fpn_ringqueue *q, int32_t *size);

/**
 * Return the number of entries in a ringqueue.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The number of entries in the ringqueue.
 */
static inline unsigned
fpn_ringqueue_count(struct fpn_ringqueue *q) {
	return fpn_atomic_read(&q->queue_nb_elt);
};

#if 0
/*
 * if Q is empty, should return NULL
 * _sc_peek returns the element, but does not dequeue it. It is NOT
 *  multi-consumer safe
 */
void *
fpn_ringqueue_sc_peek(struct fpn_ringqueue *q);

#endif


/**
 * Dump the ringqueue and attached rings
 *
 * @param q
 *   ringqueue to 'resize'
 */
void
fpn_ringqueue_dump(struct fpn_ringqueue *q);
#endif
