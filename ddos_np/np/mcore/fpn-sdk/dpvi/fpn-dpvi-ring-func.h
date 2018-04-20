/*
 * Copyright (C) 2011 6WIND, All rights reserved.
 *
 */

#ifndef __FPN_DPVI_RING_FUNC_H__
#define __FPN_DPVI_RING_FUNC_H__

static inline int fpn_dring_enqueue(struct fpn_dring *ring,
									struct fpn_dring_entry *in,
									unsigned int count,
									void (*copy)(struct fpn_dring_entry *, struct fpn_dring_entry *))
{
	uint32_t prod_head = ring->prod.head;
	uint32_t cons_tail = ring->cons.tail;
	uint32_t prod_next, free_desc;
	uint32_t mask = FPN_DRING_MASK;
	struct fpn_dring_entry *dre;
	unsigned int i;

	free_desc = mask + cons_tail - prod_head;
	if (unlikely(free_desc < count))
		return -1; /* full */
	prod_next = prod_head + count;
	ring->prod.head = prod_next;

	for (i = 0; i < count; i++) {
		dre = &ring->desc[((prod_head + i) & mask)];

		if (copy)
			(*copy)(dre, in);
		else {
			dre->data = in->data;
			dre->port = in->port;
			dre->from = in->from;
			dre->eop = in->eop;
			dre->len = in->len;
			dre->prod_desc = in->prod_desc;
		}
		in++;
	}

#ifdef __KERNEL__
	wmb();
#else
	fpn_wmb();
#endif

	ring->prod.tail = prod_next;

	return 0;
}

/* Dequeue at most count and return nb of popped elements */
static inline int fpn_dring_dequeue(struct fpn_dring *ring,
									struct fpn_dring_entry *out,
									unsigned int count,
									void (*copy)(struct fpn_dring_entry *, struct fpn_dring_entry *))
{
	uint32_t cons_head = ring->cons.head;
	uint32_t prod_tail = ring->prod.tail;
	uint32_t cons_next, desc;
	uint32_t mask = FPN_DRING_MASK;
	struct fpn_dring_entry *dre;
	unsigned int i, n;

	desc = prod_tail - cons_head;
	if (unlikely(desc < 1))
		return 0; /* empty */

	if (count > desc)
		n = desc;
	else
		n = count;

	cons_next = cons_head + n;
	ring->cons.head = cons_next;

#ifdef __KERNEL__
	rmb();
#else
	fpn_rmb();
#endif

	for (i = 0; i < n; i++) {
		dre = &ring->desc[((cons_head + i) & mask)];
		if (copy)
			(*copy)(out, dre);
		else {
			out->data = dre->data;
			out->len = dre->len;
			out->port = dre->port;
			out->from = dre->from;
			out->eop = dre->eop;
			out->cons_desc = dre->cons_desc;
		}
		out++;
	}

	ring->cons.tail = cons_next;

	return n;
}

/*
 * Like fpn_dring_dequeue(), but does not update consumer tail.
 * To be used when a basic copy function cannot be provided.
 * fpn_dring_dequeue_end() must be called with the returned value if nonzero.
 */
static inline int fpn_dring_dequeue_start(struct fpn_dring *ring,
					  struct fpn_dring_entry *out,
					  unsigned int count)
{
	uint32_t cons_head = ring->cons.head;
	uint32_t prod_tail = ring->prod.tail;
	uint32_t cons_next, desc;
	uint32_t mask = FPN_DRING_MASK;
	struct fpn_dring_entry *dre;
	unsigned int i, n;

#ifdef __KERNEL__
	smp_rmb();
#else
	fpn_rmb();
#endif

	desc = prod_tail - cons_head;
	if (unlikely(desc < 1))
		return 0; /* empty */

	if (count > desc)
		n = desc;
	else
		n = count;

	cons_next = cons_head + n;
	ring->cons.head = cons_next;

#ifdef __KERNEL__
	smp_wmb();
#else
	fpn_wmb();
#endif

	for (i = 0; i < n; i++) {
		dre = &ring->desc[((cons_head + i) & mask)];
		out->data = dre->data;
		out->len = dre->len;
		out->port = dre->port;
		out->from = dre->from;
		out->eop = dre->eop;
		out->cons_desc = dre->cons_desc;
		out++;
	}

	return n;
}

/*
 * Must be called after working on the data returned by
 * fpn_dring_dequeue_start().
 * Be careful as no checks are performed on count.
 */
static inline void fpn_dring_dequeue_end(struct fpn_dring *ring,
					 unsigned int count)
{
#ifdef __KERNEL__
	smp_wmb();
#else
	fpn_wmb();
#endif

	ring->cons.tail += count;
}

#endif
