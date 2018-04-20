/*
 * Copyright (c) 2009 6WIND
 */

#ifndef __FP_HLIST_H__
#define __FP_HLIST_H__

typedef struct fp_hlist_node {
	uint32_t next;
	uint32_t prev;
} fp_hlist_node_t;

typedef struct fp_hlist_head {
	uint32_t first;
	uint32_t last;
} fp_hlist_head_t;

/* Reserved to FPM */

#define fp_hlist_add_head(head, table, idx, node) do { \
	fp_hlist_head_t* __head = (head); \
	uint32_t __idx = idx; \
	uint32_t __next = __head->first; \
	(table)[__idx].node.prev = 0; \
	(table)[__idx].node.next = __next; \
	__head->first = __idx; \
	if (__next) \
		(table)[__next].node.prev = __idx; \
	else \
		__head->last = __idx; \
} while (0)

#define fp_hlist_add_tail(head, table, idx, node) do { \
	fp_hlist_head_t* __head = (head); \
	uint32_t __idx = idx; \
	uint32_t __prev = __head->last; \
	(table)[__idx].node.prev = __prev; \
	(table)[__idx].node.next = 0; \
	if (__prev) \
		(table)[__prev].node.next = __idx; \
	else \
		__head->first = __idx; \
	__head->last = __idx; \
} while (0)

#define fp_hlist_add_after(head, table, idx, old, node) do { \
	fp_hlist_head_t* __head = (head); \
	uint32_t __idx = idx; \
	uint32_t __prev = old; \
	uint32_t __next = (table)[__prev].node.next; \
	(table)[__idx].node.next = __next; \
	(table)[__prev].node.next = __idx; \
	(table)[__idx].node.prev = __prev; \
	if (__next) \
		(table)[__next].node.prev = __idx; \
	else \
		__head->last = __idx; \
} while (0)

#define fp_hlist_add_before(head, table, idx, old, node) do { \
	fp_hlist_head_t* __head = (head); \
	uint32_t __idx = idx; \
	uint32_t __next = old; \
	uint32_t __prev = (table)[__next].node.prev; \
	(table)[__idx].node.next = __next; \
	if (__prev) \
		(table)[__prev].node.next = __idx; \
	else \
		__head->first = __idx; \
	(table)[__next].node.prev = __idx; \
	(table)[__idx].node.prev = __prev; \
} while (0)

/* add in hlist by increasing order of cost */
#define fp_hlist_add_ordered(head, table, idx, node, cost) do { \
	uint32_t __cur; \
	uint32_t __cost = (table)[idx].cost; \
	fp_hlist_head_t* __head2 = (head); \
	fp_hlist_for_each_reverse(__cur, __head2, (table), node) { \
		if ((table)[__cur].cost <= __cost) { 			\
			fp_hlist_add_after(__head2, (table), (idx), __cur, node); \
			break; \
		} \
	} \
	if (__cur == 0) \
		fp_hlist_add_head(__head2, (table), (idx), node); \
} while (0)

#define fp_hlist_remove(head, table, idx, node) do { \
	fp_hlist_head_t* __head = (head); \
	uint32_t __idx = idx; \
	uint32_t __prev = (table)[__idx].node.prev; \
	uint32_t __next = (table)[__idx].node.next; \
	if (__prev) \
		(table)[__prev].node.next = __next; \
	else \
		__head->first = __next; \
	if (__next) \
		(table)[__next].node.prev = __prev; \
	else \
		__head->last = __prev; \
	(table)[__idx].node.prev = (table)[__idx].node.next = 0; \
} while (0)

#define fp_hlist_last(head) \
	(head)->last

#define fp_hlist_for_each_reverse(idx, head, table, node) \
	for (idx = fp_hlist_last(head); idx ; \
	     idx = (table)[idx].node.prev)

/* Usable by applications, modules and the Fast Path */

#define fp_hlist_first(head) \
	((head)->first)

#define fp_hlist_next(idx, table, node) \
	((table)[idx].node.next)

#define fp_hlist_for_each(idx, head, table, node) \
	for (idx = fp_hlist_first(head); idx ; \
	     idx = (table)[idx].node.next)

#define fp_hlist_for_each_safe(idx, nxt, head, table, node) \
	for (idx = fp_hlist_first(head), nxt = (table)[idx].node.next; \
	     idx ; \
	     idx = nxt, nxt = (table)[idx].node.next)

/* continue lookup after current entry number idx */
#define fp_hlist_for_each_continue(idx, head, table, node) \
	for (idx = (table)[idx].node.next; idx ; idx = (table)[idx].node.next)

#define fp_index_in_table(table, entry) \
	((uint32_t)((entry) - (typeof (entry))(table)))

#endif /* __FP_HLIST_H__ */
