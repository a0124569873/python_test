/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)queue.h	8.5 (Berkeley) 8/20/94
 * $FreeBSD: src/sys/sys/queue.h,v 1.32.2.7 2002/04/17 14:21:02 des Exp $
 */

#ifndef _FPN_QUEUE_H_
#define	_FPN_QUEUE_H_

/*
 * This file defines five types of data structures: singly-linked lists,
 * singly-linked tail queues, lists, tail queues, and circular queues.
 *
 * A singly-linked list is headed by a single forward pointer. The elements
 * are singly linked for minimum space and pointer manipulation overhead at
 * the expense of O(n) removal for arbitrary elements. New elements can be
 * added to the list after an existing element or at the head of the list.
 * Elements being removed from the head of the list should use the explicit
 * macro for this purpose for optimum efficiency. A singly-linked list may
 * only be traversed in the forward direction.  Singly-linked lists are ideal
 * for applications with large datasets and few or no removals or for
 * implementing a LIFO queue.
 *
 * A singly-linked tail queue is headed by a pair of pointers, one to the
 * head of the list and the other to the tail of the list. The elements are
 * singly linked for minimum space and pointer manipulation overhead at the
 * expense of O(n) removal for arbitrary elements. New elements can be added
 * to the list after an existing element, at the head of the list, or at the
 * end of the list. Elements being removed from the head of the tail queue
 * should use the explicit macro for this purpose for optimum efficiency.
 * A singly-linked tail queue may only be traversed in the forward direction.
 * Singly-linked tail queues are ideal for applications with large datasets
 * and few or no removals or for implementing a FIFO queue.
 *
 * A list is headed by a single forward pointer (or an array of forward
 * pointers for a hash table header). The elements are doubly linked
 * so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before
 * or after an existing element or at the head of the list. A list
 * may only be traversed in the forward direction.
 *
 * A tail queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or
 * after an existing element, at the head of the list, or at the end of
 * the list. A tail queue may be traversed in either direction.
 *
 * A circle queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or after
 * an existing element, at the head of the list, or at the end of the list.
 * A circle queue may be traversed in either direction, but has a more
 * complex end of list detection.
 *
 * For details on the use of these macros, see the queue(3) manual page.
 *
 *
 *			SLIST	LIST	STAILQ	TAILQ	CIRCLEQ
 * _HEAD		+	+	+	+	+
 * _HEAD_INITIALIZER	+	+	+	+	+
 * _ENTRY		+	+	+	+	+
 * _INIT		+	+	+	+	+
 * _EMPTY		+	+	+	+	+
 * _FIRST		+	+	+	+	+
 * _NEXT		+	+	+	+	+
 * _PREV		-	-	-	+	+
 * _LAST		-	-	+	+	+
 * _FOREACH		+	+	+	+	+
 * _FOREACH_REVERSE	-	-	-	+	+
 * _INSERT_HEAD		+	+	+	+	+
 * _INSERT_BEFORE	-	+	-	+	+
 * _INSERT_AFTER	+	+	+	+	+
 * _INSERT_TAIL		-	-	+	+	+
 * _REMOVE_HEAD		+	-	+	-	-
 * _REMOVE		+	+	+	+	+
 *
 */

/* Non standard */
#define FPN_SLIST_MOVE(from, to) do {					\
		((to)->slh_first) = ((from)->slh_first);		\
		FPN_SLIST_INIT(from);					\
	} while (0)


#define FPN_SLIST_FOREACH_SAFE(cur, next, head, field)			\
	for ((cur) = FPN_SLIST_FIRST((head)),				\
		     (next) = ((cur) ? FPN_SLIST_NEXT((cur), field) : NULL); \
	     (cur);							\
	     (cur) = (next),						\
		     (next) = ((cur) ? FPN_SLIST_NEXT((cur), field) : NULL))

#define FPN_LIST_MOVE(from, to, field) do {				\
		*(to) = *(from);					\
		FPN_LIST_INIT(from);					\
		if (FPN_LIST_FIRST(to) != NULL)				\
			FPN_LIST_FIRST(to)->field.le_prev =		\
				&FPN_LIST_FIRST(to);			\
	} while (0)

#define FPN_LIST_FOREACH_SAFE(cur, next, head, field)			\
	for ((cur) = FPN_LIST_FIRST((head)),				\
		     (next) = ((cur) ? FPN_LIST_NEXT((cur), field) : NULL); \
	     (cur);							\
	     (cur) = (next),						\
		     (next) = ((cur) ? FPN_LIST_NEXT((cur), field) : NULL))

/*
 * Singly-linked List declarations.
 */
#define	FPN_SLIST_HEAD(name, type)					\
struct name {								\
	struct type *slh_first;	/* first element */			\
}

#define	FPN_SLIST_HEAD_INITIALIZER(head)				\
	{ NULL }
 
#define	FPN_SLIST_ENTRY(type)						\
struct {								\
	struct type *sle_next;	/* next element */			\
}
 
/*
 * Singly-linked List functions.
 */
#define	FPN_SLIST_EMPTY(head)	((head)->slh_first == NULL)

#define	FPN_SLIST_FIRST(head)	((head)->slh_first)

#define	FPN_SLIST_FOREACH(var, head, field)				\
	for ((var) = FPN_SLIST_FIRST((head));				\
	    (var);							\
	    (var) = FPN_SLIST_NEXT((var), field))

#define	FPN_SLIST_INIT(head) do {					\
	FPN_SLIST_FIRST((head)) = NULL;					\
} while (0)

#define	FPN_SLIST_INSERT_AFTER(slistelm, elm, field) do {		\
	FPN_SLIST_NEXT((elm), field) = FPN_SLIST_NEXT((slistelm), 	\
						      field);		\
	FPN_SLIST_NEXT((slistelm), field) = (elm);			\
} while (0)

#define	FPN_SLIST_INSERT_HEAD(head, elm, field) do {			\
	FPN_SLIST_NEXT((elm), field) = FPN_SLIST_FIRST((head));		\
	FPN_SLIST_FIRST((head)) = (elm);				\
} while (0)

#define	FPN_SLIST_NEXT(elm, field)	((elm)->field.sle_next)

#define	FPN_SLIST_REMOVE(head, elm, type, field) do {			\
	if (FPN_SLIST_FIRST((head)) == (elm)) {				\
		FPN_SLIST_REMOVE_HEAD((head), field);			\
	}								\
	else {								\
		struct type *curelm = FPN_SLIST_FIRST((head));		\
		while (FPN_SLIST_NEXT(curelm, field) != (elm))		\
			curelm = FPN_SLIST_NEXT(curelm, field);		\
		FPN_SLIST_NEXT(curelm, field) =				\
		    FPN_SLIST_NEXT(FPN_SLIST_NEXT(curelm, field), 	\
				   field);				\
	}								\
} while (0)

#define	FPN_SLIST_REMOVE_SAFE(head, elm, type, field) do {		\
	if (FPN_SLIST_FIRST((head)) == (elm)) {				\
		FPN_SLIST_REMOVE_HEAD((head), field);			\
	}								\
	else {								\
		struct type *curelm = FPN_SLIST_FIRST((head));		\
		while (curelm &&					\
		       FPN_SLIST_NEXT(curelm, field) != (elm))		\
			curelm = FPN_SLIST_NEXT(curelm, field);		\
		if (curelm == NULL)					\
			break;						\
		FPN_SLIST_NEXT(curelm, field) =				\
		    FPN_SLIST_NEXT(FPN_SLIST_NEXT(curelm, field), 	\
				   field);				\
	}								\
} while (0)

#define	FPN_SLIST_REMOVE_HEAD(head, field) do {				\
	FPN_SLIST_FIRST((head)) = 					\
		FPN_SLIST_NEXT(FPN_SLIST_FIRST((head)), field);		\
} while (0)

/*
 * Singly-linked Tail queue declarations.
 */
#define	FPN_STAILQ_HEAD(name, type)					\
struct name {								\
	struct type *stqh_first;/* first element */			\
	struct type **stqh_last;/* addr of last next element */		\
}

#define	FPN_STAILQ_HEAD_INITIALIZER(head)				\
	{ NULL, &(head).stqh_first }

#define	FPN_STAILQ_ENTRY(type)						\
struct {								\
	struct type *stqe_next;	/* next element */			\
}

/*
 * Singly-linked Tail queue functions.
 */
#define	FPN_STAILQ_EMPTY(head)	((head)->stqh_first == NULL)

#define	FPN_STAILQ_FIRST(head)	((head)->stqh_first)

#define	FPN_STAILQ_FOREACH(var, head, field)				\
	for((var) = FPN_STAILQ_FIRST((head));				\
	   (var);							\
	   (var) = FPN_STAILQ_NEXT((var), field))

#define	FPN_STAILQ_INIT(head) do {					\
	FPN_STAILQ_FIRST((head)) = NULL;				\
	(head)->stqh_last = &FPN_STAILQ_FIRST((head));			\
} while (0)

#define	FPN_STAILQ_INSERT_AFTER(head, tqelm, elm, field) do {		\
	if ((FPN_STAILQ_NEXT((elm), field) = 				\
	     FPN_STAILQ_NEXT((tqelm), field)) == NULL)			\
		(head)->stqh_last = &FPN_STAILQ_NEXT((elm), field);	\
	FPN_STAILQ_NEXT((tqelm), field) = (elm);			\
} while (0)

#define	FPN_STAILQ_INSERT_HEAD(head, elm, field) do {			\
	if ((FPN_STAILQ_NEXT((elm), field) = 				\
	     FPN_STAILQ_FIRST((head))) == NULL)				\
		(head)->stqh_last = &FPN_STAILQ_NEXT((elm), field);	\
	FPN_STAILQ_FIRST((head)) = (elm);				\
} while (0)

#define	FPN_STAILQ_INSERT_TAIL(head, elm, field) do {			\
	FPN_STAILQ_NEXT((elm), field) = NULL;				\
	*(head)->stqh_last = (elm);					\
	(head)->stqh_last = &FPN_STAILQ_NEXT((elm), field);		\
} while (0)

#define	FPN_STAILQ_LAST(head, type, field)				\
	(FPN_STAILQ_EMPTY(head) ?					\
		NULL :							\
	        ((struct type *) ((char *)((head)->stqh_last) - 	\
				  fpn_offsetof(struct type, field))))

#define	FPN_STAILQ_NEXT(elm, field)	((elm)->field.stqe_next)

#define	FPN_STAILQ_REMOVE(head, elm, type, field) do {			\
	if (FPN_STAILQ_FIRST((head)) == (elm)) {			\
		FPN_STAILQ_REMOVE_HEAD(head, field);			\
	}								\
	else {								\
		struct type *curelm = FPN_STAILQ_FIRST((head));		\
		while (FPN_STAILQ_NEXT(curelm, field) != (elm))		\
			curelm = FPN_STAILQ_NEXT(curelm, field);	\
		if ((FPN_STAILQ_NEXT(curelm, field) =			\
		     FPN_STAILQ_NEXT(FPN_STAILQ_NEXT(curelm, field), 	\
				     field)) == NULL)			\
			(head)->stqh_last = &FPN_STAILQ_NEXT((curelm), 	\
							     field);	\
	}								\
} while (0)

#define	FPN_STAILQ_REMOVE_HEAD(head, field) do {			\
	if ((FPN_STAILQ_FIRST((head)) =					\
	     FPN_STAILQ_NEXT(FPN_STAILQ_FIRST((head)), field)) == NULL)	\
		(head)->stqh_last = &FPN_STAILQ_FIRST((head));		\
} while (0)

#define	FPN_STAILQ_REMOVE_HEAD_UNTIL(head, elm, field) do {		\
	if ((FPN_STAILQ_FIRST((head)) = 				\
	     FPN_STAILQ_NEXT((elm), field)) == NULL)			\
		(head)->stqh_last = &FPN_STAILQ_FIRST((head));		\
} while (0)

/*
 * List declarations.
 */
#define	FPN_LIST_HEAD(name, type)					\
struct name {								\
	struct type *lh_first;	/* first element */			\
}

#define	FPN_LIST_HEAD_INITIALIZER(head)					\
	{ NULL }

#define	FPN_LIST_ENTRY(type)						\
struct {								\
	struct type *le_next;	/* next element */			\
	struct type **le_prev;	/* address of previous next element */	\
}

/*
 * List functions.
 */

#define	FPN_LIST_EMPTY(head)	((head)->lh_first == NULL)

#define	FPN_LIST_FIRST(head)	((head)->lh_first)

#define	FPN_LIST_FOREACH(var, head, field)				\
	for ((var) = FPN_LIST_FIRST((head));				\
	    (var);							\
	    (var) = FPN_LIST_NEXT((var), field))

#define	FPN_LIST_INIT(head) do {					\
	FPN_LIST_FIRST((head)) = NULL;					\
} while (0)

#define	FPN_LIST_INSERT_AFTER(listelm, elm, field) do {			\
	if ((FPN_LIST_NEXT((elm), field) = 				\
	     FPN_LIST_NEXT((listelm), field)) != NULL)			\
		FPN_LIST_NEXT((listelm), field)->field.le_prev =	\
		    &FPN_LIST_NEXT((elm), field);			\
	FPN_LIST_NEXT((listelm), field) = (elm);			\
	(elm)->field.le_prev = &FPN_LIST_NEXT((listelm), field);	\
} while (0)

#define	FPN_LIST_INSERT_BEFORE(listelm, elm, field) do {		\
	(elm)->field.le_prev = (listelm)->field.le_prev;		\
	FPN_LIST_NEXT((elm), field) = (listelm);			\
	*(listelm)->field.le_prev = (elm);				\
	(listelm)->field.le_prev = &FPN_LIST_NEXT((elm), field);	\
} while (0)

#define	FPN_LIST_INSERT_HEAD(head, elm, field) do {			\
	if ((FPN_LIST_NEXT((elm), field) = 				\
	     FPN_LIST_FIRST((head))) != NULL)				\
		FPN_LIST_FIRST((head))->field.le_prev = 		\
			&FPN_LIST_NEXT((elm), field);			\
	FPN_LIST_FIRST((head)) = (elm);					\
	(elm)->field.le_prev = &FPN_LIST_FIRST((head));			\
} while (0)

#define	FPN_LIST_NEXT(elm, field)	((elm)->field.le_next)

#define	FPN_LIST_REMOVE(elm, field) do {				\
	if (FPN_LIST_NEXT((elm), field) != NULL)			\
		FPN_LIST_NEXT((elm), field)->field.le_prev = 		\
		    (elm)->field.le_prev;				\
	*(elm)->field.le_prev = FPN_LIST_NEXT((elm), field);		\
} while (0)

/*
 * Tail queue declarations.
 */
#define	FPN_TAILQ_HEAD(name, type)					\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
}

#define	FPN_TAILQ_HEAD_INITIALIZER(head)				\
	{ NULL, &(head).tqh_first }

#define	FPN_TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue functions.
 */
#define	FPN_TAILQ_EMPTY(head)	((head)->tqh_first == NULL)

#define	FPN_TAILQ_FIRST(head)	((head)->tqh_first)

#define	FPN_TAILQ_FOREACH(var, head, field)				\
	for ((var) = FPN_TAILQ_FIRST((head));				\
	    (var);							\
	    (var) = FPN_TAILQ_NEXT((var), field))

#define	FPN_TAILQ_FOREACH_REVERSE(var, head, headname, field)		\
	for ((var) = FPN_TAILQ_LAST((head), headname);			\
	    (var);							\
	    (var) = FPN_TAILQ_PREV((var), headname, field))

#define	FPN_TAILQ_INIT(head) do {					\
	FPN_TAILQ_FIRST((head)) = NULL;					\
	(head)->tqh_last = &FPN_TAILQ_FIRST((head));			\
} while (0)

#define	FPN_TAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if ((FPN_TAILQ_NEXT((elm), field) = 				\
	     		FPN_TAILQ_NEXT((listelm), field)) != NULL)	\
		FPN_TAILQ_NEXT((elm), field)->field.tqe_prev = 		\
		    &FPN_TAILQ_NEXT((elm), field);			\
	else								\
		(head)->tqh_last = &FPN_TAILQ_NEXT((elm), field);	\
	FPN_TAILQ_NEXT((listelm), field) = (elm);			\
	(elm)->field.tqe_prev = &FPN_TAILQ_NEXT((listelm), field);	\
} while (0)

#define	FPN_TAILQ_INSERT_BEFORE(listelm, elm, field) do {		\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	FPN_TAILQ_NEXT((elm), field) = (listelm);			\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &FPN_TAILQ_NEXT((elm), field);	\
} while (0)

#define	FPN_TAILQ_INSERT_HEAD(head, elm, field) do {			\
	if ((FPN_TAILQ_NEXT((elm), field) = 				\
	     FPN_TAILQ_FIRST((head))) != NULL)				\
		FPN_TAILQ_FIRST((head))->field.tqe_prev =		\
		    &FPN_TAILQ_NEXT((elm), field);			\
	else								\
		(head)->tqh_last = &FPN_TAILQ_NEXT((elm), field);	\
	FPN_TAILQ_FIRST((head)) = (elm);				\
	(elm)->field.tqe_prev = &FPN_TAILQ_FIRST((head));		\
} while (0)

#define	FPN_TAILQ_INSERT_TAIL(head, elm, field) do {			\
	FPN_TAILQ_NEXT((elm), field) = NULL;				\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &FPN_TAILQ_NEXT((elm), field);		\
} while (0)

#define	FPN_TAILQ_LAST(head, headname)					\
	(*(((struct headname *)((head)->tqh_last))->tqh_last))

#define	FPN_TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define	FPN_TAILQ_PREV(elm, headname, field)				\
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))

#define	FPN_TAILQ_REMOVE(head, elm, field) do {				\
	if ((FPN_TAILQ_NEXT((elm), field)) != NULL)			\
		FPN_TAILQ_NEXT((elm), field)->field.tqe_prev = 		\
		    (elm)->field.tqe_prev;				\
	else								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
	*(elm)->field.tqe_prev = FPN_TAILQ_NEXT((elm), field);		\
} while (0)

/*
 * Circular queue declarations.
 */
#define	FPN_CIRCLEQ_HEAD(name, type)					\
struct name {								\
	struct type *cqh_first;		/* first element */		\
	struct type *cqh_last;		/* last element */		\
}

#define	FPN_CIRCLEQ_HEAD_INITIALIZER(head)				\
	{ (void *)&(head), (void *)&(head) }

#define	FPN_CIRCLEQ_ENTRY(type)						\
struct {								\
	struct type *cqe_next;		/* next element */		\
	struct type *cqe_prev;		/* previous element */		\
}

/*
 * Circular queue functions.
 */
#define	FPN_CIRCLEQ_EMPTY(head)	((head)->cqh_first == (void *)(head))

#define	FPN_CIRCLEQ_FIRST(head)	((head)->cqh_first)

#define	FPN_CIRCLEQ_FOREACH(var, head, field)				\
	for ((var) = FPN_CIRCLEQ_FIRST((head));				\
	    (var) != (void *)(head) || ((var) = NULL);			\
	    (var) = FPN_CIRCLEQ_NEXT((var), field))

#define	FPN_CIRCLEQ_FOREACH_REVERSE(var, head, field)			\
	for ((var) = FPN_CIRCLEQ_LAST((head));				\
	    (var) != (void *)(head) || ((var) = NULL);			\
	    (var) = FPN_CIRCLEQ_PREV((var), field))

#define	FPN_CIRCLEQ_INIT(head) do {					\
	FPN_CIRCLEQ_FIRST((head)) = (void *)(head);			\
	FPN_CIRCLEQ_LAST((head)) = (void *)(head);			\
} while (0)

#define	FPN_CIRCLEQ_INSERT_AFTER(head, listelm, elm, field) do {	\
	FPN_CIRCLEQ_NEXT((elm), field) = 				\
			FPN_CIRCLEQ_NEXT((listelm), field);		\
	FPN_CIRCLEQ_PREV((elm), field) = (listelm);			\
	if (FPN_CIRCLEQ_NEXT((listelm), field) == (void *)(head))	\
		FPN_CIRCLEQ_LAST((head)) = (elm);			\
	else								\
		FPN_CIRCLEQ_PREV(FPN_CIRCLEQ_NEXT((listelm), field), 	\
				 field) = (elm);			\
	FPN_CIRCLEQ_NEXT((listelm), field) = (elm);			\
} while (0)

#define	FPN_CIRCLEQ_INSERT_BEFORE(head, listelm, elm, field) do {	\
	FPN_CIRCLEQ_NEXT((elm), field) = (listelm);			\
	FPN_CIRCLEQ_PREV((elm), field) = 				\
			FPN_CIRCLEQ_PREV((listelm), field);		\
	if (FPN_CIRCLEQ_PREV((listelm), field) == (void *)(head))	\
		FPN_CIRCLEQ_FIRST((head)) = (elm);			\
	else								\
		FPN_CIRCLEQ_NEXT(FPN_CIRCLEQ_PREV((listelm), field), 	\
				 field) = (elm);			\
	FPN_CIRCLEQ_PREV((listelm), field) = (elm);			\
} while (0)

#define	FPN_CIRCLEQ_INSERT_HEAD(head, elm, field) do {			\
	FPN_CIRCLEQ_NEXT((elm), field) = FPN_CIRCLEQ_FIRST((head));	\
	FPN_CIRCLEQ_PREV((elm), field) = (void *)(head);		\
	if (FPN_CIRCLEQ_LAST((head)) == (void *)(head))			\
		FPN_CIRCLEQ_LAST((head)) = (elm);			\
	else								\
		FPN_CIRCLEQ_PREV(FPN_CIRCLEQ_FIRST((head)), 		\
				 field) = (elm);			\
	FPN_CIRCLEQ_FIRST((head)) = (elm);				\
} while (0)

#define	FPN_CIRCLEQ_INSERT_TAIL(head, elm, field) do {			\
	FPN_CIRCLEQ_NEXT((elm), field) = (void *)(head);		\
	FPN_CIRCLEQ_PREV((elm), field) = FPN_CIRCLEQ_LAST((head));	\
	if (FPN_CIRCLEQ_FIRST((head)) == (void *)(head))		\
		FPN_CIRCLEQ_FIRST((head)) = (elm);			\
	else								\
		FPN_CIRCLEQ_NEXT(FPN_CIRCLEQ_LAST((head)), 		\
				 field) = (elm);			\
	FPN_CIRCLEQ_LAST((head)) = (elm);				\
} while (0)

#define	FPN_CIRCLEQ_LAST(head)	((head)->cqh_last)

#define	FPN_CIRCLEQ_NEXT(elm,field)	((elm)->field.cqe_next)

#define	FPN_CIRCLEQ_PREV(elm,field)	((elm)->field.cqe_prev)

#define	FPN_CIRCLEQ_REMOVE(head, elm, field) do {			\
	if (FPN_CIRCLEQ_NEXT((elm), field) == (void *)(head))		\
		FPN_CIRCLEQ_LAST((head)) = 				\
			FPN_CIRCLEQ_PREV((elm), field);			\
	else								\
		FPN_CIRCLEQ_PREV(FPN_CIRCLEQ_NEXT(elm, field), field) =	\
			FPN_CIRCLEQ_PREV((elm), field);			\
	if (FPN_CIRCLEQ_PREV((elm), field) == (void *)(head))		\
		FPN_CIRCLEQ_FIRST((head)) = 				\
			FPN_CIRCLEQ_NEXT((elm), field);			\
	else								\
		FPN_CIRCLEQ_NEXT(FPN_CIRCLEQ_PREV(elm, field), field) =	\
		    FPN_CIRCLEQ_NEXT((elm), field);			\
} while (0)

#endif /* !_FPN_QUEUE_H_ */
