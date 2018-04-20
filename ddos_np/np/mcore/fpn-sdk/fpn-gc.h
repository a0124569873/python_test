/*
 * Copyright(c) 2011 6WIND, All rights reserved.
 */

#ifndef __FPN_GC_H_
#define __FPN_GC_H_

/** 
 * This file provide a way to delay an operation until all cores have
 * finished their current work
 */

/**
 * Garbage collector object
 */
struct fpn_gc_object {
	FPN_SLIST_ENTRY(fpn_gc_object) next;    /**< Used to link objects      */
	void (*action)(struct fpn_gc_object *); /**< Called on garbage collect */
} __attribute__((aligned(8)));


/**
 * Add an item to garbage collector
 *
 * This function is used to add an item to garbage collector. Once 
 * we are sure that all cores have exited critical section at least once
 * since call to fpn_gc, the 'action' function is called with 'obj'
 * as unique argument.
 *
 * @param[in] obj
 *   Object to add to garbage collector
 * @param[in] action
 *   Function called on the specified object once garbage collection
 *   is done
 */
void fpn_gc(struct fpn_gc_object *obj, void (*action)(struct fpn_gc_object *));

/**
 * Initialize garbage collector
 *
 * This function initializes the garbage collector
 *
 * @return
 *   0 or -1 on error
 */
int fpn_gc_init(void);

#endif
