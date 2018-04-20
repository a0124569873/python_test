/*
 * Copyright(c) 2011 6WIND, All rights reserved.
 */

#include "fpn.h"
#include "fpn-gc.h"

/* List of objects */
FPN_SLIST_HEAD(fpn_gc_objlist, fpn_gc_object);

/**
 * Per core private structure
 */
struct fpn_gc_private {
	/* Snapshot of of all cores state */
	fpn_core_state_t core_state_copy[FPN_MAX_CORES];

	/* List where objects are put when the application calls fpn_gc() */
	struct fpn_gc_objlist delayed_list;

	/* Objects are moved in this list from
	 * delayed_list at the same time than core state copy */
	struct fpn_gc_objlist current_list;

	/* Timer */
	struct callout gctimer;
} __fpn_cache_aligned;

static FPN_DEFINE_SHARED(struct fpn_gc_private[FPN_MAX_CORES], priv);

/**
 * Copy cores state snapshot in per core priv structure
 */
static void fpn_gc_copy_core_state(int cpuid)
{
	int n;
	volatile fpn_core_state_t *core_state;

	/* For each core */
	for (n = 0; n < FPN_MAX_CORES; n++) {

		/* Get core state */
		core_state = &fpn_core_state[n];

		/* Save core state in local core snapshot */
		priv[cpuid].core_state_copy[n].state = core_state->state;
		priv[cpuid].core_state_copy[n].exitcnt = core_state->exitcnt;

		/* We need to know if the core has not reset its state during
		 * the copy. We only have to care about 1->0 transition, not
		 * 0->1, because in this case it has been done after storing the
		 * list of element, which was not accessible when he put its
		 * state to 1. */
		if (priv[cpuid].core_state_copy[n].state != core_state->state)
			priv[cpuid].core_state_copy[n].state = 0;
	}
}

/**
 * return 1 if all cores returned at least once in mainloop since we
 * copied core_state
 */
static int fpn_gc_check(int cpuid)
{
	int n;
	volatile fpn_core_state_t *core_state;

	/* For each core */
	for (n = 0; n < FPN_MAX_CORES; n++) {

		/* Get core state */
		core_state = &fpn_core_state[n];

		/* If core is in critical section */
		if (priv[cpuid].core_state_copy[n].state == 1) {
			/* Core is still busy */
			if (priv[cpuid].core_state_copy[n].exitcnt == core_state->exitcnt)
				return 0;

			/* Core has exited critical section at least once since snapshot */
			/* was taken, so it is not critical anymore */
			priv[cpuid].core_state_copy[n].state = 0;
		}
	}

	/* All cores exited critical sections at least once */
	return 1;
}

/**
 * If all cores returned at least once in mainloop since the objects
 * were moved in the per-core "current_list", call 'action' procedure
 * on all the objects in this list, reload current_list with delayed_list
 * that was filled in the meantime, take a snapshot and reschedule fpn_gc_cb().
 * Else, just reschedule fpn_gc_cb() on the same list later on this core.
 * This function is executed by a timer callback on each running core.
 */
static void fpn_gc_cb(void *arg)
{
	struct fpn_gc_object *cur, *next;
	int cpuid = (long)arg;

	/* Check that all cores exit critical section */
	if (!fpn_gc_check(cpuid)) {
		callout_reset_millisec(&priv[cpuid].gctimer, 10, fpn_gc_cb,
				       (void *)(long)cpuid);
		return;
	}

	/* Call 'action' on each elements of current list */
	FPN_SLIST_FOREACH_SAFE(cur, next, &priv[cpuid].current_list, next) {
		FPN_SLIST_REMOVE(&priv[cpuid].current_list, cur,
				 fpn_gc_object, next);
		cur->action(cur);
	}

	/* Move next list of items to process */
	FPN_SLIST_MOVE(&priv[cpuid].delayed_list, &priv[cpuid].current_list);

	/* Get current snapshot */
	fpn_gc_copy_core_state(cpuid);

	/* reload fpn_gc_cb in 10 ms */
	callout_reset_millisec(&priv[cpuid].gctimer, 10, fpn_gc_cb,
			       (void *)(long)cpuid);
}

/**
 * Called by an application to postpone an action to do on an object 
 * (generally a free procedure) once we are sure that all cores are
 * out of any critical sections.
 */
void fpn_gc(struct fpn_gc_object *obj, void (*action)(struct fpn_gc_object *))
{
	int cpuid = fpn_get_core_num();

	/* Store callback procedure */
	obj->action = action;
	FPN_SLIST_INSERT_HEAD(&priv[cpuid].delayed_list, obj, next);
}

/**
 * Initialize garbage collector service
 */
int fpn_gc_init(void)
{
	int rank, corecount, cpuid;

	/* Get fastpath cores number */
	corecount = fpn_get_online_core_count();

	for (rank = 0; rank < corecount; rank++) {
		/* Get CPU id */
		cpuid = fpn_get_online_core_num(rank);

		/* Initialize lists */
		FPN_SLIST_INIT(&priv[cpuid].delayed_list);
		FPN_SLIST_INIT(&priv[cpuid].current_list);

		/* Get initial snapshot */
		fpn_gc_copy_core_state(cpuid);

		/* Start timer */
		callout_init(&priv[cpuid].gctimer);
		callout_bind(&priv[cpuid].gctimer, cpuid);
		callout_reset_millisec(&priv[cpuid].gctimer, 10, fpn_gc_cb,
				       (void *)(long)cpuid);
	}

	return 0;
}
