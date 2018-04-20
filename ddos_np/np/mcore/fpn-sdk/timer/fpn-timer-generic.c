/*
 * Copyright(c) 2013 6WIND
 * All rights reserved.
 */

#include "fpn.h"
#include "fpn-timer-generic.h"

#if CONFIG_MCORE_TIMER_GENERIC_DEBUG_LEVEL >= 1
#define TIMER_FMT "%p(%s,%d)"
#define TIMER_ID(t) (t), (t)->caller_func, (t)->caller_line
#define CALLOUT_PRINTF(args...) printf(args)
#else
#define CALLOUT_PRINTF(args...)
#endif

#ifdef CONFIG_MCORE_TIMER_GENERIC_TABLE_ORDER
#define FPN_TIMER_TABLE_ORDER CONFIG_MCORE_TIMER_GENERIC_TABLE_ORDER
#else
#define FPN_TIMER_TABLE_ORDER 12
#endif
#define FPN_TIMER_TABLE_SIZE (1<<FPN_TIMER_TABLE_ORDER)
#define FPN_TIMER_TABLE_MASK (FPN_TIMER_TABLE_SIZE-1)

/* How many local cycles in one timer period (timer resolution) */
FPN_DEFINE_SHARED(uint64_t, fpn_timer_cycles_resolution);

struct fpn_timer_table { /* a timer list table */
	struct fpn_timer_list bucket[FPN_TIMER_TABLE_SIZE];
};

static FPN_DEFINE_SHARED(struct fpn_timer_table, timer_table[FPN_MAX_CORES]) __fpn_cache_aligned;

/* lock to protect list access */
struct per_core_lock {
	fpn_spinlock_t lock;
} __fpn_cache_aligned;
static FPN_DEFINE_SHARED(struct per_core_lock, list_lock[FPN_MAX_CORES]);

static FPN_DEFINE_SHARED(struct fpn_timer_list_cache_aligned, immediate_timers[FPN_MAX_CORES]);

void fpn_timer_dump_timers(void);
/* for timers with mode FPN_TIMER_LOCK_NONE, always managed on the same cpu */
static FPN_DEFINE_SHARED(struct fpn_timer_table, local_timer_table[FPN_MAX_CORES]);
static FPN_DEFINE_SHARED(struct fpn_timer_list_cache_aligned, local_immediate_timers[FPN_MAX_CORES]);

/* per-cpu private info for timers */
FPN_DEFINE_SHARED(struct fpn_timer_state, fpn_timer_state[FPN_MAX_CORES]);

/* statistics */
#define __TIMER_STAT_ADD(name, n) do {				\
		unsigned __cpu_id = fpn_get_core_num();		\
		fpn_timer_state[__cpu_id].stats.name += (n);	\
	} while(0)

#define fpn_timer_list_lock(cpu) fpn_spinlock_lock(&list_lock[cpu].lock)
#define fpn_timer_list_unlock(cpu) fpn_spinlock_unlock(&list_lock[cpu].lock)

/*
 * Initialize the timer library.
 */
void
fpn_timer_subsystem_init(void)
{
	CALLOUT_PRINTF("%s()\n", __func__);

	/* init timer resolution */
	uint64_t freq = fpn_get_local_clock_hz();
	int i;

	fpn_timer_cycles_resolution = (freq * TIMER_RESOLUTION_MS) / 1000;

	for (i = 0; i < FPN_MAX_CORES; i++)
		fpn_spinlock_init(&list_lock[i].lock);

}

/*
 * Initialize the timer handle for use
 */
#if CONFIG_MCORE_TIMER_GENERIC_DEBUG_LEVEL >= 1
int callout_init_debug(struct callout *timer,
		const char *caller_func, int caller_line)
#else
	int callout_init(struct callout *timer)
#endif
{
#ifdef CONFIG_MCORE_TIMER_GENERIC_SANITY_CHECK
	/* avoid callout_init on an active timer */
	FPN_ASSERT(timer->magic != FPN_CALLOUT_MAGIC ||
		   timer->status == FPN_TIMER_STOPPED);
#endif

	timer->status = FPN_TIMER_STOPPED;
	timer->cpu_id = fpn_get_core_num();
	timer->flags = 0;

	/* set poison callback pointer */
	timer->f = (void*)0x777777;
	timer->arg = NULL;

	/* by default the callout and its list will be locked by the API */
	callout_setlockmode(timer, FPN_TIMER_LOCK_ALL);

	fpn_spinlock_init(&timer->lock);

#if CONFIG_MCORE_TIMER_GENERIC_DEBUG_LEVEL >= 1
	timer->caller_func = caller_func;
	timer->caller_line = caller_line;
#endif

#ifdef CONFIG_MCORE_TIMER_GENERIC_SANITY_CHECK
	timer->magic = FPN_CALLOUT_MAGIC;
#endif

	CALLOUT_PRINTF("%s("TIMER_FMT")\n", __func__, TIMER_ID(timer));

	return 0;
}

/*
 * Convert cycles to ticks.
 * One tick is TIMER_RESOLUTION_MS milliseconds
 */
static uint64_t cycles_to_ticks(const uint64_t delta_cycles)
{
	uint64_t ticks;
	/* should not return 0: we must not schedule at current_idx */
	ticks = delta_cycles / fpn_timer_cycles_resolution;
	if (ticks == 0)
		return 1;
	else
		return ticks;
}

/*
 * Return the index in table where a timer should be added if it expires
 * in delta_ticks.
 *
 * delta_ticks is modified to the remaining ticks.
 */
static int ticks_to_idx(const int tim_cpu, uint64_t *delta_ticks)
{
	int idx;

	if (unlikely(*delta_ticks >= FPN_TIMER_TABLE_SIZE)) {
		idx = fpn_timer_state[tim_cpu].current_idx - 1;
		*delta_ticks -= FPN_TIMER_TABLE_MASK;
	}
	else {
		idx = fpn_timer_state[tim_cpu].current_idx + *delta_ticks;
		*delta_ticks = 0;
	}
	idx &= FPN_TIMER_TABLE_MASK;
	return idx;
}

/*
 * Reset (start/stop) the timer.
 */
static inline int
timer_reset(struct callout *timer, uint64_t delta_cycles,
	    void (*func)(void *), void *arg)
{
	const int cpu_id = fpn_get_core_num();
	int idx;
	uint64_t ticks;
	struct fpn_timer_list *list;
	int need_callout_lock = timer->flags & FPN_TIMER_F_DO_CALLOUT_LOCK;
	int need_list_lock = timer->flags & FPN_TIMER_F_DO_LIST_LOCK;

	CALLOUT_PRINTF("%s: scheduling timer "TIMER_FMT" on core %d\n",
		       __func__, TIMER_ID(timer), timer->cpu_id);

	/* if func is NULL, it's a callout_stop() */
	if (func == NULL)
		__TIMER_STAT_ADD(stop, 1);
	else
		__TIMER_STAT_ADD(reset, 1);

	if (need_callout_lock)
		fpn_spinlock_lock(&timer->lock);

	/* timer is already stopped, nothing to do */
	if (func == NULL && timer->status == FPN_TIMER_STOPPED) {
		if (need_callout_lock)
			fpn_spinlock_unlock(&timer->lock);
		return 0;
	}

	/* The timer status can become STOPPED here in process_list() */

	/* If timer is not in stopped state, we know that timer->cpu_id
	 * is set to the idx of the table containing the timer */
	if (timer->status != FPN_TIMER_STOPPED) {
		if (need_list_lock)
			fpn_timer_list_lock(timer->cpu_id);

		/* But we have to check again that the timer has not expired in
		 * fpn_timer_process_list() before taking the lock. This is the
		 * only place where it can occur as calling
		 * callout_reset/callout_stop concurrently is not permitted */
		if (timer->status != FPN_TIMER_STOPPED) {
			if (timer->status == FPN_TIMER_RUNNING &&
			    timer->cpu_id != cpu_id) {
				if (need_list_lock)
					fpn_timer_list_unlock(timer->cpu_id);

				if (need_callout_lock)
					fpn_spinlock_unlock(&timer->lock);
				return -1;
			}
#ifdef CONFIG_MCORE_TIMER_GENERIC_SANITY_CHECK
			FPN_ASSERT(timer->inserted == 1);
			timer->inserted = 0;
#endif
			FPN_LIST_REMOVE(timer, next);
			__TIMER_STAT_ADD(pending, -1);
			if (timer->status == FPN_TIMER_RUNNING)
				fpn_timer_state[cpu_id].running_timer_modified = 1;

			if (func == NULL) { /* callout stop */
				timer->status = FPN_TIMER_STOPPED;
				if (need_list_lock)
					fpn_timer_list_unlock(timer->cpu_id);

				if (need_callout_lock)
					fpn_spinlock_unlock(&timer->lock);
				return 0;
			}
		}
		if (need_list_lock)
			fpn_timer_list_unlock(timer->cpu_id);
	}

	/*
	 * The timer status could have become STOPPED in process_list()
	 *  => exit if we are doing a callout_stop().
	 */
	if (func == NULL) {
		if (need_callout_lock)
			fpn_spinlock_unlock(&timer->lock);
		return 0;
	}


	timer->f = func;
	timer->arg = arg;
	timer->status = FPN_TIMER_PENDING;


#ifdef CONFIG_MCORE_TIMER_GENERIC_SANITY_CHECK
	FPN_ASSERT(timer->inserted == 0);
	timer->inserted = 1;
#endif
	__TIMER_STAT_ADD(pending, 1);

	/* set the local cpu if the timer is not bound */
	if (! timer->flags & FPN_TIMER_F_BOUND)
		timer->cpu_id = cpu_id;

	if (delta_cycles == 0) {
		timer->remaining_ticks = 0;
		if (need_list_lock) {
			fpn_timer_list_lock(timer->cpu_id);
			list = &immediate_timers[timer->cpu_id].list;
			FPN_LIST_INSERT_HEAD(list, timer, next);
			fpn_wmb();
			fpn_timer_state[timer->cpu_id].immediate_list_pending = 1;
			fpn_timer_list_unlock(timer->cpu_id);
		} else {
			list = &local_immediate_timers[timer->cpu_id].list;
			FPN_LIST_INSERT_HEAD(list, timer, next);
			fpn_wmb();
			fpn_timer_state[timer->cpu_id].immediate_local_list_pending = 1;
		}
	} else {
		ticks = cycles_to_ticks(delta_cycles);
		timer->remaining_ticks = ticks;
		idx = ticks_to_idx(timer->cpu_id, &timer->remaining_ticks);

		if (need_list_lock) {
			fpn_timer_list_lock(timer->cpu_id);
			list = &timer_table[timer->cpu_id].bucket[idx];
			FPN_LIST_INSERT_HEAD(list, timer, next);
			fpn_timer_list_unlock(timer->cpu_id);
		} else {
			list = &local_timer_table[timer->cpu_id].bucket[idx];
			FPN_LIST_INSERT_HEAD(list, timer, next);
		}
	}
	if (need_callout_lock)
		fpn_spinlock_unlock(&timer->lock);

	return 0;
}

/*
 * Stop the timer.
*/
int callout_stop(struct callout *timer)
{
	return !timer_reset(timer, 0, NULL, NULL);
}

/*
 * Schedule a timer for an expiry in seconds.
 */
int callout_reset(struct callout *timer, unsigned int secs,
		  void (*func)(void *), void *arg)
{
	uint64_t cycles = secs * fpn_get_local_clock_hz();
	return timer_reset(timer, cycles, func, arg);
}

/*
 * Schedule a timer for an expiry in milliseconds.
 */
int callout_reset_millisec(struct callout *timer, unsigned int msecs,
		  void (*func)(void *), void *arg)
{
	uint64_t cycles = (msecs * fpn_get_local_clock_hz()) / 1000;
	return timer_reset(timer, cycles, func, arg);
}

/*
 * Set a timer callback function and argument.
 */
void callout_setfunc(struct callout *timer,
		void (*func)(void *), void *arg)
{
	CALLOUT_PRINTF("%s("TIMER_FMT")\n", __func__, TIMER_ID(timer));

	timer->f = func;
	timer->arg = arg;
}

/*
 * Schedule a timer for an expiry in seconds.
 */
int callout_schedule(struct callout *timer, unsigned int secs)
{
	uint64_t cycles = secs * fpn_get_local_clock_hz();
	int res;

	CALLOUT_PRINTF("%s("TIMER_FMT")\n", __func__, TIMER_ID(timer));

	res = timer_reset(timer, cycles, timer->f, timer->arg);
	return res;
}

/*
 * Schedule a timer for an expiry in milliseconds.
 */
int callout_schedule_millisec(struct callout *timer, unsigned int msecs)
{
	uint64_t cycles = (msecs * fpn_get_local_clock_hz()) / 1000;
	int res;

	CALLOUT_PRINTF("%s("TIMER_FMT")\n", __func__, TIMER_ID(timer));

	res = timer_reset(timer, cycles, timer->f, timer->arg);
	return res;
}

/*
 * Schedule a timer for an expiry in cycles.
 */
int callout_schedule_cycles(struct callout *timer, uint64_t cycles)
{
	int res;

	CALLOUT_PRINTF("%s("TIMER_FMT")\n", __func__, TIMER_ID(timer));

	res = timer_reset(timer, cycles, timer->f, timer->arg);
	return res;
}

/*
 * Test the PENDING status of the timer handle timer.
 */
int callout_pending(const struct callout *timer)
{
	return timer->status == FPN_TIMER_PENDING;
}

/*
 * Test the ACTIVE status of the timer handle.
 */
int callout_active(const struct callout *timer)
{
	return (timer->status == FPN_TIMER_PENDING ||
		timer->status == FPN_TIMER_RUNNING);
}

/*
 * Process the callout list.
 */
static inline void
fpn_timer_process_list(struct fpn_timer_table *table,
		       struct fpn_timer_list *list, int my_cpu, int need_lock)
{
	struct callout *timer;
	int idx;
	struct fpn_timer_list todo = FPN_LIST_HEAD_INITIALIZER(todo);

	/* Move list contents to our todo list. We won't process more timers
	 * than that to avoid potentially looping forever. */
	FPN_LIST_MOVE(list, &todo, next);

	/* for each timer of 'expired' list, check state and execute callback */
	while ((timer = FPN_LIST_FIRST(&todo)) != NULL) {

		/* we need to check if the timer really expired or if it
		 * should be reloaded for later. */
		if (unlikely(timer->remaining_ticks > 0)) {
			FPN_LIST_REMOVE(timer, next);
			idx = ticks_to_idx(my_cpu, &timer->remaining_ticks);
			FPN_LIST_INSERT_HEAD(&table->bucket[idx], timer, next);
			continue;
		}

		timer->status = FPN_TIMER_RUNNING;
		fpn_timer_state[my_cpu].running_timer_modified = 0;
		fpn_timer_state[my_cpu].running_timer = timer;

		/* Move timer back into the list in case it modifies itself.
		 * We don't want to see it again in this loop but it must be
		 * kept for the next one. */
		FPN_LIST_REMOVE(timer, next);
		FPN_LIST_INSERT_HEAD(list, timer, next);

		if (need_lock)
			fpn_timer_list_unlock(my_cpu);

		/* execute callback function with list unlocked */
		(*timer->f)(timer->arg);

		if (need_lock)
			fpn_timer_list_lock(my_cpu);

		fpn_timer_state[my_cpu].running_timer = NULL;

		/* the timer was stopped or reloaded by the callback
		 * function, we have nothing to do here */
		if (fpn_timer_state[my_cpu].running_timer_modified == 1)
			continue;

		/* remove from done list and mark timer as stopped */
		FPN_LIST_REMOVE(timer, next);
#ifdef CONFIG_MCORE_TIMER_GENERIC_SANITY_CHECK
		FPN_ASSERT(timer->inserted == 1);
		timer->inserted = 0;
#endif
		__TIMER_STAT_ADD(pending, -1);
		timer->status = FPN_TIMER_STOPPED;
	}
}

void fpn_timer_process_immediate(int my_cpu)
{
#if CONFIG_MCORE_TIMER_GENERIC_DEBUG_LEVEL >= 2
	CALLOUT_PRINTF("%s: core=%d time=%"PRIu64"\n", __FUNCTION__,
		       my_cpu, fpn_get_clock_cycles());
#endif
	/* execute the cb of mp-safe expired timers (the list lock will
	 * be temporarily released by the callee) */
	if (fpn_timer_state[my_cpu].immediate_list_pending) {
		fpn_rmb();
		fpn_timer_state[my_cpu].immediate_list_pending = 0;
		fpn_timer_list_lock(my_cpu);
		fpn_timer_process_list(NULL, &immediate_timers[my_cpu].list,
				       my_cpu, 1);
		fpn_timer_list_unlock(my_cpu);
	}

	/* execute the cb of expired mp-unsafe timers without locks */
	if (fpn_timer_state[my_cpu].immediate_local_list_pending) {
		fpn_rmb();
		fpn_timer_state[my_cpu].immediate_local_list_pending = 0;
		fpn_timer_process_list(NULL, &local_immediate_timers[my_cpu].list,
				       my_cpu, 0);
	}
}

/*
 * Called by fpn_timer_process_tables() periodically (the period is the timer
 * resolution) to process non-immediate timers.
 */
void fpn_timer_process_tables(int my_cpu)
{
	struct fpn_timer_table *table;
	int idx;

#if CONFIG_MCORE_TIMER_GENERIC_DEBUG_LEVEL >= 2
	CALLOUT_PRINTF("%s: core=%d time=%"PRIu64"\n", __FUNCTION__,
		       my_cpu, fpn_get_local_cycles());
#endif
	fpn_timer_list_lock(my_cpu);
	/* increase current table index, and save current time */
	idx = fpn_timer_state[my_cpu].current_idx;
	idx ++;
	idx &= FPN_TIMER_TABLE_MASK;
	fpn_timer_state[my_cpu].current_idx = idx;

	/* execute the cb of expired timers (the list lock will
	 * be temporarily released by the callee) */
	table = &timer_table[my_cpu];
	fpn_timer_process_list(table, &table->bucket[idx], my_cpu, 1);

	/* job finished, unlock the list lock */
	fpn_timer_list_unlock(my_cpu);

	/* execute the cb of expired local timers without locks */
	table = &local_timer_table[my_cpu];
	fpn_timer_process_list(table, &table->bucket[idx], my_cpu, 0);
}

/*
 * Set locking mode.
 */
void callout_setlockmode(struct callout *timer, fpn_timer_mode mode)
{
	switch (mode) {
	case FPN_TIMER_LOCK_NONE:
		timer->flags &= ~FPN_TIMER_F_DO_CALLOUT_LOCK;
		timer->flags &= ~FPN_TIMER_F_DO_LIST_LOCK;
		break;
	case FPN_TIMER_LOCK_LIST:
		timer->flags &= ~FPN_TIMER_F_DO_CALLOUT_LOCK;
		timer->flags |= FPN_TIMER_F_DO_LIST_LOCK;
		break;
	default: /* FPN_TIMER_LOCK_ALL */
		timer->flags |= FPN_TIMER_F_DO_LIST_LOCK;
		timer->flags |= FPN_TIMER_F_DO_CALLOUT_LOCK;
	}
}

/*
 * Bind a timer so that it will only execute on one CPU
 * Must be called when timer is stopped.
 */
int callout_bind(struct callout *timer, unsigned int cpu_id)
{
	CALLOUT_PRINTF("%s("TIMER_FMT")\n", __FUNCTION__, TIMER_ID(timer));

	if (timer->flags & FPN_TIMER_F_DO_CALLOUT_LOCK)
		fpn_spinlock_lock(&timer->lock);

	if (timer->status != FPN_TIMER_STOPPED) {
		if (timer->flags & FPN_TIMER_F_DO_CALLOUT_LOCK)
			fpn_spinlock_unlock(&timer->lock);
		return -1;
	}

	timer->cpu_id = cpu_id;
	timer->flags |= FPN_TIMER_F_BOUND;

	if (timer->flags & FPN_TIMER_F_DO_CALLOUT_LOCK)
		fpn_spinlock_unlock(&timer->lock);
	return 0;
}

/*
 * Unbind a timer that was bound to a specific cpu.
 */
void callout_unbind(struct callout *timer)
{
	CALLOUT_PRINTF("%s("TIMER_FMT")\n", __func__, TIMER_ID(timer));
	timer->flags &= ~FPN_TIMER_F_BOUND;
}

/*
 * Dump timer statistics
 */
void fpn_timer_dump_stats(void)
{
	struct fpn_timer_debug_stats sum;
	int cpu_id;

	memset(&sum, 0, sizeof(sum));
	for (cpu_id = 0; cpu_id < FPN_MAX_CORES; cpu_id++) {
		sum.reset += fpn_timer_state[cpu_id].stats.reset;
		sum.stop += fpn_timer_state[cpu_id].stats.stop;
		sum.pending += fpn_timer_state[cpu_id].stats.pending;
	}

	fpn_printf("Timer statistics:\n");
	fpn_printf("  reset = %"PRIu64"\n", sum.reset);
	fpn_printf("  stop = %"PRIu64"\n", sum.stop);
	fpn_printf("  pending = %"PRIu64"\n", sum.pending);
}
