/*
 * Copyright(c) 2013 6WIND
 * All rights reserved.
 */

#ifndef __FPN_TIMER_GENERIC_H__
#define __FPN_TIMER_GENERIC_H__
#include "fpn-lock.h"

/**
 * @file
 * FPN Timer
 *
 * This library provides a timer service to the Fast-Path.
 *
 * - The timers can be loaded from one core and executed on another. It has
 *   to be specified by callout_bind() function.
 * - High precision (depends on the call frequency to
 *   fpn_timer_process_tables() that checks the timer expiration
 *   for the local core).
 *   The precision of the timers is configurable with
 *   MCORE_TIMER_RESOLUTION_MS option as well as the number of timer
 *   slots (MCORE_TIMER_TABLE_ORDER).
 *
 * This library provides an interface to add, delete and restart timers.
 * The API is based on the BSD callout(9) with few differences.
 *
 * It is important to notice that all calls to the API functions such as
 * callout_reset() and callout_stop() have to be protected by locks if called
 * from different cpus.
 * No conrurrent calls to these functions are allowed without locking.
 *
 * The user can free the callout structure if the timer is in stopped state.
 * This is also true in the callback function after the user calls
 * callout_stop().
 *
 */

/*
 * A structure describing a timer.
 */
struct callout
{
	FPN_LIST_ENTRY(callout) next; /* Next and prev in list. */
	void (*f)(void*);         /* Callback function. */
	void *arg;                /* Argument to callback function. */

	uint64_t remaining_ticks; /* != 0 if a pending timer should be
				   * reloaded later by
				   * fpn_timer_process_tables() instead of
				   * being executed */

#define FPN_TIMER_STOPPED 0       /* State: timer is stopped. */
#define FPN_TIMER_PENDING 1       /* State: timer is scheduled. */
#define FPN_TIMER_RUNNING 2       /* State: timer function is running. */
	uint8_t status;

#define FPN_TIMER_F_BOUND           0x01  /* Callout is bound to a cpu */
#define FPN_TIMER_F_DO_CALLOUT_LOCK 0x02  /* Callout is locked by the API */
#define FPN_TIMER_F_DO_LIST_LOCK    0x04  /* Callout list is locked by the API */
	uint8_t flags;

	int16_t cpu_id;           /* CPU on which the cb should be executed */
	fpn_spinlock_t lock;      /* Callout lock */


#if CONFIG_MCORE_TIMER_GENERIC_DEBUG_LEVEL >= 1
	const char *caller_func;
	int caller_line;
#endif

#ifdef CONFIG_MCORE_TIMER_GENERIC_SANITY_CHECK
#define FPN_CALLOUT_MAGIC 0xAAAA
	uint32_t magic;
	int32_t inserted;
#endif
};

FPN_LIST_HEAD(fpn_timer_list, callout);
struct fpn_timer_list_cache_aligned {
	struct fpn_timer_list list __fpn_cache_aligned;
};

/*
 * A structure that stores the timer statistics (per-cpu).
 */
struct fpn_timer_debug_stats {
	uint64_t reset;   /* Number of success calls to timer_reset(). */
	uint64_t stop;    /* Number of success calls to callout_stop(). */
	uint64_t pending; /* Number of pending/running timers. */
};

/*
 * A structure that stores the timer state percpu.
 */
struct fpn_timer_state {
	int current_idx; /* current index in the table */

	struct callout *running_timer; /* timer currently running */

	/* true if a running timer was reset on the same core
	   as it is being processed on */
	int running_timer_modified;

	/* true if an immediate timer is pending */
	int immediate_list_pending;
	int immediate_local_list_pending;

	/* per-core statistics */
	struct fpn_timer_debug_stats stats;
} __fpn_cache_aligned;

FPN_DECLARE_SHARED(struct fpn_timer_state[FPN_MAX_CORES], fpn_timer_state);

/*
 * Timer resolution in milliseconds. This sets the timer expiry slot duration.
 */
#ifdef CONFIG_MCORE_TIMER_GENERIC_RESOLUTION_MS
#define TIMER_RESOLUTION_MS CONFIG_MCORE_TIMER_GENERIC_RESOLUTION_MS
#else
#define TIMER_RESOLUTION_MS 10
#endif

typedef enum {
	FPN_TIMER_LOCK_NONE,
	FPN_TIMER_LOCK_LIST,
	FPN_TIMER_LOCK_ALL,
} fpn_timer_mode;

/*
 *  How many local cycles in one timer period (timer resolution)
*/
FPN_DECLARE_SHARED(uint64_t, fpn_timer_cycles_resolution);

/*
 * Initialize the timer library.
 *
 * Initializes internal variables (list, locks and so on) for the
 * timer library.
 *
 * Must be called by only one core
 */
void fpn_timer_subsystem_init(void);

/*
 * Initialize a callout handle.
 *
 * The callout_init() function initializes the timer handle *timer*
 * for use. No operations can be performed on the timer before it is
 * initialized.
 *
 * param timer
 *   The timer to initialize.
 */
#if CONFIG_MCORE_TIMER_GENERIC_DEBUG_LEVEL >= 1
#define callout_init(timer) \
	callout_init_debug(timer, __func__, __LINE__)
int
callout_init_debug(struct callout *timer,
		const char *caller_func, int caller_line);
#else
int
callout_init(struct callout *timer);
#endif

/*
 * Reset and schedule the timer associated with the timer handle.
 *
 * The callout_reset() function resets and schedules the timer
 * associated with the timer handle *timer*. When the timer expires after
 * *secs* seconds, the function specified by *func* will be called
 * with the argument *arg* on the current core or the core specified by
 * callout_bind().
 *
 * If the timer associated with the timer handle is already running
 * (in the RUNNING state), the function will fail. The user has to check
 * the return value of the function to see if there is a chance that the
 * timer is in the RUNNING state.
 *
 * If the timer is pending or stopped, it will be rescheduled with the
 * new parameters.
 *
 * param timer
 *   The timer handle.
 * param secs
 *   The number of seconds before the callback function is called.
 * param func
 *   The callback function of the timer.
 * param arg
 *   The user argument of the callback function.
 * return
 *   - 0: Success; the timer is scheduled.
 *   - (-1): Timer is in the RUNNING state.
 */
int
callout_reset(struct callout *timer, unsigned int secs,
		  void (*func)(void *), void* arg);

/*
 * Reset and schedule the timer associated with the timer handle.
 *
 * This function does the same as callout_reset(), except that the
 * time is given in milliseconds instead of seconds.
 */
int
callout_reset_millisec(struct callout *timer, unsigned int ms,
			   void (*func)(void *), void *arg);

/*
 * Reset and schedule the timer associated with the timer handle.
 *
 * This function does the same as callout_reset(), except that the
 * time is given in local clock cycles instead of seconds.
 */
int
callout_reset_cycles(struct callout *timer, uint64_t cycles,
			void (*func)(void *), void *arg);


/*
 * Set the timer callback function and argument.
 *
 * The callout_setfunc() function sets the callback function and argument
 * associated with the timer handle *timer*.
 *
 * The timer may then be scheduled for expiry via the callout_schedule
 * or callout_schedule_millisec functions.
 *
 * When the timer expires, the function specified by *func* will be called
 * with the argument *arg* on the current core or the core specified by
 * callout_bind().
 *
 * This function must only be called when the timer is stopped.
 *
 * param timer
 *   The timer handle.
 * param func
 *   The callback function of the timer.
 * param arg
 *   The user argument of the callback function.
 */
void
callout_setfunc(struct callout *timer,
		void (*func)(void *), void *arg);

/*
 * Schedule the timer associated with the timer handle.
 *
 * The callout_schedule() function schedules the timer associated with
 * the timer handle *timer*.
 *
 * The callback function and argument must have been primarily set by a
 * call to callout_setfunc, callout_reset or callout_reset_millisec.
 *
 * When the timer expires after *secs* seconds, the pre-configured callback
 * function function will be called with the preconfigured argument
 * on the current core or the core specified by callout_bind().
 *
 * If the timer associated with the timer handle is already running
 * (in the RUNNING state), the function will fail. The user has to check
 * the return value of the function to see if there is a chance that the
 * timer is in the RUNNING state.
 *
 * If the timer is pending or stopped, it will be rescheduled with the
 * new parameters.
 *
 * param timer
 *   The timer handle.
 * param secs
 *   The number of seconds before the callback function is called.
 * param func
 *   The callback function of the timer.
 * param arg
 *   The user argument of the callback function.
 * return
 *   - 0: Success; the timer is scheduled.
 *   - (-1): Timer is in the RUNNING state.
 */
int
callout_schedule(struct callout *timer, unsigned int secs);

/*
 * Schedule the timer associated with the timer handle.
 *
 * This function does the same as callout_schedule(), except that the
 * time is given in milliseconds instead of seconds.
 */
int
callout_schedule_millisec(struct callout *timer, unsigned int ms);

/*
 * Schedule the timer associated with the timer handle.
 *
 * This function does the same as callout_schedule(), except that the
 * time is given in local clock cycles instead of seconds.
 */
int
callout_schedule_cycles(struct callout *timer, uint64_t cycles);

/*
 * Stop a timer.
 *
 * The callout_stop() function stops the timer associated with the
 * timer handle *timer*. It may fail if the timer is currently running.
 *
 * If the timer is pending or stopped (for instance, already expired),
 * the function will succeed. The timer handle *timer* must have been
 * initialized using callout_init(), otherwise, undefined behavior
 * will occur.
 *
 * This function can be called safely from a timer callback. If it
 * succeeds, the timer is not referenced anymore by the timer library
 * and the timer structure can be freed (even in the callback
 * function).
 *
 * param timer
 *   The timer handle.
 * return
 *   - 1: Success; the timer is stopped.
 *   - 0: Failure, the timer is in the RUNNING state.
 */
int
callout_stop(struct callout *timer);

/*
 * Test if a timer is pending.
 *
 * The callout_pending() function tests the PENDING status
 * of the timer handle *timer*. A PENDING timer is one that has been
 * scheduled and whose function has not yet been called.
 *
 * param timer
 *   The timer handle.
 * return
 *   - 0: The timer is not pending.
 *   - 1: The timer is pending.
 */
int
callout_pending(const struct callout *timer);

/*
 * Test if a timer is active.
 *
 * The callout_pending() function tests the PENDING or RUNNING status
 * of the timer handle *timer*. A PENDING timer is one that has been
 * scheduled and whose function has not yet been called.
 * A RUNNING timer is one that has expired and whose callback function is
 * being executed.
 *
 * param timer
 *   The timer handle.
 * return
 *   - 0: The timer is not active.
 *   - 1: The timer is active.
 */
int
callout_active(const struct callout *timer);

/*
 * Set locking mode.
 * Two modes are currently available:
 * FPN_TIMER_LOCK_NONE, FPN_TIMER_LOCK_LIST and FPN_TIMER_LOCK_ALL.
 *
 * The FPN_TIMER_LOCK_NONE mode assumes that callout locking will
 * be handled by the user (not by the API). The callouts with this
 * mode have to be set and managed always on the same core.
 *
 * The FPN_TIMER_LOCK_LIST mode allows setting up a callout on one core
 * and reset it on a different one. The API uses an internal lock to be
 * able to move a callout from one core to another or reset a callout
 * from any core.
 *
 * The FPN_TIMER_LOCK_ALL mode uses an internal lock to the API
 * for each callout. Only this mode allows concurrent calls of the API
 * functions.
 *
 * param timer
 *   The timer handle.
 * param mode
 *   The locking mode.
 */
void
callout_setlockmode(struct callout *timer, fpn_timer_mode mode);

/*
 * Bind the timer to a core
 *
 * Bind the timer handle to the specified core. If core if < 0, then
 * the timer is nomore bound to a core and will expire on the core on which
 * it is armed.
 *
 * This function must only be called when the timer is stopped. Changing
 * the callback function or argument when the timer in the RUNNING state
 * may cause adverse effects.
 *
 * This function will set the FPN_TIMER_F_BOUND flag in the
 * callout structure.
 *
 * param timer
 *   The timer handle.
 * param cpu_id
 *   The cpu_id on which the timer callback will be executed. If it is -1,
 *   then the timer callback will be executed on the core on which it was
 *   scheduled. If the cpu_id does not reference an online CPU, then the
 *   timer will never expire.
 * return
 * - 0: The timer has been successfully bound.
 * - (-1): Binding the timer to cpu_id has failed.
 */
int
callout_bind(struct callout *timer, unsigned int cpu_id);

/*
 * Unbind a timer that was bound to a specific cpu.
 * param timer
 *   The timer handle.
 * return
 *   - 0: On success.
 *   - 1: On failure.
 */
void
callout_unbind(struct callout *timer);

/*
 * Return current running timer of the current core
 *
 * return
 *   the timer handle or NULL if no timer is running
 */
static inline struct callout *callout_get_current(void)
{
	return fpn_timer_state[fpn_get_core_num()].running_timer;
}

/*
 * Called by fpn_timer_process_tables() periodically (the period is the timer
 * resolution) to process non-immediate timers.
 *
 * param my_cpu
 *   The cpu on which the timers will be executed.
 */
void
fpn_timer_process_tables(int my_cpu);

/*
 * Called by the main loops in case there are immediate timers
 * to invoke. The immediate timers function callbacks are called
 * as fast as possible without any delay. A flag is checked in all
 * main loops to see if there are any pending immediate timers.
 */
void
fpn_timer_process_immediate(int my_cpu);

/*
 * Timer statistics function.
 */
void
fpn_timer_dump_stats(void);

#endif /* __FPN_TIMER_GENERIC_H__ */
