/*
 * Copyright(c) 2007 6WIND
 */
#ifndef _FPN_TIMER_H_
#define	_FPN_TIMER_H_

struct callout;

/*
 * Timer API
 *

 *
 * int callout_init(struct callout *timer);
 *
 * This initializes the callout handle 'timer' for use. No operations
 * can be performed on the callout structure before it is initialized.
 *
 * Return 0 on success.
 *

 *
 * int callout_reset(struct callout *user, unsigned int secs,
 *			void (*function)(void *), void *data);
 *
 * This function resets and starts the callout pointer by 'user'.
 * When the timer wille expire, after 'secs' seconds, the function
 * specified by 'function' will be called with the argument 'data'.
 *
 * Return 0 on success.
 *

 *
 * int callout_stop(struct callout *user);
 *
 * This function stops the callout pointed by 'user'. It may fail if
 * the timer is currently running.
 *
 * Return 1 on success (when timer is pending or stopped)
 * Return 0 on failure (when timer is beeing processed)
 *

 *
 * void callout_stop_sync(struct callout *timer)
 *
 * Loop until callout_stop() is successful
 *

 */


/*
 * Return the number of cycles since boot (this counter is global for all cores)
 *    uint64_t fpn_get_clock_cycles(void)
 *
 * Return the number of cycles since boot (this counter may be local for each core)
 *    uint64_t fpn_get_local_cycles(void)
 *
 * Return the number of cycles since boot (this counter may be local
 * for each core, and is useful for two close measures, but wraps
 * quickly). Arch that define it must also define
 * FPN_HAS_GET_LOCAL_CYCLES_32.
 *    uint32_t fpn_get_local_cycles_32(void)
 *
 * Return the number of cycles in one second
 *    uint64_t fpn_get_clock_hz(void)
 */

#ifndef callout_stop_sync
static inline void callout_stop_sync(struct callout *timer)
{
	while (!callout_stop(timer)) ;
}
#endif

FPN_DECLARE_PER_CORE(struct callout *, running_timer);

#endif /* _FPN_TIMER_H_ */
