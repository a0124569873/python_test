/*
 * Copyright(c) 2013 6WIND
 * All rights reserved.
 */

#include "timer/fpn-timer-test.h"

/*
 * Test application for timer implementation.
 *
 * A finite number of callouts is allocated (TEST_FPN0_NB_CALLOUTS).
 * The first check loads the lockless timers + immediate timers.
 * They are all loaded on the same core. (An immediate timer == timer
 * with an expiry of 0).
 * In this check
 *  - random functions are set as callbacks expect the functions
 *    CB_FUNC_STOP_RANDOM and CB_FUNC_RESET because they can
 *    reschedule timers on different cores. Since we're lockless, it's
 *    forbidden.
 *  - random timeouts are set (if timeout == 0 => an immediate timer is
 *    created.
 *  - a timer is set. It will check after expiration if all previous
 *    callouts have executed their callback functions.
 *    If this is the case the next checks are performed.
 *
 * After the check of the local and immediate timers,
 * the first stage check is performed.
 * In this check
 *  -  random functions are set as callbacks.
 *     There are currently 5 test functions that are randomly picked
 *      as callbacks,
 *  - random timeouts are set,
 *  - a timer is set. It will check after expiration if all previous
 *    callouts have executed their callback functions.
 *    If this is the case the second stage check is performed.
 *
 * The second stage check does the same as the first stage check except
 * that it mixes the callouts on all available cores.
 * The goal of this check is to stress reschduling pending timers on
 * different cores, stopping them before they have a chance to expire
 * and trying to relauch stopped, running and pending timers.

 * If the checks succeed, they are all re-run with internal API locks
 * which allow concurrent calls to the callout_*() functions from all cores.
 *
 * If internal API locking is not used, the timer API expects us not to call
 * callout_*() functions simultaneously from different cores.
 * Thus each timer has a lock in struct callout_timer_ctx for this case.
 */

//#define TIMER_CALLOUT_CHECK_DEBUG
//#define ENDLESS_CHECK
#ifdef TIMER_CALLOUT_CHECK_DEBUG
#define NB_CALLOUTS 4
#else
#define NB_CALLOUTS (1 << 18)
#endif

#define TIMER_RETRY_STOP 2
#define TIMER_TIMEOUT 10
static FPN_DEFINE_SHARED(int, need_lock);

#define LOCK_CTX(ctx)					\
	((!need_lock) ?					\
	 fpn_spinlock_lock(&ctx->lock) :		\
	 (void)0)

#define UNLOCK_CTX(ctx)					\
	((!need_lock) ?					\
	 fpn_spinlock_unlock(&ctx->lock) :		\
	 (void)0);

enum callout_cb {
	CB_FUNC_RESET,
	CB_FUNC_STOP,
	CB_FUNC_STOP_RANDOM,
	CB_FUNC_RESCHEDULE,
	CB_FUNC_VOID,
	CB_FUNC_MAX,
};

typedef enum {
	TIM_STOPPED,
	TIM_RUNNING,
} callout_status;

struct callout_timer_ctx {
	struct callout timer;
	int cpu;
	callout_status status;
	fpn_spinlock_t lock;
};

struct callout_stats {
	int cb;
	int reset;
	int reset_fails;
};

static FPN_DEFINE_SHARED(struct callout_timer_ctx *, callouts);
static FPN_DEFINE_SHARED(struct callout, end_timer);
static FPN_DEFINE_SHARED(struct callout_stats, fpn_cb_counters[FPN_MAX_CORES]);
static FPN_DEFINE_SHARED(void (*)(void *), cb_funcs[CB_FUNC_MAX]);
static FPN_DEFINE_SHARED(int, retries) = TIMER_RETRY_STOP;
static void relaunch_api_check(void *);
static void timer_callouts_basic_check(void);

/*
 * Callback function that resets a timer with a randomly picked function as
 * new callback. The timer timeout is set randomly picked as well.
 */
static void cb_reset(void *arg)
{
	struct callout_timer_ctx *ctx;
	struct callout *timer;
	int cpuid, rank, timeout, f;
	int maxrank = fpn_get_online_core_count();
	int mycpu = fpn_get_core_num();
	int ctx_cpu, ret = 0;

	fpn_cb_counters[mycpu].reset++;

	ctx = (struct callout_timer_ctx *) arg;
	timer = &ctx->timer;
	ctx_cpu = ctx->cpu;

	if (ctx_cpu == -1) {
		/* set pseudo random core number */
		rank = fpn_get_clock_cycles() % maxrank;
		cpuid = fpn_get_online_core_num(rank);
	} else
		cpuid = ctx_cpu;

	/* set pseudo random timeout */
	timeout = fpn_get_clock_cycles() & 0xFF;

	/* set pseudo random callback function */
	f = fpn_get_clock_cycles() % CB_FUNC_MAX;

	LOCK_CTX(ctx);
	ret = callout_stop(timer);
	if (ret != 0)
		callout_bind(timer, cpuid);
	else
		fpn_printf("%s:%d callout_stop() failed\n", __func__, __LINE__);

#ifdef TIMER_CALLOUT_CHECK_DEBUG
	fpn_printf("%s: mycpu=%d cpu=%d timeout=%d callout=%p func=%d\n",
		   __func__, mycpu, cpuid, timeout, &ctx->timer, f);
#endif

	ret = callout_reset_millisec(timer, timeout,
				     cb_funcs[f], arg);
	UNLOCK_CTX(ctx);

	if (ret != 0) {
#ifdef TIMER_CALLOUT_CHECK_DEBUG
		fpn_printf("%s: callout_reset failed\n", __func__);
#endif
		fpn_cb_counters[mycpu].reset_fails++;
	}
}

/*
 * Callback function that calls callout_stop() on its own timer
 * It forces the timer state from running to stopped.
 */
static void cb_stop(void *arg)
{
	int mycpu = fpn_get_core_num();
	struct callout_timer_ctx *ctx;
	struct callout *timer;

	ctx = (struct callout_timer_ctx *) arg;
	timer = &ctx->timer;
#ifdef TIMER_CALLOUT_CHECK_DEBUG
	fpn_printf("%s: cpu=%d callout=%p\n", __func__, mycpu, timer);
#endif
	LOCK_CTX(ctx);
	callout_stop(timer);
	fpn_cb_counters[mycpu].cb++;
	ctx->status = TIM_STOPPED;
	UNLOCK_CTX(ctx);
}

/*
 * Stop a randomly picked up pending timer.
 * Do not search too long for pending timers as
 * it can be long (max_tries should be a few hundreds at most).
 *
 * This function can only be used if our locks are used (need_lock == 0)
 * as the context status (ctx->status) cannot be guaranteed after calling
 * callout_stop().
 */
static void cb_stop_random(void *arg)
{
	int mycpu = fpn_get_core_num();
	struct callout_timer_ctx *this_ctx, *ctx;
	struct callout *timer;
	int callout_idx;
	int count = 0, ret;
	int max_tries = 200 & (NB_CALLOUTS - 1);

	this_ctx = (struct callout_timer_ctx *)arg;
	timer = &this_ctx->timer;

#ifdef TIMER_CALLOUT_CHECK_DEBUG
	fpn_printf("%s: cpu=%d callout=%p\n", __func__, mycpu, timer);
#endif
	LOCK_CTX(this_ctx);
	this_ctx->status = TIM_STOPPED;
	UNLOCK_CTX(this_ctx);

	fpn_cb_counters[mycpu].cb++;

	/* pick a random pending callout */
 retry:
	do {
		callout_idx = fpn_get_clock_cycles() & (NB_CALLOUTS - 1);
		ctx = &callouts[callout_idx];
		if (ctx == this_ctx)
			continue;
		timer = &ctx->timer;
		count++;
	} while (! callout_pending(timer) && count < max_tries);

	LOCK_CTX(ctx);

	if (! callout_pending(timer) && count < max_tries) {
		UNLOCK_CTX(ctx);
		goto retry;
	}
	if (callout_pending(timer)) {
#ifdef TIMER_CALLOUT_CHECK_DEBUG
		fpn_printf("%s: cpu=%d stopping callout=%p\n", __func__, mycpu,
			   timer);
#endif
		ret = callout_stop(timer);
		if (ret != 0 && ctx->status != TIM_STOPPED) {
			ctx->status = TIM_STOPPED;
			fpn_cb_counters[mycpu].cb++;
			if (callout_active(timer))
				fpn_printf("%s: failed stopping callout\n",
					   __func__);
		}
	}
	UNLOCK_CTX(ctx);
}

/* Reset a timer on the callback's cpu. */
static void cb_reschedule_same_cpu(void *arg)
{
	struct callout_timer_ctx *ctx;
	struct callout *timer;
	int timeout, ret = 0;
	int mycpu = fpn_get_core_num();

	fpn_cb_counters[mycpu].reset++;

	ctx = (struct callout_timer_ctx *) arg;
	timer = &ctx->timer;
	ctx->cpu = timer->cpu_id;

	/* set pseudo random timeout */
	timeout = fpn_get_clock_cycles() & 0xFF;

#ifdef TIMER_CALLOUT_CHECK_DEBUG
	fpn_printf("%s: %d callout=%p timeout=%d\n", __func__, mycpu,
		   timer, timeout);
#endif
	LOCK_CTX(ctx);
	ret = callout_reset_millisec(timer, timeout, cb_reset, ctx);
	UNLOCK_CTX(ctx);

	if (ret != 0) {
#ifdef TIMER_CALLOUT_CHECK_DEBUG
		fpn_printf("%s: callout_reset failed\n", __func__);
#endif
		fpn_cb_counters[mycpu].reset_fails++;
	}
}

/* Just increment callback stat and exit. */
static void cb_void(void *arg)
{
	int mycpu = fpn_get_core_num();
	struct callout_timer_ctx *ctx;
#ifdef TIMER_CALLOUT_CHECK_DEBUG
	struct callout *timer;
#endif
	ctx = (struct callout_timer_ctx *) arg;
#ifdef TIMER_CALLOUT_CHECK_DEBUG
	timer = &ctx->timer;
	fpn_printf("%s: cpu=%d callout=%p\n", __func__, fpn_get_core_num(), timer);
#endif

	LOCK_CTX(ctx);
	ctx->status = TIM_STOPPED;
	UNLOCK_CTX(ctx);
	fpn_cb_counters[mycpu].cb++;
}

/* Stop all timers. */
static int cb_force_stop(void)
{
	int i, reset_sync_stats = 0;
	struct callout_timer_ctx *ctx = NULL;
	int mycpu = fpn_get_core_num();

	for (i = 0; i < NB_CALLOUTS; i++) {
		ctx = &callouts[i];

		LOCK_CTX(ctx);
		if (ctx->status != TIM_STOPPED || callout_active(&ctx->timer)) {
			reset_sync_stats++;

			/* force stopping the timer */
#ifdef TIMER_CALLOUT_CHECK_DEBUG
			fpn_printf("%s: cpu=%d callout=%p force stop\n",
				   __func__, fpn_get_core_num(), &ctx->timer);
#endif
			if (need_lock) {
				callout_stop_sync(&ctx->timer);
				if (! callout_active(&ctx->timer)) {
					ctx->status = TIM_STOPPED;
					fpn_cb_counters[mycpu].cb++;
				}
			} else {
				int ret, maxrank, rank, cpu;

				/* do not reschedule on the current cpu */
				maxrank = fpn_get_online_core_count();
				rank = (mycpu + 1) % maxrank;
				cpu = fpn_get_online_core_num(rank);
				ret = callout_stop(&ctx->timer);
				if (ret)
					callout_bind(&ctx->timer, cpu);
				callout_reset(&ctx->timer, 0,
					      cb_stop, ctx);
			}
		}
		UNLOCK_CTX(ctx);
	}
	return reset_sync_stats;
}

/*
 * LOCKLESS API: Check all callouts and count stats.
 * This function gathers all stats of local timers and
 * immediate timers.
 * A local timer is a timer that resides only on the same
 * core. Thus it is managed in the same list all the time
 * by the same core.
 * If a timer has been set with an expiry of 0, it becomes
 * a special timer called immediate timer.
 * An immediate timer is a timer that is managed in a dedicated
 * timer list and expires as quickly as possible.
 * If an immediate timer is set with mode
 * FPN_TIMER_LOCK_NONE it is a local immediate timer.
 */
static void cb_end_lockless(void *arg)
{
	int cb_stats = 0, reset_stats = 0;
	int reset_fails_stats = 0;
	int i, still_running = 0;
	struct callout_timer_ctx *ctx = NULL;
	int callouts_size;

	(void)arg;

	/* check if all timers have really been stopped */
	for (i = 0; i < NB_CALLOUTS; i++) {

		ctx = &callouts[i];

		if (ctx->status != TIM_STOPPED ||
		    callout_active(&ctx->timer))
			still_running++;
	}

	switch (still_running) {
	case 0:
		break;
	case 1:
		fpn_printf("Lockless API test Failed. There is sill 1 pending timer\n");
		goto end;
	default:
		fpn_printf("Lockless test failed. There are still %d pending timers\n",
			   still_running);
		goto end;
	}

	for (i = 0; i < FPN_MAX_CORES; i++) {
		cb_stats += fpn_cb_counters[i].cb;
		reset_stats += fpn_cb_counters[i].reset;
		reset_fails_stats += fpn_cb_counters[i].reset_fails;
	}

	if (still_running == 0 && cb_stats)
		fpn_printf("\nLockless API test succeeded\n");
	else {
		fpn_printf("\nLockless API test failed\n");
		fpn_printf("Callbacks called: %d (out of %d)\n", cb_stats,
			   NB_CALLOUTS);
		fpn_printf("Resets: %d\n", reset_stats);
	}

	if (reset_fails_stats)
		fpn_printf("Reset fails: %d\n", reset_fails_stats);

	/* if the test succeeded launch timer checks using locking API */

	/* reset callouts */
	callouts_size = sizeof(struct callout_timer_ctx)
			      * NB_CALLOUTS;
	memset(callouts, 0, callouts_size);

	for (i = 0; i < NB_CALLOUTS; i++) {
		callout_init(&callouts[i].timer);
		callout_setlockmode(&callouts[i].timer, FPN_TIMER_LOCK_LIST);
		fpn_spinlock_init(&callouts[i].lock);
	}

	/* reset counters */
	memset(fpn_cb_counters, 0, sizeof(fpn_cb_counters));

	/* launch 1st stage test */
	timer_callouts_basic_check();
	return;
 end:
	fpn_free(callouts);
}


/* Check all callouts and count stats. */
static void cb_end(void *arg)
{
	int cb_stats = 0, reset_stats = 0;
	int reset_sync_stats = 0, reset_fails_stats = 0;
	int i, still_running = 0;
	struct callout_timer_ctx *ctx = NULL;
	int relaunch_timer_checks = 0;

	(void)arg;

	/* force stopping remaining callouts */
	fpn_printf("\nForce stopping all remaining timers...\n");
	reset_sync_stats = cb_force_stop();

	if (reset_sync_stats && retries > 0) {
		fpn_printf("retrying to stop %d timers in %d seconds\n",
			   reset_sync_stats, TIMER_TIMEOUT);
		retries--;
		callout_reset(&end_timer, TIMER_TIMEOUT,
			      cb_end, NULL);

		return;
	}

	/* check if all timers have really been stopped */
	for (i = 0; i < NB_CALLOUTS; i++) {

		ctx = &callouts[i];
		LOCK_CTX(ctx);

		if (ctx->status != TIM_STOPPED ||
		    callout_active(&ctx->timer))
			still_running++;

		UNLOCK_CTX(ctx);
	}

	/* make this function re-entrant */
	retries = TIMER_RETRY_STOP;

	switch (still_running) {
	case 0:
		break;
	case 1:
		fpn_printf("Test Failed. There is sill 1 pending timer\n");
		goto end;
	default:
		fpn_printf("Test failed. There are still %d pending timers\n",
			   still_running);
		goto end;
	}

	for (i = 0; i < FPN_MAX_CORES; i++) {
		cb_stats += fpn_cb_counters[i].cb;
		reset_stats += fpn_cb_counters[i].reset;
		reset_fails_stats += fpn_cb_counters[i].reset_fails;
	}

	if (still_running == 0 && cb_stats) {
		relaunch_timer_checks = 1;
		fpn_printf("\nTest succeeded\n");
	} else {
		fpn_printf("\nTest failed\n");
		fpn_printf("Callbacks called: %d (out of %d)\n", cb_stats,
			   NB_CALLOUTS);
		fpn_printf("Resets: %d\n", reset_stats);
	}

	if (reset_fails_stats)
		fpn_printf("Reset fails: %d\n", reset_fails_stats);

	if (reset_sync_stats)
		fpn_printf("Forced sync stops: %d\n", reset_sync_stats);

	/*
	 * If all tests succeeded re-launch them again using
	 * lockful API
	 */

#ifndef ENDLESS_CHECK
	relaunch_timer_checks &= ~need_lock;
#endif
	if (relaunch_timer_checks) {
		/* trigger need_lock */
		need_lock ^= 1;
		if (need_lock) {
			fpn_printf("\nLaunching all tests again using lockful");
			fpn_printf(" API\n");
		} else {
			fpn_printf("\nLaunching all tests again using lockless");
			fpn_printf(" API\n");
		}
		fpn_printf("===========================================\n\n");

		callout_stop(&end_timer);
		callout_reset(&end_timer, 0,
			      relaunch_api_check, NULL);
		return;
	}
 end:
	fpn_free(callouts);
}

/* Set all timers with random callback functions and random timeouts. */
static void launch_callouts(void)
{
	int i, cpuid, f, timeout, maxrank, rank = 0;
	struct callout_timer_ctx *ctx = NULL;
	int ret = 0;

	maxrank = fpn_get_online_core_count();

	for (i = 0; i < NB_CALLOUTS; i++) {

		ctx = &callouts[i];

		cpuid = fpn_get_online_core_num(rank++);
		rank = rank % maxrank;

		/* set pseudo random callback function */
		f = fpn_get_clock_cycles() % CB_FUNC_MAX;

		/* set pseudo random timeout */
		timeout = fpn_get_clock_cycles() & 0xFF;

		LOCK_CTX(ctx);

		ret = callout_stop(&ctx->timer);
		if (ret != 0)
			callout_bind(&ctx->timer, cpuid);
#ifdef TIMER_CALLOUT_CHECK_DEBUG
		else
			fpn_printf("%s:%d callout_stop() failed\n", __func__,
				   __LINE__);

		fpn_printf("setting up timer %p on cpu %d func=%d timeout=%d\n",
			   &ctx->timer, cpuid, f, timeout);
#endif
		ctx->cpu = -1;
		ctx->status = TIM_RUNNING;
		ret = callout_reset_millisec(&ctx->timer, timeout,
					     cb_funcs[f],  ctx);

		if (!callout_active(&ctx->timer) && !need_lock) {
			UNLOCK_CTX(ctx);
			fpn_printf("%s: callout_reset failed with status=%d\n",
				   __func__, ret);
			return;
		}

		UNLOCK_CTX(ctx);

#ifdef TIMER_CALLOUT_CHECK_DEBUG
		if (ret != 0)
			fpn_printf("%s: callout_reset failed\n", __func__);
#else
		(void)ret;
#endif
	}
}

/* Check callouts from the 1st stage check then run 2nd stage check. */
static void timer_callouts_2nd_stage_check(void *arg)
{
	int i, loops = 10, failed = 0;
	int cb_stats = 0, reset_stats = 0, reset_fails_stats = 0;
	int reset_sync_stats;
	uint64_t in_one_second;

	(void ) arg;

	/* force stopping remaining callouts from 1st stage check */
	fpn_printf("\nForce stopping all remaining timers...\n");

	reset_sync_stats = cb_force_stop();

	/* wait for 1s */
	in_one_second = fpn_get_clock_cycles() + fpn_get_clock_hz();
	while (fpn_get_clock_cycles() < in_one_second) {}

	/* count stats from 1st stage check */
	for (i = 0; i < FPN_MAX_CORES; i++) {
		cb_stats += fpn_cb_counters[i].cb;
		reset_stats += fpn_cb_counters[i].reset;
		reset_fails_stats += fpn_cb_counters[i].reset_fails;
	}

	if (cb_stats == NB_CALLOUTS)
		fpn_printf("\n1st stage test succeeded\n");
	else {
		fpn_printf("\n1st stage test failed\n");
		fpn_printf("Callbacks called: %d (out of %d)\n", cb_stats,
			   NB_CALLOUTS);
		fpn_printf("Resets: %d\n", reset_stats);
		failed = 1;
	}

	if (reset_fails_stats)
		fpn_printf("Reset fails: %d\n", reset_fails_stats);

	if (reset_sync_stats)
		fpn_printf("Forced sync stops: %d\n", reset_sync_stats);


	if (failed) {
		fpn_free(callouts);
		return;
	}

	fpn_printf("\nLaunching 2nd stage timer check\n");
	fpn_printf("===============================\n\n");

	/* reset counters */
	memset(fpn_cb_counters, 0, sizeof(fpn_cb_counters));

	/* launch tests many times to mix callouts on different cores */
	for (i = 0; i < loops; i++)
		launch_callouts();


	/* set a timer that forces stopping all other timers and counts stats */
	fpn_printf("Wait for %d seconds...\n", TIMER_TIMEOUT);

	callout_reset(&end_timer, TIMER_TIMEOUT, cb_end, NULL);
}

/*
 * Load lockless local timers and immediate timers.
 * Immediate timer == timer with expiry of 0.
 */
static void timer_callouts_lockless_check(void *arg)
{
	int i, f, timeout;
	struct callout_timer_ctx *ctx = NULL;
	int ret;

	(void)arg;

	printf("\nLaunching Lockless API timer check\n");
	printf("==================================\n\n");

	for (i = 0; i < NB_CALLOUTS; i++) {

		ctx = &callouts[i];

		/*
		 * set pseudo random callback function
		 * avoid CB_FUNC_STOP_RANDOM and CB_FUNC_RESET
		 * since we're lockless
		 */
		f = fpn_get_clock_cycles() % CB_FUNC_MAX;
		if (f == CB_FUNC_STOP_RANDOM || f == CB_FUNC_RESET)
			f = CB_FUNC_RESCHEDULE;

		/*
		 * Set pseudo random timeout.
		 * If the timeout == 0 then the timer will be
		 * managed as an immediate timer.
		 */
		timeout = fpn_get_clock_cycles() & 0xFF;

		ctx->cpu = -1;
		ctx->status = TIM_RUNNING;
		ret = callout_reset_millisec(&ctx->timer, timeout,
					     cb_funcs[f],  ctx);

		if (!callout_active(&ctx->timer)) {
			fpn_printf("%s: callout_reset failed with status=%d\n",
				   __func__, ret);
			return;
		}
	}
	callout_reset(&end_timer, TIMER_TIMEOUT, cb_end_lockless, NULL);
}

/* Start the basic test. */
static void timer_callouts_basic_check(void)
{
	int maxrank, rank, cpu, mycpu;
	int ret;


	fpn_printf("\nLaunching basic timer check\n");
	fpn_printf("===========================\n\n");

	launch_callouts();

	/* set the 2nd stage timer */
	fpn_printf("Wait for %d seconds...\n", TIMER_TIMEOUT);

	mycpu = fpn_get_core_num();
	maxrank = fpn_get_online_core_count();
	rank = (mycpu + 1) % maxrank;
	cpu = fpn_get_online_core_num(rank);

	ret = callout_stop(&end_timer);
	if (ret != 0)
		callout_bind(&end_timer, cpu);
	else
		fpn_printf("%s:%d callout_stop() failed\n", __func__, __LINE__);

	callout_reset(&end_timer, TIMER_TIMEOUT,
		      timer_callouts_2nd_stage_check, NULL);
}

/* Initialize callback functions, callouts and locks. */
int fpn_test_timer_callouts_check(void)
{
	int i, callouts_size, rank, maxrank, cpuid;

	/* make this function re-entrant */
	need_lock = 0;

	/* reset counters */
	memset(fpn_cb_counters, 0, sizeof(fpn_cb_counters));

	cb_funcs[CB_FUNC_RESET] = cb_reset;
	cb_funcs[CB_FUNC_STOP] = cb_stop;
	cb_funcs[CB_FUNC_STOP_RANDOM] = cb_stop_random;
	cb_funcs[CB_FUNC_RESCHEDULE] =
		cb_reschedule_same_cpu;
	cb_funcs[CB_FUNC_VOID] = cb_void;

	fpn_printf("Setting up %d timers\n", NB_CALLOUTS);

	/* allocate callouts */
	callouts_size = sizeof(struct callout_timer_ctx)
			      * NB_CALLOUTS;
	callouts = fpn_malloc(callouts_size, 0);

	if (callouts == NULL) {
		fpn_printf("Failed allocation memory\n");
		return -1;
	}

	memset(callouts, 0, callouts_size);
	memset(&end_timer, 0, sizeof(end_timer));

	/* init callouts and locks */
	callout_init(&end_timer);
	for (i = 0; i < NB_CALLOUTS; i++) {
		callout_init(&callouts[i].timer);
		/* set lockless mode to check local timers first */
		callout_setlockmode(&callouts[i].timer, FPN_TIMER_LOCK_NONE);
		fpn_spinlock_init(&callouts[i].lock);
	}

	/* check lockless local timers */

	/* set pseudo random core number */
	maxrank = fpn_get_online_core_count();
	rank = fpn_get_clock_cycles() % maxrank;
	cpuid = fpn_get_online_core_num(rank);

	callout_bind(&end_timer, cpuid);
	callout_reset_millisec(&end_timer, 0, timer_callouts_lockless_check,
			       NULL);

	return 0;
}

static void relaunch_api_check(void *arg)
{
	(void)arg;
	int i, callouts_size;

	/* reset counters */
	memset(fpn_cb_counters, 0, sizeof(fpn_cb_counters));

	/* reset callouts */
	callouts_size = sizeof(struct callout_timer_ctx)
			      * NB_CALLOUTS;
	memset(callouts, 0, callouts_size);

	/*
	 * cb_stop_random can only be used when the callouts
	 * are locked by us (not be the timer API).
	 */
	if (need_lock == 0)
		cb_funcs[CB_FUNC_STOP_RANDOM] = cb_stop_random;
	else
		cb_funcs[CB_FUNC_STOP_RANDOM] = cb_stop;


	for (i = 0; i < NB_CALLOUTS; i++) {
		callout_init(&callouts[i].timer);
		fpn_spinlock_init(&callouts[i].lock);

		if (need_lock)
			callout_setlockmode(&callouts[i].timer,
					    FPN_TIMER_LOCK_ALL);
		else
			callout_setlockmode(&callouts[i].timer,
					    FPN_TIMER_LOCK_LIST);
	}

	/* launch 1st stage test */
	timer_callouts_basic_check();
}
