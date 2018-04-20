/*
 * Copyright(c) 2012 6WIND
 */
#ifndef __FPN_JOB_H__
#define __FPN_JOB_H__

typedef void (input_t)(struct mbuf *);
typedef int (hook_t)(void);

typedef struct fpn_mainloop_ops {
	input_t *input;
	input_t *soft_input;
	hook_t  *hook;
} fpn_mainloop_ops_t;

FPN_DECLARE_SHARED(const fpn_mainloop_ops_t *, fpn_mainloop_ops);

/*
 * Called on master cpu before starting fpn_main_loop.
 * This function defines which functions will be used as input and
 * soft_input functions by the mainloops.
 */
static inline void fpn_register_mainloop_ops(const fpn_mainloop_ops_t *ops)
{
	fpn_mainloop_ops = ops;
}

enum fpn_job_state {
	FPN_JOB_STATE_NONE,    /* initial */
	FPN_JOB_STATE_AVAIL,   /* cpu is available for jobs */
	FPN_JOB_STATE_RUNNING, /* cpu is running a job */
	FPN_JOB_STATE_DONE     /* cpu has finished job (ret value is available) */
};

enum fpn_job_skip {
	FPN_JOB_SKIP_NONE,     /* run job on all cpus from mask */
	FPN_JOB_SKIP_MASTER,   /* skip calling cpu if present in mask */
};

/* Called on master cpu */

/*
 * Write a job in cpu's table, asking to execute func(args).
 * The cpu will start it at next loop of fpn_job_poll. As a
 * consequence that args will not be used immediately, so it must not
 * be changed or freed if a pointer is used, until the job is
 * finished on this cpu.
 * Returns -1 if cpu is invalid, or if it has already a job in
 * progress, 0 on success.
 */
int fpn_job_run_oncpu(unsigned cpu, int (*func)(void*), void *args);

/*
 * Call fpn_job_run_oncpu on each cpu within the coremask.
 * The running cpu is skipped from mask if skip_master is set to 
 * FPN_JOB_SKIP_MASTER.
 * Returns -1 if one of the fpn_job_run_oncpu failed, 0 on success.
 * Note that even if an error occured on one cpu, the function still
 * tries to start the job on the other cpus.
 */
int fpn_job_run_oncpumask(const fpn_cpumask_t * coremask, int (*func)(void*), void *args,
                          enum fpn_job_skip skip_master);


/* Called on any cpus */

/*
 * Start a loop waiting for jobs on this cpu. Must be launched from
 * the cpu in parameter.
 * Note that this function does not return.
 * fpn_job_poll is called by fpn_sdk_init on all cores except master
 * core. If the master core is used to process a job, fpn_job_poll
 * must be called on it at the end of main function.
 */
int fpn_job_poll(void);

/*
 * Wait for jobs on each cpu within mask to change their status to
 * 'status' (except running cpu if skip_master is set to FPN_JOB_SKIP_MASTER)
 * and then return.
 */
void fpn_job_wait_status(const fpn_cpumask_t * mask, long status,
                         enum fpn_job_skip skip_master);

#endif /* __FPN_JOB_H__ */
