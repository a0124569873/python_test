/*
 * Copyright(c) 2012 6WIND
 */
#include "fpn.h"

FPN_DEFINE_SHARED(const fpn_mainloop_ops_t*, fpn_mainloop_ops);

typedef struct fpn_job {
	volatile long status;
	int (*func)(void*);
	void *args;
	int completed;
	int ret;
} fpn_job_t;

/* #define JOB_DEBUG 1 */

static FPN_DEFINE_SHARED(fpn_job_t, fpn_jobs[FPN_MAX_CORES]);

/* wait for all cpus in mask (except running cpu if skip_master is set to */
/* FPN_JOB_SKIP_MASTER) to reach status */
void fpn_job_wait_status(const fpn_cpumask_t * mask, long status,
                         enum fpn_job_skip skip_master)
{
	int cpu, mycpu;

	mycpu = fpn_get_core_num();
	fpn_for_each_cpumask(cpu, mask) {
		if ((skip_master == FPN_JOB_SKIP_MASTER) && (cpu == mycpu))
			continue;
		while(fpn_jobs[cpu].status != status);
	}
}

/* run a job on a particular cpu, it must be in NONE or DONE state */
int fpn_job_run_oncpu(unsigned cpu, int (*func)(void*), void* args)
{
	if (cpu >= FPN_MAX_CORES) {
		fpn_printf("%s[%d] >= FPN_MAX_CORES\n", __func__, cpu);
		return -1;
	}

	if (fpn_jobs[cpu].status == FPN_JOB_STATE_AVAIL ||
	    fpn_jobs[cpu].status == FPN_JOB_STATE_RUNNING) {
		fpn_printf("%s[%d]: can't add job, ebusy\n", __func__, cpu);
		return -1;
	}

	fpn_jobs[cpu].func = func;
	fpn_jobs[cpu].args = args;
	fpn_wmb();
	fpn_jobs[cpu].status = FPN_JOB_STATE_AVAIL;

	return 0;
}

/* run a job on all cpus in a mask, uses fpn_job_run_oncpu, except running cpu if */
/* skip_master is set to FPN_JOB_SKIP_MASTER */
int fpn_job_run_oncpumask(const fpn_cpumask_t * coremask, int (*func)(void*), void* args,
                          enum fpn_job_skip skip_master)
{
	unsigned cpu, mycpu;
	int ret = 0;

	mycpu = fpn_get_core_num();
	fpn_for_each_cpumask(cpu, coremask) {
		if ((skip_master == FPN_JOB_SKIP_MASTER) && (cpu == mycpu))
			continue;
		if (fpn_job_run_oncpu(cpu, func, args))
			ret = -1;
	}

	return ret;
}

/* run jobs when available */
int fpn_job_poll(void)
{
	fpn_job_t *job;
	unsigned my_cpu_id = fpn_get_core_num();

	job = &fpn_jobs[my_cpu_id];

#ifdef JOB_DEBUG
	fpn_printf("%s[%d]: entering\n", __func__, my_cpu_id);
#endif

	while (1) {
		if (job->status == FPN_JOB_STATE_AVAIL) {
			void *args;
			int ret;

			/* ensure that the cpu will not try to read
			   args and func before it is ready */
			fpn_rmb();

#ifdef JOB_DEBUG
			fpn_printf("%s[%d]: job started\n", __func__, my_cpu_id);
#endif
			job->status = FPN_JOB_STATE_RUNNING;

			args = job->args;
			ret = job->func(args);
			job->ret = ret;
			fpn_wmb();

			job->status = FPN_JOB_STATE_DONE;
#ifdef JOB_DEBUG
			fpn_printf("%s[%d]: job done, ret=%d\n", __func__,
				   my_cpu_id, ret);
#endif
		}
	}
}
