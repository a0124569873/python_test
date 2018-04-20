/*
 * Copyright(c) 2012 6WIND
 */
#ifndef __FPN_CPU_USAGE__
#define __FPN_CPU_USAGE__

struct busy_cycles {
	uint64_t val;
	uint64_t begin;
	uint64_t end;
	uint64_t pkts;
	uint64_t intercore_pkts;
} __fpn_cache_aligned;

typedef struct cpu_usage_shared_mem {
	int do_cpu_usage;
	int do_test_cycles;
	struct busy_cycles busy_cycles[FPN_MAX_CORES] __fpn_cache_aligned;
} cpu_usage_shared_mem_t;

#ifdef CONFIG_MCORE_DEBUG_CPU_USAGE

/*
 * Usage: active loop case
 *
 *  cpu_declare();
 *
 *  while (1) {
 *
 *    read <current time>
 *
 *    // will accumulate the cycles spent during last loop
 *    cpu_usage(<current time>);
 *
 *
 *    special case: cpu is sleeping, waiting for work
 *                  an additional call is needed
 *           wait for work
 *           read <current time>
 *           cpu_usage(<current time>)
 *
 *    periodic check (e.g. every 10ms)
 *		cpu_usage_check(<current cpu>, <current time>)
 *
 *
 *    if work done by cpu
 *		cpu_usage_acc();
 *    or if work was on n packets:
 *		cpu_usage_acc_nic(n);
 *    or if work was on n packets leaving intercore ring:
 *		cpu_usage_acc_intercore(n);
 *
 *    if another-work done by cpu
 *		cpu_usage_acc();
 *
 *    //it goes back to cpu_usage(), for sum up
 *  }
 *
 *
 * Before entering the main loop, call cpu_usage() with current cpu's cycles.
 * An additional call is required whenever the cpu can sleep in the main loop.
 * Call cpu_usage_check() to know if cpu usage has been asked, this should be called
 * periodically (not need at every each iteration).
 * Note: if cpu can sleep, it can miss the request.
 * Call cpu_usage_acc() each time the code does a job whose the cycles should
 * be account, or use the variant cpu_usage_acc_nic(n) to account the cycles
 * for n packets received from NIC. If packet went through pipeline, use
 * cpu_usage_acc_intercore(n).
 *
 * Transition 0->1 will store and accumulate cycles in sum_cycles.
 * Transition 1->0 will store end, sum cycles and packets in busy_cycles[].
 *
 */

#ifdef __FastPath__
FPN_DECLARE_SHARED(cpu_usage_shared_mem_t *, cpu_usage_shared);
#endif
int cpu_usage_init(void);

#define cpu_usage_declare() \
	uint64_t start_cycles = 0; \
	uint64_t sum_cycles = 0; \
	uint64_t nic_pkts = 0; \
	uint64_t intercore_pkts = 0; \
	int do_cpu_usage = 0; \
	int last_do_cpu_usage = 0; \
	int do_sum = 0;

#define cpu_usage_check(__cpu, __now) \
	do_cpu_usage = cpu_usage_shared->do_cpu_usage;     \
	if (unlikely(do_cpu_usage != last_do_cpu_usage)) { \
		struct busy_cycles *bc; \
		bc = &cpu_usage_shared->busy_cycles[__cpu];		\
		if (!last_do_cpu_usage) { \
			bc->begin = __now; \
			bc->val = 0; \
			bc->end = __now; \
			sum_cycles = 0; \
			nic_pkts = 0; \
			intercore_pkts = 0; \
			start_cycles = __now; \
		} else { \
			bc->end = __now; \
			bc->val = sum_cycles; \
			bc->pkts = nic_pkts; \
			bc->intercore_pkts = intercore_pkts; \
		}\
		last_do_cpu_usage = do_cpu_usage; \
	}

#define cpu_usage(__now) \
	if (unlikely(do_sum)) { \
		sum_cycles += (__now - start_cycles); \
		do_sum = 0; \
	} \
	start_cycles = __now; \

#define cpu_usage_acc() do { do_sum = do_cpu_usage; } while (0)

#define cpu_usage_acc_nic(__n) do {  \
	do_sum = do_cpu_usage; \
	nic_pkts += __n; \
} while (0)

#define cpu_usage_acc_intercore(__n) do {  \
	do_sum = do_cpu_usage; \
	intercore_pkts += __n; \
} while (0)


#else /* !  MCORE_DEBUG_CPU_USAGE */

#define cpu_usage_declare()
#define cpu_usage_acc() do { } while (0)
#define cpu_usage_acc_nic(n) do { } while (0)
#define cpu_usage_acc_intercore(n) do { } while (0)
#define cpu_usage(n) do { } while (0)
#define cpu_usage_check(c,n) do { } while (0)

#endif

#endif
