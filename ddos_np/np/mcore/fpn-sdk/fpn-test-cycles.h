#ifndef __FPN_TEST_CYCLES_H__
#define __FPN_TEST_CYCLES_H__

#if defined(CONFIG_MCORE_FPE_MCEE) && defined(CONFIG_MCORE_TEST_CYCLES)

/* Each fast path thread must fill begin/end with fpn_get_clock_cycles()
 * by reading fp_shared->conf.do_test_cycles bit.
 */
#define FP_CYCLES_DECLARE() uint64_t __do_tcy, __last_do_tcy = 0

#define FP_CYCLES_TEST() do { \
	__do_tcy = cpu_usage_shared->do_test_cycles; \
	if (unlikely(__do_tcy != __last_do_tcy)) { \
		struct busy_cycles *bc = &cpu_usage_shared->busy_cycles \
			[fpn_get_core_num()]; \
		uint64_t __now_tcy = fpn_get_clock_cycles(); \
		__last_do_tcy = __do_tcy; \
		if (__do_tcy) \
			bc->begin = __now_tcy; \
		else \
			bc->end = __now_tcy; \
	} \
} while(0)

#else

#define FP_CYCLES_DECLARE()
#define FP_CYCLES_TEST()

#endif

#endif
