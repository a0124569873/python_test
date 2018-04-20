/*
 * Copyright(c) 2010 6WIND
 */

#ifndef __FPN_TIMER_DPDK_H__
#define __FPN_TIMER_DPDK_H__

#include <rte_cycles.h>

extern uint64_t fpn_rte_tsc_hz;

static inline uint64_t fpn_get_clock_cycles(void)
{
	return rte_rdtsc();
}
#define fpn_get_local_cycles fpn_get_clock_cycles

static inline uint64_t fpn_get_clock_hz(void)
{
	return fpn_rte_tsc_hz;
}
#define fpn_get_local_clock_hz() fpn_get_clock_hz()

#ifdef CONFIG_MCORE_TIMER_GENERIC
#include "timer/fpn-timer-generic.h"
#endif


#endif
