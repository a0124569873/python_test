/*
 * Copyright(c) 2011 6WIND, All rights reserved.
 */

#include "fpn.h"

volatile FPN_DEFINE_SHARED(fpn_core_state_t, fpn_core_state[FPN_MAX_CORES]) __fpn_cache_aligned;

#ifdef FPN_CORE_DEBUG
static FPN_DEFINE_SHARED(fpn_atomic_t, fpn_cores_in);
#endif

void fpn_core_init(void)
{
#ifdef FPN_CORE_DEBUG
	fpn_atomic_set(&fpn_cores_in, 0);
#endif
}

#ifdef FPN_CORE_DEBUG
void fpn_core_enter(int cpu)
{
	__FPN_ENTER(cpu);
	fpn_atomic_inc(&fpn_cores_in);
}

void fpn_core_exit(int cpu, const char *func, int line)
{
	if (fpn_core_state[cpu].core_state == 0)
		fpn_printf("Error FPN_EXIT without FPN_ENTER in %s: %d: state: %d\n",
			   func, line,
			   fpn_core_state[cpu].core_state);
	fpn_atomic_dec(&fpn_cores_in);
	__FPN_EXIT(cpu);
}

unsigned int fpn_core_read_cores_in(void)
{
	return fpn_atomic_read(&fpn_cores_in);
}
#endif
