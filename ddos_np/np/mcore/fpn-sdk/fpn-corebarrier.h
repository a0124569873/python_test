/*
 * Copyright(c) 2010 6WIND, All rights reserved.
 */
#ifndef __FPN_COREBARRIER__
#define __FPN_COREBARRIER__

#ifdef CONFIG_MCORE_FPN_CORE_BARRIER
typedef struct fpn_core_state_s {
	int state;   /* flag: whether core is in critical section */
	unsigned int exitcnt; /* counter: nb of times core exited critical section */
} __fpn_cache_aligned fpn_core_state_t;

FPN_DECLARE_SHARED(volatile fpn_core_state_t, fpn_core_state[FPN_MAX_CORES]);

#define __FPN_ENTER(cpu)	do {						\
		fpn_core_state[cpu].state = 1;		\
	} while (0)

#define __FPN_EXIT(cpu)	do {						\
		fpn_core_state[cpu].state = 0;		\
		fpn_core_state[cpu].exitcnt++;		\
	} while (0)

extern void fpn_core_init(void);

//#define FPN_CORE_DEBUG
#ifdef FPN_CORE_DEBUG
extern void fpn_core_enter(int cpu);
extern void fpn_core_exit(int cpu, const char *func, int line);
extern unsigned int fpn_core_read_cores_in(void);

#define FPN_ENTER(cpu) fpn_core_enter(cpu)
#define FPN_EXIT(cpu) fpn_core_exit(cpu, __FUNCTION__, __LINE__)
#else
#define fpn_core_read_cores_in() 0
#define FPN_ENTER(cpu) __FPN_ENTER(cpu)
#define FPN_EXIT(cpu) __FPN_EXIT(cpu)
#endif

#else /* ! CONFIG_MCORE_FPN_CORE_BARRIER */

#define FPN_ENTER(cpu) do {} while (0)
#define FPN_EXIT(cpu) do {} while (0)

static inline void fpn_core_init(void) { }

#endif

#endif /* __FPN_COREBARRIER__ */
