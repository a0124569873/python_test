/*
 * Copyright(c) 2012 6WIND
 */
#ifndef __FPN_CORE__
#define __FPN_CORE__

/* FPN_CORE_SET_SIZE is the size in bits of the core_set */
#define FPN_CORE_SET_SIZE  (8 * sizeof(fpn_core_set_t))
#define FPN_CORE_SET_MASK  (FPN_CORE_SET_SIZE - 1)

/**
 * Full coremask as table of core_sets
 */
typedef struct {
	fpn_core_set_t core_set[fpn_roundup(FPN_MAX_CORES, FPN_CORE_SET_SIZE) / FPN_CORE_SET_SIZE]; /**< Splitted core mask bitmap */
} fpn_cpumask_t;

/**
 * Loop over all FPN cores
 */
#define fpn_for_each_cpu(cpu)				\
	for (cpu = 0; cpu < FPN_MAX_CORES; cpu++)

/**
 * Clear a coremask
 *
 * @param[inout] coremask
 *   Mask of cores
 */
static inline void
fpn_cpumask_clear(fpn_cpumask_t * coremask)
{
	memset(coremask, 0, sizeof(fpn_cpumask_t));
}

/**
 * Set a cpu in a coremask
 *
 * @param[inout] coremask
 *   Mask of cores
 * @param[in] cpu
 *   Cpu index
 */
static inline void
fpn_cpumask_set(fpn_cpumask_t * coremask, int cpu)
{
	if (cpu >= FPN_MAX_CORES)
		return;

	coremask->core_set[cpu / FPN_CORE_SET_SIZE] |=
	    (((fpn_core_set_t) 1) << (cpu & FPN_CORE_SET_MASK));
}

/**
 * Remove a cpu from a coremask
 *
 * @param[inout] coremask
 *   Mask of cores
 * @param[in] cpu
 *   Cpu index
 */
static inline void
fpn_cpumask_unset(fpn_cpumask_t * coremask, int cpu)
{
	if (cpu >= FPN_MAX_CORES)
		return;

	coremask->core_set[cpu / FPN_CORE_SET_SIZE] &=
	    ~(((fpn_core_set_t) 1) << (cpu & FPN_CORE_SET_MASK));
}

/**
 * Invert a coremask
 *
 * @param[inout] coremask
 *   Mask of cores
 */
static inline void
fpn_cpumask_invert(fpn_cpumask_t * coremask)
{
	uint32_t index;
	for (index=0 ; index<FPN_ARRAY_SIZE(coremask->core_set) ; index++) {
		coremask->core_set[index] = ~coremask->core_set[index];
	}
}

/**
 * Add two coremasks
 *
 * @param[inout] coremask
 *   Mask of cores
 * @param[in] coreset
 *   Mask of cores to merge in coremask
 */
static inline void
fpn_cpumask_add(fpn_cpumask_t * coremask, const fpn_cpumask_t * coreset)
{
	uint32_t index;
	for (index=0 ; index<FPN_ARRAY_SIZE(coremask->core_set) ; index++) {
		coremask->core_set[index] |= coreset->core_set[index];
	}
}

/**
 * Substract a coremask from another one
 *
 * @param[inout] coremask
 *   Mask of cores
 * @param[in] coreset
 *   Mask of cores to remove from coremask
 */
static inline void
fpn_cpumask_sub(fpn_cpumask_t * coremask, const fpn_cpumask_t * coreset)
{
	uint32_t index;
	for (index=0 ; index<FPN_ARRAY_SIZE(coremask->core_set) ; index++) {
		coremask->core_set[index] &= ~coreset->core_set[index];
	}
}

/**
 * Filter cores from a coremask
 *
 * @param[inout] coremask
 *   Mask of cores
 * @param[in] coreset
 *   Mask of cores to filter in coremask
 */
static inline void
fpn_cpumask_filter(fpn_cpumask_t * coremask, const fpn_cpumask_t * coreset)
{
	uint32_t index;
	for (index=0 ; index<FPN_ARRAY_SIZE(coremask->core_set) ; index++) {
		coremask->core_set[index] &= coreset->core_set[index];
	}
}

/**
 * Test if cpu is present in coremask
 *
 * @param[in] coremask
 *   Cores mask to test
 * @param[in] cpu
 *   Cpu index
 *
 * @return
 *   Non null value if cpu is part or coremask
 */
static inline int
fpn_cpumask_ismember(const fpn_cpumask_t * coremask, int cpu)
{
	if (cpu >= FPN_MAX_CORES)
		return 0;

	return ((coremask->core_set[cpu / FPN_CORE_SET_SIZE] &
	        (((fpn_core_set_t) 1) << (cpu & FPN_CORE_SET_MASK))) != 0);
}

/**
 * Test if coremask is empty
 *
 * @param[in] coremask
 *   Cores mask to test
 *
 * @return
 *   Non null value if coremask is empty
 */
static inline int
fpn_cpumask_isempty(const fpn_cpumask_t * coremask)
{
	uint32_t index;
	fpn_core_set_t res = 0;
	for (index=0 ; index<FPN_ARRAY_SIZE(coremask->core_set) ; index++) {
		res |= coremask->core_set[index];
	}
	return(!res);
}

/**
 * Test if coremasks are equal
 *
 * @param[in] coremask1
 *   Cores mask to test
 * @param[in] coremask2
 *   Cores mask to test
 *
 * @return
 *   Non null value if coremask1 == coremask2
 */
static inline int
fpn_cpumask_isequal(const fpn_cpumask_t * coremask1, const fpn_cpumask_t * coremask2)
{
	uint32_t index;
	int res = 1;
	for (index=0 ; index<FPN_ARRAY_SIZE(coremask1->core_set) ; index++) {
		res &= (coremask1->core_set[index] == coremask2->core_set[index]);
	}
	return(res);
}

/**
 * Return coremask size
 *
 * @param[in] coremask
 *   Cores mask
 *
 * @return
 *   Number of cores in mask
 */
static inline int
fpn_cpumask_size(const fpn_cpumask_t * coremask)
{
	uint32_t index;
	int res = 0;
	for (index=0 ; index<FPN_ARRAY_SIZE(coremask->core_set) ; index++) {
		fpn_core_set_t coreset = coremask->core_set[index];
		while (coreset != 0) {
			/* x & x-1 zeros out the least significant nonzero bit */
			coreset &= coreset - 1;
			res++;
		}
	}
	return(res);
}

/**
 * Get next cpu index in coremask
 *
 * @param[in] coremask
 *   Cores mask
 * @param[in] cpu
 *   Current cpu index
 *
 * @return
 *   Index of next cpu in mask, or FPN_MAX_CORES if no more cpus
 */
static inline int
fpn_cpumask_getnext(const fpn_cpumask_t * coremask, int cpu)
{
	int next;

	for (next = cpu + 1; next < FPN_MAX_CORES; next++) {
		if (fpn_cpumask_ismember(coremask, next))
			return next;
	}

	return FPN_MAX_CORES;
}

/* warning, cpu is changed by this macro */
#define fpn_for_each_cpumask(cpu, mask)					\
	for ((cpu) = -1;						\
	     (cpu) = fpn_cpumask_getnext((mask), (cpu)),		\
	     (cpu) < FPN_MAX_CORES;)

/**
 * Register cores
 *
 * This function is used to register the coremask to FPN SDK
 *
 * @param[in] coremask
 *   Cores mask to register
 */
extern void fpn_register_online_cores(const fpn_cpumask_t * coremask);

/**
 * Display coremask
 *
 * @param[in] coremask
 *   Cores mask to display
 */
extern void fpn_cpumask_display(const char * header, const fpn_cpumask_t * coremask);

/**
 * Stringify a coremask in 0xnnn format
 *
 * @param[in] coremask
 *   Cores mask to convert
 * @param[out] buffer
 *   Buffer used to store coremask string
 * @param[in] len
 *   Buffer length
 */
extern void fpn_cpumask_string(const fpn_cpumask_t * coremask, char *buffer, int len);

/**
 * Parse a string to build a core set
 *
 * @param[in] cpumask
 *   Hex string describing the core set
 * @param[out] coremask
 *   Cores mask to display
 */
extern int fpn_cpumask_parse(const char * cpumask, fpn_cpumask_t * coremask);

#ifdef __FastPath__
FPN_DECLARE_SHARED(fpn_cpumask_t, fpn_coremask);
FPN_DECLARE_SHARED(unsigned, fpn_online_core_count);
FPN_DECLARE_SHARED(int[FPN_MAX_CORES], fpn_online_cores);

static inline unsigned fpn_get_online_core_count(void)
{
	return fpn_online_core_count;
}

static inline int fpn_get_online_core_num(unsigned rank)
{
	if (likely(rank < fpn_get_online_core_count()))
		return fpn_online_cores[rank];
	else
		return -1;
}
#endif

#ifndef CONFIG_MCORE_ARCH_OCTEON
extern int fpn_thread_setname(const char *name);
#else
/* Not applicable on bare metal like Octeon */
static inline int fpn_thread_setname(const char *name) { return 0; }
#endif

#endif /* __FPN_CORE__ */
