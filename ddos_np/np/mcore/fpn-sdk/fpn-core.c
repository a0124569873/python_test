/*
 * Copyright(c) 2012 6WIND
 */
#include "fpn.h"

/* #define CORE_DEBUG 1 */

FPN_DEFINE_SHARED(fpn_cpumask_t, fpn_coremask);
FPN_DEFINE_SHARED(int[FPN_MAX_CORES], fpn_online_cores);
FPN_DEFINE_SHARED(unsigned, fpn_online_core_count) = 0;

/* Initialize list of online cores */
void fpn_register_online_cores(const fpn_cpumask_t * coremask)
{
	int cpu;

	for (cpu = 0; cpu < FPN_MAX_CORES; cpu++) {
		if (fpn_cpumask_ismember(coremask, cpu))
			fpn_online_cores[fpn_online_core_count++] = cpu;
	}

	fpn_coremask = *coremask;
#ifdef CORE_DEBUG
	fpn_printf("online cores: ");
	for (cpu = 0; cpu < FPN_MAX_CORES; cpu++) {
		if (fpn_cpumask_ismember(coremask, cpu))
			fpn_printf("%u ", cpu);
	}
	fpn_printf("\n");
#endif

}

void fpn_cpumask_string(const fpn_cpumask_t * coremask, char *buffer, int len)
{
 	int index, skip = 1;
	int offset = strlen("0x");

	/* Too small buffer, do nothing */
	if (offset >= len)
		return;

	/* Print coremask in buffer */
	strcpy(buffer, "0x");
	for (index=FPN_ARRAY_SIZE(coremask->core_set)-1 ; index>=0 ; index--) {
		if ((coremask->core_set[index] != 0) || (!skip) || (index == 0)) {
			if (skip) {
				offset += snprintf(&buffer[offset], len - offset,
								   "%" FPN_CORE_SET_DISP,
								   coremask->core_set[index]);
			} else {
				offset += snprintf(&buffer[offset], len - offset,
								   "%" FPN_CORE_SET_FILL FPN_CORE_SET_DISP,
								   coremask->core_set[index]);
			}

			/* Display is started do not skip anything even if no bit set */
			skip = 0;

			/* Not enough space in buffer, exit */
			if (offset >= len)
				break;
		}
 	}
}

/* Display list of cores in mask */
void fpn_cpumask_display(const char * header, const fpn_cpumask_t * coremask)
{
	char buffer[FPN_MAX_CORES+3];

	fpn_cpumask_string(coremask, buffer, FPN_MAX_CORES);
	printf("%s%s", header, buffer);
}

int
fpn_cpumask_parse(const char * cpumask, fpn_cpumask_t * coremask)
{
	char *end = NULL;
	unsigned long core, min, max;

	/* Invalid parameters */
	if ((cpumask == NULL) || (coremask == NULL))
		return -1;

	/* Clear coremask */
	fpn_cpumask_clear(coremask);

	/* If hex string, read mask */
	if ((cpumask[0] == '0') && ((cpumask[1] == 'x') || (cpumask[1] == 'X'))) {
		int car;
		uint32_t len, index = 0, shift = 0;
		char val;

		/* Skip 0x */
		cpumask += 2;
		len = strlen(cpumask);

		/* Start from last byte, and fill cpu mask */
		for (car=len-1 ; car>=0 ; car--) {
			if ((cpumask[car] >= 'a') &&
			    (cpumask[car] <= 'f')) {
				val = cpumask[car] - 'a' + 10;
			} else if ((cpumask[car] >= 'A') &&
			           (cpumask[car] <= 'F')) {
				val = cpumask[car] - 'A' + 10;
			} else if ((cpumask[car] >= '0') &&
			           (cpumask[car] <= '9')) {
				val = cpumask[car] - '0';
			} else {
				return -1;
			}

			if (index >= FPN_ARRAY_SIZE(coremask->core_set)) {
				return -1;
			}

			/* Fill mask */
			coremask->core_set[index] |= ((fpn_core_set_t) val) << shift;
			shift += 4;

			/* Change core set index if needed */
			if (shift == (8 * sizeof(fpn_core_set_t))) {
				index++;
				shift = 0;
			}
		}
	} else {
		/* Else this is a list of cores */
		min = FPN_MAX_CORES;
		do {
			core = strtoul(cpumask, &end, 10);
			if (end != NULL) {
				if (*end == '-') {
					min = core;
					cpumask = end + 1;
				} else if ((*end == ',') || (*end == '\0')) {
					max = core;
					if (min == FPN_MAX_CORES)
						min = core;
					for (core=min; core<=max; core++) {
						fpn_cpumask_set(coremask, core);
					}
					min = FPN_MAX_CORES;
					if (*end != '\0')
						cpumask = end + 1;
				} else {
					break;
				}
			}
		} while ((cpumask[0] != '\0') && (end != NULL) && (*end != '\0'));
		if ((cpumask[0] == '\0') || (end == NULL) || (*end != '\0'))
			return -1;
	}

	return 0;
}

#ifndef CONFIG_MCORE_ARCH_OCTEON
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>

/*
 * Overwrite /proc/self/task/<pid>/comm, used by 'top'
 */
int fpn_thread_setname(const char *name)
{
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif
	size_t name_len = strlen (name);

	if (name_len >= TASK_COMM_LEN)
		return -1;

#define FMT "/proc/self/task/%lu/comm"
	char fname[sizeof(FMT) + 9];
	snprintf(fname, sizeof(fname), FMT, syscall(SYS_gettid));

	int fd = open(fname, O_RDWR);
	if (fd == -1)
		return -1;

	if (write(fd, name, name_len) < 0)
		return -1;

	close(fd);

	return 0;
}
#endif
