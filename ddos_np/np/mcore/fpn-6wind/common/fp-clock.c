/*
 * Copyright(c) 2011 6WIND
 */
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "fp.h"

#ifndef FP_STANDALONE
#ifdef CONFIG_MCORE_ARCH_OCTEON
uint64_t get_clock_hz()
{
	char buf[256];
	uint64_t value = 0;
	FILE *fp = fopen("/proc/octeon_info", "r");

	if (!fp) {
		fp_log_common(LOG_ERR, "Unable to open /proc/octeon_info");
		return 1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		char text[256];

		sscanf(buf, "%s%"PRIu64, text, &value);
		if(!strncmp("eclock_hz", text, strlen("eclock_hz"))) {
			fclose(fp);
			return value;
		}
	}

	fclose(fp);
	return 1;
}

#elif defined(CONFIG_MCORE_ARCH_XLP)

uint64_t get_clock_hz()
{
	char buf[256];
	unsigned long long value = 0;
	FILE *fp = fopen("/proc/netlogic/xlp_cpu", "r");

	if (!fp) {
		fp_log_common(LOG_ERR, "Unable to open /proc/netlogic/xlp_cpu\n");
		return 1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		char text[256];

		sscanf(buf, "CPU %s%llu", text, &value);
		if(!strncmp("Frequency", text, strlen("Frequency"))) {
			fclose(fp);
			return value;
		}
	}

	fclose(fp);
	return 1;
}

#else

uint64_t get_clock_hz()
{
	char buf[256];
	FILE *fp;
	uint64_t freq = 1;
	double dmhz;

	fp = fopen("/proc/cpuinfo","r");
	if (!fp) {
		fp_log_common(LOG_ERR,"Unable to open /proc/cpuinfo\n");
		return 1;
	}

	while (fgets(buf,sizeof(buf),fp)) {
		if (sscanf(buf,"cpu MHz\t: %lf", &dmhz) == 1) {
			freq = (uint64_t)(dmhz * 1000000UL);
			break;
		}
	}
	fclose(fp);

	return freq;
}

#endif
#endif
