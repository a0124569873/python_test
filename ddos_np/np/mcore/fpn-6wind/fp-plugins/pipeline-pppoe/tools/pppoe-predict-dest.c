/*
 * Copyright(c) 2013 6WIND
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "fpn.h"

#include "fp-jhash.h"

#define PLUGIN_NAME "pppoe-load-balancer"

#include "log.h"
#include "portmap.h"

struct cpumap cpumap[FPN_MAX_CORES];

static void
usage(char *name)
{
	fprintf(stderr, "%s: coremask portmask ppp_sessionid ip_src ip_dst\n",
	        name);
	exit(EXIT_FAILURE);
}

int
pppoe_cpumask_parse(const char * cpumask, fpn_cpumask_t * coremask)
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

int main(int argc, char *argv[])
{
	uint32_t rxhash = 0;
	uint32_t a, b, c;
	struct in_addr ip[2];
	struct in6_addr ip6[2];
	long int tmp;
	uint16_t ppp_sid;
	char *cpumap_env;
	fpn_cpumask_t coremask;
	uint64_t portmask;
	int i;

	if (argc < 6)
		usage(argv[0]);

	if (pppoe_cpumask_parse(argv[1], &coremask) < 0) {
		printf("Invalid core mask\n");
		return -1;
	}

	portmask = strtol(argv[2], NULL, 0);

	if ((cpumap_env = getenv("PPPOE_LB_CPUPORTMAP"))) {
		if (parse_cpumap(cpumap_env, cpumap, &coremask, parse_cores) < 0)
			return -1;
	}

	tmp = strtol(argv[3], NULL, 0);
	if (tmp < 0 || tmp >= 1 << 16)
		usage(argv[0]);

	ppp_sid = htons((uint16_t)tmp);

	if ((inet_pton(AF_INET, argv[4], &ip[0]) == 1) &&
	    (inet_pton(AF_INET, argv[5], &ip[1]) == 1)) {

		a = ip[0].s_addr;
		b = ip[1].s_addr;
		c = ppp_sid;
		fp_jhash_mix(a, b, c);

		rxhash = c;
	}
	else
	if ((inet_pton(AF_INET6, argv[4], &ip6[0]) == 1) &&
	    (inet_pton(AF_INET6, argv[5], &ip6[1]) == 1)) {

		a = ip6[0].s6_addr32[0];
		b = ip6[0].s6_addr32[1];
		c = ip6[0].s6_addr32[2];
		fp_jhash_mix(a, b, c);

		a += ip6[0].s6_addr32[3];
		b += ip6[1].s6_addr32[0];
		c += ip6[1].s6_addr32[1];
		fp_jhash_mix(a, b, c);

		a += ip6[1].s6_addr32[2];
		b += ip6[1].s6_addr32[3];
		c += ppp_sid;
		fp_jhash_mix(a, b, c);

		rxhash = c;
	}
	else {
		rxhash = ppp_sid;
	}

	for (i = 0; i < FPN_MAX_CORES; i++) {
		int j;

		if (!fpn_cpumask_ismember(&coremask, i))
			continue;

		for (j = 0; j < FPN_MAX_PORTS; j++) {
			int k, index;
			struct portmap *map = &cpumap[i].ports[j];

			if (!(portmask & (1ULL << j)))
				continue;

			if (!map->count) {
				PLUGIN_INFO("recv core %d, port %d, "
				            "all traffic handled locally\n", i, j);
				continue;
			}

			/*
			 * because of this shift operation , we can't have too many elements
			 * in map => COREMAP_MAX == 32
			 */
			index = ((uint64_t)rxhash*map->count)>>COREMAP_MAX;
			k = map->next[index];
			PLUGIN_INFO("recv core %d, port %d, "
			            "pppoe sent to dest core %d\n", i, j, k);
		}
	}

	return 0;
}
