/*
 * Copyright(c) 2013 6WIND
 */

#ifndef __PORTMAP_H__
#define __PORTMAP_H__

#define COREMAP_MAX 32
struct portmap {
	uint8_t next[COREMAP_MAX];
	uint8_t count;
};

#include "cpumap.h"

static int parse_cores(char *str, unsigned long int cpu, unsigned long int port,
                       struct portmap *map, const fpn_cpumask_t *mask)
{
	char *cur, *next, *tmp;
	long int core;

	(void)cpu;
	(void)port;

	cur = str;
	while ((next = strchr(cur, ':'))) {
		core = strtol(cur, &tmp, 0);
		if ((core < 0) || (tmp[0] != ':') ||
		    (core > FPN_MAX_CORES) || fpn_cpumask_ismember(mask, core)) {
			PLUGIN_ERR("invalid dest core in cpu map: %s\n", str);
			return -1;
		}

		if (map->count >= COREMAP_MAX) {
			PLUGIN_ERR("too many dest cores in cpu map: %s\n", str);
			return -1;
		}

		map->next[map->count] = core;
		map->count++;

		cur = next+1;
	}

	/* last element */
	core = strtol(cur, &tmp, 0);
	if ((core < 0) || (tmp[0] != '\0') ||
	    (core > FPN_MAX_CORES) || !fpn_cpumask_ismember(mask, core)) {
		PLUGIN_ERR("invalid dest core in cpu map: %s\n", str);
		return -1;
	}

	if (map->count >= COREMAP_MAX) {
		PLUGIN_ERR("too many dest cores in cpu map: %s\n", str);
		return -1;
	}

	map->next[map->count] = core;
	map->count++;

	return 0;
}

#endif
