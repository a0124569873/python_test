/*
 * Copyright(c) 2013 6WIND
 */

#ifndef __PORTMAP_H__
#define __PORTMAP_H__

struct portmap {
	int next;
};

#include "cpumap.h"

static int parse_cores(char *str, unsigned long int cpu, unsigned long int port,
                       struct portmap *map, const fpn_cpumask_t *mask)
{
	char *tmp;
	long int core;

	core = strtol(str, &tmp, 0);
	if ((core < 0) || (tmp[0] != '\0') ||
	    (core > FPN_MAX_CORES) || !fpn_cpumask_ismember(mask, core)) {
		PLUGIN_ERR("invalid dest core in cpu map: %s\n", str);
		return -1;
	}

	map->next = (int) core;

	return 0;
}

#endif
