/*
 * Copyright(c) 2013 6WIND
 */

#ifndef __CPUMAP_H__
#define __CPUMAP_H__

#include "fpn-core.h"

/* portmap structure must be defined before including this header */
struct cpumap {
	struct portmap ports[FPN_MAX_PORTS];
} __fpn_cache_aligned;

typedef int (cpumap_parser)(char *str, unsigned long int core,
                            unsigned long int port, struct portmap *map,
                            const fpn_cpumask_t *mask);

static int parse_map_elt(char *str, struct cpumap *map, const fpn_cpumask_t *mask,
                         cpumap_parser *parser)
{
	char *srccore = NULL, *srcport = NULL, *tail = NULL;
	char *cur, *next;
	struct portmap *portmap;
	unsigned long int port;
	long int tmp;
	int i;

	if (!parser)
		return -1;

	cur = str;
	next = strchr(cur, '=');
	if (next) {
		srcport = cur;
		tail = cur = next+1;
	}

	next = strchr(cur, '=');
	if (next) {
		srccore = srcport;
		srcport = cur;
		tail = cur = next+1;
		cur = next+1;
	}

	next = strchr(cur, '=');
	if (next || !tail) {
		PLUGIN_ERR("invalid cpu map: %s\n", str);
		return -1;
	}

	tmp = strtol(srcport, &next, 0);
	if ((tmp < 0) || (next[0] != '=') ||
	    (tmp > FPN_MAX_PORTS)) {
		PLUGIN_ERR("invalid port in cpu map: %s\n", str);
		return -1;
	}
	port = tmp;

	if (srccore) {
		tmp = strtol(srccore, &next, 0);
		if ((tmp < 0) || (next[0] != '=') ||
		    (tmp > FPN_MAX_CORES) || !fpn_cpumask_ismember(mask, tmp)) {
			PLUGIN_ERR("invalid source core in cpu map: %s\n", str);
			return -1;
		}

		portmap = &map[tmp].ports[port];
		if (parser(tail, tmp, port, portmap, mask) < 0)
			return -1;
	}
	else {
		for (i = 0; i < FPN_MAX_CORES; i++) {
			portmap = &map[i].ports[port];
			if (parser(tail, i, port, portmap, mask) < 0)
				return -1;
		}
	}

	return 0;
}

static int parse_cpumap(char *str, struct cpumap *map, const fpn_cpumask_t *mask,
                        cpumap_parser *parser)
{
	char *cur, *next;

	if (!parser)
		return -1;

	cur = str;
	while ((next = strchr(cur, '/'))) {
		next[0] = '\0';
		next++;

		if (parse_map_elt(cur, map, mask, parser) < 0 )
			return -1;

		cur = next;
	}
	/* last element */
	if (parse_map_elt(cur, map, mask, parser) < 0 )
		return -1;

	return 0;
}
#endif
