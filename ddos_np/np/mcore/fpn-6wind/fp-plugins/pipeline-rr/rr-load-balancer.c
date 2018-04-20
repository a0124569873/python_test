/*
 * Copyright(c) 2013 6WIND
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "fpn.h"
#include "fpn-intercore.h"

#include "fp.h"
#include "fp-ether.h"

#define PLUGIN_NAME "rr-load-balancer"

#include "log.h"
#include "portmap.h"

static struct cpumap cpumap[FPN_MAX_CORES];

FPN_HOOK_CHAIN(fp_ether_input)

int fp_ether_input(struct mbuf *m, fp_ifnet_t *ifp)
{
	unsigned int cur = fpn_get_core_num();
	struct portmap *map;

	map = &cpumap[cur].ports[ifp->if_port];

	if (map->count) {
		uint8_t next = map->next[map->current];

		if (map->current < map->count - 1)
			map->current++;
		else
			map->current = 0;

		if (!m_set_process_fct(m, FPN_HOOK_PREV(fp_ether_input), ifp) &&
		    !fpn_intercore_enqueue(m, next))
			/* Let's tell Fast Path we handled this packet */
			return FP_KEEP;

		/* Fast Path will drop and free mbuf */
		return FP_DROP;
	}

	/* else, handle locally */
	return FPN_HOOK_PREV(fp_ether_input)(m, ifp);
}

static void lib_init(void) __attribute__((constructor));
void lib_init(void)
{
	int i, j, k;
	char *cpumap_env;
	fpn_cpumask_t mask;

	fpn_cpumask_clear(&mask);
	memset(cpumap, 0, sizeof(cpumap));

	if ((cpumap_env = getenv("RR_LB_CPUPORTMAP"))) {
		if (parse_cpumap(cpumap_env, cpumap, &fpn_coremask,
		                 parse_cores) < 0)
			return;
	}

	/* Let's find which cpu must look at their intercore ring */
	for (i = 0; i < FPN_MAX_CORES; i++) {
		for (j = 0; j < FPN_MAX_PORTS; j++) {
			struct portmap *map = &cpumap[i].ports[j];
			for (k = 0; k < map->count; k++) {
				fpn_cpumask_set(&mask, map->next[k]);
			}
		}
	}

	/* Ok, ready */
	fpn_cpumask_add(&fpn_intercore_mask, &mask);

	fpn_cpumask_display(PLUGIN_NAME ": using fpn_intercore_mask=", &fpn_intercore_mask);
	fpn_cpumask_display(", plugin mask=", &mask);
	printf("\n");
}
