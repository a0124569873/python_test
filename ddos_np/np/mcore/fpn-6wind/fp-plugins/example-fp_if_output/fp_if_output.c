/*
 * Copyright(c) 2013 6WIND
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "fpn.h"
#include "fpn-intercore.h"

#include "fp.h"
#include "fp-main-process.h"

#define PLUGIN_NAME "fp_if_output"

#include "log.h"
#include "portmap.h"

static struct cpumap cpumap[FPN_MAX_CORES];

FPN_HOOK_CHAIN(fp_if_output)

int fp_if_output(struct mbuf *m, fp_ifnet_t *ifp)
{
	unsigned int cur = fpn_get_core_num();
	int next;

	next = cpumap[cur].ports[ifp->if_port].next;
	/* no mapping, execute original hook */
	if (next < 0)
		return FPN_HOOK_PREV(fp_if_output)(m, ifp);

	if (!m_set_process_fct(m, FPN_HOOK_PREV(fp_if_output), ifp) &&
	    !fpn_intercore_enqueue(m, next))
		/* Let's tell Fast Path we handled this packet */
		return FP_KEEP;

	/* Fast Path will drop and free mbuf */
	return FP_DROP;
}

static void lib_init(void) __attribute__((constructor));
void lib_init(void)
{
	int i, j;
	char *cpumap_env;
	fpn_cpumask_t mask;

	fpn_cpumask_clear(&mask);

	for (i = 0; i < FPN_MAX_CORES; i++) {
		for (j = 0; j < FPN_MAX_PORTS; j++) {
			cpumap[i].ports[j].next = -1;
		}
	}

	if ((cpumap_env = getenv("FP_TX_CPUPORTMAP"))) {
		if (parse_cpumap(cpumap_env, cpumap, &fpn_coremask, parse_cores) < 0)
			return;
	}

	/* Let's find which cpu must look at their intercore ring */
	for (i = 0; i < FPN_MAX_CORES; i++) {
		for (j = 0; j < FPN_MAX_PORTS; j++) {
			if (cpumap[i].ports[j].next < 0) continue;

			fpn_cpumask_set(&mask, cpumap[i].ports[j].next);
		}
	}

	/* Ok, ready */
	fpn_cpumask_add(&fpn_intercore_mask, &mask);

	fpn_cpumask_display(PLUGIN_NAME ": using fpn_intercore_mask=", &fpn_intercore_mask);
	fpn_cpumask_display(", plugin mask=", &mask);
	printf("\n");
}
