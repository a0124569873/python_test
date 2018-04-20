/*
 * Copyright(c) 2013 6WIND
 */

#include "fpn.h"
#include "fpn-sw-sched.h"

#include "fp.h"
#include "fp-main-process.h"

#include "fp-mbuf-priv.h"
#include "fp-exceptions.h"
#include "fp-stats.h"

#include "fpdebug.h"
#include "fpdebug-priv.h"

#if defined(CONFIG_MCORE_NETFILTER) && defined(CONFIG_MCORE_M_TAG)
#include "fp-log.h"
#include "fp-nf-tables.h"
#endif

#define PLUGIN_NAME "egress-qos"

#include "log.h"

struct egress_qos_stats {
	uint64_t enq_ok;
	uint64_t enq_fail;
	uint64_t deq_ok;
};

#define SCHED_MAX_PKT_BURST 32
struct portmap {
	FPN_LIST_ENTRY(portmap) schedlist;
	FPN_LIST_ENTRY(portmap) flushlist;
	void *sched;
	struct egress_qos_stats s;
	unsigned int m_table_len;
	struct mbuf *m_table[SCHED_MAX_PKT_BURST];
};

#include "cpumap.h"

static struct cpumap cpumap[FPN_MAX_CORES];

struct cpumap_specific {
	/* all scheduling ports are here */
	FPN_LIST_HEAD(sched_list, portmap) schedhead;
	/* all ports to be drained on next loop are here */
	FPN_LIST_HEAD(flush_list, portmap) flushhead;
};
static struct cpumap_specific cpumap_list[FPN_MAX_CORES];

#include <sys/types.h>
#include <sys/stat.h>

static int parse_profile(char *str, unsigned long int core, unsigned long int port,
                         struct portmap *map, const fpn_cpumask_t *mask)
{
	static char name[32];
	char file[512] = { 0 };
	void *arg;
	struct stat st;
	fpn_sw_sched_params_t params;

	snprintf(name, sizeof(name), "port_%lu_%lu", port, core);

	/* first, try to look at file with current path */
	snprintf(file, sizeof(file), "%s", str);
	if (stat(file, &st) < 0) {
		const char *prefix = getenv("EGRESS_QOS_SCHED_CONFIG_DIR");

		if (!prefix)
			prefix = "/usr/admin/etc";

		snprintf(file, sizeof(file), "%s/%s", prefix, str);

		if (stat(file, &st) < 0) {
			/* finally, try from image */
			snprintf(file, sizeof(file), "/etc/%s", str);
		}
	}

	params.name = name;
	params.core = core;
	params.port = port;
	params.arg = file;

	if (!(arg = fpn_sw_sched_allocate(&params)))
		return -1;

	map->sched = arg;
	/* insert this scheduler in cpu list */
	FPN_LIST_INSERT_HEAD(&cpumap_list[core].schedhead, map, schedlist);

	return 0;
}

FPN_HOOK_CHAIN(fp_if_output)

static hook_t *hook_p;

static int sched_drain_cache(struct portmap *map);

/* for cpu-usage, hook must return something that is > 0 */
static int sched_hook(void)
{
	unsigned int cur = fpn_get_core_num();
	struct cpumap_specific *list = &cpumap_list[cur];
	int done = 0;

	if (!FPN_LIST_EMPTY(&list->schedhead)) {
		struct portmap *map;

		/* enqueue all remaining packets in their respective schedulers */
		FPN_LIST_FOREACH(map, &list->flushhead, flushlist) {
			sched_drain_cache(map);
			done++;
		}

		/* dequeue packets waiting in all schedulers */
		FPN_LIST_FOREACH(map, &list->schedhead, schedlist) {
			unsigned int count, i;
			struct mbuf *m_table[SCHED_MAX_PKT_BURST];
			struct mbuf *m;

			count = fpn_sw_sched_dequeue(map->sched, m_table, SCHED_MAX_PKT_BURST);
			if (count) {
				map->s.deq_ok += count;
				done++;
			}

			/* resume work on this packet */
			for (i = 0; i < count; i++) {
				m = m_table[i];
				m_call_process_fct(m);
			}
		}
	}

	/* if a hook had been set, call it as well */
	if (unlikely(hook_p != NULL)) {
		if (hook_p() > 0)
			done++;
	}

	return done;
}

/* we know that m_table_len != 0, because we can only reach this function after
 * sched_enqueue */
inline static int sched_drain_cache(struct portmap *map)
{
	unsigned int n = map->m_table_len, ret;

	map->m_table_len = 0;
	FPN_LIST_REMOVE(map, flushlist);

	ret = fpn_sw_sched_enqueue(map->sched, map->m_table, n);

	map->s.enq_ok   += ret;
	map->s.enq_fail += (n - ret);

	return ret;
}

inline static int sched_enqueue(unsigned int core, unsigned int port, struct mbuf *m)
{
	struct cpumap *cpu = &cpumap[core];
	struct portmap *map = &cpu->ports[port];
	struct cpumap_specific *list = &cpumap_list[core];

	map->m_table[map->m_table_len] = m;
	map->m_table_len++;

	/* first packet, add ourself in flushlist, so that if sched_drain_cache
	 * is not called, sched_hook will drain it */
	if (map->m_table_len == 1)
		FPN_LIST_INSERT_HEAD(&list->flushhead, map, flushlist);
	/* enough packets */
	else if (map->m_table_len == SCHED_MAX_PKT_BURST)
		sched_drain_cache(map);

	return 0;
}

inline static void sched_classify_packet(struct portmap *map, struct mbuf *m)
{
	uint32_t mark = 0;

#if defined(CONFIG_MCORE_NETFILTER) && defined(CONFIG_MCORE_M_TAG)
	/* if we have a mark, use it */
	if (!m_tag_get(m, nfm_tag_type, &mark))
		mark = ntohl(mark);
	else
#endif
		mark = fpn_sw_sched_default_class(map->sched, m);

	fpn_sw_sched_classify(map->sched, m, mark);
}

int fp_if_output(struct mbuf *m, fp_ifnet_t *ifp)
{
	/* current fpn_sw_sched only supports physical ports */
	if (unlikely(ifp->if_port != FP_IFNET_VIRTUAL_PORT)) {
		unsigned int cur = fpn_get_core_num();
		struct portmap *map = &cpumap[cur].ports[ifp->if_port];

		if (map->sched) {
			/* prepare packet */
			if (!m_set_process_fct(m, FPN_HOOK_PREV(fp_if_output), ifp)) {
				sched_classify_packet(map, m);
				sched_enqueue(cur, ifp->if_port, m);

				/* Let's tell fast path we handled this packet */
				return FP_KEEP;
			}

			/* fast path will drop and free mbuf */
			return FP_DROP;
		}
	}

	/* else, handle locally */
	return FPN_HOOK_PREV(fp_if_output)(m, ifp);
}

static int dump_egress_qos_stats(char *tok)
{
	unsigned int cpu;

	fpn_for_each_cpumask(cpu, &fpn_coremask) {
		int i;

		fpdebug_printf("core %u\n", cpu);

		for (i = 0 ; i < FP_MAX_PORT; i++) {
			uint32_t ifuid;
			fp_ifnet_t *ifp;
			struct portmap *map = &cpumap[cpu].ports[i];

			ifuid = fp_shared->ifport[i].ifuid;
			if (!ifuid || !map->sched)
				continue;

			ifp = __fp_ifuid2ifnet(ifuid);
			fpdebug_printf("  %s ifuid:0x%08x port:%"PRIu8"\n",
			               ifp->if_name, ntohl(ifuid), ifp->if_port);
			fpdebug_printf("    enq_ok=%"PRIu64"\n", map->s.enq_ok);
			fpdebug_printf("    enq_fail=%"PRIu64"\n", map->s.enq_fail);
			fpdebug_printf("    deq_ok=%"PRIu64"\n", map->s.deq_ok);

			fpn_sw_sched_dump_stats(map->sched, tok);
		}
	}

	return 0;
}

static int reset_egress_qos_stats(char *tok)
{
	unsigned int cpu;

	fpn_for_each_cpumask(cpu, &fpn_coremask) {
		int i;

		for (i = 0 ; i < FP_MAX_PORT; i++) {
			struct portmap *map = &cpumap[cpu].ports[i];

			if (!map->sched)
				continue;

			memset(&map->s, 0, sizeof(map->s));
			fpn_sw_sched_reset_stats(map->sched, tok);
		}
	}

	return 0;
}

static CLI_COMMAND egress_qos_cmds[] = {
	{"dump-egress-qos-stats", dump_egress_qos_stats, "display egress qos plugin stats"},
	{"reset-egress-qos-stats", reset_egress_qos_stats, "reset egress qos plugin stats"},
	{ NULL, NULL, NULL },
};
static cli_cmds_t egress_qos_cli = {
	.module = "egress-qos",
	.c = egress_qos_cmds,
};

static void lib_init(void) __attribute__((constructor));
void lib_init(void)
{
	unsigned int cpu;
	char *cpumap_env;
	static fpn_mainloop_ops_t sched_mainloop_ops;

	/* this must be resolved at runtime, so initialize this here */
	sched_mainloop_ops.input = fpn_mainloop_ops->input;
	sched_mainloop_ops.soft_input = fpn_mainloop_ops->soft_input;
	sched_mainloop_ops.hook = sched_hook;

	memset(cpumap, 0, sizeof(cpumap));
	for (cpu = 0; cpu < FPN_MAX_CORES; cpu++) {
		FPN_LIST_INIT(&cpumap_list[cpu].schedhead);
		FPN_LIST_INIT(&cpumap_list[cpu].flushhead);
	}

	if ((cpumap_env = getenv("EGRESS_QOS_SCHED_CPUPORTMAP"))) {
		if (parse_cpumap(cpumap_env, cpumap, &fpn_coremask, parse_profile) < 0)
			return;
	}

	fpdebug_add_commands(&egress_qos_cli);

	hook_p = fpn_mainloop_ops->hook;
	fpn_register_mainloop_ops(&sched_mainloop_ops);
}
