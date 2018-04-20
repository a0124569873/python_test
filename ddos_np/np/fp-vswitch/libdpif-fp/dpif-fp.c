/*
 * Copyright (c) <2014>, 6WIND
 * All rights reserved.
 */
#include "fpn.h"
#include "fpn-shmem.h"
#define FPVS_MAX_OVS_PORTS              256
#include "fpvs-cp.h"
#include "fpvs-common.h"
#include "fp-vswitch.h"

#include "linux/openvswitch.h"
#include "dpif-fp.h"

#define FPVS_SHMEM_CHECK()                           \
    if (!fpvs_shmem_done) {                          \
        if ((fpvs_map_shm() < 0) ||                  \
            (fpvs_shared->magic != FP_FPVS_MAGIC32)) \
            return -1;                               \
        shared_table->dpif_magic = FP_DPIF_MAGIC32;  \
        fpvs_shmem_done = 1;                         \
    }

int fpvs_parse_flow_key(struct nlattr *key_attr, size_t key_len, struct cp_flow_key *key, int encap);
int fpvs_parse_nested_flow_key(struct nlattr *key_attr, struct cp_flow_key *key, int encap);

static int fpvs_shmem_done = 0;

int dpif_fp_port_get(uint32_t ovsport, struct ovs_vport_stats *stats)
{
	fp_vswitch_port_t *port;
	/* declare as volatile to avoid unwanted AVX optimization */
	volatile fp_vswitch_port_stats_t port_stats;
	int i;

	FPVS_SHMEM_CHECK();

	port = fpvs_get_port(ovsport);
	if (port->type == OVS_VPORT_TYPE_UNSPEC)
		return -1;

	port_stats = port->stats[0];
	for (i = 1; i < FP_VSWITCH_STATS_NUM; i++) {
		port_stats.rx_pkts += port->stats[i].rx_pkts;
		port_stats.tx_pkts += port->stats[i].tx_pkts;
		port_stats.rx_bytes += port->stats[i].rx_bytes;
		port_stats.tx_bytes += port->stats[i].tx_bytes;
	}

	stats->rx_packets += port_stats.rx_pkts;
	stats->tx_packets += port_stats.tx_pkts;
	stats->rx_bytes += port_stats.rx_bytes;
	stats->tx_bytes += port_stats.tx_bytes;

	return 0;
}

int dpif_fp_flow_flush(void)
{
	int i;

	FPVS_SHMEM_CHECK();

	for (i = 1; i < MAX_FLOWS; i++) {
		struct fpvs_flow* flow = &shared_table->flow_table[i].flow;

		if (flow->state == FPVS_FLOW_ACTIVE) {
			fpvs_remove_flow(shared_table, flow);
		}
	}

	return 0;
}

int dpif_fp_flow_put(const struct nlattr *key, size_t key_len,
		     const struct nlattr *mask, size_t mask_len,
		     const struct nlattr *actions, size_t actions_len,
		     uint8_t create)
{
	struct cp_flow_key cpkey;
	struct cp_flow_key cpmask;
	struct fp_flow_key nk __attribute__((aligned(FPVS_FLOW_ALIGNMENT)));
	struct fp_flow_key nm __attribute__((aligned(FPVS_FLOW_ALIGNMENT)));
	struct fp_flow_key dst __attribute__((aligned(FPVS_FLOW_ALIGNMENT)));
	struct fp_key_range range;
	struct fpvs_flow *flow;
	int result;

	FPVS_SHMEM_CHECK();

	result = fpvs_parse_flow_key((struct nlattr *)key, key_len, &cpkey, 0);
	if (result)
		return -1;

	if (mask) {
		result = fpvs_parse_flow_key((struct nlattr *)mask, mask_len, &cpmask, 0);
		if (result)
			return -1;
	} else {
		/* if mask is not present, do exact matching,
		 * tcp flags are never matched in that case, because it would
		 * always fail.
		 */
		memset(&cpmask, 0xff, sizeof(cpmask));
		cpmask.l4.flags = 0;
	}

	cp_to_fp_flow_key(&cpkey, &nk);
	cp_to_fp_flow_key(&cpmask, &nm);
	fpvs_mask_to_range(&nm, &range);
	fpvs_flow_mask(&dst, &nk, &nm, 0, sizeof(struct fp_flow_key));

	flow = fpvs_lookup_flow(shared_table, &dst);
	if (!flow) {
		if (create) {
			/* insert */
			fpvs_insert_flow(shared_table, &dst, &nm,
					 actions, actions_len, &range);
			return 0;
		}
		return -1;
	}

	/* update action */
	if (actions_len > FPVS_MAX_ACTION_SIZE) {
		/* FIXME: This should never happen. */
		fpvs_remove_flow(shared_table, flow);
	} else {
		flow->age = 0;
		flow->hit = 1;
		flow->used = 0;
		memcpy(flow->actions, actions, actions_len);
		flow->actions_len = actions_len;
	}

	return 0;
}

int dpif_fp_flow_del(const struct nlattr *key, size_t key_len)
{
	struct cp_flow_key cpkey;
	struct fp_flow_key dst __attribute__((aligned(FPVS_FLOW_ALIGNMENT)));
	struct fpvs_flow *flow;
	int result;

	FPVS_SHMEM_CHECK();

	result = fpvs_parse_flow_key((struct nlattr *)key, key_len, &cpkey, 0);
	if (result)
		return -1;

	cp_to_fp_flow_key(&cpkey, &dst);

	flow = fpvs_lookup_flow(shared_table, &dst);
	if (!flow)
		return -1;

	flow->age = 0;
	flow->hit = 0;
	flow->used = 0;
	fpvs_remove_flow(shared_table, flow);

	return 0;
}

int dpif_fp_flow_get(const struct nlattr *key, size_t key_len,
		     const struct nlattr *mask, size_t mask_len,
		     struct ovs_flow_stats *stats, uint8_t *tcp_flags,
		     uint64_t *used, uint64_t time)
{
	struct cp_flow_key cpkey;
	struct fp_flow_key dst __attribute__((aligned(FPVS_FLOW_ALIGNMENT)));
	struct fpvs_flow *flow;
	int result;
	fpvs_flow_stats_t flow_stats;
	int i;

	FPVS_SHMEM_CHECK();

	result = fpvs_parse_nested_flow_key((struct nlattr *)key, &cpkey, 0);
	if (result)
		return -1;

	cp_to_fp_flow_key(&cpkey, &dst);

	flow = fpvs_lookup_flow(shared_table, &dst);
	if (!flow)
		return -1;

	flow_stats = flow->stats[0];
	for (i = 1; i < FPVS_FLOW_STATS_NUM; i++) {
		flow_stats.pkts += flow->stats[i].pkts;
		flow_stats.bytes += flow->stats[i].bytes;
	}

	stats->n_packets += flow_stats.pkts;
	stats->n_bytes += flow_stats.bytes;

	/* if flow was hit, send current time and reset hit */
	if (flow->hit) {
		*used = time;
		flow->hit = 0;
		flow->used = time;
	} else
	/* else send last stored value */
		*used = flow->used;

	*tcp_flags |= flow->key.l4.flags;

	return 0;
}
