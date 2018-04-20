

/*
 * Copyright(c) 2014 6WIND
 * All rights reserved
 */
#ifndef __FastPath__
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#endif

#include "fpn.h"
#include "fp.h"
#include "fp-if.h"
#include "net/fp-socket.h"   /* for AF_INET6 */
#include "fpdebug.h"
#include "fpdebug-priv.h"
#include "fpdebug-stats.h"

#include "fpvs-print.h"

#include "shmem/fpn-shmem.h"
#include "fp-vswitch.h"
#include "fpvs-common.h"
#include "linux/openvswitch.h"

struct dump_fp_vswitch_item {
	unsigned int enable:1;
	unsigned int by_default:1;
	const char *const name;
	const size_t offset;
	const size_t size;
	void (*const func)(const struct dump_fp_vswitch_item *,
			   const fpvs_flow_entry_t *);
};

#define DUMP_FP_VSWITCH_ITEM(f, suffix, def)				\
	{								\
		.by_default = def,					\
		.name = # f,						\
		.offset = offsetof(const fpvs_flow_entry_t, f),		\
		.size = sizeof(((const fpvs_flow_entry_t *)NULL)->f),	\
		.func = dump_fp_vswitch_item_ ## suffix			\
	}

#define DUMP_FP_VSWITCH_ITEM_BF(f, suffix, def)				\
	{								\
		.by_default = def,					\
		.name = # f,						\
		.offset = (size_t)-1,					\
		.size = (size_t)-1,					\
		.func = dump_fp_vswitch_item_ ## suffix			\
	}

#define dump_fp_vswitch_item_NULL NULL

static void
dump_fp_vswitch_item_u32(const struct dump_fp_vswitch_item *item,
			 const fpvs_flow_entry_t *ent)
{
	uint32_t data = *(const uint32_t *)((const uint8_t *)ent + item->offset);

	fpdebug_printf(".%s = %" PRIu32 ", ", item->name, data);
}

static void
dump_fp_vswitch_item_be64(const struct dump_fp_vswitch_item *item,
			  const fpvs_flow_entry_t *ent)
{
	uint64_t data = *(const uint64_t *)((const uint8_t *)ent + item->offset);

	fpdebug_printf(".%s = %" PRIu64 ", ", item->name, ntohll(data));
}

static void
dump_fp_vswitch_item_blob(const struct dump_fp_vswitch_item *item,
			  const fpvs_flow_entry_t *ent)
{
	const uint8_t *p = ((const uint8_t *)ent + item->offset);
	uint8_t data[item->size * 4]; /* format each byte like "\x2a" */
	size_t i;

	for (i = 0; (i != item->size); ++i) {
		data[(i * 4) + 0] = '\\';
		data[(i * 4) + 1] = 'x';
		data[(i * 4) + 2] = "0123456789abcdef"[p[i] >> 4];
		data[(i * 4) + 3] = "0123456789abcdef"[p[i] & 0xf];
	}
	fpdebug_printf(".%s = \"%.*s\", ",
		       item->name,
		       (int)sizeof(data), data);
}

static void
dump_fp_vswitch_item_actions(const struct dump_fp_vswitch_item *item,
			     const fpvs_flow_entry_t *ent)
{
	struct nlattr *actions = (struct nlattr *)((const uint8_t *)ent + item->offset);
	char buf[512];

	actions_to_str(actions, ent->flow.actions_len, buf, sizeof(buf));
	fpdebug_printf(".%s = %s,\n  ", item->name, buf);
}

static void
dump_fp_vswitch_item_int(const struct dump_fp_vswitch_item *item,
			 const fpvs_flow_entry_t *ent)
{
	int data = *(const int *)((const uint8_t *)ent + item->offset);

	fpdebug_printf(".%s = %d, ", item->name, data);
}

static void
dump_fp_vswitch_item_hash_30b(const struct dump_fp_vswitch_item *item,
			      const fpvs_flow_entry_t *ent)
{
	fpdebug_printf(".%s = 0x%08" PRIx32 ", ", item->name, ent->flow.hash);
}

static void
dump_fp_vswitch_item_state_2b(const struct dump_fp_vswitch_item *item,
			      const fpvs_flow_entry_t *ent)
{
	fpdebug_printf(".%s = 0x%" PRIx32 ", ", item->name, ent->flow.state);
}

static void
dump_fp_vswitch_item_in6_addr(const struct dump_fp_vswitch_item *item,
			      const fpvs_flow_entry_t *ent)
{
	const struct in6_addr *p = (const void *)((const uint8_t *)ent + item->offset);
	char data[FP_INET6_ADDRSTRLEN] = "";

	if (fpdebug_inet_ntop(AF_INET6, p, data, sizeof(data)) == NULL)
		dump_fp_vswitch_item_blob(item, ent);
	else
		fpdebug_printf(".%s = \"%s\", ", item->name, data);
}

static void
dump_fp_vswitch_item_in_addr(const struct dump_fp_vswitch_item *item,
			     const fpvs_flow_entry_t *ent)
{
	const struct in_addr *p = (const void *)((const uint8_t *)ent + item->offset);
	char data[FP_INET_ADDRSTRLEN] = "";

	if (fpdebug_inet_ntop(AF_INET, p, data, sizeof(data)) == NULL)
		dump_fp_vswitch_item_blob(item, ent);
	else
		fpdebug_printf(".%s = \"%s\", ", item->name, data);
}

static void
dump_fp_vswitch_item_u16(const struct dump_fp_vswitch_item *item,
			 const fpvs_flow_entry_t *ent)
{
	uint16_t data = *(const uint16_t *)((const uint8_t *)ent + item->offset);

	fpdebug_printf(".%s = %" PRIu16 ", ", item->name, data);
}

static void
dump_fp_vswitch_item_be16(const struct dump_fp_vswitch_item *item,
			  const fpvs_flow_entry_t *ent)
{
	uint16_t data = *(const uint16_t *)((const uint8_t *)ent + item->offset);

	fpdebug_printf(".%s = %" PRIu16 ", ", item->name, ntohs(data));
}

static void
dump_fp_vswitch_item_mac(const struct dump_fp_vswitch_item *item,
			 const fpvs_flow_entry_t *ent)
{
	const uint8_t *p = ((const uint8_t *)ent + item->offset);
	uint8_t data[item->size * 3]; /* format each byte like "2a:" */
	size_t i;

	for (i = 0; (i != item->size); ++i) {
		data[(i * 3) + 0] = "0123456789abcdef"[p[i] >> 4];
		data[(i * 3) + 1] = "0123456789abcdef"[p[i] & 0xf];
		data[(i * 3) + 2] = ':';
	}
	data[sizeof(data) - 1] = '\0';
	fpdebug_printf(".%s = \"%s\", ", item->name, data);
}

static void
dump_fp_vswitch_item_u8(const struct dump_fp_vswitch_item *item,
			const fpvs_flow_entry_t *ent)
{
	uint8_t data = *((const uint8_t *)ent + item->offset);

	fpdebug_printf(".%s = %" PRIu8 ", ", item->name, data);
}

static void
dump_fp_vswitch_item_flow_key(const struct dump_fp_vswitch_item *item,
			      const fpvs_flow_entry_t *ent)
{
	struct fp_flow_key *key = (struct fp_flow_key *)((const uint8_t *)ent + item->offset);
	fpvs_flow_list_t *ffl = shared_table;
	char buf[512];

	flow_key_to_str(key, buf, sizeof(buf));
	fpdebug_printf(".%s = %s,\n  ", item->name, buf);
	mask_key_to_str(&ffl->mask_table[ent->flow.mask_index].mask.key, key->l2.ether_type, buf, sizeof(buf));
	fpdebug_printf(".%s = %s,\n  ", "flow.mask", buf);
}

static int dump_fp_vswitch_flows(char *tok)
{
	struct dump_fp_vswitch_item item[] = {
		DUMP_FP_VSWITCH_ITEM(flow, NULL, 0),
		DUMP_FP_VSWITCH_ITEM(next, u32, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key, flow_key, 1),
		DUMP_FP_VSWITCH_ITEM(flow.actions, actions, 1),
		DUMP_FP_VSWITCH_ITEM(flow.actions_len, int, 0),
		DUMP_FP_VSWITCH_ITEM(flow.index, u32, 0),
		DUMP_FP_VSWITCH_ITEM_BF(flow.hash, hash_30b, 0),
		DUMP_FP_VSWITCH_ITEM_BF(flow.state, state_2b, 0),
		DUMP_FP_VSWITCH_ITEM(flow.age, u32, 0),
		/* L1 */
		DUMP_FP_VSWITCH_ITEM(flow.key.l1.ovsport, u32, 0),
		/* L2 */
		DUMP_FP_VSWITCH_ITEM(flow.key.l2.src, mac, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l2.dst, mac, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l2.ether_type, blob, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l2.vlan_tci, blob, 0),
		/* L3 */
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.frag, u8, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.tos, u8, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.ttl, u8, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.proto, u8, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.ip.src, in_addr, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.ip.dst, in_addr, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.ip.arp.sha, mac, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.ip.arp.tha, mac, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.ip6.src, in6_addr, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.ip6.dst, in6_addr, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.ip6.label, blob, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.ip6.ndp.target, in6_addr, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.ip6.ndp.sll, mac, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l3.ip6.ndp.tll, mac, 0),
		/* L4 */
		DUMP_FP_VSWITCH_ITEM(flow.key.l4.flags, u16, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l4.sport, be16, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.l4.dport, be16, 0),
		/* tunnel */
		DUMP_FP_VSWITCH_ITEM(flow.key.tunnel.id, be64, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.tunnel.src, in_addr, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.tunnel.dst, in_addr, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.tunnel.flags, u16, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.tunnel.tos, u8, 0),
		DUMP_FP_VSWITCH_ITEM(flow.key.tunnel.ttl, u8, 0),

	};
	static const size_t item_n = (sizeof(item) / sizeof(item[0]));
	static fpvs_flow_list_t *ffl;
	unsigned int i;
	unsigned int n = gettokens(tok);

	if (n == 0) {
		/* No arguments, display default items. */
		for (i = 0; (i != item_n); ++i)
			if (item[i].by_default)
				item[i].enable = 1;
	}
	for (i = 0; (i != n); ++i) {
		unsigned int j;

		for (j = 0; (j != item_n); ++j) {
			/* Enable item eventually prefixed with '+'. */
			if (!strcmp(item[j].name,
				    &(chargv[i][chargv[i][0] == '+']))) {
				item[j].enable = 1;
				break;
			}
			/* Disable item prefixed with '-'. */
			else if ((chargv[i][0] == '-') &&
				 (!strcmp(item[j].name, &(chargv[i][1])))) {
				item[j].enable = 0;
				break;
			}
		}
		if (j == item_n) {
			if (strcmp(chargv[i], "help"))
				fpdebug_fprintf(stderr, "wrong arguments: ");
			fpdebug_fprintf(stderr, "dump-fp-vswitch-flows [help");
			for (j = 0; (j != item_n); ++j)
				fpdebug_fprintf(stderr, "|[{+|-}%s]",
						item[j].name);
			fpdebug_fprintf(stderr, "] [...]\n");
			return -1;
		}
		/* Manage groups (items with NULL function pointers). */
		if (item[j].func == NULL) {
			unsigned int k;
			unsigned int len = strlen(item[j].name);

			for (k = 0; (k != item_n); ++k)
				if ((j != k) &&
				    (!strncmp(item[j].name,
					      item[k].name,
					      len)) &&
				    (item[k].name[len] == '.'))
					item[k].enable = item[j].enable;
		}
	}
	/* Retrieve flow list. */
	ffl = shared_table;
	fpdebug_printf("FPVS flow table (max %u flows):\n"
		       "  sizeof(fpvs_flow_entry_t): %zu\n"
		       "  sizeof(struct fpvs_flow): %zu\n"
		       "  Flow max age: %d\n"
		       "\n"
		       ".table = {\n",
		       MAX_FLOWS,
		       sizeof(fpvs_flow_entry_t),
		       sizeof(struct fpvs_flow),
		       ffl->flow_max_age);
	/* Start from index 1 because 0 is reserved. */
	for (i = 1; (i != MAX_FLOWS); ++i) {
		const fpvs_flow_entry_t *ent = &ffl->flow_table[i];
		fpvs_flow_stats_t flow_stats;
		int j;

		if (ent->flow.state == FPVS_FLOW_UNSPEC)
			continue;
		fpdebug_printf("  [%u] = { ", i);

		flow_stats = ent->flow.stats[0];
		for (j = 1; j < FPVS_FLOW_STATS_NUM; j++) {
			flow_stats.pkts += ent->flow.stats[j].pkts;
			flow_stats.bytes += ent->flow.stats[j].bytes;
		}
		fpdebug_printf(".pkts = %" PRIu64 ", ", flow_stats.pkts);
		fpdebug_printf(".bytes = %" PRIu64 ", \n  ", flow_stats.bytes);

		for (n = 0; (n != item_n); ++n)
			if ((item[n].enable) && (item[n].func != NULL))
				item[n].func(&item[n], ent);

		fpdebug_printf("},\n");
	}
	fpdebug_printf("}\n");
	return 0;
}

static int dump_fp_vswitch_masks(char *tok)
{
	static fpvs_flow_list_t *ffl;
	unsigned int i;
	char buf[512];

	/* Retrieve flow list. */
	ffl = shared_table;
	fpdebug_printf("FPVS flow mask table (max %u masks):\n"
		       "  sizeof(fpvs_mask_entry_t): %zu\n"
		       "  sizeof(struct fpvs_mask): %zu\n"
		       "\n"
		       ".table = {\n",
		       MAX_MASKS,
		       sizeof(fpvs_mask_entry_t),
		       sizeof(struct fpvs_mask));
	/* Start from index 1 because 0 is reserved. */
	for (i = 1; (i != MAX_MASKS); ++i) {
		fpvs_mask_entry_t *ent = &ffl->mask_table[i];

		if (ent->mask.state == FPVS_FLOW_UNSPEC)
			continue;

		mask_key_to_str(&ent->mask.key, 0xffff, buf, sizeof(buf));
		fpdebug_printf("  [%u] = {\n", i);
		fpdebug_printf("    ref_count = %u,\n", ent->mask.ref_count);
		fpdebug_printf("    range = [%#x, %#x],\n", ent->mask.range.start, ent->mask.range.end);
		fpdebug_printf("    key = %s\n", buf);
		fpdebug_printf("  },\n");
	}
	fpdebug_printf("}\n");
	return 0;
}

static const char *dump_fp_vswitch_type(uint32_t type)
{
	switch (type) {
	case OVS_VPORT_TYPE_UNSPEC:
		return "unspec";

	case OVS_VPORT_TYPE_NETDEV:
		return "netdev";

	case OVS_VPORT_TYPE_INTERNAL:
		return "internal";

	case OVS_VPORT_TYPE_GRE:
		return "gre";

	case OVS_VPORT_TYPE_VXLAN:
		return "vxlan";

	case OVS_VPORT_TYPE_GRE64:
		return "gre64";

	case OVS_VPORT_TYPE_LISP:
		return "lisp";

	default:
		break;
	}

	return "unknown";
}

#define print_fp_vswitch_port_stats(port, field)			\
	print_stats(port->stats, field, FP_VSWITCH_STATS_NUM)

static int dump_fp_vswitch_ports(char *tok)
{
	int i;
	int percore = 0;
	int nonzero = 0;

	parse_stats_token(tok, percore);

	for (i = 0; i < FPVS_MAX_OVS_PORTS; i++) {
		fp_vswitch_port_t *port = fpvs_get_port(i);

		if (port->type == OVS_VPORT_TYPE_UNSPEC)
			continue;

		fpdebug_printf("%d: %s (%s)\n", i,
			       port->ifp_name,
			       dump_fp_vswitch_type(port->type));
		print_fp_vswitch_port_stats(port, rx_pkts);
		print_fp_vswitch_port_stats(port, tx_pkts);
		print_fp_vswitch_port_stats(port, rx_bytes);
		print_fp_vswitch_port_stats(port, tx_bytes);
	}

	return 0;
}

#define print_fp_vswitch_stats(field) \
	print_stats(fpvs_shared->stats, field, FP_VSWITCH_STATS_NUM)

static int dump_fp_vswitch_stats_(int percore)
{
	print_fp_vswitch_stats(flow_not_found);
	print_fp_vswitch_stats(flow_pullup_failed);
	print_fp_vswitch_stats(flow_pullup_too_small);
	print_fp_vswitch_stats(output_ok);
	print_fp_vswitch_stats(output_failed_no_mbuf);
	print_fp_vswitch_stats(output_failed_no_ifp);
	print_fp_vswitch_stats(output_failed);
	print_fp_vswitch_stats(output_failed_unknown_type);
	print_fp_vswitch_stats(userspace);
	print_fp_vswitch_stats(push_vlan);
	print_fp_vswitch_stats(pop_vlan);
	print_fp_vswitch_stats(push_mpls);
	print_fp_vswitch_stats(pop_mpls);
	print_fp_vswitch_stats(recirc);
	print_fp_vswitch_stats(set_ethernet);
	print_fp_vswitch_stats(set_mpls);
	print_fp_vswitch_stats(set_priority);
	print_fp_vswitch_stats(set_tunnel_id);
	print_fp_vswitch_stats(set_ipv4);
	print_fp_vswitch_stats(set_ipv6);
	print_fp_vswitch_stats(set_tcp);
	print_fp_vswitch_stats(set_udp);
	print_fp_vswitch_stats(unsupported);
	return 0;
}

static int dump_fp_vswitch_stats(char *tok)
{
	return _dump_stats(tok, dump_fp_vswitch_stats_);
}

static int set_fp_vswitch_flow_max_age(char *tok)
{
	uint8_t age;
	uint8_t old_age;
	char *end;
	static fpvs_flow_list_t *ffl;
	int count;

	count = gettokens(tok);
	if (count != 1) {
		fpdebug_printf("wrong arguments: set-fp-vswitch-flow-age <age>");
		return -1;
	}
	/* Retrieve flow list. */
	ffl = shared_table;

	age = (uint8_t) strtoul(tok, &end, 0);
	old_age = ffl->flow_max_age;
	ffl->flow_max_age = age;

	fpdebug_printf("flow_max_age is %d (was %d)\n", age, old_age);

	return 0;
}

static void reset_fp_vswitch_stats_(void)
{
	memset((void *)fpvs_shared->stats, 0, sizeof(fpvs_shared->stats));
}

static CLI_COMMAND fp_vswitch_cmds[] = {
	{"dump-fp-vswitch-flows", dump_fp_vswitch_flows,
	 "Dump fp-vswitch flows: dump-fp-vswitch-flows [help|[{+|-}]{item}] [...]"},
	{"dump-fp-vswitch-masks", dump_fp_vswitch_masks,
	 "Dump fp-vswitch masks: dump-fp-vswitch-masks"},
	{"dump-fp-vswitch-ports", dump_fp_vswitch_ports,
	 "Dump fp-vswitch enabled ports: dump-fp-vswitch-ports [percore|non-zero]"},
	{"dump-fp-vswitch-stats", dump_fp_vswitch_stats,
	 "Dump fp-vswitch statistics: dump-fp-vswitch-stats [percore|non-zero]"},
	{"set-fp-vswitch-flow-max-age", set_fp_vswitch_flow_max_age,
	 "set fp-vswitch flow age (default age is 2 = 10s): set-fp-vswitch-flow-age <age>"},
	{ NULL, NULL, NULL },
};
static cli_cmds_t fp_vswitch_cli = {
	.module = "fp-vswitch",
	.c = fp_vswitch_cmds,
};

static CLI_STATS fp_vswitch_stats[] = {
	{"fp-vswitch", dump_fp_vswitch_stats_, reset_fp_vswitch_stats_ },
	{ NULL, NULL, NULL },
};
static cli_stats_t fp_vswitch_stats_cli = {
	.module = "fp-vswitch",
	.s = fp_vswitch_stats,
};

static void fpdebug_vswitch_init(void) __attribute__((constructor));
void fpdebug_vswitch_init(void)
{
	/* Do not install commands if shared mems are not present */
	if (fpvs_map_shm() < 0)
		return;

	fpdebug_add_commands(&fp_vswitch_cli);
	fpdebug_add_stats(&fp_vswitch_stats_cli);
}
