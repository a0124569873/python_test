/*
 * Copyright(c) 2014 6WIND
 * All rights reserved
 */

#ifndef __FastPath__
#include <stdio.h>
#include <string.h>
#endif

#include "fpn.h"
#include "fp.h"
#include "fpdebug.h"
#include "fpdebug-priv.h"

#if defined(__FastPath__)
#include <rte_ethdev.h>
#include <rte_byteorder.h>
#endif

/*
 * Command to configure FDIR masks of a given port.
 */
#define FPDEBUG_FDIR_SET_MASKS_USAGE \
	"\n\tfdir-set-masks portid"  \
	"\n\t\t(only_ip_flow u8)"    \
	"\n\t\t(vlan_id u8)"         \
	"\n\t\t(vlan_prio u8)"       \
	"\n\t\t(flexbytes u8)"       \
	"\n\t\t(set_ipv6_mask u8)"   \
	"\n\t\t(comp_ipv6_dst u8)"   \
	"\n\t\t(dst_ipv6_mask u16)"  \
	"\n\t\t(src_ipv6_mask u16)"  \
	"\n\t\t(src_port_mask u16)"  \
	"\n\t\t(dst_port_mask u16)"  \
	"\n\t\t(dst_ipv4_mask u32)"  \
	"\n\t\t(src_ipv4_mask u32)"  \

/*
 * Command to flush FDIR masks of a given port.
 */
#define FPDEBUG_FDIR_FLUSH_FILTERS_USAGE \
	"\n\tfdir-flush-filters portid"

/*
 * Command to add a FDIR filter on a given port.
 */
#define FPDEBUG_FDIR_ADD_FILTER_USAGE        \
	"\n\tfdir-add-filter portid"         \
	"\n\t\t(queue u8)"                   \
	"\n\t\t(drop u8)"                    \
	"\n\t\t(flex_bytes u16)"             \
	"\n\t\t(vlan_id u16)"                \
	"\n\t\t(port_src u16)"               \
	"\n\t\t(port_dst u16)"               \
	"\n\t\t(softid u16)"                 \
	"\n\t\t(ip_src [@ipv4|@ipv6])"       \
	"\n\t\t(ip_dst [@ipv4|@ipv6])"       \
	"\n\t\t(l4type [none|udp|tcp|sctp])" \
	"\n\t\t(iptype [ipv4|ipv6])"         \

/*
 * Command to remove a FDIR filter on a given port.
 */
#define FPDEBUG_FDIR_RM_FILTER_USAGE         \
	"\n\tfdir-rm-filter portid"          \
	"\n\t\t(flex_bytes value)"           \
	"\n\t\t(vlan_id value)"              \
	"\n\t\t(port_src value)"             \
	"\n\t\t(port_dst value)"             \
	"\n\t\t(softid value)"               \
	"\n\t\t(ip_src value)"               \
	"\n\t\t(ip_dst value)"               \
	"\n\t\t(l4type [none|udp|tcp|sctp])" \
	"\n\t\t(iptype [ipv4|ipv6])"         \

#if defined(__FastPath__)
//#define FDIR_DEBUG

#if BUILT_DPDK_VERSION > DPDK_VERSION(1, 7, 1)
#if 0
static struct rte_eth_fdir_masks rte_fdir_masks[FPN_MAX_PORTS] =
{
    {
	.vlan_tci_mask = 0,
	.src_port_mask = 0,
	.dst_port_mask = 0,
	.mac_addr_byte_mask = 0,
	.tunnel_id_mask = 0,
	.tunnel_type_mask = 0,
	.ipv4_mask.src_ip = 0;
	.ipv4_mask.dst_ip = 0;
	.ipv4_mask.tos = 0;
	.ipv4_mask.ttl = 0;
	.ipv4_mask.proto = 0;
	.ipv6_mask.src_ip[0] = 0;
	.ipv6_mask.dst_ip[0] = 0;
	.ipv6_mask.tc = 0;
	.ipv6_mask.proto = 0;
	.ipv6_mask.hop_limits = 0;
    }
};
#endif
struct rte_fdir_masks {
	/** When set to 1, packet l4type is \b NOT relevant in filters, and
	   source and destination port masks must be set to zero. */
	uint8_t only_ip_flow;
	/** If set to 1, vlan_id is relevant in filters. */
	uint8_t vlan_id;
	/** If set to 1, vlan_prio is relevant in filters. */
	uint8_t vlan_prio;
	/** If set to 1, flexbytes is relevant in filters. */
	uint8_t flexbytes;
	/** If set to 1, set the IPv6 masks. Otherwise set the IPv4 masks. */
	uint8_t set_ipv6_mask;
	/** When set to 1, comparison of destination IPv6 address with IP6AT
	    registers is meaningful. */
	uint8_t comp_ipv6_dst;
	/** Mask of Destination IPv4 Address. All bits set to 1 define the
	    relevant bits to use in the destination address of an IPv4 packet
	    when matching it against FDIR filters. */
	uint32_t dst_ipv4_mask;
	/** Mask of Source IPv4 Address. All bits set to 1 define
	    the relevant bits to use in the source address of an IPv4 packet
	    when matching it against FDIR filters. */
	uint32_t src_ipv4_mask;
	/** Mask of Source IPv6 Address. All bits set to 1 define the
	    relevant BYTES to use in the source address of an IPv6 packet
	    when matching it against FDIR filters. */
	uint16_t dst_ipv6_mask;
	/** Mask of Destination IPv6 Address. All bits set to 1 define the
	    relevant BYTES to use in the destination address of an IPv6 packet
	    when matching it against FDIR filters. */
	uint16_t src_ipv6_mask;
	/** Mask of Source Port. All bits set to 1 define the relevant
	    bits to use in the source port of an IP packets when matching it
	    against FDIR filters. */
	uint16_t src_port_mask;
	/** Mask of Destination Port. All bits set to 1 define the relevant
	    bits to use in the destination port of an IP packet when matching it
	    against FDIR filters. */
	uint16_t dst_port_mask;
};

/**
 *  Possible l4type of FDIR filters.
 */
enum rte_l4type {
	RTE_FDIR_L4TYPE_NONE = 0,       /**< None. */
	RTE_FDIR_L4TYPE_UDP,            /**< UDP. */
	RTE_FDIR_L4TYPE_TCP,            /**< TCP. */
	RTE_FDIR_L4TYPE_SCTP,           /**< SCTP. */
};

/**
 *  Select IPv4 or IPv6 FDIR filters.
 */
enum rte_iptype {
	RTE_FDIR_IPTYPE_IPV4 = 0,     /**< IPv4. */
	RTE_FDIR_IPTYPE_IPV6 ,        /**< IPv6. */
};

struct rte_fdir_filter {
	uint16_t flex_bytes; /**< Flex bytes value to match. */
	uint16_t vlan_id; /**< VLAN ID value to match, 0 otherwise. */
	uint16_t port_src; /**< Source port to match, 0 otherwise. */
	uint16_t port_dst; /**< Destination port to match, 0 otherwise. */
	union {
		uint32_t ipv4_addr; /**< IPv4 source address to match. */
		uint32_t ipv6_addr[4]; /**< IPv6 source address to match. */
	} ip_src; /**< IPv4/IPv6 source address to match (union of above). */
	union {
		uint32_t ipv4_addr; /**< IPv4 destination address to match. */
		uint32_t ipv6_addr[4]; /**< IPv6 destination address to match */
	} ip_dst; /**< IPv4/IPv6 destination address to match (union of above). */
	enum rte_l4type l4type; /**< l4type to match: NONE/UDP/TCP/SCTP. */
	enum rte_iptype iptype; /**< IP packet type to match: IPv4 or IPv6. */
};

int rte_eth_dev_fdir_set_masks(uint8_t port_id,
			       struct rte_fdir_masks *fdir_mask);
int rte_eth_dev_fdir_update_perfect_filter(uint8_t port_id,
					   struct rte_fdir_filter *fdir_filter,
					   uint16_t soft_id, uint8_t rx_queue,
					   uint8_t drop);
int rte_eth_dev_fdir_remove_perfect_filter(uint8_t port_id,
					   struct rte_fdir_filter *fdir_filter,
					   uint16_t soft_id);

int rte_eth_dev_fdir_set_masks(uint8_t port_id,
			       struct rte_fdir_masks *fdir_mask)
{
    return 0;
}

int rte_eth_dev_fdir_update_perfect_filter(uint8_t port_id,
					   struct rte_fdir_filter *fdir_filter,
					   uint16_t soft_id, uint8_t rx_queue,
					   uint8_t drop)
{
    return 0;
}

int rte_eth_dev_fdir_remove_perfect_filter(uint8_t port_id,
					   struct rte_fdir_filter *fdir_filter,
					   uint16_t soft_id)

{
    return 0;
}

#endif

/* store current fdir masks (useful when we want to flush everything) */
static struct rte_fdir_masks rte_fdir_masks[FPN_MAX_PORTS] =
{
	{
		.only_ip_flow = 0,
		.vlan_id = 0,
		.vlan_prio = 0,
		.flexbytes = 0,
		.set_ipv6_mask = 0,
		.comp_ipv6_dst = 0,
		.dst_ipv4_mask = 0,
		.src_ipv4_mask = 0,
		.dst_ipv6_mask = 0,
		.src_ipv6_mask = 0,
		.src_port_mask = 0,
		.dst_port_mask = 0,
	}
};

struct fpn_rte_fdir_params {
	const char *name;
	int offset;
};

static struct fpn_rte_fdir_params fpn_rte_fdir_masks_params_u8[] = {
	{ "only_ip_flow", fpn_offsetof(struct rte_fdir_masks, only_ip_flow) },
	{ "vlan_id", fpn_offsetof(struct rte_fdir_masks, vlan_id) },
	{ "vlan_prio", fpn_offsetof(struct rte_fdir_masks, vlan_prio) },
	{ "flexbytes", fpn_offsetof(struct rte_fdir_masks, flexbytes) },
	{ "set_ipv6_mask", fpn_offsetof(struct rte_fdir_masks, set_ipv6_mask) },
	{ "comp_ipv6_dst", fpn_offsetof(struct rte_fdir_masks, comp_ipv6_dst) },
};

static struct fpn_rte_fdir_params fpn_rte_fdir_masks_params_u16[] = {
	{ "dst_ipv6_mask", fpn_offsetof(struct rte_fdir_masks, dst_ipv6_mask) },
	{ "src_ipv6_mask", fpn_offsetof(struct rte_fdir_masks, src_ipv6_mask) },
	{ "src_port_mask", fpn_offsetof(struct rte_fdir_masks, src_port_mask) },
	{ "dst_port_mask", fpn_offsetof(struct rte_fdir_masks, dst_port_mask) },
};

static struct fpn_rte_fdir_params fpn_rte_fdir_masks_params_u32[] = {
	{ "dst_ipv4_mask", fpn_offsetof(struct rte_fdir_masks, dst_ipv4_mask) },
	{ "src_ipv4_mask", fpn_offsetof(struct rte_fdir_masks, src_ipv4_mask) },
};

/* for internal use */
struct fpn_rte_fdir_filter {
	struct rte_fdir_filter filter;
	uint16_t softid;
	uint8_t queue;
	uint8_t drop;
};

static struct fpn_rte_fdir_params fpn_rte_fdir_filter_params_u8[] = {
	{ "queue", fpn_offsetof(struct fpn_rte_fdir_filter, queue) },
	{ "drop", fpn_offsetof(struct fpn_rte_fdir_filter, drop) },
};

static struct fpn_rte_fdir_params fpn_rte_fdir_filter_params_u16[] = {
	{ "flex_bytes", fpn_offsetof(struct fpn_rte_fdir_filter, filter)
			+ fpn_offsetof(struct rte_fdir_filter, flex_bytes) },
	{ "vlan_id", fpn_offsetof(struct fpn_rte_fdir_filter, filter)
			+ fpn_offsetof(struct rte_fdir_filter, vlan_id) },
	{ "port_src", fpn_offsetof(struct fpn_rte_fdir_filter, filter)
			+ fpn_offsetof(struct rte_fdir_filter, port_src) },
	{ "port_dst", fpn_offsetof(struct fpn_rte_fdir_filter, filter)
			+ fpn_offsetof(struct rte_fdir_filter, port_dst) },
	{ "softid", fpn_offsetof(struct fpn_rte_fdir_filter, softid) },
};

static void
fpdebug_fdir_print_error(int portid, int diag)
{
	switch (diag) {
	case -ENODEV:
		fpdebug_fprintf(stderr, "invalid port index %d\n", portid);
		break;
	case -ENOTSUP:
		fpdebug_fprintf(stderr, "operation not supported by hardware\n");
		break;
	case -ENOSYS:
		fpdebug_fprintf(stderr, "flow director not configured properly "
				"for port index %d\n", portid);
		break;
	case -EINVAL:
		fpdebug_fprintf(stderr, "invalid parameters\n");
		break;
	default:
		fpdebug_fprintf(stderr, "operation failed. diag=%d\n", -diag);
		break;
	}
}

static int
fpdebug_fill_fdir_masks(int argc, char *argv[], struct rte_fdir_masks *masks)
{
	int i;

	/* we want pairs of arguments */
	if (argc%2)
		return -1;

	for (i = 0; i < argc; i+=2) {
		unsigned int j;
		struct fpn_rte_fdir_params *param;

		for (j=0; j<FPN_ARRAY_SIZE(fpn_rte_fdir_masks_params_u8); j++) {
			char *end;
			unsigned long int value;
			uint8_t *u8;

			param = &fpn_rte_fdir_masks_params_u8[j];
			if (strcmp(argv[i], param->name))
				continue;

			value = strtoul(argv[i+1], &end, 0);
			if (end[0] != '\0' || value > ((1<<8)-1))
				return 0;
			u8 = (uint8_t *)((char *)masks + param->offset);
			*u8 = value;
			break;
		}
		/* found one u8 */
		if (j != FPN_ARRAY_SIZE(fpn_rte_fdir_masks_params_u8))
			continue;

		for (j=0; j<FPN_ARRAY_SIZE(fpn_rte_fdir_masks_params_u16); j++) {
			char *end;
			unsigned long int value;
			uint16_t *u16;

			param = &fpn_rte_fdir_masks_params_u16[j];
			if (strcmp(argv[i], param->name))
				continue;

			value = strtoul(argv[i+1], &end, 0);
			if (end[0] != '\0' || value > ((1<<16)-1))
				return -1;
			u16 = (uint16_t *)((char *)masks + param->offset);
			*u16 = value;
			break;
		}
		/* found one u16 */
		if (j != FPN_ARRAY_SIZE(fpn_rte_fdir_masks_params_u16))
			continue;

		for (j=0; j<FPN_ARRAY_SIZE(fpn_rte_fdir_masks_params_u32); j++) {
			char *end;
			unsigned long int value;
			uint32_t *u32;

			param = &fpn_rte_fdir_masks_params_u32[j];
			if (strcmp(argv[i], param->name))
				continue;

			value = strtoul(argv[i+1], &end, 0);
			if (end[0] != '\0')
				return -1;
			u32 = (uint32_t *)((char *)masks + param->offset);
			*u32 = value;
			break;
		}
		/* found one u32 */
		if (j != FPN_ARRAY_SIZE(fpn_rte_fdir_masks_params_u32))
			continue;

		/* found nothing */
		return -1;
	}

	return 0;
}

#ifdef FDIR_DEBUG
static void
fpdebug_fdir_dump_masks(struct rte_fdir_masks *masks)
{
	fpdebug_fprintf(stdout, "masks->only_ip_flow=%u\n", masks->only_ip_flow);
	fpdebug_fprintf(stdout, "masks->vlan_id=%u\n", masks->vlan_id);
	fpdebug_fprintf(stdout, "masks->vlan_prio=%u\n", masks->vlan_prio);
	fpdebug_fprintf(stdout, "masks->flexbytes=%u\n", masks->flexbytes);
	fpdebug_fprintf(stdout, "masks->set_ipv6_mask=%u\n", masks->set_ipv6_mask);
	fpdebug_fprintf(stdout, "masks->comp_ipv6_dst=%u\n", masks->comp_ipv6_dst);
	fpdebug_fprintf(stdout, "masks->dst_ipv4_mask=%u\n", masks->dst_ipv4_mask);
	fpdebug_fprintf(stdout, "masks->src_ipv4_mask=%u\n", masks->src_ipv4_mask);
	fpdebug_fprintf(stdout, "masks->dst_ipv6_mask=%u\n", masks->dst_ipv6_mask);
	fpdebug_fprintf(stdout, "masks->src_ipv6_mask=%u\n", masks->src_ipv6_mask);
	fpdebug_fprintf(stdout, "masks->src_port_mask=%u\n", masks->src_port_mask);
	fpdebug_fprintf(stdout, "masks->dst_port_mask=%u\n", masks->dst_port_mask);
}
#endif

static inline void
fpdebug_fdir_masks_usage(const char *reason, int set)
{
	const char *name;
	const char *usage;

	if (set) {
		name = "fdir-set-masks";
		usage = FPDEBUG_FDIR_SET_MASKS_USAGE;
	} else {
		name = "fdir-flush-filters";
		usage = FPDEBUG_FDIR_FLUSH_FILTERS_USAGE;
	}
	fpdebug_fprintf(stderr, "%s: %s%s\n", name, reason, usage);
}

static inline int
fpdebug_fdir_masks(int portid, struct rte_fdir_masks *masks)
{
	int diag;

	diag = rte_eth_dev_fdir_set_masks(portid, masks);
	if (diag < 0) {
		fpdebug_fdir_print_error(portid, diag);
		return -1;
	}

	return 0;
}

static int
fpdebug_fdir_set_masks(char *tok)
{
	int nb_args;
	long int portid;
	char *end;
	struct rte_fdir_masks masks;
	memset(&masks, 0, sizeof(masks));

	nb_args = gettokens(tok);
	if (nb_args < 1) {
		fpdebug_fdir_masks_usage("wrong nb. of arguments", 1);
		return -1;
	}

	portid = strtol(chargv[0], &end, 0);
	if (end[0] != '\0' || portid < 0 || portid >= FPN_MAX_PORTS) {
		fpdebug_fdir_masks_usage("wrong port id", 1);
		return -1;
	}

	if (fpdebug_fill_fdir_masks(nb_args - 1, &chargv[1], &masks) < 0) {
		fpdebug_fdir_masks_usage("invalid masks parameters", 1);
		return -1;
	}

#ifdef FDIR_DEBUG
	fpdebug_fdir_dump_masks(&masks);
#endif

	if (fpdebug_fdir_masks(portid, &masks) < 0)
		return -1;

	/* store it for later use */
	rte_fdir_masks[portid] = masks;
	return 0;
}

static int
fpdebug_fdir_flush_filters(char *tok)
{
	int nb_args;
	long int portid;
	char *end;

	nb_args = gettokens(tok);
	if (nb_args != 1) {
		fpdebug_fdir_masks_usage("wrong nb. of arguments", 0);
		return -1;
	}

	portid = strtol(chargv[0], &end, 0);
	if (end[0] != '\0' || portid < 0 || portid >= FPN_MAX_PORTS) {
		fpdebug_fdir_masks_usage("wrong port id", 0);
		return -1;
	}

	if (fpdebug_fdir_masks(portid, &rte_fdir_masks[portid]) < 0)
		return -1;

	return 0;
}

static int
fpdebug_fill_fdir_filter(int argc, char *argv[],
			 struct fpn_rte_fdir_filter *f)
{
	int i;
	uint16_t tmp;

	/* we want pairs of arguments */
	if (argc%2)
		return -1;

	for (i = 0; i < argc; i+=2) {
		unsigned int j;
		struct fpn_rte_fdir_params *param;

		for (j=0; j<FPN_ARRAY_SIZE(fpn_rte_fdir_filter_params_u8); j++) {
			char *end;
			unsigned long int value;
			uint8_t *u8;

			param = &fpn_rte_fdir_filter_params_u8[j];
			if (strcmp(argv[i], param->name))
				continue;

			value = strtoul(argv[i+1], &end, 0);
			if (end[0] != '\0' || value > ((1<<8)-1))
				return -1;
			u8 = (uint8_t *)((char *)f + param->offset);
			*u8 = value;
			break;
		}

		/* found one u8 */
		if (j != FPN_ARRAY_SIZE(fpn_rte_fdir_filter_params_u8))
			continue;

		for (j=0; j<FPN_ARRAY_SIZE(fpn_rte_fdir_filter_params_u16); j++) {
			char *end;
			unsigned long int value;
			uint16_t *u16;

			param = &fpn_rte_fdir_filter_params_u16[j];
			if (strcmp(argv[i], param->name))
				continue;

			value = strtoul(argv[i+1], &end, 0);
			if (end[0] != '\0' || value > ((1<<16)-1))
				return -1;
			u16 = (uint16_t *)((char *)f + param->offset);
			*u16 = value;
			break;
		}

		/* found one u16 */
		if (j != FPN_ARRAY_SIZE(fpn_rte_fdir_filter_params_u16))
			continue;

		if (!strcmp(argv[i], "ip_src")) {
			struct fp_in_addr addr;
			struct fp_in6_addr addr6;

			if (fpdebug_inet_pton(AF_INET, argv[i+1], &addr) == 1) {
				f->filter.ip_src.ipv4_addr = addr.s_addr;
				continue;
			} else if (fpdebug_inet_pton(AF_INET6, argv[i+1],
						      &addr6) == 1) {
				f->filter.ip_src.ipv6_addr[0] = addr6.fp_s6_addr32[0];
				f->filter.ip_src.ipv6_addr[1] = addr6.fp_s6_addr32[1];
				f->filter.ip_src.ipv6_addr[2] = addr6.fp_s6_addr32[2];
				f->filter.ip_src.ipv6_addr[3] = addr6.fp_s6_addr32[3];
				continue;
			}
		}

		if (!strcmp(argv[i], "ip_dst")) {
			struct fp_in_addr addr;
			struct fp_in6_addr addr6;

			if (fpdebug_inet_pton(AF_INET, argv[i+1], &addr) == 1) {
				f->filter.ip_dst.ipv4_addr = addr.s_addr;
				continue;
			} else if (fpdebug_inet_pton(AF_INET6, argv[i+1],
						      &addr6) == 1) {
				f->filter.ip_dst.ipv6_addr[0] = addr6.fp_s6_addr32[0];
				f->filter.ip_dst.ipv6_addr[1] = addr6.fp_s6_addr32[1];
				f->filter.ip_dst.ipv6_addr[2] = addr6.fp_s6_addr32[2];
				f->filter.ip_dst.ipv6_addr[3] = addr6.fp_s6_addr32[3];
				continue;
			}

			/* error */
			return -1;
		}

		if (!strcmp(argv[i], "l4type")) {
			if (!strcmp(argv[i+1], "none")) {
				f->filter.l4type = RTE_FDIR_L4TYPE_NONE;
				continue;
			} else if (!strcmp(argv[i+1], "udp")) {
				f->filter.l4type = RTE_FDIR_L4TYPE_UDP;
				continue;
			} else if (!strcmp(argv[i+1], "tcp")) {
				f->filter.l4type = RTE_FDIR_L4TYPE_TCP;
				continue;
			} else if (!strcmp(argv[i+1], "sctp")) {
				f->filter.l4type = RTE_FDIR_L4TYPE_SCTP;
				continue;
			}

			/* error */
			return -1;
		}

		if (!strcmp(argv[i], "iptype")) {
			if (!strcmp(argv[i+1], "ipv4")) {
				f->filter.iptype = RTE_FDIR_IPTYPE_IPV4;
				continue;
			} else if (!strcmp(argv[i+1], "ipv6")) {
				f->filter.iptype = RTE_FDIR_IPTYPE_IPV6;
				continue;
			}

			/* error */
			return -1;
		}

		/* found nothing */
		return -1;
	}

	tmp = rte_cpu_to_be_16(f->filter.port_dst);
	f->filter.port_dst = tmp;
	tmp = rte_cpu_to_be_16(f->filter.port_src);
	f->filter.port_src = tmp;
	tmp = rte_cpu_to_be_16(f->filter.vlan_id);
	f->filter.vlan_id = tmp;
	tmp = rte_cpu_to_be_16(f->filter.flex_bytes);
	f->filter.flex_bytes = tmp;

	return 0;
}

#ifdef FDIR_DEBUG
static void
fpdebug_fdir_dump_filter(struct fpn_rte_fdir_filter *f)
{
	fpdebug_fprintf(stdout, "f->queue=%u\n", f->queue);
	fpdebug_fprintf(stdout, "f->drop=%u\n", f->drop);
	fpdebug_fprintf(stdout, "f->filter.flex_bytes=%u\n",
			rte_cpu_to_be_16(f->filter.flex_bytes));
	fpdebug_fprintf(stdout, "f->filter.vlan_id=%u\n",
			rte_cpu_to_be_16(f->filter.vlan_id));
	fpdebug_fprintf(stdout, "f->filter.port_src=%u\n",
			rte_cpu_to_be_16(f->filter.port_src));
	fpdebug_fprintf(stdout, "f->filter.port_dst=%u\n",
			rte_cpu_to_be_16(f->filter.port_dst));
	fpdebug_fprintf(stdout, "f->softid=%u\n", f->softid);
	fpdebug_fprintf(stdout, "f->filter.ip_src=0x%x\n",
			f->filter.ip_src.ipv4_addr);
	fpdebug_fprintf(stdout, "f->filter.ip_dst=0x%x\n",
			f->filter.ip_dst.ipv4_addr);
	fpdebug_fprintf(stdout, "f->filter.l4type=%u\n",
			f->filter.l4type);
	fpdebug_fprintf(stdout, "f->filter.iptype=%u\n",
			f->filter.iptype);
}
#endif

static inline void
fpdebug_fdir_filter_usage(const char *reason, int add)
{
	const char *name;
	const char *usage;

	if (add) {
		name = "fdir-add-filter";
		usage = FPDEBUG_FDIR_ADD_FILTER_USAGE;
	} else {
		name = "fdir-rm-filter";
		usage = FPDEBUG_FDIR_RM_FILTER_USAGE;
	}

	fpdebug_fprintf(stderr, "%s: %s%s\n", name, reason, usage);
}

static int
fpdebug_fdir_filter(char *tok, int add)
{
	int diag;
	int nb_args;
	long int portid;
	char *end;
	struct fpn_rte_fdir_filter f;
	memset(&f, 0, sizeof(f));

	nb_args = gettokens(tok);
	if (nb_args < 1) {
		fpdebug_fdir_filter_usage("wrong nb. of arguments", add);
		return -1;
	}

	portid = strtol(chargv[0], &end, 0);
	if (end[0] != '\0' || portid < 0 || portid >= FPN_MAX_PORTS) {
		fpdebug_fdir_filter_usage("wrong port id", add);
		return -1;
	}

	if (fpdebug_fill_fdir_filter(nb_args - 1, &chargv[1],
					     &f) < 0) {
		fpdebug_fdir_filter_usage("invalid filter", add);
		return -1;
	}

#ifdef FDIR_DEBUG
	fpdebug_fdir_dump_filter(&f);
#endif

	// FIXME: hardcoded perfect
	/* according to rte_ethdev.h, if filter does not exist, create it,
	 * if filter exist, update it, so update == replace */
	if (add)
		diag = rte_eth_dev_fdir_update_perfect_filter(portid,
							      &f.filter,
							      f.softid,
							      f.queue,
							      f.drop);
	else
		diag = rte_eth_dev_fdir_remove_perfect_filter(portid,
							      &f.filter,
							      f.softid);

	if (diag < 0) {
		fpdebug_fdir_print_error(portid, diag);
		return -1;
	}
	return 0;
}

static int
fpdebug_fdir_add_filter(char *tok)
{
	return fpdebug_fdir_filter(tok, 1);
}

static int
fpdebug_fdir_rm_filter(char *tok)
{
	return fpdebug_fdir_filter(tok, 0);
}

static int
fpdebug_fdir_get_stats(char *tok)
{
	int i;
	int nb_args;
	long int portid;
	char *end;
	struct rte_eth_stats *stats;

	nb_args = gettokens(tok);
	if (nb_args != 1)
		return -1;

	portid = strtol(chargv[0], &end, 0);
	if (end[0] != '\0' || portid < 0 || portid >= FPN_MAX_PORTS)
		return -1;

	stats = &fpn_rte_ports[portid].stats;
	
#if BUILT_DPDK_VERSION > DPDK_VERSION(1, 7, 1)
	fpdebug_fprintf(stdout, "ipackets=%ld ierrors=%ld oerrors=%ld ",
		stats->ipackets, stats->ierrors, stats->oerrors);
#else
	fpdebug_fprintf(stdout, "ipackets=%ld fdirmatch=%ld fdirmiss=%ld ",
		stats->ipackets, stats->fdirmatch, stats->fdirmiss);
#endif

	for (i = 0; i < rte_eth_devices[portid].data->nb_rx_queues; i ++) {
		fpdebug_fprintf(stdout, "rxq%d=%ld ", i, stats->q_ipackets[i]);
	}
	fpdebug_fprintf(stdout, "\n");

	return 0;
}
#else /* defined(__FastPath__) */

#define fpdebug_fdir_set_masks fpdebug_send_to_fp
#define fpdebug_fdir_flush_filters fpdebug_send_to_fp
#define fpdebug_fdir_add_filter fpdebug_send_to_fp
#define fpdebug_fdir_rm_filter fpdebug_send_to_fp
#define fpdebug_fdir_get_stats fpdebug_send_to_fp

#endif /* !defined(__FastPath__) */

static CLI_COMMAND fdir_cmds[] = {
	{ "fdir-set-masks", fpdebug_fdir_set_masks,
	  "Configure flow director masks to be used by filters (flushes all "
	  "existing filters)" FPDEBUG_FDIR_SET_MASKS_USAGE },
	{ "fdir-flush-filters", fpdebug_fdir_flush_filters,
	  "Flush all filters (reapply previous fdir-set-masks)"
	  FPDEBUG_FDIR_FLUSH_FILTERS_USAGE },
	{ "fdir-add-filter", fpdebug_fdir_add_filter,
	  "Add a flow director filter"
	  FPDEBUG_FDIR_ADD_FILTER_USAGE },
	{ "fdir-rm-filter", fpdebug_fdir_rm_filter,
	  "Remove a flow director filter"
	  FPDEBUG_FDIR_RM_FILTER_USAGE },
	{ "fdir-get-stats", fpdebug_fdir_get_stats,
	  "Get fdir stats" },
	{ NULL, NULL, NULL },
};
static cli_cmds_t fdir_cli = {
	.module = "fdir",
	.c = fdir_cmds,
};

static void fpdebug_fdir_init(void) __attribute__ ((constructor));
void fpdebug_fdir_init(void)
{
	fpdebug_add_commands(&fdir_cli);
}
