/* Copyright 2013 6WIND S.A. */

#define _GNU_SOURCE /* for getopt_long */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <net/if.h>

#include "fpn.h"
#include "fpn-port.h"
#include "shmem/fpn-shmem.h"
#if defined(CONFIG_MCORE_L2_INFRA)
#include "fpn-vlanport.h"
#endif

#if defined(CONFIG_MCORE_L2_INFRA)
#define ALL_PORTS FPN_ALL_PORTS
#else
#define ALL_PORTS FPN_MAX_PORTS
#endif

#define PORTID_ALL_ENABLED -1
#define PORTID_ALL -2

port_mem_t *fpn_port_shmem;

/* supported actions */
enum action {
	NONE,
	DUMP_PORTS,
#if defined(CONFIG_MCORE_L2_INFRA)
	ADD_VLAN,
#endif
	SW_LRO,
	FORCE_TSO,
	DUMP_STATS,
};

/* user params */
struct shmem_ports_params {
	enum action action;
	int portid;
#if defined(CONFIG_MCORE_L2_INFRA)
	int vlan_id;
	int vlan_pcp;        /* Priority Code Point */
	uint8_t vlan_mac[6]; /* Interface MAC address */
#endif
	unsigned sw_lro;     /* Maximum size of coalesced packet */
	int force_tso;       /* Force TCP segmentation at MTU, boolean */
};

static void
print_mac(const uint8_t *mac)
{
	printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int
__dump_fpn_ports(int i)
{
	struct fpn_port *p = &fpn_port_shmem->port[i];

	printf("port %u: mac ", i);
	print_mac(p->etheraddr);

	if (strlen(p->drivername) != 0)
		printf(" driver %s", p->drivername);

#if defined(CONFIG_MCORE_L2_INFRA)
	printf(" vlan_enabled %d", p->vlan_enabled);
	printf(" vlan_id %d attached: %d",
			p->vlan_id, p->attached_port_number);
	/* print all VLAN ids enabled on one physical port */
	if (p->vlan_enabled && i < FPN_MAX_PORTS) {
		int j;

		for (j = 0 ; j < FPN_MAX_VLANID; j++)
			if (fpn_port_shmem->portid[i][j] != 0)
				printf("\n port %d vlan id %d", i, j);
	}
#endif
	printf(" RX_CAP 0x%x TX_CAP 0x%x",
			p->rx_offload_capa,
			p->tx_offload_capa);
	if (p->sw_lro)
		printf(" SW_LRO=%d", p->sw_lro);

	if (p->force_tso_at_mtu)
		printf(" FORCE_TSO");

	if (strlen(p->driverargs) != 0)
		printf(" args %s", p->driverargs);

	if (p->linux_ifindex) {
		char ifname[IFNAMSIZ];

		printf(" %s", if_indextoname(p->linux_ifindex, ifname));
	}

	printf("\n");
	return 0;
}

static int
dump_fpn_ports(int portid)
{
	unsigned int i;
	struct fpn_port *p;

	if (portid >= 0)
		return __dump_fpn_ports(portid);

	for (i = 0 ; i < ALL_PORTS; i++) {
		p = &fpn_port_shmem->port[i];
		if (portid == PORTID_ALL_ENABLED && p->enabled == 0)
			continue;
		__dump_fpn_ports(i);
	}
	return 0;
}

static int
__dump_fpn_stats(int i)
{
	struct fpn_port *p = &fpn_port_shmem->port[i];

	printf("port %u: ", i);

	printf( "ipackets %8"PRIu64, p->ipackets);
	printf(" opackets %8"PRIu64, p->opackets);
	printf(" ibytes   %8"PRIu64, p->ibytes);
	printf(" obytes   %8"PRIu64, p->obytes);
	printf(" ierrors  %8"PRIu64, p->ierrors);
	printf(" oerrors  %8"PRIu64, p->oerrors);

	printf("\n");
	return 0;
}

static int
dump_fpn_stats(int portid)
{
	unsigned int i;
	struct fpn_port *p;

	if (portid >= 0)
		return __dump_fpn_stats(portid);

	for (i = 0 ; i < ALL_PORTS; i++) {
		p = &fpn_port_shmem->port[i];
		if (portid == PORTID_ALL_ENABLED && p->enabled == 0)
			continue;
		__dump_fpn_stats(i);
	}
	return 0;
}

#if defined(CONFIG_MCORE_L2_INFRA)
/* convert a string to a mac address, return 0 on success. */
static int
string2mac(const char *str, uint8_t *mac)
{
	if (sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2],
			&mac[3], &mac[4], &mac[5]) != 6)
		return -1;
	return 0;
}

static int
add_vlan_port(int port, int id, int pcp, const uint8_t *mac)
{
	int i;
	const uint8_t *p_mac = mac;

	if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
		mac[3] == 0 && mac[4] == 0 && mac[5] == 0)
		p_mac = NULL;

	i = fpn_addvlanport(port, id, pcp, p_mac);
	printf("fpn_addvlanport: %d\n", i);

	return 0;
}
#endif

/* Enable/disable LRO on ports. The "sw_lro" argument is the maximum size of
 * coalesced packets, or 0 to disable LRO. */
static int
set_sw_lro(int portid, unsigned sw_lro)
{
	unsigned int i;
	struct fpn_port *p;

	if (sw_lro > 0xFFFF) {
		fprintf(stderr, "lro value should be <= 0xffff\n");
		return 1;
	}

	if (portid >= 0) {
		p = &fpn_port_shmem->port[portid];
		if ((p->rx_offload_capa & FPN_OFFLOAD_RX_SW_LRO) == 0) {
			fprintf(stderr, "port %d does not support sw LRO\n",
				portid);
			return 1;
		}
		p->sw_lro = sw_lro;
		return 0;
	}

	for (i = 0 ; i < ALL_PORTS; i++) {
		p = &fpn_port_shmem->port[i];
		if (portid == PORTID_ALL_ENABLED && p->enabled ==0)
			continue;
		if ((p->rx_offload_capa & FPN_OFFLOAD_RX_SW_LRO) == 0)
			fprintf(stderr, "port %d does not support sw LRO\n",
				portid);
		else
			p->sw_lro = sw_lro;
	}

	return 0;
}

/* Enable/disable FORCE_TSO on ports. When enabled, any TCP packet sent
 * on this port is segmented at MTU by the hardware. */
static int
set_tso(int portid, int enabled)
{
	unsigned int i;
	struct fpn_port *p;

	if (portid >= 0) {
		p = &fpn_port_shmem->port[portid];
		if ((p->rx_offload_capa & FPN_OFFLOAD_TX_TCP_TSO) == 0) {
			fprintf(stderr, "port %d does not support TSO\n",
				portid);
			return 1;
		}
		p->force_tso_at_mtu = enabled;
		return 0;
	}

	for (i = 0 ; i < ALL_PORTS; i++) {
		p = &fpn_port_shmem->port[i];
		if (portid == PORTID_ALL_ENABLED && p->enabled == 0)
			continue;
		if ((p->rx_offload_capa & FPN_OFFLOAD_TX_TCP_TSO) == 0)
			fprintf(stderr, "port %d does not support TSO\n",
				portid);
		else
			p->force_tso_at_mtu = enabled;
	}

	return 0;
}

static void
shm_ports_usage(const char *cmd, int code)
{
	fprintf(stderr, "usage: %s <action> <options>\n", cmd);

	/* list of actions: dump ports, add vlan, ... */
	fprintf(stderr, "actions:\n");
#if defined(CONFIG_MCORE_L2_INFRA)
	fprintf(stderr, "  -a, --add_vlan: Add a vlan port\n");
	fprintf(stderr, "       ex: %s -a -e <portid|all> -i <vlan_id> "
		"[-m <mac address> -p <pcp>]\n", cmd);
#endif
	fprintf(stderr, "  -d, --dump: Dump ports\n");
	fprintf(stderr, "       ex: %s -d [ -e <portid|all> ]\n", cmd);
	fprintf(stderr, "  -l <pkt_size>, --sw_lro=<pkt_size>: Set software\n");
	fprintf(stderr, "       LRO (Large Receive Offload.\n");
	fprintf(stderr, "       pkt_size is the maximum size of coalesced\n");
	fprintf(stderr, "	packets. pkt_size=0 means LRO disabled.\n");
	fprintf(stderr, "       ex: %s -l <pkt_size> [ -e <portid> ]\n", cmd);
	fprintf(stderr, "  -t <boolean>, --force_tso=<boolean>: Enable TSO\n");
	fprintf(stderr, "       (TCP Segmentation Offload) on this port.\n");
	fprintf(stderr, "       When this option is enabled, any TCP packet\n");
	fprintf(stderr, "       larger than MTU will be segmented by HW.\n");
	fprintf(stderr, "       ex: %s -t 1 [ -e <portid> ]\n", cmd);
	fprintf(stderr, "  -s, --stats: display ports Stats\n");
	fprintf(stderr, "       ex: %s -s [ -e <portid|all> ]\n", cmd);

	/* list of options */
	fprintf(stderr, "options:\n");
	fprintf(stderr, "  -e <eth_port|all|ALL>, "
		"--eth_port=<eth_port|all|ALL>\n");
	fprintf(stderr, "	select port id, 'all' means all enabled ports "
		" and 'ALL' means all ports, enabled or disabled.\n");
#if defined(CONFIG_MCORE_L2_INFRA)
	fprintf(stderr, "  -i <vlan_id>, --vlan_id=<vlan_id>\n");
	fprintf(stderr, "	select vlan id\n");
	fprintf(stderr, "  -p <vlan_pcp>, --vlan_pcp=<vlan_pcp>\n");
	fprintf(stderr, "	select vlan priority code point\n");
	fprintf(stderr, "  -m <mac_addr>, --mac=<mac_addr>\n");
	fprintf(stderr, "	select MAC address\n");
#endif

	exit(code);
}

/* parse arguments, exit() on error */
void parse_args(struct shmem_ports_params *args, const char *progname,
	int argc, char **argv)
{
	int option_index, ch;
	struct option lgopts[] = {
		{"dump", 0, 0, 'd'},
		{"eth_port", 1, 0, 'e'},
#if defined(CONFIG_MCORE_L2_INFRA)
		{"add_vlan", 0, 0, 'a'},
		{"vlan_id", 1, 0, 'i'},
		{"mac", 1, 0, 'm'},
		{"vlan_pcp", 1, 0, 'p'},
#endif
		{"sw_lro", 1, 0, 'l'},
		{"force_tso", 1, 0, 't'},
		{"stats", 0, 0, 's'},
	};

	while ((ch = getopt_long(argc, argv,
				"d"  /* dump */
				"e:" /* eth_port */
#if defined(CONFIG_MCORE_L2_INFRA)
				"a"  /* add_vlan */
				"i:" /* vlan_id */
				"m:" /* mac */
				"p:" /* vlan_pcp */
#endif
				"l:" /* sw_lro */
				"t:" /* force_tso */
				"s"  /* display stats */
				, lgopts, &option_index)) != -1) {

		switch (ch) {
		case 'd': /* dump */
			if (args->action != NONE)
				shm_ports_usage(progname, 1);
			args->action = DUMP_PORTS;
			break;
		case 'e': /* eth_port */
			if (!strcmp(optarg, "all"))
				args->portid = PORTID_ALL_ENABLED;
			else if (!strcmp(optarg, "ALL"))
				args->portid = PORTID_ALL;
			else {
				args->portid = atoi(optarg);
				if (args->portid < 0 ||
					args->portid >= ALL_PORTS) {
					fprintf(stderr, "invalid port id\n");
					shm_ports_usage(progname, 1);
				}
			}
			break;
#if defined(CONFIG_MCORE_L2_INFRA)
		case 'a': /* add_vlan */
			if (args->action != NONE)
				shm_ports_usage(progname, 1);
			args->action = ADD_VLAN;
			break;
		case 'i': /* vlan_id */
			args->vlan_id = atoi(optarg);
			break;
		case 'm': /* mac */
			if (string2mac(optarg, args->vlan_mac) < 0)
				shm_ports_usage(progname, 1);
			break;
		case 'p': /* vlan_pcp */
			args->vlan_pcp = atoi(optarg);
			break;
#endif
		case 'l': /* sw_lro */
			if (args->action != NONE)
				shm_ports_usage(progname, 1);
			args->action = SW_LRO;
			args->sw_lro = atoi(optarg);
			break;
		case 't': /* force_tso */
			if (args->action != NONE)
				shm_ports_usage(progname, 1);
			args->action = FORCE_TSO;
			args->force_tso = atoi(optarg);
			break;
		case 's': /* stats */
			if (args->action != NONE)
				shm_ports_usage(progname, 1);
			args->action = DUMP_STATS;
			break;
		default:
			fprintf(stderr, "Unknown option.\n");
			shm_ports_usage(progname, 1);
		}
	}
}

int
main(int argc, char **argv)
{
	int ret = 0;
	const char *progname;
	struct shmem_ports_params args = {
		.action = NONE,
		.portid = -1,
#if defined(CONFIG_MCORE_L2_INFRA)
		.vlan_id = -1,
		.vlan_pcp = 0,
		.vlan_mac = { 0, 0, 0, 0, 0, 0} ,
#endif
		.sw_lro = 0,
		.force_tso = 0,
	};

	progname = strrchr(argv[0], '/');
	if (!progname)
		progname = argv[0];
	else
		progname++;

	fpn_port_shmem = (port_mem_t *) fpn_port_init();
	if (fpn_port_shmem == NULL) {
		perror("fpn_shmem_mmap failed");
		exit(EXIT_FAILURE);
	}

	/* parse arguments, exit() on error */
	parse_args(&args, progname, argc, argv);

	/* execute action */
	switch (args.action) {
#if defined(CONFIG_MCORE_L2_INFRA)
	case ADD_VLAN:
		/* check that portid and vlan_id are set */
		if (args.portid < 0 || args.vlan_id < 0)
			shm_ports_usage(progname, 1);

		ret = add_vlan_port(args.portid, args.vlan_id,
			args.vlan_pcp, args.vlan_mac);
		break;
#endif
	case DUMP_PORTS:
		ret = dump_fpn_ports(args.portid);
		break;

	case SW_LRO:
		ret = set_sw_lro(args.portid, args.sw_lro);
		break;

	case FORCE_TSO:
		ret = set_tso(args.portid, args.force_tso);
		break;

	case DUMP_STATS:
		ret = dump_fpn_stats(args.portid);
		break;

	default:
		shm_ports_usage(progname, 1);
		break;
	}

	return ret;
}
