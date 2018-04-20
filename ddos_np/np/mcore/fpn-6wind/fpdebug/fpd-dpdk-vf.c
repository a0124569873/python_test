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

/*
 * Support of additional MAC addresses for Intel 82599-VF ports
 */
#ifdef __FastPath__
#include <rte_ethdev.h>

static int
add_82599vf_mac(char *tok)
{
	int numtokens;
	uint8_t vf_port;
	struct ether_addr mac_addr;
	int diag;

	numtokens = gettokens(tok);
	if (numtokens != 2) {
		fpdebug_fprintf(stderr, "wrong number of arguments\n");
		return -1;
	}
	vf_port = (uint8_t) atoi(chargv[0]);
	if (vf_port >= rte_eth_dev_count()) {
		fpdebug_fprintf(stderr, "invalid port_id\n");
		return -1;
	}
	if (string2mac(chargv[1], mac_addr.addr_bytes) == 0) {
		fpdebug_fprintf(stderr, "invalid MAC address\n");
		return -1;
	}
	diag = rte_eth_dev_mac_addr_add(vf_port, &mac_addr, 0);
	if (diag == 0)
		return 0;
	switch (diag) {
	case -ENOTSUP:
		fpdebug_fprintf(stderr, "operation not supported by device\n");
		break;
	case -ENODEV:
		fpdebug_fprintf(stderr, "port id. invalid\n");
		break;
	case -ENOSPC:
		fpdebug_fprintf(stderr, "no more MAC address can be added\n");
		break;
	case -EINVAL:
		fpdebug_fprintf(stderr, "MAC address invalid\n");
		break;
	default:
		fpdebug_fprintf(stderr, "operation failed:diag=%d\n", diag);
		break;
	}
	return -1;
}

static int
remove_82599vf_mac(char *tok)
{
	int numtokens;
	uint8_t vf_port;
	struct ether_addr mac_addr;
	int diag;

	numtokens = gettokens(tok);
	if (numtokens != 2) {
		fpdebug_fprintf(stderr, "wrong number of arguments\n");
		return -1;
	}
	vf_port = (uint8_t) atoi(chargv[0]);
	if (vf_port >= rte_eth_dev_count()) {
		fpdebug_fprintf(stderr, "invalid port_id\n");
		return -1;
	}
	if (string2mac(chargv[1], mac_addr.addr_bytes) == 0) {
		fpdebug_fprintf(stderr, "invalid MAC address\n");
		return -1;
	}
	diag = rte_eth_dev_mac_addr_remove(vf_port, &mac_addr);
	if (diag == 0)
		return 0;
	switch (diag) {
	case -ENOTSUP:
		fpdebug_fprintf(stderr, "operation not supported by device\n");
		break;
	case -ENODEV:
		fpdebug_fprintf(stderr, "port id. invalid\n");
		break;
	case -EADDRINUSE:
		fpdebug_fprintf(stderr, "can't remove permanent MAC address\n");
		break;
	default:
		fpdebug_fprintf(stderr, "operation failed:diag=%d\n", diag);
		break;
	}
	return -1;
}
#else /* __FastPath__ */
#define add_82599vf_mac fpdebug_send_to_fp
#define remove_82599vf_mac fpdebug_send_to_fp
#endif

static CLI_COMMAND vf_cmds[] = {
	{"add-82599-vf-secondary-mac", add_82599vf_mac,
	 "Add a MAC address to a 82599 VF port: "
	 "add-82599-vf-secondary-mac port_id mac_addr"},
	{"remove-82599-vf-secondary-mac", remove_82599vf_mac,
	 "Remove a MAC address from a 82599 VF port: "
	 "remove-82599-vf-secondary-mac port_id mac_addr"},
	{ NULL, NULL, NULL },
};
static cli_cmds_t vf_cli = {
	.module = "vf",
	.c = vf_cmds,
};

static void fpdebug_vf_init(void) __attribute__ ((constructor));
void fpdebug_vf_init(void)
{
	fpdebug_add_commands(&vf_cli);
}
