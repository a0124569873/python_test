/*
 * Copyright(c) 2013 6WIND
 * All rights reserved
 */

#ifndef __FastPath__
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include "netfpc.h"
#endif
#include "fpn.h"
#include "fp.h"
#include "netinet/fp-in6.h"
#include "fpdebug-priv.h"
#include "fpn-port.h"
#include "shmem/fpn-shmem.h"
#include "fp-autoconf-if.h"

#define IFACE_COUNT 16

int fpdebug_autoconf_ifnet(char *tok)
{
	int portid, ifnum, ret = 0;
	char name[24];
	uint8_t	fpm_cp_portmac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
#if !defined(__FastPath__)
	port_mem_t *fpn_port_shmem;
	struct netfpc_if_msg if_msg;
	static int s_nfpc = -1;
#endif
	int ifuid;
	int ifindex;

	(void)tok;
	(void)ifindex;

	/* map fpn_port */
#if !defined(__FastPath__)
	fpn_port_shmem = (port_mem_t *) fpn_shmem_mmap("fpn-port-shared", NULL, sizeof(port_mem_t));
#endif
	if (fpn_port_shmem == NULL) {
		fpdebug_printf("cannot map fpn_port size=%"PRIu64" (%"PRIu64"M)\n",
			   (uint64_t)sizeof(port_mem_t),
			   (uint64_t)sizeof(port_mem_t) >> 20);
		return -1;
	}

	/* Initialize shared memory since FPM will not do it for us */
	fp_init();
	fp_set_blade_id(1, 0);
	fp_set_cp_info(IF_PORT_COLOC, fpm_cp_portmac, 1500, 0);


	/* initialize port mac addresses */
	ifnum = 0;
	for (portid = 0; portid < FPN_MAX_PORTS; portid++) {
		ifuid = 7 + ifnum;
		if (fpn_port_shmem->port[portid].enabled == 0)
			continue;

		/* maximum number of interfaces reached */
		if (ifnum >= IFACE_COUNT)
			break;

#ifndef __FastPath__
		/* If FPVI interface exists, ifindex has been set and we can get
		 * the interface name. Otherwise select ethX_0 name.
		 */
		ifindex = fpn_port_shmem->port[portid].linux_ifindex;
		if (ifindex == 0 || if_indextoname(ifindex, name) == NULL)
			snprintf(name, sizeof(name), "eth%d_0", portid);
#else
		snprintf(name, sizeof(name), "eth%d_0", portid);
#endif

		fpdebug_printf("Adding interface %s (ifuid %d) to port %d\n",
		       name, ifuid, portid);
		ret = fp_addifnet(0, name,
				  fpn_port_shmem->port[portid].etheraddr, 1500,
				  ifuid, portid, FP_IFTYPE_ETHER);
#ifndef __FastPath__
		/* notify the FP and wait for the ack */
		if_msg.vnb_nodeid = 0;
		if_msg.ifuid = ifuid;
		if_msg.error = 0;

		if (s_nfpc >= 0) {
			if (netfpc_send(s_nfpc, &if_msg, sizeof(if_msg), 0,
					NETFPC_MSGTYPE_NEWIF) < 0) {
				fpdebug_printf("%s: fail to send add notification ifuid=%d\n",
					       __func__, ifuid);
				return -1;
			}
			if (netfpc_recv(s_nfpc, &if_msg, sizeof(if_msg), MSG_NO_TIMEOUT, NULL) < 0) {
				fpdebug_printf("%s: fail to receive notification ifuid=%d\n",
					       __func__, ifuid);
				return -1;
			}
			if (if_msg.error) {
				int err = ntohl(if_msg.error);
				fpdebug_printf("%s: cannot add in FP ifuid=%d err=%d\n",
					       __func__, ifuid, err);
				return -1;
			}
		}
#endif
		fp_setifnet_flags(ifuid, IFF_CP_UP|IFF_CP_RUNNING|
				  IFF_CP_IPV4_FWD|IFF_CP_IPV6_FWD);
		ifnum++;
	}
	return ret;
}
