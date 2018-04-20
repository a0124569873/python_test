/*
 * Copyright(c) 2012 6WIND
 */

#include <string.h>
#include <stdio.h>

#include "fpn.h"
#include "fpn-port.h"
#include "fpn-vlanport.h"
#include "fpn-malloc.h"
#include "fpn-eth.h"

#ifndef __FastPath__
extern port_mem_t *fpn_port_shmem;
#endif

int fpn_addvlanport(uint16_t portid, uint16_t id, uint16_t pcp, const uint8_t *mac)
{
	int vlan_portid;

	/* only physical port can have VLANs */
	if (portid >= FPN_MAX_PORTS)
		return -1;

	/* check the VLAN id is valid */
	if (id >= FPN_MAX_VLANID)
		return -1;

	if (fpn_port_shmem->port[portid].vlan_enabled) {
		/* check duplicate port/vlan id */
		if (fpn_port_shmem->portid[portid][id] != 0)
			/* Note: add check on pcp if needed */
			return -1;
	}

	/* find an empty slot => new portid */
	for (vlan_portid = FPN_MAX_PORTS ; vlan_portid < FPN_ALL_PORTS ; vlan_portid ++) {
		if ( fpn_port_shmem->port[vlan_portid].vlan_id == 0 &&
			/* do not use reserved portid */
			vlan_portid != FPN_RESERVED_PORTID_FPN0 &&
			vlan_portid != FPN_RESERVED_PORTID_VIRT )
			break;
	}

	/*
	 * if no empty slot was found, the previous "break" condition was not taken
	 * and vlan_portid takes the array size as value.
	 */
	if (vlan_portid == FPN_ALL_PORTS)
		return -1;

	/*
	 * per-port array : portid of the vlan attached to a physical port
	 */
	fpn_port_shmem->portid[portid][id] = vlan_portid;

	snprintf(fpn_port_shmem->port[vlan_portid].portname,
			 sizeof(fpn_port_shmem->port[vlan_portid].portname),
		 "port_%d_%d", portid, id);
	if (mac != NULL)
		memcpy(&fpn_port_shmem->port[vlan_portid].etheraddr, mac, 6);
	else
		memcpy(&fpn_port_shmem->port[vlan_portid].etheraddr,
	           &fpn_port_shmem->port[portid].etheraddr, 6);
	fpn_port_shmem->port[vlan_portid].portid               = vlan_portid;
	fpn_port_shmem->port[vlan_portid].enabled              = 1;
	fpn_port_shmem->port[vlan_portid].initialized          = 1;
	fpn_port_shmem->port[vlan_portid].dpvi_managed         = 1;
	/* for physical ports */
	fpn_port_shmem->port[vlan_portid].vlan_enabled         = 0;
	/* for VLAN ports */
	fpn_port_shmem->port[vlan_portid].vlan_id              = id;
	fpn_port_shmem->port[vlan_portid].pcp                  = pcp;
	fpn_port_shmem->port[vlan_portid].attached_port_number = portid;

	/* note that the real port has one attached VLAN */
	fpn_port_shmem->port[portid].vlan_enabled = 1;

	return vlan_portid;
}
