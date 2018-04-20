/*
 * Copyright(c) 2012 6WIND
 */
#ifndef __FPN_VLANPORT_H__
#define __FPN_VLANPORT_H__

#include "fpn-eth.h"

#if defined(CONFIG_MCORE_L2_INFRA_ETH_TYPE)
#define L2_INFRA_ETH_TYPE CONFIG_MCORE_L2_INFRA_ETH_TYPE
#else
#define L2_INFRA_ETH_TYPE FPN_ETHERTYPE_VLAN
#endif

/*
 * Add a new fpn-sdk port for an "infrastructure" VLAN
 * Parameters:
 * - portid: index of the physical port where the VLAN is added
 * - id: VLAN id for the new VLAN
 * - pcp: priority for the new VLAN
 * - mac: optional MAC address for the new port (if NULL, use the
 *   mac from the underlying port)
 * Return value:
 * < 0 error condition
 * > 0 index for the newly created port (portid)
 */
int fpn_addvlanport(uint16_t portid, uint16_t id, uint16_t pcp, const uint8_t *mac);

#endif /* __FPN_VLANPORT_H__ */
