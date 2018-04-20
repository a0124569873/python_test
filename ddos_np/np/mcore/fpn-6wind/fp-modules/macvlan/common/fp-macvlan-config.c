/*
 * Copyright 2014 6WIND S.A.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "fp.h"
#include "shmem/fpn-shmem.h"
#include "netfpc.h"
#include "netfpc_var.h"

#include "fp-macvlan-var.h"
#include "fp-macvlan-lookup.h"

static uint32_t fp_macvlan_iface_assign(uint32_t link_idx, uint32_t ifuid, 
					uint32_t mode)
{
	fp_macvlan_linkiface_t *vlinkiface;
	uint32_t idx;

	vlinkiface = fp_macvlan_linkidx2linkiface(link_idx);
	/* Only one macvlan is possible with passthru mode */
	if (mode == FP_MACVLAN_MODE_PASSTHRU) {
		for (idx=0; idx<FP_MACVLAN_IFACE_MAX; idx++)
			if (vlinkiface->macvlan_iface[idx].ifuid != 0)	
				return FP_MACVLAN_IFACE_MAX;
	} else {
		if ((vlinkiface->macvlan_iface[0].ifuid != 0) &&
		    (vlinkiface->macvlan_iface[0].mode == FP_MACVLAN_MODE_PASSTHRU))
			return FP_MACVLAN_IFACE_MAX;
	}

	/* Search an empty entry */
	for (idx=0; idx<FP_MACVLAN_IFACE_MAX; idx++)
		if (vlinkiface->macvlan_iface[idx].ifuid == 0) {	
			vlinkiface->macvlan_iface[idx].ifuid = ifuid;
			vlinkiface->macvlan_iface[idx].mode = mode;
			return idx;
		}
	
	return FP_MACVLAN_IFACE_MAX;
}

/* Get link_idx for a link ifuid. */
static uint32_t fp_macvlan_get_linkidx_by_link_ifuid(uint32_t link_ifuid)
{
	fp_macvlan_linkiface_t *vlinkiface;
	uint32_t link_idx;

	for (link_idx=1; link_idx<FP_MACVLAN_LINKIFACE_MAX; link_idx++) {
		vlinkiface = fp_macvlan_linkidx2linkiface(link_idx);
		if (vlinkiface->link_ifuid == link_ifuid)	
			return link_idx;
	}
	
	return 0;
}

/* Reserved a physical interface. */
static uint32_t fp_macvlan_link_create(uint32_t link_ifuid)
{
	fp_macvlan_linkiface_t *vlinkiface;
	uint32_t link_idx = 1;

	for (link_idx=1; link_idx<FP_MACVLAN_LINKIFACE_MAX; link_idx++) {
		vlinkiface = fp_macvlan_linkidx2linkiface(link_idx);
		if (vlinkiface->link_ifuid == 0) {	
			/* A free physical entry is found */
			vlinkiface->link_ifuid = link_ifuid;
			return link_idx;
		}
	}
	
	return 0;
}

/* Released a link interface. */
static void fp_macvlan_link_delete(uint32_t link_idx)
{
	fp_macvlan_linkiface_t *vlinkiface;

	vlinkiface = fp_macvlan_linkidx2linkiface(link_idx);
	vlinkiface->link_ifuid = 0;
}

/* Count the number of active macvlan associated to a link interface.
 * If there are no registered macvlan interface the link interface
 * is released
 */
static uint32_t fp_macvlan_get_interface_number_per_link (uint32_t link_idx)
{
	fp_macvlan_linkiface_t *vlinkiface;
	uint32_t count = 0;
	uint32_t idx;

	vlinkiface = fp_macvlan_linkidx2linkiface(link_idx);

	for (idx=0; idx<FP_MACVLAN_IFACE_MAX; idx++)
		if (vlinkiface->macvlan_iface[idx].ifuid != 0)
			count ++;

	if (count == 0)
		fp_macvlan_link_delete(link_idx);

	return count;
}

int fp_addifnet_macvlaninfo(uint32_t ifuid, uint32_t link_ifuid,
			    uint32_t mode)
{
	fp_macvlan_iface_t *viface;
	fp_ifnet_t *ifp, *link_ifp;
	uint32_t link_idx, idx;

	link_idx = fp_macvlan_get_linkidx_by_link_ifuid(link_ifuid);
	if (link_idx == 0) {
		link_idx = fp_macvlan_link_create(link_ifuid);
		if (link_idx == 0)
			return -1;
	}

	viface = fp_macvlan_iface_lookup_by_ifuid(link_idx, ifuid);
	if (viface)
		/* interface is already present */
		return -1;

	idx = fp_macvlan_iface_assign(link_idx, ifuid, mode);
	if (idx == FP_MACVLAN_IFACE_MAX)
		/* max reached or incompatible mode */
		return -1;

	ifp = fp_ifuid2ifnet(ifuid);
	ifp->sub_table_index = idx;
	if (ifp)
		fp_ifnet_ops_register(ifp, TX_DEV_OPS,
				      fp_macvlan_shared->mod_uid,
				      (void *)(uintptr_t)link_idx);

	link_ifp = fp_ifuid2ifnet(link_ifuid);
	if ((link_ifp) && 
	    (fp_macvlan_get_interface_number_per_link (link_idx) == 1)) {
		/* First macvlan interface are registered on this link
		 * interface. Register input function entry for this link
		 * interface.
		 */
		if (fp_ifnet_ops_register(link_ifp, RX_DEV_OPS,
				          fp_macvlan_shared->mod_uid,
				          (void *)(uintptr_t)link_idx) != 0)
		{
			fp_log_common(LOG_ERR,
				      "%s: 0x%08x has already a dev ops.\n",
				      __FUNCTION__, link_ifp->if_ifuid);
			/* revert everything */
			if (ifp)
				fp_ifnet_ops_unregister(ifp, TX_DEV_OPS);
			viface = fp_macvlan_idxs2iface(link_idx,idx);
			viface->ifuid = 0;
			fp_macvlan_get_interface_number_per_link (link_idx);
			return -1;
		}
	}

	return 0;
}

int fp_delifnet_macvlaninfo(uint32_t ifuid)
{
	fp_ifnet_t *ifp = __fp_ifuid2ifnet(ifuid);
	fp_macvlan_linkiface_t *vlinkiface;
	fp_macvlan_iface_t *viface;
	fp_ifnet_t *link_ifp;
	uint32_t link_idx;

	link_idx = (uint32_t)(uintptr_t)fp_ifnet_ops_get_data(ifp, TX_DEV_OPS);
	if (link_idx == 0) {
		fp_log_common(LOG_ERR,
			      "%s: could not find macvlan link interface 0x%08x\n",
			      __FUNCTION__, ifuid);
		return -1;
	}

	vlinkiface = fp_macvlan_linkidx2linkiface(link_idx);
	viface = fp_macvlan_idxs2iface(link_idx,ifp->sub_table_index);
	link_ifp = __fp_ifuid2ifnet(vlinkiface->link_ifuid);

	viface->ifuid = 0;

	fp_ifnet_ops_unregister(ifp, TX_DEV_OPS);
	if (fp_macvlan_get_interface_number_per_link (link_idx) == 0) {
		/* No more macvlan interface are registered on this link
		 * interface. Remove input function entry for this link
		 * interface.
		 */
		fp_ifnet_ops_unregister(link_ifp, RX_DEV_OPS);
	}

	return 0;
}

int fp_updateifnet_macvlaninfo(uint32_t ifuid, uint32_t mode)
{
	fp_ifnet_t *ifp = __fp_ifuid2ifnet(ifuid);
	fp_macvlan_iface_t *viface;
	uint32_t link_idx;

	link_idx = (uint32_t)(uintptr_t)fp_ifnet_ops_get_data(ifp, TX_DEV_OPS);
	if (link_idx == 0) {
		fp_log_common(LOG_ERR,
			      "%s: could not find macvlan link interface 0x%08x\n", 
			      __FUNCTION__, ifuid);
		return -1;
	}

	viface = fp_macvlan_idxs2iface(link_idx, ifp->sub_table_index);
	if (viface == NULL) {
		fp_log_common(LOG_ERR,
			      "%s: could not find macvlan interface 0x%08x\n", 
			      __FUNCTION__, ifuid);
		return -1;
	}

	viface->mode = mode;

	return 0;
}

void fp_macvlan_init_shmem(int graceful)
{
	/* Reset if magic number is not here or if force reset mode */
	if ((fp_macvlan_shared->magic != FP_MACVLAN_MAGIC32) || !graceful) {

		/* Clear memory, except mod_uid */
		bzero(fp_macvlan_shared, (size_t) &((fp_macvlan_shared_mem_t *)NULL)->mod_uid);

		/* Setup magic */
		fp_macvlan_shared->magic = FP_MACVLAN_MAGIC32;
	}
}
