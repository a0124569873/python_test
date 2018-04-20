/*
 * Copyright 2014 6WIND S.A.
 */

#ifndef __FP_MACVLAN_LOOKUP_H__
#define __FP_MACVLAN_LOOKUP_H__

#include "fp-macvlan-var.h"

FPN_DECLARE_SHARED(fp_macvlan_shared_mem_t *, fp_macvlan_shared);

static inline fp_macvlan_iface_t *fp_macvlan_idxs2iface(uint32_t link_idx,
							uint32_t idx)
{
	return &fp_macvlan_shared->macvlan_linkiface[link_idx].macvlan_iface[idx];
}

static inline fp_macvlan_linkiface_t *fp_macvlan_linkidx2linkiface(uint32_t link_idx)
{
	return &fp_macvlan_shared->macvlan_linkiface[link_idx];
}

static inline fp_macvlan_iface_t *fp_macvlan_iface_lookup_by_ifuid(uint32_t link_idx, 
								   uint32_t ifuid)
{
	fp_macvlan_linkiface_t *vlinkiface = fp_macvlan_linkidx2linkiface(link_idx);
	uint32_t i;

	for (i=0; i<FP_MACVLAN_IFACE_MAX; i++)
		if (vlinkiface->macvlan_iface[i].ifuid == ifuid)
			return &vlinkiface->macvlan_iface[i];
	
	return NULL;
}

#endif /* __FP_VLAN_LOOKUP_H__ */
