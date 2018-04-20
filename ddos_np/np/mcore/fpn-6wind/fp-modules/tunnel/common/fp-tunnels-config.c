/*
 * Copyright (c) 2008 6WIND, All rights reserved.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "fp.h"

void fp_tunnel_link(uint32_t idx)
{
	uint16_t hash, next;

	switch (fp_shared->fp_tunnels.table[idx].proto) {
#ifdef CONFIG_MCORE_XIN4
	case FP_IPPROTO_IP:
		hash = FP_XIN4_HASH(fp_shared->fp_tunnels.table[idx].p.xin4.ip_src.s_addr,
				    fp_shared->fp_tunnels.table[idx].p.xin4.ip_dst.s_addr);

		next = fp_shared->fp_tunnels.hash_xin4[hash];
		fp_shared->fp_tunnels.table[idx].hash_prev = 0;
		fp_shared->fp_tunnels.table[idx].hash_next = next;
		fp_shared->fp_tunnels.hash_xin4[hash] = idx;
		if (next)
			fp_shared->fp_tunnels.table[next].hash_prev = idx;
		break;
#endif
#ifdef CONFIG_MCORE_XIN6
	case FP_IPPROTO_IPV6:
		hash = FP_XIN6_HASH(&fp_shared->fp_tunnels.table[idx].p.xin6.ip6_src,
				    &fp_shared->fp_tunnels.table[idx].p.xin6.ip6_dst);

		next = fp_shared->fp_tunnels.hash_xin6[hash];
		fp_shared->fp_tunnels.table[idx].hash_prev = 0;
		fp_shared->fp_tunnels.table[idx].hash_next = next;
		fp_shared->fp_tunnels.hash_xin6[hash] = idx;
		if (next)
			fp_shared->fp_tunnels.table[next].hash_prev = idx;
		break;
#endif
	}
}

void fp_tunnel_unlink(uint32_t idx)
{
	uint16_t hash, prev, next;

	switch (fp_shared->fp_tunnels.table[idx].proto) {
#ifdef CONFIG_MCORE_XIN4
	case FP_IPPROTO_IP:
		hash = FP_XIN4_HASH(fp_shared->fp_tunnels.table[idx].p.xin4.ip_src.s_addr,
				    fp_shared->fp_tunnels.table[idx].p.xin4.ip_dst.s_addr);
		prev = fp_shared->fp_tunnels.table[idx].hash_prev;
		next = fp_shared->fp_tunnels.table[idx].hash_next;

		if (prev)
			fp_shared->fp_tunnels.table[prev].hash_next = next;
		else
			fp_shared->fp_tunnels.hash_xin4[hash] = next;

		if (next)
			fp_shared->fp_tunnels.table[next].hash_prev = prev;
		break;
#endif
#ifdef CONFIG_MCORE_XIN6
	case FP_IPPROTO_IPV6:
		hash = FP_XIN6_HASH(&fp_shared->fp_tunnels.table[idx].p.xin6.ip6_src,
				    &fp_shared->fp_tunnels.table[idx].p.xin6.ip6_dst);
		prev = fp_shared->fp_tunnels.table[idx].hash_prev;
		next = fp_shared->fp_tunnels.table[idx].hash_next;

		if (prev)
			fp_shared->fp_tunnels.table[prev].hash_next = next;
		else
			fp_shared->fp_tunnels.hash_xin6[hash] = next;

		if (next)
			fp_shared->fp_tunnels.table[next].hash_prev = prev;
		break;
#endif
	}
}

/*
 * assign a free cell in the fp_tunnels table
 */
static uint32_t fp_tunnel_assign(uint32_t ifuid)
{
	uint32_t idx;

	for (idx = 1; idx < FP_MAX_TUNNELS; idx++)
		if (fp_shared->fp_tunnels.table[idx].ifuid == 0)
			return idx;

	return 0;
}

int fp_delifnet_xinyinfo(uint32_t ifuid)
{
	fp_tunnel_entry_t *tun;

	uint32_t idx = __fp_ifuid2ifnet(ifuid)->sub_table_index;
	if (idx == 0)
		return -1;

	tun = &fp_shared->fp_tunnels.table[idx];
	if (tun->ifuid == 0)
		return -1;
	tun->ifuid = 0;
	fp_tunnel_unlink(idx);
	memset(tun, 0, sizeof(fp_tunnel_entry_t));
	return 0;
}

int fp_addifnet_xin4info(uint32_t ifuid, uint8_t hoplim, uint8_t tos,
			 uint8_t inh_tos, uint16_t vrfid, uint16_t linkvrfid,
			 struct fp_in_addr *local, struct fp_in_addr *remote)
{
	fp_tunnel_entry_t *tun;
	fp_ifnet_t *ifp;

	uint32_t idx = fp_tunnel_assign(ifuid);
	if (idx == 0)
		return -1;

	tun = &fp_shared->fp_tunnels.table[idx];
	memset(tun, 0, sizeof(fp_tunnel_entry_t));

	tun->p.xin4.ip_v = FP_IPVERSION;
	tun->p.xin4.ip_hl = 5;
	tun->p.xin4.ip_off = htons(FP_IP_DF);
	tun->p.xin4.ip_ttl = hoplim;
	memcpy(&tun->p.xin4.ip_src, local, sizeof(struct fp_in_addr));
	memcpy(&tun->p.xin4.ip_dst, remote, sizeof(struct fp_in_addr));

	tun->linkvrfid = linkvrfid;
	tun->proto = FP_IPPROTO_IP;
	tun->ifuid = ifuid;

	fp_tunnel_link(idx);

	ifp = fp_ifuid2ifnet(ifuid);
	if (ifp)
		ifp->sub_table_index = idx;

	return 0;
}

#ifdef CONFIG_MCORE_XIN6
int fp_addifnet_xin6info(uint32_t ifuid, uint8_t hoplim, uint8_t tos,
			 uint8_t inh_tos, uint16_t vrfid, uint16_t linkvrfid,
			 fp_in6_addr_t *local, fp_in6_addr_t *remote)
{
	fp_tunnel_entry_t *tun;
	fp_ifnet_t *ifp;

	uint32_t idx = fp_tunnel_assign(ifuid);
	if (idx == 0)
		return -1;

	tun = &fp_shared->fp_tunnels.table[idx];
	memset(tun, 0, sizeof(fp_tunnel_entry_t));

	tun->p.xin6.ip6_v = FP_IP6VERSION;
	tun->p.xin6.ip6_hlim = hoplim;
	memcpy(&tun->p.xin6.ip6_src, local, sizeof(struct fp_in6_addr));
	memcpy(&tun->p.xin6.ip6_dst, remote, sizeof(struct fp_in6_addr));

	tun->linkvrfid = linkvrfid;
	tun->proto = FP_IPPROTO_IPV6;
	tun->ifuid = ifuid;

	fp_tunnel_link(idx);

	ifp = fp_ifuid2ifnet(ifuid);
	if (ifp)
		ifp->sub_table_index = idx;

	return 0;
}
#endif
