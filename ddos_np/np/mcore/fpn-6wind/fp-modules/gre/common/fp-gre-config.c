/*
 * Copyright 2014 6WIND S.A.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "fp.h"
#ifdef __FastPath__
#include "fp-includes.h"
#endif
#include "fp-gre-var.h"

/* assign a free cell in the GRE table */
static uint32_t fp_gre_assign(void)
{
	uint32_t idx = fp_gre_shared->if_gre_freecell;

	fp_gre_shared->if_gre_freecell = fp_gre_shared->if_gre[idx].next_idx;

	return idx;
}

/* unassign an used cell in the GRE table */
static void fp_gre_unassign(uint32_t idx)
{
	fp_gre_shared->if_gre[idx].next_idx = fp_gre_shared->if_gre_freecell;
	fp_gre_shared->if_gre_freecell = idx;
}

/* GRE interfaces are accessible by IP proto (v4/v6) via two hash tables.
 * the hash value is calculated with their local and remote addresses and
 * input key. If local or remote address is any the hash is computed with
 * the other address and the input key. If both addresses are any the hash
 * is computed with key only.
 */

/* compute hash value */
static uint32_t fp_gre_hash(fp_ifgre_t *gre)
{
	uint32_t local_h;
	uint32_t remote_h;
	uint32_t key_h = __FP_GRE_HASH_KEY(gre->ikey);

	if (gre->family == AF_INET) {
		local_h = __FP_GRE_HASH_ADDR4(gre->local.local4.s_addr);
		remote_h = __FP_GRE_HASH_ADDR4(gre->remote.remote4.s_addr);

		if (gre->local.local4.s_addr != 0 && gre->remote.remote4.s_addr != 0)
			return FP_GRE_HASH_IPV4(local_h, remote_h, key_h);
		else if (gre->local.local4.s_addr == 0 && gre->remote.remote4.s_addr != 0)
			return FP_GRE_HASH_IPV4_1AK(remote_h, key_h);
		else if (gre->local.local4.s_addr != 0 && gre->remote.remote4.s_addr == 0)
			return FP_GRE_HASH_IPV4_1AK(local_h, key_h);
		else
			return FP_GRE_HASH_IPV4_KEY(key_h);
	}
#ifdef CONFIG_MCORE_IPV6
	else {
		uint32_t local_isany = FP_IN6_IS_ADDR_UNSPECIFIED(&gre->local.local6);
		uint32_t remote_isany = FP_IN6_IS_ADDR_UNSPECIFIED(&gre->remote.remote6);

		local_h = __FP_GRE_HASH_ADDR6(gre->local.local6);
		remote_h = __FP_GRE_HASH_ADDR6(gre->remote.remote6);

		if (!local_isany && !remote_isany)
			return FP_GRE_HASH_IPV6(local_h, remote_h, key_h);
		else if (local_isany && !remote_isany)
			return FP_GRE_HASH_IPV6_1AK(remote_h, key_h);
		else if (!local_isany && remote_isany)
			return FP_GRE_HASH_IPV6_1AK(local_h, key_h);
		else
			return FP_GRE_HASH_IPV6_KEY(key_h);
	}
#else

	fp_log_common(LOG_ERR, "%s: invalide IP version %s.\n", __FUNCTION__,
		      ((gre->family == AF_INET) ? "IPv4" : "IPv6"));
	return 0;
#endif
}

/* add a GRE interface in the hash table */
static void fp_gre_link(uint32_t idx, fp_ifgre_t *gre)
{
	uint32_t hash;

	if (gre->family == AF_INET) {
		hash = fp_gre_hash(gre);

		fp_hlist_add_head(&fp_gre_shared->gre_ipv4_hlist[hash],
				  &fp_gre_shared->if_gre[0], idx, hlist);
#ifdef CONFIG_MCORE_IPV6
	} else {
		hash = fp_gre_hash(gre);

		fp_hlist_add_head(&fp_gre_shared->gre_ipv6_hlist[hash],
				  &fp_gre_shared->if_gre[0], idx, hlist);
#endif
	}
}

/* delete a GRE interface from the hash table */
static void fp_gre_unlink(uint32_t idx, fp_ifgre_t *gre)
{
	uint32_t hash;

	if (gre->family == AF_INET) {
		hash = fp_gre_hash(gre);

		fp_hlist_remove(&fp_gre_shared->gre_ipv4_hlist[hash],
				&fp_gre_shared->if_gre[0], idx, hlist);
#ifdef CONFIG_MCORE_IPV6
	} else {
		hash = fp_gre_hash(gre);

		fp_hlist_remove(&fp_gre_shared->gre_ipv6_hlist[hash],
				&fp_gre_shared->if_gre[0], idx, hlist);
#endif
	}
}


static void fp_ifnet_parse_greinfo(fp_ifgre_t *gre, uint32_t ifuid,
				   uint32_t link_ifuid, uint16_t iflags,
				   uint16_t oflags, uint8_t mode,
				   uint32_t ikey, uint32_t okey,
				   uint8_t ttl, uint8_t tos, uint8_t inh_tos,
				   uint8_t ip_family, void *local_addr,
				   void *remote_addr, uint16_t link_vrfid)
{
	gre->link_vrfid = link_vrfid;
	gre->link_ifuid = link_ifuid;
	gre->iflags = iflags;
	gre->oflags = oflags;
	gre->ikey = ikey;
	gre->okey = okey;
	gre->ttl = ttl;
	gre->tos = tos;
	gre->inh_tos = inh_tos;
	gre->family = ip_family;
	gre->mode = mode;

	if (gre->family == AF_INET) {
		gre->local.local4.s_addr = *(uint32_t *)local_addr;
		gre->remote.remote4.s_addr = *(uint32_t *)remote_addr;
#ifdef CONFIG_MCORE_IPV6
	} else {
		memcpy(&gre->local.local6, local_addr, sizeof(gre->local.local6));
		memcpy(&gre->remote.remote6, remote_addr, sizeof(gre->remote.remote6));
#endif
	}

	gre->ifuid = ifuid;
}

int fp_addifnet_greinfo(uint32_t ifuid, uint32_t link_ifuid, uint16_t iflags,
			uint16_t oflags, uint8_t mode,
			uint32_t ikey, uint32_t okey, uint8_t ttl,
			uint8_t tos, uint8_t inh_tos, uint8_t ip_family,
			void *local_addr, void *remote_addr, uint16_t link_vrfid)
{
	uint32_t idx;
	fp_ifgre_t *gre;
	fp_ifnet_t *ifp;

	ifp = __fp_ifuid2ifnet(ifuid);
	if ((ifp->if_type != FP_IFTYPE_GRE) &&
	    (ifp->if_type != FP_IFTYPE_GRETAP)) {
		fp_log_common(LOG_ERR, "%s: %s is not a GRE interface.\n", __FUNCTION__,
			      ifp->if_name);
		return -1;
	}

	idx = fp_gre_assign();
	if (idx == 0) {
		fp_log_common(LOG_ERR, "%s: too many GRE interfaces.\n", __FUNCTION__);
		return -1;
	}

	if (mode == FP_GRE_MODE_ETHER) {
		if (fp_ifnet_ops_register(ifp, TX_DEV_OPS,
					  fp_gre_shared->mod_uid,
					  (void *) (uintptr_t) idx) != 0) {
			fp_log_common(LOG_ERR, "%s: %s has already an ip output ops.\n",
				      __FUNCTION__, ifp->if_name);
			fp_gre_unassign(idx);
			return -1;
		}
	} else {
		if (fp_ifnet_ops_register(ifp, IP_OUTPUT_OPS,
					  fp_gre_shared->mod_uid,
					  (void *) (uintptr_t) idx) != 0) {
			fp_log_common(LOG_ERR, "%s: %s has already an ip output ops.\n",
				      __FUNCTION__, ifp->if_name);
			fp_gre_unassign(idx);
			return -1;
		}
	}

	bzero(&fp_gre_shared->if_gre[idx], sizeof(fp_gre_shared->if_gre[idx]));
	gre = &fp_gre_shared->if_gre[idx];

	fp_ifnet_parse_greinfo(gre, ifuid, link_ifuid, iflags, oflags,
			       mode, ikey, okey,
			       ttl, tos, inh_tos, ip_family, local_addr, remote_addr,
			       link_vrfid);

	fp_gre_link(idx, gre);

	return 0;
}

/* Check if the hash value will change after the update */
static int fp_gre_check_hash_param(fp_ifgre_t *gre, void *local_addr,
				   void *remote_addr, uint32_t ikey_flags,
				   uint32_t ikey)
{
	/* check local and remote addresses */
	if (gre->family == AF_INET) {
		if (gre->local.local4.s_addr != *(uint32_t *)local_addr ||
		    gre->remote.remote4.s_addr != *(uint32_t *)remote_addr)
			return 1;
#ifdef CONFIG_MCORE_IPV6
	} else {
		if (memcmp(&gre->local.local6, local_addr,
			   sizeof(gre->local.local6)) != 0 ||
		    memcmp(&gre->remote.remote6, remote_addr,
			   sizeof(gre->remote.remote6)) != 0)
			return 1;
#endif
	}

	/* check iflags and keys */
	if (ikey_flags ^ (gre->iflags & FP_GRE_FLAG_KEY))
		return 1;

	if (ikey_flags && gre->ikey != ikey)
		return 1;

	return 0;
}

int fp_upifnet_greinfo(uint32_t ifuid, uint32_t link_ifuid, uint16_t iflags,
		       uint16_t oflags, uint8_t mode,
		       uint32_t ikey, uint32_t okey, uint8_t ttl,
		       uint8_t tos, uint8_t inh_tos, uint8_t ip_family,
		       void *local_addr, void *remote_addr, uint16_t link_vrfid)
{
	fp_ifnet_t *ifp_gre;
	fp_ifgre_t *gre;
	uint32_t idx;
	int change_hash;

	ifp_gre = __fp_ifuid2ifnet(ifuid);
	if ((ifp_gre->if_type != FP_IFTYPE_GRE) &&
	    (ifp_gre->if_type != FP_IFTYPE_GRETAP)) {
		fp_log_common(LOG_ERR, "%s: %s is not a GRE interface.\n", __FUNCTION__,
			      ifp_gre->if_name);
		return -1;
	}

	if ((ifp_gre->if_type == FP_IFTYPE_GRETAP) && (mode != FP_GRE_MODE_ETHER)) {
		fp_log_common(LOG_ERR, "%s: mode IP does not match with gretap interface\n",
			      __FUNCTION__);
		return -1;
	}

	if ((ifp_gre->if_type == FP_IFTYPE_GRE) && (mode != FP_GRE_MODE_IP)) {
		fp_log_common(LOG_ERR, "%s: mode Ether does not match with gre interface\n",
			      __FUNCTION__);
		return -1;
	}

	if (mode == FP_GRE_MODE_ETHER)
		idx = (uint32_t)(uintptr_t)fp_ifnet_ops_get_data(ifp_gre, TX_DEV_OPS);
	else
		idx = (uint32_t)(uintptr_t)fp_ifnet_ops_get_data(ifp_gre, IP_OUTPUT_OPS);

	gre = &fp_gre_shared->if_gre[idx];

	change_hash = fp_gre_check_hash_param(gre, local_addr, remote_addr,
					      (iflags & FP_GRE_FLAG_KEY), ikey);
	if (change_hash)
		fp_gre_unlink(idx, gre);

	fp_ifnet_parse_greinfo(gre, ifuid, link_ifuid, iflags, oflags,
			       mode, ikey, okey,
			       ttl, tos, inh_tos, ip_family, local_addr, remote_addr,
			       link_vrfid);

	if (change_hash)
		fp_gre_link(idx, gre);

	return 0;
}

int fp_delifnet_greinfo(uint32_t ifuid)
{
	uint32_t idx;
	fp_ifnet_t *ifp;

	ifp = __fp_ifuid2ifnet(ifuid);
	if (ifp->if_type != FP_IFTYPE_GRE) {
		fp_log_common(LOG_ERR, "%s: %s is not a GRE interface.\n", __FUNCTION__,
			      ifp->if_name);
		return -1;
	}

	idx = (uint32_t)(uintptr_t)fp_ifnet_ops_get_data(ifp, IP_OUTPUT_OPS);

	fp_gre_shared->if_gre[idx].ifuid = 0;
	fp_gre_unlink(idx, &fp_gre_shared->if_gre[idx]);
	fp_gre_unassign(idx);

	fp_ifnet_ops_unregister(ifp, IP_OUTPUT_OPS);

	return 0;
}

int fp_delifnet_gretapinfo(uint32_t ifuid)
{
	uint32_t idx;
	fp_ifnet_t *ifp;

	ifp = __fp_ifuid2ifnet(ifuid);
	if (ifp->if_type != FP_IFTYPE_GRETAP) {
		fp_log_common(LOG_ERR, "%s: %s is not a GRETAP interface.\n", __FUNCTION__,
			      ifp->if_name);
		return -1;
	}

	idx = (uint32_t)(uintptr_t)fp_ifnet_ops_get_data(ifp, TX_DEV_OPS);

	fp_gre_shared->if_gre[idx].ifuid = 0;
	fp_gre_unlink(idx, &fp_gre_shared->if_gre[idx]);
	fp_gre_unassign(idx);

	fp_ifnet_ops_unregister(ifp, TX_DEV_OPS);

	return 0;
}

void fp_gre_init_shmem(int graceful)
{
	/* Reset if magic number is not here or if force reset mode */
	if ((fp_gre_shared->magic != FP_GRE_MAGIC32) || !graceful) {
		uint32_t idx;

		/* Clear memory, except mod_uid */
		bzero(fp_gre_shared, (size_t) &((fp_gre_shared_mem_t *)NULL)->mod_uid);

		/* Setup initial values */
		fp_gre_shared->if_gre_freecell = 1;
		fp_gre_shared->ovsport = 0;
		for (idx = 1; idx < FP_GRE_MAX - 1; idx++)
			fp_gre_shared->if_gre[idx].next_idx = idx+1;

		fp_gre_shared->if_gre[FP_GRE_MAX-1].next_idx = 0;

		/* Setup magic */
		fp_gre_shared->magic = FP_GRE_MAGIC32;
	}
}

void fp_gretap_fpvs_create(uint32_t ovsport)
{
	/* OVS create only one GRE datapath called gre_system for all created
	 * GRE vport.
	 * The create function is only called when the first GRE vport is
	 * created. Information about all GRE vport is managed by the fp-vswitch
	 * daemon. Just keep information that some GRE vport exists to send
	 * GRETAP packet to fp-vswitch daemon that are not for any registered
	 * GRETAP (registration done through netlink)
	 */
	fp_gre_shared->ovsport = ovsport;
}

void fp_gretap_fpvs_delete(void)
{
	/* OVS delete is called when the last GRE vport is deleted */
	fp_gre_shared->ovsport = 0;
}
