/*
 * Copyright (c) 2010 6WIND
 */
#ifndef __FP_NF_CACHE_COMMON_FUNCS_H__
#define __FP_NF_CACHE_COMMON_FUNCS_H__

#ifdef CONFIG_MCORE_NETFILTER_CACHE
#include "fp-nf-cache.h"
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE
#include "fp-nf6-cache.h"
#endif

#include "fp-nf-cache-common.h"

/* return 1 if a packet + infos (indev, outdev, hooknum, ...)
 * completely match a cache entry */
static inline int fp_nf_cache_match(const fp_nf_rule_cache_common_entry_t *nf_cache_entry,
			     const struct mbuf *m, const struct fp_nf_cache_mask *mask_desc,
			     int hook, int table, const fp_ifnet_t *indev,
			     const fp_ifnet_t *outdev, const uint8_t family)
{
	int i, len32;
	uint32_t *pkt;

	if (nf_cache_entry->hook_num != hook)
		return 0;
	if (nf_cache_entry->table_num != table)
		return 0;
	if (nf_cache_entry->vrid != m2vrfid(m))
		return 0;
	if (nf_cache_entry->in_ifuid != (indev? indev->if_ifuid : 0))
		return 0;
	if (nf_cache_entry->out_ifuid != (outdev? outdev->if_ifuid : 0))
		return 0;
	len32 = nf_cache_entry->hdr_len32;
	if (len32 != mask_desc->len32)
		return 0;

	pkt = mtod(m, uint32_t *);
	/* check if packet header matches the header stored in cache */
	for (i=0; i<len32; i++) {

		if ((pkt[i] & mask_desc->mask[i]) != nf_cache_entry->hdr[i]) {

			/* header can be different that the flow
			 * stored in cache in a specific condition:
			 *  - packet is v4
			 *  - fragment offset in cache or packet is 0 or "not 0".
			 *     0: means first fragement packet or cache created for 
			 *        first fragment.
			 *     "not 0": not first fragments. 2th, 3th ...fragments
			 * */
			if (likely(family != AF_INET))
				return 0;
			if (likely((i*4) != (fpn_offsetof(struct fp_ip, ip_off) & (~3))))
				return 0;
			if (likely((ntohl(pkt[i] & mask_desc->mask[i]) & ~FP_IP_OFFMASK) !=
				   (ntohl(nf_cache_entry->hdr[i]) & ~FP_IP_OFFMASK)))
				return 0;
			if ((ntohl(pkt[i] & mask_desc->mask[i]) & FP_IP_OFFMASK) != 0 &&
			    (ntohl(nf_cache_entry->hdr[i]) & FP_IP_OFFMASK) != 0)
				continue;

			return 0;
		}
	}

	return 1;
}

/* Browse the hashtable bucket and try to match an entry */
static inline uint32_t fp_nf_cache_get(fp_nf_cache_bucket_t *cache_bucket,
				       int cache_bucket_locked,
				       const struct mbuf *m,
				       const struct fp_nf_cache_mask *mask_desc,
				       int hook, int table,
				       const fp_ifnet_t *indev,
				       const fp_ifnet_t *outdev, const uint8_t family)
{
	uint32_t idx;
	fp_nf_rule_cache_common_entry_t *cache;

	/* Browse the list hashtable and try to fully match entries */
	idx = cache_bucket->head;
	while (idx != IDX_NONE) {
		FPN_TRACK();
#ifdef CONFIG_MCORE_NETFILTER_CACHE
		if (family == AF_INET)
			cache = (fp_nf_rule_cache_common_entry_t *)
				&fp_shared->fp_nf_rule_cache[idx];
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE
		if (family == AF_INET6)
			cache = (fp_nf_rule_cache_common_entry_t *)
				&fp_shared->fp_nf6_rule_cache[idx];
#endif

		/* Ignore entries that are not in USED state. If
		 * possible, remove all following entries from list,
		 * to avoid browsing them again. */
		if (unlikely(cache->state == FP_NF_CACHE_STATE_FREE)) {
			if (likely(cache_bucket_locked))
				cache->next = IDX_NONE;
			else {
				if (!fpn_spinlock_trylock(&cache_bucket->lock))
					return IDX_NONE;
				cache->next = IDX_NONE;
				fpn_spinlock_unlock(&cache_bucket->lock);
			}
			return IDX_NONE;
		}

		/* if entry is valid, try to match it */
		if (fp_nf_cache_match(cache, m, mask_desc, hook, table, indev,
				      outdev, family))
			break;

		idx = cache->next;
	}

	return idx;
}

#endif /* __FP_NF_CACHE_COMMON_FUNCS_H__ */
