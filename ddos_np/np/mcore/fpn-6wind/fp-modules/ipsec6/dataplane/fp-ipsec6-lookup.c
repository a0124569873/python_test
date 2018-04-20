/*
 * Copyright(c) 2009 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-ipsec6-lookup.h"
#include "fp-log.h"

#define TRACE_IPSEC6_LOOKUP(level, fmt, args...) do {			\
		FP_LOG(level, IPSEC6_LOOKUP, fmt "\n", ## args);		\
} while(0)

/*
 * The CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE option enables to perform
 * input and output SPD lookup with a hash lookup based on
 * the remote IP address.
 *
 * This lookup method requires that:
 * - SP filters do not overlap
 * - SP filters remote address is in /32
 *
 * The use case is an IPsec server that terminates remote roadwarrior
 * connections
 */


static inline int __ipv6_prefix_equal(const uint32_t *a1, const uint32_t *a2,
				      unsigned int prefixlen)
{
	unsigned pdw, pbi;

	/* check complete u32 in prefix */
	pdw = prefixlen >> 5;
	if (pdw && fpn_fast_memcmp(a1, a2, pdw << 2))
		return 0;

	/* check incomplete u32 in prefix */
	pbi = prefixlen & 0x1f;
	if (pbi && ((a1[pdw] ^ a2[pdw]) & htonl((0xffffffff) << (32 - pbi))))
		return 0;

	return 1;
}

static inline int __selector_match_v6(struct FILTER *filter,
				      const uint32_t *src, const uint32_t *dst,
				      uint8_t ul_proto,
				      uint16_t sport, uint16_t dport)
{
	if (filter->ul_proto != FILTER_ULPROTO_ANY &&
			filter->ul_proto != ul_proto)
		return 0;
	if (!__ipv6_prefix_equal(filter->dst6.fp_s6_addr32, dst, filter->dst_plen))
		return 0;
	if (!__ipv6_prefix_equal(filter->src6.fp_s6_addr32, src, filter->src_plen))
		return 0;
#ifdef CONFIG_MCORE_IPSEC_IPV6_LOOKUP_PORTS
	if ((sport ^ filter->srcport) & filter->srcport_mask)
		return 0;
	if ((dport ^ filter->dstport) & filter->dstport_mask)
		return 0;
#endif

	return 1;
}

/* perform a linear SPD lookup */
static inline uint32_t __spd6_lookup(fp_spd6_t *spd,
		const uint32_t *src, const uint32_t *dst,
		uint8_t ul_proto,
		uint16_t sport, uint16_t dport,
		uint16_t vrfid)
{
	uint32_t idx;

	fp_hlist_for_each(idx, fp_get_spd6_head(spd), spd->table, list) {
		FPN_TRACK();
		if (spd->table[idx].vrfid != vrfid)
			continue;
		if (!__selector_match_v6(&spd->table[idx].filter, src, dst, ul_proto,
				      sport, dport))
			continue;
		break;
	}

	return idx;
}

#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
/* perform a SPD hash lookup based on remote IP address */
static inline uint32_t __spd6_hash_lookup(fp_spd6_t *spd, uint16_t hash,
		const uint32_t *src, const uint32_t *dst,
		uint8_t ul_proto,
		uint16_t sport, uint16_t dport,
		uint16_t vrfid)
{
	uint32_t idx;

	TRACE_IPSEC6_LOOKUP(FP_LOG_DEBUG, "%s()", __FUNCTION__);

	fp_hlist_for_each(idx, &spd->addr_hash[hash], spd->table, addr_hlist) {
		if (spd->table[idx].vrfid != vrfid)
			continue;
		if (!__selector_match_v6(&spd->table[idx].filter, src, dst, ul_proto, 
					sport, dport))
			continue;
		break;
	}

	return idx;
}
#endif

fp_v6_sp_entry_t *spd6_in_lookup(uint32_t *src, uint32_t *dst, uint8_t ul_proto,
		uint16_t sport, uint16_t dport, uint16_t vrfid, uint32_t *spd_index)
{
	fp_spd6_t *spd = fp_get_spd6_in();
	uint32_t idx1 = 0, idx2 = 0, idx;

	if (likely(spd->entry_count == 0))
		return NULL;

#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
	if (spd->hashed_sp_count) {
		uint16_t hash;
		hash = sp6_addrvr2hash(dst, src, vrfid,
			fp_shared->ipsec6.spd6_hash_loc_plen,
			fp_shared->ipsec6.spd6_hash_rem_plen);

		idx1 = __spd6_hash_lookup(spd, hash, src, dst, ul_proto, 
					  sport, dport, vrfid);
	}
#endif

	if (spd->unhashed_sp_count) {
		idx2 = __spd6_lookup(spd, src, dst, ul_proto,
				     sport, dport, vrfid);
	}

	/* choose highest priority rule */
	if (idx1 && idx2) {
		if (spd->table[idx1].filter.cost <= spd->table[idx2].filter.cost)
			idx = idx1;
		else
			idx = idx2;
	}
	else
		/* one of idx1 or idx2 is null. idx1 ^ idx2 returns the other */
		idx = idx1 ^ idx2;

	if (idx) {
		if (spd_index)
			*spd_index = idx;
		return &spd->table[idx];
	}

	return NULL;
}

fp_v6_sp_entry_t *spd6_out_lookup(uint32_t *src, uint32_t *dst, uint8_t ul_proto,
		uint16_t sport, uint16_t dport, uint16_t vrfid)
{
	fp_spd6_t *spd = fp_get_spd6_out();
	uint32_t idx1 = 0, idx2 = 0, idx;

	if (likely(spd->entry_count == 0))
		return NULL;

#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
	if (spd->hashed_sp_count) {
		uint16_t hash;
		hash = sp6_addrvr2hash(src, dst, vrfid,
			fp_shared->ipsec6.spd6_hash_loc_plen,
			fp_shared->ipsec6.spd6_hash_rem_plen);

		idx1 = __spd6_hash_lookup(spd, hash, src, dst, ul_proto, 
			          sport, dport, vrfid);
	}
#endif

	if (spd->unhashed_sp_count) {
			idx2 = __spd6_lookup(spd, src, dst, ul_proto,
					sport, dport, vrfid);
	}

	/* choose highest priority rule */
	if (idx1 && idx2) {
		if (spd->table[idx1].filter.cost <= spd->table[idx2].filter.cost)
			idx = idx1;
		else
			idx = idx2;
	}
	else
		/* one of idx1 or idx2 is null. idx1 ^ idx2 returns the other */
		idx = idx1 ^ idx2;

	if (idx)
		return &spd->table[idx];

	return NULL;
}

#ifdef IPSEC_IPV6_SPI_HASH
fp_v6_sa_entry_t *sad6_in_lookup(uint32_t spi, uint32_t *dst, uint8_t proto, uint16_t vrfid)
{
	fp_sad6_t *sad = fp_get_sad6();
	fp_hlist_head_t *head;
	uint32_t i;

	/* empty table */
	if (sad->count ==0)
		return NULL;

	/* calculate hash line */
	head = &sad->spi_hash[sa6_spi2hash(spi)];
	i = fp_hlist_first(head);

	/* best case: first hash entry matches triplet */
	if (likely((i != 0) &&
		   (sad->table[i].vrfid == vrfid) &&
	           (sad->table[i].spi == spi) && 
	           (fpn_fast_memcmp(sad->table[i].dst6.fp_s6_addr32, dst, sizeof(fp_in6_addr_t)) == 0) &&
	           (sad->table[i].proto == proto)))
	{
		if (likely(sad->table[i].state != FP_SA_STATE_UNSPEC))
			return &sad->table[i];
	}

	/* empty list? */
	if (i == 0)
		return NULL;

	/* bad luck, follow hash list */
	fp_hlist_for_each_continue(i, head, sad->table, spi_hlist) {
		if ((sad->table[i].vrfid == vrfid) &&
		    (sad->table[i].spi == spi) &&
		    (fpn_fast_memcmp(sad->table[i].dst6.fp_s6_addr32, dst, sizeof(fp_in6_addr_t)) == 0) &&
		    (sad->table[i].proto == proto))
		{
			FPN_TRACK();
			if (likely(sad->table[i].state != FP_SA_STATE_UNSPEC))
				return &sad->table[i];
		}
	}

	/* not found */
	return NULL;
}

#else
fp_v6_sa_entry_t *sad6_in_lookup(uint32_t spi, uint32_t *dst, uint8_t proto, uint16_t vrfid)
{
	uint32_t i;
	uint32_t count;
	fp_sad6_t *sad = fp_get_sad6();
	count = sad->count;
	for (i = 1; count > 0 && i < FP_MAX_IPV6_SA_ENTRIES; i++) {
		if (sad->table[i].state == FP_SA_STATE_UNSPEC)
			continue;
		count--;
		if (vrfid != sad->table[i].vrfid)
			continue;
		if (spi != sad->table[i].spi)
			continue;
		/* 
		 * RFC4301 section 5.2 3a: use only the SPI
		 * (We support only unicast destination in SA)
		 */
		if (fpn_fast_memcmp(dst, sad->table[i].dst.fp_s6_addr32, sizeof(fp_in6_addr_t)))
			continue;
		if (proto != sad->table[i].proto)
			continue;

		return &sad->table[i];
	}
	return NULL;
}
#endif

fp_v6_sa_entry_t *sad6_out_lookup(uint32_t *src, uint32_t *dst, uint16_t proto,
			      uint8_t mode, uint32_t reqid, uint16_t vrfid, uint16_t xvrfid,
#ifdef CONFIG_MCORE_IPSEC_SVTI
			      uint32_t svti_ifuid,
#endif
			      uint32_t *sa_index)
{
	fp_sad6_t *sad = fp_get_sad6();
	fp_hlist_head_t *head;
	uint32_t i, h;

	/* empty table? */
	if (sad->count == 0)
		return NULL;

	/* find hash line */
	h = __sa6_selector2hash(src, dst, proto, vrfid, xvrfid);
	head = &sad->selector_hash[h];
	i = fp_hlist_first(head);

	/* first hash entry matches */
	if (likely(i != 0 &&
		   mode == sad->table[i].mode &&
		   proto == sad->table[i].proto &&
	           vrfid == sad->table[i].vrfid &&
	           xvrfid == sad->table[i].xvrfid &&
		   (fpn_fast_memcmp(dst, sad->table[i].dst6.fp_s6_addr32, sizeof(fp_in6_addr_t)) == 0) &&
		   (fpn_fast_memcmp(src, sad->table[i].src6.fp_s6_addr32, sizeof(fp_in6_addr_t)) == 0) &&
#ifdef CONFIG_MCORE_IPSEC_SVTI
		   svti_ifuid == sad->table[i].svti_ifuid &&
#endif
		   (!reqid || (reqid == sad->table[i].reqid)))) {
		if (likely(sad->table[i].state != FP_SA_STATE_UNSPEC)) {
			if (sa_index)
				*sa_index = i;
			return &sad->table[i];
		}
	}
	
	/* follow hash list */
	fp_hlist_for_each_continue(i, head, sad->table, selector_hlist) {
		if (mode == sad->table[i].mode &&
		    proto == sad->table[i].proto &&
		    vrfid == sad->table[i].vrfid &&
		    xvrfid == sad->table[i].xvrfid &&
		    (fpn_fast_memcmp(dst, sad->table[i].dst6.fp_s6_addr32, sizeof(fp_in6_addr_t)) == 0) &&
		    (fpn_fast_memcmp(src, sad->table[i].src6.fp_s6_addr32, sizeof(fp_in6_addr_t)) == 0) &&
#ifdef CONFIG_MCORE_IPSEC_SVTI
		   svti_ifuid == sad->table[i].svti_ifuid &&
#endif
		    (!reqid || (reqid == sad->table[i].reqid))) {
			if (likely(sad->table[i].state != FP_SA_STATE_UNSPEC)) {
				if (sa_index)
					*sa_index = i;
				return &sad->table[i];
			}
		}
	}

	/* not found */
	return NULL;
}

#ifdef CONFIG_MCORE_IPSEC_SVTI
fp_v6_sp_entry_t *spd6_svti_out_lookup(uint32_t *src, uint32_t *dst, uint8_t ul_proto,
		uint16_t sport, uint16_t dport, fp_svti_t *svti)
{
	uint32_t i;
	fp_spd6_t *spd;

	spd = fp_get_spd6_out();

	fp_hlist_for_each(i, &svti->spd6_out, spd->table, list) {
		FPN_TRACK();
		if (!__selector_match_v6(&spd->table[i].filter, src, dst, ul_proto,
					sport, dport))
			continue;
		return &spd->table[i];
	}

	return NULL;
}

fp_v6_sp_entry_t *spd6_svti_in_lookup(uint32_t *src, uint32_t *dst, uint8_t ul_proto,
		uint16_t sport, uint16_t dport, fp_svti_t *svti, uint32_t *spd_index)
{
	uint32_t i;
	fp_spd6_t *spd;

	spd = fp_get_spd6_in();

	fp_hlist_for_each(i, &svti->spd6_in, spd->table, list) {
		FPN_TRACK();
		if (!__selector_match_v6(&spd->table[i].filter, src, dst, ul_proto,
					sport, dport))
			continue;
		if (spd_index)
			*spd_index = i;
		return &spd->table[i];
	}

	return NULL;
}
#endif /* CONFIG_MCORE_IPSEC_SVTI */
