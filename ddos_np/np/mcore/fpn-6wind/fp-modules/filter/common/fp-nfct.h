/*
 * Copyright (c) 2008 6WIND
 */

#ifndef __FP_NFCT_H__
#define __FP_NFCT_H__

#define FP_NFCT_HASHTABLE_MASK (FP_NF_CT_HASH_SIZE - 1)
static inline uint32_t fp_nfct_hash(uint32_t src, uint32_t dst,
                                    uint16_t sport, uint16_t dport,
                                    uint16_t vrfid, uint8_t proto)
{
	uint32_t a, b, c = 0;

	a = src;
	b = dst;
	c = sport + ((uint32_t)dport << 16);
#ifdef CONFIG_MCORE_VRF
	c ^= vrfid + (proto << 16);
#else
	c ^= (proto << 16);
#endif

	fp_jhash_mix(a, b, c);

	return c & FP_NFCT_HASHTABLE_MASK;
}

#ifdef CONFIG_MCORE_NF_CT_CPEID
#define FP_NFCT_HASHTABLE_CPEID_MASK (FP_NF_CT_HASH_CPEID_SIZE - 1)
static inline uint32_t fp_nfct_hash_cpeid(uint32_t cpeid)
{
	return fp_jhash_1word(cpeid) & FP_NFCT_HASHTABLE_CPEID_MASK;
}
#endif

#ifdef CONFIG_MCORE_NF_CT
/* Assume that id is valid */
static inline struct fp_nfct_tuple_h *
fp_nfct_id_to_tuple(union fp_nfct_tuple_id id)
{
	return &fp_shared->fp_nf_ct.fp_nfct[id.s.index].tuple[id.s.dir];
}

static inline struct fp_nfct_entry *
fp_nfct_tuple_to_entry(struct fp_nfct_tuple_h *tuple)
{
	return (struct fp_nfct_entry *)(tuple - tuple->dir);
}

/* We don't need to verify if the conntrack that we are checking is valid.
 * At worse, one packet will not be sent to the correct destination,
 * but the hash list and the tuple are always valid.
 */
static inline struct fp_nfct_entry *
fp_nfct_lookup(uint8_t proto, uint32_t src, uint32_t dst,
               uint16_t sport, uint16_t dport, uint16_t vrfid, uint8_t *dir)
{
	uint32_t hash = fp_nfct_hash(src, dst, sport, dport, vrfid, proto);
	union fp_nfct_tuple_id id = { .u32 = fp_shared->fp_nf_ct.fp_nfct_hash[hash].u32 };
	struct fp_nfct_tuple_h *tuple;

	while (id.s.index != FP_NF_CT_MAX) {
		tuple = fp_nfct_id_to_tuple(id);
		if (tuple->src == src &&
		    tuple->dst == dst &&
		    tuple->sport == sport &&
		    tuple->dport == dport &&
		    tuple->proto == proto 
#ifdef CONFIG_MCORE_VRF
		    && tuple->vrfid == vrfid
#endif
		    ) {
			if (dir)
				*dir = tuple->dir;
			return fp_nfct_tuple_to_entry(tuple);
		}

		id.u32 = tuple->hash_next.u32;
	}

	return NULL;
}

#else
static inline struct fp_nfct_entry *
fp_nfct_lookup(uint8_t proto, uint32_t src, uint32_t dst,
               uint16_t sport, uint16_t dport, uint16_t vrfid, uint8_t *dir)
{
	return NULL;
}
#endif

#ifdef CONFIG_MCORE_NETFILTER_IPV6
/* secret number for IPv6 hash table */
#define FP_NF6CT_SECRET  0x19791123
#define FP_NF6CT_HASHTABLE_MASK (FP_NF6_CT_HASH_SIZE - 1)
static inline uint32_t fp_nf6ct_hash(struct fp_in6_addr *src,
                                     struct fp_in6_addr *dst,
                                     uint16_t sport, uint16_t dport,
                                     uint16_t vrfid, uint8_t proto)
{
	uint32_t a, b, c;

	a = src->fp_s6_addr32[0];
	b = src->fp_s6_addr32[1];
	c = src->fp_s6_addr32[2];

	a += FP_JHASH_GOLDEN_RATIO;
	b += FP_JHASH_GOLDEN_RATIO;
	c += FP_NF6CT_SECRET;

	fp_jhash_mix(a, b, c);

	a += src->fp_s6_addr32[3];
	b += dst->fp_s6_addr32[0];
	c += dst->fp_s6_addr32[1];

	fp_jhash_mix(a, b, c);

	a += dst->fp_s6_addr32[2];
	b += dst->fp_s6_addr32[3];
	c += sport;

	fp_jhash_mix(a, b, c);

	a += dport;
	b += vrfid;
	c += proto;

	fp_jhash_mix(a, b, c);

	return c & FP_NF6CT_HASHTABLE_MASK;
}

/* Assume that id is valid */
static inline struct fp_nf6ct_tuple_h *
fp_nf6ct_id_to_tuple(union fp_nfct_tuple_id id)
{
	return &fp_shared->fp_nf6_ct.fp_nf6ct[id.s.index].tuple[id.s.dir];
}

static inline struct fp_nf6ct_entry *
fp_nf6ct_tuple_to_entry(struct fp_nf6ct_tuple_h *tuple)
{
	return (struct fp_nf6ct_entry *)(tuple - tuple->dir);
}

/* We don't need to verify if the conntrack that we are checking is valid.
 * At worse, one packet will not be sent to the correct destination,
 * but the hash list and the tuple are always valid.
 */
static inline struct fp_nf6ct_entry *
fp_nf6ct_lookup(uint8_t proto, struct fp_in6_addr *src, struct fp_in6_addr *dst,
                uint16_t sport, uint16_t dport, uint16_t vrfid, uint8_t *dir)
{
	uint32_t hash = fp_nf6ct_hash(src, dst, sport, dport, vrfid, proto);
	union fp_nfct_tuple_id id = { .u32 = fp_shared->fp_nf6_ct.fp_nf6ct_hash[hash].u32 };
	struct fp_nf6ct_tuple_h *tuple;

	while (id.s.index != FP_NF6_CT_MAX) {
		tuple = fp_nf6ct_id_to_tuple(id);
		if (
#ifdef __FastPath__
		    /* we can use fpn_fast_memcmp() instead of memcmp() in FP */
		    !fpn_fast_memcmp(&tuple->src, src, sizeof(struct fp_in6_addr)) &&
		    !fpn_fast_memcmp(&tuple->dst, dst, sizeof(struct fp_in6_addr)) &&
#else
		    !memcmp(&tuple->src, src, sizeof(struct fp_in6_addr)) &&
		    !memcmp(&tuple->dst, dst, sizeof(struct fp_in6_addr)) &&
#endif
		    tuple->sport == sport &&
		    tuple->dport == dport &&
		    tuple->proto == proto
#ifdef CONFIG_MCORE_VRF
		    && tuple->vrfid == vrfid
#endif
		    ) {
			if (dir)
				*dir = tuple->dir;
			return fp_nf6ct_tuple_to_entry(tuple);
		}

		id.u32 = tuple->hash_next.u32;
	}

	return NULL;
}
#endif /* CONFIG_MCORE_NETFILTER_IPV6 */
#endif /* __FP_NFCT_H__ */
