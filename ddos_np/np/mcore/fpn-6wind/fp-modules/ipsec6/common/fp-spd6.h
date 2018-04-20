/*
 * Copyright(c) 2009 6WIND
 */

#ifndef __FP_SPD6_H__
#define __FP_SPD6_H__

#include "netinet/fp-in6.h"

/* Maximum number of SP entries for IPsec IPv6. */
#ifdef CONFIG_MCORE_IPSEC_IPV6_MAX_SP_ENTRIES
#define FP_MAX_IPV6_SP_ENTRIES (CONFIG_MCORE_IPSEC_IPV6_MAX_SP_ENTRIES + 1)
#else
#define FP_MAX_IPV6_SP_ENTRIES   2048
#endif

typedef struct fp_sp_entry __fpn_cache_aligned fp_v6_sp_entry_t;

#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
/* Order value for the per remote addr SP hashtable (the number of
 * buckets in the table is 2 ^ order). The maximum value is
 * theorically 32, but values > 16 (=65536 buckets) will consume more
 * memory without gain of speed. */
#ifndef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_ORDER
#define CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_ORDER 9
#endif

#define CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_SIZE (1 << CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_ORDER)
#define CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_MASK (CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_SIZE - 1)
#endif

#define FP_SPD_IN   0
#define FP_SPD_OUT  1

typedef struct fp_spd6 {
	/* number of global SPs */
	uint32_t global_sp_count;
	/* number of unhashed global SPs */
	uint32_t unhashed_sp_count;
#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
	/* number of hashed global SPs */
	uint32_t hashed_sp_count;
#endif
	/* number of entries in the SP table (global or SVTI) */
	uint32_t entry_count;
	/* SPD direction (IN/OUT) */
	uint32_t dir;
#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
	/* per remote addr SP hash table */
	fp_hlist_head_t addr_hash[CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_SIZE];
#endif
	fp_v6_sp_entry_t   table[FP_MAX_IPV6_SP_ENTRIES];
} __fpn_cache_aligned fp_spd6_t;


/* get head of SPD unhashed SPs */
static inline fp_hlist_head_t *fp_get_spd6_head(fp_spd6_t *spd6)
{
	return &spd6->table[0].head;
}

#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
/* 
 * Calculate the hash value based on the local and remote IPv6 addresses and vr.
 * loc_plen and rem_plen are the minimum prefix lengths of hashed policies.
 */
static inline uint16_t sp6_addrvr2hash(
	const uint32_t *plocal, const uint32_t *premote, uint16_t vr,
	uint8_t loc_plen, uint8_t rem_plen)
{
	uint32_t a, b, c;

	a = FP_JHASH_GOLDEN_RATIO + vr;
	b = 0;
	c = 0;

	while (loc_plen >= 32) {
		b += ntohl(*plocal);
		plocal++;
		loc_plen -= 32;
	}
	if (loc_plen)
		b += ntohl(*plocal) >> (32-loc_plen);

	while (rem_plen >= 32) {
		c += ntohl(*premote);
		premote++;
		rem_plen -= 32;
	}
	if (rem_plen)
		c += ntohl(*premote) >> (32-rem_plen);

	fp_jhash_mix(a, b, c);

	return c & CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_MASK;
}
#endif

#endif  /* __FP_SPD6_H__ */
