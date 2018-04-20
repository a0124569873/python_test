/*
 * Copyright(c) 2006 6WIND
 */

#ifndef __FP_SPD_H__
#define __FP_SPD_H__

#include "fp-hlist.h"
#include "fp-jhash.h"

/* Maximum number of SP entries for IPsec IPv4. */
#ifdef CONFIG_MCORE_IPSEC_MAX_SP_ENTRIES
#define	FP_MAX_SP_ENTRIES (CONFIG_MCORE_IPSEC_MAX_SP_ENTRIES + 1)
#else
#define	FP_MAX_SP_ENTRIES 2048
#endif

#include "filter.h"

typedef struct fp_sp_entry {
	struct FILTER filter;
#define FP_SP_ACTION_BYPASS      0
#define FP_SP_ACTION_DISCARD     1
#define FP_SP_ACTION_PROTECT     2

	uint32_t	sa_index;    /* cached SA */
	uint32_t	sa_genid;    /* cached SA genid */

	uint8_t	state;
#define FP_SP_STATE_UNSPEC       0
#define FP_SP_STATE_ACTIVE       1
	uint8_t	flags;
#define FP_SP_FLAG_LEVEL_USE     0x01  /* protect level use (bypass if no SA) */
#define FP_SP_FLAG_NO_SA_CACHE   0x02  /* Do not cache SA, use selectors hash lookup, say for SAs of transport mode with network addresses */
#define FP_SP_FLAG_HASHED        0x04  /* hashed in SPD hash table */
	uint8_t         mode:1;
	uint8_t         outer_family:7; /* save transform address family, AF_INET or AF_INET6 */
	uint8_t		sa_proto;  /* ESP ou AH */

	union {
		uint32_t	tunnel4_src;
#ifdef CONFIG_MCORE_IPSEC_IPV6
		fp_in6_addr_t	tunnel6_src;
#endif
	};
	union {
		uint32_t	tunnel4_dst;
#ifdef CONFIG_MCORE_IPSEC_IPV6
		fp_in6_addr_t	tunnel6_dst;
#endif
	};

	uint32_t	rule_index; /* slow path index */

	uint32_t	vrfid;
	uint32_t	link_vrfid;

	uint32_t	svti_ifuid;

	uint32_t	reqid;

	fp_sp_stats_t   stats[FP_IPSEC_STATS_NUM];

	/* SP main chaining (ordered by priority) */
	union {
		fp_hlist_node_t list;
		fp_hlist_head_t head;
#if defined(CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE) || defined(CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE)
		fp_hlist_node_t addr_hlist;
#endif
	};

#if defined(CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE) || defined(CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE)
	uint16_t hash;
	uint16_t pad;
#endif

} __fpn_cache_aligned fp_sp_entry_t;

#if defined(CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE) || defined(CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE)
/* Order value for the per remote addr SP hashtable (the number of
 * buckets in the table is 2 ^ order). The maximum value is
 * theorically 32, but values > 16 (=65536 buckets) will consume more
 * memory without gain of speed. */
#  ifndef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_ORDER
#    define CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_ORDER 9
#  endif
#  define CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_SIZE (1 << CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_ORDER)
#  define CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_MASK (CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_SIZE - 1)
#endif

#define FP_SPD_IN   0
#define FP_SPD_OUT  1

typedef struct fp_spd {
	/* number of global SPs */
	uint32_t global_sp_count;
	/* number of unhashed global SPs */
	uint32_t unhashed_sp_count;
#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
	/* number of hashed global SPs */
	uint32_t hashed_sp_count;
#endif
	/* number of entries in the SP table (global or SVTI) */
	uint32_t entry_count;
	/* SPD direction (IN/OUT) */
	uint32_t dir;
#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
	/* per remote addr SP hash table */
	fp_hlist_head_t addr_hash[CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_SIZE];
#endif
	fp_sp_entry_t table[FP_MAX_SP_ENTRIES];
} __fpn_cache_aligned fp_spd_t;

/* get head of SPD unhashed SPs */
static inline fp_hlist_head_t *fp_get_spd_head(fp_spd_t *spd)
{
	return &spd->table[0].head;
}

#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
/* 
 * Calculate the hash value based on the local and remote addresses and vr.
 * loc_plen and rem_plen are the minimum prefix lengths of hashed policies.
 */
static inline uint16_t sp_addrvr2hash(
	uint32_t local, uint32_t remote, uint16_t vr,
	uint8_t loc_plen, uint8_t rem_plen)
{
	uint32_t a, b, c;

	a = FP_JHASH_GOLDEN_RATIO + vr;
	b = loc_plen ? ntohl(local) >> (32-loc_plen) : 0;
	c = rem_plen ? ntohl(remote) >> (32-rem_plen) : 0;

	fp_jhash_mix(a, b, c);
	
	return c & CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_MASK;
}
#endif

#endif /* __FP_SPD_H__ */
