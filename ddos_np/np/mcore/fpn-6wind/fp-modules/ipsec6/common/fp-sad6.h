/*
 * Copyright(c) 2009 6WIND
 */

#ifndef __FP_SAD6_H__
#define __FP_SAD6_H__

#include "netinet/fp-in6.h"

/* To enable hash lookup on incoming packets */
#define IPSEC_IPV6_SPI_HASH  1

/* Maximum number of SA entries for IPsec IPv6 */
#ifdef CONFIG_MCORE_IPSEC_IPV6_MAX_SA_ENTRIES
#define FP_MAX_IPV6_SA_ENTRIES (CONFIG_MCORE_IPSEC_IPV6_MAX_SA_ENTRIES + 1)
#else
#define FP_MAX_IPV6_SA_ENTRIES 4096
#endif

/*
 * IPv6 SA hash table order (the number of buckets in each table is
 * 2^order). The default value is 16, which corresponds to 65536 buckets
 * in the hash table
 */
#if defined(CONFIG_MCORE_IPSEC_IPV6_SA_HASH_ORDER) && CONFIG_MCORE_IPSEC_IPV6_SA_HASH_ORDER <= 16
#define FP_IPV6_SA_HASH_ORDER         CONFIG_MCORE_IPSEC_IPV6_SA_HASH_ORDER
#else
#define FP_IPV6_SA_HASH_ORDER         16
#endif

/* depends on FP_IPV6_SA_HASH_ORDER */
#define FP_IPV6_SAD_HASH_SIZE          (1 << FP_IPV6_SA_HASH_ORDER)
#define FP_IPV6_SAD_HASH_MASK          (FP_IPV6_SAD_HASH_SIZE -1)

typedef struct fp_replaywin6_msg {
	fp_in6_addr_t dst;  /* destination addr */
	uint32_t spi;       /* SPI */
	uint8_t  proto;     /* AH, ESP */
	uint8_t  rsvd;
	uint16_t vrfid;     /* vrfid */
	uint64_t oseq;      /* last output seq number */
	uint64_t seq;       /* highest received seq number */
	uint32_t bmp_len;   /* replay window size in words */
	uint32_t bmp[];     /* replay window bitmap */
} __attribute__((packed)) fp_replaywin6_msg_t;


typedef struct fp_sa_entry __fpn_cache_aligned fp_v6_sa_entry_t;

typedef struct fp_sad6 {
	uint32_t count;

	/* per selector hash table */
	fp_hlist_head_t selector_hash[FP_IPV6_SAD_HASH_SIZE];
#ifdef IPSEC_IPV6_SPI_HASH
	/* per spi SA hash table */
	fp_hlist_head_t spi_hash[FP_IPV6_SAD_HASH_SIZE];
#endif
	fp_v6_sa_entry_t table[FP_MAX_IPV6_SA_ENTRIES];
} __fpn_cache_aligned fp_sad6_t;

/* HASH functions */
#ifdef IPSEC_IPV6_SPI_HASH
static inline void sa6_init_hash(fp_sad6_t *sad)
{
	memset(sad->spi_hash, 0, sizeof(sad->spi_hash));
}

static inline uint16_t sa6_spi2hash(uint32_t spi)
{
	return (spi ^ (spi>>16)) & FP_IPV6_SAD_HASH_MASK;
}

static inline void sa6_hash(fp_sad6_t *sad, uint32_t i)
{
	uint16_t h;

	h = sa6_spi2hash(sad->table[i].spi);
	fp_hlist_add_head(&sad->spi_hash[h], sad->table, i, spi_hlist);
}

static inline void sa6_unhash(fp_sad6_t *sad, uint32_t i)
{
	uint16_t h;

	h = sa6_spi2hash(sad->table[i].spi);
	fp_hlist_remove(&sad->spi_hash[h], sad->table, i, spi_hlist);
}
#endif

#ifdef IPSEC_IPV6_SPI_HASH
static inline uint32_t __fp_v6_sa_get(fp_sad6_t *sad, uint32_t spi, uint8_t *dst,
		uint8_t proto, uint16_t vrfid)
{
	uint32_t i;
	fp_hlist_head_t *head;

	/* empty table? */
	if (sad->count == 0)
		return 0;

	/* find per spi hash line */
	head = &sad->spi_hash[sa6_spi2hash(spi)];
	i = fp_hlist_first(head);

	/* best case: first hash entry matches triplet and vrfid */
	if (likely((i != 0) &&
		   (sad->table[i].vrfid == vrfid) &&
	           (sad->table[i].spi == spi) && 
		   (memcmp(sad->table[i].dst6.fp_s6_addr, dst, sizeof(fp_in6_addr_t)) == 0) &&
	           (sad->table[i].proto == proto)))
	{
		if (likely(sad->table[i].state != FP_SA_STATE_UNSPEC))
			return i;
	}

	/* empty list? */
	if (i == 0)
		return 0;

	/* bad luck, follow hash list */
	fp_hlist_for_each_continue(i, head, sad->table, spi_hlist) {
		if ((sad->table[i].vrfid == vrfid) &&
		    (sad->table[i].spi == spi) &&
		    (memcmp(sad->table[i].dst6.fp_s6_addr, dst, sizeof(fp_in6_addr_t)) == 0) &&
		    (sad->table[i].proto == proto))
		{
			if (likely(sad->table[i].state != FP_SA_STATE_UNSPEC))
				return i;
		}
	}

	/* not found */
	return 0;

}
#else
/* Used by FPM */
/* return SA(spi, dst, proto) or 0. */
static inline uint32_t __fp_v6_sa_get(fp_sad6_t  *sad6,  uint32_t spi, uint8_t *dst6, 
		uint8_t proto, uint16_t vrfid)
{
	uint32_t i;
	uint32_t count = sad6->count;
	for (i = 1; count > 0 && i < FP_MAX_IPV6_SA_ENTRIES; i++) {
		if (sad6->table[i].state == FP_SA_STATE_UNSPEC)
			continue;
		count--;
		if (sad6->table[i].vrfid != vrfid)
			continue;
		if (sad6->table[i].spi != spi)
			continue;
		if (sad6->table[i].proto != proto)
			continue;
		if (memcmp(&sad6->table[i].dst, dst6, sizeof(sad6->table[i].dst)))
			continue;
		return i; /* found */
	}

	return 0;
}

#endif	/* CONFIG_MCORE_IPSEC_IPV6_SPI_HASH */


/* hash functions based on selectors */
static inline void sa6_init_selector_hash(fp_sad6_t *sad)
{
	memset(sad->selector_hash, 0, sizeof(sad->selector_hash));
}

static inline uint16_t __sa6_selector2hash(uint32_t *src, uint32_t *dst,
		uint16_t proto, uint16_t vrfid, uint16_t xvrfid)
{
	union {
		uint16_t u16[4];
		uint32_t u32[2];
		uint64_t u64;
	} hash;

	/* simply add all parameters and fold the sum to a half-word */
	hash.u64 = proto + vrfid + xvrfid + src[0] + src[1] + src[2] + src[3] + dst[0] + dst[1] + dst[2] + dst[3];
	hash.u32[0] = hash.u32[0] + hash.u32[1];
	hash.u32[0] = hash.u16[0] + hash.u16[1];

	return (hash.u16[0] + hash.u16[1]) & FP_IPV6_SAD_HASH_MASK;
}

static inline void sa6_selector_hash(fp_sad6_t *sad, uint32_t i)
{
	uint16_t h;

	h = __sa6_selector2hash(sad->table[i].src6.fp_s6_addr32, sad->table[i].dst6.fp_s6_addr32,
				 sad->table[i].proto, sad->table[i].vrfid, sad->table[i].xvrfid);
	fp_hlist_add_head(&sad->selector_hash[h], sad->table, i, selector_hlist);
}

static inline void sa6_selector_unhash(fp_sad6_t *sad, uint32_t i)
{
	uint16_t h;

	h = __sa6_selector2hash(sad->table[i].src6.fp_s6_addr32, sad->table[i].dst6.fp_s6_addr32,
				 sad->table[i].proto, sad->table[i].vrfid, sad->table[i].xvrfid);
	fp_hlist_remove(&sad->selector_hash[h], sad->table, i, selector_hlist);
}

static inline void __fp_v6_sa_del(fp_sad6_t *sad6, uint32_t i)
{
	sa6_selector_unhash(sad6, i);
#ifdef IPSEC_IPV6_SPI_HASH
	sa6_unhash(sad6, i);
#endif
	sad6->table[i].state = FP_SA_STATE_UNSPEC;
}
#endif  /* __FP_SAD6_H__ */
