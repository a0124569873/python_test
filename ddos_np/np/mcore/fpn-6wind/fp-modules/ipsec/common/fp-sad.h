/*
 * Copyright(c) 2006 6WIND
 */

#ifndef __FP_SAD_H__
#define __FP_SAD_H__

/* To enable hash lookup on incoming packets */
#define IPSEC_SPI_HASH  1

/* Maximum number of SP entries for IPsec IPv4 */
#ifdef CONFIG_MCORE_IPSEC_MAX_SA_ENTRIES
#define FP_MAX_SA_ENTRIES      (CONFIG_MCORE_IPSEC_MAX_SA_ENTRIES + 1)
#else
#define FP_MAX_SA_ENTRIES      4096
#endif

/*
 * IPsec SA hash table order (the number of buckets in each hash table is
 * 2^order). The default value is 16, which corresponds to 65536 buckets
 * in the hash table
 */
#if defined(CONFIG_MCORE_IPSEC_SA_HASH_ORDER) && CONFIG_MCORE_IPSEC_SA_HASH_ORDER <= 16
#define FP_SA_HASH_ORDER         CONFIG_MCORE_IPSEC_SA_HASH_ORDER
#else
#define FP_SA_HASH_ORDER         16
#endif

/* depends on FP_SA_HASH_ORDER */
#define FP_SAD_HASH_SIZE          (1 << FP_SA_HASH_ORDER)
#define FP_SAD_HASH_MASK          (FP_SAD_HASH_SIZE -1)

typedef struct fp_sa_ah_algo {
	uint16_t	hashsize;
	uint16_t	authsize;
} fp_sa_ah_algo_t;

typedef struct fp_sa_esp_algo {
	uint16_t	blocksize;
	uint16_t	ivlen;
	uint16_t	saltsize; /* size of salt prepended to IV to form a nonce */
	uint16_t	authsize; /* ICV size for AEAD algorithms */
} fp_sa_esp_algo_t;

/* Note: maximum supported window size is 4096 packets */
#define FP_SECREPLAY_ESN_MAX 4096
#define FP_SECREPLAY_ESN_WORDS ((FP_SECREPLAY_ESN_MAX + 31) / 32)

typedef struct secreplay {
	/* input */
	uint64_t seq;
	uint32_t wsize;
	/* output */
	/* last sync'd seq number */
	uint32_t last_sync;
	uint64_t oseq;
	uint32_t bmp[FP_SECREPLAY_ESN_WORDS];
} fp_secreplay_t;

#define FP_SA_STATE_UNSPEC      0
#define FP_SA_STATE_ACTIVE      1
/* Acquire in progress, this is a temporary SA */
#define FP_SA_STATE_ACQUIRE     2

#define FP_SA_STATE_NOT_SYNCD   0
#define FP_SA_STATE_SYNC_RECVD  1

#define FP_SA_FLAG_ESN          0x1
#define FP_SA_FLAG_UDPTUNNEL    0x2
#define FP_SA_FLAG_DONT_ENCAPDSCP  0x4
#define FP_SA_FLAG_DECAPDSCP    0x8
#define FP_SA_FLAG_NOPMTUDISC   0x10
#define FP_SA_FLAG_LIFETIME     0x20

/* No limit */
#define FP_SA_LIMIT_INF         (~(uint64_t)0)

/* netfpc message for replay window merge */
typedef struct fp_replaywin_msg {
	uint32_t dst;       /* destination addr */
	uint32_t spi;       /* SPI */
	uint8_t  proto;     /* AH, ESP */
	uint8_t  rsvd;
	uint16_t vrfid;     /* vrfid */
	uint64_t oseq;      /* last output seq number */
	uint64_t seq;       /* highest received seq number */
	uint32_t bmp_len;   /* replay window size in words */
	uint32_t bmp[];     /* replay window bitmap */
} __attribute__((packed)) fp_replaywin_msg_t;

/* Force sync replay window header */
typedef struct fp_replaywin_sync_header {
	uint8_t  src_blade_id;   /* blade id of sender */
	uint8_t  version;        /* message version */
	uint16_t request_count;  /* count of SAs to be sync'ed */
} __attribute__((packed)) fp_replaywin_sync_header_t;

#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
typedef struct fp_sa_lifetime_s {
	uint64_t        nb_bytes;    /* SA bytes limit */
	uint64_t        nb_packets;  /* SA packets limit */
} fp_sa_lifetime_t;
#endif /* CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT */

typedef struct fp_sa_entry {
	uint16_t        state;             /* 0 means unspecified */
	uint16_t        ivlen;             /* IV length */
	uint32_t        spd_index;         /* link to SP */

	uint16_t        blocksize;         /* crypto block size */
	uint16_t        authsize;          /* ICV size */
	uint16_t        ahsize;            /* AH header + payload size */
	uint8_t         ah_len;            /* AH header ah_len field */
	uint8_t         counter;           /* counter */

	uint32_t        index;             /* SA index in table */
	uint32_t        spi;               /* SPI, network order */

	union {
		uint32_t        dst4;	   /* IP destination */
#ifdef CONFIG_MCORE_IPSEC_IPV6
		fp_in6_addr_t   dst6;	   /* IPv6 destination */
#endif
        };
        union {
		uint32_t        src4;	   /* IP source */
#ifdef CONFIG_MCORE_IPSEC_IPV6
		fp_in6_addr_t   src6;	   /* IPv6 source */
#endif
        };

	uint8_t         flags;
	uint8_t         proto;             /* AH, ESP */
	uint8_t         mode;              /* transport, tunnel */
	uint8_t         alg_auth;
	uint16_t        key_enc_len;
	uint8_t         alg_enc;
	uint8_t         output_blade;      /* SA output blade */

	uint32_t        svti_ifuid;        /* SVTI interface ifuid */
	uint16_t        dport;             /* dest port for UDP header (NAT-T) */
	uint16_t        sport;             /* src port for UDP header (NAT-T) */

	uint16_t        vrfid;             /* vrfid */
	uint16_t        xvrfid;            /* x-vrfid */
	uint32_t        reqid;

	uint16_t        saltsize;          /* Salt size */
	uint16_t        reserved1;
	uint32_t        reserved2;

#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
	uint32_t        svti_idx;          /* cached index in svti table */
	uint32_t        svti_genid;        /* generation id of cached entry */
#endif /* CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA */

	fp_secreplay_t  replay;            /* seq counter, 16 bytes */

	char            key_enc[FP_MAX_KEY_ENC_LENGTH];
	char            key_auth[FP_MAX_KEY_AUTH_LENGTH];

#ifndef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	char            opad[FP_MAX_HASH_BLOCK_SIZE];
	char            ipad[FP_MAX_HASH_BLOCK_SIZE];
#endif

#ifdef CONFIG_MCORE_MULTIBLADE
	uint32_t        sync_state;
#endif
	fp_sa_stats_t   stats[FP_IPSEC_STATS_NUM];

	uint32_t        genid;            /* generation ID */

	/* per selector SA hash table chaining */
	/* selector = {src, dst, protocol, vrfid} */
	fp_hlist_node_t selector_hlist;
#if defined(IPSEC_SPI_HASH) || defined(IPSEC_IPV6_SPI_HASH)
	/* per spi SA hash table chaining */
	fp_hlist_node_t spi_hlist;
#endif

#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
	fp_sa_lifetime_t soft;  /* SA soft limits */
	fp_sa_lifetime_t hard;  /* SA hard limits */
#endif /* CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT */
} __fpn_cache_aligned fp_sa_entry_t;

typedef struct fp_sad {
	uint32_t	count;
	/* per selector SA hash table */
	fp_hlist_head_t	selector_hash[FP_SAD_HASH_SIZE];
#ifdef IPSEC_SPI_HASH
	/* per spi SA hash table */
	fp_hlist_head_t	spi_hash[FP_SAD_HASH_SIZE];
#endif
	fp_sa_entry_t	table[FP_MAX_SA_ENTRIES];
} __fpn_cache_aligned fp_sad_t;

/* HASH functions */
#ifdef IPSEC_SPI_HASH
static inline void sa_init_hash(fp_sad_t *sad)
{
	memset(sad->spi_hash, 0, sizeof(sad->spi_hash));
}

static inline uint16_t sa_spi2hash(uint32_t spi)
{
	return (spi ^ (spi>>16)) & FP_SAD_HASH_MASK;
}

static inline void sa_hash(fp_sad_t *sad, uint32_t i)
{
	uint16_t h;

	h = sa_spi2hash(sad->table[i].spi);
	fp_hlist_add_head(&sad->spi_hash[h], sad->table, i, spi_hlist);
}

static inline void sa_unhash(fp_sad_t *sad, uint32_t i)
{
	uint16_t h;

	h = sa_spi2hash(sad->table[i].spi);
	fp_hlist_remove(&sad->spi_hash[h], sad->table, i, spi_hlist);
}
#endif

#ifdef IPSEC_SPI_HASH
static inline uint32_t __fp_sa_get(fp_sad_t *sad, uint32_t spi, uint32_t dst,
		uint8_t proto, uint16_t vrfid)
{
	uint32_t i;

	/* empty table? */
	if (sad->count == 0)
		return 0;

	/* find hash line */
	i = fp_hlist_first(&sad->spi_hash[sa_spi2hash(spi)]);

	/* best case: first hash entry matches triplet and vrfid */
	if (likely((i != 0) &&
		   (sad->table[i].vrfid == vrfid) &&
	           (sad->table[i].spi == spi) &&
	           (sad->table[i].dst4 == dst) &&
	           (sad->table[i].proto == proto)))
	{
		if (likely(sad->table[i].state != FP_SA_STATE_UNSPEC))
			return i;
		else
			return 0;
	}

	/* empty list? */
	if (i == 0)
		return 0;

	/* bad luck, follow hash list */
	fp_hlist_for_each_continue(i, head, sad->table, spi_hlist) {
		if ((sad->table[i].vrfid == vrfid) &&
		    (sad->table[i].spi == spi) &&
		    (sad->table[i].dst4 == dst) &&
		    (sad->table[i].proto == proto))
		{
			if (likely(sad->table[i].state != FP_SA_STATE_UNSPEC))
				return i;
			else
				return 0;
		}
	}

	/* not found */
	return 0;

}
#else
/* Used by FPM */
/* return SA(spi, dst, proto) or 0. */
static inline uint32_t __fp_sa_get(fp_sad_t  *sad,  uint32_t spi, uint32_t dst, 
		uint8_t proto, uint16_t vrfid)
{
	uint32_t i;
	uint32_t count = sad->count;
	for (i = 1; count > 0 && i < FP_MAX_SA_ENTRIES; i++) {
		if (sad->table[i].state == FP_SA_STATE_UNSPEC)
			continue;
		count--;
		if (sad->table[i].vrfid != vrfid)
			continue;
		if (sad->table[i].spi != spi)
			continue;
		if (sad->table[i].proto != proto)
			continue;
		if (sad->table[i].dst != dst)
			continue;
		return i; /* found */
	}

	return 0;
}
#endif


/* hash functions based on selectors */
static inline void sa_init_selector_hash(fp_sad_t *sad)
{
	memset(sad->selector_hash, 0, sizeof(sad->selector_hash));
}

static inline uint16_t __sa_selector2hash(uint32_t src, uint32_t dst, uint16_t proto,
				    uint16_t vrfid, uint16_t xvrfid)
{
	union {
		uint16_t u16[4];
		uint32_t u32[2];
		uint64_t u64;
	} hash;

	/* simply add all parameters and fold the sum to a half-word */
	hash.u64 = src + dst + proto + vrfid + xvrfid;
	hash.u32[0] = hash.u32[0] + hash.u32[1];
	hash.u32[0] = hash.u16[0] + hash.u16[1];

	return (hash.u16[0] + hash.u16[1]) & FP_SAD_HASH_MASK;
}

static inline void sa_selector_hash(fp_sad_t *sad, uint32_t i)
{
	uint16_t h;

	h = __sa_selector2hash(sad->table[i].src4,  sad->table[i].dst4,
			       sad->table[i].proto, sad->table[i].vrfid,
			       sad->table[i].xvrfid);
	fp_hlist_add_head(&sad->selector_hash[h], sad->table, i, selector_hlist);
}

static inline void sa_selector_unhash(fp_sad_t *sad, uint32_t i)
{
	uint16_t h;

	h = __sa_selector2hash(sad->table[i].src4,  sad->table[i].dst4,
			       sad->table[i].proto, sad->table[i].vrfid,
			       sad->table[i].xvrfid);
	fp_hlist_remove(&sad->selector_hash[h], sad->table, i, selector_hlist);
}

static inline void __fp_sa_del(fp_sad_t *sad, uint32_t i)
{
	sa_selector_unhash(sad, i);
#ifdef IPSEC_SPI_HASH
	sa_unhash(sad, i);
#endif
	sad->table[i].state = FP_SA_STATE_UNSPEC;
}

#endif /* __FP_SAD_H__ */
