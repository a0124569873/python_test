/*
 * Copyright(c) 2009 6WIND, All rights reserved.
 */

#ifndef __FP_NETFILTER6_H__
#define __FP_NETFILTER6_H__

#include "fp-netfilter.h"

/* Maximum number of IPv6 netfilter rules in shared memory. */
#ifdef CONFIG_MCORE_NF6_MAXRULES
#define FP_NF6_MAXRULES CONFIG_MCORE_NF6_MAXRULES
#else
#define FP_NF6_MAXRULES               2048
#endif


struct fp_nf6rule {
	uint32_t uid;
	struct {
		uint8_t type;
		union {
			struct {
				int verdict;
			} standard;
#define FP_NF_ERRORNAME 0
#if FP_NF_ERRORNAME
			struct {
				char errorname[FP_NF_MAXNAMELEN];
			} error;
#endif
			struct {
				uint32_t mark;
				uint32_t mask;
			} mark;
			struct {
				uint8_t dscp;
			} dscp;
			struct {
#define FP_NF6_DEV_FLAG_SET_MARK      0x01
				uint32_t flags;
				uint32_t mark;
				uint32_t ifname_len;
				uint32_t ifname_hash;
				char ifname[FP_IFNAMSIZ];
			} dev;
		} data;
	} target;

	union {
		struct {
			struct fp_in6_addr src;                  /* Source IPv6 addr */
			struct fp_in6_addr dst;                  /* Destination IPv6 addr */
			struct fp_in6_addr smsk;                 /* Mask for src IPv6 addr */
			struct fp_in6_addr dmsk;                 /* Mask for dest IPv6 addr */
			char iniface[FP_IFNAMSIZ];
			uint8_t iniface_len;
			char outiface[FP_IFNAMSIZ];
			uint8_t outiface_len;
			uint16_t proto;                          /* Protocol, 0 = ANY */
			uint8_t tos;                             /* TOS to match iff flags & FP_NF_IPT_F_TOS */
#define FP_NF6_IPT_F_PROTO            0x01                       /* Set if rule cares about upper protocols */
#define FP_NF6_IPT_F_TOS              0x02                       /* Match the TOS. */
#define FP_NF6_IPT_F_GOTO             0x04                       /* Set if jump is a goto */
#define FP_NF6_IPT_F_MASK             0x07                       /* All possible flag bits mask. */
			uint8_t flags;
			uint8_t invflags;
		} ipv6;
	} l2;

	struct {
		uint8_t opt;
		uint8_t dscp;                                    /* DSCP word */
		uint8_t invdscp;                                 /* Inverse DSCP */
		uint16_t vrfid;                                  /* VRF ID */
		uint8_t rpf_flags;
		struct {
			uint32_t credit;
			uint32_t credit_cap;
			uint32_t cost;
			uint64_t prev;
		} rateinfo;

		struct {
			uint32_t ids[2];                                 /* Security Parameter Index */
			uint32_t hdrlen;                                 /* Header Length */
#define FP_IP6T_FRAG_IDS              0x01
#define FP_IP6T_FRAG_LEN              0x02
#define FP_IP6T_FRAG_RES              0x04
#define FP_IP6T_FRAG_FST              0x08
#define FP_IP6T_FRAG_MF               0x10
#define FP_IP6T_FRAG_NMF              0x20
			uint8_t	 flags;
#define FP_IP6T_FRAG_INV_IDS          0x01                               /* Invert the sense of ids. */
#define FP_IP6T_FRAG_INV_LEN          0x02                               /* Invert the sense of length. */
#define FP_IP6T_FRAG_INV_MASK         0x03                               /* All possible flags. */
			uint8_t  invflags;
		} frag;

		struct {
			uint32_t mark;
			uint32_t mask;
			uint8_t invert;
		} mark;
		struct {
			unsigned char srcaddr[6];
			int invert;
		} mac;
		struct {
			char    physindev[FP_IFNAMSIZ];
			uint8_t physindev_len;
			char    physoutdev[FP_IFNAMSIZ];
			uint8_t physoutdev_len;

#define FP_XT_PHYSDEV_OP_IN           0x01
#define FP_XT_PHYSDEV_OP_OUT          0x02
#define FP_XT_PHYSDEV_OP_BRIDGED      0x04
#define FP_XT_PHYSDEV_OP_ISIN         0x08
#define FP_XT_PHYSDEV_OP_ISOUT        0x10
#define FP_XT_PHYSDEV_OP_MASK         (0x20 - 1)
			uint8_t invert;
			uint8_t bitmask;
		} physdev;
	} l2_opt;

	struct {
		uint8_t type;
		union {
			struct {
				uint16_t spts[2];                /* Source port range. */
				uint16_t dpts[2];                /* Destination port range. */
				uint8_t invflags;
			} udp;

			struct {
				uint16_t spts[2];                /* Source port range. */
				uint16_t dpts[2];                /* Destination port range. */
				uint8_t option;                  /* TCP Option iff non-zero*/
				uint8_t flg_mask;                /* TCP flags mask byte */
				uint8_t flg_cmp;                 /* TCP flags compare byte */
				uint8_t invflags;
			} tcp;

			struct {
				uint16_t spts[2];
				uint16_t dpts[2];
				/* Bit mask of chunks to be matched according to RFC 2960 */
				uint32_t chunkmap[FP_NF_SCTP_CHUNKMAP_SIZE / (sizeof(uint32_t) * 8)];
				uint32_t chunk_match_type;
				struct {
					uint8_t chunktype;
					uint8_t flag;
					uint8_t flag_mask;
				} flag_info[FP_NF_IPT_NUM_SCTP_FLAGS];
				uint32_t flags;
				uint32_t invflags;
				uint8_t flag_count;
			} sctp;

			struct {
				uint8_t type;                    /* Type to match */
				uint8_t code[2];                 /* Range of code */
				uint8_t invflags;
			} icmp;
		} data;
		uint8_t state;                                   /* state of the flow */
	} l3;

	struct {
		u_int8_t opt;
		struct fp_nfrule_multiport multiport;
	} l3_opt;

	fp_nfrule_stats_t stats[FP_NF_STATS_NUM];
};

typedef struct fp_nf6table {
#ifdef CONFIG_MCORE_NF6TABLE_SEQNUM
	uint32_t          fpnf6table_seqnum;
#endif
	uint32_t          fpnf6table_rules_count;
	uint32_t          fpnf6table_valid_hooks;                   /* What hooks you will enter in */
	uint32_t          fpnf6table_hook_entry[FP_NF_IP_NUMHOOKS]; /* Hook entry points */
	uint32_t          fpnf6table_underflow[FP_NF_IP_NUMHOOKS];  /* Underflow points */
} fp_nf6table_t;

/* Fast Path tuple hash order for conntracks (IPv6). */
#ifdef CONFIG_MCORE_NF6_CT_HASH_ORDER
#define FP_NF6_CT_HASH_ORDER       CONFIG_MCORE_NF6_CT_HASH_ORDER
#else
#define FP_NF6_CT_HASH_ORDER       16
#endif
#define FP_NF6_CT_HASH_SIZE        (1 << FP_NF6_CT_HASH_ORDER)

/* Maximum number of conntrack entries in fastpath (IPv6). */
#ifdef CONFIG_MCORE_NF6_CT_MAX
#define FP_NF6_CT_MAX              CONFIG_MCORE_NF6_CT_MAX
#else
#define FP_NF6_CT_MAX              1024
#endif

struct fp_nf6ct_tuple_h {
	struct fp_in6_addr     src;
	struct fp_in6_addr     dst;
	uint16_t               sport;
	uint16_t               dport;
	uint16_t               vrfid;
	uint8_t                proto;
	uint8_t                dir;
	union fp_nfct_tuple_id hash_next;
};

struct fp_nf6ct_entry {
	struct fp_nf6ct_tuple_h tuple[FP_NF_IP_CT_DIR_MAX]; /* MUST BE the first field */
	union {
		uint32_t               next_available;
		uint32_t               uid;
	};
	uint8_t                 flag;
	struct fp_nfct_stats    counters[FP_NF_IP_CT_DIR_MAX];
};

typedef struct fp_nf6ct {
	uint32_t               fp_nf6ct_count;
	/* This is used to remember from where to start from when looking
	   for a free entry in conntrack table */
	uint32_t               next_ct6_available;
	union fp_nfct_tuple_id fp_nf6ct_hash[FP_NF6_CT_HASH_SIZE];
	struct fp_nf6ct_entry  fp_nf6ct[FP_NF6_CT_MAX];
} fp_nf6ct_t;

#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE
/* number of cache elements in fp_shared */
#ifdef CONFIG_MCORE_NF6_MAX_CACHE_ORDER
#define FP_NF6_MAX_CACHE_ORDER        CONFIG_MCORE_NF6_MAX_CACHE_ORDER
#else
#define FP_NF6_MAX_CACHE_ORDER        14
#endif

#define FP_NF6_MAX_CACHE_SIZE         (1 << FP_NF6_MAX_CACHE_ORDER)
#define FP_NF6_MAX_CACHE_MASK         (FP_NF6_MAX_CACHE_SIZE-1)

/* sizeof stored headers starting at IP layer, in bytes. The value is
 * defined in order to have sizeof(fp_nf6_rule_cache_entry_t) == 84 */
/* XXX: We might have to go to 96(=32+64) for performance improvements, to be teste
   In this case, FP_NF6_CACHED_HDR_LEN_32 would be 17.
 */
#define FP_NF6_CACHED_HDR_LEN_32     14  /* 14 words = 56 bytes */

/* This structure must be kept in sync with fp_nf_rule_cache_entry */
typedef struct fp_nf6_rule_cache_entry {
	uint32_t next;          /* next idx if chained (used in hash table) */
	uint8_t hdr_len32;      /* len of stored headers (in 32 bits words) */
	uint8_t hook_num;
	uint8_t table_num;
	uint8_t flags;          /* offset of this field MUST be keep in sync
	                           with fp_nf6_rule_cache_extended_entry_t */
	fpn_uintptr_t rule6 __attribute__ ((aligned(8))); /* associated rule, pointer is only valid in FP */
	uint32_t in_ifuid;    /* 0 if not available */
	uint32_t out_ifuid;   /* 0 if not available */

	uint16_t vrid;
	uint8_t ct_state;       /* conntrack state if needed */
	uint8_t state;          /* FREE or USED */

	uint32_t hdr[FP_NF6_CACHED_HDR_LEN_32]; /* store the masked packet */
} fp_nf6_rule_cache_entry_t;

#define FP_NF6_MAX_CACHED_RULES  ((((sizeof(fp_nf6_rule_cache_entry_t) - 8) / sizeof(fpn_uintptr_t))) + 1)
typedef struct fp_nf6_rule_cache_extended_entry {
	fp_nf6_rule_cache_entry_t base;
	uint8_t ext_pad[6];
	uint8_t ext_nbrules;
	uint8_t ext_flags;    /* this MUST have the same offset as in base structure */
	fpn_uintptr_t ext_rule6[FP_NF6_MAX_CACHED_RULES - 1];
} fp_nf6_rule_cache_extended_entry_t;

#endif /* CONFIG_MCORE_NETFILTER_IPV6_CACHE */
fp_nf6table_t *fp_nf6_str2table(const char *tblname);
uint8_t fp_nf6_table_id(const char *tblname);
int fp_nf6_dump_nftable(uint8_t table, uint16_t nf_vr, int mode);
int fp_nf6_print_summary(uint8_t table, uint16_t nf_vr);
#ifdef CONFIG_MCORE_NF6_CT
void fp_nf6_dump_nf6ct(uint32_t, int);
#endif
void fp_nf6ct_add_hash(uint32_t hash, union fp_nfct_tuple_id id);
void fp_nf6ct_del_hash(uint32_t hash, struct fp_nf6ct_tuple_h *tuple);
void fp_nf6ct_add_hash_uid(uint32_t hash, uint32_t index);
void fp_nf6ct_del_hash_uid(uint32_t hash, uint32_t index);
void fp_nf6_invalidate_cache(void);
void fp_nf6_update_nftable_stats(const fp_nf6table_t *cur_table,
				 const fp_nf6table_t *new_table);
void fp_nf6_relocate_tables(uint8_t table, uint16_t nf_vr, int delta);

static inline uint32_t fp_nf6_first_ruleid(const fp_nf6table_t *table)
{
	return table->fpnf6table_hook_entry[0];
}

static inline uint32_t fp_nf6_last_ruleid(const fp_nf6table_t *table)
{
	return table->fpnf6table_hook_entry[0] + table->fpnf6table_rules_count - 1;
}
#endif /* __FP_NETFILTER6_H__ */
