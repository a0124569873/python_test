/*
 * Copyright(c) 2006 6WIND
 */
#ifndef __FP_IPSEC_H__
#define __FP_IPSEC_H__

#define FP_IPSEC_MODE_TRANSPORT  0
#define FP_IPSEC_MODE_TUNNEL     1

#ifdef CONFIG_MCORE_IPSEC_TRIE
typedef struct ipsec_trie_zone {
	fpn_uintptr_t start;
	uint64_t size;
} __fpn_cache_aligned fp_ipsec_trie_zone_t;

FPN_DECLARE_SHARED(fp_ipsec_trie_zone_t, ipsec_tries[3]);
#ifndef CONFIG_MCORE_IPSEC_TRIE_ZONE_SIZE
#define CONFIG_MCORE_IPSEC_TRIE_ZONE_SIZE   (30 << 20)
#endif

int fp_ipsec_trie_init(void);
int fp_ipsec_trie_exit(void);

typedef struct fp_ipsec_trie {
	uint64_t spd_version:16;    /* SPD version claimed by FPM */
	uint64_t trie_version:16;   /* SPD version when the trie was built */
	uint64_t threshold:16;      /* threshold to activate trie lookup */
	uint64_t building:1;        /* updating in progress */
	uint64_t running:1;         /* trie can be used */
	uint64_t index:2;           /* index of the trie memory area */
	uint64_t unused:12;

	fpn_uintptr_t ctx; /* to store trie handles */
} fp_trie_t;

/* switch from linear search to trie lookup when number of rules >= threshold */
#ifndef CONFIG_MCORE_IPSEC_TRIE_OUT_DEFAULT_THRESHOLD
#define CONFIG_MCORE_IPSEC_TRIE_OUT_DEFAULT_THRESHOLD  49
#endif
#ifndef CONFIG_MCORE_IPSEC_TRIE_IN_DEFAULT_THRESHOLD
#define CONFIG_MCORE_IPSEC_TRIE_IN_DEFAULT_THRESHOLD  49
#endif
#endif	/* CONFIG_MCORE_IPSEC_TRIE */

/* global statistics */
typedef struct fp_ipsec_stats {
	uint64_t ipsec_no_sa;           /* SA not found */
#if 0 /* not used: default policy is bypass */
	uint64_t PolicyDiscards;        /* packets did not match policy and 
					   discard */
#endif
} fp_ipsec_stats_t;

typedef struct fp_ipsec_sp_stats {
	uint64_t sp_packets;            /* packets */
	uint64_t sp_bytes;              /* bytes */
	uint64_t sp_exceptions;         /* SP exceptions */
	uint64_t sp_errors;             /* policy mismatch */
} __fpn_cache_aligned fp_sp_stats_t;

typedef struct fp_ipsec_sa_stats {
	uint64_t sa_packets;            /* packets */
	uint64_t sa_bytes;              /* bytes */
	uint64_t sa_auth_errors;
	uint64_t sa_decrypt_errors;     /* decrypt errors */
	uint64_t sa_replay_errors;      /* replay errors */
	uint64_t sa_selector_errors;    /* SPD mismatch */
} __fpn_cache_aligned fp_sa_stats_t;

#ifdef FP_IPSEC_STATS_PER_CORE
#define FP_IPSEC_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_IPSEC_STATS_DEC(st, field)          FP_STATS_PERCORE_DEC(st, field)
#define FP_IPSEC_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FP_IPSEC_STATS_SUB(st, field, val)     FP_STATS_PERCORE_SUB(st, field, val)
#define FP_IPSEC_STATS_NUM                     FPN_MAX_CORES
#else
#define FP_IPSEC_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FP_IPSEC_STATS_DEC(st, field)          FP_STATS_DEC(st, field)
#define FP_IPSEC_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FP_IPSEC_STATS_SUB(st, field, val)     FP_STATS_SUB(st, field, val)
#define FP_IPSEC_STATS_NUM                     1
#endif


#include "fp-sad.h"
#ifndef CONFIG_MCORE_FPN_CRYPTO_ASYNC
typedef struct fp_ipsec_ctx_s {
	uint32_t	proto;
	uint32_t	auth_type;
	uint32_t	authsize;
	char		*auth_data;
	char 		padbuf[FP_MAX_KEY_ENC_LENGTH + 2 /* pad length + next header */ + FP_MAX_KEY_AUTH_LENGTH];
} __fpn_cache_aligned fp_ipsec_ctx_t;

FPN_DECLARE_PER_CORE(fp_ipsec_ctx_t, fp_ipsec_context);
#define fp_ipsec_ctx FPN_PER_CORE_VAR(fp_ipsec_context)
#endif

#include "fp-spd.h"
#ifdef CONFIG_MCORE_IPSEC_SVTI
#include "fp-svti.h"
#endif

typedef struct fp_ipsec {
	fp_sad_t               sad;
	fp_spd_t               spd_in;
	fp_spd_t               spd_out;
#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
	/* SPD hash lookup minimum prefix lengths */
	uint8_t                spd_hash_loc_plen;
	uint8_t                spd_hash_rem_plen;
	uint8_t                padding[2];
#endif
	fp_ipsec_stats_t       ipsec_stats[FP_MAX_VR][FP_IPSEC_STATS_NUM];
#ifdef CONFIG_MCORE_IPSEC_TRIE
	/* 
	 * There are 3 trie memory areas, ipsec_tries[3]
	 * one for the output trie, one for the input trie,
	 * and an additional one used to build the output/input trie
	 * These areas are used in turn
	 * trie_inactive_index = 3 - trie_out.index - trie_in.index;
	 */
	uint32_t               trie_to_update;
#define IPSEC_TRIE_OUT 0
#define IPSEC_TRIE_IN  1
	fp_trie_t              trie_out; /* for outbound SPD */
	fp_trie_t              trie_in;  /* for inbound SPD */
#endif /* CONFIG_MCORE_IPSEC_TRIE */
#ifdef CONFIG_MCORE_MULTIBLADE
	uint32_t               sa_replay_sync_threshold;
#endif
	uint8_t                output_blade;
} fp_ipsec_t;

void fp_ipsec_init(void);
int fp_sp_add(fp_spd_t *spd, fp_sp_entry_t *user_sp);
int fp_sp_update(fp_spd_t *spd, fp_sp_entry_t *user_sp);
int fp_sp_del(fp_spd_t *spd, fp_sp_entry_t *user_sp);
int fp_sp_del_by_index(fp_spd_t *spd, uint32_t idx);
void __fp_sp_del(fp_spd_t *spd, uint32_t idx);
int fp_sa_add(fp_sad_t *sad, fp_sa_entry_t *user_sa);
int fp_sa_del(fp_sad_t *sad, fp_sa_entry_t *user_sa);
int fp_sa_del_by_index(fp_sad_t *sad, uint32_t i);
int fp_sp_flush_by_vrfid(fp_spd_t *spd, uint16_t vrfid);
int fp_sa_flush(fp_sad_t *sad);
int fp_sa_flush_by_vrfid(fp_sad_t *sad, uint16_t vrfid);
void fp_spd_out_commit(void);
void fp_spd_in_commit(void);
#ifdef CONFIG_MCORE_IPSEC_TRIE
void fp_spd_trie_out_commit(void);
void fp_spd_trie_in_commit(void);
#endif
uint32_t fp_sad_find_acq(uint32_t src, uint32_t dst, uint16_t proto,
				 uint8_t mode, uint32_t reqid,
				 uint16_t vrfid, uint16_t xvrfid
#ifdef CONFIG_MCORE_IPSEC_SVTI
				 , uint32_t svti_ifuid
#endif
				 );

void     fp_ipsec_index_init(void);
void     fp_ipsec_index_rebuild(void);
uint32_t fp_sa_get_index(void);
void     fp_sa_release_index(uint32_t index);
uint32_t fp_sp_get_index(fp_spd_t *spd);
void     fp_sp_release_index(fp_spd_t *spd, uint32_t index);
uint32_t fp_set_spd_conf(uint16_t hash_min_preflen_local, uint16_t hash_min_preflen_remote);

#endif
