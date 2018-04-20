/*
 * Copyright(c) 2009 6WIND
 */
#ifndef __FP_IPSEC6_H__
#define __FP_IPSEC6_H__

#define FP_IPSEC_MODE_TRANSPORT  0
#define FP_IPSEC_MODE_TUNNEL     1

/* global statistics */
typedef struct fp_ipsec6_stats {
	uint64_t ipsec6_no_sa;           /* SA not found */
#if 0 /* not used: default policy is bypass */
	uint64_t PolicyDiscards;        /* packets did not match policy and 
					   discard */
#endif
} fp_ipsec6_stats_t;

typedef struct fp_ipsec6_sp_stats {
	uint64_t sp_packets;            /* packets */
	uint64_t sp_bytes;              /* bytes */
	uint64_t sp_exceptions;         /* SP exceptions */
	uint64_t sp_errors;             /* policy mismatch */
} __fpn_cache_aligned fp_v6_sp_stats_t;

typedef struct fp_ipsec6_sa_stats {
	uint64_t sa_packets;            /* packets */
	uint64_t sa_bytes;              /* bytes */
	uint64_t sa_auth_errors;
	uint64_t sa_decrypt_errors;     /* decrypt errors */
	uint64_t sa_replay_errors;     /* replay errors */
	uint64_t sa_selector_errors;    /* SPD mismatch */
} __fpn_cache_aligned fp_v6_sa_stats_t;

#ifdef FP_IPSEC_STATS_PER_CORE
#define FP_IPSEC6_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_IPSEC6_STATS_DEC(st, field)          FP_STATS_PERCORE_DEC(st, field)
#define FP_IPSEC6_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FP_IPSEC6_STATS_SUB(st, field, val)     FP_STATS_PERCORE_SUB(st, field, val)
#define FP_IPSEC6_STATS_NUM                     FPN_MAX_CORES
#else
#define FP_IPSEC6_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FP_IPSEC6_STATS_DEC(st, field)          FP_STATS_DEC(st, field)
#define FP_IPSEC6_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FP_IPSEC6_STATS_SUB(st, field, val)     FP_STATS_SUB(st, field, val)
#define FP_IPSEC6_STATS_NUM                     1
#endif


#include "fp-sad6.h"
#ifndef CONFIG_MCORE_FPN_CRYPTO_ASYNC
typedef struct fp_ipsec6_ctx_s {
	uint32_t	proto;
	uint32_t	auth_type;
	uint32_t	authsize;
	char		*auth_data;
	char padbuf[FP_MAX_KEY_ENC_LENGTH + 2 /* pad length + next header */ + FP_MAX_KEY_AUTH_LENGTH];
} fp_ipsec6_ctx_t;

FPN_DECLARE_PER_CORE(fp_ipsec6_ctx_t, fp_ipsec6_context);
#define fp_ipsec6_ctx FPN_PER_CORE_VAR(fp_ipsec6_context)
#endif

#include "fp-spd6.h"
#ifdef CONFIG_MCORE_IPSEC_SVTI
#include "fp-svti6.h"
#endif

typedef struct fp_ipsec6 {
	fp_sad6_t               sad6;
	fp_spd6_t               spd6_in;
	fp_spd6_t               spd6_out;
#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
	/* SPD hash lookup minimum prefix lengths */
	uint8_t                 spd6_hash_loc_plen;
	uint8_t                 spd6_hash_rem_plen;
	uint8_t                 padding[2];
#endif
	fp_ipsec6_stats_t       ipsec6_stats[FP_MAX_VR][FP_IPSEC6_STATS_NUM];
#ifdef CONFIG_MCORE_MULTIBLADE
	uint32_t               sa_replay_sync_threshold;
#endif
	uint8_t                output_blade;
} fp_ipsec6_t;

void fp_ipsec6_init(void);
int fp_v6_sp_add(fp_spd6_t *spd, fp_v6_sp_entry_t *user_sp);
int fp_v6_sp_update(fp_spd6_t *spd, fp_v6_sp_entry_t *user_sp);
int fp_v6_sp_del(fp_spd6_t *spd, fp_v6_sp_entry_t *user_sp);
int fp_v6_sa_add(fp_sad6_t *sad, fp_v6_sa_entry_t *user_sa);
int fp_v6_sa_del(fp_sad6_t *sad, fp_v6_sa_entry_t *user_sa);
int fp_v6_sa_del_by_index(fp_sad6_t *sad, uint32_t i);
int fp_v6_sp_flush_by_vrfid(fp_spd6_t *spd, uint16_t vrfid);
int fp_v6_sa_flush(fp_sad6_t *sad);
int fp_v6_sa_flush_by_vrfid(fp_sad6_t *sad, uint16_t vrfid);
void fp_spd6_out_commit(void);
void fp_spd6_in_commit(void);
uint32_t fp_sad6_find_acq(const fp_in6_addr_t *src,
		const fp_in6_addr_t *dst, uint16_t proto,
		uint8_t mode, uint32_t reqid, uint16_t vrfid, uint16_t xvrfid
#ifdef CONFIG_MCORE_IPSEC_SVTI
		, uint32_t svti_ifuid
#endif
		);
void     fp_ipsec6_index_init(void);
void     fp_ipsec6_index_rebuild(void);
uint32_t fp_v6_sa_get_index(void);
void     fp_v6_sa_release_index(uint32_t index);
uint32_t fp_v6_sp_get_index(fp_spd6_t *spd);
void     fp_v6_sp_release_index(fp_spd6_t *spd, uint32_t index);
uint32_t fp_set_spd6_conf(uint16_t spd6_hash_loc_plen, uint16_t spd6_hash_rem_plen);

#endif /* __FP_IPSEC6_H__ */
