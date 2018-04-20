/*
 * Copyright(c) 2008 6WIND
 */

#ifndef __FP_SVTI_H__
#define __FP_SVTI_H__

#include "fp-hlist.h"

/* Maxium number of SVTI (Security Virtual Tunnel Interfaces). */
#ifdef CONFIG_MCORE_IPSEC_MAX_SVTI
#define FP_MAX_SVTI (CONFIG_MCORE_IPSEC_MAX_SVTI + 1)
#else
#define FP_MAX_SVTI 128
#endif

/* Fast Path hash order for SVTI interfaces */
#ifdef CONFIG_MCORE_FP_SVTI_HASH_ORDER
#define FP_SVTI_HASH_ORDER     CONFIG_MCORE_FP_SVTI_HASH_ORDER
#else
#define FP_SVTI_HASH_ORDER     8
#endif
#define FP_SVTI_HASH_SIZE      (1 << FP_SVTI_HASH_ORDER)
#define FP_SVTI_HASH_MASK      (FP_SVTI_HASH_SIZE - 1)

static inline uint32_t fp_svti_hash(
		uint32_t laddr,
		uint32_t raddr,
		uint32_t linkvrfid)
{
	uint32_t a = laddr;
	uint32_t b = raddr;
	uint32_t c = linkvrfid;

	fp_jhash_mix(a, b, c);

	return c & FP_SVTI_HASH_MASK;
}

typedef struct fp_svti {
    uint32_t           ifuid;
#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
    uint32_t           laddr;      /* local tunnel address     */
    uint32_t           raddr;      /* remote tunnel address    */
    uint32_t           link_vrfid; /* tunnel link-vrfid        */
    uint32_t           genid;      /* svti table generation id */
    fp_hlist_node_t    hlist;      /* per-addr hash table node */
#endif
    fp_hlist_head_t spd_out;
    fp_hlist_head_t spd_in;
#ifdef CONFIG_MCORE_IPSEC_IPV6
    fp_hlist_head_t spd6_out;
    fp_hlist_head_t spd6_in;
#endif
} fp_svti_t;

static inline uint32_t __fp_svti_get_sp_by_rule(fp_hlist_head_t *head,
		fp_spd_t *spd, uint32_t rule)
{
	uint32_t i;

	fp_hlist_for_each(i, head, spd->table, list) {

		if (spd->table[i].rule_index == rule)
			return i;
	}

	return 0;
}

int fp_svti_add(uint32_t ifuid);
int fp_svti_del(uint32_t ifuid);
int fp_addifnet_svtiinfo(uint32_t ifuid, uint16_t linkvrfid,
		struct fp_in_addr *local, struct fp_in_addr *remote);
int fp_delifnet_svtiinfo(uint32_t ifuid);
int fp_svti_sp_add(fp_hlist_head_t *head, fp_spd_t *spd,
		fp_sp_entry_t *user_sp);
int fp_svti_sp_update(fp_hlist_head_t *head, fp_spd_t *spd,
		fp_sp_entry_t *user_sp);
int fp_svti_sp_del(fp_hlist_head_t *head, fp_spd_t *spd,
		fp_sp_entry_t *user_sp);
int fp_svti_sp_del_by_index(fp_hlist_head_t *head, fp_spd_t *spd,
		uint32_t idx);
void __fp_svti_sp_del(fp_hlist_head_t *head, fp_spd_t *spd,
		uint32_t idx);
int fp_svti_sp_flush(fp_hlist_head_t *head, fp_spd_t *spd);
int fp_svti_sa_flush(fp_sad_t *sad, uint32_t ifuid);
void fp_svti_init(void);

#endif /* __FP_SVTI_H__ */
