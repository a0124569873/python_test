/*
 * Copyright(c) 2008 6WIND
 */

#ifndef __FP_SVTI6_H__
#define __FP_SVTI6_H__

#include "fp-hlist.h"
#include "fp-svti.h"

static inline uint32_t __fp_svti6_get_sp_by_rule(fp_hlist_head_t *head,
		fp_spd6_t *spd6, uint32_t rule)
{
	uint32_t i;

	fp_hlist_for_each(i, head, spd6->table, list) {

		if (spd6->table[i].rule_index == rule)
			return i;
	}

	return 0;
}

int fp_svti6_add(uint32_t ifuid);
int fp_svti6_del(uint32_t ifuid);
int fp_svti6_sp_add(fp_hlist_head_t *head, fp_spd6_t *spd,
		fp_v6_sp_entry_t *user_sp);
int fp_svti6_sp_update(fp_hlist_head_t *head, fp_spd6_t *spd,
		fp_v6_sp_entry_t *user_sp);
int fp_svti6_sp_del(fp_hlist_head_t *head, fp_spd6_t *spd,
		fp_v6_sp_entry_t *user_sp);
int fp_svti6_sp_flush(fp_hlist_head_t *head, fp_spd6_t *spd);
int fp_svti6_sa_flush(fp_sad6_t *sad, uint32_t ifuid);

#endif /* __FP_SVTI6_H__ */
