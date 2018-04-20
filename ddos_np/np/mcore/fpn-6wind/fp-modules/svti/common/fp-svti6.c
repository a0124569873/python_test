/*
 * Copyright 2008 6WIND, All rights reserved.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "fp.h"


static int
__fp_svti6_sp_add(fp_hlist_head_t *head, fp_spd6_t *spd,
		  fp_v6_sp_entry_t *user_sp, uint32_t new)
{
	spd->table[new] = *user_sp;
	bzero(&spd->table[new].stats, sizeof(fp_sp_stats_t));
	spd->table[new].sa_index = 0;
	spd->table[new].filter.filtId = new;

	fp_hlist_add_ordered(head, spd->table, new, list, filter.cost);

	spd->entry_count++;
	spd->table[new].state = FP_SP_STATE_ACTIVE;

	return 0;
}

static void __fp_svti6_sp_del(fp_hlist_head_t *head, fp_spd6_t *spd,
		uint32_t idx)
{
	fp_hlist_remove(head, spd->table, idx, list);

	spd->entry_count--;
	spd->table[idx].state = FP_SP_STATE_UNSPEC;
	/* inbound SA lookup checks state of cached-SP */
}

int fp_svti6_sp_update(fp_hlist_head_t *head, fp_spd6_t *spd,
		fp_v6_sp_entry_t *user_sp)
{
	uint32_t idx;

	if (head == NULL)
		return -1;

	/* XXX warning: new SP may have different index */
	/* we ought to search by selector instead */
	idx = __fp_svti6_get_sp_by_rule(head, spd, user_sp->rule_index);

	if (idx != 0)
		__fp_svti6_sp_del(head, spd, idx);
	else if ((idx = fp_v6_sp_get_index(spd)) == 0)
		return -1;

	return __fp_svti6_sp_add(head, spd, user_sp, idx);
}

int fp_svti6_sp_add(fp_hlist_head_t *head, fp_spd6_t *spd,
		fp_v6_sp_entry_t *user_sp)
{
	uint32_t new;

	if (head == NULL)
		return -1;

	if ((new = fp_v6_sp_get_index(spd)) == 0)
		return -1;

	return __fp_svti6_sp_add(head, spd, user_sp, new);
}

int fp_svti6_sp_del(fp_hlist_head_t *head, fp_spd6_t *spd,
		fp_v6_sp_entry_t *user_sp)
{
	uint32_t idx;

	if (head == NULL)
		return -1;

	idx = __fp_svti6_get_sp_by_rule(head, spd, user_sp->rule_index);

	if (idx == 0)
		return -1;

	__fp_svti6_sp_del(head, spd, idx);
	fp_v6_sp_release_index(spd, idx);
	return 0;
}

int fp_svti6_sp_flush(fp_hlist_head_t *head, fp_spd6_t *spd)
{
	uint32_t idx;

	if (head == NULL)
		return -1;

	while ((idx = fp_hlist_first(head)) != 0) {
		__fp_svti6_sp_del(head, spd, idx);
		fp_v6_sp_release_index(spd, idx);
	}
	
	return 0;	
}

int fp_svti6_sa_flush(fp_sad6_t *sad, uint32_t ifuid)
{
	uint32_t i;
	
	for (i = 1; i < FP_MAX_IPV6_SA_ENTRIES; i++) {
		if (sad->table[i].state != FP_SA_STATE_UNSPEC &&
		    sad->table[i].svti_ifuid == ifuid) {
			__fp_v6_sa_del(sad, i);
			sad->count--;
			fp_v6_sa_release_index(i);
		}
	}

	return 0;
}

