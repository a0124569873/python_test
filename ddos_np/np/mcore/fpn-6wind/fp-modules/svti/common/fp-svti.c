/*
 * Copyright 2008 6WIND, All rights reserved.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "fp.h"

/*
 * assign a free cell in the svti table
 */
static uint32_t fp_svti_assign(uint32_t ifuid)
{
	 uint32_t idx;
	 fp_svti_t *table = &fp_shared->svti[0];

	 for (idx = 1; idx < FP_MAX_SVTI; idx++)
		if (table[idx].ifuid == 0)
			return idx;

	 return 0;
}

#ifndef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
int fp_svti_add(uint32_t ifuid)
{
	uint32_t idx;
	fp_svti_t *svti;
	fp_ifnet_t *ifp;

	if ((idx = fp_svti_assign(ifuid)) == 0)
		return -1;

	svti = &fp_shared->svti[idx];

	memset(svti, 0, sizeof(fp_svti_t));
	svti->ifuid = ifuid;

	ifp = fp_ifuid2ifnet(ifuid);
	if (ifp)
		ifp->sub_table_index = idx;

	return 0;
}

int fp_svti_del(uint32_t ifuid)
{
	uint32_t idx;
	fp_svti_t *svti;

	/* look for svti interface */
	if ((idx = __fp_svti_get_index_by_ifuid(ifuid)) == 0)
		return -1;

	svti = &fp_shared->svti[idx];

	/* remove SPs */
	fp_svti_sp_flush(fp_svti_get_spd_in(ifuid), fp_get_spd_in());
	fp_svti_sp_flush(fp_svti_get_spd_out(ifuid), fp_get_spd_out());
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_svti6_sp_flush(fp_svti6_get_spd_in(ifuid), fp_get_spd6_in());
	fp_svti6_sp_flush(fp_svti6_get_spd_out(ifuid), fp_get_spd6_out());
#endif
	/* remove SAs */
	fp_svti_sa_flush(fp_get_sad(), ifuid);
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_svti6_sa_flush(fp_get_sad6(), ifuid);
#endif
	__fp_ifuid2ifnet(ifuid)->sub_table_index = 0;
	svti->ifuid = 0;

	return 0;
}
#else /* !CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA */
/*
 * svti interfaces are stored in a table. A hash table enables to easily look
 * them up via their local@, remote@, link-vrfid.
 * Inbound IPsec SAs maintain a cache to the index of the last found svti
 * interface (0 means no svti interface found => global SA). The generation id
 * enables to verify the validity of the cached index, the SA genid must equal
 * svti[idx].genid, otherwise the cached index is invalid.
 */

/*
 * add an svti interface in the hash table
 * invalidate caches to the hash table
 */
static void
fp_svti_link(uint32_t idx)
{
	uint32_t hash;
	hash = fp_svti_hash(fp_shared->svti[idx].laddr,
			    fp_shared->svti[idx].raddr,
			    fp_shared->svti[idx].link_vrfid);

	fp_hlist_add_head(&fp_shared->svti_hash[hash], fp_shared->svti, idx, hlist);

	/* increment the svti table generation id */
	if (unlikely(++fp_shared->svti[0].genid == 0))
		fp_shared->svti[0].genid = 1;
	/* set the new svti interface generation id to the table genid */
	fp_shared->svti[idx].genid = fp_shared->svti[0].genid;
}

/*
 * delete an svti interface from the hash table
 * invalidate caches to the hash table
 */
static void
fp_svti_unlink(uint32_t idx)
{
	uint32_t hash;
	hash = fp_svti_hash(fp_shared->svti[idx].laddr,
			    fp_shared->svti[idx].raddr,
			    fp_shared->svti[idx].link_vrfid);

	fp_hlist_remove(&fp_shared->svti_hash[hash], fp_shared->svti, idx, hlist);
	/* reset interface genid */
	fp_shared->svti[idx].genid = 0;
}

int fp_addifnet_svtiinfo(uint32_t ifuid, uint16_t linkvrfid,
			 struct fp_in_addr *local, struct fp_in_addr *remote)
{
	uint32_t idx;
	fp_svti_t *svti;
	fp_ifnet_t *ifp;

	if ((idx = fp_svti_assign(ifuid)) == 0)
		return -1;

	svti = &fp_shared->svti[idx];

	memset(svti, 0, sizeof(fp_svti_t));

	svti->laddr = local->s_addr;
	svti->raddr = remote->s_addr;
	svti->link_vrfid = linkvrfid;
	svti->ifuid = ifuid;

	fp_svti_link(idx);

	ifp = fp_ifuid2ifnet(ifuid);
	if (ifp)
		ifp->sub_table_index = idx;

	return 0;
}

int fp_delifnet_svtiinfo(uint32_t ifuid)
{
	uint32_t idx;
	fp_svti_t *svti;

	/* look for svti interface */
	if ((idx = __fp_svti_get_index_by_ifuid(ifuid)) == 0)
	{
		printf("%s: could not find svti 0x%08x\n", __FUNCTION__, ifuid);
		return -1;
	}

	svti = &fp_shared->svti[idx];

	/* remove SPs */
	fp_svti_sp_flush(fp_svti_get_spd_in(ifuid), fp_get_spd_in());
	fp_svti_sp_flush(fp_svti_get_spd_out(ifuid), fp_get_spd_out());
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_svti6_sp_flush(fp_svti6_get_spd_in(ifuid), fp_get_spd6_in());
	fp_svti6_sp_flush(fp_svti6_get_spd_out(ifuid), fp_get_spd6_out());
#endif

	__fp_ifuid2ifnet(ifuid)->sub_table_index = 0;
	svti->ifuid = 0;

	fp_svti_unlink(idx);

	return 0;
}
#endif /* !CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA */

static int
__fp_svti_sp_add(fp_hlist_head_t *head, fp_spd_t *spd,
		 fp_sp_entry_t *user_sp, uint32_t new)
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

/*
 * delete an svti security policy based on its table index
 */
void __fp_svti_sp_del(fp_hlist_head_t *head, fp_spd_t *spd,
		uint32_t idx)
{
	fp_hlist_remove(head, spd->table, idx, list);

	spd->entry_count--;
	spd->table[idx].state = FP_SP_STATE_UNSPEC;
	/* inbound SA lookup checks state of cached-SP */
}

int fp_svti_sp_update(fp_hlist_head_t *head, fp_spd_t *spd,
		fp_sp_entry_t *user_sp)
{
	uint32_t idx;

	if (head == NULL)
		return -1;

	/* XXX warning: new SP may have different index */
	/* we ought to search by selector instead */
	idx = __fp_svti_get_sp_by_rule(head, spd, user_sp->rule_index);

	if (idx != 0)
		__fp_svti_sp_del(head, spd, idx);
	else if ((idx = fp_sp_get_index(spd)) == 0)
		return -1;

	return __fp_svti_sp_add(head, spd, user_sp, idx);
}

int fp_svti_sp_add(fp_hlist_head_t *head, fp_spd_t *spd,
		fp_sp_entry_t *user_sp)
{
	uint32_t new;

	if (head == NULL)
		return -1;

	if ((new = fp_sp_get_index(spd)) == 0)
		return -1;

	return __fp_svti_sp_add(head, spd, user_sp, new);
}

int fp_svti_sp_del(fp_hlist_head_t *head, fp_spd_t *spd,
		fp_sp_entry_t *user_sp)
{
	uint32_t idx;

	if (head == NULL)
		return -1;

	idx = __fp_svti_get_sp_by_rule(head, spd, user_sp->rule_index);

	if (idx == 0)
		return -1;

	__fp_svti_sp_del(head, spd, idx);
	fp_sp_release_index(spd, idx);
	return 0;
}

int fp_svti_sp_del_by_index(fp_hlist_head_t *head, fp_spd_t *spd,
		uint32_t idx)
{
	if (!head)
		return -1;

	__fp_svti_sp_del(head, spd, idx);
	fp_sp_release_index(spd, idx);
	return 0;
}

int fp_svti_sp_flush(fp_hlist_head_t *head, fp_spd_t *spd)
{
	uint32_t idx;

	if (head == NULL)
		return -1;

	while ((idx = fp_hlist_first(head)) != 0) {
		__fp_svti_sp_del(head, spd, idx);
		fp_sp_release_index(spd, idx);
	}
	
	return 0;	
}

int fp_svti_sa_flush(fp_sad_t *sad, uint32_t ifuid)
{
	uint32_t i;
	
	for (i = 1; i < FP_MAX_SA_ENTRIES; i++) {
		if (sad->table[i].state != FP_SA_STATE_UNSPEC &&
		    sad->table[i].svti_ifuid == ifuid) {
			__fp_sa_del(sad, i);
			sad->count--;
			fp_sa_release_index(i);
		}
	}

	return 0;
}

void fp_svti_init(void)
{
	bzero(&fp_shared->svti, sizeof(fp_shared->svti));
#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
	bzero(&fp_shared->svti_hash, sizeof(fp_shared->svti_hash));
#endif
}

