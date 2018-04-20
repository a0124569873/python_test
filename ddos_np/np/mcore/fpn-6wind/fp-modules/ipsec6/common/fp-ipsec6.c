/*
 * Copyright 2009 6WIND, All rights reserved.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "fp.h"

static uint32_t spd6in_stack[FP_MAX_IPV6_SP_ENTRIES-1];
static uint32_t spd6in_stack_index;
static uint32_t spd6out_stack[FP_MAX_IPV6_SP_ENTRIES-1];
static uint32_t spd6out_stack_index;
static uint32_t sad6_stack[FP_MAX_IPV6_SA_ENTRIES-1];
static uint32_t sad6_stack_index;


#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
/*
 * add security policy in hash table if hashable
 * returns 0 if hashable, -1 instead
 */
static int sp6_addrvr_hash(fp_spd6_t *spd, uint32_t idx)
{
	uint16_t h;

	if (spd->dir == FP_SPD_OUT) {
		if ((fp_shared->ipsec6.spd6_hash_loc_plen == 0 &&
		     fp_shared->ipsec6.spd6_hash_rem_plen == 0) ||
		    spd->table[idx].filter.src_plen < fp_shared->ipsec6.spd6_hash_loc_plen ||
		    spd->table[idx].filter.dst_plen < fp_shared->ipsec6.spd6_hash_rem_plen)
			return -1;
		h = sp6_addrvr2hash(spd->table[idx].filter.src6.fp_s6_addr32,
				   spd->table[idx].filter.dst6.fp_s6_addr32,
				   spd->table[idx].vrfid,
				   fp_shared->ipsec6.spd6_hash_loc_plen,
				   fp_shared->ipsec6.spd6_hash_rem_plen);
	}
	else {
		if ((fp_shared->ipsec6.spd6_hash_loc_plen == 0 &&
		     fp_shared->ipsec6.spd6_hash_rem_plen == 0) ||
		    spd->table[idx].filter.dst_plen < fp_shared->ipsec6.spd6_hash_loc_plen ||
		    spd->table[idx].filter.src_plen < fp_shared->ipsec6.spd6_hash_rem_plen)
			return -1;
		h = sp6_addrvr2hash(spd->table[idx].filter.dst6.fp_s6_addr32,
				   spd->table[idx].filter.src6.fp_s6_addr32,
				   spd->table[idx].vrfid,
				   fp_shared->ipsec6.spd6_hash_loc_plen,
				   fp_shared->ipsec6.spd6_hash_rem_plen);
	}

	spd->table[idx].flags |= FP_SP_FLAG_HASHED;
	spd->table[idx].hash = h;
	fp_hlist_add_ordered(&spd->addr_hash[h], spd->table, idx, addr_hlist, filter.cost);

	return 0;
}

static int
sp6_addrvr_unhash(fp_spd6_t *spd, uint32_t idx)
{
	uint16_t h = spd->table[idx].hash;

	fp_hlist_remove(&spd->addr_hash[h], spd->table, idx, addr_hlist);

	return 0;
}
#endif

/*
 * initialize the IPsec index allocation stacks
 * (SAD and SPD are empty)
 */
void fp_ipsec6_index_init(void)
{
	uint32_t i;

	/* Reset first item of each SPD table */
	memset(fp_get_spd6_in()->table, 0, sizeof(fp_v6_sp_entry_t));
	memset(fp_get_spd6_out()->table, 0, sizeof(fp_v6_sp_entry_t));

	sad6_stack_index = 0;
	spd6in_stack_index = 0;
	spd6out_stack_index = 0;
	sad6_stack_index = 0;

	for (i = 1; i < FP_MAX_IPV6_SP_ENTRIES; i++) {
		spd6in_stack[i-1] = i;
		spd6out_stack[i-1] = i;
	}
	for (i = 1; i < FP_MAX_IPV6_SA_ENTRIES; i++)
		sad6_stack[i-1] = i;
}

/*
 * rebuild the IPsec index allocation stacks
 * (SAD and SPD are not empty)
 */
void fp_ipsec6_index_rebuild(void)
{
	uint32_t i;

	sad6_stack_index = FP_MAX_IPV6_SA_ENTRIES-1;
	for (i = FP_MAX_IPV6_SA_ENTRIES -1 ; i > 0; i--) {
		if (fp_get_sad6()->table[i].state == FP_SA_STATE_UNSPEC)
			sad6_stack[--sad6_stack_index] = i;
	}

	spd6in_stack_index = FP_MAX_IPV6_SP_ENTRIES-1;
	for (i = FP_MAX_IPV6_SP_ENTRIES -1 ; i > 0; i--) {
		if (fp_get_spd6_in()->table[i].state == FP_SP_STATE_UNSPEC)
			spd6in_stack[--spd6in_stack_index] = i;
	}

	spd6out_stack_index = FP_MAX_IPV6_SP_ENTRIES-1;
	for (i = FP_MAX_IPV6_SP_ENTRIES -1 ; i > 0; i--) {
		if (fp_get_spd6_out()->table[i].state == FP_SP_STATE_UNSPEC)
			spd6out_stack[--spd6out_stack_index] = i;
	}
}

/* return first free index in sad or 0 */
uint32_t fp_v6_sa_get_index(void)
{
	if (sad6_stack_index == FP_MAX_IPV6_SA_ENTRIES-1)
		return 0;

	return sad6_stack[sad6_stack_index++];
}

/* free an index */
void fp_v6_sa_release_index(uint32_t index)
{
	sad6_stack[--sad6_stack_index] = index;
}

/* return first free index in spd or 0 */
uint32_t fp_v6_sp_get_index(fp_spd6_t *spd6)
{
	uint32_t *spdstack;
	uint32_t *index;

	if (spd6->dir == FP_SPD_IN) {
		spdstack = spd6in_stack;
		index = &spd6in_stack_index;
	} else {
		spdstack = spd6out_stack;
		index = &spd6out_stack_index;
	}

	if (*index == FP_MAX_IPV6_SP_ENTRIES-1)
		return 0;

	return spdstack[(*index)++];
}

/* free an index */
void fp_v6_sp_release_index(fp_spd6_t *spd6, uint32_t index)
{
	if (spd6->dir == FP_SPD_IN)
		spd6in_stack[--spd6in_stack_index] = index;
	else
		spd6out_stack[--spd6out_stack_index] = index;
}

/* used by FPM */
static inline uint32_t __fp_get_v6_sp_by_rule_index(fp_spd6_t *spd6, fp_v6_sp_entry_t *user_sp)
{
	uint32_t i;

	/* empty table? */
	if (spd6->global_sp_count == 0)
		return 0;

#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
	if (fp_shared->ipsec6.spd6_hash_loc_plen ||
	    fp_shared->ipsec6.spd6_hash_rem_plen) {

		uint32_t h;

		if (spd6->dir == FP_SPD_OUT) {
			if (user_sp->filter.src_plen < fp_shared->ipsec6.spd6_hash_loc_plen ||
	      		    user_sp->filter.dst_plen < fp_shared->ipsec6.spd6_hash_rem_plen)
			    goto unhashed;
			h = sp6_addrvr2hash(user_sp->filter.src6.fp_s6_addr32,
					user_sp->filter.dst6.fp_s6_addr32,
					user_sp->vrfid,
					fp_shared->ipsec6.spd6_hash_loc_plen,
					fp_shared->ipsec6.spd6_hash_rem_plen);
		}
		else {
			if (user_sp->filter.dst_plen < fp_shared->ipsec6.spd6_hash_loc_plen ||
	      		    user_sp->filter.src_plen < fp_shared->ipsec6.spd6_hash_rem_plen)
			    goto unhashed;
			h = sp6_addrvr2hash(user_sp->filter.dst6.fp_s6_addr32,
					user_sp->filter.src6.fp_s6_addr32,
					user_sp->vrfid,
					fp_shared->ipsec6.spd6_hash_loc_plen,
					fp_shared->ipsec6.spd6_hash_rem_plen);
		}

		fp_hlist_for_each(i, &spd6->addr_hash[h], spd6->table, addr_hlist) {
			if (spd6->table[i].vrfid != user_sp->vrfid)
				continue;
			if (spd6->table[i].rule_index == user_sp->rule_index)
				return i;
		}
		return 0;
	}
unhashed:
#endif

	fp_hlist_for_each(i, fp_get_spd6_head(spd6), spd6->table, list) {
		if (spd6->table[i].rule_index == user_sp->rule_index)
			return i;
	}
	return 0;
}

static inline void __fp_v6_sp_del(fp_spd6_t *spd6, uint32_t idx)
{
#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
	if (spd6->table[idx].flags & FP_SP_FLAG_HASHED) {
		sp6_addrvr_unhash(spd6, idx);
		spd6->hashed_sp_count--;
	}
	else
#endif
	{
		fp_hlist_remove(fp_get_spd6_head(spd6), spd6->table, idx, list);
		spd6->unhashed_sp_count--;
	}
	spd6->table[idx].state = FP_SP_STATE_UNSPEC;
	/* inbound SA lookup checks state of cached-SP */

	spd6->entry_count--;
	spd6->global_sp_count--;
}

static int
__fp_v6_sp_add(fp_spd6_t *spd6, fp_v6_sp_entry_t *user_sp, uint32_t new)
{
	spd6->table[new] = *user_sp;
	bzero(&spd6->table[new].stats, sizeof(fp_v6_sp_stats_t));
	spd6->table[new].sa_index = 0;
	spd6->table[new].filter.filtId = new;

#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
	if (sp6_addrvr_hash(spd6, new) == 0)
		spd6->hashed_sp_count++;
	else
#endif
	{
		fp_hlist_add_ordered(fp_get_spd6_head(spd6), spd6->table, new, list, filter.cost);
		spd6->unhashed_sp_count++;
	}
	spd6->entry_count++;
	spd6->global_sp_count++;
	
	spd6->table[new].state = FP_SP_STATE_ACTIVE;

	if (spd6->dir == FP_SPD_OUT)
		fp_spd6_out_commit();
	else
		fp_spd6_in_commit();

	return 0;
}

int fp_v6_sp_update(fp_spd6_t *spd6, fp_v6_sp_entry_t *user_sp)
{
	uint32_t idx;

	idx = __fp_get_v6_sp_by_rule_index(spd6, user_sp);

	if (idx != 0)
		__fp_v6_sp_del(spd6, idx);
	else if ((idx = fp_v6_sp_get_index(spd6)) == 0)
		return -1;

	return __fp_v6_sp_add(spd6, user_sp, idx);
}

int fp_v6_sp_add(fp_spd6_t *spd6, fp_v6_sp_entry_t *user_sp)
{
	uint32_t new;

	if ((new = fp_v6_sp_get_index(spd6)) == 0)
		return -1;

	return __fp_v6_sp_add(spd6, user_sp, new);
}


/*
 * mark all SAs with the same selector with the provided genid
 */
static void fp_v6_sa_bump_genids(fp_sad6_t *sad, uint32_t idx, uint32_t genid)
{
	uint16_t h;
	void *src = &sad->table[idx].src6;
	void *dst = &sad->table[idx].dst6;
	uint8_t proto = sad->table[idx].proto;
	uint8_t mode = sad->table[idx].mode;
	uint16_t vrfid = sad->table[idx].vrfid;
	uint16_t xvrfid = sad->table[idx].xvrfid;
	uint32_t reqid = sad->table[idx].reqid;
#ifdef CONFIG_MCORE_IPSEC_SVTI
	uint32_t svti_ifuid = sad->table[idx].svti_ifuid;
#endif
	uint32_t i;

	/* find hash line */
	h = __sa6_selector2hash(src, dst, proto, vrfid, xvrfid);

	fp_hlist_for_each(i, &sad->selector_hash[h], sad->table, selector_hlist) {
		if (mode == sad->table[i].mode &&
				proto == sad->table[i].proto &&
				vrfid == sad->table[i].vrfid &&
				xvrfid == sad->table[i].xvrfid &&
#ifdef CONFIG_MCORE_IPSEC_SVTI
				svti_ifuid == sad->table[i].svti_ifuid &&
#endif
				reqid == sad->table[i].reqid &&
				(memcmp(dst, &sad->table[i].dst6, sizeof(fp_in6_addr_t)) == 0) &&
				(memcmp(src, &sad->table[i].src6, sizeof(fp_in6_addr_t)) == 0) &&
				sad->table[i].state != FP_SA_STATE_UNSPEC)
			sad->table[i].genid = genid;
	}
}

/* Returns SA index or -1 in case of error */
int fp_v6_sa_add(fp_sad6_t *sad6, fp_v6_sa_entry_t *user_sa)
{
	uint32_t i;

	if ((i = fp_v6_sa_get_index()) == 0)
		return -1;

	/* Get current counter, bump it only when all is ok */
	user_sa->counter = sad6->table[i].counter;
	user_sa->index   = i;
	memcpy(&sad6->table[i], user_sa, sizeof(fp_v6_sa_entry_t));
	sad6->table[i].spd_index = 0;
	sad6->table[i].ivlen = fp_get_v6_sa_esp_algo(sad6->table[i].alg_enc)->ivlen;
	sad6->table[i].blocksize = fp_get_v6_sa_esp_algo(sad6->table[i].alg_enc)->blocksize;
	sad6->table[i].authsize = (fp_get_v6_sa_esp_algo(sad6->table[i].alg_enc)->authsize != 0 ?
	                           fp_get_v6_sa_esp_algo(sad6->table[i].alg_enc)->authsize :
	                           fp_get_v6_sa_ah_algo(sad6->table[i].alg_auth)->authsize);
	sad6->table[i].saltsize = fp_get_v6_sa_esp_algo(sad6->table[i].alg_enc)->saltsize;
	sad6->table[i].key_enc_len -= sad6->table[i].saltsize;

	bzero(&sad6->table[i].stats, sizeof(fp_v6_sa_stats_t));
	sa6_selector_hash(sad6, i);
#ifdef IPSEC_IPV6_SPI_HASH
	sa6_hash(sad6, i);
#endif
	/* Increase counter */
	sad6->table[i].counter++;
	sad6->count++;

	fp_v6_sa_bump_genids(sad6, i, sad6->table[i].genid);

	return i;
}

void fp_spd6_out_commit(void)
{
	if (fp_get_spd6_out()->global_sp_count == 0) {
		fp_shared->conf.s.do_ipsec6_output = 0;
	} else {
		fp_shared->conf.s.do_ipsec6_output = 1;
	}
}

void fp_spd6_in_commit(void)
{
	if (fp_get_spd6_in()->global_sp_count == 0) {
		fp_shared->conf.s.do_ipsec6_input = 0;
	} else {
		fp_shared->conf.s.do_ipsec6_input = 1;
	}
}

int fp_v6_sp_flush_by_vrfid(fp_spd6_t *spd6, uint16_t vrfid)
{
	uint32_t i;

	for (i=1; i < FP_MAX_IPV6_SP_ENTRIES; i++) {
		if (spd6->table[i].state != FP_SP_STATE_UNSPEC &&
		    spd6->table[i].svti_ifuid == 0 &&
		    spd6->table[i].vrfid == vrfid) {
			__fp_v6_sp_del(spd6, i);
			fp_v6_sp_release_index(spd6, i);
		}
	}

	fp_spd6_out_commit();
	fp_spd6_in_commit();
	
	return 0;	
}

int fp_v6_sa_flush(fp_sad6_t *sad6)
{
	uint32_t i;

	sad6->count = 0;
	for (i = 1; i < FP_MAX_IPV6_SA_ENTRIES; i++) {
		sad6->table[i].state = FP_SA_STATE_UNSPEC;
		sad6_stack[i-1] = i;
	}
	sad6_stack_index = 0;
	sa6_init_selector_hash(sad6);

	return 0;
}

int fp_v6_sa_flush_by_vrfid(fp_sad6_t *sad6, uint16_t vrfid)
{
	uint32_t i;

	for (i = 1; i < FP_MAX_IPV6_SA_ENTRIES; i++) {
		if (sad6->table[i].state != FP_SA_STATE_UNSPEC &&
		    sad6->table[i].vrfid == vrfid) {
			__fp_v6_sa_del(sad6, i);
			sad6->count--;
			fp_v6_sa_release_index(i);
		}
	}

	return 0;
}

int fp_v6_sp_del(fp_spd6_t *spd6, fp_v6_sp_entry_t *user_sp)
{
	uint32_t idx = __fp_get_v6_sp_by_rule_index(spd6, user_sp);

	if (idx == 0)
		return -1;

	__fp_v6_sp_del(spd6, idx);
	fp_v6_sp_release_index(spd6, idx);

	if (spd6->dir == FP_SPD_OUT)
		fp_spd6_out_commit();
	else
		fp_spd6_in_commit();

	return 0;
}

int fp_v6_sa_del(fp_sad6_t *sad6, fp_v6_sa_entry_t *user_sa)
{
	uint32_t i = __fp_v6_sa_get(sad6, user_sa->spi, user_sa->dst6.fp_s6_addr, user_sa->proto, user_sa->vrfid);

	if (i == 0)
		return -1; /* not found */

	__fp_v6_sa_del(sad6, i);
	sad6->count--;

	return i;
}

int fp_v6_sa_del_by_index(fp_sad6_t *sad6, uint32_t i)
{
	__fp_v6_sa_del(sad6, i);
	sad6->count--;
	fp_v6_sa_release_index(i);

	return 0;
}

static void fp_ipsec6_init_algos(void)
{
	/* Algs are common for both ipsec and ipsec6 */
}

uint32_t fp_sad6_find_acq(const fp_in6_addr_t *src,
		const fp_in6_addr_t *dst, uint16_t proto,
		uint8_t mode, uint32_t reqid,
		uint16_t vrfid, uint16_t xvrfid
#ifdef CONFIG_MCORE_IPSEC_SVTI
		, uint32_t svti_ifuid
#endif
		)
{
	fp_sad6_t *sad = fp_get_sad6();
	uint32_t i, h;

	/* empty table? */
	if (sad->count == 0)
		return 0;

	/* find hash line */
	h = __sa6_selector2hash((uint32_t*)src, (uint32_t*)dst, proto, vrfid, xvrfid);

	/* follow hash list */
	fp_hlist_for_each(i, &sad->selector_hash[h], sad->table, selector_hlist) {
		if (sad->table[i].state == FP_SA_STATE_ACQUIRE &&
		    mode == sad->table[i].mode &&
		    proto == sad->table[i].proto &&
		    vrfid == sad->table[i].vrfid &&
		    xvrfid == sad->table[i].xvrfid &&
		    is_in6_addr_equal(*dst, sad->table[i].dst6) &&
		    is_in6_addr_equal(*src, sad->table[i].src6) &&
#ifdef CONFIG_MCORE_IPSEC_SVTI
		    svti_ifuid == sad->table[i].svti_ifuid &&
#endif
		    reqid == sad->table[i].reqid)
			return i;
	}

	/* not found */
	return 0;
}

#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
uint32_t fp_set_spd6_conf(uint16_t spd6_hash_loc_plen, uint16_t spd6_hash_rem_plen)
{
	if (spd6_hash_loc_plen > 128 || spd6_hash_rem_plen > 128)
		return -1;

	fp_shared->ipsec6.spd6_hash_loc_plen = spd6_hash_loc_plen;
	fp_shared->ipsec6.spd6_hash_rem_plen = spd6_hash_rem_plen;

	return 0;
}
#endif

void fp_ipsec6_init(void)
{
	/* bzero is enough to set state to UNSPEC (0) */

	bzero(&fp_shared->ipsec6, sizeof(fp_shared->ipsec6));
	fp_get_spd6_in()->dir  = FP_SPD_IN;
	fp_get_spd6_out()->dir = FP_SPD_OUT;
	fp_ipsec6_init_algos();
#ifdef CONFIG_MCORE_MULTIBLADE
	fp_shared->ipsec6.sa_replay_sync_threshold = 32;
#endif
}

