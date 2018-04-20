/*
 * Copyright 2007 6WIND, All rights reserved.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "fp.h"
#include "fp-var.h"

static uint32_t spdin_stack[FP_MAX_SP_ENTRIES-1];
static uint32_t spdin_stack_index;
static uint32_t spdout_stack[FP_MAX_SP_ENTRIES-1];
static uint32_t spdout_stack_index;
static uint32_t sad_stack[FP_MAX_SA_ENTRIES-1];
static uint32_t sad_stack_index;

#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
/*
 * add security policy in hash table if hashable
 * returns 0 if hashable, -1 instead
 */
static int sp_addrvr_hash(fp_spd_t *spd, uint32_t idx)
{
	uint16_t h;

	if (spd->dir == FP_SPD_OUT) {
		if ((fp_shared->ipsec.spd_hash_loc_plen == 0 &&
		     fp_shared->ipsec.spd_hash_rem_plen == 0) ||
		    spd->table[idx].filter.src_plen < fp_shared->ipsec.spd_hash_loc_plen ||
		    spd->table[idx].filter.dst_plen < fp_shared->ipsec.spd_hash_rem_plen)
			return -1;
		h = sp_addrvr2hash(spd->table[idx].filter.src,
				   spd->table[idx].filter.dst,
				   spd->table[idx].vrfid,
				   fp_shared->ipsec.spd_hash_loc_plen,
				   fp_shared->ipsec.spd_hash_rem_plen);
	}
	else {
		if ((fp_shared->ipsec.spd_hash_loc_plen == 0 &&
		     fp_shared->ipsec.spd_hash_rem_plen == 0) ||
		    spd->table[idx].filter.dst_plen < fp_shared->ipsec.spd_hash_loc_plen ||
		    spd->table[idx].filter.src_plen < fp_shared->ipsec.spd_hash_rem_plen)
			return -1;
		h = sp_addrvr2hash(spd->table[idx].filter.dst,
				   spd->table[idx].filter.src,
				   spd->table[idx].vrfid,
				   fp_shared->ipsec.spd_hash_loc_plen,
				   fp_shared->ipsec.spd_hash_rem_plen);
	}

	spd->table[idx].flags |= FP_SP_FLAG_HASHED;
	spd->table[idx].hash = h;
	fp_hlist_add_ordered(&spd->addr_hash[h], spd->table, idx, addr_hlist, filter.cost);

	return 0;
}

static int
sp_addrvr_unhash(fp_spd_t *spd, uint32_t idx)
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
void fp_ipsec_index_init(void)
{
	uint32_t i;

	/* Reset first item of each SPD table */
	memset(fp_get_spd_in()->table, 0, sizeof(fp_sp_entry_t));
	memset(fp_get_spd_out()->table, 0, sizeof(fp_sp_entry_t));

	sad_stack_index = 0;
	spdin_stack_index = 0;
	spdout_stack_index = 0;
	sad_stack_index = 0;

	for (i = 1; i < FP_MAX_SP_ENTRIES; i++) {
		spdin_stack[i-1] = i;
		spdout_stack[i-1] = i;
	}
	for (i = 1; i < FP_MAX_SA_ENTRIES; i++)
		sad_stack[i-1] = i;
}

/*
 * rebuild the IPsec index allocation stacks
 * (SAD and SPD are not empty)
 */
void fp_ipsec_index_rebuild(void)
{
	uint32_t i;

	sad_stack_index = FP_MAX_SA_ENTRIES-1;
	for (i = FP_MAX_SA_ENTRIES -1 ; i > 0; i--) {
		if (fp_get_sad()->table[i].state == FP_SA_STATE_UNSPEC)
			sad_stack[--sad_stack_index] = i;
	}

	spdin_stack_index = FP_MAX_SP_ENTRIES-1;
	for (i = FP_MAX_SP_ENTRIES -1 ; i > 0; i--) {
		if (fp_get_spd_in()->table[i].state == FP_SP_STATE_UNSPEC)
			spdin_stack[--spdin_stack_index] = i;
	}

	spdout_stack_index = FP_MAX_SP_ENTRIES-1;
	for (i = FP_MAX_SP_ENTRIES -1 ; i > 0; i--) {
		if (fp_get_spd_out()->table[i].state == FP_SP_STATE_UNSPEC)
			spdout_stack[--spdout_stack_index] = i;
	}
}

/* return first free index in sad or 0 */
uint32_t fp_sa_get_index(void)
{
	if (sad_stack_index == FP_MAX_SA_ENTRIES-1)
		return 0;

	return sad_stack[sad_stack_index++];
}

/* free an index */
void fp_sa_release_index(uint32_t index)
{
	sad_stack[--sad_stack_index] = index;
}

/* return first free index in spd or 0 */
uint32_t fp_sp_get_index(fp_spd_t *spd)
{
	uint32_t *spdstack;
	uint32_t *index;

	if (spd->dir == FP_SPD_IN) {
		spdstack = spdin_stack;
		index = &spdin_stack_index;
	} else {
		spdstack = spdout_stack;
		index = &spdout_stack_index;
	}

	if (*index == FP_MAX_SP_ENTRIES-1)
		return 0;

	return spdstack[(*index)++];
}

/* free an index */
void fp_sp_release_index(fp_spd_t *spd, uint32_t index)
{
	if (spd->dir == FP_SPD_IN)
		spdin_stack[--spdin_stack_index] = index;
	else
		spdout_stack[--spdout_stack_index] = index;
}

/*
 * delete a global security policy based on its table index
 */
void __fp_sp_del(fp_spd_t *spd, uint32_t idx)
{
#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
	if (spd->table[idx].flags & FP_SP_FLAG_HASHED) {
		sp_addrvr_unhash(spd, idx);
		spd->hashed_sp_count--;
	}
	else
#endif
	{
		fp_hlist_remove(fp_get_spd_head(spd), spd->table, idx, list);
		spd->unhashed_sp_count--;
	}
	spd->table[idx].state = FP_SP_STATE_UNSPEC;
	/* inbound SA lookup checks state of cached-SP */

	spd->entry_count--;
	spd->global_sp_count--;
}

static int
__fp_sp_add(fp_spd_t *spd, fp_sp_entry_t *user_sp, uint32_t new)
{
	spd->table[new] = *user_sp;
	bzero(&spd->table[new].stats, sizeof(fp_sp_stats_t));
	spd->table[new].sa_index = 0;
	spd->table[new].filter.filtId = new;
#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
	if (sp_addrvr_hash(spd, new) == 0)
		spd->hashed_sp_count++;
	else
#endif
	{
		fp_hlist_add_ordered(fp_get_spd_head(spd), spd->table, new, list, filter.cost);
		spd->unhashed_sp_count++;
	}
	spd->entry_count++;
	spd->global_sp_count++;
	
	spd->table[new].state = FP_SP_STATE_ACTIVE;

	return 0;
}

int fp_sp_add(fp_spd_t *spd, fp_sp_entry_t *user_sp)
{
	uint32_t new;

	if ((new = fp_sp_get_index(spd)) == 0)
		return -1;

	return __fp_sp_add(spd, user_sp, new);
}

/*
 * mark all SAs with the same selector with the provided genid
 */
static void fp_sa_bump_genids(fp_sad_t *sad, uint32_t idx, uint32_t genid)
{
	uint16_t h;
	uint32_t src = sad->table[idx].src4;
	uint32_t dst = sad->table[idx].dst4;
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
	h = __sa_selector2hash(src, dst, proto, vrfid, xvrfid);

	fp_hlist_for_each(i, &sad->selector_hash[h], sad->table, selector_hlist) {
		if (dst == sad->table[i].dst4 &&
				src == sad->table[i].src4 &&
				mode == sad->table[i].mode &&
				proto == sad->table[i].proto &&
				vrfid == sad->table[i].vrfid &&
				xvrfid == sad->table[i].xvrfid &&
#ifdef CONFIG_MCORE_IPSEC_SVTI
				svti_ifuid == sad->table[i].svti_ifuid &&
#endif
				reqid == sad->table[i].reqid &&
				sad->table[i].state != FP_SA_STATE_UNSPEC)
			sad->table[i].genid = genid;
	}
}

/* Returns SA index or -1 in case of error */
int fp_sa_add(fp_sad_t *sad, fp_sa_entry_t *user_sa)
{
	uint32_t i;

	if ((i = fp_sa_get_index()) == 0)
		return -1;

	/* Get current counter, bump it only when all is ok */
	user_sa->counter = sad->table[i].counter;
	user_sa->index   = i;
	memcpy(&sad->table[i], user_sa, sizeof(fp_sa_entry_t));
	sad->table[i].spd_index = 0;
	sad->table[i].ivlen = fp_get_sa_esp_algo(sad->table[i].alg_enc)->ivlen;
	sad->table[i].blocksize = fp_get_sa_esp_algo(sad->table[i].alg_enc)->blocksize;
	sad->table[i].authsize = (fp_get_sa_esp_algo(sad->table[i].alg_enc)->authsize != 0 ?
	                          fp_get_sa_esp_algo(sad->table[i].alg_enc)->authsize :
	                          fp_get_sa_ah_algo(sad->table[i].alg_auth)->authsize);
	sad->table[i].saltsize = fp_get_sa_esp_algo(sad->table[i].alg_enc)->saltsize;
	sad->table[i].key_enc_len -= sad->table[i].saltsize;

	bzero(&sad->table[i].stats, sizeof(fp_sa_stats_t));

	sa_selector_hash(sad, i);

#ifdef IPSEC_SPI_HASH
	sa_hash(sad, i);
#endif
	/* Increase counter */
	sad->table[i].counter++;
	sad->count++;

	fp_sa_bump_genids(sad, i, sad->table[i].genid);

	return i;
}

void fp_spd_out_commit(void)
{
	if (fp_get_spd_out()->global_sp_count == 0) {
		fp_shared->conf.s.do_ipsec_output = 0;
	} else
		fp_shared->conf.s.do_ipsec_output = 1;
}

void fp_spd_in_commit(void)
{
	if (fp_get_spd_in()->global_sp_count == 0)
		fp_shared->conf.s.do_ipsec_input = 0;
	else
		fp_shared->conf.s.do_ipsec_input = 1;
}

#ifdef CONFIG_MCORE_IPSEC_TRIE
void fp_spd_trie_out_commit(void)
{
	if (fp_get_spd_out()->global_sp_count == 0)
		fp_shared->ipsec.trie_out.running = 0;

	fp_shared->ipsec.trie_out.spd_version++;
}

void fp_spd_trie_in_commit(void)
{
	if (fp_get_spd_in()->global_sp_count == 0)
		fp_shared->ipsec.trie_in.running = 0;

	fp_shared->ipsec.trie_in.spd_version++;
}
#endif

#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
/*
 * delete an sp entry regardless if it is global or svti
 */
static void __fp_sp_entry_del(fp_spd_t *spd, uint32_t idx)
{
	fp_sp_entry_t *sp = &spd->table[idx];

	if (sp->svti_ifuid != 0) {
		fp_hlist_head_t *head;
		
		head = fp_svti_get_spd(sp->svti_ifuid, spd->dir);
		if (unlikely(head == NULL))
			return;

		__fp_svti_sp_del(head, spd, idx);

		return;
	}

	__fp_sp_del(spd, idx);
}
#endif /* CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA */

/*
 * flush all security policies within a VR
 * - 6WIND SVTI implementation: only delete global SPs
 * - vti tunnel implementation: delete all SPs (global and svti)
 */
int fp_sp_flush_by_vrfid(fp_spd_t *spd, uint16_t vrfid)
{
	uint32_t i;

	for (i=1; i < FP_MAX_SP_ENTRIES; i++) {
		if (spd->table[i].state != FP_SP_STATE_UNSPEC &&
#ifndef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
		    spd->table[i].svti_ifuid == 0 &&
#endif
		    spd->table[i].vrfid == vrfid) {
#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
			__fp_sp_entry_del(spd, i);
#else	
			__fp_sp_del(spd, i);
#endif
			fp_sp_release_index(spd, i);
		}
	}

	return 0;	
}

int fp_sa_flush(fp_sad_t *sad)
{
	uint32_t i;

	sad->count = 0;
	for (i = 1; i < FP_MAX_SA_ENTRIES; i++) {
		sad->table[i].state = FP_SA_STATE_UNSPEC;
		sad_stack[i-1] = i;
	}
	sad_stack_index = 0;

	sa_init_selector_hash(sad);

#ifdef IPSEC_SPI_HASH
	sa_init_hash(sad);
#endif
	return 0;
}

int fp_sa_flush_by_vrfid(fp_sad_t *sad, uint16_t vrfid)
{
	uint32_t i;
	
	for (i = 1; i < FP_MAX_SA_ENTRIES; i++) {
		if (sad->table[i].state != FP_SA_STATE_UNSPEC &&
		    sad->table[i].vrfid == vrfid) {
			__fp_sa_del(sad, i);
			sad->count--;
			fp_sa_release_index(i);
		}
	}

	return 0;
}

static uint32_t __fp_get_sp_by_rule_index(fp_spd_t *spd, fp_sp_entry_t *user_sp)
{
	uint32_t i;

	/* empty table? */
	if (spd->global_sp_count == 0)
		return 0;

#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
	if (fp_shared->ipsec.spd_hash_loc_plen ||
	    fp_shared->ipsec.spd_hash_rem_plen) {

		uint32_t h;

		if (spd->dir == FP_SPD_OUT) {
			if (user_sp->filter.src_plen < fp_shared->ipsec.spd_hash_loc_plen ||
	      		    user_sp->filter.dst_plen < fp_shared->ipsec.spd_hash_rem_plen)
			    goto unhashed;
			h = sp_addrvr2hash(user_sp->filter.src,
					user_sp->filter.dst,
					user_sp->vrfid,
					fp_shared->ipsec.spd_hash_loc_plen,
					fp_shared->ipsec.spd_hash_rem_plen);
		}
		else {
			if (user_sp->filter.dst_plen < fp_shared->ipsec.spd_hash_loc_plen ||
	      		    user_sp->filter.src_plen < fp_shared->ipsec.spd_hash_rem_plen)
			    goto unhashed;
			h = sp_addrvr2hash(user_sp->filter.dst,
					user_sp->filter.src,
					user_sp->vrfid,
					fp_shared->ipsec.spd_hash_loc_plen,
					fp_shared->ipsec.spd_hash_rem_plen);
		}

		fp_hlist_for_each(i, &spd->addr_hash[h], spd->table, addr_hlist) {
			if (spd->table[i].vrfid != user_sp->vrfid)
				continue;
			if (spd->table[i].rule_index == user_sp->rule_index)
				return i;
		}
		return 0;
	}
unhashed:
#endif

	fp_hlist_for_each(i, fp_get_spd_head(spd), spd->table, list) {
		if (spd->table[i].rule_index == user_sp->rule_index)
			return i;
	}
	return 0;
}

int fp_sp_update(fp_spd_t *spd, fp_sp_entry_t *user_sp)
{
	uint32_t idx;

	idx = __fp_get_sp_by_rule_index(spd, user_sp);

	if (idx != 0)
		__fp_sp_del(spd, idx);
	else if ((idx = fp_sp_get_index(spd)) == 0)
		return -1;

	return __fp_sp_add(spd, user_sp, idx);
}

int fp_sp_del(fp_spd_t *spd, fp_sp_entry_t *user_sp)
{
	uint32_t idx;

	idx = __fp_get_sp_by_rule_index(spd, user_sp);

	if (idx == 0)
		return -1;

	__fp_sp_del(spd, idx);
	fp_sp_release_index(spd, idx);

	return 0;
}

int fp_sp_del_by_index(fp_spd_t *spd, uint32_t idx)
{
	__fp_sp_del(spd, idx);
	fp_sp_release_index(spd, idx);

	return 0;
}

int fp_sa_del(fp_sad_t *sad, fp_sa_entry_t *user_sa)
{
	uint32_t i = __fp_sa_get(sad, user_sa->spi, user_sa->dst4, user_sa->proto, user_sa->vrfid);

	if (i == 0)
		return -1; /* not found */

 	__fp_sa_del(sad, i);
	sad->count--;

	return(i);
}

int fp_sa_del_by_index(fp_sad_t *sad, uint32_t i)
{
 	__fp_sa_del(sad, i);
	sad->count--;
	fp_sa_release_index(i);

	return 0;
}

static void fp_ipsec_init_algos(void)
{
	/* AH NULL algo  (NO USE)*/
	{
		fp_sa_ah_algo_t *alg = &fp_shared->sa_ah_algo[FP_AALGO_NULL];
		alg->hashsize = 0;
		alg->authsize = 0;
	}
	/* AH HMAC-MD5 algo */
	{
		fp_sa_ah_algo_t *alg = &fp_shared->sa_ah_algo[FP_AALGO_HMACMD5];
		alg->hashsize = 16;
		alg->authsize = 12;
	}
	/* AH HMAC-SHA1 algo */
	{
		fp_sa_ah_algo_t *alg = &fp_shared->sa_ah_algo[FP_AALGO_HMACSHA1];
		alg->hashsize = 20;
		alg->authsize = 12;
	}
	/* AES-XCBC-MAC algo */
	{
		fp_sa_ah_algo_t *alg = &fp_shared->sa_ah_algo[FP_AALGO_AESXCBC];
		alg->hashsize = 16;
		alg->authsize = 12;
	}
	/* AH HMAC-SHA256 algo */
	{
		fp_sa_ah_algo_t *alg = &fp_shared->sa_ah_algo[FP_AALGO_HMACSHA256];
		alg->hashsize = 32;
		alg->authsize = 16;
	}
	/* AH HMAC-SHA384 algo */
	{
		fp_sa_ah_algo_t *alg = &fp_shared->sa_ah_algo[FP_AALGO_HMACSHA384];
		alg->hashsize = 48;
		alg->authsize = 24;
	}
	/* AH HMAC-SHA512 algo */
	{
		fp_sa_ah_algo_t *alg = &fp_shared->sa_ah_algo[FP_AALGO_HMACSHA512];
		alg->hashsize = 64;
		alg->authsize = 32;
	}
	/* ESP NULL algo */
	{
		fp_sa_esp_algo_t *alg = &fp_shared->sa_esp_algo[FP_EALGO_NULL];
		alg->blocksize = 4;
		alg->ivlen = 0;
		alg->saltsize = 0;
		alg->authsize = 0;
	}
	/* ESP DES algo */
	{
		fp_sa_esp_algo_t *alg = &fp_shared->sa_esp_algo[FP_EALGO_DESCBC];
		alg->blocksize = 8;
		alg->ivlen = 8;
		alg->saltsize = 0;
		alg->authsize = 0;
	}
	/* ESP 3DES algo */
	{
		fp_sa_esp_algo_t *alg = &fp_shared->sa_esp_algo[FP_EALGO_3DESCBC];
		alg->blocksize = 8;
		alg->ivlen = 8;
		alg->saltsize = 0;
		alg->authsize = 0;
	}
	/* ESP AES algo */
	{
		fp_sa_esp_algo_t *alg = &fp_shared->sa_esp_algo[FP_EALGO_AESCBC];
		alg->blocksize = 16;
		alg->ivlen = 16;
		alg->saltsize = 0;
		alg->authsize = 0;
	}
	/* ESP AES GCM algo */
	{
		fp_sa_esp_algo_t *alg = &fp_shared->sa_esp_algo[FP_EALGO_AESGCM];
		alg->blocksize = 1;
		alg->ivlen = 8;
		alg->saltsize = 4;
		alg->authsize = 16;
	}
	/* ESP NULL AES GMAC algo */
	{
		fp_sa_esp_algo_t *alg = &fp_shared->sa_esp_algo[FP_EALGO_NULL_AESGMAC];
		alg->blocksize = 1;
		alg->ivlen = 8;
		alg->saltsize = 4;
		alg->authsize = 16;
	}
}

uint32_t fp_sad_find_acq(uint32_t src, uint32_t dst, uint16_t proto,
		uint8_t mode, uint32_t reqid,
		uint16_t vrfid, uint16_t xvrfid
#ifdef CONFIG_MCORE_IPSEC_SVTI
		, uint32_t svti_ifuid
#endif
		)
{
	fp_sad_t *sad = fp_get_sad();
	uint32_t i;
	uint16_t h;

	/* empty table? */
	if (sad->count == 0)
		return 0;

	/* find hash line */
	h = __sa_selector2hash(src, dst, proto, vrfid, xvrfid);

	/* follow hash list */
	fp_hlist_for_each(i, &sad->selector_hash[h], sad->table, selector_hlist) {
		if (sad->table[i].state == FP_SA_STATE_ACQUIRE &&
		    dst == sad->table[i].dst4 &&
		    src == sad->table[i].src4 &&
		    mode == sad->table[i].mode &&
		    proto == sad->table[i].proto &&
		    vrfid == sad->table[i].vrfid &&
		    xvrfid == sad->table[i].xvrfid &&
#ifdef CONFIG_MCORE_IPSEC_SVTI
		    svti_ifuid == sad->table[i].svti_ifuid &&
#endif
		    reqid == sad->table[i].reqid)
			return i;
	}

	/* not found */
	return 0;
}

#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
uint32_t fp_set_spd_conf(uint16_t spd_hash_loc_plen, uint16_t spd_hash_rem_plen)
{
	if (spd_hash_loc_plen > 32 || spd_hash_rem_plen > 32)
		return -1;

	fp_shared->ipsec.spd_hash_loc_plen = spd_hash_loc_plen;
	fp_shared->ipsec.spd_hash_rem_plen = spd_hash_rem_plen;

	return 0;
}
#endif

void fp_ipsec_init(void)
{
	/* bzero is enough to set state to UNSPEC (0) */

	bzero(&fp_shared->ipsec, sizeof(fp_shared->ipsec));
	fp_get_spd_in()->dir  = FP_SPD_IN;
	fp_get_spd_out()->dir = FP_SPD_OUT;
	fp_ipsec_init_algos();
#ifdef CONFIG_MCORE_IPSEC_TRIE
	fp_shared->ipsec.trie_out.index = 0;
	fp_shared->ipsec.trie_in.index = 1;
	fp_shared->ipsec.trie_to_update = 0;
	fp_shared->ipsec.trie_out.threshold = CONFIG_MCORE_IPSEC_TRIE_OUT_DEFAULT_THRESHOLD;
	fp_shared->ipsec.trie_in.threshold = CONFIG_MCORE_IPSEC_TRIE_IN_DEFAULT_THRESHOLD;
#endif
#ifdef CONFIG_MCORE_MULTIBLADE
	fp_shared->ipsec.sa_replay_sync_threshold = 32;
#endif
}

