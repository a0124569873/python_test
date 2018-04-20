/*
 * Copyright(c) 2006, 2007 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-ipsec-lookup.h"
#include "fp-log.h"

#define TRACE_IPSEC_LOOKUP(level, fmt, args...) do {			\
		FP_LOG(level, IPSEC_LOOKUP, fmt "\n", ## args);		\
} while(0)

/*
 * The CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE option enables to perform
 * input and output SPD lookup with a hash lookup based on
 * the remote IP address.
 *
 * This lookup method requires that:
 * - SP filters do not overlap
 * - SP filters remote address is in /32
 * Example:
 *   src=1.1.1.1/32 dst=2.2.2.0/24 proto=any dir=in
 *   src=2.2.2.0/24 dst=1.1.1.1/32 proto=any dir=out
 *
 * The use case is an IPsec server that terminates remote roadwarrior
 * connections
 */

#ifdef CONFIG_MCORE_IPSEC_TRIE

//#define CONFIG_EGTPC 1
//#define CONFIG_CLASSIF 1
#define CONFIG_RFC 1

#include "trie.h"

#ifdef CONFIG_EGTPC
#include "egt-pc/egt-pc.h"
#define trie_init   egtpc_init
#define trie_update egtpc_update
#define trie_final  egtpc_final
#define trie_lookup egtpc_lookup
#endif

#ifdef CONFIG_CLASSIF
#include "classif/classif_ipv4.h"
#define trie_init   classif_init
#define trie_update classif_update
#define trie_final  classif_final
#define trie_lookup classif_lookup
#endif

#ifdef CONFIG_RFC
#include "rfc/rfc.h"
#define trie_init rfc_init
#define trie_update rfc_update
#define trie_final rfc_final
#define trie_lookup rfc_lookup
#endif

FPN_DEFINE_SHARED(fp_ipsec_trie_zone_t, ipsec_tries[3]);
FPN_DEFINE_SHARED(struct callout, ipsec_trie_build_callout);
#endif /* CONFIG_MCORE_IPSEC_TRIE */

static inline int __selector_match(struct FILTER *filter,
		uint32_t src, uint32_t dst,
		uint8_t ul_proto,
		uint16_t sport, uint16_t dport)
{
	if (filter->ul_proto != FILTER_ULPROTO_ANY &&
			filter->ul_proto != ul_proto)
		return 0;
	if ((dst ^ filter->dst) & filter->dst_mask)
		return 0;
	if ((src ^ filter->src) & filter->src_mask)
		return 0;
#ifdef CONFIG_MCORE_IPSEC_LOOKUP_PORTS
	if ((sport ^ filter->srcport) & filter->srcport_mask)
		return 0;
	if ((dport ^ filter->dstport) & filter->dstport_mask)
		return 0;
#endif

	return 1;
}

/* 
 * perform a HASH lookup
 * if no matching SP is found, spd_index is not set
 */
#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
static inline uint32_t __spd_hash_lookup(fp_spd_t *spd, uint16_t hash,
		uint32_t src, uint32_t dst,
		uint8_t ul_proto,
		uint16_t sport, uint16_t dport,
		uint16_t vrfid)
{
	uint32_t idx;

	TRACE_IPSEC_LOOKUP(FP_LOG_DEBUG, "%s()", __FUNCTION__);

	fp_hlist_for_each(idx, &spd->addr_hash[hash], spd->table, addr_hlist) {
		if (spd->table[idx].vrfid != vrfid)
			continue;
		if (!__selector_match(&spd->table[idx].filter, src, dst, ul_proto, 
					sport, dport))
			continue;
		break;
	}

	return idx;
}
#endif

/*
 * perform a linear lookup 
 * return the SP index or 0 if no SP matched
 */
static inline uint32_t __spd_lookup(fp_spd_t *spd,
		uint32_t src, uint32_t dst,
		uint8_t ul_proto,
		uint16_t sport, uint16_t dport,
		uint16_t vrfid)
{
	uint32_t idx;

	fp_hlist_for_each(idx, fp_get_spd_head(spd), spd->table, list) {
		FPN_TRACK();
		if (spd->table[idx].vrfid != vrfid)
			continue;
		if (!__selector_match(&spd->table[idx].filter, src, dst, ul_proto,
				      sport, dport))
			continue;
		break;
	}

	return idx;
}

#ifdef CONFIG_MCORE_IPSEC_TRIE
/* 
 * update ipsec trie for SPD using IPSEC_TRIE_ZONE
 */
static inline fpn_uintptr_t
ipsec_update_trie(fp_spd_t *spd, fp_ipsec_trie_zone_t *ipsec_trie_zone)
{
	void *ctx;
	uint32_t i;

	if (ipsec_trie_zone->start == 0)
		return 0;

	ctx = trie_init((void *)ipsec_trie_zone->start, ipsec_trie_zone->size);
	if (unlikely(ctx == NULL))
		return 0;

	fp_hlist_for_each(i, fp_get_spd_head(spd), spd->table, list) {
		FPN_TRACK();
		if (unlikely(trie_update(&spd->table[i].filter, ctx) != 0))
			return 0;
	}
	if (unlikely(trie_final(ctx) != 0))
		return 0;

	return (fpn_uintptr_t)ctx;
}

void
fp_trie_check_update(void *arg)
{
	struct callout *co = (struct callout *)arg;
	uint32_t trie_to_use;
	fp_trie_t *trie;
	fp_spd_t *spd;
	uint16_t spd_version;
	fpn_uintptr_t ctx;

	/* check shared memory state */
	if (fp_shared->conf.w32.magic != FP_SHARED_MAGIC32)
		goto out_reschedule;

	/*
	 * Update at most one trie at each round.
	 * fp_shared->ipsec.trie_to_update specifies the trie to check first.
	 * If the first trie is up to date, then check the other one.
	 */
	trie_to_use = 3 - fp_shared->ipsec.trie_out.index - fp_shared->ipsec.trie_in.index;
	if (fp_shared->ipsec.trie_to_update == IPSEC_TRIE_OUT) {
		spd = fp_get_spd_out();
		trie = &fp_shared->ipsec.trie_out;
		if (spd->global_sp_count >= trie->threshold &&
		    trie->spd_version != trie->trie_version) {
			fp_shared->ipsec.trie_to_update = IPSEC_TRIE_IN;
			goto update_trie;
		}

		spd = fp_get_spd_in();
		trie = &fp_shared->ipsec.trie_in;
		if (spd->global_sp_count >= trie->threshold &&
		    trie->spd_version != trie->trie_version) {
			fp_shared->ipsec.trie_to_update = IPSEC_TRIE_OUT;
			goto update_trie;
		}
	} else {
		spd = fp_get_spd_in();
		trie = &fp_shared->ipsec.trie_in;
		if (spd->global_sp_count >= trie->threshold &&
				trie->spd_version != trie->trie_version) {
			fp_shared->ipsec.trie_to_update = IPSEC_TRIE_OUT;
			goto update_trie;
		}

		spd = fp_get_spd_out();
		trie = &fp_shared->ipsec.trie_out;
		if (spd->global_sp_count >= trie->threshold &&
				trie->spd_version != trie->trie_version) {
			fp_shared->ipsec.trie_to_update = IPSEC_TRIE_IN;
			goto update_trie;
		}
	}
	goto out_reschedule;

update_trie:
	spd_version = trie->spd_version;
	trie->building = 1;

	ctx = ipsec_update_trie(spd, &ipsec_tries[trie_to_use]);
	/*
	 * Always update trie_version to the spd_version we tried to build.
	 * If building failed, then unset the running flag: the SPD lookup
	 * will fall back to linear search.
	 * We will try to build the trie again if the SPD changes.
	 */
	trie->trie_version = spd_version;
	trie->index = trie_to_use;
	trie->ctx = ctx;
	trie->running = (ctx != 0);
	trie->building = 0;

	if (trie->running == 0)
		TRACE_IPSEC_LOOKUP(FP_LOG_ERR, "failed to build IPsec %s trie",
			spd->dir == FP_SPD_OUT ? "output" : "input");

 out_reschedule:
	callout_reset(co, 1, fp_trie_check_update, arg);
}
#endif	/* CONFIG_MCORE_IPSEC_TRIE */

fp_sp_entry_t *spd_in_lookup(uint32_t src, uint32_t dst, uint8_t ul_proto,
		uint16_t sport, uint16_t dport, uint16_t vrfid,
		uint32_t *spd_index)
{
	fp_spd_t *spd = fp_get_spd_in();
	uint32_t idx1 = 0, idx2 = 0, idx;

	if (likely(spd->entry_count == 0))
		return NULL;

#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
	if (spd->hashed_sp_count) {
		uint16_t hash;
		hash = sp_addrvr2hash(dst, src, vrfid,
			fp_shared->ipsec.spd_hash_loc_plen,
			fp_shared->ipsec.spd_hash_rem_plen);

		idx1 = __spd_hash_lookup(spd, hash, src, dst, ul_proto, 
		                  sport, dport, vrfid);
	}
#endif

	if (spd->unhashed_sp_count) {
#ifdef CONFIG_MCORE_IPSEC_TRIE
		if (spd->unhashed_sp_count >= fp_shared->ipsec.trie_in.threshold &&
		    fp_shared->ipsec.trie_in.running)
			trie_lookup((void *)fp_shared->ipsec.trie_in.ctx,
			            src, dst, ul_proto,
			            sport, dport, vrfid,
			            &idx2);
	else
#endif
		idx2 = __spd_lookup(spd, src, dst, ul_proto,
			     sport, dport, vrfid);
	}

	/* choose highest priority rule */
	if (idx1 && idx2) {
		if (spd->table[idx1].filter.cost <= spd->table[idx2].filter.cost)
			idx = idx1;
		else
			idx = idx2;
	}
	else
		/* one of idx1 or idx2 is null. idx1 ^ idx2 returns the other */
		idx = idx1 ^ idx2;

	if (idx) {
		if (spd_index)
			*spd_index = idx;
		return &spd->table[idx];
	}

	return NULL;
}

fp_sp_entry_t *spd_out_lookup(uint32_t src, uint32_t dst, uint8_t ul_proto,
		uint16_t sport, uint16_t dport, uint16_t vrfid)
{
	fp_spd_t *spd = fp_get_spd_out();
	uint32_t idx1 = 0, idx2 = 0, idx;

	if (likely(spd->entry_count == 0))
		return NULL;

#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
	if (spd->hashed_sp_count) {
		uint16_t hash;
		hash = sp_addrvr2hash(src, dst, vrfid,
			fp_shared->ipsec.spd_hash_loc_plen,
			fp_shared->ipsec.spd_hash_rem_plen);

		idx1 = __spd_hash_lookup(spd, hash, src, dst, ul_proto, 
			          sport, dport, vrfid);
	}
#endif

	if (spd->unhashed_sp_count) {
#ifdef CONFIG_MCORE_IPSEC_TRIE
		if (spd->unhashed_sp_count >= fp_shared->ipsec.trie_out.threshold &&
		    fp_shared->ipsec.trie_out.running)
			trie_lookup((void *)fp_shared->ipsec.trie_out.ctx,
			            src, dst, ul_proto,
			            sport, dport, vrfid,
			            &idx2);
		else
#endif
			idx2 = __spd_lookup(spd, src, dst, ul_proto,
					sport, dport, vrfid);
	}

	/* choose highest priority rule */
	if (idx1 && idx2) {
		if (spd->table[idx1].filter.cost <= spd->table[idx2].filter.cost)
			idx = idx1;
		else
			idx = idx2;
	}
	else
		/* one of idx1 or idx2 is null. idx1 ^ idx2 returns the other */
		idx = idx1 ^ idx2;

	if (idx)
		return &spd->table[idx];

	return NULL;
}

#ifdef IPSEC_SPI_HASH
fp_sa_entry_t *sad_in_lookup(uint32_t spi, uint32_t dst, uint8_t proto, uint16_t vrfid) 
{
	fp_sad_t *sad = fp_get_sad();
	fp_hlist_head_t *head;
	uint32_t i;

	/* empty table? */
	if (sad->count == 0)
		return NULL;

	/* find per spi hash line */
	head = &sad->spi_hash[sa_spi2hash(spi)];
	i = fp_hlist_first(head);

	/* best case: first hash entry matches triplet */
	if (likely((i != 0) &&
		   (sad->table[i].vrfid == vrfid) &&
	           (sad->table[i].spi == spi) &&
	           (sad->table[i].dst4 == dst) &&
	           (sad->table[i].proto == proto)))
	{
		if (likely(sad->table[i].state != FP_SA_STATE_UNSPEC))
			return &sad->table[i];
		else
			return NULL;
	}

	/* empty list? */
	if (i == 0)
		return NULL;

	/* bad luck, follow hash list */
	fp_hlist_for_each_continue(i, head, sad->table, spi_hlist) {
		if ((sad->table[i].vrfid == vrfid) &&
		    (sad->table[i].spi == spi) &&
		    (sad->table[i].dst4 == dst) &&
		    (sad->table[i].proto == proto))
		{
			FPN_TRACK();
			if (likely(sad->table[i].state != FP_SA_STATE_UNSPEC))
				return &sad->table[i];
			else
				return NULL;
		}
	}

	/* not found */
	return NULL;
}
#else
fp_sa_entry_t *sad_in_lookup(uint32_t spi, uint32_t dst, uint8_t proto, uint16_t vrfid)
{
	uint32_t i;
	uint32_t count;
	fp_sad_t *sad = fp_get_sad();
	count = sad->count;
	for (i = 1; count > 0 && i < FP_MAX_SA_ENTRIES; i++) {
		if (sad->table[i].state == FP_SA_STATE_UNSPEC)
			continue;
		count--;
		if (vrfid != sad->table[i].vrfid)
			continue;
		if (spi != sad->table[i].spi)
			continue;
		/* 
		 * RFC4301 section 5.2 3a: use only the SPI
		 * (We support only unicast destination in SA)
		 */
		if (dst != sad->table[i].dst)
			continue;
		if (proto != sad->table[i].proto)
			continue;

		return &sad->table[i];
	}
	return NULL;
}
#endif

fp_sa_entry_t *sad_out_lookup(uint32_t src, uint32_t dst, uint16_t proto,
			      uint8_t mode, uint32_t reqid, uint16_t vrfid, uint16_t xvrfid,
#if defined(CONFIG_MCORE_IPSEC_SVTI) && !defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
			      uint32_t svti_ifuid,
#endif
			      uint32_t *sa_index)
{
	fp_sad_t *sad = fp_get_sad();
	fp_hlist_head_t *head;
	uint32_t i;
	uint16_t h;

	/* empty table? */
	if (sad->count == 0)
		return NULL;

	/* find hash line */
	h = __sa_selector2hash(src, dst, proto, vrfid, xvrfid);
	head = &sad->selector_hash[h];
	i = fp_hlist_first(head);

	/* first hash entry matches */
	if (likely(i != 0 &&
		   dst == sad->table[i].dst4 &&
		   src == sad->table[i].src4 &&
		   mode == sad->table[i].mode &&
		   proto == sad->table[i].proto &&
	           vrfid == sad->table[i].vrfid &&
	           xvrfid == sad->table[i].xvrfid &&
#if defined(CONFIG_MCORE_IPSEC_SVTI) && !defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
		   svti_ifuid == sad->table[i].svti_ifuid &&
#endif
		   (!reqid || (reqid == sad->table[i].reqid)))) {
		if (likely(sad->table[i].state != FP_SA_STATE_UNSPEC)) {
			if (sa_index)
				*sa_index = i;
			return &sad->table[i];
		}
	}
	
	/* follow hash list */
	fp_hlist_for_each_continue(i, head, sad->table, selector_hlist) {
		if (dst == sad->table[i].dst4 &&
		    src == sad->table[i].src4 &&
		    mode == sad->table[i].mode &&
		    proto == sad->table[i].proto &&
		    vrfid == sad->table[i].vrfid &&
		    xvrfid == sad->table[i].xvrfid &&
#if defined(CONFIG_MCORE_IPSEC_SVTI) && !defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
		    svti_ifuid == sad->table[i].svti_ifuid &&
#endif
		    (!reqid || (reqid == sad->table[i].reqid))) {
			if (likely(sad->table[i].state != FP_SA_STATE_UNSPEC)) {
				if (sa_index)
					*sa_index = i;
				return &sad->table[i];
			}
		}
	}

	/* not found */
	return NULL;
}

#ifdef CONFIG_MCORE_IPSEC_SVTI
fp_sp_entry_t *spd_svti_out_lookup(uint32_t src, uint32_t dst, uint8_t ul_proto,
		uint16_t sport, uint16_t dport, fp_svti_t *svti)
{
	uint32_t i;
	fp_spd_t *spd;
	
	spd = fp_get_spd_out();
	
	fp_hlist_for_each(i, &svti->spd_out, spd->table, list) {
		FPN_TRACK();
		if (!__selector_match(&spd->table[i].filter, src, dst, ul_proto,
					sport, dport))
			continue;
		return &spd->table[i];
	}

	return NULL;
}

fp_sp_entry_t *spd_svti_in_lookup(uint32_t src, uint32_t dst, uint8_t ul_proto,
		uint16_t sport, uint16_t dport, fp_svti_t *svti, uint32_t *spd_index)
{
	uint32_t i;
	fp_spd_t *spd;
	
	spd = fp_get_spd_in();
	
	fp_hlist_for_each(i, &svti->spd_in, spd->table, list) {
		FPN_TRACK();
		if (!__selector_match(&spd->table[i].filter, src, dst, ul_proto,
					sport, dport))
			continue;
		if (spd_index)
			*spd_index = i;
		return &spd->table[i];
	}

	return NULL;
}
#endif /* CONFIG_MCORE_IPSEC_SVTI */

#if defined(CONFIG_MCORE_IPSEC) && defined(CONFIG_MCORE_IPSEC_TRIE)
#include "shmem/fpn-shmem.h"

static int fp_alloc_ipsec_trie(void)
{
	size_t size = CONFIG_MCORE_IPSEC_TRIE_ZONE_SIZE;

	fpn_shmem_add("TRIE0", size);
	ipsec_tries[0].size = size;
	ipsec_tries[0].start = (fpn_uintptr_t)fpn_shmem_mmap("TRIE0",
							     NULL,
							     size);
	if (ipsec_tries[0].start == 0)
		return -1;

	fpn_shmem_add("TRIE1", size);
	ipsec_tries[1].size = size;
	ipsec_tries[1].start = (fpn_uintptr_t)fpn_shmem_mmap("TRIE1",
							     NULL,
							     size);
	if (ipsec_tries[1].start == 0)
		return -1;

	fpn_shmem_add("TRIE2", size);
	ipsec_tries[2].size = size;
	ipsec_tries[2].start = (fpn_uintptr_t)fpn_shmem_mmap("TRIE2",
							     NULL,
							     size);
	if (ipsec_tries[2].start == 0)
		return -1;

	TRACE_IPSEC_LOOKUP(FP_LOG_DEBUG,
			   "ipsec_tries[0]=%llx size=%"PRIu64" MB"
			   "ipsec_tries[1]=%llx size=%"PRIu64" MB"
			   "ipsec_tries[2]=%llx size=%"PRIu64" MB\n",
			   (unsigned long long)ipsec_tries[0].start,
			   ipsec_tries[0].size / (1024*1024),
			   (unsigned long long)ipsec_tries[1].start,
			   ipsec_tries[1].size / (1024*1024),
			   (unsigned long long)ipsec_tries[2].start,
			   ipsec_tries[2].size / (1024*1024));

	return 0;
}

int fp_ipsec_trie_init(void)
{
	memset(ipsec_tries, 0, sizeof(ipsec_tries));
	if (fp_alloc_ipsec_trie() < 0) {
		fpn_printf("Error: cannot allocate memory for IPsec TRIE.\n");
		return -1;
	}

	/* Initialize timer to build IPsec tries */
	callout_init(&ipsec_trie_build_callout);
	return callout_reset(&ipsec_trie_build_callout, 0, fp_trie_check_update, &ipsec_trie_build_callout);
}

int fp_ipsec_trie_exit(void)
{
	/* Stop timer to build IPsec tries */
	return callout_stop(&ipsec_trie_build_callout);
}
#endif
