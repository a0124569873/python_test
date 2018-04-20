/*
 * Copyright(c) 2010 6WIND
 */

#ifndef __FP_NF6_CACHE_H__
#define __FP_NF6_CACHE_H__

#include "fp-nf-cache-common.h"

/* Order of netfilter cache hashtable. The number of buckets in the
 * table is 2 ^ order. The usual values are between 8 and 25 (above,
 * t will consume more memory without significant gain of
 * speed). It's usually a good idea to have the same value than
 * CONFIG_NF6_MAX_CACHE_ORDER, but not mandatory. */
#ifdef CONFIG_MCORE_NF6_CACHE_HASHTABLE_ORDER
#define FP_NF6_HASHTABLE_ORDER CONFIG_MCORE_NF6_CACHE_HASHTABLE_ORDER
#else
#define FP_NF6_HASHTABLE_ORDER  FP_NF6_MAX_CACHE_ORDER
#endif

#define FP_NF6_HASHTABLE_SIZE   (1<<FP_NF6_HASHTABLE_ORDER)
#define FP_NF6_HASHTABLE_MASK   (FP_NF6_HASHTABLE_SIZE-1)

/* init all cache structures */
void fp_nf6_cache_init(void);

/* Packet entry for nf_cache: lookup for a cached nf_rule and process
 * the packet. */
int fp_nf6_cache_input(struct mbuf *m, int hook, int table, const fp_ifnet_t *indev,
		      const fp_ifnet_t *outdev);

/* Add a new rule in cache */
void fp_nf6_cache_update(const struct mbuf *m, int hook, int table, const fp_ifnet_t *indev,
			const fp_ifnet_t *outdev);


FPN_DECLARE_PER_CORE(uint32_t, fp_nf6_cache_saved_hash);
FPN_DECLARE_PER_CORE(uint8_t, fp_nf6_cache_ct_state);
FPN_DECLARE_PER_CORE(uint8_t, fp_nf6_cache_flags);

#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE
FPN_DECLARE_PER_CORE(uint32_t, fp_nf6_cache_nb_rules);
FPN_DECLARE_PER_CORE(void *[FP_NF6_MAX_CACHED_RULES], fp_nf6_cached_rules_list);

/* On next call of fp_nf_cache_update(), don't store the entry in
 * cache. */
static inline void fp_nf6_cache_disable_next(void)
{
	FPN_PER_CORE_VAR(fp_nf6_cache_saved_hash) = NF_CACHE_INVALID_HASH;
}

/* On next call of fp_nf_cache_update(), set the wanted CT state for
 * this cache. */
static inline void fp_nf6_cache_next_need_ct_state(uint8_t state)
{
	FPN_PER_CORE_VAR(fp_nf6_cache_ct_state) = state;
}

/* On next call of fp_nf_cache_update(), set the wanted CT state for
 * this cache. */
static inline void fp_nf6_cache_set_flag(uint8_t flag)
{
	FPN_PER_CORE_VAR(fp_nf6_cache_flags) |= flag;
}

/* Add a new rule in the working cache */
static inline int fp_nf6_cache_add_rule(struct fp_nf6rule *rule)
{
	if (FPN_PER_CORE_VAR(fp_nf6_cache_nb_rules) >= FP_NF6_MAX_CACHED_RULES) {
		TRACE_NF_CACHE(FP_LOG_DEBUG, "%s() too many rules for the cache",
			       __FUNCTION__);
		fp_nf6_cache_disable_next();
		return -1;
	}

	/* If this rule is the first and target is standard with
	 * verdict ACCEPT, then we can set the flag DIRECT.
	 */
	if (FPN_PER_CORE_VAR(fp_nf6_cache_nb_rules) == 0 &&
	    rule->target.type == FP_NF_TARGET_TYPE_STANDARD &&
	    rule->target.data.standard.verdict == (-FP_NF_ACCEPT - 1))
		fp_nf6_cache_set_flag(FP_NF_CACHE_FLAG_DIRECT_ACCEPT);

#ifndef CONFIG_MCORE_NETFILTER_IPV6_CACHE_INTERMEDIATE_STATS
	/* Avoid storing rules where nothing should be done */
	if (rule->target.type == FP_NF_TARGET_TYPE_STANDARD &&
	    (rule->target.data.standard.verdict > 0 ||
	     rule->target.data.standard.verdict == FP_NF_IPT_RETURN))
		return 0;
#endif

	FPN_PER_CORE_VAR(fp_nf6_cached_rules_list)[FPN_PER_CORE_VAR(fp_nf6_cache_nb_rules)] = rule;
	FPN_PER_CORE_VAR(fp_nf6_cache_nb_rules)++;
	return 0;
}

/* If the rule cannot be cached, notify the cache. On next call of
 * fp_nf_cache_update(), we won't store the entry in cache. */
static inline void fp_nf6_cache_check_rule(struct fp_nf6rule *rule)
{
	if (unlikely((fp_shared->conf.w32.do_func & FP_CONF_DO_NF6_CACHE) == 0))
		return;

	switch (rule->target.type) {
	case FP_NF_TARGET_TYPE_STANDARD:
		/* Standard target allowed for: JUMP, RETURN and ACCEPT */
		if (rule->target.data.standard.verdict >= 0 ||
		    rule->target.data.standard.verdict == FP_NF_IPT_RETURN ||
		    rule->target.data.standard.verdict == (-FP_NF_ACCEPT - 1))
			return;
		break;
	case FP_NF_TARGET_TYPE_MARK_V2:
	case FP_NF_TARGET_TYPE_DSCP:
	case FP_NF_TARGET_TYPE_DEV:
		return;
	default:
		break;
	}

	/* All other targets won't be cached */
	fp_nf6_cache_disable_next();
}

static inline void fp_nf6_cache_check_update(const struct mbuf *m, int hook,
					    int table, const fp_ifnet_t *indev,
					    const fp_ifnet_t *outdev,
					    struct fp_nf6rule *rule, int verdict)
{
	/* cache is disabled */
	if (unlikely((fp_shared->conf.w32.do_func & FP_CONF_DO_NF6_CACHE)  == 0))
		return;

	/* nothing to do, fp_nf_cache_input() was not able to prepare
	 * infos for this packet or cache has been disabled */
	if (FPN_PER_CORE_VAR(fp_nf6_cache_saved_hash) == NF_CACHE_INVALID_HASH) {
		TRACE_NF_CACHE(FP_LOG_INFO, "%s() don't update cache", __FUNCTION__);
		return;
	}

	/* Try to add the rule */
	if (fp_nf6_cache_add_rule(rule) < 0)
		return;

	/* store in cache if this is the final rule */
	if (verdict != FP_NF_CONTINUE &&
	    verdict != FP_NF_REPEAT)
		fp_nf6_cache_update(m, hook, table, indev, outdev);
}
#else /* CONFIG_MCORE_NETFILTER_IPV6_CACHE */

#define fp_nf6_cache_disable_next() do {} while(0)
#define fp_nf6_cache_next_need_ct_state(state) do {} while(0)
#define fp_nf6_cache_set_flag(flag) do {} while(0)
#define fp_nf6_cache_check_rule(rule) do {} while(0)
#define fp_nf6_cache_add_rule(rule) do {} while(0)
#define fp_nf6_cache_check_update(m, hook, table, indev, outdev, rule,	\
				 verdict) do {} while(0)

#endif /* CONFIG_MCORE_NETFILTER_IPV6_CACHE */

#endif /* __FP_NF6_CACHE_H__ */
