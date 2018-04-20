/*
 * Copyright(c) 2010 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"
#include "fp-jhash.h"

#include "fp-dscp.h"
#include "fp-nfct.h"
#include "fp-nf-tables.h"
#include "fp-nf6-tables.h"
#include "netinet/fp-udp.h"
#include "netinet/fp-tcp.h"
#include "netinet/fp-icmp6.h"
#include "netinet/fp-sctp.h"
#include "fp-main-process.h"
#include "fp-ip.h"
#include "fp-ip6.h"

#include "fp-nf-cache-common-funcs.h"

/* the cache hashtable */
static FPN_DEFINE_SHARED(fp_nf_cache_bucket_t[FP_NF6_HASHTABLE_SIZE], fp_nf6_hashtable);

/* always keep 64 free entries in table */
#define FP_NF6_NUM_FREE_CACHE_ENTRIES 64

/* the index of the last entry that was inserted in the cache */
static FPN_DEFINE_SHARED(fpn_atomic_t, fp_nf6_cache_newest_idx);

/* We store the hash between the calls of fp_nf_cache_input() and
 * fp_nf_cache_update(). It can be resetted by
 * fp_nf_cache_disable_next() if we browse an intermediate rule
 * that forbid to use cache. */
FPN_DEFINE_PER_CORE(uint32_t, fp_nf6_cache_saved_hash);

/* Same for mask descriptor */
FPN_DEFINE_PER_CORE(const struct fp_nf_cache_mask *, fp_nf6_cache_saved_mask);

/* Same for DSCP (remember that it can be updated). */
FPN_DEFINE_PER_CORE(uint8_t, fp_nf6_cache_saved_dscp);

/* We store the ct state if at least one intermediate rule needs to
 * update the state. It is set by fp_nf_cache_next_need_ct_state(). */
FPN_DEFINE_PER_CORE(uint8_t, fp_nf6_cache_ct_state);

/* specific flags giving informations about current cache entry. */
FPN_DEFINE_PER_CORE(uint8_t, fp_nf6_cache_flags);

/* number of rules cached for the current flow */
FPN_DEFINE_PER_CORE(uint32_t, fp_nf6_cache_nb_rules);

/* pointer the cached rules for an entry */
FPN_DEFINE_PER_CORE(void *[FP_NF6_MAX_CACHED_RULES], fp_nf6_cached_rules_list);

/**** Mask templates for IPv6. Need to be 32 bits aligned. */

struct fp_nf_cache_tcp6_mask {
	struct fp_ip6_hdr ip6;
	struct fp_tcphdr tcp;
} __attribute__ ((aligned(4)));
static const struct fp_nf_cache_tcp6_mask tcp6_mask = {
	.ip6 = {
		{
		.ip6_ctlun = {
			.ip6_un1 = {
#if FPN_BYTE_ORDER == FPN_LITTLE_ENDIAN
				.ip6_un1_flow = 0x00000fff,
#endif
#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
				.ip6_un1_flow = 0xfff00000,
#endif
				.ip6_un1_plen = 0,
				.ip6_un1_nxt = 0xff,
				.ip6_un1_hlim = 0,
			},
		}
		},
		.ip6_src = {
			.in6_u = {
				.u6_addr32[0 ... 3] = 0xffffffff,
			},
		},
		.ip6_dst = {
			.in6_u = {
				.u6_addr32[0 ... 3] = 0xffffffff,
			},
		},
	},
	.tcp = {
		.th_sport = 0xffff,
		.th_dport = 0xffff,
		.th_seq = 0,
		.th_ack = 0,
		.th_off  = 0,
		.th_x2 = 0,
		.th_flags = TH_ACK|TH_PUSH,
	 	.th_win = 0,
	/* not included in structure to keep space */
	/* 	.th_sum = 0, */
	/* 	.th_urp = 0, */
	},
};
#define TCP6_MASK_LEN (sizeof(tcp6_mask)-4) /* 2 fields (uint16_t) are removed */

struct fp_nf_cache_udp6_mask {
	struct fp_ip6_hdr ip6;
	struct fp_udphdr udp;
} __attribute__ ((aligned(4)));
static const struct fp_nf_cache_udp6_mask udp6_mask = {
	.ip6 = {
		{
		.ip6_ctlun = {
			.ip6_un1 = {
#if FPN_BYTE_ORDER == FPN_LITTLE_ENDIAN
				.ip6_un1_flow = 0x00000fff,
#endif
#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
				.ip6_un1_flow = 0xfff00000,
#endif
				.ip6_un1_plen = 0,
				.ip6_un1_nxt = 0xff,
				.ip6_un1_hlim = 0,
			},
		}
		},
		.ip6_src = {
			.in6_u = {
				.u6_addr32[0 ... 3] = 0xffffffff,
			},
		},
		.ip6_dst = {
			.in6_u = {
				.u6_addr32[0 ... 3] = 0xffffffff,
			},
		},
	},
	.udp = {
		.uh_sport = 0xffff,
		.uh_dport = 0xffff,
		.uh_sum = 0,
		.uh_ulen = 0,
	},
};
#define UDP6_MASK_LEN (sizeof(udp6_mask))

struct fp_nf_cache_icmp6_mask {
	struct fp_ip6_hdr ip6;
	struct fp_icmp6_hdr icmp6;
} __attribute__ ((aligned(4)));
static const struct fp_nf_cache_icmp6_mask icmp6_mask = {
	.ip6 = {
		{
		.ip6_ctlun = {
			.ip6_un1 = {
#if FPN_BYTE_ORDER == FPN_LITTLE_ENDIAN
				.ip6_un1_flow = 0x00000fff,
#endif
#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
				.ip6_un1_flow = 0xfff00000,
#endif
				.ip6_un1_plen = 0,
				.ip6_un1_nxt = 0xff,
				.ip6_un1_hlim = 0,
			},
		}
		},
		.ip6_src = {
			.in6_u = {
				.u6_addr32[0 ... 3] = 0xffffffff,
			},
		},
		.ip6_dst = {
			.in6_u = {
				.u6_addr32[0 ... 3] = 0xffffffff,
			},
		},
	},
	.icmp6 = {
		.icmp6_type = 0xff,
		.icmp6_code = 0xff,
		.icmp6_cksum = 0,
		.icmp6_dataun = {
			.icmp6_un_data16[0 ... 1] = 0,
		},
	},
};
#define ICMP6_MASK_LEN (sizeof(icmp6_mask))

struct fp_nf_cache_sctp6_mask {
	struct fp_ip6_hdr ip6;
	struct fp_sctphdr sctp;
} __attribute__ ((aligned(4)));
static const struct fp_nf_cache_sctp6_mask sctp6_mask = {
	.ip6 = {
		{
		.ip6_ctlun = {
			.ip6_un1 = {
#if FPN_BYTE_ORDER == FPN_LITTLE_ENDIAN
				.ip6_un1_flow = 0x00000fff,
#endif
#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
				.ip6_un1_flow = 0xfff00000,
#endif
				.ip6_un1_plen = 0,
				.ip6_un1_nxt = 0xff,
				.ip6_un1_hlim = 0,
			},
		}
		},
		.ip6_src = {
			.in6_u = {
				.u6_addr32[0 ... 3] = 0xffffffff,
			},
		},
		.ip6_dst = {
			.in6_u = {
				.u6_addr32[0 ... 3] = 0xffffffff,
			},
		},
	},
	.sctp = {
		.src_port  = 0xffff,
		.dest_port = 0xffff,
		.v_tag = 0,
		.checksum = 0,
	},
};
#define SCTP6_MASK_LEN (sizeof(sctp6_mask))

struct fp_nf_cache_ip6_mask {
	struct fp_ip6_hdr ip6;
} __attribute__ ((aligned(4)));
static const struct fp_nf_cache_ip6_mask ip6_mask = {
	.ip6 = {
		{
		.ip6_ctlun = {
			.ip6_un1 = {
#if FPN_BYTE_ORDER == FPN_LITTLE_ENDIAN
				.ip6_un1_flow = 0x00000fff,
#endif
#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
				.ip6_un1_flow = 0xfff00000,
#endif
				.ip6_un1_plen = 0,
				.ip6_un1_nxt = 0xff,
				.ip6_un1_hlim = 0,
			},
		}
		},
		.ip6_src = {
			.in6_u = {
				.u6_addr32[0 ... 3] = 0xffffffff,
			},
		},
		.ip6_dst = {
			.in6_u = {
				.u6_addr32[0 ... 3] = 0xffffffff,
			},
		},
	},
};
#define IP6_MASK_LEN (sizeof(ip6_mask))

/**** mask descriptors */

static const struct fp_nf_cache_mask tcp6_mask_desc = {
	.mask = (const uint32_t *) &tcp6_mask,
	.len32 = TCP6_MASK_LEN/4,
};

static const struct fp_nf_cache_mask udp6_mask_desc = {
	.mask = (const uint32_t *) &udp6_mask,
	.len32 = UDP6_MASK_LEN/4,
};

static const struct fp_nf_cache_mask icmp6_mask_desc = {
	.mask = (const uint32_t *) &icmp6_mask,
	.len32 = ICMP6_MASK_LEN/4,
};

static const struct fp_nf_cache_mask sctp6_mask_desc = {
	.mask = (const uint32_t *) &sctp6_mask,
	.len32 = SCTP6_MASK_LEN/4,
};

static const struct fp_nf_cache_mask ip6_mask_desc = {
	.mask = (const uint32_t *) &ip6_mask,
	.len32 = IP6_MASK_LEN/4,
};

/* * * */

void fp_nf6_cache_init(void)
{
	int i;

	FPN_BUILD_BUG_ON(TCP6_MASK_LEN > (FP_NF6_CACHED_HDR_LEN_32 * 4));
	FPN_BUILD_BUG_ON(UDP6_MASK_LEN > (FP_NF6_CACHED_HDR_LEN_32 * 4));
	FPN_BUILD_BUG_ON(ICMP6_MASK_LEN > (FP_NF6_CACHED_HDR_LEN_32 * 4));
	FPN_BUILD_BUG_ON(IP6_MASK_LEN > (FP_NF6_CACHED_HDR_LEN_32 * 4));

	TRACE_NF_CACHE(FP_LOG_INFO, "Init fp_nf6_cache");

	fpn_atomic_set(&fp_nf6_cache_newest_idx, 0);

#ifdef CONFIG_MCORE_M_TAG
	nfm_tag_type = m_tag_type_register(NFM_TAG_NAME);
	if (nfm_tag_type < 0) {
		TRACE_NF_CACHE(FP_LOG_ERR, "Cannot register tag type for '"
			       NFM_TAG_NAME "'");
	}
#endif
	for (i=0; i<FP_NF6_HASHTABLE_SIZE; i++) {
		fp_nf6_hashtable[i].head = IDX_NONE;
		fpn_spinlock_init(&fp_nf6_hashtable[i].lock);
	}
	/* init the cache entries in fp_shared */
	for (i=0; i<FP_NF6_MAX_CACHE_SIZE; i++) {
		fp_shared->fp_nf6_rule_cache[i].next = IDX_NONE;
		fp_shared->fp_nf6_rule_cache[i].state = FP_NF_CACHE_STATE_FREE;
	}
	fp_shared->fp_nf6_cache_base_addr = (fpn_uintptr_t)fp_shared->fp_nf6_tables;
}

static inline uint32_t fp_nf6_cache_alloc(int pair)
{
	uint32_t free_cache, oldest;

	if (pair) {
		/* Reserve two slots */
		free_cache = fpn_atomic_add_return(&fp_nf6_cache_newest_idx, 2);
		/* If the second slot is at the beginning of the table, the set
		 * of two slots isn't contiguous. We'll have to re-allocate again.
		 */
		while (!(free_cache & FP_NF6_MAX_CACHE_MASK)) {
			/* With the ring and % operation, a -1 isn't really safe
			 * but here we can have absolute locations of slots free.
			 */
			fp_shared->fp_nf6_rule_cache[FP_NF6_MAX_CACHE_MASK - 1].state =
				FP_NF_CACHE_STATE_FREE;
			fp_shared->fp_nf6_rule_cache[FP_NF6_MAX_CACHE_MASK].state =
				FP_NF_CACHE_STATE_FREE;
			free_cache = fpn_atomic_add_return(&fp_nf6_cache_newest_idx, 2);
		}
		/* Now we can safely substract one to have the beginning of the set of
		 * two slots.
		 */
		free_cache = free_cache - 1;
		oldest = free_cache + FP_NF6_NUM_FREE_CACHE_ENTRIES;
		free_cache &= FP_NF6_MAX_CACHE_MASK;
		oldest &= FP_NF6_MAX_CACHE_MASK;
		fp_shared->fp_nf6_rule_cache[oldest].state = FP_NF_CACHE_STATE_FREE;
		oldest++;
		oldest &= FP_NF6_MAX_CACHE_MASK;
		fp_shared->fp_nf6_rule_cache[oldest].state = FP_NF_CACHE_STATE_FREE;
	} else {
		/* Free the oldest entry, and return a new one */
		free_cache = fpn_atomic_add_return(&fp_nf6_cache_newest_idx, 1);
		oldest = free_cache + FP_NF6_NUM_FREE_CACHE_ENTRIES;
		free_cache &= FP_NF6_MAX_CACHE_MASK;
		oldest &= FP_NF6_MAX_CACHE_MASK;
		fp_shared->fp_nf6_rule_cache[oldest].state = FP_NF_CACHE_STATE_FREE;
	}

	return free_cache;
}

/* Return a hash for this flow. The argument is a packet starting at
 * IP layer. We assume that the packet is accessible in a contiguous
 * memory of 'contiguous_size'. Also fill the mask_desc argument
 * according to the packet m. Return NF_CACHE_INVALID_HASH on error. */
static inline uint32_t fp_nf6_cache_l3l4hash(const struct fp_ip6_hdr *ip6,
					     unsigned int contiguous_size,
					     const struct fp_nf_cache_mask **mask_desc,
					     int hook, int table)
{
	uint32_t a, b, c=0;

	if (unlikely(contiguous_size < sizeof(*ip6)))
		return NF_CACHE_INVALID_HASH;

	/*FIXME: confirm the value of a, b*/
	a = ip6->ip6_src.fp_s6_addr32[0] ^ ip6->ip6_src.fp_s6_addr32[1] ^ ip6->ip6_src.fp_s6_addr32[2] ^ ip6->ip6_src.fp_s6_addr32[3];
	b = ip6->ip6_dst.fp_s6_addr32[0] ^ ip6->ip6_dst.fp_s6_addr32[1] ^ ip6->ip6_dst.fp_s6_addr32[2] ^ ip6->ip6_dst.fp_s6_addr32[3];
	c = (table << 28) | (hook << 24);
	switch (ip6->ip6_nxt) {
	case FP_IPPROTO_TCP: {
		const struct fp_tcphdr *tcp = (const struct fp_tcphdr *)(ip6 + 1);
		if (unlikely(contiguous_size < TCP6_MASK_LEN))
			return NF_CACHE_INVALID_HASH;
		if (unlikely(tcp->th_flags & (TH_SYN|TH_RST|TH_FIN))) /* no cache for these pkts */
			return NF_CACHE_INVALID_HASH;
		c ^= tcp->th_sport + ((uint32_t)tcp->th_dport << 16);
		c ^= ((uint32_t)(tcp->th_flags & TH_ACK) << 27) | ((tcp->th_flags & TH_PUSH) << 12);
		*mask_desc = &tcp6_mask_desc;
		break;
	}
	case FP_IPPROTO_UDP: {
		const struct fp_udphdr *udp = (const struct fp_udphdr *)(ip6 + 1);
		if (unlikely(contiguous_size < UDP6_MASK_LEN))
			return NF_CACHE_INVALID_HASH;
		c ^= udp->uh_sport + ((uint32_t)udp->uh_dport << 16);
		*mask_desc = &udp6_mask_desc;
		break;
	}
	case FP_IPPROTO_ICMPV6: {
		const struct fp_icmp6_hdr *icmp6 = (const struct fp_icmp6_hdr *)(ip6 + 1);
		if (unlikely(contiguous_size < ICMP6_MASK_LEN))
			return NF_CACHE_INVALID_HASH;
		c ^= icmp6->icmp6_type + ((uint32_t)icmp6->icmp6_code << 16);
		*mask_desc = &icmp6_mask_desc;
		break;
	}
	case FP_IPPROTO_SCTP: {
		const struct fp_sctphdr *sctp = (const struct fp_sctphdr *)(ip6 + 1);
		if (unlikely(contiguous_size < SCTP6_MASK_LEN))
			return NF_CACHE_INVALID_HASH;
		c ^= sctp->src_port + ((uint32_t)sctp->dest_port << 16);
		*mask_desc = &sctp6_mask_desc;
		break;
	}
	default:
		*mask_desc = &ip6_mask_desc;
		break;
	}

	fp_jhash_mix(a, b, c);

	return c & FP_NF6_HASHTABLE_MASK;
}

/* Dequeue an entry from a hashtable bucket. It can fail if we cannot
 * acquire the lock (very rare). In this case, we return -1. Return 0
 * on success.*/
static inline int fp_nf6_cache_dequeue(uint32_t idx, uint32_t locked_hash)
{
	uint32_t hash;
	uint32_t *prev;
	fp_nf6_rule_cache_entry_t *cache;
	const struct fp_nf_cache_mask *mask_desc; /* not used */
	int do_lock;

	cache = &fp_shared->fp_nf6_rule_cache[idx];

	/* If entry is not in hash table, don't try to dequeue it */
	if (!(cache->flags & FP_NF_CACHE_FLAG_IN_HASH_TABLE))
		return 0;

	hash = fp_nf6_cache_l3l4hash((const struct fp_ip6_hdr *)(cache->hdr),
				    cache->hdr_len32 << 2, &mask_desc,
				    cache->hook_num, cache->table_num);

	/* If cache entry is not part of any hash list, cache->hdr_len32
	 * is 0 and hash function returns invalid hash.
	 */
	if (hash == NF_CACHE_INVALID_HASH)
		return 0;

	do_lock = (hash != locked_hash);
	/* if we cannot take the lock, update cache next time */
	if (do_lock && !fpn_spinlock_trylock(&fp_nf6_hashtable[hash].lock)) {
		TRACE_NF_CACHE(FP_LOG_NOTICE, "%s() list already locked", __FUNCTION__);
		return -1;
	}

	prev = &fp_nf6_hashtable[hash].head;
	while (*prev != idx && *prev != IDX_NONE) {
		FPN_TRACK();
		cache = &fp_shared->fp_nf6_rule_cache[*prev];
		prev = &cache->next;
	}
	if (*prev != IDX_NONE) {
		cache = &fp_shared->fp_nf6_rule_cache[*prev];
		*prev = cache->next;
	}
	if (do_lock)
		fpn_spinlock_unlock(&fp_nf6_hashtable[hash].lock);
	return 0;
}

/* process cached non-standard targets */
static inline int fp_nf6_cache_process_one_rule(struct mbuf *m,
						fp_nf6_rule_cache_entry_t *cache,
						struct fp_nf6rule *rule)
{
	switch (rule->target.type) {
	case FP_NF_TARGET_TYPE_STANDARD:
		if (rule->target.data.standard.verdict < 0) {
			if (rule->target.data.standard.verdict == FP_NF_IPT_RETURN)
				return FP_NF_CONTINUE;
			else
				return FP_NF_ACCEPT; /* only accept rules are stored */
		} else {
			/* It's a jump, nothing to do */
			return FP_NF_CONTINUE;
		}
	case FP_NF_TARGET_TYPE_DEV: {
		fp_ifnet_t *ifp;
		int ret = FP_DROP; /* not FP_NF_DROP */;

#ifdef CONFIG_MCORE_M_TAG
		/* set mark if needed */
		if (rule->target.data.dev.flags & FP_NF_DEV_FLAG_SET_MARK)
			m_tag_add(m, nfm_tag_type, htonl(rule->target.data.dev.mark));
#endif

		/* send packet to device */
		ifp = fp_fast_getifnetbyname(rule->target.data.dev.ifname,
					     rule->target.data.dev.ifname_hash,
					     rule->target.data.dev.ifname_len);
		if (likely(ifp != NULL && !FP_IS_IFTYPE_ETHER(ifp->if_type)))
			ret = FPN_HOOK_CALL(fp_ip_inetif_send)(m, ifp);

		fp_process_input_finish(m, ret);
		return FP_NF_STOLEN;
	}
	case FP_NF_TARGET_TYPE_MARK_V2:
		fp_nf_update_mark(m, rule->target.data.mark.mark,
				  rule->target.data.mark.mask);
		return FP_NF_CONTINUE;
	case FP_NF_TARGET_TYPE_DSCP:
		fp_change_ipv6_dscp(mtod(m, struct fp_ip6_hdr *),
				    rule->target.data.dscp.dscp);
		return FP_NF_CONTINUE;
	default:
		/* should not happen */
		TRACE_NF_CACHE(FP_LOG_ERR, "%s: Invalid rule in the cache (type: %u)",
			       __FUNCTION__, rule->target.type);
		cache->state = FP_NF_CACHE_STATE_FREE;
		FPN_PER_CORE_VAR(fp_nf6_cache_saved_hash) = NF_CACHE_INVALID_HASH;
		return FP_NF_CONTINUE;
	}
}

/* Packet entry for nf_cache: lookup for a cached nf_rule and process
 * the packet. */
int fp_nf6_cache_input(struct mbuf *m, int hook, int table, const fp_ifnet_t *indev,
		      const fp_ifnet_t *outdev)
{
	uint32_t hash, idx, i;
	const struct fp_nf_cache_mask *mask_desc = NULL;

	TRACE_NF_CACHE(FP_LOG_INFO, "%s(hook=%d, table=%d)", __FUNCTION__, hook, table);

	/* Get the hash of the packet, only AF_INET for now */
	hash = fp_nf6_cache_l3l4hash(mtod(m, const struct fp_ip6_hdr *), m_headlen(m),
				    &mask_desc, hook, table);
	if (unlikely(hash == NF_CACHE_INVALID_HASH)) {
		FPN_PER_CORE_VAR(fp_nf6_cache_saved_hash) = NF_CACHE_INVALID_HASH;
		return FP_NF_CONTINUE;
	}

	TRACE_NF_CACHE(FP_LOG_DEBUG, "%s() hash=%x", __FUNCTION__, hash);

	/* Browse the list hashtable and try to fully match entries */
	idx = fp_nf_cache_get(&fp_nf6_hashtable[hash], 0, m, mask_desc, hook, table, indev, outdev, AF_INET6);

	/* An entry was found in cache, return the verdict of the rule */
	if (likely(idx != IDX_NONE)) {
		struct fp_nf6rule *rule;
		fp_nf6_rule_cache_entry_t *cache;

		cache = &fp_shared->fp_nf6_rule_cache[idx];
		rule = (struct fp_nf6rule *)cache->rule6;
		TRACE_NF_CACHE(FP_LOG_INFO, "%s() Found entry index=%d", __FUNCTION__, idx);
		FPN_PREFETCH(rule);

		if (cache->ct_state) {
			struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
			if (!m_priv(m)->fp_nfct_established)
				m_priv(m)->fp_nfct_established = fp_nf6ct_update(m, 0, ip6->ip6_nxt, sizeof(struct fp_ip6_hdr));
			if (m_priv(m)->fp_nfct_established != cache->ct_state) {
				cache->state = FP_NF_CACHE_STATE_FREE;
				FPN_PER_CORE_VAR(fp_nf6_cache_saved_hash) = NF_CACHE_INVALID_HASH;
				return FP_NF_CONTINUE;
			}
		}

		if (likely(cache->flags & FP_NF_CACHE_FLAG_DIRECT_ACCEPT)) {
			FP_NF_STATS_INC(rule->stats, pcnt);
			FP_NF_STATS_ADD(rule->stats, bcnt, m_len(m));
			return FP_NF_ACCEPT;
		}

		if (cache->flags & FP_NF_CACHE_FLAG_MORE_RULES) {
			fp_nf6_rule_cache_extended_entry_t *ext_cache =
				(fp_nf6_rule_cache_extended_entry_t *)cache;

			/* If everything is ok, all rules return FP_NF_CONTINUE
			 * during this loop.
			 */
			for (i = 0; i < ext_cache->ext_nbrules; i++) {
#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE_INTERMEDIATE_STATS
				FP_NF_STATS_INC(((struct fp_nf6rule *)ext_cache->ext_rule6[i])->stats, pcnt);
				FP_NF_STATS_ADD(((struct fp_nf6rule *)ext_cache->ext_rule6[i])->stats, bcnt, m_len(m));
#endif
				fp_nf6_cache_process_one_rule(m, cache,
							      (struct fp_nf6rule *)ext_cache->ext_rule6[i]);
			}
		}
		FP_NF_STATS_INC(rule->stats, pcnt);
		FP_NF_STATS_ADD(rule->stats, bcnt, m_len(m));
		return fp_nf6_cache_process_one_rule(m, cache, rule);
	}

	TRACE_NF_CACHE(FP_LOG_DEBUG, "%s() no entry found", __FUNCTION__);

	/* save the hash and mask for future use in fp_nf_cache_update() */
	FPN_PER_CORE_VAR(fp_nf6_cache_saved_hash) = hash;
	FPN_PER_CORE_VAR(fp_nf6_cache_saved_mask) = mask_desc;
	FPN_PER_CORE_VAR(fp_nf6_cache_saved_dscp) = (ntohs(mtod(m, uint16_t *)[0]) >> 4) & FP_DSCP_MASK;
	FPN_PER_CORE_VAR(fp_nf6_cache_ct_state) = 0;
	FPN_PER_CORE_VAR(fp_nf6_cache_flags) = 0;
	FPN_PER_CORE_VAR(fp_nf6_cache_nb_rules) = 0;

	/* process with normal flow */
	return FP_NF_CONTINUE;
}

/* Add a new rule in cache. We assume that fp_nf6_cache_saved_hash !=
 * NF_CACHE_INVALID_HASH, it is checked in fp_nf6_cache_check_update() */
void fp_nf6_cache_update(const struct mbuf *m, int hook, int table, const fp_ifnet_t *indev,
			const fp_ifnet_t *outdev)
{
	fp_nf6_rule_cache_entry_t *cache;
	const struct fp_nf_cache_mask *mask_desc = NULL;
	uint32_t hash = FPN_PER_CORE_VAR(fp_nf6_cache_saved_hash);
	uint32_t idx;
	int i, nbrules;
	uint32_t *pkt;
	uint8_t dscp;

	mask_desc = FPN_PER_CORE_VAR(fp_nf6_cache_saved_mask);

	/* restore original DSCP: this is needed to get the right entry with
	 * fp_nf_cache_get() and after to store the right pkt hdr.
	 */
	dscp = (ntohs(mtod(m, uint16_t *)[0]) >> 4) & FP_DSCP_MASK;
	fp_change_ipv6_dscp(mtod(m, struct fp_ip6_hdr *), FPN_PER_CORE_VAR(fp_nf6_cache_saved_dscp));

	/* if we cannot take the lock, update cache next time */
	if (!fpn_spinlock_trylock(&fp_nf6_hashtable[hash].lock)) {
		TRACE_NF_CACHE(FP_LOG_NOTICE, "%s() list already locked", __FUNCTION__);
		goto out;
	}

	/* Check that the entry is not already there (added by another
	 * core at the same time). We must do this with the lock held. */
	idx = fp_nf_cache_get(&fp_nf6_hashtable[hash], 1, m, mask_desc, hook, table, indev, outdev, AF_INET6);

	/* An entry was found, unlock and return */
	if (idx != IDX_NONE) {
		fpn_spinlock_unlock(&fp_nf6_hashtable[hash].lock);
		TRACE_NF_CACHE(FP_LOG_NOTICE, "%s() entry already there", __FUNCTION__);
		goto out;
	}

	nbrules = FPN_PER_CORE_VAR(fp_nf6_cache_nb_rules);

	/* Reserve a new entry for this flow. Once allocated, we
	 * cannot free it so we must use it. */
	idx = fp_nf6_cache_alloc((nbrules > 1));

	/* Remove the entry from the hashtable bucket. If it fails
	 * (rare), the allocated entry won't be used. */
	if (fp_nf6_cache_dequeue(idx, hash) < 0) {
		fpn_spinlock_unlock(&fp_nf6_hashtable[hash].lock);
		TRACE_NF_CACHE(FP_LOG_NOTICE, "%s() cannot dequeue", __FUNCTION__);
		goto out;
	}
	if (nbrules > 1 &&
	    fp_nf6_cache_dequeue(idx + 1, hash) < 0) {
		fpn_spinlock_unlock(&fp_nf6_hashtable[hash].lock);
		TRACE_NF_CACHE(FP_LOG_NOTICE, "%s() cannot dequeue (2)", __FUNCTION__);
		goto out;
	}

	/* Fill the all the flow informations in entry. */
	cache = &fp_shared->fp_nf6_rule_cache[idx];
	cache->flags = FPN_PER_CORE_VAR(fp_nf6_cache_flags);
	cache->hdr_len32 = mask_desc->len32;
	cache->hook_num = hook;
	cache->table_num = table;
	/* Always last rule is saved here */
	cache->rule6 = (fpn_uintptr_t)FPN_PER_CORE_VAR(fp_nf6_cached_rules_list)[nbrules - 1];
	cache->in_ifuid =  indev ? indev->if_ifuid : 0;
	cache->out_ifuid = outdev ? outdev->if_ifuid : 0;
	cache->vrid = m2vrfid(m);
	cache->ct_state = FPN_PER_CORE_VAR(fp_nf6_cache_ct_state);
	pkt = mtod(m, uint32_t *);
	for (i=0; i<cache->hdr_len32; i++) {
		FPN_TRACK();
		cache->hdr[i] = (mask_desc->mask[i] & pkt[i]);
	}
	if (nbrules > 1) {
		fp_nf6_rule_cache_extended_entry_t *ext_cache =
			(fp_nf6_rule_cache_extended_entry_t *)cache;

		cache->flags |= FP_NF_CACHE_FLAG_MORE_RULES;
		ext_cache->ext_nbrules = nbrules - 1;
		ext_cache->ext_flags = 0;
		for (i = 0; i < nbrules - 1; i++)
			ext_cache->ext_rule6[i] = (fpn_uintptr_t)FPN_PER_CORE_VAR(fp_nf6_cached_rules_list)[i];
	}

	/* add the entry in list */
	cache->next = fp_nf6_hashtable[hash].head;
	fp_nf6_hashtable[hash].head = idx;

	/* mark this slot as present in hash tables */
	cache->flags |= FP_NF_CACHE_FLAG_IN_HASH_TABLE;

	/* mark entry as valid */
	cache->state = FP_NF_CACHE_STATE_USED;

	fpn_spinlock_unlock(&fp_nf6_hashtable[hash].lock);
	TRACE_NF_CACHE(FP_LOG_INFO, "%s(hook=%d, table=%d) UPDATED %d", __FUNCTION__,
		       hook, table, idx);
out:
	/* restore DSCP */
	fp_change_ipv6_dscp(mtod(m, struct fp_ip6_hdr *), dscp);
}
