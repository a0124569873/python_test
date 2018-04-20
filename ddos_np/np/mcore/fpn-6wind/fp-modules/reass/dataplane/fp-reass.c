/*
 * Copyright(c) 2007 6WIND
 */
#include "fp-reass-common.h"
#include "fp-reass.h"

/* maximum reassembly delay for a packet (2000ms) */
#ifdef CONFIG_MCORE_MAX_IPV4_REASS_MS
#define FP_MAX_IPV4_REASS_MS CONFIG_MCORE_MAX_IPV4_REASS_MS
#else
#define FP_MAX_IPV4_REASS_MS 2000
#endif

/* maximum inter-fragment delay for a packet (200ms) */
#ifdef CONFIG_MCORE_MAX_IPV4_INTERFRAG_MS
#define FP_MAX_IPV4_INTERFRAG_MS CONFIG_MCORE_MAX_IPV4_INTERFRAG_MS
#else
#define FP_MAX_IPV4_INTERFRAG_MS 200
#endif

/* maximum number of simultaneous packet reassembly procedures */
#ifdef CONFIG_MCORE_REASSQ_IPV4_LIST_ORDER
#define FP_REASSQ_IPV4_LIST_ORDER CONFIG_MCORE_REASSQ_IPV4_LIST_ORDER
#else
#define FP_REASSQ_IPV4_LIST_ORDER  6   /* 2^6 queues */
#endif

#define FP_REASSQ_IPV4_LIST_SIZE   (1<<FP_REASSQ_IPV4_LIST_ORDER)
#define FP_REASSQ_IPV4_LIST_MASK   (FP_REASSQ_IPV4_LIST_SIZE-1)

/* queue hash table size */
#ifdef CONFIG_MCORE_REASSQ_IPV4_HASH_ORDER
#define FP_REASSQ_IPV4_HASH_ORDER CONFIG_MCORE_REASSQ_IPV4_HASH_ORDER
#else
#define FP_REASSQ_IPV4_HASH_ORDER   7
#endif

#define FP_REASSQ_IPV4_HASH_SIZE    (1<<FP_REASSQ_IPV4_HASH_ORDER)
#define FP_REASSQ_IPV4_HASH_MASK    (FP_REASSQ_IPV4_HASH_SIZE-1)

static FPN_DEFINE_SHARED(fpn_rwlock_t, ipq_list_lock);

/* hash table of ipq entries */
static FPN_DEFINE_SHARED(fp_ipq_list_t, ipq_htable[FP_REASSQ_IPV4_HASH_SIZE]);
/* list of time-ordered ipq entries */
static FPN_DEFINE_SHARED(fp_ipq_list_t, ipq_tlist);

static FPN_DEFINE_SHARED(fp_ipq_t, ipq_pool[FP_REASSQ_IPV4_LIST_SIZE]);


static FPN_DEFINE_SHARED(uint64_t, fp_max_ipv4_reass_cycles);
static FPN_DEFINE_SHARED(uint64_t, fp_max_ipv4_interfrag_cycles);

/* GC timer */
static FPN_DEFINE_SHARED(struct callout, fp_ip_reass_gc_callout);
static void fp_ip_reass_gc_timer(void *);
/*
 * Reassembly function initialization function
 * Must only called by one core
  */
int fp_ip_reass_init(void)
{
	int i;
	fp_ipq_t *ipq;
	fp_ipq_list_t *hline;
	uint64_t cycles_per_ms;

	fpn_rwlock_init(&ipq_list_lock);

	/* initialize queues hash table */
	for (i=0; i<FP_REASSQ_IPV4_HASH_SIZE; i++) {
		hline = &ipq_htable[i];
		FPN_TAILQ_INIT(hline);
	}

	/* initialize time-ordered queue list */
	FPN_TAILQ_INIT(&ipq_tlist);

	/* initialize pool of queues */
	for (i=0; i<FP_REASSQ_IPV4_LIST_SIZE; i++) {
		ipq = &ipq_pool[i];
		memset(ipq, 0, sizeof(*ipq));
		fpn_atomic_clear(&ipq->used);
	}

	/* configure timeouts */
	cycles_per_ms = fpn_div64_32(fpn_get_clock_hz(), 1000UL);

	fp_max_ipv4_reass_cycles = FP_MAX_IPV4_REASS_MS * cycles_per_ms;
	fp_max_ipv4_interfrag_cycles = FP_MAX_IPV4_INTERFRAG_MS * cycles_per_ms;

	/* configure and start queues garbage collector */
	callout_init(&fp_ip_reass_gc_callout);
	callout_reset(&fp_ip_reass_gc_callout, FP_REASSQ_GC_PERIOD, fp_ip_reass_gc_timer, NULL);
	return 0;
}

static inline uint32_t fp_ip4q_hash(const struct fp_ip *ip)
{
	uint32_t hash;

	hash = (ip->ip_src.s_addr ^ ip->ip_dst.s_addr) ^ (ip->ip_id ^ ip->ip_p);
	hash ^= (hash >> 16);
	return hash & FP_REASSQ_IPV4_HASH_MASK;
}

static inline void fp_ip4q_unlink(fp_ipq_t *ipq)
{
	TRACE_REASS(FP_LOG_DEBUG, "%s(%p)", __FUNCTION__, ipq);

	fpn_rwlock_write_lock(&ipq_list_lock);
	FPN_TAILQ_REMOVE(&ipq_htable[ipq->hash], ipq, hchain);
	FPN_TAILQ_REMOVE(&ipq_tlist, ipq, tchain);
	fpn_rwlock_write_unlock(&ipq_list_lock);
	ipq->flags |= REASSCOMPLETE;
}

/* this function must be called with a read lock on ipq list. */
static inline fp_ipq_t *fp_ip4q_lookup(uint32_t hash, const struct fp_ip *ip, uint16_t vrfid, uint8_t flags)
{
	fp_ipq_t *ipq;

	FPN_TAILQ_FOREACH(ipq, &ipq_htable[hash], hchain) {
		/* we don't want to mix AT_OFFSET queues with the others */
		if ((ipq->flags ^ flags) & AT_OFFSET)
			continue;
		if ((ipq->fp_q.ip_addr.saddr == ip->ip_src.s_addr) &&
		    (ipq->fp_q.ip_addr.daddr == ip->ip_dst.s_addr) &&
		    (ipq->id    == ip->ip_id) &&
		    (ipq->proto == ip->ip_p) &&
		    (ipq->vrfid == vrfid)) {
			fp_ipq_hold(ipq);
			return ipq;
		}
	}
	return NULL;
}

/* must be called with ipq_list_lock held (write lock) */
static inline void fp_ip4q_link(fp_ipq_t *ipq)
{
	TRACE_REASS(FP_LOG_DEBUG, "%s(%p)", __FUNCTION__, ipq);

	TRACE_REASS(FP_LOG_DEBUG, "add entry %p to hash list %u", ipq, (int)ipq->hash);
	FPN_TAILQ_INSERT_HEAD(&ipq_htable[ipq->hash], ipq, hchain);
	TRACE_REASS(FP_LOG_DEBUG, "add entry %p to time-ordered list", ipq);
	FPN_TAILQ_INSERT_TAIL(&ipq_tlist, ipq, tchain);
}

static inline void fp_ip4q_init(uint32_t hash, const struct fp_ip *ip,
		uint16_t vrfid, fp_ipq_t *ipq, uint8_t flags)
{
	fpn_spinlock_init(&ipq->lock);
	ipq->fp_q.ip_addr.saddr = ip->ip_src.s_addr;
	ipq->fp_q.ip_addr.daddr = ip->ip_dst.s_addr;
	fp_ipq_init(hash, ipq, vrfid, ip->ip_id, ip->ip_p, flags);
}

static inline fp_ipq_t *fp_ipq4_alloc(void)
{
	static unsigned int index = 0;
	unsigned i;
	fp_ipq_t *ipq;

	for (i=0; i<FP_REASSQ_IPV4_LIST_SIZE; i++) {
		ipq = &ipq_pool[index];
		index = (index + 1) & FP_REASSQ_IPV4_LIST_MASK;
		if (fpn_atomic_test_and_set(&ipq->used)) {
			fp_ipq_hold(ipq);
			return ipq;
		}
	}

	return NULL;
}

/*
 * delete timed out reassembly queues
 */
static void fp_ip4q_drain(void)
{
	fp_ipq_t *ipq;
	uint64_t curtime;
	int64_t start_delta;
	unsigned i;

	TRACE_REASS(FP_LOG_DEBUG, "%s()", __FUNCTION__);

	fpn_rwlock_read_lock(&ipq_list_lock);
	for (i=0; i < FP_REASSQ_IPV4_LIST_SIZE; i++) {

		if (FPN_TAILQ_EMPTY(&ipq_tlist))
			break;

		ipq = FPN_TAILQ_FIRST(&ipq_tlist);

		curtime = fpn_get_clock_cycles();
		start_delta = curtime - ipq->start_cycles;
		if (start_delta > (int64_t)fp_max_ipv4_reass_cycles) {
			fp_ipq_hold(ipq);
			fpn_rwlock_read_unlock(&ipq_list_lock);

			/* Another core may just have completed reassembly */
			fpn_spinlock_lock(&ipq->lock);
			if (!(ipq->flags & REASSCOMPLETE)) {
				if (!(ipq->flags & AT_OFFSET)) {
					fp_reass_send_exception(ipq, FP_IPPROTO_IP);
					FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmExceptions);
				}
				fp_reass_flush_ipq(ipq);
				fp_ip4q_unlink(ipq);
				fp_ipq_put(ipq);
				FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmTimeout);
				FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmFails);
			}
			fpn_spinlock_unlock(&ipq->lock);

			fp_ipq_put(ipq);
			fpn_rwlock_read_lock(&ipq_list_lock);
		} else
			break;
	}
	fpn_rwlock_read_unlock(&ipq_list_lock);
}

static void fp_ip_reass_gc_timer(void *arg)
{
	fp_ip4q_drain();
	/* reschedule the drain function */
	callout_reset(&fp_ip_reass_gc_callout, FP_REASSQ_GC_PERIOD, fp_ip_reass_gc_timer, NULL);
}

/*
 * retrieve an ipq entry (reassembly context)
 * if ipq is not found and (flags & IPQ_CREATE), then create and chain it
 */
static fp_ipq_t *fp_ip4q_get(const struct fp_ip *ip, uint16_t vrfid, uint8_t flags)
{
	uint32_t hash;
	fp_ipq_t *ipq;

	hash = fp_ip4q_hash(ip);
	fpn_rwlock_read_lock(&ipq_list_lock);
	ipq = fp_ip4q_lookup(hash, ip, vrfid, flags);
	fpn_rwlock_read_unlock(&ipq_list_lock);

	if ((ipq != NULL) || ((flags & IPQ_CREATE) == 0))
		goto end;

	/* Take the wrlock, and re-lookup for the queue. If another
	 * core already allocated it, return. Else do the alloc. */

	fpn_rwlock_write_lock(&ipq_list_lock);
	ipq = fp_ip4q_lookup(hash, ip, vrfid, flags);
	if( ipq != NULL ) /* already allocated by another core */
		goto end_unlock;

	TRACE_REASS(FP_LOG_INFO, "creating queue entry");
	ipq = fp_ipq4_alloc();
	if (ipq == NULL) {
		TRACE_REASS(FP_LOG_WARNING, "cannot allocate queue entry");
		goto end_unlock;
	}

	fp_ip4q_init(hash, ip, vrfid, ipq, flags);
	fp_ip4q_link(ipq);
	fp_ipq_hold(ipq);

 end_unlock:
	fpn_rwlock_write_unlock(&ipq_list_lock);
 end:
	TRACE_REASS(FP_LOG_INFO, "%s(): return entry %p", __FUNCTION__, ipq);
	return ipq;
}

static int fp_ip4_reass_finish(struct mbuf **pm, fp_ipq_t *ipq)
{
	struct mbuf *mreass, *m, *mnext;
	struct mbuf *at_offset = NULL;
	struct fp_ip *ip;
	int error = 0;
	uint16_t max_frag_size;

	TRACE_REASS(FP_LOG_DEBUG, "%s(%p)", __FUNCTION__, ipq);

	mreass = ipq->frag_list;
	max_frag_size = m_len(mreass);
	ipq->frag_list = NULL;
	if (unlikely((at_offset = ipq->at_offset) != NULL))
		ipq->at_offset = NULL;

	for (m = m_nextpkt(mreass); m; m = mnext) {
		FPN_TRACK();
		mnext = m_nextpkt(m);
		if (m_len(m) > max_frag_size)
			max_frag_size = m_len(m);
		if (m_adj(m, sizeof(struct fp_ip)) == NULL) {
			error = 1;
			break;
		}
		if (m_cat(mreass, m)) {
			error = 1;
			break;
		}
	}
	m_set_nextpkt(mreass, NULL);

	if (unlikely(error != 0)) {
		TRACE_REASS(FP_LOG_WARNING, "Error during concatenation\n");
		/* free rest of the list */
		for (; m; m = mnext) {
			FPN_TRACK();
			mnext = m_nextpkt(m);
			m_freem(m);
		}
		m_freem(mreass);
		if (unlikely(at_offset != NULL))
			m_freem(at_offset);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmFails);
		return FP_DONE;
	}

	ip = mtod(mreass, struct fp_ip*);
	ip->ip_len = htons(sizeof(struct fp_ip) + ipq->total_len);
	ip->ip_off &= htons(~(FP_IP_MF|FP_IP_OFFMASK));

	ip->ip_sum = fpn_ip_hdr_cksum(ip, sizeof(struct fp_ip));

	m_priv(mreass)->max_frag_size = max_frag_size;

	if (unlikely(at_offset != NULL)) {
		if (unlikely(m_prepend(mreass,
				       m_headlen(at_offset)) == NULL)) {
			TRACE_REASS(FP_LOG_WARNING,
				    "unable to prepend offset header to"
				    " reassembled mbuf");
			m_freem(mreass);
			m_freem(at_offset);
			FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmFails);
			return FP_DONE;
		}
		fpn_memcpy(mtod(mreass, uint8_t *),
		       mtod(at_offset, const uint8_t *), m_headlen(at_offset));
		m_freem(at_offset);
	}
	*pm = mreass;

	return FP_CONTINUE;
}

int fp_ip_reass_at_offset(struct mbuf **pm, size_t offset)
{
	struct mbuf *m = *pm;
	fp_ipq_t *ipq = NULL;
	struct fp_ip *ip;
	unsigned hlen;
	unsigned datalen;
	uint32_t start_offset;
	uint32_t end_offset;
	uint64_t curtime;
	int64_t start_delta, last_delta;
	struct mbuf *mfrag, *mprev;
	int ret = FP_KEEP;

	TRACE_REASS(FP_LOG_DEBUG, "%s()", __FUNCTION__);
	FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmReqds);

	if (unlikely(offset)) {
		struct fp_ip tmp;

		/* sanity check: the current implementation won't allow an
		   offset + a IPv4 header bigger than the first sbuf because
		   IPv4-handling code expects it there when using mtod() */
		if ((unlikely((offset + sizeof(tmp)) > m_headlen(m))) ||
		    (unlikely(m_copytobuf(&tmp, m, offset, sizeof(tmp)) !=
			      sizeof(tmp))))
			goto err_offset_too_large;
		hlen = (tmp.ip_hl << 2);
		datalen = (ntohs(tmp.ip_len) - hlen);
		start_offset = (ntohs(tmp.ip_off) & FP_IP_OFFMASK) << 3;

		ipq = fp_ip4q_get(&tmp, m2vrfid(m), (IPQ_CREATE | AT_OFFSET));
		if (unlikely(ipq == NULL))
			goto err_no_new_queue;
		fpn_spinlock_lock(&ipq->lock);
		if ((unlikely(start_offset == 0)) &&
		    (likely(ipq->at_offset == NULL))) {
			/* this is the first IP fragment, save offset data to
			   ipq */
			ipq->at_offset = m_alloc();
			if ((unlikely(ipq->at_offset == NULL)) ||
			    (unlikely(m_append(ipq->at_offset,
					       offset) == NULL)))
				goto err_offset_too_large;
			memcpy(mtod(ipq->at_offset, uint8_t *),
			       mtod(m, const uint8_t *), offset);
		}
		/* drop the offset part */
		if (unlikely(m_adj(m, offset) == NULL))
			goto err_offset_too_large;
		/* remove any padding */
		if (unlikely(ntohs(tmp.ip_len) < m_len(m)))
			m_trim(m, (m_len(m) - ntohs(tmp.ip_len)));
		ip = mtod(m, struct fp_ip *);
	}
	else {
		ip = mtod(m, struct fp_ip *);
		hlen = (ip->ip_hl << 2);
		datalen = (ntohs(ip->ip_len) - hlen);

		ipq = fp_ip4q_get(ip, m2vrfid(m), IPQ_CREATE);
		if (ipq == NULL)
			goto err_no_new_queue;
		start_offset = (ntohs(ip->ip_off) & FP_IP_OFFMASK) << 3;
		fpn_spinlock_lock(&ipq->lock);
	}

#if 0
	/* XXX hack for fp-emulator to see packets in exception */
	m_priv(m)->exc_type = FPTUN_ETH_INPUT_EXCEPT;
#endif

	if (unlikely(ipq->flags & (REASSCOMPLETE|QUEUE_FULL))) {
		TRACE_REASS(FP_LOG_INFO, "REASSCOMPLETE flag is set on queue %p", ipq);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmFails);
		ret = FP_DROP;
		goto end;
	}

	if (ipq->frag_count >= fp_shared->fp_reass4_maxq_len) {
		TRACE_REASS(FP_LOG_INFO, "Queue is full %u >= %u", ipq->frag_count, fp_shared->fp_reass4_maxq_len);
		fp_reass_flush_ipq(ipq);
		/* Mark the queue full and keep ipq in list
		 * so that we will drop subsequent fragments until timeout
		 */
		ipq->flags |= QUEUE_FULL;
		FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmFails);
		ret = FP_DROP;
		goto end;
	}

	curtime = fpn_get_clock_cycles();
	start_delta = curtime - ipq->start_cycles;
	last_delta = curtime - ipq->last_cycles;

	if ((start_delta > (int64_t)fp_max_ipv4_reass_cycles) ||
	    (last_delta > (int64_t)fp_max_ipv4_interfrag_cycles)) {
		TRACE_REASS(FP_LOG_INFO, "timeout exception");
		FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmTimeout);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmFails);
		if (unlikely(ipq->flags & AT_OFFSET))
			ret = FP_DROP;
		else
			ret = FP_NONE;
		fp_reass_flush_ipq(ipq);
		fp_ip4q_unlink(ipq);
		fp_ipq_put(ipq);
		goto end;
	}
	ipq->last_cycles = fpn_get_clock_cycles();

	if (hlen != 20) {
		TRACE_REASS(FP_LOG_INFO, "ip opt exception");
		if (unlikely(ipq->flags & AT_OFFSET))
			ret = FP_DROP;
		else {
			ret = FP_NONE;
			fp_reass_send_exception(ipq, FP_IPPROTO_IP);
			FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmExceptions);
		}
		fp_reass_flush_ipq(ipq);
		fp_ip4q_unlink(ipq);
		fp_ipq_put(ipq);
		goto end;
	}

	end_offset = start_offset + datalen;

	TRACE_REASS(FP_LOG_DEBUG, "hlen=%u datalen=%u start_offset=%u end_offset=%u",
		hlen, datalen, (unsigned)start_offset, (unsigned)end_offset);

	if (unlikely(end_offset > (FP_IP_MAXPACKET - sizeof(struct fp_ip)))) {
		TRACE_REASS(FP_LOG_INFO, "size exceeds 64K");
		fp_reass_flush_ipq(ipq);
		fp_ip4q_unlink(ipq);
		fp_ipq_put(ipq);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmFails);
		ret = FP_DROP;
		goto end;
	}

	/* last fragment? */
	if ((ntohs(ip->ip_off) & FP_IP_MF) == 0) {
		TRACE_REASS(FP_LOG_DEBUG, "last fragment");
		if (ipq->flags & LAST_RECVD) {
			TRACE_REASS(FP_LOG_INFO, "already received last fragment");
			fp_reass_flush_ipq(ipq);
			fp_ip4q_unlink(ipq);
			fp_ipq_put(ipq);
			FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmFails);
			ret = FP_DROP;
			goto end;
		} else {
			ipq->flags |= LAST_RECVD;
			ipq->total_len = end_offset;
		}
	} else if (ipq->flags & LAST_RECVD) {
		if (end_offset >= ipq->total_len) {
			TRACE_REASS(FP_LOG_INFO, "fragment overflows the packet size");
			fp_reass_flush_ipq(ipq);
			fp_ip4q_unlink(ipq);
			fp_ipq_put(ipq);
			FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmFails);
			ret = FP_DROP;
			goto end;
		}
	}

	mprev = NULL;
	for (mfrag = ipq->frag_list; mfrag; mfrag = m_nextpkt(mfrag)) {
		FPN_TRACK();
		if (start_offset <= m_priv(mfrag)->reass.start_offset)
			break;
		mprev = mfrag;
	}

	/* do we have overlapping or duplicate with next fragment? */
	if (mfrag && (end_offset > m_priv(mfrag)->reass.start_offset)) {
		TRACE_REASS(FP_LOG_DEBUG, "found a next fragment %u-%u",
			(unsigned)m_priv(mfrag)->reass.start_offset,
			(unsigned)m_priv(mfrag)->reass.end_offset);
		/* We have to drop the fragment, but keep the queue if
		 * the two fragments are the same.
		 */
		if ((start_offset != m_priv(mfrag)->reass.start_offset) ||
		    (end_offset != m_priv(mfrag)->reass.end_offset)) {
			TRACE_REASS(FP_LOG_INFO, "overlap detected");
			fp_reass_flush_ipq(ipq);
			fp_ip4q_unlink(ipq);
			fp_ipq_put(ipq);
			FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmFails);
			/* Fall through */
		}
		ret = FP_DROP;
		goto end;
	}

	/* insert in list of fragments */
	if (mprev) {
		TRACE_REASS(FP_LOG_DEBUG, "found a previous fragment %u-%u",
			(unsigned)m_priv(mprev)->reass.start_offset,
			(unsigned)m_priv(mprev)->reass.end_offset);
		/* do we overlap with previous fragment? */
		if (start_offset < m_priv(mprev)->reass.end_offset) {
			TRACE_REASS(FP_LOG_INFO, "overlap detected");
			fp_reass_flush_ipq(ipq);
			fp_ip4q_unlink(ipq);
			fp_ipq_put(ipq);
			FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmFails);
			ret = FP_DROP;
			goto end;
		}
		/* insert between mprev and mfrag */
		m_set_nextpkt(m, mfrag);
		m_set_nextpkt(mprev, m);
	} else {
		TRACE_REASS(FP_LOG_DEBUG, "inserting fragment at head of queue %p", ipq);
		/* insert at head */
		m_set_nextpkt(m, mfrag);
		ipq->frag_list = m;
	}

	m_priv(m)->reass.start_offset = start_offset;
	m_priv(m)->reass.end_offset = end_offset;
	ipq->recvd_len += datalen;
	ipq->frag_count++;

	TRACE_REASS(FP_LOG_DEBUG, "mbuf fields updated");

	if ((ipq->flags & LAST_RECVD) && (ipq->total_len == ipq->recvd_len)) {
		TRACE_REASS(FP_LOG_INFO, "all fragments received");
		fp_ip4q_unlink(ipq);
		ret = fp_ip4_reass_finish(pm, ipq);
		fp_ipq_put(ipq);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmOKs);
	} else {
		/* Refill Network Accelerator's pool if the packet is kept */
		m_freeback(m);
	}

end:
	fpn_spinlock_unlock(&ipq->lock);
	fp_ipq_put(ipq);
	return ret;

err_no_new_queue:
	TRACE_REASS(FP_LOG_WARNING, "could not allocate a new queue");
	goto err_cleanup;

err_offset_too_large:
	TRACE_REASS(FP_LOG_WARNING, "offset too large");

err_cleanup:
	FP_IP_STATS_INC(fp_shared->ip_stats, IpReasmFails);
	if (ipq != NULL) {
		fp_reass_flush_ipq(ipq);
		fp_ip4q_unlink(ipq);
		/*
		  ipq is held twice:
		  1- fp_ip4q_alloc()
		  2- fp_ip4q_lookup() *or* fp_ip4q_get()
		*/
		fp_ipq_put(ipq);
		fpn_spinlock_unlock(&ipq->lock);
		fp_ipq_put(ipq);
	}
	return FP_DROP;
}

int fp_ip_reass(struct mbuf **pm)
{
	return fp_ip_reass_at_offset(pm, 0);
}

void fp_ip_reass_display_info(void)
{
	fp_ipq_t *ipq;
	int i;

	for (i = 0; i < FP_REASSQ_IPV4_LIST_SIZE; i++) {
		ipq = &ipq_pool[i];
		fpn_printf("ipq[%u]:used=%u refcount=%u locked=%u\n",
			i,
			fpn_atomic_read(&ipq->used),
			fpn_atomic_read(&ipq->refcount),
			fpn_spinlock_is_locked(&ipq->lock));
		fpn_printf("        id=%u proto=%u flags=%u vrfid=%u\n",
			(unsigned int)ipq->id, ipq->proto, ipq->flags, ipq->vrfid);
		fpn_printf("        total_len=%u recvd_len=%u frag_count=%u hash=%x\n",
			(unsigned int)ipq->total_len,
			(unsigned int)ipq->recvd_len,
			(unsigned int)ipq->frag_count,
			(unsigned int)ipq->hash);
	}
}
