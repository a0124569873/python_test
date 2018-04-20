/*
 * Copyright(c) 2007 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"

#include "fp-main-process.h"
#include "fp-ip.h"
#ifdef CONFIG_MCORE_IPV6
#include "fp-ip6.h"
#endif
#include "fp-fragment.h"

#include "fpn-cksum.h"

#define TRACE_FRAG(level, fmt, args...) do {			\
		FP_LOG(level, FRAG, fmt "\n", ## args);		\
} while(0)

#ifdef CONFIG_MCORE_IPV6
static FPN_DEFINE_SHARED(fpn_atomic_t, ip6_frag_id);
#endif

int fp_ip_fragment(struct mbuf *m, uint64_t mtu,
		   int (*process_fragment)(struct mbuf *m, void *p1, void *p2),
		   void *p1, void *p2)
{
	struct mbuf *newm=NULL;
	struct fp_ip *ip, *ip2;
	uint32_t mtu_adj, ip_offset;
	uint16_t flag_off;

	M_TRACK(m, "IP_FRAG");

	/* XXX replace sizeof(struct fp_ip) by ip->ip_len * 4 */

#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
	/*
	 * m_cloned packets can not be split so unclone them
	 * before performing fragmentation
	 *
	 * As we enter the fragmentation code, the original mbuf is never
	 * returned to main loop: the fp_process_input_finish is called
	 * for each fragment. So we can safely replace the "m" by the duplicate
	 */
	m = m_unclone(m);
	if (unlikely(m == NULL)) {
		TRACE_FRAG(FP_LOG_WARNING, "Cannot unclone before fragmentation");
		goto fail;
	}
#endif

	/* Fragment should be 8B aligned. */
	mtu_adj = ((mtu - sizeof(struct fp_ip)) & ~7) + sizeof(struct fp_ip);
	ip = mtod(m, struct fp_ip *);
	flag_off = ntohs(ip->ip_off);
	ip_offset = (flag_off & FP_IP_OFFMASK) << 3;

	TRACE_FRAG(FP_LOG_DEBUG, "%s(): mlen(m)=%d, mtu=%d", __FUNCTION__, m_len(m), (int)mtu);

	while (m) {
		FP_LOG_MBUF(FP_LOG_DEBUG, FP_LOGTYPE_FRAG, m, 0);

		/* if we need to create a new frag */
		if (m_len(m) > mtu_adj) {
			TRACE_FRAG(FP_LOG_DEBUG, "split offset is %d", mtu_adj);

			/* split mbuf at offset mtu_adj */
			newm = m_split(m, mtu_adj);
			if (unlikely(newm == NULL)) {
				TRACE_FRAG(FP_LOG_WARNING, "Cannot m_split into new fragment.");
				goto fail;
			}

			/* prepend ip header to newm */
			ip = mtod(m, struct fp_ip *);
			ip2 = (struct fp_ip *) m_prepend(newm, sizeof(struct fp_ip));
			if (unlikely(ip2 == NULL)) {
				TRACE_FRAG(FP_LOG_WARNING, "m_prepend() failed.");
				goto fail;
			}
			memcpy(ip2, ip, sizeof(struct fp_ip));
			
			m_set_input_port(newm, m_input_port(m));
		}
		else {
			ip = mtod(m, struct fp_ip *);
			newm = NULL;
		}

		/* fix ip header for mbuf m */
		ip->ip_off &= ~htons(FP_IP_OFFMASK | FP_IP_MF);
		ip->ip_off |= htons((ip_offset >> 3) & FP_IP_OFFMASK);
		if ( (newm != NULL) || (flag_off & FP_IP_MF) )
			ip->ip_off |= htons(FP_IP_MF);
		ip->ip_len = htons(m_len(m));
		ip->ip_sum = fpn_ip_hdr_cksum(ip, sizeof(struct fp_ip));

		FP_IP_STATS_INC(fp_shared->ip_stats, IpFragCreates);
		TRACE_FRAG(FP_LOG_DEBUG, "send fragment mlen=%d, ip_offset=%d, %s", 
			    m_len(m), ip_offset, 
			    (ip->ip_off | ntohs(FP_IP_MF)) ? "have_more" : "last");
		TRACE_FRAG(FP_LOG_DEBUG, "remaining %d bytes to send", 
			    newm ? m_len(newm) : 0);

		/* update offset for next mbuf */
		ip_offset += m_len(m) - sizeof(struct fp_ip);

		m_priv(m)->exc_type = FPTUN_IPV4_OUTPUT_EXCEPT;
		process_fragment(m, p1, p2);
		m = newm;
	}

	FP_IP_STATS_INC(fp_shared->ip_stats, IpFragOKs);
	return FP_DONE;
fail:
	FP_IP_STATS_INC(fp_shared->ip_stats, IpFragFails);
	if (m)
		m_freem(m);
	if (newm)
		m_freem(newm);
	return FP_DONE;
#undef ALIGN_SIZE
}

int fp_ip_send_fragment(struct mbuf *m, void *p1, void *p2)
{
	int ret;

	ret = fp_ip_if_send(m, p1, p2);
	fp_process_input_finish(m, ret);
	return FP_DONE;
}

#ifdef CONFIG_MCORE_IPV6
int fp_ip6_fragment(struct mbuf *m, uint64_t mtu,
		    int (*process_fragment)(struct mbuf *m, void *p1, void *p2),
		    void *p1, void *p2)
{
	struct mbuf *newm=NULL;
	struct fp_ip6_hdr ip6_tmpl;
	struct fp_ip6_frag ip6fh_tmpl;
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	struct fp_ip6_frag *ip6fh;
	uint32_t  mtu_adj;
	uint16_t offset = 0;
	uint8_t nxt_hdr = ip6->ip6_nxt;

#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
	/*
	 * m_cloned packets can not be split so unclone them
	 * before performing fragmentation
	 *
	 * As we enter the fragmentation code, the original mbuf is never
	 * returned to main loop: the fp_process_input_finish is called
	 * for each fragment. So we can safely replace the "m" by the duplicate
	 */
	m = m_unclone(m);
	if (unlikely(m == NULL)) {
		TRACE_FRAG(FP_LOG_WARNING, "Cannot unclone before fragmentation");
		goto fail;
	}
#endif

	/* Adjust of data in IPv6 packet. Fragment should be 8B aligned. */
	mtu_adj = (mtu - sizeof(struct fp_ip6_hdr) - sizeof(struct fp_ip6_frag)) & ~7;

	/* Save original ipv6 header, most of the fields are the same */
	memcpy(&ip6_tmpl, mtod(m, void *), sizeof(struct fp_ip6_hdr));
	ip6_tmpl.ip6_nxt = FP_IPPROTO_FRAGMENT;

	/* Setup default Fragment Header */
	ip6fh_tmpl.ip6f_ident = htonl(((uint32_t)fpn_atomic_add_return(&ip6_frag_id, 1)));
	ip6fh_tmpl.ip6f_nxt = nxt_hdr;
	ip6fh_tmpl.ip6f_offlg = 0;
	ip6fh_tmpl.ip6f_reserved = 0;

	/* remove ipv6 header */
	m_adj(m, sizeof(struct fp_ip6_hdr));

	TRACE_FRAG(FP_LOG_DEBUG, "%s(): mlen(m)=%d, mtu=%d", __FUNCTION__, m_len(m), (int)mtu);
	while (m) {
		FPN_TRACK();
		FP_LOG_MBUF(FP_LOG_DEBUG, FP_LOGTYPE_FRAG, m, 0);

		/* if we need to create a new frag */
		if (m_len(m) > mtu_adj) {
			TRACE_FRAG(FP_LOG_DEBUG, "split offset is %d", mtu_adj);

			/* split mbuf at offset mtu_adj */
			newm = m_split(m, mtu_adj);
			if (unlikely(newm == NULL)) {
				TRACE_FRAG(FP_LOG_WARNING, "Cannot m_split for new fragment.");
				goto fail;
			}

			m_set_input_port(newm, m_input_port(m));
		}
		else {
			newm = NULL;
		}

		/* Prepend fragment header */
		ip6fh = (struct fp_ip6_frag *)m_prepend(m, sizeof(struct fp_ip6_frag));
		if (unlikely(ip6fh == NULL)) {
			TRACE_FRAG(FP_LOG_WARNING, "m_prepend() failed.");
			goto fail;
		}
		memcpy(ip6fh, &ip6fh_tmpl, sizeof(struct fp_ip6_frag));
		ip6fh->ip6f_offlg |= htons(offset) & FP_IP6F_OFF_MASK;

		if (newm != NULL)
		     ip6fh->ip6f_offlg |= FP_IP6F_MORE_FRAG;

		/* Prepend IPv6 header */
		ip6 = (struct fp_ip6_hdr *)m_prepend(m, sizeof(struct fp_ip6_hdr));
		if (unlikely(ip6 == NULL)) {
			TRACE_FRAG(FP_LOG_WARNING, "m_prepend() failed.");
			goto fail;
		}
		memcpy(ip6, &ip6_tmpl, sizeof(struct fp_ip6_hdr));
		ip6->ip6_plen = htons(m_len(m) - sizeof(struct fp_ip6_hdr));

		m_priv(m)->exc_type = FPTUN_IPV6_OUTPUT_EXCEPT;

		TRACE_FRAG(FP_LOG_DEBUG, "send fragment mlen=%d, offset=%d, %s", 
			    m_len(m), offset, newm ? "have_more" : "last");
		TRACE_FRAG(FP_LOG_DEBUG, "remaining %d bytes to send", 
			    newm ? m_len(newm) : 0);
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpFragCreates);
		process_fragment(m, p1, p2);

		m = newm;
		offset += mtu_adj;
	}
	FP_IP_STATS_INC(fp_shared->ip6_stats, IpFragOKs);

	return FP_DONE;
fail:
	FP_IP_STATS_INC(fp_shared->ip6_stats, IpFragFails);
	if (m)
		m_freem(m);
	if (newm)
		m_freem(newm);
	return FP_DONE;
}

int fp_ip6_send_fragment(struct mbuf *m, void *p1, void *p2)
{
	int ret;

	ret = fp_ip6_if_send(m, p1, p2);
	fp_process_input_finish(m, ret);
	return FP_DONE;
}
#endif /* CONFIG_MCORE_IPV6 */
