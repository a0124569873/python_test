/*
 * Copyright (c) 2013 6WIND
 */

#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"

#include "fp-dscp.h"
#include "netinet/fp-udp.h"
#include "netinet/fp-tcp.h"
#include "netinet/fp-icmp.h"
#include "netinet/fp-sctp.h"
#include "netinet/fp-gre.h"
#include "fp-nfct.h"
#include "fp-nf-tables.h"
#include "fp-ip.h"
#include "fp-nf-nat.h"
#include <sys/time.h>
#include <string.h>
#include <time.h>

static inline uint16_t fp_nf_mangle_cksum(uint32_t newip, uint32_t oldip, uint16_t newport,
					  uint16_t oldport, uint16_t cksum)
{
	uint32_t res;
	uint16_t oldipmsb, oldiplsb;
	uint16_t newipmsb = newip >> 16;
	uint16_t newiplsb = newip & 0xFFFF;

	oldip = ~oldip;
	oldipmsb = oldip >> 16;
	oldiplsb = oldip & 0xFFFF;
	oldport = ~oldport & 0xFFFF;
	cksum = ~cksum;

	res = cksum + oldipmsb + newipmsb + oldiplsb + newiplsb + oldport + newport;
	res = ((res & 0xffff0000) >> 16) + (res & 0xffff);
	res = ((res & 0xffff0000) >> 16) + (res & 0xffff);

	return (~res & 0xFFFF);
}

static inline uint16_t fp_nf_mangle_cksum_udp(uint32_t newip, uint32_t oldip, uint16_t newport,
					      uint16_t oldport, uint16_t cksum)
{
	/* checksum 0 means "no checksum" => do not adjust it */
	if (unlikely(cksum == 0))
		return 0;

	cksum = fp_nf_mangle_cksum(newip, oldip, newport, oldport, cksum);

	if (unlikely(cksum == 0))
		return 0xffff;
	else
		return cksum;
}

/*
 * Called only in case of NAT table, before browsing the rules. If
 * packet is TCP, UDP, ESP or AH, do a conntrack lookup. If not found, return
 * FP_NF_CONTINUE (will parse rules), else do the NAT on the packet
 * and update conntrack entry statistics.
 */
int fp_nfct_nat_lookup(struct mbuf *m, int hook)
{
	struct fp_ip* ip;
	struct fp_udphdr *uh = NULL;
	struct fp_tcphdr *th = NULL;
	uint16_t dport = 0, sport = 0;
	int need_exception = 0, fin = 0, need_assured = 1;
	struct fp_nfct_entry *nfct;
	uint8_t dir;

	ip = mtod(m, struct fp_ip *);

	switch (ip->ip_p) {

	case FP_IPPROTO_TCP:
		/* Must not be a fragment. */
		if (ntohs(ip->ip_off) & FP_IP_OFFMASK)
			return FP_NF_CONTINUE;
		th = m_off(m, ip->ip_hl * 4, struct fp_tcphdr *);
		/* Some special packets must be sent in exception */
		if (th->th_flags & (TH_SYN|TH_FIN|TH_RST)) {
			if (th->th_flags & TH_FIN)
				fin = 1;
			need_exception = 1;
		}
		sport = th->th_sport;
		dport = th->th_dport;
		break;
	case FP_IPPROTO_UDP:
		/* Must not be a fragment. */
		if (ntohs(ip->ip_off) & FP_IP_OFFMASK)
			return FP_NF_CONTINUE;
		uh = m_off(m, ip->ip_hl * 4, struct fp_udphdr *);
		sport = uh->uh_sport;
		dport = uh->uh_dport;
		break;
	case FP_IPPROTO_ESP:
	case FP_IPPROTO_AH:
		need_assured = 0;
		break;
	default:
		return FP_NF_CONTINUE;
	}

	if (fp_nfct_get(m, ip, sport, dport) < 0) {
		/* Conntrack not found */
		return FP_NF_CONTINUE;
	}

	dir = m_priv(m)->fp_nfct_dir;
	nfct = m_priv(m)->fp_nfct.v4;
#define NFCT_O(x)   x->tuple[FP_NF_IP_CT_DIR_ORIGINAL]
#define NFCT_R(x)   x->tuple[FP_NF_IP_CT_DIR_REPLY]
	/* For conntracks without ASSURED flag (set by SP), all packets go as exception */
	if (unlikely(need_assured && !(nfct->flag & FP_NFCT_FLAG_ASSURED))) {
		m_priv(m)->fp_nfct_established = FP_NF_CT_MBUF_OTHER;
		return FP_NF_EXCEPTION;
	}

	/* We found a conntrack but we need an exception to update the
	 * conntrack state in slow path */
	if (unlikely(need_exception ||
	             nfct->flag & FP_NFCT_FLAG_END)) {
		if (fin) {
			nfct->flag |= FP_NFCT_FLAG_END;
			/* remove update flag to prevent from sending hf sync for that conntrack
			   after a FIN segment */
			nfct->flag &= ~FP_NFCT_FLAG_UPDATE;
		}
		m_priv(m)->fp_nfct_established = FP_NF_CT_MBUF_OTHER;
		return FP_NF_EXCEPTION;
	}

	if (nfct->flag & FP_NFCT_FLAG_DNAT) {
		/* DNAT Packet nated */
		if ((hook == FP_NF_IP_PRE_ROUTING) || (hook == FP_NF_IP_LOCAL_OUT)) {
			if (dir == FP_NF_IP_CT_DIR_ORIGINAL) {
				ip->ip_sum = fp_nf_mangle_cksum(NFCT_R(nfct).src,
								NFCT_O(nfct).dst,
								0, 0, ip->ip_sum);

				ip->ip_dst.s_addr = NFCT_R(nfct).src;
				m_priv(m)->flags |= M_NFNAT_DST;

				if (th) {
					th->th_dport = NFCT_R(nfct).sport;
					th->th_sum = fp_nf_mangle_cksum(NFCT_R(nfct).src,
								       NFCT_O(nfct).dst,
								       NFCT_R(nfct).sport,
								       NFCT_O(nfct).dport,
								       th->th_sum);
				} else if (uh) {
					uh->uh_dport = NFCT_R(nfct).sport;
					uh->uh_sum = fp_nf_mangle_cksum_udp(NFCT_R(nfct).src,
									   NFCT_O(nfct).dst,
									   NFCT_R(nfct).sport,
									   NFCT_O(nfct).dport,
									   uh->uh_sum);
				}
				goto nf_nat_done;
			}
		}

		/* DNAT Packet de-nated */
		if ((hook == FP_NF_IP_POST_ROUTING)|| (hook == FP_NF_IP_LOCAL_IN)) {
			if (dir == FP_NF_IP_CT_DIR_REPLY) {
				ip->ip_sum = fp_nf_mangle_cksum(NFCT_O(nfct).dst,
								NFCT_R(nfct).src,
								0, 0, ip->ip_sum);

				ip->ip_src.s_addr = NFCT_O(nfct).dst;

				if (th) {
					th->th_sport = NFCT_O(nfct).dport;
					th->th_sum = fp_nf_mangle_cksum(NFCT_O(nfct).dst,
								       NFCT_R(nfct).src,
								       NFCT_O(nfct).dport,
								       NFCT_R(nfct).sport,
								       th->th_sum);
				} else if (uh) {
					uh->uh_sport = NFCT_O(nfct).dport;
					uh->uh_sum = fp_nf_mangle_cksum_udp(NFCT_O(nfct).dst,
									   NFCT_R(nfct).src,
									   NFCT_O(nfct).dport,
									   NFCT_R(nfct).sport,
									   uh->uh_sum);
				}
				goto nf_nat_done;
			}
		}
	}
	if (nfct->flag & FP_NFCT_FLAG_SNAT) {
		/* SNAT Packet nated */
		if (hook == FP_NF_IP_POST_ROUTING) {
			if (dir == FP_NF_IP_CT_DIR_ORIGINAL) {
				ip->ip_sum = fp_nf_mangle_cksum(NFCT_R(nfct).dst,
								NFCT_O(nfct).src,
								0, 0, ip->ip_sum);

				ip->ip_src.s_addr = NFCT_R(nfct).dst;

				if (th) {
					th->th_sport = NFCT_R(nfct).dport;
					th->th_sum = fp_nf_mangle_cksum(NFCT_R(nfct).dst,
								       NFCT_O(nfct).src,
								       NFCT_R(nfct).dport,
								       NFCT_O(nfct).sport,
								       th->th_sum);
				} else if (uh) {
					uh->uh_sport = NFCT_R(nfct).dport;
					uh->uh_sum = fp_nf_mangle_cksum_udp(NFCT_R(nfct).dst,
									   NFCT_O(nfct).src,
									   NFCT_R(nfct).dport,
									   NFCT_O(nfct).sport,
									   uh->uh_sum);
				}
				goto nf_nat_done;
			}
		}

		/* SNAT Packet de-nated */
		if (hook == FP_NF_IP_PRE_ROUTING) {
			if (dir == FP_NF_IP_CT_DIR_REPLY) {
				ip->ip_sum = fp_nf_mangle_cksum(NFCT_O(nfct).src,
								NFCT_R(nfct).dst,
								0, 0, ip->ip_sum);

				ip->ip_dst.s_addr = NFCT_O(nfct).src;
				m_priv(m)->flags |= M_NFNAT_DST;

				if (th) {
					th->th_dport = NFCT_O(nfct).sport;
					th->th_sum = fp_nf_mangle_cksum(NFCT_O(nfct).src,
								       NFCT_R(nfct).dst,
								       NFCT_O(nfct).sport,
								       NFCT_R(nfct).dport,
								       th->th_sum);
				} else if (uh) {
					uh->uh_dport = NFCT_O(nfct).sport;
					uh->uh_sum = fp_nf_mangle_cksum_udp(NFCT_O(nfct).src,
									   NFCT_R(nfct).dst,
									   NFCT_O(nfct).sport,
									   NFCT_R(nfct).dport,
									   uh->uh_sum);
				}
				goto nf_nat_done;
			}
		}
	}

	/* conntrack is found */
	return FP_NF_ACCEPT;

 nf_nat_done:
	nfct->counters[dir].packets++;
#ifdef CONFIG_MCORE_NF_CT_BYTES
	nfct->counters[dir].bytes += m_len(m);
#endif
	nfct->flag |= FP_NFCT_FLAG_UPDATE;
#undef NFCT_O
#undef NFCT_R

	/* Update the exception type. Two possibilities here:
	 *  1) The packet source address was changed (LOCAL_OUT/POSTROUTING),
	 *   we don't want to do the job a second time in slow path.
	 *  Assumption: FPTUN_IPV4_OUTPUT_EXCEPT bypasses NF HOOK.
	 *  2) The packet destination address was changed (PREROUTING/LOCAL_IN),
	 *    we don't want the packet to go in slow path stack de-nated.
	 *   (it can happen if ARP is needed)
     *  3) exception can happen between PRE and POSTROUTING: ask to fwd
	 */
	if (hook == FP_NF_IP_PRE_ROUTING)
		m_priv(m)->exc_type = FPTUN_IPV4_FWD_EXCEPT;
	else
		m_priv(m)->exc_type = FPTUN_IPV4_OUTPUT_EXCEPT;

	return FP_NF_ACCEPT;
}

static uint64_t getusec(void)
{
	struct timeval stp;
	//uint64_t cur = 0;
	gettimeofday(&stp, NULL);

	return  (((uint64_t)stp.tv_sec)*1000 + ((uint64_t)stp.tv_usec)/1000);
	//return  (((uint64_t)stp.tv_sec)*1000000 + (uint64_t)stp.tv_usec);
}

int fp_ddos_lookup(struct mbuf *m, int hook)
{
	struct fp_ip* ip;
	struct fp_udphdr *uh = NULL;
	struct fp_tcphdr *th = NULL;
	//struct fp_icmphdr *ih = NULL;
	uint16_t dport = 0, sport = 0;
	int need_exception = 0, fin = 0, need_assured = 1/*, syn = 0*/;
	struct fp_nfct_entry *nfct;
	uint8_t dir;
	ip = mtod(m, struct fp_ip *);
	switch (ip->ip_p)
	{
		case FP_IPPROTO_TCP:
			th = m_off(m, ip->ip_hl * 4, struct fp_tcphdr *);
			/* Some special packets must be sent in exception */
			if (th->th_flags & (TH_SYN|TH_FIN|TH_RST))
			{
				if (th->th_flags & TH_FIN)
					fin = 1;

				need_exception = 1;
			}
			if(th->th_flags & TH_ACK)
			{
				need_exception = 0;
			}
			sport = th->th_sport;
			dport = th->th_dport;
			//th->th_sum = 0;
			//m_set_tx_tcp_cksum(m);
		break;
		case FP_IPPROTO_UDP:
			uh = m_off(m, ip->ip_hl * 4, struct fp_udphdr *);
			sport = uh->uh_sport;
			dport = uh->uh_dport;
			//uh->uh_sum = 0;
		//	m_set_tx_udp_cksum(m);
			//dhcp packet
		break;
		default:
			return FP_NF_DROP;
	}
	
	/* Conntrack not found */
	if (fp_nfct_get(m, ip, sport, dport) < 0) {
		
		//tcp status protect	
		if((th != NULL) && (th->th_flags & (TH_FIN|TH_RST|TH_ACK)))
			return FP_NF_DROP;
		else		
			return FP_NF_EXCEPTION;
	}

	dir = m_priv(m)->fp_nfct_dir;
	nfct = m_priv(m)->fp_nfct.v4;
	/* For conntracks without ASSURED flag (set by SP), all packets go as exception */
	if (unlikely(need_assured && !(nfct->flag & FP_NFCT_FLAG_ASSURED)))
	{
		m_priv(m)->fp_nfct_established = FP_NF_CT_MBUF_OTHER;
		if(ip->ip_p == FP_IPPROTO_UDP)
		{
			nfct->counters[dir].packets++;
			nfct->counters[dir].bytes += m_len(m);
			if (nfct->counters[dir].packets == 1)
			{
				nfct->counters[dir].start_time = getusec();
			}
			if (nfct->counters[dir].packets == 10)
				nfct->counters[dir].pre_time = getusec();
			if (nfct->counters[dir].packets > 10)
			{
				//cal_session_variance(nfct, m_len(m), dir);
				//cal_session_interval(nfct, dir);
			}
			nfct->flag |= FP_NFCT_FLAG_UPDATE;
			return FP_NF_CONTINUE;

		}
		if((ip->ip_p == FP_IPPROTO_TCP)&&(need_exception == 0))
		{
			nfct->counters[dir].packets++;
			nfct->counters[dir].bytes += m_len(m);
			if (nfct->counters[dir].packets == 1)
			{
				nfct->counters[dir].start_time = getusec();
			}
			if (nfct->counters[dir].packets == 10)
				nfct->counters[dir].pre_time = getusec();
			if (nfct->counters[dir].packets > 10)
			{
				//cal_session_variance(nfct, m_len(m), dir);
				//cal_session_interval(nfct, dir);
			}
			nfct->flag |= FP_NFCT_FLAG_UPDATE;
			return FP_NF_CONTINUE;
		}
		if(ip->ip_p == FP_IPPROTO_ICMP)
		{
			nfct->counters[dir].packets++;
			nfct->counters[dir].bytes += m_len(m);
			if (nfct->counters[dir].packets == 1)
			{
				nfct->counters[dir].start_time = getusec();
			}
			if (nfct->counters[dir].packets == 10)
				nfct->counters[dir].pre_time = getusec();
			if (nfct->counters[dir].packets > 10)
			{
				//cal_session_variance(nfct, m_len(m), dir);
				//cal_session_interval(nfct, dir);
			}
			nfct->flag |= FP_NFCT_FLAG_UPDATE;
			return FP_NF_CONTINUE;

		}
	}

	/* We found a conntrack but we need an exception to update the
	 * conntrack state in slow path */
	if (unlikely(need_exception ||
	             nfct->flag & FP_NFCT_FLAG_END))
	{
		nfct->counters[dir].packets++;
		nfct->counters[dir].bytes += m_len(m);
		if (fin)
		{
			nfct->flag |= FP_NFCT_FLAG_END;
			/* remove update flag to prevent from sending hf sync for that conntrack
			   after a FIN segment */
			nfct->flag &= ~FP_NFCT_FLAG_UPDATE;
		}
		m_priv(m)->fp_nfct_established = FP_NF_CT_MBUF_OTHER;
		return FP_NF_EXCEPTION;
	}

	nfct->counters[dir].packets++;
#ifdef CONFIG_MCORE_NF_CT_BYTES
	nfct->counters[dir].bytes += m_len(m);
#endif
	if (nfct->counters[dir].packets == 1)
	{
		nfct->counters[dir].start_time = getusec();
	}
	if (nfct->counters[dir].packets == 10)
		nfct->counters[dir].pre_time = getusec();

	if (nfct->counters[dir].packets > 10)
	{
		//cal_session_variance(nfct, m_len(m), dir);
		//cal_session_interval(nfct, dir);
	}
	nfct->flag |= FP_NFCT_FLAG_UPDATE;
	/* Update the exception type. Two possibilities here:
	 *  1) The packet source address was changed (LOCAL_OUT/POSTROUTING),
	 *   we don't want to do the job a second time in slow path.
	 *  Assumption: FPTUN_IPV4_OUTPUT_EXCEPT bypasses NF HOOK.
	 *  2) The packet destination address was changed (PREROUTING/LOCAL_IN),
	 *    we don't want the packet to go in slow path stack de-nated.
	 *   (it can happen if ARP is needed)
     *  3) exception can happen between PRE and POSTROUTING: ask to fwd
	 */
//	if (hook == FP_NF_IP_PRE_ROUTING)
	//	m_priv(m)->exc_type = FPTUN_IPV4_FWD_EXCEPT;
	//else
		m_priv(m)->exc_type = FPTUN_IPV4_OUTPUT_EXCEPT;

	return FP_NF_CONTINUE;
}
