/*
 * Copyright(c) 2008 6WIND
 */
#include "fpn.h"
#include "fpn-cksum.h"
#include "fp-includes.h"

#include "fp-log.h"
#include "fp-ip.h"
#ifdef CONFIG_MCORE_IPV6
#include "fp-ip6.h"
#endif
#include "fp-tunnels-var.h"
#include "fp-tunnels.h"

#include "fp-dscp.h"
#include "fp-lookup.h"

#ifdef CONFIG_MCORE_NETFILTER
#include "fp-nf-tables.h"
#endif

#define TRACE_TNL(level, fmt, args...) do {			\
		FP_LOG(level, TUNNEL, fmt "\n", ## args);	\
} while(0)

void fp_tunnel_link(uint32_t idx)
{
	uint16_t hash, next;

	switch (fp_shared->fp_tunnels.table[idx].proto) {
#ifdef CONFIG_MCORE_XIN4
	case FP_IPPROTO_IP:
		hash = FP_XIN4_HASH(fp_shared->fp_tunnels.table[idx].p.xin4.ip_src.s_addr,
				    fp_shared->fp_tunnels.table[idx].p.xin4.ip_dst.s_addr);

		next = fp_shared->fp_tunnels.hash_xin4[hash];
		fp_shared->fp_tunnels.table[idx].hash_prev = 0;
		fp_shared->fp_tunnels.table[idx].hash_next = next;
		fp_shared->fp_tunnels.hash_xin4[hash] = idx;
		if (next)
			fp_shared->fp_tunnels.table[next].hash_prev = idx;
		break;
#endif
#ifdef CONFIG_MCORE_XIN6
	case FP_IPPROTO_IPV6:
		hash = FP_XIN6_HASH(&fp_shared->fp_tunnels.table[idx].p.xin6.ip6_src,
				    &fp_shared->fp_tunnels.table[idx].p.xin6.ip6_dst);

		next = fp_shared->fp_tunnels.hash_xin6[hash];
		fp_shared->fp_tunnels.table[idx].hash_prev = 0;
		fp_shared->fp_tunnels.table[idx].hash_next = next;
		fp_shared->fp_tunnels.hash_xin6[hash] = idx;
		if (next)
			fp_shared->fp_tunnels.table[next].hash_prev = idx;
		break;
#endif
	}
}

static inline int fp_xiny_stripheader(struct mbuf *m, fp_tunnel_entry_t *tun,
				      uint8_t size, uint8_t proto, uint8_t dscp)
{
	fp_ifnet_t *ifp = fp_ifuid2ifnet(tun->ifuid);
#ifdef CONFIG_MCORE_IPV6
	struct fp_ip6_hdr *ip6;
#endif
	struct fp_ip *ip;

#ifdef CONFIG_MCORE_NETFILTER
	fp_nfct_reset(m);
#endif

	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
		return FP_DROP;
	}

	if (likely(m_adj(m, size) != NULL)) {
		if (likely(proto == FP_IPPROTO_IPV4)) {
			ip = mtod(m, struct fp_ip *);
			if (unlikely(ntohs(ip->ip_len) < m_len(m))) {
				TRACE_TNL(FP_LOG_INFO, "XinY packet length doesn't match the packet");
				FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);
				return FP_DROP;
			}
			m_priv(m)->exc_type = FPTUN_IFACE_INPUT_EXCEPT;
			m_priv(m)->exc_proto = htons(FP_ETHERTYPE_IP);
			if (unlikely(dscp)) {
				fp_change_ipv4_dscp(ip, dscp);
			}
			fp_change_ifnet_packet(m, ifp, 1, 1);
			fp_reset_hw_flags(m); /* No known HW able to do HW Checksum here */
			return FPN_HOOK_CALL(fp_ip_input)(m);
		}
		else if (likely(proto == FP_IPPROTO_IPV6)) {
			m_priv(m)->exc_type = FPTUN_IFACE_INPUT_EXCEPT;
			m_priv(m)->exc_proto = htons(FP_ETHERTYPE_IPV6);
#ifdef CONFIG_MCORE_IPV6
			ip6 = mtod(m, struct fp_ip6_hdr *);
			if (unlikely(ntohs(ip6->ip6_plen) + sizeof(struct fp_ip6_hdr) < m_len(m))) {
				TRACE_TNL(FP_LOG_INFO, "XinY packet length doesn't match the packet");
				FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);
				return FP_DROP;
			}
			if (unlikely(dscp)) {
				fp_change_ipv6_dscp(ip6, dscp);
			}
			fp_change_ifnet_packet(m, ifp, 1, 1);
			fp_reset_hw_flags(m); /* No known HW able to do HW Checksum here */
			return FPN_HOOK_CALL(fp_ip6_input)(m);
#endif
		}
	}
	
	FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);
	return FP_DROP;
}

#ifdef CONFIG_MCORE_XIN4
static inline fp_tunnel_entry_t *fp_xin4_lookup(struct mbuf *m, struct fp_in_addr src,
						struct fp_in_addr dst)
{
	fp_tunnel_entry_t *tun;
	uint32_t idx = fp_shared->fp_tunnels.hash_xin4[FP_XIN4_HASH(src.s_addr, dst.s_addr)];

	while (idx) {
		tun = &fp_shared->fp_tunnels.table[idx];

		/* p.xin4 is the IPv4 header used in input path, so src and dst
		 * are inverted on the output path.
		 */
		if (tun->proto == FP_IPPROTO_IP &&
		    tun->ifuid &&
		    tun->linkvrfid == m2vrfid(m) &&
		    (tun->p.xin4.ip_dst.s_addr == src.s_addr) &&
		    (tun->p.xin4.ip_src.s_addr == dst.s_addr))
			return tun;
		idx = tun->hash_next;
	}

	return NULL;
}

/* 
 * The caller of this function MUST have checked the protocol
 * field of the ip header, so here no need to check it again.
 */
int fp_xin4_input(struct mbuf *m, struct fp_ip *ip)
{
	struct fp_in_addr src = ip->ip_src;
	fp_tunnel_entry_t *tun;
	uint8_t in_proto = ip->ip_p;
#ifdef CONFIG_MCORE_IPV6
	struct fp_ip6_hdr *ip6;

	if (in_proto == FP_IPPROTO_IPV6) {
		ip6 = m_off(m, sizeof(struct fp_ip), struct fp_ip6_hdr *);
		if (unlikely(!ip6)) {
			TRACE_TNL(FP_LOG_INFO, "Xin4 invalid IPv6 packet");
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpInHdrErrors);
			return FP_DROP;
		}
		if (ip6->ip6_dst.fp_s6_addr16[0] == FP_IP6_6TO4_ADDR)
			src.s_addr = 0;
	}
#endif
	tun = fp_xin4_lookup(m, src, ip->ip_dst);
	if (unlikely(tun == NULL)) {
		TRACE_TNL(FP_LOG_INFO, "Xin4 interface not found");
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	return fp_xiny_stripheader(m, tun, sizeof(struct fp_ip),
				   in_proto, ip->ip_tos & FP_DSCP_MASK);
}

static inline void fp_xin4_init_header(struct fp_ip *ip, fp_tunnel_entry_t *tun,
				       uint32_t dst, uint8_t proto, uint8_t dscp,
				       uint16_t len, uint8_t ttl)
{
	memcpy(ip, &tun->p.xin4, sizeof(struct fp_ip));
	ip->ip_tos = dscp;
	ip->ip_len = htons(len);
	ip->ip_p = proto;
#ifdef CONFIG_MCORE_IPV6
	if (unlikely(dst))
		memcpy(&ip->ip_dst, &dst, sizeof(struct fp_in_addr));
#endif
	if (!ip->ip_ttl)
		ip->ip_ttl = ttl;

	ip->ip_sum = fpn_ip_hdr_cksum(ip, sizeof(struct fp_ip));
}

int fp_xin4_output(struct mbuf *m, fp_ifnet_t *ifp, uint8_t proto)
{
	fp_tunnel_entry_t *tun = &fp_shared->fp_tunnels.table[ifp->sub_table_index];
	uint32_t dst = 0;
	fp_rt4_entry_t *rt;
	fp_nh4_entry_t *nh;
	struct fp_ip *ip;
	uint8_t dscp = 0;
	uint8_t ttl = 0;
#ifdef CONFIG_MCORE_IPV6
	struct fp_ip6_hdr *ip6;
#endif
	FP_IF_STATS_INC(ifp->if_stats, ifs_opackets);
	FP_IF_STATS_ADD(ifp->if_stats, ifs_obytes, m_len(m));

	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
		return FP_DROP;
	}

	/* Size of IPv4 header is 20 bytes and we don't add any
	 * options, so we don't need to test the MTU. The MTU of
	 * this interface MUST be the MTU of the bellow interface
	 * minus 40 bytes.
	 */

	if (proto == FP_IPPROTO_IPV4) {
		ip = mtod(m, struct fp_ip *);
		dscp = ip->ip_tos & FP_DSCP_MASK;
		if (likely((m_priv(m)->flags & M_LOCAL_OUT) == 0)) {
			FP_IP_STATS_INC(fp_shared->ip_stats, IpForwDatagrams);
			/* Update TTL (from bsd netinet/ip_flow.c) */
			ip->ip_ttl -= FP_IPTTLDEC;
			ttl = ip->ip_ttl;
			if (unlikely(ip->ip_ttl <= FP_IPTTLDEC))
				return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
			if (unlikely(ip->ip_sum >= htons(0xffff - (FP_IPTTLDEC << 8))))
				ip->ip_sum += htons(FP_IPTTLDEC << 8) + 1;
			else
				ip->ip_sum += htons(FP_IPTTLDEC << 8);
		}
	}
#ifdef CONFIG_MCORE_IPV6
	else if (likely(proto == FP_IPPROTO_IPV6)) {
		ip6 = mtod(m, struct fp_ip6_hdr *);
		dscp = (ntohs(*(uint16_t *)ip6) >> 4) & FP_DSCP_MASK;
		if (likely((m_priv(m)->flags & M_LOCAL_OUT) == 0)) {
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpForwDatagrams);
			ip6->ip6_hlim -= FP_IPTTLDEC;
			ttl = ip6->ip6_hlim;
			if (unlikely(ip6->ip6_hlim <= FP_IPTTLDEC)) {
				m_priv(m)->exc_type = FPTUN_IPV6_OUTPUT_EXCEPT;
				return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
			}
		}

		/* Check if it is a 6to4 tunnel. */
		if (unlikely(tun->p.xin4.ip_dst.s_addr == 0)) {
			if (likely(ip6->ip6_dst.fp_s6_addr16[0] == FP_IP6_6TO4_ADDR))
				memcpy(&dst, &ip6->ip6_dst.fp_s6_addr16[1],
				       sizeof(struct fp_in_addr));
			else {
				m_priv(m)->exc_type = FPTUN_IPV6_OUTPUT_EXCEPT;
				return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
			}
		}
	}
#endif
	else {
		TRACE_TNL(FP_LOG_INFO, "packet is not ipv4 or ipv6, send it to slow path");
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	ip = (struct fp_ip *)m_prepend(m, sizeof(struct fp_ip));
	if (unlikely(ip == NULL)) {
		TRACE_TNL(FP_LOG_INFO, "failed to prepend %u bytes", (int)sizeof(struct fp_ip));
		return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
	}
	fp_xin4_init_header(ip, tun, dst, proto, dscp, m_len(m), ttl);

	/* Update the vrfid of mbuf to link vrfid of the tunnel */
	set_mvrfid(m, tun2linkvrfid(tun));
	/* lookup in the FW table */
#ifdef CONFIG_MCORE_IPV6
	/* dst is only pertinent in case of 6to4 tunnel */
	if (unlikely(dst))
		rt = fp_rt4_lookup(m2vrfid(m), dst);
	else
#endif
		rt = fp_rt4_lookup(m2vrfid(m), tun->p.xin4.ip_dst.s_addr);

	if (unlikely(!rt)) {
		/* send ICMP error HOST Unreachable */
		TRACE_TNL(FP_LOG_INFO, "route not found");
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoRouteLocal);
		return FP_DROP;
	}
	nh = select_nh4(rt, (uint32_t *)&tun->p.xin4.ip_src.s_addr);

	m_priv(m)->exc_type = FPTUN_IPV4_OUTPUT_EXCEPT;
	m_priv(m)->flags |= M_LOCAL_OUT | M_LOCAL_F;

	if (!(fp_shared->conf.w32.do_func & (FP_CONF_NO_FAST_FORWARD)))
		return fp_fast_ip_output(m, rt, nh);
	else
		return fp_ip_output(m, rt, nh);
}
#endif /* CONFIG_MCORE_XIN4 */

#ifdef CONFIG_MCORE_XIN6
static inline fp_tunnel_entry_t *fp_xin6_lookup(struct mbuf *m, struct fp_in6_addr *src,
						struct fp_in6_addr *dst)
{
	fp_tunnel_entry_t *tun;
	uint32_t idx = fp_shared->fp_tunnels.hash_xin6[FP_XIN6_HASH(src, dst)];

	while (idx) {
		tun = &fp_shared->fp_tunnels.table[idx];

		/* p.xin6 is the IPv6 header used in input path, so src and dst
		 * are inverted on the output path.
		 */
		if (tun->proto == FP_IPPROTO_IPV6 &&
		    tun->ifuid &&
		    tun->linkvrfid == m2vrfid(m) &&
		    !fpn_fast_memcmp(&tun->p.xin6.ip6_dst, src, sizeof(struct fp_in6_addr)) &&
		    !fpn_fast_memcmp(&tun->p.xin6.ip6_src, dst, sizeof(struct fp_in6_addr)))
			return tun;
		idx = tun->hash_next;
	}

	return NULL;
}

static inline void fp_xin6_init_header(struct fp_ip6_hdr *ip6, fp_tunnel_entry_t *tun,
				       uint8_t proto, uint8_t dscp, uint16_t plen, uint8_t hlim)
{
	memcpy(ip6, &tun->p.xin6, sizeof(struct fp_ip6_hdr));
	if (unlikely(dscp))
		fp_change_ipv6_dscp(ip6, dscp);
	ip6->ip6_plen = htons(plen);
	ip6->ip6_nxt = proto;
	if (!ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim)
		ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = hlim;
}

int fp_xin6_input(struct mbuf *m, struct fp_ip6_hdr *ip6)
{
	fp_tunnel_entry_t *tun;
	uint8_t in_proto = ip6->ip6_nxt;

	tun = fp_xin6_lookup(m, &ip6->ip6_src, &ip6->ip6_dst);
	if (unlikely(tun == NULL)) {
		TRACE_TNL(FP_LOG_INFO, "Xin6 interface not found");
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	return fp_xiny_stripheader(m, tun, sizeof(struct fp_ip6_hdr), in_proto,
				  (ntohs(*(uint16_t *)ip6) >> 4) & FP_DSCP_MASK);
}

int fp_xin6_output(struct mbuf *m, fp_ifnet_t *ifp, uint8_t proto)
{
	fp_tunnel_entry_t *tun = &fp_shared->fp_tunnels.table[ifp->sub_table_index];
	fp_in6_addr_t dst;
	fp_rt6_entry_t *rt;
	fp_nh6_entry_t *nh;
	struct fp_ip6_hdr *ip6;
	struct fp_ip *ip = NULL;
	uint8_t dscp = 0;
	uint8_t hlim = 0;

	FP_IF_STATS_INC(ifp->if_stats, ifs_opackets);
	FP_IF_STATS_ADD(ifp->if_stats, ifs_obytes, m_len(m));

	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
		return FP_DROP;
	}
	
	/* Size of IPv6 header is 40 bytes and we don't add any
	 * options, so we don't need to test the MTU. The MTU of
	 * this interface MUST be the MTU of the bellow interface
	 * minus 40 bytes.
	 */

	if (proto == FP_IPPROTO_IPV4) {
		ip = mtod(m, struct fp_ip *);
		dscp = ip->ip_tos & FP_DSCP_MASK;
		ip->ip_ttl -= FP_IPTTLDEC;
		if (unlikely(ip->ip_sum >= htons(0xffff - (FP_IPTTLDEC << 8))))
			ip->ip_sum += htons(FP_IPTTLDEC << 8) + 1;
		else
			ip->ip_sum += htons(FP_IPTTLDEC << 8);
		if (likely((m_priv(m)->flags & M_LOCAL_OUT) == 0))
			FP_IP_STATS_INC(fp_shared->ip_stats, IpForwDatagrams);
		hlim = ip->ip_ttl;
	} else if (proto == FP_IPPROTO_IPV6) {
		ip6 = mtod(m, struct fp_ip6_hdr *);
		dscp = (ntohs(*(uint16_t *)ip6) >> 4) & FP_DSCP_MASK;
		ip6->ip6_hlim -= FP_IPTTLDEC;
		hlim = ip6->ip6_hlim;
		if (likely((m_priv(m)->flags & M_LOCAL_OUT) == 0))
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpForwDatagrams);
	} else {
		TRACE_TNL(FP_LOG_INFO, "packet is not ipv4 or ipv6, send it to slow path");
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	ip6 = (struct fp_ip6_hdr *)m_prepend(m, sizeof(struct fp_ip6_hdr));
	if (unlikely(ip6 == NULL)) {
		TRACE_TNL(FP_LOG_INFO, "failed to prepend %u bytes", (int)sizeof(struct fp_ip6_hdr));
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}
	fp_xin6_init_header(ip6, tun, proto, dscp, m_len(m) - sizeof(struct fp_ip6_hdr), hlim);

	/* Update the vrfid of mbuf to link vrfid of the tunnel */
	set_mvrfid(m, tun2linkvrfid(tun));
	dst = (fp_in6_addr_t)(ip6->ip6_dst);
	rt = fp_rt6_lookup(m2vrfid(m), &dst);
	if (unlikely(!rt)) {
		/* send ICMP error HOST Unreachable */
		TRACE_TNL(FP_LOG_INFO, "route not found");
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoRouteLocal);
		return FP_DROP;
	}
	nh = select_nh6(rt, &ip6->ip6_src);

	m_priv(m)->exc_type = FPTUN_IPV6_OUTPUT_EXCEPT;
	m_priv(m)->flags |= M_LOCAL_OUT | M_LOCAL_F;
	return fp_ip6_output(m, rt, nh);
}
#endif /* CONFIG_MCORE_XIN6 */
