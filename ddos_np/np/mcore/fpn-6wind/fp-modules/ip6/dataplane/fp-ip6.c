/*
 * Copyright(c) 2010 6WIND
 */
#include "fp-includes.h"

#include "fp-log.h"
#include "fp-main-process.h"
#include "fp-fragment.h"

#include "fpn-cksum.h"
#include "fp-lookup.h"

#ifdef CONFIG_MCORE_IPSEC_IPV6
#include "fp-ipsec6-lookup.h"
#include "fp-ipsec6-input.h"
#include "fp-ipsec6-output.h"
#endif

#ifdef CONFIG_MCORE_IPV6_REASS
#include "fp-reass6.h"
#endif

#ifdef CONFIG_MCORE_NETFILTER
#include "fp-nf-tables.h"
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
#include "fp-nf6-tables.h"
#endif

#ifdef CONFIG_MCORE_XIN6
#include "fp-tunnels.h"
#endif

#ifdef CONFIG_MCORE_TCP_MSS
#include "fp-tcp-mss.h"
#endif

#include "fp-ether.h"
#include "fp-ip6.h"
#ifdef CONFIG_MCORE_MULTICAST6
#include "fp-mcast6.h"
#endif

#ifdef CONFIG_MCORE_VXLAN
#include "fp-vxlan.h"
#endif

#ifdef CONFIG_MCORE_SOCKET_INET6
#include "fp-so.h"
#include "netinet/fp-tcp.h"
#include "netinet/fp-udp.h"
#include "fp-bsd/netinet/udp_var.h"
#include "fp-bsd/netinet/tcp_timer.h"
#include "fp-bsd/netinet/tcp.h"
#include "fp-bsd/netinet/tcp_var.h"
#include "fp-bsd/netinet6/udp6_var.h"
#endif

#define TRACE_MAIN_PROC(level, fmt, args...) do {		\
	FP_LOG(level, MAIN_PROC, fmt "\n", ## args);		\
} while(0)

#define TRACE_IP(level, fmt, args...) do {			\
	FP_LOG(level, IP, fmt "\n", ## args);			\
} while(0)

FPN_SLIST_HEAD(fp_ip6_proto_handler_lst, fp_ip6_proto_handler);

static FPN_DEFINE_SHARED(struct fp_ip6_proto_handler_lst,
                         fp_ip6_proto_handlers[FP_IPPROTO_MAX]);

/* Return
 * 0 if IPv6 packet is good
 * 1 if IPv6 packet is an exception
 * 2 if IPv6 packet should be dropped
 */
static inline int mbuf_check_ipv6(struct mbuf *m)
{
	struct fp_ip6_hdr *ip6;

#ifdef FPN_HAS_HW_CHECK_IPV6
	int res = fpn_mbuf_hw_check_ipv6(m);
	if (likely(res >= 0))
		return res;
	/* fall down to software check */
#endif

	ip6 = mtod(m, struct fp_ip6_hdr *);
	if (unlikely(m_len(m) < (int)sizeof(struct fp_ip6_hdr)))
		return 2;
	if (unlikely(ip6->ip6_v != FP_IP6VERSION))
		return 2;

	/*
	 * too short
	 * Hop-limit is 0
	 * hop-by-hop option
	 */
	if (unlikely(ntohs(ip6->ip6_plen) > (m_len(m)-sizeof(struct fp_ip6_hdr))))
		return 1; /* too short */

	if (unlikely(ntohs(ip6->ip6_hlim) == 0)) /* Hop-limit is 0 */
		return 1;

	if (unlikely(ip6->ip6_nxt == FP_IPPROTO_HOPOPTS))
		return 1;

	return 0;
}

int fp_ip6_output(struct mbuf *m, fp_rt6_entry_t *rt, fp_nh6_entry_t *nh)
{
	fp_ifnet_t *ifp;
	struct fp_ip6_hdr *ip6;
	uint16_t mtu;
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	uint32_t do_func = fp_shared->conf.w32.do_func;
#endif

	ip6 = mtod(m, struct fp_ip6_hdr *);

	ifp = __fp_ifuid2ifnet(nh->nh.nh_ifuid);

	if (likely(!(m_priv(m)->flags & M_LOCAL_OUT))) {
		/* Forwarding case */

		if (unlikely(FP_IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) ||
			FP_IN6_IS_ADDR_LOOPBACK(&ip6->ip6_src) ||
			FP_IN6_IS_ADDR_MULTICAST(&ip6->ip6_src))) {
			/* drop the packets with martian source address
			 * such as undefined, loopback, multicast, etc.
			 */
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpInAddrErrors);
			TRACE_IP(FP_LOG_DEBUG,"Martian source address");
			return FP_DROP;
		}

		if (unlikely(FP_IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src))) {
			TRACE_IP(FP_LOG_INFO, "Link-local Source address");
			return fp_ip_prepare_exception(m, FPTUN_EXC_UNDEF);
		}

#ifdef CONFIG_MCORE_IPSEC_IPV6_VERIFY_INBOUND
		if ((fp_shared->conf.w32.do_func & FP_CONF_DO_IPSEC6_IN) &&
		    !(m_priv(m)->flags & M_IPSEC_SP_OK)) {
			int res = ipsec6_check_policy(m, ip6);
			if (unlikely(res != FP_CONTINUE))
				return res;
		}
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
		if (unlikely(do_func & FP_CONF_DO_NETFILTER6)) {
			int res = fp_nf6_hook(m, FP_NF_IP_FORWARD,
					      __fp_ifuid2ifnet(m_priv(m)->ifuid),
					      ifp);
			if (unlikely(res != FP_CONTINUE))
				return res;
		}
#endif
	} else {
		/* Local out case */
#ifdef CONFIG_MCORE_NETFILTER_IPV6
		if (unlikely(do_func & FP_CONF_DO_NETFILTER6)) {
#ifdef CONFIG_MCORE_NETFILTER_ENHANCED
			fp_nfct_reset(m);
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
			/* IPsec'd packets don't go through LOCAL_OUT hook */
			if (!(m_priv(m)->flags & M_IPSEC_OUT))
#endif
			{
				int res;
#ifndef CONFIG_MCORE_NETFILTER_ENHANCED
				/* we called it just above in case of nf enhanced */
				fp_nfct_reset(m);
#endif
				res = fp_nf6_hook(m, FP_NF_IP_LOCAL_OUT,
						  __fp_ifuid2ifnet(m_priv(m)->ifuid),
						  ifp);
				if (unlikely(res != FP_CONTINUE))
					return res;
			}
		}
#endif
	}

	TRACE_IP(FP_LOG_DEBUG, "Received IPv6 packet in ip6_output");

	if (unlikely(ifp->if_ifuid == 0)) {
		TRACE_MAIN_PROC(FP_LOG_WARNING, "Unexpected/Invalid interface");
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedInvalidInterface);
		return FP_DROP;
	}

#ifdef CONFIG_MCORE_IPSEC_IPV6
	{
		if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_IPSEC6_OUT)) {
			/* Bypass SPD lookup in the following cases:
			 * - if 'IPsec only once' option is enabled and IPsec
			 *   processing has already occured on this packet
			 * - if packet has just been encrypted
			 *   => prohibit multiple IPsec transformations
			 * - if output interface is an SVTI interface
			 */

			if (!(m_priv(m)->flags & (M_IPSEC_BYPASS|M_IPSEC_OUT))) {
				int res;
#if defined(CONFIG_MCORE_NETFILTER_IPV6) && defined(CONFIG_MCORE_NETFILTER_ENHANCED)
				/* Go through postrouting before IPsec. */
				if (unlikely(do_func & FP_CONF_DO_NETFILTER6)) {
					res = fp_nf6_hook(m, FP_NF_IP_POST_ROUTING, NULL, ifp);
					if (unlikely(res != FP_CONTINUE))
						return res;
				}
#endif
				res = fp_ipsec6_output(m);
				if (unlikely(res != FP_CONTINUE))
					return res;
			}
			m_priv(m)->flags &= ~M_IPSEC_OUT;
		}
	}
#endif

	/*
	 * If we route the packet through same interface, and
	 * next hop is actually same as destination, send to slow
	 * path to ask redirect.
	 */
	if (unlikely(m_priv(m)->ifuid == nh->nh.nh_ifuid) &&
			!(m_priv(m)->flags & (M_LOCAL_OUT|M_NFNAT_DST)) &&
			rt->rt.rt_length == 128 &&
			is_in6_addr_equal(nh->nh_gw, ip6->ip6_dst)) {
		TRACE_IP(FP_LOG_INFO, "Destination on same link");
		return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
	}

	if (unlikely(ip6->ip6_hlim <= FP_IPTTLDEC)) {
		/* SP sends icmp error */
		TRACE_IP(FP_LOG_INFO, "HOP_LIMIT exceed");
		return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
	}

#ifdef CONFIG_MCORE_NETFILTER_IPV6
	/* Go through postrouting before fragmentation, it will save time. */
	if (unlikely(do_func & FP_CONF_DO_NETFILTER6)) {
		int res = fp_nf6_hook(m, FP_NF_IP_POST_ROUTING, NULL, ifp);
		if (unlikely(res != FP_CONTINUE))
			return res;
	}
#endif

#ifdef CONFIG_MCORE_TCP_MSS
	if (ifp->if_tcp6mss)
		fp_update_tcpmss_by_dev(m, ifp, AF_INET6);
#endif

	mtu = ifp->if_mtu;

#ifdef CONFIG_MCORE_IPV6_REASS
	/* If reassembly was forced, maximize mtu by the longest size
	 * of received fragment */
	if ( (m_priv(m)->flags & M_F_REASS) &&
	     (m_priv(m)->max_frag_size < mtu) ) {
		TRACE_IP(FP_LOG_INFO, "mtu limited by max_frag_size=%d, mtu=%d", m_priv(m)->max_frag_size, mtu);
		mtu = m_priv(m)->max_frag_size;
	}
#endif

	if (unlikely(ntohs(ip6->ip6_plen)+sizeof(struct fp_ip6_hdr) > mtu)) {
		TRACE_IP(FP_LOG_INFO, "Too large for interface (len=%d, mtu=%d)", 
			 (int)(ntohs(ip6->ip6_plen)+sizeof(struct fp_ip6_hdr)), mtu);

		/* We only fragment local or reassembled packets */
		if (m_priv(m)->flags & (M_LOCAL_F|M_F_REASS))
			return fp_ip6_fragment(m, mtu, fp_ip6_send_fragment, nh, ifp);
		else
			return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
	}

	return fp_ip6_if_send(m, nh, ifp);
}

#ifdef CONFIG_MCORE_SOCKET_INET6

/* #define DUMP_TCPIP */

#ifdef DUMP_TCPIP

static void dump_tcpip6(struct mbuf *m, const char *str)
{
	struct fp_ip6_hdr *ip6;
	struct fp_tcphdr *tcp;
	struct fp_in6_addr ip6src, ip6dst;
	uint16_t sport, dport;

	ip6 = mtod(m, struct fp_ip6_hdr *);
	tcp = (struct fp_tcphdr *) (ip6 + 1);

	m_check(m);

	if (unlikely(ip6->ip6_nxt != FP_IPPROTO_TCP))
		return;

	ip6src = ip6->ip6_src;
	ip6dst = ip6->ip6_dst;

	sport = tcp->th_sport;
	dport = tcp->th_dport;

	fpn_printf("%s "
		   FP_NIP6_FMT":%u -> "
		   FP_NIP6_FMT":%u "
		   "len=%u, seq=%lu, ack=%lu, flags=%s%s%s%s%s\n", str,
		   FP_NIP6(ip6src), ntohs(sport),
		   FP_NIP6(ip6dst), ntohs(dport),
		   (unsigned)ntohs(ip6->ip6_plen),
		   (long)ntohl(tcp->th_seq), (long)ntohl(tcp->th_ack),
		   (tcp->th_flags&TH_SYN) ? "S" : "",
		   (tcp->th_flags&TH_PUSH) ? "P" : "",
		   (tcp->th_flags&TH_FIN) ? "F" : "",
		   (tcp->th_flags&TH_ACK) ? "A" : "",
		   (tcp->th_flags&TH_RST) ? "R" : "");
}
#endif

/*#define DUMP_UDPIP */

#ifdef DUMP_UDPIP

static void dump_udpip6(struct mbuf *m, const char *str)
{
	struct fp_ip6_hdr *ip6;
	struct fp_udphdr *udp;
	struct fp_in6_addr ip6src, ip6dst;
	uint16_t sport, dport;

	ip6 = mtod(m, struct fp_ip6_hdr *);
	udp = (struct fp_udphdr *) (ip6 + 1);

	m_check(m);

	if (unlikely(ip6->ip6_nxt != FP_IPPROTO_UDP)) {
		fpn_printf("ip6->ip6_nxt %d\n", ip6->ip6_nxt);
		return;
	}

	ip6src = ip6->ip6_src;
	ip6dst = ip6->ip6_dst;

	sport = udp->uh_sport;
	dport = udp->uh_dport;

	fpn_printf("%s "
		   FP_NIP6_FMT":%u -> "
		   FP_NIP6_FMT":%u \n", str,
		   FP_NIP6(ip6src), ntohs(sport),
		   FP_NIP6(ip6dst), ntohs(dport));
}
#endif

int fp_ip6_route_and_output(struct mbuf *m, int hlen)
{
	fp_rt6_entry_t *rt;
	fp_nh6_entry_t *nh;
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	int ret;

	rt = fp_rt6_lookup(m2vrfid(m), &ip6->ip6_dst);
	if (rt == NULL) {
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoRouteLocal);
		m_freem(m);
		return -1;
	}
	nh = select_nh6(rt, &ip6->ip6_src);
	m_priv(m)->exc_type = FPTUN_IPV6_OUTPUT_EXCEPT;
	m_priv(m)->flags |= M_LOCAL_OUT;
	ip6->ip6_v = FP_IP6VERSION;
	switch (ip6->ip6_nxt) {
		case FP_IPPROTO_TCP: {
			struct fp_tcphdr *th;
			th = (struct fp_tcphdr *)(mtod(m, char *) + hlen);
			th->th_sum = 0;
			th->th_sum = fpn_in6_l4cksum(m);
			break;
		}
		case FP_IPPROTO_UDP: {
			struct fp_udphdr *uh;
			uh = (struct fp_udphdr *)(mtod(m, char *) + hlen);
			uh->uh_sum = 0;
			uh->uh_sum = fpn_in6_l4cksum(m);
			if (uh->uh_sum == 0)
				uh->uh_sum = 0xffff;
			break;
		}
		default:
			break;
	}

#ifdef DUMP_TCPIP
	dump_tcpip6(m, "out6");
#endif
#ifdef DUMP_UDPIP
	dump_udpip6(m, "out6");
#endif
	ret = fp_ip6_output(m, rt, nh);

	fp_process_input_finish(m, ret);
	return 0;
}
#endif /* CONFIG_MCORE_SOCKET_INET6 */

/* Send a packet on an IPv6 interface. In this function, we assume
 * ifp->if_type is not ether-like, so we don't need a
 * fp_nh6_entry_t. */
int fp_ip6_inet6if_send(struct mbuf *m, fp_ifnet_t *ifp)
{
	ip_output_ops_t *ip_output;
	void *data;

#ifdef CONFIG_MCORE_TAP
	if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_TAP))
		fp_tap(m, ifp, htons(FP_ETHERTYPE_IPV6));
#endif
#ifdef CONFIG_MCORE_VRF
	/*
	 * This may be a cross-VR forwading
	 */
	if (likely(ifp->if_type == FP_IFTYPE_LOOP)) {
		struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);

		TRACE_IP(FP_LOG_DEBUG, "cross-vrf fwd from %d to %d",
			 m_priv(m)->vrfid, ifp->if_vrfid);
		m_priv(m)->exc_type = FPTUN_LOOP_INPUT_EXCEPT;
		m_priv(m)->exc_proto = htons(FP_ETHERTYPE_IPV6);
		fp_change_ifnet_packet(m, ifp, 1, 1);
		/* fp_reset_hw_flags() not required since HW did at the same level */
		/* Update hop limit */
		ip6->ip6_hlim -= FP_IPTTLDEC;
		/* TODO reschedule the packet */
		return FPN_HOOK_CALL(fp_ip6_input)(m);
	}
	TRACE_IP(FP_LOG_INFO, "Outgoing interface %s is virtual", ifp->if_name);
#endif
#ifdef CONFIG_MCORE_XIN4
	if (likely(ifp->if_type == FP_IFTYPE_XIN4)) {
		TRACE_IP(FP_LOG_INFO, "Need to process by Xin4 tunnel\n");
		return fp_xin4_output(m, ifp, FP_IPPROTO_IPV6);
	}
#endif
#ifdef CONFIG_MCORE_XIN6
	if (likely(ifp->if_type == FP_IFTYPE_XIN6)) {
		TRACE_IP(FP_LOG_INFO, "Need to process by Xin6 tunnel\n");
		return fp_xin6_output(m, ifp, FP_IPPROTO_IPV6);
	}
#endif
#ifdef CONFIG_MCORE_IPSEC_SVTI
#ifdef CONFIG_MCORE_IPSEC_IPV6
	if (likely(ifp->if_type == FP_IFTYPE_SVTI)) {
		TRACE_IP(FP_LOG_DEBUG, "Need to process by SVTI tunnel");
		return fp_svti6_output(m, ifp);
	}
#endif
#endif

	ip_output = fp_ifnet_ops_get(ifp, IP_OUTPUT_OPS, &data);
	if (unlikely(ip_output != NULL)) {
		int ret = ip_output(m, ifp, AF_INET6, data);
		if (ret != FP_CONTINUE)
			return ret;
	}

	TRACE_IP(FP_LOG_INFO, "Outgoing interface %s is virtual", ifp->if_name);
	return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
}
FPN_HOOK_REGISTER(fp_ip6_inet6if_send)

/* Send an IPv6 packet on a device */
int fp_ip6_if_send(struct mbuf *m, fp_nh6_entry_t *nh, fp_ifnet_t *ifp)
{
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);

	if (unlikely(!FP_IS_IFTYPE_ETHER(ifp->if_type)))
		return FPN_HOOK_CALL(fp_ip6_inet6if_send)(m, ifp);

	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
		return FP_DROP;
	}

	/* check NDP resolution */
	if (unlikely(nh->nh.nh_l2_state != L2_STATE_REACHABLE)) {
		if (likely(nh->nh.nh_l2_state == L2_STATE_STALE)) {
			if (unlikely(!nh->nh.nh_hitflag))
				nh->nh.nh_hitflag = 1;
		} else if (likely(nh->nh.nh_l2_state == L2_STATE_INCOMPLETE)) {
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoArp);
			TRACE_IP(FP_LOG_INFO, "NDP resolution in progress, dropping...");
			return FP_DROP; /* L2 resolution is in progress */
		} else { /* L2_STATE_NONE */
			TRACE_IP(FP_LOG_INFO, "Need NDP resolution");
			return fp_ip_prepare_exception(m, FPTUN_EXC_NDISC_NEEDED);
		}
	}
#ifdef CONFIG_MCORE_MULTIBLADE
	/*
	 * On the inactive blade perform hit flag even on reachable
	 * entries
	 */
	else if (fp_shared->fp_neigh_bladeid != fp_shared->fp_blade_id) {
		if (unlikely(!nh->nh.nh_hitflag))
			nh->nh.nh_hitflag = 1;
	}
#endif

	/* Do not modify TTL of locally generated packets */
	if (m_priv(m)->flags & M_LOCAL_OUT)
		goto skip_fwd;

	if (unlikely(!(ifp->if_flags & IFF_CP_IPV6_FWD))) {
		TRACE_IP(FP_LOG_INFO, "IPv6 forwarding disabled on %s", ifp->if_name);
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedForwarding);
		return FP_DROP;
	}

	/* Update hop limit */
	ip6->ip6_hlim -= FP_IPTTLDEC;

	FP_IP_STATS_INC(fp_shared->ip6_stats, IpForwDatagrams);

skip_fwd:
	/*
	 * We are going to forward the packet, so mark exception type
	 * as local sending exception for IPv6 forwarding.
	 */
	m_priv(m)->exc_type = FPTUN_IPV6_OUTPUT_EXCEPT;
	TRACE_IP(FP_LOG_INFO, "Sending IPv6 packet to ether_output");
	return FPN_HOOK_CALL(fp_ether_output)(m, (struct fp_ether_header *)&nh->nh.nh_eth, ifp);
}

int fp_ip6_proto_handler_register(u_char proto, fp_ip6_proto_handler_t *handler)
{
	if (!handler || !handler->func)
		return -1;
	FPN_SLIST_INSERT_HEAD(&fp_ip6_proto_handlers[proto], handler, next);
	return 0;
}

static inline int fp_ip6_input_demux(struct mbuf *m)
{
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);

#ifdef CONFIG_MCORE_IPSEC_IPV6
	/* TODO: check extension headers */
	if ((ip6->ip6_nxt == FP_IPPROTO_AH) || (ip6->ip6_nxt == FP_IPPROTO_ESP))
		return ipsec6_input(m, ip6); /* including FP_KEEP */

#ifdef CONFIG_MCORE_IPSEC_VERIFY_INBOUND
	if (unlikely(ip6->ip6_nxt == FP_IPPROTO_UDP)) {
		uint16_t lport;
		uint16_t off = sizeof(struct fp_ip6_hdr) + 2; /* dest port offset */

		/* Extract packet local port */
		if (likely(m_headlen(m) >= off + sizeof(lport)))
			lport = *(uint16_t*)(mtod(m, uint8_t*) + off);
		else if (m_copytobuf(&lport, m, off, sizeof(lport)) < sizeof(lport)) {
			TRACE_IP(FP_LOG_WARNING, "%s: protocol %u: header too short (%u bytes)",
				 __FUNCTION__, ip6->ip6_nxt, (unsigned int) (m_len(m) - sizeof(struct fp_ip6_hdr)));
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpInHdrErrors);
			return FP_DROP;
		}

		/* IKE case: let this packet go to SP, it will check
		 * if a socket policy exists.
		 */
		if (lport == htons(500))
			m_priv(m)->flags |= M_IPSEC_SP_OK;
	}
#endif /* CONFIG_MCORE_IPSEC_VERIFY_INBOUND */
#endif	/* CONFIG_MCORE_IPSEC_IPV6 */

#ifdef CONFIG_MCORE_NETFILTER_IPV6
	if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_NETFILTER6)) {
		fp_ifnet_t *ifp = __fp_ifuid2ifnet(m_priv(m)->ifuid);
		int res;

		res = fp_nf6_hook(m, FP_NF_IP_LOCAL_IN, ifp, NULL);
		if (unlikely(res != FP_CONTINUE))
			return res;
	}
#endif

#ifdef CONFIG_MCORE_IPSEC_IPV6_VERIFY_INBOUND
		if ((fp_shared->conf.w32.do_func & FP_CONF_DO_IPSEC6_IN) &&
		    !(m_priv(m)->flags & M_IPSEC_SP_OK)) {
			int res = ipsec6_check_policy(m, ip6);
			if (unlikely(res != FP_CONTINUE))
				return res;
		}
#endif

#ifdef CONFIG_MCORE_XIN6
	/* This is a packet for Xin6 tunnel */
	if ((ip6->ip6_nxt == FP_IPPROTO_IPV4)
			|| (ip6->ip6_nxt == FP_IPPROTO_IPV6))
		return fp_xin6_input(m, ip6);
#endif

#ifdef CONFIG_MCORE_VXLAN
	{
		int res = fp_vxlan6_input(m, ip6);

		if (res != FP_CONTINUE)
			return res;
	}
#endif

	int exc_class = FPTUN_EXC_SP_FUNC;

#ifdef CONFIG_MCORE_SOCKET_INET6
	{
		int res;
		/* TCP and UDP sockets handling (imply ICMP too) */
		switch (ip6->ip6_nxt) {
		case FP_IPPROTO_UDP:
#ifdef DUMP_UDPIP
			dump_udpip6(m, "in6");
#endif
			res = udp6_input(m);
			exc_class = FPTUN_EXC_SOCKET; /* for stats */
			break;
		case FP_IPPROTO_TCP:
#ifdef DUMP_TCPIP
			dump_tcpip6(m, "in6");
#endif
			res = tcp_input(m);
			exc_class = FPTUN_EXC_SOCKET; /* for stats */
			break;
		case FP_IPPROTO_ICMP:
			res = fp_so_icmp_input(m);
			exc_class = FPTUN_EXC_SOCKET; /* for stats */
			break;
		default:
			res = FP_CONTINUE;
			break;
		}
		if (likely(res != FP_CONTINUE))
			return res;
	}
#endif

	/* TODO IPsec */

	/* TODO VNB ksocket */

	fp_ip6_proto_handler_t *hdlr;

	FPN_SLIST_FOREACH (hdlr, &fp_ip6_proto_handlers[ip6->ip6_nxt], next) {
		int res = hdlr->func(m);
		if (res != FP_CONTINUE)
			return res;
	}

	return fp_ip_prepare_exception(m, exc_class);
}

#ifdef CONFIG_MCORE_IPV6_REASS
static inline int fp_ip6_reass_local(struct mbuf *m)
{
	int res = fp_ip6_reass(&m);

	if (res == FP_CONTINUE) {
		m_priv(m)->exc_type = FPTUN_IPV6_INPUT_EXCEPT;
		res = fp_ip6_input_demux(m);
	}

	fp_process_input_finish(m, res);
	return FP_DONE;
}
#endif

static inline int fp_ip6_input_local(struct mbuf *m, uint8_t rt_type)
{
	/* packet for us */
	if (rt_type == RT_TYPE_ADDRESS) {
#ifdef CONFIG_MCORE_IPV6_REASS
		struct fp_ip6_hdr *ip6;
		ip6 = mtod(m, struct fp_ip6_hdr *);
		if ( ip6->ip6_nxt == FP_IPPROTO_FRAGMENT ) {
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpInDelivers);
			return fp_ip6_reass_local(m);
		}
#endif
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpInDelivers);

		return fp_ip6_input_demux(m);
	}

	/* exception route */
	if (rt_type == RT_TYPE_ROUTE_BLACKHOLE) {
		TRACE_IP(FP_LOG_INFO, "Packet matches black hole route, dropped");
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedBlackhole);
		return FP_DROP;
	}
	/* Local delivery, connected: go to slow path */
	TRACE_IP(FP_LOG_INFO, "Route to slow path interface (type=%x)", rt_type);

	return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
}

#ifdef CONFIG_MCORE_RPF_IPV6
int fp_ip6_rpf_check(struct mbuf *m)
{
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	uint16_t vrfid = m2vrfid(m);
	uint32_t ifuid = m_priv(m)->ifuid;
	fp_rt6_entry_t *rt;
	fp_nh6_entry_t *nh;

	/* always accept link-local or multicast packets */
	if (FP_IN6_IS_ADDR_MULTICAST(&ip6->ip6_src) || FP_IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src))
		return 0;

	rt = fp_rt6_lookup(vrfid, &ip6->ip6_src);

	if (unlikely(!rt))
		return 1;

	/* check ECMP6 route */
	if (unlikely(rt->rt.rt_nb_nh > 1)) {
		uint32_t i;
		for (i = 0; i < rt->rt.rt_nb_nh; i++) {
			nh = &fp_shared->fp_nh6_table[rt->rt.rt_next_hop[i]];
			if (nh->nh.nh_ifuid == ifuid) {
				TRACE_IP(FP_LOG_DEBUG,"RPF matched in ECMP6");
				return 0;
			}
		}
	}
	else {
		nh = &fp_shared->fp_nh6_table[rt->rt.rt_next_hop[0]];
		if (likely(nh->nh.nh_ifuid == ifuid))
			return 0;
	}

	return 1;
}
#endif /* CONFIG_MCORE_RPF_IPV6 */

static inline int in6_canforward(fp_in6_addr_t *addr)
{
	/*
	 *  Do not test for link-local scope: the packet
	 *  will match the default rules ff80::/10 LOCAL
	 *  or ff00::/8 LOCAL, and go to exception.
	 */

#ifdef CONFIG_MCORE_MULTICAST6
	if (unlikely((FP_IN6_IS_ADDR_MC_NODELOCAL(addr) ||
		      FP_IN6_IS_ADDR_MC_LINKLOCAL(addr))))
#else
	if (unlikely((FP_IN6_IS_ADDR_MULTICAST(addr))))
#endif
		return 0;

	return 1;
}
static int fp_ip6_input2(struct mbuf *m)
{
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	fp_rt6_entry_t *rt;
	fp_nh6_entry_t *nh;
	uint8_t rt_type;

#if (defined CONFIG_MCORE_TCP_MSS) || (defined CONFIG_MCORE_NETFILTER_IPV6)
	fp_ifnet_t *ifp = __fp_ifuid2ifnet(m_priv(m)->ifuid);
#endif

#ifdef CONFIG_MCORE_TCP_MSS
	if (ifp->if_tcp6mss)
		fp_update_tcpmss_by_dev(m, ifp, AF_INET6);
#endif

#ifdef CONFIG_MCORE_NETFILTER_IPV6
	if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_NETFILTER6)) {
		int res;

		/* fp_nfct_established must be set before fp_nf6_hook() */
		fp_nfct_reset(m);
		res = fp_nf6_hook(m, FP_NF_IP_PRE_ROUTING, ifp, NULL);
		if (unlikely(res != FP_CONTINUE))
			return res;
	}
#endif

#ifdef CONFIG_MCORE_RPF_IPV6
	if (unlikely(m2ifnet(m)->if_flags & IFF_FP_IPV6_RPF) &&
	    fp_ip6_rpf_check(m)) {
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpInAddrErrors);
		TRACE_IP(FP_LOG_DEBUG,"packet is dropped by RPF");
		return FP_DROP;
	}
#endif

	TRACE_IP(FP_LOG_DEBUG, "HOP_LIMIT = %d", ip6->ip6_hlim);
	TRACE_IP(FP_LOG_DEBUG, "Searching for a route for %x:%x:%x:%x:%x:%x:%x:%x...",
		 NIPOCT(ip6->ip6_dst));
	TRACE_IP(FP_LOG_DEBUG, "(Source %x:%x:%x:%x:%x:%x:%x:%x)", NIPOCT(ip6->ip6_src));

	/* multicast6 and reserved IPv6 destination are exceptions. */
	if (unlikely(in6_canforward(&ip6->ip6_dst) == 0)) {
		TRACE_IP(FP_LOG_INFO, "Packet with ipv6 reserved address");
		return fp_ip_prepare_exception(m, FPTUN_EXC_IP_DST);
	}

#ifdef CONFIG_MCORE_MULTICAST6
	/* multicast forward process */
	if (unlikely(FP_IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)))
		return fp_mcast6_input(m);
#endif /* CONFIG_MCORE_MULTICAST6 */

	/* lookup in the FW table */
	rt = fp_rt6_lookup(m2vrfid(m), &ip6->ip6_dst); /* fp_in6_addr_t */

	if (unlikely(!rt)) {
		/* send ICMP error HOST Unreachable */
		TRACE_IP(FP_LOG_INFO, "Route not found");
		return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
	}

	nh = select_nh6(rt, &ip6->ip6_src);
	TRACE_IP(FP_LOG_INFO, "Route found %x:%x:%x:%x:%x:%x:%x:%x",
		 NIPOCT(nh->nh_gw));

#ifdef CONFIG_MCORE_NEXTHOP_MARKING
	if (nh->nh.nh_mark)
		fp_nf_update_mark(m, nh->nh.nh_mark, (nh->nh.nh_mark | nh->nh.nh_mask));
#endif
	
	rt_type = nh->nh.rt_type;
	if (likely((rt_type & RT_TYPE_EXCEPTION_MASK) == 0))
		return fp_ip6_output(m, rt, nh);
	else
		return fp_ip6_input_local(m, rt_type);
}

#ifdef CONFIG_MCORE_IPV6_REASS
static inline int fp_ip6_force_reass(struct mbuf *m)
{
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	fp_nh6_entry_t *nh;
	fp_ifnet_t *ifp;
	fp_rt6_entry_t *rt;
	int res;

	rt = fp_rt6_lookup(m2vrfid(m), &ip6->ip6_dst); /* fp_in6_addr_t */
	if (unlikely(!rt)) {
		/* send ICMP error HOST Unreachable */
		TRACE_IP(FP_LOG_INFO, "Route not found");
		return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
	}
	nh = select_nh6(rt, &ip6->ip6_src);
	if (likely((nh->nh.rt_type & RT_TYPE_EXCEPTION_MASK) == 0)) {
		ifp = __fp_ifuid2ifnet(nh->nh.nh_ifuid);

		/* Like SP, before reassembly fragments, check if Host has
		 * done fragmentation needed, if not, send exception.
		 */
		if (unlikely((ntohs(ip6->ip6_plen)+sizeof(struct fp_ip6_hdr)) >
		     ifp->if_mtu)) {
			TRACE_IP(FP_LOG_INFO, "Too large for interface(%d)",
				 (int)(ntohs(ip6->ip6_plen)+sizeof(struct fp_ip6_hdr)));
			return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
		}
	}

	res = fp_ip6_reass(&m);

	if (res == FP_CONTINUE) {
		m_priv(m)->flags |= M_F_REASS;
		m_priv(m)->exc_type = FPTUN_IPV6_INPUT_EXCEPT;
		res = fp_ip6_input2(m);
	}

	/*
	 * Packet was modified (previous mbuf doesn't exist anymore)
	 * we MUST do the fp_process_input_finish() ourselves, as the
	 * the initial caller doesn't know anything about the new mbuf
	 */
	fp_process_input_finish(m, res);
	return FP_DONE;
}
#endif

int fp_ip6_input(struct mbuf *m)
{
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	int res;

	res = mbuf_check_ipv6(m);
	if (unlikely(res >=1 )) {
		if (res == 1) {
			TRACE_IP(FP_LOG_INFO, "IPv6 exception");
			return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
		}
		TRACE_IP(FP_LOG_INFO, "IPv6 error");
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpInHdrErrors);
		return FP_DROP;
	}

	/* trim too long packet: note that pkt_len may be zero if
	 * Jumbo payload option is present, but in this case, the
	 * packet has already beeing sent to CP (exception) */
	if (unlikely(ntohs(ip6->ip6_plen) + sizeof(struct fp_ip6_hdr) < m_len(m)))
		m_trim(m, m_len(m) - ntohs(ip6->ip6_plen) - sizeof(struct fp_ip6_hdr));

	 /* TODO TC input */

	/* TODO multicast and reserved IP destination are exceptions. */
#ifdef CONFIG_MCORE_IPV6_REASS
	if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_FORCED_REASS)) {
		if (unlikely(ip6->ip6_nxt == FP_IPPROTO_FRAGMENT) &&
		    m2ifnet(m)->if_flags & IFF_FP_IPV6_FORCE_REASS) {
			return fp_ip6_force_reass(m);
		}
	}
#endif /* CONFIG_MCORE_IPV6_REASS */

	return fp_ip6_input2(m);
}
FPN_HOOK_REGISTER(fp_ip6_input)

static void preflen2mask6(int mask_len, fp_in6_addr_t *mask)
{
	int i;

	memset(mask, 0, sizeof(*mask));
	for (i = 0; i < 4; i++) {
		if (mask_len > 32)
			mask->fp_s6_addr32[i] = 0xffffffff;
		else if (mask_len > 0)
			mask->fp_s6_addr32[i] = ((uint32_t)0xffffffff) \
				<< (32 - mask_len);
		mask->fp_s6_addr32[i] = htonl(mask->fp_s6_addr32[i]);

		mask_len -= 32;
		if (mask_len < 0)
			return;
	}
}

static void apply_mask6(fp_in6_addr_t * addr, fp_in6_addr_t mask)
{
	addr->fp_s6_addr32[0] &= mask.fp_s6_addr32[0];
	addr->fp_s6_addr32[1] &= mask.fp_s6_addr32[1];
	addr->fp_s6_addr32[2] &= mask.fp_s6_addr32[2];
	addr->fp_s6_addr32[3] &= mask.fp_s6_addr32[3];
}

/* This function allows to select a source address for a specified destination.
 * The source address is returned via the argument srcp.
 * If rt is provided, the result of fp_rt6_lookup() is returned to the caller
 * via this argument.
 */
int fp_rt6_selectsrc(uint32_t vrfid, struct fp_in6_addr *dst,
		     struct fp_in6_addr *srcp,
		     fp_rt6_entry_t **rt)
{
	fp_ifnet_t *ifp;  /* target interface */
	fp_in6_addr_t src = (struct fp_in6_addr){ { { 0 } } };
	fp_in6_addr_t src_default = (struct fp_in6_addr){ { { 0 } } };
	fp_in6_addr_t mask;
	fp_in6_addr_t prefix;
	int lastpass = 0;
	uint8_t rt_type;
	uint32_t idx;
	uint32_t ifuid = 0;
	int error = 0;

	fp_rt6_entry_t *rt6;
	fp_nh6_entry_t *nh6;

again:
	TRACE_IP(FP_LOG_DEBUG, "looking up for "FP_NIP6_FMT
		  " vrfid %" PRIu16, FP_NIP6(*dst), vrfid);

	rt6 = fp_rt6_lookup(vrfid, dst);
	if (rt)
	       *rt = rt6;

	if (rt6 == NULL) {
		TRACE_IP(FP_LOG_DEBUG, "no route found");
		goto end;
	}

	/* rt entry found, look at next hops */
	nh6 = &fp_shared->fp_nh6_table[rt6->rt.rt_next_hop[0]];
	ifuid = nh6->nh.nh_ifuid;

	ifp = __fp_ifuid2ifnet(ifuid);
	/* only one ip address, it should be this one */
	if (ifp->if_nb_addr6 == 1) {
		src = fp_pool_addr6_object(ifp->if_addr6_head_index).addr6;
		TRACE_IP(FP_LOG_DEBUG, "\tsrc "FP_NIP6_FMT" on %s via ifp",
			  FP_NIP6(src), fp_ifuid2str(ifuid));
		goto end;
	}
	/* more that one ip address, we should try to find the exact one by
	 * looking in the route table.
	 * Anyway save the first ip address, in case we can't find this one
	 * in the route table */
	else if (ifp->if_nb_addr6 > 0) {
		src_default = fp_pool_addr6_object(ifp->if_addr6_head_index).addr6;
		TRACE_IP(FP_LOG_DEBUG, "\tsrc_default "FP_NIP6_FMT" on %s",
			  FP_NIP6(src_default), fp_ifuid2str(ifuid));
	}

	rt_type = nh6->nh.rt_type;
	if (FP_LOG_COND(FP_LOG_DEBUG, FP_LOGTYPE_IP)) {
		prefix = *dst;
		preflen2mask6(rt6->rt.rt_length, &mask);
		apply_mask6(&prefix, mask);
		TRACE_IP(FP_LOG_DEBUG, "found %s route to "FP_NIP6_FMT"/%d",
			  fp_rt_type2str(rt_type),
			  FP_NIP6(prefix), rt6->rt.rt_length);
	}

	/* basic route, lookup for a route to the gateway */
	if (rt_type == RT_TYPE_ROUTE) {
		*dst = nh6->nh_gw;
		TRACE_IP(FP_LOG_DEBUG, "\tgateway "FP_NIP6_FMT,
			  FP_NIP6(*dst));
		if (lastpass)
			goto end;
		lastpass=1;
		goto again;
	}

	/* destination is one of my addresses. return it */
	if (rt_type == RT_TYPE_ADDRESS) {
		src = *dst;
		goto end;
	}

	/* connected route. return preferred source, stored in gw */
	if (rt_type == RT_TYPE_ROUTE_CONNECTED) {
		src = nh6->nh_src;
		TRACE_IP(FP_LOG_DEBUG, "\tsrc "FP_NIP6_FMT" on %s via lookup",
			  FP_NIP6(src), fp_ifuid2str(ifuid));
		goto end;
	}

	/* neighbour entry. Look for the connected route it depends from */
	if (rt_type == RT_TYPE_NEIGH) {
		TRACE_IP(FP_LOG_DEBUG, "\tgateway "FP_NIP6_FMT,
			  FP_NIP6(nh6->nh_gw));

		if (!is_in6_addr_equal(nh6->nh_gw, *dst)) {
			*dst = nh6->nh_gw;
			if (lastpass)
				goto end;
			lastpass=1;
			goto again;
		}

		idx = rt6->rt.rt_next;

		if (idx == 0) {
			TRACE_IP(FP_LOG_DEBUG, "no connected route for neighbor");
			goto end;
		}

		rt6 = &fp_shared->fp_rt6_table[idx];
		nh6 = &fp_shared->fp_nh6_table[rt6->rt.rt_next_hop[0]];

		rt_type = nh6->nh.rt_type;
		if (FP_LOG_COND(FP_LOG_DEBUG, FP_LOGTYPE_PCB)) {
			prefix = *dst;
			preflen2mask6(rt6->rt.rt_length, &mask);
			apply_mask6(&prefix, mask);
			TRACE_IP(FP_LOG_DEBUG, "found %s route to "FP_NIP6_FMT"/%u",
				  fp_rt_type2str(rt_type),
				  FP_NIP6(prefix), rt6->rt.rt_length);
		}

		/* found. return preferred source, stored in gw */
		if (rt_type == RT_TYPE_ROUTE_CONNECTED) {
			src = nh6->nh_src;
			ifuid = nh6->nh.nh_ifuid;
			(void)ifuid; /* value can be never read */
			TRACE_IP(FP_LOG_DEBUG, "\tsrc "FP_NIP6_FMT" on %s",
				  FP_NIP6(src), fp_ifuid2str(ifuid));
			goto end;
		} else {
			TRACE_IP(FP_LOG_DEBUG, "no connected route for neighbor");
			goto end;
		}

	}

	if (rt_type == RT_TYPE_ROUTE_LOCAL ||
			rt_type == RT_TYPE_ROUTE_BLACKHOLE)
		goto end;

	TRACE_IP(FP_LOG_DEBUG, "internal error: unsupported route type");

end:
	/* source address is found, return it */
	if (likely(!is_in6_addr_null(src)))
		goto found;
	/* if source default address is defined, uses this one as source */
	else if (!is_in6_addr_null(src_default)) {
		src = src_default;
		goto found;
	}
	error = EADDRNOTAVAIL;
	return error;

found:
	TRACE_IP(FP_LOG_DEBUG, "=> returning "FP_NIP6_FMT, FP_NIP6(src));
	*srcp = src;
	return error;
}
