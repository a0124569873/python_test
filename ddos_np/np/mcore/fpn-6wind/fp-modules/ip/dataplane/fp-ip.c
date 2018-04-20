/*
 * Copyright(c) 2010 6WIND
 */
#include "fp-includes.h"

#include "fp-log.h"
#include "fp-main-process.h"
#include "fp-fragment.h"

#include "fpn-cksum.h"
#include "fp-lookup.h"
#ifdef CONFIG_MCORE_FORCE_HW_TSO
#include "fpn-port.h"
#endif

#ifdef CONFIG_MCORE_IPSEC
#include "fp-ipsec-lookup.h"
#include "fp-ipsec-input.h"
#include "fp-ipsec-output.h"
#endif

#ifdef CONFIG_MCORE_IP_REASS
#include "fp-reass.h"
#endif

#ifdef CONFIG_MCORE_NETFILTER
#include "fp-nf-tables.h"
#endif

#ifdef CONFIG_MCORE_TCP_MSS
#include "fp-tcp-mss.h"
#endif

#ifdef CONFIG_MCORE_SOCKET
#include "fp-so.h"
#endif

#ifdef CONFIG_MCORE_XIN4
#include "fp-tunnels.h"
#endif

#include "fp-ether.h"
#include "fp-ip.h"
#ifdef CONFIG_MCORE_MULTICAST4
#include "fp-mcast.h"
#endif

#ifdef CONFIG_MCORE_VXLAN
#include "fp-vxlan.h"
#endif

#include "netinet/fp-tcp.h"
#ifdef CONFIG_MCORE_SOCKET
#include "netinet/fp-udp.h"
#include "fp-bsd/netinet/udp_var.h"
#include "fp-bsd/netinet/tcp_timer.h"
#include "fp-bsd/netinet/tcp.h"
#include "fp-bsd/netinet/tcp_var.h"
#endif

#define TRACE_MAIN_PROC(level, fmt, args...) do {		\
	FP_LOG(level, MAIN_PROC, fmt "\n", ## args);		\
} while(0)

#define TRACE_IP(level, fmt, args...) do {			\
	FP_LOG(level, IP, fmt "\n", ## args);			\
} while(0)

FPN_SLIST_HEAD(fp_ip_proto_handler_lst, fp_ip_proto_handler);

static FPN_DEFINE_SHARED(struct fp_ip_proto_handler_lst,
                         fp_ip_proto_handlers[FP_IPPROTO_MAX]);

/* Return
 * 0 if IPv4 packet is good
 * 1 if IPv4 packet is an exception
 * 2 if IPv4 packet should be dropped
 */
static inline int mbuf_check_ipv4(struct mbuf *m)
{
    struct fp_ip* ip;

#ifdef FPN_HAS_HW_CHECK_IPV4
	int res = fpn_mbuf_hw_check_ipv4(m);
	if (likely(res >= 0))
		return res;
	/* fall down to software check */
#endif

    ip = mtod(m, struct fp_ip *);
    if (unlikely(m_len(m) < (int)sizeof(struct fp_ip)))
	    return 2;
    if (unlikely(ip->ip_v != FP_IPVERSION))
	    return 2;

    /* IP options
     * malformed header
     * too short
     * TTL is 0
     * checksum error
     */

    /* IP opt and malformed header */
    if (unlikely(ip->ip_hl != (sizeof(struct fp_ip) >> 2)))
	    return 1;

    if (unlikely(ntohs(ip->ip_len) > m_len(m))) /* too short */
	    return 1;

    if (unlikely(ip->ip_ttl == 0)) /* TTL is 0 */
	    return 1;

    /* Conform to RFC1071 for cksum verification */
    if (unlikely(fpn_ip_hdr_noopt_cksum_check(ip)))
	    return 2;

    return 0;
}


/*
 * Determine whether an IP address is in a reserved set of addresses
 * that may not be forwarded, or whether datagrams to that destination
 * may be forwarded.
 */
static inline int in_canforward(uint32_t i)
{
	uint32_t net;

#ifdef CONFIG_MCORE_MULTICAST4
	if (unlikely((FP_IN_EXPERIMENTAL(i) || FP_IN_LOCAL_MULTICAST(i))))
#else
	if (unlikely((FP_IN_EXPERIMENTAL(i) || FP_IN_MULTICAST(i))))
#endif
		return 0;
	if (unlikely(FP_IN_CLASSA(i))) {
		net = i & FP_IN_CLASSA_NET;
		if (net == 0 || net == (FP_INADDR_LOOPBACK & FP_IN_CLASSA_NET))
			return 0;
	}
	return 1;
}

static inline uint32_t fp_ip_filter_src(uint32_t i)
{
	return (FP_IN_EXPERIMENTAL(i) || FP_IN_MULTICAST(i) || FP_IN_LOOPBACK(i));
}

/* If it's a TCP packet and if force_tso is enabled, return 0 and fill
 * hw offload data in mbuf. This function is called only if the packet
 * is bigger than MTU. */
static int fp_ip_force_tso(__fpn_maybe_unused struct mbuf *m, __fpn_maybe_unused fp_ifnet_t *ifp)
{
#if defined(FPN_HAS_TSO) && defined(CONFIG_MCORE_FORCE_HW_TSO)
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	struct fp_tcphdr *tcp;
	int portid;
	unsigned l2_len, l3_len, l4_len, mss;

	portid = ifp->if_port;
	if (portid == FP_IFNET_VIRTUAL_PORT)
		return -1;

	if (fpn_port_shmem->port[portid].force_tso_at_mtu == 0)
		return -1;

	if (ip->ip_p != FP_IPPROTO_TCP)
		return -1;

	l2_len = sizeof(struct ether_hdr); /* vlan not supported */
	l3_len = ip->ip_hl << 2;
	tcp = (struct fp_tcphdr *)((char *)ip + l3_len);
	l4_len = tcp->th_off << 2;

	if (ifp->if_mtu < l4_len + l3_len)
		return -1;

	mss = ifp->if_mtu - (l4_len + l3_len);
	m_set_tso(m, mss, l2_len, l3_len, l4_len);

	return 0;
#else
	return -1;
#endif
}

static inline int __fp_fast_ip_output(struct mbuf *m, fp_rt4_entry_t *rt, fp_nh4_entry_t *nh, const int fast_forward)  __attribute__((always_inline));
static inline int __fp_fast_ip_output(struct mbuf *m, fp_rt4_entry_t *rt, fp_nh4_entry_t *nh, const int fast_forward) 
{
	fp_ifnet_t *ifp;
	struct fp_ip *ip;
	uint16_t mtu;
#ifdef CONFIG_MCORE_NETFILTER
	int postrouting_done = 0;
#endif
	int is_tso = 0;

	ip = mtod(m, struct fp_ip *);
	ifp = __fp_ifuid2ifnet(nh->nh.nh_ifuid);

	if (likely(!(m_priv(m)->flags & M_LOCAL_OUT))) {
		/* Forwarding case */

		if (unlikely(fp_ip_filter_src(ip->ip_src.s_addr))) {
			/*
			 * drop packets with martian source address
			 * such as loopback, multicast, etc.
			 */
			FP_IP_STATS_INC(fp_shared->ip_stats, IpInAddrErrors);
			TRACE_IP(FP_LOG_DEBUG,"Packet with martian source address");
			return FP_DROP;
		}

#ifdef CONFIG_MCORE_IPSEC_VERIFY_INBOUND
		if ((fp_shared->conf.w32.do_func & FP_CONF_DO_IPSEC_IN) && 
		    !(m_priv(m)->flags & M_IPSEC_SP_OK)) {
			int res = ipsec_check_policy(m, ip);
			if (unlikely(res != FP_CONTINUE))
				return res;
		}
#endif
#ifdef CONFIG_MCORE_NETFILTER
		if (fast_forward == 0) {
			if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_NETFILTER)) {
				int res = fp_nf_hook(m, FP_NF_IP_FORWARD,
						__fp_ifuid2ifnet(m_priv(m)->ifuid),
						ifp);
				if (unlikely(res != FP_CONTINUE))
					return res;
			}
		}
#endif
	} else if (fast_forward == 0) {
		/* Local out case */
#ifdef CONFIG_MCORE_NETFILTER
		if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_NETFILTER)) {
#ifdef CONFIG_MCORE_NETFILTER_ENHANCED
			fp_nfct_reset(m);
#endif
#ifdef CONFIG_MCORE_IPSEC
			/* IPsec'd packets don't go through LOCAL_OUT hook */
			if (!(m_priv(m)->flags & M_IPSEC_OUT))
#endif
			{
				int res;
#ifndef CONFIG_MCORE_NETFILTER_ENHANCED
				/* we called it just above in case of nf enhanced */
				fp_nfct_reset(m);
#endif
				res = fp_nf_hook(m, FP_NF_IP_LOCAL_OUT,
						 __fp_ifuid2ifnet(m_priv(m)->ifuid),
						 ifp);
				if (unlikely(res != FP_CONTINUE))
					return res;
			}
		}
#endif
	}

	if (unlikely(ifp->if_ifuid==0)) {
		TRACE_MAIN_PROC(FP_LOG_WARNING, "Unexpected/Invalid interface");
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedInvalidInterface);
		return FP_DROP;
	}

#ifdef CONFIG_MCORE_IPSEC
	if (fast_forward == 0) {
		if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_IPSEC_OUT)) {
			/* Bypass SPD lookup in the following cases:
			 * - if 'IPsec only once' option is enabled and IPsec
			 *   processing has already occured on this packet
			 * - if packet has just been encrypted
			 *   => prohibit multiple IPsec transformations
			 * - if output interface is an SVTI interface
			 */

			if (!(m_priv(m)->flags & (M_IPSEC_BYPASS|M_IPSEC_OUT))
#ifdef CONFIG_MCORE_IPSEC_SVTI
				&& ifp->if_type != FP_IFTYPE_SVTI
#endif
				) {
				int res;
#ifdef CONFIG_MCORE_NETFILTER_ENHANCED
				/* Go through postrouting before IPsec. */
				if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_NETFILTER)) {
					res = fp_nf_hook(m, FP_NF_IP_POST_ROUTING, NULL, ifp);
					if (unlikely(res != FP_CONTINUE))
						return res;
				}
#endif

				res = fp_ipsec_output(m);
				if (unlikely(res != FP_CONTINUE))
					return res;
#ifdef CONFIG_MCORE_NETFILTER_ENHANCED
				/* If fp_ipsec_output() returns FP_CONTINUE, then packet
				 * was not mangle, so there is not need to call POST_ROUTING
				 * hook again.
				 */
				postrouting_done = 1;
#endif
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
	    rt->rt.rt_length == 32 &&
	    nh->nh_gw == ip->ip_dst.s_addr) {
		TRACE_MAIN_PROC(FP_LOG_NOTICE, "Destination on same link");
		return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
	}

	if (unlikely(ip->ip_ttl <= FP_IPTTLDEC)) {
		/* SP sends icmp error */
		TRACE_MAIN_PROC(FP_LOG_INFO, "TTL exceed");
		return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
	}

	mtu = ifp->if_mtu;
	/* Raise exception before POST_ROUTING NAT */
	/* Don't fragment if
	 * - DF flag is set and local fragmentation is not allowed
	 * - ip option is present
	 */
	if (unlikely(((ntohs(ip->ip_off) & FP_IP_DF &&
		      !(m_priv(m)->flags & M_LOCAL_F)) &&
		     unlikely(ntohs(ip->ip_len) > mtu)) ||
		     ip->ip_hl > 5)) {

		/* check if it's a TCP packet and if force segmentation
		 * is enabled, else send as exception */
		if (fp_ip_force_tso(m, ifp) < 0)
			return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
		is_tso = 1;
	}

#ifdef CONFIG_MCORE_NETFILTER
	if (fast_forward == 0) {
		/* Go through postrouting before fragmentation, it will save time. */
		if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_NETFILTER && !postrouting_done)) {
			int res = fp_nf_hook(m, FP_NF_IP_POST_ROUTING, NULL, ifp);
			if (unlikely(res != FP_CONTINUE))
				return res;
		}
	}
#endif

#ifdef CONFIG_MCORE_TCP_MSS
	if (ifp->if_tcp4mss)
		fp_update_tcpmss_by_dev(m, ifp, AF_INET);
#endif

#ifdef CONFIG_MCORE_IP_REASS
	/* If reassembly was forced, and if the "don't fragment" bit
	 * was set, maximize mtu by the longest size of received
	 * fragment */
	if ( (m_priv(m)->flags & M_F_REASS) &&
	     (ntohs(ip->ip_off) & FP_IP_DF) &&
	     (m_priv(m)->max_frag_size < mtu) ) {
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "mtu limited by max_frag_size=%d, mtu=%d", m_priv(m)->max_frag_size, mtu);
		mtu = m_priv(m)->max_frag_size;
	}
#endif

	if (unlikely(ntohs(ip->ip_len) > mtu && is_tso == 0)) {
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "Too large for interface (len=%d, mtu=%d)", ntohs(ip->ip_len), mtu);

#ifdef CONFIG_MCORE_USE_HW_TX_L4CKSUM
		fpn_deferred_in4_l4cksum_set(m, 0);
#endif

		return fp_ip_fragment(m, mtu, fp_ip_send_fragment, nh, ifp);
	}

	return fp_ip_if_send(m, nh, ifp);
}

int fp_ip_output(struct mbuf *m, fp_rt4_entry_t *rt, fp_nh4_entry_t *nh)
{
	return __fp_fast_ip_output(m, rt, nh, 0);
}

int fp_fast_ip_output(struct mbuf *m, fp_rt4_entry_t *rt, fp_nh4_entry_t *nh)
{
	return __fp_fast_ip_output(m, rt, nh, 1);
}

#ifdef CONFIG_MCORE_SOCKET

/* #define DUMP_TCPIP */

#ifdef DUMP_TCPIP
static void dump_tcpip(struct mbuf *m, const char *str)
{
	struct fp_ip *ip;
	struct fp_tcphdr *tcp;
	uint32_t ipsrc, ipdst;
	uint16_t sport, dport;

	ip = mtod(m, struct fp_ip *);
	tcp = (struct fp_tcphdr *) (ip + 1);

	m_check(m);

	if (unlikely(ip->ip_p != FP_IPPROTO_TCP))
		return;

	ipsrc = ip->ip_src.s_addr;
	ipdst = ip->ip_dst.s_addr;

	sport = tcp->th_sport;
	dport = tcp->th_dport;

	fpn_printf("%s "
		   FP_NIPQUAD_FMT":%u -> "
		   FP_NIPQUAD_FMT":%u "
		   "len=%u, seq=%lu, ack=%lu, flags=%s%s%s%s%s\n", str,
		   FP_NIPQUAD(ipsrc), ntohs(sport),
		   FP_NIPQUAD(ipdst), ntohs(dport),
		   (unsigned)ntohs(ip->ip_len),
		   (long)ntohl(tcp->th_seq), (long)ntohl(tcp->th_ack),
		   (tcp->th_flags&TH_SYN) ? "S" : "",
		   (tcp->th_flags&TH_PUSH) ? "P" : "",
		   (tcp->th_flags&TH_FIN) ? "F" : "",
		   (tcp->th_flags&TH_ACK) ? "A" : "",
		   (tcp->th_flags&TH_RST) ? "R" : "");
}
#endif

int fp_ip_route_and_output(struct mbuf *m, int hlen)
{
	fp_rt4_entry_t *rt;
	fp_nh4_entry_t *nh;
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	int ret;

	rt = fp_rt4_lookup(m2vrfid(m), ip->ip_dst.s_addr);
	if (rt == NULL) {
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoRouteLocal);
		m_freem(m);
		return -1;
	}
	nh = select_nh4(rt, &ip->ip_src.s_addr);
	m_priv(m)->exc_type = FPTUN_IPV4_OUTPUT_EXCEPT;
	m_priv(m)->flags |= M_LOCAL_OUT;
	ip->ip_v = FP_IPVERSION;
	ip->ip_off = htons(0);
	ip->ip_hl = hlen >> 2;
	ip->ip_sum = 0;
	ip->ip_sum = fpn_ip_hdr_cksum(ip, hlen);
#ifdef DUMP_TCPIP
	dump_tcpip(m, "out");
#endif
	switch (ip->ip_p) {
		case FP_IPPROTO_TCP: {
			struct fp_tcphdr *th;
			th = (struct fp_tcphdr *)(mtod(m, char *) + hlen);
			th->th_sum = 0;
#if defined(FPN_HAS_TX_CKSUM) && defined(CONFIG_MCORE_USE_HW_TX_L4CKSUM)
			m_set_tx_tcp_cksum(m);
#else
			th->th_sum = fpn_in4_l4cksum(m);
#endif
			break;
		}
		case FP_IPPROTO_UDP: {
			struct fp_udphdr *uh;
			uh = (struct fp_udphdr *)(mtod(m, char *) + hlen);
			uh->uh_sum = 0;
#if defined(FPN_HAS_TX_CKSUM) && defined(CONFIG_MCORE_USE_HW_TX_L4CKSUM)
			m_set_tx_udp_cksum(m);
#else
			uh->uh_sum = fpn_in4_l4cksum(m);
			if (uh->uh_sum == 0)
				uh->uh_sum = 0xffff;
#endif
			break;
		}
		default:
			break;
	}

	ret = fp_ip_output(m, rt, nh);

	fp_process_input_finish(m, ret);
	return 0;
}
#endif /* CONFIG_MCORE_SOCKET */

/* Send a packet on an IP interface. In this function, we assume
 * ifp->if_type is not ether-like, so we don't need a
 * fp_nh4_entry_t. */
int fp_ip_inetif_send(struct mbuf *m, fp_ifnet_t *ifp)
{
	ip_output_ops_t *ip_output;
	void *data;

#ifdef CONFIG_MCORE_USE_HW_TX_L4CKSUM
	fpn_deferred_in4_l4cksum_set(m, 0);
#endif
#ifdef CONFIG_MCORE_TAP
	if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_TAP))
		fp_tap(m, ifp, htons(FP_ETHERTYPE_IP));
#endif
#ifdef CONFIG_MCORE_VRF
	/*
	 * This may be a cross-VR forwarding
	 */
	if (likely(ifp->if_type == FP_IFTYPE_LOOP)) {
		struct fp_ip *ip = mtod(m, struct fp_ip *);

		TRACE_IP(FP_LOG_DEBUG, "cross-vrf fwd from %d to %d",
			 m_priv(m)->vrfid, ifp->if_vrfid);
		m_priv(m)->exc_type = FPTUN_LOOP_INPUT_EXCEPT;
		m_priv(m)->exc_proto = htons(FP_ETHERTYPE_IP);
		fp_change_ifnet_packet(m, ifp, 1, 1);
		/* fp_reset_hw_flags() not required since HW did at the same level */
		/* Update TTL (from bsd netinet/ip_flow.c) */
		ip->ip_ttl -= FP_IPTTLDEC;
		if (unlikely(ip->ip_sum >= htons(0xffff - (FP_IPTTLDEC << 8))))
			ip->ip_sum += htons(FP_IPTTLDEC << 8) + 1;
		else
			ip->ip_sum += htons(FP_IPTTLDEC << 8);
		/* TODO reschedule the packet */
		return FPN_HOOK_CALL(fp_ip_input)(m);
	}
#endif
#ifdef CONFIG_MCORE_XIN4
	if (likely(ifp->if_type == FP_IFTYPE_XIN4)) {
		TRACE_IP(FP_LOG_DEBUG, "Need to process by Xin4 tunnel");
		return fp_xin4_output(m, ifp, FP_IPPROTO_IPV4);
	}
#endif
#ifdef CONFIG_MCORE_XIN6
	if (likely(ifp->if_type == FP_IFTYPE_XIN6)) {
		TRACE_IP(FP_LOG_DEBUG, "Need to process by XIN6 tunnel");
		return fp_xin6_output(m, ifp, FP_IPPROTO_IPV4);
	}
#endif
#ifdef CONFIG_MCORE_IPSEC_SVTI
	if (likely(ifp->if_type == FP_IFTYPE_SVTI)) {
		TRACE_IP(FP_LOG_DEBUG, "Need to process by SVTI tunnel");
		return fp_svti_output(m, ifp);
	}
#endif

	ip_output = fp_ifnet_ops_get(ifp, IP_OUTPUT_OPS, &data);
	if (unlikely(ip_output != NULL)) {
		int ret = ip_output(m, ifp, AF_INET, data);
		if (ret != FP_CONTINUE)
			return ret;
	}

	TRACE_IP(FP_LOG_INFO, "Outgoing interface %s is virtual", ifp->if_name);
	return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
}
FPN_HOOK_REGISTER(fp_ip_inetif_send)

/* Send an IP packet on a device */
int fp_ip_if_send(struct mbuf *m, fp_nh4_entry_t *nh, fp_ifnet_t *ifp)
{
	struct fp_ip *ip;

	M_TRACK(m, "IF_SEND");

	ip = mtod(m, struct fp_ip *);

	if (unlikely(!FP_IS_IFTYPE_ETHER(ifp->if_type)))
		return FPN_HOOK_CALL(fp_ip_inetif_send)(m, ifp);

	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);	
		return FP_DROP;
	}

	/* check ARP resolution */
	if (unlikely(nh->nh.nh_l2_state != L2_STATE_REACHABLE)) {
		if (likely(nh->nh.nh_l2_state == L2_STATE_STALE)) {
			if (unlikely(!nh->nh.nh_hitflag))
				nh->nh.nh_hitflag = 1;
		} else if (likely(nh->nh.nh_l2_state == L2_STATE_INCOMPLETE)) {
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoArp);
			TRACE_IP(FP_LOG_INFO, "ARP resolution in progress");
			return FP_DROP; /* L2 resolution is in progress */
		} else { /* L2_STATE_NONE */
			TRACE_IP(FP_LOG_INFO, "Need ARP resolution");
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

	/*
	 * Forwarding action is:
	 *  - test capability of outgoing interface
	 *  - TTL decr
	 *  - ip checksum update
	 * Pkt not concerned are
	 *  - locally generated (IPsec encaps, GRE, ..)
	 */
	if (unlikely(m_priv(m)->flags & M_LOCAL_OUT))
		goto skip_fwd;

	if (unlikely(!(ifp->if_flags & IFF_CP_IPV4_FWD))) {
		TRACE_IP(FP_LOG_INFO, "IPv4 forwarding disabled on %s", ifp->if_name);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedForwarding);
		return FP_DROP;
	}

	/* Update TTL (from bsd netinet/ip_flow.c) */
	ip->ip_ttl -= FP_IPTTLDEC;
	if (unlikely(ip->ip_sum >= htons(0xffff - (FP_IPTTLDEC << 8))))
		ip->ip_sum += htons(FP_IPTTLDEC << 8) + 1;
	else
		ip->ip_sum += htons(FP_IPTTLDEC << 8);

	FP_IP_STATS_INC(fp_shared->ip_stats, IpForwDatagrams);

skip_fwd:
	/*
	 * We are going to forward the packet, so mark exception type
	 * as local sending exception for IPv4 forwarding.
	 */
	m_priv(m)->exc_type = FPTUN_IPV4_OUTPUT_EXCEPT;

	return FPN_HOOK_CALL(fp_ether_output)(m, (struct fp_ether_header *)&nh->nh.nh_eth, ifp);
}

int fp_ip_proto_handler_register(u_char proto, fp_ip_proto_handler_t *handler)
{
	if (!handler || !handler->func)
		return -1;
	FPN_SLIST_INSERT_HEAD(&fp_ip_proto_handlers[proto], handler, next);
	return 0;
}

static inline int fp_ip_input_demux(struct mbuf *m)
{
	struct fp_ip *ip = mtod(m, struct fp_ip *);

#ifdef CONFIG_MCORE_IPSEC
	if ((ip->ip_p == FP_IPPROTO_AH) || (ip->ip_p == FP_IPPROTO_ESP))
		return ipsec4_input(m, ip); /* including FP_KEEP */

	/* NAT-Traversal packet? */
	if (ip->ip_p == FP_IPPROTO_UDP) {
		uint16_t lport;
		uint16_t off = (ip->ip_hl << 2) + 2; /* dest port offset */

		/* Extract packet local port */
		if (likely(m_headlen(m) >= off + sizeof(lport)))
			lport = *(uint16_t*)(mtod(m, uint8_t*) + off);
		else if (m_copytobuf(&lport, m, off, sizeof(lport)) < sizeof(lport)) {
			TRACE_IP(FP_LOG_WARNING, "%s: protocol %u: header too short (%u bytes)",
				 __FUNCTION__, ip->ip_p, m_len(m) - (ip->ip_hl << 2));
			FP_IP_STATS_INC(fp_shared->ip_stats, IpInHdrErrors);
			return FP_DROP;
		}

		/* NAT-Traversal port? */
		if (lport == htons(4500)) {
			int ret = ipsec4_input_traversal(m, ip);
			if (likely(ret != FP_CONTINUE))
				return ret;
#ifdef CONFIG_MCORE_IPSEC_VERIFY_INBOUND
			/* IKE case: let this packet go to SP, it will check
			 * if a socket policy exists.
			 */
			m_priv(m)->flags |= M_IPSEC_SP_OK;
#endif
		}
#ifdef CONFIG_MCORE_IPSEC_VERIFY_INBOUND
		/* IKE case: let this packet go to SP, it will check
		 * if a socket policy exists.
		 */
		else if (lport == htons(500))
			m_priv(m)->flags |= M_IPSEC_SP_OK;
#endif

	}
#endif

#ifdef CONFIG_MCORE_NETFILTER
	if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_NETFILTER)) {
		fp_ifnet_t *ifp = __fp_ifuid2ifnet(m_priv(m)->ifuid);
		int res;

		res = fp_nf_hook(m, FP_NF_IP_LOCAL_IN, ifp, NULL);
		if (unlikely(res != FP_CONTINUE))
			return res;
	}
#endif
#ifdef CONFIG_MCORE_IPSEC_VERIFY_INBOUND
	if ((fp_shared->conf.w32.do_func & FP_CONF_DO_IPSEC_IN) &&
	    !(m_priv(m)->flags & M_IPSEC_SP_OK)) {
		int res = ipsec_check_policy(m, ip);
		if (unlikely(res != FP_CONTINUE))
			return res;
	}
#endif

#ifdef CONFIG_MCORE_XIN4
	if ((ip->ip_p == FP_IPPROTO_IPV4)
#ifdef CONFIG_MCORE_IPV6
			|| (ip->ip_p == FP_IPPROTO_IPV6)
#endif
		   )
			return fp_xin4_input(m, ip);
#endif

#ifdef CONFIG_MCORE_VXLAN
	{
		int res = fp_vxlan4_input(m, ip);

		if (res != FP_CONTINUE)
			return res;
	}
#endif

	int exc_class = FPTUN_EXC_SP_FUNC;

#ifdef CONFIG_MCORE_SOCKET
	{
		int res;
		/* TCP and UDP sockets handling (imply ICMP too) */
		switch (ip->ip_p) {
		case FP_IPPROTO_UDP:
			res = udp_input(m);
			exc_class = FPTUN_EXC_SOCKET; /* for stats */
			break;
		case FP_IPPROTO_TCP:
#ifdef DUMP_TCPIP
			dump_tcpip(m, "in");
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

	fp_ip_proto_handler_t *hdlr;

	FPN_SLIST_FOREACH (hdlr, &fp_ip_proto_handlers[ip->ip_p], next) {
		int res = hdlr->func(m);
		if (res != FP_CONTINUE)
			return res;
	}

	/* unhandled protocol */
	TRACE_IP(FP_LOG_NOTICE, "Unhandled IP protocol (type=%x)", ip->ip_p);

	return fp_ip_prepare_exception(m, exc_class);
}

#ifdef CONFIG_MCORE_IP_REASS
static inline int fp_ip_reass_local(struct mbuf *m)
{
	int res = fp_ip_reass(&m);

	if (res == FP_CONTINUE)
		res = fp_ip_input_demux(m);

	/*
	 * Packet was modified (previous mbuf doesn't exist anymore)
	 * we MUST do the fp_process_input_finish() ourselves, as the
	 * the initial caller doesn't know anything about the new mbuf
	 */
	fp_process_input_finish(m, res);
	return FP_DONE;
}
#endif /* CONFIG_MCORE_IP_REASS */

static inline int fp_ip_input_local(struct mbuf *m, uint8_t rt_type)
{
	/* packet for us */
	if (rt_type == RT_TYPE_ADDRESS) {
		struct fp_ip *ip = mtod(m, struct fp_ip *);

		FP_IP_STATS_INC(fp_shared->ip_stats, IpInDelivers);

		if (unlikely(ip->ip_off & htons(FP_IP_OFFMASK|FP_IP_MF)))
#ifdef CONFIG_MCORE_IP_REASS
			return fp_ip_reass_local(m);
#else
			return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
#endif /* CONFIG_MCORE_IP_REASS */
		return fp_ip_input_demux(m);
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

#ifdef CONFIG_MCORE_RPF_IPV4
int fp_ip_rpf_check(struct mbuf *m)
{

	struct fp_ip *ip = mtod(m, struct fp_ip *);
	uint16_t vrfid = m2vrfid(m);
	uint32_t ifuid = m_priv(m)->ifuid;
	fp_rt4_entry_t *rt;
	fp_nh4_entry_t *nh;

	rt = fp_rt4_lookup(vrfid, ip->ip_src.s_addr);

	if (unlikely(!rt))
		return 1;

	/* check ECMP4 route */
	if (unlikely(rt->rt.rt_nb_nh > 1)) {
		uint32_t i;
		for (i = 0; i < rt->rt.rt_nb_nh; i++) {
			nh = &fp_shared->fp_nh4_table[rt->rt.rt_next_hop[i]];
			if (nh->nh.nh_ifuid == ifuid) {
				TRACE_IP(FP_LOG_DEBUG,"RPF matched in ECMP4");
				return 0;
			}
		}
	}
	else {
		nh = &fp_shared->fp_nh4_table[rt->rt.rt_next_hop[0]];
		if (likely(nh->nh.nh_ifuid == ifuid))
			return 0;
	}

	return 1;
}
#endif /* CONFIG_MCORE_RPF_IPV4 */

static inline int fp_fast_ip_input(struct mbuf *m, const int fast_forward) __attribute__((always_inline));
static inline int fp_fast_ip_input(struct mbuf *m, const int fast_forward)
{
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	fp_rt4_entry_t *rt;
	fp_nh4_entry_t *nh;
	uint32_t dst;
	uint8_t rt_type;

#if (defined CONFIG_MCORE_TCP_MSS) || (defined CONFIG_MCORE_NETFILTER)
	fp_ifnet_t *ifp = __fp_ifuid2ifnet(m_priv(m)->ifuid);
#endif

#ifdef CONFIG_MCORE_TCP_MSS
	if (ifp->if_tcp4mss)
		fp_update_tcpmss_by_dev(m, ifp, AF_INET);
#endif

#ifdef CONFIG_MCORE_NETFILTER
	if (fast_forward == 0) {
		if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_NETFILTER)) {
			int res;

			/* fp_nfct_established must be set before fp_nf_hook() */
			fp_nfct_reset(m);
			res = fp_nf_hook(m, FP_NF_IP_PRE_ROUTING, ifp, NULL);
			if (unlikely(res != FP_CONTINUE))
				return res;
		}
	}
#endif

#ifdef CONFIG_MCORE_RPF_IPV4
	if (unlikely(m2ifnet(m)->if_flags & (IFF_CP_IPV4_RPF|IFF_FP_IPV4_RPF)) &&
	    fp_ip_rpf_check(m)) {
		FP_IP_STATS_INC(fp_shared->ip_stats, IpInAddrErrors);
		TRACE_IP(FP_LOG_DEBUG,"packet is dropped by RPF");
		return FP_DROP;
	}
#endif

	dst = ip->ip_dst.s_addr;

	/* multicast and reserved IP destination are exceptions. */
	if (unlikely(in_canforward(dst) == 0)) {
		TRACE_IP(FP_LOG_INFO, "Packet with reserved address");
		return fp_ip_prepare_exception(m, FPTUN_EXC_IP_DST);
	}

#ifdef CONFIG_MCORE_MULTICAST4
	/* multicast forward process */
	if (unlikely(FP_IN_MULTICAST(dst)))
		return fp_mcast_input(m);
#endif /* CONFIG_MCORE_MULTICAST4 */

	/* lookup in the FW table */
	rt = fp_rt4_lookup(m2vrfid(m), dst);

	if (unlikely(!rt)) {
		/* send ICMP error HOST Unreachable */
		TRACE_IP(FP_LOG_INFO, "Route not found");
		return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
	}
	nh = select_nh4(rt, &ip->ip_src.s_addr);
	rt_type = nh->nh.rt_type;

#ifdef CONFIG_MCORE_NEXTHOP_MARKING
	if (nh->nh.nh_mark)
		fp_nf_update_mark(m, nh->nh.nh_mark, (nh->nh.nh_mark | nh->nh.nh_mask));
#endif
	/* if routing exception, deliver to control plane */
	if (likely((rt_type & RT_TYPE_EXCEPTION_MASK) == 0))
		return __fp_fast_ip_output(m, rt, nh, fast_forward);
	else
		return fp_ip_input_local(m, rt_type);
}

#ifdef CONFIG_MCORE_IP_REASS
static inline int fp_ip_fwd_reass(struct mbuf *m)
{
	int res = fp_ip_reass(&m);

	if (res == FP_CONTINUE) {
		m_priv(m)->flags |= M_F_REASS;
		res = fp_fast_ip_input(m, 0);
	}

	/*
	 * Packet was modified (previous mbuf doesn't exist anymore)
	 * we MUST do the fp_process_input_finish() ourselves, as the
	 * the initial caller doesn't know anything about the new mbuf
	 */
	fp_process_input_finish(m, res);
	return FP_DONE;
}
#endif /* CONFIG_MCORE_IP_REASS */

int fp_ip_input(struct mbuf *m)
{
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	int res;

	M_TRACK(m, "IP_INPUT");

	res = mbuf_check_ipv4(m);

	if (unlikely(res >= 1)) {
		if (res == 1) {
			TRACE_IP(FP_LOG_INFO, "IP exception");
			return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
		}
		TRACE_IP(FP_LOG_INFO, "IP error");
		FP_IP_STATS_INC(fp_shared->ip_stats, IpInHdrErrors);
		return FP_DROP;
	}

	/* trim too long packets */
	if (unlikely(ntohs(ip->ip_len) < m_len(m)))
		m_trim(m, m_len(m) - ntohs(ip->ip_len));

	if (!(fp_shared->conf.w32.do_func & (FP_CONF_NO_FAST_FORWARD)))
		return fp_fast_ip_input(m, 1);

#ifdef CONFIG_MCORE_IP_REASS
	/*
	 * Reassemble fragments if:
	 * - netfilter is enabled (needed for conntrack)
	 * - or reassembly is forced on input interface
	 */
	if (unlikely(ip->ip_off & htons(FP_IP_OFFMASK|FP_IP_MF))) {
		if (unlikely((fp_shared->conf.w32.do_func & FP_CONF_DO_NETFILTER) ||
			     (fp_shared->conf.w32.do_func & FP_CONF_DO_FORCED_REASS &&
			      m2ifnet(m)->if_flags & IFF_FP_IPV4_FORCE_REASS)))
			return fp_ip_fwd_reass(m);
	}
#endif /* CONFIG_MCORE_IP_REASS */
	return fp_fast_ip_input(m, 0);
}
FPN_HOOK_REGISTER(fp_ip_input)

const char *fp_rt_type2str(uint8_t rt_type)
{
	const char *str;

	switch(rt_type) {
	case RT_TYPE_ROUTE:
		str = "ROUTE";
		break;
	case RT_TYPE_NEIGH:
		str = "NEIGH";
		break;
	case RT_TYPE_ADDRESS:
		str = "ADDRESS";
		break;
	case RT_TYPE_ROUTE_LOCAL:
		str = "LOCAL";
		break;
	case RT_TYPE_ROUTE_CONNECTED:
		str = "CONNECTED";
		break;
	case RT_TYPE_ROUTE_BLACKHOLE:
		str = "BLACKHOLE";
		break;
	default:
		str = "UNKNOWN";
		break;
	}

	return str;
}

static inline uint32_t preflen2mask(int i)
{
	uint32_t mask = 0;

	if (unlikely(i>32))
		mask = 0xffffffff;

	else if (i>0)
		mask = ((uint32_t)0xffffffff) << (32 - i);

	return htonl(mask);
}

/* This function allows to select a source address for a specified destination.
 * The source address is returned via the argument srcp.
 * If rt is provided, the result of fp_rt4_lookup() is returned to the caller
 * via this argument.
 */
int fp_rt4_selectsrc(uint32_t vrfid, uint32_t dst, uint32_t *srcp,
		     fp_rt4_entry_t **rt)
{
	fp_ifnet_t *ifp;  /* target interface */
	uint32_t src = 0;
	uint32_t src_default = 0;
	uint32_t prefix;
	int lastpass = 0;
	uint8_t rt_type;
	uint32_t idx;
	uint32_t ifuid = 0;
	int error = 0;

	fp_rt4_entry_t *rt4;
	fp_nh4_entry_t *nh4;

again:
	TRACE_IP(FP_LOG_DEBUG, "looking up for "FP_NIPQUAD_FMT
			" vrfid %" PRIu16,
			FP_NIPQUAD(dst), vrfid);

	rt4 = fp_rt4_lookup(vrfid, dst);
	if (rt)
	       *rt = rt4;

	if (rt4 == NULL) {
		TRACE_IP(FP_LOG_DEBUG, "no route found");
		goto end;
	}

	/* rt entry found, look at next hops */
	nh4 = &fp_shared->fp_nh4_table[rt4->rt.rt_next_hop[0]];
	ifuid = nh4->nh.nh_ifuid;

	ifp = __fp_ifuid2ifnet(ifuid);
	/* only one ip address, it should be this one */
	if (ifp->if_nb_addr4 == 1) {
		src = fp_pool_addr4_object(ifp->if_addr4_head_index).addr;
		TRACE_IP(FP_LOG_DEBUG, "\tsrc "FP_NIPQUAD_FMT" on %s via ifp",
			  FP_NIPQUAD(src), fp_ifuid2str(ifuid));
		goto end;
	}
	/* more that one ip address, we should try to find the exact one by
	 * looking in the route table.
	 * Anyway save the first ip address, in case we can't find this one
	 * in the route table */
	else if (ifp->if_nb_addr4 > 0) {
		src_default = fp_pool_addr4_object(ifp->if_addr4_head_index).addr;
		TRACE_IP(FP_LOG_DEBUG, "\tsrc_default "FP_NIPQUAD_FMT" on %s",
			  FP_NIPQUAD(src_default), fp_ifuid2str(ifuid));
	}

	rt_type = nh4->nh.rt_type;
	if (FP_LOG_COND(FP_LOG_DEBUG, FP_LOGTYPE_IP)) {
		prefix = dst & preflen2mask(rt4->rt.rt_length);
		TRACE_IP(FP_LOG_DEBUG, "found %s route to "FP_NIPQUAD_FMT"/%u",
				fp_rt_type2str(rt_type),
				FP_NIPQUAD(prefix), rt4->rt.rt_length);
	}

	/* basic route, lookup for a route to the gateway */
	if (rt_type == RT_TYPE_ROUTE) {
		dst = nh4->nh_gw;
		TRACE_IP(FP_LOG_DEBUG, "\tgateway "FP_NIPQUAD_FMT,
				FP_NIPQUAD(dst));
		if (lastpass)
			goto end;
		lastpass=1;
		goto again;
	}

	/* destination is one of my addresses. return it */
	if (rt_type == RT_TYPE_ADDRESS) {
		src = dst;
		goto end;
	}

	/* connected route. return preferred source, stored in gw */
	if (rt_type == RT_TYPE_ROUTE_CONNECTED) {
		src = nh4->nh_src;
		TRACE_IP(FP_LOG_DEBUG, "\tsrc "FP_NIPQUAD_FMT" on %s via lookup",
				FP_NIPQUAD(src), fp_ifuid2str(ifuid));
		goto end;
	}

	/* neighbour entry. Look for the connected route it depends from */
	if (rt_type == RT_TYPE_NEIGH) {
		TRACE_IP(FP_LOG_DEBUG, "\tgateway "FP_NIPQUAD_FMT,
				FP_NIPQUAD(nh4->nh_gw));

		if (nh4->nh_gw != dst) {
			dst = nh4->nh_gw;
			if (lastpass)
				goto end;
			lastpass=1;
			goto again;
		}

		idx = rt4->rt.rt_next;

		if (idx == 0) {
			TRACE_IP(FP_LOG_DEBUG, "no connected route for neighbor");
			goto end;
		}

		rt4 = &fp_shared->fp_rt4_table[idx];
		nh4 = &fp_shared->fp_nh4_table[rt4->rt.rt_next_hop[0]];

		rt_type = nh4->nh.rt_type;
		if (FP_LOG_COND(FP_LOG_DEBUG, FP_LOGTYPE_PCB)) {
			prefix = dst & preflen2mask(rt4->rt.rt_length);
			TRACE_IP(FP_LOG_DEBUG, "found %s route to "FP_NIPQUAD_FMT"/%u",
					fp_rt_type2str(rt_type),
					FP_NIPQUAD(prefix), rt4->rt.rt_length);
		}

		/* found. return preferred source, stored in gw */
		if (rt_type == RT_TYPE_ROUTE_CONNECTED) {
			src = nh4->nh_src;
			ifuid = nh4->nh.nh_ifuid;
			TRACE_IP(FP_LOG_DEBUG, "\tsrc "FP_NIPQUAD_FMT" on %s",
					FP_NIPQUAD(src), fp_ifuid2str(ifuid));
			/* Tell the compiler that this variable can be never read */
			(void)ifuid;
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
	if (likely(src != 0))
		goto found;
	/* if source default address is defined, uses this one as source */
	else if (src_default != 0) {
		src = src_default;
		goto found;
	}
	error = EADDRNOTAVAIL;
	return error;

found:
	TRACE_IP(FP_LOG_DEBUG, "=> returning "FP_NIPQUAD_FMT, FP_NIPQUAD(src));
	*srcp = src;
	return error;
}
