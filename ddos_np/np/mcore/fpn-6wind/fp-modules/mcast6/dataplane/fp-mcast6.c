/*
 * Copyright(c) 2010 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"

#include "fp-log.h"
#include "fp-main-process.h"

#include "fp-ip6.h"
#include "fp-mcast6.h"

#ifdef CONFIG_MCORE_M_TAG
#define VIF6_TAG_NAME "vif6"
static FPN_DEFINE_SHARED(int32_t, vif6_tag_type);
#endif

#define TRACE_IP(level, fmt, args...) do {			\
	FP_LOG(level, IP, fmt "\n", ## args);			\
} while(0)

void fp_mcast6_init(void)
{
#ifdef CONFIG_MCORE_M_TAG
	vif6_tag_type = m_tag_type_register(VIF6_TAG_NAME);
	if (vif6_tag_type < 0) {
		TRACE_IP(FP_LOG_ERR, "Cannot register tag type for '" VIF6_TAG_NAME "'");
	}
#else
	TRACE_IP(FP_LOG_ERR, "m_tag support is required for multicast6");
#endif
}

/*
 This function checks if a multicast group address belongs
 to a white list declared in shared memory.

 dst: is the multicast group address to check
 ifuid: is the ifuid of the interface on which the packet was received

 return 1 if the multicast address belongs to white list, 0 otherwise
 */
static int is_mcast6grp_accepted(fp_in6_addr_t dst, uint32_t ifuid)
{
	int i = 0;

	/* Accept all packets with dst in link local (ff02::/16) if
	   flag FP_MCASTGRP_OPT_ACCEPT_LL is set */
	if ((fp_shared->fp_mcast6grp_opt & FP_MCASTGRP_OPT_ACCEPT_LL) &&
	    ((dst.fp_s6_addr[0]  &  0xffff0000) ==  0xff020000))
		return 1;

	/* lookup for the (dst,ifuid) into the white list by walking through
	   whole table, very unoptimized */
	while (i < fp_shared->fp_mcast6grp_num) {
		fp_mcast6grp_t* mcg = &fp_shared->fp_mcast6grp_table[i];
		fp_in6_addr_t* grp = &mcg->group;

		if (((FP_IN6_IS_ADDR_UNSPECIFIED(grp)) || (is_in6_addr_equal(mcg->group, dst))) &&
		    ((mcg->ifuid == FP_MCASTGRP_IFUID_ALL) ||
		     (mcg->ifuid == ifuid)))
			return 1;

		i++;
	}

	return 0;
}

int fp_mcast6_input(struct mbuf *m)
{
	int res;
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	fp_mfc6_entry_t *mrt = NULL;
	fp_rt6_entry_t rt6;
	fp_nh6_entry_t nh6;
	fp_in6_addr_t dst;
	fp_in6_addr_t src;
	uint16_t index;
	uint16_t psend = 0xFFFF;
	uint32_t ifuid;

	/* for IGMP packet, we need to send it to slow path */
	if (unlikely(ip6->ip6_nxt == FP_IPPROTO_IGMP)) {
		TRACE_IP(FP_LOG_INFO, "IGMP Packet with no reserved  multicast Ipv6 address");
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	dst = ip6->ip6_dst;
	src = ip6->ip6_src;

	/* Accept only multicast packets registered in shared mem */
	if ((fp_shared->fp_mcast6grp_opt & FP_MCASTGRP_OPT_ENABLE) &&
	    !is_mcast6grp_accepted(dst, m_priv(m)->ifuid)) {
		TRACE_IP(FP_LOG_INFO, "Multicast group filtered, drop packet");
		return FP_DROP;
	}

	mrt = fp_mfc6_lookup(src, dst);
	if (unlikely(!mrt)) {
		/* no cache: input exception */
		TRACE_IP(FP_LOG_INFO, "Multicast Ipv6 Route not found");
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	/* input interface check */
	if (unlikely(mrt->iif != m_priv(m)->ifuid)) {
		/* wrong input if: input exception */
		TRACE_IP(FP_LOG_INFO, "Multicast Ipv6 Wrong Input IF");
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	FPN_STATS_INC(&mrt->pkt);
	FPN_STATS_ADD(&mrt->bytes, m_len(m));

	memset(&rt6, 0, sizeof(rt6));

	/* create a dummy fp_nh6_entry_t with multicast mac address
	 * and right output nh_ifuid */
	m_priv(m)->exc_type = FPTUN_MULTICAST6_EXCEPT;
	nh6.nh.nh_l2_state = L2_STATE_REACHABLE;
	nh6.nh.nh_eth.ether_type = htons(FP_ETHERTYPE_IPV6);
	nh6.nh.nh_eth.ether_dhost[0] = 0x33;
	nh6.nh.nh_eth.ether_dhost[1] = 0x33;
	nh6.nh.nh_eth.ether_dhost[2] = dst.fp_s6_addr[12];
	nh6.nh.nh_eth.ether_dhost[3] = dst.fp_s6_addr[13];
	nh6.nh.nh_eth.ether_dhost[4] = dst.fp_s6_addr[14];
	nh6.nh.nh_eth.ether_dhost[5] = dst.fp_s6_addr[15];

	for (index = 0; index < FP_MAXVIFS && mrt->oifs[index]; index++) {
		struct mbuf *tm = NULL;

		FPN_TRACK();
		ifuid = mrt->oifs[index];

		/* the incoming interface is into the oifs */
		if (unlikely(ifuid == mrt->iif))
			continue;

		if (psend == 0xFFFF) {
			psend = index;
			continue;
		}

#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
		tm = m_clone(m);
		TRACE_IP(FP_LOG_INFO, "clone");
#else
		tm = m_dup(m);
#endif
		if (unlikely(tm == NULL)) {
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedForwarding);
			continue;
		}

#ifdef CONFIG_MCORE_M_TAG
		/* add the ifuid index in the packet as a mtag: it is
		 * useful in case of mcast6 exception */
		m_tag_add(tm, vif6_tag_type, ifuid);
#endif

		nh6.nh.nh_ifuid = ifuid;
		memcpy(nh6.nh.nh_eth.ether_shost,
		       __fp_ifuid2ifnet(nh6.nh.nh_ifuid)->if_mac,
		       FP_ETHER_ADDR_LEN);

		res = fp_ip6_output(tm, &rt6, &nh6);
		fp_process_input_finish(tm, res);
	}

	/* no oif interface, drop packet */
	if (psend == 0xFFFF)
		return FP_DROP;

	ifuid = mrt->oifs[psend];
	nh6.nh.nh_ifuid = ifuid;
	memcpy(nh6.nh.nh_eth.ether_shost,
	       __fp_ifuid2ifnet(nh6.nh.nh_ifuid)->if_mac,
	       FP_ETHER_ADDR_LEN);

#ifdef CONFIG_MCORE_M_TAG
	/* add the ifuid index in the packet as a mtag: it is useful in
	 * case of mcast6 exception */
	m_tag_add(m, vif6_tag_type, ifuid);
#endif

	return fp_ip6_output(m, &rt6, &nh6);
}
