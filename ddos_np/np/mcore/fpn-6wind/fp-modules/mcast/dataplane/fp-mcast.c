/*
 * Copyright(c) 2010 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"

#include "fp-log.h"
#include "fp-main-process.h"

#include "fp-ip.h"
#include "fp-mcast.h"

#ifdef CONFIG_MCORE_M_TAG
#define VIF4_TAG_NAME "vif4"
static FPN_DEFINE_SHARED(int32_t, vif4_tag_type);
#endif

#define TRACE_IP(level, fmt, args...) do {			\
	FP_LOG(level, IP, fmt "\n", ## args);			\
} while(0)

void fp_mcast_init(void)
{
#ifdef CONFIG_MCORE_M_TAG
	vif4_tag_type = m_tag_type_register(VIF4_TAG_NAME);
	if (vif4_tag_type < 0) {
		TRACE_IP(FP_LOG_ERR, "Cannot register tag type for '" VIF4_TAG_NAME "'");
	}
#else
	TRACE_IP(FP_LOG_ERR, "m_tag support is required for multicast");
#endif
}

/*
 This function checks if a multicast group address belongs
 to a white list declared in shared memory.

 dst: is the multicast group address to check
 ifuid: is the ifuid of the interface on which the packet was received

 return 1 if the multicast address belongs to white list, 0 otherwise
 */
static int is_mcastgrp_accepted(uint32_t dst, uint32_t ifuid)
{
	int i = 0;

	/* Accept all packets with dst in link local (224.0.0.0/24) if
	   flag FP_MCASTGRP_OPT_ACCEPT_LL is set */
	if ((fp_shared->fp_mcastgrp_opt & FP_MCASTGRP_OPT_ACCEPT_LL) &&
	    ((dst & 0xffffff00) == 0xe0000000))
		return 1;

	/* lookup for the (dst,ifuid) into the white list by walking through
	   whole table, very unoptimized */
	while (i < fp_shared->fp_mcastgrp_num) {
		fp_mcastgrp_t* mcg = &fp_shared->fp_mcastgrp_table[i];

		if (((mcg->group == 0) || (mcg->group == dst)) &&
		    ((mcg->ifuid == FP_MCASTGRP_IFUID_ALL) ||
		     (mcg->ifuid == ifuid)))
			return 1;

		i++;
	}

	return 0;
}

int fp_mcast_input(struct mbuf *m)
{
	int res;
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	fp_mfc_entry_t *mrt = NULL;
	fp_rt4_entry_t rt4;
	fp_nh4_entry_t nh4;
	uint32_t dst;
	uint32_t src;
	uint16_t index;
	uint16_t psend = 0xFFFF;
	uint32_t ifuid;

	/* for IGMP packet, we need to send it to slow path */
	if (unlikely(ip->ip_p == FP_IPPROTO_IGMP)) {
		TRACE_IP(FP_LOG_INFO, "IGMP Packet with no reserved multicast address");
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	dst = ip->ip_dst.s_addr;
	src = ip->ip_src.s_addr;

	/* Accept only multicast packets registered in shared mem */
	if ((fp_shared->fp_mcastgrp_opt & FP_MCASTGRP_OPT_ENABLE) &&
	    !is_mcastgrp_accepted(dst, m_priv(m)->ifuid)) {
		TRACE_IP(FP_LOG_INFO, "Multicast group filtered, drop packet");
		return FP_DROP;
	}

	mrt = fp_mfc_lookup(src, dst);
	if (unlikely(!mrt)) {
		/* no cache: input exception */
		TRACE_IP(FP_LOG_INFO, "Multicast Route not found");
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	/* input interface check */
	if (unlikely(mrt->iif != m_priv(m)->ifuid)) {
		/* wrong input if: input exception */
		TRACE_IP(FP_LOG_INFO, "Multicast Wrong Input IF");
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	FPN_STATS_INC(&mrt->pkt);
	FPN_STATS_ADD(&mrt->bytes, m_len(m));

	memset(&rt4, 0, sizeof(rt4));

	/* create a dummy fp_nh4_entry_t with multicast mac address 
	 * and right output nh_ifuid */
	m_priv(m)->exc_type = FPTUN_MULTICAST_EXCEPT;
	nh4.nh.nh_l2_state = L2_STATE_REACHABLE;
	nh4.nh.nh_eth.ether_type = htons(FP_ETHERTYPE_IP);
	nh4.nh.nh_eth.ether_dhost[0] = 0x01;
	nh4.nh.nh_eth.ether_dhost[1] = 0x00;
	nh4.nh.nh_eth.ether_dhost[2] = 0x5E;
	nh4.nh.nh_eth.ether_dhost[3] = ntohl(dst) >>16 & 0x7F;
	nh4.nh.nh_eth.ether_dhost[4] = ntohl(dst) >>8 & 0XFF;
	nh4.nh.nh_eth.ether_dhost[5] = ntohl(dst) & 0XFF;

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
#else
		tm = m_dup(m);
#endif
		if (unlikely(tm == NULL)) {
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedForwarding);
			continue;
		}
#ifdef CONFIG_MCORE_M_TAG
		/* add the ifuid index in the packet as a mtag: it is
		 * useful in case of mcast exception */
		m_tag_add(tm, vif4_tag_type, ifuid);
#endif

		nh4.nh.nh_ifuid = ifuid;
		/* set the source MAC address to our address */
		memcpy(nh4.nh.nh_eth.ether_shost,
		       __fp_ifuid2ifnet(nh4.nh.nh_ifuid)->if_mac,
		       FP_ETHER_ADDR_LEN);

		res = fp_ip_output(tm, &rt4, &nh4);
		fp_process_input_finish(tm, res);
	}

	/* no oif interface, drop packet */
	if (psend == 0xFFFF)
		return FP_DROP;

	ifuid = mrt->oifs[psend];
	nh4.nh.nh_ifuid = ifuid;
	/* set the source MAC address to our address */
	memcpy(nh4.nh.nh_eth.ether_shost,
	       __fp_ifuid2ifnet(nh4.nh.nh_ifuid)->if_mac,
	       FP_ETHER_ADDR_LEN);

#ifdef CONFIG_MCORE_M_TAG
	/* add the ifuid index in the packet as a mtag: it is useful in
	 * case of mcast exception */
	m_tag_add(m, vif4_tag_type, ifuid);
#endif

	return fp_ip_output(m, &rt4, &nh4);
}
