/*
 * Copyright(c) 2010 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"

#include "fp-log.h"
#include "fp-main-process.h"

#include "fp-fptun.h"
#include "fp-ether.h"
#ifdef CONFIG_MCORE_IP
#include "fp-ip.h"
#endif
#ifdef CONFIG_MCORE_IPV6
#include "fp-ip6.h"
#endif
#ifdef CONFIG_MCORE_ARP_REPLY
#include "fp-arp.h"
#endif

#define TRACE_MAIN_PROC(level, fmt, args...) do {		\
	FP_LOG(level, MAIN_PROC, fmt "\n", ## args);		\
} while(0)

/* Reserved Ethernet Addresses per IEEE 802.1Q */
const uint8_t fp_ether_reserved_addr_base[FP_ETHER_ADDR_LEN] __attribute__ ((aligned(2))) =
	{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

/*
 * fp_ether_output(): prepend ethernet header and send it.
 * return FP_DROP or FP_DONE.
 */
int fp_ether_output(struct mbuf *m, const struct fp_ether_header *eh, fp_ifnet_t *ifp)
{
	struct fp_ether_header *eth;

	/* XXX check ifp state UP ? */

	TRACE_MAIN_PROC(FP_LOG_DEBUG, "%s(ifp=%s)", __FUNCTION__, ifp->if_name);
	eth = (struct fp_ether_header *)m_prepend(m, FP_ETHER_HDR_LEN);
	if (unlikely(eth == NULL)) {
		TRACE_MAIN_PROC(FP_LOG_WARNING, "%s: could not prepend ethernet header", 
				__FUNCTION__);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
		return FP_DROP;
	}

	/* copy ethernet header */
	fpn_ethcpy(eth, eh);
	return FPN_HOOK_CALL(fp_if_output)(m, ifp);
}
FPN_HOOK_REGISTER(fp_ether_output)

int fp_ether_input(struct mbuf *m, fp_ifnet_t *ifp)
{
	rx_dev_ops_t *rx_dev;
	void *data;

#ifdef CONFIG_MCORE_TAP
	if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_TAP))
		fp_tap(m, ifp, 0);
#endif

	TRACE_MAIN_PROC(FP_LOG_INFO, "%s(ifp=%s)", __FUNCTION__, ifp->if_name);
	FP_LOG_MBUF(FP_LOG_DEBUG, FP_LOGTYPE_MAIN_PROC, m, 32);

	rx_dev = fp_ifnet_ops_get(ifp, RX_DEV_OPS, &data);
	if (unlikely(rx_dev != NULL)) {
		int ret = rx_dev(m, ifp, data);
		if (ret != FP_CONTINUE)
			return ret;
	}
	return fp_ether_input_novnb(m, ifp);
}
FPN_HOOK_REGISTER(fp_ether_input)

int fp_ether_input_novnb(struct mbuf *m, fp_ifnet_t *ifp)
{
	uint16_t ether_type;
	struct fp_ether_header* eh;

	/* TODO : checking interface state (up...) */

	TRACE_MAIN_PROC(FP_LOG_DEBUG, "%s(ifp=%s)", __FUNCTION__, ifp->if_name);

	eh = mtod(m, struct fp_ether_header *);

	/* Remember if packet is destined to other host. */
	if (unlikely((fp_ethaddr_compare(eh->ether_dhost, ifp->if_mac)))) {
		if (!(m_get_flags(m) & (M_F_MCAST|M_F_BCAST)))
			m_add_flags(m, M_F_OTHERHOST);
	}

	ether_type = ntohs(eh->ether_type);
	/* save mac address if needed for some architectures,
	 * m_adj() may override data. In this case we have to restore
	 * it in case of basic exceptions. */
	m_save_mac(m);

#ifdef CONFIG_MCORE_IP
	if (likely(ether_type == FP_ETHERTYPE_IP)) {
		/* Pass the packet up, with the ether header removed. */
		if (unlikely(m_adj(m, sizeof(struct fp_ether_header)) == NULL)) {
			TRACE_MAIN_PROC(FP_LOG_WARNING, "too short ethernet frame");
			FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);
			FP_IP_STATS_INC(fp_shared->ip_stats, IpInHdrErrors);
			return FP_DROP;
		}
		/* broadcast/multicast/other-host are exceptions */
		if (unlikely(m_get_flags(m) & (M_F_BCAST|M_F_OTHERHOST))) {
			TRACE_MAIN_PROC(FP_LOG_INFO, "Frame is%s%s",
					(m_get_flags(m) & M_F_BCAST)?" broadcast":"",
					(m_get_flags(m) & M_F_OTHERHOST)?" other host":"");
			return fp_ip_prepare_exception(m, FPTUN_EXC_ETHER_DST);
		}

		return FPN_HOOK_CALL(fp_ip_input)(m);
	}
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
	if (likely(ether_type == FP_ETHERTYPE_IPV6)) {
		TRACE_MAIN_PROC(FP_LOG_INFO, "Received IPv6 packet in ether_input");
		/* Pass the packet up, with the ether header removed. */
		if (unlikely(m_adj(m, sizeof(struct fp_ether_header)) == NULL)) {
			TRACE_MAIN_PROC(FP_LOG_WARNING, "too short ethernet frame");
			FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpInHdrErrors);
			return FP_DROP;
		}
		/* broadcast/multicast/other-host are exceptions */
		if (unlikely(m_get_flags(m) & (M_F_BCAST|M_F_OTHERHOST))) {
			TRACE_MAIN_PROC(FP_LOG_INFO, "Frame is%s%s",
					(m_priv(m)->flags & M_F_BCAST)?" broadcast":"",
					(m_priv(m)->flags & M_F_OTHERHOST)?" other host":"");
			return fp_ip_prepare_exception(m, FPTUN_EXC_ETHER_DST);
		}
		return FPN_HOOK_CALL(fp_ip6_input)(m);
	}
#endif /* CONFIG_MCORE_IPV6 */

#ifdef CONFIG_MCORE_ARP_REPLY
	if (unlikely((ether_type == FP_ETHERTYPE_ARP) &&
		     (fp_shared->conf.w32.do_func & FP_CONF_DO_ARP_REPLY))) {
		return fp_arp_input(m, ifp);
	}
#endif

	if (unlikely(ether_type == ETH_P_FPTUN)) {
		TRACE_MAIN_PROC(FP_LOG_DEBUG,
				"FPTUN message received on %s",
				ifp->if_name);
#ifdef CONFIG_MCORE_MULTIBLADE
		/* FPTUN message are received from FPIB interface. */
		if (ifp->if_ifuid == fp_shared->fpib_ifuid)
			return fp_fptun_input(m);
#endif
		TRACE_MAIN_PROC(FP_LOG_WARNING,
				"FPTUN message received "
				"from unexpected interface %s",
				ifp->if_name);
		FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);
		return FP_DROP;
	}

	TRACE_MAIN_PROC(FP_LOG_DEBUG, "Unknown ethertype 0x%04x", ether_type);
	return fp_prepare_exception(m, FPTUN_EXC_SP_FUNC);
}
