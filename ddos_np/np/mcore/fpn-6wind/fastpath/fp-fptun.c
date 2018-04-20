/*
 * Copyright(c) 2010 6WIND
 */
#include "fp-includes.h"

#include "fp-log.h"
#include "fp-main-process.h"

#ifdef CONFIG_MCORE_IPSEC
#include "fp-ipsec-common.h"
#include "fp-ipsec-output.h"
#include "fp-ipsec-replay.h"
#include "fp-ipsec-lookup.h"
#endif

#ifdef CONFIG_MCORE_IPSEC_IPV6
#include "fp-ipsec6-output.h"
#include "fp-ipsec6-lookup.h"
#endif

#ifdef CONFIG_MCORE_TRAFFIC_GEN
#include "fp-traffic-gen.h"
#endif

#include "fp-fptun.h"
#ifdef CONFIG_MCORE_IP
#include "fp-ip.h"
#include "fp-neigh.h"
#endif
#ifdef CONFIG_MCORE_IPV6
#include "fp-ip6.h"
#endif

#ifdef CONFIG_MCORE_NETFILTER
#include "fp-nfct.h"
#endif

#define TRACE_MAIN_PROC(level, fmt, args...) do {		\
	FP_LOG(level, MAIN_PROC, fmt "\n", ## args);		\
} while(0)

/* Functions for hitflags */
#if defined(CONFIG_MCORE_HITFLAGS_SYNC) && defined(CONFIG_MCORE_MULTIBLADE)
static void hitflags_update_arp(uint32_t *addr, uint32_t ifuid)
{
	uint32_t i;

	/*
	 * fp_nh4_lookup uses the rt_type for selecting which fields need to
	 * be compared, but does not check the rt_type field itself. So in case
	 * of mismatch handle this as 'not found'.
	 */
	i = fp_nh4_lookup (*addr, ifuid, RT_TYPE_NEIGH, NULL);
	if (fp_shared->fp_nh4_table[i].nh.rt_type != RT_TYPE_NEIGH)
		i = 0;

	if (i) {
		/*
		 * Inactive FP may send us hit flag report for non STALE entries
		 */
		if (fp_shared->fp_nh4_table[i].nh.nh_l2_state == L2_STATE_STALE) {
			TRACE_MAIN_PROC(FP_LOG_DEBUG, "ARP: updating i=%d", i);
			fp_shared->fp_nh4_table[i].nh.nh_hitflag = 1;
		} else {
			TRACE_MAIN_PROC(FP_LOG_DEBUG, "ARP: NOT updating i=%d", i);
		}
	} else
		TRACE_MAIN_PROC(FP_LOG_WARNING, "could not find entry for update");

	return;
}

#ifdef CONFIG_MCORE_IPV6
static void hitflags_update_ndp(uint8_t *addr, uint32_t ifuid)
{
	uint32_t i;

	/*
	 * fp_nh6_lookup uses the rt_type for selecting which fields need to
	 * be compared, but does not check the rt_type field itself. So in case
	 * of mismatch handle this as 'not found'.
	 */
	i = fp_nh6_lookup ((fp_in6_addr_t *)addr, ifuid, RT_TYPE_NEIGH, NULL);
	if (fp_shared->fp_nh6_table[i].nh.rt_type != RT_TYPE_NEIGH)
		i = 0;

	if (i) {
		/*
		 * Inactive FP may send us hit flag report for non STALE entries
		 */
		if (fp_shared->fp_nh6_table[i].nh.nh_l2_state == L2_STATE_STALE) {
			TRACE_MAIN_PROC(FP_LOG_DEBUG, "NDP: updating i=%d", i);
			fp_shared->fp_nh6_table[i].nh.nh_hitflag = 1;
		} else {
			TRACE_MAIN_PROC(FP_LOG_DEBUG, "NDP: NOT updating i=%d", i);
		}
	} else
		TRACE_MAIN_PROC(FP_LOG_WARNING, "could not find entry for update");

	return;
}
#endif /* CONFIG_MCORE_IPV6 */

#ifdef CONFIG_MCORE_NF_CT
static void hitflags_update_ct(struct fphitflagsentry *hf_entry)
{
	struct fp_nfct_entry *nfct = fp_nfct_lookup(hf_entry->proto,
			hf_entry->src, hf_entry->dst, hf_entry->sport,
			hf_entry->dport, hf_entry->vrfid, NULL);

	if (nfct)
		nfct->flag |= FP_NFCT_FLAG_UPDATE;
	else
		TRACE_MAIN_PROC(FP_LOG_WARNING, "could not find conntrack entry");
}
#endif /* CONFIG_MCORE_NF_CT */

#ifdef CONFIG_MCORE_NETFILTER_IPV6
static void hitflags_update_ct6(struct fphitflags6entry *hf6_entry)
{
	struct fp_nf6ct_entry *nfct6 = fp_nf6ct_lookup(hf6_entry->proto,
			(struct fp_in6_addr *)&hf6_entry->src,
			(struct fp_in6_addr *)&hf6_entry->dst,
			hf6_entry->sport, hf6_entry->dport, hf6_entry->vrfid, NULL);

	if (nfct6)
		nfct6->flag |= FP_NFCT_FLAG_UPDATE;
	else
		TRACE_MAIN_PROC(FP_LOG_WARNING, "could not find conntrack entry");
}
#endif /* CONFIG_MCORE_NETFILTER_IPV6 */

static void fp_hitflags_update(struct fphitflagshdr *hfhdr)
{
	uint32_t count = ntohl(hfhdr->count);

	TRACE_MAIN_PROC(FP_LOG_DEBUG, "(%p)", hfhdr);
	TRACE_MAIN_PROC(FP_LOG_INFO, "hfhdr content: type=%d, count=%d",
			hfhdr->type, count);

	switch (hfhdr->type) {
	case HF_ARP:
	{
		struct fphitflagsarp *hf_arp;

		hf_arp = (struct fphitflagsarp *)(hfhdr + 1);
		while (count) {
			hitflags_update_arp(&hf_arp->ip_addr, hf_arp->ifuid);
			count--;
			hf_arp++;
		}
		break;
	}
#ifdef CONFIG_MCORE_IPV6
	case HF_NDP:
	{
		struct fphitflagsndp *hf_ndp;

		hf_ndp = (struct fphitflagsndp *)(hfhdr + 1);
		while (count) {
			hitflags_update_ndp(hf_ndp->ip6_addr, hf_ndp->ifuid);
			count--;
			hf_ndp++;
		}
		break;
	}
#endif
#ifdef CONFIG_MCORE_NETFILTER
	case HF_CT:
	{
		struct fphitflagsentry *hf_entry;

		hf_entry = (struct fphitflagsentry *)(hfhdr + 1);
		while (count) {
			hitflags_update_ct(hf_entry);
			count--;
			hf_entry++;
		}
		break;
	}
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	case HF_CT6:
	{
		struct fphitflags6entry *hf6_entry;

		hf6_entry = (struct fphitflags6entry *)(hfhdr + 1);
		while (count) {
			hitflags_update_ct6(hf6_entry);
			count--;
			hf6_entry++;
		}
		break;
	}
#endif
	default:
		break;

	}

	return;
}
#endif

int fp_is_fptun_msg(struct mbuf *m)
{
	uint16_t ether_type;
	struct fp_ether_header* eh;

	eh = mtod(m, struct fp_ether_header *);
	ether_type = ntohs(eh->ether_type);

	return (ether_type == ETH_P_FPTUN);
}

/* input packet data starts with fpmtaghdr (fptun hdr is already removed) */
static void fp_fptun_parse_mtags(struct mbuf *m, uint8_t mtags)
{
#ifdef CONFIG_MCORE_M_TAG
	const struct fpmtaghdr *mtag;

	TRACE_MAIN_PROC(FP_LOG_DEBUG, "Packet has %d mtags:", mtags);
	mtag = mtod(m, const struct fpmtaghdr *);
	while (mtags--) {
		int32_t type = m_tag_type_find_by_name(mtag->fpmtag_name);

		FPN_TRACK();
		if (type < 0) {
			type = m_tag_type_register(mtag->fpmtag_name);
			if (type < 0) {
				TRACE_MAIN_PROC(FP_LOG_WARNING, "FPTUN mtag dropped, cant register type %s",
					 mtag->fpmtag_name);
				mtag++;
				continue;
			}
		}
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "   %s(%d): 0x%8.8x", mtag->fpmtag_name, type,
				ntohl(mtag->fpmtag_data));
		m_tag_add(m, type, mtag->fpmtag_data);
		mtag++;
	}
#else
	TRACE_MAIN_PROC(FP_LOG_DEBUG, "Ignore %d mtags (CONFIG_MCORE_M_TAG disabled)", mtags);
#endif
}

int fp_fptun_input(struct mbuf *m)
{
	struct fptunhdr *fptunhdr;
	struct fp_ether_header *eth;
	fp_ifnet_t *ifp;
	uint8_t mtags;
	unsigned int len;

	/* ignore FPTUN messages for other hosts */
	if (unlikely(m_get_flags(m) & (M_F_OTHERHOST))) {
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "FPTUN other host"); 
		return FP_DROP; 
	} 

	len = m_len(m);

	/* sanity check */
	if (unlikely(len < sizeof(struct fptunhdr))) {
		TRACE_MAIN_PROC(FP_LOG_WARNING, "FPTUN message too short");
		FP_IP_STATS_INC(fp_shared->ip_stats, IpInHdrErrors);
		return FP_DROP;
	}

	eth = mtod(m, struct fp_ether_header *);
	fptunhdr = (struct fptunhdr*)(eth+1);

	if (unlikely(fptunhdr->fptun_version != FPTUN_VERSION)) {
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "FPTUN invalid version: %u instead of %u",
			fptunhdr->fptun_version, FPTUN_VERSION);
		return FP_DROP;
	}

	/* restore exc_class from fptun header */
	m_priv(m)->exc_class = fptunhdr->fptun_exc_class ;
	/* ensure exc_type is clean */
	m_priv(m)->exc_type = 0;

#ifdef CONFIG_MCORE_MULTIBLADE
	if (unlikely(fptunhdr->fptun_blade_id != fp_shared->fp_blade_id)) {
		/* if message from our CP, forward to remote FP, otherwise drop */
		/* No exception in this case (packet is sent or dropped). */
		FP_EXCEP_STATS_INC(fp_shared->exception_stats,
				RemoteExceptionClass[fptunhdr->fptun_exc_class & FPTUN_EXC_CLASS_MASK]);
		FP_EXCEP_STATS_INC(fp_shared->exception_stats,
				RemoteExceptionType[fptunhdr->fptun_cmd]);

		if (likely(fptunhdr->fptun_cmd == FPTUN_ETH_SP_OUTPUT_REQ)) {
			int ret;
			TRACE_MAIN_PROC(FP_LOG_INFO, "Forwarding FPTUN ether output message to blade %u",
					fptunhdr->fptun_blade_id);
			fptunhdr->fptun_cmd = FPTUN_ETH_FP_OUTPUT_REQ;
			ret = fp_fpib_forward(m, fptunhdr->fptun_blade_id);
			FP_MULTIBLADE_STATS_INC(fp_shared->multiblade_stats,
					SentRemotePortOutputRequests);
			return ret;

		}
		else if (likely(
				 (fptunhdr->fptun_cmd == FPTUN_IPV4_IPSEC_SP_OUTPUT_REQ) ||
				 (fptunhdr->fptun_cmd == FPTUN_IPV6_IPSEC_SP_OUTPUT_REQ))) {
			int ret;
			TRACE_MAIN_PROC(FP_LOG_INFO, "Forwarding FPTUN IPsec output message to blade %u",
					fptunhdr->fptun_blade_id);
			ret = fp_fpib_forward(m, fptunhdr->fptun_blade_id);
			return ret;
#ifdef CONFIG_MCORE_1CP_XFP
		} else if (fptunhdr->fptun_cmd == FPTUN_RFPS_UPDATE) {
			/* forward the RFPS packet which comes from other FP to CP */
			TRACE_MAIN_PROC(FP_LOG_DEBUG, "Forwarding RFPS message to CP");
			memcpy(eth->ether_dhost, fp_shared->cp_if_mac, FP_ETHER_ADDR_LEN);
			memcpy(eth->ether_shost, fp_shared->fp_if_mac, FP_ETHER_ADDR_LEN);
			return FP_NONE;
#endif
		}
		else {
			/* drop message */
			TRACE_MAIN_PROC(FP_LOG_INFO, "Dropping FPTUN message for blade %u (mine %u)",
					fptunhdr->fptun_blade_id, fp_shared->fp_blade_id);
			FP_MULTIBLADE_STATS_INC(fp_shared->multiblade_stats, RcvdLocalConfigErrors);
			return FP_DROP;
		}
	}
#endif

	/* only increase exception type, class is not set by rfpvi module */
	FP_EXCEP_STATS_INC(fp_shared->exception_stats, LocalExceptionType[fptunhdr->fptun_cmd]);

#ifdef CONFIG_MCORE_TRAFFIC_GEN
	if (likely((fptunhdr->fptun_cmd == FPTUN_TRAFFIC_GEN_MSG))) {
		return fp_traffic_gen_soft_input(m);
	}
#endif

	if (likely((fptunhdr->fptun_cmd == FPTUN_ETH_FP_OUTPUT_REQ)
		   || (fptunhdr->fptun_cmd == FPTUN_ETH_SP_OUTPUT_REQ)
		   || (fptunhdr->fptun_cmd == FPTUN_IPV4_SP_OUTPUT_REQ)
		   || (fptunhdr->fptun_cmd == FPTUN_IPV4_FP_OUTPUT_REQ)
#ifdef CONFIG_MCORE_IPV6
		   || (fptunhdr->fptun_cmd == FPTUN_IPV6_SP_OUTPUT_REQ)
		   || (fptunhdr->fptun_cmd == FPTUN_IPV6_FP_OUTPUT_REQ)
#endif
		   )) {

		TRACE_MAIN_PROC(FP_LOG_DEBUG, "FPTUN output request");

#ifdef CONFIG_MCORE_MULTIBLADE
		if ((fptunhdr->fptun_cmd == FPTUN_ETH_FP_OUTPUT_REQ)
		    || (fptunhdr->fptun_cmd == FPTUN_IPV4_FP_OUTPUT_REQ)
#ifdef CONFIG_MCORE_IPV6
		    || (fptunhdr->fptun_cmd == FPTUN_IPV6_FP_OUTPUT_REQ)
#endif
		    ) {
			FP_MULTIBLADE_STATS_INC(fp_shared->multiblade_stats,
				RcvdRemotePortOutputRequests);
		}
#endif

		/* We need ifp to get the output port used to forward */
		ifp = fp_ifuid2ifnet(fptunhdr->fptun_ifuid);
		if (unlikely(ifp == NULL)) {
			TRACE_MAIN_PROC(FP_LOG_NOTICE, "FPTUN unknown ifuid %08x",
					ntohl(fptunhdr->fptun_ifuid));
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedInvalidInterface);
			return FP_DROP;
		}

		set_mvrfid(m, ntohs(fptunhdr->fptun_vrfid));
		m_priv(m)->ifuid = ifp->if_ifuid;

		mtags = fptunhdr->fptun_mtags;
		m_adj(m, sizeof(struct fptunhdr) + sizeof(struct fp_ether_header));
		if (mtags) {
			fp_fptun_parse_mtags(m, mtags);
			m_adj(m, mtags * sizeof(struct fpmtaghdr));
		}
#ifdef CONFIG_MCORE_TAP
		if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_TAP))
			fp_tap(m, ifp, 0);
#endif

#ifdef CONFIG_MCORE_IP
		/* IPv4 / IPv6 output request */
		if ((fptunhdr->fptun_cmd == FPTUN_IPV4_SP_OUTPUT_REQ)
		    || (fptunhdr->fptun_cmd == FPTUN_IPV4_FP_OUTPUT_REQ))
			return FPN_HOOK_CALL(fp_ip_inetif_send)(m, ifp);
#endif
#ifdef CONFIG_MCORE_IPV6
		if ((fptunhdr->fptun_cmd == FPTUN_IPV6_SP_OUTPUT_REQ)
		    || (fptunhdr->fptun_cmd == FPTUN_IPV6_FP_OUTPUT_REQ))
			return FPN_HOOK_CALL(fp_ip6_inet6if_send)(m, ifp);
#endif

		/* ethernet output request */

		/* Here, do not call fp_direct_if_output() because we
		 * don't want to send an exception to CP for output to
		 * avoid infinite loop if output is delegated to FP. */

		/* VNB defines virtual interface attached to eiface node */
		if (unlikely(ifp->if_port == FP_IFNET_VIRTUAL_PORT)) {
			tx_dev_ops_t *tx_dev;
			void *data;

			tx_dev = fp_ifnet_ops_get(ifp, TX_DEV_OPS, &data);
			if (likely(tx_dev != NULL)) {
				int ret = tx_dev(m, ifp, data);
				if (ret != FP_CONTINUE)
					return ret;
			}
			TRACE_MAIN_PROC(FP_LOG_NOTICE, "No output function for %s", ifp->if_name);
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedInvalidInterface);
			return FP_DROP;
		}

		if (unlikely(!fp_ifnet_is_operative(ifp))) {
			FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
			return FP_DROP;
		}

#if 0
		FP_IF_STATS_INC(ifp->if_stats, ifs_opackets);
		FP_IF_STATS_ADD(ifp->if_stats, ifs_obytes, len);
#endif
		if (unlikely(fpn_send_packet(m, ifp->if_port))) {
#if 0
			FP_IF_STATS_DEC(ifp->if_stats, ifs_opackets);
			FP_IF_STATS_SUB(ifp->if_stats, ifs_obytes, len);
#endif
			FP_IF_STATS_INC(ifp->if_stats, ifs_oerrors);
		}
		return FP_DONE;
	}
#ifdef CONFIG_MCORE_IPSEC
	else if (likely((fptunhdr->fptun_cmd == FPTUN_IPV4_IPSEC_FP_OUTPUT_REQ)
			|| (fptunhdr->fptun_cmd == FPTUN_IPV4_IPSEC_SP_OUTPUT_REQ)
#ifdef CONFIG_MCORE_IPV6
			|| (fptunhdr->fptun_cmd == FPTUN_IPV6_IPSEC_FP_OUTPUT_REQ)
			|| (fptunhdr->fptun_cmd == FPTUN_IPV6_IPSEC_SP_OUTPUT_REQ)
#endif
		)) {
		uint8_t mtags;
		int ret = 0;
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "FPTUN IPsec output request");

		/* We need ifp to set interface m_priv(m)->ifuid used
		 * by exception handling */
		ifp = fp_ifuid2ifnet(fptunhdr->fptun_ifuid);
		if (unlikely(ifp == NULL)) {
			TRACE_MAIN_PROC(FP_LOG_NOTICE, "FPTUN unknown ifuid %08x",
					ntohl(fptunhdr->fptun_ifuid));
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedInvalidInterface);
			return FP_DROP;
		}
		m_priv(m)->ifuid = ifp->if_ifuid;
		set_mvrfid(m, ntohs(fptunhdr->fptun_vrfid));

		mtags = fptunhdr->fptun_mtags;
		m_adj(m, sizeof(struct fptunhdr) + sizeof(struct fp_ether_header));
		if (mtags) {
			fp_fptun_parse_mtags(m, mtags);
			m_adj(m, mtags * sizeof(struct fpmtaghdr));
		}

#ifdef CONFIG_MCORE_MULTIBLADE
		FP_MULTIBLADE_STATS_INC(fp_shared->multiblade_stats,
				RcvdRemoteIPsecOutputRequests);
#endif
#ifdef CONFIG_MCORE_IPV6
		if (likely((fptunhdr->fptun_cmd == FPTUN_IPV4_IPSEC_FP_OUTPUT_REQ)
			   || (fptunhdr->fptun_cmd == FPTUN_IPV4_IPSEC_SP_OUTPUT_REQ))) {
#endif
#ifdef CONFIG_MCORE_IPSEC_SVTI
			if (ifp->if_type == FP_IFTYPE_SVTI)
				ret = fp_svti_output(m, ifp);
			else
#endif
				ret = fp_ipsec_output(m);
#ifdef CONFIG_MCORE_IPV6
		}
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
		else
#ifdef CONFIG_MCORE_IPSEC_SVTI
			if (ifp->if_type == FP_IFTYPE_SVTI)
				ret = fp_svti6_output(m, ifp);
			else
#endif

			ret = fp_ipsec6_output(m);
#endif

		return ret;
	}
#endif

#ifdef CONFIG_MCORE_MULTIBLADE
#ifdef CONFIG_MCORE_IPSEC
	else if (likely(fptunhdr->fptun_cmd == FPTUN_IPV4_REPLAYWIN))
	{
		struct fp_replaywin_msg *replay;
		uint32_t sa_index;
		fp_sad_t *sad = fp_get_sad();
		uint8_t mtags = fptunhdr->fptun_mtags;

		TRACE_MAIN_PROC(FP_LOG_DEBUG, "FPTUN IPv4 IPsec replay window message");
		m_adj(m, sizeof(struct fptunhdr) + sizeof(struct fp_ether_header));
		if (mtags) {
			fp_fptun_parse_mtags(m, mtags);
			m_adj(m, mtags * sizeof(struct fpmtaghdr));
		}

		replay = mtod(m, struct fp_replaywin_msg *);
		sa_index = __fp_sa_get(sad, replay->spi, replay->dst, replay->proto, ntohl(replay->vrfid));
		if (sa_index == 0) {
			TRACE_MAIN_PROC(FP_LOG_NOTICE, "FPTUN unknown IPv4 SA spi %08x",
					ntohl(replay->spi));
/*
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
*/
			return FP_DROP;
		}

		ipsec_mergereplay(replay, sa_index);
		m_freem(m);
		return FP_DONE;
	}
	else if (fptunhdr->fptun_cmd == FPTUN_IPV4_REPLAYWIN_GET)
	{
		uint8_t mtags = fptunhdr->fptun_mtags;
		uint8_t src_blade_id;
		fp_replaywin_sync_header_t *sync_hdr;
		uint16_t request_count;

		TRACE_MAIN_PROC(FP_LOG_DEBUG, "FPTUN IPsec replay window get message");
		m_adj(m, sizeof(struct fptunhdr) + sizeof(struct fp_ether_header));

		if (mtags) {
			fp_fptun_parse_mtags(m, mtags);
			m_adj(m, mtags * sizeof(struct fpmtaghdr));
		}

		sync_hdr = mtod(m, fp_replaywin_sync_header_t *);
		if (unlikely(sync_hdr->version != 1)){
			TRACE_MAIN_PROC(FP_LOG_DEBUG, "Unsupported replay window get message version");
			m_freem(m);
			return FP_DROP;
		}
		src_blade_id = sync_hdr->src_blade_id;
		request_count = sync_hdr->request_count;
		m_adj(m, sizeof(fp_replaywin_sync_header_t));

		/* send replaywin reply msg back */
		ipsec_replaywin_reply_send(m, src_blade_id, request_count);
		m_freem(m);
		return FP_DONE;
	}
	else if (fptunhdr->fptun_cmd == FPTUN_IPV4_REPLAYWIN_REPLY)
	{
		uint8_t mtags = fptunhdr->fptun_mtags;
		fp_replaywin_sync_header_t *sync_hdr;
		uint16_t request_count;


		TRACE_MAIN_PROC(FP_LOG_DEBUG, "FPTUN IPsec replay window reply message");
		m_adj(m, sizeof(struct fptunhdr) + sizeof(struct fp_ether_header));
		if (mtags) {
			fp_fptun_parse_mtags(m, mtags);
			m_adj(m, mtags * sizeof(struct fpmtaghdr));
		}

		sync_hdr = mtod(m, fp_replaywin_sync_header_t *);
		if (unlikely(sync_hdr->version != 1)){
			TRACE_MAIN_PROC(FP_LOG_DEBUG, "Unsupported replay window reply message version");
			m_freem(m);
			return FP_DROP;
		}
		request_count = sync_hdr->request_count;
		m_adj(m, sizeof(fp_replaywin_sync_header_t));

		ipsec_replaywin_reply_recv(m, request_count);
		m_freem(m);
		return FP_DONE;
	}
#endif /* CONFIG_MCORE_IPSEC */
#ifdef CONFIG_MCORE_IPSEC_IPV6
	else if (likely(fptunhdr->fptun_cmd == FPTUN_IPV6_REPLAYWIN))
	{
		struct fp_replaywin6_msg *replay;
		uint32_t sa_index;
		fp_sad6_t *sad = fp_get_sad6();
		uint8_t mtags = fptunhdr->fptun_mtags;

		TRACE_MAIN_PROC(FP_LOG_DEBUG, "FPTUN IPv6 IPsec replay window message");
		m_adj(m, sizeof(struct fptunhdr) + sizeof(struct fp_ether_header));
		if (mtags) {
			fp_fptun_parse_mtags(m, mtags);
			m_adj(m, mtags * sizeof(struct fpmtaghdr));
		}

		replay = mtod(m, struct fp_replaywin6_msg *);
		sa_index = __fp_v6_sa_get(sad, replay->spi, (uint8_t *)replay->dst.fp_s6_addr, replay->proto, ntohl(replay->vrfid));
		if (sa_index == 0) {
			TRACE_MAIN_PROC(FP_LOG_NOTICE, "FPTUN unknown IPv6 SA spi %08x",
					ntohl(replay->spi));
/*
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
*/
			return FP_DROP;
		}

		ipsec6_mergereplay(replay, sa_index);
		m_freem(m);
		return FP_DONE;
	}
	else if (fptunhdr->fptun_cmd == FPTUN_IPV6_REPLAYWIN_GET)
	{
		uint8_t mtags = fptunhdr->fptun_mtags;
		uint8_t src_blade_id;
		fp_replaywin_sync_header_t *sync_hdr;
		uint16_t request_count;

		TRACE_MAIN_PROC(FP_LOG_DEBUG, "FPTUN IPv6 IPsec replay window get message");
		m_adj(m, sizeof(struct fptunhdr) + sizeof(struct fp_ether_header));
		if (mtags) {
			fp_fptun_parse_mtags(m, mtags);
			m_adj(m, mtags * sizeof(struct fpmtaghdr));
		}

		sync_hdr = mtod(m, fp_replaywin_sync_header_t *);
		if (unlikely(sync_hdr->version != 1)){
			TRACE_MAIN_PROC(FP_LOG_DEBUG, "Unsupported IPv6 replay window get message version");
			m_freem(m);
			return FP_DROP;
		}
		src_blade_id = sync_hdr->src_blade_id;
		request_count = sync_hdr->request_count;
		m_adj(m, sizeof(fp_replaywin_sync_header_t));

		/* send replaywin reply msg back */
		ipsec6_replaywin_reply_send(m, src_blade_id, request_count);
		m_freem(m);
		return FP_DONE;
	}
	else if (fptunhdr->fptun_cmd == FPTUN_IPV6_REPLAYWIN_REPLY)
	{
		uint8_t mtags = fptunhdr->fptun_mtags;
		fp_replaywin_sync_header_t *sync_hdr;
		uint16_t request_count;

		TRACE_MAIN_PROC(FP_LOG_DEBUG, "FPTUN IPv6 IPsec replay window reply message");
		m_adj(m, sizeof(struct fptunhdr) + sizeof(struct fp_ether_header));
		if (mtags) {
			fp_fptun_parse_mtags(m, mtags);
			m_adj(m, mtags * sizeof(struct fpmtaghdr));
		}

		sync_hdr = mtod(m, fp_replaywin_sync_header_t *);
		if (unlikely(sync_hdr->version != 1)){
			TRACE_MAIN_PROC(FP_LOG_DEBUG, "Unsupported IPv6 replay window reply message version");
			m_freem(m);
			return FP_DROP;
		}

		request_count = sync_hdr->request_count;
		m_adj(m, sizeof(fp_replaywin_sync_header_t));

		ipsec6_replaywin_reply_recv(m, request_count);
		m_freem(m);
		return FP_DONE;
	}
#endif /* CONFIG_MCORE_IPSEC_IPV6 */
	else if (fptunhdr->fptun_cmd == FPTUN_HITFLAGS_SYNC) {
#if defined(CONFIG_MCORE_HITFLAGS_SYNC) && defined(CONFIG_MCORE_MULTIBLADE)
		struct fphitflagshdr *hfhdr = (struct fphitflagshdr *)(fptunhdr + 1);
		TRACE_MAIN_PROC(FP_LOG_INFO, " Received FPTUN_HITFLAGS_SYNC from blade %u",
				fptunhdr->fptun_blade_id);

		FP_MULTIBLADE_STATS_INC(fp_shared->multiblade_stats,
				RcvdRemoteHFSyncRequest);

		fp_hitflags_update(hfhdr);

		m_freem(m);
		return FP_DONE;
#else
		TRACE_MAIN_PROC(FP_LOG_WARNING, "HITFLAGS_SYNC support is not enabled");
		return FP_DROP;
#endif
	}
	/* other exceptions destined to our CP */
	else
	{
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "FPTUN: exception type %02x",
				fptunhdr->fptun_cmd);

		/* We need ifp to set interface m_priv(m)->ifuid used
		 * by exception handling */
		ifp = fp_ifuid2ifnet(fptunhdr->fptun_ifuid);
		if (unlikely(ifp == NULL)) {
			TRACE_MAIN_PROC(FP_LOG_NOTICE, "FPTUN unknown ifuid %08x",
					ntohl(fptunhdr->fptun_ifuid));
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedInvalidInterface);
			return FP_DROP;
		}
		m_priv(m)->ifuid = ifp->if_ifuid;
		set_mvrfid(m, ntohs(fptunhdr->fptun_vrfid));

		/* Update MAC address for distributed blade case */
		if (fp_shared->cp_if_port != IF_PORT_COLOC) {
			memcpy(eth->ether_dhost, fp_shared->cp_if_mac, FP_ETHER_ADDR_LEN);
			memcpy(eth->ether_shost, fp_shared->fp_if_mac, FP_ETHER_ADDR_LEN);
		}

		return FP_NONE;
	}
#else
	else {
		TRACE_MAIN_PROC(FP_LOG_WARNING, "Unhandled FPTUN command %u",
				fptunhdr->fptun_cmd);
		return FP_DROP;
	}
#endif

}
