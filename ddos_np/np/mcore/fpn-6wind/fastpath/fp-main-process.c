/*
 * Copyright(c) 2006 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"

#include "fp-log.h"
#include "fp-main-process.h"

#include "fp-test-fpn0.h"
#include "fp-netfpc.h"

#ifdef CONFIG_MCORE_IPV6_REASS
#include "fp-reass6.h"
#endif
#include "fpn-cksum.h"

#ifdef CONFIG_MCORE_VXLAN
#include "fp-vxlan.h"
#include "fp-vxlan-lookup.h"
#endif

#ifdef CONFIG_MCORE_TRAFFIC_GEN
#include "fp-traffic-gen-rx.h"
#endif

#include "fp-fptun.h"
#include "fp-ether.h"
#ifdef CONFIG_MCORE_MULTIBLADE
#include "fp-fpib.h"
#endif

#define TRACE_MAIN_PROC(level, fmt, args...) do {		\
	FP_LOG(level, MAIN_PROC, fmt "\n", ## args);		\
} while(0)

void fp_process_input_finish(struct mbuf *m, int result)
{
	if (likely(result == FP_DONE)) {
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "FAST-FORWARDED packet");
		return; /* fast path has sent the packet */
	}
	if (result == FP_KEEP) {
		/* packet is kept for async processing */
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "KEPT packet");
		return;
	}
	if (result == FP_NONE) {
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "IP Exception packet");
		fp_sp_exception(m);

		return;
	}
	if (result == FP_DROP) {
		/* Drop packet */
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "Dropped packet");
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_dropped);
		M_TRACK(m, "FP_DROP");
		m_freem(m);
		return;
	}
	TRACE_MAIN_PROC(FP_LOG_WARNING, "Unexpected result=%d", result);
}

void fp_process_input(struct mbuf *m)
{
	fp_ifport_t *fp_port;
	fp_ifnet_t *ifp;
	uint32_t ifuid;
	int result;

	m_priv(m)->flags = 0;

	M_TRACK(m, "INPUT");
	if (unlikely(fp_shared->conf.w32.magic != FP_SHARED_MAGIC32)) {
		TRACE_MAIN_PROC(FP_LOG_WARNING, "FPM is not ready");
		fpn_send_exception(m, m_input_port(m));
		FP_EXCEP_STATS_INC(fp_shared->exception_stats, LocalBasicExceptions);
		goto out;
	}

#ifdef CONFIG_MCORE_CPONLY_PORTMASK
	/* if port is in cponly_portmask, redirect packet to CP */
	if ((1ULL << m_input_port(m)) & fp_shared->cponly_portmask) {
		fpn_send_exception(m, m_input_port(m));
		goto out;
	}
#endif

	/* reset mbuf tags */
	m_tag_reset(m);

#ifdef CONFIG_MCORE_TRAFFIC_GEN
	result = fp_traffic_gen_rx(m);

	if (likely(result == FP_DROP)) {
		m_freem(m);
		goto out;
	}
	if (result == FP_NONE) {
		fpn_send_exception(m, m_input_port(m));
		goto out;
	}
	if (result == FP_DONE)
		goto out;
#endif

	fp_port = &fp_shared->ifport[m_input_port(m)];

	ifuid = fp_port->ifuid;
	if (unlikely(ifuid == 0)) {
		TRACE_MAIN_PROC(FP_LOG_INFO, "input port %d: ifuid = 0", m_input_port(m));
		if (unlikely(fp_is_fptun_msg(m))) {
			TRACE_MAIN_PROC(FP_LOG_DEBUG,
					"FPTUN message received on port %d",
					m_input_port(m));
			/* FPTUN message must be received from cp_if interface */
			if (m_input_port(m) == fp_shared->cp_if_port) {
				fp_process_input_finish(m, fp_fptun_input(m));
				goto out;
			}
			TRACE_MAIN_PROC(FP_LOG_WARNING,
					"FPTUN message received "
					"from unknown port (%u)",
					m_input_port(m));
			fp_process_input_finish(m, FP_DROP);
			goto out;
		}
		/* packets coming on unknown interface go to slow path */
		fpn_send_exception(m, m_input_port(m));
		FP_EXCEP_STATS_INC(fp_shared->exception_stats, LocalBasicExceptions);
		goto out;
	}

	ifp = (fp_ifnet_t *)fp_port->cached_ifp;
	if (unlikely(ifp == NULL)) {
		ifp = __fp_ifuid2ifnet(ifuid);
		fp_port->cached_ifp = ifp;
		TRACE_MAIN_PROC(FP_LOG_INFO, "updating port/iface mapping cache: port=%d ifuid=0x%08x ifp=%p",
			m_input_port(m), ntohl(ifuid), ifp);
	}
	m_priv(m)->ifuid = ifuid;

	set_mvrfid(m, ifp->if_vrfid);

#if 0
	FP_IF_STATS_INC(ifp->if_stats, ifs_ipackets);
	FP_IF_STATS_ADD(ifp->if_stats, ifs_ibytes, m_len(m));
#endif

	if (likely(fp_ifnet_is_operative(ifp))) {
		m_priv(m)->exc_type = 0;
		m_priv(m)->exc_class = 0;
		result = FPN_HOOK_CALL(fp_ether_input)(m, ifp);
	} else {
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "interface %s (port %d) is not operative", ifp->if_name, ifp->if_port);
#ifdef CONFIG_MCORE_MULTIBLADE
		if (unlikely(fp_is_fptun_msg(m))) {
			TRACE_MAIN_PROC(FP_LOG_DEBUG, "FPTUN message received on port %d", m_input_port(m));
			/* FPTUN message must be received from FPIB interface */
			if (ifp->if_ifuid != fp_shared->fpib_ifuid) {
				TRACE_MAIN_PROC(FP_LOG_WARNING, "FPTUN message received from unexpected interface(ifuid:%u)", ntohl(ifp->if_ifuid));
				FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);
			}
			else {
				fp_process_input_finish(m, fp_fptun_input(m));
				goto out;
			}
		}
#endif
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
		result = FP_DROP;
	}

	fp_process_input_finish(m, result);
 out:
	;
}

static void fp_process_soft_input_finish(struct mbuf *m, int result)
{
	if (likely(result == FP_DONE)) {
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "PROCESSED packet (soft input)");
		return; /* fast path has sent the packet */
	}
	if (result == FP_KEEP) {
		/* packet is kept for async processing */
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "KEPT packet (soft input)");
		return;
	}
	if (result == FP_NONE) {
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "IP Exception packet (soft input)");
		fp_sp_exception(m);
		return;
	}
	if (result == FP_DROP) {
		TRACE_MAIN_PROC(FP_LOG_DEBUG, "DROPPED packet (soft input)");
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_dropped);
		M_TRACK(m, "FP_DROP");
		m_freem(m);
		return;
	}
	TRACE_MAIN_PROC(FP_LOG_WARNING, "Unexpected result=%d (soft input)", result);
}

/* assume ethernet */
void fp_process_soft_input(struct mbuf *m)
{
	int result = FP_DROP;
	uint16_t ethertype;
	struct fp_ether_header *eh;
	struct fp_ether_header eh_save;

	M_TRACK(m, "INPUT");
	if (m_len(m) < sizeof(struct fp_ether_header))
		goto finish;

	/* Reset flags and tag array */
	m_priv(m)->flags = 0;
	m_tag_reset(m);

	if (fp_is_fptun_msg(m)) {
		/* Check FP is ready before running through FPTUN processing */
		if (fp_shared->conf.w32.magic != FP_SHARED_MAGIC32)
			goto finish;
		result = fp_fptun_input(m);
		goto finish;
	}

	if (!fp_test_fpn0(m)) {
		result = FP_DONE;
		goto finish;
	}

	/* Save and remove ethernet header */
	eh = mtod(m, struct fp_ether_header *);
	ethertype = ntohs(eh->ether_type);
	memcpy(&eh_save, eh, sizeof(eh_save));
	m_adj(m, sizeof(struct fp_ether_header));

	if (ethertype == FP_ETHERTYPE_IPV6) {
#ifdef CONFIG_MCORE_IPV6_REASS
		struct fp_ip6_hdr *ip6;

		if (m_len(m) < sizeof(struct fp_ip6_hdr))
			goto finish;
		ip6 = mtod(m, struct fp_ip6_hdr *);

		/* packets can be fragmented, so reassemble them if needed */
		if (ip6->ip6_nxt == FP_IPPROTO_FRAGMENT) {
			/* Check FP is ready before running through reass processing */
			if (fp_shared->conf.w32.magic != FP_SHARED_MAGIC32)
				goto finish;

			set_mvrfid(m, 0);
			result = fp_ip6_reass(&m);
			/* ignore exceptions */
			if (result == FP_NONE)
				result = FP_DROP;
			if (result != FP_CONTINUE)
				goto finish;
		}
#endif

		if (fp_packet_isnetfpc(m)) {
			fp_netfpc_input(m, &eh_save);
			result = FP_DONE;
		}
	}

 finish:
	fp_process_soft_input_finish(m, result);
}

/*
 * send a packet via an interface local to the blade
 * (inline code common to fp_if_output and fp_fpib_forward)
 */
#ifdef CONFIG_MCORE_MULTIBLADE
int fp_direct_if_output(struct mbuf *m, fp_ifnet_t *ifp)
#else
int fp_if_output(struct mbuf *m, fp_ifnet_t *ifp)
#endif
{
	tx_dev_ops_t *tx_dev;
	void *data;
#if 0
	unsigned int len = m_len(m);
#endif
#ifdef CONFIG_MCORE_TAP
	if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_TAP))
		fp_tap(m, ifp, 0);
#endif
	if (unlikely(ifp->if_port == FP_IFNET_VIRTUAL_PORT)) {
		/* change the exception type, the frame is ready to be sent */
		m_priv(m)->exc_type = FPTUN_OUTPUT_EXCEPT;
		/* change the ifuid to the sending interface ifuid */
		m_priv(m)->ifuid = ifp->if_ifuid;

#ifdef CONFIG_MCORE_VRF
		if (likely(ifp->if_type == FP_IFTYPE_XVRF)) {
			uint32_t vrfid, idx;
			fp_ifnet_t *ifp_loop;
			/*
			 * The vrfid is embedded in the last two bytes of
			 * the dst mac address, hence at offset 4 in the
			 * ethernet frame
			 */
			uint8_t *buffer = mtod(m, uint8_t *);
			vrfid = (buffer[4]<<8) + buffer[5];

			idx = fp_shared->fp_xvrf[vrfid];
			ifp_loop = &fp_shared->ifnet.table[idx];

			FP_IF_STATS_INC(ifp->if_stats, ifs_opackets);
			FP_IF_STATS_ADD(ifp->if_stats, ifs_obytes, m_len(m));
			m_priv(m)->exc_type = FPTUN_ETH_INPUT_EXCEPT;
			fp_change_ifnet_packet(m, ifp_loop, 1, 0);

			return (FPN_HOOK_CALL(fp_ether_input)(m, ifp_loop));
		}
#endif
		if (likely(ifp->if_type == FP_IFTYPE_VETH)) {
			fp_ifnet_t *peer_ifp =
				fp_ifuid2ifnet(ifp->sub_table_index);

			if (likely(peer_ifp != NULL)) {
				FP_IF_STATS_INC(ifp->if_stats, ifs_opackets);
				FP_IF_STATS_ADD(ifp->if_stats, ifs_obytes, m_len(m));
				m_priv(m)->exc_type = FPTUN_ETH_INPUT_EXCEPT;
				fp_change_ifnet_packet(m, peer_ifp, 1, 0);
				return FPN_HOOK_CALL(fp_ether_input)(m, peer_ifp);
			} else {
				FP_IF_STATS_INC(ifp->if_stats, ifs_odropped);
				return FP_DROP;
			}
		}
#ifdef CONFIG_MCORE_VXLAN
		if (likely(ifp->if_type == FP_IFTYPE_VXLAN))
			return fp_vxlan_output(m, ifp);
#endif

		tx_dev = fp_ifnet_ops_get(ifp, TX_DEV_OPS, &data);
		if (unlikely(tx_dev != NULL)) {
			int ret = tx_dev(m, ifp, data);
			if (ret != FP_CONTINUE)
				return ret;
		}

		/* other virtual output functions here */
		TRACE_MAIN_PROC(FP_LOG_NOTICE, "No output function for %s", ifp->if_name);
		return fp_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}
#if 0
	FP_IF_STATS_INC(ifp->if_stats, ifs_opackets);
	FP_IF_STATS_ADD(ifp->if_stats, ifs_obytes, len);
#endif
	M_TRACK(m, "IF_SEND");
	M_TRACK_UNTRACK(m); /* mbuf will be destroyed after this anyway */
	if (unlikely(fpn_send_packet(m, ifp->if_port))) {
#if 0
		FP_IF_STATS_DEC(ifp->if_stats, ifs_opackets);
		FP_IF_STATS_SUB(ifp->if_stats, ifs_obytes, len);
#endif
		FP_IF_STATS_INC(ifp->if_stats, ifs_oerrors);
	}
	return FP_DONE;
}


#ifdef CONFIG_MCORE_MULTIBLADE
/*
 * send a packet via an interface on the local or a remote blade
 */
int fp_if_output(struct mbuf *m, fp_ifnet_t *ifp)
{
	/* if output iface is handled by a remote blade, forward frame via FPIB */
	if (unlikely(ifp->if_blade && (ifp->if_blade != fp_shared->fp_blade_id) && !(ifp->if_flags & IFF_FP_LOCAL_OUT))) {

		TRACE_MAIN_PROC(FP_LOG_DEBUG, "Output packet for interface %s, blade %u", ifp->if_name,
				ifp->if_blade);

#ifdef CONFIG_MCORE_USE_HW_TX_L4CKSUM
		fpn_deferred_in4_l4cksum_set(m, FP_ETHER_HDR_LEN);
#endif
#ifdef CONFIG_MCORE_TAP
		/*
		 * If we force tapped packets to be deliverd to the local
		 * CP, we can't rely on the remote blade to do it.
		 */
		if (unlikely((fp_shared->conf.w32.do_func &
			      (FP_CONF_DO_TAP|FP_CONF_DO_TAP_GLOBAL)) == FP_CONF_DO_TAP))
			fp_tap(m, ifp, 0);
#endif

		/* prepend an FPIB header */
		if (unlikely(fp_prepare_fpib_output_req(m, ifp) == FP_DROP)) {
			TRACE_MAIN_PROC(FP_LOG_DEBUG, "fp_prepare_fpib_output_req failed");
			FP_MULTIBLADE_STATS_INC(fp_shared->multiblade_stats,
					SentRemoteExceptionErrors);
			return FP_DROP;
		}
		else {
			int ret = fp_fpib_forward(m, ifp->if_blade);
			FP_MULTIBLADE_STATS_INC(fp_shared->multiblade_stats,
					SentRemotePortOutputRequests);
			return ret;
		}
	}

	return fp_direct_if_output(m, ifp);
}
#endif

FPN_HOOK_REGISTER(fp_if_output)
