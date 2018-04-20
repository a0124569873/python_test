/*
 * Copyright(c) 2006 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"
#include "fp-main-process.h"
#ifdef CONFIG_MCORE_TC_ERL
#include "fp-tc-erl.h"
#endif
#include "fptun.h"
#include "fp-mbuf-priv.h"
#ifdef CONFIG_MCORE_IP
#include "fp-lookup.h"
#endif

#define TRACE_EXC(level, fmt, args...) do {			\
		FP_LOG(level, EXC, fmt "\n", ## args);		\
} while(0)

/*
 * Browse the mtag list and prepend them as a fptun message
 */
static inline int fp_fptun_prepend_mtag(struct mbuf *m)
{
#ifdef CONFIG_MCORE_M_TAG
	uint8_t mtag_count = 0;

	if (unlikely(!m_tag_is_empty(m))) {
		int i, j;
		struct m_tag *m_tag;

		M_TAG_FOREACH(m, i, j, m_tag) {
			struct fpmtaghdr *mtaghdr;
			mtaghdr = (struct fpmtaghdr *)m_prepend(m, sizeof(struct fpmtaghdr));
			if (mtaghdr == NULL)
				return -1;

			snprintf(mtaghdr->fpmtag_name, sizeof(mtaghdr->fpmtag_name),
				 "%s", m_tag_name_find_by_type(m_tag->id));
			mtaghdr->fpmtag_data = m_tag->val;
			mtag_count++;
		}
	}

	/* nb mtags is 4-bit field only */
	if (mtag_count > 0xF)
		return -1;

	return mtag_count;
#else
	return 0;
#endif /* CONFIG_MCORE_M_TAG */
}


void fp_exception_set_type(struct mbuf *m, uint8_t exc_type)
{
	m_priv(m)->exc_type = exc_type;
}

/*
 * Prepare a frame for an exception:
 * (it can be an ethernet frame or an IP packet)
 * an FPTUN header is appended, if needed.
 * Return FP_NONE to indicate exception can occur
 * Return FP_DROP if exception preparation failed
 */
int fp_prepare_exception(struct mbuf *m, uint8_t exc_class)
{
	struct fp_ether_header *eth;
	struct fptunhdr *fptunhdr;
	fp_ifnet_t *ifp;
	int mtags = 0;
 	uint8_t target;
#ifdef CONFIG_MCORE_MULTIBLADE
	int interblade;
#endif

	M_TRACK(m, "EXCEPTION");
	TRACE_EXC(FP_LOG_DEBUG, "preparing exception exc_class=%d, "
		  "exc_type=%d, ifuid=0x%08x", exc_class,
		  m_priv(m)->exc_type, ntohl(m_priv(m)->ifuid));

 	/*
 	 * If the caller already specified the exception steering mode
 	 * just trust him
 	 */
 	target = FPTUN_EXC_TARGET(m_priv(m)->exc_class);
 	if (unlikely(target == FPTUN_EXC_TARGET_DROP)) 
 		return FP_DROP;
 	m_priv(m)->exc_class = exc_class | target;

#ifdef CONFIG_MCORE_MULTIBLADE
	if (unlikely(m_priv(m)->ifuid == 0)) {
		/*
		 * This packet is meant for the local CP, so bypass any interblade
		 * computation, and use the dummy interface (idx,ifuid= 0).
		 */
		interblade = 0;
		ifp = &fp_shared->ifnet.table[0];
	} else {
		ifp = __fp_ifuid2ifnet(m_priv(m)->ifuid);

		/*
		 * If !FP_CONF_DO_TAP_GLOBAL, force tapped packet to be sent to the
		 * local CP, no matter on which blade the interface is active
		 */
	 	if (unlikely(target >= FPTUN_EXC_TARGET_LOCALCP))
			interblade = 0;
		else
#ifdef CONFIG_MCORE_1CP_XFP
			interblade = (fp_shared->active_cpid != fp_shared->cp_blade_id);
#else
			interblade = (fp_shared->active_cpid != fp_shared->fp_blade_id);
#endif
			if (fp_shared->active_cpid == 0)
				interblade = 0;
	}

	if (interblade) {
		FP_EXCEP_STATS_INC(fp_shared->exception_stats, RemoteExceptionClass[exc_class & FPTUN_EXC_CLASS_MASK]);
		FP_EXCEP_STATS_INC(fp_shared->exception_stats, RemoteExceptionType[m_priv(m)->exc_type]);
	}
	else 
#endif
	{
		FP_EXCEP_STATS_INC(fp_shared->exception_stats, LocalExceptionClass[exc_class & FPTUN_EXC_CLASS_MASK]);
		FP_EXCEP_STATS_INC(fp_shared->exception_stats, LocalExceptionType[m_priv(m)->exc_type]);
	}

	/*
	 * If exception type is 0, then this is a basic exception
	 */
	if (likely(m_priv(m)->exc_type == 0)) {

		/*
		 * Due to mtag, it is NOT a basic exception any more
		 */
#ifdef CONFIG_MCORE_M_TAG
		if (unlikely(! m_tag_is_empty(m))) {
			TRACE_EXC(FP_LOG_DEBUG, "%s: Extended (mtags) exception, FPTUN header needed",
			           __FUNCTION__);
			m_priv(m)->exc_type = FPTUN_ETH_INPUT_EXCEPT;
			goto fptun;
		}
#endif /* CONFIG_MCORE_M_TAG */

#ifdef CONFIG_MCORE_MULTIBLADE
		if (unlikely(interblade)) {
			TRACE_EXC(FP_LOG_DEBUG, "%s: Basic inter-blade remote exception, "
					"FPTUN header needed", __FUNCTION__);
			FP_EXCEP_STATS_INC(fp_shared->exception_stats, InterBladeExceptions);
			if (unlikely((!fp_shared->fpib_ifuid) ||
						(fp_shared->active_cpid == 0) ||
						(fp_shared->active_cpid > FP_BLADEID_MAX))) {
				TRACE_EXC(FP_LOG_WARNING, "FPIB interface or active cpid is not defined");
				FP_MULTIBLADE_STATS_INC(fp_shared->multiblade_stats, RcvdLocalConfigErrors);
				return FP_DROP;
			}
			m_priv(m)->exc_type = FPTUN_ETH_INPUT_EXCEPT;
			goto fptun;
		}
#endif /* CONFIG_MCORE_MULTIBLADE */

		if (likely(fp_shared->cp_if_port == IF_PORT_COLOC)) {
			TRACE_EXC(FP_LOG_DEBUG, "%s: Basic co-localized exception, "
					"frame unmodified", __FUNCTION__);
			return FP_NONE;
		} else {
			TRACE_EXC(FP_LOG_DEBUG, "%s: Basic intra-blade remote exception, "
					"FPTUN header needed", __FUNCTION__);
			FP_EXCEP_STATS_INC(fp_shared->exception_stats, IntraBladeExceptions);
			m_priv(m)->exc_type = FPTUN_ETH_INPUT_EXCEPT;
		}

	} else {  /* exceptions type != 0 */

#ifdef CONFIG_MCORE_MULTIBLADE
		if (unlikely(interblade)) {
			TRACE_EXC(FP_LOG_DEBUG, "%s: Basic inter-blade remote exception, "
					"FPTUN header needed", __FUNCTION__);
			FP_EXCEP_STATS_INC(fp_shared->exception_stats, InterBladeExceptions);
			goto fptun;
		}
#endif
		if (likely(fp_shared->cp_if_port == IF_PORT_COLOC)) {
			TRACE_EXC(FP_LOG_DEBUG, "%s: Co-localized exception, FPTUN header needed", __FUNCTION__);
		} else {
			TRACE_EXC(FP_LOG_DEBUG, "%s: Basic intra-blade remote exception, "
					"FPTUN header needed", __FUNCTION__);
			FP_EXCEP_STATS_INC(fp_shared->exception_stats, IntraBladeExceptions);
			goto fptun;
		}
	}

fptun:
	FP_EXCEP_STATS_INC(fp_shared->exception_stats, LocalFPTunExceptions);

#ifdef CONFIG_MCORE_M_TAG
	mtags = fp_fptun_prepend_mtag(m);
	if (unlikely(mtags < 0)) {
		TRACE_EXC(FP_LOG_WARNING, "%s: could not prepend mtag header", __FUNCTION__);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
		return FP_DROP;
	}
#endif /* CONFIG_MCORE_M_TAG */

	/* Prepend ethernet + fptun headers */
	eth = (struct fp_ether_header *)m_prepend(m, FP_ETHER_HDR_LEN + FPTUN_HLEN);
	if (unlikely(eth == NULL)) {
		TRACE_EXC(FP_LOG_WARNING, "%s: could not prepend ethernet + fptun", __FUNCTION__);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
		return FP_DROP;
	}

#ifndef CONFIG_MCORE_MULTIBLADE
	ifp = __fp_ifuid2ifnet(m_priv(m)->ifuid);
#endif

	if (unlikely(
#ifdef CONFIG_MCORE_MULTIBLADE
	    (!interblade) &&
#endif /* CONFIG_MCORE_MULTIBLADE */
	    (fp_shared->cp_if_fptun_size_thresh && m_len(m) > (fp_shared->cp_if_fptun_size_thresh + FP_ETHER_HDR_LEN)))) {
		TRACE_EXC(FP_LOG_WARNING, "%s: FPTUN message is bigger than cp_if_fptun_size_thresh (%u>%u)", __FUNCTION__,
				(unsigned)(m_len(m)-FP_ETHER_HDR_LEN),
				(unsigned)fp_shared->cp_if_fptun_size_thresh);
		FP_EXCEP_STATS_INC(fp_shared->exception_stats, FptunSizeExceedsCpIfThresh);
	}

	fptunhdr = (struct fptunhdr *)(eth + 1);

	fptunhdr->fptun_cmd      = m_priv(m)->exc_type;
	fptunhdr->fptun_exc_class= exc_class;
	fptunhdr->fptun_mtags    = mtags;
	fptunhdr->fptun_version  = FPTUN_VERSION;
	fptunhdr->fptun_vrfid    = htons(m2vrfid(m));
	fptunhdr->fptun_proto    = m_priv(m)->exc_proto;

	fptunhdr->fptun_blade_id = fp_shared->active_cpid;
	fptunhdr->fptun_ifuid    = ifp->if_ifuid;

	eth->ether_type = htons(ETH_P_FPTUN);

#ifdef CONFIG_MCORE_MULTIBLADE
	/* inter-blade case: mac addresses will be set by fp_fpib_forward */
	if (unlikely(interblade))
		return FP_NONE;
#endif /* CONFIG_MCORE_MULTIBLADE */
	if (likely(fp_shared->cp_if_port == IF_PORT_COLOC)) {
		/* co-localized CP case: use input port to write dest MAC */
		fp_ifnet_t *ifp_coloc;

		ifp_coloc = fp_ifuid2ifnet(fp_port2ifuid(m_input_port(m)));
		if (ifp_coloc)
			memcpy(eth->ether_dhost, ifp_coloc->if_mac,
			       FP_ETHER_ADDR_LEN);
		else {
			/* m is coming from fpn0, fpm stores MAC in cp_if_mac */
			memcpy(eth->ether_dhost, fp_shared->cp_if_mac, FP_ETHER_ADDR_LEN);
		}
	} else {
		/* intra-blade case: set configured remote CP mac addresses */
		memcpy(eth->ether_dhost, fp_shared->cp_if_mac, FP_ETHER_ADDR_LEN);
	}
	memcpy(eth->ether_shost, fp_shared->fp_if_mac, FP_ETHER_ADDR_LEN);

	return FP_NONE;
}


#ifdef CONFIG_MCORE_IP
static int fp_ip_ecmp_prepare_exception(struct mbuf *m, fp_rt4_entry_t *rt,
					struct fp_ip *ip)
{
	fp_nh4_entry_t *nh;
	struct fpecmphdr *ecmphdr;
	uint8_t target;
	fp_ifnet_t *ifp;

	ecmphdr = (struct fpecmphdr *)m_prepend(m, sizeof(struct fpecmphdr));
	if (ecmphdr == NULL) {
		TRACE_EXC(FP_LOG_WARNING, "%s: could not prepend ecmp header", __FUNCTION__);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
		return FP_DROP;
	}

	nh = select_nh4(rt, &ip->ip_src.s_addr);

	ecmphdr->ip_v = FPECMP_IPV4;
	ecmphdr->ip_nexthop = nh->nh_gw;
	ifp = __fp_ifuid2ifnet(nh->nh.nh_ifuid);
	ecmphdr->ifuid = ifp->if_ifuid;

	if (likely(m_priv(m)->exc_type == 0))
		m_priv(m)->exc_type = FPTUN_ETH_INPUT_EXCEPT;

	target = FPTUN_EXC_TARGET(m_priv(m)->exc_class);
	m_priv(m)->exc_class = FPTUN_EXC_ECMP_NDISC_NEEDED | target;

	return fp_prepare_exception(m, m_priv(m)->exc_class);
}
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
static int fp_ip6_ecmp_prepare_exception(struct mbuf *m, fp_rt6_entry_t *rt,
					 struct fp_ip6_hdr *ip6)
{
	fp_nh6_entry_t *nh;
	struct fpecmp6hdr *ecmp6hdr;
	uint8_t target;
	fp_ifnet_t *ifp;

	ecmp6hdr = (struct fpecmp6hdr *)m_prepend(m, sizeof(struct fpecmp6hdr));
	if (ecmp6hdr == NULL) {
		TRACE_EXC(FP_LOG_WARNING, "%s: could not prepend ecmp header", __FUNCTION__);
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoMemory);
		return FP_DROP;
	}

	nh = select_nh6(rt, &ip6->ip6_src);

	ecmp6hdr->ip_v = FPECMP_IPV6;
	memcpy(ecmp6hdr->ip6_nexthop, nh->nh_gw.fp_s6_addr,
	       sizeof (nh->nh_gw.fp_s6_addr));
	ifp = __fp_ifuid2ifnet(nh->nh.nh_ifuid);
	ecmp6hdr->ifuid = ifp->if_ifuid;
	if (likely(m_priv(m)->exc_type == 0))
		m_priv(m)->exc_type = FPTUN_ETH_INPUT_EXCEPT;

	target = FPTUN_EXC_TARGET(m_priv(m)->exc_class);
	m_priv(m)->exc_class = FPTUN_EXC_ECMP_NDISC_NEEDED | target;

	return fp_prepare_exception(m, m_priv(m)->exc_class);
}
#endif

/*
 * Prepare an IP packet for an exception:
 * if needed, the ethernet header is restored
 * then fp_prepare_exception is called
 */
int fp_ip_prepare_exception(struct mbuf *m, uint8_t exc_class)
{

	struct fp_ip *ip = mtod(m, struct fp_ip *);

	if (unlikely (ip->ip_p == FP_IPPROTO_VRRP)) {
		fp_ifnet_t *ifp;

		ifp = __fp_ifuid2ifnet(m_priv(m)->ifuid);
		/*
		 * VRRP packet must go to the local CP
		 * and potentialyy bypass INACTIVE drops
		 */
		if (ifp->if_flags & IFF_FP_IVRRP)
			m_priv(m)->exc_class = FPTUN_EXC_TARGET_LOCALCP;
	}

	if (likely((m_priv(m)->exc_type == 0) ||
	           (m_priv(m)->exc_type == FPTUN_ETH_INPUT_EXCEPT)) ||
	           (m_priv(m)->exc_type == FPTUN_ETH_NOVNB_INPUT_EXCEPT)) {
		/* restore ethernet header */
		TRACE_EXC(FP_LOG_DEBUG, "%s: restoring ethernet header", __FUNCTION__);
		/* Revert pointers to mac layer */
		if (unlikely(m_prepend(m, sizeof(struct fp_ether_header)) == NULL)) {
			TRACE_EXC(FP_LOG_WARNING, "%s: could not restore ethernet header", __FUNCTION__);
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
			return FP_DROP;
		}
		m_restore_mac(m);
		FP_LOG_MBUF(FP_LOG_DEBUG, FP_LOGTYPE_EXC, m, 32);
	}

	if ((exc_class & FPTUN_EXC_CLASS_PRIO_MASK) == FPTUN_EXC_NDISC_NEEDED) {
		if (ip->ip_v == FP_IPVERSION) {
#ifdef CONFIG_MCORE_IP
			fp_rt4_entry_t *rt;

			rt = fp_rt4_lookup(m2vrfid(m), ip->ip_dst.s_addr);
			if (unlikely(!rt)) {
				FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoRouteLocal);
				return FP_DROP;
			}
			if (rt->rt.rt_nb_nh > 1)
				return fp_ip_ecmp_prepare_exception(m, rt, ip);
#endif
		}
#ifdef CONFIG_MCORE_IPV6
		  else {
			struct fp_ip6_hdr *ip6 = (struct fp_ip6_hdr *) ip;
			fp_rt6_entry_t *rt;

			rt = fp_rt6_lookup(m2vrfid(m), &ip6->ip6_dst);
			if (unlikely(!rt)) {
				FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoRouteLocal);
				return FP_DROP;
			}
			if (rt->rt.rt_nb_nh > 1)
				return fp_ip6_ecmp_prepare_exception(m, rt, ip6);
		}
#endif
	}

	return fp_prepare_exception(m, exc_class);
}

void fp_send_exception(struct mbuf *m, uint8_t port)
{
#ifdef CONFIG_MCORE_TC_ERL
	if (fp_tc_erl(m) < 0)
		return;
#endif
	/* exception handled by our blade, dual-NPU case */
	if (unlikely(fp_shared->cp_if_port != IF_PORT_COLOC)) {
		TRACE_EXC(FP_LOG_INFO, "%s: remote-NPU exception, cp_if_port=%d", 
			   __FUNCTION__, port);
		fpn_send_packet(m, fp_shared->cp_if_port);
		return;
	}

	/* co-localized CP case */
	/* sdk specific packet exception sending */
	TRACE_EXC(FP_LOG_INFO, "%s: co-localized CP", __FUNCTION__);
	fpn_send_exception(m, port);
	FP_EXCEP_STATS_INC(fp_shared->exception_stats, LocalBasicExceptions);
}  

void fp_sp_exception(struct mbuf *m)
{
#ifdef CONFIG_MCORE_MULTIBLADE
	fp_ifnet_t *ifp;
	int interblade = 0;
#endif

	TRACE_EXC(FP_LOG_INFO, "%s: vr=%d port=%d, ifuid=0x%08x, data_len=%d, exc_type=%d",
		__FUNCTION__, m2vrfid(m), m_input_port(m), ntohl(m_priv(m)->ifuid), m_len(m),
		m_priv(m)->exc_type);

#ifdef CONFIG_MCORE_MULTIBLADE
	/* determine which blade must handle the exception */
	if (m_priv(m)->ifuid == 0) {
		TRACE_EXC(FP_LOG_INFO, "%s: no ifuid => local exception", __FUNCTION__);
		goto localblade;
	}
	
	ifp = __fp_ifuid2ifnet(m_priv(m)->ifuid);

	if (unlikely(ifp->if_ifuid == 0)) {
		TRACE_EXC(FP_LOG_INFO, "%s: interface not yet configured", __FUNCTION__);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedInvalidInterface);
		goto drop;
	}

	/*
	 * If !FP_CONF_DO_TAP_GLOBAL, force tapped packet to be sent to the
	 * local CP, no matter on which blade the interface is active
	 */
	if (unlikely((FPTUN_EXC_TARGET(m_priv(m)->exc_class) >= FPTUN_EXC_TARGET_LOCALCP)))
		goto localblade;

	/* exception handled by another blade */
#ifdef CONFIG_MCORE_1CP_XFP
	interblade = fp_shared->active_cpid != fp_shared->cp_blade_id;
#else
	interblade = fp_shared->active_cpid != fp_shared->fp_blade_id;
#endif
	if (fp_shared->active_cpid == 0)
		interblade = 0;
	if (unlikely (interblade )) {
		int ret;
		TRACE_EXC(FP_LOG_INFO, "%s: forwarding from blade %d to blade %d required",
			__FUNCTION__, fp_shared->fp_blade_id, fp_shared->active_cpid);

#ifdef CONFIG_MCORE_TC_ERL
		if (fp_tc_erl(m) < 0)
			return;
#endif
		ret = fp_fpib_forward(m, fp_shared->active_cpid);
		if (unlikely(ret != FP_DONE))
			goto drop;
		return;
	}
localblade:
#endif

	/* basic exception goes to physical input port, else send to fpn0 */
	if (m_priv(m)->exc_type == 0)
		fp_send_exception(m, m_input_port(m));
	else
		fp_send_exception(m, m_control_port());

	return;

#ifdef CONFIG_MCORE_MULTIBLADE
drop:
#endif
	TRACE_EXC(FP_LOG_INFO, "%s: Dropped packet", __FUNCTION__);
	FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_dropped);
	m_freem(m);
}

#ifdef CONFIG_MCORE_MULTIBLADE
/*
 * Prepare a frame for FPIB forwarding:
 * an FPTUN header is appended, with command FPTUN_ETH_FP_OUTPUT_REQ
 *
 * Return values:
 * FP_CONTINUE preparation is ok. p_ifp points on fpib interface
 * FP_DROP     an error occured
 */
int fp_prepare_fpib_output_req(struct mbuf *m, fp_ifnet_t *ifp)
{
	struct fp_ether_header *eth;
	struct fptunhdr *fptunhdr;
	int mtags = 0;

	TRACE_EXC(FP_LOG_DEBUG, "preparing fpib output request");

#ifdef CONFIG_MCORE_M_TAG
	mtags = fp_fptun_prepend_mtag(m);
	if (unlikely(mtags < 0)) {
		TRACE_EXC(FP_LOG_WARNING, "%s: could not prepend mtag header", __FUNCTION__);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
		return FP_DROP;
	}
#endif /* CONFIG_MCORE_M_TAG */

	/* Prepend ethernet + fptun headers */
	eth = (struct fp_ether_header *)m_prepend(m, FP_ETHER_HDR_LEN + FPTUN_HLEN);
	if (unlikely(eth == NULL)) {
		TRACE_EXC(FP_LOG_WARNING, "%s: could not prepend ethernet + fptun", __FUNCTION__);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
		return FP_DROP;
	}

	fptunhdr = (struct fptunhdr *)(eth + 1);

	fptunhdr->fptun_cmd      = FPTUN_ETH_FP_OUTPUT_REQ;
	fptunhdr->fptun_exc_class= 0;
	fptunhdr->fptun_mtags    = mtags;
	fptunhdr->fptun_version  = FPTUN_VERSION;
	fptunhdr->fptun_proto    = 0;
	fptunhdr->fptun_vrfid    = htons(m2vrfid(m));
	fptunhdr->fptun_blade_id = ifp->if_blade;
	fptunhdr->fptun_ifuid    = ifp->if_ifuid;

	eth->ether_type = htons(ETH_P_FPTUN);

	/* mac addresses will be set by fp_fpib_forward */

	return FP_CONTINUE;
}

/*
 * Prepare a frame for FPIB forwarding:
 * an FPTUN, mtags and ipsec header are appended, with command
 * FPTUN_IPV4_FP_IPSEC_OUTPUT_REQ
 *
 * Return values:
 * FP_CONTINUE preparation is ok. p_ifp points on fpib interface
 * FP_DROP     an error occured
 */
int fp_prepare_ipsec_output_req(struct mbuf *m, uint8_t blade_id, uint32_t ifuid)
{
	struct fp_ether_header *eth;
	struct fptunhdr *fptunhdr;
	int mtags = 0;

	TRACE_EXC(FP_LOG_DEBUG, "preparing fpib output request");

#ifdef CONFIG_MCORE_M_TAG
	mtags = fp_fptun_prepend_mtag(m);
	if (unlikely(mtags < 0)) {
		TRACE_EXC(FP_LOG_WARNING, "%s: could not prepend mtag header", __FUNCTION__);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
		return FP_DROP;
	}
#endif /* CONFIG_MCORE_M_TAG */

	/* Prepend ethernet + fptun headers */
	eth = (struct fp_ether_header *)m_prepend(m, FP_ETHER_HDR_LEN + FPTUN_HLEN);
	if (unlikely(eth == NULL)) {
		TRACE_EXC(FP_LOG_WARNING, "%s: could not prepend ethernet + fptun", __FUNCTION__);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
		return FP_DROP;
	}

	fptunhdr = (struct fptunhdr *)(eth + 1);

	fptunhdr->fptun_cmd      = FPTUN_IPV4_IPSEC_FP_OUTPUT_REQ;
	fptunhdr->fptun_exc_class= 0;
	fptunhdr->fptun_mtags    = mtags;
	fptunhdr->fptun_version  = FPTUN_VERSION;
	fptunhdr->fptun_proto    = 0;
	fptunhdr->fptun_vrfid    = htons(m2vrfid(m));
	fptunhdr->fptun_blade_id = blade_id;
	fptunhdr->fptun_ifuid    = ifuid;

	eth->ether_type = htons(ETH_P_FPTUN);

	/* mac addresses will be set by fp_fpib_forward */

	return FP_CONTINUE;
}


int fp_prepare_ipsec6_output_req(struct mbuf *m, uint8_t blade_id, uint32_t ifuid)
{
	struct fp_ether_header *eth;
	struct fptunhdr *fptunhdr;
	int mtags = 0;

	TRACE_EXC(FP_LOG_DEBUG, "preparing fpib output request");

#ifdef CONFIG_MCORE_M_TAG
	mtags = fp_fptun_prepend_mtag(m);
	if (unlikely(mtags < 0)) {
		TRACE_EXC(FP_LOG_WARNING, "%s: could not prepend mtag header", __FUNCTION__);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
		return FP_DROP;
	}
#endif /* CONFIG_MCORE_M_TAG */

	/* Prepend ethernet + fptun headers */
	eth = (struct fp_ether_header *)m_prepend(m, FP_ETHER_HDR_LEN + FPTUN_HLEN);
	if (unlikely(eth == NULL)) {
		TRACE_EXC(FP_LOG_WARNING, "%s: could not prepend ethernet + fptun", __FUNCTION__);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
		return FP_DROP;
	}

	fptunhdr = (struct fptunhdr *)(eth + 1);

	fptunhdr->fptun_cmd      = FPTUN_IPV6_IPSEC_FP_OUTPUT_REQ;
	fptunhdr->fptun_exc_class= 0;
	fptunhdr->fptun_mtags    = mtags;
	fptunhdr->fptun_version  = FPTUN_VERSION;
	fptunhdr->fptun_proto    = 0;
	fptunhdr->fptun_vrfid    = htons(m2vrfid(m));
	fptunhdr->fptun_blade_id = blade_id;
	fptunhdr->fptun_ifuid    = ifuid;

	eth->ether_type = htons(ETH_P_FPTUN);

	/* mac addresses will be set by fp_fpib_forward */

	return FP_CONTINUE;
}

#endif /* CONFIG_MCORE_MULTIBLADE */
