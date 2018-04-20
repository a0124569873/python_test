/*
 * Copyright(c) 2010 6WIND
 */
#include "fp-includes.h"

#include "fp-log.h"
#include "fp-main-process.h"

#define TRACE_MAIN_PROC(level, fmt, args...) do {		\
	FP_LOG(level, MAIN_PROC, fmt "\n", ## args);		\
} while(0)

/*
 * Forward an FPTUN message to a remote blade
 * Return FP_DONE if forwarding is ok
 * Return FP_DROP if an error occured
 */
int fp_fpib_forward(struct mbuf *m, uint8_t blade_id)
{
	struct fp_ether_header *eth;
	fp_ifnet_t *fpibifp;

	TRACE_MAIN_PROC(FP_LOG_DEBUG, "preparing to forward an fpib message to blade %u", blade_id);

	if (unlikely(!fp_shared->fpib_ifuid)) {
		TRACE_MAIN_PROC(FP_LOG_NOTICE, "FPIB interface is not defined");
		FP_MULTIBLADE_STATS_INC(fp_shared->multiblade_stats, RcvdLocalConfigErrors);
		return FP_DROP;
	}

	if (unlikely((blade_id == 0) ||
				(blade_id > FP_BLADEID_MAX) ||
				(!fp_shared->fp_blades[blade_id].blade_active))) {
		TRACE_MAIN_PROC(FP_LOG_NOTICE, "%s: missing blade %u mac address", __FUNCTION__, blade_id);
		FP_MULTIBLADE_STATS_INC(fp_shared->multiblade_stats, RcvdLocalBladeUnactive);
		return FP_DROP;
	}

	fpibifp = __fp_ifuid2ifnet(fp_shared->fpib_ifuid);

	if (unlikely(fp_shared->cp_if_fptun_size_thresh && (m_len(m) > fp_shared->fpib_fptun_size_thresh + FP_ETHER_HDR_LEN))) {
		TRACE_MAIN_PROC(FP_LOG_WARNING, "%s: FPTUN message is bigger than fpib_fptun_size_thresh (%u>%u)", __FUNCTION__,
				(unsigned)(m_len(m) - FP_ETHER_HDR_LEN),
				(unsigned)fp_shared->fpib_fptun_size_thresh);
		FP_EXCEP_STATS_INC(fp_shared->exception_stats, FptunSizeExceedsFpibThresh);
	}

       if (unlikely(!fp_ifnet_is_operative(fpibifp))) {
               FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
               return FP_DROP;
       }

	/* update FPTUN frame mac addresses */
	eth = mtod(m, struct fp_ether_header *);

	memcpy(eth->ether_dhost, &fp_shared->fp_blades[blade_id].blade_mac,
			FP_ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, fpibifp->if_mac, FP_ETHER_ADDR_LEN);

	return fp_direct_if_output(m, fpibifp);
}
