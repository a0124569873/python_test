/*
 * Copyright(c) 2009 6WIND
 */

#ifndef __FP_HITFLAGS_H__
#define __FP_HITFLAGS_H__

#define HF_PERIOD_DFLT_ARP         1
#define HF_MAX_SCANNED_DFLT_ARP    2500
#define HF_MAX_SENT_DFLT_ARP       1600

#ifdef CONFIG_MCORE_IPV6
  #define HF_PERIOD_DFLT_NDP       1
  #define HF_MAX_SCANNED_DFLT_NDP  2500
  #define HF_MAX_SENT_DFLT_NDP     1600
#endif

#ifdef CONFIG_MCORE_NETFILTER
  #define HF_PERIOD_DFLT_CT        5
  #define HF_MAX_SCANNED_DFLT_CT   44000
  #define HF_MAX_SENT_DFLT_CT      22000
#endif

#ifdef CONFIG_MCORE_NETFILTER_IPV6
  #define HF_PERIOD_DFLT_CT6       5
  #define HF_MAX_SCANNED_DFLT_CT6  200
  #define HF_MAX_SENT_DFLT_CT6     100
#endif

struct fp_hf_param {
	uint32_t hfp_max_scanned;
	uint32_t hfp_max_sent;
	uint8_t  hfp_period;
	uint8_t  reserv1;
	uint16_t reserv2;
};

#endif
