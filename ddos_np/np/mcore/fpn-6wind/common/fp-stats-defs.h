/*
 * Copyright(c) 2007 6WIND
 */
#ifndef __FP_STATS_DEFS_H__
#define __FP_STATS_DEFS_H__

#if defined(CONFIG_MCORE_FPE_VFP)
/* emulator */
#define FP_IF_STATS_PER_CORE          1
#define FP_IP_STATS_PER_CORE          1
#define FP_ARP_STATS_PER_CORE         1
//#define FP_IPSEC_STATS_PER_CORE       1
#define FP_NF_STATS_PER_CORE          1
#define FP_MULTIBLADE_STATS_PER_CORE  1
#define FP_GLOBAL_STATS_PER_CORE      1
#define FP_EXCEP_STATS_PER_CORE       1
#define FP_TCP_STATS_PER_CORE         1
#define FP_UDP_STATS_PER_CORE         1
#define FP_UDP6_STATS_PER_CORE        1
#define FP_VSWITCH_STATS_PER_CORE     1
#define FP_L2_STATS_PER_CORE          1

#elif defined(CONFIG_MCORE_ARCH_XLP)
#define FP_IF_STATS_PER_CORE          1
#define FP_IP_STATS_PER_CORE          1
#define FP_ARP_STATS_PER_CORE         1
#define FP_IPSEC_STATS_PER_CORE       1
#define FP_NF_STATS_PER_CORE          1
#define FP_MULTIBLADE_STATS_PER_CORE  1
#define FP_GLOBAL_STATS_PER_CORE      1
#define FP_EXCEP_STATS_PER_CORE       1
#define FP_TCP_STATS_PER_CORE         1
#define FP_UDP_STATS_PER_CORE         1
#define FP_UDP6_STATS_PER_CORE        1
#define FP_VSWITCH_STATS_PER_CORE     1
#define FP_L2_STATS_PER_CORE          1

#elif defined(CONFIG_MCORE_ARCH_OCTEON)
#define FP_IF_STATS_PER_CORE          1
#define FP_IP_STATS_PER_CORE          1
#define FP_ARP_STATS_PER_CORE         1
//#define FP_IPSEC_STATS_PER_CORE       1
#define FP_NF_STATS_PER_CORE          1
#define FP_MULTIBLADE_STATS_PER_CORE  1
#define FP_GLOBAL_STATS_PER_CORE      1
#define FP_EXCEP_STATS_PER_CORE       1
#define FP_TCP_STATS_PER_CORE         1
#define FP_UDP_STATS_PER_CORE         1
#define FP_UDP6_STATS_PER_CORE        1
#define FP_VSWITCH_STATS_PER_CORE     1
#define FP_L2_STATS_PER_CORE          1

#elif defined(CONFIG_MCORE_ARCH_DPDK)
#define FP_IF_STATS_PER_CORE          1
#define FP_IP_STATS_PER_CORE          1
#define FP_ARP_STATS_PER_CORE         1
#define FP_IPSEC_STATS_PER_CORE       1
#define FP_NF_STATS_PER_CORE          1
#define FP_MULTIBLADE_STATS_PER_CORE  1
#define FP_GLOBAL_STATS_PER_CORE      1
#define FP_EXCEP_STATS_PER_CORE       1
#define FP_TCP_STATS_PER_CORE         1
#define FP_UDP_STATS_PER_CORE         1
#define FP_UDP6_STATS_PER_CORE        1
#define FP_VSWITCH_STATS_PER_CORE     1
#define FP_L2_STATS_PER_CORE          1

#elif defined(CONFIG_MCORE_ARCH_TILEGX)
#define FP_IF_STATS_PER_CORE          1
#define FP_IP_STATS_PER_CORE          1
#define FP_ARP_STATS_PER_CORE         1
#define FP_IPSEC_STATS_PER_CORE       1
#define FP_NF_STATS_PER_CORE          1
#define FP_MULTIBLADE_STATS_PER_CORE  1
#define FP_GLOBAL_STATS_PER_CORE      1
#define FP_EXCEP_STATS_PER_CORE       1
#define FP_TCP_STATS_PER_CORE         1
#define FP_UDP_STATS_PER_CORE         1
#define FP_UDP6_STATS_PER_CORE        1
#define FP_VSWITCH_STATS_PER_CORE     1
#define FP_L2_STATS_PER_CORE          1
#endif

#endif /* __FP_STATS_DEFS_H__ */
