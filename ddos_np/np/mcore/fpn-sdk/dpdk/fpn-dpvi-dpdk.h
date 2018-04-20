/*
 * Copyright (c) 2012 6WIND, All rights reserved.
 */

#ifndef __FPN_DPVI_DPDK_H__
#define __FPN_DPVI_DPDK_H__

#include <dpvi.h>
#include <fpn-dpvi.h>
#include "fpn-dpvi-ring.h"

#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
#define  ETH_LINK_SPEED_10           ETH_SPEED_NUM_10M   /**< 10m bits/second. */
#define  ETH_LINK_SPEED_100          ETH_SPEED_NUM_100M  /**< 100m bits/second. */
#define  ETH_LINK_SPEED_1000         ETH_SPEED_NUM_1G    /**< 1g bits/second. */
#define  ETH_LINK_SPEED_10000        ETH_SPEED_NUM_10G   /**< 10g bits/second. */
#define  ETH_LINK_SPEED_40000        ETH_SPEED_NUM_40G   /**< 40g bits/second>*/ 
#endif
extern void push_to_linux(struct mbuf *m, int port);
extern void push_to_linux_multi(struct mbuf *m, int port);

extern int fpn_dpvi_ethtool_get_drvinfo(int portid, struct dpvi_ethtool_drvinfo *dpvi_info);
extern int fpn_dpvi_ethtool_get_settings(int portid, struct dpvi_ethtool_gsettings *dpvi_settings);
extern int fpn_dpvi_ethtool_get_sset_count(int portid, struct dpvi_ethtool_sset_count *dpvi_sset_count);
extern int fpn_dpvi_ethtool_get_strings(int portid, struct dpvi_ethtool_gstrings *dpvi_strings);
extern int fpn_dpvi_ethtool_get_statsinfo(int portid, struct dpvi_ethtool_statsinfo *dpvi_stats);
extern int fpn_dpvi_ethtool_get_pauseparam(int portid, struct dpvi_ethtool_pauseparam *dpvi_pauseparam);
extern int fpn_dpvi_ethtool_set_pauseparam(int portid, struct dpvi_ethtool_pauseparam *dpvi_pauseparam);

extern struct fpn_dpvi_shmem * fpn_dpvi_shmem_mmap(void);
extern void fpn_dpvi_init(const fpn_cpumask_t * fpn_mask, const fpn_cpumask_t * fpn_linux2fp_mask,
                          const fpn_cpumask_t * dpvi_mask, const fpn_cpumask_t * online_mask);
extern void dequeue_copy(struct fpn_dring_entry *out, struct fpn_dring_entry *dre);
extern unsigned fpn_recv_exception(void);

#endif /*__FPN_DPVI_DPDK_H__*/
