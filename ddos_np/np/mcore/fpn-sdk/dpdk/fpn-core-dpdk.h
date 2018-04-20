/*
 * Copyright(c) 2012 6WIND
 */
#ifndef __FPN_CORE_DPDK_H__
#define __FPN_CORE_DPDK_H__

static inline int fpn_get_core_num(void)
{
	return rte_lcore_id();
}

#endif /* __FPN_CORE_DPDK_H__ */
