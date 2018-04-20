/*
 * Copyright (C) 2010 6WIND, All rights reserved.
 *
 */

#ifndef __FPN_DPVI_RING_H__
#define __FPN_DPVI_RING_H__

#include "fpn-core.h"

/* Definition from Linux point of view:
 * RX: packet received from Fast path
 * TX: packet sent to Fast path
 */
/* dpvi ring entry */

struct fpn_dring_entry {
	uint64_t data;
	uint32_t len;
	uint16_t port;
	uint16_t from:15;
	uint16_t eop:1;
	uint64_t prod_desc;
	uint64_t cons_desc;
};
#ifndef CONFIG_MCORE_FPN_DRING_ORDER
#define CONFIG_MCORE_FPN_DRING_ORDER 8
#endif
#define FPN_DRING_ORDER CONFIG_MCORE_FPN_DRING_ORDER
#define FPN_DRING_SIZE (1<<FPN_DRING_ORDER)
#define FPN_DRING_MASK (FPN_DRING_SIZE-1)
struct fpn_dring {
	struct {
		volatile uint32_t	head;
		volatile uint32_t	tail;
		uint64_t	enqueue;
		uint64_t	enqueue_err;
	} prod __fpn_cache_aligned;
	struct {
		volatile uint32_t	head;
		volatile uint32_t	tail;
		uint64_t	dequeue;
		uint64_t	dequeue_err;
		uint64_t	dequeue_copyerr;
		uint64_t	dequeue_no_eop;
	} cons __fpn_cache_aligned;
	struct fpn_dring_entry desc[FPN_DRING_SIZE] __fpn_cache_aligned;
};

enum dpvi_polling_state {
	DPVI_NOT_POLLING,
	DPVI_POLLING,
	DPVI_LAST_POLLING,
};

#define FPN_DRING_CPU_MAX 128
struct fpn_dring_list {
	enum dpvi_polling_state polling;
	struct fpn_dring cpu[FPN_DRING_CPU_MAX];
};

struct fpn_dpvi_shmem {
	/* Definition from Linux point of view:
	 * RX: packet received from Fast path
	 * TX: packet sent to Fast path
	 */
	struct fpn_dring_list rx_ring[FPN_DRING_CPU_MAX];
	struct fpn_dring_list tx_ring[FPN_DRING_CPU_MAX];

	/* Used to display statistics */
	fpn_cpumask_t dpvi_mask;
	fpn_cpumask_t fp_mask;

	/* size of the fast path mbufs on tx side */
	uint32_t fp_tx_mbuf_size;
};

/* Return the default value for dpvi_mask when not specified at start-up.
 * The function is shared because both Linux and FP must compute the same value.
 * We take all cores possible which are not already taken by the FP.
 */
static inline void
dpvi_select_default_mask(const fpn_cpumask_t * possible_mask,
    const fpn_cpumask_t * exclude_mask, fpn_cpumask_t * dpvi_mask)
{
	*dpvi_mask = *possible_mask;
	fpn_cpumask_sub(dpvi_mask, exclude_mask);

	return;
}

#endif
