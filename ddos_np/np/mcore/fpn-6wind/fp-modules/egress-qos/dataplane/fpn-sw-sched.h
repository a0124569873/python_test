/*
 * Copyright(c) 2013 6WIND, All rights reserved.
 */
#ifndef __FPN_SW_SCHED_H__
#define __FPN_SW_SCHED_H__

/* only available for dpdk at the moment */
#ifndef CONFIG_MCORE_ARCH_DPDK
#error Software packet scheduling is not available for this architecure.
#endif

typedef struct fpn_sw_sched_params {
	char *name;
	unsigned int core;
	unsigned int port;
	void *arg;
} fpn_sw_sched_params_t;

void *fpn_sw_sched_allocate(fpn_sw_sched_params_t *params);
uint32_t fpn_sw_sched_default_class(void *sw_port, struct mbuf *m);
int fpn_sw_sched_classify(void *sw_port, struct mbuf *m, uint32_t class);
int fpn_sw_sched_enqueue(void *sw_port, struct mbuf **pkts, int nbpkts);
int fpn_sw_sched_dequeue(void *sw_port, struct mbuf **pkts, int nbpkts);

void fpn_sw_sched_dump_stats(void *sw_port, char *tok);
void fpn_sw_sched_reset_stats(void *sw_port, char *tok);
#endif
