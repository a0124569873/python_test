/*
 * Copyright(c) 2010 6WIND
 */
#ifndef __FP_IP_H__
#define __FP_IP_H__

#include "fpn-hook.h"

int fp_ip_input(struct mbuf *m);
FPN_HOOK_DECLARE(fp_ip_input)
int fp_ip_output(struct mbuf *m, fp_rt4_entry_t *rt, fp_nh4_entry_t *nh);
int fp_fast_ip_output(struct mbuf *m, fp_rt4_entry_t *rt, fp_nh4_entry_t *nh);
int fp_ip_inetif_send(struct mbuf *m, fp_ifnet_t *ifp);
FPN_HOOK_DECLARE(fp_ip_inetif_send)
int fp_ip_route_and_output(struct mbuf *m, int hlen);
#ifdef CONFIG_MCORE_RPF_IPV4
int fp_ip_rpf_check(struct mbuf *m);
#endif

static inline uint16_t fp_ip_get_id(void)
{
	return (uint16_t)fpn_get_local_cycles();
}

#endif
