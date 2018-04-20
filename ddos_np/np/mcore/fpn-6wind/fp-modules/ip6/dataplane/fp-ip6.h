/*
 * Copyright(c) 2010 6WIND
 */
#ifndef __FP_IP6_H__
#define __FP_IP6_H__

/* IPv6 input/output functions */
#ifdef CONFIG_MCORE_IPV6

#include "fpn-hook.h"

int fp_ip6_input(struct mbuf *m);
FPN_HOOK_DECLARE(fp_ip6_input)
int fp_ip6_output(struct mbuf *m, fp_rt6_entry_t *rt, fp_nh6_entry_t *nh);
int fp_ip6_inet6if_send(struct mbuf *m, fp_ifnet_t *ifp);
FPN_HOOK_DECLARE(fp_ip6_inet6if_send)
int fp_ip6_if_send(struct mbuf *m, fp_nh6_entry_t *nh, fp_ifnet_t *ifp);
#ifdef CONFIG_MCORE_SOCKET
int fp_ip6_route_and_output(struct mbuf *m, int hlen);
#endif
#ifdef CONFIG_MCORE_RPF_IPV6
int fp_ip6_rpf_check(struct mbuf *m);
#endif
#endif

#endif
