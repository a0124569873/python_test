/*
 * Copyright(c) 2008 6WIND
 */

#ifndef   __FP_TUNNELS_H_
#define   __FP_TUNNELS_H_

#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
#define  FP_IP6_6TO4_ADDR    0x2002
#else
#define  FP_IP6_6TO4_ADDR    0x0220
#endif

#ifdef CONFIG_MCORE_XIN4
int fp_xin4_input(struct mbuf *m, struct fp_ip *ip);
int fp_xin4_output(struct mbuf *m, fp_ifnet_t *ifp, uint8_t proto);
#endif

#ifdef CONFIG_MCORE_XIN6
int fp_xin6_input(struct mbuf *m, struct fp_ip6_hdr *ip6);
int fp_xin6_output(struct mbuf *m, fp_ifnet_t *ifp, uint8_t proto);
#endif

#endif /* __FP_TUNNELS_H_ */
