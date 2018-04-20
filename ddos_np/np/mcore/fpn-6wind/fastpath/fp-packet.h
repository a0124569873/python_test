/*
 *  * Copyright(c) 2006 6WIND
 *   */
#ifndef __FP_PACKET_H__
#define __FP_PACKET_H__

void fp_change_ifnet_packet(struct mbuf *m, fp_ifnet_t *ifp, int incstats, int do_tap);

#endif /* __FP_PACKET_H__ */
