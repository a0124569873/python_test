/*
 * Copyright(c) 2008 6WIND, All rights reserved.
 */

#ifndef __FP_FLOW_INSPECTION_H__
#define __FP_FLOW_INSPECTION_H__

extern void fp_tap_init(void);
extern void fp_tap(struct mbuf *m, fp_ifnet_t *ifp, int proto);
extern void fp_prepare_tap_exception(struct mbuf *m, fp_ifnet_t *ifp,
				     int proto);

#endif /* __FP_FLOW_INSPECTION_H__ */
