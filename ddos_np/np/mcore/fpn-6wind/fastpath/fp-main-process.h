/*
 * Copyright(c) 2006 6WIND
 */
#ifndef __FP_MAIN_PROCESS_H__
#define __FP_MAIN_PROCESS_H__

#include "fpn-hook.h"

/* input/output functions */
void fp_process_input(struct mbuf *m);
void fp_process_input_finish(struct mbuf *m, int result);

#ifdef CONFIG_MCORE_MULTIBLADE
int fp_direct_if_output(struct mbuf *m, fp_ifnet_t *ifp);
#endif
int fp_if_output(struct mbuf *m, struct fp_ifnet *ifp);
FPN_HOOK_DECLARE(fp_if_output)
int fp_fpib_forward(struct mbuf *m, uint8_t blade_id);
void fp_process_soft_input(struct mbuf *m);

int fp_ip_if_send(struct mbuf *m, fp_nh4_entry_t *nh, fp_ifnet_t *ifp);

#endif
