/*
 * Copyright(c) 2010 6WIND
 */
#ifndef __FP_FPTUN_H__
#define __FP_FPTUN_H__

int fp_is_fptun_msg(struct mbuf *m);
int fp_fptun_input(struct mbuf *m);

#endif
