/*
 * Copyright (c) 2013 6WIND
 */

#ifndef __FP_NF_NAT_H__
#define __FP_NF_NAT_H__

#include <fp-nfct.h>

int fp_nfct_nat_lookup(struct mbuf *m, int hook);
int fp_ddos_lookup(struct mbuf *m, int hook);
#endif
