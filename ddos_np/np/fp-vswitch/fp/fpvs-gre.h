/*
 * Copyright (C) 2014 6WIND, All rights reserved.
 */
#ifndef _FPVS_GRE_H_
#define _FPVS_GRE_H_

#include "fp.h"
#include "fp-netfpc.h"
#include "fp-gre-var.h"

int fpvs_gre_output(struct mbuf *m, fp_vswitch_port_t *port,
		       const struct fp_flow_tnl *tun_key);
int fpvs_gre_input(struct mbuf *m, uint8_t size, uint32_t ovsport,
		   uint16_t flags, uint32_t key);

#endif /* _FPVS_GRE_H_ */
