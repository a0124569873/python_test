/*
 * Copyright (C) 2014 6WIND, All rights reserved.
 */
#ifndef _FPVS_VXLAN_H_
#define _FPVS_VXLAN_H_

#include "fp.h"
#include "fp-netfpc.h"
#include "fp-vxlan-var.h"

void fpvs_vxlan_output(struct mbuf *m, fp_vswitch_port_t *port,
		       const struct fp_flow_tnl *tun_key);
int fpvs_vxlan_input(struct mbuf *m, struct fp_vxlanhdr *vxh, uint8_t size,
		     uint32_t ovsport);

#endif /* _FPVS_VXLAN_H_ */
