/*
 * Copyright (C) 2014 6WIND, All rights reserved.
 */
#ifndef _FPVS_FLOW_H_
#define _FPVS_FLOW_H_

struct fp_vlanhdr {
	uint16_t ether_type;
	uint16_t tci;
};

struct fp_mplshdr {
	uint32_t lse;
};

#define IPV6_LABEL_MASK 0x000fffff

#define VLAN_CFI 0x1000

int
fpvs_flow_extract(struct fpvs_ofpbuf *packet, uint32_t skb_priority, uint32_t recirc_id,
		  const struct fp_flow_tnl *tun_key, uint16_t ofp_in_port,
		  struct fp_flow_key *flow, size_t pkt_offset);

#endif /* _FPVS_FLOW_H */
