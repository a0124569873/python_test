/*
 * Copyright (C) 2014 6WIND, All rights reserved.
 */

#include "fp.h"
#include "fp-main-process.h"
#include "net/fp-ethernet.h"
#include "fp-packet.h"
#include "fp-ether.h"
#include "fp-exceptions.h"
#include "fp-stats.h"
#include "fp-vswitch.h"
#include "linux/openvswitch.h"
#include "fpn-lock.h"
#include "fpn-shmem.h"
#include "fp-hlist.h"
#include "fp-netfpc.h"
#include "netinet/fp-udp.h"

#include "fpvs-datapath.h"
#include "fpvs-vxlan.h"

#define TUNNEL_KEY ((__be16)0x04)

void fpvs_vxlan_output(struct mbuf *m, fp_vswitch_port_t *port,
		       const struct fp_flow_tnl *tun_key)
{
	uint32_t ip_src, ip_dst, vni;
	uint16_t src_port, dst_port;
	uint8_t ttl, tos;
	struct fp_ip ip;

	ip_src = tun_key->src;
	ip_dst = tun_key->dst;
	vni = ntohl(tun_key->id >> 32);
	src_port = 0;
	dst_port = (uint16_t)(uintptr_t)(port->priv);
	ttl = tun_key->ttl;
	tos = tun_key->tos;

	memset(&ip, 0, sizeof(struct fp_ip));
	ip.ip_v = FP_IPVERSION;
	ip.ip_hl = 5;
	ip.ip_ttl = 255;
	ip.ip_dst.s_addr = ip_dst;

	fp_vxlan4_output_one(m, NULL, &ip, ip_src, ip_dst, 0, vni, src_port,
			     dst_port, ttl, tos);
}

static int fpvs_vxlan_decap(struct mbuf *m, size_t pkt_offset)
{
	if (unlikely(m_adj(m, pkt_offset) == NULL))
		return -1;

	return 0;
}

/* callback for vxlan input */
int fpvs_vxlan_input(struct mbuf *m, struct fp_vxlanhdr *vxh, uint8_t size,
		     uint32_t ovsport)
{
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	struct fp_flow_tnl tun_key;
	size_t pkt_offset =
		size + sizeof(struct fp_udphdr) + sizeof(struct fp_vxlanhdr);

	memset(&tun_key, 0, sizeof(struct fp_flow_tnl));
	tun_key.id = htonll(ntohl(vxh->vxh_vni) >> 8);
	tun_key.src = ip->ip_src.s_addr;
	tun_key.dst = ip->ip_dst.s_addr;
	tun_key.flags = FLOW_TNL_F_KEY;
	tun_key.tos = ip->ip_tos;
	tun_key.ttl = ip->ip_ttl;

	return fpvs_input(m, ovsport, 0, &tun_key, fpvs_vxlan_decap,
				pkt_offset);
}
