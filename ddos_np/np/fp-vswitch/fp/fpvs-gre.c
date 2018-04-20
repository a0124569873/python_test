/*
 * Copyright (C) 2014 6WIND, All rights reserved.
 */

#include "fp.h"
#include "fp-main-process.h"
#include "net/fp-ethernet.h"
#include "fp-packet.h"
#include "fp-ether.h"
#include "fp-exceptions.h"
#include "fp-mbuf-priv.h"
#include "fp-stats.h"
#include "fp-vswitch.h"
#include "linux/openvswitch.h"
#include "fpn-lock.h"
#include "fpn-shmem.h"
#include "fp-hlist.h"
#include "fp-netfpc.h"
#include "netinet/fp-udp.h"
#include "fpn.h"

#include "fpvs-datapath.h"
#include "fpvs-gre.h"

int fpvs_gre_output(struct mbuf *m, fp_vswitch_port_t *port,
		       const struct fp_flow_tnl *tun_key)
{
	uint32_t ip_src, ip_dst, key;
	uint16_t flags = 0;
	uint8_t ttl, tos;

	ip_src = tun_key->src;
	ip_dst = tun_key->dst;
	ttl = tun_key->ttl;
	tos = tun_key->tos;

	/* keep keys in network format as netlink treatment */
#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
	key = ntohl((uint32_t)(tun_key->id));
#else
	key = (uint32_t)(tun_key->id >> 32);
#endif
	if (tun_key->flags & FLOW_TNL_F_KEY)
		flags |= FP_GRE_FLAG_KEY;
	if (tun_key->flags & FLOW_TNL_F_CSUM)
		flags |= FP_GRE_FLAG_CSUM;

	return fp_gretap_fpvs_output(m, ip_src, ip_dst, ttl, tos, key, flags);
}

static int fpvs_gre_decap(struct mbuf *m, size_t pkt_offset)
{
	if (unlikely(m_adj(m, pkt_offset) == NULL))
		return -1;

	m_priv(m)->exc_type = FPTUN_ETH_INPUT_EXCEPT;
	m_priv(m)->exc_class = 0;
	m_priv(m)->exc_proto = 0;
	fp_reset_hw_flags(m); /* No known HW able to do HW Checksum here */

	return 0;
}


/* callback for gre input */
int fpvs_gre_input(struct mbuf *m, uint8_t size, uint32_t ovsport,
		   uint16_t flags, uint32_t key)
{
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	struct fp_flow_tnl tun_key;
	size_t pkt_offset = size;

	memset(&tun_key, 0, sizeof(struct fp_flow_tnl));
	tun_key.src = ip->ip_src.s_addr;
	tun_key.dst = ip->ip_dst.s_addr;
	tun_key.flags = 0;
	tun_key.id = 0;
	if (flags & FP_GRE_FLAG_KEY) {
		tun_key.flags |= FLOW_TNL_F_KEY;
#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
		tun_key.id = htonll(((uint64_t) ntohl(key)) << 32);
#else
		tun_key.id = htonll(ntohl(key));
#endif
	}
	if (flags & FP_GRE_FLAG_CSUM)
		tun_key.flags |= FLOW_TNL_F_CSUM;

	tun_key.tos = ip->ip_tos;
	tun_key.ttl = ip->ip_ttl;

	return fpvs_input(m, ovsport, 0, &tun_key, fpvs_gre_decap, pkt_offset);
}
