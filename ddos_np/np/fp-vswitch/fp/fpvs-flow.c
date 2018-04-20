/*
 * Copyright (C) 2014 6WIND, All rights reserved.
 */

#include <sys/types.h>
#include <unistd.h>

#include "fp.h"
#include "fp-stats.h"
#include "fp-vswitch.h"
#include "fpvs-datapath.h"
#include "linux/openvswitch.h"
#include "net/fp-ethernet.h"
#include "netinet/fp-ip.h"
#include "netinet/fp-ip6.h"
#include "netinet/fp-udp.h"
#include "netinet/fp-sctp.h"
#include "netinet/fp-tcp.h"
#include "netinet/fp-icmp.h"
#include "netinet/fp-icmp6.h"
#include "fpvs-flow.h"
#include "fpvs-flowops.h"

#define FLOW_NW_FRAG_ANY   (1 << 0) /* Set for any IP frag. */
#define FLOW_NW_FRAG_LATER (1 << 1) /* Set for IP frag with nonzero offset. */

static void
parse_vlan(struct mbuf *m, struct fp_flow_key *flow, char *data, size_t *pkt_offset)
{
	struct fp_vlanhdr *vh;

	vh = (struct fp_vlanhdr *) (data + *pkt_offset);
	flow->l2.vlan_tci = vh->tci | htons(VLAN_CFI);

	*pkt_offset += sizeof(struct fp_vlanhdr);
}

static void
parse_ethertype(struct mbuf *m, struct fp_flow_key *flow, char *data, size_t *pkt_offset)
{
	uint16_t *ether_type;

	ether_type = (uint16_t *)(data + *pkt_offset);
	flow->l2.ether_type = *ether_type;

	*pkt_offset += sizeof(uint16_t);
}

static void
parse_mpls(struct mbuf *m, struct fp_flow_key *flow, char *data, size_t *pkt_offset)
{
	struct fp_mplshdr *mh;

	mh = (struct fp_mplshdr *)(data + *pkt_offset);
	flow->l2_5.mpls_lse = mh->lse;

	*pkt_offset += sizeof(uint32_t);
}

/* network layer */
static void
parse_ip(struct mbuf *m, struct fp_flow_key *flow, char *data, size_t *pkt_offset)
{
	struct fp_ip *ip;

	ip = (struct fp_ip *) (data + *pkt_offset);

	flow->l3.ip.src = ip->ip_src.s_addr;
	flow->l3.ip.dst = ip->ip_dst.s_addr;
	flow->l3.proto = ip->ip_p;

	flow->l3.tos = ip->ip_tos;
	if (ip->ip_off & htons(FP_IP_OFFMASK|FP_IP_MF)) {
		flow->l3.frag = FLOW_NW_FRAG_ANY;
		if (ip->ip_off & htons(FP_IP_OFFMASK)) {
			flow->l3.frag |= FLOW_NW_FRAG_LATER;
		}
	}
	flow->l3.ttl = ip->ip_ttl;

	*pkt_offset += sizeof(struct fp_ip);
}

static void
parse_ipv6(struct mbuf *m, struct fp_flow_key *flow, char *data, size_t *pkt_offset)
{
	struct fp_ip6_hdr *ip6;
	int nexthdr;
	unsigned headlen = m_headlen(m);

	ip6 = (struct fp_ip6_hdr *) (data + *pkt_offset);

	nexthdr = ip6->ip6_nxt;

	memcpy(&flow->l3.ip6.src, &ip6->ip6_src, sizeof(flow->l3.ip6.src));
	memcpy(&flow->l3.ip6.dst, &ip6->ip6_dst, sizeof(flow->l3.ip6.dst));

	flow->l3.tos = ntohl(ip6->ip6_flow) >> 20;
	flow->l3.ip6.label = ip6->ip6_flow & htonl(IPV6_LABEL_MASK);
	flow->l3.ttl = ip6->ip6_hlim;
	flow->l3.proto = FP_IPPROTO_NONE;

	*pkt_offset += sizeof(struct fp_ip6_hdr);
	/* next headers */
	while (1) {
		if ((nexthdr != FP_IPPROTO_HOPOPTS) &&
		    (nexthdr != FP_IPPROTO_ROUTING) &&
		    (nexthdr != FP_IPPROTO_DSTOPTS) &&
		    (nexthdr != FP_IPPROTO_AH) &&
		    (nexthdr != FP_IPPROTO_FRAGMENT))
			break;

		if ((nexthdr == FP_IPPROTO_HOPOPTS) ||
		    (nexthdr == FP_IPPROTO_ROUTING) ||
		    (nexthdr == FP_IPPROTO_DSTOPTS)) {
			/* These headers, while different, have the fields we care about
			 * in the same location and with the same interpretation. */
			struct fp_ip6_ext *ext_hdr;

			ext_hdr = (struct fp_ip6_ext *)(data + *pkt_offset);
			nexthdr = ext_hdr->ip6e_nxt;

			if (!ext_hdr->ip6e_len || (unsigned)fp_ipv6_optlen(ext_hdr) > headlen)
				break;

			*pkt_offset += fp_ipv6_optlen(ext_hdr);
		} else if (nexthdr == FP_IPPROTO_AH) {
			/* A standard AH definition isn't available, but the fields
			 * we care about are in the same location as the generic
			 * option header--only the header length is calculated
			 * differently. */
			struct fp_ip6_ext *ext_hdr;

			ext_hdr = (struct fp_ip6_ext *)(data + *pkt_offset);
			nexthdr = ext_hdr->ip6e_nxt;

			if (!ext_hdr->ip6e_len || (unsigned)(ext_hdr->ip6e_len + 2) * 4 > headlen)
				break;

			*pkt_offset += (ext_hdr->ip6e_len + 2) * 4;
		} else if (nexthdr == FP_IPPROTO_FRAGMENT) {
			struct fp_ip6_frag *frag_hdr;

			frag_hdr = (struct fp_ip6_frag *)(data + *pkt_offset);
			nexthdr = frag_hdr->ip6f_nxt;

			*pkt_offset += sizeof(struct fp_ip6_frag);

			/* We only process the first fragment. */
			if (frag_hdr->ip6f_offlg != htons(0)) {
				flow->l3.frag = FLOW_NW_FRAG_ANY;
				if ((frag_hdr->ip6f_offlg & FP_IP6F_OFF_MASK) != htons(0)) {
					flow->l3.frag |= FLOW_NW_FRAG_LATER;
					nexthdr = FP_IPPROTO_FRAGMENT;
					break;
				}
			}
		}
        }

	flow->l3.proto = nexthdr;
}


struct fp_arphdr {
#define FP_ARPHRD_ETHER	1
	uint16_t ar_hrd;		/* format of hardware address */

	uint16_t ar_pro;		/* format of protocol address */
	uint8_t ar_hln;		/* length of hardware address */
	uint8_t ar_pln;		/* length of protocol address */

#define	FP_ARPOP_REQUEST	1	/* request to resolve address */
#define	FP_ARPOP_REPLY		2	/* response to previous request */
#define	FP_ARPOP_REVREQUEST	3	/* request proto addr given hardware */
#define	FP_ARPOP_REVREPLY	4	/* response giving protocol address */
#define	FP_ARPOP_INVREQUEST	8	/* request to identify peer */
#define	FP_ARPOP_INVREPLY	9	/* response identifying peer */
	uint16_t ar_op;		/* ARP opcode (command) */
#define FP_ETHER_ADDR_LEN 6
	uint8_t ar_sha[FP_ETHER_ADDR_LEN];	/* sender hardware address */
	uint32_t ar_sip;		/* sender IP address */
	uint8_t ar_tha[FP_ETHER_ADDR_LEN];	/* target hardware address */
	uint32_t ar_tip;		/* target IP address */
};

static void
parse_arp(struct mbuf *m, struct fp_flow_key *flow, char *data, size_t *pkt_offset)
{
	struct fp_arphdr *arp;

	arp = (struct fp_arphdr *)(data + *pkt_offset);

	pkt_offset += sizeof(struct fp_arphdr);

	if (arp->ar_hrd == htons(FP_ARPHRD_ETHER) &&
	    arp->ar_pro == htons(FP_ETHERTYPE_IP) &&
	    arp->ar_hln == FP_ETHER_ADDR_LEN &&
	    arp->ar_pln == 4) {
		/* We only match on the lower 8 bits of the opcode. */
		if (ntohs(arp->ar_op) <= 0xff)
			flow->l3.proto = ntohs(arp->ar_op);
	}

	flow->l3.ip.src = arp->ar_sip;
	flow->l3.ip.dst = arp->ar_tip;
	memcpy(flow->l3.ip.arp.sha, arp->ar_sha, FP_ETHER_ADDR_LEN);
	memcpy(flow->l3.ip.arp.tha, arp->ar_tha, FP_ETHER_ADDR_LEN);
}

static void
parse_tcp(struct mbuf *m, struct fp_flow_key *flow, char *data, size_t *pkt_offset)
{
	struct fp_tcphdr *th;

	th = (struct fp_tcphdr *)(data + *pkt_offset);
	flow->l4.sport = th->th_sport;
	flow->l4.dport = th->th_dport;
	flow->l4.flags = th->th_flags & htons(0x0fff);

	*pkt_offset += sizeof(struct fp_tcphdr);
}

static void
parse_udp(struct mbuf *m, struct fp_flow_key *flow, char *data, size_t *pkt_offset)
{
	struct fp_udphdr *uh;

	uh = (struct fp_udphdr *)(data + *pkt_offset);
	flow->l4.sport = uh->uh_sport;
	flow->l4.dport = uh->uh_dport;

	*pkt_offset += sizeof(struct fp_udphdr);
}

static void
parse_sctp(struct mbuf *m, struct fp_flow_key *flow, char *data, size_t *pkt_offset)
{
	struct fp_sctphdr *sh;

	sh = (struct fp_sctphdr *)(data + *pkt_offset);
	flow->l4.sport = sh->src_port;
	flow->l4.dport = sh->dest_port;

	*pkt_offset += sizeof(struct fp_sctphdr);
}

static void
parse_icmp(struct mbuf *m, struct fp_flow_key *flow, char *data, size_t *pkt_offset)
{
	struct fp_icmphdr *ih;

	ih = (struct fp_icmphdr *)(data + *pkt_offset);
	flow->l4.sport = htons(ih->icmp_type);
	flow->l4.dport = htons(ih->icmp_code);

	*pkt_offset += sizeof(struct fp_icmphdr);
}

#define ND_NEIGHBOR_SOLICIT 135
#define ND_NEIGHBOR_ADVERT 136

#define ND_OPT_SOURCE_LINKADDR 1
#define ND_OPT_TARGET_LINKADDR 2

struct fp_nd_opt_hdr {             /* Neighbor discovery option header */
	u_int8_t        nd_opt_type;
	u_int8_t        nd_opt_len;
};

static inline int mac_is_zero(const uint8_t mac[6])
{
	return !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]);
}

static int
parse_icmp6(struct mbuf *m, struct fp_flow_key *flow, char *data, size_t *pkt_offset)
{
	struct fp_icmp6_hdr *ih;

	ih = (struct fp_icmp6_hdr *)(data + *pkt_offset);
	flow->l4.sport = htons(ih->icmp6_type);
	flow->l4.dport = htons(ih->icmp6_code);

	*pkt_offset += sizeof(struct fp_icmp6_hdr);

	if (ih->icmp6_code == 0 &&
	    (ih->icmp6_type == ND_NEIGHBOR_SOLICIT ||
	     ih->icmp6_type == ND_NEIGHBOR_ADVERT)) {
		struct fp_in6_addr *nd_target;
		unsigned headlen = m_headlen(m);

		nd_target = (struct fp_in6_addr *)(data + *pkt_offset);
		memcpy(&flow->l3.ip6.ndp.target, nd_target, sizeof(flow->l3.ip6.ndp.target));

		*pkt_offset += sizeof(struct fp_in6_addr);

		while (1) {
			struct fp_nd_opt_hdr *nd_opt;
			unsigned opt_len;

			nd_opt = (struct fp_nd_opt_hdr *)(data + *pkt_offset);
			opt_len = nd_opt->nd_opt_len * 8;

			*pkt_offset += opt_len;

			if (!opt_len || opt_len > headlen)
				goto invalid;

			if (nd_opt->nd_opt_type == ND_OPT_SOURCE_LINKADDR &&
			    opt_len == 8) {
				if (mac_is_zero(flow->l3.ip6.ndp.sll))
					memcpy(flow->l3.ip6.ndp.sll, nd_opt + 1, FP_ETHER_ADDR_LEN);
				else
					goto invalid;
			} else if (nd_opt->nd_opt_type == ND_OPT_TARGET_LINKADDR &&
				   opt_len == 8) {
				if (mac_is_zero(flow->l3.ip6.ndp.tll))
					memcpy(flow->l3.ip6.ndp.tll, nd_opt + 1, FP_ETHER_ADDR_LEN);
				else
					goto invalid;
			}
		}
	}

	return 0;

invalid:
	memset(&flow->l3.ip6.ndp.target, 0, sizeof(flow->l3.ip6.ndp.target));
	memset(flow->l3.ip6.ndp.sll, 0, sizeof(flow->l3.ip6.ndp.sll));
	memset(flow->l3.ip6.ndp.tll, 0, sizeof(flow->l3.ip6.ndp.tll));

	return -1;
}

/* Initializes 'flow' members from 'm', 'skb_priority', 'tun_id', and
 * 'ofp_in_port'.
 *
 * This function should do the same parsing as the one in
 * openvswitch/lib/flow.c flow_extract function.
 *
 */
#define OVS_MAX_PULLUP_SZ 128
int
fpvs_flow_extract(struct fpvs_ofpbuf *packet, uint32_t skb_priority, uint32_t recirc_id,
		  const struct fp_flow_tnl *tun_key, uint16_t ofp_in_port,
		  struct fp_flow_key *flow, size_t initial_pkt_offset)
{
	struct mbuf *m = packet->private_p;
	struct fp_ether_header *eh;
	size_t pullup_size = OVS_MAX_PULLUP_SZ + initial_pkt_offset;
	size_t pkt_len = m_len(m);
	size_t pkt_offset = 0;

	if (pkt_len < pullup_size)
		pullup_size = pkt_len;

	/* Pull up OVS_MAX_PULLUP_SZ, it must be enough. We will check
	 * at the end if it was. In most case, it will just check the
	 * length.
	 */
	if ((m = m_pullup(m, pullup_size)) == NULL) {
		FP_IP_STATS_INC(fpvs_shared->stats, flow_pullup_failed);
		return -1;
	}

	fpvs_flow_zero(flow);

	flow->recirc_id = recirc_id;

	flow->l1.ovsport = ofp_in_port;

	packet->l2 = mtod(m, char *) + initial_pkt_offset;
	packet->l2_5 = NULL;
	packet->l3 = NULL;
	packet->l4 = NULL;
	packet->l7 = NULL;

	if (tun_key)
		memcpy(&flow->tunnel, tun_key, sizeof(flow->tunnel));

	/* Link layer. */
	eh = (struct fp_ether_header *) (packet->l2);
	memcpy(flow->l2.src, eh->ether_shost, FP_ETHER_ADDR_LEN);
	memcpy(flow->l2.dst, eh->ether_dhost, FP_ETHER_ADDR_LEN);

	pkt_offset += 2 * FP_ETHER_ADDR_LEN;
	/* dl_type, vlan_tci. */
	if (eh->ether_type == htons(FP_ETHERTYPE_VLAN))
		parse_vlan(m, flow, packet->l2, &pkt_offset);

	parse_ethertype(m, flow, packet->l2, &pkt_offset);

	/* Network layer. */
	packet->l3 = packet->l2 + pkt_offset;
	switch (htons(flow->l2.ether_type)) {

	case FP_ETHERTYPE_MPLS:
		parse_mpls(m, flow, packet->l2, &pkt_offset);
		/* update 2.5 layer and network layer */
		packet->l2_5 = packet->l3;
		packet->l3 = packet->l2 + pkt_offset;
		break;

	case FP_ETHERTYPE_IP:
		parse_ip(m, flow, packet->l2, &pkt_offset);
		packet->l4 = packet->l2 + pkt_offset;

		if (flow->l3.frag)
			break;

		switch (flow->l3.proto) {
		case FP_IPPROTO_TCP:
			parse_tcp(m, flow, packet->l2, &pkt_offset);
			packet->l7 = packet->l2 + pkt_offset;
			break;

		case FP_IPPROTO_UDP:
			parse_udp(m, flow, packet->l2, &pkt_offset);
			packet->l7 = packet->l2 + pkt_offset;
			break;

		case FP_IPPROTO_SCTP:
			parse_sctp(m, flow, packet->l2, &pkt_offset);
			packet->l7 = packet->l2 + pkt_offset;
			break;

		case FP_IPPROTO_ICMP:
			parse_icmp(m, flow, packet->l2, &pkt_offset);
			packet->l7 = packet->l2 + pkt_offset;
			break;

		default:
			break;
		}
		break;

	case FP_ETHERTYPE_IPV6:
		parse_ipv6(m, flow, packet->l2, &pkt_offset);
		packet->l4 = packet->l2 + pkt_offset;

		if (flow->l3.frag)
			break;

		switch (flow->l3.proto) {
		case FP_IPPROTO_TCP:
			parse_tcp(m, flow, packet->l2, &pkt_offset);
			packet->l7 = packet->l2 + pkt_offset;
			break;

		case FP_IPPROTO_UDP:
			parse_udp(m, flow, packet->l2, &pkt_offset);
			packet->l7 = packet->l2 + pkt_offset;
			break;

		case FP_IPPROTO_SCTP:
			parse_sctp(m, flow, packet->l2, &pkt_offset);
			packet->l7 = packet->l2 + pkt_offset;
			break;

		case FP_IPPROTO_ICMPV6:
			parse_icmp6(m, flow, packet->l2, &pkt_offset);
			packet->l7 = packet->l2 + pkt_offset;
			break;

		default:
			break;
		}
		break;

	case FP_ETHERTYPE_ARP:
#define FP_ETHERTYPE_RARP  0x8035
	case FP_ETHERTYPE_RARP:
		parse_arp(m, flow, packet->l2, &pkt_offset);
		break;

	default:
		break;
	}

	/* check if we pulled up enough */
	if (pkt_offset > pullup_size ) {
		FP_IP_STATS_INC(fpvs_shared->stats, flow_pullup_too_small);
		return -1;
	}

	return 0;
}
