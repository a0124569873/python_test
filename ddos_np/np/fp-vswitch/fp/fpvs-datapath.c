/*
 * Copyright (C) 2012 6WIND, All rights reserved.
 */
#include <sys/types.h>
#include <unistd.h>

#include "fp.h"
#include "fp-main-process.h"
#include "net/fp-ethernet.h"
#include "fp-packet.h"
#include "fp-ether.h"
#include "fp-log.h"
#include "fp-exceptions.h"
#include "netinet/fp-ip.h"
#include "netinet/fp-ip6.h"
#include "netinet/fp-udp.h"
#include "netinet/fp-tcp.h"
#include "fp-stats.h"
#include "fp-vswitch.h"
#include "fpvs-datapath.h"
#include "linux/openvswitch.h"
#include "fpn-shmem.h"
#include "fpn-cksum.h"
#include "fp-hlist.h"
#include "fp-netfpc.h"

#include "fpvs-flow.h"
#include "fpvs-flowops.h"
#include "fpvs-print.h"

#ifdef CONFIG_MCORE_VXLAN
#include "fpvs-vxlan.h"
#endif
#ifdef CONFIG_MCORE_GRE
#include "fpvs-gre.h"
#endif

#define FPVS_INC_STATS(field) FP_VSWITCH_STATS_INC(fpvs_shared->stats, field)

/* Output packet on a given OVS port ID. */
static void fpvs_output(struct mbuf* m, unsigned out_port, int dup_pkt,
			const struct fp_flow_tnl* tun_key)
{
	fp_vswitch_port_t *port = fpvs_get_port(out_port);
	fp_ifnet_t* ifp = NULL;
	int ret;
	size_t len = m_len(m);

	if (unlikely(dup_pkt)) {
		m = m_dup(m);
		if (unlikely(m == NULL)) {
			FPVS_INC_STATS(output_failed_no_mbuf);
			return;
		}
	}

	if (unlikely((port->type == OVS_VPORT_TYPE_NETDEV ||
		     port->type == OVS_VPORT_TYPE_INTERNAL) &&
		     (ifp = fpvs_get_ifnet(out_port)) == NULL)) {
		FPVS_INC_STATS(output_failed_no_ifp);
		m_freem(m);
		return;
	}

	switch (port->type) {
	case OVS_VPORT_TYPE_NETDEV:
		ret = fp_if_output(m, ifp);
		break;

	case OVS_VPORT_TYPE_INTERNAL:
		fp_exception_set_type(m, FPTUN_ETH_INPUT_EXCEPT);
		fp_change_ifnet_packet(m, ifp, 0, 0);
		ret = fp_ether_input(m, ifp);
		break;

#ifdef CONFIG_MCORE_VXLAN
	case OVS_VPORT_TYPE_VXLAN:
		/* FIXME: fpvs_vxlan_output() returns void and already calls
		 * fp_process_input_finish(). Assume success. */
		fpvs_vxlan_output(m, port, tun_key);
		ret = FP_DONE;
		break;
#endif

#ifdef CONFIG_MCORE_GRE
	case OVS_VPORT_TYPE_GRE:
		ret = fpvs_gre_output(m, port, tun_key);
		break;
#endif

	default:
		FPVS_INC_STATS(output_failed_unknown_type);
		m_freem(m);
		return;
	}

	if (likely(ret == FP_DROP)) {
		FPVS_INC_STATS(output_failed);
	} else {
		FP_VSWITCH_STATS_INC(port->stats, tx_pkts);
		FP_VSWITCH_STATS_ADD(port->stats, tx_bytes, len);
		FPVS_INC_STATS(output_ok);
	}

	return fp_process_input_finish(m, ret);
}

/* Overwrite source and destination MAC addresses. */
static void fpvs_packet_set_mac(struct fpvs_ofpbuf *packet,
				const struct ovs_key_ethernet *eth_key)
{
	struct fp_ether_header *eh = packet->l2;

	memcpy(eh->ether_shost, eth_key->eth_src, FP_ETHER_ADDR_LEN);
	memcpy(eh->ether_dhost, eth_key->eth_dst, FP_ETHER_ADDR_LEN);
}

static void fpvs_packet_set_mpls(struct fpvs_ofpbuf *packet,
				 const struct ovs_key_mpls *mpls_key)
{
	struct fp_mplshdr *mpls = packet->l2_5;

	mpls->lse = mpls_key->mpls_lse;
}

static void fpvs_packet_set_ipv4_addr(struct fpvs_ofpbuf *packet,
				      uint32_t *addr,
				      uint32_t new_addr)
{
	struct fp_ip *ip = packet->l3;
	uint32_t old_addr = *addr;

	if (ip->ip_p == FP_IPPROTO_TCP) {
		struct fp_tcphdr *th = packet->l4;

		th->th_sum = fpn_cksum_replace4(th->th_sum, old_addr, new_addr, 0);
	} else if (ip->ip_p == FP_IPPROTO_UDP) {
		struct fp_udphdr *uh = packet->l4;

		if (uh->uh_sum) {
			uh->uh_sum = fpn_cksum_replace4(uh->uh_sum, old_addr, new_addr, 0);
			if (!uh->uh_sum)
				uh->uh_sum = htons(0xffff);
		}
	}

	ip->ip_sum = fpn_cksum_replace4(ip->ip_sum, old_addr, new_addr, 0);
	*addr = new_addr;
}

static void fpvs_packet_set_ipv4(struct fpvs_ofpbuf *packet,
				 const struct ovs_key_ipv4 *ip_key)
{
	struct fp_ip *ip = packet->l3;

	if (ip->ip_src.s_addr != ip_key->ipv4_src)
		fpvs_packet_set_ipv4_addr(packet, &ip->ip_src.s_addr, ip_key->ipv4_src);

	if (ip->ip_dst.s_addr != ip_key->ipv4_dst)
		fpvs_packet_set_ipv4_addr(packet, &ip->ip_dst.s_addr, ip_key->ipv4_dst);

	if (ip->ip_tos != ip_key->ipv4_tos) {
		ip->ip_sum = fpn_cksum_replace(ip->ip_sum,
					       ip->ip_tos,
					       ip_key->ipv4_tos,
					       1);

		ip->ip_tos = ip_key->ipv4_tos;
	}

	if (ip->ip_ttl != ip_key->ipv4_ttl) {
		ip->ip_sum = fpn_cksum_replace(ip->ip_sum,
					       ip->ip_ttl,
					       ip_key->ipv4_ttl,
					       0);

		ip->ip_ttl = ip_key->ipv4_ttl;
	}
}

static void fpvs_packet_set_ipv6_addr(struct fpvs_ofpbuf *packet,
				      uint8_t proto,
				      uint32_t *addr,
				      uint32_t *new_addr)
{
	if (proto == FP_IPPROTO_TCP) {
		struct fp_tcphdr *th = packet->l4;
		uint16_t csum = th->th_sum;
		int i;

		for (i = 0; i < 4; i++)
			csum = fpn_cksum_replace4(csum, addr[i], new_addr[i], 0);

		th->th_sum = csum;
	} else if (proto == FP_IPPROTO_UDP) {
		struct fp_udphdr *uh = packet->l4;

		if (uh->uh_sum) {
			uint16_t csum = uh->uh_sum;
			int i;

			for (i = 0; i < 4; i++)
				csum = fpn_cksum_replace4(csum, addr[i], new_addr[i], 0);

			uh->uh_sum = csum;
			if (!uh->uh_sum)
				uh->uh_sum = htons(0xffff);
		}
	}

	memcpy(addr, new_addr, sizeof(uint32_t[4]));
}

static void fpvs_packet_set_ipv6(struct fpvs_ofpbuf *packet,
				 const struct ovs_key_ipv6 *ip_key)
{
	struct fp_ip6_hdr *ip6 = packet->l3;

	if (memcmp(ip6->ip6_src.fp_s6_addr32, ip_key->ipv6_src, sizeof(uint32_t[4])))
		fpvs_packet_set_ipv6_addr(packet, ip_key->ipv6_proto,
					  (uint32_t *)&ip6->ip6_src.fp_s6_addr32, (uint32_t *)ip_key->ipv6_src);

	if (memcmp(ip6->ip6_dst.fp_s6_addr32, ip_key->ipv6_dst, sizeof(uint32_t[4])))
		fpvs_packet_set_ipv6_addr(packet, ip_key->ipv6_proto,
					  (uint32_t *)&ip6->ip6_dst.fp_s6_addr32, (uint32_t *)ip_key->ipv6_dst);

	ip6->ip6_flow = (ip6->ip6_flow & htonl(0xf00fffff)) | htonl(ip_key->ipv6_tclass << 20);
	ip6->ip6_flow = (ip6->ip6_flow & htonl(~IPV6_LABEL_MASK)) | ip_key->ipv6_label;
	ip6->ip6_hlim = ip_key->ipv6_hlimit;
}

static void fpvs_packet_set_tcp_port(struct fpvs_ofpbuf *packet, uint16_t sport,
				     uint16_t dport)
{
	struct fp_tcphdr *th = packet->l4;

	th->th_sum = fpn_cksum_replace2(th->th_sum, th->th_sport, sport, 0);
	th->th_sum = fpn_cksum_replace2(th->th_sum, th->th_dport, dport, 0);

	th->th_sport = sport;
	th->th_dport = dport;
}

static void fpvs_packet_set_udp_port(struct fpvs_ofpbuf *packet, uint16_t sport,
				     uint16_t dport)
{
	struct fp_udphdr *uh = packet->l4;

	if (uh->uh_sum) {
		uh->uh_sum = fpn_cksum_replace2(uh->uh_sum, uh->uh_sport, sport, 0);
		uh->uh_sum = fpn_cksum_replace2(uh->uh_sum, uh->uh_dport, dport, 0);

		if (!uh->uh_sum)
			uh->uh_sum = htons(0xffff);
	}

	uh->uh_sport = sport;
	uh->uh_dport = dport;
}

/* Handle packet manipulation for SET actions. */
static void fpvs_execute_set_action(struct fpvs_ofpbuf *packet,
				    const struct nlattr *a,
				    struct fp_flow_tnl *tun_key)
{
	enum ovs_key_attr type = nl_attr_type(a);
	const struct ovs_key_mpls *mpls_key;
	const struct ovs_key_ipv4 *ipv4_key;
	const struct ovs_key_ipv6 *ipv6_key;
	const struct ovs_key_tcp *tcp_key;
	const struct ovs_key_udp *udp_key;

	switch (type) {
		case OVS_KEY_ATTR_PRIORITY:
			/* not implemented */
			FPVS_INC_STATS(set_priority);
			break;

		case OVS_KEY_ATTR_IPV6:
			FPVS_INC_STATS(set_ipv6);
			ipv6_key = nl_attr_get_unspec(a,
					sizeof(struct ovs_key_ipv6));
			fpvs_packet_set_ipv6(packet, ipv6_key);
			break;

		case OVS_KEY_ATTR_ETHERNET:
			FPVS_INC_STATS(set_ethernet);
			fpvs_packet_set_mac(packet,
					    nl_attr_get_unspec(a,
					    sizeof(struct ovs_key_ethernet)));
			break;

		case OVS_KEY_ATTR_MPLS:
			FPVS_INC_STATS(set_mpls);
			mpls_key = nl_attr_get_unspec(a,
					sizeof(struct ovs_key_mpls));
			fpvs_packet_set_mpls(packet, mpls_key);
			break;

		case OVS_KEY_ATTR_IPV4:
			FPVS_INC_STATS(set_ipv4);
			ipv4_key = nl_attr_get_unspec(a,
					sizeof(struct ovs_key_ipv4));
			fpvs_packet_set_ipv4(packet, ipv4_key);
			break;

		case OVS_KEY_ATTR_TCP:
			FPVS_INC_STATS(set_tcp);
			tcp_key = nl_attr_get_unspec(a,
					sizeof(struct ovs_key_tcp));
			fpvs_packet_set_tcp_port(packet, tcp_key->tcp_src,
						 tcp_key->tcp_dst);
			break;

		case OVS_KEY_ATTR_UDP:
			FPVS_INC_STATS(set_udp);
			udp_key = nl_attr_get_unspec(a,
					sizeof(struct ovs_key_udp));
			fpvs_packet_set_udp_port(packet, udp_key->udp_src,
						 udp_key->udp_dst);
			break;

		case OVS_KEY_ATTR_TUNNEL:
			FPVS_INC_STATS(set_tunnel_id);
			fpvs_ipv4_tun_from_nlattr(tun_key, a);
			break;

		case OVS_KEY_ATTR_SCTP:
		case OVS_KEY_ATTR_UNSPEC:
		case OVS_KEY_ATTR_ENCAP:
		case OVS_KEY_ATTR_ETHERTYPE:
		case OVS_KEY_ATTR_IN_PORT:
		case OVS_KEY_ATTR_VLAN:
		case OVS_KEY_ATTR_ICMP:
		case OVS_KEY_ATTR_ICMPV6:
		case OVS_KEY_ATTR_ARP:
		case OVS_KEY_ATTR_ND:
		case __OVS_KEY_ATTR_MAX:
		default:
			fpn_abort();
	}
}

struct fp_vlan_ether_hdr {
	uint8_t	ether_dhost[FP_ETHER_ADDR_LEN];
	uint8_t	ether_shost[FP_ETHER_ADDR_LEN];
	uint16_t vlan_type;
	uint16_t tci;
	uint16_t ether_type;
};

/* add vlan header */
static int fpvs_eth_push_vlan(struct fpvs_ofpbuf *packet, struct fp_flow_key *flow, uint16_t tci)
{
	struct mbuf *m = packet->private_p;
	struct fp_vlan_ether_hdr *vhdr;

	if (m_prepend(m, sizeof(struct fp_vlanhdr)) == NULL)
		return -1;

	packet->l2 = mtod(m, char *);
	vhdr = packet->l2;
	/* restore vhdr */
	memcpy(vhdr->ether_shost, flow->l2.src, FP_ETHER_ADDR_LEN);
	memcpy(vhdr->ether_dhost, flow->l2.dst, FP_ETHER_ADDR_LEN);
	vhdr->vlan_type = htons(FP_ETHERTYPE_VLAN);
	vhdr->tci = tci & htons(~VLAN_CFI);
	vhdr->ether_type = flow->l2.ether_type;

	return 0;
}

/* remove vlan header */
static int fpvs_eth_pop_vlan(struct fpvs_ofpbuf *packet, struct fp_flow_key *flow)
{
	struct mbuf *m = packet->private_p;
	struct fp_ether_header *eh;

	/* remove the vlan header size */
	if (m_adj(m, sizeof(struct fp_vlanhdr)) == NULL)
		return -1;

	packet->l2 = mtod(m, char *);
	eh = packet->l2;
	/* restore eh */
	memcpy(eh->ether_shost, flow->l2.src, FP_ETHER_ADDR_LEN);
	memcpy(eh->ether_dhost, flow->l2.dst, FP_ETHER_ADDR_LEN);
	eh->ether_type = flow->l2.ether_type;

	return 0;
}

/* add mpls header */
static int fpvs_eth_push_mpls(struct fpvs_ofpbuf *packet, struct fp_flow_key *flow,
			      uint32_t lse, uint16_t ether_type)
{
	struct mbuf *m = packet->private_p;
	struct fp_ether_header *eh;
	struct fp_mplshdr *mh;

	if (m_prepend(m, sizeof(struct fp_mplshdr)) == NULL)
		return -1;

	packet->l2 = mtod(m, char *);
	eh = packet->l2;
	/* restore eh */
	memcpy(eh->ether_shost, flow->l2.src, FP_ETHER_ADDR_LEN);
	memcpy(eh->ether_dhost, flow->l2.dst, FP_ETHER_ADDR_LEN);
	eh->ether_type = ether_type;
	mh = (struct fp_mplshdr *)(eh + 1);
	mh->lse = lse;

	return 0;
}

/* remove mpls header */
static int fpvs_eth_pop_mpls(struct fpvs_ofpbuf *packet, struct fp_flow_key *flow,
			     uint16_t ether_type)
{
	struct mbuf *m = packet->private_p;
	struct fp_ether_header *eh;

	/* remove the vlan header size */
	if (m_adj(m, sizeof(struct fp_mplshdr)) == NULL)
		return -1;

	packet->l2 = mtod(m, char *);
	eh = packet->l2;
	/* restore eh */
	memcpy(eh->ether_shost, flow->l2.src, FP_ETHER_ADDR_LEN);
	memcpy(eh->ether_dhost, flow->l2.dst, FP_ETHER_ADDR_LEN);
	eh->ether_type = ether_type;

	return 0;
}

/* Execute actions on a given packet for a given flow. */
static int fpvs_execute(struct fpvs_ofpbuf* packet, struct nlattr* actions,
			unsigned int actions_len, struct fp_flow_key* key)
{
	const struct nlattr *a;
	struct fp_flow_tnl tun_key;
	unsigned int left;
	int ret = FP_DONE;
	int dup = 0, except = 0;

	if (unlikely(!actions || actions_len == 0)) {
		FP_LOG(FP_LOG_DEBUG, VSWITCH,
		       "%s: actions=%p actions_len=%u => FP_DROP",
		       __func__, (void *)actions, actions_len);
		return FP_DROP;
	}
	NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
		int type = nl_attr_type(a);

		switch ((enum ovs_action_attr) type) {
			case OVS_ACTION_ATTR_OUTPUT:
				dup++;
				break;
			case OVS_ACTION_ATTR_USERSPACE:
				except++;
				break;
			default:
				break;
		}
	}
	if (except > 1) {
		/* This case should not happen */
		FP_LOG(FP_LOG_DEBUG, VSWITCH, "%s: except=%d => FP_DROP",
		       __func__, except);
		return FP_DROP;
	}

	NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
		const struct ovs_action_push_vlan *vlan;
		const struct ovs_action_push_mpls *mpls;
		int type = nl_attr_type(a);

		switch ((enum ovs_action_attr) type) {
			case OVS_ACTION_ATTR_OUTPUT:
				dup--;
				/*
				 * Always duplicate the packet if it must be
				 * sent as an exception in the end.
				 */
				fpvs_output(packet->private_p, nl_attr_get_u32(a),
					    except?1:dup, &tun_key);
				break;

			case OVS_ACTION_ATTR_USERSPACE:
				/*
				 * This will trigger an exception in the
				 * fastpath.
				 */
				FPVS_INC_STATS(userspace);
				ret = FP_NONE;
				break;

			case OVS_ACTION_ATTR_PUSH_VLAN:
				vlan = nl_attr_get(a);
				if (fpvs_eth_push_vlan(packet, key, vlan->vlan_tci) < 0) {
					ret = FP_NONE;
					break;
				}
				FPVS_INC_STATS(push_vlan);
				break;

			case OVS_ACTION_ATTR_POP_VLAN:
				if (fpvs_eth_pop_vlan(packet, key) < 0) {
					ret = FP_NONE;
					break;
				}
				FPVS_INC_STATS(pop_vlan);
				break;

			case OVS_ACTION_ATTR_PUSH_MPLS:
				mpls = nl_attr_get(a);
				if (fpvs_eth_push_mpls(packet, key, mpls->mpls_lse, mpls->mpls_ethertype) < 0) {
					ret = FP_NONE;
					break;
				}
				FPVS_INC_STATS(push_mpls);
				break;

			case OVS_ACTION_ATTR_POP_MPLS:
				if (fpvs_eth_pop_mpls(packet, key, nl_attr_get_u16(a)) < 0) {
					ret = FP_NONE;
					break;
				}
				FPVS_INC_STATS(pop_mpls);
				break;

			case OVS_ACTION_ATTR_SET:
				fpvs_execute_set_action(packet, nl_attr_get(a), &tun_key);
				break;

			case OVS_ACTION_ATTR_RECIRC:
				ret = fpvs_input((struct mbuf *)packet->private_p, key->l1.ovsport,
						 nl_attr_get_u32(a), NULL, NULL, 0);
				FPVS_INC_STATS(recirc);
				break;

			case OVS_ACTION_ATTR_SAMPLE:
				FPVS_INC_STATS(unsupported);
				break;

			case OVS_ACTION_ATTR_HASH:
			case OVS_ACTION_ATTR_UNSPEC:
			case __OVS_ACTION_ATTR_MAX:
				FPVS_INC_STATS(unsupported);
				break;
		}
	}
	return ret;
}

int fpvs_input(struct mbuf *m, uint32_t ovsport, uint32_t recirc_id, const struct fp_flow_tnl *tun_key,
	       const fpvs_tunnel_decap_t decap, size_t pkt_offset)
{
	struct fp_flow_key key __attribute__((aligned(FPVS_FLOW_ALIGNMENT)));
	struct fpvs_ofpbuf b;
	struct fpvs_flow *match;
	int ret;
	size_t len = m_len(m);
	fp_vswitch_port_t *port = fpvs_get_port(ovsport);

	FP_VSWITCH_STATS_INC(port->stats, rx_pkts);
	FP_VSWITCH_STATS_ADD(port->stats, rx_bytes, len);

	b.private_p = m;
	ret = fpvs_flow_extract(&b, 0, recirc_id, tun_key, ovsport, &key, pkt_offset);
	if (ret < 0)
		goto not_processed;

#ifdef CONFIG_MCORE_DEBUG
	{
		char buf[512];

		flow_key_to_str(&key, buf, sizeof(buf));
		FP_LOG(FP_LOG_DEBUG, VSWITCH, "%s: extracted flow: %s\n", __func__, buf);
	}
#endif

	/*
	 * The table by default is 0, because we can only manage one
	 * bridge. There should be another macro to obtain the table
	 * number according to the datapath ID to which the given ifnet
	 * is currently bound.
	 * This extension will be enabled when the cache manager for
	 * fp-vswitch will be extended to manage several datapath ID.
	 */
	match = fpvs_lookup_indexed_flow(0, &key);
	if (match) {
		/* Prevent the flow from being pruned. */
		match->age = 0;
		match->hit = 1;
		FPVS_FLOW_STATS_INC(match->stats, pkts);
		FPVS_FLOW_STATS_ADD(match->stats, bytes, len);

		if (decap && decap(m, pkt_offset) < 0) {
			ret = FP_DROP;
			goto not_processed;
		}

		ret = fpvs_execute(&b,
				   match->actions,
				   match->actions_len,
				   &key);

		if (ret == FP_DONE)
			return FP_DONE;
	} else
		FP_IP_STATS_INC(fpvs_shared->stats, flow_not_found);

not_processed:
	/* Decrease statistics, it was not processed by fast path */
	FP_VSWITCH_STATS_ADD(port->stats, rx_pkts, -1);
	FP_VSWITCH_STATS_ADD(port->stats, rx_bytes, -len);

	if (ret == FP_DROP)
		return ret;

	/* exception */
	if (tun_key)
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);

	return fp_prepare_exception(m, FPTUN_EXC_SP_FUNC);
}

/*
 * Exported function to be called by the datapath in lieu of
 * fp_ether_input().
 */
int fpvs_ether_input(struct mbuf *m, fp_ifnet_t *ifp, void *data)
{
	uint32_t ovsport = (uint32_t)(uintptr_t)data;
	return fpvs_input(m, ovsport, 0, NULL, NULL, 0);
}

int fpvs_if_output(struct mbuf *m, fp_ifnet_t *ifp, void *data)
{
	/* exception type is FPTUN_OUTPUT_EXCEPT */
	fp_change_ifnet_packet(m, ifp, 0, 0);
	return fpvs_ether_input(m, ifp, data);
}

int fpvs_ifchange(struct mbuf *m, struct fp_netfpc_ctx *ctx)
{
	uint32_t ovsport;
	struct netfpc_if_msg *if_msg;
	fp_vswitch_port_t *port;
	fp_ifnet_t *ifp, *old_ifp;

	if_msg = mtod(m, struct netfpc_if_msg *);
	ifp = fp_ifuid2ifnet(if_msg->ifuid);

	for (ovsport = 0; ovsport < FPVS_MAX_OVS_PORTS; ovsport++) {
		port = fpvs_get_port(ovsport);
		old_ifp = (fp_ifnet_t*) (fp_shared->ifnet.table + port->ifp_index);

		if (strcmp(port->ifp_name, ifp->if_name))
			continue;

		if (ctx->netfpc_type == NETFPC_MSGTYPE_NEWIF) {
			if (ifp == old_ifp)
				continue;
			port->ifp_index = (unsigned long)(ifp - fp_shared->ifnet.table);
			if (port->type == OVS_VPORT_TYPE_NETDEV) {
				fp_ifnet_ops_unregister(old_ifp, RX_DEV_OPS);
				if (fp_ifnet_ops_register(ifp, RX_DEV_OPS,
							fpvs_shared->mod_uid,
							(void *)(uintptr_t)ovsport)) {
					fp_log_common(FP_LOG_ERR, "%s: failed, %s rx_dev_ops is busy\n",
						      __func__, ifp->if_name);
					return 1;
				}
			}
			else if (port->type == OVS_VPORT_TYPE_INTERNAL) {
				fp_ifnet_ops_unregister(old_ifp, TX_DEV_OPS);
				if (fp_ifnet_ops_register(ifp, TX_DEV_OPS,
							fpvs_shared->mod_uid,
							(void *)(uintptr_t)ovsport)) {
					fp_log_common(FP_LOG_ERR, "%s: failed, %s tx_dev_ops is busy\n",
						      __func__, ifp->if_name);
					return 1;
				}
			}
		}
		return 0;
	}
	return 0;
}
