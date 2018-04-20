/*
 * Copyright 2014 6WIND S.A.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/attr.h>

#include "linux/openvswitch.h"
#include "fpvs-cp.h"

/* #define PARSE_FLOW_DEBUG 1 */

int fpvs_parse_nested_flow_key(struct nlattr *key_attr, struct cp_flow_key *key, int encap);

static struct nla_policy ovs_tunnel_key_attr_policy[OVS_TUNNEL_KEY_ATTR_MAX + 1] = {
	[OVS_TUNNEL_KEY_ATTR_ID] = { .type = NLA_U64 },
	[OVS_TUNNEL_KEY_ATTR_IPV4_SRC] = { .type = NLA_U32 },
	[OVS_TUNNEL_KEY_ATTR_IPV4_DST] = { .type = NLA_U32 },
	[OVS_TUNNEL_KEY_ATTR_TOS] = { .type = NLA_U8 },
	[OVS_TUNNEL_KEY_ATTR_TTL] = { .type = NLA_U8 },
	[OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT] = { .maxlen = 0 },
	[OVS_TUNNEL_KEY_ATTR_CSUM] = { .maxlen = 0 },
};

/* nla_parse in libnl skips attributes with value 0, so we have to
 * recode it here, to take OVS_TUNNEL_KEY_ATTR_ID into account
 * (OVS_TUNNEL_KEY_ATTR_ID=0).
 */
int fpvs_nla_parse(struct nlattr *tb[], int maxtype, struct nlattr *head, int len,
		   struct nla_policy *policy)
{
	struct nlattr *nla;
	int rem;

	memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));

	nla_for_each_attr(nla, head, len, rem) {
		int type = nla_type(nla);

		if (type > maxtype)
			continue;

		tb[type] = nla;
	}

	return 0;
}

int fpvs_nla_parse_nested(struct nlattr *tb[], int maxtype, struct nlattr *nla,
		     struct nla_policy *policy)
{
	return fpvs_nla_parse(tb, maxtype, nla_data(nla), nla_len(nla), policy);
}

/* parse a tunnel key nlattr to a flow key */
static int fpvs_parse_tunnel_key(struct nlattr *key_attr, struct cp_flow_key *key)
{
	struct nlattr *attrs[OVS_TUNNEL_KEY_ATTR_MAX + 1];
	int ret;

	ret = fpvs_nla_parse_nested(attrs, OVS_TUNNEL_KEY_ATTR_MAX, key_attr,
			       ovs_tunnel_key_attr_policy);
	if (ret < 0) {
		syslog(LOG_ERR, "unable to parse tunnel flow message: %s\n", nl_geterror(ret));
		return -1;
	}

	if (attrs[OVS_TUNNEL_KEY_ATTR_ID]) {
		key->tunnel.id = nla_get_u64(attrs[OVS_TUNNEL_KEY_ATTR_ID]);
		key->tunnel.flags |= FLOW_TNL_F_KEY;
	}

	if (attrs[OVS_TUNNEL_KEY_ATTR_IPV4_SRC])
		key->tunnel.src = nla_get_u32(attrs[OVS_TUNNEL_KEY_ATTR_IPV4_SRC]);

	if (attrs[OVS_TUNNEL_KEY_ATTR_IPV4_DST])
		key->tunnel.dst = nla_get_u32(attrs[OVS_TUNNEL_KEY_ATTR_IPV4_DST]);

	if (attrs[OVS_TUNNEL_KEY_ATTR_TOS])
		key->tunnel.tos = nla_get_u8(attrs[OVS_TUNNEL_KEY_ATTR_TOS]);

	if (attrs[OVS_TUNNEL_KEY_ATTR_TTL])
		key->tunnel.ttl = nla_get_u8(attrs[OVS_TUNNEL_KEY_ATTR_TTL]);

	if (attrs[OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT])
		key->tunnel.flags |= FLOW_TNL_F_DONT_FRAGMENT;

	if (attrs[OVS_TUNNEL_KEY_ATTR_CSUM])
		key->tunnel.flags |= FLOW_TNL_F_CSUM;

	return 0;
}

static struct nla_policy ovs_key_attr_policy[OVS_KEY_ATTR_MAX + 1] = {
	[OVS_KEY_ATTR_ENCAP] = { .type = NLA_NESTED },
	[OVS_KEY_ATTR_PRIORITY] = { .type = NLA_U32 },
	[OVS_KEY_ATTR_IN_PORT] = { .type = NLA_U32 },
	[OVS_KEY_ATTR_SKB_MARK] = { .type = NLA_U32 },
	[OVS_KEY_ATTR_ETHERNET] = { .maxlen = sizeof(struct ovs_key_ethernet) },
	[OVS_KEY_ATTR_VLAN] = { .type = NLA_U16 },
	[OVS_KEY_ATTR_ETHERTYPE] = { .type = NLA_U16 },
	[OVS_KEY_ATTR_IPV4] = { .maxlen = sizeof(struct ovs_key_ipv4) },
	[OVS_KEY_ATTR_IPV6] = { .maxlen = sizeof(struct ovs_key_ipv6) },
	[OVS_KEY_ATTR_TCP] = { .maxlen = sizeof(struct ovs_key_tcp) },
	[OVS_KEY_ATTR_TCP_FLAGS] = { .type = NLA_U16 },
	[OVS_KEY_ATTR_UDP] = { .maxlen = sizeof(struct ovs_key_udp) },
	[OVS_KEY_ATTR_SCTP] = { .maxlen = sizeof(struct ovs_key_sctp) },
	[OVS_KEY_ATTR_ICMP] = { .maxlen = sizeof(struct ovs_key_icmp) },
	[OVS_KEY_ATTR_ICMPV6] = { .maxlen = sizeof(struct ovs_key_icmpv6) },
	[OVS_KEY_ATTR_ARP] = { .maxlen = sizeof(struct ovs_key_arp) },
	[OVS_KEY_ATTR_ND] = { .maxlen = sizeof(struct ovs_key_nd) },
	[OVS_KEY_ATTR_DP_HASH] = { .type = NLA_U32 },
	[OVS_KEY_ATTR_RECIRC_ID] = { .type = NLA_U32 },
	[OVS_KEY_ATTR_TUNNEL] = { .type = NLA_NESTED },
	[OVS_KEY_ATTR_MPLS] = { .maxlen = sizeof(struct ovs_key_mpls) },
};

/* parse a key nlattr to a flow key */
int fpvs_parse_flow_key(struct nlattr *key_attr, size_t key_len, struct cp_flow_key *key, int encap)
{
	struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1];
	int ret;

	ret = nla_parse(attrs, OVS_KEY_ATTR_MAX, key_attr, key_len,
			ovs_key_attr_policy);
	if (ret < 0) {
		syslog(LOG_ERR, "unable to parse flow message: %s\n", nl_geterror(ret));
		return -1;
	}

	if (!encap)
		memset(key, 0, sizeof(*key));

	/* tunnel */
	if (attrs[OVS_KEY_ATTR_TUNNEL]) {
		ret = fpvs_parse_tunnel_key(attrs[OVS_KEY_ATTR_TUNNEL], key);
		if (ret < 0) {
			syslog(LOG_ERR, "unable to parse tunnel key: %s\n", nl_geterror(ret));
			return -1;
		}
	}

	if (attrs[OVS_KEY_ATTR_RECIRC_ID])
		key->recirc_id = nla_get_u32(attrs[OVS_KEY_ATTR_RECIRC_ID]);

	/* l1 */
	if (attrs[OVS_KEY_ATTR_IN_PORT])
		key->l1.ovsport = nla_get_u32(attrs[OVS_KEY_ATTR_IN_PORT]);

	/* l2 */
	if (attrs[OVS_KEY_ATTR_ETHERNET]) {
		struct ovs_key_ethernet *nlkey = nla_data(attrs[OVS_KEY_ATTR_ETHERNET]);

		memcpy(&key->l2.src, nlkey->eth_src, sizeof(key->l2.src));
		memcpy(&key->l2.dst, nlkey->eth_dst, sizeof(key->l2.dst));
	}

	if (attrs[OVS_KEY_ATTR_ETHERTYPE])
		key->l2.ether_type = nla_get_u16(attrs[OVS_KEY_ATTR_ETHERTYPE]);

	if (attrs[OVS_KEY_ATTR_VLAN])
		key->l2.vlan_tci = nla_get_u16(attrs[OVS_KEY_ATTR_VLAN]);

	/* l2_5 */
	if (attrs[OVS_KEY_ATTR_MPLS]) {
		struct ovs_key_mpls *nlkey = nla_data(attrs[OVS_KEY_ATTR_MPLS]);

		key->l2_5.mpls_lse = nlkey->mpls_lse;
	}

	/* l3 */
	if (attrs[OVS_KEY_ATTR_IPV4]) {
		struct ovs_key_ipv4 *nlkey = nla_data(attrs[OVS_KEY_ATTR_IPV4]);

		key->l3.ip.src = nlkey->ipv4_src;
		key->l3.ip.dst = nlkey->ipv4_dst;
		key->l3.proto = nlkey->ipv4_proto;
		key->l3.tos = nlkey->ipv4_tos;
		key->l3.ttl = nlkey->ipv4_ttl;
		key->l3.frag = nlkey->ipv4_frag;
	}

	if (attrs[OVS_KEY_ATTR_ARP]) {
		struct ovs_key_arp *nlkey = nla_data(attrs[OVS_KEY_ATTR_ARP]);

		key->l3.ip.src = nlkey->arp_sip;
		key->l3.ip.dst = nlkey->arp_tip;
		key->l3.proto = nlkey->arp_op;
		memcpy(&key->l3.ip.arp.sha, nlkey->arp_sha, sizeof(key->l3.ip.arp.sha));
		memcpy(&key->l3.ip.arp.tha, nlkey->arp_tha, sizeof(key->l3.ip.arp.tha));
	}

	if (attrs[OVS_KEY_ATTR_IPV6]) {
		struct ovs_key_ipv6 *nlkey = nla_data(attrs[OVS_KEY_ATTR_IPV6]);

		memcpy(&key->l3.ip6.src, &nlkey->ipv6_src, sizeof(key->l3.ip6.src));
		memcpy(&key->l3.ip6.dst, &nlkey->ipv6_dst, sizeof(key->l3.ip6.dst));
		key->l3.ip6.label = nlkey->ipv6_label;
		key->l3.proto = nlkey->ipv6_proto;
		key->l3.tos = nlkey->ipv6_tclass;
		key->l3.ttl = nlkey->ipv6_hlimit;
		key->l3.frag = nlkey->ipv6_frag;
	}

	if (attrs[OVS_KEY_ATTR_ND]) {
		struct ovs_key_nd *nlkey = nla_data(attrs[OVS_KEY_ATTR_ND]);

		memcpy(&key->l3.ip6.ndp.target, &nlkey->nd_target, sizeof(key->l3.ip6.ndp.target));
		memcpy(&key->l3.ip6.ndp.sll, nlkey->nd_sll, sizeof(key->l3.ip6.ndp.sll));
		memcpy(&key->l3.ip6.ndp.tll, nlkey->nd_tll, sizeof(key->l3.ip6.ndp.tll));
	}

	/* if (attrs[OVS_KEY_ATTR_TCP_FLAGS]) */
	/* 	key->l4.flags = nla_get_u16(attrs[OVS_KEY_ATTR_TCP_FLAGS]); */

	if (attrs[OVS_KEY_ATTR_TCP]) {
		struct ovs_key_tcp *nlkey = nla_data(attrs[OVS_KEY_ATTR_TCP]);

		key->l4.sport = nlkey->tcp_src;
		key->l4.dport = nlkey->tcp_dst;
	}

	if (attrs[OVS_KEY_ATTR_UDP]) {
		struct ovs_key_udp *nlkey = nla_data(attrs[OVS_KEY_ATTR_UDP]);

		key->l4.sport = nlkey->udp_src;
		key->l4.dport = nlkey->udp_dst;
	}

	if (attrs[OVS_KEY_ATTR_SCTP]) {
		struct ovs_key_sctp *nlkey = nla_data(attrs[OVS_KEY_ATTR_SCTP]);

		key->l4.sport = nlkey->sctp_src;
		key->l4.dport = nlkey->sctp_dst;
	}

	if (attrs[OVS_KEY_ATTR_ICMP]) {
		struct ovs_key_icmp *nlkey = nla_data(attrs[OVS_KEY_ATTR_ICMP]);

		key->l4.sport = htons(nlkey->icmp_type);
		key->l4.dport = htons(nlkey->icmp_code);
	}

	if (attrs[OVS_KEY_ATTR_ICMPV6]) {
		struct ovs_key_icmpv6 *nlkey = nla_data(attrs[OVS_KEY_ATTR_ICMPV6]);

		key->l4.sport = htons(nlkey->icmpv6_type);
		key->l4.dport = htons(nlkey->icmpv6_code);
	}

	/* Encap contains the attributes that are inside the vlan tag,
	 * and can have the same attributes as the ones in the key
	 * attribute.
	 */
	if (attrs[OVS_KEY_ATTR_ENCAP] && !encap)
		fpvs_parse_nested_flow_key(attrs[OVS_KEY_ATTR_ENCAP], key, 1);

#ifdef PARSE_FLOW_DEBUG
	/* ignored attributes */
	if (attrs[OVS_KEY_ATTR_PRIORITY] ||
	    attrs[OVS_KEY_ATTR_SKB_MARK])
		syslog(LOG_INFO, "[FPVS]: %s: ignored attribute\n", __func__);
#endif

	return 0;
}

int fpvs_parse_nested_flow_key(struct nlattr *key_attr, struct cp_flow_key *key, int encap)
{
	return fpvs_parse_flow_key(nla_data(key_attr), nla_len(key_attr), key, encap);
}
