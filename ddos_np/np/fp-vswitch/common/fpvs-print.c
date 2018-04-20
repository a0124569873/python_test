#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdarg.h>

#include "fp.h"
#include "net/fp-ethernet.h"
#include "netinet/fp-in.h"
#include "netinet/fp-in6.h"
#include "fpvs-flowops.h"
#include "fpvs-netlink.h"

#include "linux/openvswitch.h"

#include "fpvs-cp.h"

#include "fpvs-print.h"

/* Similar to snprintf(), except that the returned value is always
 * positive and smaller than the size of the given buffer. Except if the
 * Therefore it can be used several times as below:
 *      n = safe_snprintf(buf, len, "foobar");
 *      buf += n;
 *      len -= n;
 */
static unsigned safe_snprintf(char *buf, size_t size, const char *format, ...)
{
        va_list ap;
        int ret;

        if (size == 0)
                return 0;
        if (size == 1) {
                buf[0] = '\0';
                return 0;
        }

        va_start(ap, format);
        ret = vsnprintf(buf, size, format, ap);
        va_end(ap);

        if (ret < 0) {
                buf[0] = '\0';
                return 0;
        }
        if ((size_t)ret >= size)
                return size - 1;

        return ret;
}

static size_t set_action_to_str(const struct nlattr *a, char *buf, size_t buflen)
{
	size_t len = 0;
	enum ovs_key_attr type = nl_attr_type(a);
	const struct ovs_key_ethernet *eth_key;
	const struct ovs_key_ipv4 *ipv4_key;
	const struct ovs_key_ipv6 *ipv6_key;
	const struct ovs_key_tcp *tcp_key;
	const struct ovs_key_udp *udp_key;
	const struct ovs_key_mpls *mpls_key;

	switch (type) {
	case OVS_KEY_ATTR_PRIORITY:
		len += safe_snprintf(buf + len, buflen - len, "priority");
		break;

	case OVS_KEY_ATTR_IPV6:
	{
		struct fp_in6_addr src;
		struct fp_in6_addr dst;

		ipv6_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv6));

		memcpy(&src, ipv6_key->ipv6_src, sizeof(src));
		memcpy(&dst, ipv6_key->ipv6_dst, sizeof(dst));

		len += safe_snprintf(buf + len, buflen - len,
				"ipv6(src="FP_NIP6_FMT",dst="FP_NIP6_FMT",label=%#"PRIx32
				",proto=%"PRIu8",tclass=%#"PRIx8",hlimit=%"PRIu8",frag=%"PRIu8")",
				FP_NIP6(src), FP_NIP6(dst), ntohl(ipv6_key->ipv6_label),
				ipv6_key->ipv6_proto, ipv6_key->ipv6_tclass,
				ipv6_key->ipv6_hlimit,
				ipv6_key->ipv6_frag);
		break;
	}

	case OVS_KEY_ATTR_ETHERNET:
		eth_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ethernet));
		len += safe_snprintf(buf + len, buflen - len, "eth(src="FP_NMAC_FMT", dst="FP_NMAC_FMT")",
				FP_NMAC(eth_key->eth_src), FP_NMAC(eth_key->eth_dst));
		break;

	case OVS_KEY_ATTR_IPV4:
		ipv4_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv4));
                len += safe_snprintf(buf + len, buflen - len,
				"ip(src="FP_NIPQUAD_FMT",dst="FP_NIPQUAD_FMT",proto=%"PRIu8
				",tos=%#"PRIx8",ttl=%"PRIu8",frag=%"PRIu8")",
				FP_NIPQUAD(ipv4_key->ipv4_src),
				FP_NIPQUAD(ipv4_key->ipv4_dst),
				ipv4_key->ipv4_proto, ipv4_key->ipv4_tos,
				ipv4_key->ipv4_ttl,
				ipv4_key->ipv4_frag);
		break;

	case OVS_KEY_ATTR_TCP:
		tcp_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_tcp));
                len += safe_snprintf(buf + len, buflen - len,
				"tcp(sport=%"PRIu16",dport=%"PRIu16")",
				ntohs(tcp_key->tcp_src),
				ntohs(tcp_key->tcp_dst));
		break;

	case OVS_KEY_ATTR_UDP:
		udp_key = nl_attr_get_unspec(a,	sizeof(struct ovs_key_udp));
                len += safe_snprintf(buf + len, buflen - len,
				"udp(sport=%"PRIu16",dport=%"PRIu16")",
				ntohs(udp_key->udp_src),
				ntohs(udp_key->udp_dst));
		break;

	case OVS_KEY_ATTR_TUNNEL:
	{
		struct fp_flow_tnl tun_key;

		memset(&tun_key, 0, sizeof(tun_key));
		fpvs_ipv4_tun_from_nlattr(&tun_key, a);

		len += safe_snprintf(buf + len, buflen - len, "tunnel(");
		len += safe_snprintf(buf + len, buflen - len, "tun_id=%"PRIu64",", ntohll(tun_key.id));
		len += safe_snprintf(buf + len, buflen - len, "ipv4(src="FP_NIPQUAD_FMT",dst="FP_NIPQUAD_FMT"),",
				FP_NIPQUAD(tun_key.src), FP_NIPQUAD(tun_key.dst));
		len += safe_snprintf(buf + len, buflen - len, "tos=%"PRIu8",", tun_key.tos);
		len += safe_snprintf(buf + len, buflen - len, "ttl=%"PRIu8")", tun_key.ttl);
		break;
	}

	case OVS_KEY_ATTR_MPLS:
		mpls_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_mpls));
#define MPLS_TTL_MASK       0x000000ff
#define MPLS_TTL_SHIFT      0
#define MPLS_BOS_MASK       0x00000100
#define MPLS_BOS_SHIFT      8
#define MPLS_TC_MASK        0x00000e00
#define MPLS_TC_SHIFT       9
#define MPLS_LABEL_MASK     0xfffff000
#define MPLS_LABEL_SHIFT    12
		len += safe_snprintf(buf + len, buflen - len, "mpls(label=%"PRIu32",tc=%d,ttl=%d,bos=%d)",
				     (ntohl(mpls_key->mpls_lse) & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT,
				     (ntohl(mpls_key->mpls_lse) & MPLS_TC_MASK) >> MPLS_TC_SHIFT,
				     (ntohl(mpls_key->mpls_lse) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT,
				     (ntohl(mpls_key->mpls_lse) & MPLS_BOS_MASK) >> MPLS_BOS_SHIFT);
		break;

	case OVS_KEY_ATTR_SCTP:
		len += safe_snprintf(buf + len, buflen - len, "sctp");
		break;

	case OVS_KEY_ATTR_UNSPEC:
		len += safe_snprintf(buf + len, buflen - len, "unspec");
		break;

	case OVS_KEY_ATTR_ENCAP:
		len += safe_snprintf(buf + len, buflen - len, "encap");
		break;

	case OVS_KEY_ATTR_ETHERTYPE:
		len += safe_snprintf(buf + len, buflen - len, "ethertype");
		break;

	case OVS_KEY_ATTR_IN_PORT:
		len += safe_snprintf(buf + len, buflen - len, "in_port");
		break;

	case OVS_KEY_ATTR_VLAN:
		len += safe_snprintf(buf + len, buflen - len, "vlan");
		break;

	case OVS_KEY_ATTR_ICMP:
		len += safe_snprintf(buf + len, buflen - len, "icmp");
		break;

	case OVS_KEY_ATTR_ICMPV6:
		len += safe_snprintf(buf + len, buflen - len, "icmpv6");
		break;

	case OVS_KEY_ATTR_ARP:
		len += safe_snprintf(buf + len, buflen - len, "arp");
		break;

	case OVS_KEY_ATTR_ND:
		len += safe_snprintf(buf + len, buflen - len, "ndp");
		break;

	case __OVS_KEY_ATTR_MAX:
	default:
		len += safe_snprintf(buf + len, buflen - len, "default: %d", type);
		break;
	}

	return len;
}

void actions_to_str(struct nlattr *actions, size_t actions_len, char *buf, size_t buflen)
{
	const struct nlattr *a;
	size_t len = 0;
	size_t left;


	len += safe_snprintf(buf + len, buflen - len, "actions(");

	NL_ATTR_FOR_EACH_UNSAFE(a, left, actions, actions_len) {
		const struct ovs_action_push_vlan *vlan;
		const struct ovs_action_push_mpls *mpls;
		int type = nl_attr_type(a);

		switch ((enum ovs_action_attr) type) {
		case OVS_ACTION_ATTR_OUTPUT:
			len += safe_snprintf(buf + len, buflen - len, "output:%"PRIu32",",
					nl_attr_get_u32(a));
			break;

		case OVS_ACTION_ATTR_USERSPACE:
			len += safe_snprintf(buf + len, buflen - len, "userspace,");
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			vlan = nl_attr_get(a);
			len += safe_snprintf(buf + len, buflen - len, "push_vlan(tpid=0x%04"PRIx16",tci=0x%04"PRIu16"),",
					ntohs(vlan->vlan_tpid), vlan->vlan_tci);
			break;

		case OVS_ACTION_ATTR_POP_VLAN:
			len += safe_snprintf(buf + len, buflen - len, "pop_vlan,");
			break;

		case OVS_ACTION_ATTR_SET:
			len += safe_snprintf(buf + len, buflen - len, "set(");
			len += set_action_to_str(nl_attr_get(a), buf + len, buflen - len);
			len += safe_snprintf(buf + len, buflen - len, "),");
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			len += safe_snprintf(buf + len, buflen - len, "sample,");
			break;

		case OVS_ACTION_ATTR_RECIRC:
			len += safe_snprintf(buf + len, buflen - len, "recirc:%"PRIu32",",
					     nl_attr_get_u32(a));
			break;

		case OVS_ACTION_ATTR_HASH:
			len += safe_snprintf(buf + len, buflen - len, "hash,");
			break;

		case OVS_ACTION_ATTR_PUSH_MPLS:
			mpls = nl_attr_get(a);
			len += safe_snprintf(buf + len, buflen - len, "push_mpls(label=%d,tc=%d,ttl=%d,bos=%d,eth_type(0x%04x)),",
					     (ntohl(mpls->mpls_lse) & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT,
					     (ntohl(mpls->mpls_lse) & MPLS_TC_MASK) >> MPLS_TC_SHIFT,
					     (ntohl(mpls->mpls_lse) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT,
					     (ntohl(mpls->mpls_lse) & MPLS_BOS_MASK) >> MPLS_BOS_SHIFT,
					     ntohs(mpls->mpls_ethertype));
			break;

		case OVS_ACTION_ATTR_POP_MPLS:
			len += safe_snprintf(buf + len, buflen - len, "pop_mpls(eth_type(%x%04x)),",
					     ntohs(nl_attr_get_u16(a)));
			break;

		case OVS_ACTION_ATTR_UNSPEC:
		default:
			len += safe_snprintf(buf + len, buflen - len, "#%d,", type);
			break;
		}
	}
	/* remove last space */
	len -= 1;
	len += safe_snprintf(buf + len, buflen - len, ")");
}

void mask_key_to_str(const struct fp_flow_key *mask, uint16_t ether_type, char *buf, size_t buflen)
{
	size_t len = 0;

	if (mask->tunnel.flags & FLOW_TNL_F_KEY) {
		len += safe_snprintf(buf + len, buflen - len, "tunnel(");
		len += safe_snprintf(buf + len, buflen - len, "id=%08x"PRIx64",", mask->tunnel.id);

		len += safe_snprintf(buf + len, buflen - len, "ipv4(src=%04"PRIx32",", mask->tunnel.src);
		len += safe_snprintf(buf + len, buflen - len, "dst=%04"PRIx32"),", mask->tunnel.dst);

		len += safe_snprintf(buf + len, buflen - len, "tos=%x,", mask->tunnel.tos);
		len += safe_snprintf(buf + len, buflen - len, "ttl=%x),", mask->tunnel.ttl);
	}
	len += safe_snprintf(buf + len, buflen - len, "recirc(%08"PRIx64"),", mask->recirc_id);

	len += safe_snprintf(buf + len, buflen - len, "in_port(%08"PRIx64"),", mask->l1.ovsport);

	len += safe_snprintf(buf + len, buflen - len, "eth(src="FP_NMAC_FMT",", FP_NMAC(mask->l2.src));
	len += safe_snprintf(buf + len, buflen - len, "dst="FP_NMAC_FMT"),", FP_NMAC(mask->l2.dst));
	len += safe_snprintf(buf + len, buflen - len, "eth_type(0x%04x),", mask->l2.ether_type);

	if (mask->l2.vlan_tci)
		len += safe_snprintf(buf + len, buflen - len, "vlan(id=%04x),", mask->l2.vlan_tci);

	if (ether_type == htons(FP_ETHERTYPE_MPLS)) {
		len += safe_snprintf(buf + len, buflen - len, "mpls(label=%"PRIu32",tc=%d,ttl=%d,bos=%d),",
				     (ntohl(mask->l2_5.mpls_lse) & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT,
				     (ntohl(mask->l2_5.mpls_lse) & MPLS_TC_MASK) >> MPLS_TC_SHIFT,
				     (ntohl(mask->l2_5.mpls_lse) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT,
				     (ntohl(mask->l2_5.mpls_lse) & MPLS_BOS_MASK) >> MPLS_BOS_SHIFT);
		return;
	} else if (ether_type == htons(FP_ETHERTYPE_ARP)) {
		len += safe_snprintf(buf + len, buflen - len, "arp(");
		len += safe_snprintf(buf + len, buflen - len, "src="FP_NIPQUAD_FMT",", FP_NIPQUAD(mask->l3.ip.src));
		len += safe_snprintf(buf + len, buflen - len, "dst="FP_NIPQUAD_FMT, FP_NIPQUAD(mask->l3.ip.dst));
		len += safe_snprintf(buf + len, buflen - len, "sha="FP_NMAC_FMT",", FP_NMAC(mask->l3.ip.arp.sha));
		len += safe_snprintf(buf + len, buflen - len, "tha="FP_NMAC_FMT"),", FP_NMAC(mask->l3.ip.arp.tha));
		return;
	} else if (ether_type == htons(FP_ETHERTYPE_IP)) {
		len += safe_snprintf(buf + len, buflen - len, "ipv4(");
		len += safe_snprintf(buf + len, buflen - len, "src="FP_NIPQUAD_FMT",", FP_NIPQUAD(mask->l3.ip.src));
		len += safe_snprintf(buf + len, buflen - len, "dst="FP_NIPQUAD_FMT, FP_NIPQUAD(mask->l3.ip.dst));
	} else if (ether_type == htons(FP_ETHERTYPE_IPV6)) {
		struct fp_in6_addr msrc;
		struct fp_in6_addr mdst;

		memcpy(&msrc, mask->l3.ip6.src, sizeof(msrc));
		memcpy(&mdst, mask->l3.ip6.dst, sizeof(mdst));

		len += safe_snprintf(buf + len, buflen - len, "ipv6(");
		len += safe_snprintf(buf + len, buflen - len, "src="FP_NIP6_FMT",", FP_NIP6(msrc));
		len += safe_snprintf(buf + len, buflen - len, "dst="FP_NIP6_FMT",", FP_NIP6(mdst));

		len += safe_snprintf(buf + len, buflen - len, "label=%08"PRIx32, mask->l3.ip6.label);
	} else {
		unsigned int i;

		len += safe_snprintf(buf + len, buflen - len, "l3(");
		len += safe_snprintf(buf + len, buflen - len, "value=");
		for (i = 0; i < sizeof(mask->l3.ip6); i++)
			len += safe_snprintf(buf + len, buflen - len, "%02x", *((char*)&mask->l3.ip6 + i));
	}

	len += safe_snprintf(buf + len, buflen - len, ",proto=%"PRIx8",", mask->l3.proto);
	len += safe_snprintf(buf + len, buflen - len, "tos=%"PRIx8",", mask->l3.tos);
	len += safe_snprintf(buf + len, buflen - len, "ttl=%"PRIx8",", mask->l3.ttl);
	len += safe_snprintf(buf + len, buflen - len, "frag=%"PRIx8"),", mask->l3.frag);

	len += safe_snprintf(buf + len, buflen - len, "l4(sport=%"PRIx16",", ntohs(mask->l4.sport));
	len += safe_snprintf(buf + len, buflen - len, "dport=%"PRIx16",", ntohs(mask->l4.dport));
	len += safe_snprintf(buf + len, buflen - len, "flags=%"PRIx16")", mask->l4.flags);
}

void flow_key_to_str(const struct fp_flow_key *key, char *buf, size_t buflen)
{
	size_t len = 0;

	if ((key->tunnel.flags & (FLOW_TNL_F_KEY | FLOW_TNL_F_CSUM)) ||
	    ((key->tunnel.id == 0) && (key->tunnel.flags == 0) && (key->tunnel.src != 0) && (key->tunnel.dst != 0))) {
		len += safe_snprintf(buf + len, buflen - len, "tunnel(");
		len += safe_snprintf(buf + len, buflen - len, "tun_id=%"PRIu64",", ntohll(key->tunnel.id));

		len += safe_snprintf(buf + len, buflen - len, "ipv4(src="FP_NIPQUAD_FMT",", FP_NIPQUAD(key->tunnel.src));
		len += safe_snprintf(buf + len, buflen - len, "dst="FP_NIPQUAD_FMT"),", FP_NIPQUAD(key->tunnel.dst));

		len += safe_snprintf(buf + len, buflen - len, "tos=%"PRIu8",", key->tunnel.tos);
		len += safe_snprintf(buf + len, buflen - len, "ttl=%"PRIu8"),", key->tunnel.ttl);
	}

	len += safe_snprintf(buf + len, buflen - len, "recirc(%"PRIu32"),", key->recirc_id);

	len += safe_snprintf(buf + len, buflen - len, "in_port(%"PRIu32"),", key->l1.ovsport);

	len += safe_snprintf(buf + len, buflen - len, "eth(src="FP_NMAC_FMT",", FP_NMAC(key->l2.src));
	len += safe_snprintf(buf + len, buflen - len, "dst="FP_NMAC_FMT"),", FP_NMAC(key->l2.dst));
	len += safe_snprintf(buf + len, buflen - len, "eth_type(0x%04x),", ntohs(key->l2.ether_type));

	if (key->l2.vlan_tci)
		len += safe_snprintf(buf + len, buflen - len, "vlan(id=%04x),", key->l2.vlan_tci);

	if (key->l2.ether_type == htons(FP_ETHERTYPE_MPLS)) {
		len += safe_snprintf(buf + len, buflen - len, "mpls(label=%"PRIu32",tc=%d,ttl=%d,bos=%d)",
				     (ntohl(key->l2_5.mpls_lse) & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT,
				     (ntohl(key->l2_5.mpls_lse) & MPLS_TC_MASK) >> MPLS_TC_SHIFT,
				     (ntohl(key->l2_5.mpls_lse) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT,
				     (ntohl(key->l2_5.mpls_lse) & MPLS_BOS_MASK) >> MPLS_BOS_SHIFT);
		return;
	} else if (key->l2.ether_type == htons(FP_ETHERTYPE_ARP)) {
		len += safe_snprintf(buf + len, buflen - len, "arp(");
		len += safe_snprintf(buf + len, buflen - len, "src="FP_NIPQUAD_FMT",", FP_NIPQUAD(key->l3.ip.src));
		len += safe_snprintf(buf + len, buflen - len, "dst="FP_NIPQUAD_FMT",", FP_NIPQUAD(key->l3.ip.dst));
		len += safe_snprintf(buf + len, buflen - len, "sha="FP_NMAC_FMT",", FP_NMAC(key->l3.ip.arp.sha));
		len += safe_snprintf(buf + len, buflen - len, "tha="FP_NMAC_FMT")", FP_NMAC(key->l3.ip.arp.tha));
		return;
	} else if (key->l2.ether_type == htons(FP_ETHERTYPE_IP)) {
		len += safe_snprintf(buf + len, buflen - len, "ipv4(");
		len += safe_snprintf(buf + len, buflen - len, "src="FP_NIPQUAD_FMT",", FP_NIPQUAD(key->l3.ip.src));
		len += safe_snprintf(buf + len, buflen - len, "dst="FP_NIPQUAD_FMT, FP_NIPQUAD(key->l3.ip.dst));
	} else if (key->l2.ether_type == htons(FP_ETHERTYPE_IPV6)) {
		struct fp_in6_addr src;
		struct fp_in6_addr dst;

		memcpy(&src, key->l3.ip6.src, sizeof(src));
		memcpy(&dst, key->l3.ip6.dst, sizeof(dst));

		len += safe_snprintf(buf + len, buflen - len, "ipv6(");
		len += safe_snprintf(buf + len, buflen - len, "src="FP_NIP6_FMT",", FP_NIP6(src));
		len += safe_snprintf(buf + len, buflen - len, "dst="FP_NIP6_FMT",", FP_NIP6(dst));

		len += safe_snprintf(buf + len, buflen - len, "label=%#"PRIx32, key->l3.ip6.label);
	} else {
		unsigned int i;

		len += safe_snprintf(buf + len, buflen - len, "l3(");
		len += safe_snprintf(buf + len, buflen - len, "value=");
		for (i = 0; i < sizeof(key->l3.ip6); i++)
			len += safe_snprintf(buf + len, buflen - len, "%02X", *((char*)&key->l3.ip6 + i));
	}

	len += safe_snprintf(buf + len, buflen - len, ",proto=%"PRIu8",", key->l3.proto);
	len += safe_snprintf(buf + len, buflen - len, "tos=%"PRIu8",", key->l3.tos);
	len += safe_snprintf(buf + len, buflen - len, "ttl=%"PRIu8",", key->l3.ttl);
	len += safe_snprintf(buf + len, buflen - len, "frag=%"PRIu8"),", key->l3.frag);

	len += safe_snprintf(buf + len, buflen - len, "l4(sport=%"PRIu16",", ntohs(key->l4.sport));
	len += safe_snprintf(buf + len, buflen - len, "dport=%"PRIu16",", ntohs(key->l4.dport));
	len += safe_snprintf(buf + len, buflen - len, "flags=%"PRIu16",)", key->l4.flags);
}
