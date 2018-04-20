/*
 * Copyright(c) 2014 6WIND
 */

#ifndef __FPDEBUG_VSWITCH_H__
#define __FPDEBUG_VSWITCH_H__

#include "fpvs-netlink.h"
#include "fpvs-flowops.h"
#include "fpvs-cp.h"

#include "linux/openvswitch.h"

void actions_to_str(struct nlattr *actions, size_t actions_len, char *buf, size_t buflen);
void mask_key_to_str(const struct fp_flow_key *mask, uint16_t ether_type, char *buf, size_t buflen);
void flow_key_to_str(const struct fp_flow_key *key, char *buf, size_t buflen);

static const uint32_t fpvs_tunnel_key_lens[OVS_TUNNEL_KEY_ATTR_MAX + 1] = {
	[OVS_TUNNEL_KEY_ATTR_ID] = sizeof(uint64_t),
	[OVS_TUNNEL_KEY_ATTR_IPV4_SRC] = sizeof(uint32_t),
	[OVS_TUNNEL_KEY_ATTR_IPV4_DST] = sizeof(uint32_t),
	[OVS_TUNNEL_KEY_ATTR_TOS] = 1,
	[OVS_TUNNEL_KEY_ATTR_TTL] = 1,
	[OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT] = 0,
	[OVS_TUNNEL_KEY_ATTR_CSUM] = 0,
};

static inline int fpvs_ipv4_tun_from_nlattr(struct fp_flow_tnl *tun_key,
					    const struct nlattr *attr)
{
	const struct nlattr *a;
	int rem;
	int ttl = 0;

	memset(tun_key, 0, sizeof(struct fp_flow_tnl));
	tun_key->flags = 0;

	NL_NESTED_FOR_EACH(a, rem, attr) {
		int type = nl_attr_type(a);
		if (type > OVS_TUNNEL_KEY_ATTR_MAX)
			return -1;

		if (fpvs_tunnel_key_lens[type] != nl_attr_get_size(a))
			return -1;

		switch (type) {
		case OVS_TUNNEL_KEY_ATTR_ID:
			tun_key->id = nl_attr_get_u64(a);
			tun_key->flags |= FLOW_TNL_F_KEY;
			break;
		case OVS_TUNNEL_KEY_ATTR_IPV4_SRC:
			tun_key->src = nl_attr_get_u32(a);
			break;
		case OVS_TUNNEL_KEY_ATTR_IPV4_DST:
			tun_key->dst = nl_attr_get_u32(a);
			break;
		case OVS_TUNNEL_KEY_ATTR_TOS:
			tun_key->tos = nl_attr_get_u8(a);
			break;
		case OVS_TUNNEL_KEY_ATTR_TTL:
			tun_key->ttl = nl_attr_get_u8(a);
			ttl = 1;
			break;
		case OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT:
			tun_key->flags |= FLOW_TNL_F_DONT_FRAGMENT;
			break;
		case OVS_TUNNEL_KEY_ATTR_CSUM:
			tun_key->flags |= FLOW_TNL_F_CSUM;
			break;
		default:
			return -1;
		}
	}

	if (rem > 0)
		return -1;

	if (!tun_key->dst)
		return -1;

	if (!ttl)
		return -1;

	return 0;
}

#endif
