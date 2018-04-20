/*
 * Copyright(c) 2006, 2007 6WIND
 */
#ifndef __FPN_IPSEC_LOOKUP_H__
#define __FPN_IPSEC_LOOKUP_H__

void fp_trie_check_update(void *arg);

fp_sp_entry_t *spd_in_lookup(uint32_t src, uint32_t dst, uint8_t ul_proto,
		uint16_t sport, uint16_t dport, uint16_t vrfid, uint32_t *spd_index);

fp_sp_entry_t *spd_out_lookup(uint32_t src, uint32_t dst, uint8_t ul_proto,
		uint16_t sport, uint16_t dport, uint16_t vrfid);

fp_sa_entry_t *sad_in_lookup(uint32_t spi, uint32_t dst, uint8_t proto,
		uint16_t vrfid);

fp_sa_entry_t *sad_out_lookup(uint32_t src, uint32_t dst, uint16_t proto,
		uint8_t mode, uint32_t reqid, uint16_t vrfid, uint16_t xvrfid,
#if defined(CONFIG_MCORE_IPSEC_SVTI) && !defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
		uint32_t svti_ifuid,
#endif
		uint32_t *sa_index);

#ifdef CONFIG_MCORE_IPSEC_SVTI
fp_sp_entry_t *spd_svti_out_lookup(uint32_t src, uint32_t dst, uint8_t ul_proto,
		uint16_t sport, uint16_t dport, fp_svti_t *svti);

fp_sp_entry_t *spd_svti_in_lookup(uint32_t src, uint32_t dst, uint8_t ul_proto,
		uint16_t sport, uint16_t dport, fp_svti_t *svti, uint32_t *spd_index);
#endif

static inline int fp_ipsec_extract_ports(struct mbuf *m, struct fp_ip *ip,
		uint16_t *sport, uint16_t *dport)
{
	int notfrag = (ip->ip_off & ntohs(FP_IP_MF|FP_IP_OFFMASK)) == 0;
	/* if packet is not a fragment and protocol is TCP/UDP/SCTP,
	 * extract source and destination ports */
	if (likely(notfrag &&
				((ip->ip_p == FP_IPPROTO_TCP) ||
				 (ip->ip_p == FP_IPPROTO_UDP) ||
				 (ip->ip_p == FP_IPPROTO_SCTP))))
	{
		uint32_t off = (ip->ip_hl << 2); /* source port offset */

		if (likely(m_headlen(m) >= off + 4)) {
			*sport = *(uint16_t *)(mtod(m, uint8_t *) + off);
			*dport = *(uint16_t *)(mtod(m, uint8_t *) + off + 2);
		} else {
			uint16_t ports[2];
			if (m_copytobuf(ports, m, off, sizeof(ports)) < sizeof(ports))
				return FP_DROP;
			*sport = ports[0];
			*dport = ports[1];
		}
	}
	/* if packet is not a fragment and protocol is ICMP,
	 * extract ICMP type and code */
	else if (notfrag && (ip->ip_p == FP_IPPROTO_ICMP ||
		             ip->ip_p == FP_IPPROTO_ICMPV6)) {
		/* sport, dport in network order */
		uint32_t off = sizeof(struct fp_ip);
		if (likely(m_headlen(m) >= off + 2)) {
			uint8_t type, code;
			type = *(mtod(m, uint8_t *) + off);
			code = *(mtod(m, uint8_t *) + off + 1);
			*sport = htons((uint16_t)type);
			*dport = htons((uint16_t)code);
		} else {
			uint8_t typecode[2];
			if (m_copytobuf(typecode, m, off, sizeof(typecode)) < sizeof(typecode))
				return FP_DROP;
			*sport = htons((uint16_t)typecode[0]);
			*dport = htons((uint16_t)typecode[1]);
		}
	} else {
		*sport = 0;
		*dport = 0;
	}

	return FP_CONTINUE;
}

#endif /* __FPN_IPSEC_LOOKUP_H__ */
