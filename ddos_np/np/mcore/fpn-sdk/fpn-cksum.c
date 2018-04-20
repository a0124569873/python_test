/*
 * Copyright(c) 2013  6WIND
 */

#include "fpn.h"
#include "fpn-cksum.h"
#include "fpn-in.h"
#include "fpn-ip.h"
#include "fpn-tcp.h"
#include "fpn-udp.h"
#include "fpn-ip6.h"

/**
 * Return the raw (non complemented) checksum of a contiguous buffer.
 *
 * @param "buf"
 *   The address of the contiguous buffer.
 * @param "len"
 *   The length of the contiguous buffer.
 * @return
 *   The raw checksum of the contiguous buffer.
 */
static uint16_t
fpn_raw_cksum_buf(const char *buf, uint32_t len)
{
	const uint16_t *w;
	fpn_cksum32_t cksum; /* Only used to reduce final checksum result */
	uint32_t sum; /* Accumulator that can be assigned a CPU register */
	fpn_cksum16_t odd16; /* For 1st byte of "buf" if at a odd address */
	int byte_swapped;

	w = (const uint16_t *)buf;
	odd16.v16 = 0;
	byte_swapped = 0;
	sum = 0;

	/*
	 * Force buffer address to start on a even boundary.
	 */
	if (1 & (long) w) {
		odd16.c8[0] = *(const uint8_t *)w;
		w = (const uint16_t *)((const int8_t *)w + 1);
		len--;
		byte_swapped = 1;
	}

	/*
	 * Unroll the loop to make overhead from branches &c small.
	 */
	while (len >= 32) {
		sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
		sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
		sum += w[8]; sum += w[9]; sum += w[10]; sum += w[11];
		sum += w[12]; sum += w[13]; sum += w[14]; sum += w[15];
		w += 16;
		len -= 32;
	}
	while (len >= 8) {
		sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
		w += 4;
		len -= 8;
	}
	while (len >= 2) {
		sum += *w++;
		len -= 2;
	}

	if (byte_swapped) {
		cksum.v32 = sum;
		FPN_CKSUM32_REDUCE(cksum);
		sum = (cksum.v32 <<= 8);
	}
	if (len == 1)
		odd16.c8[byte_swapped] = *(const uint8_t *)w;

	sum += odd16.v16;
	cksum.v32 = sum;
	FPN_CKSUM32_REDUCE(cksum);
	return (uint16_t) cksum.v32;
}

/**
 * Compute the raw (non complemented) checksum of a packet.
 *
 */
uint16_t
fpn_raw_cksum(const struct mbuf *m, uint32_t off, uint32_t len)
{
	const struct sbuf *s;
	const char *buf;
	fpn_cksum32_t cksum;
	uint32_t sum;
	uint32_t slen;
	uint32_t done;

	/*
	 * Search for the first buffer at offset "off" in the mbuf.
	 */
	slen = 0;
	M_FOREACH_SEGMENT(m, s) {
		slen = s_len(s);
		if (off < slen)
			break;
		off -= slen;
	}
	slen -= off;
	buf = s_data(s, const char *) + off;
	if (slen >= len) /* Green case: all the data is in a single buffer. */
		return fpn_raw_cksum_buf(buf, len);

	/*
	 * Loop adding the sum of all buffers that fit the requested length.
	 */
	cksum.v32 = 0;
	done = 0;
	for (;;) {
		sum = fpn_raw_cksum_buf(buf, slen);
		if (done & 1)
			sum = (sum >> 8) + ((sum & 0xff) << 8);
		cksum.v32 += sum;
		done += slen;
		if (done == len)
			break;
		s = s_next(m, s);
		buf = s_data(s, const char *);
		slen = s_len(s);
	}
	FPN_CKSUM32_REDUCE(cksum);
	return (uint16_t) cksum.v32;
}

/**
 * Compute the checksum of the L4 (TCP, UDP) payload of a IPv4 packet,
 * including the checksum of the IPv4 pseudo-header of the packet.
 * Note: in case of a UDP packet, if the returned value is zero, it is
 *       the responsibility of the invoker to replace it by 0xFFFF.
 */
uint16_t
fpn_in4_l4cksum_at_offset(const struct mbuf *m, uint32_t ih_off)
{
	struct fpn_ip_hdr *ih;
	fpn_cksum32_t cksum;
	uint32_t l3_len;
	uint32_t l4_len;

	ih = m_off(m, ih_off, struct fpn_ip_hdr *);
	cksum.v32 = fpn_ip_phdr_cksum32(ih);

	l3_len = ih->ip_hl << 2;
	l4_len = ntohs(ih->ip_len) - l3_len;
	cksum.v32 += fpn_raw_cksum(m, ih_off + l3_len, l4_len);

	FPN_CKSUM32_REDUCE_AND_COMPLEMENT(cksum);
	return (uint16_t) (cksum.v32);
}

/**
 * Compute the checksum of the L4 (TCP, UDP) payload of a IPv4 packet
 * and stores it into the appropriate field of the L4 header.
 * Assumes that the IPv4 and the L4 headers are in a contiguous memory
 * buffer at offset "iph_off" in the packet mbuf.
 */
void
fpn_in4_l4cksum_set(struct mbuf *m, uint32_t ih_off)
{
	struct fpn_ip_hdr  *ih;
	struct fpn_tcp_hdr *th;
	struct fpn_udp_hdr *uh;

	ih = m_off(m, ih_off, struct fpn_ip_hdr *);
	switch (ih->ip_p) {
	case FPN_IPPROTO_TCP:
		th = (struct fpn_tcp_hdr *) ((char *)ih + ih->ip_hl * 4);
		th->th_sum = fpn_in4_l4cksum_at_offset(m, ih_off);
		break;

	case FPN_IPPROTO_UDP:
		uh = (struct fpn_udp_hdr *) ((char *)ih + ih->ip_hl * 4);
		uh->uh_sum = fpn_in4_l4cksum_at_offset(m, ih_off);
		if (uh->uh_sum == 0)
			uh->uh_sum = 0xFFFF;
		break;

	default:
		break;
	}
}

/**
 * Compute the checksum of the L4 (TCP, UDP) payload of a IPv6 packet
 * and stores it into the appropriate field of the L4 header.
 * Assumes that the IPv6 and the L4 headers are in a contiguous memory
 * buffer at offset "ih6_off" in the packet mbuf.
 *
 * The IPv6 pseudo header checksum is the checksum computation of the
 * following data structure, as defined in section 8.1 of RFC 2460:
 *     struct ipv6_pseudo_header {
 *         uint32_t src_addr[4]; IPv6 Source Address
 *         uint32_t dst_addr[4]; IPv6 Destination Address
 *         uint32_t upper_len;   Upper-Layer Packet Length
 *         uint8_t  zero[3];     Zero Padding
 *         uint8_t  next_hdr;    Next Packet Protocol
 *     }
 */
uint16_t
fpn_in6_l4cksum_at_offset(const struct mbuf *m, uint32_t ih6_off)
{
	const struct fpn_ip6_hdr *ih6;
	const struct s_uint16_unaligned *ua16;
	fpn_cksum32_t cksum;
	fpn_cksum16_t next_p;
	uint32_t sum; /* Accumulator that can be assigned a CPU register */

	/* Compute IPv6 pseudo-header checksum */
	ih6 = m_off(m, ih6_off, const struct fpn_ip6_hdr *);

	ua16 = (const uint16_unaligned_t *) &ih6->ip6_src;
	sum = ua16[0].val;
	if (!FPN_IN6_IS_SCOPE_LINKLOCAL(&ih6->ip6_src))
		sum += ua16[1].val;
	sum += ua16[2].val; sum += ua16[3].val;
	sum += ua16[4].val; sum += ua16[5].val;
	sum += ua16[6].val; sum += ua16[7].val;

	ua16 = (const uint16_unaligned_t *)&ih6->ip6_dst;
	sum += ua16[0].val;
	if (!FPN_IN6_IS_SCOPE_LINKLOCAL(&ih6->ip6_dst))
		sum += ua16[1].val;
	sum += ua16[2].val; sum += ua16[3].val;
	sum += ua16[4].val; sum += ua16[5].val;
	sum += ua16[6].val; sum += ua16[7].val;

	ua16 = (const uint16_unaligned_t *) &ih6->ip6_plen;
	sum += ua16->val;

	next_p.v16 = 0;
	next_p.c8[1] = ih6->ip6_nxt;
	sum += next_p.v16;

	/* Upper protocol header and data */
	sum += fpn_raw_cksum(m, ih6_off + sizeof(struct fpn_ip6_hdr),
			     (uint32_t)(ntohs(ua16->val)));
	cksum.v32 = sum;
	FPN_CKSUM32_REDUCE_AND_COMPLEMENT(cksum);
	return (uint16_t) (cksum.v32);
}
