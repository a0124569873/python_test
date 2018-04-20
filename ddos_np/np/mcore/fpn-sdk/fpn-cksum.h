/*
 * Copyright(c) 2013  6WIND
 */

#ifndef __FPN_CKSUM_H__
#define __FPN_CKSUM_H__

#include <stdint.h>
#include "fpn-ip.h"

/**
 * @file
 *
 * Checksum computation API.
 */

/*
 * When accessing a unaligned 16-bit word, some CPUs trigger an exception.
 * On such CPUs, the access is done through a packed structure containing
 * a 16-bit word to make the compiler address alignment issues.
 */
#ifdef FPN_HAVE_UNALIGNED_ACCESS
	typedef struct s_uint16_unaligned {
		uint16_t val;
	} __attribute__((may_alias)) uint16_unaligned_t;
#else
	typedef struct s_uint16_unaligned {
		uint16_t val;
	} __attribute__((packed, may_alias)) uint16_unaligned_t;
#endif

/**
 * Data structures used to manage checksum computation.
 */
typedef	union fpn_cksum16 {
	uint16_t v16; /* The value of the 16-bit word */
	uint8_t  c8[2];
} __attribute__((packed)) fpn_cksum16_t;

#define FPN_SWAP_W16(cksum16)				\
	do {						\
		uint8_t tmp = (cksum16).c8[0];		\
		(cksum16).c8[0] = (cksum16).c8[1],	\
			(cksum16).c8[1] = tmp;		\
	} while (0)

typedef	union fpn_cksum32 {
	uint32_t      v32; /* The value of the 32-bit word */
	fpn_cksum16_t w16[2];
} __attribute__((packed)) fpn_cksum32_t;

#define FPN_CKSUM32_REDUCE(cksum32)				\
	cksum32.v32 = cksum32.w16[0].v16 + cksum32.w16[1].v16,	\
	cksum32.v32 = cksum32.w16[0].v16 + cksum32.w16[1].v16
	
#define FPN_CKSUM32_COMPLEMENT(cksum32)			\
	cksum32.v32 = ((~cksum32.v32) & 0xFFFF)

#define FPN_CKSUM32_REDUCE_AND_COMPLEMENT(cksum32)	\
	FPN_CKSUM32_REDUCE(cksum32),			\
	FPN_CKSUM32_COMPLEMENT(cksum32)

/**
 * Return the non-reduced pseudo-header checksum of a IPv4 header.
 * Assumes that IPv4 header fields are in network byte order.
 *
 * The IPv4 pseudo header includes the following fields of the IP header:
 *
 *   - IPv4 source address
 *   - IPv4 destination address
 *   - next (L4) protocol identifier
 *   - length of l4 segment = size of L4 header + size of data
 *
 * that must be grouped in the following packed data structure:
 *   struct fpn_ip_phdr {
 *      uint32_t ip_src;
 *      uint32_t ip_dst;
 *      uint16_t ip_len;
 *      uint8_t  zero;
 *      uint8_t  ip_p;
 *   }
 *
 * @param "ih"
 *   The address of the IPv4 header.
 * @return
 *   The non-reduced pseudo header checksum of the IPv4 header.
 */
static inline uint32_t
fpn_ip_phdr_cksum32(const struct fpn_ip_hdr *ih)
{
	const uint16_unaligned_t *ua16 = (uint16_unaligned_t *) ih;
	uint32_t sum;
	uint16_t l4_len;
	fpn_cksum16_t proto;

	/* Source IP address */
	ua16 = (uint16_unaligned_t *) &ih->ip_src;
	sum  = ua16[0].val;
	sum += ua16[1].val;
	/* Destination IP address */
	ua16 = (uint16_unaligned_t *) &ih->ip_dst;
	sum += ua16[0].val;
	sum += ua16[1].val;
	/* Next protocol identifier */
	proto.v16 = 0;
	proto.c8[1] = ih->ip_p;
	sum += proto.v16;
	/* Length of l4 segment (L4 header + data) */
	ua16 = (uint16_unaligned_t *) &ih->ip_len;
	l4_len = ua16->val;
	l4_len = ntohs(l4_len) - (ih->ip_hl << 2);
	l4_len = htons(l4_len);
	sum += l4_len;
	return sum;
}

/**
 * Return the pseudo header checksum of a IPv4 header.
 * Assumes that the IPv4 header is in network byte order.
 *
 * @param "iph"
 *   The address of the IPv4 header, viewed as a pseudo-header
 * @return
 *   The pseudo header checksum of the IPv4 header.
 */
static inline uint16_t
fpn_ip_phdr_cksum(const struct fpn_ip_hdr *ih)
{
	fpn_cksum32_t cksum;

	cksum.v32 = fpn_ip_phdr_cksum32(ih);
	FPN_CKSUM32_REDUCE_AND_COMPLEMENT(cksum);
	return (uint16_t) (cksum.v32);
}

/**
 * Return the checksum of a IPv4 header.
 * Assumes that all field in the IPv4 header are in network byte order.
 *
 * @param "ih"
 *   The address of the IPv4 header.
 * @param "len"
 *   The length in bytes of the IPv4 header.
 * @return
 *   The checksum of the IPv4 header.
 */
static inline uint16_t
fpn_ip_hdr_cksum(const void *ih, int len)
{
	const uint16_unaligned_t *ua16 = (uint16_unaligned_t *) ih;
	fpn_cksum32_t cksum;

	cksum.v32  = ua16[0].val + ua16[1].val + ua16[2].val + ua16[3].val;
	cksum.v32 += ua16[4].val;
	/* Skip ua16[5] = ih->ip_csum */
	cksum.v32 += ua16[6].val + ua16[7].val + ua16[8].val + ua16[9].val;

	/* Optimize the case of a standard IP header without options. */
	if (len != sizeof(struct fpn_ip_hdr)) {
		int count = len - sizeof(struct fpn_ip_hdr);
		ua16 = (uint16_unaligned_t *) ((char *)ih +
					       sizeof(struct fpn_ip_hdr));
               /*
		* By construction, the size of a IP header is a multiple of
		* 4 bytes, hence the length of extra IP options is also a
		* multiple of 4 bytes.
		*/
                do {
			cksum.v32 += (ua16++)->val;
                        cksum.v32 += (ua16++)->val;
			count -= 4;
		} while (count > 0);
	}

	FPN_CKSUM32_REDUCE_AND_COMPLEMENT(cksum);
	return (uint16_t) (cksum.v32);
}

/**
 * Check the checksum of a standard 20-byte IPv4 header.
 * Assumes that all field in the IPv4 header are in network byte order.
 *
 * @param "ih"
 *   The address of the standard IPv4 header.
 * @return
 *   - 0 if checksum is OK
 *   - a positive value if checksum is invalid
 */
static inline uint16_t
fpn_ip_hdr_noopt_cksum_check(const void *ih)
{
	uint16_unaligned_t *ua16 = (uint16_unaligned_t *) ih;
	fpn_cksum32_t cksum;

	cksum.v32  = ua16[0].val + ua16[1].val + ua16[2].val + ua16[3].val;
	cksum.v32 += ua16[4].val + ua16[5].val + ua16[6].val + ua16[7].val;
	cksum.v32 += ua16[8].val + ua16[9].val;

	FPN_CKSUM32_REDUCE_AND_COMPLEMENT(cksum);
	return (uint16_t) (cksum.v32);
}

/**
 * Compute the new checksum of a packet when only changing the value of a
 * byte that is included in that packet, using for this purpose:
 *     - the previous value of the checksum of the packet,
 *     - the previous value of the byte,
 *     - the new value of the byte,
 *     - the alignment (odd or even) of the location of the byte
 *       in the packet buffer.
 *
 * @param "prev_cksum"
 *   The previous value of the checksum.
 * @param "prev_val"
 *   The previous byte value
 * @param "new_val"
 *   The new byte value
 * @param "is_odd_aligned"
 *   The odd (1) or even (0) alignment of the location of the byte.
 * @return
 *   The checksum updated with the new value of the byte.
 */
static inline uint16_t
fpn_cksum_replace(uint16_t prev_cksum, uint8_t prev_val, uint8_t new_val,
		   int is_odd_aligned)
{
	fpn_cksum32_t cksum;
	fpn_cksum16_t p_val;
	fpn_cksum16_t n_val;

	p_val.v16 = ~((uint16_t)prev_val);
	n_val.v16 = new_val;
	if (is_odd_aligned) {
		FPN_SWAP_W16(p_val);
		FPN_SWAP_W16(n_val);
	}
	/* Avoid compiler promotion to "int" in ~prev_cksum expression below */
	cksum.v32 = (uint16_t)(~prev_cksum) + p_val.v16 + n_val.v16;

	FPN_CKSUM32_REDUCE_AND_COMPLEMENT(cksum);
	return (uint16_t) (cksum.v32);
}

/**
 * Compute the new checksum of a packet when only changing the value of a
 * 16-bit word that is included in that packet, using for this purpose:
 *     - the previous value of the checksum of the packet,
 *     - the previous value of the 16-bit word,
 *     - the new value of the 16-bit word,
 *     - the alignment (odd or even) of the location of the 16-bit word
 *       in the packet buffer.
 *
 * @param "prev_cksum"
 *   The previous value of the checksum.
 * @param "prev_val"
 *   The previous value in network byte order of the 16-bit word.
 * @param "new_val"
 *   The new value in network byte order of the 16-bit word.
 * @param "is_odd_aligned"
 *   The odd (1) or even (0) alignment of the location of the 16-bit word.
 * @return
 *   The checksum updated with the new value of the 16-bit word.
 */
static inline uint16_t
fpn_cksum_replace2(uint16_t prev_cksum, uint16_t prev_val, uint16_t new_val,
		   int is_odd_aligned)
{
	fpn_cksum32_t cksum;
	fpn_cksum16_t p_val;
	fpn_cksum16_t n_val;

	p_val.v16 = ~prev_val;
	n_val.v16 = new_val;
	if (is_odd_aligned) {
		FPN_SWAP_W16(p_val);
		FPN_SWAP_W16(n_val);
	}
	/* Avoid compiler promotion to "int" in ~prev_cksum expression below */
	cksum.v32 = (uint16_t)(~prev_cksum) + p_val.v16 + n_val.v16;

	FPN_CKSUM32_REDUCE_AND_COMPLEMENT(cksum);
	return (uint16_t) (cksum.v32);
}

/**
 * Compute the new checksum of a packet when only changing the value of a
 * 32-bit word that is included in that packet, using for this purpose:
 *     - the previous value of the checksum of the packet,
 *     - the previous value of the 32-bit word,
 *     - the new value of the 32-bit word,
 *     - the alignment (odd or even) of the location of the 32-bit word
 *       in the packet buffer.
 *
 * @param "prev_cksum"
 *   The previous value of the checksum.
 * @param "prev_val"
 *   The previous value in network byte order of the 32-bit word.
 * @param "new_val"
 *   The new value in network byte order of the 32-bit word.
 * @param "is_odd_aligned"
 *   The odd (1) or even (0) alignment of the location of the 32-bit word.
 * @return
 *   The checksum of the packet with the new value of the 32-bit word.
 */
static inline uint16_t
fpn_cksum_replace4(uint16_t prev_cksum, uint32_t prev_val, uint32_t new_val,
		   int is_odd_aligned)
{
	fpn_cksum32_t cksum;
	fpn_cksum32_t p_val;
	fpn_cksum32_t n_val;

	p_val.v32 = ~prev_val;
	n_val.v32 = new_val;
	if (is_odd_aligned) {
		/* swap 32-bit values as 2 16-bit words: ABCD -> BADC */
		FPN_SWAP_W16(p_val.w16[0]);
		FPN_SWAP_W16(p_val.w16[1]);
		FPN_SWAP_W16(n_val.w16[0]);
		FPN_SWAP_W16(n_val.w16[1]);
	}
	/* Avoid compiler promotion to "int" in ~prev_cksum expression below */
	cksum.v32 = ((uint16_t) ~prev_cksum) +
		p_val.w16[0].v16 + p_val.w16[1].v16 +
		n_val.w16[0].v16 + n_val.w16[1].v16;

	FPN_CKSUM32_REDUCE_AND_COMPLEMENT(cksum);
	return (uint16_t) (cksum.v32);
}

/**
 * Compute the raw checksum of a packet.
 *
 * @param "m"
 *   The address of the *mbuf* structure which contains the packet.
 * @param "off"
 *   The starting offset in the packet payload where to start the computation
 *   of the checksum.
 * @param "len"
 *   The number of bytes in the packet payload to use for the computation
 *   of the checksum.
 * @return
 *   The raw checksum of the packet.
 */
uint16_t fpn_raw_cksum(const struct mbuf *m, uint32_t off, uint32_t len);

/**
 * Compute the complemented checksum of the packet payload at a given offset.
 *
 * @param "m"
 *   The address of the *mbuf* structure which contains the packet.
 * @param "off"
 *   The starting offset in the packet where to start the computation
 *   of the checksum.
 * @return
 *   The complemented checksum of the packet payload.
 */
static inline uint16_t
fpn_cksum(const struct mbuf *m, uint32_t off)
{
	return (~ fpn_raw_cksum(m, off, m_len(m) - off));
}

/**
 * Compute the checksum of the L4 (TCP, UDP) payload of a packet,
 * including the checksum of the IP pseudo-header of the packet.
 *
 * Note: in case of a UDP packet, if the returned value is zero, it
 *       is the responsibility of the invoker to replace it by 0xFFFF.
 *
 * @param "m"
 *   The address of the *mbuf* structure which contains the packet.
 * @param "iph_off"
 *   The offset of the IPv4 header in the packet buffer.
 * @return
 *   The checksum of the L4 payload of the packet.
 */
uint16_t fpn_in4_l4cksum_at_offset(const struct mbuf *m, uint32_t iph_off);

/**
 * Compute the checksum of the L4 (TCP, UDP) payload of a packet,
 * including the checksum of the IP pseudo-header of the packet.
 * Assumes that the IPv4 header is at the beginning of the packet buffer.
 *
 * Note: in case of a UDP packet, if the returned value is zero, it
 *       is the responsibility of the invoker to replace it by 0xFFFF.
 *
 * @param "m"
 *   The address of the *mbuf* structure which contains the packet.
 * @return
 *   The checksum of the L4 payload of the packet.
 */
static inline uint16_t
fpn_in4_l4cksum(const struct mbuf *m)
{
	return fpn_in4_l4cksum_at_offset(m, 0);
}

/**
 * Compute the checksum of the L4 (TCP, UDP) payload of a packet
 * and stores it into the appropriate field of the packet L4 header.
 * Assumes that the L3 and L4 headers are in a contiguous memory buffer
 * at offset "iph_off" in the packet mbuf.
 *
 * @param "m"
 *   The address of the *mbuf* structure which contains the packet.
 * @param "iph_off"
 *   The offset of the IPv4 header in the packet buffer.
 */
void fpn_in4_l4cksum_set(struct mbuf *m, uint32_t iph_off);

#if defined(FPN_HAS_TX_CKSUM)
/**
 * Function called before encapsulating (tunnels, IPsec, etc.) a packet.
 * If the packet was flagged for having its l4 checksum to be computed
 * by the hardware when transmitting the packet, the flag is reset and
 * the computation of the L4 checksum is immediately done in software,
 * as the hardware might not be able to perform it.
 * Assumes that the L3 and L4 headers are in a contiguous memory buffer
 * at offset "iph_off" in the packet mbuf.
 *
 * @param "m"
 *   The address of the *mbuf* structure which contains the packet.
 * @param "iph_off"
 *   The offset of the IPv4 header in the packet buffer.
 */
static inline void
fpn_deferred_in4_l4cksum_set(struct mbuf *m, uint32_t iph_off)
{
	if (unlikely(m_get_tx_l4cksum(m))) {
		fpn_in4_l4cksum_set(m, iph_off);
		m_reset_tx_l4cksum(m);
	}
}
#endif

/**
 * Compute the checksum of the L4 (TCP, UDP) payload of a IPv6 packet
 * and stores it into the appropriate field of the L4 header.
 * Assumes that the IPv6 and the L4 headers are in a contiguous memory
 * buffer at offset "ip6h_off" of the packet mbuf.
 *
 * @param "m"
 *   The address of the *mbuf* structure which contains the packet.
 * @param "ih6_off"
 *   The offset of the IPv6 header in the packet buffer.
 */
uint16_t fpn_in6_l4cksum_at_offset(const struct mbuf *m, uint32_t ih6_off);

/**
 * Compute the checksum of the L4 (TCP, UDP) payload of a IPv6 packet
 * and stores it into the appropriate field of the L4 header.
 * Assumes that the IPv6 and the L4 headers are in a contiguous memory
 * buffer at the beginning of the packet mbuf.
 *
 * @param "m"
 *   The address of the *mbuf* structure which contains the packet.
 */
static inline uint16_t
fpn_in6_l4cksum(const struct mbuf *m)
{
	return fpn_in6_l4cksum_at_offset(m, 0);
}

#endif
