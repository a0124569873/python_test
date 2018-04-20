/*
 * Copyright(c) 2010 6WIND
 */
#ifndef __FP_ETHER_H__
#define __FP_ETHER_H__

#include "fpn-hook.h"
#include "net/fp-ethernet.h"

int fp_ether_input(struct mbuf *m, struct fp_ifnet *ifp);
FPN_HOOK_DECLARE(fp_ether_input)
int fp_ether_input_novnb(struct mbuf *m, struct fp_ifnet *ifp);

int fp_ether_output(struct mbuf *m, const struct fp_ether_header *eh, fp_ifnet_t *ifp);
FPN_HOOK_DECLARE(fp_ether_output)

static inline int fp_ethaddr_compare(const uint8_t *mac1, const uint8_t *mac2)
{
	const uint16_t *a = (const uint16_t *)mac1;
	const uint16_t *b = (const uint16_t *)mac2;

	return (a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]);
}

static inline int fp_ethaddr_is_zero(const uint8_t *addr)
{
	return (*(const uint16_t *)(addr + 0) |
		*(const uint16_t *)(addr + 2) |
		*(const uint16_t *)(addr + 4)) == 0;
}

static inline int fp_ethaddr_is_multicast(const uint8_t *addr)
{
	return 0x01 & addr[0];
}

static inline int fp_ethaddr_is_broadcast(const uint8_t *addr)
{
	return (*(const uint16_t *)(addr + 0) &
		*(const uint16_t *)(addr + 2) &
		*(const uint16_t *)(addr + 4)) == 0xffff;
}

/* Check that the Ethernet address (MAC) is not 00:00:00:00:00:00, is not
 * a multicast address, and is not FF:FF:FF:FF:FF:FF.
 */
static inline int fp_ethaddr_is_valid_src(const uint8_t *addr)
{
	return !fp_ethaddr_is_multicast(addr) &&
	       !fp_ethaddr_is_zero(addr);
}

/* Return true if address is link local reserved addr (01:80:c2:00:00:0X) per
 * IEEE 802.1Q 8.6.3 Frame filtering.
 * Note: addr must be aligned to uint16_t.
 */
extern const uint8_t fp_ether_reserved_addr_base[FP_ETHER_ADDR_LEN];
static inline int fp_ethaddr_is_link_local(const uint8_t *addr)
{
	uint16_t *a = (uint16_t *)addr;
	const uint16_t m = htons(0xfff0);
	static const uint16_t *b = (const uint16_t *)fp_ether_reserved_addr_base;

	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | ((a[2] ^ b[2]) & m)) == 0;
}

#endif
