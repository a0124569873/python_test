/*
 * Copyright 2014 6WIND S.A.
 */

#ifndef _VNB_ETHER_H_
#define _VNB_ETHER_H_

#if !defined(__FastPath__)
#ifndef VNB_ETHER_ADDR_LEN
#define VNB_ETHER_ADDR_LEN       ETH_ALEN
#endif
#ifndef VNB_ETHER_HDR_LEN
#define VNB_ETHER_HDR_LEN        ETH_HLEN
#endif
#ifndef VNB_ETHER_MAX_LEN
#define VNB_ETHER_MAX_LEN        1518
#endif

#ifndef VNB_ETHERTYPE_IP
#define VNB_ETHERTYPE_IP         ETH_P_IP
#endif
#ifndef VNB_ETHERTYPE_VLAN
#define VNB_ETHERTYPE_VLAN       ETH_P_8021Q
#endif
#ifndef VNB_ETHERTYPE_IPV6
#define VNB_ETHERTYPE_IPV6       ETH_P_IPV6
#endif
#ifndef VNB_ETHERTYPE_SLOW
#define VNB_ETHERTYPE_SLOW       ETH_P_SLOW
#endif

#else

#ifndef VNB_ETHER_ADDR_LEN
#define VNB_ETHER_ADDR_LEN       FP_ETHER_ADDR_LEN
#endif
#ifndef VNB_ETHER_TYPE_LEN
#define VNB_ETHER_TYPE_LEN       FP_ETHER_TYPE_LEN
#endif
#ifndef VNB_ETHER_CRC_LEN
#define VNB_ETHER_CRC_LEN        FP_ETHER_CRC_LEN
#endif
#ifndef VNB_ETHER_HDR_LEN
#define VNB_ETHER_HDR_LEN        FP_ETHER_HDR_LEN
#endif
#ifndef VNB_ETHER_MAX_LEN
#define VNB_ETHER_MAX_LEN        FP_ETHER_MAX_LEN
#endif

#ifndef VNB_ETHERTYPE_PUP
#define VNB_ETHERTYPE_PUP        FP_ETHERTYPE_PUP
#endif
#ifndef VNB_ETHERTYPE_IP
#define VNB_ETHERTYPE_IP         FP_ETHERTYPE_IP
#endif
#ifndef VNB_ETHERTYPE_ARP
#define VNB_ETHERTYPE_ARP        FP_ETHERTYPE_ARP
#endif
#ifndef VNB_ETHERTYPE_REVARP
#define VNB_ETHERTYPE_REVARP     FP_ETHERTYPE_REVARP
#endif
#ifndef VNB_ETHERTYPE_VLAN
#define VNB_ETHERTYPE_VLAN       FP_ETHERTYPE_VLAN
#endif
#ifndef VNB_ETHERTYPE_IPV6
#define VNB_ETHERTYPE_IPV6       FP_ETHERTYPE_IPV6
#endif
#ifndef VNB_ETHERTYPE_LOOPBACK
#define VNB_ETHERTYPE_LOOPBACK   FP_ETHERTYPE_LOOPBACK
#endif
#ifndef VNB_ETHERTYPE_SLOW
#define VNB_ETHERTYPE_SLOW       FP_ETHERTYPE_P_SLOW
#endif
#endif

#define VNB_ETHERTYPE_MPLS       0x8847

struct vnb_ether_header {
    u_char  ether_dhost[VNB_ETHER_ADDR_LEN];
    u_char  ether_shost[VNB_ETHER_ADDR_LEN];
    u_short ether_type;
} __attribute__ ((packed));

/* Ethernet broadcast */
static const u_char __ng_bcast_addr[VNB_ETHER_ADDR_LEN] =
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* Compare Ethernet addresses */
#if defined(__LinuxKernelVNB__)

static inline int vnb_ether_equal(const uint8_t *mac1, const uint8_t *mac2)
{
	return (memcmp((mac1), (mac2), VNB_ETHER_ADDR_LEN) == 0);
}
static inline int vnb_is_vrrp(uint8_t *mac)
{
	return (mac[0]==0x00 && mac[1]==0x00 && mac[2]==0x5e && mac[3]==0x00);
}
static inline int vnb_is_bcast(struct mbuf *m)
{
	struct vnb_ether_header *eh = mtod(m, struct vnb_ether_header *);
	return (memcmp((eh->ether_dhost), __ng_bcast_addr, VNB_ETHER_ADDR_LEN) == 0);
}
#elif defined(__FastPath__)
static inline int vnb_ether_equal(const uint8_t *mac1, const uint8_t *mac2)
{
	const uint16_t *a = (const uint16_t *)mac1;
	const uint16_t *b = (const uint16_t *)mac2;

	return !((a[0] ^  b[0]) | (a[1] ^  b[1]) | (a[2] ^  b[2]));
}
static inline int vnb_is_vrrp(uint8_t *mac)
{
	const uint16_t *a = (const uint16_t *)mac;
	return !((a[0] ^ 0x0000) | (a[1] ^ htons(0x5e00)));
}
static inline int vnb_is_bcast(struct mbuf *m)
{
	return m_get_flags(m) & M_F_BCAST;
}
#endif


#endif
