/*
 * Copyright(c) 2012  6WIND
 */
#ifndef __FPN_ETH_H__
#define __FPN_ETH_H__

#define FPN_ETHER_ADDR_LEN 6
#define FPN_ETHER_HDR_LEN  (2*FPN_ETHER_ADDR_LEN +2) 
#define FPN_ETHERTYPE_VLAN	0x8100	/* IEEE 802.1Q VLAN tagging */
#define FPN_ETHERTYPE_IP	0x0800	/* IPv4 ethertype */

/*
 * Structure of an ethernet packet header.
 */
struct fpn_ether_header {
	uint8_t	dhost[FPN_ETHER_ADDR_LEN];  /* Destination MAC address */
	uint8_t	shost[FPN_ETHER_ADDR_LEN];  /* Source MAC address */
	uint16_t ether_type;                /* = htons(ETHERTYPE_xxx */
} __attribute__((packed));

#define FPN_MAX_VLANID     4096
#define FPN_VLAN_ENCAPLEN  4		/* length in bytes of encapsulation */

/* extract fields in tag_pcp */
#define FPN_VLAN_VLANOFTAG(tag_pcp) ((tag_pcp) & 0x0fff)
#define FPN_VLAN_PRIOFTAG(tag_pcp) (((tag_pcp) >> 13) & 0x0007)
#define FPN_VLAN_CFIOFTAG(tag_pcp) (((tag_pcp) >> 12) & 0x0001)

/*
 * Structure of an ethernet VLAN packet header.
 */
struct fpn_eth_vlan_hdr {
	uint8_t	dhost[FPN_ETHER_ADDR_LEN];  /* Destination MAC address */
	uint8_t	shost[FPN_ETHER_ADDR_LEN];  /* Source MAC address */
	uint16_t tag_proto_id;              /* = htons(ETHERTYPE_VLAN) */
	uint16_t tag_pcp;                   /* tag: 1 .. 4094 */
	uint16_t ether_type;                /* = htons(ETHERTYPE_xxx */
} __attribute__ ((packed));

#endif
