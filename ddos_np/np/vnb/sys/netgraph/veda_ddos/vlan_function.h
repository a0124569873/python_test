/*
 * vlan_function.h
 */

#ifndef VLAN_FUNCTION_H_
#define VLAN_FUNCTION_H_

#define NG_VLAN_MAX_TAG		4095
#define NG_VLAN_TAG_ANY		0xffff
#define NG_VLAN_ENCAPLEN	4		/* length in bytes of encapsulation */
#define VLAN_VLANOFTAG(tag) ((tag) & 0x0fff)
#define ETH_HEADER_LEN     14
#define VLAN_HEADER_LEN    4

/*
 * VLAN header
 */
struct vlan_header {
	uint8_t	dhost[6];  /* Destination MAC address */
	uint8_t	shost[6];  /* Source MAC address */
	uint16_t encap_proto;           /* = htons(ETHERTYPE_VLAN) */
	uint16_t tag;                   /* 1 .. 4094 */
	uint16_t proto;                 /* = htons(ETHERTYPE_xxx */
}__attribute__((packed));

#endif /* VLAN_FUNCTION_H_ */
