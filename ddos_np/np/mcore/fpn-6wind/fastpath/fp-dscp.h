/*
 * Copyright (c) 2007 6WIND
 */

#ifndef __FP_DSCP_H__
#define __FP_DSCP_H__

#define FP_DSCP_MASK  0xfc   /* 11111100 */

static inline void fp_change_ipv4_tos(struct fp_ip *ip, uint8_t tos)
{
	uint32_t check = ntohs(ip->ip_sum);

	check += ip->ip_tos;
	if ((check + 1) >> 16)
		check = (check + 1) & 0xffff;
	check -= tos;
	check += check >> 16; /* adjust carry */
	ip->ip_sum = htons(check);
	ip->ip_tos = tos;
}

/*
 * copy the DSCP bits from src TOS to dst TOS
 * keep the ECN bits unchanged
 */
static inline uint8_t fp_dscp_copy(uint8_t src, uint8_t dst)
{
       src &= FP_DSCP_MASK;
       dst &= ~FP_DSCP_MASK;

       return (src|dst);
}

/* dscp is the TOS field with the 2 MSB bits set to 0 */
static inline void fp_change_ipv4_dscp(struct fp_ip *ip, uint8_t dscp)
{
	uint8_t dsfield = (ip->ip_tos & ~FP_DSCP_MASK) | dscp;

	return fp_change_ipv4_tos(ip, dsfield);
}

#ifdef CONFIG_MCORE_IPV6
/* dscp is the Traffic Class field with the 2 MSB bits set to 0 */
static inline void fp_change_ipv6_dscp(struct fp_ip6_hdr *ip6, uint8_t dscp)
{
	uint16_t tmp;
	tmp = ntohs(*(uint16_t *) ip6);
	tmp = (tmp & 0xf03f) | (dscp << 4);
	*(uint16_t *)ip6 = htons(tmp);
}

static inline uint8_t fp_get_ipv6_tc(struct fp_ip6_hdr *ip6)
{
	uint8_t tc;
	tc = (ntohs(*(uint16_t *) ip6) >> 4);
	return tc;
}
#endif

#endif /* __FP_DSCP_H__ */
