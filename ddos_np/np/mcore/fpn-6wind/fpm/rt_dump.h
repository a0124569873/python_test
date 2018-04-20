/*
 * Copyright 2008 6WIND, All rights reserved.
 */

#ifndef __DUMP_H__
#define __DUMP_H__

/* Helper to set/get flags in a bitmap (uint32_t table) */
#define __BMAP_CLR(b,n) (((b)[(n)/32] &= ~(1u<<((n)%32))))
#define __BMAP_SET(b,n) (((b)[(n)/32] |= (1u<<((n)%32))))
#define __BMAP_TST(b,n) (((b)[(n)/32] & (1u<<((n)%32)))!=0)

int fpm_rt4_entries_to_cmd(fp_rt4_entry_t *fp_rt4_table);

int fpm_add_v4_route_cmd(uint32_t ifuid, uint32_t address, int prefixlen, uint32_t nexthop, uint8_t rt_type, uint32_t vrfid, int start_queue);
int fpm_add_v4_addr_cmd(uint32_t ifuid, uint32_t address);
int fpm_add_v4_arp_cmd(uint32_t ifuid, uint32_t address, uint8_t *dhost);
#ifdef CONFIG_MCORE_IPV6
int fpm_rt6_entries_to_cmd(fp_rt6_entry_t *fp_rt6_table);
int fpm_add_v6_addr_cmd(uint32_t ifuid, fp_in6_addr_t *address);
int fpm_add_v6_route_cmd(uint32_t ifuid, fp_in6_addr_t *address, int prefixlen, fp_in6_addr_t *nexthop, uint8_t rt_type, uint32_t vrfid, int start_queue);
int fpm_add_v6_ndp_cmd(uint32_t ifuid, fp_in6_addr_t *ip6, uint8_t *dhost);
int fpm_rt6_entries_recur(const fp_table_entry_t * entries, const uint32_t rt_idx, const int level, fp_in6_addr_t *network, uint32_t *bitmap, uint32_t vr);
#endif

/*
 * Convert a prefix length into a 32 bit prefix
 * (network order)
 */
static inline uint32_t plen2mask(int i)
{
	uint32_t mask = 0;

	if (i>32)
		mask = 0xffffffff;

	else if (i>0)
		mask = ((uint32_t)0xffffffff) << (32 - i);

	return htonl(mask);
}


#endif /* __DUMP_H__ */
