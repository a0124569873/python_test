/*
 * Copyright(c) 2007 6WIND
 */
#ifndef __FP_LOOKUP_H__
#define __FP_LOOKUP_H__

#include "fp-jhash.h"

/*
 * This function does not use a modulo to choose ECMP routes (too expansive in
 * terms of performance). It uses a hash + multiplication + shift that also
 * provides a fair distribution.
 */
static inline fp_nh4_entry_t *select_nh4(fp_rt4_entry_t *rt, uint32_t *area)
{
	uint32_t selector;
	uint32_t a, b;

	if (likely(rt->rt.rt_nb_nhp <= 1))
		return (&fp_shared->fp_nh4_table[rt->rt.rt_next_hop[0]]);

	/* Use a JHASH to dispatch values on a 32 bits */
	a = FP_JHASH_GOLDEN_RATIO;
	b = area[0];
	selector = area[1];
	fp_jhash_mix(a, b, selector);

	selector = ((uint64_t)selector * rt->rt.rt_nb_nhp) >> 32;
	return (&fp_shared->fp_nh4_table[rt->rt.rt_next_hop[selector]]);
}

static inline fp_rt4_entry_t *fp_rt4_lookup(uint16_t vrfid, uint32_t addr)
{
	fp_table_entry_t * entries;
	fp_table_entry_t t;
	int index;

	addr = ntohl(addr);

	/* Level 0 */
#ifdef CONFIG_MCORE_RT_IP_BASE8
	/* Hard-coded 8+8+8 level 0 and 0-bis */
	entries = fp_shared->fp_8_entries;
#ifdef CONFIG_MCORE_VRF
	index = vrfid<<8;
#else
	index = 0;
#endif

	/* Level 0 */
	t = entries[index+((addr>>24)&0xFF)];
	if (unlikely(t.rt))
		return &fp_shared->fp_rt4_table[t.index];

	if (unlikely(!t.index))
		return 0;

	/* Level 0-bis */
	index = (t.index << 8);
	t = entries[index+((addr>>16)&0xFF)];
	if (likely(t.rt))
		return &fp_shared->fp_rt4_table[t.index];

	if (unlikely(!t.index))
		return 0;
#else
	/* Hard-coded 16+8+8 level 0 */
	entries = fp_shared->fp_16_entries;
#ifdef CONFIG_MCORE_VRF
	index = vrfid<<16;
#else
	index = 0;
#endif

	t = entries[index + (addr>>16)];
	if (unlikely(t.rt))
		return &fp_shared->fp_rt4_table[t.index];

	if (unlikely(!t.index))
		return 0;

	/* From now on, 8-bits tables */
	entries = fp_shared->fp_8_entries;
#endif

	/* Level 1 */
	index = (t.index << 8);
	t = entries[index+((addr>>8)&0xFF)];
	if (likely(t.rt))
		return &fp_shared->fp_rt4_table[t.index];

	if (unlikely(!t.index))
		return 0;

	/* Level 2 */
	index = (t.index << 8);
	t = entries[index+(addr&0xFF)];
	if (likely(t.rt))
		return &fp_shared->fp_rt4_table[t.index];
	return 0;
}

const char *fp_rt_type2str(uint8_t rt_type);
int fp_rt4_selectsrc(uint32_t vrfid, uint32_t dst, uint32_t *srcp,
		     fp_rt4_entry_t **rt);

#ifdef CONFIG_MCORE_IPV6

static inline uint32_t fp_baseIndex6(fp_in6_addr_t * addr, int level)
#ifdef CONFIG_MCORE_RT_IPV6_BASE8
{
	uint8_t *ptr = (uint8_t *)addr;
	return (ptr[level]);
}
#else
{
	if (unlikely(level == 0))
		return (addr->fp_s6_addr[0] << 8 | addr->fp_s6_addr[1]);
	return addr->fp_s6_addr[level + 1];
}
#endif

/*
 * This function does not use a modulo to choose ECMP routes (too expansive in
 * terms of performance). It uses a hash + multiplication + shift that also
 * provides a fair distribution.
 */
static inline fp_nh6_entry_t *select_nh6(fp_rt6_entry_t *rt, fp_in6_addr_t *area)
{
	uint32_t selector;
	uint32_t a, b;

	if (likely(rt->rt.rt_nb_nhp <= 1))
		return (&fp_shared->fp_nh6_table[rt->rt.rt_next_hop[0]]);

	/*
	 * area[0] is the source address
	 * area[1] is the destination address
	 * pick the hash on the lowest part of the host-ID
	 * Use a JHASH to dispatch values on a 32 bits
	 */
	a = FP_JHASH_GOLDEN_RATIO;
	b = area[0].fp_s6_addr32[3];
	selector = area[1].fp_s6_addr32[3];
	fp_jhash_mix(a, b, selector);

	selector = ((uint64_t)selector * rt->rt.rt_nb_nhp) >> 32;
	return (&fp_shared->fp_nh6_table[rt->rt.rt_next_hop[selector]]);
}

/*
 *	return the table depending on the level
 */
#ifdef CONFIG_MCORE_RT_IPV6_BASE8
#	define fp_get_table6(l) fp_shared->fp_8_table
#	define fp_get_entries6(l) fp_shared->fp_8_entries 
#else
#	define fp_get_table6(l)	((fp_table_t*)((uint8_t*)fp_shared + fp_shared->fp_table6[(l)]))
#	define fp_get_entries6(l)	((fp_table_entry_t*)((uint8_t*)fp_shared + fp_shared->fp_entries6[(l)]))
#endif

/*
 * Search a route for a IPv6 address in a given VR.
 */
#ifdef CONFIG_MCORE_RT_IPV6_BASE8
	/*
	 * The level 0 lookup searches a 2**8-entry table that is indexed
	 * by the first byte of the IPv6 address.
	 * Then, all further successive level lookups, if any, search
	 * 2**8 tables that are respectively indexed by the value of
	 * the byte located at the lookup level in the IPv6 address.
	 */
#define RT_IPV6_ADDR_BYTE_INDEX(lookup_level) lookup_level
#else
	/*
	 * The level 0 lookup searches a 2**16-entry table that is indexed
	 * by the first 16-bit word of the IPv6 address.
	 * Then, all further successive level lookups, if any, search
	 * 2**8 tables that are respectively indexed by the value of
	 * the byte located at the lookup level + 1 in the IPv6 address.
	 */
#define RT_IPV6_ADDR_BYTE_INDEX(lookup_level) (lookup_level + 1)
#endif /* CONFIG_MCORE_RT_IPV6_BASE8 */

#define CHECK_RT6_LOOKUP_ENTRY					\
	if (entry->rt == RT_ROUTE)				\
		return &fp_shared->fp_rt6_table[entry->index];	\
	if (unlikely(!entry->index))				\
		return NULL

#define FIND_BASE8_RT6_ENTRY(lookup_level)				\
	entry = &fp_shared->fp_8_entries[(entry->index << 8) +		\
		addr->fp_s6_addr[RT_IPV6_ADDR_BYTE_INDEX(lookup_level)]]; \
	CHECK_RT6_LOOKUP_ENTRY

static inline fp_rt6_entry_t *fp_rt6_lookup(uint16_t vrfid, fp_in6_addr_t *addr)
{
	/*
	 * /!\ BIG FAT WARNING /!\
	 * The 2 MACROS above use the parameter "addr" and the local variable
	 * "entry"
	 * Don't change their name.
	 */
	fp_table_entry_t *entry;

#ifdef CONFIG_MCORE_RT_IPV6_BASE8
	/*
	 * The level 0 lookup searches a 2**8-entry table whose first entry
	 * is located in the shared memory after IPv4 route lookup tables,
	 * indexed by the vrfid argument, if relevant.
	 */
	entry = &fp_shared->fp_8_entries[
		((FP_IPV6_TABLE_START
#ifdef CONFIG_MCORE_VRF
		+ vrfid
#endif
		) << 8) + addr->fp_s6_addr[0]];
#else
	/*
	 * The level 0 lookup is based on a 2**16-entry table, indexed by
	 * the vrfid argument, that is located in the shared memory after
	 * IPv4 route lookup tables.
	 */
	entry = &fp_shared->fp_16_entries[
		((FP_IPV6_TABLE_START
#ifdef CONFIG_MCORE_VRF
		  + vrfid
#endif
		  ) << 16) + ntohs(addr->fp_s6_addr16[0])];
#endif /* CONFIG_MCORE_RT_IPV6_BASE8 */
	CHECK_RT6_LOOKUP_ENTRY;

	/*
	 * All further levels of lookup are based on 2**8-entry tables
	 * whose start address in the shared memory is indexed by the
	 * previous lookup result.
	 */
	FIND_BASE8_RT6_ENTRY(1);
	FIND_BASE8_RT6_ENTRY(2);
	FIND_BASE8_RT6_ENTRY(3);
	FIND_BASE8_RT6_ENTRY(4);
	FIND_BASE8_RT6_ENTRY(5);
	FIND_BASE8_RT6_ENTRY(6);
	FIND_BASE8_RT6_ENTRY(7);
	FIND_BASE8_RT6_ENTRY(8);
	FIND_BASE8_RT6_ENTRY(9);
	FIND_BASE8_RT6_ENTRY(10);
	FIND_BASE8_RT6_ENTRY(11);
	FIND_BASE8_RT6_ENTRY(12);
	FIND_BASE8_RT6_ENTRY(13);
	FIND_BASE8_RT6_ENTRY(14);
#ifdef CONFIG_MCORE_RT_IPV6_BASE8
	/*
	 * The last lookup level 15 is only possible when using a 2**8 lookup
	 * at level 0.
	 */
	FIND_BASE8_RT6_ENTRY(15);
#endif
	return NULL;
}

int fp_rt6_selectsrc(uint32_t vrfid, struct fp_in6_addr *dst,
		     struct fp_in6_addr *srcp, fp_rt6_entry_t **rt);
#endif /* CONFIG_MCORE_IPV6 */

#endif /* __FP_LOOKUP_H__ */
