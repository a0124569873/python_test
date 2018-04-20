/*
 * Copyright(c) 2010 6WIND
 */

#ifndef __FP_NEIGH_H__
#define __FP_NEIGH_H__

/* Ipv4 neighbour */
#define FP_NEIGH_HASH_MASK (FP_NEIGH_HASH_SIZE - 1)
static inline uint32_t fp_nh4_hash(uint32_t gw, uint32_t ifuid)
{
	uint32_t a = FP_JHASH_GOLDEN_RATIO;
	uint32_t b = gw;
	uint32_t c = ifuid;

	fp_jhash_mix(a, b, c)

	return c & FP_NEIGH_HASH_MASK;
}

static inline uint32_t fp_nh4_lookup(uint32_t gw, uint32_t ifuid, uint32_t rt_type, __fpn_maybe_unused fp_nh_mark_t *nh_mark)
{
	uint32_t hash = fp_nh4_hash(gw, ifuid);
	uint32_t i;
	fp_nh4_entry_t *nh_p;

	i = fp_shared->fp_nh4_hash[hash];

	while (i) {
		int match;
		/*
		* NH is identified either by gw, or if null, by interface
		* This allows creation of a "connected" NH
		*/
		nh_p = &fp_shared->fp_nh4_table[i];

		if (rt_type == RT_TYPE_ROUTE_CONNECTED)
			match = nh_p->nh.nh_type == NH_TYPE_IFACE &&
				nh_p->nh_gw == gw &&
				nh_p->nh.nh_ifuid == ifuid;
		else
			match = nh_p->nh.nh_type == NH_TYPE_GW &&
				nh_p->nh_gw == gw &&
				nh_p->nh.nh_ifuid == ifuid;

#ifdef CONFIG_MCORE_NEXTHOP_MARKING
		if (match && nh_mark)
			match = nh_p->nh.nh_mark == nh_mark->mark &&
				nh_p->nh.nh_mask == nh_mark->mask;
#endif
		if (match)
			return i;

		i = nh_p->next;
	}

	return 0;
}

#ifdef CONFIG_MCORE_IPV6
static inline uint32_t fp_nh6_hash(fp_in6_addr_t *gw, uint32_t ifuid)
{
	uint32_t a = FP_JHASH_GOLDEN_RATIO;
	uint32_t b = gw->fp_s6_addr32[0] ^ gw->fp_s6_addr32[1];
	uint32_t c = gw->fp_s6_addr32[3] ^ ifuid;

	fp_jhash_mix(a, b, c)

	return c & FP_NEIGH_HASH_MASK;
}

static inline uint32_t fp_nh6_lookup(fp_in6_addr_t *gw, uint32_t ifuid,
                                     uint32_t rt_type, fp_nh_mark_t *nh_mark)
{
	uint32_t hash = fp_nh6_hash(gw, ifuid);
	uint32_t i;
	fp_nh6_entry_t *nh_p;

	i = fp_shared->fp_nh6_hash[hash];

	while (i) {
		int match;
		/*
		 * NH is identified by gw and interface.
		 * For connected routes, gw is the src@.
		 * Now we have to search for a matching neighbour with
		 * the _same_ ifuid to allow the insertion of
		 * several neighbours with the same link-local address
		 * and different ifuid.
		 */
		nh_p = &fp_shared->fp_nh6_table[i];

		if (rt_type == RT_TYPE_ROUTE_CONNECTED)
			match = nh_p->nh.nh_type == NH_TYPE_IFACE &&
				is_in6_addr_equal(nh_p->nh_gw, *gw) &&
				nh_p->nh.nh_ifuid == ifuid;
		else
			match = nh_p->nh.nh_type == NH_TYPE_GW &&
				is_in6_addr_equal(nh_p->nh_gw, *gw) &&
				nh_p->nh.nh_ifuid == ifuid;

#ifdef CONFIG_MCORE_NEXTHOP_MARKING
		if (match && nh_mark)
			match = nh_p->nh.nh_mark == nh_mark->mark &&
			        nh_p->nh.nh_mask == nh_mark->mask;
#endif
		if (match)
			return i;

		i = nh_p->next;
	}

	return 0;
}
#endif
#endif /* __FP_NEIGH_H__ */
