/*
 * Copyright (c) 2008 6WIND
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>

#ifndef __TEST_FPM_RT_DUMP
#include "fpm_common.h"
#include "fpm_plugin.h"
#endif
#include "fp.h"
#include "rt_dump.h"

#ifdef CONFIG_MCORE_IPV6
/* Set bits */
static int _set_in6_bits(fp_in6_addr_t *addr, uint32_t value, uint8_t level)
{
	uint32_t sub_addr;
	uint32_t mask;
	uint8_t shift;
	uint8_t start;
	uint8_t cell;
	uint8_t width = fp_shared->fp_cumulative_width6[level];

	/* we'll work with in6_addr.s6_addr32 field
	 * remember that address is stored in network-order in this table
	 * -> s6_addr32[0] are the most significant bits, in network-order too
	 */
	if(width <= 32) {
		start = 0;
		cell = 0;
	} else if(width <= 64) {
		start = 32;
		cell = 1;
	} else if(width <= 96) {
		start = 64;
		cell = 2;
	} else {
		start = 96;
		cell = 3;
	} /* width */

	/* we need to detect overlapping */
	if(width - FP_IPV6_LAYER_WIDTH(level) < start) {
		/* Overlapping of bits on two 32-bits words */

		/* least significant bits of value are MSB of the second word */
		uint8_t nb_bits = width - start;
		uint32_t v;
		sub_addr = ntohl(addr->fp_s6_addr32[cell]);
		shift = 32-nb_bits;
		/* Clear bits */
		mask = ~((0xFFFFFFFF>>shift)<<shift);
		sub_addr &= mask;
		/* Set bits */
		mask = 0xFFFFFFFF >> shift;
		v = (htonl(value) & mask) << shift;
		sub_addr |= v;
		addr->fp_s6_addr32[cell] = htonl(sub_addr);
		
		/* most significant bits are in LSB of the first word 
		 * -> put them in MSB of the result
		 */
		sub_addr = ntohl(addr->fp_s6_addr32[cell-1]);
		shift = nb_bits;
		nb_bits = FP_IPV6_LAYER_WIDTH(level) - nb_bits;
		/* Clear bits */
		mask = ~(0xFFFFFFFF >> (32-nb_bits));
		sub_addr &= mask;
		/* Set bits */
		v = htonl(value) >> shift;
		sub_addr |= v;
		addr->fp_s6_addr32[cell-1] = htonl(sub_addr);
	} else {
		/* all right, all bits are in the same 32-bits word */
		sub_addr = ntohl(addr->fp_s6_addr32[cell]);
		shift = (32+start)-width;
		/* Clear bits */
		mask = ~((0xFFFFFFFF >> (32-FP_IPV6_LAYER_WIDTH(level)))<<shift);
		sub_addr &= mask;
		/* Set bits */
		value = value << shift; 
		sub_addr |= value;
		addr->fp_s6_addr32[cell] = htonl(sub_addr);
		//std::cout<<"mask:"<<mask<<" value:"<<value<<" "<<addr->s6_addr32[cell]<<"(cell "<<cell<<")"<<std::endl;
	}
	return 0;
}

static void __clear(fp_in6_addr_t * addr, uint8_t level)
{
	uint32_t sub_addr;
	uint32_t mask;
	uint8_t start;
	uint8_t cell;
	uint8_t i;
	uint8_t width = fp_shared->fp_cumulative_width6[level];
	uint8_t length = FP_IPV6_LAYER_WIDTH(level);

	/* we'll work with in6_addr.s6_addr32 field
	 * remember that address is stored in network-order in this table
	 * -> s6_addr32[0] are the most significant bits, in network-order too
	 */
	if(width <= 32) {
		cell = 0;
	} else if(width <= 64) {
		cell = 1;
	} else if(width <= 96) {
		cell = 2;
	} else {
		cell = 3;
	} /* width */

	start = width-length;

	/* /!\ << is NOT surcharged to work with uint*_t /!\ */

	for(i = cell; i < 4; i++) {
		if(start < (i+1)*32) {
			sub_addr = ntohl(addr->fp_s6_addr32[i]);
			if((i > cell) || (i*32 == start))
				sub_addr = 0;
			else {
				mask = 0xFFFFFFFF << ((i+1)*32-start);
				sub_addr &= mask;
			}
			addr->fp_s6_addr32[i] = htonl(sub_addr);
		}
	}
}
#endif

int fpm_process_rt4_entry(fp_rt4_entry_t e, uint32_t index, uint32_t* bitmap, uint32_t i, uint16_t j, uint16_t k, uint16_t vr)
{
	fp_nh4_entry_t nh;

	uint32_t network;
	uint8_t *pb = (uint8_t *)&network;

	int err = 0;
	int cpt_nh;

	/*
	 * In the tree the same high level route is split
	 * in as many as needed sub routes with prefix length
	 * matching byte boundary i.e. /8 /16 etc.)
	 * So the rtentry itself can be found more than once
	 */
	if (__BMAP_TST(bitmap, index))
		return 0;
	__BMAP_SET(bitmap, index);

	network = htonl((i << 16) + (j<<8) + k);
	network &= plen2mask(e.rt.rt_length);

	/*
	 * Scan ALL next-hop, as we can handle ECMP with different kind
	 * of next-hops (adresses, ARP enbtries etc.
	 */
	for (cpt_nh=0 ; cpt_nh<e.rt.rt_nb_nh ; cpt_nh++) {
		uint32_t nh_index;

		nh_index = e.rt.rt_next_hop[cpt_nh];
		nh = fp_shared->fp_nh4_table[nh_index];

		/*
		 * Different operations according to the the nh.rt_type
		 */
		switch (nh.nh.rt_type) {

		case RT_TYPE_ADDRESS:
		{
#ifndef __TEST_FPM_RT_DUMP
			/*
			 * Address itself is not stored in the gateway, it is
			 * only the /32 prefix that holds it
			 */
			if (fpm_add_v4_addr_cmd(nh.nh.nh_ifuid, network))
				err = 1;

			if (f_verbose)
#endif /*  __TEST_FPM_RT_DUMP */
			syslog(LOG_DEBUG, "Adding Addr. route for "
			       "%d.%d.%d.%d/%d\n",
			       pb[0], pb[1], pb[2], pb[3], e.rt.rt_length);
			break;
		}

		case RT_TYPE_NEIGH:
		{
			/*
			 * This may only reflect a resolved gateway. The real
			 * ARP entry related route is identified with the /32
			 * prefix.
			 */
			if ((e.rt.rt_length == 32) && (network == nh.nh_gw)) {
#ifndef __TEST_FPM_RT_DUMP
				if (fpm_add_v4_arp_cmd(nh.nh.nh_ifuid, network,
				                       nh.nh.nh_eth.ether_dhost))
					err = 1;

				if (f_verbose)
#endif /*  __TEST_FPM_RT_DUMP */
				syslog(LOG_DEBUG, "Adding ARP route for "
				       "%d.%d.%d.%d/%d\n",
				       pb[0], pb[1], pb[2], pb[3], e.rt.rt_length);
				break;
			}

			/*
			 * No break. The current NH is not the ARP entry
			 * itself, so handle it as a plain route
			 */
		}

		case RT_TYPE_ROUTE:
		case RT_TYPE_ROUTE_CONNECTED:
		case RT_TYPE_ROUTE_LOCAL:
		case RT_TYPE_ROUTE_BLACKHOLE:
		{
#ifndef __TEST_FPM_RT_DUMP
			if (fpm_add_v4_route_cmd(nh.nh.nh_ifuid, network,
			                         e.rt.rt_length, nh.nh_gw,
			                         nh.nh.rt_type, vr, FPM_GR_SHMEM_LIST))
				err = 1;

			if (f_verbose)
#endif /*  __TEST_FPM_RT_DUMP */
			syslog(LOG_DEBUG, "Adding plain route for "
			       "%d.%d.%d.%d/%d\n",
			       pb[0], pb[1], pb[2], pb[3], e.rt.rt_length);
			break;
		}

		default:
			syslog(LOG_ERR, "Unknown NH type for route %d.%d.%d.%d/%d\n",
			       pb[0], pb[1], pb[2], pb[3], e.rt.rt_length);
			break;
		}
	}

	return err;
}

int fpm_rt4_entries_to_cmd(fp_rt4_entry_t *fp_rt4_table)
{
	uint16_t vr, j = 0, k = 0;
	uint32_t l0;
#ifdef CONFIG_MCORE_RT_IP_BASE8
	uint16_t z;
#endif
	uint32_t i;
	uint32_t bitmap[(FP_IPV4_NBRTENTRIES+31)/32];
	int err = 0;

	/* For each VR */
	for (vr=0 ; vr<FP_MAX_VR; vr++) {
		fp_table_entry_t *entries;
		uint32_t vrf_idx;
		memset(bitmap, 0, sizeof(bitmap));

#ifndef __TEST_FPM_RT_DUMP
		if (f_verbose)
#endif
		syslog(LOG_DEBUG, "Scanning VR %d\n", vr);
#ifdef CONFIG_MCORE_RT_IP_BASE8
		vrf_idx = fp_shared->fp_8_table[vr].entries;
		if (!(fp_shared->fp_8_table[vr].used)) {
			continue;
		}
		for (i=0 ; i< 1<<8 ; i++) 
#else
		vrf_idx = fp_shared->fp_16_table[vr].entries;
		if (!(fp_shared->fp_16_table[vr].used)) {
			continue;
		}
		for (i=0 ; i< 1<<16 ; i++) 
#endif
		{
			uint32_t entry_index;
			j = 0;
			k = 0;

#ifdef CONFIG_MCORE_RT_IP_BASE8
			z = 0;
			entries = &fp_shared->fp_8_entries[vrf_idx];
			entry_index = i;
			/* Get the first and second index */
			if (entries[entry_index].index) {
				fp_table_entry_t e0 = entries[entry_index];

				if (e0.rt == RT_TABLE) {
					goto Level0b;
				}

				l0 = (i<<8) + z;
				if (fpm_process_rt4_entry(fp_rt4_table[e0.index], e0.index, bitmap, l0, j, k, vr))
					err = 1;
				continue;

Level0b:
			/*
			 * Dwelve into next table level
			 */
			for (z= 0; z < 256; ++z) {
				entries = fp_shared->fp_8_entries;
				entry_index = fp_shared->fp_8_table[e0.index].entries+z;
				l0 = (i<<8) + z;
#else
			entries = &fp_shared->fp_16_entries[vrf_idx];
			entry_index = i;
			l0 = i;
#endif
			/* Get the first and second index */
			if (entries[entry_index].index) {
				fp_table_entry_t e1 = entries[entry_index];

				if (e1.rt == RT_TABLE) {
					goto Level1;
				}
				if (fpm_process_rt4_entry(fp_rt4_table[e1.index], e1.index, bitmap, l0, j, k, vr))
					err = 1;
				continue;
				/* Get the third next index */
Level1:
				for(j=0 ; j<256 ; j++) {
					k = 0;
					entries = fp_shared->fp_8_entries;
					fp_table_entry_t e2;
					entry_index = fp_shared->fp_8_table[e1.index].entries+j;
					e2 = entries[entry_index];

					if (e2.index == 0)
						continue;

					if (e2.rt != RT_ROUTE) {
						goto Level2;
					}

					if (fpm_process_rt4_entry(fp_rt4_table[e2.index], e2.index, bitmap, l0, j, k, vr))
						err = 1;
					continue;
Level2:
					/* Get the fourth index */
					for(k=0 ; k<256 ; k++) {
						fp_table_entry_t e3;
						entries = fp_shared->fp_8_entries;
						entry_index = fp_shared->fp_8_table[e2.index].entries+k;
						e3 = entries[entry_index];

						if (e3.index == 0)
							continue;

						if (fpm_process_rt4_entry(fp_rt4_table[e3.index], e3.index, bitmap, l0, j, k, vr))
							err = 1;
						continue;
					}
				}
			}
#ifdef CONFIG_MCORE_RT_IP_BASE8
		} /* for (z, ...) */
		} /* if at level 0 */
#endif
		}
	}

	return err;
}



/* IPv6 routes and addresses entries */
#ifdef CONFIG_MCORE_IPV6

#ifdef CONFIG_MCORE_RT_IPV6_BASE8
#	define fp_get_table6(l) fp_shared->fp_8_table
#	define fp_get_entries6(l) fp_shared->fp_8_entries 
#else
#	define fp_get_table6(l)	((fp_table_t*)((uint8_t*)fp_shared + fp_shared->fp_table6[(l)]))
#	define fp_get_entries6(l)	((fp_table_entry_t*)((uint8_t*)fp_shared + fp_shared->fp_entries6[(l)]))
#endif

int fpm_process_rt6 (uint32_t *bitmap, fp_in6_addr_t *network, uint32_t vr, uint32_t rt6_index)
{
	fp_rt6_entry_t r;
	int cpt_nh;
	fp_nh6_entry_t nh;
	int err = 0;

	/*
	 * In the tree the same high level route is split
	 * in as many as needed sub routes with prefix length
	 * matching byte boundary i.e. /8 /16 etc.)
	 * So the rtentry itself can be found more than once
	 */
	if (__BMAP_TST(bitmap, rt6_index))
		return 0;
	__BMAP_SET(bitmap, rt6_index);

	r = fp_shared->fp_rt6_table[rt6_index];
	for (cpt_nh=0 ; cpt_nh<r.rt.rt_nb_nh ; cpt_nh++) {
		uint32_t nh_index;
		nh_index = r.rt.rt_next_hop[cpt_nh];
		nh = fp_shared->fp_nh6_table[nh_index];

		switch (nh.nh.rt_type) {

		case RT_TYPE_ADDRESS:
		{
#ifndef __TEST_FPM_RT_DUMP
			if (fpm_add_v6_addr_cmd(nh.nh.nh_ifuid, network))
				err = 1;

			if (f_verbose)
#endif /*   __TEST_FPM_RT_DUMP */
			syslog(LOG_INFO, "Adding Addr. route "
			       FP_NIP6_FMT "/128 \n",
			       FP_NIP6(*network));
			break;
		}


		case RT_TYPE_NEIGH:
			/*
			 * This is an NDP entry
			 */
			if (r.rt.rt_neigh_index && r.rt.rt_neigh_index == nh_index) {
#ifndef __TEST_FPM_RT_DUMP
				if (fpm_add_v6_ndp_cmd(nh.nh.nh_ifuid, network,
				                    nh.nh.nh_eth.ether_dhost))
					err = 1;

				if (f_verbose)
#endif /*   __TEST_FPM_RT_DUMP */
				syslog(LOG_DEBUG, "Adding NDP entry "
				       FP_NIP6_FMT " --> "
				       FP_NIP6_FMT " via %08x\n",
				       FP_NIP6(*network), FP_NIP6(nh.nh_gw),
				       nh.nh.nh_ifuid);
				break;
			}
			/*
			 * No break. The current NH is not the ARP entry
			 * itself, so handle it as a plain route
			 */

		case RT_TYPE_ROUTE:
		case RT_TYPE_ROUTE_CONNECTED:
		case RT_TYPE_ROUTE_LOCAL:
		case RT_TYPE_ROUTE_BLACKHOLE:
		{
			/*
			 * This is an NDP entry
			 */
			if (r.rt.rt_neigh_index && r.rt.rt_neigh_index == nh_index) {
#ifndef __TEST_FPM_RT_DUMP
				if (fpm_add_v6_ndp_cmd(nh.nh.nh_ifuid, network,
				                    nh.nh.nh_eth.ether_dhost))
					err = 1;

				if (f_verbose)
#endif /*   __TEST_FPM_RT_DUMP */
				syslog(LOG_DEBUG, "Adding NDP entry "
				       FP_NIP6_FMT " --> "
				       FP_NIP6_FMT " via %08x\n",
				       FP_NIP6(*network), FP_NIP6(nh.nh_gw),
				       nh.nh.nh_ifuid);
				break;
			}

			/*
			 * Classical route
			 */

#ifndef __TEST_FPM_RT_DUMP
			if (fpm_add_v6_route_cmd(nh.nh.nh_ifuid, network,
			                  r.rt.rt_length, &nh.nh_gw,
			                  nh.nh.rt_type, vr, FPM_GR_SHMEM_LIST))
				err = 1;

			if (f_verbose)
#endif /*   __TEST_FPM_RT_DUMP */
			syslog(LOG_INFO, "Adding Plain route "
			       FP_NIP6_FMT "/%d --> "
			       FP_NIP6_FMT " via %08x\n",
			       FP_NIP6(*network), r.rt.rt_length,
			       FP_NIP6(nh.nh_gw), nh.nh.nh_ifuid);
			break;
		}

		default:
			syslog(LOG_ERR, "Unknown NH type for route "
				       FP_NIP6_FMT"/%d\n",
				       FP_NIP6(*network), r.rt.rt_length);
			break;

		}
	}

	return err;
}

int fpm_rt6_entries_recur(const fp_table_entry_t * entries, const uint32_t rt_idx, const int level, fp_in6_addr_t *network, uint32_t *bitmap, uint32_t vr)
{
	int i;
	int err = 0;

	for(i = 0; i < (1<<FP_IPV6_LAYER_WIDTH(level)); i++) {
		__clear(network, level);
		fp_table_entry_t e = entries[i];

		if(e.index != RT_INDEX_UNUSED) {

			_set_in6_bits(network, i, level);
			if(e.rt != RT_TABLE) {
				fp_rt6_entry_t r;
				if (!rt_idx || (rt_idx == e.index)) {
					uint32_t rt6_index;
					uint32_t rt6_next;
					for (rt6_index = e.index; rt6_index;
					     rt6_index = rt6_next)
					{
						r = fp_shared->fp_rt6_table[rt6_index];
						rt6_next = r.rt.rt_next;

						if (fpm_process_rt6 (bitmap,
						           network, vr,
						           rt6_index))
							err = 1;
					}
				}
				continue;
			} else {
				if(level < FP_IPV6_NBLAYERS-1) {
					fp_in6_addr_t deeper = *network;
					uint32_t index = fp_get_table6(level+1)[e.index].entries;
					if(fpm_rt6_entries_recur(fp_get_entries6(level+1)+index,
					                       rt_idx, level+1,
								 &deeper, bitmap, vr))
						err = 1;
				} /* level */
			}
		}
	}
	return err;
}

int fpm_rt6_entries_to_cmd(fp_rt6_entry_t *fp_rt6_table)
{
	fp_table_entry_t *entries;
	fp_in6_addr_t addr6;
	uint32_t bitmap[(FP_IPV6_NBRTENTRIES+31)/32];
	uint32_t vr;
	int err = 0;

	memset(bitmap, 0, sizeof(bitmap));

	addr6.fp_s6_addr32[0] = 0;
	addr6.fp_s6_addr32[1] = 0;
	addr6.fp_s6_addr32[2] = 0;
	addr6.fp_s6_addr32[3] = 0;
	for (vr = 0; vr<FP_MAX_VR ; vr++) {
#ifndef __TEST_FPM_RT_DUMP
		if (f_verbose)
#endif
		syslog(LOG_INFO, "Scanning VR %d\n", vr);
		entries = fp_get_entries6(0)+
			fp_get_table6(0)[FP_IPV6_TABLE_START+vr].entries;
	
		if (fpm_rt6_entries_recur(entries, 0, 0, &addr6, bitmap, vr))
			err = 1;
	}

	return err;
}

#endif /* CONFIG_MCORE_IPV6 */

