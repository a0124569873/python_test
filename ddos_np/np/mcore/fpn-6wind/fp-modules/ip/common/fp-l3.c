/*
 * Copyright(c) 2006 6WIND
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "fp.h"
#include "fp-lookup.h"
#include "fp-neigh.h"
#include "net/fp-ethernet.h"
#include "net/fp-socket.h"

#define IS_RT_NONEXTHOP(type) ((type) == RT_TYPE_ROUTE_LOCAL || \
                               (type) == RT_TYPE_ROUTE_BLACKHOLE) 

static void fp_add_nh4_hash(uint32_t hash, uint32_t index)
{
	uint32_t next;

	next = fp_shared->fp_nh4_hash[hash];

	fp_shared->fp_nh4_table[index].next = next;
	fp_shared->fp_nh4_table[index].prev = 0;

	if (next)
		fp_shared->fp_nh4_table[next].prev = index;

	fp_shared->fp_nh4_hash[hash] = index;
}

/* Del index from hash table, and manage collisions */
static void fp_del_nh4_hash(uint32_t hash, uint32_t index)
{
	uint32_t next, prev;

	prev = fp_shared->fp_nh4_table[index].prev;
	next = fp_shared->fp_nh4_table[index].next;

	/* If prev is not null, remove node from chaining,
	 * otherwise, remove node from head
	 */
	if (prev)
		fp_shared->fp_nh4_table[prev].next = next;
	else
		fp_shared->fp_nh4_hash[hash] = fp_shared->fp_nh4_table[index].next;

	if (next)
		fp_shared->fp_nh4_table[next].prev = prev;
}

/*
 * Active next-hop maybe prioritized, and ECMP will be limited
 * to the subset of highest priority
 */
uint8_t fp_nh_priority (_fp_nh_entry_t *nh)
{
	uint8_t prio = 0;
	fp_ifnet_t *ifp = __fp_ifuid2ifnet(nh->nh_ifuid);

	if (nh->rt_type == RT_TYPE_ADDRESS)
		prio += FP_ECMP_PRIO_ADDRESS;
	if (ifp->if_flags & IFF_FP_PREF)
		prio += FP_ECMP_PRIO_PREFERRED;
	/*
	 *  The preference of neighbors over some othe routes is it not a
	 *  property of the next-hop itslef, it does only  matters for the /32
	 *  (resp /128) route that holds it. ARP weight is hence handled
	 *  inside re-roder function.
	 */
	if (nh->rt_type == RT_TYPE_ROUTE_CONNECTED)
		prio += FP_ECMP_PRIO_CONNECTED;
	else if (nh->rt_type == RT_TYPE_ROUTE_LOCAL)
		prio += FP_ECMP_PRIO_LOCAL;
	else if (nh->rt_type == RT_TYPE_ROUTE_BLACKHOLE)
		prio += FP_ECMP_PRIO_BH;
	else
		prio += FP_ECMP_PRIO_BASE;
	return prio;
}

/*
 * The current ARP entry holds the proper /32 as gw
 * this will be used to indentify all ARP entries within
 * the route
 */
uint8_t fp_nh4_neigh_prio (fp_rt4_entry_t* rte, fp_nh4_entry_t *nhe) {

	uint32_t arp_addr;

	/* This is not an ARP route */
	if (rte->rt.rt_neigh_index == 0)
		return 0;

	arp_addr = fp_shared->fp_nh4_table[rte->rt.rt_neigh_index].nh_gw;

	/*
	 * It's not only a resolved ARP entry, but the gw
	 * matches the /32 of the route
	 */
	if ((nhe->nh.rt_type == RT_TYPE_NEIGH) &&
	    (nhe->nh_gw ==  arp_addr))
		return FP_ECMP_PRIO_NEIGH;
	else
		return 0;
}

uint8_t fp_best_nh4_prio (fp_rt4_entry_t* e) {
	return (fp_shared->fp_nh4_table[e->rt.rt_next_hop[0]].nh.nh_priority);
}

/*
 * get/put to manage refcount on NH entries
 */
static inline void fp_nh4_get(uint32_t index)
{
	fp_nh4_entry_t *nh;
	nh = &fp_shared->fp_nh4_table[index];
	/*
	 * Here we could manage some free list management
	 * if (! nh->refcnt)
	 *    ...
	 */
	nh->nh.nh_refcnt++;
	/*
	 * Count all routes using the interfaces, except
	 * the fast path specifc routes used for addresses
	 */
	if ((nh->nh.nh_ifuid) && (nh->nh.rt_type != RT_TYPE_ADDRESS)) {
		fp_ifnet_t *ifp = __fp_ifuid2ifnet (nh->nh.nh_ifuid);
		ifp->if_nb_rt4++;
	}

	return;
}

/*
 * Decrease-and-release fct for NH entries
 */
static inline void fp_nh4_put(uint32_t index)
{
	fp_nh4_entry_t *nh;
	uint32_t tail;
	nh = &fp_shared->fp_nh4_table[index];
	/*
	 * Count all routes using the interfaces, except
	 * the fast path specifc routes used for addresses
	 */
	if ((nh->nh.nh_ifuid) && (nh->nh.rt_type != RT_TYPE_ADDRESS)) {
		fp_ifnet_t *ifp = __fp_ifuid2ifnet (nh->nh.nh_ifuid);
		ifp->if_nb_rt4--;
	}
	/*
	 * Here we could manage some free list management
	 * if (! nh->refcnt)
	 *    ...
	 */
	if (nh->nh.nh_refcnt == 1 && index != FP_IPV4_NH_ROUTE_LOCAL &&
	    index != FP_IPV4_NH_ROUTE_BLACKHOLE) {
		fp_del_nh4_hash(fp_nh4_hash(nh->nh_gw, nh->nh.nh_ifuid), index);
		tail = fp_shared->fp_nh4_available_tail;

		if (!tail)
			/* There is no free node in the list */
			fp_shared->fp_nh4_available_tail = fp_shared->fp_nh4_available_head = index;
		else
			fp_shared->fp_nh4_table[tail].next = fp_shared->fp_nh4_available_tail = index;

		fp_shared->fp_nh4_table[index].next = 0;
	}

	nh->nh.nh_refcnt--;
	return;
}

/*
 * NH entries are stored in a single table, and 
 * free one are just detected by their refcnt.
 *
 * Note; if fct is called in lookup mode (i.e. create = FALSE)
 * no refcnt is managed, it is up to the caller to do it.
 */
static uint32_t fp_find_nh4_entry(uint32_t gw, uint32_t ifuid, uint32_t rt_type, int create, fp_nh_mark_t *nh_mark)
{
	fp_nh4_entry_t *nh;
	uint32_t i;

	if (IS_RT_NONEXTHOP(rt_type)) {
		if (rt_type == RT_TYPE_ROUTE_LOCAL)
			i = FP_IPV4_NH_ROUTE_LOCAL;
		else
			i = FP_IPV4_NH_ROUTE_BLACKHOLE;

		fp_nh4_get(i);
		return i;
	}

	i = fp_nh4_lookup(gw, ifuid, rt_type, nh_mark);

	if (i) {
		/*
		 *In create mode, just add ref to the found
		 * entry, to keep behaviour identical to the
		 * real creation.
		 */
		if (create) {
			fp_nh4_get(i);

			/*
			 * On an neighbor add command, a next-hop
			 * can be promoted
			 */
			nh = &fp_shared->fp_nh4_table[i];

	                if ((rt_type == RT_TYPE_NEIGH) &&
			    (nh->nh.rt_type == RT_TYPE_ROUTE))
			        nh->nh.rt_type = RT_TYPE_NEIGH;
		}
		return i;
	}

	/*
	 * Nothing found, but if a free slot exists, just use it
	 * be sure to have a NONE state at creation.
	 */

	/* All nodes were used in the list, return NULL */
	if (!fp_shared->fp_nh4_available_head)
		return 0;

	if (create) {
		i = fp_shared->fp_nh4_available_head;
		fp_shared->fp_nh4_available_head = fp_shared->fp_nh4_table[i].next;

		/* all nodes are being used */
		if (!fp_shared->fp_nh4_available_head)
			fp_shared->fp_nh4_available_tail = 0;

		fp_add_nh4_hash(fp_nh4_hash(gw, ifuid), i);

		nh = &(fp_shared->fp_nh4_table[i]);
		nh->nh.nh_l2_state = L2_STATE_NONE;
		nh->nh_gw = gw;
		nh->nh.nh_ifuid = ifuid;
		nh->nh.nh_hitflag = 0;
#ifdef CONFIG_MCORE_NEXTHOP_MARKING
		if (nh_mark && nh_mark->mark) {
			nh->nh.nh_mark = nh_mark->mark;
			nh->nh.nh_mask = nh_mark->mask;
		} else {
			nh->nh.nh_mark = 0;
			nh->nh.nh_mask = 0;
		}
#endif
		if ((rt_type == RT_TYPE_ADDRESS) ||
		    (nh->nh_gw && rt_type != RT_TYPE_ROUTE_CONNECTED))
			nh->nh.nh_type = NH_TYPE_GW;
		else
			nh->nh.nh_type = NH_TYPE_IFACE;
		nh->nh.rt_type = rt_type;
		nh->nh.nh_priority = fp_nh_priority(&(nh->nh));
		fp_nh4_get(i);
	}
	return i;
}

/*
 * get/put to manage refcount on RT entries
 */
static inline void fp_rt4_mget(uint32_t index, uint32_t inc)
{
	fp_rt4_entry_t *entry;
	entry = &fp_shared->fp_rt4_table[index];
	/*
	 * Here we could manage some free list management
	 * if (! entry->refcnt)
	 *    ...
	 */
	entry->rt.rt_refcnt += inc;
	return;
}

/*
 * Decrease-and-release fct for RT entries
 */
static inline void fp_rt4_mput(uint32_t index, uint32_t inc)
{
	fp_rt4_entry_t *entry;
	entry = &fp_shared->fp_rt4_table[index];
	/*
	 * Here we could manage some free list management
	 * if (! entry->refcnt)
	 *    ...
	 * 
	 */
	entry->rt.rt_refcnt -= inc;
	return;
}

#define fp_rt4_get(e)  fp_rt4_mget((e), 1)
#define fp_rt4_put(e)  fp_rt4_mput((e), 1)

/*
 * RT entries (in fact routes) are stored in a single table, and 
 * free one are just detected by their refcnt.
 *
 * This same large table can be used in case of VRF, hence allowing
 * to share a common pool rather than having to provision a per VRF
 * quota.
 */
static unsigned int fp_new_rt4_entry(void)
{
	unsigned int i;

	/*
	 * If we ever want to switch to a more efficent way of searching
	 * such as keeping a bit-field of used entries, this bit set/reset
	 * should be done in the fp_rt4_get/put fcts.
	 *
	 * We search from the last-added entry to the top. If we don't find
	 * a free entry, we start from bottom of table upto last-added.
	 */
	for (i = fp_shared->fp_rt4_last_added; i < FP_IPV4_NBRTENTRIES; i++) {
		if (fp_shared->fp_rt4_table[i].rt.rt_refcnt == 0) {
			fp_rt4_get(i);
			fp_shared->fp_rt4_last_added = i;
			return i;
		}
	}
	/* No free slot found in upper part -> search from start */
	for (i = 1; i < fp_shared->fp_rt4_last_added; i++) {
		if (fp_shared->fp_rt4_table[i].rt.rt_refcnt == 0) {
			fp_rt4_get(i);
			fp_shared->fp_rt4_last_added = i;
			return i;
		}		
	}
   
	return 0;
}

/*
 * One or several next-hop may have their status changed
 * which needs a full re-scan of next-hop atributes
 */
void fp_rt4_nh4_reorder(fp_rt4_entry_t *rte, int refresh, fp_rt4_entry_t *rte_out)
{
	fp_rt4_entry_t ro;
	int i,j, insert;
	uint8_t best_prio = 0;

	/*
	 * Fresh rt-entry is identical except NH order
	 * This tries at most to keep the same order, hence insertion
	 * are done at the END of each type.
	 */
	ro = *rte;
	ro.rt.rt_nb_nh=0;
	ro.rt.rt_nb_nhp=0;
	for (i=0; i<rte->rt.rt_nb_nh; i++) {
		uint8_t local_prio;
		fp_nh4_entry_t *nhe;

		nhe = &fp_shared->fp_nh4_table[rte->rt.rt_next_hop[i]];
		if (refresh)
			nhe->nh.nh_priority = fp_nh_priority (&(nhe->nh));
		local_prio = nhe->nh.nh_priority;
		/*
		 * If we are handling the route for the ARP entry, this one
		 * must enforce ARP weight on the ARP next-hop(s)
		 */
		local_prio += fp_nh4_neigh_prio (rte, nhe);

		if  (local_prio > best_prio) {
			insert = 0;
			ro.rt.rt_nb_nhp = 1;
			best_prio = local_prio;
		} else if (local_prio == best_prio) {
			insert = ro.rt.rt_nb_nhp;
			ro.rt.rt_nb_nhp++;
		}
		else
			insert = ro.rt.rt_nb_nh;
		for (j=ro.rt.rt_nb_nh;  j > insert; j--)
			ro.rt.rt_next_hop[j] = ro.rt.rt_next_hop[j-1];
		ro.rt.rt_nb_nh++;
		ro.rt.rt_next_hop[insert] = rte->rt.rt_next_hop[i];
	}
	if (rte_out)
		*rte_out = ro;
	else
		*rte = ro;
}

static void
fp_rt4_nh4_check_neigh (fp_rt4_entry_t *rte, uint32_t addr)
{
	int i;

	/*
	 * If the entry was NOT a neighbor, it can not become one
	 * Only a /32 wan host real ARP entry
	 */
	if (rte->rt.rt_neigh_index == 0)
		return;
	if (rte->rt.rt_length != 32)
		return;

	rte->rt.rt_neigh_index = 0;

	for (i = 0 ; i < rte->rt.rt_nb_nh ; i++) {
		int ni = rte->rt.rt_next_hop[i];
		fp_nh4_entry_t *nhe = &fp_shared->fp_nh4_table[ni];
		if ((nhe->nh.rt_type == RT_TYPE_NEIGH) && (addr == nhe->nh_gw)){
			rte->rt.rt_neigh_index = ni;
			break;
		}
	}
}

/*
 * L3 indirection tables entries are stored in a single table, and 
 * free one are just detected by their "use". It merely points inside 
 * the big list of routes
 *
 * This same table can be used in case of VRF, hence allowing to share 
 * a common pool rather than having to provision a per VRF  quota.
 *
 * For IPv4 version we only use 8-bits wide indirection table
 */
static unsigned int fp_new_ln_table4(uint16_t vrfid)
{
	unsigned int i;

	/*
	 * If we ever want to switch to a more efficent way of searching
	 * such as keeping a bit-field of used entries, all used=0 MUST be 
	 * tracked down, to be replaced by some macro TB_FREE() (managing 
	 * both decrease and bit release)
	 */
	for (i = 1; i < FP_NB_8_TABLE_ENTRIES; i++) {
		if (!fp_shared->fp_8_table[i].used)
		{
			fp_shared->fp_8_table[i].used = FP_USED_V4;
			fp_shared->fp_8_table[i].vrfid = vrfid;
			/* .entries is initiliazed to i * (1 << 8) */

			/*
			 * Table allocation is usually followed by an harsh 
			 * duplication of higher level entry, so this clean-up
			 * is just conservative.
			 */
			bzero (fp_shared->fp_8_entries + 
					fp_shared->fp_8_table[i].entries, 
			       (1<<8) * sizeof(fp_table_entry_t));
			return i;
		}
	}
	return 0;
}

/*
 * Hard-coded table linkage into address field split
 * i.e. 16+8+8 tables
 */
static inline int fp_baseIndex4(uint32_t addr, int level)
{
#ifdef CONFIG_MCORE_RT_IP_BASE8
	uint8_t *ba = (uint8_t *)&addr;
	return (ba[level]);
#else
	uint32_t result = 0;
	addr = ntohl(addr);
	if (level == 0)
		result = addr>>16 & 0xFFFF;
	else if (level == 1)
		result = (addr >> 8) & 0xFF;
	else 
		result = addr&0xFF;
	
	return result;
#endif
}

/* 
 * Insert entry in the routes chain starting at head,
 * sorted by decreasing length 
 */
static void update_route4_chain(fp_rt4_entry_t *head, fp_rt4_entry_t *entry, 
		uint32_t index)
{
	fp_rt4_entry_t *next;

	/*
	 * Just looking where to insert the entry. The case were new 
	 * entry is head of chain is detected by the caller and NOT 
	 * managed in this function...
	 */
	while (head->rt.rt_next) {
		next = &fp_shared->fp_rt4_table[head->rt.rt_next];
		if (next->rt.rt_length < entry->rt.rt_length)
			break;
		head = next;
	}
 
    /*
     * Same length means the chain is updated
	 */
	if (head->rt.rt_length == entry->rt.rt_length)
		return;
	/*
	 * If entry is already a chain, we are inserting something
	 * that aggregates linkrs, so decrease the refcnt of 
	 * entry->next.
	 *
	 * example:
	 * 2 /15 point to a same /13, and we insert a /14 in between.
	 * on the first /15 set, the /14 is inserted, which will be done
	 * only on ONE of the two associated /16. So far so good.
	 * When the 2nd /15 set is handled, we do have a real insertion,
	 * but the link /14 --> /13 is already done, which means that the /13
	 * will loose its /15 ancestors, therefore there is no more any new 
	 * pointer pointing to it: we need to decrease ref counter.
	 */ 
	if (entry->rt.rt_next) 
		fp_rt4_put(entry->rt.rt_next);
	entry->rt.rt_next = head->rt.rt_next;
	head->rt.rt_next = index;
	fp_rt4_get(index);
}

/*
 * Now we have direct acces to the (sub)table that includes the fixed
 * length entries that provides decomposition of our new route
 * we have to
 *   - select the initial index,  and witdh for the route in this
 *     table. e.g. a /14 route is in the primary, and its witdht is 4
 *   - for each of those entries do the udpate
 *     + entry is empty: fill it
 *     + entry is and indirect table: recursion within this subtable
 *       the subsequent width/index computation will address ALL entries
 *       in the subtable
 *     + entry is an RT entry: update the RT chain
 *         = we insert a more precise (longest) route, do HEAD insertion
 *         = we insert a less precise (shortest) route, go inside the RT chain
 */
static void update_route4(fp_table_entry_t *table, int level, uint32_t addr,
                     uint8_t length, uint32_t rt_index, fp_rt4_entry_t *entry)
{
	int i = 0;
	int base = fp_baseIndex4(addr, level);
	int nb_entries = 0;

#ifdef CONFIG_MCORE_RT_IP_BASE8
	int tlevel;
	if (length)
		tlevel = (length-1)/8 ;
	else
		tlevel = 0;
	if (level > tlevel) {
		nb_entries = 256;
		base = 0;
	} else if (level == tlevel)
		nb_entries = 1<<(8*(1+tlevel) - length);
	else
		nb_entries = 1;
#else
	// to be simplified...
	if (length > 24) {
		if (level == 2) {
			nb_entries = 1<<(32-length);
		} else {
			nb_entries = 1;
		}
	} else if (length > 16) {
		if (level > 1) {
			nb_entries = 256;
			base = 0;
		} else if (level == 1) {
			nb_entries = 1<<(24-length);
		} else {
			nb_entries = 1;
		}
	} else {
		if (level > 0) {
			nb_entries = 256;
			base = 0;
		} else if (level == 0)
			nb_entries = 1<<(16-length);
		else {
			nb_entries = 1;
		}
	}
	// to be simplified...
#endif

	/*
	 * sweep all entries concerned by this route
	 */
	for (i = base; i < base + nb_entries; ++i) {
		if (table[i].index == RT_INDEX_UNUSED) {
			/* 
			 * Nothing, just a very NEW entry creation
			 */
			fp_table_entry_t e = { .rt = RT_ROUTE, .index = rt_index };
			table[i] = e;
			fp_rt4_get(rt_index);
		} else if (table[i].rt == RT_TABLE) {
			/* 
			 * We have found an indirection level: just go
			 * deeper and jump to the lower table level
			 */
			int idx = fp_shared->fp_8_table[table[i].index].entries; 
			update_route4 (fp_shared->fp_8_entries + idx, level + 1, 
			              addr, length, rt_index, entry);
		} else {
			/*
			 * Here we are reaching RT table, i.e. final routes
			 * what is needed is RT chain update
			 */
			fp_rt4_entry_t *head;
			head = &fp_shared->fp_rt4_table[table[i].index];
			if (head->rt.rt_length == length) {
				/*
				 * This case MUST not happen since we rely on 
				 * upper caller NOT to add the same route 
				 * twice.
				 */
				;
			} else if (head->rt.rt_length < length) {
				/*
				 * The new entry is meant to be linked to less 
				 * precise entry. This will be done ONCE for 
				 * ALL, and subsequent insertion will find 
				 * linkage already done.
				 */
				if (!(entry->rt.rt_next) && table[i].index) {
					entry->rt.rt_next = table[i].index;
					/* 
					 * New linkage count
					 */
					fp_rt4_get(table[i].index);
				}

				fp_table_entry_t e = { 
					.rt = RT_ROUTE, 
					.index = rt_index 
				};
				/*
				 * Now the insertion part, with a refcnt shift
				 * from the succesor (if present) to the entry
				 */
				if (table[i].index) 
					fp_rt4_put(table[i].index);
				table[i] = e;
				fp_rt4_get(rt_index);
			} else {
				/*
				 * Insert the entry inside the chain: it won't
				 * be used for forwarding but to be kept, in
				 * case the more precise route is removed
				 */
				update_route4_chain(head, entry, rt_index);
			}
		}
	}
}

/*
 * Internal route manager:
 *
 * WARNING
 *    this code won't work if the route already exists
 *    results are un-predictible.
 * WARNING
 *
 */ 
static uint32_t __fp_add_route4(fp_table_entry_t *entries, uint16_t vrfid, uint32_t addr, uint8_t length, uint32_t gateway, uint32_t ifuid, uint32_t rt_type, fp_nh_mark_t *nh_mark)
{
	fp_rt4_entry_t *entry;
	uint32_t rt_index;
	uint32_t nh_index;
	int nbLevel = 0;
	int level = 0;
	int i;

	rt_index = fp_new_rt4_entry();
	if (rt_index == 0)
		return 0;
	entry = &(fp_shared->fp_rt4_table[rt_index]);
	entry->rt.rt_length = length;
#ifdef CONFIG_MCORE_RT4_WITH_PREFIX
	entry->rt4_prefix = addr;
#endif
	entry->rt.rt_vrfid = vrfid;
	entry->rt.rt_next = 0;
	entry->rt.rt_neigh_index = 0;

	/* Create/Check a nexthop entry */
	nh_index = fp_find_nh4_entry(gateway, ifuid, rt_type, 1, nh_mark);
	/*
	 * Impossible to get/create the next-hop, free the route
	 * and return the failure
	 */
	if (!nh_index) {
		fp_rt4_put(rt_index);
		return 0;
	}

	/* Mark special entry used for ARP */
	if (rt_type == RT_TYPE_NEIGH)
		entry->rt.rt_neigh_index = nh_index;

	/*
	 * When a new rt_entry is created, we  create the very first
	 * Next-Hop, so we can safely write next-hop number 0
	 */
	entry->rt.rt_next_hop[0] = nh_index;
	entry->rt.rt_nb_nh = 1;
	entry->rt.rt_nb_nhp = 1;

#ifdef CONFIG_MCORE_RT_IP_BASE8
	/*
	 * Hard-coded level detemination (8+8+8+8)
	 */
	if (length)
		nbLevel = (length-1) / 8;
#else
	/*
	 * Hard-coded level detemination (16+8+8)
	 */
	if (length > 16) {
		if (length > 24)
			nbLevel = 2;
		else
			nbLevel = 1;
	}
#endif
	while (level < nbLevel) {
		i = fp_baseIndex4(addr, level);
		if (entries[i].rt || (entries[i].index == 0)) {
			/* 
			 * Until we reach final table level, we expect to find
			 * reference to indirection tables. If the current entry
			 * is either empty or an RT entry, the we must
			 *  - create a sub table
			 *  - populate it with RT entries copied from intial one
			 *    if it was an RT.
			 */
			uint32_t index = fp_new_ln_table4(vrfid);
			if (entries[i].rt) {
				int base = fp_shared->fp_8_table[index].entries;
				int j;

				for (j = 0; j < (1<<8); j++)
					fp_shared->fp_8_entries[base + j] = entries[i];
				/*
				 * Refcount usage goes up from 1 to a full sub-table width
				 */
				fp_rt4_mget(entries[i].index, (1<<8) - 1);
			}
			fp_table_entry_t e = { 
				.rt = RT_TABLE, 
				.index = index 
			};
			entries[i] = e;
		}
		/*
		 * else: the entry point to a sub-table, OK, nothing to create
		 * Here we can assume entry point to a sublevel (possibily
		 * freshly created) and walk through it
		 */
		int table_idx = fp_shared->fp_8_table[entries[i].index].entries;
		entries = &fp_shared->fp_8_entries[table_idx];
		level = level + 1;
	}

	/*
	 * table is here pointing to the primary table, or any
	 * indirect table, all have the same structure. Recursion
	 * level is provided by "level"
	 */
	update_route4(entries, level, addr, length, rt_index, entry);
	/*
	 * Now we can release the entry, (implicit _get() done by
	 * initial allocation).
	 */
	fp_rt4_put(rt_index);

	return rt_index;
}

#if 0 /* not optimal, but supports N levels of L3LN tables */
static inline fp_rt4_entry_t *find_route4(uint16_t vrfid, uint32_t addr)
{

need to be updated wrt
 - new names,
 - VRF
 - change in t.rt semantic

	fp_rt4_entry_t * route = 0;
	table_entry_t *entries = fp_shared->entries;
	table_entry_t* table = entries + fp_shared->l3_table.entries;
	fp_l3_table_t *l3ln_table = fp_shared->l3ln_table;
	int level = 0;
	int i = 0;
	while (route == 0) {
		i = fp_baseIndex4(addr, level++);
		table_entry_t t = table[i];
		if (t.rt) {
			if (t.index)
				route = &fp_shared->fp_rt4_table[t.index];
			else
				break;
		} else if (t.index) {
			table = entries + l3ln_table[t.index].entries;
		} else {
			break;
		}
	}
	return route;
}
#else
#define find_route4(x,y) fp_rt4_lookup(x,y)
#endif

/*
 * Here we do NOT search the best possible route, we search
 * if the route (including length) exists.
 *
 * The assumption is the prefix does not have any bit set outside
 * the mask width.
 */
fp_rt4_entry_t *fp_get_exact_route4(uint16_t vrfid, uint32_t prefix, uint8_t len)
{
	fp_rt4_entry_t *entry;
	/*
	 * First do a standard best route search. 
	 */
	entry = find_route4(vrfid, prefix);
	if (!entry)
		return NULL;
	/*
	 * knowing prefix has no bit out of the mask, 
	 * prefix/len is a route that overlaps with found route
	 * hence is stored in the RT chain
	 */
	while (entry) {
		if (entry->rt.rt_length == len)
			return entry;
		if (entry->rt.rt_next)
			entry  = &fp_shared->fp_rt4_table[entry->rt.rt_next];
		else
			entry = NULL;
	}
	return NULL;
}

/*
 * Currently neighbours entries are those routes with
 * RT type set to RT_TYPE_NEIGH.
 */
static fp_rt4_entry_t * __find_neighbour4(uint32_t addr, uint32_t ifuid)
{
	fp_rt4_entry_t *entry;
	uint16_t vrfid;

	if (!ifuid)
		return NULL;
	vrfid = ifuid2vrfid(ifuid);

	if (vrfid >= FP_MAX_VR) 
		return NULL;

	entry = fp_get_exact_route4(vrfid, addr, 32);
	if (entry && entry->rt.rt_neigh_index != 0)
			return entry;

	return NULL;
}
/*
 * Try to create a new route.
 *    0: OK
 *    1: some error occured
 *    2: route and next-hop already exist, nothing was done.
 */
#define FP_CREATE_RT_ERROR 1
#define FP_CREATE_RT_EXIST 2
static uint32_t fp_create_route4_nhmark(uint16_t vrfid, uint32_t addr, uint8_t length, 
              uint32_t next, uint32_t ifuid, uint8_t type, fp_nh_mark_t *nh_mark)
{
	fp_rt4_entry_t *entry;
	uint32_t rt_index;

	/*
	 * Routes with no nexthop don't need sanity check
	 */
	if (!IS_RT_NONEXTHOP(type)) {
		fp_ifnet_t *ifp = fp_ifuid2ifnet(ifuid);
		if (fp_ifnet_is_invalid(ifp))
			return FP_CREATE_RT_ERROR;
	}

	if (vrfid >= FP_MAX_VR)
		return FP_CREATE_RT_ERROR;
	/*
	 * If a route already exists, it is just a matter of inserting a
	 * new next-hop, else, a full route creation is needed.
	 */
	entry = fp_get_exact_route4(vrfid, addr, length);

	if (entry) {
		uint32_t nh;
		int i;

		/*
		 * find or allocate a next-hop
		 */
		nh = fp_find_nh4_entry(next, ifuid, type, 1, nh_mark);
		if (!nh)
			return FP_CREATE_RT_ERROR;
		/*
		 * Sanity check, to protect against double insertion
		 */
		for (i = 0; i < entry->rt.rt_nb_nh; i++) {
			if (entry->rt.rt_next_hop[i] == nh)  {
				fp_nh4_put(nh);
				return FP_CREATE_RT_EXIST;
			}
		}
		/*
		 * Check against too many mpath.
		 * If OK, just a new path i.e. next-hop.
		 */
		if (i == FP_MAX_MPATH) {
			fp_nh4_put(nh);
			return FP_CREATE_RT_ERROR;
		}

		/*
		 * If it's the first NEIGH entry, mark it otherwise,
		 * keep the current neigh best candidate
		 */
		if (type == RT_TYPE_NEIGH) {
			if (entry->rt.rt_neigh_index == 0)
				entry->rt.rt_neigh_index = nh;
		}

		/*
		 * If this is an ARP route, we'll have to do a full
		 * re-order, as neighbour weight is not part of next-hop
		 * priority.
		 */
		if (entry->rt.rt_neigh_index) {
			entry->rt.rt_next_hop[entry->rt.rt_nb_nh] = nh;
			entry->rt.rt_nb_nh++;
			fp_rt4_nh4_reorder (entry, 0, NULL);
		} else {
			int pos;
			fp_nh4_entry_t *nhe;
			uint8_t best_prio;

			nhe = &fp_shared->fp_nh4_table[nh];
			best_prio = fp_best_nh4_prio (entry);
			/*
			 * Priority of the 1st next-hop is the current best
			 * best priority. If new one is better, create a new
			 * class, if lower, don't bother keeping a strict order.
			 */
			if  (nhe->nh.nh_priority > best_prio) {
				pos = 0;
				entry->rt.rt_nb_nhp = 1;
			} else if  (nhe->nh.nh_priority == best_prio) {
				pos = 0;
				entry->rt.rt_nb_nhp++;
			}
			else
				pos = entry->rt.rt_nb_nh;
			for (i = entry->rt.rt_nb_nh; i > pos; i--)
				entry->rt.rt_next_hop[i] = entry->rt.rt_next_hop[i-1];
			entry->rt.rt_next_hop[pos] = nh;
			entry->rt.rt_nb_nh++;
		}

		/*
		 * Compute index out of existing entry.
		 */
		rt_index = (entry - &fp_shared->fp_rt4_table[0]);
	}
	else {
		/* 
		 * entries should first point to the first level table, i.e. the one
		 * provided thanks to fp_XX_table.
		 */
#ifdef CONFIG_MCORE_RT_IP_BASE8
		uint32_t tidx = fp_shared->fp_8_table[vrfid].entries;
		fp_table_entry_t *entries = &fp_shared->fp_8_entries[tidx];
#else
		uint32_t tidx = fp_shared->fp_16_table[vrfid].entries;
		fp_table_entry_t *entries = &fp_shared->fp_16_entries[tidx];
#endif

		rt_index = __fp_add_route4(entries, vrfid, addr, length,
					next, ifuid, type, nh_mark);
	}
	if (rt_index == 0)
		return FP_CREATE_RT_ERROR;
	else
		return 0;
}

uint32_t fp_add_route4(uint16_t vrfid, uint32_t addr, uint8_t length, 
              uint32_t next, uint32_t ifuid, uint8_t type)
{
	uint32_t res;

	res = fp_create_route4_nhmark(vrfid, addr, length, next, ifuid, type, NULL);
	if (res && (res != FP_CREATE_RT_EXIST))
		return FP_CREATE_RT_ERROR;

	return 0;
}

uint32_t fp_add_route4_nhmark(uint16_t vrfid, uint32_t addr, uint8_t length,
              uint32_t next, uint32_t ifuid, uint8_t type, fp_nh_mark_t *nh_mark)
{
        uint32_t res;

        res = fp_create_route4_nhmark(vrfid, addr, length, next, ifuid, type, nh_mark);
        if (res && (res != FP_CREATE_RT_EXIST))
                return FP_CREATE_RT_ERROR;

        return 0;
}
/*
 * Now we have direct access to the (sub)table that includes the fixed
 * length entries that provides decomposition of our new route
 * we have to
 *   - select the initial index,  and width for the route in this
 *     table. e.g. a /14 route is in the primary, and its width is 4
 *   - for each of those entries do the update
 *     + entry is empty: nothing (should only happen for deleting a
 *                       non existing route)
 *     + entry is an indirect table: recursion within this subtable
 *       the subsequent width/index computation will address ALL entries
 *       in the subtable
 *     + entry is an RT entry: update the RT chain
 *   - at the end of each recursion level:
 *     + check if the subtable is usefull (i.e. at least two routes are 
 *       different) and provide result to the caller
 *     + more ?
 */
static int __fp_delete_route4(fp_table_entry_t* entries, int level,
                              uint32_t addr, int length, uint32_t *premove)
{
	int i = 0;
	int base = fp_baseIndex4(addr, level);
	int nb_entries = 1;
#ifdef CONFIG_MCORE_RT_IP_BASE8
	int tlevel;
	if (length)
		tlevel = (length-1)/8 ;
	else
		tlevel = 0;
	if (level > tlevel) {
		nb_entries = 256;
		base = 0;
	} else if (level == tlevel)
		nb_entries = 1<<(8*(1+tlevel) - length);
	else
		nb_entries = 1;
#else
	// to be simplified...
	if (length > 24) {
		if (level == 2) {
			nb_entries = 1<<(32-length);
		} else {
			nb_entries = 1;
		}
	} else if (length > 16) {
		if (level > 1) {
			nb_entries = 256;
			base = 0;
		} else if (level == 1) {
			nb_entries = 1<<(24-length);
		} else {
			nb_entries = 1;
		}
	} else {
		if (level > 0) {
			nb_entries = 256;
			base = 0;
		} else if (level == 0)
			nb_entries = 1<<(16-length);
		else {
			nb_entries = 1;
		}
	}
#endif
	
	for (i = base; i < base + nb_entries; ++i) {
		if (entries[i].index == 0) {
			/* 
			 * Empty slot: should not occur
			 */
			;
		} else if (entries[i].rt == 0) {
			/* 
			 * We have found an indirection level: just go
			 * deeper and jump to the lower table level
			 */
			fp_table_t *subtable = 
					&fp_shared->fp_8_table[entries[i].index];
			int packing;

			packing = __fp_delete_route4(
			        fp_shared->fp_8_entries + subtable->entries, 
					level + 1, addr, length, premove);
			/*
			 * If it was the last specific route of the next table, 
			 * then remove this indirection table 
			 * (recursive approach)
			 */
			if (packing) {
				/*
				 * First copy here first entry of the subtable.
				 * ALL entries of the subtable are identical.
				 */
				entries[i] = fp_shared->fp_8_entries[subtable->entries];
				/*
				 * And refcount except first entry (width of subtable - 1)
				 */
				if(entries[i].index != 0)
					fp_rt4_mput(entries[i].index, (1<<8) - 1);
				/*
				 * Clear subtable, if we ever have several kind 
				 * of indirection subtables, each one should 
				 * include its level, so that we can derive its
				 * width.
				 */
				bzero (fp_shared->fp_8_entries + subtable->entries, 
				       (1<<8) * sizeof (fp_table_entry_t));
				subtable->used = 0;
			}
		} else  {
			/*
			 * Here we are reaching RT table, i.e. final routes.
			 * What is needed is RT chain update
			 */
			fp_rt4_entry_t *head;
			head = &fp_shared->fp_rt4_table[entries[i].index];
			if (head->rt.rt_length == length) {
				/*
				 * Keep a single reference on the entry to be 
				 * removed for final cleaning
				 */
				if (! *premove) {
					 *premove = entries[i].index;
					fp_rt4_get(*premove);
				}
				/*
				 *
				 * We hit he HEAD of chain, so remove it.
				 * There is a refcnt shift as we remove 
				 * intermediate entry, so make it on refcnt. 
				 * We rely on the end of this fct to do the last
				 * decrement of remove->next
				 */
				if (head->rt.rt_next)
					fp_rt4_get(head->rt.rt_next);

				fp_rt4_put(entries[i].index);
				entries[i].index = head->rt.rt_next;
				/*
				 * If this was the last element of chain, just mark the 
				 * entry as not an RT anymore. should be equivalent to
				 *  table[i].rt = head->rt  ?
				 */
				if (entries[i].index == 0)
					entries[i].rt = 0;
			} else {
				/*
				 * Just looking for the entry to remove. 
				 * The case where old entry is head of chain is
				 * detected by the previous case and NOT managed
				 * here.  So there will ALWAYS be an ancestor 
				 * (more precise route)
				 */
				fp_rt4_entry_t *next = 0;

				while (head->rt.rt_next) {
					next = &fp_shared->fp_rt4_table[head->rt.rt_next];
					if (next->rt.rt_length == length) {
						/*
						 * Keep a single reference on 
						 * the entry to be removed
						 * for final cleaning. 
						 * And count how many subsequent
						 * removals are done 
						 */
						if (! *premove) {
							*premove = head->rt.rt_next;
							fp_rt4_get(*premove);
						} 
						/*
						 * There is a refcnt shift as 
						 * we remove intermediate entry,
						 * so make it on refcnt. 
						 * We rely on the end of this 
						 * fct to do the last decrement
						 * of remove->next
						 */
						if (next->rt.rt_next) 
							fp_rt4_get(next->rt.rt_next);
						fp_rt4_put(head->rt.rt_next);
						head->rt.rt_next = next->rt.rt_next;
						/*
						 * OK, we found it, no use to 
						 * search further
						 */
						break;
					}
					head = next;
				}
			}
		}
	}
	/*
	 * OK we have found an entry to remove from table. It is still
	 * hanging thanks to the initial fp_rt4_get(). The last cleaning
	 * part is to deconnect it from subsequent RT chain.
	 *
	 * The premove is transmitted along with the recursive calls,
	 * and ONLY the first level (i.e level 0) is allowed to to the final
	 * clean-up. This is because a single deletion may sapn across
	 * several sub-tables.
	 */
	if ((level == 0) && (*premove)) {
		fp_rt4_entry_t *rr;
		rr = &fp_shared->fp_rt4_table[*premove];
		if (rr->rt.rt_next) {
			fp_rt4_put(rr->rt.rt_next);
			rr->rt.rt_next = 0;
		}
		/*
		 * Release the next hop associated to the dying route
		 * As the routes disappears ONLY when the last next-hop  is
		 * removed, we can safely assume working on nh number 0
		 */
		if (rr->rt.rt_nb_nh) {
			fp_nh4_put(rr->rt.rt_next_hop[0]);
			rr->rt.rt_nb_nh = 0;
			rr->rt.rt_nb_nhp = 0;
		}
		fp_rt4_put(*premove);
	}

	/*
	 * If ALL entries are identical, this means that the last more
	 * specific routes was removed, and so a single entry at previous
	 * level is enough to sum-up route description.
	 * Subtable release is done by the recursive caller. As the top-level
	 * table MUST NEVER be released, freeing at recursive level is enough.
	 */
	if (level > 0) { 
		uint32_t rt = entries[0].rt;
		uint32_t index = entries[0].index;

		for (i = 1; i < 256; i++) {
			if  ((entries[i].index != 0 && entries[i].rt != rt)
			     || entries[i].index != index)
				return 0;
		}
		return 1;
	}

	return 0;
}

/*
 * wrapper, for hiding table levels stuff
 */
uint32_t fp_delete_route4_nhmark(uint16_t vrfid, uint32_t addr, uint8_t length, 
                         uint32_t gw, uint32_t ifuid, uint8_t rt_type, fp_nh_mark_t *nh_mark)
{
	uint32_t nh = 0;
	uint32_t remove = 0;
	fp_rt4_entry_t *rte;
	int i,j;
	uint32_t tidx;
	fp_table_entry_t *entries;

	if (vrfid > FP_MAX_VR)
		return 1;

	/*
	 * There MUST be some next-hop associated to the route
	 * as well as an exact match for the route.
	 */
	rte = fp_get_exact_route4(vrfid, addr, length);
	if (rte == NULL)
		return 0;

	nh = fp_find_nh4_entry(gw, ifuid, rt_type, 0, nh_mark);
	if (!nh)
		return 0;

	for (i = 0 ; i < rte->rt.rt_nb_nh ; i++) {
		if (rte->rt.rt_next_hop[i] == nh)
			break;
	}
	/*
	 * The provided next-hop doesn't exist !
	 */
	if (i == rte->rt.rt_nb_nh)
		return 0;
	else {
		fp_nh4_entry_t *nhe = &fp_shared->fp_nh4_table[nh];

		/*
		 * This NH is no longer used by an ARP route entry
		 * so downgrade to ROUTE type
		 */
		if ((rt_type == RT_TYPE_NEIGH) && (nhe->nh.rt_type == RT_TYPE_NEIGH)) {
			nhe->nh.rt_type = RT_TYPE_ROUTE;
		}
	}

	/*
	 * In case of real mpath route, just remove the next-hop
	 * but keep the route itself.
	 */
	if (rte->rt.rt_nb_nh > 1) {
		for (j = i; j < (rte->rt.rt_nb_nh - 1); j++)
			rte->rt.rt_next_hop[j] = rte->rt.rt_next_hop[j+1];
		/*
		 *  Adjust Preferred counts
		 */
		if (i < rte->rt.rt_nb_nhp)
			rte->rt.rt_nb_nhp--;
		rte->rt.rt_nb_nh--;
		if  ((rte->rt.rt_nb_nhp == 0) || (rte->rt.rt_neigh_index))
			fp_rt4_nh4_reorder (rte, 0, NULL);
		fp_nh4_put(nh);

		/* Check if at least on of the remaining nh is a neighbour */
		fp_rt4_nh4_check_neigh (rte, addr);

		return 0;
	}
	/*
	 * Only the last next-hop removal kills the route.
	 */

	/* 
	 * entries should first point to the first level table, i.e. the one
	 * provided thanks to fp_XX_table.
	 */
#ifdef CONFIG_MCORE_RT_IP_BASE8
	tidx = fp_shared->fp_8_table[vrfid].entries;
	entries = &fp_shared->fp_8_entries[tidx];
#else
	tidx = fp_shared->fp_16_table[vrfid].entries;
	entries = &fp_shared->fp_16_entries[tidx];
#endif

	__fp_delete_route4(entries, 0, addr, length, &remove);

	return 0;
}

void fp_rt4_ifscrub (const fp_ifnet_t *ifp)
{
	uint32_t ifuid = ifp->if_ifuid;
	int i, j;
	fp_rt4_entry_t local_rte;

	memset (&local_rte, 0, sizeof(local_rte));

	/*
	 * Any route using this interface must be removed
	 */
	for (i = 1; i < FP_IPV4_NBRTENTRIES; i++) {
		fp_rt4_entry_t *rte;
		int need_update = 0;

		rte = &fp_shared->fp_rt4_table[i];
		if (! rte->rt.rt_refcnt)
			continue;
		for (j=0; j<rte->rt.rt_nb_nh; j++) {
			fp_nh4_entry_t *nhe;
			nhe = &fp_shared->fp_nh4_table[rte->rt.rt_next_hop[j]];
			if ((nhe->nh.nh_ifuid == ifuid) &&
			    (nhe->nh.rt_type != RT_TYPE_ADDRESS)) {
				fp_nh4_put(rte->rt.rt_next_hop[j]);
				/*
				 * At least one NH to remove, so let's keep
				 * the remaining ones, starting wth the already
				 * parsed NH.
				 */
				if (!need_update) {
					local_rte = *rte;
					local_rte.rt.rt_nb_nh = j;
					need_update = 1;
				}
			} else if (need_update)
				local_rte.rt.rt_next_hop[local_rte.rt.rt_nb_nh++] =
					rte->rt.rt_next_hop[j];
		}
		if (need_update) {
			/*
			 * The set of remaining NH was stored in the order they
			 * were found. This need re-rodering.
			 */
			if  (local_rte.rt.rt_nb_nh) {
				fp_rt4_nh4_reorder (&local_rte, 0, rte);
				fp_rt4_nh4_check_neigh (rte, rte->rt4_prefix);
			} else {
				uint32_t tidx;
				fp_table_entry_t *entries;
				uint32_t remove = 0;
#ifdef CONFIG_MCORE_RT_IP_BASE8
				tidx = fp_shared->fp_8_table[rte->rt.rt_vrfid].entries;
				entries = &fp_shared->fp_8_entries[tidx];
#else
				tidx = fp_shared->fp_16_table[rte->rt.rt_vrfid].entries;
				entries = &fp_shared->fp_16_entries[tidx];
#endif
				/*
				 * As thre is no more NH,; we must remove the
				 * route from the tree.
				 * As all NH are already released, prevent the
				 * __fp_delete_route4 to release the 1st NH.
				 */
				rte->rt.rt_nb_nh = 0;
				__fp_delete_route4(entries, 0,
				          rte->rt4_prefix, rte->rt.rt_length,
				          &remove);

			}
			/*
			 * As it was the last route needing clean-up, no point
			 * scanning the rest of the table
			 */
			if (ifp->if_nb_rt4 == 0)
				break;
		}
	}
}

uint32_t fp_change_route4_nhmark(uint16_t vrfid, uint32_t addr, uint8_t length,
                         uint32_t gw, uint32_t ifuid, uint8_t rt_type,
                         fp_nh_mark_t *nh_mark)
{
	uint32_t nh;
	fp_rt4_entry_t *entry;
	fp_rt4_entry_t new_entry;
	int i, nb_kept;

	/* Interface must be valid (except blackhole routes) */
	if (rt_type != RT_TYPE_ROUTE_BLACKHOLE) {
		fp_ifnet_t *ifp = fp_ifuid2ifnet(ifuid);

		if (fp_ifnet_is_invalid(ifp))
			return 1;
	}

	if (vrfid > FP_MAX_VR)
		return 1;

	entry = fp_get_exact_route4(vrfid, addr, length);
	if (entry == NULL)
		return 1;
	nh = fp_find_nh4_entry(gw, ifuid, rt_type, 1, nh_mark);
	if (!nh)
		return 1;

	/*
	 * Scan all NH to check the one(s) that may come from internal
	 * routes (address, ARP entry). They must be kept; other must
	 * be released.
	 */
	new_entry = *entry;
	nb_kept = 0;
	for (i=0; i<entry->rt.rt_nb_nh; i++) {
		int keep;
		uint32_t ni = entry->rt.rt_next_hop[i];
		fp_nh4_entry_t *nhe = &fp_shared->fp_nh4_table[ni];

		keep =
		    /* ARP entry for this address */
		   (((nhe->nh.rt_type == RT_TYPE_NEIGH) &&
		     (addr == nhe->nh_gw)) ||
		    /* Address */
		    (nhe->nh.rt_type == RT_TYPE_ADDRESS));

		if (keep)
			new_entry.rt.rt_next_hop[nb_kept++] = ni;
		else
			fp_nh4_put(entry->rt.rt_next_hop[i]);
	}

	/* Add the new NH */
	new_entry.rt.rt_next_hop[nb_kept++] = nh;
	new_entry.rt.rt_nb_nh = nb_kept;

	/*
	 * Full re-order needed. This will copy the working entry into the
	 * running one.
	 * The full re-order rewrites the whole structure, but as pure ARP
	 * entries are kept, the neigh index can be kept.
	 */
	fp_rt4_nh4_reorder (&new_entry, 0, entry);

	return 0;
}

/*
 * This allows neighbour creation as well as neighbour update
 */
uint32_t fp_add_neighbour4(uint32_t addr, const uint8_t mac[6],
                           uint32_t ifuid, uint8_t state)
{
	fp_rt4_entry_t *entry;
	fp_nh4_entry_t *nh = NULL;
	uint32_t nh_index = 0;
	fp_ifnet_t *ifp = NULL;
	uint32_t neigh_res;
	uint16_t vrfid;
	int i;

	ifp = fp_ifuid2ifnet(ifuid);
	if(fp_ifnet_is_invalid(ifp))
		return 1;

	/*
	 * FPM calls twice fp_add_neighbour: incomplete then reachable state.
	 * This allows to prevent Slow Path flooding while the resolution is
	 * still in progress.
	 */

	vrfid = ifuid2vrfid(ifuid);
	/*
	 * Neighbours are stored as routing entries for the /32
	 * with a specific type.
	 *
	 * New neighbour
	 *   - full: this will create the route and the next-hop
	 *   - addr exists, but new interface: the route already exists, but
	 *     we'll manage ECMP
	 * Existing neighbour (same addr and interface)
	 *   - fp_add_route4 ECMP handling is protected against double
	 *     insertion and does nothing.
	 *   - The first look-up is to get the numbe rof next-hops,
	 */
	neigh_res = fp_create_route4_nhmark(vrfid, addr, 32, addr, ifuid,
	                                    RT_TYPE_NEIGH, NULL);
	if (neigh_res && (neigh_res != FP_CREATE_RT_EXIST))
		return 1;
	entry = fp_get_exact_route4(vrfid, addr, 32);
	if (entry == NULL)
		return 1;

	/*
	 * Several neighbours/routes can be present on different interfaces,
	 * and are managed as ECMP.
	 */
	for (i=0; i < entry->rt.rt_nb_nh; i++) {
		nh_index = entry->rt.rt_next_hop[i];
		nh = &fp_shared->fp_nh4_table[nh_index];
		if ((nh->nh.rt_type == RT_TYPE_NEIGH) &&
		    (nh->nh_gw == addr) &&
		    (nh->nh.nh_ifuid == ifuid))
			break;
	}
	if (i == entry->rt.rt_nb_nh)
		return 1;

	if (nh->nh.nh_hitflag)
		nh->nh.nh_hitflag = 0;
	nh->nh_gw = addr;
	nh->nh.nh_ifuid = ifuid;
	nh->nh.nh_eth.ether_type = htons(FP_ETHERTYPE_IP);
	memcpy(nh->nh.nh_eth.ether_dhost, mac, FP_ETHER_ADDR_LEN);

	/*
	 * Entry is directly created with source MAC address (if the index
	 * is provided), because the whole src-dst part of eth header is cached
	 */
	memcpy(nh->nh.nh_eth.ether_shost,
	       __fp_ifuid2ifnet(ifuid)->if_mac,
	       FP_ETHER_ADDR_LEN);

	nh->nh.nh_l2_state = state;

	/*
	 * A full reordering is needed, as the
	 * priority stored in nh is not enough.
	 */
	fp_rt4_nh4_reorder (entry, 0, NULL);

	return 0;
}

uint32_t fp_delete_neighbour4(uint32_t addr, uint32_t ifuid)
{
	fp_rt4_entry_t *rte;
	fp_nh4_entry_t *nhe = NULL;
	uint32_t nh_index = 0;
	uint16_t vrfid;
	fp_ifnet_t *ifp = NULL;
	int i;

	ifp = fp_ifuid2ifnet(ifuid);
	if(fp_ifnet_is_invalid(ifp))
		return 1;

	/* FPM may call twice fp_delete_neighbour, when entry cannot be resolved. */
	rte = __find_neighbour4(addr, ifuid);
	if (rte == NULL)
		return 1;

	for (i = 0; i < rte->rt.rt_nb_nh; i++) {
		nh_index = rte->rt.rt_next_hop[i];
		nhe = &fp_shared->fp_nh4_table[nh_index];
		if ((nhe->nh.rt_type == RT_TYPE_NEIGH) &&
		    (nhe->nh_gw == addr) &&
		    (nhe->nh.nh_ifuid == ifuid))
			break;
	}
	if (i == rte->rt.rt_nb_nh)
		return 1;
	/*
	 * Reset the next-hop i.e. dst and state
	 */

	nhe->nh.nh_l2_state = L2_STATE_NONE;
	memset (nhe->nh.nh_eth.ether_dhost, 0, FP_ETHER_ADDR_LEN);

	/*
	 * As in fp_add_neighbour(),  neighbours are managed as /32 routes
	 * the route MUST persist until nobody else uses the next-hop.
	 */
	vrfid = ifuid2vrfid(ifuid);
	fp_delete_route4_nhmark(vrfid, addr, 32, addr, ifuid, nhe->nh.rt_type, NULL);
	return 0;
}

/*
 * IP address management.
 * We make IP/32 route.
 */
uint32_t fp_add_address4(uint32_t addr, uint32_t ifuid)
{
	unsigned int i;
	uint16_t vrfid;
	fp_ifnet_t *ifp = NULL;
	uint32_t index;
	struct fp_addr_object;

	ifp = fp_ifuid2ifnet(ifuid);
	if(fp_ifnet_is_invalid(ifp))
		return 1;

	/* allocate a new address object &&
	 * add this one to the address list of the interfaces
	 */
	index = fp_pool_get_addr4();
	if (index >= FP_MAX_NB_ADDR4)
		return 1;

	/* set addr and next element */
	fp_pool_addr4_object(index).addr = addr;
	fp_pool_addr4_object(index).next = ifp->if_addr4_head_index;

	/* add the new element to the list */
	ifp->if_addr4_head_index = index;
	ifp->if_nb_addr4++;

	/* We trust FPM to not add it twice. */

	vrfid = ifuid2vrfid(ifuid);
	/* Add IP/32 route. */
	i = fp_add_route4(vrfid, addr, 32, 0, ifuid, RT_TYPE_ADDRESS);

	return i;
}

uint32_t fp_delete_address4(uint32_t addr, uint32_t ifuid)
{
	uint16_t vrfid;
	fp_ifnet_t *ifp = NULL;

	ifp = fp_ifuid2ifnet(ifuid);
	if(fp_ifnet_is_invalid(ifp))
		return 1;

	/* remove addr from the address list of the interfaces */
	if (fp_pool_remove_addr4(addr, &ifp->if_addr4_head_index))
		return 1;
	ifp->if_nb_addr4--;

	/* Remove IP/32 */
	vrfid = ifuid2vrfid(ifuid);
	fp_delete_route4_nhmark(vrfid, addr, 32, 0, ifuid, RT_TYPE_ADDRESS, NULL);

	/*
	 *  Clean any IPv4 route using this interface.
	 * (IPv6 route clean-up is expected to be already
	 *  done thanks to kernel messages)
	 */
	if ((ifp->if_nb_addr4 == 0) && (ifp->if_nb_rt4 != 0))
		fp_rt4_ifscrub(ifp);

	return 0;
}

/* IPv6 functions */
#ifdef CONFIG_MCORE_IPV6

static void fp_add_nh6_hash(uint32_t hash, uint32_t index)
{
	uint32_t next;

	next = fp_shared->fp_nh6_hash[hash];

	fp_shared->fp_nh6_table[index].next = next;
	fp_shared->fp_nh6_table[index].prev = 0;

	if (next)
		fp_shared->fp_nh6_table[next].prev = index;

	fp_shared->fp_nh6_hash[hash] = index;
}

/* Del index from hash table, and manage collisions */
static void fp_del_nh6_hash(uint32_t hash, uint32_t index)
{
	uint32_t next, prev;

	prev = fp_shared->fp_nh6_table[index].prev;
	next = fp_shared->fp_nh6_table[index].next;

	/* If prev is not null, remove node from chaining,
	 * otherwise, remove node from head
	 */
	if (prev)
		fp_shared->fp_nh6_table[prev].next = next;
	else
		fp_shared->fp_nh6_hash[hash] = fp_shared->fp_nh6_table[index].next;

	if (next)
		fp_shared->fp_nh6_table[next].prev = prev;
}


uint8_t fp_best_nh6_prio (fp_rt6_entry_t* e) {
	return (fp_shared->fp_nh6_table[e->rt.rt_next_hop[0]].nh.nh_priority);
}

/* 
 * get/put to manage refcount on NH entries
 */
static inline void fp_nh6_get(uint32_t index)
{
	fp_nh6_entry_t *nh;
	nh = &fp_shared->fp_nh6_table[index];
	/*
	 * Count all routes using the interfaces, except
	 * the fast path specifc routes used for addresses
	 */
	if ((nh->nh.nh_ifuid) && (nh->nh.rt_type != RT_TYPE_ADDRESS)) {
		fp_ifnet_t *ifp = __fp_ifuid2ifnet (nh->nh.nh_ifuid);
		ifp->if_nb_rt6++;
	}
	/*
	 * Here we could manage some free list management
	 * if (! nh->refcnt)
	 *    ...
	 */
	nh->nh.nh_refcnt++;
	return;
}

/* 
 * Decrease-and-release fct for NH entries
 */
static inline void fp_nh6_put(uint32_t index)
{
	fp_nh6_entry_t *nh;
	uint32_t tail;
	nh = &fp_shared->fp_nh6_table[index];
	/*
	 * Count all routes using the interfaces, except
	 * the fast path specifc routes used for addresses
	 */
	if ((nh->nh.nh_ifuid) && (nh->nh.rt_type != RT_TYPE_ADDRESS)) {
		fp_ifnet_t *ifp = __fp_ifuid2ifnet (nh->nh.nh_ifuid);
		ifp->if_nb_rt6--;
	}

	/* Free list management  */
	if (nh->nh.nh_refcnt == 1 && index != FP_IPV6_NH_ROUTE_LOCAL &&
	    index != FP_IPV6_NH_ROUTE_BLACKHOLE) {
		fp_del_nh6_hash(fp_nh6_hash(&nh->nh_gw,
		                nh->nh.nh_ifuid), index);
		tail = fp_shared->fp_nh6_available_tail;

		if (!tail) {
			/* There is no free node in the list */
			fp_shared->fp_nh6_available_tail = index;
			fp_shared->fp_nh6_available_head = index;
		}
		else {
			fp_shared->fp_nh6_table[tail].next = index;
			fp_shared->fp_nh6_available_tail = index;
		}

		fp_shared->fp_nh6_table[index].next = 0;
	}

	nh->nh.nh_refcnt--;
	return;
}

/*
 * NH entries are stored in a single table, and
 * free one are just detected by their refcnt.
 *
 * Note; if fct is called in lookup mode (i.e. create = FALSE)
 * no refcnt is managed, it is up to the caller to do it.
 */
static uint32_t
fp_find_nh6_entry(fp_in6_addr_t * gw, uint32_t ifuid,
		  uint32_t rt_type, int create, fp_nh_mark_t *nh_mark)
{
	fp_nh6_entry_t *nh;
	uint32_t i;

	if (IS_RT_NONEXTHOP(rt_type)) {
		if (rt_type == RT_TYPE_ROUTE_LOCAL)
			i = FP_IPV6_NH_ROUTE_LOCAL;
		else
			i = FP_IPV6_NH_ROUTE_BLACKHOLE;

		fp_nh6_get(i);
		return i;
	}

	i = fp_nh6_lookup(gw, ifuid, rt_type, nh_mark);

	if (i) {
		/*
		 * In create mode, just add ref to the found
		 * entry, to keep behaviour identical to the
		 * real creation.
		 */
		if (create) {
			fp_nh6_get(i);
			/*
			 * On an neighbor add command, a
			 * next-hop can be promoted
			 */
			nh = &fp_shared->fp_nh6_table[i];

			if ((rt_type == RT_TYPE_NEIGH) &&
			    (nh->nh.rt_type == RT_TYPE_ROUTE))
				nh->nh.rt_type = RT_TYPE_NEIGH;
		}

		return i;
	}

	/* All nodes were used in the list, return NULL */
	if (!fp_shared->fp_nh6_available_head)
		return 0;

	/*
	 * Nothing found, but if a free slot exists, just use it
	 * be sure to have a NONE state at creation.
	 */
	if (create) {
		i = fp_shared->fp_nh6_available_head;
		fp_shared->fp_nh6_available_head = fp_shared->fp_nh6_table[i].next;

		/* all nodes are being used */
		if (!fp_shared->fp_nh6_available_head)
			fp_shared->fp_nh6_available_tail = 0;

		fp_add_nh6_hash(fp_nh6_hash(gw, ifuid), i);

		nh = &(fp_shared->fp_nh6_table[i]);
		nh->nh.nh_l2_state = L2_STATE_NONE;
		nh->nh_gw = *gw;
		nh->nh.nh_ifuid = ifuid;
		nh->nh.nh_hitflag = 0;
#ifdef CONFIG_MCORE_NEXTHOP_MARKING
		if (nh_mark && nh_mark->mark) {
			nh->nh.nh_mark = nh_mark->mark;
			nh->nh.nh_mask = nh_mark->mask;
		} else {
			nh->nh.nh_mark = 0;
			nh->nh.nh_mask = 0;
		}
#endif
		if ((rt_type == RT_TYPE_ADDRESS) ||
		    (!is_in6_addr_null(nh->nh_gw) && rt_type != RT_TYPE_ROUTE_CONNECTED))
			nh->nh.nh_type = NH_TYPE_GW;
		else
			nh->nh.nh_type = NH_TYPE_IFACE;
		nh->nh.rt_type = rt_type;
		nh->nh.nh_priority = fp_nh_priority(&(nh->nh));
		fp_nh6_get(i);
	}
	return i;
}

/* 
 * get/put to manage refcount on RT entries
 */
static inline void fp_rt6_mget(uint32_t index, uint32_t inc)
{
	fp_rt6_entry_t *entry;
	entry = &fp_shared->fp_rt6_table[index];
	/*
	 * Here we could manage some free list management
	 * if (! entry->refcnt)
	 *    ...
	 */
	entry->rt.rt_refcnt += inc;
	return;
}

/* 
 * Decrease-and-release fct for RT entries
 */
static inline void fp_rt6_mput(uint32_t index, uint32_t inc)
{
	fp_rt6_entry_t *entry;
	entry = &fp_shared->fp_rt6_table[index];
	entry->rt.rt_refcnt -= inc;
	/*
	 * Here we could manage some free list management
	 * if (! entry->refcnt)
	 *    ...
	 * 
	 */
	return;
}

#define fp_rt6_get(e)  fp_rt6_mget((e), 1)
#define fp_rt6_put(e)  fp_rt6_mput((e), 1)

/* 
 * RT entries (in fact routes) are stored in a single table, and 
 * free one are just detected by their refcnt.
 *
 * This same large table can be used in case of VRF, hence allowing
 * to share a common pool rather than having to provision a per VRF
 * quota.
 */
static unsigned int fp_new_rt6_entry(void)
{
	unsigned int i;

	/*
	 * If we ever want to switch to a more efficent way of searching
	 * such as keeping a bit-field of used entries, this bit set/reset
	 * should be done in the fp_rt_get/put fcts.
	 */
	for (i = fp_shared->fp_rt6_last_added; i < FP_IPV6_NBRTENTRIES; i++) {
		if (fp_shared->fp_rt6_table[i].rt.rt_refcnt == 0) {
			fp_rt6_get(i);
			fp_shared->fp_rt6_last_added = i;
			return i;
		}
	}
	/* No free slot in the bottom of the table -> goto head */
	for(i = 1; i < fp_shared->fp_rt6_last_added; i++) {
		if(fp_shared->fp_rt6_table[i].rt.rt_refcnt == 0) {
			fp_rt6_get(i);
			fp_shared->fp_rt6_last_added = i;
			return i;
		}
	}
	return 0;
}

/*
 * One or several next-hop may have their status changed
 * which needs a full re-scan of next-hop atributes
 */
void fp_rt6_nh6_reorder(fp_rt6_entry_t *rte, int refresh)
{
	fp_rt6_entry_t ro;
	int i,j, insert;
	uint8_t best_prio = 0;

	/*
	 * Fresh rt-entry is identical except NH order
	 * This tries at most to keep the same order, hence insertion
	 * are done at the END of each type.
	 */
	ro = *rte;
	ro.rt.rt_nb_nh=0;
	ro.rt.rt_nb_nhp=0;
	for (i=0; i<rte->rt.rt_nb_nh; i++) {
		fp_nh6_entry_t *nhe;
		nhe = &fp_shared->fp_nh6_table[rte->rt.rt_next_hop[i]];
		if (refresh)
			nhe->nh.nh_priority = fp_nh_priority (&(nhe->nh));
		if  (nhe->nh.nh_priority > best_prio) {
			insert = 0;
			ro.rt.rt_nb_nhp = 1;
			best_prio = nhe->nh.nh_priority;
		} else if  (nhe->nh.nh_priority == best_prio) {
			insert = ro.rt.rt_nb_nhp;
			ro.rt.rt_nb_nhp++;
		}
		else
			insert = ro.rt.rt_nb_nh;
		for (j=ro.rt.rt_nb_nh;  j > insert; j--)
			ro.rt.rt_next_hop[j] = ro.rt.rt_next_hop[j-1];
		ro.rt.rt_nb_nh++;
		ro.rt.rt_next_hop[insert] = rte->rt.rt_next_hop[i];
	}
	*rte = ro;
	return;
}

static void
fp_rt6_nh6_check_neigh (fp_rt6_entry_t *rte, fp_in6_addr_t *addr)
{
	int i;

	/*
	 * If the entry was NOT a neighbor, it can not become one
	 * Only a /128 can host real NDP entry
	 */
	if (rte->rt.rt_neigh_index == 0)
		return;
	if (rte->rt.rt_length != 128)
		return;

	rte->rt.rt_neigh_index = 0;

	for (i = 0 ; i < rte->rt.rt_nb_nh ; i++) {
		int ni = rte->rt.rt_next_hop[i];
		fp_nh6_entry_t *nhe = &fp_shared->fp_nh6_table[ni];
		if ((nhe->nh.rt_type == RT_TYPE_NEIGH) &&
		     is_in6_addr_equal(nhe->nh_gw, *addr)) {
			rte->rt.rt_neigh_index = ni;
			break;
		}
	}
}

/* 
 * Layer 'ln' indirection tables entries are stored in a single table, and 
 * free one are just detected by their "use". It merely points inside 
 * the big list of routes
 *
 * This same table can be used in case of VRF, hence allowing to share 
 * a common pool rather than having to provision a per VRF  quota.
 */
static unsigned int fp_new_ln_table6(int level, uint16_t vrfid)
{
	unsigned int i, nb_layer;
	fp_table_t * table = fp_get_table6(level);
	switch(FP_IPV6_LAYER_WIDTH(level)) {
		case 16:
			nb_layer = FP_NB_16_TABLE_ENTRIES;
			break;
		case 8:
		default:
			nb_layer = FP_NB_8_TABLE_ENTRIES;
			break;	
	}
	
	/*
	 * If we ever want to switch to a more efficent way of searching
	 * such as keeping a bit-field of used entries, all used=0 MUST be 
	 * tracked down, to be replaced by some macro TB_FREE() (managing 
	 * both decrease and bit release)
	 */
	for (i = 1; i < nb_layer; i++) {
		if (!table[i].used)
		{
			table[i].used = FP_USED_V6;
			table[i].vrfid = vrfid;

			/*
			 * Table allocation is usually followed by an harsh 
			 * duplication of higher level entry, so this clean-up
			 * is just conservative.
			 */
			/*
			bzero (fp_shared->fp6_entries + 
					fp_shared->fp6_ln_table[i].entries, 
			       (1<<L3LNWIDTH) * sizeof(table_entry_t)); // TODO
			*/
			return i;
		}
	}
	return 0;
}

/* 
 * Insert entry in the routes chain starting at head,
 * sorted by decreasing length 
 */
static void fp_update_route6_chain(fp_rt6_entry_t *head, fp_rt6_entry_t *entry, 
		uint32_t index)
{
	fp_rt6_entry_t *next;

	/*
	 * Just looking where to insert the entry. The case were new 
	 * entry is head of chain is detected by the caller and NOT 
	 * managed in this function...
	 */
	while (head->rt.rt_next) {
		next = &fp_shared->fp_rt6_table[head->rt.rt_next];
		if (next->rt.rt_length < entry->rt.rt_length)
			break;
		head = next;
	}
 
    /*
     * Same length means the chain is updated
	 */
	if (head->rt.rt_length == entry->rt.rt_length)
		return;
	/*
	 * If entry is already a chain, we are inserting something
	 * that aggregates linkrs, so decrease the refcnt of 
	 * entry->next.
	 *
	 * example:
	 * 2 /15 point to a same /13, and we insert a /14 in between.
	 * on the first /15 set, the /14 is inserted, which will be done
	 * only on ONE of the two associated /16. So far so good.
	 * When the 2nd /15 set is handled, we do have a real insertion,
	 * but the link /14 --> /13 is already done, which means that the /13
	 * will loose its /15 ancestors, therefore there is no more any new 
	 * pointer pointing to it: we need to decrease ref counter.
	 */ 
	if (entry->rt.rt_next) 
		fp_rt6_put(entry->rt.rt_next);
	entry->rt.rt_next = head->rt.rt_next;
	head->rt.rt_next = index;
	fp_rt6_get(index);
}

/* 
 * Now we have direct acces to the (sub)table that includes the fixed
 * length entries that provides decomposition of our new route
 * we have to
 *   - select the initial index,  and witdh for the route in this
 *     table. e.g. a /14 route is in the primary, and its witdht is 4
 *   - for each of those entries do the udpate
 *     + entry is empty: fill it
 *     + entry is and indirect table: recursion within this subtable
 *       the subsequent width/index computation will address ALL entries
 *       in the subtable
 *     + entry is an RT entry: update the RT chain
 *         = we insert a more precise (longest) route, do HEAD insertion
 *         = we insert a less precise (shortest) route, go inside the RT chain
 */
static void fp_update_route6(fp_table_entry_t *table, int level, fp_in6_addr_t * addr, 
		uint8_t length, uint32_t rt_index, fp_rt6_entry_t *entry)
{
	int i = 0;

	// to be simplified...
	/* OLD - here for remembering it
	if (length > 24) {
		r = 1<<(32-length);
	} else if (length > 16) {
		if (level > 1) {
			r = 256;
			b = 0;
		} else
			r = 1<<(24-length);
	} else {
		if (level > 0) {
			r = 256;
			b = 0;
		} else
			r = 1<<(16-length);
	}
	*/
	int nb_entries = 0;
	int base = 0;
	uint8_t cumul = fp_shared->fp_cumulative_width6[level];
	uint32_t mask = 0xFFFFFFFF >> (32-FP_IPV6_LAYER_WIDTH(level));


	/* Here we compute the base index & the # of entries to sweep, given the
	 * current level and the length of the route. (same in delete_route)
	 * 
	 * We have three different cases :
	 *	- Case 1: the length of the route fall right in this level
	 * 		(we consider a 8-bits wide level here)
	 *
	 *		level bits:	¤ ¤ ¤ ¤ ¤ ¤ ¤ ¤
	 *					¤ ¤ ¤|0 0 0 0 0		<- base: first bits (upto length)
	 *		length---------->|		  		<- (cumul-length)bits wide area to span
	 *	
	 *
	 *	- Case 2: the length is > cumul
	 *		Thus, we only have to explore 1 entry, given by the baseIndex
	 *
	 *
	 *	- Case 3: the length is < cumul(level-1)
	 *		In this case, we are one or more level deeper than the base level
	 *		of the route. We have to sweep all entries of this level, so
	 *		base=0 and nb_entries is level-wide.
	 */
	if (length < cumul && 
	  ((level > 0 && (cumul-FP_IPV6_LAYER_WIDTH(level))<length) || level==0)) {
		/* case 1 (works for level==0 too) */
		/* We keep the cumul-length higher bits of the baseIndex as base
		 * and the FP6_LAYER_WIDTH - (cumul-length) lower bits as nb_entries */
		base = fp_baseIndex6(addr, level) & (mask << (cumul-length));
		nb_entries = 1<<(cumul-length);
	} else if(length >= cumul) {
		/* case 2 */
		base = fp_baseIndex6(addr, level);
		nb_entries = 1;
	} else {
		/* case 3 */
		base = 0;
		nb_entries = 1 << FP_IPV6_LAYER_WIDTH(level);
	}

	/*
	 * sweep all entries concerned by this route
	 */
	for (i = base; i < base + nb_entries; ++i) {
		if (table[i].index == RT_INDEX_UNUSED) {
			/* 
			 * Nothing, just a very NEW entry creation
			 */
			fp_table_entry_t e = { .rt = RT_ROUTE, .index = rt_index };
			table[i] = e;
			fp_rt6_get(rt_index);
		} else if (table[i].rt == RT_TABLE) {
			/* 
			 * We have found an indirection level: just go
			 * deeper and jump to the lower table level
			 */
			fp_table_t * next_table = fp_get_table6(level+1);
			fp_table_entry_t * next_entries = fp_get_entries6(level+1);
			int idx = next_table[table[i].index].entries; 
			fp_update_route6(next_entries + idx, level + 1, 
			              addr, length, rt_index, entry);
		} else {
			/*
			 * Here we are reaching RT table, i.e. final routes
			 * what is needed is RT chain update
			 */
			fp_rt6_entry_t *head;
			head = &fp_shared->fp_rt6_table[table[i].index];
			if (head->rt.rt_length == length) {
				/*
				 * This case MUST not happen since we rely on 
				 * upper caller NOT to add the same route 
				 * twice.
				 */
				;
			} else if (head->rt.rt_length < length) {
				/*
				 * The new entry is meant to be linked to less 
				 * precise entry. This will be done ONCE for 
				 * ALL, and subsequent insertion will find 
				 * linkage already done.
				 */
				if (!(entry->rt.rt_next) && table[i].index) {
					entry->rt.rt_next = table[i].index;
					/* 
					 * New linkage count
					 */
					fp_rt6_get(table[i].index);
				}

				fp_table_entry_t e = { 
					.rt = RT_ROUTE, 
					.index = rt_index 
				};
				/*
				 * Now the insertion part, with a refcnt shift
				 * from the succesor (if present) to the entry
				 */
				if (table[i].index) 
					fp_rt6_put(table[i].index);
				table[i] = e;
				fp_rt6_get(rt_index);
			} else {
				/*
				 * Insert the entry inside the chain: it won't
				 * be used for forwarding but to be kept, in
				 * case the more precise route is removed
				 */
				fp_update_route6_chain(head, entry, rt_index);
			}
		}
	}
}

/* 
 * Internal route manager:
 *
 * WARNING
 *    this code won't work if the route already exists
 *    results are un-predictible.
 * WARNING
 *
 */ 
static uint32_t __fp_add_route6(uint16_t vrfid, fp_in6_addr_t * addr, uint8_t length, fp_in6_addr_t * gateway, uint32_t ifuid, uint32_t rt_type, fp_nh_mark_t *nh_mark)
{
	fp_rt6_entry_t *entry;
	uint32_t rt_index;
	uint32_t nh_index;
	int nb_level = 0;
	int level = 0;
	int i;

	rt_index = fp_new_rt6_entry();
	if (rt_index == 0)
		return 0;
	entry = &(fp_shared->fp_rt6_table[rt_index]);
	entry->rt.rt_length = length;
	entry->rt.rt_next = 0;
	entry->rt.rt_neigh_index = 0;
	entry->rt.rt_vrfid = vrfid;

	/* Create/Check a nexthop entry */
	nh_index = fp_find_nh6_entry(gateway, ifuid, rt_type, 1, nh_mark);
	/*
	 * Impossible to get/create the next-hop, free the route
	 * and return the failure
	 */
	if (!nh_index) {
		fp_rt6_put(rt_index);
		return 0;
	}

	/* Mark special entry used for NDP */
	if (rt_type == RT_TYPE_NEIGH)
		entry->rt.rt_neigh_index = nh_index;

	/*
	 * When a new rt_entry is created, we  create the very first
	 * Next-Hop, so we can safely write next-hop number 0
	 */
	entry->rt.rt_next_hop[0] = nh_index;
	entry->rt.rt_nb_nh = 1;
	entry->rt.rt_nb_nhp = 1;

	/*
	 * Table should first point to the first level table, i.e. the one
	 * provided thanks to fp_layer_table.
	 */
	fp_table_entry_t * entries = fp_get_entries6(level)+
	                  fp_get_table6(level)[FP_IPV6_TABLE_START+vrfid].entries;

	/* Determination of depth in the structure
	 * The longest the route, the deepest in the structure,
	 * the higher the nb_level.
	 */
	while((nb_level < FP_IPV6_NBLAYERS) &&
	      (length > fp_shared->fp_cumulative_width6[nb_level])) {
		nb_level++;
	}

	while (level < nb_level) {

		/* entries is a pointer to the first cell of the right subtable
		 * Thus, the baseIndex is the cell to address */
		i = fp_baseIndex6(addr, level);
		/* Table for next level */
		fp_table_t * next_table = fp_get_table6(level+1);
		/* entries for next level */
		fp_table_entry_t * next_entries = fp_get_entries6(level+1);
		if ((entries[i].rt == RT_ROUTE) || (entries[i].index == 0)) {
			/* 
			 * Until we reach final table level, we expect to find
			 * reference to indirection tables. If the current entry
			 * is either empty or an RT entry, the we must
			 *  - create a sub table
			 *  - populate it with RT entries copied from intial one
			 *    if it was an RT.
			 */
				
			/* get a new subtable for next level */
			uint32_t index = fp_new_ln_table6(level+1, vrfid);
			
			if (entries[i].rt == RT_ROUTE) {
				/* If it is a route we have to populate the subtable with it */
				int base = next_table[index].entries;
				int j;

				for (j = 0; j < (1<<FP_IPV6_LAYER_WIDTH(level+1)); j++)
					next_entries[base + j] = entries[i];
				/*
				 * Refcount usage goes up from 1 to a full sub-table width
				 */
				fp_rt6_mget(entries[i].index,
				            (1<<FP_IPV6_LAYER_WIDTH(level+1)) - 1);
			}
			/* We now point to the freshly created table */
			fp_table_entry_t e = { 
				.rt = RT_TABLE, 
				.index = index 
			};
			entries[i] = e;
		}
		/*
		 * else: the entry point to a sub-table, OK, nothing to create
		 * Here we can assume entry point to a subtable (possibly
		 * freshly created) and walk through it
		 */ 
		

		int table_idx = next_table[entries[i].index].entries;
		entries = &next_entries[table_idx];
		level = level + 1;
	}


	/*
	 * table is here pointing to the primary table, or any
	 * indirect table, all have the same structure. Recursion
	 * level is provided by "level"
	 */

	fp_update_route6(entries, level, addr, length, rt_index, entry);
	/*
	 * Now we can release the entry, (implicit _get() done by
	 * initial allocation).
	 */
	fp_rt6_put(rt_index);

	return rt_index;
}



/* 
 * Here we do NOT search the best possible route, we search
 * if the route (including length) exists.
 *
 * The assumption is the prefix does not have any bit set outside
 * the mask width.
 */
fp_rt6_entry_t *fp_get_exact_route6(uint16_t vrfid, fp_in6_addr_t * prefix, uint8_t len)
{
	fp_rt6_entry_t *entry;
	/*
	 * First do a standard best route search. 
	 */

	entry = fp_rt6_lookup(vrfid, prefix);
	if (!entry)
		return NULL;

	/*
	 * knowing prefix has no bit out of the mask, 
	 * prefix/len is a route that overlaps with found route
	 * hence is stored in the RT chain
	 */
	while (entry) {
		if (entry->rt.rt_length == len) {
			return entry;
		}
		if (entry->rt.rt_next)
			entry  = &fp_shared->fp_rt6_table[entry->rt.rt_next];
		else
			entry = NULL;
	}

	return NULL;
}

/*
 * Currently neighbours entries are those routes with RT type set to
 * RT_TYPE_NEIGH but identifed in the route by rt_neigh_index
 */
static fp_rt6_entry_t * __fp_find_neighbour6(fp_in6_addr_t * addr, uint32_t ifuid)
{
	uint16_t vrfid = ifuid2vrfid(ifuid);
	fp_rt6_entry_t *entry;

	if (vrfid >= FP_MAX_VR)
		return NULL;

	entry = fp_get_exact_route6(vrfid, addr, 128);
	if (entry && entry->rt.rt_neigh_index != 0)
		return entry;

	return NULL;
}

/*
 * Try to create a new route.
 *    0: OK
 *    1: some error occured
 *    2: route and next-hop already exist, nothing was done.
 */
static uint32_t
fp_create_route6_nhmark(uint16_t vrfid, fp_in6_addr_t * addr,
			uint8_t length, fp_in6_addr_t * next,
			uint32_t ifuid, uint8_t type,
			fp_nh_mark_t *nh_mark)
{
	fp_rt6_entry_t *entry = NULL;
	uint32_t rt_index;

	if (vrfid >= FP_MAX_VR)
		return FP_CREATE_RT_ERROR;

	/*
	 * Routes with no nexthop don't need sanity chack
	 */
	if (!IS_RT_NONEXTHOP(type)) {
		fp_ifnet_t *ifp = fp_ifuid2ifnet(ifuid);
		if (fp_ifnet_is_invalid(ifp))
			return FP_CREATE_RT_ERROR;
	}

	entry = fp_get_exact_route6(vrfid, addr, length);
	/*
	 * If a route already exists, it is just a matter of inserting a
	 * new next-hop, else, a full route creation is needed.
	 */
	if (entry) {
		uint32_t nh;
		int i;
		int pos;
		fp_nh6_entry_t *nhe;
		uint8_t best_prio;

		/*
		 * find or allocate a next-hop
		 */
		nh = fp_find_nh6_entry(next, ifuid, type, 1, nh_mark);
		if (!nh)
			return FP_CREATE_RT_ERROR;
		/*
		 * Sanity check, to protect against double insertion
		 */
		for (i = 0 ; i < entry->rt.rt_nb_nh ; i++) {
			if (entry->rt.rt_next_hop[i] == nh)  {
				fp_nh6_put(nh);
				return FP_CREATE_RT_EXIST;
			}
		}
		/*
		 * Check against too many mpath.
		 * If OK, just a new path i.e. next-hop.
		 */
		if (i == FP_MAX_MPATH) {
			fp_nh6_put (nh);
			return FP_CREATE_RT_ERROR;
		}

		/*
		 * If it's the first NEIGH entry, mark it otherwise,
		 * keep the current neigh best candidate
		 */
		if (type == RT_TYPE_NEIGH) {
			if (entry->rt.rt_neigh_index == 0)
				entry->rt.rt_neigh_index = nh;
		}

		nhe = &fp_shared->fp_nh6_table[nh];
		best_prio = fp_best_nh6_prio (entry);
		/*
		 * Priority of the 1st next-hop is the current best
		 * best priority. If new one is better, create a new
		 * class, if lower, don't bother keeping a strict order.
		 */
		if (nhe->nh.nh_priority > best_prio) {
			pos = 0;
			entry->rt.rt_nb_nhp = 1;
		} else if  (nhe->nh.nh_priority == best_prio) {
			pos = 0;
			entry->rt.rt_nb_nhp++;
		} else
			pos = entry->rt.rt_nb_nh;
		for (i = entry->rt.rt_nb_nh; i > pos; i--)
			entry->rt.rt_next_hop[i] = entry->rt.rt_next_hop[i-1];
		entry->rt.rt_next_hop[pos] = nh;
		entry->rt.rt_nb_nh++;

		/*
		 * Compute index out of existing entry.
		 */
		rt_index = (entry - &fp_shared->fp_rt6_table[0]);
	}
	else
		rt_index = __fp_add_route6(vrfid, addr, length, next, ifuid, type, nh_mark);

	if (rt_index == 0)
		return FP_CREATE_RT_ERROR;
	else
		return 0;
}

uint32_t fp_add_route6_nhmark(uint16_t vrfid, fp_in6_addr_t * addr,
                                 uint8_t length, fp_in6_addr_t * next,
                                 uint32_t ifuid, uint8_t type,
                                 fp_nh_mark_t *nh_mark)
{
        uint32_t res;

	res = fp_create_route6_nhmark(vrfid, addr, length, next, ifuid,
	                              type, nh_mark);
	if (res && (res != FP_CREATE_RT_EXIST))
		return FP_CREATE_RT_ERROR;
	return 0;
}

/* 
 * Now we have direct access to the (sub)table that includes the fixed
 * length entries that provides decomposition of our new route
 * we have to
 *   - select the initial index,  and width for the route in this
 *     table. e.g. a /14 route is in the primary, and its width is 4
 *   - for each of those entries do the update
 *     + entry is empty: nothing (should only happen for deleting a
 *                       non existing route)
 *     + entry is an indirect table: recursion within this subtable
 *       the subsequent width/index computation will address ALL entries
 *       in the subtable
 *     + entry is an RT entry: update the RT chain
 *   - at the end of each recursion level:
 *     + check if the subtable is usefull (i.e. at least two routes are 
 *       different) and provide result to the caller
 *     + more ?
 */
static int __fp_delete_route6(fp_table_entry_t* entries, int level, fp_in6_addr_t * addr, int length, uint32_t *premove, fp_nh_mark_t *nh_mark)
{
	int i = 0;
	

	int nb_entries = 0;
	int base = 0;

	/* Hum, something wrong here... */
	if(level >= FP_IPV6_NBLAYERS) return 0;

	/* computes the base index and nb of entries to explore for the given level */
	uint8_t cumul = fp_shared->fp_cumulative_width6[level];
	uint32_t mask = 0xFFFFFFFF >> (32-FP_IPV6_LAYER_WIDTH(level));
	if(length < cumul && ((level > 0 && 
	       (cumul-FP_IPV6_LAYER_WIDTH(level))<length) || level==0)) {
		/* case 1 (works for level==0 too) */
		/* We keep the cumul-length higher bits of the baseIndex as base
		 * and the FP6_LAYER_WIDTH - (cumul-length) lower bits as nb_entries */
		base = fp_baseIndex6(addr, level) & (mask << (cumul-length));
		nb_entries = 1<<(cumul-length);
	} else if(length >= cumul) {
		/* case 2 */
		base = fp_baseIndex6(addr, level);
		nb_entries = 1;
	} else {
		/* case 3 */
		base = 0;
		nb_entries = 1 << FP_IPV6_LAYER_WIDTH(level);
	}

	/* Sweep all concerned entries */
	for (i = base; i < base + nb_entries; ++i) {
		if (entries[i].index == RT_INDEX_UNUSED) {
			/* Empty slot: should not occur */
			;
		} else if (entries[i].rt == RT_TABLE) {
			/* 
			 * We have found an indirection level: just go
			 * deeper and jump to the lower table level
			 */
			fp_table_t *subtable = &(fp_get_table6(level+1)[entries[i].index]);
			int packing;

			packing = __fp_delete_route6(
			        fp_get_entries6(level+1) + subtable->entries, 
					level + 1, addr, length, premove, nh_mark);
			/*
			 * If it was the last specific route of the next table, 
			 * then remove this indirection table 
			 * (recursive approach)
			 */
			if (packing) {
				/*
				 * First copy here first entry of the subtable.
				 * ALL entries of the subtable are identical.
				 */
				entries[i] = fp_get_entries6(level+1)[subtable->entries];
				/*
				 * And refcount except first entry (width of subtable - 1)
				 */
				if(entries[i].index != 0)
					fp_rt6_mput(entries[i].index,
				                (1<<FP_IPV6_LAYER_WIDTH(level+1)) - 1);
				/*
				 * Clear subtable, if we ever have several kind 
				 * of indirection subtables, each one should 
				 * include its level, so that we can derive its
				 * width.
				 */
				bzero (fp_get_entries6(level+1) + subtable->entries, 
				       (1<<FP_IPV6_LAYER_WIDTH(level+1)) * 
				          sizeof(fp_table_entry_t));
				subtable->used = 0;
			}
		} else  {
			/*
			 * Here we are reaching RT table, i.e. final routes.
			 * What is needed is RT chain update
			 */
			fp_rt6_entry_t *head;
			head = &fp_shared->fp_rt6_table[entries[i].index];
			if (head->rt.rt_length == length) {
				/*
				 * Keep a single reference on the entry to be 
				 * removed for final cleaning
				 */
				if (! *premove) {
					 *premove = entries[i].index;
					fp_rt6_get(*premove);
				}
				/*
				 *
				 * We hit he HEAD of chain, so remove it.
				 * There is a refcnt shift as we remove 
				 * intermediate entry, so make it on refcnt. 
				 * We rely on the end of this fct to do the last
				 * decrement of remove->next
				 */
				if (head->rt.rt_next)
					fp_rt6_get(head->rt.rt_next);

				fp_rt6_put(entries[i].index);
				entries[i].index = head->rt.rt_next;
				/*
				 * If this was the last element of chain, just mark the 
				 * entry as not an RT anymore. should be equivalent to
				 *  entries[i].rt = head->rt  ?
				 */
				if (entries[i].index == 0)
					entries[i].rt = 0;
			} else {
				/*
				 * Just looking for the entry to remove. 
				 * The case where old entry is head of chain is
				 * detected by the previous case and NOT managed
				 * here.  So there will ALWAYS be an ancestor 
				 * (more precise route)
				 */
				fp_rt6_entry_t *next = 0;

				while (head->rt.rt_next) {
					next = &fp_shared->fp_rt6_table[head->rt.rt_next];
					if (next->rt.rt_length == length) {
						/*
						 * Keep a single reference on 
						 * the entry to be removed
						 * for final cleaning. 
						 * And count how many subsequent
						 * removals are done 
						 */
						if (! *premove) {
							*premove = head->rt.rt_next;
							fp_rt6_get(*premove);
						} 
						/*
						 * There is a refcnt shift as 
						 * we remove intermediate entry,
						 * so make it on refcnt. 
						 * We rely on the end of this 
						 * fct to do the last decrement
						 * of remove->next
						 */
						if (next->rt.rt_next) 
							fp_rt6_get(next->rt.rt_next);
						fp_rt6_put (head->rt.rt_next);
						head->rt.rt_next = next->rt.rt_next;
						/*
						 * OK, we found it, no use to 
						 * search further
						 */
						break;
					}
					head = next;
				}
			}
		}
	}
	/*
	 * OK we have found an entry to remove from table. It is still
	 * hanging thanks to the initial fp_rt6_get(). The last cleaning 
	 * part is to deconnect it from subsequent RT chain.
	 * 
	 * The premove is transmitted along with the recursive calls,
	 * and ONLY the first level (i.e level 0) is allowed to to the final
	 * clean-up. This is because a single deletion may sapn across
	 * several sub-tables. 
	 */
	if ((level == 0) && (*premove)) {
		fp_rt6_entry_t *rr;
		rr = &fp_shared->fp_rt6_table[*premove];
		if (rr->rt.rt_next) {
			fp_rt6_put(rr->rt.rt_next);
			rr->rt.rt_next = 0;
		}
		/*
		 * Release the next hop associated to the dying route
		 * As the routes disappears ONLY when the last next-hop  is
		 * removed, we can safely assume working on nh number 0 
		 */
		if (rr->rt.rt_nb_nh) {
			fp_nh6_put(rr->rt.rt_next_hop[0]);
			rr->rt.rt_nb_nh = 0;
			rr->rt.rt_nb_nhp = 0;
		}
		fp_rt6_put(*premove);
	}

	/*
	 * If ALL entries are identical, this means that the last more
	 * specific routes was removed, and so a single entry at previous
	 * level is enough to sum-up route description.
	 * Subtable release is done by the recursive caller. As the top-level
	 * table MUST NEVER be released, freeing at recursive level is enough.
	 */
	if (level > 0) { 
		uint32_t rt = entries[0].rt;
		uint32_t index = entries[0].index;

		for (i = 1; i < (1<<FP_IPV6_LAYER_WIDTH(level)); i++) {
			/* Modification here */
			if  ((entries[i].index != 0 && entries[i].rt != rt) 
			     || entries[i].index != index) {
				return 0;
			}
		}
		return 1;
	}

	return 0;
}

/*
 * wrapper, for hiding table levels stuff
 */
uint32_t fp_delete_route6_nhmark(uint16_t vrfid, fp_in6_addr_t * addr, uint8_t length,
                          fp_in6_addr_t * gw, uint32_t ifuid, uint8_t rt_type, fp_nh_mark_t *nh_mark)
{
	uint32_t nh = 0;
	uint32_t remove = 0;
	fp_rt6_entry_t *rte;
	int i,j;

	if (vrfid >= FP_MAX_VR)
		return 1;

	/*
	 * There MUST be some next-hop associated to the route
	 * as well as an exact match for the route.
	 */
	rte = fp_get_exact_route6(vrfid, addr, length);
	if (rte == NULL)
		return 0;

	nh = fp_find_nh6_entry(gw, ifuid, rt_type, 0, nh_mark);
	if (!nh)
		return 1;

	for (i=0 ; i<rte->rt.rt_nb_nh ; i++) {
		if (rte->rt.rt_next_hop[i] == nh)
			break;
	}
	/*
	 * The provided next-hop doesn't exist !
	 */
	if (i == rte->rt.rt_nb_nh)
		return 1;
	else {
		fp_nh6_entry_t *nhe = &fp_shared->fp_nh6_table[nh];

		/*
		 * This NH is no longer used by an ARP route entry
		 * so downgrade to ROUTE type
		 */
		if ((rt_type == RT_TYPE_NEIGH) &&
		    (nhe->nh.rt_type == RT_TYPE_NEIGH))
			nhe->nh.rt_type = RT_TYPE_ROUTE;
	}

	/*
	 * In case of real mpath route, just remove the next-hop
	 * but keep the route itself.
	 */
	if (rte->rt.rt_nb_nh > 1) {
		for (j = i ; j < (rte->rt.rt_nb_nh - 1); j++)
			rte->rt.rt_next_hop[j] = rte->rt.rt_next_hop[j+1];
		/*
		 *  Adjust Preferred counts
		 */
		if (i < rte->rt.rt_nb_nhp)
			rte->rt.rt_nb_nhp--;
		rte->rt.rt_nb_nh--;
		if  (rte->rt.rt_nb_nhp == 0)
			fp_rt6_nh6_reorder (rte, 0);
		fp_nh6_put(nh);

		/* Check if at least on of the remaining nh is a neighbour */
		fp_rt6_nh6_check_neigh (rte, addr);

		return 0;
	}

	/*
	 * Only the last next-hop removal kills the route.
	 */
	__fp_delete_route6(
		  fp_get_entries6(0) +
	      fp_get_table6(0)[FP_IPV6_TABLE_START+vrfid].entries,
		  0, addr, length, &remove, nh_mark);
	return 0;
}

/*
 * This allows neighbour creation as well as neighbour update
 */
uint32_t fp_add_neighbour6(fp_in6_addr_t * addr, const uint8_t mac[6],
			   uint32_t ifuid, uint8_t state)
{
	fp_rt6_entry_t *entry = NULL;
	fp_nh6_entry_t *nh = NULL;
	uint32_t nh_index = 0;
	uint16_t vrfid;

	/* reject neighbours on unknown interface */
	if (ifuid == 0)
		return 0;

	vrfid = ifuid2vrfid(ifuid);
	if (vrfid >= FP_MAX_VR)
		return 0;

	/*
	 * FPM calls twice fp_add_neighbour: incomplete then reachable state.
	 * This allows to prevent Slow Path flooding while the resolution is
	 * still in progress.
	 */

	/*
	 * We don't keep a /128 route for link-local neighbours, in case of
	 * two neighbours on different links with the same link-local address.
	 * So we need to search the old good way to find if it was already there.
	 */
	/* Not link_local */
	if(likely(!fp_in6_is_link_local(*addr))) {
		uint32_t neigh_res;
		int i;
		/*
		 * Neighbours are stored as routing entries for the /128
		 * with a specific type.
		 *
		 * New neighbour
		 *   - full: this will create the route and the next-hop
		 *   - addr exists, but new interface: the route already exists, but
		 *     we'll manage ECMP
		 * Existing neighbour (same addr and interface)
		 *   - fp_add_route4 ECMP handling is protected against double
		 *     insertion and does nothing.
		 *   - The first look-up is to get the numbe rof next-hops,
		 */
		neigh_res = fp_create_route6_nhmark(vrfid, addr, 128, addr,
			                       ifuid, RT_TYPE_NEIGH,  NULL);
		if (neigh_res && (neigh_res != FP_CREATE_RT_EXIST))
			return 0;
		entry = fp_get_exact_route6(vrfid, addr, 128);
		if (entry == NULL)
			return 0;

		/*
		 * Several neighbours/routes can be present on different interfaces,
		 * and are managed as ECMP.
		 */
		for (i=0; i < entry->rt.rt_nb_nh; i++) {
			nh_index = entry->rt.rt_next_hop[i];
			nh = &fp_shared->fp_nh6_table[nh_index];
			if ((nh->nh.rt_type == RT_TYPE_NEIGH) &&
			    is_in6_addr_equal(nh->nh_gw, *addr) &&
			    (nh->nh.nh_ifuid == ifuid))
				break;
		}

		if (i == entry->rt.rt_nb_nh)
			return 0;

	} /* if !link_local */
	else {
		/* link local.
		 * Mimic behaviour of process on non link local: check first if neighbour
		 * exists to avoid taking an extra reference.
		 */
		nh_index = fp_find_nh6_entry(addr, ifuid, RT_TYPE_NEIGH, 0, NULL);
		if (nh_index == 0) {
			/* It will create new entry, hence bump the reference (nh6_get) */
			nh_index = fp_find_nh6_entry(addr, ifuid, RT_TYPE_NEIGH, 1, NULL);
			nh = &fp_shared->fp_nh6_table[nh_index];
		} else {
			/* if nexthop was added because a route needed
			   it, take a reference on it for the
			   neighbour deletion */
			nh = &fp_shared->fp_nh6_table[nh_index];
			if (nh->nh.nh_l2_state == L2_STATE_NONE)
				fp_nh6_get(nh_index);
		}
		/*
		 * If NH existed, it must be 'promoted' to an neighbour sttaus
		 */
		nh->nh.rt_type = RT_TYPE_NEIGH;
	}
	if (nh->nh.nh_hitflag)
		nh->nh.nh_hitflag = 0;
	nh->nh_gw = *addr;
	nh->nh.nh_ifuid = ifuid;
	nh->nh.nh_eth.ether_type = htons(FP_ETHERTYPE_IPV6);
	memcpy(nh->nh.nh_eth.ether_dhost, mac, FP_ETHER_ADDR_LEN);

	/*
	 * Entry is directly created with source MAC address (if the index
	 * is provided), because the whole src-dst part of eth header is cached
	 */
	memcpy(nh->nh.nh_eth.ether_shost,
	       __fp_ifuid2ifnet(ifuid)->if_mac,
	       FP_ETHER_ADDR_LEN);

	nh->nh.nh_l2_state = state;

	/*
	 * Any neighbour activity in a route may have impact on ordering
	 */
	if (entry)
		fp_rt6_nh6_reorder (entry, 0);

	return 0;
}

/*  */
uint32_t
fp_delete_neighbour6(fp_in6_addr_t * addr, uint32_t ifuid)
{
	fp_rt6_entry_t *rte = NULL;
	fp_nh6_entry_t *nhe = NULL;
	int link_local = 0;
	uint32_t nh_index;
	uint16_t vrfid;

	/* reject neighbours on unknown interface */
	if (ifuid == 0)
		return 0;

	vrfid = ifuid2vrfid(ifuid);
	if (vrfid >= FP_MAX_VR)
		return 0;

	/* FPM may call twice fp_delete_neighbour, when entry cannot be resolved. */
	if(unlikely(fp_in6_is_link_local(*addr))) {
		link_local = 1;
	}

	if (likely(!link_local)) {
		int i;
		rte = __fp_find_neighbour6(addr, ifuid);
		if (rte == NULL)
			return 0;

		for (i = 0; i < rte->rt.rt_nb_nh; i++) {
			nh_index = rte->rt.rt_next_hop[i];
			nhe = &fp_shared->fp_nh6_table[nh_index];
			if ((nhe->nh.rt_type == RT_TYPE_NEIGH) &&
			    is_in6_addr_equal(nhe->nh_gw, *addr) &&
			    (nhe->nh.nh_ifuid == ifuid))
				break;
		}
		if (i == rte->rt.rt_nb_nh)
			return 0;
	}
	else {
		nh_index = fp_find_nh6_entry(addr, ifuid, RT_TYPE_NEIGH, 0, NULL);
		if (nh_index == 0)
			return 0;
		nhe = &fp_shared->fp_nh6_table[nh_index];
	}

	/*
	 * Do nothing for nh already in L2_STATE_NONE state
	 */
	if (nhe->nh.nh_l2_state == L2_STATE_NONE)
		return 0;

	nhe->nh.nh_l2_state = L2_STATE_NONE;
	memset(nhe->nh.nh_eth.ether_dhost, 0, FP_ETHER_ADDR_LEN);

	if(likely(!link_local)) {
		uint16_t vrfid;
		/*
		 * As in fp_add_neighbour(), neighbours are managed as /128
		 * routes. The route MUST persist until nobody else uses the
		 * next-hop. We expect this route del to change NH from type
		 * RT_TYPE_NEIGH to RT_TYPE_ROUTE, and also to update the
		 * entry->rt.rt_neigh_index
		 */
		vrfid = ifuid2vrfid(ifuid);
		fp_delete_route6_nhmark(vrfid, addr, 128, addr, ifuid,
		                        nhe->nh.rt_type, NULL);
	} else {
		nhe->nh.rt_type = RT_TYPE_ROUTE;
		fp_nh6_put(nh_index);
	}
	return 0;
}

/* 
 * IP address management. 
 * We make IP/128 route.
 */
uint32_t 
fp_add_address6(fp_in6_addr_t * addr, uint32_t ifuid)
{
	fp_ifnet_t *ifp = NULL;
	unsigned int i;
	fp_in6_addr_t a;
	uint16_t vrfid = ifuid2vrfid(ifuid);
	uint32_t index;

	ifp = fp_ifuid2ifnet(ifuid);
	if(fp_ifnet_is_invalid(ifp))
		return 1;

	if (vrfid >= FP_MAX_VR) 
		return 1;

	/* allocate a new address object &&
	 * add this one to the address list of the interfaces
	 */
	index = fp_pool_get_addr6();
	if (index >= FP_MAX_NB_ADDR6)
		return 1;

	/* set addr and next element */
	fp_pool_addr6_object(index).addr6 = *addr;
	fp_pool_addr6_object(index).next = ifp->if_addr6_head_index;

	ifp->if_addr6_head_index = index;
	ifp->if_nb_addr6++;

	memset(&a, 0, sizeof(fp_in6_addr_t));

	/* We trust FPM to not add it twice. */

	/* Add IP/128 route. */
	i = fp_add_route6_nhmark(vrfid, addr, 128, &a, ifuid, RT_TYPE_ADDRESS, NULL);

	return i;
}

/*  */
uint32_t 
fp_delete_address6(fp_in6_addr_t * addr, uint32_t ifuid)
{
	fp_in6_addr_t a;
	uint16_t vrfid = ifuid2vrfid(ifuid);
	fp_ifnet_t *ifp = NULL;

	ifp = fp_ifuid2ifnet(ifuid);
	if (fp_ifnet_is_invalid(ifp))
		return 1;

	/* remove addr from the address list of the interfaces */
	if (fp_pool_remove_addr6(*addr, &ifp->if_addr6_head_index))
		return 1;
	ifp->if_nb_addr6--;

	memset(&a, 0, sizeof(fp_in6_addr_t));

	/* Remove IP/128 */
	fp_delete_route6_nhmark(vrfid, addr, 128, &a, ifuid, RT_TYPE_ADDRESS, NULL);

	return 0;
}

#endif /* CONFIG_MCORE_IPV6 */

void fp_route_flush_per_vrf(uint16_t vrfid)
{
	int i = 0, j;

	/* First, clean descriptor tables */
#ifdef CONFIG_MCORE_RT_IP_BASE8
	memset(&fp_shared->fp_8_entries[fp_shared->fp_8_table[i + vrfid].entries],
	       0, sizeof(fp_table_entry_t) * (1 << 8));
	i += FP_MAX_VR;
#endif
#if defined(CONFIG_MCORE_IPV6) && defined(CONFIG_MCORE_RT_IPV6_BASE8)
	memset(&fp_shared->fp_8_entries[fp_shared->fp_8_table[i + vrfid].entries],
	       0, sizeof(fp_table_entry_t) * (1 << 8));
	i += FP_MAX_VR;
#endif
	for ( ; i < FP_NB_8_TABLE_ENTRIES; i++) {
		if (fp_shared->fp_8_table[i].vrfid != vrfid)
			continue;

		fp_shared->fp_8_table[i].used = 0;
		memset(&fp_shared->fp_8_entries[fp_shared->fp_8_table[i].entries],
		       0, sizeof(fp_table_entry_t) * (1 << 8));
	}

	i = 0;
#ifndef CONFIG_MCORE_RT_IP_BASE8
	memset(&fp_shared->fp_16_entries[fp_shared->fp_16_table[i + vrfid].entries],
	       0, sizeof(fp_table_entry_t) * (1 << 16));
	i += FP_MAX_VR;
#endif
#if defined(CONFIG_MCORE_IPV6) && !defined(CONFIG_MCORE_RT_IPV6_BASE8)
	memset(&fp_shared->fp_16_entries[fp_shared->fp_16_table[i + vrfid].entries],
	       0, sizeof(fp_table_entry_t) * (1 << 16));
	i += FP_MAX_VR;
#endif
	for ( ; i < FP_NB_16_TABLE_ENTRIES; i++) {
		if (fp_shared->fp_16_table[i].vrfid != vrfid)
			continue;

		fp_shared->fp_16_table[i].used = 0;
		memset(&fp_shared->fp_16_entries[fp_shared->fp_16_table[i].entries],
		       0, sizeof(fp_table_entry_t) * (1 << 16));
	}

	/* Second, clean rt and nh entries */
	for (i = 0; i < FP_IPV4_NBRTENTRIES; i++) {
		fp_rt4_entry_t *rt4 = &fp_shared->fp_rt4_table[i];

		if (rt4->rt.rt_vrfid != vrfid)
			continue;

		for (j = 0; j < rt4->rt.rt_nb_nh; j++)
			fp_nh4_put(rt4->rt.rt_next_hop[j]);

		fp_rt4_mput(i, rt4->rt.rt_refcnt);
	}

#ifdef CONFIG_MCORE_IPV6
	for (i = 0; i < FP_IPV6_NBRTENTRIES; i++) {
		fp_rt6_entry_t *rt6 = &fp_shared->fp_rt6_table[i];

		if (rt6->rt.rt_vrfid != vrfid)
			continue;

		for (j = 0; j < rt6->rt.rt_nb_nh; j++)
			fp_nh6_put(rt6->rt.rt_next_hop[j]);

		fp_rt6_mput(i, rt6->rt.rt_refcnt);
	}
#endif
}
