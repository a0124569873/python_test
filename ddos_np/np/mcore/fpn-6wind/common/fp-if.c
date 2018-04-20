/*
 * Copyright(c) 2006 6WIND
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#ifndef __FastPath__
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#endif

#include "fp.h"
#include "fpn-port.h"
#include "net/fp-ethernet.h"

#ifdef CONFIG_MCORE_LAG
#include "fp-bonding-var.h"
#endif

#ifndef __FastPath__
#define fpn_wmb() __sync_synchronize()

/* comes from fpn-6wind/fpdebug/fpdebug.c fpn-6wind/fpm/main_fpm.c */
extern int f_colocalized;
#endif

FPN_SLIST_HEAD(fp_if_notifier_lst, fp_if_notifier);

static FPN_DEFINE_SHARED(struct fp_if_notifier_lst, fp_if_notifiers);

int fp_if_notifier_register(fp_if_notifier_t *notifier)
{
	if (!notifier)
		return -1;
	FPN_SLIST_INSERT_HEAD(&fp_if_notifiers, notifier, next);
	return 0;
}

/*
 * assign a free cell in the ifnet table
 */
static uint32_t fp_ifnet_assign(uint32_t ifuid)
{
	uint32_t h;
	uint32_t idx, i;
	static uint32_t last_idx_found = 1;

	/* Prefer to return the hash value as index */
	h = fp_ifuid2hash(ifuid);
	if (h && h < FP_MAX_IFNET && fp_shared->ifnet.table[h].if_ifuid == 0)
		return h;

	for (idx = last_idx_found, i=1; i < FP_MAX_IFNET; i++, idx++) {
		if (unlikely(idx == FP_MAX_IFNET))
			idx = 1;
		if (fp_shared->ifnet.table[idx].if_ifuid == 0) {
			last_idx_found = idx;
			return idx;
		}
	}

	return 0;
}

/* insert ifnet into hash table */
static inline void fp_ifnet_hash(uint32_t idx)
{
	uint32_t h;
	fp_ifnet_t *ifp = &fp_shared->ifnet.table[idx];

	h = fp_ifuid2hash(ifp->if_ifuid);
	fp_hlist_add_head(&fp_shared->ifnet.hash[h], fp_shared->ifnet.table, idx, ifuid_hlist);
}

/* remove ifnet from hash table */
static inline void fp_ifnet_unhash(fp_ifnet_t *ifp)
{
	uint32_t idx = fp_index_in_table(fp_shared->ifnet.table, ifp); 
	uint32_t h;

	h = fp_ifuid2hash(ifp->if_ifuid);
	fp_hlist_remove(&fp_shared->ifnet.hash[h], fp_shared->ifnet.table, idx, ifuid_hlist);
}
#ifdef CONFIG_MCORE_VRF
int fp_set_if_vrfid(const char *name, uint16_t vrfid)
{
	fp_ifnet_t *ifp;
	if ((ifp = fp_getifnetbyname(name)) == NULL)
		return -1;

	if (vrfid > FP_MAX_VR)
		return -1;

	ifp->if_vrfid = vrfid;

	return 0;
}
#endif
int fp_addifnet(uint16_t vrfid, const char* name, const uint8_t *mac, 
                uint32_t mtu, uint32_t ifuid, uint8_t port, uint8_t type)
{
	fp_ifnet_t *ifp;
	uint32_t idx;
	uint32_t op;

	/* Do nothing if interface is already configured */
	if (fp_ifuid2ifnet(ifuid))
		return FP_ADDIFNET_EXIST;

	/* assign a cell in the ifnet table */
	if ((idx = fp_ifnet_assign(ifuid)) == 0)
		return FP_ADDIFNET_ERROR;

	/* Fill ifnet structure */
	ifp = &fp_shared->ifnet.table[idx];

	memset(ifp, 0, sizeof(*ifp));

	/* Initialize cached ops */
	for (op = 0 ; op < FP_IFNET_MAX_OPS ; op++)
		ifp->if_ops[op].func = INVALID_FUNC;

	strncpy(ifp->if_name, name, sizeof(ifp->if_name));
	ifp->if_ifuid = ifuid;
	ifp->if_port = port;
	ifp->if_type = type;
#ifdef CONFIG_MCORE_VRF
	ifp->if_vrfid = vrfid;
#endif
	/* Note : change storage size for mtu 32->16 bits */
	if (mtu > 65535)
		ifp->if_mtu = 65535;
	else
		ifp->if_mtu = mtu;
	if (mac)
		memcpy(ifp->if_mac, mac, FP_ETHER_ADDR_LEN);
	else
		memset(ifp->if_mac, 0, FP_ETHER_ADDR_LEN);
	/* Clear all CP-originated flags */
	ifp->if_flags &= ~IFF_CP_MASK;

	/* register physical port */
	if (port != FP_IFNET_VIRTUAL_PORT)
	{
		fp_shared->ifport[port].ifuid = ifuid;
		fp_shared->ifport[port].cached_ifp = NULL;
	}

	fp_ifnet_hash(idx);
	fp_ifnet_name_link(ifp);

#ifdef CONFIG_MCORE_IP
	ifp->if_addr4_head_index = FP_ADDR_INDEX_NONE;
	ifp->if_nb_addr4 = 0;
#endif

#ifdef CONFIG_MCORE_IPV6
	ifp->if_addr6_head_index = FP_ADDR_INDEX_NONE;
	ifp->if_nb_addr6 = 0;
#endif

#ifdef __FastPath__
	fp_if_notifier_t *notifier;

	FPN_SLIST_FOREACH (notifier, &fp_if_notifiers, next) {
		if (notifier->add)
			notifier->add(vrfid, name, mac, mtu, ifuid, port, type);
	}
#endif

	return FP_ADDIFNET_SUCCESS;
}

int fp_delifnet(uint32_t ifuid)
{
	fp_ifnet_t *ifp;
	uint8_t portid;

	if ((ifp = fp_ifuid2ifnet(ifuid)) == NULL)
		return -1;

	/* remove physical mapping */
	portid = ifp->if_port;
	if ((portid != FP_IFNET_VIRTUAL_PORT) &&
	    (ifuid == fp_shared->ifport[portid].ifuid))
	{
		fp_shared->ifport[portid].ifuid = 0;
		fp_shared->ifport[portid].cached_ifp = NULL;
	}

	fp_ifnet_name_unlink(ifp);
	fp_ifnet_unhash(ifp);

	ifp->if_ifuid = 0;

#ifdef CONFIG_MCORE_IP
	fp_pool_free_list_addr4(ifp->if_addr4_head_index, ifuid, ifp->if_vrfid);
	ifp->if_nb_addr4 = 0;
#endif

#ifdef CONFIG_MCORE_IPV6
	fp_pool_free_list_addr6(ifp->if_addr6_head_index);
	ifp->if_nb_addr6 = 0;
#endif

	return 0;
}

int fp_setifnet_mac(uint32_t ifuid, const uint8_t *mac)
{
	fp_ifnet_t *ifp;

	if ((ifp = fp_ifuid2ifnet(ifuid)) == NULL)
		return -1;

#ifdef CONFIG_MCORE_BRIDGE
	fp_bridge_port_update_mac(ifp, ifp->if_mac, mac);
#endif

	memcpy(ifp->if_mac, mac, FP_ETHER_ADDR_LEN);

	fp_update_l2_src(mac, ifuid);

	return fp_interface_set_mac(ifp, mac);
}

int fp_setifnet_master(uint32_t slave_ifuid, const uint32_t master_ifuid)
{
	fp_ifnet_t *ifslave;
#if defined(CONFIG_MCORE_LAG)
	fp_ifnet_t *ifmaster;
#endif

	if ((ifslave = fp_ifuid2ifnet(slave_ifuid)) == NULL)
		return -1;

#if defined(CONFIG_MCORE_LAG)
	if (master_ifuid)
		ifmaster = fp_ifuid2ifnet(master_ifuid);
	else
		ifmaster = fp_ifuid2ifnet(ifslave->if_master_ifuid);

	if (ifmaster && ifmaster->if_type == FP_IFTYPE_BONDING)
		fp_bonding_slave_set(ifslave, master_ifuid);
#endif

	ifslave->if_master_ifuid = master_ifuid;
	return 0;
}

int fp_setifnet_mtu(uint32_t ifuid, const uint32_t mtu)
{
	fp_ifnet_t *ifp;

	if ((ifp = fp_ifuid2ifnet(ifuid)) == NULL)
		return -1;

	ifp->if_mtu = mtu;
	return fp_interface_set_mtu(ifp, mtu);
}

int fp_setifnet_tcpmss4(__fpn_maybe_unused uint32_t ifuid, __fpn_maybe_unused const uint32_t mss)
{
#ifdef CONFIG_MCORE_TCP_MSS
	fp_ifnet_t *ifp;

	if ((ifp = fp_ifuid2ifnet(ifuid)) == NULL)
		return -1;

	ifp->if_tcp4mss = mss;
#endif
	return 0;
}

int fp_setifnet_tcpmss6(__fpn_maybe_unused uint32_t ifuid, __fpn_maybe_unused const uint32_t mss)
{
#if defined(CONFIG_MCORE_TCP_MSS) && defined(CONFIG_MCORE_IPV6)
	fp_ifnet_t *ifp;

	if ((ifp = fp_ifuid2ifnet(ifuid)) == NULL)
		return -1;

	ifp->if_tcp6mss = mss;
#endif
	return 0;
}

#ifdef CONFIG_MCORE_IP_REASS
/* Update do_forced_reassembly according to interface flags */
static void fp_sync_do_reass_flag(const uint16_t flags)
{
	unsigned int i;
	fp_ifnet_t *ifp;

	/* enable reassembly in cache as soon as one interface requires it */
	if (flags & (IFF_FP_IPV4_FORCE_REASS | IFF_FP_IPV6_FORCE_REASS)) {
		fp_shared->conf.s.do_forced_reassembly = 1;
		return;
	}

	/* leave if it is already disabled in the cache */
	if (fp_shared->conf.s.do_forced_reassembly == 0)
		return;

	/* look other interfaces to check if we can disable in the cache */
	for (i = 0;  i < FP_MAX_IFNET; i++) {
		ifp =  &fp_shared->ifnet.table[i];
		if (ifp->if_ifuid != 0 &&
			ifp->if_flags & (IFF_FP_IPV4_FORCE_REASS | IFF_FP_IPV6_FORCE_REASS))
			return; /* keep the cache enabled */
	}

	/* no interface requires forced reassembly */
	fp_shared->conf.s.do_forced_reassembly = 0;
}

int fp_setifnet_force_reassembly4(uint32_t ifuid, const uint32_t command)
{
	fp_ifnet_t *ifp;

	if ((ifp = fp_ifuid2ifnet(ifuid)) == NULL)
		return -1;
	if (command)
		ifp->if_flags |= IFF_FP_IPV4_FORCE_REASS;
	else
		ifp->if_flags &= ~IFF_FP_IPV4_FORCE_REASS;

	fp_sync_do_reass_flag(ifp->if_flags);

	return 0;
}

#ifdef CONFIG_MCORE_IPV6_REASS
int fp_setifnet_force_reassembly6(uint32_t ifuid, const uint32_t command)
{
	fp_ifnet_t *ifp;

	if ((ifp = fp_ifuid2ifnet(ifuid)) == NULL)
		return -1;

	if (command)
		ifp->if_flags |= IFF_FP_IPV6_FORCE_REASS;
	else
		ifp->if_flags &= ~IFF_FP_IPV6_FORCE_REASS;

	fp_sync_do_reass_flag(ifp->if_flags);

	return 0;
}
#endif
#endif

#if defined(CONFIG_MCORE_LAG)
static int fp_setifnet_slave_flags(fp_ifnet_t *ifslave,
				   const uint16_t flags)
{
	fp_ifnet_t *ifmaster;

	ifmaster = fp_ifuid2ifnet(ifslave->if_master_ifuid);

	if (ifmaster && ifmaster->if_type == FP_IFTYPE_BONDING)
		fp_bonding_slave_flags_set(ifslave);

	return 0;
}
#endif

int fp_setifnet_flags(const uint32_t ifuid, const uint16_t flags)
{
	fp_ifnet_t *ifp;
	uint16_t old_flags;
	uint16_t mask = IFF_CP_PROMISC | IFF_CP_UP;

	ifp = __fp_ifuid2ifnet(ifuid);
	old_flags = ifp->if_flags;
	ifp->if_flags = (ifp->if_flags & IFF_FP_MASK) | (flags & IFF_CP_MASK); 
	/* if goes down, there may be some route clean up to do */
	if ( (old_flags & IFF_CP_UP) && !(flags & IFF_CP_UP) )
		fp_setifnet_down(ifp);
	/* if preferred flag is modified */
	if ( (!!(old_flags & IFF_FP_PREF)) != (!!(flags & IFF_CP_PREFERRED)) )
		fp_setifnet_preferred(ifp, !!(flags & IFF_CP_PREFERRED));
	if ((flags & mask) != (old_flags & mask))
		fp_interface_set_flags(ifp, flags & mask);

#if defined(CONFIG_MCORE_LAG)
	/* bonding need to know when an iface switch down/up */
	if (ifp->if_master_ifuid)
		fp_setifnet_slave_flags(ifp, flags);
#endif

	return 0;
}

int fp_setifnet_preferred(fp_ifnet_t *ifp, const int pref)
{
#ifdef CONFIG_MCORE_IP
	int i, j;

	if (pref)
		ifp->if_flags |= IFF_FP_PREF; 
	else
		ifp->if_flags &= ~IFF_FP_PREF; 

	/*
	 * Any route having at least one next-hop associated
	 * to the interface MUST have its next-hops re-ordered
	 */
	for (i = 1; i < FP_IPV4_NBRTENTRIES; i++) {
		fp_rt4_entry_t *rte;
		rte = &fp_shared->fp_rt4_table[i];
		if (! rte->rt.rt_refcnt)
			continue;
		for (j=0; j<rte->rt.rt_nb_nh; j++) {
			fp_nh4_entry_t *nhe;
			nhe = &fp_shared->fp_nh4_table[rte->rt.rt_next_hop[j]];
			if (nhe->nh.nh_ifuid == ifp->if_ifuid) {
				fp_rt4_nh4_reorder(rte, 1, NULL);
				/*
				 * Once is enough for the current rte
				 */
				break;
			}
		}
	}
#endif
#ifdef CONFIG_MCORE_IPV6
	for (i = 1; i < FP_IPV6_NBRTENTRIES; i++) {
		fp_rt6_entry_t *rte;
		rte = &fp_shared->fp_rt6_table[i];
		if (! rte->rt.rt_refcnt)
			continue;
		for (j=0; j<rte->rt.rt_nb_nh; j++) {
			fp_nh6_entry_t *nhe;
			nhe = &fp_shared->fp_nh6_table[rte->rt.rt_next_hop[j]];
			if (nhe->nh.nh_ifuid == ifp->if_ifuid) {
				fp_rt6_nh6_reorder(rte, 1);
				/*
				 * Once is enough for the current rte
				 */
				break;
			}
		}
	}
#endif
	return 0;
}

int fp_setifnet_down (fp_ifnet_t *ifp)
{
#ifdef CONFIG_MCORE_IFDOWN_CLEANUP
	/*
	 *  Clean any IPv4 route using this interface.
	 * (IPv6 route clean-up is expected to be already
	 *  done thanks to kernel messages)
	 */
	if (ifp->if_nb_rt4 != 0)
		fp_rt4_ifscrub(ifp);
#endif
	return 0;
}

int fp_setifnet_bladeinfo(uint32_t ifuid, uint8_t blade_id)
{
	fp_ifnet_t *ifp;

	ifp = fp_ifuid2ifnet(ifuid);
	if (ifp)
		ifp->if_blade    = blade_id;

	return 0;
}

int fp_setifnet_veth_peer(const uint32_t ifuid, const uint32_t peer_ifuid)
{
	fp_ifnet_t *ifp, *peer_ifp;

	ifp = fp_ifuid2ifnet(ifuid);
	if (ifp == NULL ||
	    ifp->if_type != FP_IFTYPE_VETH)
		return -1;

	ifp->sub_table_index = peer_ifuid;

	peer_ifp = fp_ifuid2ifnet(peer_ifuid);
	if (peer_ifp == NULL ||
	    peer_ifp->if_type != FP_IFTYPE_VETH)
		return -1;

	peer_ifp->sub_table_index = ifuid;
	return 0;
}

void fp_ifnet_name_link(fp_ifnet_t *ifp)
{
	uint32_t idx = fp_index_in_table(fp_shared->ifnet.table, ifp);
	uint32_t hash;

	hash = fp_ifnet_hash_name(ifp->if_name);

	fp_hlist_add_tail(&fp_shared->ifnet.name_hash[hash], fp_shared->ifnet.table, idx, name_hlist);
}

void fp_ifnet_name_unlink(fp_ifnet_t *ifp)
{
	uint32_t idx = fp_index_in_table(fp_shared->ifnet.table, ifp); 
	uint32_t hash;

	hash = fp_ifnet_hash_name(ifp->if_name);
	fp_hlist_remove(&fp_shared->ifnet.name_hash[hash], fp_shared->ifnet.table, idx, name_hlist);
}

int fp_ifnet_ops_register(fp_ifnet_t *ifp, int type, uint16_t mod_uid, void *data)
{
	if (ifp->if_ops[type].mod_uid != 0)
		return 1;

	/* Copy function and data under seqlock */
	fp_seq_write_lock(&ifp->seqlock);

	/* First invalidate cache; seqlock will ensure that new */
	/* mod_uid/data pair is written before setting mod_uid in cache */
	ifp->if_ops[type].func = INVALID_FUNC;
	fpn_wmb();

	/* Setup new mod_uid/data pair */
	ifp->if_ops[type].mod_uid = mod_uid;
	ifp->if_ops[type].data = (size_t) data;

	/* Unlock seqlock */
	fp_seq_write_unlock(&ifp->seqlock);

	return 0;
}

void fp_ifnet_ops_unregister(fp_ifnet_t *ifp, int type)
{
	fp_seq_write_lock(&ifp->seqlock);

	/* First invalidate cache; seqlock will ensure that new */
	/* mod_uid/data pair is written before setting mod_uid in cache */
	ifp->if_ops[type].func = INVALID_FUNC;
	fpn_wmb();

	/* Clear mod_uid */
	ifp->if_ops[type].mod_uid = 0;

	/* Unlock seqlock */
	fp_seq_write_unlock(&ifp->seqlock);
}

void *fp_ifnet_ops_cache(fp_ifnet_t *ifp, int type, void **data)
{
	fp_seqlock_t seqstart;
	uint16_t mod_uid;
	void *func;

	do {
		seqstart = fp_seq_read_start(&ifp->seqlock);
		mod_uid = ifp->if_ops[type].mod_uid;
		func = fp_shared->fp_modules[mod_uid].if_ops[type];
		*data = (void *)(size_t) ifp->if_ops[type].data;
	} while (fp_seq_write_inprogress(&ifp->seqlock) ||
			 fp_seq_read_invalid(&ifp->seqlock, seqstart));

	/* Store function in cache */
	ifp->if_ops[type].func = (size_t) func;

	return(func);
}

#ifndef __FastPath__
extern int netfpc_notify_mtu(fp_ifnet_t *ifp, uint32_t mtu);
#endif

int fp_interface_set_mtu(fp_ifnet_t *ifp, uint32_t mtu)
{
#ifndef __FastPath__
	struct ifreq ifr;
	/* SIOCSIFMTU */
	int s;
#endif
	uint16_t capa;

	if (ifp->if_port == FP_IFNET_VIRTUAL_PORT)
		return EXIT_SUCCESS;

	if (!fpn_port_shmem)
		goto skip_capa;

	capa = fpn_port_shmem->port[ifp->if_port].driver_capa;
	if (capa & FPN_DRIVER_SET_MTU_FPN) {
#ifndef __FastPath__
		return netfpc_notify_mtu(ifp, mtu);
#else
		return fpn_set_mtu(ifp->if_port, mtu);
#endif
	} else if (capa & FPN_DRIVER_SET_MTU_NOOP) {
		return 0;
	}

skip_capa:
#ifndef __FastPath__
	/* TODO: move this to driver capa configuration */
	/* do nothing in coloc mode, the kernel does it already */
	if (f_colocalized)
		return EXIT_SUCCESS;

	s = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifp->if_name, IFNAMSIZ);
	ifr.ifr_mtu = mtu;
	if (ioctl(s, SIOCSIFMTU, &ifr) < 0) {
		fp_log_common(LOG_ERR, "cannot set mtu to %d on %s: %s\n",
			      mtu, ifp->if_name, strerror(errno));
		close(s);
		return EXIT_FAILURE;
	}

	close(s);
#endif
	return EXIT_SUCCESS;
}

#ifndef __FastPath__
extern int netfpc_notify_mac(fp_ifnet_t *ifp, const uint8_t *mac);
#endif

int fp_interface_set_mac(fp_ifnet_t *ifp, const uint8_t *mac)
{
#ifndef __FastPath__
	struct ifreq ifr;
	int s;
#endif
	uint16_t capa;

	if (ifp->if_port == FP_IFNET_VIRTUAL_PORT)
		return EXIT_SUCCESS;

	if (!fpn_port_shmem)
		goto skip_capa;

	capa = fpn_port_shmem->port[ifp->if_port].driver_capa;
	if (capa & FPN_DRIVER_SET_MAC_FPN) {
#ifndef __FastPath__
		return netfpc_notify_mac(ifp, mac);
#else
		return fpn_set_mac(ifp->if_port, mac);
#endif
	} else if (capa & FPN_DRIVER_SET_MAC_NOOP) {
		return 0;
	}

skip_capa:
#ifndef __FastPath__
	/* TODO: move this to driver capa configuration */
	/* do nothing in coloc mode, the kernel does it already */
	if (f_colocalized)
		return EXIT_SUCCESS;

	s = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifp->if_name, IFNAMSIZ);
	memcpy(&ifr.ifr_hwaddr.sa_data, mac, 6);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	if (ioctl(s, SIOCSIFHWADDR, &ifr) < 0) {
		fp_log_common(LOG_ERR, "cannot set address on %s: %s\n",
			      ifp->if_name, strerror(errno));
		close(s);
		return EXIT_FAILURE;
	}

	close(s);
#endif
	return EXIT_SUCCESS;
}

#ifndef __FastPath__
extern int netfpc_notify_flags(fp_ifnet_t *ifp, const uint32_t flags);
#endif

int fp_interface_set_flags(fp_ifnet_t *ifp, const uint32_t flags)
{
#ifndef __FastPath__
	struct ifreq ifr;
	int s;
#endif
	uint16_t capa;

	if (ifp->if_port == FP_IFNET_VIRTUAL_PORT)
		return EXIT_SUCCESS;

	if (!fpn_port_shmem)
		goto skip_capa;

	capa = fpn_port_shmem->port[ifp->if_port].driver_capa;
	if (capa & FPN_DRIVER_SET_FLAGS_FPN) {
#ifndef __FastPath__
		return netfpc_notify_flags(ifp, flags);
#else
		uint32_t bitmask = 0;

		if (flags & IFF_CP_PROMISC)
			bitmask |= FPN_FLAGS_PROMISC;
		if (flags & IFF_CP_UP)
			bitmask |= FPN_FLAGS_LINK_UP;

		return fpn_set_flags(ifp->if_port, bitmask);
#endif
	} else if (capa & FPN_DRIVER_SET_FLAGS_NOOP) {
		return 0;
	}

skip_capa:
#ifndef __FastPath__
	/* TODO: move this to driver capa configuration */
	/* do nothing in coloc mode, the kernel does it already */
	if (f_colocalized)
		return EXIT_SUCCESS;

	s = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifp->if_name, IFNAMSIZ);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		fp_log_common(LOG_ERR, "cannot get flags on %s: %s\n",
			      ifp->if_name, strerror(errno));
		close(s);
		return EXIT_FAILURE;
	}

	if (flags & IFF_CP_PROMISC) {
		ifr.ifr_flags = (ifr.ifr_flags & ~IFF_ALLMULTI);
		ifr.ifr_flags = (ifr.ifr_flags | IFF_PROMISC);
	} else {
		/* XXX: hack, we need allmulti flag all the
		   time to catch neighbor solicits */
		ifr.ifr_flags = (ifr.ifr_flags | IFF_ALLMULTI);
		ifr.ifr_flags = (ifr.ifr_flags & ~IFF_PROMISC);
	}

	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		fp_log_common(LOG_ERR, "cannot set flags on %s: %s\n",
			      ifp->if_name, strerror(errno));
		close(s);
		return EXIT_FAILURE;
	}

	close(s);
#endif
	return EXIT_SUCCESS;
}
