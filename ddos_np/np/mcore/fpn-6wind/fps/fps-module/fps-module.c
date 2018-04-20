/*
 * Copyright (C) 2012 6WIND, All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* 6WIND_GPL */

#include <linux/version.h>

#ifdef RHEL_RELEASE_CODE
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,5) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0)
#define RHEL65
#endif
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,6) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0)
#define RHEL66
#endif
#endif

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/netns/mib.h>
#include <net/xfrm.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
#include <linux/if_arp.h>
#endif
#ifdef RHEL65
#include <linux/u64_stats_sync.h>
#endif

#include <ifuid.h>

#include "fp-rfps-proto.h"
#include "fp-blade.h"
#include "fps-macro.h"

/*
 * =====================================
 * RFPS - Distributed Control Plane Role
 * =====================================
 *
 * Implement the "receive" side of the FP2CP RFPS protocol, and the set of
 * functions which return aggregated statistics.
 */

/*
 * Statistics counters are transmitted and are stored in the CPU byte order
 * of the sending blade. They are converted to the local CPU byte order
 * when beeing returned their value.
 * The underlying rationale is that statistics are retrieved at a much lower
 * rate than their transmission rate.
 * The "big_endian_blades_map" array records the CPU byte order of peer
 * blades from which statistics messages have been received.
 * Note: this array is updated upon receipt of each message, hopefully with
 * the same value for the same blade.
 */
#ifndef FP_BLADEID_MAX
#error  "FP_BLADEID_MAX undefined"
#else
#define RFPS_BLADEID_MAX FP_BLADEID_MAX
#endif

static uint8_t big_endian_blades_map[RFPS_BLADEID_MAX+1];
static int max_blade_id = RFPS_BLADEID_MAX;
module_param(max_blade_id, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(max_blade_id, "the MAX blade_id for CP or COLOC mode");

#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
/* define default soft/hard packet limit value */
static ulong default_soft_packet_limit32 = 0xffffffff;
module_param(default_soft_packet_limit32, ulong, 0644);
MODULE_PARM_DESC(default_soft_packet_limit32,
		 "set default soft packet limit value");
static ulong default_hard_packet_limit32 = 0xffffffff;
module_param(default_hard_packet_limit32, ulong, 0644);
MODULE_PARM_DESC(default_hard_packet_limit32,
		 "set default hard packet limit value");

/* max packet number for sa, if ESN is not enabled on SA */
#define MAX_PACKET_LIMIT32 0xffffffff

#endif

static void fps_update_common_snmp_stat(struct ipstats_mib *delta, void * ptr_stat)
{
	int i;
	struct ipstats_mib *kernel_mibs;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
	kernel_mibs = per_cpu_ptr(ptr_stat, get_cpu());
	for (i=0; i<IPSTATS_MIB_MAX; i++)
		kernel_mibs->mibs[i] += delta->mibs[i];
	put_cpu();
#else
	preempt_disable();
	kernel_mibs = this_cpu_ptr(ptr_stat);
	for (i=0; i<IPSTATS_MIB_MAX; i++)
		kernel_mibs->mibs[i] += delta->mibs[i];
	preempt_enable();
#endif
}

static void fps_update_snmp_stat(struct ipstats_mib *delta)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
	fps_update_common_snmp_stat(delta, init_net.mib.ip_statistics);
#else
	fps_update_common_snmp_stat(delta, init_net.mib.ip_statistics[0]);
#endif
}

#ifdef CONFIG_MCORE_IPV6
static void fps_update_snmp6_stat(struct ipstats_mib *delta)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
	fps_update_common_snmp_stat(delta, init_net.mib.ipv6_statistics);
#else
	fps_update_common_snmp_stat(delta, init_net.mib.ipv6_statistics[0]);
#endif
}
#endif

#define __fps_dev_stats	atalk_ptr

struct fps_net_dev_stats {
	struct net_device_stats stats[0];
};


#define STRUCT_FIELD_ADD_DELTA(dst, curr, prev, field)	do {	\
	(dst)->field += (curr)->field - (prev)->field;	\
} while (0)

#define FPS_UPDATE_FPS_STATS(dst, curr, prev)	do {	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), rx_packets);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), tx_packets);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), rx_bytes);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), tx_bytes);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), rx_errors);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), tx_errors);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), rx_dropped);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), tx_dropped);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), multicast);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), collisions);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), rx_length_errors);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), rx_over_errors);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), rx_crc_errors);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), rx_frame_errors);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), rx_fifo_errors);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), rx_missed_errors);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), tx_aborted_errors);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), tx_carrier_errors);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), tx_fifo_errors);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), tx_heartbeat_errors);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), tx_window_errors);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), rx_compressed);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), tx_compressed);	    \
} while (0)

#define FPS_UPDATE_FPS_PCPU_SW_NETSTATS(dst, curr, prev) do {		\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), rx_packets);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), tx_packets);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), rx_bytes);	\
	STRUCT_FIELD_ADD_DELTA((dst), (curr), (prev), tx_bytes);	\
} while (0)

/*
 * A "rfps_node_t" data structure is associated with each distributed object
 * for which statistics are received from peer blades in a distributed
 * architecture.
 * This concerns global remanent IPv4 and IPv6 nodes and dynamically
 * allocated nodes for Network Interfaces, IPsec Security Associations,
 * IPsec Security Policies, etc...
 * Dynamically allocated objects are assigned a 32-bit global unique identifier
 * which designates the same object on each blade.
 *
 * Dynamically allocated RFPS nodes are recorded into the hash list of the
 * rfps_map associated with the object type of the node.
 *
 * Each RFPS node includes an array of pointers to per-blade statistics entries.
 * Within a RFPS node, the statistics entry for a given blade is dynamically
 * allocated in a "lazzy" fashion upon receipt of the first FPTUN RFPS UPDATE
 * statistics message for that node from the given blade.
 */
typedef struct {
	struct hlist_node node_hentry; /* to insert the node into a hash list */
	uint32_t          node_uid;
	void              *blade_stats[RFPS_BLADEID_MAX+1]; /* per-blade stats */
	uint8_t           min_blade_id; /* lowest blade which sent stats */
	uint8_t           max_blade_id; /* highest blade which sent stats */
} rfps_node_t;

#define RFPS_NODE_HASHBITS 8
typedef struct {
	struct mutex      new_del_mutex; /* protect node creation/deletion */
	rwlock_t          update_lock; /* hlist add/remove and nodes updates */
	struct hlist_head node_list_heads[1 << RFPS_NODE_HASHBITS];
	unsigned int      fp_stats_size; /* size of FP stats entries */
} rfps_map_t;

/*
 * RFPS nodes
 */
static inline void rfps_node_init(rfps_node_t *rfps_node, uint32_t node_uid)
{
	memset(rfps_node, 0, sizeof(*rfps_node));
	rfps_node->node_uid = node_uid;
}

/*
 * Free all stats entries of the node, if any
 */
static void rfps_node_stats_entries_delete(rfps_node_t *rfps_node)
{
	uint8_t i;

	for (i = rfps_node->min_blade_id; i <= rfps_node->max_blade_id; i++) {
		void * blade_stats = rfps_node->blade_stats[i];

		if (blade_stats != NULL) {
			kfree(blade_stats);
		}
	}
}

static inline void rfps_node_delete(rfps_node_t *rfps_node)
{
	rfps_node_stats_entries_delete(rfps_node);
	kfree(rfps_node);
}

/*
 * Record the stats entry allocated for peer "bladeid"
 */
static inline void rfps_node_blade_stats_entry_add(rfps_node_t *rfps_node,
						   void        *fp_stats,
						   uint8_t     blade_id)
{
	rfps_node->blade_stats[blade_id] = fp_stats;

	if (rfps_node->min_blade_id == 0) {
		rfps_node->min_blade_id = blade_id;
		rfps_node->max_blade_id = blade_id;
	}
	if (rfps_node->min_blade_id > blade_id) {
		rfps_node->min_blade_id = blade_id;
	}
	if (rfps_node->max_blade_id < blade_id) {
		rfps_node->max_blade_id = blade_id;
	}
}

/*
 * RFPS IPv4 and IPv6 Statistics
 * A rfps_map_t structure is not needed for RFPS IP statistics because
 * IPv4 and IPv6 IP RFPS nodes are permanent objects.
 */

static rfps_node_t rfps_ipv4_node;
#ifdef CONFIG_MCORE_IPV6
static rfps_node_t rfps_ipv6_node;
#endif
static DEFINE_RWLOCK(rfps_ip_lock);

/*
 * replace the corresponding node with new ipstats_mib,
 * return the prev(old) ipstats_mib to calc delta.
 */
static struct ipstats_mib* rfps_update_rfps_ip_stats(rfps_node_t *ip_node,
		uint8_t  blade_id, struct ipstats_mib *stats)
{
	struct ipstats_mib *prev_stats;

	write_lock_bh(&rfps_ip_lock);
	prev_stats = ip_node->blade_stats[blade_id];
	rfps_node_blade_stats_entry_add(ip_node, stats, blade_id);
	write_unlock_bh(&rfps_ip_lock);

	return prev_stats;
}

static void rfp_update_rfps_stats_to_kernel(rfps_node_t *rfps_node,
		uint8_t blade_id, rfps_ip_stats_t *ip_stats,
		struct ipstats_mib *delta)
{
	int i;
	struct ipstats_mib *fp_mib;
	struct ipstats_mib *prev_mib;

	fp_mib = kzalloc(sizeof(struct ipstats_mib), GFP_ATOMIC);
	if (fp_mib == NULL)
		return;

	/* rfps_ip_stats_t ==> ipstats_mib */
	/*
	 * Copy statistics of the first blade to the Linux
	 * "ipstats_mib" structure.
	 */
#if defined __BIG_ENDIAN
	if (big_endian_blades_map[blade_id]) {
		/* no conversion - peer & local CPUs are Big Endian */
		COPY_FP_IP_STATS_TO_IPSTATS_MIB(ip_stats, fp_mib);
	} else {
		/* converts peer Little Endian to local Big Endian */
		COPY_LE_FP_IP_STATS_TO_IPSTATS_MIB(ip_stats, fp_mib);
	}
#elif defined __LITTLE_ENDIAN
	if (big_endian_blades_map[blade_id]) {
		/* converts peer Big Endian to local Little Endian */
		COPY_BE_FP_IP_STATS_TO_IPSTATS_MIB(ip_stats, fp_mib);
	} else {
		/* no conversion - peer & this CPUs are Little Endian */
		COPY_FP_IP_STATS_TO_IPSTATS_MIB(ip_stats, fp_mib);
	}
#else
#error "UNKNOWN ENDIANESS NOT SUPPORTED"
#endif

	memcpy(delta, fp_mib, sizeof(struct ipstats_mib));

	prev_mib = rfps_update_rfps_ip_stats(rfps_node, blade_id, fp_mib);
	if (prev_mib) {
		for (i=0; i<IPSTATS_MIB_MAX; i++)
			delta->mibs[i] -= prev_mib->mibs[i];
		kfree(prev_mib);
	}
}

/*
 * Store RFPS IP statistics received in a FPTUN RFPS UPDATE message
 */
static void rfps_ip_msg_handler(rfps_ip_stats_t *ip_stats,
				uint16_t        nb_stats,
				uint8_t         blade_id)
{
	struct ipstats_mib delta;

	memset(&delta, 0, sizeof(delta));
	rfp_update_rfps_stats_to_kernel(&rfps_ipv4_node, blade_id,
			ip_stats, &delta);
	fps_update_snmp_stat(&delta);
#ifdef CONFIG_MCORE_IPV6
	if (nb_stats == 2) {
		memset(&delta, 0, sizeof(delta));
		rfp_update_rfps_stats_to_kernel(&rfps_ipv6_node,
				blade_id, ip_stats+1, &delta);
		fps_update_snmp6_stat(&delta);
	}
#endif
}

#ifdef CONFIG_MCORE_IPSEC
/*
 * Store IPsec SA statistics received in a FPTUN RFPS UPDATE message
 * sent by the remote "blade_id".
 */
static void rfps_ipsec_sa_msg_handler(rfps_sa_stats_t *rsas,
	      uint16_t nb_stats, uint8_t blade_id)
{
	int i;
	uint64_t bytes;
	uint64_t packets;

	for (i = 0; i < nb_stats; i++, rsas++) {
		struct xfrm_state *x;
		struct net *net;

		if (rsas->sa_bytes == 0)
			continue;

		bytes = rsas->sa_bytes;
		packets = rsas->sa_packets;
#if defined __BIG_ENDIAN
		/* converts peer Little Endian to local Big Endian */
		if (!big_endian_blades_map[blade_id]) {
			bytes = __le64_to_cpu(bytes);
			packets = __le64_to_cpu(packets);
		}
#elif defined __LITTLE_ENDIAN
		/* converts peer Big Endian to local Little Endian */
		if (big_endian_blades_map[blade_id]) {
			bytes = __be64_to_cpu(bytes);
			packets = __be64_to_cpu(packets);
		}
#else
#error "UNKNOWN ENDIANESS NOT SUPPORTED"
#endif

		net = fps_vrfid_to_net(htons(rsas->vrfid));
		if (net == NULL)
			continue;
		/* Deal with vanilla and 6WIND VRF patched kernel */
		x = xfrm_state_lookup(net,
#ifdef CONFIG_NET_VRF
				              htons(rsas->vrfid),
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
							  0, /* mark */
#endif
							  (xfrm_address_t *)&rsas->daddr,
							  rsas->spi, rsas->proto, rsas->family);

		if (x) {
			spin_lock_bh(&x->lock);
#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
			/* if soft/hard packet limit is not set, use default value
			 * ESN is not taken into account now, for it is not supported */
			if ((x->lft.soft_packet_limit == XFRM_INF) ||
					(x->lft.soft_packet_limit > MAX_PACKET_LIMIT32))
				x->lft.soft_packet_limit = default_soft_packet_limit32;

			if ((x->lft.hard_packet_limit == XFRM_INF) ||
					(x->lft.hard_packet_limit > MAX_PACKET_LIMIT32))
				x->lft.hard_packet_limit = default_hard_packet_limit32;

#endif
			x->curlft.bytes = bytes;
			x->curlft.packets = packets;
			xfrm_state_check_expire(x);
			spin_unlock_bh(&x->lock);

			xfrm_state_put(x);
		}

	}
}

#endif /* CONFIG_MCORE_IPSEC */


static int fps_alloc_net_dev_fps_stats(struct net_device* dev)
{
	struct fps_net_dev_stats *fps_stats;
	int size;

	if (dev->__fps_dev_stats)
		return -1;

	BUG_ON(max_blade_id == 0);

	size = max_blade_id * sizeof(struct net_device_stats);

	fps_stats = kzalloc(size, GFP_ATOMIC);
	if (fps_stats == NULL)
		return -1;

	dev->__fps_dev_stats = fps_stats;
	dev_hold(dev);

	return 0;
}

static int fps_free_net_dev_fps_stats(struct net_device *dev)
{
	struct fps_net_dev_stats *fps_stats = dev->__fps_dev_stats;

	if (fps_stats == NULL)
		return 0;

	dev->__fps_dev_stats = NULL;

	kfree(fps_stats);

	dev_put(dev);

	return 0;
}

static int fps_ifdev_event(struct notifier_block *this,
		unsigned long event, void *ptr)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
	struct net_device *dev = ptr;
#else
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
#endif

	switch (event) {
	case NETDEV_REGISTER:
		if (fps_alloc_net_dev_fps_stats(dev))
			printk(KERN_WARNING "FPS: unable to register stats for dev %s\n", dev->name);
		break;

	case NETDEV_UNREGISTER:
		fps_free_net_dev_fps_stats(dev);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block fps_netdev_notifier = {
	.notifier_call= fps_ifdev_event,
	.priority = INT_MIN, /* must be the last notifier: lowest priority. */
};

/* Return true if the interface stores statistics in the pcpu_sw_netstats
 * structure.
 * Logical interfaces maintain per cpu tx_bytes, tx_packets, rx_bytes and
 * rx_packets. 'dev->tstats' or internal structure (eg. bridge) is used to store
 * those statistics instead of 'dev->stats'.
 */
static bool use_pcpu_sw_netstats(struct net_device *dev)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
	if (dev->type == ARPHRD_TUNNEL ||
	    dev->type == ARPHRD_SIT ||
	    dev->type == ARPHRD_TUNNEL6)
		return true;
#endif

	if (dev->rtnl_link_ops == NULL)
		return false;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	if (!strcmp(dev->rtnl_link_ops->kind, "bridge"))
		return true;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
	if (!strcmp(dev->rtnl_link_ops->kind, "sit") ||
	    !strcmp(dev->rtnl_link_ops->kind, "ipip") ||
	    !strcmp(dev->rtnl_link_ops->kind, "ip6tnl") ||
	    !strcmp(dev->rtnl_link_ops->kind, "gre") ||
	    !strcmp(dev->rtnl_link_ops->kind, "ip6gre") ||
	    !strcmp(dev->rtnl_link_ops->kind, "gretap") ||
	    !strcmp(dev->rtnl_link_ops->kind, "ip6gretap") ||
	    !strcmp(dev->rtnl_link_ops->kind, "vti") ||
	    !strcmp(dev->rtnl_link_ops->kind, "vti6") ||
	    !strcmp(dev->rtnl_link_ops->kind, "vxlan"))
		return true;
#endif

#ifdef RHEL65
	if (!strcmp(dev->rtnl_link_ops->kind, "vxlan"))
		return true;
#endif

	return false;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
struct gen_percpu_stats64 {
	u64                     rx_packets;
	u64                     rx_bytes;
	u64                     tx_packets;
	u64                     tx_bytes;
	struct u64_stats_sync   syncp;
};

struct gen_percpu_stats {
	unsigned long   rx_packets;
	unsigned long   rx_bytes;
	unsigned long   tx_packets;
	unsigned long   tx_bytes;
};
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
#include <linux/if_tunnel.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
struct pcpu_tstats {
	u64     rx_packets;
	u64     rx_bytes;
	u64     tx_packets;
	u64     tx_bytes;
	struct u64_stats_sync   syncp;
};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
struct pcpu_tstats {
	unsigned long   rx_packets;
	unsigned long   rx_bytes;
	unsigned long   tx_packets;
	unsigned long   tx_bytes;
};
#endif
#endif /* < 3.14 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
struct vxlan_dev {
	struct hlist_node hlist;
	struct net_device *dev;
	struct gen_percpu_stats64 __percpu *stats;
};
#endif
#ifdef RHEL65
struct vxlan_stats {
	u64                     rx_packets;
	u64                     rx_bytes;
	u64                     tx_packets;
	u64                     tx_bytes;
	struct u64_stats_sync   syncp;
};

struct vxlan_dev {
	struct hlist_node hlist;	/* vni hash table */
	struct list_head  next;		/* vxlan's per namespace list */
	struct vxlan_sock *vn_sock;	/* listening socket */
	struct net_device *dev;
	struct vxlan_stats __percpu *stats;
};
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
struct net_bridge
{
	spinlock_t			lock;
	struct list_head		port_list;
	struct net_device		*dev;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	struct pcpu_sw_netstats __percpu *stats;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
	struct gen_percpu_stats64 __percpu *stats;
#else
	struct gen_percpu_stats __percpu *stats;
#endif
};
#endif

static void fps_update_pcpu_sw_netstats(struct net_device *dev,
					struct net_device_stats *fp_nds,
					struct net_device_stats *prev_stats)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	struct pcpu_sw_netstats *tstats;

	if (!strcmp(dev->rtnl_link_ops->kind, "bridge")) {
		struct net_bridge *br = netdev_priv(dev);

		tstats = this_cpu_ptr(br->stats);
	} else
		tstats = this_cpu_ptr(dev->tstats);

	u64_stats_update_begin(&tstats->syncp);
	FPS_UPDATE_FPS_PCPU_SW_NETSTATS(tstats, fp_nds, prev_stats);
	u64_stats_update_end(&tstats->syncp);

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	struct gen_percpu_stats64 *tstats64 = NULL;
	struct gen_percpu_stats *tstats = NULL;

	if (dev->rtnl_link_ops &&
	    !strcmp(dev->rtnl_link_ops->kind, "bridge")) {
		struct net_bridge *br = netdev_priv(dev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
		tstats64 = this_cpu_ptr(br->stats);
#else
		tstats = this_cpu_ptr(br->stats);
#endif
	} else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	if (!strcmp(dev->rtnl_link_ops->kind, "vxlan")) {
		struct vxlan_dev *vxlan = netdev_priv(dev);

		tstats64 = this_cpu_ptr(vxlan->stats);
	} else
#endif
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
		tstats64 = (struct gen_percpu_stats64 *)this_cpu_ptr(dev->tstats);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
		if (dev->type == ARPHRD_TUNNEL6)
			tstats = (struct gen_percpu_stats *)this_cpu_ptr(dev->tstats);
		else
			tstats64 = (struct gen_percpu_stats64 *)this_cpu_ptr(dev->tstats);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
		tstats = (struct gen_percpu_stats *)this_cpu_ptr(dev->tstats);
#endif
	}

	if (tstats64) {
		u64_stats_update_begin(&tstats64->syncp);
		FPS_UPDATE_FPS_PCPU_SW_NETSTATS(tstats64, fp_nds, prev_stats);
		u64_stats_update_end(&tstats64->syncp);
	} else
		FPS_UPDATE_FPS_PCPU_SW_NETSTATS(tstats, fp_nds, prev_stats);

#endif /* >= 2.6.35 && < 3.14 */

#ifdef RHEL65
	if (dev->rtnl_link_ops &&
	    !strcmp(dev->rtnl_link_ops->kind, "vxlan")) {
		struct vxlan_dev *vxlan = netdev_priv(dev);
		struct vxlan_stats *stats = this_cpu_ptr(vxlan->stats);

		u64_stats_update_begin(&stats->syncp);
		FPS_UPDATE_FPS_PCPU_SW_NETSTATS(stats, fp_nds, prev_stats);
		u64_stats_update_end(&stats->syncp);
	}
#endif
}

static bool is_veth(struct net_device *dev)
{
	if (dev->rtnl_link_ops &&
	    !strcmp(dev->rtnl_link_ops->kind, "veth"))
		return true;

	return false;
}

struct pcpu_vstats {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0) || \
    (defined(UBUNTU_RELEASE) && UBUNTU_KERNEL_CODE >= UBUNTU_KERNEL_VERSION(3,2,0,61,92))
	u64			packets;
	u64			bytes;
#else /* < 3.9 */
	u64			rx_packets;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
	u64			tx_packets;
#endif
	u64			rx_bytes;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
	u64			tx_packets;
#endif
	u64			tx_bytes;
	u64			rx_dropped;
#endif
	struct u64_stats_sync	syncp;
#else /* < 3.1 */
	unsigned long		rx_packets;
	unsigned long		tx_packets;
	unsigned long		rx_bytes;
	unsigned long		tx_bytes;
	unsigned long		tx_dropped;
	unsigned long		rx_dropped;
#endif
};

struct veth_priv {
	struct net_device *peer;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0) || \
    (defined(UBUNTU_RELEASE) && UBUNTU_KERNEL_CODE >= UBUNTU_KERNEL_VERSION(3,2,0,61,92))
	atomic64_t dropped;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	struct pcpu_vstats __percpu *stats;
#else
	struct pcpu_vstats *stats;
#endif
	/* snip */
};

static void fps_update_veth_netstats(struct net_device *dev,
				     struct net_device_stats *fp_nds,
				     struct net_device_stats *prev_stats)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct pcpu_vstats *vstats;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0) || \
    (defined(UBUNTU_RELEASE) && UBUNTU_KERNEL_CODE >= UBUNTU_KERNEL_VERSION(3,2,0,61,92))
	vstats = this_cpu_ptr(dev->vstats);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	vstats = this_cpu_ptr(priv->stats);
#else /* < 2.6.34 */
	vstats = per_cpu_ptr(priv->stats, get_cpu());
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
	u64_stats_update_begin(&vstats->syncp);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0) || \
    (defined(UBUNTU_RELEASE) && UBUNTU_KERNEL_CODE >= UBUNTU_KERNEL_VERSION(3,2,0,61,92))
	vstats->packets += fp_nds->tx_packets - prev_stats->tx_packets;
	vstats->bytes += fp_nds->tx_bytes - prev_stats->tx_bytes;
	atomic64_add(fp_nds->tx_dropped - prev_stats->tx_dropped,
		     &priv->dropped);
	if (!strncmp(dev->name, "xvrf", 4)) {
		/* peer interfaces of xvrf are not synchronized in fast path,
		 * thus we need to update here peer's statistics so that
		 * the veth driver will report the right rx stats for this
		 * xvrf interface.
		 */
		struct net_device *peer = rtnl_dereference(priv->peer);
		struct pcpu_vstats *peer_vstats = this_cpu_ptr(peer->vstats);

		u64_stats_update_begin(&peer_vstats->syncp);
		peer_vstats->packets += fp_nds->rx_packets -
					prev_stats->rx_packets;
		peer_vstats->bytes += fp_nds->rx_bytes - prev_stats->rx_bytes;
		u64_stats_update_end(&peer_vstats->syncp);
	}
#else /* < 3.9 */
	STRUCT_FIELD_ADD_DELTA(vstats, fp_nds, prev_stats, rx_packets);
	STRUCT_FIELD_ADD_DELTA(vstats, fp_nds, prev_stats, rx_bytes);
	STRUCT_FIELD_ADD_DELTA(vstats, fp_nds, prev_stats, tx_packets);
	STRUCT_FIELD_ADD_DELTA(vstats, fp_nds, prev_stats, tx_bytes);
	STRUCT_FIELD_ADD_DELTA(vstats, fp_nds, prev_stats, rx_dropped);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
	STRUCT_FIELD_ADD_DELTA(vstats, fp_nds, prev_stats, tx_dropped);
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
	u64_stats_update_end(&vstats->syncp);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
static bool is_macvlan(struct net_device *dev)
{
	if (dev->rtnl_link_ops &&
	    !strcmp(dev->rtnl_link_ops->kind, "macvlan"))
		return true;

	return false;
}

#include <linux/if_macvlan.h>
static void fps_update_macvlan_netstats(struct net_device *dev,
					struct net_device_stats *fp_nds,
					struct net_device_stats *prev_stats)
{
	struct macvlan_dev *priv = netdev_priv(dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	struct vlan_pcpu_stats *stats = this_cpu_ptr(priv->pcpu_stats);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
	struct macvlan_pcpu_stats *stats = this_cpu_ptr(priv->pcpu_stats);
#else
	struct macvlan_rx_stats *stats = this_cpu_ptr(priv->rx_stats);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
	u64_stats_update_begin(&stats->syncp);
#endif

	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, rx_packets);
	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, rx_bytes);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, tx_packets);
	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, tx_bytes);
	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, tx_dropped);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
	stats->rx_multicast += fp_nds->multicast - prev_stats->multicast;
#else
	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, multicast);
#endif
	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, rx_errors);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
	u64_stats_update_end(&stats->syncp);
#endif
}
#endif /* >= 2.6.34 */

#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33) || defined(RHEL65)
static bool is_vlan(struct net_device *dev)
{
	if (dev->rtnl_link_ops &&
	    !strcmp(dev->rtnl_link_ops->kind, "vlan"))
		return true;

	return false;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0) || defined(RHEL66)
#include <linux/if_vlan.h>
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
struct vlan_pcpu_stats {
	u64			rx_packets;
	u64			rx_bytes;
	u64			rx_multicast;
	u64			tx_packets;
	u64			tx_bytes;
	struct u64_stats_sync	syncp;
	u32			rx_errors;
	u32			tx_dropped;
};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
struct vlan_rx_stats {
	u64			rx_packets;
	u64			rx_bytes;
	u64			rx_multicast;
	struct u64_stats_sync	syncp;
	unsigned long		rx_errors;
};
#else
struct vlan_rx_stats {
	unsigned long rx_packets;
	unsigned long rx_bytes;
	unsigned long multicast;
	unsigned long rx_errors;
};
#endif

struct vlan_dev_priv {
	unsigned int				nr_ingress_mappings;
	u32					ingress_priority_map[8];
	unsigned int				nr_egress_mappings;
	struct vlan_priority_tci_mapping	*egress_priority_map[16];

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	__be16					vlan_proto;
#endif
	u16					vlan_id;
	u16					flags;

	struct net_device			*real_dev;
	unsigned char				real_dev_addr[ETH_ALEN];

	struct proc_dir_entry			*dent;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
	struct vlan_pcpu_stats __percpu		*vlan_pcpu_stats;
#else
	unsigned long				cnt_inc_headroom_on_tx;
	unsigned long				cnt_encap_on_xmit;
	struct vlan_rx_stats __percpu		*vlan_rx_stats;
#endif
	/* snip */
};
#endif /* >= 3.13 || RHEL66 */

static void fps_update_vlan_netstats(struct net_device *dev,
				     struct net_device_stats *fp_nds,
				     struct net_device_stats *prev_stats)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
	struct vlan_dev_priv *priv = vlan_dev_priv(dev);
	struct vlan_pcpu_stats *stats = this_cpu_ptr(priv->vlan_pcpu_stats);
#elif defined(RHEL66)
	struct vlan_dev_info *priv = vlan_dev_info(dev);
	struct vlan_pcpu_stats *stats = this_cpu_ptr(priv->vlan_pcpu_stats);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
	struct vlan_dev_priv *priv = netdev_priv(dev);
	struct vlan_pcpu_stats *stats = this_cpu_ptr(priv->vlan_pcpu_stats);
#else
	struct vlan_dev_priv *priv = netdev_priv(dev);
	struct netdev_queue *txq;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	struct vlan_rx_stats *stats = this_cpu_ptr(priv->vlan_rx_stats);
#else
	struct vlan_rx_stats *stats = per_cpu_ptr(priv->vlan_rx_stats,
						  get_cpu());
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) || defined(RHEL66)
	u64_stats_update_begin(&stats->syncp);
#endif

	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, rx_packets);
	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, rx_bytes);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38) || defined(RHEL66)
	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, tx_packets);
	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, tx_bytes);
	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, tx_dropped);
#else
	if (dev->num_tx_queues > 0) {
		/* The queue 0 is arbitrarily chosen to add FP stats. */
		txq = netdev_get_tx_queue(dev, 0);
		STRUCT_FIELD_ADD_DELTA(txq, fp_nds, prev_stats, tx_packets);
		STRUCT_FIELD_ADD_DELTA(txq, fp_nds, prev_stats, tx_bytes);
		STRUCT_FIELD_ADD_DELTA(txq, fp_nds, prev_stats, tx_dropped);
	}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) || defined(RHEL66)
	stats->rx_multicast += fp_nds->multicast - prev_stats->multicast;
#else
	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, multicast);
#endif
	STRUCT_FIELD_ADD_DELTA(stats, fp_nds, prev_stats, rx_errors);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) || defined(RHEL66)
	u64_stats_update_end(&stats->syncp);
#endif
}
#endif /* >= 2.6.33 || RHEL65 */
#endif /* CONFIG_VLAN_8021Q */

static int fps_update_ifdev_stats(unsigned int ifuid, unsigned int blade_id,
			struct net_device_stats *fp_nds)
{
	struct net_device *dev = NULL;
	struct net_device_stats *prev_stats;
	struct fps_net_dev_stats *fps_stats;

	dev = dev_get_by_ifuid(ifuid);
	if (unlikely(!dev)) {
		printk(KERN_DEBUG "FPS: failed to find net device (ifuid=0x%x)\n",
				ntohl(ifuid));
		return -1;
	}

	/* Use alive netdev */
	if (dev->reg_state != NETREG_REGISTERED ||
			dev->__fps_dev_stats == NULL) {
		dev_put(dev);
		return -1;
	}

	fps_stats = dev->__fps_dev_stats;
	prev_stats = &fps_stats->stats[blade_id - 1];

	if (use_pcpu_sw_netstats(dev))
		fps_update_pcpu_sw_netstats(dev, fp_nds, prev_stats);
	else if (is_veth(dev))
		fps_update_veth_netstats(dev, fp_nds, prev_stats);
#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33) || defined(RHEL65)
	else if (is_vlan(dev))
		fps_update_vlan_netstats(dev, fp_nds, prev_stats);
#endif
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	else if (is_macvlan(dev))
		fps_update_macvlan_netstats(dev, fp_nds, prev_stats);
#endif

	FPS_UPDATE_FPS_STATS(&dev->stats, fp_nds, prev_stats);
	memcpy(prev_stats, fp_nds, sizeof(*prev_stats));

	dev_put(dev);

	return 0;
}

/*
 * Store Network Interfaces statistics received in a FPTUN RFPS UPDATE message
 * sent by the remote "blade_id".
 */
static void rfps_if_msg_handler(rfps_if_stats_t *rifs, uint16_t nb_stats,
				uint8_t  blade_id)
{
	uint16_t i;
	struct net_device_stats tmp;
	struct net_device_stats *fp_nds = &tmp;

	if (max_blade_id == 0)
		return; /* No statistics processing */

	if (blade_id == 0 || blade_id > max_blade_id) {
		printk(KERN_ERR "FPS: received blade-id %u out of range [1..%u]\n",
			    blade_id, max_blade_id);
		return;
	}

	for (i = 0; i < nb_stats; i++, rifs++) {
		memset(fp_nds, 0, sizeof(*fp_nds));

#if defined __BIG_ENDIAN
		if (big_endian_blades_map[blade_id]) {
			/* no conversion - peer & local CPUs are Big Endian */
			COPY_FP_IF_STATS_TO_NET_DEV_STATS(rifs, fp_nds);
		} else {
			/* converts peer Little Endian to local Big Endian */
			COPY_LE_FP_IF_STATS_TO_NET_DEV_STATS(rifs, fp_nds);
		}
#elif defined __LITTLE_ENDIAN
		if (big_endian_blades_map[blade_id]) {
			/* converts peer Big Endian to local Little Endian */
			COPY_BE_FP_IF_STATS_TO_NET_DEV_STATS(rifs, fp_nds);
		} else {
			/* no conversion - peer & this CPUs are Little Endian */
			COPY_FP_IF_STATS_TO_NET_DEV_STATS(rifs, fp_nds);
		}
#else
#error "UNKNOWN ENDIANESS NOT SUPPORTED"
#endif
		fps_update_ifdev_stats(rifs->ifs_ifuid, blade_id, fp_nds);
	}
}

/*
 * Receipt entry point of FPTUN RFPS UPDATE messages sent by the Fast Path
 * of remote blades.
 * This handler is invoked by the input handler of the "fptun.c" module.
 */
typedef void (*rfps_msg_hdlr_t)(void     *rfps_stats_desc,
				uint16_t nb_stats,
				uint8_t  blade_id);
typedef struct {
	rfps_msg_hdlr_t msg_hdlr;
	unsigned int    msg_stats_desc_size;
} rfps_msg_hook_t;

static rfps_msg_hook_t rfps_msg_hook_map[] = {
	[RFPS_IP_STATS] = { /* RFPS IPv4 and IPv6 statistics */
		.msg_hdlr            = (rfps_msg_hdlr_t) rfps_ip_msg_handler,
		.msg_stats_desc_size = sizeof(rfps_ip_stats_t),
	},
	[RFPS_IF_STATS] = { /* RFPS Network Interface statistics */
		.msg_hdlr            = (rfps_msg_hdlr_t) rfps_if_msg_handler,
		.msg_stats_desc_size = sizeof(rfps_if_stats_t),
	},
#ifdef CONFIG_MCORE_IPSEC
	[RFPS_SA_STATS] = { /* RFPS IPsec SA statistics */
		.msg_hdlr            = (rfps_msg_hdlr_t) rfps_ipsec_sa_msg_handler,
		.msg_stats_desc_size = sizeof(rfps_sa_stats_t),
	},
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
	[RFPS_SA6_STATS] = { /* RFPS IPv6 IPsec SA statistics */
		.msg_hdlr            = (rfps_msg_hdlr_t) rfps_ipsec_sa_msg_handler,
		.msg_stats_desc_size = sizeof(rfps_sa_stats_t),
	},
#endif
};

static void rfps_fptun_msg_handler(struct sk_buff *skb)
{
	rfps_v0_hdr_t   *rfps_hdr;
	rfps_msg_hook_t *rfps_hk;
	uint8_t         vbof_statsid;
	uint8_t         stats_id;
	uint8_t         blade_id;
	uint16_t        nb_stats;

	if (!pskb_may_pull(skb, sizeof(rfps_v0_hdr_t))) {
		FPS_TRACE("Unable to pull rfps_hdr_t header");
		return;
	}
	rfps_hdr = (rfps_v0_hdr_t *)skb_network_header(skb);
	vbof_statsid = rfps_hdr->vbof_statid;

	FPS_TRACE("V=%d %s statid=0x%x blade_id=%d nb_stats=%d",
		  RFPS_HDR_PROTO_VERSION(vbof_statsid),
		  (RFPS_V0_HDR_BYTE_ORDER(vbof_statsid) == RFPS_BIG_ENDIAN) ?
		  "BE" : "LE",
		  RFPS_V0_HDR_STATS_ID(vbof_statsid),
		  rfps_hdr->src_bladeid,
		  ntohs(rfps_hdr->nb_stats));

	/* Check protocol version */
	if (RFPS_HDR_PROTO_VERSION(vbof_statsid) != RFPS_INITIAL_VERSION) {
		FPS_TRACE("RFPS Protocol Version 0x%x not supported",
			  RFPS_HDR_PROTO_VERSION(vbof_statsid));
		return;
	}
	/* Retrieve sender blade identifier */
	blade_id = rfps_hdr->src_bladeid;
	if (blade_id > RFPS_BLADEID_MAX) {
		FPS_TRACE("Invalid src blade id=%d", blade_id);
		return;
	}
	/* Retrieve RFPS statistics identifier */
	stats_id = RFPS_V0_HDR_STATS_ID(vbof_statsid);
	if (stats_id >= ARRAY_SIZE(rfps_msg_hook_map)) {
		if (stats_id > RFPS_V0_STATS_ID_MAX) {
			FPS_TRACE("Invalid Stats Id=%d", stats_id);
		} else {
			FPS_TRACE("RFPS Stats Id=%d not supported", stats_id);
		}
		return;
	}

	/* Retrieve sender byte order */
	big_endian_blades_map[blade_id] = RFPS_V0_HDR_BYTE_ORDER(vbof_statsid);

	/* Retrieve number of statistics - Always transmitted in BIG ENDIAN */
	nb_stats = ntohs(rfps_hdr->nb_stats);

	/*
	 * Check that skbuff contains all stats data sent in the message
	 * before invoking the relevant RFPS hook handler.
	 */
	rfps_hk = &rfps_msg_hook_map[stats_id];
	if (!pskb_may_pull(skb, sizeof(rfps_v0_hdr_t) + rfps_hk->msg_stats_desc_size * nb_stats)) {

		FPS_TRACE("pksb_may_pull(%d entries of size %d) failed",
			  nb_stats, rfps_hk->msg_stats_desc_size);
		return;
	}
	rfps_hdr = (rfps_v0_hdr_t *)skb_network_header(skb);
	(*rfps_hk->msg_hdlr)((void *)(rfps_hdr + 1), nb_stats, blade_id);
}

typedef void (*fptun_rfps_msg_handler_t)(struct sk_buff *);
extern fptun_rfps_msg_handler_t fptun_rfps_msg_hdlr_p;

int __init dist_cp_role_init(void)
{
	/*
	 * Initialise receipt side of FPTUN RFPS UPDATE messages for
	 * IPv4 and IPv6 statistics.
	 */
	rfps_node_init(&rfps_ipv4_node, 0);
#ifdef CONFIG_MCORE_IPV6
	rfps_node_init(&rfps_ipv6_node, 0);
#endif
	if (max_blade_id > RFPS_BLADEID_MAX) {
		printk(KERN_ERR "FPS: Invalid max_blade_id paramater (max = %u)\n",
				RFPS_BLADEID_MAX);
		return -EINVAL;
	}
	if (max_blade_id > 0) {
		int ret = register_netdevice_notifier(&fps_netdev_notifier);
		if (ret)
			return ret;
	}
	/*
         * Finally, attach FPTUN handler to receive FPTUN_RFPS_UPDATE messages
	 * sent by the Fast Path of peer blades.
	 */
	FPS_TRACE("Attach fptun_rfps_msg_handler");
	fptun_rfps_msg_hdlr_p = rfps_fptun_msg_handler;

	return 0;
}

void __exit dist_cp_role_exit(void)
{
	if (max_blade_id > 0)
		unregister_netdevice_notifier(&fps_netdev_notifier);

	/* Free all dynamically allocated memory (stats entries and nodes) */
	rfps_node_stats_entries_delete(&rfps_ipv4_node);
#ifdef CONFIG_MCORE_IPV6
	rfps_node_stats_entries_delete(&rfps_ipv6_node);
#endif
}

module_init(dist_cp_role_init);
module_exit(dist_cp_role_exit);

MODULE_DESCRIPTION("FPS");
MODULE_LICENSE("GPL");
