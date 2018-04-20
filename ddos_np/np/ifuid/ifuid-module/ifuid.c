/*
 * Copyright (C) 2013 6WIND, All rights reserved.
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
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>

#if defined(USE_VRF_NETNS)
/* Generic VRF implementation with netns for Linux 3.x */
#include <vrf.h>
#endif

#include "ifuid.h"

struct iface_uid {
	struct hlist_node   d_next;
	struct hlist_node   u_next;

	uint32_t            ifuid;
	struct net_device  *dev;
};

#define IF_HASH_ORDER   10
#define IF_HASH_MAX    (1<<IF_HASH_ORDER)
#define IF_HASH_MASK   (IF_HASH_MAX-1)
struct hlist_head iface_dev_head[IF_HASH_MAX];
struct hlist_head iface_uid_head[IF_HASH_MAX];

static DEFINE_RWLOCK(iface_uid_lock);

/*
 * Link, unlink: needs iface_uid_lock taken
 * Each structure is reachable via H tables with
 * 2 different search keys:
 *   - by ifuid
 *   - by net_device
 */
static inline int do_u_hash (uint32_t ifuid)
{
	return ifuid & IF_HASH_MASK;
}

static inline int do_d_hash (struct net_device *dev)
{
	uint64_t idev  = (uint64_t)(uintptr_t)dev;
	return jhash_2words (idev & 0xffffffff, idev>>32, 0) & IF_HASH_MASK;
}

static void  __iface_link (struct iface_uid *ifp)
{
	int u_hash = do_u_hash(ifp->ifuid);
	int d_hash = do_d_hash(ifp->dev);

	hlist_add_head(&ifp->u_next, &iface_uid_head[u_hash]);
	hlist_add_head(&ifp->d_next, &iface_dev_head[d_hash]);
}

static void __iface_unlink (struct iface_uid *ifp)
{
	hlist_del(&ifp->u_next);
	hlist_del(&ifp->d_next);
}

/*
 * iface lookup, needs iface_uid_lock taken
 * two search keys:
 *   - by ifuid
 *   - by net_device
 */
static struct iface_uid *__iface_lookup_by_dev (struct net_device *dev)
{
	struct iface_uid *ifp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *hn;
#endif
	int d_hash = do_d_hash(dev);

	hlist_for_each_entry(ifp,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
			     hn,
#endif
			     &iface_dev_head[d_hash], d_next) {
		if (ifp->dev != dev)
			continue;
		return ifp;
	}

	return NULL;
}

static struct iface_uid *__iface_lookup_by_uid (uint32_t ifuid)
{
	struct iface_uid *ifp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *hn;
#endif
	int u_hash = do_u_hash(ifuid);

	hlist_for_each_entry(ifp,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
			     hn,
#endif
			     &iface_uid_head[u_hash], u_next) {
		if (ifp->ifuid != ifuid)
			continue;
		return ifp;
	}

	return NULL;
}

/*
 * Feed the internal table.
 * The _change function is for iface renaming.
 */
static int iface_add (struct net_device *dev, uint32_t ifuid)
{
	struct iface_uid *ifp;
	int err = 0;

	write_lock_bh(&iface_uid_lock);
	/* netdevice is already held by caller */

	ifp = __iface_lookup_by_dev(dev);
	if (ifp == NULL) {
		ifp = (struct iface_uid *)kmalloc(sizeof(struct iface_uid), GFP_ATOMIC);
		if (ifp == NULL) {
			err = -ENOMEM;
			goto exit;
		}
	} else {
		if (ifp->ifuid == ifuid) {
			err = -EEXIST;
			goto exit;
		}
		/* interface changed vrf */
		__iface_unlink (ifp);
		dev_put(ifp->dev);
	}

	ifp->dev = dev;
	dev_hold(dev);
	ifp->ifuid = ifuid;

	__iface_link (ifp);

exit:
	write_unlock_bh(&iface_uid_lock);

	return err;
}

static int iface_change (struct net_device *dev, uint32_t ifuid)
{
	struct iface_uid *ifp;

	write_lock_bh(&iface_uid_lock);
	ifp = __iface_lookup_by_dev(dev);
	if (ifp == NULL) {
		write_unlock_bh(&iface_uid_lock);
		return -ENOENT;
	}

	__iface_unlink (ifp);
	ifp->ifuid = ifuid;
	__iface_link (ifp);

	write_unlock_bh(&iface_uid_lock);

	return 0;
}

static int iface_del (struct net_device *dev)
{
	struct iface_uid *ifp;

	write_lock_bh(&iface_uid_lock);
	ifp = __iface_lookup_by_dev(dev);
	if (ifp == NULL) {
		write_unlock_bh(&iface_uid_lock);
		return -ENOENT;
	}

	__iface_unlink (ifp);
	write_unlock_bh(&iface_uid_lock);

	dev_put (dev);
	kfree (ifp);
	return 0;
}

static int ifuid_dev_event(struct notifier_block *this, unsigned long event,
                           void *ptr)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
	struct net_device *dev = ptr;
#else
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
#endif
	uint32_t ifuid;
	uint32_t vrfid;


	switch (event) {
	case NETDEV_REGISTER:
	case NETDEV_CHANGENAME:
#ifdef CONFIG_NET_VRF
		vrfid = dev_vrfid(dev);
#elif defined(USE_VRF_NETNS)
		vrfid = vrf_lookup_by_net(dev_net(dev));
		if (vrfid == VRF_VRFID_UNSPEC) {
			/* If vrfid is not configured, then we can skip this event. A
			 * new call will be done via the vrf notifier chain.
			 */
			return 0;
		}
#else
		/* No VRF, no NETNS */
		vrfid = 0;
#endif
		ifuid = ifname2ifuid(dev->name, vrfid);
		if (event == NETDEV_REGISTER)
			iface_add(dev, ifuid);
		else
			iface_change(dev, ifuid);
		break;
	case NETDEV_UNREGISTER:
		iface_del(dev);
		break;
	}

	return 0;
}

static struct notifier_block ifuid_netdev_notifier = {
	.notifier_call = ifuid_dev_event,
};

#ifdef USE_VRF_NETNS
static int ifuid_vrf_event(struct notifier_block *this, unsigned long event,
			   void *data)
{
	struct net *net = data;
	struct net_device *dev;
	uint32_t vrfid;

	if (event != VRF_NOTIF_NEW)
		return 0;

	vrfid = vrf_lookup_by_net(net);
	if (vrfid == VRF_VRFID_UNSPEC) {
		pr_err("%s: event new but vrfid unspec\n", __func__);
		return -EINVAL;
	}

	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
		uint32_t ifuid = ifname2ifuid(dev->name, vrfid);

		iface_add(dev, ifuid);
	}
	rcu_read_unlock();
	return 0;
}

static struct notifier_block ifuid_vrf_notifier = {
	.notifier_call = ifuid_vrf_event,
};
#endif /* USE_VRF_NETNS */

#ifdef CONFIG_SYSCTL
/*
 * sysctl section
 */
static struct ctl_table_header *ifuid_sysctl_header;
static char ifuid_sysctl_list_buf[128];

/*
 * Handler when /proc/sys/ifuid/list is read
 * Returns 0 on success, else returns a negative value
 */
static int ifuid_sysctl_list (struct ctl_table *ctl, int write,
			      void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int err;
	int total, nb_buckets, max;
	int hash, hash_line;
	struct iface_uid *ifp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *hn;
#endif
	int len;

	strcpy((char*)ctl->data, "");

	read_lock_bh(&iface_uid_lock);

	if (write) {
		printk(KERN_INFO "Table dump per net_device\n");
		printk(KERN_INFO "=========================\n");
	}
	total = 0;
	nb_buckets = 0;
	max = 0;
	for (hash = 0; hash < IF_HASH_MAX; hash++) {
		if (hlist_empty(&iface_dev_head[hash]))
			continue;
		nb_buckets++;
		hash_line = 0;

		hlist_for_each_entry(ifp,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
				     hn,
#endif
				     &iface_dev_head[hash], d_next) {
			if (write) {
				printk(KERN_INFO "iface %s --> %08x\n",
					ifp->dev->name, ifp->ifuid);
			}
			hash_line++;
			total++;
		}
		if (hash_line > max)
			max = hash_line;
	}

	len = snprintf((char *)ctl->data, ctl->maxlen,
	         "iface: %d entries across %d buckets. Max bucket is %d\n",
	         total, nb_buckets, max);

	if (write) {
		printk(KERN_INFO "Table dump per ifuid\n");
		printk(KERN_INFO "====================\n");
	}
	total = 0;
	nb_buckets = 0;
	max = 0;
	for (hash=0; hash<IF_HASH_MAX; hash++) {
		if (hlist_empty(&iface_uid_head[hash]))
			continue;
		nb_buckets++;
		hash_line = 0;

		hlist_for_each_entry(ifp,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
				     hn,
#endif
				     &iface_uid_head[hash], u_next) {
			if (write) {
				printk(KERN_INFO "iface %s --> %08x\n",
					ifp->dev->name, ifp->ifuid);
			}
			hash_line++;
			total++;
		}
		if (hash_line > max)
			max = hash_line;
	}

	snprintf((char *)ctl->data + len, ctl->maxlen - len,
	         "ifuid: %d entries across %d buckets. Max bucket is %d\n",
	         total, nb_buckets, max);

	read_unlock_bh(&iface_uid_lock);

	if ((err = proc_dostring(ctl, write, buffer, lenp, ppos)) < 0)
		return err;

	return err;
}

/*
 * Contents of /proc/sys/ifuid directory
 */
static struct ctl_table ifuid_sysctl_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "list",
		.data           =       &ifuid_sysctl_list_buf,
		.maxlen         =       sizeof(ifuid_sysctl_list_buf),
		.mode           =       0644,
		.proc_handler   =       &ifuid_sysctl_list,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       0,      /* sentinel */
#endif
		.procname       =       NULL,
	}
};

/*
 * Define /proc/sys/ifuid directory
 */
static struct ctl_table ifuid_sysctl_root_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "ifuid",
		.mode           =       0555,
		.child          =       ifuid_sysctl_table,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       0,      /* sentinel */
#endif
		.procname       =       NULL,
	}
};
#endif

static int __init ifuid_init(void)
{
	int i;

        /* ifuid lists lock */
        rwlock_init(&iface_uid_lock);

	/* H table heads */
	for (i=0; i<IF_HASH_MAX; i++) {
		INIT_HLIST_HEAD(&iface_dev_head[i]);
		INIT_HLIST_HEAD(&iface_uid_head[i]);
	}

#ifdef CONFIG_SYSCTL
	/* register sysfs */
	ifuid_sysctl_header = register_sysctl_table(ifuid_sysctl_root_table);
	if (ifuid_sysctl_header == NULL) {
		printk("%s: init failed\n", __func__);
		return -ENOMEM;
	}
#endif

	/* Netdevice/vrf events. As it trigers callback for all exisiting
	 * netdevices/vrf, it MUST be the last init operations.
	 */
	register_netdevice_notifier(&ifuid_netdev_notifier);
#ifdef USE_VRF_NETNS
	vrf_register_notifier(&ifuid_vrf_notifier);
#endif

	printk("%s: init completed\n", __func__);

	return 0;
}

static void __exit ifuid_exit(void)
{
	int hash;
	struct iface_uid *ifp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *hn;
#endif
	struct hlist_node *hn2;

	printk("%s: exit\n", __func__);

#ifdef USE_VRF_NETNS
	vrf_unregister_notifier(&ifuid_vrf_notifier);
#endif
	unregister_netdevice_notifier(&ifuid_netdev_notifier);
#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(ifuid_sysctl_header);
#endif

	write_lock_bh(&iface_uid_lock);
	for (hash=0; hash<IF_HASH_MAX; hash++) {
		if (hlist_empty(&iface_dev_head[hash]))
			continue;
		hlist_for_each_entry_safe(ifp,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
					  hn,
#endif
					  hn2, &iface_dev_head[hash], d_next) {
			dev_put (ifp->dev);
			kfree (ifp);
		}
	}
	write_unlock_bh(&iface_uid_lock);
}

/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define GOLDEN_RATIO_PRIME_32 0x9e370001UL
uint32_t ifname2ifuid (const char *ifname, uint32_t vrfid)
{
	unsigned long hash = 0;
	int len = strnlen(ifname, IFNAMSIZ);
	unsigned char c;
	char *vrf = (char *)&vrfid;
	vrfid = htonl(vrfid);

	while (len--) {
		c = *ifname++;
		hash = (hash + (c << 4) + (c >> 4)) * 11;
	}

	len = sizeof(uint32_t);
	while (len--) {
		c = *vrf++;
		hash = (hash + (c << 4) + (c >> 4)) * 11;
	}

        return (htonl(hash * GOLDEN_RATIO_PRIME_32));
}
EXPORT_SYMBOL(ifname2ifuid);

struct net_device *dev_get_by_ifuid (uint32_t ifuid)
{
	struct iface_uid *conv;
	struct net_device *ifp = NULL;

	read_lock_bh(&iface_uid_lock);
	conv = __iface_lookup_by_uid(ifuid);
	if (conv) {
		ifp = conv->dev;
		dev_hold(ifp);
	}
	read_unlock_bh(&iface_uid_lock);
	return ifp;
}
EXPORT_SYMBOL(dev_get_by_ifuid);

uint32_t netdev2ifuid (struct net_device *dev)
{
	struct iface_uid *conv;
	uint32_t ifuid = 0;
	uint32_t vrfid;

	read_lock_bh(&iface_uid_lock);
	conv = __iface_lookup_by_dev(dev);
	if (conv) {
		ifuid = conv->ifuid;
		read_unlock_bh(&iface_uid_lock);
		return ifuid;
	}
	read_unlock_bh(&iface_uid_lock);

#ifdef CONFIG_NET_VRF
	vrfid = dev_vrfid(dev);
#elif defined(USE_VRF_NETNS)
	vrfid = vrf_lookup_by_net(dev_net(dev));
	if (vrfid == VRF_VRFID_UNSPEC) {
		printk(KERN_ERR
		       "netdev2ifuid: unable to get VRFID of interface %s\n",
		       dev->name);
		return 0;
	}
#else
	vrfid = 0;
#endif

	ifuid = ifname2ifuid(dev->name, vrfid);
	(void)iface_add(dev, ifuid);
	return ifuid;
}
EXPORT_SYMBOL(netdev2ifuid);

module_init(ifuid_init);
module_exit(ifuid_exit);
MODULE_LICENSE("GPL");
