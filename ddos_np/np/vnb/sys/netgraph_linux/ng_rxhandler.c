/*
 * Copyright 2013 6WIND S.A.
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
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/hash.h>
#include <net/netns/generic.h>

#include <netgraph_linux/ng_rxhandler.h>
#ifdef USE_MACVLAN_HOOK
#include <linux/if_macvlan.h>
#endif

#define VNB_LINUX_HASH_BITS	8
#define VNB_LINUX_HASH_SIZE	(1 << VNB_LINUX_HASH_BITS)
struct hlist_head vnb_linux_dev_hlist[VNB_LINUX_HASH_SIZE];
rwlock_t vnb_linux_dev_lock[VNB_LINUX_HASH_SIZE];

static inline u32 vnb_linux_dev_hash(const struct net_device *dev)
{
	return hash_32((u32)(uintptr_t)dev, VNB_LINUX_HASH_BITS);
}

static struct vnb_linux_dev *
__vnb_linux_dev_find(const struct net_device *dev, u32 hash)
{
	struct vnb_linux_dev *vdev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *n;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	hlist_for_each_entry(vdev, n, &vnb_linux_dev_hlist[hash], hlist)
#else
	hlist_for_each_entry(vdev, &vnb_linux_dev_hlist[hash], hlist)
#endif
		if (vdev->dev == dev)
			return vdev;

	return NULL;
}

struct vnb_linux_dev *vnb_linux_dev_find(const struct net_device *dev)
{
	struct vnb_linux_dev *vdev;
	u32 hash = vnb_linux_dev_hash(dev);

	read_lock(&vnb_linux_dev_lock[hash]);
	vdev = __vnb_linux_dev_find(dev, hash);
	read_unlock(&vnb_linux_dev_lock[hash]);

	return vdev;
}
EXPORT_SYMBOL(vnb_linux_dev_find);

bool vnb_linux_dev_exist(const struct net_device *dev)
{
	return vnb_linux_dev_find(dev) ? true : false;
}
EXPORT_SYMBOL(vnb_linux_dev_exist);

int vnb_linux_dev_create(struct net_device *dev, node_p node)
{
	struct vnb_linux_dev *vdev;
	int hash = vnb_linux_dev_hash(dev);
	int err = 0;

	write_lock(&vnb_linux_dev_lock[hash]);
	if (__vnb_linux_dev_find(dev, hash)) {
		err = -EEXIST;
		goto end;
	}

	vdev = kmalloc(sizeof(struct vnb_linux_dev), GFP_KERNEL);
	if (vdev == NULL) {
		err = -ENOMEM;
		goto end;
	}

	vdev->dev = dev;
	vdev->node = node;
	hlist_add_head(&vdev->hlist, &vnb_linux_dev_hlist[hash]);
	atomic_set(&vdev->has_rx_handler, 0);
end:
 	write_unlock(&vnb_linux_dev_lock[hash]);
	return err;
}
EXPORT_SYMBOL(vnb_linux_dev_create);

void vnb_linux_dev_delete(struct net_device *dev)
{
	struct vnb_linux_dev *vdev;
	u32 hash = vnb_linux_dev_hash(dev);

	write_lock(&vnb_linux_dev_lock[hash]);
	vdev = __vnb_linux_dev_find(dev, hash);
	if (vdev != NULL) {
		hlist_del(&vdev->hlist);
		kfree(vdev);
	}
	write_unlock(&vnb_linux_dev_lock[hash]);
}
EXPORT_SYMBOL(vnb_linux_dev_delete);

int vnb_netdev_rx_handler_register(struct net_device *dev,
#ifndef USE_MACVLAN_HOOK
				   rx_handler_func_t *rx_handler,
#endif
				   void *rx_handler_data)
{
	int err = 0;

#ifdef USE_MACVLAN_HOOK
	if (dev->macvlan_port != NULL)
		return -EBUSY;
	rcu_assign_pointer(dev->macvlan_port, rx_handler_data);
#else
	err = netdev_rx_handler_register(dev, rx_handler, rx_handler_data);
#endif

	return err;
}
EXPORT_SYMBOL(vnb_netdev_rx_handler_register);

void vnb_netdev_rx_handler_unregister(struct net_device *dev)
{
#ifdef USE_MACVLAN_HOOK
	rcu_assign_pointer(dev->macvlan_port, NULL);
#else
	netdev_rx_handler_unregister(dev);
#endif
}
EXPORT_SYMBOL(vnb_netdev_rx_handler_unregister);

#ifdef USE_MACVLAN_HOOK
void netgraph_linux_set_macvlan_hook(struct sk_buff *(*handler)(struct sk_buff *skb))
{
	if (macvlan_handle_frame_hook == NULL)
		macvlan_handle_frame_hook = handler;
	else
		printk(KERN_ERR
		       "%s: unable to register ng_ether hook()\n",
		       __func__);
}
EXPORT_SYMBOL(netgraph_linux_set_macvlan_hook);

void netgraph_linux_unset_macvlan_hook(struct sk_buff *(*handler)(struct sk_buff *skb))
{
	if (macvlan_handle_frame_hook == handler)
		macvlan_handle_frame_hook = NULL;
}
EXPORT_SYMBOL(netgraph_linux_unset_macvlan_hook);
#endif

static int __init netgraph_linux_init_module(void)
{
	u32 hash;

	for (hash = 0; hash < VNB_LINUX_HASH_SIZE; hash++) {
		INIT_HLIST_HEAD(&vnb_linux_dev_hlist[hash]);
		rwlock_init(&vnb_linux_dev_lock[hash]);
	}

	printk(KERN_INFO "vnb-linux module initialized\n");
	return 0;
}

static void __exit netgraph_linux_exit_module(void)
{
	struct vnb_linux_dev *vdev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *n;
#endif
	u32 hash;

	for (hash = 0; hash < VNB_LINUX_HASH_SIZE; hash++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
		hlist_for_each_entry(vdev, n, &vnb_linux_dev_hlist[hash], hlist)
#else
		hlist_for_each_entry(vdev, &vnb_linux_dev_hlist[hash], hlist)
#endif
		{
			if (atomic_add_unless(&vdev->has_rx_handler, -1, 0)) {
				rtnl_lock();
				vnb_netdev_rx_handler_unregister(vdev->dev);
				rtnl_unlock();
			}
		}
	}

	printk(KERN_INFO "vnb-linux module exited\n");
}

module_init(netgraph_linux_init_module);
module_exit(netgraph_linux_exit_module);
