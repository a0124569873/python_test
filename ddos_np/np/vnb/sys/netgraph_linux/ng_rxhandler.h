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

#ifndef _NG_RXHANDLER_H_
#define _NG_RXHANDLER_H_

#ifdef __KERNEL__

#include <netgraph/netgraph.h>

#ifdef RHEL_RELEASE_CODE
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,5) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0)
#define USE_MACVLAN_HOOK 1
void netgraph_linux_set_macvlan_hook(struct sk_buff *(*handler)(struct sk_buff *skb));
void netgraph_linux_unset_macvlan_hook(struct sk_buff *(*handler)(struct sk_buff *skb));
#endif
#endif

int vnb_netdev_rx_handler_register(struct net_device *dev,
#ifndef USE_MACVLAN_HOOK
				   rx_handler_func_t *rx_handler,
#endif
				   void *rx_handler_data);
void vnb_netdev_rx_handler_unregister(struct net_device *dev);
bool vnb_linux_dev_exist(const struct net_device *dev);
int vnb_linux_dev_create(struct net_device *dev, node_p node);
void vnb_linux_dev_delete(struct net_device *dev);

struct vnb_linux_dev {
	struct net_device *dev;
	node_p node;
	atomic_t has_rx_handler;	/* whether rx_handler is set or not */
	struct hlist_node hlist;
};

struct vnb_linux_dev *vnb_linux_dev_find(const struct net_device *dev);

#endif /* __KERNEL__ */
#endif /* _NG_RXHANDLER_H_ */
