/*
 * Copyright 2010-2013 6WIND S.A.
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

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/netlink.h>

#include <netgraph_linux/ng_rxhandler.h>
#include <netgraph/vnblinux.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>

#include <linux/netlink.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>
#include <netgraph_linux/ng_netlink.h>
#include <netgraph/ng_socket.h>

static DEFINE_MUTEX(vnb_mutex);

#ifdef CONFIG_VNB_NETLINK_NOTIFY
static size_t vnb_get_link_af_size(const struct net_device *dev)
{
	size_t size = 0;

	if (vnb_linux_dev_exist(dev)) {
		size += nla_total_size(4); /* IFLA_VNB_NODEID */

		if (dev->reg_state == NETREG_REGISTERED)
			size += nla_total_size(1); /* IFLA_VNB_NODE_REG */
	}

	return size;
}

static int vnb_fill_link_af(struct sk_buff *skb, const struct net_device *dev)
{
	int ret;
	node_p node;
	struct vnb_linux_dev *vdev = vnb_linux_dev_find(dev);

	if (vdev && (node = vdev->node)) {
		ret = nla_put_u32(skb, IFLA_VNB_NODEID, node->ID);
		if (ret)
			goto nla_put_failure;

		if (dev->reg_state == NETREG_REGISTERED) {
			ret = nla_put_u8(skb, IFLA_VNB_NODE_REG, 1);
			if (ret)
				goto nla_put_failure;
		}
	}

	return 0;

 nla_put_failure:
	return -EMSGSIZE;
}

static struct rtnl_af_ops vnb_af_ops = {
	.family		  = AF_NETGRAPH,
	.fill_link_af	  = vnb_fill_link_af,
	.get_link_af_size = vnb_get_link_af_size,
};

void vnb_af_register(void)
{
	rtnl_af_register(&vnb_af_ops);
}

void vnb_af_unregister(void)
{
	rtnl_af_unregister(&vnb_af_ops);
}
#else
void vnb_af_register(void* vnb_dump)
{
}

void vnb_af_unregister(void)
{
}
#endif

int vnb_rtnl_link_register(struct rtnl_link_ops *ops)
{
	return rtnl_link_register(ops);
}

void vnb_rtnl_link_unregister(struct rtnl_link_ops *ops)
{
	rtnl_link_unregister(ops);
}

EXPORT_SYMBOL(vnb_af_register);
EXPORT_SYMBOL(vnb_af_unregister);
EXPORT_SYMBOL(vnb_rtnl_link_register);
EXPORT_SYMBOL(vnb_rtnl_link_unregister);

MODULE_LICENSE("GPL");
