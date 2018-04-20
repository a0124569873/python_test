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

#ifndef _NG_NETLINK_H_
#define _NG_NETLINK_H_

#include <linux/types.h>

enum {
	IFLA_VNB_UNSPEC,
	IFLA_VNB_NODEID,
	IFLA_VNB_NODE_REG,
	__IFLA_VNB_MAX,
};
#define IFLA_VNB_MAX (__IFLA_VNB_MAX - 1)

#ifdef __KERNEL__
void vnb_af_register(void);
void vnb_af_unregister(void);
int vnb_rtnl_link_register(struct rtnl_link_ops *ops);
void vnb_rtnl_link_unregister(struct rtnl_link_ops *ops);
#endif /* __KERNEL__ */

#endif
