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

#ifndef CONFIG_SYSCTL
#error "this module needs CONFIG_SYSCTL"
#endif

#ifndef CONFIG_XFRM
#error "this module needs CONFIG_XFRM"
#endif

#include <linux/version.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/ctype.h>
#include <net/genetlink.h>

#include <net/xfrm.h>
#include "blade-ipsec.h"

/* GENL */
static struct genl_multicast_group blade_ipsec_mcgrp[] = {
	{	.name = BLADE_IPSEC_FAMILY_NAME,	},
};

struct genl_family blade_ipsec_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = BLADE_IPSEC_FAMILY_NAME,
	.version = 1,
	.maxattr = BLADE_IPSEC_A_MAX,
};

static const struct nla_policy blade_ipsec_genl_policy[BLADE_IPSEC_A_MAX + 1] = {
	[BLADE_IPSEC_A_TYPE] = { .len = sizeof(u8) },
	[BLADE_IPSEC_A_SA_ID] = { .len = sizeof(struct xfrm_usersa_id) },
	[BLADE_IPSEC_A_SRC_FP] = { .len = sizeof(u8) },
	[BLADE_IPSEC_A_COUNTER] = { .len = sizeof(u32) },
	[BLADE_IPSEC_A_DST_FP] = { .len = sizeof(u8) },
	[BLADE_IPSEC_A_GAP] = { .len = sizeof(u32) },
	[BLADE_IPSEC_A_VRFID] = { .len = sizeof(u32) },
};

static size_t blade_ipsec_genl_size(u8 type)
{
	size_t size = nla_total_size(sizeof(u8)) + /* BLADE_IPSEC_A_TYPE */
		nla_total_size(sizeof(u8))       + /* BLADE_IPSEC_A_DST_FP */
#ifdef CONFIG_NET_VRF
		nla_total_size(sizeof(u32))      + /* BLADE_IPSEC_A_VRFID */
#endif
		nla_total_size(sizeof(u32));       /* BLADE_IPSEC_A_GAP */

	switch (type) {
	case BLADE_IPSEC_MIG_SINGLE:
		size += nla_total_size(sizeof(struct xfrm_usersa_id)); /* BLADE_IPSEC_A_SA_ID */
		break;
	case BLADE_IPSEC_MIG_BULK_BY_FP:
		size += nla_total_size(sizeof(u8)); /* BLADE_IPSEC_A_SRC_FP */
		break;
	default:
		break;
	}

	return size;
}

static void blade_ipsec_genl_notify_migrate(struct net *net, u32 vrfid, struct xfrm_usersa_id *p,
					    u8 type, u8 src_fp, u8 dst_fp, u32 gap)
{
	size_t size = blade_ipsec_genl_size(type);
	struct sk_buff *skb;
	struct nlmsghdr *nlh;

	skb = genlmsg_new(size, GFP_ATOMIC);
	if (!skb)
		return;

	nlh = genlmsg_put(skb, 0, 0, &blade_ipsec_genl_family, 0, BLADE_IPSEC_C_MIGRATE);
	if (nlh == NULL) {
		genlmsg_cancel(skb, nlh);
		return;
	}

	nla_put_u8(skb, BLADE_IPSEC_A_TYPE, type);
	nla_put_u8(skb, BLADE_IPSEC_A_DST_FP, dst_fp);
	nla_put_u32(skb, BLADE_IPSEC_A_GAP, gap);
#ifdef CONFIG_NET_VRF
	nla_put_u32(skb, BLADE_IPSEC_A_VRFID, vrfid);
#endif

	switch (type) {
	case BLADE_IPSEC_MIG_SINGLE:
		nla_put(skb, BLADE_IPSEC_A_SA_ID, sizeof(*p), p);
		break;
	case BLADE_IPSEC_MIG_BULK_BY_FP:
		nla_put_u32(skb, BLADE_IPSEC_A_SRC_FP, src_fp);
		break;
	default:
		break;
	}
	genlmsg_end(skb, nlh);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	genlmsg_multicast_netns(net, skb, 0, blade_ipsec_mcgrp[0].id,
				GFP_KERNEL);
#else
	genlmsg_multicast_netns(&blade_ipsec_genl_family, net, skb, 0, 0,
				GFP_KERNEL);
#endif
}

static void blade_ipsec_migrate_single(struct xfrm_state *x, u8 dst_fpid)
{
	x->sel.user = dst_fpid;
}

static void blade_ipsec_migrate_bulk_by_fp(struct net *net, u32 vrfid, u8 src_fpid, u8 dst_fpid)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *entry;
#endif
	struct xfrm_state *x;
	int i;

	for (i = 0; i <= net->xfrm.state_hmask; i++)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
		hlist_for_each_entry(x, entry, net->xfrm.state_bydst+i, bydst) {
#else
		hlist_for_each_entry(x, net->xfrm.state_bydst+i, bydst) {
#endif
#ifdef CONFIG_NET_VRF
			if (xs_vrfid(x) != vrfid)
				continue;
#endif
			if (x->sel.user == src_fpid)
				x->sel.user = dst_fpid;
		}
}

static int blade_ipsec_genl_migrate(struct sk_buff *skb, struct genl_info *info)
{
	u8 mig_type;
	struct net* net = sock_net(skb->sk);
	u8 src_fp, dst_fp;
	u32 vrfid = 0;
	u32 gap;

	if (!info->attrs[BLADE_IPSEC_A_TYPE])
		return -EINVAL;

	mig_type = nla_get_u8(info->attrs[BLADE_IPSEC_A_TYPE]);

	if (!info->attrs[BLADE_IPSEC_A_DST_FP])
		return -EINVAL;

	dst_fp = nla_get_u8(info->attrs[BLADE_IPSEC_A_DST_FP]);

	if (!info->attrs[BLADE_IPSEC_A_GAP])
		gap = 0;
	else
		gap = nla_get_u32(info->attrs[BLADE_IPSEC_A_GAP]);

#ifdef CONFIG_NET_VRF
	/* VRFID is ignored for netns implementation */
	if (info->attrs[BLADE_IPSEC_A_VRFID])
		vrfid = nla_get_u32(info->attrs[BLADE_IPSEC_A_VRFID]);
#endif

	switch (mig_type) {
	case BLADE_IPSEC_MIG_SINGLE:
	{
		struct xfrm_state *x;
		struct xfrm_usersa_id *p;
		/* we don't support marked SA migration */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
		u32 mark = 0;
#endif

		if (!info->attrs[BLADE_IPSEC_A_SA_ID])
			return -EINVAL;
		p = nla_data(info->attrs[BLADE_IPSEC_A_SA_ID]);

		x = xfrm_state_lookup(net,
#ifdef CONFIG_NET_VRF
				      vrfid,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
				      mark,
#endif
				      &p->daddr, p->spi, p->proto, p->family);
		if (!x)
			return -EINVAL;

		blade_ipsec_migrate_single(x, dst_fp);
		blade_ipsec_genl_notify_migrate(net, vrfid, p, mig_type, 0, dst_fp, gap);

		/* release reference taken in xfrm_state_lookup */
		xfrm_state_put(x);

		break;
	}
	case BLADE_IPSEC_MIG_BULK_BY_FP:

		if (!info->attrs[BLADE_IPSEC_A_SRC_FP])
			return -EINVAL;

		src_fp = nla_get_u8(info->attrs[BLADE_IPSEC_A_SRC_FP]);

		blade_ipsec_migrate_bulk_by_fp(net, vrfid, src_fp, dst_fp);
		blade_ipsec_genl_notify_migrate(net, vrfid, NULL, mig_type, src_fp, dst_fp, gap);

		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static struct genl_ops blade_ipsec_genl_ops[] = {
	{
		.cmd = BLADE_IPSEC_C_MIGRATE,
		.flags = 0,
		.policy = blade_ipsec_genl_policy,
		.doit = blade_ipsec_genl_migrate,
		.dumpit = NULL,
	},
};


/* SYSCTL */
struct ctl_table_header *blade_ipsec_sysctl_header;
static unsigned int blade_ipsec_sysctl_default_fp = 0;

/* Contents of /proc/sys/blade_ipsec directory  */
struct ctl_table blade_ipsec_sysctl_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "default_fp",
		.data           =       &blade_ipsec_sysctl_default_fp,
		.maxlen         =       sizeof(unsigned int),
		.mode           =       0644,
		.proc_handler   =       &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       0,      /* sentinel */
#endif
		.procname       =       NULL,
	}
};

/* Define /proc/sys/blade_ipsec directory  */
struct ctl_table blade_ipsec_sysctl_root_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "blade-ipsec",
		.mode           =       0555,
		.child          =       blade_ipsec_sysctl_table,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       0,      /* sentinel */
#endif
		.procname       =       NULL,
	}
};

/* XFRM manager */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
static int blade_state_notify(struct xfrm_state *x, struct km_event *c)
#else
static int blade_state_notify(struct xfrm_state *x, const struct km_event *c)
#endif
{
        switch (c->event) {
        case XFRM_MSG_UPDSA:
        case XFRM_MSG_NEWSA:
		if (!x->sel.user)
			x->sel.user = blade_ipsec_sysctl_default_fp;
		break;
        default:
		break;
        }

        return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
static int blade_acquire(struct xfrm_state *x, struct xfrm_tmpl *xt,
			 struct xfrm_policy *xp, int dir)
#else
static int blade_acquire(struct xfrm_state *x, struct xfrm_tmpl *xt,
			 struct xfrm_policy *xp)
#endif
{
	return 0;
}

static struct xfrm_policy *blade_compile_policy(struct sock *sk, int opt,
						u8 *data, int len, int *dir)
{
	*dir = -EOPNOTSUPP;
	return NULL;
}

static struct xfrm_mgr blade_mgr = {
	.id             = "blade-ipsec",
	.notify         = blade_state_notify,
	/*
	 * kernel does not check if the pointer is defined,
	 * we need dummy functions.
	 */
	.acquire        = blade_acquire,
	.compile_policy = blade_compile_policy,
	/* kernel checks if the pointer is defined */
	.notify_policy  = NULL,
	.report         = NULL,
	.migrate        = NULL,
	.new_mapping    = NULL,
};

static int __init blade_ipsec_init(void)
{
	int ret;
	struct list_head *xfrm_km_list;
	struct xfrm_mgr *km, *next;

	/* genl */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	ret = genl_register_family_with_ops(&blade_ipsec_genl_family, blade_ipsec_genl_ops,
					    ARRAY_SIZE(blade_ipsec_genl_ops));
#else
	ret = genl_register_family_with_ops_groups(&blade_ipsec_genl_family,
						   blade_ipsec_genl_ops,
						   blade_ipsec_mcgrp);
#endif
	if (ret != 0)
		goto fail;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	ret = genl_register_mc_group(&blade_ipsec_genl_family, blade_ipsec_mcgrp);
	if (ret != 0)
		goto fail_mc_grp;
#endif

	/* register sysfs */
	blade_ipsec_sysctl_header = register_sysctl_table(blade_ipsec_sysctl_root_table);
	if (blade_ipsec_sysctl_header == NULL) {
		ret = -ENOMEM;
		goto fail_sysctl;
	}

	/* get xfrm_km_list */
	xfrm_register_km(&blade_mgr);
	/* xfrm_register_km adds in tail, so next is the head */
	xfrm_km_list = (struct list_head *)blade_mgr.list.next;

	/* ensure that our manager is put before the others, we will
	 * need to put a default value in sel.user field before
	 * netlink / pfkey2 are notified
	 */
	list_for_each_entry_safe(km, next, xfrm_km_list, list) {
		if (!km->id)
			continue;

		/* stop when we get ours, we are finished */
		if (!strcmp(km->id, "blade-ipsec"))
			break;

		xfrm_unregister_km(km);
		xfrm_register_km(km);
	}

	if (xfrm_km_list->next == &blade_mgr.list)
		printk("%s: completed\n", __func__);
	else {
		printk("%s: blade_mgr is not in head\n", __func__);
		list_for_each_entry(km, xfrm_km_list, list)
			printk("%s: id=%s\n", __func__, km->id);
		ret = -EINVAL;
		goto fail_xfrm;
	}

	return 0;

fail_xfrm:
	unregister_sysctl_table(blade_ipsec_sysctl_header);

fail_sysctl:
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	genl_unregister_mc_group(&blade_ipsec_genl_family, blade_ipsec_mcgrp);

fail_mc_grp:
#endif
	genl_unregister_family(&blade_ipsec_genl_family);

fail:
	printk("%s: init failed\n", __func__);

	return ret;
}

static void __exit blade_ipsec_exit(void)
{
	printk("%s: exit\n", __func__);

	xfrm_unregister_km(&blade_mgr);

	unregister_sysctl_table(blade_ipsec_sysctl_header);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	genl_unregister_mc_group(&blade_ipsec_genl_family, blade_ipsec_mcgrp);
#endif
	genl_unregister_family(&blade_ipsec_genl_family);
}

module_init(blade_ipsec_init);
module_exit(blade_ipsec_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("6WIND");
