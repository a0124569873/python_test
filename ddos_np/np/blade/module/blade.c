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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/ctype.h>
#include <net/genetlink.h>

#include <net/arp.h>

#include "blade.h"

struct blade_fp {
	struct list_head next;
	uint8_t id;
	char mac[ETH_ALEN];
};

static LIST_HEAD(blade_fp_list);
static DEFINE_RWLOCK(blade_fp_list_lock);

static struct genl_multicast_group blade_mcgrp[] = {
	{	.name = BLADE_FAMILY_NAME,	},
};

struct genl_family blade_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = BLADE_FAMILY_NAME,
	.version = 1,
	.maxattr = BLADE_A_FP_MAX,
};

static const struct nla_policy blade_genl_policy[BLADE_A_FP_MAX + 1] = {
	[BLADE_A_FP_INFO] = { .len = sizeof(struct blade_fpinfo) },
};

/* static functions */
static int blade_fp_add(uint8_t fpid, char *mac);
static int blade_fp_del_one(uint8_t fpid);
static char *blade_mac_ntoa(const uint8_t *addr, size_t len);

/* genl */
static int genl_fill_blade_fpinfo(struct sk_buff *skb, struct blade_fp *fp,
				  u32 pid, u32 seq, unsigned int flags,
				  int type)
{
	struct nlmsghdr *nlh;
	struct blade_fpinfo fpinfo;

	nlh = genlmsg_put(skb, pid, seq, &blade_genl_family, flags, type);
	if (nlh == NULL)
		goto nla_put_failure;

	fpinfo.id = fp->id;
	memcpy(&fpinfo.mac, fp->mac, ETH_ALEN);

	nla_put(skb, BLADE_A_FP_INFO, sizeof(fpinfo), &fpinfo);

	genlmsg_end(skb, nlh);

	return skb->len;

nla_put_failure:
	genlmsg_cancel(skb, nlh);

	return -EMSGSIZE;
}

static void blade_genl_notify_newfp(struct blade_fp *fp)
{
	size_t size;
	struct sk_buff *skb;

	size = nla_total_size(sizeof(struct blade_fpinfo));
	skb = genlmsg_new(size, GFP_ATOMIC);
	if (!skb)
		return;

	if (genl_fill_blade_fpinfo(skb, fp, 0, 0, 0, BLADE_C_FP_NEW) <= 0) {
		kfree_skb(skb);
		return;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	genlmsg_multicast_netns(&init_net, skb, 0, blade_mcgrp[0].id,
				GFP_KERNEL);
#else
	genlmsg_multicast_netns(&blade_genl_family, &init_net, skb, 0, 0,
				GFP_KERNEL);
#endif
}

static void blade_genl_notify_delfp(struct blade_fp *fp)
{
	size_t size;
	struct sk_buff *skb;

	size = nla_total_size(sizeof(struct blade_fpinfo));
	skb = genlmsg_new(size, GFP_ATOMIC);
	if (!skb)
		return;

	if (genl_fill_blade_fpinfo(skb, fp, 0, 0, 0, BLADE_C_FP_DEL) <= 0) {
		kfree_skb(skb);
		return;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	genlmsg_multicast_netns(&init_net, skb, 0, blade_mcgrp[0].id,
				GFP_KERNEL);
#else
	genlmsg_multicast_netns(&blade_genl_family, &init_net, skb, 0, 0,
				GFP_KERNEL);
#endif
}

static int blade_genl_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	int ret = 0;
	u32 idx = 0;
	u32 s_idx = cb->args[0];
	struct blade_fp *fp;

	read_lock(&blade_fp_list_lock);
	list_for_each_entry(fp, &blade_fp_list, next) {
		if (idx++ < s_idx)
			continue;

		if ((ret = genl_fill_blade_fpinfo(skb, fp,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
						  NETLINK_CB(cb->skb).pid,
#else
						  NETLINK_CB(cb->skb).portid,
#endif
						  cb->nlh->nlmsg_seq,
						  NLM_F_MULTI,
						  BLADE_C_FP_DUMP)) <= 0) {
			idx--;
			break;
		}
	}
	read_unlock(&blade_fp_list_lock);

	cb->args[0] = idx;
	return skb->len;
}

static int blade_genl_new(struct sk_buff *skb, struct genl_info *info)
{
	struct blade_fpinfo *fpinfo;
	int ret;

	if (!info->attrs[BLADE_A_FP_INFO])
		return -EINVAL;

	fpinfo = nla_data(info->attrs[BLADE_A_FP_INFO]);

	ret = blade_fp_add(fpinfo->id, fpinfo->mac);

	return ret;
}

static int blade_genl_del(struct sk_buff *skb, struct genl_info *info)
{
	struct blade_fpinfo *fpinfo;
	int ret;

	if (!info->attrs[BLADE_A_FP_INFO])
		return -EINVAL;

	fpinfo = nla_data(info->attrs[BLADE_A_FP_INFO]);

	ret = blade_fp_del_one(fpinfo->id);

	return ret;
}

static struct genl_ops blade_genl_ops[] = {
	{
		.cmd = BLADE_C_FP_DUMP,
		.flags = 0,
		.policy = blade_genl_policy,
		.doit = NULL,
		.dumpit = blade_genl_dump,
	},
	{
		.cmd = BLADE_C_FP_NEW,
		.flags = 0,
		.policy = blade_genl_policy,
		.doit = blade_genl_new,
		.dumpit = NULL,
	},
	{
		.cmd = BLADE_C_FP_DEL,
		.flags = 0,
		.policy = blade_genl_policy,
		.doit = blade_genl_del,
		.dumpit = NULL,
	}
};

/* utils */
/* taken from rfpvi code */
static const char hexdigit[]="0123456789abcdef";

static char *blade_mac_ntoa(const uint8_t *addr, size_t len)
{
	static char addrstr[ETH_ALEN * 3];
	const uint8_t *src;
	char *dst;
	uint8_t byte;
	size_t i, maclen;

	if (len > ETH_ALEN)
		maclen = ETH_ALEN;
	else
		maclen = len;

	src = addr;
	dst = addrstr;

	if (maclen > 0) {
		byte = *src++;
		*dst++ = hexdigit[(byte >> 4) & 0xf];
		*dst++ = hexdigit[byte & 0xf];

		for (i=1; i<maclen; i++) {
			byte = *src++;
			*dst++ = ':';
			*dst++ = hexdigit[(byte >> 4) & 0xf];
			*dst++ = hexdigit[byte & 0xf];
		}
	}

	*dst++ = 0;

	return addrstr;
}

/* taken from rfpvi code */
static int blade_parse_mac_addr(const char *string, char *macbuf)
{
	int i;

	for (i=0; i<ETH_ALEN; i++) {
		unsigned long byte;
		char *end;

		byte = simple_strtoul(string, &end, 16);

		if (((*end != ':') && (*end != '\0')) ||
		    (end == string) ||
		    (byte > 255))
			return -1;

		macbuf[i] = (char)byte;

		if (*end == '\0')
			break;

		string = end + 1;
	}

	return i+1;
}


/* fp lookup, needs blade_fp_list_lock taken */
static struct blade_fp *__blade_fp_lookup_byid(uint8_t id)
{
	struct blade_fp *fp;

	list_for_each_entry(fp, &blade_fp_list, next) {
		if (fp->id != id)
			continue;

		return fp;
	}

	return NULL;
}

/* fp add */
static int blade_fp_add(uint8_t fpid, char *mac)
{
	struct blade_fp *fp;

	if (fpid == 0 || fpid > BLADE_MAX_FPID)
		return -EINVAL;

	fp = (struct blade_fp *)kmalloc(sizeof(struct blade_fp), GFP_KERNEL);
	fp->id = fpid;
	memcpy(fp->mac, mac, ETH_ALEN);

	/* lookup */
	write_lock(&blade_fp_list_lock);
	if (__blade_fp_lookup_byid(fpid) != NULL) {
		write_unlock(&blade_fp_list_lock);
		kfree(fp);
		return -EEXIST;
	}
	list_add(&fp->next, &blade_fp_list);
	write_unlock(&blade_fp_list_lock);

	printk("new fp added: %u %s\n", fpid, blade_mac_ntoa(mac, ETH_ALEN));

	blade_genl_notify_newfp(fp);

	return 0;
}

static int blade_fp_init_one(char *line)
{
	char *string, *fpid_str, *mac_str, *end_str;
	uint8_t fpid;
	char mac[ETH_ALEN];
	int ret;

	/* parse parameters */
	string = line;
	fpid_str = strsep(&string, " \t");
	while (string && isspace(*string))
		string++;
	mac_str = strsep(&string, " \t");

	if (!fpid_str || !mac_str) {
		printk("add fp format: fpid mac_addr\n");
		return -EINVAL;
	}

	fpid = (uint8_t) simple_strtol(fpid_str, &end_str, 0);
	memset(mac, 0, sizeof(mac));
	if (blade_parse_mac_addr(mac_str, mac) != 6) {
		printk("invalid mac address: %s\n", blade_mac_ntoa(mac, ETH_ALEN));
		return -EINVAL;
	}

	ret = blade_fp_add(fpid, mac);

	return ret;
}

/* fp del */
static int blade_fp_del_one(uint8_t fpid)
{
	struct blade_fp *fp;

	if (fpid == 0 || fpid > BLADE_MAX_FPID)
		return -EINVAL;

	write_lock(&blade_fp_list_lock);
	fp = __blade_fp_lookup_byid(fpid);
	if (fp == NULL) {
		write_unlock(&blade_fp_list_lock);
		return -EINVAL;
	}
	list_del(&fp->next);
	write_unlock(&blade_fp_list_lock);

	printk("blade fp deleted: %u\n", fpid);

	blade_genl_notify_delfp(fp);

	kfree(fp);
	return 0;
}

/* SYSCTL */
struct ctl_table_header *blade_sysctl_header;
/*
 * Buffers used to the information of blade fp to add/delete/list
 * format: fpid peer_mac for add and fpid for delete
 */
static char blade_sysctl_add_fp_buf[512];
static int blade_sysctl_del_fp_id = 0;
static char blade_sysctl_list_fp_buf[512];

/*
 * Handler when /proc/sys/blade/add_fp is written
 * Add the fp in the system
 * Returns 0 on success, else returns a negative value
 */
static int blade_sysctl_add_fp(struct ctl_table *ctl, int write,
			       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int err;

	if ((err = proc_dostring(ctl, write, buffer, lenp, ppos)) < 0)
		return err;

	/* add blade blade and empty add_blade */
	if (write) {
		err = blade_fp_init_one(ctl->data);
		strcpy((char*)ctl->data, "");
	}

	return err;
}

/*
 * Handler when /proc/sys/blade/del_fp is written
 * Delete the fp from the system
 * Returns 0 on success, else returns a negative value
 */
static int blade_sysctl_del_fp(struct ctl_table *ctl, int write,
			       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	/* struct blade_blade *blade; */
	uint8_t fpid;
	int *valp = ctl->data;
	int err = 0;

	if ((err = proc_dointvec(ctl, write, buffer, lenp, ppos)) < 0)
		return err;

	if (write) {
		fpid = (uint8_t)*valp;
		err = blade_fp_del_one(fpid);
		strcpy((char*)ctl->data, "");
	}

	return err;
}


/*
 * Handler when /proc/sys/blade/list_fp is read
 * Returns 0 on success, else returns a negative value
 */
static int blade_sysctl_list_fp(struct ctl_table *ctl, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct blade_fp *fp;
	int err;
	int len = 0;
	int n = 0;

	if (write) {
		err = -EPERM;
		goto out;
	}

	strcpy((char*)ctl->data, "");

	read_lock(&blade_fp_list_lock);

	list_for_each_entry(fp, &blade_fp_list, next) {
		n = snprintf((char *)ctl->data + len, ctl->maxlen - len,
			    "%sfp%d %s", len == 0 ? "" : "\n",
			    fp->id, blade_mac_ntoa(fp->mac, ETH_ALEN));
		if (n < 0) {
			err = -EINVAL;
			goto out;
		}
		len += n;

		if (len >= ctl->maxlen) {
			printk("fp list is truncated (%d>=%d)\n",
			       len, ctl->maxlen);
			break;
		}
	}

	read_unlock(&blade_fp_list_lock);

	if ((err = proc_dostring(ctl, write, buffer, lenp, ppos)) < 0)
		return err;

	return err;

out:
	strcpy((char*)ctl->data, "");
	return err;
}

/*
 * Contents of /proc/sys/blade directory
 */
struct ctl_table blade_sysctl_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "add_fp",
		.data           =       blade_sysctl_add_fp_buf,
		.maxlen         =       sizeof(blade_sysctl_add_fp_buf),
		.mode           =       0644,
		.proc_handler   =       &blade_sysctl_add_fp,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "del_fp",
		.data           =       &blade_sysctl_del_fp_id,
		.maxlen         =       sizeof(int),
		.mode           =       0644,
		.proc_handler   =       &blade_sysctl_del_fp,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "list_fp",
		.data           =       &blade_sysctl_list_fp_buf,
		.maxlen         =       sizeof(blade_sysctl_list_fp_buf),
		.mode           =       0644,
		.proc_handler   =       &blade_sysctl_list_fp,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       0,      /* sentinel */
#endif
		.procname       =       NULL,
	}
};

/*
 * Define /proc/sys/blade directory
 */
struct ctl_table blade_sysctl_root_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "blade",
		.mode           =       0555,
		.child          =       blade_sysctl_table,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       0,      /* sentinel */
#endif
		.procname       =       NULL,
	}
};

static int __init blade_init(void)
{
	int ret;

	/* fp list lock */
	rwlock_init(&blade_fp_list_lock);

	/* genl */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	ret = genl_register_family_with_ops(&blade_genl_family, blade_genl_ops,
					    ARRAY_SIZE(blade_genl_ops));
#else
	ret = genl_register_family_with_ops_groups(&blade_genl_family,
						   blade_genl_ops, blade_mcgrp);
#endif
	if (ret != 0)
		goto fail;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	ret = genl_register_mc_group(&blade_genl_family, blade_mcgrp);
	if (ret != 0)
		goto fail_mc_grp;
#endif

	/* register sysfs */
	blade_sysctl_header = register_sysctl_table(blade_sysctl_root_table);
	if (blade_sysctl_header == NULL) {
		ret = -ENOMEM;
		goto fail_sysctl;
	}

	printk("%s: init completed\n", __func__);

	return 0;

fail_sysctl:
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	genl_unregister_mc_group(&blade_genl_family, blade_mcgrp);

fail_mc_grp:
#endif
	genl_unregister_family(&blade_genl_family);

fail:
	printk("%s: init failed\n", __func__);

	return ret;
}

static void __exit blade_exit(void)
{
	printk("%s: exit\n", __func__);

	unregister_sysctl_table(blade_sysctl_header);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	genl_unregister_mc_group(&blade_genl_family, blade_mcgrp);
#endif
	genl_unregister_family(&blade_genl_family);
}

module_init(blade_init);
module_exit(blade_exit);
MODULE_LICENSE("GPL");
