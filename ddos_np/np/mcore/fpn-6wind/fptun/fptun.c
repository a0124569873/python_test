/* 
 * Copyright (C) 2006 6WIND, All rights reserved. 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * #endif
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* 6WIND_GPL */

/* FPTUN for Linux */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/percpu.h>
#include <net/route.h> /* for BUGTRAP */
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/ip.h>
#include <linux/etherdevice.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/flow.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h> /* ARPHRD_LOOPBACK */
#include <asm/uaccess.h>
#include <linux/mroute.h>
#include <linux/mroute6.h>
#include <net/xfrm.h>

#include <net/neighbour.h>
#include <net/arp.h>
#include <net/ndisc.h>
#ifdef CONFIG_MCORE_NF_CT
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
#include <net/netfilter/nf_conntrack_zones.h>
#endif
#endif

#include <ifuid.h>

#if defined(USE_VRF_NETNS)
/* Generic VRF implementation with netns for Linux 3.x */
#include <vrf.h>
#endif

#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif

#include <linux/kallsyms.h>
#include "fptun.h"
#include "fp-hitflags.h"

int bladeid = -1;
module_param(bladeid, int, 0);
MODULE_PARM_DESC(bladeid, "in distributed SDS mode, id of our blade");

struct fptun_stats {
	unsigned long FPTunExceptions;
#ifdef CONFIG_MCORE_FPTUN_INTERFACE_WHITE_LIST
	unsigned long FPTunExceptionsFiltered;
#endif
	unsigned long ExceptionClass[FPTUN_EXC_CLASS_MAX+1];
	unsigned long ExceptionType[FPTUN_TYPE_MAX+1];
};
static DEFINE_PER_CPU(struct fptun_stats, fptun_stats);

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
/* alias for the unexported symbols, prefix fptun_ */
static int (*fptun_ip6_forward)(struct sk_buff *skb);
static void (*fptun_ip6_route_input)(struct sk_buff *skb);
static struct neigh_table *fptun_nd_tbl;
#endif
#ifdef CONFIG_MCORE_TAP
static struct list_head *fptun_ptype_all __read_mostly;
#endif

static unsigned int fptun_debug_level = 0;
module_param(fptun_debug_level, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(fptun_debug_level, "enable debug");

static struct proc_dir_entry *fptun_proc;

#define TRACE_FPTUN(fmt, args...) \
do { \
	if (fptun_debug_level) \
		printk(KERN_DEBUG "FPTUN: " fmt "\n", ## args); \
} while(0)

#define SENDERROR(text) \
do { \
	TRACE_FPTUN(text " at line %d", __LINE__); \
	goto error; \
} while (0)

/* Should be kept in sync with VNB headers */
struct vnb_skb_parms {
	u64	vnb_magic;
#define VNB_MAGIC_SKIP	0x2010102212072012ULL
};
#define VNB_CB(skb)         (*(struct vnb_skb_parms*)&((skb)->cb))

/* Specific handler invoked upon receipt of FPTUN_RFPS_UPDATE messages */
typedef void (*fptun_rfps_msg_handler_t)(struct sk_buff *);
fptun_rfps_msg_handler_t fptun_rfps_msg_hdlr_p = NULL;
EXPORT_SYMBOL(fptun_rfps_msg_hdlr_p);

#ifdef CONFIG_MCORE_FPTUN_INTERFACE_WHITE_LIST
/* fptun interface white list node struct */
struct fptun_iface_node {
	struct list_head  list;
	char   name[IFNAMSIZ];  /* interface name */
	struct net_device *dev; /* net_device pointer */
};

/* interface white list, define interfaces on which a fptun packet can be received */
LIST_HEAD(fptun_ifaces);

static DEFINE_RWLOCK(fptun_ifaces_lock);

/* The maximum number of interface in white list */
#define FPTUN_MAX_IFACES 16
static unsigned int total_fptun_ifaces = 0;

/* Save interface name of last dropped FPTUN packet.
 * It may help monitoring the packet incoming from unauthorized devices.
 */
char last_filtered_packet_indev[IFNAMSIZ];

/* Get interface node by interface name
 * Returns node if find one, else returns NULL */
static struct fptun_iface_node *get_fptun_iface_node_by_name(char *name)
{
	struct list_head *tmp;
	struct fptun_iface_node *node = NULL;

	if (!name) return NULL;

	read_lock_bh(&fptun_ifaces_lock);
	list_for_each(tmp, &fptun_ifaces) {
		node = list_entry(tmp, struct fptun_iface_node, list);
		if (strcmp(node->name, name) == 0) {
			read_unlock_bh(&fptun_ifaces_lock);
			return node;
		}
	}
	read_unlock_bh(&fptun_ifaces_lock);

	return NULL;
}


/* Get interface node by dev ptr
 * Returns node if find one, else returns NULL
 */
static struct fptun_iface_node *get_fptun_iface_node_by_dev(struct net_device *dev)
{
	struct list_head *tmp;
	struct fptun_iface_node *node = NULL;

	if (!dev) return NULL;

	read_lock_bh(&fptun_ifaces_lock);
	list_for_each(tmp, &fptun_ifaces) {
		node = list_entry(tmp, struct fptun_iface_node, list);
		if (node->dev == dev) {
			read_unlock_bh(&fptun_ifaces_lock);
			return node;
		}
	}
	read_unlock_bh(&fptun_ifaces_lock);

	return NULL;
}

/* Add one node to while list
 * Returns 0 on success, else returns a negative value
 */
static int fptun_add_iface(char *name)
{
	struct fptun_iface_node *new_node = NULL;
	struct net_device *dev = NULL;

	if (!name) return 0;

	if (total_fptun_ifaces >= FPTUN_MAX_IFACES) {
		printk(KERN_INFO "FPTUN: total interface number reaches the limit: %u\n",
					FPTUN_MAX_IFACES);
		return -EPERM;
	}

	if (get_fptun_iface_node_by_name(name) != NULL) {
		printk(KERN_INFO "FPTUN: fptun interface node already exists: %s\n", name);
		return -EEXIST;
	}

	/* Don't forget to call dev_put() when del interface or module exit */
	dev = dev_get_by_name(&init_net, name);
	if (!dev) {
		printk(KERN_INFO "FPTUN: interface %s not found\n", name);
		return -ENODEV;
	}

	new_node = (struct fptun_iface_node *)kmalloc(sizeof(struct fptun_iface_node), GFP_KERNEL);
	if (!new_node) {
		printk(KERN_ALERT "FPTUN: can not allocate memory\n");
		dev_put(dev);
		return -ENOMEM;
	}

	snprintf(new_node->name, sizeof(new_node->name), "%s", name);
	new_node->dev = dev;

	write_lock_bh(&fptun_ifaces_lock);
	/* the interface which is used frequently should be added to the front of list,
	 * so list_add_tail is used, instead of list_add
	 */
	list_add_tail(&new_node->list, &fptun_ifaces);
	total_fptun_ifaces++;
	write_unlock_bh(&fptun_ifaces_lock);
	printk(KERN_DEBUG "FPTUN: interface %s added to white list\n", name);

	return 0;
}

/* Delete one node from while list
 * Returns 0 on success, else returns a negative value
 */
static int fptun_del_iface_byname(char *name)
{
	struct fptun_iface_node *node = NULL;

	if (!name) return 0;

	if ((node = get_fptun_iface_node_by_name(name)) == NULL) {
		printk(KERN_INFO "FPTUN: fptun interface node can not be found: %s\n", name);
		return -ENODEV;
	}

	write_lock_bh(&fptun_ifaces_lock);
	list_del(&node->list);
	total_fptun_ifaces--;
	write_unlock_bh(&fptun_ifaces_lock);

	dev_put(node->dev);
	kfree(node);
	printk(KERN_DEBUG "FPTUN: interface %s deleted from white list\n", name);

	return 0;
}

/* Delete one node which is specified by dev ptr */
static int fptun_del_iface_bydev(struct net_device *dev)
{
	struct fptun_iface_node *node = NULL;

	if (!dev)
		return 0;

	if ((node = get_fptun_iface_node_by_dev(dev)) == NULL)
		return -ENODEV;

	write_lock_bh(&fptun_ifaces_lock);
	list_del(&node->list);
	total_fptun_ifaces--;
	write_unlock_bh(&fptun_ifaces_lock);

	dev_put(node->dev);
	kfree(node);
	pr_debug("%s: interface %s deleted from white list\n",
		 __func__, dev->name);
	return 0;
}

/* called on module exit to free all nodes */
static void fptun_free_all_ifaces(void)
{
	struct list_head *tmp, *next;
	struct fptun_iface_node *node = NULL;

	write_lock_bh(&fptun_ifaces_lock);
	list_for_each_safe(tmp, next, &fptun_ifaces) {
		node = list_entry(tmp, struct fptun_iface_node, list);

		list_del(&node->list);
		total_fptun_ifaces--;
		dev_put(node->dev);
		kfree(node);
	}
	write_unlock_bh(&fptun_ifaces_lock);

	return;
}

static int fptun_netdev_event(struct notifier_block *this, unsigned long event,
			      void *data)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
	struct net_device *dev = (struct net_device *) data;
#else
	struct net_device *dev = netdev_notifier_info_to_dev(data);
#endif
	switch (event) {
	case NETDEV_UNREGISTER:
		fptun_del_iface_bydev(dev);
		break;
	default:
		/* do nothing now */
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block fptun_netdev_notifier = {
	.notifier_call = fptun_netdev_event,
};
#endif

/*
 * Specific handler invoked upon reception
 * of FPTUN_VNB2VNB_FP_TO_LINUX_EXCEPT messages
 */

static void printk_buf(const unsigned char *data, unsigned int len)
{
	unsigned int i, out, ofs;
#define LINE_LEN 80
	char line[LINE_LEN];	/* space needed 8+16*3+3+16 == 75 */

	if (fptun_debug_level <= 1)
		return;
	TRACE_FPTUN("Dump packet");

	ofs = 0;
	while (ofs < len) {
		/* format 1 line in the buffer, then use printk to print them */
		out = snprintf(line, LINE_LEN, "%08X", ofs);
		for (i=0; ofs+i < len && i<16; i++)
			out += snprintf(line+out, LINE_LEN - out, " %02X", data[ofs+i]);
		for(;i<=16;i++)
			out += snprintf(line+out, LINE_LEN - out, "   ");
		for(i=0; ofs < len && i<16; i++, ofs++) {
			unsigned char c = data[ofs];
			if (!isascii(c) || !isprint(c))
				c = '.';
			out += snprintf(line+out, LINE_LEN - out, "%c", c);
		}
		printk(KERN_DEBUG "%s\n", line);
	}

#if 0
	{
		struct iphdr *ip = (struct iphdr *)data;
		printk("IP %u.%u.%u.%u to %u.%u.%u.%u \n", NIPQUAD(ip->saddr), NIPQUAD(ip->daddr));
		printk("IP ttl=%d proto=%d check=%x\n", ip->ttl, ip->protocol, ip->check);
	}
#endif
}

static int fptun_show_debug_level(struct seq_file *m, void *v)
{
	seq_printf(m, "0x%08X\n", fptun_debug_level);
	return 0;
}

static int fptun_open_debug_level(struct inode *inode, struct file *file)
{
	return single_open(file, fptun_show_debug_level, NULL);
}

static ssize_t fptun_store_debug_level(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *ppos)

{
	unsigned long value;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	char          str[16];
	char          *strend;

	if (count > (sizeof(str) - 1))
		return -EINVAL;

	if (copy_from_user(str,buffer,count))
		return -EFAULT;

	str[count] = '\0';

	value = simple_strtoul(str,&strend,0);
	if (str == strend)
		return -EINVAL;
#else
	int err = kstrtoul_from_user(buffer, count, 0, &value);

	if (err)
		return err;
#endif

	fptun_debug_level = value;

	return (count);
}

static const struct file_operations fptun_debug_fops = {
	.owner = THIS_MODULE,
	.open = fptun_open_debug_level,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = fptun_store_debug_level,
};

#ifdef CONFIG_MCORE_FPTUN_INTERFACE_WHITE_LIST
static int fptun_show_empty(struct seq_file *m, void *v)
{
	seq_printf(m, "\n");
	return 0;
}

static int fptun_open_empty(struct inode *inode, struct file *file)
{
	return single_open(file, fptun_show_empty, NULL);
}

/* Read string from user buffer
 * Returns 0 on success, else returns a negative value.
 */
static int get_devname_from_userland(const char *buffer, unsigned long count,
				     void *result, int maxlen)
{
	size_t len;
	char __user *p;
	char c;

	len = 0;
	p = (char __user *)buffer;
	while (len < count) {
		if (get_user(c, p++))
			return -EFAULT;
		if (c == 0 || c == '\n')
			break;
		len++;
	}
	if (len > (maxlen - 1))
		return -EINVAL;
	if (copy_from_user(result, buffer, len))
		return -EFAULT;

	((char *)result)[len] = '\0';

	return 0;
}

static ssize_t fptun_add_iface_handler(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *ppos)
{
	char name[IFNAMSIZ];
	int err;

	if ((err = get_devname_from_userland(buffer, count, name, IFNAMSIZ)) < 0)
		return err;

	fptun_add_iface(name);
	return count;
}

static const struct file_operations fptun_add_iface_fops = {
	.owner = THIS_MODULE,
	.open = fptun_open_empty,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = fptun_add_iface_handler,
};

static ssize_t fptun_del_iface_handler(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *ppos)
{
	char name[IFNAMSIZ];
	int err;

	if ((err = get_devname_from_userland(buffer, count, name, IFNAMSIZ)) < 0)
		return err;

	fptun_del_iface_byname(name);
	return count;
}

static const struct file_operations fptun_del_iface_fops = {
	.owner = THIS_MODULE,
	.open = fptun_open_empty,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = fptun_del_iface_handler,
};

static int fptun_show_iface(struct seq_file *m, void *v)
{
	struct list_head *tmp;
	struct fptun_iface_node *node = NULL;

	read_lock_bh(&fptun_ifaces_lock);
	list_for_each(tmp, &fptun_ifaces) {
		node = list_entry(tmp, struct fptun_iface_node, list);
		seq_printf(m, "%s\n", node->name);
	}
	read_unlock_bh(&fptun_ifaces_lock);
	return 0;
}

static int fptun_open_iface_handler(struct inode *inode, struct file *file)
{
	return single_open(file, fptun_show_iface, NULL);
}

static const struct file_operations fptun_show_iface_fops = {
	.owner = THIS_MODULE,
	.open = fptun_open_iface_handler,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int fptun_show_last_filtered_packet_indev(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", last_filtered_packet_indev);
	return 0;
}

static int fptun_open_last_filtered_packet_indev(struct inode *inode, struct file *file)
{
	return single_open(file, fptun_show_last_filtered_packet_indev, NULL);
}

static ssize_t fptun_reset_last_filtered_packet_indev(struct file *file,
						      const char __user *buffer,
						      size_t count, loff_t *ppos)
{
       memset(last_filtered_packet_indev, '\0', IFNAMSIZ);
       return count;
}

static const struct file_operations fptun_show_indev_fops = {
	.owner = THIS_MODULE,
	.open = fptun_open_last_filtered_packet_indev,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = fptun_reset_last_filtered_packet_indev,
};
#endif

/* Statistics MACRO */
#define FPTUN_STATS_SUM(field) \
({ \
	unsigned long sum = 0; \
	int i; \
	for (i = 0; i < NR_CPUS; i++) { \
		if (cpu_possible(i)) \
			sum += per_cpu(fptun_stats, i).field; \
	} \
	sum; \
})

#define FPTUN_STATS_PRINT(field) \
	seq_printf(m, "  %s: %lu\n", #field, FPTUN_STATS_SUM(field));

#define FPTUN_STATS_PRINT_VAR(name, var) \
	seq_printf(m, "    %s: %lu\n", #var, FPTUN_STATS_SUM(name[var]));

#define FPTUN_STATS_PRINT_TYPE(name) \
	seq_printf(m, "  %s:\n", #name);	\
	FPTUN_STATS_PRINT_VAR(name, FPTUN_BASIC_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV4_OUTPUT_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV6_OUTPUT_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV4_INPUT_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV6_INPUT_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV4_FWD_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV6_FWD_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV4_IPSECDONE_OUTPUT_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV6_IPSECDONE_OUTPUT_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_ETH_INPUT_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_ETH_NOVNB_INPUT_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IFACE_INPUT_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_LOOP_INPUT_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_OUTPUT_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_MULTICAST_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_MULTICAST6_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_ETH_SP_OUTPUT_REQ); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV4_IPSEC_SP_OUTPUT_REQ); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV6_IPSEC_SP_OUTPUT_REQ); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_ETH_FP_OUTPUT_REQ); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV4_IPSEC_FP_OUTPUT_REQ); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV6_IPSEC_FP_OUTPUT_REQ); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_TAP); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV4_REPLAYWIN); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV6_REPLAYWIN); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_HITFLAGS_SYNC); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_RFPS_UPDATE); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV4_REPLAYWIN_GET); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV6_REPLAYWIN_GET); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV4_REPLAYWIN_REPLY); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_IPV6_REPLAYWIN_REPLY); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_VNB2VNB_FP_TO_LINUX_EXCEPT); \
	FPTUN_STATS_PRINT_VAR(name, FPTUN_VNB2VNB_LINUX_TO_FP_EXCEPT);


#define FPTUN_STATS_PRINT_VAR_MASK(name, var)                       \
	seq_printf(m, "    %s: %lu\n", #var, FPTUN_STATS_SUM(name[(var) & FPTUN_EXC_CLASS_MASK]));

#define FPTUN_STATS_PRINT_CLASS(name) \
	seq_printf(m, "  %s:\n", #name);	\
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_UNDEF); \
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_SP_FUNC); \
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_ETHER_DST); \
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_IP_DST); \
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_ICMP_NEEDED); \
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_NDISC_NEEDED); \
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_IKE_NEEDED); \
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_FPC); \
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_NF_FUNC); \
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_TAP); \
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_REPLAYWIN); \
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_ECMP_NDISC_NEEDED); \
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_VNB_TO_VNB); \
	FPTUN_STATS_PRINT_VAR_MASK(name, FPTUN_EXC_SOCKET);

static int fptun_show_stats(struct seq_file *m, void *v)
{
	FPTUN_STATS_PRINT(FPTunExceptions);
#ifdef CONFIG_MCORE_FPTUN_INTERFACE_WHITE_LIST
	FPTUN_STATS_PRINT(FPTunExceptionsFiltered);
#endif
	FPTUN_STATS_PRINT_CLASS(ExceptionClass);
	FPTUN_STATS_PRINT_TYPE(ExceptionType);
	return 0;
}

static int fptun_open_stats(struct inode *inode, struct file *file)
{
	return single_open(file, fptun_show_stats, NULL);
}

static const struct file_operations fptun_stats_fops = {
	.owner = THIS_MODULE,
	.open = fptun_open_stats,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static void fptun_inc_stats(struct fptunhdr *hdr)
{
	struct fptun_stats *stats;

	stats = &per_cpu(fptun_stats, get_cpu());
	stats->FPTunExceptions++;
	stats->ExceptionClass[hdr->fptun_exc_class & FPTUN_EXC_CLASS_MASK]++;
	stats->ExceptionType[hdr->fptun_cmd]++;
	put_cpu();
}

#ifdef CONFIG_MCORE_FPTUN_INTERFACE_WHITE_LIST
static void fptun_inc_dropped_stats(void)
{
	struct fptun_stats *stats;

	stats = &per_cpu(fptun_stats, get_cpu());
	stats->FPTunExceptionsFiltered++;
	put_cpu();
}
#endif

/* Realign skb data pointer to a multiple of 4 + mod. This function
 * assumes that the skb is not shared and that the headroom is large
 * enough for that: it should be the case as the function is called
 * after removing a fptun header.
 * To keep ether headers complete for ethernet packets which will be
 * locally inputed, the function realigns a packet by moving data
 * with its ether header included. We need to do this only when the
 * packet is known to be an ethernet packet (hdr_len != 0).
 */
static void align_skb_data(struct sk_buff *skb, int mod, int hdr_len)
{
#if defined(CONFIG_TILE) || defined(CONFIG_TILEGX)
	int headroom = skb_headroom(skb);
	int align;

	align = ((unsigned long)(skb->data) + mod) & 3;
	headroom -= hdr_len;
	WARN_ON(headroom < align);
	if (align != 0 && align <= headroom) {
		u8 *data = skb->data;
		size_t len = skb_headlen(skb);
		skb->data -= align;
		memmove(skb->data - hdr_len, data - hdr_len, len + hdr_len);
		if (hdr_len) {
			skb->mac_header -= align;
			skb_reset_network_header(skb);
		}
		skb_set_tail_pointer(skb, len);
	}
#endif
}

/*
 * Kicks an ARP/NDP entry out of STALE state
 * If required, may also create the entry itself, which will trigger the
 * ARP/NDP resolution.
 */
static void fptun_neigh_activate(void *nexthop, struct neigh_table *tbl,
				struct net_device *vdev, int create)
{
	struct neighbour *neigh;

	/* if neighbour does not exist, create it */
	if ((neigh = __neigh_lookup(tbl, nexthop, vdev, create)) == NULL)
		return;

	neigh_event_send(neigh, NULL);
	neigh_release(neigh);
}

/*
 * lookup for an output route
 * if ipsec_done is set, bypass IPsec processing
 */
static int fptun_ip_route(struct sk_buff *skb, int ipsec_done)
{
	struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
	struct flowi fl = { .oif = 0 };
	fl.fl4_dst = iph->daddr;
#else
	struct flowi4 fl = { .flowi4_oif = 0 };
	fl.daddr = iph->daddr;
#endif

#ifdef CONFIG_NET_VRF
	fl.vrfid = skb_vrfid(skb);
#endif
	/* fl.fl4_protocol is undefined => no xfrm_lookup will be performed */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
	if (ip_route_output_key(dev_net(skb->dev), &rt, &fl) != 0)
#else
	rt = ip_route_output_key(dev_net(skb->dev), &fl);
	if (IS_ERR(rt))
#endif
		SENDERROR("ip_route_output_key");

	skb_dst_drop(skb);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
	skb_dst_set(skb, &rt->u.dst);

	if (rt->u.dst.error)
		SENDERROR("dst->error");
#else
	skb_dst_set(skb, &rt->dst);

	if (rt->dst.error)
		SENDERROR("dst->error");
#endif

	if (!ipsec_done && !xfrm4_route_forward(skb))
		SENDERROR("xfrm4_route_forward");
	if (ipsec_done)
		IPCB(skb)->flags |= IPSKB_XFRM_TRANSFORMED;

	return 0;
error:
	return -1;
}

static int fptun_ipv4_input(struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;

	if (skb_dst(skb) == NULL) {
		int err = ip_route_input(skb, iph->daddr, iph->saddr, iph->tos,
					 skb->dev);
		if (unlikely(err)) {
			if (err == -EHOSTUNREACH)
				IP_INC_STATS_BH(dev_net(skb->dev),
						IPSTATS_MIB_INADDRERRORS);
			else if (err == -ENETUNREACH)
				IP_INC_STATS_BH(dev_net(skb->dev),
						IPSTATS_MIB_INNOROUTES);
			kfree_skb(skb);
			return NET_RX_DROP;
		}
	}

	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
		IP_UPD_PO_STATS_BH(dev_net(rt->u.dst.dev), IPSTATS_MIB_INMCAST,
				   skb->len);
#else
		IP_UPD_PO_STATS_BH(dev_net(rt->dst.dev), IPSTATS_MIB_INMCAST,
				   skb->len);
#endif
	} else if (rt->rt_type == RTN_BROADCAST)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
		IP_UPD_PO_STATS_BH(dev_net(rt->u.dst.dev), IPSTATS_MIB_INBCAST,
				   skb->len);
#else
		IP_UPD_PO_STATS_BH(dev_net(rt->dst.dev), IPSTATS_MIB_INBCAST,
				   skb->len);
#endif

	/* disable IPsec inbound policy check */
	skb_dst(skb)->flags |= DST_NOPOLICY;
	return dst_input(skb);
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
/*
 * lookup for an output route
 * if ipsec_done is set, bypass IPsec processing
 */
static int fptun_ip6_route(struct sk_buff *skb, int ipsec_done)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
	struct flowi fl = { .oif = 0 };
	fl.fl6_dst = iph->daddr;
	fl.fl6_src = iph->saddr;
	fl.proto = iph->nexthdr;
#else
	struct flowi6 fl = { .flowi6_oif = 0 };
	fl.daddr = iph->daddr;
	fl.saddr = iph->saddr;
	fl.flowi6_proto = iph->nexthdr;
#endif

#ifdef CONFIG_NET_VRF
	fl.vrfid = skb_vrfid(skb);
#endif

	skb_dst_drop(skb);
	skb_dst_set(skb, ip6_route_output(dev_net(skb->dev), NULL, &fl));

	if (skb_dst(skb)->error)
		SENDERROR("dst->error");

	if (!ipsec_done && !xfrm6_route_forward(skb))
		SENDERROR("xfrm6_route_forward");

	return 0;
error:
	return -1;
}
#endif


#ifdef CONFIG_MCORE_NF_CT
/* These values are defined as enums in net/netfilter/nf_conntrack_proto_udp.c
 * since we need them here, I had to redefine them.
 * Hopefully, we will find a cleaner way to to this in the future. */
#define UDP_CT_UNREPLIED	0
#define UDP_CT_REPLIED		1
#define UDP_CT_MAX		2
/* These values are defined as enums in net/netfilter/nf_conntrack_proto_gre.c
 * since we need them here, I had to redefine them.
 * Hopefully, we will find a cleaner way to to this in the future. */
#define GRE_CT_UNREPLIED	0
#define GRE_CT_REPLIED		1

static unsigned int *(*nf_ct_timeout_lookup_p)(struct net *,
					       struct nf_conn *,
					       struct nf_conntrack_l4proto *) = NULL;

#ifdef CONFIG_SYSCTL
static struct {
	unsigned int *tcp[TCP_CONNTRACK_MAX];
	int tcp_initialized;
	unsigned int *udp[UDP_CT_MAX];
	int udp_initialized;
	unsigned int *sctp[SCTP_CONNTRACK_MAX];
	int sctp_initialized;
} fptun_timeouts_addr;

static int
fptun_init_timeouts_addr(struct net *net, struct nf_conntrack_l4proto *proto)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	struct ctl_table *ctl = proto->ctl_table;
#else
	struct ctl_table *ctl = proto->get_net_proto(net)->ctl_table;
#endif

	if (ctl == NULL) {
		printk(KERN_ERR "FPTUN: %s: proto '%s' .ctl_table is NULL\n",
		       __FUNCTION__, proto->name);
		return -1;
	}

	switch (proto->l4proto) {

	case IPPROTO_TCP:
		while (ctl->procname != NULL) {
			if (strcmp(ctl->procname, "nf_conntrack_tcp_timeout_syn_sent") == 0)
				fptun_timeouts_addr.tcp[TCP_CONNTRACK_SYN_SENT] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_tcp_timeout_syn_recv") == 0)
				fptun_timeouts_addr.tcp[TCP_CONNTRACK_SYN_RECV] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_tcp_timeout_established") == 0)
				fptun_timeouts_addr.tcp[TCP_CONNTRACK_ESTABLISHED] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_tcp_timeout_fin_wait") == 0)
				fptun_timeouts_addr.tcp[TCP_CONNTRACK_FIN_WAIT] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_tcp_timeout_close_wait") == 0)
				fptun_timeouts_addr.tcp[TCP_CONNTRACK_CLOSE_WAIT] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_tcp_timeout_last_ack") == 0)
				fptun_timeouts_addr.tcp[TCP_CONNTRACK_LAST_ACK] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_tcp_timeout_time_wait") == 0)
				fptun_timeouts_addr.tcp[TCP_CONNTRACK_TIME_WAIT] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_tcp_timeout_close") == 0)
				fptun_timeouts_addr.tcp[TCP_CONNTRACK_CLOSE] = (int *)ctl->data;
			ctl++;
		}
		fptun_timeouts_addr.tcp_initialized = 1;
		break;

	case IPPROTO_UDP:
		while (ctl->procname != NULL) {
			if (strcmp(ctl->procname, "nf_conntrack_udp_timeout") == 0)
				fptun_timeouts_addr.udp[UDP_CT_UNREPLIED] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_udp_timeout_stream") == 0)
				fptun_timeouts_addr.udp[UDP_CT_REPLIED] = (int *)ctl->data;
			ctl++;
		}
		fptun_timeouts_addr.udp_initialized = 1;
		break;

	case IPPROTO_SCTP:
		while (ctl->procname != NULL) {
			if (strcmp(ctl->procname, "nf_conntrack_sctp_timeout_closed") == 0)
				fptun_timeouts_addr.sctp[SCTP_CONNTRACK_CLOSED] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_sctp_timeout_cookie_wait") == 0)
				fptun_timeouts_addr.sctp[SCTP_CONNTRACK_COOKIE_WAIT] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_sctp_timeout_cookie_echoed") == 0)
				fptun_timeouts_addr.sctp[SCTP_CONNTRACK_COOKIE_ECHOED] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_sctp_timeout_established") == 0)
				fptun_timeouts_addr.sctp[SCTP_CONNTRACK_ESTABLISHED] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_sctp_timeout_shutdown_sent") == 0)
				fptun_timeouts_addr.sctp[SCTP_CONNTRACK_SHUTDOWN_SENT] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_sctp_timeout_shutdown_recd") == 0)
				fptun_timeouts_addr.sctp[SCTP_CONNTRACK_SHUTDOWN_RECD] = (int *)ctl->data;
			else if (strcmp(ctl->procname, "nf_conntrack_sctp_timeout_shutdown_ack_sent") == 0)
				fptun_timeouts_addr.sctp[SCTP_CONNTRACK_SHUTDOWN_ACK_SENT] = (int *)ctl->data;
			ctl++;
		}
		fptun_timeouts_addr.sctp_initialized = 1;
		break;

	default:
		break;
	}

	return 0;
}


static unsigned int fptun_timeouts[TCP_CONNTRACK_MAX];

#define RESET_TIMEOUT_VALUES()				\
	do {						\
		int i;					\
		for (i = 0; i < TCP_CONNTRACK_MAX; i++)	\
			fptun_timeouts[i] = UINT_MAX;	\
	} while (0)
#define SET_TIMEOUT_VALUE(proto, state)							\
	do {										\
		if (likely(fptun_timeouts_addr.proto[state] != NULL))			\
			fptun_timeouts[state] = *fptun_timeouts_addr.proto[state];	\
	} while (0)

static unsigned int *
fptun_nf_ct_timeout_lookup(struct net *net, struct nf_conn *ct, struct nf_conntrack_l4proto *proto)
{
	int ret;

	switch (proto->l4proto) {
	case IPPROTO_TCP:
		if (!fptun_timeouts_addr.tcp_initialized) {
			ret = fptun_init_timeouts_addr(net, proto);
			if (ret != 0)
				return NULL;
		}
		RESET_TIMEOUT_VALUES();
		SET_TIMEOUT_VALUE(tcp, TCP_CONNTRACK_SYN_SENT);
		SET_TIMEOUT_VALUE(tcp, TCP_CONNTRACK_SYN_RECV);
		SET_TIMEOUT_VALUE(tcp, TCP_CONNTRACK_ESTABLISHED);
		SET_TIMEOUT_VALUE(tcp, TCP_CONNTRACK_FIN_WAIT);
		SET_TIMEOUT_VALUE(tcp, TCP_CONNTRACK_CLOSE_WAIT);
		SET_TIMEOUT_VALUE(tcp, TCP_CONNTRACK_LAST_ACK);
		SET_TIMEOUT_VALUE(tcp, TCP_CONNTRACK_TIME_WAIT);
		SET_TIMEOUT_VALUE(tcp, TCP_CONNTRACK_CLOSE);
		break;

	case IPPROTO_UDP:
		if (!fptun_timeouts_addr.udp_initialized) {
			ret = fptun_init_timeouts_addr(net, proto);
			if (ret != 0)
				return NULL;
		}
		RESET_TIMEOUT_VALUES();
		SET_TIMEOUT_VALUE(udp, UDP_CT_UNREPLIED);
		SET_TIMEOUT_VALUE(udp, UDP_CT_REPLIED);
		break;

	case IPPROTO_SCTP:
		if (!fptun_timeouts_addr.sctp_initialized) {
			ret = fptun_init_timeouts_addr(net, proto);
			if (ret != 0)
				return NULL;
		}
		RESET_TIMEOUT_VALUES();
		SET_TIMEOUT_VALUE(sctp, SCTP_CONNTRACK_CLOSED);
		SET_TIMEOUT_VALUE(sctp, SCTP_CONNTRACK_COOKIE_WAIT);
		SET_TIMEOUT_VALUE(sctp, SCTP_CONNTRACK_COOKIE_ECHOED);
		SET_TIMEOUT_VALUE(sctp, SCTP_CONNTRACK_ESTABLISHED);
		SET_TIMEOUT_VALUE(sctp, SCTP_CONNTRACK_SHUTDOWN_SENT);
		SET_TIMEOUT_VALUE(sctp, SCTP_CONNTRACK_SHUTDOWN_RECD);
		SET_TIMEOUT_VALUE(sctp, SCTP_CONNTRACK_SHUTDOWN_ACK_SENT);
		break;

	case IPPROTO_GRE:
		memset(&fptun_timeouts, 0, sizeof(fptun_timeouts));
/* These are hard coded constants copied from net/netfilter/nf_conntrack_proto_gre.c */
#define GRE_TIMEOUT		(30 * HZ)
#define GRE_STREAM_TIMEOUT	(180 * HZ)
		fptun_timeouts[GRE_CT_UNREPLIED] = GRE_TIMEOUT;
		fptun_timeouts[GRE_CT_REPLIED] = GRE_STREAM_TIMEOUT;
		break;

	default:
		return NULL;
	}

	return fptun_timeouts;
}
#endif /* CONFIG_SYSCTL */


static void
fptun_nf_conntrack_update_timeout(struct net *net, const struct sk_buff *skb,
				  const struct nf_conntrack_tuple *tuple)
{
	struct nf_conn *ct;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_l4proto *proto;
	unsigned int timeout, *timeouts;

	if (nf_ct_timeout_lookup_p == NULL)
		return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, tuple);
#else
	h = nf_conntrack_find_get(net, tuple);
#endif
	if (h == NULL)
		return;

	ct = nf_ct_tuplehash_to_ctrack(h);

#ifdef CONFIG_NF_CONNTRACK_UID
	if (test_bit(IPS_STOPPED_BIT, &ct->status))
		goto release_ct;
#endif

	if (nf_ct_protonum(ct) != IPPROTO_TCP &&
	    nf_ct_protonum(ct) != IPPROTO_UDP &&
	    nf_ct_protonum(ct) != IPPROTO_SCTP &&
	    nf_ct_protonum(ct) != IPPROTO_GRE)
		goto release_ct;

	proto = __nf_ct_l4proto_find(nf_ct_l3num(ct), nf_ct_protonum(ct));
	if (proto == NULL)
		goto release_ct;

	timeouts = (*nf_ct_timeout_lookup_p)(net, ct, proto);
	if (timeouts == NULL)
		goto release_ct;

	switch (nf_ct_protonum(ct)) {
	case IPPROTO_TCP: {
		enum tcp_conntrack state;

		spin_lock_bh(&ct->lock);
		state = ct->proto.tcp.state;
		spin_unlock_bh(&ct->lock);

		/* In some case the state is not associated with a timer,
		 * we need a dummy value to keep the session.
		 */
		timeout = timeouts[state];
		if (unlikely(timeout == 0))
			ct->timeout.expires = 60 * HZ;
		break;
	}
	case IPPROTO_UDP:
		if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status))
			timeout = timeouts[UDP_CT_REPLIED];
		else
			timeout = timeouts[UDP_CT_UNREPLIED];
		break;
	case IPPROTO_SCTP:
		/* XXX: Why no lock on "ct->proto.sctp.state" here??? */
		timeout = timeouts[ct->proto.sctp.state];
		break;
	case IPPROTO_GRE:
		if (ct->status & IPS_SEEN_REPLY)
			timeout = timeouts[GRE_CT_REPLIED];
		else
			timeout = timeouts[GRE_CT_UNREPLIED];
		break;
	default:
		goto release_ct;
	}

	if (unlikely(timeout == UINT_MAX))
		goto release_ct;

	nf_ct_refresh(ct, skb, timeout);
release_ct:
	nf_ct_put(ct);
}
#endif /* MCORE_NF_CT */


static int fptun_handle_hitflags(struct sk_buff *skb)
{
	struct fphitflagshdr *fphfhdr;
	uint32_t count, i;

	if (!pskb_may_pull(skb, sizeof(struct fphitflagshdr))) {
		TRACE_FPTUN("Unable to pull hitflags header");
		return -EINVAL;
	}
	fphfhdr = (struct fphitflagshdr *)skb_network_header(skb);

	count = ntohl(fphfhdr->count);

	switch (fphfhdr->type) {
	case HF_ARP:
	{
		struct net_device *nh_dev;
		struct fphitflagsarp *entry;

		if (count > HF_MAX_SENT_DFLT_ARP) {
			TRACE_FPTUN("Error too much ARP hitflags entries");
			return -EINVAL;
		}

		if (!pskb_may_pull(skb, sizeof(struct fphitflagshdr)
					+ count * sizeof(struct fphitflagsarp))) {
			TRACE_FPTUN("Unable to pull ARP hitflags entries");
			return -EINVAL;
		}

		entry = (struct fphitflagsarp *)(fphfhdr + 1);

		for (i = 0; i < count; i++) {
			nh_dev = dev_get_by_ifuid(entry->ifuid);
			if (nh_dev) {
				fptun_neigh_activate(&entry->ip_addr,
				                    &arp_tbl, nh_dev, 0);
				dev_put (nh_dev);
			}
			entry++;
		}
		break;
	}
#if defined(CONFIG_MCORE_IPV6) && (defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE))
	case HF_NDP:
	{
		struct net_device *nh_dev;
		struct fphitflagsndp *entry;

		if (count > HF_MAX_SENT_DFLT_NDP) {
			TRACE_FPTUN("Error too much NDP hitflags entries");
			return -EINVAL;
		}

		if (!pskb_may_pull(skb, sizeof(struct fphitflagshdr)
					+ count * sizeof(struct fphitflagsndp))) {
			TRACE_FPTUN("Unable to pull NDP hitflags entries");
			return -EINVAL;
		}

		entry = (struct fphitflagsndp *)(fphfhdr + 1);

		for (i = 0; i < count; i++) {
			nh_dev = dev_get_by_ifuid(entry->ifuid);
			if (nh_dev) {
				fptun_neigh_activate(&entry->ip6_addr,
				                    fptun_nd_tbl, nh_dev, 0);
				dev_put (nh_dev);
			}
			entry++;
		}
		break;
	}
#endif
#ifdef CONFIG_MCORE_NF_CT
	case HF_CT:
	{
		struct fphitflagsentry *entry;
		struct nf_conntrack_tuple tuple;
		struct net *net;

		if (count > HF_MAX_SENT_DFLT_CT) {
			TRACE_FPTUN("Error too much CT hitflags entries");
			return -EINVAL;
		}

		if (!pskb_may_pull(skb, sizeof(struct fphitflagshdr)
					+ count * sizeof(struct fphitflagsentry))) {
			TRACE_FPTUN("Unable to pull CT hitflags entries");
			return -EINVAL;
		}

		entry = (struct fphitflagsentry *)(fphfhdr + 1);
		memset(&tuple, 0, sizeof(struct nf_conntrack_tuple));

		for (i = 0; i < count; i++) {
			tuple.src.u3.ip = entry->src;
			tuple.dst.u3.ip = entry->dst;
			tuple.src.l3num = AF_INET;
			tuple.src.u.tcp.port = entry->sport;
			tuple.dst.u.tcp.port = entry->dport;
			tuple.dst.protonum = entry->proto;
#ifdef CONFIG_NF_CONNTRACK_VRFID
			tuple.dst.vrfid = (u_int32_t)entry->vrfid;
#endif
#if defined(USE_VRF_NETNS)
			net = vrf_lookup_by_vrfid((u_int32_t)entry->vrfid);
#else
			net = &init_net;
#endif
			tuple.dst.dir = entry->dir;
			if (net)
				fptun_nf_conntrack_update_timeout(net, skb, &tuple);
			else
				printk(KERN_ERR "FPTUN %s: invalid vrfid=%u, cannot update ct timeout\n",
				       __FUNCTION__, (u_int32_t)entry->vrfid);
			entry++;
		}
		break;
	}
#endif /* CONFIG_MCORE_NF_CT */

#ifdef CONFIG_MCORE_NF6_CT
	case HF_CT6:
	{
		struct fphitflags6entry *entry;
		struct nf_conntrack_tuple tuple;
		struct net *net;

		if (count > HF_MAX_SENT_DFLT_CT6) {
			TRACE_FPTUN("Error too much CT6 hitflags entries");
			return -EINVAL;
		}

		if (!pskb_may_pull(skb, sizeof(struct fphitflagshdr)
					+ count * sizeof(struct fphitflags6entry))) {
			TRACE_FPTUN("Unable to pull CT6 hitflags entries");
			return -EINVAL;
		}

		entry = (struct fphitflags6entry *)(fphfhdr + 1);
		memset(&tuple, 0, sizeof(struct nf_conntrack_tuple));

		for (i = 0; i < count; i++) {
			memcpy(&tuple.src.u3.in6, &entry->src, sizeof(struct in6_addr));
			memcpy(&tuple.dst.u3.in6, &entry->dst, sizeof(struct in6_addr));
			tuple.src.l3num = AF_INET6;
			tuple.src.u.tcp.port = entry->sport;
			tuple.dst.u.tcp.port = entry->dport;
			tuple.dst.protonum = entry->proto;
#ifdef CONFIG_NF_CONNTRACK_VRFID
			tuple.dst.vrfid = (u_int32_t)entry->vrfid;
#endif
#if defined(USE_VRF_NETNS)
			net = vrf_lookup_by_vrfid((u_int32_t)entry->vrfid);
#else
			net = &init_net;
#endif
			tuple.dst.dir = entry->dir;
			if (net)
				fptun_nf_conntrack_update_timeout(net, skb, &tuple);
			else
				printk(KERN_ERR "FPTUN %s: invalid vrfid=%u, cannot update ct timeout\n",
				       __FUNCTION__, (u_int32_t)entry->vrfid);
			entry++;
		}
		break;
	}
#endif /* CONFIG_MCORE_NF6_CT */
	default:
		i = 0;
		TRACE_FPTUN("Type (%u) not supported", fphfhdr->type);
		return -EINVAL;
	}

	return 0;
}

static int (*vnb_exception_input_p)(struct sk_buff *skb) = NULL;

static int fptun_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *netdev)
{
	struct fptunhdr *fptunhdr;
	struct net_device *vdev = NULL;
#ifndef CONFIG_NET_VRF
	struct net *net = &init_net;
#endif
	uint8_t  fptun_cmd;
	uint16_t vrfid;
	uint16_t proto;
	uint32_t ifuid;
	int ret = 0;
	uint8_t mtags;
	uint32_t vif_ifuid = 0;

	if (!pskb_may_pull(skb, FPTUN_HLEN))
		SENDERROR("Unable to pull FPTUN header");

	fptunhdr = (struct fptunhdr *)skb_network_header(skb);
	if (unlikely(fptunhdr->fptun_version != FPTUN_VERSION)) {
		TRACE_FPTUN("FPTUN invalid version: %u instead of %u",
			fptunhdr->fptun_version, FPTUN_VERSION);
		goto error;
	}

	fptun_cmd = fptunhdr->fptun_cmd;
	if ((fptun_debug_level == 1 && skb->dev->ifindex != 1) ||
	    fptun_debug_level >= 2 ) {
		/* fpsd uses lo and sends a lot of packets: display this trace
		 * only when fptun_debug_level >= 2.
		 * Note that hitflagsd also uses lo.
		 */
		TRACE_FPTUN("Received a packet from the fast path on port %s",
			    skb->dev->name);
	}
	printk_buf(skb->data, skb->len);

#ifdef CONFIG_MCORE_FPTUN_INTERFACE_WHITE_LIST
	/* check if input dev is valid, it must be in white list */
	if (get_fptun_iface_node_by_dev(skb->dev) == NULL) {
		TRACE_FPTUN("The port %s is not in interface white list, drop packet", skb->dev->name);
		snprintf(last_filtered_packet_indev, sizeof(last_filtered_packet_indev), "%s", skb->dev->name);
		fptun_inc_dropped_stats();
		goto error;
	}
#endif

	ifuid  = fptunhdr->fptun_ifuid;
	vrfid     = ntohs(fptunhdr->fptun_vrfid);
#ifdef CONFIG_NET_VRF
	/* Ensure that skb->dev is in the right vrf. */
	if (vrfid != dev_vrfid(skb->dev))
		skb->dev = per_vrf(dev_net(skb->dev)->loopback_dev, vrfid);
	skb_set_vrfid(skb, vrfid);
#elif defined(USE_VRF_NETNS)
	net = vrf_lookup_by_vrfid(vrfid);
	if (net == NULL) {
		TRACE_FPTUN("Unknown vrfid (%d)", vrfid);
		goto error;
	}
	/* Ensure that skb->dev is in the right netns. */
	if (net != dev_net(skb->dev))
		skb->dev = net->loopback_dev;
#else
	/* No VR support: vrfid must be 0 */
	if (vrfid != 0) {
		TRACE_FPTUN("Unsupported vrfid (%d)", vrfid);
		goto error;
	}
#endif
	proto     = fptunhdr->fptun_proto;
	mtags     = fptunhdr->fptun_mtags;


	__skb_pull(skb, FPTUN_HLEN);
	skb_reset_network_header(skb);
	skb_orphan(skb);

	fptun_inc_stats(fptunhdr);

	if (mtags) {
		struct fpmtaghdr *mtag;
#ifdef CONFIG_NET_SKBUFF_SKTAG_SIZE
		struct cmsghdr *cmsg;
		struct in_taginfo *iti = NULL;
		struct msghdr msg = {
			.msg_control = skb->sktag,
			.msg_controllen = sizeof(skb->sktag)
		};
#endif

		if (!pskb_may_pull(skb, mtags*sizeof(struct fpmtaghdr)))
			SENDERROR("Unable to pull MTAG header");
		mtag = (struct fpmtaghdr *)skb_network_header(skb);
		__skb_pull(skb, mtags*sizeof(struct fpmtaghdr));
		skb_reset_network_header(skb);

#ifdef CONFIG_NET_SKBUFF_SKTAG_SIZE
		cmsg = CMSG_FIRSTHDR(&msg);
		if (!CMSG_OK(&msg, cmsg)
			&& (CMSG_LEN(mtags*sizeof(struct in_taginfo)) <= msg.msg_controllen))
		{
			memset (skb->sktag, 0, sizeof(skb->sktag));
			cmsg->cmsg_len = CMSG_LEN(mtags*sizeof(struct in_taginfo));
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type  = IP_TAGINFO;
			iti = (struct in_taginfo *)CMSG_DATA(cmsg);
#endif
			while (mtags--) {
				if (!strcmp(mtag->fpmtag_name, "nfm"))
					skb->mark = ntohl(mtag->fpmtag_data);
				else if (!strcmp(mtag->fpmtag_name, "vif4") ||
					 !strcmp(mtag->fpmtag_name, "vif6"))
					vif_ifuid = mtag->fpmtag_data;
#ifdef CONFIG_NET_SKBUFF_SKTAG_SIZE
				else {
					memcpy(iti->iti_name, mtag->fpmtag_name, sizeof(iti->iti_name));
					iti->iti_tag = mtag->fpmtag_data;
					iti++;
				}
#endif
				mtag++;
			}
#ifdef CONFIG_NET_SKBUFF_SKTAG_SIZE
		}
#endif
	}

	/* Get ECMP nexthop infos for next hop selection during route lookup */
	if ((fptunhdr->fptun_exc_class & FPTUN_EXC_CLASS_PRIO_MASK) ==
	    FPTUN_EXC_ECMP_NDISC_NEEDED) {
		struct fpecmphdr *ecmphdr;
		struct net_device *nh_dev = NULL;

		if (!pskb_may_pull(skb, sizeof(struct fpecmphdr)))
			SENDERROR("Unable to pull ECMP header");
		ecmphdr = (struct fpecmphdr *)skb_network_header(skb);

		if (ecmphdr->ip_v == FPECMP_IPV4) {
			__skb_pull(skb, sizeof(struct fpecmphdr));
			skb_reset_network_header(skb);

			nh_dev = dev_get_by_ifuid(ecmphdr->ifuid);
			if (nh_dev)
				fptun_neigh_activate(&ecmphdr->ip_nexthop,
				                     &arp_tbl, nh_dev, 1);
		} else {
			struct fpecmp6hdr *ecmp6hdr;

			if (!pskb_may_pull(skb, sizeof(struct fpecmp6hdr)))
				SENDERROR("Unable to pull ECMP6 header");
			ecmp6hdr = (struct fpecmp6hdr *)skb_network_header(skb);
			__skb_pull(skb, sizeof(struct fpecmp6hdr));
			skb_reset_network_header(skb);

			nh_dev = dev_get_by_ifuid(ecmp6hdr->ifuid);
			if (nh_dev)
				fptun_neigh_activate(ecmp6hdr->ip6_nexthop,
				                     fptun_nd_tbl, nh_dev, 1);
		}
		if (nh_dev)
			dev_put(nh_dev);
	}

	/* skb is cloned by AF_PACKET if tcpdump is running */
	skb = skb_unshare(skb, GFP_ATOMIC);
	if (!skb)
		goto error;

	switch (fptun_cmd) {
	case FPTUN_IPV4_FWD_EXCEPT:
	{
		struct iphdr *iph;

		TRACE_FPTUN("%s: FPTUN_IPV4_FWD_EXCEPT", __FUNCTION__);

		align_skb_data(skb, 0, 0);
		vdev = dev_get_by_ifuid(ifuid);
		if (vdev == NULL)
			SENDERROR("Unknown interface");

		skb_dst_set(skb, NULL);
		skb->protocol = htons(ETH_P_IP);
		skb->dev = vdev;

		/* sanity checks from ip_rcv */
		if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
			SENDERROR("Unable to share IPv4 skb");

		if (!pskb_may_pull(skb, sizeof(struct iphdr)))
			SENDERROR("Unable to pull IPv4 header");

		iph = ip_hdr(skb);

		if (iph->ihl < 5 || iph->version != 4)
			SENDERROR("wrong IPv4 header");

		ret = ip_route_input(skb, iph->daddr, iph->saddr, iph->tos,
				vdev);
		if (unlikely(ret)) {
			if (ret == -EHOSTUNREACH)
				IP_INC_STATS_BH(dev_net(skb->dev), IPSTATS_MIB_INADDRERRORS);
			SENDERROR("host unreachable");
		}
		ret = dst_input(skb);

		goto out;
	}

	case FPTUN_IPV4_IPSECDONE_OUTPUT_EXCEPT:
	case FPTUN_IPV4_OUTPUT_EXCEPT:
	{
		struct iphdr *iph;
		const char *cmdname;
		int ipsec_done;

		if (fptun_cmd == FPTUN_IPV4_IPSECDONE_OUTPUT_EXCEPT) {
			ipsec_done = 1;
			cmdname = "FPTUN_IPV4_IPSECDONE_OUTPUT_EXCEPT";
		} else {
			ipsec_done = 0;
			cmdname = "FPTUN_IPV4_OUTPUT_EXCEPT";
		}

		TRACE_FPTUN("%s: %s", __FUNCTION__, cmdname);

		skb_dst_set(skb, NULL);
		skb->protocol = htons(ETH_P_IP);

		/* sanity checks from ip_rcv */
		if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
			SENDERROR("Unable to share IPv4 skb");

		if (!pskb_may_pull(skb, sizeof(struct iphdr)))
			SENDERROR("Unable to pull IPv4 header");

		iph = ip_hdr(skb);

		if (iph->ihl < 5 || iph->version != 4)
			SENDERROR("wrong IPv4 header");

		if (fptun_ip_route(skb, ipsec_done))
			SENDERROR("can't route IPv4 packet");

		/* Change in oif may mean change in hh_len. */
		if (skb_cow(skb, skb_dst(skb)->dev->hard_header_len))
			SENDERROR("skb_cow");

		align_skb_data(skb, 0, 0);
		if (ipsec_done)
			ret = ip_local_out(skb);
		else
			ret = dst_output(skb);
		goto out;
	}

	case FPTUN_IPV6_FWD_EXCEPT:
	{
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		struct ipv6hdr *hdr;

		TRACE_FPTUN("%s: FPTUN_IPV6_FWD_EXCEPT", __FUNCTION__);

		vdev = dev_get_by_ifuid(ifuid);
		if (vdev == NULL)
			SENDERROR("Unknown interface");

		skb_dst_set(skb, NULL);
		skb->protocol = htons(ETH_P_IPV6);
		skb->dev = vdev;

		/* sanity checks from ipv6_rcv */
		if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
			SENDERROR("Unable to share IPv6 skb");

		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
			SENDERROR("IPv6 packet too short");

		align_skb_data(skb, 0, 0);
		hdr = ipv6_hdr(skb);

		if (hdr->version != 6)
			SENDERROR("wrong IPv6 header");

		((struct inet6_skb_parm *)skb->cb)->iif = dev->ifindex;

		fptun_ip6_route_input(skb);
		ret = fptun_ip6_forward(skb);
		goto out;
#else
		TRACE_FPTUN("FPTUN_IPV6_OUTPUT_EXCEPT not supported");
		goto error;
#endif
	}

	case FPTUN_IPV6_IPSECDONE_OUTPUT_EXCEPT:
	case FPTUN_IPV6_OUTPUT_EXCEPT:
	{
		const char *cmdname;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		struct ipv6hdr *hdr;
#endif
		int ipsec_done;

		if (fptun_cmd == FPTUN_IPV6_IPSECDONE_OUTPUT_EXCEPT) {
			ipsec_done = 1;
			cmdname = "FPTUN_IPV6_IPSECDONE_OUTPUT_EXCEPT";
		} else {
			ipsec_done = 0;
			cmdname = "FPTUN_IPV6_OUTPUT_EXCEPT";
		}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		TRACE_FPTUN("%s: %s", __FUNCTION__, cmdname);

		skb_dst_set(skb, NULL);
		skb->protocol = htons(ETH_P_IPV6);

		/* sanity checks from ipv6_rcv */
		if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
			SENDERROR("Unable to share IPv6 skb");

		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
			SENDERROR("IPv6 packet too short");

		align_skb_data(skb, 0, 0);
		hdr = ipv6_hdr(skb);

		if (hdr->version != 6)
			SENDERROR("wrong IPv6 header");

		((struct inet6_skb_parm *)skb->cb)->iif = dev->ifindex;
		((struct inet6_skb_parm *)skb->cb)->nhoff = offsetof(struct ipv6hdr, nexthdr);
		skb_set_transport_header(skb, sizeof(struct ipv6hdr));

		if (fptun_ip6_route(skb, ipsec_done))
			SENDERROR("can't route IPv6 packet");

		/* Change in oif may mean change in hh_len. */
		if (skb_cow(skb, skb_dst(skb)->dev->hard_header_len))
			SENDERROR("skb_cow");

		if (ipsec_done)
			ret = ip6_local_out(skb);
		else
			ret = dst_output(skb);
		goto out;
#else /* CONFIG_IPV6 */
		TRACE_FPTUN("%s: %s not supported", cmdname,
			fptun_cmd == FPTUN_IPV6_IPSECDONE_OUTPUT_EXCEPT ?
			"FPTUN_IPV6_IPSECDONE_OUTPUT_EXCEPT" :
			"FPTUN_IPV6_OUTPUT_EXCEPT");
		goto error;
#endif /* CONFIG_IPV6 */
	}

	case FPTUN_IPV4_INPUT_EXCEPT:
	{
		struct iphdr *iph;
		struct ethhdr *eth;
		int err;

		TRACE_FPTUN("%s: FPTUN_IPV4_INPUT_EXCEPT", __FUNCTION__);

		vdev = dev_get_by_ifuid(ifuid);
		if (vdev == NULL)
			SENDERROR("Unknown interface");

		if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
			TRACE_FPTUN("%s: could not clone skb", __FUNCTION__);
			IP_INC_STATS_BH(dev_net(skb->dev), IPSTATS_MIB_INDISCARDS);
			goto out;
		}

		if (!pskb_may_pull(skb, sizeof(struct iphdr))) {
			TRACE_FPTUN("%s: IP packet too short", __FUNCTION__);
			IP_INC_STATS_BH(dev_net(skb->dev), IPSTATS_MIB_INHDRERRORS);
			goto error;
		}

		align_skb_data(skb, 0, ETH_HLEN);
		iph = ip_hdr(skb);

		/* Starting from 3.11, transport_header is not set in
		 * ip_local_deliver_finish anymore, so set it here.
		 * Note that the patch has been backported in 3.10.4 (and thus
		 * RHEL7).
		 */
#ifdef RHEL_RELEASE
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,0)
		skb->transport_header = skb->network_header + iph->ihl*4;
#endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,4)
		skb->transport_header = skb->network_header + iph->ihl*4;
#endif

		if (iph->ihl < 5 || iph->version != 4) {
			TRACE_FPTUN("%s: invalid IP packet", __FUNCTION__);
			IP_INC_STATS_BH(dev_net(skb->dev), IPSTATS_MIB_INHDRERRORS);
			goto error;
		}

		/* Prepare to inject via loopback interface */
		skb->pkt_type = PACKET_HOST;
		skb->protocol = htons(ETH_P_IP);

		skb->dev = vdev;
		err = ip_route_input(skb, iph->daddr, iph->saddr, iph->tos,
					 vdev);
		if (unlikely(err)) {
			TRACE_FPTUN("%s: host unreachable", __FUNCTION__);
			if (err == -EHOSTUNREACH)
				IP_INC_STATS_BH(dev_net(skb->dev), IPSTATS_MIB_INHDRERRORS);
			goto error; 
		}

		/* disable IPsec inbound policy check */
		skb_dst(skb)->flags |= DST_NOPOLICY;

		if (vdev->type == ARPHRD_ETHER) {
			/* build a pseudo ethernet header */
			skb_set_mac_header(skb, -ETH_HLEN);
			eth = eth_hdr(skb);
			memset(eth->h_dest, 0, ETH_ALEN*2);
			eth->h_proto = skb->protocol;
		}

		TRACE_FPTUN("injecting packet via %s ethertype %04x",
				vdev->name, ntohs(skb->protocol));
		printk_buf(skb->data, skb->len);

		IP_UPD_PO_STATS_BH(dev_net(dev), IPSTATS_MIB_IN, skb->len);
		memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
		NF_HOOK(PF_INET, NF_INET_PRE_ROUTING, skb, vdev, NULL, fptun_ipv4_input);
		goto out;
	}

	case FPTUN_IPV6_INPUT_EXCEPT:
	{
		struct ipv6hdr *hdr;
		struct ethhdr *eth;

		TRACE_FPTUN("%s: FPTUN_IPV6_INPUT_EXCEPT", __FUNCTION__);

		vdev = dev_get_by_ifuid(ifuid);
		if (vdev == NULL)
			SENDERROR("Unknown interface");

		if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
			TRACE_FPTUN("%s: could not clone skb", __FUNCTION__);
			goto out;
		}

		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr))) {
			TRACE_FPTUN("%s: IPv6 packet too short", __FUNCTION__);
			goto error;
		}

		align_skb_data(skb, 0, ETH_HLEN);
		hdr = ipv6_hdr(skb);

		if (hdr->version != 6) {
			TRACE_FPTUN("%s: invalid IPv6 packet", __FUNCTION__);
			goto out;
		}

		/* Prepare to inject via loopback interface */
		skb->pkt_type = PACKET_HOST;
		skb->protocol = htons(ETH_P_IPV6);

		skb->dev = vdev;
		fptun_ip6_route_input(skb);

		/* disable IPsec inbound policy check */
		skb_dst(skb)->flags |= DST_NOPOLICY;

		if (vdev->type == ARPHRD_ETHER) {
			/* build a pseudo ethernet header */
			skb_set_mac_header(skb, -ETH_HLEN);
			eth = eth_hdr(skb);
			memset(eth->h_dest, 0, ETH_ALEN*2);
			eth->h_proto = skb->protocol;
		}

		TRACE_FPTUN("injecting packet via %s ethertype %04x",
				vdev->name, ntohs(skb->protocol));
		printk_buf(skb->data, skb->len);

		netif_rx(skb);

		goto out;
	}

	case FPTUN_ETH_INPUT_EXCEPT:
	case FPTUN_ETH_NOVNB_INPUT_EXCEPT:
	{
		TRACE_FPTUN("%s: %s", __FUNCTION__,
				(fptun_cmd == FPTUN_ETH_INPUT_EXCEPT) ?
				"FPTUN_ETH_INPUT_EXCEPT" :
				"FPTUN_ETH_NOVNB_INPUT_EXCEPT");

		vdev = dev_get_by_ifuid(ifuid);
		if (vdev == NULL)
			SENDERROR("Unknown interface");

		if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
			SENDERROR("Unable to share skb");

		if (!pskb_may_pull(skb, ETH_HLEN))
			SENDERROR("Unable to pull ethernet header");

		TRACE_FPTUN("packet is for ifuid 0x%08x", ntohl(ifuid));

		/* Restore default packet type. */
		skb->pkt_type = PACKET_HOST;
		skb->protocol = eth_type_trans(skb, vdev);
		skb->dev = vdev;

		TRACE_FPTUN("injecting packet via %s ethertype %04x",
				vdev->name, ntohs(skb->protocol));

		align_skb_data(skb, 0, ETH_HLEN);
		printk_buf(skb->data, skb->len);
		if (fptun_cmd == FPTUN_ETH_INPUT_EXCEPT)
			netif_rx(skb);
		else {
			VNB_CB(skb).vnb_magic = VNB_MAGIC_SKIP;
			netif_receive_skb(skb);
		}
		goto out;
	}

	case FPTUN_OUTPUT_EXCEPT:
	{
		TRACE_FPTUN("%s: FPTUN_OUTPUT_EXCEPT", __FUNCTION__);

		vdev = dev_get_by_ifuid(ifuid);
		if (vdev == NULL)
			SENDERROR("Unknown interface");

		/* The ifuid received is the ifuid for the sending interface */
		skb->dev = vdev;

		/* Send packet */
		align_skb_data(skb, 0, 0);
		ret = dev_queue_xmit(skb);
		goto out;
	}

	case FPTUN_IFACE_INPUT_EXCEPT:
	{
		TRACE_FPTUN("%s: FPTUN_IP_INPUT_EXCEPT", __FUNCTION__);

		vdev = dev_get_by_ifuid(ifuid);
		if (vdev == NULL)
			SENDERROR("Unknown interface");

		if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
			SENDERROR("Unable to share skb");

		TRACE_FPTUN("packet is for ifuid 0x%08x", ntohl(ifuid));

		/* Restore default packet type. */
		skb->pkt_type = PACKET_HOST;
		skb->protocol = proto;
		skb->dev = vdev;

		TRACE_FPTUN("injecting packet via %s ethertype %04x",
				vdev->name, ntohs(skb->protocol));
		printk_buf(skb->data, skb->len);

		align_skb_data(skb, 0, ETH_HLEN);
		netif_rx(skb);
		goto out;
	}

	case FPTUN_LOOP_INPUT_EXCEPT:
	{

		struct ethhdr *eth;

		TRACE_FPTUN("%s: FPTUN_LOOP_INPUT_EXCEPT", __FUNCTION__);

		if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
			SENDERROR("Unable to share skb");

		TRACE_FPTUN("packet originated from ifuid 0x%08x", ntohl(ifuid));

		/* Restore default packet type. */
		skb->pkt_type = PACKET_HOST;
		skb->protocol = proto;

#ifdef CONFIG_NET_VRF
		skb->dev = vdev = per_vrf(dev_net(skb->dev)->loopback_dev,
					  vrfid);
#else
		skb->dev = vdev = net->loopback_dev;
#endif
		dev_hold(vdev);

		skb_set_mac_header(skb, -ETH_HLEN);
		eth = eth_hdr(skb);
		memset(eth->h_dest, 0, ETH_ALEN*2);
		eth->h_proto = proto;

		TRACE_FPTUN("injecting packet via %s ethertype %04x",
				vdev->name, ntohs(skb->protocol));
		printk_buf(skb->data, skb->len);

		align_skb_data(skb, 0, ETH_HLEN);
		netif_rx(skb);
		goto out;
 	}

#ifdef CONFIG_MCORE_TAP
	case FPTUN_TAP:
	{
		struct packet_type *ptype;

		TRACE_FPTUN("%s: FPTUN_TAP", __FUNCTION__);

		vdev = dev_get_by_ifuid(ifuid);
		if (vdev == NULL)
			SENDERROR("Unknown interface");

		if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
			SENDERROR("Unable to share skb");

		TRACE_FPTUN("packet is for ifuid 0x%08x", ntohl(ifuid));

		vdev->last_rx = jiffies;
		skb->pkt_type = PACKET_FASTROUTE;
		skb->protocol = proto;
		skb->dev = vdev;
		skb_reset_mac_header(skb);
		skb_reset_network_header(skb);

		/* 
		 * Loopback interfaces are expected to have an hardware 
		 * header, but FP * has removed it. Hence, we build a fake.
		 */
		if (vdev->type == ARPHRD_LOOPBACK)
			if (vdev->header_ops->create(skb, vdev, ntohs(proto), NULL, NULL, skb->len) < 0)
				goto error;

		if (proto == 0) {
			struct ethhdr *eth;

			if (!pskb_may_pull(skb, sizeof(struct ethhdr)))
				goto error;
			eth = eth_hdr(skb);
			skb->protocol = eth->h_proto;
			__skb_pull(skb, ETH_HLEN);
			skb_set_mac_header(skb, -ETH_HLEN);
			skb_reset_network_header(skb);
		}

		printk_buf(skb->data, skb->len);

		rcu_read_lock();
		list_for_each_entry_rcu(ptype, fptun_ptype_all, list)
			if (!ptype->dev || ptype->dev == skb->dev) {
				atomic_inc(&skb->users);
				ptype->func(skb, skb->dev, ptype, skb->dev);
			}
		rcu_read_unlock();

		kfree_skb(skb);
		goto out;
	}
#endif

#ifdef CONFIG_MCORE_MULTICAST4
	case FPTUN_MULTICAST_EXCEPT:
	{
#if defined(CONFIG_IP_PIMSM_V1) || defined(CONFIG_IP_PIMSM_V2)
		struct net_device *out_dev = NULL;

		TRACE_FPTUN("%s: FPTUN_MULTICAST_EXCEPT", __FUNCTION__);

		vdev = dev_get_by_ifuid(ifuid);
		if (vdev == NULL)
			SENDERROR("Unknown interface");

		if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
			SENDERROR("Unable to share skb");

		if (!pskb_may_pull(skb, sizeof(struct iphdr)))
			SENDERROR("Unable to pull IPv4 header");

		TRACE_FPTUN("packet is for ifuid 0x%08x", ntohl(ifuid));

		vdev->last_rx = jiffies;
		skb->pkt_type = PACKET_MULTICAST;
		skb->protocol = proto;
		skb->dev = vdev;
		skb_reset_network_header(skb);

		printk_buf(skb->data, skb->len);

		out_dev = dev_get_by_ifuid(vif_ifuid);
		if (out_dev == NULL)
			SENDERROR("Unknown outgoing interface");

		if (out_dev->type != ARPHRD_PIMREG) {
			dev_put(out_dev);
			SENDERROR("mcast4: not a register iface");
		}

		/* In case of register iface, ndo_start_xmit will do a cache
		 * report to pim daemon.
		 */
		align_skb_data(skb, 0, 0);
		out_dev->netdev_ops->ndo_start_xmit(skb, out_dev);
		dev_put(out_dev);
		goto out;
#else
		SENDERROR("mcast4: CONFIG_IP_PIMSM_V[1|2] are not set");
#endif
	}
#endif

#ifdef CONFIG_MCORE_MULTICAST6
	case FPTUN_MULTICAST6_EXCEPT:
	{
#ifdef CONFIG_IPV6_PIMSM_V2
		struct net_device *out_dev = NULL;

		TRACE_FPTUN("%s: FPTUN_MULTICAST6_EXCEPT", __FUNCTION__);

		vdev = dev_get_by_ifuid(ifuid);
		if (vdev == NULL)
			SENDERROR("Unknown interface");

		if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
			SENDERROR("Unable to share skb");

		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
			SENDERROR("Unable to pull IPv6 header");

		TRACE_FPTUN("packet is for ifuid 0x%08x", ntohl(ifuid));

		vdev->last_rx = jiffies;
		skb->pkt_type = PACKET_MULTICAST;
		skb->protocol = proto;
		skb->dev = vdev;
		skb_reset_network_header(skb);

		printk_buf(skb->data, skb->len);

		out_dev = dev_get_by_ifuid(vif_ifuid);
		if (out_dev == NULL)
			SENDERROR("Unknown outgoing interface");

		if (out_dev->type != ARPHRD_PIMREG) {
			dev_put(out_dev);
			SENDERROR("mcast6: not a register iface");
		}

		/* In case of register iface, ndo_start_xmit will do a cache
		 * report to pim6 daemon.
		 */
		align_skb_data(skb, 0, 0);
		out_dev->netdev_ops->ndo_start_xmit(skb, out_dev);
		dev_put(out_dev);
		goto out;
#else
		SENDERROR("mcast6: CONFIG_IPV6_PIMSM_V2 is not set");
#endif
	}
#endif

	case FPTUN_HITFLAGS_SYNC:
	{
		TRACE_FPTUN("%s: FPTUN_HITFLAGS_SYNC", __FUNCTION__);

		ret = fptun_handle_hitflags(skb);
		kfree_skb(skb);
		goto out;
	}

	case FPTUN_RFPS_UPDATE:
	{
		if (fptun_debug_level >= 2) {
			/* Too noisy, fpsd sends a lot of this kind of packets:
			 * display this trace only when fptun_debug_level >= 2.
			 */
			TRACE_FPTUN("%s: FPTUN_RFPS_UPDATE", __FUNCTION__);
		}

		if (fptun_rfps_msg_hdlr_p != NULL){
			(*fptun_rfps_msg_hdlr_p)(skb);
		}
		kfree_skb(skb);
		goto out;
	}

	case FPTUN_VNB2VNB_FP_TO_LINUX_EXCEPT:
	{
		TRACE_FPTUN("%s: FPTUN_VNB2VNB_FP_TO_LINUX_EXCEPT",
		            __FUNCTION__);

		if (vnb_exception_input_p != NULL) {
			ret = (*vnb_exception_input_p)(skb);
		} else {
			TRACE_FPTUN("%s: NO ng_recv_exception handler\n",
			            __FUNCTION__);
			ret = EINVAL;
		}
		goto out;
	}

	default:
		TRACE_FPTUN("unknown fptun_cmd 0x%02x", (unsigned)fptun_cmd);
		break;
	} /* Switch */

error:
	kfree_skb(skb);
	ret = -1;
out:
	if (vdev)
		dev_put(vdev);
	return ret;
}

static struct packet_type fptun_packet_type = {
type:   __constant_htons(ETH_P_FPTUN),
func:   fptun_rcv,
af_packet_priv:   (void*) 1, /* XXX */
};

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
/*
 * Register then unregister a dummy family the time to get
 * the list and lookup for this potentially unexported nd_tbl.
 */
static u32 dummy_hash(__attribute__ ((unused)) const void *pkey,
                      __attribute__ ((unused)) const struct net_device *dev
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
		      , __attribute__ ((unused)) __u32 *hash_rnd
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
		      , __attribute__ ((unused)) __u32 hash_rnd
#endif
		     )
{ return 0; }

static int dummy_constructor(__attribute__ ((unused)) struct neighbour *neigh)
{ return 0; }

static void dummy_redo(__attribute__ ((unused)) struct sk_buff *skb)
{ return; }

static struct neigh_table dummy_tbl = {
	.family = AF_UNSPEC,
	.key_len =      4,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
	.entry_size =   sizeof(struct neighbour) + 4,
#endif
	.hash =         dummy_hash,
	.constructor =  dummy_constructor,
	.proxy_redo =   dummy_redo,
	.id =           "dummy_cache",
	.parms = {
		.tbl =                  &dummy_tbl,
#ifndef NEIGH_VAR_DATA_MAX
		.base_reachable_time =  30 * HZ,
		.retrans_time =         1 * HZ,
		.gc_staletime =         60 * HZ,
#else
		.data[NEIGH_VAR_BASE_REACHABLE_TIME] = 30 * HZ,
		.data[NEIGH_VAR_RETRANS_TIME] = 1 * HZ,
		.data[NEIGH_VAR_GC_STALETIME] = 60 * HZ,
#endif
		.reachable_time =       30 * HZ,
#ifndef NEIGH_VAR_DATA_MAX
		.delay_probe_time =     5 * HZ,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
		.queue_len =            3,
#else
		.queue_len_bytes =      64 * 1024,
#endif
		.ucast_probes =         3,
		.mcast_probes =         3,
		.anycast_delay =        1 * HZ,
		.proxy_delay =          (8 * HZ) / 10,
		.proxy_qlen =           64,
		.locktime =             1 * HZ,
#else
		.data[NEIGH_VAR_DELAY_PROBE_TIME] = 5 * HZ,
		.data[NEIGH_VAR_QUEUE_LEN_BYTES] = 64 * 1024,
		.data[NEIGH_VAR_UCAST_PROBES] = 3,
		.data[NEIGH_VAR_MCAST_PROBES] = 3,
		.data[NEIGH_VAR_ANYCAST_DELAY] = 1 * HZ,
		.data[NEIGH_VAR_PROXY_DELAY] = (8 * HZ) / 10,
		.data[NEIGH_VAR_PROXY_QLEN] = 64,
		.data[NEIGH_VAR_LOCKTIME] = 1 * HZ,
#endif
	},
	.gc_interval =  30 * HZ,
	.gc_thresh1 =   128,
	.gc_thresh2 =   512,
	.gc_thresh3 =   1024,
};

static struct neigh_table *fptun_lookup_nd_tbl(void)
{
	struct neigh_table *tmp;

	/* Initialize dummy_tlb to get the head of list */
	neigh_table_init(&dummy_tbl);

	for (tmp = &dummy_tbl; tmp ; tmp = tmp->next) {
		if (tmp->family == AF_INET6)
			break;
	}
	neigh_table_clear(&dummy_tbl);

	return tmp;
}
#endif

static int __init fptun_parse_params(void)
{
	if (bladeid == -1)
		printk(KERN_INFO "Starting FPTUN module in monoblade co-localized mode\n");
	else
		printk(KERN_INFO "Starting FPTUN module in distributed mode\n");

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
/* kallsyms_lookup_name is exported from 2.6.33,
 * but kallsyms_on_each_symbol() is present.
 * kallsyms_on_each_symbol() is using int type so
 * that we cannot return u_long address: we define
 * a structure to store the result addr.
 */
struct ksyms_type {
	const char *namebuf;
	unsigned long addr;
};

static int fptun_kallsyms_fn(void *data, const char *namebuf,
		struct module *module, unsigned long addr)
{
	struct ksyms_type *kdata = data;
	if (strcmp(kdata->namebuf, namebuf) == 0) {
		kdata->addr = addr;
		return 1;
	}

	return 0;
}

static void *fptun_get_sym(const char *name)
{
	struct ksyms_type data = { .namebuf = name, .addr = 0 };
	int ret;

	ret = kallsyms_on_each_symbol(fptun_kallsyms_fn, (void *)&data);
	if (ret)
		return (void *)data.addr;

	return NULL;
}
#else
static void *fptun_get_sym(const char *name)
{
	return (void *)kallsyms_lookup_name(name);
}
#endif

static int initialize_unexported_symbols(void)
{
#ifdef CONFIG_MCORE_TAP
	struct packet_type ptype;

	memset(&ptype, 0, sizeof(ptype));
	ptype.type = htons(ETH_P_ALL);
	/* just put a fake pointer to ensure that we will no be called */
	ptype.dev = (struct net_device *)-1;
	dev_add_pack(&ptype);
	fptun_ptype_all = ptype.list.next;
	/* The assumption is that no AF_PACKET sockets bound to all proto are
	 * opened when fptun is loaded, so we are the only one and because the
	 * list is doubly linked, we can check this assumption with the below
	 * test.
	 */
	if (fptun_ptype_all->next != &ptype.list) {
		/* There is already some AF_PACKET sockets, but we know that
		 * pack are always inserted after the head of the list. The
		 * probability that another pack has been inserted at the same
		 * time is very low, so let's use prev.
		 */
		fptun_ptype_all = ptype.list.prev;
		pr_info("%s: use prev for to get ptype_all\n", __func__);
	}
	dev_remove_pack(&ptype);
#endif
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	fptun_ip6_forward = fptun_get_sym("ip6_forward");
	if (fptun_ip6_forward == NULL)
		return -1;

	fptun_ip6_route_input = fptun_get_sym("ip6_route_input");
	if (fptun_ip6_route_input == NULL)
		return -1;

	fptun_nd_tbl = fptun_lookup_nd_tbl();
	if (fptun_nd_tbl == NULL)
		return -1;
#endif

	return 0;
}

static int __init fptun_init(void)
{
	struct proc_dir_entry *e;

	printk(KERN_INFO "FPTUN Module 1.1\n");

	if (fptun_parse_params())
		return -EINVAL;

	if (initialize_unexported_symbols() < 0) {
		printk(KERN_ERR "FPTUN: unable to find symbols");
		return -ENOTSUPP;
	}

	dev_add_pack(&fptun_packet_type);

	/* Create a directory to store our file */
	fptun_proc = proc_mkdir("fptun", init_net.proc_net);
	if (fptun_proc == NULL) {
		return -EIO;
	}
	/* Create a file to change the debug_level */
	e = proc_create("debug_level", S_IFREG | S_IRUGO | S_IWUSR,
			fptun_proc, &fptun_debug_fops);
	if (!e)
		goto remove_fptun;

	e = proc_create("stats", S_IFREG | S_IRUGO,
			fptun_proc, &fptun_stats_fops);
	if (!e)
		goto remove_debug_level;

#ifdef CONFIG_MCORE_FPTUN_INTERFACE_WHITE_LIST
	/* Create a file to add interface to white list  */
	e = proc_create("add_iface_to_whitelist", S_IFREG | S_IRUGO | S_IWUSR,
			fptun_proc, &fptun_add_iface_fops);
	if (!e)
		goto remove_stats;

	/* Create a file to delete interface from white list  */
	e = proc_create("del_iface_from_whitelist", S_IFREG | S_IRUGO | S_IWUSR,
			fptun_proc, &fptun_del_iface_fops);
	if (!e)
		goto remove_add_iface_to_whitelist;

	/* Create a file to show interface list  */
	e = proc_create("whitelist", S_IFREG | S_IRUGO,
			fptun_proc, &fptun_show_iface_fops);
	if (!e)
		goto remove_del_iface_from_whitelist;

	/* print input dev of last dropped packet by white list */
	e = proc_create("last_filtered_packet_indev", S_IFREG | S_IRUGO | S_IWUSR,
			fptun_proc, &fptun_show_indev_fops);
	if (!e)
		goto remove_whitelist;
	memset(last_filtered_packet_indev, '\0', IFNAMSIZ);
	register_netdevice_notifier(&fptun_netdev_notifier);
#endif

	vnb_exception_input_p = __symbol_get("ng_recv_exception");
	if (vnb_exception_input_p == NULL)
		printk("%s: no ng_recv_exception handler\n",
		       __func__);

#ifdef CONFIG_MCORE_NF_CT
	nf_ct_timeout_lookup_p = __symbol_get("nf_ct_timeout_lookup");
	if (nf_ct_timeout_lookup_p == NULL) {
		printk(KERN_WARNING "FPTUN: nf_ct_timeout_lookup() not available in kernel, "
#ifdef CONFIG_SYSCTL
		       "using fptun_nf_ct_timeout_lookup() instead.\n");
		nf_ct_timeout_lookup_p = &fptun_nf_ct_timeout_lookup;
		memset(&fptun_timeouts_addr, 0, sizeof(fptun_timeouts_addr));
#else
		       "since CONFIG_SYSCTL is not enabled, conntrack hitflags will not be updated.\n");
#endif
	}
#endif /* CONFIG_MCORE_NF_CT */

	return 0;
#ifdef CONFIG_MCORE_FPTUN_INTERFACE_WHITE_LIST
remove_whitelist:
	remove_proc_entry("whitelist", fptun_proc);
remove_del_iface_from_whitelist:
	remove_proc_entry("del_iface_from_whitelist", fptun_proc);
remove_add_iface_to_whitelist:
	remove_proc_entry("add_iface_to_whitelist", fptun_proc);
remove_stats:
	remove_proc_entry("stats", fptun_proc);
#endif
remove_debug_level:
	remove_proc_entry("debug_level", fptun_proc);
remove_fptun:
	remove_proc_entry("fptun", init_net.proc_net);
	return -EIO;
}

#ifdef MODULE
static void fptun_exit(void)
{
	printk(KERN_INFO "Unloading FPTUN Module 1.0\n");
	dev_remove_pack(&fptun_packet_type);
	if (fptun_proc) {
#ifdef CONFIG_MCORE_FPTUN_INTERFACE_WHITE_LIST
		remove_proc_entry("last_filtered_packet_indev", fptun_proc);
		remove_proc_entry("whitelist", fptun_proc);
		remove_proc_entry("del_iface_from_whitelist", fptun_proc);
		remove_proc_entry("add_iface_to_whitelist", fptun_proc);
#endif
		remove_proc_entry("stats", fptun_proc);
		remove_proc_entry("debug_level", fptun_proc);
		remove_proc_entry("fptun", init_net.proc_net);
	}

#ifdef CONFIG_MCORE_FPTUN_INTERFACE_WHITE_LIST
	unregister_netdevice_notifier(&fptun_netdev_notifier);
	/* free all nodes in white list */
	fptun_free_all_ifaces();
#endif

	if (vnb_exception_input_p)
		__symbol_put("ng_recv_exception");
#ifdef CONFIG_MCORE_NF_CT
	if (nf_ct_timeout_lookup_p &&
			nf_ct_timeout_lookup_p != &fptun_nf_ct_timeout_lookup)
		__symbol_put("nf_ct_timeout_lookup");
#endif

}
#endif

module_init(fptun_init);
module_exit(fptun_exit);

MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("Fast Path TUNneling driver");
MODULE_LICENSE("GPL");
