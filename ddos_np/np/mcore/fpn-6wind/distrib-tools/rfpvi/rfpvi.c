/* 
 * Copyright (C) 2007 6WIND, All rights reserved. 
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

/*
   rfpvi.c: a remote fpvi net driver

	The purpose of this driver is to exchange packets between a
    Control Plane and a Fast Path located on different machines

	A part of this driver is based on the dummy driver from:
			Nick Holloway, 27th May 1994
			Alan Cox, 30th May 1994

	The other part, from 6WIND fpvi module.
*/

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/list.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif
#include <net/dst.h>
#include <net/arp.h>
#include <net/xfrm.h>
#include <linux/ctype.h>

#include <ifuid.h>

#include "fptun.h"

#define RFPVI_NAME "rfpvi: "

#define RFPVI_PARAM_MAC     0
#define RFPVI_PARAM_FLAGS   1
#define RFPVI_PARAM_XFLAGS  2
#define RFPVI_PARAM_MTU     3
#define RFPVI_PARAM_BLADE   4
#define RFPVI_PARAM_CPBLADE 5
#define RFPVI_PARAM_MAX     6

struct rfpvi_if_param {
	int type;
	const char *keyword;
	int nval;
};

static struct rfpvi_if_param rfpvi_if_param_tab[] = {
	{ RFPVI_PARAM_MAC,     "mac",     1 },
	{ RFPVI_PARAM_FLAGS,   "flags",   1 },
	{ RFPVI_PARAM_XFLAGS,  "xflags",  1 },
	{ RFPVI_PARAM_MTU,     "mtu",     1 },
	{ RFPVI_PARAM_BLADE,   "blade",   1 },
	{ RFPVI_PARAM_CPBLADE, "cpblade", 1 },
	{ -1,   NULL,   -1 },
};

/*
 * /proc/sys/rfpvi is used to create/delete rfpvi interfaces
 * Add an interface by writing its name in /proc/sys/rfpvi/add_interface
 * Delete an interface by writing its name in /proc/sys/rfpvi/del_interface
 */
#ifdef CONFIG_SYSCTL
struct ctl_table_header *rfpvi_sysctl_header;
#endif

/*
 * struct rfpvi for a rfpvi interface
 * Each rfpvi interface contains a name and a pointer to a net_device
 * rfpvi interfaces in the system are managed in a list
 */
struct rfpvi {
	struct list_head rfpvi_list;
	struct net_device *rfpvi_dev;
	uint8_t fptun_cmd;
	uint8_t fptun_exc_class;
};
LIST_HEAD(rfpvi_ifaces);

/*
 * struct rfpvi_blade for a rfpvi blade
 * Each rfpvi blade contains an id for identifying remote 
 * blade, a pointer to the local net_device and peer mac address.
 * rfpvi blades in the system are managed in a list and protected
 * by read/write lock:rfpvi_blades_lock.
 */
struct rfpvi_blade {
	struct list_head rfpvi_blade_list;
	uint8_t blade_id;
	char peer_mac[MAX_ADDR_LEN];
	struct net_device *output_if;
};
LIST_HEAD(rfpvi_blades);
static DEFINE_RWLOCK(rfpvi_blades_lock);

static char * phys_mac = NULL;
static char * phys_ifname = NULL;
/* local blade id as well as fast path to which we send the packets destinated to remote fast paths */
static uint blade_id = 1;
module_param(phys_mac, charp, 0);
module_param(phys_ifname, charp, 0);
module_param(blade_id, uint, 0);
MODULE_PARM_DESC(phys_mac, "physical port mac address");
MODULE_PARM_DESC(phys_ifname, "physical port interface name");
MODULE_PARM_DESC(blade_id, "local blade id");

struct rfpvi_stats {
	unsigned long tx_packets;
	unsigned long tx_bytes;
};

struct rfpvi_priv {
	struct rfpvi_stats      private_stats; /* for debug purposes */
	struct rfpvi            *rfpvi;
	uint8_t bladeid;
};

static struct rfpvi_blade *rfpvi_find_blade_by_id(uint8_t blade_id);
static struct rfpvi_blade *rfpvi_find_blade_by_dev(struct net_device *dev);
static int rfpvi_xmit(struct sk_buff *skb, struct net_device *dev);
static char *rfpvi_mac_ntoa(const uint8_t *addr, size_t len);
static int rfpvi_fill_info(struct sk_buff *skb, const struct net_device *dev);
static size_t rfpvi_get_size(const struct net_device *dev);


/* fake multicast ability
 *   it allows to call SIOC[ADD|DEL]MULTI of the device.
 */
static void rfpvi_set_rx_mode(struct net_device *dev)
{
	return;
}

static int rfpvi_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < FPTUN_HLEN)
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

static int rfpvi_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	return 0;
}

static struct rtnl_link_ops rfpvi_link_ops __read_mostly = {
	.kind		= "rfpvi",
	.get_size	= rfpvi_get_size,
	.fill_info	= rfpvi_fill_info,
};

static struct ethtool_ops rfpvi_ethtool_ops = {
	.get_settings		= rfpvi_get_settings
};

struct net_device_ops rfpvi_setup_ops = {
	.ndo_start_xmit = rfpvi_xmit,
	.ndo_set_rx_mode = rfpvi_set_rx_mode,
	.ndo_change_mtu = rfpvi_change_mtu,
	.ndo_set_mac_address = eth_mac_addr, 
};

static size_t rfpvi_get_size(const struct net_device *dev)
{
	size_t size;

	size = nla_total_size(1); /* IFLA_RFPVI_BLADEID */

	return size;
}

/* must be changed in all users (libif and cmgr) as well */
enum {
	IFLA_RFPVI_UNSPEC,
	IFLA_RFPVI_BLADEID,
	__IFLA_RFPVI_MAX
};

#define IFLA_RFPVI_MAX (__IFLA_RFPVI_MAX - 1)

static int rfpvi_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct rfpvi_priv *priv = netdev_priv(dev);
	uint8_t bladeid = 0;
	int err = 0;

	bladeid = priv->bladeid;

	nla_put_u8(skb, IFLA_RFPVI_BLADEID, bladeid);
	if (err < 0)
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}


static void rfpvi_setup(struct net_device *dev)
{
	dev->netdev_ops = &rfpvi_setup_ops;

	/* Fill in device structure with ethernet-generic values. */
	ether_setup(dev);
	dev->mtu -= FPTUN_HLEN + ETH_HLEN;
	dev->rtnl_link_ops = &rfpvi_link_ops;
	dev->tx_queue_len = 0;
	dev->ethtool_ops = &rfpvi_ethtool_ops;
	dev->hard_header_len += LL_MAX_HEADER + FPTUN_HLEN;
	dev->features |= NETIF_F_LLTX; /* lockless */

	random_ether_addr(dev->dev_addr);
	/*
	 * This driver should always have its carrier on. Userspace
	 * will put the interface in dormant mode and use
	 * IF_OPER_DORMANT to configure the interface running flag.
	 */
	netif_carrier_on(dev);
}

struct net_device_ops rfpvi_ops = {
	.ndo_start_xmit = rfpvi_xmit,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_set_rx_mode = rfpvi_set_rx_mode,
	.ndo_change_mtu = rfpvi_change_mtu,
};

/*
 * Called by rfpvi interfaces hard_start_xmit() and by dev_queue_xmit().
 * The following cases can be encountered:
 *   1/ dev is a RFPVI interface: we are called by dev->hard_start_xmit().
 *      If blade infos are not defined, packet is dropped.
 *   2/ dev has the IFF_FP_OUTPUT flag, is _not_ a RFPVI interface,
 *      and has no blade infos. It means that we are in colocalized
 *      mode. The device can be a physical or logical device.
 *   3/ dev has the IFF_FP_OUTPUT flag, is _not_ a RFPVI interface,
 *      and its blade infos are configured.
 */
static int rfpvi_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct fptunhdr *fptunhdr;
	int need_head, prepend;
#ifdef CONFIG_NET_SKBUFF_SKTAG
	struct cmsghdr *cmsg;
	struct msghdr msg = {
		.msg_control = skb->sktag,
		.msg_controllen = sizeof(skb->sktag)
	};
	struct fpmtaghdr *mtag;
	struct in_taginfo *sktag;
#endif
	int tags = 0;
	struct net_device_stats *stats;
	struct rfpvi_priv *priv = NULL;
	struct rfpvi *rfpvi = NULL;
	struct net_device *output_dev = NULL;
	char dst_mac[MAX_ADDR_LEN];
	struct rfpvi_blade *blade = NULL;
	uint8_t tmp_blade_id;
	uint32_t ifuid;

	stats = &dev->stats;

	priv = netdev_priv(dev);
	rfpvi = priv->rfpvi;

#ifdef CONFIG_FP_DEV_OUTPUT
	/* check if the interface is RFPVI */
	/* if CONFIG_FP_DEV_OUTPUT is unset, dev is inevitably RFPVI */
	if (dev->netdev_ops->ndo_start_xmit == rfpvi_xmit)
#endif /* CONFIG_FP_DEV_OUTPUT */
	{
		if (rfpvi->fptun_cmd == FPTUN_ETH_SP_OUTPUT_REQ) {
			priv->private_stats.tx_packets++;
			priv->private_stats.tx_bytes += skb->len;
		} else {
			stats->tx_packets++;
			stats->tx_bytes += skb->len;
		}
	}

	tmp_blade_id = priv->bladeid;
	ifuid = netdev2ifuid(dev);

	read_lock_bh(&rfpvi_blades_lock);
	blade = rfpvi_find_blade_by_id(tmp_blade_id);
	if (blade == NULL) {
		/* blade is not directly connected to CP,
		 * forward packet through local FP */
		blade = rfpvi_find_blade_by_id(blade_id);
	}
	if (blade == NULL) {
		printk(KERN_DEBUG RFPVI_NAME
		       "failed to output packet to blade %u\n", tmp_blade_id);
		stats->tx_dropped++;
		read_unlock_bh(&rfpvi_blades_lock);
		goto bad;
	} else {
		output_dev = blade->output_if;
		memcpy(dst_mac, blade->peer_mac, MAX_ADDR_LEN);
		read_unlock_bh(&rfpvi_blades_lock);
	}

#ifdef CONFIG_FP_DEV_OUTPUT
	if (dev_fp_output && (output_dev->nd_extra_flags & IFF_FP_OUTPUT)) {
		printk(KERN_ALERT RFPVI_NAME
		       "%s has the FP_OUTPUT flag, drop packet to avoid infinite loop\n",
		       output_dev->name);
		stats->tx_dropped++;
		goto bad;
	}
#endif /* CONFIG_FP_DEV_OUTPUT */

	/* room to reserve for FPTUN header */
	prepend = FPTUN_HLEN;

#ifdef CONFIG_NET_SKBUFF_SKTAG
	/* room to reserve for mtags */
	cmsg = CMSG_FIRSTHDR(&msg);
	if (CMSG_OK(&msg, cmsg)) {
		int max_ntags = 0xF; /* nb tags is 4-bit field */

		/* if present, skb->mark will need one mtag */
		if (skb->mark)
			max_ntags--;
		tags = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(struct in_taginfo);
		if (tags > max_ntags) {
			printk(KERN_ALERT RFPVI_NAME
					"Too many sktags %u\n", tags);
			stats->tx_dropped++;
			goto bad;
		}
		prepend += tags * sizeof(struct fpmtaghdr);
	} else
		tags = 0;

	/* mark will be added as a mtag */
	if (skb->mark) {
		prepend += sizeof(struct fpmtaghdr);
	}
#endif

	need_head = prepend + output_dev->hard_header_len;

	/*
	 * Check and prepare headroom for FPTUN encapsulation
	 */
	if (skb_headroom(skb) < need_head || skb_cloned(skb) || skb_shared(skb)) {
		struct sk_buff *new_skb = skb_realloc_headroom(skb, need_head);
		if (!new_skb) {
			stats->tx_dropped++;
			goto bad;
		}
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		dev_kfree_skb(skb);
		skb = new_skb;
	}

	/* append FPTUN header */
	fptunhdr = (struct fptunhdr *)skb_push(skb, prepend);
	memset(fptunhdr, 0, prepend);
	if (rfpvi) {
		fptunhdr->fptun_cmd       = rfpvi->fptun_cmd;
		fptunhdr->fptun_exc_class = rfpvi->fptun_exc_class;
		fptunhdr->fptun_blade_id  = tmp_blade_id;
		fptunhdr->fptun_ifuid     = ifuid;
	}
	else {
		if (dev->type == ARPHRD_ETHER)
			fptunhdr->fptun_cmd       = FPTUN_ETH_SP_OUTPUT_REQ;
		else if (skb->protocol == htons(ETH_P_IP))
			fptunhdr->fptun_cmd       = FPTUN_IPV4_SP_OUTPUT_REQ;
		else if (skb->protocol == htons(ETH_P_IPV6))
			fptunhdr->fptun_cmd       = FPTUN_IPV6_SP_OUTPUT_REQ;
		else
			goto bad;
		fptunhdr->fptun_exc_class = 0;
		fptunhdr->fptun_blade_id  = tmp_blade_id;
		fptunhdr->fptun_ifuid     = ifuid;
	}
	fptunhdr->fptun_mtags     = tags;
	fptunhdr->fptun_version   = FPTUN_VERSION;
#ifdef CONFIG_NET_VRF
	fptunhdr->fptun_vrfid     = htons(dev_vrfid(skb->dev) & 0xFFFF);
#else
	fptunhdr->fptun_vrfid	  = 0;
#endif
	fptunhdr->fptun_proto     = skb->protocol;

	skb->protocol = htons(ETH_P_FPTUN);

#ifdef CONFIG_NET_SKBUFF_SKTAG
	mtag = (struct fpmtaghdr*)(fptunhdr + 1);
	sktag = CMSG_DATA(cmsg);
	while (tags) {
		memcpy(mtag->fpmtag_name, sktag->iti_name, sizeof(mtag->fpmtag_name));
		mtag->fpmtag_data = sktag->iti_tag;

		mtag++;
		sktag++;
		tags--;
	}

	/* add a tag for mark */
	if (skb->mark) {
		strncpy(mtag->fpmtag_name, "nfm", sizeof(mtag->fpmtag_name));
		mtag->fpmtag_data = htonl(skb->mark);
		mtag++;
		fptunhdr->fptun_mtags++;
	}
#endif

	skb->dev = output_dev;

	/* encapsulate message for output on physical interface */
	if (output_dev->header_ops->create && 
			output_dev->header_ops->create(skb, output_dev, ETH_P_FPTUN, dst_mac, NULL, skb->len) < 0)
		goto bad;

	dev_queue_xmit(skb);
	return NETDEV_TX_OK;

bad:
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

/*
 * rfpvi_find: look for a rfpvi interface thanks to its name
 * Returns NULL if not found, else returns pointer to the struct rfpvi
 */
static struct rfpvi *rfpvi_find(char *name)
{
	struct list_head *rfpvi_idx;
	struct rfpvi *rfpvi = NULL;

	list_for_each(rfpvi_idx, &rfpvi_ifaces) {
		rfpvi = list_entry(rfpvi_idx, struct rfpvi, rfpvi_list);
		if (strcmp(rfpvi->rfpvi_dev->name, name) == 0)
			return rfpvi;
	}
	return NULL;
}

/*
 * rfpvi_find_blade_by_id: look for a rfpvi blade thanks to its id
 * caller must lock  rfpvi_blades_lock for protection.
 * Returns NULL if not found, else returns pointer to the struct rfpvi_blade
 */
static struct rfpvi_blade *rfpvi_find_blade_by_id(uint8_t blade_id)
{
	struct list_head *rfpvi_idx;
	struct rfpvi_blade *blade = NULL;

	list_for_each(rfpvi_idx, &rfpvi_blades) {
		blade = list_entry(rfpvi_idx, struct rfpvi_blade, rfpvi_blade_list);
		if (blade->blade_id == blade_id) {
			return blade;
		}
	}
	return NULL;
}

int rfpvi_get_blade_info(uint8_t blade_id, struct net_device **pdev, char *mac)
{
	struct rfpvi_blade *blade = NULL;

	read_lock_bh(&rfpvi_blades_lock);
	blade = rfpvi_find_blade_by_id(blade_id);
	read_unlock_bh(&rfpvi_blades_lock);

	if (blade == NULL)
		return -ENOENT;

	*pdev = blade->output_if;
	memcpy(mac, blade->peer_mac, MAX_ADDR_LEN);
	return 0;
}
EXPORT_SYMBOL(rfpvi_get_blade_info);

/*
 * rfpvi_find_blade_by_dev: look for a rfpvi blade thanks to its output
 * interface pointer; 
 * Caller must lock rfpvi_blades_lock for protection.
 * Returns NULL if not found, else returns pointer to the struct rfpvi_blade
 */
static struct rfpvi_blade *rfpvi_find_blade_by_dev(struct net_device *dev)
{
	struct list_head *rfpvi_idx;
	struct rfpvi_blade *blade = NULL;

	list_for_each(rfpvi_idx, &rfpvi_blades) {
		blade = list_entry(rfpvi_idx, struct rfpvi_blade, rfpvi_blade_list);
		if (blade->output_if == dev) {
			return blade;
		}
	}
	return NULL;
}

static int rfpvi_parse_mac_addr(const char *string, char *macbuf)
{
	int i;

	for (i=0; i<MAX_ADDR_LEN; i++) {
		unsigned long byte;
		char *end;

		byte = simple_strtoul(string, &end, 16);

		if (   ((*end != ':') && (*end != '\0'))
		    || (end == string)
		    || (byte > 255))
			return -1;

		macbuf[i] = (char)byte;

		if (*end == '\0')
			break;

		string = end + 1;
	}

	return i+1;
}

#define RFPVI_ADD_USAGE(name) \
	printk(KERN_ALERT RFPVI_NAME "%s: usage: IFNAME [mtu=MTU] [mac=XX:XX:XX:XX:XX:XX]\n", (name))

/*
 * check if string is of the form "keyword=val"
 * if yes, return a pointer to val
 * else return NULL;
 */
static const char *find_val(const char *string, const char *keyword)
{
	while ((*string) && (*string == *keyword)) {
		string++; keyword++;
	}
	if ((*keyword == 0) && (*string == '='))
		return (string + 1);

	return NULL;
}

static int rfpvi_parse_if_params(char *line, const char *tab[])
{
	char *stringp;
	char *token;
	const char *val;
	char *name;

	stringp = line;

	memset(tab, 0, RFPVI_PARAM_MAX * sizeof(const char*));

	/* bypass name */
	name = strsep(&stringp, " \t");

	while (stringp) {
		const struct rfpvi_if_param *p;

		/* ignore white space */
		while (isspace(*stringp))
			stringp++;

		token = strsep(&stringp, " \t");

		val = NULL;

		for (p=rfpvi_if_param_tab; p->type != -1; p++) {
			if (p->nval == 0) {
				if (strcmp(token, p->keyword) == 0) {
					val = token;
					break;
				}
			} else {
				if ((val = find_val(token, p->keyword))) {
					break;
				}
			}
		}

		if (val)
			tab[p->type] = val;
		else {
			printk(KERN_ALERT RFPVI_NAME "%s: invalid argument %s\n", __FUNCTION__, token);
			RFPVI_ADD_USAGE(name);
			return -1;
		}
	}

	return 0;
}

/*
 * rfpvi_init_one: add a rfpvi interface
 * Returns 0 on success, else returns a negative value
 */
static int rfpvi_init_one(char *name)
{
	struct rfpvi *new_rfpvi = NULL;
	struct net_device *dev_rfpvi = NULL;
	struct rfpvi_priv *priv;
	long flags = 0;
	uint8_t blade = 1;
	int err;

	const char *tab[RFPVI_PARAM_MAX];

	if (rfpvi_parse_if_params(name, tab)) {
		err = -EINVAL;
		goto out_err;
	}

	if (rfpvi_find(name) != NULL) {
		printk(KERN_INFO RFPVI_NAME "rfpvi interface already exists: %s\n", name);
		err = -EEXIST;
		goto out_err;
	}

	new_rfpvi = (struct rfpvi *)kmalloc(sizeof(struct rfpvi), GFP_KERNEL);
	if (!new_rfpvi) {
		printk(KERN_ALERT RFPVI_NAME "could not allocate new rfpvi interface\n");
		err = -ENOMEM;
		goto out_err;
	}

	dev_rfpvi = alloc_netdev(sizeof(struct rfpvi_priv), name,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
				 NET_NAME_USER,
#endif
				 rfpvi_setup);
	if (!dev_rfpvi) {
		printk(KERN_ALERT RFPVI_NAME "could not allocate new rfpvi device\n");
		err = -ENOMEM;
		goto out_err;
	}
	priv = netdev_priv(dev_rfpvi);

	if (tab[RFPVI_PARAM_MTU]) {
		long mtu;
		char *end;

		mtu = simple_strtol(tab[RFPVI_PARAM_MTU], &end, 0);

		if (*end == 0)
			dev_rfpvi->mtu = mtu;
		else {
			printk(KERN_ALERT RFPVI_NAME "%s: invalid mtu %s\n", name, tab[RFPVI_PARAM_MTU]);
			err = -EINVAL;
			goto out_err;
		}
	}

	if (tab[RFPVI_PARAM_FLAGS]) {
		char *end;

		flags = simple_strtol(tab[RFPVI_PARAM_FLAGS], &end, 16);

		if (*end != 0) {
			printk(KERN_ALERT RFPVI_NAME "%s: invalid flags %s\n", name, tab[RFPVI_PARAM_FLAGS]);
			err = -EINVAL;
			goto out_err;
		}
	}

	if (tab[RFPVI_PARAM_XFLAGS]) {
		long xflags;
		char *end;

		xflags = simple_strtol(tab[RFPVI_PARAM_XFLAGS], &end, 16);

		if (*end == 0) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
			dev_rfpvi->nd_extra_flags = xflags;
#else
			printk(KERN_ALERT RFPVI_NAME "xflags=0x%lx ignored\n", xflags);
#endif
		} else {
			printk(KERN_ALERT RFPVI_NAME "%s: invalid xflags %s\n", name, tab[RFPVI_PARAM_XFLAGS]);
			err = -EINVAL;
			goto out_err;
		}
	}

	if (tab[RFPVI_PARAM_BLADE]) {
		char *end;

		blade = simple_strtol(tab[RFPVI_PARAM_BLADE], &end, 0);
		if (*end != 0 || blade == 0) {
			printk(KERN_ALERT RFPVI_NAME "%s: invalid blade %s\n", name, tab[RFPVI_PARAM_BLADE]);
			err = -EINVAL;
			goto out_err;
		}
	}

	/* must be set before register_netdev so that it is right in
	   the first netlink message */
	priv->bladeid = blade;

	if (tab[RFPVI_PARAM_MAC]) {
		if (rfpvi_parse_mac_addr(tab[RFPVI_PARAM_MAC], dev_rfpvi->dev_addr) != 6) {
			printk(KERN_ALERT RFPVI_NAME "%s: invalid mac address %s\n", name, tab[RFPVI_PARAM_MAC]);
			err = -EINVAL;
			goto out_err;
		}
	}

	if ((err = register_netdev(dev_rfpvi))) {
		printk(KERN_ALERT RFPVI_NAME "could not register new rfpvi device\n");
		goto out_err;
	}

	if (flags) {
		rtnl_lock();
		dev_change_flags(dev_rfpvi, flags);
		rtnl_unlock();
	}

	new_rfpvi->fptun_cmd = FPTUN_ETH_SP_OUTPUT_REQ;
	new_rfpvi->fptun_exc_class = 0;
	new_rfpvi->rfpvi_dev = dev_rfpvi;

	/* everything went fine, insert the new rfpvi interface into the list */
	priv->rfpvi = new_rfpvi;
	list_add(&new_rfpvi->rfpvi_list, &rfpvi_ifaces);
	printk(KERN_DEBUG RFPVI_NAME "new rfpvi interface added: %s\n", name);

	return 0;

out_err:
	if (new_rfpvi)
		kfree(new_rfpvi);
	if (dev_rfpvi)
		free_netdev(dev_rfpvi);
	return err;
}

/*
 * rfpvi_init_blade: add a rfpvi blade
 * the information speicified by argument line should have
 * the format as blade id, output interface name and peer
 * mac address
 * Returns 0 on success, else returns a negative value
 */
static int rfpvi_init_blade(char *line)
{
	struct rfpvi_blade *new_blade= NULL;
	char *stringp, *tmp_blade_idp, *macp, *output_ifname, *endp;
	char mac[MAX_ADDR_LEN];
	uint8_t tmp_blade_id;

	/* parse parameters */
	stringp = line;
	tmp_blade_idp = strsep(&stringp, " \t");
	while (stringp && isspace(*stringp))
		stringp++;
	output_ifname = strsep(&stringp, " \t");

	while (stringp && isspace(*stringp))
		stringp++;
	macp = strsep(&stringp, " \t");

	if (!tmp_blade_idp || !output_ifname || !macp) {
		printk(KERN_ALERT RFPVI_NAME "Add blade format: blade_id ifname mac_addr\n");
		return -EINVAL;
	}

	/* check parameters */
	tmp_blade_id = (uint8_t)simple_strtol(tmp_blade_idp, &endp, 0);
	if (*endp != 0 || tmp_blade_id == 0) {
		printk(KERN_ALERT RFPVI_NAME "invalid blade id: %u\n", tmp_blade_id);
		return -EINVAL;
	}
	memset(mac, 0, MAX_ADDR_LEN);
	if (rfpvi_parse_mac_addr(macp, mac) != 6) {
		printk(KERN_INFO RFPVI_NAME "invalid mac address: %s\n", rfpvi_mac_ntoa(mac, ETH_ALEN));
		return -EINVAL;
	}

	read_lock_bh(&rfpvi_blades_lock);
	if (rfpvi_find_blade_by_id(tmp_blade_id) != NULL) {
		printk(KERN_INFO RFPVI_NAME "rfpvi blade already exists: %u\n", tmp_blade_id);
		read_unlock_bh(&rfpvi_blades_lock);
		return -EEXIST;
	}
	read_unlock_bh(&rfpvi_blades_lock);

	new_blade = (struct rfpvi_blade *)kmalloc(sizeof(struct rfpvi_blade), GFP_KERNEL);
	if (!new_blade) {
		printk(KERN_ALERT RFPVI_NAME "could not allocate new rfpvi blade\n");
		return -ENOMEM;
	}

	memset(new_blade, 0, sizeof(struct rfpvi_blade));
	new_blade->blade_id = tmp_blade_id;
	memcpy(new_blade->peer_mac, mac, MAX_ADDR_LEN);
	new_blade->output_if = dev_get_by_name(&init_net, output_ifname);
	if (new_blade->output_if == NULL) {
		printk(KERN_INFO RFPVI_NAME "interface %s not found\n", output_ifname);
		kfree(new_blade);
		return -ENODEV;
	}
	write_lock_bh(&rfpvi_blades_lock);
	list_add(&new_blade->rfpvi_blade_list, &rfpvi_blades);
	write_unlock_bh(&rfpvi_blades_lock);
	printk(KERN_DEBUG RFPVI_NAME "new rfpvi blade added: (%u %s %s)\n", 
		tmp_blade_id, output_ifname, rfpvi_mac_ntoa(mac, ETH_ALEN));
	return 0;
}

/*
 * rfpvi_free_one: remove a rfpvi interface
 * Returns 0 on success, else returns a negative value
 */
static int rfpvi_free_one(struct rfpvi *rfpvi)
{
	int err;

	list_del(&rfpvi->rfpvi_list);

	unregister_netdev(rfpvi->rfpvi_dev);
	err = 0;
	free_netdev(rfpvi->rfpvi_dev);

	kfree(rfpvi);

	return err;
}

/*
 * rfpvi_free_blade: remove a rfpvi blade from global list
 * Returns 0 on success, else returns a negative value
 */
static int rfpvi_free_blade(struct rfpvi_blade *blade)
{
	int err = 0;

	dev_put(blade->output_if);
	list_del(&blade->rfpvi_blade_list);
	kfree(blade);

	return err;
}

#ifdef CONFIG_SYSCTL
/*
 * Buffers used to store the name of rfpvi interface to add/delete
 * format: ifname [mtu=MTU] [mac=MAC]
 *
 * Buffers used to the information of rfpvi blade to add/delete
 * format: blade_id ifname peer_mac for add and blade id for delete
 */
static char rfpvi_sysctl_add_interface_buf[512],
            rfpvi_sysctl_del_interface_buf[512],
            rfpvi_sysctl_add_blade_buf[512];
static int rfpvi_sysctl_del_blade_id = 0;

/*
 * Handler when /proc/sys/rfpvi/add_interface is written
 * Add the rfpvi interface in the system
 * Returns 0 on success, else returns a negative value
 */
static
int rfpvi_sysctl_add_interface(struct ctl_table *ctl, int write,
		       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int err;

	if ((err = proc_dostring(ctl, write, buffer, lenp, ppos)) < 0)
		return err;

	/* add rfpvi interface and empty add_interface */
	if (write) {
		err = rfpvi_init_one(ctl->data);
		strcpy((char*)ctl->data, "");
	}

	return err;
}

/*
 * Handler when /proc/sys/rfpvi/del_interface is written
 * Delete the rfpvi interface from the system
 * Returns 0 on success, else returns a negative value
 */
static
int rfpvi_sysctl_del_interface(struct ctl_table *ctl, int write,
		       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct rfpvi *rfpvi;
	char name[IFNAMSIZ];
	int err;

	if ((err = proc_dostring(ctl, write, buffer, lenp, ppos)) < 0)
		return err;

	if (write) {
		snprintf(name, sizeof(name), "%s", (char *)ctl->data);
		if ((rfpvi = rfpvi_find(name))) {
			if ((err = rfpvi_free_one(rfpvi)) < 0)
				printk(KERN_ALERT RFPVI_NAME
				       "could not delete rfpvi interface: %s\n", name);
			else
				printk(KERN_DEBUG RFPVI_NAME
				       "rfpvi interface deleted: %s\n", name);
			goto out;
		}
		printk(KERN_INFO RFPVI_NAME "rfpvi interface not found: %s\n", name);
		err = -ENODEV;
		goto out;
	}

	return 0;

out:
	/* empty del_interface */
	strcpy((char*)ctl->data, "");
	return err;
}

/*
 * Handler when /proc/sys/rfpvi/add_blade is written
 * Add the rfpvi blade in the system
 * Returns 0 on success, else returns a negative value
 */
static
int rfpvi_sysctl_add_blade(struct ctl_table *ctl, int write,
		       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int err;

	if ((err = proc_dostring(ctl, write, buffer, lenp, ppos)) < 0)
		return err;

	/* add rfpvi blade and empty add_blade */
	if (write) {
		err = rfpvi_init_blade(ctl->data);
		strcpy((char*)ctl->data, "");
	}

	return err;
}

/*
 * Handler when /proc/sys/rfpvi/del_blade is written
 * Delete the rfpvi blade from the system
 * Returns 0 on success, else returns a negative value
 */
static
int rfpvi_sysctl_del_blade(struct ctl_table *ctl, int write,
		       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct rfpvi_blade *blade;
	uint8_t blade_id;
	int *valp = ctl->data;
	int err = 0;

	if ((err = proc_dointvec(ctl, write, buffer, lenp, ppos)) < 0)
		return err;

	if (write) {
#ifndef BLADEID_MAX
#define BLADEID_MAX 16
#endif
		if ((*valp <= 0) || (*valp > BLADEID_MAX)) {
			printk(KERN_ALERT RFPVI_NAME "invalid blade id: %u\n", (uint8_t)*valp);
			err = -EINVAL;
			goto out;
		}
		blade_id = (uint8_t)*valp;
		write_lock_bh(&rfpvi_blades_lock);
		if ((blade = rfpvi_find_blade_by_id(blade_id))) {
			if ((err = rfpvi_free_blade(blade)) < 0)
				printk(KERN_ALERT RFPVI_NAME
				       "could not delete rfpvi blade: %u\n", blade_id);
			else
				printk(KERN_DEBUG RFPVI_NAME
				       "rfpvi blade deleted: %u\n", blade_id);
			write_unlock_bh(&rfpvi_blades_lock);
			goto out;
		}
		write_unlock_bh(&rfpvi_blades_lock);
		printk(KERN_INFO RFPVI_NAME "rfpvi blade not found: %u\n", blade_id);
		err = -ENODEV;
	}
out:
	/* empty del_blade */
	strcpy((char*)ctl->data, "");
	return err;
}

/*
 * Contents of /proc/sys/rfpvi directory
 */
struct ctl_table rfpvi_sysctl_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "add_interface",
		.data           =       rfpvi_sysctl_add_interface_buf,
		.maxlen         =       sizeof(rfpvi_sysctl_add_interface_buf),
		.mode           =       0644,
		.proc_handler   =       &rfpvi_sysctl_add_interface,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "del_interface",
		.data           =       rfpvi_sysctl_del_interface_buf,
		.maxlen         =       sizeof(rfpvi_sysctl_del_interface_buf),
		.mode           =       0644,
		.proc_handler   =       &rfpvi_sysctl_del_interface,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "add_blade",
		.data           =       rfpvi_sysctl_add_blade_buf,
		.maxlen         =       sizeof(rfpvi_sysctl_add_blade_buf),
		.mode           =       0644,
		.proc_handler   =       &rfpvi_sysctl_add_blade,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "del_blade",
		.data           =       &rfpvi_sysctl_del_blade_id,
		.maxlen         =       sizeof(int),
		.mode           =       0644,
		.proc_handler   =       &rfpvi_sysctl_del_blade,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       0,      /* sentinel */
#endif
		.procname       =       NULL,
	}
};

/*
 * Define /proc/sys/rfpvi directory
 */
struct ctl_table rfpvi_sysctl_root_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "rfpvi",
		.mode           =       0555,
		.child          =       rfpvi_sysctl_table,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       0,      /* sentinel */
#endif
		.procname       =       NULL,
	}
};

#endif

static const char hexdigit[]="0123456789abcdef";

static char * rfpvi_mac_ntoa(const uint8_t *addr, size_t len)
{
	static char addrstr[MAX_ADDR_LEN * 3];
	const uint8_t *src;
	char *dst;
	uint8_t byte;
	size_t i, maclen;

	if (len > MAX_ADDR_LEN)
		maclen = MAX_ADDR_LEN;
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

static int __init rfpvi_parse_params(void)
{
	char mac[MAX_ADDR_LEN];
	struct net_device *dev;
	struct rfpvi_blade *new_blade;
	u8 local_blade_id = blade_id;

	if ((phys_ifname == NULL) || (phys_mac == NULL)) {
		printk(KERN_INFO RFPVI_NAME "Start module without default blade\n");
		return 0;
	}

	if (local_blade_id == 0) {
		/* Ensure backward compatibility */
		local_blade_id = 1;
	}

	dev = dev_get_by_name(&init_net, phys_ifname);

	if (dev == NULL) {
		printk(KERN_INFO RFPVI_NAME "interface %s not found\n", phys_ifname);
		return -ENODEV;
	}

	if (rfpvi_parse_mac_addr(phys_mac, mac) < 0) {
		printk(KERN_INFO RFPVI_NAME "invalid mac address %s\n", phys_mac);
		dev_put(dev);
		return -EINVAL;
	}

	new_blade = (struct rfpvi_blade *)kmalloc(sizeof(struct rfpvi_blade), GFP_KERNEL);
	if (!new_blade) {
		printk(KERN_ALERT RFPVI_NAME "could not allocate new rfpvi blade\n");
		dev_put(dev);
		return -ENOMEM;
	}

	new_blade->blade_id = local_blade_id;
	new_blade->output_if = dev;
	memcpy(new_blade->peer_mac, mac, MAX_ADDR_LEN);

	/* don't need to lock since we are at startup time */
	list_add(&new_blade->rfpvi_blade_list, &rfpvi_blades);

	printk(KERN_INFO RFPVI_NAME "rfpvi module loaded (%u %s %s)\n",
			local_blade_id, dev->name,
			rfpvi_mac_ntoa(mac, dev->addr_len));

	return 0;
}

/* 
 * rfpvi_dev_notify: listen dev event NETDEV_UNREGISTER. When a device is 
 * unregistered, it releases the reference count for dev (dev_put()) and 
 * remove the blade with this device as output interface. 
 * Administrator have to add it himself if device is resgistered again.
 *
 */
static int rfpvi_dev_notify(struct notifier_block *this, unsigned long event, void * data)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
	struct net_device *dev = (struct net_device *) data;
#else
	struct net_device *dev = netdev_notifier_info_to_dev(data);
#endif
	struct rfpvi_blade *blade;

	switch(event) {
		case NETDEV_UNREGISTER:
			write_lock_bh(&rfpvi_blades_lock);
			blade = rfpvi_find_blade_by_dev(dev);
			if (blade) {
				printk(KERN_DEBUG RFPVI_NAME "%s: rfpvi blade deleted: %u\n", 
					__FUNCTION__, blade->blade_id);
				rfpvi_free_blade(blade);
			}
			write_unlock_bh(&rfpvi_blades_lock);
			break;
		default:
			/* do nothing now */
			break;
	}
	return NOTIFY_OK;
}
static struct notifier_block rfpvi_dev_notf = {
	.notifier_call = rfpvi_dev_notify,
	.priority = 0
};

static int __init rfpvi_init_module(void)
{
	int error;

	/* init rwlock for blades list */
	rwlock_init(&rfpvi_blades_lock);

	error = rfpvi_parse_params();
	if (error)
		return error;
#ifdef CONFIG_SYSCTL
	rfpvi_sysctl_header = register_sysctl_table(rfpvi_sysctl_root_table);
#endif
#ifdef CONFIG_FP_DEV_OUTPUT
	dev_fp_output = rfpvi_xmit;
#endif
	register_netdevice_notifier(&rfpvi_dev_notf);
	printk(KERN_INFO RFPVI_NAME "rfpvi module initialized\n");
	return 0;
}

static void __exit rfpvi_cleanup_module(void)
{
	struct list_head *rfpvi_idx, *rfpvi_idx_next;
	struct list_head *blade_idx, *blade_idx_next;

#ifdef CONFIG_FP_DEV_OUTPUT
	dev_fp_output = NULL;
#endif

#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(rfpvi_sysctl_header);
#endif
	list_for_each_safe(rfpvi_idx, rfpvi_idx_next, &rfpvi_ifaces)
		rfpvi_free_one(list_entry(rfpvi_idx, struct rfpvi, rfpvi_list));
	
	write_lock_bh(&rfpvi_blades_lock);
	list_for_each_safe(blade_idx, blade_idx_next, &rfpvi_blades)
		rfpvi_free_blade(list_entry(blade_idx, struct rfpvi_blade, rfpvi_blade_list));
	write_unlock_bh(&rfpvi_blades_lock);
	unregister_netdevice_notifier(&rfpvi_dev_notf);

}

module_init(rfpvi_init_module);
module_exit(rfpvi_cleanup_module);
MODULE_LICENSE("GPL");
