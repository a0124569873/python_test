/*
 * Copyright (C) 2010 6WIND, All rights reserved.
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

/*
 * DPVI module: Dataplane Proxy Virtual Interface
 * See documentation in dpvi.h
 */

#ifndef CONFIG_SYSCTL
#error "this module needs CONFIG_SYSCTL"
#endif

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <net/sock.h>
#include <linux/sysctl.h>
#include <net/dst.h>
#include <net/arp.h>
#include <linux/ctype.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <linux/kthread.h>
#include <linux/file.h>

#include "dpvi.h"
#include "shmem/fpn-shmem.h"
#include "fpn.h"
#include "fpn-port.h"

#define DPVI_NAME    "dpvi"
#define DPVI_VERSION "0.1"
#define DPVI_PREFIX  "dpvi: "

#define DPVI_ERR(fmt, ...) do {						\
		if (unlikely(net_ratelimit()))				\
			printk(KERN_ERR DPVI_PREFIX "%s() " fmt,	\
			       __FUNCTION__, ##__VA_ARGS__);		\
	} while (0)

#define DPVI_INFO(fmt, ...) do {					\
		if (unlikely(net_ratelimit()))				\
			printk(KERN_INFO DPVI_PREFIX "%s() " fmt,	\
			       __FUNCTION__, ##__VA_ARGS__);		\
	} while (0)

#define DPVI_LOG(fmt, ...) do {					\
		printk(KERN_INFO DPVI_PREFIX "%s() " fmt,		\
			   __FUNCTION__, ##__VA_ARGS__);		\
	} while (0)

#define DPVI_DEBUG(fmt, ...) do {					\
		if (dpvi_debug) {					\
			if (unlikely(net_ratelimit()))			\
				printk(KERN_DEBUG DPVI_PREFIX		\
				       "%s():%d " fmt,			\
				       __FUNCTION__, __LINE__,		\
				       ##__VA_ARGS__);			\
		}							\
	} while (0)

/* when sending a request, time to wait for the answer */
#define DPVI_CTRL_TIMEOUT_MS 10
#define DPVI_CTRL_INIT_TIMEOUT_MS 100

/* maximum number of queued messages in queues */
#define DPVI_CTRL_RXMODE_MAX_QLEN 32

/* Netlink message buffer size */
#define DPVI_NL_BUFSIZE 512

/* Net link socket and poll task */
struct socket *nl_sock;
struct task_struct *nl_poll;

#if defined __LITTLE_ENDIAN
#ifndef htonll
#define htonll(x)  __cpu_to_be64 (x)
#define ntohll(x)  __be64_to_cpu (x)
#endif
#elif defined  __BIG_ENDIAN
#ifndef htonll
#define htonll(x)  (x)
#define ntohll(x)  (x)
#endif
#else
#error "ENDIANESS undefined"
#endif

port_mem_t *fpn_port_shmem;

static DEFINE_MUTEX(dpvi_ctrl_lock);

/* /proc/sys/dpvi is used to list dpvi interfaces */
struct ctl_table_header *dpvi_sysctl_header;

/* Buffer used to store the list of dpvi interfaces */
static char dpvi_sysctl_list_interfaces_buf[4096];

/* Buffer used to store running fastpath pid */
static int running_fastpath = 0;

/* table containing the list of registered interfaces */
struct net_device *dpvi_table[DPVI_MAX_PORTS];

/* interface used to communicate with FP */
static char *fp_ifname = NULL;
module_param(fp_ifname, charp, S_IRUGO);
MODULE_PARM_DESC(fp_ifname, "name of interface to use to communicate with FP");

/* enable/disable debug */
static int dpvi_debug;
module_param(dpvi_debug, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(dpvi_debug, "enable debug");

static struct sk_buff_head ctrl_answer_queue;

/* private data attached to a DPVI interface */
struct dpvi_priv {
	uint16_t portid;     /* port identifier in FP */

	spinlock_t lock;     /* lock access to stats and link status */
	struct net_device_stats stats; /* returned by dpvi_get_stats */

	/* link status */
	uint16_t speed;      /* [10, 100, 1000, 10000] */
	uint8_t full_duplex; /* 0: half, 1: full */
	uint8_t link;        /* 1 -> link up, 0 -> link down */
};

/* xmit data on DPVI */
static int dpvi_xmit(struct sk_buff *skb, struct net_device *dev);

/* receive ctrl/data with proto = ETH_P_DPVI */
static int dpvi_rcv(struct sk_buff *skb, struct net_device *dev,
		    struct packet_type *pt, struct net_device *netdev);

/* new protocol handler for ETH_P_DPVI) */
static struct packet_type dpvi_packet_type = {
	.type = __constant_htons(ETH_P_DPVI),
	.func = dpvi_rcv,
};

/* Realign skb data pointer to a multiple of 4 + mod. This function
 * assumes that the skb is not shared and that the headroom is large
 * enough for that: it should be the case as the function is called
 * after removing a dpvi header. */
static void align_skb_data(struct sk_buff *skb, int mod)
{
#if defined(CONFIG_TILE) || defined(CONFIG_TILEGX)
	int headroom = skb_headroom(skb);
	int align;

	align = ((unsigned long)(skb->data) + mod) & 3;
	WARN_ON(headroom < align);
	if (align != 0 && align <= headroom) {
		u8 *data = skb->data;
		size_t len = skb_headlen(skb);
		skb->data -= align;
		memmove(skb->data, data, len);
		skb_set_tail_pointer(skb, len);
	}
#endif
}


/*
 * Send a request to the FP to change the MAC address of the
 * interface.
 * Called from process context only.
 */
static int dpvi_set_address(struct net_device *dev, void *addr)
{
	struct sockaddr *sa = addr;

	DPVI_DEBUG("enter\n");

	if (!is_valid_ether_addr(sa->sa_data))
		return -EADDRNOTAVAIL;

	/* update netdevice info */
	memcpy(dev->dev_addr, sa->sa_data, ETH_ALEN);
	return 0;
}

/* return driver information */
static void dpvi_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *info)
{
	snprintf(info->driver, sizeof(info->driver), "%s", DPVI_NAME);
	snprintf(info->version, sizeof(info->version), "%s", DPVI_VERSION);
}

/*
 * Ask the FP to change the MTU of the device. Return 0 on sucess.
 * Called from process context only.
 */
static int dpvi_change_mtu(struct net_device *dev, int new_mtu)
{
	DPVI_DEBUG("enter\n");

	/* update dev structure with new mtu on success */
	dev->mtu = new_mtu;
	return 0;
}

/*
 * Fake ethtool ability. This is not very accurate (only speed, duplex
 * and link status are provided). It can be extended if needed.
 */
static int dpvi_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct dpvi_priv *priv = netdev_priv(dev);
	uint16_t portid;
	struct fpn_port *port;

	if (priv == NULL)
		return -1;

	portid = priv->portid;
	port = &fpn_port_shmem->port[portid];

	/* update priv from shmem */
	spin_lock(&priv->lock);

	priv->speed       = port->speed;
	priv->full_duplex = port->full_duplex;

	spin_unlock(&priv->lock);

	switch (priv->speed) {
		case 10:
			ethtool_cmd_speed_set(cmd, SPEED_10);
			break;
		case 100:
			ethtool_cmd_speed_set(cmd, SPEED_100);
			break;
		case 1000:
			ethtool_cmd_speed_set(cmd, SPEED_1000);
			break;
		case 10000:
			ethtool_cmd_speed_set(cmd, SPEED_10000);
			break;
		default:
			break;
	}

	if (priv->full_duplex)
		cmd->duplex = DUPLEX_FULL;
	else
		cmd->duplex = DUPLEX_HALF;

	return 0;
}

/*
 * Get the status of the link (updated periodically by the FP)
 */
u32 dpvi_get_link(struct net_device *dev)
{
	struct dpvi_priv *priv = netdev_priv(dev);
	uint16_t portid;
	struct fpn_port *port;

	if (priv == NULL)
		return 0;

	portid = priv->portid;
	port = &fpn_port_shmem->port[portid];

	spin_lock(&priv->lock);
	priv->link = port->link;
	spin_unlock(&priv->lock);

	return priv->link;
}

/*
 * Return a pointer to statistics, updated periodically thanks to FP
 * messages
 */
static struct net_device_stats *dpvi_get_stats(struct net_device *dev)
{
	struct dpvi_priv *priv = netdev_priv(dev);
	uint16_t portid;
	struct fpn_port *port;

	if (priv == NULL)
		return (struct net_device_stats *)NULL;

	portid = priv->portid;
	port = &fpn_port_shmem->port[portid];

	spin_lock(&priv->lock);

	priv->stats.rx_packets = port->ipackets;
	priv->stats.tx_packets = port->opackets;
	priv->stats.rx_bytes   = port->ibytes;
	priv->stats.tx_bytes   = port->obytes;
	priv->stats.rx_errors  = port->ierrors;
	priv->stats.tx_errors  = port->oerrors;

	spin_unlock(&priv->lock);

	return &((struct dpvi_priv*)netdev_priv(dev))->stats;
}

static struct ethtool_ops dpvi_ethtool_ops = {
	.get_drvinfo      = dpvi_get_drvinfo,
	.get_settings     = dpvi_get_settings,
	.get_link         = dpvi_get_link,
};

struct net_device_ops dpvi_ops = {
	.ndo_get_stats = dpvi_get_stats,
	.ndo_start_xmit = dpvi_xmit,
	.ndo_change_mtu = dpvi_change_mtu,
	.ndo_set_mac_address = dpvi_set_address,
};

/* called at interface creation */
static void dpvi_setup(struct net_device *dev)
{
	dev->netdev_ops = &dpvi_ops;

	/* Fill in device structure with ethernet-generic values. */
	ether_setup(dev);
	dev->tx_queue_len = 0;
	dev->ethtool_ops = &dpvi_ethtool_ops;

	/* the packet will have another ethernet header and dpvi
	 * header in addition to the first ether header */
	dev->hard_header_len += ETH_HLEN + DPVI_HLEN;

	/* Don't release dst in caller, this is needed for all devices
	 * that call again dev_queue_xmit() from their xmit function
	 * (as some classifiers need skb->dst) : bonding, vlan,
	 * macvlan, eql, ifb, hdlc_fr */
	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
}

/*
 * Called when we transmit a packet on a DPVI interface. It will
 * encapsulate the packet in DPVI header, then send it over fpdev
 * (fpn0).
 */
static int dpvi_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device *fpdev;
	struct dpvi_hdr *dpvi_hdr;
	int need_head, prepend, ret;
	struct dpvi_priv *priv = NULL;
	char dst_mac[MAX_ADDR_LEN];

	DPVI_DEBUG("enter\n");

	priv = netdev_priv(dev);

	/* get pointer and reference to fpdev */
	fpdev = dev_get_by_name(&init_net, fp_ifname);
	if (fpdev == NULL)
		goto bad;

	/* room to reserve for DPVI header */
	prepend = DPVI_HLEN;
	need_head = prepend + fpdev->hard_header_len;

	/*
	 * Check and prepare headroom for DPVI encapsulation
	 */
	if (skb_headroom(skb) < need_head || skb_cloned(skb) || skb_shared(skb)) {
		struct sk_buff *new_skb = skb_realloc_headroom(skb, need_head);
		if (new_skb == NULL) {
			DPVI_ERR("Cannot realloc skbuff, drop packet\n");
			goto bad_devput;
		}
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		dev_kfree_skb(skb);
		skb = new_skb;
	}

	/* prepend DPVI header */
	dpvi_hdr = (struct dpvi_hdr *)skb_push(skb, prepend);
	memset(dpvi_hdr, 0, prepend);
	dpvi_hdr->type = DPVI_TYPE_DATA_LINUX2FP;
	dpvi_hdr->portid = priv->portid;
	dpvi_hdr->cmd = 0;
	dpvi_hdr->reqid = 0;

	skb->protocol = htons(ETH_P_DPVI);
	skb->dev = fpdev;

	/* encapsulate message for output on physical interface */
	if (fpdev->header_ops->create == NULL) {
		DPVI_ERR("fpdev has no create() method\n");
		goto bad_devput;
	}

	memset(dst_mac, 0, MAX_ADDR_LEN);
	ret = fpdev->header_ops->create(skb, fpdev, ETH_P_DPVI, dst_mac,
					NULL, skb->len);
	if (ret < 0) {
		DPVI_ERR("fpdev create() method returned %d\n", ret);
		goto bad_devput;
	}

	dev_queue_xmit(skb);
	dev_put(fpdev);
	return NETDEV_TX_OK;

bad_devput:
	dev_put(fpdev);
bad:
	kfree_skb(skb);
	return NETDEV_TX_OK;
}

/* netlink socket unload */
static void dpvi_cleanup_socket(void)
{
	struct msghdr msg;
	struct kvec	iov;
	struct nlmsghdr *nl_hdr;
	struct cn_msg *cn_hdr;
	enum proc_cn_mcast_op *op;
	char buffer[DPVI_NL_BUFSIZE];

	/* Close netlink socket */
	if (nl_sock)
	{
		/* Setup message */
		memset(buffer, 0, sizeof(buffer));
		memset(&msg, 0, sizeof(msg));
		nl_hdr = (struct nlmsghdr *)buffer;
		cn_hdr = (struct cn_msg *)NLMSG_DATA(nl_hdr);
		op = (enum proc_cn_mcast_op*)&cn_hdr->data[0];
		*op = PROC_CN_MCAST_IGNORE;

		/* Fill the netlink header */
		nl_hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) +
		                                 sizeof(enum proc_cn_mcast_op));
		nl_hdr->nlmsg_type = NLMSG_DONE;
		nl_hdr->nlmsg_flags = 0;
		nl_hdr->nlmsg_seq = 0;
		nl_hdr->nlmsg_pid = 0;

		/* Fill the connector header */
		cn_hdr->id.idx = CN_IDX_PROC;
		cn_hdr->id.val = CN_VAL_PROC;
		cn_hdr->seq = 0;
		cn_hdr->ack = 0;
		cn_hdr->len = sizeof(enum proc_cn_mcast_op);

		/* Fill descriptor */
		iov.iov_base = &buffer;
		iov.iov_len  = sizeof(buffer);

		/* Send message */
		if (kernel_sendmsg(nl_sock, &msg, &iov, 1, nl_hdr->nlmsg_len) !=
		    nl_hdr->nlmsg_len) {
			DPVI_ERR("Could not send group exit message\n");
		}

		/* Close the socket */
		sock_release(nl_sock);
		nl_sock = NULL;
	}
}

static int dpvi_nl_poll_task(void *arg)
{
	struct msghdr msg;
	struct kvec	iov;
	struct nlmsghdr *nl_hdr;
	struct cn_msg *cn_hdr;
	struct proc_event *proc_ev;
	char buffer[DPVI_NL_BUFSIZE];
	int len;

	/* Allow to be killed using SIGKILL (this is not obvious!) */
	allow_signal(SIGKILL);
	allow_signal(SIGTERM);

	memset(&msg, 0, sizeof(msg));

	/* Loop until termination is asked */
	while (!kthread_should_stop()) {

		/* Setup buffer */
		iov.iov_base = &buffer;
		iov.iov_len  = DPVI_NL_BUFSIZE;

		/* Get message from socket */
		if ((len = kernel_recvmsg(nl_sock, &msg, &iov, 1, DPVI_NL_BUFSIZE, 0)) <= 0)
			break;

		/* Get multipart messages */
		for (nl_hdr = (struct nlmsghdr *) buffer; NLMSG_OK(nl_hdr, len);
			 nl_hdr = NLMSG_NEXT (nl_hdr, len)) {
			cn_hdr  = (struct cn_msg *)NLMSG_DATA(nl_hdr);
			proc_ev = (struct proc_event *)&cn_hdr->data[0];

			/* Only interested in PROC_EVENT_EXIT events */
			/* To check that fastpath is alive */
			if ((proc_ev->what == PROC_EVENT_EXIT) &&  
				(proc_ev->event_data.exit.process_pid == running_fastpath)) {
				DPVI_INFO("Fastpath killed, stopping DPVI\n");
				running_fastpath = 0;
			}

			if (nl_hdr->nlmsg_type == NLMSG_DONE)
				break;
		}
	}

	if (!kthread_should_stop()) {
		DPVI_ERR("%s exiting\n", __func__);
	} else {
		DPVI_LOG("%s exiting\n", __func__);
	}

	/* Close netlink socket */
	dpvi_cleanup_socket();

	/* Task is not running anymore */
	nl_poll = NULL;

	return 0;
}

/*
 * Called when we receive a packet with ethertype = ETH_P_DPVI
 * that contains data to be received on a DPVI.
 */
static int dpvi_rcv_data(struct sk_buff *skb, uint16_t portid)
{
	struct net_device *dpvi_dev;

	DPVI_DEBUG("enter\n");

	if (portid >= DPVI_MAX_PORTS) {
		DPVI_ERR("Bad port id: %d\n", portid);
		kfree_skb(skb);
		return -EINVAL;
	}

	dpvi_dev = dpvi_table[portid];
	if (dpvi_dev == NULL) {
		DPVI_ERR("DPVI is not registered\n");
		kfree_skb(skb);
		return -ENODEV;
	}

	/* remove dpvi header */
	if (skb_pull(skb, sizeof(struct dpvi_hdr)) == NULL) {
		DPVI_ERR("Cannot pull DPVI header\n");
		kfree_skb(skb);
		return -ENOBUFS;
	}

	/* eth_type_trans() will change pkt_type if needed, pull data
	 * by dev->hard_header_len bytes and return the new proto. */
	skb->dev = dpvi_dev;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, dpvi_dev);

	align_skb_data(skb, 0);

	netif_rx(skb);
	return 0;
}

/*
 * We received a "port status" info control message. This is sent
 * by the FP to indicate a status change.
 */
static int dpvi_rcv_port_status(struct sk_buff *skb)
{
	uint16_t portid;

	DPVI_DEBUG("enter\n");

	if (skb_pull(skb, sizeof(struct dpvi_hdr)) == NULL) {
		DPVI_ERR("Cannot pull DPVI header\n");
		return -ENOBUFS;
	}

	/* blind update of status in netdevice private data */
	for (portid = 0; portid < FPN_MAX_PORTS; portid ++) {
		struct net_device *dpvi_dev = NULL;
		struct dpvi_priv *priv = NULL;
		struct fpn_port *port;

		port = &fpn_port_shmem->port[portid];

		/* if port is not enabled, skip */
		if (port->enabled == 0)
			continue;
		if (port->dpvi_managed == 0)
			continue;

		dpvi_dev = dpvi_table[portid];
		if (dpvi_dev == NULL)
			continue;
		priv = netdev_priv(dpvi_dev);
		if (priv == NULL)
			continue;

		spin_lock(&priv->lock);

		/* notify link changes to the stack */
		if (priv->link != 0 && port->link == 0) {
			DPVI_INFO("%s NIC Link is Down\n",
			       dpvi_dev->name);
			netif_carrier_off(dpvi_dev);
		}
		if (priv->link == 0 && port->link != 0) {
			DPVI_INFO("%s NIC Link is Up\n",
			       dpvi_dev->name);
			netif_carrier_on(dpvi_dev);
		}

		/* update private data */
		priv->speed       = port->speed;
		priv->full_duplex = port->full_duplex;
		priv->link        = port->link;

		spin_unlock(&priv->lock);
	}

	return 0;
}

/*
 * We received a control message (type=info). These kind of messages
 * are sent by the FP without any request from DPVI module. Dispatch
 * the messages to the specific handler.
 */
static int dpvi_rcv_ctrl_info(struct sk_buff *skb)
{
	struct dpvi_hdr *dpvi_hdr;
	int ret = 0;

	DPVI_DEBUG("enter\n");

	dpvi_hdr = (struct dpvi_hdr *)skb->data;

	switch (dpvi_hdr->cmd) {
		case DPVI_CMD_PORT_STATUS:
			ret = dpvi_rcv_port_status(skb);
			break;

		default:
			DPVI_ERR("Unknown info control message\n");
			break;
	}

	kfree_skb(skb);
	return ret;
}


/*
 * Called when we receive a packet with ethertype = ETH_P_DPVI. The
 * packet contains either control information or data to be received
 * on a DPVI. This function dispatch to the appropriate handler.
 */
static int dpvi_rcv(struct sk_buff *skb, struct net_device *dev,
		    struct packet_type *pt, struct net_device *netdev)
{
	struct dpvi_hdr *dpvi_hdr;

	DPVI_DEBUG("enter\n");

	if (strncmp(dev->name, fp_ifname, sizeof(dev->name) != 0)) {
		DPVI_ERR("DPVI Packet received on interface != fpdev: %s %s\n",
			 dev->name, fp_ifname);
		goto error;
	}

	/* skb is cloned by AF_PACKET if tcpdump is running */
	skb = skb_unshare(skb, GFP_ATOMIC);
	if (skb == NULL)
		goto error;

	if (!pskb_may_pull(skb, DPVI_HLEN)) {
		DPVI_ERR("Malformed packet\n");
		goto error;
	}
	dpvi_hdr = (struct dpvi_hdr *)skb_network_header(skb);

	switch (dpvi_hdr->type) {

		/* ctrl message, add in queue */
		case DPVI_TYPE_CTRL_INFO:
			dpvi_rcv_ctrl_info(skb);
			break;

		/* dispatch data, depending on portid */
		case DPVI_TYPE_DATA_FP2LINUX:
			dpvi_rcv_data(skb, dpvi_hdr->portid);
			break;

		/* answer to a previous request, add in queue */
		case DPVI_TYPE_CTRL_ANS:
			/* fallthrough */

		/* other control messages are garbage, drop
		 * them */
		default:
			goto error;
			break;
	}

	return 0;

 error:
	kfree_skb(skb);
	return 0;
}

/*
 * Allocate and add a dpvi interface.
 * Returns 0 on success, else returns a negative value
 */
static int dpvi_init_one(char *name, struct fpn_port *port)
{
	struct net_device *dpvi_dev = NULL;
	struct dpvi_priv *priv = NULL;
	int err;

	if (port->portid >= DPVI_MAX_PORTS) {
		DPVI_ERR("Invalid port id: %d\n", port->portid);
		return -EINVAL;
	}

	if (dpvi_table[port->portid] != NULL) {
		DPVI_ERR("Interface already exist for portid: %d\n", port->portid);
		return -EEXIST;
	}

	dpvi_dev = alloc_netdev(sizeof(struct dpvi_priv), name,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
				NET_NAME_ENUM,
#endif
				dpvi_setup);
	if (!dpvi_dev) {
		DPVI_ERR("could not allocate new dpvi device for portid: %d\n",
		          port->portid);
		return -ENOMEM;
	}

	if ((err = register_netdev(dpvi_dev))) {
		DPVI_ERR("could not register new dpvi device for portid: %d\n",
		          port->portid);
		free_netdev(dpvi_dev);
		return err;
	}

	/* always start with carrier off */
	netif_carrier_off(dpvi_dev);

	/* everything went fine, insert the new dpvi interface into the list */
	priv = netdev_priv(dpvi_dev);
	memset(priv, 0, sizeof(*priv));
	priv->portid = port->portid;
	priv->link = port->link;
	spin_lock_init(&priv->lock);
	memcpy(dpvi_dev->dev_addr, port->etheraddr, ETH_ALEN);
	/* XXX MTU is 1500 by default, it should be sync'd with FP */

	dpvi_table[port->portid] = dpvi_dev;
	port->linux_ifindex = dpvi_dev->ifindex;

	if (port->link)
		netif_carrier_on(dpvi_dev);

	DPVI_DEBUG("dpvi i/f added: %s for portid %d\n", dpvi_dev->name, priv->portid);

	return 0;
}

/*
 * dpvi_free_one: remove a dpvi interface
 * Returns 0 on success, else returns a negative value
 */
static int dpvi_free_one(uint16_t portid)
{
	struct net_device *dpvi_dev;

	if (portid >= DPVI_MAX_PORTS) {
		DPVI_ERR("Invalid port id\n");
		return -1;
	}

	dpvi_dev = dpvi_table[portid];
	if (dpvi_dev == NULL) {
		DPVI_ERR("Interface is not registered\n");
		return -1;
	}

	dpvi_table[portid] = NULL;
	unregister_netdev(dpvi_dev);
	free_netdev(dpvi_dev);
	return 0;
}

/*
 * Handler when /proc/sys/dpvi/list_interfaces is read
 * Returns 0 on success, else returns a negative value
 */
static int dpvi_sysctl_list_interfaces(struct ctl_table *ctl, int write,
				       void __user *buffer, size_t *lenp,
				       loff_t *ppos)
{
	struct net_device *dpvi_dev;
	int err, n = 0;
	uint16_t portid;
	int len = 0;

	if (write) {
		err = -EPERM;
		goto out;
	}

	strcpy((char*)ctl->data, "");

	for (portid = 0; portid < DPVI_MAX_PORTS; portid++) {
		dpvi_dev = dpvi_table[portid];
		if (dpvi_dev == NULL)
			continue;
		n = snprintf((char *)ctl->data + len, ctl->maxlen-len,
			     "%s%d %s", len == 0 ? "" : "\n",
			     portid, dpvi_dev->name);
		if (n < 0) {
			err = -EINVAL;
			goto out;
		}
		len += n;
		if (len >= ctl->maxlen) {
			DPVI_ERR("dpvi list is truncated (%d>=%d)\n",
				 len, ctl->maxlen);
			break;
		}
	}

	if ((err = proc_dostring(ctl, write, buffer, lenp, ppos)) < 0)
		return err;

	return err;

out:
	strcpy((char*)ctl->data, "");
	return err;
}

/*
 * Handler when /proc/sys/dpvi/running_fastpath is read/write
 * Returns 0 on success, else returns a negative value
 */
static int dpvi_sysctl_running_fastpath(struct ctl_table *ctl, int write,
				       void __user *buffer, size_t *lenp,
				       loff_t *ppos)
{
	int err;

	DPVI_DEBUG("enter");

	if ((err = proc_dointvec(ctl, write, buffer, lenp, ppos)) < 0)
		return err;

	if (write) {
		DPVI_INFO("Watching PID %d\n", running_fastpath);
	}

	return 0;
}

/*
 * Contents of /proc/sys/dpvi directory
 */
struct ctl_table dpvi_sysctl_table[] = {
	{
		.procname       =       "list_interfaces",
		.data           =       dpvi_sysctl_list_interfaces_buf,
		.maxlen         =       sizeof(dpvi_sysctl_list_interfaces_buf),
		.mode           =       0644,
		.proc_handler   =       &dpvi_sysctl_list_interfaces,
	},
 	{
		.procname       =       "running_fastpath",
		.data           =       &running_fastpath,
		.maxlen         =       sizeof(running_fastpath),
		.mode           =       0644,
		.proc_handler   =       &dpvi_sysctl_running_fastpath,
	},
	{
		/* sentinel */
		.procname       =       NULL,
	}
};

/*
 * Define /proc/sys/dpvi directory
 */
struct ctl_table dpvi_sysctl_root_table[] = {
	{
		.procname       =       "dpvi",
		.mode           =       0555,
		.child          =       dpvi_sysctl_table,
	},
	{
		/* sentinel */
		.procname       =       NULL,
	}
};

/*
 * Check parameters at module load.
 */
static int __init dpvi_parse_params(void)
{
	if (fp_ifname == NULL) {
		DPVI_ERR("No fp_ifname\n");
		return -EINVAL;
	}

	DPVI_INFO("dpvi module loaded (%s)\n", fp_ifname);

	return 0;
}

/*
 * Delete all DPVI interfaces.
 */
static void dpvi_clear_interfaces(void)
{
	struct sk_buff *skb;
	uint16_t portid;

	/* delete all interfaces */
	for (portid = 0; portid < DPVI_MAX_PORTS; portid++) {
		if (dpvi_table[portid] == NULL)
			continue;
		dpvi_free_one(portid);
	}

	/* purge queues */
	while ((skb = skb_dequeue_tail(&ctrl_answer_queue)))
		kfree_skb(skb);
}

/* module unload */
static void dpvi_cleanup_module(void)
{
	/* Remove sysctl */
	if (dpvi_sysctl_header != NULL)
		unregister_sysctl_table(dpvi_sysctl_header);

	/* Clear virtual interfaces */
	dpvi_clear_interfaces();

	/* Remove protocol handler */
	dev_remove_pack(&dpvi_packet_type);
}

/* module load */
static int __init dpvi_init_module(void)
{
	int ret, i;
	struct sockaddr_nl sin;
	struct msghdr msg;
	struct kvec	iov;
	struct nlmsghdr *nl_hdr;
	struct cn_msg *cn_hdr;
	enum proc_cn_mcast_op *op;
	char buffer[DPVI_NL_BUFSIZE];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	struct file *file;
#endif

	/* check module parameters */
	ret = dpvi_parse_params();
	if (ret)
		return ret;

	/* init queues and work tasks */
	skb_queue_head_init(&ctrl_answer_queue);
	/* add the ETH_P_DPVI protocol handler (always successful) */
	dev_add_pack(&dpvi_packet_type);

	fpn_port_shmem = (port_mem_t *) fpn_shmem_mmap("fpn-port-shared", NULL, sizeof(port_mem_t));
	if (!fpn_port_shmem) {
		DPVI_ERR("could not find port shmem\n");
		ret = -ENOMEM;
		goto fail;
	}

	/* init the local dpvi table */
	for (i=0; i<DPVI_MAX_PORTS; i++)
		dpvi_table[i] = NULL;

	/* for each port, create a DPVI */
	/* First create ports with a name specified, to be sure that */
	/* unspecified names will not override a named interface */
	for (i=0; i<DPVI_MAX_PORTS; i++) {
		if (fpn_port_shmem->port[i].enabled == 0)
			continue;
		if (fpn_port_shmem->port[i].dpvi_managed == 0)
			continue;

		/* Here either dpvi_table[i] is NULL, or it is set */
		/* to the correct interface */
		if ((dpvi_table[i] == NULL) && 
			(fpn_port_shmem->port[i].portname[0] != 0)) {
			ret = dpvi_init_one(fpn_port_shmem->port[i].portname,
			                    &fpn_port_shmem->port[i]);
			if (ret != 0)
				goto fail;
		}
	}

	/* for each port, create a DPVI */
	for (i=0; i<DPVI_MAX_PORTS; i++) {
		if (fpn_port_shmem->port[i].enabled == 0)
			continue;
		if (fpn_port_shmem->port[i].dpvi_managed == 0)
			continue;

		/* Setup remaining unset interfaces using default name */
		if (dpvi_table[i] == NULL) {
			/* eth%d is the default template for the new netdevices */
			ret = dpvi_init_one("eth%d", &fpn_port_shmem->port[i]);

			if (ret != 0)
				goto fail;
		}
	}

	/* register the list_interface sysctl */
	dpvi_sysctl_header = register_sysctl_table(dpvi_sysctl_root_table);
	if (dpvi_sysctl_header == NULL) {
		ret = -ENOMEM;
		goto fail;
	}

	/* Create netlink socket */
	ret = sock_create_kern(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR, &nl_sock);
	if (ret < 0) {
		DPVI_ERR("Fail to initialize kernel socket (%d)\n", ret);
		goto fail;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	/* Since kernel 3.15, it is mandatory to have a file mapping of the socket */
	/* Needed by ns capabilities check in connector module (file_ns_capable) */
	/* Since it has been backported on some 3.14 kernels, start on 3.10 */
	file = sock_alloc_file(nl_sock, 0, NULL);
	if (IS_ERR(file)) {
		DPVI_ERR("Fail to map socket (%p)\n", file);
		ret = (int)(size_t) file;
		goto fail;
	}
#endif

	/* Start to watch proc group */
	sin.nl_family = AF_NETLINK;
	sin.nl_groups = CN_IDX_PROC;
	sin.nl_pid = 0;
	ret = kernel_bind(nl_sock, (struct sockaddr *) &sin, sizeof(sin));
	if (ret < 0) {
		DPVI_ERR("Fail to bind socket (%d)\n", ret);
		goto fail;
	}

	/* Setup multicast listen message */
	memset(&msg, 0, sizeof(msg));
	memset(buffer, 0, sizeof(buffer));
	nl_hdr = (struct nlmsghdr *)buffer;
	cn_hdr = (struct cn_msg *)NLMSG_DATA(nl_hdr);
	op = (enum proc_cn_mcast_op*)&cn_hdr->data[0];
	*op = PROC_CN_MCAST_LISTEN;

	/* Fill the netlink header */
	nl_hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op));
	nl_hdr->nlmsg_type = NLMSG_DONE;
	nl_hdr->nlmsg_flags = 0;
	nl_hdr->nlmsg_seq = 0;
	nl_hdr->nlmsg_pid = 0;

	/* Fill the connector header */
	cn_hdr->id.idx = CN_IDX_PROC;
	cn_hdr->id.val = CN_VAL_PROC;
	cn_hdr->seq = 0;
	cn_hdr->ack = 0;
	cn_hdr->len = sizeof(enum proc_cn_mcast_op);

	/* Fill descriptor */
	iov.iov_base = &buffer;
	iov.iov_len  = sizeof(buffer);

	/* Send message */
	ret = kernel_sendmsg(nl_sock, &msg, &iov, 1, nl_hdr->nlmsg_len);
	if (ret != nl_hdr->nlmsg_len) {
		DPVI_ERR("Could not send mcast listen message\n");
		goto fail;
	}

	/* Init polling task */
	nl_poll = kthread_create(dpvi_nl_poll_task, NULL, "dpvi-nl-task");
	if (nl_poll == NULL) {
		DPVI_ERR("dpvi: can not start kernel thread\n");
		ret = -ECHILD;
		goto fail;
	}
	wake_up_process(nl_poll);

	DPVI_DEBUG("dpvi module initialized\n");
	return 0;

 fail:
	/* Close netlink socket here since kthread is not started */
	dpvi_cleanup_socket();

	/* Cleanup module */
  	dpvi_cleanup_module();
	return ret;
}

/* module exit */
static void __exit dpvi_exit_module(void)
{
	struct task_struct *tid = nl_poll;

	if (tid != NULL) {
		/* Kill poll task, this will close netlink socket */
		send_sig_info(SIGKILL, SEND_SIG_NOINFO, tid);
		kthread_stop(tid);
	}

	/* Cleanup module */
 	dpvi_cleanup_module();
}

module_init(dpvi_init_module);
module_exit(dpvi_exit_module);
MODULE_LICENSE("GPL");
