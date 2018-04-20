/*
 * ng_eiface.c
 *
 * Copyright (c) 1999-2000, Vitaly V Belekhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * 	$Id: ng_eiface_linux.c,v 1.24 2010-07-08 08:25:54 gauthier Exp $
 * $FreeBSD: src/sys/netgraph/ng_eiface.c,v 1.4.2.5 2002/12/17 21:47:48 julian Exp $
 */

/*
 * Copyright 2005-2013 6WIND S.A.
 */

#include <linux/version.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>
#include <linux/bitops.h> /* for ffs */
#include <net/dst.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <netgraph/vnblinux.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_eiface.h>
#include <netgraph/vnb_ether.h>

#include <linux/ctype.h>

#include <net/rtnetlink.h>
#include <netgraph_linux/ng_netlink.h>

static const struct ng_parse_struct_field ng_eiface_par_fields[]
	= NG_EIFACE_PAR_FIELDS;

static const struct ng_parse_type ng_eiface_par_type = {
	&ng_parse_struct_type,
	&ng_eiface_par_fields
};

static const struct ng_cmdlist ng_eiface_cmdlist[] = {
	{
	  NGM_EIFACE_COOKIE,
	  NGM_EIFACE_SET_IFNAME,
	  "setifname",
	  &ng_parse_string_type,
	  NULL
	},
	{
	  NGM_EIFACE_COOKIE,
	  NGM_EIFACE_GET_IFNAME,
	  "getifname",
	  NULL,
	  &ng_parse_string_type
	},
	{
	  NGM_EIFACE_COOKIE,
	  NGM_EIFACE_SET,
	  "set",
	  &ng_eiface_par_type,
	  NULL
	},
	{ 0 }
};

/* Node private data */
struct ng_eiface_private {
	struct	net_device *ifp;		/* This interface */
	node_p	node;			/* Our netgraph node */
	hook_p	ether;			/* Hook for ethernet stream */
	struct	private *next;		/* When hung on the free list */
	struct ng_eiface_par eaddr;     /* mac address (valid before interface creation) */
};
typedef struct ng_eiface_private *priv_p;

/* Interface methods */
static int ng_eiface_start_xmit(struct sk_buff *skb, struct net_device *ifp);
#ifdef DEBUG
static void	ng_eiface_print_ioctl(struct ifnet *ifp, int cmd, caddr_t data);
#endif
#include <net/sock.h>
#include <kcompat.h>

/* Netgraph methods */
static ng_constructor_t	ng_eiface_constructor;
static ng_rcvmsg_t	ng_eiface_rcvmsg;
static ng_shutdown_t	ng_eiface_rmnode;
static ng_newhook_t	ng_eiface_newhook;
static ng_rcvdata_t	ng_eiface_rcvdata;
static ng_connect_t	ng_eiface_connect;
static ng_disconnect_t	ng_eiface_disconnect;
static ng_dumpnode_t    ng_eiface_dumpnode;

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, typestruct) = {
	.version   = NG_VERSION,
	.name      = NG_EIFACE_NODE_TYPE,
	.mod_event = NULL,
	.constructor=ng_eiface_constructor,
	.rcvmsg    = ng_eiface_rcvmsg,
	.shutdown  = ng_eiface_rmnode,
	.newhook   = ng_eiface_newhook,
	.findhook  = NULL,
	.connect   = ng_eiface_connect,
	.afterconnect = NULL,
	.rcvdata   = ng_eiface_rcvdata,
	.rcvdataq  = ng_eiface_rcvdata,
	.disconnect= ng_eiface_disconnect,
	.rcvexception = NULL,
	.dumpnode = ng_eiface_dumpnode,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist   = ng_eiface_cmdlist
};
NETGRAPH_INIT(eiface, &typestruct);
NETGRAPH_EXIT(eiface, &typestruct);


/************************************************************************
			INTERFACE STUFF
 ************************************************************************/

static int ng_eiface_start_xmit(struct sk_buff *m, struct net_device *ifp)
{
	priv_p priv;
	meta_p meta = NULL;
	int len, error = 0;

	VNB_ENTER();

	priv = netdev_priv(ifp);
	if (!priv) {
		kfree_skb(m);
		VNB_EXIT();
		return NETDEV_TX_OK;
	}

	if (!(ifp->flags & IFF_UP)) {
		ifp->stats.tx_errors++;
		kfree_skb(m);
		VNB_EXIT();
		return NETDEV_TX_OK;
	}

	if (m->ip_summed == CHECKSUM_PARTIAL)
		skb_checksum_help(m);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	/* skb->mapping is TX queue id before entering here,
	 * restore RX queue + 1 to make next call to dev_pick_tx()
	 * choose the expected TX queue.
	 */
	skb_record_rx_queue(m, skb_get_queue_mapping(m));
#endif
	len = m->len;
	/* Send packet; if hook is not connected, mbuf will get freed. */
	NG_SEND_DATA(error, priv->ether, m, meta);

	/* error may happen however we have to return 0
	 * (packet m is freed)
	 * XX sure ?
	 */

	if (error == 0) {
		ifp->stats.tx_bytes += len;
		ifp->stats.tx_packets++;
	} else {
		ifp->stats.tx_errors++;
	}
	VNB_EXIT();
	return NETDEV_TX_OK;
}

#ifdef DEBUG
/*
 * Display an ioctl to the virtual interface
 */

static void
ng_eiface_print_ioctl(struct ifnet *ifp, int command, caddr_t data)
{
	char   *str;

	switch (command & IOC_DIRMASK) {
	case IOC_VOID:
		str = "IO";
		break;
	case IOC_OUT:
		str = "IOR";
		break;
	case IOC_IN:
		str = "IOW";
		break;
	case IOC_INOUT:
		str = "IORW";
		break;
	default:
		str = "IO??";
	}
	log(LOG_DEBUG, "%s: %s('%c', %d, char[%d])\n",
	       ifp->name,
	       str,
	       IOCGROUP(command),
	       command & 0xff,
	       IOCPARM_LEN(command));
}
#endif /* DEBUG */

/************************************************************************
			NETGRAPH NODE STUFF
 ************************************************************************/

static int
ng_eiface_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}
static int
ng_eiface_close(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static int ng_eiface_change_mtu(struct net_device *dev, int new_mtu)
{
        /*
         * ((16 * 1024) + 20 + 20 + 12) is the limit for lo
	 * RF loopback.c
         */
        if ((new_mtu < 68) || (new_mtu > (16 * 1024) + 20 + 20 + 12))
                return -EINVAL;
        dev->mtu = new_mtu;
        return 0;
}

/* fake multicast ability:
 *  it allows to call SIOC[ADD|DEL]MULTI of the device.
 */
static void ng_eiface_set_rx_mode(struct net_device *dev)
{
}

static const struct net_device_ops ng_eiface_ops = {
	.ndo_change_mtu		= ng_eiface_change_mtu,
	.ndo_start_xmit		= ng_eiface_start_xmit,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_open		= ng_eiface_open,
	.ndo_stop		= ng_eiface_close,
	.ndo_set_rx_mode	= ng_eiface_set_rx_mode,
};

/*
 * Constructor for a node
 */
static int
ng_eiface_constructor(node_p *nodep, ng_ID_t nodeid)
{

	int error = 0;
	/* Call generic node constructor */
	if ((error = ng_make_node_common(&typestruct, nodep, nodeid))) {
		return (error);
	}
	/* Done */
	return 0;
}


/*
 * Give our ok for a hook to be added
 */
static int
ng_eiface_newhook(node_p node, hook_p hook, const char *name)
{
	priv_p priv = node->private;
	if (strcmp(name, NG_EIFACE_HOOK_ETHER))
		return (EPFNOSUPPORT);
	if (priv != NULL) {
		if (priv->ether != NULL)
			return (EISCONN);
		priv->ether = hook;
		hook->private = &priv->ether;
		if (priv->ifp != NULL) {
			netif_carrier_on(priv->ifp);
		}
	}
	return (0);
}

static void ng_eiface_dellink(struct net_device *dev
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
			      , struct list_head *head
#endif
			     )
{
	priv_p priv = netdev_priv(dev);
	node_p node = priv->node;

	ng_cutlinks(node);
	ng_unname(node);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	unregister_netdevice_queue(dev, head);
#else
	unregister_netdevice(dev);
#endif
	priv->ifp = NULL;
	node->private = NULL;
	ng_unref(node);
}

static struct rtnl_link_ops ng_eiface_link_ops __read_mostly = {
	.kind			= "ng_eiface",
	.dellink                = ng_eiface_dellink,
};

/*
 * Receive a control message
 */
static int
ng_eiface_rcvmsg(node_p node, struct ng_mesg *msg,
		const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	priv_p priv = node->private;
	struct ifnet * ifp = NULL;
	struct ng_mesg *resp = NULL;
	hook_p hook;
	int error = 0;
	if (priv != NULL) {
		ifp = priv->ifp;
	}

	switch (msg->header.typecookie) {
	case NGM_EIFACE_COOKIE:
		switch (msg->header.cmd) {

	case NGM_EIFACE_SET_IFNAME:
	{
		priv_p old_priv;
		struct ng_eiface_ifname *arg;
		char ifname[NG_EIFACE_EIFACE_NAME_MAX + 1];

		arg = (struct ng_eiface_ifname *) msg->data;

		/* copy the ifname in a local buffer and ensure that it is
		 * 0-terminated */
		strlcpy(ifname, arg->ngif_name, sizeof(ifname));
		if (strlen(ifname) == 0) {
			error = EINVAL;
			break;
		}
		if (ifp != NULL) {
			error = EINVAL;
			break;
		}

		/* Check that the name isn't already used */
		if (ng_findname(node, ifname) != NULL) {
			log(LOG_ERR, "%s: NGM_EIFACE_SET_IFNAME %s already used\n",
					node->name, ifname);
			error = EEXIST;
			break;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
		/* Allocate 128 TX queues to scale better when TX mapping is selected
		 * from RX recorded queue.
		 */
		ifp = alloc_netdev_mq(sizeof(*priv), ifname,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
				      NET_NAME_USER,
#endif
				      ether_setup, 128);
#else
		ifp = alloc_netdev(sizeof(*priv), ifname, ether_setup);
#endif

		if(ifp == NULL) {
		    VNB_TRAP();
		    error = ENOMEM;
				break;
		}
		/*
		 * For possible further encaps, as in dev_alloc_skb()
		 * take care to have more than strict ethernet header
		 * 64 is more than enough
		 * XXX: check if we can remove this
		 */
		ifp->needed_headroom += 64;
		ifp->features |= NETIF_F_SG | NETIF_F_IP_CSUM;

		old_priv = priv;
#ifdef __LinuxKernelVNB__
		priv = netdev_priv(ifp);
#else
		priv = (priv_p)ifp->priv;
#endif
		/* a node->private was allocated for mac address */
		if (old_priv != NULL) {
			memcpy(priv, old_priv, sizeof(*priv));
			FREE(old_priv, M_NETGRAPH);
		}

		ifp->priv_flags &= ~IFF_XMIT_DST_RELEASE;
		ifp->netdev_ops = &ng_eiface_ops;
		ifp->destructor	= free_netdev;
		ifp->tx_queue_len = 0;
		ifp->rtnl_link_ops = &ng_eiface_link_ops;

		memcpy(ifp->dev_addr, &priv->eaddr, VNB_ETHER_ADDR_LEN);
		/* Link together node and private info */
		ng_set_node_private(node, priv);
		priv->node = node;
		priv->ifp = ifp;

		error = register_netdev(ifp);

		if(error < 0) {
			printk(KERN_INFO "register_netdevice(%s) return %d\n",ifp->name, error);
			free_netdev(ifp);
			node->private = NULL;
			break;
		}

		hook = ng_findhook(node, NG_EIFACE_HOOK_ETHER);
		if (hook != NULL) {
			priv->ether = hook;
			hook->private = &priv->ether;
			netif_carrier_on(priv->ifp);
		}
		else {
			netif_carrier_off(priv->ifp);
		}

		break;
	}

		case NGM_EIFACE_SET:
		{
		      struct ng_eiface_par *eaddr;

		      if (msg->header.arglen != sizeof(struct ng_eiface_par)) {
			      error = EINVAL;
			      break;
		      }
		      /* only allowed when interface does not exist */
		      if (ifp != NULL) {
			      error = EINVAL;
			      break;
		      }
		      if (priv == NULL) {
			      /* Allocate and initialize private info */
			      MALLOC(priv, priv_p, sizeof(*priv), M_NETGRAPH, M_NOWAIT);
			      if (priv == NULL)
				      error = ENOMEM;
			      bzero(priv, sizeof(*priv));
			      node->private = priv;
		      }
		      eaddr = (struct ng_eiface_par *)(msg->data);
		      memcpy(&priv->eaddr, eaddr, VNB_ETHER_ADDR_LEN);
		      break;
		}

		case NGM_EIFACE_GET_IFNAME:
		    {
			struct ng_eiface_ifname *arg;

			NG_MKRESPONSE(resp, msg, sizeof(*arg), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			if (ifp == NULL) {
				error = EINVAL;
				break;
			}
			arg = (struct ng_eiface_ifname *) resp->data;
			snprintf(arg->ngif_name, sizeof(arg->ngif_name),
			    "%s", ifp->name);
			break;
		    }

		case NGM_EIFACE_GET_IFADDRS:
			printk(KERN_INFO "NGM_EIFACE_GET_IFADDRS not supported\n");
			return EINVAL;

		default:
			error = EINVAL;
			break;
		}
		break;
	default:
		error = EINVAL;
		break;
	}
	if (rptr)
		*rptr = resp;
	else if (resp)
		FREE(resp, M_NETGRAPH);
	FREE(msg, M_NETGRAPH);
	return (error);
}

/*
 * Recive data from a hook. Pass the packet to the ether_input routine.
 */
static int
ng_eiface_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p priv = hook->node_private;
	struct ifnet *ifp;

	if ((priv == NULL) || (priv->ifp == NULL)) {
		m_freem(m);
		return (ENETDOWN);
	}

	ifp = priv->ifp;

	/* Meta-data is end its life here... */
	NG_FREE_META(meta);

	if (m == NULL) {
	    log(LOG_ERR, "ng_eiface: mbuf is null.\n");
	    return (EINVAL);
	}

	if ( !(ifp->flags & IFF_UP) ) {
		m_freem(m);
		return (ENETDOWN);
	}

	__kcompat_skb_tunnel_rx(m, ifp, packet_net(m));

	/* Note receiving interface */
	m->dev = ifp;
	/*
	 * current packet type is likely to be PACKET_OTHER
	 * let think it is for us, eth_type_trans() will
	 * change it if need
	 */
	m->pkt_type = PACKET_HOST;
	/*
	 * eth_type_trans() keep current data to mac.raw,
	 * pull data dev->hard_header_len bytes
	 */
	m->protocol = eth_type_trans(m, ifp);

	ifp->stats.rx_packets++;
	ifp->stats.rx_bytes += m->len;
	skb_dst_drop(m);
	/* m->h.raw = m->nh.raw = m->data; this is done in netif_receive() */
	nf_reset(m);
	netif_rx(m);
	return 0;
}

/*
 * Because the BSD networking code doesn't support the removal of
 * networking interfaces, iface nodes (once created) are persistent.
 * So this method breaks all connections and marks the interface
 * down, but does not remove the node.
 */
static int
ng_eiface_rmnode(node_p node)
{
	const priv_p	priv = NG_NODE_PRIVATE(node);

	node->flags |= NG_INVALID;

	if (priv != NULL) {
		struct ifnet	*ifp = priv->ifp;

		NG_NODE_SET_PRIVATE(node, NULL);
		if (ifp)
			/* will free private data when no one use it anymore */
			unregister_netdev(ifp);
		else
			ng_free(priv);
	}

	ng_cutlinks(node);
	ng_unname(node);

	/* Unref node */
	NG_NODE_UNREF(node);
	return (0);
}

/*
 * This is called once we've already connected a new hook to the other node.
 * It gives us a chance to balk at the last minute.
 */
static int
ng_eiface_connect(hook_p hook)
{
	/* be really amiable and just say "YUP that's OK by me! " */
	return (0);
}

/*
 * Hook disconnection
 */
static int
ng_eiface_disconnect(hook_p hook)
{
	const priv_p priv = hook->node->private;

	if (priv != NULL) {
		priv->ether = NULL;
		if ( priv->ifp ) {
			netif_carrier_off(priv->ifp);
		}
	}
	return (0);
}

static struct ng_nl_nodepriv *
ng_eiface_dumpnode(node_p node)
{
	struct ng_nl_nodepriv *nlnodepriv;
	struct ng_eiface_ifname *ifname;
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ifnet *ifp = NULL;

	if (!priv)
		return NULL;

	ifp = priv->ifp;
	if (!ifp)
		return NULL;

	MALLOC(nlnodepriv, struct ng_nl_nodepriv *,
	       sizeof(*nlnodepriv) + sizeof(*ifname), M_NETGRAPH, M_NOWAIT | M_ZERO);

	if (!nlnodepriv)
		return NULL;

	nlnodepriv->data_len = sizeof(*ifname);
	ifname = (struct ng_eiface_ifname *)nlnodepriv->data;

	snprintf(ifname->ngif_name, sizeof(ifname->ngif_name),
		 "%s", ifp->name);

	return nlnodepriv;
}

static int __init ng_local_eiface_init(void)
{
	int err;

	err = vnb_rtnl_link_register(&ng_eiface_link_ops);
	if (err < 0)
		goto out_rtnl_link;

	err =  ng_eiface_init();
	if (err < 0)
		goto out_ng_eiface;

	return 0;

out_ng_eiface:
	vnb_rtnl_link_unregister(&ng_eiface_link_ops);
out_rtnl_link:
	return err;
}

static void __exit ng_local_eiface_exit(void)
{
	vnb_rtnl_link_unregister(&ng_eiface_link_ops);
	ng_eiface_exit();
}

module_init(ng_local_eiface_init);
module_exit(ng_local_eiface_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB eiface node");
MODULE_LICENSE("6WIND");
