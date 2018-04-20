
/*
 * ng_raw.c
 *
 * Copyright 2005 6WIND S.A.
 * Copyright (c) 1996-2000 Whistle Communications, Inc.
 * All rights reserved.
 *
 * Subject to the following obligations and disclaimer of warranty, use and
 * redistribution of this software, in source or object code forms, with or
 * without modifications are expressly permitted by Whistle Communications;
 * provided, however, that:
 * 1. Any and all reproductions of the source or object code must include the
 *    copyright notice above and the following disclaimer of warranties; and
 * 2. No rights are granted, in any manner or form, to use Whistle
 *    Communications, Inc. trademarks, including the mark "WHISTLE
 *    COMMUNICATIONS" on advertising, endorsements, or otherwise except as
 *    such appears in the above copyright notice or in the software.
 *
 * THIS SOFTWARE IS BEING PROVIDED BY WHISTLE COMMUNICATIONS "AS IS", AND
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, WHISTLE COMMUNICATIONS MAKES NO
 * REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, REGARDING THIS SOFTWARE,
 * INCLUDING WITHOUT LIMITATION, ANY AND ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
 * WHISTLE COMMUNICATIONS DOES NOT WARRANT, GUARANTEE, OR MAKE ANY
 * REPRESENTATIONS REGARDING THE USE OF, OR THE RESULTS OF THE USE OF THIS
 * SOFTWARE IN TERMS OF ITS CORRECTNESS, ACCURACY, RELIABILITY OR OTHERWISE.
 * IN NO EVENT SHALL WHISTLE COMMUNICATIONS BE LIABLE FOR ANY DAMAGES
 * RESULTING FROM OR ARISING OUT OF ANY USE OF THIS SOFTWARE, INCLUDING
 * WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * PUNITIVE, OR CONSEQUENTIAL DAMAGES, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES, LOSS OF USE, DATA OR PROFITS, HOWEVER CAUSED AND UNDER ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF WHISTLE COMMUNICATIONS IS ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Authors: Archie Cobbs <archie@freebsd.org>
 *	    Julian Elischer <julian@freebsd.org>
 *
 * $FreeBSD: src/sys/netgraph/ng_ether.c,v 1.2.2.13 2002/07/02 20:10:25 archie Exp $
 */

/*
 * ng_raw netgraph node type
 */

#include <linux/version.h>
#include <linux/module.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netdevice.h>
//#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <linux/ctype.h> /* for isdigit */
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <netgraph_linux/ng_rxhandler.h>
#include <netgraph/vnblinux.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_raw.h>

/* Per-node private data */
struct private {
	struct ifnet	*ifp;		/* associated interface */
	hook_p		upper;		/* upper hook connection */
	hook_p		lower;		/* lower OR orphan hook connection */
	u_char		lowerOrphan;	/* whether lower is lower or orphan */
};
typedef struct private *priv_p;

static int	ng_raw_input(struct sk_buff **pskb);
static int	ng_raw_attach(struct ifnet *ifp);
static int	ng_raw_detach(struct ifnet *ifp);

/* Other functions */
static int	ng_raw_rcv_lower(hook_p hook, struct mbuf *m, meta_p meta);
static int	ng_raw_rcv_upper(hook_p hook, struct mbuf *m, meta_p meta);

/* Netgraph node methods */
static ng_constructor_t	ng_raw_constructor;
static ng_rcvmsg_t	ng_raw_rcvmsg;
static ng_shutdown_t	ng_raw_rmnode;
static ng_newhook_t	ng_raw_newhook;
static ng_connect_t	ng_raw_afterconnect;
static ng_disconnect_t	ng_raw_disconnect;

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_raw_cmdlist[] = {
	{
	  NGM_RAW_COOKIE,
	  NGM_RAW_GET_IFNAME,
	  "getifname",
	  NULL,
	  &ng_parse_string_type
	},
	{
	  NGM_RAW_COOKIE,
	  NGM_RAW_GET_IFINDEX,
	  "getifindex",
	  NULL,
	  &ng_parse_int32_type
	},
	{ 0 }
};

static VNB_DEFINE_SHARED(struct ng_type, ng_raw_typestruct) = {
	.version   = NG_VERSION,
	.name      = NG_RAW_NODE_TYPE,
	.mod_event = NULL,
	.constructor=ng_raw_constructor,
	.rcvmsg    = ng_raw_rcvmsg,
	.shutdown  = ng_raw_rmnode,
	.newhook   = ng_raw_newhook,
	.findhook  = NULL,
	.connect   = NULL,
	.afterconnect = ng_raw_afterconnect,
	.rcvdata   = NULL,			/* Only specific receive data functions */
	.rcvdataq  = NULL,
	.disconnect= ng_raw_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist   = ng_raw_cmdlist,
};
NETGRAPH_INIT(raw, &ng_raw_typestruct);
NETGRAPH_EXIT(raw, &ng_raw_typestruct);

/******************************************************************
		    RAW FUNCTION HOOKS
******************************************************************/

static int ng_raw_input2(struct sk_buff **pskb, const priv_p priv);
/*
 * Handle a packet that has come in on an interface. We get to
 * look at it here before any upper layer protocols do.
 *
 */
static int
ng_raw_input(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	const struct net_device *dev = skb->dev;
	node_p node;
	priv_p priv;
	int ret = 0;

	VNB_ENTER();

	/* called under rcu_read_lock() from netif_receive_skb */
	node = (node_p)rcu_dereference(dev->rx_handler_data);
	if (!node) {
		kfree_skb(skb);
		ret = NET_RX_DROP;
		goto vnb_exit;
	}

	priv = node->private;
	if (!priv) {
		kfree_skb(skb);
		ret = NET_RX_DROP;
		goto vnb_exit;
	}

	/* If "lower" hook not connected, let packet continue */
	if (priv->lower == NULL || priv->lowerOrphan)
		goto vnb_exit;
	ret = ng_raw_input2(pskb, priv);

vnb_exit:
	/* No more need for the node */
	VNB_EXIT();
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
static struct sk_buff *ng_raw_rx_handler(struct sk_buff *skb)
{
	if (skb->pkt_type == PACKET_LOOPBACK ||
	    VNB_CB(skb).vnb_magic == VNB_MAGIC_SKIP) {
		VNB_CB(skb).vnb_magic = 0;
		return skb;
	}

	if (ng_raw_input(&skb) != 0) {
		kfree(skb);
		skb = NULL;
	}

	return skb;
}
#else
static rx_handler_result_t ng_raw_rx_handler(struct sk_buff **pskb)
{
	if ((*pskb)->pkt_type == PACKET_LOOPBACK ||
	    VNB_CB(*pskb).vnb_magic == VNB_MAGIC_SKIP) {
		VNB_CB(*pskb).vnb_magic = 0;
		return RX_HANDLER_PASS;
	}

	if (ng_raw_input(pskb) != 0) {
		kfree(*pskb);
		*pskb = NULL;
	}

	if (*pskb == NULL)
		return RX_HANDLER_CONSUMED;

	return RX_HANDLER_PASS;
}
#endif

static int
ng_raw_input2(struct sk_buff **pskb, const priv_p priv)
{
	struct sk_buff *skb = *pskb;
	meta_p meta = NULL;
	int error = 0;

	/* required ? */
	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
		*pskb = NULL;
		return NET_RX_DROP;
	}

	/*
	 * XXX where is data pointer ?
	 */

	/* Send out lower/orphan hook */
	/* NG_SEND_DATA actually send the data */
	NG_SEND_DATA(error, priv->lower, skb, meta);
	*pskb = NULL;
	return 0;
}


/*
 * A new RAW interface has been attached.
 * Create a new node for it, etc.
 */
static int
ng_raw_attach(struct ifnet *ifp)
{
	char name[IFNAMSIZ + 1];
	priv_p priv;
	node_p node;
	int err;

	/* Create node */
	snprintf(name, sizeof(name), "raw_%s", ifp->name);

	if (ng_make_node_common(&ng_raw_typestruct, &node, 0) != 0) {
		VNB_TRAP();
		log(LOG_ERR, "%s: can't %s for %s\n", __FUNCTION__, "create node", name);
		return EINVAL;
	}

	/* Allocate private data */
	priv = ng_malloc(sizeof(*priv), M_NOWAIT);
	if (priv == NULL) {
		VNB_TRAP();
		log(LOG_ERR, "%s: can't %s for %s\n",
		    __FUNCTION__, "allocate memory", name);
		ng_unref(node);
		return ENOMEM;
	}
	bzero(priv, sizeof(*priv));
	node->private = priv;
	priv->ifp = ifp;

	err = vnb_linux_dev_create(ifp, node);
	if (err < 0) {
		VNB_TRAP();
		return -err;
	}

	/* Try to give the node the same name as the interface (with 'raw_' prefix) */
	if (ng_name_node(node, name) != 0) {
		VNB_TRAP();
		log(LOG_WARNING, "%s: can't name node %s\n",
		    __FUNCTION__, name);
	}
	return err;
}

/*
 * An RAW interface is being detached.
 * Destroy its node.
 */
static int
ng_raw_detach(struct ifnet *ifp)
{
	node_p node;
	struct vnb_linux_dev *vdev;
	priv_p priv;

	if ((vdev = vnb_linux_dev_find(ifp)) == NULL)
		return 0;

	node = vdev->node;

	ng_rmnode(node);		/* break all links to other nodes */
	node->flags |= NG_INVALID;

	if (atomic_add_unless(&vdev->has_rx_handler, -1, 0))
		vnb_netdev_rx_handler_unregister(ifp);

	ng_unname(node);		/* free name (and its reference) */
	priv = node->private;		/* free node private info */
	bzero(priv, sizeof(*priv));
	node->private = NULL;
	ng_free(priv);
	ng_unref(node);			/* free node itself */

	vnb_linux_dev_delete(ifp);

	return 0;
}

/******************************************************************
		    NETGRAPH NODE METHODS
******************************************************************/

/*
 * It is not possible or allowable to create a node of this type.
 * Nodes get created when the interface is attached (or, when
 * this node type's KLD is loaded).
 */
static int
ng_raw_constructor(node_p *nodep, ng_ID_t nodeid)
{
	return (EINVAL);
}

/*
 * Check for attaching a new hook.
 */
static	int
ng_raw_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = node->private;
	u_char orphan = priv->lowerOrphan;
	hook_p *hookptr;

	/* Divert hook is an alias for lower */
	if (strcmp(name, NG_RAW_HOOK_DIVERT) == 0)
		name = NG_RAW_HOOK_LOWER;

	/* Which hook? */
	if (strcmp(name, NG_RAW_HOOK_UPPER) == 0) {
		hookptr = &priv->upper;
		hook->hook_rcvdata = ng_raw_rcv_upper;
	}
	else if (strcmp(name, NG_RAW_HOOK_LOWER) == 0) {
		hookptr = &priv->lower;
		orphan = 0;
		hook->hook_rcvdata = ng_raw_rcv_lower;
	} else if (strcmp(name, NG_RAW_HOOK_ORPHAN) == 0) {
		hookptr = &priv->lower;
		orphan = 1;
	} else
		return (EINVAL);

	/* Check if already connected (shouldn't be, but doesn't hurt) */
	if (*hookptr != NULL)
		return (EISCONN);

	/* OK */
	*hookptr = hook;
	priv->lowerOrphan = orphan;
	return (0);
}

/*
 * Register rx handler at first hook connection
 */
static int
ng_raw_afterconnect(hook_p hook)
{
	node_p node = hook->node;
	priv_p priv = node->private;
	struct vnb_linux_dev *vdev;
	int err = 0;

	if (node->numhooks != 1)
		return err;

	if ((vdev = vnb_linux_dev_find(priv->ifp)) == NULL)
		return err;

	rtnl_lock();
	if (atomic_add_unless(&vdev->has_rx_handler, 1, 1)) {
		err = vnb_netdev_rx_handler_register(priv->ifp,
		                                     ng_raw_rx_handler,
		                                     node);
		if (err != 0)
			atomic_add_unless(&vdev->has_rx_handler, -1, 0);
	}
	rtnl_unlock();

	if (err < 0) {
		VNB_TRAP();
		log(LOG_WARNING,
		    "%s: rx_handler registration failed for %s",
		    __FUNCTION__, priv->ifp->name);
	}

	return err;
}

/*
 * Receive an incoming control message.
 */
static int
ng_raw_rcvmsg(node_p node, struct ng_mesg *msg,
	const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const priv_p priv = node->private;
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_RAW_COOKIE:
		switch (msg->header.cmd) {
		case NGM_RAW_GET_IFNAME:
			NG_MKRESPONSE(resp, msg, IFNAMSIZ + 1, M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			snprintf(resp->data, IFNAMSIZ + 1,
			    "%s", priv->ifp->name);
			break;
		case NGM_RAW_GET_IFINDEX:
			NG_MKRESPONSE(resp, msg, sizeof(u_int32_t), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			*((u_int32_t *)resp->data) = priv->ifp->ifindex;
			break;
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
	else if (resp != NULL)
		FREE(resp, M_NETGRAPH);
	FREE(msg, M_NETGRAPH);
	return (error);
}

/*
 * Handle an mbuf received on the "lower" hook.
 */
static int
ng_raw_rcv_lower(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p priv = hook->node_private;
	struct net_device *dev;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	dev = priv->ifp;
	/* Discard meta info */
	NG_FREE_META(meta);

	/* Check whether interface is ready for packets */
	if (!(dev->flags & IFF_UP)) {
		kfree_skb(m);
		return ENETDOWN;
	}

	/* Send it on its way */
	if (m->dev == dev) {
		/* VNB chain called from dev_queue_xmit */
		if (dev->netdev_ops->ndo_start_xmit(m, dev) != 0) {
			kfree_skb(m);
			return ENETDOWN;
		}
		return 0;
	}

	m->dev = dev;

	return -(dev_queue_xmit(m));
}

/*
 * Handle an mbuf received on the "upper" hook.
 */
static int
ng_raw_rcv_upper(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p priv = hook->node_private;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	/* Discard meta info */
	NG_FREE_META(meta);

	m->dev = priv->ifp;
	/* like netif_receive_skb() */
	skb_reset_mac_header(m);
	skb_reset_network_header(m);

	/* m->protocol  unchanged  XXX OK ? */
	/* m->type unchanged XXX OK ? */

#ifndef CONFIG_NET_CLS_ACT
#error "CONFIG_NET_CLS_ACT must be set"
#endif
	m->tc_verd = SET_TC_NCLS(m->tc_verd);
	VNB_CB(m).vnb_magic = VNB_MAGIC_SKIP;

	/* Route packet back in */
	return netif_receive_skb(m);
}

/*
 * Shutdown node. This resets the node but does not remove it.
 */
static int
ng_raw_rmnode(node_p node)
{
	ng_cutlinks(node);
	node->flags &= ~NG_INVALID;	/* bounce back to life */
	return (0);
}

/*
 * Hook disconnection.
 */
static int
ng_raw_disconnect(hook_p hook)
{
	node_p node = hook->node;
	const priv_p priv = node->private;
	struct vnb_linux_dev *vdev;

	if (hook == priv->upper) {
		priv->upper = NULL;
		hook->hook_rcvdata = NULL;
	} else if (hook == priv->lower) {
		priv->lower = NULL;
		priv->lowerOrphan = 0;
		hook->hook_rcvdata = NULL;
	} else
		panic("%s: weird hook", __FUNCTION__);

	if (node->numhooks == 0) {
		if ((vdev = vnb_linux_dev_find(priv->ifp)) == NULL)
			return 0;

		if (atomic_add_unless(&vdev->has_rx_handler, -1, 0)) {
			/* The rtnl lock is already taken only if we come from
			   vnb_ether_device_event(), but if so, the rx handler
			   has already been unregistered by ng_raw_detach().
			*/
			rtnl_lock();
			vnb_netdev_rx_handler_unregister(priv->ifp);
			rtnl_unlock();
		}
	}
	return (0);
}

static int vnb_raw_device_event(struct notifier_block *unused,
			    unsigned long event, void *ptr)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
	struct net_device *dev = ptr;
#else
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
#endif

	switch (event) {
	case NETDEV_REGISTER:
		/* Node exists, this is probably the notification after changing
		 * vrf.
		 */
		if (vnb_linux_dev_exist(dev))
			return NOTIFY_DONE;

		if (dev->type != ARPHRD_ETHER) {
			ng_raw_attach(dev);
		}
		break;
	case NETDEV_UNREGISTER:
		/* Check if netdevice is just moving to another vrf
		 * (dev_change_[net_namespace|vrfid]()/ explicitly keeps this
		 * flag to inform that netdevice is not destroyed).
		 */
		if (dev->reg_state == NETREG_REGISTERED)
			return NOTIFY_DONE;

		if (dev->type != ARPHRD_ETHER) {
			ng_raw_detach(dev);
		}
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block vnb_raw_notifier_block __read_mostly = {
	.notifier_call  = vnb_raw_device_event,
};

/******************************************************************
			INITIALIZATION
******************************************************************/

/*
 * Handle loading and unloading for this node type.
 */
int ng_raw_init_module(void)
{
	int error;
#ifdef notyet
	struct net_device *dev;
#endif

	if ((error = ng_raw_init())) {
		return error;
	}
	register_netdevice_notifier(&vnb_raw_notifier_block);

	return 0;
}

void ng_raw_exit_module(void)
{
#ifdef notyet
	struct net_device *dev;
#endif
	unregister_netdevice_notifier(&vnb_raw_notifier_block);
	ng_raw_exit();
}

#if defined(__LinuxKernelVNB__)
module_init(ng_raw_init_module);
module_exit(ng_raw_exit_module);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB raw node");
MODULE_LICENSE("6WIND");
#endif
