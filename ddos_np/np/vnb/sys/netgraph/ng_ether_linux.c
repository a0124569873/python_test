
/*
 * ng_ether.c
 *
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
 * Copyright 2004-2013 6WIND S.A.
 */

/*
 * ng_ether(4) netgraph node type
 */

#include <linux/version.h>
#include <linux/module.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <linux/ctype.h> /* for isdigit */
#include <net/dst.h>
#include <net/xfrm.h>
#include <linux/pkt_cls.h>
#include <netgraph_linux/ng_rxhandler.h>
#include <netgraph/vnblinux.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_ether.h>
#include <netgraph/vnb_ether.h>

#if defined(CONFIG_VNB_ETHER_MAX_LOWER_IN)
#define NG_ETHER_MAX_LOWER_IN CONFIG_VNB_ETHER_MAX_LOWER_IN
#else
#define NG_ETHER_MAX_LOWER_IN 64
#endif

/* Per-node private data */
struct private {
	struct ifnet	*ifp;		/* associated interface */
	hook_p		upper;		/* upper hook connection */
	hook_p		lower;		/* lower OR orphan hook connection */
	hook_p		lower_in[NG_ETHER_MAX_LOWER_IN];	/* lower input hooks */
	hook_p		attach;		/* attach hook */
	u_char		lowerOrphan;	/* whether lower is lower or orphan */
	u_char		autoSrcAddr;	/* always overwrite source address */
};
typedef struct private *priv_p;

typedef unsigned long *hookpriv_p;

/* Functional hooks called from net/core.c */
static int	ng_ether_input(struct sk_buff **pskb);

static int	ng_ether_attach(struct ifnet *ifp);
static int	ng_ether_detach(struct ifnet *ifp);

/* Other functions */
static int	ng_ether_rcv_lower(hook_p hook, struct mbuf *m, meta_p meta);
static int	ng_ether_rcv_upper(hook_p hook, struct mbuf *m, meta_p meta);

/* Netgraph node methods */
static ng_constructor_t	ng_ether_constructor;
static ng_rcvmsg_t	ng_ether_rcvmsg;
static ng_shutdown_t	ng_ether_rmnode;
static ng_newhook_t	ng_ether_newhook;
static ng_connect_t	ng_ether_afterconnect;
static ng_rcvdata_t	ng_ether_rcvdata;
static ng_disconnect_t	ng_ether_disconnect;

/* Parse type for an Ethernet address */
static ng_parse_t	ng_enaddr_parse;
static ng_unparse_t	ng_enaddr_unparse;
const struct ng_parse_type ng_ether_enaddr_type = {
	NULL,
	NULL,
	NULL,
	ng_enaddr_parse,
	ng_enaddr_unparse,
	NULL,			/* no such thing as a "default" EN address */
	0
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_ether_cmdlist[] = {
	{
	  NGM_ETHER_COOKIE,
	  NGM_ETHER_GET_IFNAME,
	  "getifname",
	  NULL,
	  &ng_parse_string_type
	},
	{
	  NGM_ETHER_COOKIE,
	  NGM_ETHER_SET_IFNAME,
	  "setifname",
	  &ng_parse_string_type,
	  NULL
	},
	{
	  NGM_ETHER_COOKIE,
	  NGM_ETHER_GET_IFINDEX,
	  "getifindex",
	  NULL,
	  &ng_parse_int32_type
	},
	{
	  NGM_ETHER_COOKIE,
	  NGM_ETHER_GET_ENADDR,
	  "getenaddr",
	  NULL,
	  &ng_ether_enaddr_type
	},
	{
	  NGM_ETHER_COOKIE,
	  NGM_ETHER_SET_ENADDR,
	  "setenaddr",
	  &ng_ether_enaddr_type,
	  NULL
	},
	{
	  NGM_ETHER_COOKIE,
	  NGM_ETHER_GET_AUTOSRC,
	  "getautosrc",
	  NULL,
	  &ng_parse_int32_type
	},
	{
	  NGM_ETHER_COOKIE,
	  NGM_ETHER_SET_AUTOSRC,
	  "setautosrc",
	  &ng_parse_int32_type,
	  NULL
	},
	{
	  NGM_ETHER_COOKIE,
	  NGM_ETHER_ATTACH_INTERFACE,
	  "attach",
	  &ng_parse_string_type,
	  NULL
	},
	{ 0 }
};

static VNB_DEFINE_SHARED(struct ng_type, ng_ether_typestruct) = {
	.version   = NG_VERSION,
	.name      = NG_ETHER_NODE_TYPE,
	.mod_event = NULL,
	.constructor=ng_ether_constructor,
	.rcvmsg    = ng_ether_rcvmsg,
	.shutdown  = ng_ether_rmnode,
	.newhook   = ng_ether_newhook,
	.findhook  = NULL,
	.connect   = NULL,
	.afterconnect = ng_ether_afterconnect,
	.rcvdata   = ng_ether_rcvdata,
	.rcvdataq  = ng_ether_rcvdata,
	.disconnect= ng_ether_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist   = ng_ether_cmdlist,
};
NETGRAPH_INIT(ether, &ng_ether_typestruct);
NETGRAPH_EXIT(ether, &ng_ether_typestruct);

/******************************************************************
		    ETHERNET FUNCTION HELPERS
******************************************************************/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
static struct sk_buff *ng_ether_rx_handler(struct sk_buff *skb);
#else
static rx_handler_result_t ng_ether_rx_handler(struct sk_buff **pskb);
#endif

/******************************************************************
		    ETHERNET FUNCTION HOOKS
******************************************************************/

static int ng_ether_input2(struct sk_buff **pskb, const priv_p priv, const hook_p);
/*
 * Handle a packet that has come in on an interface. We get to
 * look at it here before any upper layer protocols do.
 *
 */
static int
ng_ether_input(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	const struct net_device *dev = skb->dev;
	node_p node;
	priv_p priv;
	int ret = 0;

	VNB_ENTER();

	/* called under rcu_read_lock() from netif_receive_skb */
#ifdef USE_MACVLAN_HOOK
	node = (node_p)rcu_dereference(dev->macvlan_port);
#else
	node = (node_p)rcu_dereference(dev->rx_handler_data);
#endif
	if (!node) {
		ret = NET_RX_DROP;
		goto vnb_exit;
	}

	priv = node->private;
	if (!priv) {
		ret = NET_RX_DROP;
		goto vnb_exit;
	}

	/* If "lower" hook not connected, let packet continue */
	if (priv->lower == NULL || priv->lowerOrphan)
		goto vnb_exit;

	/* default: send to lower (connected) */
	ret = ng_ether_input2(pskb, priv, priv->lower);

vnb_exit:
	/* No more need for the node */
	VNB_EXIT();
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
static struct sk_buff *ng_ether_rx_handler(struct sk_buff *skb)
{
	if (skb->pkt_type == PACKET_LOOPBACK ||
	    VNB_CB(skb).vnb_magic == VNB_MAGIC_SKIP) {
		VNB_CB(skb).vnb_magic = 0;
		return skb;
	}

	if (ng_ether_input(&skb) != 0) {
		kfree(skb);
		skb = NULL;
	}

	return skb;
}
#else
static rx_handler_result_t ng_ether_rx_handler(struct sk_buff **pskb)
{
	if ((*pskb)->pkt_type == PACKET_LOOPBACK ||
	    VNB_CB(*pskb).vnb_magic == VNB_MAGIC_SKIP) {
		VNB_CB(*pskb).vnb_magic = 0;
		return RX_HANDLER_PASS;
	}

	if (ng_ether_input(pskb) != 0) {
		kfree(*pskb);
		*pskb = NULL;
	}

	if (*pskb == NULL)
		return RX_HANDLER_CONSUMED;

	return RX_HANDLER_PASS;
}
#endif

static int
ng_ether_input2(struct sk_buff **pskb, const priv_p priv, hook_p nexthook)
{
	struct sk_buff *skb = *pskb;
	meta_p meta = NULL;
	int error = 0;

	/* required ? */
	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
		*pskb = NULL;
		return NET_RX_DROP;
	}
	/* data pointer is on data layer (eg VLAN, IP)
	 * Before delivering skb, linux net drivers
	 * save into skb->mac.ethernet a pointer
	 * on ethernet header and  move data pointer
	 * after ethernet header.
	 * For convenience with netgraph nodes (vlan,ppp),
	 * we push the data to rebuild ethernet-like header.
	 */
	skb_push(skb, sizeof(struct ethhdr));
	/* Send out lower/orphan hook */
	/* NG_SEND_DATA actually send the data */
	NG_SEND_DATA(error, nexthook, skb, meta);
	*pskb = NULL;
	return error;
}

/*
 * A new Ethernet interface has been attached.
 * Create a new node for it, etc.
 */
static int
ng_ether_attach(struct ifnet *ifp)
{
	char name[IFNAMSIZ + 1];
	priv_p priv;
	node_p node;
	int err;

	/* Create node */
	snprintf(name, sizeof(name), "%s", ifp->name);

	/* Called from netdevice event, make sure to take ref count on module.
	 * For this, don't call constructor directly, but generic API instead
	 */
	if ((err = ng_make_node(NG_ETHER_NODE_TYPE, &node, 0))) {
		VNB_TRAP();
		log(LOG_ERR, "%s: can't %s for %s\n", __FUNCTION__, "create node", name);
		return err;
	}

	priv = node->private;
	priv->ifp = ifp;

	err = vnb_linux_dev_create(ifp, node);
	if (err < 0) {
		VNB_TRAP();
		return -err;
	}

	/* Try to give the node the same name as the interface */
	if (ng_name_node(node, name) != 0) {
		VNB_TRAP();
		log(LOG_WARNING, "%s: can't name node %s\n",
		    __FUNCTION__, name);
	}
	return err;
}

/*
 * An Ethernet interface is being detached.
 * Destroy its node.
 */
static int
ng_ether_detach(struct ifnet *ifp)
{
	int ret;
	node_p node;
	struct vnb_linux_dev *vdev;

	if ((vdev = vnb_linux_dev_find(ifp)) == NULL)
		return 0;

	node = vdev->node;

	/* Check if it's already shutting down */
	if ((node->flags & NG_INVALID) != 0)
		return 0;

	/* Add an extra reference so it doesn't go away during this */
	NG_NODE_REF(node);

	/* Mark it invalid so any newcomers know not to try use it */
	node->flags |= NG_INVALID;

	if (atomic_add_unless(&vdev->has_rx_handler, -1, 0))
		vnb_netdev_rx_handler_unregister(ifp);

	ret = ng_ether_rmnode(node);

	/* Remove extra reference, possibly the last */
	NG_NODE_UNREF(node);

	return ret;
}

/******************************************************************
		    NETGRAPH NODE METHODS
******************************************************************/

/*
 * Ethernet node constructor
 */
static int
ng_ether_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int error;

	/* Call superclass constructor that mallocs *nodep */
	if ((error = ng_make_node_common_and_priv(&ng_ether_typestruct, nodep,
						  &priv, sizeof(*priv), nodeid))) {
		return (error);
	}
	bzero(priv, sizeof(*priv));
	NG_NODE_SET_PRIVATE(*nodep, priv);

	return (0);
}

/*
 * Check for attaching a new hook.
 */
static	int
ng_ether_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = node->private;
	u_char orphan = priv->lowerOrphan;
	hook_p *hookptr;

	/* Don't allow hook creation if we are not attached to an interface */
	if ( unlikely(!(priv->ifp)) && strcmp(name, NG_ETHER_HOOK_ATTACH) )
		return (EINVAL);

	/* Which hook? */
	if (strcmp(name, NG_ETHER_HOOK_UPPER) == 0)
		hookptr = &priv->upper;
	else if (strcmp(name, NG_ETHER_HOOK_LOWER) == 0) {
		hookptr = &priv->lower;
		orphan = 0;
	} else if (strcmp(name, NG_ETHER_HOOK_ORPHAN) == 0) {
		hookptr = &priv->lower;
		orphan = 1;
	} else if (strcmp(name, NG_ETHER_HOOK_ATTACH) == 0) {
		hookptr = &priv->attach;
	} else if (strncmp(name, NG_ETHER_HOOK_LOWER_PREFIX,
			   sizeof (NG_ETHER_HOOK_LOWER_PREFIX) - 1) == 0) {
		const char     *tag_str;
		char           *err_ptr;
		unsigned long   tag;
		hookpriv_p      hpriv;

		/* Get the link index Parse link_0xa, link_10, ... */
		tag_str = name + sizeof(NG_ETHER_HOOK_LOWER_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0')
			return (EINVAL);

		if (tag >= NG_ETHER_MAX_LOWER_IN)
			return (EINVAL);

		/* Do not connect twice a nomatch hook */
		if (priv->lower_in[tag] != NULL)
			return (EISCONN);

		/* Register the per-link private data */

#if !defined(M_ZERO)
		hpriv = ng_malloc(sizeof(*hpriv), M_NOWAIT);
#else
		hpriv = ng_malloc(sizeof(*hpriv), M_NOWAIT | M_ZERO);
#endif
		if (hpriv == NULL)
			return (ENOMEM);

#if !defined(M_ZERO)
		bzero(hpriv, sizeof(*hpriv));
#endif
		*hpriv = tag;
		NG_HOOK_SET_PRIVATE(hook, hpriv);

		priv->lower_in[tag] = hook;

		return 0;
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
ng_ether_afterconnect(hook_p hook)
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
#ifndef USE_MACVLAN_HOOK
		                                     ng_ether_rx_handler,
#endif
		                                     node);
		if (err != 0)
			atomic_add_unless(&vdev->has_rx_handler, -1, 0);
	}
	rtnl_unlock();

	if (err < 0) {
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
ng_ether_rcvmsg(node_p node, struct ng_mesg *msg,
	const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const priv_p priv = node->private;
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_ETHER_COOKIE:
		switch (msg->header.cmd) {
		case NGM_ETHER_GET_IFNAME:
			NG_MKRESPONSE(resp, msg, IFNAMSIZ + 1, M_NOWAIT);
			if (priv->ifp == NULL) {
				error = ENOTCONN;
				break;
			}
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			snprintf(resp->data, IFNAMSIZ + 1,
			    "%s", priv->ifp->name);
			break;
		case NGM_ETHER_SET_IFNAME:
		    {
			char *node_name;

			if (node->numhooks != 0) {
				error = EINVAL;
				break;
			}

			node_name = ng_malloc(IFNAMSIZ + 1, M_NOWAIT);
			if (node_name == NULL) {
				error = ENOMEM;
				break;
			}
			snprintf(node_name, IFNAMSIZ + 1, "%s",
				 (char *)msg->data);

			ng_unname(node);
			node->name = node_name;
			ng_rehash_node(node);
			break;
		    }
		case NGM_ETHER_GET_IFINDEX:
			NG_MKRESPONSE(resp, msg, sizeof(u_int32_t), M_NOWAIT);
			if (priv->ifp == NULL) {
				error = ENOTCONN;
				break;
			}
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			*((u_int32_t *)resp->data) = priv->ifp->ifindex;
			break;
		case NGM_ETHER_GET_ENADDR:
			NG_MKRESPONSE(resp, msg, VNB_ETHER_ADDR_LEN, M_NOWAIT);
			if (priv->ifp == NULL) {
				error = ENOTCONN;
				break;
			}
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			memcpy(resp->data, priv->ifp->dev_addr, VNB_ETHER_ADDR_LEN);
			break;
		case NGM_ETHER_SET_ENADDR:
		    {
			if (priv->ifp == NULL) {
				error = ENOTCONN;
				break;
			}
			if (msg->header.arglen != VNB_ETHER_ADDR_LEN) {
				error = EINVAL;
				break;
			}
			memcpy(priv->ifp->dev_addr, msg->data,  VNB_ETHER_ADDR_LEN);
			break;
		    }
		case NGM_ETHER_GET_AUTOSRC:
			NG_MKRESPONSE(resp, msg, sizeof(u_int32_t), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			*((u_int32_t *)resp->data) = priv->autoSrcAddr;
			break;
		case NGM_ETHER_SET_AUTOSRC:
			if (msg->header.arglen != sizeof(u_int32_t)) {
				error = EINVAL;
				break;
			}
			priv->autoSrcAddr = !!*((u_int32_t *)msg->data);
			break;
		case NGM_ETHER_ATTACH_INTERFACE:
		    {
			struct ifnet *ifp;

			ifp = dev_get_by_name(&init_net, (char *)msg->data);
			if (ifp == NULL) {
				error = EINVAL;
				break;
			}

			priv->ifp = ifp;
			if ((error = vnb_linux_dev_create(ifp, node))) {
				dev_put(ifp);
				break;
			}

			/* If node is already named, check that it matches */
			if (node->name) {
				if (strcmp(node->name, (char *)msg->data)) {
					error = EINVAL;
					dev_put(ifp);
					break;
				}
			} else	if ((error = ng_name_node(node, (char *)msg->data))) {
				dev_put(ifp);
				break;
			}

			dev_put(ifp);
			break;
		    }
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
 * Receive data on a hook.
 */
static int
ng_ether_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p priv = hook->node_private;
	hookpriv_p hpriv = NG_HOOK_PRIVATE(hook);

	if (!priv) {
		kfree_skb(m);
		return ENETDOWN;
	}

	if ((hook == priv->lower) ||
	    ((hpriv != NULL) && (hook == priv->lower_in[*hpriv])))
		return ng_ether_rcv_lower(hook, m, meta);
	if (hook == priv->upper)
		return ng_ether_rcv_upper(hook, m, meta);
	NG_FREE_DATA(m, meta);
	return ENETDOWN;
}

/*
 * Handle an mbuf received on the "lower" hook.
 */
static int
ng_ether_rcv_lower(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p priv = hook->node_private;
	struct net_device *dev;

	/* Discard meta info */
	NG_FREE_META(meta);

	if (!priv) {
		kfree_skb(m);
		return (ENETDOWN);
	}
	dev = priv->ifp;

	/* Interface might not be attached */
	if (!dev) {
		kfree_skb(m);
		return (ENETDOWN);
	}

	/* Check whether interface is ready for packets */
	if (!(dev->flags & IFF_UP)) {
		kfree_skb(m);
		return (ENETDOWN);
	}

	if (m->len < sizeof(struct vnb_ether_header)) {
		kfree_skb(m);
		return (EINVAL);
	}
	if (!pskb_may_pull(m, sizeof(struct vnb_ether_header))) {
		kfree_skb(m);
		return (EINVAL);
	}

	/* Drop in the MAC address if desired */
	if (priv->autoSrcAddr||
		( (mtod(m, struct vnb_ether_header *)->ether_shost[5] == 0) &&
		(mtod(m, struct vnb_ether_header *)->ether_shost[4] == 0) &&
		(mtod(m, struct vnb_ether_header *)->ether_shost[3] == 0) &&
		(mtod(m, struct vnb_ether_header *)->ether_shost[2] == 0) &&
		(mtod(m, struct vnb_ether_header *)->ether_shost[1] == 0) &&
		(mtod(m, struct vnb_ether_header *)->ether_shost[0] == 0) )
		) {

		/* Overwrite source MAC address */
		memcpy(mtod(m, struct vnb_ether_header *)->ether_shost, priv->ifp->dev_addr, VNB_ETHER_ADDR_LEN);

	}
	skb_reset_network_header(m);

	m->dev = dev;
#ifdef CONFIG_XFRM
	secpath_put(m->sp);
	m->sp = NULL;
#endif
	skb_dst_drop(m);
	nf_reset(m);

	return dev_queue_xmit(m);
}

/*
 * Handle an mbuf received on the "upper" hook.
 */
static int
ng_ether_rcv_upper(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p priv = hook->node_private;
	struct vnb_ether_header *eh;

	/* Discard meta info */
	NG_FREE_META(meta);

	/* Interface might not be attached */
	if ( (!priv) || (!priv->ifp) ) {
		m_freem(m);
		return (EINVAL);
	}

	/* Check length and pull off header */
	if (m->len < sizeof(*eh))
	{
		m_freem(m);
		return (EINVAL);
	}
	if (!pskb_may_pull(m, sizeof(*eh))) {
		kfree_skb(m);
		return (EINVAL);
	}
	eh = mtod(m, struct vnb_ether_header *);
	m->dev = priv->ifp;

	/* skb_reset_mac_header(skb); done by eth_type_trans below */

	m->protocol = eth_type_trans(m, priv->ifp);

#ifndef CONFIG_NET_CLS_ACT
#error "CONFIG_NET_CLS_ACT must be set"
#endif
	m->tc_verd = SET_TC_NCLS(m->tc_verd);
	VNB_CB(m).vnb_magic = VNB_MAGIC_SKIP;

	/* Route packet back in */
	return netif_receive_skb(m);
}

/*
 * Shutdown node
 */
static int
ng_ether_rmnode(node_p node)
{
	priv_p priv = node->private;
	struct ifnet *ifp = priv->ifp;

	ng_unname(node);		/* free name (and its reference) */
	ng_cutlinks(node);		/* break all links to other nodes */
	NG_NODE_SET_PRIVATE(node, NULL);
	ng_unref(node);			/* free node itself */

	if (ifp)
		vnb_linux_dev_delete(ifp);

	return 0;
}

/*
 * Hook disconnection.
 */
static int
ng_ether_disconnect(hook_p hook)
{
	node_p node = hook->node;
	const priv_p priv = node->private;
	hookpriv_p hpriv = NG_HOOK_PRIVATE(hook);
	struct vnb_linux_dev *vdev;

	if (hook == priv->upper) {
		priv->upper = NULL;
	} else if (hook == priv->lower) {
		priv->lower = NULL;
		priv->lowerOrphan = 0;
	} else if ((hpriv != NULL) && (hook == priv->lower_in[*hpriv])){
		priv->lower_in[*hpriv] = NULL;
		NG_HOOK_SET_PRIVATE(hook, NULL);
		ng_free(hpriv);
	} else if (hook == priv->attach) {
		priv->attach = NULL;
	} else
		panic("%s: weird hook", __FUNCTION__);

	if (node->numhooks == 0) {
		if ((vdev = vnb_linux_dev_find(priv->ifp)) == NULL)
			return 0;

		if (atomic_add_unless(&vdev->has_rx_handler, -1, 0)) {
			/* The rtnl lock is already taken only if we come from
			   vnb_ether_device_event(), but if so, the rx handler
			   has already been unregistered by ng_ether_detach().
			*/
			rtnl_lock();
			vnb_netdev_rx_handler_unregister(priv->ifp);
			rtnl_unlock();
		}
	}
	return (0);
}

static int
ng_enaddr_parse(const struct ng_parse_type *type,
	const char *s, int *const off, const u_char *const start,
	u_char *const buf, int *const buflen)
{
	char *eptr;
	u_long val;
	int i;

	if (*buflen < VNB_ETHER_ADDR_LEN)
		return (ERANGE);
	for (i = 0; i < VNB_ETHER_ADDR_LEN; i++) {
		val = strtoul(s + *off, &eptr, 16);
		if (val > 0xff || eptr == s + *off)
			return (EINVAL);
		buf[i] = (u_char)val;
		*off = (eptr - s);
		if (i < VNB_ETHER_ADDR_LEN - 1) {
			if (*eptr != ':')
				return (EINVAL);
			(*off)++;
		}
	}
	*buflen = VNB_ETHER_ADDR_LEN;
	return (0);
}

static int
ng_enaddr_unparse(const struct ng_parse_type *type,
	const u_char *data, int *off, char *cbuf, int cbuflen)
{
	int len;

	len = snprintf(cbuf, cbuflen, "%02x:%02x:%02x:%02x:%02x:%02x",
	    data[*off], data[*off + 1], data[*off + 2],
	    data[*off + 3], data[*off + 4], data[*off + 5]);
	if (len >= cbuflen)
		return (ERANGE);
	*off += VNB_ETHER_ADDR_LEN;
	return (0);
}

static int vnb_ether_device_event(struct notifier_block *unused,
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

		if (dev->type == ARPHRD_ETHER) {
			ng_ether_attach(dev);
		}
		break;
	case NETDEV_UNREGISTER:
		/* Check if netdevice is just moving to another vrf
		 * (dev_change_[net_namespace|vrfid]()/ explicitly keeps this
		 * flag to inform that netdevice is not destroyed).
		 */
		if (dev->reg_state == NETREG_REGISTERED)
			return NOTIFY_DONE;

		if (dev->type == ARPHRD_ETHER) {
			ng_ether_detach(dev);
		}
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block vnb_ether_notifier_block __read_mostly = {
	.notifier_call  = vnb_ether_device_event,
};

/******************************************************************
			INITIALIZATION
******************************************************************/

/*
 * Handle loading and unloading for this node type.
 */
int ng_ether_init_module(void)
{
	int error;

        if ((error = ng_ether_init())) {
            return error;
        }

#ifdef USE_MACVLAN_HOOK
	netgraph_linux_set_macvlan_hook(ng_ether_rx_handler);
#endif
	register_netdevice_notifier(&vnb_ether_notifier_block);

	return 0;
}

void ng_ether_exit_module(void)
{
	unregister_netdevice_notifier(&vnb_ether_notifier_block);
#ifdef USE_MACVLAN_HOOK
	netgraph_linux_unset_macvlan_hook(ng_ether_rx_handler);
#endif
	ng_ether_exit();
}

EXPORT_SYMBOL(ng_ether_enaddr_type);

module_init(ng_ether_init_module);
module_exit(ng_ether_exit_module);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB ether node");
MODULE_LICENSE("6WIND");
