/*
 * ng_iface.c
 *
 * Copyright (c) 1996-1999 Whistle Communications, Inc.
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
 * Author: Archie Cobbs <archie@freebsd.org>
 *
 * $FreeBSD: src/sys/netgraph/ng_iface.c,v 1.7.2.5 2002/07/02 23:44:02 archie Exp $
 * $Whistle: ng_iface.c,v 1.33 1999/11/01 09:24:51 julian Exp $
 */
/*
 * Copyright 2004-2013 6WIND S.A.
 */

/*
 * This node is also a system networking interface. It has
 * a hook for each protocol (IP, AppleTalk, IPX, etc). Packets
 * are simply relayed between the interface and the hooks.
 *
 * Interfaces are named ng0, ng1, etc.  New nodes take the
 * first available interface name.
 *
 * This node also includes Berkeley packet filter support.
 */

#include <linux/version.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>
#include <linux/ctype.h>
#include <net/dst.h>
#include <linux/bitops.h> /* for ffs */
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_tunnel.h>
#include <asm/uaccess.h>
#include <netgraph/vnblinux.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_iface.h>
#include <net/sock.h>
#include <kcompat.h>

#include <net/rtnetlink.h>
#include <netgraph_linux/ng_netlink.h>

struct ifproto {
	uint16_t	protocol;
	const char	*hookname;	/* Name for hook */
};
typedef const struct ifproto *ifproto_p;

#define ETH_P_ALLIP 0

/* List of address protocols supported by our interface */
static const struct ifproto gProtocols[] = {
/* ALLIP MUST be the first */
	{ ETH_P_ALLIP,	NG_IFACE_HOOK_ALLIP },
	{ ETH_P_IP,	NG_IFACE_HOOK_INET	},
	{ ETH_P_IPV6,	NG_IFACE_HOOK_INET6	},
	{ ETH_P_ATALK,	NG_IFACE_HOOK_ATALK	},
#if defined(ETH_P_IPX)
	{ ETH_P_IPX,	NG_IFACE_HOOK_IPX	},
#endif
#if defined(ETH_P_ATMMPOA)
	{ ETH_P_ATMMPOA,	NG_IFACE_HOOK_ATM	},
#endif
#if defined(ETH_P_ATMFATE)
	{ ETH_P_ATMFATE,	NG_IFACE_HOOK_ATM	},
#endif
};
#define NUM_PROTOCOLS		(sizeof(gProtocols) / sizeof(*gProtocols))

/* Node private data */
struct ng_iface_private {
	struct	ifnet *ifp;		/* Our interface */
	node_p	node;			/* Our netgraph node */
	hook_p	hooks[NUM_PROTOCOLS];	/* Hook for each address family */
	uint16_t ifp_type;
	unsigned int ifp_carrier_set:1;
	unsigned int ifp_broadcast_set:1;
	unsigned int ifp_encapaddr_set:1;
	uint8_t ifp_addr_len;
	union {
		struct in_addr in;
		struct in6_addr in6;
		uint8_t buf[1];
	} ifp_dev_addr;
	union {
		struct in_addr in;
		struct in6_addr in6;
		uint8_t buf[1];
	} ifp_broadcast;
};
typedef struct ng_iface_private *priv_p;

struct ng_ifp_private {
	LIST_ENTRY(ng_ifp_private) placeholder;
	priv_p iface_priv;
	u_int32_t has_key;              /* designed for gre key */
	u_int32_t use_key;              /* designed for gre key */
};

/* Interface methods */
static int	ng_iface_output(struct sk_buff *, struct net_device *dev);

/* Netgraph methods */
static ng_constructor_t	ng_iface_constructor;
static ng_rcvmsg_t	ng_iface_rcvmsg;
static ng_shutdown_t	ng_iface_rmnode;
static ng_newhook_t	ng_iface_newhook;
static ng_rcvdata_t	ng_iface_rcvdata;
static ng_disconnect_t	ng_iface_disconnect;
static ng_dumpnode_t    ng_iface_dumpnode;

static int
ng_iface_rcvdata_allip_in(hook_p hook, struct mbuf *m, meta_p meta);

/* Helper stuff */
static ifproto_p	get_ifproto_from_proto(uint16_t proto);
static ifproto_p	get_ifproto_from_hook(priv_p priv, hook_p hook);
static ifproto_p	get_ifproto_from_name(const char *name);
static hook_p  *get_hook_from_ifproto(priv_p priv, ifproto_p ifproto);

/* Parse type for struct ng_iface_ifname */
static const struct ng_parse_fixedstring_info ng_iface_ifname_info = {
	NG_IFACE_IFACE_NAME_MAX + 1
};
static const struct ng_parse_type ng_iface_ifname_type = {
	&ng_parse_fixedstring_type,
	&ng_iface_ifname_info
};

/* Parse types for struct ng_iface_info */

static const struct ng_parse_struct_field ng_iface_info_fields[] = {
	{ "id", &ng_parse_hint32_type, 0 },
	{ "index", &ng_parse_uint32_type, 0 },
	{ "name", &ng_iface_ifname_type, 0 },
	{ NULL, NULL, 0 }
};

static const struct ng_parse_type ng_iface_info_type = {
	&ng_parse_struct_type,
	&ng_iface_info_fields
};

/* Parse type for struct ng_iface_key */
static const struct ng_parse_struct_field
       ng_iface_key_type_fields[] = NG_IFACE_KEY_TYPE_INFO;

static const struct ng_parse_type ng_iface_key_type = {
       .supertype = &ng_parse_struct_type,
       .info = &ng_iface_key_type_fields,
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_iface_cmds[] = {
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_GET_IFNAME,
	  "getifname",
	  NULL,
	  &ng_iface_ifname_type
	},
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_SET_IFNAME,
	  "setifname",
	  &ng_iface_ifname_type,
	  NULL
	},
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_SETGET_IFNAME,
	  "setgetifname",
	  &ng_iface_ifname_type,
	  &ng_iface_ifname_type
	},
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_GET_INFO,
	  "getinfo",
	  NULL,
	  &ng_iface_info_type
	},
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_SET_INFO,
	  "setinfo",
	  &ng_iface_info_type,
	  NULL
	},
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_SETGET_INFO,
	  "setgetinfo",
	  &ng_iface_info_type,
	  &ng_iface_info_type
	},
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_POINT2POINT,
	  "point2point",
	  NULL,
	  NULL
	},
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_BROADCAST,
	  "broadcast",
	  NULL,
	  NULL
	},
	/* 6WIND add-ons: */
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_GET_IFTYPE,
	  "getiftype",
	  NULL,
	  &ng_parse_uint16_type
	},
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_SET_IFTYPE,
	  "setiftype",
	  &ng_parse_uint16_type,
	  NULL
	},
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_SET_CARRIER,
	  "setcarrier",
	  &ng_parse_uint8_type,
	  NULL
	},
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_SET_ENCAPADDR,
	  "setencapaddr",
	  NULL, /* not usable in ascii : TODO */
	  NULL
	},
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_SET_KEY,
	  "setkey",
	  &ng_iface_key_type,
	  NULL,
	},
	{ 0 }
};

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, typestruct) = {
	.version   = NG_VERSION,
	.name      = NG_IFACE_NODE_TYPE,
	.mod_event = NULL,
	.constructor=ng_iface_constructor,
	.rcvmsg    = ng_iface_rcvmsg,
	.shutdown  = ng_iface_rmnode,
	.newhook   = ng_iface_newhook,
	.findhook  = NULL,
	.connect   = NULL,
	.afterconnect = NULL,
	.rcvdata   = ng_iface_rcvdata,
	.rcvdataq  = ng_iface_rcvdata,
	.disconnect= ng_iface_disconnect,
	.rcvexception = NULL,
	.dumpnode = ng_iface_dumpnode,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist   = ng_iface_cmds
};

#if NG_IFACE_TYPE == 0
NETGRAPH_INIT(iface, &typestruct);
NETGRAPH_EXIT(iface, &typestruct);
#endif

#ifdef ASYNCHRONOUS_NETDEV_REMOVAL

#ifdef CONFIG_PROC_FS
extern uint32_t unregister_bulksize;
#else
static uint32_t unregister_bulksize = 1024;

#endif

/* intermediate struct used to create a list of ifnet */
struct ifnet_element {
	/* space needed before ifp_priv data */
	char dummy[(ALIGN(sizeof(struct net_device), NETDEV_ALIGN))];
	LIST_ENTRY(ifnet_element) next;
};
/* local list of in-progress deleted netdevices */
LIST_HEAD(ng_ifnet_rm_dev_list, ifnet_element);
static struct ng_ifnet_rm_dev_list staging_rm_dev_list;
static struct callout timeout_handle;   /* see timeout(9) */
#endif

/************************************************************************
			HELPER STUFF
 ************************************************************************/

/*
 * Get the family descriptor from the family ID
 */
static inline ifproto_p
get_ifproto_from_proto(uint16_t proto)
{
	ifproto_p ifproto;
	unsigned int k;

	for (k = 0; k < NUM_PROTOCOLS; k++) {
		ifproto = &gProtocols[k];
		if (ifproto->protocol == proto)
			return (ifproto);
	}
	return (NULL);
}

/*
 * Get the family descriptor from the hook
 */
static inline ifproto_p
get_ifproto_from_hook(priv_p priv, hook_p hook)
{
	unsigned int k;

	for (k = 0; k < NUM_PROTOCOLS; k++)
		if (priv->hooks[k] == hook)
			return (&gProtocols[k]);
	return (NULL);
}

/*
 * Get the hook from the ifproto descriptor
 */

static inline hook_p *
get_hook_from_ifproto(priv_p priv, ifproto_p ifproto)
{
	return (&priv->hooks[ifproto - gProtocols]);
}

/*
 * Get the ifproto descriptor from the name
 */
static inline ifproto_p
get_ifproto_from_name(const char *name)
{
	ifproto_p ifproto;
	unsigned int k;

	for (k = 0; k < NUM_PROTOCOLS; k++) {
		ifproto = &gProtocols[k];
		if (!strcmp(ifproto->hookname, name))
			return (ifproto);
	}
	return (NULL);
}

static size_t ng_iface_get_size(const struct net_device *dev)
{
	size_t size;

	size = nla_total_size(4) + /* IFLA_GRE_IKEY */
	       nla_total_size(4);  /* IFLA_GRE_OKEY */

	return size;
}

static int ng_iface_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	const struct ng_ifp_private *t = (struct ng_ifp_private *)netdev_priv(dev);
	int err = 0;

	if (t->has_key) {
		/*
		 * We use the same value for in and out gre key for
		 * gre key in ng_gre node.
		 */
		err = nla_put_u32(skb, IFLA_GRE_IKEY, t->use_key);
		if (err < 0)
			goto nla_put_failure;

		err = nla_put_u32(skb, IFLA_GRE_OKEY, t->use_key);
		if (err < 0)
			goto nla_put_failure;
	}

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static void ng_iface_dellink(struct net_device *dev
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
			     , struct list_head *head
#endif
			    )
{
	priv_p priv = ((struct ng_ifp_private *)netdev_priv(dev))->iface_priv;
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

static struct rtnl_link_ops ng_iface_link_ops __read_mostly = {
	.kind			= "ng_iface",
	.get_size		= ng_iface_get_size,
	.fill_info		= ng_iface_fill_info,
	.dellink                = ng_iface_dellink,
};


/************************************************************************
			INTERFACE STUFF
 ************************************************************************/

/*
 * This routine is called to deliver a packet out the interface.
 * We simply look at the address family and relay the packet to
 * the corresponding hook, if it exists and is connected.
 */

static int
ng_iface_output(struct sk_buff *m, struct net_device *ifp) {
	struct ng_ifp_private *ifp_priv = (struct ng_ifp_private *)netdev_priv(ifp);
	priv_p priv;
	ifproto_p ifproto;
	hook_p hook;
	meta_p meta = NULL;
	int len, error = 0;

	VNB_ENTER();

	priv = ifp_priv->iface_priv;
	if (!priv) {
		ifp->stats.tx_errors++;
		kfree_skb(m);

		VNB_EXIT();

		return NETDEV_TX_OK;
	}

	if (m->ip_summed == CHECKSUM_PARTIAL)
		skb_checksum_help(m);

	switch (ntohs(m->protocol)) {
	case ETH_P_IP:
	case ETH_P_IPV6:
		/*
		 * If connected, allinet hook should be used
		 * for both IPv4 and IPv6. This is the FIRST hook.
		 */
		if (priv->hooks[0]) {
			hook = priv->hooks[0];
			break;
		}
		/* No break, common protocol stuff */
	default:
		ifproto = get_ifproto_from_proto(ntohs(m->protocol));
		if (ifproto == NULL) {
			log(LOG_WARNING, "ng_iface: proto %x not supported\n",
			    ntohs(m->protocol));
			ifp->stats.tx_errors++;
			kfree_skb(m);

			VNB_EXIT();

			return NETDEV_TX_OK;
		}
		hook = *get_hook_from_ifproto(priv, ifproto);
	}


	/* interface flags check done in dev_queue_xmit */

	/* Copy length before the mbuf gets invalidated */
	len = m->len;
	/* Send packet; if hook is not connected, mbuf will get freed. */

	NG_SEND_DATA(error, hook, m, meta);

	/* Update stats */
	if (error == 0) {
		ifp->stats.tx_bytes += len;
		ifp->stats.tx_packets++;
	} else
		ifp->stats.tx_errors++;

	/* No more need of the Node, exit VNB */
	VNB_EXIT();

	return NETDEV_TX_OK;
}


/************************************************************************
			NETGRAPH NODE STUFF
 ************************************************************************/
static int
ng_iface_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}
static int
ng_iface_close(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static const struct net_device_ops ng_iface_ops = {
	.ndo_change_mtu		= NULL,
	.ndo_start_xmit		= ng_iface_output,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_do_ioctl		= NULL,
	.ndo_open		= ng_iface_open,
	.ndo_stop		= ng_iface_close,
};

static void ng_iface_setup(struct net_device *dev)
{
	dev->type = ARPHRD_PPP; /*NGIFACE;*/
	dev->flags = IFF_POINTOPOINT|IFF_NOARP|IFF_MULTICAST;
	dev->mtu = NG_IFACE_MTU_DEFAULT;
	dev->addr_len = 0;			/* XXX */
	dev->needed_headroom = sizeof(struct iphdr) + sizeof(struct udphdr)
	                       + SKB_RESERVED_HEADER_SIZE;
	dev->tx_queue_len = 0;
	dev->iflink = 0;
	dev->rtnl_link_ops = &ng_iface_link_ops;
	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
	dev->netdev_ops = &ng_iface_ops;
	dev->destructor = free_netdev;
}
/*
 * Constructor for a node
 */
static int
ng_iface_constructor(node_p *nodep, ng_ID_t nodeid)
{
	node_p node;
	priv_p priv;
	int error = 0;

	/* Call generic node constructor */
	error = ng_make_node_common_and_priv(&typestruct, nodep, &priv,
					     sizeof(*priv), nodeid);
	if (error)
		return error;
	memset(priv, 0, sizeof(*priv));

	/* Link together node and private info */
	node = *nodep;
	node->private = priv;
	priv->node = node;
	priv->ifp = NULL;

	return (0);
}

/*
 * Give our ok for a hook to be added
 */
static int
ng_iface_newhook(node_p node, hook_p hook, const char *name)
{
	const ifproto_p ifproto = get_ifproto_from_name(name);
	hook_p *hookptr;

	if (strncmp(name, NG_IFACE_HOOK_ALLIP_IN_PREFIX,
		     sizeof (NG_IFACE_HOOK_ALLIP_IN_PREFIX) -1) == 0) {
		hook->hook_rcvdata = ng_iface_rcvdata_allip_in;
		return 0;
	}

	if (ifproto == NULL)
		return (EPFNOSUPPORT);
	hookptr = get_hook_from_ifproto((priv_p) node->private, ifproto);
	if (*hookptr != NULL) {
		VNB_TRAP();
		return (EISCONN);
	}
	*hookptr = hook;
	return (0);
}

/*
 * Apply NGM_IFACE_SET_ENCAPADDR values.
 */
static void ifp_encapaddr_from_priv(priv_p priv)
{
	struct ifnet *const ifp = priv->ifp;

	/* ifp must not be NULL */
	ifp->type = priv->ifp_type;
	ifp->addr_len = priv->ifp_addr_len;
	memcpy(ifp->dev_addr, priv->ifp_dev_addr.buf, priv->ifp_addr_len);
	memcpy(ifp->broadcast, priv->ifp_broadcast.buf, priv->ifp_addr_len);
	if (ifp->type == AF_INET) {
		log(LOG_DEBUG,
		    "IFACE %s set encapsulation address:\n", ifp->name);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
		log(LOG_DEBUG, "  local %u.%u.%u.%u, remote %u.%u.%u.%u\n",
		    NIPQUAD(priv->ifp_dev_addr.in.s_addr),
		    NIPQUAD(priv->ifp_broadcast.in.s_addr));
#else
		log(LOG_DEBUG, "  local %pI4, remote %pI4\n",
		    &priv->ifp_dev_addr.in.s_addr,
		    &priv->ifp_broadcast.in.s_addr);
#endif
	}
	else {
		log(LOG_DEBUG,
		    "IFACE %s set encapsulation address:\n", ifp->name);
		log(LOG_DEBUG, "   local %pI6\n",
		    &priv->ifp_dev_addr.in6.s6_addr);
		log(LOG_DEBUG, "  remote %pI6\n",
		    &priv->ifp_broadcast.in6.s6_addr);
	}
}

/*
 * Register network interface and rename node accordingly. The new name
 * doesn't need to be NUL-terminated but its size must be provided.
 * Return zero on success or errno otherwise.
 */
static int ng_iface_register(node_p node, const char *name, size_t size,
		  uint32_t netdev_flag)
{
	const priv_p priv = node->private;
	struct ifnet *ifp;
	/* special handling for %d suffix */
	static const char pattern[] = "%d";
	const char *p = pattern;
	/* change name */
	char *boardname;
	char *oldname;
	unsigned int len;
	int ret;
	int error = 0;

	if (priv->ifp != NULL)
		return EEXIST;
	boardname = ng_malloc(IFNAMSIZ, M_NOWAIT);
	if (boardname == NULL)
		return ENOMEM;
	/*
	 * While copying the new interface name into boardname, make sure no
	 * character may interfere, basically we don't want anything outside
	 * of [a-zA-Z0-9_-] before '\0'. Note that '\0' may not be present
	 * either.
	 * As a special case, %d is allowed at the end to let the kernel
	 * pick a number.
	 */
	for (len = 0; (len < size); ++len) {
		if (len >= IFNAMSIZ) {
			error = E2BIG;
			goto error;
		}
		if (name[len] == '\0')
			break;
		if (name[len] == *p) {
			boardname[len] = *p;
			++p;
			continue;
		}
		if ((p == pattern) &&
		    ((isalnum(name[len])) ||
		     (name[len] == '_') ||
		     (name[len] == '-'))) {
			boardname[len] = name[len];
			continue;
		}
		error = EINVAL;
		goto error;
	}
	boardname[len] = '\0';
	/* Node name length check */
	if (((p != pattern) && (*p != '\0')) ||
	    (len < 2) || (len > NG_NODELEN)) {
		error = EINVAL;
		goto error;
	}
	ifp = alloc_netdev(sizeof(struct ng_ifp_private), boardname,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
			   NET_NAME_USER,
#endif
			   ng_iface_setup);
	if (ifp == NULL) {
		error = ENOMEM;
		goto error;
	}
#ifdef __LinuxKernelVNB__
	((struct ng_ifp_private *)netdev_priv(ifp))->iface_priv = priv;
#else
	*(priv_p *)ifp->priv = priv;
#endif
	/* Apply configuration from node->priv */
	/* NGM_IFACE_POINT2POINT, NGM_IFACE_BROADCAST */
	if (priv->ifp_broadcast_set == 0) {
		ifp->flags |= IFF_POINTOPOINT;
		ifp->flags &= ~IFF_BROADCAST;
	}
	else {
		ifp->flags &= ~IFF_POINTOPOINT;
		ifp->flags |= IFF_BROADCAST;
	}
	ifp->features |= NETIF_F_SG | NETIF_F_IP_CSUM;
#ifdef CONFIG_NETDEV_LITE
	if (netdev_flag == NG_IFACE_NETDEV_LITE)
		ifp->features |= NETIF_F_NETDEV_LITE;
#else
	(void) netdev_flag;
#endif
	/* NGM_IFACE_SET_IFTYPE */
	if (priv->ifp_type)
		ifp->type = priv->ifp_type;
	/* NGM_IFACE_SET_ENCAPADDR */
	if (priv->ifp_encapaddr_set)
		ifp_encapaddr_from_priv(priv);
	/*
	 * ng_base.c: ng_name_node() uses M_NETGRAPH for the node->name field
	 * too.
	 */

#ifdef ASYNCHRONOUS_NETDEV_REMOVAL
	/* if the device is in the list of devices to be removed, remove it now */
	rtnl_lock();
	if (!LIST_EMPTY(&staging_rm_dev_list)) {
		struct ifnet_element *entry;
		struct ifnet *ifp_rem;

		LIST_FOREACH(entry, &staging_rm_dev_list, next) {
			ifp_rem = (struct ifnet *) entry;
			if (strcmp(ifp_rem->name, ifp->name) == 0) {
				unregister_netdevice(ifp_rem);
				LIST_REMOVE(entry, next);
				break;
			}
		}
	}
	rtnl_unlock();
	/* and here register it anew */
#endif
	ret = register_netdev(ifp);
	if (ret < 0) {
		free_netdev(ifp);
		error = -ret; /* convert LINUX error to BSD error */
		goto error;
	}
	/* If "%d" was replaced, copy the new name */
	if (p != pattern)
		strlcpy(boardname, ifp->name, IFNAMSIZ);
	oldname = node->name;
	/* Check whether the name is already being used by another node */
	if (((oldname == NULL) || (strcmp(oldname, boardname) != 0)) &&
	    (ng_findname(node, boardname) != NULL)) {
		unregister_netdev(ifp);
		error = EEXIST;
		goto error;
	}
	/* Apply remaining configuration from node->priv */
	/* NGM_IFACE_SET_CARRIER */
	if (priv->ifp_carrier_set)
		netif_carrier_on(ifp);
	priv->ifp = ifp;
	node->name = boardname;
	ng_rehash_node(node);
	if (oldname)
		ng_free(oldname);
	return 0;
error:
	if (boardname != NULL)
		ng_free(boardname);
	return error;
}

/*
 * Receive a control message
 */
static int
ng_iface_rcvmsg(node_p node, struct ng_mesg *msg,
		const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const priv_p priv = node->private;
	struct ifnet *ifp = priv->ifp;
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_IFACE_COOKIE:
		switch (msg->header.cmd) {
		case NGM_IFACE_GET_IFNAME:
		case NGM_IFACE_SETGET_IFNAME:
		case NGM_IFACE_SET_IFNAME:
		{
			struct ng_iface_ifname *arg;

			if (msg->header.cmd != NGM_IFACE_SET_IFNAME) {
				NG_MKRESPONSE(resp, msg, sizeof(*arg),
					      M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				if (msg->header.cmd == NGM_IFACE_GET_IFNAME)
					goto get_ifname_resp;
			}
			arg = (struct ng_iface_ifname *)msg->data;
			error = ng_iface_register(node, arg->ngif_name,
						  sizeof(arg->ngif_name), 0);
			if (error) {
				if (resp != NULL) {
					FREE(resp, M_NETGRAPH);
					resp = NULL;
				}
				log(LOG_DEBUG,
				    "%s: NGM_IFACE_SET_IFNAME: %d\n",
				    node->name, error);
				break;
			}
			ifp = priv->ifp;
#if defined(__LinuxKernelVNB__) && defined(CONFIG_VNB_NETLINK_NOTIFY)
			if ((error = VNB_DUP_NG_MESG(*nl_msg, msg)) != 0)
				break;
			arg = (struct ng_iface_ifname *)(*nl_msg)->data;
			/* Set the real name in nl_mesg */
			snprintf(arg->ngif_name, sizeof(arg->ngif_name), "%s",
				 ifp->name);
#endif
			if (resp != NULL) {
			get_ifname_resp:
				if (ifp == NULL) {
					/* SET_IFNAME must be called first */
					FREE(resp, M_NETGRAPH);
					resp = NULL;
					error = EINVAL;
					break;
				}
				arg = (struct ng_iface_ifname *)resp->data;
				snprintf(arg->ngif_name,
					 sizeof(arg->ngif_name),
					 "%s", ifp->name);
			}
			break;
		}
		case NGM_IFACE_GET_INFO:
		case NGM_IFACE_SETGET_INFO:
		case NGM_IFACE_SET_INFO:
		{
			struct ng_iface_info *arg;

			if (msg->header.cmd != NGM_IFACE_SET_INFO) {
				NG_MKRESPONSE(resp, msg, sizeof(*arg),
					      M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				if (msg->header.cmd == NGM_IFACE_GET_INFO)
					goto get_info_resp;
			}
			arg = (struct ng_iface_info *)msg->data;
			error = ng_iface_register(node, arg->name,
						  sizeof(arg->name), arg->netdev_flag);
			if (error) {
				if (resp != NULL) {
					FREE(resp, M_NETGRAPH);
					resp = NULL;
				}
				log(LOG_DEBUG, "%s: NGM_IFACE_SET_INFO: %d\n",
				    node->name, error);
				break;
			}
			ifp = priv->ifp;
#if defined(__LinuxKernelVNB__) && defined(CONFIG_VNB_NETLINK_NOTIFY)
			if ((error = VNB_DUP_NG_MESG(*nl_msg, msg)) != 0)
				break;
			arg = (struct ng_iface_info *)(*nl_msg)->data;
			/* Set the real name in nl_mesg */
			snprintf(arg->name, sizeof(arg->name), "%s", ifp->name);
#endif
			if (resp != NULL) {
			get_info_resp:
				if (ifp == NULL) {
					/* SET_IFINFO must be called first */
					FREE(resp, M_NETGRAPH);
					resp = NULL;
					error = EINVAL;
					break;
				}
				arg = (struct ng_iface_info *)resp->data;
				arg->id = ng_node2ID(node);
				arg->index = ifp->ifindex;
				snprintf(arg->name, sizeof(arg->name), "%s",
					 ifp->name);
			}
			break;
		}
		case NGM_IFACE_POINT2POINT:
		case NGM_IFACE_BROADCAST:
		{
			/* Deny request if interface is UP */
			if ((ifp != NULL) && (ifp->flags & IFF_UP))
				return (EBUSY);

			/* Change flags */
			switch (msg->header.cmd) {
				case NGM_IFACE_POINT2POINT:
					priv->ifp_broadcast_set = 0;
					if (ifp == NULL)
						break;
					ifp->flags |= IFF_POINTOPOINT;
					ifp->flags &= ~IFF_BROADCAST;
					break;
				case NGM_IFACE_BROADCAST:
					priv->ifp_broadcast_set = 1;
					if (ifp == NULL)
						break;
					ifp->flags &= ~IFF_POINTOPOINT;
					ifp->flags |= IFF_BROADCAST;
					break;
			}
			break;
		}
		case NGM_IFACE_GET_IFTYPE:
		{
			u_short *arg;

			NG_MKRESPONSE(resp, msg, sizeof(*arg), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			arg = (u_short*)resp->data;
			if (ifp != NULL)
				priv->ifp_type = ifp->type;
			*arg = priv->ifp_type;
			break;
		}
		case NGM_IFACE_SET_IFTYPE:
		{
			u_short *arg;

			if (msg->header.arglen != sizeof(*arg)) {
				error = EINVAL;
				break;
			}
			arg = (u_short*)msg->data;
			priv->ifp_type = *arg;
			if (ifp != NULL)
				ifp->type = priv->ifp_type;
			break;
		}
		case NGM_IFACE_SET_CARRIER:
		{
			__u8 *arg;

			if (msg->header.arglen != sizeof(*arg)) {
				error = EINVAL;
				break;
			}
			arg = (__u8 *)msg->data;
			priv->ifp_carrier_set = (!!(*arg));
			if (ifp == NULL)
				break;
			if (priv->ifp_carrier_set)
				netif_carrier_on(ifp);
			else
				netif_carrier_off(ifp);
			break;
		}
		case NGM_IFACE_SET_ENCAPADDR:
		{
			struct ng_iface_encap_addr *addr = (struct ng_iface_encap_addr*)msg->data;

			priv->ifp_encapaddr_set = 1;
			priv->ifp_type = addr->link_type;
			if (addr->family_type == AF_INET)
				priv->ifp_addr_len = sizeof(struct in_addr);
			else
				priv->ifp_addr_len = sizeof(struct in6_addr);
			memcpy(priv->ifp_dev_addr.buf, &addr->s_addr,
			       priv->ifp_addr_len);
			memcpy(priv->ifp_broadcast.buf, &addr->d_addr,
			       priv->ifp_addr_len);
			if (ifp != NULL)
				ifp_encapaddr_from_priv(priv);
			break;
		}
		case NGM_IFACE_SET_KEY:
		{
			struct ng_iface_key * const key = (struct ng_iface_key*)msg->data;
			struct ng_ifp_private * t;

			if (ifp == NULL) {
				/* SET_IFNAME must be called first */
				error = EINVAL;
				break;
			}
			t = (struct ng_ifp_private *)netdev_priv(ifp);

			if (msg->header.arglen != sizeof(*key)) {
				error = EINVAL;
				break;
			}
			t->has_key = key->hasKey;
			t->use_key = key->useKey;
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
	else if (resp)
		FREE(resp, M_NETGRAPH);
	FREE(msg, M_NETGRAPH);
	return (error);
}

#if defined(__LinuxKernelVNB__)
#if defined(CONFIG_TILE) || defined(CONFIG_TILEGX)
/* Realign skb data pointer to a multiple of 4 + mod. This function
 * assumes that the skb is not shared and that the headroom is large
 * enough for that: it should be the case as the function is called
 * when exiting the VNB graph. */
static void align_skb_data(struct sk_buff *skb, int mod)
{
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
}
#endif
#endif

/*
 * Receive data from a hook. Pass the packet to the correct input routine.
 */
static int
__ng_iface_rcvdata(hook_p hook, struct mbuf *m, meta_p meta, char *proto)
{
	const priv_p priv = hook->node_private;
	ifproto_p ifproto;
	struct ifnet *ifp;

	/* Sanity checks */

	if (m == NULL)
		return (EINVAL);

	if (!priv) {
		/* Node has been shutdown */
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	if (proto != NULL)
		ifproto = get_ifproto_from_name(proto);
	else
		ifproto = get_ifproto_from_hook(priv, hook);
	KASSERT(ifproto != NULL);

	ifp = priv->ifp;
	if (!ifproto || !ifp) {
		/* Hook has been disconnected */
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	if ((ifp->flags & IFF_UP) == 0) {
		NG_FREE_DATA(m, meta);
		ifp->stats.rx_errors++;
		return (ENETDOWN);
	}

	ifp->stats.rx_bytes += m->len;
	ifp->stats.rx_packets++;

	/* Ignore any meta-data */
	NG_FREE_META(meta);

	/* Send packet */

	/*
	 * Through this hook, we have to check first
	 * quartet to select IP version
	 */
	if (ifproto->protocol == ETH_P_ALLIP) {
		unsigned char ipv;

		if (!m_pullup(m, sizeof(ulong))) {
			/* mbuf is already freed */
			NG_FREE_META(meta);
			return EINVAL;
		}
		ipv = (m->data[0] & 0xf0);

		if (ipv == 0x40)
			m->protocol = htons(ETH_P_IP);
		if (ipv == 0x60)
			m->protocol = htons(ETH_P_IPV6);
	}
	else {
		m->protocol = htons(ifproto->protocol);
	}

	m->pkt_type = PACKET_HOST;
	/* reset destination cache */

#if defined(__LinuxKernelVNB__)
#if defined(CONFIG_TILE) || defined(CONFIG_TILEGX)
	/* align IP/IPv6 packet on 4-byte boundary */
	align_skb_data((struct sk_buff *)m, 0);
#endif
#endif

	__kcompat_skb_tunnel_rx(m, ifp, packet_net(m));

	netif_rx(m);

	return(0);
}

static int
ng_iface_rcvdata_allip_in(hook_p hook, struct mbuf *m, meta_p meta)
{
	return __ng_iface_rcvdata(hook, m, meta, NG_IFACE_HOOK_ALLIP);
}

static int
ng_iface_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	return __ng_iface_rcvdata(hook, m, meta, NULL);
}

#ifdef ASYNCHRONOUS_NETDEV_REMOVAL

/*
 * garbage collector for in-progress device removal
 */
static void
ng_iface_ticker(void *arg)
{
	struct ifnet_element *entry;
	struct ifnet *ifp;
	/* list of netdevs queued to be unregistered */
	struct list_head queued_rm_dev_list;
	int i = 0;

	rtnl_lock();
	if (!LIST_EMPTY(&staging_rm_dev_list)) {
		INIT_LIST_HEAD(&queued_rm_dev_list);
		LIST_FOREACH(entry, &staging_rm_dev_list, next) {
			i++;
			if (i > unregister_bulksize)
				break;
			ifp = (struct ifnet *) entry;
			unregister_netdevice_queue(ifp, &queued_rm_dev_list);
			LIST_REMOVE(entry, next);
		}
		unregister_netdevice_many(&queued_rm_dev_list);
	}
	rtnl_unlock();

	callout_reset(&timeout_handle, hz / 100,
			ng_iface_ticker, NULL);
}
#endif

/*
 * Shutdown and remove the node and its associated interface.
 */
static int
ng_iface_rmnode(node_p node)
{
	const priv_p priv = node->private;
	struct ifnet *ifp = priv->ifp;
	ng_cutlinks(node);
	ng_unname(node);
	if (ifp) {
#ifndef ASYNCHRONOUS_NETDEV_REMOVAL
		unregister_netdev(ifp);
#else
		struct ifnet_element *entry;
		rtnl_lock();
		entry = (struct ifnet_element *) ifp;
		((struct ng_ifp_private *)netdev_priv(ifp))->iface_priv = NULL;
		LIST_INSERT_HEAD(&staging_rm_dev_list, entry, next);
		rtnl_unlock();
#endif
		priv->ifp = NULL;
	}
	/* do not free the ifp structure. actual release may be delayed
	 * due because some objects still point on this device (e.g. a route
	 * cache stored into a sockets. The Linux kernel will free the structure
	 * itself */
	node->private = NULL;
	ng_unref(node);
	return (0);
}

/*
 * Hook disconnection. Note that we do *not* shutdown when all
 * hooks have been disconnected.
 */
static int
ng_iface_disconnect(hook_p hook)
{
	const priv_p priv = hook->node->private;
	const ifproto_p ifproto = get_ifproto_from_hook(priv, hook);

	if (strncmp(hook->name, NG_IFACE_HOOK_ALLIP_IN_PREFIX,
		    sizeof (NG_IFACE_HOOK_ALLIP_IN_PREFIX) - 1) == 0) {
		hook->hook_rcvdata = NULL;
		return 0;
	}

	if (ifproto == NULL)
		panic(__FUNCTION__);
	*get_hook_from_ifproto(priv, ifproto) = NULL;
	return (0);
}

static struct ng_nl_nodepriv *
ng_iface_dumpnode(node_p node)
{
	struct ng_nl_nodepriv *nlnodepriv;
	struct ng_iface_ifname *ifname;
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
	ifname = (struct ng_iface_ifname *)nlnodepriv->data;

	snprintf(ifname->ngif_name, sizeof(ifname->ngif_name),
		 "%s", ifp->name);

	return nlnodepriv;
}

/*
 * local wrappers for the generic init/exit functions
 * (used for the management of the callout)
 */
static int ng_local_iface_init(void)
{
	int err;

#ifdef ASYNCHRONOUS_NETDEV_REMOVAL
	/* gc for deleted iface netdevices */
	LIST_INIT(&staging_rm_dev_list);
	callout_init(&timeout_handle);

	callout_reset(&timeout_handle, hz / 100,
			ng_iface_ticker, NULL);
#endif

	err = vnb_rtnl_link_register(&ng_iface_link_ops);
	if (err < 0)
		goto out_rtnl_link;

	err =  ng_iface_init();
	if (err < 0)
		goto out_ng_iface;

	return 0;

out_ng_iface:
	vnb_rtnl_link_unregister(&ng_iface_link_ops);
out_rtnl_link:
#ifdef ASYNCHRONOUS_NETDEV_REMOVAL
	callout_stop_sync(&timeout_handle);
#endif
	return err;
}

static void ng_local_iface_exit(void)
{
#ifdef ASYNCHRONOUS_NETDEV_REMOVAL
	/* stop the gc for deleted iface netdevices */
	callout_stop_sync(&timeout_handle);
#endif
	vnb_rtnl_link_unregister(&ng_iface_link_ops);
	ng_iface_exit();
}

module_init(ng_local_iface_init);
module_exit(ng_local_iface_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB iface node");
MODULE_LICENSE("6WIND");
