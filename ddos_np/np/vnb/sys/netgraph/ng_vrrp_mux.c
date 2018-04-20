/*
 * Copyright 2011-2013 6WIND S.A.
 */

#if defined(__LinuxKernelVNB__)

#include <linux/version.h>
#include <linux/module.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/timer.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <linux/ctype.h> /* for isdigit */
#include <netgraph/vnblinux.h>

#include <linux/icmpv6.h>
#include <linux/ipv6.h>
#include <linux/igmp.h>

#elif defined(__FastPath__)
#include "fp-netgraph.h"
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_ether.h>
#include <netgraph/ng_vrrp_mux.h>
#include <netgraph/vnb_ether.h>

#define NG_VRRP_MAX_ID 255

/* Per-node private data */
struct ng_vrrp_mux_private {
	hook_p			ether_upper_hook;
	hook_p			ether_lower_hook;
	hook_p			vrrp_hooks[NG_VRRP_MAX_ID + 1];
	node_p			node;		/* netgraph node */
};
typedef struct ng_vrrp_mux_private *priv_p;

/* Per vrrp hook private data */
struct ng_vrrp_hook_private {
	u_int8_t                vrrpid;	        /* vrrp id */
};
typedef struct ng_vrrp_hook_private *hookpriv_p;

/* Netgraph node methods */
static ng_constructor_t	ng_vrrp_mux_constructor;
static ng_shutdown_t	ng_vrrp_mux_rmnode;
static ng_newhook_t	ng_vrrp_mux_newhook;
static ng_disconnect_t	ng_vrrp_mux_disconnect;

static int
ng_vrrp_mux_rcvdata_vrrp_or_upper(hook_p hook, struct mbuf *m, meta_p meta);
static int
ng_vrrp_mux_rcvdata_ether(hook_p hook, struct mbuf *m, meta_p meta);

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_vrrp_mux_typestruct) = {
	.version = NG_VERSION,
	.name = NG_VRRP_MUX_NODE_TYPE,
	.mod_event = NULL,
	.constructor = ng_vrrp_mux_constructor,
	.rcvmsg = NULL,
	.shutdown = ng_vrrp_mux_rmnode,
	.newhook = ng_vrrp_mux_newhook,
	.findhook = NULL,
	.connect = NULL,
	.afterconnect = NULL,
	.rcvdata = NULL,			/* Only specific receive data functions */
	.rcvdataq = NULL,			/* Only specific receive data functions */
	.disconnect = ng_vrrp_mux_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist = NULL,
};
NETGRAPH_INIT(vrrp_mux, &ng_vrrp_mux_typestruct);
NETGRAPH_EXIT(vrrp_mux, &ng_vrrp_mux_typestruct);

/******************************************************************
		    NETGRAPH NODE METHODS
******************************************************************/

/*
 * Node constructor
 */
static int
ng_vrrp_mux_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int error;

	/* Allocate and initialize private info */
	priv = ng_malloc(sizeof(*priv), M_NOWAIT);
	if (priv == NULL)
		return (ENOMEM);
	bzero(priv, sizeof(*priv));

	/* Call superclass constructor */
	if ((error = ng_make_node_common(&ng_vrrp_mux_typestruct, nodep, nodeid))) {
		ng_free(priv);
		return (error);
	}
	(*nodep)->private = priv;
	priv->node = *nodep;

	/* Done */
	return (0);
}

/*
 * Method for attaching a new hook
 */
static	int
ng_vrrp_mux_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = node->private;

	/* Check for a link hook */
	if (strncmp(name, NG_VRRP_MUX_HOOK_ETHER_UPPER,
		    strlen(NG_VRRP_MUX_HOOK_ETHER_UPPER)) == 0) {
		priv->ether_upper_hook = hook;
		hook->hook_rcvdata = ng_vrrp_mux_rcvdata_vrrp_or_upper;
		return (0);
	} else if (strncmp(name, NG_VRRP_MUX_HOOK_ETHER_LOWER,
			   strlen(NG_VRRP_MUX_HOOK_ETHER_LOWER)) == 0) {
		priv->ether_lower_hook = hook;
		hook->hook_rcvdata = ng_vrrp_mux_rcvdata_ether;
		return (0);
	} else if (strncmp(name, NG_VRRP_MUX_HOOK_VRRP_PREFIX,
			   strlen(NG_VRRP_MUX_HOOK_VRRP_PREFIX) - 1) == 0) {
		const char *vrrpid_str;
		char *err_ptr;
		u_int8_t vrrpid;
		hookpriv_p hpriv;

		/*
		 * Get the link index
		 * Parse vrrp0xa, vrrp10, ...
		 */
		vrrpid_str = name + sizeof(NG_VRRP_MUX_HOOK_VRRP_PREFIX) - 1;

		/* Allow decimal and hexadecimal values.
		 * The hexadecimal values must be prefixed by 0x
		 */
		vrrpid = strtoul(vrrpid_str, &err_ptr, 0); /* allow decimal and hexadecimal */
		if ((*err_ptr) != '\0')
			return (EINVAL);

		/*
		 * Register the per-link private data
		 */
		hpriv = (hookpriv_p) ng_malloc(sizeof(*hpriv), M_NOWAIT | M_ZERO);
		if (!hpriv)
			return ENOMEM;
		hpriv->vrrpid = vrrpid;

		priv->vrrp_hooks[vrrpid] = hook;

		NG_HOOK_SET_PRIVATE(hook, hpriv);
#ifdef NG_NODE_CACHE
		NG_HOOK_SET_NODE_CACHE(hook, node->private);
#endif
		hook->hook_rcvdata = ng_vrrp_mux_rcvdata_vrrp_or_upper;
		return (0);
	}

	/* Unknown hook name */
	return (EINVAL);
}

/*
 * Receive data on a hook
 */
static int
ng_vrrp_mux_rcvdata_ether(hook_p hook, struct mbuf *m, meta_p meta)
{
	priv_p priv = hook->node_private;
	struct vnb_ether_header *eh;
	int error = 0;
	hook_p vrrp_hook;
	hook_p ether_upper_hook;
	int i;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	if (unlikely(MBUF_LENGTH(m) < VNB_ETHER_HDR_LEN)) {
		NG_FREE_DATA(m, meta);
		return (EINVAL);
	}

#if defined (__LinuxKernelVNB__)
	if (!pskb_may_pull(m, VNB_ETHER_HDR_LEN)) {
		kfree_skb(m);
		m = NULL;
		NG_FREE_META(meta);
		VNB_TRAP();
		return (ENOBUFS);
	}
#endif
	eh = mtod(m, struct vnb_ether_header *);

	if (vnb_is_vrrp(eh->ether_dhost)) {
		u_int8_t vrrpid = eh->ether_dhost[5];

		vrrp_hook = priv->vrrp_hooks[vrrpid];
		if (vrrp_hook) {
			NG_SEND_DATA(error, vrrp_hook, m, meta);
			return (error);
		} else
			goto send_ether;
	}

	/*
	 * Broadcast and Multicast packet are forwarded to all
	 * VRRP interfaces connected
	 */
	if (vnb_is_bcast(m) || ((eh->ether_dhost[0] & 1) != 0)) {
		/* broadcast packets to all connected hooks */
		for (i = 1; i <= NG_VRRP_MAX_ID; i++) {
			meta_p meta2 = NULL;
			struct mbuf *m2 = NULL;

			vrrp_hook = priv->vrrp_hooks[i];
			if (!vrrp_hook)
				continue;

#if defined(__FastPath__)
			m2 = m_dup(m);
#else
			m2 = m_dup(m, M_NOWAIT);	/* XXX m_copypacket() */
#endif
			if (m2 == NULL) {
				NG_FREE_DATA(m, meta);
				return (ENOBUFS);
			}

			if (meta != NULL
			    && (meta2 = ng_copy_meta(meta)) == NULL) {
				m_freem(m2);
				NG_FREE_DATA(m, meta);
				return (ENOMEM);
			}

			NG_SEND_DATA(error, vrrp_hook, m2, meta);
		}
	}

 send_ether:

	ether_upper_hook = priv->ether_upper_hook;
	if (!ether_upper_hook) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	NG_SEND_DATA(error, ether_upper_hook, m, meta);
	return (error);
}

static int
ng_vrrp_mux_rcvdata_vrrp_or_upper(hook_p hook, struct mbuf *m, meta_p meta)
{
	priv_p priv = hook->node_private;
	hook_p ether_lower_hook;
	int error = 0;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	ether_lower_hook = priv->ether_lower_hook;
	if (!ether_lower_hook) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	NG_SEND_DATA(error, ether_lower_hook, m, meta);

	return (error);
}

/*
 * Shutdown node
 */
static int
ng_vrrp_mux_rmnode(node_p node)
{
	const priv_p priv = node->private;

	ng_unname(node);
	ng_cutlinks(node);		/* frees all link and host info */
	node->private = NULL;
	ng_free(priv);
	ng_unref(node);
	return (0);
}

/*
 * Hook disconnection.
 */
static int
ng_vrrp_mux_disconnect(hook_p hook)
{
	node_p node = hook->node;
	const priv_p priv = node->private;

	hook->hook_rcvdata = NULL;
	if (hook == priv->ether_upper_hook) {
		priv->ether_upper_hook = NULL;
	} else if (hook == priv->ether_lower_hook) {
		priv->ether_lower_hook = NULL;
	} else {
		hookpriv_p hpriv = NG_HOOK_PRIVATE(hook);

		priv->vrrp_hooks[hpriv->vrrpid] = NULL;
		NG_HOOK_SET_PRIVATE(hook, NULL);
		ng_free(hpriv);
	}

	/* If no more lower hooks, go away */
	if (node->numhooks == 0)
		ng_rmnode(node);
	return (0);
}

#if defined(__LinuxKernelVNB__)
module_init(ng_vrrp_mux_init);
module_exit(ng_vrrp_mux_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB VRRP mux node");
MODULE_LICENSE("6WIND");
#endif
