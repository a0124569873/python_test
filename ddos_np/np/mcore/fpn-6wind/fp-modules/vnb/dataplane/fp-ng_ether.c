/*
 * Copyright(c) 2007 6WIND
 */
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
 * ng_ether(4) netgraph node type
 */
#include "fpn.h"
#include "fp-includes.h"

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_ether.h>

#include "fp-ng_ether.h"
#include "fp-main-process.h"
#include "fp-ether.h"

#define IFP2ETHER(ifp, ns) (ether_priv_p)fp_vnb_shared->if_ops[IFP2IDX(ifp)].if_vnb_ops[ns].ether.u.priv
#define SET_IFP2ETHER(ifp, val, ns) fp_vnb_shared->if_ops[IFP2IDX(ifp)].if_vnb_ops[ns].ether.u.priv = (val)

#define NG_ETHER_HOOK_TYPE_LOWER    0
#define NG_ETHER_HOOK_TYPE_UPPER    1
#define NG_ETHER_HOOK_TYPE_LOWER_IN 2
#define NG_ETHER_HOOK_TYPE_ATTACH   3

/* return 1 if IFF_NG_ETHER is present in at least one vnb_ns */
static int ifnet_ether_attached(fp_ifnet_t *ifp)
{
	int i;

	for (i = 0; i < CONFIG_MCORE_VNB_MAX_NS; i++) {
		if (IFP2FLAGS(ifp, i) & IFF_NG_ETHER)
			return 1;
	}
	return 0;
}

static inline int ifnet_ether_attach(fp_ifnet_t *ifp)
{
	/* already attached */
	if (ifnet_ether_attached(ifp) == 1)
		return 0;

	if (fp_ifnet_ops_register(ifp, RX_DEV_OPS, vnb_moduid, NULL))
		return EINVAL;

	IFP2FLAGS(ifp, ctrl_vnb_ns) |= IFF_NG_ETHER;
	return 0;
}

static inline void ifnet_ether_detach(fp_ifnet_t *ifp)
{
	/* not attached */
	if (ifnet_ether_attached(ifp) == 0)
		return;

	IFP2FLAGS(ifp, ctrl_vnb_ns) &= ~IFF_NG_ETHER;

	/* still attached in the other vnb_ns */
	if (ifnet_ether_attached(ifp) == 1)
		return;

	fp_ifnet_ops_unregister(ifp, RX_DEV_OPS);
}

/* We store interface pointer in hook cache  hook->node_cache */
static void
ng_ether_update_node_cache(ether_priv_p priv)
{
#ifdef NG_NODE_CACHE
	int i;

	if (priv->upper)
		NG_HOOK_SET_NODE_CACHE(priv->upper, priv->ifp);
	if (priv->lower)
		NG_HOOK_SET_NODE_CACHE(priv->lower, priv->ifp);
	if (priv->attach)
		NG_HOOK_SET_NODE_CACHE(priv->attach, priv->ifp);
	for (i = 0; i < FP_NG_ETHER_MAX_LOWER_IN_HOOKS; i++)
		if (priv->lower_in[i])
			NG_HOOK_SET_NODE_CACHE(priv->lower_in[i], priv->ifp);
#endif
}

/* Netgraph node methods */
static ng_constructor_t	ng_ether_constructor;
static ng_rcvmsg_t	ng_ether_rcvmsg;
static ng_shutdown_t	ng_ether_rmnode;
static ng_newhook_t	ng_ether_newhook;
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
	{ 0, 0, NULL, NULL, NULL }
};

static VNB_DEFINE_SHARED(struct ng_type, ng_ether_typestruct) = {
	.version = NG_VERSION,
	.name = NG_ETHER_NODE_TYPE,
	.mod_event = NULL,
	.constructor = ng_ether_constructor,
	.rcvmsg = ng_ether_rcvmsg,
	.shutdown = ng_ether_rmnode,
	.newhook = ng_ether_newhook,
	.findhook = NULL,
	.connect = NULL,
	.rcvdata = NULL,		/* Only specific receive data functions */
	.rcvdataq = NULL,		/* Only specific receive data functions */
	.disconnect = ng_ether_disconnect,
	.rcvexception = NULL,
	.cmdlist = ng_ether_cmdlist,
};

/******************************************************************
			    PROTOTYPES
******************************************************************/
static inline int ng_ether_rcv_upper(hook_p hook, struct mbuf *m, meta_p meta);
static inline int ng_ether_rcv_lower(hook_p hook, struct mbuf *m, meta_p meta);

/******************************************************************
		    ETHERNET FUNCTION HELPERS
******************************************************************/
/*
 * Link ethernet network device to a given node
 */
static int
ng_ether_setup(node_p node, fp_ifnet_t *ifp)
{
	ether_priv_p priv = node->private;

	priv->ifp = ifp;
	ng_ether_update_node_cache(priv);
	SET_IFP2ETHER(ifp, priv, ctrl_vnb_ns);

	return 0;
}

/******************************************************************
		    ETHERNET FUNCTION HOOKS
******************************************************************/


/*
 * A new Ethernet interface has been attached.
 * Create a new node for it, etc.
 */
int ng_ether_attach(fp_ifnet_t *ifp, uint32_t nodeid)
{
	int ret;
	ether_priv_p priv;
	node_p node;

	/* test if interface is attached */
	if (IFP2ETHER(ifp, ctrl_vnb_ns) != NULL)
		return 0;

	/* Check if node already exists: it can happen when an interface moves
	 * from a vrf to another vrf
	 */
	if ((node = ng_ID2node(nodeid)) != NULL &&
	    node->type == &ng_ether_typestruct) {
		ng_ether_setup(node, ifp);
		priv = NG_NODE_PRIVATE(node);

		ifnet_ether_detach(priv->ifp);

		log(LOG_INFO, "Attaching existing VNB node ether (%u) to %s\n",
		    nodeid, ifp->if_name);
		return 0;
	}

	/* node might already exist */
	if ((node = ng_findname(NULL, ifp->if_name)) != NULL) {
		fp_ifnet_t *oifp;

		/* check if it is a ng_ether node */
		if (node->type != &ng_ether_typestruct) {
			log(LOG_WARNING,
			    "%s: cannot attach interface, node of "
			    "different type already exists <%s>\n",
			    __FUNCTION__, ifp->if_name);
			return EINVAL;
		}

		priv = NG_NODE_PRIVATE(node);
		oifp = priv->ifp;
		if (oifp == NULL) {
			ng_ether_setup(node, ifp);
			ifnet_ether_detach(priv->ifp);
			log(LOG_INFO, "Re-attaching VNB node ether to %s\n", ifp->if_name);
			return 0;
		}

		/* Detach previous interface if attached */
		ret = ng_ether_detach(oifp, 0);
		if (ret == ENOENT) {
			/* This should not happen: we found a node attached to
			 * an ifp there is no reference from the ifp to the
			 * node. Remove the node anyway and log a warning. */
			log(LOG_WARNING, "Can't detach already existing VNB "
			    "node ether to %s\n", ifp->if_name);

			ng_rmnode(node);
		}
	}

	/* at this step, we know that no ether node */

	if ((ret = ng_ether_constructor(&node, nodeid) != 0)) {
		VNB_TRAP("EINVAL");
		log(LOG_ERR, "%s: can't %s for %s\n", __FUNCTION__, "create node", ifp->if_name);
		return ret;
	}

	ng_ether_setup(node, ifp);

	/* Try to give the node the same name as the interface */
	if (ng_name_node(node, ifp->if_name) != 0) {
		VNB_TRAP();
		log(LOG_WARNING, "%s: can't name node %s\n",
		    __FUNCTION__, ifp->if_name);
	}
	log(LOG_INFO, "Attaching VNB node ether to %s\n", ifp->if_name);
	return 0;
}

/*
 * An Ethernet interface is being detached.
 * Destroy or clean (depending on vnb_keep_node) its node.
 */
int ng_ether_detach(fp_ifnet_t *ifp, uint8_t vnb_keep_node)
{
	node_p node;
	ether_priv_p priv;

	priv = IFP2ETHER(ifp, ctrl_vnb_ns);
	if (priv == NULL) /* not attached */
		return ENOENT;

	node = priv->node;

	if (node == NULL)		/* no node (why not?), ignore */
		return ENOENT;

	if (vnb_keep_node) {
		/* Interface moves to another vrf, we need to keep the ng_ether
		 * node. However, the interface may be already created in the
		 * new vrf (and so already attached to this node), hence we
		 * need to check the ifuid before cleaning the node.
		 */
		if (priv->ifp && priv->ifp->if_ifuid == ifp->if_ifuid) {
			log(LOG_INFO, "Detaching VNB node ether from %p\n", ifp);
			ifnet_ether_detach(ifp);
			priv->ifp = NULL;
			ng_ether_update_node_cache(priv);
		}
		/* Anyway, this ifp has no longer an ng_ether node */
		SET_IFP2ETHER(ifp, NULL, ctrl_vnb_ns);
	} else
		ng_rmnode(node);
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
ng_ether_constructor(node_p *nodep, ng_ID_t nodeid)
{
	ether_priv_p priv;
	int error;

	/* Call superclass constructor that mallocs *nodep */
	if ((error = ng_make_node_common_and_priv(&ng_ether_typestruct, nodep,
						  &priv, sizeof(*priv), nodeid))) {
		return (error);
	}
	bzero(priv, sizeof(*priv));
	NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->node = *nodep;
	return (0);
}

/*
 * Check for attaching a new hook.
 */
static	int
ng_ether_newhook(node_p node, hook_p hook, const char *name)
{
	const ether_priv_p priv = node->private;
	hook_p *hookptr;
	hether_priv_p hpriv;
	int error = 0;

	/* Don't allow hook creation if we are not attached to an interface */
	if ( unlikely(!(priv->ifp))
	     && fpn_fast_memcmp(name, NG_ETHER_HOOK_ATTACH,
				sizeof(NG_ETHER_HOOK_ATTACH)) )
		return (EINVAL);

	hpriv = (hether_priv_p) ng_malloc(sizeof(*hpriv), M_NOWAIT);
	if (hpriv == NULL) {
		VNB_TRAP("ENOMEM");
		log(LOG_ERR, "%s: can't allocate memory for %s\n",
		    __FUNCTION__, node->name);
		return ENOMEM;
	}
	bzero(hpriv, sizeof(*hpriv));

	/* Which hook? */
	if (fpn_fast_memcmp(name, NG_ETHER_HOOK_UPPER, sizeof(NG_ETHER_HOOK_UPPER)) == 0) {
		hookptr = &priv->upper;
		hpriv->type = NG_ETHER_HOOK_TYPE_UPPER;
		hook->hook_rcvdata = ng_ether_rcv_upper;
	} else if (fpn_fast_memcmp(name, NG_ETHER_HOOK_LOWER, sizeof(NG_ETHER_HOOK_LOWER)) == 0) {
		hookptr = &priv->lower;
		hpriv->type = NG_ETHER_HOOK_TYPE_LOWER;
		hpriv->autoSrcAddr = priv->autoSrcAddr;
		hook->hook_rcvdata = ng_ether_rcv_lower;
	} else if (fpn_fast_memcmp(name, NG_ETHER_HOOK_LOWER_PREFIX,
				   sizeof (NG_ETHER_HOOK_LOWER_PREFIX) - 1) == 0) {
		const char     *tag_str;
		char           *err_ptr;
		unsigned long   tag;

		/* Get the link index Parse lower_in_0xa, lower_in_10, ... */
		tag_str = name + sizeof(NG_ETHER_HOOK_LOWER_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0') {
			error = EINVAL;
			goto error;
		}

		if (tag >= FP_NG_ETHER_MAX_LOWER_IN_HOOKS) {
			error = EINVAL;
			goto error;
		}

		/* Do not connect twice a nomatch hook */
		if (priv->lower_in[tag] != NULL) {
			error = EISCONN;
			goto error;
		}

		/* Register the per-link private data */
		hpriv->tag = tag;

		/* Works like a lower hook in reception */
		hpriv->type = NG_ETHER_HOOK_TYPE_LOWER_IN;

		hookptr = &priv->lower_in[tag];
		hook->hook_rcvdata = ng_ether_rcv_lower;
	} else if (fpn_fast_memcmp(name, NG_ETHER_HOOK_ATTACH,
				   sizeof(NG_ETHER_HOOK_ATTACH)) == 0) {
		hookptr = &priv->attach;
		hpriv->type = NG_ETHER_HOOK_TYPE_ATTACH;
	} else {
		error = EINVAL;
		goto error;
	}

	/* Check if already connected (shouldn't be, but doesn't hurt) */
	if (*hookptr != NULL) {
		error = EISCONN;
		goto error;
	}

	/* OK */
	*hookptr = hook;
	/* store hook type and node info in hook */
	NG_HOOK_SET_PRIVATE(*hookptr, hpriv);
	/* store interface in cache */
	NG_HOOK_SET_NODE_CACHE(*hookptr, priv->ifp);
	/* mark lower is connected to interface */
	if (hpriv->type == NG_ETHER_HOOK_TYPE_LOWER) {
		if ((error = ifnet_ether_attach(priv->ifp)) != 0)
			goto error;
	}
	return (0);

 error:
	ng_free(hpriv);
	return error;
}

/*
 * Receive an incoming control message.
 */
static int
ng_ether_rcvmsg(node_p node, struct ng_mesg *msg,
		const char *retaddr, struct ng_mesg **rptr,
		struct ng_mesg **nl_msg)
{
	const ether_priv_p priv = node->private;
	struct ng_mesg *resp = NULL;
	int error = 0;
	void *msgdata, *respdata;

	switch (msg->header.typecookie) {
	case NGM_ETHER_COOKIE:
		switch (msg->header.cmd) {
		case NGM_ETHER_GET_IFNAME:
			NG_MKRESPONSE(resp, msg, FP_IFNAMSIZ + 1, M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			if (priv->ifp == NULL) {
				error = EINVAL;
				break;
			}
			snprintf(resp->data, FP_IFNAMSIZ + 1,
			    "%s", priv->ifp->if_name);
			break;
		case NGM_ETHER_GET_IFINDEX:
			NG_MKRESPONSE(resp, msg, sizeof(u_int32_t), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			if (priv->ifp == NULL) {
				error = EINVAL;
				break;
			}
			respdata = resp->data;
			/* No ifindex available in fast path */
			*((u_int32_t *)respdata) = 0;
			break;
		case NGM_ETHER_GET_ENADDR:
			NG_MKRESPONSE(resp, msg, FP_ETHER_ADDR_LEN, M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			if (priv->ifp == NULL) {
				error = EINVAL;
				break;
			}
			memcpy(resp->data, priv->ifp->if_mac, FP_ETHER_ADDR_LEN);
			break;
		case NGM_ETHER_SET_ENADDR:
		    {
			if (msg->header.arglen != FP_ETHER_ADDR_LEN) {
				error = EINVAL;
				break;
			}
			if (priv->ifp == NULL) {
				error = EINVAL;
				break;
			}
			memcpy(priv->ifp->if_mac, msg->data,  FP_ETHER_ADDR_LEN);
			break;
		    }
		case NGM_ETHER_GET_AUTOSRC:
			NG_MKRESPONSE(resp, msg, sizeof(u_int32_t), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			respdata = resp->data;
			*((u_int32_t *)respdata) = priv->autoSrcAddr;
			break;
		case NGM_ETHER_SET_AUTOSRC:
			{
				hook_p lower = priv->lower;
				if (msg->header.arglen != sizeof(u_int32_t)) {
					error = EINVAL;
					break;
				}
				msgdata = msg->data;
				priv->autoSrcAddr = !!*((u_int32_t *)msgdata);
				if (lower) {
					hether_priv_p hpriv = (hether_priv_p)NG_HOOK_PRIVATE(lower);
					hpriv->autoSrcAddr= priv->autoSrcAddr;
				}
			}
			break;
		case NGM_ETHER_ATTACH_INTERFACE:
			{
				fp_ifnet_t *ifp;

				/* There must be an interface with the wanted name */
				if ((ifp = fp_getifnetbyname(msg->data)) == NULL) {
					error = EINVAL;
					break;
				}

				/* If node is already named, check that it matches */
				if (node->name) {
					if (strcmp(node->name, (char *)msg->data)) {
						error = EINVAL;
						break;
					}
				} else if ((error = ng_name_node(node, msg->data))) {
					break;
				}

				ng_ether_setup(node, ifp);
				break;
			}
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
static inline int ng_ether_rcv_lower(hook_p hook, struct mbuf *m, meta_p meta)
{
	int ret;
	uint32_t *srcaddr_u32_a;
	uint32_t *srcaddr_u32_b;
	void *ifmac_a, *ifmac_b;

	struct fp_ether_header *eh = mtod(m, struct fp_ether_header *);
	const hether_priv_p hpriv = (hether_priv_p)NG_HOOK_PRIVATE(hook);
	fp_ifnet_t *ifp = NG_HOOK_NODE_CACHE(hook);

	/* Discard meta info */
	NG_FREE_META(meta);

	if (unlikely(hpriv == NULL)) {
		m_freem(m);
		return ENOTCONN;
	}

#ifdef DEBUG_FP
	if (m_len(m) < sizeof(struct fp_ether_header)) {
		m_freem(m);
		return (EINVAL);
	}
#endif

	/* Drop in the MAC address if desired or if the 4 first bytes
	 * of src mac address are 0. */
	srcaddr_u32_a = (uint32_t *) (eh->ether_shost);
	if (unlikely(hpriv->autoSrcAddr || *srcaddr_u32_a == 0)) {

		srcaddr_u32_b = (uint32_t *) (eh->ether_shost+2);

		/* copy the mac address using two 32 bits words, this
		 * is faster than a byte copy. */
		ifmac_a = ifp->if_mac;
		*srcaddr_u32_a = *(uint32_t *)(ifmac_a);
		ifmac_b = ifp->if_mac + 2;
		*srcaddr_u32_b = *(uint32_t *)(ifmac_b);
	}
	/* fp_if_output() does not check operative state */
	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_dropped);
		m_freem(m);
		return -1;
	}
	ret = FPN_HOOK_CALL(fp_if_output)(m, ifp);
	fp_process_input_finish(m, ret);
	return 0;
}

/*
 * Handle an mbuf received on the "upper" hook.
 */
static inline int
ng_ether_rcv_upper(hook_p hook, struct mbuf *m, meta_p meta)
{
	int ret;
	fp_ifnet_t *ifp = NG_HOOK_NODE_CACHE(hook);

	/* Discard meta info */
	NG_FREE_META(meta);
#ifdef DEBUG_FP
	/* Check length and pull off header */
	if (m_len(m) < sizeof(struct fp_ether_header))
	{
		VNB_TRAP("EINVAL");
		m_freem(m);
		return (EINVAL);
	}
#endif
	if (m_priv(m)->ifuid != ifp->if_ifuid)
		fp_change_ifnet_packet(m, ifp, 0, 1);
	m_priv(m)->exc_type = FPTUN_ETH_NOVNB_INPUT_EXCEPT;
	ret = fp_ether_input_novnb(m, ifp);
	fp_process_input_finish(m, ret);
	
	return 0;
}

/*
 * Shutdown node. This resets the node but does not remove it.
 */
static int
ng_ether_rmnode(node_p node)
{
	ether_priv_p priv = node->private;
	fp_ifnet_t *ifp = priv->ifp;

	/* If interface is attached to this node */
	if (ifp) {
		log(LOG_INFO, "Detaching VNB node ether from %p\n", ifp);
		ifnet_ether_detach(ifp);

		SET_IFP2ETHER(ifp, NULL, ctrl_vnb_ns);
	}

	ng_unname(node);		/* free name (and its reference) */
	ng_cutlinks(node);		/* break all links to other nodes */
	NG_NODE_SET_PRIVATE(node, NULL);
	ng_unref(node);			/* free node itself */
	return 0;
}

/*
 * Hook disconnection.
 */
static int
ng_ether_disconnect(hook_p hook)
{
	const ether_priv_p priv = hook->node->private;
	hether_priv_p hpriv = NG_HOOK_PRIVATE(hook);

	if (hook == priv->upper)
		priv->upper = NULL;
	else if (hook == priv->lower) {
		priv->lower = NULL;
		if (priv->ifp) {
			ifnet_ether_detach(priv->ifp);
		}
	} else if (hook == priv->lower_in[hpriv->tag]) {
		priv->lower_in[hpriv->tag] = NULL;
	} else if (hook == priv->attach) {
		priv->attach = NULL;
	} else
		panic("%s: weird hook", __FUNCTION__);

	hook->hook_rcvdata = NULL;
	NG_HOOK_SET_PRIVATE(hook, NULL);
	ng_free(hpriv);
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

	if (*buflen < FP_ETHER_ADDR_LEN)
		return (ERANGE);
	for (i = 0; i < FP_ETHER_ADDR_LEN; i++) {
		val = strtoul(s + *off, &eptr, 16);
		if (val > 0xff || eptr == s + *off)
			return (EINVAL);
		buf[i] = (u_char)val;
		*off = (eptr - s);
		if (i < FP_ETHER_ADDR_LEN - 1) {
			if (*eptr != ':')
				return (EINVAL);
			(*off)++;
		}
	}
	*buflen = FP_ETHER_ADDR_LEN;
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
	*off += FP_ETHER_ADDR_LEN;
	return (0);
}

/******************************************************************
		    	INITIALIZATION
******************************************************************/

/*
 * Handle loading and unloading for this node type.
 */
int ng_ether_init(void)
{
	int error;
	void *type = &ng_ether_typestruct;

	TRACE_VNB(FP_LOG_DEBUG, "VNB: Loading ng_ether\n");

	if ((error = ng_newtype(type)) != 0) {
		TRACE_VNB(FP_LOG_ERR, "VNB: ng_ether_init failed (%d)\n", error);
		return -EINVAL;
	}

	return 0;
}

/*
 * Handle a packet that has come in on an interface. We get to
 * look at it here before any upper layer protocols do.
 *
 */
int ng_ether_input(struct mbuf *m, fp_ifnet_t *ifp, void *data)
{
	if ((IFP2FLAGS(ifp, fp_get_vnb_ns()) & IFF_NG_ETHER) == 0)
		return FP_CONTINUE;

	const ether_priv_p priv = IFP2ETHER(ifp, fp_get_vnb_ns());

	FPN_ASSERT(priv);

	/* lower is connected when we enter here */
	ng_send_data_fast(priv->lower, m, NULL);
	return FP_DONE;
}
