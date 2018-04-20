/*
 * Copyright(c) 2007 6WIND
 */
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
 * $FreeBSD: src/sys/netgraph/ng_eiface.c,v 1.4.2.5 2002/12/17 21:47:48 julian Exp $
 */

#include "fpn.h"
#include "fpn-cksum.h"
#include "fp-includes.h"
#include "fp-main-process.h"
#include "fp-ether.h"

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_eiface.h>

#include "fp-ng_eiface.h"

#define IFP2EIFACE(ifp, ns) (eiface_priv_p)fp_vnb_shared->if_ops[IFP2IDX(ifp)].if_vnb_ops[ns].eiface.u.priv
#define SET_IFP2EIFACE(ifp, val, ns) fp_vnb_shared->if_ops[IFP2IDX(ifp)].if_vnb_ops[ns].eiface.u.priv = (val)

static const struct ng_parse_struct_field ng_eiface_par_fields[]
	= NG_EIFACE_PAR_FIELDS;

static const struct ng_parse_type ng_eiface_par_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_eiface_par_fields
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
	{ 0, 0, NULL, NULL, NULL }
};

/* Node cache info */
/* hook->node_cache is used to store attached interface pointer */

/* list of eiface priv to bind interface */
static FPN_DEFINE_SHARED(FPN_LIST_HEAD(, ng_eiface_private), eiface_list_ns[VNB_MAX_NS]);

/* Netgraph methods */
static ng_constructor_t	ng_eiface_constructor;
static ng_rcvmsg_t	ng_eiface_rcvmsg;
static ng_shutdown_t	ng_eiface_rmnode;
static ng_newhook_t	ng_eiface_newhook;
static ng_rcvdata_t	ng_eiface_rcvdata;
static ng_connect_t	ng_eiface_connect;
static ng_disconnect_t	ng_eiface_disconnect;
static ng_restorenode_t ng_eiface_restorenode;

/* Node type descriptor */
static FPN_DEFINE_SHARED(struct ng_type, typestruct) = {
	.version = NG_VERSION,
	.name = NG_EIFACE_NODE_TYPE,
	.mod_event = NULL,
	.constructor = ng_eiface_constructor,
	.rcvmsg = ng_eiface_rcvmsg,
	.shutdown = ng_eiface_rmnode,
	.newhook = ng_eiface_newhook,
	.findhook = NULL,
	.connect = ng_eiface_connect,
	.rcvdata = ng_eiface_rcvdata,
	.rcvdataq = ng_eiface_rcvdata,
	.disconnect = ng_eiface_disconnect,
	.rcvexception = NULL,
	.cmdlist = ng_eiface_cmdlist,
	.restorenode = ng_eiface_restorenode,
};

/* return 1 if IFF_NG_EIFACE is present in at least one vnb_ns */
static int ifnet_eiface_attached(fp_ifnet_t *ifp)
{
	int i;

	for (i = 0; i < CONFIG_MCORE_VNB_MAX_NS; i++) {
		if (IFP2FLAGS(ifp, i) & IFF_NG_EIFACE)
			return 1;
	}
	return 0;
}

static inline int ifnet_eiface_attach(fp_ifnet_t *ifp)
{
	/* already attached */
	if (ifnet_eiface_attached(ifp) == 1)
		return 0;

	if (fp_ifnet_ops_register(ifp, TX_DEV_OPS, vnb_moduid, ifp))
		return EINVAL;

	IFP2FLAGS(ifp, ctrl_vnb_ns) |= IFF_NG_EIFACE;
	return 0;
}

static inline void ifnet_eiface_detach(fp_ifnet_t *ifp)
{
	/* not attached */
	if (ifnet_eiface_attached(ifp) == 0)
		return;

	IFP2FLAGS(ifp, ctrl_vnb_ns) &= ~IFF_NG_EIFACE;

	/* still attached in the other vnb_ns */
	if (ifnet_eiface_attached(ifp) == 1)
		return;

	fp_ifnet_ops_unregister(ifp, TX_DEV_OPS);
}

int ng_eiface_init(void)
{
	int error;
	void *type = &typestruct;
	uint16_t ns;

	TRACE_VNB(FP_LOG_DEBUG, "VNB: Loading ng_eiface\n");
	if ((error = ng_newtype(type)) != 0) {
		log(LOG_ERR, "Unable to register type eiface");
		return error;
	}

	for (ns = 0; ns < VNB_MAX_NS; ns++)
		FPN_LIST_INIT(&per_ns(eiface_list, ns));

	return 0;
}

static eiface_priv_p ng_eiface_find(fp_ifnet_t *ifp)
{
	eiface_priv_p priv;

	FPN_LIST_FOREACH(priv, &per_ns(eiface_list, ctrl_vnb_ns), chain) {
		 if (priv->ifname && strncmp(priv->ifname, ifp->if_name, 
			      FP_IFNAMSIZ) == 0)
			 return priv;
	}
	return NULL;
}


/************************************************************************
			INTERFACE STUFF
 ************************************************************************/

/************************************************************************
			NETGRAPH NODE STUFF
 ************************************************************************/

static void ng_eiface_unlink(fp_ifnet_t *ifp, eiface_priv_p priv)
{
	TRACE_VNB(FP_LOG_DEBUG, "Detaching eiface %p", ifp);
	ifnet_eiface_detach(ifp);
	SET_IFP2EIFACE(ifp, NULL, ctrl_vnb_ns);
	if (priv->ether) /* hook is connected */
		NG_HOOK_SET_NODE_CACHE(priv->ether, NULL);
	priv->ifp = NULL;
}

void ng_eiface_link(fp_ifnet_t *ifp, eiface_priv_p priv)
{
	TRACE_VNB(FP_LOG_DEBUG, "Attaching eiface to interface %s", ifp->if_name);
	SET_IFP2EIFACE(ifp, priv, ctrl_vnb_ns);
	if (priv->ether)
		NG_HOOK_SET_NODE_CACHE(priv->ether, ifp);
	priv->ifp = ifp;
	ifnet_eiface_attach(ifp);
}

int ng_eiface_attach(fp_ifnet_t *ifp)
{
	eiface_priv_p priv;

	priv = ng_eiface_find(ifp);
	if (priv == NULL) {
		ifnet_eiface_detach(ifp);
		return 0;
	}
	ng_eiface_link(ifp, priv);

	return 0;
}

int ng_eiface_detach(fp_ifnet_t *ifp, uint8_t vnb_keep_node)
{
	eiface_priv_p priv;
    
	ifnet_eiface_detach(ifp);
	priv = ng_eiface_find(ifp);
	if (priv == NULL) /* not attached */
		return 0;

	/* When vnb_keep_node != 0, interface moves to another vrf. We need to
	 * unlink the ng_eiface node (like when interface is destroyed).
	 * However, the interface may be already created in the new vrf (and so
	 * already linked to this node), hence we need to check the ifuid before
	 * unlinking the node.
	 */
	if (vnb_keep_node == 0 ||
	    (priv->ifp && priv->ifp->if_ifuid == ifp->if_ifuid))
		ng_eiface_unlink(ifp, priv);
	return 0;
}

/*
 * Constructor for a node
 */
static int
ng_eiface_constructor(node_p *nodep, ng_ID_t nodeid)
{
	eiface_priv_p priv;
	node_p node;
	int error = 0;	

	/* Call generic node constructor */
	if ((error = ng_make_node_common(&typestruct, nodep, nodeid))) {
		VNB_TRAP("errno=%d", error);
		return error;
	}

	/* Allocate private data */
	priv = (eiface_priv_p) ng_malloc(sizeof(*priv), M_NOWAIT);
	if (priv == NULL) {
		VNB_TRAP("ENOMEM");
		log(LOG_ERR, "%s: can't  allocate \n", __FUNCTION__);
		return ENOMEM;
	}

	node = *nodep;

	bzero(priv, sizeof(*priv));
	/* Link together node and private info */
	NG_NODE_SET_PRIVATE(node, priv);
	priv->node = node;
	FPN_LIST_INSERT_HEAD(&per_ns(eiface_list, ctrl_vnb_ns), priv, chain);

	/* Done */
	return 0;
}

/*
 * Give our ok for a hook to be added
 */
static int
ng_eiface_newhook(node_p node, hook_p hook, const char *name)
{
	eiface_priv_p priv = node->private;

	if (fpn_fast_memcmp(name, NG_EIFACE_HOOK_ETHER, sizeof(NG_EIFACE_HOOK_ETHER)))
		return EINVAL;
	if (priv->ether != NULL)
		return (EISCONN);
	priv->ether = hook;
	NG_HOOK_SET_NODE_CACHE(hook, priv->ifp); /* might be null if not attached */
	if (priv->ifp)
		ifnet_eiface_attach(priv->ifp);
	return 0;
}

static int
ng_eiface_set_ifname(struct ng_eiface_ifname *arg, eiface_priv_p priv)
{
	fp_ifnet_t *ifp = priv->ifp;

	if (ifp != NULL) { /* already attached and named */
		VNB_TRAP("EINVAL");
		return EINVAL;
	}


	if (strlen(arg->ngif_name) == 0) {
		VNB_TRAP("EINVAL");
		return EINVAL;
	}

	/* update name */
	strncpy(priv->ifname, arg->ngif_name, FP_IFNAMSIZ);
	priv->ifname[FP_IFNAMSIZ-1] = '\0';

	/* it might happen that interface has been created */
	if ((ifp = fp_getifnetbyname(priv->ifname)) != NULL)
		ng_eiface_link(ifp, priv);
	return 0;
}

/*
 * Receive a control message
 */
static int
ng_eiface_rcvmsg(node_p node, struct ng_mesg *msg,
		 const char *retaddr, struct ng_mesg **rptr,
		 struct ng_mesg **nl_msg)
{
	eiface_priv_p priv = node->private;
	fp_ifnet_t *ifp;
	struct ng_mesg *resp = NULL;
	int error = 0;

	ifp = priv->ifp; /* may be NULL */

	switch (msg->header.typecookie) {
	case NGM_EIFACE_COOKIE:
		switch (msg->header.cmd) {

		case NGM_EIFACE_SET_IFNAME:
			{
				struct ng_eiface_ifname *arg;
				arg = (struct ng_eiface_ifname *) msg->data;

				error = ng_eiface_set_ifname(arg, priv);
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
			    "%s", ifp->if_name);
			break;
		    }

		case NGM_EIFACE_GET_IFADDRS:
			log(LOG_ERR, "NGM_EIFACE_GET_IFADDRS not supported\n");
			error = EINVAL;
			break;
		case NGM_EIFACE_SET:
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
	else if (resp)
		FREE(resp, M_NETGRAPH);
	FREE(msg, M_NETGRAPH);
	return (error);
}

/*
 * Receive data from a hook. Pass the packet to the ether_input routine.
 */
static int
ng_eiface_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	int ret;
	fp_ifnet_t *const ifp = (fp_ifnet_t *)NG_HOOK_NODE_CACHE(hook);
  
	/* Meta-data is end its life here... */
	NG_FREE_META(meta);

	if (unlikely(ifp == NULL)) { /* not yet attached */
		/* here we may call vnb_attach_all() to update bindings */
		m_freem(m);
		return ENETDOWN;
	}

	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_dropped);
		m_freem(m);
		return (ENETDOWN);
	}

	fp_change_ifnet_packet(m, ifp, 1, 0);
	m_priv(m)->exc_type = FPTUN_ETH_INPUT_EXCEPT;
	ret = FPN_HOOK_CALL(fp_ether_input)(m, ifp);
	fp_process_input_finish(m, ret);

	return 0;
}

static int
ng_eiface_rmnode(node_p node)
{
	const eiface_priv_p	priv = NG_NODE_PRIVATE(node);
	fp_ifnet_t	* const ifp = priv->ifp;

	node->flags |= NG_INVALID;

	if (ifp)
		ng_eiface_detach(ifp, 0);

	FPN_LIST_REMOVE(priv, chain);

	ng_cutlinks(node);
	ng_unname(node);

	/* Free private data */
	NG_NODE_SET_PRIVATE(node, NULL);
	ng_free(priv);

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
	const eiface_priv_p priv = hook->node->private;

	if (priv->ifp)
		ifnet_eiface_detach(priv->ifp);
	priv->ether = NULL;
	return (0);
}

static void
ng_eiface_restorenode(struct ng_nl_nodepriv *nlnodepriv, node_p node)
{
	struct ng_eiface_ifname *ifname;
	eiface_priv_p priv = node->private;
	int error;

	if (ntohl(nlnodepriv->data_len) != sizeof(*ifname)) {
		TRACE_VNB(FP_LOG_ERR, "FPVNB: size mismatch (%d instead of %zu",
			  nlnodepriv->data_len,
			  sizeof(*ifname));
		return;
	}

	ifname = (struct ng_eiface_ifname *) nlnodepriv->data;

	error = ng_eiface_set_ifname(ifname, priv);

	/* Inform the compiler that error can be never read */
	(void)error;

	TRACE_VNB(FP_LOG_DEBUG, "FPVNB:  eiface_priv ifname=%s - error =%d\n",
		  ifname->ngif_name, error);
}

int ng_eiface_output(struct mbuf *m, fp_ifnet_t *ifp, void *data)
{
	int ret;
	int len __fpn_maybe_unused = m_len(m);

	if (unlikely((IFP2FLAGS(ifp, fp_get_vnb_ns()) & IFF_NG_EIFACE) == 0))
		return FP_CONTINUE;

	const eiface_priv_p priv = IFP2EIFACE(ifp, fp_get_vnb_ns());

#ifdef CONFIG_MCORE_USE_HW_TX_L4CKSUM
	fpn_deferred_in4_l4cksum_set(m, FP_ETHER_HDR_LEN);
#endif

	M_TRACK(m, "VNB");
	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_dropped);
		m_freem(m);
		return FP_DONE;
	}

	FP_IF_STATS_INC(ifp->if_stats, ifs_opackets);
	FP_IF_STATS_ADD(ifp->if_stats, ifs_obytes, len);
	/* ether is connected when we enter here */
	ret = ng_send_data_fast(priv->ether, m, NULL);
	/* warning: m could have been freed */
	if (unlikely(ret)) {
		FP_IF_STATS_DEC(ifp->if_stats, ifs_opackets);
		FP_IF_STATS_SUB(ifp->if_stats, ifs_obytes, len);
		FP_IF_STATS_INC(ifp->if_stats, ifs_oerrors);
	}
	return FP_DONE;
}
