/*
 * Copyright(c) 2007 6WIND
 */
/*
 * ng_iface.c
 */

#include "fpn.h"
#include "fp-includes.h"
#include "fp-main-process.h"
#ifdef CONFIG_MCORE_IP
#include "fp-ip.h"
#endif
#ifdef CONFIG_MCORE_IPV6
#include "fp-ip6.h"
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_hash_name.h>

#include "fp-ng_iface.h"

#undef panic
#define panic(x) fpn_printf("PANIC %s\n", (x))

/* Netgraph methods */
static ng_constructor_t	ng_iface_constructor;
static ng_rcvmsg_t	ng_iface_rcvmsg;
static ng_shutdown_t	ng_iface_rmnode;
static ng_newhook_t	ng_iface_newhook;
static ng_disconnect_t	ng_iface_disconnect;
static ng_restorenode_t	ng_iface_restorenode;

/* Helper stuff */
static iffam_p	get_iffam_from_hook(iface_priv_p priv, hook_p hook);
static iffam_p	get_iffam_from_name(const char *name);
static int ng_iface_rcvdata_inet(hook_p hook, struct mbuf *m, meta_p meta);
static int ng_iface_rcvdata_inet6(hook_p hook, struct mbuf *m, meta_p meta);
static int ng_iface_rcvdata_allip(hook_p hook, struct mbuf *m, meta_p meta);

/* Parse type for struct ng_iface_ifname */
static const struct ng_parse_fixedstring_info ng_iface_ifname_info = {
	NG_IFACE_IFACE_NAME_MAX + 1
};
static const struct ng_parse_type ng_iface_ifname_type = {
	.supertype = &ng_parse_fixedstring_type,
	.info = &ng_iface_ifname_info
};

/* Parse types for struct ng_iface_info */
static const struct ng_parse_struct_field ng_iface_info_fields[] = {
	{ "id", &ng_parse_hint32_type, 0 },
	{ "index", &ng_parse_uint32_type, 0 },
	{ "name", &ng_iface_ifname_type, 0 },
	{ NULL, NULL, 0 }
};

static const struct ng_parse_type ng_iface_info_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_iface_info_fields
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
	  NGM_IFACE_GET_IFTYPE,
	  "getiftype",
	  NULL,
	  &ng_parse_uint16_type
	},
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_SET_IFTYPE,
	  "setiftype",
	  &ng_iface_ifname_type,
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
	  NULL,
	  NULL
	},
	{
	  NGM_IFACE_COOKIE,
	  NGM_IFACE_SET_KEY,
	  "setkey",
	  NULL,
	  NULL
	},
	{ 0, 0, NULL, NULL, NULL }
};

/* list of iface priv to bind interface */
#if defined(CONFIG_MCORE_IFACE_HASH_ORDER)
#define IFACE_HASH_ORDER CONFIG_MCORE_IFACE_HASH_ORDER
#else
#define IFACE_HASH_ORDER 11
#endif
#define IFACE_HASH_SIZE	(1 << IFACE_HASH_ORDER)

#define NG_IFACEHASH(NAME, HASH)					\
	do {							\
		(HASH) = ng_hash_name(NAME, 0, IFACE_HASH_SIZE);			\
	} while (0)

static FPN_DEFINE_SHARED(FPN_LIST_HEAD(, ng_iface_private), iface_list_ns[VNB_MAX_NS][IFACE_HASH_SIZE]);

/* Node type descriptor */
static FPN_DEFINE_SHARED(struct ng_type, typestruct) = {
	.version = NG_VERSION,
	.name = NG_IFACE_NODE_TYPE,
	.mod_event = NULL,
	.constructor = ng_iface_constructor,
	.rcvmsg = ng_iface_rcvmsg,
	.shutdown = ng_iface_rmnode,
	.newhook = ng_iface_newhook,
	.findhook = NULL,
	.connect = NULL,
	.rcvdata = NULL,			/* Only specific receive data functions */
	.rcvdataq = NULL,			/* Only specific receive data functions */
	.disconnect = ng_iface_disconnect,
	.rcvexception = NULL,
	.cmdlist = ng_iface_cmds,
	.restorenode = ng_iface_restorenode,
};

/* return 1 if IFF_NG_IFACE is present in at least one vnb_ns */
static int ifnet_iface_attached(fp_ifnet_t *ifp)
{
	int i;

	for (i = 0; i < CONFIG_MCORE_VNB_MAX_NS; i++) {
		if (IFP2FLAGS(ifp, i) & IFF_NG_IFACE)
			return 1;
	}
	return 0;
}

static inline int ifnet_iface_attach(fp_ifnet_t *ifp)
{
	/* already attached */
	if (ifnet_iface_attached(ifp) == 1)
		return 0;

	if (fp_ifnet_ops_register(ifp, IP_OUTPUT_OPS, vnb_moduid, ifp))
		return EINVAL;

	IFP2FLAGS(ifp, ctrl_vnb_ns) |= IFF_NG_IFACE;
	return 0;
}

static inline void ifnet_iface_detach(fp_ifnet_t *ifp)
{
	/* not attached */
	if (ifnet_iface_attached(ifp) == 0)
		return;

	IFP2FLAGS(ifp, ctrl_vnb_ns) &= ~IFF_NG_IFACE;

	/* still attached in the other vnb_ns */
	if (ifnet_iface_attached(ifp) == 1)
		return;

	fp_ifnet_ops_unregister(ifp, IP_OUTPUT_OPS);
}

int ng_iface_init(void)
{
	int error;
	unsigned int i;
	void *type = &typestruct;
	uint16_t ns;

	TRACE_VNB(FP_LOG_DEBUG, "VNB: Loading ng_iface\n");
	if ((error = ng_newtype(type)) != 0) {
		log(LOG_ERR, "Unable to register type iface");
		return error;
	}

	for (ns = 0; ns < VNB_MAX_NS; ns++)
		for (i = 0; i < IFACE_HASH_SIZE; i++)
			FPN_LIST_INIT(&per_ns(iface_list, ns)[i]);

	return 0;
}

static iface_priv_p ng_iface_find(fp_ifnet_t *ifp)
{
	iface_priv_p priv;
	u_int32_t hash;

	NG_IFACEHASH(ifp->if_name, hash);

	FPN_LIST_FOREACH(priv, &per_ns(iface_list, ctrl_vnb_ns)[hash], chain) {
		 if (priv->ifname && strncmp(priv->ifname, ifp->if_name, 
			      FP_IFNAMSIZ) == 0)
			 return priv;
	}
	return NULL;
}

/************************************************************************
			NETGRAPH NODE STUFF
 ************************************************************************/


/*
 * Constructor for a node
 */
static int
ng_iface_constructor(node_p *nodep, ng_ID_t nodeid)
{
	node_p node;
	iface_priv_p priv;
	int error = 0;

	/* Call generic node constructor */
	if ((error = ng_make_node_common(&typestruct, nodep, nodeid)) != 0)
		return (error);

	/* Allocate private data */
	priv = (iface_priv_p) ng_malloc(sizeof(*priv), M_NOWAIT);
	if (priv == NULL) {
		VNB_TRAP("ENOMEM");
		log(LOG_ERR, "%s: can't  allocate \n", __FUNCTION__);
		return ENOMEM;
	}

	/* Link together node and private info */
	node = *nodep;

	bzero(priv, sizeof(*priv));
	NG_NODE_SET_PRIVATE(node, priv);
	priv->node = node;

	/* Done */
	return (0);
}

/*
 * Give our ok for a hook to be added
 */
static int
ng_iface_newhook(node_p node, hook_p hook, const char *name)
{
	const iffam_p iffam = get_iffam_from_name(name);
	hook_p *hookptr;
	const iface_priv_p priv = node->private;

	if (strncmp(name, NG_IFACE_HOOK_ALLIP_IN_PREFIX,
		     sizeof (NG_IFACE_HOOK_ALLIP_IN_PREFIX) -1) == 0) {
		hook->hook_rcvdata = ng_iface_rcvdata_allip;
		return 0;
	}

	if (iffam == NULL)
		return (EAFNOSUPPORT);
	hookptr = get_hook_from_iffam((iface_priv_p) node->private, iffam);
	if (*hookptr != NULL) {
		VNB_TRAP("EISCONN");
		return (EISCONN);
	}
	*hookptr = hook;

	if (likely(hook == priv->hooks[FP_NGIFACE_IDX_INET]))
		hook->hook_rcvdata = ng_iface_rcvdata_inet;
	else if (likely(hook == priv->hooks[FP_NGIFACE_IDX_INET6]))
		hook->hook_rcvdata = ng_iface_rcvdata_inet6;
	else
		hook->hook_rcvdata = ng_iface_rcvdata_allip;

	return (0);
}

static void ng_iface_unlink(fp_ifnet_t *ifp, iface_priv_p priv)
{
	ifnet_iface_detach(ifp);
	priv->ifp = NULL;
	SET_IFP2IFACE(ifp, NULL, ctrl_vnb_ns);
}

static void ng_iface_link(fp_ifnet_t *ifp, iface_priv_p priv)
{
	SET_IFP2IFACE(ifp, priv, ctrl_vnb_ns);
	priv->ifp = ifp;
	ifnet_iface_attach(ifp);
}

int ng_iface_attach(fp_ifnet_t *ifp)
{
	iface_priv_p priv;

	priv = ng_iface_find(ifp);
	if (priv == NULL) {
		ifnet_iface_detach(ifp);
		return 0;
	}
	ng_iface_link(ifp, priv);

	return 0;
}

int ng_iface_detach(fp_ifnet_t *ifp, uint8_t vnb_keep_node)
{
	iface_priv_p priv;

	ifnet_iface_detach(ifp);
	priv = ng_iface_find(ifp);
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
		ng_iface_unlink(ifp, priv);
	return 0;
}
/*
 * Register network interface and rename node accordingly.
 * Return zero on success or errno otherwise.
 */
static int ng_iface_register(node_p node, const char *boardname, size_t size, int force)
{
	const iface_priv_p priv = node->private;
	fp_ifnet_t *ifp;
	char *oldname, *node_name;
	int len;
	u_int32_t hash;

	len = strlen(boardname);
	if ( ! ( (len >= 2) && (len <= NG_NODELEN) ) ) {
		log(LOG_ERR, "%s: NGM_IFACE_SET_IFNAME %s bad length\n", node->name,
				boardname);
		return EINVAL;
	}

	if ( len > FP_IFNAMSIZ ) {
		log(LOG_ERR, "%s: NGM_IFACE_SET_IFNAME %s bad ifname length\n",
				node->name, boardname);
		return EINVAL;
	}

	if (force)
		goto name_node;

	/* Check the name isn't already being used */
	if (((node->name == NULL) || (strcmp(node->name, boardname) != 0)) &&
	    (ng_findname(node, boardname) != NULL)) {
		log(LOG_ERR, "%s: NGM_IFACE_SET_IFNAME %s already used\n",
				node->name, boardname);
		return EEXIST;
	}

 name_node:
	oldname = node->name;
	/*
	 * Allocate space and copy it
	 * ng_base.c: ng_name_node() uses M_NETGRAPH for the node->name field too.
	 */
	node_name = ng_malloc(FP_IFNAMSIZ, M_NOWAIT);
	if (node_name == NULL) {
		log(LOG_ERR, "%s: NGM_IFACE_SET_IFNAME %s no mem\n",
				oldname, boardname);
		return ENOMEM;
	}
	strncpy(node_name, boardname, FP_IFNAMSIZ);
	node->name = node_name;
	ng_rehash_node(node);
	strncpy(priv->ifname, boardname, sizeof(priv->ifname)-1);

	NG_IFACEHASH(node_name, hash);
	FPN_LIST_INSERT_HEAD(&per_ns(iface_list, ctrl_vnb_ns)[hash], priv, chain);

	/* it might happen that interface has been created */
	if ((ifp = fp_getifnetbyname(priv->ifname)) != NULL)
		ng_iface_link(ifp, priv);

	if (oldname)
		ng_free(oldname);

	return 0;
}

/*
 * Receive a control message
 */
static int
ng_iface_rcvmsg(node_p node, struct ng_mesg *msg,
		const char *retaddr, struct ng_mesg **rptr,
		struct ng_mesg **nl_msg)
{
	const iface_priv_p priv = node->private;
	fp_ifnet_t *ifp = priv->ifp;
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_IFACE_COOKIE:
		switch (msg->header.cmd) {
		case NGM_IFACE_GET_IFNAME:
		case NGM_IFACE_SETGET_IFNAME:
		case NGM_IFACE_SET_IFNAME:
		{
			if (msg->header.cmd != NGM_IFACE_GET_IFNAME) {
				/* change name */
				if ((error = ng_iface_register(node, msg->data, msg->header.arglen, 0)))
					break;
				/* priv->ifp can be udpated by ng_iface_register() */
				ifp = priv->ifp;
			}

			if (msg->header.cmd != NGM_IFACE_SET_IFNAME) {
				struct ng_iface_ifname *arg;

				NG_MKRESPONSE(resp, msg, sizeof(*arg), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				arg = (struct ng_iface_ifname *)resp->data;
				if (!ifp)
					memset(arg->ngif_name, 0, sizeof(arg->ngif_name));
				else
					snprintf(arg->ngif_name, sizeof(arg->ngif_name),
						"%s", ifp->if_name);
			}
			break;
		}
		case NGM_IFACE_GET_INFO:
		case NGM_IFACE_SETGET_INFO:
		case NGM_IFACE_SET_INFO:
		{
			struct ng_iface_info *arg;

			if (msg->header.cmd != NGM_IFACE_GET_INFO) {
				arg = (struct ng_iface_info *)msg->data;
				/* change name */
				if ((error = ng_iface_register(node, arg->name, sizeof(arg->name), 0)))
					break;
				/* priv->ifp can be udpated by ng_iface_register() */
				ifp = priv->ifp;
			}

			if (msg->header.cmd != NGM_IFACE_SET_INFO) {
				NG_MKRESPONSE(resp, msg, sizeof(*arg), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}

				arg = (struct ng_iface_info *)resp->data;
				arg->id = ng_node2ID(node);
				/* No ifindex in the fast path */
				arg->index = 0;
				if (!ifp)
					/* The ifnet does not exist */
					memset(arg->name, 0, sizeof(arg->name));
				else
					snprintf(arg->name, sizeof(arg->name),
						"%s", ifp->if_name);
			}
			break;
		}

		case NGM_IFACE_POINT2POINT:
		case NGM_IFACE_BROADCAST:
		case NGM_IFACE_GET_IFADDRS:
		case NGM_IFACE_GET_IFTYPE:
		case NGM_IFACE_SET_IFTYPE:
		case NGM_IFACE_SET_CARRIER:
		case NGM_IFACE_SET_ENCAPADDR:
		case NGM_IFACE_SET_KEY:
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
 * Receive data from allip hook. Pass the packet to the FP input routine.
 */
static int
ng_iface_rcvdata_allip(hook_p hook, struct mbuf *m, meta_p meta)
{
	const iface_priv_p priv = hook->node_private;
	fp_ifnet_t *ifp;
	int ret;
	u_char *p;

	/* Meta-data is end its life here... */
	NG_FREE_META(meta);

	/* Sanity checks */
	if (m == NULL)
		return (EINVAL);

	if (!priv) {
		m_freem(m);
		return (ENOTCONN);
	}

	ifp = priv->ifp;
	if (unlikely(ifp == NULL)) {
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

	/*
	 * This is the ALLIP case
	 */
	p = mtod(m, u_char *);
	if (likely((*p & 0xf0) == 0x40)) {
		/* TBD change this exception */
		m_priv(m)->exc_type = FPTUN_IFACE_INPUT_EXCEPT;
		m_priv(m)->exc_proto = htons(FP_ETHERTYPE_IP);
		fp_change_ifnet_packet(m, ifp, 1, 1);
#ifdef CONFIG_MCORE_IP
		ret = FPN_HOOK_CALL(fp_ip_input)(m);
#else
		fp_prepare_exception(m, FPTUN_EXC_SP_FUNC);
		ret = FP_NONE;
#endif
	} else {
		/* TBD change this exception */
		m_priv(m)->exc_type = FPTUN_IFACE_INPUT_EXCEPT;
		m_priv(m)->exc_proto = htons(FP_ETHERTYPE_IPV6);
		fp_change_ifnet_packet(m, ifp, 1, 1);
#ifdef CONFIG_MCORE_IPV6
		ret = FPN_HOOK_CALL(fp_ip6_input)(m);
#else
		fp_prepare_exception(m, FPTUN_EXC_SP_FUNC);
		ret = FP_NONE;
#endif
	}

	fp_process_input_finish(m, ret);
	return 0;
}

static int ng_iface_rcvdata_inet(hook_p hook, struct mbuf *m, meta_p meta)
{
	const iface_priv_p priv = hook->node_private;
	fp_ifnet_t *ifp;
	int ret;

	/* Meta-data is end its life here... */
	NG_FREE_META(meta);

	/* Sanity checks */
	if (m == NULL)
		return (EINVAL);

	if (!priv) {
		m_freem(m);
		return (ENOTCONN);
	}

	ifp = priv->ifp;
	if (unlikely(ifp == NULL)) {
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

	/*
	 * Stack selection is driven by reception hook
	 */
	m_priv(m)->exc_type = FPTUN_IFACE_INPUT_EXCEPT;
	m_priv(m)->exc_proto = htons(FP_ETHERTYPE_IP);
	fp_change_ifnet_packet(m, ifp, 1, 1);
#ifdef CONFIG_MCORE_IP
	ret = FPN_HOOK_CALL(fp_ip_input)(m);
#else
	fp_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	ret = FP_NONE;
#endif

	fp_process_input_finish(m, ret);
	return 0;
}

static int ng_iface_rcvdata_inet6(hook_p hook, struct mbuf *m, meta_p meta)
{
	const iface_priv_p priv = hook->node_private;
	fp_ifnet_t *ifp;
	int ret;

	/* Meta-data is end its life here... */
	NG_FREE_META(meta);

	/* Sanity checks */
	if (m == NULL)
		return (EINVAL);

	if (!priv) {
		m_freem(m);
		return (ENOTCONN);
	}

	ifp = priv->ifp;
	if (unlikely(ifp == NULL)) {
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

	/*
	 * Stack selection is driven by reception hook
	 */
	m_priv(m)->exc_type = FPTUN_IFACE_INPUT_EXCEPT;
	m_priv(m)->exc_proto = htons(FP_ETHERTYPE_IPV6);
	fp_change_ifnet_packet(m, ifp, 1, 1);
#ifdef CONFIG_MCORE_IPV6
	ret = FPN_HOOK_CALL(fp_ip6_input)(m);
#else
	fp_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	ret = FP_NONE;
#endif
	fp_process_input_finish(m, ret);
	return 0;
}

/*
 * Shutdown and remove the node and its associated interface.
 */
static int
ng_iface_rmnode(node_p node)
{
	static const FPN_LIST_ENTRY(ng_iface_private) empty_element;
	const iface_priv_p priv = NG_NODE_PRIVATE(node);
	fp_ifnet_t *const ifp = priv->ifp;

	ng_cutlinks(node);
	ng_unname(node);
	if (ifp)
		ng_iface_detach(ifp, 0);

	/* Delete only when it has been linked before */
	if (memcmp(&priv->chain, &empty_element, sizeof(priv->chain)))
		FPN_LIST_REMOVE(priv, chain);

	/* do not free the ifp structure. actual release may be delayed
	 * due because some objects still point on this device (e.g. a route
	 * cache stored into a sockets. The Linux kernel will free the structure
	 * itself */
	NG_NODE_SET_PRIVATE(node, NULL);
	ng_free(priv);

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
	const iface_priv_p priv = hook->node->private;
	const iffam_p iffam = get_iffam_from_hook(priv, hook);

	if (strncmp(hook->name, NG_IFACE_HOOK_ALLIP_IN_PREFIX,
		    sizeof (NG_IFACE_HOOK_ALLIP_IN_PREFIX) - 1) == 0) {
		hook->hook_rcvdata = NULL;
		return 0;
	}

	if (iffam == NULL)
		panic(__FUNCTION__);
	hook->hook_rcvdata = NULL;
	*get_hook_from_iffam(priv, iffam) = NULL;
	return (0);
}

static void
ng_iface_restorenode(struct ng_nl_nodepriv *nlnodepriv, node_p node)
{
	struct ng_iface_ifname *ifname;
	int error;

	if (ntohl(nlnodepriv->data_len) != sizeof(*ifname)) {
		TRACE_VNB(FP_LOG_ERR, "FPVNB: size mismatch (%d instead of %zu)",
			  nlnodepriv->data_len,
			  sizeof(*ifname));
		return;
	}

	ifname = (struct ng_iface_ifname *) nlnodepriv->data;

	error = ng_iface_register(node, ifname->ngif_name, strlen(ifname->ngif_name), 1);

	/* Inform the compiler that error can be never read */
	(void)error;

	TRACE_VNB(FP_LOG_DEBUG, "FPVNB:  iface_priv ifname=%s - error =%d\n",
		  ifname->ngif_name, error);
}

/************************************************************************
			FPN ng_iface_output
 ************************************************************************/


int ng_iface_output(struct mbuf *m, fp_ifnet_t *ifp, int af, void *data)
{
	const iface_priv_p priv = IFP2IFACE(ifp, fp_get_vnb_ns());
	hook_p hook, send_hook;
	int ret;
	int len __fpn_maybe_unused = m_len(m);
	int hook_idx;

	if (af == AF_INET6)
		hook_idx = FP_NGIFACE_IDX_INET6;
	else
		hook_idx = FP_NGIFACE_IDX_INET;

	if (likely((m_priv(m)->flags & M_LOCAL_OUT) == 0)) {
		if (hook_idx == FP_NGIFACE_IDX_INET)
			FP_IP_STATS_INC(fp_shared->ip_stats, IpForwDatagrams);
#ifdef CONFIG_MCORE_IPV6
		else
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpForwDatagrams);
#endif
	}

	/*
	 * If the ALL-IP is connected, use it,
	 * else use specific hook
	 */
	send_hook = priv->hooks[FP_NGIFACE_IDX_ALLIP];
	if (send_hook)
		hook = send_hook;
	else 
		hook = priv->hooks[hook_idx];

	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_dropped);
		m_freem(m);
		return FP_DROP;
	}

	/*
	 * Keep track of IP TOS, for driving further encapsulation
	 */
	if (likely(hook_idx == FP_NGIFACE_IDX_INET)) {
		struct fp_ip *ip = mtod(m, struct fp_ip*);
		m_priv(m)->tos = ip->ip_tos;
		m_priv(m)->flags |= M_TOS;
	} else if (likely(hook_idx == FP_NGIFACE_IDX_INET6)) {
		u_char *p = mtod(m, u_char *);
		m_priv(m)->tos = ((p[0] & 0x0f) << 4) | ((p[1] & 0xf0) >> 4);
		m_priv(m)->flags |= M_TOS;
	}
	/* No TOS handling through the ALLIP hook */

	FP_IF_STATS_INC(ifp->if_stats, ifs_opackets);
	FP_IF_STATS_ADD(ifp->if_stats, ifs_obytes, len);
	ret = ng_send_data_fast(hook, m, NULL);
	/* warning: m could have been freed */
	if (unlikely(ret)) {
		FP_IF_STATS_DEC(ifp->if_stats, ifs_opackets);
		FP_IF_STATS_SUB(ifp->if_stats, ifs_obytes, len);
		FP_IF_STATS_INC(ifp->if_stats, ifs_oerrors);
	}
	return FP_DONE;
}
