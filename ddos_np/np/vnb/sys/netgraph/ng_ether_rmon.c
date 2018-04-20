/*
 * Copyright 2005-2013 6WIND S.A.
 */

/*
 * RMON etherStatistics
 * ----
 *
 * Loadable kernel module and netgraph support
 * Based on ng_vlan node
 *
 */

#include <linux/version.h>
#include <linux/module.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <netgraph/vnblinux.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_ether_rmon.h>

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_ETHER_RMON, "ng_ether_rmon",
				"netgraph RMON etherStats");
#else
#define M_NETGRAPH_ETHER_RMON M_NETGRAPH
#endif


/*
 * Local definitions
 */

struct ng_ether_rmon_private {
	node_p		node;				/* back pointer to node */

	struct ifnet	*ifp;				/* node device */
	struct ng_ether_rmon_stats	stats;		/* node stats */

	hook_p		lowerin;			/* lowerin hook connection */
	hook_p		lowerout;			/* lowerout hook connection */
	hook_p		upperin;			/* upperin hook connection */
	hook_p		upperout;			/* upperout hook connection */
};
typedef struct ng_ether_rmon_private *priv_p;

/*
 * Local functions
 */

/*
 * Netgraph node methods
 */
static ng_constructor_t ng_ether_rmon_constructor;
static ng_rcvmsg_t      ng_ether_rmon_rcvmsg;
static ng_shutdown_t    ng_ether_rmon_rmnode;
static ng_newhook_t     ng_ether_rmon_newhook;
static ng_rcvdata_t     ng_ether_rmon_rcvdata;
static ng_disconnect_t  ng_ether_rmon_disconnect;

/*
 * Local processing
 */
static int ng_ether_rmon_recv_lowerin(node_p node, struct mbuf *m, meta_p meta);
static int ng_ether_rmon_recv_lowerout(node_p node, struct mbuf *m, meta_p meta);
static int ng_ether_rmon_recv_upperin(node_p node, struct mbuf *m, meta_p meta);
static int ng_ether_rmon_recv_upperout(node_p node, struct mbuf *m, meta_p meta);


/*
 * Local variables
 */

/* Parse type for struct ng_ether_rmon_stats */
static const struct ng_parse_struct_field
	ng_ether_rmon_stats_type_fields[] = NG_ETHER_RMON_STATS_TYPE_INFO;
static const struct ng_parse_type ng_ether_rmon_stats_type = {
	&ng_parse_struct_type,
	&ng_ether_rmon_stats_type_fields
};

static const struct ng_cmdlist ng_ether_rmon_cmdlist[] = {
	{
	  NGM_ETHER_RMON_COOKIE,
	  NGM_ETHER_RMON_GET_STATS,
	  "getstats",
	  mesgType: NULL,
	  respType: &ng_ether_rmon_stats_type
	},
	{
	  NGM_ETHER_RMON_COOKIE,
	  NGM_ETHER_RMON_CLR_STATS,
	  "clrstats",
	  mesgType: NULL,
	  respType: NULL
	},
	{
	  NGM_ETHER_RMON_COOKIE,
	  NGM_ETHER_RMON_GETCLR_STATS,
	  "getclrstats",
	  mesgType: NULL,
	  respType: &ng_ether_rmon_stats_type
	},

	{ 0 }
};

/*
 * Node type descriptor
 */
static VNB_DEFINE_SHARED(struct ng_type, ng_ether_rmon_typestruct) = {
	version:    NG_VERSION,
	name:       NG_ETHER_RMON_NODE_TYPE,
	mod_event:  NULL,					/* Module event handler (optional) */
	constructor:ng_ether_rmon_constructor,			/* Node constructor */
	rcvmsg:     ng_ether_rmon_rcvmsg,			/* control messages come here */
	shutdown:   ng_ether_rmon_rmnode,			/* reset, and free resources */
	newhook:    ng_ether_rmon_newhook,			/* first notification of new hook */
	findhook:   NULL,					/* only if you have lots of hooks */
	connect:    NULL,					/* final notification of new hook */
	afterconnect: NULL,
	rcvdata:    ng_ether_rmon_rcvdata,			/* date comes here */
	rcvdataq:   ng_ether_rmon_rcvdata,			/* or here if being queued */
	disconnect: ng_ether_rmon_disconnect,			/* notify on disconnect */
	rcvexception: NULL,					/* exceptions come here */
	dumpnode: NULL,
	restorenode: NULL,
	dumphook: NULL,
	restorehook: NULL,
	cmdlist:    ng_ether_rmon_cmdlist,			/* commands we can convert */
};
NETGRAPH_INIT(ether_rmon, &ng_ether_rmon_typestruct);
NETGRAPH_EXIT(ether_rmon, &ng_ether_rmon_typestruct);

/******************************************************************
		    NETGRAPH NODE METHODS
 ******************************************************************/

/*
 * Node constructor
 *
 * Called at splnet()
 */
static int
ng_ether_rmon_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int error;

	/*
	 * Allocate and initialize private info
	 */
	priv = ng_malloc(sizeof(*priv), M_NOWAIT);
	if (priv == NULL)
		return (ENOMEM);
	bzero(priv, sizeof(*priv));

	/* Call superclass constructor that mallocs *nodep */
	if ((error = ng_make_node_common(&ng_ether_rmon_typestruct, nodep, nodeid))) {
		ng_free(priv);
		return (error);
	}
	NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->node = *nodep;

	/* Done */
	return (0);
}

static  int
ng_ether_rmon_newhook(node_p node, hook_p hook, const char *name)
{
        const priv_p priv = node->private;
        hook_p *hookptr;

        /* Which hook? */
        if (strcmp(name, NG_ETHER_RMON_HOOK_LOWERIN) == 0) {
		/* XXX We should try to know to which interface we are linked with here */
                hookptr = &priv->lowerin;
	}
        else if (strcmp(name, NG_ETHER_RMON_HOOK_LOWEROUT) == 0)
                hookptr = &priv->lowerout;
        else if (strcmp(name, NG_ETHER_RMON_HOOK_UPPERIN) == 0)
                hookptr = &priv->upperin;
        else if (strcmp(name, NG_ETHER_RMON_HOOK_UPPEROUT) == 0)
                hookptr = &priv->upperout;
        else
                return (EINVAL);

        /* Check if already connected (shouldn't be, but doesn't hurt) */
        if (*hookptr != NULL)
                return (EISCONN);

        /* OK */
        *hookptr = hook;
        return (0);
}



/*
 * Receive a control message from ngctl or the netgraph's API
 */
static int
ng_ether_rmon_rcvmsg(node_p node, struct ng_mesg *msg,
	const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_ETHER_RMON_COOKIE:
		switch (msg->header.cmd) {
		case NGM_ETHER_RMON_GET_STATS:
		case NGM_ETHER_RMON_CLR_STATS:
		case NGM_ETHER_RMON_GETCLR_STATS:
		    {
			if (msg->header.cmd != NGM_ETHER_RMON_CLR_STATS) {
				NG_MKRESPONSE(resp, msg,
				    sizeof(priv->stats), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				memcpy(resp->data,
				    &priv->stats, sizeof(priv->stats));
			}
			if (msg->header.cmd != NGM_ETHER_RMON_GET_STATS)
				memset(&priv->stats, 0, sizeof(priv->stats));
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

	/* Done */
	if (rptr)
		*rptr = resp;
	else if (resp != NULL)
		FREE(resp, M_NETGRAPH);
	FREE(msg, M_NETGRAPH);
	return (error);
}

/*
 * Hook disconnection.
 *
 * If all the hooks are removed, let's free itself.
 */
static int
ng_ether_rmon_disconnect(hook_p hook)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);

	/* Zero out hook pointer */
	if (hook == priv->lowerin)
		priv->lowerin = NULL;
	else if (hook == priv->lowerout)
		priv->lowerout = NULL;
	else if (hook == priv->upperin)
		priv->upperin = NULL;
	else if (hook == priv->upperout)
		priv->upperout = NULL;

	/* Go away if no longer connected to anything */
	if (node->numhooks == 0)
		ng_rmnode(node);
	return (0);
}

/*
 * Shutdown node
 *
 * Free the private data.
 *
 * Called at splnet()
 */
static int
ng_ether_rmon_rmnode(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

#ifdef SPLASSERT
	SPLASSERT(net, __FUNCTION__);
#endif
	node->flags |= NG_INVALID;
	if (priv->lowerin && priv->lowerout)
                ng_bypass(priv->lowerin, priv->lowerout);
	if (priv->upperin && priv->upperout)
                ng_bypass(priv->upperin, priv->upperout);
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
 * Receive data
 *
 * Handle incoming data on a hook.
 *
 * Called at splnet() or splimp()
 */
static int
ng_ether_rmon_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	priv_p priv;
	int error;

	if (!node) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	priv = NG_NODE_PRIVATE(node);
	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	/* Handle incoming frame from lowerin hook */
	if (hook == priv->lowerin) {
		error = ng_ether_rmon_recv_lowerin(node, m, meta);
		return error;
	}

	/* Handle incoming frame from lowerout hook */
	if (hook == priv->lowerout) {
		error = ng_ether_rmon_recv_lowerout(node, m, meta);
		return error;
	}

	/* Handle incoming frame from upperin hook */
	if (hook == priv->upperin) {
		error = ng_ether_rmon_recv_upperin(node, m, meta);
		return error;
	}

	/* Handle incoming frame from upperout hook */
	if (hook == priv->upperout) {
		error = ng_ether_rmon_recv_upperout(node, m, meta);
		return error;
	}

	return (EINVAL);
}

/*
 * Receive data from lowerin hook
 * We just calculate some stats, and take it to the upper layers.
 *
 * Called at splnet() or splimp()
 */
static int
ng_ether_rmon_recv_lowerin(node_p node, struct mbuf *m, meta_p meta)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	int error = 0;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	/*
	 * Update stats
	 */

	/* etherStatsPkts */
	priv->stats.pkts++;

	/* etherStatsOctets */
	priv->stats.octets += m->len;

	/* etherStatsUndersizePkts */
        if (m->len < 64)
                priv->stats.undersize_pkts++;

	/* etherStatsPkts64Octets */
	if (m->len == 64)
		priv->stats.pkts_64++;

	/* etherStatsPkts65to127Octets */
	if ((m->len >= 65) && (m->len <= 127))
		priv->stats.pkts_65to127++;

	/* etherStatsPkts128to255Octets */
	if ((m->len >= 128) && (m->len <= 255))
		priv->stats.pkts_128to255++;

        /* etherStatsPkts256to511Octets */
        if ((m->len >= 256) && (m->len <= 511))
                priv->stats.pkts_256to511++;

        /* etherStatsPkts512to1023Octets */
        if ((m->len >= 512) && (m->len <= 1023))
                priv->stats.pkts_512to1023++;

        /* etherStatsPkts1024to1518Octets */
        if ((m->len >= 1024) && (m->len <= 1518))
                priv->stats.pkts_1024to1518++;

        /* etherStatsOversizePkts */
        if (m->len > 1518)
                priv->stats.oversize_pkts++;

	/* etherStatsBroadcastPkts */
        if (m->pkt_type == PACKET_BROADCAST)
                priv->stats.bcast_pkts++;

        /* etherStatsMulticastPkts */
        if (m->pkt_type == PACKET_MULTICAST)
                priv->stats.mcast_pkts++;

	/*
	 * Forward data to the output hook : orphan or links
	 * The mbuf and meta are consumed by the nodes of the peers.
	 */
	if (priv->lowerout == NULL)
		NG_SEND_DATA(error, priv->upperout, m, meta);
	else
		NG_SEND_DATA(error, priv->lowerout, m, meta);


	/*
	 * When NG_SEND_DATA fails, the mbuf and meta do not need to be freed because it has already
	 * been done by the peer's node.
	 */
	return error;
}

/*
 * Receive data from lowerout hook
 * We just take it to the downer layers.
 *
 * Called at splnet() or splimp()
 */
static int
ng_ether_rmon_recv_lowerout(node_p node, struct mbuf *m, meta_p meta)
{
        const priv_p priv = NG_NODE_PRIVATE(node);

        int error = 0;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

        /*
         * Forward data to the output hook
         * The mbuf and meta are consumed by the nodes of the peers.
         */

        NG_SEND_DATA(error, priv->lowerin, m, meta);

        /*
         * When NG_SEND_DATA fails, the mbuf and meta do not need to be freed because it has already
         * been done by the peer's node.
         */
        return error;
}

/*
 * Receive data from upperin hook
 * We just take it to the upper layers.
 *
 * Called at splnet() or splimp()
 */
static int
ng_ether_rmon_recv_upperin(node_p node, struct mbuf *m, meta_p meta)
{
        const priv_p priv = NG_NODE_PRIVATE(node);

        int error = 0;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

        /*
         * Forward data to the output hook
         * The mbuf and meta are consumed by the nodes of the peers.
         */

        NG_SEND_DATA(error, priv->upperout, m, meta);

        /*
         * When NG_SEND_DATA fails, the mbuf and meta do not need to be freed because it has already
         * been done by the peer's node.
         */
        return error;
}

/*
 * Receive data from upperin hook
 * We just take it to the upper layers.
 *
 * Called at splnet() or splimp()
 */
static int
ng_ether_rmon_recv_upperout(node_p node, struct mbuf *m, meta_p meta)
{
        const priv_p priv = NG_NODE_PRIVATE(node);

        int error = 0;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

        /*
         * Forward data to the output hook
         * The mbuf and meta are consumed by the nodes of the peers.
         */
	if (priv->upperin == NULL)
		NG_SEND_DATA(error, priv->lowerin, m, meta);
	else
		NG_SEND_DATA(error, priv->upperin, m, meta);

        /*
         * When NG_SEND_DATA fails, the mbuf and meta do not need to be freed because it has already
         * been done by the peer's node.
         */
        return error;
}

#if defined(__LinuxKernelVNB__)
module_init(ng_ether_rmon_init);
module_exit(ng_ether_rmon_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB ethernet RMON node");
MODULE_LICENSE("6WIND");
#endif
