/*
 * Copyright 2003-2013 6WIND S.A.
 */

/*
 * This node is useful for diverting packets to applications
 * It has 4 hooks: in, out, divin, and divout. Data
 * entering from the in is passed to the divin if connected,
 * otherwise to out. Date from out is passed to divout if connected,
 * otherwise to in.
 * Application can connect to divin and/or divout to divert packets.
 */

#if defined(__LinuxKernelVNB__)
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

#elif defined(__FastPath__)
#include "fp-netgraph.h"
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_socket.h>
#include <netgraph/ng_div.h>

/* Per hook info */
struct hookinfo {
	hook_p			hook;
	struct ng_div_hookstat	stats;
};

/* Per node info */
struct privdata {
	node_p			node;
	struct hookinfo		in;
	struct hookinfo		out;
	struct hookinfo		divin;
	struct hookinfo		divout;
};
typedef struct privdata *sc_p;

/* Netgraph methods */
static ng_constructor_t	ng_div_constructor;
static ng_rcvmsg_t	ng_div_rcvmsg;
static ng_shutdown_t	ng_div_rmnode;
static ng_newhook_t	ng_div_newhook;
static ng_rcvdata_t	ng_div_rcvdata;
static ng_disconnect_t	ng_div_disconnect;

/* Parse type for struct ng_div_hookstat */
static const struct ng_parse_struct_field ng_div_hookstat_type_fields[]
	= NG_DIV_HOOKSTAT_INFO;
static const struct ng_parse_type ng_div_hookstat_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_div_hookstat_type_fields
};

/* Parse type for struct ng_div_stats */
static const struct ng_parse_struct_field ng_div_stats_type_fields[]
	= NG_DIV_STATS_INFO(&ng_div_hookstat_type);
static const struct ng_parse_type ng_div_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_div_stats_type_fields
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_div_cmds[] = {
	{
	  NGM_DIV_COOKIE,
	  NGM_DIV_GET_STATS,
	  "getstats",
	  NULL,
	  &ng_div_stats_type
	},
	{
	  NGM_DIV_COOKIE,
	  NGM_DIV_CLR_STATS,
	  "clrstats",
	  NULL,
	  NULL
	},
	{
	  NGM_DIV_COOKIE,
	  NGM_DIV_GETCLR_STATS,
	  "getclrstats",
	  NULL,
	  &ng_div_stats_type
	},
	{ 0, 0, NULL, NULL, NULL }
};

/* Netgraph type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_div_typestruct) = {
	.version = 	NG_VERSION,
	.name = 	NG_DIV_NODE_TYPE,
	.mod_event = 	NULL,
	.constructor = 	ng_div_constructor,
	.rcvmsg = 	ng_div_rcvmsg,
	.shutdown = 	ng_div_rmnode,
	.newhook = 	ng_div_newhook,
	.findhook = 	NULL,
	.connect = 	NULL,
	.afterconnect = NULL,
	.rcvdata = 	ng_div_rcvdata,
	.rcvdataq = 	ng_div_rcvdata,
	.disconnect = 	ng_div_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist = 	ng_div_cmds
};
NETGRAPH_INIT(div, &ng_div_typestruct);
NETGRAPH_EXIT(div, &ng_div_typestruct);

/*
 * Node constructor
 */
static int
ng_div_constructor(node_p *nodep, ng_ID_t nodeid)
{
	sc_p privdata;
	int error = 0;

	if ((error = ng_make_node_common_and_priv(&ng_div_typestruct, nodep,
						  &privdata, sizeof(*privdata), nodeid))) {
		return (error);
	}
	bzero(privdata, sizeof(*privdata));

	(*nodep)->private = privdata;
	privdata->node = *nodep;
	return (0);
}

/*
 * Add a hook
 */
static int
ng_div_newhook(node_p node, hook_p hook, const char *name)
{
	const sc_p sc = node->private;

	if (strcmp(name, NG_DIV_HOOK_IN) == 0) {
		sc->in.hook = hook;
		bzero(&sc->in.stats, sizeof(sc->in.stats));
		hook->private = &sc->in;
	} else if (strcmp(name, NG_DIV_HOOK_OUT) == 0) {
		sc->out.hook = hook;
		bzero(&sc->out.stats, sizeof(sc->out.stats));
		hook->private = &sc->out;
	} else if (strcmp(name, NG_DIV_HOOK_DIVIN) == 0) {
		sc->divin.hook = hook;
		bzero(&sc->divin.stats, sizeof(sc->divin.stats));
		hook->private = &sc->divin;
	} else if (strcmp(name, NG_DIV_HOOK_DIVOUT) == 0) {
		sc->divout.hook = hook;
		bzero(&sc->divout.stats, sizeof(sc->divout.stats));
		hook->private = &sc->divout;
	} else
		return (EINVAL);
	return (0);
}

/*
 * Receive a control message
 */
static int
ng_div_rcvmsg(node_p node, struct ng_mesg *msg, const char *retaddr,
	   struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const sc_p sc = node->private;
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_DIV_COOKIE:
		switch (msg->header.cmd) {
		case NGM_DIV_GET_STATS:
		case NGM_DIV_CLR_STATS:
		case NGM_DIV_GETCLR_STATS:
                    {
			struct ng_div_stats *stats;

                        if (msg->header.cmd != NGM_DIV_CLR_STATS) {
                                NG_MKRESPONSE(resp, msg,
                                    sizeof(*stats), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					goto done;
				}
				stats = (struct ng_div_stats *)resp->data;
				bcopy(&sc->in.stats, &stats->in,
				    sizeof(stats->in));
				bcopy(&sc->out.stats, &stats->out,
				    sizeof(stats->out));
				bcopy(&sc->divin.stats, &stats->divin,
				    sizeof(stats->divin));
				bcopy(&sc->divout.stats, &stats->divout,
				    sizeof(stats->divout));
                        }
                        if (msg->header.cmd != NGM_DIV_GET_STATS) {
				bzero(&sc->in.stats,
				    sizeof(sc->in.stats));
				bzero(&sc->out.stats,
				    sizeof(sc->out.stats));
				bzero(&sc->divin.stats,
				    sizeof(sc->divin.stats));
				bzero(&sc->divout.stats,
				    sizeof(sc->divout.stats));
			}
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

done:
	FREE(msg, M_NETGRAPH);
	return (error);
}

/*
 * Receive data on a hook
 *
 * Data entering from the 'in' is passed to the 'divin' if connected,
 * otherwise to out. Data entering form 'out' is passed to 'divout' if
 * connected, otherwise to in.
 * Data entering from 'divin' is passed to the 'out'. Data entering from
 * 'divout' is passed to the 'in'.
 */
static int
ng_div_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	sc_p sc;
	struct hookinfo *const hinfo = (struct hookinfo *) hook->private;
	struct hookinfo *dest = NULL;
	int error = 0;

	if (!node) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	sc = NG_NODE_PRIVATE(node);
	if (!sc) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	if (!hinfo) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	/* Which hook? */
	if (hinfo == &sc->in) {
		if (sc->divin.hook != NULL)
			dest = &sc->divin;
		else
			dest = &sc->out;
	} else if (hinfo == &sc->divin) {
		dest = &sc->out;
	} else if (hinfo == &sc->out) {
		if (sc->divout.hook != NULL)
			dest = &sc->divout;
		else
			dest = &sc->in;
	} else if (hinfo == &sc->divout) {
		dest = &sc->in;
	} else
		panic("%s: no hook!", __FUNCTION__);

#if 0
        /* If any meta info, look for socket control info */
	/* this example assumes in6_addr structure */
        if (meta != NULL) {
                struct meta_field_header *field;

                /* Look for peer socket address */
                for (field = &meta->options[0];
                    (caddr_t)field < (caddr_t)meta + meta->used_len;
                    field = (struct meta_field_header *)
                      ((caddr_t)field + field->len)) {
                        if (field->cookie != NGM_SOCKET_COOKIE)
				continue;
			switch(field->type) {
			case NG_SOCKET_META_CONTROL_INADDR:
			  {
				struct in_addr *in4;
				in4 = (struct in_addr *)field->data;
				printf("control:%s\n",inet_ntoa(*in4));
				break;
			  }
			case NG_SOCKET_META_CONTROL_IN6ADDR:
			  {
				struct in6_addr *sa;
				sa = (struct in6_addr *)field->data;
				printf("control:%s\n",ip6_sprintf(sa));
				break;
			  }
			}
                }
        }
#endif

	/* Update stats on incoming hook */
#if defined(__LinuxKernelVNB__)
	hinfo->stats.inOctets += m->len;
#endif
	hinfo->stats.inFrames++;

	/* Deliver frame out destination hook */
#if defined(__LinuxKernelVNB__)
	dest->stats.outOctets += m->len;
#endif
	dest->stats.outFrames++;
	NG_SEND_DATA(error, dest->hook, m, meta);
	return error;
}

/*
 * Shutdown processing
 *
 * This is tricky. If we have both a left and right hook, then we
 * probably want to extricate ourselves and leave the two peers
 * still linked to each other. Otherwise we should just shut down as
 * a normal node would.
 *
 * To keep the scope of info correct the routine to "extract" a node
 * from two links is in ng_base.c.
 */
/* JMG : feature not used in ng_div for now. It needs to use ng_bypass. */
static int
ng_div_rmnode(node_p node)
{
	const sc_p privdata = node->private;

	node->flags |= NG_INVALID;
#if 0
	if (privdata->left.hook && privdata->right.hook)
		ng_bypass(privdata->left.hook, privdata->right.hook);
#endif
	ng_cutlinks(node);
	ng_unname(node);
	node->private = NULL;
	ng_unref(privdata->node);
	return (0);
}

/*
 * Hook disconnection
 */
static int
ng_div_disconnect(hook_p hook)
{
	struct hookinfo *const hinfo = (struct hookinfo *) hook->private;

	NG_KASSERT(hinfo != NULL, ("%s: null info", __FUNCTION__));
	hinfo->hook = NULL;
	if (hook->node->numhooks == 0)
		ng_rmnode(hook->node);
	return (0);
}

#if defined(__LinuxKernelVNB__)
module_init(ng_div_init);
module_exit(ng_div_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB DIV node");
MODULE_LICENSE("6WIND");
#endif
