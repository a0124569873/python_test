
/*
 * ng_one2many.c
 *
 * Copyright (c) 2000 Whistle Communications, Inc.
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
 * $FreeBSD: src/sys/netgraph/ng_one2many.c,v 1.17 2004/06/26 22:24:16 julian Exp $
 */
/*
 * Copyright 2003-2013 6WIND S.A.
 */

/*
 * ng_one2many(4) netgraph node type
 *
 * Packets received on the "one" hook are sent out each of the
 * "many" hooks accoring to an algorithm. Packets received on any
 * "many" hook are always delivered to the "one" hook.
 */

#if defined(__LinuxKernelVNB__)
#include <linux/version.h>
#include <linux/module.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/ctype.h>
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
#include <netgraph/ng_one2many.h>

/* Per-link private data */
struct ng_one2many_link {
	hook_p				hook;	/* netgraph hook */
#ifdef NG_ONE2MANY_STATS
	struct ng_one2many_link_stats	stats;	/* link stats */
#endif
};

/* Per-node private data */
struct ng_one2many_private {
	struct ng_one2many_config	conf;		/* node configuration */
	struct ng_one2many_link		one;		/* "one" hook */
	struct ng_one2many_link		*many;
	u_int16_t			nextMany;	/* next round-robin */
	u_int16_t			numActiveMany;	/* # active "many" */
	u_int16_t			*activeMany;
};
typedef struct ng_one2many_private *priv_p;

/* Netgraph node methods */
static ng_constructor_t ng_one2many_constructor;
static ng_rcvmsg_t      ng_one2many_rcvmsg;
static ng_shutdown_t    ng_one2many_shutdown;
static ng_newhook_t     ng_one2many_newhook;
static ng_rcvdata_t     ng_one2many_rcvdata;
static ng_disconnect_t  ng_one2many_disconnect;

/* Other functions */
static void             ng_one2many_update_many(priv_p priv);

/* Store each hook's link number in the private field */
#define LINK_NUM(hook)		(intptr_t)NG_HOOK_PRIVATE(hook)

/******************************************************************
		    NETGRAPH PARSE TYPES
******************************************************************/

/* Parse type for struct ng_one2many_config */
static const struct ng_parse_fixedarray_info
    ng_one2many_enableLinks_array_type_info = {
	&ng_parse_uint8_type,
	NG_ONE2MANY_MAX_LINKS,
	NULL
};
static const struct ng_parse_type ng_one2many_enableLinks_array_type = {
	.supertype = &ng_parse_fixedarray_type,
	.info = &ng_one2many_enableLinks_array_type_info,
};
static const struct ng_parse_struct_field ng_one2many_config_type_fields[]
	= NG_ONE2MANY_CONFIG_TYPE_INFO(&ng_one2many_enableLinks_array_type);
static const struct ng_parse_type ng_one2many_config_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_one2many_config_type_fields
};

#ifdef NG_ONE2MANY_STATS
/* Parse type for struct ng_one2many_link_stats */
static const struct ng_parse_struct_field ng_one2many_link_stats_type_fields[]
	= NG_ONE2MANY_LINK_STATS_TYPE_INFO;
static const struct ng_parse_type ng_one2many_link_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_one2many_link_stats_type_fields
};
#endif

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_one2many_cmdlist[] = {
	{
	  NGM_ONE2MANY_COOKIE,
	  NGM_ONE2MANY_SET_CONFIG,
	  "setconfig",
	  &ng_one2many_config_type,
	  NULL
	},
	{
	  NGM_ONE2MANY_COOKIE,
	  NGM_ONE2MANY_GET_CONFIG,
	  "getconfig",
	  NULL,
	  &ng_one2many_config_type
	},
#ifdef NG_ONE2MANY_STATS
	{
	  NGM_ONE2MANY_COOKIE,
	  NGM_ONE2MANY_GET_STATS,
	  "getstats",
	  &ng_parse_int32_type,
	  &ng_one2many_link_stats_type
	},
	{
	  NGM_ONE2MANY_COOKIE,
	  NGM_ONE2MANY_CLR_STATS,
	  "clrstats",
	  &ng_parse_int32_type,
	  NULL,
	},
	{
	  NGM_ONE2MANY_COOKIE,
	  NGM_ONE2MANY_GETCLR_STATS,
	  "getclrstats",
	  &ng_parse_int32_type,
	  &ng_one2many_link_stats_type
	},
#endif
	{ 0, 0, NULL, NULL, NULL }
};

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_one2many_typestruct) = {
	.version = 	NG_VERSION,
	.name = 	NG_ONE2MANY_NODE_TYPE,
	.mod_event = 	NULL,
	.constructor = 	ng_one2many_constructor,
	.rcvmsg = 	ng_one2many_rcvmsg,
	.shutdown = 	ng_one2many_shutdown,
	.newhook = 	ng_one2many_newhook,
	.findhook = 	NULL,
	.connect = 	NULL,
	.afterconnect = NULL,
	.rcvdata = 	ng_one2many_rcvdata,
	.rcvdataq = 	ng_one2many_rcvdata,
	.disconnect = 	ng_one2many_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist = 	ng_one2many_cmdlist,
};
NETGRAPH_INIT(one2many, &ng_one2many_typestruct);
NETGRAPH_EXIT(one2many, &ng_one2many_typestruct);

/******************************************************************
		    NETGRAPH NODE METHODS
******************************************************************/

/*
 * Node constructor
 */
static int
ng_one2many_constructor(node_p *nodep, ng_ID_t nodeid)
{
        priv_p priv;
	int error;

	/* Call superclass constructor */
	if ((error = ng_make_node_common_and_priv(&ng_one2many_typestruct, nodep,
						  &priv, sizeof(*priv), nodeid))) {
		return (error);
	}
	bzero(priv, sizeof(*priv));

	priv->many = ng_malloc(NG_ONE2MANY_MAX_LINKS*sizeof(struct ng_one2many_link),
                       M_NOWAIT | M_ZERO);
	if (unlikely(priv->many == NULL)) {
		ng_free(priv);
		return (ENOMEM);
	}

	priv->activeMany = ng_malloc(NG_ONE2MANY_MAX_LINKS*sizeof(u_int16_t),
                       M_NOWAIT | M_ZERO);
	if (unlikely(priv->activeMany == NULL)) {
		ng_free(priv);
		ng_free(priv->many);
		return (ENOMEM);
	}

	priv->conf.xmitAlg = NG_ONE2MANY_XMIT_ROUNDROBIN;
	priv->conf.failAlg = NG_ONE2MANY_FAIL_MANUAL;

	NG_NODE_SET_PRIVATE(*nodep, priv);

	/* Done */
	return (0);
}

/*
 * Method for attaching a new hook
 */
static	int
ng_one2many_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_one2many_link *link;
	int linkNum;
	u_long i;

	/* Which hook? */
	if (strncmp(name, NG_ONE2MANY_HOOK_MANY_PREFIX,
	    strlen(NG_ONE2MANY_HOOK_MANY_PREFIX)) == 0) {
		const char *cp;
		char *eptr;

		cp = name + strlen(NG_ONE2MANY_HOOK_MANY_PREFIX);
		if (!isdigit(*cp) || (cp[0] == '0' && cp[1] != '\0'))
			return (EINVAL);
		i = strtoul(cp, &eptr, 10);
		if (*eptr != '\0' || i >= NG_ONE2MANY_MAX_LINKS)
			return (EINVAL);
		linkNum = (int)i;
		link = &priv->many[linkNum];
	} else if (strncmp( name, NG_ONE2MANY_HOOK_ANY_PREFIX,
	    strlen(NG_ONE2MANY_HOOK_ANY_PREFIX ) ) == 0) {
		for ( linkNum = 0; linkNum < NG_ONE2MANY_MAX_LINKS; linkNum++ ) {
			if ( priv->conf.enabledLinks[linkNum] )
				continue;
			break;
		}
		if ( linkNum >= NG_ONE2MANY_MAX_LINKS) {
                        return (EINVAL);
		}
                link = &priv->many[linkNum];
	} else if (strcmp(name, NG_ONE2MANY_HOOK_ONE) == 0) {
		linkNum = NG_ONE2MANY_ONE_LINKNUM;
		link = &priv->one;
	} else
		return (EINVAL);

	/*
	 * Is hook already connected?
	 * this can appear when we are using hooks any and many
	 * when using any we don't know each hook will be connected
	 * so many can't be used with great reliability
	 * many0 points to the hook number 0
	 * anyX points to the first hook that isn't connected
	 */

	if (link->hook != NULL)
		return (EISCONN);

	/* Setup private info for this link */
	NG_HOOK_SET_PRIVATE(hook, (void *)(intptr_t)linkNum);
	link->hook = hook;
#ifdef NG_ONE2MANY_STATS
	bzero(&link->stats, sizeof(link->stats));
#endif
	if (linkNum != NG_ONE2MANY_ONE_LINKNUM) {
		priv->conf.enabledLinks[linkNum] = 1;	/* auto-enable link */
		ng_one2many_update_many(priv);
	}

	/* Done */
	return (0);
}

/*
 * Receive a control message
 */
static int
ng_one2many_rcvmsg(node_p node, struct ng_mesg *msg,
	const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_ONE2MANY_COOKIE:
		switch (msg->header.cmd) {
		case NGM_ONE2MANY_SET_CONFIG:
		    {
			struct ng_one2many_config *conf;
			int i;

			/* Check that new configuration is valid */
			if (msg->header.arglen != sizeof(*conf)) {
				error = EINVAL;
				break;
			}
			conf = (struct ng_one2many_config *)msg->data;
			switch (conf->xmitAlg) {
			case NG_ONE2MANY_XMIT_ROUNDROBIN:
			case NG_ONE2MANY_XMIT_ALL:
				break;
			default:
				error = EINVAL;
				break;
			}
			switch (conf->failAlg) {
			case NG_ONE2MANY_FAIL_MANUAL:
				break;
			default:
				error = EINVAL;
				break;
			}
			if (error != 0)
				break;

			/* Normalized many link enabled bits */
			for (i = 0; i < NG_ONE2MANY_MAX_LINKS; i++)
				conf->enabledLinks[i] = !!conf->enabledLinks[i];

			/* Copy config and reset */
			bcopy(conf, &priv->conf, sizeof(*conf));
			ng_one2many_update_many(priv);
			break;
		    }
		case NGM_ONE2MANY_GET_CONFIG:
		    {
			struct ng_one2many_config *conf;

			NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			conf = (struct ng_one2many_config *)resp->data;
			bcopy(&priv->conf, conf, sizeof(priv->conf));
			break;
		    }
#ifdef NG_ONE2MANY_STATS
		case NGM_ONE2MANY_GET_STATS:
		case NGM_ONE2MANY_CLR_STATS:
		case NGM_ONE2MANY_GETCLR_STATS:
		    {
			struct ng_one2many_link *link;
			int linkNum;
			void *msgdata;

			/* Get link */
			if (msg->header.arglen != sizeof(int32_t)) {
				error = EINVAL;
				break;
			}
			msgdata = msg->data;
			linkNum = *((int32_t *)msgdata);
			if (linkNum == NG_ONE2MANY_ONE_LINKNUM)
				link = &priv->one;
			else if (linkNum >= 0
			    && linkNum < NG_ONE2MANY_MAX_LINKS) {
				link = &priv->many[linkNum];
			} else {
				error = EINVAL;
				break;
			}

			/* Get/clear stats */
			if (msg->header.cmd != NGM_ONE2MANY_CLR_STATS) {
				NG_MKRESPONSE(resp, msg,
				    sizeof(link->stats), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				bcopy(&link->stats,
				    resp->data, sizeof(link->stats));
			}
			if (msg->header.cmd != NGM_ONE2MANY_GET_STATS)
				bzero(&link->stats, sizeof(link->stats));
			break;
		    }
#endif
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
 * Receive data on a hook
 */
static int
ng_one2many_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
        const node_p node = NG_HOOK_NODE(hook);
        priv_p priv;
	struct ng_one2many_link *src;
	struct ng_one2many_link *dst = NULL;
	int error = 0;
	int linkNum;
	int i;

	if (!node) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	priv = NG_NODE_PRIVATE(node);
	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	/* Get link number */
	linkNum = LINK_NUM(hook);
	NG_KASSERT(linkNum == NG_ONE2MANY_ONE_LINKNUM
	    || (linkNum >= 0 && linkNum < NG_ONE2MANY_MAX_LINKS),
	    ("%s: linkNum=%d", __FUNCTION__, linkNum));

	/* Figure out source link */
	src = (linkNum == NG_ONE2MANY_ONE_LINKNUM) ?
	    &priv->one : &priv->many[linkNum];
	NG_KASSERT(src->hook != NULL, ("%s: no src%d", __FUNCTION__, linkNum));

	/* Update receive stats */
#ifdef NG_ONE2MANY_STATS
	src->stats.recvPackets++;
#if defined(__LinuxKernelVNB__)
	src->stats.recvOctets += m->len;
#else
	(void)src; /* silent compiler warning */
#endif
#else
	(void)src; /* silent compiler warning */
#endif
	/* Figure out destination link */
	if (linkNum == NG_ONE2MANY_ONE_LINKNUM) {
		if (priv->numActiveMany == 0) {
			NG_FREE_DATA(m, meta);
			return (ENOTCONN);
		}
                switch(priv->conf.xmitAlg) {
                case NG_ONE2MANY_XMIT_ROUNDROBIN:
                        dst = &priv->many[priv->activeMany[priv->nextMany]];
                        priv->nextMany = (priv->nextMany + 1) % priv->numActiveMany;
                        break;
                case NG_ONE2MANY_XMIT_ALL:
                        /* no need to copy data for the 1st one */
                        dst = &priv->many[priv->activeMany[0]];

                        /* make copies of data and send for all links
                         * except the first one, which we'll do last
                         */
                        for (i = 1; i < priv->numActiveMany; i++) {
                                struct mbuf *m2;
                                struct ng_one2many_link *mdst;

                                mdst = &priv->many[priv->activeMany[i]];
#if defined(__FastPath__)
				m2 = m_dup(m);
#else
                                m2 = m_dup(m, M_DONTWAIT);        /* XXX m_copypacket() */
#endif
                                if (m2 == NULL) {
#ifdef NG_ONE2MANY_STATS
                                        mdst->stats.memoryFailures++;
#endif
                                        NG_FREE_M(m);
                                        return (ENOBUFS);
                                }
#ifdef NG_ONE2MANY_STATS
                                /* Update transmit stats */
                                mdst->stats.xmitPackets++;
#if defined(__LinuxKernelVNB__)
                                mdst->stats.xmitOctets += m->len;
#endif
#endif
                                NG_SEND_DATA_ONLY(error, mdst->hook, m2);
                        }
                        break;
                }
	} else
		dst = &priv->one;

#ifdef NG_ONE2MANY_STATS
	/* Update transmit stats */
	dst->stats.xmitPackets++;
#if defined(__LinuxKernelVNB__)
	dst->stats.xmitOctets += m->len;
#endif
#endif

	KASSERT(dst != NULL);

	/* Deliver packet */
	NG_SEND_DATA(error, dst->hook, m, meta);

	return (error);
}

/*
 * Shutdown node
 */
static int
ng_one2many_shutdown(node_p node)
{
        const priv_p priv = NG_NODE_PRIVATE(node);

	(void)priv;
	ng_unname(node);
	ng_cutlinks(node);
	NG_KASSERT(priv->numActiveMany == 0,
	    ("%s: numActiveMany=%d", __FUNCTION__, priv->numActiveMany));
        NG_NODE_SET_PRIVATE(node, NULL);
        NG_NODE_UNREF(node);
	return (0);
}

/*
 * Hook disconnection.
 */
static int
ng_one2many_disconnect(hook_p hook)
{
        const priv_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
        int linkNum;

	/* Get link number */
	linkNum = LINK_NUM(hook);
	NG_KASSERT(linkNum == NG_ONE2MANY_ONE_LINKNUM
	    || (linkNum >= 0 && linkNum < NG_ONE2MANY_MAX_LINKS),
	    ("%s: linkNum=%d", __FUNCTION__, linkNum));

	/* Nuke the link */
	if (linkNum == NG_ONE2MANY_ONE_LINKNUM)
		priv->one.hook = NULL;
	else {
		priv->many[linkNum].hook = NULL;
		priv->conf.enabledLinks[linkNum] = 0;
		ng_one2many_update_many(priv);
	}

	/* If no hooks left, go away */
        if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
        && (NG_NODE_IS_VALID(NG_HOOK_NODE(hook)))) {
		ng_free(priv->many);
		ng_free(priv->activeMany);

                ng_rmnode(NG_HOOK_NODE(hook));
	}
	return (0);
}

/******************************************************************
			OTHER FUNCTIONS
******************************************************************/

/*
 * Update internal state after the addition or removal of a "many" link
 */
static void
ng_one2many_update_many(priv_p priv)
{
	int linkNum;

	/* Update list of which "many" links are up */
	priv->numActiveMany = 0;
	for (linkNum = 0; linkNum < NG_ONE2MANY_MAX_LINKS; linkNum++) {
		switch (priv->conf.failAlg) {
		case NG_ONE2MANY_FAIL_MANUAL:
			if (priv->many[linkNum].hook != NULL
			    && priv->conf.enabledLinks[linkNum]) {
				priv->activeMany[priv->numActiveMany] = linkNum;
				priv->numActiveMany++;
			}
			break;
		}
	}

	/* Update transmit algorithm state */
	switch (priv->conf.xmitAlg) {
	case NG_ONE2MANY_XMIT_ROUNDROBIN:
		if (priv->numActiveMany > 0)
			priv->nextMany %= priv->numActiveMany;
		break;
	case NG_ONE2MANY_XMIT_ALL:
		break;
	}
}


#if defined(__LinuxKernelVNB__)
module_init(ng_one2many_init);
module_exit(ng_one2many_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB ONE2MANY node");
MODULE_LICENSE("6WIND");
#endif
