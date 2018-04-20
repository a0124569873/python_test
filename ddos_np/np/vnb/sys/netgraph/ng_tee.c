
/*
 * ng_tee.c
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
 * Author: Julian Elischer <julian@freebsd.org>
 *
 * $FreeBSD: src/sys/netgraph/ng_tee.c,v 1.7.2.5 2002/07/02 23:44:03 archie Exp $
 * $Whistle: ng_tee.c,v 1.18 1999/11/01 09:24:52 julian Exp $
 */
/*
 * Copyright 2003-2013 6WIND S.A.
 */

/*
 * This node is like the tee(1) command and is useful for ``snooping.''
 * It has 4 hooks: left, right, left2right, and right2left. Data
 * entering from the right is passed to the left and duplicated on
 * right2left, and data entering from the left is passed to the right
 * and duplicated on left2right. Data entering from left2right is
 * sent to right, and data from right2left to left.
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
#include <netgraph/ng_tee.h>

#if defined(__LinuxKernelVNB__)
#define TEE_STATS
#endif

/* Per hook info */
struct hookinfo {
	hook_p			hook;
	struct ng_tee_hookstat	stats;
};

/* Per node info */
struct privdata {
	node_p			node;
	struct hookinfo		left;
	struct hookinfo		right;
	struct hookinfo		left2right;
	struct hookinfo		right2left;
};
typedef struct privdata *sc_p;

/* Netgraph methods */
static ng_constructor_t	ngt_constructor;
static ng_rcvmsg_t	ngt_rcvmsg;
static ng_shutdown_t	ngt_rmnode;
static ng_newhook_t	ngt_newhook;
static ng_disconnect_t	ngt_disconnect;

static int ngt_rcvdata_left(hook_p hook, struct mbuf *m, meta_p meta);
static int ngt_rcvdata_right(hook_p hook, struct mbuf *m, meta_p meta);
static int ngt_rcvdata_left2right(hook_p hook, struct mbuf *m, meta_p meta);
static int ngt_rcvdata_right2left(hook_p hook, struct mbuf *m, meta_p meta);


/* Parse type for struct ng_tee_hookstat */
static const struct ng_parse_struct_field ng_tee_hookstat_type_fields[]
	= NG_TEE_HOOKSTAT_INFO;
static const struct ng_parse_type ng_tee_hookstat_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_tee_hookstat_type_fields
};

/* Parse type for struct ng_tee_stats */
static const struct ng_parse_struct_field ng_tee_stats_type_fields[]
	= NG_TEE_STATS_INFO(&ng_tee_hookstat_type);
static const struct ng_parse_type ng_tee_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_tee_stats_type_fields
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_tee_cmds[] = {
#ifdef TEE_STATS
	{
	  NGM_TEE_COOKIE,
	  NGM_TEE_GET_STATS,
	  "getstats",
	  NULL,
	  &ng_tee_stats_type
	},
	{
	  NGM_TEE_COOKIE,
	  NGM_TEE_CLR_STATS,
	  "clrstats",
	  NULL,
	  NULL
	},
	{
	  NGM_TEE_COOKIE,
	  NGM_TEE_GETCLR_STATS,
	  "getclrstats",
	  NULL,
	  &ng_tee_stats_type
	},
#endif
	{ 0, 0, NULL, NULL, NULL }
};

/* Netgraph type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_tee_typestruct) = {
	.version = 	NG_VERSION,
	.name = 	NG_TEE_NODE_TYPE,
	.mod_event = 	NULL,
	.constructor = 	ngt_constructor,
	.rcvmsg = 	ngt_rcvmsg,
	.shutdown = 	ngt_rmnode,
	.newhook = 	ngt_newhook,
	.findhook = 	NULL,
	.connect = 	NULL,
	.afterconnect = NULL,
	.rcvdata = 	NULL,
	.rcvdataq = 	NULL,
	.disconnect = 	ngt_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist = 	ng_tee_cmds
};
NETGRAPH_INIT(tee, &ng_tee_typestruct);
NETGRAPH_EXIT(tee, &ng_tee_typestruct);

/*
 * Node constructor
 */
static int
ngt_constructor(node_p *nodep, ng_ID_t nodeid)
{
	sc_p privdata;
	int error = 0;

	if ((error = ng_make_node_common_and_priv(&ng_tee_typestruct, nodep,
						  &privdata, sizeof(*privdata),
						  nodeid))) {
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
ngt_newhook(node_p node, hook_p hook, const char *name)
{
	const sc_p sc = node->private;

	if (strncmp(name, NG_TEE_HOOK_RIGHT,
	      sizeof(NG_TEE_HOOK_RIGHT)) == 0) {
		sc->right.hook = hook;
		bzero(&sc->right.stats, sizeof(sc->right.stats));
		hook->private = &sc->right;
		hook->hook_rcvdata = ngt_rcvdata_right;
	} else if (strncmp(name, NG_TEE_HOOK_LEFT,
	      sizeof(NG_TEE_HOOK_LEFT)) == 0) {
		sc->left.hook = hook;
		bzero(&sc->left.stats, sizeof(sc->left.stats));
		hook->private = &sc->left;
		hook->hook_rcvdata = ngt_rcvdata_left;
	} else if (strncmp(name, NG_TEE_HOOK_RIGHT2LEFT,
	      sizeof(NG_TEE_HOOK_RIGHT2LEFT)) == 0) {
		sc->right2left.hook = hook;
		bzero(&sc->right2left.stats, sizeof(sc->right2left.stats));
		hook->private = &sc->right2left;
		hook->hook_rcvdata = ngt_rcvdata_right2left;
	} else if (strncmp(name, NG_TEE_HOOK_LEFT2RIGHT,
	      sizeof(NG_TEE_HOOK_LEFT2RIGHT)) == 0) {
		sc->left2right.hook = hook;
		bzero(&sc->left2right.stats, sizeof(sc->left2right.stats));
		hook->private = &sc->left2right;
		hook->hook_rcvdata = ngt_rcvdata_left2right;
	} else
		return (EINVAL);
	return (0);
}

/*
 * Receive a control message
 */
static int
ngt_rcvmsg(node_p node, struct ng_mesg *msg, const char *retaddr,
	   struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_TEE_COOKIE:
		switch (msg->header.cmd) {
#ifdef TEE_STATS
		case NGM_TEE_GET_STATS:
		case NGM_TEE_CLR_STATS:
		case NGM_TEE_GETCLR_STATS:
                    {
			const sc_p sc = node->private;
			struct ng_tee_stats *stats;

                        if (msg->header.cmd != NGM_TEE_CLR_STATS) {
                                NG_MKRESPONSE(resp, msg,
                                    sizeof(*stats), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					goto done;
				}
				stats = (struct ng_tee_stats *)resp->data;
				bcopy(&sc->right.stats, &stats->right,
				    sizeof(stats->right));
				bcopy(&sc->left.stats, &stats->left,
				    sizeof(stats->left));
				bcopy(&sc->right2left.stats, &stats->right2left,
				    sizeof(stats->right2left));
				bcopy(&sc->left2right.stats, &stats->left2right,
				    sizeof(stats->left2right));
                        }
                        if (msg->header.cmd != NGM_TEE_GET_STATS) {
				bzero(&sc->right.stats,
				    sizeof(sc->right.stats));
				bzero(&sc->left.stats,
				    sizeof(sc->left.stats));
				bzero(&sc->right2left.stats,
				    sizeof(sc->right2left.stats));
				bzero(&sc->left2right.stats,
				    sizeof(sc->left2right.stats));
			}
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
	if (rptr)
		*rptr = resp;
	else if (resp)
		FREE(resp, M_NETGRAPH);

#ifdef TEE_STATS
done:
#endif
	FREE(msg, M_NETGRAPH);
	return (error);
}

/*
 * Receive data on a hook (1 function per hook)
 *
 * If data comes in the right link send a copy out right2left, and then
 * send the original onwards out through the left link.
 * Do the opposite for data coming in from the left link.
 * Data coming in right2left or left2right is forwarded
 * on through the appropriate destination hook as if it had come
 * from the other side.
 */
static int
ngt_rcvdata_left(hook_p hook, struct mbuf *m, meta_p meta)
{
	sc_p sc = hook->node_private;
#ifdef TEE_STATS
	struct hookinfo *const hinfo = (struct hookinfo *) hook->private;
#endif
	struct hookinfo *dest = NULL;
	struct hookinfo *dup = NULL;
	hook_p dest_hook = NULL;
	hook_p dup_hook = NULL;
	int error = 0;

	if (!sc) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

#ifdef TEE_STATS
	if (!hinfo) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}
#endif
	dup = &sc->left2right;
	if (dup != NULL)
		dup_hook = dup->hook;
	dest = &sc->right;
	if (dest != NULL)
		dest_hook = dest->hook;

	/* Update stats on incoming hook */
#ifdef TEE_STATS
	hinfo->stats.inOctets += MBUF_LENGTH(m);
	hinfo->stats.inFrames++;
#endif
	/*
	  Duplicate packet and meta info if required.
	  VNB SMP: dup->hook must be copied to prevent a race condition.
	*/
	if (dup_hook != NULL) {
		struct mbuf *m2;
		meta_p meta2;

		/* Copy packet */
#if defined(__FastPath__)
		m2 = m_dup(m);
#else
		m2 = m_dup(m, M_NOWAIT);
#endif
		if (m2 == NULL) {
			NG_FREE_DATA(m, meta);
			return (ENOBUFS);
		}

		/* Copy meta info */
		if (meta != NULL) {
			MALLOC(meta2, meta_p,
			    meta->used_len, M_NETGRAPH, M_NOWAIT);
			if (meta2 == NULL) {
				m_freem(m2);
				NG_FREE_DATA(m, meta);
				return (ENOMEM);
			}
			bcopy(meta, meta2, meta->used_len);
			meta2->allocated_len = meta->used_len;
		} else
			meta2 = NULL;

		/* Deliver duplicate */
#ifdef TEE_STATS
		dup->stats.outOctets += MBUF_LENGTH(m);
		dup->stats.outFrames++;
#endif
		NG_SEND_DATA(error, dup_hook, m2, meta2);
	}

	/* Deliver frame out destination hook */
	if (dest_hook != NULL) {
#ifdef TEE_STATS
		dest->stats.outOctets += MBUF_LENGTH(m);
		dest->stats.outFrames++;
#endif
	}
	NG_SEND_DATA(error, dest_hook, m, meta);

	return error;
}

static int
ngt_rcvdata_right(hook_p hook, struct mbuf *m, meta_p meta)
{
	sc_p sc = hook->node_private;
#ifdef TEE_STATS
	struct hookinfo *const hinfo = (struct hookinfo *) hook->private;
#endif
	struct hookinfo *dest = NULL;
	struct hookinfo *dup = NULL;
	hook_p dest_hook = NULL;
	hook_p dup_hook = NULL;
	int error = 0;

	if (!sc) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

#ifdef TEE_STATS
	if (!hinfo) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}
#endif
	dup = &sc->right2left;
	if (dup != NULL)
		dup_hook = dup->hook;
	dest = &sc->left;
	if (dest != NULL)
		dest_hook = dest->hook;

	/* Update stats on incoming hook */
#ifdef TEE_STATS
	hinfo->stats.inOctets += MBUF_LENGTH(m);
	hinfo->stats.inFrames++;
#endif
	/*
	  Duplicate packet and meta info if required.
	  VNB SMP: dup->hook must be copied to prevent a race condition.
	*/
	if (dup_hook != NULL) {
		struct mbuf *m2;
		meta_p meta2;

		/* Copy packet */
#if defined(__FastPath__)
		m2 = m_dup(m);
#else
		m2 = m_dup(m, M_NOWAIT);
#endif
		if (m2 == NULL) {
			NG_FREE_DATA(m, meta);
			return (ENOBUFS);
		}

		/* Copy meta info */
		if (meta != NULL) {
			MALLOC(meta2, meta_p,
			    meta->used_len, M_NETGRAPH, M_NOWAIT);
			if (meta2 == NULL) {
				m_freem(m2);
				NG_FREE_DATA(m, meta);
				return (ENOMEM);
			}
			bcopy(meta, meta2, meta->used_len);
			meta2->allocated_len = meta->used_len;
		} else
			meta2 = NULL;

		/* Deliver duplicate */
#ifdef TEE_STATS
		dup->stats.outOctets += MBUF_LENGTH(m);
		dup->stats.outFrames++;
#endif
		NG_SEND_DATA(error, dup_hook, m2, meta2);
	}

	/* Deliver frame out destination hook */
	if (dest_hook != NULL) {
#ifdef TEE_STATS
		dest->stats.outOctets += MBUF_LENGTH(m);
		dest->stats.outFrames++;
#endif
	}
	NG_SEND_DATA(error, dest_hook, m, meta);

	return error;
}

static int
ngt_rcvdata_left2right(hook_p hook, struct mbuf *m, meta_p meta)
{
	sc_p sc = hook->node_private;
#ifdef TEE_STATS
	struct hookinfo *const hinfo = (struct hookinfo *) hook->private;
#endif
	struct hookinfo *dest = NULL;
	hook_p dest_hook = NULL;
	int error = 0;

	if (!sc) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

#ifdef TEE_STATS
	if (!hinfo) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}
#endif
	dest = &sc->left;
	if (dest != NULL)
		dest_hook = dest->hook;

	/* Update stats on incoming hook */
#ifdef TEE_STATS
	hinfo->stats.inOctets += MBUF_LENGTH(m);
	hinfo->stats.inFrames++;
#endif

	/* Deliver frame out destination hook */
	if (dest_hook != NULL) {
#ifdef TEE_STATS
		dest->stats.outOctets += MBUF_LENGTH(m);
		dest->stats.outFrames++;
#endif
	}
	NG_SEND_DATA(error, dest_hook, m, meta);

	return error;
}

static int
ngt_rcvdata_right2left(hook_p hook, struct mbuf *m, meta_p meta)
{
	sc_p sc = hook->node_private;
#ifdef TEE_STATS
	struct hookinfo *const hinfo = (struct hookinfo *) hook->private;
#endif
	struct hookinfo *dest = NULL;
	hook_p dest_hook = NULL;
	int error = 0;

	if (!sc) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

#ifdef TEE_STATS
	if (!hinfo) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}
#endif
	dest = &sc->right;
	if (dest != NULL)
		dest_hook = dest->hook;

	/* Update stats on incoming hook */
#ifdef TEE_STATS
	hinfo->stats.inOctets += MBUF_LENGTH(m);
	hinfo->stats.inFrames++;
#endif

	/* Deliver frame out destination hook */
	if (dest_hook != NULL) {
#ifdef TEE_STATS
		dest->stats.outOctets += MBUF_LENGTH(m);
		dest->stats.outFrames++;
#endif
	}
	NG_SEND_DATA(error, dest_hook, m, meta);

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
static int
ngt_rmnode(node_p node)
{
	const sc_p privdata = node->private;

	node->flags |= NG_INVALID;
	if (privdata->left.hook && privdata->right.hook)
		ng_bypass(privdata->left.hook, privdata->right.hook);
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
ngt_disconnect(hook_p hook)
{
	struct hookinfo *const hinfo = (struct hookinfo *) hook->private;

	NG_KASSERT(hinfo != NULL, ("%s: null info", __FUNCTION__));
	hinfo->hook = NULL;
	if (hook->node->numhooks == 0)
		ng_rmnode(hook->node);
	return (0);
}

#if defined(__LinuxKernelVNB__)
module_init(ng_tee_init);
module_exit(ng_tee_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB tee node");
MODULE_LICENSE("6WIND");
#endif
