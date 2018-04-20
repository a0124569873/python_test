/*-
 * ng_etf.c  Ethertype filter
 *
 * Copyright (c) 2001, FreeBSD Incorporated
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
 * Author: Julian Elischer <julian@freebsd.org>
 *
 * $FreeBSD: src/sys/netgraph/ng_etf.c,v 1.1.2.2 2002/07/02 23:44:02 archie Exp $
 */

/*
 * Copyright 2003-2013 6WIND S.A.
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
#include <netgraph/ng_etf.h>
#include <netgraph/vnb_ether.h>

/* If you do complicated mallocs you may want to do this */
/* and use it for your mallocs */
#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_ETF, "netgraph_etf", "netgraph etf node ");
#else
#define M_NETGRAPH_ETF M_NETGRAPH
#endif

/*
 * This section contains the netgraph method declarations for the
 * etf node. These methods define the netgraph 'type'.
 */

static ng_constructor_t	ng_etf_constructor;
static ng_rcvmsg_t	ng_etf_rcvmsg;
static ng_shutdown_t	ng_etf_shutdown;
static ng_newhook_t	ng_etf_newhook;
static ng_connect_t	ng_etf_connect;
static ng_rcvdata_t	ng_etf_rcvdata;	 /* note these are both ng_rcvdata_t */
static ng_disconnect_t	ng_etf_disconnect;

#ifdef NG_ETF_STATS
/* Parse type for struct ng_etfstat */
static const struct ng_parse_struct_field ng_etf_stat_type_fields[]
	= NG_ETF_STATS_TYPE_INFO;
static const struct ng_parse_type ng_etf_stat_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_etf_stat_type_fields
};
#endif
/* Parse type for struct ng_setfilter */
static const struct ng_parse_struct_field ng_etf_filter_type_fields[]
	= NG_ETF_FILTER_TYPE_INFO;
static const struct ng_parse_type ng_etf_filter_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_etf_filter_type_fields
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_etf_cmdlist[] = {
#ifdef NG_ETF_STATS
	{
	  NGM_ETF_COOKIE,
	  NGM_ETF_GET_STATUS,
	  "getstatus",
	  NULL,
	  &ng_etf_stat_type,
	},
#endif
	{
	  NGM_ETF_COOKIE,
	  NGM_ETF_SET_FLAG,
	  "setflag",
	  &ng_parse_int32_type,
	  NULL
	},
	{
	  NGM_ETF_COOKIE,
	  NGM_ETF_SET_FILTER,
	  "setfilter",
	  &ng_etf_filter_type,
	  NULL
	},
	{ 0, 0, NULL, NULL, NULL }
};

/* Netgraph node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, typestruct) = {
	.version = NG_ABI_VERSION,
	.name = NG_ETF_NODE_TYPE,
	.mod_event = NULL,
	.constructor = ng_etf_constructor,
	.rcvmsg = ng_etf_rcvmsg,
	.shutdown = ng_etf_shutdown,
	.newhook = ng_etf_newhook,
	.findhook = NULL,
	.connect = ng_etf_connect,
	.afterconnect = NULL,
	.rcvdata = ng_etf_rcvdata,
	.rcvdataq = ng_etf_rcvdata,
	.disconnect = ng_etf_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist = ng_etf_cmdlist
};
NETGRAPH_INIT(etf, &typestruct);
NETGRAPH_EXIT(etf, &typestruct);

struct filter {
	LIST_ENTRY(filter) next;
	u_int16_t	ethertype;	/* network order ethertype */
	hook_p		match_hook;	/* Hook to use on a match */
};

#define HASHORDER 4 /* Dont change this without changing HASH() */
#define HASHSIZE (1 << HASHORDER)
#define HASH(et) ((((et)>>12)+((et)>>8)+((et)>>4)+(et)) & 0x0f)
LIST_HEAD(filterhead, filter);

static VNB_DEFINE_SHARED(vnb_spinlock_t, list_lock);  /* lock for list access */

/* Information we store for each node */
struct ETF {
	hook_p          downstream_hook;
	hook_p          nomatch_hook;
	node_p		node;		/* back pointer to node */
#ifdef NG_ETF_STATS
	u_int   	packets_in;	/* packets in from downstream */
	u_int   	packets_out;	/* packets out towards downstream */
#endif
	u_int32_t	flags;
	struct filterhead hashtable[HASHSIZE];
};
typedef struct ETF *etf_p;

static struct filter *
ng_etf_findentry(etf_p etfp, u_int16_t ethertype)
{
	struct filterhead *chain = etfp->hashtable + HASH(ethertype);
	struct filter *fil;


	vnb_spinlock_lock(&list_lock);
	LIST_FOREACH(fil, chain, next) {
		if (fil->ethertype == ethertype) {
			vnb_spinlock_unlock(&list_lock);
			return (fil);
		}
	}
	vnb_spinlock_unlock(&list_lock);

	return (NULL);
}

/*
 * Allocate the private data structure. The generic node has already
 * been created. Link them together. We arrive with a reference to the node
 * i.e. the reference count is incremented for us already.
 */
static int
ng_etf_constructor(node_p *nodep, ng_ID_t nodeid)
{
	etf_p privdata;
	int error;
	int i;

	/* Call the 'generic' (ie, superclass) node constructor */
	if ((error = ng_make_node_common_and_priv(&typestruct, nodep,
						  &privdata, sizeof(*privdata), nodeid))) {
		return (error);
	}

	bzero(privdata, sizeof(*privdata));
	for (i = 0; i < HASHSIZE; i++) {
		LIST_INIT((privdata->hashtable + i));
	}

	vnb_spinlock_init(&list_lock);
	/* Link structs together; this counts as our one reference to node */
	NG_NODE_SET_PRIVATE((*nodep), privdata);
	privdata->node = *nodep;
	return (0);
}

/*
 * Give our ok for a hook to be added...
 * All names are ok. Two names are special.
 */
static int
ng_etf_newhook(node_p node, hook_p hook, const char *name)
{
	const etf_p etfp = NG_NODE_PRIVATE(node);

	if (strcmp(name, NG_ETF_HOOK_DOWNSTREAM) == 0) {
		etfp->downstream_hook = hook;
#ifdef NG_ETF_STATS
		etfp->packets_in = 0;
		etfp->packets_out = 0;
#endif
	} else if (strcmp(name, NG_ETF_HOOK_NOMATCH) == 0) {
		etfp->nomatch_hook = hook;
	} else {
		/*
		 * Any other hook name is valid and can
		 * later be associated with a filter rule.
		 */
	}
	return(0);
}

/*
 * Get a netgraph control message.
 * We actually recieve a queue item that has a pointer to the message.
 * If we free the item, the message will be freed too, unless we remove
 * it from the item using NGI_GET_MSG();
 * The return address is also stored in the item, as an ng_ID_t,
 * accessible as NGI_RETADDR(item);
 * Check it is one we understand. If needed, send a response.
 * We could save the address for an async action later, but don't here.
 * Always free the message.
 * The response should be in a malloc'd region that the caller can 'free'.
 * The NG_MKRESPONSE macro does all this for us.
 * A response is not required.
 * Theoretically you could respond defferently to old message types if
 * the cookie in the header didn't match what we consider to be current
 * (so that old userland programs could continue to work).
 */
static int
ng_etf_rcvmsg(node_p node, struct ng_mesg *msg,
    const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const etf_p etfp = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;
	void *msgdata;

	/* Deal with message according to cookie and command */
	switch (msg->header.typecookie) {
	case NGM_ETF_COOKIE:
		switch (msg->header.cmd) {
#ifdef NG_ETF_STATS
		case NGM_ETF_GET_STATUS:
		    {
			struct ng_etfstat *stats;

			NG_MKRESPONSE(resp, msg, sizeof(*stats), M_NOWAIT);
			if (!resp) {
				error = ENOMEM;
				break;
			}
			stats = (struct ng_etfstat *) resp->data;
			stats->packets_in = etfp->packets_in;
			stats->packets_out = etfp->packets_out;
			break;
		    }
#endif
		case NGM_ETF_SET_FLAG:
			if (msg->header.arglen != sizeof(u_int32_t)) {
				error = EINVAL;
				break;
			}
			msgdata = msg->data;
			etfp->flags = *((u_int32_t *) msgdata);
			break;
		case NGM_ETF_SET_FILTER:
			{
				struct ng_etffilter *f;
				struct filter *fil;
				hook_p  hook;

				/* Check message long enough for this command */
				if (msg->header.arglen != sizeof(*f)) {
					error = EINVAL;
					break;
				}

				/* Make sure hook referenced exists */
				f = (struct ng_etffilter *)msg->data;
				hook = ng_findhook(node, f->matchhook);
				if (hook == NULL) {
					error = ENOENT;
					break;
				}

				/* and is not the downstream hook */
				if (hook == etfp->downstream_hook) {
					error = EINVAL;
					break;
				}

				/* Check we don't already trap this ethertype */
				if (ng_etf_findentry(etfp,
						htons(f->ethertype))) {
					error = EEXIST;
					break;
				}

				/*
				 * Ok, make the filter and put it in the
				 * hashtable ready for matching.
				 */
				fil = ng_malloc(sizeof(*fil), M_NOWAIT | M_ZERO);
				if (fil == NULL) {
					return (ENOMEM);
				}

				fil->match_hook = hook;
				fil->ethertype = htons(f->ethertype);

				vnb_spinlock_lock(&list_lock);
				LIST_INSERT_HEAD( etfp->hashtable
					+ HASH(fil->ethertype),
						fil, next);
				vnb_spinlock_unlock(&list_lock);
			}
			break;
		default:
			error = EINVAL;		/* unknown command */
			break;
		}
		break;
	default:
		error = EINVAL;			/* unknown cookie type */
		break;
	}

	/* Take care of synchronous response, if any */
	NG_RESPOND_MSG(error, node, retaddr, resp, rptr);
	/* Free the message and return */
	NG_FREE_MSG(msg);
	return(error);
}

/*
 * Receive data, and do something with it.
 * Actually we receive a queue item which holds the data.
 * If we free the item it wil also froo the data and metadata unless
 * we have previously disassociated them using the NGI_GET_etf() macros.
 * Possibly send it out on another link after processing.
 * Possibly do something different if it comes from different
 * hooks. the caller will never free m or meta, so
 * if we use up this data or abort we must free BOTH of these.
 *
 * If we want, we may decide to force this data to be queued and reprocessed
 * at the netgraph NETISR time.
 * We would do that by setting the HK_QUEUE flag on our hook. We would do that
 * in the connect() method.
 */
static int
ng_etf_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	etf_p etfp;
	struct vnb_ether_header *eh;
	struct filter *fil;
	int error = 0;
	u_int16_t ethertype;

	if (!node) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	etfp = NG_NODE_PRIVATE(node);
	if (!etfp) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	/*
	 * Everything not from the downstream hook goes to the
	 * downstream hook. But only if it matches the ethertype
	 * of the source hook. Un matching must go to/from 'nomatch'.
	 */

	/* Make sure we have an entire header plus one extra byte */
	m = m_pullup(m, 1 + sizeof(*eh));
	if (m == NULL) {
		NG_FREE_META(meta);
		return(EINVAL);
	}

	eh = mtod(m, struct vnb_ether_header *);
	ethertype = eh->ether_type;

#define MIN_ETHTYPE 0x600
	/* If < 1536, it's a length, type is in LLC DSAP (only ONE byte) */
	if (unlikely(ntohs(ethertype) < MIN_ETHTYPE)) {
		uint8_t e = *(uint8_t *)(eh + 1);
		ethertype = htons (e);
	}

	/*
	 * if from downstream, select between a match hook or
	 * the nomatch hook
	 */
	if (hook == etfp->downstream_hook) {
#ifdef NG_ETF_STATS
		etfp->packets_in++;
#endif
		fil = ng_etf_findentry(etfp, ethertype);
		if (likely(fil && fil->match_hook))
			NG_SEND_DATA(error, fil->match_hook, m, meta);
		else
			NG_SEND_DATA(error, etfp->nomatch_hook, m, meta);
	} else {
		/*
		 * It must be heading towards the downstream.
		 * Check that it's ethertype matches
		 * the filters for it's input hook.
		 * If it doesn't have one, check it's from nomatch.
		 */
		fil = ng_etf_findentry(etfp, ethertype);
#ifdef __LinuxKernelVNB__
		m->protocol = ethertype;
#endif
		if (likely(fil && fil->match_hook == hook))
			NG_SEND_DATA(error, etfp->downstream_hook, m, meta);
		else {
			if (fil || hook != etfp->nomatch_hook) {
				NG_FREE_DATA(m, meta);
				return (EPROTOTYPE);
			}
			NG_SEND_DATA(error, etfp->downstream_hook, m, meta);
		}

#ifdef NG_ETF_STATS
		if (error == 0)
			etfp->packets_out++;
#endif
	}
	return (error);
}

/*
 * Do local shutdown processing..
 * All our links and the name have already been removed.
 */
static int
ng_etf_shutdown(node_p node)
{
	const etf_p privdata = NG_NODE_PRIVATE(node);

	node->flags |= NG_INVALID;
	ng_cutlinks(node);
	ng_unname(node);

	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(privdata->node);
	return (0);
}

/*
 * This is called once we've already connected a new hook to the other node.
 * It gives us a chance to balk at the last minute.
 */
static int
ng_etf_connect(hook_p hook)
{
	return (0);
}

/*
 * Hook disconnection
 *
 * For this type, removal of the last link destroys the node
 */
static int
ng_etf_disconnect(hook_p hook)
{
	const etf_p etfp = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	struct filter *fil, *fil2;
	int i;

	/* purge any rules that refer to this filter */
	vnb_spinlock_lock(&list_lock);
	for (i = 0; i < HASHSIZE; i++) {
		LIST_FOREACH_SAFE(fil, fil2, (etfp->hashtable + i), next) {
			if (fil->match_hook == hook) {
				LIST_REMOVE(fil, next);
				ng_free(fil);
			}
		}
	}
	vnb_spinlock_unlock(&list_lock);


	/* If it's not one of the special hooks, then free it */
	if (hook == etfp->downstream_hook) {
		etfp->downstream_hook = NULL;
	} else if (hook == etfp->nomatch_hook) {
		etfp->nomatch_hook = NULL;
	}

	if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
	&& (NG_NODE_IS_VALID(NG_HOOK_NODE(hook)))) /* already shutting down? */
		ng_rmnode(NG_HOOK_NODE(hook));
	return (0);
}

#if defined(__LinuxKernelVNB__)
module_init(ng_etf_init);
module_exit(ng_etf_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB ETF node");
MODULE_LICENSE("6WIND");
#endif
