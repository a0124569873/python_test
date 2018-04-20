/*-
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
 * $FreeBSD: src/sys/netgraph/ng_split.c,v 1.3 2001/12/10 08:09:47 obrien Exp $
 *
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
#include <netgraph/ng_split.h>

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_SPLIT, "ng_split",
	      "netgraph split");
#else
#define M_NETGRAPH_SPLIT M_NETGRAPH
#endif

/* Netgraph methods */
static ng_constructor_t ng_split_constructor;
static ng_shutdown_t ng_split_shutdown;
static ng_newhook_t ng_split_newhook;
static ng_rcvdata_t ng_split_rcvdata;
static ng_disconnect_t ng_split_disconnect;

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, typestruct) = {
	.version = 	NG_ABI_VERSION,
	.name = 	NG_SPLIT_NODE_TYPE,
	.mod_event = 	NULL,
	.constructor = 	ng_split_constructor,
	.rcvmsg = 	NULL,
	.shutdown = 	ng_split_shutdown,
	.newhook = 	ng_split_newhook,
	.findhook = 	NULL,
	.connect = 	NULL,
	.afterconnect = NULL,
	.rcvdata = 	ng_split_rcvdata,
	.rcvdataq = 	ng_split_rcvdata,
	.disconnect = 	ng_split_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist = 	NULL
};
NETGRAPH_INIT(split, &typestruct);
NETGRAPH_EXIT(split, &typestruct);

/* Node private data */
struct ng_split_private {
	hook_p in2mixa;
	hook_p mixa;
	hook_p mixb;
	node_p	node;		/* Our netgraph node */
};
typedef struct ng_split_private *priv_p;

/************************************************************************
			NETGRAPH NODE STUFF
 ************************************************************************/

/*
 * Constructor for a node
 */
static int
ng_split_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p		priv;
	int 		error;

	/* Link together node and private info */
	/* Call superclass constructor that mallocs *nodep */
	if ((error = ng_make_node_common_and_priv(&typestruct, nodep,
						  &priv, sizeof(*priv), nodeid))) {
		return (error);
	}

	bzero(priv, sizeof(*priv));
	NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->node = *nodep;

	/* Done */
	return (0);
}

/*
 * Give our ok for a hook to be added
 */
static int
ng_split_newhook(node_p node, hook_p hook, const char *name)
{
	priv_p		priv = NG_NODE_PRIVATE(node);
	hook_p		*localhook;

	if (strcmp(name, NG_SPLIT_HOOK_IN2MIXA) == 0) {
		localhook = &priv->in2mixa;
	} else if (strcmp(name, NG_SPLIT_HOOK_MIXA) == 0) {
		localhook = &priv->mixa;
	} else if (strcmp(name, NG_SPLIT_HOOK_MIXB) == 0) {
		localhook = &priv->mixb;
	} else {
		return (-1);
	}

	if (*localhook != NULL)
		return (EISCONN);
	*localhook = hook;
	NG_HOOK_SET_PRIVATE(hook, localhook);

	return (0);
}

/*
 * Recive data from a hook.
 */
static int
ng_split_rcvdata(hook_p hook,struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	priv_p	priv;
	int	error = 0;

	if (!node) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	priv = NG_NODE_PRIVATE(node);
	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	if ((hook == priv->in2mixa) && (priv->mixa != NULL)) {
		NG_SEND_DATA(error, priv->mixa, m, meta);
	} else if ((hook == priv->mixa) && (priv->mixb != NULL)) {
		NG_SEND_DATA(error, priv->mixb, m, meta);

	} else if ((hook == priv->mixb) && (priv->mixa != NULL)) {
		NG_SEND_DATA(error, priv->mixa, m, meta);
	}
	return (error);
}

static int
ng_split_shutdown(node_p node)
{
	ng_unname(node);
	ng_cutlinks(node);
	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);

	return (0);
}

/*
 * Hook disconnection
 */
static int
ng_split_disconnect(hook_p hook)
{
	hook_p		*localhook = NG_HOOK_PRIVATE(hook);

	NG_KASSERT(localhook != NULL, ("%s: null info", __func__));
	*localhook = NULL;
	if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
	    && (NG_NODE_IS_VALID(NG_HOOK_NODE(hook)))) {
		ng_rmnode(NG_HOOK_NODE(hook));
	}

	return (0);
}

#if defined(__LinuxKernelVNB__)
module_init(ng_split_init);
module_exit(ng_split_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB split node");
MODULE_LICENSE("6WIND");
#endif
