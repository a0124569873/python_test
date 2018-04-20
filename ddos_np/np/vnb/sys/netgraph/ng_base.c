
/*
 * ng_base.c
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
 * Authors: Julian Elischer <julian@freebsd.org>
 *          Archie Cobbs <archie@freebsd.org>
 *
 * $FreeBSD: src/sys/netgraph/ng_base.c,v 1.11.2.17 2002/07/02 23:44:02 archie Exp $
 * $Whistle: ng_base.c,v 1.39 1999/01/28 23:54:53 julian Exp $
 */

/*
 * Copyright 2003-2013 6WIND S.A.
 */

/*
 * This file implements the base netgraph code.
 */

#if defined(__LinuxKernelVNB__)

#include <linux/version.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <netgraph_linux/callout.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <linux/ctype.h> /* for isdigit */
#include <netgraph/vnblinux.h>
#include <netgraph/ng_ether.h>
#include <netgraph_linux/ng_rxhandler.h>
#include <netgraph_linux/ng_netlink.h>
#include <net/genetlink.h>

#include <netgraph/ng_socket.h>

#elif defined(__FastPath__)
#define _GNU_SOURCE  /* needed for strnlen() */
#include "fp-netgraph.h"
#include "fp-ng_ether.h"
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_hash_name.h>

VNB_DEFINE_SHARED(u_int32_t, gNumNodes_ns[VNB_MAX_NS]);
#if defined(__FastPath__) && defined(CONFIG_MCORE_M_TAG)
VNB_DEFINE_SHARED(int32_t, vnb_nfm_tag_type);
#endif

#if defined(__LinuxKernelVNB__) && defined(CONFIG_VNB_EXCEPTION_HANDLER)
VNB_DEFINE_SHARED(vnb_atomic_t, gNumDstHookErrs);
VNB_DEFINE_SHARED(vnb_atomic_t, gNumDstNodeErrs);
#endif

#if VNB_DEBUG
VNB_DEFINE_SHARED(vnb_atomic_t, gNumPtrs);
VNB_DEFINE_SHARED(vnb_atomic_t, gFreeNumPtrs);
#endif

/* Destructor entry */
struct ng_dtor {
	SLIST_ENTRY(ng_dtor) next;
	void (*dtor)(void *);
	void *data;
};

VNB_DEFINE_SHARED(uint16_t, ctrl_vnb_ns);

/* List of all nodes */
static VNB_DEFINE_SHARED(LIST_HEAD(, ng_node), nodelist_ns[VNB_MAX_NS]);

/* List of pointer to be freed */
static VNB_DEFINE_SHARED(SLIST_HEAD(, ng_object), delayed_free_list);
static VNB_DEFINE_SHARED(SLIST_HEAD(, ng_object), free_list);

/* for destructor calls */
static VNB_DEFINE_SHARED(SLIST_HEAD(, ng_dtor), dtor_list);

/* List of destructors to be called */
static VNB_DEFINE_SHARED(SLIST_HEAD(, ng_dtor), delayed_dtor_list);
static VNB_DEFINE_SHARED(vnb_spinlock_t, gc_lock);  /* lock for list access */
static VNB_DEFINE_SHARED(struct callout, gctimer);      /* 1 second periodic timer */
#ifdef __LinuxKernelVNB__
volatile VNB_DEFINE_SHARED(vnb_core_state_t, vnb_core_state[VNB_NR_CPUS]);
VNB_DEFINE_SHARED(vnb_core_state_t, vnb_core_nb_instances[VNB_NR_CPUS]);

static VNB_DEFINE_SHARED(vnb_spinlock_t, type_list_lock);  /* lock for type list */
#endif

#if defined(CONFIG_VNB_NAME_HASH_ORDER)
#define NAME_HASH_ORDER CONFIG_VNB_NAME_HASH_ORDER
#else
#define NAME_HASH_ORDER 11
#endif
#define NAME_HASH_SIZE	(1 << NAME_HASH_ORDER)
static VNB_DEFINE_SHARED(LIST_HEAD(,ng_node), NAME_hash_ns[VNB_MAX_NS][NAME_HASH_SIZE]);

#define NG_NAMEHASH(NAME, HASH)					\
	do {							\
		(HASH) = ng_hash_name(NAME, 0, NAME_HASH_SIZE);			\
	} while (0)

#if defined(CONFIG_VNB_HOOK_NAME_HASH_ORDER)
#define HOOK_NAME_HASH_ORDER CONFIG_VNB_HOOK_NAME_HASH_ORDER
#else
#define HOOK_NAME_HASH_ORDER 11
#endif
#define HOOK_NAME_HASH_SIZE (1 << HOOK_NAME_HASH_ORDER)
static VNB_DEFINE_SHARED(LIST_HEAD(,ng_hook), HOOK_NAME_hash_ns[VNB_MAX_NS][HOOK_NAME_HASH_SIZE]);

#define NG_HOOK_NAMEHASH(NAME, NODEID, HASH)			\
	do {							\
		(HASH) = ng_hash_name(NAME, NODEID, HOOK_NAME_HASH_SIZE);			\
	} while (0)

/* List of installed types */
static VNB_DEFINE_SHARED(LIST_HEAD(, ng_type), typelist);

/* Hash releted definitions */
#if defined(CONFIG_VNB_ID_HASH_ORDER)
#define ID_HASH_ORDER CONFIG_VNB_ID_HASH_ORDER
#else
#define ID_HASH_ORDER 11
#endif
#define ID_HASH_SIZE (1 << ID_HASH_ORDER) /* most systems wont need even this many */
static VNB_DEFINE_SHARED(LIST_HEAD(, ng_node), ID_hash_ns[VNB_MAX_NS][ID_HASH_SIZE]);

static VNB_DEFINE_SHARED(ng_ID_t, nextID) = 1;

/* Internal functions */
static int	ng_connect_prepare(hook_p hook1, hook_p hook2);
static int	ng_connect_finish(hook_p hook1, hook_p hook2);
static void	ng_disconnect_hook(hook_p hook);
static int	ng_generic_msg(node_p here, struct ng_mesg *msg,
			const char *retaddr, struct ng_mesg ** resp,
			struct ng_mesg **nl_msg);
static ng_ID_t	ng_decodeidname(const char *name);

/*
 * on linux, messages can be received from different contexts
 * (syscall, or softirq). We don't want a syscall to be interrupted
 * during a spinlock (causing a deadlock), so we need to use
 * spinlock_bh()
 */
#ifdef __LinuxKernelVNB__
#define gc_list_lock() spin_lock_bh(&gc_lock)
#define gc_list_unlock() spin_unlock_bh(&gc_lock)
#else
#define gc_list_lock() vnb_spinlock_lock(&gc_lock)
#define gc_list_unlock() vnb_spinlock_unlock(&gc_lock)
#endif

/*
 * Allocate sizeof (struct ng_object) more before the pointer, in order to
 * be able to free it safely using the garbage collector.
 * This function have to be used for each data allocated or freed in
 * data processing or timers.
 */

#ifdef __LinuxKernelVNB__
uint32_t vnb_seqnum = 1;
EXPORT_SYMBOL(vnb_seqnum);
DEFINE_SPINLOCK(vnb_seqnum_lock);
EXPORT_SYMBOL(vnb_seqnum_lock);

static struct genl_family vnb_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "VNB",
	.version = 1,
	.maxattr = VNBA_DUMP_MAX,
};

static struct genl_multicast_group vnb_mcgrp[] = {
	{	.name = "VNB",	},
};

#ifdef CONFIG_VNB_NETLINK_NOTIFY
static int genl_fill_vnbinfo(struct sk_buff *skb,
		      node_p node, u32 count,
		      u32 total_count,
		      int type,
		      u32 pid, u32 seq,
		      unsigned int flags)
{
	struct nlmsghdr *nlh;
	hook_p hook;
	struct ng_nl_status nlstatus;
	struct ng_nl_node nlnode;
	struct ng_nl_nodepriv *nlnodepriv = NULL;

	/* ng_msghdr should be replaced by smthg more meaningful */
	nlh = genlmsg_put(skb, pid, seq, &vnb_genl_family, flags, type);
	if (nlh == NULL)
		goto nla_put_failure;

	/* STATUS part */
	memset(&nlstatus, 0, sizeof(struct ng_nl_status));
	nlstatus.version = NG_VERSION;
	nlstatus.count = count;
	nlstatus.total_count = total_count;

	if (nla_put(skb, VNBA_DUMP_STATUS, sizeof(nlstatus), &nlstatus) < 0)
		goto nla_put_failure;

	/* NODE part */
	memset(&nlnode, 0, sizeof(nlnode));
	snprintf(nlnode.name, sizeof(nlnode.name), "%s", node->name);
	snprintf(nlnode.type, sizeof(nlnode.type), "%s", node->type->name);
	nlnode.id = node->ID;
	nlnode.numhooks = node->numhooks;

	if (nla_put(skb, VNBA_DUMP_NODE, sizeof(nlnode), &nlnode) < 0)
		goto nla_put_failure;
	log(LOG_DEBUG, "%s: %s/%s/%u/%u\n", __func__, node->name,
	    node->type->name, (unsigned int) node->ID, node->numhooks);

	if (node->type && node->type->dumpnode)
		nlnodepriv = node->type->dumpnode(node);

	/* NODE_PRIV part */
	if (nlnodepriv) {
		if (nla_put(skb, VNBA_DUMP_NODE_PRIV,
			    nlnodepriv->data_len + sizeof(*nlnodepriv),
			    nlnodepriv) < 0)
			goto nla_put_failure;
		log(LOG_DEBUG, "%s: nlnodepriv data len = %zu\n", __func__,
		    nlnodepriv->data_len + sizeof(*nlnodepriv));
	}

	/* HOOK_LIST part */
	if (node->numhooks) {
		struct nlattr *hook_list_attr;

		hook_list_attr = nla_nest_start(skb, VNBA_DUMP_HOOK_LIST);
		if (hook_list_attr == NULL) {
			log(LOG_DEBUG, "%s: hook_list attr failed\n", __func__);
			goto nla_put_failure;
		}

		LIST_FOREACH(hook, &node->hooks, hooks) {
			struct ng_nl_hook nlhook;
			hook_p peerhook = hook->peer;
			node_p peernode;

			if (!peerhook) {
				log(LOG_DEBUG, "%s: NULL peerhook\n", __func__);
				continue;
			}
			peernode = peerhook->node;

			if (hook->flags & HK_INVALID)
				continue;

			/* HOOK part */
			memset(&nlhook, 0, sizeof(nlhook));
			snprintf(nlhook.name, sizeof(nlhook.name),
				 "%s", hook->name);
			snprintf(nlhook.peername, sizeof(nlhook.peername),
				 "%s", peerhook->name);
			if (peernode)
				nlhook.peernodeid = peernode->ID;

			if (nla_put(skb, VNBA_DUMP_HOOK, sizeof(nlhook),
				    &nlhook) < 0)
				goto nla_put_failure;

			log(LOG_DEBUG, "hook %s <-> %s[%x]:%s\n", hook->name,
			    peernode ? peernode->name : "null",
			    peernode ? peernode->ID : 0,
			    peerhook->name);

			/* HOOK_PRIV part */
			if (node->type->dumphook) {
				struct ng_nl_hookpriv *nlhookpriv;

				nlhookpriv = node->type->dumphook(node, hook);

				if (nlhookpriv) {
					if (nla_put(skb, VNBA_DUMP_HOOK_PRIV,
						    sizeof(*nlhookpriv) +
							nlhookpriv->data_len,
						    nlhookpriv) < 0)
						goto nla_put_failure;

					log(LOG_DEBUG, "nlhookpriv data len = %zu\n",
					    nlhookpriv->data_len + sizeof(*nlhookpriv));
				}
			}
		}

		nla_nest_end(skb, hook_list_attr);
	}

	genlmsg_end(skb, nlh);

	if (nlnodepriv)
		FREE(nlnodepriv, M_NETGRAPH);

	return skb->len;

nla_put_failure:
	log(LOG_DEBUG, "%s: node %s failed\n", __func__, node->name);
	genlmsg_cancel(skb, nlh);
	if (nlnodepriv)
		FREE(nlnodepriv, M_NETGRAPH);

	return -EMSGSIZE;
}

static void vnb_netlink_dump(node_p node, u32 count, u32 total_count)
{
	struct sk_buff *skb;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		return;

	if (genl_fill_vnbinfo(skb, node, count, total_count,
			      VNB_C_DUMP, 0, 0, 0) < 0)
	{
		kfree_skb(skb);
		return;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	genlmsg_multicast_netns(&init_net, skb, 0, vnb_mcgrp[0].id,
				GFP_KERNEL);
#else
	genlmsg_multicast_netns(&vnb_genl_family, &init_net, skb, 0, 0,
				GFP_KERNEL);
#endif
}

void vnb_netlink_notify(const struct ng_mesg *msg, const struct ng_cmdlist *c,
			const char *path, int pathlen)
{
	struct sk_buff *skb;
	struct nlmsghdr  *nlh;
	int msgdatalen, size;
	struct ng_mesg *msg2 = NULL;
	uint32_t seqnum;

	msgdatalen = msg->header.arglen;
	if (msgdatalen > 0 && c && c->name) {
		int bufSize = 20 * 1024; /* XXX hard coded constant */
		const struct ng_parse_type *argstype, *temp;

		/* Convert command arguments to ASCII */
		argstype = temp = (msg->header.flags & NGF_RESP) ?
			c->respType : c->mesgType;
		if (argstype == NULL) {
			log(LOG_DEBUG, "ascii-to-binary conversion function is missing"
			  " for cookie %x cmd %d\n", msg->header.typecookie, msg->header.cmd);
		} else {
			/* Get a response message with lots of room */
			MALLOC(msg2, struct ng_mesg *, bufSize + sizeof(*msg2), M_NETGRAPH, M_NOWAIT);
			if (msg2 == NULL)
				return;
			bzero(msg2 + 1, bufSize);

			/* Copy binary message header to response message payload */
			bcopy(msg, msg2, sizeof(*msg2));

			/* Convert command name to ASCII */
			snprintf(msg2->header.cmdstr, sizeof(msg2->header.cmdstr),
					"%s", c->name);

			while (temp != NULL && temp->unparse == NULL)
				temp = temp->supertype;
			if (temp && temp->unparse) {
				int off = 0;
				if (temp->unparse(argstype, (u_char *)msg->data, &off, msg2->data, bufSize)) {
					FREE(msg2, M_NETGRAPH);
					return;
				}
			}

			/* Return the result as struct ng_mesg plus ASCII string */
			bufSize = strlen(msg2->data) + 1;
			msg2->header.arglen = bufSize;
			msgdatalen = msg2->header.arglen;
		}
	}

	size = nla_total_size(sizeof(struct ng_msghdr)
			      + NG_PATHLEN + 1
			      + msgdatalen);

	skb = genlmsg_new(size, GFP_ATOMIC);
	if (!skb) {
		if (msg2)
			FREE(msg2, M_NETGRAPH);
		return;
	}

	nlh = genlmsg_put(skb, current->pid, 0, &vnb_genl_family, 0, VNB_C_NEW);

	if (msg2) {
		if (nla_put(skb, VNBA_MSGHDR, sizeof(struct ng_msghdr),
			    &msg2->header) < 0)
				    goto nla_put_failure;
	} else
		if (nla_put(skb, VNBA_MSGHDR, sizeof(struct ng_msghdr),
			    &msg->header) < 0)
			goto nla_put_failure;

	if (pathlen)
		if (nla_put(skb, VNBA_MSGPATH, pathlen, path) < 0)
			goto nla_put_failure;

	if (msg2) {
		if (nla_put(skb, VNBA_MSGASCIIDATA, msg2->header.arglen,
			    msg2->data) < 0)
			goto nla_put_failure;
	} else if (msg->header.arglen)
		if (nla_put(skb, VNBA_MSGDATA, msg->header.arglen,
			    msg->data) < 0)
			goto nla_put_failure;

	spin_lock_bh(&vnb_seqnum_lock);

	seqnum = vnb_seqnum;
	/*
	 * Do not increment sequence number in case of NGM_NULL in order
	 * to detect loss of VNB messages only for messages which manipulates
	 * VNB graph.
	 */
	if (msg->header.typecookie != NGM_GENERIC_COOKIE ||
	    msg->header.cmd != NGM_NULL) {
		vnb_seqnum++;

		/* vnb_seqnum should not be null */
		if (vnb_seqnum == 0)
			vnb_seqnum = 1;
	}

	if (nla_put_u32(skb, VNBA_SEQNUM, seqnum) < 0)
		goto nla_put_failure;

	genlmsg_end(skb, nlh);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	genlmsg_multicast_netns(&init_net, skb, 0, vnb_mcgrp[0].id,
				GFP_ATOMIC);
#else
	genlmsg_multicast_netns(&vnb_genl_family, &init_net, skb, 0, 0,
				GFP_ATOMIC);
#endif

	spin_unlock_bh(&vnb_seqnum_lock);

	if (msg2)
		FREE(msg2, M_NETGRAPH);

	return;
nla_put_failure:
	genlmsg_cancel(skb, nlh);
	if (msg2)
		FREE(msg2, M_NETGRAPH);
	kfree_skb(skb);
}

void vnb_socket_netlink_notify(u_int32_t nodeid, char *name, u_int32_t cmd)
{
	struct sk_buff *skb;
	struct nlmsghdr  *nlh;
	struct ngm_name nm;
	int size;
	struct ng_mesg msg;
	uint32_t seqnum;

	memset(&msg, 0, sizeof(struct ng_mesg));
	msg.header.nodeid = nodeid;
	msg.header.version = NG_VERSION;
	msg.header.typecookie = NGM_SOCKET_COOKIE;
	msg.header.cmd = cmd;
	if (name)
		msg.header.arglen = sizeof(nm);

	size = nla_total_size(sizeof(struct ng_msghdr)
			      + NG_PATHLEN + 1);

	skb = genlmsg_new(size, GFP_KERNEL);
	if (!skb)
		return;

	nlh = genlmsg_put(skb, current->pid, 0, &vnb_genl_family, 0, VNB_C_NEW);

	if (nla_put(skb, VNBA_MSGHDR, sizeof(struct ng_msghdr),
		    &msg.header) < 0)
		goto nla_put_failure;

	spin_lock_bh(&vnb_seqnum_lock);

	seqnum = vnb_seqnum;
	if (msg.header.cmd != NGM_NULL) {
		vnb_seqnum++;

		/* vnb_seqnum should not be null */
		if (vnb_seqnum == 0)
			vnb_seqnum = 1;
	}

	if (nla_put_u32(skb, VNBA_SEQNUM, seqnum) < 0)
		goto nla_put_failure;

	if (name) {
		memset(&nm, 0, sizeof(nm));
		strncpy(nm.name, name, sizeof(nm.name));
		if (nla_put(skb, VNBA_MSGDATA, sizeof(nm), &nm) < 0)
			goto nla_put_failure;
	}

	genlmsg_end(skb, nlh);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	genlmsg_multicast_netns(&init_net, skb, 0, vnb_mcgrp[0].id,
				GFP_ATOMIC);
#else
	genlmsg_multicast_netns(&vnb_genl_family, &init_net, skb, 0, 0,
				GFP_ATOMIC);
#endif

	spin_unlock_bh(&vnb_seqnum_lock);

	return;
nla_put_failure:
	genlmsg_cancel(skb, nlh);
	kfree_skb(skb);
}
#else
static int genl_fill_vnbinfo(struct sk_buff *skb,
		      node_p node, u32 count,
		      u32 total_count,
		      int type,
		      u32 pid, u32 seq,
		      unsigned int flags)
{
	return 0;
}

static void vnb_netlink_dump(node_p node, u32 count, u32 total_count)
{
}

void vnb_netlink_notify(const struct ng_mesg *msg, const struct ng_cmdlist *c,
			const char *path, int pathlen)
{
}

void vnb_socket_netlink_notify(u_int32_t nodeid, char *name, u_int32_t cmd)
{
}
#endif /* CONFIG_VNB_NETLINK_NOTIFY */
EXPORT_SYMBOL(vnb_netlink_notify);
EXPORT_SYMBOL(vnb_socket_netlink_notify);

static int vnb_genl_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	int ret = 0;
	u32 idx = 0;
	u32 s_idx = cb->args[0];
	u32 total_count = per_ns(gNumNodes, ctrl_vnb_ns);
	node_p node;

	LIST_FOREACH(node, &per_ns(nodelist, ctrl_vnb_ns), nodes) {
		if (idx++ < s_idx)
			continue;
		if ((ret = genl_fill_vnbinfo(skb, node, idx,
					     total_count,
					     VNB_C_DUMP,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
					     NETLINK_CB(cb->skb).pid,
#else
					     NETLINK_CB(cb->skb).portid,
#endif
					     cb->nlh->nlmsg_seq,
					     NLM_F_MULTI)) <= 0)
			idx--;
			break;
	}

	cb->args[0] = idx;
	return skb->len;
}

static struct genl_ops vnb_genl_ops[] = {
	{
		.cmd = VNB_C_DUMP,
		.flags = 0,
		.policy = NULL,
		.doit = NULL,
		.dumpit = vnb_genl_dump,
	},
};
#endif /* __LinuxKernelVNB__ */

void *ng_malloc(unsigned int length, int flags)
{
	void *ptr;

	MALLOC(ptr, char *, (length + sizeof(struct ng_object)), M_NETGRAPH,
	       flags);
	if (ptr) {
		obj_p obj = ptr;

		/* Initialize next pointer */
		SLIST_NEXT(obj, next) = NULL;

#if VNB_DEBUG
		vnb_atomic_inc(&gNumPtrs);
#endif
		return (ptr + sizeof (struct ng_object));
	}
	return NULL;
}

void ng_free(void *ptr)
{
	struct ng_object *elt =
		(struct ng_object *) ((char *)ptr - sizeof (struct ng_object));

	gc_list_lock();
	SLIST_INSERT_HEAD(&delayed_free_list, elt, next);
#if VNB_DEBUG
	vnb_atomic_inc(&gFreeNumPtrs);
#endif
	gc_list_unlock();
#if VNB_DEBUG
	vnb_atomic_dec(&gNumPtrs);
#endif
}

/*
 * Register a destructor callback and its associated data pointer to be
 * called asynchronously. Using the garbage collector for this guarantees
 * that no core will use the data being destroyed.
 * Useful for nodes that must free non-vnb data at rmnode time.
 *
 * You need to reserve room for the destructor callback with ng_dtor_alloc(),
 * then use either ng_dtor() to register the actual callback when the object
 * needs to be destroyed, _or_ ng_dtor_free() in order to free memory if you
 * never intend to call ng_dtor() (which would otherwise free that memory).
 * Hence, do not ever call both on the same pointer returned by
 * ng_dtor_alloc().
 *
 * This extra step is needed because if ng_dtor() was allowed to allocate
 * its own memory, it would have been possible for it to fail. Backing up
 * from this situation would be problematic.
 */
void *ng_dtor_alloc(void)
{
	struct ng_dtor *ret;

	MALLOC(ret, struct ng_dtor *, sizeof(*ret), M_NETGRAPH, M_NOWAIT);
	return ret;
}

void ng_dtor_free(void *ptr)
{
	FREE(ptr, M_NETGRAPH);
}

void ng_dtor(void *ptr, void (*dtor)(void *data), void *data)
{
	((struct ng_dtor *)ptr)->dtor = dtor;
	((struct ng_dtor *)ptr)->data = data;
	gc_list_lock();
	SLIST_INSERT_HEAD(&delayed_dtor_list, (struct ng_dtor *)ptr, next);
	gc_list_unlock();
}

/************************************************************************
	Parse type definitions for generic messages
************************************************************************/

/* Handy structure parse type defining macro */
#define DEFINE_PARSE_STRUCT_TYPE(lo, up, args)				\
static const struct ng_parse_struct_field				\
	ng_ ## lo ## _type_fields[] = NG_GENERIC_ ## up ## _INFO args;	\
static const struct ng_parse_type ng_generic_ ## lo ## _type = {	\
	.supertype = &ng_parse_struct_type,						\
	.info = &ng_ ## lo ## _type_fields					\
}

DEFINE_PARSE_STRUCT_TYPE(mkpeer, MKPEER, ());
DEFINE_PARSE_STRUCT_TYPE(inspeer, INSPEER, ());
DEFINE_PARSE_STRUCT_TYPE(connect, CONNECT, ());
DEFINE_PARSE_STRUCT_TYPE(insnode, INSNODE, ());
DEFINE_PARSE_STRUCT_TYPE(name, NAME, ());
DEFINE_PARSE_STRUCT_TYPE(rmhook, RMHOOK, ());
DEFINE_PARSE_STRUCT_TYPE(bypass, BYPASS, ());
DEFINE_PARSE_STRUCT_TYPE(nodeinfo, NODEINFO, ());
DEFINE_PARSE_STRUCT_TYPE(typeinfo, TYPEINFO, ());
DEFINE_PARSE_STRUCT_TYPE(linkinfo, LINKINFO, (&ng_generic_nodeinfo_type));

/* Get length of an array when the length is stored as a 32 bit
   value immediately preceeding the array -- as with struct namelist
   and struct typelist. */
static int
ng_generic_list_getLength(const struct ng_parse_type *type,
	const u_char *start, const u_char *buf)
{
	return *((const u_int32_t *)(buf - 4));
}

/* Get length of the array of struct linkinfo inside a struct hooklist */
static int
ng_generic_linkinfo_getLength(const struct ng_parse_type *type,
	const u_char *start, const u_char *buf)
{
	const struct hooklist *hl = (const struct hooklist *)start;

	return hl->nodeinfo.hooks;
}

/* Array type for a variable length array of struct namelist */
static const struct ng_parse_array_info ng_nodeinfoarray_type_info = {
	.elementType = &ng_generic_nodeinfo_type,
	.getLength = &ng_generic_list_getLength
};
static const struct ng_parse_type ng_generic_nodeinfoarray_type = {
	.supertype = &ng_parse_array_type,
	.info = &ng_nodeinfoarray_type_info
};

/* Array type for a variable length array of struct typelist */
static const struct ng_parse_array_info ng_typeinfoarray_type_info = {
	.elementType = &ng_generic_typeinfo_type,
	.getLength = &ng_generic_list_getLength
};
static const struct ng_parse_type ng_generic_typeinfoarray_type = {
	.supertype = &ng_parse_array_type,
	.info = &ng_typeinfoarray_type_info
};

/* Array type for array of struct linkinfo in struct hooklist */
static const struct ng_parse_array_info ng_generic_linkinfo_array_type_info = {
	.elementType = &ng_generic_linkinfo_type,
	.getLength = &ng_generic_linkinfo_getLength
};
static const struct ng_parse_type ng_generic_linkinfo_array_type = {
	.supertype = &ng_parse_array_type,
	.info = &ng_generic_linkinfo_array_type_info
};

static const struct ng_parse_struct_field ng_generic_htable_fields_info[] =
	NG_GENERIC_HTABLE_FIELDS_INFO();
static const struct ng_parse_type ng_generic_htable_fields_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_generic_htable_fields_info
};

static const struct ng_parse_struct_field ng_generic_showhtables_info[] =
	NG_GENERIC_SHOWHTABLES_INFO(&ng_generic_htable_fields_type);
static const struct ng_parse_type ng_generic_showhtables_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_generic_showhtables_info
};

DEFINE_PARSE_STRUCT_TYPE(typelist, TYPELIST, (&ng_generic_nodeinfoarray_type));
DEFINE_PARSE_STRUCT_TYPE(hooklist, HOOKLIST,
	(&ng_generic_nodeinfo_type, &ng_generic_linkinfo_array_type));
DEFINE_PARSE_STRUCT_TYPE(listnodes, LISTNODES,
	(&ng_generic_nodeinfoarray_type));

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_generic_cmds[] = {
	{
	  NGM_GENERIC_COOKIE,
	  NGM_SHUTDOWN,
	  "shutdown",
	  NULL,
	  NULL
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_MKPEER_GET_NODEID,
	  "mkpeergetnodeid",
	  &ng_generic_mkpeer_type,
	  &ng_parse_uint32_type
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_MKPEER,
	  "mkpeer",
	  &ng_generic_mkpeer_type,
	  NULL
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_MKPEER_ID,
	  "mkpeer",
	  &ng_generic_mkpeer_type,
	  NULL
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_INSPEER,
	  "inspeer",
	  &ng_generic_inspeer_type,
	  NULL
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_CONNECT,
	  "connect",
	  &ng_generic_connect_type,
	  NULL
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_CONNECT_FORCE,
	  "conforce",
	  &ng_generic_connect_type,
	  NULL
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_INSNODE,
	  "insnode",
	  &ng_generic_insnode_type,
	  NULL
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_NAME,
	  "name",
	  &ng_generic_name_type,
	  NULL
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_RMHOOK,
	  "rmhook",
	  &ng_generic_rmhook_type,
	  NULL
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_BYPASS,
	  "bypass",
	  &ng_generic_bypass_type,
	  NULL
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_NODEINFO,
	  "nodeinfo",
	  NULL,
	  &ng_generic_nodeinfo_type
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_LISTHOOKS,
	  "listhooks",
	  NULL,
	  &ng_generic_hooklist_type
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_LISTNAMES,
	  "listnames",
	  NULL,
	  &ng_generic_listnodes_type	/* same as NGM_LISTNODES */
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_DUMPNODES,
	  "dumpnodes",
	  NULL,
	  NULL
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_LISTNODES,
	  "listnodes",
	  NULL,
	  &ng_generic_listnodes_type
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_FINDNODE,
	  "findnode",
	  &ng_parse_string_type,
	  &ng_parse_string_type
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_LISTTYPES,
	  "listtypes",
	  NULL,
	  &ng_generic_typeinfo_type
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_TEXT_CONFIG,
	  "textconfig",
	  NULL,
	  &ng_parse_string_type
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_TEXT_STATUS,
	  "textstatus",
	  NULL,
	  &ng_parse_string_type
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_ASCII2BINARY,
	  "ascii2binary",
	  &ng_parse_ng_mesg_type,
	  &ng_parse_ng_mesg_type
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_BINARY2ASCII,
	  "binary2ascii",
	  &ng_parse_ng_mesg_type,
	  &ng_parse_ng_mesg_type
	},
	{
	  NGM_GENERIC_COOKIE,
	  NGM_SHOWHTABLES,
	  "showhtables",
	  NULL,
	  &ng_generic_showhtables_type,
	},
    {
      NGM_GENERIC_COOKIE,
      NGM_CLILISTNAMES,
      "clilistnames",
      NULL,
      &ng_generic_listnodes_type    /* same as NGM_CLILISTNODES */
    },
    {
      NGM_GENERIC_COOKIE,
      NGM_CLILISTNODES,
      "clilistnodes",
      NULL,
      &ng_generic_listnodes_type
    },
	{
		NGM_GENERIC_COOKIE,
		NGM_NULL,
		"null",
		NULL,
		NULL
	},

    { 0, 0, NULL, NULL, NULL }
};

static VNB_DEFINE_SHARED(char *, ngm_findnode_bitfield) = NULL;
static VNB_DEFINE_SHARED(unsigned int, ngm_findnode_bitfield_size) = 0;

static volatile VNB_DEFINE_SHARED(vnb_core_state_t[VNB_NR_CPUS], core_state_copy);

/************************************************************************
			Node routines
************************************************************************/
static void vnb_copy_core_state(void)
{
	int n;
	volatile vnb_core_state_t *core_state;

	for (n = 0; n < VNB_NR_CPUS; n++) {

		core_state = &vnb_core_state[n];
		core_state_copy[n].state = core_state->state;
		core_state_copy[n].exitcnt = core_state->exitcnt;
		/*
		 * We need to know if the core has not reset its state during
		 * the copy. We only have to care about 1->0 transition, not
		 * 0->1, because in this case it has been done after storing the
		 * list of element to be freed, which was not accessible when he
		 * put its state to 1.
		 */
		if (core_state_copy[n].state != core_state->state)
			core_state_copy[n].state = 0;
	}
}

static int vnb_gc_can_free(void)
{
	int n;
	volatile vnb_core_state_t *core_state;

	for (n = 0; n < VNB_NR_CPUS; n++) {
		core_state = &vnb_core_state[n];

		if (core_state_copy[n].state == 1) {
			/* core is still busy */
			if (core_state_copy[n].exitcnt == core_state->exitcnt)
				return 0;
			core_state_copy[n].state = 0;
		}
	}

	return 1;
}

/*
 * garbage collector: free all unsused entries in the hook/node list and
 * call all registered destructor functions.
 *
 * garbage collector is only executed on 1 core at a time so we have only
 * to protect delayed_free_list and not free_list which is only used in this
 * handler.
 */
static inline void ng_gc(void)
{
	obj_p  cur, next;
	struct ng_dtor *cur_dtor, *next_dtor;

	/* if we are not waiting that all cores exited from their
	 * critical section (both lists are empty), we can check if
	 * there is new objects to free or destructors to call in the
	 * global lists. */
	if (SLIST_EMPTY(&free_list) && SLIST_EMPTY(&dtor_list)) {
#if VNB_DEBUG
		int i, j;
#endif

		/* copy the global lists locally */
		gc_list_lock();
		SLIST_MOVE(&delayed_free_list, &free_list);
		SLIST_MOVE(&delayed_dtor_list, &dtor_list);
#if VNB_DEBUG
		j = vnb_atomic_read(&gFreeNumPtrs);
#endif
		gc_list_unlock();


		/* if lists are still empty, nothing to do, just reload
		 * the timer. */
		if (SLIST_EMPTY(&free_list) && SLIST_EMPTY(&dtor_list))
			return;

		/* Else, there are new objects to free or dtor to call,
		 * copy the core state locally, we will free them once
		 * all cores exited from their critical section. */
		vnb_copy_core_state();
#if VNB_DEBUG
		i = 0;
		SLIST_FOREACH_SAFE(cur, next, &free_list, next) {
			i++;
		}
		if (i != j)
			log(LOG_ERR,
			    "%s: %d: error gFreeNumptrs is %d"
			    " but there are %d elements in the list\n",
			    __func__, __LINE__, j, i);
#endif
	}

	/* we are waiting that cores exited their critical section (at
	 * least one list is not empty), vnb_gc_can_free() will return
	 * true in this case. */
	if (vnb_gc_can_free()) {

		/* browse the list of objects to free */
		SLIST_FOREACH_SAFE(cur, next, &free_list, next) {
			SLIST_REMOVE(&free_list, cur, ng_object, next);
			FREE(cur, M_NETGRAPH);
#if VNB_DEBUG
			vnb_atomic_dec(&gFreeNumPtrs);
#endif
		}
		/* browse the list of destructors to call */
		SLIST_FOREACH_SAFE(cur_dtor, next_dtor,
				   &dtor_list, next) {
			SLIST_REMOVE(&dtor_list, cur_dtor,
				     ng_dtor, next);
			cur_dtor->dtor(cur_dtor->data);
			FREE(cur_dtor, M_NETGRAPH);
		}
	}
}

static void ng_gc_callout(void *arg)
{
	ng_gc();
	/* Re-launch Garbage Collector */
	callout_reset(&gctimer, hz, ng_gc_callout, NULL);
}

/*
 * Instantiate a node of the requested type
 * mg_make_node is a wrapper to the type-specific constructor which manages
 * the number of references to the kernel module.
 */
int
ng_make_node(const char *typename, node_p *nodepp, ng_ID_t nodeid)
{
	struct ng_type *type;
	int ret;

	/* Check that the type makes sense */
	if (typename == NULL) {
		VNB_TRAP();
		return (EINVAL);
	}

#ifdef __LinuxKernelVNB__
	/* Prevent races in case type is unregistered by module unloading */
	vnb_spinlock_lock(&type_list_lock);
#endif

	/* Locate the node type */
	if ((type = ng_findtype(typename)) == NULL) {
#ifdef __LinuxKernelVNB__
		vnb_spinlock_unlock(&type_list_lock);
#endif
		return (ENXIO);
	}

#ifdef __LinuxKernelVNB__
	/* Protect executing module code if it is being removed */
	if (try_module_get(type->module)) {
#endif
		/* Call the constructor */
		if (type->constructor != NULL)
			ret = ((*type->constructor)(nodepp, nodeid));
		else
			ret = (ng_make_node_common(type, nodepp, nodeid));

#ifdef __LinuxKernelVNB__
		/* If construction failed, decrease reference count on the module */
		if (ret) {
			module_put(type->module);
		}
	} else {
		/* Module is being removed */
		ret = ENXIO;
	}

	/* We can release the lock here, as a reference on this type has been taken */
	vnb_spinlock_unlock(&type_list_lock);
#endif
	return ret;
}

/*
 * Generic node creation. Called by node constructors.
 * The returned node has a reference count of 1.
 */
int
ng_make_node_common_and_priv(struct ng_type *type, node_p *nodepp,
			     void *privpp, unsigned priv_size,
			     ng_ID_t nodeid)
{
	node_p node;

	/* Require the node type to have been already installed */
	if (ng_findtype(type->name) == NULL) {
		VNB_TRAP();
		return (EINVAL);
	}

	/* Make a node and try attach it to the type */
	node = (node_p) ng_malloc(sizeof(*node) + priv_size, M_NOWAIT);
	if (node == NULL) {
		VNB_TRAP();
		return (ENOMEM);
	}
	bzero(node, sizeof(*node));
	per_ns(gNumNodes, ctrl_vnb_ns)++;
	node->type = type;
	node->flags = NG_INVALID;
	NG_NODE_REF(node);			/* note reference */
	node->vnb_ns = ctrl_vnb_ns;
	NG_TYPE_REF(type);

	/* Initialize hook list for new node */
	LIST_INIT(&node->hooks);

	/* Link us into the node linked list */
	LIST_INSERT_HEAD(&per_ns(nodelist, ctrl_vnb_ns), node, nodes);
	LIST_INSERT_HEAD(&per_ns(NAME_hash, ctrl_vnb_ns)[0], node, namenodes);

	/* get an ID and put us in the hash chain */
	if (nodeid) {
		if (ng_ID2node(nodeid))
			return (EEXIST);
		node->ID = nodeid;
	} else {
		do {
			nextID = (nextID + 1) & VNB_ID_MASK; /* 137 per second for 6 months before wrap */
#if defined(__FastPath__)
			node->ID = VNB_ID_SET_FP(nextID);
#else
			node->ID = VNB_ID_SET_CP(nextID);
#endif
		} while (node->ID == 0 || ng_ID2node(node->ID));
	}
	LIST_INSERT_HEAD(&per_ns(ID_hash, ctrl_vnb_ns)[node->ID % ID_HASH_SIZE], node, idnodes);

	if (privpp) {
		void **tmp = privpp;
		*tmp = ((void *)(node)) + sizeof(struct ng_node);
	}

	/* Done */
	node->flags &= ~NG_INVALID;
	*nodepp = node;
	return (0);
}

int
ng_make_node_common(struct ng_type *type, node_p *nodepp, ng_ID_t nodeid)
{
	return ng_make_node_common_and_priv(type, nodepp, NULL, 0, nodeid);
}

/* paranoia ? */
int ng_base_init(void);

static void
ng_base_ns_init(uint16_t ns) {
	int i;

	LIST_INIT(&per_ns(nodelist, ns));

	for(i=0; i<NAME_HASH_SIZE; i++)
		LIST_INIT(&per_ns(NAME_hash, ns)[i]);

	for(i=0; i<ID_HASH_SIZE; i++)
		LIST_INIT(&per_ns(ID_hash, ns)[i]);

	for(i = 0; i < HOOK_NAME_HASH_SIZE; i++)
		LIST_INIT(&per_ns(HOOK_NAME_hash, ns)[i]);

	per_ns(gNumNodes, ns) = 0;
}

int ng_base_init(void) {
	uint16_t ns;

	ctrl_vnb_ns = 0;

	LIST_INIT(&typelist);

	for (ns = 0; ns < VNB_MAX_NS; ns++)
		ng_base_ns_init(ns);

#ifdef __LinuxKernelVNB__
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	if (genl_register_family_with_ops(&vnb_genl_family, vnb_genl_ops,
					  ARRAY_SIZE(vnb_genl_ops)) != 0)
#else
	if (genl_register_family_with_ops_groups(&vnb_genl_family, vnb_genl_ops,
						 vnb_mcgrp) != 0)
#endif
	{
		printk("%s: could not register vnb genl family\n", __func__);
		goto next;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	if (genl_register_mc_group(&vnb_genl_family, vnb_mcgrp) != 0) {
		printk("%s: could not register vnb genl family mcgroup\n",
		       __func__);
		genl_unregister_family(&vnb_genl_family);
		goto next;
	}
#endif

	vnb_af_register();
next:
#endif

#if defined(__LinuxKernelVNB__) && defined(CONFIG_VNB_EXCEPTION_HANDLER)
	vnb_atomic_set(&gNumDstNodeErrs, 0);
	vnb_atomic_set(&gNumDstHookErrs, 0);
#endif
#if VNB_DEBUG
	vnb_atomic_set(&gNumPtrs, 0);
	vnb_atomic_set(&gFreeNumPtrs, 0);
#endif
	SLIST_INIT(&delayed_free_list);
	SLIST_INIT(&free_list);
	SLIST_INIT(&delayed_dtor_list);
	SLIST_INIT(&dtor_list);
	vnb_spinlock_init(&gc_lock);
#ifdef __LinuxKernelVNB__
	vnb_spinlock_init(&type_list_lock);
#endif
	callout_init(&gctimer);
	callout_reset(&gctimer, hz, ng_gc_callout, NULL);
	return 0;
}

static void ng_invalid_cache(node_p node)
{
	hook_p hook;
	LIST_FOREACH(hook, &node->hooks, hooks) {
		hook->peer_rcvdata = NULL;
		if (hook->peer)
			hook->peer->peer_rcvdata = NULL;
	}
}

/*
 * Forceably start the shutdown process on a node. Either call
 * it's shutdown method, or do the default shutdown if there is
 * no type-specific method.
 *
 * Persistent nodes must have a type-specific method which
 * resets the NG_INVALID flag.
 */
void
ng_rmnode(node_p node)
{
	/* Check if it's already shutting down */
	if ((node->flags & NG_INVALID) != 0)
		return;

	/* Add an extra reference so it doesn't go away during this */
	NG_NODE_REF(node);

	/* Mark it invalid so any newcomers know not to try use it */
	node->flags |= NG_INVALID;

	ng_invalid_cache(node);
	/* Ask the type if it has anything to do in this case */
	if (node->type && node->type->shutdown)
		(*node->type->shutdown)(node);
	else {				/* do the default thing */
		ng_unname(node);
		ng_cutlinks(node);
		ng_unref(node);
	}

	/* Remove extra reference, possibly the last */
	ng_unref(node);
}

/*
 * Called by the destructor to remove any STANDARD external references
 */
void
ng_cutlinks(node_p node)
{
	hook_p  hook;

	/* Make sure that this is set to stop infinite loops */
	node->flags |= NG_INVALID;

	/* Notify all remaining connected nodes to disconnect */
	while ((hook = LIST_FIRST(&node->hooks)) != NULL)
		ng_destroy_hook(hook);
}

/*
 * Remove a reference to the node, possibly the last
 */
int
ng_unref(node_p node)
{
	int ret = 0;

	if (vnb_atomic_dec_and_test(&node->refs)) {
#if defined(__LinuxKernelVNB__) && defined(CONFIG_STACKTRACE) && VNB_DEBUG
		struct ng_object *elt = ((struct ng_object *)node - 1);
		struct MALLOC_debug *m = ((struct MALLOC_debug *)elt - 1);
		struct stack_trace st;

		st.max_entries = (sizeof(m->unref_trace) /
				  sizeof(m->unref_trace[0]));
		st.nr_entries = 0;
		st.entries = (unsigned long *)m->unref_trace;
		st.skip = 1;
		save_stack_trace(&st);
#endif
		NG_TYPE_UNREF(node->type);
		/*
		 * Remove node from lists can be done immediately
		 * as someone who search for it will either see it valid
		 * or not see it at all.
		 */
		LIST_REMOVE(node, nodes);
		LIST_REMOVE(node, namenodes);
		LIST_REMOVE(node, idnodes);
		per_ns(gNumNodes, ctrl_vnb_ns)--;
#if defined(__LinuxKernelVNB__)
		module_put(node->type->module);
#endif
		ng_free(node);
		ret = 1;
	}
	return ret;
}

/************************************************************************
			Node ID handling
************************************************************************/
node_p
ng_ID2node(ng_ID_t ID)
{
	node_p np;
	LIST_FOREACH(np, &per_ns(ID_hash, ctrl_vnb_ns)[ID % ID_HASH_SIZE], idnodes) {
		if ((np->flags & NG_INVALID) == 0 && np->ID == ID)
			break;
	}
	return(np);
}

ng_ID_t
ng_node2ID(node_p node)
{
	return (node->ID);
}

/************************************************************************
			Node name handling
************************************************************************/

/*
 * Assign a node a name. Once assigned, the name cannot be changed.
 */
int
ng_name_node(node_p node, const char *name)
{
	int i;
	u_int32_t hash;
	char *node_name;

	/* Check the name is valid */
	for (i = 0; i < NG_NODELEN + 1; i++) {
		if (name[i] == '\0' || name[i] == '.' || name[i] == ':')
			break;
	}
	if (i == 0 || name[i] != '\0') {
		VNB_TRAP();
		return (EINVAL);
	}
	if (ng_decodeidname(name) != 0) { /* valid IDs not allowed here */
		VNB_TRAP();
		return (EINVAL);
	}

	/* Check the node isn't already named */
	if (node->name != NULL) {
		VNB_TRAP();
		return (EISCONN);
	}

	/* Check the name isn't already being used */
	if (ng_findname(node, name) != NULL) {
		VNB_TRAP();
		return (EADDRINUSE);
	}

	/* Allocate space and copy it */
	node_name = ng_malloc(strlen(name) + 1, M_NOWAIT);
	if (node_name == NULL) {
		VNB_TRAP();
		return (ENOMEM);
	}
	strcpy(node_name, name);
	node->name = node_name;
	NG_NAMEHASH(name, hash);
	LIST_REMOVE(node, namenodes);
	LIST_INSERT_HEAD(&per_ns(NAME_hash, ctrl_vnb_ns)[hash], node, namenodes);

	return (0);
}

void
ng_rehash_node(node_p node)
{
	int hash;

	NG_NAMEHASH(node->name, hash);
	LIST_REMOVE(node, namenodes);
	LIST_INSERT_HEAD(&per_ns(NAME_hash, ctrl_vnb_ns)[hash], node, namenodes);
}

/*
 * Find a node by absolute name. The name should NOT end with ':'
 * The name "." means "this node" and "[xxx]" means "the node
 * with ID (ie, at address) xxx".
 *
 * Returns the node if found, else NULL.
 */
node_p
ng_findname(node_p this, const char *name)
{
	node_p node;
	ng_ID_t temp;
	u_int32_t hash;
	int name_len;

	/* "." means "this node" */
	if ((name[0] == '.') && (name[1] == '\0'))
		return(this);

	/* Check for name-by-ID */
	if ((temp = ng_decodeidname(name)) != 0) {
		return (ng_ID2node(temp));
	}
	name_len = strnlen(name, NG_NODESIZ) + 1;

	/* Find node by name */
	NG_NAMEHASH(name, hash);
	LIST_FOREACH(node, &per_ns(NAME_hash, ctrl_vnb_ns)[hash], namenodes) {
		if ((node->name != NULL)
		&& (strncmp(node->name, name, name_len) == 0)
		&& ((node->flags & NG_INVALID) == 0))
			break;
	}
	return (node);
}

/*
 * Set node private structure and node_private field
 * in all node's hooks.
 */
void ng_set_node_private(node_p node, void *priv)
{
	hook_p hook;

	node->private = priv;

	LIST_FOREACH(hook, &node->hooks, hooks) {
		hook->node_private = priv;
	}

	return ;
}

void ng_exit(void);

void ng_ns_exit(uint16_t ns) {
	node_p node, next;

	for (node = LIST_FIRST(&per_ns(nodelist, ns)); node; node = next) {
		next = LIST_NEXT(node, nodes);
		ng_rmnode(node);
	}
}

void ng_exit(void) {
	uint16_t ns;

	for (ns = 0; ns < VNB_MAX_NS; ns++)
		ng_ns_exit(ns);

#ifdef __LinuxKernelVNB__
	genl_unregister_family(&vnb_genl_family);
	vnb_af_unregister();
#endif
	callout_stop_sync(&gctimer);
}

/*
 * Decode a ID name, eg. "[f03034de]". Returns 0 if the
 * string is not valid, otherwise returns the value.
 */
static ng_ID_t
ng_decodeidname(const char *name)
{
	const int len = strlen(name);
	char *eptr;
	u_long val;

	/* Check for proper length, brackets, no leading junk */
	if (len < 3 || name[0] != '[' || name[len - 1] != ']'
	    || !isxdigit(name[1]))
		return (0);

	/* Decode number */
	val = strtoul(name + 1, &eptr, 16);
	if (eptr - name != len - 1 || val == ULONG_MAX || val == 0)
		return ((ng_ID_t)0);
	return (ng_ID_t)val;
}

/*
 * Remove a name from a node. This should only be called
 * when shutting down and removing the node.
 */
void
ng_unname(node_p node)
{
	char *node_name = node->name;

	if (node_name) {
		node->name = NULL;
		ng_free(node_name);
	}
}

/************************************************************************
			Hook routines

 Names are not optional. Hooks are always connected, except for a
 brief moment within these routines.

************************************************************************/

/*
 * Remove a hook reference
 */
void
ng_unref_hook(hook_p hook)
{
	if (--hook->refs == 0)
		ng_free(hook);
}

/*
 * Add an unconnected hook to a node. Only used internally.
 */
int
ng_add_hook(node_p node, const char *name, hook_p *hookp)
{
	hook_p hook;
	int error = 0;
	char *hook_name;
	u_int32_t hash;

	/* Check that the given name is good */
	if (name == NULL) {
		VNB_TRAP();
		return (EINVAL);
	}
	if (ng_findhook(node, name) != NULL) {
		VNB_TRAP();
		return (EEXIST);
	}

	/* Allocate the hook and link it up */
	hook = (hook_p) ng_malloc(sizeof(*hook), M_NOWAIT);
	if (hook == NULL) {
		VNB_TRAP();
		return (ENOMEM);
	}
	bzero(hook, sizeof(*hook));
	hook->refs = 1;
	hook->flags = HK_INVALID;
	hook->node = node;
	hook->node_private = NG_NODE_PRIVATE(node);
	NG_NODE_REF(node);	/* each hook counts as a reference */

	/* Check if the node type code has something to say about it */
	if (node->type->newhook != NULL)
		if ((error = (*node->type->newhook)(node, hook, name)) != 0)
			goto fail;

	/*
	 * The 'type' agrees so far, so go ahead and link it in.
	 * We'll ask again later when we actually connect the hooks.
	 */
	LIST_INSERT_HEAD(&node->hooks, hook, hooks);
	node->numhooks++;
	/* Set hook name */
	hook_name = (char *) ng_malloc(strlen(name) + 1, M_NOWAIT);
	if (hook_name == NULL) {
		error = ENOMEM;
		LIST_REMOVE(hook, hooks);
		node->numhooks--;
fail:
		hook->node = NULL;
		ng_unref(node);
		ng_unref_hook(hook);	/* this frees the hook */
		return (error);
	}
	strcpy(hook_name, name);
	hook->name = hook_name;
	/*
	 * Do not store in hash table node's hook
	 * which have a specific findhook function
	 */
	if (node->type->findhook == NULL) {
		NG_HOOK_NAMEHASH(name, node->ID, hash);
		LIST_INSERT_HEAD(&per_ns(HOOK_NAME_hash, ctrl_vnb_ns)[hash], hook, namehooks);
	}

	if (hookp)
		*hookp = hook;
	return (error);
}

/*
 * Connect a pair of hooks. Only used internally.
 */
static int
ng_connect_prepare(hook_p hook1, hook_p hook2)
{
	int     error;

	hook1->peer = hook2;
	hook2->peer = hook1;

	/* Give each node the opportunity to veto the impending connection */
	if (hook1->node->type->connect) {
		if ((error = (*hook1->node->type->connect) (hook1))) {
			ng_destroy_hook(hook1);	/* also zaps hook2 */
			return (error);
		}
	}
	if (hook2->node->type->connect) {
		if ((error = (*hook2->node->type->connect) (hook2))) {
			ng_destroy_hook(hook2);	/* also zaps hook1 */
			return (error);
		}
	}
	return (0);
}

/*
 * After connect a pair of hooks. Only used internally.
 */
static int
ng_connect_finish(hook_p hook1, hook_p hook2)
{
	int     error;

	/* Give each node the opportunity to veto the impending connection */
	if (hook1->node->type->afterconnect) {
		if ((error = (*hook1->node->type->afterconnect) (hook1))) {
			ng_destroy_hook(hook1);	/* also zaps hook2 */
			return (error);
		}
	}
	if (hook2->node->type->afterconnect) {
		if ((error = (*hook2->node->type->afterconnect) (hook2))) {
			ng_destroy_hook(hook2);	/* also zaps hook1 */
			return (error);
		}
	}
	return (0);
}

int
ng_connect(hook_p hook1, hook_p hook2)
{
	int error = ng_connect_prepare (hook1, hook2);
	if (error)
		return (error);

	if (hook2->hook_rcvdata)
		hook1->peer_rcvdata = hook2->hook_rcvdata;
	else
		hook1->peer_rcvdata = hook2->node->type->rcvdata;

	if (hook1->hook_rcvdata)
		hook2->peer_rcvdata = hook1->hook_rcvdata;
	else
		hook2->peer_rcvdata = hook1->node->type->rcvdata;

	hook1->flags &= ~HK_INVALID;
	hook2->flags &= ~HK_INVALID;
	error = ng_connect_finish (hook1, hook2);
	if (error)
		return (error);
	return (0);
}

 /*
  * Find a hook using hash table
  *
  * Node types may supply their own optimized routines for finding
  * hooks. However, this one is already quite efficient as it is
  * based on a hash table.
  */
hook_p
ng_findhook(node_p node, const char *name)
{
	hook_p hook;
	u_int32_t hash;
	int name_len;

	if (node->type->findhook != NULL)
		return (*node->type->findhook)(node, name);
	name_len = strnlen(name, NG_HOOKSIZ) + 1;

	/* Find hook by name */
	NG_HOOK_NAMEHASH(name, node->ID, hash);
	LIST_FOREACH(hook, &per_ns(HOOK_NAME_hash, ctrl_vnb_ns)[hash], namehooks) {
		if (hook->name != NULL
		    && hook->node == node
		    && strncmp(hook->name, name, name_len) == 0
		    && (hook->flags & HK_INVALID) == 0)
			return (hook);
	}
	return (NULL);
}

/*
 * Find a hook
 *
 * If an invalid hook is found, still return it.
 */

hook_p
ng_findhook_inval(node_p node, const char *name)
{
	hook_p hook;
	int name_len = strnlen(name, NG_HOOKSIZ) + 1;

	LIST_FOREACH(hook, &node->hooks, hooks) {
		if (hook->name != NULL
		    && hook->node == node
		    && strncmp(hook->name, name, name_len) == 0)
			return (hook);
	}
	return (NULL);
}

/*
 * Destroy a hook
 *
 * As hooks are always attached, this really destroys two hooks.
 * The one given, and the one attached to it. Disconnect the hooks
 * from each other first.
 */
void
ng_destroy_hook(hook_p hook)
{
	hook_p peer = hook->peer;

	hook->flags |= HK_INVALID;		/* as soon as possible */
	hook->peer_rcvdata = NULL;

	if (peer) {
		peer->flags |= HK_INVALID;	/* as soon as possible */
		peer->peer_rcvdata = NULL;
		hook->peer = NULL;
		peer->peer = NULL;
		ng_disconnect_hook(peer);
	}
	ng_disconnect_hook(hook);
}

/*
 * Notify the node of the hook's demise. This may result in more actions
 * (e.g. shutdown) but we don't do that ourselves and don't know what
 * happens there. If there is no appropriate handler, then just remove it
 * (and decrement the reference count of it's node which in turn might
 * make something happen).
 */
static void
ng_disconnect_hook(hook_p hook)
{
	node_p node = hook->node;
	char *hook_name;

	hook->node_private = NULL;
	/*
	 * Remove the hook from the node's list to avoid possible recursion
	 * in case the disconnection results in node shutdown.
	 */
	LIST_REMOVE(hook, hooks);
	/*
	 * If node do not have a specific findhook,
	 * hooks are stored in htable.
	 */
	if (node->type->findhook == NULL)
		LIST_REMOVE(hook, namehooks);
	node->numhooks--;
	if (node->type->disconnect) {
		/*
		 * The type handler may elect to destroy the peer so don't
		 * trust its existance after this point.
		 */
		(*node->type->disconnect) (hook);
	}
	hook->node = NULL;
	ng_unref(node);
	hook_name = hook->name;
	if (hook_name) {
		hook->name = NULL;
		ng_free(hook_name);
	}

	ng_unref_hook(hook);
}

/*
 * Take two hooks on a node and merge the connection so that the given node
 * is effectively bypassed.
 */
int
ng_bypass(hook_p hook1, hook_p hook2)
{
	if (hook1->node != hook2->node)
		return (EINVAL);

	if ((hook1->flags & HK_INVALID) || (hook2->flags & HK_INVALID))
		return (EINVAL);

	if (hook2->peer->hook_rcvdata)
		hook1->peer->peer_rcvdata = hook2->peer->hook_rcvdata;
	else
		hook1->peer->peer_rcvdata = hook2->peer->node->type->rcvdata;

	if (hook1->peer->hook_rcvdata)
		hook2->peer->peer_rcvdata = hook1->peer->hook_rcvdata;
	else
		hook2->peer->peer_rcvdata = hook1->peer->node->type->rcvdata;
	hook1->peer->peer = hook2->peer;
	hook2->peer->peer = hook1->peer;

	hook1->peer_rcvdata = NULL;
	hook2->peer_rcvdata = NULL;
	hook1->peer = NULL;
	hook2->peer = NULL;
	ng_destroy_hook(hook1);
	ng_destroy_hook(hook2);
	return (0);
}

/*
 * Install a new netgraph type
 */
int
ng_newtype(struct ng_type *tp)
{
	const size_t namelen = strlen(tp->name);

	/* Check version and type name fields */
	if (tp->version != NG_VERSION || namelen == 0 || namelen > NG_TYPELEN) {
		VNB_TRAP();
		return (EINVAL);
	}

	/* Check for name collision */
	if (ng_findtype(tp->name) != NULL) {
		VNB_TRAP();
		return (EEXIST);
	}

	/* Link in new type */
	LIST_INSERT_HEAD(&typelist, tp, types);
	NG_TYPE_REF(tp); /* first ref is linked list */
	return (0);
}

/*
 * Remove a reference on a netgraph type
 */
int
ng_type_unref(struct ng_type *tp)
{
#ifdef __LinuxKernelVNB__
	/* Prevent races in case type is unregistered by module unloading */
	vnb_spinlock_lock(&type_list_lock);
#endif

	KASSERT(tp != NULL);

	/* Remove a reference on the type, possibly the last */
	if (vnb_atomic_dec_and_test(&tp->refs)) {
		/* Remove type */
		LIST_REMOVE(tp, types);
	}

#ifdef __LinuxKernelVNB__
	vnb_spinlock_unlock(&type_list_lock);
#endif

	return (0);
}

/*
 * Look for a type of the name given
 */
struct ng_type *
ng_findtype(const char *typename)
{
	struct ng_type *type;
	const int name_len = strlen(typename) + 1;

	LIST_FOREACH(type, &typelist, types) {
		if (strncmp(type->name, typename, name_len) == 0)
			break;
	}
	return (type);
}


/************************************************************************
			Composite routines
************************************************************************/

/*
 * Make a peer and connect. The order is arranged to minimise
 * the work needed to back out in case of error.
 */
int
ng_mkpeer(node_p node, const char *name, const char *name2, char *type, ng_ID_t *nodeid)
{
	node_p  node2;
	hook_p  hook = NULL;
	hook_p  hook2 = NULL;
	int     error;

	if ((error = ng_add_hook(node, name, &hook)))
		return (error);
	if ((error = ng_make_node(type, &node2, *nodeid))) {
		ng_destroy_hook(hook);
		return (error);
	}
	*nodeid = node2->ID;
	if ((error = ng_add_hook(node2, name2, &hook2))) {
		ng_rmnode(node2);
		ng_destroy_hook(hook);
		VNB_TRAP();
		return (error);
	}

	/*
	 * Actually link the two hooks together.. on failure they are
	 * destroyed so we don't have to do that here.
	 */
	if ((error = ng_connect(hook, hook2)))
		ng_rmnode(node2);
	return (error);
}

/*
 * Make a peer (if need be)  and insert it.
 */
static int
ng_insert (node_p base_node, const char *name,
            const char *from, const char *to,
            node_p ins_node, char *type, ng_ID_t *nodeid)
{
	node_p  new_node;
	hook_p  base_hook;
	hook_p  dst_hook;
	hook_p  hook_from = NULL;
	hook_p  hook_to = NULL;
	int     error;

	/*
	 * Find pair of connected hooks where to insert new node
	 */
	base_hook = ng_findhook(base_node, name);
	if (base_hook == NULL || (base_hook->flags & HK_INVALID) != 0)
		return (ENOENT);
	dst_hook = base_hook->peer;
	if (dst_hook == NULL || (dst_hook->flags & HK_INVALID) != 0)
		return (ENOENT);

	/*
	 * Create (if need be) new node and its two hooks (self-connected)
	 */
	new_node = ins_node;
	if ((new_node == NULL) && (error = ng_make_node(type, &new_node, *nodeid)))
		return (error);
	*nodeid = new_node->ID;
	if ((error = ng_add_hook(new_node, from, &hook_from)) ||
	    (error = ng_add_hook(new_node, to, &hook_to))     ||
	    (error = ng_connect_prepare(hook_from, hook_to))) {
		if (ins_node == NULL)
			ng_rmnode(new_node);
		return (error);
	}

	/*
	 * Temporary invalidates original hooks. No need for new hooks
	 * because ng_connect_prepare does NOT validate them
	 */
    base_hook->flags |= HK_INVALID;
    dst_hook->flags |= HK_INVALID;

	/*
	 * Hack the connections
	 */
	base_hook->peer = hook_from;
	hook_from->peer = base_hook;
	dst_hook->peer = hook_to;
	hook_to->peer = dst_hook;

	if (hook_from->hook_rcvdata)
		base_hook->peer_rcvdata = hook_from->hook_rcvdata;
	else
		base_hook->peer_rcvdata = hook_from->node->type->rcvdata;

	if (base_hook->hook_rcvdata)
		hook_from->peer_rcvdata = base_hook->hook_rcvdata;
	else
		hook_from->peer_rcvdata = base_hook->node->type->rcvdata;

	if (hook_to->hook_rcvdata)
		dst_hook->peer_rcvdata = hook_to->hook_rcvdata;
	else
		dst_hook->peer_rcvdata = hook_to->node->type->rcvdata;

	if (dst_hook->hook_rcvdata)
		hook_to->peer_rcvdata = dst_hook->hook_rcvdata;
	else
		hook_to->peer_rcvdata = dst_hook->node->type->rcvdata;

	/*
	 * Now ALL hoks can be used safely
	 */
	base_hook->flags &= ~HK_INVALID;
	dst_hook->flags &= ~HK_INVALID;
	hook_from->flags &= ~HK_INVALID;
	hook_to->flags &= ~HK_INVALID;

	return (0);
}

/*
 * Connect two nodes using the specified hooks
 */
int
ng_con_nodes(node_p node, const char *name, node_p node2, const char *name2)
{
	int     error;
	hook_p  hook = NULL;
	hook_p  hook2= NULL;

	if ((error = ng_add_hook(node, name, &hook)))
		return (error);
	if ((error = ng_add_hook(node2, name2, &hook2))) {
		ng_destroy_hook(hook);
		return (error);
	}
	return (ng_connect(hook, hook2));
}
/*
 * Connect force two nodes using the specified hooks
 */
static int
ng_con_force_nodes(node_p node, const char *name, node_p node2, const char *name2)
{
	int     error;
	hook_p  hook = NULL;
	hook_p  hook2= NULL;

	hook_p old_peer = NULL;
	hook_p old_peer2 = NULL;
	int newhook = 0;

	hook = ng_findhook(node, name);
	if (!hook) {
		error = ng_add_hook(node, name, &hook);
		if(error) return error;
		newhook = 1;
	}

	hook2 = ng_findhook(node2, name2);
	if (!hook2) {
		error = ng_add_hook(node2, name2, &hook2);
		/*if hook was not newly constructed, don't disturb it. */
		if(error && newhook) {
			ng_destroy_hook(hook);
			return (error);
		}
	}
	/* if hooks already connect each other, do nothing here. */
	if (hook->peer == hook2 && hook2->peer == hook)
		return 0;
	old_peer = hook->peer;
	old_peer2 = hook2->peer;
	hook->peer = hook2;
	hook->peer_rcvdata = hook2->node->type->rcvdata;
	hook->flags &= ~HK_INVALID;
	hook2->peer = hook;
	hook2->peer_rcvdata = hook->node->type->rcvdata;
	hook2->flags &= ~HK_INVALID;

	if (old_peer) {
		old_peer->flags |= HK_INVALID;      /* as soon as possible */
		old_peer->peer_rcvdata = NULL;
		old_peer->peer = NULL;
		ng_disconnect_hook(old_peer);
	}
	if (old_peer2) {
		old_peer2->flags |= HK_INVALID;      /* as soon as possible */
		old_peer2->peer_rcvdata = NULL;
		old_peer2->peer = NULL;
		ng_disconnect_hook(old_peer2);
	}
	return (0);
}
/*
 * Parse and verify a string of the form:  <NODE:><PATH>
 *
 * Such a string can refer to a specific node or a specific hook
 * on a specific node, depending on how you look at it. In the
 * latter case, the PATH component must not end in a dot.
 *
 * Both <NODE:> and <PATH> are optional. The <PATH> is a string
 * of hook names separated by dots. This breaks out the original
 * string, setting *nodep to "NODE" (or NULL if none) and *pathp
 * to "PATH" (or NULL if degenerate). Also, *hookp will point to
 * the final hook component of <PATH>, if any, otherwise NULL.
 *
 * This returns -1 if the path is malformed. The char ** are optional.
 */

int
ng_path_parse(char *addr, char **nodep, char **pathp, char **hookp)
{
	char   *node, *path, *hook;
	int     k;
	int path_len;

	/*
	 * Extract absolute NODE, if any
	 */
	for (path = addr; *path && *path != ':'; path++);
	if (*path) {
		node = addr;	/* Here's the NODE */
		*path++ = '\0';	/* Here's the PATH */

		/* Node name must not be empty */
		if (!*node)
			return -1;

		/* A name of "." is OK; otherwise '.' not allowed */
		if ((node[0] != '.') && node[1] != '\0') {
			for (k = 0; node[k]; k++)
				if (node[k] == '.')
					return -1;
		}
	} else {
		node = NULL;	/* No absolute NODE */
		path = addr;	/* Here's the PATH */
	}

	/* Snoop for illegal characters in PATH */
	for (k = 0; path[k]; k++)
		if (path[k] == ':')
			return -1;

	/* Check for no repeated dots in PATH */
	for (k = 0; path[k]; k++)
		if (path[k] == '.' && path[k + 1] == '.')
			return -1;

	/* Remove extra (degenerate) dots from beginning or end of PATH */
	if (path[0] == '.')
		path++;
	path_len = strlen(path) - 1;
	if (*path && path[path_len] == '.')
		path[path_len] = '\0';

	/* If PATH has a dot, then we're not talking about a hook */
	if (*path) {
		for (hook = path, k = 0; path[k]; k++)
			if (path[k] == '.') {
				hook = NULL;
				break;
			}
	} else
		path = hook = NULL;

	/* Done */
	if (nodep)
		*nodep = node;
	if (pathp)
		*pathp = path;
	if (hookp)
		*hookp = hook;
	return (0);
}

/*
 * Given a path, which may be absolute or relative, and a starting node,
 * return the destination node. Compute the "return address" if desired.
 */
int
ng_path2node(node_p here, const char *address, node_p *destp, char **rtnp)
{
	const	node_p start = here;
	char    fullpath[NG_PATHLEN + 1];
	char   *nodename, *path, pbuf[2];
	node_p  node;
	char   *cp;

	/* Initialize */
	if (rtnp)
		*rtnp = NULL;
	if (destp == NULL)
		return EINVAL;
	*destp = NULL;

	/* Make a writable copy of address for ng_path_parse() */
	strncpy(fullpath, address, sizeof(fullpath) - 1);
	fullpath[sizeof(fullpath) - 1] = '\0';

	/* Parse out node and sequence of hooks */
	if (ng_path_parse(fullpath, &nodename, &path, NULL) < 0) {
		VNB_TRAP();
		return EINVAL;
	}
	if (path == NULL) {
		pbuf[0] = '.';	/* Needs to be writable */
		pbuf[1] = '\0';
		path = pbuf;
	}

	/* For an absolute address, jump to the starting node */
	if (nodename) {
		node = ng_findname(here, nodename);
		if (node == NULL) {
			return (ENOENT);
		}
	} else
		node = here;

	/* Now follow the sequence of hooks */
	for (cp = path; node != NULL && *cp != '\0'; ) {
		hook_p hook;
		char *segment;

		/*
		 * Break out the next path segment. Replace the dot we just
		 * found with a NUL; "cp" points to the next segment (or the
		 * NUL at the end).
		 */
		for (segment = cp; *cp != '\0'; cp++) {
			if (*cp == '.') {
				*cp++ = '\0';
				break;
			}
		}

		/* Empty segment */
		if (*segment == '\0')
			continue;

		/* We have a segment, so look for a hook by that name */
		hook = ng_findhook(node, segment);

		/* Can't get there from here... */
		if (hook == NULL
		    || hook->peer == NULL
		    || (hook->flags & HK_INVALID) != 0) {
			return (ENOENT);
		}

		/* Hop on over to the next node */
		node = hook->peer->node;
	}

	/* If node somehow missing, fail here (probably this is not needed) */
	if (node == NULL) {
		VNB_TRAP();
		return (ENXIO);
	}

	/* Now compute return address, i.e., the path to the sender */
	if (rtnp != NULL) {
		MALLOC(*rtnp, char *, NG_NODELEN + 2, M_NETGRAPH, M_NOWAIT);
		if (*rtnp == NULL) {
			VNB_TRAP();
			return (ENOMEM);
		}
		if (start->name != NULL)
			sprintf(*rtnp, "%s:", start->name);
		else
			sprintf(*rtnp, "[%x]:", ng_node2ID(start));
	}

	/* Done */
	*destp = node;
	return (0);
}

/*
 * Call the appropriate message handler for the object.
 * It is up to the message handler to free the message.
 * If it's a generic message, handle it generically, otherwise
 * call the type's message handler (if it exists)
 * XXX (race). Remember that a queued message may reference a node
 * or hook that has just been invalidated. It will exist
 * as the queue code is holding a reference, but..
 */

#define CALL_MSG_HANDLER(error, node, msg, retaddr, resp, nl_msg)	\
do {									\
	if((msg)->header.typecookie == NGM_GENERIC_COOKIE) {		\
		(error) = ng_generic_msg((node), (msg),			\
				(retaddr), (resp), (nl_msg));		\
	} else {							\
		if ((node)->type->rcvmsg != NULL) {			\
			(error) = (*(node)->type->rcvmsg)((node),	\
					(msg), (retaddr), (resp),	\
					(nl_msg));			\
		} else {						\
			VNB_TRAP();					\
			FREE((msg), M_NETGRAPH);			\
			(error) = EINVAL;				\
		}							\
	}								\
} while (0)


/*
 * Send a control message to a node
 */
int
ng_send_msg(node_p here, struct ng_mesg *msg, const char *address,
	    struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	node_p  dest = NULL;
	char   *retaddr = NULL;
	int     error;

	/* Find the target node */
	error = ng_path2node(here, address, &dest, &retaddr);
	if (error) {
		FREE(msg, M_NETGRAPH);
		if (retaddr)
			FREE(retaddr, M_NETGRAPH);
		return error;
	}

	/* Make sure the resp and nl_msg fields are null before we start */
	if (rptr != NULL)
		*rptr = NULL;
	if (nl_msg != NULL)
		*nl_msg = NULL;

	if (msg->header.flags & NGF_ASCII) {
		int bufSize = 20 * 1024;	/* XXX hard coded constant */
		const struct ng_cmdlist *c;
		const struct ng_parse_type *argstype;
		struct ng_mesg *msg2 = NULL;
		int off = 0;

		if (msg->header.cmdstr[0] != '\0') {
			const int cmdstr_len = strlen(msg->header.cmdstr) + 1;
			/* Find command by matching ASCII command string */
			for (c = dest->type->cmdlist;
			     c != NULL && c->name != NULL; c++) {
				if (strncmp(msg->header.cmdstr, c->name, cmdstr_len) == 0)
					break;
			}
			if (c == NULL || c->name == NULL) {
				for (c = ng_generic_cmds; c->name != NULL; c++) {
					if (strncmp(msg->header.cmdstr, c->name, cmdstr_len) == 0)
						break;
				}
				if (c->name == NULL) {
					log(LOG_DEBUG, "generic command cmdstr=%s not found\n",
							msg->header.cmdstr);
					FREE((msg), M_NETGRAPH);
					if (retaddr)
						FREE(retaddr, M_NETGRAPH);
					return -1;
				}
			}
		} else {
			/* Find command by matching typecookie and command number */
			for (c = dest->type->cmdlist;
			     c != NULL && c->name != NULL; c++) {
				if (msg->header.typecookie == c->cookie
						&& msg->header.cmd == c->cmd)
					break;
			}
			if (c == NULL || c->name == NULL) {
				for (c = ng_generic_cmds; c->name != NULL; c++) {
					if (msg->header.typecookie == c->cookie
							&& msg->header.cmd == c->cmd)
						break;
				}
				if (c->name == NULL) {
					log(LOG_DEBUG, "specific or generic command typecookie=%d cmd=%d not found\n",
							msg->header.typecookie, msg->header.cmd);
					FREE((msg), M_NETGRAPH);
					if (retaddr)
						FREE(retaddr, M_NETGRAPH);
					return -1;
				}
			}
		}

		/* If message has no data, do not try to translate from ASCII to binary */
		if (msg->header.arglen == 0) {
			msg->header.typecookie = c->cookie;
			msg->header.cmd = c->cmd;
			CALL_MSG_HANDLER(error, dest, msg, retaddr, rptr, nl_msg);
			goto postprocess;
		}

		/* Translate ASCII message to binary */
		msg->data[msg->header.arglen - 1] = '\0';

		MALLOC(msg2, struct ng_mesg *, bufSize + sizeof(*msg2), M_NETGRAPH, M_NOWAIT);
		if (msg2 == NULL) {
			FREE(msg, M_NETGRAPH);
			if (retaddr)
				FREE(retaddr, M_NETGRAPH);
			return -1;
		}
		bzero(msg2, bufSize);

		/* Copy ASCII message header to response message payload */
		bcopy(msg, msg2, sizeof(*msg2));
		msg2->header.flags = NGF_ORIG;
		/* Convert command arguments to binary */
		argstype = (msg2->header.flags & NGF_RESP) ?
			c->respType : c->mesgType;
		if (argstype == NULL) {
			FREE(msg, M_NETGRAPH);
			FREE(msg2, M_NETGRAPH);
			if (retaddr)
				FREE(retaddr, M_NETGRAPH);
			return (EINVAL);
		} else {
			if (ng_parse(argstype, msg->data,
			    &off, (u_char *)msg2->data, &bufSize) != 0) {
				FREE(msg, M_NETGRAPH);
				FREE(msg2, M_NETGRAPH);
				if (retaddr)
					FREE(retaddr, M_NETGRAPH);
				return -1;
			}
		}

		/* Return the result */
		msg2->header.arglen = bufSize;
		CALL_MSG_HANDLER(error, dest, msg2, retaddr, rptr, nl_msg);
		FREE(msg, M_NETGRAPH);
	} else
		CALL_MSG_HANDLER(error, dest, msg, retaddr, rptr, nl_msg);

postprocess:
	/* Make sure that if there is a response, it has the RESP bit set */
	if ((error == 0) && rptr && *rptr)
		(*rptr)->header.flags |= NGF_RESP;

	/*
	 * If we had a return address it is up to us to free it. They should
	 * have taken a copy if they needed to make a delayed response.
	 */
	if (retaddr)
		FREE(retaddr, M_NETGRAPH);
	return (error);
}

/*
 * Implement the 'generic' control messages
 */
static int
ng_generic_msg(node_p here, struct ng_mesg *msg, const char *retaddr,
	       struct ng_mesg **resp, struct ng_mesg **nl_msg)
{
	int error = 0;

	if (msg->header.typecookie != NGM_GENERIC_COOKIE) {
		VNB_TRAP();
		FREE(msg, M_NETGRAPH);
		return (EINVAL);
	}
	switch (msg->header.cmd) {
	case NGM_SHUTDOWN:
		ng_rmnode(here);
		break;
	case NGM_MKPEER_GET_NODEID:
	case NGM_MKPEER:
	case NGM_MKPEER_ID:
	    {
		struct ngm_mkpeer *mkp = (struct ngm_mkpeer *) msg->data;
		ng_ID_t nodeid = 0;

		if (msg->header.arglen != sizeof(*mkp)) {
			VNB_TRAP();
			return (EINVAL);
		}
		mkp->type[sizeof(mkp->type) - 1] = '\0';
		mkp->ourhook[sizeof(mkp->ourhook) - 1] = '\0';
		mkp->peerhook[sizeof(mkp->peerhook) - 1] = '\0';
		if (msg->header.cmd == NGM_MKPEER_ID)
			nodeid = mkp->nodeid;
		error = ng_mkpeer(here, mkp->ourhook, mkp->peerhook, mkp->type, &nodeid);
#if defined(__LinuxKernelVNB__) && defined(CONFIG_VNB_NETLINK_NOTIFY)
		VNB_BUILD_BUG_ON(sizeof(ng_ID_t) != sizeof(uint32_t));
		if (error == 0 && nl_msg) {
			if ((error = VNB_DUP_NG_MESG(*nl_msg, msg)) != 0)
				break;
			/* We are allowed to change the cmd because NGM_MKPEER and
			 * NGM_MKPEER_ID use the same structure: struct ngm_mkpeer.
			 */
			(*nl_msg)->header.cmd = NGM_MKPEER_ID;
			mkp = (struct ngm_mkpeer *)(*nl_msg)->data;
			mkp->nodeid = nodeid;
		}
#endif

		if (msg->header.cmd == NGM_MKPEER_GET_NODEID) {
			struct ng_mesg *rp;
			u_int32_t *id;

			/* Get response struct */
			if (resp == NULL) {
				error = EINVAL;
				break;
			}
			NG_MKRESPONSE(rp, msg, sizeof(*id), M_NOWAIT);
			if (rp == NULL) {
				error = ENOMEM;
				break;
			}
			id = (u_int32_t *) rp->data;

			*id = nodeid;
			*resp = rp;
		}

		break;
	    }
	case NGM_INSPEER:
	    {
		struct ngm_inspeer *isp = (struct ngm_inspeer *) msg->data;
		ng_ID_t nodeid = isp->nodeid;

		if (msg->header.arglen != sizeof(*isp)) {
			VNB_TRAP();
			return (EINVAL);
		}
		isp->type[sizeof(isp->type) - 1] = '\0';
		isp->ourhook[sizeof(isp->ourhook) - 1] = '\0';
		isp->peerhook[sizeof(isp->peerhook) - 1] = '\0';
		isp->peerhook2[sizeof(isp->peerhook2) - 1] = '\0';
		error = ng_insert (here, isp->ourhook, isp->peerhook,
		                   isp->peerhook2, NULL, isp->type, &nodeid);
#if defined(__LinuxKernelVNB__) && defined(CONFIG_VNB_NETLINK_NOTIFY)
		if (error == 0 && nl_msg) {
			if ((error = VNB_DUP_NG_MESG(*nl_msg, msg)) != 0)
				break;
			isp = (struct ngm_inspeer *) (*nl_msg)->data;
			isp->nodeid = nodeid;
		}
#endif
		break;
	    }
	case NGM_BYPASS:
	    {
		hook_p hook1, hook2;
		struct ngm_bypass *const bp = (struct ngm_bypass *) msg->data;

		if (msg->header.arglen != sizeof(*bp)) {
			VNB_TRAP();
			return (EINVAL);
		}
		bp->ourhook[sizeof(bp->ourhook) - 1] = '\0';
		bp->ourhook2[sizeof(bp->ourhook2) - 1] = '\0';
		hook1  = ng_findhook(here, bp->ourhook);
		hook2  = ng_findhook(here, bp->ourhook2);
		if (hook1 && hook2)
			error = ng_bypass (hook1, hook2);
		else
			return (ENOENT);
		break;
	    }
	case NGM_CONNECT:
	case NGM_CONNECT_FORCE:
	    {
		struct ngm_connect *const con =
			(struct ngm_connect *) msg->data;
		node_p node2;

		if (msg->header.arglen != sizeof(*con)) {
			VNB_TRAP();
			return (EINVAL);
		}
		con->path[sizeof(con->path) - 1] = '\0';
		con->ourhook[sizeof(con->ourhook) - 1] = '\0';
		con->peerhook[sizeof(con->peerhook) - 1] = '\0';
		error = ng_path2node(here, con->path, &node2, NULL);
		if (error)
			break;
		if (msg->header.cmd == NGM_CONNECT)
			error = ng_con_nodes(here, con->ourhook, node2, con->peerhook);
		else
			error = ng_con_force_nodes(here, con->ourhook, node2, con->peerhook);
		break;
	    }

	case NGM_INSNODE:
	    {
		struct ngm_insnode *isn =
			(struct ngm_insnode *) msg->data;
		node_p node2;
		ng_ID_t nodeid = isn->nodeid;

		if (msg->header.arglen != sizeof(*isn)) {
			VNB_TRAP();
			return (EINVAL);
		}
		isn->path[sizeof(isn->path) - 1] = '\0';
		isn->ourhook[sizeof(isn->ourhook) - 1] = '\0';
		isn->peerhook[sizeof(isn->peerhook) - 1] = '\0';
		isn->peerhook2[sizeof(isn->peerhook2) - 1] = '\0';
		error = ng_path2node(here, isn->path, &node2, NULL);
		if (error)
			break;
		error = ng_insert (here, isn->ourhook, isn->peerhook,
		                   isn->peerhook2, node2, 0, &nodeid);
#if defined(__LinuxKernelVNB__) && defined(CONFIG_VNB_NETLINK_NOTIFY)
		if (error == 0 && nl_msg) {
			if ((error = VNB_DUP_NG_MESG(*nl_msg, msg)) != 0)
				break;
			isn = (struct ngm_insnode *) (*nl_msg)->data;
			isn->nodeid = nodeid;
		}
#endif
		break;
	    }
	case NGM_NAME:
	    {
		struct ngm_name *const nam = (struct ngm_name *) msg->data;

		if (msg->header.arglen != sizeof(*nam)) {
			VNB_TRAP();
			return (EINVAL);
		}
		nam->name[sizeof(nam->name) - 1] = '\0';
		error = ng_name_node(here, nam->name);
		break;
	    }
	case NGM_RMHOOK:
	    {
		struct ngm_rmhook *const rmh = (struct ngm_rmhook *) msg->data;
		hook_p hook;

		if (msg->header.arglen != sizeof(*rmh)) {
			VNB_TRAP();
			return (EINVAL);
		}
		rmh->ourhook[sizeof(rmh->ourhook) - 1] = '\0';
		if ((hook = ng_findhook(here, rmh->ourhook)) != NULL)
			ng_destroy_hook(hook);
		break;
	    }
	case NGM_NODEINFO:
	    {
		struct nodeinfo *ni;
		struct ng_mesg *rp;

		/* Get response struct */
		if (resp == NULL) {
			error = EINVAL;
			break;
		}
		NG_MKRESPONSE(rp, msg, sizeof(*ni), M_NOWAIT);
		if (rp == NULL) {
			error = ENOMEM;
			break;
		}

		/* Fill in node info */
		ni = (struct nodeinfo *) rp->data;
		if (here->name != NULL)
			strncpy(ni->name, here->name, NG_NODELEN);
		strncpy(ni->type, here->type->name, NG_TYPELEN);
		ni->id = ng_node2ID(here);
		ni->hooks = here->numhooks;
		*resp = rp;
		break;
	    }
	case NGM_LISTHOOKS:
	    {
		const unsigned int nhooks = here->numhooks;
		struct hooklist *hl;
		struct nodeinfo *ni;
		struct ng_mesg *rp;
		hook_p hook;
		struct listoffset *list_offset;
		unsigned int count, offset = 0;

		/* Get response struct */
		if (resp == NULL) {
			error = EINVAL;
			break;
		}

		if (msg->header.arglen != 0) {
			/* Get offset and count information */
			list_offset = (struct listoffset*)msg->data;
			if (msg->header.arglen != sizeof(struct listoffset)) {
				VNB_TRAP();
				return (EINVAL);
			}
			offset = list_offset->offset;
			count = list_offset->count;
			if (count == 0 || count > nhooks)
				count = nhooks;
		} else {
			count = nhooks;
		}

		NG_MKRESPONSE(rp, msg, sizeof(*hl)
		    + (count * sizeof(struct linkinfo)), M_NOWAIT);
		if (rp == NULL) {
			error = ENOMEM;
			break;
		}
		hl = (struct hooklist *) rp->data;
		ni = &hl->nodeinfo;

		/* Fill in node info */
		if (here->name)
			strncpy(ni->name, here->name, NG_NODELEN);
		strncpy(ni->type, here->type->name, NG_TYPELEN);
		ni->id = ng_node2ID(here);
		ni->vnb_ns = here->vnb_ns;

		/* Cycle through the linked list of hooks */
		ni->hooks = 0;
		LIST_FOREACH(hook, &here->hooks, hooks) {
			struct linkinfo *const link = &hl->link[ni->hooks];

			if (ni->hooks >= nhooks) {
				log(LOG_ERR, "%s: number of %s changed\n",
				    __FUNCTION__, "hooks");
				break;
			}
			if (ni->hooks >= count)
				break;
			if ((hook->flags & HK_INVALID) != 0)
				continue;
			if (offset > 0) {
				offset--;
				continue;
			}

			strncpy(link->ourhook, hook->name, NG_HOOKLEN);
			strncpy(link->peerhook, hook->peer->name, NG_HOOKLEN);
			if (hook->peer->node->name != NULL)
				strncpy(link->nodeinfo.name,
				    hook->peer->node->name, NG_NODELEN);
			strncpy(link->nodeinfo.type,
			   hook->peer->node->type->name, NG_TYPELEN);
			link->nodeinfo.id = ng_node2ID(hook->peer->node);
			link->nodeinfo.hooks = hook->peer->node->numhooks;
			ni->hooks++;
		}
		*resp = rp;
		break;
	    }

#ifdef __LinuxKernelVNB__
	case NGM_DUMPNODES:
	    {
		node_p node;
		uint32_t total_count = per_ns(gNumNodes, ctrl_vnb_ns);
		uint32_t count = 1;

		LIST_FOREACH(node, &per_ns(nodelist, ctrl_vnb_ns), nodes) {
			vnb_netlink_dump(node, count++, total_count);
		}

		break;
	    }
#endif

	case NGM_LISTNAMES:
	case NGM_LISTNODES:
	    {
		const int unnamed = (msg->header.cmd == NGM_LISTNODES);
		struct namelist *nl;
		struct ng_mesg *rp;
		struct listoffset *list_offset;
		node_p node;
		unsigned int num = 0, count, offset;

		if (resp == NULL) {
			error = EINVAL;
			VNB_TRAP();
			break;
		}

		/* Count number of nodes */
		LIST_FOREACH(node, &per_ns(nodelist, ctrl_vnb_ns), nodes) {
			if ((node->flags & NG_INVALID) == 0
			    && (unnamed || node->name != NULL))
				num++;
		}

		/* Get offset and count information */
		list_offset = (struct listoffset*)msg->data;
		if (msg->header.arglen != sizeof(struct listoffset)) {
			VNB_TRAP();
			return (EINVAL);
		}
		offset = list_offset->offset;
		count = list_offset->count;
		if (count == 0 || count > num)
			count = num;

		/* Get response struct */
		if (resp == NULL) {
			error = EINVAL;
			VNB_TRAP();
			break;
		}
		NG_MKRESPONSE(rp, msg, sizeof(*nl)
		    + (count * sizeof(struct nodeinfo)), M_NOWAIT);
		if (rp == NULL) {
			error = ENOMEM;
			break;
		}
		nl = (struct namelist *) rp->data;

		/* Cycle through the linked list of nodes */
		nl->numnames = 0;
		nl->totalnames = num;
		LIST_FOREACH(node, &per_ns(nodelist, ctrl_vnb_ns), nodes) {
			struct nodeinfo *const np = &nl->nodeinfo[nl->numnames];

			if (nl->numnames >= num) {
				log(LOG_ERR, "%s: number of %s changed\n",
				    __FUNCTION__, "nodes");
				break;
			}
			if (nl->numnames >= count)
				break;
			if ((node->flags & NG_INVALID) != 0)
				continue;
			if (!unnamed && node->name == NULL)
				continue;
			if (offset > 0) {
				offset --;
				continue;
			}
			if (node->name != NULL)
				strncpy(np->name, node->name, NG_NODELEN);
			strncpy(np->type, node->type->name, NG_TYPELEN);
			np->id = ng_node2ID(node);
			np->hooks = node->numhooks;
			nl->numnames++;
		}
		*resp = rp;
		break;
	    }

	case NGM_FINDNODE:
		{
			struct ng_mesg *rp;
			node_p node;
			int len;
			unsigned int i, reqifunit, ifunit;
			/*
			 * str is supposed to be an ascii string ending with digits,
			 * for instance pppX or l2tpX. No ending digits is the same
			 * as ending with 0.
			 */
			char *str=msg->data,*eptr;

			if (per_ns(gNumNodes, ctrl_vnb_ns)/8 + 1 > ngm_findnode_bitfield_size) {
				/* if needed > tab_size, then tab_size=2*needed
					( to avoid too many reallocation )
				*/
				ngm_findnode_bitfield_size=per_ns(gNumNodes, ctrl_vnb_ns)/4 + 1;
				if (ngm_findnode_bitfield)
					FREE(ngm_findnode_bitfield, M_NETGRAPH);
				MALLOC(ngm_findnode_bitfield, char *, ngm_findnode_bitfield_size, M_NETGRAPH, M_NOWAIT);
				if (ngm_findnode_bitfield == NULL) {
					error = ENOMEM;
					break;
				}
			}

			if (msg->header.arglen < 2) {
				error = EINVAL;
				break;
			}

			/* len is the number of characters before leading digits:
			 * for instance, if str is "l2tp1", then len is 4
			 */
			len = strlen(str) - 1;

			if (len >= NG_NODELEN || len <= 0) {
				error = EINVAL;
				break;
			}

			while ((len >= 0) && isdigit(str[len]))
				len--;

			len++;

			/* string is empty or only digits */
			if (len <= 0) {
				error = EINVAL;
				break;
			}

			memset(ngm_findnode_bitfield, 0, ngm_findnode_bitfield_size);

			/* requested ifunit */
			reqifunit = strtoul(str+len, NULL, 0);

			if (resp == NULL) {
				error = EINVAL;
				break;
			}

			NG_MKRESPONSE(rp, msg, NG_NODELEN + 1, M_NOWAIT);

			if (rp == NULL) {
				error = ENOMEM;
				break;
			}

			error = ENOENT;

			LIST_FOREACH(node, &per_ns(nodelist, ctrl_vnb_ns), nodes) {
				if ( ((node->flags & NG_INVALID) != 0) || (node->name == NULL) )
					continue;

				if ( (strncmp(node->name,str,len) == 0) &&
					(isdigit(node->name[len])) ) {
					/* if the node has no hook then we can use it */
					if (node->numhooks == 0) {
						error = 0;
						break;
					}
					ifunit = (int)strtoul(node->name + len, &eptr, 10);

					if ( (*eptr=='\0') && (ifunit >= reqifunit)
						&& (ifunit<(ngm_findnode_bitfield_size*8)) )
					ngm_findnode_bitfield[ifunit/8] |= 1 << (ifunit%8);
				}
			}

			/* first char rp->data[0] is + or -, whether node exists or not */
			if (error == 0) {
				/* we have found a 0-hook node */
				rp->data[0]='+';
				strncpy(rp->data+1,node->name,NG_NODELEN);
			} else for(i=reqifunit; i < ngm_findnode_bitfield_size*8; i++)
				/* we have to find an unused ifunit in the bit-field */
				if ( (ngm_findnode_bitfield[i/8] & (1 << (i%8))) == 0 ) {
					rp->data[0]='-';
					strncpy(rp->data+1, str, len+1);
					snprintf(rp->data+1+len, NG_NODELEN-len, "%d", i);
					error = 0;
					break;
				}

			if (error == 0)
			*resp=rp;

			break;
		}
	case NGM_LISTTYPES:
	    {
		struct typelist *tl;
		struct ng_mesg *rp;
		struct ng_type *type;
		unsigned int num = 0, offset, count;
		struct listoffset *list_offset;

		if (resp == NULL) {
			error = EINVAL;
			break;
		}

		/* Count number of types */
		LIST_FOREACH(type, &typelist, types)
			num++;

		/* Get offset and count information */
		list_offset = (struct listoffset*)msg->data;
		if (msg->header.arglen != sizeof(struct listoffset)) {
			VNB_TRAP();
			return (EINVAL);
		}
		offset = list_offset->offset;
		count = list_offset->count;
		if (count == 0 || count > num)
			count = num;

		/* Get response struct */
		if (resp == NULL) {
			error = EINVAL;
			break;
		}
		NG_MKRESPONSE(rp, msg, sizeof(*tl)
		    + (count * sizeof(struct typeinfo)), M_NOWAIT);
		if (rp == NULL) {
			error = ENOMEM;
			break;
		}
		tl = (struct typelist *) rp->data;

		/* Cycle through the linked list of types */
		tl->numtypes = 0;
		LIST_FOREACH(type, &typelist, types) {
			struct typeinfo *const tp = &tl->typeinfo[tl->numtypes];

			if (tl->numtypes >= num) {
				log(LOG_ERR, "%s: number of %s changed\n",
				    __FUNCTION__, "types");
				break;
			}
			if (tl->numtypes >= count)
				break;
			if (offset > 0) {
				offset--;
				continue;
			}

			strncpy(tp->type_name, type->name, NG_TYPELEN);
			tp->numnodes = vnb_atomic_read(&(type->refs)) - 1; /* don't count list */
			tl->numtypes++;
		}
		*resp = rp;
		break;
	    }

	case NGM_BINARY2ASCII:
	    {
		int bufSize = 20 * 1024;	/* XXX hard coded constant */
		const struct ng_parse_type *argstype;
		const struct ng_cmdlist *c;
		struct ng_mesg *rp, *binary, *ascii;

		/* Data area must contain a valid netgraph message */
		binary = (struct ng_mesg *)msg->data;
		if (msg->header.arglen < sizeof(struct ng_mesg)
		    || msg->header.arglen - sizeof(struct ng_mesg)
		      < binary->header.arglen) {
			error = EINVAL;
			break;
		}

		/* Get a response message with lots of room */
		NG_MKRESPONSE(rp, msg, sizeof(*ascii) + bufSize, M_NOWAIT);
		if (rp == NULL) {
			error = ENOMEM;
			break;
		}
		ascii = (struct ng_mesg *)rp->data;

		/* Copy binary message header to response message payload */
		bcopy(binary, ascii, sizeof(*binary));

		/* Find command by matching typecookie and command number */
		for (c = here->type->cmdlist;
		    c != NULL && c->name != NULL; c++) {
			if (binary->header.typecookie == c->cookie
			    && binary->header.cmd == c->cmd)
				break;
		}
		if (c == NULL || c->name == NULL) {
			for (c = ng_generic_cmds; c->name != NULL; c++) {
				if (binary->header.typecookie == c->cookie
				    && binary->header.cmd == c->cmd)
					break;
			}
			if (c->name == NULL) {
				FREE(rp, M_NETGRAPH);
				error = ENOSYS;
				break;
			}
		}

		/* Convert command name to ASCII */
		snprintf(ascii->header.cmdstr, sizeof(ascii->header.cmdstr),
		    "%s", c->name);

		/* Convert command arguments to ASCII */
		argstype = (binary->header.flags & NGF_RESP) ?
		    c->respType : c->mesgType;
		if (argstype == NULL)
			*ascii->data = '\0';
		else {
			if ((error = ng_unparse(argstype,
			    (u_char *)binary->data,
			    ascii->data, bufSize)) != 0) {
				FREE(rp, M_NETGRAPH);
				break;
			}
		}

		/* Return the result as struct ng_mesg plus ASCII string */
		bufSize = strlen(ascii->data) + 1;
		ascii->header.arglen = bufSize;
		rp->header.arglen = sizeof(*ascii) + bufSize;
		*resp = rp;
		break;
	    }

	case NGM_ASCII2BINARY:
	    {
		int bufSize = 20 * 1024;	/* XXX hard coded constant */
		const struct ng_cmdlist *c;
		const struct ng_parse_type *argstype;
		struct ng_mesg *rp, *ascii, *binary;
		int off = 0;
		int cmdstr_len;

		/* Data area must contain at least a struct ng_mesg + '\0' */
		ascii = (struct ng_mesg *)msg->data;
		if (msg->header.arglen < sizeof(*ascii) + 1
		    || ascii->header.arglen < 1
		    || msg->header.arglen
		      < sizeof(*ascii) + ascii->header.arglen) {
			error = EINVAL;
			break;
		}
		ascii->data[ascii->header.arglen - 1] = '\0';

		/* Get a response message with lots of room */
		NG_MKRESPONSE(rp, msg, sizeof(*binary) + bufSize, M_NOWAIT);
		if (rp == NULL) {
			error = ENOMEM;
			break;
		}
		binary = (struct ng_mesg *)rp->data;

		/* Copy ASCII message header to response message payload */
		bcopy(ascii, binary, sizeof(*ascii));
		cmdstr_len = strlen(ascii->header.cmdstr) + 1;

		/* Find command by matching ASCII command string */
		for (c = here->type->cmdlist;
		    c != NULL && c->name != NULL; c++) {
			if (strncmp(ascii->header.cmdstr, c->name, cmdstr_len) == 0)
				break;
		}
		if (c == NULL || c->name == NULL) {
			for (c = ng_generic_cmds; c->name != NULL; c++) {
				if (strncmp(ascii->header.cmdstr, c->name, cmdstr_len) == 0)
					break;
			}
			if (c->name == NULL) {
				FREE(rp, M_NETGRAPH);
				error = ENOSYS;
				break;
			}
		}

		/* Convert command name to binary */
		binary->header.cmd = c->cmd;
		binary->header.typecookie = c->cookie;

		/* Convert command arguments to binary */
		argstype = (binary->header.flags & NGF_RESP) ?
		    c->respType : c->mesgType;
		if (argstype == NULL)
			bufSize = 0;
		else {
			if ((error = ng_parse(argstype, ascii->data,
			    &off, (u_char *)binary->data, &bufSize)) != 0) {
				FREE(rp, M_NETGRAPH);
				break;
			}
		}

		/* Return the result */
		binary->header.arglen = bufSize;
		rp->header.arglen = sizeof(*binary) + bufSize;
		*resp = rp;
		break;
	    }
	case NGM_SHOWHTABLES:
		{
			unsigned int cnt[4] = { 1, 2, 5, 10 };
			unsigned int res[4];
			unsigned int i, sum, nempty, max;
			struct showhtables *showhtables;
			struct ng_mesg *rp;

			NG_MKRESPONSE(rp, msg, sizeof(*showhtables), M_NOWAIT);
			if (rp == NULL) {
				error = ENOMEM;
				break;
			}

			/* Fill in node info */
			showhtables = (struct showhtables *) rp->data;

			sum = nempty = max = 0;
			memset((void *)res, 0, sizeof (res));
			for (i = 0; i < NAME_HASH_SIZE; i++) {
				node_p node;
				unsigned int nb_elt;
				unsigned int j;

				LIST_GET_NB_ELT(node,
						&per_ns(NAME_hash,
							ctrl_vnb_ns)[i],
						namenodes, nb_elt);
				if (nb_elt) {
					sum += nb_elt;
					nempty++;
				}

				if (nb_elt > max)
					max = nb_elt;

				for (j = 0; j <= 3; j++) {
					if (nb_elt > cnt[j])
						res[j]++;
					else
						break;
				}
			}

			showhtables->namenodes.size = NAME_HASH_SIZE;
			showhtables->namenodes.nb_elt = sum;
			showhtables->namenodes.more_than_10 = res[3];
			showhtables->namenodes.more_than_5 = res[2];
			showhtables->namenodes.more_than_2 = res[1];
			showhtables->namenodes.more_than_1 = res[0];
			showhtables->namenodes.max = max;
			showhtables->namenodes.non_empty_average =
				nempty ? (sum / nempty) : 0;

			sum = nempty = max = 0;
			memset((void *)res, 0, sizeof (res));
			for (i = 0; i < ID_HASH_SIZE; i++) {
				node_p node;
				unsigned int nb_elt;
				unsigned int j;

				LIST_GET_NB_ELT(node,
						&per_ns(ID_hash,
							ctrl_vnb_ns)[i],
						idnodes, nb_elt);
				if (nb_elt) {
					sum += nb_elt;
					nempty++;
				}

				if (nb_elt > max)
					max = nb_elt;

				for (j = 0; j <= 3; j++) {
					if (nb_elt > cnt[j])
						res[j]++;
					else
						break;
				}
			}

			showhtables->idnodes.size = ID_HASH_SIZE;
			showhtables->idnodes.nb_elt = sum;
			showhtables->idnodes.more_than_10 = res[3];
			showhtables->idnodes.more_than_5 = res[2];
			showhtables->idnodes.more_than_2 = res[1];
			showhtables->idnodes.more_than_1 = res[0];
			showhtables->idnodes.max = max;
			showhtables->idnodes.non_empty_average =
				nempty ? (sum / nempty) : 0;

			sum = nempty = max = 0;
			memset((void *)res, 0, sizeof (res));
			for (i = 0; i < HOOK_NAME_HASH_SIZE; i++) {
				hook_p hook;
				unsigned int nb_elt;
				unsigned int j;

				LIST_GET_NB_ELT(hook,
						&per_ns(HOOK_NAME_hash,
							ctrl_vnb_ns)[i],
						namehooks, nb_elt);
				if (nb_elt) {
					sum += nb_elt;
					nempty++;
				}

				if (nb_elt > max)
					max = nb_elt;

				for (j = 0; j <= 3; j++) {
					if (nb_elt > cnt[j])
						res[j]++;
					else
						break;
				}
			}

			showhtables->namehooks.size = HOOK_NAME_HASH_SIZE;
			showhtables->namehooks.nb_elt = sum;
			showhtables->namehooks.more_than_10 = res[3];
			showhtables->namehooks.more_than_5 = res[2];
			showhtables->namehooks.more_than_2 = res[1];
			showhtables->namehooks.more_than_1 = res[0];
			showhtables->namehooks.max = max;
			showhtables->namehooks.non_empty_average =
				nempty ? (sum / nempty) : 0;

			*resp = rp;
			break;
		}

    case NGM_CLILISTNAMES:
    case NGM_CLILISTNODES:
        {
        const int unnamed = (msg->header.cmd == NGM_CLILISTNODES);
        struct namelist *nl;
        struct ng_mesg *rp;
        node_p node;
        unsigned int num = 0;
        unsigned int idNum;
        unsigned int id=0;
	void *msgdata;

        /* Get id number */
        if (msg->header.arglen != sizeof(u_int32_t)) {
            error = EINVAL;
            break;
        }
	msgdata = msg->data;
        idNum = *((u_int32_t *)msgdata);
        if (idNum>10000) {
            error = EINVAL;
            break;
        }

        /* Count number of nodes */
        LIST_FOREACH(node, &per_ns(nodelist, ctrl_vnb_ns), nodes) {
            if (unnamed || node->name != NULL)
                num++;
        }
        if (num>=(idNum+1)*100) num=100;
        else
        if (num>idNum*100) num=num-idNum*100;
        else {
            error = EFAULT;
            break;
        }
        /* Get response struct */
        if (resp == NULL) {
            error = EINVAL;
            break;
        }
        NG_MKRESPONSE(rp, msg, sizeof(*nl)
            + (num * sizeof(struct nodeinfo)), M_NOWAIT);
        if (rp == NULL) {
            error = ENOMEM;
            break;
        }
        nl = (struct namelist *) rp->data;

        /* Cycle through the linked list of nodes */
        nl->numnames = 0;
        LIST_FOREACH(node, &per_ns(nodelist, ctrl_vnb_ns), nodes) {
            struct nodeinfo *const np = &nl->nodeinfo[nl->numnames];

            if (nl->numnames >= num) {
                log(LOG_ERR, "%s: number of %s changed\n",
                    __FUNCTION__, "nodes");
                break;
            }
            if ((node->flags & NG_INVALID) != 0)
                continue;
            if (!unnamed && node->name == NULL)
                continue;
            id++;
            if (id >=(idNum+1)*100) break;
            else
            if (id<idNum*100) continue;

            if (node->name != NULL)
                strncpy(np->name, node->name, NG_NODELEN);
            strncpy(np->type, node->type->name, NG_TYPELEN);
            np->id = ng_node2ID(node);
            np->hooks = node->numhooks;
            np->vnb_ns = node->vnb_ns;
            nl->numnames++;
        }
        *resp = rp;
        break;
        }

	case NGM_NULL:
		break ;

	case NGM_TEXT_CONFIG:
	case NGM_TEXT_STATUS:
		/*
		 * This one is tricky as it passes the command down to the
		 * actual node, even though it is a generic type command.
		 * This means we must assume that the msg is already freed
		 * when control passes back to us.
		 */
		if (resp == NULL) {
			error = EINVAL;
			break;
		}
		if (here->type->rcvmsg != NULL)
			return((*here->type->rcvmsg)(here, msg, retaddr, resp, nl_msg));
		/* Fall through if rcvmsg not supported */
	default:
		VNB_TRAP();
		error = EINVAL;
	}
	FREE(msg, M_NETGRAPH);
	return (error);
}

/*
 * Send a data packet to a node. If the recipient has no
 * 'receive data' method, then silently discard the packet.
 */
int
ng_send_data(hook_p hook, struct mbuf *m, meta_p meta)
{
	int    (*rcvdata)(hook_p, struct mbuf *, meta_p);
	hook_p peer_hook;
	node_p peer_node;
	int    error = ENOTCONN;

	if ((hook == NULL) || (hook->flags & HK_INVALID))
		goto ng_free_and_return;
	peer_hook = hook->peer;
	if ((peer_hook == NULL) || (peer_hook->flags & HK_INVALID))
		goto ng_free_and_return;
	peer_node = peer_hook->node;
	if ((peer_node == NULL) || (peer_node->flags & NG_INVALID))
		goto ng_free_and_return;
	rcvdata = peer_node->type->rcvdata;
	if (rcvdata != NULL)
		return (*rcvdata)(peer_hook, m, meta);

ng_free_and_return:
	NG_FREE_DATA(m, meta);
	return (error);
}

/*
 * Copy a 'meta'.
 *
 * Returns new meta, or NULL if original meta is NULL or ENOMEM.
 */
meta_p
ng_copy_meta(meta_p meta)
{
	meta_p meta2;

	if (meta == NULL)
		return (NULL);
	MALLOC(meta2, meta_p, meta->used_len, M_NETGRAPH, M_NOWAIT);

	if (meta2 == NULL)
		return (NULL);
	meta2->allocated_len = meta->used_len;
	bcopy(meta, meta2, meta->used_len);
	return (meta2);
}

/*
 * Helper to find an option in a 'meta'.
 *
 * Returns the option or NULL if not found.
 */
struct meta_field_header *
ng_get_meta_option(meta_p meta, u_int32_t cookie, u_int16_t type)
{
	struct meta_field_header *option;
	int len;

	if (meta == NULL)
		return NULL;

	len = meta->used_len - sizeof(struct ng_meta);
	option = (struct meta_field_header *)meta->options;
	while (len >= (int)sizeof(struct meta_field_header)) {
		if (option->cookie == cookie &&
		    option->type == type)
			return option;
		len -= option->len;
		option = (struct meta_field_header *)(((char *)option) + option->len);
	};

	return NULL;
}

int
ng_queue_msg(node_p here, struct ng_mesg *msg, const char *address)
{
	node_p  node = NULL;
	char   *retaddr = NULL;
	int     error;

	/* Find the target node. */
	error = ng_path2node(here, address, &node, &retaddr);
	if (error) {
		FREE(msg, M_NETGRAPH);
		return (error);
	}
	if (node->flags & NG_INVALID) {
		FREE(msg, M_NETGRAPH);
	} else {
		CALL_MSG_HANDLER(error, node, msg,
				 retaddr, NULL, NULL);
	}
	if (retaddr)
		FREE(retaddr, M_NETGRAPH);

	return 0;
}

const struct ng_cmdlist *
ng_find_generic_node(const struct ng_mesg *msg)
{
	const struct ng_cmdlist *c;
	for (c = ng_generic_cmds; c->name != NULL; c++) {
		if (msg->header.typecookie == c->cookie
			    && msg->header.cmd == c->cmd)
			return c;
	}
	return c;
}

#if defined(__FastPath__)

static struct mbuf *ng_excep_realloc_headroom(struct mbuf *m, uint size)
{
	struct mbuf *n;
	uint init_headroom;

	/* m_headroom is sufficient, return m */
	if ( (init_headroom = s_headroom(m_first_seg(m))) >= size)
		return m;

	/* not enough headroom, prepend a new segment */
	n = m_alloc();
	if (n == NULL) {
		m_freem(m);
		return NULL;
	}
	if (m_cat(n, m)) {
		m_freem(m);
		m_freem(n);
		return NULL;
	}

	/* still not enough headroom, drop the new mbuf */
	if ( (init_headroom + s_headroom(m_first_seg(n))) < size) {
		m_freem(n);
		return NULL;
	}

	return n;
}

int
ng_send_exception(const node_p node, const hook_p hook,
                  int flags, int node_flags, struct mbuf *m, meta_p meta)
{
	/* send exception from FP VNB to kernel VNB */
	int error = 0;
	struct fpvnbtovnbhdr * hdr = NULL;
	char *hookname;
#ifdef CONFIG_MCORE_MULTIBLADE
	char *nodename;
#endif
	unsigned int hookname_len;	/* len of the hook name to send the exception to */
	unsigned int nodename_len;	/* len of the node name to send the exception to */
	unsigned int hdr_len;		/* len of the complete structure, with names */

#if VNB_DEBUG
	log(LOG_DEBUG, "%s: entering\n", __FUNCTION__);
#endif

	/* only DATA or EXCEPTION transfers are currently supported */
	if ((flags != VNB2VNB_DATA) && (flags != VNB2VNB_EXC)) {
		NG_FREE_DATA(m, meta);
		return EINVAL;
	}

	/*
	 * preliminary checks :
	 * the FP graph is similar to the kernel graph
	 */
	if (node == NULL ||
#ifdef CONFIG_MCORE_MULTIBLADE
	    ((nodename = node->name) == NULL) ||
#endif
	    hook == NULL ||
	    ((hookname = hook->name) == NULL)) {
		NG_FREE_DATA(m, meta);
		return EINVAL;
	}
	hookname_len = strnlen(hookname, NG_HOOKSIZ) +1;
#ifdef CONFIG_MCORE_MULTIBLADE
	nodename_len = strnlen(nodename, NG_NODESIZ) +1;
#else
	nodename_len = 0;
#endif

	/* compute variable length for the vnbtovnb struct */
	hdr_len = sizeof(struct fpvnbtovnbhdr) +
					 hookname_len + nodename_len;
	/* ensure enough headroom for fpvnbtovnbhdr and exception hdr */
	m = ng_excep_realloc_headroom(m,
	      hdr_len + FP_ETHER_HDR_LEN + FPTUN_HLEN);
	if (m == NULL) {
#if VNB_DEBUG
		log(LOG_ERR, "%s: cannot realloc enough headroom for exception\n",
			__FUNCTION__);
#endif
		/* m was already freed */
		return ENOMEM;
	}

	/* prepend with fpvnbtovnbhdr */
	hdr = (struct fpvnbtovnbhdr *)m_prepend(m, hdr_len);
	if (unlikely(hdr == NULL)) {
		log(LOG_WARNING, "%s: could not prepend fpvnbtovnbhdr\n",
			__FUNCTION__);
		NG_FREE_DATA(m, meta);
		return ECANCELED;
	}
	memset((void *)hdr, 0, hdr_len);
	hdr->hookname_len = hookname_len;
	memcpy((void *)&hdr->names[0], hookname, hookname_len);
	/* In multiblade, we use the nodename, which is unique in the
	 * whole system, else node ID is enough (unique between CP and FP).
	 */
	hdr->nodename_len = nodename_len;
#ifdef CONFIG_MCORE_MULTIBLADE
	memcpy((void *)&hdr->names[hookname_len], nodename, nodename_len);
#else
	hdr->nodeid = htonl(node->ID);
#endif
	hdr->flags      = htons(flags);
	hdr->node_flags = htons(node_flags);

	/* change the exception type, the frame is ready to be sent */
	m_priv(m)->exc_type = FPTUN_VNB2VNB_FP_TO_LINUX_EXCEPT;
	error = fp_prepare_exception(m, FPTUN_EXC_VNB_TO_VNB);

	if (error == FP_NONE) {
#if VNB_DEBUG
		log(LOG_DEBUG, "%s: sending exception\n",
			__FUNCTION__);
#endif
		fp_sp_exception(m);
	} else  {
		if (error == FP_DROP)
			NG_FREE_M(m);
#if VNB_DEBUG
		log(LOG_ERR, "%s: NOT sending exception (error: %d)\n",
			__FUNCTION__, error);
#endif
	}

	NG_FREE_META(meta);
	return error == FP_NONE ? 0 : ECANCELED;
}
#endif /*__FastPath__*/

#if defined(__LinuxKernelVNB__) && defined(CONFIG_VNB_EXCEPTION_HANDLER)
int ng_recv_exception(struct mbuf *m)
{
	int error = 0;
	struct fpvnbtovnbhdr * hdr = NULL;
	char * hook_name;
	char * node_name = NULL;
	ng_ID_t nodeid = 0;
	int flags;
	node_p dest_node;
	hook_p dest_hook;
	int    (*rcvdata)(hook_p, struct mbuf *, meta_p);
	int    (*rcvexception)(hook_p, struct mbuf *, meta_p);
	unsigned int hookname_len;	/* len of the hook name to send the exception to */
	unsigned int nodename_len;	/* len of the node name to send the exception to */
	unsigned int hdr_len;		/* len of the complete structure, with names */

#if VNB_DEBUG
	log(LOG_DEBUG, "%s: entering\n", __FUNCTION__);
#endif

	/* remove VNB exception header */
	if (!pskb_may_pull(m, sizeof(struct fpvnbtovnbhdr))) {
		log(LOG_ERR, "%s: Unable to pull VNB2VNB header\n",
			   __FUNCTION__);
		m_freem(m);
		error = EINVAL;
		goto error;
	}
	hdr = (struct fpvnbtovnbhdr *)skb_network_header(m);
	hookname_len = hdr->hookname_len;
	nodename_len = hdr->nodename_len;
	if ( (hookname_len > (NG_HOOKSIZ+1)) ||
	     (nodename_len > (NG_NODESIZ+1)) ) {
		log(LOG_ERR, "%s: Bad VNB2VNB exception format\n",
			   __FUNCTION__);
		m_freem(m);
		error = EINVAL;
		goto error;
	}

	hdr_len = sizeof(struct fpvnbtovnbhdr) +
					 hookname_len + nodename_len;
	if (!pskb_may_pull(m, hdr_len)) {
		log(LOG_ERR, "%s: Unable to pull the full VNB2VNB header\n",
			   __FUNCTION__);
		m_freem(m);
		error = EINVAL;
		goto error;
	}

	/* extract dest_hook_name, flags */
	hook_name  = (char *)&hdr->names[0];
	hook_name[hookname_len-1] = '\0';
	flags      = htons(hdr->flags);

	VNB_ENTER();
	/* find dest_node: in monoblade mode, we use the node ID and
	 * in multiblade node the node name.
	 */
	if (nodename_len != 0) {
		node_name = (char *)&hdr->names[hookname_len];
		node_name[nodename_len-1] = '\0';
		dest_node = ng_findname(NULL, node_name);
	} else {
		nodeid    = ntohl(hdr->nodeid);
		dest_node = ng_ID2node(nodeid);
	}

	if ( (dest_node == NULL)  || (dest_node->flags & NG_INVALID)) {
		if (net_ratelimit()) {
			log(LOG_INFO, "%s: Invalid dest node", __FUNCTION__);
			if (nodename_len != 0)
				log(LOG_INFO, ": %s", node_name);
			else
				log(LOG_INFO, ": %x", nodeid);
			log(LOG_INFO, "\n");
		}
		m_freem(m);
		error = EINVAL;
		vnb_atomic_inc(&gNumDstNodeErrs);
		goto error;
	}
	/* find dest_hook */
	dest_hook=ng_findhook(dest_node, hook_name);
	if ( (dest_hook == NULL) || (dest_hook->flags & HK_INVALID) ) {
		if (net_ratelimit())
			log(LOG_INFO, "%s: Invalid dest hook: %s\n", __FUNCTION__, hook_name);
		m_freem(m);
		error = EINVAL;
		vnb_atomic_inc(&gNumDstHookErrs);
		goto error;
	}
	if (flags == VNB2VNB_DATA) {
		/* remove exception header, always successful due to previous
		 * call to pskb_may_pull() */
		__skb_pull(m, hdr_len);

		/* use per-node recv data function */
		rcvdata = dest_node->type->rcvdata;
		if (rcvdata == NULL)
			/* use per-hook recv data function */
			rcvdata = dest_hook->hook_rcvdata;
		if (rcvdata != NULL) {
#if VNB_DEBUG
			log(LOG_DEBUG, "%s: sending to %s: %s\n", __FUNCTION__,
				  dest_node->name, dest_hook->name);
#endif
			error = (*rcvdata)(dest_hook, m, NULL);
		} else {
			log(LOG_ERR, "%s: NULL recv data for %s\n", __FUNCTION__,
				dest_hook->name);
			m_freem(m);
			error = EINVAL;
		}
	} else if (flags == VNB2VNB_EXC) {
		rcvexception = dest_node->type->rcvexception;
		if (rcvexception != NULL) {
#if VNB_DEBUG
			log(LOG_DEBUG, "%s: sending to %s\n", __FUNCTION__,
				  dest_node->name);
#endif
			error = (*rcvexception)(dest_hook, m, NULL);
		} else{
			log(LOG_ERR, "%s: no handler for exceptions in %s\n",
				__FUNCTION__, dest_node->name);
			m_freem(m);
			error = EINVAL;
		}
	} else {
		/* only DATA or EXCEPTION transfers are currently supported */
		m_freem(m);
		error = EINVAL;
		if (net_ratelimit())
			log(LOG_ERR, "%s: unknown exception type: %d\n",
				__FUNCTION__, flags);
	}

error:
	VNB_EXIT();
	return error;
}
EXPORT_SYMBOL(ng_recv_exception);
#endif
#ifdef __LinuxKernelVNB__
#ifdef CONFIG_PROC_FS
#include <netgraph/ng_proc.h>
#endif

static int __init vnb_init(void)
{
	int error = EINVAL;

	printk(KERN_INFO "VNB: Linux Netgraph 2.0\n");

	if ((error = ng_base_init()) != 0)
		goto error;

	/*
	 *	Create all the /proc entries.
	 */
#ifdef CONFIG_PROC_FS
	if ((error = vnb_init_proc()) != 0)
		goto error;
	/* later
	proc_net_create ("raw", 0, raw_get_info); */
#endif		/* CONFIG_PROC_FS */

	return 0;
error:
	printk(KERN_INFO "VNB: init failed (%d)\n", error);
	return -error;
}

static void vnb_exit(void)
{
	printk(KERN_INFO "VNB: Unloading Linux Netgraph 2.0\n");

	ng_exit();

#ifdef CONFIG_PROC_FS
	vnb_remove_proc();
#endif
}

EXPORT_SYMBOL(ng_free);
EXPORT_SYMBOL(ng_cutlinks);
EXPORT_SYMBOL(ng_unname);
EXPORT_SYMBOL(ng_malloc);
EXPORT_SYMBOL(ng_make_node);
EXPORT_SYMBOL(ng_make_node_common);
EXPORT_SYMBOL(ng_newtype);
EXPORT_SYMBOL(ng_type_unref);
EXPORT_SYMBOL(ng_unref);
EXPORT_SYMBOL(ng_send_data);
EXPORT_SYMBOL(ng_make_node_common_and_priv);
EXPORT_SYMBOL(ng_name_node);
EXPORT_SYMBOL(ng_rehash_node);
EXPORT_SYMBOL(ng_rmnode);
EXPORT_SYMBOL(ng_ID2node);
EXPORT_SYMBOL(ng_dtor_alloc);
EXPORT_SYMBOL(ng_dtor_free);
EXPORT_SYMBOL(vnb_core_state);
EXPORT_SYMBOL(ng_parse_bytearray_type);
EXPORT_SYMBOL(ng_parse_get_token);
EXPORT_SYMBOL(vnb_core_nb_instances);
EXPORT_SYMBOL(ng_queue_msg);
EXPORT_SYMBOL(ng_dtor);
EXPORT_SYMBOL(ng_findhook);
EXPORT_SYMBOL(ng_destroy_hook);
EXPORT_SYMBOL(ng_copy_meta);
EXPORT_SYMBOL(ng_get_meta_option);
EXPORT_SYMBOL(ng_node2ID);
EXPORT_SYMBOL(ng_path2node);
EXPORT_SYMBOL(ng_parse_array_type);
EXPORT_SYMBOL(ng_send_msg);
EXPORT_SYMBOL(ng_findname);
EXPORT_SYMBOL(ng_findtype);
EXPORT_SYMBOL(ng_set_node_private);
EXPORT_SYMBOL(ng_bypass);
EXPORT_SYMBOL(ng_path_parse);
EXPORT_SYMBOL(ng_find_generic_node);
EXPORT_SYMBOL(ng_con_nodes);

module_init(vnb_init);
module_exit(vnb_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB core module");
MODULE_LICENSE("6WIND");
#endif
