/*
 * netgraph.h
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
 * $FreeBSD: src/sys/netgraph/netgraph.h,v 1.6.2.7 2002/04/14 23:31:08 julian Exp $
 * $Whistle: netgraph.h,v 1.29 1999/11/01 07:56:13 julian Exp $
 */
/*
 * Copyright 2003-2013 6WIND S.A.
 */
#ifndef _NETGRAPH_NETGRAPH_H_
#define _NETGRAPH_NETGRAPH_H_ 1

#include "vnb_config.h"

#if defined(__FastPath__)
#include "fp-netgraph.h"
#elif defined(__LinuxKernelVNB__)
#include "vnblinux.h"
#endif

#include <netgraph/ng_message.h>
#include <netgraph/queue.h>

/* Use likely unused PF_ROSE as an alias for NETGRAPH */
#ifndef PF_NETGRAPH
#define PF_NETGRAPH PF_ROSE
#endif

#ifndef AF_NETGRAPH
#define AF_NETGRAPH     PF_NETGRAPH
#endif

#ifndef SOL_NETGRAPH
#define SOL_NETGRAPH SOL_ROSE
#endif

/* Use likely unused PF_AX25 as an alias for LINK */
#ifndef PF_LINK
#define PF_LINK PF_AX25
#endif

#ifndef AF_LINK
#define AF_LINK PF_LINK
#endif

#if !defined(_KERNEL) && !defined(__KERNEL__)
#error "This file should not be included in user level programs"
#endif

#ifndef VNB_MAX_NS
/* only tested with 1 on control plane */
#define VNB_MAX_NS 1
#endif

VNB_DECLARE_SHARED(uint16_t, ctrl_vnb_ns);

VNB_DECLARE_SHARED(u_int32_t, gNumNodes_ns[VNB_MAX_NS]);

/*
 * ng_recv_exception() statistics for invalid hook/node
 */
#if defined(__LinuxKernelVNB__) && defined(CONFIG_VNB_EXCEPTION_HANDLER)
VNB_DECLARE_SHARED(vnb_atomic_t, gNumDstHookErrs);
VNB_DECLARE_SHARED(vnb_atomic_t, gNumDstNodeErrs);
#endif

#ifndef VNB_DEBUG
#if defined(__LinuxKernelVNB__)
#error VNB_DEBUG should have been defined by vnblinux.h.
#elif defined(__FastPath__)
#error VNB_DEBUG should have been defined by fp-netgraph.h.
#else
#error VNB_DEBUG is undefined.
#endif
#endif

#if VNB_DEBUG
VNB_DECLARE_SHARED(vnb_atomic_t, gNumPtrs);
VNB_DECLARE_SHARED(vnb_atomic_t, gFreeNumPtrs);
#endif

#define NG_ABI_VERSION NG_VERSION

/*
 * Structure of a hook
 */
struct ng_meta;

struct ng_hook {
	struct	ng_hook *peer;	/* the other end of this link */
	int (*peer_rcvdata)(struct ng_hook *, struct mbuf *, struct ng_meta *);
	int (*hook_rcvdata)(struct ng_hook *, struct mbuf *, struct ng_meta *);
	void   *private;	/* node dependant ID for this hook */
#ifdef NG_NODE_CACHE
	void   *node_cache;     /* node dependant cache info for this hook */
#endif
	void   *node_private;   /* pointer to node private structure */
	int	flags;		/* info about this hook/link */
	int	refs;		/* dont actually free this till 0 */
	char   *name;		/* what this node knows this link as */
	struct	ng_node *node;	/* The node this hook is attached to */
	LIST_ENTRY(ng_hook) hooks;	/* linked list of all hooks on node */
	LIST_ENTRY(ng_hook) namehooks; /* linked list of hooks for name hash */
};
typedef struct ng_hook *hook_p;

/* Flags for a hook */
#define HK_INVALID		0x0001	/* don't trust it! */
/* used only in ng_pppoe */
#define HK_EXCEP		0x0002	/* treat IPCP and LCP as exceptions for this hook */

void ng_unref_hook(hook_p hook); /* don't move this */
#define NG_HOOK_REF(hook)	atomic_add_int(&(hook)->refs, 1)
#define NG_HOOK_NAME(hook)	((hook)->name)
#define NG_HOOK_UNREF(hook)	ng_unref_hook(hook)
#define NG_HOOK_SET_PRIVATE(hook, val)	do {(hook)->private = val;} while (0)
#define NG_HOOK_SET_RCVMSG(hook, val)	do {(hook)->rcvmsg = val;} while (0)
#define NG_HOOK_SET_RCVDATA(hook, val)	(void)((hook)->hook_rcvdata = (val))
#define NG_HOOK_PRIVATE(hook)	((hook)->private)
#ifdef NG_NODE_CACHE
#define NG_HOOK_SET_NODE_CACHE(hook, val)	do {(hook)->node_cache = val;} while (0)
#define NG_HOOK_NODE_CACHE(hook)	        ((hook)->node_cache)
#endif
#define NG_HOOK_NOT_VALID(hook)	((hook)->flags & HK_INVALID)
#define NG_HOOK_IS_VALID(hook)	(!((hook)->flags & HK_INVALID))
#define NG_HOOK_NODE(hook)	((hook)->node) /* only rvalue! */
#define NG_HOOK_PEER(hook)	((hook)->peer) /* only rvalue! */

/* Some shortcuts */
#define NG_PEER_NODE(hook)	NG_HOOK_NODE(NG_HOOK_PEER(hook))
#define NG_PEER_HOOK_NAME(hook)	NG_HOOK_NAME(NG_HOOK_PEER(hook))
#define NG_PEER_NODE_NAME(hook)	NG_NODE_NAME(NG_PEER_NODE(hook))

/*
 * Structure of a node
 */
struct ng_node {
	char   *name;		/* optional globally unique name */
	struct	ng_type *type;	/* the installed 'type' */
	int	flags;		/* see below for bit definitions */
	vnb_atomic_t	refs;   /* number of references to this node */
	u_int	numhooks;	/* number of hooks */
	int	colour;		/* for graph colouring algorithms */
	void   *private;	/* node type dependant node ID */
	ng_ID_t		ID;	/* Unique per node */
	uint16_t     vnb_ns;
	LIST_HEAD(hooks, ng_hook) hooks;	/* linked list of node hooks */
	LIST_ENTRY(ng_node)	  nodes;	/* linked list of all nodes for linear search */
	LIST_ENTRY(ng_node)	  namenodes;	/* linked list of all nodes for name hash */
	LIST_ENTRY(ng_node)	  idnodes;	/* ID hash collision list */
};
typedef struct ng_node *node_p;

/* Flags for a node */
#define NG_INVALID	0x001	/* free when all sleepers and refs go to 0 */
#define NG_BUSY		0x002	/* callers should sleep or wait */
#define NG_TOUCHED	0x004	/* to avoid cycles when 'flooding' */
#define NGF_TYPE1	0x10000000	/* reserved for type specific storage */
#define NGF_TYPE2	0x20000000	/* reserved for type specific storage */
#define NGF_TYPE3	0x40000000	/* reserved for type specific storage */
#define NGF_TYPE4	0x80000000	/* reserved for type specific storage */

void	ng_unref_node(node_p node); /* don't move this */
#define NG_NODE_NAME(node)	((node)->name + 0)
#define NG_NODE_HAS_NAME(node)	((node)->name[0] + 0)
#define NG_NODE_ID(node)	((node)->ID + 0)
#define NG_NODE_REF(node)	vnb_atomic_inc(&(node)->refs)
#define NG_NODE_UNREF(node)	ng_unref(node)
#define NG_NODE_SET_PRIVATE(node, val)	do {(node)->private = val;} while (0)
#define NG_NODE_PRIVATE(node)	((node)->private)
#define NG_NODE_IS_VALID(node)	(!((node)->flags & NG_INVALID))
#define NG_NODE_NOT_VALID(node)	((node)->flags & NG_INVALID)
#define NG_NODE_NUMHOOKS(node)	((node)->numhooks + 0) /* rvalue */

struct ng_object {
	SLIST_ENTRY(ng_object) next;
} __attribute__((aligned(8)));
typedef struct ng_object *obj_p;

typedef int ng_fn_eachhook(hook_p hook, void *arg);

/*
 * The structure that holds meta_data about a data packet (e.g. priority)
 * Nodes might add or subtract options as needed if there is room.
 * They might reallocate the struct to make more room if they need to.
 * Meta-data is still experimental.
 */

/* To zero out an option 'in place' set it's cookie to this */
#define NGM_INVALID_COOKIE	865455152

/* This part of the metadata is always present if the pointer is non NULL */
struct ng_meta {
	char	priority;	/* -ve is less priority,  0 is default */
	char	discardability; /* higher is less valuable.. discard first */
	u_short allocated_len;	/* amount malloc'd */
	u_short used_len;	/* sum of all fields, options etc. */
	u_short flags;		/* see below.. generic flags */
	struct meta_field_header options[];	/* add as (if) needed */
};
typedef struct ng_meta *meta_p;

/* Flags for meta-data */
#define NGMF_TEST	0x01	/* discard at the last moment before sending */
#define NGMF_TRACE	0x02	/* trace when handing this data to a node */

/* node method definitions */
typedef	int	ng_constructor_t(node_p *node, ng_ID_t nodeid);
typedef	int	ng_rcvmsg_t(node_p node, struct ng_mesg *msg,
			const char *retaddr, struct ng_mesg **resp,
			struct ng_mesg **nl_msg);
typedef	int	ng_shutdown_t(node_p node);
typedef	int	ng_newhook_t(node_p node, hook_p hook, const char *name);
typedef	hook_p	ng_findhook_t(node_p node, const char *name);
typedef	int	ng_connect_t(hook_p hook);
typedef	int	ng_rcvdata_t(hook_p hook, struct mbuf *m, meta_p meta);
typedef	int	ng_disconnect_t(hook_p hook);
typedef	int	ng_rcvexception_t(hook_p hook, struct mbuf *m, meta_p meta);
typedef struct ng_nl_nodepriv *ng_dumpnode_t(node_p node);
typedef void    ng_restorenode_t(struct ng_nl_nodepriv * nlnodepriv, node_p node);
typedef struct ng_nl_hookpriv *ng_dumphook_t(node_p node, hook_p hook);
typedef void    ng_restorehook_t(struct ng_nl_hookpriv * nlhookpriv, node_p node, hook_p hook);

/*
 * Command list -- each node type specifies the command that it knows
 * how to convert between ASCII and binary using an array of these.
 * The last element in the array must be a terminator with cookie=0.
 */

struct ng_cmdlist {
	u_int32_t			cookie;		/* command typecookie */
	u_int				cmd;		/* command number */
	const char			*name;		/* command name */
	const struct ng_parse_type	*mesgType;	/* args if !NGF_RESP */
	const struct ng_parse_type	*respType;	/* args if NGF_RESP */
};

#if defined(__LinuxKernelVNB__)
/*
 * NGM_RCVMSG_NO_NETLINK_ADV can be used as a successful return value for
 * rcvmsg() instead of 0. It prevents ng_socket from advertising that message
 * to netlink.
 */
#define NGM_NO_NETLINK_ADV -1
#endif

/*
 * Structure of a node type
 */
struct ng_type {

	u_int32_t	version; 	/* must equal NG_VERSION */
	const char	*name;		/* Unique type name */
	void *	mod_event; 	/* not used */
	ng_constructor_t *constructor;	/* Node constructor */
	ng_rcvmsg_t	*rcvmsg;	/* control messages come here */
	ng_shutdown_t	*shutdown;	/* reset, and free resources */
	ng_newhook_t	*newhook;	/* first notification of new hook */
	ng_findhook_t	*findhook;	/* only if you have lots of hooks */
	ng_connect_t	*connect;	/* final notification of new hook */
	ng_connect_t	*afterconnect;	/* final notification of new hook */
	ng_rcvdata_t	*rcvdata;	/* date comes here */
	ng_rcvdata_t	*rcvdataq;	/* or here if being queued */
	ng_disconnect_t	*disconnect;	/* notify on disconnect */
	ng_rcvexception_t *rcvexception; /* exceptions come here */
	ng_dumpnode_t  *dumpnode;	/* dump node private data */
	ng_restorenode_t  *restorenode;
	ng_dumphook_t  *dumphook;	/* dump hook private data */
	ng_restorehook_t  *restorehook;

	const struct	ng_cmdlist *cmdlist;	/* commands we can convert */

	/* R/W data private to the base netgraph code DON'T TOUCH! */
	LIST_ENTRY(ng_type) types;		/* linked list of all types */
	vnb_atomic_t	    refs;		/* number of instances */
#if defined(__LinuxKernelVNB__)
	struct module	    *module;		/* module creating the type */
#endif
};

#define NG_TYPE_REF(type)	vnb_atomic_inc(&(type)->refs)
#define NG_TYPE_UNREF(type)	ng_type_unref(type)

/* Send data packet with meta-data */
#define NG_SEND_DATA(error, hook, m, a)					\
	do {								\
		(error) = ng_send_data_fast((hook), (m), (a));		\
		(m) = NULL;						\
		(a) = NULL;						\
	} while (0)

#define NG_SEND_DATA_ONLY(error, hook, m)				\
	do {								\
		(error) = ng_send_data_fast((hook), (m), NULL);		\
		(m) = NULL;						\
	} while (0)

#define NG_RESPOND_MSG(error, here, retaddr, resp, rptr)		\
	do {								\
		if (rptr) {						\
			*rptr = resp;					\
		} else if (resp) {					\
			if (retaddr) {					\
				error = ng_queue_msg(here, resp, retaddr); \
			} else {					\
				FREE(resp, M_NETGRAPH);			\
			}						\
		}							\
	} while (0)

#define NG_FREE_MSG(msg)						\
	do {								\
		if ((msg)) {						\
			FREE((msg), M_NETGRAPH);			\
			(msg) = NULL;					\
		}	 						\
	} while (0)

#define NG_FREE_META(a)							\
	do {								\
		if ((a)) {						\
			FREE((a), M_NETGRAPH);				\
			(a) = NULL;					\
		}							\
	} while (0)

#define NG_FREE_M(m)							\
	do {								\
		if ((m)) {						\
			m_freem((m));					\
			(m) = NULL;					\
		}							\
	} while (0)

/* Free any data packet and/or meta-data */
#define NG_FREE_DATA(m, a)						\
	do {								\
		NG_FREE_M((m));						\
		NG_FREE_META((a));					\
	} while (0)

/*
 * Use the NETGRAPH_INIT() macro to link a node type into the
 * netgraph system. This works for types compiled into the kernel
 * as well as KLD modules. The first argument should be the type
 * name (eg, echo) and the second a pointer to the type struct.
 *
 * If a different link time is desired, e.g., a device driver that
 * needs to install its netgraph type before probing, use the
 * NETGRAPH_INIT_ORDERED() macro instead. Deivce drivers probably
 * want to use SI_SUB_DRIVERS instead of SI_SUB_PSEUDO.
 */

#define NETGRAPH_INIT_ORDERED(typename, typestructp, sub, order)	\
static moduledata_t ng_##typename##_mod = {				\
	"ng_" #typename,						\
	ng_mod_event,							\
	(typestructp)							\
};									\
DECLARE_MODULE(ng_##typename, ng_##typename##_mod, sub, order)

int	ng_send_data(hook_p hook, struct mbuf *m, meta_p meta);
/* To debug peer_rcvdata cache: when turned on,
 * it tests if this pointer is coherent and
 * and any error is logged.
 * In any case we call regular ng_send_data().
 */
//#define NG_PEER_RCVDATA_DEBUG 1
static inline int ng_send_data_fast(hook_p hook, struct mbuf *m, meta_p meta)
{
	int (*peer_rcvdata)(hook_p, struct mbuf *, meta_p) = NULL;
	hook_p peer_hook;
#ifdef NG_PEER_RCVDATA_DEBUG
	int error = 1;
	node_p peer_node;
	const char *hook_name;

	if (hook) {
		peer_rcvdata = hook->peer_rcvdata;
		if (peer_rcvdata) {
			peer_hook = hook->peer;
			if (hook->flags & HK_INVALID)
				log(LOG_ERR, "hook->flags & HK_INVALID\n");
			else if (peer_hook == NULL)
				log(LOG_ERR, "hook->peer == NULL\n");
			hook_name = hook->name;
			if (hook_name == NULL)
				log(LOG_ERR, "hook->name == NULL\n");
			peer_node = peer_hook->node;
			if (peer_node == NULL)
				log(LOG_ERR, "hook->peer->node == NULL %s\n",
				    (hook_name ? hook_name : "<NULL>"));
			else if (peer_node->flags & NG_INVALID)
				log(LOG_ERR, "hook->peer->node->flags & NG_INVALID\n");
			else if (peer_node->type->rcvdata == NULL)
				log(LOG_ERR, "hook->peer->node->type->rcvdata == NULL\n");
			else if (peer_node->type->rcvdata != peer_rcvdata)
				log(LOG_ERR, "hook->peer->node->type->rcvdata != hook->peer_rcvdata\n");
			else
				error = 0;
		} else {
			if ((hook->flags & HK_INVALID)==0 &&
			    (hook->peer->node->flags & NG_INVALID) == 0 &&
			    hook->peer->node->type->rcvdata != NULL) {
				log(LOG_ERR, "hook->peer->node->type->rcvdata != NULL\n");
			}
			else
				error = 0;


		}
	}
#endif

	if (likely(hook && !(hook->flags & HK_INVALID) &&
		   ((peer_rcvdata = hook->peer_rcvdata) != NULL))) {
#ifdef NG_PEER_RCVDATA_DEBUG
		if (error)
			printf("Arg, error using peer\n");
#else
		peer_hook = hook->peer;
		if (peer_hook == NULL) {
			NG_FREE_DATA(m, meta);
			return ENOTCONN;
		}
		return (*peer_rcvdata)(peer_hook, m, meta);
#endif
	}
	return ng_send_data(hook, m, meta);
}

#if defined(__LinuxKernelVNB__)

#define NETGRAPH_INIT(tn, tp)						\
int ng_##tn##_init(void); 						\
int ng_##tn##_init(void) { 							\
        int error; 							\
        struct ng_type *type = (tp);					\
        type->module = THIS_MODULE;					\
        printk(KERN_INFO "VNB: Loading ng_" #tn "\n");			\
        if ((error = ng_newtype(type)) != 0) {				\
                printk(KERN_INFO "VNB: ng_" #tn "_init failed (%d)\n",error);	\
                return -EINVAL;						\
        }								\
        return(0);							\
}

#define NETGRAPH_EXIT(tn, tp)						\
void ng_##tn##_exit(void);						\
void ng_##tn##_exit(void) {							\
        struct ng_type *type = (tp);					\
        printk(KERN_INFO "VNB: Unloading ng_" #tn "\n");		\
        NG_TYPE_UNREF(type);						\
        if (vnb_atomic_read(&(type->refs)))				\
                VNB_TRAP("VNB: Remaining %d reference on ng_" #tn "\n",	\
                         vnb_atomic_read(&(type->refs)));		\
        return;								\
}
#else
#define NETGRAPH_INIT(tn, tp)						\
int ng_##tn##_init(void);						\
int ng_##tn##_init(void) { 						\
        int error; 							\
        struct ng_type *type = (tp);					\
        log(LOG_DEBUG, "VNB: Loading ng_" #tn "\n");            	\
        if ((error = ng_newtype(type)) != 0) {				\
                log(LOG_DEBUG, "VNB: ng_" #tn "_init failed (%d)\n",error);	\
                return EINVAL;						\
        }								\
        return(0);							\
}

#define NETGRAPH_EXIT(tn, tp)						\
void ng_##tn##_exit(void);						\
void ng_##tn##_exit(void) {							\
        struct ng_type *type = (tp);					\
        log(LOG_DEBUG, "VNB: Unloading ng_" #tn "\n");			\
        NG_TYPE_UNREF(type);						\
        if (vnb_atomic_read(&(type->refs)))				\
                log(LOG_ERR, "VNB: Remaining %d references on ng_"	\
                    #tn "\n", vnb_atomic_read(&(type->refs)));		\
        return;								\
}
#endif

/* declare the base of the netgraph sysctl hierarchy */
/* but only if this file cares about sysctls */
#ifdef	SYSCTL_DECL
SYSCTL_DECL(_net_graph);
#endif

int	ng_bypass(hook_p hook1, hook_p hook2);
void	ng_cutlinks(node_p node);
int	ng_con_nodes(node_p node,
	     const char *name, node_p node2, const char *name2);
meta_p	ng_copy_meta(meta_p meta);
struct meta_field_header *ng_get_meta_option(meta_p meta, u_int32_t cookie,
					     u_int16_t type);
void	ng_destroy_hook(hook_p hook);
hook_p	ng_findhook(node_p node, const char *name);
hook_p	ng_findhook_inval(node_p node, const char *name);
node_p	ng_findname(node_p node, const char *name);
void    ng_set_node_private(node_p node, void *priv);
struct	ng_type *ng_findtype(const char *type);
int	ng_make_node(const char *type, node_p *nodepp, ng_ID_t nodeid);
int	ng_make_node_common(struct ng_type *typep, node_p *nodep, ng_ID_t nodeid);
int     ng_make_node_common_and_priv(struct ng_type *type, node_p *nodepp,
				     void *privpp, unsigned priv_size, ng_ID_t nodeid);
int	ng_mkpeer(node_p node, const char *name, const char *name2, char *type, ng_ID_t *nodeid);
int	ng_name_node(node_p node, const char *name);
int	ng_newtype(struct ng_type *tp);
int	ng_type_unref(struct ng_type *tp);
void 	ng_rehash_node(node_p node);

int	ng_add_hook(node_p node, const char *name, hook_p *hookp);
int	ng_connect(hook_p hook1, hook_p hook2);

ng_ID_t ng_node2ID(node_p node);
node_p ng_ID2node(ng_ID_t ID);
int	ng_path2node(node_p here, const char *path, node_p *dest, char **rtnp);
int	ng_path_parse(char *addr, char **node, char **path, char **hook);
int	ng_queue_data(hook_p hook, struct mbuf *m, meta_p meta);
int	ng_queue_msg(node_p here, struct ng_mesg *msg, const char *address);
void	ng_release_node(node_p node);
void	ng_rmnode(node_p node);
int	ng_send_data(hook_p hook, struct mbuf *m, meta_p meta);
int	ng_send_msg(node_p here, struct ng_mesg *msg,
	    const char *address, struct ng_mesg **resp, struct ng_mesg **nl_msg);
#if VNB_WITH_MSG_POST
void	ng_post_msg(node_p node, struct ng_mesg *msg);
#endif
void	ng_unname(node_p node);
int	ng_unref(node_p node);
int	ng_wait_node(node_p node, char *msg);
const struct ng_cmdlist* ng_find_generic_node(const struct ng_mesg *msg);
void *ng_malloc(unsigned int length, int wait);
void ng_free(void *ptr);
void *ng_dtor_alloc(void);
void ng_dtor_free(void *ptr);
void ng_dtor(void *ptr, void (*dtor)(void *data), void *data);
#ifdef __LinuxKernelVNB__
#ifdef CONFIG_VNB_NETLINK_NOTIFY
extern spinlock_t vnb_seqnum_lock;
extern uint32_t vnb_seqnum;
#endif
void vnb_netlink_notify(const struct ng_mesg *msg, const struct ng_cmdlist *c,
			const char *path, int pathlen);
void vnb_socket_netlink_notify(u_int32_t nodeid, char *name, u_int32_t cmd);
#endif

/* additional socket level control messages */
/* XXX bsd: sys/socket.h, linux: linux/socket.h */
#define SCM_INADDR	0x06
#define SCM_IN6ADDR	0x07

struct ng_callout {
	struct callout callout;
	void *arg;
	void (*handler) (void *);
};

static inline void ng_callout_handler(void *arg)
{
	struct ng_callout *ng_callout = (struct ng_callout *)arg;

	VNB_ENTER();
	ng_callout->handler(ng_callout->arg);
	VNB_EXIT();
}
static inline int ng_callout_init(struct ng_callout *ng_callout)
{
	ng_callout->arg = NULL;
	ng_callout->handler = NULL;
	return (callout_init(&ng_callout->callout));
}

static inline int ng_callout_reset(struct ng_callout* ng_callout, unsigned int sec,
				   void (*handler)(void *), void *data)
{
	ng_callout->arg = data;
	ng_callout->handler = handler;

	callout_reset(&ng_callout->callout, sec,
		      ng_callout_handler, ng_callout);
	return 0;
}

static inline void ng_callout_stop_sync(struct ng_callout *ng_callout)
{
	callout_stop_sync(&ng_callout->callout);
}

static inline void ng_callout_stop(struct ng_callout *ng_callout)
{
	callout_stop(&ng_callout->callout);
}

static inline int ng_callout_pending(struct ng_callout *ng_callout)
{
	return callout_pending(&ng_callout->callout);
}

void bqsort(void *base, int nmemb, int size,
	    int (*compar)(const void *, const void *));
void bqsort_r(void *base, int nmemb, int size, void *arg,
	      int (*compar)(void *, const void *, const void *));

/* The exception receiver handles the packet as normal data */
#define VNB2VNB_DATA 0x1
/* The exception receiver handles the packet as an exception */
#define VNB2VNB_EXC  0x2
#if defined(__FastPath__)
int ng_send_exception(const node_p node, const hook_p hook,
                      int flags, int node_flags, struct mbuf *m, meta_p meta);
#endif


#define per_ns(x,i) (x##_ns)[i]

extern void ng_ns_exit(uint16_t ns);

struct fpvnbtovnbhdr {
	uint32_t nodeid;		/* node ID to send the exception to */
	uint16_t flags;                 /* Internal VNB to VNB framework flags */
	uint16_t node_flags;            /* Node specific flags */
	uint8_t hookname_len;		/* len of the hook name to send the exception to */
	uint8_t nodename_len;		/* len of the node name to send the exception to */
	uint8_t names[];		/* start of the memory space where names are stored */
} __attribute__((packed));
#endif /* _NETGRAPH_NETGRAPH_H_ */
