/*
 * Copyright 2004-2013 6WIND S.A.
 */

/*
 * VNB		An implementation of the VNB stack for the LINUX
 *		operating system.
 */
#include <linux/module.h>
#include <linux/version.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <net/route.h> /* for BUGTRAP */
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/if_arp.h> /* for ARPHRD_ETHER */

#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <netgraph/vnblinux.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_socket.h>

#include <netgraph_linux/ng_rcu.h>

#ifdef CONFIG_VNB_NETLINK_NOTIFY
#include <linux/netlink.h>
#endif

/* rcu_access_pointer() doesn't exist before 2.6.34 but exist in
 * some redhat version!
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
  #ifdef RHEL_RELEASE_CODE
    #if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,5)
      #define rcu_access_pointer(x) rcu_dereference(x)
    #endif
  #else
    #define rcu_access_pointer(x) rcu_dereference(x)
  #endif
#endif

#define atomic_inc_not_one(v) atomic_add_unless((v), 1, 1)

#ifndef smp_mb__before_atomic
#define smp_mb__before_atomic smp_mb__before_atomic_inc
#endif
#ifndef smp_mb__after_atomic
#define smp_mb__after_atomic smp_mb__after_atomic_inc
#endif

extern void vnb_call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *head));
extern void vnb_netlink_notify(const struct ng_mesg *msg, const struct ng_cmdlist *c, const char *path, int pathlen);
extern void vnb_socket_netlink_notify(u_int32_t nodeid, char *name, u_int32_t cmd);

/*
 * Obligatory ASCII-art diagram.
 *
 * Arrows are pointers, rectangles are structures named "{name}" and ".name"
 * are structure members.
 *
 *         CTRL                              DATA
 *        .-----------------.               .-----------------.
 *        | {struct socket} |               | {struct socket} |
 *        |             .sk ---.            |             .sk ---.
 *        `-----------------'  |            `-----------------'  |
 *                        ^    |                            ^    |
 * .-------------------.  |    |     .-------------------.  |    |
 * | {struct vnb_sock} |  |    |     | {struct vnb_sock} |  |    |
 * | .sk =             |  |    |     | .sk =             |  |    |
 * | .---------------. |  |    |     | .---------------. |  |    |
 * | |    .sk_socket -----'    |     | |    .sk_socket -----'    |
 * | | {struct sock} | |       |     | | {struct sock} | |       |
 * | | .refcnt = 2   |<--------'     | | .refcnt = 2   |<--------'
 * | `---------------' |             | `---------------' |
 * | .update = 0       |  .--------->| .update = 0       |
 * | .remove = 0       |  |          | .remove = 0       |
 * | .vnb_rcu          |  |          | .vnb_rcu          |
 * | .ng_rcu           |  |          | .ng_rcu           |
 * | .node             |  |          | .node             |
 * `-|-----------------'  |          `-|-----------------'
 *   |    ^               |            |
 *   |    |               |            |
 *   |    |               |            |                    Kernel
 * ..|....|...............|............|..........................
 *   |    |               |            |                  Netgraph
 *   |    |               |            |
 *   |  .-|---------------|---------.  |
 *   |  | .ctrl_vsk       .data_vsk |  |
 *   |  | {struct ngs_private}      |  |
 *   |  | .count = 2                |  |
 *   |  | .update = 0               |  |
 *   |  | .remove = 0               |  |
 *   |  | .node                     |  |
 *   |  `-|-------------------------'  |
 *   |    |  ^                         |
 *   |    |  |                         |
 *   |    |  |                         |
 *   v    v  |                         |
 * .---------|--------.                |
 * |         .private |<---------------'
 * | {struct ng_node} |
 * `------------------'
 *
 * The hard part is to avoid memory leaks when destroying struct ng_node or
 * releasing sockets while packets are going through.
 *
 * - struct socket holds a reference on struct sock for as long as it's alive.
 *   This reference is automatically taken by sock_init_data().
 * - struct ngs_private also holds a reference on struct sock using
 *   sock_hold() when attached.
 * - ngs_private.count must be increased/decreased whenever vnb_sock.node
 *   is attached/detached.
 * - When ngs_private.count drops to 0, ng_node must be destroyed because
 *   both CTRL and DATA sockets are detached.
 * - ngs_rmnode() must completely unlink struct ngs_private from
 *   struct vnb_sock before freeing the node. This is obvious but keep in mind
 *   some packets may still be in flight.
 * - Finally, packets coming from Netgraph may be in atomic context thus
 *   locking anything is complicated.
 * - In order to meet all the above requirements, RCUs, atomics and memory
 *   barriers are necessary.
 */

typedef struct ngs_private *priv_p;
struct vnb_sock;

/* Netgraph node methods */
static ng_constructor_t	ngs_constructor;
static ng_rcvmsg_t	ngs_rcvmsg;
static ng_shutdown_t	ngs_rmnode;
static ng_newhook_t	ngs_newhook;
static ng_rcvdata_t	ngs_rcvdata;
static ng_disconnect_t	ngs_disconnect;

/* Internal methods */
static void	ng_detach_common(struct vnb_sock *vsk, int type);
static int	ng_attach_cntl(node_p node, struct vnb_sock *vsk);

static int	ng_connect_data(struct sockaddr *nam, struct vnb_sock *vsk);
static int	ng_connect_cntl(struct sockaddr *nam, node_p here);
static int	ng_bind(struct sockaddr *nam, node_p here);
static int	ng_deliver_msg(node_p node, struct ng_mesg *msg,
			       const char *address, struct ng_mesg **rptr,
			       struct ng_mesg **nl_msg);
static int	ship_msg(struct vnb_sock *vsk, struct ng_mesg *msg,
			struct sockaddr_ng *addr);

struct ngs_private {
	node_p node; /* back pointer to node */
	struct vnb_sock *ctrl_vsk; /* kernel control socket */
	struct vnb_sock *data_vsk; /* kernel data socket */
	atomic_t count; /* when decreased to 0, this node must be removed */
	atomic_t update; /* nonzero when this structure is being updated */
	atomic_t remove; /* nonzero when this node is being removed */
	unsigned int no_linger: 1; /* NGS_FLAG_NOLINGER */
};

/* Netgraph type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_socket_typestruct) = {
	.version   = NG_VERSION,
	.name      = NG_SOCKET_NODE_TYPE,
	.mod_event = NULL,
	.constructor=ngs_constructor,
	.rcvmsg    = ngs_rcvmsg,
	.shutdown  = ngs_rmnode,
	.newhook   = ngs_newhook,
	.findhook  = NULL,
	.connect   = NULL,
	.afterconnect = NULL,
	.rcvdata   = ngs_rcvdata,
	.rcvdataq  = ngs_rcvdata,
	.disconnect= ngs_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist   = NULL
};
NETGRAPH_INIT(socket, &ng_socket_typestruct);
NETGRAPH_EXIT(socket, &ng_socket_typestruct);

#ifdef VNB_REFCNT_DEBUG
static atomic_t vnb_sock_nr;
#endif

struct vnb_sock {
	/* sk has to be the first member */
	struct sock sk;
	node_p node; /* associated node */
	atomic_t update; /* nonzero when this structure is being updated */
	atomic_t remove; /* nonzero when this structure is being removed */
	struct rcu_head ng_rcu; /* for netgraph call_rcu() */
	struct rcu_head vnb_rcu; /* for socket call_rcu() */
};

static struct proto vnb_proto = {
	.name	  = "VNB",
	.owner	  = THIS_MODULE,
	.obj_size = sizeof(struct vnb_sock),
};

#define VNB_MAXHDR_LEN	16

/*
 * Mutual exclusion lock used to serialize the processing of external
 * VNB control messages issued by [user-land] applications (XMS, ngctl)
 * and the processing of internal VNB control messages issued by VNB
 * node functions.
 */
#include <linux/mutex.h>
static DEFINE_MUTEX(ng_mutex);

#define ng_mutex_acquire() mutex_lock(&ng_mutex)
#define ng_mutex_release() mutex_unlock(&ng_mutex)
#define ng_mutex_try()     mutex_trylock(&ng_mutex)

#define ng_socket_lock_acquire() ng_mutex_acquire()
#define ng_socket_lock_try()     ng_mutex_try()

#if ! VNB_WITH_MSG_POST
#define ng_socket_lock_init()
#define ng_socket_lock_release() ng_mutex_release()
#else
static VNB_DEFINE_SHARED(struct ng_mesg *, first_pending) = NULL;
static VNB_DEFINE_SHARED(struct ng_post_msg *, last_pending) = NULL;
static VNB_DEFINE_SHARED(spinlock_t, msg_queue_lock);

#define ng_socket_lock_init() do {			 \
		spin_lock_init(&msg_queue_lock); \
	} while (0)

static void ng_send_pending_msg_with_lock(void)
{
	struct ng_mesg *next_msg;
	struct ng_mesg *cur_msg;

	spin_lock_bh(&msg_queue_lock);
	cur_msg = first_pending;
	first_pending = NULL;
	last_pending = NULL;
	spin_unlock_bh(&msg_queue_lock);
	for (; cur_msg != NULL; cur_msg = next_msg) {
		struct ng_post_msg *post_msg;
		node_p node;

		post_msg = NG_MESG_TO_POST_MSG(cur_msg);
		next_msg = post_msg->next_mesg;
		node = ng_ID2node(post_msg->node_id);
		if (unlikely(node == NULL)) {
			FREE(cur_msg, M_NETGRAPH);
			continue;
		}
		(void) ng_send_msg(node, cur_msg, ".", NULL);
	}
}

static void ng_socket_lock_release(void)
{
	for (;;) {
		ng_mutex_release();
		if (likely(first_pending == NULL))
			return;
		if (unlikely(ng_mutex_try())) /* re-acquired in the meantime */
			return;
		ng_send_pending_msg_with_lock();
	}
}

static void ng_defer_msg(node_p node, struct ng_mesg *msg)
{
	struct ng_post_msg *post_msg;
	struct ng_post_msg *last_posted;

	post_msg = NG_MESG_TO_POST_MSG(msg);
	post_msg->node_id = NG_NODE_ID(node);
	post_msg->next_mesg = NULL;

	spin_lock_bh(&msg_queue_lock);
	last_posted = last_pending;
	last_pending = post_msg;
	if (unlikely(last_pending != NULL)) {
		last_posted->next_mesg = msg;
		spin_unlock_bh(&msg_queue_lock);
		return;
	}
	first_pending = msg;
	/* should we call barrier() here ? */
	spin_unlock_bh(&msg_queue_lock);
	if (unlikely(ng_socket_lock_try())) /* lock already acquired */
		return;
	ng_send_pending_msg_with_lock();
	ng_socket_lock_release();
}

void ng_post_msg(node_p node, struct ng_mesg *msg)
{
	/*
	 * Try to send it now.
	 */
	if (unlikely(ng_socket_lock_try())) { /* lock already acquired */
		ng_defer_msg(node, msg);
		return;
	}
	/*
	 * Green case
	 * Send message immediately and release lock.
	 */
	(void) ng_send_msg(node, msg, ".", NULL);
	ng_socket_lock_release();
}
#endif /* VNB_WITH_MSG_POST */

/*
 * Create a ng_socket node.
 * Must be called with ng_socket_lock acquired.
 */
static int ng_create_socket(node_p *node)
{
	/* Make sure to take ref count on module.
	 * For this, don't call constructor directly, but generic API instead
	 */
	return ng_make_node(NG_SOCKET_NODE_TYPE, node, 0);
}

/*
 * Attach a socket to its protocol specific partner.
 * Must be called with ng_socket_lock acquired.
 */
static int
ng_attach_cntl(node_p node, struct vnb_sock *vsk)
{
	priv_p priv;
	int err = 0;

	vnb_rcu_read_lock();
	if (((priv = rcu_dereference(node->private)) == NULL) ||
	    (!atomic_inc_not_one(&priv->update))) {
		err = EBUSY;
		VNB_TRAP("EBUSY");
		goto end;
	}
	if (!atomic_inc_not_one(&vsk->update)) {
		atomic_dec(&priv->update);
		err = EBUSY;
		VNB_TRAP("EBUSY");
		goto end;
	}
	/* XXX some refactoring needed, see ng_connect_data(). */
	/* Increase number of linked sockets. */
	smp_mb__before_atomic();
	atomic_inc(&priv->count);
	smp_mb__after_atomic();
	/* Increase sock refcount for node. */
	sock_hold(&vsk->sk);
	/* Link node and vsk together. */
	rcu_assign_pointer(vsk->node, node);
	rcu_assign_pointer(priv->ctrl_vsk, vsk);
	/* If the node was removed in the meantime, rollback. */
	if ((!atomic_dec_and_test(&priv->update)) &&
	    (atomic_read(&priv->remove)))
		err = EBUSY;
	/* If vsk was removed in the meantime, rollback. */
	if ((!atomic_dec_and_test(&vsk->update)) &&
	    (atomic_read(&vsk->remove)))
		err = EBUSY;
	if (err) {
		/* Rollback. */
		rcu_assign_pointer(vsk->node, NULL);
		rcu_assign_pointer(priv->ctrl_vsk, NULL);
		smp_mb__before_atomic();
		atomic_dec(&priv->count);
		smp_mb__after_atomic();
		err = EBUSY;
		/* Decrease sock refcount. */
		sock_put(&vsk->sk);
	}
end:
	vnb_rcu_read_unlock();
	return err;
}

/*
 * Disassociate the socket from its protocol specific
 * partner. If it's attached to a node's private data structure,
 * then unlink from that too. If we were the last socket attached to it,
 * then shut down the entire node. Shared code for control and data sockets.
 */

static void ng_rcu_vsk(struct rcu_head *rh)
{
	struct vnb_sock *vsk = container_of(rh, struct vnb_sock, ng_rcu);

	/* Decrease sock refcount for node. */
	sock_put(&vsk->sk);
}

/* Must be called with ng_socket_lock acquired. */
static void
ng_detach_common(struct vnb_sock *vsk, int type)
{
	node_p node;
	priv_p priv;
	struct vnb_sock **node_vsk;

	vnb_rcu_read_lock();
	if (((node = rcu_dereference(vsk->node)) == NULL) ||
	    ((priv = rcu_dereference(node->private)) == NULL) ||
	    (!atomic_inc_not_one(&vsk->remove))) {
		vnb_rcu_read_unlock();
		return;
	}
	rcu_assign_pointer(vsk->node, NULL);
	smp_mb__before_atomic();
	atomic_inc(&vsk->update);
	smp_mb__after_atomic();
	switch (type) {
	case NG_DATA:
		node_vsk = &priv->data_vsk;
		break;
	case NG_CONTROL:
	default: /* XXX */
		node_vsk = &priv->ctrl_vsk;
		break;
	}
	smp_mb__before_atomic();
	atomic_inc(&priv->update);
	smp_mb__after_atomic();
	rcu_assign_pointer(*node_vsk, NULL);
	if ((atomic_dec_and_test(&priv->count)) &&
	    (atomic_inc_not_one(&priv->remove))) {
		ng_rmnode(node);
		/*
		  Because priv->remove was already 1, the following hasn't
		  been done by ngs_rmnode().
		*/
		rcu_assign_pointer(node->private, NULL);
		ng_unname(node);
		ng_cutlinks(node);
		ng_unref(node);
	}
	else {
		smp_mb__before_atomic();
		atomic_dec(&priv->update);
		smp_mb__after_atomic();
	}
	/* ng_detach_common_rcu_vsk() will call sock_put() */
	vnb_call_rcu(&vsk->ng_rcu, ng_rcu_vsk);
	vnb_rcu_read_unlock();
}

static int
ngd_detach(struct socket *so)
{
	struct vnb_sock *vsk;

	vnb_rcu_read_lock();
	if ((vsk = (struct vnb_sock *)rcu_dereference(so->sk)) != NULL)
		ng_detach_common(vsk, NG_DATA);
	vnb_rcu_read_unlock();
	return 0;
}

static int
ngc_detach(struct socket *so)
{
	struct vnb_sock *vsk;

	vnb_rcu_read_lock();
	if ((vsk = (struct vnb_sock *)rcu_dereference(so->sk)) != NULL)
		ng_detach_common(vsk, NG_CONTROL);
	vnb_rcu_read_unlock();
	return 0;
}

/*
 * Connect the data socket to a named control socket node.
 * Must be called with ng_socket_lock acquired.
 */
static int
ng_connect_data(struct sockaddr *nam, struct vnb_sock *vsk)
{
	struct sockaddr_ng *sap;
	node_p farnode;
	priv_p priv;
	int error;

	vnb_rcu_read_lock();
	/* Make sure no one else is also updating vsk. */
	if (!atomic_inc_not_one(&vsk->update)) {
		vnb_rcu_read_unlock();
		return EBUSY;
	}
	/* If we are already connected, don't do it again */
	if (rcu_access_pointer(vsk->node) != NULL) {
		atomic_dec(&vsk->update);
		vnb_rcu_read_unlock();
		return (EISCONN);
	}
	/* Find the target (victim) and check it doesn't already have a data
	 * socket. Also check it is a 'socket' type node. */
	sap = (struct sockaddr_ng *) nam;
	if (((error = ng_path2node(NULL, sap->sg_data, &farnode, NULL))) ||
	    (error = EINVAL, /* if node has the wrong type */
	     (strcmp(farnode->type->name, NG_SOCKET_NODE_TYPE) != 0)) ||
	    (error = EINVAL, /* if node is being removed */
	     ((priv = rcu_dereference(farnode->private)) == NULL)) ||
	    (error = EADDRINUSE, /* if node already has a data socket */
	     (rcu_access_pointer(priv->data_vsk) != NULL)) ||
	    (error = EBUSY, /* if node is already being updated */
	     (!atomic_inc_not_one(&priv->update)))) {
		atomic_dec(&vsk->update);
		vnb_rcu_read_unlock();
		return error;
	}
	error = 0;
	/* XXX some refactoring needed, see ng_attach_cntl(). */
	/* Increase number of linked sockets. */
	smp_mb__before_atomic();
	atomic_inc(&priv->count);
	smp_mb__after_atomic();
	/* Increase sock refcount for node. */
	sock_hold(&vsk->sk);
	/* Link node and vsk together. */
	rcu_assign_pointer(vsk->node, farnode);
	rcu_assign_pointer(priv->data_vsk, vsk);
	/* If the node was removed in the meantime, rollback. */
	if ((!atomic_dec_and_test(&priv->update)) &&
	    (atomic_read(&priv->remove)))
		error = EBUSY;
	/* If vsk was removed in the meantime, rollback. */
	if ((!atomic_dec_and_test(&vsk->update)) &&
	    (atomic_read(&vsk->remove)))
		error = EBUSY;
	if (error) {
		/* Rollback. */
		rcu_assign_pointer(vsk->node, NULL);
		rcu_assign_pointer(priv->data_vsk, NULL);
		smp_mb__before_atomic();
		atomic_dec(&priv->count);
		smp_mb__after_atomic();
		error = EBUSY;
		/* Decrease sock refcount. */
		sock_put(&vsk->sk);
	}
	vnb_rcu_read_unlock();
	return error;
}

/*
 * Connect the existing control socket node to a named node:hook.
 * The hook we use on this end is the same name as the remote node name.
 * Must be called with ng_socket_lock acquired.
 */
static int
ng_connect_cntl(struct sockaddr *nam, node_p here)
{
	struct sockaddr_ng *sap;
	char *node, *hook;
	node_p farnode;
	int rtn, error;

	sap = (struct sockaddr_ng *) nam;
	rtn = ng_path_parse(sap->sg_data, &node, NULL, &hook);
	if (rtn < 0 || node == NULL || hook == NULL) {
		VNB_TRAP("EINVAL");
		return (EINVAL);
	}
	farnode = ng_findname(here, node);
	if (farnode == NULL) {
		VNB_TRAP("EADDRNOTAVAIL");
		return (EADDRNOTAVAIL);
	}

	/* Connect, using a hook name the same as the far node name. */
	error = ng_con_nodes(here, node, farnode, hook);
	return error;
}

/*
 * Binding a socket means giving the corresponding node a name
 * Must be called with ng_socket_lock acquired.
 */
static int
ng_bind(struct sockaddr *nam, node_p here)
{
	struct sockaddr_ng *const sap = (struct sockaddr_ng *) nam;
	int    error;

	if (sap->sg_len < 3 || sap->sg_data[sap->sg_len - 3] != '\0') {
		VNB_TRAP("EINVAL");
		return (EINVAL);
	}
	error = ng_name_node(here, sap->sg_data);
	return error;
}

/*
 * Take a message and pass it up to the control socket associated
 * with the node.
 */
static int
ship_msg(struct vnb_sock *vsk, struct ng_mesg *msg, struct sockaddr_ng *addr)
{
	struct sk_buff *skb;
	int msglen;

	/* Copy the message itself into an skbuff */
	msglen = sizeof(struct ng_mesg) + msg->header.arglen;
	/*skb = dev_alloc_skb(msglen);*/
	skb = alloc_skb(msglen, GFP_ATOMIC);
	if(skb == NULL) {
		VNB_TRAP("ENOMEM");
		return -ENOMEM;
	}

	skb_put(skb, msglen); /* len = size, tail=memory+size, return data(unchanged) */

	memcpy(skb->data, msg, msglen);

	FREE(msg, M_NETGRAPH);

	/* save a copy of destination addr ? */
	if(addr)
		memcpy(&skb->cb, addr, addr->sg_len);

	/* Send it up to the socket */
	if (sock_queue_rcv_skb(&vsk->sk, skb)) {
		kfree_skb(skb);
		VNB_TRAP("ENOBUFS");
		return -ENOBUFS;
	}
	return (0);
}

/*
 * A new function "ng_deliver_msg()" must be invoked to make an "external"
 * VNB control message provided from the outside be processed in a VNB graph
 * starting at node "here".
 * Currently, the only caller is the "ng_socket" node for control messages
 * issued by user-land applications (XMS, ngctl).
 * The "ng_send_msg" function remains for internal VNB control messages
 * issued by VNB node functions.
 */
static int
ng_deliver_msg(node_p here, struct ng_mesg *msg, const char *address,
	       struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	int diag;

	diag = ng_send_msg(here, msg, address, rptr, nl_msg);
	return diag;
}

/*
 * Must be called with ng_socket_lock acquired and outside of vnb_rcu_read_lock().
 */
static int
ngc_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
	 struct mbuf *control /*, struct proc *p*/)
{
	struct vnb_sock *vsk;
	struct sockaddr_ng *const sap = (struct sockaddr_ng *) addr;
	node_p node;
	priv_p priv;
	struct ng_mesg *resp, *nl_msg;
	char *msg, *path = NULL;
#ifdef CONFIG_VNB_NETLINK_NOTIFY
	node_p here = NULL;
	const struct ng_cmdlist *c = NULL;
#endif
	int len, pathlen, error = 0;

	vnb_rcu_read_lock();
	if (((vsk = (struct vnb_sock *)rcu_dereference(so->sk)) == NULL) ||
	    ((node = rcu_dereference(vsk->node)) == NULL) ||
	    ((priv = rcu_dereference(node->private)) == NULL)) {
		vnb_rcu_read_unlock();
		error = EINVAL;
		VNB_TRAP("EINVAL");
		goto release_not_held;
	}
	/*
	 * This extra reference prevents vsk from going away. vnb_rcu_read_lock()
	 * can't be kept because synchronize_rcu() may be called through
	 * unregister_netdev() in iface and eiface nodes.
	 */
	sock_hold(&vsk->sk);
	vnb_rcu_read_unlock();
	if (control) {
		error = EINVAL;
		goto release;
	}

	/* Require destination as there may be >= 1 hooks on this node */
	if (addr == NULL) {
		error = EDESTADDRREQ;
		goto release;
	}

	/* Allocate an expendable buffer for the path, chop off
	 * the sockaddr header, and make sure it's NUL terminated */
	pathlen = sap->sg_len - 2;
	MALLOC(path, char *, pathlen + 1, M_NETGRAPH, M_NOWAIT);
	if (path == NULL) {
		error = ENOMEM;
		goto release;
	}
	bcopy(sap->sg_data, path, pathlen);
	path[pathlen] = '\0';

	len = m->len;
	/* Move the data into a linear buffer as well. Messages are not
	 * delivered in mbufs. */
	MALLOC(msg, char *, len + 1, M_NETGRAPH, M_NOWAIT);
	if (msg == NULL) {
		error = ENOMEM;
		goto release;
	}
	m_copydata(m, 0, len, msg);

#ifdef CONFIG_VNB_NETLINK_NOTIFY
	/* vnb_netlink_notify() needs a pointer to the cmd. We must get this pointer
	 * before delivering the message to the node, because the message may change
	 * the path to the node (eg change the name of the node), so we will not be
	 * able to find it later.
	 * If ng_path2node() fails, ng_deliver_msg() will fail too, because it calls
	 * ng_send_msg() which calls ng_path2node() with the same parameters.
	 */
	if (ng_path2node(node, path, &here, NULL) == 0) {
		struct ng_mesg * mesg = (struct ng_mesg *) m->data;

		/* Find command by matching typecookie and command number */
		for (c = here->type->cmdlist; c != NULL && c->name != NULL; c++) {
			if (mesg->header.typecookie == c->cookie &&
			    mesg->header.cmd == c->cmd)
				break;
		}
		if (c == NULL || c->name == NULL) {
			c = ng_find_generic_node(mesg);
			if (c->name == NULL) {
				log(LOG_WARNING, "cannot find the cmd list typecookie=%d, cmd=%d\n",
				    mesg->header.typecookie, mesg->header.cmd);
			}
		}
	}
#endif

	/* The callee will free the msg when done. The addr is our business. */
	error = ng_deliver_msg(node,
			       (struct ng_mesg *) msg, path, &resp, &nl_msg);
#ifdef CONFIG_VNB_NETLINK_NOTIFY
	/* Don't advertise error path,
	 * Don't advertise reply to query.
	 *
	 * Advertise the command. */
	if (error == 0 &&
	    (resp == NULL || nl_msg != NULL)) {
		struct ng_mesg *mesg;

		if (nl_msg)
			mesg = nl_msg;
		else
			mesg = (struct ng_mesg *) m->data;

		mesg->header.nodeid = node->ID;

		if (mesg->header.arglen) {
			if (c && c->name)
				vnb_netlink_notify(mesg, c, path, pathlen);
		} else
			vnb_netlink_notify(mesg, NULL, path, pathlen);

		if (nl_msg)
			FREE(nl_msg, M_NETGRAPH);
	}
#endif

	/* If the callee responded with a synchronous response, then put it
	 * back on the receive side of the socket; sap is source address. */
	if (error == NGM_NO_NETLINK_ADV)
		error = 0;
	if (error == 0 && resp != NULL)
		error = ship_msg(vsk, resp, sap);

release:
	sock_put(&vsk->sk);
release_not_held:
	if (path != NULL)
		FREE(path, M_NETGRAPH);
	if (control != NULL)
		m_freem(control);
	if (m != NULL)
		m_freem(m);
	return (error);
}

/* Must be called after VNB_ENTER(). No need for ng_socket_lock. */
static int
ngd_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
	 struct mbuf *control /*, struct proc *p*/, meta_p mp)
{
	struct vnb_sock *vsk;
	node_p node;
	priv_p priv;
	struct sockaddr_ng *const sap = (struct sockaddr_ng *) addr;
	int     len, error;
	hook_p  hook = NULL;
	char	hookname[NG_HOOKLEN + 1];

	vnb_rcu_read_lock();
	if ((control != NULL) ||
	    ((vsk = (struct vnb_sock *)rcu_dereference(so->sk)) == NULL)) {
		error = EINVAL;
		goto release;
	}
	if (((node = rcu_dereference(vsk->node)) == NULL) ||
	    ((priv = rcu_dereference(node->private)) == NULL)) {
		error = ENOTCONN;
		goto release;
	}
	/*
	 * If the user used any of these ways to not specify an address
	 * then handle specially.
	 */
	if ((sap == NULL)
	    || ((len = sap->sg_len - 2) <= 0)
	    || (*sap->sg_data == '\0')) {
		if (node->numhooks != 1) {
			error = EDESTADDRREQ;
			goto release;
		}
		/*
		 * if exactly one hook exists, just use it.
		 * Special case to allow write(2) to work on an ng_socket.
		 */
		hook = LIST_FIRST(&node->hooks);
	} else {
		if (len > NG_HOOKLEN) {
			error = EINVAL;
			goto release;
		}

		/*
		 * chop off the sockaddr header, and make sure it's NUL
		 * terminated
		 */
		bcopy(sap->sg_data, hookname, len);
		hookname[len] = '\0';

		/* Find the correct hook from 'hookname' */
		hook = ng_findhook(node, hookname);
		if (hook == NULL) {
			error = EHOSTUNREACH;
			goto release;
		}
	}

	/* Send data (OK if hook is NULL) */
	skb_orphan(m);
	NG_SEND_DATA(error, hook, m, mp);	/* makes m and mp NULL */

release:
	if (control != NULL)
		m_freem(control);
	if (m != NULL)
		m_freem(m);
	if (mp != NULL)
		NG_FREE_META(mp);
	vnb_rcu_read_unlock();
	return (error);
}

/*
 * You can only create new nodes from the socket end of things.
 */
static int
ngs_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int error;

	/* Allocate node with its private data. */
	error = ng_make_node_common_and_priv(&ng_socket_typestruct, nodep, &priv,
					     sizeof(*priv), 0);
	if (error)
		return error;
	/* Initialize private data. */
	memset(priv, 0, sizeof(*priv));
	rcu_assign_pointer((*nodep)->private, priv);
	rcu_assign_pointer(priv->node, *nodep);
	rcu_assign_pointer(priv->ctrl_vsk, NULL);
	rcu_assign_pointer(priv->data_vsk, NULL);
	atomic_set(&priv->count, 0);
	atomic_set(&priv->update, 0);
	atomic_set(&priv->remove, 0);
	return 0;
}

/*
 * We allow any hook to be connected to the node.
 * There is no per-hook private information though.
 */
static int
ngs_newhook(node_p node, hook_p hook, const char *name)
{
	hook->private = node->private;
	return (0);
}

/*
 * Incoming messages get passed up to the control socket.
 * Unless they are for us specifically (socket_type)
 */
static int
ngs_rcvmsg(node_p node, struct ng_mesg *msg, const char *retaddr,
	   struct ng_mesg **resp, struct ng_mesg **nl_msg)
{
	priv_p priv;
	struct vnb_sock *vsk;
	struct sockaddr_ng *addr;
	int error = 0;

	vnb_rcu_read_lock();
	/* Only allow mesgs to be passed if we have the control socket.
	 * Data sockets can only support the generic messages. */
	if (((priv = rcu_dereference(node->private)) == NULL) ||
	    ((vsk =
	      (struct vnb_sock *)rcu_dereference(priv->ctrl_vsk)) == NULL)) {
		VNB_TRAP("EINVAL");
		vnb_rcu_read_unlock();
		return (EINVAL);
	}
	if (msg->header.typecookie == NGM_SOCKET_COOKIE) {
		switch (msg->header.cmd) {
		case NGM_SOCK_CMD_NOLINGER:
			priv->no_linger = 1;
			break;
		case NGM_SOCK_CMD_LINGER:
			priv->no_linger = 0;
			break;
		default:
			error = EINVAL;		/* unknown command */
		}
		vnb_rcu_read_unlock();
		/* Free the message and return */
		FREE(msg, M_NETGRAPH);
		return(error);

	}
	/* Get the return address into a sockaddr */
	if ((retaddr == NULL) || (*retaddr == '\0'))
		retaddr = "";
	/* We cannot pass more than sockaddr_ng to user */
	MALLOC(addr, struct sockaddr_ng *, sizeof(*addr), M_NETGRAPH, M_NOWAIT);
	if(addr == NULL) {
		VNB_TRAP("ENOMEM");
		vnb_rcu_read_unlock();
		return (ENOMEM);
	}
	if (retaddr && strlcpy(addr->sg_data, retaddr, sizeof(addr->sg_data))
			>= sizeof(addr->sg_data)) {
		printk(KERN_WARNING "VNB: ngs_rcvmsg() - retaddr name too long"
				", truncated to \"%s\"", addr->sg_data);
	} else {
		addr->sg_data[0] = '\0';
	}
	addr->sg_len = strlen(addr->sg_data) + 3;
	addr->sg_family = AF_NETGRAPH;

	/* Send it up */
	error = ship_msg(vsk, msg, addr);
	vnb_rcu_read_unlock();
	FREE(addr, M_NETGRAPH);
	return (error);
}

/*
 * Receive data on a hook
 */
static int
ngs_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	priv_p priv;
	struct vnb_sock *vsk;
	struct sockaddr_ng *addr;
	const char *hook_name;

	vnb_rcu_read_lock();
	if (((priv = rcu_dereference(hook->node_private)) == NULL) ||
	    ((vsk = rcu_dereference(priv->data_vsk)) == NULL)) {
		vnb_rcu_read_unlock();
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	hook_name = hook->name;
	if (hook_name == NULL) {
		vnb_rcu_read_unlock();
		NG_FREE_DATA(m, meta);
		return 0;
	}

	/* We have no use for the meta data, free/clear it now. */
	NG_FREE_META(meta);

	/* Try to tell the socket which hook it came in on */
	/* hook_name should be <= NG_HOOKLEN and can be
	 * stored into sg_data[] */
	addr = (struct sockaddr_ng *)&m->cb;
	if (strlcpy(addr->sg_data, hook_name, sizeof(addr->sg_data))
			>= sizeof(addr->sg_data)) {
		printk(KERN_WARNING "VNB: ngs_rcvdata() - hook name too long"
				", truncated to \"%s\"", addr->sg_data);
	}
	addr->sg_len = strlen(addr->sg_data) + 3;
	addr->sg_family = AF_NETGRAPH;


	skb_orphan(m);
	if (sock_queue_rcv_skb(&vsk->sk, m)) {
		kfree_skb(m);
		VNB_TRAP("ENOBUFS");
		vnb_rcu_read_unlock();
		return ENOBUFS;
	}
	vnb_rcu_read_unlock();
	return 0;
}

/*
 * Hook disconnection
 *
 * For this type, removal of the last link destroys the node
 * if the NOLINGER flag is set.
 */
static int
ngs_disconnect(hook_p hook)
{
	priv_p priv;
	node_p node;

	vnb_rcu_read_lock();
	if (((node = rcu_dereference(hook->node)) == NULL) ||
	    ((priv = rcu_dereference(node->private)) == NULL)) {
		vnb_rcu_read_unlock();
		return 0;
	}
	if ((priv->no_linger) && (node->numhooks == 0))
		ng_rmnode(node);
	vnb_rcu_read_unlock();
	return 0;
}

/*
 * Do local shutdown processing.
 * In this case, that involves making sure the socket
 * knows we should be shutting down.
 */
static int
ngs_rmnode(node_p node)
{
	priv_p priv;
	struct vnb_sock *vsk;

	vnb_rcu_read_lock();
	if (((priv = rcu_dereference(node->private)) == NULL) ||
	    (!atomic_inc_not_one(&priv->remove))) {
		/* Someone is already removing this node. */
		vnb_rcu_read_unlock();
		return 0;
	}
	ng_cutlinks(node);
	ng_unname(node);
	rcu_assign_pointer(node->private, NULL);
	/* Prevent others from trying to attach sockets from now on. */
	smp_mb__before_atomic();
	atomic_inc(&priv->update);
	smp_mb__after_atomic();
	/* Unlink ctrl and data safely. */
	if ((vsk = rcu_dereference(priv->ctrl_vsk)) != NULL) {
		rcu_assign_pointer(priv->ctrl_vsk, NULL);
		smp_mb__before_atomic();
		atomic_inc(&vsk->update);
		smp_mb__after_atomic();
		rcu_assign_pointer(vsk->node, NULL);
		smp_mb__before_atomic();
		atomic_dec(&vsk->update);
		smp_mb__after_atomic();
		/* Remove ctrl sock reference. */
		vnb_call_rcu(&vsk->ng_rcu, ng_rcu_vsk);
	}
	if ((vsk = rcu_dereference(priv->data_vsk)) != NULL) {
		rcu_assign_pointer(priv->data_vsk, NULL);
		smp_mb__before_atomic();
		atomic_inc(&vsk->update);
		smp_mb__after_atomic();
		rcu_assign_pointer(vsk->node, NULL);
		smp_mb__before_atomic();
		atomic_dec(&vsk->update);
		smp_mb__after_atomic();
		/* Remove data sock reference. */
		vnb_call_rcu(&vsk->ng_rcu, ng_rcu_vsk);
	}
	ng_unref(node);
	vnb_rcu_read_unlock();
	return 0;
}

/*
 * Control and data socket type descriptors
 */


/***************************************************************
        Control sockets
***************************************************************/

static int vnbc_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	node_p node;
	struct sock *sk = sock->sk;
	int err;

	ng_socket_lock_acquire();
	lock_sock(sk);
	vnb_rcu_read_lock();
	node = rcu_dereference(((struct vnb_sock *)sk)->node);
	err = ng_bind(uaddr, node);
	if ((node != NULL) && (!err))
		vnb_socket_netlink_notify(node->ID, node->name,
					  NGM_SOCKET_CREATE);
	vnb_rcu_read_unlock();
	release_sock(sk);
	ng_socket_lock_release();
	if(err) {
		VNB_TRAP("error=%d", err);
		return -err;
	}
	return 0;
}

static void vnb_rcu_vsk(struct rcu_head *rh)
{
	struct vnb_sock *vsk = container_of(rh, struct vnb_sock, vnb_rcu);

	/* Decrease sock refcount. */
	sock_put(&vsk->sk);
}

static int vnbc_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct vnb_sock *vsk = (struct vnb_sock *)sk;
	node_p node;
	priv_p priv;
	int err;

	ng_socket_lock_acquire();
	sock_hold(sk);
	lock_sock(sk);
	vnb_rcu_read_lock();
	if (sock->sk == NULL) {
		vnb_rcu_read_unlock();
		release_sock(sk);
		sock_put(sk);
		ng_socket_lock_release();
		return -EINVAL;
	}
	if (((node = rcu_dereference(vsk->node)) != NULL) &&
	    ((priv = rcu_dereference(node->private)) != NULL))
		vnb_socket_netlink_notify(node->ID, NULL, NGM_SOCKET_DELETE);
	err = ngc_detach(sock);
	sock->sk = NULL;
	vnb_call_rcu(&vsk->vnb_rcu, vnb_rcu_vsk);
	vnb_rcu_read_unlock();
	release_sock(sk);
	sock_orphan(sk);
	sock_put(sk);
	ng_socket_lock_release();
	if (err) {
		VNB_TRAP("error=%d", err);
		return -err;
	}
	return 0;
}

static int vnbc_connect(struct socket *sock, struct sockaddr * uaddr,
		       int addr_len, int flags)
{
	node_p node;
	int err;

	ng_socket_lock_acquire();
	vnb_rcu_read_lock();
	node = rcu_dereference(((struct vnb_sock *)sock->sk)->node);
	if (node == NULL)
		err = -EINVAL;
	else
		err = -(ng_connect_cntl(uaddr, node));
	vnb_rcu_read_unlock();
	ng_socket_lock_release();
	return err;
}

static int vnbc_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t  size)
{
	struct sock *sk = sock->sk;
	int err;
	struct sk_buff *skb;
	struct sockaddr *nam = (struct sockaddr *)msg->msg_name;

	/* scm ? */

	skb = sock_alloc_send_skb(sk, size + VNB_MAXHDR_LEN, msg->msg_flags&MSG_DONTWAIT, &err);

	if(skb == NULL)
		return -ENOMEM;

	skb_reserve(skb, VNB_MAXHDR_LEN); /* XX forecast encapsulation */
	/* JMG: data_len and len still 0 */
	skb_put(skb, size); /* len = size, tail=memory+size, return data(unchanged) */
        err = memcpy_fromiovecend(skb->data, msg->msg_iov, 0, size);
	if(err) {
		VNB_TRAP("error=%d", err);
		kfree_skb(skb);
		return(err);
	}
	ng_socket_lock_acquire();
	/* XX META in control not supported */
	err = ngc_send(sock, 0 /* flags not used */, skb, nam, NULL);
	ng_socket_lock_release();
	if (err == 0)
		err = size;
	else if (err > 0)
		err = -err;
	else printk("ngc_send return Invalid error\n");
	return err;
}

/*
 *	This should be easy, if there is something there
 *	we return it, otherwise we block.
 */

static int vnb_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
	int copied = 0;
	struct sock *sk = sock->sk;
	int err = -EOPNOTSUPP;
	struct sockaddr_ng *sg = (struct sockaddr_ng *)msg->msg_name;
	struct sk_buff *skb;

	if (flags & MSG_OOB)
		goto out;

	if (flags & MSG_ERRQUEUE) {
		printk(KERN_INFO "VNB: vnb_recvmsg - flags & MSG_ERRQUEUE ?\n");
		goto out;
	}

	skb = skb_recv_datagram(sk, flags, flags&MSG_DONTWAIT, &err);
	if (!skb)
		goto out;

	copied = skb->len;
	if (size < (unsigned int)copied) {
		msg->msg_flags |= MSG_TRUNC;
		copied = size;
	}

	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	if (err)
		goto done;

	/* Copy the address. */
	if (sg)
		memcpy(sg, &skb->cb, sizeof(*sg));

	msg->msg_namelen = sizeof(*sg);

done:
	skb_free_datagram(sk, skb);
out:	return err ? : copied;
}

/*
 * Data sockets
 */

static int vnbd_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct vnb_sock *vsk = (struct vnb_sock *)sk;
	int err;

	ng_socket_lock_acquire();
	sock_hold(sk);
	lock_sock(sk);
	vnb_rcu_read_lock();
	if (sock->sk == NULL) {
		vnb_rcu_read_unlock();
		release_sock(sk);
		sock_put(sk);
		ng_socket_lock_release();
		return -EINVAL;
	}
	err = ngd_detach(sock);
	sock->sk = NULL;
	vnb_call_rcu(&vsk->vnb_rcu, vnb_rcu_vsk);
	vnb_rcu_read_unlock();
	release_sock(sk);
	sock_orphan(sk);
	sock_put(sk);
	ng_socket_lock_release();
	if (err) {
		VNB_TRAP("error=%d", err);
		return -err;
	}
	return(0);
}

static int vnbd_connect(struct socket *sock, struct sockaddr * uaddr,
                       int addr_len, int flags)
{
	int ret;

	ng_socket_lock_acquire();
	ret = -(ng_connect_data(uaddr, (struct vnb_sock *)sock->sk));
	ng_socket_lock_release();
	return ret;
}

/* Parse ancillary data of level SOL_NETGRAPH */
static int vnb_cmsg_send(struct msghdr *msg, meta_p *ptr, struct sk_buff *skb)
{
	struct cmsghdr *cmsg;
	meta_p meta = NULL;
	int err;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (!CMSG_OK(msg, cmsg)) {
			err = -EINVAL;
			goto err;
		}
		if (cmsg->cmsg_level != SOL_NETGRAPH)
			continue;
		switch (cmsg->cmsg_type) {
		case NG_OPT_METADATA:
		{
			struct meta_header *hdr;

			if (cmsg->cmsg_len < CMSG_LEN(sizeof(*hdr))) {
				err = -EINVAL;
				goto err;
			}

			hdr = (struct meta_header *)CMSG_DATA(cmsg);
			/* At least one entry! */
			if (hdr->len < sizeof(struct meta_field_header)) {
				err = -EINVAL;
				goto err;
			}

			MALLOC(meta, meta_p, sizeof(struct ng_meta) + hdr->len,
			       M_NETGRAPH, M_ZERO | M_WAITOK);
			if (meta == NULL) {
				err = -ENOMEM;
				goto err;
			}
			meta->allocated_len = sizeof(struct ng_meta) + hdr->len;
			meta->used_len = sizeof(struct ng_meta) + hdr->len;
			memcpy(meta->options, hdr->options, hdr->len);
			*ptr = meta;
			break;
		}
		case NG_OPT_MARK:
		{
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(uint32_t))) {
				err = -EINVAL;
				goto err;
			}
			skb->mark = *(uint32_t *)CMSG_DATA(cmsg);
			break;
		}
		default:
			return -EINVAL;
		}
	}
	return 0;

err:
	if (meta)
		NG_FREE_META(meta);
	return err;
}

static int vnbd_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	int err;
	struct sk_buff *skb;
	struct sockaddr *nam = (struct sockaddr *)msg->msg_name;
	meta_p meta = NULL;
	/* scm ? */

	skb = sock_alloc_send_skb(sk, size + VNB_MAXHDR_LEN, msg->msg_flags&MSG_DONTWAIT, &err);

	if(skb == NULL)
		return err;

	skb_reserve(skb, VNB_MAXHDR_LEN); /* XX forecast encapsulation */
	/* JMG: data_len and len still 0 */
	skb_put(skb, size); /* len = size, tail=memory+size, return data(unchanged) */

        err = memcpy_fromiovecend(skb->data, msg->msg_iov, 0, size);
	if(err) {
		kfree_skb(skb);
		return(err);
	}

	err = vnb_cmsg_send(msg, &meta, skb);
	if (err) {
		kfree_skb(skb);
		return err;
	}
#ifdef CONFIG_NET_SKBUFF_SKTAG
	/* also copy the tags */
	err = skb_copy_sktag(skb, msg->msg_control, msg->msg_controllen);
	if(err) {
		kfree_skb(skb);
		return(err);
	}
#endif

	/* XX META in control not supported */
	VNB_ENTER();
	err = ngd_send(sock, 0 /* flags not used */, skb, nam, NULL, meta);
	VNB_EXIT();

	if (err == 0)
		err = size;
	else if (err > 0)
		err = -err;
	else printk("ngd_send return Invalid error\n");
	return err;
}


/*
 * common
 */

/*
 *	This does sockname. peername ?
 */

static int vnb_getname(struct socket *sock, struct sockaddr *uaddr,
		 int *uaddr_len, int peer)
{
	struct sock *sk		= sock->sk;
	struct sockaddr_ng *sg	= (struct sockaddr_ng *)uaddr;
	node_p node;
	int error = 0;

	if (*uaddr_len < (int)sizeof(struct sockaddr_ng)) {
		printk(KERN_WARNING "VNB: vnb_getname() - invalid length %u\n",
				*uaddr_len);
		return -EINVAL;
	}

	lock_sock(sk);
	vnb_rcu_read_lock();
	VNB_ENTER();
	node = rcu_dereference(((struct vnb_sock *)sk)->node);
	if (node == NULL) {
		error = -EINVAL;
		goto release;
	}

        if ((node->name != NULL) &&
	    (strlcpy(sg->sg_data, node->name,
		     sizeof(sg->sg_data)) >= sizeof(sg->sg_data))) {
		printk(KERN_WARNING "VNB: vnb_getname() - node name too long"
				", truncated to \"%s\"", sg->sg_data);
	} else
		sg->sg_data[0] = '\0';

	sg->sg_len = strlen(sg->sg_data) + 3;
	sg->sg_family = AF_NETGRAPH;

	*uaddr_len = sizeof(*sg);
release:
	VNB_EXIT();
	vnb_rcu_read_unlock();
	release_sock(sk);

	return(error);
}

/*
 * init
 */

struct proto_ops vnbc_dgram_ops = {
	family:		PF_NETGRAPH,

	release:	vnbc_release,
	bind:		vnbc_bind,
	connect:	vnbc_connect,
	socketpair:	sock_no_socketpair,
	accept:		sock_no_accept,
	getname:	vnb_getname,
	poll:		datagram_poll,
	ioctl:		sock_no_ioctl,
	listen:		sock_no_listen,
	shutdown:	sock_no_shutdown,
	setsockopt:	sock_no_setsockopt,
	getsockopt:	sock_no_getsockopt,
	sendmsg:	vnbc_sendmsg,
	recvmsg:	vnb_recvmsg,
	mmap:		sock_no_mmap,
	sendpage:	sock_no_sendpage,
};

struct proto_ops vnbd_dgram_ops = {
	family:		PF_NETGRAPH,

	release:	vnbd_release,
	bind:		sock_no_bind,
	connect:	vnbd_connect,
	socketpair:	sock_no_socketpair,
	accept:		sock_no_accept,
	getname:	vnb_getname,
	poll:		datagram_poll,
	ioctl:		sock_no_ioctl,
	listen:		sock_no_listen,
	shutdown:	sock_no_shutdown,
	setsockopt:	sock_no_setsockopt,
	getsockopt:	sock_no_getsockopt,
	sendmsg:	vnbd_sendmsg,
	recvmsg:	vnb_recvmsg,
	mmap:		sock_no_mmap,
	sendpage:	sock_no_sendpage,
};


static void vnb_sock_destruct(struct sock *sk)
{
	/* Delete all skbuffs in &sk->receive_queue and &sk->error_queue lists. */
	skb_queue_purge(&sk->sk_receive_queue);
	skb_queue_purge(&sk->sk_error_queue);

	if (! sock_flag(sk, SOCK_DEAD)) {
                printk(KERN_INFO "Attempt to release alive netgraph socket %p\n", sk);
                return;
        }

        WARN_ON(atomic_read(&sk->sk_rmem_alloc));
        WARN_ON(atomic_read(&sk->sk_wmem_alloc));
        WARN_ON(sk->sk_wmem_queued);
        WARN_ON(sk->sk_forward_alloc);

	dst_release(sk->sk_dst_cache);

#ifdef VNB_REFCNT_DEBUG
	atomic_dec(&vnb_sock_nr);
	printk(KERN_DEBUG "NETGRAPH socket %p released, %d are still alive\n", sk, atomic_read(&vnb_sock_nr));
#endif
}

/*
 *	Create a vnb socket.
 */

#ifdef RHEL_RELEASE_CODE
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,2)
static int vnb_create(struct net *net, struct socket *sock, int protocol, int kern)
#endif
#elif LINUX_VERSION_CODE >=  KERNEL_VERSION(2,6,33)
static int vnb_create(struct net *net,struct socket *sock, int protocol, int kern)
#else
static int vnb_create(struct net *net,struct socket *sock, int protocol)
#endif
{
	struct sock *sk;
	struct vnb_sock *vsk;
	node_p node = NULL;
	int error = 0;

	sock->state = SS_UNCONNECTED;
	sk = sk_alloc(net,PF_NETGRAPH, GFP_ATOMIC, &vnb_proto);
	if (sk == NULL)
		goto do_oom;

	/* Look for the requested type/protocol pair. */

	if (sock->type != SOCK_DGRAM)
		goto free_and_badtype;
	if (!protocol)
		goto free_and_noproto;

	if ((protocol != NG_CONTROL) && (protocol != NG_DATA))
		goto free_and_badtype;

	/* sock_init_data() sets sk refcount to 1. */
	sock_init_data(sock, sk);

	sk->sk_destruct = vnb_sock_destruct;
	sk->sk_backlog_rcv = NULL;
	sk->sk_state = 0;
	sk->sk_type = SOCK_DGRAM;
	sk->sk_family = PF_NETGRAPH;
	sk->sk_protocol	= protocol;

	vsk = (struct vnb_sock *)sk;
	rcu_assign_pointer(vsk->node, NULL);
	atomic_set(&vsk->update, 0);
	atomic_set(&vsk->remove, 0);

	ng_socket_lock_acquire();
	switch(protocol) {
	case NG_CONTROL:
		sock->ops = &vnbc_dgram_ops;
		/* Create ng_socket. */
		if (ng_create_socket(&node)) {
			error = ENOMEM;
			break;
		}
		/* Attach socket to ng_socket node. */
		error = ng_attach_cntl(node, vsk);
		if (error) {
			ng_rmnode(node);
			node = NULL;
		}
		break;
	case NG_DATA:
		sock->ops = &vnbd_dgram_ops;
		error = 0;
		break;
	}
	ng_socket_lock_release();
	if(error) {
		sk_free(sk);
		return -error;
	}

	sock_reset_flag(sk, SOCK_ZAPPED);

#ifdef VNB_REFCNT_DEBUG
	atomic_inc(&vnb_sock_nr);
#endif
	return 0;

free_and_badtype:
	sk_free(sk);
	VNB_TRAP("ESOCKTNOSUPPORT");
	return -ESOCKTNOSUPPORT;
/*
free_and_badperm:
	sk_free(sk);
	return -EPERM;
*/
free_and_noproto:
	VNB_TRAP("EPROTONOSUPPORT");
	sk_free(sk);
	return -EPROTONOSUPPORT;

do_oom:
	VNB_TRAP("ENOBUFS");
	return -ENOBUFS;
}


/*
 *	Called by socket.c on kernel startup.
 */

struct net_proto_family vnb_family_ops = {
	family:	PF_NETGRAPH,
	create:	vnb_create,
	.owner	=	THIS_MODULE,
};

static int
vnb_gifconf(struct net_device *dev, char *buf, int len) {
	/* called by ifconfig */
	return 0;
}

static int __init vnb_socket_init_module(void)
{
	int error = EINVAL;
	enum {
		VNB_INIT_SOCK = 0x01,
		VNB_INIT_PROTO = 0x02,
		VNB_INIT_NETDEV = 0x04
	} deinit_vnb = 0;

	if ((error = ng_socket_init())) {
		return error;
	}

	ng_socket_lock_init();

	register_gifconf(PF_NETGRAPH, vnb_gifconf);

	deinit_vnb |= VNB_INIT_NETDEV;

        /* register proto */
        if ((error = proto_register(&vnb_proto, 0)) != 0)
		goto error;
	deinit_vnb |= VNB_INIT_PROTO;

	/*
	 *	Tell SOCKET that we are alive...
	 */

        if ((error = sock_register(&vnb_family_ops)) != 0)
		goto error;
	deinit_vnb |= VNB_INIT_SOCK;

	return 0;
error:
	if (deinit_vnb & VNB_INIT_SOCK)
		sock_unregister(PF_NETGRAPH);
	if (deinit_vnb & VNB_INIT_PROTO)
		proto_unregister(&vnb_proto);
	if (deinit_vnb & VNB_INIT_NETDEV) {
		register_gifconf(PF_NETGRAPH, NULL);
	}
	printk(KERN_INFO "VNB: init failed (%d)\n", error);
	return -error;
}

static void vnb_socket_exit_module(void)
{
	/* First of all disallow new sockets creation. */
	/* and remove net_family[PF_NETGRAPH]->create dumb pointer */

	sock_unregister(PF_NETGRAPH);

        proto_unregister(&vnb_proto);
	register_gifconf(PF_NETGRAPH, NULL);

	ng_socket_exit();
}

module_init(vnb_socket_init_module);
module_exit(vnb_socket_exit_module);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB socket module");
MODULE_LICENSE("6WIND");
