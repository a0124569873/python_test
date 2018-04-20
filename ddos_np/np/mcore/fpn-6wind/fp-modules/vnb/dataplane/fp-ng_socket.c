/*
 * Copyright(c) 2007 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"

#include "fp-netfpc.h"

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>

#include "vnb_config.h"

#include "fp-ng_iface.h"
#include "fp-ng_socket.h"
#include "fp-ng_ether.h"
#include "fp-ng_eiface.h"
#include "fp-ng_message.h"
#include "fp-module.h"
#include "fpn-shmem.h"
#include "fp-test-fpn0.h"

FPN_DEFINE_SHARED(node_p, ngc_node) = NULL;

FPN_DEFINE_SHARED(fp_vnb_shared_mem_t *, fp_vnb_shared);

/* socket private data */
struct ng_socket_private {
	node_p node;
	FPN_LIST_ENTRY(ng_socket_private) next;
};

typedef struct ng_socket_private *priv_p;

/* socket_list */
FPN_LIST_HEAD(ng_socket_list, ng_socket_private);

#if defined(CONFIG_MCORE_SOCKET_HASH_ORDER)
#define SOCKET_HASH_ORDER CONFIG_MCORE_SOCKET_HASH_ORDER
#else
#define SOCKET_HASH_ORDER 11
#endif
#define SOCKET_HASH_SIZE        (1 << SOCKET_HASH_ORDER)

/* a hashtable is used as we have many socket nodes in fastpath */
FPN_DEFINE_SHARED(struct ng_socket_list,  ng_socket_node_list_ns[VNB_MAX_NS][SOCKET_HASH_SIZE]);

static ng_newhook_t  ng_socket_newhook;
static ng_rcvdata_t  ng_socket_rcvdata;
static ng_shutdown_t ng_socket_rmnode;

/* Netgraph type descriptor */
static FPN_DEFINE_SHARED(struct ng_type, typestruct) = {
	.version = NG_VERSION, 
	.name = NG_SOCKET_NODE_TYPE,
	.newhook = ng_socket_newhook,
	.rcvdata = ng_socket_rcvdata,
	.rcvdataq = ng_socket_rcvdata,
	.shutdown = ng_socket_rmnode
};

extern int ng_etf_init(void);
extern int ng_base_init(void);
extern int ng_vlan_init(void);
extern int ng_bridge_init(void);
extern int ng_vrrp_mux_init(void);
extern int ng_gre_init(void);
extern int ng_iface_init(void);
extern int ng_ksocket_init(void);
extern int ng_ethgrp_init(void);
extern int ng_tee_init(void);
extern int ng_div_init(void);
extern int ng_split_init(void);
extern int ng_one2many_init(void);
#ifdef CONFIG_VNB_NODE_MPLS
extern int ng_mpls_ilm2nhlfe_init(void);
extern int ng_mpls_nhlfe_init(void);
extern int ng_mpls_ether_init(void);
extern int ng_mpls_oam_init(void);
#endif
extern int ng_nffec_init(void);
extern int ng_mux_init(void);
extern int ng_etherbridge_init(void);
extern int ng_gen_init(void);
extern int ng_gtpu_init(void);
extern int ng_l2tp_init(void);
extern int ng_ppp_init(void);
extern int ng_pppoe_init(void);
extern int ng_pppchdlcdetect_init(void);
extern int ng_cisco_init(void);
extern int ng_ddos_init(void);

static priv_p ng_socket_lookup_by_id(uint32_t nodeid);
static node_p ng_socket_new(uint32_t nodeid, struct ngm_name *nm);

#if VNB_WITH_MSG_POST
#include "fpn-lock.h"
static FPN_DEFINE_SHARED(fpn_spinlock_t, ng_socket_lock);
static FPN_DEFINE_SHARED(int, ng_socket_lock_core_owner) = (int) -1;

#define ng_socket_lock_init() \
	fpn_spinlock_init(&ng_socket_lock)

#define ng_socket_lock_acquire() do {					\
		fpn_spinlock_lock(&ng_socket_lock);			\
		ng_socket_lock_core_owner = fpn_get_core_num();	\
	} while (0)

#define ng_socket_lock_release() do {			\
		ng_socket_lock_core_owner = (int) -1;	\
		fpn_spinlock_unlock(&ng_socket_lock);	\
	} while (0)

void ng_post_msg(node_p node, struct ng_mesg *msg)
{
	if (ng_socket_lock_core_owner == fpn_get_core_num()) {
		(void) ng_send_msg(node, msg, ".", NULL, NULL);
		return;
	}
	ng_socket_lock_acquire();
	(void) ng_send_msg(node, msg, ".", NULL, NULL);
	ng_socket_lock_release();
}
#endif /* NG_WITH_MSG_POST */

static void* fp_vnb_shared_alloc(void)
{
	void *addr;

	/* Create fp-vnb-shared memory. Ignore error, it may already
	 * exist.
	 */
	fpn_shmem_add("fp-vnb-shared", sizeof(fp_vnb_shared_mem_t));
	addr = fpn_shmem_mmap("fp-vnb-shared", NULL, sizeof(fp_vnb_shared_mem_t));
	if (addr == NULL) {
		fpn_printf("cannot map fp_vnb_shared size=%"PRIu64" (%"PRIu64"M)\n",
		           (uint64_t)sizeof(fp_vnb_shared_mem_t),
		           (uint64_t)sizeof(fp_vnb_shared_mem_t) >> 20);
		return NULL;
	}
	fpn_printf("Using fp_vnb_shared=%p size=%"PRIu64" (%"PRIu64"M)\n",
		   addr, (uint64_t)sizeof(fp_vnb_shared_mem_t),
		   (uint64_t)sizeof(fp_vnb_shared_mem_t) >> 20);

	return addr;
}

static void vnb_dump_lists_infos(void)
{
	uint16_t ns = 0;

	for (ns = 0 ; ns < VNB_MAX_NS; ns++)
		fpn_printf("Total Nodes in activity for ns%d: %u\n", ns, per_ns(gNumNodes, ns));
#if VNB_DEBUG
	fpn_printf("Total Pointers in activity: %u\n", vnb_atomic_read(&gNumPtrs));
	fpn_printf("Total Pointers in Free list: %u\n", vnb_atomic_read(&gFreeNumPtrs));
	fpn_printf("Total core in VNB: %u\n", fpn_core_read_cores_in());
#endif
}

static int ng_socket_rmnode(node_p node)
{
	const priv_p priv = node->private;

	ng_cutlinks(node);
	if (priv) {
		/* dynamically nodes created by synchronization of CP
		 * nodes */
		FPN_LIST_REMOVE(priv, next);
		NG_NODE_SET_PRIVATE(node, NULL);
		ng_free(priv);
		ng_unname(node);
		ng_unref(node);
	}
	else {
		/* static fastpath node, never remove it */
		node->flags &= ~NG_INVALID;     /* bounce back to life */
	}
	return 0;
}

/*
 * VNB control messages format:
 * 
 * mtod(m, char*)                         size:
 *      ---> ----------------------------
 *           |  fp_hdr                  | NG_FP_HDR_SIZE + (fp_hdr->len << 2)
 *           ----------------------------
 *           |  struct ng_mesg          | sizeof(struct ng_mesg)  
 * [OPTIONAL]----------------------------                        
 *           |  ng_msg ->data           | ng_msg->header.arglen  
 *           ----------------------------
 */

 /* max size of a fragment */
#define MSG_MAX_LEN(size) ((size) - NETFPC_HDRSIZE - \
		     sizeof(struct fp_ip6_hdr) - \
		     sizeof(struct fp_ether_header))

static void ship_msg(struct mbuf *m, struct ng_mesg *resp, int error, 
		     struct fp_netfpc_ctx *ctx)
{
	ng_fp_hdr_t *fp_hdr_query, *fp_hdr_resp;
	char *msg_resp;
	unsigned int fp_hdr_len, mbuf_len;
	int total_msglen, msglen, msgoff=0;
	struct mbuf *m_resp;
	int frag_size;

	TRACE_VNB(FP_LOG_INFO, "ship msg resp=%p, error=%d arglen=%d", 
		  resp, error, resp ? resp->header.arglen : 0);

	/* get headers of original query */
	/* m->data starts with original fp_hdr */
	fp_hdr_query = mtod(m, ng_fp_hdr_t *);
	fp_hdr_len = NG_FP_HDR_SIZE + (fp_hdr_query->len << 2);

	/* message size */
	if (resp)
		total_msglen = sizeof(struct ng_mesg) + resp->header.arglen;
	else
		total_msglen = 0;

	do {
		/* alloc mbuf */
		m_resp = m_alloc();
		if (!m_resp) {
			m_freem(m); /* free incoming mbuf and return */
			return;
		}

		/* guess mbuf len, maybe we will have to fragment */
		mbuf_len = fp_hdr_len + total_msglen;

		/* fragment if needed */
		frag_size = m_tailroom(m_resp);
		/* we could use ifp->mtu XXX */
		if (frag_size > 1514)
			frag_size = 1514;
		if (mbuf_len > MSG_MAX_LEN(frag_size))
			mbuf_len = MSG_MAX_LEN(frag_size);

		msglen = (mbuf_len - fp_hdr_len); /* len of data embedded in this packet */

		/* Reserve room */
		fp_hdr_resp = (ng_fp_hdr_t *) m_append(m_resp, fp_hdr_len + msglen);
		if (!fp_hdr_resp) {
			m_freem(m);
			m_freem(m_resp);
			return;
		}

		/* FP HDR */
		fp_hdr_resp->len = (fp_hdr_len - NG_FP_HDR_SIZE) >> 2;
		fp_hdr_resp->error= error;
		if (fp_hdr_resp->len) /* path in first frag only */
			fpn_memcpy(fp_hdr_resp->path, fp_hdr_query->path, fp_hdr_resp->len << 2);
		if (total_msglen-msglen == 0)
			fp_hdr_resp->last_frag = 1;
		else
			fp_hdr_resp->last_frag = 0;
				
		fp_hdr_resp->offset = msgoff;

		/* RESP */
		msg_resp = ((char *)fp_hdr_resp) + fp_hdr_len;

		if (resp)
			fpn_memcpy(msg_resp, ((char *)resp) + msgoff, msglen);

		/* send to slow path */
		m_priv(m_resp)->ifuid = m_priv(m)->ifuid;
		set_mvrfid(m_resp, m2vrfid(m));
		TRACE_VNB(FP_LOG_DEBUG, "resp MLEN = %d, m->data = %p", 
			  m_len(m_resp), mtod(m_resp, char *));

		fp_netfpc_output(m_resp, ctx);

		/* prepare vars for next iteration */
		fp_hdr_len = NG_FP_HDR_SIZE;
		msgoff += msglen;
		total_msglen -= msglen;
	}
	while(total_msglen > 0);
	
	if (resp) 
		FREE(resp, M_NETGRAPH);
	m_freem(m);
}

/*
 * We allow any hook to be connected to the node.
 * There is no per-hook private information though.
 */
static int
ng_socket_newhook(node_p node, hook_p hook, const char *name)
{
	hook->private = node->private;
	return (0);
}

static int
ng_socket_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	struct ng_socket_private *sockdata = hook->node_private;

	if (!sockdata || !sockdata->node || !sockdata->node->name) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	return ng_send_exception(sockdata->node, hook, VNB2VNB_DATA, 0, m, meta);
}

int vnb_ifattach(uint32_t ifuid, uint32_t nodeid)
{
	int ret = 0;
	fp_ifnet_t *ifp;

	ifp = fp_ifuid2ifnet(ifuid);
	if (ifp == NULL)
		return ENOENT;

	if (FP_IS_IFTYPE_ETHER(ifp->if_type)) {
		ret = ng_ether_attach(ifp, nodeid);
		if (!ret)
			ret = ng_eiface_attach(ifp);
	}
#ifdef CONFIG_MCORE_IP
	else if (ifp->if_type == FP_IFTYPE_LOCAL) {
		ret = ng_iface_attach(ifp);
	}
#endif

	return ret;
}

int vnb_ifdetach(uint32_t ifuid, uint8_t vnb_keep_node)
{
	int ret = 0;
	fp_ifnet_t *ifp;

	ifp = fp_ifuid2ifnet(ifuid);
	if (ifp == NULL)
		return ENOENT;

	if (FP_IS_IFTYPE_ETHER(ifp->if_type)) {
		ret = ng_ether_detach(ifp, vnb_keep_node);
		if (!ret)
			ret = ng_eiface_detach(ifp, vnb_keep_node);
	}
#ifdef CONFIG_MCORE_IP
	else if (ifp->if_type == FP_IFTYPE_LOCAL) {
		ret = ng_iface_detach(ifp, vnb_keep_node);
	}
#endif

	return ret;
}

extern void ng_exit(void);

static int vnb_reset(struct mbuf *m, struct fp_netfpc_ctx *ctx)
{
	ng_exit();
	m_freem(m);
	return 0;
}

static
node_p vnb_gr_get_node(struct ng_nl_node *nlnode)
{
	node_p node;
	uint32_t id = ntohl(nlnode->id);

	node = ng_ID2node(id);

	if (node == NULL) {
		/* socket is a particular case, use ng_socket_new */
		if (!strncmp(nlnode->type, "socket", sizeof(nlnode->type)))
			node = ng_socket_new(id, NULL);
		else if (!strncmp(nlnode->type, "ether", sizeof(nlnode->type))) {
			fp_ifnet_t *ifp;

			/* it might happen that interface has been created */
			if ((ifp = fp_getifnetbyname(nlnode->name)) != NULL)
				ng_ether_attach(ifp, id);

			node = ng_ID2node(id);
		} else
			ng_make_node(nlnode->type, &node, id);

		if (!node) {
			TRACE_VNB(FP_LOG_DEBUG, "%s: ng_make_node failed for node %s\n", __func__, nlnode->name);
			return NULL;
		}

		if (node->name == NULL)
			ng_name_node(node, nlnode->name);
	}

	return node;
}

static
hook_p vnb_gr_get_hook(struct ng_nl_hook *nlhook, node_p node)
{
	int err;
	hook_p hook;
	node_p peernode = NULL;
	hook_p peer;

	/* if we already have a valid hook, nothing to do */
	if ((hook = ng_findhook(node, nlhook->name)) != NULL)
		return hook;

	err = ng_add_hook(node, nlhook->name, &hook);

	if (err && err != EEXIST) {
		TRACE_VNB(FP_LOG_ERR, "%s: ng_add_hook failed\n", __func__);
		return NULL;
	}

	peernode = ng_ID2node(ntohl(nlhook->peernodeid));

	/* try to connect the nodes only */
	if (peernode) {
		peer = ng_findhook_inval(peernode, nlhook->peername);
		if (peer) {
			err = ng_connect(hook, peer);
			if (err)
				TRACE_VNB(FP_LOG_ERR, "%s: ng_connect failed\n", __func__);
		}
	}

	return hook;
}

#define GET_NEXT_ATTR(vnb_msg) ((struct netfpc_vnbdump_attr *)		\
				((char*)vnb_msg +			\
				 FPN_ALIGN4(ntohl(vnb_msg->len) +	\
					    sizeof(struct netfpc_vnbdump_attr))))


enum {
	CMD_VNB_NONE = 0,
	CMD_VNB_NODE,
	CMD_VNB_NODE_PRIV,
	CMD_VNB_STATUS,
	CMD_VNB_HOOK,
	CMD_VNB_HOOK_PRIV,
	CMD_VNB_MAX,
};

static int vnb_gr_start(struct mbuf *m, struct fp_netfpc_ctx *ctx)
{
	/* We don't know what sequence number the CP has, put
	   it to 0 (undefined) */
	fp_vnb_shared->expected_seqnum = 0;

#if CONFIG_MCORE_VNB_MAX_NS > 1
	/* Switch to control namespace that will be used... */
	ctrl_vnb_ns = (fp_vnb_shared->data_ns + 1) % VNB_MAX_NS;
#endif

	/* ...and flush it */
	ng_ns_exit(ctrl_vnb_ns);

	return 0;
}

static int vnb_receive_dump_msg(struct mbuf *m, struct fp_netfpc_ctx *ctx)
{
	struct netfpc_vnbdump_msg *msg;
	struct netfpc_vnbdump_attr *attr;
	void *large_buf = NULL;
	size_t len;
	int attr_count = 0;
	node_p node;
	hook_p hook = NULL;

	struct ng_nl_status *nlstatus;
	struct ng_nl_node *nlnode;
	struct ng_nl_nodepriv *nlnodepriv;
	struct ng_nl_hook *nlhook;
	struct ng_nl_hookpriv *nlhookpriv;

	if (unlikely(!m_is_contiguous(m))) {
		MALLOC(large_buf, void *, m_len(m), M_NETGRAPH, M_WAITOK);
		if (!large_buf) {
			TRACE_VNB(FP_LOG_ERR, "FPVNB: Unable to allocate %u bytes\n", m_len(m));
			goto done;
		}

		m_copytobuf(large_buf, m, 0, m_len(m));
		msg = (struct netfpc_vnbdump_msg *) large_buf;
	} else {
		if ((m = m_pullup(m, sizeof(struct netfpc_vnbdump_msg))) == NULL) {
			TRACE_VNB(FP_LOG_ERR, "FPVNB: too short message\n");
			goto done;
		}

		msg = mtod(m, struct netfpc_vnbdump_msg *);
	}

	attr_count = ntohl(msg->attr_count);
	len = ntohl(msg->len);
	(void)len; /* Inform the compiler that len can be never read */

	TRACE_VNB(FP_LOG_DEBUG, "FPVNB: dump msg contains %d attr - len=%zu\n", attr_count, len);

	attr = (struct netfpc_vnbdump_attr *) (msg + 1);

	/* is it a status message? */
	if (ntohl(attr->type) != CMD_VNB_STATUS) {
		TRACE_VNB(FP_LOG_ERR, "FPVNB: attr type should be CMD_VNB_STATUS\n");
		goto done;
	}

	nlstatus = (struct ng_nl_status *) attr->data;

	if (ntohl(nlstatus->count) == 1) {
		TRACE_VNB(FP_LOG_DEBUG, "FPVNB: VNB DUMP START in namespace %d\n", ctrl_vnb_ns);
	} else {
		if (ntohl(nlstatus->count) == ntohl(nlstatus->total_count)) {
			TRACE_VNB(FP_LOG_DEBUG, "FPVNB: VNB DUMP END (%d attr)\n",
				ntohl(nlstatus->count));
		} else {
			TRACE_VNB(FP_LOG_DEBUG, "FPVNB: VNB DUMP %d/%d\n",
				ntohl(nlstatus->count),
				ntohl(nlstatus->total_count));
		}
	}

	attr = GET_NEXT_ATTR(attr);
	attr_count--;

	/* else first message must describe the node */
	if (ntohl(attr->type) != CMD_VNB_NODE) {
		TRACE_VNB(FP_LOG_ERR, "FPVNB: attr type should be CMD_VNB_NODE\n");
		goto done;
	}

	/* create the node */
	nlnode = (struct ng_nl_node *) attr->data;
	node = vnb_gr_get_node(nlnode);

	if (!node) {
		TRACE_VNB(FP_LOG_DEBUG, "FPVNB: vnb_gr_get_node failed\n");
		goto skip;
	}

	TRACE_VNB(FP_LOG_DEBUG, "FPVNB: node %s[%x] - %s\n", node->name, node->ID, node->type->name);

	attr = GET_NEXT_ATTR(attr);
	attr_count--;

	while (attr_count > 0) {
		switch (ntohl(attr->type)) {
		case CMD_VNB_NODE_PRIV:
			nlnodepriv = (struct ng_nl_nodepriv *) attr->data;
			if (node && node->type && node->type->restorenode)
				node->type->restorenode(nlnodepriv, node);
			else
				TRACE_VNB(FP_LOG_DEBUG, "FPVNB:  priv len=%d ignored\n",
					  ntohl(nlnodepriv->data_len));
			break;
		case CMD_VNB_HOOK:
			nlhook = (struct ng_nl_hook *) attr->data;
			hook = vnb_gr_get_hook(nlhook, node);
			if (hook) {
				if (hook->flags & HK_INVALID)
					TRACE_VNB(FP_LOG_DEBUG, "FPVNB:   hook %s <-X-> [%x]:%s\n",
						  hook->name, ntohl(nlhook->peernodeid), nlhook->peername);
				else
					TRACE_VNB(FP_LOG_DEBUG, "FPVNB:   hook %s <---> %s[%x]:%s\n",
						  hook->name, hook->peer->node->name, hook->peer->node->ID, hook->peer->name);
			} else
				TRACE_VNB(FP_LOG_ERR, "FPVNB:   could not add hook %s\n", nlhook->name);
			break;
		case CMD_VNB_HOOK_PRIV:
			nlhookpriv = (struct ng_nl_hookpriv *) attr->data;
			/* XXX: applies to last hook... we could put
			   the name of node + name of hook to be
			   sure */
			if (node && node->type && node->type->restorehook)
				node->type->restorehook(nlhookpriv, node, hook);
			else
				TRACE_VNB(FP_LOG_DEBUG, "FPVNB:    hook priv len=%d ignored\n", ntohl(attr->len));
			break;
		default:
			TRACE_VNB(FP_LOG_DEBUG, "FPVNB:    attribute %d not supported\n", ntohl(attr->type));
			break;
		}
		attr = GET_NEXT_ATTR(attr);
		attr_count--;
	}

skip:
#if CONFIG_MCORE_VNB_MAX_NS > 1
	if (ntohl(nlstatus->count) == ntohl(nlstatus->total_count))
		fp_vnb_shared->data_ns = ctrl_vnb_ns;
#endif

done:
	if (large_buf)
		FREE(large_buf, M_NETGRAPH);

	m_freem(m);

	return 0;
}

static int vnb_receive_msg(struct mbuf *m, struct fp_netfpc_ctx *ctx)
{
	struct ng_mesg *msg = NULL;
	char *path = NULL;
	struct ng_mesg *resp = NULL;
	ng_fp_hdr_t *fp_hdr;
	int path_len;
	int error = 0;
	int msglen;
	priv_p priv;

	MALLOC(path, char *, NG_PATHLEN + 1, M_NETGRAPH, M_WAITOK);
	if (path == NULL) {
		error = ENOMEM;
		goto send_reply;
	}
	memset(path, 0, NG_PATHLEN + 1);
	fp_hdr = mtod(m, ng_fp_hdr_t *);
	path_len = fp_hdr->len << 2;
	msglen = m_len(m) - (NG_FP_HDR_SIZE + path_len);
	if ((path_len >= NG_PATHLEN) || (msglen <= 0)) {
		error = EINVAL;
		goto send_reply;
	}

	fpn_memcpy(path, fp_hdr->path, path_len);
	path[path_len] = '\0';

	TRACE_VNB(FP_LOG_DEBUG, "path = %s", path);

	MALLOC(msg, struct ng_mesg *, msglen, M_NETGRAPH, M_WAITOK);
	if (msg == NULL) {
		error = ENOMEM;
		goto send_reply;
	}

	m_copytobuf(msg, m, NG_FP_HDR_SIZE + path_len, msglen);

	TRACE_VNB(FP_LOG_DEBUG, "arglen=%d typecookie=%d cmd=%d",
		  msg->header.arglen,
		  msg->header.typecookie,
		  msg->header.cmd);

#if VNB_WITH_MSG_POST
	ng_socket_lock_acquire();
#endif

	/* process socket node's messages */
	if (msg->header.typecookie == NGM_SOCKET_COOKIE) {
		if (msg->header.cmd == NGM_SOCKET_CREATE) {
			ng_socket_new(msg->header.nodeid,
				      msg->header.arglen ? (struct ngm_name *)msg->data : NULL);
		}
		else if (msg->header.cmd == NGM_SOCKET_DELETE) {
			priv = ng_socket_lookup_by_id(msg->header.nodeid);
			if (priv)
				ng_rmnode(priv->node);
		}
		else {
			error = EINVAL;
		}
		goto send_reply_lock_release;
	}

	/* process others than socket node */

	/* find socket node that is the reference for relative path */
	priv = ng_socket_lookup_by_id(msg->header.nodeid);

	/* the node does not exist in FP, but it should, create it */
	if (priv == NULL && msg->header.nodeid != 0) {
		node_p node;
		node = ng_socket_new(msg->header.nodeid, NULL);
		if (node)
			priv = node->private;
	}
	if (priv) {
		/* use a specific socket node as reference */
		error = ng_send_msg(priv->node, msg, path, &resp, NULL); // free msg
	} else {
		/* use the static socket node as reference */
		error = ng_send_msg(ngc_node, msg, path, &resp, NULL); // free msg
	}
	msg = NULL;

send_reply_lock_release:

#if VNB_WITH_MSG_POST
	ng_socket_lock_release();
#endif

send_reply:
	/* If the callee responded with a synchronous response, then
	 * put it back on the receive side of the socket; anyway,
	 * there is always at least the error code in the receive
	 * message. Path is still stored in mbuf. */
	ship_msg(m, resp, error, ctx); /* free m */

	if (path)
		FREE(path, M_NETGRAPH);
	if (msg)
		FREE(msg, M_NETGRAPH);

	return 0;
}

static int vnb_receive_data_msg(struct mbuf *m, struct fp_netfpc_ctx *ctx)
{
	TRACE_VNB(FP_LOG_NOTICE, "Data port not implemented");
	m_freem(m);
	return 0;
}

static int vnb_newif(struct mbuf *m, struct fp_netfpc_ctx *ctx)
{
	struct netfpc_if_msg *if_msg = mtod(m, struct netfpc_if_msg *);
	int ret = 0;
	uint32_t ifuid = if_msg->ifuid;
	uint32_t vnb_nodeid = ntohl(if_msg->vnb_nodeid);

	TRACE_VNB(FP_LOG_INFO, "netfpc vnb newif");
	ret = vnb_ifattach(ifuid, vnb_nodeid);

	/* set error code for the message ack */
	if (ret)
		if_msg->error = htonl(ret);

	return 0;
}

static int vnb_delif(struct mbuf *m, struct fp_netfpc_ctx *ctx)
{
	struct netfpc_if_msg *if_msg = mtod(m, struct netfpc_if_msg *);
	int ret = 0;
	uint32_t ifuid = if_msg->ifuid;
	uint8_t keep_node = if_msg->vnb_keep_node;

	TRACE_VNB(FP_LOG_INFO, "netfpc vnb delif");
	ret = vnb_ifdetach(ifuid, keep_node);

	/* set error code for the message ack */
	if (ret)
		if_msg->error = htonl(ret);

	return 0;
}

static priv_p ng_socket_lookup_by_id(uint32_t nodeid)
{
	priv_p priv;
	const u_int32_t hash = nodeid & (SOCKET_HASH_SIZE-1);

	FPN_LIST_FOREACH(priv, &per_ns(ng_socket_node_list, ctrl_vnb_ns)[hash], next) {
		if (nodeid == priv->node->ID) {
			return priv;
		}
	}

	return NULL;
}

static node_p ng_socket_new(uint32_t nodeid, struct ngm_name *nm)
{
	priv_p priv, tmp;
	node_p node;
	const u_int32_t hash = nodeid & (SOCKET_HASH_SIZE-1);

	tmp = ng_socket_lookup_by_id(nodeid);
	if (tmp)
		return tmp->node;

	/* Allocate private structure */
	priv = ng_malloc(sizeof(*priv), M_NOWAIT);
	if (priv == NULL)
		return NULL;
	bzero(priv, sizeof(*priv));

	if (ng_make_node_common(&typestruct, &node, nodeid) != 0) {
		FREE(priv, M_NETGRAPH);
		return NULL;
	}

	FPN_LIST_INSERT_HEAD(&per_ns(ng_socket_node_list, ctrl_vnb_ns)[hash], priv, next);

	priv->node = node;
	if (nm)
		ng_name_node(node, nm->name);
	NG_NODE_SET_PRIVATE(node, priv);

	return node;
}

static FPN_DEFINE_SHARED(fp_netfpc_hook_t, vnb_gr_start_hook) = {
	.func = vnb_gr_start
};
static FPN_DEFINE_SHARED(fp_netfpc_hook_t, vnb_newif_hook) = {
	.func = vnb_newif
};
static FPN_DEFINE_SHARED(fp_netfpc_hook_t, vnb_delif_hook) = {
	.func = vnb_delif
};

static FPN_DEFINE_SHARED(fp_test_fpn0_handler_t, fp_test_fpn0_vnb) = {
	.func = vnb_dump_lists_infos,
	.comment = "Show VNB Garbage Collector Stats",
};

static int ng_on_ifadd(uint16_t vrfid, const char* name,
                            const uint8_t *mac, uint32_t mtu, uint32_t ifuid,
                            uint8_t port, uint8_t type)
{
	return vnb_ifattach(ifuid, 0);
}

static FPN_DEFINE_SHARED(fp_if_notifier_t, vnb_if_notifier) = {
	.add = ng_on_ifadd,
};

static void vnb_init(void);

static struct fp_mod vnb_mod = {
	.name = "vnb",
	.init = vnb_init,
	.if_ops = {
		[RX_DEV_OPS] = ng_ether_input,
		[TX_DEV_OPS] = ng_eiface_output,
		[IP_OUTPUT_OPS] = ng_iface_output,
	},
};

FPN_DEFINE_SHARED(uint16_t, vnb_moduid);

static void vnb_init(void)
{
	void *type = &typestruct;
	uint32_t ns, i;
	int error;

	/* Store module uid */
	vnb_moduid = vnb_mod.uid;

	fp_netfpc_register(NETFPC_MSGTYPE_VNB, vnb_receive_msg);
	fp_netfpc_register(NETFPC_MSGTYPE_VNBDATA, vnb_receive_data_msg);
	fp_netfpc_register(NETFPC_MSGTYPE_VNBDUMP, vnb_receive_dump_msg);
	fp_netfpc_register(NETFPC_MSGTYPE_VNB_RESET, vnb_reset);
	fp_netfpc_add_hook(NETFPC_MSGTYPE_GR_START, &vnb_gr_start_hook);
	fp_netfpc_add_hook(NETFPC_MSGTYPE_NEWIF, &vnb_newif_hook);
	fp_netfpc_add_hook(NETFPC_MSGTYPE_DELIF, &vnb_delif_hook);

	fp_if_notifier_register(&vnb_if_notifier);

	fp_test_fpn0_register(TEST_FPN0_VNB_INFOS, &fp_test_fpn0_vnb);

	FP_LOG_REGISTER(VNB);

	TRACE_VNB(FP_LOG_DEBUG, "Loading VNB module.\n");

	fp_vnb_shared = fp_vnb_shared_alloc();
	if (fp_vnb_shared == NULL) {
		FP_LOG(FP_LOG_ERR, USER, "fp_vnb_shared_alloc error\n");
		return;
	}

	memset(fp_vnb_shared, 0, sizeof(fp_vnb_shared_mem_t));

#if VNB_WITH_MSG_POST
	ng_socket_lock_init();
#endif
	ng_base_init();
	if ((error = ng_newtype(type)) != 0) {
		TRACE_VNB(FP_LOG_ERR, "ng_newtype failed(%d)", error);
		return;
	}

	if ((error = ng_make_node_common(&typestruct, &ngc_node, 0)) != 0) {
		TRACE_VNB(FP_LOG_ERR, "ng_make_node_common failed(%d)", error);
		return;
	}

#if CONFIG_MCORE_VNB_MAX_NS > 1
	/* Reuse last ns as starting one */
	ctrl_vnb_ns = fp_vnb_shared->data_ns;
#endif
	for (ns = 0; ns < VNB_MAX_NS; ns++)
		for (i = 0; i < SOCKET_HASH_SIZE; i++)
			FPN_LIST_INIT(&per_ns(ng_socket_node_list, ns)[i]);

	/* Reset VNB flags and priv pointers on all interfaces */
	for (i = 0 ; i < sizeof(fp_vnb_shared->if_ops)/sizeof(ng_if_ops_t); i++) {
		if (fp_shared->ifnet.table[i].if_ifuid == 0)
			continue;

		/* Manually unregister devops from existing interfaces in shared mem */
		/* In all modules except VNB, ifnet devops are setup by FPM */
		/* so a (re)start of the fastpath must not modify them. VNB devops are */
		/* setup by the fastpath itself, so we must reset them on fastpath */
		/* initialization to avoid a failure when they will be setup after a */
		/* graceful restart */
		if (fp_shared->ifnet.table[i].if_ops[RX_DEV_OPS].mod_uid == vnb_moduid)
			fp_ifnet_ops_unregister(&fp_shared->ifnet.table[i], RX_DEV_OPS);
		if (fp_shared->ifnet.table[i].if_ops[TX_DEV_OPS].mod_uid == vnb_moduid)
			fp_ifnet_ops_unregister(&fp_shared->ifnet.table[i], TX_DEV_OPS);
		if (fp_shared->ifnet.table[i].if_ops[IP_OUTPUT_OPS].mod_uid == vnb_moduid)
			fp_ifnet_ops_unregister(&fp_shared->ifnet.table[i], IP_OUTPUT_OPS);

		memset(fp_vnb_shared->if_ops[i].if_vnb_flags, 0,
		       sizeof(fp_vnb_shared->if_ops[i].if_vnb_flags));
		memset(fp_vnb_shared->if_ops[i].if_vnb_ops, 0,
		       sizeof(fp_vnb_shared->if_ops[i].if_vnb_ops));
	}

	ng_ether_init();
	ng_eiface_init();
#ifdef CONFIG_VNB_NODE_VLAN
	ng_vlan_init();
#endif
#ifdef CONFIG_VNB_NODE_BRIDGE
	ng_bridge_init();
#endif
#ifdef CONFIG_VNB_NODE_VRRP_MUX
	ng_vrrp_mux_init();
#endif
#ifdef CONFIG_VNB_NODE_GRE
	ng_gre_init();
#endif
	ng_iface_init();
	ng_ksocket_init();
#ifdef CONFIG_VNB_NODE_ETHGRP
	ng_ethgrp_init();
#endif
	ng_tee_init();
	ng_div_init();
	ng_split_init();
	ng_one2many_init();
#ifdef CONFIG_VNB_NODE_ETF
	ng_etf_init();
#endif
#ifdef CONFIG_VNB_NODE_MPLS
	ng_mpls_ilm2nhlfe_init();
	ng_mpls_nhlfe_init();
	ng_mpls_ether_init();
	ng_mpls_oam_init();
#endif
#ifdef CONFIG_VNB_NODE_NFFEC
	ng_nffec_init();
#endif
	ng_mux_init();
#ifdef CONFIG_VNB_NODE_ETHERBRIDGE
	ng_etherbridge_init();
#endif
#ifdef CONFIG_VNB_NODE_GEN
	ng_gen_init();
#endif
#ifdef CONFIG_VNB_NODE_GTPU
	ng_gtpu_init();
#endif
#ifdef CONFIG_VNB_NODE_L2TP
	ng_l2tp_init();
#endif
#ifdef CONFIG_VNB_NODE_PPP
	ng_ppp_init();
#endif
#ifdef CONFIG_VNB_NODE_PPPOE
	ng_pppoe_init();
#endif
#ifdef CONFIG_VNB_NODE_PPPCHDLCDETECT
	ng_pppchdlcdetect_init();
#endif
#ifdef CONFIG_VNB_NODE_CISCO
	ng_cisco_init();
#endif

	/* Register other nodes here */
	ng_ddos_init();
}

FP_MOD_REGISTER(vnb_mod)
