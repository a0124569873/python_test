/*
 * Copyright 2011-2013 6WIND S.A.
 */

#if defined(__LinuxKernelVNB__)
#include <linux/version.h>
#include <linux/in6.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>
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
#include <netgraph/vnb_in.h>
#include <netgraph/vnb_ip.h>
#include <netgraph/vnb_udp.h>
#include <netgraph/ng_mpls_common.h>
#include <netgraph/ng_mpls_oam.h>

#ifdef NG_MPLS_OAM_STATS
#define STATS_INC(x, y) do { \
		(x)->stats.y++; \
	} while(0)

#define STATS_ADD(x, y, z) do { \
		(x)->stats.y += z; \
	} while(0)

#endif

#define NG_MPLS_OAM_DEBUG 0
#if NG_MPLS_OAM_DEBUG >= 1
#ifdef __LinuxKernelVNB__
#define NG_MPLS_OAM_DPRINTF(x, y...) do { \
		log(LOG_DEBUG, "%s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#else
/* for now : force DEBUG output */
#define NG_MPLS_OAM_DPRINTF(x, y...) do { \
		FP_LOG(LOG_DEBUG, VNB, "FP %s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#endif
#else
#define NG_MPLS_OAM_DPRINTF(x, y...) do {} while(0)
#endif

/* Per-node private data */
struct ng_mpls_oam_private {
	node_p		mpls_oam_node;     /* back pointer to node */
#ifdef NG_MPLS_OAM_STATS
	/*
	* later : define per-tunnel stats AND per-node stats
	* later : also define per-CPU stats to avoid locking
	*/
	struct ng_mpls_oam_stats	stats;		/* node stats */
#endif
	hook_p		mpls_oam_upper_lsp;    /* pointer to configured upper for LSP packets */
	hook_p		mpls_oam_upper_bfd;    /* pointer to configured upper for BFD packets */
	struct ng_mpls_oam_config config;
};
typedef struct ng_mpls_oam_private *priv_p;

/*
 * Netgraph node methods
 */
static ng_constructor_t ng_mpls_oam_constructor;
static ng_rcvmsg_t      ng_mpls_oam_rcvmsg;
static ng_newhook_t     ng_mpls_oam_newhook;
static ng_shutdown_t    ng_mpls_oam_rmnode;
static ng_disconnect_t  ng_mpls_oam_disconnect;

#if defined(__LinuxKernelVNB__)
static int
ng_mpls_oam_rcvdata_lower_ra(const hook_p hook, struct mbuf *m, meta_p meta);
static int
ng_mpls_oam_rcvdata_lower_ttl(const hook_p hook, struct mbuf *m, meta_p meta);
static int
ng_mpls_oam_rcvdata_lower_ip(const hook_p hook, struct mbuf *m, meta_p meta);
static int
ng_mpls_oam_rcvexception(const hook_p hook, struct mbuf *m, meta_p meta);
#elif defined(__FastPath__)
static int ng_mpls_oam_send_exc(const hook_p hook, struct mbuf *m, meta_p meta);
#endif

/* Local variables */

/* Parse type for struct ng_mpls_config */
static const struct ng_parse_struct_field
	ng_mpls_oam_config_type_fields[] = NG_MPLS_OAM_CONFIG_TYPE_INFO;

static const struct ng_parse_type ng_mpls_oam_config_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_mpls_oam_config_type_fields
};

#ifdef NG_MPLS_OAM_STATS
/* Parse type for struct ng_mpls_oam_stats */
static const struct ng_parse_struct_field
	ng_mpls_oam_stats_type_fields[] = NG_MPLS_OAM_STATS_TYPE_INFO;
static const struct ng_parse_type ng_mpls_oam_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_mpls_oam_stats_type_fields
};
#endif

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_mpls_oam_cmdlist[] = {
	{
		.cookie = NGM_MPLS_OAM_COOKIE,
		.cmd = NGM_MPLS_OAM_SET_CONFIG,
		.name = "setconfig",
		.mesgType = &ng_mpls_oam_config_type,
		.respType = NULL
	},
	{
		.cookie = NGM_MPLS_OAM_COOKIE,
		.cmd = NGM_MPLS_OAM_GET_CONFIG,
		.name = "getconfig",
		.mesgType = NULL,
		.respType = &ng_mpls_oam_config_type
	},
#ifdef NG_MPLS_OAM_STATS
	/* later . = stats per tunnel */
	{
		.cookie = NGM_MPLS_OAM_COOKIE,
		.cmd = NGM_MPLS_OAM_GET_STATS,
		.name = "getstats",
		.mesgType = NULL,
		.respType = &ng_mpls_oam_stats_type
	},
	{
		.cookie = NGM_MPLS_OAM_COOKIE,
		.cmd = NGM_MPLS_OAM_CLR_STATS,
		.name = "clrstats",
		.mesgType = NULL,
		.respType = NULL
	},
	{
		.cookie = NGM_MPLS_OAM_COOKIE,
		.cmd = NGM_MPLS_OAM_GETCLR_STATS,
		.name = "getclrstats",
		.mesgType = NULL,
		.respType = &ng_mpls_oam_stats_type
	},
#endif
	{ 0, 0, NULL, NULL, NULL }
};

/*
 * Node type descriptor
 */
static VNB_DEFINE_SHARED(struct ng_type, ng_mpls_oam_typestruct) = {
	.version = NG_VERSION,
	.name = NG_MPLS_OAM_NODE_TYPE,
	.mod_event = NULL,		  /* module event handler (optional) */
	.constructor = ng_mpls_oam_constructor, /* node constructor */
	.rcvmsg = ng_mpls_oam_rcvmsg,      /* control messages come here */
	.shutdown = ng_mpls_oam_rmnode,      /* reset, and free resources */
	.newhook = ng_mpls_oam_newhook,     /* first notification of new hook */
	.findhook = NULL,		  /* TODO . = for config only if you have lots of hooks */
	.connect = NULL,		  /* final notification of new hook */
	.afterconnect = NULL,
	.rcvdata = NULL,                   /* Generic receive data */
	.rcvdataq = NULL,                   /* Only specific receive data */
	.disconnect = ng_mpls_oam_disconnect,  /* notify on disconnect */
#if defined(__LinuxKernelVNB__)
	.rcvexception = ng_mpls_oam_rcvexception, /* exceptions come here */
#else
	.rcvexception = NULL,                 /* exceptions come here */
#endif
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist = ng_mpls_oam_cmdlist,     /* commands we can convert */
};

NETGRAPH_INIT(mpls_oam, &ng_mpls_oam_typestruct);
NETGRAPH_EXIT(mpls_oam, &ng_mpls_oam_typestruct);

/******************************************************************
			NETGRAPH NODE METHODS
 ******************************************************************/

/*
 * Node constructor
 */
static int
ng_mpls_oam_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int error = 0;

	/*
	* Allocate and initialize private info
	*/
	priv = ng_malloc(sizeof(*priv), M_NOWAIT | M_ZERO);
	if (unlikely(priv == NULL))
		return (ENOMEM);

	/* Call superclass constructor that mallocs *nodep */
	error = ng_make_node_common(&ng_mpls_oam_typestruct, nodep, nodeid);
	if (unlikely((error != 0))) {
		ng_free(priv);
		return (error);
	}

	NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->mpls_oam_node = *nodep;

	return (0);
}

/*
 * Method for attaching a new hook
 * There are two kinds of hook :
 *	- multiple lower hooks which link to other MPLS nodes
 *	- one upper hook which links toward a socket
 */
static int
ng_mpls_oam_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	/* default init for private space */
	NG_MPLS_OAM_DPRINTF("entering for (%s)", name);

	NG_HOOK_SET_PRIVATE(hook, NULL);
	/*
	* the check against double creation of "upper" or "lower"
	* is done by base netgraph (same hook name)
	*/
	if (unlikely(strncmp(name, NG_MPLS_OAM_HOOK_UPPER_LSP,
			sizeof(NG_MPLS_OAM_HOOK_UPPER_LSP) - 1) == 0)) {
		NG_MPLS_OAM_DPRINTF("found upper (LSP)");
		if (priv->mpls_oam_upper_lsp != NULL)
			return (EISCONN);

		priv->mpls_oam_upper_lsp = hook;
		/* no data will be accepted from upper hook */
		hook->hook_rcvdata = NULL;
	} else if (unlikely(strncmp(name, NG_MPLS_OAM_HOOK_UPPER_BFD,
			sizeof(NG_MPLS_OAM_HOOK_UPPER_BFD) - 1) == 0)) {
		NG_MPLS_OAM_DPRINTF("found upper (BFD)");
		if (priv->mpls_oam_upper_bfd != NULL)
			return (EISCONN);

		priv->mpls_oam_upper_bfd = hook;
		/* no data will be accepted from upper hook */
		hook->hook_rcvdata = NULL;
	} else if (unlikely(strncmp(name, NG_MPLS_OAM_LOWER_PREFIX_RA,
			sizeof(NG_MPLS_OAM_LOWER_PREFIX_RA) - 1) == 0)) {
		/* lower_tx : with a known PREFIX */
		NG_MPLS_OAM_DPRINTF("found lower (MPLS RA))");
#if defined(__LinuxKernelVNB__)
		hook->hook_rcvdata = ng_mpls_oam_rcvdata_lower_ra;
#elif defined(__FastPath__)
		hook->hook_rcvdata = ng_mpls_oam_send_exc;
#endif
	} else if (unlikely(strncmp(name, NG_MPLS_OAM_LOWER_PREFIX_TTL,
			sizeof(NG_MPLS_OAM_LOWER_PREFIX_TTL) - 1) == 0)) {
		/* lower_tx : with a known PREFIX */
		NG_MPLS_OAM_DPRINTF("found lower (MPLS TTL))");

#if defined(__LinuxKernelVNB__)
		hook->hook_rcvdata = ng_mpls_oam_rcvdata_lower_ttl;
#elif defined(__FastPath__)
		hook->hook_rcvdata = ng_mpls_oam_send_exc;
#endif
	} else if (unlikely(strncmp(name, NG_MPLS_OAM_LOWER_PREFIX_IP,
			sizeof(NG_MPLS_OAM_LOWER_PREFIX_IP) - 1) == 0)) {
		/* lower_tx : with a known PREFIX */
		NG_MPLS_OAM_DPRINTF("found lower (IP))");
#if defined(__LinuxKernelVNB__)
		hook->hook_rcvdata = ng_mpls_oam_rcvdata_lower_ip;
#elif defined(__FastPath__)
		hook->hook_rcvdata = ng_mpls_oam_send_exc;
#endif
	} else {
		log(LOG_ERR, "VNB: %s: unknown hook name: %s\n", __func__, name);
		return (EINVAL);
	}

	return 0;
}

/*
 * Receive a control message
 */
static int
ng_mpls_oam_rcvmsg(node_p node, struct ng_mesg *msg,
		const char *retaddr, struct ng_mesg **rptr,
		struct ng_mesg **nl_msg)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;

	NG_MPLS_OAM_DPRINTF("entering - arglen : %d", msg->header.arglen);

	switch (msg->header.typecookie) {

	case NGM_MPLS_OAM_COOKIE:
		switch (msg->header.cmd) {
		case NGM_MPLS_OAM_SET_CONFIG:
		{
			struct ng_mpls_oam_config *const conf =
				(struct ng_mpls_oam_config *) msg->data;

			if (msg->header.arglen != sizeof(*conf)) {
				error = EINVAL;
				break;
			}
			priv->config = *conf;
			break;
		}
		case NGM_MPLS_OAM_GET_CONFIG:
		{
			struct ng_mpls_oam_config *conf;

			NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			conf = (struct ng_mpls_oam_config *) resp->data;
			*conf = priv->config;	/* no sanity checking needed */
			break;
		}
		/* example only : to be merged into per-tunnel NG_MPLS_OAM_STATS */
#ifdef NG_MPLS_OAM_STATS
		case NGM_MPLS_OAM_GET_STATS:
		case NGM_MPLS_OAM_CLR_STATS:
		case NGM_MPLS_OAM_GETCLR_STATS:
		{
			if (msg->header.cmd != NGM_MPLS_OAM_CLR_STATS) {
				NG_MKRESPONSE(resp, msg, sizeof(priv->stats), M_NOWAIT);
				if (unlikely(resp == NULL)) {
					error = ENOMEM;
					break;
				}
				memcpy(resp->data,
					&priv->stats, sizeof(priv->stats));
			}

			if (msg->header.cmd != NGM_MPLS_OAM_GET_STATS) {
				memset(&priv->stats, 0, sizeof(priv->stats));
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

	FREE(msg, M_NETGRAPH);
	return (error);
}


#if defined(__LinuxKernelVNB__)
static int ng_mpls_oam_send(const hook_p ohook, struct mbuf *m, meta_p meta)
{
	int error = EINVAL;
	mpls_header_t *phdr;
	mpls_header_t hdr;
	int i=0;
	void *p_tmp;

	/*
	 * LSP ping : restore *all* original, saved MPLS headers
	 * for a packet in original format (as CB is only valid in kernel)
	 *  => must prepend some MPLS headers
	 */
	/* Have a pointer on the saved label stack */
	phdr = (mpls_header_t *)m->cb;
	/* find all headers until BS */
	for (i=0; i < 2 * NG_MPLS_SAVED_WORDS; i++) {
		/* + Big to Little Endian conversion */
		hdr.header = ntohl(phdr[i].header);
		/* bottom of stack bit is set ? */
		if (hdr.mhbs)
			break;
	}
	NG_MPLS_OAM_DPRINTF("found %d MPLS headers", (i + 1));
	/* Prepend 'i+1' MPLS header(s) */
	M_PREPEND(m, (i + 1) * NG_MPLS_HEADER_ENCAPLEN, M_DONTWAIT);
	if (unlikely(m == NULL))
		goto drop;

	/* copy 'i+1' labels */
	p_tmp = mtod(m, void *);
	memcpy(p_tmp, (void *)m->cb, (i + 1) * NG_MPLS_HEADER_ENCAPLEN);

	NG_MPLS_OAM_DPRINTF("sending packet on %s", ohook->name);

	/* the userland app will finish parsing */
	/* prepend original packet with I/F name - from CB field */
	M_PREPEND(m, NG_NODESIZ, M_DONTWAIT);
	if (unlikely(m == NULL))
		goto drop;

	p_tmp = mtod(m, void *);
	memcpy(p_tmp, (void *)(m->cb+NG_MPLS_SAVED_WORDS*sizeof(uint64_t)),
	       NG_NODESIZ);
	/* send to upper => userland socket */
	NG_SEND_DATA(error, ohook, m, meta);

	return error;

 drop:
	NG_FREE_META(meta);
	return error;
}

/*
 * Handle incoming data frame from below
 *  lower hook for IP (TTL == 1 or RA)
 *
 * Data coming from the lower link are checked. Matching data are
 * sent to one of the upper links.
 */
static int
ng_mpls_oam_rcvdata_lower_ip(const hook_p hook, struct mbuf *m, meta_p meta)
{
	priv_p priv = hook->node_private;
	int error = EINVAL;
	mpls_header_t * phdr;
	mpls_header_t hdr;
	hook_p upper_lsp;
	struct vnb_ip *iphdr;
	struct vnb_udphdr *udphdr;

	(void)hdr;
	(void)phdr;

	if (!priv) {
		error = ENOTCONN;
		goto drop;
	}

	/* saved MPLS header in skb->cb */
	/* also saved input interface in skb->cb */
	if (priv->config.debugFlag & NG_MPLS_OAM_DEBUG_HEADER) {
		hdr.header = ntohl(*(uint32_t *)m->cb);
		NG_MPLS_OAM_DPRINTF("MPLS header: 0x%08x", hdr.header);
		NG_MPLS_OAM_DPRINTF("MPLS incoming I/F: %s",
				   (char *)((void*)m->cb) +
				   NG_MPLS_SAVED_WORDS*sizeof(uint64_t));
	}

	/* here, the skb is common format, with header in cb or shared variable */
	phdr = mtod(m, mpls_header_t *);
	hdr.header = ntohl(phdr->header);
	if (priv->config.debugFlag & NG_MPLS_OAM_DEBUG_HEADER) {
		NG_MPLS_OAM_DPRINTF("MPLS header: 0x%08x", hdr.header);
	}

	/*
	 * IP ttl == 1 : the MPLS labels have already been removed
	 *    check_lspping_format(fast_check) was already run => exception
	 */
	m = m_pullup(m, sizeof(*iphdr) +
		     sizeof(struct vnb_udphdr));
	if (unlikely(m == NULL))
		goto drop;

	iphdr = mtod(m, struct vnb_ip *);
	udphdr = (struct vnb_udphdr *) ((void*)iphdr + MPLS_IP_HLEN(iphdr) *
					sizeof(uint32_t));

	/* confirmed with TTL == 1 or RA */
	upper_lsp = (udphdr->uh_dport == ntohs(LSP_PING_PORT)) ?
		priv->mpls_oam_upper_lsp : priv->mpls_oam_upper_bfd;
	NG_MPLS_OAM_DPRINTF("UDP dst port: %d", ntohs(udphdr->uh_dport));

	if (unlikely(upper_lsp == NULL)) {
		log(LOG_ERR, "%s: no upper\n", __func__);
		error = ENOTCONN;
		goto drop;
	}

#ifdef NG_MPLS_OAM_STATS
	STATS_INC(priv, recvPackets);
	STATS_ADD(priv, recvOctets, MBUF_LENGTH(m));
#endif
	return ng_mpls_oam_send(upper_lsp, m, meta);

drop:
	NG_FREE_DATA(m, meta);
	return error;
}

/*
 * Handle incoming data frame from below
 *  lower hook for (MPLS or IP) TTL==1
 *
 * Data coming from the lower link are checked. Matching data are
 * sent to one of the upper links.
 */
static int
ng_mpls_oam_rcvdata_lower_ttl(const hook_p hook, struct mbuf *m, meta_p meta)
{
	priv_p priv = hook->node_private;
	int error = EINVAL;
	mpls_header_t * phdr;
	mpls_header_t hdr;
	int confirmation_ttl=0;
	int i=0;
	void * p_tmp;
	hook_p upper_lsp;
	struct vnb_ip *iphdr;

	if (!priv) {
		error = ENOTCONN;
		goto drop;
	}

	/* saved MPLS header in skb->cb */
	/* also saved input interface in skb->cb */
	if (priv->config.debugFlag & NG_MPLS_OAM_DEBUG_HEADER) {
		hdr.header = ntohl(*(uint32_t *)m->cb);
		NG_MPLS_OAM_DPRINTF("MPLS cb header: 0x%08x", hdr.header);
		NG_MPLS_OAM_DPRINTF("MPLS cb incoming I/F: %s",
				   (char *)((void*)m->cb) +
				   NG_MPLS_SAVED_WORDS*sizeof(uint64_t));
	}

	/* here, the skb is common format, with header in cb or shared variable */
	phdr = mtod(m, mpls_header_t *);
	hdr.header = ntohl(phdr->header);
	if (priv->config.debugFlag & NG_MPLS_OAM_DEBUG_HEADER) {
		NG_MPLS_OAM_DPRINTF("MPLS current header: 0x%08x", hdr.header);
	}

	/*
	 * MPLS ttl == 1 : walk all MPLS labels until BS
	 *    if LSP ping packet (request/reply) => exception
	 *    else return original packet to original node
	 */
	for (i=0; i<2*NG_MPLS_SAVED_WORDS; i++){
		/* Have a pointer on a saved label */
		/* + Big to Little Endian conversion */
		hdr.header = ntohl(phdr[i].header);
		/* bottom of stack bit is set ? */
		if (hdr.mhbs)
			break;
	}
	NG_MPLS_OAM_DPRINTF("found %d MPLS headers", (i+1));
	m = m_pullup(m, sizeof(*iphdr)+
		     sizeof(struct vnb_udphdr)+
		     (i+1)*NG_MPLS_HEADER_ENCAPLEN);
	if (unlikely(m == NULL))
		goto drop;

	/* pointer to data after scanned MPLS headers : m_adj cannot be used */
	p_tmp = mtod(m, void *) + (i+1)*NG_MPLS_HEADER_ENCAPLEN;
	/* pointer to real start of IP packet */
	iphdr = (struct vnb_ip *)p_tmp;

	/* confirmation for LSP ping format */
	/* check IPv4, for MPLS TTL == 1 packets */
	if ( likely(MPLS_IS_IPV4(iphdr)) ) {
		NG_MPLS_OAM_DPRINTF("found IPv4");

		if ( likely(MPLS_IS_UDP4(iphdr)) ) {
			NG_MPLS_OAM_DPRINTF("found UDPv4");

			/* full checks when compared to nhlfe:mpls_pop */
			confirmation_ttl = check_lspping_format(iphdr);
			NG_MPLS_OAM_DPRINTF("confirmation_ttl: %d", confirmation_ttl);

		}
	}

	if (likely(confirmation_ttl)) {
		/* confirmed with TTL==1 */
		upper_lsp = (confirmation_ttl == NG_MPLS_CONFIRMATION_LSP_PING) ?
			priv->mpls_oam_upper_lsp : priv->mpls_oam_upper_bfd;

		if (unlikely(upper_lsp == NULL)) {
			log(LOG_ERR, "%s: no upper\n", __func__);
			goto nomatch;
		}

#ifdef NG_MPLS_OAM_STATS
		STATS_INC(priv, recvPackets);
		STATS_ADD(priv, recvOctets, MBUF_LENGTH(m));
#endif
		/*
		 * for confirmed MPLS TTL==1,
		 *   the remaining MPLS headers must be removed
		 *   before restoring the complete saved MPLS headers
		 * m_pullup check was already done at the start of the function
		 */
		m_adj(m, (i+1)*NG_MPLS_HEADER_ENCAPLEN);

		return ng_mpls_oam_send(upper_lsp, m, meta);
	} else {
		/* no LSP ping */
#ifdef NG_MPLS_OAM_STATS
		STATS_INC(priv, recvInvalid);
#endif
		/* return to original node */
		NG_MPLS_OAM_DPRINTF("return to original node");
		NG_SEND_DATA(error, hook, m, meta);
	}
	return error;

nomatch:
	error = EINVAL;

drop:
	NG_FREE_DATA(m, meta);
	return error;
}

/*
 * Handle incoming data frame from below (lower hook for Router Alert)
 *
 * Data coming from the lower link are checked. Matching data are
 * sent to one of the upper links.
 */
static int
ng_mpls_oam_rcvdata_lower_ra(const hook_p hook, struct mbuf *m, meta_p meta)
{
	priv_p priv = hook->node_private;
	int i, error = EINVAL;
	mpls_header_t * phdr;
	mpls_header_t hdr;
	int confirmation_ra=0;
	void * p_tmp;
	hook_p upper_lsp;
	struct vnb_ip *iphdr;

	if (!priv) {
		error = ENOTCONN;
		goto drop;
	}

	if (priv->config.debugFlag & NG_MPLS_OAM_DEBUG_HEADER) {
		hdr.header = ntohl(*(uint32_t *)m->cb);
		NG_MPLS_OAM_DPRINTF("MPLS header: 0x%08x", hdr.header);
		NG_MPLS_OAM_DPRINTF("MPLS incoming I/F: %s",
				   (char *)((void*)m->cb) +
				   NG_MPLS_SAVED_WORDS*sizeof(uint64_t));
	}

	/* here, the skb is common format, with header in cb or shared variable */
	phdr = mtod(m, mpls_header_t *);
	hdr.header = ntohl(phdr->header);
	if (priv->config.debugFlag & NG_MPLS_OAM_DEBUG_HEADER) {
		NG_MPLS_OAM_DPRINTF("MPLS header: 0x%08x", hdr.header);
	}

	/* pop all MPLS headers until BS */
	for (i=0; i < 2 * NG_MPLS_SAVED_WORDS; i++){
		/* Have a pointer on a saved label */
		/* + Big to Little Endian conversion */
		hdr.header = ntohl(phdr[i].header);
		/* bottom of stack bit is set ? */
		if (hdr.mhbs)
			break;
	}
	NG_MPLS_OAM_DPRINTF("found %d MPLS headers", (i+1));
	m = m_pullup(m, sizeof(*iphdr)+
		sizeof(struct vnb_udphdr)+
		(i+1)*NG_MPLS_HEADER_ENCAPLEN);
	if (unlikely(m == NULL)) {
		goto drop;
	}
	/* pointer to data after scanned MPLS headers : m_adj cannot be used */
	p_tmp = mtod(m, void *) + (i+1)*NG_MPLS_HEADER_ENCAPLEN;
	/* pointer to real start of IP packet */
	iphdr = (struct vnb_ip *)p_tmp;

	/* confirmation for LSP ping format */
	/* check IPv4, for MPLS RA packets */
	if ( likely(MPLS_IS_IPV4(iphdr)) ) {
		NG_MPLS_OAM_DPRINTF("found IPv4");
		/* An LSP ping req or rep is defined by src or dst port == 3503 */
		if ( likely(MPLS_IS_UDP4(iphdr)) ) {
			NG_MPLS_OAM_DPRINTF("found UDPv4");

			/* full checks when compared to nhlfe:mpls_pop */
			confirmation_ra = check_lspping_format(iphdr);
			NG_MPLS_OAM_DPRINTF("%d: confirmation_ra: %d",
					      __LINE__, confirmation_ra);
		}
	}

	if (likely(confirmation_ra)) {
		/* confirmed with Router Alert */
		upper_lsp = (confirmation_ra == NG_MPLS_CONFIRMATION_LSP_PING) ?
			priv->mpls_oam_upper_lsp : priv->mpls_oam_upper_bfd;

		if (unlikely(upper_lsp == NULL)) {
			log(LOG_ERR, "%s: no upper\n", __func__);
			error = EINVAL;
			goto drop;
		}

#ifdef NG_MPLS_OAM_STATS
		STATS_INC(priv, recvPackets);
		STATS_ADD(priv, recvOctets, MBUF_LENGTH(m));
#endif
		NG_MPLS_OAM_DPRINTF("sending packet");

		/* the userland app will finish parsing */
		/* prepend original packet with I/F name - from CB field */
		M_PREPEND(m, NG_NODESIZ, M_DONTWAIT);
		if (unlikely(m == NULL)) {
			NG_FREE_META(meta);
			return error;
		}

		p_tmp = mtod(m, void *);
		memcpy(p_tmp, (void *)(m->cb +
		              NG_MPLS_SAVED_WORDS * sizeof(uint64_t)),
		              NG_NODESIZ);
		/* send to upper => userland socket */
		NG_SEND_DATA(error, upper_lsp, m, meta);
	} else {
		/* no LSP ping : other MPLS Router Alert */
#ifdef NG_MPLS_OAM_STATS
		STATS_INC(priv, recvInvalid);
#endif
		/* return to original node */
		NG_MPLS_OAM_DPRINTF("return to original node");
		NG_SEND_DATA(error, hook, m, meta);
	}
	return error;

drop:
	NG_FREE_DATA(m, meta);
	return error;
}

static int
ng_mpls_oam_rcvexception(const hook_p hook, struct mbuf *m, meta_p meta)
{
	int error=0;
	void * p_tmp;
	mpls_header_t * phdr;
	mpls_header_t hdr;
	struct fpvnbtovnbhdr * exc_hdr = NULL;
	unsigned int hookname_len;
	unsigned int nodename_len;
	unsigned int hdr_len;

	(void)hdr;
	(void)phdr;

	NG_MPLS_OAM_DPRINTF("exception received for %s", hook->name);

	if (!pskb_may_pull(m, sizeof(struct fpvnbtovnbhdr))) {
		log(LOG_ERR, "%s: Unable to pull VNB2VNB header\n",
			   __FUNCTION__);
		kfree_skb(m);
		return EINVAL;
	}
	exc_hdr = (struct fpvnbtovnbhdr *)skb_network_header(m);
	hookname_len = exc_hdr->hookname_len;
	nodename_len = exc_hdr->nodename_len;
	hdr_len = sizeof(struct fpvnbtovnbhdr) +
					 hookname_len + nodename_len;
	if (!pskb_may_pull(m, hdr_len)) {
		log(LOG_ERR, "%s: Unable to pull the full VNB2VNB header\n",
			   __FUNCTION__);
		kfree_skb(m);
		return EINVAL;
	}
	/* exception header is not used here, always successful due to previous
	 * call to pskb_may_pull() */
	__skb_pull(m, hdr_len);

	/* packet coming from fast path VNB */
	/* copy saved MPLS labels from packet header and I/F name into CB */
	p_tmp = mtod(m, void *);
	memcpy((void *)(m->cb), p_tmp,
		   NG_MPLS_SAVED_WORDS*sizeof(uint64_t) + NG_NODESIZ);

	phdr = (mpls_header_t *)p_tmp;
	hdr.header = ntohl(phdr->header);
	NG_MPLS_OAM_DPRINTF("MPLS header: 0x%08x", hdr.header);
	p_tmp += NG_MPLS_SAVED_WORDS*sizeof(uint64_t);
	NG_MPLS_OAM_DPRINTF("MPLS incoming I/F: %s", (char *)(p_tmp));

	/* remove prepended data */
	m_adj(m, NG_MPLS_SAVED_WORDS*sizeof(uint64_t) + NG_NODESIZ);
	if (m == NULL)
		return EINVAL;

	/* find correct recv function : ra or ttl */
	if (hook->hook_rcvdata != NULL)
		error = hook->hook_rcvdata(hook, m, meta);
	else
		error = EINVAL;
	return error;
}
#elif defined(__FastPath__)
static int ng_mpls_oam_send_exc(const hook_p hook, struct mbuf *m, meta_p meta)
{
	priv_p priv = hook->node_private;
	int error = EINVAL;
#if NG_MPLS_OAM_DEBUG >= 1
	mpls_header_t * phdr;
	mpls_header_t hdr;
#endif
	void *p_tmp;

	/* prepend current packet with saved labels and I/F name
	 *      from shared variable */
	M_PREPEND(m, NG_MPLS_SAVED_WORDS * sizeof(uint64_t) +
		  NG_NODESIZ, M_DONTWAIT);
	if (unlikely(m == NULL)) {
		NG_FREE_META(meta);
		return error;
	}
	p_tmp = mtod(m, void *);
	memcpy(p_tmp, (void *)(FPN_PER_CORE_VAR(mpls_saved_stack)),
	       NG_MPLS_SAVED_WORDS*sizeof(uint64_t));
#if NG_MPLS_OAM_DEBUG >= 1
	phdr = mtod(m, mpls_header_t *);
	hdr.header = ntohl(phdr->header);
	NG_MPLS_OAM_DPRINTF("MPLS header: 0x%08x", hdr.header);
#endif

	p_tmp += NG_MPLS_SAVED_WORDS*sizeof(uint64_t);
	memcpy(p_tmp, (void *)(FPN_PER_CORE_VAR(mpls_input_iface)),
	       NG_NODESIZ);
	NG_MPLS_OAM_DPRINTF("MPLS incoming I/F: %s", (char *)(p_tmp));

	/* exception to kernel VNB */
	NG_MPLS_OAM_DPRINTF("exception sent len = %d", m_len(m));
	error = ng_send_exception(priv->mpls_oam_node, hook,
				  VNB2VNB_EXC, 0, m, meta);
	return error;
}
#endif

/*
 * Shutdown processing
 */
static int
ng_mpls_oam_rmnode(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	node->flags |= NG_INVALID;
	ng_cutlinks(node);
	ng_unname(node);

	NG_NODE_SET_PRIVATE(node, NULL);

	ng_free(priv);
	NG_NODE_UNREF(node);
	return 0;
}

/*
 * Hook disconnection
 * If all the hooks are removed, let's free itself.
 */
static int
ng_mpls_oam_disconnect(hook_p hook)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);

	if (strncmp(hook->name, NG_MPLS_OAM_LOWER_PREFIX_RA,
			sizeof(NG_MPLS_OAM_LOWER_PREFIX_RA) - 1) == 0) {
		/* lower_tx : with a known PREFIX */
		NG_MPLS_OAM_DPRINTF("mpls_oam_lower (MPLS ra)");

		hook->hook_rcvdata = NULL;

		NG_HOOK_SET_PRIVATE(hook, NULL);
	} else if (strncmp(hook->name, NG_MPLS_OAM_LOWER_PREFIX_TTL,
			sizeof(NG_MPLS_OAM_LOWER_PREFIX_TTL) - 1) == 0) {
		/* lower_tx : with a known PREFIX */
		NG_MPLS_OAM_DPRINTF("mpls_oam_lower (MPLS ttl)");

		hook->hook_rcvdata = NULL;

		NG_HOOK_SET_PRIVATE(hook, NULL);
	} else if (strncmp(hook->name, NG_MPLS_OAM_LOWER_PREFIX_IP,
			sizeof(NG_MPLS_OAM_LOWER_PREFIX_IP) - 1) == 0) {
		/* lower_tx : with a known PREFIX */
		NG_MPLS_OAM_DPRINTF("mpls_oam_lower (IP)");

		NG_HOOK_SET_PRIVATE(hook, NULL);
	} else if (hook == priv->mpls_oam_upper_lsp) {
		NG_MPLS_OAM_DPRINTF("upper (lsp)");

		priv->mpls_oam_upper_lsp = NULL;
		NG_HOOK_SET_PRIVATE(hook, NULL);
	} else if (hook == priv->mpls_oam_upper_bfd) {
		NG_MPLS_OAM_DPRINTF("upper (bfd)");

		priv->mpls_oam_upper_bfd = NULL;
		NG_HOOK_SET_PRIVATE(hook, NULL);
	}

	/* Go away if no longer connected to anything */
	if (unlikely(node->numhooks == 0))
		ng_rmnode(node);
	return 0;
}
