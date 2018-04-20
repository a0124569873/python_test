
/*
 * ng_cisco.c
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
 * $FreeBSD: src/sys/netgraph/ng_cisco.c,v 1.4.2.6 2002/07/02 23:44:02 archie Exp $
 * $Whistle: ng_cisco.c,v 1.25 1999/11/01 09:24:51 julian Exp $
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
#include <linux/timer.h>
#include <linux/ctype.h> /* for isdigit */
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <netgraph/vnblinux.h>
#define ETHERTYPE_IPX ETH_P_IPX
#define ETHERTYPE_TRANSETHER 0x6558
#define ETHERTYPE_AT ETH_P_ATALK
#elif defined(__FastPath__)
#include <fp-netgraph.h>
#endif /* !defined(__FastPath__) */

#include <netgraph/vnb_ether.h>

#define TRACE_CISCO(...) VNB_TRAP(__VA_ARGS__)

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_cisco.h>

#define CISCO_MULTICAST         0x8f	/* Cisco multicast address */
#define CISCO_UNICAST           0x0f	/* Cisco unicast address */
#define CISCO_KEEPALIVE         0x8035	/* Cisco keepalive protocol */
#define CISCO_ADDR_REQ          0	/* Cisco address request */
#define CISCO_ADDR_REPLY        1	/* Cisco address reply */
#define CISCO_KEEPALIVE_REQ     2	/* Cisco keepalive request */

#define DEFAULT_KEEPALIVE_SECS      10
#define DEFAULT_SEQ_RETRIES_MAX      3
#define NG_CISCO_KEEPALIVE_PRIORITY 127 /* priority for Keepalive data */

u_int32_t ng_chdlc_getifindex (node_p node);

struct cisco_header {
	u_int8_t  address;
	u_int8_t  control;
	u_int16_t protocol;
} __attribute__((packed));

#define CISCO_HEADER_LEN          sizeof (struct cisco_header)

struct cisco_packet {
	u_int32_t  type;
	u_int32_t  par1;
	u_int32_t  par2;
	u_int16_t rel;
	u_int16_t time0;
	u_int16_t time1;
} __attribute__((packed));

#define CISCO_PACKET_LEN (sizeof(struct cisco_packet))

struct protoent {
	hook_p  hook;		/* the hook for this proto */
	u_int16_t af;		/* address family, -1 = downstream */
};

struct cisco_priv {
	u_int32_t  local_seq;
	u_int32_t  remote_seq;
	u_int32_t  seqRetries;	/* how many times we've been here throwing out
				 * the same sequence number without ack */
	u_int32_t keepAlivePeriod; /* in seconds */
	u_int32_t seqRetriesMax;  /* number of retries before sending a "down" state */
	node_p  node;
#if defined(__LinuxKernelVNB__)
	struct ng_callout handle;
#elif defined(__FastPath__)
	/* FastPath doesn't manage keep-alive messages. */
#endif
	hook_p hook_info;		/* Hook to send information */
	int    state;			/* State of the link (0: down) */
	struct protoent downstream;
	struct protoent inet;		/* IP information */
	struct in_addr localip;
	struct in_addr localmask;
	struct protoent inet6;		/* IPv6 information */
#ifndef __FastPath__
	struct protoent atalk;		/* AppleTalk information */
	struct protoent ipx;		/* IPX information */
	struct protoent transeth;	/* Eth bridging information */
	struct protoent mpls;		/* MPLS information */
#endif
};
typedef struct cisco_priv *sc_p;

/* Netgraph methods */
static ng_constructor_t		cisco_constructor;
static ng_rcvmsg_t		cisco_rcvmsg;
static ng_shutdown_t		cisco_rmnode;
static ng_newhook_t		cisco_newhook;
static ng_rcvdata_t		cisco_rcvdata;
static ng_disconnect_t		cisco_disconnect;

/* Other functions */
static int	cisco_input(sc_p sc, hook_p hook, struct mbuf *m, meta_p meta);
#ifndef __FastPath__
static void	cisco_keepalive(void *arg);
static int	cisco_send(sc_p sc, int type, int32_t par1, int32_t par2);
#endif
static int	cisco_send_info_linkstate(sc_p sc, int state);

/* Parse type for struct ng_cisco_ipaddr */
static const struct ng_parse_struct_field ng_cisco_ipaddr_type_fields[]
	= NG_CISCO_IPADDR_TYPE_INFO;
static const struct ng_parse_type ng_cisco_ipaddr_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_cisco_ipaddr_type_fields
};

/* Parse type for struct ng_async_stat */
static const struct ng_parse_struct_field ng_cisco_stats_type_fields[]
	= NG_CISCO_STATS_TYPE_INFO;
static const struct ng_parse_type ng_cisco_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_cisco_stats_type_fields
};

/* Parse type for struct ng_cisco_keepalive */
static const struct ng_parse_struct_field
	ng_cisco_keepalive_type_info[] = NG_CISCO_KEEPALIVE_TYPE_INFO;

static const struct ng_parse_type ng_cisco_keepalive_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_cisco_keepalive_type_info
};

#ifdef FASTPATH_STATS
/* Parse type for struct ng_async_stat */
static const struct ng_parse_struct_field ng_cisco_fastpathstats_type_fields[] = {
	{ "IPxmitOctets",     &ng_parse_uint32_type   },      \
	{ "IPxmitFrames",     &ng_parse_uint32_type   },      \
	{ "IPxmitDropped",    &ng_parse_uint32_type   },      \
	{ "IPrecvOctets",     &ng_parse_uint32_type   },      \
	{ "IPrecvFrames",     &ng_parse_uint32_type   },      \
	{ "IPrecvDropped",    &ng_parse_uint32_type   },      \
	{ "xmitOctets",       &ng_parse_uint32_type   },      \
	{ "xmitFrames",       &ng_parse_uint32_type   },      \
	{ "recvOctets",       &ng_parse_uint32_type   },      \
	{ "recvFrames",       &ng_parse_uint32_type   },      \
	{ "badProtos",        &ng_parse_uint32_type   },      \
	{ "HDLCrecvOctets",   &ng_parse_uint32_type   },      \
	{ "HDLCrecvFrame",    &ng_parse_uint32_type   },      \
	{ "HDLCrecvFCSErr",   &ng_parse_uint32_type   },      \
	{ "HDLCrecvAbortErr", &ng_parse_uint32_type   },      \
	{ "HDLCrecvLongErr",  &ng_parse_uint32_type   },      \
	{ "HDLCrecvShortErr", &ng_parse_uint32_type   },      \
	{ "HDLCrecvAlignErr", &ng_parse_uint32_type   },      \
	{ "HDLCxmitOctets",   &ng_parse_uint32_type   },      \
	{ "HDLCxmitFrame",    &ng_parse_uint32_type   },      \
	{ "HDLCxmitAbortErr", &ng_parse_uint32_type   },      \
	{ NULL }                                              \
};

static const struct ng_parse_type ng_cisco_fastpathstats_type = {
        &ng_parse_struct_type,
        &ng_cisco_fastpathstats_type_fields
};
#endif

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_cisco_cmdlist[] = {
	{
	  NGM_CISCO_COOKIE,
	  NGM_CISCO_SET_IPADDR,
	  "setipaddr",
	  &ng_cisco_ipaddr_type,
	  NULL
	},
	{
	  NGM_CISCO_COOKIE,
	  NGM_CISCO_GET_IPADDR,
	  "getipaddr",
	  NULL,
	  &ng_cisco_ipaddr_type
	},
	{
	  NGM_CISCO_COOKIE,
	  NGM_CISCO_GET_STATUS,
	  "getstats",
	  NULL,
	  &ng_cisco_stats_type
	},
	{
	  NGM_CISCO_COOKIE,
	  NGM_CISCO_SET_KEEPALIVE,
	  "setkeepalive",
	  &ng_cisco_keepalive_type,
	  NULL
	},
#ifdef FASTPATH_STATS
        {
          NGM_CISCO_COOKIE,
          NGM_CISCO_GET_FASTPATH_STATS,
          "getfastpathstats",
          NULL,
          &ng_cisco_fastpathstats_type
        },
#endif
	{
	  .cookie = 0
	}
};

/* Node type */
static VNB_DEFINE_SHARED(struct ng_type, typestruct) = {
	.version   = NG_VERSION,
	.name      = NG_CISCO_NODE_TYPE,
	.mod_event = NULL,
	.constructor=cisco_constructor,
	.rcvmsg    = cisco_rcvmsg,
	.shutdown  = cisco_rmnode,
	.newhook   = cisco_newhook,
	.findhook  = NULL,
	.connect   = NULL,
	.afterconnect = NULL,
	.rcvdata   = cisco_rcvdata,
	.rcvdataq  = cisco_rcvdata,
	.disconnect= cisco_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist   = ng_cisco_cmdlist
};
NETGRAPH_INIT(cisco, &typestruct);
NETGRAPH_EXIT(cisco, &typestruct);

/*
 * Node constructor
 */
static int
cisco_constructor(node_p *nodep, ng_ID_t nodeid)
{
	sc_p sc;
	int error = 0;

	if ((error = ng_make_node_common_and_priv(&typestruct, nodep,
						  &sc, sizeof(*sc), nodeid))) {
		return (error);
	}
	bzero(sc, sizeof(struct cisco_priv));

#if defined(__LinuxKernelVNB__)
	ng_callout_init(&sc->handle);
#elif defined(__FastPath__)
	/* FastPath doesn't manage keep-alive messages. */
#endif
	(*nodep)->private = sc;
	sc->node = *nodep;

        /* Set the default KeepAlive value in secondes */
        sc->keepAlivePeriod = DEFAULT_KEEPALIVE_SECS;
        sc->seqRetriesMax   = DEFAULT_SEQ_RETRIES_MAX;


	/* Initialise the varous protocol hook holders */
	sc->downstream.af = 0xffff;
	sc->inet.af = AF_INET;
	sc->inet6.af = AF_INET6;
#ifndef __FastPath__
	sc->atalk.af = AF_APPLETALK;
	sc->ipx.af = AF_IPX;
	sc->transeth.af = AF_LINK;	/* No to define new AF_ family ... */
	sc->mpls.af = AF_ROUTE;     /* No to define new AF_ family ... */
#endif
	return (0);
}

/*
 * Check new hook
 */
static int
cisco_newhook(node_p node, hook_p hook, const char *name)
{
	const sc_p sc = node->private;

	if (strcmp(name, NG_CISCO_HOOK_DOWNSTREAM) == 0) {
		sc->downstream.hook = hook;
		hook->private = &sc->downstream;

#ifndef __FastPath__
		/* Start keepalives */
		if (sc->keepAlivePeriod)
			ng_callout_reset(&sc->handle, hz * sc->keepAlivePeriod,
					 cisco_keepalive, sc);
#endif /* !__FastPath__ */
	} else if (strcmp(name, NG_CISCO_HOOK_INET) == 0) {
		sc->inet.hook = hook;
		hook->private = &sc->inet;
	} else if (strcmp(name, NG_CISCO_HOOK_INET6) == 0) {
		sc->inet6.hook = hook;
		hook->private = &sc->inet6;
#ifndef __FastPath__
	} else if (strcmp(name, NG_CISCO_HOOK_APPLETALK) == 0) {
		sc->atalk.hook = hook;
		hook->private = &sc->atalk;
	} else if (strcmp(name, NG_CISCO_HOOK_IPX) == 0) {
		sc->ipx.hook = hook;
		hook->private = &sc->ipx;
	} else if (strcmp(name, NG_CISCO_HOOK_TRANSETH) == 0) {
		sc->transeth.hook = hook;
		hook->private = &sc->transeth;
	} else if (strcmp(name, NG_CISCO_HOOK_MPLS) == 0) {
		sc->mpls.hook = hook;
		hook->private = &sc->mpls;
#endif
	} else if (strcmp(name, NG_CISCO_HOOK_DEBUG) == 0) {
		hook->private = NULL;	/* unimplemented */
	} else if (strcmp(name, NG_CISCO_HOOK_INFO) == 0) {
		sc->hook_info = hook;
		hook->private = NULL;	/* unimplemented */
	} else
		return (EINVAL);
	return 0;
}

#ifdef FASTPATH_STATS
extern int get_pmdtype(int *pmdno);
#endif

/*
 * Receive control message.
 */
static int
cisco_rcvmsg(node_p node, struct ng_mesg *msg,
	const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const sc_p sc = node->private;
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_GENERIC_COOKIE:
		switch (msg->header.cmd) {
		case NGM_TEXT_STATUS:
		    {
			char *arg;
			int pos;

			NG_MKRESPONSE(resp, msg, NG_TEXTRESPONSE, M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			arg = (char *) resp->data;
			pos = sprintf(arg,
			  "keepalive period: %d sec; ", sc->keepAlivePeriod);
			pos += sprintf(arg + pos,
			  "unacknowledged keepalives: %d", sc->seqRetries);
			resp->header.arglen = pos + 1;
			break;
		    }
		default:
			error = EINVAL;
			break;
		}
		break;

	case NGM_CISCO_COOKIE:
		switch (msg->header.cmd) {
		case NGM_CISCO_GET_IPADDR:	/* could be a late reply! */
			if ((msg->header.flags & NGF_RESP) == 0) {
				struct in_addr *ips;

				NG_MKRESPONSE(resp, msg,
				    2 * sizeof(*ips), M_NOWAIT);
				if (!resp) {
					error = ENOMEM;
					break;
				}
				ips = (struct in_addr *) resp->data;
				ips[0] = sc->localip;
				ips[1] = sc->localmask;
				break;
			}
			/* FALLTHROUGH */	/* ...if it's a reply */
		case NGM_CISCO_SET_IPADDR:
		    {
			struct in_addr *const ips = (struct in_addr *)msg->data;

			if (msg->header.arglen < 2 * sizeof(*ips)) {
				error = EINVAL;
				break;
			}
			sc->localip = ips[0];
			sc->localmask = ips[1];
			break;
		    }
		case NGM_CISCO_GET_STATUS:
		    {
			struct ng_cisco_stats *stat;

			NG_MKRESPONSE(resp, msg, sizeof(*stat), M_NOWAIT);
			if (!resp) {
				error = ENOMEM;
				break;
			}
			stat = (struct ng_cisco_stats *)resp->data;
			stat->seqRetries = sc->seqRetries;
			stat->seqRetriesMax = sc->seqRetriesMax;
			stat->keepAlivePeriod = sc->keepAlivePeriod;
			stat->lineStatus = sc->state;
			break;
		    }
		case NGM_CISCO_SET_KEEPALIVE:
		{
			struct ng_cisco_keepalive *const keepalive
				= (struct ng_cisco_keepalive *)msg->data;

			if (keepalive->keepAlivePeriod > 0xffffff) {
				error = EINVAL;
				break;
			}

			if (keepalive->seqRetriesMax < 1) {
				error = EINVAL;
				break;
			}

			/*
			 * 0 means NO keep alive, manage transitions !
			 */
			if ((sc->keepAlivePeriod != 0) && (keepalive->keepAlivePeriod == 0)) {
#if defined(__LinuxKernelVNB__)
				ng_callout_stop(&sc->handle);
#elif defined(__FastPath__)
				/* FastPath doesn't manage keep-alive messages. */
#endif
                                /* set the state to up, and send the state to the info hook */
                                if (sc->state == 0) {
                                    sc->state = 1;
                                    cisco_send_info_linkstate(sc, 1);
                                }
			}
			if ((sc->keepAlivePeriod == 0) && (keepalive->keepAlivePeriod != 0)) {
#if defined(__LinuxKernelVNB__)
				ng_callout_reset(&sc->handle, hz * keepalive->keepAlivePeriod,
						 cisco_keepalive, sc);
#elif defined(__FastPath__)
				/* FastPath doesn't manage keep-alive messages. */
#endif
                        }
			sc->keepAlivePeriod = keepalive->keepAlivePeriod;
			sc->seqRetriesMax = keepalive->seqRetriesMax;
			break;
		}
#ifdef FASTPATH_STATS
		case NGM_CISCO_GET_FASTPATH_STATS:
		{
			struct ng_cisco_link_stats *stats;
			int ret, ret2, ifindex;
			int port, pmdno[2];
			u_int64_t rx_dropped, tx_dropped;

			ifindex = ng_chdlc_getifindex(node);
			if (ifindex == 0) {
				error = EINVAL;
				break;
			}

			ret2 = sc_if_get_drop_stats(ifindex, &rx_dropped, &tx_dropped);

			NG_MKRESPONSE(resp, msg,
				sizeof(struct ng_cisco_link_stats), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}

			stats = (struct ng_cisco_link_stats*)resp->data;

			if (get_pmdtype(pmdno) != 0) {
				error = ENOMEM;
				break;
			}

			// ng_chdlc_getifdev is not NULL since ng_chdlc_getifindex is not 0
			port = atoi(ng_chdlc_getifdev(node)->name + sizeof("serial") - 1);

			if ((port != 0)&&(port != 1)) {
				error = EINVAL;
				break;
			}

			if (pmdno[port] == 0x30) { // this is DS1
				TRACE_CISCO("Found DS1 port #%d\n",port);
				ret = kernel2cc_ds1_hdlc_get_stats(ifindex, &stats->hdlcstats);
			}
			else
			if (pmdno[port] == 0x40) { // this is DS3
				TRACE_CISCO("Found DS3 port #%d\n",port);
				ret = kernel2cc_hdlc_get_stats(ifindex, &stats->hdlcstats);
			}
			else {
				error = EINVAL;
				break;
			}

			stats->IPxmitFrames=stats->hdlcstats.thdl_msgcnt;
			stats->IPxmitOctets=stats->hdlcstats.thdl_octetcnt;
			stats->IPxmitDropped=(uint32_t)(tx_dropped & 0xFFFFFFFF);
			stats->IPrecvFrames=stats->hdlcstats.rhdl_msgcnt;
			stats->IPrecvOctets=stats->hdlcstats.rhdl_octetcnt;
			stats->IPrecvDropped=(uint32_t)(rx_dropped & 0xFFFFFFFF);

			stats->xmitFrames = stats->hdlcstats.rhdl_msgcnt - stats->IPxmitDropped;
			stats->xmitOctets = stats->hdlcstats.rhdl_octetcnt ;
			stats->recvFrames = stats->hdlcstats.thdl_msgcnt - stats->IPrecvDropped;
			stats->recvOctets = stats->hdlcstats.thdl_octetcnt;
			stats->badProtos = 0;

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

/*
 * Receive data
 */
static int
cisco_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	sc_p sc;
	node_p node;
	struct protoent *pep;
	struct cisco_header *h;
	int error = 0;

	if (((node = hook->node) == NULL) ||
	    ((sc = node->private) == NULL) ||
	    ((pep = hook->private) == NULL))
		goto out;

	/* If it came from our downlink, deal with it separately */
	if (pep->af == 0xffff)
		return (cisco_input(sc, hook, m, meta));

	/* OK so it came from a protocol, heading out. Prepend general data
	   packet header. For now, IP,IPX only  */
	M_PREPEND(m, CISCO_HEADER_LEN, M_DONTWAIT);
	if (!m) {
		error = ENOBUFS;
		goto out;
	}
	h = mtod(m, struct cisco_header *);
	h->address = CISCO_UNICAST;
	h->control = 0;

	switch (pep->af) {
	case AF_INET:		/* Internet Protocol */
		h->protocol = htons(VNB_ETHERTYPE_IP);
		break;
	case AF_INET6:
		h->protocol = htons(VNB_ETHERTYPE_IPV6);
		break;
#ifndef __FastPath__
	case AF_APPLETALK:	/* AppleTalk Protocol */
		h->protocol = htons(ETHERTYPE_AT);
		break;
	case AF_IPX:		/* Novell IPX Protocol */
		h->protocol = htons(ETHERTYPE_IPX);
		break;
	case AF_LINK:		/* Eth bridge */
		h->protocol = htons(ETHERTYPE_TRANSETHER);
		break;
	case AF_ROUTE:		/* MPLS */
		h->protocol = htons(VNB_ETHERTYPE_MPLS);
		break;
#endif
	default:
		error = EAFNOSUPPORT;
		goto out;
	}

	/* Send it */
	NG_SEND_DATA(error, sc->downstream.hook, m, meta);
	return (error);

out:
	NG_FREE_DATA(m, meta);
	return (error);
}

/*
 * Shutdown node
 */
static int
cisco_rmnode(node_p node)
{
	const sc_p sc = node->private;

	node->flags |= NG_INVALID;
	ng_cutlinks(node);
	ng_unname(node);
	node->private = NULL;
	ng_unref(sc->node);
	return (0);
}

/*
 * Disconnection of a hook
 *
 * For this type, removal of the last link destroys the node
 */
static int
cisco_disconnect(hook_p hook)
{
	const sc_p sc = hook->node->private;
	struct protoent *pep;

	/* Check it's not the debug hook */
	if ((pep = hook->private)) {
		pep->hook = NULL;
		if (pep->af == 0xffff) {
			/* If it is the downstream hook, stop the timers */
#if defined(__LinuxKernelVNB__)
			ng_callout_stop_sync(&sc->handle);
#elif defined(__FastPath__)
			/* FastPath doesn't manage keep-alive messages. */
			(void)sc;
#endif
		}
	}

	/* If no more hooks, remove the node */
	if (hook->node->numhooks == 0)
		ng_rmnode(hook->node);
	return (0);
}

/*
 * Receive data
 */
static int
cisco_input(sc_p sc, hook_p hook, struct mbuf *m, meta_p meta)
{
	const struct cisco_header *h;
	node_p node;
	struct protoent *pep;
	int error = 0;

	/* Make sure node is still valid */
	if ((node = sc->node) == NULL) {
		error = EINVAL;
		goto drop;
	}

	/* Sanity check header length */
	if ((MBUF_LENGTH(m) < sizeof(*h)) ||
	    ((m = m_pullup(m, sizeof(*h))) == NULL)) {
		error = EINVAL;
		goto drop;
	}

	/* Get cisco header */
	h = mtod(m, const struct cisco_header *);
	m_adj(m, sizeof(*h));

	/* Check header address */
	switch (h->address) {
	default:		/* Invalid Cisco packet. */
		goto drop;
	case CISCO_UNICAST:
	case CISCO_MULTICAST:
		/* Don't check the control field here (RFC 1547). */
		switch (ntohs(h->protocol)) {
		default:
			goto drop;
		case CISCO_KEEPALIVE:
		    {
#ifdef __FastPath__
			/* Keep-alive messages aren't for us. */
			return ng_send_exception(node, hook,
						 VNB2VNB_DATA, 0,
						 m, meta);
#else /* __FastPath__ */
			const struct cisco_packet *p;

			(void)hook;
			/* Sanity check packet length */
			if (MBUF_LENGTH(m) < sizeof(*p)) {
				error = EINVAL;
				goto drop;
			}

			/* Get cisco packet */
			p = mtod(m, const struct cisco_packet *);

			/* Check packet type */
			switch (ntohl(p->type)) {
			default:
				log(LOG_WARNING,
				    "cisco: unknown cisco packet type: 0x%x\n",
				       ntohl(p->type));
				break;
			case CISCO_ADDR_REPLY:
				/* Reply on address request, ignore */
				break;
			case CISCO_KEEPALIVE_REQ:
				sc->remote_seq = ntohl(p->par1);
				if (sc->local_seq == ntohl(p->par2)) {
					sc->local_seq++;
					sc->seqRetries = 0;
					if (sc->state == 0) {
						/* We are down, up the interface */
						sc->state = 1;
						cisco_send_info_linkstate(sc, 1);
					}
				}
				break;
			case CISCO_ADDR_REQ:
			    {
/*
 * FIXME
 * The following is unsafe to do with VNB-SMP because we're on the data path.
 * Commented-out to prevent crashes.
 */
#if 0 /* FIXME */
				struct ng_mesg *msg, *resp;

				/* Ask inet peer for IP address information */
				if (sc->inet.hook == NULL)
					goto nomsg;
				NG_MKMESSAGE(msg, NGM_CISCO_COOKIE,
				    NGM_CISCO_GET_IPADDR, 0, M_NOWAIT);
				if (msg == NULL)
					goto nomsg;
				ng_send_msg(node, msg,
				    NG_CISCO_HOOK_INET, &resp, NULL);
				if (resp != NULL)
					cisco_rcvmsg(node, resp, ".", NULL, NULL);

		nomsg:
#endif /* FIXME */
				/* Send reply to peer device */
				error = cisco_send(sc, CISCO_ADDR_REPLY,
					    ntohl(sc->localip.s_addr),
					    ntohl(sc->localmask.s_addr));
				break;
			    }
			}
			goto drop;
#endif /* __FastPath__ */
		    }
		case VNB_ETHERTYPE_IP:
			pep = &sc->inet;
			break;
		case VNB_ETHERTYPE_IPV6:
			pep = &sc->inet6;
			break;
#ifndef __FastPath__
		case ETHERTYPE_AT:
			pep = &sc->atalk;
			break;
		case ETHERTYPE_IPX:
			pep = &sc->ipx;
			break;
		case ETHERTYPE_TRANSETHER:
			pep = &sc->transeth;
			break;
		case VNB_ETHERTYPE_MPLS:
			pep = &sc->mpls;
			break;
#endif
		}
		break;
	}

	/* Drop if payload is empty */
	if (MBUF_LENGTH(m) == 0) {
		error = EINVAL;
		goto drop;
	}

	/* Send it on */
	if ((hook = pep->hook) == NULL)
		goto drop;
	NG_SEND_DATA(error, hook, m, meta);
	return (error);

drop:
	NG_FREE_DATA(m, meta);
	return (error);
}

#ifndef __FastPath__

/*
 * Send keepalive packets, every Keepalive period (default is 10 seconds).
 */
static void
cisco_keepalive(void *arg)
{
	const sc_p sc = arg;

	TRACE_CISCO("Sending keepalive packet request count=%lu\n", sc->seqRetries);
	cisco_send(sc, CISCO_KEEPALIVE_REQ, sc->local_seq, sc->remote_seq);
	sc->seqRetries++;

	if (sc->seqRetries > sc->seqRetriesMax) {
		if (sc->state == 1) {
			/* We are up, down the interface */
			sc->state = 0;
			cisco_send_info_linkstate(sc, 0);
		}
	}

#if defined(__LinuxKernelVNB__)
	ng_callout_reset(&sc->handle, hz * sc->keepAlivePeriod,
			 cisco_keepalive, sc);
#elif defined(__FastPath__)
	/* FastPath doesn't manage keep-alive messages. */
#endif
}

#endif /* !__FastPath__ */

/*
 * Send linkstate up/down
 * @param sc
 * @param state: 0:down 1:up
 * @return
 */
static int
cisco_send_info_linkstate(sc_p sc, int state)
{
	unsigned char *buf;
	struct mbuf *m;
	int error = 0;
	int buflen;
	hook_p hook_info;

	if ((hook_info = sc->hook_info) == NULL)
	  return EINVAL;

	if (((m = m_alloc()) != NULL) &&
	    (m_append(m, NG_CISCO_LINKSTATE_STR_SIZE) == NULL)) {
		m_freem(m);
		m = NULL;
	}
	if (!m)
		return (ENOBUFS);

	buf = mtod(m, unsigned char *);

	if (state) {
	  strcpy((char *)buf, NG_CISCO_LINKSTATE_STR_UP);
	  buflen = strlen(NG_CISCO_LINKSTATE_STR_UP)+1;
	} else {
	  strcpy((char *)buf, NG_CISCO_LINKSTATE_STR_DOWN);
	  buflen = strlen(NG_CISCO_LINKSTATE_STR_DOWN)+1;
	}

	m_trim(m, (NG_CISCO_LINKSTATE_STR_SIZE - buflen));

	NG_SEND_DATA_ONLY(error, hook_info, m);
	return (error);
}

#ifndef __FastPath__

/*
 * Send Cisco keepalive packet.
 */
#define META_PAD 16
static int
cisco_send(sc_p sc, int type, int32_t par1, int32_t par2)
{
	struct cisco_header *h;
	struct cisco_packet *ch;
	struct mbuf *m;
	u_int32_t  t;
	int     error = 0;
	meta_p  meta = NULL;
#if defined(__FastPath__)
	struct vnb_timeval time;
#else
	struct timeval time;
#endif

	microtime(&time);
	if (((m = m_alloc()) != NULL) &&
	    (m_append(m, (CISCO_HEADER_LEN + CISCO_PACKET_LEN)) == NULL)) {
		m_freem(m);
		m = NULL;
	}
	if (!m)
		return (ENOBUFS);

	t = (time.tv_sec ) * 1000;
	/* time seems not to be important,
	 * dont care bootime
	 */

	h = mtod(m, struct cisco_header *);
	h->address = CISCO_MULTICAST;
	h->control = 0;
	h->protocol = htons(CISCO_KEEPALIVE);

	ch = (struct cisco_packet *) (h + 1);
	ch->type = htonl(type);
	ch->par1 = htonl(par1);
	ch->par2 = htonl(par2);
	ch->rel = -1;
	ch->time0 = htons((u_int16_t) (t >> 16));
	ch->time1 = htons((u_int16_t) t);

    /* Allocate a meta struct (and leave some slop for options to be
     * added by other modules). */
    MALLOC(meta, meta_p, sizeof(*meta) + META_PAD, M_NETGRAPH, M_NOWAIT);
    if (meta != NULL) { /* if it failed, well, it was optional anyhow */
        meta->used_len = (u_int16_t) sizeof(struct ng_meta);
        meta->allocated_len
            = (u_int16_t) sizeof(struct ng_meta) + META_PAD;
        meta->flags = 0;
        meta->priority = NG_CISCO_KEEPALIVE_PRIORITY;
        meta->discardability = -1;
    }

	NG_SEND_DATA(error, sc->downstream.hook, m, meta);
	return (error);
}

#endif /* !__FastPath__ */

#if defined(__LinuxKernelVNB__)
module_init(ng_cisco_init);
module_exit(ng_cisco_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB CISCO node");
MODULE_LICENSE("6WIND");
#endif
