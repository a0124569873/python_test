
/*
 * ng_ksocket.c
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
 * Author: Archie Cobbs <archie@freebsd.org>
 *
 * $FreeBSD: src/sys/netgraph/ng_ksocket.c,v 1.5.2.12 2002/07/02 23:44:02 archie Exp $
 * $Whistle: ng_ksocket.c,v 1.1 1999/11/16 20:04:40 archie Exp $
 */
/*
 * Copyright 2004-2013 6WIND S.A.
 */

/*
 * Kernel socket node type.  This node type is basically a kernel-mode
 * version of a socket... kindof like the reverse of the socket node type.
 */
#include <linux/version.h>
#include <linux/module.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <linux/ctype.h>
#include <linux/un.h>
#include <linux/in6.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <netgraph/vnblinux.h>
#include <asm/uaccess.h>

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#include "ip6_sprintf.h"
#include "inet_pton.c"
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_ksocket.h>
#include <netgraph_linux/ng_netns.h>

#include <net/udp.h>
#include <net/ip.h>

#ifdef CONFIG_XFRM
#include <net/xfrm.h>
#endif

#if defined(USE_VRF_NETNS)
/* Generic VRF implementation with netns */
#include <vrf.h>
#endif
#include <kcompat.h>

#define ERROUT(x)				\
	do {					\
		error = (x);			\
		VNB_TRAP("error %d", error);	\
		goto done;			\
	}					\
	while (0)

#define OFFSETOF(s, e) ((char *)&((s *)0)->e - (char *)((s *)0))
#define SADATA_OFFSET	(OFFSETOF(struct sockaddr, sa_data))

/*
 * global static data : A work queue is used to queue messages to be sent
 * in a socket. Indeed, the socket layer in linux can not be called
 * from an atomic context because the lock_sock() might sleep if it
 * cannot acquire the lock... sleeping can cause a panic if we are in
 * an interrupt !
 *
 * Moreover, we have the same problem in reception :
 * skb_recv_datagram() should be called from user-level only. This
 * part is inspired from net/sunrpc/svcsock.c
 */

/*
 * Module parameter.
 */
#define KSOCKET_MAX_XMIT_QUEUE_SIZE 100
static int max_xmit = KSOCKET_MAX_XMIT_QUEUE_SIZE;
module_param(max_xmit, int, 0);
MODULE_PARM_DESC(max_xmit, "max. nb of queued packets");

/* Node private data */
struct ng_ksocket_private {
	node_p		node;
	hook_p		hook;
	void		*so_dtor; /* destructor entry for "so" */
	struct socket	*so;
	struct sock     *sk;
	struct sockaddr connect_sa;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
	void		(*old_data_ready)(struct sock *sk,int bytes);
#else
	void		(*old_data_ready)(struct sock *sk);
#endif
	void		(*old_write_space)(struct sock *sk);
	unsigned long	flags;
#define	KSF_CONNECTING	0	/* Waiting for connection complete */
#define	KSF_ACCEPTING	1	/* Waiting for accept complete */
#define	KSF_EOFSEEN	2	/* Have sent 0-length EOF mbuf */
#define	KSF_CLONED	3	/* Cloned from an accepting socket */
#define	KSF_EMBRYONIC	4	/* Cloned node with no hooks yet */
#define	KSF_SENDING	5	/* Sending on socket */
#define	KSF_CONNECTED	6	/* made connect on the socket without error */
#define	KSF_ACCEPTED	7	/* made accept on the socket without error */
#define	KSF_BOUND	8	/* made bind on the socket without error */
#define	KSF_ALLOCMETA	10	/* allocate meta to store source sockaddr */

	u_int32_t	response_token;
	char		response_addr[NG_PATHLEN+1];

	/* Node receive side. */
	struct work_struct  recv_work;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	atomic_t            recv_work_exec_count;
#endif
	/* Node transmit side. */
	struct work_struct  xmit_work;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	atomic_t            xmit_work_exec_count;
#endif
	struct sk_buff      *xmit_first_skb;
	struct sk_buff      *xmit_last_skb;
	atomic_t            xmit_skb_count;
	spinlock_t          xmit_skb_fifo_lock;
};
typedef struct ng_ksocket_private *priv_p;

static inline priv_p
recv_work_to_kspriv(struct work_struct *recv_wk)
{
	return container_of(recv_wk, struct ng_ksocket_private, recv_work);
}

static inline priv_p
xmit_work_to_kspriv(struct work_struct *xmit_wk)
{
	return container_of(xmit_wk, struct ng_ksocket_private, xmit_work);
}

/*
 * Scalability and Reentrance Issues.
 *
 * Different receive or transmit work items can be executed in parallel to
 * achieve as much scalability as possible.
 * For this purpose, receive and transmit work items are scheduled in
 * unbound work queues that can run multiple "workers" to process work items
 * on different CPUs:
 * - until kernel release 2.6.35, use the default system work queue.
 * - since kernel release 2.6.36, use the system-wide unbound work queue.
 *
 * Conversely, the receive work item and the transmit work item of a given
 * VNB ksocket must not be reentered to guarantee the initial order of the
 * packets that cross a given VNB graph.
 * To comply with this constraint, a given work item that is scheduled while
 * being processed must not be processed in parallel by another "worker".
 * Instead, this new processing must be deferred after the completion of the
 * current processing of the same work item.
 * Since kernel release 3.6.0, this issue is directly addressed by the
 * workqueue framework itself that defers a scheduled work item to the
 * worker that is currently processing it when this is the case.
 * In all previous kernel releases, this issue is addressed by the work item
 * handlers themselves. For this purpose, the "ksp_recv_work_handler" and the
 * "ksp_xmit_work_handler" use an atomic execution counter per work item to
 * detect and to cancel parallel processing situations, then self-reschedule
 * the work item they finished to process when such a situation was detected.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#define ksf_work_schedule(wk) \
	schedule_work((wk))
#else
#define ksf_work_schedule(wk) \
	queue_work(system_unbound_wq, (wk))
#endif
#define ksf_recv_work_schedule(priv) ksf_work_schedule(&(priv)->recv_work)
#define ksf_xmit_work_schedule(priv) ksf_work_schedule(&(priv)->xmit_work)

static void ksp_recv_work_handler(struct work_struct *recv_wk);
static void ksp_xmit_work_handler(struct work_struct *recv_wk);

/* Internal commands which we send to ourselves */
#define	NGM_KSOCKET_INTERNAL_COOKIE	(NGM_KSOCKET_COOKIE + 1)

enum {
	NGM_KSOCKET_INTERNAL_UPCALL = 1
};

/* Netgraph node methods */
static ng_constructor_t	ng_ksocket_constructor;
static ng_rcvmsg_t	ng_ksocket_rcvmsg;
static ng_shutdown_t	ng_ksocket_rmnode;
static ng_newhook_t	ng_ksocket_newhook;
static ng_rcvdata_t	ng_ksocket_rcvdata;
static ng_disconnect_t	ng_ksocket_disconnect;
static ng_dumphook_t	ng_ksocket_dumphook;

/* Alias structure */
struct ng_ksocket_alias {
	const char	*name;
	const int	value;
	const int	family;
};

/* Protocol family aliases */
static const struct ng_ksocket_alias ng_ksocket_families[] = {
	{ "local",	PF_LOCAL	},
	{ "inet",	PF_INET		},
	{ "inet6",	PF_INET6	},
	{ "atalk",	PF_APPLETALK	},
	{ "ipx",	PF_IPX		},
	{ NULL,		-1		},
};

/* Socket type aliases */
static const struct ng_ksocket_alias ng_ksocket_types[] = {
	{ "stream",	SOCK_STREAM	},
	{ "dgram",	SOCK_DGRAM	},
	{ "raw",	SOCK_RAW	},
	{ "rdm",	SOCK_RDM	},
	{ "seqpacket",	SOCK_SEQPACKET	},
	{ "seq",    	SOCK_SEQPACKET 	},
	{ NULL,		-1		},
};

/* Protocol aliases */
static const struct ng_ksocket_alias ng_ksocket_protos[] = {
	{ "ip",		IPPROTO_IP,		PF_INET		},
	{ "raw",	IPPROTO_RAW,		PF_INET		},
	{ "icmp",	IPPROTO_ICMP,		PF_INET		},
	{ "igmp",	IPPROTO_IGMP,		PF_INET		},
	{ "tcp",	IPPROTO_TCP,		PF_INET		},
	{ "udp",	IPPROTO_UDP,		PF_INET		},
	{ "gre",	IPPROTO_GRE,		PF_INET		},
	{ "esp",	IPPROTO_ESP,		PF_INET		},
	{ "ah",		IPPROTO_AH,		PF_INET		},
#if defined(IPPROTO_SWIPE)
	{ "swipe",	IPPROTO_SWIPE,		PF_INET		},
#endif
#if defined(IPPROTO_ENCAP)
	{ "encap",	IPPROTO_ENCAP,		PF_INET		},
#endif
#if defined(IPPROTO_DIVERT)
	{ "divert",	IPPROTO_DIVERT,		PF_INET		},
#endif
#if defined(ATPROTO_DDP)
	{ "ddp",	ATPROTO_DDP,		PF_APPLETALK	},
#endif
#if defined(ATPROTO_AARP)
	{ "aarp",	ATPROTO_AARP,		PF_APPLETALK	},
#endif
#if defined(ATM_PROTO_AAL5) && defined(PF_ATM)
	{ "aal5",   	ATM_PROTO_AAL5,     	PF_ATM  	},
#endif
#ifdef INET6
	{ "ip",		IPPROTO_IP,		PF_INET6	},
	{ "ipip",	IPPROTO_IPIP, 		PF_INET6	},
	{ "tcp",	IPPROTO_TCP,		PF_INET6	},
	{ "egp",	IPPROTO_EGP,		PF_INET6	},
	{ "pup", 	IPPROTO_PUP,		PF_INET6	},
	{ "udp",	IPPROTO_UDP,		PF_INET6	},
        { "gre",        IPPROTO_GRE,            PF_INET6        },
	{ "idp",	IPPROTO_IDP,		PF_INET6	},
#if defined(IPPROTO_TP)
	{ "tp",		IPPROTO_TP,		PF_INET6	},
#endif
	{ "ipv6",	IPPROTO_IPV6,		PF_INET6	},
	{ "icmpv6",	IPPROTO_ICMPV6,		PF_INET6	},
#if defined(IPPROTO_EON)
	{ "eon",	IPPROTO_EON,		PF_INET6	},
#endif
#if defined(IPPROTO_ENCAP)
	{ "encap",	IPPROTO_ENCAP,		PF_INET6	},
#endif
#if defined(IPPROTO_DIVERT)
	{ "divert6",	IPPROTO_DIVERT,		PF_INET6	},
#endif
	{ "raw",	IPPROTO_RAW,		PF_INET6	},
	{ "esp",	IPPROTO_ESP,		PF_INET6	},
	{ "ah",		IPPROTO_AH,		PF_INET6	},
#endif /* INET6 */
	{ NULL,		-1					},

};

/* Helper functions */
static int	ng_ksocket_parse(const struct ng_ksocket_alias *aliases,
			const char *s, int family);

/************************************************************************
			STRUCT SOCKADDR PARSE TYPE
 ************************************************************************/

/* Get the length of the data portion of a generic struct sockaddr */
static int
ng_parse_generic_sockdata_getLength(const struct ng_parse_type *type,
	const u_char *start, const u_char *buf)
{
	return (sizeof(struct sockaddr) < SADATA_OFFSET) ? 0 : sizeof(struct sockaddr) - SADATA_OFFSET;
}

/* Type for the variable length data portion of a generic struct sockaddr */
static const struct ng_parse_type ng_ksocket_generic_sockdata_type = {
	&ng_parse_bytearray_type,
	&ng_parse_generic_sockdata_getLength
};

/* Type for a generic struct sockaddr */
static const struct ng_parse_struct_field
    ng_parse_generic_sockaddr_type_fields[] = {
	  { "len",	&ng_parse_uint8_type			},
	  { "family",	&ng_parse_uint8_type			},
	  { "data",	&ng_ksocket_generic_sockdata_type	},
	  { NULL }
};
static const struct ng_parse_type ng_ksocket_generic_sockaddr_type = {
	&ng_parse_struct_type,
	&ng_parse_generic_sockaddr_type_fields
};


/* Convert a struct sockaddr from ASCII to binary.  If its a protocol
   family that we specially handle, do that, otherwise defer to the
   generic parse type ng_ksocket_generic_sockaddr_type. */
static int
ng_ksocket_sockaddr_parse(const struct ng_parse_type *type,
	const char *s, int *off, const u_char *const start,
	u_char *const buf, int *buflen)
{
	struct sockaddr *const sa = (struct sockaddr *)buf;
	enum ng_parse_token tok;
	char fambuf[32];
	int family;
	unsigned int len;
	char *t;
	int sa_len = 0;

	/* If next token is a left curly brace, use generic parse type */
	if ((tok = ng_parse_get_token(s, off, &len)) == T_LBRACE) {
		return (*ng_ksocket_generic_sockaddr_type.supertype->parse)
		    (&ng_ksocket_generic_sockaddr_type,
		    s, off, start, buf, buflen);
	}

	/* Get socket address family followed by a slash */
	while (isspace(s[*off]))
		(*off)++;
	if ((t = strchr(s + *off, '/')) == NULL)
		return (EINVAL);
	if ((len = t - (s + *off)) > sizeof(fambuf) - 1)
		return (EINVAL);
	strncpy(fambuf, s + *off, len);
	fambuf[len] = '\0';
	*off += len + 1;
	if ((family = ng_ksocket_parse(ng_ksocket_families, fambuf, 0)) == -1)
		return (EINVAL);

	/* Set family */
	if (*buflen < SADATA_OFFSET)
		return (ERANGE);
	sa->sa_family = family;

	/* Set family-specific data and length */
	switch (sa->sa_family) {
	case PF_INET:		/* Get an IP address with optional port */
	    {
		struct sockaddr_in *const sin = (struct sockaddr_in *)sa;
		int i;

		/* Parse this: <ipaddress>[:port] */
		for (i = 0; i < 4; i++) {
			u_long val;
			char *eptr;

			val = strtoul(s + *off, &eptr, 10);
			if (val > 0xff || eptr == s + *off)
				return (EINVAL);
			*off += (eptr - (s + *off));
			((u_char *)&sin->sin_addr)[i] = (u_char)val;
			if (i < 3) {
				if (s[*off] != '.')
					return (EINVAL);
				(*off)++;
			} else if (s[*off] == ':') {
				(*off)++;
				val = strtoul(s + *off, &eptr, 10);
				if (val > 0xffff || eptr == s + *off)
					return (EINVAL);
				*off += (eptr - (s + *off));
				sin->sin_port = htons(val);
			} else
				sin->sin_port = 0;
		}
		bzero(&sin->sin_zero, sizeof(sin->sin_zero));
		sa_len = sizeof(*sin);
		break;
	    }

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#ifdef INET6
	case PF_INET6:		/* Get an IPv6 address with optional port */
		{
		struct sockaddr_in6 *const sin6 = (struct sockaddr_in6 *)sa;

		/*
		 * Parse this: [X:X::X:X%ifname]:port
		 *  ifname and port are optional
		 */
		const char *sptr;
		/* const */ char *ifnameptr = NULL; /* const is not supported by ifunit !! */
		const char *portptr = NULL;
		char scpy[INET6_ADDRSTRLEN +1+IFNAMSIZ +1+1+4 +2];
		char *escpyptr;

		/*
		 * Parse this: [X:X::X:X%ifname]:port
		 */

		s += *off;
		if (s[0] != '[')
			return (EINVAL);
		sptr = &(s[1]); /* X:X::X:X%ifname]:port */

		bzero(scpy, sizeof(scpy));
		strncpy(scpy, sptr, sizeof(scpy)); /* XXX strlcpy -> E2BIG */

		/* parse ifname if any */
		escpyptr = strchr(scpy, '%');
		if (escpyptr != NULL) {
			escpyptr[0] = '\0';
			escpyptr++;
			ifnameptr = escpyptr;
		} else {
			escpyptr = scpy;
		}

		escpyptr = strchr(escpyptr, ']');
		if (escpyptr == NULL)
			return (EINVAL);
		escpyptr[0] = '\0'; /* \0:port */
		escpyptr++; /* :port */

		/* parse port if any */
		if (escpyptr[0] == ':') {
			escpyptr++; /* port */
			portptr = escpyptr;

			/* support the [X:X::X:X%ifname]:\0 case */
			if (portptr[0] == '\0')
				portptr = NULL;
		}

		/* set sin6 */
#ifdef DEBUG_INET6
		printf(__func__": sin6_addr %s\n", scpy);
		printf(__func__": ifname %s\n", ifnameptr);
		printf(__func__": port %s\n", portptr);
#endif /* DEBUG_INET6 */
		inet_pton(AF_INET6, scpy, &(sin6->sin6_addr));
		if (portptr != NULL)
			sin6->sin6_port = htons(strtoul(portptr, NULL, 10));
		else
			sin6->sin6_port = 0;
		if (ifnameptr != NULL) {
			const struct ifnet *ifp;

			ifp = __dev_get_by_name(&init_net,ifnameptr);
			sin6->sin6_scope_id = ifp->ifindex;
		}
		sin6->sin6_flowinfo = 0;

#ifdef DEBUG_INET6
		printf(__func__": sin6_addr %s sin6_scope_id %d port %d\n",
		       ip6_sprintf(&(sin6->sin6_addr)),
		       (u_int)sin6->sin6_scope_id,
		       (u_int)ntohs(sin6->sin6_port));
#endif /* DEBUG_INET6 */

		*off += strlen(s); /* XXX: Is it required ? */

		sa_len = sizeof(*sin6);
		break;
		}
#endif
#endif

	default:
		return (EINVAL);
	}

	/* Done */
	*buflen = sa_len;
	return (0);
}

/* Convert a struct sockaddr from binary to ASCII */
static int
ng_ksocket_sockaddr_unparse(const struct ng_parse_type *type,
	const u_char *data, int *off, char *cbuf, int cbuflen)
{
	const struct sockaddr *sa = (const struct sockaddr *)(data + *off);
	int slen = 0;

	/* Output socket address, either in special or generic format */
	switch (sa->sa_family) {

	case PF_INET:
	    {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;

		slen += snprintf(cbuf, cbuflen, "inet/%d.%d.%d.%d",
		  ((const u_char *)&sin->sin_addr)[0],
		  ((const u_char *)&sin->sin_addr)[1],
		  ((const u_char *)&sin->sin_addr)[2],
		  ((const u_char *)&sin->sin_addr)[3]);
		if (sin->sin_port != 0) {
			slen += snprintf(cbuf + strlen(cbuf),
			    cbuflen - strlen(cbuf), ":%d",
			    (u_int)ntohs(sin->sin_port));
		}
		if (slen >= cbuflen)
			return (ERANGE);
		*off += sizeof(*sin);
		return(0);
	    }

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#ifdef INET6
	case PF_INET6:
		{
		const struct sockaddr_in6 *sin6 =
			(const struct sockaddr_in6 *)sa;

		slen += snprintf(cbuf, cbuflen, "inet6/[%s",
			ip6_sprintf(&(sin6->sin6_addr)));

		if (sin6->sin6_scope_id != 0) {
			const struct ifnet *ifp;

			ifp = __dev_get_by_index(&init_net,sin6->sin6_scope_id);
			slen += snprintf(cbuf + strlen(cbuf),
				cbuflen - strlen(cbuf), "%%%s",
				ifp->name);
		}

		slen += snprintf(cbuf + strlen(cbuf),
				 cbuflen - strlen(cbuf),
				 "]");

		if (sin6->sin6_port != 0) {
			slen += snprintf(cbuf + strlen(cbuf),
				cbuflen - strlen(cbuf), ":%d",
			    (u_int)ntohs(sin6->sin6_port));
		}

		if (slen >= cbuflen)
			return (ERANGE);
		*off += sizeof(*sin6);
		return (0);
		}
#endif
#endif

	default:
		return (*ng_ksocket_generic_sockaddr_type.supertype->unparse)
		    (&ng_ksocket_generic_sockaddr_type,
		    data, off, cbuf, cbuflen);
	}
}

/* Parse type for struct sockaddr */
static const struct ng_parse_type ng_ksocket_sockaddr_type = {
	NULL,
	NULL,
	NULL,
	&ng_ksocket_sockaddr_parse,
	&ng_ksocket_sockaddr_unparse,
	NULL		/* no such thing as a default struct sockaddr */
};

/************************************************************************
		STRUCT NG_KSOCKET_SOCKOPT PARSE TYPE
 ************************************************************************/

/* Get length of the struct ng_ksocket_sockopt value field, which is the
   just the excess of the message argument portion over the length of
   the struct ng_ksocket_sockopt. */
static int
ng_parse_sockoptval_getLength(const struct ng_parse_type *type,
	const u_char *start, const u_char *buf)
{
	static const int offset = OFFSETOF(struct ng_ksocket_sockopt, value);
	const struct ng_ksocket_sockopt *sopt;
	const struct ng_mesg *msg;

	sopt = (const struct ng_ksocket_sockopt *)(buf - offset);
	msg = (const struct ng_mesg *)((const u_char *)sopt - sizeof(*msg));
	return (msg->header.arglen < sizeof(*sopt)) ?
		0 :
		msg->header.arglen - sizeof(*sopt);

}

/* Parse type for the option value part of a struct ng_ksocket_sockopt
   XXX Eventually, we should handle the different socket options specially.
   XXX This would avoid byte order problems, eg an integer value of 1 is
   XXX going to be "[1]" for little endian or "[3=1]" for big endian. */
static const struct ng_parse_type ng_ksocket_sockoptval_type = {
	&ng_parse_bytearray_type,
	&ng_parse_sockoptval_getLength
};

/* Parse type for struct ng_ksocket_sockopt */
static const struct ng_parse_struct_field ng_ksocket_sockopt_type_fields[]
	= NG_KSOCKET_SOCKOPT_INFO(&ng_ksocket_sockoptval_type);
static const struct ng_parse_type ng_ksocket_sockopt_type = {
	&ng_parse_struct_type,
	&ng_ksocket_sockopt_type_fields
};

/* Parse type for struct ng_ksocket_accept */
static const struct ng_parse_struct_field ng_ksocket_accept_type_fields[]
	= NGM_KSOCKET_ACCEPT_INFO;
static const struct ng_parse_type ng_ksocket_accept_type = {
	&ng_parse_struct_type,
	&ng_ksocket_accept_type_fields
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_ksocket_cmds[] = {
	{
	  NGM_KSOCKET_COOKIE,
	  NGM_KSOCKET_BIND,
	  "bind",
	  &ng_ksocket_sockaddr_type,
	  NULL
	},
	{
	  NGM_KSOCKET_COOKIE,
	  NGM_KSOCKET_LISTEN,
	  "listen",
	  &ng_parse_int32_type,
	  NULL
	},
	{
	  NGM_KSOCKET_COOKIE,
	  NGM_KSOCKET_ACCEPT,
	  "accept",
	  NULL,
	  &ng_ksocket_accept_type
	},
	{
	  NGM_KSOCKET_COOKIE,
	  NGM_KSOCKET_CONNECT,
	  "connect",
	  &ng_ksocket_sockaddr_type,
	  &ng_parse_int32_type
	},
	{
	  NGM_KSOCKET_COOKIE,
	  NGM_KSOCKET_GETNAME,
	  "getname",
	  NULL,
	  &ng_ksocket_sockaddr_type
	},
	{
	  NGM_KSOCKET_COOKIE,
	  NGM_KSOCKET_GETPEERNAME,
	  "getpeername",
	  NULL,
	  &ng_ksocket_sockaddr_type
	},
	{
	  NGM_KSOCKET_COOKIE,
	  NGM_KSOCKET_SETOPT,
	  "setopt",
	  &ng_ksocket_sockopt_type,
	  NULL
	},
	{
	  NGM_KSOCKET_COOKIE,
	  NGM_KSOCKET_GETOPT,
	  "getopt",
	  &ng_ksocket_sockopt_type,
	  &ng_ksocket_sockopt_type
	},
    {
      NGM_KSOCKET_COOKIE,
      NGM_KSOCKET_REUSE_DGRAM,
      "setreuse",
      NULL,
      NULL
    },
	{
	  NGM_KSOCKET_COOKIE,
	  NGM_KSOCKET_SETVRFID,
	  "setvrfid",
	  &ng_parse_uint16_type,
	  NULL
	},
	{
	  NGM_KSOCKET_COOKIE,
	  NGM_KSOCKET_ALLOCMETA,
	  "allocmeta",
	  NULL,
	  NULL
	},
	{
	  NGM_KSOCKET_COOKIE,
	  NGM_KSOCKET_STATUS,
	  "status",
	  NULL,
	  NULL
	},
	/* Internal commands */
	{
	  NGM_KSOCKET_INTERNAL_COOKIE,
	  NGM_KSOCKET_INTERNAL_UPCALL,
	  "upcall",
	  NULL,
	  NULL
	},
	{ 0 }
};

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_ksocket_typestruct) = {
	.version   = NG_VERSION,
	.name      = NG_KSOCKET_NODE_TYPE,
	.mod_event = NULL,
	.constructor=ng_ksocket_constructor,
	.rcvmsg    = ng_ksocket_rcvmsg,
	.shutdown  = ng_ksocket_rmnode,
	.newhook   = ng_ksocket_newhook,
	.findhook  = NULL,
	.connect   = NULL,
	.afterconnect = NULL,
	.rcvdata   = ng_ksocket_rcvdata,
	.rcvdataq  = ng_ksocket_rcvdata,
	.disconnect= ng_ksocket_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = ng_ksocket_dumphook,
	.restorehook = NULL,
	.cmdlist   = ng_ksocket_cmds
};
NETGRAPH_INIT(ksocket, &ng_ksocket_typestruct);
NETGRAPH_EXIT(ksocket, &ng_ksocket_typestruct);


/* For NGM_KSOCKET_REUSE_DGRAM command */
#ifdef SO_REUSEPORT
static int reuseport=1;
#endif
static int reuseaddr=1;

int ng_ksocket_init_module(void)
{
	return ng_ksocket_init();
}


/*
 * if we had an exit function, in case of a module for instance, we
 * would have an exit function like the following one for destroying
 * the thread.
 */
void ng_ksocket_exit_module(void)
{
	/* Unregister our type */
	ng_ksocket_exit();
}

/************************************************************************
			NETGRAPH NODE STUFF
 ************************************************************************/

/*
 * Node type constructor
 */
static int
ng_ksocket_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int error;

	if ((error = ng_make_node_common_and_priv(&ng_ksocket_typestruct,
						  nodep,
						  &priv,
						  sizeof(*priv),
						  nodeid))) {
		return (error);
	}
	bzero(priv, sizeof(*priv));

	/* Init receive side of the node's private data */
	INIT_WORK(&priv->recv_work, ksp_recv_work_handler);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	atomic_set(&priv->recv_work_exec_count, 0);
#endif

	/* Init transmit side of the node's private data */
	INIT_WORK(&priv->xmit_work, ksp_xmit_work_handler);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	atomic_set(&priv->xmit_work_exec_count, 0);
#endif
	spin_lock_init(&priv->xmit_skb_fifo_lock);
	priv->xmit_first_skb = NULL;
	priv->xmit_last_skb = NULL;
	atomic_set(&priv->xmit_skb_count, 0);

	/* Call generic node constructor */
	(*nodep)->private = priv;
	priv->node = *nodep;

	/* Done */
	return (0);
}

static void
ng_ksocket_write_space(struct sock *sk)
{
	struct socket *sock;
	read_lock(&sk->sk_callback_lock);
	if (!(sock = sk->sk_socket))
		goto out;
	if (!sock_writeable(sk))
		goto out;
	if (!test_and_clear_bit(SOCK_NOSPACE, &sock->flags))
		goto out;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
		wake_up_interruptible(sk->sk_sleep);
#else
	if (sk_sleep(sk) && waitqueue_active(sk_sleep(sk)))
		wake_up_interruptible(sk_sleep(sk));
#endif
out:
	read_unlock(&sk->sk_callback_lock);
}

/*
 *      sort out what type of thing it is
 *      and hand it to the right function.
 */
static void ng_ksocket_data_ready(struct sock *sk
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
				  , int slen
#endif
				  )
{
	node_p node;
	priv_p priv;

	read_lock(&sk->sk_callback_lock);

	VNB_ENTER();

	node = (node_p)sk->sk_user_data;

	if (!node || (node->flags & NG_INVALID))
		goto end;

	priv = node->private;
	if (!priv)
		goto end;

	if (sock_flag(sk, SOCK_DEAD)) {
		VNB_TRAP();
		goto end;
	}

	/*
	 * Schedule the receive work item that is associated with the socket.
	 */
	ksf_recv_work_schedule(priv);
end:
	VNB_EXIT();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
		wake_up_interruptible(sk->sk_sleep);
#else
	if (sk_sleep(sk) && waitqueue_active(sk_sleep(sk)))
		wake_up_interruptible(sk_sleep(sk));
#endif
	read_unlock(&sk->sk_callback_lock);

}

/*
 * Give our OK for a hook to be added. The hook name is of the
 * form "<family>/<type>/<proto>" where the three components may
 * be decimal numbers or else aliases from the above lists.
 *
 * Connecting a hook amounts to opening the socket.  Disconnecting
 * the hook closes the socket and destroys the node as well.
 */
static int
ng_ksocket_newhook(node_p node, hook_p hook, const char *name0)
{
	const priv_p priv = node->private;
	struct ng_mesg *msg;
	char *s1, *s2, name[NG_HOOKLEN+1];
	int family, type, protocol, error;

	/* Check if we're already connected */
	if (priv->hook != NULL)
		return (EISCONN);

	/* Extract family, type, and protocol from hook name */
	snprintf(name, sizeof(name), "%s", name0);
	s1 = name;
	if ((s2 = strchr(s1, '/')) == NULL)
		return (EINVAL);
	*s2++ = '\0';
	family = ng_ksocket_parse(ng_ksocket_families, s1, 0);
	if (family == -1)
		return (EINVAL);
	s1 = s2;
	if ((s2 = strchr(s1, '/')) == NULL)
		return (EINVAL);
	*s2++ = '\0';
	type = ng_ksocket_parse(ng_ksocket_types, s1, 0);
	if (type == -1)
		return (EINVAL);
	s1 = s2;
	protocol = ng_ksocket_parse(ng_ksocket_protos, s1, family);
	if (protocol == -1)
		return (EINVAL);

	/* udp & gre only */
	if (!((protocol == IPPROTO_UDP) || (protocol == IPPROTO_GRE)))
		return (EINVAL);

	/* Allocate the socket destructor */
	if ((priv->so_dtor = ng_dtor_alloc()) == NULL)
		return ENOMEM;
	/* Create the socket */
	error = sock_create_kern(family, type, protocol, &priv->so);
	if (error != 0) {
		ng_dtor_free(priv->so_dtor);
		priv->so_dtor = NULL;
		return (-error);
	}

#if defined(CONFIG_VNB_KSOCK_LARGE_BUFSZ)
	/* for all new ksockets, reserve large snd and rcv buffers */
	lock_sock(priv->so->sk);
	{
		int snd, rcv;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
		/* sysctl_?mem_max is not EXPORT_SYMBOL'ed'
		 * and so cannot be used to check CONFIG_VNB_KSOCK_BUFSZ.
		 */
		snd = max_t(u32, CONFIG_VNB_KSOCK_BUFSZ, (SOCK_MIN_SNDBUF + 1) / 2);
		rcv = max_t(u32, CONFIG_VNB_KSOCK_BUFSZ, (SOCK_MIN_RCVBUF + 1) / 2);
#else
		snd = clamp_t(int, CONFIG_VNB_KSOCK_BUFSZ, (SOCK_MIN_SNDBUF + 1) / 2,
			      sysctl_wmem_max);
		rcv = clamp_t(int, CONFIG_VNB_KSOCK_BUFSZ, (SOCK_MIN_RCVBUF + 1) / 2,
			      sysctl_rmem_max);
#endif
		priv->so->sk->sk_sndbuf = snd * 2;
		priv->so->sk->sk_rcvbuf = rcv * 2;
	}
	release_sock(priv->so->sk);
#endif

	/* XXX call soreserve() ? */

	priv->old_data_ready = priv->so->sk->sk_data_ready;
	priv->old_write_space = priv->so->sk->sk_write_space;
	priv->so->sk->sk_user_data = (void *)node;
	priv->so->sk->sk_data_ready = ng_ksocket_data_ready;
	priv->so->sk->sk_write_space = ng_ksocket_write_space;
	priv->so->sk->sk_allocation = GFP_ATOMIC;

	sock_hold(priv->so->sk); /* Released in "ng_ksocket_rmnode" */
	priv->sk = priv->so->sk;

	/* OK */
	priv->hook = hook;

	/*
	 * On a cloned socket we may have already received one or more
	 * upcalls which we couldn't handle without a hook.  Handle
	 * those now.  We cannot call the upcall function directly
	 * from here, because until this function has returned our
	 * hook isn't connected.  So we queue a message to ourselves
	 * which will cause the upcall function to be called a bit
	 * later.
	 */
	if (test_bit(KSF_CLONED, &priv->flags)) {
		NG_MKMESSAGE(msg, NGM_KSOCKET_INTERNAL_COOKIE,
		    NGM_KSOCKET_INTERNAL_UPCALL, 0, M_NOWAIT);
		if (msg != NULL)
			ng_queue_msg(node, msg, ".:");
	}

	return (0);
}

/*
 * Receive a control message
 */
static int
ng_ksocket_rcvmsg(node_p node, struct ng_mesg *msg,
	      const char *raddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const priv_p priv = node->private;
	struct socket *const so = priv->so;
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_KSOCKET_COOKIE:
		switch (msg->header.cmd) {
		case NGM_KSOCKET_BIND:
		    {
			struct sockaddr *sa = (struct sockaddr *)msg->data;

			u_int sa_len = (sa->sa_family == AF_INET ?
					sizeof(struct sockaddr_in) :
					sizeof(struct sockaddr_in6));

			/* Sanity check */
			if (msg->header.arglen < SADATA_OFFSET ||
			    msg->header.arglen < sa_len)
				ERROUT(EINVAL);
			if (so == NULL)
				ERROUT(ENXIO);

			/* Bind */
			if ((error = kernel_bind(so, sa, sa_len)) < 0)
				ERROUT(-error);

			set_bit(KSF_BOUND, &priv->flags);

#if defined(__LinuxKernelVNB__) && defined(CONFIG_VNB_NETLINK_NOTIFY)
			if ((error = VNB_DUP_NG_MESG(*nl_msg, msg)) != 0)
				break;
			memcpy(*nl_msg, msg,
			       sizeof(struct ng_mesg) + msg->header.arglen);
			sa = (struct sockaddr *)(*nl_msg)->data;
			switch (sa->sa_family) {
			case AF_INET:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
				((struct sockaddr_in *)sa)->sin_port =
					inet_sk(so->sk)->sport;
				((struct sockaddr_in *)sa)->sin_addr.s_addr =
					inet_sk(so->sk)->saddr;
#else
				((struct sockaddr_in *)sa)->sin_port =
					inet_sk(so->sk)->inet_sport;
				((struct sockaddr_in *)sa)->sin_addr.s_addr =
					inet_sk(so->sk)->inet_saddr;
#endif
				break;
			case AF_INET6:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
				((struct sockaddr_in6*)sa)->sin6_port =
					inet_sk(so->sk)->sport;
#else
				((struct sockaddr_in6*)sa)->sin6_port =
					inet_sk(so->sk)->inet_sport;
#endif
				((struct sockaddr_in6*)sa)->sin6_addr =
					inet6_sk(so->sk)->saddr;
				break;
			}
#endif
			break;
		    }
		case NGM_KSOCKET_LISTEN:
		    {
			/* Sanity check */
			if (msg->header.arglen != sizeof(int32_t))
				ERROUT(EINVAL);
			if (so == NULL)
				ERROUT(ENXIO);

			/* Listen */
			if ((error = so->ops->listen(so,
						     *((int *)msg->data))) < 0)
				ERROUT(-error);

			break;
		    }

		case NGM_KSOCKET_ACCEPT:
		    {
			struct socket *newsock;
			/* Sanity check */
			if (msg->header.arglen != 0)
				ERROUT(EINVAL);
			if (so == NULL)
				ERROUT(ENXIO);

			if ((error = kernel_accept(so, &newsock, 0)) < 0)
				ERROUT(-error);

			set_bit(KSF_ACCEPTED, &priv->flags);

			break;
		    }

		case NGM_KSOCKET_CONNECT:
		    {
			struct sockaddr *const sa
			    = (struct sockaddr *)msg->data;
			u_int sa_len;

			if (sa == NULL)
				ERROUT(EINVAL);

			if (msg == NULL)
				ERROUT(EINVAL);

			sa_len = (sa->sa_family == AF_INET ?
				  sizeof(struct sockaddr_in) :
				  sizeof(struct sockaddr_in6));

			/* Sanity check */
			if (msg->header.arglen < SADATA_OFFSET ||
			    msg->header.arglen < sa_len)
				ERROUT(EINVAL);
			if (so == NULL)
				ERROUT(ENXIO);
			if (so->ops == NULL)
				ERROUT(ENXIO);

			if (so->ops->connect == NULL)
				ERROUT(EINVAL);

			/* so->file is NULL, of course */

			if (test_bit(KSF_CONNECTING, &priv->flags))
				ERROUT(EALREADY);

			error = kernel_connect(so, sa, sa_len, 0);
			if (sa->sa_family == AF_INET &&
			    (error == -EHOSTUNREACH || error == -ENETUNREACH)) {
				struct inet_sock *inet = inet_sk(so->sk);
				struct sockaddr_in *sin =
					(struct sockaddr_in *) sa;

				set_bit(KSF_CONNECTING, &priv->flags);
				memcpy(&priv->connect_sa, sa,
				       sizeof(struct sockaddr));
				error = 0;

				/* save wanted addr and port in the sock
				 * structure: even if the connect failed, we
				 * will be able to filter received packets */
#if LINUX_VERSION_CODE >=  KERNEL_VERSION(2,6,33)
				inet->inet_daddr = sin->sin_addr.s_addr;
				inet->inet_dport = sin->sin_port;
#else
				inet->daddr = sin->sin_addr.s_addr;
				inet->dport = sin->sin_port;
#endif
			}
			else if (error < 0) {
				ERROUT(-error);
			}
			else { /* error == 0 */
				set_bit(KSF_CONNECTED, &priv->flags);
				memcpy(&priv->connect_sa, sa,
				       sizeof(struct sockaddr));
			}

			break;
		    }

		case NGM_KSOCKET_GETNAME:
		case NGM_KSOCKET_GETPEERNAME:
		    {
			char address[MAX_SOCK_ADDR];
			int len;

			error = so->ops->getname(so,
						 (struct sockaddr *)address,
						 &len,
						 (msg->header.cmd ==
						  NGM_KSOCKET_GETPEERNAME));
			if (error)
				ERROUT(-error);
			NG_MKRESPONSE(resp, msg, len, M_NOWAIT);
			if (resp == NULL)
				error = ENOMEM;
			else
				bcopy(address, resp->data, len);
			break;
		    }

		case NGM_KSOCKET_GETOPT:
		case NGM_KSOCKET_SETOPT:
		    {
			/* TODO: ops->getopt/setopt */
			error = EINVAL;
			break;
		    }

		case NGM_KSOCKET_REUSE_DGRAM:
		    {
			/* Sanity check */
			if ((so == NULL) || (so->sk == NULL))
				ERROUT(ENXIO);
			so->sk->sk_reuse = reuseaddr;
#ifdef SO_REUSEPORT
			so->sk->sk_reuseport = reuseport;
#endif
			break;
		    }

		case NGM_KSOCKET_SETVRFID:
		    {
			int vrfid = (int)*((uint16_t *)msg->data);
#if defined(USE_VRF_NETNS)
			struct net *net;
#endif

			/* An alredy bound socket can not change VR anymore */
			if (test_bit(KSF_BOUND, &priv->flags) != 0) {
				error = EINVAL;
				break;
			}

#ifdef CONFIG_NET_VRF

			error = kernel_setsockopt(priv->so, SOL_SOCKET,
						  SO_VRFID, (char *)&vrfid,
						  sizeof(int));
#else

#if defined(USE_VRF_NETNS)
			net = vrf_lookup_by_vrfid(vrfid);
			if (net == NULL) {
				error = ENOENT;
				break;
			}
			vnb_sk_change_net(priv->so->sk, net);
#else
			/* No VRF, no NETNS: changing VR is not supported */
			if (vrfid != 0)  {
				error = ENOSYS;
				break;
			}
#endif /* CONFIG_NET_NS && >= 3.0 */

#endif /* CONFIG_NET_VRF */
			break;

		    }

		case NGM_KSOCKET_ALLOCMETA:
			set_bit(KSF_ALLOCMETA, &priv->flags);
			break;

		case NGM_KSOCKET_STATUS:
			/* Supported only in fast path node */
			error = EOPNOTSUPP;
			break;

		default:
			error = EINVAL;
			break;
	}
	break;

	case NGM_KSOCKET_INTERNAL_COOKIE:
		switch (msg->header.cmd) {
		case NGM_KSOCKET_INTERNAL_UPCALL:
		/* linux does not support "NGM_KSOCKET_INTERNAL_UPCALL */
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

done:
	FREE(msg, M_NETGRAPH);
	return (error);
}

/* Transmit data from node to kernel socket */
static void
ksp_xmit_work_handler(struct work_struct *xmit_wk)
{
	struct sk_buff *m;
	struct sk_buff *skb_first;
	struct msghdr msg;
	struct iovec iov;
	struct sockaddr *sa = NULL;
	meta_p meta;
	struct socket * so;
	int error;
	mm_segment_t	oldfs;
	priv_p priv;
	node_p node;
	unsigned long flags;
	bool xvr = false;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	int exec_count;
#endif

	priv = xmit_work_to_kspriv(xmit_wk);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	exec_count = atomic_inc_return(&priv->xmit_work_exec_count);
	if (exec_count > 1) {
		/*
		 * The handler is currently executed by another worker.
		 * Give-up immediately. The handler currently executed
		 * will self-reschedule before returning.
		 */
		return;
	}
#endif

	/*
	 * Empty the transmit fifo of the node.
	 */
	spin_lock_irqsave(&priv->xmit_skb_fifo_lock, flags);
	skb_first = priv->xmit_first_skb;
	priv->xmit_first_skb = NULL;
	priv->xmit_last_skb = NULL;
	atomic_set(&priv->xmit_skb_count, 0);
	spin_unlock_irqrestore(&priv->xmit_skb_fifo_lock, flags);

	/* Process all packets in the fifo, if any. */
	while (skb_first != NULL) {
		m = skb_first;
		skb_first = m->next;
		meta = (meta_p) m->prev;
#if VNB_DEBUG
		int current_cpu;
#endif
		sa = NULL;

		/* We must not be rescheduled on another core */
		VNB_ENTER();
#if VNB_DEBUG
		current_cpu = VNB_CORE_ID();
#endif
		node = priv->node;
		if (!node) {
			VNB_EXIT();
			NG_FREE_DATA(m, meta);
			continue;
		}
		if ((NG_NODE_NOT_VALID(node)) ||
		    ((so = priv->so) == NULL)) {
			VNB_EXIT();
			NG_FREE_DATA(m, meta);
			continue;
		}

		/* If any meta info, look for peer socket address */
		if (meta != NULL) {
			struct meta_field_header *field;

			/* Look for peer socket address */
			for (field = &meta->options[0];
			     (caddr_t)field < (caddr_t)meta + meta->used_len;
			     field = (struct meta_field_header *)
				     ((caddr_t)field + field->len)) {
				if (field->cookie != NGM_KSOCKET_COOKIE ||
				    field->type != NG_KSOCKET_META_SOCKADDR)
					continue;
				sa = (struct sockaddr *)field->data;
				break;
			}
		}

		if (sa == NULL) {
			if (test_bit(KSF_CONNECTING, &priv->flags)) {
				/*
				 * Connect if not already done. If this flag
				 * is set, we know that family = AF_INET.
				 */
				int err;
				struct inet_sock *inet = inet_sk(so->sk);
				struct sockaddr_in *sin;

				sa = &priv->connect_sa;
				sin = (struct sockaddr_in *) sa;

				/*
				 * Restore the correct state of the inet_sk
				 * structure before doing the connect
				 * (the values were overriden when try to
				 * connect the first time).
				 */
#if LINUX_VERSION_CODE >=  KERNEL_VERSION(2,6,33)
				inet->inet_daddr = 0;
				inet->inet_dport = 0;
#else
				inet->daddr = 0;
				inet->dport = 0;
#endif
				err = so->ops->connect(so, sa, sizeof(*sin), 0);
				if (err == 0) {
					clear_bit(KSF_CONNECTING, &priv->flags);
					set_bit(KSF_CONNECTED, &priv->flags);
				} else {
					/*
					 * re-save wanted addr and port in the
					 * sock structure: even if the connect
					 * failed, we will be able to filter
					 * received packets.
					 */
#if LINUX_VERSION_CODE >=  KERNEL_VERSION(2,6,33)
					inet->inet_daddr = sin->sin_addr.s_addr;
					inet->inet_dport = sin->sin_port;
#else
					inet->daddr = sin->sin_addr.s_addr;
					inet->dport = sin->sin_port;
#endif
					VNB_EXIT();
					NG_FREE_DATA(m, meta);
					continue;
				}
			}

			/*
			 * Do not send packet on the socket before we are
			 * connected.
			 */
			if (test_bit(KSF_CONNECTED, &priv->flags) == 0) {
				VNB_EXIT();
				NG_FREE_DATA(m, meta);
				continue;
			}
		}

		iov.iov_base=m->data;
		iov.iov_len=m->len;
		msg.msg_name=NULL;
		/* XXX other fragments ? */
		msg.msg_iov=&iov;
		msg.msg_iovlen=1;
		msg.msg_control=NULL;
		msg.msg_controllen=0;
		msg.msg_namelen=0;
		if (sa) {
			u_int sa_len = (sa->sa_family == AF_INET ?
					sizeof(struct sockaddr_in) :
					sizeof(struct sockaddr_in6));
			msg.msg_name=sa;
			msg.msg_namelen=sa_len;
		}

		msg.msg_flags = MSG_DONTWAIT;

		oldfs = get_fs(); set_fs(KERNEL_DS);

#ifdef CONFIG_NET_VRF
		xvr = (m->vrfid != sock_vrfid(so->sk));
#else
		xvr = !net_eq(packet_net(m), sock_net(so->sk));
#endif
		kcompat_skb_scrub_packet(m, xvr);
		skb_orphan(m);

		error = sock_sendmsg(so, &msg, m->len);
		/* No more need for the node (we're done with "so") */
#if VNB_DEBUG
		/* VNB_CORE_ID() cannot be put in KASSERT() */
		if (current_cpu != VNB_CORE_ID())
			KASSERT(0);
#endif
		VNB_EXIT();
		set_fs(oldfs);

#if VNB_DEBUG
		/* positive return value is length of data sent */
		if (error < 0) {
			if (net_ratelimit())
				printk(KERN_DEBUG "unable to send packet via "
				       "ksocket (%d)\n", error);
		}
#else
		(void)error;
#endif

		NG_FREE_DATA(m, meta);
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	exec_count = atomic_xchg(&priv->xmit_work_exec_count, 0);
	if (exec_count > 1) {
		/*
		 * Parallel execution(s) of the receive work item immediately
		 * left at the entry of the receive handler above.
		 * Self-reschedule the same receive work item again.
		 */
		ksf_xmit_work_schedule(priv);
	}
#endif
}


/*
 * Transmit data from kernel socket to netgraph
 * The execution of this handler is triggered as the result of the
 * scheduling of the receive work item into a workqueue.
 */
static void
ksp_recv_work_handler(struct work_struct *recv_wk)
{
	int err;
	struct sk_buff *skb = NULL;
	meta_p meta = NULL;
	priv_p priv;
	unsigned int cutoff_size = 0;
	struct sock * sk;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	int exec_count;
#endif

	priv = recv_work_to_kspriv(recv_wk);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	exec_count = atomic_inc_return(&priv->recv_work_exec_count);
	if (exec_count > 1) {
		/*
		 * The handler is currently executed by another worker.
		 * Give-up immediately. The handler currently executed
		 * will self-reschedule before returning.
		 */
		return;
	}
#endif
#if VNB_DEBUG
	int current_cpu;
#endif
	/* We must not be rescheduled on another core */
	VNB_ENTER();
#if VNB_DEBUG
	current_cpu = VNB_CORE_ID();
#endif

	sk = priv->sk;
	while ((skb = skb_recv_datagram(sk, 0, 1, &err)) != NULL) {
		cutoff_size = 0;
		meta = NULL;

		if ((sk->sk_type == SOCK_RAW) &&
		    (sk->sk_protocol == IPPROTO_GRE)) {
			if (sk->sk_family == AF_INET)
				cutoff_size = sizeof(struct iphdr);
		}
		else if ((sk->sk_type == SOCK_DGRAM) &&
			 (sk->sk_protocol == IPPROTO_UDP))
			cutoff_size = sizeof(struct udphdr);

		if (skb->len < cutoff_size) {
			VNB_TRAP();
			goto dropit;
		}

		if (!pskb_may_pull(skb, cutoff_size))
			goto dropit;
		skb_pull(skb, cutoff_size);

		skb_reset_mac_header(skb);
		skb_reset_network_header(skb);

		/*
		 * If we don't have a hook, we must handle data events later.
		 * When the hook gets created and is connected, this upcall
		 * function will be called again.
		 */
		if (priv->hook == NULL) {
			VNB_TRAP();
			goto dropit;
		}

		if ((sk->sk_family == AF_INET)) {
			struct meta_field_header *mhead;
			struct sockaddr_in sin;
			u_int len;
			struct inet_sock *inet = inet_sk(sk);

			/* sin should be initialized */
			bzero(&sin, sizeof(sin));
#if LINUX_VERSION_CODE >=  KERNEL_VERSION(2,6,33)
			if (inet->inet_daddr == 0)
				goto sendit;
			sin.sin_port = inet->inet_dport;
			sin.sin_addr.s_addr = inet->inet_daddr;
#else
			if (inet->daddr == 0)
				goto sendit;
			sin.sin_port = inet->dport;
			sin.sin_addr.s_addr = inet->daddr;
#endif
			sin.sin_family = AF_INET;
			len = sizeof(*meta) + sizeof(*mhead) + sizeof(sin);
			MALLOC(meta, meta_p, len, M_NETGRAPH, M_NOWAIT);
			if (meta == NULL) {
				printk(KERN_INFO "can't alloc meta\n");
				goto dropit;
			}
			mhead = &meta->options[0];
			bzero(meta, sizeof(*meta));
			bzero(mhead, sizeof(*mhead));
			meta->allocated_len = len;
			meta->used_len = len;
			mhead->cookie = NGM_KSOCKET_COOKIE;
			mhead->type = NG_KSOCKET_META_SOCKADDR;
			mhead->len = sizeof(*mhead) + sizeof(sin);
			bcopy(&sin, mhead->data, sizeof(sin));
		}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else if ((sk->sk_family == AF_INET6)) {

#ifndef sk_v6_daddr
			struct ipv6_pinfo *np = inet6_sk(sk);
#endif
			struct sockaddr_in6 sin6;
			struct meta_field_header *mhead;
			u_int len;

#ifndef sk_v6_daddr
			if (ipv6_addr_type(&np->daddr) == IPV6_ADDR_ANY)
#else
			if (ipv6_addr_type(&sk->sk_v6_daddr) == IPV6_ADDR_ANY)
#endif
				goto sendit;

			sin6.sin6_family = AF_INET6;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
			sin6.sin6_port = inet_sk(sk)->inet_dport;
#else
			sin6.sin6_port = inet_sk(sk)->dport;
#endif
#ifndef sk_v6_daddr
			bcopy(&np->daddr, &sin6.sin6_addr,
			      sizeof(struct in6_addr));
#else
			bcopy(&sk->sk_v6_daddr, &sin6.sin6_addr,
			      sizeof(struct in6_addr));
#endif
			len = sizeof(*meta) + sizeof(*mhead) + sizeof(sin6);
			MALLOC(meta, meta_p, len, M_NETGRAPH, M_NOWAIT);
			if (meta == NULL) {
				printk(KERN_INFO "can't alloc meta\n");
				goto dropit;
			}
			mhead = &meta->options[0];
			bzero(meta, sizeof(*meta));
			bzero(mhead, sizeof(*mhead));
			meta->allocated_len = len;
			meta->used_len = len;
			mhead->cookie = NGM_KSOCKET_COOKIE;
			mhead->type = NG_KSOCKET_META_SOCKADDR;
			mhead->len = sizeof(*mhead) + sizeof(sin6);
			bcopy(&sin6, mhead->data, sizeof(sin6));
		}
#endif

		/*
		 * free our recv buffer before passing the skb to upper
		 * layer. This skb is likely to be attached to another
		 * socket that overwrites skb->sk. In this case kfree_skb
		 * will free recv buffer of the new socket, not ours.
		 * skb_orphan() will call skb->destructor == sock_rfree()
		 */
	sendit:
		skb_orphan(skb);

		/* Forward data with optional peer sockaddr as meta info */
		NG_SEND_DATA(err, priv->hook, skb, meta);

		/* skb = 0 if xmit successful */
		if (skb)
			skb_free_datagram(sk, skb);

		/* XXX display err on error ? */

		continue;

	dropit:
		skb_orphan(skb);
		skb_free_datagram(sk, skb);

	} /* end of while (skb_recv_datagram()) */

#if VNB_DEBUG
	/* VNB_CORE_ID() cannot be put in KASSERT() */
	if (current_cpu != VNB_CORE_ID())
		KASSERT(0);
#endif
	VNB_EXIT();
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	exec_count = atomic_xchg(&priv->recv_work_exec_count, 0);
	if (exec_count > 1) {
		/*
		 * Parallel execution(s) of the receive work item immediately
		 * left at the entry of the receive handler above.
		 * Self-reschedule the same receive work item again.
		 */
		ksf_recv_work_schedule(priv);
	}
#endif
}

/*
 * Receive incoming data on our hook.  Send it out the socket.
 * By construction, the "prev" and "next" fields of the supplied skbuff
 * are available.
 * Use the "next" field of the skbuff to append the packet at the tail of
 * the transmit fifo of the node.
 * Use the "prev" field to store the "meta" argument that is associated
 * with the packet.
 */
static int
ng_ksocket_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = hook->node;
	priv_p priv;
	struct socket *so;
	struct sk_buff *last_skb;
	unsigned long flags;

	if (!node) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	priv = node->private;
	if (!priv) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	so = priv->so;

	/* node is invalid, drop every new packet */
	if (((node->flags & NG_INVALID) != 0) || (so == NULL)) {
		NG_FREE_DATA(m, meta);
		return(EINVAL);
	}

	/*
	 * First check that the number of pending packets that are queued into
	 * the transmit fifo of the node did not reach the [configurable]
	 * common threshold.
	 * If so, free the packet and return the ENOMEM error code.
	 * Otherwise, append the packet at the tail of the transmit fifo of
	 * the node.
	 */
	spin_lock_irqsave(&priv->xmit_skb_fifo_lock, flags);
	if (atomic_read(&priv->xmit_skb_count) >= max_xmit) {
		spin_unlock_irqrestore(&priv->xmit_skb_fifo_lock, flags);
		NG_FREE_DATA(m, meta);
		return (ENOMEM);
	}

	/*
	 * Store the meta parameter into the otherwise unused "prev" field
	 * of the sk_buff.
	 */
	m->prev = (struct sk_buff *) meta;

	/*
	 * Append the packet at the tail of the transmit fifo of the node.
	 */
	m->next = NULL;
	last_skb = priv->xmit_last_skb;
	priv->xmit_last_skb = m;
	if (last_skb == NULL)
		priv->xmit_first_skb = m;
	else
		last_skb->next = m;
	atomic_inc(&priv->xmit_skb_count);
	spin_unlock_irqrestore(&priv->xmit_skb_fifo_lock, flags);

	/*
	 * Schedule the transmit work item.
	 * Avoid the overhead of checking if the transmit work item
	 * has already been queued, as the workqueue framework already
	 * addresses this case.
	 */
	ksf_xmit_work_schedule(priv);
	return (0);
}

/*
 * Asynchronous socket destructor
 */
static void ng_ksocket_rmnode_sock_release(void *data)
{
	struct socket *so = (struct socket *)data;
	sk_release_kernel(so->sk);
}

/*
 * Destroy node
 */
static int
ng_ksocket_rmnode(node_p node)
{
	const priv_p priv = node->private;
	struct sock     *sk;
	struct socket *so = priv->so;
	void *so_dtor = priv->so_dtor;
	struct sk_buff *skb;
	unsigned long flags;

	priv->so = NULL;
	priv->so_dtor = NULL;

	/* Register a destructor for our socket (if any) */
	if (so != NULL) {
		sk = so->sk;
		if (sk) {
			write_lock_bh(&sk->sk_callback_lock);
			sk->sk_data_ready =  priv->old_data_ready;
			sk->sk_write_space = priv->old_write_space;
			sk->sk_user_data = NULL;
			write_unlock_bh(&sk->sk_callback_lock);
		}
		KASSERT(so_dtor != NULL);
		ng_dtor(so_dtor, ng_ksocket_rmnode_sock_release, so);
	}
	else if (so_dtor != NULL)
		ng_dtor_free(so_dtor); /* somehow there's no socket but the
					  destructor is allocated, free it. */

	/* Take down netgraph node */
	ng_cutlinks(node);
	ng_unname(node);
	/* private structure is freed when the node is freed */
	node->private = NULL;
	NG_NODE_UNREF(node);	/* let the node escape */

	/* Cancel transmit work item. */
	(void) cancel_work_sync(&priv->xmit_work);

	/* Flush transmit fifo of the node. */
	spin_lock_irqsave(&priv->xmit_skb_fifo_lock, flags);
	skb = priv->xmit_first_skb;
	priv->xmit_first_skb = NULL;
	priv->xmit_last_skb = NULL;
	atomic_set(&priv->xmit_skb_count, 0);
	spin_unlock_irqrestore(&priv->xmit_skb_fifo_lock, flags);
	while (skb != NULL) {
		struct sk_buff *next_skb;
		meta_p meta;

		next_skb = skb->next;
		meta = (meta_p) skb->prev;
		NG_FREE_DATA(skb, meta);
		skb = next_skb;
	}

	/* Cancel receive work item. */
	(void) cancel_work_sync(&priv->recv_work);

	/* Release reference to sk, if any.*/
	sk = priv->sk;
	priv->sk = NULL;
	if (sk != NULL)
		sock_put(sk);
	return 0;
}

/*
 * Hook disconnection
 */
static int
ng_ksocket_disconnect(hook_p hook)
{
	KASSERT(hook->node->numhooks == 0);
	ng_rmnode(hook->node);
	return (0);
}

/************************************************************************
			HELPER STUFF
 ************************************************************************/

/*
 * Parse out either an integer value or an alias.
 */
static int
ng_ksocket_parse(const struct ng_ksocket_alias *aliases,
	const char *s, int family)
{
	int k, val;
	char *eptr;

	/* Try aliases */
	for (k = 0; aliases[k].name != NULL; k++) {
		if (strcmp(s, aliases[k].name) == 0 &&
		    aliases[k].family == family)
			return aliases[k].value;
	}

	/* Try parsing as a number */
	val = (int)strtoul(s, &eptr, 10);
	if (val < 0 || *eptr != '\0')
		return (-1);
	return (val);
}

struct ng_ksocket_nl_hookpriv {
	uint32_t node_flags;
	struct sockaddr addr;
	struct sockaddr peeraddr;
	uint16_t vrfid;
} __attribute__ ((packed));

static struct ng_nl_hookpriv *
ng_ksocket_dumphook(node_p node, hook_p hook)
{
	struct ng_nl_hookpriv *nlhookpriv;
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct socket *const so = priv->so;
	unsigned long flags = priv->flags;
	struct ng_ksocket_nl_hookpriv *ksocket_nlhookpriv;
	int error = 0;
#ifdef SO_VRFID
	int vrfid = 0;
#endif
	int len = 0;

	MALLOC(nlhookpriv, struct ng_nl_hookpriv *,
	       sizeof(*nlhookpriv) + sizeof(*ksocket_nlhookpriv),
	       M_NETGRAPH, M_NOWAIT | M_ZERO);

	if (!nlhookpriv)
		return NULL;

	ksocket_nlhookpriv = (struct ng_ksocket_nl_hookpriv *)nlhookpriv->data;

	nlhookpriv->data_len = sizeof(*ksocket_nlhookpriv);

	/* KSF_CONNECTING is not used in fast path, set the KSF_CONNECTED bit */
	if (test_bit(KSF_CONNECTING, &flags))
		set_bit(KSF_CONNECTED, &flags);

	ksocket_nlhookpriv->node_flags = htonl(flags);

	if (test_bit(KSF_BOUND, &flags)) {
		if ((error = kernel_getsockname(so, &ksocket_nlhookpriv->addr,
						&len))) {
			log(LOG_DEBUG, "%s: getsockname for addr for node %s "
			    "/ hook %s failed err=%d\n", __func__,
			    node->name, hook->name, error);
			goto error;
		}
	}

	if (test_bit(KSF_CONNECTED, &flags)) {
		memcpy(&ksocket_nlhookpriv->peeraddr, &priv->connect_sa,
		       sizeof(struct sockaddr));
	}

#ifdef SO_VRFID
	len = sizeof(vrfid);
	if ((error = kernel_getsockopt(so, SOL_SOCKET, SO_VRFID,
				       (char *)&vrfid, &len))) {
		log(LOG_DEBUG, "%s: get vrfid for node %s / hook %s "
		    "failed err=%d\n", __func__,
		    node->name, hook->name, error);
		goto error;
	}

	ksocket_nlhookpriv->vrfid = htons((uint16_t)vrfid);
#endif

	return nlhookpriv;

 error:

	FREE(nlhookpriv, M_NETGRAPH);
	return NULL;
}

module_init(ng_ksocket_init_module);
module_exit(ng_ksocket_exit_module);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB ksocket node");
MODULE_LICENSE("GPL");
