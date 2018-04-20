/*
 * Copyright(c) 2007 6WIND
 */

/*
 * fp-ng_ksocket.c
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
 */

#include <stdbool.h>

#include "fpn.h"
#include "fp-includes.h"
#include "fpn-assert.h"
#include "fpn-gc.h"
#include "fpn-lock.h"

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>

#include "netinet/fp-udp.h"
#include "netinet/fp-in6.h"
#include "fp-jhash.h"

#include "fp-main-process.h"
#ifdef CONFIG_MCORE_IP
#include "fp-ip.h"
#endif
#ifdef CONFIG_MCORE_IPV6
#include "fp-ip6.h"
#endif
#ifdef CONFIG_MCORE_IP
#include "fp-lookup.h"
#endif
#include "fpn-cksum.h"
#include "fp-ng_ksocket.h"
#ifdef CONFIG_MCORE_IPV6
#include "ip6_sprintf.h"
#include "inet_pton.c"
#endif

#define OFFSETOF(s, e) ((char *)&((s *)0)->e - (char *)((s *)0))
#define SADATA_OFFSET	(OFFSETOF(struct fp_sockaddr, sa_data))

/* Internal commands which we send to ourselves */
#define	NGM_KSOCKET_INTERNAL_COOKIE	(NGM_KSOCKET_COOKIE + 1)

#ifdef CONFIG_MCORE_KSOCKET_HASH_ORDER
#define KSOCKET_HASH_ORDER CONFIG_MCORE_KSOCKET_HASH_ORDER
#else
#define KSOCKET_HASH_ORDER 10
#endif

#define KSOCKET_HASH_SIZE (1 << KSOCKET_HASH_ORDER)

#ifdef CONFIG_MCORE_KSOCKET_POOL_SIZE
#define KSOCKET_POOL_SIZE CONFIG_MCORE_KSOCKET_POOL_SIZE
#else
#define KSOCKET_POOL_SIZE 65536
#endif

//#define DEBUG_INET6

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
static ng_restorehook_t ng_ksocket_restorehook;


/* Alias structure */
struct ng_ksocket_alias {
	const char	*name;
	const int	value;
	const int	family;
};

/* Protocol family aliases */
static const struct ng_ksocket_alias ng_ksocket_families[] = {
	{ "local",	PF_LOCAL, 0	},
	{ "inet",	PF_INET, 0		},
	{ "inet6",	PF_INET6, 0	},
	{ NULL,		-1, 0		},
};

/* Socket type aliases */
static const struct ng_ksocket_alias ng_ksocket_types[] = {
	{ "stream",	FP_SOCK_STREAM, 0	},
	{ "dgram",	FP_SOCK_DGRAM, 0	},
	{ "raw",	FP_SOCK_RAW, 0	},
	{ NULL,		-1, 0		},
};

/* Protocol aliases */
static const struct ng_ksocket_alias ng_ksocket_protos[] = {
	{ "ip",		FP_IPPROTO_IP,		PF_INET		},
	{ "raw",	FP_IPPROTO_RAW,		PF_INET		},
	{ "icmp",	FP_IPPROTO_ICMP,		PF_INET		},
	{ "igmp",	FP_IPPROTO_IGMP,		PF_INET		},
	{ "tcp",	FP_IPPROTO_TCP,		PF_INET		},
	{ "udp",	FP_IPPROTO_UDP,		PF_INET		},
	{ "gre",	FP_IPPROTO_GRE,		PF_INET		},
	{ "esp",	FP_IPPROTO_ESP,		PF_INET		},
	{ "ah",		FP_IPPROTO_AH,		PF_INET		},
#if defined(FP_IPPROTO_SWIPE)
	{ "swipe",	FP_IPPROTO_SWIPE,		PF_INET		},
#endif
#if defined(FP_IPPROTO_ENCAP)
	{ "encap",	FP_IPPROTO_ENCAP,		PF_INET		},
#endif
#if defined(FP_IPPROTO_DIVERT)
	{ "divert",	FP_IPPROTO_DIVERT,		PF_INET		},
#endif
#if defined(ATM_PROTO_AAL5) && defined(FP_PF_ATM)
	{ "aal5",   	FP_ATM_PROTO_AAL5,     	FP_PF_ATM  	},
#endif
#ifdef CONFIG_MCORE_IPV6
	{ "ip",		FP_IPPROTO_IP,		PF_INET6	},
	{ "ipip",	FP_IPPROTO_IPIP, 		PF_INET6	},
	{ "tcp",	FP_IPPROTO_TCP,		PF_INET6	},
	{ "egp",	FP_IPPROTO_EGP,		PF_INET6	},
	{ "pup", 	FP_IPPROTO_PUP,		PF_INET6	},
	{ "udp",	FP_IPPROTO_UDP,		PF_INET6	},
        { "gre",        FP_IPPROTO_GRE,            PF_INET6        },
	{ "idp",	FP_IPPROTO_IDP,		PF_INET6	},
#if defined(FP_IPPROTO_TP)
	{ "tp",		FP_IPPROTO_TP,		PF_INET6	},
#endif
	{ "ipv6",	FP_IPPROTO_IPV6,		PF_INET6	},
	{ "icmpv6",	FP_IPPROTO_ICMPV6,		PF_INET6	},
#if defined(FP_IPPROTO_EON)
	{ "eon",	FP_IPPROTO_EON,		PF_INET6	},
#endif
#if defined(FP_IPPROTO_ENCAP)
	{ "encap",	FP_IPPROTO_ENCAP,		PF_INET6	},
#endif
#if defined(FP_IPPROTO_DIVERT)
	{ "divert6",	FP_IPPROTO_DIVERT,		PF_INET6	},
#endif
	{ "raw",	FP_IPPROTO_RAW,		PF_INET6	},
	{ "esp",	FP_IPPROTO_ESP,		PF_INET6	},
	{ "ah",		FP_IPPROTO_AH,		PF_INET6	},
#endif
	{ NULL,		-1, 0					},

};


/* structure containing elements that define a flow, uniq for each
 * socket. Data are stored in network order. */
struct ng_ksocket_flow {
	union {
		struct {
			struct fp_sockaddr src;
			struct fp_sockaddr dst;
		} sa;
		struct {
			struct fp_sockaddr_in src;
			struct fp_sockaddr_in dst;
		} sin;
#ifdef CONFIG_MCORE_IPV6
		struct {
			struct fp_sockaddr_in6 src;
			struct fp_sockaddr_in6 dst;
		} sin6;
#endif
	} u;
	uint16_t family;
	uint8_t proto;
	uint16_t vrfid;
};

/* Node private data */
struct ng_ksocket_private {
	node_p		node;
	hook_p		hook;
	struct ng_ksocket_flow fl;
	union {
		struct fp_ip ip;
#ifdef CONFIG_MCORE_IPV6
		struct fp_ip6_hdr ip6;
#endif
	} hdr;
	unsigned int next; /* Next index in list. */
	struct {
		bool connecting:1; /* Waiting for connection complete */
		bool accepting:1; /* Waiting for accept complete */
		bool eofseen:1; /* Have sent 0-length EOF mbuf */
		bool cloned:1; /* Cloned from an accepting socket */
		bool embryonic:1; /* Cloned node with no hooks yet */
		bool sending:1; /* Sending on socket */
		bool connected:1; /* Made connect on the socket without error */
		bool accepted:1; /* Made accept on the socket without error */
		bool bound:1; /* Made bind on the socket without error */
		bool busy:1; /* Used to sync access to socket, socket enqueued */
		bool allocmeta:1; /* Allocate meta to store source sockaddr */
		bool reuse:1; /* Enable reuse of LADDR/LPORT */
#ifdef CONFIG_MCORE_FPN_ASSERT_ENABLE
		volatile bool pooled:1; /* Object is in the pool (free). */
#endif
		volatile bool hashed:1; /* Object is linked in a hash table. */
	} ksf;
	uint32_t hash;
};

typedef struct ng_ksocket_private *priv_p;

static FPN_DEFINE_SHARED(struct ng_ksocket_private (*)[KSOCKET_POOL_SIZE],
			 ng_ksocket_pool_ns[VNB_MAX_NS]);
static FPN_DEFINE_SHARED(volatile unsigned int,
			 ng_ksocket_pool_free_ns[VNB_MAX_NS]);
static FPN_DEFINE_SHARED(volatile unsigned int,
			 ng_ksocket_pool_free_gc_ns[VNB_MAX_NS]);
static FPN_DEFINE_SHARED(fpn_spinlock_t, ng_ksocket_pool_lock_ns[VNB_MAX_NS]);
static FPN_DEFINE_SHARED(struct fpn_gc_object, ng_ksocket_gco_ns[VNB_MAX_NS]);

static priv_p ng_ksocket_pool_fetch(unsigned int ns);
static void ng_ksocket_pool_return_gc(struct fpn_gc_object *gco);
static void ng_ksocket_pool_return(unsigned int ns, priv_p priv);
static unsigned int ng_ksocket_pool_index(unsigned int ns, priv_p priv);

#define KSOCKET_LIST_END KSOCKET_POOL_SIZE

/* Hash table entries contain the pool index of the first element in list
 * or KSOCKET_LIST_END when empty.
 *
 * Entries are volatile to ensure ordering during access and prevent the
 * compiler from optimizing them out. */

static FPN_DEFINE_SHARED(volatile unsigned int (*)[KSOCKET_HASH_SIZE],
			 ng_ksocket_hashtable_ns[VNB_MAX_NS]);
static void ng_ksocket_link(unsigned int ns, uint32_t hash, priv_p priv);
static void ng_ksocket_unlink(unsigned int ns, uint32_t hash, priv_p priv);
static priv_p ng_ksocket_lookup(unsigned int ns, struct ng_ksocket_flow *fl);
static uint32_t ng_ksocket_hash(struct ng_ksocket_flow * fl);
#ifdef CONFIG_MCORE_IP
static int ng_ksocket_input(struct mbuf *m);
#endif

#ifdef CONFIG_MCORE_IP
static FPN_DEFINE_SHARED(fp_ip_proto_handler_t, ng_udp_hdlr) = {
	.func = ng_ksocket_input
};
static FPN_DEFINE_SHARED(fp_ip_proto_handler_t, ng_gre_hdlr) = {
	.func = ng_ksocket_input
};
#endif

#ifdef CONFIG_MCORE_IPV6
static FPN_DEFINE_SHARED(volatile unsigned int (*)[KSOCKET_HASH_SIZE],
			 ng_ksocket6_hashtable_ns[VNB_MAX_NS]);
static void ng_ksocket6_link(unsigned int ns, uint32_t hash, priv_p priv);
static void ng_ksocket6_unlink(unsigned int ns, uint32_t hash, priv_p priv);
static priv_p ng_ksocket6_lookup(unsigned int ns, struct ng_ksocket_flow *fl);
static uint32_t ng_ksocket6_hash(struct ng_ksocket_flow * fl);
static int ng_ksocket6_input(struct mbuf *m);

static FPN_DEFINE_SHARED(fp_ip6_proto_handler_t, ng_udp6_hdlr) = {
	.func = ng_ksocket6_input
};
static FPN_DEFINE_SHARED(fp_ip6_proto_handler_t, ng_gre6_hdlr) = {
	.func = ng_ksocket6_input
};
#endif

static int ng_ksocket_parse(const struct ng_ksocket_alias *aliases, const char *s, int family);


static void init_ip_header(priv_p priv)
{
	struct fp_ip *ip = &priv->hdr.ip;

	ip->ip_v = IPVERSION;
	ip->ip_hl = 5;
	ip->ip_tos = 0;
	ip->ip_ttl = IPDEFTTL;
	ip->ip_len = 0;
	ip->ip_src.s_addr = priv->fl.u.sin.src.sin_addr.s_addr;
	ip->ip_dst.s_addr = priv->fl.u.sin.dst.sin_addr.s_addr;
	ip->ip_p = priv->fl.proto;
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_sum = fpn_ip_hdr_cksum(ip, sizeof(struct fp_ip));
}

#ifdef CONFIG_MCORE_IPV6
static void init_ip6_header(priv_p priv)
{
	struct fp_ip6_hdr *ip6 = &priv->hdr.ip6;

	ip6->ip6_v = FP_IP6VERSION;
	ip6->ip6_vfc = 0;
	ip6->ip6_flow = 0;
	ip6->ip6_nxt = 0;
	ip6->ip6_plen = 0;
	ip6->ip6_hlim = IPDEFTTL;
	memcpy(&ip6->ip6_src, &priv->fl.u.sin6.src.sin6_addr, sizeof(struct fp_in6_addr));
	memcpy(&ip6->ip6_dst, &priv->fl.u.sin6.dst.sin6_addr, sizeof(struct fp_in6_addr));
}
#endif
/************************************************************************
			STRUCT SOCKADDR PARSE TYPE
 ************************************************************************/

/* Get the length of the data portion of a generic struct fp_sockaddr */
static int
ng_parse_generic_sockdata_getLength(const struct ng_parse_type *type,
	const u_char *start, const u_char *buf)
{
	return (sizeof(struct fp_sockaddr) < SADATA_OFFSET) ? 0 : sizeof(struct fp_sockaddr) - SADATA_OFFSET;
}

/* Type for the variable length data portion of a generic struct fp_sockaddr */
static const struct ng_parse_type ng_ksocket_generic_sockdata_type = {
	.supertype = &ng_parse_bytearray_type,
	.info = &ng_parse_generic_sockdata_getLength
};

/* Type for a generic struct fp_sockaddr */
static const struct ng_parse_struct_field
    ng_parse_generic_sockaddr_type_fields[] = {
	  { "len",	&ng_parse_uint8_type, 0			},
	  { "family",	&ng_parse_uint8_type, 0			},
	  { "data",	&ng_ksocket_generic_sockdata_type, 0	},
	  { NULL, NULL, 0 }
};
static const struct ng_parse_type ng_ksocket_generic_sockaddr_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_parse_generic_sockaddr_type_fields
};


/* Convert a struct fp_sockaddr from ASCII to binary.  If its a protocol
   family that we specially handle, do that, otherwise defer to the
   generic parse type ng_ksocket_generic_sockaddr_type. */
static int
ng_ksocket_sockaddr_parse(const struct ng_parse_type *type,
	const char *s, int *off, const u_char *const start,
	u_char *const buf, int *buflen)
{
	struct fp_sockaddr *const sa = (struct fp_sockaddr *)buf;
	enum ng_parse_token tok;
	char fambuf[32];
	int family;
	unsigned int len;
	char *t;
	int sa_len = 0;

	/* If next token is a left curly brace, use generic parse type */
	if ((tok = ng_parse_get_token(s, off, (int *)&len)) == T_LBRACE) {
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
		struct fp_sockaddr_in *const sin = (struct fp_sockaddr_in *)sa;
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
#ifdef CONFIG_MCORE_IPV6
	case PF_INET6:		/* Get an IPv6 address with optional port */
		{
		struct fp_sockaddr_in6 *const sin6 = (struct fp_sockaddr_in6 *)sa;

		/*
		 * Parse this: [X:X::X:X%ifname]:port
		 *  ifname and port are optional
		 */
		const char *sptr;
		/* const */ char *ifnameptr = NULL; /* const is not supported by ifunit !! */
		const char *portptr = NULL;
		char scpy[FP_INET6_ADDRSTRLEN +1+FP_IFNAMSIZ +1+1+4 +2];
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
		TRACE_VNB(FP_LOG_DEBUG, "%s: sin6_addr %s\n", __FUNCTION__, scpy);
		TRACE_VNB(FP_LOG_DEBUG, "%s: ifname %s\n", __FUNCTION__, ifnameptr);
		TRACE_VNB(FP_LOG_DEBUG, "%s: port %s\n", __FUNCTION__, portptr);
#endif /* DEBUG_INET6 */
		inet_pton(AF_INET6, scpy, &(sin6->sin6_addr));
		if (portptr != NULL)
			sin6->sin6_port = htons(strtoul(portptr, NULL, 10));
		else
			sin6->sin6_port = 0;

		if (ifnameptr != NULL) {
			fp_ifnet_t *ifp;

			ifp = fp_getifnetbyname(ifnameptr);
			if(ifp != NULL)
				sin6->sin6_scope_id = ifp->if_ifuid;
		}
		sin6->sin6_flowinfo = 0;

#ifdef DEBUG_INET6
		TRACE_VNB(FP_LOG_DEBUG, "%s %p: sin6_addr %s sin6_scope_id %d port %d\n",
			__FUNCTION__, &(sin6->sin6_addr),
			ip6_sprintf(&(sin6->sin6_addr)), (u_int)sin6->sin6_scope_id,
			(u_int)ntohs(sin6->sin6_port));
#endif /* DEBUG_INET6 */

		*off += strlen(s); /* XXX: Is it required ? */

		sa_len = sizeof(*sin6);
		break;
		}
#endif

#if 0
	case PF_APPLETALK:	/* XXX implement these someday */
	case PF_IPX:
	case PF_LOCAL:		/* Get pathname */
#endif

	default:
		return (EINVAL);
	}

	/* Done */
	*buflen = sa_len;
	return (0);
}

/* Convert a struct fp_sockaddr from binary to ASCII */
static int
ng_ksocket_sockaddr_unparse(const struct ng_parse_type *type,
	const u_char *data, int *off, char *cbuf, int cbuflen)
{
	const struct fp_sockaddr *sa = (const struct fp_sockaddr *)(data + *off);
	int slen = 0;

	/* Output socket address, either in special or generic format */
	switch (sa->sa_family) {

	case PF_INET:
	    {
		const struct fp_sockaddr_in *sin = (const struct fp_sockaddr_in *)sa;

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
#ifdef CONFIG_MCORE_IPV6
	case PF_INET6:
		{
		const struct fp_sockaddr_in6 *sin6 = (const struct fp_sockaddr_in6 *)sa;
		const struct fp_in6_addr *addr6;

		addr6 = (const struct fp_in6_addr *) &(sin6->sin6_addr);
		slen += snprintf(cbuf, cbuflen, "inet6/[%s", ip6_sprintf(addr6));

		if (sin6->sin6_scope_id != 0) {
			fp_ifnet_t *ifp;

			ifp = fp_ifuid2ifnet(sin6->sin6_scope_id);
			if (ifp != NULL)
				slen += snprintf(cbuf + strlen(cbuf),
					cbuflen - strlen(cbuf), "%%%s",
					ifp->if_name);
		}

		slen += snprintf(cbuf + strlen(cbuf), cbuflen - strlen(cbuf), "]");

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

#if 0
	case PF_APPLETALK:	/* XXX implement these someday */
	case PF_IPX:
	case PF_LOCAL:
#endif

	default:
		return (*ng_ksocket_generic_sockaddr_type.supertype->unparse)
		    (&ng_ksocket_generic_sockaddr_type,
		    data, off, cbuf, cbuflen);
	}
}

/* Parse type for struct fp_sockaddr */
static const struct ng_parse_type ng_ksocket_sockaddr_type = {
	.supertype = NULL,
	.info = NULL,
	.private = NULL,
	.parse = &ng_ksocket_sockaddr_parse,
	.unparse = &ng_ksocket_sockaddr_unparse,
	NULL		/* no such thing as a default struct fp_sockaddr */
};


/* Convert a struct ksocket_flow from binary to ASCII */
static int
ng_ksocket_flow_unparse(const struct ng_parse_type *type,
	const u_char *data, int *off, char *cbuf, int cbuflen)
{
	const struct ng_ksocket_flow *fl = (const struct ng_ksocket_flow *)(data + *off);
	int slen = 0;
	int i = 0;

	ng_ksocket_sockaddr_unparse(&ng_ksocket_sockaddr_type,
				    (const u_char *)fl, off,
				    cbuf + strlen(cbuf),
				    cbuflen - strlen(cbuf));

	slen += snprintf(cbuf + strlen(cbuf), cbuflen - strlen(cbuf), " <=> ");

	ng_ksocket_sockaddr_unparse(&ng_ksocket_sockaddr_type,
				    (const u_char *)fl, off,
				    cbuf + strlen(cbuf),
				    cbuflen - strlen(cbuf));

	/* parse prototype */
	for (i = 0; ng_ksocket_protos[i].name != NULL; i++)
		if (ng_ksocket_protos[i].value == fl->proto) {
			slen += snprintf(cbuf + strlen(cbuf), cbuflen - strlen(cbuf),
					 " (%s)", ng_ksocket_protos[i].name);
			goto next;
		}

	slen += snprintf(cbuf + strlen(cbuf), cbuflen - strlen(cbuf),
			 " (proto%d)",
			 fl->proto);
next:
	slen += snprintf(cbuf + strlen(cbuf), cbuflen - strlen(cbuf),
			 " (vr%d)",
			 fl->vrfid);

	if (slen >= cbuflen)
		return (ERANGE);
	*off += sizeof(*fl);
	return(0);
}

static const struct ng_parse_type ng_ksocket_flow_type = {
	.supertype = NULL,
	.info = NULL,
	.private = NULL,
	.parse = NULL,
	.unparse = &ng_ksocket_flow_unparse,
	NULL
};

/* Convert a struct ksocket_flow from binary to ASCII */
static int
ng_ksocket_priv_unparse(const struct ng_parse_type *type,
	const u_char *data, int *off, char *cbuf, int cbuflen)
{
	const struct ng_ksocket_private *priv =
		(const struct ng_ksocket_private *)(data + *off);
	size_t i;
	int slen = 0;
	int fl_off = 0;
	const struct {
		const char *name;
		bool enabled;
	} flag[] = {
		{ "connecting", priv->ksf.connecting },
		{ "accepting", priv->ksf.accepting },
		{ "eofseen", priv->ksf.eofseen },
		{ "cloned", priv->ksf.cloned },
		{ "embryonic", priv->ksf.embryonic },
		{ "sending", priv->ksf.sending },
		{ "connected", priv->ksf.connected },
		{ "accepted", priv->ksf.accepted },
		{ "bound", priv->ksf.bound },
		{ "busy", priv->ksf.busy },
		{ "allocmeta", priv->ksf.allocmeta },
	};

	ng_ksocket_flow_unparse(&ng_ksocket_flow_type,
				(const u_char *)&priv->fl,
				&fl_off, cbuf + strlen(cbuf),
				cbuflen - strlen(cbuf));

	slen += snprintf(cbuf + strlen(cbuf), cbuflen - strlen(cbuf), " < ");

	for (i = 0; (i != FPN_ARRAY_SIZE(flag)); i++)
		if (flag[i].enabled)
			slen += snprintf(cbuf + strlen(cbuf),
					 cbuflen - strlen(cbuf),
					 "%s%s",
					 flag[i].name,
					 ((i == 0) ? "" : " "));

	slen += snprintf(cbuf + strlen(cbuf), cbuflen - strlen(cbuf), ">");

	if (slen >= cbuflen)
		return (ERANGE);
	*off += sizeof(*priv);
	return(0);
}


static const struct ng_parse_type ng_ksocket_priv_type = {
	.supertype = NULL,
	.info = NULL,
	.private = NULL,
	.parse = NULL,
	.unparse = &ng_ksocket_priv_unparse,
	NULL
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
	return (msg->header.arglen < sizeof(*sopt))?0:msg->header.arglen - sizeof(*sopt);

}

/* Parse type for the option value part of a struct ng_ksocket_sockopt
   XXX Eventually, we should handle the different socket options specially.
   XXX This would avoid byte order problems, eg an integer value of 1 is
   XXX going to be "[1]" for little endian or "[3=1]" for big endian. */
static const struct ng_parse_type ng_ksocket_sockoptval_type = {
	.supertype = &ng_parse_bytearray_type,
	.info = &ng_parse_sockoptval_getLength
};

/* Parse type for struct ng_ksocket_sockopt */
static const struct ng_parse_struct_field ng_ksocket_sockopt_type_fields[]
	= NG_KSOCKET_SOCKOPT_INFO(&ng_ksocket_sockoptval_type);
static const struct ng_parse_type ng_ksocket_sockopt_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_ksocket_sockopt_type_fields
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
	  NGM_KSOCKET_ACCEPT,
	  "accept",
	  NULL,
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
	  &ng_ksocket_priv_type
	},
	/* Internal commands */
	{
	  NGM_KSOCKET_INTERNAL_COOKIE,
	  NGM_KSOCKET_INTERNAL_UPCALL,
	  "upcall",
	  NULL,
	  NULL
	},
	{ 0, 0, NULL, NULL, NULL }
};

/* Node type descriptor */
static FPN_DEFINE_SHARED(struct ng_type, ng_ksocket_typestruct) = {
	.version = NG_VERSION,
	.name = NG_KSOCKET_NODE_TYPE,
	.mod_event = NULL,
	.constructor = ng_ksocket_constructor,
	.rcvmsg = ng_ksocket_rcvmsg,
	.shutdown = ng_ksocket_rmnode,
	.newhook = ng_ksocket_newhook,
	.findhook = NULL,
	.connect = NULL,
	.rcvdata = ng_ksocket_rcvdata,
	.rcvdataq = ng_ksocket_rcvdata,
	.disconnect = ng_ksocket_disconnect,
	.rcvexception = NULL,
	.restorehook = ng_ksocket_restorehook,
	.cmdlist = ng_ksocket_cmds
};


int ng_ksocket_init(void)
{
	int error;
	void *type = &ng_ksocket_typestruct;
	unsigned int ns;

	TRACE_VNB(FP_LOG_DEBUG, "VNB: Loading ng_ksocket\n");

	if ((error = ng_newtype(type)) != 0) {
		TRACE_VNB(FP_LOG_ERR, "VNB: ng_ksocket_init failed (%d)\n",error);
		return EINVAL;
	}

	for (ns = 0; (ns < VNB_MAX_NS); ns++) {
		unsigned int i;
		struct ng_ksocket_private (*pool)[KSOCKET_POOL_SIZE];
		volatile unsigned int (*htable)[KSOCKET_HASH_SIZE];
#ifdef CONFIG_MCORE_IPV6
		volatile unsigned int (*htable6)[KSOCKET_HASH_SIZE];
#endif

		pool = fpn_zalloc(sizeof(*pool), FPN_CACHELINE_SIZE);
		if (pool == NULL)
			goto nomem;
		htable = fpn_zalloc(sizeof(*htable), FPN_CACHELINE_SIZE);
		if (htable == NULL) {
			fpn_free(pool);
			goto nomem;
		}
#ifdef CONFIG_MCORE_IPV6
		htable6 = fpn_zalloc(sizeof(*htable6), FPN_CACHELINE_SIZE);
		if (htable6 == NULL) {
			fpn_free(pool);
			fpn_free(htable);
			goto nomem;
		}
		for (i = 0; (i < KSOCKET_HASH_SIZE); i++)
			(*htable6)[i] = KSOCKET_LIST_END;
		per_ns(ng_ksocket6_hashtable, ns) = htable6;
#endif
		for (i = 0; (i < KSOCKET_HASH_SIZE); i++)
			(*htable)[i] = KSOCKET_LIST_END;
		per_ns(ng_ksocket_hashtable, ns) = htable;
		/* Link free elements together. Indices >= KSOCKET_POOL_SIZE
		 * are obviously invalid, but KSOCKET_POOL_SIZE is used to
		 * signal the end of the list. See KSOCKET_LIST_END. */
		for (i = 0; (i < KSOCKET_POOL_SIZE); i++) {
#ifdef CONFIG_MCORE_FPN_ASSERT_ENABLE
			(*pool)[i].ksf.pooled = true;
#endif
			(*pool)[i].ksf.hashed = false;
			(*pool)[i].next = (i + 1);
		}
		per_ns(ng_ksocket_pool_free, ns) = 0;
		per_ns(ng_ksocket_pool_free_gc, ns) = KSOCKET_LIST_END;
		fpn_spinlock_init(&per_ns(ng_ksocket_pool_lock, ns));
		per_ns(ng_ksocket_pool, ns) = pool;
	}

#ifdef CONFIG_MCORE_IP
	fp_ip_proto_handler_register(FP_IPPROTO_UDP, &ng_udp_hdlr);
	fp_ip_proto_handler_register(FP_IPPROTO_GRE, &ng_gre_hdlr);
#endif
#ifdef CONFIG_MCORE_IPV6
	fp_ip6_proto_handler_register(FP_IPPROTO_UDP, &ng_udp6_hdlr);
	fp_ip6_proto_handler_register(FP_IPPROTO_GRE, &ng_gre6_hdlr);
#endif

	return(0);
nomem:
	log(LOG_ERR, "Unable to allocate memory for ng_ksocket");
	while (ns--) {
		fpn_free(per_ns(ng_ksocket_pool, ns));
		per_ns(ng_ksocket_pool, ns) = NULL;
		fpn_free(per_ns(ng_ksocket_hashtable, ns));
		per_ns(ng_ksocket_hashtable, ns) = NULL;
#ifdef CONFIG_MCORE_IPV6
		fpn_free(per_ns(ng_ksocket6_hashtable, ns));
		per_ns(ng_ksocket6_hashtable, ns) = NULL;
#endif
	}
	return ENOMEM;
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
	unsigned int ns = ctrl_vnb_ns;

	/* Allocate private structure */
	priv = ng_ksocket_pool_fetch(ns);
	if (priv == NULL)
		return (ENOMEM);

	/* Call generic node constructor */
	if ((error = ng_make_node_common(&ng_ksocket_typestruct, nodep, nodeid))) {
		ng_ksocket_pool_return(ns, priv);
		return (error);
	}
	(*nodep)->private = priv;
	priv->node = *nodep;

	/* Done */
	return (0);
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
	char *s1, *s2, name[NG_HOOKLEN+1];
	int family, type, protocol;
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
	if (family != PF_INET && family != PF_INET6)
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

	/* grev4 and udpv4 only in FP now */
	if(!( (protocol == FP_IPPROTO_UDP) || (protocol == FP_IPPROTO_GRE)))
		return (EINVAL);

	priv->fl.family = family;
	priv->fl.proto = protocol;

	/* OK */
	priv->hook = hook;

	return (0);
}


static int
ng_ksocket_bind(struct fp_sockaddr *sa, priv_p priv, uint16_t ns)
{
	struct ng_ksocket_flow flow = {
		.family = priv->fl.family,
		.proto = priv->fl.proto,
		.vrfid = priv->fl.vrfid,
	};
	int error = 0;

	if (sa->sa_family != flow.family) {
		log(LOG_ERR, "mismatched protocol family");
		ERROUT(EINVAL);
	}
	switch (sa->sa_family) {
		priv_p found;

	case AF_INET:
		flow.u.sin.src = *(struct fp_sockaddr_in *)sa;
		flow.u.sin.dst = priv->fl.u.sin.dst;
		/* Reset port field for protocols that do not support it
		 * because it may be set to anything during parsing. */
		if (flow.proto != FP_IPPROTO_UDP)
			flow.u.sin.src.sin_port = 0;
		found = ng_ksocket_lookup(ns, &flow);
		/* Binding the same flow to the same node multiple times
		 * is always successful. */
		if (unlikely(found == priv))
			ERROUT(0);
		/* Reject if another socket is already bound with the same
		 * parameters, or for UDP, if the REUSE flag is not set. */
		if (found) {
			FPN_ASSERT(found->ksf.pooled == false);
			FPN_ASSERT(found->ksf.hashed == true);
			if ((priv->fl.proto != FP_IPPROTO_UDP) ||
			    (!priv->ksf.reuse))
				ERROUT(EADDRINUSE);
		}
		/* Unlink entry if necessary. */
		if (priv->ksf.hashed == true)
			ng_ksocket_unlink(ns, priv->hash, priv);
		FPN_ASSERT(priv->ksf.hashed == false);
		/* Update flow information. */
		priv->fl.u.sin.src = flow.u.sin.src;
		priv->hash = ng_ksocket_hash(&flow);
		/* Update cached IP header */
		init_ip_header(priv);
		/* Add hash entry. */
		ng_ksocket_link(ns, priv->hash, priv);
		FPN_ASSERT(priv->ksf.hashed == true);
		break;

#ifdef CONFIG_MCORE_IPV6
	case AF_INET6:
		flow.u.sin6.src = *(struct fp_sockaddr_in6 *)sa;
		flow.u.sin6.dst = priv->fl.u.sin6.dst;
		/* Reset port field for protocols that do not support it
		 * because it may be set to anything during parsing. */
		if (flow.proto != FP_IPPROTO_UDP)
			flow.u.sin6.src.sin6_port = 0;
		found = ng_ksocket6_lookup(ns, &flow);
		/* Binding the same flow to the same node multiple times
		 * is always successful. */
		if (unlikely(found == priv))
			ERROUT(0);
		/* Reject if another socket is already bound with the same
		 * parameters, or for UDP, if the REUSE flag is not set. */
		if (found) {
			FPN_ASSERT(found->ksf.pooled == false);
			FPN_ASSERT(found->ksf.hashed == true);
			if ((priv->fl.proto != FP_IPPROTO_UDP) ||
			    (!priv->ksf.reuse))
				ERROUT(EADDRINUSE);
		}
		/* Unlink entry if necessary. */
		if (priv->ksf.hashed == true)
			ng_ksocket6_unlink(ns, priv->hash, priv);
		FPN_ASSERT(priv->ksf.hashed == false);
		/* Update flow information. */
		priv->fl.u.sin6.src = flow.u.sin6.src;
		priv->hash = ng_ksocket6_hash(&flow);
		/* Update cached IP header */
		init_ip6_header(priv);
		/* Add hash entry. */
		ng_ksocket6_link(ns, priv->hash, priv);
		FPN_ASSERT(priv->ksf.hashed == true);
		break;
#endif

	default:
		ERROUT(EINVAL);
	}

	priv->ksf.bound = true;
 done:
	return error;
}

static int
ng_ksocket_connect(struct fp_sockaddr *sa, priv_p priv, uint16_t ns)
{
	struct ng_ksocket_flow flow = {
		.family = priv->fl.family,
		.proto = priv->fl.proto,
		.vrfid = priv->fl.vrfid,
	};
	int error = 0;

	/* assert the socket is already locally bound */
	if (!priv->ksf.bound) {
		log(LOG_ERR, "connect on unbound socket");
		ERROUT(EINVAL);
	}
	if (sa->sa_family != flow.family) {
		log(LOG_ERR, "mismatched bind/connect SA");
		ERROUT(EINVAL);
	}
	switch (sa->sa_family) {
		priv_p found;

	case AF_INET:
		flow.u.sin.src = priv->fl.u.sin.src;
		flow.u.sin.dst = *(struct fp_sockaddr_in *)sa;
		/* Reset port field for protocols that do not support it
		 * because it may be set to anything during parsing. */
		if (flow.proto != FP_IPPROTO_UDP)
			flow.u.sin.dst.sin_port = 0;
		found = ng_ksocket_lookup(ns, &flow);
		/* Connecting with the same flow from the same node multiple
		 * times is always successful. */
		if (unlikely(found == priv))
			ERROUT(0);
		/* Reject if another socket is already connected with the same
		 * parameters, or for UDP, if the REUSE flag is not set. */
		if (found) {
			FPN_ASSERT(found->ksf.pooled == false);
			FPN_ASSERT(found->ksf.hashed == true);
			if ((priv->fl.proto != FP_IPPROTO_UDP) ||
			    (!priv->ksf.reuse))
				ERROUT(EADDRINUSE);
		}
		/* Unlink entry if necessary. */
		if (priv->ksf.hashed == true)
			ng_ksocket_unlink(ns, priv->hash, priv);
		FPN_ASSERT(priv->ksf.hashed == false);
		/* Update flow information. */
		priv->fl.u.sin.dst = flow.u.sin.dst;
		priv->hash = ng_ksocket_hash(&flow);
		/* Update cached IP header */
		init_ip_header(priv);
		/* Add hash entry. */
		ng_ksocket_link(ns, priv->hash, priv);
		FPN_ASSERT(priv->ksf.hashed == true);
		break;

#ifdef CONFIG_MCORE_IPV6
	case AF_INET6:
		flow.u.sin6.src = priv->fl.u.sin6.src;
		flow.u.sin6.dst = *(struct fp_sockaddr_in6 *)sa;
		/* Reset port field for protocols that do not support it
		 * because it may be set to anything during parsing. */
		if (flow.proto != FP_IPPROTO_UDP)
			flow.u.sin6.dst.sin6_port = 0;
		found = ng_ksocket6_lookup(ns, &flow);
		/* Connecting with the same flow from the same node multiple
		 * times is always successful. */
		if (unlikely(found == priv))
			ERROUT(0);
		/* Reject if another socket is already connected with the same
		 * parameters, or for UDP, if the REUSE flag is not set. */
		if (found) {
			FPN_ASSERT(found->ksf.pooled == false);
			FPN_ASSERT(found->ksf.hashed == true);
			if ((priv->fl.proto != FP_IPPROTO_UDP) ||
			    (!priv->ksf.reuse))
				ERROUT(EADDRINUSE);
		}
		/* Unlink entry if necessary. */
		if (priv->ksf.hashed == true)
			ng_ksocket6_unlink(ns, priv->hash, priv);
		FPN_ASSERT(priv->ksf.hashed == false);
		/* Update flow information. */
		priv->fl.u.sin6.dst = flow.u.sin6.dst;
		priv->hash = ng_ksocket6_hash(&flow);
		/* Update cached IP header */
		init_ip6_header(priv);
		/* Add hash entry. */
		ng_ksocket6_link(ns, priv->hash, priv);
		FPN_ASSERT(priv->ksf.hashed == true);
		break;
#endif
	default:
		ERROUT(EINVAL);
	}

	priv->ksf.connected = true;
 done:
	return error;
}

/*
 * Receive a control message
 */
static int
ng_ksocket_rcvmsg(node_p node, struct ng_mesg *msg,
		  const char *raddr, struct ng_mesg **rptr,
		  struct ng_mesg **nl_msg)
{
	const priv_p priv = node->private;
	uint16_t ns = node->vnb_ns;
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_KSOCKET_COOKIE:
		switch (msg->header.cmd) {
		case NGM_KSOCKET_BIND: {
			struct fp_sockaddr *const sa
				= (struct fp_sockaddr *)msg->data;

			u_int sa_len = (sa->sa_family == AF_INET ?
					sizeof(struct fp_sockaddr_in) :
					sizeof(struct fp_sockaddr_in6));

			/* Sanity check */
			if (msg->header.arglen < SADATA_OFFSET
			    || msg->header.arglen < sa_len)
				ERROUT(EINVAL);

			error = ng_ksocket_bind(sa, priv, ns);

			break;
		}
		case NGM_KSOCKET_LISTEN: {
			/* Sanity check */
			if (msg->header.arglen != sizeof(int32_t))
				ERROUT(EINVAL);

			ERROUT(EINVAL);
			break;
		}

		case NGM_KSOCKET_ACCEPT: {
			/* Sanity check */
			if (msg->header.arglen != 0)
				ERROUT(EINVAL);

			priv->ksf.accepted = true;
			ERROUT(EINVAL);
			break;
		}

		case NGM_KSOCKET_CONNECT: {
			struct fp_sockaddr *const sa
				= (struct fp_sockaddr *)msg->data;
			u_int sa_len;

			if(sa == NULL)
				ERROUT(EINVAL);

			if(msg == NULL)
				ERROUT(EINVAL);

			sa_len = (sa->sa_family == AF_INET ?
				  sizeof(struct fp_sockaddr_in)
				  : sizeof(struct fp_sockaddr_in6));

			/* Sanity check */
			if (msg->header.arglen < SADATA_OFFSET
			    || msg->header.arglen < sa_len)
				ERROUT(EINVAL);

			error = ng_ksocket_connect(sa, priv, ns);

			break;
		}

		case NGM_KSOCKET_GETNAME:
		case NGM_KSOCKET_GETPEERNAME: {
			if(priv->fl.family == AF_INET)
				NG_MKRESPONSE(resp, msg, sizeof(struct fp_sockaddr_in), M_NOWAIT);
			else
				NG_MKRESPONSE(resp, msg, sizeof(struct fp_sockaddr_in6), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}

			if(priv->fl.family == AF_INET) {
				if (msg->header.cmd == NGM_KSOCKET_GETPEERNAME)
					memcpy(resp->data, &priv->fl.u.sin.dst, sizeof(priv->fl.u.sin.dst));
				else
					memcpy(resp->data, &priv->fl.u.sin.src, sizeof(priv->fl.u.sin.src));
			}
#ifdef CONFIG_MCORE_IPV6
			else {
				if (msg->header.cmd == NGM_KSOCKET_GETPEERNAME)
					memcpy(resp->data, &priv->fl.u.sin6.dst, sizeof(priv->fl.u.sin6.dst));
				else
					memcpy(resp->data, &priv->fl.u.sin6.src, sizeof(priv->fl.u.sin6.src));
			}
#endif

			break;
		}

		case NGM_KSOCKET_GETOPT:
		case NGM_KSOCKET_SETOPT: {
			/* TODO: ops->getopt/setopt ? */
			error = EINVAL;
			break;
		}

		case NGM_KSOCKET_REUSE_DGRAM: {
			priv->ksf.reuse = true;
			break;
		}

		case NGM_KSOCKET_SETVRFID: {
			void *msgdata;
			if (!priv->ksf.connected) {
				msgdata = msg->data;
				priv->fl.vrfid = *(uint16_t *)(msgdata);
			}
			else
				ERROUT(EINVAL);
			break;
		}

		case NGM_KSOCKET_ALLOCMETA:
			priv->ksf.allocmeta = true;
			break;

		case NGM_KSOCKET_STATUS:
			NG_MKRESPONSE(resp, msg, sizeof(struct ng_ksocket_private), M_NOWAIT);

			if (resp == NULL) {
				error = ENOMEM;
				break;
			}

			memcpy(resp->data, priv, sizeof(*priv));
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

/* Pool management. */

/* Get a private structure from the pool.
 * This function must be called from the control path only. */
static priv_p
ng_ksocket_pool_fetch(unsigned int ns)
{
	fpn_spinlock_t *lock = &per_ns(ng_ksocket_pool_lock, ns);
	volatile unsigned int *index = &per_ns(ng_ksocket_pool_free, ns);
	struct ng_ksocket_private (*pool)[KSOCKET_POOL_SIZE];
	priv_p priv;

	/* Prevent ng_ksocket_pool_return_gc() from running concurrently. */
	fpn_spinlock_lock(lock);
	if (unlikely(*index == KSOCKET_LIST_END)) {
		fpn_spinlock_unlock(lock);
		return NULL;
	}
	FPN_ASSERT(*index < KSOCKET_POOL_SIZE);
	pool = per_ns(ng_ksocket_pool, ns);
	priv = &(*pool)[*index];
	FPN_ASSERT(priv->ksf.pooled == true);
	FPN_ASSERT(priv->ksf.hashed == false);
	*index = priv->next;
	fpn_spinlock_unlock(lock);
	/* Initialize element. */
	*priv = (struct ng_ksocket_private){
		.next = KSOCKET_LIST_END,
		.ksf.hashed = false,
#ifdef CONFIG_MCORE_FPN_ASSERT_ENABLE
		.ksf.pooled = false,
#endif
	};
	return priv;
}

/* Return elements to the free list. GC-only function. */
static void ng_ksocket_pool_return_gc(struct fpn_gc_object *gco)
{
	unsigned int ns = (gco - &ng_ksocket_gco_ns[0]);
	struct ng_ksocket_private (*pool)[KSOCKET_POOL_SIZE] =
		per_ns(ng_ksocket_pool, ns);
	volatile unsigned int *f_index =
		&per_ns(ng_ksocket_pool_free, ns);
	volatile unsigned int *r_index =
		&per_ns(ng_ksocket_pool_free_gc, ns);
	fpn_spinlock_t *lock = &per_ns(ng_ksocket_pool_lock, ns);

	FPN_ASSERT(ns < FPN_ARRAY_SIZE(ng_ksocket_gco_ns));
#ifdef CONFIG_MCORE_FPN_ASSERT_ENABLE
	/* Poison GCO, should be reinitialized by fpn_gc(). */
	memset(gco, 0x2a, sizeof(*gco));
#endif
	fpn_spinlock_lock(lock);
	while (*r_index != KSOCKET_LIST_END) {
		priv_p priv = &(*pool)[*r_index];
		unsigned int next = priv->next;

		priv->next = *f_index;
		*f_index = *r_index;
		*r_index = next;
	}
	fpn_spinlock_unlock(lock);
}

/* Append private structure to the list of returned elements, then fire
 * the GC to put it back into the free list. This makes sure the data path
 * is not using it anymore when ng_ksocket_pool_fetch() is called.
 * This function must be called from the control path only. */
static void
ng_ksocket_pool_return(unsigned int ns, priv_p priv)
{
	struct fpn_gc_object *gco = &per_ns(ng_ksocket_gco, ns);
	fpn_spinlock_t *lock = &per_ns(ng_ksocket_pool_lock, ns);
	volatile unsigned int *index = &per_ns(ng_ksocket_pool_free_gc, ns);

	FPN_ASSERT(priv->ksf.hashed == false);
	FPN_ASSERT(priv->ksf.pooled == false);
	/* Do not clean element since it may still be in use. */
#ifdef CONFIG_MCORE_FPN_ASSERT_ENABLE
	priv->ksf.pooled = true;
#endif
	/* Prevent ng_ksocket_pool_return_gc() from running concurrently. */
	fpn_spinlock_lock(lock);
	priv->next = *index;
	*index = ng_ksocket_pool_index(ns, priv);
	/* Schedule GC if this is the only element. */
	if (priv->next == KSOCKET_LIST_END)
		fpn_gc(gco, ng_ksocket_pool_return_gc);
	fpn_spinlock_unlock(lock);
}

/* Get private structure index in the pool. */
static unsigned int
ng_ksocket_pool_index(unsigned int ns, priv_p priv)
{
	struct ng_ksocket_private (*pool)[KSOCKET_POOL_SIZE] =
		per_ns(ng_ksocket_pool, ns);

	FPN_ASSERT(priv >= &(*pool)[0]);
	FPN_ASSERT(priv < &(*pool)[KSOCKET_POOL_SIZE]);
	return (priv - &(*pool)[0]);
}

/************************************************************************
			KSOCKET HASH TABLE
 ************************************************************************/

/* v4 only */
static uint32_t
ng_ksocket_hash(struct ng_ksocket_flow * fl)
{
	uint32_t a, b, c;

	a = fl->u.sin.src.sin_addr.s_addr;
	b = fl->u.sin.dst.sin_addr.s_addr;
	c = fl->u.sin.src.sin_port | ((uint32_t)fl->u.sin.dst.sin_port << 16);

	fp_jhash_mix(a, b, c);

	return ((c ^ fl->proto) & (KSOCKET_HASH_SIZE - 1));
}

/* v4 only */
static int
ng_ksocket_flow_are_equal(struct ng_ksocket_flow * fl1, struct ng_ksocket_flow * fl2)
{
	/*
	 * check remote params only in UDP
	 */
	if (fl1->u.sin.src.sin_addr.s_addr != fl2->u.sin.src.sin_addr.s_addr)
		return 0;
	if (fl1->u.sin.dst.sin_addr.s_addr != fl2->u.sin.dst.sin_addr.s_addr)
		return 0;
	if (fl1->u.sin.src.sin_port != fl2->u.sin.src.sin_port)
		return 0;
	if (fl1->u.sin.dst.sin_port != fl2->u.sin.dst.sin_port)
		return 0;
	if (fl1->proto != fl2->proto)
		return 0;
	if (fl1->vrfid != fl2->vrfid)
		return 0;
	return 1;
}

/* Add private structure to the IPv4 hash table.
 * Not reentrant; can only be called from the control path. */
static void
ng_ksocket_link(unsigned int ns, uint32_t hash, priv_p priv)
{
	volatile unsigned int (*htable)[KSOCKET_HASH_SIZE] =
		per_ns(ng_ksocket_hashtable, ns);

	FPN_ASSERT(priv->ksf.pooled == false);
	FPN_ASSERT(priv->ksf.hashed == false);
	FPN_ASSERT(priv->next == KSOCKET_LIST_END);
	priv->ksf.hashed = true;
	/* Ordering is enforced by the volatile qualifier. Prevents race
	 * conditions with ng_ksocket_lookup(). */
	priv->next = (*htable)[hash];
	(*htable)[hash] = ng_ksocket_pool_index(ns, priv);
}

/* Remove private structure from the IPv4 hash table.
 * Not reentrant; can only be called from the control path. */
static void
ng_ksocket_unlink(unsigned int ns, uint32_t hash, priv_p priv)
{
	struct ng_ksocket_private (*pool)[KSOCKET_POOL_SIZE] =
		per_ns(ng_ksocket_pool, ns);
	volatile unsigned int (*htable)[KSOCKET_HASH_SIZE] =
		per_ns(ng_ksocket_hashtable, ns);
	unsigned int index = ng_ksocket_pool_index(ns, priv);
	unsigned int curr = (*htable)[hash];
	unsigned int prev;

	FPN_ASSERT(priv->ksf.pooled == false);
	FPN_ASSERT(priv->ksf.hashed == true);
	priv->ksf.hashed = false;
	if (likely(curr == index))
		(*htable)[hash] = priv->next;
	else if (curr != KSOCKET_LIST_END)
		do {
			/* Since we are modifying the list, race conditions
			 * with ng_ksocket_lookup() are unavoidable.
			 * It has to rely on the "hashed" flag. */
			prev = curr;
			curr = (*pool)[curr].next;
			if (curr == index) {
				(*pool)[prev].next = priv->next;
				break;
			}
		}
		while (curr != KSOCKET_LIST_END);
	priv->next = KSOCKET_LIST_END;
}

/* Find private structure with matching flow entry in IPv4 hash table. */
static priv_p
ng_ksocket_lookup(unsigned int ns, struct ng_ksocket_flow *fl)
{
	struct ng_ksocket_private (*pool)[KSOCKET_POOL_SIZE] =
		per_ns(ng_ksocket_pool, ns);
	uint32_t hash = ng_ksocket_hash(fl);
	unsigned int index;

restart:
	index = (*per_ns(ng_ksocket_hashtable, ns))[hash];
	while (index != KSOCKET_LIST_END) {
		priv_p priv = &(*pool)[index];

		/* Start over if the current element is not hashed anymore,
		 * otherwise we may uselessly iterate on freed elements in
		 * the pool. */
		if (unlikely(priv->ksf.hashed == false))
			goto restart;
		if (likely(ng_ksocket_flow_are_equal(fl, &priv->fl)))
			return priv;
		index = priv->next;
	}
	return NULL;
}

#ifdef CONFIG_MCORE_IPV6
static inline void ng_ksocket6_ipv6_addr_get(struct fp_in6_addr *addr,
					     uint32_t *w1, uint32_t *w2,
					     uint32_t *w3, uint32_t *w4)
{
	*w1 = addr->fp_s6_addr32[0];
	*w2 = addr->fp_s6_addr32[1];
	*w3 = addr->fp_s6_addr32[2];
	*w4 = addr->fp_s6_addr32[3];
}

static uint32_t
ng_ksocket6_hash(struct ng_ksocket_flow * fl)
{
	uint32_t a[4], b[4], c;
	int i;
	ng_ksocket6_ipv6_addr_get(&fl->u.sin6.src.sin6_addr, &a[0], &a[1], &a[2], &a[3]);
	ng_ksocket6_ipv6_addr_get(&fl->u.sin6.dst.sin6_addr, &b[0], &b[1], &b[2], &b[3]);
	c = (fl->u.sin6.src.sin6_port + ((uint32_t)fl->u.sin6.dst.sin6_port << 16));

	for(i = 0; i < 4; i++) {
		a[i] -= b[i]; a[i] -= c; a[i] ^= (c >> 13);
		b[i] -= c; b[i] -= a[i]; b[i] ^= (a[i] << 8);
		c -= a[i]; c -= b[i]; c ^= (b[i] >> 13);
		a[i] -= b[i]; a[i] -= c; a[i] ^= (c >> 12);
		b[i] -= c; b[i] -= a[i]; b[i] ^= (a[i] << 16);
		c -= a[i]; c -= b[i]; c ^= (b[i] >> 5);
		a[i] -= b[i]; a[i] -= c; a[i] ^= (c >> 3);
		b[i] -= c; b[i] -= a[i]; b[i] ^= (a[i] << 10);
		c -= a[i]; c -= b[i]; c ^= (b[i] >> 15);
	}

	return ((c ^ fl->proto) & (KSOCKET_HASH_SIZE - 1));
}

static int
ng_ksocket6_flow_are_equal(struct ng_ksocket_flow * fl1, struct ng_ksocket_flow * fl2)
{
	if (!is_in6_addr_equal(fl1->u.sin6.src.sin6_addr, fl2->u.sin6.src.sin6_addr))
		return 0;
	if (!is_in6_addr_equal(fl1->u.sin6.dst.sin6_addr, fl2->u.sin6.dst.sin6_addr))
		return 0;
	if (fl1->u.sin6.src.sin6_port != fl2->u.sin6.src.sin6_port)
		return 0;
	if (fl1->u.sin6.dst.sin6_port != fl2->u.sin6.dst.sin6_port)
		return 0;
	if (fl1->proto != fl2->proto)
		return 0;
	if (fl1->vrfid != fl2->vrfid)
		return 0;
	return 1;
}

/* Add private structure to the IPv6 hash table.
 * Not reentrant; can only be called from the control path. */
static void
ng_ksocket6_link(unsigned int ns, uint32_t hash, priv_p priv)
{
	volatile unsigned int (*htable6)[KSOCKET_HASH_SIZE] =
		per_ns(ng_ksocket6_hashtable, ns);

	FPN_ASSERT(priv->ksf.pooled == false);
	FPN_ASSERT(priv->ksf.hashed == false);
	FPN_ASSERT(priv->next == KSOCKET_LIST_END);
	priv->ksf.hashed = true;
	/* Ordering is enforced by the volatile qualifier. Prevents race
	 * conditions with ng_ksocket6_lookup(). */
	priv->next = (*htable6)[hash];
	(*htable6)[hash] = ng_ksocket_pool_index(ns, priv);
}

/* Remove private structure from the IPv6 hash table.
 * Not reentrant; can only be called from the control path. */
static void
ng_ksocket6_unlink(unsigned int ns, uint32_t hash, priv_p priv)
{
	struct ng_ksocket_private (*pool)[KSOCKET_POOL_SIZE] =
		per_ns(ng_ksocket_pool, ns);
	volatile unsigned int (*htable6)[KSOCKET_HASH_SIZE] =
		per_ns(ng_ksocket6_hashtable, ns);
	unsigned int index = ng_ksocket_pool_index(ns, priv);
	unsigned int curr = (*htable6)[hash];
	unsigned int prev;

	FPN_ASSERT(priv->ksf.pooled == false);
	FPN_ASSERT(priv->ksf.hashed == true);
	priv->ksf.hashed = false;
	if (likely(curr == index))
		(*htable6)[hash] = priv->next;
	else if (curr != KSOCKET_LIST_END)
		do {
			/* Since we are modifying the list, race conditions
			 * with ng_ksocket_lookup() are unavoidable.
			 * It has to rely on the "hashed" flag. */
			prev = curr;
			curr = (*pool)[curr].next;
			if (curr == index) {
				(*pool)[prev].next = priv->next;
				break;
			}
		}
		while (curr != KSOCKET_LIST_END);
	priv->next = KSOCKET_LIST_END;
}

/* Find private structure with matching flow entry in IPv6 hash table. */
static priv_p
ng_ksocket6_lookup(unsigned int ns, struct ng_ksocket_flow *fl)
{
	struct ng_ksocket_private (*pool)[KSOCKET_POOL_SIZE] =
		per_ns(ng_ksocket_pool, ns);
	uint32_t hash = ng_ksocket6_hash(fl);
	unsigned int index;

restart:
	index = (*per_ns(ng_ksocket6_hashtable, ns))[hash];
	while (index != KSOCKET_LIST_END) {
		priv_p priv = &(*pool)[index];

		/* Start over if the current element is not hashed anymore,
		 * otherwise we may uselessly iterate on freed elements in
		 * the pool. */
		if (unlikely(priv->ksf.hashed == false))
			goto restart;
		if (likely(ng_ksocket6_flow_are_equal(fl, &priv->fl)))
			return priv;
		index = priv->next;
	}
	return NULL;
}
#endif

/************************************************************************
			INPUT / OUTPUT
 ************************************************************************/


/*
 * Receive incoming data on our hook.  Send it out the socket.
 */

static int
ng_ksocket_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = hook->node;
	priv_p priv;
	int error, ret = -1;

	/* node is invalid, drop every new packet */
	if ((node == NULL) ||
	    ((node->flags & NG_INVALID) != 0)) {
		error = EINVAL;
		goto drop;
	}

	priv = node->private;
	/* Do not send packet on the socket before we are connected */
	if ((priv == NULL) ||
	    (!priv->ksf.connected)) {
		error = ENOTCONN;
		goto drop;
	}

	if(priv->fl.family == AF_INET) {
#ifdef CONFIG_MCORE_IP
		struct fp_ip *ip;
		struct fp_udphdr *udp = NULL;
		fp_rt4_entry_t *rt;
		fp_nh4_entry_t *nh;
		uint32_t dst;
		/* XXX ipv4 only */
		/* XXX if src=0.0.0.0 -> exception */

		switch (priv->fl.proto) {
		case FP_IPPROTO_GRE: {
			/* build header for protocol and send packet */
			ip = (struct fp_ip *)m_prepend(m, sizeof(struct fp_ip));
			if (unlikely(ip == NULL)) {
				error = 0;
				goto drop;
			}
			break;
		}

		case FP_IPPROTO_UDP: {
			/* build header for protocol and send packet */
			udp = (struct fp_udphdr *)m_prepend(m, sizeof(struct fp_udphdr));
			if (unlikely(udp == NULL)) {
				error = 0;
				goto drop;
			}

			udp->uh_sport = priv->fl.u.sin.src.sin_port; /* already in network order */
			udp->uh_dport = priv->fl.u.sin.dst.sin_port; /* already in network order */
			udp->uh_ulen = htons(m_len(m));
			udp->uh_sum = 0;

			ip = (struct fp_ip *)m_prepend(m, sizeof(struct fp_ip));
			if (unlikely(ip == NULL)) {
				error = 0;
				goto drop;
			}
			break;
		}

		default: /* bad proto */
			error = EINVAL;
			goto drop;
		}

		memcpy(ip, &priv->hdr.ip, sizeof(*ip));
		ip->ip_len = htons(m_len(m));

		ip->ip_id = fp_ip_get_id();

		if (likely((m_priv(m)->flags & M_TOS)))
			ip->ip_tos = m_priv(m)->tos;

		/* we could have incremental cksum */
		ip->ip_sum = fpn_ip_hdr_cksum(ip, sizeof(struct fp_ip));

		if (udp) {
#if defined(FPN_HAS_TX_CKSUM) && defined(CONFIG_MCORE_USE_HW_TX_L4CKSUM)
			m_set_tx_udp_cksum(m);
#else
			udp->uh_sum = fpn_in4_l4cksum(m);
			if (udp->uh_sum == 0)
				udp->uh_sum = 0xffff;
#endif
		}

		dst = priv->fl.u.sin.dst.sin_addr.s_addr;

		m_priv(m)->exc_type = FPTUN_IPV4_OUTPUT_EXCEPT;
		m_priv(m)->flags |= M_LOCAL_OUT;

#ifdef CONFIG_MCORE_VRF
		set_mvrfid(m, priv->fl.vrfid);
#endif
		rt = fp_rt4_lookup(m2vrfid(m), dst);
		if (unlikely(rt == NULL)) {
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoRouteLocal);
			error = EINVAL;
			goto drop;
		}
		nh = select_nh4(rt, &priv->hdr.ip.ip_src.s_addr);

		ret = fp_ip_output(m, rt, nh);
#endif
	} else {
#ifdef CONFIG_MCORE_IPV6
		struct fp_ip6_hdr *ip6;
		struct fp_udphdr *udp = NULL;
		fp_in6_addr_t dst;
		fp_rt6_entry_t *rt;
		fp_nh6_entry_t *nh;

		switch (priv->fl.proto) {
		case FP_IPPROTO_GRE: {
			/* build header for protocol and send packet */
			ip6 = (struct fp_ip6_hdr *)m_prepend(m, sizeof(struct fp_ip6_hdr));
			if (unlikely(ip6== NULL)) {
				error = 0;
				goto drop;
			}
			break;
		}
		case FP_IPPROTO_UDP: {
			/* build header for protocol and send packet */
			udp = (struct fp_udphdr *)m_prepend(m, sizeof(struct fp_udphdr));
			if (unlikely(udp == NULL)) {
				error = 0;
				goto drop;
			}
			udp->uh_sport = priv->fl.u.sin6.src.sin6_port; /* already in network order */
			udp->uh_dport = priv->fl.u.sin6.dst.sin6_port; /* already in network order */
			udp->uh_ulen = htons(m_len(m));
			udp->uh_sum = 0;

			ip6 = (struct fp_ip6_hdr *)m_prepend(m, sizeof(struct fp_ip6_hdr));
			if (unlikely(ip6 == NULL)) {
				error = 0;
				goto drop;
			}
			break;
		}
		default: /* bad proto */
			error = EINVAL;
			goto drop;
		}

		memcpy(ip6, &priv->hdr.ip6, sizeof(struct fp_ip6_hdr));
		ip6->ip6_plen = htons(m_len(m) - sizeof(struct fp_ip6_hdr));
		ip6->ip6_nxt = priv->fl.proto;
		ip6->ip6_v = FP_IP6VERSION;

		if (priv->fl.proto == FP_IPPROTO_UDP)
			udp->uh_sum = fpn_in6_l4cksum(m);

#ifdef CONFIG_MCORE_VRF
		set_mvrfid(m, priv->fl.vrfid);
#endif
		dst = (fp_in6_addr_t)(priv->fl.u.sin6.dst.sin6_addr);
		rt = fp_rt6_lookup(m2vrfid(m), &dst);
		if (unlikely(!rt)) {
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoRouteLocal);
			error = EINVAL;
			goto drop;
		}
		nh = select_nh6(rt, &ip6->ip6_src);

		m_priv(m)->exc_type = FPTUN_IPV6_OUTPUT_EXCEPT;
		m_priv(m)->flags |= M_LOCAL_OUT | M_LOCAL_F;
		ret = fp_ip6_output(m, rt, nh);
#else
		error = 0;
		goto drop;
#endif
	}

	NG_FREE_META(meta);
	fp_process_input_finish(m, ret);
	return 0;

drop:
	NG_FREE_DATA(m, meta);
	return error;
}


#ifdef CONFIG_MCORE_IP
/* input for ksocket */
static int ng_ksocket_input(struct mbuf *m)
{
	priv_p priv;
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	struct ng_ksocket_flow fl;
	meta_p meta = NULL;

	/* assume it is v4 */


	/* fill flow structure from packet */
	fl.u.sin.src.sin_addr.s_addr = ip->ip_dst.s_addr;
	fl.u.sin.dst.sin_addr.s_addr = ip->ip_src.s_addr;
	fl.proto = ip->ip_p;
	fl.vrfid = m2vrfid(m);

	switch (ip->ip_p) {
	case FP_IPPROTO_UDP: {
		struct fp_udphdr *udp = (struct fp_udphdr *)(ip + 1);
		fl.u.sin.src.sin_port = udp->uh_dport;
		fl.u.sin.dst.sin_port = udp->uh_sport;
		break;
	}

	case FP_IPPROTO_GRE: { /* XXX check that ports are 0 for gre */
		fl.u.sin.src.sin_port = 0;
		fl.u.sin.dst.sin_port = 0;
		break;
	}

	default:
		return FP_CONTINUE;
	}

	/* find the flow, the function takes a ref on priv->node */
	priv = ng_ksocket_lookup(fp_get_vnb_ns(), &fl);
	if (!priv && ip->ip_p == FP_IPPROTO_UDP) {
		/* find a matching LADDR/LPORT bound socket */
		fl.u.sin.dst.sin_addr.s_addr = 0;
		fl.u.sin.dst.sin_port = 0;
		priv = ng_ksocket_lookup(fp_get_vnb_ns(), &fl);
		if (!priv) {
			/* find a matching LPORT bound socket */
			fl.u.sin.src.sin_addr.s_addr = 0;
			priv = ng_ksocket_lookup(fp_get_vnb_ns(), &fl);
		}
	}
	if (!priv)
		return FP_CONTINUE;

	switch (priv->fl.proto) {
	case FP_IPPROTO_GRE: {
		/* remove ip header */
		if (m_len(m) < sizeof(struct fp_ip))
			goto drop;
		m_adj(m, sizeof(struct fp_ip));
		break;
	}
	case FP_IPPROTO_UDP: {
		struct fp_udphdr *udp = (struct fp_udphdr *)(ip + 1);

		if (m_len(m) < sizeof(struct fp_ip) + sizeof(struct fp_udphdr))
			goto drop;

		/* check ip len, udp len */
		if (ntohs(ip->ip_len) != m_len(m))
			goto drop;
		if (ntohs(udp->uh_ulen) != (m_len(m)-sizeof(struct fp_ip)))
			goto drop;

		/* check the checksum */
		if ((udp->uh_sum != 0) && fpn_in4_l4cksum(m))
			goto drop;

		/* remove ip+udp header */
		m_adj(m, sizeof(struct fp_ip)+sizeof(struct fp_udphdr));
		break;
	}
	default:
		break;
	}

	fp_reset_hw_flags(m); /* No known HW able to do HW Checksum here */

	if (priv->ksf.allocmeta) {
		struct meta_field_header *mhead;
		struct fp_sockaddr_in *sin = &fl.u.sin.dst;
		u_int len = (sizeof(*meta) + sizeof(*mhead) + sizeof(*sin));

		MALLOC(meta, meta_p, len, M_NETGRAPH, M_NOWAIT);
		if (meta == NULL) {
			log(LOG_ERR, "can't alloc meta");
			goto drop;
		}
		mhead = &meta->options[0];
		memset(meta, 0, sizeof(*meta));
		memset(mhead, 0, sizeof(*mhead));
		meta->allocated_len = len;
		meta->used_len = len;
		mhead->cookie = NGM_KSOCKET_COOKIE;
		mhead->type = NG_KSOCKET_META_SOCKADDR;
		mhead->len = (sizeof(*mhead) + sizeof(*sin));
		memcpy(mhead->data, sin, sizeof(*sin));
	}

	/* send packet to next hook */
	ng_send_data_fast(priv->hook, m, meta);
	goto end;

drop:
	m_freem(m);
end:
	return FP_DONE;
}
#endif

#ifdef CONFIG_MCORE_IPV6
/* input for ksocket */
static int ng_ksocket6_input(struct mbuf *m)
{
	priv_p priv;
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	struct ng_ksocket_flow fl;
	meta_p meta = NULL;

	/* assume it is v6 */
	/* fill flow structure from packet */
	memcpy(&fl.u.sin6.src.sin6_addr, &ip6->ip6_dst, sizeof(struct fp_in6_addr));
	memcpy(&fl.u.sin6.dst.sin6_addr, &ip6->ip6_src, sizeof(struct fp_in6_addr));
	fl.proto = ip6->ip6_nxt;
	fl.vrfid = m2vrfid(m);

	switch (ip6->ip6_nxt) {
	case FP_IPPROTO_UDP: {
		struct fp_udphdr *udp = (struct fp_udphdr *)(ip6 + 1);
		fl.u.sin6.src.sin6_port = udp->uh_dport;
		fl.u.sin6.dst.sin6_port = udp->uh_sport;
		break;
	}

	case FP_IPPROTO_GRE: { /* XXX check that ports are 0 for gre */
		fl.u.sin6.src.sin6_port = 0;
		fl.u.sin6.dst.sin6_port = 0;
		break;
	}

	default:
		return FP_CONTINUE;
	}

	/* find the flow, the function takes a ref on priv->node */
	priv = ng_ksocket6_lookup(fp_get_vnb_ns(), &fl);
	if (!priv && ip6->ip6_nxt == FP_IPPROTO_UDP) {
		/* find a matching LADDR/LPORT bound socket */
		memset(&fl.u.sin6.dst.sin6_addr, 0,
		       sizeof(fl.u.sin6.dst.sin6_addr));
		fl.u.sin6.dst.sin6_port = 0;
		priv = ng_ksocket6_lookup(fp_get_vnb_ns(), &fl);
		if (!priv) {
			/* find a matching LPORT bound socket */
			memset(&fl.u.sin6.src.sin6_addr, 0,
			       sizeof(fl.u.sin6.src.sin6_addr));
			priv = ng_ksocket6_lookup(fp_get_vnb_ns(), &fl);
		}
	}
	if (!priv)
		return FP_CONTINUE;

	switch (priv->fl.proto) {
	case FP_IPPROTO_GRE: {
		/* remove ip header */
		if (m_len(m) < sizeof(struct fp_ip6_hdr))
			goto drop;
		m_adj(m, sizeof(struct fp_ip6_hdr));
		break;
	}
	case FP_IPPROTO_UDP: {
		struct fp_udphdr *udp = (struct fp_udphdr *)(ip6 + 1);

		if (m_len(m) < sizeof(struct fp_ip6_hdr) + sizeof(struct fp_udphdr))
			goto drop;

		/* udp len */
		if (ntohs(udp->uh_ulen) != (m_len(m)-sizeof(struct fp_ip6_hdr)))
			goto drop;

		/* check the checksum */
		if (fpn_in6_l4cksum(m))
			goto drop;

		/* remove ip+udp header */
		m_adj(m, sizeof(struct fp_ip6_hdr)+sizeof(struct fp_udphdr));
		break;
	}
	default:
		break;
	}

	fp_reset_hw_flags(m); /* No known HW able to do HW Checksum here */

	if (priv->ksf.allocmeta) {
		struct meta_field_header *mhead;
		struct fp_sockaddr_in6 *sin6 = &fl.u.sin6.dst;
		u_int len = (sizeof(*meta) + sizeof(*mhead) + sizeof(*sin6));

		MALLOC(meta, meta_p, len, M_NETGRAPH, M_NOWAIT);
		if (meta == NULL) {
			log(LOG_ERR, "can't alloc meta");
			goto drop;
		}
		mhead = &meta->options[0];
		memset(meta, 0, sizeof(*meta));
		memset(mhead, 0, sizeof(*mhead));
		meta->allocated_len = len;
		meta->used_len = len;
		mhead->cookie = NGM_KSOCKET_COOKIE;
		mhead->type = NG_KSOCKET_META_SOCKADDR;
		mhead->len = (sizeof(*mhead) + sizeof(*sin6));
		memcpy(mhead->data, sin6, sizeof(*sin6));
	}

	/* send packet to next hook */
	ng_send_data_fast(priv->hook, m, meta);
	goto end;

drop:
	m_freem(m);
end:
	return FP_DONE;
}
#endif
/*
 * Destroy node
 */
static int
ng_ksocket_rmnode(node_p node)
{
	const priv_p priv = node->private;
	uint16_t ns = node->vnb_ns;

	if (priv->ksf.hashed == true) {
		switch (priv->fl.family) {
		case AF_INET:
			ng_ksocket_unlink(ns, priv->hash, priv);
			break;
#ifdef CONFIG_MCORE_IPV6
		case AF_INET6:
			ng_ksocket6_unlink(ns, priv->hash, priv);
			break;
#endif
		default:
			fpn_abort();
		}
	}
	/* Take down netgraph node */
	ng_cutlinks(node);
	ng_unname(node);
	node->private = NULL;
	ng_ksocket_pool_return(ns, priv);
	ng_unref(node);

	return 0;
}

/*
 * Hook disconnection
 */
static int
ng_ksocket_disconnect(hook_p hook)
{
	ng_rmnode(hook->node);
	return (0);
}

/************************************************************************
			HELPER STUFF
 ************************************************************************/

/* These macros are shared with kernel VNB. */
#define KSF_CONNECTED 6
#define KSF_BOUND 8

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
		FPN_TRACK();
		if (strcmp(s, aliases[k].name) == 0
		    && aliases[k].family == family)
			return aliases[k].value;
	}

	/* Try parsing as a number */
	val = (int)strtoul(s, &eptr, 10);
	if (val < 0 || *eptr != '\0')
		return (-1);
	return (val);
}

struct linux_sockaddr {
	/* The size of the struct is same as struct sockaddr */
	char sa_data[16];
};

struct ng_ksocket_nl_hookpriv {
	uint32_t node_flags;
	struct linux_sockaddr addr;
	struct linux_sockaddr peeraddr;
	uint16_t vrfid;
} __attribute__ ((packed));

static void
ng_ksocket_restorehook(struct ng_nl_hookpriv *nlhookpriv, node_p node, hook_p hook)
{
	struct ng_ksocket_nl_hookpriv *ksocket_nlhookpriv;
	priv_p priv = NG_NODE_PRIVATE(node);
	uint32_t flags;
	int error = 0;

	if (ntohl(nlhookpriv->data_len) != sizeof(*ksocket_nlhookpriv)) {
		TRACE_VNB(FP_LOG_ERR, "%s: bad size\n", __func__);
		return;
	}

	/* gre and udp only in FP now */
	if(!((priv->fl.proto == FP_IPPROTO_UDP) || (priv->fl.proto == FP_IPPROTO_GRE)))
		return;

	ksocket_nlhookpriv = (struct ng_ksocket_nl_hookpriv *)nlhookpriv->data;

	flags = ntohl(ksocket_nlhookpriv->node_flags);

	priv->fl.vrfid = ntohs(ksocket_nlhookpriv->vrfid);

	if (flags & (1 << KSF_BOUND)) {
		struct fp_sockaddr addr;

		memset(&addr, 0, sizeof(addr));
		memcpy(&addr, &ksocket_nlhookpriv->addr, sizeof(ksocket_nlhookpriv->addr));
		error = ng_ksocket_bind(&addr, priv, node->vnb_ns);
		if (error)
			TRACE_VNB(FP_LOG_ERR, "%s: bind failed (%d)\n", __func__, error);
	}

	if (flags & (1 << KSF_CONNECTED)) {
		struct fp_sockaddr peeraddr;

		memset(&peeraddr, 0, sizeof(peeraddr));
		memcpy(&peeraddr, &ksocket_nlhookpriv->peeraddr, sizeof(ksocket_nlhookpriv->peeraddr));
		error = ng_ksocket_connect(&peeraddr, priv, node->vnb_ns);
		if (error)
			TRACE_VNB(FP_LOG_ERR, "%s: connect failed (%d)\n", __func__, error);
	}
}

