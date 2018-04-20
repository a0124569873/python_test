/*-
 * Copyright (c) 1996-2000 Whistle Communications, Inc.
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
 * Copyright (c) 2007 Alexander Motin <mav@alkar.net>
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
 * Authors: Archie Cobbs <archie@freebsd.org>, Alexander Motin <mav@alkar.net>
 *
 * $FreeBSD$
 * $Whistle: ng_ppp.c,v 1.24 1999/11/01 09:24:52 julian Exp $
 */

/*
 * Copyright 2003-2013 6WIND S.A.
 */

/*
 * PPP node type data-flow.
 *
 *       hook      xmit        layer         recv      hook
 *              ------------------------------------
 *       inet ->                                    -> inet
 *       ipv6 ->                                    -> ipv6
 *        ipx ->               proto                -> ipx
 *      atalk ->                                    -> atalk
 *     bypass ->                                    -> bypass
 *              -hcomp_xmit()----------proto_recv()-
 *     vjc_ip <-                                    <- vjc_ip
 *   vjc_comp ->         header compression         -> vjc_comp
 * vjc_uncomp ->                                    -> vjc_uncomp
 *   vjc_vjip ->
 *              -comp_xmit()-----------hcomp_recv()-
 *   compress <-            compression             <- decompress
 *   compress ->                                    -> decompress
 *              -crypt_xmit()-----------comp_recv()-
 *    encrypt <-             encryption             <- decrypt
 *    encrypt ->                                    -> decrypt
 *              -ml_xmit()-------------crypt_recv()-
 *                           multilink
 *              -link_xmit()--------------ml_recv()-
 *      linkX <-               link                 <- linkX
 *
 */

#if defined(__LinuxKernelVNB__)
#include <linux/version.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <linux/timer.h>
#include <linux/ctype.h>
#include <asm/uaccess.h>
#include <netgraph/vnblinux.h>
#elif defined(__FastPath__)
#include <fp-netgraph.h>
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_ppp.h>
#ifdef CONFIG_VNB_NODE_VJC
#include <netgraph/ng_vjc.h>
#endif

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_PPP, "netgraph_ppp", "netgraph ppp node");
#else
#define M_NETGRAPH_PPP M_NETGRAPH
#endif

#define PROT_VALID(p)		(((p) & 0x0101) == 0x0001)
#define PROT_COMPRESSABLE(p)	(((p) & 0xff00) == 0x0000)

/* Some PPP protocol numbers we're interested in */
#define PROT_ATALK		0x0029
#define PROT_COMPD		0x00fd
#define PROT_CRYPTD		0x0053
#define PROT_IP			0x0021
#define PROT_IPV6		0x0057
#define PROT_IPX		0x002b
#define PROT_LCP		0xc021
#define PROT_MP			0x003d
#ifdef CONFIG_VNB_NODE_VJC
#define PROT_VJCOMP		0x002d
#define PROT_VJUNCOMP		0x002f
#endif

/* Multilink PPP definitions */
#define MP_INITIAL_SEQ		0		/* per RFC 1990 */
#define MP_MIN_LINK_MRU		32

#define MP_SHORT_SEQ_MASK	0x00000fff	/* short seq # mask */
#define MP_SHORT_SEQ_HIBIT	0x00000800	/* short seq # high bit */
#define MP_SHORT_FIRST_FLAG	0x00008000	/* first fragment in frame */
#define MP_SHORT_LAST_FLAG	0x00004000	/* last fragment in frame */

#define MP_LONG_SEQ_MASK	0x00ffffff	/* long seq # mask */
#define MP_LONG_SEQ_HIBIT	0x00800000	/* long seq # high bit */
#define MP_LONG_FIRST_FLAG	0x80000000	/* first fragment in frame */
#define MP_LONG_LAST_FLAG	0x40000000	/* last fragment in frame */

#define MP_NOSEQ		0x7fffffff	/* impossible sequence number */

/* Only enable multilink if NG_PPP_MAX_LINKS > 1 in ng_ppp.h */
#if NG_PPP_MAX_LINKS > 1
#define MP_ENABLE
#endif

#ifdef MP_ENABLE

/* Sign extension of MP sequence numbers */
#define MP_SHORT_EXTEND(s)	(((s) & MP_SHORT_SEQ_HIBIT) ?		\
				    ((s) | ~MP_SHORT_SEQ_MASK)		\
				    : ((s) & MP_SHORT_SEQ_MASK))
#define MP_LONG_EXTEND(s)	(((s) & MP_LONG_SEQ_HIBIT) ?		\
				    ((s) | ~MP_LONG_SEQ_MASK)		\
				    : ((s) & MP_LONG_SEQ_MASK))

/* Comparision of MP sequence numbers. Note: all sequence numbers
   except priv->xseq are stored with the sign bit extended. */
#define MP_SHORT_SEQ_DIFF(x,y)	MP_SHORT_EXTEND((x) - (y))
#define MP_LONG_SEQ_DIFF(x,y)	MP_LONG_EXTEND((x) - (y))

#define MP_RECV_SEQ_DIFF(priv,x,y)					\
				((priv)->conf.recvShortSeq ?		\
				    MP_SHORT_SEQ_DIFF((x), (y)) :	\
				    MP_LONG_SEQ_DIFF((x), (y)))

/* Increment receive sequence number */
#define MP_NEXT_RECV_SEQ(priv,seq)					\
				((priv)->conf.recvShortSeq ?		\
				    MP_SHORT_EXTEND((seq) + 1) :	\
				    MP_LONG_EXTEND((seq) + 1))

/* Don't fragment transmitted packets to parts smaller than this */
#define MP_MIN_FRAG_LEN		32

/* Maximum fragment reasssembly queue length */
#define MP_MAX_QUEUE_LEN	128

/* Fragment queue scanner period */
#define MP_FRAGTIMER_INTERVAL	(hz/2)

/* Average link overhead. XXX: Should be given by user-level */
#define MP_AVERAGE_LINK_OVERHEAD	16

#else /* MP_ENABLE */

#define MP_AVERAGE_LINK_OVERHEAD	1

#endif /* MP_ENABLE */

/* stats are only enabled in the kernel */
#if defined(__LinuxKernelVNB__)
#define NG_PPP_STATS
#endif

/* Keep this equal to ng_ppp_hook_names lower! */
enum {
	HOOK_INDEX_ATALK = 0,
	HOOK_INDEX_BYPASS,
	HOOK_INDEX_COMPRESS,
	HOOK_INDEX_ENCRYPT,
	HOOK_INDEX_DECOMPRESS,
	HOOK_INDEX_DECRYPT,
	HOOK_INDEX_INET,
	HOOK_INDEX_IPX,
#ifdef CONFIG_VNB_NODE_VJC
	HOOK_INDEX_VJC_COMP,
	HOOK_INDEX_VJC_IP,
	HOOK_INDEX_VJC_UNCOMP,
	HOOK_INDEX_VJC_VJIP,
#endif
	HOOK_INDEX_IPV6,
	HOOK_INDEX_MAX,
};

#ifdef MP_ENABLE

/* We store incoming fragments this way */
struct ng_ppp_frag {
	int				seq;		/* fragment seq# */
	uint8_t				first;		/* First in packet? */
	uint8_t				last;		/* Last in packet? */
	struct vnb_timeval		timestamp;	/* time of reception */
	struct mbuf			*data;		/* Fragment data */
	meta_p				meta;		/* Fragment meta */
	TAILQ_ENTRY(ng_ppp_frag)	f_qent;		/* Fragment queue */
};

#endif /* MP_ENABLE */

/* Per-link private information */
struct ng_ppp_link {
	struct ng_ppp_link_conf	conf;		/* link configuration */
	struct ng_ppp_link_stat64	stats;	/* link stats */
	hook_p			hook;		/* connection to link data */
	int32_t			seq;		/* highest rec'd seq# - MSEQ */
	uint32_t		latency;	/* calculated link latency */
	struct vnb_timeval	lastWrite;	/* time of last write for MP */
	int			bytesInQueue;	/* bytes in the output queue for MP */
};

/* Total per-node private information */
struct ng_ppp_private {
	node_p			node;			/* parent node */
	struct ng_ppp_bund_conf	conf;			/* bundle config */
	struct ng_ppp_link_stat64	bundleStats;	/* bundle stats */
	struct ng_ppp_link	links[NG_PPP_MAX_LINKS];/* per-link info */
	int32_t			xseq;			/* next out MP seq # */
	int32_t			mseq;			/* min links[i].seq */
	uint16_t		activeLinks[NG_PPP_MAX_LINKS];	/* indicies */
	uint16_t		numActiveLinks;		/* how many links up */
	uint16_t		lastLink;		/* for round robin */
#ifdef CONFIG_VNB_NODE_VJC
	uint8_t			vjCompHooked;		/* VJ comp hooked up? */
#endif
	uint8_t			allLinksEqual;		/* all xmit the same? */
	hook_p			hooks[HOOK_INDEX_MAX];	/* non-link hooks */
#ifdef MP_ENABLE
	struct ng_ppp_frag	fragsmem[MP_MAX_QUEUE_LEN]; /* fragments storage */
	TAILQ_HEAD(ng_ppp_fraglist, ng_ppp_frag)	/* fragment queue */
				frags;
	TAILQ_HEAD(ng_ppp_fragfreelist, ng_ppp_frag)	/* free fragment queue */
				fragsfree;
	struct ng_callout	fragTimer;		/* fraq queue check */
	unsigned int		fragtimer_running:1;	/* callout running */
	vnb_spinlock_t		fraglock;		/* frags processing */
	vnb_spinlock_t		rmtx;			/* recv mutex */
	vnb_spinlock_t		xmtx;			/* xmit mutex */
#endif /* MP_ENABLE */
};
typedef struct ng_ppp_private *priv_p;

/* Netgraph node methods */
static ng_constructor_t	ng_ppp_constructor;
static ng_rcvmsg_t	ng_ppp_rcvmsg;
static ng_shutdown_t	ng_ppp_shutdown;
static ng_newhook_t	ng_ppp_newhook;
static ng_rcvdata_t	ng_ppp_rcvdata_link;
static ng_disconnect_t	ng_ppp_disconnect;

static ng_rcvdata_t	ng_ppp_rcvdata_inet;
static ng_rcvdata_t	ng_ppp_rcvdata_ipv6;
static ng_rcvdata_t	ng_ppp_rcvdata_ipx;
static ng_rcvdata_t	ng_ppp_rcvdata_atalk;
static ng_rcvdata_t	ng_ppp_rcvdata_bypass;

#ifdef CONFIG_VNB_NODE_VJC
static ng_rcvdata_t	ng_ppp_rcvdata_vjc_ip;
static ng_rcvdata_t	ng_ppp_rcvdata_vjc_comp;
static ng_rcvdata_t	ng_ppp_rcvdata_vjc_uncomp;
static ng_rcvdata_t	ng_ppp_rcvdata_vjc_vjip;
#endif

static ng_rcvdata_t	ng_ppp_rcvdata_compress;
static ng_rcvdata_t	ng_ppp_rcvdata_decompress;

static ng_rcvdata_t	ng_ppp_rcvdata_encrypt;
static ng_rcvdata_t	ng_ppp_rcvdata_decrypt;

/* We use enum integer indices to refer to the non-link hooks. */
static VNB_DEFINE_SHARED(struct {
	const char *name;
	ng_rcvdata_t *fn;
}, ng_ppp_hook_names[]) = {
	{ NG_PPP_HOOK_ATALK,	ng_ppp_rcvdata_atalk },
	{ NG_PPP_HOOK_BYPASS,	ng_ppp_rcvdata_bypass },
	{ NG_PPP_HOOK_COMPRESS,	ng_ppp_rcvdata_compress },
	{ NG_PPP_HOOK_ENCRYPT,	ng_ppp_rcvdata_encrypt },
	{ NG_PPP_HOOK_DECOMPRESS, ng_ppp_rcvdata_decompress },
	{ NG_PPP_HOOK_DECRYPT,	ng_ppp_rcvdata_decrypt },
	{ NG_PPP_HOOK_INET,	ng_ppp_rcvdata_inet },
	{ NG_PPP_HOOK_IPX,	ng_ppp_rcvdata_ipx },
#ifdef CONFIG_VNB_NODE_VJC
	{ NG_PPP_HOOK_VJC_COMP,	ng_ppp_rcvdata_vjc_comp },
	{ NG_PPP_HOOK_VJC_IP,	ng_ppp_rcvdata_vjc_ip },
	{ NG_PPP_HOOK_VJC_UNCOMP, ng_ppp_rcvdata_vjc_uncomp },
	{ NG_PPP_HOOK_VJC_VJIP,	ng_ppp_rcvdata_vjc_vjip },
#endif
	{ NG_PPP_HOOK_IPV6,	ng_ppp_rcvdata_ipv6 },
	{ NULL, NULL }
};

/* Helper functions */
static int	ng_ppp_proto_recv(priv_p priv, struct mbuf *m, meta_p meta,
				  uint16_t proto, uint16_t linkNum);
static int	ng_ppp_hcomp_xmit(priv_p priv, struct mbuf *m, meta_p meta,
				  uint16_t proto);
static int	ng_ppp_hcomp_recv(priv_p priv, struct mbuf *m, meta_p meta,
				  uint16_t proto, uint16_t linkNum);
static int	ng_ppp_comp_xmit(priv_p priv, struct mbuf *m, meta_p meta,
				 uint16_t proto);
static int	ng_ppp_comp_recv(priv_p priv, struct mbuf *m, meta_p meta,
				 uint16_t proto, uint16_t linkNum);
static int	ng_ppp_crypt_xmit(priv_p priv, struct mbuf *m, meta_p meta,
				  uint16_t proto);
static int	ng_ppp_crypt_recv(priv_p priv, struct mbuf *m, meta_p meta,
				  uint16_t proto, uint16_t linkNum);

#ifdef MP_ENABLE

static int	ng_ppp_mp_xmit(priv_p priv, struct mbuf *m, meta_p meta,
			       uint16_t proto);
static int	ng_ppp_mp_recv(priv_p priv, struct mbuf *m, meta_p meta,
			       uint16_t proto, uint16_t linkNum);

#else /* MP_ENABLE */

static int	ng_ppp_recv(priv_p priv, struct mbuf *m, meta_p meta,
			    uint16_t proto, uint16_t linkNum);

#endif /* MP_ENABLE */

static int	ng_ppp_link_xmit(priv_p priv, struct mbuf *m, meta_p meta,
				 uint16_t proto, uint16_t linkNum, int plen);
static int	ng_ppp_bypass(priv_p priv, struct mbuf *m, meta_p meta,
			      uint16_t proto, uint16_t linkNum);

#ifdef MP_ENABLE

static void	ng_ppp_bump_mseq(priv_p priv, int32_t new_mseq);
static int	ng_ppp_frag_drop(priv_p priv);
static int	ng_ppp_check_packet(priv_p priv);
static void	ng_ppp_get_packet(priv_p priv, struct mbuf **mp, meta_p *meta);
static int	ng_ppp_frag_process(priv_p priv);
static int	ng_ppp_frag_trim(priv_p priv);
static void	ng_ppp_frag_timeout(node_p node);
static void	ng_ppp_frag_checkstale(node_p node, priv_p priv);
static void	ng_ppp_frag_reset(node_p node);
static void	ng_ppp_mp_strategy(priv_p priv, int len, unsigned int *distrib);
static int	ng_ppp_intcmp(void *latency, const void *v1, const void *v2);

#endif /* MP_ENABLE */

static struct mbuf *ng_ppp_addproto(struct mbuf *m, uint16_t proto, int compOK);
static struct mbuf *ng_ppp_cutproto(struct mbuf *m, uint16_t *proto);
static struct mbuf *ng_ppp_prepend(struct mbuf *m, const void *buf, int len);
static int	ng_ppp_config_valid(node_p node,
		    const struct ng_ppp_node_conf *newConf);
static void	ng_ppp_update(node_p node, int newConf);

#ifdef MP_ENABLE

static void	ng_ppp_start_frag_timer(node_p node, priv_p priv);
static void	ng_ppp_stop_frag_timer(node_p node);

#endif /* MP_ENABLE */

/* Parse type for struct ng_ppp_mp_state_type */
static VNB_DEFINE_SHARED(struct ng_parse_fixedarray_info,
			 ng_ppp_rseq_array_info) = {
	.elementType = &ng_parse_hint32_type,
	.length = NG_PPP_MAX_LINKS
};
static VNB_DEFINE_SHARED(struct ng_parse_type,
			 ng_ppp_rseq_array_type) = {
	.supertype = &ng_parse_fixedarray_type,
	.info = &ng_ppp_rseq_array_info
};
static VNB_DEFINE_SHARED(struct ng_parse_struct_field,
			 ng_ppp_mp_state_type_fields[]) =
	NG_PPP_MP_STATE_TYPE_INFO(&ng_ppp_rseq_array_type);
static VNB_DEFINE_SHARED(struct ng_parse_type, ng_ppp_mp_state_type) = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_ppp_mp_state_type_fields
};

/* Parse type for struct ng_ppp_link_conf */
static VNB_DEFINE_SHARED(struct ng_parse_struct_field,
			 ng_ppp_link_type_fields[]) =
	NG_PPP_LINK_TYPE_INFO;
static VNB_DEFINE_SHARED(struct ng_parse_type, ng_ppp_link_type) = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_ppp_link_type_fields
};

/* Parse type for struct ng_ppp_bund_conf */
static VNB_DEFINE_SHARED(struct ng_parse_struct_field,
			 ng_ppp_bund_type_fields[]) =
	NG_PPP_BUND_TYPE_INFO;
static VNB_DEFINE_SHARED(struct ng_parse_type, ng_ppp_bund_type) = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_ppp_bund_type_fields
};

/* Parse type for struct ng_ppp_node_conf */
static VNB_DEFINE_SHARED(struct ng_parse_fixedarray_info,
			 ng_ppp_array_info) = {
	.elementType = &ng_ppp_link_type,
	.length = NG_PPP_MAX_LINKS
};
static VNB_DEFINE_SHARED(struct ng_parse_type,
			 ng_ppp_link_array_type) = {
	.supertype = &ng_parse_fixedarray_type,
	.info = &ng_ppp_array_info,
};
static VNB_DEFINE_SHARED(struct ng_parse_struct_field,
			 ng_ppp_conf_type_fields[]) =
	NG_PPP_CONFIG_TYPE_INFO(&ng_ppp_bund_type, &ng_ppp_link_array_type);
static VNB_DEFINE_SHARED(struct ng_parse_type, ng_ppp_conf_type) = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_ppp_conf_type_fields
};

#ifdef NG_PPP_STATS
/* Parse type for struct ng_ppp_link_stat */
static VNB_DEFINE_SHARED(struct ng_parse_struct_field,
			 ng_ppp_stats_type_fields[]) =
	NG_PPP_STATS_TYPE_INFO;
static VNB_DEFINE_SHARED(struct ng_parse_type, ng_ppp_stats_type) = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_ppp_stats_type_fields
};

/* Parse type for struct ng_ppp_link_stat64 */
static VNB_DEFINE_SHARED(struct ng_parse_struct_field,
			 ng_ppp_stats64_type_fields[]) =
	NG_PPP_STATS64_TYPE_INFO;
static VNB_DEFINE_SHARED(struct ng_parse_type, ng_ppp_stats64_type) = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_ppp_stats64_type_fields
};
#endif
/* List of commands and how to convert arguments to/from ASCII */
static VNB_DEFINE_SHARED(struct ng_cmdlist, ng_ppp_cmds[]) = {
	{
	  NGM_PPP_COOKIE,
	  NGM_PPP_SET_CONFIG,
	  "setconfig",
	  &ng_ppp_conf_type,
	  NULL
	},
	{
	  NGM_PPP_COOKIE,
	  NGM_PPP_GET_CONFIG,
	  "getconfig",
	  NULL,
	  &ng_ppp_conf_type
	},
	{
	  NGM_PPP_COOKIE,
	  NGM_PPP_GET_MP_STATE,
	  "getmpstate",
	  NULL,
	  &ng_ppp_mp_state_type
	},
#ifdef NG_PPP_STATS
	{
	  NGM_PPP_COOKIE,
	  NGM_PPP_GET_LINK_STATS,
	  "getstats",
	  &ng_parse_int16_type,
	  &ng_ppp_stats_type
	},
	{
	  NGM_PPP_COOKIE,
	  NGM_PPP_CLR_LINK_STATS,
	  "clrstats",
	  &ng_parse_int16_type,
	  NULL
	},
	{
	  NGM_PPP_COOKIE,
	  NGM_PPP_GETCLR_LINK_STATS,
	  "getclrstats",
	  &ng_parse_int16_type,
	  &ng_ppp_stats_type
	},
	{
	  NGM_PPP_COOKIE,
	  NGM_PPP_GET_LINK_STATS64,
	  "getstats64",
	  &ng_parse_int16_type,
	  &ng_ppp_stats64_type
	},
	{
	  NGM_PPP_COOKIE,
	  NGM_PPP_GETCLR_LINK_STATS64,
	  "getclrstats64",
	  &ng_parse_int16_type,
	  &ng_ppp_stats64_type
	},
#endif
	{
	  NGM_PPP_COOKIE,
	  NGM_PPP_BUND_INIT,
	  "bundinit",
	  &ng_ppp_conf_type,
	  NULL
	},
	{
		.cookie = 0
	}
};

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_ppp_typestruct) = {
	.version = 	NG_ABI_VERSION,
	.name = 	NG_PPP_NODE_TYPE,
	.mod_event = 	NULL,
	.constructor = 	ng_ppp_constructor,
	.rcvmsg =	ng_ppp_rcvmsg,
	.shutdown = 	ng_ppp_shutdown,
	.newhook = 	ng_ppp_newhook,
	.findhook = 	NULL,
	.connect = 	NULL,
	.afterconnect = NULL,
	.rcvdata =	NULL, /* use hook methods */
	.rcvdataq = 	NULL,
	.disconnect = 	ng_ppp_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist =	ng_ppp_cmds,
};
NETGRAPH_INIT(ppp, &ng_ppp_typestruct);
NETGRAPH_EXIT(ppp, &ng_ppp_typestruct);

/* Address and control field header */
static VNB_DEFINE_SHARED(uint8_t, ng_ppp_acf[2]) = { 0xff, 0x03 };

#ifdef MP_ENABLE
/* Maximum time we'll let a complete incoming packet sit in the queue */
static VNB_DEFINE_SHARED(struct vnb_timeval,
			 ng_ppp_max_staleness) = { 2, 0 }; /* 2 seconds */
#endif

#define ERROUT(x)	do { error = (x); goto done; } while (0)

/************************************************************************
			NETGRAPH NODE STUFF
 ************************************************************************/

/*
 * Node type constructor
 */
static int
ng_ppp_constructor(node_p *nodep, ng_ID_t nodeid)
{
	node_p node;
	priv_p priv;
	int i;

	/* Allocate node and private structure */
	if ((i = ng_make_node_common_and_priv(&ng_ppp_typestruct, &node,
					      &priv, sizeof(*priv), nodeid)) != 0)
		return i;
	KASSERT(node != NULL);
	KASSERT(priv != NULL);
	memset(priv, 0, sizeof(*priv));
	NG_NODE_SET_PRIVATE(node, priv);

	priv->node = node;
#ifdef MP_ENABLE
	/* Initialize state */
	TAILQ_INIT(&priv->frags);
	TAILQ_INIT(&priv->fragsfree);
	for (i = 0; i < MP_MAX_QUEUE_LEN; i++)
		TAILQ_INSERT_TAIL(&priv->fragsfree, &priv->fragsmem[i], f_qent);
	ng_callout_init(&priv->fragTimer);
	vnb_spinlock_init(&priv->fraglock);

	vnb_spinlock_init(&priv->rmtx);
	vnb_spinlock_init(&priv->xmtx);
#endif /* MP_ENABLE */
	for (i = 0; i < NG_PPP_MAX_LINKS; i++)
		priv->links[i].seq = MP_NOSEQ;

	/* Done */
	*nodep = node;
	return (0);
}

/*
 * Give our OK for a hook to be added
 */
static int
ng_ppp_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	hook_p *hookPtr = NULL;
	int linkNum = -1;
	int hookIndex = -1;

	/* Figure out which hook it is */
	if (strncmp(name, NG_PPP_HOOK_LINK_PREFIX,	/* a link hook? */
	    sizeof(NG_PPP_HOOK_LINK_PREFIX) - 1) == 0) {
		const char *cp;
		char *eptr;

		cp = name + sizeof(NG_PPP_HOOK_LINK_PREFIX) - 1;
		if (!isdigit(*cp) || (cp[0] == '0' && cp[1] != '\0'))
			return (EINVAL);
		linkNum = (int)strtoul(cp, &eptr, 10);
		if (*eptr != '\0' || linkNum < 0 || linkNum >= NG_PPP_MAX_LINKS)
			return (EINVAL);
		hookPtr = &priv->links[linkNum].hook;
		hookIndex = ~linkNum;

		/* See if hook is already connected. */
		if (*hookPtr != NULL)
			return (EISCONN);

		/* Disallow more than one link unless multilink is enabled. */
#ifdef MP_ENABLE
		if (priv->links[linkNum].conf.enableLink &&
		    !priv->conf.enableMultilink && priv->numActiveLinks >= 1)
			return (ENODEV);
#else /* MP_ENABLE */
		NG_KASSERT(priv->numActiveLinks <= 1,
			   ("priv->numActiveLinks == %d",
			    priv->numActiveLinks));
		if ((priv->links[linkNum].conf.enableLink) &&
		    (priv->numActiveLinks == 1))
			return ENODEV;
#endif /* MP_ENABLE */
		NG_HOOK_SET_RCVDATA(hook, ng_ppp_rcvdata_link);
	} else {				/* must be a non-link hook */
		int i;

		for (i = 0; ng_ppp_hook_names[i].name != NULL; i++) {
			if (strcmp(name, ng_ppp_hook_names[i].name) == 0) {
				hookPtr = &priv->hooks[i];
				hookIndex = i;
				break;
			}
		}
		if (ng_ppp_hook_names[i].name == NULL)
			return (EINVAL);	/* no such hook */

		/* See if hook is already connected */
		if (*hookPtr != NULL)
			return (EISCONN);

		/* Every non-linkX hook have it's own function. */
		NG_HOOK_SET_RCVDATA(hook, ng_ppp_hook_names[i].fn);
	}

	/* OK */
	*hookPtr = hook;
	NG_HOOK_SET_PRIVATE(hook, (void *)(intptr_t)hookIndex);
	ng_ppp_update(node, 0);
	return (0);
}

/*
 * Receive a control message
 */
static int
ng_ppp_rcvmsg(node_p node, struct ng_mesg *msg, const char *raddr,
	      struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_PPP_COOKIE:
		switch (msg->header.cmd) {
		case NGM_PPP_BUND_INIT:
		    {
			struct ng_ppp_node_conf *const conf =
			    (struct ng_ppp_node_conf *)msg->data;
			/* for now, assume linkNum = 0 since we only have one link per bundle */
			uint16_t linkNum = 0;
			int i;

			/* clear the link and bund stats */
			memset(&priv->links[linkNum].stats, 0,  sizeof(struct ng_ppp_link_stat64));
			memset(&priv->bundleStats, 0,  sizeof(struct ng_ppp_link_stat64));

			/* Check for invalid or illegal config */
			if (msg->header.arglen != sizeof(*conf))
				ERROUT(EINVAL);
			if (!ng_ppp_config_valid(node, conf))
				ERROUT(EINVAL);

			/* Copy config */
			priv->conf = conf->bund;
			for (i = 0; i < NG_PPP_MAX_LINKS; i++)
				priv->links[i].conf = conf->links[i];
			ng_ppp_update(node, 1);
			break;
		    }
		case NGM_PPP_SET_CONFIG:
		    {
			struct ng_ppp_node_conf *const conf =
			    (struct ng_ppp_node_conf *)msg->data;
			int i;

			/* Check for invalid or illegal config */
			if (msg->header.arglen != sizeof(*conf))
				ERROUT(EINVAL);
			if (!ng_ppp_config_valid(node, conf))
				ERROUT(EINVAL);

			/* Copy config */
			priv->conf = conf->bund;
			for (i = 0; i < NG_PPP_MAX_LINKS; i++)
				priv->links[i].conf = conf->links[i];
			ng_ppp_update(node, 1);
			break;
		    }
		case NGM_PPP_GET_CONFIG:
		    {
			struct ng_ppp_node_conf *conf;
			int i;

			NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
			if (resp == NULL)
				ERROUT(ENOMEM);
			conf = (struct ng_ppp_node_conf *)resp->data;
			conf->bund = priv->conf;
			for (i = 0; i < NG_PPP_MAX_LINKS; i++)
				conf->links[i] = priv->links[i].conf;
			break;
		    }
		case NGM_PPP_GET_MP_STATE:
		    {
			struct ng_ppp_mp_state *info;
			int i;

			NG_MKRESPONSE(resp, msg, sizeof(*info), M_NOWAIT);
			if (resp == NULL)
				ERROUT(ENOMEM);
			info = (struct ng_ppp_mp_state *)resp->data;
			bzero(info, sizeof(*info));
			for (i = 0; i < NG_PPP_MAX_LINKS; i++) {
				if (priv->links[i].seq != MP_NOSEQ)
					info->rseq[i] = priv->links[i].seq;
			}
			info->mseq = priv->mseq;
			info->xseq = priv->xseq;
			break;
		    }
#ifdef NG_PPP_STATS
		case NGM_PPP_GET_LINK_STATS:
		case NGM_PPP_CLR_LINK_STATS:
		case NGM_PPP_GETCLR_LINK_STATS:
		case NGM_PPP_GET_LINK_STATS64:
		case NGM_PPP_GETCLR_LINK_STATS64:
		    {
			struct ng_ppp_link_stat64 *stats;
			uint16_t linkNum;

			/* Process request. */
			if (msg->header.arglen != sizeof(uint16_t))
				ERROUT(EINVAL);
			memcpy(&linkNum, msg->data, sizeof(linkNum));
			if (linkNum >= NG_PPP_MAX_LINKS
			    && linkNum != NG_PPP_BUNDLE_LINKNUM)
				ERROUT(EINVAL);
			stats = (linkNum == NG_PPP_BUNDLE_LINKNUM) ?
			    &priv->bundleStats : &priv->links[linkNum].stats;

			/* Make 64bit reply. */
			if (msg->header.cmd == NGM_PPP_GET_LINK_STATS64 ||
			    msg->header.cmd == NGM_PPP_GETCLR_LINK_STATS64) {
				NG_MKRESPONSE(resp, msg,
				    sizeof(struct ng_ppp_link_stat64), M_NOWAIT);
				if (resp == NULL)
					ERROUT(ENOMEM);
				bcopy(stats, resp->data, sizeof(*stats));
			} else
			/* Make 32bit reply. */
			if (msg->header.cmd == NGM_PPP_GET_LINK_STATS ||
			    msg->header.cmd == NGM_PPP_GETCLR_LINK_STATS) {
				struct ng_ppp_link_stat *rs;
				NG_MKRESPONSE(resp, msg,
				    sizeof(struct ng_ppp_link_stat), M_NOWAIT);
				if (resp == NULL)
					ERROUT(ENOMEM);
				rs = (struct ng_ppp_link_stat *)resp->data;
				/* Truncate 64->32 bits. */
				rs->xmitFrames = stats->xmitFrames;
				rs->xmitOctets = stats->xmitOctets;
				rs->recvFrames = stats->recvFrames;
				rs->recvOctets = stats->recvOctets;
				rs->badProtos = stats->badProtos;
				rs->runts = stats->runts;
				rs->dupFragments = stats->dupFragments;
				rs->dropFragments = stats->dropFragments;
			}
			/* Clear stats. */
			if (msg->header.cmd != NGM_PPP_GET_LINK_STATS &&
			    msg->header.cmd != NGM_PPP_GET_LINK_STATS64)
				bzero(stats, sizeof(*stats));
			break;
		    }
#endif
		default:
			error = EINVAL;
			break;
		}
		break;
#ifdef CONFIG_VNB_NODE_VJC
	case NGM_VJC_COOKIE:
	    {
		    node_p origNode;
		    char path[NG_PATHSIZ];

		    if ((error = ng_path2node(node, raddr,
					      &origNode, NULL)) != 0)
			    ERROUT(error);
		    snprintf(path, sizeof(path), "[%lx]:%s",
			     (long)node, NG_PPP_HOOK_VJC_IP);
		    return ng_send_msg(origNode, msg, path, rptr, NULL);
	    }
#endif
	default:
		error = EINVAL;
		break;
	}
done:
	NG_RESPOND_MSG(error, node, raddr, resp, rptr);
	NG_FREE_MSG(msg);
	return (error);
}

/*
 * Destroy node
 */
static int
ng_ppp_shutdown(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	KASSERT(priv != NULL);

#ifdef MP_ENABLE
	/* Stop fragment queue timer */
	ng_ppp_stop_frag_timer(node);

	/* Take down netgraph node */
	ng_ppp_frag_reset(node);
#endif /* MP_ENABLE */
	node->flags |= NG_INVALID;
	ng_cutlinks(node);
	ng_unname(node);
	bzero(priv, sizeof(*priv));
	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);		/* let the node escape */
	return (0);
}

/*
 * Hook disconnection
 */
static int
ng_ppp_disconnect(hook_p hook)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);
	const int index = (intptr_t)NG_HOOK_PRIVATE(hook);

	/* Zero out hook pointer */
	if (index < 0)
		priv->links[~index].hook = NULL;
	else
		priv->hooks[index] = NULL;

	/* Update derived info (or go away if no hooks left). */
	if (NG_NODE_NUMHOOKS(node) > 0)
		ng_ppp_update(node, 0);
	else if (NG_NODE_IS_VALID(node))
		ng_rmnode(node);

	return (0);
}

/*
 * Proto layer
 */

/*
 * Receive data on a hook inet.
 */
static int
ng_ppp_rcvdata_inet(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p priv = hook->node_private;

	if (unlikely(priv == NULL)) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	if (unlikely(!priv->conf.enableIP)) {
		NG_FREE_DATA(m, meta);
		return (ENXIO);
	}
	return ng_ppp_hcomp_xmit(priv, m, meta, PROT_IP);
}

/*
 * Receive data on a hook ipv6.
 */
static int
ng_ppp_rcvdata_ipv6(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p priv = hook->node_private;

	if (unlikely(priv == NULL)) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	if (unlikely(!priv->conf.enableIPv6)) {
		NG_FREE_DATA(m, meta);
		return (ENXIO);
	}
	return ng_ppp_hcomp_xmit(priv, m, meta, PROT_IPV6);
}

/*
 * Receive data on a hook atalk.
 */
static int
ng_ppp_rcvdata_atalk(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p priv = hook->node_private;

	if (priv == NULL) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	if (!priv->conf.enableAtalk) {
		NG_FREE_DATA(m, meta);
		return (ENXIO);
	}
	return ng_ppp_hcomp_xmit(priv, m, meta, PROT_ATALK);
}

/*
 * Receive data on a hook ipx
 */
static int
ng_ppp_rcvdata_ipx(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p priv = hook->node_private;

	if (priv == NULL) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	if (!priv->conf.enableIPX) {
		NG_FREE_DATA(m, meta);
		return (ENXIO);
	}
	return ng_ppp_hcomp_xmit(priv, m, meta, PROT_IPX);
}

/*
 * Receive data on a hook bypass
 */
static int
ng_ppp_rcvdata_bypass(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p priv = hook->node_private;
	uint16_t linkNum;
	uint16_t proto;

	if (unlikely(priv == NULL)) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	if (unlikely(MBUF_LENGTH(m) < 4)) {
		NG_FREE_DATA(m, meta);
		return (EINVAL);
	}
	if (unlikely((m = m_pullup(m, 4)) == NULL)) {
		NG_FREE_META(meta);
		return (ENOBUFS);
	}
	linkNum = ntohs(mtod(m, uint16_t *)[0]);
	proto = ntohs(mtod(m, uint16_t *)[1]);
	m_adj(m, 4);

	if (linkNum == NG_PPP_BUNDLE_LINKNUM)
		return ng_ppp_hcomp_xmit(priv, m, meta, proto);
	else
		return ng_ppp_link_xmit(priv, m, meta, proto,
					linkNum, 0);
}

static int
ng_ppp_bypass(priv_p priv, struct mbuf *m, meta_p meta, uint16_t proto,
	      uint16_t linkNum)
{
	uint16_t hdr[2];
	int error;

	if (unlikely(priv->hooks[HOOK_INDEX_BYPASS] == NULL)) {
		NG_FREE_DATA(m, meta);
		return (ENXIO);
	}

	/* Add 4-byte bypass header. */
	hdr[0] = htons(linkNum);
	hdr[1] = htons(proto);

	if (unlikely((m = ng_ppp_prepend(m, &hdr, 4)) == NULL)) {
		NG_FREE_META(meta);
		return (ENOBUFS);
	}

	/* Send packet out hook. */
	NG_SEND_DATA(error, priv->hooks[HOOK_INDEX_BYPASS], m, meta);
	return (error);
}

static int
ng_ppp_proto_recv(priv_p priv, struct mbuf *m, meta_p meta, uint16_t proto,
		  uint16_t linkNum)
{
	hook_p outHook = NULL;
	int error;

	switch (proto) {
	    case PROT_IP:
		if (priv->conf.enableIP)
		    outHook = priv->hooks[HOOK_INDEX_INET];
		break;
	    case PROT_IPV6:
		if (priv->conf.enableIPv6)
		    outHook = priv->hooks[HOOK_INDEX_IPV6];
		break;
	    case PROT_ATALK:
		if (priv->conf.enableAtalk)
		    outHook = priv->hooks[HOOK_INDEX_ATALK];
		break;
	    case PROT_IPX:
		if (priv->conf.enableIPX)
		    outHook = priv->hooks[HOOK_INDEX_IPX];
		break;
	}

	if (unlikely(outHook == NULL))
		return ng_ppp_bypass(priv, m, meta, proto, linkNum);

	/* Send packet out hook. */
	NG_SEND_DATA(error, outHook, m, meta);
	return (error);
}

/*
 * Header compression layer
 */

static int
ng_ppp_hcomp_xmit(priv_p priv, struct mbuf *m, meta_p meta, uint16_t proto)
{
#ifdef CONFIG_VNB_NODE_VJC
	if (proto == PROT_IP &&
	    priv->conf.enableVJCompression &&
	    priv->vjCompHooked) {
		int error;

		/* Send packet out hook. */
		NG_SEND_DATA(error, priv->hooks[HOOK_INDEX_VJC_IP], m, meta);
		return (error);
	}
#endif

	return ng_ppp_comp_xmit(priv, m, meta, proto);
}

#ifdef CONFIG_VNB_NODE_VJC
/*
 * Receive data on a hook vjc_comp.
 */
static int
ng_ppp_rcvdata_vjc_comp(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = hook->node_private;

	if ((node == NULL) || (priv == NULL)) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	if (!priv->conf.enableVJCompression) {
		NG_FREE_DATA(m, meta);
		return (ENXIO);
	}
	return ng_ppp_comp_xmit(priv, m, meta, PROT_VJCOMP);
}

/*
 * Receive data on a hook vjc_uncomp.
 */
static int
ng_ppp_rcvdata_vjc_uncomp(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = hook->node_private;

	if ((node == NULL) || (priv == NULL)) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	if (!priv->conf.enableVJCompression) {
		NG_FREE_DATA(m, meta);
		return (ENXIO);
	}
	return ng_ppp_comp_xmit(priv, m, meta, PROT_VJUNCOMP);
}

/*
 * Receive data on a hook vjc_vjip.
 */
static int
ng_ppp_rcvdata_vjc_vjip(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = hook->node_private;

	if ((node == NULL) || (priv == NULL)) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	if (!priv->conf.enableVJCompression) {
		NG_FREE_DATA(m, meta);
		return (ENXIO);
	}
	return ng_ppp_comp_xmit(priv, m, meta, PROT_IP);
}
#endif /* CONFIG_VNB_NODE_VJC */

static int
ng_ppp_hcomp_recv(priv_p priv, struct mbuf *m, meta_p meta, uint16_t proto,
		  uint16_t linkNum)
{
#ifdef CONFIG_VNB_NODE_VJC
	if (unlikely(priv->conf.enableVJDecompression &&
		     priv->vjCompHooked)) {
		hook_p outHook = NULL;

		switch (proto) {
		    case PROT_VJCOMP:
			outHook = priv->hooks[HOOK_INDEX_VJC_COMP];
			break;
		    case PROT_VJUNCOMP:
			outHook = priv->hooks[HOOK_INDEX_VJC_UNCOMP];
			break;
		}

		if (outHook) {
			int error;

			/* Send packet out hook. */
			NG_SEND_DATA(error, outHook, m, meta);
			return (error);
		}
	}
#endif

	return ng_ppp_proto_recv(priv, m, meta, proto, linkNum);
}

#ifdef CONFIG_VNB_NODE_VJC
/*
 * Receive data on a hook vjc_ip.
 */
static int
ng_ppp_rcvdata_vjc_ip(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = hook->node_private;

	if ((node == NULL) || (priv == NULL)) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	if (!priv->conf.enableVJDecompression) {
		NG_FREE_DATA(m, meta);
		return (ENXIO);
	}
	return ng_ppp_proto_recv(priv, m, meta, PROT_IP,
				 NG_PPP_BUNDLE_LINKNUM);
}
#endif

/*
 * Compression layer
 */

static int
ng_ppp_comp_xmit(priv_p priv, struct mbuf *m, meta_p meta, uint16_t proto)
{
	if (priv->conf.enableCompression &&
	    proto < 0x4000 &&
	    proto != PROT_COMPD &&
	    proto != PROT_CRYPTD &&
	    priv->hooks[HOOK_INDEX_COMPRESS] != NULL) {
		int error;

		if ((m = ng_ppp_addproto(m, proto, 0)) == NULL) {
			NG_FREE_META(meta);
			return (ENOBUFS);
		}

		/* Send packet out hook. */
		NG_SEND_DATA(error, priv->hooks[HOOK_INDEX_COMPRESS], m, meta);
		return (error);
	}

	return ng_ppp_crypt_xmit(priv, m, meta, proto);
}

/*
 * Receive data on a hook compress.
 */
static int
ng_ppp_rcvdata_compress(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = hook->node_private;
	uint16_t proto;

	if ((node == NULL) || (priv == NULL)) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	switch (priv->conf.enableCompression) {
	    case NG_PPP_COMPRESS_NONE:
		    NG_FREE_DATA(m, meta);
		    return (ENXIO);
	    case NG_PPP_COMPRESS_FULL:
		{
			if ((m = ng_ppp_cutproto(m, &proto)) == NULL) {
				NG_FREE_META(meta);
				return (EIO);
			}
			if (!PROT_VALID(proto)) {
				NG_FREE_DATA(m, meta);
				return (EIO);
			}
		}
		break;
	    default:
		proto = PROT_COMPD;
		break;
	}
	return ng_ppp_crypt_xmit(priv, m, meta, proto);
}

static int
ng_ppp_comp_recv(priv_p priv, struct mbuf *m, meta_p meta, uint16_t proto,
		 uint16_t linkNum)
{
	if (proto < 0x4000 &&
	    ((proto == PROT_COMPD && priv->conf.enableDecompression) ||
	    priv->conf.enableDecompression == NG_PPP_DECOMPRESS_FULL) &&
	    priv->hooks[HOOK_INDEX_DECOMPRESS] != NULL) {
		int error;

		if (priv->conf.enableDecompression == NG_PPP_DECOMPRESS_FULL) {
			if ((m = ng_ppp_addproto(m, proto, 0)) == NULL) {
				NG_FREE_META(meta);
				return (EIO);
			}
		}

		/* Send packet out hook. */
		NG_SEND_DATA(error, priv->hooks[HOOK_INDEX_DECOMPRESS],
			     m, meta);
		return (error);
	} else if (proto == PROT_COMPD) {
		/* Disabled protos MUST be silently discarded, but
		 * unsupported MUST not. Let user-level decide this. */
		return ng_ppp_bypass(priv, m, meta, proto, linkNum);
	}

	return ng_ppp_hcomp_recv(priv, m, meta, proto, linkNum);
}

/*
 * Receive data on a hook decompress.
 */
static int
ng_ppp_rcvdata_decompress(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = hook->node_private;
	uint16_t proto;

	if ((node == NULL) || (priv == NULL)) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	if (!priv->conf.enableDecompression) {
		NG_FREE_DATA(m, meta);
		return (ENXIO);
	}
	if ((m = ng_ppp_cutproto(m, &proto)) == NULL) {
	        NG_FREE_META(meta);
	        return (EIO);
	}
	if (!PROT_VALID(proto)) {
#ifdef NG_PPP_STATS
		priv->bundleStats.badProtos++;
#endif
		NG_FREE_DATA(m, meta);
		return (EIO);
	}
	return ng_ppp_hcomp_recv(priv, m, meta, proto, NG_PPP_BUNDLE_LINKNUM);
}

/*
 * Encryption layer
 */

static int
ng_ppp_crypt_xmit(priv_p priv, struct mbuf *m, meta_p meta, uint16_t proto)
{
	if (priv->conf.enableEncryption &&
	    proto < 0x4000 &&
	    proto != PROT_CRYPTD &&
	    priv->hooks[HOOK_INDEX_ENCRYPT] != NULL) {
		int error;

		if ((m = ng_ppp_addproto(m, proto, 0)) == NULL) {
			NG_FREE_META(meta);
			return (ENOBUFS);
		}

		/* Send packet out hook. */
		NG_SEND_DATA(error, priv->hooks[HOOK_INDEX_ENCRYPT], m, meta);
		return (error);
	}

#ifdef MP_ENABLE
	return ng_ppp_mp_xmit(priv, m, meta, proto);
#else /* MP_ENABLE */
	return ng_ppp_link_xmit(priv, m, meta, proto, priv->activeLinks[0],
				MBUF_LENGTH(m));
#endif /* MP_ENABLE */
}

/*
 * Receive data on a hook encrypt.
 */
static int
ng_ppp_rcvdata_encrypt(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = hook->node_private;

	if ((node == NULL) || (priv == NULL)) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	if (!priv->conf.enableEncryption) {
		NG_FREE_DATA(m, meta);
		return (ENXIO);
	}
#ifdef MP_ENABLE
	return ng_ppp_mp_xmit(priv, m, meta, PROT_CRYPTD);
#else /* MP_ENABLE */
	return ng_ppp_link_xmit(priv, m, meta, PROT_CRYPTD,
				priv->activeLinks[0], MBUF_LENGTH(m));
#endif /* MP_ENABLE */
}

static int
ng_ppp_crypt_recv(priv_p priv, struct mbuf *m, meta_p meta, uint16_t proto,
		  uint16_t linkNum)
{
	if (unlikely(proto == PROT_CRYPTD)) {
		if (priv->conf.enableDecryption &&
		    priv->hooks[HOOK_INDEX_DECRYPT] != NULL) {
			int error;

			/* Send packet out hook. */
			NG_SEND_DATA(error, priv->hooks[HOOK_INDEX_DECRYPT],
				     m, meta);
			return (error);
		} else {
			/* Disabled protos MUST be silently discarded, but
			 * unsupported MUST not. Let user-level decide this. */
			return ng_ppp_bypass(priv, m, meta, proto, linkNum);
		}
	}

	return ng_ppp_comp_recv(priv, m, meta, proto, linkNum);
}

/*
 * Receive data on a hook decrypt.
 */
static int
ng_ppp_rcvdata_decrypt(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = hook->node_private;
	uint16_t proto;

	if ((node == NULL) || (priv == NULL)) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}
	if (!priv->conf.enableDecryption) {
		NG_FREE_DATA(m, meta);
		return (ENXIO);
	}
	if ((m = ng_ppp_cutproto(m, &proto)) == NULL) {
	        NG_FREE_META(meta);
	        return (EIO);
	}
	if (!PROT_VALID(proto)) {
#ifdef NG_PPP_STATS
		priv->bundleStats.badProtos++;
#endif
		NG_FREE_DATA(m, meta);
		return (EIO);
	}
	return ng_ppp_comp_recv(priv, m, meta, proto, NG_PPP_BUNDLE_LINKNUM);
}

/*
 * Link layer
 */

static int
ng_ppp_link_xmit(priv_p priv, struct mbuf *m, meta_p meta, uint16_t proto,
		 uint16_t linkNum, int plen)
{
	struct ng_ppp_link *link;
	int error;
#if defined(NG_PPP_STATS) || defined(MP_ENABLE)
	int len;
#endif
	uint16_t mru;

	/* Check if link correct. */
	if (unlikely(linkNum >= NG_PPP_MAX_LINKS)) {
		ERROUT(ENETDOWN);
	}

	/* Get link pointer (optimization). */
	link = &priv->links[linkNum];

	/* Check link status (if real). */
	if (unlikely(link->hook == NULL)) {
		ERROUT(ENETDOWN);
	}

	/* Check peer's MRU for this link. */
	mru = link->conf.mru;
	if (unlikely((mru != 0) && (MBUF_LENGTH(m) > mru))) {
		NG_FREE_M(m);
		ERROUT(EMSGSIZE);
	}

	/* Prepend protocol number, possibly compressed. */
	if (unlikely((m = ng_ppp_addproto(m, proto,
					  link->conf.enableProtoComp)) ==
		     NULL)) {
		ERROUT(ENOBUFS);
	}

	/* Prepend address and control field (unless compressed). */
	if (unlikely(proto == PROT_LCP || !link->conf.enableACFComp)) {
		if ((m = ng_ppp_prepend(m, &ng_ppp_acf, 2)) == NULL)
			ERROUT(ENOBUFS);
	}

	/* Deliver frame. */
#if defined(NG_PPP_STATS) || defined(MP_ENABLE)
	len = MBUF_LENGTH(m);
#endif
	NG_SEND_DATA(error, link->hook, m, meta);

#ifdef MP_ENABLE
	vnb_spinlock_lock(&priv->xmtx);
#endif

#ifdef NG_PPP_STATS
	/* Update link stats. */
	link->stats.xmitFrames++;
	link->stats.xmitOctets += len;

	/* Update bundle stats. */
	if (plen > 0) {
	    priv->bundleStats.xmitFrames++;
	    priv->bundleStats.xmitOctets += plen;
	}
#endif
#ifdef MP_ENABLE
	/* Update 'bytes in queue' counter. */
	if (error == 0) {
		/* bytesInQueue and lastWrite required only for mp_strategy. */
		if (priv->conf.enableMultilink && !priv->allLinksEqual &&
		    !priv->conf.enableRoundRobin) {
			/* If queue was empty, then mark this time. */
			if (link->bytesInQueue == 0)
				microtime(&link->lastWrite);
			link->bytesInQueue += len + MP_AVERAGE_LINK_OVERHEAD;
			/* Limit max queue length to 50 pkts. BW can be defined
			   incorrectly and link may not signal overload. */
			if (link->bytesInQueue > 50 * 1600)
				link->bytesInQueue = 50 * 1600;
		}
	}
	vnb_spinlock_unlock(&priv->xmtx);
#endif /* MP_ENABLE */
	return (error);

done:
	NG_FREE_DATA(m, meta);
	return (error);
}

/*
 * Receive data on a hook linkX.
 */
static int
ng_ppp_rcvdata_link(hook_p hook, struct mbuf *m, meta_p meta)
{
	const priv_p priv = hook->node_private;
	const int index = (intptr_t)NG_HOOK_PRIVATE(hook);
	const uint16_t linkNum = (uint16_t)~index;
	struct ng_ppp_link *link;
	uint16_t proto;
	int error = 0;

	if (unlikely(priv == NULL)) {
		NG_FREE_DATA(m, meta);
		return ENOTCONN;
	}

	NG_KASSERT(linkNum < NG_PPP_MAX_LINKS, ("bogus index 0x%x", index));

	link = &priv->links[linkNum];

#ifdef MP_ENABLE
	vnb_spinlock_lock(&priv->rmtx);
#endif /* MP_ENABLE */

#ifdef NG_PPP_STATS
	/* Stats */
	link->stats.recvFrames++;
	link->stats.recvOctets += MBUF_LENGTH(m);
#endif
	/* Strip address and control fields, if present. */
	if (unlikely((m = m_pullup(m, 2)) == NULL))
		ERROUT(ENOBUFS);
	if (mtod(m, uint8_t *)[0] == 0xff &&
	    mtod(m, uint8_t *)[1] == 0x03)
		m_adj(m, 2);

	/* Get protocol number */
	if (unlikely((m = ng_ppp_cutproto(m, &proto)) == NULL))
		ERROUT(ENOBUFS);

	if (unlikely(!PROT_VALID(proto))) {
#ifdef NG_PPP_STATS
		link->stats.badProtos++;
#endif
		ERROUT(EIO);
	}

	/* LCP packets must go directly to bypass. */
	if (unlikely(proto >= 0xB000)) {
#ifdef MP_ENABLE
		vnb_spinlock_unlock(&priv->rmtx);
#endif /* MP_ENABLE */
		return ng_ppp_bypass(priv, m, meta, proto, linkNum);
	}

	/* Other packets are denied on a disabled link. */
	if (unlikely(!link->conf.enableLink))
		ERROUT(ENXIO);

#ifdef MP_ENABLE
	/* Proceed to multilink layer. Mutex will be unlocked inside. */
	error = ng_ppp_mp_recv(priv, m, meta, proto, linkNum);
#else /* MP_ENABLE */
	error = ng_ppp_recv(priv, m, meta, proto, linkNum);
#endif /* MP_ENABLE */
	return (error);

done:
#ifdef MP_ENABLE
	vnb_spinlock_unlock(&priv->rmtx);
#endif /* MP_ENABLE */
	NG_FREE_DATA(m, meta);
	return (error);
}

#ifdef MP_ENABLE

/*
 * Multilink layer
 */

/*
 * Handle an incoming multi-link fragment
 *
 * The fragment reassembly algorithm is somewhat complex. This is mainly
 * because we are required not to reorder the reconstructed packets, yet
 * fragments are only guaranteed to arrive in order on a per-link basis.
 * In other words, when we have a complete packet ready, but the previous
 * packet is still incomplete, we have to decide between delivering the
 * complete packet and throwing away the incomplete one, or waiting to
 * see if the remainder of the incomplete one arrives, at which time we
 * can deliver both packets, in order.
 *
 * This problem is exacerbated by "sequence number slew", which is when
 * the sequence numbers coming in from different links are far apart from
 * each other. In particular, certain unnamed equipment (*cough* Ascend)
 * has been seen to generate sequence number slew of up to 10 on an ISDN
 * 2B-channel MP link. There is nothing invalid about sequence number slew
 * but it makes the reasssembly process have to work harder.
 *
 * However, the peer is required to transmit fragments in order on each
 * link. That means if we define MSEQ as the minimum over all links of
 * the highest sequence number received on that link, then we can always
 * give up any hope of receiving a fragment with sequence number < MSEQ in
 * the future (all of this using 'wraparound' sequence number space).
 * Therefore we can always immediately throw away incomplete packets
 * missing fragments with sequence numbers < MSEQ.
 *
 * Here is an overview of our algorithm:
 *
 *    o Received fragments are inserted into a queue, for which we
 *	maintain these invariants between calls to this function:
 *
 *	- Fragments are ordered in the queue by sequence number
 *	- If a complete packet is at the head of the queue, then
 *	  the first fragment in the packet has seq# > MSEQ + 1
 *	  (otherwise, we could deliver it immediately)
 *	- If any fragments have seq# < MSEQ, then they are necessarily
 *	  part of a packet whose missing seq#'s are all > MSEQ (otherwise,
 *	  we can throw them away because they'll never be completed)
 *	- The queue contains at most MP_MAX_QUEUE_LEN fragments
 *
 *    o We have a periodic timer that checks the queue for the first
 *	complete packet that has been sitting in the queue "too long".
 *	When one is detected, all previous (incomplete) fragments are
 *	discarded, their missing fragments are declared lost and MSEQ
 *	is increased.
 *
 *    o If we recieve a fragment with seq# < MSEQ, we throw it away
 *	because we've already delcared it lost.
 *
 * This assumes linkNum != NG_PPP_BUNDLE_LINKNUM.
 */
static int
ng_ppp_mp_recv(priv_p priv, struct mbuf *m, meta_p meta, uint16_t proto,
	       uint16_t linkNum)
{
	struct ng_ppp_link *const link = &priv->links[linkNum];
	struct ng_ppp_frag *frag;
	struct ng_ppp_frag *qent;
	int i, diff, inserted;
	int	error = 0;

	if ((!priv->conf.enableMultilink) || proto != PROT_MP) {
		/* Stats */
#ifdef NG_PPP_STATS
		priv->bundleStats.recvFrames++;
		priv->bundleStats.recvOctets += MBUF_LENGTH(m);
#endif

		vnb_spinlock_unlock(&priv->rmtx);
		return ng_ppp_crypt_recv(priv, m, meta, proto, linkNum);
	}

	vnb_spinlock_lock(&priv->fraglock);

	/* Get a new frag struct from the free queue */
	if ((frag = TAILQ_FIRST(&priv->fragsfree)) == NULL) {
		NG_FREE_DATA(m, meta);
		goto process;
	}

	/* Extract fragment information from MP header */
	if (priv->conf.recvShortSeq) {
		uint16_t shdr;

		if (MBUF_LENGTH(m) < 2) {
#ifdef NG_PPP_STATS
			link->stats.runts++;
#endif
			NG_FREE_M(m);
			ERROUT(EINVAL);
		}
		if ((m = m_pullup(m, 2)) == NULL)
			ERROUT(ENOBUFS);

		shdr = ntohs(*mtod(m, uint16_t *));
		frag->seq = MP_SHORT_EXTEND(shdr);
		frag->first = (shdr & MP_SHORT_FIRST_FLAG) != 0;
		frag->last = (shdr & MP_SHORT_LAST_FLAG) != 0;
		diff = MP_SHORT_SEQ_DIFF(frag->seq, priv->mseq);
		m_adj(m, 2);
	} else {
		uint32_t lhdr;

		if (MBUF_LENGTH(m) < 4) {
#ifdef NG_PPP_STATS
			link->stats.runts++;
#endif
			NG_FREE_M(m);
			ERROUT(EINVAL);
		}
		if ((m = m_pullup(m, 4)) == NULL)
			ERROUT(ENOBUFS);

		lhdr = ntohl(*mtod(m, uint32_t *));
		frag->seq = MP_LONG_EXTEND(lhdr);
		frag->first = (lhdr & MP_LONG_FIRST_FLAG) != 0;
		frag->last = (lhdr & MP_LONG_LAST_FLAG) != 0;
		diff = MP_LONG_SEQ_DIFF(frag->seq, priv->mseq);
		m_adj(m, 4);
	}
	frag->data = m;
	frag->meta = meta;
	microtime(&frag->timestamp);

	/* If sequence number is < MSEQ, we've already declared this
	   fragment as lost, so we have no choice now but to drop it */
	if (diff < 0) {
#ifdef NG_PPP_STATS
		link->stats.dropFragments++;
#endif
		NG_FREE_M(m);
		ERROUT(0);
	}

	/* Update highest received sequence number on this link and MSEQ */
	priv->mseq = link->seq = frag->seq;
	for (i = 0; i < priv->numActiveLinks; i++) {
		struct ng_ppp_link *const alink =
		    &priv->links[priv->activeLinks[i]];

		if (MP_RECV_SEQ_DIFF(priv, alink->seq, priv->mseq) < 0)
			priv->mseq = alink->seq;
	}

	/* Remove frag struct from free queue. */
	TAILQ_REMOVE(&priv->fragsfree, frag, f_qent);

	/* Add fragment to queue, which is sorted by sequence number */
	inserted = 0;
	TAILQ_FOREACH_REVERSE(qent, &priv->frags, ng_ppp_fraglist, f_qent) {
		diff = MP_RECV_SEQ_DIFF(priv, frag->seq, qent->seq);
		if (diff > 0) {
			TAILQ_INSERT_AFTER(&priv->frags, qent, frag, f_qent);
			inserted = 1;
			break;
		} else if (diff == 0) {	     /* should never happen! */
			vnb_spinlock_unlock(&priv->fraglock);
#ifdef NG_PPP_STATS
			link->stats.dupFragments++;
#endif
			NG_FREE_DATA(frag->data, frag->meta);
			TAILQ_INSERT_HEAD(&priv->fragsfree, frag, f_qent);
			ERROUT(EINVAL);
		}
	}
	if (!inserted)
		TAILQ_INSERT_HEAD(&priv->frags, frag, f_qent);

process:
	/* Process the queue */
	/* NOTE: rmtx will be unlocked for sending time! */
	error = ng_ppp_frag_process(priv);
	vnb_spinlock_unlock(&priv->fraglock);
	vnb_spinlock_unlock(&priv->rmtx);
	return (error);

done:
	vnb_spinlock_unlock(&priv->fraglock);
	vnb_spinlock_unlock(&priv->rmtx);
	NG_FREE_DATA(m, meta);
	return (error);
}

/************************************************************************
			HELPER STUFF
 ************************************************************************/

/*
 * If new mseq > current then set it and update all active links
 */
static void
ng_ppp_bump_mseq(priv_p priv, int32_t new_mseq)
{
	int i;

	if (MP_RECV_SEQ_DIFF(priv, priv->mseq, new_mseq) < 0) {
		priv->mseq = new_mseq;
		for (i = 0; i < priv->numActiveLinks; i++) {
			struct ng_ppp_link *const alink =
			    &priv->links[priv->activeLinks[i]];

			if (MP_RECV_SEQ_DIFF(priv,
			    alink->seq, new_mseq) < 0)
				alink->seq = new_mseq;
		}
	}
}

/*
 * Examine our list of fragments, and determine if there is a
 * complete and deliverable packet at the head of the list.
 * Return 1 if so, zero otherwise.
 * priv->fraglock must be locked.
 */
static int
ng_ppp_check_packet(priv_p priv)
{
	struct ng_ppp_frag *qent, *qnext;

	/* Check for empty queue */
	if (TAILQ_EMPTY(&priv->frags))
		return (0);

	/* Check first fragment is the start of a deliverable packet */
	qent = TAILQ_FIRST(&priv->frags);
	if (!qent->first || MP_RECV_SEQ_DIFF(priv, qent->seq, priv->mseq) > 1)
		return (0);

	/* Check that all the fragments are there */
	while (!qent->last) {
		qnext = TAILQ_NEXT(qent, f_qent);
		if (qnext == NULL)	/* end of queue */
			return (0);
		if (qnext->seq != MP_NEXT_RECV_SEQ(priv, qent->seq))
			return (0);
		qent = qnext;
	}

	/* Got one */
	return (1);
}

/*
 * Pull a completed packet off the head of the incoming fragment queue.
 * This assumes there is a completed packet there to pull off.
 * priv->fraglock must be locked.
 */
static void
ng_ppp_get_packet(priv_p priv, struct mbuf **mp, meta_p *metap)
{
	struct ng_ppp_frag *qent, *qnext;
	struct mbuf *m = NULL;
	meta_p meta = NULL;
	int fail = 0;

	qent = TAILQ_FIRST(&priv->frags);
	NG_KASSERT(!TAILQ_EMPTY(&priv->frags) && qent->first, ("no packet"));
	for (; qent != NULL; qent = qnext) {
		qnext = TAILQ_NEXT(qent, f_qent);
		NG_KASSERT(!TAILQ_EMPTY(&priv->frags), ("empty q"));
		TAILQ_REMOVE(&priv->frags, qent, f_qent);
		if (m == NULL) {
			m = qent->data;
			meta = qent->meta; /* inherit first frag's meta */
		}
		else if ((fail) ||
			 ( /* suggest parentheses around && */
#ifdef __LinuxKernelVNB__
			 /* reducing the number of sk_buffs also reduces
			    m->truesize which is checked in sock.c,
			    if that fails, fallback to m_cat() */
			 (m_cram(m, qent->data)) &&
#endif /* __LinuxKernelVNB__ */
			 (m_cat(m, qent->data)))) {
			/* failing, drop subsequent data */
			NG_FREE_DATA(qent->data, qent->meta);
			fail = 1;
		}
		else
			NG_FREE_META(qent->meta); /* drop other frags' metas */
		if (qent->last) {
			qnext = NULL;
			/* Bump MSEQ if necessary */
			ng_ppp_bump_mseq(priv, qent->seq);
		}
		TAILQ_INSERT_HEAD(&priv->fragsfree, qent, f_qent);
	}
	*mp = m;
	*metap = meta;
}

/*
 * Trim fragments from the queue whose packets can never be completed.
 * This assumes a complete packet is NOT at the beginning of the queue.
 * Returns 1 if fragments were removed, zero otherwise.
 * priv->fraglock must be locked.
 */
static int
ng_ppp_frag_trim(priv_p priv)
{
	struct ng_ppp_frag *qent, *qnext = NULL;
	int removed = 0;

	/* Scan for "dead" fragments and remove them */
	while (1) {
		int dead = 0;

		/* If queue is empty, we're done */
		if (TAILQ_EMPTY(&priv->frags))
			break;

		/* Determine whether first fragment can ever be completed */
		TAILQ_FOREACH(qent, &priv->frags, f_qent) {
			if (MP_RECV_SEQ_DIFF(priv, qent->seq, priv->mseq) >= 0)
				break;
			qnext = TAILQ_NEXT(qent, f_qent);
			NG_KASSERT(qnext != NULL, ("last frag < MSEQ?"));
			if (qnext->seq != MP_NEXT_RECV_SEQ(priv, qent->seq)
			    || qent->last || qnext->first) {
				dead = 1;
				break;
			}
		}
		if (!dead)
			break;

		/* Remove fragment and all others in the same packet */
		while ((qent = TAILQ_FIRST(&priv->frags)) != qnext) {
			NG_KASSERT(!TAILQ_EMPTY(&priv->frags), ("empty q"));
#ifdef NG_PPP_STATS
			priv->bundleStats.dropFragments++;
#endif
			TAILQ_REMOVE(&priv->frags, qent, f_qent);
			NG_FREE_DATA(qent->data, qent->meta);
			TAILQ_INSERT_HEAD(&priv->fragsfree, qent, f_qent);
			removed = 1;
		}
	}
	return (removed);
}

/*
 * Drop fragments on queue overflow.
 * Returns 1 if fragments were removed, zero otherwise.
 * priv->fraglock must be locked.
 */
static int
ng_ppp_frag_drop(priv_p priv)
{
	/* Check queue length */
	if (TAILQ_EMPTY(&priv->fragsfree)) {
		struct ng_ppp_frag *qent;

		/* Get oldest fragment */
		NG_KASSERT(!TAILQ_EMPTY(&priv->frags), ("empty q"));
		qent = TAILQ_FIRST(&priv->frags);

		/* Bump MSEQ if necessary */
		ng_ppp_bump_mseq(priv, qent->seq);

		/* Drop it */
#ifdef NG_PPP_STATS
		priv->bundleStats.dropFragments++;
#endif
		TAILQ_REMOVE(&priv->frags, qent, f_qent);
		NG_FREE_DATA(qent->data, qent->meta);
		TAILQ_INSERT_HEAD(&priv->fragsfree, qent, f_qent);

		return (1);
	}
	return (0);
}

/*
 * Run the queue, restoring the queue invariants
 * priv->fraglock must be locked.
 */
static int
ng_ppp_frag_process(priv_p priv)
{
	struct mbuf *m;
	meta_p meta;
	uint16_t proto;

	do {
		/* Deliver any deliverable packets */
		while (ng_ppp_check_packet(priv)) {
			ng_ppp_get_packet(priv, &m, &meta);
			if ((m = ng_ppp_cutproto(m, &proto)) == NULL) {
				NG_FREE_META(meta);
				continue;
			}
			if (!PROT_VALID(proto)) {
#ifdef NG_PPP_STATS
				priv->bundleStats.badProtos++;
#endif
				NG_FREE_DATA(m, meta);
				continue;
			}
			if (m != NULL) {
#ifdef NG_PPP_STATS
				/* Stats */
				priv->bundleStats.recvFrames++;
				priv->bundleStats.recvOctets += MBUF_LENGTH(m);
#endif

				/* Drop mutex for the sending time.
				 * Priv may change, but we are ready!
				 */
				vnb_spinlock_unlock(&priv->rmtx);
				vnb_spinlock_unlock(&priv->fraglock);
				ng_ppp_crypt_recv(priv, m, meta, proto,
						  NG_PPP_BUNDLE_LINKNUM);
				vnb_spinlock_lock(&priv->fraglock);
				vnb_spinlock_lock(&priv->rmtx);
			}
		}
	  /* Delete dead fragments and try again */
	} while (ng_ppp_frag_trim(priv) || ng_ppp_frag_drop(priv));

	/* Done */
	return (0);
}

/*
 * Check for 'stale' completed packets that need to be delivered
 *
 * If a link goes down or has a temporary failure, MSEQ can get
 * "stuck", because no new incoming fragments appear on that link.
 * This can cause completed packets to never get delivered if
 * their sequence numbers are all > MSEQ + 1.
 *
 * This routine checks how long all of the completed packets have
 * been sitting in the queue, and if too long, removes fragments
 * from the queue and increments MSEQ to allow them to be delivered.
 */
static void
ng_ppp_frag_checkstale(node_p node, priv_p priv)
{
	struct ng_ppp_frag *qent, *beg, *end;
	struct vnb_timeval now = { 0, 0 };
	struct vnb_timeval age;
	struct mbuf *m;
	meta_p meta;
	int seq;
	uint16_t proto;

	while (1) {
		vnb_spinlock_lock(&priv->fraglock);

		/* If queue is empty, we're done */
		if (TAILQ_EMPTY(&priv->frags))
			break;

		/* Find the first complete packet in the queue */
		beg = end = NULL;
		seq = TAILQ_FIRST(&priv->frags)->seq;
		TAILQ_FOREACH(qent, &priv->frags, f_qent) {
			if (qent->first)
				beg = qent;
			else if (qent->seq != seq)
				beg = NULL;
			if (beg != NULL && qent->last) {
				end = qent;
				break;
			}
			seq = MP_NEXT_RECV_SEQ(priv, seq);
		}

		/* If none found, exit */
		if (end == NULL)
			break;

		/* Get current time (we assume we've been up for >= 1 second) */
		if (now.tv_sec == 0)
			microtime(&now);

		/* Check if packet has been queued too long */
		age = now;
		timevalsub(&age, &beg->timestamp);
		if (timevalcmp(&age, &ng_ppp_max_staleness, < ))
			break;

		/* Throw away junk fragments in front of the completed packet */
		while ((qent = TAILQ_FIRST(&priv->frags)) != beg) {
			NG_KASSERT(!TAILQ_EMPTY(&priv->frags), ("empty q"));
#ifdef NG_PPP_STATS
			priv->bundleStats.dropFragments++;
#endif
			TAILQ_REMOVE(&priv->frags, qent, f_qent);
			NG_FREE_DATA(qent->data, qent->meta);
			TAILQ_INSERT_HEAD(&priv->fragsfree, qent, f_qent);
		}

		/* Extract completed packet */
		ng_ppp_get_packet(priv, &m, &meta);

		vnb_spinlock_unlock(&priv->fraglock);

		if ((m = ng_ppp_cutproto(m, &proto)) == NULL)
			continue;
		if (!PROT_VALID(proto)) {
#ifdef NG_PPP_STATS
			priv->bundleStats.badProtos++;
#endif
			NG_FREE_M(m);
			continue;
		}

#ifdef NG_PPP_STATS
		/* Stats */
		priv->bundleStats.recvFrames++;
		priv->bundleStats.recvOctets += MBUF_LENGTH(m);
#endif
		/* Deliver packet */
		ng_ppp_crypt_recv(priv, m, meta, proto, NG_PPP_BUNDLE_LINKNUM);
	}
	vnb_spinlock_unlock(&priv->fraglock);
}

/*
 * Periodically call ng_ppp_frag_checkstale()
 */
static void
ng_ppp_frag_timeout(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	if (NG_NODE_NOT_VALID(node))
		return;

	/* Scan the fragment queue */
	ng_ppp_frag_checkstale(node, priv);

	/* Start timer again */
	ng_ppp_start_frag_timer(node, priv);
}

/*
 * Deliver a frame out on the bundle, i.e., figure out how to fragment
 * the frame across the individual PPP links and do so.
 */
static int
ng_ppp_mp_xmit(priv_p priv, struct mbuf *m, meta_p meta, uint16_t proto)
{
	const unsigned int hdr_len = priv->conf.xmitShortSeq ? 2 : 4;
	unsigned int distrib[NG_PPP_MAX_LINKS];
	int firstFragment;
	int activeLinkNum;
	int	plen;
	int	frags;
	int32_t	seq;

	/* At least one link must be active */
	if (priv->numActiveLinks == 0) {
		NG_FREE_DATA(m, meta);
		return (ENETDOWN);
	}

	/* Save length for later stats. */
	plen = MBUF_LENGTH(m);

	if (!priv->conf.enableMultilink) {
		return ng_ppp_link_xmit(priv, m, meta, proto,
					priv->activeLinks[0], plen);
	}

	/* Check peer's MRRU for this bundle. */
	if (plen > priv->conf.mrru) {
		NG_FREE_DATA(m, meta);
		return (EMSGSIZE);
	}

	/* Prepend protocol number, possibly compressed. */
	if ((m = ng_ppp_addproto(m, proto, 1)) == NULL) {
		NG_FREE_META(meta);
		return (ENOBUFS);
	}

	/* Clear distribution plan */
	bzero(&distrib, priv->numActiveLinks * sizeof(distrib[0]));

	vnb_spinlock_lock(&priv->xmtx);

	/* Round-robin strategy */
	if (priv->conf.enableRoundRobin) {
		activeLinkNum = priv->lastLink++ % priv->numActiveLinks;
		distrib[activeLinkNum] = MBUF_LENGTH(m);
		goto deliver;
	}

	/* Strategy when all links are equivalent (optimize the common case) */
	if (priv->allLinksEqual) {
		uint16_t numFrags;
		int	fraction, remain;
		int	i;

		/* Calculate optimal fragment count */
		numFrags = priv->numActiveLinks;
		if (numFrags > (MBUF_LENGTH(m) / MP_MIN_FRAG_LEN))
			numFrags = (MBUF_LENGTH(m) / MP_MIN_FRAG_LEN);
		if (numFrags == 0)
			numFrags = 1;

		fraction = (MBUF_LENGTH(m) / numFrags);
		remain = (MBUF_LENGTH(m) - (fraction * numFrags));

		/* Assign distribution */
		for (i = 0; i < numFrags; i++) {
			distrib[priv->lastLink++ % priv->numActiveLinks] =
				(fraction + (((remain--) > 0) ? 1 : 0));
		}
		goto deliver;
	}

	/* Strategy when all links are not equivalent */
	ng_ppp_mp_strategy(priv, MBUF_LENGTH(m), distrib);

deliver:
	/* Estimate fragments count */
	frags = 0;
	for (activeLinkNum = priv->numActiveLinks - 1;
	    activeLinkNum >= 0; activeLinkNum--) {
		const uint16_t linkNum = priv->activeLinks[activeLinkNum];
		struct ng_ppp_link *const link = &priv->links[linkNum];

		frags += (distrib[activeLinkNum] + link->conf.mru - hdr_len - 1) /
		    (link->conf.mru - hdr_len);
	}

	/* Get out initial sequence number */
	seq = priv->xseq;

	/* Update next sequence number */
	if (priv->conf.xmitShortSeq) {
	    priv->xseq = (seq + frags) & MP_SHORT_SEQ_MASK;
	} else {
	    priv->xseq = (seq + frags) & MP_LONG_SEQ_MASK;
	}

	vnb_spinlock_unlock(&priv->xmtx);

	/* Send alloted portions of frame out on the link(s) */
	for (firstFragment = 1, activeLinkNum = priv->numActiveLinks - 1;
	    activeLinkNum >= 0; activeLinkNum--) {
		const uint16_t linkNum = priv->activeLinks[activeLinkNum];
		struct ng_ppp_link *const link = &priv->links[linkNum];

		/* Deliver fragment(s) out the next link */
		for ( ; distrib[activeLinkNum] > 0; firstFragment = 0) {
			unsigned int len;
			int lastFragment, error;
			struct mbuf *m2;
			meta_p meta2;

			/* Calculate fragment length; don't exceed link MTU */
			len = distrib[activeLinkNum];
			if (len > link->conf.mru - hdr_len)
				len = link->conf.mru - hdr_len;
			distrib[activeLinkNum] -= len;
			lastFragment = (len == MBUF_LENGTH(m));

			/* Split off next fragment as "m2" */
			m2 = m;
			if (!lastFragment) {
				struct mbuf *n = M_SPLIT(m, len, M_DONTWAIT);

				if (n == NULL) {
					NG_FREE_M(m);
					if (firstFragment)
						NG_FREE_META(meta);
					return (ENOMEM);
				}
				m = n;
			}

			/* Prepend MP header */
			if (priv->conf.xmitShortSeq) {
				uint16_t shdr;

				shdr = seq;
				seq = (seq + 1) & MP_SHORT_SEQ_MASK;
				if (firstFragment)
					shdr |= MP_SHORT_FIRST_FLAG;
				if (lastFragment)
					shdr |= MP_SHORT_LAST_FLAG;
				shdr = htons(shdr);
				m2 = ng_ppp_prepend(m2, &shdr, 2);
			} else {
				uint32_t lhdr;

				lhdr = seq;
				seq = (seq + 1) & MP_LONG_SEQ_MASK;
				if (firstFragment)
					lhdr |= MP_LONG_FIRST_FLAG;
				if (lastFragment)
					lhdr |= MP_LONG_LAST_FLAG;
				lhdr = htonl(lhdr);
				m2 = ng_ppp_prepend(m2, &lhdr, 4);
			}
			if (m2 == NULL) {
				if (!lastFragment)
					NG_FREE_M(m);
				if (firstFragment)
					NG_FREE_META(meta);
				return (ENOBUFS);
			}

			/* Copy meta information if any. */
			meta2 = (lastFragment ? meta : ng_copy_meta(meta));

			/* Send fragment */
			error = ng_ppp_link_xmit(priv, m2, meta2, PROT_MP,
						 linkNum,
						 (firstFragment ? plen : 0));
			if (error != 0) {
				if (!lastFragment)
					NG_FREE_DATA(m, meta);
				return error;
			}
		}
	}

	/* Done */
	return (0);
}

/*
 * Computing the optimal fragmentation
 * -----------------------------------
 *
 * This routine tries to compute the optimal fragmentation pattern based
 * on each link's latency, bandwidth, and calculated additional latency.
 * The latter quantity is the additional latency caused by previously
 * written data that has not been transmitted yet.
 *
 * This algorithm is only useful when not all of the links have the
 * same latency and bandwidth values.
 *
 * The essential idea is to make the last bit of each fragment of the
 * frame arrive at the opposite end at the exact same time. This greedy
 * algorithm is optimal, in that no other scheduling could result in any
 * packet arriving any sooner unless packets are delivered out of order.
 *
 * Suppose link i has bandwidth b_i (in tens of bytes per milisecond) and
 * latency l_i (in miliseconds). Consider the function function f_i(t)
 * which is equal to the number of bytes that will have arrived at
 * the peer after t miliseconds if we start writing continuously at
 * time t = 0. Then f_i(t) = b_i * (t - l_i) = ((b_i * t) - (l_i * b_i).
 * That is, f_i(t) is a line with slope b_i and y-intersect -(l_i * b_i).
 * Note that the y-intersect is always <= zero because latency can't be
 * negative.  Note also that really the function is f_i(t) except when
 * f_i(t) is negative, in which case the function is zero.  To take
 * care of this, let Q_i(t) = { if (f_i(t) > 0) return 1; else return 0; }.
 * So the actual number of bytes that will have arrived at the peer after
 * t miliseconds is f_i(t) * Q_i(t).
 *
 * At any given time, each link has some additional latency a_i >= 0
 * due to previously written fragment(s) which are still in the queue.
 * This value is easily computed from the time since last transmission,
 * the previous latency value, the number of bytes written, and the
 * link's bandwidth.
 *
 * Assume that l_i includes any a_i already, and that the links are
 * sorted by latency, so that l_i <= l_{i+1}.
 *
 * Let N be the total number of bytes in the current frame we are sending.
 *
 * Suppose we were to start writing bytes at time t = 0 on all links
 * simultaneously, which is the most we can possibly do.  Then let
 * F(t) be equal to the total number of bytes received by the peer
 * after t miliseconds. Then F(t) = Sum_i (f_i(t) * Q_i(t)).
 *
 * Our goal is simply this: fragment the frame across the links such
 * that the peer is able to reconstruct the completed frame as soon as
 * possible, i.e., at the least possible value of t. Call this value t_0.
 *
 * Then it follows that F(t_0) = N. Our strategy is first to find the value
 * of t_0, and then deduce how many bytes to write to each link.
 *
 * Rewriting F(t_0):
 *
 *   t_0 = ( N + Sum_i ( l_i * b_i * Q_i(t_0) ) ) / Sum_i ( b_i * Q_i(t_0) )
 *
 * Now, we note that Q_i(t) is constant for l_i <= t <= l_{i+1}. t_0 will
 * lie in one of these ranges.  To find it, we just need to find the i such
 * that F(l_i) <= N <= F(l_{i+1}).  Then we compute all the constant values
 * for Q_i() in this range, plug in the remaining values, solving for t_0.
 *
 * Once t_0 is known, then the number of bytes to send on link i is
 * just f_i(t_0) * Q_i(t_0).
 *
 * In other words, we start allocating bytes to the links one at a time.
 * We keep adding links until the frame is completely sent.  Some links
 * may not get any bytes because their latency is too high.
 *
 * Is all this work really worth the trouble?  Depends on the situation.
 * The bigger the ratio of computer speed to link speed, and the more
 * important total bundle latency is (e.g., for interactive response time),
 * the more it's worth it.  There is however the cost of calling this
 * function for every frame.  The running time is O(n^2) where n is the
 * number of links that receive a non-zero number of bytes.
 *
 * Since latency is measured in miliseconds, the "resolution" of this
 * algorithm is one milisecond.
 *
 * To avoid this algorithm altogether, configure all links to have the
 * same latency and bandwidth.
 */
static void
ng_ppp_mp_strategy(priv_p priv, int len, unsigned int *distrib)
{
	int latency[NG_PPP_MAX_LINKS];
	int sortByLatency[NG_PPP_MAX_LINKS];
	int activeLinkNum;
	int t0, total, topSum, botSum;
	struct vnb_timeval now;
	int i, numFragments;

	/* If only one link, this gets real easy */
	if (priv->numActiveLinks == 1) {
		distrib[0] = len;
		return;
	}

	/* Get current time */
	microtime(&now);

	/* Compute latencies for each link at this point in time */
	for (activeLinkNum = 0;
	    activeLinkNum < priv->numActiveLinks; activeLinkNum++) {
		struct ng_ppp_link *alink;
		struct vnb_timeval diff;
		int xmitBytes;

		/* Start with base latency value */
		alink = &priv->links[priv->activeLinks[activeLinkNum]];
		latency[activeLinkNum] = alink->latency;
		sortByLatency[activeLinkNum] = activeLinkNum;	/* see below */

		/* Any additional latency? */
		if (alink->bytesInQueue == 0)
			continue;

		/* Compute time delta since last write */
		diff = now;
		timevalsub(&diff, &alink->lastWrite);

		/* alink->bytesInQueue will be changed, mark change time. */
		alink->lastWrite = now;

		if (now.tv_sec < 0 || diff.tv_sec >= 10) {	/* sanity */
			alink->bytesInQueue = 0;
			continue;
		}

		/* How many bytes could have transmitted since last write? */
		xmitBytes = (alink->conf.bandwidth * 10 * diff.tv_sec)
		    + (alink->conf.bandwidth * (diff.tv_usec / 1000)) / 100;
		alink->bytesInQueue -= xmitBytes;
		if (alink->bytesInQueue < 0)
			alink->bytesInQueue = 0;
		else
			latency[activeLinkNum] +=
			    (100 * alink->bytesInQueue) / alink->conf.bandwidth;
	}

	/* Sort active links by latency */
	bqsort_r(sortByLatency, priv->numActiveLinks, sizeof(*sortByLatency),
		 latency, ng_ppp_intcmp);

	/* Find the interval we need (add links in sortByLatency[] order) */
	for (numFragments = 1;
	    numFragments < priv->numActiveLinks; numFragments++) {
		for (total = i = 0; i < numFragments; i++) {
			int flowTime;

			flowTime = latency[sortByLatency[numFragments]]
			    - latency[sortByLatency[i]];
			total += ((flowTime * priv->links[
			    priv->activeLinks[sortByLatency[i]]].conf.bandwidth)
				+ 99) / 100;
		}
		if (total >= len)
			break;
	}

	/* Solve for t_0 in that interval */
	for (topSum = botSum = i = 0; i < numFragments; i++) {
		int bw = priv->links[
		    priv->activeLinks[sortByLatency[i]]].conf.bandwidth;

		topSum += latency[sortByLatency[i]] * bw;	/* / 100 */
		botSum += bw;					/* / 100 */
	}
	t0 = ((len * 100) + topSum + botSum / 2) / botSum;

	/* Compute f_i(t_0) all i */
	for (total = i = 0; i < numFragments; i++) {
		int bw = priv->links[
		    priv->activeLinks[sortByLatency[i]]].conf.bandwidth;

		distrib[sortByLatency[i]] =
		    (bw * (t0 - latency[sortByLatency[i]]) + 50) / 100;
		total += distrib[sortByLatency[i]];
	}

	/* Deal with any rounding error */
	if (total < len) {
		struct ng_ppp_link *fastLink =
		    &priv->links[priv->activeLinks[sortByLatency[0]]];
		int fast = 0;

		/* Find the fastest link */
		for (i = 1; i < numFragments; i++) {
			struct ng_ppp_link *const link =
			    &priv->links[priv->activeLinks[sortByLatency[i]]];

			if (link->conf.bandwidth > fastLink->conf.bandwidth) {
				fast = i;
				fastLink = link;
			}
		}
		distrib[sortByLatency[fast]] += len - total;
	} else while (total > len) {
		struct ng_ppp_link *slowLink =
		    &priv->links[priv->activeLinks[sortByLatency[0]]];
		unsigned int delta;
		int slow = 0;

		/* Find the slowest link that still has bytes to remove */
		for (i = 1; i < numFragments; i++) {
			struct ng_ppp_link *const link =
			    &priv->links[priv->activeLinks[sortByLatency[i]]];

			if (distrib[sortByLatency[slow]] == 0
			  || (distrib[sortByLatency[i]] > 0
			    && link->conf.bandwidth <
			      slowLink->conf.bandwidth)) {
				slow = i;
				slowLink = link;
			}
		}
		delta = total - len;
		if (delta > distrib[sortByLatency[slow]])
			delta = distrib[sortByLatency[slow]];
		distrib[sortByLatency[slow]] -= delta;
		total -= delta;
	}
}

/*
 * Compare two integers
 */
static int
ng_ppp_intcmp(void *latency, const void *v1, const void *v2)
{
	const int index1 = *((const int *) v1);
	const int index2 = *((const int *) v2);

	return ((int *)latency)[index1] - ((int *)latency)[index2];
}

#else /* MP_ENABLE */

static int
ng_ppp_recv(priv_p priv, struct mbuf *m, meta_p meta, uint16_t proto,
	    uint16_t linkNum)
{
#ifdef NG_PPP_STATS
	/* Stats */
	priv->bundleStats.recvFrames++;
	priv->bundleStats.recvOctets += MBUF_LENGTH(m);
#endif
	return ng_ppp_crypt_recv(priv, m, meta, proto, linkNum);
}

#endif /* MP_ENABLE */

/*
 * Prepend a possibly compressed PPP protocol number in front of a frame
 */
static struct mbuf *
ng_ppp_addproto(struct mbuf *m, uint16_t proto, int compOK)
{
	if (compOK && PROT_COMPRESSABLE(proto)) {
		uint8_t pbyte = (uint8_t)proto;

		return ng_ppp_prepend(m, &pbyte, 1);
	} else {
		uint16_t pword = htons((uint16_t)proto);

		return ng_ppp_prepend(m, &pword, 2);
	}
}

/*
 * Cut a possibly compressed PPP protocol number from the front of a frame.
 */
static struct mbuf *
ng_ppp_cutproto(struct mbuf *m, uint16_t *proto)
{
	*proto = 0;
	if ((m = m_pullup(m, 1)) == NULL)
		return (NULL);

	*proto = *mtod(m, uint8_t *);
	m_adj(m, 1);

	if (!PROT_VALID(*proto)) {
		if ((m = m_pullup(m, 1)) == NULL)
			return (NULL);

		*proto = (*proto << 8) + *mtod(m, uint8_t *);
		m_adj(m, 1);
	}

	return (m);
}

/*
 * Prepend some bytes to an mbuf.
 */
static struct mbuf *
ng_ppp_prepend(struct mbuf *m, const void *buf, int len)
{
	M_PREPEND(m, len, M_DONTWAIT);
	if (unlikely((m == NULL) || ((m = m_pullup(m, len)) == NULL)))
		return (NULL);
	bcopy(buf, mtod(m, uint8_t *), len);
	return (m);
}

/*
 * Update private information that is derived from other private information
 */
static void
ng_ppp_update(node_p node, int newConf)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	int i;

#ifdef CONFIG_VNB_NODE_VJC
	/* Update active status for VJ Compression */
	priv->vjCompHooked = priv->hooks[HOOK_INDEX_VJC_IP] != NULL
	    && priv->hooks[HOOK_INDEX_VJC_COMP] != NULL
	    && priv->hooks[HOOK_INDEX_VJC_UNCOMP] != NULL
	    && priv->hooks[HOOK_INDEX_VJC_VJIP] != NULL;
#endif

	/* Increase latency for each link an amount equal to one MP header */
	if (newConf) {
		for (i = 0; i < NG_PPP_MAX_LINKS; i++) {
			int hdrBytes;

			if (priv->links[i].conf.bandwidth == 0)
			    continue;

			hdrBytes = MP_AVERAGE_LINK_OVERHEAD
			    + (priv->links[i].conf.enableACFComp ? 0 : 2)
			    + (priv->links[i].conf.enableProtoComp ? 1 : 2)
			    + (priv->conf.xmitShortSeq ? 2 : 4);
			priv->links[i].latency =
			    priv->links[i].conf.latency +
			    (hdrBytes / priv->links[i].conf.bandwidth + 50) / 100;
		}
	}

	/* Update list of active links */
	bzero(&priv->activeLinks, sizeof(priv->activeLinks));
	priv->numActiveLinks = 0;
	priv->allLinksEqual = 1;
	for (i = 0; i < NG_PPP_MAX_LINKS; i++) {
		struct ng_ppp_link *const link = &priv->links[i];

		/* Is link active? */
		if (link->conf.enableLink && link->hook != NULL) {
			struct ng_ppp_link *link0;

			/* Add link to list of active links */
			priv->activeLinks[priv->numActiveLinks++] = i;
			link0 = &priv->links[priv->activeLinks[0]];

			/* Determine if all links are still equal */
			if (link->latency != link0->latency
			  || link->conf.bandwidth != link0->conf.bandwidth)
				priv->allLinksEqual = 0;

			/* Initialize rec'd sequence number */
			if (link->seq == MP_NOSEQ) {
				link->seq = (link == link0) ?
				    MP_INITIAL_SEQ : link0->seq;
			}
		} else
			link->seq = MP_NOSEQ;
	}

#ifdef MP_ENABLE
	/* Update MP state as multi-link is active or not */
	if (priv->conf.enableMultilink && priv->numActiveLinks > 0)
		ng_ppp_start_frag_timer(node, priv);
	else {
		ng_ppp_stop_frag_timer(node);
		ng_ppp_frag_reset(node);
#endif /* MP_ENABLE */
		priv->xseq = MP_INITIAL_SEQ;
		priv->mseq = MP_INITIAL_SEQ;
		for (i = 0; i < NG_PPP_MAX_LINKS; i++) {
			struct ng_ppp_link *const link = &priv->links[i];

			bzero(&link->lastWrite, sizeof(link->lastWrite));
			link->bytesInQueue = 0;
			link->seq = MP_NOSEQ;
		}
#ifdef MP_ENABLE
	}
#endif /* MP_ENABLE */
}

/*
 * Determine if a new configuration would represent a valid change
 * from the current configuration and link activity status.
 */
static int
ng_ppp_config_valid(node_p node, const struct ng_ppp_node_conf *newConf)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	int i, newNumLinksActive;

	/* Check per-link config and count how many links would be active */
	for (newNumLinksActive = i = 0; i < NG_PPP_MAX_LINKS; i++) {
		if (newConf->links[i].enableLink && priv->links[i].hook != NULL)
			newNumLinksActive++;
		if (!newConf->links[i].enableLink)
			continue;
		if (newConf->links[i].mru < MP_MIN_LINK_MRU)
			return (0);
		if (newConf->links[i].bandwidth == 0)
			return (0);
		if (newConf->links[i].bandwidth > NG_PPP_MAX_BANDWIDTH)
			return (0);
		if (newConf->links[i].latency > NG_PPP_MAX_LATENCY)
			return (0);
	}

#ifdef MP_ENABLE
	/* Disallow changes to multi-link configuration while MP is active */
	if (priv->numActiveLinks > 0 && newNumLinksActive > 0) {
		if (!priv->conf.enableMultilink
				!= !newConf->bund.enableMultilink
		    || !priv->conf.xmitShortSeq != !newConf->bund.xmitShortSeq
		    || !priv->conf.recvShortSeq != !newConf->bund.recvShortSeq)
			return (0);
	}

	/* At most one link can be active unless multi-link is enabled */
	if (!newConf->bund.enableMultilink && newNumLinksActive > 1)
		return (0);
#else /* MP_ENABLE */
	if (newNumLinksActive > 1)
		return 0;
#endif /* MP_ENABLE */

	/* Configuration change would be valid */
	return (1);
}

#ifdef MP_ENABLE

/*
 * Free all entries in the fragment queue
 */
static void
ng_ppp_frag_reset(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_ppp_frag *qent, *qnext;

	vnb_spinlock_lock(&priv->fraglock);
	for (qent = TAILQ_FIRST(&priv->frags); qent; qent = qnext) {
		qnext = TAILQ_NEXT(qent, f_qent);
		NG_FREE_DATA(qent->data, qent->meta);
		TAILQ_INSERT_HEAD(&priv->fragsfree, qent, f_qent);
	}
	TAILQ_INIT(&priv->frags);
	vnb_spinlock_unlock(&priv->fraglock);
}

/*
 * Start fragment queue timer
 */
static void
ng_ppp_start_frag_timer(node_p node, priv_p priv)
{
	if (priv->fragtimer_running == 0) {
		priv->fragtimer_running = 1;
		NG_NODE_REF(node);
	}
	ng_callout_reset(&priv->fragTimer, MP_FRAGTIMER_INTERVAL,
			 (void (*)(void *))ng_ppp_frag_timeout, node);
}

/*
 * Stop fragment queue timer
 */
static void
ng_ppp_stop_frag_timer(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	if ((priv == NULL) || (priv->fragtimer_running == 0))
		return;
	ng_callout_stop_sync(&priv->fragTimer);
	priv->fragtimer_running = 0;
	NG_NODE_UNREF(node);
}

#endif /* MP_ENABLE */

#if defined(__LinuxKernelVNB__)
module_init(ng_ppp_init);
module_exit(ng_ppp_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB PPP node");
MODULE_LICENSE("6WIND");
#endif
