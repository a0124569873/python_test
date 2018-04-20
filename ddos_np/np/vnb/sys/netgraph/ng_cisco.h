
/*
 * ng_cisco.h
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
 * $FreeBSD: src/sys/netgraph/ng_cisco.h,v 1.2.2.4 2002/07/02 23:44:02 archie Exp $
 * $Whistle: ng_cisco.h,v 1.6 1999/01/25 01:21:48 archie Exp $
 */

/*
 * Copyright 2003-2012 6WIND S.A.
 */

#ifndef _NETGRAPH_CISCO_H_
#define _NETGRAPH_CISCO_H_

/* Node type name and magic cookie */
#define NG_CISCO_NODE_TYPE		"cisco"
#define NGM_CISCO_COOKIE		860707227

/* Hook names */
#define NG_CISCO_HOOK_DOWNSTREAM	"downstream"
#define NG_CISCO_HOOK_INET		"inet"
#define NG_CISCO_HOOK_INET6		"inet6"
#define NG_CISCO_HOOK_APPLETALK		"atalk"
#define NG_CISCO_HOOK_IPX		"ipx"
#define NG_CISCO_HOOK_TRANSETH		"eth"
#define NG_CISCO_HOOK_MPLS		"mpls"
#define NG_CISCO_HOOK_DEBUG		"debug"
#define NG_CISCO_HOOK_INFO		"info"

/* Magic string use to report state of this node */
#define NG_CISCO_LINKSTATE_STR_SIZE	16
#define NG_CISCO_LINKSTATE_STR_UP	"linkstate=up"
#define NG_CISCO_LINKSTATE_STR_DOWN	"linkstate=down"

/* Netgraph commands */
enum {
	NGM_CISCO_SET_IPADDR = 1,	/* requires a struct ng_cisco_ipaddr */
	NGM_CISCO_GET_IPADDR,		/* returns a struct ng_cisco_ipaddr */
	NGM_CISCO_GET_STATUS,		/* returns a struct ng_cisco_stat */
	NGM_CISCO_SET_KEEPALIVE,	/* Set the keepalive period (default 10s) */
	NGM_CISCO_GET_FASTPATH_STATS,
};

#ifdef FASTPATH_STATS
struct ng_cisco_link_stats {
	u_int32_t IPxmitFrames;
	u_int32_t IPxmitOctets;
	u_int32_t IPxmitDropped;
	u_int32_t IPrecvFrames;
	u_int32_t IPrecvOctets;
	u_int32_t IPrecvDropped;
	u_int32_t xmitFrames;           /* xmit frames on link */
	u_int32_t xmitOctets;           /* xmit octets on link */
	u_int32_t recvFrames;           /* recv frames on link */
	u_int32_t recvOctets;           /* recv octets on link */
	u_int32_t badProtos;            /* frames rec'd with bogus protocol */
	struct kernel2cc_hdlc_stats hdlcstats;
};

extern u_int32_t sc_if_get_drop_stats(u_int32_t arg_ifIndex,
		u_int64_t *arg_pRxDrop,
		u_int64_t *arg_pTxDrop);

extern unsigned int kernel2cc_hdlc_get_stats(int ifindex,
	struct kernel2cc_hdlc_stats *hdlc_stats_);
extern unsigned int kernel2cc_ds1_hdlc_get_stats(int ifindex,
	struct kernel2cc_hdlc_stats *hdlc_stats_);

#endif

struct ng_cisco_ipaddr {
	struct in_addr	ipaddr;		/* IP address */
	struct in_addr	netmask;	/* Netmask */
};

/* Keep this in sync with the above structure definition */
#define NG_CISCO_IPADDR_TYPE_INFO	{			\
	{ .name = "ipaddr", .type = &ng_parse_ipaddr_type },	\
	{ .name = "netmask", .type = &ng_parse_ipaddr_type },	\
	{ .name = NULL }					\
}

struct ng_cisco_stats {
	u_int32_t   seqRetries;		/* # unack'd retries */
	u_int32_t   seqRetriesMax ;	/* nb retries before sending the down state */
	u_int32_t   keepAlivePeriod;	/* in seconds */
	u_int32_t   lineStatus;		/* Line Status (0: down) */
};

/* Keep this in sync with the above structure definition */
#define NG_CISCO_STATS_TYPE_INFO	{				\
	{ .name = "seqRetries", .type = &ng_parse_uint32_type },	\
	{ .name = "seqRetriesMax", .type = &ng_parse_uint32_type },	\
	{ .name = "keepAlivePeriod", .type = &ng_parse_uint32_type },	\
	{ .name = "lineStatus", .type = &ng_parse_uint32_type },	\
	{ .name = NULL }						\
}

struct ng_cisco_keepalive {
	u_int32_t   seqRetriesMax ;	/* nb retries before sending the down state */
	u_int32_t keepAlivePeriod; /* in seconds */
};

/* keep in sync */
#define NG_CISCO_KEEPALIVE_TYPE_INFO {					\
	{ .name = "seqRetriesMax", .type = &ng_parse_uint32_type },	\
	{ .name = "keepAlivePeriod", .type = &ng_parse_uint32_type },	\
	{ .name = NULL }						\
}


#endif /* _NETGRAPH_CISCO_H_ */

