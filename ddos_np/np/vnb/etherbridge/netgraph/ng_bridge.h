
/*
 * ng_bridge.h
 *
 * Copyright (c) 2000 Whistle Communications, Inc.
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
 * $FreeBSD: src/sys/netgraph/ng_bridge.h,v 1.1.2.2 2002/07/02 23:44:02 archie Exp $
 */

 /*
  * Copyright 2003-2012 6WIND S.A.
  */

#ifndef _NETGRAPH_NG_BRIDGE_H_
#define _NETGRAPH_NG_BRIDGE_H_

/* Node type name and magic cookie */
#define NG_BRIDGE_NODE_TYPE		"bridge"
#define NGM_BRIDGE_COOKIE		967239368

/* Hook names */
#define NG_BRIDGE_HOOK_LINK_PREFIX	"link"	 /* append decimal integer */
#define NG_BRIDGE_HOOK_LINK_FMT		"link%d" /* for use with printf(3) */

/* Maximum number of supported links */
#define NG_BRIDGE_MAX_LINKS (1 << 11)

/*
 * NG_BRIDGE_SNOOP : to enable snooping management
 * NG_BRIDGE_FLOOD : to enable flooding to discover outgoing ports
 * NG_BRIDGE_TIMER : to enable expiration of host entries
 * NG_BRIDGE_STATS : to count valid incoming packets (unicast and mcast)
 */
#if defined (__LinuxKernelVNB__)
#define NG_BRIDGE_SNOOP 1
#define NG_BRIDGE_FLOOD 1
#define NG_BRIDGE_TIMER 1
#define NG_BRIDGE_STATS 1
//#define NG_BRIDGE_DEBUG 1
#endif

/* Node configuration structure */
struct ng_bridge_config {
	u_int16_t	loopTimeout;		/* link loopback mute time */
	u_int16_t	maxStaleness;		/* max host age before nuking */
	u_int16_t	minStableAge;		/* min time for a stable host */
	u_int16_t	debugLevel;		/* debug level */
#ifdef NG_BRIDGE_IPFW
	uint8_t		ipfw[NG_BRIDGE_MAX_LINKS]; 	/* enable ipfw */
#endif
};

/* Keep this in sync with the above structure definition */
#ifdef NG_BRIDGE_IPFW
#define NG_BRIDGE_CONFIG_TYPE_INFO(ainfo)	{		\
	  { "loopTimeout",	&ng_parse_uint16_type, 0	},	\
	  { "maxStaleness",	&ng_parse_uint16_type, 0	},	\
	  { "minStableAge",	&ng_parse_uint16_type, 0	},	\
	  { "debugLevel",	&ng_parse_uint16_type, 0	},	\
	  { "ipfw",		(ainfo), 0			},	\
	  { NULL, NULL, 0 }						\
}
#else
#define NG_BRIDGE_CONFIG_TYPE_INFO	{		\
	  { "loopTimeout",	&ng_parse_uint16_type, 0	},	\
	  { "maxStaleness",	&ng_parse_uint16_type, 0	},	\
	  { "minStableAge",	&ng_parse_uint16_type, 0	},	\
	  { "debugLevel",	&ng_parse_uint16_type, 0	},	\
	  { NULL, NULL, 0 }						\
}
#endif

#ifdef NG_BRIDGE_STATS
/* Statistics structure (one for each link) */
struct ng_bridge_link_stats {
	u_int64_t	recvOctets;	/* total octets rec'd on link */
	u_int64_t	recvPackets;	/* total pkts rec'd on link */
	u_int64_t	recvMulticasts;	/* multicast pkts rec'd on link */
	u_int64_t	recvBroadcasts;	/* broadcast pkts rec'd on link */
	u_int64_t	recvUnknown;	/* pkts rec'd with unknown dest addr */
	u_int64_t	recvRunts;	/* pkts rec'd less than 14 bytes */
	u_int64_t	recvInvalid;	/* pkts rec'd with bogus source addr */
	u_int64_t	xmitOctets;	/* total octets xmit'd on link */
	u_int64_t	xmitPackets;	/* total pkts xmit'd on link */
	u_int64_t	xmitMulticasts;	/* multicast pkts xmit'd on link */
	u_int64_t	xmitBroadcasts;	/* broadcast pkts xmit'd on link */
	u_int64_t	loopDrops;	/* pkts dropped due to loopback */
	u_int64_t	loopDetects;	/* number of loop detections */
	u_int64_t	memoryFailures;	/* times couldn't get mem or mbuf */
};

/* Keep this in sync with the above structure definition */
#define NG_BRIDGE_STATS_TYPE_INFO	{			\
	  { "recvOctets",	&ng_parse_uint64_type, 0	},	\
	  { "recvPackets",	&ng_parse_uint64_type, 0 	},	\
	  { "recvMulticast",	&ng_parse_uint64_type, 0	},	\
	  { "recvBroadcast",	&ng_parse_uint64_type, 0	},	\
	  { "recvUnknown",	&ng_parse_uint64_type, 0	},	\
	  { "recvRunts",	&ng_parse_uint64_type, 0	},	\
	  { "recvInvalid",	&ng_parse_uint64_type, 0	},	\
	  { "xmitOctets",	&ng_parse_uint64_type, 0	},	\
	  { "xmitPackets",	&ng_parse_uint64_type, 0	},	\
	  { "xmitMulticasts",	&ng_parse_uint64_type, 0	},	\
	  { "xmitBroadcasts",	&ng_parse_uint64_type, 0	},	\
	  { "loopDrops",	&ng_parse_uint64_type, 0	},	\
	  { "loopDetects",	&ng_parse_uint64_type, 0	},	\
	  { "memoryFailures",	&ng_parse_uint64_type, 0	},	\
	  { NULL, NULL, 0 }						\
}
#endif

/* Structure describing a single host */
struct ng_bridge_host {
	u_int8_t	addr[6];	/* ethernet address */
	u_int16_t	linkNum;	/* link where addr can be found */
	u_int16_t	age;		/* seconds ago entry was created */
	u_int16_t	staleness;	/* seconds ago host last heard from */
};

/* Keep this in sync with the above structure definition */
#define NG_BRIDGE_HOST_TYPE_INFO(entype)	{		\
	  { "addr",		(entype), 0		},	\
	  { "linkNum",		&ng_parse_uint16_type, 0	},	\
	  { "age",		&ng_parse_uint16_type, 0	},	\
	  { "staleness",	&ng_parse_uint16_type, 0	},	\
	  { NULL, NULL, 0 }						\
}

/* Structure describing a static host */
struct ng_bridge_static_host {
	u_int8_t	addr[6];	/* ethernet address */
	u_int16_t	linkNum;	/* link where addr can be found */
};

/* Keep this in sync with the above structure definition */
#define NG_BRIDGE_STATIC_HOST_TYPE_INFO(entype)	{		\
	  { "addr",		(entype), 0		},	\
	  { "linkNum",		&ng_parse_uint16_type, 0	},	\
	  { NULL, NULL, 0 }						\
}

/* Structure returned by NGM_BRIDGE_GET_TABLE */
struct ng_bridge_host_ary {
	u_int32_t		numHosts;
	struct ng_bridge_host	hosts[];
};

/* Keep this in sync with the above structure definition */
#define NG_BRIDGE_HOST_ARY_TYPE_INFO(harytype)	{		\
	  { "numHosts",		&ng_parse_uint32_type, 0	},	\
	  { "hosts",		(harytype),  0		},	\
	  { NULL, NULL, 0 }						\
}

/* Netgraph control messages */
enum {
	NGM_BRIDGE_SET_CONFIG = 1,	/* set node configuration */
	NGM_BRIDGE_GET_CONFIG,		/* get node configuration */
	NGM_BRIDGE_RESET,		/* reset (forget) all information */
	NGM_BRIDGE_GET_STATS,		/* get link stats */
	NGM_BRIDGE_CLR_STATS,		/* clear link stats */
	NGM_BRIDGE_GETCLR_STATS,	/* atomically get & clear link stats */
	NGM_BRIDGE_GET_TABLE,		/* get link table */
	NGM_BRIDGE_SET_SNOOP_CONFIG,	/* set snoop configuration */
	NGM_BRIDGE_GET_SNOOP_CONFIG,	/* get snoop configuration */
	NGM_BRIDGE_NOTIFY_SNOOPD,		/* notification to snoop daemon */
	NGM_BRIDGE_ADD_HOST,		/* add static host to bridge table */
	NGM_BRIDGE_DEL_HOST,		/* delete static host to bridge table */
};

#endif /* _NETGRAPH_NG_BRIDGE_H_ */
