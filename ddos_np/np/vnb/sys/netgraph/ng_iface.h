
/*
 * ng_iface.h
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
 * $FreeBSD: src/sys/netgraph/ng_iface.h,v 1.1.4.2 2000/10/24 18:36:45 julian Exp $
 * $Whistle: ng_iface.h,v 1.5 1999/01/20 00:22:13 archie Exp $
 */
/*
 * Copyright 2003-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_IFACE_H_
#define _NETGRAPH_IFACE_H_

#ifndef NG_IFACE_TYPE
#define NG_IFACE_TYPE 0
#endif

/* Node type name and magic cookie */
/* if NG_IFACE_TYPE == 0 then type = iface
 */

#if NG_IFACE_TYPE == 0
#define NG_IFACE_NODE_TYPE		"iface"
#define NGM_IFACE_COOKIE		858821772
#define NG_IFACE_MTU_DEFAULT		1500
/* Interface base name */
#define NG_IFACE_IFACE_NAME		"ng"
#endif

#define NG_IFACE_IFACE_NAME_MAX		15

/* My hook names */
#define NG_IFACE_HOOK_INET		"inet"
#define NG_IFACE_HOOK_INET6		"inet6"
#define NG_IFACE_HOOK_ATALK		"atalk"	/* AppleTalk phase 2 */
#define NG_IFACE_HOOK_IPX		"ipx"
#define NG_IFACE_HOOK_ATM		"atm"
#define NG_IFACE_HOOK_NATM		"natm"
#define NG_IFACE_HOOK_NS		"ns"
#define NG_IFACE_HOOK_ALLIP		"allip"
#define NG_IFACE_HOOK_ALLIP_IN_PREFIX   "allip_in_"

/* Netgraph commands */
enum {
	NGM_IFACE_GET_IFNAME = 1,   /* returns struct ng_iface_ifname */
	NGM_IFACE_POINT2POINT,
	NGM_IFACE_BROADCAST,
	NGM_IFACE_GET_IFADDRS,      /* returns list of addresses */

	NGM_IFACE_SET_IFNAME,       /* change name ( under linux )*/
	NGM_IFACE_SETGET_IFNAME,    /* change and return name */
	NGM_IFACE_GET_INFO,         /* get struct ng_iface_info */
	NGM_IFACE_SET_INFO,         /* set struct ng_iface_info */
	NGM_IFACE_SETGET_INFO,      /* set and get struct ng_iface_info */
	NGM_IFACE_GET_IFTYPE,       /* read interface type (e.g. ppp, gre...) */
	NGM_IFACE_SET_IFTYPE,       /* change interface type (e.g. ppp, gre...) */
	NGM_IFACE_SET_CARRIER,      /* change carrier status */
	NGM_IFACE_SET_ENCAPADDR,    /* set encapsulation addresses for better display */
	NGM_IFACE_SET_KEY,          /* set optional key for better display */
};

struct ng_iface_ifname {
	char    ngif_name[NG_IFACE_IFACE_NAME_MAX + 1];
};

#define NG_IFACE_NETDEV_LITE		1
struct ng_iface_info {
	uint32_t id; /* node id (read-only) */
	uint32_t index; /* interface index (read-only) */
	char name[(NG_IFACE_IFACE_NAME_MAX + 1)]; /* interface name */
	uint32_t netdev_flag; /* flag to use when creating the netdev */
};

struct ng_iface_key {
	uint32_t hasKey;  /* do we use a specific key ? */
	uint32_t useKey;  /* used key */
};

#define NG_IFACE_KEY_TYPE_INFO   {                 \
       { "hasKey",   &ng_parse_uint32_type, 0 }, \
       { "useKey",   &ng_parse_uint32_type, 0 }, \
       { NULL, NULL, 0 }                         \
}


#if !defined (__FastPath__)
struct ng_iface_encap_addr {
	unsigned short link_type;
	unsigned short family_type;
	union {
		struct in_addr in;
		struct in6_addr in6;
	} s_addr;
	union {
		struct in_addr in;
		struct in6_addr in6;
	} d_addr;
};
#endif

#endif /* _NETGRAPH_IFACE_H_ */
