/*
 * ng_bridge.c
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
 * $FreeBSD: src/sys/netgraph/ng_bridge.c,v 1.1.2.5 2002/07/02 23:44:02 archie Exp $
 */

 /*
  * Copyright 2003-2013 6WIND S.A.
  */

/*
 * ng_bridge(4) netgraph node type
 *
 * The node performs standard intelligent Ethernet bridging over
 * each of its connected hooks, or links.  A simple loop detection
 * algorithm is included which disables a link for priv->conf.loopTimeout
 * seconds when a host is seen to have jumped from one link to
 * another within priv->conf.minStableAge seconds.
 *
 * We keep a hashtable that maps Ethernet addresses to host info,
 * which is contained in struct ng_bridge_host's. These structures
 * tell us on which link the host may be found. A host's entry will
 * expire after priv->conf.maxStaleness seconds.
 *
 * This node is optimzed for stable networks, where machines jump
 * from one port to the other only rarely.
 */

#if defined(__LinuxKernelVNB__)

#include <linux/version.h>
#include <linux/module.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/timer.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <linux/ctype.h> /* for isdigit */
#include <netgraph/vnblinux.h>

#include <linux/icmpv6.h>
#include <linux/ipv6.h>
#include <linux/igmp.h>
#define ip6_hdr	ipv6hdr
#define ip6_nxt	nexthdr
#define ip6_dst	daddr

#ifndef ICMP6_MEMBERSHIP_QUERY
	#define ICMP6_MEMBERSHIP_QUERY ICMPV6_MGM_QUERY
	#define ICMP6_MEMBERSHIP_REPORT ICMPV6_MGM_REPORT
	#define ICMP6_MEMBERSHIP_REDUCTION ICMPV6_MGM_REDUCTION
#endif

#elif defined(__FastPath__)
#include "fp-netgraph.h"
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_ether.h>
#include <netgraph/ng_bridge.h>
#ifdef NG_BRIDGE_SNOOP
#include <netgraph/ng_bridge_snoop.h>
#endif
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#include <netgraph/vnb_in6.h>
#endif
#include <netgraph/vnb_ether.h>

#define NG_BRIDGE_LOG_DEBUG 0

/* Per-link private data */
struct ng_bridge_link {
	hook_p				hook;		/* netgraph hook */
	u_int16_t			loopCount;	/* loop ignore timer */
#ifdef NG_BRIDGE_STATS
	struct ng_bridge_link_stats	stats;		/* link stats */
#endif
};

/* Per-node private data */
struct ng_bridge_private {
	struct ng_bridge_bucket	*tab;		/* hash table bucket array */
	struct ng_bridge_link	*links[NG_BRIDGE_MAX_LINKS];
	struct ng_bridge_config	conf;		/* node configuration */
	node_p			node;		/* netgraph node */
	u_int			numSHosts;	/* number of static hosts in table */
	u_int			numDHosts;	/* number of dynamic hosts in table */
	u_int			numBuckets;	/* num buckets in table */
	u_int			hashMask;	/* numBuckets - 1 */
	u_int			numLinks;	/* num connected links */
	vnb_spinlock_t		spinlock;
#ifdef NG_BRIDGE_TIMER
	struct ng_callout	timer;		/* one second periodic timer */
#endif
#ifdef NG_BRIDGE_SNOOP
	hook_p          snoop_hook;
	u_int           snoop_mode;
#			define   MLD_SNOOP    0x01
#			define   IGMP_SNOOP   0x02
	port_set		mld_routers;
	port_set		igmp_routers;
	port_set		spy_ports;
	u_int			nb_spy;
	struct ng_bridge_grp_bucket	*gtab;	/* hash table grp_bucket array */
	u_int			numGroups;		/* num entries in table */
	u_int			num_grpBuckets;	/* num buckets in table */
	u_int			hash_grpMask;	/* numBuckets - 1 */

	/* all port/no port configuration */
	port_set  all_ports;
	port_set  no_port;
#endif
};
typedef struct ng_bridge_private *priv_p;

/* Information about a host, stored in a hash table entry */
struct ng_bridge_hent {
	struct ng_bridge_host		host;	/* actual host info */
	SLIST_ENTRY(ng_bridge_hent)	next;	/* next entry in bucket */
};

/* Hash table bucket declaration */
SLIST_HEAD(ng_bridge_bucket, ng_bridge_hent);

#ifdef NG_BRIDGE_SNOOP
/* Information about a group, stored in a hash table entry */
struct ng_bridge_grp_ent {
	struct ng_bridge_group			group;	/* actual host info */
	SLIST_ENTRY(ng_bridge_grp_ent)	next;	/* next entry in bucket */
};

/* Hash table bucket declaration */
SLIST_HEAD(ng_bridge_grp_bucket, ng_bridge_grp_ent);
#endif

/* Netgraph node methods */
static ng_constructor_t	ng_bridge_constructor;
static ng_rcvmsg_t	ng_bridge_rcvmsg;
static ng_shutdown_t	ng_bridge_rmnode;
static ng_newhook_t	ng_bridge_newhook;
static ng_rcvdata_t	ng_bridge_rcvdata;
static ng_disconnect_t	ng_bridge_disconnect;
#ifdef __LinuxKernelVNB__
static ng_dumpnode_t    ng_bridge_dumpnode;
#else
static ng_restorenode_t ng_bridge_restorenode;
#endif

struct ng_bridge_nl_nodepriv {
	u_int32_t numHosts;
	struct ng_bridge_static_host hosts[];
};

/* Other internal functions */
static int	ng_bridge_put(priv_p priv, const u_char *addr, int linkNum, int dynamic);
static struct ng_bridge_host *ng_bridge_get(priv_p priv, const u_char *addr);
static void	__ng_bridge_rehash(priv_p priv);

/* values for argument flags */
#define ALL_ENTRIES          0
#define DYNAMIC_ENTRIES_ONLY 1
static void	ng_bridge_remove_hosts(priv_p priv, int linkNum, int flags);
/* Magic values for the host entry age */
#define NG_BRIDGE_AGE_STAT_MAGIC (0xFFFF)
#define NG_BRIDGE_AGE_DYN_MAX (0xFFFE)

/* static void	ng_bridge_rehash(priv_p priv); */
#ifdef NG_BRIDGE_TIMER
static void	ng_bridge_timeout(void *arg);
#endif
static const	char *ng_bridge_nodename(node_p node);
static void ng_bridge_remove_one_host(priv_p priv, const u_int8_t *addr);

#ifdef NG_BRIDGE_SNOOP
/* Other internal functions, dedicated to group management */
static struct ng_bridge_group *ng_bridge_grp_get(priv_p priv,
                                                 const u_char *addr);
static int	ng_bridge_grp_put(priv_p priv, const struct ng_bridge_group *bgrp);
static int	ng_bridge_grp_del(priv_p priv, const struct ng_bridge_group *bgrp);
static void	ng_bridge_remove_groups(priv_p priv, int);
/* Snooping configuration method */
static int	ng_bridge_snoop_cfg(node_p node, struct ng_mesg *msg,
				const char *retaddr, struct ng_mesg **rptr);
#endif

/* Store each hook's link number in the private field */
typedef union {
	void *s;
	uint16_t linknum;
} hookpriv_p;
#define LINK_NUM(hook)		((hookpriv_p)hook->private).linknum

/* Minimum and maximum number of hash buckets. Must be a power of two. */
#define MIN_BUCKETS		(1 << 5)	/* 32 */
#define MAX_BUCKETS		(1 << 14)	/* 16384 */

/* Configuration default values */
#define DEFAULT_LOOP_TIMEOUT	60
#define DEFAULT_MAX_STALENESS	(15 * 60)	/* same as ARP timeout */
#define DEFAULT_MIN_STABLE_AGE	1

/******************************************************************
		    NETGRAPH PARSE TYPES
******************************************************************/

/*
 * How to determine the length of the table returned by NGM_BRIDGE_GET_TABLE
 */
static int
ng_bridge_getTableLength(const struct ng_parse_type *type,
	const u_char *start, const u_char *buf)
{
	const struct ng_bridge_host_ary *const hary
	    = (const struct ng_bridge_host_ary *)(buf - sizeof(u_int32_t));

	return hary->numHosts;
}

/* Parse type for struct ng_bridge_host_ary */
static const struct ng_parse_struct_field ng_bridge_host_type_fields[]
	= NG_BRIDGE_HOST_TYPE_INFO(&ng_ether_enaddr_type);
static const struct ng_parse_type ng_bridge_host_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_bridge_host_type_fields
};
static const struct ng_parse_array_info ng_bridge_hary_type_info = {
	.elementType = &ng_bridge_host_type,
	.getLength = ng_bridge_getTableLength
};
static const struct ng_parse_type ng_bridge_hary_type = {
	.supertype = &ng_parse_array_type,
	.info = &ng_bridge_hary_type_info
};
static const struct ng_parse_struct_field ng_bridge_host_ary_type_fields[]
	= NG_BRIDGE_HOST_ARY_TYPE_INFO(&ng_bridge_hary_type);
static const struct ng_parse_type ng_bridge_host_ary_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_bridge_host_ary_type_fields
};

/* Parse type for struct ng_bridge_config */
#ifdef NG_BRIDGE_IPFW
static const struct ng_parse_fixedarray_info ng_bridge_ipfwary_type_info = {
	.elementType = &ng_parse_uint8_type,
	.length = NG_BRIDGE_MAX_LINKS
};
static const struct ng_parse_type ng_bridge_ipfwary_type = {
	.supertype = &ng_parse_fixedarray_type,
	.info  = &ng_bridge_ipfwary_type_info
};
static const struct ng_parse_struct_field ng_bridge_config_type_fields[]
	= NG_BRIDGE_CONFIG_TYPE_INFO(&ng_bridge_ipfwary_type);
#else
static const struct ng_parse_struct_field ng_bridge_config_type_fields[]
	= NG_BRIDGE_CONFIG_TYPE_INFO;
#endif
static const struct ng_parse_type ng_bridge_config_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_bridge_config_type_fields
};

#ifdef NG_BRIDGE_STATS
/* Parse type for struct ng_bridge_link_stat */
static const struct ng_parse_struct_field ng_bridge_stats_type_fields[]
	= NG_BRIDGE_STATS_TYPE_INFO;
static const struct ng_parse_type ng_bridge_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_bridge_stats_type_fields
};
#endif
#ifdef NG_BRIDGE_SNOOP
/* Parse type for struct ng_bridge_snoop_msg */
static const struct ng_parse_struct_field ng_bridge_snoop_msg_type_fields[]
	= NG_BRIDGE_SNOOP_MSG_TYPE_INFO;
static const struct ng_parse_type ng_bridge_snoop_msg_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_bridge_snoop_msg_type_fields
};
#endif

/* Parse type for struct ng_bridge_static_host (add and del host) */
static const struct ng_parse_struct_field ng_bridge_static_host_type_fields[]
       = NG_BRIDGE_STATIC_HOST_TYPE_INFO(&ng_ether_enaddr_type);
static const struct ng_parse_type ng_bridge_static_host_type = {
       .supertype = &ng_parse_struct_type,
       .info = &ng_bridge_static_host_type_fields
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_bridge_cmdlist[] = {
	{
	  NGM_BRIDGE_COOKIE,
	  NGM_BRIDGE_SET_CONFIG,
	  "setconfig",
	  &ng_bridge_config_type,
	  NULL
	},
	{
	  NGM_BRIDGE_COOKIE,
	  NGM_BRIDGE_GET_CONFIG,
	  "getconfig",
	  NULL,
	  &ng_bridge_config_type
	},
	{
	  NGM_BRIDGE_COOKIE,
	  NGM_BRIDGE_RESET,
	  "reset",
	  NULL,
	  NULL
	},
#ifdef NG_BRIDGE_STATS
	{
	  NGM_BRIDGE_COOKIE,
	  NGM_BRIDGE_GET_STATS,
	  "getstats",
	  &ng_parse_uint32_type,
	  &ng_bridge_stats_type
	},
	{
	  NGM_BRIDGE_COOKIE,
	  NGM_BRIDGE_CLR_STATS,
	  "clrstats",
	  &ng_parse_uint32_type,
	  NULL
	},
	{
	  NGM_BRIDGE_COOKIE,
	  NGM_BRIDGE_GETCLR_STATS,
	  "getclrstats",
	  &ng_parse_uint32_type,
	  &ng_bridge_stats_type
	},
#endif
	{
	  NGM_BRIDGE_COOKIE,
	  NGM_BRIDGE_GET_TABLE,
	  "gettable",
	  NULL,
	  &ng_bridge_host_ary_type
	},
	{
	 NGM_BRIDGE_COOKIE,
	 NGM_BRIDGE_ADD_HOST,
	 "addhost",
	 &ng_bridge_static_host_type,
	 NULL,
	},
	{
	 NGM_BRIDGE_COOKIE,
	 NGM_BRIDGE_DEL_HOST,
	 "delhost",
	 &ng_bridge_static_host_type,
	 NULL,
	},
#ifdef NG_BRIDGE_SNOOP
	{
	  NGM_BRIDGE_COOKIE,
	  NGM_BRIDGE_SET_SNOOP_CONFIG,
	  "setsnoopconfig",
	  &ng_bridge_snoop_msg_type,
	  NULL,
	},
	{
	  NGM_BRIDGE_COOKIE,
	  NGM_BRIDGE_GET_SNOOP_CONFIG,
	  "getsnoopconfig",
	  NULL,
	  &ng_bridge_snoop_msg_type,
	},
#endif
	{ 0, 0, NULL, NULL, NULL }
};

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_bridge_typestruct) = {
	.version = NG_VERSION,
	.name = NG_BRIDGE_NODE_TYPE,
	.mod_event = NULL,
	.constructor = ng_bridge_constructor,
	.rcvmsg = ng_bridge_rcvmsg,
	.shutdown = ng_bridge_rmnode,
	.newhook = ng_bridge_newhook,
	.findhook = NULL,
	.connect = NULL,
	.afterconnect = NULL,
	.rcvdata = ng_bridge_rcvdata,
	.rcvdataq = ng_bridge_rcvdata,
	.disconnect = ng_bridge_disconnect,
	.rcvexception = NULL,
#ifdef __LinuxKernelVNB__
	.dumpnode = ng_bridge_dumpnode,
#else
	.dumpnode = NULL,
#endif
#ifdef __LinuxKernelVNB__
	.restorenode = NULL,
#else
	.restorenode = ng_bridge_restorenode,
#endif
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist = ng_bridge_cmdlist,
};
NETGRAPH_INIT(bridge, &ng_bridge_typestruct);
NETGRAPH_EXIT(bridge, &ng_bridge_typestruct);

/******************************************************************
		    NETGRAPH NODE METHODS
******************************************************************/

/*
 * Node constructor
 */
static int
ng_bridge_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int error;

	/* Allocate and initialize private info */
	priv = ng_malloc(sizeof(*priv), M_NOWAIT);
	if (priv == NULL)
		return (ENOMEM);
	bzero(priv, sizeof(*priv));

	vnb_spinlock_init(&priv->spinlock);

#ifdef NG_BRIDGE_TIMER
	ng_callout_init(&priv->timer);
#endif
	/* Allocate and initialize hash table, etc. */
	priv->tab = ng_malloc(MIN_BUCKETS * sizeof(*priv->tab), M_NOWAIT);
	if (priv->tab == NULL) {
		ng_free(priv);
		return (ENOMEM);
	}
	bzero(priv->tab, MIN_BUCKETS * sizeof(*priv->tab));  /* init SLIST's */
	priv->numBuckets = MIN_BUCKETS;
	priv->hashMask = MIN_BUCKETS - 1;

#ifdef NG_BRIDGE_SNOOP
	priv->gtab = ng_malloc(MIN_BUCKETS * sizeof(*priv->gtab), M_NOWAIT);
	if (priv->gtab == NULL) {
		ng_free(priv->tab);
		ng_free(priv);
		return (ENOMEM);
	}
	bzero(priv->gtab, MIN_BUCKETS * sizeof(*priv->gtab));  /* init SLIST's */
	priv->num_grpBuckets = MIN_BUCKETS;
	priv->hash_grpMask = MIN_BUCKETS - 1;

	bzero(&priv->no_port, sizeof(priv->no_port));
	memset(&priv->all_ports, 0xff, sizeof(priv->all_ports));
#endif
	priv->conf.debugLevel = 1;
	priv->conf.loopTimeout = DEFAULT_LOOP_TIMEOUT;
	priv->conf.maxStaleness = DEFAULT_MAX_STALENESS;
	priv->conf.minStableAge = DEFAULT_MIN_STABLE_AGE;


	/* Call superclass constructor */
	if ((error = ng_make_node_common(&ng_bridge_typestruct, nodep, nodeid))) {
		ng_free(priv->tab);
#ifdef NG_BRIDGE_SNOOP
		ng_free(priv->gtab);
#endif
		ng_free(priv);
		return (error);
	}
	(*nodep)->private = priv;
	priv->node = *nodep;

#ifdef NG_BRIDGE_TIMER
	/* Start timer; timer is always running while node is alive */
	ng_callout_reset(&priv->timer, hz, ng_bridge_timeout, priv->node);
#endif

	/* Done */
	return (0);
}

/*
 * Method for attaching a new hook
 */
static	int
ng_bridge_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = node->private;

	/* Check for a link hook */
	if (strncmp(name, NG_BRIDGE_HOOK_LINK_PREFIX,
	    strlen(NG_BRIDGE_HOOK_LINK_PREFIX)) == 0) {
		const char *cp;
		char *eptr;
		hookpriv_p hpriv;
		u_int16_t linkNum;


		cp = name + strlen(NG_BRIDGE_HOOK_LINK_PREFIX);
		if (!isdigit(*cp) || (cp[0] == '0' && cp[1] != '\0'))
			return (EINVAL);
		linkNum = strtoul(cp, &eptr, 10);
		if (*eptr != '\0' || linkNum >= NG_BRIDGE_MAX_LINKS)
			return (EINVAL);
		if (priv->links[linkNum] != NULL)
			return (EISCONN);
		priv->links[linkNum] = ng_malloc(sizeof(*priv->links[linkNum]),
						 M_NOWAIT);
		if (priv->links[linkNum] == NULL)
			return (ENOMEM);
		bzero(priv->links[linkNum], sizeof(*priv->links[linkNum]));
		priv->links[linkNum]->hook = hook;
		hpriv.linknum = linkNum;
		NG_HOOK_SET_PRIVATE(hook, hpriv.s);
		priv->numLinks++;

#ifdef NG_BRIDGE_SNOOP
		/* Send notification message to snoop daemon */
		if (priv->snoop_hook != NULL) {
			struct ng_mesg *msg = NULL;
			struct ng_bridge_snoop_msg* nbsm = NULL;

			NG_MKMESSAGE(msg, NGM_BRIDGE_COOKIE,
				NGM_BRIDGE_NOTIFY_SNOOPD,
				sizeof(struct ng_bridge_snoop_msg),	M_NOWAIT);
			if (msg == NULL)
				return(ENOMEM);

			/* Append snoop message */
			nbsm = (struct ng_bridge_snoop_msg *)msg->data;
			nbsm->nbs_cmd = RECV_ADDED_PORT_INDEX;
			nbsm->nbs_port = (u_int8_t)linkNum;
			nbsm->nbs_len = (u_int16_t)0;

			ng_send_msg(node, msg, NG_HOOK_NAME(priv->snoop_hook), NULL, NULL);
		}
#endif
		return (0);
	}

#ifdef NG_BRIDGE_SNOOP
	if (strcmp(name, NG_BRIDGE_SNOOP_HOOK) == 0) {
		if (priv->snoop_hook != NULL)
			return (EISCONN);
		priv->snoop_hook = hook;

		return (0);
	}
#endif
	/* Unknown hook name */
	return (EINVAL);
}

/*
 * Receive a control message
 */
static int
ng_bridge_rcvmsg(node_p node, struct ng_mesg *msg,
	const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const priv_p priv = node->private;
	struct ng_mesg *resp = NULL;
	int error = 0;

	switch (msg->header.typecookie) {
	case NGM_BRIDGE_COOKIE:
		switch (msg->header.cmd) {
		case NGM_BRIDGE_GET_CONFIG:
		    {
			struct ng_bridge_config *conf;

			NG_MKRESPONSE(resp, msg,
			    sizeof(struct ng_bridge_config), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			conf = (struct ng_bridge_config *)resp->data;
			*conf = priv->conf;	/* no sanity checking needed */
			break;
		    }
		case NGM_BRIDGE_SET_CONFIG:
		    {
			struct ng_bridge_config *conf;
#ifdef NG_BRIDGE_IPFW
			int i;
#endif

			if (msg->header.arglen
			    != sizeof(struct ng_bridge_config)) {
				error = EINVAL;
				break;
			}
			conf = (struct ng_bridge_config *)msg->data;
			priv->conf = *conf;
#ifdef NG_BRIDGE_IPFW
			for (i = 0; i < NG_BRIDGE_MAX_LINKS; i++)
				priv->conf.ipfw[i] = !!priv->conf.ipfw[i];
#endif
			break;
		    }
		case NGM_BRIDGE_RESET:
		    {
			int i;

			/* Flush all entries in the hash table, even
			 * the static ones */
			ng_bridge_remove_hosts(priv, -1, ALL_ENTRIES);

			/* Reset all loop detection counters and stats */
			for (i = 0; i < NG_BRIDGE_MAX_LINKS; i++) {
				if (priv->links[i] == NULL)
					continue;
				priv->links[i]->loopCount = 0;
#ifdef NG_BRIDGE_STATS
				bzero(&priv->links[i]->stats,
				    sizeof(priv->links[i]->stats));
#endif
			}
			break;
		    }
#ifdef NG_BRIDGE_STATS
		case NGM_BRIDGE_GET_STATS:
		case NGM_BRIDGE_CLR_STATS:
		case NGM_BRIDGE_GETCLR_STATS:
		    {
			struct ng_bridge_link *link;
			int linkNum;

			/* Get link number */
			if (msg->header.arglen != sizeof(u_int32_t)) {
				error = EINVAL;
				break;
			}
			linkNum = *((u_int32_t *)msg->data);
			if (linkNum < 0 || linkNum >= NG_BRIDGE_MAX_LINKS) {
				error = EINVAL;
				break;
			}
			if ((link = priv->links[linkNum]) == NULL) {
				error = ENOTCONN;
				break;
			}

			/* Get/clear stats */
			if (msg->header.cmd != NGM_BRIDGE_CLR_STATS) {
				NG_MKRESPONSE(resp, msg,
				    sizeof(link->stats), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				bcopy(&link->stats,
				    resp->data, sizeof(link->stats));
			}
			if (msg->header.cmd != NGM_BRIDGE_GET_STATS)
				bzero(&link->stats, sizeof(link->stats));
			break;
		    }
#endif
		case NGM_BRIDGE_GET_TABLE:
		    {
			struct ng_bridge_host_ary *ary;
			struct ng_bridge_hent *hent;
			int i = 0;
			u_int mybucket;

			NG_MKRESPONSE(resp, msg, sizeof(*ary)
			    + ((priv->numSHosts + priv->numDHosts) * sizeof(*ary->hosts)), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			ary = (struct ng_bridge_host_ary *)resp->data;
			ary->numHosts = priv->numSHosts + priv->numDHosts;
			vnb_spinlock_lock(&priv->spinlock);
			for (mybucket = 0; mybucket < priv->numBuckets; mybucket++) {
				SLIST_FOREACH(hent, &priv->tab[mybucket], next)
					ary->hosts[i++] = hent->host;
			}
			vnb_spinlock_unlock(&priv->spinlock);
			break;
		    }
		case NGM_BRIDGE_ADD_HOST:
		    {
			struct ng_bridge_static_host *h;
			struct ng_bridge_host *hent;
			if (msg->header.arglen
			    != sizeof(struct ng_bridge_static_host)) {
				error = EINVAL;
				break;
			}
			h = (struct ng_bridge_static_host *)msg->data;
			hent = ng_bridge_get(priv, h->addr);
			if (hent != NULL ) {
				/* there is a static entry already */
				if (hent->age == NG_BRIDGE_AGE_STAT_MAGIC) {
					error = EEXIST;
					break;
				}
				/* erase the dynamic entry */
				else {
					ng_bridge_remove_one_host(priv, h->addr);
				}
			}
			if (!ng_bridge_put(priv, h->addr, h->linkNum, 0)) {
				error = ENOMEM;
				break;
			}
			break;
		    }
		case NGM_BRIDGE_DEL_HOST:
		    {
			struct ng_bridge_static_host *h;
			if (msg->header.arglen
			    != sizeof(struct ng_bridge_static_host)) {
				error = EINVAL;
				break;
			}
			h = (struct ng_bridge_static_host *)msg->data;
			if (ng_bridge_get(priv, h->addr) == NULL) {
				error = ENOENT;
				break;
			}

			ng_bridge_remove_one_host(priv, h->addr);
			break;
		    }
#ifdef NG_BRIDGE_SNOOP
		case NGM_BRIDGE_SET_SNOOP_CONFIG:
		case NGM_BRIDGE_GET_SNOOP_CONFIG:
			error = ng_bridge_snoop_cfg(node, msg, retaddr, &resp);
			break;
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

	/* Done */
	if (rptr)
		*rptr = resp;
	else if (resp != NULL)
		FREE(resp, M_NETGRAPH);
	FREE(msg, M_NETGRAPH);
	return (error);
}

#ifdef NG_BRIDGE_SNOOP
/*
 * Configuration/evolution of snooping part
 */
static int
ng_bridge_snoop_cfg(node_p node, struct ng_mesg *msg,
		const char *retaddr, struct ng_mesg **rptr)
{
	int err = 0;
	const priv_p priv = node->private;
	struct ng_mesg *resp = NULL;
	struct ng_bridge_snoop_msg *nbsm = NULL;

	if ((msg->header.arglen < sizeof(struct ng_bridge_snoop_msg)) ||
		((nbsm = (struct ng_bridge_snoop_msg *)msg->data) == NULL)) {
		err = EINVAL;
		goto cfg_done;
	}

	/* Validate snoop message length*/
	if (msg->header.arglen <
		(sizeof(struct ng_bridge_snoop_msg) + nbsm->nbs_len)) {
		err = EINVAL;
		goto cfg_done;
	}

	switch (nbsm->nbs_cmd) {
		case GET_NUM_PORTS:
		{
			/*
			 * The daemon expects to receiv the number
			 * of ports immediatly after connection.
			 */
			struct ng_bridge_snoop_msg* nbsr;
			NG_MKRESPONSE(resp, msg,
				sizeof(struct ng_bridge_snoop_msg), M_NOWAIT);
			if (resp == NULL) {
				err = ENOMEM;
				goto cfg_done;
			}
			/* Append snoop message at end */
			nbsr = (struct ng_bridge_snoop_msg *)resp->data;
			nbsr->nbs_cmd = RECV_NUM_PORTS;
			nbsr->nbs_port = priv->numLinks;
			nbsr->nbs_len = 0;
			break;
		 }
		case START_MLD_SNOOPING:
			priv->snoop_mode |= MLD_SNOOP;
			break;
		case START_IGMP_SNOOPING:
			priv->snoop_mode |= IGMP_SNOOP;
			break;
		case STOP_MLD_SNOOPING:
			priv->snoop_mode &= ~MLD_SNOOP;
			ng_bridge_remove_groups(priv, AF_INET6);
			bzero (&priv->mld_routers, sizeof(priv->mld_routers));
			break;
		case STOP_IGMP_SNOOPING:
			priv->snoop_mode &= ~IGMP_SNOOP;
			ng_bridge_remove_groups(priv, AF_INET);
			bzero (&priv->igmp_routers, sizeof(priv->igmp_routers));
			break;
		case ADD_L2_GROUP:
		case DEL_L2_GROUP:
		{
			struct ng_bridge_group *nbg;

			nbg = (struct ng_bridge_group *)(nbsm + 1);
			if (nbsm->nbs_cmd == ADD_L2_GROUP)
				err = ng_bridge_grp_put (priv, nbg);
			else
				err = ng_bridge_grp_del (priv, nbg);
			break;
		}
		case DEL_ALL_L2_GROUP:
			ng_bridge_remove_groups(priv, 0);
			break;
		case SET_MLD_ROUTERS:
		case SET_IGMP_ROUTERS:
		case SET_SPY_PORTS:
		{
			port_set *dst = NULL;
			port_set *src = NULL;

			src = (port_set *)(nbsm + 1);
			if (nbsm->nbs_cmd == SET_MLD_ROUTERS)
				dst = &priv->mld_routers;
			else if (nbsm->nbs_cmd == SET_IGMP_ROUTERS)
				dst = &priv->igmp_routers;
			else {
				int i;
				dst = &priv->spy_ports;
				priv->nb_spy=0;
				for (i=0; i<MAX_PORTS ; i++) {
					if PORT_ISSET(i, src)
						priv->nb_spy++;
				}
			}
			bcopy (src, dst, sizeof (port_set));
			break;
		}
		default:
			err = EINVAL;
			break;
	}

cfg_done:
	/* Done */
	if (rptr)
		*rptr = resp;
	return (err);
}
#endif

static inline unsigned HASH(const void *addr, unsigned mask)
{
	return ( (((const u_int16_t *)(addr))[0]
		  ^ ((const u_int16_t *)(addr))[1]
		  ^ ((const u_int16_t *)(addr))[2]) & (mask) );
}

#define NETHSEXT(mac) \
((unsigned char *)&mac)[0], \
	((unsigned char *)&mac)[1], \
	((unsigned char *)&mac)[2], \
	((unsigned char *)&mac)[3], \
	((unsigned char *)&mac)[4], \
	((unsigned char *)&mac)[5]

/*
 * Find a host entry in the table.
 */
static struct ng_bridge_host *
ng_bridge_get(priv_p priv, const u_char *addr)
{
	const int bucket = HASH(addr, priv->hashMask);
	struct ng_bridge_hent *hent;

	vnb_spinlock_lock(&priv->spinlock);
	SLIST_FOREACH(hent, &priv->tab[bucket], next) {
		if (vnb_ether_equal(hent->host.addr, addr)) {
			vnb_spinlock_unlock(&priv->spinlock);
			return (&hent->host);
		}
	}
	vnb_spinlock_unlock(&priv->spinlock);
	return (NULL);
}
/*
 * Add a new host entry to the table. This assumes the host doesn't
 * already exist in the table. Returns 1 on success, 0 if there
 * was a memory allocation failure.
 */
static int
ng_bridge_put(priv_p priv, const u_char *addr, int linkNum, int dynamic)
{
	const int mybucket = HASH(addr, priv->hashMask);
	struct ng_bridge_hent *hent;

#ifdef CONFIG_VNB_ETHERBRIDGE_HASHTABLE_CHECKS
	/* Assert that entry does not already exist in hashtable */
	vnb_spinlock_lock(&priv->spinlock);
	SLIST_FOREACH(hent, &priv->tab[mybucket], next) {
		NG_KASSERT(!vnb_ether_equal(hent->host.addr, addr),
		    ("%s: entry %6D exists in table", __FUNCTION__, addr, ":"));
	}
	vnb_spinlock_unlock(&priv->spinlock);
#endif

	/* Allocate and initialize new hashtable entry */
	hent = (struct ng_bridge_hent *) ng_malloc(sizeof(*hent), M_NOWAIT);
	if (hent == NULL)
		return (0);
	bcopy(addr, hent->host.addr, VNB_ETHER_ADDR_LEN);
	hent->host.linkNum = linkNum;
	hent->host.staleness = 0;
	if (dynamic) {
              hent->host.age = 0;
              priv->numDHosts++;
	}
	else {
              hent->host.age = NG_BRIDGE_AGE_STAT_MAGIC;
              priv->numSHosts++;
	}

	/* Add new element to hash bucket */
	vnb_spinlock_lock(&priv->spinlock);
	SLIST_INSERT_HEAD(&priv->tab[mybucket], hent, next);

	/* Resize table if necessary */
	__ng_bridge_rehash(priv);
	vnb_spinlock_unlock(&priv->spinlock);
	return (1);
}

extern void dumphex(const unsigned char *data, unsigned int len);
/*
 * Receive data on a hook
 */
static int
ng_bridge_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
#if NG_BRIDGE_LOG_DEBUG
	const node_p node = hook->node;
#endif
	priv_p priv = hook->node_private;
	struct ng_bridge_host *host;
	struct ng_bridge_link *link;
	struct vnb_ether_header *eh;
	int error = 0;
	u_int linkNum;
#ifdef NG_BRIDGE_FLOOD
	u_int linksSeen;
	struct ng_bridge_link *firstLink;
#endif
	int manycast;
#ifdef NG_BRIDGE_SNOOP
	port_set *oifs = NULL;
	port_set r_oifs;
#endif
#if NG_BRIDGE_LOG_DEBUG
	if (!node) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}
#endif
	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}
	/* Get link number */
	linkNum = LINK_NUM(hook);

	NG_KASSERT(linkNum < NG_BRIDGE_MAX_LINKS,
	    ("%s: linkNum=%u", __FUNCTION__, linkNum));
	link = priv->links[linkNum];
	if (link == NULL) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	/* Sanity check packet and pull up header */
	if (unlikely(MBUF_LENGTH(m) < VNB_ETHER_HDR_LEN)) {
#ifdef NG_BRIDGE_STATS
		link->stats.recvRunts++;
#endif
		NG_FREE_DATA(m, meta);
		return (EINVAL);
	}
#if defined(__LinuxKernelVNB__)
	if (!pskb_may_pull(m, VNB_ETHER_HDR_LEN)) {
		kfree_skb(m);
		m = NULL;
#ifdef NG_BRIDGE_STATS
		link->stats.memoryFailures++;
#endif
		NG_FREE_META(meta);
		VNB_TRAP();
		return (ENOBUFS);
	}
#endif
	eh = mtod(m, struct vnb_ether_header *);
	if (unlikely((eh->ether_shost[0] & 1) != 0)) {
#ifdef NG_BRIDGE_STATS
		link->stats.recvInvalid++;
#endif
		NG_FREE_DATA(m, meta);
		return (EINVAL);
	}

	/* Is link disabled due to a loopback condition? */
	if (unlikely(link->loopCount != 0)) {
#ifdef NG_BRIDGE_STATS
		link->stats.loopDrops++;
#endif
		NG_FREE_DATA(m, meta);
		return (ELOOP);		/* XXX is this an appropriate error? */
	}

#ifdef NG_BRIDGE_STATS
	/* Update stats */
	link->stats.recvPackets++;
	link->stats.recvOctets += MBUF_LENGTH(m);
#endif

	if ((manycast = (eh->ether_dhost[0] & 1)) != 0) {
		if (vnb_is_bcast(m)) {
#ifdef NG_BRIDGE_STATS
			link->stats.recvBroadcasts++;
#endif
			manycast = 2;
		} else {
#ifdef NG_BRIDGE_STATS
			link->stats.recvMulticasts++;
#endif
		}
	}

	/* Look up packet's source Ethernet address in hashtable */
	if (likely((host = ng_bridge_get(priv, eh->ether_shost)) != NULL)) {

		/* Update time since last heard from this host */
		if (unlikely(host->staleness))
			host->staleness = 0;

		/* Did host jump to a different link? */
		if (unlikely(host->linkNum != linkNum)) {

			/*
			 * If the host's old link was recently established
			 * on the old link and it's already jumped to a new
			 * link, declare a loopback condition.
			 * We allow VRRP sources to be more volatile.
			 */
			if ((host->age < priv->conf.minStableAge) &&
			    !vnb_is_vrrp(eh->ether_shost) ) {

				/* Log the problem */
				if (priv->conf.debugLevel >= 2) {
#if defined(__LinuxKernelVNB__)
					struct ifnet *ifp = m->dev;
#endif
					char suffix[32];

#if defined(__LinuxKernelVNB__)
					if (ifp != NULL)
						snprintf(suffix, sizeof(suffix),
						    " (%s)", ifp->name
						);
					else
#endif
						*suffix = '\0';
#if NG_BRIDGE_LOG_DEBUG
					log(LOG_WARNING, "ng_bridge: %s:"
					    " loopback detected on %s%s\n",
					    ng_bridge_nodename(node),
					    hook->name, suffix);
#endif
				}

				/* Mark link as linka non grata */
				link->loopCount = priv->conf.loopTimeout;
#ifdef NG_BRIDGE_STATS
				link->stats.loopDetects++;
#endif

				/* Forget all dynamic hosts on this link */
				ng_bridge_remove_hosts(priv, linkNum, DYNAMIC_ENTRIES_ONLY);

				/* Drop packet */
#ifdef NG_BRIDGE_STATS
				link->stats.loopDrops++;
#endif
				NG_FREE_DATA(m, meta);
				return (ELOOP);		/* XXX appropriate? */
			}

			/* Move host over to new link */
			host->linkNum = linkNum;
			host->age = 0;
		}
	} else {
		if (!ng_bridge_put(priv, eh->ether_shost, linkNum, 1)) {
#ifdef NG_BRIDGE_STATS
			link->stats.memoryFailures++;
#endif
			NG_FREE_DATA(m, meta);
			return (ENOMEM);
		}
	}

#ifdef NG_BRIDGE_IPFW
	/* Run packet through ipfw processing, if enabled */
	if (priv->conf.ipfw[linkNum] && fw_enable && ip_fw_chk_ptr != NULL) {
		/* XXX not implemented yet */
	}
#endif

	/*
	 * If unicast and destination host known, deliver to host's link,
	 * unless it is the same link as the packet came in on.
	 */
	if (likely(!manycast)) {

		/* Determine packet destination link */
		if (likely((host = ng_bridge_get(priv, eh->ether_dhost)) != NULL)) {
			struct ng_bridge_link *const destLink
			    = priv->links[host->linkNum];

#ifdef NG_BRIDGE_SNOOP
			/*
			 * If at least ONE port is in spy mode,
			 * even unicats can tunr into manycast
			 */
			if (priv->nb_spy) {
				r_oifs = priv->no_port;
				oifs = &r_oifs;
				PORT_SET (host->linkNum, oifs);
				goto do_manycast;
			}
#endif

			NG_KASSERT(destLink != NULL,
			    ("%s: link%d null", __FUNCTION__, host->linkNum));

			/* Deliver packet out the destination link */
			if (likely(destLink != link)) {
#ifdef NG_BRIDGE_STATS
				destLink->stats.xmitPackets++;
				destLink->stats.xmitOctets += MBUF_LENGTH(m);
#endif
				NG_SEND_DATA(error, destLink->hook, m, meta);
				return (error);
			}

			/* If destination same as incoming link, do nothing
			   Be permissive with VRRP packets. */
			if (!vnb_is_vrrp(eh->ether_dhost)) {
				NG_FREE_DATA(m, meta);
				return (0);
			}
		}

		/* Destination host is not known */
#ifdef NG_BRIDGE_STATS
		link->stats.recvUnknown++;
#endif
	}
#ifdef NG_BRIDGE_SNOOP
	else {
		/*
		 *  MLD/mcast-v6 processing
		 *   (0) if MLD snooping is activated, then
		 *   (1) recognize IPv6 mcast packets
		 *   (2) recognize MLD/MRD packets,
		 *      2-a  they MUST be copied to the snooping daemon
		 *      2-b  MLD Reports are to be sent only to "Router" ports
		 *   (3) to help snooping daemon build "Router Ports" list
		 *      3-a copy the RA (not that sure ...)
		 *      3-b copy any PIM message
		 *   (4) else force broadcast for link-local mcast (ffX2::)
		 *   (5) else All others :
		 *      5-a  forward accordingly to fw entry found
		 *      5-b  if no entry found, forward it to
		 *             + either to the "Router" ports
		 *             + either to All Ports (i.e. broadcast)
		 *
		 *  IGMP/mcast-v4 processing is similar
		 *
		 *  The entry list creation/maintenance, as well as the "Router"
		 *  port list or the default behaviour is managed by the snooping
		 *  daemon.
		 */
		if ((priv->snoop_mode & MLD_SNOOP) &&
		    IS_ETH_MCAST6 (eh->ether_dhost)) {
			u_int8_t feed_daemon = 0;
			u_char *packet;
			struct ip6_hdr *ip6;

			/*
			 * Just be sure to have at least a full IPv6 header
			 */
#if defined(__LinuxKernelVNB__)
			if (!pskb_may_pull(m, (VNB_ETHER_HDR_LEN + sizeof(struct ip6_hdr)))) {
#ifdef NG_BRIDGE_STATS
				link->stats.memoryFailures++;
#endif
				kfree_skb(m);
				m = NULL;
				NG_FREE_META(meta);
				VNB_TRAP();
				return (ENOBUFS);
			}
#else
			if (MBUF_LENGTH(m) < (VNB_ETHER_HDR_LEN + sizeof(struct ip6_hdr))) {
#ifdef NG_BRIDGE_STATS
				link->stats.memoryFailures++;
#endif
				m_freem(m);
				NG_FREE_META(meta);
				return (ENOBUFS);
			}
#endif
			packet = mtod (m, u_char *) + VNB_ETHER_HDR_LEN;
			ip6 = (struct ip6_hdr*)packet;

			/*
			 * In the following, just pick the minimal values to perform
			 * tests sucha as LL mcast. With pure bytes handling, we don't
			 * have to care about packet being correclty aligned or not
			 */

			/*
			 * MLD messages MUST begin with a Hop-by-Hop ext header
			 * immediatly followed by ICMPv6 header
			 */
			if (ip6->ip6_nxt == IPPROTO_HOPOPTS) {
				u_int8_t next = 0;
				u_int8_t hop_len = 0;
				unsigned int offset = sizeof (struct ip6_hdr) + VNB_ETHER_HDR_LEN + 1;

				if (MBUF_LENGTH(m) >= offset) {
					m_copydata (m, offset-1, 1, &next);
					m_copydata (m, offset, 1, &hop_len);
				}
				if (next == IPPROTO_ICMPV6) {
					u_int8_t type = 0;

					offset += 8* (hop_len + 1);
					if (MBUF_LENGTH(m) >= offset)
						m_copydata (m, offset-1, 1, &type);
/*
 * Until it is properly defined
 */
#ifndef ICMP6_MEMBERSHIP_REPORT_V2
#	define ICMP6_MEMBERSHIP_REPORT_V2   143
#endif
					if ((type == ICMP6_MEMBERSHIP_QUERY) ||
					    (type == ICMP6_MEMBERSHIP_REPORT) ||
					    (type == ICMP6_MEMBERSHIP_REDUCTION) ||
					    (type == ICMP6_MEMBERSHIP_REPORT_V2)) {

						feed_daemon = RECV_MLD_MSG;
						if ((type == ICMP6_MEMBERSHIP_REPORT) ||
						    (type == ICMP6_MEMBERSHIP_REPORT_V2))
							r_oifs = priv->mld_routers;
						else
							r_oifs = priv->all_ports;
						oifs = &r_oifs;
					}
				}
			}
			else if (ip6->ip6_nxt == IPPROTO_PIM)
				feed_daemon = RECV_PIM6_MSG;

			if (feed_daemon) {
				struct ng_bridge_snoop_msg* msg;
				struct mbuf *md;
				meta_p metad = NULL;
				md = m_dup(m, M_NOWAIT);
				if (md == NULL) {
#ifdef NG_BRIDGE_STATS
					link->stats.memoryFailures++;
#endif
					NG_FREE_DATA(m, meta);
					return (ENOBUFS);
				}
				/*
				 * Give only the IPv6 packet to the daemon
				 */
				m_adj (md, VNB_ETHER_HDR_LEN);
				M_PREPEND (md,
				           sizeof (struct ng_bridge_snoop_msg),
				           M_DONTWAIT);
				msg = mtod (md, struct ng_bridge_snoop_msg *);
				msg->nbs_cmd = feed_daemon;
				msg->nbs_port = (u_int8_t)linkNum;
				NG_SEND_DATA(error, priv->snoop_hook, md, metad);
			}

			/*
			 * At this stage oifs only set by MLD report detection
			 * for further use, keeping it to NULL means broadcast
			 * mcast link local : dst_addr = ffx2::...
			 */
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
			if (!oifs && !VNB_IN6_IS_ADDR_MC_LINKLOCAL(&ip6->ip6_dst)) {
				struct ng_bridge_group *bg;
				port_set *loifs;
				bg = ng_bridge_grp_get (priv, eh->ether_dhost);
				/*
				 * No special case here, pure forwarding accordingly
				 * to dst group. No entry means nobody interested
				 */
				if (bg)
					loifs = &bg->oifs;
				else
					loifs = &priv->no_port;
				PORT_OR (&r_oifs, loifs, &priv->mld_routers);
				oifs = &r_oifs;
			}
#endif
		} else if ((priv->snoop_mode & IGMP_SNOOP) && IS_ETH_MCAST4 (eh->ether_dhost)
			) {
		/*
		 *  IGMP/mcast-v4 processing
		 *   (0) if IGMP snooping is activated, then
		 *   (1) recognize IPv4 mcast packets
		 *   (2) recognize IGMP/MRD packets,
		 *      2-a  they MUST be copied to the snooping daemon
		 *      2-b  IGMP Reports are to be sent only to "Router" ports
		 *   (3) to help snooping daemon build "Router Ports" list
		 *      3-a copy the RA (not that sure ...)
		 *      3-b copy any PIM message
		 *   [(4) else force broadcast for link-local mcast (?????)]
		 *   (5) else All others :
		 *      5-a  forward accordingly to fw entry found
		 *      5-b  if no entry found, forward it to
		 *             + either to the "Router" ports
		 *             + either to All Ports (i.e. broadcast)
		 *
		 *  The entry list creation/maintenance, as well as the "Router"
		 */
			u_int8_t feed_daemon = 0;
			u_char *packet;
			struct iphdr *ip;

			/*
			 * Just be sure to have at least a full IPv4 header
			 */
#if defined(__LinuxKernelVNB__)
			if (!pskb_may_pull(m, (VNB_ETHER_HDR_LEN + sizeof(struct iphdr)))) {
#ifdef NG_BRIDGE_STATS
				link->stats.memoryFailures++;
#endif
				kfree_skb(m);
				m = NULL;
				NG_FREE_META(meta);
				VNB_TRAP();
				return (ENOBUFS);
			}
#else
			if (MBUF_LENGTH(m) < (VNB_ETHER_HDR_LEN + sizeof(struct iphdr))) {
#ifdef NG_BRIDGE_STATS
				link->stats.memoryFailures++;
#endif
				m_freem(m);
				NG_FREE_META(meta);
				return (ENOBUFS);
			}
#endif
			packet = mtod (m, u_char *) + VNB_ETHER_HDR_LEN;
			ip = (struct iphdr*)packet;
			if (ip->protocol == IPPROTO_IGMP) {
				int offset = sizeof(u_int32_t)*ip->ihl + VNB_ETHER_HDR_LEN;
				u_char type;

				m_copydata (m, offset, 1, &type);
                                feed_daemon = RECV_IGMP_MSG;
                                if ((type == IGMP_HOST_MEMBERSHIP_REPORT) ||
                                    (type == IGMPV2_HOST_MEMBERSHIP_REPORT) ||
                                    (type == IGMPV3_HOST_MEMBERSHIP_REPORT))
                                         r_oifs = priv->igmp_routers;
                                else
					 r_oifs = priv->all_ports;
                                oifs = &r_oifs;

			} else if (ip->protocol == IPPROTO_PIM) {
				feed_daemon = RECV_PIM4_MSG;
			}
			if (feed_daemon) {
				struct ng_bridge_snoop_msg* msg;
				struct mbuf *md;
				meta_p metad = NULL;
				md = m_dup(m, M_NOWAIT);
				if (md == NULL) {
#ifdef NG_BRIDGE_STATS
					link->stats.memoryFailures++;
#endif
					NG_FREE_DATA(m, meta);
					return (ENOBUFS);
				}
				/*
				 * Give only IPv4 packet to the daemon
				 */
				m_adj (md, VNB_ETHER_HDR_LEN);
				M_PREPEND (md,
				           sizeof (struct ng_bridge_snoop_msg),
				           M_DONTWAIT);
				msg = mtod (md, struct ng_bridge_snoop_msg *);
				msg->nbs_cmd = feed_daemon;
				msg->nbs_port = (u_int8_t)linkNum;
				NG_SEND_DATA(error, priv->snoop_hook, md, metad);
			}

			/*
			 * At this stage oifs only set by IGMP report detection
			 * for further use, keeping it to NULL means broadcast
			 */
			if (!oifs && (ntohl(ip->daddr) > INADDR_MAX_LOCAL_GROUP)) {
				struct ng_bridge_group *bg;
				port_set *loifs;
				bg = ng_bridge_grp_get (priv, eh->ether_dhost);
				/*
				 * No special case here, pure forwarding accordingly
				 * to dst group. No entry means nobody interested
				 */
				if (bg)
					loifs = &bg->oifs;
				else
					loifs = &priv->no_port;
				PORT_OR (&r_oifs, loifs, &priv->igmp_routers);
				oifs = &r_oifs;
			}
		}
	}

do_manycast:
	if (oifs) {
		PORT_OR (oifs, oifs, &priv->spy_ports);
	}
#endif /* NG_BRIDGE_SNOOP */

#ifdef NG_BRIDGE_FLOOD
	/* Distribute unknown, multicast, broadcast pkts to all other links */
	firstLink = NULL;
	for (linkNum = linksSeen = 0; linksSeen <= priv->numLinks; linkNum++) {
		struct ng_bridge_link *destLink;
		meta_p meta2 = NULL;
		struct mbuf *m2 = NULL;

		/* We missed our valid(s) link(s), graph is being modified */
		if (linkNum >= NG_BRIDGE_MAX_LINKS) {
			NG_FREE_DATA(m, meta);
			return 0;
		}

#ifdef NG_BRIDGE_SNOOP
		/*
		 * If broadcast is "forbidden", only forward to the
		 * desired port list
		 */
		if (oifs && !PORT_ISSET(linkNum, oifs)) {
			/*
			 * This is the last link, it will not be used. So
			 * we've one extra unneeded copy, and nobody will
			 * consume m/meta
			 */
			destLink = priv->links[linkNum];
			if (destLink != NULL)
				linksSeen++;
			if (linksSeen == priv->numLinks) {
				if (firstLink == NULL) {
					NG_FREE_DATA(m, meta);
					return error;
				}
			}
			continue;
		}
#endif /* SNOOP */

		/*
		 * If we have checked all the links then now
		 * send the original on its reserved link
		 */
		if (linksSeen == priv->numLinks) {
			/* If we never saw a good link, leave. */
			if (firstLink == NULL) {
				NG_FREE_DATA(m, meta);
				return (0);
			}
			destLink = firstLink;
		} else {
			destLink = priv->links[linkNum];
			if (destLink != NULL)
				linksSeen++;
			/* Skip incoming link and disconnected links */
			if (destLink == NULL || destLink == link) {
				continue;
			}
			if (firstLink == NULL) {
				/*
				 * This is the first usable link we have found.
				 * Reserve it for the originals.
				 * If we never find another we save a copy.
				 */
				firstLink = destLink;
				continue;
			}

			/*
			 * It's usable link but not the reserved (first) one.
			 * Copy mbuf and meta info for sending.
			 */

#if defined(__FastPath__)
			m2 = m_dup(m);
#else
			m2 = m_dup(m, M_NOWAIT);	/* XXX m_copypacket() */
#endif
			if (m2 == NULL) {
#ifdef NG_BRIDGE_STATS
				link->stats.memoryFailures++;
#endif
				NG_FREE_DATA(m, meta);
				return (ENOBUFS);
			}
			if (meta != NULL
					&& (meta2 = ng_copy_meta(meta)) == NULL) {
#ifdef NG_BRIDGE_STATS
				link->stats.memoryFailures++;
#endif
				m_freem(m2);
				NG_FREE_DATA(m, meta);
				return (ENOMEM);
			}
		}

#ifdef NG_BRIDGE_STATS
		/* Update stats */
		destLink->stats.xmitPackets++;
		destLink->stats.xmitOctets += MBUF_LENGTH(m);
		switch (manycast) {
		case 0:					/* unicast */
			break;
		case 1:					/* multicast */
			destLink->stats.xmitMulticasts++;
			break;
		case 2:					/* broadcast */
			destLink->stats.xmitBroadcasts++;
			break;
		}
#endif

		/* Send packet */
		if (destLink == firstLink) {
			/*
			 * If we've sent all the others, send the original
			 * on the first link we found.
			 */
			NG_SEND_DATA(error, destLink->hook, m, meta);
			break; /* always done last - not really needed. */
		} else {
			NG_SEND_DATA(error, destLink->hook, m2, meta2);
		}
	}

#else /* !NG_BRIDGE_FLOOD */
	/* no other choice, drop */
	NG_FREE_DATA(m, meta);
	return (0);

#endif /* NG_BRIDGE_FLOOD */
	return (error);
}

/*
 * Shutdown node
 */
static int
ng_bridge_rmnode(node_p node)
{
	const priv_p priv = node->private;
	struct ng_bridge_bucket	*tab;
#ifdef NG_BRIDGE_SNOOP
	struct ng_bridge_grp_bucket *gtab; /* hash table grp_bucket array */
#endif

	/* Shutdown is called when unloading the module.
	 * Then remove any pending timer.
	 * XX : hope it has not already been dequeued.
	 */

#ifdef NG_BRIDGE_TIMER
	ng_callout_stop_sync(&priv->timer);
#endif
	ng_unname(node);
	ng_cutlinks(node);		/* frees all link and host info */
	NG_KASSERT(priv->numLinks == 0 && priv->numSHosts == 0 && priv->numDHosts == 0,
	    ("%s: numLinks=%d numHosts=%d",
	    __FUNCTION__, priv->numLinks, (priv->numSHosts + priv->numDHosts)));
	node->private = NULL;
	vnb_spinlock_lock(&priv->spinlock);
	tab = priv->tab;
	priv->tab = NULL;
	ng_free(tab);
	vnb_spinlock_unlock(&priv->spinlock);
#ifdef NG_BRIDGE_SNOOP
	gtab = priv->gtab;
	priv->gtab = NULL;
	ng_free(gtab);
#endif

	ng_free(priv);
	ng_unref(node);
	return (0);
}

/*
 * Hook disconnection.
 */
static int
ng_bridge_disconnect(hook_p hook)
{
	const priv_p priv = hook->node->private;
	int linkNum;
	struct ng_bridge_link *link;
#ifdef NG_BRIDGE_SNOOP
	int clean_snoop = 0;
#endif

#ifdef NG_BRIDGE_SNOOP
	/*
	 * The link with snooping daemon is broken :
	 *   - remove any snooping info
	 *   - back to the broadcasting mode
	 */
	if (priv->snoop_hook == hook) {
		priv->snoop_hook = NULL;
		clean_snoop = 1;
		goto remove_all;
	}
#endif
	/* Get link number */
	linkNum = LINK_NUM(hook);
	NG_KASSERT(linkNum >= 0 && linkNum < NG_BRIDGE_MAX_LINKS,
			("%s: linkNum=%u", __FUNCTION__, linkNum));

	/* Remove all hosts associated with this link */
	ng_bridge_remove_hosts(priv, linkNum, ALL_ENTRIES);

	/* Free associated link information */
	NG_KASSERT(priv->links[linkNum] != NULL, ("%s: no link", __FUNCTION__));
	link = priv->links[linkNum];
	priv->links[linkNum] = NULL;
	ng_free(link);
	priv->numLinks--;

#ifdef NG_BRIDGE_SNOOP
	/* Send notification message to snoop daemon */
	if (priv->snoop_hook != NULL) {
		struct ng_mesg *msg = NULL;
		struct ng_bridge_snoop_msg* nbsm = NULL;

		NG_MKMESSAGE(msg, NGM_BRIDGE_COOKIE,
				NGM_BRIDGE_NOTIFY_SNOOPD,
				sizeof(struct ng_bridge_snoop_msg), M_NOWAIT);
		if (msg == NULL)
			return(ENOMEM);

		/* Append snoop message */
		nbsm = (struct ng_bridge_snoop_msg *)msg->data;
		nbsm->nbs_cmd = RECV_REMOVED_PORT_INDEX;
		nbsm->nbs_port = (u_int8_t)linkNum;
		nbsm->nbs_len = (u_int16_t)0;

		ng_send_msg(priv->node, msg,
			    NG_HOOK_NAME(priv->snoop_hook), NULL, NULL);
	}
#endif


#ifdef NG_BRIDGE_SNOOP
remove_all:
	/*
	 * if we loose the last lower link  no more bridging,
	 * abort link with snooping daemon
	 */
	if (clean_snoop || (priv->numLinks == 0)) {
		priv->snoop_mode = 0;
		priv->nb_spy = 0;
		bzero (&priv->mld_routers, sizeof(priv->mld_routers));
		bzero (&priv->igmp_routers, sizeof(priv->igmp_routers));
		bzero (&priv->spy_ports, sizeof(priv->spy_ports));
		ng_bridge_remove_groups (priv, 0);
	}
#endif
	/* If no more lower hooks, go away */
	if (priv->numLinks == 0)
		ng_rmnode(hook->node);
	return (0);
}

/******************************************************************
		    HASH TABLE FUNCTIONS
******************************************************************/

/*
 * Hash algorithm
 *
 * Only hashing bytes 3-6 of the Ethernet address is sufficient and fast.
 */

/*
 * Resize the hash table. We try to maintain the number of buckets
 * such that the load factor is in the range 0.25 to 1.0.
 *
 * If we can't get the new memory then we silently fail. This is OK
 * because things will still work and we'll try again soon anyway.
 */
/* unprotected version of ng_bridge_rehash */
static void
__ng_bridge_rehash(priv_p priv)
{
	struct ng_bridge_bucket *newTab, *tab;
	u_int oldBucket, newBucket;
	int newNumBuckets;
	u_int newMask;

	/* Is table too full or too empty? */
	if ((priv->numSHosts + priv->numDHosts) > priv->numBuckets
	    && (priv->numBuckets << 1) <= MAX_BUCKETS)
		newNumBuckets = priv->numBuckets << 1;
	else if ((priv->numSHosts + priv->numDHosts) < (priv->numBuckets >> 2)
	    && (priv->numBuckets >> 2) >= MIN_BUCKETS)
		newNumBuckets = priv->numBuckets >> 2;
	else
		return;
	newMask = newNumBuckets - 1;

	/* Allocate and initialize new table */
	newTab = ng_malloc(newNumBuckets * sizeof(*newTab), M_NOWAIT);
	if (newTab == NULL)
		return;
	bzero(newTab, newNumBuckets * sizeof(*newTab));

	/* Move all entries from old table to new table */
	for (oldBucket = 0; oldBucket < priv->numBuckets; oldBucket++) {
		struct ng_bridge_bucket *const oldList = &priv->tab[oldBucket];

		while (!SLIST_EMPTY(oldList)) {
			struct ng_bridge_hent *const hent
			    = SLIST_FIRST(oldList);

			SLIST_REMOVE_HEAD(oldList, next);
			newBucket = HASH(hent->host.addr, newMask);
			SLIST_INSERT_HEAD(&newTab[newBucket], hent, next);
		}
	}

	/* Replace old table with new one */
	if (priv->conf.debugLevel >= 3) {
		log(LOG_INFO, "ng_bridge: %s: table size %d -> %d\n",
		    ng_bridge_nodename(priv->node),
		    priv->numBuckets, newNumBuckets);
	}
	tab = priv->tab;
	priv->tab = NULL;
	ng_free(tab);
	priv->numBuckets = newNumBuckets;
	priv->hashMask = newMask;
	priv->tab = newTab;
	return;
}

/* protected version of ng_bridge_rehash, not used for now */
/* static void */
/* ng_bridge_rehash(priv_p priv) */
/* { */
/* 	vnb_spinlock_lock(&priv->spinlock); */
/* 	__ng_bridge_rehash(priv); */
/* 	vnb_spinlock_unlock(&priv->spinlock); */
/* } */

#ifdef NG_BRIDGE_SNOOP
/*
 * Find a host entry in the table.
 */
static struct ng_bridge_group *
ng_bridge_grp_get(priv_p priv, const u_char *addr)
{
	const int mybucket = HASH(addr, priv->hash_grpMask);
	struct ng_bridge_grp_ent *ge;

	SLIST_FOREACH(ge, &priv->gtab[mybucket], next) {
		if (vnb_ether_equal(ge->group.addr, addr))
			return (&ge->group);
	}
	return (NULL);
}

/*
 * Add/Modify a group entry to the table.
 */
static int
ng_bridge_grp_put(priv_p priv, const struct ng_bridge_group *grp)
{
	const int mybucket = HASH(grp->addr, priv->hash_grpMask);
	struct ng_bridge_grp_ent *ge;

	SLIST_FOREACH(ge, &priv->gtab[mybucket], next) {
		if (vnb_ether_equal(ge->group.addr, grp->addr)) {
			break;
		}
	}

	/*
	 * if group found, update iface list,
	 * else create a new entry
	 */
	if (!ge) {
		/* Allocate and initialize new hashtable entry */
		ge = ng_malloc(sizeof(*grp), M_NOWAIT);
		if (ge == NULL)
			return (ENOMEM);
		/* Add new element to hash bucket */
		SLIST_INSERT_HEAD(&priv->gtab[mybucket], ge, next);
		priv->numGroups++;

		/* Resize table if necessary */
		/* HCL later ...
			ng_bridge_rehash(priv);
		 */
	}
	bcopy(grp, &(ge->group), sizeof (*grp));
	return (0);
}

/*
 * Delete a group entry to the table.
 */
static int
ng_bridge_grp_del(priv_p priv, const struct ng_bridge_group *grp)
{
	const int mybucket = HASH(grp->addr, priv->hash_grpMask);
	struct ng_bridge_grp_ent **gptr = &SLIST_FIRST(&priv->gtab[mybucket]);

	while (*gptr != NULL) {
		struct ng_bridge_grp_ent *const ge = *gptr;

		if (vnb_ether_equal(ge->group.addr, grp->addr)) {
			*gptr = SLIST_NEXT(ge, next);
			ng_free(ge);
			priv->numGroups--;
			break;
		} else
			gptr = &SLIST_NEXT(ge, next);
	}
	if (gptr == NULL)
		return (EADDRNOTAVAIL);
	else
		return (0);
}
#endif


/******************************************************************
		    MISC FUNCTIONS
******************************************************************/

/*
 * Remove all hosts associated with a specific link from the hashtable.
 * If linkNum == -1, then remove all hosts in the table.
 */
static void
ng_bridge_remove_hosts(priv_p priv, int linkNum, int flags)
{
	u_int mybucket;

	vnb_spinlock_lock(&priv->spinlock);

	for (mybucket = 0; mybucket < priv->numBuckets; mybucket++) {
		struct ng_bridge_hent **hptr = &SLIST_FIRST(&priv->tab[mybucket]);

		while (*hptr != NULL) {
			struct ng_bridge_hent *const hent = *hptr;

			if (flags == DYNAMIC_ENTRIES_ONLY &&
			    hent->host.age == NG_BRIDGE_AGE_STAT_MAGIC) {
				hptr = &SLIST_NEXT(hent, next);
				continue;
			}

			if (linkNum == -1 || hent->host.linkNum == linkNum) {
				*hptr = SLIST_NEXT(hent, next);
				if (hent->host.age == NG_BRIDGE_AGE_STAT_MAGIC)
					priv->numSHosts--;
				else
					priv->numDHosts--;

				ng_free(hent);
			} else
				hptr = &SLIST_NEXT(hent, next);
		}
	}

	vnb_spinlock_unlock(&priv->spinlock);
}

/*
 * Remove one host from hashtable
 */
static void
ng_bridge_remove_one_host(priv_p priv, const u_int8_t *addr)
{
	u_int mybucket;

	vnb_spinlock_lock(&priv->spinlock);

	for (mybucket = 0; mybucket < priv->numBuckets; mybucket++) {
		struct ng_bridge_hent **hptr = &SLIST_FIRST(&priv->tab[mybucket]);

		while (*hptr != NULL) {
			struct ng_bridge_hent *const hent = *hptr;

			if (memcmp(hent->host.addr, addr, 6) == 0) {
				*hptr = SLIST_NEXT(hent, next);
				if (hent->host.age == NG_BRIDGE_AGE_STAT_MAGIC)
					priv->numSHosts--;
				else
					priv->numDHosts--;

				ng_free(hent);
			} else
				hptr = &SLIST_NEXT(hent, next);
		}
	}

	vnb_spinlock_unlock(&priv->spinlock);
}


#ifdef NG_BRIDGE_SNOOP
static void
ng_bridge_remove_groups(priv_p priv, int select)
{
	unsigned int mybucket;

	for (mybucket = 0; mybucket < priv->num_grpBuckets; mybucket++) {
		struct ng_bridge_grp_ent **gptr = &SLIST_FIRST(&priv->gtab[mybucket]);

		while (*gptr != NULL) {
			struct ng_bridge_grp_ent *const ge = *gptr;
			int del = ((select == 0) ||
			    ((select == AF_INET)  && (IS_ETH_MCAST4 (ge->group.addr))) ||
			    ((select == AF_INET6) && (IS_ETH_MCAST6 (ge->group.addr))));
			if (del) {
				*gptr = SLIST_NEXT(ge, next);
				ng_free(ge);
				priv->numGroups--;
			} else
				gptr = &SLIST_NEXT(ge, next);
		}
	}
}
#endif

#ifdef NG_BRIDGE_TIMER
/*
 * Handle our once-per-second timeout event. We do two things:
 * we decrement link->loopCount for those links being muted due to
 * a detected loopback condition, and we remove any hosts from
 * the hashtable whom we haven't heard from in a long while.
 *
 * If the node has the NG_INVALID flag set, our job is to kill it.
 */
static void
ng_bridge_timeout(void *arg)
{
	const node_p node = arg;
	const priv_p priv = node->private;
	u_int mybucket;
	u_int counter = 0;
	int linkNum;

	/* If node was shut down, this is the final lingering timeout */
	if ((node->flags & NG_INVALID) != 0) {
		return;
	}

#if defined(__LinuxKernelVNB__)
	/* Register a new timeout, keeping the existing node reference */
	ng_callout_reset(&priv->timer, hz, ng_bridge_timeout, node);
	/* Update host time counters and remove stale entries */
#endif
	vnb_spinlock_lock(&priv->spinlock);
	for (mybucket = 0; mybucket < priv->numBuckets; mybucket++) {
		struct ng_bridge_hent **hptr = &SLIST_FIRST(&priv->tab[mybucket]);

		while (*hptr != NULL) {
			struct ng_bridge_hent *const hent = *hptr;

			/* Make sure host's link really exists */
			NG_KASSERT(priv->links[hent->host.linkNum] != NULL,
			    ("%s: host %02x:%02x:%02x:%02x:%02x:%02x on nonexistent link %d\n",
			    __FUNCTION__,
			    ((unsigned char *)&hent->host.addr)[0],
			    ((unsigned char *)&hent->host.addr)[1],
			    ((unsigned char *)&hent->host.addr)[2],
			    ((unsigned char *)&hent->host.addr)[3],
			    ((unsigned char *)&hent->host.addr)[4],
			    ((unsigned char *)&hent->host.addr)[5],
			    hent->host.linkNum));

			/* Remove hosts we haven't heard from in a while */
			if (++hent->host.staleness >= priv->conf.maxStaleness) {
				/* if it's not a static entry */
				if (hent->host.age != NG_BRIDGE_AGE_STAT_MAGIC) {
					*hptr = SLIST_NEXT(hent, next);
					ng_free(hent);
					priv->numDHosts--;
				}
			} else {
				/* dynamic entry */
				if (hent->host.age < NG_BRIDGE_AGE_DYN_MAX)
					hent->host.age++;
				hptr = &SLIST_NEXT(hent, next);
				counter++;
			}
		}
	}
	NG_KASSERT((priv->numSHosts + priv->numDHosts) == counter,
	    ("%s: hosts: %d != %d", __FUNCTION__, (priv->numSHosts + priv->numDHosts), counter));

	/* Decrease table size if necessary */
	__ng_bridge_rehash(priv);

	vnb_spinlock_unlock(&priv->spinlock);

	/* Decrease loop counter on muted looped back links */
	for (counter = linkNum = 0; linkNum < NG_BRIDGE_MAX_LINKS; linkNum++) {
		struct ng_bridge_link *const link = priv->links[linkNum];

		if (link != NULL) {
			if (link->loopCount != 0) {
				link->loopCount--;
				if (link->loopCount == 0
				    && priv->conf.debugLevel >= 2) {
					log(LOG_INFO, "ng_bridge: %s:"
					    " restoring looped back link%d\n",
					    ng_bridge_nodename(node), linkNum);
				}
			}
			counter++;
		}
	}

	NG_KASSERT(priv->numLinks == counter,
			("%s: links: %d != %d", __FUNCTION__, priv->numLinks, counter));

#if !defined(__LinuxKernelVNB__)
	/* Register a new timeout, keeping the existing node reference */
	ng_callout_reset(&priv->timer, hz, ng_bridge_timeout, node);
#endif
	/* Done */
}
#endif

/*
 * Return node's "name", even if it doesn't have one.
 */
static const char *
ng_bridge_nodename(node_p node)
{
	static char name[NG_NODELEN+1];

	if (node->name != NULL)
		snprintf(name, sizeof(name), "%s", node->name);
	else
		snprintf(name, sizeof(name), "[%x]", ng_node2ID(node));
	return name;
}

#ifdef __LinuxKernelVNB__

static struct ng_nl_nodepriv *
ng_bridge_dumpnode(node_p node)
{
	struct ng_nl_nodepriv *nlnodepriv;
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_bridge_nl_nodepriv *br_nlpriv;
	int i = 0;
	u_int mybucket;
	struct ng_bridge_hent *hent;

	/* only dump static host entries */
	MALLOC(nlnodepriv, struct ng_nl_nodepriv *,
		sizeof(*nlnodepriv) + sizeof(*br_nlpriv)
		+ sizeof(struct ng_bridge_static_host) * priv->numSHosts,
		M_NETGRAPH, M_NOWAIT | M_ZERO);
	if (!nlnodepriv)
		return NULL;

	nlnodepriv->data_len = sizeof(*br_nlpriv) + sizeof(struct ng_bridge_static_host) * priv->numSHosts;
	br_nlpriv  = (struct ng_bridge_nl_nodepriv *)nlnodepriv->data;
	br_nlpriv->numHosts = htonl(priv->numSHosts);

	vnb_spinlock_lock(&priv->spinlock);
	for (mybucket = 0; mybucket < priv->numBuckets; mybucket++) {
		SLIST_FOREACH(hent, &priv->tab[mybucket], next) {
			if (hent->host.age == NG_BRIDGE_AGE_STAT_MAGIC) {
				memcpy(br_nlpriv->hosts[i].addr, hent->host.addr, 6);
				br_nlpriv->hosts[i].linkNum = htons(hent->host.linkNum);
				i++;
			}
		}
	}
	vnb_spinlock_unlock(&priv->spinlock);

	return nlnodepriv;
}

#else

static void
ng_bridge_restorenode(struct ng_nl_nodepriv *nlnodepriv, node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_bridge_nl_nodepriv *br_nlpriv;
	u_int32_t i;
	struct ng_bridge_static_host *h;

	br_nlpriv = (struct ng_bridge_nl_nodepriv *)nlnodepriv->data;
	br_nlpriv->numHosts = ntohl(br_nlpriv->numHosts);

	if (ntohl(nlnodepriv->data_len) != sizeof(*br_nlpriv)
		+ sizeof(struct ng_bridge_static_host) * br_nlpriv->numHosts)
		return;

	for (i = 0; i< br_nlpriv->numHosts; i++) {
		h = &br_nlpriv->hosts[i];
		if (!ng_bridge_put(priv, h->addr, ntohs(h->linkNum), 0))
			return;
	}
}

#endif

#if defined(__LinuxKernelVNB__)
module_init(ng_bridge_init);
module_exit(ng_bridge_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB bridge node");
MODULE_LICENSE("6WIND");
#endif
