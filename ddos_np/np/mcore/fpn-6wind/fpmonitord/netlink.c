/*
 * Copyright (c) 2011 6WIND, All rights reserved.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <syslog.h>
#include <event.h>

#include "netlink.h"
#include <netlink/msg.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/link.h>
#include <hasupport.h>
extern struct has_ctx *fpmonitord_has;

static void (*fpmonitor_callback)(void) = NULL;

static struct event fpmonitord_netlink_event;
static struct nl_sock *fpmonitord_netlink_socket;

/*
 * Netlink General Dispatcher
 */
static int
fpmonitord_accept_nl_msg (struct nl_msg *msg, void *arg)
{
	struct ifinfomsg *ifi;
	struct nlattr *tb [IFLA_MAX + 1];
	const char *name;
	int err;
	struct nlmsghdr *h = nlmsg_hdr(msg);

	if (h->nlmsg_type != RTM_NEWLINK && h->nlmsg_type != RTM_DELLINK)
		return 0;

	ifi = nlmsg_data (h);

	err = nlmsg_parse(h, sizeof(*ifi), tb, IFLA_MAX, NULL);
	if (err < 0) {
		syslog(LOG_DEBUG,"%s: wrong nlmsg: %s\n", __FUNCTION__, nl_geterror(err));
		return -1;
	}

	if (tb[IFLA_IFNAME] == NULL) {
		syslog(LOG_DEBUG, "%s no IFLA_IFNAME attribute\n", __FUNCTION__);
		return 0;
	}
	name = (char *)nla_data(tb[IFLA_IFNAME]);

	/* only if name == fpn0 */
	if ( !(strncmp(name, "fpn0", 4)) && (h->nlmsg_type == RTM_NEWLINK)) {
		/* tell fpmonitor of fpn0 presence */
		if (fpmonitor_callback != NULL)
			(*fpmonitor_callback)();

		syslog(LOG_DEBUG, "link %s (RUNNING=%d, UP=%d)\n",  name,
	      !!(ifi->ifi_flags & IFF_RUNNING),
	      !!(ifi->ifi_flags & IFF_UP) );
 	}

	return 0;
}

/*
 * Netlink Reception & Re-assembly
 */
static void
fpmonitord_nl_recv(int sock, short evtype, void *data)
{
	struct nl_sock *nl = data;
	int ret;
	
	ret = nl_recvmsgs_default(nl);
	if (ret < 0) {
		syslog(LOG_ERR, "%s: %s", __FUNCTION__, strerror(errno));
		if (errno == ENOBUFS) {
#ifdef NOTYET
			/* NB : we cannot (yet) restart the fastpath */
			has_critical_state (fpmonitord_has);
#else
			fpmonitord_has->healthState = HA6W_HEALTH_DEGRADED;
#endif
		}
	}
}

int fpmonitord_netlink_dump(void)
{
	struct nl_sock *nl;
	int ret = -1;
	struct rtnl_link *link = NULL;

	nl = nl_socket_alloc();
	if (!nl)
		goto err;

	nl_socket_disable_auto_ack(nl);
	if (nl_connect(nl, NETLINK_ROUTE) < 0)
		goto err;

	if ((ret = rtnl_link_get_kernel(nl, 0, "fpn0", &link)) < 0)
		goto err;

	if (nl_object_get_msgtype((struct nl_object *)link) == RTM_NEWLINK) {
		/* tell fpmonitor of fpn0 presence */
		if (fpmonitor_callback != NULL)
			(*fpmonitor_callback)();

		syslog(LOG_DEBUG, "link %s (RUNNING=%d, UP=%d)\n",  "fpn0",
			   !!(rtnl_link_get_flags(link) & IFF_RUNNING),
			   !!(rtnl_link_get_flags(link) & IFF_UP) );
	}

err:
	rtnl_link_put(link);
	nl_socket_free(nl);
	return ret;
}

int fpmonitord_netlink_init( void (*fpn0_CB)(void) )
{
	/* register fpmonitor callback */
	fpmonitor_callback = fpn0_CB;

	fpmonitord_netlink_socket = nl_socket_alloc();
	if (!fpmonitord_netlink_socket)
		return -1;

	nl_socket_disable_auto_ack(fpmonitord_netlink_socket);
	if (nl_connect(fpmonitord_netlink_socket, NETLINK_ROUTE) < 0) {
		nl_socket_free(fpmonitord_netlink_socket);
		fpmonitord_netlink_socket = NULL;
		return -1;
	}
	nl_socket_add_membership(fpmonitord_netlink_socket, RTMGRP_LINK);
	nl_socket_modify_cb(fpmonitord_netlink_socket, NL_CB_VALID, NL_CB_CUSTOM,
			    fpmonitord_accept_nl_msg, NULL);

	event_set(&fpmonitord_netlink_event, nl_socket_get_fd(fpmonitord_netlink_socket),
		  EV_READ | EV_PERSIST, fpmonitord_nl_recv, fpmonitord_netlink_socket);
	event_add(&fpmonitord_netlink_event, NULL);
	return 0;
}

int fpmonitord_netlink_close(void)
{
	if (fpmonitord_netlink_socket) {
		event_del(&fpmonitord_netlink_event);
		nl_socket_drop_membership(fpmonitord_netlink_socket, RTMGRP_LINK);
		nl_socket_free(fpmonitord_netlink_socket);
	}
	fpmonitord_netlink_socket = NULL;
	return 0;
}
