/*
 * Copyright 2014 6WIND S.A.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/socket.h>

#include <event.h>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/route/link.h>

#include "fpm_common.h"

/*
 * undef __USE_MISC is required because net/if.h and linux/if.h (included
 * by netlink/route/link.h) defines same structures and enumarations,
 * but net/if.h is required to use if_nametoindex()
 */
#undef __USE_MISC
#include <net/if.h>

unsigned int fpn0_status = 0;

static struct nl_sock *fpm_netlink_socket;
static struct event *fpm_netlink_event;
static int fpn0_ifindex = -1;

/* Netlink callback */
int fpm_netlink_recv(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nl_hdr = nlmsg_hdr(msg);
	struct ifinfomsg *ifinfo = (struct ifinfomsg *) NLMSG_DATA(nl_hdr);
	struct nlattr *nl_attr;
	int rem;
	char *name;

	/* Only check NEWLINK/DELLINK messages */
	switch(nl_hdr->nlmsg_type) {
		case RTM_NEWLINK:
			/* fpn0 not detected for now */
			if (fpn0_ifindex == -1) {
				/* Scan attributes to find interface name */
				nla_for_each_attr(nl_attr, nlmsg_attrdata(nl_hdr, sizeof(struct ifinfomsg)),
				                  nlmsg_attrlen(nl_hdr, sizeof(struct ifinfomsg)), rem) {
					if (nla_type(nl_attr) == IFLA_IFNAME) {
						name = (char *)nla_data(nl_attr);

						/* Initialize fpn0 ifindex and state */
						if (!strcmp(name, "fpn0")) {
							fpn0_ifindex = ifinfo->ifi_index;
							fpn0_status = ifinfo->ifi_flags & IFF_RUNNING;
							syslog(LOG_INFO, "%s: fpn0 found : ifindex %d status %x\n",
							       __FUNCTION__, fpn0_ifindex, fpn0_status);
						}
					}
				}
			}

			/* fpn0 always undetected, exit */
			if (fpn0_ifindex == -1)
				break;

			/* Exit if not an effective fpn0 status change message */
			if ((ifinfo->ifi_index != fpn0_ifindex) ||
				(fpn0_status == (ifinfo->ifi_flags & IFF_RUNNING)))
				break;

			/* Here status changed, there is something to do */
			fpn0_status = ifinfo->ifi_flags & IFF_RUNNING;
			if (fpn0_status & IFF_RUNNING) {
				syslog(LOG_ERR, "%s: fastpath is restarting\n", __func__);
				fpm_restart();
			} else {
				syslog(LOG_ERR, "%s: fastpath lost\n", __func__);
			}
			break;

		case RTM_DELLINK:
			/* Interface deleted, it is down */
			if (ifinfo->ifi_index == fpn0_ifindex) {
				syslog(LOG_ERR, "%s: fpn0 deleted\n", __func__);
				fpn0_ifindex = -1;
				fpn0_status = 0;
			}
			break;

		default:
			break;
	}

	return 0;
}

/* Callback used to receive events */
void fpm_netlink_event_recv(int fd, short event, void *arg)
{
	struct nl_sock *s = (struct nl_sock *)arg;
	int ret;

	/* Receive netlinkm message */
	ret = nl_recvmsgs_default(s);
	if (ret < 0) {
		syslog(LOG_ERR, "%s: failed to receive netlink message\n",
		       __FUNCTION__);
	}
}

/* Close netlink socket and event */
void fpm_netlink_close(void)
{
	/* Delete event */
	if (fpm_netlink_event != NULL) {
		event_del(fpm_netlink_event);
		free(fpm_netlink_event);
		fpm_netlink_event = NULL;
	}

	/* Close socket */
	if (fpm_netlink_socket != NULL) {
		nl_socket_free(fpm_netlink_socket);
		fpm_netlink_socket = NULL;
	}
}

/* Initialize netlink socket to watch fpn0 */
int fpm_netlink_init(struct event_base *fpm_event_base)
{
	struct nl_msg *msg;

	/* Create netlink socket */
	fpm_netlink_socket = nl_socket_alloc();
	if (fpm_netlink_socket == NULL) {
		syslog(LOG_ERR, "%s: failed to allocate netlink socket\n", __func__);
		return -1;
	}

	/* Setup netlink socket */
	nl_socket_modify_cb(fpm_netlink_socket, NL_CB_VALID, NL_CB_CUSTOM, fpm_netlink_recv, NULL);
	nl_socket_disable_auto_ack(fpm_netlink_socket);

	/* Connect to NET_ROUTE */
	if (nl_connect(fpm_netlink_socket, NETLINK_ROUTE) < 0) {
		syslog(LOG_ERR, "%s: failed to connect netlink socket\n", __func__);
		fpm_netlink_close();
		return -1;
	}

	/* Watch link messages */
	nl_socket_add_memberships(fpm_netlink_socket, RTNLGRP_LINK, 0);

	/* Create an event on netlink socket */
	fpm_netlink_event = event_new(fpm_event_base, nl_socket_get_fd(fpm_netlink_socket),
	                              EV_READ | EV_PERSIST, fpm_netlink_event_recv, fpm_netlink_socket);
	if (fpm_netlink_event == NULL) {
		syslog(LOG_ERR, "%s: failed to allocate event\n", __func__);
		fpm_netlink_close();
		return -1;
	}

	/* Start waiting events on netlink socket */
	if (event_add(fpm_netlink_event, NULL)) {
		syslog(LOG_ERR, "%s: failed to setup event notification\n", __func__);
		fpm_netlink_close();
		return -1;
	}
	/* Send a request for fpn0 status dump */
	if (rtnl_link_build_get_request(if_nametoindex("fpn0"), "fpn0", &msg) < 0) {
		syslog(LOG_ERR, "%s: failed to setup initial link status message\n", __func__);
		return -1;
	}

	if (nl_send_auto(fpm_netlink_socket, msg) < 0) {
		syslog(LOG_ERR, "%s: failed to send link status message\n", __func__);
		nlmsg_free(msg);
		return -1;
	}

	nlmsg_free(msg);
	return 0;
}
