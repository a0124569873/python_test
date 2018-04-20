/*
 * Copyright 2011-2013 6WIND S.A.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <net/if.h>
#include <event.h>
#include <libconsole.h>
#include <sys/queue.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/time.h>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/route/rtnl.h>

#include <netgraph/ng_message.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_ethgrp.h>

#include "lacp.h"
#include <netgraph/ieee8023_slowprotocols.h>
#include <netgraph/ieee8023_tlv.h>
#include <netgraph/ieee8023ad_lacp.h>
#include "iface.h"
#include "node.h"
#include "ieee8023ad_lacp_sm.h"
#include "ieee8023ad_lacp_debug.h"

#include <assert.h>

#include "netlink.h"

#ifdef HA_SUPPORT
#include <hasupport.h>
extern struct has_ctx *myhas;
#include "ifuid.h"
#endif

static struct event lacpd_netlink_event;
static struct nl_sock *lacpd_nl_sock;
static struct nl_sock *lacpd_nl_cmd_sock;

#define IS_OPERATIVE(flags) ((flags & IFF_UP) && (flags & IFF_RUNNING))

static int
lacpd_nl_link (struct nl_msg *msg, void *arg)
{
	struct ifinfomsg *ifi;
	struct nlattr *tb [IFLA_MAX + 1];
	struct nlmsghdr *h = nlmsg_hdr(msg);
	const char *name;
	int err;
	struct chgrp_node *node;
	struct chgrp_link *link;
	struct lacpd_iface *iface = NULL;
	unsigned old_flags = 0;
	uint32_t ifuid;
#ifdef HA_SUPPORT
	uint32_t vrf_id = 0;
#endif

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "Entering"));

	ifi = nlmsg_data (h);

	err = nlmsg_parse(h, sizeof(*ifi), tb, IFLA_MAX, NULL);
	if (err < 0) {
		syslog(LOG_ERR,"%s: could not parse message (%s)", __FUNCTION__, nl_geterror(err));
		return -1;
	}

	if (tb[IFLA_IFNAME] == NULL) {
		DEBUG(LOG_DEBUG, "%s no IFLA_IFNAME attribute\n", __FUNCTION__);
		return 0;
	}
	name = (char *)nla_data(tb[IFLA_IFNAME]);

#ifdef HA_SUPPORT
#ifdef IFLA_VRFID
	/* vrf_id */
	if (tb[IFLA_VRFID])
		vrf_id = *(uint32_t *) nla_data (tb[IFLA_VRFID]);
#endif
	ifuid = ifname2ifuid (name, vrf_id);
#else
	ifuid = ntohl (ifi->ifi_index);
#endif

	node = chgrp_node_lookup_by_chgrpname(name);
	if (node && h->nlmsg_type == RTM_NEWLINK) {
		if(node->status && !(ifi->ifi_flags & IFF_RUNNING)) {
			LACP_DPRINTF((LOG_DEBUG, __func__, NULL,
						  "set %s running on", node->chgrpname));
			if (set_running_flag(node->chgrpname, IFF_RUNNING) < 0)
				DEBUG(LOG_ERR, "set %s running flag on failed: %s\n", node->chgrpname, __FUNCTION__);
		}
		if (!node->status && (ifi->ifi_flags & IFF_RUNNING)) {
			LACP_DPRINTF((LOG_DEBUG, __func__, NULL,
						  "set %s running off", node->chgrpname));
			if (set_running_flag(node->chgrpname, ~IFF_RUNNING) < 0)
				DEBUG(LOG_ERR, "set %s running flag off failed: %s\n", node->chgrpname, __FUNCTION__);
		}
		/* check new HW mac address */
		if (tb[IFLA_ADDRESS]) {
			char cmd[64];
			memcpy (node->ether_addr, RTA_DATA(tb[IFLA_ADDRESS]), ETH_ALEN);
			chgrp_node_configure_mac(node);
			DEBUG(LOG_DEBUG, "new hw address %s\n",
				lacp_format_mac(node->ether_addr, cmd, sizeof(cmd)));
		}
	}

	/* keep the state of interfaces (to avoid a dump when creating
	 * a new link) */
	if (h->nlmsg_type == RTM_NEWLINK) {
		iface = lacpd_iface_lookup(name);
		if (iface) {
			DEBUG(LOG_DEBUG, "lacpd_iface update %s.\n", name);
			lacpd_iface_update(iface, ifi->ifi_flags);
		}
		else {
			DEBUG(LOG_DEBUG, "lacpd_iface new %s.\n", name);
			lacpd_iface_add(name, ifi->ifi_index, ifuid, ifi->ifi_flags);
		}
	}
	else if (h->nlmsg_type == RTM_DELLINK) {
		DEBUG(LOG_DEBUG, "lacpd_iface_delete %s.\n", name);
		lacpd_iface_delete(name);
	} else {
		DEBUG(LOG_DEBUG, "Unknown message: %08x %08x %08x\n",
			h->nlmsg_len, h->nlmsg_type, h->nlmsg_flags);
	}


	node = chgrp_node_lookup_by_link_ifname(name);
	if (node == NULL) {
		DEBUG(LOG_DEBUG, "no node for %s.\n", name);
		return 0;
	}
	link = chgrp_link_lookup_by_ifname(node, name);
	if (link == NULL) {
		DEBUG(LOG_DEBUG, "no link for %s.\n", name);
		return 0;
	}

	if (h->nlmsg_type == RTM_DELLINK) {
		link->if_flags = 0;
		link->iface = NULL;
		/* update the RUNNING flags first*/
		if(link->status == NG_ETH_GRP_HOOK_ACTIVE)
			decrease(node);
		link->status = NG_ETH_GRP_HOOK_INACTIVE;
		DEBUG(LOG_INFO, "We lost member %s. Will reconnect later.\n",
		      link->ifname);
		/* also reset LACP_STATE_AGGREGATION in link->lp_state */
		if (LACP_TIMER_ISARMED(link, LACP_TIMER_WAIT_WHILE)) {
			assert(link->lp_aggregator != NULL);
			assert(link->lp_aggregator->la_pending > 0);
			link->lp_aggregator->la_pending--;
		}
		LACP_TIMER_DISARM(link, LACP_TIMER_WAIT_WHILE);
		lacp_sm_rx_set_expired(link);
		/* Give a chance to state machine to make
		   things right. */
		lacp_sm_mux(link);
		return 0;
	}

	old_flags = link->if_flags;
	link->if_flags = ifi->ifi_flags;

	/* RTM_NEWLINK + flags up or running changed */
	if (IS_OPERATIVE(old_flags) != IS_OPERATIVE(link->if_flags)) {

		/* Static mode */
		if (link->mode == MODE_LINK_ON) {
			if (IS_OPERATIVE(link->if_flags)) {
				if (link->status == NG_ETH_GRP_HOOK_INACTIVE)
					increase(node);
				link->status = NG_ETH_GRP_HOOK_ACTIVE;
			} else {
				if (link->status == NG_ETH_GRP_HOOK_ACTIVE)
					decrease(node);
				link->status = NG_ETH_GRP_HOOK_INACTIVE;
			}
			goto bypass_dynamic;
		}

		/* Dynamic mode */

		/* both up and running */
		if (IS_OPERATIVE(link->if_flags)) {
			/* set LACP_STATE_ACTIVITY if active only, not passive */
			if (link->mode == MODE_LINK_LACP_ACTIVE)
				link->lp_state |= LACP_STATE_ACTIVITY | LACP_STATE_AGGREGATION;
			else
				link->lp_state |= LACP_STATE_AGGREGATION;
		} else {
			DEBUG(LOG_INFO, "Member %s is down. Will reconnect later.\n",
			      link->ifname);
			if (LACP_TIMER_ISARMED(link, LACP_TIMER_WAIT_WHILE)) {
				assert(link->lp_aggregator != NULL);
				assert(link->lp_aggregator->la_pending > 0);
				link->lp_aggregator->la_pending--;
			}
			LACP_TIMER_DISARM(link, LACP_TIMER_WAIT_WHILE);
			if (link->mode == MODE_LINK_LACP_ACTIVE)
				link->lp_state &= ~(LACP_STATE_ACTIVITY | LACP_STATE_AGGREGATION);
			else
				link->lp_state &= ~LACP_STATE_AGGREGATION;
		}

		/* restart LACP state machine */
		LACP_DPRINTF((LOG_DEBUG, __func__, link,
			      "restart LACP state machine: %s", name));
		lacp_sm_rx_set_expired(link);

		if (!IS_OPERATIVE(link->if_flags)) {
			LACP_DPRINTF((LOG_DEBUG, __func__, link,
				      "reset LACP state machine: %s", name));
			lacp_sm_rx_timer_force(link);
		}

		/* Give a chance to state machine to make things right. */
		lacp_sm_mux(link);
	}

bypass_dynamic:

	/* existing iface with corresponding node and link */
	if (iface) {
		link->iface = iface;
		link->lp_actor.lip_portid.lpi_portno = htobe16(iface->portid);
	}

	/* if the link is configured for this ifname, but the iface is
	 * new, send connect the link to ng_ether */
	if (iface == NULL)
		chgrp_link_connect(node, link);
	/* Sync state: lacpd MIB => VNB */
	chgrp_node_configure_status(node, link->linknum, link->status);
	chgrp_node_configure_prio(node, link->linknum, link->priority);

	DEBUG(LOG_DEBUG, "link %s:%d (%s) (RUNNING=%d, UP=%d)\n",
	      node->chgrpname, link->linknum, link->ifname,
	      !!(ifi->ifi_flags & IFF_RUNNING),
	      !!(ifi->ifi_flags & IFF_UP) );

	return 0;
}

/*
 * Netlink General Dispatcher
 */
static int
lacpd_accept_nl_msg(struct nl_msg *msg, void *unused)
{
	struct nlmsghdr *h = nlmsg_hdr(msg);
	switch (h->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		lacpd_nl_link (msg, NULL);
		break;
	default:
		break;
	}
	return 0;
}


/*
 * libevent callback for
 * Netlink Reception & Re-assembly
 */
static void
lacpd_nl_recv(int sock, short evtype, void *data)
{
	struct nl_sock *nlsock = data;
	int ret;

	ret = nl_recvmsgs_default(nlsock);
	if (ret < 0) {
		DEBUG(LOG_ERR, "%s: %s", __FUNCTION__, strerror(errno));
		if (errno == ENOBUFS) {
#ifdef HA_SUPPORT
			has_critical_state(myhas);
#endif
		}
	}
}

int lacpd_netlink_dump(void)
{
	/* trigger a dump */
	if (nl_rtgen_request(lacpd_nl_cmd_sock, RTM_GETLINK, AF_UNSPEC, NLM_F_DUMP|NLM_F_REQUEST) < 0) {
		DEBUG(LOG_ERR, "%s: send dump request\n", __FUNCTION__);
		return -1;
	}
	if (nl_recvmsgs_default(lacpd_nl_cmd_sock) < 0) {
		DEBUG(LOG_ERR, "%s: error when parsing dump response\n", __FUNCTION__);
		return -1;
	}
	return 0;
}

int lacpd_netlink_init(int lacpd_nl_sockbufsiz)
{
	/* nl_cmd_sock */
	lacpd_nl_cmd_sock = nl_socket_alloc();
	if (!lacpd_nl_cmd_sock)
		goto error;

	nl_socket_disable_auto_ack(lacpd_nl_cmd_sock);

	if (nl_connect(lacpd_nl_cmd_sock, NETLINK_ROUTE) < 0)
		goto error;

	nl_socket_modify_cb(lacpd_nl_cmd_sock, NL_CB_VALID, NL_CB_CUSTOM, lacpd_nl_link, NULL);
	/* increase netlink sock buffersize */
	setsockopt(nl_socket_get_fd(lacpd_nl_cmd_sock), SOL_SOCKET, SO_RCVBUF,
			&lacpd_nl_sockbufsiz, sizeof(lacpd_nl_sockbufsiz));

	/* nl_sock */
	lacpd_nl_sock = nl_socket_alloc();
	if (!lacpd_nl_sock)
		goto error;

	nl_socket_disable_auto_ack(lacpd_nl_sock);
	nl_join_groups(lacpd_nl_sock, RTMGRP_LINK);

	if (nl_connect(lacpd_nl_sock, NETLINK_ROUTE) < 0)
		goto error;

	nl_socket_modify_cb(lacpd_nl_sock, NL_CB_VALID, NL_CB_CUSTOM, lacpd_accept_nl_msg, NULL);
	/* increase netlink sock buffersize */
	setsockopt(nl_socket_get_fd(lacpd_nl_sock), SOL_SOCKET, SO_RCVBUF,
			&lacpd_nl_sockbufsiz, sizeof(lacpd_nl_sockbufsiz));

	event_set(&lacpd_netlink_event, nl_socket_get_fd(lacpd_nl_sock),
		  EV_READ | EV_PERSIST, lacpd_nl_recv, lacpd_nl_sock);
	event_add(&lacpd_netlink_event, NULL);

	return 0;
error:
	if (lacpd_nl_cmd_sock) {
		nl_socket_free(lacpd_nl_cmd_sock);
		lacpd_nl_cmd_sock = NULL;
	}
	if (lacpd_nl_sock) {
		nl_socket_free(lacpd_nl_sock);
		lacpd_nl_sock = NULL;
	}
	return -1;
}

int lacpd_netlink_close(void)
{
	if (lacpd_nl_cmd_sock) {
		nl_socket_free(lacpd_nl_cmd_sock);
		lacpd_nl_cmd_sock = NULL;
	}

	if (lacpd_nl_sock) {
		event_del(&lacpd_netlink_event);
		nl_socket_free(lacpd_nl_sock);
		lacpd_nl_sock = NULL;
	}

	return 0;
}
