/*
 * Copyright 2013 6WIND S.A.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <syslog.h>
#include <event.h>

#include <netinet/in.h>
#include <net/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>

#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/errno.h>
#include <netlink/route/link.h>

#include "sock.h"
#include "stream.h"

#include "sdsifd_conf.h"
#include <libif.h>
#include <libifevent.h>

extern int sdsifd_fp_tx_interface(struct libif_iface *iface);
extern void sdsifd_fp_set_libif_userdata(struct libif_iface *iface);
extern int sdsifd_cp_tx_interface(struct libif_iface *iface);
extern void sdsifd_cp_set_libif_userdata(struct libif_iface *iface);

/* libnl's socket */
struct nl_sock *if_sk;


/* libif callback functions */

/*
 * libif callback for new/update link messages
 *
 * we set the libif userdata, and send the interface.
 *
 * in cp mode, the userdata is a sdsifd_iface structure (we need to
 * store the peer, and if the interface is an fpib).
 *
 * in fp mode, the userdata is the corresponding sdsifd_ifconf
 * structure (XXX: for now, interface that don't have an ifconf make a
 * lookup at each nl message, this could be optimized by adding a
 * 'void' ifconf).
 *
 * When iface->userdata can't be set, it means that we don't care
 * about the interface, hence the (filtered) log.
 */
static void sdsifd_notif_new_cb(const struct libif_iface *iface, uint16_t notif_flags, void *arg)
{
	if (sdsifd_mode == CP_MODE) {
		sdsifd_cp_set_libif_userdata((struct libif_iface *)iface);
		if (!iface->userdata) {
			IFD_LOG(LOG_DEBUG, " RX NL NEW_LINK <%s> (filtered)\n", iface->name);
			return;
		}

		IFD_LOG(LOG_INFO, " RX NL NEW_LINK <%s> [%02x:%02x:%02x:%02x:%02x:%02x] %s\n",
			iface->name,
			iface->devaddr[0], iface->devaddr[1], iface->devaddr[2],
			iface->devaddr[3], iface->devaddr[4], iface->devaddr[5],
			iface->flags & IFF_UP ? "<up>" : "<down>");

		sdsifd_cp_tx_interface((struct libif_iface *)iface);
	} else {
		sdsifd_fp_set_libif_userdata((struct libif_iface *)iface);
		if (!iface->userdata) {
			IFD_LOG(LOG_DEBUG, " RX NL NEW_LINK <%s> (filtered)\n", iface->name);
			return;
		}

		IFD_LOG(LOG_INFO, " RX NL NEW_LINK <%s> [%02x:%02x:%02x:%02x:%02x:%02x] mtu=%d %s\n",
			iface->name,
			iface->devaddr[0], iface->devaddr[1], iface->devaddr[2],
			iface->devaddr[3], iface->devaddr[4], iface->devaddr[5],
			iface->mtu,
			iface->flags & IFF_RUNNING ? "<running>" : "");

		sdsifd_fp_tx_interface((struct libif_iface *)iface);
	}

	return;
}

/* libif callback for del link messages
 *
 * in cp mode, we free the sdsifd_iface on del message reception. It
 * typically happens for a fpib, when it is deleted by
 * hao-ifd. Non fpib interfaces are filtered.
 *
 * in fp mode, our physical interface should not be deleted, so we
 * don't care about the message. It should not be called anyway.
 */
static void sdsifd_notif_del_cb(const struct libif_iface *iface, uint16_t notif_flags, void *arg)
{
	if (sdsifd_mode == CP_MODE) {
		struct sdsifd_iface *sdsifd_iface;
		struct sdsifd_peer *peer;

		if (!iface->userdata) {
			IFD_LOG(LOG_DEBUG, " RX NL DEL_LINK <%s> (filtered)\n", iface->name);
			return;
		}

		sdsifd_iface = iface->userdata;
		if (!sdsifd_iface->fpib) {
			IFD_LOG(LOG_DEBUG, " RX NL DEL_LINK <%s> (filtered)\n", iface->name);
			return;
		}

		IFD_LOG(LOG_DEBUG, " RX NL DEL_LINK <%s>\n", iface->name);

		peer = sdsifd_iface->peer;
		SLIST_REMOVE(&peer->peer_iface_list, sdsifd_iface,
			     sdsifd_iface, iface_next);

		((struct libif_iface *)iface)->userdata = NULL;
		free(sdsifd_iface);
	} else {
		IFD_LOG(LOG_DEBUG, " RX NL DEL_LINK <%s> (filtered)\n", iface->name);
	}
}


/* fp mode netlink set functions */

/* this function uses libnl to set allmulti flag on interface 'ifname'.
 * It is used only in fp mode.
 *
 * We check in our libif cache if the flag is already set before
 * trying to set it.
 *
 * It does not work if the interface is not in vrf0.
 */
int sdsifd_nl_fp_if_set_allmulti(const char *ifname)
{
	struct rtnl_link *link;
	struct libif_iface *libif_iface;
	int err = 0;

	libif_iface = libif_iface_lookup_allvr(ifname);
	if (!libif_iface)
		return -1;

	/* already up-to-date */
	if (libif_iface->flags & IFF_ALLMULTI)
		return 0;

	IFD_LOG(LOG_DEBUG, "<%s> + ALLMULTI", ifname);

	link = rtnl_link_alloc();
	if (!link) {
		IFD_LOG(LOG_ERR, "could not alloc link for %s\n", ifname);
		goto end;
	}

	rtnl_link_set_name(link, ifname);
	rtnl_link_set_flags(link, libif_iface->flags | IFF_ALLMULTI);

	err = rtnl_link_change(if_sk, link, link, 0);
	if (err)
		IFD_LOG(LOG_ERR, "could not set <allmulti> on %s (%s)",
			ifname, nl_geterror(err));

end:
	rtnl_link_put(link);

	return err;
}

/* this function uses libnl to set/reset up flag on interface 'ifname'.
 * It is used only in fp mode.
 *
 * We check in our libif cache if the flag is already at the correct
 * value before setting it.
 *
 * It does not work if the interface is not in vrf0.
 */
int sdsifd_nl_fp_if_update(const char *ifname, uint8_t up)
{
	struct rtnl_link *link;
	struct libif_iface *libif_iface;
	int err = 0;

	libif_iface = libif_iface_lookup_allvr(ifname);
	if (!libif_iface)
		return -1;

	/* already up-to-date */
	if ((up && (libif_iface->flags & IFF_UP)) ||
	    (!up && !(libif_iface->flags & IFF_UP)))
		return 0;

	IFD_LOG(LOG_DEBUG, "<%s> %c UP", ifname, up ? '+' : '-');

	link = rtnl_link_alloc();
	if (!link) {
		IFD_LOG(LOG_ERR, "could not alloc link for %s\n", ifname);
		goto end;
	}

	rtnl_link_set_name(link, ifname);
	rtnl_link_set_flags(link, libif_iface->flags);
	if (up)
		rtnl_link_set_flags(link, IFF_UP);
	else
		rtnl_link_unset_flags(link, IFF_UP);

	err = rtnl_link_change(if_sk, link, link, 0);
	if (err)
		IFD_LOG(LOG_ERR, "could not set %s on %s (%s)",
			up ? "<up>" : "<down>",
			ifname, nl_geterror(err));

end:
	rtnl_link_put(link);

	return err;
}


/* cp mode netlink set functions */

/* this function uses libnl to set dormant linkmode on interface
 * 'ifname'. It is used only in cp mode.
 *
 * This is needed to be able to set the operstate in next function.
 * Every rfpvi interface created by sds-ifd must have dormant
 * linkmode.
 *
 * It does not work if the interface is not in vrf0.
 */
int sdsifd_nl_cp_if_set_dormant(const char *ifname)
{
	struct rtnl_link *link;
	int err = 0;

	link = rtnl_link_alloc();
	rtnl_link_set_name(link, ifname);
	rtnl_link_set_linkmode(link, IF_LINK_MODE_DORMANT);

	IFD_LOG(LOG_INFO, "<%s> + MODE_DORMANT", ifname);

	err = rtnl_link_change(if_sk, link, link, 0);
	if (err)
		IFD_LOG(LOG_ERR, "could not set mode dormant on %s (%s)", ifname, nl_geterror(err));

	rtnl_link_put(link);

	return err;
}

/* this function uses libnl to set DORMANT/UP operstate on interface
 * 'ifname'. It is used only in cp mode.
 *
 * We use this to change running flag on an interface.
 *
 * It does not work if the interface is not in vrf0.
 */
int sdsifd_nl_cp_if_set_operstate(const char *ifname, uint8_t operstate)
{
	struct rtnl_link *link;
	int err = 0;

	link = rtnl_link_alloc();
	rtnl_link_set_name(link, ifname);
	rtnl_link_set_operstate(link, operstate);

	if (operstate == IF_OPER_DORMANT)
		IFD_LOG(LOG_INFO, "<%s> - RUNNING", ifname);
	else
		IFD_LOG(LOG_INFO, "<%s> + RUNNING", ifname);

	err = rtnl_link_change(if_sk, link, link, 0);
	if (err)
		IFD_LOG(LOG_ERR, "could not set operstate to %d on %s (%s)", operstate, ifname, nl_geterror(err));

	rtnl_link_put(link);

	return err;
}


/*
 * this function initializes libif and libnl.
 *
 * in cp mode, we register to deletion to maintain our sdsifd_iface
 * list in case hao-ifd removes it instead of us.
 *
 * in fp mode, we initialize prepare the libif interfaces by setting
 * their userdata (ifconf structure) when there is one. By
 * initializing at start and at each netlink message reception, we are
 * sure that the value is correct at all time.
 *
 * We would need several if_sk if we were to support several netns.
 */
int sdsifd_nl_init(void)
{
	const struct iface_list *ifaces;
	struct libif_iface *iface;
#define SDSIFD_NETLINK_BUFSIZE 2097152
	int opt = SDSIFD_NETLINK_BUFSIZE;
	int err;

	if_sk = nl_socket_alloc();
	if (!if_sk) {
		IFD_LOG(LOG_ERR, "could not allocate libnl's socket");
		return -1;
	}

	nl_socket_add_membership(if_sk, RTMGRP_LINK);
	err = nl_connect(if_sk, NETLINK_ROUTE);
	if (err)
		IFD_LOG(LOG_ERR, "could not connect libnl's socket(%s)", nl_geterror(err));


	libif_start();
	libif_event_new_ctx(0, opt);

	libif_notif_add(LIBIF_F_CREATE|LIBIF_F_UPDATE,
			sdsifd_notif_new_cb,
			NULL);

	libif_notif_add(LIBIF_F_DELETE,
			sdsifd_notif_del_cb,
			NULL);

	if (sdsifd_mode == FP_MODE) {
		ifaces = libif_iface_get_allvr_list();
		LIST_FOREACH(iface, ifaces, next) {
			sdsifd_fp_set_libif_userdata(iface);
		}
	}

	return 0;
}
