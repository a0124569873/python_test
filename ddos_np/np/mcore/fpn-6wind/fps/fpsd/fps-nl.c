/*
 * Copyright 2013 6WIND S.A.
 */

#include <stdio.h>
#include <errno.h>
#include <netlink/netlink.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/link.h>

/* net/if.h conflicts with linux/if.h included by libnl */
extern unsigned int if_nametoindex(const char *ifname);
#include "fps-nl.h"

static struct nl_sock *nl_sk;

int fps_nl_init(void)
{
	int err;

	nl_sk = nl_socket_alloc();
	if ((err = nl_connect(nl_sk, NETLINK_ROUTE)) < 0) {
		nl_perror(err, "Unable to connect socket");
		return err;
	}

	return 0;
}

static int nl_get_stats(char *devname, struct rtnl_link **result)
{
	int err;

	/* Only kernel >= 2.6.34 accepts GETLINK with ifindex 0 and ifname,
	 * so compute ifindex.
	 */

	/* TODO: handle the case of physical ports in another namespace */
	unsigned ifindex = if_nametoindex(devname);
	err = rtnl_link_get_kernel(nl_sk, ifindex, devname, result);
	if (err < 0) {
		nl_perror(err, "rtnl_link_get_kernel");
		return -1;
	}

	return 0;
}

int fps_nl_get_stats(char *devname, struct fps_nl_stats *stats)
{
	struct rtnl_link *res;
	int err;

	err = nl_get_stats(devname, &res);
	if (err)
		return err;

	stats->rx_packets = rtnl_link_get_stat(res, RTNL_LINK_RX_PACKETS);
	stats->tx_packets = rtnl_link_get_stat(res, RTNL_LINK_TX_PACKETS);
	stats->rx_bytes = rtnl_link_get_stat(res, RTNL_LINK_RX_BYTES);
	stats->tx_bytes = rtnl_link_get_stat(res, RTNL_LINK_TX_BYTES);

	rtnl_link_put(res);

	return 0;
}
