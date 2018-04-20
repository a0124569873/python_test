/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *
 *                   Inits for the Cache Manager (CM)
 * $Id: cm_init.c,v 1.15 2010-10-21 14:56:21 dichtel Exp $
 ***************************************************************
 */

#include <sys/types.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter/nfnetlink.h>

#include "fpc.h"
#include "cm_pub.h"
#include "cm_priv.h"

void vrf_init (void);
void vrf_close (void);
static int sysctl_set(const char *path, int value)
{
	int fd, res = 0;
	char buf[16];

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd < 0)
		return -1;

	snprintf(buf, sizeof(buf), "%d", value);
	if (write(fd, buf, strlen(buf)) < 0)
		res = -1;

	close(fd);
	return res;
}

/*
 * This is terminated in fpm_init() with initialization of
 * the first CM/FPM messages (probably using the netlink
 * command sockets), and having some CM internal used (such
 * as iface list ...)
 * The very last thing to activate is the spontaneous Kernel
 * reports through the 'data' netlink socket.
 *   SO: keep this list of inits ORDERED
 */
void
cm_init (void)
{
	/*
	 * Vrf Init
	 */
	vrf_init();

	sysctl_set(CM_SYSCTL_NFCT_LIBERAL, 1);

	/*
	 * Iptc Init
	 */
#if defined(NF_NETLINK_TABLES) || defined(CONFIG_CACHEMGR_AUDIT)
	cm_iptc_init();
#endif

	return;
}

void
cm_destroy (void)
{
	/*
	 * Vrf Close
	 */
	vrf_close();

	sysctl_set(CM_SYSCTL_NFCT_LIBERAL, 0);

	/*
	 * Iptc Exit
	 */
#if defined(NF_NETLINK_TABLES) || defined(CONFIG_CACHEMGR_AUDIT)
	cm_iptc_exit();
#endif

	return;
}
