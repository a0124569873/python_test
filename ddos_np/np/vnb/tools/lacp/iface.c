/*
 * Copyright 2011-2013 6WIND S.A.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/queue.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <netgraph/ng_message.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_ethgrp.h>

#include <syslog.h>
#include <event.h>
#include <libconsole.h>
#include <sys/time.h>

#include "iface.h"

#include "lacp.h"
#include <netgraph/ieee8023_slowprotocols.h>
#include <netgraph/ieee8023_tlv.h>
#include <netgraph/ieee8023ad_lacp.h>
#include "node.h"
#include "ieee8023ad_lacp_debug.h"

#include <assert.h>

/* list of all interfaces in the system with their flags */
LIST_HEAD(lacpd_iface_list, lacpd_iface);
static struct lacpd_iface_list lacpd_ifaces;

int lacpd_iface_init(void)
{
	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "Entering"));

	LIST_INIT(&lacpd_ifaces);
	return 0;
}

int lacpd_iface_destroy_all(void)
{
	struct lacpd_iface *iface;

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "Entering"));

	while ( (iface = LIST_FIRST(&lacpd_ifaces)) ) {
		LIST_REMOVE(iface, next);
		free(iface);
	}
	return 0;
}

struct lacpd_iface *lacpd_iface_lookup(const char *ifname)
{
	struct lacpd_iface *iface;

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "Entering for %s", ifname));

	LIST_FOREACH(iface, &lacpd_ifaces, next)
		if (!strncmp(ifname, iface->name, IFNAMSIZ))
			return iface;
	return NULL;
}

int lacpd_iface_update(struct lacpd_iface *iface, int flags)
{

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "Entering"));

	assert(iface != NULL);
	iface->flags = flags;
	return 0;
}

/* assume interface does not exist */
int lacpd_iface_add(const char *ifname, unsigned int k_index, uint32_t ifuid, int flags)
{
	struct lacpd_iface *iface;

	DEBUG(LOG_DEBUG, "new interface: %s\n", ifname);

	iface = calloc(1, sizeof(struct lacpd_iface));
	if (iface == NULL)
		return -1;
	snprintf(iface->name, IFNAMSIZ, "%s", ifname);
	/* this function is only called from netlink */
	iface->k_index = k_index;
	iface->portid = (ifuid ^ (ifuid >> 16)) & 0xFFFF;
	LIST_INSERT_HEAD(&lacpd_ifaces, iface, next);
	lacpd_iface_update(iface, flags);

	return 0;
}

int lacpd_iface_delete(const char *ifname)
{
	struct lacpd_iface *iface;

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "Entering for %s", ifname));

	iface = lacpd_iface_lookup(ifname);
	if (iface == NULL)
		return -1;
	LIST_REMOVE(iface, next);
	free(iface);
	return 0;
}
