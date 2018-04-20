/*
 * Copyright 2007 6WIND S.A.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <event.h>
#include <time.h>
#include <sys/queue.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <netgraph.h>
#include <netgraph/ng_filter.h>
#include <netgraph/ng_iface.h>
#include <linux/icmp.h>

#include "pingd.h"
#include "util.h"
#include "node.h"
#include "network.h"


struct node *node_create(char *name, char *fltname, char *ifname,
		uint32_t ouraddr, uint32_t peeraddr, uint32_t brdaddr)
{
	struct node *new;

	/* Create the entry */
	new = (struct node *)malloc(sizeof(struct node));
	if (new == NULL) {
		DEBUG(LOG_ERR, "not enough memory (new)\n");
		return NULL;
	}
	memset(new, 0, sizeof(struct node));

	/* Copy data */
	new->nd_name = (char *)malloc(strlen(name) + 1);
	if (new->nd_name == NULL) {
		DEBUG(LOG_ERR, "not enough memory (new->nd_name)\n");
		goto fail;
	}
	memcpy(new->nd_name, name, strlen(name) + 1);

	new->nd_fltname = (char *)malloc(strlen(fltname) + 1);
	if (new->nd_fltname == NULL) {
		DEBUG(LOG_ERR, "not enough memory (new->nd_fltname)\n");
		goto fail;
	}
	memcpy(new->nd_fltname, fltname, strlen(fltname) + 1);

	new->nd_ifname = (char *)malloc(strlen(ifname) + 1);
	if (new->nd_ifname == NULL) {
		DEBUG(LOG_ERR, "not enough memory (new->nd_ifname)\n");
		goto fail;
	}
	memcpy(new->nd_ifname, ifname, strlen(ifname) + 1);

	new->nd_ouraddr = ouraddr;
	new->nd_peeraddr = peeraddr;
	new->nd_brdaddr = brdaddr;
	new->nd_interval = PINGD_NODE_DFLT_INT;
	new->nd_robustness = PINGD_NODE_DFLT_ROB;
	new->nd_checkdelay = PINGD_NODE_DFLT_CHECK;
	new->nd_carrier = 1;
	new->nd_current_seqno = PINGD_NODE_DFLT_ROB;

	LIST_INSERT_HEAD(&nodes, new, nd_entries);
	return new;
fail:
	if (new->nd_name)
		free(new->nd_name);
	if (new->nd_fltname)
		free(new->nd_fltname);
	if (new->nd_ifname)
		free(new->nd_ifname);
	free(new);
	return NULL;
}

void node_destroy(struct node *entry)
{
	if (entry == NULL)
		return;

	LIST_REMOVE(entry, nd_entries);
	if (entry->nd_csock) {
		entry->nd_carrier = 1;
		node_setcarrier(entry);
		close(entry->nd_csock);
	}
	if (entry->nd_dsock)
		close(entry->nd_dsock);
	if (entry->nd_name)
		free(entry->nd_name);
	if (entry->nd_fltname)
		free(entry->nd_fltname);
	if (entry->nd_ifname)
		free(entry->nd_ifname);
	if (event_initialized(&entry->nd_cs_ev))
		event_del(&entry->nd_cs_ev);
	if (event_initialized(&entry->nd_ds_ev))
		event_del(&entry->nd_ds_ev);
	if (evtimer_initialized(&entry->nd_sendreq))
		evtimer_del(&entry->nd_sendreq);
	if (evtimer_initialized(&entry->nd_carriercheck))
		evtimer_del(&entry->nd_carriercheck);
	free(entry);
	return;
}

void node_destroy_all(void)
{
	struct node *entry, *next;

	for (entry = LIST_FIRST(&nodes); entry; entry = next) {
		next = LIST_NEXT(entry, nd_entries);
		node_destroy(entry);
	}
	return;
}

int node_connect(struct node *entry)
{
	struct ngm_connect ngc;
	struct ng_filter_icmp icmpfilter;
	int err;

	if (entry == NULL)
		return -EFAULT;

	/* Connect to VNB node */
	if ((err = NgMkSockNode(NULL, &entry->nd_csock, &entry->nd_dsock)) < 0) {
		DEBUG(LOG_ERR, "unable to get a VNB socket\n");
		goto fail;
	}

	snprintf(ngc.path, sizeof(ngc.path), "%s:", entry->nd_fltname);
	snprintf(ngc.ourhook, sizeof(ngc.ourhook), PINGD_NG_SOCK_HOOK_NAME);
	snprintf(ngc.peerhook, sizeof(ngc.peerhook), NG_FILTER_HOOK_DAEMON);
	if ((err = NgSendMsg(entry->nd_csock, ".", NGM_GENERIC_COOKIE,
				NGM_CONNECT, &ngc, sizeof(ngc))) < 0) {
		DEBUG(LOG_ERR, "unable to connect to node %s\n", entry->nd_name);
		goto fail;
	}

	/* Set filter to receive ICMP Echo Reply from peer with our ID */
	snprintf(ngc.path, sizeof(ngc.path), "%s:", entry->nd_fltname);
	memset(&icmpfilter, 0, sizeof(icmpfilter));
	icmpfilter.icmp_saddr = entry->nd_peeraddr;
	icmpfilter.icmp_daddr = entry->nd_ouraddr;
	icmpfilter.icmp_type = ICMP_ECHOREPLY;
	icmpfilter.icmp_echo_id = ping_id;
	if ((err = NgSendMsg(entry->nd_csock, ngc.path, NGM_FILTER_COOKIE,
				NGM_FILTER_SET_ICMP, &icmpfilter, sizeof(icmpfilter))) < 0) {
		DEBUG(LOG_ERR, "unable to set filter for ICMP Echo Reply\n");
		goto fail;
	}

	/* Set filter to receive ICMP Echo Request from peer on broadcast addr */
	if (entry->nd_brdaddr) {
		snprintf(ngc.path, sizeof(ngc.path), "%s:", entry->nd_fltname);
		memset(&icmpfilter, 0, sizeof(icmpfilter));
		icmpfilter.icmp_saddr = entry->nd_peeraddr;
		icmpfilter.icmp_daddr = entry->nd_brdaddr;
		icmpfilter.icmp_type = ICMP_ECHO;
		icmpfilter.icmp_echo_id = 0;
		if ((err = NgSendMsg(entry->nd_csock, ngc.path, NGM_FILTER_COOKIE,
						NGM_FILTER_SET_ICMP, &icmpfilter,
						sizeof(icmpfilter))) < 0) {
			DEBUG(LOG_ERR, "unable to set filter for ICMP Echo Request\n");
			goto fail;
		}
	}

	/* Set filter to receive ICMP Echo Request from peer to 255.255.255.255 */
	if (broadcast && entry->nd_brdaddr != 0xffffffff) {
		snprintf(ngc.path, sizeof(ngc.path), "%s:", entry->nd_fltname);
		memset(&icmpfilter, 0, sizeof(icmpfilter));
		icmpfilter.icmp_saddr = entry->nd_peeraddr;
		icmpfilter.icmp_daddr = 0xffffffff;
		icmpfilter.icmp_type = ICMP_ECHO;
		icmpfilter.icmp_echo_id = 0;
		if ((err = NgSendMsg(entry->nd_csock, ngc.path, NGM_FILTER_COOKIE,
						NGM_FILTER_SET_ICMP, &icmpfilter,
						sizeof(icmpfilter))) < 0) {
			DEBUG(LOG_ERR, "unable to set filter for ICMP Echo Request\n");
			goto fail;
		}
	}

	/* Set event for csock and dscok */
	event_set(&entry->nd_cs_ev, entry->nd_csock, EV_READ | EV_PERSIST, csock_input, entry);
	event_add(&entry->nd_cs_ev, NULL);
	event_set(&entry->nd_ds_ev, entry->nd_dsock, EV_READ | EV_PERSIST, dsock_input, entry);
	event_add(&entry->nd_ds_ev, NULL);

	return 0;
fail:
	if (entry->nd_csock)
		close(entry->nd_csock);
	if (entry->nd_dsock)
		close(entry->nd_dsock);
	return err;
}

int node_set_carriertimer(struct node *entry)
{
	struct timeval tm;

	if (entry == NULL)
		return -EFAULT;

	if (!evtimer_pending(&entry->nd_carriercheck, &tm)) {
		tm.tv_sec = entry->nd_checkdelay;
		tm.tv_usec = 0;
		evtimer_set(&entry->nd_carriercheck, check_carrier, (void *)entry);
		evtimer_add(&entry->nd_carriercheck, &tm);
	}
	return 0;
}

int node_set_pingtimer(struct node *entry)
{
	struct timeval tm;

	if (entry == NULL)
		return -EFAULT;

	tm.tv_sec = entry->nd_interval;
	tm.tv_usec = 0;
	evtimer_set(&entry->nd_sendreq, send_echorequest_event, (void *)entry);
	evtimer_add(&entry->nd_sendreq, &tm);
	return 0;
}

struct node *node_findbyname(char *name)
{
	struct node *entry;

	LIST_FOREACH(entry, &nodes, nd_entries)
		if (!strcmp(name, entry->nd_name))
			return entry;

	return NULL;
}

struct node *node_findbyaddr(uint32_t ouraddr, uint32_t peeraddr)
{
	struct node *entry;

	LIST_FOREACH(entry, &nodes, nd_entries)
		if (entry->nd_ouraddr == ouraddr &&
		    entry->nd_peeraddr == peeraddr)
			return entry;

	return NULL;
}

int node_setcarrier(struct node *entry)
{
	char path[NG_PATHLEN + 1];
	struct ng_filter_icmp icmpfilter;
	int err;

	snprintf(path, sizeof(path), "%s:", entry->nd_ifname);
	if ((err = NgSendMsg(entry->nd_csock, path, NGM_IFACE_COOKIE,
					NGM_IFACE_SET_CARRIER, &entry->nd_carrier,
					sizeof(entry->nd_carrier))) < 0) {
		DEBUG(LOG_ERR, "unable to set carrier status for %s\n", entry->nd_name);
		goto end;
	}

	/* Add or delete filter to receive all ICMP Echo Request from peer */
	snprintf(path, sizeof(path), "%s:", entry->nd_fltname);
	memset(&icmpfilter, 0, sizeof(icmpfilter));
	icmpfilter.icmp_saddr = entry->nd_peeraddr;
	icmpfilter.icmp_daddr = entry->nd_ouraddr;
	icmpfilter.icmp_type = ICMP_ECHO;
	icmpfilter.icmp_echo_id = 0;
	if (entry->nd_carrier) {
		if ((err = NgSendMsg(entry->nd_csock, path, NGM_FILTER_COOKIE,
						NGM_FILTER_DEL_ICMP, &icmpfilter,
						sizeof(icmpfilter))) < 0) {
			DEBUG(LOG_ERR, "unable to remove filter for ICMP Echo Request\n");
			goto end;
		}
	} else {
		if ((err = NgSendMsg(entry->nd_csock, path, NGM_FILTER_COOKIE,
						NGM_FILTER_SET_ICMP, &icmpfilter,
						sizeof(icmpfilter))) < 0) {
			DEBUG(LOG_ERR, "unable to set filter for ICMP Echo Request\n");
			goto end;
		}
	}

end:
	return err;
}
