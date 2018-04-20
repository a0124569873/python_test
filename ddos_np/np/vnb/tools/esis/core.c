/*
 * Copyright 2007-2013 6WIND S.A.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <event.h>

#include <syslog.h>
#include "esisd.h"


/*
 * cb for periodical ES Hello announce (one per interface)
 */
void
es_announce_cb (int fd, short event, void *param)
{
	struct iface *ifp = (struct iface *)param;
	struct timeval tm;

	send_es_hello (ifp);

	/* Re-arm timer */
	tm.tv_sec  = ES_HELLO_INTERVAL;
	tm.tv_usec = 0;
	evtimer_add (&ifp->if_es_announce, &tm);

	return;
}

/*
 * Manage a single OSI/MAC association, may be called several time for
 * a single ES Hello message
 */
void
receive_es_hello (struct iface *ifp, struct osi_addr *osi,
                  struct mac_addr *mac, u_int16_t hold)
{
	struct es_entry *es;
	struct timeval tm;
	int new = 0;

	LIST_FOREACH (es, &(ifp->if_es_head), es_link) {
		if (memcmp (osi, &(es->es_osi), sizeof(struct osi_addr)) == 0)
			break;
	}
	/* Create a new one */
	if (!es) {
		es = malloc (sizeof *es);
		if (!es)
			return;
		memset (es, 0, sizeof(*es));
		es->es_osi = *osi;
		es->es_ifp = ifp;
		evtimer_set (&(es->es_evt), es_entry_aging, es);
		LIST_INSERT_HEAD(&(ifp->if_es_head), es, es_link);
		new = 1;
	}
	/* or cancel running timer */
	else {
		if (es->es_hold)
			evtimer_del (&(es->es_evt));
		/* Only permanent can override  permanent entry */
		else if (hold)
			return;
	}
	/* update MAC if need be, and start timer */
	if (memcmp (&(es->es_mac), mac, sizeof (*mac))) {
		es->es_mac = *mac;
		notify_es (new ? OSI_ADD : OSI_CHANGE, es);
	}
	es->es_hold = hold;
	time (&(es->es_date));
	if (hold) {
		tm.tv_sec  = hold;
		tm.tv_usec = 0;
		evtimer_add (&(es->es_evt), &tm);
	}

	return;
}

/*
 * Manage a single OSI/MAC association, may be called several time for
 * a single IS Hello message
 */
void
receive_is_hello (struct iface *ifp, struct osi_addr *osi,
                  struct mac_addr *mac, u_int16_t hold)
{
	struct is_entry *is;
	struct timeval tm;
	int new = 0;

	LIST_FOREACH (is, &(ifp->if_is_head), is_link) {
		if (memcmp (osi, &(is->is_osi), sizeof(struct osi_addr)) == 0)
			break;
	}
	/* Create a new one */
	if (!is) {
		is = malloc (sizeof *is);
		if (!is)
			return;
		memset (is, 0, sizeof(*is));
		is->is_osi = *osi;
		is->is_ifp = ifp;
		evtimer_set (&(is->is_evt), is_entry_aging, is);
		LIST_INSERT_HEAD(&(ifp->if_is_head), is, is_link);
		new = 1;
	}
	/* or cancel running timer */
	else {
		if (is->is_hold)
			evtimer_del (&(is->is_evt));
		/* Only permanent can override  permanent entry */
		else if (hold)
			return;
	}
	/* update MAC if need be, and start timer */
	if (memcmp (&(is->is_mac), mac, sizeof (*mac))) {
		is->is_mac = *mac;
		notify_is (new ? OSI_ADD : OSI_CHANGE, is);
	}
	is->is_hold = hold;
	time (&(is->is_date));
	if (hold) {
		tm.tv_sec  = hold;
		tm.tv_usec = 0;
		evtimer_add (&(is->is_evt), &tm);
	}

	return;
}

/*
 * Manage a single Redirect,
 */
void
receive_redirect (struct iface *ifp, struct osi_addr *tgt,
                  struct mac_addr *mac, struct osi_addr *gw,
                  u_int16_t hold)
{
	struct rd_entry *rd;
	struct timeval tm;
	int new = 0;
	struct osi_addr empty_osi;

	if (gw == NULL) {
		memset (&empty_osi, 0, sizeof(empty_osi));
		gw = &empty_osi;
	}

	LIST_FOREACH (rd, &(ifp->if_rd_head), rd_link) {
		if (memcmp (tgt, &(rd->rd_es_osi), sizeof(struct osi_addr)) == 0)
			break;
	}
	/* Create a new one */
	if (!rd) {
		rd = malloc (sizeof *rd);
		if (!rd)
			return;
		memset (rd, 0, sizeof(*rd));
		rd->rd_es_osi = *tgt;
		rd->rd_ifp = ifp;
		evtimer_set (&(rd->rd_evt), rd_entry_aging, rd);
		LIST_INSERT_HEAD(&(ifp->if_rd_head), rd, rd_link);
		new = 1;
	}
	/* or cancel running timer */
	else {
		if (rd->rd_hold)
			evtimer_del (&(rd->rd_evt));
		/* Only permanent can override  permanent entry */
		else if (hold)
			return;
	}
	/* Update optional gw */
	rd->rd_is_osi = *gw;
	/* update MAC if need be, and start timer */
	if (memcmp (&(rd->rd_is_mac), mac, sizeof (*mac))) {
		rd->rd_is_mac = *mac;
		notify_rd (new ? OSI_ADD : OSI_CHANGE, rd);
	}
	rd->rd_hold = hold;
	time (&(rd->rd_date));
	if (hold) {
		tm.tv_sec  = hold;
		tm.tv_usec = 0;
		evtimer_add (&(rd->rd_evt), &tm);
	}

	return;
}

/*
 * Kill a single ES entry
 */
int
remove_es_hello (struct iface *ifp, struct osi_addr *osi)
{
	struct es_entry *es;

	LIST_FOREACH (es, &(ifp->if_es_head), es_link) {
		if (memcmp (osi, &(es->es_osi), sizeof(struct osi_addr)) == 0)
			break;
	}
	if (!es)
		return EINVAL;
	if (es->es_hold)
		evtimer_del (&(es->es_evt));
	es_entry_aging (0, 0, (void *)es);
	return;
}

/*
 * Kill a single IS entry
 */
int
remove_is_hello (struct iface *ifp, struct osi_addr *osi)
{
	struct is_entry *is;

	LIST_FOREACH (is, &(ifp->if_is_head), is_link) {
		if (memcmp (osi, &(is->is_osi), sizeof(struct osi_addr)) == 0)
			break;
	}
	if (!is)
		return EINVAL;
	if (is->is_hold)
		evtimer_del (&(is->is_evt));
	is_entry_aging (0, 0, (void *)is);
	return;
}

/*
 * Kill a single RD entry
 */
int
remove_redirect (struct iface *ifp, struct osi_addr *osi)
{
	struct rd_entry *rd;

	LIST_FOREACH (rd, &(ifp->if_rd_head), rd_link) {
		if (memcmp (osi, &(rd->rd_es_osi), sizeof(struct osi_addr)) == 0)
			break;
	}
	if (!rd)
		return EINVAL;
	if (rd->rd_hold)
		evtimer_del (&(rd->rd_evt));
	rd_entry_aging (0, 0, (void *)rd);
	return;
}

/*
 * Removes expired ES entry
 */
void
es_entry_aging (int fd, short event, void *param)
{
	struct es_entry *es = (struct es_entry *)param;

	LIST_REMOVE (es, es_link);
	notify_es (OSI_DEL, es);
	free (es);
	return;
}

/*
 * Removes expired IS entry
 */
void
is_entry_aging (int fd, short event, void *param)
{
	struct is_entry *is = (struct is_entry *)param;

	LIST_REMOVE (is, is_link);
	notify_is (OSI_DEL, is);
	free (is);
	return;
}

/*
 * Removes expired RD entry
 */
void
rd_entry_aging (int fd, short event, void *param)
{
	struct rd_entry *rd = (struct rd_entry *)param;

	LIST_REMOVE (rd, rd_link);
	notify_rd (OSI_DEL, rd);
	free (rd);
	return;
}

struct an_entry *
/*
 * This is a loose get(), i.e. do not look at the NSEL
 */
osi_get_an (struct iface *ifp, struct osi_addr *osi)
{
	struct an_entry *an = NULL;
	LIST_FOREACH (an, &(ifp->if_an_head), an_link) {
		/* CMP is done on osi_len and NOT osi_len + 1 to let NSEL free */
		if (memcmp (osi, &(an->an_osi), an->an_osi.osi_len) == 0)
			break;
	}
	return an;
}

struct mac_addr *
osi_get_l2 (struct iface *ifp, struct osi_addr *osi)
{
	struct es_entry *es = NULL;
	struct rd_entry *rd = NULL;
	struct is_entry *is = NULL;

	dump_osi (osi, dump_buf1, SZ_DBUF, NULL);
	log_msg (LOG_DEBUG, 0, " L2 resolv for : %s \n --> ", dump_buf1);
	/* First scan ES table */
	LIST_FOREACH (es, &(ifp->if_es_head), es_link) {
		if (memcmp (osi, &(es->es_osi), es->es_osi.osi_len + 1) == 0)
			break;
	}
	if (es) {
		dump_mac (&(es->es_mac), dump_buf1, SZ_DBUF, NULL);
		log_msg (LOG_DEBUG, 0, "(ES table) %s\n", dump_buf1);
		return (&(es->es_mac));
	}

	/* Then RD table */
	LIST_FOREACH (rd, &(ifp->if_rd_head), rd_link) {
		if (memcmp (osi, &(rd->rd_es_osi), rd->rd_es_osi.osi_len + 1) == 0)
			break;
	}
	if (rd) {
		dump_mac (&(rd->rd_is_mac), dump_buf1, SZ_DBUF, NULL);
		log_msg (LOG_DEBUG, 0, "(RD table) %s\n", dump_buf1);
		return (&(rd->rd_is_mac));
	}

	is = LIST_FIRST (&(ifp->if_is_head));
	if (is) {
		dump_mac (&(is->is_mac), dump_buf1, SZ_DBUF, NULL);
		log_msg (LOG_DEBUG, 0, "(IS table) %s\n", dump_buf1);
		return (&(is->is_mac));
	}

	log_msg (LOG_DEBUG, 0, " Failure\n");
	return NULL;
}
