
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "fpc.h"
#include "cm_pub.h"
#include "cm_sock.h"
#include "genl_base.h"
#include "cm_priv.h"
#include "cm_netlink.h"
#ifdef CONFIG_PORTS_CACHEMGR_NETNS
#include "libvrf.h"
#endif

/*
 * This MUST not be shared by CM client, for it is meant to
 * track API evolution. So keep it ou of .h files
 */
#define FPC_API_MAJOR   14
#define FPC_API_MINOR   0

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
static struct event *event_vrf = NULL;
static int max_vrf = 0;
static int vrf_fd = -1;
/* nlsock_vrf table size is 2048 for nets, as we have one netlink socket per type per vrf */
#define MAX_NL_SOCK_VRF 2048
#else
/* nlsock_vrf table size is 1 for , as we have one netlink socket per type for all vrfs */
#define MAX_NL_SOCK_VRF 1
#endif
static struct nlsock_vr nlsock_vrf [MAX_NL_SOCK_VRF];

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
/* New VRF.  */
static void
vrf_add(int id, void *data)
{
	int i;
	struct nlsock *s;

	if (id > MAX_NL_SOCK_VRF) {
		syslog(LOG_ERR, "%s: invalid vrf id%d\n", __func__, id);
		return;
	}

	if (nlsock_vrf[id].valid) {
		syslog(LOG_ERR, "%s: vrf socket %d is not valid\n", __func__, id);
		return;
	}

	nlsock_vrf[id].valid = 1;

	if (id > max_vrf)
		max_vrf = id;

	if (id && (libvrf_change(id) < 0)) {
		syslog(LOG_ERR, "%s: libvrf_change failed for vrf %d\n", __func__, id);
		return;
	}

	s = nlsock_vrf[id].cm_nlsock;
	for (i = 0; i < CM_MAX; i++) {
		s[i].vrfid = id;
		s[i].init_failed = 1;
		s[i].hooks = &nlsock_hooks[i];
		if (nlsock_hooks[i].vrf0_only && id != 0)
			continue;
		if (nlsock_hooks[i].init) {
			s[i].init_failed = 0;
			nlsock_hooks[i].init(&s[i]);
		}
	}

	if (id && (libvrf_back() < 0)) {
		syslog(LOG_ERR, "%s: libvrf_back failed for vrf %d\n", __func__, id);
		return;
	}
	/*
	 * Now the context is quite initialized
	 * except for the data socket at CPDPs cnx
	 * we can prepare initial messages Q
	 *   - RESET
	 *   - FLUSH ??
	 *   - Phys I/F after netlink scan
	 */
	fpm_process_queue(1);
	for (i = 0; i < CM_MAX; i++)
		if (nlsock_hooks[i].dump && !s[i].init_failed)
			nlsock_hooks[i].dump(&s[i]);
	fpm_process_queue(0);
}

/* Destroy VRF.  */
static void
vrf_del(int id, void *data)
{
	int i;
	struct nlsock *s;

	if (id > MAX_NL_SOCK_VRF) {
		syslog(LOG_ERR, "%s: invalid vrf id%d\n", __func__, id);
		return;
	}

	if (!nlsock_vrf[id].valid) {
		syslog(LOG_ERR, "%s: vrf socket %d is not valid\n", __func__, id);
		return;
	}

	nlsock_vrf[id].valid = 0;

	/*
	 * CM internals
	 */
	nlbase_clear(id);

	s = nlsock_vrf[id].cm_nlsock;
	for (i = 0; i < CM_MAX; i++)
		if (nlsock_hooks[i].destroy && !s[i].init_failed)
			nlsock_hooks[i].destroy(&s[i]);

	cm2cp_vrf_del(id);
}

void
netlink_for_each(void (*func)(int fd, struct nlsock *cmn),
			int fd, int type)
{
	int i = 0;

	for (; i <= max_vrf; i++) {
		if (!nlsock_vrf[i].valid)
			continue;
		func(fd, &nlsock_vrf[i].cm_nlsock[type]);
	}
}

static void
vrf_read (int fd, short event, void *data)
{
	libvrf_monitor_event(vrf_add, vrf_del, data);
}

static void
vrf_monitor_init(void)
{
	vrf_fd = libvrf_monitor_init();
	if (vrf_fd < 0) {
		syslog(LOG_ERR, "%s: failed to get fd for monitoring\n", __func__);
		return;
	}
	event_vrf = event_new(cm_event_base, vrf_fd,
	           EV_READ | EV_PERSIST,
	           vrf_read, NULL);
	if (event_add(event_vrf, NULL)) {
		syslog(LOG_ERR, "%s: failed to add event for monitoring\n", __func__);
		close(vrf_fd);
		vrf_fd = -1;
	}
}

static void
vrf_monitor_dump(void)
{
	if (libvrf_iterate(vrf_add, NULL) < 0)
		syslog(LOG_ERR, "%s: failed to open netns directory\n", __func__);
}

static void
vrf_monitor_close(void)
{
	if (vrf_fd >= 0) {
		if (event_vrf) {
			event_free(event_vrf);
			event_vrf = NULL;
		}
		close(vrf_fd);
	}
	vrf_fd = -1;
}

struct nlsock *
vrf_get_nlsock(int vrfid, int type)
{
	if (!nlsock_vrf[vrfid].valid)
		return NULL;
	if (type < CM_MAX)
		return &nlsock_vrf[vrfid].cm_nlsock[type];

	return NULL;
}

struct event *
vrf_get_diag_ev(int vrfid)
{
	return &nlsock_vrf[vrfid].diag_dump_ev;
}

#else
static void
vrf_add(int id, void *data)
{
	int i;
	struct nlsock *s;

	/* should be called only for id 0 */
	if (id)
		return;

	s = nlsock_vrf[0].cm_nlsock;
	for (i = 0; i < CM_MAX; i++)
		if (nlsock_hooks[i].init) {
			s[i].vrfid = 0;
			s[i].init_failed = 0;
			s[i].hooks = &nlsock_hooks[i];
			nlsock_hooks[i].init(&s[i]);
		}

	/*
	 * Now the context is quite initialized
	 * except for the data socket at CPDPs cnx
	 * we can prepare initial messages Q
	 *   - RESET
	 *   - FLUSH ??
	 *   - Phys I/F after netlink scan
	 */
	fpm_process_queue(1);
	for (i = 0; i < CM_MAX; i++)
		if (nlsock_hooks[i].dump && !s[i].init_failed)
			nlsock_hooks[i].dump(&s[i]);
	fpm_process_queue(0);
}

/* Destroy VRF.  */
static void
vrf_del(int id, void *data)
{
	int i;
	struct nlsock *s;

	/* should be called only for id 0 */
	if (id)
		return;

	/*
	 * CM internals
	 */
	nlbase_clear(0);

	s = nlsock_vrf[0].cm_nlsock;
	for (i = 0; i < CM_MAX; i++)
		if (nlsock_hooks[i].destroy && !s[i].init_failed)
			nlsock_hooks[i].destroy(&s[i]);
}

void
netlink_for_each(void (*func)(int fd, struct nlsock *cmn),
			int fd, int type)
{
	func(fd, &nlsock_vrf[0].cm_nlsock[type]);
}

struct nlsock *
vrf_get_nlsock(int vrfid, int type)
{
	if (type < CM_MAX)
		return &nlsock_vrf[0].cm_nlsock[type];

	return NULL;
}

struct event *
vrf_get_diag_ev(int vrfid)
{
	return &nlsock_vrf[0].diag_dump_ev;
}
#endif

void
vrf_init (void)
{
	memset (nlsock_vrf, 0, sizeof nlsock_vrf);
	/*
	 * Vrf monitor Init
	 */
	nlbase_init();

	/* Send reset before starting the dump */
	cm2cp_reset(FPC_API_MAJOR, FPC_API_MINOR);

#ifndef CONFIG_PORTS_CACHEMGR_NETNS
	vrf_add(0, NULL);
#else
	vrf_monitor_init();
	vrf_monitor_dump();
#endif

	/* If all dumps done, warn fpm */
	cm_nl_dump_in_progress--;
	if (cm_nl_dump_in_progress == 0) {
		/* Leave 1 in cm_nl_dump_in_progress to avoid graceful_done message */
		cm_nl_dump_in_progress = 1;

		cm2cp_graceful_done(0);
	}
}

void
vrf_close (void)
{
#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	int i;

	vrf_monitor_close();

	for (i = 0; i <= max_vrf; i++) {
		if (!nlsock_vrf[i].valid)
			continue;
		vrf_del(i, NULL);
	}
#else
	vrf_del(0, NULL);
#endif
}
