/*
 * Copyright 2013 6WIND S.A.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <event.h>

#include "fpc.h"
#include "cm_pub.h"
#include "cm_priv.h"
#include "cm_sock.h"
#ifdef CONFIG_PORTS_CACHEMGR_NETNS
#include "libvrf.h"
#endif

static FILE *generic_proc_open(const char *env, const char *name,
		__attribute__ ((unused)) uint32_t vrfid)
{
	const char *p = getenv(env);
	char store[128];
#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	FILE *f;
#endif

	if (!p) {
		p = getenv("PROC_ROOT") ? : "/proc";
		snprintf(store, sizeof(store)-1, "%s/%s", p, name);
		p = store;
	}

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	libvrf_change(vrfid);
	f = fopen(p, "r");
	libvrf_back();
	return f;
#else
	return fopen(p, "r");
#endif
}

void cm_proc_packet_dump(uint32_t vrfid)
{
	FILE *file = NULL;
	char buf[256];
	int type;
	int prot;
	int ifindex;
	int state;
	int rq;
	int uid;
	int ino;
	unsigned long long sk;
	struct cp_bpf bpf;
	struct cm_iface *ifp;

	file = generic_proc_open("PROC_NET_PACKET", "net/packet", vrfid);
	if (file == NULL)
		goto end;

	/* Remove header line */
	if (fgets(buf, sizeof(buf)-1, file) == NULL)
		goto end;

	while (fgets(buf, sizeof(buf)-1, file)) {
		sscanf(buf, "%llx %*d %d %x %d %d %u %u %u",
		       &sk, &type, &prot, &ifindex, &state, &rq, &uid, &ino);

		if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
			syslog(LOG_DEBUG, "BPF: ifindex: %d\n", ifindex);

		/* Ignore BPF created by raw sockets like in fpsd */
		if (prot == CM_BPF_FPTUN_PROTOCOL)
			continue;

		memset(&bpf, 0, sizeof(bpf));
		ifp = iflookup(ifindex, vrfid);
		/* In case of tcpdump -i any, bpf_ifindex is 0, thus ifp is
		 * NULL.
		 */
		bpf.ifuid = ifp ? ifp->ifuid : 0;

		/* We don't set any BPF filter, we will use the default one. */
		cm2cp_bpf_update(0, &bpf);
	}
end:
	if (file != NULL)
		fclose(file);
}

static void cm_proc_packet_dump_sock(int fd, struct nlsock *cmn)
{
	cm_proc_packet_dump(cmn->vrfid);
}

static void event_cm_proc_packet_dump(int sock, short evtype, void *data)
{
	netlink_for_each(cm_proc_packet_dump_sock, 0 /* unused fd */, CM_DIAG);
	cm_proc_packet_start_timer();
}

void cm_proc_packet_start_timer(void)
{
	struct event *event = vrf_get_diag_ev(0);
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = 300 * 1000; /* every 300ms */
	evtimer_assign(event, cm_event_base, event_cm_proc_packet_dump, NULL);
	evtimer_add(event, &tv);
}

void cm_proc_packet_stop_timer(void)
{
	struct event *event = vrf_get_diag_ev(0);
	if (event)
		evtimer_del(event);
}
