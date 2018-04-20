/*
 * Copyright(c) 2013 6WIND S.A.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <event.h>


#include <netlink/msg.h>

#include "fpc.h"
#include "cm_netlink.h"
#include "cm_pub.h"
#include "cm_priv.h"
#include "cm_sock.h"

#include <linux/connector.h>
#include <linux/cn_proc.h>

#define APPS_MAX 16
struct app {
	int present;
	unsigned pid;
};

struct cmn_priv {
	struct app apps[APPS_MAX];
	struct event *event;
};

#define cmn_priv(c) ((struct cmn_priv *)((c)->priv))

#define SIZE_PRIV sizeof(struct cmn_priv)

static int is_present_pid(struct app *apps, unsigned int pid)
{
	int i;

	for (i = 0; i < APPS_MAX; i++)
		if (apps[i].present == 1 && apps[i].pid == pid)
			return 1;

	return 0;
}

static int is_empty_pid(struct app *apps)
{
	int i;

	for (i = 0; i < APPS_MAX; i++)
		if (apps[i].present == 1)
			return 0;

	return 1;
}

static int add_pid(struct app *apps, unsigned int pid)
{
	int i;

	/* avoid any duplicate */
	if (is_present_pid(apps, pid))
		return 0;

	for (i = 0; i < APPS_MAX; i++)
		if (apps[i].present == 1 && apps[i].pid == pid)
			return 0;

	for (i = 0; i < APPS_MAX; i++)
		if (apps[i].present == 0) {
			apps[i].present = 1;
			apps[i].pid = pid;
			return 0;
		}

	return -1;
}

static void del_pid(struct nlsock *cmn, unsigned int pid)
{
	struct app *apps = cmn_priv(cmn)->apps;
	int i;

	for (i = 0; i < APPS_MAX; i++)
		if (apps[i].present == 1 && apps[i].pid == pid) {
			apps[i].present = 0;
			break;
		}
}

static void check_new_pid(struct nlsock *cmn, unsigned pid)
{
	struct app *apps = cmn_priv(cmn)->apps;
	char stat_path[32];
	char name[32];
	FILE* f;

	/* /proc/<pid>/stat is "pid (name) ..." */
	snprintf(stat_path, sizeof(stat_path), "/proc/%u/stat", pid);
	f = fopen(stat_path,"r");
	if (f == NULL) {
		/* if it already disappeared, remove any record */
		del_pid(cmn, pid);
	} else {
		int n = fscanf(f, "%*d (%[^)])", name);
		fclose(f);

		if (n != EOF && n >= 1 && bpf_match_pattern(name)) {
			add_pid(apps, pid);
			/* Don't call dump_bpf() immediatly: the BPF is probably not
			 * yet announced in /proc/net/packet or via netlink DIAG.
			 * Prefer to schedule at next 300ms.
			 */
			cm_connector_keep_alive();
		}
	}
}

int cm_nl_getconnector(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *h = nlmsg_hdr(msg);
	struct cn_msg *cn_msg = NLMSG_DATA(h);
	struct proc_event *ev = (struct proc_event *)cn_msg->data;
	struct nlsock *cmn = arg;

	switch(ev->what){
		case PROC_EVENT_EXEC:
			check_new_pid(cmn, ev->event_data.exec.process_pid);
			break;
		case PROC_EVENT_EXIT:
			del_pid(cmn, ev->event_data.exit.process_pid);
			break;
		default:
			break;
	}

	return 0;
}

/* func_packet_dump() scans BPF, sends updates to FPM, and
 * call cm_connector_keep_alive() if an update was sent.
 */

static void dump_bpf_per_vrf(int fd, struct nlsock *cmn)
{
	uint32_t vrfid = cmn->vrfid;

#ifdef CONFIG_CACHEMGR_DIAG
	if (cmn_socket_is_alive(cmn))
		cm_nldiag_packet_dump(vrfid);
	else
#endif
		cm_proc_packet_dump(vrfid);
}

static void dump_bpf(void)
{
	netlink_for_each(dump_bpf_per_vrf, 0 /* unused fd */, CM_DIAG);
	cm_connector_keep_alive();
}

static void event_dump_bpf(int sock, short evtype, void *data)
{
	struct nlsock *cmn = data;
	struct app *apps = cmn_priv(cmn)->apps;

	if (!is_empty_pid(apps))
		dump_bpf();
}

/* To be called if an update has been sent. The caller may pass
 * its vrfid value, but we just use a single socket in VRF-0
 */
void cm_connector_keep_alive()
{
	struct nlsock *cmn = vrf_get_nlsock(0, CM_CONNECTOR);
	struct event *event;
	struct timeval tv;

	if (cmn == NULL)
		return;

	event = cmn_priv(cmn)->event;

	/* Caution: cm_connector_keep_alive() is called on netlink
	 * connector event, this timer event may be set already.
	 */
	if (event && evtimer_initialized(event) && evtimer_pending(event, NULL))
		return;

	tv.tv_sec = 0;
	tv.tv_usec = 300 * 1000; /* every 300ms */
	event = evtimer_new(cm_event_base, event_dump_bpf, cmn);
	evtimer_add(event, &tv);
}

static void cm_bpf_keep_alive_stop(void)
{
	struct nlsock *cmn = vrf_get_nlsock(0, CM_CONNECTOR);
	struct event *event;

	if (cmn == NULL)
		return;

	event = cmn_priv(cmn)->event;

	if (event) {
		event_free(event);
		cmn_priv(cmn)->event = NULL;
	}
}

int cm_nl_connector_start(struct nlsock *cmn)
{
	struct nl_sock *sk = cmn->sk;
	struct cn_cmd {
		struct cn_msg hdr;
		enum proc_cn_mcast_op op;
	} cn_cmd;

	if (sk == NULL)
		return -1;

	if (cm_bpf_notify == CM_BPF_NEVER)
		return -1;

	/* We will hear about application in init_net only, one
	 * socket is enough.
	 */
	if (cmn->vrfid != 0)
		return 0;

	cmn->priv = malloc(SIZE_PRIV);
	if (cmn->priv == NULL)
		return -1;

	memset(cmn->priv, 0, SIZE_PRIV);

	cn_cmd.hdr.id.idx = CN_IDX_PROC;
	cn_cmd.hdr.id.val = CN_VAL_PROC;
	cn_cmd.hdr.seq = 0;
	cn_cmd.hdr.ack = 0;
	cn_cmd.hdr.len = sizeof(enum proc_cn_mcast_op);
	cn_cmd.op = PROC_CN_MCAST_LISTEN;

	if (nl_send_simple(sk, NLMSG_DONE, 0, &cn_cmd, sizeof(cn_cmd)) < 0) {
		syslog(LOG_ERR, "Could not initialize connector\n");
		return -1;
	}

	return 0;
}

void cm_nl_connector_stop(struct nlsock *cmn)
{
	struct nl_sock *sk = cmn->sk;
	struct cn_cmd {
		struct cn_msg hdr;
		enum proc_cn_mcast_op op;
	} cn_cmd;

	if (sk == NULL)
		return;

	if (cmn->vrfid != 0)
		return;

	cm_bpf_keep_alive_stop();

	cn_cmd.hdr.id.idx = CN_IDX_PROC;
	cn_cmd.hdr.id.val = CN_VAL_PROC;
	cn_cmd.hdr.seq = 0;
	cn_cmd.hdr.ack = 0;
	cn_cmd.hdr.len = sizeof(enum proc_cn_mcast_op);
	cn_cmd.op = PROC_CN_MCAST_IGNORE;

	if (nl_send_simple(sk, NLMSG_DONE, 0, &cn_cmd, sizeof(cn_cmd)) < 0)
		syslog(LOG_ERR, "Could not initialize connector\n");
}
