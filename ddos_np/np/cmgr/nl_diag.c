/*
 * Copyright(c) 2013 6WIND, all rights reserved
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <event.h>

#include <netinet/in.h>

#include <linux/netdevice.h>    /* for MAX_ADDR_LEN */
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/packet_diag.h>
#include <linux/filter.h>
#include <netlink/msg.h>

#include "fpc.h"
#include "cm_netlink.h"
#include "cm_pub.h"
#include "cm_priv.h"
#include "cm_sock.h"

static void cm_nldiag_packet(struct nlmsghdr *nlh, struct nlsock *cmn)
{
	struct packet_diag_msg *r = nlmsg_data(nlh);
	struct nlattr *tb[PACKET_DIAG_MAX+1];
	struct cp_bpf bpf;
	uint32_t sock_vrfid = cmn->vrfid;
	int err;

	if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
		syslog(LOG_DEBUG, "New BPF (cookie: %08x%08x)\n",
		       r->pdiag_cookie[0], r->pdiag_cookie[1]);

	memset(&bpf, 0, sizeof(bpf));
	err = cm_nlmsg_parse(nlh, sizeof(*r), (struct nlattr **)tb, PACKET_DIAG_MAX, MSG_FAMILY_DIAG);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

	/* Ignore BPF created by raw sockets like in fpsd */
	if (r->pdiag_num == CM_BPF_FPTUN_PROTOCOL)
		return;

	/*
	 * libnl starts parsing nla_type at 1, ignoring 0. But
	 * PACKET_DIAG_INFO attribute is not well implemented. Try to
	 * parse it in this case.
	 */
#if PACKET_DIAG_INFO == 0
	if (!tb[PACKET_DIAG_INFO])
		tb[PACKET_DIAG_INFO] = nlmsg_attrdata(nlh, sizeof(*r));
#endif

	if (tb[PACKET_DIAG_INFO]) {
		struct packet_diag_info *pinfo = nla_data(tb[PACKET_DIAG_INFO]);
		struct cm_iface *ifp;

		if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
			syslog(LOG_DEBUG, "BPF: ifindex: %d\n", pinfo->pdi_index);

		ifp = iflookup(pinfo->pdi_index, sock_vrfid);
		/* In case of tcpdump -i any, bpf_ifindex is 0, thus ifp is
		 * NULL.
		 */
		bpf.ifuid = ifp ? ifp->ifuid : 0;
	} else {
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
			syslog(LOG_DEBUG, "BPF: ifindex: 0\n");
		bpf.ifuid = 0;
	}

#ifdef PACKET_SHOW_FILTER
	if (tb[PACKET_DIAG_FILTER]) {
		struct sock_filter *fil = nla_data(tb[PACKET_DIAG_FILTER]);
		int i;

		bpf.num = nla_len(tb[PACKET_DIAG_FILTER]) /
			  sizeof(struct sock_filter);
		if (bpf.num > CM_BPF_MAXFILTERS) {
			syslog(LOG_INFO, "%s: too many filter commands (%u, max: %u), use default filter\n",
			       __FUNCTION__, bpf.num, CM_BPF_MAXFILTERS);
			goto end;
		}
		if (bpf.num == 0) {
			syslog(LOG_DEBUG, "%s: no filter set (num is 0)\n",
			       __FUNCTION__);
			return;
		}

		if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
			syslog(LOG_DEBUG, "BPF: num: %u\n", bpf.num);

		for (i = 0; i < bpf.num; i++) {
			if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
				syslog(LOG_DEBUG,
				       "\t%d: code: 0x%02x jt: %d jf: %d k: 0x%08x\n",
				       i, fil[i].code, fil[i].jt, fil[i].jf,
				       fil[i].k);

			bpf.filters[i].code = fil[i].code;
			bpf.filters[i].jt = fil[i].jt;
			bpf.filters[i].jf = fil[i].jf;
			bpf.filters[i].k = fil[i].k;
		}
	} else
#endif
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
			syslog(LOG_INFO,
			       "%s: PACKET_DIAG_FILTER not set, use default filter\n",
			       __FUNCTION__);

#ifdef PACKET_SHOW_FILTER
end:
#endif

	cm2cp_bpf_update(nlh->nlmsg_seq, &bpf);
}

void cm_nldiag_dispatch(struct nlmsghdr *nlh, struct nlsock *cmn)
{
	uint8_t family = *(uint8_t *)nlmsg_data(nlh);

	if (family != AF_PACKET)
		return;

	switch (nlh->nlmsg_type) {
	case SOCK_DIAG_BY_FAMILY:
		cm_nldiag_packet(nlh, cmn);
		break;
	default:
		break;
	}
}

void cm_nldiag_packet_dump(uint32_t vrfid)
{
	struct nlsock *cmn = vrf_get_nlsock(vrfid, CM_DIAG);
	struct nl_sock *sk;
	struct packet_diag_req req;

	if (cmn == NULL)
		return;

	sk = cmn->sk;

	if (sk == NULL)
		return;

	memset(&req, 0, sizeof(req));
	req.sdiag_family = AF_PACKET;
	req.pdiag_show = PACKET_SHOW_INFO;
#ifdef PACKET_SHOW_FILTER
	req.pdiag_show |= PACKET_SHOW_FILTER;
#endif
	nl_send_simple(sk, SOCK_DIAG_BY_FAMILY, NLM_F_DUMP|NLM_F_REQUEST,
			&req, sizeof(req));

	if (nl_recvmsgs_default(sk) < 0) {
		syslog(LOG_NOTICE, "sock-diag netlink error, fallback to proc packet monitoring\n");
		cm_close_netlink_sock(cmn, 0);
		if (cmn->vrfid == 0 && cm_bpf_notify == CM_BPF_ALWAYS) {
			cm_nldiag_stop_timer();
			cm_proc_packet_start_timer();
		}
	}
}

static void nldiag_packet_dump_sock(int fd, struct nlsock *cmn)
{
	cm_nldiag_packet_dump(cmn->vrfid);
}

static void event_nldiag_packet_dump(int sock, short evtype, void *data)
{
	netlink_for_each(nldiag_packet_dump_sock, 0 /* unused fd */, CM_DIAG);
	cm_nldiag_start_timer();

	/* Note: the result of cm_nldiag_packet_dump() is asynchronous, the
	 * response is handled by cm_nldiag_packet. However we schedule the
	 * next dump, assuming the responses will all have been processed at
	 * next iteration.
	 */
}

void cm_nldiag_start_timer(void)
{
	struct event *event = vrf_get_diag_ev(0);
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = 300 * 1000; /* every 300ms */
	evtimer_set(event, event_nldiag_packet_dump, NULL);
	evtimer_add(event, &tv);
}

void cm_nldiag_stop_timer(void)
{
	struct event *event = vrf_get_diag_ev(0);

	if (event)
		evtimer_del(event);
}
