#ifndef _CM_SOCK_H_
#define _CM_SOCK_H_

#include "cm_sock_pub.h"

/*
 * CM_MAX is the only used enum to get the size of netlink sockets per vr.
 * It must be the same size with nlsock_hooks[].
 */
enum
{
	CM_NETLINK = 0,
	CM_NETCMD,
	CM_SVTI,
	CM_XFRM,
	CM_XFRM_CMD,
#ifdef NF_NETLINK_TABLES
	CM_NF_TABLE,
#endif
#ifdef NF_NETLINK_LSN_CPE
	CM_NF_CPE,
#endif
	CM_NF_CONNTRACK,
#ifdef CONFIG_CACHEMGR_AUDIT
	CM_AUDIT,
#endif
	CM_DIAG,
	CM_CONNECTOR,
	/* Room for cm_nlsock_hooks_register(). */
	CM_REGISTERED_FIRST,
	CM_REGISTERED_LAST = (CM_REGISTERED_FIRST + 15),
	CM_MAX
};

struct nlsock_vr
{
	int valid;
	struct nlsock cm_nlsock[CM_MAX];
	struct event diag_dump_ev;
};

extern struct nlsock_hooks nlsock_hooks[CM_MAX];

#ifdef CONFIG_CACHEMGR_DIAG
extern void cm_nldiag_start_timer(void);
extern void cm_nldiag_stop_timer(void);
extern void cm_nldiag_packet_dump(uint32_t vrfid);
#endif
extern void cm_proc_packet_start_timer(void);
extern void cm_proc_packet_stop_timer(void);
extern void cm_proc_packet_dump(uint32_t vrfid);

extern void netlink_for_each(void func(int id, struct nlsock *cmn),
	int fd, int type);
extern struct nlsock *vrf_get_nlsock(int vrfid, int type);

extern struct event *vrf_get_diag_ev(int vrfid);

extern int cm_nl_getconnector(struct nl_msg *msg, void *arg);
extern int cm_nl_connector_start(struct nlsock *cmn);
extern void cm_nl_connector_stop(struct nlsock *cmn);
extern void cm_connector_keep_alive(void);
#endif /* _CM_SOCK_H_ */
