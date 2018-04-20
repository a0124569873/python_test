#ifndef _CM_SOCK_PUB_H_
#define _CM_SOCK_PUB_H_

/*
 * Exported function to register plugins in the future.
 */
#include <event.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <netlink/netlink.h>
#include <linux/netfilter/nfnetlink.h>

struct cm_iface;

struct nlsock
{
	struct nl_sock  *sk;
#if defined(NETLINK_GENERIC)
	struct genl_family *genl_fam;
#endif
	struct event        *ev;
	/* Needed because of libevent version < 2.0 */
	struct event        *timeout_ev;
	struct timeval      timeout_tv;

	uint32_t            recv_count;
	uint32_t            vrfid;
	uint8_t             init_failed;
	uint8_t             dump_in_progress;
	struct nlsock_hooks *hooks;
	void *priv;
};

struct nlsock_hooks
{
	char *name;
	void (*init)(struct nlsock *);
	void (*destroy)(struct nlsock *);
	void (*dump)(struct nlsock *);

	int (*recv)(struct nl_msg*, void*);
	int (*finish_cb)(struct nl_msg*, void*);
	int (*timeout)(void *);

	void (*gr_dump)(struct nlsock *);
	u_int32_t gr_type;
	uint32_t *stats;
	int size;
	const char *(*type2str)(u_int16_t);
	void (*parse_afspec)(struct  nlattr **, struct cm_iface *, int);
	uint8_t vrf0_only;
};

#define CM_ONE_BY_ONE_READ      0
#define CM_BULK_READ            1

#define CM_INCREASE_NL_STATS(s, t) \
{ \
	s->recv_count++; \
	s->hooks->stats[t]++; \
}

extern int cm_nlsock_hooks_register(struct nlsock_hooks *hooks);

void cm_netlink_sock (int proto, struct nlsock *cmn, long groups,
		       int listen, int bulk, const struct timeval *tv, int ignore_multi);
void cm_close_netlink_sock (struct nlsock *cmn, int listen);

int cmn_socket_is_alive(struct nlsock *cmn);

extern void cm_iptc_dump_all_tables(struct nlsock *cmn);
#endif /* _CM_SOCK_PUB_H_ */
