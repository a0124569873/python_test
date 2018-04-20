/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *
 *                CM internals
 *
 * $Id: cm_priv.h,v 1.55 2010-10-21 14:56:21 dichtel Exp $
 ***************************************************************
 */
#ifndef __CM_PRIV_H_
#define __CM_PRIV_H_

#include <inttypes.h>
#include <sys/queue.h>
#include <syslog.h>
#include <errno.h>
#include <linux/netlink.h>

#include "cm_plugin.h"

/*
 * Missing TAILQ macros
 */
#ifndef TAILQ_FIRST
#	define TAILQ_FIRST(head)   ((head)->tqh_first)
#endif
#ifndef TAILQ_LAST
#	define TAILQ_LAST(head, headname)                  \
    (*(((struct headname *)((head)->tqh_last))->tqh_last))
#endif
#ifndef TAILQ_PREV
#	define TAILQ_PREV(elm, headname, field)                \
    (*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))
#endif
#ifndef TAILQ_NEXT
#	define TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)
#endif
#ifndef TAILQ_EMPTY
#	define TAILQ_EMPTY(head)   ((head)->tqh_first == NULL)
#endif
#ifndef TAILQ_FOREACH
#	define TAILQ_FOREACH(var, head, field)         \
		for ((var) = TAILQ_FIRST((head));          \
			(var);                                 \
			(var) = TAILQ_NEXT((var), field))
#endif

/*
 *  Files for the main()
 */
#define  DEFAULT_CM_PIDFILE  "/var/run/cmgrd.pid"

/* nl_base.c */
#define CM_MAX_VRF 2048
extern int cm_vrf [];

extern struct event_base *cm_event_base;

/* nl_dump.c */
struct nfattr;
extern void hexdump(const void *buf, int len, int columns, char *str);
extern void attr_dump(const struct nlattr *rta, int family);
extern void nfattr_dump(const struct nfattr *nfa, u_int32_t subsys);
extern const char *rtm_type2str(u_int16_t);
extern const char *rtm_attr2str(u_int16_t);
extern const char *rtm_rta_attr2str(u_int16_t);
extern const char *cm_iftype2str(u_int32_t);
extern const char *cm_ifsubtype2str(u_int32_t);
extern const char *cm_nhtype2str(u_int32_t);
extern const char *nlnf_subsys2str(u_int16_t);
extern const char *nlnf_tables_type2str(u_int16_t);
extern const char *nlnf_cpe_type2str(u_int16_t);
extern const char *nlnf_tables_nftype2str(u_int16_t);
extern const char *nlnf_cpe_nftype2str(u_int16_t);
extern const char *nlnf_conntrack_type2str(u_int16_t);
extern const char *nlnf_conntrack_nftype2str(u_int16_t);
extern const char *nlxfrm_type2str(u_int16_t);
extern const char *nlnf_table_type2str(u_int16_t);

/* if_linux.c */
extern const unsigned short CM_ARPHRD_SVTI;

/* fpm.c */
extern int fpm_ignore;
extern int  fpm_init (int delay);
extern void fpm_dump_queue(int fd);

/* rt_post.c */
extern void post_rt_msg (struct cp_hdr *);
extern void purge_rtQueues(void);
extern void rtQ_destroy(void);

/* netlink.c */
extern void cm_dump_netlink_stats(int fd);

#define CM_BPF_ALWAYS       0
#define CM_BPF_PATTERN_ONLY 1
#define CM_BPF_NEVER        2
extern int cm_bpf_notify;
extern int bpf_match_pattern(const char *name);
#ifdef CONFIG_CACHEMGR_DIAG
extern const char *nldiag_type2str(u_int16_t);
struct nlmsghdr;
struct nlsock;
extern void cm_nldiag_dispatch(struct nlmsghdr *h, struct nlsock *cmn);
#endif
#define CM_BPF_FPTUN_PROTOCOL 0x2007
#ifdef CONFIG_CACHEMGR_AUDIT
extern const char *nlaudit_type2str(u_int16_t type);
#endif

#ifdef CONFIG_CACHEMGR_EBTABLES
/* ebtc.c */
extern void cm_ebtc_update_timer(int sock, short evtype, void *data);
#endif

/* iptc.c */
extern void cm_iptc_dump_table_async(u_int32_t, char *, u_int8_t, u_int32_t);
extern void cm_iptc_init(void);
extern void cm_iptc_exit(void);

/* nl_base.c */
extern void nlbase_init(void);
extern void nlbase_clear(u_int32_t);
extern char *cm_index2name(u_int32_t ifindex, u_int32_t vrfid);
extern char *cm_ifuid2name(uint32_t ifuid);
extern void cm_display_interfaces(void(*display)(int, const char *, ...), int s);

extern char *srv_path;
extern struct sockaddr *srv_sockaddr;
extern int srv_family;
extern int srv_conn_maxtry;

/* main.c */
extern int cm_sockbufsiz;
extern int cm_skip_level;
extern int cm_disable_nl_nfct;

#endif
