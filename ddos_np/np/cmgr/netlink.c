/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *
 *                   netlink general stuff
 * $Id: netlink.c,v 1.100 2011-02-14 17:11:22 dichtel Exp $
 ***************************************************************
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <string.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <event.h>
#include <syslog.h>

#include <net/if.h>
#include <netinet/in.h>

#include <linux/types.h> // for 2.4 kernel
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/attr.h>
#include <netlink/msg.h>
#include <netlink/route/rtnl.h>
#include <netlink/genl/genl.h>
#include <netlink/netfilter/nfnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <limits.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/xfrm.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#ifdef CONFIG_CACHEMGR_DIAG
#include <net/if_arp.h>    /* for MAX_ADDR_LEN */
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <linux/packet_diag.h>
#endif
#ifdef CONFIG_CACHEMGR_AUDIT
#include <linux/audit.h>
#endif

#include "fpc.h"
#include "sockmisc.h"
#include "cm_pub.h"
#include "cm_ipsec_pub.h"
#include "cm_priv.h"
#include "cm_netlink.h"
#include "cm_sock.h"
#include "genl_base.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifdef CONFIG_HA6W_SUPPORT
#  include "hasupport.h"
   extern struct has_ctx * cmg_has;
#endif

static void cm_nl_recv_event (int fd, short event, void *data);

static int cm_nl_recv (struct nl_msg *msg, void *arg);
static void cm_nl_dump_if_and_addr (struct nlsock *cmn);
#ifdef RTM_GETNETCONF
static void cm_nl_dump_netconf (struct nlsock *cmn);
#endif
static void cm_nl_dump_neigh (struct nlsock *cmn);
static void cm_nl_dump_route (struct nlsock *cmn);
#ifdef NF_NETLINK_TABLES
static int cm_nlnf_table_recv(struct nl_msg *msg, void *arg);
#endif
#ifdef NF_NETLINK_LSN_CPE
static int cm_nlnf_cpe_recv(struct nl_msg *msg, void *arg);
#endif
static int cm_nlnf_conntrack_recv(struct nl_msg *msg, void *arg);
#ifdef CONFIG_CACHEMGR_AUDIT
static int cm_nlaudit_recv(struct nl_msg *msg, void *arg);
static void cm_nlaudit_dump_all(struct nlsock *cmn);
extern  void cm_nlaudit_dispatch(struct nlmsghdr *h, u_int32_t vrfid);
extern int cm_nlaudit_set_pid(struct nl_sock *);
extern int cm_nlaudit_set_enabled(struct nl_sock *, int enabled);
extern void cm_nlaudit_rule_init(struct audit_rule_data *rule,
				 int flags, int action);
extern void cm_nlaudit_rule_add_filter(struct audit_rule_data *rule, int field,
				       int op, int value);
extern int cm_nlaudit_rule_add(struct nl_sock *,
			       struct audit_rule_data *rule);
extern int cm_nlaudit_rule_del(struct nl_sock *,
			       struct audit_rule_data *rule);
#endif
static int cm_nlxfrm_recv(struct nl_msg *msg, void *arg);
extern void cm_nl_xfrm_dispatch(struct nlmsghdr *h, u_int32_t vrfid);
extern int cm_nl_getsp(struct nl_msg *msg, void *arg);
extern int cm_nl_getsa(struct nl_msg *msg, void *arg);
static int cm_nl_getsvti(struct nl_msg *msg, void *arg);
static void cm_nl_dump_svti_sp(uint32_t ifindex, struct nlsock *cmn);
static void cm_nl_dump_sa (struct nlsock *cmn);
static void cm_nl_dump_sp (struct nlsock *cmn);
static void cm_nl_dump_svti (struct nlsock *cmn);

static uint32_t cm_nlroute_stats[RTM_MAX+1];

static uint32_t cm_nlroutecmd_stats[RTM_MAX+1];

#ifdef NF_NETLINK_TABLES
static uint32_t cm_nlnf_table_stats[NFTBL_MSG_MAX];
#endif
#ifdef NF_NETLINK_LSN_CPE
static uint32_t cm_nlnf_cpe_stats[NF_LSN_CPE_MAX];
#endif
static uint32_t cm_nlnf_conntrack_stats[IPCTNL_MSG_MAX];

#ifdef CONFIG_CACHEMGR_AUDIT
static uint32_t cm_audit_stats[AUDIT_LAST_USER_MSG2];
#endif

static uint32_t cm_nlxfrm_stats[XFRM_MSG_MAX+1];
static uint32_t cm_nlxfrmcmd_stats[XFRM_MSG_MAX+1];

#ifdef CONFIG_CACHEMGR_DIAG
static uint32_t cm_nldiag_stats[INET_DIAG_GETSOCK_MAX+1];
#endif

int cm_nl_dump_in_progress = 1;


void
cm_do_has_check_request(void)
{
#ifdef CONFIG_HA6W_SUPPORT
	has_check_request(cmg_has);
#endif
}

int
cm_nl_parse_nlattr (struct nlattr **tb, int max, struct nlattr *head, int len, int family)
{
	struct nlattr *nla;
	int rem, type, err;

	if ((err = nla_parse(tb, max, head, len, NULL)) < 0)
		return err;

	nla_for_each_attr(nla, head, len, rem) {
		type = nla_type(nla);
		/* Padding attributes */
		if (type == 0)
			continue;

		if (type > max)
			continue;

		attr_dump(nla, family);
	}

	return 0;
}

int
cm_nlmsg_parse (struct nlmsghdr *h, int hdrlen, struct nlattr **tb, int maxtype, int family)
{
	if (!nlmsg_valid_hdr(h, hdrlen))
		return -NLE_MSG_TOOSHORT;

	return cm_nl_parse_nlattr(tb, maxtype, nlmsg_attrdata(h, hdrlen),
				  nlmsg_attrlen(h, hdrlen), family);
}

int
cm_nl_parse_nlattr_byindex (struct nlattr **tb, int max, struct nlattr *head, int len, int family)
{
	struct nlattr *nla;
	int rem;
	int i = 0;

	nla_for_each_attr(nla, head, len, rem) {
		if (i <= max)
			tb[i++] = nla;

		/* display message */
		attr_dump(nla, family);
	}

	return i;
}

#ifdef NF_NETLINK_TABLES
int
cm_nl_parse_nfattr(struct nlmsghdr *h, int hdrlen, struct nfattr **tb, int max)
{
	int rem, type, err = 0;
	struct nlattr *nla;
	struct nlattr *head;
	int len = nlmsg_attrlen(h, hdrlen);

	if (!nlmsg_valid_hdr(h, hdrlen))
		return -NLE_MSG_TOOSHORT;

	head = nlmsg_attrdata(h, hdrlen);
	if ((err = nla_parse((struct nlattr **)tb, max, head, len, NULL)) < 0)
		return err;

	nla_for_each_attr(nla, head, len, rem) {
		type = nla_type(nla);
		/* Padding attributes */
		if (type == 0)
			continue;
		if (type > max)
			continue;

		nfattr_dump((struct nfattr *)nla, h->nlmsg_type);
	}

	return 0;
}
#endif /* NF_NETLINK_TABLES */
#define cm_nl_nfattr_parse_nested(tb, max, nfa) \
      nla_parse_nested((struct nlattr **)tb, max, (struct nlattr *)nfa, NULL)
static int
cm_nl_parse_conntrack_ip(struct nfattr *attr, struct cp_nfct *nfct, int mode)
{
	struct nfattr *tb[CTA_IP_MAX+1];

	cm_nl_nfattr_parse_nested(tb, CTA_IP_MAX, attr);

	if (!tb[CTA_IP_V4_SRC])
		return -1;
	if (mode == CTA_TUPLE_ORIG)
		nfct->orig_src = *(u_int32_t *)NFA_DATA(tb[CTA_IP_V4_SRC]);
	else
		nfct->reply_src = *(u_int32_t *)NFA_DATA(tb[CTA_IP_V4_SRC]);

	if (!tb[CTA_IP_V4_DST])
		return -1;
	if (mode == CTA_TUPLE_ORIG)
		nfct->orig_dst = *(u_int32_t *)NFA_DATA(tb[CTA_IP_V4_DST]);
	else
		nfct->reply_dst = *(u_int32_t *)NFA_DATA(tb[CTA_IP_V4_DST]);

	return 0;
}

static int
cm_nl_parse_conntrack_proto(struct nfattr *attr,
			    struct cp_nfct *nfct, int mode)
{
	struct nfattr *tb[CTA_PROTO_MAX+1];

	cm_nl_nfattr_parse_nested(tb, CTA_PROTO_MAX, attr);

	if (!tb[CTA_PROTO_NUM])
		return -1;
	nfct->proto = *(u_int8_t *)NFA_DATA(tb[CTA_PROTO_NUM]);

	if (nfct->proto == IPPROTO_TCP ||
	    nfct->proto == IPPROTO_UDP ||
	    nfct->proto == IPPROTO_SCTP ||
	    nfct->proto == IPPROTO_GRE) {
		if (!tb[CTA_PROTO_SRC_PORT] || !tb[CTA_PROTO_DST_PORT])
			return -1;

		if (nfct->proto == IPPROTO_GRE) {
			/* TODO: we don't support sport for GRE in FP now*/
			if (mode == CTA_TUPLE_ORIG) {
				nfct->orig_sport = 0;
				nfct->orig_dport = 0;
			} else {
				nfct->reply_sport = 0;
				nfct->reply_dport = 0;
			}
		} else {
			if (mode == CTA_TUPLE_ORIG) {
				nfct->orig_sport = *(u_int16_t *)NFA_DATA(tb[CTA_PROTO_SRC_PORT]);
				nfct->orig_dport = *(u_int16_t *)NFA_DATA(tb[CTA_PROTO_DST_PORT]);
			} else {
				nfct->reply_sport = *(u_int16_t *)NFA_DATA(tb[CTA_PROTO_SRC_PORT]);
				nfct->reply_dport = *(u_int16_t *)NFA_DATA(tb[CTA_PROTO_DST_PORT]);
			}
		}
	}
	return 0;
}

static struct cp_nfct *
nfct_nl2cm(struct nfattr *cda[], u_int32_t sock_vrfid)
{
	struct cp_nfct *nfct = NULL;
	int err;

	nfct = (struct cp_nfct *)calloc(1, sizeof(*nfct));
	if (!nfct)
		goto bad;
	if (cda[CTA_TUPLE_ORIG] && cda[CTA_TUPLE_REPLY]) {
		struct nfattr *tb[CTA_TUPLE_MAX+1];

		/* Parse ORIG tuple */
		cm_nl_nfattr_parse_nested(tb, CTA_TUPLE_MAX, cda[CTA_TUPLE_ORIG]);
		if (!tb[CTA_TUPLE_PROTO])
			goto bad;
		err = cm_nl_parse_conntrack_proto(tb[CTA_TUPLE_PROTO], nfct, CTA_TUPLE_ORIG);
		if (err < 0)
			goto bad;

		if (!tb[CTA_TUPLE_IP])
			goto bad;
		err = cm_nl_parse_conntrack_ip(tb[CTA_TUPLE_IP], nfct, CTA_TUPLE_ORIG);
		if (err < 0)
			goto bad;

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
		nfct->vrfid = htonl(sock_vrfid);
#else
#ifdef CTA_TUPLE_VRFID
		if (tb[CTA_TUPLE_VRFID])
			nfct->vrfid = htonl(*(u_int32_t *)NFA_DATA(tb[CTA_TUPLE_VRFID]));
#endif /*CTA_TUPLE_VRFID*/
#endif

		/* Parse REPLY tuple */
		cm_nl_nfattr_parse_nested(tb, CTA_TUPLE_MAX, cda[CTA_TUPLE_REPLY]);
		if (!tb[CTA_TUPLE_PROTO])
			goto bad;
		err = cm_nl_parse_conntrack_proto(tb[CTA_TUPLE_PROTO], nfct, CTA_TUPLE_REPLY);
		if (err < 0)
			goto bad;

		if (!tb[CTA_TUPLE_IP])
			goto bad;
		err = cm_nl_parse_conntrack_ip(tb[CTA_TUPLE_IP], nfct, CTA_TUPLE_REPLY);
		if (err < 0)
			goto bad;

		return nfct;
	}

bad:
	if (nfct)
		free(nfct);
	return NULL;
}

static int
cm_nl_parse_conntrack_ipv6(struct nfattr *attr, struct cp_nf6ct *nf6ct, int mode)
{
	struct nfattr *tb[CTA_IP_MAX+1];

	cm_nl_nfattr_parse_nested(tb, CTA_IP_MAX, attr);

	if (!tb[CTA_IP_V6_SRC])
		return -1;
	if (mode == CTA_TUPLE_ORIG)
		nf6ct->orig_src = *(struct in6_addr *)NFA_DATA(tb[CTA_IP_V6_SRC]);
	else
		nf6ct->reply_src = *(struct in6_addr *)NFA_DATA(tb[CTA_IP_V6_SRC]);

	if (!tb[CTA_IP_V6_DST])
		return -1;
	if (mode == CTA_TUPLE_ORIG)
		nf6ct->orig_dst = *(struct in6_addr *)NFA_DATA(tb[CTA_IP_V6_DST]);
	else
		nf6ct->reply_dst = *(struct in6_addr *)NFA_DATA(tb[CTA_IP_V6_DST]);

	return 0;
}

static int
cm_nl_parse_conntrack_protov6(struct nfattr *attr, struct cp_nf6ct *nf6ct, int mode)
{
	struct nfattr *tb[CTA_PROTO_MAX+1];

	cm_nl_nfattr_parse_nested(tb, CTA_PROTO_MAX, attr);

	if (!tb[CTA_PROTO_NUM])
		return -1;
	nf6ct->proto = *(u_int8_t *)NFA_DATA(tb[CTA_PROTO_NUM]);

	if (nf6ct->proto == IPPROTO_TCP ||
	    nf6ct->proto == IPPROTO_UDP ||
	    nf6ct->proto == IPPROTO_SCTP ||
	    nf6ct->proto == IPPROTO_GRE) {
		if (!tb[CTA_PROTO_SRC_PORT] || !tb[CTA_PROTO_DST_PORT])
			return -1;

		if (nf6ct->proto == IPPROTO_GRE) {
			/* TODO: we don't support sport for GRE in FP now*/
			if (mode == CTA_TUPLE_ORIG) {
				nf6ct->orig_sport = 0;
				nf6ct->orig_dport = 0;
			} else {
				nf6ct->reply_sport = 0;
				nf6ct->reply_dport = 0;
			}
		} else
			if (mode == CTA_TUPLE_ORIG) {
				nf6ct->orig_sport = *(u_int16_t *)NFA_DATA(tb[CTA_PROTO_SRC_PORT]);
				nf6ct->orig_dport = *(u_int16_t *)NFA_DATA(tb[CTA_PROTO_DST_PORT]);
			} else {
				nf6ct->reply_sport = *(u_int16_t *)NFA_DATA(tb[CTA_PROTO_SRC_PORT]);
				nf6ct->reply_dport = *(u_int16_t *)NFA_DATA(tb[CTA_PROTO_DST_PORT]);
			}
	}
	return 0;
}

static struct cp_nf6ct *
nf6ct_nl2cm(struct nfattr *cda[], u_int32_t sock_vrfid)
{
	struct cp_nf6ct *nf6ct = NULL;
	int err;

	nf6ct = (struct cp_nf6ct *)calloc(1, sizeof(*nf6ct));
	if (!nf6ct)
		goto bad;
	if (cda[CTA_TUPLE_ORIG] && cda[CTA_TUPLE_REPLY]) {
		struct nfattr *tb[CTA_TUPLE_MAX+1];

		/* Parse ORIG tuple */
		cm_nl_nfattr_parse_nested(tb, CTA_TUPLE_MAX, cda[CTA_TUPLE_ORIG]);
		if (!tb[CTA_TUPLE_PROTO])
			goto bad;
		err = cm_nl_parse_conntrack_protov6(tb[CTA_TUPLE_PROTO], nf6ct, CTA_TUPLE_ORIG);
		if (err < 0)
			goto bad;

		if (!tb[CTA_TUPLE_IP])
			goto bad;
		err = cm_nl_parse_conntrack_ipv6(tb[CTA_TUPLE_IP], nf6ct, CTA_TUPLE_ORIG);
		if (err < 0)
			goto bad;

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
		nf6ct->vrfid = htonl(sock_vrfid);
#else
#ifdef CTA_TUPLE_VRFID
		if (tb[CTA_TUPLE_VRFID])
			nf6ct->vrfid = htonl(*(u_int32_t *)NFA_DATA(tb[CTA_TUPLE_VRFID]));
#endif /*CTA_TUPLE_VRFID*/
#endif
		/* Parse REPLY tuple */
		cm_nl_nfattr_parse_nested(tb, CTA_TUPLE_MAX, cda[CTA_TUPLE_REPLY]);
		if (!tb[CTA_TUPLE_PROTO])
			goto bad;
		err = cm_nl_parse_conntrack_protov6(tb[CTA_TUPLE_PROTO], nf6ct, CTA_TUPLE_REPLY);
		if (err < 0)
			goto bad;

		if (!tb[CTA_TUPLE_IP])
			goto bad;
		err = cm_nl_parse_conntrack_ipv6(tb[CTA_TUPLE_IP], nf6ct, CTA_TUPLE_REPLY);
		if (err < 0)
			goto bad;

		return nf6ct;
	}

bad:
	if (nf6ct)
		free(nf6ct);
	return NULL;
}

static void
cm_nl_new_conntrack(struct nlmsghdr *h, u_int32_t sock_vrfid)
{
	struct nfgenmsg *nfmsg;
	struct nfattr *tb[CTA_MAX + 1];
	int err;
	struct cp_nfct *nfct;
	struct cp_nf6ct *nf6ct;
	unsigned long status = 0;
	u_int32_t uid = 0;

	nfmsg = nlmsg_data(h);
	err = nlmsg_parse(h, sizeof(*nfmsg), (struct nlattr **)tb, CTA_MAX, NULL);
	if (err < 0) {
#ifdef NF_NETLINK_TABLES
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
#endif
		return;
	}

	/* Do not create conntracks for ALGs */
	if (tb[CTA_HELP])
		return;

	if (tb[CTA_STATUS])
		status = ntohl(*(u_int32_t *)NFA_DATA(tb[CTA_STATUS]));

#ifdef CTA_UID
/* Used only if CONFIG_NF_CONNTRACK_UID is set */
	if (tb[CTA_UID])
		uid = *(u_int32_t *)NFA_DATA(tb[CTA_UID]);
#endif /*CTA_UID*/
	if ((1 << IPS_SEEN_REPLY_BIT) & status &&
	    !(status & IPS_NAT_MASK) &&
	    status & IPS_ASSURED) {
		switch (nfmsg->nfgen_family) {
		case AF_INET:
			nfct = nfct_nl2cm(tb, sock_vrfid);
			if (nfct == NULL)
				break;
			nfct->flag |= CM_NFCT_FLAG_ASSURED;
			if (nfct->proto == IPPROTO_TCP ||
			    nfct->proto == IPPROTO_UDP ||
			    nfct->proto == IPPROTO_SCTP ||
			    nfct->proto == IPPROTO_GRE ||
			    nfct->proto == IPPROTO_ESP ||
			    nfct->proto == IPPROTO_AH) {
				nfct->uid = uid;
				cm2cp_nfct_create(h->nlmsg_seq, nfct);
			}
			free(nfct);
			break;
		case AF_INET6:
			nf6ct = nf6ct_nl2cm(tb, sock_vrfid);
			if (nf6ct == NULL)
				break;
			nf6ct->flag |= CM_NFCT_FLAG_ASSURED;
			if (nf6ct->proto == IPPROTO_TCP ||
			    nf6ct->proto == IPPROTO_UDP ||
			    nf6ct->proto == IPPROTO_SCTP ||
			    nf6ct->proto == IPPROTO_GRE ||
			    nf6ct->proto == IPPROTO_ESP ||
			    nf6ct->proto == IPPROTO_AH) {
				nf6ct->uid = uid;
				cm2cp_nf6ct_create(h->nlmsg_seq, nf6ct);
			}
			free(nf6ct);
			break;
		}
	}

	/* For NAT: we need the first conntrack message, to be able to process replies in FP,
	 * and the ASSURED flag update, so that the conntrack is ASSURED in SP and FP.
	 */
	if ((IPS_CONFIRMED & status) && (status & IPS_NAT_MASK)) {
		switch (nfmsg->nfgen_family) {
		case AF_INET:
			nfct = nfct_nl2cm(tb, sock_vrfid);
			if (nfct &&
			    (nfct->proto == IPPROTO_TCP ||
			     nfct->proto == IPPROTO_UDP ||
			     nfct->proto == IPPROTO_ESP ||
			     nfct->proto == IPPROTO_AH)) {
				if (status & IPS_ASSURED)
					nfct->flag |= CM_NFCT_FLAG_ASSURED;
				if (status & IPS_DST_NAT)
					nfct->flag |= CM_NFCT_FLAG_DNAT;
				if (status & IPS_SRC_NAT)
					nfct->flag |= CM_NFCT_FLAG_SNAT;
#ifdef NF_NETLINK_LSN_CPE
				if (status & IPS_FROM_CPE)
					nfct->flag |= CM_NFCT_FLAG_FROM_CPE;
				if (status & IPS_TO_CPE)
					nfct->flag |= CM_NFCT_FLAG_TO_CPE;
#endif /*NF_NETLINK_LSN_CPE*/
				nfct->uid = uid;
				cm2cp_nfct_create(h->nlmsg_seq, nfct);
			}
			if (nfct)
				free(nfct);
			break;
		}
	}
}

static void
cm_nl_del_conntrack(struct nlmsghdr *h, u_int32_t sock_vrfid)
{
	struct nfgenmsg *nfmsg;
	struct nfattr *tb[CTA_MAX + 1];
	int err;
	struct cp_nfct *nfct;
	struct cp_nf6ct *nf6ct;

	nfmsg = nlmsg_data(h);

	err = nlmsg_parse(h, sizeof(*nfmsg), (struct nlattr **)tb, CTA_MAX, NULL);
	if (err < 0) {
#ifdef NF_NETLINK_TABLES
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
#endif
		return;
	}

	switch (nfmsg->nfgen_family) {
	case AF_INET:
		nfct = nfct_nl2cm(tb, sock_vrfid);
		if (nfct &&
				(nfct->proto == IPPROTO_TCP ||
				 nfct->proto == IPPROTO_UDP ||
				 nfct->proto == IPPROTO_SCTP ||
				 nfct->proto == IPPROTO_GRE ||
				 nfct->proto == IPPROTO_ESP ||
				 nfct->proto == IPPROTO_AH))
			cm2cp_nfct_delete(h->nlmsg_seq, nfct);
		if (nfct)
			free(nfct);
		break;
	case AF_INET6:
		nf6ct = nf6ct_nl2cm(tb, sock_vrfid);
		if (nf6ct &&
				(nf6ct->proto == IPPROTO_TCP ||
				 nf6ct->proto == IPPROTO_UDP ||
				 nf6ct->proto == IPPROTO_SCTP ||
				 nf6ct->proto == IPPROTO_GRE ||
				 nf6ct->proto == IPPROTO_ESP ||
				 nf6ct->proto == IPPROTO_AH))
			cm2cp_nf6ct_delete(h->nlmsg_seq, nf6ct);
		if (nf6ct)
			free(nf6ct);
		break;
	}
}

static void
cm_nl_flush_conntrack(const struct nlmsghdr *h)
{
	cm2cp_nfct_flush(h->nlmsg_seq);
}

static void dump(int s, const char *fmt, ...)
{
	va_list ap;
	char buffer[1024];

	va_start(ap, fmt);
	vsnprintf(buffer, 1024, fmt, ap);
	va_end(ap);
	if (write(s, buffer, strlen(buffer)) < 0) {
		syslog(LOG_ERR, "%s: failed to write the result in the buffer: %s\n",
		       __FUNCTION__, strerror(errno));
		return;
	}
}

static void cm_dump_netlink_messages(int fd, uint32_t* table,
					int size, const char* f(u_int16_t type))
{
	int i;

	for (i = 0 ; i < size ; i++) {
		if (table[i] != 0)
			dump(fd, "    %-28s\t%d\n", f(i), table[i]);
	}
	dump(fd, "\n");
}

static void cm_dump_netlink_stats_per_sock(int fd, struct nlsock* s)
{
	char name[32];
	snprintf(name, 32, "%s-%d", s->hooks->name, s->vrfid);
	dump(fd, "%-32s\t%d\n", name, s->recv_count);
}

void cm_dump_netlink_stats(int fd)
{
	int i;
	struct nlsock_hooks *hooks;
	dump(fd, "Dump netlink socket statistics:\n");
	dump(fd, "%-32s\tpackets received\n", "netlink socket name");
	for (i = 0; i < CM_MAX; i++) {
		hooks = &nlsock_hooks[i];
		if (hooks->stats && hooks->size && hooks->type2str) {
			netlink_for_each(cm_dump_netlink_stats_per_sock, fd, i);
			cm_dump_netlink_messages(fd, hooks->stats,
				hooks->size, hooks->type2str);
		}
	}
}

static void cm_nl_recv_event (int fd, short event, void *data)
{
	int ret;
	struct nlsock *s = (struct nlsock *)data;
	struct nlsock_hooks *hooks = s->hooks;
	char name[32];
	snprintf(name, 32, "%s-%d", hooks->name, s->vrfid);

	fpm_process_queue(1);
	/* Check for timeout. */
	if (event & EV_TIMEOUT && hooks->timeout) {
		hooks->timeout(s);
		evtimer_add(s->timeout_ev, &s->timeout_tv);
		ret = 0;
	} else {
		ret = nl_recvmsgs_default(s->sk);
	}
	fpm_process_queue(0);
	if (ret < 0) {
		int err_hold = errno;
		syslog(LOG_ERR, "%s: failed to receive message from %s: %s\n",
				__FUNCTION__, name, strerror(err_hold));
		if (err_hold == ENOBUFS) {
			/* dump for this netlink protocol */
			if (hooks->gr_dump) {
				fpm_process_queue(1);
				if (hooks->gr_type)
					cm2cp_graceful_restart(hooks->gr_type);
				hooks->gr_dump(s);
				fpm_process_queue(0);
			}
		}
	}
}

static void
cm_nl_route_dump (struct nlsock *cmn)
{
	nlbase_clear(cmn->vrfid);
	cm_nl_dump_if_and_addr(cmn);
#ifdef RTM_GETNETCONF
	cm_nl_dump_netconf(cmn);
#endif
	cm_nl_dump_neigh(cmn);
	cm_nl_dump_route(cmn);
}

static void
cm_nl_xfrm_dump (struct nlsock *cmn)
{
	cm_nl_dump_sa(cmn);
	cm_nl_dump_sp(cmn);
	cm_nl_dump_svti(cmn);
}

static void
cm_nl_dump_if_and_addr (struct nlsock *cmn)
{
	nl_rtgen_request(cmn->sk, RTM_GETLINK, AF_UNSPEC, NLM_F_DUMP|NLM_F_REQUEST);
	nl_recvmsgs_default(cmn->sk);
#ifdef CONFIG_CACHEMGR_BRIDGE
	nl_rtgen_request(cmn->sk, RTM_GETLINK, AF_BRIDGE, NLM_F_DUMP|NLM_F_REQUEST);
	nl_recvmsgs_default(cmn->sk);
#endif
	nl_rtgen_request(cmn->sk, RTM_GETADDR, AF_UNSPEC, NLM_F_DUMP|NLM_F_REQUEST);
	nl_recvmsgs_default(cmn->sk);
}

#ifdef RTM_GETNETCONF
static void
cm_nl_dump_netconf (struct nlsock *cmn)
{
	nl_rtgen_request(cmn->sk, RTM_GETNETCONF, AF_INET, NLM_F_DUMP|NLM_F_REQUEST);
	nl_recvmsgs_default(cmn->sk);
	nl_rtgen_request(cmn->sk, RTM_GETNETCONF, AF_INET6, NLM_F_DUMP|NLM_F_REQUEST);
	nl_recvmsgs_default(cmn->sk);
}
#endif

#ifndef CONFIG_PORTS_CACHEMGR_NETNS
static int
set_netlink_sovrfid(struct nlsock *nl, const u_int32_t id)
{
#ifdef SO_VRFID
	u_int32_t vrf_id = id;

	if (setsockopt(nl_socket_get_fd(nl->sk), SOL_SOCKET, SO_VRFID, &vrf_id, sizeof(vrf_id)) < 0)
		return -1;
	return 0;
#else
	return -1;
#endif
}
#endif

/* For netns, cm_nl_dump_route will be called for each netns, but for
   vrf, we must loop */
static void
cm_nl_dump_route (struct nlsock *cmn)
{
#ifndef CONFIG_PORTS_CACHEMGR_NETNS
	int i, ret;

	for (i=CM_MAX_VRF-1; i>=1; i--) {
		if (!cm_vrf[i])
			continue;
		ret = set_netlink_sovrfid(cmn, i);
		if ((ret < 0) && (i!= 0))
			continue;
		nl_rtgen_request(cmn->sk, RTM_GETROUTE, AF_INET, NLM_F_DUMP|NLM_F_REQUEST);
		nl_recvmsgs_default(cmn->sk);
		nl_rtgen_request(cmn->sk, RTM_GETROUTE, AF_INET6, NLM_F_DUMP|NLM_F_REQUEST);
		nl_recvmsgs_default(cmn->sk);
	}
	set_netlink_sovrfid(cmn, 0);
#endif
	nl_rtgen_request(cmn->sk, RTM_GETROUTE, AF_INET, NLM_F_DUMP|NLM_F_REQUEST);
	nl_recvmsgs_default(cmn->sk);
	nl_rtgen_request(cmn->sk, RTM_GETROUTE, AF_INET6, NLM_F_DUMP|NLM_F_REQUEST);
	nl_recvmsgs_default(cmn->sk);
}

static void
cm_nl_dump_neigh (struct nlsock *cmn)
{
	/* ARP entries */
	nl_rtgen_request(cmn->sk, RTM_GETNEIGH, AF_INET, NLM_F_DUMP|NLM_F_REQUEST);
	nl_recvmsgs_default(cmn->sk);
	/* NDP entries */
	nl_rtgen_request(cmn->sk, RTM_GETNEIGH, AF_INET6, NLM_F_DUMP|NLM_F_REQUEST);
	nl_recvmsgs_default(cmn->sk);
#ifdef CONFIG_CACHEMGR_VXLAN
	/* FDB entries */
	nl_rtgen_request(cmn->sk, RTM_GETNEIGH, AF_BRIDGE, NLM_F_DUMP|NLM_F_REQUEST);
	nl_recvmsgs_default(cmn->sk);
#endif

	return;
}

#if defined(XFRMA_VRFID) || defined(XFRMA_SVTI_IFINDEX)
static int
cm_nl_send_attr (struct nl_sock *sk, int fmly, int mt, void *data, int data_type, int data_len)
{
	int res = -1;
	struct rtgenmsg g;
	struct nl_msg *msg = NULL;

	msg = nlmsg_alloc_simple(mt, NLM_F_DUMP|NLM_F_REQUEST);
	if (!msg)
		goto nla_put_failure;

	memset(&g, 0, sizeof(g));
	g.rtgen_family = fmly;

	if (nlmsg_append(msg, &g, sizeof(g), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (data_len)
		NLA_PUT(msg, data_type, data_len, data);

	res = nl_send_auto(sk, msg);

nla_put_failure:
	nlmsg_free(msg);
	return res;
}
#endif

void
cm_nl_dump_sa (struct nlsock *cmn)
{
#ifdef XFRMA_VRFID
	uint32_t i;
#endif
	if (nl_rtgen_request(cmn->sk, XFRM_MSG_GETSA, AF_UNSPEC, NLM_F_DUMP|NLM_F_REQUEST) < 0)
		return;

	if (nl_recvmsgs_default(cmn->sk) < 0)
		return;

#ifdef XFRMA_VRFID
	for (i = i; i < CM_MAX_VRF; i++) {
		if (!cm_vrf[i])
			continue;

		if (cm_nl_send_attr(cmn->sk, AF_UNSPEC, XFRM_MSG_GETSA,
					    &i, XFRMA_VRFID, sizeof(i)) < 0)
			continue;

		if (nl_recvmsgs_default(cmn->sk) < 0)
			return;
	}
#endif
}

void
cm_nl_dump_sp (struct nlsock *cmn)
{
#ifdef XFRMA_VRFID
	uint32_t i;
#endif
	if (nl_rtgen_request(cmn->sk, XFRM_MSG_GETPOLICY, AF_UNSPEC, NLM_F_DUMP|NLM_F_REQUEST) < 0)
		return;

	if (nl_recvmsgs_default(cmn->sk) < 0)
		return;

#ifdef XFRMA_VRFID
	for (i = i; i < CM_MAX_VRF; i++) {
		if (!cm_vrf[i])
			continue;

		if (cm_nl_send_attr(cmn->sk, AF_UNSPEC, XFRM_MSG_GETPOLICY,
					    &i, XFRMA_VRFID, sizeof(i)) < 0)
			continue;

		if (nl_recvmsgs_default(cmn->sk) < 0)
			continue;
	}
#endif
}


/*
 * Dump interfaces, in order to list SVTI interfaces
 */
static void
cm_nl_dump_svti (struct nlsock *cmn)
{
	struct nlsock *nlsock = vrf_get_nlsock(cmn->vrfid, CM_SVTI);

	if (CM_ARPHRD_SVTI == 0)
		return;

	if (nl_rtgen_request(nlsock->sk, RTM_GETLINK, AF_UNSPEC, NLM_F_DUMP|NLM_F_REQUEST) < 0) {
		syslog(LOG_DEBUG, "%s: nl_send_simple failed\n", __FUNCTION__);
		return;
	}

	/* warning, these stats are not incremented due to the direct svti call */
	if (nl_recvmsgs_default(nlsock->sk) < 0) {
		syslog(LOG_DEBUG, "%s: nl_recvmsgs_default failed\n", __FUNCTION__);
	}
}

/*
 * Select SVTI interfaces in order to dump attached SPs
 */
static int cm_nl_getsvti(struct nl_msg *msg, void *arg)
{
	int err;
	struct ifinfomsg *ifi;
	struct nlmsghdr *h = nlmsg_hdr(msg);
	struct nlattr *tb[IFLA_MAX + 1];
	struct nlsock *nlsock = (struct nlsock *)arg;

	if (h->nlmsg_type != RTM_NEWLINK)
		return 0;

	ifi = nlmsg_data(h);

	if (ifi->ifi_type != CM_ARPHRD_SVTI)
		return 0;

	err = nlmsg_parse(h, sizeof(*ifi), tb, IFLA_MAX, NULL);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return -1;
	}

	/* ignore svti_cfg0 interface and unnamed interfaces */
	if (tb[IFLA_IFNAME]) {
		if (!strncmp("svti_cfg",
					nla_data(tb[IFLA_IFNAME]),
					nla_len(tb[IFLA_IFNAME])))
			return 0;
	} else
		return 0;

	cm_nl_dump_svti_sp(ifi->ifi_index, nlsock);

	return 0;
}

/*
 * Dump SPs attached to an SVTI interface
 */
static void cm_nl_dump_svti_sp(uint32_t ifindex, struct nlsock *cmn)
{
#ifdef XFRMA_SVTI_IFINDEX
	if (cm_nl_send_attr(cmn->sk, AF_UNSPEC, XFRM_MSG_GETPOLICY,
				&ifindex, XFRMA_SVTI_IFINDEX, sizeof(ifindex)) < 0) {
		syslog(LOG_ERR, "%s: cm_nl_send_attr failed\n", __FUNCTION__);
		return;
	}
#endif

	if (nl_recvmsgs_default(cmn->sk) < 0) {
		syslog(LOG_ERR, "%s: nl_recvmsgs_default failed\n", __FUNCTION__);
		return;
	}
}

/*
 * Netlink Reception & Re-assembly
 * and  General dispatcher
 */


static void
cm_nl_dispatch(struct nlmsghdr * h, u_int32_t sock_vrfid)
{
	switch (h->nlmsg_type) {
		case RTM_NEWROUTE:
		case RTM_DELROUTE:
			cm_nl_route (h, sock_vrfid);
			break;

		case RTM_NEWLINK:
		case RTM_DELLINK:
			cm_nl_link (h, sock_vrfid);
			break;

		case RTM_NEWADDR:
		case RTM_DELADDR:
			cm_nl_iface_addr (h, sock_vrfid);
			break;

		case RTM_NEWNEIGH:
		case RTM_DELNEIGH:
			cm_nl_l2 (h, sock_vrfid);
			break;

#ifdef RTM_NEWNETCONF
		case RTM_NEWNETCONF:
			cm_nl_netconf (h, sock_vrfid);
			break;
#endif

		default:
			break;
	}
}

static int cm_nl_recv(struct nl_msg *msg, void *arg)
{
	struct nlsock *s = arg;
	struct nlmsghdr *h = nlmsg_hdr(msg);
#ifdef CONFIG_HA6W_SUPPORT
	/*
	 * This may be called in a close loop, so keep an eye
	 * on Health socket
	 */
	has_check_request(cmg_has);
#endif
	if (cm_debug_level &
			(CM_DUMP_HDR_NL_RECV|CM_DUMP_EXT_NL_RECV|CM_DUMP_HEX_NL_RECV))
	{
		syslog(LOG_DEBUG, "----------------------------------------"
				"--------------------\n");

		if (cm_debug_level & CM_DUMP_HDR_NL_RECV)
			syslog(LOG_DEBUG, "netlink recv: %s(%d) #%u len=%hu pid=%u\n",
					rtm_type2str(h->nlmsg_type), h->nlmsg_type,
					h->nlmsg_seq, h->nlmsg_len,
					h->nlmsg_pid);
	}
	CM_INCREASE_NL_STATS(s, h->nlmsg_type);
	cm_nl_dispatch(h, s->vrfid);

	return 0;
}

#ifdef NF_NETLINK_TABLES
static int cm_nlnf_table_recv(struct nl_msg *msg, void *arg)
{
	struct nlsock *s = arg;
	struct nlmsghdr *h = nlmsg_hdr(msg);
	struct nfgenmsg *nfmsg;
	struct nfattr *tb[NFTBLA_MAX + 1];
	struct nftbl_tablename *tblmsg = NULL;
	int err;

#ifdef CONFIG_HA6W_SUPPORT
	/*
	 * This may be called in a close loop, so keep an eye
	 * on Health socket
	 */
	has_check_request(cmg_has);
#endif
	if (cm_debug_level &
		(CM_DUMP_HDR_NL_RECV|CM_DUMP_EXT_NL_RECV|CM_DUMP_HEX_NL_RECV)) {
		syslog(LOG_DEBUG, "----------------------------------------"
		       "--------------------\n");

		if (cm_debug_level & CM_DUMP_HDR_NL_RECV)
			syslog(LOG_DEBUG, "netlink_netfilter: %s/%s(%d) #%u len=%hu pid=%u\n",
					nlnf_subsys2str(h->nlmsg_type),
					nlnf_tables_nftype2str(h->nlmsg_type),
					h->nlmsg_type, h->nlmsg_seq,
					h->nlmsg_len, h->nlmsg_pid);
	}

	if (nfnlmsg_subsys(h) != NFNL_SUBSYS_TABLES)
		return 0;

	CM_INCREASE_NL_STATS(s, NFNL_MSG_TYPE(h->nlmsg_type));

	switch (nfnlmsg_subtype(h)) {
	case NFTBL_UPDATE:
		nfmsg = nlmsg_data(h);

		err = cm_nl_parse_nfattr(h, sizeof(struct nfgenmsg), tb, NFTBLA_MAX);
		if (err < 0) {
			syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));

			break;
		}

		if (tb[NFTBLA_TABLENAME])
			tblmsg = (struct nftbl_tablename *)NFA_DATA(tb[NFTBLA_TABLENAME]);
		else {
			syslog(LOG_ERR, "%s: %s - %s no table name attribute\n",
					__FUNCTION__, nlnf_subsys2str(h->nlmsg_type),
					nlnf_tables_nftype2str(h->nlmsg_type));
			break;
		}

		/* we only dump tables handled by the fast path */
		if (!strcmp(tblmsg->name, "filter") ||
		    !strcmp(tblmsg->name, "mangle") ||
		    (!strcmp(tblmsg->name, "nat") && nfmsg->nfgen_family == AF_INET)) {

			if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
				syslog(LOG_DEBUG, SPACES" nftable name: [%s], family: %s\n", tblmsg->name,
						(nfmsg->nfgen_family == AF_INET) ? "AF_INET" : "AF_INET6");

			cm_iptc_dump_table_async(h->nlmsg_seq, tblmsg->name, nfmsg->nfgen_family, s->vrfid);
		}
		break;
	default:
		break;
	}

	return 0;
}
#endif /*NF_NETLINK_TABLES*/

#ifdef NF_NETLINK_LSN_CPE
static int cm_nlnf_cpe_recv(struct nl_msg *msg, void *arg)
{
	struct nlsock *s = arg;
	struct nlmsghdr *h = nlmsg_hdr(msg);
	struct nfattr *tb[NF_LSN_CPE_ATTR_MAX + 1];
	u_int32_t *cpeid = NULL;
	int err;

#ifdef CONFIG_HA6W_SUPPORT
	/*
	 * This may be called in a close loop, so keep an eye
	 * on Health socket
	 */
	has_check_request(cmg_has);
#endif
	if (cm_debug_level &
		(CM_DUMP_HDR_NL_RECV|CM_DUMP_EXT_NL_RECV|CM_DUMP_HEX_NL_RECV)) {
		syslog(LOG_DEBUG, "----------------------------------------"
		       "--------------------\n");

#ifdef NF_NETLINK_TABLES
		if (cm_debug_level & CM_DUMP_HDR_NL_RECV)
			syslog(LOG_DEBUG, "netlink_netfilter: %s/%s(%d) #%u len=%hu pid=%u\n",
					nlnf_subsys2str(h->nlmsg_type),
					nlnf_cpe_nftype2str(h->nlmsg_type),
					h->nlmsg_type, h->nlmsg_seq,
					h->nlmsg_len, h->nlmsg_pid);
	}
#endif /*NF_NETLINK_TABLES*/

	if (nfnlmsg_subsys(h) != NFNL_SUBSYS_LSN_CPE)
		return 0;

	CM_INCREASE_NL_STATS(s, NFNL_MSG_TYPE(h->nlmsg_type));

	switch (nfnlmsg_subtype(h)) {
	case NF_LSN_CPE_DEL:
		err = cm_nl_parse_nfattr(h, sizeof(struct nfgenmsg), tb, NF_LSN_CPE_ATTR_MAX);
		if (err < 0) {
			syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
			break;
		}

		if (tb[NF_LSN_CPE_INTERNAL_ADDR])
			cpeid = NFA_DATA(tb[NF_LSN_CPE_INTERNAL_ADDR]);

		if (cpeid) {
			if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
				syslog(LOG_DEBUG, SPACES"cpeid: %d\n", *cpeid);
			cm2cp_nfcpe_delete(h->nlmsg_seq, *cpeid);
		}
		break;
	default:
		break;
	}

	return 0;
}
#endif /*NF_NETLINK_LSN_CPE*/

static int cm_nlnf_conntrack_recv(struct nl_msg *msg, void *arg)
{
	struct nlsock *s = arg;
	struct nlmsghdr *h = nlmsg_hdr(msg);
#ifdef CONFIG_HA6W_SUPPORT
	/*
	 * This may be called in a close loop, so keep an eye
	 * on Health socket
	 */
	has_check_request(cmg_has);
#endif
	if (cm_debug_level &
		(CM_DUMP_HDR_NL_RECV|CM_DUMP_EXT_NL_RECV|CM_DUMP_HEX_NL_RECV)) {
		syslog(LOG_DEBUG, "----------------------------------------"
				"--------------------\n");

#ifdef NF_NETLINK_TABLES
		if (cm_debug_level & CM_DUMP_HDR_NL_RECV)
			syslog(LOG_DEBUG, "netlink_netfilter: %s/%s(%d) #%u len=%hu pid=%u\n",
					nlnf_subsys2str(h->nlmsg_type),
					nlnf_conntrack_nftype2str(h->nlmsg_type),
					h->nlmsg_type, h->nlmsg_seq,
					h->nlmsg_len, h->nlmsg_pid);
#endif /*NF_NETLINK_TABLES*/
	}

	if (nfnlmsg_subsys(h) != NFNL_SUBSYS_CTNETLINK)
		return 0;

	CM_INCREASE_NL_STATS(s, nfnlmsg_subtype(h));

	switch (nfnlmsg_subtype(h)) {
	case IPCTNL_MSG_CT_NEW:
		cm_nl_new_conntrack(h, s->vrfid);
		break;
	case IPCTNL_MSG_CT_DELETE:
		/* The message only contains a header. This is a flush */
		if (h->nlmsg_len == NLMSG_LENGTH(sizeof(struct nfgenmsg)))
			cm_nl_flush_conntrack(h);
		/* This is a normal delete message */
		else
			cm_nl_del_conntrack(h, s->vrfid);
		break;
	default:
		break;
	}

	return 0;
}

#ifdef CONFIG_CACHEMGR_AUDIT
/*
 * This is workaround for a kernel bug in audit code, the netlink message in the kernel does
 * not include the message head length, so we have to add it here.
 * libnl will use this length to make a new message.
 * This function is derived from libnl nl_recv(), some code being removed because
 * we don't have access to libnl's private code.
 */
static int cm_audit_nl_recv(struct nl_sock *sk, struct sockaddr_nl *nla,
			    unsigned char **buf, struct ucred **creds)
{
	ssize_t n;
	int flags = 0;
	static int page_size = 0;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = (void *) nla,
		.msg_namelen = sizeof(struct sockaddr_nl),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int retval = 0;

	if (!buf || !nla)
		return -NLE_INVAL;

	if (page_size == 0)
		page_size = getpagesize() * 4;

	iov.iov_len = nl_socket_get_msg_buf_size(sk) ? : page_size;

	iov.iov_base = malloc(iov.iov_len);

	if (!iov.iov_base) {
		retval = -NLE_NOMEM;
		goto abort;
	}

 retry:
	n = recvmsg(nl_socket_get_fd(sk), &msg, flags);

	if (!n) {
		retval = 0;
		goto abort;
	}

	if (n < 0) {
		if (errno == EINTR) {
			goto retry;
		}
		retval = -nl_syserr2nlerr(errno);
		goto abort;
	}

	if (iov.iov_len < n || (msg.msg_flags & MSG_TRUNC)) {
		void *tmp;
		/* Provided buffer is not long enough, enlarge it
		 * to size of n (which should be total length of the message)
		 * and try again. */
		iov.iov_len = n;
		tmp = realloc(iov.iov_base, iov.iov_len);
		if (!tmp) {
			retval = -NLE_NOMEM;
			goto abort;
		}
		iov.iov_base = tmp;
		flags = 0;
		goto retry;
	}

	if (flags != 0) {
		/* Buffer is big enough, do the actual reading */
		flags = 0;
		goto retry;
	}

	if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
		retval =  -NLE_NOADDR;
		goto abort;
	}

	retval = n;
 abort:
	if (retval <= 0) {
		free(iov.iov_base);
		iov.iov_base = NULL;
	} else {
		/*
		 * Add NLMSG_HDRLEN to nlmsg_len instead of the original value from kernel
		 */
		struct nlmsghdr *hdr = (struct nlmsghdr *) iov.iov_base;
		hdr->nlmsg_len += NLMSG_HDRLEN;
		*buf = iov.iov_base;
	}

	return retval;
}

static int cm_nlaudit_recv(struct nl_msg *msg, void *arg)
{
	struct nlsock *s = arg;
	struct nlmsghdr *h = nlmsg_hdr(msg);

#ifdef CONFIG_HA6W_SUPPORT
	/*
	 * This may be called in a close loop, so keep an eye
	 * on Health socket
	 */
	has_check_request(cmg_has);
#endif

	if (cm_debug_level &
	    (CM_DUMP_HDR_NL_RECV|CM_DUMP_EXT_NL_RECV|CM_DUMP_HEX_NL_RECV)) {
		syslog(LOG_DEBUG, "----------------------------------------"
		       "--------------------\n");

		if (cm_debug_level & CM_DUMP_HDR_NL_RECV)
			syslog(LOG_DEBUG, "%s: %s(%d) #%u len=%hu pid=%u\n",
			       __func__, nlaudit_type2str(h->nlmsg_type),
			       h->nlmsg_type, h->nlmsg_seq, h->nlmsg_len,
			       h->nlmsg_pid);
	}

	CM_INCREASE_NL_STATS(s, h->nlmsg_type);

	cm_nlaudit_dispatch(h, s->vrfid);

	return 0;
}

static void cm_nlaudit_dump_all(struct nlsock *cmn)
{
	/* AUDIT_NETFILTER_CFG */
	cm_iptc_dump_all_tables(cmn);
}
#endif /*CONFIG_CACHEMGR_AUDIT*/

static int cm_nlxfrm_recv(struct nl_msg *msg, void *arg)
{
	struct nlsock *s = arg;
	struct nlmsghdr *h = nlmsg_hdr(msg);

	/*TODO: add some para check here*/
	if (cm_debug_level &
		(CM_DUMP_HDR_NL_RECV|CM_DUMP_EXT_NL_RECV|CM_DUMP_HEX_NL_RECV))
	{
		syslog(LOG_DEBUG, "----------------------------------------"
				"--------------------\n");

		if (cm_debug_level & CM_DUMP_HDR_NL_RECV)
			syslog(LOG_DEBUG, "netlink_xfrm: %s(%d) #%u len=%hu pid=%u\n",
					nlxfrm_type2str(h->nlmsg_type),
					h->nlmsg_type, h->nlmsg_seq,
					h->nlmsg_len, h->nlmsg_pid);
	}

	CM_INCREASE_NL_STATS(s, h->nlmsg_type);

	cm_nl_xfrm_dispatch(h, s->vrfid);

	return 0;
}

#ifdef CONFIG_CACHEMGR_DIAG
static int cm_nldiag_dumprecv(struct nl_msg *msg, void *arg)
{
	struct nlsock *s = arg;
	struct nlmsghdr *h = nlmsg_hdr(msg);

	if (cm_debug_level &
	    (CM_DUMP_HDR_NL_RECV|CM_DUMP_EXT_NL_RECV|CM_DUMP_HEX_NL_RECV)) {
		syslog(LOG_DEBUG, "----------------------------------------"
		       "--------------------\n");

		if (cm_debug_level & CM_DUMP_HDR_NL_RECV)
			syslog(LOG_DEBUG, "%s: %s(%d) #%u len=%hu pid=%u\n",
			       __func__, nldiag_type2str(h->nlmsg_type),
			       h->nlmsg_type, h->nlmsg_seq, h->nlmsg_len,
			       h->nlmsg_pid);
	}

	CM_INCREASE_NL_STATS(s, h->nlmsg_type);

	cm_nldiag_dispatch(h, s);
	return 0;
}
#endif
/*
 *==========================================================
 * NETLINK sockets stuff (creation ...)
 *==========================================================
 */

extern int cm_nl_sockbufsiz;

/*
 * This function is used to overwrite libnl nl_recv function to always remove
 * the NLM_F_MULTI flag. This is a work around to a kernel bug which makes
 * some nl messages sent with the NLM_F_MULTI flag set whereas they shouldn't.
 * Note: it is only used with the "netlink-route-listen" socket.
 * Warning: This function MUST NOT be used on socket performing dumps.
 */
static int
cm_nl_recv_nomulti(struct nl_sock *sk, struct sockaddr_nl *nla,
		    unsigned char **buf, struct ucred **creds)
{
	int n;
	struct nlmsghdr *hdr;

	n = nl_recv(sk, nla, buf, creds);

	if (n <= 0)
		return n;

	hdr = (struct nlmsghdr *) *buf;
	hdr->nlmsg_flags &= ~NLM_F_MULTI;

	return n;
}

/*
 * This function is used to catch all dump requests.
 */
static int
cm_nl_send_cb(struct nl_msg *msg, void *arg)
{
	struct nlsock *cmn = arg;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);

	if (hdr->nlmsg_flags & NLM_F_MATCH) {
		cmn->dump_in_progress++;
		cm_nl_dump_in_progress++;
	}

	/* Always send the packet, no filtering done */
	return(NL_OK);
}

/*
 * This function is used to catch all dump requests.
 */
static int
cm_nl_finish_cb(struct nl_msg *msg, void *arg)
{
	struct nlsock *cmn = arg;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);

	/* End of a dump request */
	if (cmn->dump_in_progress > 0) {
		cmn->dump_in_progress--;

		/* If all dumps done, warn fpm */
		cm_nl_dump_in_progress--;
		if (cm_nl_dump_in_progress == 0) {
			/* Leave 1 in cm_nl_dump_in_progress to avoid more messages to be sent */
			cm_nl_dump_in_progress = 1;

			cm2cp_graceful_done(hdr->nlmsg_seq);
		}
	}

	/* Call finish callback if needed */
	if (cmn->hooks->finish_cb != NULL) {
		return(cmn->hooks->finish_cb(msg, arg));
	}

	return(NL_OK);
}

/* Return 1 if cmn->sk is alive, or 0 */
int cmn_socket_is_alive(struct nlsock *cmn)
{
	return !!(cmn->sk);
}

static int cm_nl_error_handler(struct sockaddr_nl *who,
	struct nlmsgerr *e, void *arg)
{
	struct nlsock *cmn = arg;
	char buf1[256];
	char buf2[33];
	char buf3[256];
	char buf4[128];

	buf2[32] = 0;
	strerror_r(-e->error, buf1, sizeof(buf1));
	snprintf(buf2, 32, "%s-%d", cmn->hooks->name, cmn->vrfid);
	nl_nlmsgtype2str(e->msg.nlmsg_type, buf3, sizeof(buf3));
	nl_nlmsg_flags2str(e->msg.nlmsg_flags, buf4, sizeof(buf4));
	syslog(LOG_INFO, "%s received on socket %s: type=%s length=%u "
	       "flags=<%s> sequence-nr=%u pid=%u\n",
	       buf1, buf2, buf3, e->msg.nlmsg_len, buf4, e->msg.nlmsg_seq,
	       e->msg.nlmsg_pid);

	if ((e->msg.nlmsg_flags & NLM_F_MATCH) &&
		(cmn->dump_in_progress > 0)) {
		cmn->dump_in_progress--;
		cm_nl_dump_in_progress--;
		if (cm_nl_dump_in_progress == 0) {
			/* Leave 1 in cm_nl_dump_in_progress to avoid more messages to be sent */
			cm_nl_dump_in_progress = 1;

			cm2cp_graceful_done(e->msg.nlmsg_seq);
		}
	}

	return NL_STOP;
}

void
cm_netlink_sock (int proto, struct nlsock *cmn, long groups, int listen,
		  int bulk, const struct timeval *tv, int ignore_multi)
{
	char name[32];
	snprintf(name, 32, "%s-%d", cmn->hooks->name, cmn->vrfid);

	cmn->sk = nl_socket_alloc();
	if (!cmn->sk) {
		syslog(LOG_ERR, "%s: failed to allocate netlink socket(%s)\n", __func__, name);
		return;
	}

	nl_join_groups(cmn->sk, groups);
	nl_socket_disable_auto_ack(cmn->sk);
	if (nl_connect(cmn->sk, proto) < 0) {
		syslog(LOG_ERR, "%s: failed to connect netlink socket(%s)\n", __func__, name);
		nl_socket_free(cmn->sk);
		cmn->sk = NULL;
		return;
	}

	if (cmn->hooks->recv)
		nl_socket_modify_cb(cmn->sk, NL_CB_VALID, NL_CB_CUSTOM, cmn->hooks->recv, cmn);

	if (ignore_multi)
		nl_cb_overwrite_recv(nl_socket_get_cb(cmn->sk), cm_nl_recv_nomulti);
	nl_socket_modify_cb(cmn->sk, NL_CB_MSG_OUT, NL_CB_CUSTOM, cm_nl_send_cb, cmn);
	nl_socket_modify_cb(cmn->sk, NL_CB_FINISH, NL_CB_CUSTOM, cm_nl_finish_cb, cmn);

	nl_socket_modify_err_cb(cmn->sk, NL_CB_CUSTOM, cm_nl_error_handler, cmn);

	if (nl_socket_set_buffer_size(cmn->sk, cm_nl_sockbufsiz, cm_nl_sockbufsiz) < 0)
		syslog(LOG_ERR, "%s: failed to set receiving/sending buffer size to %d\n", __func__, cm_nl_sockbufsiz);

	if (listen) {
#ifdef NETLINK_BULK_MSG
		if (bulk) {
			unsigned int opt = 1;
			socklen_t optlen = sizeof(opt);
			if (setsockopt(nl_socket_get_fd(cmn->sk), SOL_NETLINK, NETLINK_BULK_MSG,
				       &opt, optlen) < 0)
				syslog(LOG_ERR, "Could not set BULK_MSG socket option\n");
		}
#endif
		cmn->ev = event_new(cm_event_base, nl_socket_get_fd(cmn->sk),
				    EV_READ | EV_PERSIST,
				    cm_nl_recv_event, cmn);

		event_add (cmn->ev, NULL);

		if (tv != NULL) {
			cmn->timeout_tv = *tv;
			cmn->timeout_ev = evtimer_new(cm_event_base, cm_nl_recv_event, cmn);
			evtimer_add(cmn->timeout_ev, &cmn->timeout_tv);
		}
	}
	return;
}

void
cm_close_netlink_sock (struct nlsock *cmn, int listen)
{
	if (listen) {
		if (cmn->ev) {
			event_free(cmn->ev);
			cmn->ev = NULL;
		}
		if (cmn->timeout_ev) {
			event_free(cmn->timeout_ev);
			cmn->timeout_ev = NULL;
		}
	}
	nl_socket_free(cmn->sk);
	cmn->sk = NULL;
	return;
}

static void cm_netlink_cmd_init(struct nlsock *cmn)
{
	cm_netlink_sock (NETLINK_ROUTE, cmn, 0, 0, CM_BULK_READ, NULL, 0);
#ifdef HAVE_IFLA_BOND
	cm_nl_bonding_init(cmn);
#endif
}

static void cm_netlink_cmd_destroy(struct nlsock *cmn)
{
	cm_close_netlink_sock (cmn, 0);
#ifdef HAVE_IFLA_BOND
	cm_nl_bonding_destroy(cmn);
#endif
}

static void cm_netlink_svti_init(struct nlsock *cmn)
{
	cm_netlink_sock (NETLINK_ROUTE, cmn, 0, 0, CM_BULK_READ, NULL, 0);
}

static void cm_netlink_svti_destroy(struct nlsock *cmn)
{
	cm_close_netlink_sock (cmn, 0);
}

#include <linux/connector.h>

static void cm_netlink_connector_init(struct nlsock *cmn)
{
	if (cm_bpf_notify != CM_BPF_PATTERN_ONLY)
		return;

	cm_netlink_sock (NETLINK_CONNECTOR, cmn, CN_IDX_PROC, 1, 0, NULL, 0);

	if (!cmn->sk)
		return;

	cm_nl_connector_start(cmn);
}

static void cm_netlink_connector_destroy(struct nlsock *cmn)
{
	if (cm_bpf_notify != CM_BPF_PATTERN_ONLY)
		return;
	cm_nl_connector_stop(cmn);
	cm_close_netlink_sock (cmn, 1);
}
static void cm_netlink_route_init(struct nlsock *cmn)
{
	/*
	 * We want to receive
	 *    iface info
	 *    addresses
	 *    routes
	 * This needs to be updated with additional
	 * netlink resources
	 */
	cm_netlink_sock (NETLINK_ROUTE,
			cmn,
			(RTMGRP_LINK | RTMGRP_NEIGH | RTMGRP_NOTIFY |
			 RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE |
			 RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR
#ifdef RTM_NEWNETCONF
			 | nl_mgrp(RTNLGRP_IPV4_NETCONF) |
			 nl_mgrp(RTNLGRP_IPV6_NETCONF)
#endif
			 | nl_mgrp(RTNLGRP_IPV4_MROUTE)
			 | nl_mgrp(RTNLGRP_IPV6_MROUTE)
			 ),
			 1, CM_BULK_READ, NULL, 1);
}

static void cm_netlink_route_destroy(struct nlsock *cmn)
{
	cm_close_netlink_sock (cmn, 1);
}

#ifdef NF_NETLINK_TABLES
static void cm_netlink_netfilter_table_init(struct nlsock *cmn)
{
	cm_netlink_sock(NETLINK_NETFILTER, cmn,
			NF_NETLINK_TABLES, 1, CM_BULK_READ, NULL, 0);
}
static void cm_netlink_netfilter_table_destroy(struct nlsock *cmn)
{
	cm_close_netlink_sock(cmn, 1);
}
#endif

#ifdef NF_NETLINK_LSN_CPE
static void cm_netlink_netfilter_cpe_init(struct nlsock *cmn)
{
	if (cm_disable_nl_nfct == 0)
		cm_netlink_sock(NETLINK_NETFILTER, cmn,
				NF_NETLINK_LSN_CPE | NF_NETLINK_LSN_CPE_LOG,
				1, CM_BULK_READ, NULL, 0);
}

static void cm_netlink_netfilter_cpe_destroy(struct nlsock *cmn)
{
	if (cm_disable_nl_nfct == 0)
		cm_close_netlink_sock(cmn, 1);
}
#endif

static void cm_netlink_netfilter_conntrack_init(struct nlsock *cmn)
{
	if (cm_disable_nl_nfct == 0)
		cm_netlink_sock(NETLINK_NETFILTER, cmn,
				(NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE |
				 NF_NETLINK_CONNTRACK_DESTROY), 1, CM_BULK_READ, NULL, 0);
}

static void cm_netlink_netfilter_conntrack_destroy(struct nlsock *cmn)
{
	if (cm_disable_nl_nfct == 0)
		cm_close_netlink_sock(cmn, 1);
}

#ifdef CONFIG_CACHEMGR_AUDIT
static void cm_netlink_audit_init(struct nlsock *cmn)
{
	struct audit_rule_data rule;
	struct nl_cb *cb;

	cm_netlink_sock(NETLINK_AUDIT, cmn, 0, 1,
			CM_BULK_READ, NULL, 0);

	/* if cmn->sk is null, it is probably because AUDIT support
	   is disabled in the kernel */
	if (!cmn->sk)
		return;

	cb = nl_socket_get_cb(cmn->sk);
	if (!cb) {
		nl_socket_free(cmn->sk);
		cmn->sk = NULL;
		return;
	}
	nl_cb_put(cb);
	nl_cb_overwrite_recv(cb, cm_audit_nl_recv);

	cm_nlaudit_set_pid(cmn->sk);
	cm_nlaudit_set_enabled(cmn->sk, 1);
	cm_nlaudit_rule_init(&rule, AUDIT_FILTER_TYPE, AUDIT_ALWAYS);
	cm_nlaudit_rule_add_filter(&rule, AUDIT_MSGTYPE, AUDIT_NOT_EQUAL,
				   AUDIT_NETFILTER_CFG);
	cm_nlaudit_rule_add(cmn->sk, &rule);
}

static void cm_netlink_audit_destroy(struct nlsock *cmn)
{
	struct audit_rule_data rule;

	cm_nlaudit_rule_init(&rule, AUDIT_FILTER_TYPE, AUDIT_ALWAYS);
	cm_nlaudit_rule_add_filter(&rule, AUDIT_MSGTYPE, AUDIT_NOT_EQUAL,
				   AUDIT_NETFILTER_CFG);
	cm_nlaudit_set_enabled(cmn->sk, 0);
	cm_nlaudit_rule_del(cmn->sk, &rule);
	cm_close_netlink_sock(cmn, 1);
}
#endif

static void cm_netlink_xfrm_listen_init(struct nlsock *cmn)
{
	cm_netlink_sock(NETLINK_XFRM, cmn,
			( XFRMGRP_SA
#ifdef XFRMGRP_NOTIFY
			| XFRMGRP_NOTIFY
#endif /*XFRMGRP_NOTIFY*/
			| XFRMGRP_POLICY | XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE),
			1, CM_BULK_READ, NULL, 0);
}

static void cm_netlink_xfrm_listen_destroy(struct nlsock *cmn)
{
	cm_close_netlink_sock(cmn, 1);
}

static void cm_netlink_xfrm_cmd_init(struct nlsock *cmn)
{
	cm_netlink_sock(NETLINK_XFRM, cmn, 0, 0, CM_BULK_READ, NULL, 0);
}

static void cm_netlink_xfrm_cmd_destroy(struct nlsock *cmn)
{
	cm_close_netlink_sock(cmn, 0);
}

static void cm_diag_cmd_init(struct nlsock *cmn)
{
	if (cm_bpf_notify == CM_BPF_NEVER)
		return;

#ifdef CONFIG_CACHEMGR_DIAG
	cm_netlink_sock(NETLINK_INET_DIAG, cmn, 0, 0, CM_BULK_READ, NULL, 0);
	/* fallback to periodic scan of proc/net/packet if diag socket failed */
	if (cmn_socket_is_alive(cmn)) {
		if (cmn->vrfid == 0 && cm_bpf_notify == CM_BPF_ALWAYS)
			cm_nldiag_start_timer();
	} else
#endif
		if (cmn->vrfid == 0 && cm_bpf_notify == CM_BPF_ALWAYS)
			cm_proc_packet_start_timer();
}

static void cm_diag_cmd_destroy(struct nlsock *cmn)
{
	if (cm_bpf_notify == CM_BPF_NEVER)
		return;

#ifdef CONFIG_CACHEMGR_DIAG
	if (cmn_socket_is_alive(cmn)) {
		cm_close_netlink_sock(cmn, 0);
		if (cmn->vrfid == 0 && cm_bpf_notify == CM_BPF_ALWAYS)
			cm_nldiag_stop_timer();
	} else
#endif
		if (cmn->vrfid == 0 && cm_bpf_notify == CM_BPF_ALWAYS)
			cm_proc_packet_stop_timer();
}

struct nlsock_hooks nlsock_hooks[CM_MAX] =
{
	[CM_NETLINK] = {
		.name = "netlink-route-listen",
		.init = cm_netlink_route_init,
		.destroy = cm_netlink_route_destroy,
		.recv = cm_nl_recv,
		.dump = NULL,
		.gr_dump = cm_nl_route_dump,
		.gr_type = CM_GR_TYPE_ROUTE,
		.stats = cm_nlroute_stats,
		.size = CM_ARRAY_SIZE(cm_nlroute_stats),
		.type2str = rtm_type2str,
	},
	[CM_NETCMD] = {
		.name = "netlink-route-cmd",
		.init = cm_netlink_cmd_init,
		.destroy = cm_netlink_cmd_destroy,
		.dump = cm_nl_route_dump,
		.recv = cm_nl_recv,
		.stats = cm_nlroutecmd_stats,
		.size = CM_ARRAY_SIZE(cm_nlroutecmd_stats),
		.type2str = rtm_type2str,
	},
	[CM_SVTI] = {
		.name = "netlink-svti-cmd",
		.init = cm_netlink_svti_init,
		.destroy = cm_netlink_svti_destroy,
		.recv = cm_nl_getsvti,
	},
	[CM_XFRM] = {
		.name = "netlink-xfrm-listen",
		.init = cm_netlink_xfrm_listen_init,
		.destroy = cm_netlink_xfrm_listen_destroy,
		.dump = NULL,
		.recv = cm_nlxfrm_recv,
		.gr_dump = cm_nl_xfrm_dump,
		.gr_type = CM_GR_TYPE_XFRM,
		.stats = cm_nlxfrm_stats,
		.size = CM_ARRAY_SIZE(cm_nlxfrm_stats),
		.type2str = nlxfrm_type2str,
	},
	[CM_XFRM_CMD] = {
		.name = "netlink-xfrm-cmd",
		.init = cm_netlink_xfrm_cmd_init,
		.destroy = cm_netlink_xfrm_cmd_destroy,
		.dump = cm_nl_xfrm_dump,
		.recv = cm_nlxfrm_recv,
		.stats = cm_nlxfrmcmd_stats,
		.size = CM_ARRAY_SIZE(cm_nlxfrmcmd_stats),
		.type2str = nlxfrm_type2str,
	},
#ifdef NF_NETLINK_TABLES
	[CM_NF_TABLE] = {
		.name = "netlink-netfilter-table-listen",
		.init = cm_netlink_netfilter_table_init,
		.destroy = cm_netlink_netfilter_table_destroy,
		.dump = cm_iptc_dump_all_tables,
		.recv = cm_nlnf_table_recv,
		.gr_dump = cm_iptc_dump_all_tables,
		.gr_type = CM_GR_TYPE_NFTABLES,
		.stats = cm_nlnf_table_stats,
		.size = CM_ARRAY_SIZE(cm_nlnf_table_stats),
		.type2str = nlnf_tables_type2str,
	},
#endif
#ifdef NF_NETLINK_LSN_CPE
	[CM_NF_CPE] = {
		.name = "netlink-netfilter-cpe-listen",
		.init = cm_netlink_netfilter_cpe_init,
		.destroy = cm_netlink_netfilter_cpe_destroy,
		.dump = NULL,
		.recv = cm_nlnf_cpe_recv,
		.gr_dump = NULL,
		.gr_type = CM_GR_TYPE_NFCPE,
		.stats = cm_nlnf_cpe_stats,
		.size = CM_ARRAY_SIZE(cm_nlnf_cpe_stats),
		.type2str = nlnf_cpe_type2str,
	},
#endif
	[CM_NF_CONNTRACK] = {
		.name = "netlink-netfilter-conntrack-listen",
		.init = cm_netlink_netfilter_conntrack_init,
		.destroy = cm_netlink_netfilter_conntrack_destroy,
		.dump = NULL,
		.recv = cm_nlnf_conntrack_recv,
		.gr_dump = NULL, /* TODO: cm_nlnf_conntrack_dump */
		.stats = cm_nlnf_conntrack_stats,
		.size = CM_ARRAY_SIZE(cm_nlnf_conntrack_stats),
		.type2str = nlnf_conntrack_type2str,
	},
#ifdef CONFIG_CACHEMGR_AUDIT
	[CM_AUDIT] = {
		.name = "netlink-audit-listen",
		.init = cm_netlink_audit_init,
		.destroy = cm_netlink_audit_destroy,
		.dump = cm_iptc_dump_all_tables,
		.recv = cm_nlaudit_recv,
		.gr_dump = cm_nlaudit_dump_all,
		.gr_type = CM_GR_TYPE_AUDIT,
		.stats = cm_audit_stats,
		.size = CM_ARRAY_SIZE(cm_audit_stats),
		.type2str = nlaudit_type2str,
		.vrf0_only = 1,
	},
#endif
	[CM_DIAG] = {
		.name = "netlink-diag-cmd",
		.init = cm_diag_cmd_init,
		.destroy = cm_diag_cmd_destroy,
		.dump = NULL,
		.gr_dump = NULL,
		.gr_type = 0,
#ifdef CONFIG_CACHEMGR_DIAG
		.recv = cm_nldiag_dumprecv,
		.stats = cm_nldiag_stats,
		.size = CM_ARRAY_SIZE(cm_nldiag_stats),
		.type2str = nldiag_type2str,
#endif
	},
	[CM_CONNECTOR] = {
		.name = "netlink-connector",
		.init = cm_netlink_connector_init,
		.destroy = cm_netlink_connector_destroy,
		.finish_cb = cm_nl_getconnector,
		.dump = NULL,
		.gr_dump = NULL,
		.gr_type = 0,
		.recv = NULL,
		.stats = NULL,
	},
};

/*
 * Register a struct nlsock_hooks into nlsock_hooks[] in the area between
 * and including CM_REGISTERED_FIRST and CM_REGISTERED_LAST.
 * If successful, this function returns the new array index, otherwise,
 * -1 is returned.
 */
int cm_nlsock_hooks_register(struct nlsock_hooks *hooks)
{
	unsigned int i;

	for (i = CM_REGISTERED_FIRST; (i <= CM_REGISTERED_LAST); ++i) {
		if (nlsock_hooks[i].name != NULL) {
			if (strcmp(hooks->name, nlsock_hooks[i].name) == 0)
				return -1;
			continue;
		}
		nlsock_hooks[i] = *hooks;
		return i;
	}
	return -1;
}
