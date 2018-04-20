/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *
 *                CM internals for Netlink
 *
 * $Id: cm_netlink.h,v 1.18 2010-02-18 09:51:07 guerin Exp $
 ***************************************************************
 */

extern int cm_nl_dump_in_progress;

/*
 * Netlink Tools
 */
extern int cm_nl_parse_nlattr (struct nlattr **, int, struct nlattr *, int, int);
extern int cm_nlmsg_parse (struct nlmsghdr *h, int hdrlen, struct nlattr **tb, int maxtype, int family);
extern int cm_nl_parse_nlattr_byindex (struct nlattr **, int, struct nlattr *, int, int);
extern int cm_genlmsg_parse(struct nlmsghdr *h, int hdrlen, struct nlattr **tb, int max, int family);
static inline __u32 nl_mgrp(__u32 group)
{
	if (group > RTNLGRP_MAX ) {
		fprintf(stderr, "Use setsockopt for this group %d\n", group);
		exit(-1);
	}
	return group ? (1 << (group - 1)) : 0;
}

/*
 * Netlink MSG analysis
 */
extern void cm_nl_iface_addr (struct nlmsghdr *, u_int32_t);
extern void cm_nl_link (struct nlmsghdr *, u_int32_t);
extern void cm_nl_route (struct nlmsghdr *, u_int32_t);
extern void cm_nl_bpf(struct nlmsghdr *);


extern void cm_nl_nat (struct nlmsghdr *h);
extern void cm_nl_l2 (struct nlmsghdr *h, u_int32_t);
#ifdef RTM_NEWNETCONF
extern void cm_nl_netconf (struct nlmsghdr *h, u_int32_t);
#endif
