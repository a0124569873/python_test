/*
 * Copyright 2004-2013 6WIND S.A.
 */

/*
 * Copyright 1998 WIDE Project
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <netinet/in.h>
#ifndef __linux__
#include <net/if_dl.h>
#include <netinet6/ip6_mroute.h>
#endif
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <ifaddrs.h>

#include <syslog.h>

#include "snoop.h"
#include "mld.h"
#include "mldv2.h"
#include <event.h>

#include "config.h"

#include "in_cksum.h"


#define RECV_BUFFER_SIZE 4096

/*
 * ICMPv6 raw socket and packet buffer for sending MLDv2 Queries
 */
int mld6_socket = -1;		/* socket for all icmp6 network I/O */
int pim6_socket = -1;		/* socket for all pim6 network I/O */
struct sockaddr_in6 allnodes_group = {sizeof(struct sockaddr_in6), AF_INET6};
struct sockaddr_in6 allrouters_group = {sizeof(struct sockaddr_in6), AF_INET6};
struct sockaddr_in6 allmldv2routers_group = {sizeof(struct sockaddr_in6), AF_INET6};
struct sockaddr_in6 allpim6routers_group = {sizeof(struct sockaddr_in6), AF_INET6};

static char *mld6_send_buf;		/* output packet buffer */
static char *mld6_recv_buf;		/* input packet buffer */
static char *pim6_recv_buf;		/* input packet buffer */
static struct msghdr sndmh, rcvmh, pim6_rcvmh;		/* message header to be passed in sendmsg */
static unsigned char *sndcmsgbuf, rcvcmsgbuf[RECV_BUFFER_SIZE], pim6_rcvcmsgbuf[RECV_BUFFER_SIZE];
static int ctlbuflen = 0;
static int rcvcmsglen = RECV_BUFFER_SIZE;
static int pim6_rcvcmsglen = RECV_BUFFER_SIZE;
static struct iovec sndiov[2], rcviov[2], pim6_rcviov[2];
static struct sockaddr_in6 dst_sa;	/* MLD packet destination address  */
static struct sockaddr_in6      from;
static struct sockaddr_in6      pim6_from;
static struct event mld_event;
static struct event pim6_event;

#ifndef USE_RFC2292BIS
static u_int8_t raopt[IP6OPT_RTALERT_LEN];
#endif
static u_int16_t rtalert_code;


/* returns <0, ==0 or >0 if sa1 is less, equal or greater than sa2 */
static int inet6_compare(struct in6_addr * sa1, struct in6_addr * sa2)
{
    return memcmp(sa1->s6_addr, sa2->s6_addr, 16);
}

static void
pim6_received (struct eth_if *ifp, int port)
{
	struct proto_mc_param *mcp = &(ifp->if_mld_pr);
        struct eth_port *prt;
        int portidx = get_port_for_ifp (ifp, port);

        if (!ifp->if_started_mld || !mcp->pr_snooping || portidx < 0)
                return;

	prt = &ifp->if_port[portidx];
	syslog (LOG_DEBUG, "PIM6 msgt received on %s (port %d)\n", ifp->if_name, port);

	if (prt->prt_rtr6_tmo != TMO_INFINITE)
		prt->prt_rtr6_tmo = compute_deadline (PR_LISTENER_INTERVAL(mcp));
	if (!PORT_ISSET(port, &ifp->if_rtr6)) {
		PORT_SET(port, &ifp->if_rtr6);
		notify_port_list (SET_MLD_ROUTERS, ifp);
	}
	return;
}

static void
mld_received(struct eth_if *ifp, int port, struct in6_addr *src, struct in6_addr *dst, struct mld_hdr *mldh, int len)
{
	struct mld_report_hdr *report;
	struct mld_group_record_hdr *mard;
	int i, nummard, numsrc, totsrc;
	u_int8_t *p;
	struct sockaddr_in6 grp, intfaddr6;
	struct proto_mc_param *mcp = &(ifp->if_mld_pr);
	struct querier_event *qep = &(ifp->if_mld_querier_ev);
	char buf_group [128];
	int hbhlen;
	struct eth_port *prt;
	int portidx = get_port_for_ifp (ifp, port);

	if (!ifp->if_started_mld || !mcp->pr_snooping || portidx < 0)
		return;

	prt = &ifp->if_port[portidx];
	memset (&grp, 0, sizeof(grp));
#ifdef HAVE_SIN_LEN
	grp.sin6_len = sizeof(grp);
#endif
	grp.sin6_family = AF_INET6;
	if (mldh->mld_type != MLD6V2_LISTENER_REPORT) {
		grp.sin6_addr = mldh->mld_addr;
		display_sa (buf_group, (struct sockaddr *)&grp);
	}

	switch (mldh->mld_type) {
		case MLD6_LISTENER_QUERY:
		{
			/*
			 * Drop self-generated queries
			 */
			if ((mcp->pr_querier_status == PR_QUERIER) && (qep->qrr_myquery_ind > 0)) {
				ip6_get_lladdr(ifp->if_name, &intfaddr6);
				if (IN6_ARE_ADDR_EQUAL(&(intfaddr6.sin6_addr), src)) {
					qep->qrr_myquery_ind--;
					break;
				}
			}
			/*
			 * Query from other querier :
			 * - non-router behaviour : withdraw querier responsibilty
			 * - router behaviour : election process
			 *
			 */
			/* Some of the following logic could be moved to some IP-agnostic part */
			int withdraw = 0;
			if (mcp->pr_querier_candidature == PR_ROUTER_CANDIDATE) {
				/* ROUTER behaviour */
				/* Compare our address to the one from the query received */
				/* We are ignoring queries from lower addresses */
				ip6_get_lladdr(ifp->if_name, &intfaddr6);
				if (inet6_compare(&intfaddr6.sin6_addr, src) < 0) {
						syslog (LOG_INFO, "---- other MLD querier detected at %s on %s - ignored\n", inet6_fmt(src), ifp->if_name);
						withdraw = 1;
				}
			}
			if (mcp->pr_querier_status == PR_QUERIER) {
				if (!withdraw) {
					int version;
					mcp->pr_querier_status = PR_NONQUERIER;
					qep->qrr_gq_timer = TMO_INFINITE;
					if (len == sizeof(struct icmp6_hdr)) {
						version = PR_VERSION_MLDv1;
					} else {
						version = PR_VERSION_MLDv2;
					}
					if (mcp->pr_querier_version == PR_VERSION_UNKNOWN || version < mcp->pr_querier_version)
						mcp->pr_querier_version = version;
					syslog (LOG_INFO, "----> switching to non-querier state for interface %s (other MLDv%d querier detected at %s)\n",
						ifp->if_name, mcp->pr_querier_version-PR_VERSION_UNKNOWN, inet6_fmt(src));
				}
			}

			if ((mcp->pr_querier_candidature == PR_QUERIER_CANDIDATE) || ((mcp->pr_querier_candidature == PR_ROUTER_CANDIDATE) && !withdraw)) {
				/*
				 * Restart querier timer
				 */
				qep->qrr_timer = compute_deadline(mcp->pr_querier_timeout);
			}

			if (!IN6_IS_ADDR_UNSPECIFIED (&mldh->mld_addr)) {
				if (mcp->pr_querier_status != PR_QUERIER)
					specific_group_received (ifp, (struct sockaddr *)&grp,
						mldh->mld_type);
				syslog (LOG_DEBUG,
				        "MLD m-a-s query received on %s (port %d) for %s\n",
				        ifp->if_name, port, buf_group);
			}
			else {
				syslog (LOG_DEBUG,
				        "MLD general query received on %s (port %d)\n",
				        ifp->if_name, port);
			}

			/*
			 * Update MLD port list and timer
			 */
			if (prt && !IN6_IS_ADDR_UNSPECIFIED(src)) {
				if (prt->prt_rtr6_tmo != TMO_INFINITE)
					prt->prt_rtr6_tmo = compute_deadline (PR_LISTENER_INTERVAL(mcp));
				if (!PORT_ISSET(port, &ifp->if_rtr6)) {
					PORT_SET(port, &ifp->if_rtr6);
					notify_port_list (SET_MLD_ROUTERS, ifp);
				}
			}
			break;
		}
		case MLD6_LISTENER_DONE:
			if (mcp->pr_querier_status == PR_QUERIER) {
				specific_group_received (ifp, (struct sockaddr *)&grp,
						mldh->mld_type);
			}
			syslog (LOG_DEBUG,
			        "MLD done received on %s (port %d) for %s\n",
			        ifp->if_name, port, buf_group);
			break;
		case MLD6_LISTENER_REPORT:
			/*
			 * Only manage non link-local membership, for all
			 * link-local mcast (apart from MLD) will be forwarded
			 * to ALL ports
			 */
			if (!IN6_IS_ADDR_MC_LINKLOCAL(&grp.sin6_addr))
				report_received (ifp, prt, (struct sockaddr *)&grp);
			syslog (LOG_DEBUG,
			        "MLDv1 report received on %s (port %d) for %s\n",
			        ifp->if_name, port, buf_group);
			if (mcp->pr_querier_version == PR_VERSION_UNKNOWN || PR_VERSION_MLDv1 < mcp->pr_querier_version)
				mcp->pr_querier_version = PR_VERSION_MLDv1;
			break;
		case MLD6V2_LISTENER_REPORT:
			syslog (LOG_DEBUG,
			        "MLDv2 report received on %s (port %d):\n",
			        ifp->if_name, port);
			/*
			 * loop through each multicast record,
			 * extract only group information and
			 * ignore source list
			 */
			report = (struct mld_report_hdr *) mldh;
			nummard = ntohs(report->mld_grpnum);
			totsrc = 0;

			for (i = 0; i < nummard; i++) {
				struct mld_group_record_hdr *mard0 = (struct mld_group_record_hdr *)(report + 1);
				p = (u_int8_t *)(mard0 + i) - sizeof(struct in6_addr) * i + totsrc * sizeof(struct in6_addr);
				mard = (struct mld_group_record_hdr *) p;
				numsrc = ntohs(mard->numsrc);
				totsrc += numsrc;

				grp.sin6_addr = mard->group;
				display_sa (buf_group, (struct sockaddr *)&grp);
				syslog (LOG_DEBUG,
				    " + group reported: %s\n", buf_group);

				if (IN6_IS_ADDR_MC_LINKLOCAL(&grp.sin6_addr)) {
					continue;
				}
				/*
				 * No fast leave for MLDv2 as of now
				 * So update group timer for all record types
				 */
				report_received (ifp, prt, (struct sockaddr *)&grp);
			}
			if (mcp->pr_querier_version == PR_VERSION_UNKNOWN || PR_VERSION_MLDv2 < mcp->pr_querier_version)
				mcp->pr_querier_version = PR_VERSION_MLDv2;
			break;
	}
	return;
}

static void pim6_decode(int recvlen)
{
	struct in6_addr *group, *dst = NULL;
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;
	int *hlimp = NULL;
	u_int ifindex = 0;
	struct sockaddr_in6 *src = (struct sockaddr_in6 *) pim6_rcvmh.msg_name;
	struct eth_if *ifp = 0;

	/* extract optional information via Advanced API */
	for (cm = (struct cmsghdr *) CMSG_FIRSTHDR(&pim6_rcvmh);
	     cm;
	     cm = (struct cmsghdr *) CMSG_NXTHDR(&pim6_rcvmh, cm))
	{
		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo)))
		{
			pi = (struct in6_pktinfo *) (CMSG_DATA(cm));
			ifindex = (u_int)pi->ipi6_ifindex;
			ifp = get_ifp_index(ifindex);
			if (!ifp || ifp->if_bridge)
				return;
			dst = &pi->ipi6_addr;
		}
		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_HOPLIMIT &&
		    cm->cmsg_len == CMSG_LEN(sizeof(int)))
		{
			hlimp = (int *) CMSG_DATA(cm);
		}
	}
	if (ifindex == 0)
	{
		log_msg(LOG_WARNING, 0, "failed to get receiving interface");
		return;
	}
	if (ifp) {
		pim6_received (ifp, 0);
	}
}

static void decode(int recvlen)
{
	struct in6_addr *dst = NULL;
	struct mld_hdr *mldh;
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;
	int *hlimp = NULL;
	u_int ifindex = 0;
	struct sockaddr_in6 *src = (struct sockaddr_in6 *) rcvmh.msg_name;
	struct eth_if *ifp = 0;

	if (recvlen < sizeof(struct mld_hdr))
	{
		log_msg(LOG_WARNING, 0,
		    "received packet too short (%u bytes) for MLD header",
		    recvlen);
		return;
	}
	mldh = (struct mld_hdr *) rcvmh.msg_iov[0].iov_base;

	/* extract optional information via Advanced API */
	for (cm = (struct cmsghdr *) CMSG_FIRSTHDR(&rcvmh);
	     cm;
	     cm = (struct cmsghdr *) CMSG_NXTHDR(&rcvmh, cm))
	{
		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo)))
		{
			pi = (struct in6_pktinfo *) (CMSG_DATA(cm));
			ifindex = (u_int)pi->ipi6_ifindex;
			ifp = get_ifp_index(ifindex);
			if (!ifp || ifp->if_bridge)
				return;
			dst = &pi->ipi6_addr;
		}
		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_HOPLIMIT &&
		    cm->cmsg_len == CMSG_LEN(sizeof(int)))
		{
			hlimp = (int *) CMSG_DATA(cm);
		}
	}
	if (hlimp == NULL)
	{
		log_msg(LOG_WARNING, 0,
		    "failed to get receiving hop limit");
		return;
	}

	/* hop limit check */
	if (*hlimp != 1)
	{
		log_msg(LOG_WARNING, 0,
		    "received an MLD6 message with illegal hop limit(%d) from %s",
		    *hlimp, sa6_fmt(src));
		/*
		 * But accept the packet in case of MLDv1, since RFC2710
		 * does not mention whether to discard such MLD packets or not.
		 * Whereas in case of MLDv2, it'll be discarded as is stated in
		 * draft-vida-mld-v2-08.txt section 6.2.
		 */
	}
	if (ifindex == 0)
	{
		log_msg(LOG_WARNING, 0, "failed to get receiving interface");
		return;
	}

	/* scope check */
	if (IN6_IS_ADDR_MC_NODELOCAL(&mldh->mld_addr))
	{
		log_msg(LOG_INFO, 0,
		    "RECV with an invalid scope: %s from %s",
		    inet6_fmt(&mldh->mld_addr), sa6_fmt(src));
		return;			/* discard */
	}

	/* source address check */
        if (!IN6_IS_ADDR_LINKLOCAL(&src->sin6_addr) &&
            !IN6_IS_ADDR_UNSPECIFIED(&src->sin6_addr)) {
                syslog (LOG_WARNING, "decode: bad src address \n");
                return;
        }

        if (!IN6_IS_ADDR_MULTICAST(dst)) {
                syslog (LOG_WARNING, "decode: bad dst address \n");
                return;
        }

	mld_received(ifp, 0, &src->sin6_addr, dst, mldh, recvlen);
}


/* PIM6 RAW socket receive callback */
static void pim6_callback(int fd, short event, void *param)
{
	int n = recvmsg(fd, &pim6_rcvmh, 0);
        if (n > 0) {
		pim6_decode(n);
        } else if (param) {
                /* disconnection */
                struct event *ev = (struct event *)param;
                event_del(ev);
                free(ev);
        }
}


/* ICMP6 RAW socket receive callback */
static void mld_callback(int fd, short event, void *param)
{
	int n = recvmsg(fd, &rcvmh, 0);
        if (n > 0) {
		decode(n);
        } else if (param) {
                /* disconnection */
                struct event *ev = (struct event *)param;
                event_del(ev);
                free(ev);
        }
}


/* join/leave MLD group */
int
mld_join_group(struct sockaddr_in6 *group, int ifindex, int join)
{
	struct ipv6_mreq mreq;

	mreq.ipv6mr_multiaddr = group->sin6_addr;
	mreq.ipv6mr_interface = ifindex;

	if (setsockopt(mld6_socket, IPPROTO_IPV6, join?IPV6_JOIN_GROUP:IPV6_LEAVE_GROUP, (char *) &mreq, sizeof(mreq)) < 0)
                        return -1;
	return 0;
}

/*
pim6_socket, allpim6routers_group
mld6_socket, allrouters_group
mld6_socket, allmldv2routers_group
*/
int
mld_join_routers_group(int ifindex, int join)
{
	struct ipv6_mreq mreq;

	mreq.ipv6mr_interface = ifindex;

	mreq.ipv6mr_multiaddr = allpim6routers_group.sin6_addr;
	if (setsockopt(pim6_socket, IPPROTO_IPV6, join?IPV6_JOIN_GROUP:IPV6_LEAVE_GROUP, (char *) &mreq, sizeof(mreq)) < 0)
                        return -1;
	mreq.ipv6mr_multiaddr = allrouters_group.sin6_addr;
	if (setsockopt(mld6_socket, IPPROTO_IPV6, join?IPV6_JOIN_GROUP:IPV6_LEAVE_GROUP, (char *) &mreq, sizeof(mreq)) < 0)
                        return -1;
	mreq.ipv6mr_multiaddr = allmldv2routers_group.sin6_addr;
	if (setsockopt(mld6_socket, IPPROTO_IPV6, join?IPV6_JOIN_GROUP:IPV6_LEAVE_GROUP, (char *) &mreq, sizeof(mreq)) < 0)
                        return -1;
	return 0;
}


/* initialise ICMP6 RAW socket */
void
mld_init(void)
{
	struct icmp6_filter filt;
	int hlim, on;
	int err = 0;

	rtalert_code = htons(IP6OPT_RTALERT_MLD);

	if (!mld6_send_buf && (mld6_send_buf = malloc(SEND_BUF_SIZE)) == NULL)
		log_msg(LOG_ERR, ENOMEM, "mld_init: malloc failed");

	log_msg(LOG_DEBUG, 0,
		"mld_init: %d octets allocated for MLD emit buffer", SEND_BUF_SIZE);

	if ((mld6_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		log_msg(LOG_ERR, errno,
			"mld_init: unable to open ICMPv6 raw socket");
		fatal_exit();
	}

	if ((mld6_recv_buf = malloc(RECV_BUFFER_SIZE)) == NULL)
		log_msg(LOG_ERR, ENOMEM, "mld_init: malloc failed");
	/* initialize msghdr for receiving packets */
	rcviov[0].iov_base = (caddr_t) mld6_recv_buf;
	rcviov[0].iov_len = RECV_BUFFER_SIZE;
	rcvmh.msg_name = (caddr_t) & from;
	rcvmh.msg_namelen = sizeof(from);
	rcvmh.msg_iov = rcviov;
	rcvmh.msg_iovlen = 1;
	rcvmh.msg_control = (caddr_t) rcvcmsgbuf;
	rcvmh.msg_controllen = rcvcmsglen;

	hlim = MINHLIM;
	if ((err = setsockopt(mld6_socket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
		(char *) &hlim, sizeof(hlim))) < 0)
		log_msg(LOG_ERR, errno,
			"mld_init: unable to set multicast hop limit %d", errno);

	/* address initialization */
	allnodes_group.sin6_addr = in6addr_linklocal_allnodes;
	if (inet_pton(AF_INET6, "ff02::2",
		(void *) &allrouters_group.sin6_addr) != 1)
		log_msg(LOG_ERR, 0, "mld_init: inet_pton failed for ff02::2");

	if (inet_pton(AF_INET6, "ff02::16",
		(void *) &allmldv2routers_group.sin6_addr) != 1)
		log_msg(LOG_ERR, 0, "mld_init: inet_pton failed for ff02::16");

        if (inet_pton(AF_INET6, "ff02::d",
                      (void *)&allpim6routers_group.sin6_addr) != 1 )
                log_msg(LOG_ERR, 0, "inet_pton failed for ff02::d");

	on = 1;
	if (setsockopt(mld6_socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
		log_msg(LOG_ERR, errno, "setsockopt(mld6_socket, IPV6_RECVPKTINFO)");

	/* filter all non-MLD ICMP messages */
	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(ICMP6_ECHO_REQUEST, &filt);
	ICMP6_FILTER_SETPASS(ICMP6_MEMBERSHIP_QUERY, &filt);
	ICMP6_FILTER_SETPASS(ICMP6_MEMBERSHIP_REPORT, &filt);
	ICMP6_FILTER_SETPASS(ICMP6_MEMBERSHIP_REDUCTION, &filt);
#ifdef MLD6V2_LISTENER_REPORT
	ICMP6_FILTER_SETPASS(MLD6V2_LISTENER_REPORT,&filt);
#endif

	if (setsockopt(mld6_socket, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
                   sizeof(filt)) < 0) {
		log_msg(LOG_ERR, errno, "setsockopt(ICMP6_FILTER)");
		fatal_exit();
	}


	on = 1;
	/* specify to tell value of hoplimit field of IP6 hdr */
	if (setsockopt(mld6_socket, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)) < 0) {
		log_msg(LOG_ERR, errno, "mld_init: setsockopt failed for IPV6_RECVHOPLIMIT");
		fatal_exit();
	}

	on = 0;
	/* don't loopback MLD messages */
	if (setsockopt(mld6_socket, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on)) < 0) {
		log_msg(LOG_ERR, errno, "mld_init: setsockopt failed for IPV6_MULTICAST_LOOP");
		fatal_exit();
	}

	/* initialize msghdr for sending packets */
	sndiov[0].iov_base = (caddr_t)mld6_send_buf;
	sndmh.msg_namelen = sizeof(struct sockaddr_in6);
	sndmh.msg_iov = sndiov;
	sndmh.msg_iovlen = 1;

	/* specifiy to insert router alert option in a hop-by-hop opt hdr. */
#ifndef USE_RFC2292BIS
	raopt[0] = IP6OPT_ROUTER_ALERT;
	raopt[1] = IP6OPT_RTALERT_LEN - 2;
	memcpy(&raopt[2], (caddr_t) & rtalert_code, sizeof(u_int16_t));
#endif

	event_set(&mld_event, mld6_socket, EV_READ | EV_PERSIST, (void *) mld_callback, &mld_event);
	event_add(&mld_event, NULL);

	/*  PIM RAW SOCKET */
	if ((pim6_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_PIM)) < 0) {
		log_msg(LOG_ERR, errno,
			"mld_init: unable to open PIM6 raw socket");
		fatal_exit();
	}

	if ((pim6_recv_buf = malloc(RECV_BUFFER_SIZE)) == NULL)
		log_msg(LOG_ERR, ENOMEM, "mld_init: malloc failed");
	/* initialize msghdr for receiving packets */
	pim6_rcviov[0].iov_base = (caddr_t) pim6_recv_buf;
	pim6_rcviov[0].iov_len = RECV_BUFFER_SIZE;
	pim6_rcvmh.msg_name = (caddr_t) & pim6_from;
	pim6_rcvmh.msg_namelen = sizeof(pim6_from);
	pim6_rcvmh.msg_iov = pim6_rcviov;
	pim6_rcvmh.msg_iovlen = 1;
	pim6_rcvmh.msg_control = (caddr_t) pim6_rcvcmsgbuf;
	pim6_rcvmh.msg_controllen = pim6_rcvcmsglen;

	on = 1;
	if (setsockopt(pim6_socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
		log_msg(LOG_ERR, errno, "setsockopt(pim6_socket, IPV6_RECVPKTINFO)");
	/* specify to tell value of hoplimit field of IP6 hdr */
	if (setsockopt(pim6_socket, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)) < 0)
		log_msg(LOG_ERR, errno, "setsockopt(pim6_socket, IPV6_RECVHOPLIMIT)");

	event_set(&pim6_event, pim6_socket, EV_READ | EV_PERSIST, (void *)pim6_callback, &pim6_event);
	event_add(&pim6_event, NULL);
}

void
mld_input (struct eth_if *ifp, int port, u_int8_t *m, int full_len)
{
	struct ip6_hdr *ip6 = (struct ip6_hdr *)m;
	struct mld_hdr *mldh;
	struct mld_report_hdr *report;
	struct mld_group_record_hdr *mard;
	int i, nummard, numsrc, totsrc;
	u_int8_t *p;
	int len = full_len;
	struct sockaddr_in6 grp, intfaddr6;
	int portidx;
	struct eth_port *prt;
	struct proto_mc_param *mcp = &(ifp->if_mld_pr);
	struct querier_event *qep = &(ifp->if_mld_querier_ev);
	char buf_group [128];
	int hbhlen;

	portidx = get_port_for_ifp (ifp, port);
	if ( portidx < 0 ) {
		syslog (LOG_WARNING,
		        "mld_input: invalid port number %d\n", port);
		return;
	}

	prt = &ifp->if_port[portidx];

	/*
	 * Sanity checks about MLD
	 *   HopLim = 1
	 *   dst is MCAST
	 *   src is LL or unspec
	 */
	if (len < sizeof (struct ip6_hdr)) {
		syslog (LOG_DEBUG, "mld_input: IP6HDR %d\n", len);
		goto bad_mld;
	}
	if (full_len != (htons(ip6->ip6_plen) + sizeof(struct ip6_hdr))) {
		syslog (LOG_WARNING,
		        "mld_input: IP6 len %d != %d\n",
		        htons(ip6->ip6_plen), full_len);
		goto bad_mld;
	}
	if (ip6->ip6_hlim != 1) {
		syslog (LOG_WARNING, "mld_input: HopLim %d != 1\n", ip6->ip6_hlim);
		goto bad_mld;
	}
	if (!IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src) &&
	    !IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src)) {
		syslog (LOG_WARNING, "mld_input: bad src address \n");
		goto bad_mld;
	}
	if (!IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		syslog (LOG_WARNING, "mld_input: bad dst address \n");
		goto bad_mld;
	}

	/*
	 * skip IPv6 Header, and HbH header
	 * bzero HbHand swap some IPv6 hdr fields
	 * for checksum computation
	 *
	 */
	len -=  sizeof (struct ip6_hdr);
	p = m+ sizeof (struct ip6_hdr);
	hbhlen = ((p[1]+1) * 8);
	((u_int32_t *)m)[0] = htonl (htons(ip6->ip6_plen) - hbhlen);
	((u_int32_t *)m)[1] = htonl (IPPROTO_ICMPV6);
	len -= hbhlen;
	if (len <0)
		return;
	memset (p, 0, hbhlen);
	p += hbhlen;

	/*
	 * Now we're at the ICMPv6
	 *   verify checksum
	 *   there MUST be at least an MLD header
	 */
	if (in_cksum (m, full_len)) {
		syslog (LOG_WARNING, "mld_input: bad checksum\n");
		goto bad_mld;
	}

	if (len < sizeof (struct mld_hdr)) {
		syslog (LOG_WARNING, "mld_input: mld_hdr %d\n", len);
		return;
	}
	mldh = (struct mld_hdr *)p;

	mld_received(ifp, port, &ip6->ip6_src, &ip6->ip6_dst, mldh, len);
	return;

bad_mld:
	syslog (LOG_WARNING, "Bad MLD received\n");
	return;
}

void
pim6_input (struct eth_if *ifp, int port, u_int8_t *m, int full_len)
{
	/*
	 * TBD : Here some sanity checks about PIM6 ....
	 */
	pim6_received(ifp, port);
}

/*
 * This function builds two types of messages :
 *	- general queries
 *	- group spec. query S flag set/not set
 * Returns 0 on success, 1 on failure
 */
static int
mldv2_build_query(struct sockaddr_in6 *src,
		struct sockaddr_in6 *dst, struct sockaddr_in6 *group,
		int ifindex, unsigned int delay, int alert,
		int sflag, int qrv, int qqic, int gss)
{
	struct mldv2_hdr *mhp = (struct mldv2_hdr *) mld6_send_buf;
	int datalen, ctllen, hbhlen = 0;
	int nbsrc = 0;
	u_int8_t misc = 0;	/*Resv+S flag + QRV */
	unsigned int    realnbr;
	struct listaddr *g = NULL;
	struct cmsghdr *cmsgp;

	memset(&dst_sa, 0, sizeof(dst_sa));
	dst_sa.sin6_family = AF_INET6;
#ifdef HAVE_SIN_LEN
	dst_sa.sin6_len = sizeof(dst_sa);
#endif
	dst_sa.sin6_addr = allnodes_group.sin6_addr;
	sndmh.msg_name = (caddr_t) &dst_sa;

	if (group != NULL)
		dst_sa.sin6_addr = group->sin6_addr;

	/* scan the source-list only in case of GSS query */
	if (gss) {
		/*
		 * GSS staff can be added here in future
		 */
		;
	}

	log_msg(LOG_DEBUG, 0, "==>(%s) Query Sent With S flag %s",
		sa6_fmt(&dst_sa), sflag ? "ON" : "OFF");

	/* fill the misc field */
	misc |= sflag?SFLAGYES:SFLAGNO;
	if (qrv <= 7)
		misc |= qrv;

	/* XXX : hard-coding, 28 is the minimal size of the mldv2 query header */
	datalen = 28 + nbsrc * sizeof(struct in6_addr) + sizeof(uint32_t);
	mhp->mld_type = MLD_LISTENER_QUERY;
	mhp->mld_code = 0;
	mhp->mld_maxdelay = htons(codafloat(delay, &realnbr, 3, 12));
	if (group!=NULL)
		mhp->mld_addr = group->sin6_addr;
	else
		mhp->mld_addr = in6addr_any;
	mhp->mld_rtval = misc;
	mhp->mld_qqi = codafloat(qqic, &realnbr, 3, 4);
	mhp->mld_numsrc = htons(nbsrc);

	sndiov[0].iov_len = datalen;

	/* estimate total ancillary data length */
	ctllen = 0;
	if (ifindex != -1 || src)
		ctllen += CMSG_SPACE(sizeof(struct in6_pktinfo));
	if (alert) {
#ifdef USE_RFC2292BIS
		if ((hbhlen = inet6_opt_init(NULL, 0)) == -1)
			log_msg(LOG_ERR, 0, "inet6_opt_init(0) failed");
		if ((hbhlen = inet6_opt_append(NULL, 0, hbhlen,
			IP6OPT_ROUTER_ALERT, 2, 2, NULL)) == -1)
			log_msg(LOG_ERR, 0, "inet6_opt_append(0) failed");
		if ((hbhlen = inet6_opt_finish(NULL, 0, hbhlen)) == -1)
			log_msg(LOG_ERR, 0, "inet6_opt_finish(0) failed");
			ctllen += CMSG_SPACE(hbhlen);
#else				/* old advanced API */
		hbhlen = inet6_option_space(sizeof(raopt));
		ctllen += hbhlen;
#endif
	}

	/* extend ancillary data space (if necessary) */
	if (ctlbuflen < ctllen) {
		if (sndcmsgbuf)
			free(sndcmsgbuf);
		if ((sndcmsgbuf = malloc(ctllen)) == NULL)
			log_msg(LOG_ERR, 0, "mldv2_build_query: malloc failed");
		ctlbuflen = ctllen;
	}
	/* store ancillary data */
	sndmh.msg_controllen = ctllen;
	if (ctllen <= 0) {
		sndmh.msg_control = NULL;	/* XXX clear for safety */
		return 0;
	}
	memset( sndcmsgbuf, 0, ctllen );

	sndmh.msg_control = sndcmsgbuf;
	cmsgp = CMSG_FIRSTHDR(&sndmh);

	if (ifindex != -1 || src) {
		struct in6_pktinfo *pktinfo;

		cmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = IPV6_PKTINFO;
		pktinfo = (struct in6_pktinfo *) CMSG_DATA(cmsgp);
		memset((caddr_t) pktinfo, 0, sizeof(*pktinfo));
		if (ifindex != -1)
			pktinfo->ipi6_ifindex = ifindex;
		if (src)
			pktinfo->ipi6_addr = src->sin6_addr;
		cmsgp = CMSG_NXTHDR(&sndmh, cmsgp);
    }
    if (alert) {
#ifdef USE_RFC2292BIS
		int             currentlen;
		void           *hbhbuf, *optp = NULL;
		u_int16_t rtalert_code;

		rtalert_code = htons(IP6OPT_RTALERT_MLD);

		cmsgp->cmsg_len = CMSG_LEN(hbhlen);
		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = IPV6_HOPOPTS;
		hbhbuf = CMSG_DATA(cmsgp);

		if ((currentlen = inet6_opt_init(hbhbuf, hbhlen)) == -1)
			log_msg(LOG_ERR, 0, "inet6_opt_init(len = %d) failed", hbhlen);
		if ((currentlen = inet6_opt_append(hbhbuf, hbhlen, currentlen,
			IP6OPT_ROUTER_ALERT, 2, 2, &optp)) == -1)
			log_msg(LOG_ERR, 0,
				"inet6_opt_append(len = %d/%d) failed", currentlen, hbhlen);
		(void)inet6_opt_set_val(optp, 0, &rtalert_code, sizeof(rtalert_code));
		if (inet6_opt_finish(hbhbuf, hbhlen, currentlen) == -1)
			log_msg(LOG_ERR, 0, "inet6_opt_finish(buf) failed");
#else	/* old advanced API */
		if (inet6_option_init((void *) cmsgp, &cmsgp, IPV6_HOPOPTS))
			log_msg(LOG_ERR, 0,	/* assert */
				"mldv2_build_query: inet6_option_init failed");
		if (inet6_option_append(cmsgp, raopt, 4, 0))
			log_msg(LOG_ERR, 0,	/* assert */
				"mldv2_build_query: inet6_option_append failed");
#endif
		cmsgp = CMSG_NXTHDR(&sndmh, cmsgp);
	}
	return 0;
}

static int
mld_build_query(struct sockaddr_in6 *src,
		struct sockaddr_in6 *dst, struct sockaddr_in6 *group,
		int ifindex, unsigned int delay, int alert,
		int sflag, int qrv, int qqic, int gss, int version)
{
	return mldv2_build_query(src, dst, group, ifindex, delay, alert, sflag, qrv, qqic, gss);
}

/*
 * This function sends two types of messages :
 *	- general queries
 *	- group spec. query S flag set/not set
 * Returns 0 on success, 1 on failure
 */
int
mld_send_query(struct sockaddr_in6 *src,
		struct sockaddr_in6 *dst, struct sockaddr_in6 *group,
		int index, unsigned int delay, int alert,
		int sflag, int qrv, int qqic, int gss, int version)
{
	struct sockaddr_in6 *dstp;

	if (mld_build_query(src, dst, group, index, delay,
		alert, sflag, qrv, qqic, gss, version)) {
		log_msg(LOG_ERR, 0,	/* assert */
			"mld_send_query: mld_build_query failed");
		return 1;
	}

	dstp = (struct sockaddr_in6 *) sndmh.msg_name;

#ifdef __KAME__
	if (IN6_IS_ADDR_LINKLOCAL(&dstp->sin6_addr) ||
	IN6_IS_ADDR_MC_LINKLOCAL(&dstp->sin6_addr))
	dstp->sin6_scope_id = index;
#endif

	if (sendmsg(mld6_socket, &sndmh, 0) < 0) {
		log_msg(LOG_WARNING, errno,	/* assert */
			"mldv2_send_query: sendmsg to %s with src %s on %s",
			sa6_fmt(dstp), src ? sa6_fmt(src) : "(unspec)", ifindex2str(index));

		return 1;
	}

	log_msg(LOG_DEBUG, 0, "SENT MLDv2 Query from %-15s to %s",
		src ? sa6_fmt(src) : "unspec", sa6_fmt(dstp));
	return 0;
}

/*
 * given a number, an exp. size in bits and a mantisse size in bits, return
 * the coded number value according to the code described in
 * draft-vida-mld-v2-08.txt
 * used to compute the Maximum Response Code (exp=3bit, mant=12bit)
 * and the Querier Query interval Code (exp=3bit, mant=4 bit)
 * format  : |1|...exp...|...mant...|
 * if the number isn't representable there is a difference between realnbr
 * and nbr if the number is too big return the max code value with a warning
 */
unsigned int
codafloat(unsigned int nbr, unsigned int *realnbr, unsigned int sizeexp,
	  unsigned int sizemant)
{
	unsigned int mask = 0x1;
	unsigned int max = 0x0;
	unsigned int exp = 1;	/*exp value */
	unsigned int tmax;	/*max code value */
	unsigned int mantmask = 1;	/*mantisse mask */
	unsigned int onebit = 1;
	unsigned int mant;
	u_int16_t code = 1;	/* code */
	int i;

	/* compute maximal exp value */
	for (i = 1; i < sizeexp; i++)
		exp = (exp << 1) | 1;

	/* maximum size of this number in bits (after decoding) */
	tmax = exp + 3 + sizemant + 1;

	/* minimum value of this number */
	code <<= sizeexp + sizemant;
	mask <<= tmax - 1;

	/* maximum value of this number + a mantisse masque */
	for (i = 0; i <= sizemant; i++)
		max = max | mask >> i;
	for (i = 0; i < sizemant; i++)
		mantmask = mantmask | (onebit << i);

	/* not in coded number, so just return the given number as it is */
	if (nbr < code) {
		code = *realnbr = nbr;
		return code;
	}

	/* overflowed, so just return the possible max value */
	if (nbr > max) {
		*realnbr = max;
		return codafloat(max, realnbr, sizeexp, sizemant);
	}

	/* calculate the float number */
	while (!(nbr & mask)) {
		mask >>= 1;
		tmax--;
	}
	exp = tmax - (sizemant + 1);
	mant = nbr >> exp;
	exp -= 3;

	/* build code */
	mant &= mantmask;
	code |= mant;
	code |= exp << sizemant;

	/* compute effective value (draft-vida-mld-v2-08.txt p.11) */
	onebit <<= sizemant;
	*realnbr = (mant | onebit) << (exp + 3);
	return code;
}

unsigned int
decodeafloat(unsigned int nbr,unsigned int sizeexp,unsigned int sizemant)
{
	unsigned int onebit = 1;
	unsigned int mantmask = 0;
	unsigned int mant = 0;
	unsigned int exp = 0;
	int i;

	for (i = 0; i < sizemant; i++)
		mantmask = mantmask | (onebit << i);
	mant = nbr & mantmask;
	exp = (nbr & ~(onebit << (sizemant + sizeexp))) >> sizemant;
	onebit <<= sizemant;
	return (mant | onebit) << (exp + 3);
}

void
ip6_get_lladdr(char *ifname, struct sockaddr_in6 *addr)
{
	struct ifaddrs *ifap = NULL, *ifa;
	struct sockaddr_in6 *paddr = NULL;

	if (getifaddrs(&ifap))
		log_msg(LOG_ERR, errno, "ip6_get_lladdr");

	/*
	 * Loop through all of the interfaces.
	 */
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		/*
		 * Sanity check
		 */
		if(!ifa->ifa_addr || !ifa->ifa_name)
			continue;
		/*
		 * Ignore any other interface
		 */
		if(strcmp(ifname, ifa->ifa_name))
			continue;
		/*
		 * Ignore address family other than IPv6.
		 */
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		paddr = (struct sockaddr_in6 *)ifa->ifa_addr;
		/*
		 * Need link-local address
		 */
		if (!IN6_IS_ADDR_LINKLOCAL(&(paddr->sin6_addr)))
			continue;

		memcpy(addr, paddr, sizeof(struct sockaddr_in6));
		break;
	}

	freeifaddrs(ifap);
}
