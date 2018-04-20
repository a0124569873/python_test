/*
 * Copyright 2006-2013 6WIND S.A.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <netinet/in.h>
#ifndef __linux__
#include <net/if_dl.h>
#include <netinet/ip_mroute.h>
#else
#include <linux/types.h>
#include <linux/igmp.h>
#include <linux/icmp.h>
#endif
#include <net/if.h>
#include <netinet/ip.h>
#include <ifaddrs.h>

#include <syslog.h>

#include "event.h"

#include "config.h"
#include "snoop.h"
#include "igmp.h"
#include "igmpv3.h"
#include "in_cksum.h"

static void ip_get_lladdr(char *ifname, struct sockaddr_in *addr);
static unsigned int decodeafloat(unsigned int nbr,unsigned int sizeexp,unsigned int sizemant);

/*
 * IGMP raw socket and packet buffer for sending IGMPv3 Queries
 */
#define RECV_BUFFER_SIZE 4096

int igmp_socket = -1;		/* socket for all network I/O */
int pim4_socket = -1;		/* socket for pim4 messages I/O */
static char *igmp_send_buf;		/* output packet buffer */
static struct msghdr sndmh;		/* message header to be passed in sendmsg */
static char *sndcmsgbuf;
static int ctlbuflen = 0;
static struct iovec sndiov[2];
static struct sockaddr_in dst_sa;	/* IGMP packet destination address  */
static struct sockaddr_in from;
static struct sockaddr_in pim4_from;
static unsigned char *igmp_recv_buf;             /* input packet buffer */
static char *pim4_recv_buf;             /* input packet buffer */
static struct msghdr sndmh, rcvmh, pim4_rcvmh;          /* message header to be passed in sendmsg */
static unsigned char rcvcmsgbuf[RECV_BUFFER_SIZE], pim4_rcvcmsgbuf[RECV_BUFFER_SIZE];
static int rcvcmsglen = RECV_BUFFER_SIZE;
static int pim4_rcvcmsglen = RECV_BUFFER_SIZE;
static struct iovec rcviov[2], pim4_rcviov[2];

static struct event igmp_event;
static struct event pim4_event;

static void pim4_decode(int n)
{
        struct cmsghdr *cm;
        struct in_pktinfo *pi = NULL;
        u_int ifindex = 0;
        struct eth_if *ifp = 0;


        /* extract optional information via Advanced API */
        for (cm = (struct cmsghdr *) CMSG_FIRSTHDR(&pim4_rcvmh);
             cm;
             cm = (struct cmsghdr *) CMSG_NXTHDR(&pim4_rcvmh, cm))
        {
                if (cm->cmsg_level == IPPROTO_IP &&
                    cm->cmsg_type == IP_PKTINFO &&
                    cm->cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo)))
                {
                        pi = (struct in_pktinfo *) (CMSG_DATA(cm));
                        ifindex = (u_int)pi->ipi_ifindex;
                        ifp = get_ifp_index(ifindex);
                        if (!ifp || ifp->if_bridge)
                                return;
                }
        }
        if (ifindex == 0)
        {
                log_msg(LOG_WARNING, 0, "failed to get receiving interface");
                return;
        }
	pim4_input (ifp, 0, pim4_recv_buf, n);
}

static void decode(int n)
{
        struct igmp_hdr *igmph;
        struct cmsghdr *cm;
        struct in_pktinfo *pi = NULL;
        int *hlimp = NULL;
        u_int ifindex = 0;
        struct sockaddr_in *src = (struct sockaddr_in *) rcvmh.msg_name;
        struct eth_if *ifp = 0;


        if (n < sizeof(struct igmp_hdr))
        {
                log_msg(LOG_WARNING, 0,
                    "received packet too short (%u bytes) for IGMP header",
                    n);
                return;
        }
        igmph = (struct igmp_hdr *) rcvmh.msg_iov[0].iov_base;

        /* extract optional information via Advanced API */
        for (cm = (struct cmsghdr *) CMSG_FIRSTHDR(&rcvmh);
             cm;
             cm = (struct cmsghdr *) CMSG_NXTHDR(&rcvmh, cm))
        {
                if (cm->cmsg_level == IPPROTO_IP &&
                    cm->cmsg_type == IP_PKTINFO &&
                    cm->cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo)))
                {
                        pi = (struct in_pktinfo *) (CMSG_DATA(cm));
                        ifindex = (u_int)pi->ipi_ifindex;
                        ifp = get_ifp_index(ifindex);
                        if (!ifp || ifp->if_bridge)
                                return;
                }
        }
        if (ifindex == 0)
        {
                log_msg(LOG_WARNING, 0, "failed to get receiving interface");
                return;
        }
	igmp_input (ifp, 0, igmp_recv_buf, n);
}

/* PIM4 RAW socket receive callback */
static void pim4_callback(int fd, short event, void *param)
{
        int n = recvmsg(fd, &pim4_rcvmh, 0);
        if (n > 0) {
                pim4_decode(n);
        } else if (param) {
                /* disconnection */
                struct event *ev = (struct event *)param;
                event_del(ev);
                free(ev);
        }
}

/* IGMP RAW socket receive callback */
static void igmp_callback(int fd, short event, void *param)
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

void
igmp_init(void)
{
	struct icmp_filter filt;
	int ttl, on;
	int err = 0;

	if (!igmp_send_buf && (igmp_send_buf = malloc(SEND_BUF_SIZE)) == NULL)
		log_msg(LOG_ERR, ENOMEM, "igmp_init: malloc failed");

	log_msg(LOG_DEBUG, 0,
		"igmp_init: %d octets allocated for IGMP emit buffer", SEND_BUF_SIZE);

	if ((igmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP)) < 0) {
		log_msg(LOG_ERR, errno,
			"igmp_init: unable to open IGMP raw socket");
		fatal_exit();
	}

        if ((igmp_recv_buf = malloc(RECV_BUFFER_SIZE)) == NULL)
                log_msg(LOG_ERR, ENOMEM, "igmp_init: malloc failed");
        /* initialize msghdr for receiving packets */
        rcviov[0].iov_base = (caddr_t) igmp_recv_buf;
        rcviov[0].iov_len = RECV_BUFFER_SIZE;
        rcvmh.msg_name = (caddr_t) & from;
        rcvmh.msg_namelen = sizeof(from);
        rcvmh.msg_iov = rcviov;
        rcvmh.msg_iovlen = 1;
        rcvmh.msg_control = (caddr_t) rcvcmsgbuf;
        rcvmh.msg_controllen = rcvcmsglen;

	ttl = 1;
	if ((err = setsockopt(igmp_socket, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl))) < 0)
		log_msg(LOG_ERR, errno,
			"igmp_init: unable to set multicast ttl %d", errno);

	/* We want the packet info */
        on = 1;
        if (setsockopt(igmp_socket, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0)
		log_msg(LOG_ERR, errno, "igmp_init: setsockopt failed for IP_PKTINFO");

	/* specify to tell value of ttl field of IP4 hdr */
	if (setsockopt(igmp_socket, IPPROTO_IP, IP_TTL, &on,
		sizeof(on)) < 0)
		log_msg(LOG_ERR, errno, "igmp_init: setsockopt failed for IP_TTL");

        on = 0;
        /* don't loopback IGMP messages */
        if (setsockopt(igmp_socket, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on)) < 0) {
		log_msg(LOG_ERR, errno, "igmp_init: setsockopt failed for IP_MULTICAST_LOOP");
                fatal_exit();
        }

	/* initialize msghdr for sending packets */
	sndiov[0].iov_base = (caddr_t)igmp_send_buf;
	sndmh.msg_namelen = sizeof(struct sockaddr_in);
	sndmh.msg_iov = sndiov;
	sndmh.msg_iovlen = 1;

        event_set(&igmp_event, igmp_socket, EV_READ | EV_PERSIST, (void *) igmp_callback, &igmp_event);
        event_add(&igmp_event, NULL);

        /*  PIM RAW SOCKET */
        if ((pim4_socket = socket(AF_INET, SOCK_RAW, IPPROTO_PIM)) < 0) {
                log_msg(LOG_ERR, errno,
                        "igmp_init: unable to open PIM raw socket");
                fatal_exit();
        }
        if ((pim4_recv_buf = malloc(RECV_BUFFER_SIZE)) == NULL)
                log_msg(LOG_ERR, ENOMEM, "igmp_init: malloc failed");
        /* initialize msghdr for receiving packets */
        pim4_rcviov[0].iov_base = (caddr_t) pim4_recv_buf;
        pim4_rcviov[0].iov_len = RECV_BUFFER_SIZE;
        pim4_rcvmh.msg_name = (caddr_t) & pim4_from;
        pim4_rcvmh.msg_namelen = sizeof(pim4_from);
        pim4_rcvmh.msg_iov = pim4_rcviov;
        pim4_rcvmh.msg_iovlen = 1;
        pim4_rcvmh.msg_control = (caddr_t) pim4_rcvcmsgbuf;
        pim4_rcvmh.msg_controllen = pim4_rcvcmsglen;

        on = 1;
        if (setsockopt(pim4_socket, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0)
		log_msg(LOG_ERR, errno, "igmp_init: setsockopt failed for IP_PKTINFO (pim4_socket)");
        /* specify to tell value of ttl field of IP4 hdr */
	if (setsockopt(pim4_socket, IPPROTO_IP, IP_TTL, &on,
		sizeof(on)) < 0)
		log_msg(LOG_ERR, errno, "igmp_init: setsockopt failed for IP_TTL");

        event_set(&pim4_event, pim4_socket, EV_READ | EV_PERSIST, (void *)pim4_callback, &pim4_event);
        event_add(&pim4_event, NULL);
}

void
igmp_input (struct eth_if *ifp, int port, u_int8_t *m, int full_len)
{
	struct iphdr *ip4 = (struct iphdr *)m;
	struct igmp_hdr *igmph;
	struct igmp_report_hdr *report;
	struct igmpv3_report *reportv3;
	struct igmp_group_record_hdr *mard;
	int i, nummard, numsrc, totsrc;
	u_int8_t *p;
	int len = full_len;
	struct sockaddr_in grp, intfaddr;
	struct eth_port *prt;
	int portidx = get_port_for_ifp (ifp, port);

	struct proto_mc_param *mcp = &(ifp->if_igmp_pr);
	struct querier_event *qep = &(ifp->if_igmp_querier_ev);
	char buf_group [128];
	char buf_src [32];
	struct in_addr src;
	int hbhlen;

	if (!ifp->if_started_igmp || !mcp->pr_snooping || portidx < 0)
		return;

	prt = &ifp->if_port[portidx];
	/*
	 * Sanity checks about IGMP
	 *   HopLim = 1
	 *   dst is MCAST
	 *   src is LL or unspec
	 */
	if (len < sizeof (struct iphdr)) {
		syslog (LOG_DEBUG, "igmp_input: IP4HDR %d\n", len);
		goto bad_igmp;
	}
	if (len < (htons(ip4->tot_len))) {
		syslog (LOG_WARNING,
		        "igmp_input: IP4 len %d != %d\n",
		        htons(ip4->tot_len), len);
		goto bad_igmp;
	}
	if (ip4->ttl != 1) {
		syslog (LOG_WARNING, "igmp_input: ttl %d != 1\n", ip4->ttl);
		goto bad_igmp;
	}
	if (!ip4->saddr) {
		syslog (LOG_WARNING, "igmp_input: bad src address \n");
		goto bad_igmp;
	}
	if (!IN_MULTICAST(htonl(ip4->daddr))) {
		syslog (LOG_WARNING, "igmp_input: bad dst address (%X) \n", htonl(ip4->daddr));
		goto bad_igmp;
	}

	src.s_addr = ip4->saddr;
	/*
	 * skip IPv4 Header
	 *
	 */
	p = m + sizeof(u_int32_t)*ip4->ihl;
	len -=  sizeof(u_int32_t)*ip4->ihl;

	/*
	 * Now we're at the IGMP
	 *   there MUST be at least an IGMP header
	 */
	if (len < sizeof (struct igmp_hdr)) {
		syslog (LOG_WARNING, "igmp_input: igmp_hdr %d\n", len);
		return;
	}

	if (in_cksum (p, len)) {
		syslog (LOG_WARNING, "igmp_input: bad checksum\n");
		goto bad_igmp;
	}
	igmph = (struct igmp_hdr *)p;

	memset (&grp, 0, sizeof(grp));
#ifdef HAVE_SIN_LEN
	grp.sin_len = sizeof(grp);
#endif
	grp.sin_family = AF_INET;

	if (igmph->igmp_type == IGMPV3_HOST_MEMBERSHIP_REPORT)
	{
		int i;
		struct igmpv3_report *rep = (struct igmpv3_report *)p;
		int ngr = ntohs(rep->ngrec);
		for (i = 0; i < ngr; ++i) {
			grp.sin_addr.s_addr = rep->grec[i].grec_mca;
			display_sa (buf_group, (struct sockaddr *)&grp);
			/* we are ignoring source addresses */
		}
	}
	else
	{
		grp.sin_addr.s_addr = igmph->hdr.group;
		display_sa (buf_group, (struct sockaddr *)&grp);
	}

	ip_get_lladdr(ifp->if_name, &intfaddr);
	switch (igmph->igmp_type) {
		case IGMP_HOST_MEMBERSHIP_QUERY:
		{
			/*
			 * Drop self-generated queries
			 */
			if ((mcp->pr_querier_status == PR_QUERIER) &&
				(qep->qrr_myquery_ind > 0)) {
				if (intfaddr.sin_addr.s_addr == ip4->saddr) {
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
                        int withdraw = 0;
                        if (mcp->pr_querier_candidature == PR_ROUTER_CANDIDATE) {
                                /* Compare our address to the one from the query received */
                                /* We are ignoring queries from lower addresses */
				if (ntohl(intfaddr.sin_addr.s_addr) < ntohl(ip4->saddr)) {
                                                syslog (LOG_INFO, "---- other IGMP querier detected at %s on %s - ignored\n", inet_fmt(&src), ifp->if_name);
                                                withdraw = 1;
                                }
                        }
                        if (mcp->pr_querier_status == PR_QUERIER) {
                                if (!withdraw) {
					int version = PR_VERSION_UNKNOWN;
                                        mcp->pr_querier_status = PR_NONQUERIER;
                                        qep->qrr_gq_timer = TMO_INFINITE;
					if (len == 8) {
						if (igmph->igmp_code == 0)
							version = PR_VERSION_IGMPv1;
						else
							version = PR_VERSION_IGMPv2;
					} else if (len >= 12) {
						version = PR_VERSION_IGMPv3;
					} else {
						/* Illegal size */
						break;
					}
					if (mcp->pr_querier_version == PR_VERSION_UNKNOWN || version < mcp->pr_querier_version)
						mcp->pr_querier_version = version;
                                        syslog (LOG_INFO, "----> switching to non-querier state for interface %s (other IGMP querier v%d detected at %s)\n",
							ifp->if_name, mcp->pr_querier_version-PR_VERSION_UNKNOWN, inet_fmt(&src));
                                }
                        }

                        if ((mcp->pr_querier_candidature == PR_QUERIER_CANDIDATE) || ((mcp->pr_querier_candidature == PR_ROUTER_CANDIDATE) && !withdraw)) {
                                /*
                                 * Restart querier timer
                                 */
                                qep->qrr_timer = compute_deadline(mcp->pr_querier_timeout);
                        }

                        if (grp.sin_addr.s_addr) {
                                if (mcp->pr_querier_status != PR_QUERIER)
                                        specific_group_received (ifp, (struct sockaddr *)&grp,
                                                igmph->igmp_type);
                                syslog (LOG_DEBUG,
                                        "IGMP m-a-s query received on %s (port %d) for %s\n",
                                        ifp->if_name, port, buf_group);
                        } else {
                                syslog (LOG_DEBUG,
                                        "IGMP general query received on %s (port %d)\n",
                                        ifp->if_name, port);
                        }

			/*
			 * Update IGMP port list and timer
			 */
			if ((ip4->saddr)) {
				if (prt->prt_rtr4_tmo != TMO_INFINITE)
					prt->prt_rtr4_tmo = \
					compute_deadline (PR_LISTENER_INTERVAL(mcp));
				if (!PORT_ISSET(port, &ifp->if_rtr4)) {
					PORT_SET(port, &ifp->if_rtr4);
					notify_port_list (SET_IGMP_ROUTERS, ifp);
				}
			}
			break;
		}
		case IGMP_HOST_MEMBERSHIP_REPORT:
			if (ntohl(grp.sin_addr.s_addr) > INADDR_MAX_LOCAL_GROUP)
				report_received (ifp, prt, (struct sockaddr *)&grp);
			if (mcp->pr_querier_version == PR_VERSION_UNKNOWN || PR_VERSION_IGMPv1 < mcp->pr_querier_version)
				mcp->pr_querier_version = PR_VERSION_IGMPv1;
			syslog (LOG_DEBUG,
				"IGMPv1 report received on %s (port %d) for %s\n",
				ifp->if_name, port, buf_group);
			break;
		case IGMP_HOST_LEAVE_MESSAGE:
                        if (grp.sin_addr.s_addr) {
                                if (mcp->pr_querier_status != PR_QUERIER)
                                        specific_group_received (ifp, (struct sockaddr *)&grp, igmph->igmp_type);
                                syslog (LOG_DEBUG,
                                        "IGMP m-a-s leaving received on %s (port %d) for %s\n",
                                        ifp->if_name, port, buf_group);
                        }
			break;
		case IGMPV2_HOST_MEMBERSHIP_REPORT:
			if (mcp->pr_querier_version == PR_VERSION_UNKNOWN || PR_VERSION_IGMPv2 < mcp->pr_querier_version)
				mcp->pr_querier_version = PR_VERSION_IGMPv2;

			if (ntohl(grp.sin_addr.s_addr) > INADDR_MAX_LOCAL_GROUP)
				report_received (ifp, prt, (struct sockaddr *)&grp);
			syslog (LOG_DEBUG,
				"IGMPv2 report received on %s (port %d) for %s\n",
				ifp->if_name, port, buf_group);
			break;
		case IGMPV3_HOST_MEMBERSHIP_REPORT:
			if (mcp->pr_querier_version == PR_VERSION_UNKNOWN || PR_VERSION_IGMPv3 < mcp->pr_querier_version)
				mcp->pr_querier_version = PR_VERSION_IGMPv3;
			syslog (LOG_DEBUG,
			        "IGMPv3 report received on %s (port %d)\n",
			        ifp->if_name, port);
			/*
			 * loop through each multicast record,
			 * extract only group information and
			 * ignore source list
			 */
			reportv3 = (struct igmpv3_report *) igmph;
			nummard = ntohs(reportv3->ngrec);
			totsrc = 0;

			for (i = 0; i < nummard; i++) {
				grp.sin_addr.s_addr = reportv3->grec[i].grec_mca;

				if (ntohl(grp.sin_addr.s_addr) <= INADDR_MAX_LOCAL_GROUP) {
					continue;
				}
				/*
				 * No fast leave for IGMPv3 as of now
				 * So update group timer for all record types
				 */
				report_received (ifp, prt, (struct sockaddr *)&grp);
			}
			break;
	}
	return;

bad_igmp:
	syslog (LOG_WARNING, "Bad IGMP received\n");
	return;
}

void
pim4_input (struct eth_if *ifp, int port, u_int8_t *m, int full_len)
{
        struct eth_port *prt;
        int portidx = get_port_for_ifp (ifp, port);
	struct proto_mc_param *mcp = &(ifp->if_igmp_pr);

	if (!ifp->if_started_igmp || !mcp->pr_snooping || portidx < 0)
		return;

	prt = &ifp->if_port[portidx];

	/*
	 * TBD : Here some sanity checks about PIM4 ....
	 */
	syslog (LOG_DEBUG,
	        "PIM4 msgt received on %s (port %d) len = %d\n",
	        ifp->if_name, port, full_len);

	if (prt->prt_rtr4_tmo != TMO_INFINITE)
		prt->prt_rtr4_tmo = compute_deadline (PR_LISTENER_INTERVAL(mcp));
	if (!PORT_ISSET(port, &ifp->if_rtr4)) {
		PORT_SET(port, &ifp->if_rtr4);
		notify_port_list (SET_IGMP_ROUTERS, ifp);
	}
	return;
}


/*
 * This function builds two types of messages :
 *	- general queries
 *	- group spec.
 * Returns 0 on success, 1 on failure
 */
static int
igmp_build_query_v3(struct sockaddr_in *src,
		struct sockaddr_in *dst, struct sockaddr_in *group,
		int ifindex, unsigned int delay, int alert,
		int sflag, int qrv, int qqic, int gss)
{
	struct igmpv3_hdr *mhp = (struct igmpv3_hdr *) igmp_send_buf;
	int datalen, ctllen, hbhlen = 0;
	int nbsrc = 0;
	u_int8_t misc = 0;	/*Resv+S flag + QRV */
	unsigned int    realnbr;
	struct listaddr *g = NULL;
	struct cmsghdr *cmsgp;

	memset(&dst_sa, 0, sizeof(dst_sa));
	dst_sa.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	dst_sa.sin_len = sizeof(dst_sa);
#endif
	sndmh.msg_name = (caddr_t) &dst_sa;
	if (group != NULL)
		dst_sa.sin_addr = group->sin_addr;
	else
		dst_sa.sin_addr.s_addr = IGMP_ALL_HOSTS;

	/* scan the source-list only in case of GSS query */
	if (gss) {
		/*
		 * GSS staff can be added here in future
		 */
		;
	}

	log_msg(LOG_DEBUG, 0, "==>(%s) Query Sent With S flag %s", sa_fmt(&dst_sa), sflag ? "ON" : "OFF");

	/* fill the misc field */
        misc |= sflag?SFLAGYES:SFLAGNO;
	if (qrv <= 7)
		misc |= qrv;

	if (group)
		datalen = sizeof(*mhp) + nbsrc * sizeof(struct in_addr);
	else
		datalen = sizeof(struct igmphdr ) + sizeof( struct in_addr );

	memset(mhp, 0, datalen);
	mhp->igmp_type = IGMP_HOST_MEMBERSHIP_QUERY;
	mhp->igmp_csum = 0;
        mhp->igmp_maxdelay = codafloat(delay/100, &realnbr, 3, 4);
        mhp->igmp_rtval = misc;
        mhp->igmp_qqi = codafloat(qqic, &realnbr, 3, 4);
        mhp->igmp_numsrc = htons(nbsrc);
	if (group!=NULL)
		mhp->igmp_addr = group->sin_addr;
	else
		mhp->igmp_addr.s_addr = 0;
	mhp->igmp_csum = in_cksum((char *)mhp, datalen);

	sndiov[0].iov_len = datalen;

	/* estimate total ancillary data length */
	ctllen = 0;
	if (ifindex != -1 || src)
		ctllen += CMSG_SPACE(sizeof(struct in_pktinfo));

	/* extend ancillary data space (if necessary) */
	if (ctlbuflen < ctllen) {
		if (sndcmsgbuf)
			free(sndcmsgbuf);
		if ((sndcmsgbuf = malloc(ctllen)) == NULL)
			log_msg(LOG_ERR, 0, "igmp_build_query: malloc failed");
		ctlbuflen = ctllen;
	}
	/* store ancillary data */
	sndmh.msg_controllen = ctllen;
	if (ctllen <= 0) {
		sndmh.msg_control = NULL;
		return 0;
	}
	memset( sndcmsgbuf, 0, ctllen );

	sndmh.msg_control = sndcmsgbuf;
	cmsgp = CMSG_FIRSTHDR(&sndmh);

	if (ifindex != -1 || src) {
		struct in_pktinfo *pktinfo;

		cmsgp->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
		cmsgp->cmsg_level = IPPROTO_IP;
		cmsgp->cmsg_type = IP_PKTINFO;
		pktinfo = (struct in_pktinfo *) CMSG_DATA(cmsgp);
		memset((caddr_t) pktinfo, 0, sizeof(*pktinfo));
		if (ifindex != -1)
			pktinfo->ipi_ifindex = ifindex;
		if (src)
			pktinfo->ipi_spec_dst = src->sin_addr;
		cmsgp = CMSG_NXTHDR(&sndmh, cmsgp);
	}
	return 0;
}

/*
 * This function builds two types of messages :
 *	- general queries
 *	- group spec.
 * Returns 0 on success, 1 on failure
 */
static int
igmp_build_query(struct sockaddr_in *src,
		struct sockaddr_in *dst, struct sockaddr_in *group,
		int ifindex, unsigned int delay, int alert,
		int sflag, int qrv, int qqic, int gss, int version)
{
	return igmp_build_query_v3(src, dst, group, ifindex, delay, alert, sflag, qrv, qqic, gss);
}

/*
 * This function sends two types of messages :
 *	- general queries
 *	- group spec. query S flag set/not set
 * Returns 0 on success, 1 on failure
 */
int
igmp_send_query(struct sockaddr_in *src,
		struct sockaddr_in *dst, struct sockaddr_in *group,
		int index, unsigned int delay, int alert,
		int sflag, int qrv, int qqic, int gss, int version)
{
	struct sockaddr_in *dstp;
        struct ifreq ifr;
        int s, sockerr;
        struct sockaddr_in* addr= (struct sockaddr_in*)&ifr.ifr_addr;
        struct eth_if *ifp = 0;

	/* Don't send any query if we don't have an IPv4 address on the interface */
        ifp = get_ifp_index(index);
	if (ifp) {
		strcpy(ifr.ifr_name, ifp->if_name);
		s = socket(AF_INET, SOCK_DGRAM, 0);
		sockerr = ioctl(s, SIOCGIFADDR, &ifr);
		close(s);
		if (sockerr == -1)
			return 1;
	}

        s = socket(AF_INET, SOCK_DGRAM, 0);
        sockerr = ioctl(s, SIOCGIFADDR, &ifr);
        if (sockerr == -1) {
                addr->sin_addr.s_addr = 0;
                ifr.ifr_addr.sa_family = AF_INET;
                ioctl(s, SIOCSIFADDR, &ifr);
        }
        close(s);

	if (igmp_build_query(src, dst, group, index, delay,
		alert, sflag, qrv, qqic, gss, version)) {
		log_msg(LOG_ERR, 0,	/* assert */
			"igmp_send_query: igmp_build_query failed");
		return 1;
	}
	dstp = (struct sockaddr_in *) sndmh.msg_name;

	/* set socket options : router alert */
	if (alert) {
		char ra[IPOPT_RTALERT_LEN];
		bzero(ra,IPOPT_RTALERT_LEN);
		ra[IPOPT_OPTVAL] = IPOPT_RA;
		ra[IPOPT_OLEN] = IPOPT_RTALERT_LEN;
		if (setsockopt(igmp_socket, IPPROTO_IP, IP_OPTIONS, ra, IPOPT_RTALERT_LEN) < 0) {
				log_msg(LOG_ERR, errno,	/* assert */ "igmp_send_query: can't set RA");
		}
	} else {
		if (setsockopt(igmp_socket, IPPROTO_IP, IP_OPTIONS, 0, 0) < 0) {
				log_msg(LOG_ERR, errno,	/* assert */ "igmp_send_query: can't remove RA");
		}
	}
	if (sendmsg(igmp_socket, &sndmh, 0) < 0) {
		log_msg(LOG_WARNING, errno,	/* assert */
			"igmp_send_query: sendmsg to %s for group %s with src %s on %s",
			sa_fmt(dstp), group?sa_fmt(group) : "(unspec)", src ? sa_fmt(src) : "(unspec)",
		ifindex2str(index));

		return 1;
	}

	log_msg(LOG_DEBUG, 0, "SENT IGMPv3 Query from %-12s to %s (group %s)",
		src ? sa_fmt(src) : "unspec", sa_fmt(dstp), group ? sa_fmt(group) : "unspec");
	return 0;
}

static unsigned int
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

static void
ip_get_lladdr(char *ifname, struct sockaddr_in *addr)
{
	struct ifaddrs *ifap = NULL, *ifa;
	struct sockaddr_in *paddr = NULL;

	if (getifaddrs(&ifap))
		log_msg(LOG_ERR, errno, "ip_get_lladdr");

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
		 * Ignore address family other than IPv4.
		 */
		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;

		paddr = (struct sockaddr_in *)ifa->ifa_addr;
		memcpy(addr, paddr, sizeof(struct sockaddr_in));
		break;
	}
	freeifaddrs(ifap);
}

#ifndef IGMP_ALL_PIM_ROUTERS
#define IGMP_ALL_PIM_ROUTERS  htonl(0xe000000D)
#endif

/* join/leave IGMP group */
int
igmp_join_group(struct sockaddr_in *group, int ifindex, int join)
{
	struct ip_mreqn mreq;

        mreq.imr_address.s_addr = htonl(INADDR_ANY);
	mreq.imr_multiaddr = group->sin_addr;

        mreq.imr_ifindex = ifindex;

        if (setsockopt(igmp_socket, IPPROTO_IP, join?IP_ADD_MEMBERSHIP:IP_DROP_MEMBERSHIP, (char *) &mreq, sizeof(mreq)) < 0)
                        return -1;
        return 0;
}

int
igmp_join_routers_group(int ifindex, int join)
{
	struct ip_mreqn mreq;

        mreq.imr_ifindex = ifindex;
        mreq.imr_address.s_addr = htonl(INADDR_ANY);

	mreq.imr_multiaddr.s_addr = IGMP_ALL_PIM_ROUTERS;
        if (setsockopt(pim4_socket, IPPROTO_IP, join?IP_ADD_MEMBERSHIP:IP_DROP_MEMBERSHIP, (char *) &mreq, sizeof(mreq)) < 0) {
                        return -1;
	}
	mreq.imr_multiaddr.s_addr = IGMP_ALL_ROUTER;
        if (setsockopt(igmp_socket, IPPROTO_IP, join?IP_ADD_MEMBERSHIP:IP_DROP_MEMBERSHIP, (char *) &mreq, sizeof(mreq)) < 0) {
                        return -1;
	}
	mreq.imr_multiaddr.s_addr = IGMPV3_ALL_MCR;
        if (setsockopt(igmp_socket, IPPROTO_IP, join?IP_ADD_MEMBERSHIP:IP_DROP_MEMBERSHIP, (char *) &mreq, sizeof(mreq)) < 0) {
                        return -1;
	}
        return 0;
}
