/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *                  Routing MSG management
 *                 (with delay and cancel)
 * $Id:
 ***************************************************************
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/un.h>
#include <sys/time.h>

#include <event.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>

#include <net/if.h>
#include <netinet/in.h>

#include "fpc.h"
#include "sockmisc.h"
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "cm_netlink.h"
#include "cm_pub.h"
#include "cm_priv.h"

#define RT_Q_HOLDTIME_SEC  0
#define RT_Q_HOLDTIME_MS   50

/* Routing message linkage */
struct rt_msg {
    TAILQ_ENTRY(rt_msg)   rtm_link;  /* chaining stuff       */
	struct cp_hdr        *rtm_msg;   /* message to be sent   */
};
TAILQ_HEAD(rtmmsg, rt_msg);

/* Data structures for generic Route Qs management */
struct rt_Q {
	struct rtmmsg   rtq_head;
	struct event    rtq_tmo;
	int             rtq_family;
	int             rtq_depth;
};

/* Route Qs declarations */
static struct rt_Q  R4;
static struct rt_Q  R6;
static struct timeval tm_rtq;
static void purge_rtQ_tmo (int, short, void *);

static int init_rtQ_done = 0;
static void
init_rtQ (void)
{
	TAILQ_INIT (&R4.rtq_head);
	R4.rtq_family = AF_INET;
	R4.rtq_depth = 0;
	evtimer_set (&R4.rtq_tmo, purge_rtQ_tmo, &R4);

	TAILQ_INIT (&R6.rtq_head);
	R6.rtq_depth = 0;
	R6.rtq_family = AF_INET6;
	evtimer_set (&R6.rtq_tmo, purge_rtQ_tmo, &R6);

	tm_rtq.tv_sec= RT_Q_HOLDTIME_SEC;
	tm_rtq.tv_usec = RT_Q_HOLDTIME_MS * 1000;
	init_rtQ_done = 1;
	return;
}

/*
 * All Qed delete commands are sent
 */
static void
purge_rtQ (struct rt_Q *rtQ)
{
	struct rt_msg *pkt;

	while ((pkt = TAILQ_FIRST (&rtQ->rtq_head))) {
		TAILQ_REMOVE(&rtQ->rtq_head, pkt, rtm_link);
		rtQ->rtq_depth--;
		post_msg (pkt->rtm_msg);
		CM_FREE(pkt);
	}
	return;
}

/*
 * Purge all Q (exported function)
 */
void
purge_rtQueues()
{
	purge_rtQ(&R4);
	purge_rtQ(&R6);
}

/*
 * Delete & Free all RT msgs.
 */
static void
purge_rtQ_only (struct rt_Q *rtQ)
{
	struct rt_msg *pkt;

	while ((pkt = TAILQ_FIRST (&rtQ->rtq_head))) {
		TAILQ_REMOVE(&rtQ->rtq_head, pkt, rtm_link);
		rtQ->rtq_depth--;
		if (pkt->rtm_msg)
			CM_FREE(pkt->rtm_msg);
		CM_FREE(pkt);
	}
	evtimer_del(&rtQ->rtq_tmo);

	return;
}

/*
 * Purge all Q without sending msgs.
 */
void
rtQ_destroy(void)
{
	purge_rtQ_only(&R4);
	purge_rtQ_only(&R6);
}

/*
 * Q purge is also managed n timeout
 */
static void
purge_rtQ_tmo (int fd, short event, void *data)
{
	purge_rtQ ((struct rt_Q *)data);
}

/*
 * CMD_ROUTEx_DEL management
 */
static int
insert_rtQ (struct rt_Q *rtQ, struct cp_hdr *msg)
{
	struct rt_msg *pkt;

	/*
	 * We store all consecutive DEL for the same dest/plen
	 * to be able to cancel them when associated ADD command
	 * are received.
	 */
	pkt = TAILQ_FIRST (&rtQ->rtq_head);
	if (pkt) {
		int nomatch = 0;
		if (rtQ->rtq_family == AF_INET) {
			struct cp_route4 *cr4= (struct cp_route4 *)(pkt->rtm_msg + 1);
			struct cp_route4 *cm4= (struct cp_route4 *)(msg + 1);
			nomatch = (memcmp (&cr4->cpr4_prefix,
			                &cm4->cpr4_prefix,
							sizeof (cm4->cpr4_prefix)) ||
			           memcmp (&cr4->cpr4_mask,
			                &cm4->cpr4_mask,
			                sizeof (cm4->cpr4_mask)));
		} else {
			struct cp_route6 *cr6= (struct cp_route6 *)(pkt->rtm_msg + 1);
			struct cp_route6 *cm6= (struct cp_route6 *)(msg + 1);
			nomatch = (memcmp (&cr6->cpr6_prefix,
			                &cm6->cpr6_prefix,
			                sizeof (cm6->cpr6_prefix)) ||
			           (cr6->cpr6_pfxlen != cm6->cpr6_pfxlen));
		}
		/*
		 * The dest/pln is different : we don't expect DEL/ADD
		 * cancellation. So send all Qed DEL.
		 */
		if (nomatch) {
			purge_rtQ (rtQ);
		}
		evtimer_del (&rtQ->rtq_tmo);
	}
	CM_MALLOC(pkt, sizeof(*pkt));

	pkt->rtm_msg = msg;

	TAILQ_INSERT_TAIL (&rtQ->rtq_head, pkt, rtm_link);
	rtQ->rtq_depth++;
	/* (Re-)activate timer vith (new) deadline */
	evtimer_add (&rtQ->rtq_tmo, &tm_rtq);
	return 0;
}

/*
 * CMD_ROUTEx_ADD management
 */
static void
check_rtQ(struct rt_Q *rtQ, struct cp_hdr *msg)
{
	struct rt_msg *pkt;
	int len = htonl (msg->cphdr_length);

	/*
	 * Scan all memorized DEL commands
	 */
	TAILQ_FOREACH (pkt, &rtQ->rtq_head, rtm_link) {
		if (memcmp(msg + 1, pkt->rtm_msg + 1, len) == 0) {
			/*
			 * If it matches dest/plen, route type etc ...
			 * then remove DEL command from Q, and cancel both
			 * ADD and DEL commands
			 */
			TAILQ_REMOVE(&rtQ->rtq_head, pkt, rtm_link);
			rtQ->rtq_depth--;
			CM_FREE(pkt->rtm_msg);
			CM_FREE(pkt);
			CM_FREE(msg);
			return;
		}
	}
	/*
	 * No match found : all DEL commands must be sent
	 * as well as the ADD command
	 */
	evtimer_del (&rtQ->rtq_tmo);
	purge_rtQ(rtQ);
	post_msg(msg);
	return;
}


/*
 * DEL/ADD management for ECMP:
 *   currently, when a route is present:
 *       P::/n  -->  G1
 *              -->  G2
 *              -->  G3
 *
 *  and a delele route (P::/n, G2) is sent, the associated
 *  MSG are:
 *    DEL (P::/n, G1)
 *    DEL (P::/n, G2)
 *    DEL (P::/n, G3)
 *    ADD (P::/n, G1)
 *    ADD (P::/n, G3)
 *
 * Same thing for adding a new destination: it first removes all
 * routes then add again the same routes, plus the new one.
 *
 * The idea is then top manage a Q for DEL commands, with an associated
 * timeout, and during this timeout, all ADD command that match a DEL
 * command are cancelled. This leads to message reduction : in the previous
 * exmple, only
 *  DEL (P::/n, G2)
 * will be sent
 */
void
post_rt_msg (struct cp_hdr *msg)
{

	if (!init_rtQ_done)
		init_rtQ();

	switch (htonl(msg->cphdr_type)) {
	case CMD_ROUTE4_DEL:
		insert_rtQ(&R4, msg);
		break;
	case CMD_ROUTE4_ADD:
	case CMD_ROUTE4_CHG:
		check_rtQ(&R4, msg);
		break;
	case CMD_ROUTE6_DEL:
		insert_rtQ(&R6, msg);
		break;
	case CMD_ROUTE6_ADD:
		check_rtQ(&R6, msg);
		break;
	default:
		break;
	}
	return;
}
