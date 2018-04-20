/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *
 *          Generic Msg exchange between
 *    Cache Manager (CM) and  Fast Path Manager (FPM)
 *
 * $Id: fpm.c,v 1.64 2010-10-21 14:56:21 dichtel Exp $
 ***************************************************************
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/un.h>

#include <event.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>

#include <net/if.h>
#include <netinet/in.h>

#include "sockmisc.h"
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/rtnetlink.h>
#include "fpc.h"
#include "cm_netlink.h"
#include "cm_pub.h" /* for cm2cp_reset() */
#include "cm_priv.h"

#include "libconsole.h"

#ifdef CONFIG_HA6W_SUPPORT
#  include "hasupport.h"
   extern struct has_ctx * cmg_has;
#endif

#define	TCP_SYN_TIMEOUT		1
#define	TCP_RECONNECT_INTERVAL	3

TAILQ_HEAD(fpmmsg, fpm_msg);

struct fpm_ctx {
	int                   fpm_sock;
	u_int32_t             fpm_ev_set;
	struct event          *fpm_ev_send;
	struct event          *fpm_ev_recv;
	struct event          *fpm_ev_connection;
	struct timeval        fpm_tv_connection;
	struct event          *fpm_ev_connection_delay;
	struct timeval        fpm_tv_connection_delay;

	struct fpmmsg         fpm_msg_head;
	u_int32_t             fpm_msg;
	u_int32_t             fpm_sent;
	u_int32_t	      fpm_highest;
	u_int32_t	      fpm_blocked;
	u_int32_t	      fpm_direct;
	u_int32_t	      fpm_partial;
	u_int32_t	      fpm_error;
	u_int8_t	      fpm_force_enqueue; /* used to limit number of syscalls */
};

static void fpm_dequeue (int, short, void *);
static void fpm_recv (int, short, void *);
static void fpm_connect_delay(struct fpm_ctx *fpm);
static void fpm_connect_delay_cb(int fd, short event, void *arg);
static void fpm_connect(struct fpm_ctx *fpm);
static void fpm_connection(int fd, short event, void *arg);

/*
 * UNIX socket server variables
 */
char *srv_path = DEFAULT_CM_PATH;

/*
 * In case of single FPM, let's have it STATIC
 */
struct fpm_ctx FPM_CTX;

/*
 *========================================================
 *   LOCAL TOOLS
 *========================================================
 */

void fpm_dump_queue(int s)
{
	struct fpm_ctx *fpm = &FPM_CTX;

	command_printf(s, "Queue information\n");
	command_printf(s, "- sent: %u\n", fpm->fpm_sent);
	command_printf(s, "- directly: %u\n", fpm->fpm_direct);
	command_printf(s, "- in-queue: %u\n", fpm->fpm_msg);
	command_printf(s, "- highest in-queue: %u\n", fpm->fpm_highest);
	command_printf(s, "- has blocked: %u\n", fpm->fpm_blocked);
	command_printf(s, "- partially sent: %u\n", fpm->fpm_partial);
	command_printf(s, "- errors: %u\n", fpm->fpm_error);
	command_printf(s, "- ev armed: %u\n\n", fpm->fpm_ev_set);
}

static void
purge_msgQ (struct fpmmsg *head)
{
	struct fpm_msg *msg;

	while ((msg = TAILQ_FIRST(head))) {
		TAILQ_REMOVE(head, msg, msg_link);
		CM_FREE(msg->msg_pkt);
		CM_FREE(msg);
	}
}

static void
fpm_destroy (struct fpm_ctx *fpm)
{
	/*
	 * First, remove any event, and close socket
	 */
	if (fpm->fpm_ev_recv)
		event_free(fpm->fpm_ev_recv);
	if (fpm->fpm_ev_send)
		event_free(fpm->fpm_ev_send);
	if (fpm->fpm_ev_connection)
		event_free(fpm->fpm_ev_connection);
	if (fpm->fpm_ev_connection_delay)
		event_free(fpm->fpm_ev_connection_delay);
	close (fpm->fpm_sock);
	fpm->fpm_sock = (-1);

#ifdef CONFIG_CACHEMGR_MULTIBLADE
	cm_fpib.ifuid = 0;
#endif
	/*
	 * Then free Qs
	 */
	purge_msgQ (&fpm->fpm_msg_head);
	if (fpm->fpm_msg) {
		syslog(LOG_ERR,
		       "%s: fpm queue is destroyed whereas there are still %d msgs in queue\n",
		       __FUNCTION__, fpm->fpm_msg);
		fpm->fpm_msg = 0;
	}
}

/*
 * Determines if sending conditions are met
 * and if needed set associated libevent event
 */
static void
fpm_resched_ev_send (struct fpm_ctx *fpm)
{

	/*
	 * If there are still one remaining , re-arm (if needed)
	 * the evt to allow future sending when socket is ready
	 * else, wait for something to be posted
	 */
	if (fpm->fpm_sock != (-1) &&
	    !(TAILQ_EMPTY(&fpm->fpm_msg_head)) &&
	    !fpm->fpm_force_enqueue &&
	    !fpm->fpm_ev_set &&
	    fpm->fpm_ev_send &&
	    event_initialized(fpm->fpm_ev_send)) {
		if (event_add (fpm->fpm_ev_send, NULL))
			syslog(LOG_ERR, "%s: failed to add sending event for fpm (%s)\n",
			       __FUNCTION__, strerror(errno));
		else
			fpm->fpm_ev_set = 1;
	}
}

void
fpm_dump (void)
{
	struct fpm_ctx *fpm = &FPM_CTX;
	struct fpm_msg *msg;

	syslog(LOG_INFO, "Cache Manager dump message queues\n");
	TAILQ_FOREACH(msg, &fpm->fpm_msg_head, msg_link)
		cm_dump (CM_DUMP_FPM, msg, "POST_Q:", cm_ifuid2name);
}

/*
 *========================================================
 *   CM-FPM establishment and inits
 *========================================================
 */

static void
fpm_connect_delay_cb(int fd, short event, void *arg)
{
	struct fpm_ctx *fpm = arg;

	fpm_connect(fpm);
}

static void
fpm_connect_delay(struct fpm_ctx *fpm)
{
	syslog(LOG_DEBUG, "%s: tcp reconnect start\n", __FUNCTION__);

	fpm->fpm_ev_connection_delay = evtimer_new(cm_event_base,
						   fpm_connect_delay_cb, fpm);
	if (evtimer_add(fpm->fpm_ev_connection_delay, &fpm->fpm_tv_connection_delay)) {
		syslog(LOG_ERR, "%s: failed to add event for fpm reconnect\n",
		       __FUNCTION__);
		exit(1);
	}
}

static void
fpm_connection(int fd, short event, void *arg)
{
	struct fpm_ctx *fpm = arg;

	if (event & EV_WRITE) {
		int error;
		int ret;
		socklen_t optlen = sizeof(error);

		ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &optlen);
		if ((ret == 0) && (error == 0)) {
			syslog(LOG_DEBUG, "%s: connected to fpm socket\n", __FUNCTION__);

			fpm->fpm_ev_send = event_new(cm_event_base, fpm->fpm_sock,
						     EV_WRITE,
						     fpm_dequeue, fpm);

			/*
			 * All CM inits
			 */
			cm_init();

			fpm->fpm_ev_recv = event_new(cm_event_base, fpm->fpm_sock,
						     EV_READ | EV_PERSIST,
						     fpm_recv, fpm);
			if (event_add(fpm->fpm_ev_recv, NULL)) {
				syslog(LOG_ERR,
				       "%s: failed to add event for fpm receiving\n",
				       __FUNCTION__);
				exit(-1);
			}
		} else {
			if (ret == -1)
				syslog(LOG_NOTICE, "%s: failed at getsockopt:%s\n",
				       __FUNCTION__, strerror(errno));
			else
				syslog(LOG_NOTICE, "%s: failed to connect to fpm socket:%s\n",
				       __FUNCTION__, strerror(error));
			close(fd);
			fpm_connect_delay(fpm);
		}
	} else {
		syslog(LOG_DEBUG, "%s: connect timeout, try again\n",
		       __FUNCTION__);
		close(fd);
		fpm_connect(fpm);
	}
}

static int fpm_connect_retries = 3;
static void
fpm_connect(struct fpm_ctx *fpm)
{
	fpm->fpm_sock = newsock(srv_family, SOCK_STREAM, 0, O_NONBLOCK, cm_sockbufsiz,
				"CM/FPM");
	if (fpm->fpm_sock < 0) {
	    syslog(LOG_ERR, "%s: failed to open socket(family:%d, name:CM/FPM)\n",
	           __FUNCTION__, srv_family);
	    exit (-1);
	}

	if (cm_debug_level & CM_DUMP_DBG_SOCK) {
		char log[LOG_BUFFER_LEN];

		dump_sockaddr(log, srv_sockaddr);
		syslog(LOG_DEBUG, "Connecting to socket: %s\n", log);
	}

	syslog(LOG_DEBUG, "%s: trying to connect to fpm\n", __FUNCTION__);
	if (connect(fpm->fpm_sock, srv_sockaddr, sockaddr_len(srv_sockaddr)) < 0) {
		if ((srv_family == AF_UNIX) && (fpm_connect_retries > 0)) {
			if (errno != ECONNREFUSED)
				fpm_connect_retries--;
			syslog(LOG_NOTICE,
			       "%s: failed to connect to fpm socket: '%s'. Retrying in %ds.\n",
			       __FUNCTION__, strerror(errno), TCP_RECONNECT_INTERVAL);
			close(fpm->fpm_sock);
			fpm_connect_delay(fpm);
			return;
		} else if (errno != EINPROGRESS) {
			syslog(LOG_ERR,
			       "%s: failed to connect to fpm socket: '%s'. Giving up.\n",
			       __FUNCTION__, strerror(errno));
			close(fpm->fpm_sock);
			return;
		}
	}
	fpm->fpm_ev_connection = event_new(cm_event_base, fpm->fpm_sock, EV_WRITE,
					   fpm_connection, fpm);
	if (event_add(fpm->fpm_ev_connection, &fpm->fpm_tv_connection)) {
		syslog(LOG_ERR, "%s: failed to add event for connecting fpm => exiting\n",
		       __FUNCTION__);
		exit(1);
	}
}

int
fpm_init(int delay)
{
	struct fpm_ctx *fpm = &FPM_CTX;

	memset (fpm, 0, sizeof(*fpm));
	TAILQ_INIT (&fpm->fpm_msg_head);
	fpm->fpm_sock = -1;

	if (fpm_ignore) {
		/* No plan to connect to fpm: warn and start netlink */
		syslog(LOG_WARNING, "Option IGNORE: no connection with fpm\n");
		cm_init();
		return 0;
	}

	fpm->fpm_tv_connection.tv_sec = TCP_SYN_TIMEOUT;
	fpm->fpm_tv_connection.tv_usec = 0;
	fpm->fpm_tv_connection_delay.tv_sec = TCP_RECONNECT_INTERVAL;
	fpm->fpm_tv_connection_delay.tv_usec = 0;
	if (delay)
		fpm_connect_delay(fpm);
	else
		fpm_connect(fpm);

	return 0;
}

/*
 *========================================================
 *   running CM-FPM  Direct Calls
 *========================================================
 */

/*
 * MSG posting, to sent to the FPM.
 * Called from the CM internal process (netlink translation)
 * Manages a list, and update sending evt
 */
int
fpm_enqueue (struct cp_hdr *m, void *_fpm)
{
	struct fpm_ctx *fpm = (struct fpm_ctx *)_fpm;
	struct fpm_msg *msg;
	int offset = 0;
	int len = ntohl(m->cphdr_length) + sizeof (struct cp_hdr);

	if (fpm == NULL)
		fpm = &FPM_CTX;

	/* Debug mode -i : no connection to fpm, drop it */
	if (fpm_ignore) {
		fpm->fpm_error++;
		return 0;
	}

	/*
	 * SPECIAL management for RESET Command
	 *  - flush every waiting message
	 */
	if (m->cphdr_type == htonl(CMD_RESET)) {
		purge_msgQ (&fpm->fpm_msg_head);
		if (fpm->fpm_msg) {
			syslog(LOG_ERR,
			       "%s: fpm queue is reset whereas there are still %d msgs in queue\n",
			       __FUNCTION__, fpm->fpm_msg);
			fpm->fpm_msg = 0;
		}
	}

	/* Attempt to send directly. If it fails,
	 * enqueue the packet.
	 * If enqueue failed, retry directly.
	 */
retry:
	if (fpm->fpm_sock != (-1) &&
	    TAILQ_EMPTY(&fpm->fpm_msg_head) &&
	    !fpm->fpm_force_enqueue &&
	    !fpm->fpm_ev_set) {
		int ret;

		ret = send(fpm->fpm_sock, m + offset, len - offset, 0);
		if (ret == (len - offset)) {
			/* success */
			struct fpm_msg msg0;
			msg0.msg_off = offset;
			msg0.msg_len = len;
			msg0.msg_pkt = m;
			cm_dump (CM_DUMP_SENT_WITH_PAYLOAD, &msg0, NULL, cm_ifuid2name);
			CM_FREE(m);
			fpm->fpm_sent++;
			fpm->fpm_direct++;
			return 0;
		}
		/* if partially sent */
		if (ret > 0) {
			offset = ret;
			fpm->fpm_partial++;
		}
	}
	CM_MALLOC(msg, sizeof(*msg));
	if (!msg) {
		syslog(LOG_WARNING, "%s: failed to enqueue msg\n",
				__FUNCTION__);
		fpm->fpm_error++;
		goto retry;
	}

	msg->msg_off = offset;
	msg->msg_len = len;
	msg->msg_pkt = m;
	TAILQ_INSERT_TAIL(&fpm->fpm_msg_head, msg, msg_link);
	fpm->fpm_msg++;
	if (fpm->fpm_msg > fpm->fpm_highest)
		fpm->fpm_highest = fpm->fpm_msg;
	cm_dump (CM_DUMP_QUEUED, msg, NULL, cm_ifuid2name);

	/*
	 * Schedule event send for dequeuing.
	 */
	fpm_resched_ev_send (fpm);
	return 0;
}

/*
 *========================================================
 *   running CM-FPM  Event driven fct
 *========================================================
 */

/*
 * MSG emission to the FPM.
 * Called through the libevent framework. The associated
 * evt is NOT persistent, and needs to be re-armed.
 */
static void
fpm_dequeue(int fd, short event, void *data)
{
	struct fpm_ctx *fpm = (struct fpm_ctx *)data;
	struct fpm_msg *fpm_msg;

	fpm->fpm_ev_set = 0;

	/*
	 * try to send as many msg as possible,
	 * without being blocked
	 */
	while ((fpm_msg = TAILQ_FIRST(&fpm->fpm_msg_head))) {
		int lg;
		struct msghdr msg;
		struct iovec iov[CM_DEFAULT_IOVLEN];
		int i = 1, total_len = 0;

		memset(&msg, 0, sizeof(msg));
		memset(iov, 0, sizeof(iov));
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		iov[0].iov_base = (char *)fpm_msg->msg_pkt + fpm_msg->msg_off;
		iov[0].iov_len = fpm_msg->msg_len - fpm_msg->msg_off;
		total_len = fpm_msg->msg_len - fpm_msg->msg_off;

		for (i = 1; i < CM_DEFAULT_IOVLEN &&
		            total_len < cm_sockbufsiz * 2; i++) {
			if ((fpm_msg = TAILQ_NEXT(fpm_msg, msg_link)) == NULL)
				break;

			iov[i].iov_base = (char *)fpm_msg->msg_pkt + fpm_msg->msg_off;
			iov[i].iov_len = fpm_msg->msg_len - fpm_msg->msg_off;
			msg.msg_iovlen++;
			total_len += fpm_msg->msg_len - fpm_msg->msg_off;
		}
		lg = sendmsg(fpm->fpm_sock, &msg, 0);
		if (cm_debug_level & CM_DUMP_DBG_SOCK  && lg > 0)
			syslog(LOG_DEBUG, "%s: try to send %d msg (%d bytes) and "
			       "%d bytes have been really sent\n", __FUNCTION__,
			       i, total_len, lg);

		if (lg == -1) {
			/* could not send */
			if (errno == EAGAIN) {
				fpm->fpm_blocked++;
				break;
			}
			/* real error */
			syslog(LOG_DEBUG, "%s: connection with fpm is lost "
			       "(error: %s)\n", __FUNCTION__, strerror(errno));
			/* fpm_destroy() purges the list */
			fpm_destroy(fpm);
			cm_destroy();
			rtQ_destroy();
			fpm_init(1);
			return;
		}

		while (lg > 0) {
			fpm_msg = TAILQ_FIRST(&fpm->fpm_msg_head);

			if (lg >= (signed) (fpm_msg->msg_len - fpm_msg->msg_off)) {
				/* message fully sent */
				lg -= fpm_msg->msg_len - fpm_msg->msg_off;
				TAILQ_REMOVE(&fpm->fpm_msg_head, fpm_msg, msg_link);
				fpm->fpm_msg--;
				fpm->fpm_sent++;

				cm_dump (CM_DUMP_SENT_WITH_PAYLOAD, fpm_msg, NULL, cm_ifuid2name);

				CM_FREE(fpm_msg->msg_pkt);
				CM_FREE(fpm_msg);
			} else {
				/* could not send all data => retry */
				fpm_msg->msg_off += lg;
				fpm->fpm_partial++;
				lg = 0;

				if (cm_debug_level & CM_DUMP_DBG_SOCK)
					syslog(LOG_DEBUG, "%s: partially sent %d bytes, continue\n",
					       __FUNCTION__, fpm_msg->msg_len - fpm_msg->msg_off);
			}
		}
	}

	if (!(TAILQ_EMPTY(&fpm->fpm_msg_head))) {
		if (cm_debug_level & CM_DUMP_DBG_SOCK)
			syslog(LOG_DEBUG, "%s: socket is full\n",
					__FUNCTION__);
		/* Ask to wake-up when we receive a signal */
		fpm_resched_ev_send(fpm);
	}
}

void fpm_process_queue(u_int8_t value)
{
	struct fpm_ctx *fpm = &FPM_CTX;

	if (value)
		fpm->fpm_force_enqueue = 1;
	else {
		fpm->fpm_force_enqueue = 0;
		fpm_resched_ev_send(fpm);
	}
}

/*
 * MSG reception from the FPM, mainly ACK/NACK.
 * Called through the libevent framework.
 */
static int __fpm_received = 0;
static int __fpm_expected = sizeof (struct cp_hdr) ;
static int __fpm_waithdr = 1;
static u_int8_t __fpm_recv_buf[4096];
static u_int8_t *__fpm_recv_largebuf = NULL;

static void
fpm_recv (int fd, short event, void *data)
{
	struct fpm_ctx *fpm = (struct fpm_ctx *)data;
	struct fpm_msg r_msg;
	struct cp_hdr *hdr;
	int       lg;

	if (__fpm_recv_largebuf)
		hdr = (struct cp_hdr *)__fpm_recv_largebuf;
	else
		hdr = (struct cp_hdr *)__fpm_recv_buf;

	lg = recv(fd, (u_int8_t *)hdr + __fpm_received, __fpm_expected, 0);
	if (lg <= 0) {
		/* nothing to read */
		if (errno == EAGAIN) {
			/* the event is PERSIST */
			return;
		}

		/* real error */
		syslog(LOG_DEBUG,  "%s: connection with fpm is lost\n", __FUNCTION__);
		fpm_destroy (fpm);
		cm_destroy();
		rtQ_destroy();
		fpm_init(1);
		return;
	}

	__fpm_received += lg;
	__fpm_expected -= lg;
	if (__fpm_expected)
		return;
	if (__fpm_waithdr) {
		__fpm_expected = ntohl(hdr->cphdr_length);
		if (__fpm_expected < 0) {
			syslog(LOG_ERR, "%s: expected size(%d) is invalid\n",
					__FUNCTION__, __fpm_expected);
			__fpm_waithdr = 1;
			__fpm_expected = sizeof(struct cp_hdr);
			__fpm_received = 0;
			return;
		}
		if (__fpm_expected + sizeof(struct cp_hdr) > sizeof(__fpm_recv_buf)) {
			if (__fpm_recv_largebuf)
				free(__fpm_recv_largebuf);
			__fpm_recv_largebuf = (u_int8_t *)malloc(__fpm_expected
					+ sizeof(struct cp_hdr));
			if (__fpm_recv_largebuf == NULL) {
				syslog(LOG_ERR, "%s: failed to malloc %llubytes memory(%s)\n",
						__FUNCTION__,
						(unsigned long long)(__fpm_expected + sizeof(struct cp_hdr)),
						strerror(errno));
				syslog(LOG_ERR, "%s: DROP message (type: 0x%x)\n",
						__FUNCTION__, ntohl(hdr->cphdr_type));
				while(__fpm_expected > 0) {
					lg = recv(fd, __fpm_recv_buf,
						  ((size_t)__fpm_expected > sizeof(__fpm_recv_buf)) ?
						  sizeof(__fpm_recv_buf) : (size_t)__fpm_expected, 0);
					if (lg <= 0) {
						/* nothing to read */
						if (errno == EAGAIN)
							break;
						syslog(LOG_ERR, "%s: connection with fpm is lost\n", __FUNCTION__);
						fpm_destroy(fpm);
						cm_destroy();
						rtQ_destroy();
						fpm_init(1);
						return;
					}
					__fpm_expected -= lg;
				}
				__fpm_waithdr = 1;
				__fpm_expected = sizeof(struct cp_hdr);
				__fpm_received = 0;
				return;
			}
			memcpy(__fpm_recv_largebuf, __fpm_recv_buf, sizeof(struct cp_hdr));
		}
		__fpm_waithdr = 0;
		if (__fpm_expected)
			return;
	}
	__fpm_waithdr = 1;
	__fpm_expected = sizeof (struct cp_hdr);
	r_msg.msg_len  = __fpm_received;
	__fpm_received = 0;

	r_msg.msg_pkt = hdr ;
	cm_dump (CM_DUMP_RECV, &r_msg, NULL, cm_ifuid2name);
}
