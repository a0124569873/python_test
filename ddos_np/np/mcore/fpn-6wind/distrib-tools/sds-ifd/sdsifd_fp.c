/*
 * Copyright 2013 6WIND S.A.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <syslog.h>
#include <event.h>
#include <libconsole.h>

#include "sock.h"
#include "stream.h"

#include "sdsifd_conf.h"
#include "sdsifd_pkt.h"
#include <libif.h>

/*
 * we have only one peer at a time, here are its stream to write data
 * and its id.
 */
static struct stream peer_stream;
static int peer_id;

/* libconsole functions */
/* show network informations about the peer */
void command_show_fp_stream(int s, struct stream *stream)
{
	command_printf(s, "fd=%d ", stream->stream_sock);
	if (stream->stream_state == STREAM_DISCONNECTED)
		command_printf(s, "state=disconnected ");
	else {
		command_printf(s, "state=%s [%s:%d] ",
			       stream->stream_state == STREAM_CONNECTING ? "connecting":"connected",
			       sock_getaddr(&stream->stream_addr.sa),
			       sock_getport(&stream->stream_addr.sa));
	}
	command_printf(s, "\n");
}

void command_show_fp_peer(int s, __attribute__ ((unused)) char *dummy,
			  __attribute__ ((unused))void *evt)
{
	command_printf(s, "cp%d\n", peer_id);
	command_show_fp_stream(s, &peer_stream);
}

static void sdsifd_fp_reconnect(void);

int sdsifd_nl_fp_if_update(const char *ifname, uint8_t up);
int sdsifd_nl_fp_if_set_allmulti(const char *ifname);

/*
 * put ifconf in libif userdata for further use.
 *
 * We also use it to know, when we get a libif_iface, if we should
 * take care of it (!iface->userdata means filter).
 *
 */
void sdsifd_fp_set_libif_userdata(struct libif_iface *iface)
{
	if (!iface->userdata)
		iface->userdata = (void *) sdsifd_interface_conf_lookup_by_name(iface->name);
}

/*
 * prepare an interface message and send it.
 *
 * Callers of this function must take care that iface->userdata is not NULL.
 */
int sdsifd_fp_tx_interface(struct libif_iface *iface)
{
	struct sdsifd_fp_if_msg data;
	struct sdsifd_interface_conf *ifconf;

	ifconf = iface->userdata;

	snprintf(data.name, sizeof(data.name), "%s", iface->name);
	data.version = htons(SDSIFD_PROTOCOL_VERSION);
	memcpy(data.mac, iface->devaddr, sizeof(data.mac));
	data.mtu = htonl(iface->mtu);
	data.running = (iface->flags & IFF_RUNNING) ? 1 : 0;
	data.fpib    = ifconf->fpib;

	return sdsifd_send_message(SDSIFD_FP_IF_MSG, &data, sizeof(data),
				   &peer_stream, peer_id);
}


/*
 * libstream callback, called on a message reception
 *
 * 'code' is sent by libstream, in case there was a problem.
 *
 * If we receive:
 *  - SDSIFD_CP_PEER_MSG, we send all our interface to the peer
 *  - SDSIFD_CP_IF_MSG, we try to update the up flag of our interface
 */
static void sdsifd_fp_rxdata_cb(void *data, struct stream_msg *msg, int code)
{
	struct iface_list *ifaces;
	struct libif_iface *iface;
	uint8_t command;
	uint8_t id;
	char buf[512];

	if (code < 0) {
		IFD_LOG(LOG_WARNING, "%s", strerror(errno));
		stream_close(&peer_stream);
		sdsifd_fp_reconnect();
		return;
	} else if (code == 0) {
		IFD_LOG(LOG_WARNING, "connection closed");
		stream_close(&peer_stream);
		sdsifd_fp_reconnect();
		return;
	}

	command = ntohs(msg->msg_type);
	id = ntohs(msg->msg_id);
	peer_id = id;

	sdsifd_pkt_log_msg(command, (msg + 1), buf, sizeof(buf));
	IFD_LOG(LOG_DEBUG, " RX CP%d  %s", id, buf);

	/* parse msg */
	switch (command) {

	case SDSIFD_CP_PEER_MSG:
		ifaces = libif_iface_get_allvr_list();
		LIST_FOREACH(iface, ifaces, next) {
			if (!iface->userdata)
				continue;

			sdsifd_fp_tx_interface(iface);
		}
		break;
	case SDSIFD_CP_IF_MSG:
		{
			struct sdsifd_cp_if_msg *ifmsg = (struct sdsifd_cp_if_msg *)(msg + 1);

			if (ntohs(ifmsg->version) != SDSIFD_PROTOCOL_VERSION) {
				IFD_LOG(LOG_WARNING, "different version: ours %d peer %d",
					SDSIFD_PROTOCOL_VERSION, ntohs(ifmsg->version));
				return;
			}

			sdsifd_nl_fp_if_update(ifmsg->name, ifmsg->up);
		}
		break;

	default:
		break;
	}
}

/*
 * function called on peer disconnection
 *
 * Try to reconnect.
 */
static void sdsifd_fp_peer_del(void)
{
	IFD_LOG(LOG_INFO, "CP disconnected");
	sdsifd_fp_reconnect();
	return;
}

/*
 * function called on peer connection
 *
 * Send the initial message SDSIFD_FP_PEER_MSG to the cp.
 */
static void sdsifd_fp_peer_new(void)
{
	IFD_LOG(LOG_INFO, "CP connected");

	sdsifd_send_message(SDSIFD_FP_PEER_MSG, NULL, 0, &peer_stream, peer_id);
}

/*
 * libstream callback, called on peer connection
 *
 * 'code' is sent by libstream, -1 means disconnect.
 */
static void sdsifd_fp_peer_connected(void *data, int code)
{
	if (code == -1)
		sdsifd_fp_peer_del();
	else
		sdsifd_fp_peer_new();
}

/*
 * common socket/tcp options
 */
static int sdsifd_fp_common_setsockopt(int fd)
{
	int val;
	struct linger linger;

	/* set TCP no delay option to send data immediately */
	val = 1;
	if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &val, sizeof(val)) < 0) {
		IFD_LOG(LOG_ERR, "%s: cannot set nodelay tcp option: %s\n",
			__FUNCTION__, strerror(errno));
		close (fd);
		return -1;
	}

	/* immediately send a TCP RST when closing socket */
	linger.l_onoff  = 1;
	linger.l_linger = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) < 0) {
		IFD_LOG(LOG_WARNING, "%s: cannot set linger option: %s\n",
			__FUNCTION__, strerror(errno));
	}

	/* Enable tcp keepalive */
	val = 1;
	if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) < 0) {
		IFD_LOG(LOG_ERR, "%s: cannot set keepalive tcp option: %s\n",
			__FUNCTION__, strerror(errno));
		close (fd);
		return -1;
	}

	/* the interval between the last data packet sent
	 * (simple ACKs are not considered data) and the first
	 * keepalive probe; after the connection is marked to
	 * need keepalive, this counter is not used any
	 * further  */
	val = 1;
	if(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &val, sizeof(val)) < 0) {
		IFD_LOG(LOG_ERR, "%s: cannot set TCP_KEEPIDLE option: %s\n",
			__FUNCTION__, strerror(errno));
		close (fd);
		return -1;
	}

	/* the interval between subsequential keepalive
	 * probes, regardless of what the connection has
	 * exchanged in the meantime  */
	val = 1;
	if(setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &val, sizeof(val)) < 0) {
		IFD_LOG(LOG_ERR, "%s: cannot set TCP_KEEPINTVL: %s\n",
			__FUNCTION__, strerror(errno));
		close (fd);
		return -1;
	}

	/* the number of unacknowledged probes to send before
	 * considering the connection dead and notifying the
	 * application layer  */
	val = 5;
	if(setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &val, sizeof(val)) < 0) {
		IFD_LOG(LOG_ERR, "%s: cannot set TCP_KEEPCNT option: %s\n",
			__FUNCTION__, strerror(errno));
		close (fd);
		return -1;
	}

	return 0;
}

/*
 * this function initialize the libstream and makes a connection.
 *
 * If first connection failed, we try to reconnect.
 */
static int sdsifd_fp_connect()
{
	int ret;
	sock_addr_t addr;

	memset(&addr, 0, sizeof(addr));

	addr.sin.sin_family = AF_INET;
	inet_pton(AF_INET, sdsifd_cp_address, &addr.sin.sin_addr);
	addr.sin.sin_port   = htons(sdsifd_cp_port);

	/* Init libstream */
	IFD_LOG(LOG_INFO, "connecting to [%s:%d]", sock_getaddr(&addr.sa),
		sock_getport(&addr.sa));

	stream_init(&peer_stream, 0, 0);

	ret = stream_connect(&peer_stream, &addr.sa,
			     sdsifd_fp_peer_connected, NULL /* priv */,
			     sdsifd_fp_rxdata_cb, NULL /* priv */);

	if (ret >= 0) {
		IFD_LOG(LOG_ERR, " => success");
		sdsifd_fp_common_setsockopt(peer_stream.stream_sock);
	} else {
		sdsifd_fp_reconnect();
		IFD_LOG(LOG_ERR, " => failure");
	}

	return ret;
}

/*
 * this function start a connection, it is called from libevent, see
 * sdsifd_fp_reconnect.
 */
static void sdsifd_fp_reconnect_cb(int fd, short ev_type, void *arg)
{
	struct event *ev = arg;
	free(ev); /* free this event */
	sdsifd_fp_connect();
}

/*
 * this function schedules a reconnection in 3 seconds.
 */
static void sdsifd_fp_reconnect(void)
{
	struct event *ev;
	struct timeval tv;

	IFD_LOG(LOG_DEBUG, "");

	tv.tv_sec = 3;
	tv.tv_usec = 0;
	ev = calloc(sizeof(struct event), 1);
	evtimer_set(ev, sdsifd_fp_reconnect_cb, ev);
	evtimer_add(ev, &tv);
}

/*
 * This function sets allmulti flags on the needed interfaces, and
 * tries to connect to the cp.
 *
 * Note that the fast path is the one to initiate the connection. It
 * must be called after sdsifd_nl_init (which sets iface->userdata).
 */
int sdsifd_fp_init(void)
{
	struct iface_list *ifaces;
	struct libif_iface *iface;
	struct sdsifd_interface_conf *ifconf;

	ifaces = libif_iface_get_allvr_list();
	LIST_FOREACH(iface, ifaces, next) {
		ifconf = iface->userdata;
		if (!ifconf)
			continue;

		if (ifconf->allmulti)
			sdsifd_nl_fp_if_set_allmulti(iface->name);
	}

	return sdsifd_fp_connect();
}
