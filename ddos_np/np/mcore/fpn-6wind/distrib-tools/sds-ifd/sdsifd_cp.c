/*
 * Copyright 2013 6WIND S.A.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <syslog.h>
#include <event.h>
#include <libconsole.h>
#include <linux/if.h>

#include "sock.h"
#include "stream.h"

#include "sdsifd_conf.h"
#include "sdsifd_pkt.h"
#include <libif.h>

struct event listen_ev;

/* we can have several peers, stored in this list */
SLIST_HEAD(speer_list, sdsifd_peer) sdsifd_peer_list;

int sdsifd_cp_tx_interface(struct libif_iface *iface);
int sdsifd_nl_cp_if_set_dormant(const char *ifname);
int sdsifd_nl_cp_if_set_operstate(const char *ifname, uint8_t operstate);

/* libconsole functions */
/* show network informations about the peers */
void command_show_cp_stream(int s, struct stream *stream)
{
	command_printf(s, " fd=%d ", stream->stream_sock);
	if (stream->stream_state == STREAM_DISCONNECTED)
		command_printf(s, "state=disconnected");
	else {
		command_printf(s, "state=%s [%s:%d] ",
			       stream->stream_state == STREAM_CONNECTING ? "connecting":"connected",
			       sock_getaddr(&stream->stream_addr.sa),
			       sock_getport(&stream->stream_addr.sa));
	}
	command_printf(s, "\n");
}

/* show interface informations about thet peers */
void command_show_cp_peer(int s, __attribute__ ((unused)) char *dummy,
			  __attribute__ ((unused))void *evt)
{
	struct sdsifd_peer *peer;
	struct sdsifd_iface *iface;

	SLIST_FOREACH(peer, &sdsifd_peer_list, peer_next)
	{
		command_printf(s, "fp%d:\n", peer->id);
		if (peer->grace_time_seconds > 0)
			command_printf(s, " gracetime=%d\n", peer->grace_time_seconds);
		command_show_cp_stream(s, &peer->stream);
		command_printf(s, " interfaces: ");
		SLIST_FOREACH(iface, &peer->peer_iface_list, iface_next) {
			command_printf(s, "<%s> ", iface->name);
		}
		command_printf(s, "\n");
	}
}

/*
 * find an interface by its name
 *
 * We have to look in each peer interface list.
 */
struct sdsifd_iface *sdsifd_cp_iface_lookup_by_name(char *name)
{
	struct sdsifd_peer *peer;
	struct sdsifd_iface *iface;

	SLIST_FOREACH(peer, &sdsifd_peer_list, peer_next)
	{
		SLIST_FOREACH(iface, &peer->peer_iface_list, iface_next) {
			if (strcmp(iface->name, name))
				continue;

			return iface;
		}
	}
	return NULL;
}

/*
 * put sdsifd_iface in libif userdata for further use.
 *
 * We also use it to know, when we get a libif_iface, if we should
 * take care of it (!iface->userdata means filter).
 */
void sdsifd_cp_set_libif_userdata(struct libif_iface *iface)
{
	if (!iface->userdata)
		iface->userdata = (void *) sdsifd_cp_iface_lookup_by_name(iface->name);
}

/*
 * add a new rfpvi interface
 *
 * we write the proper command into the /proc/sys/rfpvi/add_interface.
 * The rfpvi interface is set dormant if it was successfully reated.
 */
static int sdsifd_cp_rfpvi_add(const char *ifname, const uint8_t *mac,
			       int mtu, int peer, int fpib)
{
	int fd;
	static const char procfile[] = "/proc/sys/rfpvi/add_interface";
	int errval = 0;
	char command[512];

	fd = open(procfile, O_WRONLY, 0);
	if (fd < 0) {
		errval = errno;
		IFD_LOG(LOG_ERR, "cannot write to %s: %s\n",
			procfile, strerror(errval));
		return errval;
	}

	snprintf(command, sizeof(command), "%s flags=%x mac=%x:%x:%x:%x:%x:%x mtu=%d blade=%d cpblade=%d",
		 ifname, fpib ? IFF_UP : 0,
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
		 mtu, peer, sdsifd_local_peer_id);
	IFD_LOG(LOG_DEBUG, "%s > %s\n", command, procfile);

	if (write(fd, command, strlen(command)) < 0) {
		errval = errno;
		if (errval == EEXIST) {
			IFD_LOG(LOG_WARNING, "interface %s already exists\n",
				ifname);
		} else {
			IFD_LOG(LOG_ERR, "cannot create interface %s: %s\n",
				ifname, strerror(errval));
		}
	}
	close(fd);

	if (!errval)
		sdsifd_nl_cp_if_set_dormant(ifname);

	return errval;
}

/*
 * delete a new rfpvi interface
 *
 * we write the proper command into the /proc/sys/rfpvi/del_interface.
 */
static int sdsifd_cp_rfpvi_del(const char *ifname)
{
	int fd;
	static const char procfile[] = "/proc/sys/rfpvi/del_interface";
	int errval = 0;
	char command[512];

	fd = open(procfile, O_WRONLY, 0);
	if (fd < 0) {
		errval = errno;
		IFD_LOG(LOG_ERR, "cannot write to %s: %s\n",
			procfile, strerror(errval));
		return errval;
	}

	snprintf(command, sizeof(command), "%s", ifname);
	IFD_LOG(LOG_DEBUG, "%s > %s\n", command, procfile);

	if (write(fd, command, strlen(command)) < 0) {
		errval = errno;
		if (errval)
			IFD_LOG(LOG_ERR, "cannot delete interface %s: %s\n",
				ifname, strerror(errval));
	}
	close(fd);

	return errval;
}

/* peer management functions */
/* add a peer */
static void sdsifd_cp_peer_add(struct sdsifd_peer *peer)
{
	if (peer->id) {
		/* unset gracetime on this peer */
		if (peer->grace_time_seconds)
			peer->grace_time_seconds = 0;

		IFD_LOG(LOG_INFO, "<> FP%d reconnected", peer->id);
	} else
		IFD_LOG(LOG_INFO, "<> FP  connected");
}

/* 
 * delete a peer
 *
 * also, delete its fpib interface (fpib interface is the proof that
 * we manage the peer in HA mode), and set a gracetime to remove
 * running flags from the interface of this peer.
 */
static void sdsifd_cp_peer_del(struct sdsifd_peer *peer)
{
	struct sdsifd_iface *iface;
	struct libif_iface *libif_iface;

	IFD_LOG(LOG_INFO, "== FP%d  disconnected, start GR %ds",
		peer->id, sdsifd_gracetime);

	stream_close(&peer->stream);
	peer->grace_time_seconds = sdsifd_gracetime;

	/* safe because we return after deletion */
	SLIST_FOREACH(iface, &peer->peer_iface_list, iface_next) {
		if (!iface->fpib)
			continue;

		IFD_LOG(LOG_INFO, "== FP%d  removing fpib %s\n",
			peer->id, iface->name);

		SLIST_REMOVE(&peer->peer_iface_list, iface,
			     sdsifd_iface, iface_next);

		sdsifd_cp_rfpvi_del(iface->name);

		libif_iface = libif_iface_lookup_allvr(iface->name);
		if (libif_iface)
			libif_iface->userdata = NULL;

		free(iface);
		return;
	}
}

/*
 * allocate a new peer
 *
 * we don't check if it was already here, so callers must take care of
 * it.
 */
struct sdsifd_peer *sdsifd_peer_add(void)
{
	struct sdsifd_peer *peer = malloc(sizeof(*peer));
	if (peer == NULL) {
		IFD_LOG(LOG_CRIT, "OOM\n");
		return NULL;
	}

	memset(peer, 0, sizeof(*peer));

	SLIST_INSERT_HEAD(&sdsifd_peer_list, peer, peer_next);
	return peer;
}

/*
 * lookup a peer using his libstream address
 */
struct sdsifd_peer *sdsifd_cp_peer_lookup_by_addr(sock_addr_t *addr)
{
	struct sdsifd_peer *peer;

	SLIST_FOREACH(peer, &sdsifd_peer_list, peer_next) {
		if (peer->addr.sa.sa_family != addr->sa.sa_family)
			continue;
		switch (peer->addr.sa.sa_family) {
		case AF_INET:
			if (peer->addr.sin.sin_addr.s_addr == addr->sin.sin_addr.s_addr)
				return peer;
			break;
		case AF_INET6:
			if (memcmp(&peer->addr.sin6.sin6_addr, &addr->sin6.sin6_addr,
				   sizeof(addr->sin6.sin6_addr)) == 0)
				return peer;
			break;
		default:
			syslog (LOG_ERR, "%s: invalid family %d", __FUNCTION__, peer->addr.sa.sa_family);
		}
	}
	return NULL;
}



/* sdsifd_iface management */
/*
 * allocate an new interface
 *
 * we don't check if it was already here, so callers must take care of
 * it.
 */
static struct sdsifd_iface *sdsifd_iface_add(const char *name, struct sdsifd_peer *peer, int fpib)
{
	struct sdsifd_iface *iface = malloc(sizeof(*iface));
	if (iface == NULL) {
		IFD_LOG(LOG_CRIT, "OOM\n");
		return NULL;
	}

	memset(iface, 0, sizeof(*iface));

	snprintf(iface->name, sizeof(iface->name), "%s", name);
	iface->peer = peer;
	iface->fpib = fpib;
	SLIST_INSERT_HEAD(&peer->peer_iface_list, iface, iface_next);

	return iface;
}

/*
 * libstream callback, called on a message reception
 *
 * 'code' is sent by libstream, in case there was a problem.
 *
 * If we receive:
 *  - SDSIFD_FP_PEER_MSG, we reply with SDSIFD_CP_PEER_MSG, and send
 *    an update of the up flag of this peer interfaces if needed
 * - SDSIFD_FP_IF_MSG, if the interface was not present, we add it,
 *   then we update the running flag
 */
static void sdsifd_cp_rxdata_cb(void *data, struct stream_msg *msg, int code)
{
	struct sdsifd_peer *peer = (struct sdsifd_peer *)data;
	struct sdsifd_iface *iface;
	uint8_t command;
	uint8_t id;
	char buf[512];

	if (code < 0) {
		IFD_LOG(LOG_WARNING, "%s", strerror(errno));
		sdsifd_cp_peer_del(peer);
		return;
	} else if (code == 0) {
		IFD_LOG(LOG_WARNING, "connection closed");
		sdsifd_cp_peer_del(peer);
		return;
	}

	command = ntohs(msg->msg_type);
	id = ntohs(msg->msg_id);

	if (peer->id == 0)
		peer->id = id;
	else {
		if (peer->id != id) {
			IFD_LOG(LOG_INFO, "peer %d came back with different id %d, updating\n",
				peer->id, id);
		}

		peer->id = id;
	}

	sdsifd_pkt_log_msg(command, (msg + 1), buf, sizeof(buf));
	IFD_LOG(LOG_DEBUG, " RX FP%d  %s", id, buf);

	/* parse msg */
	switch (command) {

	/* new fastpath peer message */
	case SDSIFD_FP_PEER_MSG:
		sdsifd_send_message(SDSIFD_CP_PEER_MSG, NULL, 0, &peer->stream,
				    peer->id);

		if (peer->id != id) {
			IFD_LOG(LOG_INFO, "peer %d came back with different id %d, updating\n",
				peer->id, id);
		}

		/* the peer existed already, send interfaces */
		SLIST_FOREACH(iface, &peer->peer_iface_list, iface_next) {
			struct libif_iface *libif_iface;

			libif_iface = libif_iface_lookup_allvr(iface->name);
			if (libif_iface && libif_iface->userdata)
				sdsifd_cp_tx_interface(libif_iface);
		}
		break;

	case SDSIFD_FP_IF_MSG:
		{
			struct sdsifd_fp_if_msg *ifmsg = (struct sdsifd_fp_if_msg *)(msg + 1);

			if (ntohs(ifmsg->version) != SDSIFD_PROTOCOL_VERSION) {
				IFD_LOG(LOG_WARNING, "different version: ours %d peer %d",
					SDSIFD_PROTOCOL_VERSION, ntohs(ifmsg->version));
				return;
			}

			iface = sdsifd_cp_iface_lookup_by_name(ifmsg->name);
			if (iface == NULL || ifmsg->fpib) {
				sdsifd_iface_add(ifmsg->name, peer, ifmsg->fpib);
				sdsifd_cp_rfpvi_add(ifmsg->name, ifmsg->mac, ntohl(ifmsg->mtu),
						    id, ifmsg->fpib);
			}
			sdsifd_nl_cp_if_set_operstate(ifmsg->name, ifmsg->running ? IF_OPER_UP : IF_OPER_DORMANT);
		}
		break;
	default:
		break;
	}
}

/*
 * common socket/tcp options
 */
static int sdsifd_cp_common_setsockopt(int fd)
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
 * accept callback function
 *
 * we check if the peer was already know, else allocate it. We init
 * the libstream for this peer.
 */
static void sdsifd_cp_accept_cb(int fd, short event, void *data)
{
	sock_addr_t addr;
	socklen_t addrlen = sizeof(struct sockaddr);
	struct sdsifd_peer *peer;
	int sock;

	sock = accept(fd, &addr.sa, &addrlen);
	if (sock < 0) {
		IFD_LOG(LOG_DEBUG, "accept: %s", strerror(errno));
		return;
	}
	IFD_LOG(LOG_NOTICE, "accepting connection from [%s:%d]",
		sock_getaddr(&addr.sa), sock_getport(&addr.sa));

	/* XXX: check error */
	sock_nonblock(sock);
	sdsifd_cp_common_setsockopt(sock);

	peer = sdsifd_cp_peer_lookup_by_addr(&addr);
	if (!peer) {
		peer = sdsifd_peer_add();
		memcpy(&peer->addr, &addr, addrlen);
	} else {
		/*
		 * On CP side, whenever a new connection is established, the old
		 * stream should be closed to avoid the pending event in the old
		 * fd entering a dead loop
		 */
		stream_close(&peer->stream);
	}
	stream_init(&peer->stream, 0, 0);

	if (stream_setup(&peer->stream, sock, &addr.sa,
			 sdsifd_cp_rxdata_cb, peer)) {
		IFD_LOG(LOG_ERR, "stream setup failed");
		close(sock);
		return;
	}

	sdsifd_cp_peer_add(peer);
}

/*
 * prepare an interface message and send it.
 *
 * Callers of this function must take care that iface->userdata is not NULL.
 */
int sdsifd_cp_tx_interface(struct libif_iface *iface)
{
	struct sdsifd_cp_if_msg data;
	struct sdsifd_iface *sdsifd_iface = NULL;

	snprintf(data.name, sizeof(data.name), "%s", iface->name);
	data.version = htons(SDSIFD_PROTOCOL_VERSION);
	data.up = (iface->flags & IFF_UP) ? 1 : 0;

	sdsifd_iface = (struct sdsifd_iface *)iface->userdata;

	return sdsifd_send_message(SDSIFD_CP_IF_MSG, &data, sizeof(data),
				   &sdsifd_iface->peer->stream,
				   sdsifd_iface->peer->id);
}


/* graceful restart management */
/* graceful restart event */
static struct event ev_gr;

/*
 * sdsifd graceful restart callback
 *
 * When a peer is deleted, we don't touch its interface apart from the
 * fpib right away. We set a gracetime on the peer. When the gracetime
 * reaches 0, we remove the running flag from all its interfaces.
 */
static void sdsifd_gr_cb(int fd, short ev_type, void *arg)
{
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	struct sdsifd_peer *peer;
	struct sdsifd_iface *iface;

	SLIST_FOREACH(peer, &sdsifd_peer_list, peer_next) {
		if (peer->grace_time_seconds > 0) {
			peer->grace_time_seconds--;

			if (peer->grace_time_seconds == 0) {
				SLIST_FOREACH(iface, &peer->peer_iface_list, iface_next) {
					sdsifd_nl_cp_if_set_operstate(iface->name, IF_OPER_DORMANT);
				}
			}
		}
	}

	/* reload timer */
	evtimer_add(&ev_gr, &tv);
}

/*
 * This function initializes the libstream server and the graceful
 * restart event.
 *
 * Note that it is the fast path that initiates the connections.
 */
int sdsifd_cp_init(void)
{
	int sock;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	int ret;
	int val = 1;
	sock_addr_t addr;

	sock = socket(AF_INET, SOCK_STREAM, 0);

	/* bind on the bladepeer interface */
	if (strlen(sdsifd_bind_bladepeer) != 0) {
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, sdsifd_bind_bladepeer, strlen(sdsifd_bind_bladepeer))) {
			IFD_LOG(LOG_ERR, "%s: cannot set bindtodevice option: %s\n",__FUNCTION__, strerror(errno));
			close (sock);
			return -1;
		}
	} else {
		IFD_LOG(LOG_WARNING, "%s: bind_bladepeer not found, accepting connection from any interface\n", __FUNCTION__);
	}

	memset(&addr, 0, sizeof(addr));

	addr.sin.sin_family = AF_INET;
	if (sdsifd_cp_address)
		inet_pton(AF_INET, sdsifd_cp_address, &addr.sin.sin_addr);
	addr.sin.sin_port   = htons(sdsifd_cp_port);

	/* set reuse addr option, to avoid bind error when re-starting */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
		IFD_LOG(LOG_ERR, "cannot set reuseaddr option: %s", strerror(errno));
		return -1;
	}

	/* load a timer triggered every second */
	evtimer_set(&ev_gr, sdsifd_gr_cb, NULL);
	evtimer_add(&ev_gr, &tv);

	ret = bind(sock, &addr.sa, sock_getlen(&addr.sa));
	if (ret < 0) {
		IFD_LOG(LOG_INFO, "bind %s %u: %s", sock_getaddr(&addr.sa),
			(unsigned)sock_getport(&addr.sa), strerror(errno));
		return 0;
	}

	ret = listen(sock, 16 /* MAX FPID */);
	if (ret < 0) {
		IFD_LOG(LOG_ERR, "listen: %s", strerror(errno));
		return 0;
	}

	event_set(&listen_ev, sock, EV_READ | EV_PERSIST,
		  sdsifd_cp_accept_cb, NULL);

	if (event_add(&listen_ev, NULL))
		IFD_LOG(LOG_ERR, "event_add listen_ev: %s", strerror(errno));

	return ret;
}
