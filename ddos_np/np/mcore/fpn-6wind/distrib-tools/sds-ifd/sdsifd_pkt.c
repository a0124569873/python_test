/*
 * Copyright 2013 6WIND S.A.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>

#include <syslog.h>
#include <event.h>

#include "sock.h"
#include "stream.h"

#include "sdsifd_conf.h"
#include "sdsifd_pkt.h"

#define IFD_LOG(prio, fmt, args...) \
do { \
	syslog((prio), "%s: " fmt "\n", __func__, ##args);	\
} while (0)

/* fills buf with a format output of the message stored in data */
void sdsifd_pkt_log_msg(uint8_t command, void *data, char *buf, size_t buflen)
{
	switch (command) {
	case SDSIFD_CP_PEER_MSG:
		snprintf(buf, buflen, "CP_PEER_MSG");
		break;

	case SDSIFD_FP_PEER_MSG:
		snprintf(buf, buflen, "FP_PEER_MSG");
		break;

	case SDSIFD_CP_IF_MSG:
		{
		struct sdsifd_cp_if_msg *ifmsg = (struct sdsifd_cp_if_msg *)(data);

		snprintf(buf, buflen, "CP_IF_MSG   <%s> %s",
			ifmsg->name,
			ifmsg->up ? "<up>" : "<down>");
		}
		break;

	case SDSIFD_FP_IF_MSG:
		{
		struct sdsifd_fp_if_msg *ifmsg = (struct sdsifd_fp_if_msg *)(data);

		snprintf(buf, buflen, "FP_IF_MSG   <%s> [%02x:%02x:%02x:%02x:%02x:%02x] mtu=%d %s %s",
			ifmsg->name,
			ifmsg->mac[0], ifmsg->mac[1], ifmsg->mac[2],
			ifmsg->mac[3], ifmsg->mac[4], ifmsg->mac[5],
			ntohl(ifmsg->mtu),
			ifmsg->running ? "<running>" : "",
			ifmsg->fpib ? "<fpib>" : "");
		}
		break;

	default:
		snprintf(buf, buflen, "Unknown msg(%d)", command);
		break;
	}
}

/* sends a message to a peer, given its stream */
int sdsifd_send_message(uint8_t command, void *data,
			uint32_t data_len, struct stream *peer_stream,
			int peer_id)
{
	struct stream_msg msgdata;
	struct iovec iov[2];
	size_t iovlen = 0;
	int ret;
	char buf[512];

	sdsifd_pkt_log_msg(command, data, buf, sizeof(buf));
	if (sdsifd_mode == CP_MODE)
		IFD_LOG(LOG_DEBUG, " TX FP%d  %s", peer_id, buf);
	else {
		/* This is the case for SDSIFD_FP_PEER_MSG */
		if (peer_id == 0)
			IFD_LOG(LOG_DEBUG, " TX CP  %s", buf);
		else
			IFD_LOG(LOG_DEBUG, " TX CP%d  %s", peer_id, buf);
	}

	msgdata.msg_type = htons(command);
	msgdata.msg_id = htons(sdsifd_local_peer_id);
	msgdata.msg_len = htonl(data_len);

	iov[iovlen].iov_base = &msgdata;
	iov[iovlen].iov_len   = sizeof(msgdata);
	iovlen++;

	if (data && data_len) {
		iov[iovlen].iov_base  = data;
		iov[iovlen].iov_len   = data_len;
		iovlen++;
	}

	if (peer_stream->stream_state != STREAM_CONNECTED) {
		IFD_LOG(LOG_NOTICE, "can't send message while not connected");
		return -1;
	}

	ret = stream_post_iov(peer_stream, iov, iovlen);
	/* XXX: stats */
	/* if (ret == sizeof(struct stream_msg) + data_len) */
	/* 	HAO_PEER_STATS_INC(peer, cmd_tx_ok, command); */
	/* else */
	/* 	HAO_PEER_STATS_INC(peer, cmd_tx_fail, command); */

	if (ret < 0) {
		IFD_LOG(LOG_NOTICE, "could not send message, disconnecting");
		return -1;
	}

	return ret;
}
