#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <event.h>
#include <syslog.h>

/* librib includes */
#include "zebra.h"
#include "prefix.h"
#include "zclient.h"
#include "thread.h"

#include "hao_peer.h"
#include "haorouted_main.h"
#include "haorouted_protocol.h"
#include "haorouted_zebra.h"

#define HAO_ROUTED_RECONNECT_DELAY  10

static struct zclient* zclient = NULL;

/*
 * This timer is used to control the reconnection to zebrad.
 */
static struct timeval event_tv = { .tv_sec = HAO_ROUTED_RECONNECT_DELAY, .tv_usec = 0 };
static struct event event_reconnect;
static int    event_reconnecting = 0;

static int hao_routed_zebra_dump(int cmd, struct zclient* zclient, zebra_size_t len)
{
	switch (cmd) {
	case ZEBRA_DUMP_START:
		return hao_send_message(HAO_PEER_ALL, HAO_CMD_DUMP_START, 0, 0);
	case ZEBRA_DUMP_END:
		return hao_send_message(HAO_PEER_ALL, HAO_CMD_DUMP_END, 0, 0);
	default:
		ROUTED_LOG(LOG_ERR, "hao_routed_zebra_dump: wrong command");
		break;
	}
	return 0;
}

/* Messages from zebra to hao-routed */
/* 
 * Get the message from the zclient incoming buffer. The zebra header was already removed.
 */
static int hao_routed_zebra_get_route(int cmd, struct zclient* zclient, zebra_size_t len)
 {
	struct rib_buffer *s;
	struct route_message *message = (struct route_message*) malloc(sizeof(*message));
	uint8_t family;
	uint16_t msg_len;

	if (cmd == ZEBRA_IPV4_DYN_ROUTE_ADD || cmd == ZEBRA_IPV4_DYN_ROUTE_DELETE) {
		family = AF_INET;
	}

#ifdef HAVE_IPV6
	if (cmd == ZEBRA_IPV6_DYN_ROUTE_ADD || cmd == ZEBRA_IPV6_DYN_ROUTE_DELETE) {
		family = AF_INET6;
	}
#endif /* HAVE_IPV6 */

	if (family != AF_INET6 && family != AF_INET) {
		ROUTED_LOG(LOG_ERR, "%s() - dropping %s message invalid family", __FUNCTION__, hao_routed_zcommand_name(cmd));
		free(message);
		return 0;
	}

	ROUTED_LOG(LOG_DEBUG, "%s() - processing %s message", __FUNCTION__, hao_routed_zcommand_name(cmd));

	s = zclient->ibuf;

	memset(message, 0, sizeof(struct route_message));

	/* Type, flags, message, command */
	READ_N_FILL_MSG_FIELD(HAO_ROUTED_TYPE, s, message);
	READ_N_FILL_MSG_FIELD(HAO_ROUTED_FLAGS, s, message);
	READ_N_FILL_MSG_FIELD(HAO_ROUTED_MESSAGE, s, message);
	FILL_MSG_FIELD(HAO_ROUTED_COMMAND, &(cmd), message);

	/* IP prefix */
	FILL_MSG_FIELD(HAO_ROUTED_FAMILY, &family, message);
	READ_N_FILL_MSG_FIELD(HAO_ROUTED_PREFIX_AND_LEN, s, message);

	/* Vrf_id and safi */
	READ_N_FILL_MSG_FIELD(HAO_ROUTED_VRF_ID, s, message);
	READ_N_FILL_MSG_FIELD(HAO_ROUTED_SAFI, s, message);

	/* Nexthop, ifindex, distance, metric. */
	/* We can have more than one nexthop */
	if (family == AF_INET) {
		if (IS_FLAG (message->message, ZAPI_MESSAGE_NEXTHOP)) {
			int i;
			READ_N_FILL_MSG_FIELD(HAO_ROUTED_NEXTHOP_NUM, s, message);
			for (i = 0; i < message->nexthop_num; i++) {
				READ_N_FILL_MSG_FIELD(HAO_ROUTED_NEXTHOPv4, s, message);
			}
		}

		/* We can have more than one ifindex */
		if (IS_FLAG (message->message, ZAPI_MESSAGE_IFINDEX)) {
			int i;
			READ_N_FILL_MSG_FIELD(HAO_ROUTED_IFINDEX_NUM, s, message);
			for (i = 0; i < message->ifindex_num; i++) {
				READ_N_FILL_MSG_FIELD(HAO_ROUTED_PORTUID, s, message);
			}
		}
	}
#ifdef HAVE_IPV6
	else {
		if (IS_FLAG (message->message, ZAPI_MESSAGE_NEXTHOP)) {
			int i;
			READ_N_FILL_MSG_FIELD(HAO_ROUTED_NEXTHOP_NUM, s, message);
			message->ifindex_num = 0;
			for (i = 0; i < message->nexthop_num; i++)
				READ_N_FILL_MSG_FIELD(HAO_ROUTED_NEXTHOPv6, s, message);
		}

		/* We have one ifindex for each nexthop */
		if (IS_FLAG (message->message, ZAPI_MESSAGE_IFINDEX)) {
			int i;
			READ_N_FILL_MSG_FIELD(HAO_ROUTED_IFINDEX_NUM, s, message);
			for (i = 0; i < message->ifindex_num; i++) 
				READ_N_FILL_MSG_FIELD(HAO_ROUTED_PORTUID, s, message);
		}
	}
#endif /* HAVE_IPV6 */

	if (IS_FLAG (message->message, ZAPI_MESSAGE_DISTANCE))
		READ_N_FILL_MSG_FIELD(HAO_ROUTED_DISTANCE, s, message);

	if (IS_FLAG (message->message, ZAPI_MESSAGE_METRIC))
		READ_N_FILL_MSG_FIELD(HAO_ROUTED_METRIC, s, message);

	msg_len = message->offset;
	message->offset = htons(message->offset);

	/* We got a new message from zebra, saying that a route was added or delete, advertise it */
	switch (cmd) {
	case ZEBRA_IPV4_DYN_ROUTE_ADD:
		hao_routed_protocol_send_new_message(HAO_PEER_ALL, (void*)message, msg_len + ROUTE_MESSAGE_HEADER_SIZE);
		break;
	case ZEBRA_IPV4_DYN_ROUTE_DELETE:
		hao_routed_protocol_send_del_message(HAO_PEER_ALL, (void*)message, msg_len + ROUTE_MESSAGE_HEADER_SIZE);
		break;
#ifdef HAVE_IPV6
	case ZEBRA_IPV6_DYN_ROUTE_ADD:
		hao_routed_protocol_send_new_message(HAO_PEER_ALL, (void*)message, msg_len + ROUTE_MESSAGE_HEADER_SIZE);
		break;
	case ZEBRA_IPV6_DYN_ROUTE_DELETE:
		hao_routed_protocol_send_del_message(HAO_PEER_ALL, (void*)message, msg_len + ROUTE_MESSAGE_HEADER_SIZE);
		break;
#endif /* HAVE_IPV6 */
	default:
		ROUTED_LOG(LOG_ERR, "%s(): unknown command %d", __FUNCTION__, cmd);
		break;
	}

	/* The message was copied by libhao, we can free it here */
	free(message);

	return 0;
}

/* Messages from hao-routed to zebra  */
/* Send a add or delete route message to zebra. Work for v4 and v6 routes. */
void hao_routed_zebra_process_route(uint8_t command, void *p, void *api)
{
	ROUTED_LOG(LOG_DEBUG, "%s()", __FUNCTION__);

	switch (command) {
	case ZEBRA_IPV4_DYN_ROUTE_ADD:
		zapi_ipv4_route(command, zclient, (struct prefix_ipv4 *)p, (struct zapi_ipv4 *)api);
		break;
	case ZEBRA_IPV4_DYN_ROUTE_DELETE:
		/* 
		 * Zebra cannot manage more than one nexthop and one ifindex in a api message, 
		 * we have to send one message for each.
		 */
		{
			struct zapi_ipv4 *zapi = (struct zapi_ipv4 *)api;
			struct in_addr** nexthop = zapi->nexthop;
			unsigned int* ifuid = zapi->ifindex;
			uint8_t nexthop_num = zapi->nexthop_num;
			uint8_t ifindex_num = zapi->ifindex_num;
			int i;
			
			/* In v4, we send the nexthops and ifindexes one after another */
			for (i = 0 ; i < nexthop_num ; i++) {
				zapi->nexthop_num = 1;
				zapi->nexthop = &nexthop[i];
				zapi->ifindex_num = 0;
				zapi->ifindex = NULL;
				zapi_ipv4_route(command, zclient, (struct prefix_ipv4 *)p, zapi);
			}
			for (i = 0 ; i < ifindex_num ; i++) {
				zapi->nexthop_num = 0;
				zapi->nexthop = NULL;
				zapi->ifindex_num = 1;
				zapi->ifindex = &ifuid[i];
				zapi_ipv4_route(command, zclient, (struct prefix_ipv4 *)p, zapi);
			}

			zapi->nexthop_num = nexthop_num;
			zapi->ifindex_num = ifindex_num;
			zapi->nexthop = nexthop;
			zapi->ifindex = ifuid;
		}
		break;

#ifdef HAVE_IPV6
	case ZEBRA_IPV6_DYN_ROUTE_ADD:
		zapi_ipv6_route(command, zclient, (struct prefix_ipv6 *)p, (struct zapi_ipv6 *)api);
		break;
	case ZEBRA_IPV6_DYN_ROUTE_DELETE:
		/* 
		 * Zebra cannot manage more than one nexthop and one ifindex in a api message, 
		 * we have to send one message for each.
		 */
		{
			struct zapi_ipv6 *zapi = (struct zapi_ipv6 *)api;
			struct in6_addr** nexthop = zapi->nexthop;
			unsigned int* ifuid = zapi->ifindex;
			uint8_t nexthop_num = zapi->nexthop_num;
			uint8_t ifindex_num = zapi->ifindex_num;
			int i;

			/* 
			 * In v6, we send couples (nexthop, ifindex), 
			 * and then the remaining nexthops or ifindexes if any 
			 * We assume that nexthop_num = ifindex_num.
			 */
			for (i = 0 ; i < nexthop_num ; i++) {
				zapi->nexthop_num = 1;
				zapi->nexthop = &nexthop[i];
				zapi->ifindex_num = 1;
				zapi->ifindex = &ifuid[i];
				zapi_ipv6_route(command, zclient, (struct prefix_ipv6 *)p, zapi);
			}

			zapi->nexthop_num = nexthop_num;
			zapi->ifindex_num = ifindex_num;
			zapi->nexthop = nexthop;
			zapi->ifindex = ifuid;
		}
		break;
#endif /* HAVE_IPV6 */

	default:
		ROUTED_LOG(LOG_ERR, "%s(): unknown command %d", __FUNCTION__, command);
		break;
	}
}

/* 
 * Ask zebra to redistribute ZEBRA_ROUTE_DYN type routes.
 * Used to get a dump of all routes when a new peer connects to us
 */
void hao_routed_zebra_redistribute()
{
	int res = -1;
	if (zclient->sock >= 0) {
		ROUTED_LOG(LOG_DEBUG, "%s(): sending redistribution requests for dynamic routes", __FUNCTION__);
		res= rib_zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zclient->sock, ZEBRA_ROUTE_DYN);
	} 
	if (res < 0) {
		ROUTED_LOG(LOG_ERR, "%s(): fail to send redistribution message(zclient->sock=%d).",
			__FUNCTION__, zclient->sock);
	}
}

/* 
 * Get the message when connecting to zebra successfully.
 */
static int hao_routed_zebra_connection_achieved(struct zclient* zclient)
{
	event_reconnecting = 0;

	/* Re-register the redistribution */
	hao_routed_zebra_redistribute ();

	/* Send a message to peers to obtain all the routes */
	hao_send_message (HAO_PEER_ALL, HAO_CMD_OBJ_DUMP, NULL, 0);

	return 0;
}


/* 
 * Callback function of the reconnecting timer.
 */
static void hao_routed_zebra_connection_retry(int dummyfd, short event, void *data)
{
	/* Restart the zclient */
	zclient_stop(zclient);
	switch (zclient_start(zclient)) {
		case -1:
			ROUTED_LOG(LOG_DEBUG, "%s(): did not reconnect to fib manager", __FUNCTION__);
			break;
		case 1:
			ROUTED_LOG(LOG_DEBUG, "%s(): already connected to fib manager ?", __FUNCTION__);
		case 0:
			evtimer_del(&event_reconnect);

			ROUTED_LOG(LOG_INFO, "%s(): connected to fib manager", __FUNCTION__);
			/* Listen on zebra socket */
			zclient_listen(zclient);
			break;
		default:
			ROUTED_LOG(LOG_ERR, "%s(): zclient_start unknown err code", __FUNCTION__);
	}
}

/* 
 * Get the message when connection to zebra is broken.
 */
static int hao_routed_zebra_schedule_reconnect(struct zclient* zclient)
{
    if (event_reconnecting++ == 0) {
		/* Send a message to all peers */
		ROUTED_LOG(LOG_INFO, "%s(): initiate graceful restart with peers", __FUNCTION__);
		hao_send_message (HAO_PEER_ALL, HAO_CMD_GRACE_START, NULL, 0);
	}

	/* Start a timer to try the reconnection for every HAO_ROUTED_RECONNECT_DELAY seconds */
	ROUTED_LOG(LOG_INFO, "%s(): waiting to reconnect to fib manager", __FUNCTION__);
	if (evtimer_add(&event_reconnect, &event_tv)) {
		ROUTED_LOG(LOG_ERR, "%s(): evtimer_add failed", __FUNCTION__);
		return -1;
	}

	return 0;
}

/* 
 * Send a message to zebra about the restarting of the peer zebrad.
 * Zebra will set the lifetime for the hao-routed routes on receiving
 * this message.
 */
int hao_routed_peer_zebra_restart()
{
	return zapi_send_command(ZEBRA_GRACE_RESTART, zclient);
}

/* Init zebra */
void hao_routed_zebra_init()
{
	ROUTED_LOG(LOG_DEBUG, "%s()", __FUNCTION__);
	/* Allocate zebra structure. */
	zclient = zclient_new();
	/* Register callback functions to read message sent by zebra */
 	zclient->ipv4_route_add = hao_routed_zebra_get_route;
 	zclient->ipv4_route_delete = hao_routed_zebra_get_route;
#ifdef HAVE_IPV6
 	zclient->ipv6_route_add = hao_routed_zebra_get_route;
 	zclient->ipv6_route_delete = hao_routed_zebra_get_route;
#endif /* HAVE_IPV6 */
	zclient->dump_start = hao_routed_zebra_dump;
	zclient->dump_end = hao_routed_zebra_dump;

 	zclient->zclient_connection_achieved = hao_routed_zebra_connection_achieved;
 	zclient->zclient_schedule_reconnect = hao_routed_zebra_schedule_reconnect;
 	evtimer_set(&event_reconnect, hao_routed_zebra_connection_retry, zclient);

	/* Connect to zebra */
	zclient_init(zclient, ZEBRA_ROUTE_DYN);
	if (zclient_start(zclient) < 0) {
		ROUTED_LOG(LOG_INFO, "%s(): not connected to fib manager, reconnect in progress", __FUNCTION__);
		return;
	}

	/* Listen on zebra socket */
	zclient_listen(zclient);
}
