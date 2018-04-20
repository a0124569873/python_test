#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <event.h>

#include "zebra.h"
#include "prefix.h"
#include "zclient.h"

#include "hao_peer.h"

#include "haorouted_main.h"
#include "haorouted_protocol.h"
#include "haorouted_zebra.h"

#define _PF(f) case f: str = #f ; break;
static void hao_routed_protocol_dump_value(enum hao_routed_commands cmd, void* data, int size, struct route_message* message);

/* Dump function for zebra commands */
const char *
hao_routed_zcommand_name(int cmd)
{
	char *str="unknown";

	switch(cmd) {
		_PF(ZEBRA_INTERFACE_ADD)
		_PF(ZEBRA_INTERFACE_DELETE)
		_PF(ZEBRA_INTERFACE_ADDRESS_ADD)
		_PF(ZEBRA_INTERFACE_ADDRESS_DELETE)
		_PF(ZEBRA_INTERFACE_UP)
		_PF(ZEBRA_INTERFACE_DOWN)
		_PF(ZEBRA_IPV4_ROUTE_ADD)
		_PF(ZEBRA_IPV4_ROUTE_DELETE)
		_PF(ZEBRA_IPV6_ROUTE_ADD)
		_PF(ZEBRA_IPV6_ROUTE_DELETE)
		_PF(ZEBRA_REDISTRIBUTE_ADD)
		_PF(ZEBRA_REDISTRIBUTE_DEFAULT_ADD)
		_PF(ZEBRA_IPV4_DYN_ROUTE_ADD)
		_PF(ZEBRA_IPV4_DYN_ROUTE_DELETE)
		_PF(ZEBRA_IPV6_DYN_ROUTE_ADD)
		_PF(ZEBRA_IPV6_DYN_ROUTE_DELETE)
		default:
			break;
	}

	return str;
}

/* Dump function for hao_routed value types */
static const char *
hao_routed_command_name(enum hao_routed_commands cmd)
{
	char *str="unknown";

	switch(cmd) {
		_PF(HAO_ROUTED_NEXTHOPv4)
		_PF(HAO_ROUTED_NEXTHOPv6)
		_PF(HAO_ROUTED_PORTUID)
		_PF(HAO_ROUTED_PREFIX)
		_PF(HAO_ROUTED_METRIC)
		_PF(HAO_ROUTED_VRF_ID)
		_PF(HAO_ROUTED_SAFI)
		_PF(HAO_ROUTED_FLAGS)
		_PF(HAO_ROUTED_COMMAND)
		_PF(HAO_ROUTED_DISTANCE)
		_PF(HAO_ROUTED_FAMILY)
		_PF(HAO_ROUTED_TYPE)
		_PF(HAO_ROUTED_MESSAGE)
		_PF(HAO_ROUTED_PREFIXLEN)
		_PF(HAO_ROUTED_PREFIX_AND_LEN)
		_PF(HAO_ROUTED_IFINDEX_NUM)
		_PF(HAO_ROUTED_NEXTHOP_NUM)
                default:
			break;
	}

	return str;
}

/* Add type/length/value to the route_message data buffer */
void hao_routed_protocol_route_msg_add_data(enum hao_routed_commands cmd, void* data, struct route_message *message, uint8_t size)
{
	/* TODO: need smthg to avoid going out of the buffer */
	message->data[message->offset++] = cmd;
	message->data[message->offset++] = size;
	memcpy((message->data + message->offset), data, size);
	message->offset += size;
}

/* Fill a route_message with either a value, or read the value from a rib_buffer */
/* This function is not used directly, we use FILL_MSG_FIELD and READ_N_FILL_MSG_FIELD instead */
void hao_routed_protocol_route_msg_fill_field(enum hao_routed_commands cmd, struct rib_buffer *s, void* value, struct route_message *message)
{
	switch (cmd) {
		
	case HAO_ROUTED_TYPE:
		message->type = rib_buffer_getc(s);
		hao_routed_protocol_dump_value(cmd, NULL, 0, message);
		break;
	case HAO_ROUTED_FLAGS:
		message->flags = htons(rib_buffer_getw(s));
		hao_routed_protocol_dump_value(cmd, NULL, 0, message);
		break;
	case HAO_ROUTED_MESSAGE:
		message->message = rib_buffer_getc(s);
		hao_routed_protocol_dump_value(cmd, NULL, 0, message);
		break;
	case HAO_ROUTED_COMMAND:
		message->command = htonl(*((uint32_t*) value));
		hao_routed_protocol_dump_value(cmd, NULL, 0, message);
		break;
	case HAO_ROUTED_FAMILY:
		message->family = *((uint8_t*)value);
		hao_routed_protocol_dump_value(cmd, NULL, 0, message);
		break;
	case HAO_ROUTED_NEXTHOP_NUM:
		message->nexthop_num = rib_buffer_getc(s);
		hao_routed_protocol_dump_value(cmd, NULL, 0, message);
		break;
	case HAO_ROUTED_IFINDEX_NUM:
		message->ifindex_num += rib_buffer_getc(s);
		hao_routed_protocol_dump_value(cmd, NULL, 0, message);
		break;

	case HAO_ROUTED_PREFIX_AND_LEN:
		{
			uint32_t prefix[4];
			uint8_t prefixlen = rib_buffer_getc(s);

			memset(prefix, 0, sizeof(prefix));
			rib_buffer_get(prefix, s, PSIZE(prefixlen));
			hao_routed_protocol_route_msg_add_data(HAO_ROUTED_PREFIXLEN, &prefixlen,
							       message, sizeof(prefixlen));
			hao_routed_protocol_dump_value(HAO_ROUTED_PREFIXLEN, &prefixlen, sizeof(prefixlen), message);
			hao_routed_protocol_route_msg_add_data(HAO_ROUTED_PREFIX, &prefix,
							       message, sizeof(prefix));
			hao_routed_protocol_dump_value(HAO_ROUTED_PREFIX, &prefix, PSIZE(prefixlen), message);
		}
		break;

	case HAO_ROUTED_DISTANCE:
		{
			uint8_t read_value = rib_buffer_getc(s);

			hao_routed_protocol_route_msg_add_data(cmd, &read_value,
							       message, sizeof(uint8_t));
			hao_routed_protocol_dump_value(cmd, &read_value, sizeof(read_value), message);
		}
		break;

	case HAO_ROUTED_NEXTHOPv4:
		{
			struct in_addr nexthop;

			rib_buffer_get(&nexthop, s, 4);
			hao_routed_protocol_route_msg_add_data(cmd, &nexthop,
							       message, sizeof(struct in_addr));
			hao_routed_protocol_dump_value(cmd, &nexthop, sizeof(nexthop), message);
		}
		break;

	case HAO_ROUTED_NEXTHOPv6:
		{
			struct in6_addr nexthop;

			rib_buffer_get(&nexthop, s, 16);
			hao_routed_protocol_route_msg_add_data(cmd, &nexthop,
							       message, sizeof(struct in6_addr));
			hao_routed_protocol_dump_value(cmd, &nexthop, sizeof(nexthop), message);
		}
		break;

	case HAO_ROUTED_PORTUID:
		{
			/* Portuid is already in network order*/
			uint32_t read_value = rib_buffer_getl(s);

			hao_routed_protocol_route_msg_add_data(cmd, &read_value,
							       message, sizeof(uint32_t));
			hao_routed_protocol_dump_value(cmd, &read_value, sizeof(read_value), message);
		}
		break;

	case HAO_ROUTED_SAFI:
		{
			uint16_t read_value = htons(rib_buffer_getw(s));
			hao_routed_protocol_route_msg_add_data(cmd, &(read_value),
							       message, sizeof(uint16_t));
			hao_routed_protocol_dump_value(cmd, &read_value, sizeof(read_value), message);
		}
		break;

	case HAO_ROUTED_METRIC:
	case HAO_ROUTED_VRF_ID:
		{
			uint32_t read_value = htonl(rib_buffer_getl(s));

			hao_routed_protocol_route_msg_add_data(cmd, &read_value,
							       message, sizeof(uint32_t));
			hao_routed_protocol_dump_value(cmd, &read_value, sizeof(read_value), message);
		}
		break;

	default:
		break;
	}
}

/* Dump functions */
/* Dump value for one command */
static void hao_routed_protocol_dump_value(enum hao_routed_commands cmd, void* data, int size, struct route_message* message)
{
	switch (cmd) {
		
	case HAO_ROUTED_TYPE:		
		ROUTED_LOG(LOG_DEBUG, "%s(): %s -> 0x%02x\n", __FUNCTION__, hao_routed_command_name(cmd),
			message->type);
		break;
	case HAO_ROUTED_FLAGS:
		ROUTED_LOG(LOG_DEBUG, "%s(): %s -> %d\n", __FUNCTION__, hao_routed_command_name(cmd),
			htons(message->flags));
		break;
	case HAO_ROUTED_MESSAGE:
		ROUTED_LOG(LOG_DEBUG, "%s(): %s -> 0x%02x\n", __FUNCTION__, hao_routed_command_name(cmd),
			message->message);
		break;
	case HAO_ROUTED_COMMAND:
		ROUTED_LOG(LOG_DEBUG, "%s(): %s -> %s\n", __FUNCTION__, hao_routed_command_name(cmd),
			hao_routed_zcommand_name(ntohl(message->command)));
		break;
	case HAO_ROUTED_FAMILY:
		ROUTED_LOG(LOG_DEBUG, "%s(): %s -> 0x%02x\n", __FUNCTION__, hao_routed_command_name(cmd),
			message->family);
		break;

	case HAO_ROUTED_NEXTHOP_NUM:
		ROUTED_LOG(LOG_DEBUG, "%s(): %s -> %d\n", __FUNCTION__, hao_routed_command_name(cmd), 
			message->nexthop_num);
		break;

	case HAO_ROUTED_IFINDEX_NUM:
		ROUTED_LOG(LOG_DEBUG, "%s(): %s -> %d\n", __FUNCTION__, hao_routed_command_name(cmd), 
			message->ifindex_num);
		break;

	case HAO_ROUTED_DISTANCE:
	case HAO_ROUTED_PREFIXLEN:
		ROUTED_LOG(LOG_DEBUG, "%s(): %s -> %d\n", __FUNCTION__, hao_routed_command_name(cmd), 
			*((uint8_t*)data));
		break;

	case HAO_ROUTED_PREFIX:
		{
			uint32_t prefix[4];
			char addr_str[256];

			memset(&prefix, 0, sizeof(prefix));
			memcpy(&prefix, data, size);
			ROUTED_LOG(LOG_DEBUG, "%s(): %s -> %s\n", __FUNCTION__, hao_routed_command_name(cmd), 
				inet_ntop(message->family, &prefix, addr_str, sizeof(addr_str)));
		}
		break;

	case HAO_ROUTED_NEXTHOPv6:
	case HAO_ROUTED_NEXTHOPv4:
		{
			char addr_str[256];
			ROUTED_LOG(LOG_DEBUG, "%s(): %s -> %s\n", __FUNCTION__, hao_routed_command_name(cmd), 
				inet_ntop(message->family, (uint32_t*)data, addr_str, sizeof(addr_str)));
		}
		break;

	case HAO_ROUTED_PORTUID:
		ROUTED_LOG(LOG_DEBUG, "%s(): %s -> 0x%08x\n", __FUNCTION__, hao_routed_command_name(cmd), 
			ntohl(*((uint32_t*)data)));
		break;

	case HAO_ROUTED_SAFI:
		ROUTED_LOG(LOG_DEBUG, "%s(): %s -> 0x%04x\n", __FUNCTION__, hao_routed_command_name(cmd), 
			ntohs(*((uint16_t*)data)));
		break;

	case HAO_ROUTED_METRIC:
	case HAO_ROUTED_VRF_ID:
		ROUTED_LOG(LOG_DEBUG, "%s(): %s -> 0x%08x\n", __FUNCTION__, hao_routed_command_name(cmd), 
			ntohl(*((uint32_t*)data)));
		break;

	default:
		break;
	}	
}

/* Dump all the values in a route_message data buffer */
static void hao_routed_protocol_dump_route_msg_data(struct route_message* msg)
{
	uint16_t i = 0;
	void* data = msg->data;
	uint16_t offset = msg->offset;

	while (i < offset) {
		uint8_t cmd = *(uint8_t*)(data + i++);
		uint8_t size = *(uint8_t*)(data + i++);
		hao_routed_protocol_dump_value(cmd, data + i, size, msg);
		i += size;
	}
}


/* Dump a route message */
void hao_routed_protocol_dump_route_msg(struct route_message* msg)
{
	ROUTED_LOG(LOG_DEBUG, "%s()\n", __FUNCTION__);

	hao_routed_protocol_dump_value(HAO_ROUTED_TYPE, NULL, 0, msg);
	hao_routed_protocol_dump_value(HAO_ROUTED_FLAGS, NULL, 0, msg);
	hao_routed_protocol_dump_value(HAO_ROUTED_MESSAGE, NULL, 0, msg);
	hao_routed_protocol_dump_value(HAO_ROUTED_COMMAND, NULL, 0, msg);
	hao_routed_protocol_dump_value(HAO_ROUTED_FAMILY, NULL, 0, msg);
	hao_routed_protocol_dump_value(HAO_ROUTED_NEXTHOP_NUM, NULL, 0, msg);
	hao_routed_protocol_dump_value(HAO_ROUTED_IFINDEX_NUM, NULL, 0, msg);

	hao_routed_protocol_dump_route_msg_data(msg);
}

/* Message sending */
/* HAO_CMD_OBJ_NEW message */
int hao_routed_protocol_send_new_message(uint8_t peer_id, void* message, size_t len)
{
	ROUTED_LOG(LOG_DEBUG, "%s()\n", __FUNCTION__);

	return hao_send_message(peer_id, HAO_CMD_OBJ_NEW, message, len);
}

/* HAO_CMD_OBJ_DEL message */
int hao_routed_protocol_send_del_message(uint8_t peer_id, void* message, size_t len)
{
	ROUTED_LOG(LOG_DEBUG, "%s()\n", __FUNCTION__);

	return hao_send_message(peer_id, HAO_CMD_OBJ_DEL, message, len);
}

static int hao_routed_protocol_min(int a, int b)
{
	if (a <= b)
		return a;

	return b;
}

/* Message reception */
/* Get all the occurences of cmd in the route_message buffer, and put them in answer */
static void hao_routed_protocol_get_route_msg_data(enum hao_routed_commands cmd, void* answer,
						   struct route_message* msg, int max_size)
{
	int i = 0;
	void* data = msg->data;
	int offset = msg->offset;
	int answer_offset = 0;

	while (i < offset) {
		uint8_t current_cmd = *(uint8_t*)(data + i++);
		uint8_t current_size = *(uint8_t*)(data + i++);
		if (current_cmd == cmd) {
			memcpy(answer + answer_offset, data + i, 
			       hao_routed_protocol_min(current_size, max_size - answer_offset));
			answer_offset += current_size;
		}
		i += current_size;
	}
}

/* Message processing (DEL and NEW) */
static int hao_routed_protocol_recv_message(uint8_t peer_id, uint16_t size, void *data)
{
	ROUTED_LOG(LOG_DEBUG, "%s()\n", __FUNCTION__);

	struct route_message *message = (struct route_message *) data;

	message->offset = ntohs(message->offset);

	hao_routed_protocol_dump_route_msg(message);

	/* v4 part */
	if (message->family == AF_INET) {
		struct zapi_ipv4 api;
		struct prefix_ipv4 p;
		struct in_addr* nexthop = NULL;
		int command = ntohl(message->command);

		/* If we have no nexthop and no ifindex, get out */
		if ((message->ifindex_num + message->nexthop_num) == 0)
			goto end;

		memset(&api, 0, sizeof(api));
		memset(&p, 0, sizeof(p));

		/* Type, flags, message */
		api.type = message->type;
		api.flags = ntohs(message->flags);
		api.message = message->message;

		/* IPv4 prefix */
		p.family = AF_INET;
		hao_routed_protocol_get_route_msg_data(HAO_ROUTED_PREFIXLEN, &p.prefixlen, message, sizeof(p.prefixlen));
		hao_routed_protocol_get_route_msg_data(HAO_ROUTED_PREFIX, &p.prefix, message, sizeof(p.prefix));

		/* Vrf_id and safi */
		{
			uint16_t safi;
			hao_routed_protocol_get_route_msg_data(HAO_ROUTED_VRF_ID, &api.vrf_id, message, sizeof(api.vrf_id));
			api.vrf_id = ntohl(api.vrf_id);
			/* api.safi is a uint8_t, but zebra sends a uint16_t ... */
			hao_routed_protocol_get_route_msg_data(HAO_ROUTED_SAFI, &safi, message, sizeof(safi));
			api.safi = (uint8_t) ntohs(safi);
		}

		/* Nexthop, ifindex, distance, metric */
		/* We can have more than one nexthop */
		if (IS_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP)) {
			int i;
			api.nexthop_num = message->nexthop_num;
			nexthop = (struct in_addr *) malloc(message->nexthop_num *
							    sizeof(struct in_addr));
			hao_routed_protocol_get_route_msg_data(HAO_ROUTED_NEXTHOPv4, nexthop, message, message->nexthop_num * sizeof(struct in_addr));
			api.nexthop = (struct in_addr**) malloc(message->nexthop_num * sizeof(struct in_addr*));
			for (i = 0 ; i < message->nexthop_num ; i++) {
				api.nexthop[i] = &nexthop[i];
			}
		}
		/* We can have more than one ifindex */
		if (IS_FLAG (api.message, ZAPI_MESSAGE_IFINDEX)) {
			api.ifindex_num = message->ifindex_num;
			/* Warning: might not work if sizeof(int) != sizeof(uint32_t) */
			api.ifindex = (uint32_t *) malloc(message->ifindex_num * sizeof(uint32_t));
			hao_routed_protocol_get_route_msg_data(HAO_ROUTED_PORTUID, api.ifindex, message, message->ifindex_num * sizeof(uint32_t));
		}
		if (IS_FLAG (api.message, ZAPI_MESSAGE_METRIC)) {
			hao_routed_protocol_get_route_msg_data(HAO_ROUTED_METRIC, &api.metric, message, sizeof(api.metric));
			api.metric = ntohl(api.metric);
		}

		if (IS_FLAG (api.message, ZAPI_MESSAGE_DISTANCE)) {
			hao_routed_protocol_get_route_msg_data(HAO_ROUTED_DISTANCE, &api.distance, message, sizeof(api.distance));
		}

		/* 
		 * Add / Delete command dispatching
		 * Send the route command to zebra.
		 * Care only about *_DYN_* routes.
		 */
		if (command == ZEBRA_IPV4_DYN_ROUTE_ADD ||
		    command == ZEBRA_IPV4_DYN_ROUTE_DELETE) {
			hao_routed_zebra_process_route(command, &p, &api);
		}

		if (api.nexthop)
			free(api.nexthop);
		if (api.ifindex)
			free(api.ifindex);
		if (nexthop)
			free(nexthop);

	/* v6 part. Should be the same as v4, but the structure names are different. */
#ifdef HAVE_IPV6
	} else if (message->family == AF_INET6) {
		struct zapi_ipv6 api;
		struct prefix_ipv6 p;
		struct in6_addr* nexthop = NULL;
		int command = ntohl(message->command);

		/* If we have no nexthop and no ifindex, get out */
		if ((message->ifindex_num + message->nexthop_num) == 0)
			goto end;
	
		memset(&api, 0, sizeof(api));
		memset(&p, 0, sizeof(p));

		/* Type, flags, message */
		api.type = message->type;
		api.flags = ntohs(message->flags);
		api.message = message->message;

		/* IPv6 prefix */
		p.family = AF_INET6;
		hao_routed_protocol_get_route_msg_data(HAO_ROUTED_PREFIXLEN, &p.prefixlen, message, sizeof(p.prefixlen));
		hao_routed_protocol_get_route_msg_data(HAO_ROUTED_PREFIX, &p.prefix, message, sizeof(p.prefix));

		/* Vrf_id and safi */
		{
			uint16_t safi;
			hao_routed_protocol_get_route_msg_data(HAO_ROUTED_VRF_ID, &api.vrf_id, message, sizeof(api.vrf_id));
			api.vrf_id = ntohl(api.vrf_id);
			/* api.safi is a uint8_t, but zebra sends a uint16_t ... */
			hao_routed_protocol_get_route_msg_data(HAO_ROUTED_SAFI, &safi, message, sizeof(safi));
			api.safi = ntohs(safi);
		}

		/* Nexthop, ifindex, distance, metric */
		/* We can have more than one nexthop */
		if (IS_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP)) {
			int i;
			api.nexthop_num = message->nexthop_num;
			nexthop = (struct in6_addr *) malloc(message->nexthop_num *
							    sizeof(struct in6_addr));
			hao_routed_protocol_get_route_msg_data(HAO_ROUTED_NEXTHOPv6, nexthop, message, message->nexthop_num * sizeof(struct in6_addr));
			api.nexthop = (struct in6_addr**) malloc(message->nexthop_num * sizeof(struct in6_addr*));
			for (i = 0 ; i < message->nexthop_num ; i++) {
				api.nexthop[i] = &nexthop[i];
			}
		}
		/* We can have more than one ifindex */
		if (IS_FLAG (api.message, ZAPI_MESSAGE_IFINDEX)) {
			api.ifindex_num = message->ifindex_num;
			/* Warning: might not work if sizeof(int) != sizeof(uint32_t) */
			api.ifindex = (uint32_t *) malloc(message->ifindex_num * sizeof(uint32_t));
			hao_routed_protocol_get_route_msg_data(HAO_ROUTED_PORTUID, api.ifindex, message, message->ifindex_num * sizeof(uint32_t));
		}
		if (IS_FLAG (api.message, ZAPI_MESSAGE_METRIC)) {
			hao_routed_protocol_get_route_msg_data(HAO_ROUTED_METRIC, &api.metric, message, sizeof(api.metric));
			api.metric = ntohl(api.metric);
		}

		if (IS_FLAG (api.message, ZAPI_MESSAGE_DISTANCE)) {
			hao_routed_protocol_get_route_msg_data(HAO_ROUTED_DISTANCE, &api.distance, message, sizeof(api.distance));
		}

		/* 
		 * Add / Delete command dispatching
		 * Send the route command to zebra.
		 * Care only about *_DYN_* routes.
		 */
		if (command == ZEBRA_IPV6_DYN_ROUTE_ADD ||
		    command == ZEBRA_IPV6_DYN_ROUTE_DELETE) {
			hao_routed_zebra_process_route(command, &p, &api);
		}

		if (api.nexthop)
			free(api.nexthop);
		if (api.ifindex)
			free(api.ifindex);
		if (nexthop)
			free(nexthop);
#endif /* HAVE_IPV6 */
	}

 end:

	return 0;
}

/* Message processing (DUMP) */
static int hao_routed_protocol_dump_message(uint8_t peer_id, uint16_t size, void *data)
{
	ROUTED_LOG(LOG_DEBUG, "%s()\n", __FUNCTION__);

	/* The peer is asking re-sending all the routes.
	   Re-register the redistribution to re-obtain the routes.  */
	hao_routed_zebra_redistribute ();
	return 0;
}

/* Message dispatching */
int hao_routed_protocol_recv_cb(uint8_t peer_id,
				__attribute__((unused)) uint16_t version,
				uint8_t command, uint16_t size, void *data)
{
	ROUTED_LOG(LOG_DEBUG, "%s(peer_id=%u,command=%u,size=%u)\n", __FUNCTION__,
		peer_id, command, size);

	switch (command) {
	case HAO_CMD_OBJ_NEW:
		ROUTED_LOG(LOG_DEBUG, "%s(): HAO_CMD_OBJ_NEW COMMAND\n", __FUNCTION__);
		hao_routed_protocol_recv_message(peer_id, size, data);
		break;

	case HAO_CMD_OBJ_DEL:
		ROUTED_LOG(LOG_DEBUG, "%s(): HAO_CMD_OBJ_DEL COMMAND\n", __FUNCTION__);
		hao_routed_protocol_recv_message(peer_id, size, data);
		break;

	case HAO_CMD_OBJ_DUMP:
		ROUTED_LOG(LOG_DEBUG, "%s(): HAO_CMD_OBJ_DUMP COMMAND\n", __FUNCTION__);
		hao_routed_protocol_dump_message(peer_id, size, data);
		break;

	case HAO_CMD_GRACE_START:
		ROUTED_LOG(LOG_DEBUG, "%s(): HAO_CMD_GRACE_START COMMAND\n", __FUNCTION__);
		hao_routed_peer_zebra_restart();
		break;

	case HAO_CMD_DUMP_START:
	case HAO_CMD_DUMP_END:
		break;

	default:
		ROUTED_LOG(LOG_ERR, "%s(): UNKNOWN COMMAND %u\n", __FUNCTION__, command);
		break;
	}
	return 0;
}
