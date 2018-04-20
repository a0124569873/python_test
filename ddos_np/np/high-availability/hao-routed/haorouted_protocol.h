#ifndef _HAOROUTED_PROTOCOL_H_
#define _HAOROUTED_PROTOCOL_H_

#define ROUTE_MESSAGE_HEADER_SIZE   15
/* 
 * Route message data size is:
 * - distance (1)
 * - prefixlen (1)
 * - prefix (16)
 * - safi (2)
 * - metric (4)
 * - vrf_id (4)
 * - nexthops (8 * 16 = 128)
 * - ifindexes (8 * 4 = 32)
 * - a margin for cmd and size for each element
 */

struct route_message
{
	uint32_t command;
	uint16_t offset;
	uint16_t flags;
	uint8_t family;
	uint8_t type;
	uint8_t message;
	uint8_t ifindex_num;
	uint8_t nexthop_num;
	uint8_t data[512];
} __attribute__((packed));

enum hao_routed_commands {
	HAO_ROUTED_NEXTHOPv4 = 1,
	HAO_ROUTED_NEXTHOPv6,
	HAO_ROUTED_PORTUID,
	HAO_ROUTED_PREFIX,
	HAO_ROUTED_METRIC,
	HAO_ROUTED_VRF_ID,
	HAO_ROUTED_SAFI,
	HAO_ROUTED_FLAGS,
	HAO_ROUTED_COMMAND,
	HAO_ROUTED_DISTANCE,
	HAO_ROUTED_FAMILY,
	HAO_ROUTED_TYPE,
	HAO_ROUTED_MESSAGE,
	HAO_ROUTED_PREFIXLEN,
	HAO_ROUTED_PREFIX_AND_LEN,
	HAO_ROUTED_IFINDEX_NUM,
	HAO_ROUTED_NEXTHOP_NUM
};

#define PSIZE(a) (((a) + 7) / (8))

/* Put the value (v) in the route_message (m) with type (t) */ 
#define FILL_MSG_FIELD(t, v, m) hao_routed_protocol_route_msg_fill_field(t, NULL, v, m)
/* Read from the buffer (b), and put the value in the route_message (m) with type (t) */ 
#define READ_N_FILL_MSG_FIELD(t, b, m) hao_routed_protocol_route_msg_fill_field(t, b, NULL, m)

const char* hao_routed_zcommand_name(int cmd);
void hao_routed_protocol_route_msg_fill_field(enum hao_routed_commands cmd, struct rib_buffer *s, void* value, struct route_message *message);
void hao_routed_protocol_dump_route_msg(struct route_message* msg);
int hao_routed_protocol_send_new_message(uint8_t peer_id, void* message, size_t len);
int hao_routed_protocol_send_del_message(uint8_t peer_id, void* message, size_t len);
int hao_routed_protocol_recv_cb(uint8_t, uint16_t, uint8_t, uint16_t, void*);

#endif /* _HAOROUTED_PROTOCOL_H_ */
