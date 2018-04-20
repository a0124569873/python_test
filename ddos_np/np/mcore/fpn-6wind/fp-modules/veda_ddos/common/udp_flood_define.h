#ifndef __UDP_FLOOD_DEFINE_H__
#define __UDP_FLOOD_DEFINE_H__

#include "flow_define.h"
#include "ddos_gc.h"

enum  dynamic_black {
	NOT_BLACK,
	IS_BLACK
};

struct client_udp {
	struct        client_status  status;
	enum  dynamic_black  black;
	uint32_t    black_effect_time;
	uint64_t    black_create_time;
}__attribute__((packed));

struct client_udp_node {
	struct ad_free_obj gc;
	struct client_udp  udp;
	struct client_udp_node *next;
}__attribute__((packed));

struct client_udp_table {
	struct client_udp_node *next;
}__attribute__((packed));

#endif /* __UDP_FLOOD_DEFINE_H__ */