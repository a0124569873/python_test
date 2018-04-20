#ifndef __SYN_FLOOD_DEFINE_H__
#define __SYN_FLOOD_DEFINE_H__

#include "flow_define.h"
#include "ddos_gc.h"

enum syn_check {
	NORMAL,
	CHECKING,
	CHECKING_SEND,
};

enum dynamic_white {
	NOT_WHITE,
	IS_WHITE
};
enum cc_attack{
	CC_NORMAL,
	CC_ATTACK
};
struct client_tcp {
	struct        client_status  status;
	enum            syn_check  check;
	enum            dynamic_white white;
	enum cc_attack cc_attack;
	uint32_t    white_effect_time;
	uint64_t    white_create_time;
	uint8_t log_send;
	uint64_t cc_flood_start_time;
}__attribute__((packed));

struct client_tcp_node {
	struct ad_free_obj gc;
	struct client_tcp tcp;
	struct client_tcp_node *next;
}__attribute__((packed));

struct client_tcp_table {
	struct client_tcp_node *next;
}__attribute__((packed));

#endif /* __SYN_FLOOD_DEFINE_H__ */