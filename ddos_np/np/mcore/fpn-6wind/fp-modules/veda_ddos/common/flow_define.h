#ifndef __FLOW_DEFINE_H__
#define __FLOW_DEFINE_H__
#include "ddos_gc.h"
#define  SERVER_FLOW_TABLE         (1 << 10)
#define  CLIENT_TABLE         (1 << 20)
#define  CLIENT_PORTS_NUM         (1 << 6)

#define  CLIENT_TCP_TABLE    CLIENT_TABLE
#define  CLIENT_UDP_TABLE    CLIENT_TABLE

#define  DROPG                               0
#define  SEND_TO_OUT                    1
#define  SEND_TO_KERNEL              2
#define  SEND_BACK                       3
#define  CONTINUE_DEALING	          4

struct client_port_status{
    uint16_t port;
    uint64_t latest_pkt_time;
    uint8_t on;
    struct client_port *next;
}__attribute__((packed));

struct client_port{
    struct ad_free_obj gc;
    struct client_port_status status;
    struct client_port *next;
}__attribute__((packed));

struct client_port_table {
    struct client_port *next;
}__attribute__((packed));

struct client_status {
	uint32_t   client_ip;
	uint32_t   server_ip;
	uint16_t   server_port;
	uint64_t   latest_pkt_time;
         uint64_t   last_detect_time;
         uint32_t   session_num;
         uint64_t   current_packets;
         uint64_t    current_flow;
         uint64_t   pps;
         uint64_t   bps;
         struct client_port_table client_port_table[CLIENT_PORTS_NUM];
}__attribute__((packed));


#endif /* __FLOW_DEFINE_H__ */