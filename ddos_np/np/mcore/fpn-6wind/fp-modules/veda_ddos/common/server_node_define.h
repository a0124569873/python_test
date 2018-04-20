#ifndef __SERVER_NODE_DEFINE_H__
#define __SERVER_NODE_DEFINE_H__

#include "ddos_gc.h"

#define  SERVER_TABLE         (1 << 14)
#define SERVER_PORTS_NUM    (1<<4)
#define SERVER_LOG_NUM 100

enum server_flow_type {
    IP_FLOW_NORMAL,
    IP_OVER_THRESHOLD,
    IP_BLACK_HOLE,
};
enum flow_strategy {
    FLOW_NORMAL,
    FLOW_FORWARD,
    FLOW_DROP,
    FLOW_THRESHOLD,
};
struct port_status{
    uint16_t start;
    uint16_t end;
    uint8_t on_off;     //off 1: on
    uint8_t session_beyond_black;   //tcp port 0: off 1: on
    uint16_t session_limit_per_client;
    uint16_t visit_limit_per_client;
    uint32_t session_num;

}__attribute__((packed));
enum syn_attack_type {
    TCP_FLOW_NORMAL,
    TCP_SYN_FLOOD,
};

struct server_syn {
    enum syn_attack_type  type;
    uint32_t   syn_threshold;
    uint64_t   last_detect_time;
    uint64_t   current_syn;
    uint64_t   current_syn_afterclean;
    uint64_t       flood_start_time;
    uint64_t   syn_pps;
     uint8_t log_num;
}__attribute__((packed));

enum udp_attack_type {
    UDP_FLOW_NORMAL,
    UDP_FLOW_FLOOD,
};

struct server_udp {
    enum udp_attack_type  type;
    uint32_t   udp_threshold;
    uint64_t   last_detect_time;
    uint64_t   current_flow;
    uint64_t   current_flow_afterclean;
    uint64_t   bps;
    uint64_t flood_start_time;
    uint8_t log_num;
}__attribute__((packed));

struct server_status {
    uint32_t   server_ip;
    enum flow_strategy flow_strategy;
    enum server_flow_type flow_type;
    uint64_t    over_threshold_start_time;
    uint64_t    black_hole_start_time;

    uint32_t   in_ip_threshold;                           // Mbit
    uint64_t   in_latest_pkt_time;                     // the time unit is msec
    uint64_t   in_last_detect_time;

    uint64_t    in_bps;
    uint64_t   in_current_flow;
    uint64_t   in_bps_after_clean;
    uint64_t   in_current_flow_after_clean;

    uint64_t    in_pps;
    uint64_t   in_last_packets;
    uint64_t   in_current_packets;
    uint64_t   in_pps_after_clean;
    uint64_t   in_current_packets_after_clean;

    uint32_t   out_ip_threshold;
    uint64_t   out_latest_pkt_time;
    uint64_t   out_last_detect_time;

    uint64_t   out_bps;
    uint64_t   out_current_flow;
    uint64_t   out_bps_after_clean;
    uint64_t   out_current_flow_after_clean;

    uint64_t   out_pps;
    uint64_t   out_current_packets;
    uint64_t   out_pps__after_clean;
    uint64_t   out_current_packets_after_clean;

    uint32_t   tcp_session_num;
    uint32_t   udp_session_num;

    struct server_syn  syn;
    struct server_udp  udp;
    uint32_t    tcp_idle_time;
    uint32_t    udp_idle_time;
    uint8_t ports_num;
    struct port_status	ports_status[SERVER_PORTS_NUM];
    uint8_t udp_ports_num;
    struct port_status  udp_ports_status[SERVER_PORTS_NUM];
    int32_t black_num;
    int32_t white_num;

}__attribute__((packed));
struct server_node {
    struct ad_free_obj gc;
	struct server_status  status;
	struct server_node *next;
}__attribute__((packed));

struct server_table {
	struct server_node *next;
}__attribute__((packed));




#endif /* __SERVER_NODE_DEFINE_H__ */