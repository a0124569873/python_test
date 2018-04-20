#ifndef __SERVER_FLOW_DEAL_H__
#define __SERVER_FLOW_DEAL_H__

#include "syn_flood_deal.h"
#include "udp_flood_deal.h"
#include "server_node_define.h"

#include "../common/cJSON.h"

#define DDOS_PATH    "/tmp/ddos"

extern struct server_table    server_table[SERVER_TABLE];
extern struct black_white_table  black_white_table[BLACK_WHITE_NUM][BLACK_WHITE_TABLE];
extern struct black_white_table tmp_black_table[TMP_BLACK_WHITE_TABLE];
extern struct ip_mac_table ip_mac_table[IP_MAC_TABLE ];

uint8_t server_flow_deal(struct mbuf *m, uint32_t adj_len ,uint32_t linkNum);

void update_server_flow_before_deal(uint32_t dstip, uint32_t dport, uint32_t pkt_len, uint64_t current_time, uint32_t hash_code, struct server_table *server_table, struct server_node **server_node);
void update_server_flow_in_black(uint32_t dstip, uint32_t dport, uint32_t pkt_len, uint64_t current_time, struct server_node *server_node);

static inline void push_pkt_info(uint32_t srcip, uint32_t dstip, uint16_t sport, uint16_t dport, uint8_t proto, uint32_t pkt_len, uint8_t tcp_flag, uint64_t current_time, uint16_t dport_index);

void show_server_node(void);

static inline uint8_t check_black_white_table(struct black_white_table * black_white, uint32_t srcip, uint32_t pkt_len)
{
    struct black_white_node *tmpnode = NULL;

    if (FAST_SEARCH_HASH_TABLE(black_white, IP_HASH_TABLE_INDEX(srcip, BLACK_WHITE_TABLE), tmpnode,
        tmpnode->black_white.srcip == srcip)
        ) {
        return tmpnode->black_white.type == BLACK_TYPE ? DROPG : SEND_TO_OUT;
    }

    return CONTINUE_DEALING;
}

static inline int8_t check_tmp_black_white_table(struct black_white_table * black_white, uint32_t srcip, uint32_t dstip, uint32_t size)
{
    struct black_white_node *tmpnode = NULL;

    if (FAST_SEARCH_HASH_TABLE(tmp_black_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, 0, size), tmpnode,
        tmpnode->black_white.srcip == srcip&&
        tmpnode->black_white.dstip == dstip)
        ) {
        return 1;
    }
    return 0;
}

static inline void push_pkt_info(uint32_t srcip, uint32_t dstip, uint16_t sport, uint16_t dport, uint8_t proto, uint32_t pkt_len, uint8_t tcp_flag, uint64_t current_time, uint16_t dport_index)
{
    struct buffer_entity e = {0};
    struct pkt_common_info* pi = NULL;
    entry_type(&e) = ENTRY_STRUCT_PK_INFO;
    pi = entry_data(&e, struct pkt_common_info*);

    pi->src = srcip;
    pi->dst = dstip;
    pi->sport = sport;
    pi->dport = dport;
    pi->proto = proto;
    pi->len = pkt_len;
    pi->tcp_flag = tcp_flag;
    pi->current_time = current_time;
    pi->dport_index = dport_index;

    ring_buffer_enqueue(&ring_buffer[rte_lcore_id()], &e, 1, ring_overflow);
}

//void add_black_white_node(uint32_t srcip, uint32_t dstip, uint16_t dport, uint32_t type);
void show_black_white_node(void);

void add_ip_mac_node(uint32_t ip, uint8_t* mac);
void update_ip_mac_node(uint32_t ip, uint8_t* mac);
void delete_ip_mac_node(uint32_t ip);
void show_ip_mac_node(void);

int stream_return_mac(struct mbuf *m,uint32_t adj_len);

#endif  /*__SERVER_FLOW_DEAL_H__*/