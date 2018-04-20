/*
 * Copyright (c) 2007 6WIND
 */

#ifndef __SYN_FLOOD_DEAL_H__
#define __SYN_FLOOD_DEAL_H__

#include "general_function.h"
#include "syn_flood_define.h"
#include "fp-netgraph.h"
#include "../fp-anti-ddos.h"

extern struct client_tcp_table    client_tcp_table[CLIENT_UDP_TABLE];

static inline void flush_syn_check_info(uint32_t srcip, uint32_t dstip, uint16_t dport, uint64_t current_time)
{
    uint32_t lcore_id = rte_lcore_id();
    struct syn_check_info *syn_info = LCORE_CACHE(syn_check_info, lcore_id);
    struct syn_check_info *c_syn_info = NULL;
    do {
        if (srcip ==0 || dstip == 0 || dport == 0 )
            break;

        if(!SEARCH_HASH_ARRAY(syn_info, MAX_SYN_CHECK_CACHE_LEN, srcip + dstip + dport, c_syn_info,
                c_syn_info->src == 0 || (
                    c_syn_info->src == srcip&&
                    c_syn_info->dst == dstip&&
                    c_syn_info->dport == dport)))
        {
            struct buffer_entity e = {0};
            entry_type(&e) = ENTRY_FLUSH_SYN_CHECK_INFO;
            ring_buffer_enqueue(&ring_buffer[rte_lcore_id()], &e, 1, ring_overflow);
            break;
        }

        if (c_syn_info->src == 0) {
            c_syn_info->src = srcip;
            c_syn_info->dst = dstip;
            c_syn_info->dport = dport;
        }

        c_syn_info->update_time = current_time;

    } while(0);
}

static inline uint8_t deal_reset_add_dynamic_white(struct client_tcp_node *client_tcp_node, uint64_t current_time)
{
    if(client_tcp_node == NULL){
        log(LOG_ERR, "deal_reset_add_dynamic_white client_tcp_node==NULL\n");
        return SEND_TO_OUT;
    }

    struct client_tcp_node *tmpnode = client_tcp_node;
    //find the client node, hash with three tuple, srcip, dstip and dport
    if(tmpnode->tcp.check == CHECKING)
    {
        tmpnode->tcp.check = NORMAL;
        tmpnode->tcp.white = IS_WHITE;
        tmpnode->tcp.white_effect_time = fp_shared->white_effect_time;
        tmpnode->tcp.white_create_time = current_time;
        return DROPG;
    }
    else
    {
        return SEND_TO_OUT;
    }

    return SEND_TO_OUT;
}

static inline int32_t search_client_tcp_table(uint32_t srcip,uint32_t dstip ,uint16_t dport, struct client_tcp_node **client_tcp_node, uint64_t current_time)
{
    struct client_tcp_node *client_tcp_node_tmp = NULL;
    if (FAST_SEARCH_HASH_TABLE(client_tcp_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, dport, CLIENT_TCP_TABLE), client_tcp_node_tmp,
        client_tcp_node_tmp->tcp.status.client_ip == srcip &&
        client_tcp_node_tmp->tcp.status.server_ip == dstip &&
        client_tcp_node_tmp->tcp.status.server_port == dport))
    {
        *client_tcp_node = client_tcp_node_tmp;
        return 0;
    }
    return -1;
}

static inline int32_t search_client_tcp_port(uint16_t sport, struct client_tcp_node *client_tcp_node,  struct client_port ** client_port)
{
    struct client_port_table * client_port_table = NULL;
    struct client_port * client_port_tmp = NULL;
    if (client_tcp_node ==NULL){
        return -1;
    }

    client_port_table = client_tcp_node->tcp.status.client_port_table;

    if (FAST_SEARCH_HASH_TABLE(client_port_table, IP_HASH_TABLE_INDEX(sport, CLIENT_PORTS_NUM), client_port_tmp,
        client_port_tmp->status.port == sport))
    {
        *client_port = client_port_tmp;
        return 0;
    }

    return -1;
}

static inline uint8_t tcp_session_num_deal(struct client_tcp_node *client_tcp_node,uint64_t current_time)
{
    if (client_tcp_node -> tcp.cc_attack == CC_ATTACK)
    {
        return DROPG;
    }
    return CONTINUE_DEALING;
}

#endif /* __SYN_FLOOD_DEAL_H__ */
