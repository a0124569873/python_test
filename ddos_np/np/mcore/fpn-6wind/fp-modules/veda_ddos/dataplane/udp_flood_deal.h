/*
 * Copyright (c) 2007 6WIND
 */

#ifndef __UDP_FLOOD_DEAL_H__
#define __UDP_FLOOD_DEAL_H__

#include "general_function.h"
#include "udp_flood_define.h"
#include "../fp-anti-ddos.h"

#define SPEED_COMPARE(client_udp_speed, udp_speed_threshold)       (client_udp_speed) * 10 > (udp_speed_threshold)  ? 1 : 0  //unit is Bps
#define PACKET_DROP_PERCENT(client_udp_speed, udp_speed_threshold)  \
	(20 + 100*(client_udp_speed) / (udp_speed_threshold))


extern struct client_udp_table    client_udp_table[CLIENT_UDP_TABLE];

static inline void flush_client_udp_info(uint32_t srcip, uint32_t dstip, uint16_t dport, uint32_t pkt_len, uint64_t current_time)
{
    uint32_t lcore_id = rte_lcore_id();
    struct client_udp_info *udp_info = LCORE_CACHE(client_udp_info, lcore_id);
    struct client_udp_info *c_udp_info = NULL;
    do {
        if (srcip ==0 || dstip == 0 || dport == 0 )
            break;

        if(!SEARCH_HASH_ARRAY(udp_info, MAX_CLIENT_UDP_CACHE_LEN, srcip + dstip + dport, c_udp_info,
                c_udp_info->src == 0 || (
                    c_udp_info->src == srcip&&
                    c_udp_info->dst == dstip&&
                    c_udp_info->dport == dport)))
        {
            struct buffer_entity e = {0};
            entry_type(&e) = ENTRY_FLUSH_CLIENT_UDP_INFO;
            ring_buffer_enqueue(&ring_buffer[lcore_id], &e, 1, ring_overflow);
            break;
        }

        if (c_udp_info->src == 0) {
            c_udp_info->src = srcip;
            c_udp_info->dst = dstip;
            c_udp_info->dport = dport;
        }
        c_udp_info->udp_bytes += pkt_len;
        c_udp_info->update_time = current_time;

    } while(0);
}

static inline int32_t search_client_udp_table(uint32_t srcip,uint32_t dstip ,uint16_t dport, struct client_udp_node **client_udp_node, uint64_t current_time)
{
    struct client_udp_node *client_udp_node_tmp = NULL;

    if( FAST_SEARCH_HASH_TABLE(client_udp_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, dport, CLIENT_UDP_TABLE ), client_udp_node_tmp,
        client_udp_node_tmp->udp.status.client_ip == srcip &&
        client_udp_node_tmp->udp.status.server_ip == dstip &&
        client_udp_node_tmp->udp.status.server_port == dport) )
    {
        *client_udp_node = client_udp_node_tmp;
        return 0;
    }
    return -1;
}

static inline int32_t search_client_udp_port(uint16_t sport, struct client_udp_node *client_udp_node,  struct client_port ** client_port)
{
    struct client_port_table * client_port_table = NULL;
    struct client_port * client_port_tmp = NULL;
    if (client_udp_node ==NULL){
        return -1;
    }

    client_port_table = client_udp_node->udp.status.client_port_table;

    if (FAST_SEARCH_HASH_TABLE(client_port_table, IP_HASH_TABLE_INDEX(sport, CLIENT_PORTS_NUM), client_port_tmp,
        client_port_tmp->status.port == sport))
    {
        *client_port = client_port_tmp;
        return 0;

    }

    return -1;
}



#endif /* __UDP_FLOOD_DEAL_H__ */
