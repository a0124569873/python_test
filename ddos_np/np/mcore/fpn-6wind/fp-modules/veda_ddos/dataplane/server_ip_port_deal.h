#ifndef __SERVER_IP_PORT_DEAL_H__
#define __SERVER_IP_PORT_DEAL_H__
#include "syn_flood_deal.h"
#include "udp_flood_deal.h"
#include "server_flow_deal.h"
#include "ddos_gc.h"
#include "../fp-anti-ddos.h"

#include "fp-netgraph.h"

static inline int search_ordered_port(struct port_status *ports_status, int size,  uint16_t dport) {
    int i = 0;

    while(i < size) {
        int strip = 1;

        if (ports_status[i].start <= dport && ports_status[i].end >= dport) {
            return i;
        }

        while(i + strip < size && (ports_status[i + strip].start > dport || ports_status[i + strip].end < dport)) {
            strip *= 2;
        }

        i = i + (strip + 1) / 2;
    }

    return -1;
}

static inline int32_t search_server_table(uint32_t dstip, struct server_node **server_node)
{
    struct server_node *server_node_tmp = NULL;
    if(FAST_SEARCH_HASH_TABLE(server_table, IP_HASH_TABLE_INDEX(dstip, SERVER_TABLE), server_node_tmp,
        server_node_tmp->status.server_ip == dstip) )
    {
        *server_node = server_node_tmp;
        return 0;
    }
    return -1;
}

static inline uint8_t server_ip_port_deal_in(struct server_node *server_node, uint16_t proto, uint16_t dport ,uint32_t pkt_len, uint64_t current_time, uint8_t *dport_index)
{
    int server_port_index=0;
    if(server_node == NULL)
    {
        log(LOG_WARNING, "%d ip_flood_deal_in server_node==NULL\n", __LINE__);
        return DROPG;
    }

    if(server_node->status.flow_strategy == FLOW_FORWARD){
         log(LOG_WARNING, "%d FLOW_FORWARD\n", __LINE__);
        return SEND_TO_OUT;
    }
    else if(server_node->status.flow_strategy == FLOW_DROP){
         log(LOG_WARNING, "%d FLOW_DROP\n", __LINE__);
        return DROPG;
    }


    if (dport == 0){
        return SEND_TO_OUT;
    }
    if (proto == FP_IPPROTO_TCP)
    {
        server_port_index = search_ordered_port(server_node->status.ports_status, server_node->status.ports_num, ntohs(dport));
        if( server_port_index < 0 || server_node->status.ports_status[server_port_index].on_off == 0)// 0 :off 1:on
        {
            log(LOG_WARNING, "%d tcp port FLOW_DROP\n", __LINE__);
            return DROPG;
        }
    }
    else if (proto == FP_IPPROTO_UDP)
    {
        server_port_index = search_ordered_port(server_node->status.udp_ports_status, server_node->status.udp_ports_num, ntohs(dport));
        if( server_port_index < 0 || server_node->status.udp_ports_status[server_port_index].on_off == 0)// 0 :off 1:on
        {
            log(LOG_WARNING, "%d udp port FLOW_DROP\n", __LINE__);
            return DROPG;
        }
    }

    *dport_index = (uint8_t)server_port_index;
    return CONTINUE_DEALING;
}

#endif