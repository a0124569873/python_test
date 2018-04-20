#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"
#include "fp-dscp.h"
#include "fp-ip.h"
#include "fp-netgraph.h"
#include "netinet/fp-udp.h"
#include "netinet/fp-tcp.h"

#include "server_flow_deal.h"
#include "server_ip_port_deal.h"
#include "ddos_gc.h"
#include "../fp-anti-ddos.h"
//#include "fp-ring-buffer.h"

/*hash table for server status*/
struct server_table    server_table[SERVER_TABLE] = {{0}};
/*hash table for black white list*/
struct black_white_table  black_table[BLACK_WHITE_NUM][BLACK_WHITE_TABLE] = {{{0}}};
struct black_white_table  white_table[BLACK_WHITE_NUM][BLACK_WHITE_TABLE] = {{{0}}};
struct black_white_table tmp_black_table[TMP_BLACK_WHITE_TABLE]= {{0}};
struct black_white_table tmp_white_table[TMP_BLACK_WHITE_TABLE]= {{0}};
struct ip_mac_table ip_mac_table[IP_MAC_TABLE ] = {{0}};

//server status to json
static inline void flush_server_and_total_flow_packets(uint32_t dstip, uint32_t pkt_len, uint8_t proto,  uint8_t tcp_flag, uint64_t current_time, uint8_t flow_type) {    // 0 drop ; 1 forward
    uint32_t lcore_id = rte_lcore_id();
    struct total_status  * status = NULL;

    do {
        struct server_flow_info* flow_info = LCORE_CACHE(server_flow_info, lcore_id);
        struct server_flow_info* s_flow_info = NULL;

        if (dstip == 0)
            break;

        if (!SEARCH_HASH_ARRAY(flow_info, MAX_LSERVER_FLOW_CACHE_LEN, dstip, s_flow_info, 
            s_flow_info->ip == 0 || s_flow_info->ip == dstip)) {
                // notify flush all cache
                struct buffer_entity e = {0};

                entry_type(&e) = ENTRY_FLUSH_STATUS_FLOW_CACHE;

                ring_buffer_enqueue(&ring_buffer[lcore_id], &e, 1, ring_overflow);
                break;
        }

        FPN_PREFETCH(s_flow_info);

        s_flow_info->ip = dstip;
        s_flow_info->in.bytes += pkt_len;
        s_flow_info->in.pkts += 1;

        s_flow_info->update_time = current_time;

        if (flow_type == 1) {
            s_flow_info->out.bytes += pkt_len;
            s_flow_info->out.pkts += 1;
        }
        if(proto == FP_IPPROTO_UDP){
        	s_flow_info->udp.bytes += pkt_len;
        }
        else if(proto == FP_IPPROTO_TCP && (tcp_flag & TH_SYN)){
        	s_flow_info->syn.pkts += 1;
        }

    } while(0);

    status = &lcore_cache_data[lcore_id].total_server.status;

    FPN_PREFETCH(status);
    // 1. add
    status->in_current_flow += pkt_len;
    status->in_current_packets += 1;
    status->in_latest_pkt_time = current_time;

    if (flow_type == 1){
        status->in_current_flow_after_clean += pkt_len;
        status->in_current_packets_after_clean += 1;
    }

    // 2.calc

    if(unlikely(current_time - status->in_last_detect_time >= fpn_get_clock_hz())) {
        uint64_t in_flow_speed = 0;
        uint64_t in_packets_speed = 0;
        uint64_t in_flow_speed_after_clean = 0;
        uint64_t in_packets_speed_after_clean = 0;
        uint64_t time = 0;

        time = (current_time - status->in_last_detect_time)/ fpn_get_clock_hz();
        if(status->in_current_flow > 0){
            in_flow_speed = status->in_current_flow  / time ;
        }
        if(status->in_current_packets > 0)
        {
            in_packets_speed = status->in_current_packets  / time;
        }
        // after clean
        if(status->in_current_flow_after_clean > 0)
        {
            in_flow_speed_after_clean = status->in_current_flow_after_clean  / time ;
        }
        if(status->in_current_packets_after_clean > 0)
        {
            in_packets_speed_after_clean = status->in_current_packets_after_clean  / time   ;
        }
        status->in_bps = in_flow_speed * 8;
        status->in_pps = in_packets_speed;
        status->in_bps_after_clean = in_flow_speed_after_clean * 8;
        status->in_pps_after_clean = in_packets_speed_after_clean;

        status->in_current_flow = 0;
        status->in_current_packets = 0;
        status->in_current_flow_after_clean = 0;
        status->in_current_packets_after_clean = 0;
        status->in_last_detect_time = current_time;
    }

}

uint8_t server_flow_deal(struct mbuf *m, uint32_t adj_len, uint32_t linkNum)
{
	struct server_node *server_node = NULL;
	struct fp_ether_header *eth = NULL;
	struct fp_ip *ip = NULL;
	struct fp_tcphdr *th = NULL;

	uint32_t srcip = 0;
	uint32_t dstip = 0;
	uint16_t sport = 0;
	uint16_t dport = 0;
	uint64_t current_time = 0;

	uint8_t deal_result = 0;
	uint8_t b_w_deal_result = 0;
	uint8_t dport_index = 0;
	uint32_t pkt_len = 0;
	uint8_t proto = 0;
	uint8_t tcp_flag = 0;

	if (unlikely(m_adj(m, adj_len) == NULL))
	{
		return DROPG;
	}

	if(unlikely(m_len(m) < sizeof(struct fp_ip)))
	{
		m_prepend(m, adj_len);
		return DROPG;
	}

	ip = mtod(m, struct fp_ip *);

	srcip = ip->ip_src.s_addr;
	dstip = ip->ip_dst.s_addr;

	if(unlikely(m_len(m) < htons(ip->ip_len)))
	{
		m_prepend(m, adj_len);
		return DROPG;
	}

/*	if(linkNum != outer_port)     //only deal one direction packet, which is from Internet to server
	{
		return SEND_TO_OUT;
	}*/

    if (!CHECK_L3_PACKET(m, ip, sport, dport,proto)) {
        return DROPG;
    }

	m_prepend(m, adj_len);
	pkt_len = m_len(m);

	current_time = sys_tsc;
	do {
		// 0. prepare

		if(fp_shared->flow_strategy == TOTAL_FLOW_FORWARD){
			deal_result = SEND_TO_OUT;
			break;
		}

                    // 1.
		if(search_server_table(dstip, &server_node) == -1)
		{
			deal_result = SEND_TO_OUT;
			break;
		}

            FPN_PREFETCH(server_node);

                    // 2.
		deal_result = server_ip_port_deal_in(server_node, proto, dport, pkt_len, current_time, &dport_index);
		if (deal_result  == SEND_TO_OUT || deal_result  == DROPG) {
			break;
		}


		// 3. search black_list and white_list 
		if (server_node->status.black_num >= 0 && server_node->status.black_num < BLACK_WHITE_NUM){
			struct black_white_table *black = black_table[server_node->status.black_num];
			b_w_deal_result = check_black_white_table(black, srcip, pkt_len);
			if (b_w_deal_result  == SEND_TO_OUT || b_w_deal_result  == DROPG) {
				deal_result = b_w_deal_result;
				break;
			}
		}
		if (server_node->status.white_num >= 0 && server_node->status.white_num < BLACK_WHITE_NUM){
			struct black_white_table *white = white_table[server_node->status.white_num];
			b_w_deal_result = check_black_white_table(white, srcip, pkt_len);
			if (b_w_deal_result  == SEND_TO_OUT || b_w_deal_result  == DROPG) {
				deal_result = b_w_deal_result;
				break;
			}
		}

		if (proto == FP_IPPROTO_TCP){
			// 4.
			th = (struct fp_tcphdr *)((uint8_t *)ip + ip->ip_hl * 4);
			tcp_flag = th->th_flags;
			int32_t tcp_query_result = search_tcp_query_table(srcip, dstip, sport, dport, current_time);
			if(check_tmp_black_white_table(tmp_black_table, srcip, dstip, TMP_BLACK_WHITE_TABLE)){
				deal_result = DROPG;
				break;
			}
		/*	if(check_tmp_black_white_table(tmp_white_table, srcip, dstip, TMP_BLACK_WHITE_TABLE)){
				deal_result = SEND_TO_OUT;
				break;
			}*/

			if (tcp_query_result == -1 )
			{
				if (!(tcp_flag & TH_SYN))
				{
					deal_result = DROPG;
					break;
				}
				if (search_tcp_cc_table(srcip, dstip, dport, current_time) != -1)
				{
					deal_result = DROPG;
					break;
				}

				push_pkt_info(srcip, dstip, sport, dport, proto, pkt_len, th->th_flags, current_time, dport_index);
				
				deal_result = server_node->status.syn.type == TCP_FLOW_NORMAL ? SEND_TO_OUT : DROPG;

			} else {
				if (tcp_query_result == SYN_NORMAL){
					deal_result = SEND_TO_OUT;
					break;
				}
				if(tcp_flag & TH_SYN) {
					if (tcp_query_result == SYN_CHECKING_SEND){
						push_pkt_info(srcip, dstip, sport, dport, proto, pkt_len, th->th_flags, current_time, dport_index);
						deal_result = DROP;
						break;
					}
					eth = mtod(m, struct fp_ether_header *);
				//	th->th_ack = fp_shared->tcp_ack_number;
					th->th_ack = htonl(ntohl(th->th_seq) + 1);
					th->th_flags = (TH_SYN | TH_ACK);
					REVERSE_TCP_PORT(th);
					REVERSE_IP(ip);
					REVERSE_ETH(eth);

					m_adj(m, adj_len);
					ip->ip_sum = fpn_ip_hdr_cksum(ip, ip->ip_hl * 4);
					th->th_sum = 0;
					m_set_tx_tcp_cksum(m);
					fpn_deferred_in4_l4cksum_set(m, 0);
					m_prepend(m, adj_len);

					flush_tcp_query(srcip, dstip, sport, dport, SYN_CHECKING_SEND);
					deal_result = SEND_BACK;
					break;
				} else if((tcp_flag == TH_ACK) && (th->th_seq == th->th_ack)) {
					flush_syn_check_info(srcip, dstip, dport, current_time);
					deal_result = DROP;
				}
				else{
					deal_result = DROP;
				}
			}

		}
		else if(proto == FP_IPPROTO_UDP)
		{
			// 5.
			flush_client_udp_info(srcip, dstip, dport, pkt_len, current_time);
			int32_t udp_query_result = search_udp_query_table(srcip, dstip, sport, dport, current_time);
			if(check_tmp_black_white_table(tmp_black_table, srcip, dstip, TMP_BLACK_WHITE_TABLE)){
				deal_result = DROPG;
				break;
			}

			if (udp_query_result == -1)
			{
				push_pkt_info(srcip, dstip, sport, dport, proto, pkt_len, 0, current_time, dport_index);
				deal_result = server_node->status.udp.type == UDP_FLOW_NORMAL ? SEND_TO_OUT : DROPG;
			} else {
				deal_result = udp_query_result == FORWARD ? SEND_TO_OUT : DROPG;
			}
		} else {
			deal_result = SEND_TO_OUT;
		}

	} while(0);

	flush_server_and_total_flow_packets(server_node != NULL ? dstip : 0, pkt_len, proto, tcp_flag, current_time, 
		deal_result == SEND_TO_OUT || deal_result == SEND_BACK);

	return deal_result;
}

void show_server_node(void)
{
	uint32_t i = 0;
	char ipstr[30] = {0};

	FASAT_FOREACH_HASH_TABLE(server_table, tmpnode, SERVER_TABLE, {
		bzero(ipstr, sizeof(ipstr));
		IP_2_STR(tmpnode->status.server_ip, ipstr, sizeof(ipstr));

		printf("No:%u: dstip==%s, syn==%d, udp==%d %lu %lu %lu %lu\n", i++, ipstr, tmpnode->status.syn.syn_threshold, tmpnode->status.udp.udp_threshold,
			tmpnode->status.in_bps,tmpnode->status.in_pps,
			tmpnode->status.in_bps_after_clean,tmpnode->status.in_pps_after_clean);
	})
}


void add_ip_mac_node(uint32_t ip, uint8_t* mac)
{

	struct ip_mac_node **tmpnode = NULL;
	struct ip_mac_node *newnode = NULL;

	if (SEARCH_HASH_TABLE(ip_mac_table, IP_HASH_TABLE_INDEX(ip, IP_MAC_TABLE), tmpnode,
		(*tmpnode)->ip_mac.ip == ip && ETHER_EQUAL_NF((*tmpnode)->ip_mac.mac,mac))) {
		return;
	}

	newnode = (struct ip_mac_node *)malloc(sizeof(struct ip_mac_node));
	newnode->ip_mac.ip = ip;
	memcpy(newnode->ip_mac.mac,mac,6);
	newnode->ip_mac.is_config=1;

	newnode->next = NULL;
	*tmpnode = newnode;

}
void update_ip_mac_node(uint32_t ip, uint8_t* mac)
{
	struct ip_mac_node *tmpnode = NULL;

	if (!FAST_SEARCH_HASH_TABLE(ip_mac_table, IP_HASH_TABLE_INDEX(ip, IP_MAC_TABLE), tmpnode,
		tmpnode->ip_mac.ip == ip)) {
		return;
	}

	memcpy(tmpnode->ip_mac.mac,mac,6);
	tmpnode->ip_mac.is_config=1;
}
void delete_ip_mac_node(uint32_t ip)
{
	struct ip_mac_node **tmpnode = NULL;

	if (SEARCH_HASH_TABLE(ip_mac_table, IP_HASH_TABLE_INDEX(ip, IP_MAC_TABLE), tmpnode,
		(*tmpnode)->ip_mac.ip == ip)) {
		struct ip_mac_node *n = *tmpnode;
		*tmpnode = (*tmpnode)->next;
		free(n);
	}
}

void show_ip_mac_node(void)
{
	char ip[30] = {0};

	FASAT_FOREACH_HASH_TABLE(ip_mac_table, tmpnode, IP_MAC_TABLE, {
		bzero(ip, sizeof(ip));
		struct ip_mac_t* m = &tmpnode->ip_mac;
		IP_2_STR(m->ip, ip, sizeof(ip));
		printf("%s %x:%x:%x:%x:%x:%x %d\n", ip, m->mac[0], m->mac[1], m->mac[2],
			m->mac[3], m->mac[4], m->mac[5], m->is_config);
	})
}

int stream_return_mac(struct mbuf *m,uint32_t adj_len)
{

	struct fp_ether_header *vhdr = NULL;
	vhdr = mtod(m, struct fp_ether_header *);
	struct fp_ip *ip = NULL;

	m_adj(m, adj_len);
	ip = mtod(m, struct fp_ip *);
	uint32_t dstip = ip->ip_dst.s_addr;

	struct ip_mac_node *tmpnode = NULL;

	if (FAST_SEARCH_HASH_TABLE(ip_mac_table, IP_HASH_TABLE_INDEX(dstip, IP_MAC_TABLE), tmpnode,
		tmpnode->ip_mac.ip == dstip)) {
		memcpy(vhdr->ether_dhost, tmpnode->ip_mac.mac,6);

		m_prepend(m, adj_len);
		return 1;
	}

	m_prepend(m, adj_len);
	return 0;
}
