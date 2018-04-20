
#include "fp-anti-ddos.h"
#include "server_ip_port_deal.h"
#include "fp-netgraph.h"

struct ring_buffer ring_buffer[FPN_MAX_CORES];
int64_t ring_buffer_overflow[FPN_MAX_CORES];

struct query_table udp_query_table[UDP_QUERY_TABLE];
struct query_table tcp_query_table[TCP_QUERY_TABLE];
struct query_table tcp_cc_table[TCP_CC_TABLE];

struct client_tcp_table    client_tcp_table[CLIENT_UDP_TABLE];
struct client_udp_table    client_udp_table[CLIENT_UDP_TABLE];

struct lcore_cache_data lcore_cache_data[FPN_MAX_CORES];

struct ad_gc_status gc_status_table[GC_STATUS_TABLE_SIZE];

extern int fp_ddos_init(void);

void ddos_loop_start(void) {
    bzero(ring_buffer, sizeof(struct ring_buffer) * FPN_MAX_CORES);
    bzero(ring_buffer_overflow, sizeof(int64_t) * FPN_MAX_CORES);

    bzero(client_tcp_table, sizeof(struct client_tcp_table) * CLIENT_TCP_TABLE);
    bzero(client_udp_table, sizeof(struct client_udp_table) * CLIENT_UDP_TABLE);

    bzero(udp_query_table, sizeof(struct query_table) * UDP_QUERY_TABLE);
    bzero(tcp_query_table, sizeof(struct query_table) * TCP_QUERY_TABLE);
    bzero(tcp_cc_table, sizeof(struct query_table) * TCP_CC_TABLE);

    bzero(lcore_cache_data, sizeof(struct lcore_cache_data) * FPN_MAX_CORES);
    
    bzero(gc_status_table, sizeof(struct ad_gc_status) * GC_STATUS_TABLE_SIZE);

    fp_ddos_init();
}

// ring buffer
void ring_buffer_init(void) {
    int i = 0;
    for( i = 0; i < FPN_MAX_CORES; i ++) {
        if (!rte_lcore_is_enabled(i)) {
            continue;
        }

        fpn_spinlock_init(&ring_buffer[i].lock);
    }
}

// ad free
FPN_SLIST_HEAD(ad_free_objlist, ad_free_obj);

struct ad_free_objlist ad_free_objlist = {0};

void ad_free_init(void) {
    FPN_SLIST_INIT(&ad_free_objlist);
}

void ad_free_check(void) {
    static uint64_t free_size = 0;
    struct ad_free_obj *cur, *next;

    FPN_SLIST_FOREACH_SAFE(cur, next, &ad_free_objlist, next) {
        if (sys_tsc - AD_FREE_OBJ_TIMESTAMP(cur) >= fpn_rte_tsc_hz) {
            FPN_SLIST_REMOVE(&ad_free_objlist, cur, ad_free_obj, next);
            free_size += AD_FREE(cur);

            if (free_size >= 10*1024*1024) {
                if (malloc_trim(0) != 0) {
                    free_size = 0;
                }
            }
        }
    }
}

void ad_free_add(void* obj) {
    AD_FREE_OBJ_TIMESTAMP(((struct ad_free_obj*)obj)) = sys_tsc;
    FPN_SLIST_INSERT_HEAD(&ad_free_objlist, (struct ad_free_obj*)obj, next);
}

const char * basename(const char *filename);

void dump_gc_status(char* buf, int size) {
    char* ptr = buf;
    int len = size;
    int i = 0;

    for(; i < GC_STATUS_TABLE_SIZE; i ++) {
        struct ad_gc_status* g = gc_status_table + i;
        if (g->line_no == 0) {
            continue;
        }

        int n = 0;

        n = snprintf(ptr, len, "%s:<%s:%d> size/count: %ld/%ld \n", 
            basename(g->file),
            g->func,
            g->line_no,
            g->size,
            g->count);

        if (n <= 0 || n >= len) {
            return;
        }

        ptr += n;
        len -= n;
    }
}

#include "udp_flood_deal.h"
#include "syn_flood_deal.h"

int32_t add_client_tcp_node(uint32_t srcip,uint32_t dstip ,uint16_t dport,struct client_tcp_node **client_tcp_node, uint32_t pkt_len,uint64_t current_time);
int32_t add_client_tcp_port(uint16_t sport, struct client_tcp_node *client_tcp_node,  struct client_port ** client_port, uint64_t current_time);
void init_client_tcp_node(struct client_tcp_node * client_tcp_node,uint32_t srcip,uint32_t dstip,uint16_t dport,uint32_t pkt_len, uint64_t current_time);
int flush_client_tcp_node(struct client_tcp_node *client_tcp_node, uint64_t current_time);

int32_t add_client_udp_node(uint32_t srcip,uint32_t dstip ,uint16_t dport,struct client_udp_node **client_udp_node,uint32_t pkt_len, uint64_t current_time);
int32_t add_client_udp_port(uint16_t sport, struct client_udp_node *client_udp_node,  struct client_port ** client_port, uint64_t current_time);
void init_client_udp_node(struct client_udp_node * client_udp_node,uint32_t srcip,uint32_t dstip,uint16_t dport,uint32_t pkt_len,uint64_t current_time);
void cal_client_udp_node_bps(struct client_udp_node *client_udp_node, uint64_t current_time);

int32_t add_udp_query_node(uint32_t srcip, uint32_t dstip, uint16_t sport, uint16_t dport, uint32_t *attack_type, uint64_t current_time);
int32_t add_tcp_query_node(uint32_t srcip, uint32_t dstip, uint16_t sport, uint16_t dport, uint32_t *attack_type, uint64_t current_time, uint32_t idle_time);
int32_t add_tcp_cc_node(uint32_t srcip, uint32_t dstip, uint16_t dport, uint32_t *attack_type, uint64_t current_time);
int32_t del_tcp_cc_node(uint32_t srcip, uint32_t dstip, uint16_t dport);

int32_t add_tmp_black_white_table(struct black_white_table * black_white, uint32_t srcip, uint32_t dstip, uint32_t size);
int32_t del_tmp_black_white_table(struct black_white_table * black_white, uint32_t srcip, uint32_t dstip, uint32_t size);

int process_info(struct pkt_common_info* pinfo)
{
    uint32_t srcip = pinfo->src;
    uint32_t dstip = pinfo->dst;
    uint16_t sport = pinfo->sport;
    uint16_t dport = pinfo->dport;
    uint8_t proto = pinfo->proto;
    uint32_t len = pinfo->len;
    uint8_t tcp_flag = 0;
    uint64_t current_time = pinfo->current_time;
    uint8_t dport_index = pinfo->dport_index;
    struct server_node *server_node = NULL;
    struct port_status *ports_status = NULL;
    int32_t node_deal_result = 0;
    int32_t port_deal_result = 0;
    uint32_t *attack_type = 0;
    if(search_server_table(dstip, &server_node) == -1)
    {
        return -1;
    }
    if (proto == FP_IPPROTO_TCP)
    {
        struct client_tcp_node *client_tcp_node = NULL;
        struct client_port * client_port = NULL;
        uint32_t connection_timeout_time = 0;

        tcp_flag = pinfo->tcp_flag;
        if (!(tcp_flag & TH_SYN)){
            return -1;
        }


        node_deal_result = add_client_tcp_node(srcip, dstip, dport,&client_tcp_node,len ,current_time);
        if ( node_deal_result == -1 )
        {
            return -1;
        }
        if (client_tcp_node->tcp.check == CHECKING_SEND){
             add_tmp_black_white_table(tmp_black_table, srcip, dstip, TMP_BLACK_WHITE_TABLE);
             if(client_tcp_node->tcp.log_send == 0 && server_node->status.syn.log_num < SERVER_LOG_NUM){
                add_attack_log(srcip, dstip, ntohs(dport), server_node->status.syn.flood_start_time, 0, 1);
                client_tcp_node->tcp.log_send = 1;
                server_node->status.syn.log_num += 1;
             }
             return -1;
        }

        port_deal_result = add_client_tcp_port(sport,client_tcp_node,&client_port,current_time);
        if ( port_deal_result == -1 )
        {
            return -1;
        }
        if (node_deal_result ==1 && server_node->status.syn.type == TCP_SYN_FLOOD){
            client_tcp_node->tcp.check = CHECKING;
        }
        attack_type =  &(client_tcp_node->tcp.check);
        connection_timeout_time = server_node->status.tcp_idle_time;

        //printf("%s %d deal_result %d %d \n", __func__, __LINE__,node_deal_result,port_deal_result);
        ports_status =  &(server_node->status.ports_status[dport_index]);
        client_port->status.latest_pkt_time = current_time;
        client_tcp_node->tcp.status.latest_pkt_time = current_time;

        if (port_deal_result == 1){
            fp_shared->tcp_session_num += 1;
            client_tcp_node->tcp.status.session_num +=1;
            ports_status->session_num+=1;
            server_node->status.tcp_session_num +=1;
        }
        add_tcp_query_node(srcip, dstip, sport, dport, attack_type, current_time, connection_timeout_time);

        //printf("%s %d %d %d %d %d \n", __func__, __LINE__,client_tcp_node->tcp.status.session_num,
                //ports_status->session_num,server_node->status.tcp_session_num,ports_status->session_limit_per_client);
        if (ports_status->session_limit_per_client > 0 && client_tcp_node->tcp.status.session_num >= ports_status->session_limit_per_client)
        {
            client_tcp_node -> tcp.cc_attack = CC_ATTACK;
            client_tcp_node -> tcp.cc_flood_start_time = current_time;
            attack_type = &(client_tcp_node -> tcp.cc_attack);
            if (ports_status->session_beyond_black == 1){
                add_tmp_black_white_table(tmp_black_table, srcip, dstip, TMP_BLACK_WHITE_TABLE);
            }
            add_tcp_cc_node(srcip, dstip, dport, attack_type, current_time);
            add_attack_log(srcip, dstip, ntohs(dport), current_time, 0, 3);
        }
    }
    else
    {
        struct client_udp_node *client_udp_node = NULL;
        struct client_port * client_port = NULL;
        node_deal_result = add_client_udp_node(srcip, dstip, dport, &client_udp_node,len,current_time);
        if (node_deal_result == -1 )
        {
            return -1;
        }
        port_deal_result = add_client_udp_port(sport, client_udp_node, &client_port, current_time) ;
        if (port_deal_result == -1 )
        {
            return -1;
        }
        attack_type = &(client_udp_node->udp.black);
        //printf("%s %d deal_result %d %d \n", __func__, __LINE__,node_deal_result,port_deal_result);
        ports_status =  &(server_node->status.udp_ports_status[dport_index]);
        client_port->status.latest_pkt_time = current_time;
        client_udp_node->udp.status.latest_pkt_time = current_time;

        if (port_deal_result == 1){
            fp_shared->udp_session_num += 1;
            client_udp_node->udp.status.session_num += 1;
            ports_status->session_num += 1;
            server_node->status.udp_session_num += 1;
        }
        add_udp_query_node(srcip, dstip, sport, dport, attack_type, current_time);
        //printf("%s %d %d %d %d total udp session %d\n", __func__, __LINE__,client_udp_node->udp.status.session_num, ports_status->session_num,server_node->status.udp_session_num,fp_shared->udp_session_num);
    }

    return 0;
}

pkt_action do_ad_query(struct pkt_common_info* pkt_info)
{
    return PKT_ACTION_UNKNOW;
}

void flush_server_flow_info_cache(uint32_t lcore) {
    struct server_flow_info* flow_info = LCORE_SWITCH_CACHE(server_flow_info, lcore);
    int i = 0;

    for (i = 0; i < MAX_LSERVER_FLOW_CACHE_LEN; i ++) {
        struct server_node *server_node = NULL;

        if (flow_info[i].ip == 0) {
            continue;
        }

        if(!FAST_SEARCH_HASH_TABLE(server_table, IP_HASH_TABLE_INDEX(flow_info[i].ip, SERVER_TABLE), server_node,
            server_node->status.server_ip == flow_info[i].ip) ) {
            continue;
        }

        server_node->status.in_current_flow += flow_info[i].in.bytes;
        server_node->status.in_current_packets += flow_info[i].in.pkts;
        server_node->status.in_latest_pkt_time = flow_info[i].update_time;
        server_node->status.in_current_flow_after_clean += flow_info[i].out.bytes;
        server_node->status.in_current_packets_after_clean += flow_info[i].out.pkts;
        server_node->status.syn.current_syn += flow_info[i].syn.pkts;
        server_node->status.udp.current_flow += flow_info[i].udp.bytes;
    }

    bzero(flow_info, MAX_LSERVER_FLOW_CACHE_LEN * sizeof(struct server_flow_info));
}

int32_t add_client_tcp_node(uint32_t srcip,uint32_t dstip ,uint16_t dport,struct client_tcp_node **client_tcp_node, uint32_t pkt_len,uint64_t current_time)
{
    struct client_tcp_node *newnode = NULL;
    struct client_tcp_node **client_tcp_node_tmp = NULL;
    if (SEARCH_HASH_TABLE(client_tcp_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, dport, CLIENT_TCP_TABLE), client_tcp_node_tmp,
        (*client_tcp_node_tmp)->tcp.status.client_ip == srcip &&
        (*client_tcp_node_tmp)->tcp.status.server_ip == dstip &&
        (*client_tcp_node_tmp)->tcp.status.server_port == dport)) {
        *client_tcp_node = *client_tcp_node_tmp;
        return 0;
    }

    newnode = (struct client_tcp_node *)AD_ZALLOC(sizeof(struct client_tcp_node));
    if (newnode == NULL)
        return -1;

    init_client_tcp_node(newnode, srcip,dstip,dport, pkt_len, current_time);
    *client_tcp_node_tmp = newnode;
    *client_tcp_node = *client_tcp_node_tmp;

    return 1;
}

int32_t add_client_tcp_port(uint16_t sport, struct client_tcp_node *client_tcp_node,  struct client_port ** client_port,uint64_t current_time)
{
    struct client_port_table * client_port_table = NULL;
    struct client_port *newnode = NULL;
     struct client_port ** client_port_tmp = NULL;

    if (!client_tcp_node) {
        return -1;
    }

    client_port_table = client_tcp_node->tcp.status.client_port_table;

    if (SEARCH_HASH_TABLE(client_port_table, IP_HASH_TABLE_INDEX(sport, CLIENT_PORTS_NUM), client_port_tmp,
        (*client_port_tmp)->status.port == sport))
    {
        *client_port = *client_port_tmp;
        return 0;
    }

    newnode = (struct client_port *)AD_ZALLOC(sizeof(struct client_port));
    if (newnode == NULL)
        return -1;

    newnode ->status.port = sport;
    newnode->status.latest_pkt_time = current_time;
    newnode ->next = NULL;
    *client_port_tmp = newnode;
    *client_port = *client_port_tmp;

     return 1;
}

void init_client_tcp_node(struct client_tcp_node * client_tcp_node,uint32_t srcip,uint32_t dstip,uint16_t dport,uint32_t pkt_len, uint64_t current_time)
{
    client_tcp_node->tcp.status.client_ip = srcip;
    client_tcp_node->tcp.status.server_ip = dstip;
    client_tcp_node->tcp.status.server_port = dport;
    client_tcp_node->tcp.status.latest_pkt_time = current_time;
    client_tcp_node->tcp.status.last_detect_time = current_time;
    client_tcp_node->tcp.status.session_num = 0;
    client_tcp_node->tcp.status.current_packets = 1;
    client_tcp_node->tcp.status.current_flow = pkt_len;
    client_tcp_node->tcp.status.pps = 0;
    client_tcp_node->tcp.status.bps = 0;
    memset((uint8_t *)client_tcp_node->tcp.status.client_port_table, 0, CLIENT_PORTS_NUM * sizeof(struct client_port_table));

    client_tcp_node->tcp.check = NORMAL;
    client_tcp_node->tcp.white = NOT_WHITE;
    client_tcp_node->tcp.cc_attack = CC_NORMAL;
    client_tcp_node->tcp.white_effect_time = 0;
    client_tcp_node->tcp.white_create_time = 0;
    client_tcp_node->tcp.log_send = 0;
    client_tcp_node->next = NULL;
 }

int32_t add_client_udp_node(uint32_t srcip,uint32_t dstip ,uint16_t dport,struct client_udp_node **client_udp_node, uint32_t pkt_len, uint64_t current_time)
{
    struct client_udp_node *newnode = NULL;
    struct client_udp_node **client_udp_node_tmp = NULL;

    if (SEARCH_HASH_TABLE(client_udp_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, dport, CLIENT_UDP_TABLE), client_udp_node_tmp,
            (*client_udp_node_tmp)->udp.status.client_ip == srcip &&
            (*client_udp_node_tmp)->udp.status.server_ip == dstip &&
            (*client_udp_node_tmp)->udp.status.server_port == dport))
    {
        *client_udp_node = *client_udp_node_tmp;
        return 0;
    }

    newnode = (struct client_udp_node *)AD_ZALLOC(sizeof(struct client_udp_node));
    if (newnode == NULL)
        return -1;

    init_client_udp_node(newnode, srcip,dstip,dport,pkt_len, current_time);
    *client_udp_node_tmp = newnode;
    *client_udp_node = *client_udp_node_tmp;
    return 1;

}
int32_t add_client_udp_port(uint16_t sport, struct client_udp_node *client_udp_node,  struct client_port ** client_port, uint64_t current_time)
{
    struct client_port_table * client_port_table = NULL;
    struct client_port *newnode = NULL;
    struct client_port ** client_port_tmp = NULL;

    if (!client_udp_node) {
        return -1;
    }

    client_port_table = client_udp_node->udp.status.client_port_table;
    if (SEARCH_HASH_TABLE(client_port_table, IP_HASH_TABLE_INDEX(sport, CLIENT_PORTS_NUM), client_port_tmp,
        (*client_port_tmp)->status.port == sport)) {
        *client_port = *client_port_tmp;
        return 0;
    }

    newnode = (struct client_port *)AD_ZALLOC(sizeof(struct client_port));
    if (newnode == NULL)
        return -1;

    newnode ->status.port = sport;
    newnode->status.latest_pkt_time = current_time;
    newnode ->next = NULL;
    *client_port_tmp = newnode;
    *client_port = *client_port_tmp;
    return 1;
}
void init_client_udp_node(struct client_udp_node * client_udp_node,uint32_t srcip,uint32_t dstip,uint16_t dport,uint32_t pkt_len,uint64_t current_time)
{
    client_udp_node->udp.status.client_ip = srcip;
    client_udp_node->udp.status.server_ip = dstip;
    client_udp_node->udp.status.server_port = dport;
    client_udp_node->udp.status.latest_pkt_time = current_time;
    client_udp_node->udp.status.last_detect_time = current_time;
    client_udp_node->udp.status.session_num = 0;
    client_udp_node->udp.status.current_packets = 1;
    client_udp_node->udp.status.current_flow = pkt_len;
    client_udp_node->udp.status.pps = 0;
    client_udp_node->udp.status.bps = 0;
    memset((uint8_t *)client_udp_node->udp.status.client_port_table, 0, CLIENT_PORTS_NUM * sizeof(struct client_port_table));

    client_udp_node->udp.black = NOT_BLACK;
    client_udp_node->udp.black_effect_time = 0;
    client_udp_node->udp.black_create_time = 0;
    client_udp_node->next = NULL;
}

void flush_client_tcp_table(uint64_t current_time)
{

    FOREACH_HASH_TABLE(client_tcp_table, node, CLIENT_TCP_TABLE, {
     struct client_tcp_node *tmp = NULL;
/*
        if (flush_client_tcp_node(*node, current_time) < 0) {
            tmp = *node;

            *node = (*node)->next;
            ad_free_add(tmp);
            continue;
        }
*/
        flush_client_tcp_node(*node, current_time);

        if (likely((current_time - (*node)->tcp.status.latest_pkt_time) < CLIENT_TCP_UPTIME_TIME *  fpn_get_clock_hz())
         || (*node)->tcp.status.session_num > 0) {
            continue;
        }

        tmp = *node;
        *node = (*node)->next;
        ad_free_add(tmp);
    });
}

int flush_client_tcp_node(struct client_tcp_node *client_tcp_node, uint64_t current_time) {
    struct server_node *server_node = NULL;
    // struct port_status *ports_status = NULL;
    // uint32_t    connection_timeout_time = 0;
     uint32_t srcip = 0;
     uint32_t dstip = 0;
    // uint16_t dport = 0;
    
    srcip = client_tcp_node->tcp.status.client_ip;
    dstip = client_tcp_node->tcp.status.server_ip;
    //dport = client_tcp_node->tcp.status.server_port;

    do {

        if (search_server_table(dstip, &server_node) < 0) {
            break;
        }
        if (client_tcp_node->tcp.check == NORMAL && client_tcp_node->tcp.white == IS_WHITE){
            if(current_time - client_tcp_node->tcp.white_create_time >=
                fpn_get_clock_hz() * client_tcp_node->tcp.white_effect_time)
            {
                client_tcp_node->tcp.check = CHECKING;
                client_tcp_node->tcp.white = NOT_WHITE;
                client_tcp_node->tcp.white_effect_time = 0;
                client_tcp_node->tcp.white_create_time = 0;
            }
        }
        uint32_t syn_type = server_node->status.syn.type;
        if (syn_type == TCP_SYN_FLOOD){
            if(client_tcp_node->tcp.check == NORMAL && client_tcp_node->tcp.white == NOT_WHITE){
                client_tcp_node->tcp.check = CHECKING;
            }
        }
        else if (syn_type == TCP_FLOW_NORMAL){
            if(client_tcp_node->tcp.check != NORMAL){
                client_tcp_node->tcp.check = NORMAL;
                client_tcp_node->tcp.log_send = 0;
                del_tmp_black_white_table(tmp_black_table, srcip, dstip, TMP_BLACK_WHITE_TABLE);
            }
        }


/*
        int server_port_index = 0;
        server_port_index = search_ordered_port(server_node->status.ports_status, server_node->status.ports_num , ntohs(dport));
        if (server_port_index < 0) {
            break;
        }

        connection_timeout_time = server_node->status.tcp_idle_time ;

        ports_status =  &server_node->status.ports_status[server_port_index];
        */

    } while(0);

/*
    FOREACH_HASH_TABLE(client_tcp_node->tcp.status.client_port_table, node, CLIENT_PORTS_NUM, {
        if(ports_status == NULL) {
            struct client_port *t = *node;
            *node = (*node)->next;
            ad_free_add(t);
            continue;
        }

        if(likely(current_time - (*node)->status.latest_pkt_time < connection_timeout_time * fpn_get_clock_hz())) {
            continue;
        }

        client_tcp_node->tcp.status.session_num -= 1;
        ports_status->session_num -= 1;
        server_node->status.tcp_session_num -= 1;
        {
            struct client_port *t = *node;
            *node = (*node)->next;
            ad_free_add(t);
        }
    })

    if (ports_status != NULL && client_tcp_node->tcp.status.session_num < ports_status->session_limit_per_client && client_tcp_node -> tcp.cc_attack == CC_ATTACK) {
        del_tcp_cc_node(srcip, dstip, dport);
        client_tcp_node -> tcp.cc_attack = CC_NORMAL;
    }

    return ports_status != NULL ? 0 : -1;
    */
    return 0;
}

void ring_overflow(struct ring_buffer* r, struct buffer_entity* e) {
    ring_buffer_overflow[rte_lcore_id()] ++;
}

void dump_ring_buffer_info(char* buf, int size) {
    char* ptr = buf;
    int len = size;
    int i = 0;

    static int64_t last_ring_buffer_overflow[FPN_MAX_CORES];

    for(; i < FPN_MAX_CORES; i ++) {
        int n = 0;

        if (!rte_lcore_is_enabled(i)) {
            continue;
        }

        n = snprintf(ptr, len, "core %d C/P: %d/%d size: %d overflow: %ld \n", i,
            ring_buffer[i].cons,
            ring_buffer[i].prod,
            ring_buffer_size(&ring_buffer[i]),
            ring_buffer_overflow[i] - last_ring_buffer_overflow[i]);

        last_ring_buffer_overflow[i] = ring_buffer_overflow[i];

        if (n <= 0 || n >= len) {
            return;
        }

        ptr += n;
        len -= n;
    }
}

void flush_client_udp_table(uint64_t current_time)
{
    FOREACH_HASH_TABLE(client_udp_table, node, CLIENT_UDP_TABLE, {
        struct client_udp_node *tmp = NULL;
        cal_client_udp_node_bps(*node, current_time);

         if(likely(current_time - (*node)->udp.status.latest_pkt_time < CLIENT_UDP_UPTIME_TIME * fpn_get_clock_hz())) {
            continue;
         }

         if ((*node)->udp.status.session_num > 0){
            continue;
         }

         tmp = *node;
         *node = (*node)->next;
         ad_free_add(tmp);
    });
}

void cal_client_udp_node_bps(struct client_udp_node *client_udp_node, uint64_t current_time)
{
    struct server_node *server_node = NULL;
    uint64_t  client_udp_speed = 0;
    uint64_t time =0;
    uint32_t dstip = client_udp_node->udp.status.server_ip;
    if (search_server_table(dstip, &server_node) < 0) {
            return;
    }
    uint64_t udp_speed_threshold = (uint64_t)1024 * 1024 * server_node->status.udp.udp_threshold / 8;
    uint32_t attack_type = server_node->status.udp.type;
    uint32_t srcip = client_udp_node->udp.status.client_ip;

    if(client_udp_node->udp.black == IS_BLACK)
    {
        if( (current_time - client_udp_node->udp.black_create_time)  >=
                    client_udp_node->udp.black_effect_time * fpn_get_clock_hz())
        {
            client_udp_node->udp.black = NOT_BLACK;
            client_udp_node->udp.black_create_time = 0;
            client_udp_node->udp.black_effect_time = 0;
            del_tmp_black_white_table(tmp_black_table, srcip, dstip, TMP_BLACK_WHITE_TABLE);
        }
        else
            return;
    }
    if(attack_type == UDP_FLOW_NORMAL)
    {
        return;
    }
    uint64_t flood_start_time = server_node->status.udp.flood_start_time;
    if(likely(current_time - client_udp_node->udp.status.last_detect_time >= fpn_get_clock_hz()))
    {
        time = (current_time - client_udp_node->udp.status.last_detect_time) / fpn_get_clock_hz();
        client_udp_speed =  client_udp_node->udp.status.current_flow  / time;
        client_udp_node->udp.status.current_flow = 0;
        client_udp_node->udp.status.last_detect_time = current_time;
    }
    if(SPEED_COMPARE(client_udp_speed, udp_speed_threshold) > 0)
    {
        client_udp_node->udp.black = IS_BLACK;
        client_udp_node->udp.black_create_time = current_time;
        client_udp_node->udp.black_effect_time = fp_shared->black_effect_time;
        if (server_node->status.udp.log_num < SERVER_LOG_NUM){
            add_attack_log(client_udp_node->udp.status.client_ip, dstip, ntohs(client_udp_node->udp.status.server_port), flood_start_time, 0, 2 );
            server_node->status.udp.log_num += 1;
        }
        add_tmp_black_white_table(tmp_black_table, srcip, dstip, TMP_BLACK_WHITE_TABLE);
    }

}

void flush_lcore_server(uint64_t current_time)
{
    uint32_t i =0;
    struct total_status  *status = NULL;
    struct total_status  *total_status = &fp_shared->total.status;
    bzero(total_status,sizeof(struct total_status));
    for (i= 0; i< FPN_MAX_CORES; i++)
    {
        if (!rte_lcore_is_enabled(i)) {
            continue;
        }
        
        status = &lcore_cache_data[i].total_server.status;
        if (unlikely( (current_time - status->in_latest_pkt_time ) > 3 * fpn_get_clock_hz() ))
        {
            status->in_bps = 0;
            status->in_pps = 0;
            status->in_bps_after_clean = 0;
            status->in_pps_after_clean = 0;
        }
        total_status->in_bps += status->in_bps;
        total_status->in_pps += status->in_pps;
        total_status->in_bps_after_clean += status->in_bps_after_clean;
        total_status->in_pps_after_clean += status->in_pps_after_clean;

    }
}

void flush_server_table( uint64_t current_time, uint64_t expired_cycles){

    FASAT_FOREACH_HASH_TABLE(server_table, tmpnode, SERVER_TABLE, {
         struct server_status* status = &tmpnode->status;
         uint64_t  in_flow_speed = 0;
         uint64_t  in_packets_speed = 0;
         uint64_t  in_flow_speed_after_clean = 0;
         uint64_t  in_packets_speed_after_clean = 0;
         uint64_t  server_udp_speed = 0;
         uint32_t   syn_speed = 0;
         uint64_t time =0;

        time = expired_cycles / fpn_get_clock_hz();
        if(status->in_current_flow > 0)
        {
            in_flow_speed = status->in_current_flow /time ;
        }
        if(status->in_current_packets > 0)
        {
            in_packets_speed = status->in_current_packets / time ;
        }

        //after clean
        if(status->in_current_flow_after_clean > 0)
        {
            //the server speed uint is Bps
            in_flow_speed_after_clean = status->in_current_flow_after_clean / time ;
        }
        if(status->in_current_packets_after_clean > 0)
        {
            in_packets_speed_after_clean = status->in_current_packets_after_clean  / time ;
        }
        //                tmpnode->status.flow_type = IP_FLOW_NORMAL;
        status->in_bps = in_flow_speed * 8;
        status->in_pps = in_packets_speed;
        status->in_bps_after_clean = in_flow_speed_after_clean * 8;
        status->in_pps_after_clean = in_packets_speed_after_clean;
        status->in_current_flow = 0;
        status->in_current_packets = 0;
        status->in_current_flow_after_clean = 0;
        status->in_current_packets_after_clean = 0;
        status->in_last_detect_time = current_time;

        syn_speed = status->syn.current_syn  / time ;
        status->syn.current_syn = 0;
        uint32_t syn_threshold = status->syn.syn_threshold;
        if(syn_speed >= syn_threshold && status->syn.type == TCP_FLOW_NORMAL)
        {
            status->syn.type = TCP_SYN_FLOOD;
            status->syn.flood_start_time = current_time;
        }
        else if(syn_speed < syn_threshold && status->syn.type == TCP_SYN_FLOOD)
        {
            status->syn.type = TCP_FLOW_NORMAL;
            add_attack_log(0, status->server_ip, 0, status->syn.flood_start_time, current_time, 1);
            status->syn.log_num = 0;
        }
        status->syn.syn_pps = syn_speed;
//       server_node->status.syn.last_detect_time = current_time;

        server_udp_speed =  status->udp.current_flow / time;
        uint64_t udp_speed_threshold = (uint64_t)1024 * 1024 * status->udp.udp_threshold / 8;
        if(server_udp_speed >= udp_speed_threshold && status->udp.type == UDP_FLOW_NORMAL)
        {
            status->udp.flood_start_time = current_time;
            status->udp.type = UDP_FLOW_FLOOD;
        }
        else if(server_udp_speed < udp_speed_threshold && status->udp.type == UDP_FLOW_FLOOD)
        {
            status->udp.type = UDP_FLOW_NORMAL;
            add_attack_log(0,status->server_ip, 0,status->udp.flood_start_time,current_time, 2 );
            status->udp.log_num = 0;
        }
        status->udp.bps = server_udp_speed * 8;
        status->udp.current_flow = 0;

    })
}


int32_t add_udp_query_node(uint32_t srcip, uint32_t dstip, uint16_t sport, uint16_t dport, uint32_t *attack_type, uint64_t current_time)
{
    struct query_node *newnode = NULL;
    struct query_node **udp_query_node_tmp = NULL;
    uint32_t port = ((sport<<16)|dport);
    uint64_t k0 = ((uint64_t)srcip<<32) | dstip;
    uint64_t k1 = ((uint64_t)sport<<16) | dport;
    if (SEARCH_HASH_TABLE(udp_query_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, port, UDP_QUERY_TABLE), udp_query_node_tmp,
            (*udp_query_node_tmp)->k[0] == k0 &&
            (*udp_query_node_tmp)->k[1] == k1 ))
    {
        FLUSH_QUERY_TIME((*udp_query_node_tmp)->t, current_time);
        return 0;
    }

    newnode = (struct query_node *)AD_ZALLOC(sizeof(struct query_node));
    if (newnode == NULL)
        return -1;

    newnode->k[0] = k0;
    newnode->k[1] = k1;
    newnode->v = attack_type;
    newnode->t = current_time;
    newnode->e = CLIENT_UDP_UPTIME_TIME;
    newnode->next = NULL;

    *udp_query_node_tmp = newnode;
    return 1;
}

int32_t add_tcp_query_node(uint32_t srcip, uint32_t dstip, uint16_t sport, uint16_t dport, uint32_t *attack_type, uint64_t current_time, uint32_t idle_time)
{
    struct query_node *newnode = NULL;
    struct query_node **tcp_query_node_tmp = NULL;
    uint32_t port = ((sport<<16)|dport);
    uint64_t k0 = ((uint64_t)srcip<<32) | dstip;
    uint64_t k1 = ((uint64_t)sport<<16) | dport;
    if (SEARCH_HASH_TABLE(tcp_query_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, port, TCP_QUERY_TABLE), tcp_query_node_tmp,
            (*tcp_query_node_tmp)->k[0] == k0 &&
            (*tcp_query_node_tmp)->k[1] == k1 ))
    {
        FLUSH_QUERY_TIME((*tcp_query_node_tmp)->t, current_time);
        return 0;
    }

    newnode = (struct query_node *)AD_ZALLOC(sizeof(struct query_node));
    if (newnode == NULL)
        return -1;

    newnode->k[0] = k0;
    newnode->k[1] = k1;
    newnode->v = attack_type;
    newnode->t = current_time;
    newnode->e = idle_time;
    newnode->next = NULL;
    *tcp_query_node_tmp = newnode;
    return 1;
}

int32_t add_tcp_cc_node(uint32_t srcip, uint32_t dstip, uint16_t dport, uint32_t *attack_type, uint64_t current_time)
{
    struct query_node *newnode = NULL;
    struct query_node **tcp_cc_node_tmp = NULL;
    uint64_t k0 = ((uint64_t)srcip<<32) | dstip;

    if (SEARCH_HASH_TABLE(tcp_cc_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, dport, TCP_CC_TABLE), tcp_cc_node_tmp,
            (*tcp_cc_node_tmp)->k[0] == k0 &&
            (*tcp_cc_node_tmp)->k[1] == dport ))
    {
        FLUSH_QUERY_TIME((*tcp_cc_node_tmp)->t, current_time);
        return 0;
    }

    newnode = (struct query_node *)AD_ZALLOC(sizeof(struct query_node));
    if (newnode == NULL)
        return -1;

    newnode->k[0] = k0;
    newnode->k[1] = dport;
    newnode->v = attack_type;
    newnode->t = current_time;
    newnode->next = NULL;
    *tcp_cc_node_tmp = newnode;
    return 1;
}

int32_t del_tcp_cc_node(uint32_t srcip, uint32_t dstip, uint16_t dport)
{
    struct query_node **tmpnode = NULL;
    struct query_node *tcp_cc_node = NULL;
    uint64_t k0 = ((uint64_t)srcip<<32) | dstip;
    if (SEARCH_HASH_TABLE(tcp_cc_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, dport, TCP_CC_TABLE), tmpnode,
            (*tmpnode)->k[0] == k0 &&
            (*tmpnode)->k[1] == dport ))
    {
        tcp_cc_node = *tmpnode;
        *tmpnode = (*tmpnode)->next;
        ad_free_add(tcp_cc_node);
        return 0;
    }
    return -1;
}

void flush_client_udp_info_cache(uint32_t lcore)
{
    struct client_udp_info *udp_info = LCORE_SWITCH_CACHE(client_udp_info, lcore);
    uint32_t srcip = 0;
    uint32_t dstip = 0;
    uint16_t dport = 0;
    int i = 0;
    for (i = 0; i < MAX_CLIENT_UDP_CACHE_LEN; i++)
    {
        struct client_udp_node *client_udp_node = NULL;
        srcip = udp_info[i].src;
        dstip = udp_info[i].dst;
        dport = udp_info[i].dport;
        if (srcip == 0 || dstip == 0 || dport == 0)
        {
            continue;
        }

        if(FAST_SEARCH_HASH_TABLE(client_udp_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, dport, CLIENT_UDP_TABLE), client_udp_node,
                client_udp_node->udp.status.client_ip == srcip &&
                client_udp_node->udp.status.server_ip == dstip &&
                client_udp_node->udp.status.server_port == dport) )
        {
            client_udp_node->udp.status.current_flow += udp_info[i].udp_bytes;
            client_udp_node->udp.status.latest_pkt_time = udp_info[i].update_time;
        }

        bzero(udp_info + i, sizeof(struct client_udp_info));
    }
}
void flush_syn_check_info_cache(uint32_t lcore)
{
    struct syn_check_info *syn_info = LCORE_SWITCH_CACHE(syn_check_info, lcore);
    uint32_t srcip = 0;
    uint32_t dstip = 0;
    uint16_t dport = 0;
    int i = 0;
    for (i = 0; i < MAX_SYN_CHECK_CACHE_LEN; i++)
    {
        struct client_tcp_node *client_tcp_node = NULL;
        srcip = syn_info[i].src;
        dstip = syn_info[i].dst;
        dport = syn_info[i].dport;
        if (srcip == 0 || dstip == 0 || dport == 0)
        {
            continue;
        }

        if(FAST_SEARCH_HASH_TABLE(client_tcp_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, dport, CLIENT_TCP_TABLE), client_tcp_node,
                client_tcp_node->tcp.status.client_ip == srcip &&
                client_tcp_node->tcp.status.server_ip == dstip &&
                client_tcp_node->tcp.status.server_port == dport) )
        {
            client_tcp_node->tcp.check = NORMAL;
            client_tcp_node->tcp.white = IS_WHITE;
            client_tcp_node->tcp.white_effect_time = fp_shared->white_effect_time;
            client_tcp_node->tcp.white_create_time = syn_info[i].update_time;
            client_tcp_node->tcp.status.latest_pkt_time = syn_info[i].update_time;
        }

        bzero(syn_info + i, sizeof(struct syn_check_info));
    }
}

void flush_tcp_query_table(uint64_t current_time)
{
    struct server_node *server_node = NULL;
    struct port_status *ports_status = NULL;
    struct client_tcp_node *client_tcp_node = NULL;
    uint32_t srcip = 0;
    uint32_t dstip = 0;
    uint16_t sport = 0;
    uint16_t dport = 0;
    int server_port_index = 0;
    FOREACH_HASH_TABLE(tcp_query_table, node, TCP_QUERY_TABLE, {
        struct query_node *tmp = NULL;
        if (likely(current_time - (*node)->t < (*node)->e * fpn_get_clock_hz() ))
        {
            continue;
        }

        srcip = (uint32_t)((*node)->k[0] >> 32);
        dstip = (uint32_t)(*node)->k[0];
        sport = (uint16_t)((*node)->k[1] >> 16);
        dport = (uint16_t)(*node)->k[1];

        fp_shared->tcp_session_num -= 1;
        if (search_server_table(dstip, &server_node) != -1) 
        {
            server_node->status.tcp_session_num -= 1;
            server_port_index = search_ordered_port(server_node->status.ports_status, server_node->status.ports_num , ntohs(dport));
            if (server_port_index != -1) {
                ports_status =  &server_node->status.ports_status[server_port_index];
                ports_status->session_num -= 1;
            }
        }
        if (search_client_tcp_table(srcip, dstip, dport, &client_tcp_node, current_time) != -1)
        {
            client_tcp_node->tcp.status.session_num -= 1;
            struct client_port_table *client_port_table = client_tcp_node->tcp.status.client_port_table;
             struct client_port **client_port_tmp = NULL;
            if (SEARCH_HASH_TABLE(client_port_table, IP_HASH_TABLE_INDEX(sport, CLIENT_PORTS_NUM), client_port_tmp,
                    (*client_port_tmp)->status.port == sport))
            {
                struct client_port * client_port = *client_port_tmp;
                *client_port_tmp = (*client_port_tmp)->next;
                ad_free_add(client_port);
            }
        }
        if (ports_status != NULL && client_tcp_node->tcp.status.session_num < ports_status->session_limit_per_client && client_tcp_node -> tcp.cc_attack == CC_ATTACK) {
            del_tcp_cc_node(srcip, dstip, dport);
            client_tcp_node -> tcp.cc_attack = CC_NORMAL;
            del_tmp_black_white_table(tmp_black_table, srcip, dstip, TMP_BLACK_WHITE_TABLE);
            add_attack_log(srcip, dstip, ntohs(dport), client_tcp_node -> tcp.cc_flood_start_time, current_time, 3);
        }

        tmp = *node;
         (*node)->v = NULL;
        *node = (*node)->next;
        ad_free_add(tmp);
    });
}

void flush_udp_query_table(uint64_t current_time)
{
    struct server_node *server_node = NULL;
    struct port_status *ports_status = NULL;
    struct client_udp_node *client_udp_node = NULL;
    uint32_t srcip = 0;
    uint32_t dstip = 0;
    uint16_t sport = 0;
    uint16_t dport = 0;
    int server_port_index = 0;
    FOREACH_HASH_TABLE(udp_query_table, node, UDP_QUERY_TABLE, {
        struct query_node *tmp = NULL;
        if (likely(current_time - (*node)->t < (*node)->e * fpn_get_clock_hz() ))
        {
            continue;
        }

        srcip = (uint32_t)((*node)->k[0] >> 32);
        dstip = (uint32_t)(*node)->k[0];
        sport = (uint16_t)((*node)->k[1] >> 16);
        dport = (uint16_t)(*node)->k[1];

        fp_shared->udp_session_num -= 1;

        if (search_server_table(dstip, &server_node) != -1) 
        {
            server_node->status.udp_session_num -= 1;
            server_port_index = search_ordered_port(server_node->status.udp_ports_status, server_node->status.udp_ports_num , ntohs(dport));
            if (server_port_index != -1) {
                ports_status =  &server_node->status.udp_ports_status[server_port_index];
                ports_status->session_num -= 1;
            }
        }

        if (search_client_udp_table(srcip, dstip, dport, &client_udp_node, current_time) != -1)
        {
            client_udp_node->udp.status.session_num -= 1;
            struct client_port_table *client_port_table = client_udp_node->udp.status.client_port_table;
            struct client_port **client_port_tmp = NULL;
            if (SEARCH_HASH_TABLE(client_port_table, IP_HASH_TABLE_INDEX(sport, CLIENT_PORTS_NUM), client_port_tmp,
                    (*client_port_tmp)->status.port == sport))
            {
                struct client_port * client_port = *client_port_tmp;
                *client_port_tmp = (*client_port_tmp)->next;
                ad_free_add(client_port);
            }
        }

        tmp = *node;
        (*node)->v = NULL;
        *node = (*node)->next;
        ad_free_add(tmp);

    });
}

int32_t add_tmp_black_white_table(struct black_white_table * black_white, uint32_t srcip, uint32_t dstip, uint32_t size)
{
    struct black_white_node *newnode = NULL;
    struct black_white_node **black_white_node_tmp = NULL;

    if (SEARCH_HASH_TABLE(black_white, TUPLE_HASH_TABLE_INDEX(srcip, dstip, 0, size), black_white_node_tmp,
            (*black_white_node_tmp)->black_white.srcip == srcip &&
            (*black_white_node_tmp)->black_white.dstip == dstip)){
        return 0;
    }

     newnode = (struct black_white_node *)AD_ZALLOC(sizeof(struct black_white_node));
    if (newnode == NULL)
        return -1;

    newnode->black_white.srcip = srcip;
    newnode->black_white.dstip = dstip;
    newnode->next = NULL;

    *black_white_node_tmp = newnode;
    return 1;
}

int32_t del_tmp_black_white_table(struct black_white_table * black_white, uint32_t srcip, uint32_t dstip, uint32_t size)
{
    struct black_white_node *tmpnode = NULL;
    struct black_white_node **black_white_node_tmp = NULL;

    if (SEARCH_HASH_TABLE(black_white, TUPLE_HASH_TABLE_INDEX(srcip, dstip, 0, size), black_white_node_tmp,
            (*black_white_node_tmp)->black_white.srcip == srcip &&
            (*black_white_node_tmp)->black_white.dstip == dstip))
    {
        tmpnode = *black_white_node_tmp;
        *black_white_node_tmp = (*black_white_node_tmp)->next;
        ad_free_add(tmpnode);
        return 0;
    }
    return -1;
}

