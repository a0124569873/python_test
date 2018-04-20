#ifndef _FP_ANTI_DDOS_H_
#define _FP_ANTI_DDOS_H_

#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"
#include "ddos_gc.h"
#include "ddos_hash_table.h"

#define TCP_IDLE_TIME 20 //s
#define CLIENT_TCP_UPTIME_TIME 30 //s
#define CLIENT_UDP_UPTIME_TIME 30 //s

#define CYCLES_LIMIT_CODE(cur_tsc, cycles, block) { \
    static uint64_t last_cycles; \
    if (unlikely(cur_tsc - last_cycles >= cycles)) { \
        last_cycles = cur_tsc; \
        block \
    } \
}

#if 1

#define __TRACE(fmt, ...) {printf("%s(%d):%s: "fmt, basename(__FILE__), __LINE__, __func__, ## __VA_ARGS__ );}

#define LIMIT_LOG(seconds, fmt, ...) CYCLES_LIMIT_CODE(sys_tsc, seconds * fpn_get_clock_hz(), { \
    __TRACE(fmt, ## __VA_ARGS__); \
})

#else

#define LIMIT_LOG(cycles, fmt, ...) {}
#define __TRACE() {}

#endif

struct pkt_common_info {
	uint32_t src;
	uint32_t dst;
	uint16_t sport;
	uint16_t dport;
	uint8_t proto;
	uint32_t len;
    uint8_t tcp_flag;
    uint64_t current_time;
    uint16_t dport_index;
} __attribute__((packed));

struct server_flow_info {
    uint32_t ip;
    struct {
        uint32_t bytes;
        uint32_t pkts;
    } in;
    struct {
        uint32_t bytes;
        uint32_t pkts;
    } out;
    struct{
        uint32_t pkts;
    }syn;
    struct{
        uint32_t bytes;
    }udp;
    uint64_t update_time;
}__rte_cache_aligned;

struct client_udp_info {
    uint32_t src;
    uint32_t dst;
    uint16_t dport;
    uint32_t udp_bytes;
    uint64_t update_time;
}__rte_cache_aligned;

struct syn_check_info{
    uint32_t src;
    uint32_t dst;
    uint16_t sport;
    uint16_t dport;
    uint64_t update_time;
}__rte_cache_aligned;

enum udp_action{
    FORWARD,
    DROP,
};

enum syn_action{
    SYN_NORMAL,
    SYN_CHECKING,
    SYN_CHECKING_SEND,
};

struct query_node {
    struct ad_free_obj gc;//28
    uint64_t k[2];                //srcip dstip srcport dstport
    uint32_t *v;
    uint64_t t;
    uint32_t e;
    struct query_node *next;
}__attribute__((packed));//68

struct query_table {
    struct query_node *next;
}__attribute__((packed));

#define UDP_QUERY_TABLE        (1 << 24)
extern struct query_table udp_query_table[UDP_QUERY_TABLE];

#define TCP_QUERY_TABLE        (1 << 24)
extern struct query_table tcp_query_table[TCP_QUERY_TABLE];

#define TCP_CC_TABLE        (1 << 14)
extern struct query_table tcp_cc_table[TCP_CC_TABLE];


#define FLUSH_PACKET_TIME(a,b) do{  \
    if(unlikely( (b-a) > (fpn_rte_tsc_hz>>10) )){   \
        a = b;  \
    }   \
}while(0)

#define FLUSH_QUERY_TIME(a,b) do{  \
    if(unlikely( (b-a) > fpn_rte_tsc_hz )){   \
        a = b;  \
    }   \
}while(0)

struct lcore_cache_data {
#define MAX_SWITCH_BUFFER 2

    struct total_server total_server __rte_cache_aligned;
    
    struct {
        uint8_t id;
#define MAX_LSERVER_FLOW_CACHE_LEN (1<<5)
        struct server_flow_info data[MAX_SWITCH_BUFFER][MAX_LSERVER_FLOW_CACHE_LEN];
    } server_flow_info __rte_cache_aligned;

    struct {
        uint8_t id;
#define MAX_CLIENT_UDP_CACHE_LEN (1<<10)
        struct client_udp_info data[MAX_SWITCH_BUFFER][MAX_CLIENT_UDP_CACHE_LEN];
    } client_udp_info __rte_cache_aligned;

    struct {
        uint8_t id;
#define MAX_SYN_CHECK_CACHE_LEN (1<<10)
        struct syn_check_info data[MAX_SWITCH_BUFFER][MAX_SYN_CHECK_CACHE_LEN];
    } syn_check_info __rte_cache_aligned;
} __rte_cache_aligned;

extern struct lcore_cache_data lcore_cache_data[FPN_MAX_CORES];

#define LCORE_CACHE(field, lcore) lcore_cache_data[lcore].field.data[lcore_cache_data[lcore].field.id]
#define LCORE_SWITCH_CACHE(field, lcore) ({ \
    typeof(lcore_cache_data[lcore].field.data[0][0]) *d = LCORE_CACHE(field, lcore); \
    lcore_cache_data[lcore].field.id = (lcore_cache_data[lcore].field.id + 1)%MAX_SWITCH_BUFFER; \
    d; \
})

#define _BUFFER_ENNTRY_SIZE (sizeof(struct pkt_common_info))
#include "fp-ring-buffer.h"

#define ENTRY_STRUCT_PK_INFO 0
#define ENTRY_FLUSH_STATUS_FLOW_CACHE 1
#define ENTRY_FLUSH_CLIENT_UDP_INFO 2
#define ENTRY_FLUSH_SYN_CHECK_INFO 3

extern struct ring_buffer ring_buffer[FPN_MAX_CORES];
extern void ring_buffer_init(void);
/*
*
*  functions for manage cpu
*
*/

extern int process_info(struct pkt_common_info* pinfo);
extern void flush_server_flow_info_cache(uint32_t lcore);
extern void flush_client_udp_info_cache(uint32_t lcore);
extern void flush_syn_check_info_cache(uint32_t lcore);

extern void ad_free_check(void);
extern void ad_free_init(void);
extern void ad_free_add(void* obj);
extern void ddos_loop_start(void);

/*
*
*  functions for forward cpu
*/
/* query api */
typedef enum {
	PKT_ACTION_UNKNOW,
} pkt_action;

extern pkt_action do_ad_query(struct pkt_common_info* pkt_info);

/*
*
*
*/
void flush_client_tcp_table(uint64_t current_time);
void flush_client_udp_table(uint64_t current_time);
void flush_lcore_server(uint64_t current_time);
void flush_server_table( uint64_t current_time, uint64_t expired_cycles);

void flush_tcp_query_table(uint64_t current_time);
void flush_udp_query_table(uint64_t current_time);

extern void ring_overflow(struct ring_buffer* r, struct buffer_entity* e);
extern void dump_ring_buffer_info(char* buf, int size);
extern void dump_gc_status(char* buf, int size);

static inline int32_t search_udp_query_table(uint32_t srcip,uint32_t dstip ,uint16_t sport, uint16_t dport, uint64_t current_time)
{
    struct query_node *udp_query_node_tmp = NULL;
    uint32_t port = ((sport<<16)|dport);
    uint64_t k0 = ((uint64_t)srcip<<32) | dstip;
    uint64_t k1 = ((uint64_t)sport<<16) | dport;

    if( FAST_SEARCH_HASH_TABLE(udp_query_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, port, UDP_QUERY_TABLE), udp_query_node_tmp,
            udp_query_node_tmp->k[0] == k0 &&
            udp_query_node_tmp->k[1] == k1 ))
    {
        FLUSH_QUERY_TIME(udp_query_node_tmp->t, current_time);
        return (udp_query_node_tmp->v) == NULL ? -1 : (int32_t)*(udp_query_node_tmp->v);
    }
    return -1;
}

static inline int32_t search_tcp_query_table(uint32_t srcip,uint32_t dstip ,uint16_t sport, uint16_t dport, uint64_t current_time)
{
    struct query_node *tcp_query_node_tmp = NULL;
    uint32_t port = ((sport<<16)|dport);
    uint64_t k0 = ((uint64_t)srcip<<32) | dstip;
    uint64_t k1 = ((uint64_t)sport<<16) | dport;

    if( FAST_SEARCH_HASH_TABLE(tcp_query_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, port, TCP_QUERY_TABLE), tcp_query_node_tmp,
            tcp_query_node_tmp->k[0] == k0 &&
            tcp_query_node_tmp->k[1] == k1 ))
    {
        FLUSH_QUERY_TIME(tcp_query_node_tmp->t, current_time);
        return (tcp_query_node_tmp->v) == NULL ? -1 : (int32_t)*(tcp_query_node_tmp->v);
    }
    return -1;
}

static inline int32_t flush_tcp_query(uint32_t srcip,uint32_t dstip ,uint16_t sport, uint16_t dport, uint32_t type)
{
    struct query_node *tcp_query_node_tmp = NULL;
    uint32_t port = ((sport<<16)|dport);
    uint64_t k0 = ((uint64_t)srcip<<32) | dstip;
    uint64_t k1 = ((uint64_t)sport<<16) | dport;

    if( FAST_SEARCH_HASH_TABLE(tcp_query_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, port, TCP_QUERY_TABLE), tcp_query_node_tmp,
            tcp_query_node_tmp->k[0] == k0 &&
            tcp_query_node_tmp->k[1] == k1 ))
    {
        if (*(tcp_query_node_tmp->v) != type){
               *(tcp_query_node_tmp->v) = type;
        }
        return 1;
    }
    return -1;
}

static inline int32_t search_tcp_cc_table(uint32_t srcip,uint32_t dstip, uint16_t dport, uint64_t current_time)
{
    struct query_node *tcp_cc_node_tmp = NULL;
    uint64_t k0 = ((uint64_t)srcip<<32) | dstip;

    if( FAST_SEARCH_HASH_TABLE(tcp_cc_table, TUPLE_HASH_TABLE_INDEX(srcip, dstip, dport, TCP_CC_TABLE), tcp_cc_node_tmp,
            tcp_cc_node_tmp->k[0] == k0 &&
            tcp_cc_node_tmp->k[1] == dport ))
    {
        return 0;
//        FLUSH_QUERY_TIME(tcp_cc_node_tmp->t, current_time);
//        return tcp_cc_node_tmp->v;
    }
    return -1;
}


#endif // _FP_ANTI_DDOS_H_