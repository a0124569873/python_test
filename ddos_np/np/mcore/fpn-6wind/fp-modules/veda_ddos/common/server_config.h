#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

#include "server_node_define.h"

#define HOST_MASK 0x1
#define HOST_PARA_MASK 0x2
#define TCP_PORT_PROTECT_MASK 0x4
#define UDP_PORT_PROTECT_MASK 0x8
#define BLACK_WHITE_GROUP_MASK 0x10
#define SERVER_CONFIG_MASK_ALL 0x1f

struct host_param {
	/*input traffic bandwidth threshold, Mbps*/
	uint32_t flow_in;

	/*input packet number threshold,  packet number per second*/
	uint32_t pkt_in;

	/*Output traffic bandwidth threshold, Mbps*/
	uint32_t flow_out;

	/*Output packet number threshold,  packet number per second*/
	uint32_t pkt_out;

	/*flow policy:  1: Ignore all traffic; 2: Black all traffic; 3:Traffic will be blacked when exceed threshold */
	uint32_t flow_pol;
};


struct host_protect_param {
	/*syn flood threshold, syn packet number per second*/
	uint32_t syn_thres;

	/*syn flood single server threshold, syn packet number per second*/
	uint32_t syn_ss_thres;

	/*ACK&RST Flood threshold, ack or rst packet number per second*/
	uint32_t ack_rst_thres;

	/*udp flood threshold, packet number per second */
	uint32_t udp_thres;

	/*icmp flood threshold, packet number per second */
	uint32_t icmp_thres;

	/*TCP input connection number threshold, connection number per second*/
	uint32_t tcp_con_in;

	/*TCP output connection number threshold, connection number per second*/
	uint32_t tcp_con_out;

	/*TCP connection number threshold per IP, connection number per second*/
	uint32_t tcp_con_ip;

	/*tcp connection frequency, connection  number per second */
	uint32_t tcp_frequency;

	/*tcp connection idle time threshold, connection will be reset if timer expired */
	uint32_t tcp_idle;

	/*udp connection threshold, connection number per second*/
	uint32_t udp_conn;

	/*udp connection frequency, connection  number per second*/
	uint32_t udp_frequency;

	/*icmp connection frequency, connection  number per second */
	uint32_t icmp_frequency;
};

struct tcp_port_protect_param {
	/*port start*/
	uint32_t start;

	/*port end*/
	uint32_t end;

	/*Ports open or disable; 0: disable; 1: Open*/
	uint32_t on_off;

	/*attack frequency*/
	uint32_t attack_frequency;

	/*connection limitation*/
	uint32_t connection_limit;

 	/*1: Connection expired; 2: Delay submit; 4: Blacked when exceed threshold*/
	uint32_t protection_mode;
};

struct udp_port_protect_param {
	/*port start*/
	uint32_t start;

	/*port end*/
	uint32_t end;

	/*Ports open or disable; 0: disable; 1: Open*/
	uint32_t on_off;

	/*attack frequency*/
	uint32_t attack_frequency;

	/*packet frequency, number per second*/
	uint32_t packet_frequency;

 	/*1: Open port; 2: Sync connection; 4: Delay submit; 8: TTL verify*/
	uint32_t protection_mode;
};

struct server_config
{
	struct host_param host_para;
	struct host_protect_param  host_prot_para;

	uint32_t tcp_port_num;
	struct tcp_port_protect_param tcp_prot_para[SERVER_PORTS_NUM];

	uint32_t udp_port_num;
	struct udp_port_protect_param udp_prot_para[SERVER_PORTS_NUM];

	int32_t black_num; /*black table group number: 0-15, -1 means black table is disabled*/
	int32_t white_num; /*white table group number: 0-15, -1 means white table is disabled*/
};


extern struct ddos_shm_info fp_ddos_shm[DDOS_SHM_TOTAL];

extern void *fp_shm_addr[DDOS_SHM_TOTAL];

extern struct black_white_table  black_table[BLACK_WHITE_NUM][BLACK_WHITE_TABLE];
extern struct black_white_table  white_table[BLACK_WHITE_NUM][BLACK_WHITE_TABLE];
extern struct black_white_table tmp_black_table[TMP_BLACK_WHITE_TABLE];
extern struct black_white_table tmp_white_table[TMP_BLACK_WHITE_TABLE];

extern char host_key[MAX_HOST_ITEM_NUM][16];
extern char host_param_key[MAX_HOST_PARAM_ITEM_NUM][16];
extern char tcp_port_prot_key[MAX_TCP_PORT_PROTECT_ITEM_NUM][16];
extern char udp_port_prot_key[MAX_UDP_PORT_PROTECT_ITEM_NUM][16];
extern int32_t del_tmp_black_white_table(struct black_white_table * black_white, uint32_t srcip, uint32_t dstip, uint32_t size);

void init_server_node(uint32_t dstip, uint64_t current_time, struct server_config *p_server_cfg, struct server_node *newnode);
int32_t add_server_node(uint32_t dstip, struct server_config *p_server_cfg);
int32_t update_server_node(uint32_t dstip, uint32_t mask, struct server_config *p_server_cfg);
int32_t delete_server_node(uint32_t dstip);
int32_t add_black_white_node(uint32_t srcip, uint32_t dstip, uint16_t dport, uint32_t type, int32_t grp);
int32_t delete_black_white_node(uint32_t srcip, uint32_t dstip, uint16_t dport, uint32_t type, int32_t grp);
int32_t create_ddos_server_info(void);
int32_t ddos_server_config(void);
int32_t ddos_black_white_config(void);
void* fp_configuration_shm_lookup(key_t key);

void show_black_node(void);
void show_white_node(void);

int32_t delete_temp_black_white_node(uint32_t srcip, uint32_t dstip, uint32_t type);
int32_t get_temp_black_white_info(void);

int32_t show_server_config(uint32_t dstip);
void* fp_ddos_shm_create(struct ddos_shm_info *ddos_shm);

void add_jason_to_shm_test(void *fp_config);
//void add_jason_to_shm_b_w_test(void *fp_config);
#endif