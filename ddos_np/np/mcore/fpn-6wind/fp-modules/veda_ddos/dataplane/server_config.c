#include <sys/ipc.h>
#include <sys/shm.h>
#include <error.h>

#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"

#include "syn_flood_deal.h"
#include "udp_flood_deal.h"
#include "server_ip_port_deal.h"
#include "server_node_define.h"
#include "server_flow_deal.h"
#include "black_white.h"

#include "../common/cJSON.h"
#include "../common/server_config.h"
#include "../fp-anti-ddos.h"

struct ddos_shm_info fp_ddos_shm[DDOS_SHM_TOTAL] = {
	{"ddos_config", "/tmp/ddos_config", 1, 32 * 1024 * 1024},
	{"ddos_status", "/tmp/ddos_status", 1, 32 * 1024 * 1024},
	{"ddos_log", "/tmp/ddos_log", 1, 16 * 1024 * 1024},
	{"ddos_tmp_b_w", "/tmp/ddos_tmp_b_w", 1, 32 * 1024 * 1024}
};

void *fp_shm_addr[DDOS_SHM_TOTAL];

extern const char *fpdebug_inet_ntop(int af, const void *src, char *dst,
				     size_t size);
extern int fpdebug_inet_pton(int af, const char *src, void *dst);
void add_system_status_to_json(cJSON *root);
void add_server_status_to_json(cJSON *root);

void init_server_node(uint32_t dstip, uint64_t current_time, struct server_config *p_server_cfg, struct server_node *newnode)
{
	uint32_t  port_num = 0;
	
	newnode->status.server_ip = dstip;
	//newnode->status.in_latest_pkt_time = 0;
//	newnode->status.flow = 0;
//	newnode->status.flow_in_black = 0;
//	newnode->status.flow_after_clean = 0;
	newnode->status.flow_strategy = FLOW_THRESHOLD;
	newnode->status.flow_type = IP_FLOW_NORMAL;

	newnode->status.syn.type = TCP_FLOW_NORMAL;
	//newnode->status.syn.syn_threshold = syn_threshold;
	newnode->status.syn.last_detect_time = current_time;
//	newnode->status.syn.last_syn = 0;
	//newnode->status.syn.current_syn = 0;
	//newnode->status.syn.current_syn_afterclean = 0;

	newnode->status.udp.type = UDP_FLOW_NORMAL;
	//newnode->status.udp.udp_threshold = udp_threshold;
	newnode->status.udp.last_detect_time = current_time;
//	newnode->status.udp.last_flow = 0;
	//newnode->status.udp.current_flow = 0;
	//newnode->status.udp.current_flow_afterclean = 0;
	newnode->next = NULL;


	newnode->status.in_ip_threshold = p_server_cfg->host_para.flow_in;
	//newnode->status.in_pkt_threshold = p_server_cfg->host_para.pkt_in;
	newnode->status.out_ip_threshold = p_server_cfg->host_para.flow_out;
	//newnode->status.out_pkt_threshold = p_server_cfg->host_para.pkt_out;
	newnode->status.flow_strategy = (enum flow_strategy)p_server_cfg->host_para.flow_pol;

	newnode->status.syn.syn_threshold = p_server_cfg->host_prot_para.syn_thres;
	newnode->status.udp.udp_threshold = p_server_cfg->host_prot_para.udp_thres;
	newnode->status.tcp_idle_time = p_server_cfg->host_prot_para.tcp_idle;

	newnode->status.black_num = p_server_cfg->black_num;
	newnode->status.white_num = p_server_cfg->white_num;

#if 1
	if(p_server_cfg->tcp_port_num > SERVER_PORTS_NUM)
	{
		printf("Too much configured tcp port number:%d!\n", p_server_cfg->tcp_port_num);
		p_server_cfg->tcp_port_num = SERVER_PORTS_NUM;
	}

	for(port_num = 0;  port_num < p_server_cfg->tcp_port_num; port_num++)
	{
		newnode->status.ports_status[port_num].start = p_server_cfg->tcp_prot_para[port_num].start;
		newnode->status.ports_status[port_num].end = p_server_cfg->tcp_prot_para[port_num].end;
		newnode->status.ports_status[port_num].on_off = p_server_cfg->tcp_prot_para[port_num].on_off;
		newnode->status.ports_status[port_num].session_limit_per_client
			=  p_server_cfg->tcp_prot_para[port_num].connection_limit;
			
		newnode->status.ports_status[port_num].session_beyond_black 
			= ((p_server_cfg->tcp_prot_para[port_num].protection_mode > 1) ? 1:0);
	}
	newnode->status.ports_num = p_server_cfg->tcp_port_num;


	if(p_server_cfg->udp_port_num > SERVER_PORTS_NUM)
	{
		printf("Too much configured udp port number:%d!\n", p_server_cfg->udp_port_num);
		p_server_cfg->udp_port_num = SERVER_PORTS_NUM;
	}

	for(port_num = 0; port_num < p_server_cfg->udp_port_num; port_num++)
	{
		newnode->status.udp_ports_status[port_num].start = p_server_cfg->udp_prot_para[port_num].start;
		newnode->status.udp_ports_status[port_num].end = p_server_cfg->udp_prot_para[port_num].end;
		newnode->status.udp_ports_status[port_num].on_off = p_server_cfg->udp_prot_para[port_num].on_off;
		//newnode->status.ports_status[port_num].session_limit_per_client
		//	=  p_server_cfg->udp_prot_para.connection_limit;
	}

	newnode->status.udp_ports_num = p_server_cfg->udp_port_num;

#endif
	newnode->next = NULL;
}

int32_t add_server_node(uint32_t dstip, struct server_config *p_server_cfg)
{
	uint32_t  port_num = 0;
	struct server_node *newnode = NULL;
	struct server_node **tmpnode = NULL;

	if(SEARCH_HASH_TABLE(server_table, IP_HASH_TABLE_INDEX(dstip, SERVER_TABLE), tmpnode, (*tmpnode)->status.server_ip == dstip)) {
		(*tmpnode)->status.in_ip_threshold = p_server_cfg->host_para.flow_in;
		//tmpnode->status.in_pkt_threshold = p_server_cfg->host_para.pkt_in;
		(*tmpnode)->status.out_ip_threshold = p_server_cfg->host_para.flow_out;
		//tmpnode->status.out_pkt_threshold = p_server_cfg->host_para.pkt_out;
		(*tmpnode)->status.flow_strategy = (enum flow_strategy)p_server_cfg->host_para.flow_pol;

		(*tmpnode)->status.syn.syn_threshold = p_server_cfg->host_prot_para.syn_thres;
		(*tmpnode)->status.udp.udp_threshold = p_server_cfg->host_prot_para.udp_thres;
		(*tmpnode)->status.tcp_idle_time = p_server_cfg->host_prot_para.tcp_idle;

		if(p_server_cfg->tcp_port_num > SERVER_PORTS_NUM)
		{
			printf("Too much configured tcp port number:%d!\n", p_server_cfg->tcp_port_num);
			return -1;
		}

		for(port_num = 0;  port_num < p_server_cfg->tcp_port_num; port_num++)
		{
			(*tmpnode)->status.ports_status[port_num].start = p_server_cfg->tcp_prot_para[port_num].start;
			(*tmpnode)->status.ports_status[port_num].end = p_server_cfg->tcp_prot_para[port_num].end;
			(*tmpnode)->status.ports_status[port_num].on_off = p_server_cfg->tcp_prot_para[port_num].on_off;
			(*tmpnode)->status.ports_status[port_num].session_limit_per_client
				=  p_server_cfg->tcp_prot_para[port_num].connection_limit;
			(*tmpnode)->status.ports_status[port_num].session_beyond_black 
				= ((p_server_cfg->tcp_prot_para[port_num].protection_mode > 1) ? 1:0);
		}
		(*tmpnode)->status.ports_num = port_num;

		if(p_server_cfg->udp_port_num > SERVER_PORTS_NUM)
		{
			printf("Too much configured udp port number:%d!\n", p_server_cfg->udp_port_num);
			return -1;
		}

		for(port_num = 0; port_num < p_server_cfg->udp_port_num; port_num++)
		{
			(*tmpnode)->status.udp_ports_status[port_num].start = p_server_cfg->udp_prot_para[port_num].start;
			(*tmpnode)->status.udp_ports_status[port_num].end = p_server_cfg->udp_prot_para[port_num].end;
			(*tmpnode)->status.udp_ports_status[port_num].on_off = p_server_cfg->udp_prot_para[port_num].on_off;
			//newnode->status.ports_status[port_num].session_limit_per_client
			//	=  p_server_cfg->udp_prot_para.connection_limit;
		}

		(*tmpnode)->status.udp_ports_num = port_num;

		(*tmpnode)->status.black_num = p_server_cfg->black_num;
		(*tmpnode)->status.white_num = p_server_cfg->white_num;

		return -1;
	}

	newnode = (struct server_node *)AD_ZALLOC(sizeof(struct server_node));

	if (!newnode) {
		return -1;
	}

	init_server_node(dstip, sys_tsc, p_server_cfg, newnode);

	*tmpnode = newnode;
	return 0;
}

int32_t update_server_node(uint32_t dstip, uint32_t mask, struct server_config *p_server_cfg)
{
	struct server_node **tmpnode = NULL;
	uint32_t port_num = 0;

	if(!SEARCH_HASH_TABLE(server_table, IP_HASH_TABLE_INDEX(dstip, SERVER_TABLE), tmpnode, (*tmpnode)->status.server_ip == dstip)) {
		return -1;
	}

	if(mask & HOST_MASK)
	{
		(*tmpnode)->status.in_ip_threshold = p_server_cfg->host_para.flow_in;
		//tmpnode->status.in_pkt_threshold = p_server_cfg->host_para.pkt_in;
		(*tmpnode)->status.out_ip_threshold = p_server_cfg->host_para.flow_out;
		//tmpnode->status.out_pkt_threshold = p_server_cfg->host_para.pkt_out;
		(*tmpnode)->status.flow_strategy = (enum flow_strategy)p_server_cfg->host_para.flow_pol;
	}

	if(mask & HOST_PARA_MASK)
	{
		(*tmpnode)->status.syn.syn_threshold = p_server_cfg->host_prot_para.syn_thres;
		(*tmpnode)->status.udp.udp_threshold = p_server_cfg->host_prot_para.udp_thres;
	}

	if(mask & TCP_PORT_PROTECT_MASK)
	{
		if(p_server_cfg->tcp_port_num > SERVER_PORTS_NUM)
		{
			printf("Too much configured tcp port number:%d!\n", p_server_cfg->tcp_port_num);
			p_server_cfg->tcp_port_num = SERVER_PORTS_NUM;
		}

		for(port_num = 0;  port_num < p_server_cfg->tcp_port_num; port_num++)
		{
			(*tmpnode)->status.ports_status[port_num].start = p_server_cfg->tcp_prot_para[port_num].start;
			(*tmpnode)->status.ports_status[port_num].end = p_server_cfg->tcp_prot_para[port_num].end;
			(*tmpnode)->status.ports_status[port_num].on_off = p_server_cfg->tcp_prot_para[port_num].on_off;
			(*tmpnode)->status.ports_status[port_num].session_limit_per_client
				=  p_server_cfg->tcp_prot_para[port_num].connection_limit;
			(*tmpnode)->status.ports_status[port_num].session_beyond_black 
				= ((p_server_cfg->tcp_prot_para[port_num].protection_mode > 1) ? 1:0);
		}

		(*tmpnode)->status.ports_num = port_num;
	}

	if(mask & UDP_PORT_PROTECT_MASK)
	{
		if(p_server_cfg->udp_port_num > SERVER_PORTS_NUM)
		{
			printf("Too much configured udp port number:%d!\n", p_server_cfg->udp_port_num);
			p_server_cfg->udp_port_num = SERVER_PORTS_NUM;
		}
		for(port_num = 0; port_num < p_server_cfg->udp_port_num; port_num++)
		{
			(*tmpnode)->status.udp_ports_status[port_num].start = p_server_cfg->udp_prot_para[port_num].start;
			(*tmpnode)->status.udp_ports_status[port_num].end = p_server_cfg->udp_prot_para[port_num].end;
			(*tmpnode)->status.udp_ports_status[port_num].on_off = p_server_cfg->udp_prot_para[port_num].on_off;
		}

		(*tmpnode)->status.udp_ports_num = port_num;
	}

	if(mask & BLACK_WHITE_GROUP_MASK)
	{
		(*tmpnode)->status.black_num = p_server_cfg->black_num;
		(*tmpnode)->status.white_num = p_server_cfg->white_num;
	}

	return 0;
}


int32_t show_server_config(uint32_t dstip)
{
	uint32_t port_num = 0;
	char ipstr[16] = {0};
	struct server_node **tmpnode = NULL;

	fpdebug_inet_ntop(AF_INET, &dstip, ipstr, sizeof(ipstr));

	if(!SEARCH_HASH_TABLE(server_table, IP_HASH_TABLE_INDEX(dstip, SERVER_TABLE), tmpnode, (*tmpnode)->status.server_ip == dstip)) {
		printf("Cannot find node of ip:%s.\n", ipstr);
		return -1;
	}

	printf("Configuration of server:%s:\n", ipstr);

	printf("in_ip_threshold:%d, flow_strategy:%d, syn_threshold:%d, udp_threshold:%d, tcp_idle_time:%d, black_table_num:%d, white_table_num:%d.\n",
		(*tmpnode)->status.in_ip_threshold,
		(*tmpnode)->status.flow_strategy,
		(*tmpnode)->status.syn.syn_threshold,
		(*tmpnode)->status.udp.udp_threshold,
		(*tmpnode)->status.tcp_idle_time,
		(*tmpnode)->status.black_num,
		(*tmpnode)->status.white_num);

	printf("TCP port set number:%d\n", (*tmpnode)->status.ports_num);
	for(port_num = 0;  port_num < (*tmpnode)->status.ports_num; port_num++)
	{
		printf("No:%d --- start:%d, end:%d, on_off:%d, conn_limit:%d, session_beyond_black:%d\n", port_num,
			(*tmpnode)->status.ports_status[port_num].start,
			(*tmpnode)->status.ports_status[port_num].end,
			(*tmpnode)->status.ports_status[port_num].on_off,
			(*tmpnode)->status.ports_status[port_num].session_limit_per_client,
			(*tmpnode)->status.ports_status[port_num].session_beyond_black);
	}
	printf("\nUDP port set number:%d\n", (*tmpnode)->status.udp_ports_num);
	for(port_num = 0;  port_num < (*tmpnode)->status.udp_ports_num; port_num++)
	{
		printf("No:%d --- start:%d, end:%d, on_off:%d, conn_limit:%d\n", port_num,
			(*tmpnode)->status.udp_ports_status[port_num].start,
			(*tmpnode)->status.udp_ports_status[port_num].end,
			(*tmpnode)->status.udp_ports_status[port_num].on_off,
			(*tmpnode)->status.udp_ports_status[port_num].visit_limit_per_client);
	}

	printf("\n");

	return 0;
}

inline int32_t delete_server_node(uint32_t dstip)
{
	struct server_node **tmpnode = NULL;
	struct server_node *node = NULL;

	if(!SEARCH_HASH_TABLE(server_table, IP_HASH_TABLE_INDEX(dstip, SERVER_TABLE), tmpnode, (*tmpnode)->status.server_ip == dstip)) {
		return -1;
	}

	node = *tmpnode;
	*tmpnode = (*tmpnode)->next;
	ad_free_add(node);
	return 0;
}


inline int32_t add_black_white_node(uint32_t srcip, uint32_t dstip, uint16_t dport, uint32_t type, int32_t grp)
{
	struct black_white_node **tmpnode = NULL;
	struct black_white_node *newnode = NULL;
	struct black_white_table *table = NULL;

	if(grp >= BLACK_WHITE_NUM || grp < 0)
	{
		printf("Invalid grp number:%u.\n", grp);
		return -1;
	}
	if(IS_BLACK == type)
		table =  black_table[grp];
	else
		table =  white_table[grp];

	if(SEARCH_HASH_TABLE((table), IP_HASH_TABLE_INDEX(srcip, BLACK_WHITE_TABLE), tmpnode,
		((*tmpnode)->black_white.srcip == srcip) ) ) {
		return -1;
	}

	newnode = (struct black_white_node *)AD_ZALLOC(sizeof(struct black_white_node));

	if (!newnode) {
		return -1;
	}
	
	newnode->black_white.srcip = srcip;
	newnode->black_white.dstip = dstip;
	newnode->black_white.dport = dport;
	newnode->black_white.type = type;
	newnode->next = NULL;
	*tmpnode = newnode;

	return 0;
}

inline int32_t delete_black_white_node(uint32_t srcip, uint32_t dstip, uint16_t dport, uint32_t type, int32_t grp)
{
	struct black_white_node **tmpnode = NULL;
	struct black_white_node *node = NULL;
	struct black_white_table *table = NULL;

	if(grp >= BLACK_WHITE_NUM || grp < 0)
	{
		printf("Invalid grp number:%u.\n", grp);
		return -1;
	}
	if(IS_BLACK == type)
		table =  black_table[grp];
	else
		table =  white_table[grp];

	if(!SEARCH_HASH_TABLE(table, IP_HASH_TABLE_INDEX(srcip, BLACK_WHITE_TABLE), tmpnode,
		((*tmpnode)->black_white.srcip == srcip) ) ) {
		return -1;
	}

	node = *tmpnode;
	*tmpnode = (*tmpnode)->next;
	ad_free_add(node);

	return 0;
}

void show_black_node(void)
{
	char srcip[30] = {0};
	char dstip[30] = {0};
	uint16_t dport = 0;
	uint32_t count = 0;

	printf("--->Black table info:\n");
	for(int grp = 0; grp < BLACK_WHITE_NUM; grp++)
	{		
		count = 0;
		FASAT_FOREACH_HASH_TABLE(black_table[grp], tmpnode, BLACK_WHITE_TABLE, {
			bzero(srcip, sizeof(srcip));
			IP_2_STR(tmpnode->black_white.srcip, srcip, sizeof(srcip));

			bzero(dstip, sizeof(dstip));
			IP_2_STR(tmpnode->black_white.dstip, dstip, sizeof(dstip));

			dport = ntohs(tmpnode->black_white.dport);

			printf("Grp:%d, No:%u: srcip==%s, dstip==%s, dport==%d\n", grp, count++, srcip, dstip, dport);
		})
		if(count > 0)
			printf("\n");
	}
}

void show_white_node(void)
{
	char srcip[30] = {0};
	char dstip[30] = {0};
	uint16_t dport = 0;
	uint32_t count = 0; 

	printf("--->White table info:\n");
	for(int grp = 0; grp < BLACK_WHITE_NUM; grp++)
	{
		count = 0;
		FASAT_FOREACH_HASH_TABLE(white_table[grp], tmpnode, BLACK_WHITE_TABLE, {
			bzero(srcip, sizeof(srcip));
			IP_2_STR(tmpnode->black_white.srcip, srcip, sizeof(srcip));

			bzero(dstip, sizeof(dstip));
			IP_2_STR(tmpnode->black_white.dstip, dstip, sizeof(dstip));

			dport = ntohs(tmpnode->black_white.dport);

			printf("Grp:%d, No:%u: srcip==%s, dstip==%s, dport==%d\n", grp, count++, srcip, dstip, dport);

		})
		if(count > 0)
			printf("\n");
	}
}

void add_system_status_to_json(cJSON *root)
{
	cJSON *system = NULL;
	cJSON *item = NULL;

	struct total_status *sys_status = &fp_shared->total.status;

	system = cJSON_CreateObject();

	item = cJSON_CreateNumber(sys_status->in_bps);
	cJSON_AddItemToObject(system, "in_bps", item);

	item = cJSON_CreateNumber(sys_status->out_bps);
	cJSON_AddItemToObject(system, "out_bps", item);

	item = cJSON_CreateNumber(sys_status->in_pps);
	cJSON_AddItemToObject(system, "in_pps", item);

	item = cJSON_CreateNumber(sys_status->out_pps);
	cJSON_AddItemToObject(system, "out_pps", item);

	item = cJSON_CreateNumber(fp_shared->tcp_session_num);
	cJSON_AddItemToObject(system, "tcp_conn_in", item);

	item = cJSON_CreateNumber(0);
	cJSON_AddItemToObject(system, "tcp_conn_out", item);

	item = cJSON_CreateNumber(fp_shared->udp_session_num);
	cJSON_AddItemToObject(system, "udp_conn", item);

	item = cJSON_CreateNumber(sys_status->in_bps_after_clean);
	cJSON_AddItemToObject(system, "in_bps_after_clean", item);

	item = cJSON_CreateNumber(sys_status->out_bps_after_clean);
	cJSON_AddItemToObject(system, "out_bps_after_clean", item);

	item = cJSON_CreateNumber(sys_status->in_pps_after_clean);
	cJSON_AddItemToObject(system, "in_pps_after_clean", item);

	item = cJSON_CreateNumber(sys_status->out_pps__after_clean);
	cJSON_AddItemToObject(system, "out_pps_after_clean", item);

	cJSON_AddItemToObject(root, "system", system);

}

void add_server_status_to_json(cJSON *root)
{
	char ipstr[16] = {0};

	//cJSON *server_status_obj = NULL;

	cJSON *item = NULL;
	cJSON *server = NULL;
	struct server_status *server_status = NULL;

	FASAT_FOREACH_HASH_TABLE(server_table, server_node, SERVER_TABLE, {
		server_status = &server_node->status;
		server = cJSON_CreateObject();
		if(server == NULL) {
			continue;
		}

		fpdebug_inet_ntop(AF_INET, &server_status->server_ip, ipstr, sizeof(ipstr));

		item = cJSON_CreateNumber(server_status->in_bps);
		cJSON_AddItemToObject(server, "in_bps", item);

		item = cJSON_CreateNumber(server_status->out_bps);
		cJSON_AddItemToObject(server, "out_bps", item);

		item = cJSON_CreateNumber(server_status->in_pps);
		cJSON_AddItemToObject(server, "in_pps", item);

		item = cJSON_CreateNumber(server_status->out_pps);
		cJSON_AddItemToObject(server, "out_pps", item);

		item = cJSON_CreateNumber(server_status->tcp_session_num);
		cJSON_AddItemToObject(server, "tcp_conn_in", item);

		item = cJSON_CreateNumber(0);
		cJSON_AddItemToObject(server, "tcp_conn_out", item);

		item = cJSON_CreateNumber(server_status->udp_session_num);
		cJSON_AddItemToObject(server, "udp_conn", item);

		item = cJSON_CreateNumber(server_status->in_bps_after_clean);
		cJSON_AddItemToObject(server, "in_bps_after_clean", item);

		item = cJSON_CreateNumber(server_status->out_bps_after_clean);
		cJSON_AddItemToObject(server, "out_bps_after_clean", item);

		item = cJSON_CreateNumber(server_status->in_pps_after_clean);
		cJSON_AddItemToObject(server, "in_pps_after_clean", item);

		item = cJSON_CreateNumber(server_status->out_pps__after_clean);
		cJSON_AddItemToObject(server, "out_pps_after_clean", item);

		//cJSON_AddItemToObject(server_status_obj, ipstr, server);

		cJSON_AddItemToObject(root, ipstr, server);
	})
}

int32_t create_ddos_server_info(void)
{
	char * out = NULL;
	cJSON *root = NULL;
	void *fp_status_shm = fp_shm_addr[DDOS_SHM_STATUS];

	if(NULL == fp_status_shm)
	{
		return -1;
	}

	root = cJSON_CreateObject();
	if (root == NULL)
	{
		return -1;
	}

	add_system_status_to_json(root);

	add_server_status_to_json(root);

	//out = cJSON_Print(root);
	out = cJSON_PrintUnformatted(root);
	if(out != NULL)
	{
		memcpy(fp_status_shm, out, strlen(out));
	}
	else
	{
		printf("Jason string is NULL when create ddos server info.\n");
		return -1;
	}

	cJSON_Delete(root);
	if(out != NULL)
		free(out);
	return 0;
}

void* fp_ddos_shm_create(struct ddos_shm_info *ddos_shm )
{	
	int shm_id;
	void *p_config = NULL;	
	char cmd[64];

	snprintf(cmd, sizeof(cmd), "mkdir -p %s", ddos_shm->path);
	system(cmd);

	key_t key = ftok(ddos_shm->path, ddos_shm->id);
	if(key == -1)
	{
		perror("ftok error");
		return NULL;
	}

	printf("key=%d\n",key);

	shm_id = shmget(key, ddos_shm->size, IPC_CREAT|0666);
	if(shm_id == -1)
	{
		perror("shmget error");
		return NULL;
	}
	//printf("shm_id=%d\n", shm_id);

	p_config = (void *)shmat(shm_id,NULL,0);

	if(p_config == NULL)
	{
		perror("shmat addr error");
		return NULL ;
	}

	printf("shared memory for %s created.\n",  ddos_shm->name);

	return p_config;
}

int32_t ddos_server_config(void)
{
	cJSON *root = NULL;
	cJSON *server_config = NULL;
	cJSON *item = NULL;
	cJSON *server = NULL;
	cJSON *host = NULL;
	cJSON *host_para = NULL;
	cJSON *tcp_port_prot = NULL;
	cJSON *udp_port_prot = NULL;
	cJSON *port_item = NULL;
	cJSON *b_w_grp_info = NULL;

	struct server_config server_cfg;
	struct server_config *p_server_cfg = &server_cfg;
	//HOST_PARAM *phost = NULL;
	//HOST_PROTECT_PARAM *phost_prot = NULL;
	//TCP_PORT_PROTECT_PARAM *ptcp = NULL;
	//UDP_PORT_PROTECT_PARAM *pudp = NULL;
	uint32_t dstip = 0;
	uint32_t *pvalue = NULL;
	uint32_t i = 0, j = 0;
	uint32_t size = 0, port_size = 0, iport = 0;

	int32_t mask = 0;
	char ipstr[32] = {0};
	char oper[8] = {0};
	void *fp_config_shm = fp_shm_addr[DDOS_SHM_CONFIG];
	
	if(NULL == fp_config_shm)
	{
		return -1;
	}


	//printf("fp_config_shm: %s.\n", (char *)fp_config_shm);

	root = cJSON_Parse((char *)fp_config_shm);
	if(root == NULL)
	{
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		return 0;
	}

	server_config = cJSON_GetObjectItem(root, "server");
	if(server_config != NULL)
	{
		size = cJSON_GetArraySize(server_config);
		for(i = 0; i < size; i++)
		{
			server = cJSON_GetArrayItem(server_config, i);
			if(server == NULL)
				continue;

			bzero(p_server_cfg, sizeof(struct server_config));
			p_server_cfg->black_num = -1;
			p_server_cfg->white_num = -1;

			item = cJSON_GetObjectItem(server,"ip");

			bzero(ipstr, sizeof(ipstr));
			snprintf(ipstr, sizeof(ipstr) - 1, "%s", item->valuestring);
			fpdebug_inet_pton(AF_INET, ipstr, &dstip);
			//printf("ip:%s.\n", ipstr);

			item = cJSON_GetObjectItem(server,"oper");
			bzero(oper, sizeof(oper));
			snprintf(oper, sizeof(oper) - 1, "%s", item->valuestring);
			//printf("oper:%s.\n", oper);

			if(!strcmp(oper, "del"))
			{				
				delete_server_node(dstip);
			}
			else
			{
				item = cJSON_GetObjectItem(server, "mask");
				mask = item->valueint;
				//printf("mask:%d.\n", mask);

				if(mask <= 0)
				{
					printf("Invalid mask:%d for ip:%s.\n", mask, ipstr);
					continue;
				}

				if(mask & HOST_MASK)
				{
					/*get host parameters*/
					host = cJSON_GetObjectItem(server,"host");

					if(NULL == host)
					{
						//printf("Cannot get host!\n");
						//continue;
					}
					else
					{
						pvalue = (uint32_t *)&p_server_cfg->host_para;
						for(j = 0; j < MAX_HOST_ITEM_NUM; j++)
						{
							item = cJSON_GetObjectItem(host, host_key[j]);
							//printf("host: item value:%d!\n", item->valueint);
							if(NULL == item) {							
								printf("Cannot get item from key:%s!\n", host_key[j]);
								continue;
							}
							else
								*pvalue++ = item->valueint;
						}
					}
				}

				if(mask & HOST_PARA_MASK)
				{
					/*get host_para parameters*/
					host_para = cJSON_GetObjectItem(server,"host_para");

					if(NULL == host_para)
					{
						//printf("Cannot get host_para!\n");
						//continue;
					}
					else
					{					
						pvalue = (uint32_t *)&p_server_cfg->host_prot_para;
						for(j = 0; j < MAX_HOST_PARAM_ITEM_NUM; j++)
						{
							item = cJSON_GetObjectItem(host_para, host_param_key[j]);
							//printf("host_para: item value:%d!\n", item->valueint);
							if(NULL == item) {							
								printf("Cannot get item from key:%s!\n", host_param_key[j]);
								continue;
							}
							else
								*pvalue++ = item->valueint;
						}
					}
				}

				if(mask & TCP_PORT_PROTECT_MASK)
				{
					/*get tcp port protection parameters*/
					tcp_port_prot = cJSON_GetObjectItem(server,"tcp_port_prot");

					if(NULL == tcp_port_prot)
					{
						//printf("Cannot get tcp_port_prot!\n");
						//continue;
					}
					else
					{
						port_size = cJSON_GetArraySize(tcp_port_prot);	
						
						p_server_cfg->tcp_port_num = port_size;
						for(iport = 0; iport < port_size; iport++)
						{
							port_item = cJSON_GetArrayItem(tcp_port_prot, iport);
							if(port_item == NULL)
								continue;
							pvalue = (uint32_t *)&p_server_cfg->tcp_prot_para[iport];
							for(j = 0; j < MAX_TCP_PORT_PROTECT_ITEM_NUM; j++)
							{
								item = cJSON_GetObjectItem(port_item, tcp_port_prot_key[j]);
								//printf("tcp_port_prot: item value:%d!\n", item->valueint);
								if(NULL == item) {							
									printf("Cannot get item from key:%s!\n", tcp_port_prot_key[j]);
									continue;
								}
								else
									*pvalue++ = item->valueint;
							}
						}
					}
				}

				if(mask & UDP_PORT_PROTECT_MASK)
				{
					/*get udp port protection parameters*/
					udp_port_prot = cJSON_GetObjectItem(server, "udp_port_prot");

					if(NULL == udp_port_prot)
					{
						//printf("Cannot get udp_port_prot!\n");
						//continue;
					}
					else
					{
						port_size = cJSON_GetArraySize(udp_port_prot);
						
						p_server_cfg->udp_port_num = port_size;
						for(iport = 0; iport < port_size; iport++)
						{
							port_item = cJSON_GetArrayItem(udp_port_prot, iport);
							if(port_item == NULL)
								continue;
							
							pvalue = (uint32_t *)&p_server_cfg->udp_prot_para[iport];
							for(j = 0; j < MAX_UDP_PORT_PROTECT_ITEM_NUM; j++)
							{
								item = cJSON_GetObjectItem(port_item, udp_port_prot_key[j]);
								//printf("udp_port_prot: item value:%d!\n", item->valueint);
								if(NULL == item) {							
									printf("Cannot get item from key:%s!\n", udp_port_prot_key[j]);
									continue;
								}
								else								
									*pvalue++ = item->valueint;								
							}
						}
					}
				}

				if(mask & BLACK_WHITE_GROUP_MASK)
				{
					b_w_grp_info = cJSON_GetObjectItem(server, "b_w_list");
					if(NULL == b_w_grp_info)
					{
						printf("Cannot get b_w grp info.\n");
					}
					item = cJSON_GetObjectItem(b_w_grp_info, "b_grp");
					if(NULL == item) {							
						printf("Cannot get b_grp!\n");
						continue;
					}
					else
						p_server_cfg->black_num = item->valueint;

					item = cJSON_GetObjectItem(b_w_grp_info, "w_grp");
					if(NULL == item) {							
						printf("Cannot get w_grp!\n");
						continue;
					}
					else
						p_server_cfg->white_num = item->valueint;
				}

				if( !strcmp(oper, "add") && (mask == SERVER_CONFIG_MASK_ALL))
				{
					//printf("Add dst ip:%d.\n", dstip);
					add_server_node(dstip,  p_server_cfg);
				}
				else if (!strcmp(oper, "update"))
				{
					//printf("Update dst ip:%d.\n", dstip);
					update_server_node(dstip,  mask, p_server_cfg);
				}
				else
				{
					printf("Invalid oper:%s or mask:%d for ip:%s.\n", oper, mask, ipstr);
				}
			}
		}
	}
	else
	{
		fprintf (stderr, "Cannot get server_config  from key:server.\n");
	}

	cJSON_Delete(root);
	return 0;
}

static int32_t ip_addr_check(uint32_t ip_addr)
{
	if(0 == (ip_addr % 255) || 255 == (ip_addr % 255) )
		return -1;

	return 0;
}

static inline int32_t ip_mask_parse(char *arg, uint32_t *start, uint32_t *end)
{
	char *dash;
	uint32_t start_ip = 0;	
	uint32_t end_ip = 0;
	uint32_t mask = 0, mask_val = 0;

	dash = strchr(arg, '/');
	if (dash == NULL) {		
		return 0;
	}

	*dash = '\0';

	fpdebug_inet_pton(AF_INET, arg, &start_ip);
	mask = atoi((dash+1));
		
	if(mask == 0 || mask > 32) {
		fprintf(stderr, "Invalid mask:%d.\n", mask);
		return -1;
	}
	mask_val = (1 << (32 - mask)) - 1;
		
	start_ip = ~(ntohl(start_ip) & mask_val) & ntohl(start_ip) ; 
	end_ip = start_ip + mask_val;  

	
	//fprintf(stdout, "ip_mask_parse: ip:%s, mask_value:%u, start_ip:%u, end_ip:%u. \n", arg, mask_val, start_ip, end_ip);
	
	*start = start_ip + 1; /*host number in subnet cannot all 0 */
	*end = end_ip - 1; /*host number in subnet cannot all 1 */

	return 1;
}

static inline int32_t ip_range_parse(char *arg, uint32_t *start, uint32_t *end)
{
	char *dash;
	uint32_t start_ip = 0;	
	uint32_t end_ip = 0;

	dash = strchr(arg, '-');
	if (dash == NULL) {
		return 0;
	}

	*dash = '\0';
	
	fpdebug_inet_pton(AF_INET, arg, &start_ip);
	fpdebug_inet_pton(AF_INET, dash + 1, &end_ip);

	start_ip = ntohl(start_ip);
	end_ip = ntohl(end_ip);
	
	//fprintf(stdout, "ip_range_parse: range %s-%s, start_ip:%d, end_ip:%d. \n", arg, dash + 1, start_ip, end_ip);

	if(start_ip > end_ip) {
		fprintf(stderr, "ip_range_parse: range %s-%s is invalid. \n", arg, dash + 1);
		return -1;
	}

	*start = start_ip;
	*end = end_ip;

	return 1;
}

static inline int32_t ip_string_parse(char *arg, uint32_t *start, uint32_t *end)
{	
	uint32_t start_ip = 0;	
	int32_t ret = 0;

	ret = ip_range_parse(arg, start, end);
	if(ret < 0)
		return ret;
	else if(1 == ret)	
		return 0;
	
	ret = ip_mask_parse(arg, start, end);
	if(ret < 0)
		return ret;
	else if(1 == ret)	
		return 0;
	
	fpdebug_inet_pton(AF_INET, arg, &start_ip);

	if(ip_addr_check(htonl(start_ip)) < 0){
		printf("Invalid ip:%s.\n", arg);
		return -1;
	}
	
	
	*start = htonl(start_ip);
	*end = htonl(start_ip);

	return 0;
	
}

int32_t ddos_black_white_config(void)
{
	cJSON *root = NULL;
	cJSON *item = NULL;
	cJSON *b_w_list = NULL;
	//cJSON *w_list = NULL;
	cJSON *list = NULL;
	cJSON *ip_item = NULL;

	uint32_t i = 0, j = 0, t = 0;
	uint32_t b_w_type = 0;
	int32_t grp_num = -1;
	uint32_t size = 0,  ip_size = 0, dport = 0;
	uint32_t dst_ip = 0;
	char oper[16] = {0};
	uint32_t total_type = 2;	
	char ipstr[64] = {0};
	char src_ipstr[32] = {0};
	uint32_t start_ip = 0, end_ip = 0;
	//char dstip[32] = {0};
	//char rule[128] = {0};
	void *fp_config_shm = fp_shm_addr[DDOS_SHM_CONFIG];
	
	if(NULL == fp_config_shm)
	{		
		return -1;
	}

	root = cJSON_Parse((char *)fp_config_shm);
	if(root == NULL)
	{
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		return -1;
	}

#define IS_WHITE  0
#define IS_BLACK  1

	for (t = 0; t < total_type; t++)
	{	
		grp_num = -1;
		if(IS_WHITE == t)
			b_w_list = cJSON_GetObjectItem(root, "w_list");
		else if (IS_BLACK == t)
			b_w_list = cJSON_GetObjectItem(root, "b_list");
		else 
			return -1;

		if(b_w_list != NULL)
		{
			size = cJSON_GetArraySize(b_w_list);
			for(i = 0; i < size; i++)
			{
				list = cJSON_GetArrayItem(b_w_list, i);

				if(list == NULL)
					continue;

				item = cJSON_GetObjectItem(list, "grp");
				if(NULL != item)
					grp_num = item->valueint;

				item = cJSON_GetObjectItem(list, "oper");
				bzero(oper, sizeof(oper));
				snprintf(oper, sizeof(oper) - 1, "%s", item->valuestring);
				
				b_w_type = t;

				snprintf(src_ipstr, sizeof(src_ipstr) - 1, "0.0.0.0");				
				snprintf(ipstr, sizeof(ipstr) - 1, "0.0.0.0");
				//snprintf(dstip, sizeof(dstip) - 1, "0.0.0.0");
				dport = 0;

				ip_item = cJSON_GetObjectItem(list, "ip");

				ip_size = cJSON_GetArraySize(ip_item);
				for(j = 0; j < ip_size; j++)
				{
					item = cJSON_GetArrayItem(ip_item, j);
					if(NULL == item->valuestring) {
						printf("Cannot get ip item in b_w_list.\n");
						continue;
					}
					snprintf(ipstr, sizeof(ipstr) - 1, "%s", item->valuestring);

					start_ip = 0;
					end_ip = 0;

					if(ip_string_parse(ipstr, &start_ip, &end_ip) < 0) {
						continue;
					}

					while(start_ip <= end_ip)
					{					
						//fpdebug_inet_pton(AF_INET, src_ipstr, &src_ip);	
						if(ip_addr_check(start_ip) < 0)
						{
							start_ip++;
							continue;					
						}

						if( !strcmp(oper, "add") )
						{
							add_black_white_node(htonl(start_ip), dst_ip,  dport,  (uint32_t)b_w_type, grp_num);
						}
						else if (!strcmp(oper, "del"))
						{
							delete_black_white_node(htonl(start_ip), dst_ip,  dport,  (uint32_t)b_w_type, grp_num);
						}
						else
						{
							printf("Invalid oper:%s for ip:%s.\n", oper, src_ipstr);
						}
						start_ip++;
					}
				}
			}
		}
	}
	return 0;
}



static int32_t add_temp_black_table_to_json(cJSON *root)
{
	cJSON *t_b_table = NULL;
	cJSON *item = NULL;
	cJSON *pJsonArry = NULL;
	uint32_t count = 0;
	char dstip[32] = {0};
	char srcip[32] = {0};

	pJsonArry = cJSON_CreateArray();

#define MAX_ITEM_NUM 100

	FASAT_FOREACH_HASH_TABLE(tmp_black_table, tmpnode, TMP_BLACK_WHITE_TABLE, {		
		t_b_table = cJSON_CreateObject();
		if(t_b_table == NULL) {
			printf("Create object for t_b_table failed.\n");
			return -1;
		}

		bzero(srcip, sizeof(srcip));
		fpdebug_inet_ntop(AF_INET, &tmpnode->black_white.srcip, srcip, sizeof(srcip));

		bzero(dstip, sizeof(dstip));
		fpdebug_inet_ntop(AF_INET, &tmpnode->black_white.dstip, dstip, sizeof(dstip));

		item = cJSON_CreateString(dstip);
		if(NULL == item) {
			printf("Create item for %s failed.\n", dstip);
			return -1;
		}
		else
			cJSON_AddItemToObject(t_b_table, "dst_ip", item);

		item = cJSON_CreateString(srcip);
		if(NULL == item) {
			printf("Create item for %s failed.\n", srcip);
			return -1;
		}
		else
			cJSON_AddItemToObject(t_b_table, "src_ip", item);

		//printf("B-->dst_ip:%s, src_ip:%s.\n", dstip, srcip);
		cJSON_AddItemToArray(pJsonArry, t_b_table);

		if(++count > MAX_ITEM_NUM)
		{
			cJSON_AddItemToObject(root, "t_b_list", pJsonArry);
			return 0; 
		}
	})

	cJSON_AddItemToObject(root, "t_b_list", pJsonArry);

	return 0;
}

static int32_t add_temp_white_table_to_json(cJSON *root)
{
	cJSON *t_w_table = NULL;
	cJSON *item = NULL;
	cJSON *pJsonArry = NULL;
	uint32_t count = 0;
	char dstip[32] = {0};
	char srcip[32] = {0};

	pJsonArry = cJSON_CreateArray();

#define MAX_ITEM_NUM 100

	FASAT_FOREACH_HASH_TABLE(tmp_white_table, tmpnode, TMP_BLACK_WHITE_TABLE, {		
		t_w_table = cJSON_CreateObject();
		if(t_w_table == NULL) {			
			printf("Create object for t_w_table failed.\n");
			return -1;
		}
		bzero(srcip, sizeof(srcip));
		fpdebug_inet_ntop(AF_INET, &tmpnode->black_white.srcip, srcip, sizeof(srcip));

		bzero(dstip, sizeof(dstip));
		fpdebug_inet_ntop(AF_INET, &tmpnode->black_white.dstip, dstip, sizeof(dstip));

		item = cJSON_CreateString(dstip);
		if(NULL == item) {
			printf("Create item for %s failed.\n", dstip);
			return -1;
		}
		else
			cJSON_AddItemToObject(t_w_table, "dst_ip", item);

		item = cJSON_CreateString(srcip);
		if(NULL == item) {
			printf("Create item for %s failed.\n", srcip);
			return -1;
		}
		else
			cJSON_AddItemToObject(t_w_table, "src_ip", item);

		cJSON_AddItemToArray(pJsonArry, t_w_table);

		//printf("W-->dst_ip:%s, src_ip:%s.\n", dstip, srcip);

		if(++count > MAX_ITEM_NUM)
		{
			cJSON_AddItemToObject(root, "t_w_list", pJsonArry);
			return 0;
		}

	})

	cJSON_AddItemToObject(root, "t_w_list", pJsonArry);
	return 0;
}

int32_t get_temp_black_white_info(void)
{
	char *out = NULL;
	cJSON *root = NULL;
	void *fp_temp_b_w_shm = fp_shm_addr[DDOS_SHM_TMP_B_W];

	if(NULL == fp_temp_b_w_shm)
	{
		return -1;
	}

	root = cJSON_CreateObject();
	if (root == NULL)
	{
		return -1;
	}


	add_temp_black_table_to_json(root);

	add_temp_white_table_to_json(root);

	//out = cJSON_Print(root);
	out = cJSON_PrintUnformatted(root);
	if(out != NULL)
	{
		memcpy(fp_temp_b_w_shm, out, strlen(out));
	}
	else
	{
		printf("Jason string is NULL when temp black table info.\n");
		return -1;
	}

	cJSON_Delete(root);
	if(out != NULL)
		free(out);

	return 0;
}

int32_t delete_temp_black_white_node(uint32_t srcip, uint32_t dstip, uint32_t type)
{
	struct black_white_table *temp_b_w_table = NULL;

	if(type == 0)
		temp_b_w_table = tmp_white_table;
	else if(type == 1)
		temp_b_w_table = tmp_black_table;
	else
		printf("Invalid type:%d.\n", type);

	if(NULL != temp_b_w_table)
		del_tmp_black_white_table(temp_b_w_table, srcip, dstip, TMP_BLACK_WHITE_TABLE);
	else 
		return -1;

	return 0;
}