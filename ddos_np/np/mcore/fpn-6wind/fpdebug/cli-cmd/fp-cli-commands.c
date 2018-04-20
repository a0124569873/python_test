
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <error.h>
#include <sys/time.h>
#include "fp.h"
#include "fpdebug-priv.h"

#ifndef __FastPath__
#include "shmem/fpn-shmem.h"
#include "fpn-cpu-usage.h"
#endif

#include "fp-cli-commands.h"
#include "../b64/b64.h"

#define DDOS_PATH    "/tmp/ddos"

extern char *chargv[FPDEBUG_MAX_ARGS];
int32_t gettokens(char *s __fpn_maybe_unused);

/*int32_t fp_nfct_print(char *tok)
{
	uint32_t numtokens = gettokens(tok);
	int i = 0;
	uint32_t count = 0;

	if(numtokens != 1)
		goto fp_nfct_print_usage;

	if(strcmp(chargv[0],"-s") == 0)
	{
		for(i = 0; i < FP_NF_CT_MAX; i++)
		{
			if (fp_shared->fp_nf_ct.fp_nfct[i].flag & FP_NFCT_FLAG_VALID)
				count++;
		}
		printf("Number of flows: %u/%u/%u\n", count, fp_shared->fp_nf_ct.fp_nfct_count, FP_NF_CT_MAX);
	}
	else
	{
		goto fp_nfct_print_usage;
	}
	return 0;

fp_nfct_print_usage:
	fpdebug_fprintf (stderr, "fpcmd fp_nfct_print -s\n");
	return 0;
}

int32_t iptables_match_init(char *tok)
{
	uint32_t numtokens = gettokens(tok);
	int i = 0;
	struct fp_nfrule *r = NULL;
	int cur_table = fp_shared->fp_nf_current_table;

#define RULEY(n)  fp_shared->fp_nf_rules[cur_table][n]

	if(numtokens != 1)
		goto iptables_match_init_usage;

	if(strcmp(chargv[0],"-s") == 0)
	{
		for (i = 0; i < FP_NF_MAXRULES; i++)
		{
			r = &RULEY(i);
			printf("r->dispatch ==%u   r->syns==%u   r-> speed==%u\n", r->dispatch, r->syns, r->speed);
		}
	}
	else if(strcmp(chargv[0],"-init") == 0)
	{
		for(i = 0; i < DISPATCH_MAX_NUM; i++)
		{
			if(i == 0)
				fp_shared->dispatch_type[i] = TYPEGMAX;
			if(i == 1)
				fp_shared->dispatch_type[i] = BLACK_IP;
			if(i == 2)
				fp_shared->dispatch_type[i] = WHITE_IP;
			if(i == 3)
				fp_shared->dispatch_type[i] = IS_PROTECT_SERVER;
			if(i >= 4)
				fp_shared->dispatch_type[i] = TYPEGMAX;
		}

		for (i = 0; i < FP_NF_MAXRULES; i++)
		{
			r = &RULEY(i);
			r->dispatch = 0;
			r->syns = 0;
			r->speed = 0;
		}
	}
	else
	{
		goto iptables_match_init_usage;
	}
	return 0;

iptables_match_init_usage:
	fpdebug_fprintf (stderr, "fpcmd iptables_match_init -s/-init\n");
	return 0;

#undef 	RULEY
}*/

int32_t ddos_time(char *tok)
{
	uint32_t numtokens = gettokens(tok);

	if (numtokens != 1 && numtokens != 2)
	{
		printf("parameters numbers error\n");
		goto ddos_time_usage;
	}

	if(strcmp(chargv[0],"-print") == 0 && numtokens == 1)
	{

		printf("default_detect_cycle==%d  white_effect_time==%d  black_effect_time==%d\n",
		fp_shared->default_detect_cycle,
		fp_shared->white_effect_time,
		fp_shared->black_effect_time);
	}
	else if(strcmp(chargv[0],"-detect") == 0 && numtokens == 2)
	{
		fp_shared->default_detect_cycle = atoi(chargv[1]);
	}
	else if(strcmp(chargv[0],"-white") == 0 && numtokens == 2)
	{
		fp_shared->white_effect_time = atoi(chargv[1]);
	}
	else if(strcmp(chargv[0],"-black") == 0 && numtokens == 2)
	{
		fp_shared->black_effect_time = atoi(chargv[1]);
	}
	else
	{
		goto ddos_time_usage;
	}

	return 0;

ddos_time_usage:
	fpdebug_fprintf (stderr, "fpcmd ddos_time -print/-detect/-white/-black\n");
	return 0;
}

int32_t server_threshold(char *tok)
{
	cJSON *root = NULL;
	cJSON *server_threshold = NULL;
	cJSON *item = NULL;
	cJSON *server = NULL;

	uint32_t i = 0;
	uint32_t size = 0;

	char *json_string = NULL;

	char ipstr[30] = {0};
	uint32_t port = 0;
	uint32_t syn = 0;
	uint32_t udp = 0;

	char rule[500] = {0};

	uint32_t numtokens = gettokens(tok);

	if(numtokens != 2)
	{
		fpdebug_fprintf (stderr, "fpcmd server_threshold -s/-a/-u/-d\n");
		return 0;
	}

	json_string = b64_decode(chargv[1], strlen(chargv[1]));

	root = cJSON_Parse(json_string);
	if(root == NULL)
	{
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		return 0;
	}

	if(strcmp(chargv[0],"-s") == 0)
	{
		system("fpngctl msg ddos: server_empty");

		server_threshold = cJSON_GetObjectItem(root, "server_threshold");
		if(server_threshold != NULL)
		{
			size = cJSON_GetArraySize(server_threshold);
			for(i = 0; i < size; i++)
			{
				server = cJSON_GetArrayItem(server_threshold, i);
				if(server == NULL)
					continue;

				item = cJSON_GetObjectItem(server,"ip");
				if(item == NULL)
					continue;

				bzero(ipstr, sizeof(ipstr));
				snprintf(ipstr, sizeof(ipstr) - 1, "%s", item->valuestring);

				item = cJSON_GetObjectItem(server,"port");
				if(item == NULL)
					continue;
				port = item->valueint;

				item = cJSON_GetObjectItem(server,"syn");
				if(item == NULL)
					continue;
				syn = item->valueint;

				item = cJSON_GetObjectItem(server,"udp");
				if(item == NULL)
					continue;
				udp = item->valueint;

				bzero(rule, sizeof(rule));
				snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: server_add {ip=%s port=%d syn=%d udp=%d}", ipstr, port, syn, udp);

				system(rule);
				printf("%s\n", rule);
			}
		}
	}
	else if(strcmp(chargv[0],"-a") == 0)
	{
		item = cJSON_GetObjectItem(root,"ip");
		if(item != NULL)
		{
			bzero(ipstr, sizeof(ipstr));
			snprintf(ipstr, sizeof(ipstr) - 1, "%s", item->valuestring);
		}


		item = cJSON_GetObjectItem(root,"port");
		if(item != NULL)
		{
			port = item->valueint;
		}

		item = cJSON_GetObjectItem(root,"syn");
		if(item != NULL)
		{
			syn = item->valueint;
		}

		item = cJSON_GetObjectItem(root,"udp");
		if(item != NULL)
		{
			udp = item->valueint;
		}

		bzero(rule, sizeof(rule));
		snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: server_add {ip=%s port=%d syn=%d udp=%d}", ipstr, port, syn, udp);
		system(rule);
		printf("%s\n", rule);
	}
	else if(strcmp(chargv[0],"-u") == 0)
	{
		item = cJSON_GetObjectItem(root,"ip");
		if(item != NULL)
		{
			bzero(ipstr, sizeof(ipstr));
			snprintf(ipstr, sizeof(ipstr) - 1, "%s", item->valuestring);
		}

		item = cJSON_GetObjectItem(root,"port");
		if(item != NULL)
		{
			port = item->valueint;
		}

		item = cJSON_GetObjectItem(root,"syn");
		if(item != NULL)
		{
			syn = item->valueint;
		}

		item = cJSON_GetObjectItem(root,"udp");
		if(item != NULL)
		{
			udp = item->valueint;
		}

		bzero(rule, sizeof(rule));
		snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: server_update {ip=%s port=%d syn=%d udp=%d}", ipstr, port, syn, udp);

		system(rule);
		printf("%s\n", rule);
	}
	else if(strcmp(chargv[0],"-d") == 0)
	{
		item = cJSON_GetObjectItem(root,"ip");
		if(item != NULL)
		{
			bzero(ipstr, sizeof(ipstr));
			snprintf(ipstr, sizeof(ipstr) - 1, "%s", item->valuestring);
		}

		item = cJSON_GetObjectItem(root,"port");
		if(item != NULL)
		{
			port = item->valueint;
		}

		item = cJSON_GetObjectItem(root,"syn");
		if(item != NULL)
		{
			syn = item->valueint;
		}

		item = cJSON_GetObjectItem(root,"udp");
		if(item != NULL)
		{
			udp = item->valueint;
		}

		bzero(rule, sizeof(rule));
		snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: server_delete {ip=%s port=%d syn=%d udp=%d}", ipstr, port, syn, udp);
		system(rule);
		printf("%s\n", rule);
	}
	else
	{
		fpdebug_fprintf (stderr, "fpcmd server_threshold -s/-a/-u/-d\n");
	}

	cJSON_Delete(root);
	return 0;
}

int32_t black_white(char *tok)
{
	cJSON *root = NULL;

	cJSON *white_list = NULL;
	cJSON *black_list = NULL;

	cJSON *white = NULL;
	cJSON *black = NULL;
	cJSON *item = NULL;

	uint32_t i = 0;
	uint32_t size = 0;

	char *json_string = NULL;

	char srcip[30] = {0};
	char dstip[30] = {0};
	uint32_t dport = 0;

	char rule[500] = {0};

	uint32_t numtokens = gettokens(tok);

	if(numtokens != 2 || (strcmp(chargv[0],"-s") != 0))
	{
		fpdebug_fprintf (stderr, "fpcmd black_white -s\n");
		return 0;
	}

	json_string = b64_decode(chargv[1], strlen(chargv[1]));

	root = cJSON_Parse(json_string);
	if(root == NULL)
	{
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		return 0;
	}

#define IS_WHITE      0
#define IS_BLACK      1

	system("fpngctl msg ddos: black_white_empty");

	white_list = cJSON_GetObjectItem(root, "white");
	if(white_list != NULL)
	{
		size = cJSON_GetArraySize(white_list);
		for(i = 0; i < size; i++)
		{
			white = cJSON_GetArrayItem(white_list, i);
			if(white == NULL)
				continue;

			snprintf(srcip, sizeof(srcip) - 1, "0.0.0.0");
			snprintf(dstip, sizeof(dstip) - 1, "0.0.0.0");
			dport = 0;

			item = cJSON_GetObjectItem(white,"srcip");
			if(item != NULL)
			{
				snprintf(srcip, sizeof(srcip) - 1, "%s", item->valuestring);
			}

			item = cJSON_GetObjectItem(white,"dstip");
			if(item != NULL)
			{
				snprintf(dstip, sizeof(dstip) - 1, "%s", item->valuestring);
			}

			item = cJSON_GetObjectItem(white,"dport");
			if(item != NULL)
			{
				dport = item->valueint;
			}

			bzero(rule, sizeof(rule));
			snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: black_white_add {srcip=%s dstip=%s dport=%d type=%d}", srcip, dstip, dport, IS_WHITE);

			system(rule);
			printf("%s\n", rule);
		}
	}

	black_list = cJSON_GetObjectItem(root, "black");
	if(black_list != NULL)
	{
		size = cJSON_GetArraySize(black_list);
		for(i = 0; i < size; i++)
		{
			black = cJSON_GetArrayItem(black_list, i);
			if(black == NULL)
				continue;

			snprintf(srcip, sizeof(srcip) - 1, "0.0.0.0");
			snprintf(dstip, sizeof(dstip) - 1, "0.0.0.0");
			dport = 0;

			item = cJSON_GetObjectItem(black,"srcip");
			if(item != NULL)
			{
				snprintf(srcip, sizeof(srcip) - 1, "%s", item->valuestring);
			}

			item = cJSON_GetObjectItem(black,"dstip");
			if(item != NULL)
			{
				snprintf(dstip, sizeof(dstip) - 1, "%s", item->valuestring);
			}

			item = cJSON_GetObjectItem(black,"dport");
			if(item != NULL)
			{
				dport = item->valueint;
			}

			bzero(rule, sizeof(rule));
			snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: black_white_add {srcip=%s dstip=%s dport=%d type=%d}", srcip, dstip, dport, IS_BLACK);

			system(rule);
			printf("%s\n", rule);
		}
	}

	cJSON_Delete(root);
	return 0;
}

int32_t get_ddos_status(char *tok)
{
	//int sockfd = 0;
    	//int len = 0;
    	//struct sockaddr_un addr;
    	//char recv_buf[1000000] = {0};

    uint32_t numtokens = gettokens(tok);

	if(numtokens != 0)
	{
		fpdebug_fprintf (stderr, "fpcmd get_ddos_status\n");
		return 0;
	}

#if 0
    	unlink(DDOS_PATH);
    	addr.sun_family = AF_UNIX;
    	strcpy(addr.sun_path, DDOS_PATH);

    	len = strlen(addr.sun_path) + sizeof(addr.sun_family);
    	sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    	if(sockfd < 0 )
    	{
       	 	perror("socket error");
       		return 0;
   	}

    	if(bind(sockfd, (struct sockaddr *)&addr, len) < 0)
    	{
        		perror("bind error");
        		close(sockfd);
        		return 0;
    	}
#endif
    	system("fpngctl msg ddos: get_ddos_status");
    	//printf("%s\n",recv_buf);

    	//recvfrom(sockfd, recv_buf, sizeof(recv_buf) - 1, 0, (struct sockaddr*)&addr, (socklen_t *)&len);
    	//printf("%s\n",recv_buf);
    	//close(sockfd);
    	return 0;
}



int32_t ip_mac(char *tok)
{
	cJSON *root = NULL;
	cJSON *ip_mac = NULL;
	cJSON *item = NULL;
	cJSON *server = NULL;

	uint32_t i = 0;
	uint32_t size = 0;

	char *json_string = NULL;

	char ipstr[30] = {0};
	char mac[40]={0};

	char rule[500] = {0};

	uint32_t numtokens = gettokens(tok);

	if(numtokens != 2)
	{
		fpdebug_fprintf (stderr, "fpcmd ip_mac -s/-a/-u/-d\n");
		return 0;
	}

	json_string = b64_decode(chargv[1], strlen(chargv[1]));

	root = cJSON_Parse(json_string);
	if(root == NULL)
	{
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		return 0;
	}

	if(strcmp(chargv[0],"-s") == 0)
	{
		system("fpngctl msg ddos: ip_mac_empty");

		ip_mac = cJSON_GetObjectItem(root, "ip_mac");
		if(ip_mac != NULL)
		{
			size = cJSON_GetArraySize(ip_mac);
			for(i = 0; i < size; i++)
			{
				server = cJSON_GetArrayItem(ip_mac, i);
				if(server == NULL)
					continue;

				item = cJSON_GetObjectItem(server,"ip");
				if(item == NULL)
					continue;

				bzero(ipstr, sizeof(ipstr));
				snprintf(ipstr, sizeof(ipstr) - 1, "%s", item->valuestring);

				item = cJSON_GetObjectItem(server,"mac");
				if(item == NULL)
					continue;
				bzero(mac, sizeof(mac));
				snprintf(mac, sizeof(mac) - 1, "%s", item->valuestring);

				bzero(rule, sizeof(rule));
				snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: ip_mac_add {ip=%s mac=%s}", ipstr, mac);

				system(rule);
				printf("%s\n", rule);
			}
		}
	}
	else if(strcmp(chargv[0],"-a") == 0)
	{
		item = cJSON_GetObjectItem(root,"ip");
		if(item != NULL)
		{
			bzero(ipstr, sizeof(ipstr));
			snprintf(ipstr, sizeof(ipstr) - 1, "%s", item->valuestring);
		}

		item = cJSON_GetObjectItem(root,"mac");
		if(item != NULL)
		{
			bzero(mac, sizeof(mac));
			snprintf(mac, sizeof(mac) - 1, "%s", item->valuestring);
		}


		bzero(rule, sizeof(rule));
		snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: ip_mac_add {ip=%s mac=%s}", ipstr, mac);
		system(rule);
		printf("%s\n", rule);
	}
	else if(strcmp(chargv[0],"-u") == 0)
	{
		item = cJSON_GetObjectItem(root,"ip");
		if(item != NULL)
		{
			bzero(ipstr, sizeof(ipstr));
			snprintf(ipstr, sizeof(ipstr) - 1, "%s", item->valuestring);
		}

		item = cJSON_GetObjectItem(root,"mac");
		if(item != NULL)
		{
			bzero(mac, sizeof(mac));
			snprintf(mac, sizeof(mac) - 1, "%s", item->valuestring);
		}

		bzero(rule, sizeof(rule));
		snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: ip_mac_update {ip=%s mac=%s}", ipstr, mac);

		system(rule);
		printf("%s\n", rule);
	}
	else if(strcmp(chargv[0],"-d") == 0)
	{
		item = cJSON_GetObjectItem(root,"ip");
		if(item != NULL)
		{
			bzero(ipstr, sizeof(ipstr));
			snprintf(ipstr, sizeof(ipstr) - 1, "%s", item->valuestring);
		}

		bzero(rule, sizeof(rule));
		snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: ip_mac_delete {ip=%s}", ipstr);
		system(rule);
		printf("%s\n", rule);
	}
	else
	{
		fpdebug_fprintf (stderr, "fpcmd ip_mac -s/-a/-u/-d\n");
	}

	cJSON_Delete(root);
	return 0;
}

int32_t stream_return(char *tok)
{
	uint32_t numtokens = gettokens(tok);

	if (numtokens != 1 )
	{
		printf("parameters numbers error\n");
		fpdebug_fprintf (stderr, "fpcmd stream_return -print/-mac/-mpls\n");
		return 0;
	}

	if(strcmp(chargv[0],"-mac") == 0 )
	{
		fp_shared->stream_return=1;
	}
	else if(strcmp(chargv[0],"-mpls") == 0 )
	{
		fp_shared->stream_return=2;
	}
	else if(strcmp(chargv[0],"-pbr") == 0 )		//policy-Based routing
	{
		fp_shared->stream_return=3;
	}
	else if(strcmp(chargv[0],"-print") == 0 )
	{
		printf("stream_return=%d\n",fp_shared->stream_return);
	}
	else
	{
		fpdebug_fprintf (stderr, "fpcmd stream_return -print/-mac/-mpls\n");
		return 0;
	}

	return 0;
}

int32_t server_flow(char *tok)
{
	uint32_t numtokens = gettokens(tok);
	char rule[500] = {0};
	if ( numtokens != 1 && numtokens != 2)
	{
		printf("parameters numbers error\n");
		goto server_flow_usage;
	}
	if(strcmp(chargv[0],"-p") == 0  && numtokens == 1)
	{
		bzero(rule, sizeof(rule));
		snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: show_server_flow");
		system(rule);
		printf("%s\n", rule);
	}
	else if(strcmp(chargv[0],"-a") == 0  && numtokens == 2)
	{
		bzero(rule, sizeof(rule));
		snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: server_flow_add {ip=%s}", chargv[1]);
		system(rule);
		printf("%s\n", rule);
	}
	else if(strcmp(chargv[0],"-d") == 0 && numtokens == 2)
	{
		bzero(rule, sizeof(rule));
		snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: server_flow_delete {ip=%s}", chargv[1]);
		system(rule);
		printf("%s\n", rule);
	}
	else
	{
		goto server_flow_usage;
	}

	return 0;

server_flow_usage:
	fpdebug_fprintf (stderr, "fpcmd server_flow -a/-d/-p\n");
	return 0;
}

#ifdef __FastPath__

extern void fpn_dump_pools_info(char* buff, int32_t size);
extern void dump_ring_buffer_info(char* buff, int32_t size);
extern void dump_gc_status(char* buff, int32_t size);

int fpn_sock_mempools(char* tok) {
	fpn_dump_pools_info(fp_shared->verbose_msg, FP_VERBOSE_MSG_SIZE);
	return 0;
}

int dump_ring_buffer(char* tok) {
	dump_ring_buffer_info(fp_shared->verbose_msg, FP_VERBOSE_MSG_SIZE);
	return 0;
}

int dump_mem_status(char* tok) {
	dump_gc_status(fp_shared->verbose_msg, FP_VERBOSE_MSG_SIZE);
	return 0;
}

#else

int fpn_sock_mempools(char *tok) {
	fpdebug_send_to_fp(tok);

	printf(fp_shared->verbose_msg);
	return 0;
}

int dump_ring_buffer(char* tok) {
	fpdebug_send_to_fp(tok);

	printf(fp_shared->verbose_msg);
	return 0;
}

int dump_mem_status(char* tok) {
	fpdebug_send_to_fp(tok);

	printf(fp_shared->verbose_msg);
	return 0;
}
#endif


void* fp_shm_addr[DDOS_SHM_TOTAL];

char host_key[MAX_HOST_ITEM_NUM][16] = {"flow_in", "pkt_in", "flow_out", "pkt_out", "flow_pol"};
char host_param_key[MAX_HOST_PARAM_ITEM_NUM][16] = {"syn", "syn_ss", "ack_rst", "udp", "icmp", "tcp_con_in", "tcp_con_out", "tcp_con_ip", "tcp_fre", "tcp_idle", "udp_con", "udp_fre", "icmp_fre"};
char tcp_port_prot_key[MAX_TCP_PORT_PROTECT_ITEM_NUM][16] = {"str", "end", "on_off", "atk_fre", "con_lmt", "pro_mod"};
char udp_port_prot_key[MAX_UDP_PORT_PROTECT_ITEM_NUM][16] = {"str", "end", "on_off", "atk_fre", "pkt_fre", "pro_mod"};

void* fp_ddos_shm_lookup(struct ddos_shm_info *ddos_shm);
void* fp_ddos_shm_lookup(struct ddos_shm_info *ddos_shm)
{
	int shm_id;
	void *p_config = NULL;
	//int ret;

	key_t key = ftok(ddos_shm->path, ddos_shm->id);
	if(key == -1)
	{
		perror("ftok error");
		return NULL;
	}

	shm_id = shmget(key, 0, 0);
	if( shm_id == -1)
	{
		perror("Shm lookup, shmget error");
		return NULL;
	}
	//printf("Shm lookup shm_id = %d\n", shm_id) ;

	p_config = (void *)shmat(shm_id, NULL, 0);

	if(p_config == NULL )
	{
		perror("Shm lookup, shmat addr error") ;
		return NULL ;
	}
	//printf("Find shared mem for fp_config:%p!\n", p_config);
	return p_config;
}

int32_t system_config(char *tok)
{
	cJSON *root = NULL;
	cJSON *sys_param = NULL;
	cJSON *item = NULL;

	char mode[16] = {0};


	uint32_t numtokens = gettokens(tok);

	if(numtokens != 0)
	{
		fpdebug_fprintf (stderr, "fpcmd system_config \n");
		return 0;
	}
	
	fp_shm_addr[DDOS_SHM_CONFIG] = fp_ddos_shm_lookup(&fp_shared->fp_ddos_shm[DDOS_SHM_CONFIG]);
	if(NULL == fp_shm_addr[DDOS_SHM_CONFIG]){
		printf("Lookup share memory:%s failed.\n", fp_shared->fp_ddos_shm[DDOS_SHM_CONFIG].name);
		return -1;
	}



	//printf("fp_config_shm: %s.\n", (char *)fp_config_shm);

	//json_string = b64_decode((char *)p_shm_config, atoi(chargv[1]));

	//printf("json_string: %s.\n", json_string);

	root = cJSON_Parse((char *)fp_shm_addr[DDOS_SHM_CONFIG]);
	if(root == NULL)
	{
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		return 0;
	}

	sys_param = cJSON_GetObjectItem(root, "system_para");
	if(sys_param != NULL)
	{
		item = cJSON_GetObjectItem(sys_param, "def_mod");
		bzero(mode, sizeof(mode));
		snprintf(mode, sizeof(mode) - 1, "%s", item->valuestring);

		if(!strcmp(mode, "bypass"))
		{
			fp_shared->flow_strategy = TOTAL_FLOW_FORWARD;
		}
		else if (!strcmp(mode, "atk_def"))
		{
			fp_shared->flow_strategy = TOTAL_FLOW_THRESHOLD;
		}
		else
		{
			printf("Invalid def_mode:%s!\n", mode);
			return -1;
		}

		item = cJSON_GetObjectItem(sys_param, "blk_time");
		fp_shared->black_effect_time = item->valueint;
		printf("System para: flow_strategy:%d, black_hole_time:%u.\n", fp_shared->flow_strategy, fp_shared->black_effect_time);
	}
	else
	{
		fpdebug_fprintf (stderr, "Cannot get sys_config  from key:system_para.\n");
	}

	cJSON_Delete(root);
	return 0;
}

int32_t total_server_config(char *tok)
{
	uint32_t numtokens = gettokens(tok);

	if(numtokens != 0)
	{
		fpdebug_fprintf (stderr, "fpcmd server_config \n");
		return -1;
	}

	system("fpngctl msg ddos: server_config");

	return 0;
}

int32_t server_config(char *tok)
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
	//cJSON *b_list = NULL;
	//cJSON *w_list = NULL;

	uint32_t i = 0, j = 0, n= 0;
	uint32_t size = 0, port_size = 0, iport = 0;

	char ipstr[32] = {0};
	char oper[8] = {0};
	char cfg_host[128] = {0};
	char cfg_host_para[256] = {0};
	char cfg_tcp[512] = {0};
	char cfg_udp[512] = {0};
	//char cfg_w_list[128] = {0};
	//char cfg_b_list[128] = {0};
	char config_msg[512] = {0};
	char rule[2048] = {0};
	int32_t mask = 0;

	uint32_t numtokens = gettokens(tok);

	if(numtokens != 0)
	{
		fpdebug_fprintf (stderr, "fpcmd server_config \n");
		return 0;
	}
	fp_shm_addr[DDOS_SHM_CONFIG] = fp_ddos_shm_lookup(&fp_shared->fp_ddos_shm[DDOS_SHM_CONFIG]);
	if(NULL == fp_shm_addr[DDOS_SHM_CONFIG]){
		printf("Lookup share memory:%s failed.\n", fp_shared->fp_ddos_shm[DDOS_SHM_CONFIG].name);
		return -1;
	}

	//printf("fp_config_shm: %s.\n", (char *)fp_config_shm);

	//json_string = b64_decode((char *)p_shm_config, atoi(chargv[1]));

	//printf("json_string: %s.\n", json_string);

	root = cJSON_Parse((char *)fp_shm_addr[DDOS_SHM_CONFIG]);
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

			item = cJSON_GetObjectItem(server,"ip");

			bzero(ipstr, sizeof(ipstr));
			snprintf(ipstr, sizeof(ipstr) - 1, "%s", item->valuestring);
			//printf("ip:%s.\n", ipstr);

			item = cJSON_GetObjectItem(server,"oper");
			bzero(oper, sizeof(oper));
			snprintf(oper, sizeof(oper) - 1, "%s", item->valuestring);
			//printf("oper:%s.\n", oper);

			if(!strcmp(oper, "del"))
			{
				bzero(rule, sizeof(rule));
				snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: server_delete {ip=%s}", ipstr);
				system(rule);
				printf("%s\n", rule);
			}
			else
			{
				item = cJSON_GetObjectItem(server, "mask");
				mask = item->valueint;
				//printf("mask:%d.\n", mask);

				bzero(cfg_host, sizeof(cfg_host));
				bzero(cfg_host_para, sizeof(cfg_host_para));
				bzero(cfg_tcp, sizeof(cfg_tcp));
				bzero(cfg_udp, sizeof(cfg_udp));
				bzero(config_msg, sizeof(config_msg));
				bzero(rule, sizeof(rule));

				if(mask <= 0)
				{
					printf("Invalid mask:%d for ip:%s.\n", mask, ipstr);
					continue;
				}
				else if( !strcmp(oper, "add") && (mask == SERVER_CONFIG_MASK_ALL))
				{
					n = snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: server_add {ip=%s ", ipstr);
				}
				else
				{
					n = snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: server_update {ip=%s  mask=%d ", ipstr, mask);
				}

				if(mask & HOST_MASK)
				{
					/*get host parameters*/
					host = cJSON_GetObjectItem(server,"host");

					if(NULL == host)
					{
						printf("Cannot get host!\n");
						continue;
					}
					else
					{
						for(j = 0; j < MAX_HOST_ITEM_NUM; j++)
						{
							item = cJSON_GetObjectItem(host, host_key[j]);
							//printf("host: item value:%d!\n", item->valueint);

							n = snprintf(config_msg, sizeof(config_msg) - 1, "%s=%d ", host_key[j], item->valueint);
							strncat(cfg_host, config_msg, n);
						}
						snprintf(config_msg, sizeof(config_msg) - 1, "host={%s} ", cfg_host);
						strcat(rule, config_msg);
					}
				}

				if(mask & HOST_PARA_MASK)
				{
					/*get host_para parameters*/
					host_para = cJSON_GetObjectItem(server,"host_para");

					if(NULL == host_para)
					{
						printf("Cannot get host_para!\n");
						//continue;
					}
					else
					{
						for(j = 0; j < MAX_HOST_PARAM_ITEM_NUM; j++)
						{
							item = cJSON_GetObjectItem(host_para, host_param_key[j]);
							//printf("host_para: item value:%d!\n", item->valueint);

							n = snprintf(config_msg, sizeof(config_msg) - 1, "%s=%d ", host_param_key[j], item->valueint);
							strncat(cfg_host_para, config_msg, n);
						}
						snprintf(config_msg, sizeof(config_msg) - 1, "host_para={%s} ", cfg_host_para);
						strcat(rule, config_msg);
					}
				}

				if(mask & TCP_PORT_PROTECT_MASK)
				{
					/*get tcp port protection parameters*/
					tcp_port_prot = cJSON_GetObjectItem(server,"tcp_port_prot");

					if(NULL == tcp_port_prot)
					{
						printf("Cannot get tcp_port_prot!\n");
						//continue;
					}
					else
					{
						port_size = cJSON_GetArraySize(tcp_port_prot);
						for(iport = 0; iport < port_size; iport++)
						{
							port_item = cJSON_GetArrayItem(tcp_port_prot, iport);
							if(port_item == NULL)
								continue;
							//bzero(cfg_tcp, sizeof(cfg_tcp));
							strcat(cfg_tcp, "{");
							for(j = 0; j < MAX_TCP_PORT_PROTECT_ITEM_NUM; j++)
							{
								item = cJSON_GetObjectItem(port_item, tcp_port_prot_key[j]);
								//printf("tcp_port_prot: item value:%d!\n", item->valueint);

								n = snprintf(config_msg, sizeof(config_msg) - 1, "%s=%d ", tcp_port_prot_key[j], item->valueint);
								strncat(cfg_tcp, config_msg, n);
							}
							strcat(cfg_tcp, "} ");
						}


						snprintf(config_msg, sizeof(config_msg) - 1, "tcp_port_prot={port_num=%u tcp_port_set=[%s]} ", port_size, cfg_tcp);
						strcat(rule, config_msg);
					}
				}

				if(mask & UDP_PORT_PROTECT_MASK)
				{
					/*get udp port protection parameters*/
					udp_port_prot = cJSON_GetObjectItem(server,"udp_port_prot");

					if(NULL == udp_port_prot)
					{
						printf("Cannot get udp_port_prot!\n");
						//continue;
					}
					else
					{
						port_size = cJSON_GetArraySize(udp_port_prot);
						for(iport = 0; iport < port_size; iport++)
						{
							port_item = cJSON_GetArrayItem(udp_port_prot, iport);
							if(port_item == NULL)
								continue;
							strcat(cfg_udp, "{");
							for(j = 0; j < MAX_UDP_PORT_PROTECT_ITEM_NUM; j++)
							{
								item = cJSON_GetObjectItem(port_item, udp_port_prot_key[j]);
								//printf("udp_port_prot: item value:%d!\n", item->valueint);

								n = snprintf(config_msg, sizeof(config_msg) - 1, "%s=%d ", udp_port_prot_key[j], item->valueint);
								strncat(cfg_udp, config_msg, n);
							}
							strcat(cfg_udp, "} ");
						}

						snprintf(config_msg, sizeof(config_msg) - 1, "udp_port_prot={port_num=%u udp_port_set=[%s]} ", port_size, cfg_udp);
						strcat(rule, config_msg);
					}
				}

				strcat(rule, "}");
				//snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: server_add {ip=%s  mask=%d host={%s} host_para={%s} tcp_port_prot={%s} udp_port_prot={%s} }",
				//ipstr, mask, cfg_host, cfg_host_para, cfg_tcp, cfg_udp);

				system(rule);
				printf("%s\n", rule);
			}
		}
	}
	else
	{
		fpdebug_fprintf (stderr, "Cannot get server_config  from key:server.\n");
	}

	cJSON_Delete(root);
	return 0;
}

int32_t total_b_w_list_config(char *tok)
{
	uint32_t numtokens = gettokens(tok);

	if(numtokens != 0)
	{
		fpdebug_fprintf (stderr, "fpcmd b_w_list_config \n");
		return -1;
	}

	system("fpngctl msg ddos: black_white_config");

	return 0;
}

int32_t b_w_list_config(char *tok)
{
	cJSON *root = NULL;
	cJSON *item = NULL;
	cJSON *b_w_list = NULL;
	cJSON *list = NULL;
	cJSON *ip_item = NULL;

	uint32_t i = 0, j = 0;
	uint32_t b_w_type = 0;
	uint32_t size = 0,  ip_size = 0, dport = 0;
	char oper[16] = {0};
	char type[16] = {0};
	char srcip[32] = {0};
	char dstip[32] = {0};
	char rule[128] = {0};

	uint32_t numtokens = gettokens(tok);

	if(numtokens != 0)
	{
		fpdebug_fprintf (stderr, "fpcmd b_w_config\n");
		return 0;
	}

	fp_shm_addr[DDOS_SHM_CONFIG] = fp_ddos_shm_lookup(&fp_shared->fp_ddos_shm[DDOS_SHM_CONFIG]);
	if(NULL == fp_shm_addr[DDOS_SHM_CONFIG]){
		printf("Lookup share memory:%s failed.\n", fp_shared->fp_ddos_shm[DDOS_SHM_CONFIG].name);
		return -1;
	}


	//json_string = b64_decode((char *)p_shm_config, atoi(chargv[1]));

	//printf("json_string: %s.\n", json_string);

	root = cJSON_Parse((char *)fp_shm_addr[DDOS_SHM_CONFIG]);
	if(root == NULL)
	{
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		return -1;
	}

#define IS_WHITE  0
#define IS_BLACK  1

	b_w_list = cJSON_GetObjectItem(root, "b_w_list");
	if(b_w_list != NULL)
	{
		size = cJSON_GetArraySize(b_w_list);
		for(i = 0; i < size; i++)
		{
			list = cJSON_GetArrayItem(b_w_list, i);

			if(list == NULL)
				continue;

			item = cJSON_GetObjectItem(list, "oper");
			bzero(oper, sizeof(oper));
			snprintf(oper, sizeof(oper) - 1, "%s", item->valuestring);

			item = cJSON_GetObjectItem(list, "type");
			bzero(type, sizeof(type));
			snprintf(type, sizeof(type) - 1, "%s", item->valuestring);

			if(!strcmp(type, "black"))
				b_w_type = IS_BLACK;
			else if (!strcmp(type, "white"))
				b_w_type = IS_WHITE;
			else
				printf("Invalid b_w_type:%s!\n", type);

			snprintf(srcip, sizeof(srcip) - 1, "0.0.0.0");
			snprintf(dstip, sizeof(dstip) - 1, "0.0.0.0");
			dport = 0;

			ip_item = cJSON_GetObjectItem(list, "ip");

			ip_size = cJSON_GetArraySize(ip_item);
			for(j = 0; j < ip_size; j++)
			{
				item = cJSON_GetArrayItem(ip_item, j);
				snprintf(srcip, sizeof(srcip) - 1, "%s", item->valuestring);
				printf("b_w_list, ip:%s.\n", srcip);
				bzero(rule, sizeof(rule));
				snprintf(rule, sizeof(rule) - 1, "fpngctl msg ddos: black_white_%s {srcip=%s dstip=%s dport=%d type=%d}", oper, srcip, dstip, dport, b_w_type);
				printf("%s\n", rule);
			}
		}
	}
	return 0;
}


static uint64_t r_rdtsc(void)
{
	union {
		uint64_t tsc_64;
		struct {
			uint32_t lo_32;
			uint32_t hi_32;
		};
	} tsc;

	asm volatile("rdtsc" :
		"=a" (tsc.lo_32),
		"=d" (tsc.hi_32));
	return tsc.tsc_64;
}

int32_t log_test(char *tok)
{
	uint32_t numtokens = gettokens(tok);
#define NUM_LOG_SIZE 10
	if(numtokens != 0)
	{
		fpdebug_fprintf (stderr, "fpcmd log_test\n");
		return 0;
	}
	for( int i = 0; i < NUM_LOG_SIZE; i++)
	{
		fp_shared->attack_log_table[i].client_ip = i;
		fp_shared->attack_log_table[i].server_ip = 3232236801+i;
		fp_shared->attack_log_table[i].server_port = 3232236801+i;
		fp_shared->attack_log_table[i].start_time = r_rdtsc();
		fp_shared->attack_log_table[i].end_time = r_rdtsc()+100;
		fp_shared->attack_log_table[i].type = i%2;
	}

	//fp_shared->attack_log_start = 0;
	fp_shared->attack_log_end += NUM_LOG_SIZE;

	return 0;
}

int32_t log_show(char *tok)
{
	char client_ipstr[20] = {0};
	char server_ipstr[20] = {0};
	uint32_t numtokens = gettokens(tok);
	uint32_t num_log = 0;

	if(numtokens != 1)
	{
		fpdebug_fprintf (stderr, "fpcmd log_show no \n");
		return -1;
	}

	printf("log_start:%d, log_end:%d \n", fp_shared->attack_log_start, fp_shared->attack_log_end);

	num_log = atoi(chargv[0]);

	if(num_log > ATTACK_LOG_TABLE)
	{		
		return -1;
	}

	bzero(client_ipstr, sizeof(client_ipstr));
	bzero(server_ipstr, sizeof(server_ipstr));

		
	fpdebug_inet_ntop(AF_INET, &fp_shared->attack_log_table[num_log].client_ip, client_ipstr, sizeof(client_ipstr));

	fpdebug_inet_ntop(AF_INET, &fp_shared->attack_log_table[num_log].server_ip, server_ipstr, sizeof(server_ipstr));	


	printf("%d: client_ip:%s, server_ip:%s, server_port:%d, start_time:%lu, end_time:%lu, type:%d\n ", 
		num_log, client_ipstr,  server_ipstr,
		fp_shared->attack_log_table[num_log].server_port,
		fp_shared->attack_log_table[num_log].start_time,
		fp_shared->attack_log_table[num_log].end_time,
		fp_shared->attack_log_table[num_log].type);	


	return 0;
}

static uint64_t get_current_time(void)
{
	struct timeval cur_t;
	uint64_t current_time = 0;

	gettimeofday(&cur_t, NULL);
	current_time = cur_t.tv_sec * 1000 + cur_t.tv_usec / 1000;

	return current_time;
}


static uint64_t get_log_time(uint64_t log_cycle)
{
	uint64_t current_cycle = r_rdtsc();
	uint64_t current_time = get_current_time();

	if(0 == log_cycle)
	{
		return 0;
	}

	if(current_cycle < log_cycle)
	{
		printf("Invalid log_cycle:%lu > current_cycle:%lu.\n", log_cycle, current_cycle);
		return current_time;
	}
	uint64_t diff_time = 1000 * (current_cycle - log_cycle) / (fp_shared->cpu_hz); // ms

	return current_time - diff_time;
}

int32_t send_ddos_log(char *tok){
	int i = fp_shared->attack_log_start;
	int end = fp_shared->attack_log_end;
	char * out = NULL;
	cJSON *root = NULL;
	cJSON *item = NULL;
	cJSON *server_log = NULL;
	cJSON *pJsonArry = NULL;
	//uint64_t cur_cycle = 0;

	char ipstr[20] = {0};
	int get_num = 0;
	uint32_t numtokens = gettokens(tok);

	if(numtokens != 0)
	{
		fpdebug_fprintf (stderr, "fpcmd send_ddos_log\n");
		return 0;
	}

	if ( (end - i + ATTACK_LOG_TABLE)%ATTACK_LOG_TABLE ==0)
	{
		return 0;
	}
	fp_shm_addr[DDOS_SHM_LOG] = fp_ddos_shm_lookup(&fp_shared->fp_ddos_shm[DDOS_SHM_LOG]);
	if(NULL == fp_shm_addr[DDOS_SHM_LOG]){
		printf("Lookup share memory:%s failed.\n", fp_shared->fp_ddos_shm[DDOS_SHM_LOG].name);
		return -1;
	}

#if 1
	root = cJSON_CreateObject();
	if (root == NULL)
	{
		return -1;
	}
#endif
	//printf("attack_log_start: %d, attack_log_end:%d.\n", fp_shared->attack_log_start, fp_shared->attack_log_end);
	pJsonArry = cJSON_CreateArray();
	while( (end - i + ATTACK_LOG_TABLE)%ATTACK_LOG_TABLE > 0 )
	{
 		server_log = cJSON_CreateObject();

		if(server_log == NULL)
		{
			i = (i+1)%ATTACK_LOG_TABLE;
			cJSON_Delete(server_log);
			continue;
		}
		else
		{
			bzero(ipstr, sizeof(ipstr));
			if(0 != fp_shared->attack_log_table[i].client_ip)
				fpdebug_inet_ntop(AF_INET, &fp_shared->attack_log_table[i].client_ip, ipstr, sizeof(ipstr));
			else
				strcat(ipstr, "0");
			item = cJSON_CreateString(ipstr);

		 	if(item)
				cJSON_AddItemToObject(server_log, "attack_ip", item);
	    	else
    		{
    			i = (i+1)%ATTACK_LOG_TABLE;
				continue;
	    	}

	    	bzero(ipstr, sizeof(ipstr));
	    	if(0 != fp_shared->attack_log_table[i].server_ip)
				fpdebug_inet_ntop(AF_INET, &fp_shared->attack_log_table[i].server_ip, ipstr, sizeof(ipstr));
			else
				strcat(ipstr, "0");

			item = cJSON_CreateString(ipstr);
		 	if(item)
				cJSON_AddItemToObject(server_log, "target_ip", item);
	    	else
    		{
    			i = (i+1)%ATTACK_LOG_TABLE;
				continue;
	    	}


		 	item = cJSON_CreateNumber(fp_shared->attack_log_table[i].server_port);
		 	if(item)
	    			cJSON_AddItemToObject(server_log, "target_port", item);
		 	else
		 	{
	    		i = (i+1)%ATTACK_LOG_TABLE;
				continue;
	    	}


			item = cJSON_CreateNumber( get_log_time(fp_shared->attack_log_table[i].start_time));
		 	if(item)
	    			cJSON_AddItemToObject(server_log, "start_time", item);
		 	else
		 	{
	    		i = (i+1)%ATTACK_LOG_TABLE;
				continue;
	    	}

	    	item = cJSON_CreateNumber(get_log_time(fp_shared->attack_log_table[i].end_time));
		 	if(item)
	    			cJSON_AddItemToObject(server_log, "end_time", item);
		 	else
		 	{
	    		i = (i+1)%ATTACK_LOG_TABLE;
				continue;
	    	}

	    	item = cJSON_CreateNumber(fp_shared->attack_log_table[i].type);
		 	if(item)
	    			cJSON_AddItemToObject(server_log, "attack_type", item);
		 	else
		 	{
	    		i = (i+1)%ATTACK_LOG_TABLE;
				continue;
	    	}
	    	cJSON_AddItemToArray(pJsonArry, server_log);

			//cJSON_AddItemToObject(root, ipstr, server_log);
		}

		i = (i+1)%ATTACK_LOG_TABLE;
		get_num++;
		if(get_num >= ATTACK_LOG_TABLE)
			break;

	}
	cJSON_AddItemToObject(root, "server", pJsonArry);
	fp_shared->attack_log_start = i;
	//printf("Update attack_log_start to %d.\n", fp_shared->attack_log_start);

	out = cJSON_PrintUnformatted(pJsonArry);
	//printf("Out: %s.\n", out);
	if(out != NULL)
		memcpy(fp_shm_addr[DDOS_SHM_LOG], out, strlen(out));

	cJSON_Delete(root);
	if(out != NULL)
       		free(out);

	return 0;
}

int32_t fp_shm_lookup_show(enum ddos_shm  shm_id)
{
	fp_shm_addr[shm_id] = fp_ddos_shm_lookup(&fp_shared->fp_ddos_shm[shm_id]);
	if(NULL == fp_shm_addr[shm_id]){
		printf("Lookup share memory:%s failed.\n", fp_shared->fp_ddos_shm[shm_id].name);
		return -1;
	}
	else {
		printf("%s: %s.\n", fp_shared->fp_ddos_shm[shm_id].name, (char *)fp_shm_addr[shm_id]);
	}

	return 0;
}

int32_t fp_shm_lookup_clear(enum ddos_shm  shm_id)
{
	fp_shm_addr[shm_id] = fp_ddos_shm_lookup(&fp_shared->fp_ddos_shm[shm_id]);
	if(NULL == fp_shm_addr[shm_id]){
		printf("Lookup share memory:%s failed.\n", fp_shared->fp_ddos_shm[shm_id].name);
		return -1;
	}
	else {
		memset(fp_shm_addr[shm_id], 0, strlen(fp_shm_addr[shm_id]));
	}

	return 0;
}

int32_t fp_shm_show(char *tok)
{
	uint32_t numtokens = gettokens(tok);

	if(numtokens != 1)
	{
		fpdebug_fprintf (stderr, "fpcmd fp_shm_show -config/-status/-log/-t_b_w_table\n");
		return -1;
	}
	if(strcmp(chargv[0],"-config") == 0 )
	{
		fp_shm_lookup_show(DDOS_SHM_CONFIG);
	}
	else if(strcmp(chargv[0],"-status") == 0 )
	{
		fp_shm_lookup_show(DDOS_SHM_STATUS);
	}
	else if(strcmp(chargv[0],"-log") == 0 )
	{
		fp_shm_lookup_show(DDOS_SHM_LOG);			
	}
	else if(strcmp(chargv[0],"-t_b_w_table") == 0 )
	{
		fp_shm_lookup_show(DDOS_SHM_TMP_B_W);
	}
	else
	{
		fpdebug_fprintf (stderr, "Invalid cmd, right format is: fpcmd fp_shm_show -config/-status/-log/-t_b_w_table\n");
		return -1;
	}

	return 0;
}

int32_t fp_shm_clear(char *tok)
{
	uint32_t numtokens = gettokens(tok);

	if(numtokens != 1)
	{
		fpdebug_fprintf (stderr, "fpcmd fp_shm_clear -config/-status/-log/-t_b_w_table\n");
		return -1;
	}
	if(strcmp(chargv[0], "-config") == 0 )
	{
		fp_shm_lookup_clear(DDOS_SHM_CONFIG);
	}
	else if(strcmp(chargv[0], "-status") == 0 )
	{
		fp_shm_lookup_clear(DDOS_SHM_STATUS);
	}
	else if(strcmp(chargv[0], "-log") == 0 )
	{
		fp_shm_lookup_clear(DDOS_SHM_LOG);
	}
	else if(strcmp(chargv[0],"-t_b_w_table") == 0 )
	{
		fp_shm_lookup_clear(DDOS_SHM_TMP_B_W);
	}
	else
	{
		fpdebug_fprintf (stderr, "Invalid cmd, right format is: fpcmd fp_shm_clear -config/-status/-log/-t_b_w_table\n");
		return -1;
	}
	return 0;
}

int32_t temp_black_white_table_show(char *tok)
{
	uint32_t numtokens = gettokens(tok);

	if(numtokens != 0)
	{
		fpdebug_fprintf (stderr, "fpcmd temp_b_w_table_status\n");
		return -1;
	}
	system("fpngctl msg ddos: temp_black_white_status");

	return 0;
}

int32_t temp_black_table_delete(char *tok)
{
	uint32_t numtokens = gettokens(tok);
	char dst_ip[32] = {0};
	char src_ip[32] = {0};
	char msg[256] = {0};
	

	if(numtokens != 4)
	{
		fpdebug_fprintf (stderr, "fpcmd temp_b_table_del -dst_ip x.x.x.x -src_ip y.y.y.y\n");
		return -1;
	}
	if(strcmp(chargv[0], "-dst_ip") == 0 )
	{
		strcpy(dst_ip, chargv[1]);
		if(strcmp(chargv[2], "-src_ip") == 0 )
		{
			strcpy(src_ip, chargv[3]);
		}
	}
	else 
	{
		fpdebug_fprintf (stderr, "Invalid cmd, right format is: fpcmd temp_b_table_del -dst_ip x.x.x.x -src_ip y.y.y.y\n");
		return -1;
	}

	snprintf(msg, sizeof(msg)-1, "fpngctl msg ddos: temp_black_white_del {srcip=%s dstip=%s type=1}", src_ip, dst_ip);
	system(msg);

	printf("%s\n", msg);

	return 0;
}

int32_t temp_white_table_delete(char *tok)
{
	uint32_t numtokens = gettokens(tok);
	char dst_ip[32];
	char src_ip[32];
	char msg[256] = {0};
	

	if(numtokens != 4)
	{
		fpdebug_fprintf (stderr, "fpcmd temp_w_table_del -dst_ip x.x.x.x -src_ip y.y.y.y\n");
		return -1;
	}
	if(strcmp(chargv[0], "-dst_ip") == 0 )
	{
		memcpy(dst_ip, chargv[1], strlen(chargv[1]));
		if(strcmp(chargv[2], "-src_ip") == 0 )
		{
			memcpy(src_ip, chargv[3], strlen(chargv[3]));
		}
	}
	else 
	{
		fpdebug_fprintf (stderr, "Invalid cmd, right format is: fpcmd temp_w_table_del -dst_ip x.x.x.x -src_ip y.y.y.y\n");
		return -1;
	}

	snprintf(msg, sizeof(msg)-1, "fpngctl msg ddos: temp_black_white_del {srcip=%s dstip=%s type=0}", src_ip, dst_ip);
	system(msg);
	
	printf("%s\n", msg);

	return 0;
}

int32_t server_test_config(char *tok)
{
	int nlen = 0;
	char * out = NULL;

	cJSON *root = NULL;
	cJSON *item = NULL;
	cJSON *server = NULL;
	cJSON *host = NULL;
	cJSON *pJsonArry = NULL;
	cJSON *ptcp = NULL;
	cJSON *ptcpArry = NULL;
	cJSON *system = NULL;
	char ipstr[32] = {0};
	char oper[16] = {0};

	fp_shm_addr[DDOS_SHM_CONFIG] = fp_ddos_shm_lookup(&fp_shared->fp_ddos_shm[DDOS_SHM_CONFIG]);
	if(NULL == fp_shm_addr[DDOS_SHM_CONFIG]){
		printf("Lookup share memory:%s failed.\n", fp_shared->fp_ddos_shm[DDOS_SHM_CONFIG].name);
		return -1;
	}

	uint32_t numtokens = gettokens(tok);

	if(numtokens != 2)
	{
		fpdebug_fprintf (stderr, "fpcmd server_test_config add/del/update 1-50000\n");
		return -1;
	}
	memcpy(oper, chargv[0], strlen(chargv[0]));	
	int nIP = atoi(chargv[1]);	
	uint32_t ip = 0;

#if 1
	root = cJSON_CreateObject();
	if (root == NULL)
	{
		return -1;
	}
#endif

	pJsonArry = cJSON_CreateArray();

	for(int i = 0;  i < nIP; i++)
	{
		//begin
		server = cJSON_CreateObject();		
		fpdebug_inet_pton(AF_INET, "1.5.168.192", &ip);
		ip = ntohl(ip+i);
		fpdebug_inet_ntop(AF_INET, &ip, ipstr, sizeof(ipstr));
		item = cJSON_CreateString(ipstr);
		cJSON_AddItemToObject(server, "ip", item);

		item = cJSON_CreateString(oper);
		cJSON_AddItemToObject(server, "oper", item);

		item = cJSON_CreateNumber(15);
		cJSON_AddItemToObject(server, "mask", item);
		
		if(!strcmp(oper, "add")){
			host = cJSON_CreateObject();
			item = cJSON_CreateNumber(23+i);
			cJSON_AddItemToObject(host, "flow_in", item);

			item = cJSON_CreateNumber(23+i);
			cJSON_AddItemToObject(host, "pkt_in", item);

			item = cJSON_CreateNumber(123);
			cJSON_AddItemToObject(host, "flow_out", item);

			item = cJSON_CreateNumber(390);
			cJSON_AddItemToObject(host, "pkt_out", item);

			item = cJSON_CreateNumber(5);
			cJSON_AddItemToObject(host, "flow_pol", item);

			cJSON_AddItemToObject(server, "host", host);

			ptcpArry = cJSON_CreateArray();
			//ptcp = cJSON_CreateString("tcp_port_prot");
			for(int j = 0; j < 2; j++)
			{
				ptcp = cJSON_CreateObject();
				/*str=1 end=80 on_off=1 atk_fre=100, con_lmt=56 det_wei=100 pro_mode=2*/
				item = cJSON_CreateNumber(156+i);
				cJSON_AddItemToObject(ptcp, "str", item);

				item = cJSON_CreateNumber(157+i);
				cJSON_AddItemToObject(ptcp, "end", item);

				item = cJSON_CreateNumber(1);
				cJSON_AddItemToObject(ptcp, "on_off", item);

				item = cJSON_CreateNumber(19);
				cJSON_AddItemToObject(ptcp, "atk_fre", item);

				item = cJSON_CreateNumber(15);
				cJSON_AddItemToObject(ptcp, "con_lmt", item);

				item = cJSON_CreateNumber(1900);
				cJSON_AddItemToObject(ptcp, "det_wei", item);

				item = cJSON_CreateNumber(2);
				cJSON_AddItemToObject(ptcp, "pro_mod", item);

				cJSON_AddItemToArray(ptcpArry, ptcp);
			}

			cJSON_AddItemToObject(server, "tcp_port_prot", ptcpArry);
		}	

		//cJSON_AddItemToObject(root, "server", server);
		cJSON_AddItemToArray(pJsonArry, server);
		//end
	}

	cJSON_AddItemToObject(root, "server", pJsonArry);

	system = cJSON_CreateObject();

	item = cJSON_CreateString("bypass");
	cJSON_AddItemToObject(system, "def_mod", item);

	item = cJSON_CreateNumber(20000);
	cJSON_AddItemToObject(system, "blk_time", item);

	cJSON_AddItemToObject(root, "system_para", system);

	//out = cJSON_Print(root);
	out = cJSON_PrintUnformatted(root);
	if(out != NULL)
	{
		nlen = strlen(out);
		printf("Length of test jason is :%d!\n", nlen);
		memcpy(fp_shm_addr[DDOS_SHM_CONFIG], out, nlen);
	}

	//printf("out: %s.\n", out);
	//memcpy(fp_config, test_jason, strlen(test_jason));

	//printf("fp_config: %s.\n", (char *)fp_config);

	cJSON_Delete(root);
	if(out != NULL)
		free(out);

	return 0;
}

int32_t b_w_test_config(char *tok)
{
	int nlen = 0;
	char * out = NULL;

	cJSON *root = NULL;
	cJSON *list = NULL;
	cJSON *item = NULL;
	//cJSON *b_w_list = NULL;
	cJSON *pJsonArry = NULL;
	cJSON *ipArry = NULL;
	//char ipstr[32] = {0};
	//uint32_t ip = 0;

	fp_shm_addr[DDOS_SHM_CONFIG] = fp_ddos_shm_lookup(&fp_shared->fp_ddos_shm[DDOS_SHM_CONFIG]);
	if(NULL == fp_shm_addr[DDOS_SHM_CONFIG]){
		printf("Lookup share memory:%s failed.\n", fp_shared->fp_ddos_shm[DDOS_SHM_CONFIG].name);
		return -1;
	}

	uint32_t numtokens = gettokens(tok);

	if(numtokens != 0)
	{
		fpdebug_fprintf (stderr, "fpcmd b_w_test \n");
		return -1;
	}
	

#if 1
	root = cJSON_CreateObject();
	if (root == NULL)
	{
		return -1;
	}
#endif

	pJsonArry = cJSON_CreateArray();

	//b_w_list = cJSON_CreateObject();	
	for(int i = 0;  i < 2; i++)
	{
		//begin
		list = cJSON_CreateObject();		

		item = cJSON_CreateNumber(i);
		cJSON_AddItemToObject(list, "grp", item);

		item = cJSON_CreateString("add");
		cJSON_AddItemToObject(list, "oper", item);	
		
		ipArry = cJSON_CreateArray();
		/*
		for(int j = 0; j < 3; j++)
		{			
			fpdebug_inet_pton(AF_INET, "1.5.168.192", &ip);
			ip = ntohl(ip+i+j);
			fpdebug_inet_ntop(AF_INET, &ip, ipstr, sizeof(ipstr));
			item = cJSON_CreateString(ipstr);	

			cJSON_AddItemToArray(ipArry, item);
		}
		*/
		item = cJSON_CreateString("1.2.3.4/28");
		cJSON_AddItemToArray(ipArry, item);

		item = cJSON_CreateString("12.12.13.14");
		cJSON_AddItemToArray(ipArry, item);

		cJSON_AddItemToObject(list, "ip", ipArry);
		

		//cJSON_AddItemToObject(root, "server", server);
		cJSON_AddItemToArray(pJsonArry, list);
		//end
	}

	cJSON_AddItemToObject(root, "b_list", pJsonArry);


	pJsonArry = cJSON_CreateArray();
	//b_w_list = cJSON_CreateObject();	
	for(int i = 0;  i < 2; i++)
	{
		//begin
		list = cJSON_CreateObject();		

		item = cJSON_CreateNumber(i);
		cJSON_AddItemToObject(list, "grp", item);

		item = cJSON_CreateString("add");
		cJSON_AddItemToObject(list, "oper", item);	
		
		ipArry = cJSON_CreateArray();

		/*
		for(int j = 0; j < 3; j++)
		{			
			fpdebug_inet_pton(AF_INET, "1.10.168.192", &ip);
			ip = ntohl(ip+i+j);
			fpdebug_inet_ntop(AF_INET, &ip, ipstr, sizeof(ipstr));
			item = cJSON_CreateString(ipstr);	

			cJSON_AddItemToArray(ipArry, item);
		}*/

		item = cJSON_CreateString("10.20.30.40-10.20.30.60");
		cJSON_AddItemToArray(ipArry, item);

		item = cJSON_CreateString("120.120.130.1");
		cJSON_AddItemToArray(ipArry, item);


		cJSON_AddItemToObject(list, "ip", ipArry);
		

		//cJSON_AddItemToObject(root, "server", server);
		cJSON_AddItemToArray(pJsonArry, list);
		//end
	}

	cJSON_AddItemToObject(root, "w_list", pJsonArry);

	
	//out = cJSON_Print(root);
	out = cJSON_PrintUnformatted(root);
	if(out != NULL)
	{
		nlen = strlen(out);
		printf("Length of test jason is :%d!\n", nlen);
		memcpy(fp_shm_addr[DDOS_SHM_CONFIG], out, nlen);
	}

	//printf("out: %s.\n", out);
	//memcpy(fp_config, test_jason, strlen(test_jason));

	//printf("fp_config: %s.\n", (char *)fp_config);

	cJSON_Delete(root);
	if(out != NULL)
		free(out);

	return 0;
}

// licence
uint8_t check_sum(uint8_t* bytes, uint32_t len);
void serial_init(char info[1024]);
uint32_t verify_licence(const char* file_name, char debug_info_str[4096], uint32_t for_test) ;
int32_t load_licence(char *tok);
int32_t licence_status(char *tok);
//
// @return value:  0: success; -1: licence not exist; -2: mmap error
//
int32_t get_licence_time(const char* file_name, int32_t *alive_time, int32_t *tick_count, int32_t *utc_timestamp, uint8_t *cksum);
int32_t set_licence_time(const char* file_name, int32_t alive_time, int32_t tick_count, int32_t utc_timestamp, uint8_t cksum);
// }

int32_t product_serial(char *tok) {
	uint32_t c = gettokens(tok);

	if ((c > 0 && !strcmp(chargv[0], "init"))) {
		char info[1024];

		serial_init(info);

		fpdebug_printf("%s - ", info);
	} else if (!fp_shared->product_serial.data[0]) {
		serial_init(0);
	}

	fpdebug_printf("%s", fp_shared->product_serial.data);

	return 0;
}

int32_t load_licence(char *tok) {
	uint32_t c = gettokens(tok);
	uint32_t for_test = 0;
	uint32_t status = 0;
	char* licence_file_name = NULL;
	char buf[4096] = {0};

	if (c > 1 && !strcmp(chargv[0], "--test")) {
		for_test = 1;
		licence_file_name = chargv[1];
	}

	status = verify_licence(licence_file_name, buf, for_test);

	if (c > 2 && !strcmp(chargv[2], "-v")) {
		fpdebug_printf("%s -- ", buf);
	}

	switch(status) {
		case LICENCE_UNINIT:
			fpdebug_printf("uninit");
		break;
		case LICENCE_VALID:
			fpdebug_printf("valid");
		break;
		case LICENCE_MISSING:
			fpdebug_printf("missing");
		break;
		case LICENCE_DEVICE_NOT_MATCH:
			fpdebug_printf("device_not_match");
		break;
		case LICENCE_MALFORM:
			fpdebug_printf("malform");
		break;
		case LICENCE_EXPIRED:
			fpdebug_printf("expired");
		break;
		case LICENCE_TYPE_ERROR:
			fpdebug_printf("type_error");
		break;
		default:
			fpdebug_printf("unknown");
		break;
	}

	return 0;
}

int32_t licence_status(char *tok) {
	cJSON* root_obj;

	if (fp_shared->licence.status == LICENCE_UNINIT) {
		verify_licence(NULL, NULL, 0);
	}

	root_obj = cJSON_CreateObject();

	switch(fp_shared->licence.status) {
		case LICENCE_UNINIT:
			cJSON_AddItemToObject(root_obj, "status", cJSON_CreateString("uninit"));
		break;
		case LICENCE_VALID:
		case LICENCE_EXPIRED:
			cJSON_AddItemToObject(root_obj, "status", cJSON_CreateString(fp_shared->licence.status == LICENCE_VALID ? "valid" : "expired"));
			cJSON_AddItemToObject(root_obj, "id", cJSON_CreateString(fp_shared->licence.id));
			cJSON_AddItemToObject(root_obj, "desc", cJSON_CreateString(fp_shared->licence.desc));
			cJSON_AddItemToObject(root_obj, "lang", cJSON_CreateString(fp_shared->licence.lang));
			cJSON_AddItemToObject(root_obj, "licence_owner", cJSON_CreateString(fp_shared->licence.licence_owner));
			cJSON_AddItemToObject(root_obj, "copy_right", cJSON_CreateString(fp_shared->licence.copy_right));
			cJSON_AddItemToObject(root_obj, "type", cJSON_CreateString(fp_shared->licence.type == LICENCE_TYPE_OFFICIAL ? "official" : "test"));
			cJSON_AddItemToObject(root_obj, "device_id", cJSON_CreateString(fp_shared->product_serial.data));
			cJSON_AddItemToObject(root_obj, "user", cJSON_CreateString(fp_shared->licence.user));
			cJSON_AddItemToObject(root_obj, "model", cJSON_CreateString(fp_shared->licence.model));

			cJSON_AddItemToObject(root_obj, "create_time", cJSON_CreateNumber(fp_shared->licence.create_time));
			cJSON_AddItemToObject(root_obj, "start_time", cJSON_CreateNumber(fp_shared->licence.start_time));
			cJSON_AddItemToObject(root_obj, "end_time", cJSON_CreateNumber(fp_shared->licence.end_time));

			cJSON_AddItemToObject(root_obj, "max_hosts", cJSON_CreateNumber(fp_shared->licence.max_hosts));
			cJSON_AddItemToObject(root_obj, "max_flows", cJSON_CreateNumber(fp_shared->licence.max_flows));

			cJSON_AddItemToObject(root_obj, "alive_time", cJSON_CreateNumber(fp_shared->licence.licence_time.alive_time));
			cJSON_AddItemToObject(root_obj, "tick_count", cJSON_CreateNumber(fp_shared->licence.licence_time.sys_tick_count));
			cJSON_AddItemToObject(root_obj, "utc_timestamp", cJSON_CreateNumber(fp_shared->licence.licence_time.utc_timestamp));
		break;
		case LICENCE_MISSING:
			cJSON_AddItemToObject(root_obj, "status", cJSON_CreateString("missing"));
		break;
		case LICENCE_DEVICE_NOT_MATCH:
			cJSON_AddItemToObject(root_obj, "status", cJSON_CreateString("device_not_match"));
		break;
		case LICENCE_MALFORM:
			cJSON_AddItemToObject(root_obj, "status", cJSON_CreateString("malform"));
		break;
		case LICENCE_TYPE_ERROR:
			cJSON_AddItemToObject(root_obj, "status", cJSON_CreateString("type_error"));
		break;
		default:
			cJSON_AddItemToObject(root_obj, "status", cJSON_CreateString("unknown"));
		break;

	}

	fpdebug_printf("%s", cJSON_PrintUnformatted(root_obj));

	cJSON_Delete(root_obj);
	return 0;
}

int32_t update_licence_time(char *tok) {

	int32_t alive_time;
	int32_t sys_tick_count;
	int32_t utc_timestamp;

	int32_t now_tick_count, now_utc;
	uint8_t cksum = 0;

	if (fp_shared->licence.status == LICENCE_UNINIT) {
		verify_licence(NULL, NULL, 0);
	}

	if (fp_shared->licence.status != LICENCE_VALID) {
		fp_shared->licence.licence_time.alive_time = 0;
		fp_shared->licence.licence_time.sys_tick_count = 0;
		fp_shared->licence.licence_time.utc_timestamp = 0;
		return 0;
	}

	alive_time = fp_shared->licence.licence_time.alive_time;
	sys_tick_count = fp_shared->licence.licence_time.sys_tick_count;
	utc_timestamp = fp_shared->licence.licence_time.utc_timestamp;

	now_utc = time(0);

	{
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);

		now_tick_count = ts.tv_sec;
	}

	if (now_tick_count <= sys_tick_count) {
		alive_time -= now_utc - utc_timestamp;
	} else {
		alive_time -= now_tick_count - sys_tick_count;
	}

	if (alive_time <= 0) {
		fp_shared->licence.status = LICENCE_EXPIRED;
		return 0;
	}

	{
		uint32_t ar[3] = {alive_time, now_tick_count, now_utc};

		cksum = check_sum((uint8_t*)ar, 12);
	}

	if (set_licence_time(NULL, alive_time, now_tick_count, now_utc, cksum) >= 0) {
		// backup
		fp_shared->licence.licence_time.alive_time = alive_time;
		fp_shared->licence.licence_time.sys_tick_count = now_tick_count;
		fp_shared->licence.licence_time.utc_timestamp = now_utc;
	}

	return 0;
}
int32_t sys_total(char *tok){
	struct timeval cur_t;
	uint64_t current_time = 0;
	gettimeofday(&cur_t, NULL);
        current_time = cur_t.tv_sec * 1000 + cur_t.tv_usec / 1000;
	printf("total:%lu,%lu,%lu,%lu,%lu, %d,%d\n",current_time, fp_shared->total.status.in_bps, fp_shared->total.status.in_pps,
		fp_shared->total.status.in_bps_after_clean, fp_shared->total.status.in_pps_after_clean,
		fp_shared->tcp_session_num,fp_shared->udp_session_num);

	return 0;
}

#ifndef __FastPath__

struct cpu_t {
    unsigned long long u, n, s, i, w, x, y, z;
};

inline int read_cpu_usage(struct cpu_t *cpus) {
    FILE *fp = NULL;
    char buf[256] = {0};

    if (!(fp = fopen("/proc/stat", "r")) || !fgets(buf, sizeof(buf), fp)) {
        return -1;
    }

    fclose(fp);

    return sscanf(buf, "cpu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu",
        &cpus->u,
        &cpus->n,
        &cpus->s,
        &cpus->i,
        &cpus->w,
        &cpus->x,
        &cpus->y,
        &cpus->z
    ) < 8 ? -3 : 0;
}

int32_t sys_cpu_usage(char *tok __fpn_maybe_unused) {
    uint32_t delay = 200000; /* wait delay in us. by default 200ms */
    struct cpu_t cpu[2] = {{0}};

    uint64_t fp_work_cycles = 0, fp_total_cycles = 0;

    int argcount = gettokens(tok);
    int i;
    int fp_cpu_count = 0;

    cpu_usage_shared_mem_t *cpu_usage_shared = fpn_shmem_mmap("cpu-usage-shared",
                                  NULL,
                                  sizeof(cpu_usage_shared_mem_t));

    if (cpu_usage_shared == NULL) {
        return -1;
    }

    if (argcount > 0) {
        long d = strtoul(chargv[0], NULL, 0);
        delay = d > 100 ? d * 1000 : delay;
    }

    if (read_cpu_usage(&cpu[0]) < 0) {
        return -2;
    }

    /* Make sure to re-initialize the state */
    cpu_usage_shared->do_cpu_usage = 0;

    usleep(1000);

    for (i=0; i<FPN_MAX_CORES; i++)
        cpu_usage_shared->busy_cycles[i].end = 0;

    /* Enable dump-cpu-usage all cores main loop */
    cpu_usage_shared->do_cpu_usage = 1;

    usleep(delay);

    /* Disable dump-cpu-usage all cores main loop */
    cpu_usage_shared->do_cpu_usage = 0;

    /* Make sure all cores have finished */
    usleep(1000);

    if (read_cpu_usage(&cpu[1]) < 0) {
        return -3;
    }

    for (i=0; i<FPN_MAX_CORES; i++) {

        /* Skip vcpu that did not participate */
        if (cpu_usage_shared->busy_cycles[i].end == 0)
            continue;

        fp_cpu_count ++;

        if (cpu_usage_shared->busy_cycles[i].end <= cpu_usage_shared->busy_cycles[i].begin) {
            continue;
        }

        fp_total_cycles += cpu_usage_shared->busy_cycles[i].end - cpu_usage_shared->busy_cycles[i].begin;
        fp_work_cycles += cpu_usage_shared->busy_cycles[i].val;
    }

    {

        double total_cpu_usage = 1 - (double)(cpu[1].i - cpu[0].i)/(
            (cpu[1].u + cpu[1].n + cpu[1].s + cpu[1].i + cpu[1].w + cpu[1].x + cpu[1].y + cpu[1].z) -  
            (cpu[0].u + cpu[0].n + cpu[0].s + cpu[0].i + cpu[0].w + cpu[0].x + cpu[0].y + cpu[0].z));

        double fp_cpu_usage = (double)fp_work_cycles/fp_total_cycles;

        unsigned total_cpu = sysconf(_SC_NPROCESSORS_ONLN);

        double modified_usage = total_cpu_usage - (1 - fp_cpu_usage) * fp_cpu_count / total_cpu;

        if (argcount > 1 && strcmp(chargv[1], "-v") == 0) {
            printf("total/c: %lf/%d, fp/c: %lf/%d, modify: %lf\n", total_cpu_usage, total_cpu, fp_cpu_usage, fp_cpu_count, modified_usage);
        } else {
            printf("%.1lf", 100*modified_usage);
        }
    }

    return 0;
}
#endif