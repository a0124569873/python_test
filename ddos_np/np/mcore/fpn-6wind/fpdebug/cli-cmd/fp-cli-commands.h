#ifdef _EXPORT_DFCLI_CMDS_

	//{"fp_nfct_print", fp_nfct_print, "print the nfct count in shared memory"},
	//{"iptables_match_init", iptables_match_init, "iptables_match_init"},
	{"ddos_time", ddos_time, "ddos_time_param_config"},
	{"sys_status", get_ddos_status, "get_ddos_status"},
	//{"server_threshold", server_threshold, "server_threshold"},
	//{"black_white", black_white, "black_white"},
	{"ip_mac", ip_mac, "ip_mac"},
	{"stream_return", stream_return, "1: mac 2:mpls"},
	{"server_flow", server_flow, "server_flow"},

	{"system_config", system_config, "system_config"},
	//{"server_config", server_config, "server_config"},
	{"server_config", total_server_config, "server_config"},
	{"b_w_list_config", total_b_w_list_config, "b_w_list_config"},
	{"server_test_config", server_test_config, "server_test_config"},
	{"ddos_log", send_ddos_log, "send_ddos_log"},
	{"log_show", log_show, "log_show"},
	{"log_test", log_test, "log_test"},
	{"fp_shm_show", fp_shm_show, "fp config|status|log share memory show"},
	{"fp_shm_clear", fp_shm_clear, "fp config|status|log share memory clear"},
	{"b_w_test", b_w_test_config, "b_w_list_test_config"},
	{"temp_b_w_table_status", temp_black_white_table_show, "temp_b_w_table_status"},
	{"temp_b_table_del", temp_black_table_delete, "temp_b_table_del"},
	{"temp_w_table_del", temp_white_table_delete, "temp_w_table_del"},
	//
	
	{"dump-sock-mempool", fpn_sock_mempools, "dump sock mempool status"},
	{"dump-ring-buffer", dump_ring_buffer, "dump ring buffer info"},
	{"dump-mem-status", dump_mem_status, "dump mem status"},

	//
	{"serial_no", product_serial, "serial number"},
    {"load_licence", load_licence, "load licence"},
    {"licence_status", licence_status, "licence status in json format"},
    {"update_licence_time", update_licence_time, "update licence alive time"},

	//
	{"sys_total", sys_total, "sys_total"},
	//

#ifndef __FastPath__
    {"cpu-usage", sys_cpu_usage, "sys cpu usage"},
#endif

#else

#ifndef _COMMANDS_H
#define _COMMANDS_H



#define FP_CONFIG_SHM_KEY 0x19283746
#define FP_STATUS_SHM_KEY 0x78563412
#define FP_LOG_SHM_KEY 0x11335577

//int32_t fp_nfct_print(char *tok);
//int32_t iptables_match_init(char *tok);
int32_t ddos_time(char *tok);
int32_t server_threshold(char *tok);
int32_t get_ddos_status(char *tok);
int32_t black_white(char *tok);
int32_t ip_mac(char *tok);
int32_t stream_return(char *tok);
int32_t server_flow(char *tok);
int32_t system_config(char *tok);
int32_t total_server_config(char *tok);
int32_t server_config(char *tok);
int32_t total_b_w_list_config(char *tok);
int32_t b_w_list_config(char *tok);
int32_t send_ddos_log(char *tok);
int32_t log_show(char *tok);
int32_t log_test(char *tok);
int32_t b_w_test_config(char *tok);
int32_t fp_shm_show(char *tok);
int32_t fp_shm_clear(char *tok);
int32_t temp_black_white_table_show(char *tok);
int32_t temp_white_table_delete(char *tok);
int32_t temp_black_table_delete(char *tok);

int32_t server_test_config(char *tok);

//
int32_t fpn_sock_mempools(char* tok);
int32_t dump_ring_buffer(char* tok);
int32_t dump_mem_status(char* tok);
//
//int32_t add_jason_to_shm_b_w_test(char *tok);

// licence
int32_t product_serial(char *tok);
int32_t load_licence(char *tok);
int32_t licence_status(char *tok);
int32_t update_licence_time(char *tok);
int32_t sys_total(char *tok);

#ifndef __FastPath__
int32_t sys_cpu_usage(char *tok);
#endif

#endif // _COMMANDS_H
#endif // _EXPORT_DFCLI_CMDS_

