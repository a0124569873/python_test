#include <sys/ipc.h>
#include <sys/shm.h>
#include <error.h>

#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"
#include "../common/ddos_log.h"

void add_attack_log(uint32_t client_ip,uint32_t server_ip, uint16_t server_port,uint64_t start_time,uint64_t end_time,uint8_t type )
{
    uint32_t end = fp_shared->attack_log_end;
    fp_shared->attack_log_table[end].client_ip = client_ip;
    fp_shared->attack_log_table[end].server_ip = server_ip;
    fp_shared->attack_log_table[end].server_port = server_port;
    fp_shared->attack_log_table[end].start_time = start_time;
    fp_shared->attack_log_table[end].end_time = end_time;
    fp_shared->attack_log_table[end].type = type;

    end = (end+1)%ATTACK_LOG_TABLE;
    fp_shared->attack_log_end = end;
    return ;
}