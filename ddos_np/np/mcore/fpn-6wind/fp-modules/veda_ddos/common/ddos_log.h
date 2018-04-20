#ifndef __DDOS_LOG_H__
#define __DDOS_LOG_H__

#define ATTACK_LOG_TABLE    (1<<10)
struct attack_log{
    uint32_t client_ip;
    uint32_t server_ip;
    uint16_t server_port;
    uint64_t start_time;
    uint64_t end_time;
    uint8_t type;
}__attribute__((packed));

void add_attack_log(uint32_t client_ip,uint32_t server_ip, uint16_t server_port,uint64_t start_time,uint64_t end_time,uint8_t type );

#endif /* __DDOS_LOG_H__*/