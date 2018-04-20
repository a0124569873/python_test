#ifndef __IP_MAC_H__
#define __IP_MAC_H__
#define IP_MAC_TABLE     256
#define IP_MAC_RESULT    1024
struct ip_mac_t {
    uint32_t ip;
    uint8_t mac[6];
    uint8_t is_config;              // 1 user configure or 0 auto learn by arp
}__attribute__((packed));
struct ip_mac_node {
    struct ip_mac_t  ip_mac;
    struct ip_mac_node *next;
}__attribute__((packed));

struct ip_mac_table {
    struct ip_mac_node *next;
}__attribute__((packed));

#endif /* __IP_MAC_H_ */