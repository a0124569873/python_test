
#include <stdint.h>
#include <stdio.h>

#include <string.h>
#include <ifaddrs.h>  
#include <linux/if_packet.h>

uint32_t get_all_macs(char* macs, uint32_t len);
uint32_t get_sorted_macs(char* mac_buffer, uint32_t size, uint32_t (*f_mac_filter)(const char* name, const char* mac, uint32_t argc, void*  argv), uint32_t argc, void*  argv);


uint32_t get_all_macs(char* macs, uint32_t len) {
#if 1

    uint32_t c = 0;
    char* pmc = macs;
    struct ifaddrs *ifaddr, *ifa;

    *pmc = 0;

    if (getifaddrs(&ifaddr) == -1) {
        return 0;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != PF_PACKET) {
            continue;
        }

        struct sockaddr_ll* sl = (struct sockaddr_ll*)ifa->ifa_addr;
        uint32_t *pi = (uint32_t*)sl->sll_addr;

        if (*(pi) == 0 && *(pi + 1) == 0) {
            continue;
        }
    
        c ++;

        pmc += (uint32_t)snprintf(pmc, len - (pmc - macs), "%s", ifa->ifa_name);
        *pmc++ = 0;

        pmc += snprintf(pmc, len - (pmc - macs), "%02x:%02x:%02x:%02x:%02x:%02x",
            (uint8_t)sl->sll_addr[0],
            (uint8_t)sl->sll_addr[1],
            (uint8_t)sl->sll_addr[2],
            (uint8_t)sl->sll_addr[3],
            (uint8_t)sl->sll_addr[4],
            (uint8_t)sl->sll_addr[5]);
        *pmc++ = 0;
    }

    freeifaddrs(ifaddr);
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>

    char buf[8192] = {0};
  struct ifconf ifc = {0};
  int i = 0, c = 0;
  char* pmc = macs;
  int sck = socket(PF_INET, SOCK_DGRAM, 0);

  if(sck < 0) {
    perror("socket");
    return 1;
  }

  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  if(ioctl(sck, SIOCGIFCONF, &ifc) < 0) {
    close(sck);
    return 0;
  }

  *pmc = 0;

  for(i = 0; i < ifc.ifc_len / sizeof(struct ifreq); i++) {
    struct ifreq *item = &ifc.ifc_req[i];

    if(ioctl(sck, SIOCGIFHWADDR, item) < 0) {
        continue;
    }
    
    c ++;

    pmc += snprintf(pmc, len - (pmc - macs), item->ifr_name);
    *pmc++ = 0;

    pmc += snprintf(pmc, len - (pmc - macs), "%02x:%02x:%02x:%02x:%02x:%02x",
        (unsigned char)item->ifr_hwaddr.sa_data[0],
        (unsigned char)item->ifr_hwaddr.sa_data[1],
        (unsigned char)item->ifr_hwaddr.sa_data[2],
        (unsigned char)item->ifr_hwaddr.sa_data[3],
        (unsigned char)item->ifr_hwaddr.sa_data[4],
        (unsigned char)item->ifr_hwaddr.sa_data[5]);
    *pmc++ = 0;
  }
#endif
  return c;
}

uint32_t get_sorted_macs(char* mac_buffer, uint32_t size, uint32_t (*f_mac_filter)(const char* name, const char* mac, uint32_t argc, void*  argv), uint32_t argc, void*  argv) {
    char tmp_buf[1024] = {0};
    char *p = tmp_buf;

    uint32_t i = 0, c = 0;

    char* mac_enties[100] = {0};
    char** l_enties = mac_enties;

    c = get_all_macs(tmp_buf, sizeof(tmp_buf)/sizeof(tmp_buf[0]));

    // set
    for(i = 0; i < c; i ++) {
        char* pname = p;
        char* pmac = p + strlen(p) + 1;

        if (!f_mac_filter || f_mac_filter(pname, pmac, argc, argv)) {
            *l_enties++ = pmac;
        }

        p = p + strlen(pname) + strlen(pmac) + 2;
    }

    // sort
    for(i = 0; i < l_enties - mac_enties; i ++) {
        uint32_t j = i + 1;
        for(; j < l_enties - mac_enties; j ++) {
            if (strcmp(mac_enties[i], mac_enties[j]) > 0) {
                void * p = mac_enties[j];
                mac_enties[j] = mac_enties[i];
                mac_enties[i] = p;
            }
        }
    }

    // ret
    p = mac_buffer;
    for(i = 0; i < l_enties - mac_enties; i ++) {
        strcpy(p, mac_enties[i]);
        p += strlen(p) + 1;
    }

    return l_enties - mac_enties;
}