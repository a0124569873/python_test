#ifndef __GENERAL_FUNCTION_H__
#define __GENERAL_FUNCTION_H__

#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <fpn-mbuf.h>

#include "netinet/fp-ip.h"
#include "netinet/fp-udp.h"
#include "netinet/fp-tcp.h"
#include "net/fp-ethernet.h"
#include "rte_cycles.h"
#include "rte_random.h"

#include "black_white.h"
#include "flow_define.h"
#include "ddos_hash_table.h"
#include "server_node_define.h"
#include "ip_mac.h"

#define CURRENT_TIME() ({ \
	struct timeval cur_t; \
	gettimeofday(&cur_t, NULL); \
      cur_t.tv_sec * 1000 + cur_t.tv_usec / 1000; \
})

#define REVERSE_ETH(eth) do { \
	uint8_t tmp[6]; \
	fpn_memcpy(tmp, eth->ether_shost, 6); \
	fpn_memcpy(eth->ether_shost, eth->ether_dhost, 6); \
	fpn_memcpy(eth->ether_dhost, tmp, 6); \
} while(0)

#define REVERSE_IP(ip) { \
	uint32_t tmp; \
	tmp = ip->ip_src.s_addr; \
	ip->ip_src.s_addr = ip->ip_dst.s_addr; \
	ip->ip_dst.s_addr = tmp; \
}

#define REVERSE_UDP_PORT(uh) { \
	uint16_t tmp; \
	tmp = uh->uh_sport; \
	uh->uh_sport = uh->uh_dport; \
	uh->uh_dport = tmp; \
}

#define REVERSE_TCP_PORT(ip) { \
	uint16_t tmp; \
	tmp = th->th_sport; \
	th->th_sport = th->th_dport; \
	th->th_dport = tmp; \
}

#define IP_2_STR(ip, ipstr, size) ({ \
	uint8_t* t = (uint8_t*)&ip; \
	int32_t result = 0; \
	result = snprintf(ipstr, size, "%u.%u.%u.%u", t[0], t[1], t[2], t[3]); \
	result > 0 && result < (int32_t)size; \
})

#define ETHER_EQUAL_NF(mac1, mac2) ({ \
    const uint16_t *a = (const uint16_t *) mac1; \
    const uint16_t *b = (const uint16_t *) mac2; \
    !((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])); \
})

#define IS_BCAST_NF(mac) ({ \
	const uint16_t *a = (const uint16_t *) mac; \
	!((a[0] ^ 0xffff) | (a[1] ^ 0xffff) | (a[2] ^ 0xffff)); \
})

#define IS_VRRP_NF(mac) ({ \
    const uint16_t *a = (const uint16_t *) mac; \
    !((a[0] ^ 0x0000) | (a[1] ^ htons(0x5e00))); \
})

#define IS_MCAST_NF(mac) ({ \
    const uint16_t *a = (const uint16_t *) mac; \
    !((a[0] ^ 0x0100) | (a[1] ^ htons(0x5e00))); \
})

#define CHECK_L3_PACKET(m, ip, sport, dport, proto) ({ \
	int ok = 1; \
	proto = ip->ip_p; \
	do { \
		if (proto == FP_IPPROTO_TCP) { \
			struct fp_tcphdr *th = m_off(m, ip->ip_hl * 4, struct fp_tcphdr *); \
			if (th == NULL || m_len(m) < (unsigned int)(ip->ip_hl * 4 + th->th_off * 4)) { \
				ok = 0; \
				break; \
			} \
			sport = th->th_sport; \
			dport = th->th_dport; \
		} else if (proto == FP_IPPROTO_UDP) { \
			struct fp_udphdr *uh = m_off(m, ip->ip_hl * 4, struct fp_udphdr *); \
			if (uh == NULL || m_len(m) < (unsigned int)(ip->ip_hl * 4 + sizeof(struct fp_udphdr))) { \
				ok = 0; \
				break; \
			} \
			sport = uh->uh_sport; \
			dport = uh->uh_dport; \
		} \
	} while(0); \
	ok; \
})

#endif  /*__GENERAL_FUNCTION_H__*/