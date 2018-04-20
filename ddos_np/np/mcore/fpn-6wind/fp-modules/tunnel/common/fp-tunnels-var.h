/*
 * Copyright (c) 2008 6WIND, All rights reserved.
 */

#ifndef __FP_TUNNELS_VAR_H__
#define __FP_TUNNELS_VAR_H__

#include <netinet/fp-ip.h>
#include <netinet/fp-ip6.h>
#include <fp-jhash.h>

#define FP_MAX_TUNNELS             FP_MAX_IFNET

#ifdef CONFIG_MCORE_XIN4_HASH_ORDER
#define FP_XIN4_HASH_ORDER CONFIG_MCORE_XIN4_HASH_ORDER
#else
#define FP_XIN4_HASH_ORDER          4
#endif

#define FP_XIN4_HASH_SIZE          (1<<FP_XIN4_HASH_ORDER)
#define FP_XIN4_HASH_MASK          (FP_XIN4_HASH_SIZE-1)

#define FP_XIN4_HASH(src, dst)     ((fp_jhash_1word(src) ^ \
					fp_jhash_1word(dst)) & \
					FP_XIN4_HASH_MASK)

#ifdef CONFIG_MCORE_XIN6_HASH_ORDER
#define FP_XIN6_HASH_ORDER CONFIG_MCORE_XIN6_HASH_ORDER
#else
#define FP_XIN6_HASH_ORDER          5
#endif

#define FP_XIN6_HASH_SIZE          (1<<FP_XIN6_HASH_ORDER)
#define FP_XIN6_HASH_MASK          (FP_XIN6_HASH_SIZE-1)

#define FP_XIN6_HASH_(addr)        ((addr)->fp_s6_addr32[0] ^ \
					(addr)->fp_s6_addr32[1] ^ \
					(addr)->fp_s6_addr32[2] ^ \
					(addr)->fp_s6_addr32[3])
#define FP_XIN6_HASH(src, dst)     ((fp_jhash_1word(FP_XIN6_HASH_(src)) ^ \
					fp_jhash_1word(FP_XIN6_HASH_(dst))) & \
					FP_XIN6_HASH_MASK)


typedef struct fp_tunnel_entry {
	union {
		struct fp_ip xin4;
#ifdef CONFIG_MCORE_IPV6
		struct fp_ip6_hdr xin6;
#endif
	}          p;
	uint32_t   hash_prev;
	uint32_t   hash_next;
	uint32_t   ifuid;
	uint16_t   linkvrfid;
	uint8_t    proto;
} fp_tunnel_entry_t;

typedef struct fp_tunnel_table {
	uint32_t          hash_xin4[FP_XIN4_HASH_SIZE];
#ifdef CONFIG_MCORE_IPV6
	uint32_t          hash_xin6[FP_XIN6_HASH_SIZE];
#endif
	fp_tunnel_entry_t table[FP_MAX_TUNNELS];
} fp_tunnel_table_t;

void fp_tunnel_link(uint32_t ifuid);
void fp_tunnel_unlink(uint32_t ifuid);

int fp_delifnet_xinyinfo(uint32_t ifuid);
int fp_addifnet_xin4info(uint32_t ifuid, uint8_t hoplim, uint8_t tos,
			 uint8_t inh_tos, uint16_t vrfid, uint16_t linkvrfid,
			 struct fp_in_addr *local, struct fp_in_addr *remote);
#ifdef CONFIG_MCORE_XIN6
int fp_addifnet_xin6info(uint32_t ifuid, uint8_t hoplim, uint8_t tos,
			 uint8_t inh_tos, uint16_t vrfid, uint16_t linkvrfid,
			 fp_in6_addr_t *local, fp_in6_addr_t *remote);
#endif


#ifdef CONFIG_MCORE_VRF
#define tun2linkvrfid(t) (t)->linkvrfid
#else
#define tun2linkvrfid(t) 0
#endif

#endif /* __FP_TUNNELS_VAR_H__ */
