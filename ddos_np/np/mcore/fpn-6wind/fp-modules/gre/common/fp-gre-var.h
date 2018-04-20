/*
 * Copyright 2014 6WIND S.A.
 */

#ifndef __FP_GRE_VAR_H__
#define __FP_GRE_VAR_H__

/* GRE magic number */
#define FP_GRE_MAGIC32 19710703

/* Maximum number of GRE interfaces */
#ifdef CONFIG_MCORE_GRE_MAX
#define FP_GRE_MAX (CONFIG_MCORE_GRE_MAX + 1)
#else
#define FP_GRE_MAX  256
#endif

#ifdef CONFIG_MCORE_GRE_IPV4_HASH_ORDER
#define FP_GRE_IPV4_HASH_ORDER (CONFIG_MCORE_GRE_IPV4_HASH_ORDER)
#else
#define FP_GRE_IPV4_HASH_ORDER 4
#endif

#define FP_GRE_IPV4_HASH_SIZE  (1 << FP_GRE_IPV4_HASH_ORDER)
#define FP_GRE_IPV4_HASH_MASK  (FP_GRE_IPV4_HASH_SIZE - 1)

#ifdef CONFIG_MCORE_IPV6
#ifdef CONFIG_MCORE_GRE_IPV6_HASH_ORDER
#define FP_GRE_IPV6_HASH_ORDER (CONFIG_MCORE_GRE_IPV6_HASH_ORDER)
#else
#define FP_GRE_IPV6_HASH_ORDER 4
#endif

#define FP_GRE_IPV6_HASH_SIZE  (1 << FP_GRE_IPV6_HASH_ORDER)
#define FP_GRE_IPV6_HASH_MASK  (FP_GRE_IPV6_HASH_SIZE - 1)
#endif

typedef int (*fp_gretap_fpvs_input_t) (struct mbuf *m, uint8_t size,
				       uint32_t ovsport, uint16_t flags,
				       uint32_t key);

typedef struct {
	uint32_t	ifuid;
	uint32_t	next_idx;

	fp_hlist_node_t	hlist;

	uint32_t	ikey;
	uint32_t	okey;

	union {
		struct fp_in_addr	local4;
#ifdef CONFIG_MCORE_IPV6
		struct fp_in6_addr	local6;
#endif
	} local;
	union {
		struct fp_in_addr	remote4;
#ifdef CONFIG_MCORE_IPV6
		struct fp_in6_addr	remote6;
#endif
	} remote;

	uint32_t	link_ifuid;
	uint16_t	link_vrfid;
#define FP_GRE_FLAG_CSUM        0x01
#define FP_GRE_FLAG_KEY         0x02
	uint16_t	iflags;

	uint16_t	oflags;
	uint8_t		ttl;
	uint8_t		tos;
	uint8_t		inh_tos;
	uint8_t		family;
#define FP_GRE_MODE_UNKNOWN	0
#define FP_GRE_MODE_IP		1   /* IPv4 0x0800 or IPv6 0x86DD           */
#define FP_GRE_MODE_ETHER	2   /* Transparent Ethernet Bridging 0x6558 */
	uint8_t		mode;
} fp_ifgre_t;

typedef struct {
	fp_hlist_head_t	gre_ipv4_hlist[FP_GRE_IPV4_HASH_SIZE];
#ifdef CONFIG_MCORE_IPV6
	fp_hlist_head_t	gre_ipv6_hlist[FP_GRE_IPV6_HASH_SIZE];
#endif
	fp_ifgre_t	if_gre[FP_GRE_MAX];
	uint32_t	if_gre_freecell;
	uint32_t	ovsport;
	fp_gretap_fpvs_input_t  gretap_fpvs_input;

	uint32_t	magic;
	/* Keep in last place, preserved on shared mem initialization */
	uint16_t	mod_uid;
} fp_gre_shared_mem_t;

#define FP_GRE_SHARED "fp-share-gre"

FPN_DECLARE_SHARED(fp_gre_shared_mem_t *, fp_gre_shared);

#define __FP_GRE_HASH_KEY(key) fp_jhash_1word(key)

#define __FP_GRE_HASH_ADDR4(addr) fp_jhash_1word(addr)

#define FP_GRE_HASH_IPV4_KEY(key_h) ((key_h) & FP_GRE_IPV4_HASH_MASK)

#define FP_GRE_HASH_IPV4_1AK(addr_h, key_h)		\
	(((addr_h) ^ (key_h)) & FP_GRE_IPV4_HASH_MASK)

#define FP_GRE_HASH_IPV4(local_h, remote_h, key_h)			\
	(((local_h) ^ (remote_h) ^ (key_h)) & FP_GRE_IPV4_HASH_MASK)

#ifdef CONFIG_MCORE_IPV6
#define __FP_GRE_HASH_ADDR6(addr)			\
	(fp_jhash_1word((addr).fp_s6_addr32[0] ^	\
			(addr).fp_s6_addr32[1] ^	\
			(addr).fp_s6_addr32[2] ^	\
			(addr).fp_s6_addr32[3]))

#define FP_GRE_HASH_IPV6_KEY(key_h) ((key_h) & FP_GRE_IPV6_HASH_MASK)

#define FP_GRE_HASH_IPV6_1AK(addr_h,key_h)		\
	(((addr_h) ^ (key_h)) & FP_GRE_IPV6_HASH_MASK)

#define FP_GRE_HASH_IPV6(local_h, remote_h, key_h)			\
	(((local_h) ^ (remote_h) ^ (key_h)) & FP_GRE_IPV6_HASH_MASK)
#endif

int fp_addifnet_greinfo(uint32_t ifuid, uint32_t link_ifuid, uint16_t iflags,
			uint16_t oflags, uint8_t mode, uint32_t ikey,
			uint32_t okey, uint8_t ttl,
			uint8_t tos, uint8_t inh_tos, uint8_t ip_family,
			void *local_addr, void *remote_addr, uint16_t link_vrfid);
int fp_upifnet_greinfo(uint32_t ifuid, uint32_t link_ifuid, uint16_t iflags,
		       uint16_t oflags, uint8_t mode, uint32_t ikey,
		       uint32_t okey, uint8_t ttl,
		       uint8_t tos, uint8_t inh_tos, uint8_t ip_family,
		       void *local_addr, void *remote_addr, uint16_t link_vrfid);
int fp_delifnet_greinfo(uint32_t ifuid);
int fp_delifnet_gretapinfo(uint32_t ifuid);

void fp_gre_init_shmem(int graceful);
void fp_gretap_fpvs_create(uint32_t ovsport);
void fp_gretap_fpvs_delete(void);
int fp_gretap_fpvs_output(struct mbuf *m, uint32_t ip_src, uint32_t ip_dst,
			  uint8_t ttl, uint8_t tos, uint32_t key,
			  uint16_t flags);
void fp_gretap_fpvs_input_register(fp_gretap_fpvs_input_t input_p);

#endif
