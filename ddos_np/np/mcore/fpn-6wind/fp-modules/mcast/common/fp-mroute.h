/*
 * Copyright(c) 2009 6WIND, All rights reserved.
 */

#ifndef __FP_MROUTE_H__
#define __FP_MROUTE_H__

#define FP_MAXVIFS         32

typedef struct fp_mfc_entry {
	uint32_t        mcastgrp;          /* Group the entry belongs to */
	uint32_t        origin;            /* Source of packet */

#define FP_IIF_UNUSED   0
	uint32_t        iif;               /* Source interface */
#define FP_NEXT_UNUSED  0xFFFF
	uint16_t        next;              /* Next entry on cache line */
	uint16_t        hole;

	uint32_t        oifs[FP_MAXVIFS];  /* Output interfaces */

	uint64_t        pkt;
	uint64_t        bytes;
} fp_mfc_entry_t;

/* Order of the hashtable of MFC (Multicast Forwarding Cache
 * entries). The maximum number of buckets in the hashtable is 2 ^
 * order. */
#ifdef CONFIG_MCORE_MULTICAST4_MFC_LINE_ORDER
#define FP_MFC_LINE_ORDER CONFIG_MCORE_MULTICAST4_MFC_LINE_ORDER
#else
#define FP_MFC_LINE_ORDER          6
#endif

#define FP_MFC_LINE (1<<FP_MFC_LINE_ORDER)

/* Maximum number of MFC (Multicast Forwarding Cache entries). These
 * entries are stored in a hashtable, whose size is defined by
 * CONFIG_MCORE_MULTICAST4_MFC_LINE_ORDER */
#ifdef CONFIG_MCORE_MULTICAST4_MFC_MAX
#define FP_MFC_MAX CONFIG_MCORE_MULTICAST4_MFC_MAX
#else
#define FP_MFC_MAX           256                      /* FP_MFC_MAX < 65536 */
#endif

#define FP_MFC_INVALID       FP_MFC_MAX + 1
#define FP_MFC_COLLISION     FP_MFC_MAX - FP_MFC_LINE

#ifdef FPN_BIG_ENDIAN
#define FP_MFC_HASH(a,b)     ((((a)>>24)^((b)>>26))&(FP_MFC_LINE-1))
#else
#define FP_MFC_HASH(a,b)     (((a)^((b)>>2))&(FP_MFC_LINE-1))
#endif

#ifdef CONFIG_MCORE_MULTICAST4_GRP_MAX
#define FP_MCASTGRP_MAX      CONFIG_MCORE_MULTICAST4_GRP_MAX
#else
#define FP_MCASTGRP_MAX      20
#endif

typedef struct fp_mcastgrp {
     uint32_t        group;             /* Group the entry belongs to */
#define FP_MCASTGRP_IFUID_ALL   0
     uint32_t        ifuid;             /* Source interface */
} fp_mcastgrp_t;

#ifdef CONFIG_MCORE_IPV6
typedef struct fp_mfc6_entry {
	fp_in6_addr_t        mcastgrp;          /* Group the entry belongs to */
	fp_in6_addr_t        origin;            /* Source of packet */

	uint32_t             iif;               /* Source interface */
	uint16_t             next;              /* Next entry on cache line */
	uint16_t             hole;

	uint32_t             oifs[FP_MAXVIFS];  /* Output interfaces */

	uint64_t             pkt;
	uint64_t             bytes;
} fp_mfc6_entry_t;


/* Order of the hashtable of MFC (Multicast Forwarding Cache
 * entries). The maximum number of buckets in the hashtable is 2 ^
 * order. */
#ifdef CONFIG_MCORE_MULTICAST6_MFC_LINE_ORDER
#define FP_MFC6_LINE_ORDER CONFIG_MCORE_MULTICAST6_MFC_LINE_ORDER
#else
#define FP_MFC6_LINE_ORDER          6
#endif

#define FP_MFC6_LINE (1<<FP_MFC_LINE_ORDER)

/* Maximum number of MFC (Multicast Forwarding Cache entries). These
 * entries are stored in a hashtable, whose size is defined by
 * CONFIG_MCORE_MULTICAST6_MFC_LINE_ORDER */
#ifdef CONFIG_MCORE_MULTICAST6_MFC_MAX
#define FP_MFC6_MAX CONFIG_MCORE_MULTICAST6_MFC_MAX
#else
#define FP_MFC6_MAX           256                      /* FP_MFC_MAX < 65536 */
#endif

#define FP_MFC6_INVALID       FP_MFC6_MAX + 1
#define FP_MFC6_COLLISION     FP_MFC6_MAX - FP_MFC6_LINE
#define FP_MFC6HASHMOD(h)     ((h) & (FP_MFC6_LINE -1))
#define FP_MFC6_HASH(a, g)    FP_MFC6HASHMOD((a).fp_s6_addr32[0] ^ (a).fp_s6_addr32[1] ^ \
				(a).fp_s6_addr32[2] ^ (a).fp_s6_addr32[3] ^ \
				(g).fp_s6_addr32[0] ^ (g).fp_s6_addr32[1] ^ \
				(g).fp_s6_addr32[2] ^ (g).fp_s6_addr32[3])

#ifdef CONFIG_MCORE_MULTICAST6_GRP_MAX
#define FP_MCAST6GRP_MAX      CONFIG_MCORE_MULTICAST6_GRP_MAX
#else
#define FP_MCAST6GRP_MAX      20
#endif

typedef struct fp_mcast6grp {
     fp_in6_addr_t   group;             /* Group the entry belongs to */
     uint32_t        ifuid;             /* Source interface */
} fp_mcast6grp_t;

#endif /* CONFIG_MCORE_IPV6 */
#endif /* __FP_MROUTE_H__ */
