/*
 * Copyright(c) 2007 6WIND
 */
#ifndef _FILTER_H_
#define _FILTER_H_

#define ADRLEN          32
#define SRCADRLEN       ADRLEN/8

#define MAX_STRIDE		8

#ifdef CONFIG_MCORE_IPV6
#include "netinet/fp-in6.h"
#endif
struct FILTER {
	uint32_t filtId;
	uint32_t cost;           /* host order */

#ifdef CONFIG_MCORE_IPV6
	union {
		uint32_t 	dst;       /* network order */
		fp_in6_addr_t	dst6;      /* network order */
	};
	union {
		uint32_t	dst_mask;  /* network order */
		fp_in6_addr_t	dst6_mask; /* network order */
	};
	union {
		uint32_t	src;       /* network order */
		fp_in6_addr_t	src6;      /* network order */
	};
	union {
		uint32_t	src_mask;  /* network order */
		fp_in6_addr_t	src6_mask; /* network order */
	};
#else
	uint32_t dst;            /* network order */
	uint32_t dst_mask;       /* network order */

	uint32_t src;            /* network order */
	uint32_t src_mask;       /* network order */
#endif /* CONFIG_MCORE_IPV6 */

	uint8_t  dst_plen;
	uint8_t  src_plen;
	uint8_t  ul_proto;
#define FILTER_ULPROTO_ANY    255
	uint8_t  action;

	uint16_t vrfid;          /* host order */

	uint16_t srcport;        /* network order */
	uint16_t srcport_mask;   /* network order */
	uint16_t dstport;        /* network order */
	uint16_t dstport_mask;   /* network order */
};

#endif
