/*
 * Copyright 2013 6WIND S.A.
 */

/*-
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*-
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ip.h	8.1 (Berkeley) 6/10/93
 */

#ifndef __FPN_IP6_H__
#define __FPN_IP6_H__

#include "fpn-in6.h"

/*
 * In order to avoid conflicts when netinet/ip6.h (system header) or any other
 * header that defines ip6_hdr and its fields macros are included, we can't
 * redefine them. Thus, struct fpn_ip6_hdr fields are declared twice (named and
 * unnamed) in a union to ensure that they can be accessed whether these macros
 * are already defined or not.
 */

#define FPN_IP6VERSION   6

struct fpn_ip6_hdr {
	__extension__ union {
#ifndef ip6_flow
#if defined(ip6_v) || defined(ip6_tclass) || \
	defined(ip6_vfc) || defined(ip6_plen) || \
	defined(ip6_nxt) || defined(ip6_hlim) || \
	defined(ip6_hops)
#error Either all or none of the struct ip6_hdr fields macros must be defined.
#endif
		/*
		 * Unnamed members are only declared when fields macros aren't
		 * already defined to avoid compilation failures.
		 * When these macros are defined, these fields cannot be used
		 * anyway.
		 */
		union {
			struct {
				uint32_t ip6_flow; /* 4 bits version,
						    * 8 bits TC,
						    * 20 bits flow-ID */
				uint16_t ip6_plen; /* payload length */
				uint8_t ip6_nxt; /* next header */
				uint8_t ip6_hlim; /* hop limit */
			} __attribute__((packed));
			uint8_t ip6_vfc;
			struct {
#if FPN_BYTE_ORDER == FPN_LITTLE_ENDIAN
				uint8_t ip6_tclass:4; /* 4 bits tclass */
				uint8_t ip6_v:4; /* 4 bits version */
#elif FPN_BYTE_ORDER == FPN_BIG_ENDIAN
				uint8_t ip6_v:4; /* 4 bits version */
				uint8_t ip6_tclass:4; /* 4 bits tclass */
#else /* FPN_BYTE_ORDER */
#error Unknown byte ordering.
#endif /* FPN_BYTE_ORDER */
			} __attribute__((packed));
		} __attribute__((packed));
#endif /* ip6_flow */
		/*
		 * Named members are used when macros are defined. They must
		 * exactly match without exception the above definitions.
		 * Note that struct fpn_ip6_hdrctl is also declared here.
		 */
		union {
			struct fpn_ip6_hdrctl {
				uint32_t ip6_un1_flow;
				uint16_t ip6_un1_plen;
				uint8_t ip6_un1_nxt;
				uint8_t ip6_un1_hlim;
			} __attribute__((packed)) ip6_un1;
			uint8_t ip6_un2_vfc;
			struct {
#if FPN_BYTE_ORDER == FPN_LITTLE_ENDIAN
				uint8_t ip6_un2_tclass1:4;
				uint8_t ip6_un2_v:4;
#elif FPN_BYTE_ORDER == FPN_BIG_ENDIAN
				uint8_t ip6_un2_v:4;
				uint8_t ip6_un2_tclass1:4;
#else /* FPN_BYTE_ORDER */
#error Unknown byte ordering.
#endif /* FPN_BYTE_ORDER */
			} __attribute__((packed)) ip6_s;
		} __attribute__((packed)) ip6_ctlun;
	} __attribute__((packed));
	struct fpn_in6_addr ip6_src;
	struct fpn_in6_addr ip6_dst;
} __attribute__((packed));

/* IPv6 extension header */
struct fpn_ip6_ext
{
	uint8_t  ip6e_nxt;
	uint8_t  ip6e_len;
} __attribute__((__packed__));

#define fpn_ipv6_optlen(p)  (((p)->ip6e_len+1) << 3)

struct fpn_ip6_frag {
	uint8_t ip6f_nxt;
	uint8_t ip6f_reserved;
	uint16_t ip6f_offlg;
	uint32_t ip6f_ident;
} __attribute__((__packed__));

#if     FPN_BYTE_ORDER == FPN_BIG_ENDIAN
#define FPN_IP6F_OFF_MASK       0xfff8  /* mask out offset from _offlg */
#define FPN_IP6F_RESERVED_MASK  0x0006  /* reserved bits in ip6f_offlg */
#define FPN_IP6F_MORE_FRAG      0x0001  /* more-fragments flag */
#elif   FPN_BYTE_ORDER == FPN_LITTLE_ENDIAN
#define FPN_IP6F_OFF_MASK       0xf8ff  /* mask out offset from _offlg */
#define FPN_IP6F_RESERVED_MASK  0x0600  /* reserved bits in ip6f_offlg */
#define FPN_IP6F_MORE_FRAG      0x0100  /* more-fragments flag */
#endif

/* Check for an extension */
static inline int ip6_ext_hdr(uint8_t nexthdr)
{
	return (nexthdr == FPN_IPPROTO_HOPOPTS  ||
		nexthdr == FPN_IPPROTO_ROUTING  ||
		nexthdr == FPN_IPPROTO_FRAGMENT ||
		nexthdr == FPN_IPPROTO_ESP      ||
		nexthdr == FPN_IPPROTO_AH       ||
		nexthdr == FPN_IPPROTO_NONE     ||
		nexthdr == FPN_IPPROTO_DSTOPTS);
}

#endif
