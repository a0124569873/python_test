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

/*
 * Copyright 2010-2013 6WIND S.A.
 */

#ifndef __NETINET_VNB_IP6_H__
#define __NETINET_VNB_IP6_H__

#define IP6VERSION   6

struct vnb_ip6_hdr
{
	union
	{
		struct
		{
			uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
						    20 bits flow-ID */
			uint16_t ip6_un1_plen;   /* payload length */
			uint8_t  ip6_un1_nxt;    /* next header */
			uint8_t  ip6_un1_hlim;   /* hop limit */
		} __attribute__((__packed__)) ip6_un1;

		uint8_t ip6_un2_vfc;
		struct {
#if VNB_BYTE_ORDER == VNB_LITTLE_ENDIAN
		uint8_t ip6_un2_tclass1:4,	/* 4 bits version, top 4 bits tclass */
			ip6_un2_v:4;
#endif
#if VNB_BYTE_ORDER == VNB_BIG_ENDIAN
		uint8_t ip6_un2_v:4,		/* 4 bits version, top 4 bits tclass */
			ip6_un2_tclass1:4;
#endif
		} __attribute__((__packed__)) ip6_s;
	} __attribute__((__packed__)) ip6_ctlun;

	struct vnb_in6_addr ip6_src;      /* source address */
	struct vnb_in6_addr ip6_dst;      /* destination address */
} __attribute__((__packed__));

#define ip6_v		ip6_ctlun.ip6_s.ip6_un2_v
#define ip6_tclass	ip6_ctlun.ip6_s.ip6_un2_tclass1
#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim

/* IPv6 extension header */
struct vnb_ip6_ext
{
	uint8_t  ip6e_nxt;
	uint8_t  ip6e_len;
} __attribute__((__packed__));

#define vnb_ipv6_optlen(p)  (((p)->ip6e_len+1) << 3)

struct vnb_ip6_frag {
	uint8_t ip6f_nxt;
	uint8_t ip6f_reserved;
	uint16_t ip6f_offlg;
	uint32_t ip6f_ident;
} __attribute__((__packed__));

#if     VNB_BYTE_ORDER == VNB_BIG_ENDIAN
#define VNB_IP6F_OFF_MASK       0xfff8  /* mask out offset from _offlg */
#define VNB_IP6F_RESERVED_MASK  0x0006  /* reserved bits in ip6f_offlg */
#define VNB_IP6F_MORE_FRAG      0x0001  /* more-fragments flag */
#elif   VNB_BYTE_ORDER == VNB_LITTLE_ENDIAN
#define VNB_IP6F_OFF_MASK       0xf8ff  /* mask out offset from _offlg */
#define VNB_IP6F_RESERVED_MASK  0x0600  /* reserved bits in ip6f_offlg */
#define VNB_IP6F_MORE_FRAG      0x0100  /* more-fragments flag */
#endif

#define VNB_NEXTHDR_HOP		0	/* Hop-by-hop option header. */
#define VNB_NEXTHDR_TCP		6	/* TCP segment. */
#define VNB_NEXTHDR_UDP		17	/* UDP message. */
#define VNB_NEXTHDR_IPV6	41	/* IPv6 in IPv6 */
#define VNB_NEXTHDR_ROUTING	43	/* Routing header. */
#define VNB_NEXTHDR_FRAGMENT	44	/* Fragmentation/reassembly header. */
#define VNB_NEXTHDR_ESP		50	/* Encapsulating security payload. */
#define VNB_NEXTHDR_AUTH	51	/* Authentication header. */
#define VNB_NEXTHDR_ICMP	58	/* ICMP for IPv6. */
#define VNB_NEXTHDR_NONE	59	/* No next header */
#define VNB_NEXTHDR_DEST	60	/* Destination options header. */
#define VNB_NEXTHDR_MOBILITY	135	/* Mobility header. */
#define VNB_NEXTHDR_MAX		255

/*
 * find out if nexthdr is a well-known extension header or a protocol
 */
static inline int vnb_ipv6_ext_hdr(uint8_t nexthdr)
{
	/*
	 * find out if nexthdr is an extension header or a protocol
	 */
	return ( (nexthdr == VNB_NEXTHDR_HOP)	||
		 (nexthdr == VNB_NEXTHDR_ROUTING)	||
		 (nexthdr == VNB_NEXTHDR_FRAGMENT)	||
		 (nexthdr == VNB_NEXTHDR_AUTH)	||
		 (nexthdr == VNB_NEXTHDR_NONE)	||
		 (nexthdr == VNB_NEXTHDR_DEST) );
}
#endif /* __NETINET_VNB_IP6_H__ */
