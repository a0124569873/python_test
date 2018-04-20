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
 *	@(#)tcp.h	8.1 (Berkeley) 6/10/93
 * $FreeBSD$
 */

/*
 * Copyright 2010-2013 6WIND S.A.
 */

#ifndef __NETINET_VNB_TCP_H__
#define __NETINET_VNB_TCP_H__

struct vnb_tcphdr {
	uint16_t	th_sport;		/* source port */
	uint16_t	th_dport;		/* destination port */
	uint32_t	th_seq;			/* sequence number */
	uint32_t	th_ack;			/* acknowledgement number */
#if VNB_BYTE_ORDER == VNB_LITTLE_ENDIAN
	uint8_t		th_x2:4,		/* (unused) */
			th_off:4;		/* data offset */
#elif VNB_BYTE_ORDER == VNB_BIG_ENDIAN
	uint8_t		th_off:4,		/* data offset */
			th_x2:4;		/* (unused) */
#else
#error "No endianness defined"
#endif
	uint8_t		th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
#define	TH_ECE	0x40
#define	TH_CWR	0x80
#define	TH_FLAGS	(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

	uint16_t	th_win;			/* window */
	uint16_t	th_sum;			/* checksum */
	uint16_t	th_urp;			/* urgent pointer */
} __attribute__ ((packed));

/*
 *      TCP option
 */

#define VNB_TCPOPT_NOP              1       /* Padding */
#define VNB_TCPOPT_EOL              0       /* End of options */
#define VNB_TCPOPT_MSS              2       /* Segment size negotiating */
#define VNB_TCPOPT_WINDOW           3       /* Window scaling */
#define VNB_TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define VNB_TCPOPT_SACK             5       /* SACK Block */
#define VNB_TCPOPT_TIMESTAMP        8       /* Better RTT estimations/PAWS */
#define VNB_TCPOPT_RFC2385          19      /* MD5 protection */

/*
 *     TCP option lengths
 */

#define VNB_TCPOLEN_MSS            4
#define VNB_TCPOLEN_WINDOW         3
#define VNB_TCPOLEN_SACK_PERM      2
#define VNB_TCPOLEN_TIMESTAMP      10
#define VNB_TCPOLEN_RFC2385        18

#define VNB_TCPOLEN_TSTAMP_ALIGNED          12
#define VNB_TCPOLEN_WSCALE_ALIGNED          4
#define VNB_TCPOLEN_SACKPERM_ALIGNED        4
#define VNB_TCPOLEN_SACK_BASE               2
#define VNB_TCPOLEN_SACK_BASE_ALIGNED       4
#define VNB_TCPOLEN_SACK_PERBLOCK           8
#define VNB_TCPOLEN_RFC2385_ALIGNED         20

#endif /* __NETINET_VNB_TCP_H__ */
