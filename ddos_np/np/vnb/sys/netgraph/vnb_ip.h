/*-
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.
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
 *	@(#)ip.h	8.2 (Berkeley) 6/1/94
 * $FreeBSD$
 */

/*
 * Copyright 2010-2013 6WIND S.A.
 */

#ifndef _NETINET_VNB_IP_H_
#define _NETINET_VNB_IP_H_
/*
 * Definitions for internet protocol version 4.
 * Per RFC 791, September 1981.
 */
#define	VNB_IPVERSION	4

/*
 * Structure of an internet header, naked of options.
 */
struct vnb_ip {
#if VNB_BYTE_ORDER == VNB_LITTLE_ENDIAN
	u_int	ip_hl:4,		/* header length */
	ip_v:4;				/* version */
#endif
#if VNB_BYTE_ORDER == VNB_BIG_ENDIAN
	u_int	ip_v:4,			/* version */
	ip_hl:4;			/* header length */
#endif
	u_char	ip_tos;			/* type of service */
	u_short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	u_short	ip_off;			/* fragment offset field */
#define	VNB_IP_RF 0x8000		/* reserved fragment flag */
#define	VNB_IP_DF 0x4000		/* dont fragment flag */
#define	VNB_IP_MF 0x2000		/* more fragments flag */
#define	VNB_IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	vnb_in_addr ip_src, ip_dst;	/* source and dest address */
} __attribute__ ((packed));

#define	VNB_IP_MAXPACKET	65535	/* maximum packet size */

/*
 * Internet implementation parameters.
 */
#define	VNB_MAXTTL	255		/* maximum time to live (seconds) */
#define	VNB_IPDEFTTL	64		/* default ttl, from RFC 1340 */
#define	VNB_IPFRAGTTL	60		/* time to live for frags, slowhz */
#define	VNB_IPTTLDEC	1		/* subtracted when forwarding */

#define	VNB_IP_MSS	576		/* default maximum segment size */

#endif
