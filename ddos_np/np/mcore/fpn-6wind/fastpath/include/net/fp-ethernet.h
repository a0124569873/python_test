/*
 * Copyright (C) 2010 6WIND, All rights reserved.
 */

/*
 * Copyright (c) 1992-2010 The FreeBSD Project. All rights reserved.
 * Copyright (c) 1982, 1986, 1990, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
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
 */

#ifndef __NET_FP_ETHERNET_H__
#define __NET_FP_ETHERNET_H__

/*
 * The number of bytes in an ethernet (MAC) address.
 */
#define	FP_ETHER_ADDR_LEN		6

/*
 * The number of bytes in the type field.
 */
#define	FP_ETHER_TYPE_LEN		2

/*
 * The number of bytes in the trailing CRC field.
 */
#define	FP_ETHER_CRC_LEN		4

/*
 * The length of the combined header.
 */
#define	FP_ETHER_HDR_LEN		(FP_ETHER_ADDR_LEN*2+FP_ETHER_TYPE_LEN)

/*
 * The minimum packet length.
 */
#define	FP_ETHER_MIN_LEN		64

/*
 * The maximum packet length.
 */
#define	FP_ETHER_MAX_LEN		1518

/*
 * A macro to validate a length with
 */
#define	FP_ETHER_IS_VALID_LEN(foo)	\
	((foo) >= FP_ETHER_MIN_LEN && (foo) <= FP_ETHER_MAX_LEN)

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct	fp_ether_header {
	uint8_t	ether_dhost[FP_ETHER_ADDR_LEN];
	uint8_t	ether_shost[FP_ETHER_ADDR_LEN];
	uint16_t	ether_type;
} __attribute__((packed));

#define	FP_ETHERTYPE_PUP	0x0200	/* PUP protocol */
#define	FP_ETHERTYPE_IP		0x0800	/* IP protocol */
#define	FP_ETHERTYPE_ARP	0x0806	/* Addr. resolution protocol */
#define	FP_ETHERTYPE_TEB	0x6558	/* Transparent Ethernet Bridging */
#define	FP_ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */
#define	FP_ETHERTYPE_VLAN	0x8100	/* IEEE 802.1Q VLAN tagging */
#define	FP_ETHERTYPE_IPV6	0x86dd	/* IPv6 */
#define	FP_ETHERTYPE_LOOPBACK	0x9000	/* used to test interfaces */
#define	FP_ETHERTYPE_802_3_MIN	0x0600	/* if ether_type is greater, it's a 802_3 frame.
					 * Otherwise the frame is Ethernet II. */
/* XXX - add more useful types here */
#define FP_ETHERTYPE_P_SLOW     0x8809	/* Slow Protocol. See 802.3ad 43B */
#define FP_ETHERTYPE_MPLS       0x8847	/* MPLS */

#define    FP_ETHERTYPE_PPPOE_DISCOVERY      0x8863
#define     FP_ETHERTYPE_PPPOE_SESSION         0x8864

/*
 * The FP_ETHERTYPE_NTRAILER packet types starting at FP_ETHERTYPE_TRAIL have
 * (type-FP_ETHERTYPE_TRAIL)*512 bytes of data followed
 * by an ETHER type (as given above) and then the (variable-length) header.
 */
#define	FP_ETHERTYPE_TRAIL	0x1000		/* Trailer packet */
#define	FP_ETHERTYPE_NTRAILER	16

#define	FP_ETHERMTU	(FP_ETHER_MAX_LEN-FP_ETHER_HDR_LEN-FP_ETHER_CRC_LEN)
#define	FP_ETHERMIN	(FP_ETHER_MIN_LEN-FP_ETHER_HDR_LEN-FP_ETHER_CRC_LEN)

/*
 *      Display a MAC address in readable format.
 */

#define FP_NMAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define FP_NMAC(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3], \
    ((unsigned char *)&addr)[4], \
    ((unsigned char *)&addr)[5]

#endif /* !__NET_FP_ETHERNET_H__ */
