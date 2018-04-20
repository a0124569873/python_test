/*-
 * Copyright (c) 1982, 1986, 1990, 1993
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
 *	@(#)in.h	8.3 (Berkeley) 1/3/94
 * $FreeBSD$
 */

/*
 * Copyright 2010-2013 6WIND S.A.
 */

#ifndef _NETINET_VNB_IN_H_
#define _NETINET_VNB_IN_H_
/*
 * Constants and structures defined by the internet system,
 * Per RFC 790, September 1981, and numerous additions.
 */

/*
 * Protocols (RFC 1700)
 */
#define	VNB_IPPROTO_IP		0		/* dummy for IP */
#define	VNB_IPPROTO_HOPOPTS	0		/* IP6 hop-by-hop options */
#define	VNB_IPPROTO_ICMP	1		/* control message protocol */
#define	VNB_IPPROTO_IGMP	2		/* group mgmt protocol */
#define	VNB_IPPROTO_GGP		3		/* gateway^2 (deprecated) */
#define VNB_IPPROTO_IPV4	4 		/* IPv4 encapsulation */
#define VNB_IPPROTO_IPIP	VNB_IPPROTO_IPV4	/* for compatibility */
#define	VNB_IPPROTO_TCP		6		/* tcp */
#define	VNB_IPPROTO_ST		7		/* Stream protocol II */
#define	VNB_IPPROTO_EGP		8		/* exterior gateway protocol */
#define	VNB_IPPROTO_PIGP	9		/* private interior gateway */
#define	VNB_IPPROTO_RCCMON	10		/* BBN RCC Monitoring */
#define	VNB_IPPROTO_NVPII	11		/* network voice protocol*/
#define	VNB_IPPROTO_PUP		12		/* pup */
#define	VNB_IPPROTO_ARGUS	13		/* Argus */
#define	VNB_IPPROTO_EMCON	14		/* EMCON */
#define	VNB_IPPROTO_XNET	15		/* Cross Net Debugger */
#define	VNB_IPPROTO_CHAOS	16		/* Chaos*/
#define	VNB_IPPROTO_UDP		17		/* user datagram protocol */
#define	VNB_IPPROTO_MUX		18		/* Multiplexing */
#define	VNB_IPPROTO_MEAS	19		/* DCN Measurement Subsystems */
#define	VNB_IPPROTO_HMP		20		/* Host Monitoring */
#define	VNB_IPPROTO_PRM		21		/* Packet Radio Measurement */
#define	VNB_IPPROTO_IDP		22		/* xns idp */
#define	VNB_IPPROTO_TRUNK1	23		/* Trunk-1 */
#define	VNB_IPPROTO_TRUNK2	24		/* Trunk-2 */
#define	VNB_IPPROTO_LEAF1	25		/* Leaf-1 */
#define	VNB_IPPROTO_LEAF2	26		/* Leaf-2 */
#define	VNB_IPPROTO_RDP		27		/* Reliable Data */
#define	VNB_IPPROTO_IRTP	28		/* Reliable Transaction */
#define	VNB_IPPROTO_TP		29 		/* tp-4 w/ class negotiation */
#define	VNB_IPPROTO_BLT		30		/* Bulk Data Transfer */
#define	VNB_IPPROTO_NSP		31		/* Network Services */
#define	VNB_IPPROTO_INP		32		/* Merit Internodal */
#define	VNB_IPPROTO_SEP		33		/* Sequential Exchange */
#define	VNB_IPPROTO_3PC		34		/* Third Party Connect */
#define	VNB_IPPROTO_IDPR	35		/* InterDomain Policy Routing */
#define	VNB_IPPROTO_XTP		36		/* XTP */
#define	VNB_IPPROTO_DDP		37		/* Datagram Delivery */
#define	VNB_IPPROTO_CMTP	38		/* Control Message Transport */
#define	VNB_IPPROTO_TPXX	39		/* TP++ Transport */
#define	VNB_IPPROTO_IL		40		/* IL transport protocol */
#define	VNB_IPPROTO_IPV6	41		/* IP6 header */
#define	VNB_IPPROTO_SDRP	42		/* Source Demand Routing */
#define	VNB_IPPROTO_ROUTING	43		/* IP6 routing header */
#define	VNB_IPPROTO_FRAGMENT	44		/* IP6 fragmentation header */
#define	VNB_IPPROTO_IDRP	45		/* InterDomain Routing*/
#define	VNB_IPPROTO_RSVP	46 		/* resource reservation */
#define	VNB_IPPROTO_GRE		47		/* General Routing Encap. */
#define	VNB_IPPROTO_MHRP	48		/* Mobile Host Routing */
#define	VNB_IPPROTO_BHA		49		/* BHA */
#define	VNB_IPPROTO_ESP		50		/* IP6 Encap Sec. Payload */
#define	VNB_IPPROTO_AH		51		/* IP6 Auth Header */
#define	VNB_IPPROTO_INLSP	52		/* Integ. Net Layer Security */
#define	VNB_IPPROTO_SWIPE	53		/* IP with encryption */
#define	VNB_IPPROTO_NHRP	54		/* Next Hop Resolution */
/* 55-57: Unassigned */
#define	VNB_IPPROTO_ICMPV6	58		/* ICMP6 */
#define	VNB_IPPROTO_NONE	59		/* IP6 no next header */
#define	VNB_IPPROTO_DSTOPTS	60		/* IP6 destination option */
#define	VNB_IPPROTO_AHIP	61		/* any host internal protocol */
#define	VNB_IPPROTO_CFTP	62		/* CFTP */
#define	VNB_IPPROTO_HELLO	63		/* "hello" routing protocol */
#define	VNB_IPPROTO_SATEXPAK	64		/* SATNET/Backroom EXPAK */
#define	VNB_IPPROTO_KRYPTOLAN	65		/* Kryptolan */
#define	VNB_IPPROTO_RVD		66		/* Remote Virtual Disk */
#define	VNB_IPPROTO_IPPC	67		/* Pluribus Packet Core */
#define	VNB_IPPROTO_ADFS	68		/* Any distributed FS */
#define	VNB_IPPROTO_SATMON	69		/* Satnet Monitoring */
#define	VNB_IPPROTO_VISA	70		/* VISA Protocol */
#define	VNB_IPPROTO_IPCV	71		/* Packet Core Utility */
#define	VNB_IPPROTO_CPNX	72		/* Comp. Prot. Net. Executive */
#define	VNB_IPPROTO_CPHB	73		/* Comp. Prot. HeartBeat */
#define	VNB_IPPROTO_WSN		74		/* Wang Span Network */
#define	VNB_IPPROTO_PVP		75		/* Packet Video Protocol */
#define	VNB_IPPROTO_BRSATMON	76		/* BackRoom SATNET Monitoring */
#define	VNB_IPPROTO_ND		77		/* Sun net disk proto (temp.) */
#define	VNB_IPPROTO_WBMON	78		/* WIDEBAND Monitoring */
#define	VNB_IPPROTO_WBEXPAK	79		/* WIDEBAND EXPAK */
#define	VNB_IPPROTO_EON		80		/* ISO cnlp */
#define	VNB_IPPROTO_VMTP	81		/* VMTP */
#define	VNB_IPPROTO_SVMTP	82		/* Secure VMTP */
#define	VNB_IPPROTO_VINES	83		/* Banyon VINES */
#define	VNB_IPPROTO_TTP		84		/* TTP */
#define	VNB_IPPROTO_IGP		85		/* NSFNET-IGP */
#define	VNB_IPPROTO_DGP		86		/* dissimilar gateway prot. */
#define	VNB_IPPROTO_TCF		87		/* TCF */
#define	VNB_IPPROTO_IGRP	88		/* Cisco/GXS IGRP */
#define	VNB_IPPROTO_OSPFIGP	89		/* OSPFIGP */
#define	VNB_IPPROTO_SRPC	90		/* Strite RPC protocol */
#define	VNB_IPPROTO_LARP	91		/* Locus Address Resoloution */
#define	VNB_IPPROTO_MTP		92		/* Multicast Transport */
#define	VNB_IPPROTO_AX25	93		/* AX.25 Frames */
#define	VNB_IPPROTO_IPEIP	94		/* IP encapsulated in IP */
#define	VNB_IPPROTO_MICP	95		/* Mobile Int.ing control */
#define	VNB_IPPROTO_SCCSP	96		/* Semaphore Comm. security */
#define	VNB_IPPROTO_ETHERIP	97		/* Ethernet IP encapsulation */
#define	VNB_IPPROTO_ENCAP	98		/* encapsulation header */
#define	VNB_IPPROTO_APES	99		/* any private encr. scheme */
#define	VNB_IPPROTO_GMTP	100		/* GMTP*/
#define	VNB_IPPROTO_IPCOMP	108		/* payload compression (IPComp) */
/* 101-254: Partly Unassigned */
#define	VNB_IPPROTO_PIM		103		/* Protocol Independent Mcast */
#define	VNB_IPPROTO_PGM		113		/* PGM */
#define	VNB_IPPROTO_SCTP	132		/* Stream Control Transport Protocol    */
/* 255: Reserved */
/* BSD Private, local use, namespace incursion */
#define	VNB_IPPROTO_DIVERT	254		/* divert pseudo-protocol */
#define	VNB_IPPROTO_RAW		255		/* raw IP packet */
#define	VNB_IPPROTO_MAX		256


/*
 * Internet address (a structure for historical reasons)
 */
struct vnb_in_addr {
	uint32_t s_addr;
};

struct vnb_in6_addr
{
        union
        {
                uint8_t            u6_addr8[16];
                uint16_t           u6_addr16[8];
                uint32_t           u6_addr32[4];
        } in6_u;
#define vnb_s6_addr                 in6_u.u6_addr8
#define vnb_s6_addr16               in6_u.u6_addr16
#define vnb_s6_addr32               in6_u.u6_addr32
};

/*
 * Definitions of bits in internet address integers.
 * On subnets, the decomposition of addresses to host and net parts
 * is done according to subnet mask, not the masks here.
 */
#define	VNB_IN_CLASSA(i)	(((uint32_t)(i) & 0x80000000) == 0)
#define	VNB_IN_CLASSA_NET	0xff000000
#define	VNB_IN_CLASSA_NSHIFT	24
#define	VNB_IN_CLASSA_HOST	0x00ffffff
#define	VNB_IN_CLASSA_MAX	128

#define	VNB_IN_CLASSB(i)	(((uint32_t)(i) & 0xc0000000) == 0x80000000)
#define	VNB_IN_CLASSB_NET	0xffff0000
#define	VNB_IN_CLASSB_NSHIFT	16
#define	VNB_IN_CLASSB_HOST	0x0000ffff
#define	VNB_IN_CLASSB_MAX	65536

#define	VNB_IN_CLASSC(i)	(((uint32_t)(i) & 0xe0000000) == 0xc0000000)
#define	VNB_IN_CLASSC_NET	0xffffff00
#define	VNB_IN_CLASSC_NSHIFT	8
#define	VNB_IN_CLASSC_HOST	0x000000ff

#define	VNB_IN_CLASSD(i)	(((uint32_t)(i) & 0xf0000000) == 0xe0000000)
#define	VNB_IN_CLASSD_NET	0xf0000000	/* These ones aren't really */
#define	VNB_IN_CLASSD_NSHIFT	28		/* net and host fields, but */
#define	VNB_IN_CLASSD_HOST	0x0fffffff	/* routing needn't know.    */
#define	VNB_IN_MULTICAST(i)	VNB_IN_CLASSD(i)
#define	VNB_IN_LOCAL_MULTICAST(i)	(((uint32_t)(i) & 0xffffff00) == 0xe0000000)

#define	VNB_IN_EXPERIMENTAL(i)	(((uint32_t)(i) & 0xf0000000) == 0xf0000000)
#define	VNB_IN_BADCLASS(i)	(((uint32_t)(i) & 0xf0000000) == 0xf0000000)
#define	VNB_IN_LOOPBACK(i)	(((uint32_t)(i) & 0xff000000) == 0x7f000000)

#define	VNB_INADDR_ANY		(uint32_t)0x00000000
#define	VNB_INADDR_LOOPBACK	(uint32_t)0x7f000001
#define	VNB_INADDR_BROADCAST	(uint32_t)0xe0000000	/* 224.0.0.0 */
#define	VNB_INADDR_ALLHOSTS_GROUP	(uint32_t)0xe0000001	/* 224.0.0.1 */
#define	VNB_INADDR_ALLRTRS_GROUP	(uint32_t)0xe0000002	/* 224.0.0.2 */
#define	VNB_INADDR_MAX_LOCAL_GROUP	(uint32_t)0xe00000ff	/* 224.0.0.255 */

#define	VNB_IN_LOOPBACKNET	127			/* official! */

/*
 * Socket address, internet style.
 * Mimic Linux sockaddrs
 */
struct vnb_sockaddr_in {
	uint16_t sin_family;
	u_short	sin_port;
	struct	vnb_in_addr sin_addr;
	char	sin_zero[8];
};

#define	VNB_INET_ADDRSTRLEN	16
#define	VNB_INET6_ADDRSTRLEN	46

struct vnb_sockaddr_in6
  {
    uint16_t sin6_family;
    u_short sin6_port;        /* Transport layer port # */
    uint32_t sin6_flowinfo;     /* IPv6 flow information */
    struct vnb_in6_addr sin6_addr;  /* IPv6 address */
    uint32_t sin6_scope_id;     /* IPv6 scope-id */
  };

/*
 *      Display an IP address in readable format.
 */

#define VNB_NIPQUAD_FMT "%u.%u.%u.%u"
#define VNB_NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define VNB_NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#define VNB_NIP6(addr) \
    ntohs((addr).vnb_s6_addr16[0]), \
    ntohs((addr).vnb_s6_addr16[1]), \
    ntohs((addr).vnb_s6_addr16[2]), \
    ntohs((addr).vnb_s6_addr16[3]), \
    ntohs((addr).vnb_s6_addr16[4]), \
    ntohs((addr).vnb_s6_addr16[5]), \
    ntohs((addr).vnb_s6_addr16[6]), \
    ntohs((addr).vnb_s6_addr16[7])

#endif
