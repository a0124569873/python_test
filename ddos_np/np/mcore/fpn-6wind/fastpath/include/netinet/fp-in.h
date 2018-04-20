/*
 * Copyright 6WIND 2010
 */

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

#ifndef _NETINET_FP_IN_H_
#define _NETINET_FP_IN_H_
/*
 * Constants and structures defined by the internet system,
 * Per RFC 790, September 1981, and numerous additions.
 */

/*
 * Protocols (RFC 1700)
 */
#define	FP_IPPROTO_IP		0		/* dummy for IP */
#define	FP_IPPROTO_HOPOPTS		0		/* IP6 hop-by-hop options */
#define	FP_IPPROTO_ICMP		1		/* control message protocol */
#define	FP_IPPROTO_IGMP		2		/* group mgmt protocol */
#define	FP_IPPROTO_GGP		3		/* gateway^2 (deprecated) */
#define FP_IPPROTO_IPV4		4 		/* IPv4 encapsulation */
#define FP_IPPROTO_IPIP		FP_IPPROTO_IPV4	/* for compatibility */
#define	FP_IPPROTO_TCP		6		/* tcp */
#define	FP_IPPROTO_ST		7		/* Stream protocol II */
#define	FP_IPPROTO_EGP		8		/* exterior gateway protocol */
#define	FP_IPPROTO_PIGP		9		/* private interior gateway */
#define	FP_IPPROTO_RCCMON		10		/* BBN RCC Monitoring */
#define	FP_IPPROTO_NVPII		11		/* network voice protocol*/
#define	FP_IPPROTO_PUP		12		/* pup */
#define	FP_IPPROTO_ARGUS		13		/* Argus */
#define	FP_IPPROTO_EMCON		14		/* EMCON */
#define	FP_IPPROTO_XNET		15		/* Cross Net Debugger */
#define	FP_IPPROTO_CHAOS		16		/* Chaos*/
#define	FP_IPPROTO_UDP		17		/* user datagram protocol */
#define	FP_IPPROTO_MUX		18		/* Multiplexing */
#define	FP_IPPROTO_MEAS		19		/* DCN Measurement Subsystems */
#define	FP_IPPROTO_HMP		20		/* Host Monitoring */
#define	FP_IPPROTO_PRM		21		/* Packet Radio Measurement */
#define	FP_IPPROTO_IDP		22		/* xns idp */
#define	FP_IPPROTO_TRUNK1		23		/* Trunk-1 */
#define	FP_IPPROTO_TRUNK2		24		/* Trunk-2 */
#define	FP_IPPROTO_LEAF1		25		/* Leaf-1 */
#define	FP_IPPROTO_LEAF2		26		/* Leaf-2 */
#define	FP_IPPROTO_RDP		27		/* Reliable Data */
#define	FP_IPPROTO_IRTP		28		/* Reliable Transaction */
#define	FP_IPPROTO_TP		29 		/* tp-4 w/ class negotiation */
#define	FP_IPPROTO_BLT		30		/* Bulk Data Transfer */
#define	FP_IPPROTO_NSP		31		/* Network Services */
#define	FP_IPPROTO_INP		32		/* Merit Internodal */
#define	FP_IPPROTO_SEP		33		/* Sequential Exchange */
#define	FP_IPPROTO_3PC		34		/* Third Party Connect */
#define	FP_IPPROTO_IDPR		35		/* InterDomain Policy Routing */
#define	FP_IPPROTO_XTP		36		/* XTP */
#define	FP_IPPROTO_DDP		37		/* Datagram Delivery */
#define	FP_IPPROTO_CMTP		38		/* Control Message Transport */
#define	FP_IPPROTO_TPXX		39		/* TP++ Transport */
#define	FP_IPPROTO_IL		40		/* IL transport protocol */
#define	FP_IPPROTO_IPV6		41		/* IP6 header */
#define	FP_IPPROTO_SDRP		42		/* Source Demand Routing */
#define	FP_IPPROTO_ROUTING		43		/* IP6 routing header */
#define	FP_IPPROTO_FRAGMENT	44		/* IP6 fragmentation header */
#define	FP_IPPROTO_IDRP		45		/* InterDomain Routing*/
#define	FP_IPPROTO_RSVP		46 		/* resource reservation */
#define	FP_IPPROTO_GRE		47		/* General Routing Encap. */
#define	FP_IPPROTO_MHRP		48		/* Mobile Host Routing */
#define	FP_IPPROTO_BHA		49		/* BHA */
#define	FP_IPPROTO_ESP		50		/* IP6 Encap Sec. Payload */
#define	FP_IPPROTO_AH		51		/* IP6 Auth Header */
#define	FP_IPPROTO_INLSP		52		/* Integ. Net Layer Security */
#define	FP_IPPROTO_SWIPE		53		/* IP with encryption */
#define	FP_IPPROTO_NHRP		54		/* Next Hop Resolution */
/* 55-57: Unassigned */
#define	FP_IPPROTO_ICMPV6		58		/* ICMP6 */
#define	FP_IPPROTO_NONE		59		/* IP6 no next header */
#define	FP_IPPROTO_DSTOPTS		60		/* IP6 destination option */
#define	FP_IPPROTO_AHIP		61		/* any host internal protocol */
#define	FP_IPPROTO_CFTP		62		/* CFTP */
#define	FP_IPPROTO_HELLO		63		/* "hello" routing protocol */
#define	FP_IPPROTO_SATEXPAK	64		/* SATNET/Backroom EXPAK */
#define	FP_IPPROTO_KRYPTOLAN	65		/* Kryptolan */
#define	FP_IPPROTO_RVD		66		/* Remote Virtual Disk */
#define	FP_IPPROTO_IPPC		67		/* Pluribus Packet Core */
#define	FP_IPPROTO_ADFS		68		/* Any distributed FS */
#define	FP_IPPROTO_SATMON		69		/* Satnet Monitoring */
#define	FP_IPPROTO_VISA		70		/* VISA Protocol */
#define	FP_IPPROTO_IPCV		71		/* Packet Core Utility */
#define	FP_IPPROTO_CPNX		72		/* Comp. Prot. Net. Executive */
#define	FP_IPPROTO_CPHB		73		/* Comp. Prot. HeartBeat */
#define	FP_IPPROTO_WSN		74		/* Wang Span Network */
#define	FP_IPPROTO_PVP		75		/* Packet Video Protocol */
#define	FP_IPPROTO_BRSATMON	76		/* BackRoom SATNET Monitoring */
#define	FP_IPPROTO_ND		77		/* Sun net disk proto (temp.) */
#define	FP_IPPROTO_WBMON		78		/* WIDEBAND Monitoring */
#define	FP_IPPROTO_WBEXPAK		79		/* WIDEBAND EXPAK */
#define	FP_IPPROTO_EON		80		/* ISO cnlp */
#define	FP_IPPROTO_VMTP		81		/* VMTP */
#define	FP_IPPROTO_SVMTP		82		/* Secure VMTP */
#define	FP_IPPROTO_VINES		83		/* Banyon VINES */
#define	FP_IPPROTO_TTP		84		/* TTP */
#define	FP_IPPROTO_IGP		85		/* NSFNET-IGP */
#define	FP_IPPROTO_DGP		86		/* dissimilar gateway prot. */
#define	FP_IPPROTO_TCF		87		/* TCF */
#define	FP_IPPROTO_IGRP		88		/* Cisco/GXS IGRP */
#define	FP_IPPROTO_OSPFIGP		89		/* OSPFIGP */
#define	FP_IPPROTO_SRPC		90		/* Strite RPC protocol */
#define	FP_IPPROTO_LARP		91		/* Locus Address Resoloution */
#define	FP_IPPROTO_MTP		92		/* Multicast Transport */
#define	FP_IPPROTO_AX25		93		/* AX.25 Frames */
#define	FP_IPPROTO_IPEIP		94		/* IP encapsulated in IP */
#define	FP_IPPROTO_MICP		95		/* Mobile Int.ing control */
#define	FP_IPPROTO_SCCSP		96		/* Semaphore Comm. security */
#define	FP_IPPROTO_ETHERIP		97		/* Ethernet IP encapsulation */
#define	FP_IPPROTO_ENCAP		98		/* encapsulation header */
#define	FP_IPPROTO_APES		99		/* any private encr. scheme */
#define	FP_IPPROTO_GMTP		100		/* GMTP*/
#define	FP_IPPROTO_IPCOMP		108		/* payload compression (IPComp) */
/* 101-254: Partly Unassigned */
#define	FP_IPPROTO_PIM		103		/* Protocol Independent Mcast */
#define	FP_IPPROTO_VRRP		112		/* VRRP */
#define	FP_IPPROTO_PGM		113		/* PGM */
#define	FP_IPPROTO_SCTP		132		/* Stream Control Transport Protocol    */
/* 255: Reserved */
/* BSD Private, local use, namespace incursion */
#define	FP_IPPROTO_DIVERT		254		/* divert pseudo-protocol */
#define	FP_IPPROTO_RAW		255		/* raw IP packet */
#define	FP_IPPROTO_MAX		256


/*
 * Internet address (a structure for historical reasons)
 */
struct fp_in_addr {
	uint32_t s_addr;
};

struct fp_in6_addr
{
        union
        {
                uint8_t            u6_addr8[16];
                uint16_t           u6_addr16[8];
                uint32_t           u6_addr32[4];
        } in6_u;
#define fp_s6_addr                 in6_u.u6_addr8
#define fp_s6_addr16               in6_u.u6_addr16
#define fp_s6_addr32               in6_u.u6_addr32
};

/*
 * By byte-swapping the constants, we avoid ever having to byte-swap IP
 * addresses inside the fast path.
 */
#define	__IPADDR(x)	((uint32_t) htonl((uint32_t)(x)))

/*
 * Definitions of bits in internet address integers.
 * On subnets, the decomposition of addresses to host and net parts
 * is done according to subnet mask, not the masks here.
 */
#define	FP_IN_CLASSA(i)		(((uint32_t)(i) & __IPADDR(0x80000000)) == 0)
#define	FP_IN_CLASSA_NET	__IPADDR(0xff000000)
#define	FP_IN_CLASSA_NSHIFT	24
#define	FP_IN_CLASSA_HOST	__IPADDR(0x00ffffff)
#define	FP_IN_CLASSA_MAX	128

#define	FP_IN_CLASSB(i)		(((uint32_t)(i) & __IPADDR(0xc0000000)) == \
				 __IPADDR(0x80000000))
#define	FP_IN_CLASSB_NET	__IPADDR(0xffff0000)
#define	FP_IN_CLASSB_NSHIFT	16
#define	FP_IN_CLASSB_HOST	__IPADDR(0x0000ffff)
#define	FP_IN_CLASSB_MAX	65536

#define	FP_IN_CLASSC(i)		(((uint32_t)(i) & __IPADDR(0xe0000000)) == \
				 __IPADDR(0xc0000000))
#define	FP_IN_CLASSC_NET	__IPADDR(0xffffff00)
#define	FP_IN_CLASSC_NSHIFT	8
#define	FP_IN_CLASSC_HOST	__IPADDR(0x000000ff)

#define	FP_IN_CLASSD(i)		(((uint32_t)(i) & __IPADDR(0xf0000000)) == \
				 __IPADDR(0xe0000000))
#define	FP_IN_CLASSD_NET	__IPADDR(0xf0000000) /* These ones aren't really */
#define	FP_IN_CLASSD_NSHIFT	28		/* net and host fields, but */
#define	FP_IN_CLASSD_HOST	__IPADDR(0x0fffffff)	/* routing needn't know.    */
#define	FP_IN_MULTICAST(i)	FP_IN_CLASSD(i)
#define	FP_IN_LOCAL_MULTICAST(i) (((uint32_t)(i) & __IPADDR(0xffffff00)) == \
				  __IPADDR(0xe0000000))

#define	FP_IN_EXPERIMENTAL(i)	(((uint32_t)(i) & __IPADDR(0xf0000000)) == \
				 __IPADDR(0xf0000000))
#define	FP_IN_BADCLASS(i)	(((uint32_t)(i) & __IPADDR(0xf0000000)) == \
				 __IPADDR(0xf0000000))
#define	FP_IN_LOOPBACK(i)	(((uint32_t)(i) & __IPADDR(0xff000000)) == \
				 __IPADDR(0x7f000000))

#define	FP_INADDR_ANY             __IPADDR(0x00000000)
#define	FP_INADDR_LOOPBACK        __IPADDR(0x7f000001)
#define	FP_INADDR_BROADCAST       __IPADDR(0xe0000000)	/* 224.0.0.0 */
#define	FP_INADDR_ALLHOSTS_GROUP  __IPADDR(0xe0000001)	/* 224.0.0.1 */
#define	FP_INADDR_ALLRTRS_GROUP   __IPADDR(0xe0000002)	/* 224.0.0.2 */
#define	FP_INADDR_MAX_LOCAL_GROUP __IPADDR(0xe00000ff)	/* 224.0.0.255 */

#define	FP_IN_LOOPBACKNET		127			/* official! */

/*
 * Socket address, internet style.
 * Mimic Linux sockaddrs
 */
struct fp_sockaddr_in {
	uint16_t sin_family;
	uint16_t sin_port;
	struct	fp_in_addr sin_addr;
	char	sin_zero[8];
};

#define	FP_INET_ADDRSTRLEN	16
#define	FP_INET6_ADDRSTRLEN	46

struct fp_sockaddr_in6
  {
    uint16_t sin6_family;
    uint16_t sin6_port;        /* Transport layer port # */
    uint32_t sin6_flowinfo;     /* IPv6 flow information */
    struct fp_in6_addr sin6_addr;  /* IPv6 address */
    uint32_t sin6_scope_id;     /* IPv6 scope-id */
  };

/*
 *      Display an IP address in readable format.
 */

#define FP_NIPQUAD_FMT "%u.%u.%u.%u"
#define FP_NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define FP_NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#define FP_NIP6(addr) \
    ntohs((addr).fp_s6_addr16[0]), \
    ntohs((addr).fp_s6_addr16[1]), \
    ntohs((addr).fp_s6_addr16[2]), \
    ntohs((addr).fp_s6_addr16[3]), \
    ntohs((addr).fp_s6_addr16[4]), \
    ntohs((addr).fp_s6_addr16[5]), \
    ntohs((addr).fp_s6_addr16[6]), \
    ntohs((addr).fp_s6_addr16[7])

#endif
