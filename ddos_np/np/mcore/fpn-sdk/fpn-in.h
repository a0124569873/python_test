/*
 * Copyright 2013 6WIND S.A.
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

#ifndef _FPN_IN_H_
#define _FPN_IN_H_

/*
 * Constants and structures defined by the internet system,
 * Per RFC 790, September 1981, and numerous additions.
 */

/*
 * Protocols (RFC 1700)
 */
#define	FPN_IPPROTO_IP		0	/* dummy for IP */
#define	FPN_IPPROTO_HOPOPTS	0	/* IP6 hop-by-hop options */
#define	FPN_IPPROTO_ICMP	1	/* control message protocol */
#define	FPN_IPPROTO_IGMP	2	/* group mgmt protocol */
#define	FPN_IPPROTO_GGP		3	/* gateway^2 (deprecated) */
#define FPN_IPPROTO_IPV4	4 	/* IPv4 encapsulation */
#define FPN_IPPROTO_IPIP	FPN_IPPROTO_IPV4 /* for compatibility */
#define	FPN_IPPROTO_TCP		6	/* tcp */
#define	FPN_IPPROTO_ST		7	/* Stream protocol II */
#define	FPN_IPPROTO_EGP		8	/* exterior gateway protocol */
#define	FPN_IPPROTO_PIGP	9	/* private interior gateway */
#define	FPN_IPPROTO_RCCMON	10	/* BBN RCC Monitoring */
#define	FPN_IPPROTO_NVPII	11	/* network voice protocol*/
#define	FPN_IPPROTO_PUP		12	/* pup */
#define	FPN_IPPROTO_ARGUS	13	/* Argus */
#define	FPN_IPPROTO_EMCON	14	/* EMCON */
#define	FPN_IPPROTO_XNET	15	/* Cross Net Debugger */
#define	FPN_IPPROTO_CHAOS	16	/* Chaos*/
#define	FPN_IPPROTO_UDP		17	/* user datagram protocol */
#define	FPN_IPPROTO_MUX		18	/* Multiplexing */
#define	FPN_IPPROTO_MEAS	19	/* DCN Measurement Subsystems */
#define	FPN_IPPROTO_HMP		20	/* Host Monitoring */
#define	FPN_IPPROTO_PRM		21	/* Packet Radio Measurement */
#define	FPN_IPPROTO_IDP		22	/* xns idp */
#define	FPN_IPPROTO_TRUNK1	23	/* Trunk-1 */
#define	FPN_IPPROTO_TRUNK2	24	/* Trunk-2 */
#define	FPN_IPPROTO_LEAF1	25	/* Leaf-1 */
#define	FPN_IPPROTO_LEAF2	26	/* Leaf-2 */
#define	FPN_IPPROTO_RDP		27	/* Reliable Data */
#define	FPN_IPPROTO_IRTP	28	/* Reliable Transaction */
#define	FPN_IPPROTO_TP		29 	/* tp-4 w/ class negotiation */
#define	FPN_IPPROTO_BLT		30	/* Bulk Data Transfer */
#define	FPN_IPPROTO_NSP		31	/* Network Services */
#define	FPN_IPPROTO_INP		32	/* Merit Internodal */
#define	FPN_IPPROTO_SEP		33	/* Sequential Exchange */
#define	FPN_IPPROTO_3PC		34	/* Third Party Connect */
#define	FPN_IPPROTO_IDPR	35	/* InterDomain Policy Routing */
#define	FPN_IPPROTO_XTP		36	/* XTP */
#define	FPN_IPPROTO_DDP		37	/* Datagram Delivery */
#define	FPN_IPPROTO_CMTP	38	/* Control Message Transport */
#define	FPN_IPPROTO_TPXX	39	/* TP++ Transport */
#define	FPN_IPPROTO_IL		40	/* IL transport protocol */
#define	FPN_IPPROTO_IPV6	41	/* IP6 header */
#define	FPN_IPPROTO_SDRP	42	/* Source Demand Routing */
#define	FPN_IPPROTO_ROUTING	43	/* IP6 routing header */
#define	FPN_IPPROTO_FRAGMENT	44	/* IP6 fragmentation header */
#define	FPN_IPPROTO_IDRP	45	/* InterDomain Routing*/
#define	FPN_IPPROTO_RSVP	46 	/* resource reservation */
#define	FPN_IPPROTO_GRE		47	/* General Routing Encap. */
#define	FPN_IPPROTO_MHRP	48	/* Mobile Host Routing */
#define	FPN_IPPROTO_BHA		49	/* BHA */
#define	FPN_IPPROTO_ESP		50	/* IP6 Encap Sec. Payload */
#define	FPN_IPPROTO_AH		51	/* IP6 Auth Header */
#define	FPN_IPPROTO_INLSP	52	/* Integ. Net Layer Security */
#define	FPN_IPPROTO_SWIPE	53	/* IP with encryption */
#define	FPN_IPPROTO_NHRP	54	/* Next Hop Resolution */
/* 55-57: Unassigned */
#define	FPN_IPPROTO_ICMPV6	58	/* ICMP6 */
#define	FPN_IPPROTO_NONE	59	/* IP6 no next header */
#define	FPN_IPPROTO_DSTOPTS	60	/* IP6 destination option */
#define	FPN_IPPROTO_AHIP	61	/* any host internal protocol */
#define	FPN_IPPROTO_CFTP	62	/* CFTP */
#define	FPN_IPPROTO_HELLO	63	/* "hello" routing protocol */
#define	FPN_IPPROTO_SATEXPAK	64	/* SATNET/Backroom EXPAK */
#define	FPN_IPPROTO_KRYPTOLAN	65	/* Kryptolan */
#define	FPN_IPPROTO_RVD		66	/* Remote Virtual Disk */
#define	FPN_IPPROTO_IPPC	67	/* Pluribus Packet Core */
#define	FPN_IPPROTO_ADFS	68	/* Any distributed FS */
#define	FPN_IPPROTO_SATMON	69	/* Satnet Monitoring */
#define	FPN_IPPROTO_VISA	70	/* VISA Protocol */
#define	FPN_IPPROTO_IPCV	71	/* Packet Core Utility */
#define	FPN_IPPROTO_CPNX	72	/* Comp. Prot. Net. Executive */
#define	FPN_IPPROTO_CPHB	73	/* Comp. Prot. HeartBeat */
#define	FPN_IPPROTO_WSN		74	/* Wang Span Network */
#define	FPN_IPPROTO_PVP		75	/* Packet Video Protocol */
#define	FPN_IPPROTO_BRSATMON	76	/* BackRoom SATNET Monitoring */
#define	FPN_IPPROTO_ND		77	/* Sun net disk proto (temp.) */
#define	FPN_IPPROTO_WBMON	78	/* WIDEBAND Monitoring */
#define	FPN_IPPROTO_WBEXPAK	79	/* WIDEBAND EXPAK */
#define	FPN_IPPROTO_EON		80	/* ISO cnlp */
#define	FPN_IPPROTO_VMTP	81	/* VMTP */
#define	FPN_IPPROTO_SVMTP	82	/* Secure VMTP */
#define	FPN_IPPROTO_VINES	83	/* Banyon VINES */
#define	FPN_IPPROTO_TTP		84	/* TTP */
#define	FPN_IPPROTO_IGP		85	/* NSFNET-IGP */
#define	FPN_IPPROTO_DGP		86	/* dissimilar gateway prot. */
#define	FPN_IPPROTO_TCF		87	/* TCF */
#define	FPN_IPPROTO_IGRP	88	/* Cisco/GXS IGRP */
#define	FPN_IPPROTO_OSPFIGP	89	/* OSPFIGP */
#define	FPN_IPPROTO_SRPC	90	/* Strite RPC protocol */
#define	FPN_IPPROTO_LARP	91	/* Locus Address Resoloution */
#define	FPN_IPPROTO_MTP		92	/* Multicast Transport */
#define	FPN_IPPROTO_AX25	93	/* AX.25 Frames */
#define	FPN_IPPROTO_IPEIP	94	/* IP encapsulated in IP */
#define	FPN_IPPROTO_MICP	95	/* Mobile Int.ing control */
#define	FPN_IPPROTO_SCCSP	96	/* Semaphore Comm. security */
#define	FPN_IPPROTO_ETHERIP	97	/* Ethernet IP encapsulation */
#define	FPN_IPPROTO_ENCAP	98	/* encapsulation header */
#define	FPN_IPPROTO_APES	99	/* any private encr. scheme */
#define	FPN_IPPROTO_GMTP	100	/* GMTP*/
#define	FPN_IPPROTO_IPCOMP	108	/* payload compression (IPComp) */
/* 101-254: Partly Unassigned */
#define	FPN_IPPROTO_PIM		103	/* Protocol Independent Mcast */
#define	FPN_IPPROTO_VRRP	112	/* VRRP */
#define	FPN_IPPROTO_PGM		113	/* PGM */
#define	FPN_IPPROTO_SCTP	132	/* Stream Control Transport Protocol */
/* 255: Reserved */
/* BSD Private, local use, namespace incursion */
#define	FPN_IPPROTO_DIVERT	254		/* divert pseudo-protocol */
#define	FPN_IPPROTO_RAW		255		/* raw IP packet */
#define	FPN_IPPROTO_MAX		256

#endif
