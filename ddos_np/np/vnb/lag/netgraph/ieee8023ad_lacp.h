/*
 * Copyright 2011 6WIND S.A.
 */

/*	$NetBSD: ieee8023ad_lacp.h,v 1.2 2005/12/10 23:21:39 elad Exp $	*/

/*-
 * Copyright (c)2005 YAMAMOTO Takashi,
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NET_AGR_IEEE8023AD_LACP_H_
#define	_NET_AGR_IEEE8023AD_LACP_H_

/*
 * Macros to convert to a specific endianness.
 */
#ifndef htobe16
#define htobe16(x)	htons((uint16_t)(x))
#endif
#ifndef be16toh
#define be16toh(x)	htobe16(x)
#endif

/*
 * IEEE802.3ad LACP
 *
 * protocol definitions.
 */

struct lacp_systemid {
	uint16_t lsi_prio;
	uint8_t lsi_mac[6];
} __attribute__((__packed__));

struct lacp_portid {
	uint16_t lpi_prio;
	uint16_t lpi_portno;
} __attribute__((__packed__));

struct lacp_peerinfo {
	struct lacp_systemid lip_systemid;
	uint16_t lip_key;
	struct lacp_portid lip_portid;
	uint8_t lip_state;
	uint8_t lip_resv[3];
} __attribute__((__packed__));

#define	LACP_STATE_ACTIVITY	(1<<0)
#define	LACP_STATE_TIMEOUT	(1<<1)
#define	LACP_STATE_AGGREGATION	(1<<2)
#define	LACP_STATE_SYNC		(1<<3)
#define	LACP_STATE_COLLECTING	(1<<4)
#define	LACP_STATE_DISTRIBUTING	(1<<5)
#define	LACP_STATE_DEFAULTED	(1<<6)
#define	LACP_STATE_EXPIRED	(1<<7)

/* for bitmask_snprintf(9) */
#define	LACP_STATE_BITS		\
	"\177\020"		\
	"b\0ACTIVITY\0"		\
	"b\1TIMEOUT\0"		\
	"b\2AGGREGATION\0"	\
	"b\3SYNC\0"		\
	"b\4COLLECTING\0"	\
	"b\5DISTRIBUTING\0"	\
	"b\6DEFAULTED\0"		\
	"b\7EXPIRED\0"

struct lacp_collectorinfo {
	uint16_t lci_maxdelay;
	uint8_t lci_resv[12];
} __attribute__((__packed__));

struct lacpdu {
	struct vnb_ether_header ldu_eh;
	struct slowprothdr ldu_sph;

	struct tlvhdr ldu_tlv_actor;
	struct lacp_peerinfo ldu_actor;
	struct tlvhdr ldu_tlv_partner;
	struct lacp_peerinfo ldu_partner;
	struct tlvhdr ldu_tlv_collector;
	struct lacp_collectorinfo ldu_collector;
	struct tlvhdr ldu_tlv_term;
	uint8_t ldu_resv[50];
} __attribute__((__packed__));

#define	LACP_TYPE_ACTORINFO	1
#define	LACP_TYPE_PARTNERINFO	2
#define	LACP_TYPE_COLLECTORINFO	3

/* timeout values (in sec) */
/*
 * invocation frequency for the LACP State Machine (in Hertz)
 * values larger than 10 are not supported
 */
#define	LACP_TICK_HZ	10
/*
 * acceleration factor for the LACP state machine :
 *   the real-time delays are shorter by a (LACP_TICK_HZ/LACP_TICK_RATIO) factor.
 * As an example : LACP_TICK_HZ=10 with LACP_TICK_RATIO=2
 *   implies 5 times faster LACP convergence.
 */
#define	LACP_TICK_RATIO	10
#define	LACP_FAST_PERIODIC_TIME		(1*LACP_TICK_RATIO)
#define	LACP_SLOW_PERIODIC_TIME		(30*LACP_TICK_RATIO)
#define	LACP_SHORT_TIMEOUT_TIME		(3 * LACP_FAST_PERIODIC_TIME)
#define	LACP_LONG_TIMEOUT_TIME		(3 * LACP_SLOW_PERIODIC_TIME)
#define	LACP_CHURN_DETECTION_TIME	(60*LACP_TICK_RATIO)
#define	LACP_AGGREGATE_WAIT_TIME	(2*LACP_TICK_RATIO)

#endif /* !_NET_AGR_IEEE8023AD_LACP_H_ */
