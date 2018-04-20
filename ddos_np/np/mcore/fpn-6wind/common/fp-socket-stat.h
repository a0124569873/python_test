/*
 * Copyright(c) 2011 6WIND, all rights reserved
 */
/*	$NetBSD: tcp_var.h,v 1.158.4.1 2009/09/26 18:34:29 snj Exp $	*/

/*
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

/*
 *      @(#)COPYRIGHT   1.1 (NRL) 17 January 1995
 *
 * NRL grants permission for redistribution and use in source and binary
 * forms, with or without modification, of the software and documentation
 * created at NRL provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgements:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 *      This product includes software developed at the Information
 *      Technology Division, US Naval Research Laboratory.
 * 4. Neither the name of the NRL nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THE SOFTWARE PROVIDED BY NRL IS PROVIDED BY NRL AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL NRL OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation
 * are those of the authors and should not be interpreted as representing
 * official policies, either expressed or implied, of the US Naval
 * Research Laboratory (NRL).
 */

/*-
 * Copyright (c) 1997, 1998, 1999, 2001, 2005 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
 * This code is derived from software contributed to The NetBSD Foundation
 * by Charles M. Hannum.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 1982, 1986, 1993, 1994, 1995
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
 * 3. Neither the name of the University nor the names of its contributors
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
 *	@(#)tcp_var.h	8.4 (Berkeley) 5/24/95
 */

#ifndef _SOCKET_STAT_H_
#define _SOCKET_STAT_H_

/*
 * TCP statistics.
 * Each counter is an unsigned 64-bit value.
 *
 * Many of these should be kept per connection, but that's inconvenient
 * at the moment.
 */
enum {
	TCP_STAT_CONNATTEMPT=0,	/* connections initiated */
	TCP_STAT_ACCEPTS,	/* connections accepted */
	TCP_STAT_CONNECTS,	/* connections established */
	TCP_STAT_DROPS,		/* connections dropped */
	TCP_STAT_CONNDROPS,	/* embryonic connections dropped */
	TCP_STAT_CLOSED,	/* conn. closed (includes drops) */
	TCP_STAT_SEGSTIMED,	/* segs where we tried to get rtt */
	TCP_STAT_RTTUPDATED,	/* times we succeeded */
	TCP_STAT_DELACK,	/* delayed ACKs sent */
	TCP_STAT_TIMEOUTDROP,	/* conn. dropped in rxmt timeout */
	TCP_STAT_REXMTTIMEO,	/* retransmit timeouts */
	TCP_STAT_PERSISTTIMEO,	/* persist timeouts */
	TCP_STAT_KEEPTIMEO,	/* keepalive timeouts */
	TCP_STAT_KEEPPROBE,	/* keepalive probes sent */
	TCP_STAT_KEEPDROPS,	/* connections dropped in keepalive */
	TCP_STAT_PERSISTDROPS,	/* connections dropped in persist */
	//TCP_STAT_CONNSDRAINED,	/* connections drained due to memory
	//				   shortage */
	//TCP_STAT_PMTUBLACKHOLE,	/* PMTUD blackhole detected */
	TCP_STAT_SNDTOTAL,	/* total packets sent */
	TCP_STAT_SNDPACK,	/* data packlets sent */
	TCP_STAT_SNDBYTE,	/* data bytes sent */
	TCP_STAT_SNDREXMITPACK,	/* data packets retransmitted */
	TCP_STAT_SNDREXMITBYTE,	/* data bytes retransmitted */
	TCP_STAT_SNDACKS,	/* ACK-only packets sent */
	TCP_STAT_SNDPROBE,	/* window probes sent */
	//TCP_STAT_SNDURG,	/* packets sent with URG only */
	TCP_STAT_SNDWINUP,	/* window update-only packets sent */
	TCP_STAT_SNDSYN,	/* SYN packets sent */
	TCP_STAT_SNDFIN,	/* FIN packets sent */
	TCP_STAT_SNDRST,	/* RST packets sent */
	TCP_STAT_RCVRST,	/* RST packets received */
	TCP_STAT_RCVTOTAL,	/* total packets received */
	TCP_STAT_RCVPACK,	/* packets received in sequence */
	TCP_STAT_RCVBYTE,	/* bytes received in sequence */
	TCP_STAT_RCVBADSUM,	/* packets received with cksum errs */
	TCP_STAT_RCVBADOFF,	/* packets received with bad offset */
	TCP_STAT_RCVMEMDROP,	/* packets dropped for lack of memory */
	TCP_STAT_RCVSHORT,	/* packets received too short */
	TCP_STAT_RCVDUPPACK,	/* duplicate-only packets received */
	TCP_STAT_RCVDUPBYTE,	/* duplicate-only bytes received */
	TCP_STAT_RCVPARTDUPPACK,	/* packets with some duplicate data */
	TCP_STAT_RCVPARTDUPBYTE,	/* dup. bytes in part-dup. packets */
	TCP_STAT_RCVOOPACK,	/* out-of-order packets received */
	TCP_STAT_RCVOOBYTE,	/* out-of-order bytes received */
	TCP_STAT_RCVPACKAFTERWIN,	/* packets with data after window */
	TCP_STAT_RCVBYTEAFTERWIN,	/* bytes received after window */
	TCP_STAT_RCVAFTERCLOSE,	/* packets received after "close" */
	TCP_STAT_RCVWINPROBE,	/* rcvd window probe packets */
	//TCP_STAT_RCVDUPACK,	/* rcvd duplicate ACKs */
	TCP_STAT_RCVACKTOOMUCH,	/* rcvd ACKs for unsent data */
	TCP_STAT_RCVACKPACK,	/* rcvd ACK packets */
	TCP_STAT_RCVACKBYTE,	/* bytes ACKed by rcvd ACKs */
	TCP_STAT_RCVWINUPD,	/* rcvd window update packets */
	TCP_STAT_PAWSDROP,	/* segments dropped due to PAWS */
	TCP_STAT_PREDACK,	/* times hdr predict OK for ACKs */
	TCP_STAT_PREDDAT,	/* times hdr predict OK for data pkts */
	TCP_STAT_PCBHASHMISS,	/* input packets missing PCB hash */
	TCP_STAT_NOPORT,	/* no socket on port */
	TCP_STAT_BADSYN,	/* received ACK for which we have
					   no SYN in compressed state */
	TCP_STAT_DELAYED_FREE,	/* delayed pool_put() of tcpcb */
	TCP_STAT_BACKLOG,       /* listen backlog exceeded */
	TCP_STAT_SC_ADDED,	/* # of sc entries added */
	TCP_STAT_SC_COMPLETED,	/* # of sc connections completed */
	TCP_STAT_SC_TIMED_OUT,	/* # of sc entries timed out */
	TCP_STAT_SC_OVERFLOWED,	/* # of sc drops due to overflow */
	TCP_STAT_SC_RESET,	/* # of sc drops due to RST */
	TCP_STAT_SC_UNREACH,	/* # of sc drops due to ICMP unreach */
	TCP_STAT_SC_BUCKETOVERFLOW,	/* # of sc drops due to bucket ovflow */
	TCP_STAT_SC_ABORTED,	/* # of sc entries aborted (no mem) */
	TCP_STAT_SC_DUPESYN,	/* # of duplicate SYNs received */
	TCP_STAT_SC_DROPPED,	/* # of SYNs dropped (no route/mem) */
	TCP_STAT_SC_COLLISIONS,	/* # of sc hash collisions */
	TCP_STAT_SC_RETRANSMITTED,	/* # of sc retransmissions */
	TCP_STAT_SC_DELAYED_FREE,	/* # of delayed pool_put()s */
	TCP_STAT_SELFQUENCH,	/* # of ENOBUFS we get on output */
	//TCP_STAT_BADSIG,	/* # of drops due to bad signature */
	//TCP_STAT_GOODSIG,	/* # of packets with good signature */
	TCP_STAT_ECN_SHS,	/* # of successful ECN handshakes */
	TCP_STAT_ECN_CE,	/* # of packets with CE bit */
	TCP_STAT_ECN_ECT,	/* # of packets with ECT(0) bit */
	TCP_STAT_RCVSKIP,	/* # of packets not managed by MCORE_SOCKET */

	TCP_NSTATS		/* total number of stat variables */
};

typedef struct fp_tcp_stats {
	uint64_t stats[TCP_NSTATS];
} __fpn_cache_aligned fp_tcp_stats_t;

#ifdef FP_TCP_STATS_PER_CORE
#define FP_TCP_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_TCP_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FP_TCP_STATS_NUM                     FPN_MAX_CORES

#else /* FP_TCP_STATS_PER_CORE */
#define FP_TCP_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FP_TCP_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FP_TCP_STATS_NUM                     1

#endif /* FP_TCP_STATS_PER_CORE */


/*
 * UDP statistics.
 * Each counter is an unsigned 64-bit value.
 */
enum {
	UDP_STAT_IPACKETS=0,	/* total input packets */
	UDP_STAT_HDROPS,	/* packet shorter than header */
	//UDP_STAT_BADSUM,	/* checksum error */
	UDP_STAT_BADLEN,	/* data length larger than packet */
	UDP_STAT_NOPORT,	/* no socket on port */
	UDP_STAT_NOPORTBCAST,	/* of above, arrived as broadcast */
	UDP_STAT_FULLSOCK,	/* not delivered, input socket full */
	UDP_STAT_PCBHASHMISS,	/* input packets missing PCB hash */
	UDP_STAT_OPACKETS,	/* total output packets */
	UDP_STAT_RCVSKIP,	/* # of packets not managed by MCORE_SOCKET */

	UDP_NSTATS		/* total number of stat variables */
};

typedef struct fp_udp_stats {
	uint64_t stats[UDP_NSTATS];
} __fpn_cache_aligned fp_udp_stats_t;

#ifdef FP_UDP_STATS_PER_CORE
#define FP_UDP_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_UDP_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FP_UDP_STATS_NUM                     FPN_MAX_CORES

#else /* FP_UDP_STATS_PER_CORE */
#define FP_UDP_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FP_UDP_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FP_UDP_STATS_NUM                     1

#endif /* FP_UDP_STATS_PER_CORE */

#ifdef CONFIG_MCORE_SOCKET_INET6
/*
 * UDP6 statistics.
 * Each counter is an unsigned 64-bit value.
 */
enum {
	UDP6_STAT_IPACKETS=0,	/* total input packets */
	//UDP6_STAT_HDROPS,	/* packet shorter than header */
	//UDP6_STAT_BADSUM,	/* checksum error */
	UDP6_STAT_NOSUM,	/* no checksum */
	UDP6_STAT_BADLEN,	/* data length larger than packet */
	UDP6_STAT_NOPORT,	/* no socket on port */
	UDP6_STAT_NOPORTMCAST,	/* of above, arrived as multicast */
	UDP6_STAT_FULLSOCK,     /* not delivered, input socket full */
	UDP6_STAT_PCBHASHMISS, /* input packets missing pcb cache */
	UDP6_STAT_OPACKETS,     /* total output packets */
	UDP6_STAT_EXC,		/* # of exception packets sent to linux */

	UDP6_NSTATS		/* total number of stat variables */
};

typedef struct fp_udp6_stats {
	uint64_t stats[UDP6_NSTATS];
} __fpn_cache_aligned fp_udp6_stats_t;

#ifdef FP_UDP6_STATS_PER_CORE
#define FP_UDP6_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_UDP6_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FP_UDP6_STATS_NUM                     FPN_MAX_CORES

#else /* FP_UDP6_STATS_PER_CORE */
#define FP_UDP6_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FP_UDP6_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FP_UDP6_STATS_NUM                     1

#endif /* FP_UDP6_STATS_PER_CORE */
#endif /* CONFIG_MCORE_SOCKET_INET6 */

#endif /* _SOCKET_STAT_H_ */
