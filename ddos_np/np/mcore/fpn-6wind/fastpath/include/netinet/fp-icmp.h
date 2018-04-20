/*
 * Copyright (c) 2010 6WIND
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

#ifndef __NETINET_FP_ICMP_H__
#define __NETINET_FP_ICMP_H__

/*
 * Internal of an ICMP Router Advertisement
 */
struct fp_icmp_ra_addr {
	uint32_t ira_addr;
	uint32_t ira_preference;
} __attribute__ ((packed));

struct fp_icmphdr {
	uint8_t		icmp_type;	/* type of message, see below */
	uint8_t		icmp_code;	/* type sub code */
	uint16_t	icmp_cksum;	/* ones complement cksum of struct */
	union {
		uint8_t		ih_pptr;	/* ICMP_PARAMPROB */
		uint32_t	ih_gwaddr;	/* ICMP_REDIRECT */
		struct fp_ih_idseq {
			uint16_t	icd_id;
			uint16_t	icd_seq;
		} ih_idseq;
		uint32_t	 ih_void;
		/* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
		struct fp_ih_pmtu {
			  uint16_t ipm_void;
			  uint16_t ipm_nextmtu;
		} ih_pmtu __attribute__((packed));
		struct fp_ih_rtradv {
			uint8_t irt_num_addrs;
			uint8_t irt_wpa;
			uint16_t irt_lifetime;
		} ih_rtradv __attribute__((packed));
	} icmp_hun;
#define	icmp_pptr	  icmp_hun.ih_pptr
#define	icmp_gwaddr	  icmp_hun.ih_gwaddr
#define	icmp_id		  icmp_hun.ih_idseq.icd_id
#define	icmp_seq	  icmp_hun.ih_idseq.icd_seq
#define	icmp_void	  icmp_hun.ih_void
#define	icmp_pmvoid	  icmp_hun.ih_pmtu.ipm_void
#define	icmp_nextmtu	  icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs    icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa	  icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime	  icmp_hun.ih_rtradv.irt_lifetime
	union {
		struct fp_id_ts {
			  uint32_t its_otime;
			  uint32_t its_rtime;
			  uint32_t its_ttime;
		} id_ts __attribute__ ((packed));
		struct fp_id_ip  {
			  struct fp_ip idi_ip;
			  /* options and then 64 bits of data */
		} id_ip;
		struct fp_icmp_ra_addr id_radv;
		u_int32_t id_mask;
		int8_t	  id_data[1];
	} icmp_dun;
#define	icmp_otime	  icmp_dun.id_ts.its_otime
#define	icmp_rtime	  icmp_dun.id_ts.its_rtime
#define	icmp_ttime	  icmp_dun.id_ts.its_ttime
#define	icmp_ip		  icmp_dun.id_ip.idi_ip
#define icmp_radv	  icmp_dun.id_mask
#define	icmp_mask	  icmp_dun.id_mask
#define	icmp_data	  icmp_dun.id_data
} __attribute__ ((packed));

#endif /* __NETINET_FP_ICMP_H__ */
