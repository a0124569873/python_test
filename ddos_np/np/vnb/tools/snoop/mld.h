/*	$KAME: mld6.h,v 1.13 2004/06/09 15:52:57 suz Exp $	*/

/*
 * Copyright (C) 1998 WIDE Project.
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
 *  Questions concerning this software should be directed to
 *  Mickael Hoerdt (hoerdt@clarinet.u-strasbg.fr) LSIIT Strasbourg.
 *
 */
/*
 * This program has been derived from pim6dd.
 * The pim6dd program is covered by the license in the accompanying file
 * named "LICENSE.pim6dd".
 */
/*
 * This program has been derived from pimd.
 * The pimd program is covered by the license in the accompanying file
 * named "LICENSE.pimd".
 *
 */


#ifndef MLD6_H
#define MLD6_H

#include <netinet/icmp6.h>

#define SEND_BUF_SIZE			64
#define MINHLIM					1
#define IP6OPT_RTALERT_LEN		4



extern int mld6_socket;
extern int pim6_socket;
extern struct sockaddr_in6 allnodes_group;
extern struct sockaddr_in6 allrouters_group;
extern struct sockaddr_in6 allmldv2routers_group;

/* portability with older KAME headers */
#ifndef MLD_LISTENER_QUERY
#define MLD_LISTENER_QUERY	MLD6_LISTENER_QUERY
#define MLD_LISTENER_REPORT	MLD6_LISTENER_REPORT
#define MLD_LISTENER_DONE	MLD6_LISTENER_DONE
#define MLD_MTRACE_RESP		MLD6_MTRACE_RESP
#define MLD_MTRACE		MLD6_MTRACE
#endif

#ifdef __linux__

struct mld_hdr {
	struct icmp6_hdr mld_icmp6_hdr;
	struct in6_addr	mld_addr;
} __attribute__ ((__packed__));;

#define mld_type mld_icmp6_hdr.icmp6_type
#define mld_code mld_icmp6_hdr.icmp6_code
#define mld_maxdelay mld_icmp6_hdr.icmp6_maxdelay

#endif

/*
#define mld_hdr		mld6_hdr
#define mld_type	mld6_type
#define mld_code	mld6_code
#define mld_cksum	mld6_cksum
#define mld_maxdelay	mld6_maxdelay
#define mld_reserved	mld6_reserved
#define mld_addr	mld6_addr
*/

#ifdef __linux__

#define MLD6_LISTENER_QUERY ICMP6_MEMBERSHIP_QUERY
#define MLD6_LISTENER_REPORT ICMP6_MEMBERSHIP_REPORT
#define MLD6_LISTENER_DONE ICMP6_MEMBERSHIP_REDUCTION
#define MLD6_MTRACE 		200
#define MLD6_MTRACE_RESP	201

int inet6_opt_init(void *extbuf, socklen_t extlen);
int
inet6_opt_append(void *extbuf, socklen_t extlen, int offset, u_int8_t type,
		                 socklen_t len, u_int8_t align, void **databufp);
int
inet6_opt_finish(void *extbuf, socklen_t extlen, int offset);
int
inet6_opt_set_val(void *databuf, int offset, void *val, socklen_t vallen);
int inet6_option_space(int nbytes);
/*
int inet6_option_init(void *bp, struct cmsghdr *cmsgp, int type);
*/
int inet6_option_append(struct cmsghdr *cmsg, const u_int8_t *typep, int multx, int plusy);
void ip6_get_lladdr(char *ifname, struct sockaddr_in6 *addr);

#define IN6ADDR_LINKLOCAL_ALLNODES_INIT \
	        {{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
static const struct in6_addr in6addr_linklocal_allnodes = IN6ADDR_LINKLOCAL_ALLNODES_INIT;
#define IP6OPT_RTALERT_MLD      0
#define IP6OPT_RTALERT          0x05
#ifndef IP6OPT_ROUTER_ALERT	/* XXX to be compatible older systems */
#define IP6OPT_ROUTER_ALERT IP6OPT_RTALERT
#define IP6OPT_RTALERT_LEN    4
#endif

#endif

/* mld.c */
extern void mld_init(void);
extern void mld_input (struct eth_if *, int, u_int8_t *, int);
extern void pim6_input (struct eth_if *, int, u_int8_t *, int);
extern int mld_join_routers_group(int ifindex, int join);
/* join/leave MLD group */
extern int mld_join_group(struct sockaddr_in6 *group, int ifindex, int join);


#endif
