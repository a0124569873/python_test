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
 *      @(#)in.h        8.3 (Berkeley) 1/3/94
 */

/*
 * Copyright 2010-2013 6WIND S.A.
 */

#ifndef __VNB_IN6_H__
#define __VNB_IN6_H__

/* IPv6 address type */
#include <netgraph/vnb_in.h>
typedef struct vnb_in6_addr vnb_in6_addr_t;

/*
 *      Addr scopes
 */

#define VNB_IPV6_ADDR_MC_SCOPE(a)  \
	((a)->vnb_s6_addr[1] & 0x0f)            /* nonstandard */
#define __VNB_IPV6_ADDR_SCOPE_INVALID  -1

#define VNB_IPV6_ADDR_SCOPE_NODELOCAL  0x01
#define VNB_IPV6_ADDR_SCOPE_LINKLOCAL  0x02
#define VNB_IPV6_ADDR_SCOPE_SITELOCAL  0x05
#define VNB_IPV6_ADDR_SCOPE_ORGLOCAL   0x08
#define VNB_IPV6_ADDR_SCOPE_GLOBAL     0x0e


/* TRUE if the in6_addr_t gw is null */
static inline int is_in6_addr_null(vnb_in6_addr_t a) {
	return ((a.vnb_s6_addr32[0] == 0) && (a.vnb_s6_addr32[1] == 0) &&
			(a.vnb_s6_addr32[2] == 0) && (a.vnb_s6_addr32[3] == 0));
}

/* TRUE when addresses are the same */
static inline int is_in6_addr_equal(vnb_in6_addr_t a, vnb_in6_addr_t b) {
	return ((a.vnb_s6_addr32[0] == b.vnb_s6_addr32[0]) &&
			(a.vnb_s6_addr32[1] == b.vnb_s6_addr32[1]) &&
			(a.vnb_s6_addr32[2] == b.vnb_s6_addr32[2]) &&
			(a.vnb_s6_addr32[3] == b.vnb_s6_addr32[3]));
}

/*
 * Unspecified
 */
#define VNB_IN6_IS_ADDR_UNSPECIFIED(a)			\
	((((a)->vnb_s6_addr32[0]) == 0) &&			\
	 (((a)->vnb_s6_addr32[1]) == 0) &&			\
	 (((a)->vnb_s6_addr32[2]) == 0) &&			\
	 (((a)->vnb_s6_addr32[3]) == 0))

/*
 * Loopback
 */
#define VNB_IN6_IS_ADDR_LOOPBACK(a)			\
	((((a)->vnb_s6_addr32[0]) == 0) &&			\
	 (((a)->vnb_s6_addr32[1]) == 0) &&			\
	 (((a)->vnb_s6_addr32[2]) == 0) &&			\
	 (((a)->vnb_s6_addr32[3]) == ntohl(1)))

/*
 * IPv4 compatible
 */
#define VNB_IN6_IS_ADDR_V4COMPAT(a)			\
	((((a)->vnb_s6_addr32[0]) == 0) &&			\
	 (((a)->vnb_s6_addr32[1]) == 0) &&			\
	 (((a)->vnb_s6_addr32[2]) == 0) &&			\
	 (((a)->vnb_s6_addr32[3]) != 0) &&			\
	 (((a)->vnb_s6_addr32[3]) != ntohl(1)))

/*
 * Mapped
 */
#define VNB_IN6_IS_ADDR_V4MAPPED(a)			\
	((((a)->vnb_s6_addr32[0]) == 0) &&			\
	 (((a)->vnb_s6_addr32[1]) == 0) &&			\
	 (((a)->vnb_s6_addr32[2]) == ntohl(0x0000ffff)))

/*
 * Unicast Scope
 * Note that we must check topmost 10 bits only, not 16 bits (see RFC2373).
 */
#define VNB_IN6_IS_ADDR_LINKLOCAL(a)	\
	(((a)->vnb_s6_addr[0] == 0xfe) && (((a)->vnb_s6_addr[1] & 0xc0) == 0x80))
#define VNB_IN6_IS_ADDR_SITELOCAL(a)	\
	(((a)->vnb_s6_addr[0] == 0xfe) && (((a)->vnb_s6_addr[1] & 0xc0) == 0xc0))

/*
 * Multicast
 */
#define VNB_IN6_IS_ADDR_MULTICAST(a)	((a)->vnb_s6_addr[0] == 0xff)

#define VNB_IN6_IS_ADDR_MC_SCOPE(a)		((a)->vnb_s6_addr[1] & 0x0f)

/*
 * Multicast Scope
 */

#define VNB_IN6_IS_ADDR_MC_NODELOCAL(a)     \
	(VNB_IN6_IS_ADDR_MULTICAST(a) &&    \
	(VNB_IN6_IS_ADDR_MC_SCOPE(a) == VNB_IPV6_ADDR_SCOPE_NODELOCAL))
#define VNB_IN6_IS_ADDR_MC_LINKLOCAL(a)     \
	(VNB_IN6_IS_ADDR_MULTICAST(a) &&    \
	(VNB_IN6_IS_ADDR_MC_SCOPE(a) == VNB_IPV6_ADDR_SCOPE_LINKLOCAL))
#define VNB_IN6_IS_ADDR_MC_SITELOCAL(a)     \
	(VNB_IN6_IS_ADDR_MULTICAST(a) &&    \
	(VNB_IN6_IS_ADDR_MC_SCOPE(a) == VNB_IPV6_ADDR_SCOPE_SITELOCAL))
#define VNB_IN6_IS_ADDR_MC_ORGLOCAL(a)      \
	(VNB_IN6_IS_ADDR_MULTICAST(a) &&    \
	(VNB_IN6_IS_ADDR_MC_SCOPE(a) == VNB_IPV6_ADDR_SCOPE_ORGLOCAL))
#define VNB_IN6_IS_ADDR_MC_GLOBAL(a)        \
	(VNB_IN6_IS_ADDR_MULTICAST(a) &&    \
	(VNB_IN6_IS_ADDR_MC_SCOPE(a) == VNB_IPV6_ADDR_SCOPE_GLOBAL))


/*
 * KAME Scope
 */
#define VNB_IN6_IS_SCOPE_LINKLOCAL(a)	\
	((VNB_IN6_IS_ADDR_LINKLOCAL(a)) ||	\
	 (VNB_IN6_IS_ADDR_MC_LINKLOCAL(a)))


#endif /* __VNB_IN6_H__ */
