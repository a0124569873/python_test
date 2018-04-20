/*
 * Copyright 2013 6WIND S.A.
 */

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

#ifndef __FPN_IN6_H__
#define __FPN_IN6_H__

#include "fpn-in.h"

/*
 * IPv6 address
 */
typedef struct fpn_in6_addr {
        union {
                uint8_t  u6_addr8[16];
                uint16_t u6_addr16[8];
                uint32_t u6_addr32[4];
        } in6_u;
#define fpn_s6_addr   in6_u.u6_addr8
#define fpn_s6_addr16 in6_u.u6_addr16
#define fpn_s6_addr32 in6_u.u6_addr32
} fpn_in6_addr_t;

/*
 * IPv6 address scopes
 */
#define FPN_IPV6_ADDR_SCOPE_NODELOCAL  0x01
#define FPN_IPV6_ADDR_SCOPE_LINKLOCAL  0x02
#define FPN_IPV6_ADDR_SCOPE_SITELOCAL  0x05
#define FPN_IPV6_ADDR_SCOPE_ORGLOCAL   0x08
#define FPN_IPV6_ADDR_SCOPE_GLOBAL     0x0e

/*
 * Return TRUE if IPv6 address is null.
 */
static inline int
is_fpn_in6_addr_null(const fpn_in6_addr_t *a) {
	return ((a->fpn_s6_addr32[0] == 0) && (a->fpn_s6_addr32[1] == 0) &&
		(a->fpn_s6_addr32[2] == 0) && (a->fpn_s6_addr32[3] == 0));
}

/*
 * Return TRUE if both IPv6 addresses are identical.
 */
static inline int
is_fpn_in6_addr_equal(const fpn_in6_addr_t *a1, const fpn_in6_addr_t *a2) {
	return ((a1->fpn_s6_addr32[0] == a2->fpn_s6_addr32[0]) &&
		(a1->fpn_s6_addr32[1] == a2->fpn_s6_addr32[1]) &&
		(a1->fpn_s6_addr32[2] == a2->fpn_s6_addr32[2]) &&
		(a1->fpn_s6_addr32[3] == a2->fpn_s6_addr32[3]));
}

/*
 * Unspecified
 */
#define FPN_IN6_IS_ADDR_UNSPECIFIED(a)				\
	((((a)->fpn_s6_addr32[0]) == 0) &&			\
	 (((a)->fpn_s6_addr32[1]) == 0) &&			\
	 (((a)->fpn_s6_addr32[2]) == 0) &&			\
	 (((a)->fpn_s6_addr32[3]) == 0))

/*
 * IPv6 loopback address.
 */
#define FPN_IN6_IS_ADDR_LOOPBACK(a)				\
	((((a)->fpn_s6_addr32[0]) == 0) &&			\
	 (((a)->fpn_s6_addr32[1]) == 0) &&			\
	 (((a)->fpn_s6_addr32[2]) == 0) &&			\
	 (((a)->fpn_s6_addr32[3]) == ntohl(1)))

/*
 * Is IPv6 address IPv4 compatible?
 */
#define FPN_IN6_IS_ADDR_V4COMPAT(a)				\
	((((a)->fpn_s6_addr32[0]) == 0) &&			\
	 (((a)->fpn_s6_addr32[1]) == 0) &&			\
	 (((a)->fpn_s6_addr32[2]) == 0) &&			\
	 (((a)->fpn_s6_addr32[3]) != 0) &&			\
	 (((a)->fpn_s6_addr32[3]) != ntohl(1)))

/*
 * Mapped
 */
#define FPN_IN6_IS_ADDR_V4MAPPED(a)				\
	((((a)->fpn_s6_addr32[0]) == 0) &&			\
	 (((a)->fpn_s6_addr32[1]) == 0) &&			\
	 (((a)->fpn_s6_addr32[2]) == ntohl(0x0000ffff)))

/*
 * Unicast Scope
 * Only topmost 10 bits must be checked, not 16 bits (see RFC2373).
 */
#define FPN_IN6_IS_ADDR_LINKLOCAL(a)	  \
	(((a)->fpn_s6_addr[0] == 0xfe) && \
	 (((a)->fpn_s6_addr[1] & 0xc0) == 0x80))

#define FPN_IN6_IS_ADDR_SITELOCAL(a)	  \
	(((a)->fpn_s6_addr[0] == 0xfe) && \
	 (((a)->fpn_s6_addr[1] & 0xc0) == 0xc0))

/*
 * Multicast
 */
#define FPN_IN6_IS_ADDR_MULTICAST(a)	((a)->fpn_s6_addr[0] == 0xff)

#define FPN_IN6_IS_ADDR_MC_SCOPE(a)	((a)->fpn_s6_addr[1] & 0x0f)

/*
 * Multicast Scope
 */
#define FPN_IN6_IS_ADDR_MC_NODELOCAL(a)     \
	(FPN_IN6_IS_ADDR_MULTICAST(a) &&    \
	(FPN_IN6_IS_ADDR_MC_SCOPE(a) == FPN_IPV6_ADDR_SCOPE_NODELOCAL))
#define FPN_IN6_IS_ADDR_MC_LINKLOCAL(a)     \
	(FPN_IN6_IS_ADDR_MULTICAST(a) &&    \
	(FPN_IN6_IS_ADDR_MC_SCOPE(a) == FPN_IPV6_ADDR_SCOPE_LINKLOCAL))
#define FPN_IN6_IS_ADDR_MC_SITELOCAL(a)     \
	(FPN_IN6_IS_ADDR_MULTICAST(a) &&    \
	(FPN_IN6_IS_ADDR_MC_SCOPE(a) == FPN_IPV6_ADDR_SCOPE_SITELOCAL))
#define FPN_IN6_IS_ADDR_MC_ORGLOCAL(a)      \
	(FPN_IN6_IS_ADDR_MULTICAST(a) &&    \
	(FPN_IN6_IS_ADDR_MC_SCOPE(a) == FPN_IPV6_ADDR_SCOPE_ORGLOCAL))
#define FPN_IN6_IS_ADDR_MC_GLOBAL(a)        \
	(FPN_IN6_IS_ADDR_MULTICAST(a) &&    \
	(FPN_IN6_IS_ADDR_MC_SCOPE(a) == FPN_IPV6_ADDR_SCOPE_GLOBAL))

/*
 * KAME Scope
 */
#define FPN_IN6_IS_SCOPE_LINKLOCAL(a)		\
	((FPN_IN6_IS_ADDR_LINKLOCAL(a)) ||	\
	 (FPN_IN6_IS_ADDR_MC_LINKLOCAL(a)))

#endif
