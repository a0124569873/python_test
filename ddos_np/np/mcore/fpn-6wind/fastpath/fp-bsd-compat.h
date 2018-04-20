/*
 * Copyright(c) 2011 6WIND, all rights reserved
 */

#ifndef _FP_BSD_COMPAT_H_
#define _FP_BSD_COMPAT_H_

/* for FPN_ASSERT() in KASSERT() below */
#include "fpn.h"
#include "netinet/fp-in.h"

#ifndef __P
#define __P(a) a
#endif
typedef int fp_register_t;
#ifndef SSIZE_MAX
#define SSIZE_MAX ((ssize_t)(((size_t)-1) >> 1))
#endif

/* for BSD callout_reset */
#define hz 1
#define khz 1000

/* already defined in newlib */
#if !defined(_BSDTYPES_DEFINED)
typedef unsigned int u_int;
typedef unsigned long u_long;
#endif

/* tell we don't have random: currently we won't support
 * http://www.ietf.org/rfc/rfc1948.txt  */
#define NRND 0

/* Macros for fp_min/fp_max.  */
#define FP_MIN(a, b)	(((a) < (b)) ? (a) : (b))
#define FP_MAX(a, b)	(((a) > (b)) ? (a) : (b))

/* from lib/libkern/fp_min.c */
static inline unsigned int
fp_min(unsigned int a, unsigned int b)
{
	return (a < b ? a : b);
}

/* from lib/libkern/fp_max.c */
static inline unsigned int
fp_max(unsigned int a, unsigned int b)
{
	return (a > b ? a : b);
}

/* from lib/libkern/fp_ulmin.c */
static inline unsigned long
fp_ulmin(unsigned long a, unsigned long b)
{
	return (a < b ? a : b);
}

/* from lib/libkern/fp_lmin.c */
static inline long
fp_lmin(long a, long b)
{
	return (a < b ? a : b);
}

/* from lib/libkern/fp_imax.c */
static inline int
fp_imax(int a, int b)
{
	return (a > b ? a : b);
}

/* panic may exist with a different signature */
#if defined(panic)
#undef panic
#endif
#define panic(fmt, args...) do {\
   fpn_printf("\nPANIC:" fmt "\n", ## args); \
   exit(1); \
} while (0)

#ifndef KASSERT
#define KASSERT(x)	FPN_ASSERT(x)
#endif
#define KDASSERT(x)	KASSERT(x)

#define	fp_roundup(x, y) ((((x)+((y)-1))/(y))*(y))

#define SB_MAX (256*1024)

#define	NTOHL(x)	(x) = ntohl((uint32_t)(x))
#define	NTOHS(x)	(x) = ntohs((uint16_t)(x))
#define	HTONL(x)	(x) = htonl((uint32_t)(x))
#define	HTONS(x)	(x) = htons((uint16_t)(x))

/* strl* functions exist in fp-mcee with newlib */
#if !defined(_NEWLIB_VERSION)
static inline size_t
strlcpy(char *dest, const char *src, size_t size)
{

	strncpy(dest, src, size-1);
	dest[size-1] = '\0';

	return strlen(dest);
}

size_t
strlcat(char *dst, const char *src, size_t siz);
#endif

char	*fp_intoa(uint32_t);
#define fp_inet_ntoa(a) fp_intoa((a).s_addr)
char * fp_ip6_sprintf(const struct fp_in6_addr *addr);

int ppsratecheck(uint64_t *lasttime, uint64_t min_interval);

#endif /* _FP_BSD_COMPAT_H_ */
