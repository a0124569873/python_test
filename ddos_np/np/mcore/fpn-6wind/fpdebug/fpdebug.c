/*
 * Copyright(c) 2007 6WIND
 */
#ifndef __FastPath__
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <getopt.h>
#ifdef CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY
#include <glob.h>
#include <dlfcn.h>
#endif
#endif
#include "fpn.h"

#include <ifuid.h>

#ifdef HAVE_LIBEDIT
#include <readline/readline.h>
#endif

#include "fp.h"
#include "fpn-port.h"
#include "fpdebug.h"
#include "fpdebug-ifnet.h"
#include "fpdebug-priv.h"
#ifdef CONFIG_MCORE_IP
#include "fp-lookup.h"
#endif
#include "net/fp-socket.h"
#include "netinet/fp-ip.h"
#include "netinet/fp-ip6.h"
#include "netinet/fp-tcp.h"
#include "netinet/fp-udp.h"
#include "netinet/fp-icmp.h"
#include "netinet/fp-icmp6.h"
#ifndef __FastPath__
#include "shmem/fpn-shmem.h"
#include "libfp_shm.h"
#endif
#include "fpn-cpu-usage.h"
#include "../fpm/rt_dump.h"
#include "fp-blade.h"
#if defined(CONFIG_MCORE_TAP_BPF) && !defined(__FastPath__)
#ifdef CONFIG_MCORE_FPDEBUG_DECODE_BPF
#include <pcap.h>
#endif
#include "fp-bpf.h"
#endif
#ifdef CONFIG_MCORE_TAP_CIRCULAR_BUFFER
#if (!defined(__FastPath__) && !defined(FP_STANDALONE)) || (defined(__FastPath__) && defined(FP_STANDALONE))
#include <pcap.h>
#include <net/if.h>
#include "fp-bpf.h"
#include "fp-var.h"
#include "shmem/fpn-shmem.h"
#include "fp-tap-capture.h"
#endif
#endif
#ifdef __FastPath__
#include "fpn-mempool.h"
#include "fp-test-fpn0.h"
#include "fp-probe.h"
#endif
#ifdef CONFIG_MCORE_L2SWITCH
#include "shmem/fpn-shmem.h"
#include "fp-l2switch.h"
#endif

#ifdef CONFIG_MCORE_VXLAN
#include "net/fp-ethernet.h" /* for FP_NMAC */
#endif

#ifdef CONFIG_MCORE_LAG
#include "fp-bonding-var.h"
#endif

#ifdef CONFIG_MCORE_KTABLES
#include "fpd-ktables.h"
#endif

#include "fp-autoconf-if.h"
#include "cli-cmd/fp-cli-commands.h"

#define FPDEBUG_XFRM_LIMIT(x) \
((x) == FP_SA_LIMIT_INF ? fpdebug_printf("INF") : fpdebug_printf("%"PRIu64, x))

/*
 * Helper to set/get flags in a bitmap (uint32_t table)
 */
#define __BMAP_CLR(b,n) (((b)[(n)/32] &= ~(1u<<((n)%32))))
#define __BMAP_SET(b,n) (((b)[(n)/32] |= (1u<<((n)%32))))
#define __BMAP_TST(b,n) (((b)[(n)/32] & (1u<<((n)%32)))!=0)

/*
 * Helper to set/get flags for up to 256 values
 * used to detect loops.
 */
uint32_t __BF [8];
#define __BF_NUL() memset (__BF, 0, sizeof(__BF))
#define __BF_CLR(x) __BMAP_CLR(__BF,x)
#define __BF_SET(x) __BMAP_SET(__BF,x)
#define __BF_TST(x) __BMAP_TST(__BF,x)

/*
 * Helper to calculate the index of an element in an array, from a pointer
 * within the element.
 *
 * e.g.:
 * - let: ptr = &array[5].field3
 * - then: ARRAY_INDEX(ptr, array) = 5
 */
#define ARRAY_INDEX(elt, array) (((void*)(elt)-(void*)(array))/sizeof(array[0]))

#define FP_LOADED    1
#define FPM_LOADED   2
#define FPCLI_LOADED 4

#ifdef CONFIG_MCORE_IPSEC
#include "fpn-crypto-algo.h"
#include "netipsec/fp-ah.h"
#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
static void display_sp_hashed_in(fp_sp_entry_t *sp);
static void display_sp_hashed_out(fp_sp_entry_t *sp);
static void display_sp_in(fp_sp_entry_t *sp);
static void display_sp_out(fp_sp_entry_t *sp);
#endif /* CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE */
#endif /* CONFIG_MCORE_IPSEC */

#ifdef CONFIG_MCORE_IP
static void print_rt_type(uint8_t rt_type);
#endif

#ifndef __FastPath__
shared_mem_t *fp_shared;
port_mem_t *fpn_port_shmem;
#else
FPN_DECLARE_SHARED(shared_mem_t *, fp_shared);
FPN_DECLARE_SHARED(port_mem_t *, fpn_port_shmem);
#endif
int f_colocalized = 1;

#define PRINT_FIB_HELPER fpdebug_printf ("# - Preferred, * - Active, > - selected\n")

char *chargv[FPDEBUG_MAX_ARGS];
static unsigned int interactive = 1;
#if !defined(__FastPath__) && defined(CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY)
/* only used when passing plugins at the moment */
static unsigned int verbose = 0;
#endif

char prompt[16];
uint16_t default_vrfid = 0;
char *cur_command; /* command beeing executed */

#ifndef __FastPath__
#include "netfpc.h"
int s_nfpc = -1;
#endif

#ifdef FP_STANDALONE
#include "net/fp-ethernet.h"
#include "fp-netfpc.h"
#endif

FPN_STAILQ_HEAD(fpdebug_ifnet_info_lst, fpdebug_ifnet_info);
static FPN_DEFINE_SHARED(struct fpdebug_ifnet_info_lst, fpdebug_ifnet_infos) =
	FPN_STAILQ_HEAD_INITIALIZER(fpdebug_ifnet_infos);

int fpdebug_add_ifnet_info(fpdebug_ifnet_info_t *ifnet_info)
{
	if (!ifnet_info)
		return -1;
	FPN_STAILQ_INSERT_TAIL(&fpdebug_ifnet_infos, ifnet_info, next);
	return 0;
}

static void fpdebug_prompt_reset(void)
{
	snprintf(prompt, sizeof(prompt), "<fp-%"PRIu16"> ", default_vrfid);
}

#ifdef CONFIG_MCORE_IP
static void print_addr(uint32_t *addr)
{
	uint8_t *nibble = (uint8_t *)addr;

	fpdebug_printf("%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8,
	       nibble[0], nibble[1], nibble[2], nibble[3]);
}
#endif

int gettokens(char *s)
{
	char *tok, *str1;
	char *saveptr = NULL;
	int i = 0;

	if (s == NULL)
		return -1;
	/* skip leading white spaces */
	str1 = s + strspn(s, " \t");
	for (;;) {
		/* read next token */
		tok = strtok_r(str1, " \t", &saveptr);

		if (tok == NULL) /* no more token */
			break;
		else if (i < FPDEBUG_MAX_ARGS)
			chargv[i++] = tok;
		else /* too many tokens */
		{
			fpdebug_printf("%s: too many arguments (max %u)\n",
				__func__, FPDEBUG_MAX_ARGS);
			return -1;
		}
		str1 = NULL;
	}
	
	return i;
}

/*
 * For inet_ntop() functions:
 *
 * Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */
#ifndef INADDRSZ
#define INADDRSZ 4
#endif
#ifndef IN6ADDRSZ
#define IN6ADDRSZ 16
#endif
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

static int inet_pton4(const char *src, void *dst);
static int inet_pton6(const char *src, void *dst);

/* int
 * inet_pton(af, src, dst)
 *      convert from presentation format (which usually means ASCII printable)
 *      to network format (which is usually some kind of binary format).
 * return:
 *      1 if the address was valid for the specified address family
 *      0 if the address wasn't valid (`dst' is untouched in this case)
 *      -1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *      Paul Vixie, 1996.
 */
int
fpdebug_inet_pton(int af, const char *src, void *dst)
{
	if (af == AF_INET)
		return inet_pton4(src, dst);
	else if (af == AF_INET6)
		return inet_pton6(src, dst);
	errno = EAFNOSUPPORT;
	return -1;
}

/* int
 * inet_pton4(src, dst)
 *      like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *      1 if `src' is a valid dotted quad, else 0.
 * notice:
 *      does not touch `dst' unless it's returning 1.
 * author:
 *      Paul Vixie, 1996.
 */
static int
inet_pton4(const char *src, void *dst)
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
	unsigned char tmp[INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr(digits, ch)) != NULL) {
			unsigned int new = *tp * 10 + (pch - digits);

			if (new > 255)
				return (0);
			if (! saw_digit) {
				if (++octets > 4)
					return (0);
				saw_digit = 1;
			}
			*tp = (unsigned char)new;
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
		} else
			return (0);
	}
	if (octets < 4)
		return (0);

	memcpy(dst, tmp, INADDRSZ);
	return (1);
}

/* int
 * inet_pton6(src, dst)
 *      convert presentation level address to network order binary form.
 * return:
 *      1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *      (1) does not touch `dst' unless it's returning 1.
 *      (2) :: in a full address is silently ignored.
 * credit:
 *      inspired by Mark Andrews.
 * author:
 *      Paul Vixie, 1996.
 */
static int
inet_pton6(const char *src, void *dst)
{
	static const char xdigits_l[] = "0123456789abcdef",
		xdigits_u[] = "0123456789ABCDEF";
	unsigned char tmp[IN6ADDRSZ], *tp, *endp, *colonp;
	const char *xdigits, *curtok;
	int ch, saw_xdigit, count_xdigit;
	unsigned int val;

	memset((tp = tmp), '\0', IN6ADDRSZ);
	endp = tp + IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = count_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			if (count_xdigit >= 4)
				return (0);
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			count_xdigit++;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			} else if (*src == '\0') {
				return (0);
			}
			if (tp + sizeof(int16_t) > endp)
				return (0);
			*tp++ = (unsigned char) ((val >> 8) & 0xff);
			*tp++ = (unsigned char) (val & 0xff);
			saw_xdigit = 0;
			count_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + INADDRSZ) <= endp) &&
		    inet_pton4(curtok, tp) > 0) {
			tp += INADDRSZ;
			saw_xdigit = 0;
			break;  /* '\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + sizeof(int16_t) > endp)
			return (0);
		*tp++ = (unsigned char) ((val >> 8) & 0xff);
		*tp++ = (unsigned char) (val & 0xff);
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	memcpy(dst, tmp, IN6ADDRSZ);
	return (1);
}

#ifndef INT16SZ
#define INT16SZ sizeof(int16_t)
#endif

static const char *inet_ntop4(const u_char *src, char *dst, size_t size);
static const char *inet_ntop6(const u_char *src, char *dst, size_t size);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
const char *
fpdebug_inet_ntop(int af, const void *src, char *dst, size_t size)
{
	switch (af) {
	case AF_INET:
		return (inet_ntop4(src, dst, size));
	case AF_INET6:
		return (inet_ntop6(src, dst, size));
	default:
		errno = EAFNOSUPPORT;
		return (NULL);
	}
	/* NOTREACHED */
}

/* const char *
 * inet_ntop4(src, dst, size)
 *	format an IPv4 address, more or less like inet_ntoa()
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a u_char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
inet_ntop4(const u_char *src, char *dst, size_t size)
{
	static const char fmt[] = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];
	int l;

	l = snprintf(tmp, size, fmt, src[0], src[1], src[2], src[3]);
	if (l <= 0 || l >= (int)size) {
		errno = ENOSPC;
		return (NULL);
	}
	strncpy(dst, tmp, size-1);
	dst[size-1] = '\0';
	return (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
inet_ntop6(const u_char *src, char *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	char *tp, *ep;
	struct { int base, len; } best, cur;
	u_int words[IN6ADDRSZ / INT16SZ];
	int i;
	int advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.len = 0;
	cur.len = 0;
	best.base = -1;
	cur.base = -1;
	for (i = 0; i < (int)(IN6ADDRSZ / INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + sizeof(tmp);
	for (i = 0; i < (int)(IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			if (i == best.base) {
				if (tp + 1 >= ep)
					return (NULL);
				*tp++ = ':';
			}
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0) {
			if (tp + 1 >= ep)
				return (NULL);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
			if (!inet_ntop4(src+12, tp, (size_t)(ep - tp)))
				return (NULL);
			tp += strlen(tp);
			break;
		}
		advance = snprintf(tp, ep - tp, "%x", words[i]);
		if (advance <= 0 || advance >= ep - tp)
			return (NULL);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ)) {
		if (tp + 1 >= ep)
			return (NULL);
		*tp++ = ':';
	}
	if (tp + 1 >= ep)
		return (NULL);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((size_t)(tp - tmp) > size) {
		errno = ENOSPC;
		return (NULL);
	}
	strncpy(dst, tmp, size-1);
	dst[size-1] = '\0';
	return (dst);
}

/*
 * print first bytes of an IPv4 address
 */
#ifdef CONFIG_MCORE_IP
static void
print_addr_bytes(uint32_t *addr, int bytes)
{
	uint8_t *nibble = (uint8_t *)addr;
	int i;

	fpdebug_printf("%"PRIu8, nibble[0]);
	for (i=1; i < bytes; i++)
		fpdebug_printf(".%"PRIu8, nibble[i]);
}

static uint32_t
string2address(const char *str)
{
	uint32_t address = 0;
	int a,b,c,d;

	if (sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
		uint8_t *ptr = (uint8_t *)&address;
		ptr[0] = a;
		ptr[1] = b;
		ptr[2] = c;
		ptr[3] = d;
	}
	/*return htonl(address);*/
	return address;
}
#endif

#ifdef CONFIG_MCORE_IPV6
static void
print_addr6(fp_in6_addr_t * addr)
{
	char buf[255];

	fpdebug_inet_ntop(AF_INET6, addr, buf, 255);
	fpdebug_printf("%s", buf);
}

static fp_in6_addr_t string2address6(const char *str)
{
	fp_in6_addr_t addr;
	int result;

	addr.fp_s6_addr32[0] = 0;
	addr.fp_s6_addr32[1] = 0;
	addr.fp_s6_addr32[2] = 0;
	addr.fp_s6_addr32[3] = 0;

	result = fpdebug_inet_pton(AF_INET6, (const char *)str, &addr);
	if(result <= 0)
		fpdebug_printf("Error - malformed address \n");
	fpdebug_printf("Address: ");
	print_addr6(&addr);
	fpdebug_printf("\n");
	return addr;
}
#endif /* CONFIG_MCORE_IPV6 */

int string2mac(const char *str, uint8_t *mac)
{
	int res = 0;
	int a,b,c,d,e,f;

	if (sscanf(str, "%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f) == 6) {
		mac[0] = a;
		mac[1] = b;
		mac[2] = c;
		mac[3] = d;
		mac[4] = e;
		mac[5] = f;
		res = 1;
	}
	return res;
}

static void print_ifuid(fp_ifnet_t *ifp)
{
	fpdebug_printf("ifuid=0x%"PRIx32" ", ntohl(ifp->if_ifuid));
	if (ifp->if_ifuid == 0)
		fpdebug_printf("(unknown)");
	else if (ifp->if_port == FP_IFNET_VIRTUAL_PORT)
		fpdebug_printf("(virtual)");
	else
		fpdebug_printf("(port %"PRIu8")", ifp->if_port);
}

static void
print_mac(const uint8_t *mac)
{
	int i;

	fpdebug_printf("%02"PRIx8, mac[0]);
	for (i=1; i<6; i++)
		fpdebug_printf(":%02"PRIx8, mac[i]);
}

#ifdef CONFIG_MCORE_IP
static void print_via_iface(uint32_t ifuid)
{
	fp_ifnet_t *ifp = fp_ifuid2ifnet(ifuid);

	fpdebug_printf("%s(0x%08x)", ifp ? ifp->if_name : "unknown", ntohl(ifuid));
}
#endif

static const struct iftype {
	int type;
	const char *name;
} iftype[] = {
	{ FP_IFTYPE_ETHER, "ether" },
	{ FP_IFTYPE_EIFACE, "eiface" },
	{ FP_IFTYPE_XVRF, "xvrf" },
	{ FP_IFTYPE_LOCAL, "local" },
	{ FP_IFTYPE_LOOP, "loop" },
	{ FP_IFTYPE_XIN4, "Xin4" },
	{ FP_IFTYPE_XIN6, "Xin6" },
#ifdef CONFIG_MCORE_IPSEC_SVTI
	{ FP_IFTYPE_SVTI, "svti" },
#endif
#ifdef CONFIG_MCORE_VXLAN
	{ FP_IFTYPE_VXLAN, "vxlan" },
#endif
#ifdef CONFIG_MCORE_VLAN
	{ FP_IFTYPE_VLAN, "vlan" },
#endif
	{ FP_IFTYPE_BRIDGE, "bridge" },
	{ FP_IFTYPE_BONDING, "bonding" },
	{ FP_IFTYPE_GRE, "gre" },
	{ FP_IFTYPE_GRETAP, "gretap" },
	{ FP_IFTYPE_MACVLAN, "macvlan" },
	{ FP_IFTYPE_VETH, "veth" },
	{ 0, NULL }
};

static const struct iftype *iftype_lookup(const char *name, int type)
{
	unsigned int i;

	if (name != NULL) {
		for (i = 0; (iftype[i].name != NULL); ++i)
			if (!strcasecmp(name, iftype[i].name))
				return &iftype[i];
		return NULL;
	}
	for (i = 0; (iftype[i].name != NULL); ++i)
		if (type == iftype[i].type)
			return &iftype[i];
	return NULL;
}

static void
print_iftype(int type)
{
	const struct iftype *pr_iftype = iftype_lookup(NULL, type);

	if (pr_iftype != NULL)
		fpdebug_printf("%s", pr_iftype->name);
	else
		fpdebug_printf("unknown(%d)", type);
}

static int __exit(char *tok __fpn_maybe_unused)
{
#ifndef __FastPath__
	if (s_nfpc >= 0)
		close(s_nfpc);
#endif
	exit(0);
}

static int dump_size(char *tok __fpn_maybe_unused)
{
	fpdebug_printf("Shared = %p\n", fp_shared);
	if (fp_shared)
		fpdebug_printf("Shared magic = 0x%"PRIx32"\n", fp_shared->conf.s.magic);
	print_size();
	return 0;
}

#ifdef __FastPath__
struct fpdebug_async_cmd {
	char *cmd;
	struct callout tim;
};

static void fpdebug_post_cmd_cb(void *arg)
{
	struct fpdebug_async_cmd *async_cmd = arg;

	fpdebug_run_command(async_cmd->cmd);
	callout_stop(&async_cmd->tim);
	fpn_free(async_cmd->cmd);
	fpn_free(async_cmd);
}

/* post a command to an online fast path core */
int fpdebug_post_cmd(const char *string, unsigned cpu)
{
	struct fpdebug_async_cmd *async_cmd;

	if (!fpn_cpumask_ismember(&fpn_coremask, cpu)) {
		fpdebug_printf("invalid cpu\n");
		return -1;
	}

	async_cmd = fpn_malloc(sizeof(*async_cmd), 0);
	if (async_cmd == NULL) {
		fpdebug_printf("cannot allocate memory\n");
		return -1;
	}

	memset(async_cmd, 0, sizeof(*async_cmd));
	async_cmd->cmd = fpn_malloc(strlen(string) + 1, 0);
	if (async_cmd->cmd == NULL) {
		free(async_cmd);
		fpdebug_printf("cannot allocate memory\n");
		return -1;
	}
	strcpy(async_cmd->cmd, string);
	callout_init(&async_cmd->tim);
	callout_bind(&async_cmd->tim, cpu);
	callout_reset_millisec(&async_cmd->tim, 0, fpdebug_post_cmd_cb, async_cmd);
	return 0;
}
#endif

#ifndef __FastPath__
/* when a command cannot be processed by the userland fpdebug, we can
 * send it to the embedded fpdebug (in fast path) */
static int
send_to_fastpath(char *cmd)
{
	struct netfpc_ack_msg ack_msg;
	int ret;
	ssize_t len;

	if (s_nfpc < 0) {
		fpdebug_fprintf(stderr, "Not connected to fast path\n");
		return -1;
	}

	ret = netfpc_send(s_nfpc, cmd, strlen(cmd) + 1, 0,
			  NETFPC_MSGTYPE_FPDEBUG);

	if (ret < 0)
		return ret;

	len = netfpc_recv(s_nfpc, &ack_msg, sizeof(ack_msg), MSG_NO_TIMEOUT, NULL);
	if (len < (ssize_t)sizeof(ack_msg)) {
		fpdebug_fprintf(stderr, "Error netfpc_recv\n");
		return -1;
	}

	return ntohl(ack_msg.error);
}

/* wrapper for all functions that need to be processed on the fp side */
int fpdebug_send_to_fp(__attribute__((unused)) char *tok)
{
	send_to_fastpath(cur_command);
	return 0;
}

/* called by the "fp" command */
static int fp_command(char *tok)
{
	return send_to_fastpath(tok);
}
#endif

#ifdef __FastPath__
/* called by the "on-cpu" command */
static int on_cpu_command(char *tok)
{
	unsigned long cpu;
	char *end;

	cpu = strtoul(tok, &end, 0);
	if (!fpn_cpumask_ismember(&fpn_coremask, cpu)) {
		fpdebug_printf("invalid cpu %lu\n", cpu);
		return -1;
	}

	return fpdebug_post_cmd(end, cpu);
}
#else
#define on_cpu_command fpdebug_send_to_fp
#endif

#ifdef CONFIG_MCORE_FPN_MBUF_TRACK

#include "fpn-mbuf-track.h"
#include "shmem/fpn-shmem.h"

static int dump_mtrack(char *tok)
{
	size_t i;
	size_t c;
	size_t max;
	const char *group = NULL;
	struct m_track *track = (struct m_track *)fpn_shmem_mmap("mtrack-shared",
								 NULL,
								 CONFIG_MCORE_MBUF_TRACK_SIZE);

	if (track == NULL) {
		fpdebug_printf("mtrack-shared not available\n");
		return 0;
	}

	if (gettokens(tok))
		group = chargv[0];
	max = (CONFIG_MCORE_MBUF_TRACK_SIZE / sizeof(struct m_track));
	puts("mbuf tracking information:");
	for (i = 0, c = 0; (i < max); ++i) {
		if ((track[i].file[0] == '\0') || (track[i].func[0] == '\0'))
			break;
		if ((group != NULL) && (strcmp(group, track[i].group)))
			continue;
		++c;
		fpdebug_printf("  [%s] mbuf %" PRIi32 "/%" PRIu64 ","
		       " seg %" PRIi32 "/%" PRIu64
		       " [%s:%" PRIi32 ": %s]\n",
		       track[i].group,
		       track[i].mbuf_tracked, track[i].mbuf_hits,
		       track[i].seg_tracked, track[i].seg_hits,
		       track[i].file, track[i].line, track[i].func);
	}
	fpdebug_printf("%lu tracking entries, %lu shown (max %lu)\n",
		(u_long)i, (u_long)c, (u_long)max);
	return 0;
}

#endif

static int dump_cpu_usage(char *tok __fpn_maybe_unused)
{
#ifdef __FastPath__
	fpdebug_printf("Not supported in embedded fpdebug\n");
	return 0;
#else
	uint64_t sum_cycles = 0;
	uint64_t sum_fwd = 0;
	uint32_t delay = 200000; /* wait delay in us. by default 200ms */
	int argcount = gettokens(tok);
	int i;
	cpu_usage_shared_mem_t *cpu_usage_shared = fpn_shmem_mmap("cpu-usage-shared",
								  NULL,
								  sizeof(cpu_usage_shared_mem_t));

	if (cpu_usage_shared == NULL) {
		fpdebug_printf("can't map cpu-usage-shared\n");
		return -1;
	}

	if (argcount > 0)
		delay = strtoul(chargv[0], NULL, 0);

	/* Make sure to re-initialize the state */
	cpu_usage_shared->do_cpu_usage = 0;
	usleep(delay);
	for (i=0; i<FPN_MAX_CORES; i++)
		cpu_usage_shared->busy_cycles[i].end = 0;

	/* Enable dump-cpu-usage all cores main loop */
	cpu_usage_shared->do_cpu_usage = 1;
	/* get initial global IPv4 and IPv6 forwarding statistics at t1 */
	for (i=0; i<FP_IP_STATS_NUM; i++) {
		sum_fwd -= fp_shared->ip_stats[i].IpForwDatagrams;
#ifdef CONFIG_MCORE_IPV6
		sum_fwd -= fp_shared->ip6_stats[i].IpForwDatagrams;
#endif
	}

	usleep(delay);

	/* Disable dump-cpu-usage all cores main loop */
	cpu_usage_shared->do_cpu_usage = 0;

	/* get the delta of global IPv4 and IPv6 forwarding statistics */
	for (i=0; i<FP_IP_STATS_NUM; i++) {
		sum_fwd += fp_shared->ip_stats[i].IpForwDatagrams;
#ifdef CONFIG_MCORE_IPV6
		sum_fwd += fp_shared->ip6_stats[i].IpForwDatagrams;
#endif
	}
	/* Make sure all cores have finished */
	usleep(delay);

#ifdef CONFIG_MCORE_DEBUG_CPU_USAGE
	fpdebug_printf("Fast path CPU usage:\n");
#else
	fpdebug_printf("Fast path CPU usage (Warning, CONFIG_MCORE_DEBUG_CPU_USAGE disabled):\n");
#endif

	fpdebug_printf("cpu: %%busy     cycles\n");

	/* display cpu usage percentage cpu usage */
	for (i=0; i<FPN_MAX_CORES; i++) {
		uint64_t busy, cycles;
		int64_t delta;

		/* Skip vcpu that did not participate */
		if (cpu_usage_shared->busy_cycles[i].end == 0)
			continue;
		/* CPU number */
		fpdebug_printf ("%3d:", i);

		delta = cpu_usage_shared->busy_cycles[i].end - cpu_usage_shared->busy_cycles[i].begin;
		if (delta <= 0) {
			fpdebug_printf(" n/a - delta is not positive\n");
			continue;
		}

		cycles = cpu_usage_shared->busy_cycles[i].val;
		/* % busy time */
		busy = (cycles * 100) / delta;
		if ((busy == 0) && cycles)
			fpdebug_printf("   <1%%"); /* display at least 1% if the CPU was used */
		else
			fpdebug_printf(" %4"PRIu64"%%", busy);

		/* cycles */
		fpdebug_printf(" %10"PRIu64"\n", cycles);

		sum_cycles += cycles;
	}

	fpdebug_printf("average cycles/IPv4 and IPv6 forwarded packet: ");
	if (sum_fwd)
		fpdebug_printf("%"PRIu64" ", sum_cycles / sum_fwd);
	else
		fpdebug_printf("--- ");
	fpdebug_printf("(%"PRIu64"/%"PRIu64")\n", sum_cycles, sum_fwd);

	return 0;
#endif
}

enum {
	LEVEL_SUMMARY = 0, /* display hash table summary */
	LEVEL_COUNT = 1,   /* for each hash line, display count of entries */
	LEVEL_INDEX = 2,   /* for each hash line, display index of entries in main table */
	LEVEL_ID = 3,      /* for each hash line, display id of entries */
	LEVEL_ALL = 4      /* for each hash line, fully display all entries */
};

/*
 * generic macro to dump a hash table
 *
 * htable: hash table (contains indexes)
 * table: main table (contains entries themselves)
 * node: entries chaining field
 * dump_id: optional function to dump the entry id when level is LEVEL_INDEX
 * dump_entry: function to dump the entry itself when level is LEVEL_ALL
 * level: dump level
 */
#define DUMP_HASH_TABLE(htable, table, node, dump_id, dump_entry, level) \
do { \
	size_t __hash_size = (sizeof(htable) / sizeof((htable)[0])); \
	unsigned __hash;     /* hash key */ \
	unsigned __idx;      /* entry index */ \
	unsigned __count;    /* sum of of each hash line entry count */ \
	unsigned __countsq;  /* sum of squares of each hash line entry count */ \
	unsigned __countl;   /* entry count on current hash line */ \
	unsigned __countmin; /* minimum entry count for a hash key */ \
	unsigned __countmax; /* maximum entry count for a hash key */ \
	uint64_t __average;  /* average entry count for a hash key */ \
	uint64_t __variance; /* variance of entry count for a hash key */ \
 \
	int __display_summary = 0; \
 \
	 /* reminder: if the average of values X is noted E[X],         */ \
	 /* variance = E[X**2] - (E[X])**2                              */ \
	 /* A small variance means that entries are well distributed in */ \
	 /* the hash table.                                             */ \
 \
	__count = __countsq = __countmax = 0; \
	__countmin = (unsigned)-1; \
 \
	for (__hash = 0; __hash < __hash_size; __hash++) { \
		__countl = 0; \
		if (fp_hlist_first(&(htable)[__hash]) != 0) { \
			switch (level) { \
			/* display entry count for each line */ \
			case LEVEL_COUNT: \
				fp_hlist_for_each(__idx, &(htable)[__hash], \
						(table), node) { \
					__countl++; \
				} \
				fpdebug_printf("--hash key %u: %u entries\n", __hash, __countl); \
				break; \
			/* list all entry indexes for each line */ \
			case LEVEL_INDEX: \
				fpdebug_printf("--hash key %u:", __hash); \
				fp_hlist_for_each(__idx, &(htable)[__hash], \
						(table), node) { \
					fpdebug_printf(" %u", __idx); \
					__countl++; \
				} \
				fpdebug_printf("\n"); \
				break; \
				/* list all entry ids for each line */ \
			case LEVEL_ID: \
				fpdebug_printf("--hash key %u:", __hash); \
				fp_hlist_for_each(__idx, &(htable)[__hash], \
						(table), node) { \
					putchar(' '); \
					(dump_id)(&(table)[__idx]); \
					__countl++; \
				} \
				fpdebug_printf("\n"); \
				break; \
			/* display all entries indexes for each line */ \
			case LEVEL_ALL: \
				fpdebug_printf("-- hash key %u:\n", __hash); \
				fp_hlist_for_each(__idx, &(htable)[__hash], \
						(table), node) { \
					fpdebug_printf("%u: ", __idx); \
					(dump_entry)(&(table)[__idx]); \
					__countl++; \
				} \
				break; \
			/* only count entries for each line */ \
			default: \
				 __display_summary = 1; \
				fp_hlist_for_each(__idx, &(htable)[__hash], \
						(table), node) { \
					__countl++; \
				} \
			} \
 \
			if (__countl > __countmax) \
				__countmax = __countl; \
		} \
		__count += __countl; \
		__countsq += __countl * __countl; \
		if (__countmin == 0 || __countl < __countmin) \
			__countmin = __countl; \
	} \
 \
	if (__display_summary) { \
		fpdebug_printf("hash table:\n"); \
		fpdebug_printf("   total lines: %lu\n", (u_long)__hash_size); \
		fpdebug_printf("   total entries: %u\n", __count); \
		fpdebug_printf("entries per line:\n"); \
		__average = (__count * 100) / __hash_size; \
		__variance = (__countsq * 100) / __hash_size - \
		(__average/10)*(__average/10); \
		fpdebug_printf("   average: %"PRIu64".%02u variance %"PRIu64".%02u\n", \
				__average/100, (unsigned)__average%100, \
				__variance/100, (unsigned)__variance%100); \
		fpdebug_printf("   minimum: %u\n", __countmin); \
		fpdebug_printf("   maximum: %u\n", __countmax); \
	} \
} while(0)

#define DUMP_HASH_OPTS "[count|index|id|all]"

static inline int dump_hash_level(char *tok)
{
	int level = LEVEL_SUMMARY;

	if (gettokens(tok) > 0) {
		const char *arg = chargv[0];
		if (!strcmp(arg, "count"))
			level = LEVEL_COUNT;
		else if (!strcmp(arg, "id"))
			level = LEVEL_ID;
		else if (!strcmp(arg, "index"))
			level = LEVEL_INDEX;
		else if (!strcmp(arg, "all"))
			level = LEVEL_ALL;
	}

	return level;
}

static void display_ifnet(fp_ifnet_t *ifp);

static inline void display_ifnet_ifname(fp_ifnet_t *ifp)
{
	fpdebug_printf("%s", ifp->if_name);
}
static int dump_interfaces_ifname_hash(char *tok)
{
	int level = dump_hash_level(tok);

	fpdebug_printf("ifname hash table:\n");
	DUMP_HASH_TABLE(fp_shared->ifnet.name_hash, fp_shared->ifnet.table,
			name_hlist, display_ifnet_ifname, display_ifnet,
			level);
	
	return 0;
}

static inline void display_ifnet_ifuid(fp_ifnet_t *ifp)
{
	fpdebug_printf("0x%0x08", ntohl(ifp->if_ifuid));
}
static int dump_interfaces_ifuid_hash(char *tok)
{
	int level = dump_hash_level(tok);

	fpdebug_printf("ifuid hash table:\n");
	DUMP_HASH_TABLE(fp_shared->ifnet.hash, fp_shared->ifnet.table,
			ifuid_hlist, display_ifnet_ifuid, display_ifnet,
			level);

	return 0;
}

static int add_interface(char *tok)
{
	int numtokens = gettokens(tok);
	char		*name;		/* Interface name */
	int		port;		/* Hardware port */
	uint32_t	ifuid;		/* Interface UID */
	uint8_t		mac[6];		/* Interface MAC address */

	if (numtokens != 3 && numtokens != 4) {
		fpdebug_fprintf(stderr, "wrong arguments: "
				"add-interface <name> <port> <mac> [ifindex]\n");
		return -1;
	}

	name = chargv[0];
	port = atoi(chargv[1]);
	if (string2mac(chargv[2], mac) == 0) {
		fpdebug_fprintf(stderr, "invalid mac address\n");
		return 0;
	}
	if (numtokens == 4)
		ifuid = atoi(chargv[3]);
	else {
		for (ifuid = 1; ifuid < FP_MAX_IFNET; ifuid++)
			if (fp_ifuid2ifnet(ifuid) == NULL)
				break;
		if (ifuid == FP_MAX_IFNET) {
			fpdebug_fprintf (stderr, "no ifuid available\n");
			return -1;
		}
	}

	fp_addifnet(0, name, mac, 1500, ifuid, port, FP_IFTYPE_ETHER);
	fp_setifnet_flags(ifuid, IFF_CP_UP|IFF_CP_RUNNING|IFF_CP_IPV4_FWD);
	display_ifnet(fp_ifuid2ifnet(ifuid));

	return 0;
}

static int del_interface(char *tok)
{
	fp_ifnet_t *ifp;
	uint32_t ifuid;

	if (gettokens(tok) != 1) {
		fpdebug_printf("wrong arguments: del-interface <ifname>\n");
		return -1;
	}
	ifp = fp_getifnetbyname(chargv[0]);
	if (ifp == NULL) {
		fpdebug_fprintf(stderr, "unknown interface %s\n", chargv[0]);
		return -1;
	}
	ifuid = ifp->if_ifuid;
	return fp_delifnet(ifuid);
}

static int set_if_mtu(char *tok)
{
	uint16_t mtu;
	fp_ifnet_t *ifp;

	if (gettokens(tok) != 2) {
		fpdebug_fprintf(stderr, "wrong arguments: set-if-mtu <if_name> <mtu>\n");
		return -1;
	}

	mtu = (uint16_t)strtoul(chargv[1], NULL, 0);
	ifp = fp_getifnetbyname(chargv[0]);

	if (ifp == NULL) {
		fpdebug_fprintf(stderr, "Cannot find interface %s\n", chargv[0]);
		return -1;
	}

	fp_setifnet_mtu(ifp->if_ifuid, mtu);

	return 0;
}

static int set_if_type(char *tok)
{
	fp_ifnet_t *ifp;
	const struct iftype *set_iftype;

	if (gettokens(tok) != 2) {
		fpdebug_fprintf(stderr,
				"wrong arguments: set-if-type <if_name>"
				" <type>\n");
		return -1;
	}
	if (((set_iftype = iftype_lookup(chargv[1], 0)) == NULL) &&
	    ((set_iftype = iftype_lookup(NULL, atoi(chargv[1]))) == NULL)) {
		fpdebug_fprintf(stderr,
				"Unknown interface type \"%s\"\n",
				chargv[1]);
		return -1;
	}
	if ((ifp = fp_getifnetbyname(chargv[0])) == NULL) {
		fpdebug_fprintf(stderr,
				"Cannot find interface \"%s\"\n",
				chargv[0]);
		return -1;
	}
	ifp->if_type = set_iftype->type;
	return 0;
}

#ifdef CONFIG_MCORE_IP
static int add_address4(char *tok)
{
	fp_ifnet_t *ifp;
	int numtokens = gettokens(tok);
	char		*ifname;	/* Interface name */
	uint32_t	ip_addr;	/* IP address */
	int		prefix;		/* Network prefix length */
	uint32_t ifuid;
	int res;

	if (numtokens != 3) {
		fpdebug_fprintf (stderr, "wrong arguments: "
				 "add-address4 <ifname> <ipv4> <prefix>\n");
		return -1;
	}

	ifname = chargv[0];
	ifp = fp_getifnetbyname(ifname);
	if (ifp == NULL) {
		fpdebug_fprintf(stderr, "unknown interface %s\n", chargv[0]);
		return -1;
	}
	ifuid = ifp->if_ifuid;

	res = fpdebug_inet_pton(AF_INET, (const char*)chargv[1], &ip_addr);
	if (res <= 0) {
		fpdebug_fprintf (stderr, "bad IPv4 address\n");
		/* bad IPv4 address */
		return -1;
	}
	prefix = atoi(chargv[2]);

	if (ip_addr == 0) {
		fpdebug_fprintf (stderr, "No IPv4 address\n");
		return -1;
	}

	fp_add_address4(ip_addr, ifuid);
	if (prefix != 32) {
		uint16_t vrfid = (ifuid2vrfid(ifuid) &
				  FP_VRFID_MASK);

		fp_add_route4(vrfid, ip_addr, prefix, ip_addr, ifuid,
			      RT_TYPE_ROUTE_CONNECTED);
	}

	return 0;
}

static int del_address4(char *tok)
{
	fp_ifnet_t *ifp;
	int numtokens = gettokens(tok);
	char		*ifname;	/* Interface name */
	uint32_t	ip_addr;	/* IP address */
	int		prefix;		/* Network prefix length */
	uint32_t ifuid;
	int res;

	if (numtokens != 3) {
		fpdebug_fprintf (stderr, "wrong arguments: "
				 "del-address4 <ifname> <ipv4> <prefix>\n");
		return -1;
	}

	ifname = chargv[0];
	ifp = fp_getifnetbyname(ifname);
	if (ifp == NULL) {
		fpdebug_fprintf(stderr, "unknown interface %s\n", chargv[0]);
		return -1;
	}
	ifuid = ifp->if_ifuid;

	res = fpdebug_inet_pton(AF_INET, (const char*)chargv[1], &ip_addr);
	if (res <= 0) {
		fpdebug_fprintf (stderr, "bad IPv4 address\n");
		/* bad IPv4 address */
		return -1;
	}
	prefix = atoi(chargv[2]);

	if (ip_addr == 0) {
		fpdebug_fprintf (stderr, "No IPv4 address\n");
		return -1;
	}

	if (prefix != 32) {
		uint16_t vrfid = (ifuid2vrfid(ifuid) &
				  FP_VRFID_MASK);

		fp_delete_route4_nhmark(vrfid, ip_addr, prefix, ip_addr, ifuid,
					RT_TYPE_ROUTE_CONNECTED, NULL);
	}
	fp_delete_address4(ip_addr, ifuid);

	return 0;
}

static int dump_address4(char *tok)
{
	fp_ifnet_t *ifp;
	int numtokens = gettokens(tok);
	char	   *ifname;      /* Interface name */
	uint32_t    index;
	struct fp_pool_addr4 *pool4 = &(fp_shared->fp_empty_pool_addr4);

	if (numtokens != 1) {
		fpdebug_fprintf(stderr, "wrong arguments: "
				"dump-address4 <ifname> \n");
		return -1;
	}

	ifname = chargv[0];

	ifp = fp_getifnetbyname(ifname);
	if (ifp == NULL) {
		fpdebug_fprintf(stderr, "unknown interface %s\n", chargv[0]);
		return -1;
	}

	fpdebug_printf("number of ip address: %d\n", ifp->if_nb_addr4);

	index = ifp->if_addr4_head_index;
	while (index < FP_MAX_NB_ADDR4) {
		fpdebug_printf(FP_NIPQUAD_FMT" [%d]\n",
			       FP_NIPQUAD(pool4->table_addr4[index].addr),
			       index);
		index = pool4->table_addr4[index].next;
	}

	return 0;
}
#endif /* CONFIG_MCORE_IP */


#ifdef CONFIG_MCORE_IPV6
static int add_address6(char *tok)
{
	fp_ifnet_t *ifp;
	char	   *ifname;      /* Interface name */
	fp_in6_addr_t ipv6_addr; /* IPv6 address */
	int           prefix;    /* Network prefix length */
	uint32_t      ifuid;
	int res;

	if (gettokens(tok) != 3) {
		fpdebug_fprintf (stderr, "wrong arguments: "
				 "add-address6 <ifname> <ipv6> <prefix>\n");
		return -1;
	}

	ifname = chargv[0];
	ifp = fp_getifnetbyname(ifname);
	if (ifp == NULL) {
		fpdebug_fprintf(stderr, "unknown interface %s\n", chargv[0]);
		return -1;
	}
	ifuid = ifp->if_ifuid;
	res = fpdebug_inet_pton(AF_INET6, (const char*)chargv[1], &ipv6_addr);
	if (res <= 0) {
		fpdebug_fprintf (stderr, "bad IPv6 address: %s\n", chargv[1]);
		return -1;
	}
	prefix = atoi(chargv[2]);

	if (is_in6_addr_null(ipv6_addr)) {
		fpdebug_fprintf (stderr, "No IPv6 address\n");
		return -1;
	}

	fp_add_address6(&ipv6_addr, ifuid);
	if (prefix != 128) {
		uint16_t vrfid = (ifuid2vrfid(ifuid) &
				  FP_VRFID_MASK);

		fp_add_route6_nhmark(vrfid, &ipv6_addr, prefix, &ipv6_addr,
				     ifuid, RT_TYPE_ROUTE_CONNECTED, NULL);
	}

	return 0;
}

static int del_address6(char *tok)
{
	fp_ifnet_t *ifp;
	char       *ifname;      /* Interface name */
	fp_in6_addr_t ipv6_addr; /* IPv6 address */
	int           prefix;    /* Network prefix length */
	uint32_t      ifuid;
	int res;

	if (gettokens(tok) != 3) {
		fpdebug_fprintf (stderr, "wrong arguments: "
				 "del-address6 <ifname> <ipv6> <prefix>\n");
		return -1;
	}

	ifname = chargv[0];
	ifp = fp_getifnetbyname(ifname);
	if (ifp == NULL) {
		fpdebug_fprintf(stderr, "unknown interface %s\n", chargv[0]);
		return -1;
	}
	ifuid = ifp->if_ifuid;
	res = fpdebug_inet_pton(AF_INET6, (const char*)chargv[1], &ipv6_addr);
	if (res <= 0) {
		fpdebug_fprintf (stderr, "bad IPv6 address: %s\n", chargv[1]);
		return -1;
	}
	prefix = atoi(chargv[2]);

	if (is_in6_addr_null(ipv6_addr)) {
		fpdebug_fprintf (stderr, "No IPv6 address\n");
		return -1;
	}

	if (prefix != 128) {
		uint16_t vrfid = (ifuid2vrfid(ifuid) &
				  FP_VRFID_MASK);

		fp_delete_route6_nhmark(vrfid, &ipv6_addr, prefix, &ipv6_addr,
					ifuid, RT_TYPE_ROUTE_CONNECTED, NULL);
	}
	fp_delete_address6(&ipv6_addr, ifuid);

	return 0;
}

static int dump_address6(char *tok)
{
	fp_ifnet_t *ifp;
	int numtokens = gettokens(tok);
	char	   *ifname;      /* Interface name */
	uint32_t    index;
	struct fp_pool_addr6 *pool6 = &(fp_shared->fp_empty_pool_addr6);

	if (numtokens != 1) {
		fpdebug_fprintf(stderr, "wrong arguments: "
				"dump-address6 <ifname> \n");
		return -1;
	}

	ifname = chargv[0];

	ifp = fp_getifnetbyname(ifname);
	if (ifp == NULL) {
		fpdebug_fprintf(stderr, "unknown interface %s\n", chargv[0]);
		return -1;
	}

	fpdebug_printf("number of ip address: %d\n", ifp->if_nb_addr6);

	index = ifp->if_addr6_head_index;
	while (index < FP_MAX_NB_ADDR6) {
		fpdebug_printf(FP_NIP6_FMT" [%d]\n",
			       FP_NIP6(pool6->table_addr6[index].addr6),
			       index);
		index = pool6->table_addr6[index].next;
	}

	return 0;
}

#endif /* CONFIG_MCORE_IPV6 */

#define DISPLAY_FLAG(disp, count) do { \
	if ((count)++) \
		fpdebug_printf("|"); \
	fpdebug_printf(disp); \
} while (0)

static void display_ifnet_tunnel(fp_ifnet_t *ifp);
static void display_ifnet_svti(fp_ifnet_t *ifp);
static void display_ifnet_vxlan(fp_ifnet_t *ifp);
static void display_ifnet_veth(fp_ifnet_t *ifp);

static void display_ifnet(fp_ifnet_t *ifp)
{
	fpdebug_ifnet_info_t * ifnet_info;

	fpdebug_printf("%s", ifp->if_name);

#ifdef CONFIG_MCORE_VRF
	fpdebug_printf(" [VR-%"PRIu16"]", ifp->if_vrfid);
#endif
	fpdebug_printf(" ");
	print_ifuid(ifp);

	/* flags */
	fpdebug_printf (" <");
	{
		int count = 0;

		if (ifp->if_flags & IFF_CP_UP)
			DISPLAY_FLAG("UP", count);
		if (ifp->if_flags & IFF_CP_RUNNING)
			DISPLAY_FLAG("RUNNING", count);
		if (ifp->if_flags & IFF_CP_PROMISC)
			DISPLAY_FLAG("PROMISC", count);
		if (ifp->if_flags & IFF_CP_IPV4_FWD)
			DISPLAY_FLAG("FWD4", count);
		if (ifp->if_flags & IFF_CP_IPV6_FWD)
			DISPLAY_FLAG("FWD6", count);
		if (ifp->if_flags & IFF_FP_PREF)
			DISPLAY_FLAG("PREF", count);
		if (ifp->if_flags & IFF_FP_IVRRP)
			DISPLAY_FLAG("IVRRP", count);
		if (ifp->if_flags & IFF_FP_IPV4_FORCE_REASS)
			DISPLAY_FLAG("REASS4", count);
		if (ifp->if_flags & IFF_FP_IPV6_FORCE_REASS)
			DISPLAY_FLAG("REASS6", count);
		if (ifp->if_flags & (IFF_CP_IPV4_RPF|IFF_FP_IPV4_RPF))
			DISPLAY_FLAG("RPF4", count);
		if (ifp->if_flags & IFF_FP_IPV6_RPF)
			DISPLAY_FLAG("RPF6", count);
		if (ifp->if_flags & IFF_FP_LOCAL_OUT)
			DISPLAY_FLAG("LOCAL_OUT", count);
	}
	fpdebug_printf(">");

	fpdebug_printf (" (0x%"PRIx16")", ifp->if_flags);

	fpdebug_printf("\n\ttype=");
	print_iftype(ifp->if_type);

	fpdebug_printf(" mac=");
	print_mac((uint8_t *)&ifp->if_mac);

	fpdebug_printf(" mtu=%"PRIu16"", ifp->if_mtu);

#ifdef CONFIG_MCORE_TCP_MSS
	fpdebug_printf(" tcp4mss=%"PRIu32"", ifp->if_tcp4mss);
	fpdebug_printf(" tcp6mss=%"PRIu32"", ifp->if_tcp6mss);
#endif

	if (ifp->if_master_ifuid != 0)
		fpdebug_printf(" master=%s", fp_ifuid2str(ifp->if_master_ifuid));

	if (ifp->if_blade) {
		if (ifp->if_flags & IFF_FP_LOCAL_OUT)
			fpdebug_printf("\n\t(blade=%"PRIu8")", ifp->if_blade);
		else
			fpdebug_printf("\n\tblade=%"PRIu8, ifp->if_blade);
	}

	switch (ifp->if_type) {
	case FP_IFTYPE_XIN4:
	case FP_IFTYPE_XIN6:
		display_ifnet_tunnel(ifp);
		break;
	case FP_IFTYPE_SVTI:
		display_ifnet_svti(ifp);
		break;
	case FP_IFTYPE_VXLAN:
		display_ifnet_vxlan(ifp);
		break;
	case FP_IFTYPE_VETH:
		display_ifnet_veth(ifp);
		break;
	}

	fpdebug_printf("\n\t");
	fpdebug_printf("IPv4 routes=%"PRIu32"", ifp->if_nb_rt4);
	fpdebug_printf("  IPv6 routes=%"PRIu32"", ifp->if_nb_rt6);
	fpdebug_printf("\n");

	FPN_STAILQ_FOREACH(ifnet_info, &fpdebug_ifnet_infos, next) {
		if (ifnet_info->func)
			ifnet_info->func(ifp);
	}
}

static void display_ifnet_tunnel(fp_ifnet_t *ifp __fpn_maybe_unused)
{
#if defined(CONFIG_MCORE_XIN4) || defined(CONFIG_MCORE_XIN6)
	fp_tunnel_entry_t *tun = &fp_shared->fp_tunnels.table[ifp->sub_table_index];
#endif
#ifdef CONFIG_MCORE_XIN4
	if (tun->ifuid && tun->proto == FP_IPPROTO_IP) {
		fpdebug_printf(" link-vrfid=%"PRIu16"", tun->linkvrfid);
		fpdebug_printf("\n\tXin4(6to4) tunnel ttl=%"PRIu8" local=", tun->p.xin4.ip_ttl);
		print_addr(&tun->p.xin4.ip_src.s_addr);
		fpdebug_printf(" remote=");
		print_addr(&tun->p.xin4.ip_dst.s_addr);
	}
#endif
#ifdef CONFIG_MCORE_XIN6
	if (tun->ifuid && tun->proto == FP_IPPROTO_IPV6) {
		fpdebug_printf(" link-vrfid=%"PRIu16"", tun->linkvrfid);
		fpdebug_printf("\n\tXin6 tunnel hlim=%"PRIu8" local=", tun->p.xin6.ip6_hlim);
		print_addr6(&tun->p.xin6.ip6_src);
		fpdebug_printf(" remote=");
		print_addr6(&tun->p.xin6.ip6_dst);
	}
#endif
}

static void display_ifnet_svti(fp_ifnet_t *ifp __fpn_maybe_unused)
{
#if defined(CONFIG_MCORE_IPSEC_SVTI) && defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
	fp_svti_t *svti = &fp_shared->svti[ifp->sub_table_index];

	fpdebug_printf(" link-vrfid=%"PRIu16"", svti->link_vrfid);
	fpdebug_printf("\n\tSVTI tunnel local=");
	print_addr(&svti->laddr);
	fpdebug_printf(" remote=");
	print_addr(&svti->raddr);
#endif
}

static void display_ifnet_vxlan(fp_ifnet_t *ifp __fpn_maybe_unused)
{
#ifdef CONFIG_MCORE_VXLAN
	fp_vxlan_iface_t *vxiface = &fp_shared->vxlan_iface[ifp->sub_table_index];

	fpdebug_printf("\n\tvni=%"PRIu32" dstport=%"PRIu16 , vxiface->vni,
		       ntohs(vxiface->dstport));
	if (vxiface->ttl)
		fpdebug_printf(" ttl=%"PRIu8, vxiface->ttl);
	if (vxiface->tos == 1)
		fpdebug_printf(" tos inherit");
	else if (vxiface->tos)
		fpdebug_printf(" tos=0x%"PRIx8, vxiface->tos);
#endif
}

static void display_ifnet_veth(fp_ifnet_t *ifp)
{
	fp_ifnet_t *peer_ifp;

	fpdebug_printf("\n\tveth peer: ");
	if (ifp->sub_table_index == 0) {
		fpdebug_printf("not set");
		return;
	}

	peer_ifp = fp_ifuid2ifnet(ifp->sub_table_index);
	if (peer_ifp == NULL) {
		fpdebug_printf("unknown ifuid (0x%"PRIx32")",
			       ntohl(ifp->sub_table_index));
		return;
	}

	fpdebug_printf("%s vrfid %"PRIu16" (0x%"PRIx32")",
		       peer_ifp->if_name, peer_ifp->if_vrfid,
		       ntohl(peer_ifp->if_ifuid));
}

static int dump_interfaces(char *tok __fpn_maybe_unused)
{
	uint32_t i;
	fp_ifnet_t *ifp;

	for (i = 1 ; i < FP_MAX_IFNET; i++) {
		ifp = &fp_shared->ifnet.table[i];
		if (ifp->if_ifuid == 0)
			continue;

		fpdebug_printf("%"PRIu32":", i);

		display_ifnet(ifp);
	}
	return 0;
}

#ifdef CONFIG_MCORE_VRF
static int dump_xvrf(char *tok __fpn_maybe_unused)
{
	uint32_t i;
	uint32_t idx;
	fp_ifnet_t *ifp;

	for (i = 0 ; i < FP_MAX_VR; i++) {
		idx = fp_shared->fp_xvrf[i];
		if (!idx)
			continue;
		fpdebug_printf("X-VR interface for VR %"PRIu32" is (%"PRIu32")\n", i, idx);
		ifp = &fp_shared->ifnet.table[idx];
		if (ifp->if_ifuid == 0)
			fpdebug_printf("   **** is invalid ! ****\n");
		else
			display_ifnet(ifp);
	}
	return 0;
}
#endif

#define FPDEBUG_CONFIG_FPNSDK_CONFIG_FILE "/usr/local/6WINDGate/etc/fpnsdk.config"
#define FPDEBUG_CONFIG_FP_CONFIG_FILE "/usr/local/6WINDGate/etc/fp.config"
static int dump_file(const char *config)
{
	int error = 0;
	FILE *file;
	char buf[BUFSIZ];

	if (!(file = fopen(config, "r"))) {
		fpdebug_fprintf(stderr, "fopen(%s): %s\n", config,
				strerror(errno));
		error = -1;
	} else {
		while (fgets(buf, sizeof(buf), file) != NULL)
			fpdebug_printf("%s", buf);

		fclose(file);
	}
	return error;
}

static int dump_config(char *tok __fpn_maybe_unused)
{
	if (dump_file(FPDEBUG_CONFIG_FPNSDK_CONFIG_FILE))
		return -1;
	if (dump_file(FPDEBUG_CONFIG_FP_CONFIG_FILE))
		return -1;

	return 0;
}

#define FPDEBUG_ALL_SHARED      1
#define FPDEBUG_NF_TABLES       2
/*
 * dump_u32: dump the shared memory content
 * @fp: output stream
 * @addr: start addr
 * @len: memory length
 *
 * return value: the number of array length
 *
 * This function dumps memory into file stream fp as C code.
 * The output is an array of simu_fp_shared_t structures describing
 * a sequence of 32-bit words.
 * This C code can be used by the standalone fast path.
 * The struct definition:
 * typedef struct simu_fp_shared_s {
 * 	uint32_t	num;
 * 	uint32_t	value;
 * } simu_fp_shared_t;
 *
 * fields:
 * 	num  : number of contiguous 32-bit words with same value
 * 	value: value of each 32-bit word
 */
static int dump_u32(FILE *fp, unsigned char *addr, int len)
{
	uint32_t *arr, value, num;
	int words, arrlen, i;

	if (fp == NULL || addr == NULL) return 0;

	if ((words = len/4) <= 0)
		return 0;

	i       = 0;
	arr 	= (uint32_t *)addr;
	arrlen	= 0;
	value	= arr[0];
	num 	= 1;

	do {
		i++;

		if (i < words && arr[i] == value) {
			num++;
			continue;
		}
		fpdebug_fprintf(fp, "{%6"PRIu32",0x%08"PRIx32"}", num, value);

		arrlen++;
		value = arr[i];
		num = 1;

		if (i < words) {
			fpdebug_fprintf(fp, ",");
			if (arrlen %4 == 0)
				fpdebug_fprintf(fp, "\n");
		}

	} while (i < words);

	return arrlen;
}

/*
 * This function enables to dump into a C header file the
 * fp_shared memory, then you can add it to the compilation
 * of the cavium simulator to automatically configure netfilter
 * rules. The idea is to create a Netfilter configuration in 6WINDGate
 * then to dump it in a header with this utility and to recompile the
 * simulator with this file included which will apply the same
 * configuration.
 */
static int dump_fp_shared(char *tok)
{
	int type = 0, num_elt;
	uint8_t *fp_shared_to_dump, *ch;
	size_t size_to_dump, i;
	FILE *file;
	int numtokens = gettokens(tok);
	size_t n4, n1;

	if ((numtokens < 2) || numtokens > 3) {
		fpdebug_fprintf (stderr, "wrong arguments: dump-fp-shared <all|nf> <path_to_file> [var_name]\n");
		return 0;
	}

	if (strncmp(chargv[0], "all", 3) == 0)
		type = FPDEBUG_ALL_SHARED;
	else if (strncmp(chargv[0], "nf", 2) == 0)
		type = FPDEBUG_NF_TABLES;

	switch (type) {
	case FPDEBUG_ALL_SHARED:
		fp_shared_to_dump = (uint8_t *)fp_shared;
		size_to_dump = sizeof (shared_mem_t);
		break ;
#ifdef CONFIG_MCORE_NETFILTER
	case FPDEBUG_NF_TABLES:
		fp_shared_to_dump = (uint8_t *)&fp_shared->fp_nf_current_table;
		size_to_dump = sizeof(fp_shared->fp_nf_current_table)
					+ sizeof(fp_shared->fp_nf_tables)
					+ sizeof(fp_shared->fp_nf_rules);
#ifdef CONFIG_MCORE_NF_CT
		size_to_dump += sizeof(fp_shared->fp_nf_ct);
#endif
		break ;
#else
		fpdebug_fprintf (stderr, "netfilter support is not enabled\n");
		return 0;
#endif
	default:
		fpdebug_fprintf (stderr, "wrong type: valid types are: all|nf\n");
		return 0;
	}

	n4 = size_to_dump / 4;
	n1 = size_to_dump % 4;

	if (!(file = fopen(chargv[1], "w"))) {
		fpdebug_fprintf (stderr, "fopen(%s, \"w\"): %s\n", chargv[1], strerror(errno));
		fpdebug_fprintf (stderr, "usage: dump-fp_shared <type> <path_to_file> [var_name]\n");
		return 0;
	}
	fpdebug_fprintf(file, "#include \"simu-fp-shared.h\"\n");
	fpdebug_fprintf(file, "\n");

#ifdef CONFIG_MCORE_NETFILTER
	if (type == FPDEBUG_NF_TABLES) {
		uint16_t nf_vr;
		fpdebug_fprintf(file, "uint64_t simu_nf_conf[FP_NF_MAX_VR][FP_NF_IP_NUMHOOKS] = {\n");
		for (nf_vr = 0; nf_vr < FP_NF_MAX_VR; nf_vr++) {
			fpdebug_fprintf(file, "\t{");
			for (i = 0; i < FP_NF_IP_NUMHOOKS; i++) {
				if (i > 0)
					fpdebug_fprintf(file, ", ");
				fpdebug_fprintf(file, "0x%"PRIx64,
					fp_shared->nf_conf.enabled_hook[nf_vr][i]);
			}
			fpdebug_fprintf(file, "},\n");
		}
		fpdebug_fprintf(file, "};\n");
		fpdebug_fprintf(file,"\n");
	}
#endif
	fpdebug_fprintf(file, "/*\n");
	fpdebug_fprintf(file, " * Dump of the fp_shared memory as a sequence of 32 bit words\n");
	fpdebug_fprintf(file, " * Format of each element: {num,value}\n");
	fpdebug_fprintf(file, " *   num: number of consecutive 32 bit words with the same value\n");
	fpdebug_fprintf(file, " *   value: the value of these words\n");
	fpdebug_fprintf(file, " * This table contains SHMEM_WORDS_SEQUENCE_NUM elements\n");
	fpdebug_fprintf(file, " */\n");
	if (numtokens == 3)
		fpdebug_fprintf(file, "simu_fp_shared_t %s", chargv[2]);
	else
		fpdebug_fprintf(file, "simu_fp_shared_t shmem_words_sequence");

	if (n4 == 0) {
		num_elt = 0;
		fpdebug_fprintf(file, "[0];\n");
	} else {
		fpdebug_fprintf(file, "[] = {\n");
		num_elt = dump_u32(file, fp_shared_to_dump, size_to_dump);
		fpdebug_fprintf(file, "\n};\n");
	}
	fpdebug_fprintf(file, "\n");
	fpdebug_fprintf(file, "#define SHMEM_WORDS_SEQUENCE_NUM %"PRId32"\n", num_elt);
	fpdebug_fprintf(file, "#define SHMEM_LAST_BYTES_NUM %lu\n",
			(unsigned long)n1);
	fpdebug_fprintf(file, "\n");

	fpdebug_fprintf(file, "/* Dump of the fp_shared memory last bytes */\n");
	ch = &fp_shared_to_dump[4*n4];
	fpdebug_fprintf(file,"uint8_t shmem_last_bytes[SHMEM_LAST_BYTES_NUM]");
	for(i=0; i<n1; i++){
		if (i==0)
			fpdebug_fprintf(file, "= {0x%"PRIx8, ch[i]);
		else
			fpdebug_fprintf(file, ",0x%"PRIx8, ch[i]);
	}
	fpdebug_fprintf(file,"%s;\n", (i == 0) ? "" : "}" );
	fclose(file);

	return 0;
}

static int set_preferred(char *tok)
{
	int val = 0;
	fp_ifnet_t *ifp;
	char *ifce;

	if (gettokens(tok) != 2) {
		fpdebug_fprintf (stderr, "wrong arguments: set-pref <interface> <val>\n");
		return 0;
	}
	ifce = chargv[0];
	if ((ifp = fp_getifnetbyname(ifce)) == NULL) {
		fpdebug_printf("bad interface name: %s\n", ifce);
		return -1;
	}

	if (0 == strncmp(chargv[1],"on",2))
		val = 1;
	else {
		if (0 != strncmp(chargv[1],"off",3)) {
			fpdebug_printf("bad command %s, must be on|off\n",
				       chargv[1]);
			return -1;
		}
	}

	fp_setifnet_preferred(ifp, val);
	return 0;
}

#ifdef CONFIG_MCORE_IP
static int set_ifdown(char *tok)
{
	fp_ifnet_t *ifp;
	char *ifce;

	if (gettokens(tok) != 1) {
		fpdebug_fprintf (stderr, "wrong arguments: set-ifdown <interface>\n");
		return 0;
	}

	ifce = chargv[0];
	if ((ifp = fp_getifnetbyname(ifce)) == NULL) {
		fpdebug_printf("bad interface name: %s\n", ifce);
		return -1;
	}

	fp_setifnet_down(ifp);
	return 0;
}
#endif

static int set_flags (char *tok)
{
	fp_ifnet_t *ifp;
#if defined(CONFIG_MCORE_LAG)
	fp_ifnet_t *ifmaster;
#endif
	char *ifce;
	int flags;

	if (gettokens(tok) != 2) {
		fpdebug_fprintf (stderr, "wrong arguments: set-flags <interface> <flags>\n");
		return 0;
	}

	ifce = chargv[0];
	if ((ifp = fp_getifnetbyname(ifce)) == NULL) {
		fpdebug_printf("bad interface name: %s\n", ifce);
		return -1;
	}
	sscanf(chargv[1], "%x", &flags);

	fp_setifnet_flags(ifp->if_ifuid, flags & IFF_CP_MASK);

#if defined(CONFIG_MCORE_LAG)
	if (ifp->if_master_ifuid != 0) {
		ifmaster = __fp_ifuid2ifnet(ifp->if_master_ifuid);
		if (ifmaster != NULL && ifmaster->if_type == FP_IFTYPE_BONDING)
			return fp_bonding_slave_flags_set(ifp);
	}
#endif

	return 0;
}

static int dump_ports(char *tok)
{
	unsigned int i;
	fp_ifport_t *p;
	int all = 0;

	if (gettokens(tok) == 1 && strcmp(chargv[0], "all")==0)
		all = 1;

	for (i = 0 ; i < FP_MAX_PORT; i++) {
		p = &fp_shared->ifport[i];
		if (!all && p->ifuid ==0)
			continue;
		fpdebug_printf("%u: ifuid=0x%"PRIx32" cached ifp=0x%"PRIx64"\n", i, ntohl(p->ifuid), p->u.u64);
	}
	return 0;
}

/*
 * Merely checks the eth addr is all NULL
 */
#ifdef CONFIG_MCORE_IP
static int
eth_is_addr_unspec(const uint8_t *dst)
{
	uint32_t *dst03 = (uint32_t *)dst;
	uint16_t *dst45 = (uint16_t *)&dst[4];

	return ((*dst03 == 0) && (*dst45 == 0));
}

static int add_neighbour(char *tok)
{
	uint8_t mac[6];
	uint32_t addr = 0;
	int ifuid;
	fp_ifnet_t *ifp;
	int res;

	if (gettokens(tok) != 3) {
		fpdebug_fprintf (stderr, "wrong arguments: add-neighbour <ip> <mac> <ifname>\n");
		return 0;
	}

	if (string2mac(chargv[1], mac) == 0) {
		fpdebug_fprintf(stderr, "invalid mac address\n");
		return 0;
	}

	ifp = fp_getifnetbyname(chargv[2]);
	if (ifp == NULL) {
		fpdebug_fprintf(stderr, "unknown interface %s\n", chargv[2]);
		return 0;
	}
	ifuid = ifp->if_ifuid;

	res = fpdebug_inet_pton(AF_INET, chargv[0], &addr);
	if (res > 0) {
		/* IPv4 address */
		if (fp_add_neighbour4(addr, mac, ifuid,
				eth_is_addr_unspec(mac) ?
				L2_STATE_INCOMPLETE :
				L2_STATE_REACHABLE) != 0)
			fpdebug_fprintf(stderr, "failed to add neighbour\n");
	} else {
#ifdef CONFIG_MCORE_IPV6
		/* IPv6 address ? */
		fp_in6_addr_t address;
		address.fp_s6_addr32[0] = 0;
		address.fp_s6_addr32[1] = 0;
		address.fp_s6_addr32[2] = 0;
		address.fp_s6_addr32[3] = 0;
		res = fpdebug_inet_pton(AF_INET6, chargv[0], &address);

		if (res > 0) {
			if (fp_add_neighbour6(&address, mac, ifuid,
					eth_is_addr_unspec(mac) ?
					L2_STATE_INCOMPLETE :
					L2_STATE_REACHABLE) != 0)
				fpdebug_fprintf(stderr, "failed to add neighbour\n");
		}
		else
#endif /* CONFIG_MCORE_IPV6 */
			fpdebug_fprintf(stderr, "malformed address\n");
	}

	return 0;
}

static int delete_neighbour(char *tok)
{
	uint32_t addr = 0;
	int ifuid;
	fp_ifnet_t *ifp;
	int res;

	if (gettokens(tok) != 2) {
		fpdebug_fprintf (stderr, "wrong arguments: delete-neighbour <ip> <ifname>\n");
		return 0;
	}

	ifp = fp_getifnetbyname(chargv[1]);
	if (ifp == NULL) {
		fpdebug_fprintf(stderr, "unknown interface %s\n", chargv[1]);
		return 0;
	}
	ifuid = ifp->if_ifuid;

	res = fpdebug_inet_pton(AF_INET, chargv[0], &addr);
	if (res > 0) {
		/* IPv4 address */
		if (fp_delete_neighbour4(addr, ifuid) != 0)
			fpdebug_fprintf(stderr, "failed to delete neighbour\n");
	} else {
#ifdef CONFIG_MCORE_IPV6
		/* IPv6 address ? */
		fp_in6_addr_t address;
		address.fp_s6_addr32[0] = 0;
		address.fp_s6_addr32[1] = 0;
		address.fp_s6_addr32[2] = 0;
		address.fp_s6_addr32[3] = 0;
		res = fpdebug_inet_pton(AF_INET6, chargv[0], &address);

		if (res > 0) {
			if (fp_delete_neighbour6(&address, ifuid) != 0)
				fpdebug_fprintf(stderr, "failed to delete neighbour\n");
		}
		else
#endif
			fpdebug_fprintf(stderr, "malformed address\n");
	}
	return 0;
}

/* Select an IPv4 route for display using input rt_type */
static int select_type4(int rt_type, struct fp_rt4_entry *rt4)
{
	int nh;
	if (rt_type == -1)
		return 1;

	/* Short-cut: rt_neigh_index !=0 tells there is one
	 * neighbour at least.
	 */
	if (rt_type == RT_TYPE_NEIGH) {
		if (rt4->rt.rt_neigh_index)
			return 1;
		else
			return 0;
	}

	for (nh=0; nh<rt4->rt.rt_nb_nh; nh++) {
		uint32_t i;
		int local_rt_type;

		i = rt4->rt.rt_next_hop[nh];
		local_rt_type = fp_shared->fp_nh4_table[i].nh.rt_type;

		/* The GW is resolved, but the route itself is not a neighbor */
		if (local_rt_type == RT_TYPE_NEIGH && rt4->rt.rt_neigh_index == 0)
			local_rt_type = RT_TYPE_ROUTE;

		if (rt_type == local_rt_type)
			return 1;
	}

	/* No NH matched the desired type */
	return 0;
}
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
/* Select an IPv6 route for display using input rt_type */
static int select_type6(int rt_type, struct fp_rt6_entry *rt6)
{
	int nh;

	if (rt_type == -1)
		return 1;

	/* Short-cut: rt_neigh_index !=0 tells there is one
	 * neighbour at least.
	 */
	if (rt_type == RT_TYPE_NEIGH) {
		if (rt6->rt.rt_neigh_index)
			return 1;
		else
			return 0;
	}

	for (nh=0; nh<rt6->rt.rt_nb_nh; nh++) {
		uint32_t i;
		int local_rt_type;

		i = rt6->rt.rt_next_hop[nh];
		local_rt_type = fp_shared->fp_nh6_table[i].nh.rt_type;

		/* The GW is resolved, but the route itself is not a neighbor */
		if (local_rt_type == RT_TYPE_NEIGH && rt6->rt.rt_neigh_index == 0)
			local_rt_type = RT_TYPE_ROUTE;

		if (rt_type == local_rt_type)
			return 1;
	}

	/* No NH matched the desired type */
	return 0;
}
#endif

#ifdef CONFIG_MCORE_IP
static int add_route(char *tok)
{
	uint8_t rt_type;
	int numtokens = gettokens(tok);
	char *ip_str;
	uint32_t addr = 0;
	int prefix;
	char *prefix_str;
	uint32_t next = 0;
	char *ifname;
	int ifuid;
	int res;

	if (numtokens < 4) {
		fpdebug_fprintf (stderr, "wrong arguments: add-route <ip> "
				 "<prefix length> <gateway> <ifname|0xifuid> [<type>]\n");
		return 0;
	}

	ip_str = chargv[0];
	prefix = atoi(chargv[1]);
	prefix_str = chargv[2];
	ifname = chargv[3];
	if (strncmp (ifname, "0x",2)) {
		fp_ifnet_t *ifp;
		ifp = fp_getifnetbyname(ifname);
		if (ifp == NULL) {
			fpdebug_fprintf(stderr, "unknown interface %s\n", ifname);
			return -1;
		}
		ifuid = ifp->if_ifuid;
	} else {
		char *end;

		errno = 0;
		ifuid = htonl(strtoul(ifname, &end, 0));
		if (errno || *end) {
			fpdebug_fprintf(stderr, "invalid ifuid %s\n", ifname);
			return -1;
		}
	}

	res = fpdebug_inet_pton(AF_INET, ip_str, &addr);
	if (numtokens == 5)
		rt_type = atoi(chargv[4]);
	else
		rt_type = RT_TYPE_ROUTE;

	if (res > 0) {
		/* IPv4 address */
		int res2 = fpdebug_inet_pton(AF_INET, prefix_str, &next);
		if (res2 > 0) {
			fp_add_route4(default_vrfid,addr, prefix, next, ifuid, rt_type);
		} else {
			fpdebug_printf("Malformed IPv4 address !\n");
		}
	} else {
		/* IPv6 address */
#ifdef CONFIG_MCORE_IPV6
		fp_in6_addr_t address;
		fp_in6_addr_t next2 = address;
		int res2;

		address.fp_s6_addr32[0] = 0;
		address.fp_s6_addr32[1] = 0;
		address.fp_s6_addr32[2] = 0;
		address.fp_s6_addr32[3] = 0;

		res = fpdebug_inet_pton(AF_INET6, ip_str, &address);
		res2 = fpdebug_inet_pton(AF_INET6, prefix_str, &next2);

		if (res > 0 && res2 > 0) {
			fp_add_route6_nhmark(default_vrfid, &address, prefix, &next2,
					ifuid, rt_type, NULL);
		} else
			fpdebug_printf("Malformed IPv6 address !\n");
#endif
	}
	return 0;
}
#endif /* CONFIG_MCORE_IP */

static void
print_magic_state(uint32_t x)
{
	if (x == FP_SHARED_MAGIC32)
		fpdebug_printf("on");
	else
		fpdebug_printf("off");
}

static int turn(char *tok)
{
	uint32_t old_status = fp_shared->conf.s.magic;

	if (gettokens(tok) == 1) {
		char *str = chargv[0];
		if (strcmp(str, "on")==0)
			fp_shared->conf.s.magic = FP_SHARED_MAGIC32;
		else if (strcmp(str, "off")==0)
			fp_shared->conf.s.magic = 0xdeadbeef;
	}

	fpdebug_printf("FP is turned ");
	print_magic_state(fp_shared->conf.s.magic);
	if (fp_shared->conf.s.magic != old_status) {
		fpdebug_printf(" (was ");
		print_magic_state(old_status);
		fpdebug_printf(")\n");
	} else
		fpdebug_printf("\n");

	return 0;
}

#ifndef __FastPath__
static int init_sharedmem(char *tok)
{
	int ret = 0;
	uint8_t	fpm_cp_portmac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

	/* Initialize shared memory since FPM will not do it for us */
	fp_init();
	fp_set_blade_id(1, 0);
	fp_set_cp_info(IF_PORT_COLOC, fpm_cp_portmac, 1500, 0);

	return ret;
}
#endif

static int dump_conf(char *tok __fpn_maybe_unused)
{
#define FPDEBUG_ONOFF(x) (fp_shared->conf.s.x ? "on": "off")
	fpdebug_printf("Netfilter: %s \n", FPDEBUG_ONOFF(do_netfilter));
	fpdebug_printf("IPv6 Netfilter: %s \n", FPDEBUG_ONOFF(do_netfilter6));
	fpdebug_printf("Bridge filtering: %s \n", FPDEBUG_ONOFF(do_ebtables));
	fpdebug_printf("IPsec output: %s \n", FPDEBUG_ONOFF(do_ipsec_output));
	fpdebug_printf("IPsec input: %s \n", FPDEBUG_ONOFF(do_ipsec_input));
	fpdebug_printf("IPv6 IPsec output: %s \n", FPDEBUG_ONOFF(do_ipsec6_output));
	fpdebug_printf("IPv6 IPsec input: %s \n", FPDEBUG_ONOFF(do_ipsec6_input));
	fpdebug_printf("Forced reassembly: %s \n", FPDEBUG_ONOFF(do_forced_reassembly));
	fpdebug_printf("Tap: %s %s \n", FPDEBUG_ONOFF(do_tap),
			fp_shared->conf.s.do_tap_global ? "(global)" : "(local)");
	fpdebug_printf("Do IPsec only once: %s \n", FPDEBUG_ONOFF(do_ipsec_once));
	fpdebug_printf("Netfilter cache: %s \n", FPDEBUG_ONOFF(do_nf_cache));
	fpdebug_printf("IPv6 Netfilter cache: %s \n", FPDEBUG_ONOFF(do_nf6_cache));
	fpdebug_printf("ARP reply: %s \n", FPDEBUG_ONOFF(do_arp_reply));
	fpdebug_printf("Fast forward: %s \n", fp_shared->conf.w32.do_func & FP_CONF_NO_FAST_FORWARD ? "off": "on");
#undef FPDEBUG_ONOFF

	return 0;
}

#ifdef CONFIG_MCORE_ARP_REPLY
static int set_arp_reply(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	char *on_str = NULL;

	if (arg_count > 1) {
		fpdebug_printf("wrong arguments: arp-reply [on|off]\n");
		return 0;
	}

	if (arg_count == 1) {
		on_str = chargv[0];
		if (strcmp(on_str, "on") == 0)
			fp_shared->conf.s.do_arp_reply = 1;
		else if (strcmp(on_str, "off") == 0)
			fp_shared->conf.s.do_arp_reply = 0;
	}

	fpdebug_printf("arp reply is %s\n",
		       fp_shared->conf.s.do_arp_reply ? "on" : "off");
	return 0;
}
#endif

#ifdef CONFIG_MCORE_L2SWITCH
static void dump_l2switch_ports(l2switch_shared_mem_t *l2switch_shared)
{
	fp_ifnet_t *ifnet;
	fp_ifport_t *p;
	int i;

	for (i = 0 ; i < FP_MAX_PORT; i++) {
		p = &fp_shared->ifport[i];
		if (p->ifuid ==0)
			continue;

		ifnet = fp_ifuid2ifnet(p->ifuid);
		fpdebug_printf("port%u[", i);
		print_mac((uint8_t *)&ifnet->if_mac);
		fpdebug_printf("] => ");
		if (l2switch_shared->next_portid[i] == FP_L2SWITCH_PORT_DROP)
			fpdebug_printf("drop\n");
		else if (l2switch_shared->next_portid[i] == FP_L2SWITCH_PORT_EXCEPTION)
			fpdebug_printf("exception\n");
		else
			fpdebug_printf("port%u\n", l2switch_shared->next_portid[i]);
	}
}

static void dump_l2switch_mode(l2switch_shared_mem_t *l2switch_shared)
{
	fpdebug_printf("L2 switch mode: ");

	switch (l2switch_shared->mode) {
		case FP_L2SWITCH_ON:
			fpdebug_printf("on\n");
			break;

		case FP_L2SWITCH_OFF:
		default:
			fpdebug_printf("off\n");
			break;
	}
}

static int set_l2switch_nextport(char *tok)
{
	l2switch_shared_mem_t *l2switch_shared;
	unsigned portid, next_portid;
	char *str;

	l2switch_shared = get_l2switch_shared_mem();
	if (l2switch_shared == NULL) {
		fpdebug_printf("l2-switch shared memory not available\n");
		return -1;
	}

	if (gettokens(tok) != 2) {
		fpdebug_printf("set-l2switch-nextport <portid[0-%d]> <next_portid[0-%d]|drop|exception>\n",
			       FP_MAX_PORT, FP_MAX_PORT);
		return -1;
	}

	str = chargv[1];


	portid = atoi(chargv[0]);
	if (portid >= FP_MAX_PORT) {
		fpdebug_printf("set-l2switch-nextport <portid[0-%d]> <next_portid[0-%d]|drop|exception>\n",
			       FP_MAX_PORT, FP_MAX_PORT);
		return -1;
	}

	if (!strcmp(str, "drop") || !strcmp(str, "exception")) {
		if (!strcmp(str, "drop"))
			next_portid = FP_L2SWITCH_PORT_DROP;
		else
			next_portid = FP_L2SWITCH_PORT_EXCEPTION;
	} else {
		next_portid = atoi(chargv[1]);
		if (next_portid > FP_MAX_PORT) {
			fpdebug_printf("set-l2switch-nextport <portid[0-%d]> <next_portid[0-%d]|drop|exception>\n",
				       FP_MAX_PORT, FP_MAX_PORT);
			return -1;
		}
	}
	l2switch_shared->next_portid[portid] = next_portid;

	dump_l2switch_ports(l2switch_shared);

	return 0;
}

static int set_l2switch_mode(char *tok)
{
	char *str;
	l2switch_shared_mem_t *l2switch_shared;

	l2switch_shared = get_l2switch_shared_mem();
	if (l2switch_shared == NULL) {
		fpdebug_printf("l2-switch shared memory not available\n");
		return -1;
	}

	if (gettokens(tok) != 1) {
		fpdebug_printf("set-l2switch-mode <on|off>\n");
		return -1;
	}

	str = chargv[0];

	if (!strcmp(str, "on"))
		l2switch_shared->mode = FP_L2SWITCH_ON;
	else if (!strcmp(str, "off"))
		l2switch_shared->mode = FP_L2SWITCH_OFF;
	else
		fpdebug_printf("set-l2switch-mode <on|off>\n");

	dump_l2switch_mode(l2switch_shared);

	return 0;
}

static int dump_l2switch(char *tok __fpn_maybe_unused)
{
	l2switch_shared_mem_t *l2switch_shared;

	l2switch_shared = get_l2switch_shared_mem();
	if (l2switch_shared == NULL) {
		fpdebug_printf("l2-switch shared memory not available\n");
		return -1;
	}

	dump_l2switch_mode(l2switch_shared);
	dump_l2switch_ports(l2switch_shared);

	return 0;
}
#endif

static int dump_clock_hz(char *tok __fpn_maybe_unused)
{
#ifndef __FastPath__
	fpdebug_printf("Clock HZ: %"PRIu64"\n", get_clock_hz());
#else
	fpdebug_printf("Not supported in embedded fpdebug\n");
#endif
	return 0;
}

#ifdef CONFIG_MCORE_IPSEC
static void print_ipsec_once_state(uint64_t x)
{
	if (x)
		fpdebug_printf("on");
	else
		fpdebug_printf("off");
}

static int set_ipsec_once(char *tok)
{
	uint64_t old_status = fp_shared->conf.s.do_ipsec_once;

	if (gettokens(tok) == 1) {
		char *str = chargv[0];
		if (strcmp(str, "on")==0)
			fp_shared->conf.s.do_ipsec_once = 1;
		else if (strcmp(str, "off")==0)
			fp_shared->conf.s.do_ipsec_once = 0;
	}

	fpdebug_printf("IPsec processing only once is ");
	print_ipsec_once_state(fp_shared->conf.s.do_ipsec_once);
	if (fp_shared->conf.s.do_ipsec_once!= old_status) {
		fpdebug_printf(" (was ");
		print_ipsec_once_state(old_status);
		fpdebug_printf(")");
	}
	fpdebug_printf("\n");

	return 0;
}

static int set_ipsec_output_blade(char *tok)
{
	if (gettokens(tok) != 1) {
		fpdebug_printf("Need blade id value");
		return 0;
	}
	fp_shared->ipsec.output_blade = atoi(chargv[0]);
	return 0;
}

#ifdef CONFIG_MCORE_MULTIBLADE
static int set_sa_sync_threshold(char *tok)
{
	if (gettokens(tok) != 1) {
		fpdebug_printf("Need threshold value");
		return 0;
	}
	fp_shared->ipsec.sa_replay_sync_threshold = atoi(chargv[0]);
	return 0;
}

static int show_sa_sync_threshold(char *tok)
{
	fpdebug_printf("IPv4 IPsec threshold between two sequence number sync messages is: %"PRIu32"\n",
	       fp_shared->ipsec.sa_replay_sync_threshold);
	return 0;
}
#ifdef CONFIG_MCORE_IPSEC_IPV6
static int set_sa6_sync_threshold(char *tok)
{
	if (gettokens(tok) != 1) {
		fpdebug_printf("Need threshold value");
		return 0;
	}
	fp_shared->ipsec6.sa_replay_sync_threshold = atoi(chargv[0]);
	return 0;
}

static int show_sa6_sync_threshold(char *tok)
{
	fpdebug_printf("IPv6 IPsec threshold between two sequence number sync messages is: %"PRIu32"\n",
	       fp_shared->ipsec6.sa_replay_sync_threshold);
	return 0;
}
#endif	/* CONFIG_MCORE_IPSEC_IPV6 */
#endif	/* CONFIG_MCORE_MULTIBLADE */

#ifdef CONFIG_MCORE_IPSEC_TRIE

static int show_ipsec_trie(char *tok)
{
	fpdebug_printf("Trie area size=%u MB, number of areas=%d\n",
	       CONFIG_MCORE_IPSEC_TRIE_ZONE_SIZE/(1024*1024), 3);
	fpdebug_printf("Outbound SPD trie:\n");
	fpdebug_printf("    TRIE%u thresh=%"PRIu16" spd_version=%"PRIu16
	       " trie_version=%"PRIu16" running=%u building=%u\n",
	       (uint16_t)fp_shared->ipsec.trie_out.index,
	       (uint16_t)fp_shared->ipsec.trie_out.threshold,
	       (uint16_t)fp_shared->ipsec.trie_out.spd_version,
	       (uint16_t)fp_shared->ipsec.trie_out.trie_version,
	       (unsigned)fp_shared->ipsec.trie_out.running,
	       (unsigned)fp_shared->ipsec.trie_out.building);
	fpdebug_printf("Inbound SPD trie:\n");
	fpdebug_printf("    TRIE%u thresh=%"PRIu16" spd_version=%"PRIu16
	       " trie_version=%"PRIu16" running=%u building=%u\n",
	       (uint16_t)fp_shared->ipsec.trie_in.index,
	       (uint16_t)fp_shared->ipsec.trie_in.threshold,
	       (uint16_t)fp_shared->ipsec.trie_in.spd_version,
	       (uint16_t)fp_shared->ipsec.trie_in.trie_version,
	       (unsigned)fp_shared->ipsec.trie_in.running,
	       (unsigned)fp_shared->ipsec.trie_in.building);

	return 0;
}

static int set_ipsec_trie_threshold(char *tok)
{
	int dir = 0;  /* display=0 in=1 out=2 both=3 */
	unsigned int old_threshold_out, old_threshold_in, threshold;
	int nt = gettokens(tok);

	old_threshold_out = fp_shared->ipsec.trie_out.threshold;
	old_threshold_in = fp_shared->ipsec.trie_in.threshold;
	if (nt == 1) {
		threshold = atoi(chargv[0]);
		dir = 3;
	}
	else if (nt > 1) {
		if (strcmp(chargv[0], "in") == 0)
			dir = 1;
		else if (strcmp(chargv[0], "out") == 0)
			dir = 2;
		threshold = atoi(chargv[1]);
	}

	if (dir) {
		if (dir == 3 || dir == 1) {
			fp_shared->ipsec.trie_in.threshold = threshold;
			if (threshold > fp_get_spd_in()->global_sp_count)
				fp_shared->ipsec.trie_in.running = 0;
			else if (old_threshold_in > fp_get_spd_in()->global_sp_count)
				fp_spd_in_commit();
		}
		if (dir == 3 || dir == 2) {
			fp_shared->ipsec.trie_out.threshold = threshold;
			if (threshold > fp_get_spd_out()->global_sp_count)
				fp_shared->ipsec.trie_out.running = 0;
			else if (old_threshold_out > fp_get_spd_out()->global_sp_count)
				fp_spd_out_commit();
		}
	}

	fpdebug_printf("IPsec output trie threshold: %"PRIu16"\n",
			(uint16_t)fp_shared->ipsec.trie_out.threshold);
	fpdebug_printf("IPsec input trie threshold: %"PRIu16"\n",
			(uint16_t)fp_shared->ipsec.trie_in.threshold);

	return 0;
}
#endif	/* CONFIG_MCORE_IPSEC_TRIE */
#endif	/* CONFIG_MCORE_IPSEC */

#ifdef CONFIG_MCORE_TAP
static void print_tap_state(uint64_t x)
{
	if (x)
		fpdebug_printf("global");
	else
		fpdebug_printf("local");
}

static int set_tap_state(char *tok)
{
	uint64_t old_status = fp_shared->conf.s.do_tap_global;

	if (gettokens(tok) == 1) {
		char *str = chargv[0];
		if (strcmp(str, "global")==0)
			fp_shared->conf.s.do_tap_global = 1;
		else if (strcmp(str, "local")==0)
			fp_shared->conf.s.do_tap_global = 0;
	}

	fpdebug_printf("TAP behavior is ");
	print_tap_state(fp_shared->conf.s.do_tap_global);
	if (fp_shared->conf.s.do_tap_global != old_status) {
		fpdebug_printf(" (was ");
		print_tap_state(old_status);
		fpdebug_printf(")");
	}
	fpdebug_printf("\n");

	return 0;
}

static void print_tap_enable(uint64_t x)
{
	if (x)
		fpdebug_printf("on");
	else
		fpdebug_printf("off");
}

static int set_tap(char *tok)
{
	uint64_t old_status = fp_shared->conf.s.do_tap;

	if (gettokens(tok) == 1) {
		char *str = chargv[0];
		if (strcmp(str, "on") == 0)
			fp_shared->conf.s.do_tap = 1;
		else if (strcmp(str, "off") == 0)
			fp_shared->conf.s.do_tap = 0;
	}

	fpdebug_printf("TAP is ");
	print_tap_enable(fp_shared->conf.s.do_tap);
	if (fp_shared->conf.s.do_tap != old_status) {
		fpdebug_printf(" (was ");
		print_tap_enable(old_status);
		fpdebug_printf(")");
	}
	fpdebug_printf("\n");

	return 0;
}
#endif

#ifdef CONFIG_MCORE_TAP_CIRCULAR_BUFFER
#if (!defined(__FastPath__) && !defined(FP_STANDALONE)) || (defined(__FastPath__) && defined(FP_STANDALONE))

void fpdebug_hexdump(const char *title, const void *buf, unsigned int len)
{
	unsigned int i, out, ofs;
	const unsigned char *data = buf;
#define LINE_LEN 80
	char line[LINE_LEN];    /* space needed 8+16*3+3+16 == 75 */

	fpdebug_printf("%s at [%p], len=%d\n", title, data, len);
	ofs = 0;
	while (ofs < len) {
		/* format 1 line in the buffer, then use printk to print them */
		out = snprintf(line, LINE_LEN, "%08X", ofs);
		for (i = 0; ofs + i < len && i < 16; i++)
			out += snprintf(line + out, LINE_LEN - out, " %02X",
					data[ofs + i] & 0xff);
		for(; i <= 16; i++)
			out += snprintf(line + out, LINE_LEN - out, "   ");
		for(i = 0; ofs < len && i < 16; i++, ofs++) {
			unsigned char c = data[ofs];
			if (!isascii(c) || !isprint(c))
				c = '.';
			out += snprintf(line + out, LINE_LEN - out, "%c", c);
		}
		fpdebug_printf("%s\n", line);
	}
}

static int tap_dump(char *tok)
{
	struct fp_tap_pkt *pkt;
	char *filename = NULL;
	uint64_t pkt_total_size;
	int offset;
	unsigned int shm_size;
	int max_pkt_count, i;
	struct fp_tap_pkt *fp_circ_buf;
	pcap_t *p;
	pcap_dumper_t *pd = NULL;
	struct pcap_pkthdr h;
	uint64_t freq;
	uint64_t freq_us;

#ifndef __FastPath__
	freq = get_clock_hz();
#else
	freq = fpn_get_clock_hz();
#endif
	freq_us = freq / 1000000;

	if (fp_shared->conf.s.do_tap_circular_buffer == 1) {
		fpdebug_printf("stop the capture first\n");
		return -1;
	}

	if (gettokens(tok) == 1)
		filename = chargv[0];

	shm_size = fp_shared->cap_buf_size;

	fp_circ_buf = fpn_shmem_mmap(CAP_SHM_NAME, NULL, shm_size);
	if (fp_circ_buf == NULL) {
		fpdebug_printf("failed mapping %s of size %d\n",
			       CAP_SHM_NAME, shm_size);
		return -1;
	}

	pkt_total_size = sizeof(struct fp_tap_pkt) + fp_shared->cap_pkt_len;

	/* start from offset 0 if offset is out of buffer bounds */
	if (fp_shared->cap_buf_offset + pkt_total_size >= fp_shared->cap_buf_size)
		offset = 0;
	else
		offset = fp_shared->cap_buf_offset;
	pkt = (struct fp_tap_pkt *)((char *) fp_circ_buf + offset);

	/* start from offset 0 if there is not packet at offset */
	if (pkt->pkt_len == 0) {
		offset = 0;
		pkt = (struct fp_tap_pkt *)((char *) fp_circ_buf + offset);
	}

	/* now pkt points to the older packet */

	if (filename != NULL) {
		p = pcap_open_dead(DLT_EN10MB, 65535);
		if (p == NULL) {
			fpdebug_printf("pcap_open_dead failed\n");
			return -1;
		}
		pd = pcap_dump_open(p, filename);
		if (pd == NULL) {
			fpdebug_printf("pcap_dump_open failed\n");
			return -1;
		}
	}

	max_pkt_count = fp_shared->cap_buf_size / pkt_total_size;
	for (i = 0; i < max_pkt_count; i ++) {
		if (pkt->pkt_len == 0)
			goto end;

		if (filename != NULL) {
			h.ts.tv_sec = pkt->timestamp / freq;
			h.ts.tv_usec = (pkt->timestamp - (h.ts.tv_sec * freq));
			h.ts.tv_usec /= freq_us;
			h.caplen = fp_shared->cap_pkt_len;
			h.len = pkt->pkt_len;
			pcap_dump((unsigned char *)pd, &h, (u_char *) pkt->data);
		} else
			fpdebug_hexdump("pkt", pkt->data, fp_shared->cap_pkt_len);

		offset += pkt_total_size;
		if (offset + pkt_total_size > fp_shared->cap_buf_size)
			offset = 0;
		pkt = (struct fp_tap_pkt *)((char *) fp_circ_buf + offset);
	}
 end:
	if (filename != NULL)
		pcap_dump_close(pd);

	return 0;
}

static uint64_t tap_shmem_size(char *size_str)
{
	uint64_t size = 0;

	if (size_str == NULL)
		return -1;

	size = atoi(size_str);

	while (isdigit(*size_str))
		size_str++;

	switch (*size_str) {
	case 'G':
		size *= 1024;
	case 'M':
		size *= 1024;
	case 'K':
		size *= 1024;
	case 'B':
		break;
	default:
		return 0;
	}
	return size;
}

static int tap_buffer(char *tok)
{
	void *shmem = NULL;
	uint64_t shm_size = 0;
	int tokens = gettokens(tok);
	char *str = chargv[0];
	uint32_t cap_wrap = 1;

	if (tokens >= 1 && strcmp("create_nowrap", str) == 0)
		cap_wrap = 0;

	if (tokens == 1 && (strcmp("delete", str) == 0)) {
		if (fp_shared->conf.s.do_tap_circular_buffer == 1) {
			fpdebug_printf("stop the running capture first\n");
			return -1;
		} else if (fp_shared->cap_buf_size) {
			fpn_shmem_del(CAP_SHM_NAME);
			fp_shared->cap_buf_size = 0;
			fpdebug_printf("capture buffer deleted\n");
		} else {
			fpdebug_printf("buffer doesn't exist\n");
			return -1;
		}
	} else if (tokens == 2 && (strcmp("create", str) == 0 ||
				   strcmp("create_nowrap", str) == 0)) {
		if (fp_shared->cap_buf_size == 0) {
			shm_size = tap_shmem_size(chargv[1]);
			if (shm_size <= 0) {
				fpdebug_printf("invalid size\n");
				return -1;
			}
			fpn_shmem_add(CAP_SHM_NAME, shm_size);
			shmem = fpn_shmem_mmap(CAP_SHM_NAME, NULL, shm_size);
			if (shmem == NULL) {
				fpdebug_printf("failed creating shared memory\n");
				return -1;
			}
			fp_shared->cap_buf_offset = 0;
			fp_shared->cap_wrap = cap_wrap;
			fpdebug_printf("created capture buffer of %lu bytes\n", shm_size);
		} else {
			fpdebug_printf("buffer already created\n");
			return -1;
		}
		memset(shmem, 0, shm_size);
		fp_shared->cap_buf_size = shm_size;
	} else if (tokens == 0 && fp_shared->cap_buf_size) {
		fpdebug_printf("capture buffer of size %lu present\n",
			       fp_shared->cap_buf_size);
	} else {
		fpdebug_printf("invalid argument\n");
		return -1;
	}
	return 0;
}

static int tap_capture(char *tok)
{
	int tokens = gettokens(tok);
	int bpf_tokens_index = 3;
	struct bpf_program bpf_pcap;
	fp_bpf_filter_t bpf_fp;
	char *cmd, *ifce, *bpf_str;
	unsigned int bpf_str_size = 0, index;
	int i, ret = 0;
	fp_ifnet_t *ifp;
	bpf_u_int32 netmask = 0;
	int cap_len;


	if (tokens < bpf_tokens_index) {
		fpdebug_printf("usage: <on|off> <interface> <packet size> [bpf commands]\n");
		return -1;
	}

	if (fp_shared->cap_buf_size == 0) {
		fpdebug_printf("first, create the capture buffer using tap-buffer create <size[B|K|M|G]>\n");
		return -1;
	}

	cmd = chargv[0];
	ifce = chargv[1];
	cap_len = atoi(chargv[2]);

	if (cap_len <= 0)
		cap_len = 64 + sizeof(struct fp_tap_pkt);
	else
		cap_len = cap_len + sizeof(struct fp_tap_pkt);

	for (i = bpf_tokens_index; i < tokens; i++)
		bpf_str_size += strlen(chargv[i]) + 1;

	bpf_str_size++;

	bpf_str = malloc(sizeof(char) * bpf_str_size);
	*bpf_str = '\0';

	for (i = bpf_tokens_index; i < tokens; i++) {
		strncat(bpf_str, chargv[i], bpf_str_size);
		strncat(bpf_str, " ", 1);
	}
	ret = pcap_compile_nopcap(65535, DLT_EN10MB, &bpf_pcap,
				  bpf_str, 1, netmask);
	free(bpf_str);

	if (ret != 0) {
		fpdebug_printf("error compiling bpf byte code\n");
		return ret;
	}

	for (index = 0; index < bpf_pcap.bf_len; index++) {
		fp_filter_t *bf_fp;
		struct bpf_insn *bf_pcap = bpf_pcap.bf_insns;

		bf_fp = &bpf_fp.filters[index];
		bf_fp->code = bf_pcap->code;
		bf_fp->jt = bf_pcap->jt;
		bf_fp->jf = bf_pcap->jf;
		bf_fp->k = bf_pcap->k;
		bpf_pcap.bf_insns++;
	}

	if ((ifp = fp_getifnetbyname(ifce)) == NULL) {
		fpdebug_printf("bad interface name: %s\n", ifce);
		return -1;
	}

	bpf_fp.ifuid = ifp->if_ifuid;
	bpf_fp.num = bpf_pcap.bf_len;
	bpf_fp.status = BPF_FILTER_PERMANENT;
	if (strcmp(cmd, "on") == 0) {
		void *shmem;

		if (fp_shared->conf.s.do_tap_circular_buffer == 1) {
			fpdebug_printf("capture already enabled\n");
			return -1;
		}

		/* reset burrent buffer */
		shmem = fpn_shmem_mmap(CAP_SHM_NAME, NULL,
				       fp_shared->cap_buf_size);
		if (shmem == NULL) {
			fpdebug_printf("failed creating shared memory\n");
			return -1;
		}
		fp_shared->cap_buf_offset = 0;
		memset(shmem, 0, fp_shared->cap_buf_size);

		ret = fp_bpf_create(&bpf_fp);
		if (ret != 0) {
			fpdebug_printf("bpf_create failed ret=%d\n", ret);
			return -1;
		}

		fp_shared->cap_pkt_len = cap_len - sizeof(struct fp_tap_pkt);
		fp_shared->cap_cookie++;
		fp_shared->conf.s.do_tap_circular_buffer = 1;
		fp_shared->conf.w32.do_func |= FP_CONF_DO_TAP;

	} else if (strcmp(cmd, "off") == 0) {
		if (fp_shared->conf.s.do_tap_circular_buffer == 0) {
			fpdebug_printf("capture already disabled\n");
			return -1;
		}

		ret = fp_bpf_del(&bpf_fp);
		if (ret != 0) {
			fpdebug_printf("bpf_delete failed ret=%d\n", ret);
			return -1;
		}

		fp_shared->conf.s.do_tap_circular_buffer = 0;
		fp_shared->conf.w32.do_func &= ~FP_CONF_DO_TAP;

	} else {
		fpdebug_printf("unknown command: %s\n", cmd);
		fpdebug_printf("Valid commands are <on|off>\n");
		return -1;
	}

	fpdebug_printf("TAP circular buffer is ");
	print_tap_state(fp_shared->conf.s.do_tap_circular_buffer);
	fpdebug_printf("\n");

	return 0;
}
#endif
#endif /* CONFIG_MCORE_TAP_CIRCULAR_BUFFER */

#ifdef CONFIG_MCORE_IP
static int delete_route(char *tok)
{
	fp_ifnet_t *ifp;
	uint8_t rt_type;
	int numtokens;
	char *ip_str;
	uint32_t addr = 0;
	int prefix;
	char *prefix_str;
	uint32_t gw = 0;
	char *ifname;
	uint32_t ifuid;
	int res;

	numtokens = gettokens(tok);
	if (numtokens < 4) {
		fpdebug_fprintf (stderr, "wrong arguments: delete-route <ip> "
				 "<prefix length> <gateway> <ifname> [<type>]\n");
		return 0;
	}

	ip_str = chargv[0];
	res = fpdebug_inet_pton(AF_INET, ip_str, &addr);
	prefix = atoi(chargv[1]);
	prefix_str = chargv[2];
	ifname = chargv[3];
	ifp = fp_getifnetbyname(ifname);
	if (ifp == NULL) {
		fpdebug_fprintf(stderr, "unknown interface %s\n", ifname);
		return -1;
	}
	ifuid = ifp->if_ifuid;

	if (numtokens == 5)
		rt_type = atoi(chargv[4]);
	else
		rt_type = RT_TYPE_ROUTE;

	if (res > 0) {
		/* IPv4 address */
		int res2 = fpdebug_inet_pton(AF_INET, prefix_str, &gw);

		if (res2 <= 0) {
			fpdebug_printf("Malformed IPv4 address !\n");
		} else {
			fp_delete_route4_nhmark(default_vrfid,addr, prefix, gw, ifuid, rt_type, NULL);
		}
	} else {
		/* IPv6 address ? */
#ifdef CONFIG_MCORE_IPV6
		fp_in6_addr_t address;
		address.fp_s6_addr32[0] = 0;
		address.fp_s6_addr32[1] = 0;
		address.fp_s6_addr32[2] = 0;
		address.fp_s6_addr32[3] = 0;
		fp_in6_addr_t next2 = address;

		res = fpdebug_inet_pton(AF_INET6, ip_str, &address);
		int res2 = fpdebug_inet_pton(AF_INET6, prefix_str, &next2);
		if(res > 0 && res2 > 0)
			fp_delete_route6_nhmark(default_vrfid, &address, prefix, &next2, ifuid, rt_type, NULL);
		else
			fpdebug_printf("Malformed address !\n");
#endif
	}
	return 0;
}

static void
print_l2_state(uint8_t l2_state)
{
	fpdebug_printf(" ");
	switch(l2_state) {
	case L2_STATE_NONE:
		fpdebug_printf("NONE");
		break;
	case L2_STATE_INCOMPLETE:
		fpdebug_printf("INCOMPLETE");
		break;
	case L2_STATE_STALE:
		fpdebug_printf("STALE");
		break;
	case L2_STATE_REACHABLE:
		fpdebug_printf("REACHABLE");
		break;
	default:
		fpdebug_printf("UNKNOWN(%d)", l2_state);
		break;
	}
	return;
}

static void
dump_nhe4(fp_nh4_entry_t *nhe, fp_rt4_entry_t *rte, int idx)
{
	uint8_t rt_type = nhe->nh.rt_type;

	if (nhe->nh.nh_type == NH_TYPE_GW) {
		fpdebug_printf("GW/");
		print_rt_type(rt_type);
		fpdebug_printf(" ");
		print_addr(&nhe->nh_gw);
		fpdebug_printf(" ");
		print_mac((uint8_t *)&nhe->nh.nh_eth.ether_dhost);
		fpdebug_printf(" via ");
		print_via_iface(nhe->nh.nh_ifuid);
		print_l2_state (nhe->nh.nh_l2_state);
	} else {
		fpdebug_printf("IFACE/");
		print_rt_type(rt_type);
		if (nhe->nh_src) {
			fpdebug_printf(" src ");
			print_addr(&nhe->nh_src);
		}
		fpdebug_printf(" via ");
		print_via_iface(nhe->nh.nh_ifuid);
	}
#ifdef CONFIG_MCORE_NEXTHOP_MARKING
	if (nhe->nh.nh_mark)
		printf(" mark/mask %"PRIu32"/%"PRIu32"", nhe->nh.nh_mark, nhe->nh.nh_mask);
#endif
	/*
	 * Dump as part of rt_entry 
	 */
	if (rte) {
#if 0
		if (idx == FP_IPV4_NH_ROUTE_LOCAL)
			fpdebug_printf(" local");
		else if (idx == FP_IPV4_NH_ROUTE_BLACKHOLE)
			fpdebug_printf(" blackhole");
#endif
		fpdebug_printf(" (nh:%d)", idx);
	}
	else
		fpdebug_printf(" refcnt=%"PRIu32"", (uint32_t)nhe->nh.nh_refcnt);

	fpdebug_printf("\n");

	return ;
}
#endif

#ifdef CONFIG_MCORE_IPV6
static void
dump_nhe6(fp_nh6_entry_t *nhe, fp_rt6_entry_t *rte, int idx)
{
	uint8_t rt_type = nhe->nh.rt_type;

	if (nhe->nh.nh_type == NH_TYPE_GW) {
		fpdebug_printf("GW/");
		print_rt_type(rt_type);
		fpdebug_printf(" ");
		print_addr6(&nhe->nh_gw);
		fpdebug_printf(" ");
		print_mac((uint8_t *)&nhe->nh.nh_eth.ether_dhost);
		fpdebug_printf(" via ");
		print_via_iface(nhe->nh.nh_ifuid);
		print_l2_state (nhe->nh.nh_l2_state);
	} else {
		fpdebug_printf("IFACE/");
		print_rt_type(rt_type);
		if (!is_in6_addr_null(nhe->nh_src)) {
			fpdebug_printf(" src ");
			print_addr6(&nhe->nh_src);
		}
		fpdebug_printf(" via ");
		print_via_iface(nhe->nh.nh_ifuid);
	}
#ifdef CONFIG_MCORE_NEXTHOP_MARKING
	if (nhe->nh.nh_mark)
		printf(" mark/mask %"PRIu32"/%"PRIu32"", nhe->nh.nh_mark, nhe->nh.nh_mask);
#endif
	/*
	 * Dump as part of rt_entry
	 */
	if (rte) {
		/*
		 * idx < 0 means we are dumping the rt_nhc.
		 * here the refcnt is the one of the rt_entry
		 */
		if (idx < 0)  {
			fpdebug_printf(" refcnt=%"PRIu32, (uint32_t)rte->rt.rt_refcnt);
			fpdebug_printf(" (nh:%"PRIu32")", (uint32_t)nhe->nh.nh_refcnt);
		} else
			fpdebug_printf(" (nh:%d)", idx);
	} else
		fpdebug_printf(" refcnt=%"PRIu32, (uint32_t)nhe->nh.nh_refcnt);

	fpdebug_printf("\n");

	return ;
}
#endif /* CONFIG_MCORE_IPV6 */

#ifdef CONFIG_MCORE_IP
static int
__dump_rt (int dneigh, int rt)
{
	unsigned int i;
	int j;
	unsigned int min = 1;
	unsigned int max = FP_IPV4_NBRTENTRIES;
	if (rt) {
		min = rt;
		max = rt+1;
	}
	for (i = min; i < max ; i++) {
		fp_rt4_entry_t entry = fp_shared->fp_rt4_table[i];
		/* Ignore unused entries */
		if (entry.rt.rt_refcnt == 0)
			continue;
		if (dneigh == 0 && entry.rt.rt_neigh_index == 0)
			continue;
		for (j = 0; j < entry.rt.rt_nb_nh; j++ ) {
			int nh_index = entry.rt.rt_next_hop[j];

			if (j == 0) {
				fpdebug_printf("R[%06d] ", i);
			} else {
				fpdebug_printf("     -   ");
			}
			fpdebug_printf("vrfid %u ", entry.rt.rt_vrfid);
			dump_nhe4(&fp_shared->fp_nh4_table[nh_index], &entry, nh_index);
		}
	}
	return 0;
}

/* dump-neighbours all will dump neigh info cached in routes entry */
static int dump_neighbours(char *tok)
{
	int rt = 0;
	if (gettokens(tok) == 1) {
		rt = atoi(chargv[0]);
		if ((rt == 0) || (rt >= FP_IPV4_NBRTENTRIES))
			return 0;
	}
	return (__dump_rt(0, rt));
}

static int dump_rt_table(char *tok)
{
	int rt = 0;
	if (gettokens(tok) == 1) {
		rt = atoi(chargv[0]);
		if ((rt == 0) || (rt >= FP_IPV4_NBRTENTRIES))
			return 0;
	}
	return (__dump_rt(1, rt));
}
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
static int
__dump_rt6 (int dneigh, int rt)
{
	unsigned int i;
	int j;
	unsigned int min = 1;
	unsigned int max = FP_IPV6_NBRTENTRIES;
	if (rt) {
		min = rt;
		max = rt+1;
	}
	for (i = min; i < max ; i++) {
		fp_rt6_entry_t entry = fp_shared->fp_rt6_table[i];
		/* Ignore unused entries */
		if (entry.rt.rt_refcnt == 0)
			continue;
		if (dneigh == 0 && entry.rt.rt_neigh_index == 0)
			continue;
		for (j = 0; j < entry.rt.rt_nb_nh; j++ ) {
			int nh_index = entry.rt.rt_next_hop[j];

			if (j == 0)
				fpdebug_printf("R6[%06d]", i);
			else
				fpdebug_printf("     -  ");
			dump_nhe6(&fp_shared->fp_nh6_table[nh_index], &entry, nh_index);
		}
	}
	return 0;
}

/* dump-neighbours all will dump neigh info cached in routes entry */
static int dump_neighbours6(char *tok)
{
	int rt = 0;
	if (gettokens(tok) == 1) {
		rt = atoi(chargv[0]);
		if ((rt == 0) || (rt >= FP_IPV6_NBRTENTRIES))
			return 0;
	}
	return (__dump_rt6(0, rt));
}

static int dump_rt6_table(char *tok)
{
	int rt = 0;
	if (gettokens(tok) == 1) {
		rt = atoi(chargv[0]);
		if ((rt == 0) || (rt >= FP_IPV6_NBRTENTRIES))
			return 0;
	}
	return (__dump_rt6(1, rt));
}
#endif

#ifdef CONFIG_MCORE_IP
static int dump_nh_table(char *tok)
{
	unsigned int i;
	unsigned int min = 1;
	unsigned int max = FP_IPV4_NBNHENTRIES;

	if (gettokens(tok) == 1) {
		min = atoi(chargv[0]);
		if ((min == 0) || (min >= FP_IPV4_NBNHENTRIES))
			return 0;
		max = min + 1;
	}
	for (i = min; i < max ; i++) {
		fp_nh4_entry_t nhe = fp_shared->fp_nh4_table[i];
		if (!nhe.nh.nh_refcnt)
			continue;
		fpdebug_printf("N4[%04d]", i);
		dump_nhe4(&nhe, NULL, i);
	}
	return 0;
}
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
static int dump_nh6_table (char *tok)
{
	unsigned int i;
	char buf[16];
	unsigned int min = 1;
	unsigned int max = FP_IPV6_NBNHENTRIES;

	if (gettokens(tok) == 1) {
		min = atoi(chargv[0]);
		if ((min == 0) || (min >= FP_IPV6_NBNHENTRIES))
			return 0;
		max = min+1;
	}
	for (i = min; i < max ; i++) {
		fp_nh6_entry_t nhe = fp_shared->fp_nh6_table[i];
		if (!nhe.nh.nh_refcnt)
			continue;
		snprintf (buf, sizeof(buf), "N6[%04d]", i);
		fpdebug_printf("%s ", buf);
		dump_nhe6 (&nhe, NULL, i);
	}
	return 0;
}
#endif

#ifdef CONFIG_MCORE_IP
static void print_rt_type(uint8_t rt_type)
{
	switch(rt_type) {
	case RT_TYPE_ROUTE:
		fpdebug_printf("ROUTE");
		break;
	case RT_TYPE_NEIGH:
		fpdebug_printf("NEIGH");
		break;
	case RT_TYPE_ADDRESS:
		fpdebug_printf("ADDRESS");
		break;
	case RT_TYPE_ROUTE_LOCAL:
		fpdebug_printf("LOCAL");
		break;
	case RT_TYPE_ROUTE_CONNECTED:
		fpdebug_printf("CONNECTED");
		break;
	case RT_TYPE_ROUTE_BLACKHOLE:
		fpdebug_printf("BLACKHOLE");
		break;
	default: {
		fpdebug_printf("UNKNOWN(%d)", rt_type);
		break;
		 }
	}
}
#endif

/*
 * Convert a prefix length into a 32 bit prefix
 * (network order)
 */
static inline uint32_t preflen2mask(int i)
{
	uint32_t mask = 0;

	if (unlikely(i>32))
		mask = 0xffffffff;

	else if (i>0)
		mask = ((uint32_t)0xffffffff) << (32 - i);

	return htonl(mask);
}

/* do not display the whole chain of routes with decreasing prefix lengths */
#define F_NO_ROUTE_CHAIN 0x01

#ifdef CONFIG_MCORE_IP
static void __dump_route_entry(uint32_t rt_index, uint32_t network,
		fp_rt4_entry_t e, fp_nh4_entry_t *sel, uint8_t flags)
{
	fp_nh4_entry_t nhe = fp_shared->fp_nh4_table[e.rt.rt_next_hop[0]];
	int i=0;

	if (sel) {
		fpdebug_printf(" Prio: ADDR=%d, PREF=%d, NEIGH=%d, CNX=%d\n",
			FP_ECMP_PRIO_ADDRESS,
			FP_ECMP_PRIO_PREFERRED,
			FP_ECMP_PRIO_NEIGH,
			FP_ECMP_PRIO_CONNECTED);
	}

	__BF_NUL();
#ifdef CONFIG_MCORE_RT4_WITH_PREFIX
	(void)network;
	print_addr(&e.rt4_prefix);
#else
	/* bits not part of the mask are set to zero */
	network &= preflen2mask(e.rt.rt_length);
	print_addr(&network);
#endif
	fpdebug_printf("/%"PRIu8"", e.rt.rt_length);
	fpdebug_printf(" ");
	if (e.rt.rt_nb_nh > 1) {
		fpdebug_printf(" Multipath Entry");
	} else if (sel) {
		/*
		 * If sel is provided, more detail on the route
		 * is dispalyed later
		 */
		fpdebug_printf(" Single Entry");
	} else {
		fpdebug_printf(" [%02d]  ", e.rt.rt_next_hop[0]);
		print_rt_type(nhe.nh.rt_type);
		if (nhe.nh.rt_type == RT_TYPE_ROUTE || 
		    nhe.nh.rt_type == RT_TYPE_NEIGH) {
			if (nhe.nh_gw) {
				fpdebug_printf(" gw ");
				print_addr(&nhe.nh_gw);
			}
		}

		if (e.rt.rt_neigh_index == e.rt.rt_next_hop[0])
			fpdebug_printf (" (N)");

		if (nhe.nh.nh_ifuid) {
			fpdebug_printf(" via ");
			print_via_iface(nhe.nh.nh_ifuid);
		}
		if (e.rt.rt_neigh_index && 
			(e.rt.rt_neigh_index != e.rt.rt_next_hop[0]))
			fpdebug_printf (" !rt_neigh_index KO! %"PRIu32"", e.rt.rt_neigh_index);
	}

	if (flags & F_NO_ROUTE_CHAIN)
		fpdebug_printf(" (%"PRIu32")", rt_index);
	else {
		fpdebug_printf(" /%"PRIu8" (%"PRIu32")", e.rt.rt_length, rt_index);
		fp_rt4_entry_t *rt = &e;
		__BF_SET((int)rt->rt.rt_length);
		while (rt->rt.rt_next) {
			rt = &fp_shared->fp_rt4_table[rt->rt.rt_next];
			fpdebug_printf(" -> /%"PRIu8, rt->rt.rt_length);
			fpdebug_printf(" (%d)", (int)(rt - fp_shared->fp_rt4_table));
			if (__BF_TST((int)rt->rt.rt_length)) {
				fpdebug_printf("ERROR: L2 Loop detected");
				break;
			}
			__BF_SET((int)rt->rt.rt_length);
		}
	}

	fpdebug_printf("\n");

	if ((e.rt.rt_nb_nh > 1) || sel) {
		uint8_t best_prio, refresh_prio;
		uint8_t local_prio, neigh4_prio;
		int neigh_found = 0;

		/*
		 * Neighbor extra priority can affect the 'best prio' only
		 * if the first next-hop is a neighbor. At least with the
		 * current weighting values
		 */
		best_prio = fp_best_nh4_prio (&e)+
			fp_nh4_neigh_prio (&e,
				&fp_shared->fp_nh4_table[e.rt.rt_next_hop[0]]);
		if (sel) {
			fpdebug_printf(" Preferred: %"PRIu8, e.rt.rt_nb_nhp);
			fpdebug_printf(" (prio %"PRIu8")", best_prio);
			fpdebug_printf("   Total: %"PRIu8, e.rt.rt_nb_nh);
			fpdebug_printf("\n");
		}
		for (i=0; i<e.rt.rt_nb_nh; i++) {
			int pref=0;
			fpdebug_printf("     [%02d]  ", e.rt.rt_next_hop[i]);
			if (i<e.rt.rt_nb_nhp) {
				pref=1;
				fpdebug_printf("#");
			} else
				fpdebug_printf(" ");
			if (sel == &fp_shared->fp_nh4_table[e.rt.rt_next_hop[i]])
				fpdebug_printf("> ");
			else
				fpdebug_printf("  ");
			if (e.rt.rt_neigh_index == e.rt.rt_next_hop[i]) {
				fpdebug_printf("N");
				neigh_found = 1;
			} else
				fpdebug_printf(" ");
			nhe = fp_shared->fp_nh4_table[e.rt.rt_next_hop[i]];
			neigh4_prio = fp_nh4_neigh_prio (&e, &nhe);
			local_prio = nhe.nh.nh_priority + neigh4_prio;
			if (neigh4_prio)
				fpdebug_printf(" (p=%03d+%03d)  ", nhe.nh.nh_priority, neigh4_prio);
			else
				fpdebug_printf(" (p=%03d)  ", nhe.nh.nh_priority);
			print_rt_type(nhe.nh.rt_type);
			if (nhe.nh.rt_type == RT_TYPE_ROUTE ||
			    nhe.nh.rt_type == RT_TYPE_NEIGH) {
				if (nhe.nh_gw) {
					fpdebug_printf(" gw ");
					print_addr(&nhe.nh_gw);
				}
			}
			if (nhe.nh.nh_ifuid) {
				fpdebug_printf(" via ");
				print_via_iface(nhe.nh.nh_ifuid);
			}

			refresh_prio = fp_nh_priority (&nhe.nh);
			if (refresh_prio != nhe.nh.nh_priority)
				fpdebug_printf(" !Wrong prio != %d!", refresh_prio);
			if (pref && (local_prio != best_prio))
				fpdebug_printf(" !Pref KO undue)!");
			if (!pref && (local_prio >= best_prio))
				fpdebug_printf(" !Pref KO (missing)!");
			fpdebug_printf("\n");
		}
		if (e.rt.rt_neigh_index &&  (neigh_found == 0)) {
			fpdebug_printf("       ");
			fpdebug_printf ("  !rt_neigh_index KO! %"PRIu32"\n", e.rt.rt_neigh_index);
		}
	}
}

static void dump_route_entry(uint32_t rt_index, uint32_t network,
		fp_rt4_entry_t e, fp_nh4_entry_t *sel)
{
	__dump_route_entry(rt_index, network, e, sel, 0);
}
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
static void
__dump_route_entry6(uint32_t rt_index, fp_in6_addr_t *network,
		    fp_rt6_entry_t e, fp_nh6_entry_t *sel, uint8_t flags)
{
	fp_nh6_entry_t nhe = fp_shared->fp_nh6_table[e.rt.rt_next_hop[0]];
	int i=0;

	if (sel) {
		fpdebug_printf(" Prio: ADDR=%d, PREF=%d, CNX=%d\n",
			FP_ECMP_PRIO_ADDRESS,
			FP_ECMP_PRIO_PREFERRED,
			FP_ECMP_PRIO_CONNECTED);
	}

	__BF_NUL();

	print_addr6(network);
	fpdebug_printf("/%"PRIu8, e.rt.rt_length);
	fpdebug_printf(" ");
	if (e.rt.rt_nb_nh > 1) {
		fpdebug_printf(" Multipath Entry");
	} else if (sel) {
		/*
		 * If sel is provided, more detail on the route
		 * is dispalyed later
		 */
		fpdebug_printf(" Single Entry");
	} else {
		fpdebug_printf(" [%02d]  ", e.rt.rt_next_hop[0]);
		print_rt_type(nhe.nh.rt_type);
		if (nhe.nh.rt_type == RT_TYPE_ROUTE ||
		    nhe.nh.rt_type == RT_TYPE_NEIGH) {
			fpdebug_printf(" gw ");
			print_addr6(&nhe.nh_gw);
		}
		if (e.rt.rt_neigh_index == e.rt.rt_next_hop[0])
			fpdebug_printf (" (N)");
		if (nhe.nh.nh_ifuid) {
			fpdebug_printf(" via ");
			print_via_iface(nhe.nh.nh_ifuid);
		}
	}

	if (flags & F_NO_ROUTE_CHAIN)
		fpdebug_printf(" (%"PRIu32")", rt_index);
	else {
		fpdebug_printf(" /%"PRIu8" (%"PRIu32")", e.rt.rt_length, rt_index);
		fp_rt6_entry_t *rt = &e;
		__BF_SET((int)rt->rt.rt_length);
		while (rt->rt.rt_next) {
			rt = &fp_shared->fp_rt6_table[rt->rt.rt_next];
			fpdebug_printf("-> /%"PRIu8, rt->rt.rt_length);
			fpdebug_printf(" (%d)", (int)(rt - fp_shared->fp_rt6_table));
			if (__BF_TST((int)rt->rt.rt_length)) {
				fpdebug_printf("ERROR: L2 Loop detected");
				break;
			}
			__BF_SET((int)rt->rt.rt_length);
		}
	}
	fpdebug_printf("\n");

	if ((e.rt.rt_nb_nh > 1) || sel) {
		uint8_t best_prio, refresh_prio;
		int neigh_found = 0;

		best_prio = fp_best_nh6_prio (&e);
		if (sel) {
			fpdebug_printf(" Preferred: %"PRIu8, e.rt.rt_nb_nhp);
			fpdebug_printf(" (prio %"PRIu8")", best_prio);
			fpdebug_printf("   Total: %"PRIu8, e.rt.rt_nb_nh);
			fpdebug_printf("\n");
		}
		for (i=0; i<e.rt.rt_nb_nh; i++) {
			int pref=0;
			fpdebug_printf("     [%02d]  ", e.rt.rt_next_hop[i]);
			if (i<e.rt.rt_nb_nhp) {
				pref=1;
				fpdebug_printf("#");
			} else
				fpdebug_printf(" ");
			if (sel == &fp_shared->fp_nh6_table[e.rt.rt_next_hop[i]])
				fpdebug_printf("> ");
			else
				fpdebug_printf("  ");
			if (e.rt.rt_neigh_index == e.rt.rt_next_hop[i]) {
				fpdebug_printf("N");
				neigh_found = 1;
			} else
				fpdebug_printf(" ");
			nhe = fp_shared->fp_nh6_table[e.rt.rt_next_hop[i]];
			fpdebug_printf(" (p=%03d)  ", nhe.nh.nh_priority);
			print_rt_type(nhe.nh.rt_type);
			if (nhe.nh.rt_type == RT_TYPE_ROUTE || 
				nhe.nh.rt_type == RT_TYPE_NEIGH) {
				if (!is_in6_addr_null(nhe.nh_gw)) {
					fpdebug_printf(" gw ");
					print_addr6(&nhe.nh_gw);
				}
			}
			if (nhe.nh.nh_ifuid) {
				fpdebug_printf(" via ");
				print_via_iface(nhe.nh.nh_ifuid);
			}
			refresh_prio = fp_nh_priority (&nhe.nh);
			if (refresh_prio != nhe.nh.nh_priority)
				fpdebug_printf(" !Wrong prio != %d!", refresh_prio);
			if (pref && (fp_nh_priority(&(nhe.nh)) != best_prio))
				fpdebug_printf(" !Pref KO (undu)!");
			if (!pref && (fp_nh_priority(&(nhe.nh)) >= best_prio))
				fpdebug_printf(" !Pref KO (missing)!");
			fpdebug_printf("\n");
		}
		if (e.rt.rt_neigh_index &&  (neigh_found == 0)) {
			fpdebug_printf("       ");
			fpdebug_printf ("  !rt_neigh_index KO! %"PRIu32"\n", e.rt.rt_neigh_index);
		}
	}
}
static void dump_route_entry6(uint32_t rt_index, fp_in6_addr_t *network,
		fp_rt6_entry_t e, fp_nh6_entry_t *sel)
{
	__dump_route_entry6(rt_index, network, e, sel, 0);
}


/* Set bits */
static int
_set_in6_bits(fp_in6_addr_t *addr, uint32_t value, uint8_t level)
{
	uint32_t sub_addr;
	uint32_t mask;
	uint8_t shift;
	uint8_t start;
	uint8_t cell;
	uint8_t width = fp_shared->fp_cumulative_width6[level];

	/* we'll work with in6_addr.s6_addr32 field
	 * remember that address is stored in network-order in this table
	 * -> s6_addr32[0] are the most significant bits, in network-order too
	 */
	if(width <= 32) {
		start = 0;
		cell = 0;
	} else if(width <= 64) {
		start = 32;
		cell = 1;
	} else if(width <= 96) {
		start = 64;
		cell = 2;
	} else {
		start = 96;
		cell = 3;
	} /* width */

	/* we need to detect overlapping */
	if(width - FP_IPV6_LAYER_WIDTH(level) < start) {
		/* Overlapping of bits on two 32-bits words */

		/* least significant bits of value are MSB of the second word */
		uint8_t nb_bits = width - start;
		uint32_t v;
		sub_addr = ntohl(addr->fp_s6_addr32[cell]);
		shift = 32-nb_bits;
		/* Clear bits */
		mask = ~((0xFFFFFFFF>>shift)<<shift);
		sub_addr &= mask;
		/* Set bits */
		mask = 0xFFFFFFFF >> shift;
		v = (htonl(value) & mask) << shift;
		sub_addr |= v;
		addr->fp_s6_addr32[cell] = htonl(sub_addr);

		/* most significant bits are in LSB of the first word 
		 * -> put them in MSB of the result
		 */
		sub_addr = ntohl(addr->fp_s6_addr32[cell-1]);
		shift = nb_bits;
		nb_bits = FP_IPV6_LAYER_WIDTH(level) - nb_bits;
		/* Clear bits */
		mask = ~(0xFFFFFFFF >> (32-nb_bits));
		sub_addr &= mask;
		/* Set bits */
		v = htonl(value) >> shift;
		sub_addr |= v;
		addr->fp_s6_addr32[cell-1] = htonl(sub_addr);
	} else {
		/* all right, all bits are in the same 32-bits word */
		sub_addr = ntohl(addr->fp_s6_addr32[cell]);
		shift = (32+start)-width;
		/* Clear bits */
		mask = ~((0xFFFFFFFF >> (32-FP_IPV6_LAYER_WIDTH(level)))<<shift);
		sub_addr &= mask;
		/* Set bits */
		value = value << shift;
		sub_addr |= value;
		addr->fp_s6_addr32[cell] = htonl(sub_addr);
		//std::cout<<"mask:"<<mask<<" value:"<<value<<" "<<addr->s6_addr32[cell]<<"(cell "<<cell<<")"<<std::endl;
	}
	return 0;
}

static void
__clear(fp_in6_addr_t * addr, uint8_t level)
{
	uint32_t sub_addr;
	uint32_t mask;
	uint8_t start;
	uint8_t cell;
	uint8_t i;
	uint8_t width = fp_shared->fp_cumulative_width6[level];
	uint8_t length = FP_IPV6_LAYER_WIDTH(level);

	/* we'll work with in6_addr.s6_addr32 field
	 * remember that address is stored in network-order in this table
	 * -> s6_addr32[0] are the most significant bits, in network-order too
	 */
	if(width <= 32) {
		cell = 0;
	} else if(width <= 64) {
		cell = 1;
	} else if(width <= 96) {
		cell = 2;
	} else {
		cell = 3;
	} /* width */

	start = width-length;

	/* /!\ << is NOT surcharged to work with uint*_t /!\ */
	//printf("level %d, start %d, width %d, cell %d, length %d\n",
	//	level, start, width, cell, length);

	for(i = cell; i < 4; i++) {
		if(start < (i+1)*32) {
			sub_addr = ntohl(addr->fp_s6_addr32[i]);
			//printf(" -> i=%d, start=%d, val=%u ", i, start, sub_addr);
			if((i > cell) || (i*32 == start))
				sub_addr = 0;
			else {
				mask = 0xFFFFFFFF << ((i+1)*32-start);
				//printf("mask=%x ", mask);
				sub_addr &= mask;
			}
			//printf("-> val=%u\n", sub_addr);
			addr->fp_s6_addr32[i] = htonl(sub_addr);
		}
	}
}

static int __dump_routes_recur(const fp_table_entry_t * entries, const int rt_type, const uint32_t rt_idx, const int level, fp_in6_addr_t * network, uint32_t *bitmap)
{
	int i;
	char buf[16];

	for(i = 0; i < (1<<FP_IPV6_LAYER_WIDTH(level)); i++) {
		__clear(network, level);
		fp_table_entry_t e = entries[i];

		if(e.index != RT_INDEX_UNUSED) {

			_set_in6_bits(network, i, level);
			if(e.rt == RT_ROUTE) {
//				print_addr6(network);
//				printf("Entry n.%d, rt=%u, index=%u\n", i, e.rt, e.index);

				fp_rt6_entry_t r = fp_shared->fp_rt6_table[e.index];
				if (!rt_idx || (rt_idx == e.index)) {
					if (bitmap) {
						uint32_t rt6_index;
						uint32_t rt6_next;
						for (rt6_index = e.index; rt6_index;
								rt6_index = rt6_next)
						{
							r = fp_shared->fp_rt6_table[rt6_index];
							rt6_next = r.rt.rt_next;

							if (!select_type6(rt_type, &r))
								continue;

							if (__BMAP_TST(bitmap, rt6_index))
								continue;
							__BMAP_SET(bitmap, rt6_index);
							__dump_route_entry6(rt6_index, network, r, NULL,
									F_NO_ROUTE_CHAIN);
						}
					} else {
						/* To be improved as for IPv4 */
						snprintf (buf, sizeof(buf), "%06d", i);
						fpdebug_printf("E[%s]", buf);
						dump_route_entry6(e.index, network, r, NULL);
						if (rt_idx)
							return 1;
					}
				}
				/* 
				 * Dump done, goto next
				 */
				continue;
			}
			else {
				if(level < FP_IPV6_NBLAYERS-1) {
					fp_in6_addr_t deeper = *network;
					uint32_t index = fp_get_table6(level+1)[e.index].entries;
					if(__dump_routes_recur(fp_get_entries6(level+1)+index,
								rt_type, rt_idx, level+1,
								&deeper, bitmap))
						return 1;
				} /* level */
			} /* RT_ROUTE */
		} /* RT_UNUSED */
	} /* FOR */
	return 0;
}

static int __dump_routes6(uint16_t vrfid, int rt_type, uint32_t rt_idx, uint32_t *bitmap)
{
	fp_table_entry_t *entries;
	fp_in6_addr_t addr6;

	addr6.fp_s6_addr32[0] = 0;
	addr6.fp_s6_addr32[1] = 0;
	addr6.fp_s6_addr32[2] = 0;
	addr6.fp_s6_addr32[3] = 0;
	entries = fp_get_entries6(0)+
		fp_get_table6(0)[FP_IPV6_TABLE_START+vrfid].entries;
	__dump_routes_recur(entries, rt_type, rt_idx, 0, &addr6, bitmap);
	return 0;
}
#endif /* CONFIG_MCORE_IPV6 */

#ifdef CONFIG_MCORE_IP
/*
 * dumps the full forwarding table, or a subset of it
 *
 * Note: if a route type (rt_type) or a route entry (rt_idx)
 *       is specified, the routes matching these parameters
 *       will only be displayed if they are not hidden by a
 *       shorter prefix route.
 */
static int __dump_routes(uint16_t vrfid, int rt_type, uint32_t rt_idx, uint32_t *bitmap)
{
	fp_table_entry_t *entries;
	unsigned int i = 0;
	int j, k;
#ifdef CONFIG_MCORE_RT_IP_BASE8
	int z;
#endif
	uint32_t network;
	uint32_t entry_index;
	fp_rt4_entry_t e;
	uint32_t vrf_idx;

	/* Level 0 */
#ifdef CONFIG_MCORE_RT_IP_BASE8
	vrf_idx = fp_shared->fp_8_table[vrfid].entries;
	for (i = 0; i < 1<<8; ++i)
#else
	vrf_idx = fp_shared->fp_16_table[vrfid].entries;
	for (i = 0; i < 1<<16; ++i)
#endif
	{
#ifdef CONFIG_MCORE_RT_IP_BASE8
		entries = &fp_shared->fp_8_entries[vrf_idx];
		entry_index = i;
		if (entries[entry_index].index) {
			fp_table_entry_t e0 = entries[entry_index];
			if (e0.rt != RT_ROUTE)
				goto Level0b;
			if (bitmap) {
				uint32_t rt4_index;
				uint32_t rt4_next;

				for (rt4_index = e0.index; rt4_index;
						rt4_index = rt4_next)
				{
					e = fp_shared->fp_rt4_table[rt4_index];
					rt4_next = e.rt.rt_next;
					if (!select_type4(rt_type, &e))
						continue;

					if (__BMAP_TST(bitmap, rt4_index))
						continue;
					__BMAP_SET(bitmap, rt4_index);
					network = htonl (i << 24);
					__dump_route_entry(rt4_index, network, e, NULL,
							F_NO_ROUTE_CHAIN);
				}
				/* 
				 * Dump done, goto next
				 */
				continue;
			} else /* !bitmap */ {
				e = fp_shared->fp_rt4_table[e0.index];
				if (!select_type4(rt_type, &e)) {
					if (rt_idx && (rt_idx == e0.index))
						return 0;
					continue;
				}
				network = htonl (i << 24);
				/* display forwarding table entry id as a prefix */
				fpdebug_printf("E[");
				print_addr_bytes(&network, 1);
				fpdebug_printf("] ");

				if (!rt_idx || (rt_idx == e0.index)) {
					dump_route_entry(e0.index, network, e, NULL);
					if (rt_idx)
						return 0;
				}
				/* 
				 * Dump done, goto next
				 */
				continue;
			}
Level0b:
			/*
			 * Dwelve into next table level
			 */
			for (z= 0; z < 256; ++z) {
				entries = fp_shared->fp_8_entries;
				entry_index = fp_shared->fp_8_table[e0.index].entries+z;
#else
				entries = &fp_shared->fp_16_entries[vrf_idx];
				entry_index = i;
#endif
				if (entries[entry_index].index) {
					fp_table_entry_t e1 = entries[entry_index];
					if (e1.rt != RT_ROUTE)
						goto Level1;
					if (bitmap) {
						uint32_t rt4_index;
						uint32_t rt4_next;

						for (rt4_index = e1.index; rt4_index;
								rt4_index = rt4_next)
						{
							e = fp_shared->fp_rt4_table[rt4_index];
							rt4_next = e.rt.rt_next;

							if (!select_type4(rt_type, &e))
								continue;

							if (__BMAP_TST(bitmap, rt4_index))
								continue;
							__BMAP_SET(bitmap, rt4_index);

#ifdef CONFIG_MCORE_RT_IP_BASE8
							network = htonl((i << 24) + (z<<16));
#else
							network = htonl((i << 16));
#endif

							__dump_route_entry(rt4_index, network, e, NULL,
									F_NO_ROUTE_CHAIN);
						}
						/* 
						 * Dump done, goto next
						 */
						continue;

					} else /* !bitmap */ {
						e = fp_shared->fp_rt4_table[e1.index];
						if (!select_type4(rt_type, &e)) {
							if (rt_idx && (rt_idx == e1.index))
								return 0;
							continue;
						}
#ifdef CONFIG_MCORE_RT_IP_BASE8
						network = htonl((i << 24) + (z<<16));
#else
						network = htonl((i << 16));
#endif
						/* display forwarding table entry id as a prefix */
						fpdebug_printf("E[");
						print_addr_bytes(&network, 2);
						fpdebug_printf("] ");

						if (!rt_idx || (rt_idx == e1.index)) {
							dump_route_entry(e1.index, network, e, NULL);
							if (rt_idx)
								return 0;
						}
						/* 
						 * Dump done, goto next
						 */
						continue;
					}
Level1:
					/*
					 * Dwelve into next table level
					 */
					for (j = 0; j < 256; ++j) {
						entries = fp_shared->fp_8_entries;
						fp_table_entry_t e2;
						entry_index = fp_shared->fp_8_table[e1.index].entries+j;
						e2 = entries[entry_index];
						if (e2.index == 0)
							continue;
						if (e2.rt != RT_ROUTE)
							goto Level2;
						if (bitmap) {
							uint32_t rt4_index;
							uint32_t rt4_next;

							for (rt4_index = e2.index; rt4_index;
									rt4_index = rt4_next)
							{
								e = fp_shared->fp_rt4_table[rt4_index];
								rt4_next = e.rt.rt_next;

								if (!select_type4(rt_type, &e))
									continue;

								if (__BMAP_TST(bitmap, rt4_index))
									continue;
								__BMAP_SET(bitmap, rt4_index);

#ifdef CONFIG_MCORE_RT_IP_BASE8
								network = htonl((i << 24) + (z<<16) + (j<<8));
#else
								network = htonl((i << 16) + (j<<8));
#endif

								__dump_route_entry(rt4_index, network, e, NULL,
										F_NO_ROUTE_CHAIN);
							}
							/* 
							 * Dump done, goto next
							 */
							continue;

						} else /* !bitmap */ {
							e = fp_shared->fp_rt4_table[e2.index];
							if (!select_type4(rt_type, &e)) {
								if (rt_idx && (rt_idx == e2.index))
									return 0;
								continue;
							}
#ifdef CONFIG_MCORE_RT_IP_BASE8
							network = htonl((i << 24) + (z<<16) + (j<<8));
#else
							network = htonl((i << 16) + (j<<8));
#endif
							/* display forwarding table entry id as a prefix */
							fpdebug_printf("E[");
							print_addr_bytes(&network, 3);
							fpdebug_printf("] ");

							if (!rt_idx || (rt_idx == e2.index)) {
								dump_route_entry(e2.index, network, e, NULL);
								if (rt_idx)
									return 0;
							}
							/* 
							 * Dump done, goto next
							 */
							continue;
						}
Level2:
						/*
						 * Dwelve into next table level
						 */
						for (k = 0; k < 256; ++k) {
							fp_table_entry_t e3;
							entries = fp_shared->fp_8_entries;
							entry_index = fp_shared->fp_8_table[e2.index].entries+k;
							e3 = entries[entry_index];
							if (e3.index == 0)
								continue;
							if (e3.rt != RT_ROUTE)
								continue;
							if (bitmap) {
								uint32_t rt4_index;
								uint32_t rt4_next;

								for (rt4_index = e3.index; rt4_index;
										rt4_index = rt4_next)
								{
									e = fp_shared->fp_rt4_table[rt4_index];
									rt4_next = e.rt.rt_next;

									if (!select_type4(rt_type, &e))
										continue;

									if (__BMAP_TST(bitmap, rt4_index))
										continue;
									__BMAP_SET(bitmap, rt4_index);

#ifdef CONFIG_MCORE_RT_IP_BASE8
									network = htonl((i << 24) + (z<<16) + (j<<8) + k);
#else
									network = htonl((i << 16) + (j<<8) + k);
#endif

									__dump_route_entry(rt4_index, network, e, NULL,
											F_NO_ROUTE_CHAIN);
								}
								/* 
								 * Dump done, goto next
								 */
								continue;

							} else /* !bitmap */ {
								e = fp_shared->fp_rt4_table[e3.index];
								if (!select_type4(rt_type, &e)) {
									if (rt_idx && (rt_idx == e3.index))
										return 0;
									continue;
								}
#ifdef CONFIG_MCORE_RT_IP_BASE8
								network = htonl((i << 24) + (z<<16) + (j<<8) + k);
#else
								network = htonl((i << 16) + (j<<8) + k);
#endif
								/* display forwarding table entry id as a prefix */
								fpdebug_printf("E[");
								print_addr_bytes(&network, 4);
								fpdebug_printf("] ");

								if (!rt_idx || (rt_idx == e3.index)) {
									dump_route_entry(e3.index, network, e, NULL);
									if (rt_idx)
										return 0;
								}
							}
						}
					}
				}
#ifdef CONFIG_MCORE_RT_IP_BASE8
			} /* for (z, ...) */
		} /* if at level 0 */
#endif
	}
	return 0;
}

static int route_sel (char *tok)
{
	int rt_type;
	char *arg = tok;
	rt_type = atoi(tok);
	if (strcmp(arg, "all") == 0)
		rt_type = -1;
	else if (strcmp(arg, "fpm") == 0)
		rt_type = -2;
	else if (strcmp(arg, "neigh") == 0)
		rt_type = RT_TYPE_NEIGH;
	else if (strcmp(arg, "local") == 0)
		rt_type = RT_TYPE_ROUTE_LOCAL;
	else if (strcmp(arg, "connected") == 0)
		rt_type = RT_TYPE_ROUTE_CONNECTED;
	else if (strcmp(arg, "black") == 0)
		rt_type = RT_TYPE_ROUTE_BLACKHOLE;
	return rt_type;
}
static int dump_routes(char *tok)
{
	int rt_type = -255;

	if (gettokens(tok) == 1)
		rt_type = route_sel (tok);
	if (rt_type == -255)
		__dump_routes (default_vrfid, RT_TYPE_ROUTE, 0, NULL);
	else
		__dump_routes (default_vrfid, rt_type, 0, NULL);
	return 0;
}

static int dump_user(char *tok)
{
	int rt_type = -255;
	uint32_t bitmap[(FP_IPV4_NBRTENTRIES+31)/32];

	memset(bitmap, 0, sizeof(bitmap));

	PRINT_FIB_HELPER;
	if (gettokens(tok) == 1)
		rt_type = route_sel (tok);
	if (rt_type == -2) {
#ifndef __FastPath__
		fpdebug_printf ("FPM dump for the whole table\n");
		fpm_rt4_entries_to_cmd(fp_shared->fp_rt4_table);
#else
		fpdebug_printf ("Not supported in embedded fpdebug\n");
#endif
	}
	else if (rt_type == -255)
		__dump_routes (default_vrfid, RT_TYPE_ROUTE, 0, bitmap);
	else
		__dump_routes (default_vrfid, rt_type, 0, bitmap);

	return 0;
}
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
static int dump_routes6(char *tok)
{
	int rt_type = -255;

	if (gettokens(tok) == 1)
		rt_type = route_sel (tok);
	if (rt_type == -255)
		__dump_routes6 (default_vrfid, RT_TYPE_ROUTE, 0, NULL);
	else
		__dump_routes6 (default_vrfid, rt_type, 0, NULL);
	return 0;
}

static int dump_user6(char *tok)
{
	int rt_type = -255;
	uint32_t bitmap[(FP_IPV6_NBRTENTRIES+31)/32];

	memset(bitmap, 0, sizeof(bitmap));

	PRINT_FIB_HELPER;
	if (gettokens(tok) == 1)
		rt_type = route_sel (tok);
	if (rt_type == -2) {
#ifndef __FastPath__
		fpdebug_printf ("FPM dump for the whole table\n");
		fpm_rt6_entries_to_cmd(fp_shared->fp_rt6_table);
#else
		fpdebug_printf ("Not supported in embedded fpdebug\n");
#endif
	}
	else if (rt_type == -255)
		__dump_routes6(default_vrfid, RT_TYPE_ROUTE, 0, bitmap);
	else
		__dump_routes6(default_vrfid, rt_type, 0, bitmap);

	return 0;
}
#endif

#ifdef CONFIG_MCORE_IP
static int show_route(char *tok)
{
	int nt = gettokens(tok);
	if (nt != 1 && nt != 2) {
		fpdebug_fprintf (stderr, "wrong arguments: show-route <ip> [src]\n");
		return 0;
	}
	char *str = chargv[0];
	uint32_t addr = 0;
	int res = fpdebug_inet_pton(AF_INET, (const char*)str, &addr);

	if (res > 0) {
		/* IPv4 route */
		fp_rt4_entry_t *entry = fp_rt4_lookup(default_vrfid,addr);
		if (entry) {
			fp_nh4_entry_t fake_nhe;
			fp_nh4_entry_t *nhe = &fake_nhe;

			memset (&fake_nhe, 0, sizeof (fake_nhe));
			if (nt == 2) {
				uint32_t addrs[2];
				addrs[1] = addr;
				res = fpdebug_inet_pton(AF_INET, (const char*)chargv[1], &addrs[0]);
				if(res > 0)
					nhe = select_nh4(entry, addrs);
				else {
					fpdebug_printf("Malformed IPv4 address !\n");
					return 0;
				}
			}
			dump_route_entry(entry-fp_shared->fp_rt4_table, addr, *entry, nhe);
		}
	} else {
		/* IPv6 route */
#ifdef CONFIG_MCORE_IPV6
		fp_in6_addr_t address;
		address.fp_s6_addr32[0] = 0;
		address.fp_s6_addr32[1] = 0;
		address.fp_s6_addr32[2] = 0;
		address.fp_s6_addr32[3] = 0;
		res = fpdebug_inet_pton(AF_INET6, (const char*)str, &address);

		if(res <= 0) {
			fpdebug_printf("Malformed address !\n");
			return 0;
		}

		fp_rt6_entry_t *entry = fp_rt6_lookup(default_vrfid, &address);
		if (entry) {
			fp_nh6_entry_t fake_nhe;
			fp_nh6_entry_t *nhe = &fake_nhe;

			memset (&fake_nhe, 0, sizeof (fake_nhe));
			if (nt == 2) {
				fp_in6_addr_t addrs[2];
				addrs[0] = address;
				res = fpdebug_inet_pton(AF_INET6, (const char*)chargv[1], &addrs[1]);
				if(res <= 0) {
					fpdebug_printf("Malformed IPv6 address !\n");
					return 0;
				}
				nhe = select_nh6(entry, addrs);
			}
			dump_route_entry6(entry-fp_shared->fp_rt6_table, &address, *entry, nhe);
		}
#endif
	}
	return 0;
}
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_NETFILTER
/* enable/disable netfilter in fast path */
static int netfilter(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	char *on_str = NULL;

	if (arg_count > 1) {
		fpdebug_printf("wrong arguments: netfilter [on|off]\n");
		return 0;
	}

	if (arg_count == 1) {
		on_str = chargv[0];
		if (strcmp(on_str, "on") == 0)
			fp_shared->conf.s.do_netfilter = 1;
		else if (strcmp(on_str, "off") == 0)
			fp_shared->conf.s.do_netfilter = 0;
	}

	fpdebug_printf("netfilter is %s\n", fp_shared->conf.s.do_netfilter ? "on" : "off");
	return 0;
}

static int dump_nfhook(char *tok)
{
	uint8_t cur = fp_shared->fp_nf_current_hook_prio;
	int h, t;

	for (h = 0; h < FP_NF_IP_NUMHOOKS; h++) {
		fpdebug_printf("%s:\n\t", fp_hook_name(h));
		for (t = 0;
		     t < FP_NF_TABLE_NUM + 1 && fp_shared->fp_nf_hook_prio[cur][h][t] != -1;
		     t++)
			fpdebug_printf("%s ", fp_table_name(fp_shared->fp_nf_hook_prio[cur][h][t]));
		fpdebug_printf("\n");
	}

	return 0;
}

static int dump_nftable(char *tok)
{
	int table;
	int nt = gettokens(tok);
	int family;
#ifdef CONFIG_MCORE_NF_TABLE_PER_VR
	uint16_t nf_vr = default_vrfid;
#else
	uint16_t nf_vr = 0;
#endif

	if (nt < 2) {
		fpdebug_fprintf(stderr, "wrong arguments: dump-nftable <4|6> <filter|mangle|nat> [all|nonzero]\n");
		return -1;
	}

	switch (atoi(chargv[0])) {
	case 4:
		family = AF_INET;
		table = fp_nf_table_id(chargv[1]);
		if (table >= FP_NF_TABLE_NUM) {
			fpdebug_fprintf(stderr, "wrong arguments: table %s does not exist for IPv4\n",
					chargv[1]);
			return -1;
		}
		break;
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	case 6:
		family = AF_INET6;
		table = fp_nf6_table_id(chargv[1]);
		if (table >= FP_NF6_TABLE_NUM) {
			fpdebug_fprintf(stderr, "wrong arguments: table %s does not exist for IPv6\n",
					chargv[1]);
			return -1;
		}
		break;
#endif
	default:
		fpdebug_fprintf(stderr, "wrong arguments: %s is not a valid family\n", chargv[0]);
		return -1;
	}

	if (nt > 2) {
		int mode;

		if (strcmp(chargv[2], "all") == 0)
			mode = FP_NF_DUMP_NFTABLE_MODE_VERBOSE;
		else if (strcmp(chargv[2], "nonzero") == 0)
			mode = FP_NF_DUMP_NFTABLE_MODE_NONZERO;
		else {
			fpdebug_printf("Wrong argument: \"%s\"\n", chargv[2]);
			return -1;
		}

		switch(family){
			case AF_INET:
				fp_nf_dump_nftable(table, nf_vr, mode);
				break;
#ifdef CONFIG_MCORE_NETFILTER_IPV6
			case AF_INET6:
				fp_nf6_dump_nftable(table, nf_vr, mode);
				break;
#endif
		}
	} else {
		switch(family){
			case AF_INET:
				fp_nf_print_summary(table, nf_vr);
				break;
#ifdef CONFIG_MCORE_NETFILTER_IPV6
			case AF_INET6:
				fp_nf6_print_summary(table, nf_vr);
				break;
#endif
		}
	}

	return 0;
}

#ifdef CONFIG_MCORE_NF_CT
static int dump_nfct(char *tok)
{
	int nt = gettokens(tok);
	int count = FP_NF_CT_MAX;
	int summary = 0;

	if (nt) {
		count = atoi(chargv[0]);
		if (count < 1 || count > FP_NF_CT_MAX)
			count = FP_NF_CT_MAX;
	}

	if (nt > 1) {
		if (strcasecmp(chargv[1],"summary") == 0)
			summary = 1;
	}


	fp_nf_dump_nfct(count, summary);
	return 0;
}
#endif

static const char *nftable_num2str(int tablenum)
{
	switch (tablenum) {
	case FP_NF_TABLE_FILTER:
		return FP_NF_FILTER_TABLE;
	case FP_NF_TABLE_MANGLE:
		return FP_NF_MANGLE_TABLE;
	case FP_NF_TABLE_NAT:
		return FP_NF_NAT_TABLE;
	default:
		break;
	}
	return "unknown";
}

static const char *nfhook_num2str(int hooknum)
{
	switch (hooknum) {
	case FP_NF_IP_PRE_ROUTING:
		return "pre_routing";
	case FP_NF_IP_LOCAL_IN:
		return "local_in";
	case FP_NF_IP_FORWARD:
		return "forward";
	case FP_NF_IP_LOCAL_OUT:
		return "local_out";
	case FP_NF_IP_POST_ROUTING:
		return "post_routing";
	default:
		break;
	}
	return "unknown";
}

static int nf_hook(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	char *hook_str = NULL;
	char *table_str = NULL;
	char *on_str = NULL;
	int on = 0, fail = 1, show = 0;
	int hook, table;
	fp_nftable_t *tb;
	const uint8_t cur = fp_shared->fp_nf_current_table;
#ifdef CONFIG_MCORE_NF_TABLE_PER_VR
	uint16_t nf_vr = default_vrfid;
#else
	uint16_t nf_vr = 0;
#endif

	if (arg_count != 0 && arg_count != 3)
		goto fail;

	if (arg_count == 0)
		show = 1;
	else if (arg_count == 3) {
		table_str = chargv[0];
		hook_str = chargv[1];
		on_str = chargv[2];
		if (strcmp(on_str, "on") == 0)
			on = 1;
		else if (strcmp(on_str, "off") == 0)
			on = 0;
		else if (strcmp(on_str, "show") == 0)
			show = 1;
		else
			goto fail;
	}

	for (table = 0; table < FP_NF_TABLE_NUM; table++) {
		tb = &fp_shared->fp_nf_tables[cur][nf_vr][table]; /* v4 only */
		for (hook = 0; hook < FP_NF_IP_NUMHOOKS; hook++) {
			/* skip invalid hooks for this table */
			if ((tb->fpnftable_valid_hooks & (1<<hook)) == 0)
				continue;
			if (arg_count != 0) {
				if ( strcmp(hook_str, "all_hooks") &&
						strcmp(hook_str, nfhook_num2str(hook)) )
					continue;
				if ( strcmp(table_str, "all_tables") &&
						strcmp(table_str, nftable_num2str(table)) )
					continue;
				fail = 0;
				if (on == 1 && show == 0)
					fp_shared->nf_conf.enabled_hook[nf_vr][hook] |= 1ULL << table;
				else if (on == 0 && show==0)
					fp_shared->nf_conf.enabled_hook[nf_vr][hook] &= ~(1ULL << table);
			}
			if (show == 0)
				fpdebug_printf("Set ");
			fpdebug_printf("%s %s: %s\n", nftable_num2str(table), nfhook_num2str(hook),
					fp_shared->nf_conf.enabled_hook[nf_vr][hook] & (1ULL << table) ? "on":"off");

		}
	}

	if (fail && arg_count != 0)
		goto fail;

	return 0;
fail:
	fpdebug_printf("wrong arguments: nf-hook [<table>|'all_tables' <hook>|'all_hooks' <on|off|show>]\n");
	fpdebug_printf("   table is one of: 'filter', 'mangle', 'nat'\n");
	fpdebug_printf("   hook is one of: 'pre_routing', 'local_in', 'forward', 'local_out', 'post_routing'\n");
	return 0;
}

#ifdef CONFIG_MCORE_NETFILTER_IPV6
/* enable/disable netfilter6 in fast path */
static int netfilter6(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	char *on_str = NULL;

	if (arg_count > 1) {
		fpdebug_printf("wrong arguments: netfilter6 [on|off]\n");
		return 0;
	}

	if (arg_count == 1) {
		on_str = chargv[0];
		if (strcmp(on_str, "on") == 0)
			fp_shared->conf.s.do_netfilter6 = 1;
		else if (strcmp(on_str, "off") == 0)
			fp_shared->conf.s.do_netfilter6 = 0;
	}

	fpdebug_printf("IPv6 netfilter is %s\n", fp_shared->conf.s.do_netfilter6 ? "on" : "off");
	return 0;
}

static int dump_nf6hook(char *tok)
{
	uint8_t cur = fp_shared->fp_nf6_current_hook_prio;
	int h, t;

	for (h = 0; h < FP_NF_IP_NUMHOOKS; h++) {
		fpdebug_printf("%s:\n\t", fp_hook_name(h));
		for (t = 0;
		     t < FP_NF6_TABLE_NUM + 1 && fp_shared->fp_nf6_hook_prio[cur][h][t] != -1;
		     t++)
			fpdebug_printf("%s ", fp_table_name(fp_shared->fp_nf6_hook_prio[cur][h][t]));
		fpdebug_printf("\n");
	}

	return 0;
}

static int nf_hook6(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	char *hook_str = NULL;
	char *table_str = NULL;
	char *on_str = NULL;
	int on = 0, fail = 1, show = 0;
	int hook, table;
	fp_nf6table_t *tb;
	const uint8_t cur = fp_shared->fp_nf6_current_table;
#ifdef CONFIG_MCORE_NF_TABLE_PER_VR
	uint16_t nf_vr = default_vrfid;
#else
	uint16_t nf_vr = 0;
#endif

	if (arg_count != 0 && arg_count != 3)
		goto fail;

	if (arg_count == 0)
		show = 1;
	else if (arg_count == 3) {
		table_str = chargv[0];
		hook_str = chargv[1];
		on_str = chargv[2];
		if (strcmp(on_str, "on") == 0)
			on = 1;
		else if (strcmp(on_str, "off") == 0)
			on = 0;
		else if (strcmp(on_str, "show") == 0)
			show = 1;
		else
			goto fail;
	}

	for (table = 0; table < FP_NF6_TABLE_NUM; table++) {
		tb = &fp_shared->fp_nf6_tables[cur][nf_vr][table];
		for (hook = 0; hook < FP_NF_IP_NUMHOOKS; hook++) {
			/* skip invalid hooks for this table */
			if ((tb->fpnf6table_valid_hooks & (1<<hook)) == 0)
				continue;
			if (arg_count != 0) {
				if ( strcmp(hook_str, "all_hooks") &&
						strcmp(hook_str, nfhook_num2str(hook)) )
					continue;
				if ( strcmp(table_str, "all_tables") &&
						strcmp(table_str, nftable_num2str(table)) )
					continue;
				fail = 0;
				if (on == 1 && show == 0)
					fp_shared->nf6_conf.enabled_hook[nf_vr][hook] |= 1ULL << table;
				else if (on == 0 && show==0)
					fp_shared->nf6_conf.enabled_hook[nf_vr][hook] &= ~(1ULL << table);
			}
			if (show == 0)
				fpdebug_printf("Set ");
			fpdebug_printf("%s %s: %s\n", nftable_num2str(table), nfhook_num2str(hook),
					fp_shared->nf6_conf.enabled_hook[nf_vr][hook] & (1ULL << table) ? "on":"off");

		}
	}

	if (fail && arg_count != 0)
		goto fail;

	return 0;
fail:
	fpdebug_printf("wrong arguments: nf-hook6 [<table>|'all_tables' <hook>|'all_hooks' <on|off|show>]\n");
	fpdebug_printf("   table is one of: 'filter', 'mangle'\n");
	fpdebug_printf("   hook is one of: 'pre_routing', 'local_in', 'forward', 'local_out', 'post_routing'\n");
	return 0;
}

#ifdef CONFIG_MCORE_NF6_CT
static int dump_nf6ct(char *tok)
{
	int nt = gettokens(tok);
	int count = FP_NF6_CT_MAX;
	int summary = 0;

	if (nt) {
		count = atoi(chargv[0]);
		if (count < 1 || count > FP_NF6_CT_MAX)
			count = FP_NF6_CT_MAX;
	}

	if (nt > 1) {
		if (strcasecmp(chargv[1],"summary") == 0)
			summary = 1;
	}

	fp_nf6_dump_nf6ct(count, summary);
	return 0;
}
#endif
#endif /* CONFIG_MCORE_NETFILTER_IPV6 */

static int nf_nat_conntrack(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	char *on_str = NULL;
	int on = 0;
#ifdef CONFIG_MCORE_NF_TABLE_PER_VR
	uint16_t nf_vr = default_vrfid;
#else
	uint16_t nf_vr = 0;
#endif

	if (arg_count != 0 && arg_count != 1)
		goto fail;

	if (arg_count == 1) {
		on_str = chargv[0];
		if (strcmp(on_str, "on") == 0)
			on = 1;
		else if (strcmp(on_str, "off") == 0)
			on = 0;
		else
			goto fail;

		fp_nf_set_conntrack_nat(on, nf_vr);
	}

	/* just check on prerouting hook, but state should be the same
	 * on other NAT hooks */
	if (fp_shared->nf_conf.enabled_hook[nf_vr][FP_NF_IP_PRE_ROUTING] &
	    (1ULL << FP_NF_FLAG_FORCE_NAT_CONNTRACK))
		fpdebug_printf("nf-nat-conntrack is on\n");
	else
		fpdebug_printf("nf-nat-conntrack is off\n");
	return 0;

fail:
	fpdebug_printf("wrong arguments: nf-nat-conntrack [<on|off>]\n");
	return 0;
}
#endif /* CONFIG_MCORE_NETFILTER */

#ifdef CONFIG_MCORE_NETFILTER_CACHE
static int nf_cache_invalidate(char *tok)
{
	uint8_t arg_count = gettokens(tok);

	if (arg_count != 0) {
		fpdebug_printf("wrong arguments: nf-cache-invalidate\n");
		return 0;
	}

	fp_nf_invalidate_cache();
	return 0;
}

static void dump_nf_cache_target(struct fp_nfrule *rule)
{
	fpdebug_printf("(uid:0x%x): ", rule->uid);
	switch (rule->target.type) {
	case FP_NF_TARGET_TYPE_STANDARD:
		if (rule->target.data.standard.verdict < 0) {
			const char *verdict = "unknow";

			switch (- rule->target.data.standard.verdict - 1) {
#define _V2S(v) case v: verdict = #v ; break;
			_V2S(FP_NF_DROP);
			_V2S(FP_NF_ACCEPT);
			_V2S(FP_NF_STOLEN);
			_V2S(FP_NF_QUEUE);
			_V2S(FP_NF_REPEAT);
			_V2S(FP_NF_STOP);
#undef _V2S
			}
			fpdebug_printf("target STANDARD, verdict: %s\n", verdict);
		} else
			fpdebug_printf("target STANDARD, verdict: jump to rule #%d\n",
			       rule->target.data.standard.verdict);
		break;
	case FP_NF_TARGET_TYPE_MARK_V2:
		fpdebug_printf("target MARK V2, mark: 0x%x, mask: 0x%x\n",
		       rule->target.data.mark.mark,
		       rule->target.data.mark.mask);
		break;
	case FP_NF_TARGET_TYPE_DSCP:
		fpdebug_printf("target DSCP, dscp: 0x%x\n",
		       rule->target.data.dscp.dscp);
		break;
	case FP_NF_TARGET_TYPE_DEV:
		fpdebug_printf("target DEV, to iface <%s>",
		       rule->target.data.dev.ifname);
		if (rule->target.data.dev.flags & FP_NF_DEV_FLAG_SET_MARK)
			fpdebug_printf(", set-mark 0x%x\n",
			       rule->target.data.dev.mark);
		else
			fpdebug_printf("\n");
		break;
	default:
		fpdebug_printf("target type: %u\n", rule->target.type);
		break;
	}
}

static int dump_nf_cache_one(uint32_t i, int details)
{
	struct fp_ip *ip;
	int j, len;
	struct fp_nf_rule_cache_entry *cache;
	struct fp_nf_rule_cache_extended_entry *ext_cache = NULL;
	fpn_uintptr_t offset;

	cache = &fp_shared->fp_nf_rule_cache[i];
	if (cache->state != FP_NF_CACHE_STATE_USED) {
		if (details)
			fpdebug_printf("empty cache entry\n");
		return -1;
	}
	if (!(cache->flags & FP_NF_CACHE_FLAG_IN_HASH_TABLE)) {
		fpdebug_printf("end of previous cache entry (double entry)\n");
		return 0;
	}
	fpdebug_printf("%"PRIu32": ", i);
	/* always ipv4 for now */
	ip = (struct fp_ip *)cache->hdr;
	print_addr(&ip->ip_src.s_addr);
	fpdebug_printf(" -> ");
	print_addr(&ip->ip_dst.s_addr);
	fpdebug_printf(" tos %"PRIu8" ", ip->ip_tos);
	fpdebug_printf("frag_flags 0x%"PRIx16" ", (ntohs(ip->ip_off) & 0xe000) >> 13);
	switch (ip->ip_p) {
	case FP_IPPROTO_TCP: {
		const struct fp_tcphdr *tcp = (const struct fp_tcphdr *)(ip + 1);
		fpdebug_printf("TCP sport %"PRIu16" dport %"PRIu16" ", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
		fpdebug_printf("flags %s%s%s%s%s ",
		       tcp->th_flags & TH_ACK ? "A":"-",
		       tcp->th_flags & TH_PUSH ? "P":"-",
		       tcp->th_flags & TH_RST ? "R":"-",
		       tcp->th_flags & TH_SYN ? "S":"-",
		       tcp->th_flags & TH_FIN ? "F":"-");
		break;
	}
	case FP_IPPROTO_UDP: {
		const struct fp_udphdr *udp = (const struct fp_udphdr *)(ip + 1);
		fpdebug_printf("UDP sport %"PRIu16" dport %"PRIu16" ", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
		break;
	}
	case FP_IPPROTO_ICMP: {
		const struct fp_icmphdr *icmp = (const struct fp_icmphdr *)(ip + 1);
		fpdebug_printf("ICMP type %"PRIu8" code %"PRIu8" ", icmp->icmp_type, icmp->icmp_code);
		break;
	}
	default:
		fpdebug_printf(" proto %"PRIu8" ", ip->ip_p);
		break;
	}
	fpdebug_printf("vr %"PRIu16" ", cache->vrid);
	fpdebug_printf("indev 0x%08x outdev 0x%08x ", ntohl(cache->in_ifuid),
	       ntohl(cache->out_ifuid));
	fpdebug_printf("table %"PRIu8" hook %"PRIu8" ", cache->table_num,
	       cache->hook_num);
	if (cache->flags & FP_NF_CACHE_FLAG_DIRECT_ACCEPT)
		fpdebug_printf("direct-accept ");

	if (cache->flags & FP_NF_CACHE_FLAG_MORE_RULES) {
		ext_cache = (fp_nf_rule_cache_extended_entry_t *)cache;

		fpdebug_printf("rules %u", ext_cache->ext_nbrules + 1);
	}
	fpdebug_printf("\n");

	j = 0;
	if (cache->flags & FP_NF_CACHE_FLAG_MORE_RULES)
		for (j = 0; j < ext_cache->ext_nbrules; j++) {
			offset = ext_cache->ext_rule[j] - fp_shared->fp_nf_cache_base_addr;
			fpdebug_printf("\t#%d ", j + 1);
			dump_nf_cache_target((struct fp_nfrule *)((void *)fp_shared->fp_nf_tables + offset));
		}

	offset = cache->rule - fp_shared->fp_nf_cache_base_addr;
	fpdebug_printf("\t#%d ", j + 1);
	dump_nf_cache_target((struct fp_nfrule *)((void *)fp_shared->fp_nf_tables + offset));

	if (details) {
		len = cache->hdr_len32;
		fpdebug_printf("mask (len=%u):\n", len<<2);
		for (j=0; j<len; j++) {
			if ((j%4) == 0)
				fpdebug_printf("    ");
			fpdebug_printf("%08x ", cache->hdr[j]);
			if ((j%4) == 3)
				fpdebug_printf("\n");
		}
		fpdebug_printf("\n");
	}

	return 0;
}

static int dump_nf_cache(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	int i;

	fpdebug_printf("Max cached rules per entry is %lu\n",
		(u_long)FP_NF_MAX_CACHED_RULES);

	if (arg_count == 1) {
		i = atoi(chargv[0]);
		dump_nf_cache_one(i, 1);
	}
	else if (arg_count == 0) {
		for (i=0; i<FP_NF_MAX_CACHE_SIZE; i++) {
			dump_nf_cache_one(i, 0);
		}
	}
	else if (arg_count == 2) {
		int count = atoi(chargv[0]);
		int details = atoi(chargv[1]);
		for (i=0; i<FP_NF_MAX_CACHE_SIZE && count > 0; i++) {
			if (!dump_nf_cache_one(i, details))
				count--;
		}
	} else {
		fpdebug_printf("wrong arguments: dump-nf-cache [num] | [count details]\n");
	}
	return 0;
}

static int nf_cache(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	char *on_str = NULL;

	if (arg_count > 1) {
		fpdebug_printf("wrong arguments: nf-cache [on|off]\n");
		return 0;
	}

	if (arg_count == 1) {
		on_str = chargv[0];
		if (strcmp(on_str, "on") == 0)
			fp_shared->conf.s.do_nf_cache = 1;
		else if (strcmp(on_str, "off") == 0)
			fp_shared->conf.s.do_nf_cache = 0;
	}

	fpdebug_printf("nf-cache is %s\n", fp_shared->conf.s.do_nf_cache ? "on" : "off");
	return 0;
}
#endif

#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE
static int nf6_cache(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	char *on_str = NULL;

	if (arg_count > 1) {
		fpdebug_printf("wrong arguments: nf6-cache [on|off]\n");
		return 0;
	}

	if (arg_count == 1) {
		on_str = chargv[0];
		if (strcmp(on_str, "on") == 0)
			fp_shared->conf.s.do_nf6_cache = 1;
		else if (strcmp(on_str, "off") == 0)
			fp_shared->conf.s.do_nf6_cache = 0;
	}

	fpdebug_printf("nf6-cache is %s\n", fp_shared->conf.s.do_nf6_cache ? "on" : "off");
	return 0;
}

static int nf6_cache_invalidate(char *tok)
{
	uint8_t arg_count = gettokens(tok);

	if (arg_count != 0) {
		fpdebug_printf("wrong arguments: nf6-cache-invalidate\n");
		return 0;
	}

	fp_nf6_invalidate_cache();
	return 0;
}

static void dump_nf6_cache_target(struct fp_nf6rule *rule)
{
	fpdebug_printf("(uid:0x%x): ", rule->uid);
	switch (rule->target.type) {
	case FP_NF_TARGET_TYPE_STANDARD:
		if (rule->target.data.standard.verdict < 0) {
			const char *verdict = "unknow";

			switch (- rule->target.data.standard.verdict - 1) {
#define _V2S(v) case v: verdict = #v ; break;
			_V2S(FP_NF_DROP);
			_V2S(FP_NF_ACCEPT);
			_V2S(FP_NF_STOLEN);
			_V2S(FP_NF_QUEUE);
			_V2S(FP_NF_REPEAT);
			_V2S(FP_NF_STOP);
#undef _V2S
			}
			fpdebug_printf("target STANDARD, verdict: %s\n", verdict);
		} else
			fpdebug_printf("target STANDARD, verdict: jump to rule #%d\n",
			       rule->target.data.standard.verdict);
		break;
	case FP_NF_TARGET_TYPE_MARK_V2:
		fpdebug_printf("target MARK V2, mark: 0x%x, mask: 0x%x\n",
		       rule->target.data.mark.mark,
		       rule->target.data.mark.mask);
		break;
	case FP_NF_TARGET_TYPE_DSCP:
		fpdebug_printf("target DSCP, dscp: 0x%x\n",
		       rule->target.data.dscp.dscp);
		break;
	case FP_NF_TARGET_TYPE_DEV:
		fpdebug_printf("target DEV, to iface <%s>",
		       rule->target.data.dev.ifname);
		if (rule->target.data.dev.flags & FP_NF_DEV_FLAG_SET_MARK)
			fpdebug_printf(", set-mark 0x%x\n",
			       rule->target.data.dev.mark);
		else
			fpdebug_printf("\n");
		break;
	default:
		fpdebug_printf("target type: %u\n", rule->target.type);
		break;
	}
}

static int dump_nf6_cache_one(uint32_t i, int details)
{
	struct fp_ip6_hdr *ip6;
	int j, len;
	struct fp_nf6_rule_cache_entry *cache;
	struct fp_nf6_rule_cache_extended_entry *ext_cache = NULL;
	fpn_uintptr_t offset;

	cache = &fp_shared->fp_nf6_rule_cache[i];
	if (cache->state != FP_NF_CACHE_STATE_USED) {
		if (details)
			fpdebug_printf("empty cache entry\n");
		return -1;
	}
	if (!(cache->flags & FP_NF_CACHE_FLAG_IN_HASH_TABLE)) {
		fpdebug_printf("end of previous cache entry (double entry)\n");
		return 0;
	}
	fpdebug_printf("%"PRIu32": ", i);
	ip6 = (struct fp_ip6_hdr *)cache->hdr;
	print_addr6(&ip6->ip6_src);
	fpdebug_printf(" -> ");
	print_addr6(&ip6->ip6_dst);
	fpdebug_printf(" tcclass 0x%"PRIx8" ", (ntohl(ip6->ip6_flow) & 0x0ff00000) >> 20);
	switch (ip6->ip6_nxt) {
	case FP_IPPROTO_TCP: {
		const struct fp_tcphdr *tcp = (const struct fp_tcphdr *)(ip6 + 1);
		fpdebug_printf("TCP sport %"PRIu16" dport %"PRIu16" ", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
		fpdebug_printf("flags %s%s%s%s%s ",
		       tcp->th_flags & TH_ACK ? "A":"-",
		       tcp->th_flags & TH_PUSH ? "P":"-",
		       tcp->th_flags & TH_RST ? "R":"-",
		       tcp->th_flags & TH_SYN ? "S":"-",
		       tcp->th_flags & TH_FIN ? "F":"-");
		break;
	}
	case FP_IPPROTO_UDP: {
		const struct fp_udphdr *udp = (const struct fp_udphdr *)(ip6 + 1);
		fpdebug_printf("UDP sport %"PRIu16" dport %"PRIu16" ", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
		break;
	}
	case FP_IPPROTO_ICMPV6: {
		const struct fp_icmp6_hdr *icmp6 = (const struct fp_icmp6_hdr *)(ip6 + 1);
		fpdebug_printf("ICMPV6 type %"PRIu8" code %"PRIu8" ", icmp6->icmp6_type, icmp6->icmp6_code);
		break;
	}
	default:
		fpdebug_printf(" proto %"PRIu8" ", ip6->ip6_nxt);
		break;
	}
	fpdebug_printf("vr %"PRIu16" ", cache->vrid);
	fpdebug_printf("indev %"PRIu32" outdev %"PRIu32" ", cache->in_ifuid,
	       cache->out_ifuid);
	fpdebug_printf("table %"PRIu8" hook %"PRIu8" ", cache->table_num,
	       cache->hook_num);
	if (cache->flags & FP_NF_CACHE_FLAG_DIRECT_ACCEPT)
		fpdebug_printf("direct-accept ");

	if (cache->flags & FP_NF_CACHE_FLAG_MORE_RULES) {
		ext_cache = (fp_nf6_rule_cache_extended_entry_t *)cache;

		fpdebug_printf("rules %u ", ext_cache->ext_nbrules + 1);
	}
	fpdebug_printf("\n");

	j = 0;
	if (cache->flags & FP_NF_CACHE_FLAG_MORE_RULES)
		for (j = 0; j < ext_cache->ext_nbrules; j++) {
			offset = ext_cache->ext_rule6[j] - fp_shared->fp_nf6_cache_base_addr;
			fpdebug_printf("\t#%d ", j + 1);
			dump_nf6_cache_target((struct fp_nf6rule *)((void *)fp_shared->fp_nf6_tables + offset));
		}

	offset = cache->rule6 - fp_shared->fp_nf6_cache_base_addr;
	fpdebug_printf("\t#%d ", j + 1);
	dump_nf6_cache_target((struct fp_nf6rule *)((void *)fp_shared->fp_nf6_tables + offset));

	if (details) {
		len = cache->hdr_len32 << 2;
		fpdebug_printf("mask (len=%d):\n", len);
		for (j=0; j<len; j++) {
			if ((j%16) == 0)
				fpdebug_printf("    ");
			fpdebug_printf("%.2"PRIx32" ", cache->hdr[j]);
			if (j && j != (len - 1))
				fpdebug_printf("\n");
		}
		fpdebug_printf("\n");
	}

	return 0;
}

static int dump_nf6_cache(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	int i;

	fpdebug_printf("Max cached rules per entry is %lu\n",
		(u_long)FP_NF6_MAX_CACHED_RULES);

	if (arg_count == 1) {
		i = atoi(chargv[0]);
		dump_nf6_cache_one(i, 1);
	}
	else if (arg_count == 0) {
		for (i=0; i<FP_NF6_MAX_CACHE_SIZE; i++) {
			dump_nf6_cache_one(i, 0);
		}
	}
	else if (arg_count == 2) {
		int count = atoi(chargv[0]);
		int details = atoi(chargv[1]);
		for (i=0; i<FP_NF6_MAX_CACHE_SIZE && count > 0; i++) {
			if (!dump_nf6_cache_one(i, details))
				count--;
		}
	} else {
		fpdebug_printf("wrong arguments: dump-nf6-cache [num] | [count details]\n");
	}
	return 0;
}

#endif

#ifdef CONFIG_MCORE_NF_CT_CPEID
static int dump_nfct_bycpeid(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	char *cpeip_str = NULL;
	uint32_t cpeid;
	int count = FP_NF_CT_MAX;
	int summary = 0;
	int res;

	if ((arg_count != 1) && (arg_count != 2))
		goto fail;

	/* Recover cpeid */
	cpeip_str = chargv[0];
	res = fpdebug_inet_pton(AF_INET, (const char*)cpeip_str, &cpeid);
	if (res != 1)
		goto fail;

	if (arg_count == 2) {
		count = atoi(chargv[1]);
		if (count < 1 || count > FP_NF_CT_MAX)
			count = FP_NF_CT_MAX;
	}

	if (arg_count == 3) {
		if (strcasecmp(chargv[2],"summary") == 0)
			summary = 1;
	}

	fp_nf_dump_nfct_bycpeid(cpeid, count, summary);

	return 0;
fail:
	fpdebug_printf("wrong arguments: dump-nfct-bycpeid <CPE address> [number of entries]\n");
	return 0;
}
#endif

#ifdef CONFIG_MCORE_MULTIBLADE
#ifdef CONFIG_MCORE_NETFILTER
static int ct_bladeid(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	uint8_t id = 0;

	if (arg_count > 1) {
		fpdebug_printf("wrong arguments: ct-bladeid [blade ID]\n");
		return 0;
	}

	if (arg_count == 1) {
		id = atoi(chargv[0]);
		if (id == 0) {
			fpdebug_fprintf(stderr, "Incorrect value (%s)\n", chargv[0]);
			return 0;
		}
		fp_shared->fp_nf_ct_bladeid = id;
	}

	fpdebug_printf("ct-bladeid is %"PRIu8"\n", fp_shared->fp_nf_ct_bladeid);
	return 0;
}
#endif /* CONFIG_MCORE_NETFILTER */
#endif /* CONFIG_MCORE_MULTIBLADE */

#ifndef __FastPath__
static int __dump_eqos(char *tok, int type)
{
	int countTokens = gettokens(tok);
	struct netfpc_eqos neq, *r_neq;
	ssize_t len;
	char *reply = NULL;
	char *buf;
	ssize_t goodsize;
	uint32_t error;

	switch (type) {
	case NETFPC_EQOS_GET_STATS:
		goodsize = (256 * sizeof(struct netfpc_eqos_stats)) + 32;
		break;
	case NETFPC_EQOS_GET_PARAMS:
		goodsize = (256 * sizeof(struct netfpc_eqos_params)) + 32;
		break;
	default:
		return -1;
	}

	if (countTokens < 1)
		goto usage;

	if (s_nfpc < 0) {
		fpdebug_fprintf(stderr, "Not connected to fast path\n");
		goto out;
	}

	neq.type = htonl(type);

	if (strcasecmp(chargv[0], "all") == 0) {
		neq.port_id = NETFPC_EQOS_PORTID_ALL;
		neq.queue_id = htons(NETFPC_EQOS_QUEUEID_ALL);
	} else if (strcasecmp(chargv[0], "port") == 0) {
		if (countTokens != 2)
			goto usage;
		neq.port_id = atoi(chargv[1]);
		neq.queue_id = htons(NETFPC_EQOS_QUEUEID_ALL);
	} else if (strcasecmp(chargv[0], "queue") == 0) {
		if (countTokens != 2)
			goto usage;
		neq.queue_id = htons(atoi(chargv[1]));
		neq.port_id = NETFPC_EQOS_PORTID_ALL;
	} else
		goto usage;

	if (netfpc_send(s_nfpc, &neq, sizeof(neq), 0,
				NETFPC_MSGTYPE_EQOS) < 0) {
		fpdebug_fprintf(stderr, "Error netfpc_send\n");
		goto out;
	}

	reply = malloc(goodsize);
	if (reply == NULL) {
		fpdebug_fprintf(stderr, "Unable to allocate memory\n");
		return -1;
	}

	len = netfpc_recv(s_nfpc, reply, goodsize, MSG_NO_TIMEOUT, NULL);
	if (len < (ssize_t)sizeof(struct netfpc_eqos)) {
		fpdebug_fprintf(stderr, "Error netfpc_recv\n");
		goto out;
	}

	r_neq = (struct netfpc_eqos *)reply;
	error = ntohl(r_neq->error);
	if (error && error != NETFPC_TC_ERROR_TRUNCATED) {
		switch(error) {
		case NETFPC_EQOS_ERROR_INVALID_PARAM:
			fpdebug_fprintf(stderr, "invalid parameter\n");
			break;
		case NETFPC_EQOS_ERROR_INVALID_CMD:
			fpdebug_fprintf(stderr, "invalid command\n");
			break;
		default:
			fpdebug_fprintf(stderr, "unknown error %d\n", error);
			break;
		}
		goto out;
	}
	buf = (char *)(r_neq + 1);
	len -= sizeof(struct netfpc_eqos);
	while (len > 0) {
		if (type == NETFPC_EQOS_GET_STATS) {
			struct netfpc_eqos_stats *es;

			es = (struct netfpc_eqos_stats *)buf;
			fpdebug_printf("Queue %3u, Port %u index %u\n", ntohs(es->queue_id),
				es->port_id, es->queue_idx);
			fpdebug_printf("  Green  %" PRIu32 " packets %"PRIu64" bytes\n",
					ntohl(es->discardPacketsG),
					(uint64_t) ntohll(es->discardBytesG));
			fpdebug_printf("  Yellow %" PRIu32 " packets %"PRIu64" bytes\n",
					ntohl(es->discardPacketsY),
					(uint64_t) ntohll(es->discardBytesY));
			fpdebug_printf("  Red    %" PRIu32 " packets %"PRIu64" bytes\n",
					ntohl(es->discardPacketsR),
					(uint64_t) ntohll(es->discardBytesR));
			fpdebug_printf("  Current length %u highest=%u\n",
					ntohl(es->currentQueueLength),
					ntohl(es->highestQueueLength));
			buf += sizeof(*es);
			len -= sizeof(*es);
		} else {
			struct netfpc_eqos_params *ep;

			ep = (struct netfpc_eqos_params *)buf;
			fpdebug_printf("Queue %3u, Port %u index %u, Discard algo. %s\n", ntohl(ep->queue_id),
				ep->port_id, ep->queue_idx,
				ep->discardAlgorithm == NETFPC_EQOS_DISC_TAILDROP ? "taildrop" :
				ep->discardAlgorithm == NETFPC_EQOS_DISC_WRED ? "red": "none");
			if (ep->discardAlgorithm == NETFPC_EQOS_DISC_TAILDROP) {
				fpdebug_printf("  Thresholds Green:%u Yellow:%u Red:%u\n",
					ntohl(ep->ud.taildrop.dpGmax),
					ntohl(ep->ud.taildrop.dpYmax),
					ntohl(ep->ud.taildrop.dpRmax));
			} else if (ep->discardAlgorithm == NETFPC_EQOS_DISC_WRED) {
				fpdebug_printf("Thresholds min / max / drop prob. moving avg=%u\n",
					ntohl(ep->ud.red.movingAverage));
				fpdebug_printf("   Green:  %u / %u / %u\n",
					ntohl(ep->ud.red.dpGmin),
					ntohl(ep->ud.red.dpGmax),
					ntohl(ep->ud.red.dpGprob));
				fpdebug_printf("   Yellow: %u / %u / %u\n",
					ntohl(ep->ud.red.dpYmin),
					ntohl(ep->ud.red.dpYmax),
					ntohl(ep->ud.red.dpYprob));
				fpdebug_printf("   Red:    %u / %u / %u\n",
					ntohl(ep->ud.red.dpRmin),
					ntohl(ep->ud.red.dpRmax),
					ntohl(ep->ud.red.dpRprob));
			}
			buf += sizeof(*ep);
			len -= sizeof(*ep);
		}
	}
	if (error == NETFPC_TC_ERROR_TRUNCATED)
		fpdebug_fprintf(stderr, "truncated reply\n");

out:
	if (reply)
		free(reply);

	return 0;

usage:
	fpdebug_fprintf(stderr, "usage:%s all | port <id | queue <id>\n",
			type == NETFPC_EQOS_GET_STATS ? "dump-eqos-stats" :
											"dump-eqos-params");
	return -1;
}

static int dump_eqos_stats(char *tok)
{
	return __dump_eqos(tok, NETFPC_EQOS_GET_STATS);
}

static int dump_eqos_params(char *tok)
{
	return __dump_eqos(tok, NETFPC_EQOS_GET_PARAMS);
}
#endif /* !__FastPath__ */

static int echo (char *tok)
{
	int nbtk = gettokens(tok);
	int i = 0;

	while (i < nbtk) {
		fpdebug_printf("%s ", chargv[i]);
		i++;
	}
	fpdebug_printf("\n");
	return 0;
}

#ifdef CONFIG_MCORE_IP
static int get_route(char *tok)
{
	char *str;
	uint32_t addr;
	int len;

	if (gettokens(tok) != 2) {
		fpdebug_fprintf (stderr, "wrong arguments: get-route <ip> <len>\n");
		return 0;
	}
	str = chargv[0];
	addr = string2address(str);
	len = atoi(chargv[1]);
	if(addr != 0) {
		/* IPv4 route */
		fp_rt4_entry_t *entry = fp_get_exact_route4(default_vrfid,addr, len);
		if (entry) {
			dump_route_entry(entry-fp_shared->fp_rt4_table, addr, *entry, NULL);
		}
	}
	else {
#ifdef CONFIG_MCORE_IPV6
		/* IPv6 route */
		fp_in6_addr_t address = string2address6(str);
		if(is_in6_addr_null(address))
			return 0;
		fp_rt6_entry_t *entry = fp_get_exact_route6(default_vrfid,
				&address, len);
		if(entry) {
			dump_route_entry6(entry-fp_shared->fp_rt6_table, &address, *entry, NULL);
		}
#endif
	}
	return 0;
}

static int get_src_address(char *tok)
{
	char *str;
	uint32_t addr;
	uint32_t src = 0;
	uint32_t prefix;
	int lastpass = 0;
	uint8_t rt_type;
	uint32_t idx;
	uint32_t ifuid = 0;

	fp_rt4_entry_t *rt4;
	fp_nh4_entry_t *nh4;

	if (gettokens(tok) != 1) {
		fpdebug_fprintf (stderr, "wrong arguments: get-src-address <ip>\n");
		return 0;
	}
	str = chargv[0];
	addr = string2address(str);

again:
	fpdebug_printf("looking up for ");
	print_addr(&addr);
	fpdebug_printf(" vrfid %" PRIu16"\n", default_vrfid);

	rt4 = fp_rt4_lookup(default_vrfid, addr);

	if (rt4 == NULL) {
		fpdebug_printf("no route found\n");
		goto end;
	}

	/* rt entry found, look at next hops */
	nh4 = &fp_shared->fp_nh4_table[rt4->rt.rt_next_hop[0]];
	ifuid = nh4->nh.nh_ifuid;

	rt_type = nh4->nh.rt_type;
	fpdebug_printf("found ");
	print_rt_type(rt_type);
	fpdebug_printf(" route to ");
	prefix = addr & preflen2mask(rt4->rt.rt_length);
	print_addr(&prefix);
	fpdebug_printf("/%u\n", rt4->rt.rt_length);

	/* basic route, lookup for a route to the gateway */
	if (rt_type == RT_TYPE_ROUTE) {
		addr = nh4->nh_gw;
		fpdebug_printf("\tgateway ");
		print_addr(&addr);
		fpdebug_printf("\n");
		if (lastpass)
			goto end;
		lastpass=1;
		goto again;
	}

	/* destination is one of my addresses. return it */
	if (rt_type == RT_TYPE_ADDRESS) {
		src = addr;
		goto end;
	}

	/* connected route. return preferred source, stored in gw */
	if (rt_type == RT_TYPE_ROUTE_CONNECTED) {
		src = nh4->nh_gw;
		fpdebug_printf("\tsrc ");
		print_addr(&src);
		fpdebug_printf(" on ");
		print_via_iface(ifuid);
		fpdebug_printf("\n");
		goto slow;
	}

	/* neighbour entry. Look for the connected route it depends from */
	if (rt_type == RT_TYPE_NEIGH) {
		fpdebug_printf("\tgateway ");
		print_addr(&nh4->nh_gw);
		fpdebug_printf("\n");

		if (nh4->nh_gw != addr) {
			addr = nh4->nh_gw;
			if (lastpass)
				goto end;
			lastpass=1;
			goto again;
		}

		idx = rt4->rt.rt_next;

		if (idx == 0) {
			fpdebug_printf("no connected route for neighbor\n");
			goto slow;
		}

		rt4 = &fp_shared->fp_rt4_table[idx];
		nh4 = &fp_shared->fp_nh4_table[rt4->rt.rt_next_hop[0]];

		rt_type = nh4->nh.rt_type;
		fpdebug_printf("found ");
		print_rt_type(rt_type);
		fpdebug_printf(" route to ");
		prefix = addr & preflen2mask(rt4->rt.rt_length);
		print_addr(&prefix);
		fpdebug_printf("/%u\n", rt4->rt.rt_length);

		/* found. return preferred source, stored in gw */
		if (rt_type == RT_TYPE_ROUTE_CONNECTED) {
			src = nh4->nh_gw;
			ifuid = nh4->nh.nh_ifuid;
			fpdebug_printf("\tsrc ");
			print_addr(&src);
			fpdebug_printf(" on ");
			print_via_iface(ifuid);
			fpdebug_printf("\n");
			goto slow;
		} else {
			fpdebug_printf("no connected route for neighbor\n");
			goto slow;
		}

	}

	if (rt_type == RT_TYPE_ROUTE_LOCAL ||
	    rt_type == RT_TYPE_ROUTE_BLACKHOLE)
		goto end;

	fpdebug_printf("internal error: unsupported route type\n");
	goto end;

slow:
	if (src == 0) {
		fp_ifnet_t *ifp;  /* target interface */
		fp_ifnet_t *ifp2; /* fallback interface */

		ifp = fp_ifuid2ifnet(ifuid);
		fpdebug_printf("looking for an address configured on ");
		print_via_iface(ifuid);
		fpdebug_printf("\n");

		if (ifp == NULL)
			goto end;

		for (idx=1; idx<FP_IPV4_NBNHENTRIES; idx++) {

			nh4 = &fp_shared->fp_nh4_table[idx];
			if (nh4->nh.rt_type != RT_TYPE_ADDRESS)
				continue;
			if (nh4->nh.nh_ifuid == ifuid) {
				src = nh4->nh_gw;
				fpdebug_printf("found address ");
				print_addr(&src);
				fpdebug_printf(" on ");
				print_via_iface(ifuid);
				fpdebug_printf("\n");
				goto end;
			} else if (src == 0) {

				ifp2 = fp_ifuid2ifnet(nh4->nh.nh_ifuid);
				if (ifp2->if_type != FP_IFTYPE_LOOP &&
				    ifp2->if_vrfid == default_vrfid) {
					src = nh4->nh_gw;
					fpdebug_printf("found address ");
					print_addr(&src);
					fpdebug_printf(" on ");
					print_via_iface(nh4->nh.nh_ifuid);
					fpdebug_printf("\n");
				}
			}
		}
	}

end:
	fpdebug_printf("=> returning ");
	print_addr(&src);
	fpdebug_printf("\n");

	return 0;
}
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_VRF
static int set_vrfid(char *tok)
{
	int nt;
	uint16_t vrfid;

	nt = gettokens(tok);
	if (nt != 1 && nt != 0) {
		fpdebug_fprintf (stderr, "wrong arguments: vrf [vrfid]\n");
		return 0;
	}

#ifndef __FastPath__
	/* duplicate this message to FP to synchronize vrid */
	send_to_fastpath(cur_command);
#endif

	if (nt) {
		vrfid = (uint16_t)strtoul(chargv[0], NULL, 0);
		if (vrfid >= FP_MAX_VR) {
#if !defined(__FastPath__) || defined(FP_STANDALONE)
			/* only display when running in userland or in standalone */
			fpdebug_fprintf(stderr, "error: invalid vrfid (%u), should be < FP_MAX_VR (%u)\n",
					vrfid, FP_MAX_VR);
#endif
			return -1;
		}
		default_vrfid = vrfid;
	}

	/* only display when running in userland or in standalone */
#if !defined(__FastPath__) || defined(FP_STANDALONE)
	if (nt)
		fpdebug_printf(" New reference for VRF: %"PRIu16, default_vrfid);
	else
		fpdebug_printf(" Current reference for VRF: %"PRIu16, default_vrfid);
	fpdebug_printf("\n");
	fpdebug_prompt_reset();
#endif

	return 0;
}

static int set_if_vrfid(char *tok)
{
	uint16_t vrfid;
	char *name = NULL;

	if (gettokens(tok) != 2) {
		fpdebug_fprintf(stderr, "wrong arguments: set-if-vrfid <if_name> <vrfid>\n");
		return -1;
	}

	name = chargv[0];
	vrfid = (uint32_t)strtoul(chargv[1], NULL, 0);

	if (fp_set_if_vrfid(name, vrfid) < 0) {
		fpdebug_fprintf(stderr, "Invalid arguments %s %d\n", name, vrfid);
		return -1;
	}

	return 0;
}
#endif

#ifdef CONFIG_MCORE_RPF_IPV4
static int rpf_ipv4(char *tok)
{
	int ntok;
	char *ifname;
	fp_ifnet_t *iface;

	ntok = gettokens(tok);
	if (ntok < 1 || ntok > 2)
		goto args_error;

	ifname = chargv[0];
	iface = fp_getifnetbyname(ifname);
	if (iface == NULL)
		goto bad_iface;

	if (ntok == 2) {
		/* set the RPF flag */
		if (strncmp("on", chargv[1], 2) == 0)
			iface->if_flags |= IFF_FP_IPV4_RPF;
		else if (strncmp("off", chargv[1], 3) == 0)
			iface->if_flags &= ~IFF_FP_IPV4_RPF;
		else
			goto args_error;
	}

	/* display the RPF flag */
	fpdebug_printf("%s: IPv4 RPF is %s\n", ifname,
		       iface->if_flags & IFF_FP_IPV4_RPF ? "on" : "off");

	return 0;
args_error:
	fpdebug_fprintf(stderr, "wrong arguments: rpf-ipv4 <interface> [on|off]\n");
	return -1;
bad_iface:
	fpdebug_fprintf(stderr, "bad interface name: %s\n", ifname);
	return -1;
}
#endif

#ifdef CONFIG_MCORE_RPF_IPV6
static int rpf_ipv6(char *tok)
{
	int ntok;
	char *ifname;
	fp_ifnet_t *iface;

	ntok = gettokens(tok);
	if (ntok < 1 || ntok > 2)
		goto args_error;

	ifname = chargv[0];
	iface = fp_getifnetbyname(ifname);
	if (iface == NULL)
		goto bad_iface;

	if (ntok == 2) {
		/* set the RPF flag */
		if (strncmp("on", chargv[1], 2) == 0)
			iface->if_flags |= IFF_FP_IPV6_RPF;
		else if (strncmp("off", chargv[1], 3) == 0)
			iface->if_flags &= ~IFF_FP_IPV6_RPF;
		else
			goto args_error;
	}

	/* display the RPF flag */
	fpdebug_printf("%s: IPv6 RPF is %s\n", ifname,
		       iface->if_flags & IFF_FP_IPV6_RPF ? "on" : "off");

	return 0;
args_error:
	fpdebug_fprintf(stderr, "wrong arguments: rpf-ipv6 <interface> [on|off]\n");
	return -1;
bad_iface:
	fpdebug_fprintf(stderr, "bad interface name: %s\n", ifname);
	return -1;
}
#endif

static int set_ivrrp(char *tok)
{
	int ntok;
	char *ifname;
	fp_ifnet_t *iface;

	ntok = gettokens(tok);
	if (ntok < 1 || ntok > 2)
		goto args_error;

	ifname = chargv[0];
	iface = fp_getifnetbyname(ifname);
	if (iface == NULL)
		goto bad_iface;

	if (ntok == 2) {
		/* set the IVRRP flag */
		if (strncmp("on", chargv[1], 2) == 0)
			iface->if_flags |= IFF_FP_IVRRP;
		else if (strncmp("off", chargv[1], 3) == 0)
			iface->if_flags &= ~IFF_FP_IVRRP;
		else
			goto args_error;
	}

	/* display the IVRRP flag */
	fpdebug_printf("%s: IVRRP is %s\n", ifname,
		       iface->if_flags & IFF_FP_IVRRP ? "on" : "off");

	return 0;
args_error:
	fpdebug_fprintf(stderr, "wrong arguments: set-ivrrp <interface> [on|off]\n");
	return -1;
bad_iface:
	fpdebug_fprintf(stderr, "bad interface name: %s\n", ifname);
	return -1;
}

#if defined(CONFIG_MCORE_IPSEC) || defined(CONFIG_MCORE_IPSEC_IPV6)
static void print_port_range(uint16_t port, uint16_t mask)
{
	if (!port && !mask)
		return;

	if (mask == 0xFFFF)
		fpdebug_printf("[%"PRIu16"]", port);
	else
		fpdebug_printf("[%"PRIu16"/%"PRIu16"]", port, mask);
}

static void print_typecode_range(uint16_t port, uint16_t mask)
{
	if (!port && !mask)
		return;

	if (mask == 0xFFFF)
		fpdebug_printf("%"PRIu16, port);
	else
		fpdebug_printf("%"PRIu16"/%"PRIu16, port, mask);
}

static void print_typecode(uint16_t type, uint16_t typemask,
			   uint16_t code, uint16_t codemask)
{
	int typeany = (!type && !typemask);
	int codeany = (!code && !codemask);

	if (typeany && codeany)
		return;

	if (codeany) {
		fpdebug_printf("[");
		print_typecode_range(type, typemask);
	} else if (typeany) {
		fpdebug_printf("[any,");
		print_typecode_range(code, codemask);
	} else {
		fpdebug_printf("[");
		print_typecode_range(type, typemask);
		fpdebug_printf(",");
		print_typecode_range(code, codemask);
	}
	fpdebug_printf("]");
}


static char *ealg2str(uint8_t alg)
{
	static char result[16];

	switch (alg) {
	case FP_EALGO_NULL:
		snprintf(result, sizeof(result), "ESP-null");
		break;
	case FP_EALGO_DESCBC:
		snprintf(result, sizeof(result), "DES-CBC");
		break;
	case FP_EALGO_3DESCBC:
		snprintf(result, sizeof(result), "3DES-CBC");
		break;
	case FP_EALGO_AESCBC:
		snprintf(result, sizeof(result), "AES-CBC");
		break;
	case FP_EALGO_AESGCM:
		snprintf(result, sizeof(result), "AES-GCM");
		break;
	case FP_EALGO_NULL_AESGMAC:
		snprintf(result, sizeof(result), "AES-GMAC");
		break;
	default:
		snprintf(result, sizeof(result), "ENC#%"PRIu8, alg);
		break;
	}

	return result;
}

static char * aalg2str(uint8_t alg)
{
	static char result[16];

	switch (alg) {
	case FP_AALGO_NULL:
		snprintf(result, sizeof(result), "AUTH-null");
		break;
	case FP_AALGO_HMACMD5:
		snprintf(result, sizeof(result), "HMAC-MD5");
		break;
	case FP_AALGO_HMACSHA1:
		snprintf(result, sizeof(result), "HMAC-SHA1");
		break;
	case FP_AALGO_HMACSHA256:
		snprintf(result, sizeof(result), "HMAC-SHA256");
		break;
	case FP_AALGO_HMACSHA384:
		snprintf(result, sizeof(result), "HMAC-SHA384");
		break;
	case FP_AALGO_HMACSHA512:
		snprintf(result, sizeof(result), "HMAC-SHA512");
		break;
	case FP_AALGO_AESXCBC:
		snprintf(result, sizeof(result), "AES-XCBC-MAC");
		break;
	default:
		snprintf(result, sizeof(result), "AUTH#%"PRIu8, alg);
		break;
	}

	return result;
}

static size_t aalg_keylen(uint8_t alg)
{
	size_t result;

	switch (alg) {
	case FP_AALGO_NULL:
		result = 0;
		break;
	case FP_AALGO_HMACMD5:
		result = 16;
		break;
	case FP_AALGO_HMACSHA1:
		result = 20;
		break;
	case FP_AALGO_HMACSHA256:
		result = 32;
		break;
	case FP_AALGO_HMACSHA384:
		result = 48;
		break;
	case FP_AALGO_HMACSHA512:
		result = 64;
		break;
	case FP_AALGO_AESXCBC:
		result = 16;
		break;
	default:
		result = FP_MAX_KEY_AUTH_LENGTH;
		break;
	}

	return result;
}

static inline int addr_match(void *token1, void *token2, int prefixlen)
{
	uint32_t *a1 = (uint32_t *)token1;
	uint32_t *a2 = (uint32_t *)token2;
	int pdw;
	int pbi;

	pdw = prefixlen >> 5;	  /* num of whole __u32 in prefix */
	pbi = prefixlen &  0x1f;  /* num of bits in incomplete u32 in prefix */

	if (pdw)
		if (memcmp(a1, a2, pdw << 2))
			return 0;

	if (pbi) {
		uint32_t mask;

		mask = htonl((0xffffffff) << (32 - pbi));

		if ((a1[pdw] ^ a2[pdw]) & mask)
			return 0;
	}

	return 1;
}
#endif	/* CONFIG_MCORE_IPSEC || CONFIG_MCORE_IPSEC_IPV6 */

#ifdef CONFIG_MCORE_IPSEC
static int __dump_one_sp(fp_sp_entry_t *sp, int cached)
{
	int icmp = (sp->filter.ul_proto == FP_IPPROTO_ICMP ||
	            sp->filter.ul_proto == FP_IPPROTO_ICMPV6);
	fp_sp_stats_t   stats;
	int cpu;

	print_addr(&sp->filter.src);
	fpdebug_printf("/%"PRIu8"", sp->filter.src_plen);

	if (!icmp) {
		print_port_range(ntohs(sp->filter.srcport),
				 ntohs(sp->filter.srcport_mask));
	}

	fpdebug_printf(" ");

	print_addr(&sp->filter.dst);
	fpdebug_printf("/%"PRIu8"", sp->filter.dst_plen);

	if (!icmp) {
		print_port_range(ntohs(sp->filter.dstport),
				 ntohs(sp->filter.dstport_mask));
	}

	if (sp->filter.ul_proto == FILTER_ULPROTO_ANY)
		fpdebug_printf(" proto any");
	else
		fpdebug_printf(" proto %"PRIu8"", sp->filter.ul_proto);

	/* print ICMP type and code */
	if (icmp) {
		print_typecode(ntohs(sp->filter.srcport),
			       ntohs(sp->filter.srcport_mask),
			       ntohs(sp->filter.dstport),
			       ntohs(sp->filter.dstport_mask));
	}

	fpdebug_printf(" vr%"PRIu16, sp->filter.vrfid);

	if (sp->filter.action == FP_SP_ACTION_BYPASS)
		fpdebug_printf(" bypass");
	else if (sp->filter.action == FP_SP_ACTION_DISCARD)
		fpdebug_printf(" discard");
	else if (sp->filter.action == FP_SP_ACTION_PROTECT)
		fpdebug_printf(" protect");
	else
		fpdebug_printf(" action (%"PRIu8"?)", sp->filter.action);

	fpdebug_printf(" prio %"PRIu32"\n", sp->filter.cost);

	fpdebug_printf("     link-vr%"PRIu32, sp->link_vrfid);
	if (cached)
		fpdebug_printf(" cached-SA %"PRIu32" (genid %"PRIu32")", sp->sa_index, sp->sa_genid);
#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
	if (sp->flags & FP_SP_FLAG_HASHED)
		fpdebug_printf(" hash %"PRIu16, sp->hash);
#endif
	fpdebug_printf("\n");

#ifdef CONFIG_MCORE_IPSEC_SVTI
	if (sp->svti_ifuid) {
		fp_ifnet_t *ifp = __fp_ifuid2ifnet(sp->svti_ifuid);
		fpdebug_printf("     svti=%s(0x%"PRIx32")\n",
				ifp->if_ifuid ? ifp->if_name : "<invalid>",
				ntohl(sp->svti_ifuid));
	}
#endif

	if (sp->filter.action == FP_SP_ACTION_PROTECT) {
		fpdebug_printf("     ");
		if (sp->sa_proto == FP_IPPROTO_AH)
			fpdebug_printf("AH");
		else if (sp->sa_proto == FP_IPPROTO_ESP)
			fpdebug_printf("ESP");
		else
			fpdebug_printf("proto %"PRIu8"", sp->sa_proto);
		if (sp->mode == FP_IPSEC_MODE_TUNNEL) {
			fpdebug_printf(" tunnel ");
			if (sp->outer_family == AF_INET) {
				print_addr(&sp->tunnel4_src);
				fpdebug_printf(" - ");
				print_addr(&sp->tunnel4_dst);
			}
#ifdef CONFIG_MCORE_IPSEC_IPV6
			else {
				print_addr6(&sp->tunnel6_src);
				fpdebug_printf(" - ");
				print_addr6(&sp->tunnel6_dst);
			}
#endif
		} else
			fpdebug_printf(" transport");
		if (sp->reqid)
			fpdebug_printf(" reqid=%"PRIu32"", sp->reqid);

		if (sp->flags & FP_SP_FLAG_LEVEL_USE)
			fpdebug_printf(" (level use)");
		fpdebug_printf("\n");
	}

	stats = sp->stats[0];
	for (cpu = 1; cpu < FP_IPSEC_STATS_NUM; cpu++) {
		stats.sp_packets += sp->stats[cpu].sp_packets;
		stats.sp_bytes += sp->stats[cpu].sp_bytes;
		stats.sp_exceptions += sp->stats[cpu].sp_exceptions;
		stats.sp_errors += sp->stats[cpu].sp_errors;
	}

	fpdebug_printf("     ");
	fpdebug_printf("sp_packets=%"PRIu64" ", stats.sp_packets);
	fpdebug_printf("sp_bytes=%"PRIu64" ", stats.sp_bytes);
	fpdebug_printf("sp_exceptions=%"PRIu64" ", stats.sp_exceptions);
	fpdebug_printf("sp_errors=%"PRIu64"\n", stats.sp_errors);

	return 0;
}

static int __dump_spd(fp_spd_t *spd, int cached)
{
	uint32_t i;
	fp_sp_entry_t *sp;

#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
	if (spd->hashed_sp_count) {
		uint32_t cur;
		for (i=0; i < CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_SIZE; i++) {
			fp_hlist_for_each(cur, &spd->addr_hash[i], spd->table, addr_hlist) {
				if (cur && spd->table[cur].vrfid == default_vrfid)
					fpdebug_printf("%"PRIu32": ", cur);
				__dump_one_sp(&spd->table[cur], cached);
			}
		}
	}
#endif

	if (spd->unhashed_sp_count)
		fp_hlist_for_each(i, fp_get_spd_head(spd), spd->table, list) {
			sp = &spd->table[i];

			if (sp->vrfid != default_vrfid)
				continue;

			fpdebug_printf("%"PRIu32": ", i);
			__dump_one_sp(sp, cached);
		}

	return 0;
}

static int __dump_spd_raw(fp_spd_t *spd, int cached)
{
	uint32_t i;
	fp_sp_entry_t *sp;

	for (i = 1; i < FP_MAX_SP_ENTRIES; i++) {
		sp = &spd->table[i];

		if (sp->state == FP_SP_STATE_UNSPEC)
			continue;

		fpdebug_printf("%"PRIu32": ", i);
		__dump_one_sp(sp, cached);
	}

	return 0;
}
#ifdef CONFIG_MCORE_IPSEC_SVTI
static int __dump_svti_spd(fp_hlist_head_t *head,
		fp_spd_t *spd, int cached)
{
	uint32_t i;
	fp_sp_entry_t *sp;

	fp_hlist_for_each(i, head, spd->table, list) {
		sp = &spd->table[i];

		fpdebug_printf("%"PRIu32": ", i);
		__dump_one_sp(sp, cached);
	}

	return 0;
}
#endif /* CONFIG_MCORE_IPSEC_SVTI */


static int __dump_sa_filter(fp_sa_entry_t *sa, uint32_t *saddr, int prefix_s,
		uint32_t *daddr, int prefix_d, uint32_t proto)
{
	uint32_t src = sa->src4;
	uint32_t dst = sa->dst4;

	return (proto == FP_IPPROTO_MAX || sa->proto == proto) &&
	       addr_match(&src, saddr, prefix_s) &&
	       addr_match(&dst, daddr, prefix_d);
}

static void display_sa(fp_sa_entry_t *sa)
{
	uint32_t i, j;
	uint32_t src, dst;
	fp_sa_stats_t   stats;
	int cpu;

#ifdef CONFIG_MCORE_IPSEC_SVTI
	if (sa->svti_ifuid) {
		fp_ifnet_t *ifp = __fp_ifuid2ifnet(sa->svti_ifuid);
		fpdebug_printf("svti %s(0x%"PRIx32") ",
				ifp->if_ifuid ? ifp->if_name : "<invalid>",
				ntohl(sa->svti_ifuid));
	}
#endif
	src = sa->src4;
	dst = sa->dst4;
	print_addr(&src);
	fpdebug_printf(" - ");
	print_addr(&dst);
	fpdebug_printf(" vr%"PRIu16, (uint16_t)sa->vrfid);
	fpdebug_printf(" spi 0x%x", ntohl((uint32_t)sa->spi));
	fpdebug_printf(" %s %s",
			(sa->proto == FP_IPPROTO_AH ? "AH" : "ESP"),
			(sa->mode == FP_IPSEC_MODE_TUNNEL ? "tunnel" : "transport"));

	fpdebug_printf("\n");
	fpdebug_printf("     x-vr%"PRIu16, (uint16_t)sa->xvrfid);
	if (sa->reqid)
		fpdebug_printf(" reqid=%"PRIu32, (uint32_t)sa->reqid);

	fpdebug_printf(" counter %"PRIu8, sa->counter);
	fpdebug_printf(" cached-SP %"PRIu32, (uint32_t)sa->spd_index);
	fpdebug_printf(" (genid %"PRIu32")\n", (uint32_t)sa->genid);

#if defined(CONFIG_MCORE_IPSEC_SVTI) && defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
	fpdebug_printf("     cached-svti %"PRIu32, sa->svti_idx);
	fpdebug_printf(" (genid %"PRIu32")\n", sa->svti_genid);
#endif

	if (sa->output_blade) {
		fpdebug_printf("     output_blade=%"PRIu8"\n",
				(uint8_t)sa->output_blade);
	}

	fpdebug_printf("     ");

	if (sa->state == FP_SA_STATE_ACQUIRE) {
		fpdebug_printf("(acquire in progress)\n");
		return;
	}

	if (sa->proto == FP_IPPROTO_AH)
		fpdebug_printf("%s", aalg2str(sa->alg_auth));
	else {
		fpdebug_printf("%s", ealg2str(sa->alg_enc));
		if (sa->alg_auth != FP_AALGO_NULL)
			fpdebug_printf(" %s", aalg2str(sa->alg_auth));
	}
	fpdebug_printf("%s%s%s%s\n", (sa->flags & FP_SA_FLAG_DONT_ENCAPDSCP)?" dontencapdscp":"",
	       (sa->flags & FP_SA_FLAG_DECAPDSCP)?" decapdscp":"",
	       (sa->flags & FP_SA_FLAG_NOPMTUDISC)?" nopmtudisc":"",
	       (sa->flags & FP_SA_FLAG_ESN)?" esn":"");

	if (sa->key_enc_len != 0) {
 		fpdebug_printf("     key enc:");
 		for (j = 0; j < sa->key_enc_len; j++)
 			fpdebug_printf("%02"PRIx8, (uint8_t)sa->key_enc[j]);
 		fpdebug_printf("\n");
	}
	if (sa->saltsize != 0) {
		fpdebug_printf("     nonce salt:");
		for (j = 0; j < sa->saltsize; j++)
			fpdebug_printf("%02"PRIx8, (uint8_t)sa->key_enc[sa->key_enc_len+j]);
		fpdebug_printf("\n");
	}
	if (sa->authsize != 0) {
		fpdebug_printf("     digest length: %"PRIu16"\n", sa->authsize);
		if (aalg_keylen(sa->alg_auth) > 0) {
			fpdebug_printf("     key auth:");
			for (j = 0; j < aalg_keylen(sa->alg_auth); j++)
				fpdebug_printf("%02"PRIx8, (uint8_t)sa->key_auth[j]);
			fpdebug_printf("\n");
		}
	}

	if (sa->flags & FP_SA_FLAG_UDPTUNNEL) {
		fpdebug_printf("     NAT traversal:");
		fpdebug_printf(" sport: %"PRIu16" dport: %"PRIu16"", ntohs(sa->sport), ntohs(sa->dport));
		fpdebug_printf("\n");
	}

	stats = sa->stats[0];
	for (cpu = 1; cpu < FP_IPSEC_STATS_NUM; cpu++) {
		stats.sa_packets += sa->stats[cpu].sa_packets;
		stats.sa_bytes += sa->stats[cpu].sa_bytes;
		stats.sa_auth_errors += sa->stats[cpu].sa_auth_errors;
		stats.sa_decrypt_errors += sa->stats[cpu].sa_decrypt_errors;
		stats.sa_replay_errors += sa->stats[cpu].sa_replay_errors;
		stats.sa_selector_errors += sa->stats[cpu].sa_selector_errors;
	}

	fpdebug_printf("     ");
	fpdebug_printf("sa_packets=%"PRIu64" ", stats.sa_packets);
	fpdebug_printf("sa_bytes=%"PRIu64" ", stats.sa_bytes);
	fpdebug_printf("sa_auth_errors=%"PRIu64" ", stats.sa_auth_errors);
	fpdebug_printf("sa_decrypt_errors=%"PRIu64" ", stats.sa_decrypt_errors);
	fpdebug_printf("\n");
	fpdebug_printf("     ");
	fpdebug_printf("sa_replay_errors=%"PRIu64" ", stats.sa_replay_errors);
	fpdebug_printf("sa_selector_errors=%"PRIu64" ", stats.sa_selector_errors);
	fpdebug_printf("\n");
	fpdebug_printf("     ");
	fpdebug_printf("replay width=%"PRIu32" seq=0x%"PRIx64" - oseq=0x%"PRIx64"",
			sa->replay.wsize,
			sa->replay.seq,
			sa->replay.oseq);
	if (sa->replay.wsize > FP_SECREPLAY_ESN_MAX) {
		fpdebug_printf("\n     ");
		fpdebug_printf("SA anti-replay window cannot be larger than %u",
			       FP_SECREPLAY_ESN_MAX);
	} else {
		for (i = (sa->replay.wsize + 31)/32, j = 0; i; i--) {
			if (j++ % 8 == 0)
				fpdebug_printf("\n     ");
			fpdebug_printf("%.8"PRIx32" ", sa->replay.bmp[i - 1]);
		}
	}
	fpdebug_printf("\n");
#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
	if (sa->flags & FP_SA_FLAG_LIFETIME) {
		fpdebug_printf("     soft limits : bytes=");
		FPDEBUG_XFRM_LIMIT(sa->soft.nb_bytes);
		fpdebug_printf(" packets=");
		FPDEBUG_XFRM_LIMIT(sa->soft.nb_packets);

		fpdebug_printf("\n     hard limits : bytes=");
		FPDEBUG_XFRM_LIMIT(sa->hard.nb_bytes);
		fpdebug_printf(" packets=");
		FPDEBUG_XFRM_LIMIT(sa->hard.nb_packets);
		fpdebug_printf("\n");
	}
#endif /* CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT */
}

static int dump_sad(char *tok)
{
	int tokens = gettokens(tok);
	uint32_t i;
	fp_sad_t *sad = fp_get_sad();
	uint32_t count = sad->count;
	fp_sa_entry_t *sa;
	char *str = NULL;
	uint32_t saddr = 0, daddr = 0;
	int prefix_s = 0, prefix_d = 0, max_prefix = 0;
	uint32_t proto = FP_IPPROTO_MAX;
	int do_filter = 0;
	int cur_arg = 0;
#ifdef CONFIG_MCORE_IPSEC_SVTI
	fp_ifnet_t *ifp = NULL;
	uint32_t svti_ifuid = 0;
#endif
	uint32_t *sa_index = NULL;
	uint32_t sa_match_count = 0;
	int dump_sa = 0;

	while (tokens > 0) {
		str = chargv[cur_arg++];
		tokens --;
#ifdef CONFIG_MCORE_IPSEC_SVTI
		/* svti <ifname> */
		if (!strcmp(str, "svti")) {
			if (tokens < 1) {
				fpdebug_fprintf(stderr, "svti: IFNAME is missing\n");
				return 0;
			}
			str = chargv[cur_arg++];
			tokens --;
			ifp = fp_getifnetbyname(str);
			if (!ifp || !ifp->if_ifuid) {
				fpdebug_fprintf(stderr, "svti %s: unknown interface\n", str);
				return 0;
			}
			svti_ifuid = ifp->if_ifuid;
			continue;
		}
#endif
		/* all */
		if (!strcmp(str, "all")) {
			dump_sa = 1;
		}
		/* <src> <prefix> <dst> <prefix> <proto> */
		else {
			/* parse <src> */
			if (fpdebug_inet_pton(AF_INET, (const char *)str, &saddr) <= 0) {
				fpdebug_fprintf (stderr, "Wrong arguments: invalid source network address\n");
				return 0;
			}
			max_prefix = 32;
			do_filter = 1;
			/* parse <prefix> */
			if (tokens > 0) {
				prefix_s = atoi(chargv[cur_arg++]);
				tokens --;
			}
			else if (saddr)
				prefix_s = max_prefix;
			/* parse <dst> */
			if (tokens > 0) {
				str = chargv[cur_arg++];
				tokens --;
				if (fpdebug_inet_pton(AF_INET, (const char *)str, &daddr) <= 0) {
					fpdebug_fprintf (stderr, "Wrong arguments: invalid dest network address\n");
					return 0;
				}
			}
			/* parse <prefix> */
			if (tokens > 0) {
				prefix_d = atoi(chargv[cur_arg++]);
				tokens --;
			}
			else if (daddr)
				prefix_d = max_prefix;
			/* parse <proto> */
			if (tokens > 0) {
				str = chargv[cur_arg++];
				tokens --;
				if (!strcmp(str, "esp"))
					proto = FP_IPPROTO_ESP;
				else if (!strcmp(str, "ah"))
					proto = FP_IPPROTO_AH;
			}
			goto dump;
		}
	}

dump:
	sa_index = calloc(count, sizeof(*sa_index));
	if (!sa_index) {
		fpdebug_fprintf(stderr, "%s alloc sad index failed\n", __func__);
		return 0;
	}
	for (i = 1; (count > 0) && (i < FP_MAX_SA_ENTRIES); i++) {
		sa = &sad->table[i];
		if (sa->state == FP_SA_STATE_UNSPEC)
			continue;
		count--;

		if (sa->vrfid != default_vrfid)
			continue;

#ifdef CONFIG_MCORE_IPSEC_SVTI
		if (svti_ifuid && sa->svti_ifuid != svti_ifuid)
			continue;
#endif

		if (do_filter && !__dump_sa_filter(sa, &saddr, prefix_s, &daddr, prefix_d, proto))
			continue;

		sa_index[sa_match_count++] = i;
	}
	fpdebug_printf("SAD %"PRIu32" SA.\n", sa_match_count);
	if (dump_sa) {
		for (i = 0; i < sa_match_count; i ++) {
			fpdebug_printf("%"PRIu32": ", sa_index[i]);
			display_sa(&sad->table[sa_index[i]]);
		}
	}
	free(sa_index);

	return 0;
}

static inline uint32_t fp_sp_count_by_vrfid(fp_spd_t *spd, uint16_t vrfid)
{
	uint32_t i;
	uint32_t res = 0;

	for (i=1; i < FP_MAX_SP_ENTRIES; i++) {
		if (spd->table[i].state == FP_SP_STATE_ACTIVE &&
#ifdef CONFIG_MCORE_IPSEC_SVTI
		    spd->table[i].svti_ifuid == 0 &&
#endif
		    spd->table[i].vrfid == vrfid)
			res++;
	}

	return res;
}

#ifdef CONFIG_MCORE_IPSEC_SVTI
static inline uint32_t fp_svti_sp_count(fp_hlist_head_t *head,
		fp_spd_t *spd)
{
	uint32_t i;
	uint32_t res = 0;

	fp_hlist_for_each(i, head, spd->table, list)
		res++;

	return res;
}
#endif /* CONFIG_MCORE_IPSEC_SVTI */

static int dump_spd(char *tok)
{
	fp_spd_t *spd;
	int all = 0, raw = 0;
	int tokens = gettokens(tok), cur_arg = 0;
	const char *str = NULL;
#ifdef CONFIG_MCORE_IPSEC_SVTI
	uint32_t svti_ifuid = 0;
#endif

	while (tokens > 0) {
		str = chargv[cur_arg++];
		tokens --;
#ifdef CONFIG_MCORE_IPSEC_SVTI
		/* svti <ifname> */
		if (!strcmp("svti", str)) {
			fp_ifnet_t *ifp;

			if (tokens < 1) {
				fpdebug_fprintf(stderr, "svti: IFNAME is missing\n");
				return 0;
			}
			/* parse <ifname> */
			str = chargv[cur_arg++];
			tokens --;
			ifp = fp_getifnetbyname(str);
			if (!ifp || !ifp->if_ifuid) {
				fpdebug_fprintf(stderr, "svti %s: unknown interface\n", str);
				return 0;
			}
			svti_ifuid = ifp->if_ifuid;
			continue;
		}
#endif
		if (!strcmp(str, "all"))
			all = 1;
		else if (!strcmp(str, "raw"))
			raw = 1;
		else {
#ifdef CONFIG_MCORE_IPSEC_SVTI
			fpdebug_fprintf(stderr, "usage: dump-spd [all] [svti IFNAME]\n");
#else
			fpdebug_fprintf(stderr, "usage: dump-spd [all]\n");
#endif
			fpdebug_fprintf(stderr, "   or: dump-spd raw\n");
			return 0;
		}
	}

#ifdef CONFIG_MCORE_IPSEC_SVTI
	if (svti_ifuid) /* If svti is set, raw must be ignored */
		raw = 0;
#endif

#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
	fpdebug_printf("SPD hash lookup min prefix lengths: local=%u, remote=%u\n",
	       fp_shared->ipsec.spd_hash_loc_plen,
	       fp_shared->ipsec.spd_hash_rem_plen);
#endif

	spd = fp_get_spd_in();
	if (!raw) {
#ifdef CONFIG_MCORE_IPSEC_SVTI
		if (svti_ifuid) /* Dump svti spd count */
			fpdebug_printf("Inbound svti SPD: %"PRIu32" rules\n",
				fp_svti_sp_count(fp_svti_get_spd_in(svti_ifuid), spd));
		else
#endif
			/* Dump global spd count */
			fpdebug_printf("Inbound SPD: %"PRIu32" rules\n",
				fp_sp_count_by_vrfid(spd, default_vrfid));

		if (all) {
#ifdef CONFIG_MCORE_IPSEC_SVTI
			if (svti_ifuid) /* Dump svti spd */
				__dump_svti_spd(fp_svti_get_spd_in(svti_ifuid), spd, 0);
			else
#endif
				/* Dump global spd */
				__dump_spd(spd, 0);
		}
	} else { /* Raw means dump both global and svti spd */
		fpdebug_printf("Inbound SPD: %"PRIu32" total rules, %"PRIu32" global rules\n",
				spd->entry_count, spd->global_sp_count);
		__dump_spd_raw(spd, 0);
	}

	spd = fp_get_spd_out();
	if (!raw) {
#ifdef CONFIG_MCORE_IPSEC_SVTI
		if (svti_ifuid) /* Dump svti spd count */
			fpdebug_printf("Outbound svti SPD: %"PRIu32" rules\n",
					fp_svti_sp_count(fp_svti_get_spd_out(svti_ifuid), spd));
		else
#endif
			/* Dump global spd count */
			fpdebug_printf("Outbound SPD: %"PRIu32" rules\n",
					fp_sp_count_by_vrfid(spd, default_vrfid));

		if (all) {
#ifdef CONFIG_MCORE_IPSEC_SVTI
			if (svti_ifuid) /* Dump svti spd */
				__dump_svti_spd(fp_svti_get_spd_out(svti_ifuid), spd, 1);
			else
#endif
				/* Dump global spd */
				__dump_spd(spd, 1);
		}

	} else { /* Raw means dump both global and svti spd */
		fpdebug_printf("Outbound SPD: %"PRIu32" total rules, %"PRIu32" global rules\n",
				spd->entry_count, spd->global_sp_count);
		__dump_spd_raw(spd, 1);
	}

	return 0;
}

#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
static inline void display_sp_in(fp_sp_entry_t *sp)
{
	__dump_one_sp(sp, 0);
}
static inline void display_sp_out(fp_sp_entry_t *sp)
{
	__dump_one_sp(sp, 1);
}
static inline void display_sp_hashed_in(fp_sp_entry_t *sp)
{
	char addr[INET_ADDRSTRLEN] = "A.B.C.D";
	fpdebug_inet_ntop(AF_INET, &sp->filter.dst, addr, sizeof(addr));
	fpdebug_printf("%s/%u", addr, sp->filter.dst_plen);
	fpdebug_inet_ntop(AF_INET, &sp->filter.src, addr, sizeof(addr));
	fpdebug_printf("-%s/%u", addr, sp->filter.src_plen);
	fpdebug_printf("(vr%u)", sp->vrfid);
}
static inline void display_sp_hashed_out(fp_sp_entry_t *sp)
{
	char addr[INET_ADDRSTRLEN] = "A.B.C.D";
	fpdebug_inet_ntop(AF_INET, &sp->filter.src, addr, sizeof(addr));
	fpdebug_printf("%s/%u", addr, sp->filter.src_plen);
	fpdebug_inet_ntop(AF_INET, &sp->filter.dst, addr, sizeof(addr));
	fpdebug_printf("-%s/%u", addr, sp->filter.dst_plen);
	fpdebug_printf("(vr%u)", sp->vrfid);
}
static int dump_spd_hash(char *tok)
{
	fp_spd_t *spd;
	int level = dump_hash_level(tok);

	spd = fp_get_spd_in();
	fpdebug_printf("Inbound hash table:\n");
	DUMP_HASH_TABLE(spd->addr_hash, spd->table, addr_hlist,
			display_sp_hashed_in, display_sp_in, level);
	fpdebug_printf("\n");

	spd = fp_get_spd_out();
	fpdebug_printf("Outbound hash table:\n");
	DUMP_HASH_TABLE(spd->addr_hash, spd->table, addr_hlist,
			display_sp_hashed_out, display_sp_out, level);

	return 0;
}
#endif /* CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE */

static inline uint32_t fp_sa_count_by_vrfid(fp_sad_t *sad, uint16_t vrfid)
{
	uint32_t i;
	uint32_t res = 0;
	uint32_t count = sad->count;

	for (i=0; count > 0 && i < FP_MAX_SA_ENTRIES; i++) {
		if (sad->table[i].state == FP_SA_STATE_UNSPEC)
			continue;

		count--;

		if (sad->table[i].vrfid == vrfid)
			res++;
	}

	return res;
}

#ifdef IPSEC_SPI_HASH
static void display_sa_spi(fp_sa_entry_t *sa)
{
	fpdebug_printf("0x%"PRIx32, ntohl(sa->spi));
}
static int dump_sad_spi_hash(char *tok)
{
	fp_sad_t *sad;
	int level = dump_hash_level(tok);

	sad = fp_get_sad();

	DUMP_HASH_TABLE(sad->spi_hash, sad->table, spi_hlist,
			display_sa_spi, display_sa, level);

	return 0;
}
#endif /* IPSEC_SPI_HASH */

static void display_sa_selector(fp_sa_entry_t *sa)
{
	char src[INET_ADDRSTRLEN] = "A.B.C.D";
	char dst[INET_ADDRSTRLEN] = "A.B.C.D";
	uint32_t src0 = sa->src4;
	uint32_t dst0 = sa->dst4;

	fpdebug_inet_ntop(AF_INET, &src0, src, sizeof(src));
	fpdebug_inet_ntop(AF_INET, &dst0, dst, sizeof(dst));
	if (sa->vrfid)
		fpdebug_printf("(vr%"PRIu16")%s-%s/%s",
				(uint16_t)sa->vrfid,
				src, dst,
				sa->proto == FP_IPPROTO_AH ? "AH" : "ESP");
	else
		fpdebug_printf("%s-%s/%s",
				src, dst,
				sa->proto == FP_IPPROTO_AH ? "AH" : "ESP");
}
static int dump_sad_selector_hash(char *tok)
{
	fp_sad_t *sad;
	int level = dump_hash_level(tok);

	sad = fp_get_sad();

	DUMP_HASH_TABLE(sad->selector_hash, sad->table, selector_hlist,
			display_sa_selector, display_sa, level);

	return 0;
}

#if defined(FP_STANDALONE) || !defined(__FastPath__)

/* current sa generation id */
static uint32_t fpdebug_sa_genid = 0;

/* read byte written as 2 hexadecimal nibbles */
static int get_hexbyte(uint8_t *val, const char *arg)
{
	char c;
	uint8_t high;
	uint8_t low;

	/* parse high nibble */
	c = *arg++;

	high = ((uint8_t)(c - '0') <= 9) ? (c - '0') /* 0-9 */ :
	       ((uint8_t)(c | 0x20) >= 'a') ? ((c | 0x20) - 'a' + 10) /* >= a/A */:
	       40 /* bad value */;

	if (high >= 16)
		return -1;

	/* parse low nibble */
	c = *arg;

	low = ((uint8_t)(c - '0') <= 9) ? (c - '0') /* 0-9 */ :
	      ((uint8_t)(c | 0x20) >= 'a') ? ((c | 0x20) - 'a' + 10) /* >= a/A */:
	      40 /* bad value */;

	if (low >= 16)
		return -1;

	*val = high << 4 | low;
	return 0;
}

/*
 * read crypto key in quoted string or byte stream format:
 * quoted string: "az12;:/"
 * byte stream:   0x1234567890abcdef
 *
 * return:
 *  >=0: key size
 *   -1: invalid format
 *   -2: key too long
 */
static int read_crypto_key(char *src, uint8_t *dst, int dstmaxlen)
{
	int srclen = strlen(src);
	int len = 0;
	int i;

	/* bytestream format */
	if (srclen > 4 && src[0] == '0' && src[1] == 'x' && (srclen & 1) == 0) {
		if ((srclen-2)/2 > dstmaxlen)
			return -2;
		for (i = 2; i < srclen; i += 2) {
			if (get_hexbyte(dst++, src + i) != 0)
				return -1;
		}
		len = (srclen-2)/2;
	}
	/* quoted string format */
	else if (src[0] == '"' && src[srclen-1] == '"') {
		if (srclen-2 > dstmaxlen)
			return -2;
		memcpy(dst, src + 1, srclen - 2);
		len = srclen-2;
	}
	else
		return -1;

	return len;
}

/*
 * read encryption crypto algorithm and check that key length is valid
 *
 * return:
 *  >=0: algorithm id
 *   -1: invalid key length
 *   -2: invalid algorithm name
 */
static int read_crypto_alg_enc(const char *algname, int keylen)
{
	/* aes-cbc with 128/192/256 bit key */
	if (strcmp(algname, "aes-cbc") == 0) {
		if (keylen != 16 && keylen != 24 && keylen != 32)
			return -1;
		return FP_EALGO_AESCBC;
	}
	/* 3des-cbc with 192 bit key */
	else if (strcmp(algname, "3des-cbc") == 0) {
		if (keylen != 24)
			return -1;
		return FP_EALGO_3DESCBC;
	}
	/* des-cbc with 64 bit key */
	else if (strcmp(algname, "des-cbc") == 0) {
		if (keylen != 8)
			return -1;
		return FP_EALGO_3DESCBC;
	}
	else if (strcmp(algname, "aes-gcm") == 0) {
		if (keylen != 20 && keylen != 28 && keylen != 36)
			return -1;
		return FP_EALGO_AESGCM;
	}
	else if (strcmp(algname, "aes-gmac") == 0) {
		if (keylen != 20 && keylen != 28 && keylen != 36)
			return -1;
		return FP_EALGO_NULL_AESGMAC;
	}
	return -2;
}

/*
 * read authentication crypto algorithm and check that key length is valid
 *
 * return:
 *  >=0: algorithm id
 *   -1: invalid key length
 *   -2: invalid algorithm name
 */
static int read_crypto_alg_auth(const char *algname, int keylen)
{
	/* hmac-sha1 with 160 bit key */
	if (strcmp(algname, "hmac-sha1") == 0) {
		if (keylen != 20)
			return -1;
		return FP_AALGO_HMACSHA1;
	}
	/* hmac-md5 with 128 bit key */
	else if (strcmp(algname, "hmac-md5") == 0) {
		if (keylen != 16)
			return -1;
		return FP_AALGO_HMACMD5;
	}
	/* hmac-sha256 with 256 bit key */
	else if (strcmp(algname, "hmac-sha256") == 0) {
		if (keylen != 32)
			return -1;
		return FP_AALGO_HMACSHA256;
	}
	/* hmac-sha384 with 384 bit key */
	else if (strcmp(algname, "hmac-sha384") == 0) {
		if (keylen != 48)
			return -1;
		return FP_AALGO_HMACSHA384;
	}
	/* hmac-sha512 with 512 bit key */
	else if (strcmp(algname, "hmac-sha512") == 0) {
		if (keylen != 64)
			return -1;
		return FP_AALGO_HMACSHA512;
	}
	/* aes-xcbc with 128 bit key */
	else if (strcmp(algname, "aes-xcbc") == 0) {
		if (keylen != 16)
			return -1;
		return FP_AALGO_AESXCBC;
	}

	return -2;
}

#define FPDEBUG_ADD_SA_USAGE \
	"\n\tadd-sa esp SADDR DADDR SPI MODE [vr VR] [xvr VR] [svti IFNAME]" \
	"\n\t\t[enc CRYPTALGO CRYPTKEY] [auth AUTHALGO AUTHKEY]" \
	"\n\t\t[reqid REQID]" \
	"\n\t\t[encapdscp] [decapdscp] [nopmtudisc] [replaywin SIZE]" \
	"\n\tadd-sa ah SADDR DADDR SPI MODE [vr VR] [xvr VR] [svti IFNAME]" \
	"\n\t\t[auth AUTHALGO AUTHKEY]" \
	"\n\t\t[reqid REQID]" \
	"\n\t\t[encapdscp] [decapdscp] [nopmtudisc] [replaywin SIZE]"

static int add_sa(char *tok)
{
	int count;
	int ind;
	char *word;
	char *end;
	fp_sa_entry_t user_sa;
	int sa_index;
	uint32_t addr;
	fp_sad_t *sad = fp_get_sad();

	count = gettokens(tok);

	/* 5 compulsory arguments */
	if (count < 5)
		FPDEBUG_ERRX("add-sa: too few arguments");

	memset(&user_sa, 0, sizeof(user_sa));
	ind = 0;

	/* esp|ah */
	word = chargv[ind++];
	if (strcmp(word, "esp") == 0)
		user_sa.proto = FP_IPPROTO_ESP;
	else if (strcmp(word, "ah") == 0)
		user_sa.proto = FP_IPPROTO_AH;
	else
		FPDEBUG_ERRX("%s: invalid ipsec protocol", word);

	/* SADDR */
	word = chargv[ind++];
	if (inet_pton4(word, (void*)&addr) != 1)
		FPDEBUG_ERRX("%s: invalid IPv4 address", word);
	user_sa.src4 = addr;

	/* DADDR */
	word = chargv[ind++];
	if (inet_pton4(word, (void*)&addr) != 1)
		FPDEBUG_ERRX("%s: invalid IPv4 address", word);
	user_sa.dst4 = addr;

	/* SPI */
	word = chargv[ind++];
	user_sa.spi = htonl(strtoul(word, &end, 0));
	if (*end != 0)
		FPDEBUG_ERRX("%s: invalid SPI", word);

	/* MODE */
	word = chargv[ind++];
	if (strcmp(word, "tunnel") == 0)
		user_sa.mode = FP_IPSEC_MODE_TUNNEL;
	else if (strcmp(word, "transport") == 0)
		user_sa.mode = FP_IPSEC_MODE_TRANSPORT;
	else
		FPDEBUG_ERRX("%s: invalid mode", word);

	count -= ind;

	/* optional arguments */
	while (count > 0) {
		word = chargv[ind++];
		count--;
		if (strcmp(word, "enc") == 0) {
			char *algname;
			int keylen;
			int algnum;
			if (count < 2)
				FPDEBUG_ERRX("%s: missing alg name or key", word);
			if (user_sa.proto == FP_IPPROTO_AH)
				FPDEBUG_ERRX("%s: no encryption algorithm for ah", word);
			algname = chargv[ind++];
			word = chargv[ind++];
			count -= 2;
			keylen = read_crypto_key(word, (void*)user_sa.key_enc, FP_MAX_KEY_ENC_LENGTH);
			if (keylen <= 0)
				FPDEBUG_ERRX("%s: malformed key", algname);
			user_sa.key_enc_len = keylen;
			algnum = read_crypto_alg_enc(algname, keylen);
			if (algnum < 0) {
				if (algnum == -1)
					FPDEBUG_ERRX("%s: invalid key length", algname);
				else if (algnum == -2)
					FPDEBUG_ERRX("%s: unknown enc alg", algname);
			}
			user_sa.alg_enc = (uint8_t)algnum;
		}
		else if (strcmp(word, "auth") == 0) {
			char *algname;
			int keylen;
			int algnum;
			if (count < 2)
				FPDEBUG_ERRX("%s: missing alg name or key", word);
			algname = chargv[ind++];
			word = chargv[ind++];
			count -= 2;
			keylen = read_crypto_key(word, (void*)user_sa.key_auth, FP_MAX_KEY_AUTH_LENGTH);
			if (keylen <= 0)
				FPDEBUG_ERRX("%s: malformed key", algname);
			algnum = read_crypto_alg_auth(algname, keylen);
			if (algnum < 0) {
				if (algnum == -1)
					FPDEBUG_ERRX("%s: invalid key length", algname);
				else if (algnum == -2)
					FPDEBUG_ERRX("%s: unknown auth alg", algname);
			}
			user_sa.alg_auth = (uint8_t)algnum;
			if (algnum != FP_AALGO_NULL) {
				uint16_t ahsize = sizeof(struct fp_ah) +
					fp_get_sa_ah_algo(algnum)->authsize;
				/* roundup to 4-octet */
				user_sa.ahsize = ((ahsize + 3) & ~0x03);
				/* the same, in 4-octet units, minus 2 */
				user_sa.ah_len = (user_sa.ahsize >> 2) - 2;
			}
		}
		else if (strcmp(word, "vr") == 0) {
			if (count < 1)
				FPDEBUG_ERRX("%s: missing value", word);
			word = chargv[ind++];
			count--;
			user_sa.vrfid = (uint16_t)strtoul(word, &end, 0);
			if (*end != 0)
				FPDEBUG_ERRX("%s: invalid vr", word);
		}
		else if (strcmp(word, "xvr") == 0) {
			if (count < 1)
				FPDEBUG_ERRX("%s: missing value", word);
			word = chargv[ind++];
			count--;
			user_sa.xvrfid = (uint16_t)strtoul(word, &end, 0);
			if (*end != 0)
				FPDEBUG_ERRX("%s: invalid xvr", word);
		}
#ifdef CONFIG_MCORE_IPSEC_SVTI
		else if (strcmp(word, "svti") == 0) {
			fp_ifnet_t *ifp;
			if (count < 1)
				FPDEBUG_ERRX("%s: missing ifname", word);
			word = chargv[ind++];
			count--;
			ifp = fp_getifnetbyname(word);
			if (ifp == NULL || ifp->if_type != FP_IFTYPE_SVTI)
				FPDEBUG_ERRX("%s: invalid svti ifname", word);
			user_sa.svti_ifuid = ifp->if_ifuid;
		}
#endif /* CONFIG_MCORE_IPSEC_SVTI */
		else if (strcmp(word, "reqid") == 0) {
			if (count < 1)
				FPDEBUG_ERRX("%s: missing value", word);
			word = chargv[ind++];
			count--;
			user_sa.reqid = (uint32_t)strtoul(word, &end, 0);
			if (*end != 0)
				FPDEBUG_ERRX("%s: invalid reqid", word);
		}
		else if (strcmp(word, "replaywin") == 0) {
			if (count < 1)
				FPDEBUG_ERRX("%s: missing replay window size", word);
			word = chargv[ind++];
			count--;
			user_sa.replay.wsize = (uint32_t)strtoul(word, &end, 0);
			if (*end != 0)
				FPDEBUG_ERRX("%s: invalid replay window size", word);
		}
		else if (strcmp(word, "dontencapdscp") == 0)
			user_sa.flags |= FP_SA_FLAG_DONT_ENCAPDSCP;
		else if (strcmp(word, "decapdscp") == 0)
			user_sa.flags |= FP_SA_FLAG_DECAPDSCP;
		else if (strcmp(word, "nopmtudisc") == 0)
			user_sa.flags |= FP_SA_FLAG_NOPMTUDISC;
		else
			FPDEBUG_ERRX("%s: unknown keyword", word);

	}

	/* check for duplicate SA */
	if (__fp_sa_get(sad, user_sa.spi, user_sa.dst4,
			user_sa.proto, user_sa.vrfid) != 0)
		FPDEBUG_ERRX("add-sa: SA already exists");

	if (++fpdebug_sa_genid == 0)
		++fpdebug_sa_genid;

	user_sa.genid = fpdebug_sa_genid;

	/* add SA in the SAD*/
	sa_index = fp_sa_add(sad, &user_sa);
	if (sa_index < 0)
		FPDEBUG_ERRX("add-sa: SAD is full");

	/* Activate SA in non-acquire state */
	if (user_sa.spi == 0) {
		sad->table[sa_index].state = FP_SA_STATE_ACQUIRE;
	} else {
		sad->table[sa_index].state = FP_SA_STATE_ACTIVE;
	}

end:
	return 0;
}

#define FPDEBUG_DEL_SA_USAGE \
	"\n\tdel-sa esp|ah DADDR SPI [vr VR]"

static int del_sa(char *tok)
{
	int count;
	int ind;
	char *word;
	char *end;
	fp_sa_entry_t user_sa;
	int sa_index;
	uint32_t addr;
	
	count = gettokens(tok);

	/* 5 compulsory arguments */
	if (count < 2)
		FPDEBUG_ERRX("del-sa: too few arguments");

	ind = 0;

	word = chargv[ind++];
	count--;

	memset(&user_sa, 0, sizeof(user_sa));

	/* esp|ah */
	if (strcmp(word, "esp") == 0)
		user_sa.proto = FP_IPPROTO_ESP;
	else if (strcmp(word, "ah") == 0)
		user_sa.proto = FP_IPPROTO_AH;
	else
		FPDEBUG_ERRX("%s: invalid ipsec protocol", word);

	if (count < 2)
		FPDEBUG_ERRX("del-sa: too few arguments");

	/* DADDR */
	word = chargv[ind++];
	if (inet_pton4(word, (void*)&addr) != 1)
		FPDEBUG_ERRX("%s: invalid IPv4 address", word);
	user_sa.dst4 = addr;

	/* SPI */
	word = chargv[ind++];
	user_sa.spi = htonl(strtoul(word, &end, 0));
	if (*end != 0)
		FPDEBUG_ERRX("%s: invalid SPI", word);

	count -= 2;

	/* optional arguments */
	while (count > 0) {
		word = chargv[ind++];
		count--;
		if (strcmp(word, "vr") == 0) {
			if (count < 1)
				FPDEBUG_ERRX("%s: missing value", word);
			word = chargv[ind++];
			count--;
			user_sa.vrfid = (uint16_t)strtoul(word, &end, 0);
			if (*end != 0)
				FPDEBUG_ERRX("%s: invalid vr", word);
		}
		else
			FPDEBUG_ERRX("%s: unknown keyword", word);
	}

	sa_index = fp_sa_del(fp_get_sad(), &user_sa);
	if (sa_index < 0)
		FPDEBUG_ERRX("del-sa: SA not found");

end:
	return 0;
}

#define FPDEBUG_FLUSH_SA_USAGE \
	"\n\tflush-sa [vr VR]"

static int flush_sa(char *tok)
{
	int count;
	int ind;
	char *word;
	char *end;
	uint16_t vrfid = default_vrfid;
	
	count = gettokens(tok);

	/* no compulsory arguments */

	ind = 0;

	/* optional arguments */
	while (count > 0) {
		word = chargv[ind++];
		count--;
		if (strcmp(word, "vr") == 0) {
			if (count < 1)
				FPDEBUG_ERRX("%s: missing value", word);
			word = chargv[ind++];
			count--;
			vrfid = (uint16_t)strtoul(word, &end, 0);
			if (*end != 0)
				FPDEBUG_ERRX("%s: invalid vr", word);
		}
		else
			FPDEBUG_ERRX("%s: unknown keyword", word);
	}

	fp_sa_flush_by_vrfid(fp_get_sad(), vrfid);

end:
	return 0;
}

#define FPDEBUG_ADD_SP_USAGE \
	"\n\tadd-sp in|out SADDR DADDR PROTO" \
	"\n\t\tbypass|discard|(esp|ah (tunnel SADDR DADDR)|transport) PRIORITY" \
	"\n\t\t[vr VR] [lvr VR] [svti IFNAME]" \
	"\n\t\t[reqid REQID]"

/* common code to add or update an sp */
static int __add_sp(char *tok, int update)
{
	int count;
	int ind;
	char *word;
	char *end;
	fp_sp_entry_t user_sp;
	uint32_t addr;
	char *straddr;
	char *strpflen;
	char *strport;
	int dir_output;
	int err;

	count = gettokens(tok);

	/* 5 compulsory arguments */
	if (count < 6)
		FPDEBUG_ERRX("add-sp: too few arguments");

	memset(&user_sp, 0, sizeof(user_sp));
	ind = 0;

	/* direction: in|out */
	word = chargv[ind++];
	if (strcmp(word, "in") == 0)
		dir_output = 0;
	else if (strcmp(word, "out") == 0)
		dir_output = 1;
	else
		FPDEBUG_ERRX("%s: invalid direction", word);

	/* SADDR */
	straddr = word = chargv[ind++];
	/* SADDR prefix length */
	strpflen = strchr(word, '/');
	if (strpflen) {
		*strpflen++ = 0;
		word = strpflen;
	}
	/* SADDR port */
	strport = strchr(word, '[');
	if (strport) {
		*strport++ = 0;
		end = strchr(strport, ']');
		if (end)
			*end = 0;
	}
	if (inet_pton4(straddr, (void*)&addr) != 1)
		FPDEBUG_ERRX("%s: invalid IPv4 address", straddr);
	if (strpflen) {
		user_sp.filter.src_plen = (uint8_t)strtoul(strpflen, &end, 0);
		if (*end != 0 || user_sp.filter.src_plen > 32)
			FPDEBUG_ERRX("%s: invalid prefix length", strpflen);
	}
	else
		user_sp.filter.src_plen = 32;
	user_sp.filter.src_mask = preflen2mask(user_sp.filter.src_plen);
	user_sp.filter.src = addr & user_sp.filter.src_mask;
#ifdef CONFIG_MCORE_IPSEC_LOOKUP_PORTS
	if (strport) {
		user_sp.filter.srcport = htons((uint16_t)strtoul(strport, &end, 0));
		if (*end != 0)
			FPDEBUG_ERRX("%s: invalid port", strport);
		user_sp.filter.srcport_mask = 0xFFFF;
	}
#endif /* CONFIG_MCORE_IPSEC_LOOKUP_PORTS */

	/* DADDR */
	straddr = word = chargv[ind++];
	/* DADDR prefix length */
	strpflen = strchr(word, '/');
	if (strpflen) {
		*strpflen++ = 0;
		word = strpflen;
	}
	/* DADDR port */
	strport = strchr(word, '[');
	if (strport) {
		*strport++ = 0;
		end = strchr(strport, ']');
		if (end)
			*end = 0;
	}
	if (inet_pton4(straddr, (void*)&addr) != 1)
		FPDEBUG_ERRX("%s: invalid IPv4 address", straddr);
	if (strpflen) {
		user_sp.filter.dst_plen = (uint8_t)strtoul(strpflen, &end, 0);
		if (*end != 0 || user_sp.filter.dst_plen > 32)
			FPDEBUG_ERRX("%s: invalid prefix length", strpflen);
	}
	else
		user_sp.filter.dst_plen = 32;
	user_sp.filter.dst_mask = preflen2mask(user_sp.filter.dst_plen);
	user_sp.filter.dst = addr & user_sp.filter.dst_mask;
#ifdef CONFIG_MCORE_IPSEC_LOOKUP_PORTS
	if (strport) {
		user_sp.filter.dstport = htons((uint16_t)strtoul(strport, &end, 0));
		if (*end != 0)
			FPDEBUG_ERRX("%s: invalid port", strport);
		user_sp.filter.dstport_mask = 0xFFFF;
	}
#endif /* CONFIG_MCORE_IPSEC_LOOKUP_PORTS */

	/* PROTO */
	word = chargv[ind++];
	if (strcmp(word, "any") == 0)
		user_sp.filter.ul_proto = FILTER_ULPROTO_ANY;
	else {
		user_sp.filter.ul_proto = (uint8_t)strtoul(word, &end, 0);
		if (*end != 0)
			FPDEBUG_ERRX("%s: invalid protocol", word);
	}

	count -= ind;

	/* action: bypass|discard|esp|ah */
	word = chargv[ind++];
	count--;
	if (strcmp(word, "esp") == 0) {
		user_sp.filter.action = FP_SP_ACTION_PROTECT;
		user_sp.sa_proto = FP_IPPROTO_ESP;
	}
	else if (strcmp(word, "ah") == 0) {
		user_sp.filter.action = FP_SP_ACTION_PROTECT;
		user_sp.sa_proto = FP_IPPROTO_AH;
	}
	else if (strcmp(word, "bypass") == 0) {
		user_sp.filter.action = FP_SP_ACTION_BYPASS;
		goto priority;
	}
	else if (strcmp(word, "discard") == 0) {
		user_sp.filter.action = FP_SP_ACTION_DISCARD;
		goto priority;
	}
	else
		FPDEBUG_ERRX("%s: invalid action", word);

	if (count < 1)
		FPDEBUG_ERRX("%s: missing ipsec mode", word);

	/* mode: tunnel|transport */
	word = chargv[ind++];
	count--;
	if (strcmp(word, "tunnel") == 0) {
		user_sp.mode = FP_IPSEC_MODE_TUNNEL;
		if (count < 2)
			FPDEBUG_ERRX("%s: missing SADDR and/or DADDR", word);
		/* SADDR */
		word = chargv[ind++];
		if (inet_pton4(word, (void*)&addr) != 1)
			FPDEBUG_ERRX("%s: invalid IPv4 address", word);
		user_sp.tunnel4_src = addr;

		/* DADDR */
		word = chargv[ind++];
		if (inet_pton4(word, (void*)&addr) != 1)
			FPDEBUG_ERRX("%s: invalid IPv4 address", word);
		user_sp.tunnel4_dst = addr;
		count -= 2;

	}
	else if (strcmp(word, "transport") == 0)
		user_sp.mode = FP_IPSEC_MODE_TRANSPORT;
	else
		FPDEBUG_ERRX("%s: invalid ipsec mode", word);

priority:

	if (count < 1)
		FPDEBUG_ERRX("add-sp: missing priority");

	/* PRIORITY */
	word = chargv[ind++];
	count--;
	user_sp.filter.cost = (uint32_t)strtoul(word, &end, 0);
	if (*end != 0)
		FPDEBUG_ERRX("%s: invalid priority", word);

	/* optional arguments */
	while (count > 0) {
		word = chargv[ind++];
		count--;
		if (strcmp(word, "vr") == 0) {
			if (count < 1)
				FPDEBUG_ERRX("%s: missing value", word);
			word = chargv[ind++];
			count--;
			user_sp.filter.vrfid = (uint16_t)strtoul(word, &end, 0);
			if (*end != 0)
				FPDEBUG_ERRX("%s: invalid vr", word);
			user_sp.vrfid = user_sp.filter.vrfid;
		}
		else if (strcmp(word, "lvr") == 0) {
			if (count < 1)
				FPDEBUG_ERRX("%s: missing value", word);
			word = chargv[ind++];
			count--;
			user_sp.link_vrfid = (uint16_t)strtoul(word, &end, 0);
			if (*end != 0)
				FPDEBUG_ERRX("%s: invalid lvr", word);
		}
#ifdef CONFIG_MCORE_IPSEC_SVTI
		else if (strcmp(word, "svti") == 0) {
			fp_ifnet_t *ifp;
			if (count < 1)
				FPDEBUG_ERRX("%s: missing ifname", word);
			word = chargv[ind++];
			count--;
			ifp = fp_getifnetbyname(word);
			if (ifp == NULL || ifp->if_type != FP_IFTYPE_SVTI)
				FPDEBUG_ERRX("%s: invalid svti ifname", word);
			user_sp.svti_ifuid = ifp->if_ifuid;
		}
#endif /* CONFIG_MCORE_IPSEC_SVTI */
		else if (strcmp(word, "reqid") == 0) {
			if (count < 1)
				FPDEBUG_ERRX("%s: missing value", word);
			word = chargv[ind++];
			count--;
			user_sp.reqid = (uint32_t)strtoul(word, &end, 0);
			if (*end != 0)
				FPDEBUG_ERRX("%s: invalid reqid", word);
		}
		else
			FPDEBUG_ERRX("%s: unknown keyword", word);
	}

	/* Disable caching of last used SA */
	if (user_sp.mode == FP_IPSEC_MODE_TRANSPORT &&
	       (user_sp.filter.src_plen < 32 || user_sp.filter.dst_plen < 32)) {
		user_sp.flags |= FP_SP_FLAG_NO_SA_CACHE;
	}

#ifdef CONFIG_MCORE_IPSEC_SVTI
	if (user_sp.svti_ifuid) {
		if (dir_output)
			err = fp_svti_sp_add(fp_svti_get_spd_out(user_sp.svti_ifuid),
					fp_get_spd_out(), &user_sp);
		else
			err = fp_svti_sp_add(fp_svti_get_spd_in(user_sp.svti_ifuid),
					fp_get_spd_in(), &user_sp);

		if (err < 0)
			FPDEBUG_ERRX("failed to add SP");
	} else
#endif
	{
		if (dir_output) {
			if (update)
				err = fp_sp_update(fp_get_spd_out(), &user_sp);
			else
				err = fp_sp_add(fp_get_spd_out(), &user_sp);
		} else {
			if (update)
				err = fp_sp_update(fp_get_spd_in(), &user_sp);
			else
				err = fp_sp_add(fp_get_spd_in(), &user_sp);
		}

		if (err < 0)
			FPDEBUG_ERRX("failed to add SP");

		/* activate ipsec */
		if (dir_output)
			fp_spd_out_commit();
		else
			fp_spd_in_commit();

#ifdef CONFIG_MCORE_IPSEC_TRIE
		/* request fast path to update SPD trie */
		if (dir_output)
			fp_spd_trie_out_commit();
		else
			fp_spd_trie_in_commit();
#endif	/* CONFIG_MCORE_IPSEC_TRIE */
	}

end:
	return 0;
}

static int add_sp(char *tok)
{
	return __add_sp(tok, 0);
}

static int update_sp(char *tok)
{
	return __add_sp(tok, 1);
}

#define FPDEBUG_DEL_SP_USAGE \
	"\n\tdel-sp in|out SADDR DADDR PROTO [vr VR] [svti IFNAME]"

/* return whether 2 sp selectors are equal */
static inline int __fp_sp_sel_eq(const fp_sp_entry_t *sp1,
		const fp_sp_entry_t *sp2)
{
	return (sp1->filter.vrfid == sp2->filter.vrfid
		&& sp1->filter.src == sp2->filter.src
		&& sp1->filter.dst == sp2->filter.dst
		&& sp1->filter.src_plen == sp2->filter.src_plen
		&& sp1->filter.dst_plen == sp2->filter.dst_plen
		&& sp1->filter.ul_proto == sp2->filter.ul_proto
#ifdef CONFIG_MCORE_IPSEC_LOOKUP_PORTS
		&& sp1->filter.srcport == sp2->filter.srcport
		&& sp1->filter.srcport_mask == sp2->filter.srcport_mask
		&& sp1->filter.dstport == sp2->filter.dstport
		&& sp1->filter.dstport_mask == sp2->filter.dstport_mask
#endif /* CONFIG_MCORE_IPSEC_LOOKUP_PORTS */
	       );
}

static int del_sp(char *tok)
{
	int count;
	int ind;
	char *word;
	char *end;
	fp_sp_entry_t user_sp;
	uint32_t sp_index;
	fp_hlist_head_t *head;
	fp_spd_t *spd;
	uint32_t addr;
	char *straddr;
	char *strpflen;
	char *strport;
	int dir_output;

	count = gettokens(tok);

	/* 2 compulsory arguments */
	if (count < 2)
		FPDEBUG_ERRX("del-sp4: too few arguments");

	ind = 0;

	/* direction: in|out */
	word = chargv[ind++];
	if (strcmp(word, "in") == 0) {
		dir_output = 0;
		spd = fp_get_spd_in();
	}
	else if (strcmp(word, "out") == 0) {
		dir_output = 1;
		spd = fp_get_spd_out();
	}
	else
		FPDEBUG_ERRX("%s: invalid direction", word);

	word = chargv[ind++];

	if (count < 4)
		FPDEBUG_ERRX("del-sp4: too few arguments");

	memset(&user_sp, 0, sizeof(user_sp));

	/* SADDR */
	straddr = word;
	/* SADDR prefix length */
	strpflen = strchr(word, '/');
	if (strpflen) {
		*strpflen++ = 0;
		word = strpflen;
	}
	/* SADDR port */
	strport = strchr(word, '[');
	if (strport) {
		*strport++ = 0;
		end = strchr(strport, ']');
		if (end)
			*end = 0;
	}
	if (inet_pton4(straddr, (void*)&addr) != 1)
		FPDEBUG_ERRX("%s: invalid IPv4 address", straddr);
	if (strpflen) {
		user_sp.filter.src_plen = (uint8_t)strtoul(strpflen, &end, 0);
		if (*end != 0 || user_sp.filter.src_plen > 32)
			FPDEBUG_ERRX("%s: invalid prefix length", strpflen);
	}
	else
		user_sp.filter.src_plen = 32;
	user_sp.filter.src_mask = preflen2mask(user_sp.filter.src_plen);
	user_sp.filter.src = addr & user_sp.filter.src_mask;
#ifdef CONFIG_MCORE_IPSEC_LOOKUP_PORTS
	if (strport) {
		user_sp.filter.srcport = htons((uint16_t)strtoul(strport, &end, 0));
		if (*end != 0)
			FPDEBUG_ERRX("%s: invalid port", strport);
		user_sp.filter.srcport_mask = 0xFFFF;
	}
#endif /* CONFIG_MCORE_IPSEC_LOOKUP_PORTS */

	/* DADDR */
	straddr = word = chargv[ind++];
	/* DADDR prefix length */
	strpflen = strchr(word, '/');
	if (strpflen) {
		*strpflen++ = 0;
		word = strpflen;
	}
	/* DADDR port */
	strport = strchr(word, '[');
	if (strport) {
		*strport++ = 0;
		end = strchr(strport, ']');
		if (end)
			*end = 0;
	}
	if (inet_pton4(straddr, (void*)&addr) != 1)
		FPDEBUG_ERRX("%s: invalid IPv4 address", straddr);
	if (strpflen) {
		user_sp.filter.dst_plen = (uint8_t)strtoul(strpflen, &end, 0);
		if (*end != 0 || user_sp.filter.dst_plen > 32)
			FPDEBUG_ERRX("%s: invalid prefix length", strpflen);
	}
	else
		user_sp.filter.dst_plen = 32;
	user_sp.filter.dst_mask = preflen2mask(user_sp.filter.dst_plen);
	user_sp.filter.dst = addr & user_sp.filter.dst_mask;
#ifdef CONFIG_MCORE_IPSEC_LOOKUP_PORTS
	if (strport) {
		user_sp.filter.dstport = htons((uint16_t)strtoul(strport, &end, 0));
		if (*end != 0)
			FPDEBUG_ERRX("%s: invalid port", strport);
		user_sp.filter.dstport_mask = 0xFFFF;
	}
#endif /* CONFIG_MCORE_IPSEC_LOOKUP_PORTS */

	/* PROTO */
	word = chargv[ind++];
	if (strcmp(word, "any") == 0)
		user_sp.filter.ul_proto = FILTER_ULPROTO_ANY;
	else {
		user_sp.filter.ul_proto = (uint8_t)strtoul(word, &end, 0);
		if (*end != 0)
			FPDEBUG_ERRX("%s: invalid protocol", word);
	}

	count -= ind;

	/* optional arguments */
	while (count > 0) {
		word = chargv[ind++];
		count--;
		if (strcmp(word, "vr") == 0) {
			if (count < 1)
				FPDEBUG_ERRX("%s: missing value", word);
			word = chargv[ind++];
			count--;
			user_sp.filter.vrfid = (uint16_t)strtoul(word, &end, 0);
			if (*end != 0)
				FPDEBUG_ERRX("%s: invalid vr", word);
			user_sp.vrfid = user_sp.filter.vrfid;
		}
#ifdef CONFIG_MCORE_IPSEC_SVTI
		else if (strcmp(word, "svti") == 0) {
			fp_ifnet_t *ifp;
			if (count < 1)
				FPDEBUG_ERRX("%s: missing ifname", word);
			word = chargv[ind++];
			count--;
			ifp = fp_getifnetbyname(word);
			if (ifp == NULL || ifp->if_type != FP_IFTYPE_SVTI)
				FPDEBUG_ERRX("%s: invalid svti ifname", word);
			user_sp.svti_ifuid = ifp->if_ifuid;
		}
#endif /* CONFIG_MCORE_IPSEC_SVTI */
		else
			FPDEBUG_ERRX("%s: unknown keyword", word);
	}

#ifdef CONFIG_MCORE_IPSEC_SVTI
	if (user_sp.svti_ifuid) {
		/* lookup sp by selector */
		if (dir_output)
			head = fp_svti_get_spd_out(user_sp.svti_ifuid);
		else
			head = fp_svti_get_spd_in(user_sp.svti_ifuid);

		fp_hlist_for_each(sp_index, head, spd->table, list) {
			if (__fp_sp_sel_eq(&spd->table[sp_index], &user_sp))
				break;
		}

		if (sp_index == 0)
			FPDEBUG_ERRX("del-sp4: SP not found");

		fp_svti_sp_del_by_index(head, spd, sp_index);
	} else
#endif
	{
		if (dir_output) {
#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
			if ((fp_shared->ipsec.spd_hash_loc_plen != 0 ||
			     fp_shared->ipsec.spd_hash_rem_plen != 0) &&
			    user_sp.filter.src_plen >= fp_shared->ipsec.spd_hash_loc_plen &&
			    user_sp.filter.dst_plen >= fp_shared->ipsec.spd_hash_rem_plen)
			{
				uint16_t h;
				h = sp_addrvr2hash(user_sp.filter.src, user_sp.filter.dst,
						user_sp.vrfid, fp_shared->ipsec.spd_hash_loc_plen,
						fp_shared->ipsec.spd_hash_rem_plen);
				head = &spd->addr_hash[h];
			}
			else
#endif /* CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE */
				head = fp_get_spd_head(spd);
		} else {
#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
			if ((fp_shared->ipsec.spd_hash_loc_plen != 0 ||
			     fp_shared->ipsec.spd_hash_rem_plen != 0) &&
			    user_sp.filter.src_plen >= fp_shared->ipsec.spd_hash_rem_plen &&
			    user_sp.filter.dst_plen >= fp_shared->ipsec.spd_hash_loc_plen)
			{
				uint16_t h;
				h = sp_addrvr2hash(user_sp.filter.dst, user_sp.filter.src,
						user_sp.vrfid, fp_shared->ipsec.spd_hash_loc_plen,
						fp_shared->ipsec.spd_hash_rem_plen);
				head = &spd->addr_hash[h];
			}
			else
#endif /* CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE */
				head = fp_get_spd_head(spd);
		}

		fp_hlist_for_each(sp_index, head, spd->table, list) {
			if (__fp_sp_sel_eq(&spd->table[sp_index], &user_sp))
				break;
		}

		if (sp_index == 0)
			FPDEBUG_ERRX("del-sp4: SP not found");

		fp_sp_del_by_index(spd, sp_index);

		/* disable ipsec if needed */
		if (dir_output)
			fp_spd_out_commit();
		else
			fp_spd_in_commit();

#ifdef CONFIG_MCORE_IPSEC_TRIE
		/* request fast path to update SPD trie */
		if (dir_output)
			fp_spd_trie_out_commit();
		else
			fp_spd_trie_in_commit();
#endif	/* CONFIG_MCORE_IPSEC_TRIE */
	}

end:
	return 0;
}

#define FPDEBUG_FLUSH_SP_USAGE \
	"\n\tflush-sp [vr VR] [svti IFNAME]"

static int flush_sp(char *tok)
{
	int count;
	int ind;
	char *word;
	char *end;
	uint16_t vrfid = default_vrfid;
#ifdef CONFIG_MCORE_IPSEC_SVTI
	uint32_t svti_ifuid = 0;
#endif
	
	count = gettokens(tok);

	ind = 0;

	/* no compulsory arguments */

	/* optional arguments */
	while (count > 0) {
		word = chargv[ind++];
		count--;
		if (strcmp(word, "vr") == 0) {
			if (count < 1)
				FPDEBUG_ERRX("%s: missing value", word);
			word = chargv[ind++];
			count--;
			vrfid = (uint16_t)strtoul(word, &end, 0);
			if (*end != 0)
				FPDEBUG_ERRX("%s: invalid vr", word);
		}
#ifdef CONFIG_MCORE_IPSEC_SVTI
		else if (strcmp(word, "svti") == 0) {
			fp_ifnet_t *ifp;
			if (count < 1)
				FPDEBUG_ERRX("%s: missing ifname", word);
			word = chargv[ind++];
			count--;
			ifp = fp_getifnetbyname(word);
			if (ifp == NULL || ifp->if_type != FP_IFTYPE_SVTI)
				FPDEBUG_ERRX("%s: invalid svti ifname", word);
			svti_ifuid = ifp->if_ifuid;
		}
#endif /* CONFIG_MCORE_IPSEC_SVTI */
		else
			FPDEBUG_ERRX("%s: unknown keyword", word);
	}

#ifdef CONFIG_MCORE_IPSEC_SVTI
	if (svti_ifuid) {
		fp_svti_sp_flush(fp_svti_get_spd_in(svti_ifuid), fp_get_spd_in());
		fp_svti_sp_flush(fp_svti_get_spd_out(svti_ifuid), fp_get_spd_out());
		return 0;
	}
#endif

	fp_sp_flush_by_vrfid(fp_get_spd_in(), vrfid);
	fp_sp_flush_by_vrfid(fp_get_spd_out(), vrfid);

	/* disable ipsec if needed */
	fp_spd_out_commit();
	fp_spd_in_commit();

#ifdef CONFIG_MCORE_IPSEC_TRIE
	/* request fast path to update SPD trie */
	fp_spd_trie_out_commit();
	fp_spd_trie_in_commit();
#endif

end:
	return 0;
}

#endif /* FP_STANDALONE */

#endif /* CONFIG_MCORE_IPSEC */

#ifdef CONFIG_MCORE_IPSEC_IPV6
static int __dump_one_v6_sp(fp_v6_sp_entry_t *sp, int cached)
{
	int icmp = (sp->filter.ul_proto == FP_IPPROTO_ICMPV6 ||
	            sp->filter.ul_proto == FP_IPPROTO_ICMP);
	fp_sp_stats_t   stats;
	int cpu;

	print_addr6(&sp->filter.src6);
	fpdebug_printf("/%"PRIu8, sp->filter.src_plen);

	if (!icmp) {
		print_port_range(ntohs(sp->filter.srcport),
				 ntohs(sp->filter.srcport_mask));
	}

	fpdebug_printf(" ");

	print_addr6(&sp->filter.dst6);
	fpdebug_printf("/%"PRIu8, sp->filter.dst_plen);

	if (!icmp) {
		print_port_range(ntohs(sp->filter.dstport),
				 ntohs(sp->filter.dstport_mask));
	}

	if (sp->filter.ul_proto == FILTER_ULPROTO_ANY)
		fpdebug_printf(" proto any");
	else
		fpdebug_printf(" proto %"PRIu8, sp->filter.ul_proto);

	/* print ICMPv6 type and code */
	if (icmp) {
		print_typecode(ntohs(sp->filter.srcport),
			       ntohs(sp->filter.srcport_mask),
			       ntohs(sp->filter.dstport),
			       ntohs(sp->filter.dstport_mask));
	}

	fpdebug_printf(" vr%"PRIu16, sp->filter.vrfid);

	if (sp->filter.action == FP_SP_ACTION_BYPASS)
		fpdebug_printf(" bypass");
	else if (sp->filter.action == FP_SP_ACTION_DISCARD)
		fpdebug_printf(" discard");
	else if (sp->filter.action == FP_SP_ACTION_PROTECT)
		fpdebug_printf(" protect");
	else
		fpdebug_printf(" action (%"PRIu8"?)", sp->filter.action);


	fpdebug_printf(" prio %"PRIu32"\n", sp->filter.cost);

	fpdebug_printf("     link-vr%"PRIu32, sp->link_vrfid);
	if (cached) 
		fpdebug_printf(" cached-SA %"PRIu32" genid %"PRIu32, sp->sa_index, sp->sa_genid);
#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
	if (sp->flags & FP_SP_FLAG_HASHED)
		fpdebug_printf(" hash %"PRIu16, sp->hash);
#endif
	fpdebug_printf("\n");

#ifdef CONFIG_MCORE_IPSEC_SVTI
	if (sp->svti_ifuid) {
		fp_ifnet_t *ifp = __fp_ifuid2ifnet(sp->svti_ifuid);
		fpdebug_printf("     svti=%s(0x%"PRIx32")\n",
				ifp->if_ifuid ? ifp->if_name : "<invalid>",
				ntohl(sp->svti_ifuid));
	}
#endif
	if (sp->filter.action == FP_SP_ACTION_PROTECT) {
		fpdebug_printf("    ");
		if (sp->sa_proto == FP_IPPROTO_AH)
			fpdebug_printf("AH");
		else if (sp->sa_proto == FP_IPPROTO_ESP)
			fpdebug_printf("ESP");
		else
			fpdebug_printf("proto %"PRIu8, sp->sa_proto);
		if (sp->mode == FP_IPSEC_MODE_TUNNEL) {
			fpdebug_printf(" tunnel ");
			if (sp->outer_family == AF_INET6) {
				print_addr6(&sp->tunnel6_src);
				fpdebug_printf(" - ");
				print_addr6(&sp->tunnel6_dst);
			} else {
				print_addr(&sp->tunnel4_src);
				fpdebug_printf(" - ");
				print_addr(&sp->tunnel4_dst);
			}
		} else
			fpdebug_printf(" transport");
		if (sp->reqid)
			fpdebug_printf(" reqid=%"PRIu32, sp->reqid);

		if (sp->flags & FP_SP_FLAG_LEVEL_USE)
			fpdebug_printf(" (level use)");
		fpdebug_printf("\n");
	}

	stats = sp->stats[0];
	for (cpu = 1; cpu < FP_IPSEC6_STATS_NUM; cpu++) {
		stats.sp_packets += sp->stats[cpu].sp_packets;
		stats.sp_bytes += sp->stats[cpu].sp_bytes;
		stats.sp_exceptions += sp->stats[cpu].sp_exceptions;
		stats.sp_errors += sp->stats[cpu].sp_errors;
	}

	fpdebug_printf("     ");
	fpdebug_printf("sp_packets=%"PRIu64" ", stats.sp_packets);
	fpdebug_printf("sp_bytes=%"PRIu64" ", stats.sp_bytes);
	fpdebug_printf("sp_exceptions=%"PRIu64" ", stats.sp_exceptions);
	fpdebug_printf("sp_errors=%"PRIu64"\n", stats.sp_errors);

	return 0;
}

#ifdef CONFIG_MCORE_IPSEC_SVTI
static int __dump_svti_spd6(fp_hlist_head_t *head,
		fp_spd6_t *spd, int cached)
{
	uint32_t i;
	fp_v6_sp_entry_t *sp;

	fp_hlist_for_each(i, head, spd->table, list) {
		sp = &spd->table[i];

		fpdebug_printf("%"PRIu32": ", i);
		__dump_one_v6_sp(sp, cached);
	}

	return 0;
}
static inline uint32_t fp_svti6_sp_count(fp_hlist_head_t *head,
		fp_spd6_t *spd)
{
	uint32_t i;
	uint32_t res = 0;

	fp_hlist_for_each(i, head, spd->table, list)
		res++;

	return res;
}
#endif

static int __dump_spd6(fp_spd6_t *spd, int cached)
{
	uint32_t i;
	fp_v6_sp_entry_t *sp;

#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
	if (spd->hashed_sp_count) {
		uint32_t cur;
		for (i=0; i < CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_SIZE; i++) {
			fp_hlist_for_each(cur, &spd->addr_hash[i], spd->table, addr_hlist) {
				if (cur && spd->table[cur].vrfid == default_vrfid)
					fpdebug_printf("%"PRIu32": ", cur);
				__dump_one_v6_sp(&spd->table[cur], cached);
			}
		}
	}
#endif

	if (spd->unhashed_sp_count)
		fp_hlist_for_each(i, fp_get_spd6_head(spd), spd->table, list) {
			sp = &spd->table[i];

			if (sp->vrfid != default_vrfid)
				continue;

			fpdebug_printf("%"PRIu32": ", i);
			__dump_one_v6_sp(sp, cached);
		}

	return 0;
}

static int __dump_spd6_raw(fp_spd6_t *spd, int cached)
{
	uint32_t i;
	fp_v6_sp_entry_t *sp;

	for (i = 1; i < FP_MAX_IPV6_SP_ENTRIES; i++) {
		sp = &spd->table[i];

		if (sp->state == FP_SP_STATE_UNSPEC)
			continue;

		fpdebug_printf("%"PRIu32": ", i);
		__dump_one_v6_sp(sp, cached);
	}

	return 0;
}

static int __dump_v6_sa_filter(fp_v6_sa_entry_t *sa, uint32_t *saddr, int prefix_s,
                            uint32_t *daddr, int prefix_d, uint32_t proto)
{
	uint32_t *src = sa->src6.fp_s6_addr32;
	uint32_t *dst = sa->dst6.fp_s6_addr32;

	return (proto == FP_IPPROTO_MAX || sa->proto == proto) &&
	       addr_match(src, saddr, prefix_s) &&
	       addr_match(dst, daddr, prefix_d);
}

static void display_v6_sa(fp_v6_sa_entry_t *sa)
{
	uint32_t i, j;
	fp_sa_stats_t   stats;
	int cpu;

#ifdef CONFIG_MCORE_IPSEC_SVTI
	if (sa->svti_ifuid) {
		fp_ifnet_t *ifp = __fp_ifuid2ifnet(sa->svti_ifuid);
		fpdebug_printf("svti %s(0x%"PRIx32") ",
				ifp->if_ifuid ? ifp->if_name : "<invalid>",
				ntohl(sa->svti_ifuid));
	}
#endif

	print_addr6(&sa->src6);
	fpdebug_printf(" - ");
	print_addr6(&sa->dst6);
	fpdebug_printf(" vr%"PRIu16, (uint16_t)sa->vrfid);
	fpdebug_printf(" spi 0x%x", ntohl((uint32_t)sa->spi));
	fpdebug_printf(" %s %s\n",
			(sa->proto == FP_IPPROTO_AH ? "AH" : "ESP"),
			(sa->mode == FP_IPSEC_MODE_TUNNEL ? "tunnel" : "transport"));

	fpdebug_printf("     x-vr%"PRIu16, (uint16_t)sa->xvrfid);
	if (sa->reqid)
		fpdebug_printf(" reqid=%"PRIu32, (uint32_t)sa->reqid);

	fpdebug_printf(" counter %"PRIu8, sa->counter);
	fpdebug_printf(" genid %"PRIu32, (uint32_t)sa->genid);
	fpdebug_printf(" cached-SP: %"PRIu32, (uint32_t)sa->spd_index);
	fpdebug_printf("\n");

	if (sa->output_blade) {
		fpdebug_printf("     output_blade=%"PRIu8"\n",
				(uint8_t)sa->output_blade);
	}

	fpdebug_printf("     ");

	if (sa->state == FP_SA_STATE_ACQUIRE) {
		fpdebug_printf("(acquire in progress)\n");
		return;
	}

	if (sa->proto == FP_IPPROTO_AH)
		fpdebug_printf("%s", aalg2str(sa->alg_auth));
	else {
		fpdebug_printf("%s", ealg2str(sa->alg_enc));
		if (sa->alg_auth != FP_AALGO_NULL)
			fpdebug_printf(" %s", aalg2str(sa->alg_auth));
	}
	fpdebug_printf("%s%s%s\n", (sa->flags & FP_SA_FLAG_DONT_ENCAPDSCP)?" dontencapdscp":"",
			(sa->flags & FP_SA_FLAG_DECAPDSCP)?" decapdscp":"",
			(sa->flags & FP_SA_FLAG_ESN)?" esn":"");

	if (sa->key_enc_len != 0) {
		fpdebug_printf("     key enc:");
		for (j = 0; j < sa->key_enc_len; j++)
			fpdebug_printf("%02"PRIx8, (uint8_t)sa->key_enc[j]);
		fpdebug_printf("\n");
	}
	if (sa->saltsize != 0) {
		fpdebug_printf("     nonce salt:");
		for (j = 0; j < sa->saltsize; j++)
			fpdebug_printf("%02"PRIx8, (uint8_t)sa->key_enc[sa->key_enc_len+j]);
		fpdebug_printf("\n");
	}
	if (sa->authsize != 0) {
		fpdebug_printf("     digest length: %"PRIu16"\n", sa->authsize);
		if (aalg_keylen(sa->alg_auth) > 0) {
			fpdebug_printf("     key auth:");
			for (j = 0; j < aalg_keylen(sa->alg_auth); j++)
				fpdebug_printf("%02"PRIx8, (uint8_t)sa->key_auth[j]);
			fpdebug_printf("\n");
		}
	}
	if (sa->flags & FP_SA_FLAG_UDPTUNNEL) {
		fpdebug_printf("     NAT traversal:");
		fpdebug_printf(" sport: %"PRIu16" dport: %"PRIu16,
				ntohs(sa->sport), ntohs(sa->dport));
		fpdebug_printf("\n");
	}

	stats = sa->stats[0];
	for (cpu = 1; cpu < FP_IPSEC6_STATS_NUM; cpu++) {
		stats.sa_packets += sa->stats[cpu].sa_packets;
		stats.sa_bytes += sa->stats[cpu].sa_bytes;
		stats.sa_auth_errors += sa->stats[cpu].sa_auth_errors;
		stats.sa_decrypt_errors += sa->stats[cpu].sa_decrypt_errors;
		stats.sa_replay_errors += sa->stats[cpu].sa_replay_errors;
		stats.sa_selector_errors += sa->stats[cpu].sa_selector_errors;
	}

	fpdebug_printf("     ");
	fpdebug_printf("sa_packets=%"PRIu64" ", stats.sa_packets);
	fpdebug_printf("sa_bytes=%"PRIu64" ", stats.sa_bytes);
	fpdebug_printf("sa_auth_errors=%"PRIu64" ", stats.sa_auth_errors);
	fpdebug_printf("sa_decrypt_errors=%"PRIu64" ", stats.sa_decrypt_errors);
	fpdebug_printf("\n");
	fpdebug_printf("     ");
	fpdebug_printf("sa_replay_errors=%"PRIu64" ", stats.sa_replay_errors);
	fpdebug_printf("sa_selector_errors=%"PRIu64" ", stats.sa_selector_errors);
	fpdebug_printf("\n");
	fpdebug_printf("     ");
	fpdebug_printf("replay width=%"PRIu32" seq=0x%"PRIx64" - oseq=0x%"PRIx64"",
			sa->replay.wsize,
			sa->replay.seq,
			sa->replay.oseq);
	if (sa->replay.wsize > FP_SECREPLAY_ESN_MAX) {
		fpdebug_printf("\n     ");
		fpdebug_printf("SA anti-replay window cannot be larger than %u",
			       FP_SECREPLAY_ESN_MAX);
	} else {
		for (i = (sa->replay.wsize + 31)/32, j = 0; i; i--) {
			if (j++ % 8 == 0)
				fpdebug_printf("\n     ");
			fpdebug_printf("%.8"PRIx32" ", sa->replay.bmp[i - 1]);
		}
	}
	fpdebug_printf("\n");
#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
	if (sa->flags & FP_SA_FLAG_LIFETIME) {
		fpdebug_printf("     soft limits : bytes=");
		FPDEBUG_XFRM_LIMIT(sa->soft.nb_bytes);
		fpdebug_printf(" packets=");
		FPDEBUG_XFRM_LIMIT(sa->soft.nb_packets);

		fpdebug_printf("\n     hard limits : bytes=");
		FPDEBUG_XFRM_LIMIT(sa->hard.nb_bytes);
		fpdebug_printf(" packets=");
		FPDEBUG_XFRM_LIMIT(sa->hard.nb_packets);
		fpdebug_printf("\n");
	}
#endif /* CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT */
}

#ifdef IPSEC_SPI_HASH
static void display_v6_sa_spi(fp_v6_sa_entry_t *sa)
{
	fpdebug_printf("0x%"PRIx32, ntohl(sa->spi));
}
static int dump_sad6_spi_hash(char *tok)
{
	fp_sad6_t *sad;
	int level = dump_hash_level(tok);

	sad = fp_get_sad6();

	DUMP_HASH_TABLE(sad->spi_hash, sad->table, spi_hlist,
			display_v6_sa_spi, display_v6_sa, level);

	return 0;
}
#endif /* IPSEC_SPI_HASH */

static void display_v6_sa_selector(fp_v6_sa_entry_t *sa)
{
	char src[INET6_ADDRSTRLEN] = "X::Y";
	char dst[INET6_ADDRSTRLEN] = "X::Y";

	fpdebug_inet_ntop(AF_INET6, &sa->src6, src, sizeof(src));
	fpdebug_inet_ntop(AF_INET6, &sa->dst6, dst, sizeof(dst));
	if (sa->vrfid)
		fpdebug_printf("(vr%"PRIu16")%s-%s/%s",
				(uint16_t)sa->vrfid,
				src, dst,
				sa->proto == FP_IPPROTO_AH ? "AH" : "ESP");
	else
		fpdebug_printf("%s-%s/%s",
				src, dst,
				sa->proto == FP_IPPROTO_AH ? "AH" : "ESP");
}
static int dump_sad6_selector_hash(char *tok)
{
	fp_sad6_t *sad;
	int level = dump_hash_level(tok);

	sad = fp_get_sad6();

	DUMP_HASH_TABLE(sad->selector_hash, sad->table, selector_hlist,
			display_v6_sa_selector, display_v6_sa, level);

	return 0;
}

static int set_ipsec6_output_blade(char *tok)
{
	if (gettokens(tok) != 1) {
		fpdebug_printf("Need blade id value");
		return 0;
	}
	fp_shared->ipsec6.output_blade = atoi(chargv[0]);
	return 0;
}

static inline uint32_t fp_v6_sp_count_by_vrfid(fp_spd6_t *spd, uint16_t vrfid)
{
	uint32_t i;
	uint32_t res = 0;

	for (i=1; i < FP_MAX_IPV6_SP_ENTRIES; i++) {
		if (spd->table[i].state == FP_SP_STATE_ACTIVE &&
		    spd->table[i].vrfid == vrfid)
			res++;
	}
	
	return res;
}

static int dump_spd6(char *tok)
{
	fp_spd6_t *spd;
	int all = 0, raw = 0;
	int tokens = gettokens(tok), cur_arg = 0;
	const char *str = NULL;
#ifdef CONFIG_MCORE_IPSEC_SVTI
	uint32_t svti_ifuid = 0;
#endif

	while (tokens > 0) {
		str = chargv[cur_arg++];
		tokens --;
#ifdef CONFIG_MCORE_IPSEC_SVTI
		/* svti <ifname> */
		if (!strcmp("svti", str)) {
			fp_ifnet_t *ifp;

			if (tokens < 1) {
				fpdebug_fprintf(stderr, "svti: IFNAME is missing\n");
				return 0;
			}
			/* parse <ifname> */
			str = chargv[cur_arg++];
			tokens --;
			ifp = fp_getifnetbyname(str);
			if (!ifp || !ifp->if_ifuid) {
				fpdebug_fprintf(stderr, "svti %s: unknown interface\n", str);
				return 0;
			}
			svti_ifuid = ifp->if_ifuid;
			continue;
		}
#endif
		if (!strcmp(str, "all"))
			all = 1;
		else if (!strcmp(str, "raw"))
			raw = 1;
		else {
#ifdef CONFIG_MCORE_IPSEC_SVTI
			fpdebug_fprintf(stderr, "usage: dump-spd6 [all] [svti IFNAME]\n");
#else
			fpdebug_fprintf(stderr, "usage: dump-spd6 [all]\n");
#endif
			fpdebug_fprintf(stderr, "   or: dump-spd6 raw\n");
			return 0;
		}
	}

#ifdef CONFIG_MCORE_IPSEC_SVTI
	if (svti_ifuid) /* If svti is set, raw must be ignored */
		raw = 0;
#endif

#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
	fpdebug_printf("IPv6 SPD hash lookup min prefix lengths: local=%u, remote=%u\n",
	       fp_shared->ipsec6.spd6_hash_loc_plen,
	       fp_shared->ipsec6.spd6_hash_rem_plen);
#endif

	spd = fp_get_spd6_in();
	if (!raw) {
#ifdef CONFIG_MCORE_IPSEC_SVTI
		if (svti_ifuid) /* Dump svti spd count */
			fpdebug_printf("Inbound svti SPD: %"PRIu32" rules\n",
				fp_svti6_sp_count(fp_svti6_get_spd_in(svti_ifuid), spd));
		else
#endif
			fpdebug_printf("Inbound SPD: %"PRIu32" rules\n",
					fp_v6_sp_count_by_vrfid(spd, default_vrfid));

		if (all) {
#ifdef CONFIG_MCORE_IPSEC_SVTI
			if (svti_ifuid) /* Dump svti spd */
				__dump_svti_spd6(fp_svti6_get_spd_in(svti_ifuid), spd, 0);
			else
#endif
				__dump_spd6(spd, 0);
		}
	} else {
		fpdebug_printf("Inbound SPD: %"PRIu32" total rules, %"PRIu32" global rules\n",
			spd->entry_count, spd->global_sp_count);
		__dump_spd6_raw(spd, 0);
	}

	spd = fp_get_spd6_out();
	if (!raw) {
#ifdef CONFIG_MCORE_IPSEC_SVTI
		if (svti_ifuid) /* Dump svti spd count */
			fpdebug_printf("Outbound svti SPD: %"PRIu32" rules\n",
					fp_svti6_sp_count(fp_svti6_get_spd_out(svti_ifuid), spd));
		else
#endif
			fpdebug_printf("Outbound SPD: %"PRIu32" rules\n",
					fp_v6_sp_count_by_vrfid(spd, default_vrfid));

		if (all) {
#ifdef CONFIG_MCORE_IPSEC_SVTI
			if (svti_ifuid) /* Dump svti spd */
				__dump_svti_spd6(fp_svti6_get_spd_out(svti_ifuid), spd, 1);
			else
#endif
				__dump_spd6(spd, 1);
		}
	} else {
		fpdebug_printf("Outbound SPD: %"PRIu32" total rules, %"PRIu32" global rules\n",
			spd->entry_count, spd->global_sp_count);
		__dump_spd6_raw(spd, 1);
	}

    return 0;
}

#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
static inline int display_v6_sp_in(fp_v6_sp_entry_t *sp)
{
	return __dump_one_v6_sp(sp, 0);
}
static inline int display_v6_sp_out(fp_v6_sp_entry_t *sp)
{
	return __dump_one_v6_sp(sp, 1);
}
static inline void display_v6_sp_src(fp_v6_sp_entry_t *sp)
{
	char addr[INET6_ADDRSTRLEN] = "X::Y";
	fpdebug_inet_ntop(AF_INET6, &sp->filter.src6, addr, sizeof(addr));
	fpdebug_printf("%s", addr);
}
static inline void display_v6_sp_dst(fp_v6_sp_entry_t *sp)
{
	char addr[INET6_ADDRSTRLEN] = "X::Y";
	fpdebug_inet_ntop(AF_INET6, &sp->filter.dst6, addr, sizeof(addr));
	fpdebug_printf("%s", addr);
}
static inline void display_v6_sp_hashed_in(fp_v6_sp_entry_t *sp)
{
	char addr[INET6_ADDRSTRLEN] = "X::Y";
	fpdebug_inet_ntop(AF_INET6, &sp->filter.dst6, addr, sizeof(addr));
	fpdebug_printf("%s/%u", addr, sp->filter.dst_plen);
	fpdebug_inet_ntop(AF_INET6, &sp->filter.src6, addr, sizeof(addr));
	fpdebug_printf("-%s/%u", addr, sp->filter.src_plen);
	fpdebug_printf("(vr%u)", sp->vrfid);
}
static inline void display_v6_sp_hashed_out(fp_v6_sp_entry_t *sp)
{
	char addr[INET6_ADDRSTRLEN] = "X::Y";
	fpdebug_inet_ntop(AF_INET6, &sp->filter.src6, addr, sizeof(addr));
	fpdebug_printf("%s/%u", addr, sp->filter.src_plen);
	fpdebug_inet_ntop(AF_INET6, &sp->filter.dst6, addr, sizeof(addr));
	fpdebug_printf("-%s/%u", addr, sp->filter.dst_plen);
	fpdebug_printf("(vr%u)", sp->vrfid);
}

static int dump_spd6_hash(char *tok)
{
	fp_spd6_t *spd;
	int level = dump_hash_level(tok);

	spd = fp_get_spd6_in();
	fpdebug_printf("Inbound hash table:\n");
	DUMP_HASH_TABLE(spd->addr_hash, spd->table, addr_hlist,
			display_v6_sp_hashed_in, display_v6_sp_in, level);
	fpdebug_printf("\n");

	spd = fp_get_spd6_out();
	fpdebug_printf("Outbound hash table:\n");
	DUMP_HASH_TABLE(spd->addr_hash, spd->table, addr_hlist,
			display_v6_sp_hashed_out, display_v6_sp_out, level);
	fpdebug_printf("\n");

	return 0;
}
#endif /* CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE */

static inline uint32_t fp_v6_sa_count_by_vrfid(fp_sad6_t *sad, uint16_t vrfid)
{
	uint32_t i;
	uint32_t res = 0;
	uint32_t count = sad->count;

	for (i=0; count > 0 && i < FP_MAX_IPV6_SA_ENTRIES; i++) {
		if (sad->table[i].state == FP_SA_STATE_UNSPEC)
			continue;

		count--;

		if (sad->table[i].vrfid == vrfid)
			res++;
	}
	
	return res;
}

static int dump_sad6(char *tok)
{
	int tokens = gettokens(tok);
	uint32_t i;
	fp_sad6_t *sad = fp_get_sad6();
	uint32_t count = sad->count;
	fp_v6_sa_entry_t *sa;
	char *str = NULL;
	uint32_t saddr[4] = {0}, daddr[4] = {0};
	int prefix_s = 0, prefix_d = 0, max_prefix = 0;
	uint32_t proto = FP_IPPROTO_MAX;
	int do_filter = 0;
	int cur_arg = 0;
#ifdef CONFIG_MCORE_IPSEC_SVTI
	fp_ifnet_t *ifp = NULL;
	uint32_t svti_ifuid = 0;
#endif
	uint32_t *sa_index = NULL;
	uint32_t sa_match_count = 0;
	int dump_sa = 0;

	while (tokens > 0) {
		str = chargv[cur_arg++];
		tokens --;
#ifdef CONFIG_MCORE_IPSEC_SVTI
		/* svti <ifname> */
		if (!strcmp(str, "svti")) {
			if (tokens < 1) {
				fpdebug_fprintf(stderr, "svti: IFNAME is missing\n");
				return 0;
			}
			str = chargv[cur_arg++];
			tokens --;
			ifp = fp_getifnetbyname(str);
			if (!ifp || !ifp->if_ifuid) {
				fpdebug_fprintf(stderr, "svti %s: unknown interface\n", str);
				return 0;
			}
			svti_ifuid = ifp->if_ifuid;
			continue;
		}
#endif
		/* all */
		if (!strcmp(str, "all")) {
			dump_sa = 1;
		}
		/* <src> <prefix> <dst> <prefix> <proto> */
		else {
			/* parse <src> */
			if (fpdebug_inet_pton(AF_INET6, (const char *)str, saddr) <= 0) {
				fpdebug_fprintf (stderr, "Wrong arguments: invalid source network address\n");
				return 0;
			}
			max_prefix = 128;
			do_filter = 1;
			/* parse <prefix> */
			if (tokens > 0) {
				prefix_s = atoi(chargv[cur_arg++]);
				tokens --;
			}
			else
				prefix_s = max_prefix;
			/* parse <dst> */
			if (tokens > 0) {
				str = chargv[cur_arg++];
				tokens --;
				if (fpdebug_inet_pton(AF_INET6, (const char *)str, daddr) <= 0) {
					fpdebug_fprintf (stderr, "Wrong arguments: invalid dest network address\n");
					return 0;
				}
				/* parse <prefix> */
				if (tokens > 0) {
					prefix_d = atoi(chargv[cur_arg++]);
					tokens --;
				}
				else
					prefix_d = max_prefix;
			}
			/* parse <proto> */
			if (tokens > 0) {
				str = chargv[cur_arg++];
				tokens --;
				if (!strcmp(str, "esp"))
					proto = FP_IPPROTO_ESP;
				else if (!strcmp(str, "ah"))
					proto = FP_IPPROTO_AH;
			}
			goto dump;
		}
	}

dump:
	sa_index = calloc(count, sizeof(*sa_index));
	if (!sa_index) {
		fpdebug_fprintf(stderr, "%s alloc sad index failed\n", __func__);
		return 0;
	}
	for (i = 1; (count > 0) && (i < FP_MAX_IPV6_SA_ENTRIES); i++) {
		sa = &sad->table[i];
		if (sa->state == FP_SA_STATE_UNSPEC)
			continue;
		count--;

		if (sa->vrfid != default_vrfid)
			continue;

#ifdef CONFIG_MCORE_IPSEC_SVTI
		if (svti_ifuid && sa->svti_ifuid != svti_ifuid)
			continue;
#endif

		if (do_filter && !__dump_v6_sa_filter(sa, saddr, prefix_s, daddr, prefix_d, proto))
			continue;

		sa_index[sa_match_count++] = i;
	}
	fpdebug_printf("IPv6 SAD %"PRIu32" SA.\n", sa_match_count);
	if (dump_sa) {
		for (i = 0; i < sa_match_count; i ++) {
			fpdebug_printf("%"PRIu32": ", sa_index[i]);
			display_v6_sa(&sad->table[sa_index[i]]);
		}
	}
	free(sa_index);

	return 0;
}

#endif  /* CONFIG_MCORE_IPSEC_IPV6 */

#ifdef CONFIG_MCORE_IPSEC_SVTI
static int dump_one_svti(fp_ifnet_t *ifp, uint32_t idx, int all)
{
	uint32_t ifuid, sp_count;
	fp_spd_t *spd;
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_spd6_t *spd6;
#endif
	fp_svti_t *svti = &fp_shared->svti[idx];

	ifuid = svti->ifuid;

	if (ifp->if_ifuid == 0) {
		fpdebug_printf("[%"PRIu32"] <invalid> ifuid=0x%08x\n",
		               idx, ntohl(ifuid));
	}
	else {
		fpdebug_printf("[%"PRIu32"] %s [VR-%"PRIu16"] ifuid=0x%08x\n",
		               idx, ifp->if_name, ifp->if_vrfid, ntohl(ifuid));
	}

#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
	{
		char laddr[INET_ADDRSTRLEN] = "A.B.C.D";
		char raddr[INET_ADDRSTRLEN] = "A.B.C.D";

		fpdebug_inet_ntop(AF_INET, &svti->laddr, laddr, sizeof(laddr));
		fpdebug_inet_ntop(AF_INET, &svti->raddr, raddr, sizeof(raddr));
		fpdebug_printf("     local=%s remote=%s link-vrfid=%"PRIu32"\n",
				laddr, raddr, svti->link_vrfid);
	}
#endif

	spd = fp_get_spd_in();
#ifdef CONFIG_MCORE_IPSEC_IPV6
	spd6 = fp_get_spd6_in();
#endif
	sp_count = fp_svti_sp_count(&svti->spd_in, spd)
#ifdef CONFIG_MCORE_IPSEC_IPV6
		+ fp_svti6_sp_count(&svti->spd6_in, spd6)
#endif
		;

	fpdebug_printf("Inbound SPD: %"PRIu32" rules\n", sp_count);
	if (all) {
		__dump_svti_spd(&svti->spd_in, spd, 0);
#ifdef CONFIG_MCORE_IPSEC_IPV6
		__dump_svti_spd6(&svti->spd6_in, spd6, 0);
#endif
	}

	spd = fp_get_spd_out();
#ifdef CONFIG_MCORE_IPSEC_IPV6
	spd6 = fp_get_spd6_out();
#endif
	sp_count = fp_svti_sp_count(&svti->spd_out, spd)
#ifdef CONFIG_MCORE_IPSEC_IPV6
		+ fp_svti6_sp_count(&svti->spd6_out, spd6)
#endif
		;

	fpdebug_printf("Outbound SPD: %"PRIu32" rules\n", sp_count);
	if (all) {
		__dump_svti_spd(&svti->spd_out, spd, 1);
#ifdef CONFIG_MCORE_IPSEC_IPV6
		__dump_svti_spd6(&svti->spd6_out, spd6, 0);
#endif
	}

	return 0;
}

static int dump_svti(char *tok)
{
	int tokens = gettokens(tok), all = 0, cur_arg = 0;
	uint32_t i, ifuid;
	char *str = NULL, *svti_ifname = NULL;
	fp_ifnet_t *ifp = NULL;

	while (tokens > 0) {
		str = chargv[cur_arg++];
		tokens --;
		/* svti <ifname> */
		if (!strcmp(str, "svti")) {
			if (tokens < 1) {
				fpdebug_fprintf(stderr, "svti: IFNAME is missing\n");
				return 0;
			}
			/* parse <ifname> */
			svti_ifname = chargv[cur_arg++];
			tokens --;
			ifp = fp_getifnetbyname(svti_ifname);
			if (!ifp || !ifp->if_ifuid || ifp->if_type != FP_IFTYPE_SVTI) {
				fpdebug_fprintf(stderr, "svti %s: unknown interface\n", str);
				return 0;
			}
			continue;
		}
		if (!strcmp(str, "all"))
			all = 1;
		else {
			fpdebug_fprintf(stderr, "usage: dump-svti [all] [svti IFNAME]\n");
			return 0;
		}
	}

	if (ifp) {
		dump_one_svti(ifp, ifp->sub_table_index, all);
	} else for (i=1; i<FP_MAX_SVTI; i++) {

		ifuid = fp_shared->svti[i].ifuid;
		if (!ifuid)
			continue;
		ifp  = __fp_ifuid2ifnet(ifuid);

		dump_one_svti(ifp, i, all);
	}
	return 0;
}

#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
static void display_ifnet(fp_ifnet_t *ifp);

static inline void display_svti_ifname(fp_svti_t *svti)
{
	fpdebug_printf("%s(0x%08x)", __fp_ifuid2ifnet(svti->ifuid)->if_name,
		ntohl(svti->ifuid));
}

static inline void display_svti_detail(fp_svti_t *svti)
{
	dump_one_svti(__fp_ifuid2ifnet(svti->ifuid),
	              ARRAY_INDEX(svti, fp_shared->svti), 0);
}

static int dump_svti_hash(char *tok)
{
	int level = dump_hash_level(tok);

	fpdebug_printf("svti hash table:\n");
	DUMP_HASH_TABLE(fp_shared->svti_hash, fp_shared->svti,
			hlist, display_svti_ifname, display_svti_detail,
			level);

	return 0;
}
#endif /* CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA */
#endif /* CONFIG_MCORE_IPSEC_SVTI */

#ifdef CONFIG_MCORE_IP
/* Show the amount of used memory for each table */
static int show_filling(char *tok __fpn_maybe_unused)
{
	uint32_t i;
	uint32_t count;
	uint32_t count_v4;
	uint32_t count_v6;

	fpdebug_printf("Tables filling:\n");

	/* Intermediate tables */
	count = 0;
	count_v4 = 0;
	count_v6 = 0;
	for (i = 0; i < FP_NB_8_TABLE_ENTRIES; i++) {
		if(fp_shared->fp_8_table[i].used != 0) {
			count++;
			if(fp_shared->fp_8_table[i].used == FP_USED_V4)
				count_v4++;
			else if(fp_shared->fp_8_table[i].used == FP_USED_V6)
				count_v6++;
		}
	}
	fpdebug_printf("fp_8_table: %"PRIu32"/%"PRIu32"", count, FP_NB_8_TABLE_ENTRIES);
	fpdebug_printf(" (%f%%)", ((float)count)/FP_NB_8_TABLE_ENTRIES*100);
#ifdef CONFIG_MCORE_IPV6
	fpdebug_printf(" IPv4:%"PRIu32" IPv6:%"PRIu32"", count_v4, count_v6);
#endif
	fpdebug_printf("\n");

#if (defined FP_NB_16_TABLE_ENTRIES) && FP_NB_16_TABLE_ENTRIES != 0
	count = 0;
	count_v4 = 0;
	count_v6 = 0;
	for (i = 0; i < FP_NB_16_TABLE_ENTRIES; i++) {
		if(fp_shared->fp_16_table[i].used != 0) {
			count++;
			if(fp_shared->fp_16_table[i].used == FP_USED_V4)
				count_v4++;
			else if(fp_shared->fp_16_table[i].used == FP_USED_V6)
				count_v6++;
		}
	}
	fpdebug_printf("fp_16_table: %"PRIu32"/%"PRIu32"", count, FP_NB_16_TABLE_ENTRIES);
	fpdebug_printf(" (%f%%)\n", ((float)count)/FP_NB_16_TABLE_ENTRIES*100);
#ifdef CONFIG_MCORE_IPV6
	fpdebug_printf(" IPv4:%"PRIu32" IPv6:%"PRIu32"", count_v4, count_v6);
#endif
	fpdebug_printf("\n");
#endif

	/* Entries tables */
	count = 0;
	for (i = 0; i < FP_NB_8_ENTRIES; i++) {
		if(fp_shared->fp_8_entries[i].index != 0)
			count++;
	}
	fpdebug_printf("fp_8_entries: %"PRIu32"/%"PRIu32"", count, FP_NB_8_ENTRIES);
	fpdebug_printf(" (%f%%)\n", ((float)count)/FP_NB_8_ENTRIES*100);

#if (defined FP_NB_16_TABLE_ENTRIES) && FP_NB_16_TABLE_ENTRIES != 0
	count = 0;
	for (i = 0; i < FP_NB_16_ENTRIES; i++) {
		if(fp_shared->fp_16_entries[i].index != 0)
			count++;
	}
	fpdebug_printf("fp_16_entries: %"PRIu32"/%"PRIu32"", count, FP_NB_16_ENTRIES);
	fpdebug_printf(" (%f%%)\n", ((float)count)/FP_NB_16_ENTRIES*100);
#endif

	/* Routes table */
	count = 0;
	for (i = 1; i < FP_IPV4_NBRTENTRIES; i++) {
		if(fp_shared->fp_rt4_table[i].rt.rt_refcnt != 0)
			count++;
	}
	fpdebug_printf("fp_rt4_table: %"PRIu32"/%"PRIu32"", count, FP_IPV4_NBRTENTRIES);
	fpdebug_printf(" (%f%%)\n", ((float)count)/FP_IPV4_NBRTENTRIES*100);
#ifdef CONFIG_MCORE_IPV6
	count = 0;
	for (i = 1; i < FP_IPV6_NBRTENTRIES; i++) {
		if(fp_shared->fp_rt6_table[i].rt.rt_refcnt != 0)
			count++;
	}
	fpdebug_printf("fp_rt6_table: %"PRIu32"/%"PRIu32"", count, FP_IPV6_NBRTENTRIES);
	fpdebug_printf(" (%f%%)\n", ((float)count)/FP_IPV6_NBRTENTRIES*100);
#endif


	/* Neighbours table */
	count = 0;
	for (i = 1; i < FP_IPV4_NBNHENTRIES; i++) {
		if(fp_shared->fp_nh4_table[i].nh.nh_refcnt != 0)
			count++;
	}
	fpdebug_printf("fp_nh4_table: %"PRIu32"/%"PRIu32"", count, FP_IPV4_NBNHENTRIES);
	fpdebug_printf(" (%f%%)\n", ((float)count)/FP_IPV4_NBNHENTRIES*100);
#ifdef CONFIG_MCORE_IPV6
	count = 0;
	for (i = 1; i < FP_IPV6_NBNHENTRIES; i++) {
		if(fp_shared->fp_nh6_table[i].nh.nh_refcnt != 0)
			count++;
	}
	fpdebug_printf("fp_nh6_table: %"PRIu32"/%"PRIu32"", count, FP_IPV6_NBNHENTRIES);
	fpdebug_printf(" (%f%%)\n", ((float)count)/FP_IPV6_NBNHENTRIES*100);
#endif
	return 0;
}
#endif /* CONFIG_MCORE_IP */

static int set_blade_id(char *tok)
{
	uint8_t id, cp_id = 0;
	uint8_t count = gettokens(tok);

	if (count < 1 || count > 2) {
		fpdebug_fprintf (stderr, "wrong arguments: set-blade-id <id> [cp_blade_id]\n");
		return 0;
	}

#ifdef CONFIG_MCORE_1CP_XFP
	if (count > 1)
		cp_id = atoi(chargv[1]);
#endif
	id = atoi(chargv[0]);
	if (fp_set_blade_id(id, cp_id))
		fpdebug_fprintf (stderr, "bad blade_id value\n");
	return 0;
}

static int set_active_cpid(char *tok)
{
	uint8_t id = 0;
	uint8_t count = gettokens(tok);

	if (count != 1) {
		fpdebug_fprintf (stderr, "wrong arguments: set-active-cpid <id>\n");
		return 0;
	}

	id = atoi(chargv[0]);
	if (fp_set_active_cpid(id))
		fpdebug_fprintf (stderr, "bad cpid value\n");
	return 0;
}

static int set_blade_cp(char *tok)
{
	uint8_t if_port;
	uint8_t mac[6] = { 0,0,0,0,0,0 };
	uint8_t count = gettokens(tok);
	uint32_t mtu = 1280;

	if (count < 1 || count > 4) {
		fpdebug_fprintf (stderr, "wrong arguments: set-blade-cp <if_port> [<mac>] [mtu <mtu>]\n");
		return 0;
	}
	if_port = atoi(chargv[0]);
	switch (count) {
	case 2:
		string2mac(chargv[1], mac);
		break;
	case 3:
		mtu = atoi(chargv[2]);
		break;
	case 4:
		if (!strcmp(chargv[1], "mtu")) {
			mtu = atoi(chargv[2]);
			string2mac(chargv[3], mac);
		} else {
			string2mac(chargv[1], mac);
			mtu = atoi(chargv[3]);
		}
		break;
	}

	if (fp_set_cp_info(if_port, mac, mtu, 0))
		fpdebug_fprintf (stderr, "wrong arguments: bad <if_port>, <mac> or <mtu>\n");

	return 0;
}

#ifdef CONFIG_MCORE_MULTIBLADE
static int set_fpib_ifuid(char *tok)
{
	uint32_t ifuid;
	uint8_t count = gettokens(tok);

	if (count != 1) {
		fpdebug_fprintf (stderr, "wrong arguments: set-fpib-ifuid <ifuid>\n");
		return 0;
	}

	ifuid = atoi(chargv[0]);

	fp_set_fpib_ifuid(ifuid, 0);

	return 0;
}

static int add_blade(char *tok)
{
	uint8_t mac[6];
	uint8_t id;
	uint8_t count = gettokens(tok);

	if ( count != 2 && count != 3) {
		fpdebug_fprintf (stderr, "wrong arguments: add-blade <id> <mac> [local]\n");
		return 0;
	}
	id = atoi(chargv[0]);
	string2mac(chargv[1], mac);
	if (count == 2) {
		fp_add_blade(id, 0, mac);
	} else {
		if (strcmp(chargv[2], "local") == 0) {
			fp_add_blade(id, 1, mac);
		} else {
			fpdebug_fprintf (stderr, "wrong arguments: add-blade <id> <mac> [local]\n");
			return 0;
		}
	}
	return 0;
}

static int del_blade(char *tok)
{
	uint8_t id;
	uint8_t count = gettokens(tok);

	if (count != 1 && count != 2) {
		fpdebug_fprintf (stderr, "wrong arguments: del-blade <id> [local]\n");
		return 0;
	}

	id = atoi(chargv[0]);
	if (count == 1) {
		fp_delete_blade(id, 0);
	} else {
		if (strcmp(chargv[2], "local") == 0) {
			fp_delete_blade(id, 1);
		} else {
			fpdebug_fprintf (stderr, "wrong arguments: del-blade <id> [local]\n");
			return 0;
		}
	}

	return 0;
}
#endif /* CONFIG_MCORE_MULTIBLADE */

static int dump_blades(char *tok __fpn_maybe_unused)
{
	fpdebug_printf("Local blade: \n");
	fpdebug_printf("  blade ID: %"PRIu8"\n", fp_shared->fp_blade_id);

	if (fp_shared->cp_if_port == IF_PORT_COLOC) {
		fpdebug_printf("  FPVI interface: co-localized CP, fpn0 mac ");
		print_mac((uint8_t *)&fp_shared->cp_if_mac);
		fpdebug_printf(", mtu %"PRIu32"\n", fp_shared->cp_if_mtu);
	} else {
		fpdebug_printf("  FPVI interface: ifport %"PRIu8", mac ", fp_shared->cp_if_port);
		print_mac((uint8_t *)&fp_shared->cp_if_mac);
		fpdebug_printf(", mtu %"PRIu32"\n", fp_shared->cp_if_mtu);
	}
#ifdef CONFIG_MCORE_MULTIBLADE
	fp_blade_t *blade;
	int i;

#ifdef CONFIG_MCORE_1CP_XFP
	fpdebug_printf("  CP blade ID: %"PRIu8"\n", fp_shared->cp_blade_id);
#endif
	fpdebug_printf("  FPIB interface: ");

	if (fp_shared->fpib_ifuid) {
		fp_ifnet_t *ifnet;
		fpdebug_printf("ifuid %"PRIu32, fp_shared->fpib_ifuid);
		ifnet = fp_ifuid2ifnet(fp_shared->fpib_ifuid);
		if (ifnet) {
			fpdebug_printf(" (%s", ifnet->if_name);
			fpdebug_printf(", mac ");
			print_mac((uint8_t *)ifnet->if_mac);
			fpdebug_printf(")\n");
		} else {
			fpdebug_printf(" (unknown interface)\n");
		}
	}
	else
		fpdebug_printf("undefined\n");

	fpdebug_printf("  Active CP ID: %"PRIu8"\n", fp_shared->active_cpid);

	fpdebug_printf("Blade list:\n");
	for (i=1; i<= FP_BLADEID_MAX; i++) {
		blade = &fp_shared->fp_blades[i];
		if (blade->blade_active) {
			fpdebug_printf("  ID %d", i);
			fpdebug_printf(": mac ");
			print_mac((uint8_t *)&blade->blade_mac);
			fpdebug_printf("\n");
		}
	}
#endif

	return 0;
}

#if !defined(__FastPath__) && defined(CONFIG_MCORE_TAP_BPF)
static int dump_bpf(char *tok)
{
	uint32_t idx, j, n;
	uint8_t count = gettokens(tok);
	fp_bpf_filter_t *bpf;

	fpdebug_printf("BPF list (ifuid 0 is the virtual interface \"any\"):\n");
	for (idx = 0; idx < FP_MAX_IFNET; idx++)
		for (j = 0; j < FP_BPF_MAXINSTANCE; j++) {
			bpf = &fp_shared->fp_bpf_filters[idx][j];
			if (bpf->num) {
				fpdebug_printf("%"PRIu32": ifuid 0x%08x, instance %"PRIu32" (# cmds: %"PRIu32")\n", idx,
						ntohl(fp_shared->ifnet.table[idx].if_ifuid), j, bpf->num);
				if (count == 2)
					for (n = 0; n < bpf->num ; n++)
						fpdebug_printf("{ 0x%02"PRIx16" %"PRIu8" %"PRIu8" %"PRIu32" },\n",
								bpf->filters[n].code,
								bpf->filters[n].jt,
								bpf->filters[n].jf,
								bpf->filters[n].k);
				else if (count == 1)
					for (n = 0; n < bpf->num ; n++)
#ifdef CONFIG_MCORE_FPDEBUG_DECODE_BPF
						puts(bpf_image((struct bpf_insn *)&bpf->filters[n], n));
#else
						/* fall back to raw mode */
						fpdebug_printf("{ 0x%02"PRIx16" %"PRIu8" %"PRIu8" %"PRIu32" },\n",
								bpf->filters[n].code,
								bpf->filters[n].jt,
								bpf->filters[n].jf,
								bpf->filters[n].k);
#endif
			}
		}

	return 0;
}

static int set_tap_iface(char *tok)
{
	int argc = gettokens(tok);
	fp_bpf_filter_t req;
	fp_ifnet_t *ifp;

	if (argc != 2) {
		fpdebug_fprintf(stderr,
				"wrong arguments: set-tap-iface <ifname|any> <on|off>\n");
		return 0;
	}

	memset(&req, 0, sizeof(req));

	ifp = fp_getifnetbyname(chargv[0]);
	if (ifp == NULL)
		req.ifuid = 0;
	else
		req.ifuid = ifp->if_ifuid;

	req.status = BPF_FILTER_PERMANENT;
	req.num = 1;
	req.filters[0].code = 0x06;
	req.filters[0].jt = 0;
	req.filters[0].jf = 0;
	req.filters[0].k = 0xffff;

	if (strcmp(chargv[1], "on") == 0)
		fp_bpf_create(&req);
	else
		fp_bpf_del(&req);

	return 0;
}
#endif /* !__FastPath__ && CONFIG_MCORE_TAP_BPF */

#ifdef CONFIG_MCORE_MULTICAST4
static int dump_mfc4(char *tok)
{
	uint32_t i, index;
	fp_mfc_entry_t *c;
	fp_ifnet_t *ifp;

	fpdebug_printf("MFC list:\n");
	for (i = 0; i < FP_MFC_MAX; i++) {
		c = &fp_shared->fp_mfc_table[i];
		if (c->iif != FP_IIF_UNUSED) {
			fpdebug_printf("\t(");
			print_addr(&c->origin);
			fpdebug_printf(" ,");
			print_addr(&c->mcastgrp);
			ifp = __fp_ifuid2ifnet(c->iif);
			fpdebug_printf("), Incoming interface: %s (0x%08x)\n",
				       ifp->if_name, ntohl(c->iif));
			fpdebug_printf("\t\t Outgoing interfaces:\n");
			for (index = 0; index < FP_MAXVIFS && c->oifs[index]; index++) {
				ifp = __fp_ifuid2ifnet(c->oifs[index]);
				fpdebug_printf("\t\t\t %s (0x%08x)\n", ifp->if_name,
					       ntohl(c->oifs[index]));
			}
			fpdebug_printf("\t\t Pkts: %"PRIu64" Bytes: %"PRIu64"\n", c->pkt, c->bytes);
			fpdebug_printf("\t\t Offset: %"PRIu32" Next: %"PRIu16"\n", i, (uint16_t)c->next);
		}
	}
	return 0;
}

static int mcastgrp_filter(char *tok)
{

	int res = -1, ind = 0;
	int count;
	char *word;
	uint8_t *opt = &fp_shared->fp_mcastgrp_opt;

	count = gettokens(tok);

	/* check validity of argument count */
	if (count > 2) {
		FPDEBUG_ERRX("wrong arguments: mcastgrp-filter [on [accept-all]|off]");
	}

	/* no parameter given, display the status of the filtering and groups in whitelist
	   if enabled */
	if (count == 0) {
		int i;
		char addr[INET_ADDRSTRLEN];
		char ifname[255];

		fpdebug_printf("Multicast IPv4 group filtering is %s\n",
				*opt ? "on":"off");
		fpdebug_printf("Accept all packets on link local: %s\n",
			       (*opt == FP_MCASTGRP_OPT_ACCEPT_LL)?"yes":"no");
		if (fp_shared->fp_mcastgrp_num)
			fpdebug_printf("\n%-17s| incoming interface\n\n",
				       "group");

		/* Display all entries in whitelist */
		for (i = 0; i < fp_shared->fp_mcastgrp_num; i++) {

			/* traduct ifuid to interface name */
			if (fp_shared->fp_mcastgrp_table[i].ifuid) {
				strcpy(ifname, fp_ifuid2str(fp_shared->fp_mcastgrp_table[i].ifuid));
				if (!strcmp(ifname,""))
					sprintf(ifname, "unknown ifuid %u",
						fp_shared->fp_mcastgrp_table[i].ifuid);
			} 
			else
				sprintf(ifname, "all");

			/* traduct address from network to ascii */
			fpdebug_inet_ntop(AF_INET,
					  &fp_shared->fp_mcastgrp_table[i].group,
					  addr,
					  sizeof(addr));

			fpdebug_printf("%-17s|   %s\n", addr, ifname);
		}
		fpdebug_printf(" %d entries\n", fp_shared->fp_mcastgrp_num);
		res = 0;
		goto end;
	}

	word = chargv[ind++];

	/* Enable multicast filtering */
	if (strcmp(word, "on") == 0) {
		fpdebug_printf("Multicast group filtering is on, was %s\n",
			       *opt ? "on":"off");
		*opt = FP_MCASTGRP_OPT_ENABLE;

		/* check if accept-all is given as second parameter */
		if (count == 2) {
			word = chargv[ind++];
			if (strcmp(word, "accept-ll") == 0) {
				*opt = FP_MCASTGRP_OPT_ACCEPT_LL;
				fpdebug_printf("configured to accept all link layer multicast traffic\n");
			} else {
				FPDEBUG_ERRX("wrong arguments: only accept-all parameter allowed along with on");
			}
		}
		res = 0;
	/* Disable multicast filtering */
	} else if (strcmp(word, "off") == 0) {
		fpdebug_printf("Multicast group filtering is off, was %s\n",
			       *opt ? "on":"off");
		*opt = 0;

		/* nothing more to do since it is set to off */
		if (count == 2) {
				FPDEBUG_ERRX("wrong arguments: no parameter allowed along with off");
		}

		res = 0;
	}
end:
	return res;
}

static int mcastgrp_add(char *tok)
{

	int res = -1, ind = 0, i;
	int count;
	char *word;
	uint32_t ifuid;
	uint32_t group;

	count = gettokens(tok);

	if (count != 2) {
		FPDEBUG_ERRX("wrong arguments: mcastgrp-add <mcast-addr|all> <source-interface|all>");
	}

	if (fp_shared->fp_mcastgrp_num+1 > FP_MCASTGRP_MAX)
		FPDEBUG_ERRX("Can't add more entries in whitelist table, there are already %d entries!", fp_shared->fp_mcastgrp_num);

	word = chargv[ind++];

	/* read group address or all */
	if (strcmp(word, "all") == 0) {
		group = 0;
	} else {
		res = fpdebug_inet_pton(AF_INET, word, &group);

		if (res <= 0)
			FPDEBUG_ERRX("wrong arguments: invalid group address %s", word);
	}

	word = chargv[ind++];

	/* read interface name or all */
	if (strcmp(word, "all") == 0) {
		ifuid = FP_MCASTGRP_IFUID_ALL;
	} else {
		fp_ifnet_t *ifp = fp_getifnetbyname(word);

		if (ifp == NULL)
			FPDEBUG_ERRX("wrong arguments: invalid interface name %s", word);

		ifuid = ifp->if_ifuid;
	}

	/* parse of all arguments succeeded, store in shared mem */

	/* at least check the couple doesn't already exist */
	for (i = 0; i < fp_shared->fp_mcastgrp_num; i++) {
		if ((fp_shared->fp_mcastgrp_table[i].group == group) &&
		    (fp_shared->fp_mcastgrp_table[i].ifuid == ifuid))
		break;
	}

	if (i == fp_shared->fp_mcastgrp_num) {
		fp_shared->fp_mcastgrp_table[i].group = group;
		fp_shared->fp_mcastgrp_table[i].ifuid = ifuid;
		fp_shared->fp_mcastgrp_num++;
		res = 0;
	} else
		FPDEBUG_ERRX("already in list!");
end:
	return res;
}

static int mcastgrp_del(char *tok)
{

	int res = -1, ind = 0, i;
	int count;
	char *word;
	uint32_t ifuid;
	uint32_t group;

	count = gettokens(tok);

	/* check validity of argument count */
	if (count != 2) {
		FPDEBUG_ERRX("wrong arguments: mcastgrp-del <mcast-addr|all> <source-interface|all>");
	}

	if (fp_shared->fp_mcastgrp_num == 0)
		FPDEBUG_ERRX("whitelist table is empty, can't delete any one!");

	word = chargv[ind++];

	/* read group address or all */
	if (strcmp(word, "all") == 0) {
		group = 0;
	} else {
		res = fpdebug_inet_pton(AF_INET, word, &group);

		if (res <= 0)
			FPDEBUG_ERRX("wrong arguments: invalid group address %s", word);
	}

	word = chargv[ind++];

	/* read interface name or all */
	if (strcmp(word, "all") == 0) {
		ifuid = FP_MCASTGRP_IFUID_ALL;
	} else {
		fp_ifnet_t *ifp;

		ifp = fp_getifnetbyname(word);
		if (ifp == NULL)
			FPDEBUG_ERRX("wrong arguments: invalid interface name %s", word);

		ifuid = ifp->if_ifuid;
	}

	/* parse of all arguments succeeded, look for the couple to delete
	   in table */
	for (i = 0; i < fp_shared->fp_mcastgrp_num; i++) {

		if ((fp_shared->fp_mcastgrp_table[i].group == group) &&
		    (fp_shared->fp_mcastgrp_table[i].ifuid == ifuid))
			break;
	}

	/* check that we didn't loop on entire table */
	if (i == fp_shared->fp_mcastgrp_num)
		FPDEBUG_ERRX("couple not found in whitelist table!");

	/* copy next items on actual one to delete the element and the hole
	   in table */
	memcpy(&fp_shared->fp_mcastgrp_table[i],
	       &fp_shared->fp_mcastgrp_table[i+1],
	       sizeof(fp_shared->fp_mcastgrp_table[i]) * (fp_shared->fp_mcastgrp_num - i - 1));	
	/* last but not least, decrease table size */
	fp_shared->fp_mcastgrp_num--;
end:
	return res;
}

#endif /* CONFIG_MCORE_MULTICAST4 */

#ifdef CONFIG_MCORE_MULTICAST6
static int dump_mfc6(char *tok)
{
	uint32_t i, index;
	fp_mfc6_entry_t *c;
	fp_ifnet_t *ifp;

	fpdebug_printf("MFC6 list:\n");
	for (i = 0; i < FP_MFC_MAX; i++) {
		c = &fp_shared->fp_mfc6_table[i];
		if (c->iif != FP_IIF_UNUSED) {
			fpdebug_printf("\t(");
			print_addr6(&c->origin);
			fpdebug_printf(" ,");
			print_addr6(&c->mcastgrp);
			ifp = __fp_ifuid2ifnet(c->iif);
			fpdebug_printf("), Incoming interface: %s (0x%08x)\n",
				       ifp->if_name, ntohl(c->iif));
			fpdebug_printf("\t\t Outgoing interfaces:\n");
			for (index = 0; index < FP_MAXVIFS && c->oifs[index]; index++) {
				ifp = __fp_ifuid2ifnet(c->oifs[index]);
				fpdebug_printf("\t\t\t %s (0x%08x)\n", ifp->if_name,
					       ntohl(c->oifs[index]));
			}
			fpdebug_printf("\t\t Pkts: %"PRIu64" Bytes: %"PRIu64"\n", c->pkt, c->bytes);
			fpdebug_printf("\t\t Offset: %"PRIu32" Next: %"PRIu16"\n", i, (uint16_t)c->next);
		}
	}
	return 0;
}

static int mcast6grp_filter(char *tok)
{

	int res = -1, ind = 0;
	int count;
	char *word;
	uint8_t *opt = &fp_shared->fp_mcast6grp_opt;

	count = gettokens(tok);

	/* check validity of argument count */
	if (count > 2) {
		FPDEBUG_ERRX("wrong arguments: mcast6grp-filter [on [accept-ll]|off]");
	}

	/* no parameter given, display the status of the filtering and groups in whitelist
	   if enabled */
	if (count == 0) {
		int i;
		char addr[INET_ADDRSTRLEN];
		char ifname[255];

		fpdebug_printf("Multicast IPv6 group filtering is %s\n",
				 *opt? "on":"off");
		fpdebug_printf("Accept all packets on link local: %s\n",
			       (*opt == FP_MCASTGRP_OPT_ACCEPT_LL)?"yes":"no");
		if (fp_shared->fp_mcast6grp_num)
			fpdebug_printf("\n%-25s| incoming interface\n\n",
				       "group");

		/* Display all entries in whitelist */
		for (i = 0; i < fp_shared->fp_mcast6grp_num; i++) {

			/* traduct ifuid to interface name */
			if (fp_shared->fp_mcast6grp_table[i].ifuid) {
				strcpy(ifname, fp_ifuid2str(fp_shared->fp_mcast6grp_table[i].ifuid));
				if (!strcmp(ifname,""))
					sprintf(ifname, "unknown ifuid %u",
						fp_shared->fp_mcast6grp_table[i].ifuid);
			} 
			else
				sprintf(ifname, "all");

			/* traduct address from network to ascii */
			fpdebug_inet_ntop(AF_INET6,
					  &fp_shared->fp_mcast6grp_table[i].group,
					  addr,
					  sizeof(addr));

			fpdebug_printf("%-25s|   %s\n", addr, ifname);
		}
		fpdebug_printf(" %d entries\n", fp_shared->fp_mcast6grp_num);
		res = 0;
		goto end;
	}

	word = chargv[ind++];

	/* Enable multicast filtering */
	if (strcmp(word, "on") == 0) {
		fpdebug_printf("Multicast group filtering is on, was %s\n",
			       fp_shared->fp_mcast6grp_opt ? "on":"off");
		*opt = FP_MCASTGRP_OPT_ENABLE;

		/* check if accept-all is given as second parameter */
		if (count == 2) {
			word = chargv[ind++];
			if (strcmp(word, "accept-ll") == 0) {
				*opt = FP_MCASTGRP_OPT_ACCEPT_LL;
				fpdebug_printf("configured to accept link layer multicast traffic\n");
			} else {
				FPDEBUG_ERRX("wrong arguments: only accept-ll parameter allowed along with on");
			}
		}
		res = 0;
	/* Disable multicast filtering */
	} else if (strcmp(word, "off") == 0) {
		fpdebug_printf("Multicast group filtering is off, was %s\n",
			       fp_shared->fp_mcast6grp_opt ? "on":"off");
		*opt = 0;

		/* nothing more to do since it is set to off */
		if (count == 2) {
				FPDEBUG_ERRX("wrong arguments: no parameter allowed along with off");
		}

		res = 0;
	}
end:
	return res;
}

static int mcast6grp_add(char *tok)
{

	int res = -1, ind = 0, i;
	int count;
	char *word;
	uint32_t ifuid;
	fp_in6_addr_t group;

	count = gettokens(tok);

	if (count != 2) {
		FPDEBUG_ERRX("wrong arguments: mcast6grp-add <mcast-addr|all> <source-interface|all>");
	}

	if (fp_shared->fp_mcast6grp_num+1 > FP_MCASTGRP_MAX)
		FPDEBUG_ERRX("Can't add more entries in whitelist table, there are already %d entries!", fp_shared->fp_mcast6grp_num);

	word = chargv[ind++];

	/* read group address or all */
	if (strcmp(word, "all") == 0) {
		res = fpdebug_inet_pton(AF_INET6, "::", &group);
	} else {
		res = fpdebug_inet_pton(AF_INET6, word, &group);
	}
	if (res <= 0)
		FPDEBUG_ERRX("wrong arguments: invalid group address %s", word);

	word = chargv[ind++];

	/* read interface name or all */
	if (strcmp(word, "all") == 0) {
		ifuid = FP_MCASTGRP_IFUID_ALL;
	} else {
		fp_ifnet_t *ifp = fp_getifnetbyname(word);

		if (ifp == NULL)
			FPDEBUG_ERRX("wrong arguments: invalid interface name %s", word);

		ifuid = ifp->if_ifuid;
	}

	/* parse of all arguments succeeded, store in shared mem */

	/* at least check the couple doesn't already exist */
	for (i = 0; i < fp_shared->fp_mcast6grp_num; i++) {

		if (is_in6_addr_equal(fp_shared->fp_mcast6grp_table[i].group, group) &&
		    (fp_shared->fp_mcast6grp_table[i].ifuid == ifuid))
			break;
	}

	if (i == fp_shared->fp_mcast6grp_num) {
		fp_shared->fp_mcast6grp_table[i].group = group;
		fp_shared->fp_mcast6grp_table[i].ifuid = ifuid;
		fp_shared->fp_mcast6grp_num++;
		res = 0;
	} else
		FPDEBUG_ERRX("already in list!");
end:
	return res;
}

static int mcast6grp_del(char *tok)
{

	int res = -1, ind = 0, i;
	int count;
	char *word;
	uint32_t ifuid;
	fp_in6_addr_t group;

	count = gettokens(tok);

	if (count != 2) {
		FPDEBUG_ERRX("wrong arguments: mcast6grp-del <mcast-addr|all> <source-interface|all>");
	}

	if (fp_shared->fp_mcast6grp_num == 0)
		FPDEBUG_ERRX("whitelist table is empty, can't delete any one!");

	word = chargv[ind++];

	/* read group address or all */
	if (strcmp(word, "all") == 0) {
		res = fpdebug_inet_pton(AF_INET6, "::", &group);
	} else {
		res = fpdebug_inet_pton(AF_INET6, word, &group);
	}
	if (res <= 0)
		FPDEBUG_ERRX("wrong arguments: invalid group address %s", word);

	word = chargv[ind++];

	/* read interface name or all */
	if (strcmp(word, "all") == 0) {
		ifuid = FP_MCASTGRP_IFUID_ALL;
	} else {
		fp_ifnet_t *ifp = fp_getifnetbyname(word);

		if (ifp == NULL)
			FPDEBUG_ERRX("wrong arguments: invalid interface name %s", word);

		ifuid = ifp->if_ifuid;
	}

	/* parse of all arguments succeeded, look for the couple to delete
	   in table */
	for (i = 0; i < fp_shared->fp_mcast6grp_num; i++) {

		if (is_in6_addr_equal(fp_shared->fp_mcast6grp_table[i].group, group) &&
		    (fp_shared->fp_mcast6grp_table[i].ifuid == ifuid))
			break;
	}

	/* check that we didn't loop on entire table */
	if (i == fp_shared->fp_mcast6grp_num)
		FPDEBUG_ERRX("couple not found in whitelist table!");

	/* copy next items on actual one to delete the element and the hole
	   in table */
	memcpy(&fp_shared->fp_mcast6grp_table[i],
	       &fp_shared->fp_mcast6grp_table[i+1],
	       sizeof(fp_shared->fp_mcast6grp_table[i]) * (fp_shared->fp_mcast6grp_num - i - 1));

	/* last but not least, decrease table size */
	fp_shared->fp_mcast6grp_num--;
end:
	return res;
}
#endif /* CONFIG_MCORE_MULTICAST6 */

#ifdef CONFIG_MCORE_VXLAN
static int vxlan_dump_fdb(char *tok)
{
	fp_vxlan_iface_t *vxiface;
	fp_ifnet_t *ifp;
	uint32_t idx, idx2;
	int i;

	if (gettokens(tok) != 1) {
		fpdebug_fprintf (stderr,
				 "wrong arguments: vxlan-dump-fdb <interface>\n");
		return 0;
	}

	if ((ifp = fp_getifnetbyname(chargv[0])) == NULL) {
		fpdebug_printf("bad interface name: %s\n", chargv[0]);
		return -1;
	}

	vxiface = &fp_shared->vxlan_iface[ifp->sub_table_index];
	fpdebug_printf("%s: vni=%"PRIu32" dstport=%"PRIu16, chargv[0],
		       vxiface->vni, ntohs(vxiface->dstport));
	if (vxiface->ttl)
		fpdebug_printf(" ttl=%"PRIu8, vxiface->ttl);
	if (vxiface->tos == 1)
		fpdebug_printf(" tos inherit");
	else if (vxiface->tos)
		fpdebug_printf(" tos=0x%"PRIx8, vxiface->tos);
	fpdebug_printf(" srcminport=%"PRIu16 " srcmaxport=%"PRIu16,
		       ntohs(vxiface->srcminport), ntohs(vxiface->srcmaxport));
	if (vxiface->flags & FP_VXLAN_IFACE_F_LEARN)
		fpdebug_printf(" learn");
	if (vxiface->family == AF_INET)
		fpdebug_printf("\nsaddr: " FP_NIPQUAD_FMT,
			       FP_NIPQUAD(vxiface->saddr.saddr4));
#ifdef CONFIG_MCORE_IPV6
	if (vxiface->family == AF_INET6)
		fpdebug_printf("\nsaddr: " FP_NIP6_FMT,
			       FP_NIP6(vxiface->saddr.saddr6));
#endif
	fpdebug_printf("\nFDB entries:\n");
	for (i = 0; i < FP_VXLAN_FDB_HASH_SIZE; i++)
		fp_hlist_for_each(idx, &vxiface->vxlan_fdb_hash[i],
				  fp_shared->vxlan_fdb, hlist) {
			fp_hlist_for_each(idx2,
					  &fp_shared->vxlan_fdb[idx].remotes,
					  fp_shared->vxlan_fdb_remote, hlist) {
				fpdebug_printf(FP_NMAC_FMT,
					       FP_NMAC(fp_shared->vxlan_fdb[idx].eth_addr));
				if (fp_shared->vxlan_fdb_remote[idx2].family == AF_INET)
					fpdebug_printf(" " FP_NIPQUAD_FMT,
						       FP_NIPQUAD(fp_shared->vxlan_fdb_remote[idx2].ip.ip4.ip_dst));
#ifdef CONFIG_MCORE_IPV6
				if (fp_shared->vxlan_fdb_remote[idx2].family == AF_INET6)
					fpdebug_printf(" " FP_NIP6_FMT,
						       FP_NIP6(fp_shared->vxlan_fdb_remote[idx2].ip.ip6.ip6_dst));
#endif
				fpdebug_printf(" vni: %"PRIu32,
					       fp_shared->vxlan_fdb_remote[idx2].vni);
				if (fp_shared->vxlan_fdb_remote[idx2].port)
					fpdebug_printf(" port: %" PRIu16,
						       ntohs(fp_shared->vxlan_fdb_remote[idx2].port));
				if (fp_shared->vxlan_fdb_remote[idx2].ifuid)
					fpdebug_printf(" %s (ifuid: %" PRIu32 ")",
						       fp_ifuid2str(fp_shared->vxlan_fdb_remote[idx2].ifuid),
						       ntohl(fp_shared->vxlan_fdb_remote[idx2].ifuid));
				fpdebug_printf("\n");
			}
		}

	return 0;
}

static int vxlan_dump(char *tok)
{
	uint32_t p, i;
	int ph, ih;

	for (ph = 0; ph < FP_VXLAN_PORT_HASH_SIZE; ph++)
		fp_hlist_for_each(p, &fp_shared->vxlan_port_hash[ph],
				  fp_shared->vxlan_port, hlist) {
			fpdebug_printf("dstport: %"PRIu16"\n",
				       ntohs(fp_shared->vxlan_port[p].dstport));
			for (ih = 0; ih < FP_VXLAN_IFACE_HASH_SIZE; ih++)
				fp_hlist_for_each(i, &fp_shared->vxlan_port[p].vxlan_iface_hash[ih],
						  fp_shared->vxlan_iface, hlist)
					fpdebug_printf("\t%s (ifuid: %" PRIu32
						       ") vni: %" PRIu32 "\n",
						       fp_ifuid2str(fp_shared->vxlan_iface[i].ifuid),
						       ntohl(fp_shared->vxlan_iface[i].ifuid),
						       fp_shared->vxlan_iface[i].vni);
		}
	return 0;
}

#ifndef __FastPath__
#define VXLAN_HEADER_OVERHEAD 50

#define VXLAN_IFACE_ADD_USAGE \
	"Add a vxlan interface: vxlan-iface-add IFNAME MAC_ADDR VNI " \
	"LINK_IFNAME PORT IPv4_GW_ADDR"
static int vxlan_iface_add(char *tok)
{
	uint8_t flags = 0, ttl = 255, tos = 0;
	uint32_t mtu;
	uint16_t minsrcport = htons(32768), maxsrcport = htons(61000);
	uint32_t ifuid, vni;
	fp_ifnet_t *linkifp;
	char ifname[16];
	uint8_t macaddr[6];
	uint16_t dstport;
	struct in_addr gw;
	int count, rc = -1, ind = 0;
	char *word, *end = NULL;

	count = gettokens(tok);
	if (count < 6)
		FPDEBUG_ERRX("vxlan-iface-add: too few arguments");

	/* IFNAME */
	strncpy(ifname, chargv[ind++], 16);
	ifuid = ifname2ifuid(ifname, default_vrfid);

	/* MAC_ADDR */
	word = chargv[ind++];
	if (string2mac(word, macaddr) == 0)
		FPDEBUG_ERRX("vxlan-fdb-add: invalid MAC address (%s)", word);

	/* VNI */
	word = chargv[ind++];
	vni = (uint32_t)strtoul(word, &end, 0);

	/* LINK_IFNAME */
	word = chargv[ind++];
	if ((linkifp = fp_getifnetbyname(word)) == NULL)
		FPDEBUG_ERRX("vxlan-iface-add: bad interface name: %s", word);

	mtu = linkifp->if_mtu - VXLAN_HEADER_OVERHEAD;

	/* PORT */
	word = chargv[ind++];
	dstport = htons((uint16_t)strtoul(word, &end, 0));

	/* IPv4_GW_ADDR */
	word = chargv[ind++];
	if (fpdebug_inet_pton(AF_INET, word, &gw) != 1)
		FPDEBUG_ERRX("vxlan-iface-add: invalid IPv4 gw address (%s)", word);

	rc = fp_interface_add(default_vrfid, ifname, macaddr, mtu,
			      ifuid, 0, FP_IFNET_VIRTUAL_PORT, FP_IFTYPE_VXLAN,
			      0);

	if (rc == FP_ADDIFNET_ERROR)
		FPDEBUG_ERRX("vxlan-iface-add: fail to add the ifnet");
	if (rc == FP_ADDIFNET_EXIST)
		FPDEBUG_ERRX("vxlan-iface-add: ifnet exists");

	rc = fp_addifnet_vxlaninfo(ifuid, vni, linkifp->if_ifuid, dstport,
				   minsrcport, maxsrcport, ttl, tos, AF_INET,
				   &gw, 0, NULL, flags);
	if (rc < 0)
		FPDEBUG_ERRX("vxlan-iface-add: fail to configure the ifnet");
end:
	return rc;
}

#define VXLAN_IFACE_DEL_USAGE \
	"Del a vxlan interface: vxlan-iface-del IFNAME"
static int vxlan_iface_del(char *tok)
{
	char *word;
	int count, ind = 0;
	fp_ifnet_t *ifp;

	count = gettokens(tok);
	if (count < 1)
		FPDEBUG_ERRX("vxlan-iface-del: too few arguments");

	/* IFNAME */
	word = chargv[ind++];
	if ((ifp = fp_getifnetbyname(word)) == NULL)
		FPDEBUG_ERRX("vxlan-iface-del: bad interface name: %s", word);

	fp_delifnet_vxlaninfo(ifp->if_ifuid);
	fp_interface_del(ifp->if_ifuid, 0, 0);
	return 0;

end:
	return -1;
}

static int vxlan_fdb_manage(char *tok, int add)
{
	int count, rc = -1, ind = 0;
	char *word;
	fp_vxlan_iface_t *vxiface;
	fp_ifnet_t *ifp;
	uint8_t macaddr[6];
	struct in_addr ipaddr;

	count = gettokens(tok);
	if (count < 3)
		FPDEBUG_ERRX("vxlan-fdb-%s: too few arguments",
			     add ? "add" : "del");

	/* IFNAME */
	word = chargv[ind++];
	if ((ifp = fp_getifnetbyname(word)) == NULL)
		FPDEBUG_ERRX("vxlan-fdb-%s: bad interface name: %s",
			     add ? "add" : "del", word);

	/* MAC_ADDR */
	word = chargv[ind++];
	if (string2mac(word, macaddr) == 0)
		FPDEBUG_ERRX("vxlan-fdb-%s: invalid MAC address (%s)",
			     add ? "add" : "del", word);

	/* IPv4_ADDR */
	word = chargv[ind++];
	if (fpdebug_inet_pton(AF_INET, word, &ipaddr) != 1)
		FPDEBUG_ERRX("vxlan-fdb-%s: invalid IPv4 address (%s)",
			     add ? "add" : "del", word);

	if (ifp->sub_table_index == 0)
		FPDEBUG_ERRX("vxlan-fdb-%s: ifnet sub_table_index is not defined",
			     add ? "add" : "del");

	vxiface = &fp_shared->vxlan_iface[ifp->sub_table_index];
	if (add) {
		rc = fp_vxlan_fdb_remote_add(vxiface, macaddr, vxiface->vni,
					     vxiface->dstport, 0, AF_INET, &ipaddr);
		if (rc < 0)
			FPDEBUG_ERRX("vxlan-fdb-add: fail to add the entry");
	} else {
		rc = fp_vxlan_fdb_remote_del(vxiface, macaddr, vxiface->vni,
					     vxiface->dstport, 0, AF_INET, &ipaddr);
		if (rc < 0)
			FPDEBUG_ERRX("vxlan-fdb-del: fail to del the entry");
	}

end:
	return rc;
}

#define VXLAN_FDB_ADD_USAGE \
	"Add a vxlan fdb entry: vxlan-fdb-add IFNAME MAC_ADDR IPv4_ADDR"
static int vxlan_fdb_add(char *tok)
{
	return vxlan_fdb_manage(tok, 1);
}

#define VXLAN_FDB_DEL_USAGE \
	"Del a vxlan fdb entry: vxlan-fdb-del IFNAME MAC_ADDR IPv4_ADDR"
static int vxlan_fdb_del(char *tok)
{
	return vxlan_fdb_manage(tok, 0);
}
#endif /* !__FastPath__ */
#endif /* CONFIG_MCORE_VXLAN */

static int memtest(char *tok)
{
	int argc = gettokens(tok);
	volatile uint8_t *cp;
	size_t count, i;
	uint8_t c;

	if (argc != 1 && argc != 0) {
		fpdebug_fprintf (stderr, "wrong argument: memtest [count]\n");
		return 0;
	}
	if (argc)
		count = atoi(chargv[0]);
	else
		count = sizeof(*fp_shared);

	cp = (volatile uint8_t *)fp_shared;
	fpdebug_printf("Testing r/w memory %p-%p (size 0x%lx)...", cp, cp+count-1,
			(unsigned long)count);

	for (i = 0 ; i < count ; i++) {
		c = *cp;
		*cp = c;
		cp++;
	}
	fpdebug_printf("ok\n");

	return 0;
}

static int logmode(char *tok)
{
	char *type_str = NULL;
	uint8_t count = gettokens(tok);

	if (count != 0 && count != 1) {
		fpdebug_printf("wrong arguments: logmode [console|syslog]\n");
		return -1;
	}

	if (count == 1) {
		int mode;

		type_str = chargv[0];
		if (strcmp(type_str, "console") == 0)
			mode = FP_LOG_MODE_CONSOLE;
		else if (strcmp(type_str, "syslog") == 0)
			mode = FP_LOG_MODE_SYSLOG;
		else {
			fpdebug_printf("wrong arguments: logmode [console|syslog]\n");
			return -1;
		}
		fp_shared->debug.mode = mode;
	}

	fpdebug_printf("Log mode is %s\n", fp_shared->debug.mode == FP_LOG_MODE_CONSOLE ?
			"console" : "syslog");
	return 0;
}

static int loglevel(char *tok)
{
	uint8_t count = gettokens(tok);
	int level;

	if (count != 0 && count != 1) {
		fpdebug_printf("wrong arguments: loglevel [value]\n");
		return 0;
	}

	if (count == 1) {
		level = atoi(chargv[0]);
		if (level < 0 || level > 7) {
			fpdebug_printf("wrong arguments: 0 <= loglevel <= 7\n");
			return 0;
		}
		fp_shared->debug.level = level;
	}

	fpdebug_printf("Log level is %"PRIu8"\n",
		       (uint8_t)fp_shared->debug.level);
#ifndef CONFIG_MCORE_DEBUG
	fpdebug_printf("CONFIG_MCORE_DEBUG is disabled, hence only messages with "
			"log level <= FP_LOG_DEFAULT (%"PRIu8") will be displayed.\n",
			FP_LOG_DEFAULT);
#endif
	return 0;
}

static int logtype(char *tok)
{
	uint8_t count = gettokens(tok);
	char *type_str = NULL;
	char *on_str = NULL;
	int on = 0;
	int all = 0;
	int i;

	if (count != 0 && count != 2)
		goto fail;

	if (count == 2) {
		type_str = chargv[0];
		if (strcmp(type_str, "all") == 0)
			all = 1;
		on_str = chargv[1];
		if (strcmp(on_str, "on") == 0)
			on = 1;
		else if (strcmp(on_str, "off") == 0)
			on = 0;
		else
			goto fail;
	}

	for (i = 0; i < FP_MAX_LOGTYPES; i++) {
		if (!fp_shared->logname[i][0])
			continue;

		if (count == 2) {
			if (all || strcmp(type_str, fp_shared->logname[i]) == 0) {
				if (on)
					fp_shared->debug.type = fp_shared->debug.type | (UINT64_C(1) << i);
				else
					fp_shared->debug.type = fp_shared->debug.type & (~(UINT64_C(1) << i));
				fpdebug_printf( "log %s is %s\n", fp_shared->logname[i],
				                (fp_shared->debug.type & (UINT64_C(1) << i)) ?
				                "on" : "off");
				if (!all)
					return 0;
			}
		}
		else
			fpdebug_printf( "log %s is %s\n", fp_shared->logname[i],
			                (fp_shared->debug.type & (UINT64_C(1) << i)) ?
			                "on" : "off");
	}

	if (count == 2 && !all)
		fpdebug_printf("cannot find logtype <%s>\n", type_str);

	return 0;
fail:
	fpdebug_printf("wrong arguments: logtype [<type|all> <on|off>]\n");
	return 0;
}

#ifdef CONFIG_MCORE_IP_REASS
static int reass4_maxqlen(char *tok)
{
	if (gettokens(tok) == 0)
		fpdebug_printf("IPv4 reass. max queue length: %"PRIu32"\n", fp_shared->fp_reass4_maxq_len);
	else {
		uint32_t val = atoi(chargv[0]);

		fp_shared->fp_reass4_maxq_len = val;
	}
	return 0;
}
#endif

#ifdef CONFIG_MCORE_IPV6_REASS
static int reass6_maxqlen(char *tok)
{
	if (gettokens(tok) == 0)
		fpdebug_printf("IPv6 reass. max queue length: %"PRIu32"\n", fp_shared->fp_reass6_maxq_len);
	else {
		uint32_t val = atoi(chargv[0]);

		fp_shared->fp_reass6_maxq_len = val;
	}
	return 0;
}
#endif

#ifdef CONFIG_MCORE_HITFLAGS_SYNC
static void fp_dump_arp_hitflags(void)
{
	fpdebug_printf("arp hitflags\n");
	fpdebug_printf("  period_in_seconds:%"PRIu8"\n", fp_shared->fp_hf_arp.hfp_period);
	fpdebug_printf("  max_scanned:%"PRIu32"\n", fp_shared->fp_hf_arp.hfp_max_scanned);
	fpdebug_printf("  max_sent:%"PRIu32"\n", fp_shared->fp_hf_arp.hfp_max_sent);
}

static void fp_dump_ndp_hitflags(void)
{
#ifdef CONFIG_MCORE_IPV6
	fpdebug_printf("ndp hitflags\n");
	fpdebug_printf("  period_in_seconds:%"PRIu8"\n", fp_shared->fp_hf_ndp.hfp_period);
	fpdebug_printf("  max_scanned:%"PRIu32"\n", fp_shared->fp_hf_ndp.hfp_max_scanned);
	fpdebug_printf("  max_sent:%"PRIu32"\n", fp_shared->fp_hf_ndp.hfp_max_sent);
#endif
}

static void fp_dump_ct_hitflags(void)
{
#ifdef CONFIG_MCORE_NF_CT
	fpdebug_printf("conntrack hitflags\n");
	fpdebug_printf("  period_in_seconds:%"PRIu8"\n", fp_shared->fp_hf_ct.hfp_period);
	fpdebug_printf("  max_scanned:%"PRIu32"\n", fp_shared->fp_hf_ct.hfp_max_scanned);
	fpdebug_printf("  max_sent:%"PRIu32"\n", fp_shared->fp_hf_ct.hfp_max_sent);
#endif
}

static void fp_dump_ct6_hitflags(void)
{
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	fpdebug_printf("conntrack6 hitflags\n");
	fpdebug_printf("  period_in_seconds:%"PRIu8"\n", fp_shared->fp_hf_ct6.hfp_period);
	fpdebug_printf("  max_scanned:%"PRIu32"\n", fp_shared->fp_hf_ct6.hfp_max_scanned);
	fpdebug_printf("  max_sent:%"PRIu32"\n", fp_shared->fp_hf_ct6.hfp_max_sent);
#endif
}

static int dump_hitflags(char *tok)
{
	char *type;
	if (gettokens(tok) == 0) {
		fp_dump_arp_hitflags();
		fp_dump_ndp_hitflags();
		fp_dump_ct_hitflags();
		fp_dump_ct6_hitflags();
		return 0;
	}

	if (gettokens(tok) != 1) {
		fpdebug_printf("wrong arguments: dump-hitflags [all | <arp | ndp | conntrack | conntrack6>]\n");
		return 0;
	}

	type = chargv[0];
	if (strcmp(type, "arp") == 0) {
		fp_dump_arp_hitflags();
	} else if (strcmp(type, "ndp") == 0) {
		fp_dump_ndp_hitflags();
	} else if (strcmp(type, "conntrack") == 0) {
		fp_dump_ct_hitflags();
	} else if (strcmp(type, "conntrack6") == 0) {
		fp_dump_ct6_hitflags();
	} else if (strcmp(type, "all") == 0) {
		fp_dump_arp_hitflags();
		fp_dump_ndp_hitflags();
		fp_dump_ct_hitflags();
		fp_dump_ct6_hitflags();
	} else {
		fpdebug_printf("wrong arguments: dump-hitflags [all | <arp | ndp | conntrack | conntrack6>]\n");
	}

	return 0;
}

static int hitflags_sanity_check(int period, int scanned, int sent)
{
	if ((period <= 0) || (scanned <=0)
			|| (sent <=0))
		return 1;
	return 0;
}

static void fp_set_arp_hf(uint8_t period, uint32_t max_scanned, uint32_t max_sent)
{
	fp_shared->fp_hf_arp.hfp_period = period;
	fp_shared->fp_hf_arp.hfp_max_scanned = max_scanned;
	fp_shared->fp_hf_arp.hfp_max_sent = max_sent;
}

static int set_arp_hitflags(char *tok)
{
	uint8_t period;
	uint32_t max_scanned, max_sent;

	if (gettokens(tok) != 3) {
		fpdebug_printf("wrong arguments: set-arp-hitflags <period_in_seconds> <max_scanned> <max_sent>\n");
		return 0;
	}

	period = atoi(chargv[0]);
	max_scanned = atoi(chargv[1]);
	max_sent = atoi(chargv[2]);

	if (hitflags_sanity_check(period, max_scanned, max_sent)) {
		fpdebug_printf("wrong arguments: set-arp-hitflags <period_in_seconds> <max_scanned> <max_sent>\n");
		return 0;
	}

	fp_set_arp_hf(period,  max_scanned, max_sent);
	return 0;
}

#ifdef CONFIG_MCORE_IPV6
static void fp_set_ndp_hf(uint8_t period, uint32_t max_scanned, uint32_t max_sent)
{
	fp_shared->fp_hf_ndp.hfp_period = period;
	fp_shared->fp_hf_ndp.hfp_max_scanned = max_scanned;
	fp_shared->fp_hf_ndp.hfp_max_sent = max_sent;
}

static int set_ndp_hitflags(char *tok)
{
	uint8_t period;
	uint32_t max_scanned, max_sent;

	if (gettokens(tok) != 3) {
		fpdebug_printf("wrong arguments: set-ndp-hitflags <period_in_seconds> <max_scanned> <max_sent>\n");
		return 0;
	}

	period = atoi(chargv[0]);
	max_scanned = atoi(chargv[1]);
	max_sent = atoi(chargv[2]);

	if (hitflags_sanity_check(period, max_scanned, max_sent)) {
		fpdebug_printf("wrong arguments: set-ndp-hitflags <period_in_seconds> <max_scanned> <max_sent>\n");
		return 0;
	}

	fp_set_ndp_hf(period,  max_scanned, max_sent);
	return 0;
}
#endif

#ifdef CONFIG_MCORE_NF_CT
static void fp_set_ct_hf(uint8_t period, uint32_t max_scanned, uint32_t max_sent)
{
	fp_shared->fp_hf_ct.hfp_period = period;
	fp_shared->fp_hf_ct.hfp_max_scanned = max_scanned;
	fp_shared->fp_hf_ct.hfp_max_sent = max_sent;
}

static int set_ct_hitflags(char *tok)
{
	uint8_t period;
	uint32_t max_scanned, max_sent;

	if (gettokens(tok) != 3) {
		fpdebug_printf("wrong arguments: set-conntrack-hitflags <period_in_seconds> <max_scanned> <max_sent>\n");
		return 0;
	}

	period = atoi(chargv[0]);
	max_scanned = atoi(chargv[1]);
	max_sent = atoi(chargv[2]);

	if (hitflags_sanity_check(period, max_scanned, max_sent)) {
		fpdebug_printf("wrong arguments: set-conntrack-hitflags <period_in_seconds> <max_scanned> <max_sent>\n");
		return 0;
	}

	fp_set_ct_hf(period,  max_scanned, max_sent);
	return 0;
}
#endif

#ifdef CONFIG_MCORE_NF6_CT
static void fp_set_ct6_hf(uint8_t period, uint32_t max_scanned, uint32_t max_sent)
{
	fp_shared->fp_hf_ct6.hfp_period = period;
	fp_shared->fp_hf_ct6.hfp_max_scanned = max_scanned;
	fp_shared->fp_hf_ct6.hfp_max_sent = max_sent;
}

static int set_ct6_hitflags(char *tok)
{
	uint8_t period;
	uint32_t max_scanned, max_sent;

	if (gettokens(tok) != 3) {
		fpdebug_printf("wrong arguments: set-conntrack6-hitflags <period_in_seconds> <max_scanned> <max_sent>\n");
		return 0;
	}

	period = atoi(chargv[0]);
	max_scanned = atoi(chargv[1]);
	max_sent = atoi(chargv[2]);

	if (hitflags_sanity_check(period, max_scanned, max_sent)) {
		fpdebug_printf("wrong arguments: set-conntrack6-hitflags <period_in_seconds> <max_scanned> <max_sent>\n");
		return 0;
	}

	fp_set_ct6_hf(period,  max_scanned, max_sent);
	return 0;
}
#endif
#endif /* CONFIG_MCORE_HITFLAGS_SYNC */

#ifdef CONFIG_MCORE_MULTIBLADE
static int neigh_bladeid(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	uint8_t id = 0;

	if (arg_count > 1) {
		fpdebug_printf("wrong arguments: neigh-bladeid [blade ID]\n");
		return -1;
	}

	if (arg_count == 1) {
		id = atoi(chargv[0]);
		if (id == 0) {
			fpdebug_fprintf(stderr, "Incorrect value (%s)\n", chargv[0]);
			return -1;
		}
		fp_shared->fp_neigh_bladeid = id;
	}

	fpdebug_printf("neigh-bladeid is %"PRIu8"\n", fp_shared->fp_neigh_bladeid);
	return 0;
}
#endif /* CONFIG_MCORE_MULTIBLADE */

static int cp_if_fptun_size_thresh(char *tok)
{
	if (gettokens(tok) == 0)
		fpdebug_printf("FP/CP FPTUN message size warning threshold: %"PRIu32"\n",
		       fp_shared->cp_if_fptun_size_thresh);
	else {
		uint32_t val = strtoul(chargv[0], NULL, 0);

		fp_shared->cp_if_fptun_size_thresh = val;
	}
	return 0;
}

static int fpib_fptun_size_thresh(char *tok)
{
	if (gettokens(tok) == 0)
		fpdebug_printf("FPIB FPTUN message size warning threshold: %"PRIu32"\n",
		       fp_shared->fpib_fptun_size_thresh);
	else {
		uint32_t val = strtoul(chargv[0], NULL, 0);

		fp_shared->fpib_fptun_size_thresh = val;
	}
	return 0;
}

/* Remote Fast Path Statistics configuration */
static void rfps_usage(int raw)
{
	if (raw)
		fpdebug_printf("Usage: rfps-raw-conf RFPS_MODULE "
		       "[<transmit_period_in_milliseconds> <max_msg_per_tick>"
		       " <min_refresh_period_in_milliseconds>]\n");
	else
		fpdebug_printf("Usage: rfps-conf RFPS_MODULE "
		       "[<max_throughput_in_[k/K, m/M]bits_per_second>"
		       " <min_refresh_period_in_milliseconds>]\n");

	fpdebug_printf("RFPS_MODULE are:\n");
	fpdebug_printf("\tIP, IF\n");
#ifdef CONFIG_MCORE_IPSEC
	fpdebug_printf("\tSA, SP_IN, SP_OUT\n");
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fpdebug_printf("\tSA6, SP6_IN, SP6_OUT\n");
#endif
}

typedef void (*fp_set_rfps)(uint32_t tx_period,
			    uint32_t max_msg_per_tick,
			    uint32_t min_refresh_period);

typedef struct {
	const char  *cmd_name;
	const char  *full_name;
	size_t      cfg_off_in_shmem;
	fp_set_rfps fp_set;
} fp_rfps_cmd_t;

#define FP_SHMEM_OFF(member) \
	((size_t) &((shared_mem_t *)0)->member)

static fp_rfps_cmd_t fp_rfps_map[] = {
	{"", "invalid name", 0, (fp_set_rfps) 0},
	{"IP", "IPv4/IPv6", FP_SHMEM_OFF(fp_rfps.fp_rfps_ip), fp_set_rfps_ip},
	{"IF", "Network Interfaces", FP_SHMEM_OFF(fp_rfps.fp_rfps_if), fp_set_rfps_if},
#ifdef CONFIG_MCORE_IPSEC
	{"SA", "IPsec SA", FP_SHMEM_OFF(fp_rfps.fp_rfps_ipsec_sa), fp_set_rfps_ipsec_sa},
	{"SP_IN", "IPsec SP In", FP_SHMEM_OFF(fp_rfps.fp_rfps_ipsec_sp_in), fp_set_rfps_ipsec_sp_in},
	{"SP_OUT", "IPsec SP Out", FP_SHMEM_OFF(fp_rfps.fp_rfps_ipsec_sp_out), fp_set_rfps_ipsec_sp_out},
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
	{"SA6", "IPsec IPv6 SA", FP_SHMEM_OFF(fp_rfps.fp_rfps_ipsec6_sa), fp_set_rfps_ipsec6_sa},
	{"SP6_IN", "IPsec IPv6 SP In", FP_SHMEM_OFF(fp_rfps.fp_rfps_ipsec6_sp_in), fp_set_rfps_ipsec6_sp_in},
	{"SP6_OUT", "IPsec IPv6 SP Out", FP_SHMEM_OFF(fp_rfps.fp_rfps_ipsec6_sp_out), fp_set_rfps_ipsec6_sp_out},
#endif
};

#define	is_invalid_rfps(rfps) \
	(rfps == fp_rfps_map)

static fp_rfps_cmd_t* fp_rfps_name_parse(char* stat_name, int raw)
{
	fp_rfps_cmd_t *rfps;

	fp_rfps_map[0].cmd_name = stat_name; /* sentinel algorithm */
	for (rfps = &fp_rfps_map[(sizeof(fp_rfps_map) / sizeof(fp_rfps_cmd_t)) - 1];
	     strcmp(stat_name, rfps->cmd_name) != 0; rfps--);
	fp_rfps_map[0].cmd_name = "";
	if (is_invalid_rfps(rfps)) {
		fpdebug_printf("Invalid stat name: %s\n", stat_name);
		rfps_usage(raw);
	}
	return rfps;
}

static void print_period(uint32_t value, const char* name)
{
	fpdebug_printf("%s=%"PRIu32" milliseconds", name, value);
}

static void dump_rfps_raw_conf(fp_rfps_cmd_t *rfps)
{
	rfps_conf_t* rfps_cf;

	rfps_cf = (rfps_conf_t*) ((char*) fp_shared + rfps->cfg_off_in_shmem);
	fpdebug_printf("%s:", rfps->full_name);
	print_period(rfps_cf->tx_period, "tx_period");
	fpdebug_printf(" max_msg_per_tick=%"PRIu32" ", rfps_cf->max_msg_per_tick);
	print_period(rfps_cf->min_refresh_period, "min_refresh_period");
	fpdebug_printf("\n");
}

static void dump_rfps_conf(fp_rfps_cmd_t *rfps)
{
	rfps_conf_t *rfps_cf;
	const char  *unit;
	uint32_t    max_msg_per_tick;
	uint32_t    max_bits_per_tick;
	uint32_t    tx_period;
	uint32_t    max_throughput;

	rfps_cf = (rfps_conf_t*) ((char*) fp_shared + rfps->cfg_off_in_shmem);
	tx_period = rfps_cf->tx_period;
	max_msg_per_tick = rfps_cf->max_msg_per_tick;
	max_bits_per_tick = (fp_shared->cp_if_mtu * 8) * max_msg_per_tick;
	if (tx_period < 1000) {
		max_throughput = max_bits_per_tick * (1000 / tx_period);
	} else {
		max_throughput = max_bits_per_tick * (tx_period / 1000);
	}
	unit = "";
	if ((max_throughput % 1000) == 0) {
		max_throughput /= 1000;
		unit = "K";
	}
	if ((max_throughput % 1000) == 0) {
		max_throughput /= 1000;
		unit = "M";
	}
	fpdebug_printf("%s", rfps->full_name);
	fpdebug_printf("  max_throughput=%"PRIu32"%s bits/second ",
	       max_throughput, unit);
	print_period(rfps_cf->min_refresh_period, "min_refresh_period");
	fpdebug_printf("\n");
}

#define MAX_MEGA32 (0xFFFFFFFF / 1000000)
#define MAX_KILO32 (0xFFFFFFFF / 1000)

static int rfps_conf(char *tok)
{
	int            nb_args;
	fp_rfps_cmd_t* rfps;
	uint32_t       max_throughput;
	uint32_t       tx_period;
	uint32_t       mtu_bits;
	uint32_t       max_msg_per_sec;
	uint32_t       max_msg_per_tick;
	uint32_t       min_refresh_period;
	uint32_t       max_unit_value;
	int            unit;
	int            unit_idx;
	char           unit_char;
	char           last_char;

	nb_args = gettokens(tok);
	if ((nb_args != 1) && (nb_args != 3)) {
		fpdebug_printf("Wrong number of args.\n");
		rfps_usage(0);
		return 0;
	}
	rfps = fp_rfps_name_parse(chargv[0], 0);
	if (is_invalid_rfps(rfps)) {
		return 0;
	}
	if (nb_args == 1) {
		dump_rfps_conf(rfps);
		return 0;
	}
	/* Get throughput */
	unit_idx = strlen(chargv[1]) - 1;
	unit_char = chargv[1][unit_idx];
	switch (unit_char) {
	case 'k':
	case 'K':
		unit = 1024;
		last_char = '\0';
		max_unit_value = (0xFFFFFFFF / 1024);
		break;

	case 'm':
	case 'M':
		unit = 1024 * 1024;
		last_char = '\0';
		max_unit_value = (0xFFFFFFFF / (1024 * 1024));
		break;

	default:
		unit = 1;
		last_char = unit_char;
		max_unit_value = 0xFFFFFFFE;
		break;
	}
	chargv[1][unit_idx] = last_char;
	max_throughput = atoi(chargv[1]);
	chargv[1][unit_idx] = unit_char; /* restore last character */
	if ((int)max_throughput <= 0) {
		fpdebug_printf("invalid throughput value: %s\n", chargv[1]);
		return 0;
	}
	if (max_throughput > max_unit_value) {
		fpdebug_printf("throughput value %s > max %d%c\n",
		       chargv[1], max_unit_value, unit_char);
		return 0;
	}
	min_refresh_period = atoi(chargv[2]);
	if ((int)min_refresh_period < 0) {
		fpdebug_printf("invalid min refresh value: %s\n", chargv[2]);
		return 0;
	}
	max_throughput *= unit;
	tx_period = min_refresh_period;
	/*
	 * Compute TX period and max_msg_per_tick from the cp_if_mtu and the
	 * min_refresh period.
	 */
	mtu_bits = fp_shared->cp_if_mtu * 8;
	if (max_throughput < mtu_bits) {
		max_msg_per_tick = 1;
	} else {
		max_msg_per_sec = max_throughput / mtu_bits;
		max_msg_per_tick = (max_msg_per_sec * tx_period) / 1000;
		if (max_msg_per_tick == 0) {
			max_msg_per_tick = 1;
			tx_period = 1000 * (max_throughput / mtu_bits);
		}
	}
	(*rfps->fp_set)(tx_period, max_msg_per_tick, min_refresh_period);
	return 0;
}

static int rfps_raw_conf(char *tok)
{
	int            nb_args;
	fp_rfps_cmd_t* rfps;
	uint32_t       tx_period;
	uint32_t       max_msg_per_tick;
	uint32_t       min_refresh_period;

	nb_args = gettokens(tok);
	if ((nb_args != 1) && (nb_args != 4)) {
		fpdebug_printf("Wrong number of args.\n");
		rfps_usage(1);
		return 0;
	}
	rfps = fp_rfps_name_parse(chargv[0], 1);
	if (is_invalid_rfps(rfps)) {
		return 0;
	}
	if (nb_args == 1) {
		dump_rfps_raw_conf(rfps);
		return 0;
	}
	tx_period = atoi(chargv[1]);
	if ((int)tx_period <= 0) {
		fpdebug_printf("invalid tx_period: %s\n", chargv[1]);
		return 0;
	}
	max_msg_per_tick = atoi(chargv[2]);
	if ((int)max_msg_per_tick < 0) {
		fpdebug_printf("invalid max_msg_per_tick: %s\n", chargv[2]);
		return 0;
	}
	min_refresh_period = atoi(chargv[3]);
	if ((int)min_refresh_period <= 0) {
		fpdebug_printf("invalid min_refresh: %s\n", chargv[3]);
		return 0;
	}
	(*rfps->fp_set)(tx_period, max_msg_per_tick, min_refresh_period);
	return 0;
}

#ifdef CONFIG_MCORE_DEBUG_PROBE
#ifdef __FastPath__
static int
fpdebug_probe(char *tok)
{
	if (gettokens(tok) > 1) {
		fpdebug_fprintf(stderr, "wrong arguments\n");
		return -1;
	}
	if (gettokens(tok) == 1 && strcmp(chargv[0], "reset") == 0)
		fp_probe_reset();
	else if (gettokens(tok) == 1 && strcmp(chargv[0], "start") == 0)
		fp_probe_start();
	else if (gettokens(tok) == 1 && strcmp(chargv[0], "stop") == 0)
		fp_probe_stop();
	else if (gettokens(tok) == 1 && strcmp(chargv[0], "percore") == 0)
		fp_probe_dump(1);
	else
		fp_probe_dump(0);
	return 0;
}
#else
#define fpdebug_probe fpdebug_send_to_fp
#endif
#endif

#if defined(__FastPath__)
static int
fpdebug_show_lockstate(char *tok __fpn_maybe_unused)
{
#if defined(CONFIG_MCORE_FPN_LOCK_DEBUG)
	unsigned long addr_arg;

	if (gettokens(tok) != 1) {
		fpdebug_fprintf(stderr, "wrong number of arguments\n");
		return -1;
	}
	addr_arg = strtoul(chargv[0], NULL, 0);
	if (addr_arg == 0) {
		fpdebug_fprintf(stderr, "invalid lock address %s\n", chargv[0]);
		return -1;
	}
	fpn_debug_lock_display((void *)addr_arg);
	return 0;
#else
	fpdebug_printf("CONFIG_MCORE_FPN_LOCK_DEBUG is not enabled\n");
	return -1;
#endif
}
#else
#define fpdebug_show_lockstate fpdebug_send_to_fp
#endif

#if defined(__FastPath__)
static int
fpdebug_show_locklog(char *tok __fpn_maybe_unused)
{
#if defined(CONFIG_MCORE_FPN_LOCK_DEBUG)
	int nb_args;
	int core_id;
	int max_rcds;

	nb_args = gettokens(tok);
	max_rcds = CONFIG_MCORE_FPN_LOCK_DEBUG_MAX_RECORDS; /* default is max. */
	if (nb_args == 0) { /* Display maximum lock records of all cores */
		for (core_id = 0; core_id < FPN_MAX_CORES; core_id++)
			fpn_debug_lock_log_display(core_id, max_rcds);
		return 0;
	}
	core_id = atoi(chargv[0]);
	if (core_id < 0 || core_id >= FPN_MAX_CORES) {
		fpdebug_fprintf(stderr, "core-id=%s invalid (0 <= core-id < %d)\n",
			chargv[0], FPN_MAX_CORES);
		return -1;
	}
	if (nb_args == 2) {
		max_rcds = atoi(chargv[1]);
		if (max_rcds < 0 ||
		    max_rcds >= CONFIG_MCORE_FPN_LOCK_DEBUG_MAX_RECORDS) {
			fpdebug_fprintf(stderr, "max-records=%s invalid (0 <= "
				"max-records < %d)\n",
				chargv[1], CONFIG_MCORE_FPN_LOCK_DEBUG_MAX_RECORDS);
			return -1;
		}
	}
	fpn_debug_lock_log_display(core_id, max_rcds);
	return 0;
#else
	fpdebug_printf("CONFIG_MCORE_FPN_LOCK_DEBUG is not enabled\n");
	return -1;
#endif
}
#else
#define fpdebug_show_locklog fpdebug_send_to_fp
#endif

#ifdef CONFIG_MCORE_CPONLY_PORTMASK
static int fpdebug_cponly_portmask(char *tok)
{
	uint8_t arg_count = gettokens(tok);
	uint64_t mask = 0;

	if (arg_count > 1) {
		fpdebug_printf("wrong arguments: cponly-portmask [mask]\n");
		return -1;
	}

	if (arg_count == 1) {
		mask = strtoull(chargv[0], NULL, 0);
		fp_shared->cponly_portmask = mask;
	}

	fpdebug_printf("cponly-portmask is 0x%"PRIx64"\n", fp_shared->cponly_portmask);
	return 0;
}
#endif

#ifdef __FastPath__
static int fpdebug_dump_mempool(char *tok)
{
	struct fpn_mempool *mp;
	int numtokens = gettokens(tok);

	if (numtokens == 0) {
		fpdebug_printf("Please specify mempool name among:\n");
		fpn_mempool_list();
		return 0;
	}
	else if (numtokens != 1) {
		fpdebug_fprintf(stderr, "wrong arguments\n");
		return -1;
	}

	mp = fpn_mempool_lookup(chargv[0]);
	if (mp == NULL) {
		fpdebug_fprintf(stderr, "no such mempool\n");
		return -1;
	}
	fpn_mempool_dump(mp);
	return 0;
}
#else
#define fpdebug_dump_mempool fpdebug_send_to_fp
#endif

#ifdef __FastPath__
static int fpdebug_dump_timer_stats(char *tok __fpn_maybe_unused)
{
#ifdef CONFIG_MCORE_TIMER_GENERIC
	fpn_timer_dump_stats();
#endif
	return 0;
}
#else
#define fpdebug_dump_timer_stats fpdebug_send_to_fp
#endif

#ifdef CONFIG_MCORE_TCP_MSS
static int set_tcpmss4(char *tok)
{
	fp_ifnet_t *ifp;
	char *   ifce;
	uint32_t tcp4mss;
	int numtokens = gettokens(tok);

	if (numtokens != 2 ) {
		fpdebug_fprintf(stderr, "wrong arguments\n");
		return -1;
	}

	ifce = chargv[0];
	tcp4mss = atoi(chargv[1]);

	if ((ifp = fp_getifnetbyname(ifce)) == NULL) {
		fpdebug_printf("bad interface name: %s\n", ifce);
		return -1;
	}

	if (fp_setifnet_tcpmss4(ifp->if_ifuid,
				tcp4mss) != 0 ) {
		fpdebug_fprintf(stderr, "wrong interface %s\n",ifce);
		return -1;
	}
	return 0;
}
#endif

#if defined(CONFIG_MCORE_TCP_MSS) && defined(CONFIG_MCORE_IPV6)
static int set_tcpmss6(char *tok)
{
	fp_ifnet_t *ifp;
	char *   ifce;
	uint32_t tcp6mss;
	int numtokens = gettokens(tok);

	if (numtokens != 2 ) {
		fpdebug_fprintf(stderr, "wrong arguments\n");
		return -1;
	}

	ifce = chargv[0];
	tcp6mss = atoi(chargv[1]);

	if ((ifp = fp_getifnetbyname(ifce)) == NULL) {
		fpdebug_printf("bad interface name: %s\n", ifce);
		return -1;
	}

	if (fp_setifnet_tcpmss6(ifp->if_ifuid,
				tcp6mss) != 0 ) {
		fpdebug_fprintf(stderr, "wrong interface %s\n",ifce);
		return -1;
	}
	return 0;
}
#endif

#ifdef CONFIG_MCORE_IP_REASS
static int set_force_reassembly4(char *tok)
{
	fp_ifnet_t *ifp;
	char *   ifce;
	uint32_t command = 0;
	int numtokens = gettokens(tok);

	if (numtokens != 2 ) {
		fpdebug_fprintf(stderr, "wrong arguments\n");
		return -1;
	}

	ifce = chargv[0];
	if ((ifp = fp_getifnetbyname(ifce)) == NULL) {
		fpdebug_printf("bad interface name: %s\n", ifce);
		return -1;
	}

	if (0 == strncmp(chargv[1],"on",2))
		command = 1;
	else {
		if (0 != strncmp(chargv[1],"off",3)) {
			fpdebug_printf("bad command %s, must be on|off\n",
				       chargv[1]);
			return -1;
		}
	}

	if (fp_setifnet_force_reassembly4(ifp->if_ifuid,
					  command) != 0 ) {
		fpdebug_fprintf(stderr, "wrong interface %s\n",ifce);
		return -1;
	}
	return 0;
}
#endif

#ifdef CONFIG_MCORE_IPV6_REASS
static int set_force_reassembly6(char *tok)
{
	fp_ifnet_t *ifp;
	char *   ifce;
	uint32_t command = 0;
	int numtokens = gettokens(tok);

	if (numtokens != 2 ) {
		fpdebug_fprintf(stderr, "wrong arguments\n");
		return -1;
	}

	ifce = chargv[0];
	if ((ifp = fp_getifnetbyname(ifce)) == NULL) {
		fpdebug_printf("bad interface name: %s\n", ifce);
		return -1;
	}

	if (0 == strncmp(chargv[1],"on",2))
		command = 1;
	else {
		if (0 != strncmp(chargv[1],"off",3)) {
			fpdebug_printf("bad command %s, must be on|off\n",
				       chargv[1]);
			return -1;
		}
	}

	if (fp_setifnet_force_reassembly6(ifp->if_ifuid,
					  command) != 0 ) {
		fpdebug_fprintf(stderr, "wrong interface %s\n",ifce);
		return -1;
	}
	return 0;
}
#endif

#ifdef CONFIG_MCORE_XIN4
#ifndef __FastPath__
#define FPDEBUG_ADD_XIN4_USAGE \
	"\n\ttun-xin4-add NAME LOCAL_ADDR REMOTE_ADDR" \
	"\n\t\t[vr VR] [lvr LVR] [mtu MTU] [ttl TTL]" \
	"\n\t\t[tos TOS] [inhtos INHTOS]"
static int fpdebug_tunnel_xin4_add(char* tok)
{
	int res = 0;
	int count;
	int ind = 0;
	char *word;
	char *end = NULL;
	char ifname[16];
	uint32_t ifuid;
	uint32_t vrfid = default_vrfid;
	uint32_t linkvrfid = default_vrfid;
	uint32_t mtu = 1480;
	uint8_t ttl = 0;
	uint8_t tos = 0;
	uint8_t inh_tos = 0;
	struct in_addr  local;
	struct in_addr  remote;

	count = gettokens(tok);

	/* 3 compulsory arguments */
	if (count < 3)
		FPDEBUG_ERRX("tun-xin4-add: too few arguments");
	/* Get tunnel NAME */
	strncpy(ifname, chargv[ind++], 16);

	/* LOCAL_ADDR */
	word = chargv[ind++];
	if (fpdebug_inet_pton(AF_INET, word, &local) != 1)
		FPDEBUG_ERRX("%s: invalid IPv4 address", word);

	/* REMOTE_ADDR */
	word = chargv[ind++];
	if (fpdebug_inet_pton(AF_INET, word, &remote) != 1)
		FPDEBUG_ERRX("%s: invalid IPv4 address", word);

	/* parse optional parameters if any */
	while (ind < count) {

		/* VRFID */
		word = chargv[ind++];
		if (strcmp(word, "vr") == 0) {
			word = chargv[ind++];
			vrfid = (uint32_t)strtoul(word, &end, 0);
			if ((vrfid & FP_VRFID_MASK) >= FP_MAX_VR) {
				FPDEBUG_ERRX("%s: vrfid too high, max is %d",
					     word, FP_MAX_VR);
			}
		}
		/* LVRFID */
		else if (strcmp(word, "lvr") == 0) {
			word = chargv[ind++];
			linkvrfid = (uint32_t)strtoul(word, &end, 0);
			if ((linkvrfid & FP_VRFID_MASK) >= FP_MAX_VR) {
				FPDEBUG_ERRX("%s: link vrfid too high, max is %d",
					     word, FP_MAX_VR);
			}
		}

		/* MTU */
		else if (strcmp(word, "mtu") == 0) {
			word = chargv[ind++];
			mtu = (uint32_t)strtoul(word, &end, 0);
		}

		/* TTL */
		else if (strcmp(word, "ttl") == 0) {
			word = chargv[ind++];
			ttl = (uint8_t)strtoul(word, &end, 0);
		}

		/* TOS */
		else if (strcmp(word, "tos") == 0) {
			word = chargv[ind++];
			tos = (uint8_t)strtoul(word, &end, 0);
		}

		/* INHTOS */
		else if (strcmp(word, "inhtos") == 0) {
			word = chargv[ind++];
			inh_tos = (uint8_t)strtoul(word, &end, 0);
		}
		else
			FPDEBUG_ERRX("%s: invalid optional parameter", word);
	}

	ifuid = ifname2ifuid(ifname, vrfid & FP_VRFID_MASK);

	res = fp_interface_add(vrfid & FP_VRFID_MASK, ifname, NULL, mtu,
			       ifuid, 0, FP_IFNET_VIRTUAL_PORT, FP_IFTYPE_XIN4,
			       0);

	if (res == FP_ADDIFNET_SUCCESS) {
		fp_addifnet_xin4info(ifuid, ttl,
				     tos, inh_tos,
				     vrfid & FP_VRFID_MASK,
				     linkvrfid & FP_VRFID_MASK,
				     (struct fp_in_addr *)&local.s_addr,
				     (struct fp_in_addr *)&remote.s_addr);

		if (f_colocalized) {
			fp_setifnet_bladeinfo(ifuid, fp_shared->fp_blade_id);
		}

	} else if (res != FP_ADDIFNET_EXIST)
		FPDEBUG_ERRX("Error when creating tunnel in fastpath");

end:
	return res;
}

#define FPDEBUG_DEL_XIN4_USAGE \
	"\n\ttun-xin4-del IFNAME"
static int fpdebug_tunnel_xin4_del(char* tok)
{
	int res = 0;
	int count;
	int ind = 0;
	char *word;
	uint32_t ifuid = 0;
	fp_ifnet_t *ifp;

	count = gettokens(tok);

	/* 1 compulsory arguments */
	if (count < 1)
		FPDEBUG_ERRX("tun-xin4-del: too few arguments");

	/* Get tunnel IFNAME */
	word = chargv[ind++];
	ifp = fp_getifnetbyname(word);
	if (ifp == NULL || ifp->if_type != FP_IFTYPE_XIN4) {
		fpdebug_fprintf(stderr, "unknown xin4 tunnel %s\n", chargv[0]);
		return -1;
	}
	ifuid = ifp->if_ifuid;

	fpdebug_printf("removing xin4 (ctu) %s ifuid=0x%08x bound to port %d\n",
		       ifp->if_name, ifuid, FP_IFNET_VIRTUAL_PORT);

	fp_delifnet_xinyinfo(ifuid);
	res = fp_interface_del(ifuid, 0, 0);

	if (res)
		FPDEBUG_ERRX("tunnel deletion failed");
end:
	return res;
}
#endif /* !__FastPath__ */
#endif /* CONFIG_MCORE_XIN4 */

#ifdef CONFIG_MCORE_IPSEC_SVTI
#ifndef __FastPath__

#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
#define FPDEBUG_ADD_SVTI_USAGE \
	"\n\tadd-svti NAME LOCAL_ADDR REMOTE_ADDR" \
	"\n\t\t[vr VR] [lvr LVR] [mtu MTU]"
#else
#define FPDEBUG_ADD_SVTI_USAGE \
	"\n\tadd-svti NAME [vr VR] [mtu MTU]"
#endif
static int fpdebug_add_svti(char* tok)
{
	int res = -1;
	int count;
	int ind = 0;
	char *word;
	char *end = NULL;
	char ifname[16];
	uint32_t ifuid;
	uint32_t vrfid = default_vrfid;
#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
	uint32_t linkvrfid = default_vrfid;
	struct in_addr  local;
	struct in_addr  remote;
#endif
	uint32_t mtu = 1480;

	count = gettokens(tok);

#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
	if (count < 3)
#else
	if (count < 1)
#endif
		FPDEBUG_ERRX("add-svti: too few arguments");
	/* Get tunnel NAME */
	strncpy(ifname, chargv[ind++], 16);

#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
	/* LOCAL_ADDR */
	word = chargv[ind++];
	if (fpdebug_inet_pton(AF_INET, word, &local) != 1)
		FPDEBUG_ERRX("add-svti: %s: invalid IPv4 address", word);

	/* REMOTE_ADDR */
	word = chargv[ind++];
	if (fpdebug_inet_pton(AF_INET, word, &remote) != 1)
		FPDEBUG_ERRX("add-svti: %s: invalid IPv4 address", word);
#endif

	/* parse optional parameters if any */
	while (ind < count) {

		/* VRFID */
		word = chargv[ind++];
		if (strcmp(word, "vr") == 0) {
			word = chargv[ind++];
			vrfid = (uint32_t)strtoul(word, &end, 0);
			if ((vrfid & FP_VRFID_MASK) >= FP_MAX_VR) {
				FPDEBUG_ERRX("add-svti: %s: vrfid too high, max is %d",
					     word, FP_MAX_VR);
			}
		}

#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
		/* LVRFID */
		else if (strcmp(word, "lvr") == 0) {
			word = chargv[ind++];
			linkvrfid = (uint32_t)strtoul(word, &end, 0);
			if ((linkvrfid & FP_VRFID_MASK) >= FP_MAX_VR) {
				FPDEBUG_ERRX("add-svti: %s: link vrfid too high, max is %d",
					     word, FP_MAX_VR);
			}
		}
#endif /* CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA */

		/* MTU */
		else if (strcmp(word, "mtu") == 0) {
			word = chargv[ind++];
			mtu = (uint32_t)strtoul(word, &end, 0);
		}

		else
			FPDEBUG_ERRX("add-svti: %s: invalid optional parameter", word);
	}

	ifuid = ifname2ifuid(ifname, vrfid & FP_VRFID_MASK);

	res = fp_interface_add(vrfid & FP_VRFID_MASK, ifname, NULL, mtu,
			       ifuid, 0, FP_IFNET_VIRTUAL_PORT, FP_IFTYPE_SVTI,
			       0);

	if (res == FP_ADDIFNET_SUCCESS) {

#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
		res = fp_addifnet_svtiinfo(ifuid,
				     linkvrfid & FP_VRFID_MASK,
				     (struct fp_in_addr *)&local.s_addr,
				     (struct fp_in_addr *)&remote.s_addr);
#else
		res = fp_svti_add(ifuid);
#endif

		if (res != 0) {
			fp_delifnet(ifuid);
			FPDEBUG_ERRX("add-svti: could not allocate room for svti info");
		}

		if (f_colocalized) {
			fp_setifnet_bladeinfo(ifuid, fp_shared->fp_blade_id);
		}

	}
	else if (res == FP_ADDIFNET_EXIST)
		FPDEBUG_ERRX("add-svti: ifuid 0x%08x already exists", ntohl(ifuid));
	else
		FPDEBUG_ERRX("add-svti: Error when creating svti in fastpath");

end:
	return res;
}

#define FPDEBUG_DEL_SVTI_USAGE \
	"\n\tdel-svti IFNAME"
static int fpdebug_del_svti(char* tok)
{
	int res = -1;
	int count;
	int ind = 0;
	char *word;
	uint32_t ifuid = 0;
	fp_ifnet_t *ifp;

	count = gettokens(tok);

	/* 1 compulsory argument */
	if (count < 1)
		FPDEBUG_ERRX("del-svti: too few arguments");

	/* Get tunnel IFNAME */
	word = chargv[ind++];
	ifp = fp_getifnetbyname(word);
	if (ifp == NULL || ifp->if_type != FP_IFTYPE_SVTI)
		FPDEBUG_ERRX("del-svti: unknown svti interface %s", chargv[0]);

	ifuid = ifp->if_ifuid;

	fpdebug_printf("del-svti: removing svti %s ifuid=0x%08x bound to port %d\n",
		       ifp->if_name, ntohl(ifuid), FP_IFNET_VIRTUAL_PORT);

#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
	fp_delifnet_svtiinfo(ifuid);
#else
	fp_svti_del(ifuid);
#endif

	res = fp_interface_del(ifuid, 0, 0);

	if (res)
		FPDEBUG_ERRX("del-svti: svti %s deletion failed", chargv[0]);
end:
	return res;
}
#endif /* !__FastPath__ */
#endif /* CONFIG_MCORE_IPSEC_SVTI */

#ifdef __FastPath__
static int fpdebug_autotest(char *tok)
{
	int numtokens = gettokens(tok);

	if (numtokens != 1) {
		fpdebug_fprintf(stderr, "wrong arguments\n");
		return -1;
	}

	return fp_do_test_fpn0(atoi(chargv[0]));
}
#else
#define fpdebug_autotest fpdebug_send_to_fp
#endif

#if defined CONFIG_MCORE_VFP_FTRACE
#ifdef __FastPath__
static int fpdebug_ftrace(char *tok)
{
	int numtokens = gettokens(tok);

	if (numtokens == 1 && !strcmp(chargv[0], "list")) {
		fpn_ftrace_list();
		return 0;
	}

	if (numtokens == 2 && !strcmp(chargv[0], "hook"))
		return fpn_ftrace_hook(chargv[1]);

	if (numtokens == 2 && !strcmp(chargv[0], "unhook"))
		return fpn_ftrace_unhook(chargv[1]);


	fpdebug_fprintf(stderr, "wrong arguments\n");
	return -1;
}
#else
#define fpdebug_ftrace fpdebug_send_to_fp
#endif
#endif /* CONFIG_MCORE_VFP_FTRACE */

#if !defined(__FastPath__) && \
	defined(CONFIG_MCORE_FPE_MCEE) && defined(CONFIG_MCORE_TEST_CYCLES)
static int do_test_cycles(char *tok)
{
	uint64_t delta;
	int i;
	cpu_usage_shared_mem_t *cpu_usage_shared = fpn_shmem_mmap("cpu-usage-shared",
								  NULL,
								  sizeof(cpu_usage_shared_mem_t));

	if (cpu_usage_shared == NULL) {
		fpdebug_printf("can't map cpu-usage-shared\n");
		return -1;
	}

	memset(cpu_usage_shared->busy_cycles, 0, sizeof(cpu_usage_shared->busy_cycles));
	cpu_usage_shared->do_test_cycles = 1;
	sleep(1);
	cpu_usage_shared->do_test_cycles = 0;
	sleep(1);

	for (i = 0; i < FPN_MAX_CORES; i++) {
		if (cpu_usage_shared->busy_cycles[i].end == 0)
			continue;
		delta = cpu_usage_shared->busy_cycles[i].end - cpu_usage_shared->busy_cycles[i].begin;
		printf("cpu%02u: begin=%16llu end=%16llu delta=%16llu\n",
				i,
				(unsigned long long)cpu_usage_shared->busy_cycles[i].begin,
				(unsigned long long)cpu_usage_shared->busy_cycles[i].end,
				(unsigned long long)delta);
	}

	return 0;
}
#endif

#if defined(__FastPath__) &&  defined(FP_STANDALONE) && defined(CONFIG_MCORE_NET_EMUL)
#include "fp-net-emul.h"

static int
net_emul_rx_run(char *tok)
{
	int nb_args;
	int nb_sec;

	nb_args = gettokens(tok);
	if (nb_args < 1) {
		fpdebug_fprintf(stderr, "nb-seconds argument missing\n");
		return -1;
	}
	nb_sec = atoi(chargv[0]);
	if (nb_sec <= 0) {
		fpdebug_fprintf(stderr, "nb-seconds=%s invalid\n", chargv[0]);
		return -1;
	}
	fp_net_emul_self_rx_run((unsigned int)nb_sec);
	return 0;
}
#endif

static int load_config(char *tok)
{
	if (gettokens(tok) != 1) {
		fpdebug_fprintf(stderr, "invalid args: load-config FILE\n");
		return -1;
	}
	return fpdebug_load_config(chargv[0]);
}

static int show_loaded_plugins(char *tok)
{
	uint8_t count = gettokens(tok);
	char *type_str = NULL;
	int select = 0;
	unsigned int i;

	if (count != 1)
		goto fail;

	type_str = chargv[0];
	if (strcmp(type_str, "fp") == 0)
		select = FP_LOADED;
	else if (strcmp(type_str, "fpm") == 0)
		select = FPM_LOADED;
	else if (strcmp(type_str, "all") == 0)
		select = FPCLI_LOADED | FP_LOADED | FPM_LOADED;
	else if (strcmp(type_str, "fpcli") == 0)
		select = FPCLI_LOADED;
	else
		goto fail;

	if (select & FP_LOADED) {
		fpdebug_printf("FP loaded modules:\n");
		for (i = 0; i < FP_MAX_PLUGINS; i++)
			if (strlen(fp_shared->fpplugins[i]))
				fpdebug_printf("\t%s\n",
				               fp_shared->fpplugins[i]);
	}
	if (select & FPM_LOADED) {
		fpdebug_printf("FPM loaded modules:\n");
		for (i = 0; i < FP_MAX_PLUGINS; i++)
			if (strlen(fp_shared->fpmplugins[i]))
				fpdebug_printf("\t%s\n",
				               fp_shared->fpmplugins[i]);
	}
	if (select & FPCLI_LOADED) {
		fpdebug_printf("FPCLI loaded modules:\n");
		for (i = 0; i < FP_MAX_PLUGINS; i++)
			if (strlen(fp_shared->fpcliplugins[i]))
				fpdebug_printf("\t%s\n",
				               fp_shared->fpcliplugins[i]);
	}

	return 0;
fail:
	fpdebug_printf("wrong arguments: show-loaded-plugins [fp|fpm|fpcli|all]\n");
	return 0;
}

static int comment(char *tok __fpn_maybe_unused)
{
	return 0;
}

static int reset(char *tok __fpn_maybe_unused)
{
	memset(fp_shared, 0, sizeof(shared_mem_t));
	fp_init();
	return 0;
}

static int show_help(char *tok);
static int find_command(char *tok);
CLI_COMMAND *search_command (char *name);

static CLI_COMMAND builtin_cmds[] = {
	{"help", show_help, "Display command list: [<name>]"},
	{"find", find_command, "Find a command containing pattern: <pattern>"},
	{"reset", reset, "Zero and initialize shared memory"},
	{"exit", __exit, "Quit"},
	{"quit", __exit, "Quit"},
	{"memtest", memtest, "Test read/write of all shared memory"},
	{"turn", turn, "Turn fast path on or off: turn [on|off]"},
#ifndef __FastPath__
	{"fp-init", init_sharedmem, "Initialize shared memory with default paramaters (coloc)"},
#endif
#ifdef CONFIG_MCORE_L2SWITCH
	{"set-l2switch-mode", set_l2switch_mode, "set-l2switch-mode <on|off>"},
	{"set-l2switch-nextport", set_l2switch_nextport, "set-l2switch-nextport <portid> <nextportid|drop|exception>"},
	{"dump-l2switch", dump_l2switch, "Dump l2switch configuration"},
#endif
	{"dump-conf", dump_conf, "Dump fast path configuration flags"},
	{"dump-clock-hz", dump_clock_hz, "Dump clock HZ value"},
#ifdef CONFIG_MCORE_IP
	{"add-neighbour", add_neighbour, "Add neighbour info: add-neighbour <ip> <mac> <ifname>"},
	{"delete-neighbour", delete_neighbour, "Delete neighbour info: delete-neighbour <ip> <ifname>"},
	{"add-route", add_route, "Add a new route: add-route <ip> <prefix length> <gateway> <ifname> [<type>]"},
	{"delete-route", delete_route, "Delete a route: delete-route <ip> <prefix length> <gateway> <ifname>"},
	{"dump-neighbours", dump_neighbours, "Dump the neighbours table"},
	{"dump-rt", dump_rt_table, "Dump the rt_entry table [rt_index]"},
	{"dump-nh", dump_nh_table, "Dump the Next-Hop table [nh_index]"},
	{"dump-user", dump_user, "Dump the user routing entries [all|<type>] (default type ROUTE=1)"},
	{"dump-routes", dump_routes, "Dump the route table [all|<type>] (default type ROUTE=1)"},
#endif
	{"dump-interfaces", dump_interfaces, "Dump the interface table: dump-interfaces"},
	{"add-interface", add_interface, "add an interface: add-interface <name> <port> <mac> [ifindex]"},
	{"del-interface", del_interface, "delete an interface: del-interface <ifname>"},
	{"set-if-mtu", set_if_mtu, "set MTU on an interface <if_name> <mtu>"},
	{"set-if-type", set_if_type, "set interface type: set-if-type <if_name> <type>"},
#ifdef CONFIG_MCORE_VRF
	{"dump-xvrf", dump_xvrf, "Dump the active X-VRF interfaces: dump-xvrf"},
#endif
#ifdef CONFIG_MCORE_IP
	{"add-address4", add_address4, "add an ip address: add-address4 <ifname> <ipv4> <prefix>"},
	{"del-address4", del_address4, "delete an ip address: del-address4 <ifname> <ipv4> <prefix>"},
	{"dump-address4", dump_address4, "Dump the ip addresses for a specific interface: print-address4 <ifname>"},
#endif
#ifdef CONFIG_MCORE_IPV6
	{"add-address6", add_address6, "add an IPv6 address: add-address6 <ifname> <ipv6> <prefix>"},
	{"del-address6", del_address6, "delete an IPv6 address: del-address6 <ifname> <ipv6> <prefix>"},
	{"dump-address6", dump_address6, "Dump the IPv6 addresses for a specific interface: print-address6 <ifname>"},
#endif
#ifdef CONFIG_MCORE_NETFILTER
	{"netfilter", netfilter, "show/enable/disable netfilter: netfilter [on|off]"},
#endif
	{"dump-interfaces-ifname-hash", dump_interfaces_ifname_hash, "Dump the interface per-ifname hash table " DUMP_HASH_OPTS},
	{"dump-interfaces-ifuid-hash", dump_interfaces_ifuid_hash, "Dump the interface per-ifuid hash table" DUMP_HASH_OPTS},
	{"dump-ports", dump_ports, "Dump the ports table: dump-ports"},
#ifdef CONFIG_MCORE_IPV6
	{"dump-neighbours6", dump_neighbours6, "Dump the IPv6 neighbours table"},
	{"dump-rt6", dump_rt6_table, "Dump the IPv6 rt_entry table [rt_index]"},
	{"dump-nh6", dump_nh6_table, "Dump the IPv6 Next-Hop table [nh_index]"},
	{"dump-user6", dump_user6, "Dump the user routing entries [all|<type>] (default type ROUTE=1)"},
	{"dump-routes6", dump_routes6, "Dump the IPv6 route table [all|<type>] (default type ROUTE=1)"},
#endif
	{"dump-fp-shared", dump_fp_shared, "Dump raw shared memory into a header file <all|nf> <file> [var_name]\nall for all shared memory, nf for Netfilter tables"},
#ifdef CONFIG_MCORE_IPSEC
#ifdef CONFIG_MCORE_IPSEC_SVTI
	{"dump-spd", dump_spd, "Dump SPD [all] [svti IFNAME]\nor: dump-spd raw"},
	{"dump-sad", dump_sad, "Dump SAD [all] [svti IFNAME] [<src> <prefix> <dst> <prefix> <proto>]"},
#else
	{"dump-spd", dump_spd, "Dump SPD [all]\nor: dump-spd raw"},
	{"dump-sad", dump_sad, "Dump SAD [all] [<src> <prefix> <dst> <prefix> <proto>]"},
#endif
	{"dump-sad-spi-hash", dump_sad_spi_hash, "Dump SAD SPI hash table " DUMP_HASH_OPTS},
	{"dump-sad-selector-hash", dump_sad_selector_hash, "Dump SAD selector hash table " DUMP_HASH_OPTS},
	{"set-ipsec-once", set_ipsec_once, "Do IPsec maximum once on each packet [on|off]"},
	{"set-ipsec-output-blade", set_ipsec_output_blade, "Set default IPsec output blade [bladeid]"},
#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
	{"dump-spd-hash", dump_spd_hash, "Dump SPD hash table " DUMP_HASH_OPTS},
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
	{"dump-spd6-hash", dump_spd6_hash, "Dump IPv6 SPD hash table " DUMP_HASH_OPTS},
#endif
#ifdef CONFIG_MCORE_MULTIBLADE
	{"set-sa-sync-threshold", set_sa_sync_threshold, "Set packet number threshold between two sync messages"},
	{"show-sa-sync-threshold", show_sa_sync_threshold, "Show packet number threshold between two sync messages"},
#endif
#ifdef CONFIG_MCORE_IPSEC_TRIE
	{"show-ipsec-trie", show_ipsec_trie, "Show ipsec trie stats and thresholds: show-ipsec-trie"},
	{"set-ipsec-trie-threshold", set_ipsec_trie_threshold, "Set ipsec trie thresholds: set-ipsec-trie-threshold [in|out] THRESHOLD"},
#endif
#endif	/* CONFIG_MCORE_IPSEC */
#ifdef CONFIG_MCORE_IPSEC_IPV6
#ifdef CONFIG_MCORE_IPSEC_SVTI
	{"dump-spd6", dump_spd6, "Dump IPv6 SPD [all] [svti IFNAME]\nor: dump-spd6 raw"},
	{"dump-sad6", dump_sad6, "Dump IPv6 SAD [all] [svti IFNAME] [<src> <prefix> <dst> <prefix> <proto>]"},
#else
	{"dump-spd6", dump_spd6, "Dump IPv6 SPD [all]\nor: dump-spd6 raw"},
	{"dump-sad6", dump_sad6, "Dump IPv6 SAD [all] [<src> <prefix> <dst> <prefix> <proto>]"},
#endif
	{"dump-sad6-spi-hash", dump_sad6_spi_hash, "Dump IPv6 SAD SPI hash table " DUMP_HASH_OPTS},
	{"dump-sad6-selector-hash", dump_sad6_selector_hash, "Dump IPv6 SAD selector hash table " DUMP_HASH_OPTS},
	{"set-ipsec6-output-blade", set_ipsec6_output_blade, "Set default IPsec6 output blade [bladeid]"},
#ifdef CONFIG_MCORE_MULTIBLADE
	{"set-sa6-sync-threshold", set_sa6_sync_threshold, "Set IPv6 IPsec packet number threshold between two sync messages"},
	{"show-sa6-sync-threshold", show_sa6_sync_threshold, "Show IPv6 IPsec packet number threshold between two sync messages"},
#endif
#endif	/* CONFIG_MCORE_IPSEC_IPV6 */
#ifdef CONFIG_MCORE_TAP
	{"set-tap-state", set_tap_state, "Select TAP behavior [local|global]"},
	{"set-tap", set_tap, "Enable/disable TAP [on|off]"},
#endif
#ifdef CONFIG_MCORE_TAP_CIRCULAR_BUFFER
#if (!defined(__FastPath__) && !defined(FP_STANDALONE)) || (defined(__FastPath__) && defined(FP_STANDALONE))

	{"tap-capture", tap_capture, "Enable/disable TAP circular buffer capture [on|off] <interface> <nb pkts> <pkt length> <bpf filter>"},
	{"tap-dump", tap_dump, "Dump TAP circular buffer [file]"},
	{"tap-buffer", tap_buffer, "Create/delete TAP cicular buffer [create <size[B|K|M|G]> | delete]"},
#endif
#endif
#ifdef CONFIG_MCORE_IPSEC_SVTI
	{"dump-svti", dump_svti, "Dump SVTI interfaces SPDs [all] [svti IFNAME]"},
#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
	{"dump-svti-hash", dump_svti_hash, "Dump SVTI interfaces hash table " DUMP_HASH_OPTS},
#endif
#ifndef __FastPath__
	{"add-svti", fpdebug_add_svti, "Create an SVTI interface: " FPDEBUG_ADD_SVTI_USAGE},
	{"del-svti", fpdebug_del_svti, "Delete an SVTI interface: " FPDEBUG_DEL_SVTI_USAGE},
#endif /* !__FastPath__ */
#endif /* CONFIG_MCORE_IPSEC_SVTI */
#ifdef CONFIG_MCORE_TCP_MSS
	{"set-tcpmss", set_tcpmss4, "Set TCP Maximum Segment Size on port for IPv4: <port> <mss4>"},
#endif
#if defined(CONFIG_MCORE_TCP_MSS) && defined(CONFIG_MCORE_IPV6)
	{"set-tcpmss6", set_tcpmss6, "Set TCP Maximum Segment Size on port for IPv6: <port> <mss6>"},
#endif
#ifdef CONFIG_MCORE_IP_REASS
	{"set-force-reassembly", set_force_reassembly4, "Set force reassembly flag for IPv4: <interface> <on|off>"},
#endif
#ifdef CONFIG_MCORE_IPV6_REASS
	{"set-force-reassembly6", set_force_reassembly6, "Set force reassembly flag for IPv6: <interface> <on|off>"},
#endif
#ifdef CONFIG_MCORE_NETFILTER
	{"dump-nfhook", dump_nfhook, "Dump hook priority table"},
	{"dump-nftable", dump_nftable, "Dump a netfilter table: dump-nftable <4|6> <filter|mangle> [all|nonzero]"},
#ifdef CONFIG_MCORE_NF_CT
	{"dump-nfct", dump_nfct, "Dump the netfilter conntrack table: dump-nfct [number of entries] {summary}"},
#ifdef CONFIG_MCORE_NF_CT_CPEID
	{"dump-nfct-bycpeid", dump_nfct_bycpeid, "Dump conntrack associated to a CPE (ip address): dump-nfct-bycpeid <CPE address> [number of entries] {summary}"},
#endif
#endif
	{"nf-hook", nf_hook, "show/enable/disable hooks in nf_conf: nf-hook [<table>|'all_tables' <hook>|'all_hooks' <on|off>]"},
	{"nf-nat-conntrack", nf_nat_conntrack, "show/enable/disable nat conntrack in nf_conf: nf-nat-conntrack [<on|off>]"},
#ifdef CONFIG_MCORE_MULTIBLADE
	{"ct-bladeid", ct_bladeid, "set ct-bladeid: ct-bladeid [blade ID]"},
#endif
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	{"netfilter6", netfilter6, "show/enable/disable IPv6 netfilter: netfilter6 [on|off]"},
	{"dump-nf6hook", dump_nf6hook, "Dump hook priority table for IPv6"},
	{"nf-hook6", nf_hook6, "show/enable/disable hooks in nf6_conf: nf-hook6 [<table>|'all_tables' <hook>|'all_hooks' <on|off>]"},
#ifdef CONFIG_MCORE_NF6_CT
	{"dump-nf6ct", dump_nf6ct, "Dump the IPv6 netfilter conntrack table: dump-nf6ct [number of entries] {summary}"},
#endif
#endif
#ifdef CONFIG_MCORE_NETFILTER_CACHE
	{"nf-cache-invalidate", nf_cache_invalidate, "Invalidate fp-nf-cache: nf-cache-invalidate"},
	{"dump-nf-cache", dump_nf_cache, "Dump fast path netfilter cache entries: dump-nf-cache [num] | count details"},
	{"nf-cache", nf_cache, "show/enable/disable netfilter cache: nf-cache [on|off]"},
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE
	{"nf6-cache", nf6_cache, "show/enable/disable IPv6 netfilter cache: nf6-cache [on|off]"},
	{"nf6-cache-invalidate", nf6_cache_invalidate, "Invalidate fp-nf6-cache: nf6-cache-invalidate"},
	{"dump-nf6-cache", dump_nf6_cache, "Dump fast path IPv6 netfilter cache entries: dump-nf6-cache [num] | count details"},
#endif
	{"dump-size", dump_size, "Dump size of shared structures"},
	{"dump-cpu-usage", dump_cpu_usage, "Dump FP cpu usage [delay_usec]"},
#ifdef CONFIG_MCORE_FPN_MBUF_TRACK
	{"dump-mtrack", dump_mtrack, "dump mbuf tracking information: dump-mtrack [group]"},
#endif
	{"dump-config", dump_config, "Dump mcore configuration file"},
#ifndef __FastPath__ /* no netfpc in embedded fpdebug */
#ifdef CONFIG_MCORE_KTABLES
	{"ktables-set", fpd_ktables_set, "set kernel table"},
	{"ktables-dump", fpd_ktables_dump, "dump kernel tables"},
#endif
	{"dump-eqos-stats", dump_eqos_stats, "Dump the statistics of egress QoS : dump-eqos-stats all | port <id> | queue <id>"},
	{"dump-eqos-params", dump_eqos_params, "Dump the parameters of egress QoS : dump-eqos-params all | port <id> | queue <id>"},
#endif /* !__FastPath__ */
#ifdef CONFIG_MCORE_ARP_REPLY
	{"arp-reply", set_arp_reply, "Enable/disable ARP reply: arp-reply [on|off]"},
#endif
#ifdef CONFIG_MCORE_IP
	{"show-route", show_route, "Search for the route to a destination: show-route <ip> [src]"},
	{"show-filling", show_filling, "Show the filling of each table in memory"},
	{"get-route", get_route, "Search for the exact route to a prefix: get-route <ip> <len>"},
	{"get-src-address", get_src_address, "Search for the source address to a given destination: get-src-address <ip>"},
#endif /* CONFIG_MCORE_IP */
#ifdef CONFIG_MCORE_MULTIBLADE
	{"add-blade", add_blade, "Add a new blade: add-blade <id> <mac> [local]"},
	{"del-blade", del_blade, "Delete a blade: del-blade <id>"},
	{"set-fpib-ifuid", set_fpib_ifuid, "Set the FP interblade interface: set-fpib-ifuid <ifuid>"},
#endif
	{"set-blade-id", set_blade_id, "Set the local blade_id (and cp blade_id): set-blade <fp_id> [cp_id]"},
	{"set-active-cpid", set_active_cpid, "Set the active control plane: set-active-cpid <cp_id>"},
	{"set-blade-cp", set_blade_cp, "Set the local blade Control Plane contact info: set-blade-cp <if_port> [<mac>] [mtu <mtu>]"},
	{"dump-blades", dump_blades, "Show list of all configured blades: dump-blades"},
#if !defined(__FastPath__) && defined(CONFIG_MCORE_TAP_BPF)
	{"set-tap-iface", set_tap_iface, "Enable/disable TAP on an interface: set-tap-iface [ifname|any] [on|off]"},
	{"dump-bpf", dump_bpf, "Dump BPF (Socket filter) information: dump-bpf [all [raw]]"},
#endif
#ifdef CONFIG_MCORE_MULTICAST4
	{"dump-mfc4", dump_mfc4, "Dump Multicast routing table: dump-mfc4 [all]"},
	{"mcastgrp-filter", mcastgrp_filter, "Enable Multicast group filtering: mcastgrp-filter [on [accept-all]|off]"},
	{"mcastgrp-add", mcastgrp_add, "Add a multicast group into filtering whitelist: mcastgrp-add <mcast-addr|all> <source-interface|all>"},
	{"mcastgrp-del", mcastgrp_del, "Del a multicast group from filtering whitelist: mcastgrp-del <mcast-addr|all> <source-interface|all>"},
#endif
#ifdef CONFIG_MCORE_MULTICAST6
	{"dump-mfc6", dump_mfc6, "Dump Multicast routing table ipv6 : dump-mfc6 [all]"},
	{"mcast6grp-filter", mcast6grp_filter, "Enable Multicast group filtering: mcast6grp-filter [on [accept-all]|off]"},
	{"mcast6grp-add", mcast6grp_add, "Add a multicast group into filtering whitelist: mcast6grp-add <mcast-addr|all> <source-interface|all>"},
	{"mcast6grp-del", mcast6grp_del, "Del a multicast group from filtering whitelist: mcast6grp-del <mcast-addr|all> <source-interface|all>"},
#endif
#ifdef CONFIG_MCORE_VXLAN
	{"vxlan-dump-fdb", vxlan_dump_fdb, "Dump vxlan fdb: vxlan-dump-fdb <interface>"},
	{"vxlan-dump", vxlan_dump, "Dump vxlan infos"},
#ifndef __FastPath__
	{"vxlan-iface-add", vxlan_iface_add, VXLAN_IFACE_ADD_USAGE},
	{"vxlan-iface-del", vxlan_iface_del, VXLAN_IFACE_DEL_USAGE},
	{"vxlan-fdb-add", vxlan_fdb_add, VXLAN_FDB_ADD_USAGE},
	{"vxlan-fdb-del", vxlan_fdb_del, VXLAN_FDB_DEL_USAGE},
#endif
#endif
	{"set-flags", set_flags, "Set interface flags: <interface> <flags>"},
	{"set-pref", set_preferred, "Set interface preference: <interface> on|off"},
#ifdef CONFIG_MCORE_IP
	{"set-ifdown", set_ifdown, "Clean any IPv4 route using this interface: <interface>"},
#endif
	{"echo", echo, "echo"},
	{"autoconf-ifp", fpdebug_autoconf_ifnet, "Auto configure interfaces"},
#ifdef CONFIG_MCORE_VRF
	{"vrf", set_vrfid, "Set/Check the reference for VRF-ID"},
	{"set-if-vrfid", set_if_vrfid, "set VRF-ID of an interface <if_name> <vrfid>"},
#endif
	{"set-ivrrp", set_ivrrp, "enable/disable/show the IVRRP flag: set-ivrrp <interface> [on|off]"},
#ifdef CONFIG_MCORE_RPF_IPV4
	{"rpf-ipv4", rpf_ipv4, "enable/disable/show the IPv4 Reverse Path Filtering: rpf-ipv4 <interface> [on|off]"},
#endif
#ifdef CONFIG_MCORE_RPF_IPV6
	{"rpf-ipv6", rpf_ipv6, "enable/disable/show the IPv6 Reverse Path Filtering: rpf-ipv6 <interface> [on|off]"},
#endif
	{"loglevel", loglevel, "set/show the loglevel from 0 (EMERG) to 7 (DEBUG): loglevel [value]"},
	{"logtype", logtype, "enable/disable logs, show enabled logs: logtype [<type|all> <on|off>]"},
	{"logmode", logmode, "set/show log mode: console or syslog. Default is console"},
#ifdef CONFIG_MCORE_IP_REASS
	{"reass4-maxqlen", reass4_maxqlen, "set/show IPv4 max queue length for reassembly: reass4-maxqlen [val]"},
#endif
#ifdef CONFIG_MCORE_IPV6_REASS
	{"reass6-maxqlen", reass6_maxqlen, "set/show IPv6 max queue length for reassembly: reass6-maxqlen [val]"},
#endif
	{"cp-if-fptun-size-thresh", cp_if_fptun_size_thresh, "set/show the FP/CP FPTUN message size warning threshold: cp-if-fptun-size-thresh [val]"},
	{"fpib-fptun-size-thresh", fpib_fptun_size_thresh, "set/show the FPIB FPTUN message size warning threshold: fpib-fptun-size-thresh [val]"},

#ifdef CONFIG_MCORE_HITFLAGS_SYNC
	{"dump-hitflags", dump_hitflags, "show ARP/NDP/CT hitflags: dump-hitflags [all | <arp | ndp | conntrack | conntrack6>] "},
	{"set-arp-hitflags", set_arp_hitflags, "set-arp-hitflags <period_in_seconds> <max_scanned> <max_sent>" },
#ifdef CONFIG_MCORE_IPV6
	{"set-ndp-hitflags", set_ndp_hitflags, "set-ndp-hitflags <period_in_seconds> <max_scanned> <max_sent>" },
#endif
#ifdef CONFIG_MCORE_NF_CT
	{"set-conntrack-hitflags", set_ct_hitflags, "set-conntrack-hitflags <period_in_seconds> <max_scanned> <max_sent>" },
#endif
#ifdef CONFIG_MCORE_NF6_CT
	{"set-conntrack6-hitflags", set_ct6_hitflags, "set-conntrack6-hitflags <period_in_seconds> <max_scanned> <max_sent>" },
#endif
#endif /*CONFIG_MCORE_HITFLAGS_SYNC */
#ifdef CONFIG_MCORE_MULTIBLADE
	{"neigh-bladeid", neigh_bladeid, "set neigh-bladeid: neigh-bladeid [blade ID]"},
#endif
	{"rfps-conf", rfps_conf, "Usage: rfps-conf RFPS_MODULE [<max_throughput_in_[k/K, m/M]bits_per_second> <min_refresh_period_in_milliseconds>]"},
	{"rfps-raw-conf", rfps_raw_conf, "Usage: rfps-raw-conf RFPS_MODULE [<transmit_period_in_milliseconds> <max_msg_per_tick> <min_refresh_period_in_milliseconds>]"},
#if defined CONFIG_MCORE_VFP_FTRACE
	{"ftrace", fpdebug_ftrace, "trace/untrace a function in " FPN_FTRACE_LOG_FILE
	 ": ftrace [hook|unhook] <fctname>"},
#endif
	{"show-lock-state", fpdebug_show_lockstate,
	 "display state of a spinlock/rwlock: show-lock-state <lock-addr>"},
	{"show-lock-log", fpdebug_show_locklog,
	 "display lock operations recorded on cores: show-lock-log [<core-id> "
	 "[max-records]] (all cores if no argument)"},
	{"dump-mempool", fpdebug_dump_mempool, "dump mempool status: dump-mempool <name>"},
	{"autotest", fpdebug_autotest, "start an autotest: autotest <id>"},
#ifdef CONFIG_MCORE_CPONLY_PORTMASK
	{"cponly-portmask", fpdebug_cponly_portmask, "set/display cponly portmask, if set, incoming packets are always directed to linux: cponly-portmask [mask]"},
#endif
#ifdef CONFIG_MCORE_DEBUG_PROBE
	{"dump-fp-probes", fpdebug_probe,
	 "show/reset probe stats: probe [dump|percore|reset|start|stop]"},
#endif
#ifndef __FastPath__
	{"fp", fp_command, "launch a fpdebug command in fastpath: fp [fp-cmd]" },
#endif
	{"on-cpu", on_cpu_command, "launch a fpdebug command on a specific fast path "
	 "core: on-cpu <core> <fpdebug cmd>" },
#if !defined(__FastPath__) && \
	defined(CONFIG_MCORE_FPE_MCEE) && defined(CONFIG_MCORE_TEST_CYCLES)
	{"test-cycles", do_test_cycles, "test fast path get-cycles"},
#endif
#if defined(__FastPath__) &&  defined(FP_STANDALONE) && defined(CONFIG_MCORE_NET_EMUL)
	{"rx_run", net_emul_rx_run,
	 "rx_run <sec> : receive self-generated IP packets for <sec> seconds"},
#endif
#if defined(FP_STANDALONE) || !defined(__FastPath__)
#ifdef CONFIG_MCORE_IPSEC
	{ "add-sa", add_sa, "create an IPv4 IPsec Security Association"
	  FPDEBUG_ADD_SA_USAGE },
	{ "del-sa", del_sa, "delete an IPv4 IPsec Security Association"
	  FPDEBUG_DEL_SA_USAGE },
	{ "flush-sa", flush_sa, "flush IPv4 IPsec Security Associations (per-vr)"
	  FPDEBUG_FLUSH_SA_USAGE },
	{ "add-sp", add_sp, "create an IPv4 IPsec Security Policy"
	  FPDEBUG_ADD_SP_USAGE },
	{ "update-sp", update_sp, "update an IPv4 IPsec Security Policy"
	  FPDEBUG_ADD_SP_USAGE },
	{ "del-sp", del_sp, "delete an IPv4 IPsec Security Policy"
	  FPDEBUG_DEL_SP_USAGE },
	{ "flush-sp", flush_sp, "flush IPv4 IPsec Security Policies (per-vr or per-svti)"
	  FPDEBUG_FLUSH_SP_USAGE },
#endif /* CONFIG_MCORE_IPSEC */
#endif /* defined(FP_STANDALONE) || !defined(__FastPath__) */
#ifdef CONFIG_MCORE_XIN4
#ifndef __FastPath__
	{"tun-xin4-add", fpdebug_tunnel_xin4_add,
	 "Create an IPv4/6 in IPv4 tunnel"
	  FPDEBUG_ADD_XIN4_USAGE},
	{"tun-xin4-del", fpdebug_tunnel_xin4_del,
	 "Delete an IPv4/6 in IPv4 tunnel"
	  FPDEBUG_DEL_XIN4_USAGE},
#endif
#endif

#define _EXPORT_DFCLI_CMDS_
#include "cli-cmd/fp-cli-commands.h"
#undef _EXPORT_DFCLI_CMDS_
	  
	{"load-config", load_config, "load a fpdebug configuration file: load-config FILE" },
	{"dump-timer-stats", fpdebug_dump_timer_stats, "dump timer stats"},
	{"show-loaded-plugins", show_loaded_plugins, "List loaded plugins for <module> [fp|fpm|fpcli|all]"},
	{"#", comment, "comment line" },
	{"//", comment, "comment line" },
	{";", comment, "comment line" },
	{(char *)NULL,0,(char *)NULL},
};
static cli_cmds_t builtin_cli = {
	.module = "builtin",
	.c = builtin_cmds,
};

FPN_STAILQ_HEAD(cli_cmds_list, cli_cmds);
FPN_DEFINE_SHARED(struct cli_cmds_list, cli_commands) =
	FPN_STAILQ_HEAD_INITIALIZER(cli_commands);

int fpdebug_add_commands(cli_cmds_t *cmds)
{
	cli_cmds_t *cur;

	if (!cmds)
		return -1;

	/* sanity check */
	FPN_STAILQ_FOREACH(cur, &cli_commands, next) {
		if (!strcmp(cur->module, cmds->module))
			return -1;
	}

	FPN_STAILQ_INSERT_TAIL(&cli_commands, cmds, next);

	return 0;
}

int fpdebug_del_commands(const char *module)
{
	cli_cmds_t *cur;

	if (!module)
		return -1;

	FPN_STAILQ_FOREACH(cur, &cli_commands, next) {
		if (strcmp(cur->module, module))
			continue;

		FPN_STAILQ_REMOVE(&cli_commands, cur, cli_cmds, next);
		return 0;
	}

	return -1;
}

// this symbol is called before anything else and registers builtin commands
static void fpdebug_builtin_init(void) __attribute__ ((constructor));
void fpdebug_builtin_init(void)
{
	fpdebug_add_commands(&builtin_cli);
}

static int show_help(char *tok)
{
	cli_cmds_t *cmd;

	if (gettokens(tok) == 0) {
		FPN_STAILQ_FOREACH(cmd, &cli_commands, next) {
			unsigned int j;

			for (j = 0; cmd->c[j].name; j++) {
				fpdebug_printf("%s: %s\n", cmd->c[j].name, cmd->c[j].help);
			}
		}
	} else {
		CLI_COMMAND *cli_cmd = search_command(chargv[0]);

		if (cli_cmd)
			fpdebug_printf("%s: %s\n", cli_cmd->name, cli_cmd->help);
	}
	return 0;
}

static int find_command(char *tok)
{
	cli_cmds_t *cmd;
	char *token;

	/* 1 compulsory argument */
	if (gettokens(tok) !=1)
		FPDEBUG_ERRX("find: too few arguments");

	token = chargv[0];

	FPN_STAILQ_FOREACH(cmd, &cli_commands, next) {
		unsigned int j;

		for (j = 0; cmd->c[j].name; j++) {
			if ((strstr(cmd->c[j].name, token) != NULL)) {
				fpdebug_printf("%s: %s\n", cmd->c[j].name, cmd->c[j].help);
			}
		}
	}

end:
	return 0;
}

CLI_COMMAND *search_command (char *name)
{
	unsigned int len;
	unsigned int ambiguous = 0;
	cli_cmds_t *cmd;
	CLI_COMMAND *candidate = NULL;

	len = strlen(name);

	FPN_STAILQ_FOREACH(cmd, &cli_commands, next) {
		unsigned int j;

		for (j = 0; cmd->c[j].name; j++) {
			if (!strncmp(cmd->c[j].name, name, len)) {
				/* exact match */
				if (cmd->c[j].name[len] == 0)
					return &cmd->c[j];
				/* 'name' matches beginning of command */
				if (candidate != NULL) {
					ambiguous = 1;
					continue;
				}
				candidate = &cmd->c[j];
			}
		}
	}

	if (ambiguous) {
		fpdebug_printf("Ambiguous command name '%s'\n", name);
		return NULL;
	}

	if (candidate == NULL)
		fpdebug_printf("Command '%s' not found\n", name);

	return candidate;
}

int fpdebug_run_command(char *cli_input)
{
	int ret = 0;
	CLI_COMMAND *command;

	char *cmd, *args, *next;

	next = cli_input;

	/* skip leading spaces */
	while (isspace (*next))
		next++;

	/* a line starting with ';' is a comment */
	if (*next == ';')
		return 0;

	do {
		/* point on next command */
		cmd = next;

		/*
		 * ';' in the middle of a line separates several commands
		 * find possible next command if ';' separator is found
		 */
		next = strchr(cmd, ';');
		if (next)
			*next++ = '\0';

		/* skip spaces before command name */
		while (isspace (*cmd))
			cmd++;

		/* find end of command name */
		cur_command = strdup(cmd);
		if (cur_command == NULL) {
			fpdebug_printf("Not enough memory\n");
			return -1;
		}

		args = cmd;
		while (*args && !isspace (*args))
			args++;

		if (*args)
			*args++ = '\0';

		if (*cmd == '\0') {
			free(cur_command);
			continue;
		}

		/* search in list of commands */
		command = search_command(cmd);
		if (!command) {
			free(cur_command);
			return (-1);
		}

		/* skip spaces before command arguments */
		while (isspace (*args))
			args++;

		ret = (command->func)(args);

	} while (ret == 0 && next);

	return ret;
}

static char *
stripwhite(char *string)
{
	register char *s, *t;
	for (s = string; isspace (*s); s++)
		;
	if (*s == 0)
		return (s);
	t = s + strlen (s) - 1;
	while (t > s && isspace (*t))
		t--;
	*++t = '\0';
	return s;
}

void fpdebug_prompt(void)
{
	fpdebug_prompt_reset();
	fpdebug_printf("%s", prompt);
	fflush(stdout);
}

static char *fpdebug_getline(FILE *f)
{
	size_t off = 0;
	size_t size = 64;
	char *line = NULL;
	char *buf;

	while ((buf = realloc(line, size)) != NULL) {
		line = buf;
		if (fgets(&line[off], (size - off), f) != NULL)
			off += strlen(&line[off]);
		else if ((feof(f)) || (ferror(f))) {
			if (off != 0)
				return line;
			break;
		}
		if ((off != 0) && (line[off - 1] == '\n'))
			return line;
		size *= 2;
	}
	free(line);
	return NULL;
}

int fpdebug_interact(void)
{
	int res = 0;

	fpdebug_prompt_reset();
	while (res == 0) {
		char *line;

		if (interactive) {
#ifdef HAVE_LIBEDIT
			line = readline(prompt);
#else /* HAVE_LIBEDIT */
			fpdebug_prompt();
			line = fpdebug_getline(stdin);
#endif /* HAVE_LIBEDIT */
		}
		else
			line = fpdebug_getline(stdin);
		if (line == NULL) {
			res = 1;
		} else {
			char *s;;

			s = stripwhite (line);
			if (*s)
			{
#ifdef HAVE_LIBEDIT
				add_history(line);
#endif
				fpdebug_run_command(s);
			}
		}
		free((void*)line);
	}
	return res;
}

int fpdebug_load_config(const char *filename)
{
	FILE *f;
	char linebuf[200];
	char *s;
	int err = 0;

	f = fopen(filename, "r");
	if (f == NULL) {
		printf("cannot open %s: %s\n", filename, strerror(errno));
		return -1;
	}
	while (fgets(linebuf, sizeof(linebuf), f) != NULL) {
		s = stripwhite(linebuf);
		if (*s != '\0') {
			fpdebug_printf("-> %s\n", s);
#ifdef HAVE_LIBEDIT
			add_history(linebuf);
#endif
			err |= fpdebug_run_command(s);
		}
	}
	fclose(f);

	return err;
}

#if !defined(__FastPath__) && defined(CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY)
struct plugin_elt {
	FPN_STAILQ_ENTRY(plugin_elt) next;
	char *filename;
	void *handle;
};
FPN_STAILQ_HEAD(plugin_list, plugin_elt);
static struct plugin_list plugin_list =
	FPN_STAILQ_HEAD_INITIALIZER(plugin_list);
#endif

void fpdebug_init(void)
{
#if !defined(__FastPath__) && defined(CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY)
	struct plugin_elt *plugin;
	unsigned int i;
#endif

#ifdef HAVE_LIBEDIT
	rl_initialize();
	using_history();
	stifle_history(20);
#endif

#ifndef __FastPath__
	fp_shared = (shared_mem_t *)get_fp_shared();
	if (fp_shared == NULL) {
		fpdebug_fprintf(stderr, "Failed to open shared memory\n");
		exit(1);
	}

	/* no need to check for fpn_port_shmem, some arch have none */
	fpn_port_shmem = fpn_port_mmap();

	s_nfpc = netfpc_open(NULL);
	if (s_nfpc < 0)
		fpdebug_fprintf(stderr, "WARNING: could not create netfpc socket\n");	
#ifdef CONFIG_MCORE_IPSEC
	/* In case of fpdebug termination, rebuild index to permit creation of
	   other SA and SP */
	fp_ipsec_index_rebuild();
#endif

#ifdef CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY
	for (i=0; i<FP_MAX_PLUGINS; i++)
		memset(fp_shared->fpcliplugins[i], 0, FP_PLUGINSNAME_MAXLEN);

	i = 0;
	FPN_STAILQ_FOREACH(plugin, &plugin_list, next) {
		plugin->handle = dlopen(plugin->filename, RTLD_NOW | RTLD_GLOBAL);
		if (plugin->handle == NULL) {
			fpdebug_fprintf(stderr, "cannot load %s: %s\n",
			                plugin->filename, dlerror());
			exit(1);
		}
		if (i<FP_MAX_PLUGINS)
			memcpy(fp_shared->fpcliplugins[i], plugin->filename,
			       FP_PLUGINSNAME_MAXLEN - 1);
		else
			fpdebug_fprintf(stderr,
			                "WARNING: %s plugin not stored for fpcmd show-loaded-plugins\n",
			                plugin->filename);
		i++;
		if (verbose)
			fpdebug_printf("plugin %s loaded\n", plugin->filename);
	}
#endif

#else
	/* we will use fp_shared exported by fast path. There is no
	 * netfpc */
#ifdef FP_STANDALONE
#ifdef CONFIG_MCORE_IPSEC
	 fp_ipsec_index_init();
#endif /* CONFIG_MCORE_IPSEC */
#endif /* FP_STANDALONE */
#endif /* __FastPath__ */
}

#ifndef __FastPath__
static void
usage(const char *prgname)
{
	fpdebug_fprintf(stderr, "%s [-h] ", prgname);
#ifdef CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY
	fpdebug_fprintf(stderr, "[-p plugin] ");
	fpdebug_fprintf(stderr, "[-v] ");
#endif
	fpdebug_fprintf(stderr, "[--] [commands]\n\n");
#ifdef CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY
	fpdebug_fprintf(stderr, "   -p plugin     : specify plugins to be loaded during init\n");
	fpdebug_fprintf(stderr, "   -v            : verbose output\n");
#endif
}

#ifdef CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY
static int
add_plugin(char *filename)
{
	struct plugin_elt *plugin = malloc(sizeof(*plugin));

	if (plugin == NULL) {
		fprintf(stderr, "cannot alloc plugin elt\n");
		return -1;
	}
	plugin->filename = strdup(filename);
	if (plugin->filename == NULL) {
		fprintf(stderr, "cannot alloc plugin name\n");
		free(plugin);
		return -1;
	}
	FPN_STAILQ_INSERT_TAIL(&plugin_list, plugin, next);
	return 0;
}
#endif

static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "hp:v", NULL, NULL)) != EOF) {

		switch (opt) {

#ifdef CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY
		/* plugins */
		case 'p':
		{
			glob_t gl;
			unsigned int i;

			/* use quotes so that shell won't try to expand * */
			if (optarg[0] == '\'' &&
			    optarg[strlen(optarg)-1] == '\'') {
				optarg[strlen(optarg)-1] = '\0';
				optarg++;
			}

			if (glob(optarg, 0, NULL, &gl)) {
				if (add_plugin(optarg) < 0)
					exit(1);
				continue;
			}

			for (i = 0; i < gl.gl_pathc; i++) {
				if (add_plugin(gl.gl_pathv[i]) < 0)
					exit(1);
			}

			globfree(&gl);
		}
			break;

		case 'v':
			verbose++;
			break;
#endif

		case 'h':
			usage(prgname);
			exit(0);

		default:
			usage(prgname);
			exit(1);
		}
	}

	if (optind > 0)
		argv[optind-1] = prgname;

	ret = optind - 1;
	optind = 0; /* reset getopt lib */
	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	ret = parse_args(argc, argv);
	if (ret < 0)
		return -1;
	argc -= ret;
	argv += ret;

#ifdef CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY
	if (FPN_STAILQ_EMPTY(&plugin_list)) {
		char *pattern;
		glob_t gl;

		if (!(pattern = getenv("FP_CLI_PLUGINS")))
			pattern = DEFAULT_FP_CLI_PLUGINS;

		if (!glob(pattern, 0, NULL, &gl)) {
			unsigned int i;

			for (i = 0; i < gl.gl_pathc; i++) {
				if (add_plugin(gl.gl_pathv[i]) < 0)
					return -1;
			}

			globfree(&gl);
		}
	}
#endif
	fpdebug_init();
	/* Not interactive when command-line arguments are provided. */
	if (argc > 1) {
		int i;
		size_t size = 0;
		size_t argv_len[argc];

		interactive = 0;

		/* Generate a single command from argv[]. */
		for (i = 1; (i < argc); ++i) {
			argv[i] = stripwhite(argv[i]);
			argv_len[i] = strlen(argv[i]);
			size += (argv_len[i] + 1);
		}
		if (size == 0)
			return 1;

		char line[size];

		size = 0;
		for (i = 1; (i < argc); ++i) {
			strncpy(&line[size], argv[i], argv_len[i]);
			size += argv_len[i];
			line[size] = ' ';
			++size;
		}
		line[size - 1] = '\0';
		return !!fpdebug_run_command(line);
	}
	/* Disable interactve mode if stdin is not a tty */
	if (!isatty(0))
		interactive = 0;
	return !!fpdebug_interact();
}
#endif
