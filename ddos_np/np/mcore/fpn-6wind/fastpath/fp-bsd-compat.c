/*
 * Copyright(c) 2011 6WIND, all rights reserved
 */

#include "fpn.h"
#include "netinet/fp-in.h"
#include "fp-bsd-compat.h"

/* Similar to inet_ntoa() */
char *
fp_intoa(u_int32_t addr)
{
	char *cp;
	u_int byte;
	int n;
	static char buf[17];	/* strlen(".255.255.255.255") + 1 */

	addr = ntohl(addr);
	cp = &buf[sizeof buf];
	*--cp = '\0';

	n = 4;
	do {
		byte = addr & 0xff;
		*--cp = byte % 10 + '0';
		byte /= 10;
		if (byte > 0) {
			*--cp = byte % 10 + '0';
			byte /= 10;
			if (byte > 0)
				*--cp = byte + '0';
		}
		*--cp = '.';
		addr >>= 8;
	} while (--n > 0);

	return (cp+1);
}

const char hexdigits[] = "0123456789abcdef";
static FPN_DEFINE_PER_CORE(int, ip6round) = 0;
static FPN_DEFINE_PER_CORE(char [8][48], ip6buf);
/* Similar to inet_ntop6() */
char *
fp_ip6_sprintf(const struct fp_in6_addr *addr)
{
	int i;
	char *cp;
	const u_int16_t *a = (const u_int16_t *)addr;
	const u_int8_t *d;
	int dcolon = 0;

	FPN_PER_CORE_VAR(ip6round) = (FPN_PER_CORE_VAR(ip6round) + 1) & 7;
	cp = FPN_PER_CORE_VAR(ip6buf)[FPN_PER_CORE_VAR(ip6round)];

	for (i = 0; i < 8; i++) {
		if (dcolon == 1) {
			if (*a == 0) {
				if (i == 7)
					*cp++ = ':';
				a++;
				continue;
			} else
				dcolon = 2;
		}
		if (*a == 0) {
			if (dcolon == 0 && *(a + 1) == 0) {
				if (i == 0)
					*cp++ = ':';
				*cp++ = ':';
				dcolon = 1;
			} else {
				*cp++ = '0';
				*cp++ = ':';
			}
			a++;
			continue;
		}
		d = (const u_char *)a;
		*cp++ = hexdigits[*d >> 4];
		*cp++ = hexdigits[*d++ & 0xf];
		*cp++ = hexdigits[*d >> 4];
		*cp++ = hexdigits[*d & 0xf];
		*cp++ = ':';
		a++;
	}
	*--cp = 0;
	return FPN_PER_CORE_VAR(ip6buf)[FPN_PER_CORE_VAR(ip6round)];

}


/* strl* functions exist in fp-mcee with newlib */
#if !defined(_NEWLIB_VERSION)
/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
size_t
strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));       /* count does not include NUL */
}
#endif

/*
 * ppsratecheck(): packets (or events) per second limitation (per-core).
 */
int
ppsratecheck(uint64_t *lasttime, uint64_t min_interval)
{
	uint64_t cycles, delta;

	cycles = fpn_get_local_cycles();

	delta = cycles - *lasttime;
	if (delta < min_interval)
		return 0;

	*lasttime = cycles;
	return 1;
}
