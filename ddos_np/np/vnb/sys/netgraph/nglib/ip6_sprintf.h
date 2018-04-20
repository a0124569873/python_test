/*
 * Copyright 2004-2010 6WIND S.A.
 */

#ifndef _NG_IP6_SPRINTF_H_
#define _NG_IP6_SPRINTF_H_
/*
 * Convert IP6 address to printable (loggable) representation.
 */
static const char digits[] = "0123456789abcdef";
static char *ip6_sprintf(const void *addr)
{
        static char ip6buf[8][48];
        static int ip6round = 0;
        int i;
        char *cp;
        u_short *a = (u_short *)addr;
        u_char *d;
        int dcolon = 0;

        ip6round = (ip6round + 1) & 7;
        cp = ip6buf[ip6round];

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
                d = (u_char *)a;
                *cp++ = digits[*d >> 4];
                *cp++ = digits[*d++ & 0xf];
                *cp++ = digits[*d >> 4];
                *cp++ = digits[*d & 0xf];
                *cp++ = ':';
                a++;
        }
        *--cp = 0;
        return(ip6buf[ip6round]);
}

#endif
