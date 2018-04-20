/*
 * Copyright 2007-2012 6WIND S.A.
 */
#ifndef __NETLINK_H__
#define __NETLINK_H__

/* Max bit/byte length of IPv4 address. */
#define IPV4_MAX_BYTELEN    4
#define IPV4_MAX_BITLEN    32
#define IPV4_MAX_PREFIXLEN 32

/* Max bit/byte length of IPv6 address. */
#define IPV6_MAX_BYTELEN    16
#define IPV6_MAX_BITLEN    128
#define IPV6_MAX_PREFIXLEN 128

#define MASK_TO_MASKLEN(mask, masklen)                           \
    do { \
        register u_int32_t tmp_mask = ntohl((mask)); \
        register u_int8_t  tmp_masklen = sizeof((mask)) << 3; \
        for ( ; tmp_masklen > 0; tmp_masklen--, tmp_mask >>= 1) \
            if (tmp_mask & 0x1) \
                break; \
        (masklen) = tmp_masklen; \
    } while (0)

#define MASK_TO_MASKLEN6(mask , masklen) \
    do { \
        register u_int32_t tmp_mask; \
        register u_int8_t  tmp_masklen = sizeof((mask)) <<3; \
        int i; \
        int kl; \
        for (i = 0; i < 4; i++) { \
            tmp_mask = ntohl(*(u_int32_t *)&mask.s6_addr[i * 4]); \
            for (kl=32; tmp_masklen > 0 && kl > 0; \
                 tmp_masklen--, kl-- , tmp_mask >>= 1) \
                if (tmp_mask & 0x1) \
                    break; \
        } \
        (masklen) = tmp_masklen; \
    } while (0)

extern void netlink_init (void);
extern void config_ifaddr_from_kernel(struct eth_if *ifp);
extern void clear_ifaddr (struct eth_if *ifp);
extern void clear_ifaddr6 (struct eth_if *ifp);

#endif

