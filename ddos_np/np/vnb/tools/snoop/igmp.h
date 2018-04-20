/*
 * Copyright 2006-2013 6WIND S.A.
 */

#ifndef IGMP_H
#define IGMP_H

#define SEND_BUF_SIZE			64
#define IPOPT_RTALERT_LEN               4


extern int igmp_socket;
extern int pim4_socket;

#ifdef __linux__
#include <linux/igmp.h>
struct igmp_hdr {
	struct igmphdr hdr;
}  __attribute__ ((__packed__));
#define igmpv2_hdr igmp_hdr

#define igmp_type hdr.type
#define igmp_code hdr.code
#define igmp_csum hdr.csum
#define igmp_maxdelay hdr.code
#endif

/* igmp.c */
extern void igmp_init(void);
extern void igmp_input (struct eth_if *, int, u_int8_t *, int);
extern void pim4_input (struct eth_if *, int, u_int8_t *, int);
extern int igmp_join_group(struct sockaddr_in *group, int ifindex, int join);
extern int igmp_join_routers_group(int ifindex, int join);
#endif
