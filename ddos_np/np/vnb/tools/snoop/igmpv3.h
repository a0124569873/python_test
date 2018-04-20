/*
 * Copyright 2006-2013 6WIND S.A.
 */

#ifndef IGMPV3_H
#define IGMPV3_H

#include "igmp.h"


#ifdef __linux__
struct igmpv3_hdr {
	struct igmphdr hdr;
        struct in_addr igmp_addr;
	u_int8_t igmp_rtval;              /* Resv+S+QRV */
	u_int8_t igmp_qqi;                /* QQIC */
	u_int16_t igmp_numsrc;             /* Number of Sources */
	struct in6_addr igmp_src[0];             /* Sources Addresses List */
}  __attribute__ ((__packed__));

#define igmp_type hdr.type
#define igmp_code hdr.code
#define igmp_csum hdr.csum
#define igmp_maxdelay hdr.code
#endif

#define SFLAGYES                0x08
#define SFLAGNO                 0x0

int igmp_send_query(struct sockaddr_in *src,
                struct sockaddr_in *dst, struct sockaddr_in *group,
                int index, unsigned int delay, int alert,
                int sflag, int qrv, int qqic, int gss, int version);
#endif
