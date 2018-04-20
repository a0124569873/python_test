/*
 * Copyright (c) 2006 6WIND
 */

/*
 ***************************************************************
 *
 *                CM IPsec 'Public'
 *
 * $Id: cm_ipsec_pub.h,v 1.10 2008-10-07 15:09:22 gouault Exp $
 ***************************************************************
 */

#ifndef __CM_IPSEC_PUB_H_
#define __CM_IPSEC_PUB_H_

#include <sys/queue.h>

typedef struct cm_ipsec_sa_lifetime_s {
	u_int64_t         nb_bytes;   /* SA bytes limit */
	u_int64_t         nb_packets; /* SA packets limit */
} cm_ipsec_sa_lifetime_t;

/*
 * IPsec SA structure (internal to CM)
 * CM allocates size of this struct + size for crypto keys
 */
struct cm_ipsec_sa
{
	u_int8_t          family;   /* AF_INET or AF_INET6 */
	u_int8_t          proto;   /* IPPROTO_AH or IPPROTO_ESP */
	u_int8_t          state;   /* e.g. dying or dead */
	u_int8_t          mode;    /* tunnel if set, transport if 0 */

	u_int32_t         spi;     /* IPsec SPI */
	cp_ipsec_addr_t   daddr;   /* destination address */
	cp_ipsec_addr_t   saddr;   /* source address */
	u_int32_t         reqid;   /* request ID */

	u_int32_t         vrfid;
	u_int32_t         xvrfid;

	u_int32_t         svti_ifuid; /* SVTI interface ifuid */

	u_int16_t         sport;   /* (optional), used in NAT-traversal mode */
	u_int16_t         dport;   /* (optional), used in NAT-traversal mode */

	u_int64_t         oseq;    /* sent sequence number */
	u_int64_t         seq;     /* received sequence number */
	u_int32_t         bitmap;  /* replay window bitmap */

	u_int32_t         replay;  /* optional replay window size */

	u_int8_t          reserve;
	u_int8_t          ealgo;   /* encryption algorithm */
	u_int8_t          aalgo;   /* authentication algorithm */
	u_int8_t          calgo;   /* compression algorithm (not yet) */

	u_int16_t         ekeylen; /* encryption key length in bytes */
	u_int16_t         akeylen; /* authentication key length in bytes */
	u_int32_t         flags;

	u_int32_t         gap;      /* GAP in output sequence number, for SA Migration purpose */

	u_int8_t          output_blade; /* fast path output blade */

	cm_ipsec_sa_lifetime_t soft; /* SA lifetime soft limits */
	cm_ipsec_sa_lifetime_t hard; /* SA lifetime hard limits */

	u_int8_t          keys[0];   /* cryptographic keys */
};

/*
 * IPsec SP structure (internal to CM)
 */
struct cm_ipsec_sp
{
	u_int32_t         index;    /* rule unique ID */
	u_int32_t         priority; /* rule priority (order in SPD) */

	u_int8_t          family;   /* AF_INET or AF_INET6 */
	u_int8_t          dir;      /* flow direction */
	u_int8_t          proto;     /* L4 protocol */
	u_int8_t          action;   /* destination address prefix length */

	cp_ipsec_addr_t   saddr;   /* source address */
	cp_ipsec_addr_t   daddr;   /* destination address */

	u_int16_t         sport;   /* source port */
	u_int16_t         dport;   /* destination port */
	u_int16_t         sportmask;   /* source port mask */
	u_int16_t         dportmask;   /* destination mask */

	u_int32_t         vrfid;
	u_int32_t         link_vrfid;

	u_int32_t         svti_ifuid; /* SVTI interface ifuid */

	u_int8_t          spfxlen;   /* source address prefix length */
	u_int8_t          dpfxlen;   /* destination address prefix length */
	u_int8_t          xfrm_count;  /* nb of transformations in bundle */
	u_int8_t          reserved2;

	u_int32_t         flags;

	struct cp_ipsec_xfrm xfrm[0];  /* transformations (SA templates) */
};

#endif /* __CM_IPSEC_PUB_H_ */
