/*
 * Copyright (c) 2009  6WIND
 */
#ifndef _FP_RFPS_PROTO_H_
#define _FP_RFPS_PROTO_H_

/*
 * RFPS (Remote Fast Path Statistics) protocol
 */

/*
 * First byte (8 bits) of RFPS Initial Version (0) Header:
 *   - protocol version      (1 bit)
 *   - sender byte order     (1 bit)
 *   - forward flag          (1 bit)
 *   - statistics identifier (5 bits)
 *
 *      protocol byte   forward                statistics
 *      version  order   flag                  identifier
 *         |        |      |                       |
 *         |        |      |                       |
 *         |        |      |                       |
 *         V        V      V                       V
 *     |       |       |       |                                       |
 *     |_______|_______|_______|_______|_______|_______|_______|_______|
 *
 */

#define RFPS_VERSION_MASK      0x80 /* at most 2 RFPS protocol versions */
#define RFPS_VERSION_SHIFT     7

#define RFPS_HDR_PROTO_VERSION(hdr_flags) \
	(((hdr_flags) & RFPS_VERSION_MASK) >> RFPS_VERSION_SHIFT)

#define RFPS_BIG_ENDIAN      1
#define RFPS_LITTLE_ENDIAN   0

#define RFPS_IP_STATS        0x00 /* IPv4 and IPv6 statistics */
#define RFPS_IF_STATS        0x01 /* Network Interfaces statistics */
#define RFPS_SA_STATS        0x02 /* Ipsec SA statistics */
#define RFPS_SA6_STATS       0x03 /* IPv6 Ipsec SA statistics */

#define RFPS_INITIAL_VERSION 0

    /*
     * Initial RFPS Protocol Version Header
     */
#define RFPS_V0_BYTE_ORDER_MASK   0x40
#define RFPS_V0_BYTE_ORDER_SHIFT  6

#define RFPS_V0_FORWARD_MSG       1
#define RFPS_V0_FORWARD_MSG_MASK  0x20
#define RFPS_V0_FORWARD_MSG_SHIFT 5

#define RFPS_V0_STATS_ID_MAX      0x1F /* 32 stats max in RFPS V0 */
#define RFPS_V0_STATS_ID_MASK     0x1F

#define RFPS_V0_HDR_BYTE_ORDER(v0_flags) \
	(((v0_flags) & RFPS_V0_BYTE_ORDER_MASK) >> RFPS_V0_BYTE_ORDER_SHIFT)

#define RFPS_V0_HDR_FORWARD_FLAG(v0_flags) \
	(((v0_flags) & RFPS_V0_FORWARD_MSG_MASK) >> RFPS_V0_FORWARD_MSG_SHIFT)

#define RFPS_V0_HDR_STATS_ID(v0_flags) \
	((v0_flags) & RFPS_V0_STATS_ID_MASK)

typedef struct {
	uint8_t  vbof_statid; /* version, byte order, forward flag, stat id. */
	uint8_t  src_bladeid; /* sender blade identifier */
	uint16_t nb_stats;    /* number of statistics entries in msg. */
} __attribute__((packed)) rfps_v0_hdr_t;

    /*
     * RFPS Statistics Entries
     */

/* RFPS IPv4 and IPv6 statistics */
typedef struct {
	/* This structure contains only fields used by
	 * the control plane.
	 */
	uint64_t    IpForwDatagrams;
	uint64_t    IpInDelivers;
	uint64_t    IpReasmReqds;
	uint64_t    IpReasmOKs;
	uint64_t    IpReasmFails;
	uint64_t    IpFragOKs;
	uint64_t    IpFragFails;
	uint64_t    IpFragCreates;
	uint32_t    IpInHdrErrors;
	uint32_t    IpInAddrErrors;
	uint32_t    IpReasmTimeout;
} __attribute__((packed)) rfps_ip_stats_t;

/* RFPS Network Interface statistics */
typedef struct {
	/* This structure contains only fields used by
	 * the control plane.
	 */
	uint64_t    ifs_ipackets;    /* packets received on interface */
	uint64_t    ifs_ibytes;      /* total number of octets received */
	uint64_t    ifs_opackets;    /* packets sent on interface */
	uint64_t    ifs_obytes;      /* total number of octets sent */
	uint32_t    ifs_ierrors;     /* input errors on interface */
	uint32_t    ifs_imcasts;     /* packets received via multicast */
	uint32_t    ifs_oerrors;     /* output errors on interface */
	uint32_t    ifs_idropped;    /* input packets dropped on interface */
	uint32_t    ifs_odropped;    /* output packets dropped on interface */
	uint32_t    ifs_ififoerrors; /* input fifo errors on interface */
	uint32_t    ifs_ofifoerrors; /* output fifo errors on interface */
	uint32_t    ifs_ifuid;
} __attribute__((packed)) rfps_if_stats_t;

#ifdef CONFIG_MCORE_IPSEC
/* RFPS IPsec SA statistics */
typedef struct {
	/* This structure contains only fields used by
	 * the control plane.
	 */
	uint64_t    sa_packets;            /* packets */
	uint64_t    sa_bytes;              /* bytes */
	uint64_t    sa_auth_errors;
	uint64_t    sa_decrypt_errors;     /* decrypt errors */

	/* xfrm identity */
	uint32_t    spi;
	uint16_t    vrfid;
	uint8_t     family;
	uint8_t     proto;
	uint32_t    daddr[4]; /* NETWORK order for V4 and V6*/
} __attribute__((packed)) rfps_sa_stats_t;
#endif /* CONFIG_MCORE_IPSEC */

#endif /* _FP_RFPS_PROTO_H_ */
