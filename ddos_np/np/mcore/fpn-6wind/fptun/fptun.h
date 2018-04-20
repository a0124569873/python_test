/*****************************************************************************
* Copyright 2006 6WIND S.A.  All rights reserved.
*
* Unless you and 6WIND execute a separate written software license
* agreement governing use of this software, this software is licensed to you
* under the terms of the GNU General Public License version 2, available at
* http://www.gnu.org/licenses/gpl-2.0.txt (the "GPL").
*
* Notwithstanding the above, under no circumstances may you combine this
* software in any way with any other 6WIND software provided under a
* license other than the GPL, without 6WIND's express prior written
* consent.
*****************************************************************************/

/* 6WIND_GPL */

#ifndef _FPTUN_H_
#define _FPTUN_H_

#ifdef __KERNEL__
#include <asm/byteorder.h>
#endif

/*
 * FPTUN (Fast Path TUNnelling) protocol
 *
 * note: if you need to modify this value, please also update FPTUN_VERSION
 * in traffic-gen/config/fptrafficgen.py
 */
#define FPTUN_VERSION      4

#define FPTUN_TAG_NAMESIZE 8 /* like SK_TAG_NAMESIZE and M_TAG_NAMESIZE */

struct fptunhdr {
	uint8_t  fptun_cmd;       /* tunneling command */
	uint8_t  fptun_exc_class; /* exception class */
#ifndef __KERNEL__
#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
	uint8_t  fptun_version:4, /* FPTUN version */
	         fptun_mtags:4;   /* mtag number */
#endif
#if FPN_BYTE_ORDER == FPN_LITTLE_ENDIAN
	uint8_t  fptun_mtags:4,   /* mtag number */
	         fptun_version:4; /* FPTUN version */
#endif
#else
#if defined (__BIG_ENDIAN)
	uint8_t  fptun_version:4, /* FPTUN version */
	         fptun_mtags:4;   /* mtag number */
#endif
#if defined (__LITTLE_ENDIAN)
	uint8_t  fptun_mtags:4,   /* mtag number */
	         fptun_version:4; /* FPTUN version */
#endif
#endif
	uint8_t  fptun_blade_id;  /* dst blade_id */
	uint16_t fptun_proto;     /* protocol (ethertype), when needed */
	uint16_t fptun_vrfid;     /* VRF id */
	uint32_t fptun_ifuid;     /* interface unique id */
} __attribute__((packed));

struct fpmtaghdr {
	char     fpmtag_name[FPTUN_TAG_NAMESIZE];
	uint32_t fpmtag_data;
} __attribute__((packed));

struct fpecmphdr {
	uint8_t  ip_v;
	uint8_t  pad[3];
	uint32_t ip_nexthop;
	uint32_t ifuid;
} __attribute__((packed));
#define FPECMP_IPV4 4

struct fpecmp6hdr {
	uint8_t  ip_v;
	uint8_t  pad[3];
	uint8_t ip6_nexthop[16];
	uint32_t ifuid;
} __attribute__((packed));
#define FPECMP_IPV6 6

enum hf_types {
	HF_ARP,
	HF_NDP,
	HF_CT,
	HF_CT6,
};

struct fphitflagshdr {
	uint32_t count;
	uint8_t type;
	uint8_t  pad[3];
} __attribute__((packed));

struct fphitflagsentry {
	uint32_t	src;
	uint32_t	dst;
	uint16_t	sport;
	uint16_t	dport;
	uint16_t	vrfid;
	uint8_t		proto;
	uint8_t		dir;
} __attribute__((packed));

struct fphitflags6entry {
	uint8_t		src[16];
	uint8_t		dst[16];
	uint16_t	sport;
	uint16_t	dport;
	uint16_t	vrfid;
	uint8_t		proto;
	uint8_t		dir;
} __attribute__((packed));

struct fphitflagsarp {
	uint32_t ifuid;
	uint32_t ip_addr;
} __attribute__((packed));

struct fphitflagsndp {
	uint32_t ifuid;
	uint8_t ip6_addr[16];
} __attribute__((packed));

#define FPTUN_HLEN sizeof(struct fptunhdr)

/*
 * ------------------------------------------------------------
 * FPVI messages
 * ------------------------------------------------------------
 */
#define FPTUN_BASIC_EXCEPT              0x00
/*
 * local sending exceptions
 */
/*
 * Inject a packet into the output path of the SP IP stack,
 * before the IPsec processing
 */
#define FPTUN_IPV4_OUTPUT_EXCEPT        0x01
#define FPTUN_IPV6_OUTPUT_EXCEPT        0x02
/*
 * Inject a packet into the input path of the SP IP stack,
 * after the IPsec inbound policy check
 */
#define FPTUN_IPV4_INPUT_EXCEPT         0x03
#define FPTUN_IPV6_INPUT_EXCEPT         0x04
/*
 * Inject a packet into the forward path of the SP IP stack,
 * after the IPsec inbound policy check
 */
#define FPTUN_IPV4_FWD_EXCEPT           0x05
#define FPTUN_IPV6_FWD_EXCEPT           0x06
/*
 * Inject a packet into the output path of the SP IP stack,
 * after the IPsec processing
 */
#define FPTUN_IPV4_IPSECDONE_OUTPUT_EXCEPT        0x07
#define FPTUN_IPV6_IPSECDONE_OUTPUT_EXCEPT        0x08

/* Following commands use blade_id and ifuid as interface identifier */
/* receive an ethernet frame via an ethernet interface */
#define FPTUN_ETH_INPUT_EXCEPT          0x10
/* same as FPTUN_ETH_INPUT_EXCEPT with a bypass of VNB */
#define FPTUN_ETH_NOVNB_INPUT_EXCEPT    0x11
/* receive a L3 packet via an interface (proto field required) */
#define FPTUN_IFACE_INPUT_EXCEPT        0x12
/* Following command uses vrfid to determine input interface */
/* receive an L3 packet via the loopback interface (proto field required) */
#define FPTUN_LOOP_INPUT_EXCEPT         0x14

/* request from FP to SP to send a frame */
#define FPTUN_OUTPUT_EXCEPT             0x20
#define FPTUN_MULTICAST_EXCEPT          0x21
#define FPTUN_MULTICAST6_EXCEPT         0x22

/* request from SP to FP to send an ethernet frame */
#define FPTUN_ETH_SP_OUTPUT_REQ         0x30
/* request from SP to FP to perform IPsec output */
#define FPTUN_IPV4_IPSEC_SP_OUTPUT_REQ  0x31
#define FPTUN_IPV6_IPSEC_SP_OUTPUT_REQ  0x32
/* request from SP to FP to perform IP output */
#define FPTUN_IPV4_SP_OUTPUT_REQ        0x33
#define FPTUN_IPV6_SP_OUTPUT_REQ        0x34

/* request from FP to FP to send an ethernet frame */
#define FPTUN_ETH_FP_OUTPUT_REQ         0x40
/* request from FP to FP to perform IPsec output */
#define FPTUN_IPV4_IPSEC_FP_OUTPUT_REQ  0x41
#define FPTUN_IPV6_IPSEC_FP_OUTPUT_REQ  0x42
/* request from FP to FP to perform IP output */
#define FPTUN_IPV4_FP_OUTPUT_REQ        0x43
#define FPTUN_IPV6_FP_OUTPUT_REQ        0x44

/*
 * ------------------------------------------------------------
 * FPC/FPS messages
 * ------------------------------------------------------------
 */
/* Tapped packet from FP to SP */
#define FPTUN_TAP                      0x60
/* IPv4 replay window messages */
#define FPTUN_IPV4_REPLAYWIN           0x61
/* hitflags synchronization messages */
#define FPTUN_HITFLAGS_SYNC            0x62
/* IPv6 replay window messages */
#define FPTUN_IPV6_REPLAYWIN           0x63
/* Remote Fast Path statistics update messages */
#define FPTUN_RFPS_UPDATE              0x64
/* IPv4 replay window get messages */
#define FPTUN_IPV4_REPLAYWIN_GET       0x65
/* IPv6 replay window get messages */
#define FPTUN_IPV6_REPLAYWIN_GET       0x66
/* IPv4 replay window reply messages */
#define FPTUN_IPV4_REPLAYWIN_REPLY     0x67
/* IPv6 replay window reply messages */
#define FPTUN_IPV6_REPLAYWIN_REPLY     0x68

/*
 * ------------------------------------------------------------
 * VNB to VNB exceptions
 * ------------------------------------------------------------
 */
/* exception from fastpath to Linux */
#define FPTUN_VNB2VNB_FP_TO_LINUX_EXCEPT 0x6A
/* exception from Linux to fastpath */
#define FPTUN_VNB2VNB_LINUX_TO_FP_EXCEPT 0x6B

/*
 * ------------------------------------------------------------
 * TRAFFIC GENERATOR messages
 * ------------------------------------------------------------
 */

#define FPTUN_TRAFFIC_GEN_MSG          0x70

/* max FPTUN type */
#define FPTUN_TYPE_MAX                0X100


/*
 * exception classes
 */
#define FPTUN_EXC_PRIO_MASK      0xC0
#define FPTUN_EXC_PRIO_HIGH      3
#define FPTUN_EXC_PRIO_MED       2
#define FPTUN_EXC_PRIO_LOW       1
#define FPTUN_EXC_PRIO(x)        (((x) & FPTUN_EXC_PRIO_MASK) >> 6)

#define FPTUN_EXC_TARGET_MASK    0x30
#define FPTUN_EXC_TARGET_NORMAL  0x00  /* This MUST be zero */
#define FPTUN_EXC_TARGET_DROP    0x10
#define FPTUN_EXC_TARGET_LOCALCP 0x20
#define FPTUN_EXC_TARGET_LINUX   0x30
#define FPTUN_EXC_TARGET(x)      (((x) & FPTUN_EXC_TARGET_MASK))
#define FPTUN_EXC_SET_TARGET(x, y)  (((x) & ~FPTUN_EXC_TARGET_MASK) | (y))
#define FPTUN_EXC_UNDEF          0 /* not used */

/* slow path interface/route/protocol/IP option */
#define FPTUN_EXC_SP_FUNC        (1 | (FPTUN_EXC_PRIO_HIGH << 6))
/* special ethernet destination (bcast, mcast, other host) */
#define FPTUN_EXC_ETHER_DST      (2 | (FPTUN_EXC_PRIO_LOW << 6))
/* special IP destination (bcast, mcast, reserved) */
#define FPTUN_EXC_IP_DST         (3 | (FPTUN_EXC_PRIO_LOW << 6))
/* ICMP or ICMPv6 message must be sent */
#define FPTUN_EXC_ICMP_NEEDED    (4 | (FPTUN_EXC_PRIO_LOW << 6))
/* Neighbor Discovery (ARP/NDP) needed */
#define FPTUN_EXC_NDISC_NEEDED   (5 | (FPTUN_EXC_PRIO_LOW << 6))
/* IKE negotiation needed */
#define FPTUN_EXC_IKE_NEEDED     (6 | (FPTUN_EXC_PRIO_LOW << 6))
/* Message from remote CP to local FP linux */
#define FPTUN_EXC_FPC            (7 | (FPTUN_EXC_PRIO_LOW << 6))
/* Need to be analyzed by netfilter in kernel */
#define FPTUN_EXC_NF_FUNC        (8 | (FPTUN_EXC_PRIO_LOW << 6))
/* Filtered packets are sent by FP to local linux */
#define FPTUN_EXC_TAP            (9 | (FPTUN_EXC_PRIO_LOW << 6))
/* ipsec replay window sync packet */
#define FPTUN_EXC_REPLAYWIN   (0xA | (FPTUN_EXC_PRIO_LOW << 6))
/* ECMP Neighbor Discovery force needed */
#define FPTUN_EXC_ECMP_NDISC_NEEDED   (0xB | (FPTUN_EXC_PRIO_LOW << 6))
/* VNB to VNB exception */
#define FPTUN_EXC_VNB_TO_VNB   (0xC | (FPTUN_EXC_PRIO_LOW << 6))
/* TCP/UDP socket exception */
#define FPTUN_EXC_SOCKET       (0xD | (FPTUN_EXC_PRIO_LOW << 6))

#define FPTUN_EXC_CLASS_MASK  0x0f
#define FPTUN_EXC_CLASS_MAX   (FPTUN_EXC_CLASS_MASK+1)

#define FPTUN_EXC_CLASS_PRIO_MASK (FPTUN_EXC_CLASS_MASK | FPTUN_EXC_PRIO_MASK)
/* Pseudo ethertype for FPTUN */
#define ETH_P_FPTUN              0x2007

#endif
