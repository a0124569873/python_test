/*
 * Copyright(c) 2007  6WIND
 */
#ifndef __FPN_IP_H__
#define __FPN_IP_H__

/*
 * Structure of an internet header, naked of options.
 */
struct fpn_ip_hdr {
#if FPN_BYTE_ORDER == FPN_LITTLE_ENDIAN
	uint8_t  ip_hl:4, /* header length */
	         ip_v :4; /* version */
#elif FPN_BYTE_ORDER == FPN_BIG_ENDIAN
	uint8_t  ip_v :4, /* version */
	         ip_hl:4; /* header length */
#else
#error Please define FPN_BYTE_ORDER
#endif
	uint8_t  ip_tos;  /* type of service */
	uint16_t ip_len;  /* total length */
	uint16_t ip_id;   /* identification */
	uint16_t ip_off;  /* fragment offset field */
#define	FPN_IP_RF 0x8000 /* reserved fragment flag */
#define	FPN_IP_DF 0x4000 /* dont fragment flag */
#define	FPN_IP_MF 0x2000 /* more fragments flag */
#define	FPN_IP_OFFMASK 0x1fff /* mask for fragmenting bits */
	uint8_t  ip_ttl;  /* time to live */
	uint8_t  ip_p;    /* protocol */
	uint16_t ip_sum;  /* checksum */
	uint32_t ip_src;  /* source */
	uint32_t ip_dst;  /* destination */
} __attribute__ ((packed));

#define FPN_IPVERSION    4
#define	FPN_IP_MAXPACKET 65535 /* maximum packet size */

/*
 * Internet implementation parameters.
 */
#define	FPN_MAXTTL     255 /* maximum time to live (seconds) */
#define	FPN_IPDEFTTL    64 /* default ttl, from RFC 1340 */
#define	FPN_IPFRAGTTL   60 /* time to live for frags, slowhz */
#define	FPN_IPTTLDEC     1 /* subtracted when forwarding */

#endif
