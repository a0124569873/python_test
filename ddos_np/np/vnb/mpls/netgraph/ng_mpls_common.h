/*
 * Copyright 2011 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_MPLS_COMMON_H_
#define _NETGRAPH_NG_MPLS_COMMON_H_

union mpls_header {
	uint32_t header;
	struct {
#if VNB_BYTE_ORDER == VNB_LITTLE_ENDIAN
		uint32_t	mhttl:8;	/* TTL             */
		uint32_t	mhbs:1;		/* bit stack       */
		uint32_t	mhexp:3;	/* Exp bits        */
		uint32_t	mhtag:20;	/* label           */
#elif VNB_BYTE_ORDER == VNB_BIG_ENDIAN
		uint32_t	mhtag:20;	/* label           */
		uint32_t	mhexp:3;	/* 0..8 : Exp bits */
		uint32_t	mhbs:1;		/* 1 bit stack     */
		uint32_t	mhttl:8;	/* Time To Live    */
#else
#error VNB_BYTE_ORDER is not defined properly
#endif
	} mpls_header;
#define mhttl mpls_header.mhttl
#define mhexp mpls_header.mhexp
#define mhbs  mpls_header.mhbs
#define mhtag mpls_header.mhtag
};

typedef union mpls_header mpls_header_t;

/* MPLS OAM Stuff */

/* pre-defined constant UDP ports */
#define LSP_PING_PORT	3503
#define BFD_PORT	3784

/* resources for saving the starting MPLS headers */
#define NG_MPLS_SAVED_WORDS	2
#if defined(__FastPath__)
FPN_DECLARE_PER_CORE(uint64_t, mpls_saved_stack[NG_MPLS_SAVED_WORDS]);
FPN_DECLARE_PER_CORE(char, mpls_input_iface[NG_NODESIZ]);
#endif

/* IPv4 and IPv6-related macros */
#define ip6_hdr 		vnb_ip6_hdr
#define MPLS_MTODV4(m)		mtod(m, struct vnb_ip *)
#define MPLS_IS_IPV4(iphdr) 	(iphdr->ip_v == VNB_IPVERSION)
#define MPLS_IP_TTL(iphdr)	iphdr->ip_ttl
#define MPLS_IS_IPV6(ip6hdr)	(ip6hdr->ip6_ctlun.ip6_s.ip6_un2_v == 6)
#define MPLS_IP_HLIM(ip6hdr)	ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim
#define MPLS_IP_CSUM(iphdr)	iphdr->ip_sum
#define MPLS_IS_UDP4(iphdr)	(iphdr->ip_p == VNB_IPPROTO_UDP)
#define MPLS_IP_HLEN(iphdr)	iphdr->ip_hl

/*************************************************************
 * Constants and definitions specific to MPLS
 *************************************************************/

#define NG_MPLS_NHLFE_MAX_TAG		1048576	/* 2^20 */
#define NG_MPLS_HEADER_ENCAPLEN		4	/* Length in bytes of
						 * encapsulation */
#define NG_MPLS_TTLDEC			1	/* Substtracted when forwarding */

#define NG_MPLS_CONFIRMATION_LSP_PING   1
#define NG_MPLS_CONFIRMATION_BFD        2

#if defined(__LinuxKernelVNB__) || defined(__FastPath__)
static __inline int check_lspping_format(struct vnb_ip *iphdr)
{
	struct vnb_udphdr *udphdr;
	int confirmation_lsp=0;

	/* if existing IP ttl <= 1 : send to OAM */
	confirmation_lsp = MPLS_IP_TTL(iphdr) <= NG_MPLS_TTLDEC;

	/* IP header Router Alert Check */
	confirmation_lsp |= (MPLS_IP_HLEN(iphdr) != 5);

	/* dsp IP == 127/8 */
	confirmation_lsp |= ((iphdr->ip_dst.s_addr & htonl(VNB_IN_CLASSA_NET))
			     == htonl(VNB_INADDR_LOOPBACK & VNB_IN_CLASSA_NET));

	/*
	 * An LSP ping req is defined by one of the above conditions and:
	 *   request : dst port == 3503
	 *   reply : src port == 3503
	 * A BFD packet is defined by one of the above conditions and
	 * UDP dst port == 3784
	 */
	udphdr = (struct vnb_udphdr *) ((void*)iphdr + MPLS_IP_HLEN(iphdr)*sizeof(uint32_t));
	confirmation_lsp &=
			(udphdr->uh_dport == ntohs(LSP_PING_PORT)) ||
			(udphdr->uh_dport == ntohs(BFD_PORT)) ||
			(udphdr->uh_sport == ntohs(LSP_PING_PORT));

	if (likely(confirmation_lsp))
		return (udphdr->uh_dport == ntohs(BFD_PORT)) ?
			NG_MPLS_CONFIRMATION_BFD : NG_MPLS_CONFIRMATION_LSP_PING;
	else
		return 0;
}
#endif /*defined(__LinuxKernelVNB__) || defined(__FastPath__)*/

#endif
