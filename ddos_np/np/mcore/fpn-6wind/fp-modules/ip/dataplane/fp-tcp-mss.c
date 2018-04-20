/*
 * Copyright(c) 2010 6WIND
 */

#include "fpn.h"
#include "fp-includes.h"
#include "fp-tcp-mss.h"

#include "fpn-cksum.h"
#include "netinet/fp-tcp.h"

#ifdef CONFIG_MCORE_IPV6
/*
 * skip this packet's all extended next-header,
 * return offset of first non-extended packets header by ipv6 header
 *
 * Return value:
 * --------------------
 *     -1 : can't parse next-header
 * offset : function works OK
 *
 * nexthdr:
 * 	the next header value
 * first_frag:
 * 	1, if it's not a fragmented packets, or 1st fragment if it's a fragemented
 * 	0, if it's a fragment, but not the 1st fragment
 *
 */
static int fp_ipv6_skip_exthdr(struct mbuf *m, unsigned char *ret_nexthdr, int *first_frag)
{
	struct fp_ip6_hdr *ip6;
	struct fp_ip6_ext exthdr;
	uint32_t offset;
	uint8_t nexthdr;

	if (first_frag)
		*first_frag = 1;

	ip6	= mtod(m, struct fp_ip6_hdr *);
	nexthdr = ip6->ip6_nxt;
	offset  = sizeof(struct fp_ip6_hdr);

	while (ip6_ext_hdr(nexthdr)) {
		if (nexthdr == FP_IPPROTO_NONE)
			return -1;
		if (m_copytobuf(&exthdr, m, offset, sizeof(struct fp_ip6_ext)) !=
			    sizeof(struct fp_ip6_ext))
				return -1;

		if (nexthdr == FP_IPPROTO_FRAGMENT) {
			struct fp_ip6_frag fh;
			uint16_t fragoff;

			if (m_copytobuf(&fh, m, offset, sizeof(struct fp_ip6_frag)) !=
				    sizeof(struct fp_ip6_frag))
					return -1;

			if (fh.ip6f_nxt == FP_IPPROTO_NONE)
					return -1;

			fragoff = ntohs(fh.ip6f_offlg);
			if (fragoff & FP_IP6F_OFF_MASK) {
				if (ip6_ext_hdr(fh.ip6f_nxt))
					return -1;
				if (first_frag)
					*first_frag = 0;
			}
			offset += 8;

		} else if (nexthdr == FP_IPPROTO_AH)
			offset += (exthdr.ip6e_len + 2) << 2;
		else
	                offset += fp_ipv6_optlen(&exthdr);

		nexthdr = exthdr.ip6e_nxt;
	}

	if (ret_nexthdr)
		*ret_nexthdr = nexthdr;
	return offset;
}
#endif /* CONFIG_MCORE_IPV6 */

/*
 * check whether a IPv4/v6 packet is a TCP SYN
 * If so, return tcp header offset
 * else,  return 0
 *
 * Must be called in Layer3
 */
static inline unsigned int tcpsyn_packet(struct mbuf *m, int family)
{
	struct fp_ip *iph;
	struct fp_tcphdr *th;
#ifdef CONFIG_MCORE_IPV6
	struct fp_ip6_hdr *ip6h;
	uint8_t nexthdr;
	int thoff;
	int first_frag;
#endif

	switch (family) {
	case AF_INET:
		iph = mtod(m, struct fp_ip *);
		if ((ntohs(iph->ip_off) & FP_IP_OFFMASK) == 0 &&
			iph->ip_p == FP_IPPROTO_TCP &&
			m_len(m) >= (iph->ip_hl<<2) + sizeof(struct fp_tcphdr)) {
				th = (struct fp_tcphdr *)((char *)iph + (iph->ip_hl<<2));
				if ((int)m_len(m) >= (iph->ip_hl<<2) + (th->th_off<<2) && (th->th_flags & TH_SYN)) {
					return iph->ip_hl << 2;
				}
		}
		break;

#ifdef CONFIG_MCORE_IPV6
	case AF_INET6:
		ip6h = mtod(m, struct fp_ip6_hdr *);
		nexthdr = ip6h->ip6_nxt;

		/* skip all extension header */
		thoff = fp_ipv6_skip_exthdr(m, &nexthdr, &first_frag);
		if (thoff < 0 || first_frag == 0 || nexthdr != FP_IPPROTO_TCP)
			return 0;

		if (m_len(m) >= thoff +sizeof(struct fp_tcphdr)) { 
			th = (struct fp_tcphdr *)((char *)ip6h + thoff);
			if ((int)m_len(m) >= thoff + (th->th_off << 2) && (th->th_flags & TH_SYN))
				return thoff;
		}
		break;
#endif
	default:
		break;
	}
	return 0;
}

/*
 * fp_update_tcpmss_by_dev(...):
 * update tcp syn packet's MSS value by device's tcp4mss|tcp6mss
 *
 * We assume that:
 * 1) call place should be in Layer3(i.e. skb_network_header(skb) should be valid)
 * 2) IP header & TCP header must be checked before calling this function
 *
 * Mangle TCP MSS by device MSS setting:
 * 1.Only mangle SYN packets
 * 2.Only update MSS option if it exist (We don't try to add a New MSS Option if not exist)
 *
 * Return:
 *  0: packet's mss has been updated, or nothing was done (not a TCP syn packet)
 * -1: error, packet was freed
 */
#define TCPMSS_CLAMP_PMTU 0xFFFF
int fp_update_tcpmss_by_dev(struct mbuf *m, fp_ifnet_t *ifp, unsigned int family)
{
	unsigned char *iph = mtod(m, unsigned char *);
	struct fp_tcphdr *th;
	unsigned int minlen;
	unsigned int oldmss, newmss;
	unsigned char *opt;
	int i;
	unsigned int thoff;

	if (ifp == NULL)
		return 0;

	thoff = tcpsyn_packet(m, family);

	if (thoff == 0)
		return 0;

	th = (struct fp_tcphdr *)(iph + thoff);
	if (th->th_flags & TH_SYN) {
		switch (family) {
		case AF_INET:
			minlen = sizeof(struct fp_ip) + sizeof(struct fp_tcphdr);
			break;
#ifdef CONFIG_MCORE_IPV6
		case AF_INET6:
			minlen = sizeof(struct fp_ip6_hdr) + sizeof(struct fp_tcphdr);
			break;
#endif

		default:
			return 0;
		}

		opt = (unsigned char *)th;
		for (i = sizeof(struct fp_tcphdr); i < th->th_off * 4; ) {
			if (opt[i] == FP_TCPOPT_MSS &&
			 	th->th_off * 4 - i >= FP_TCPOLEN_MSS && opt[i+1] == FP_TCPOLEN_MSS) {
				oldmss = opt[i+2] << 8 | opt[i+3];
				newmss = (family == AF_INET) ?  ifp->if_tcp4mss : ifp->if_tcp6mss;
				/*Only mangle those packets with bigger MSS*/
				if (newmss == TCPMSS_CLAMP_PMTU) {
					if (ifp->if_mtu > minlen) {
						newmss =  ifp->if_mtu - minlen;
					} else {
						/* we do nothing: we will not overwrite to a 0 MSS*/
						return 0;
					}
				}

				if (newmss && newmss < oldmss) {
					/* Need do nothing for make packet writable*/
					opt[i+2] = (newmss >> 8) & 0xff;
					opt[i+3] = newmss & 0xff;

					th->th_sum = fpn_cksum_replace2(th->th_sum, htons(oldmss), htons(newmss), i&1);
					return 0;
				}
				break;
			}
			if(opt[i] <= FP_TCPOPT_NOP || opt[i+1] == 0)
				i += 1;
			else
				i += opt[i+1];
		}
	}
	return 0;
}
