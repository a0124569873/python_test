/*
 * Copyright(c) 2009 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-main-process.h"
#include "fp-log.h"
#include "fp-ip6.h"

#include "fp-lookup.h"

#include "netipsec/fp-ah.h"
#include "netipsec/fp-esp.h"
#include "netinet/fp-udp.h"

#include "fp-fpib.h"
#include "fp-ipsec-common.h"
#include "fp-ipsec6-output.h"
#include "fp-ipsec6-lookup.h"
#include "fp-ipsec-replay.h"
#include "fp-ipsec-iv.h"
#include "fpn-crypto.h"
#include "fp-dscp.h"
#include "fp-ipsec-output.h"
#include "fp-ipsec-lookup.h"


#define TRACE_IPSEC6_OUT(level, fmt, args...) do {			\
		FP_LOG(level, IPSEC6_OUT, fmt "\n", ## args);		\
} while(0)

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
#define m_ipsec6(m) m_priv(m)->ipsec.m_ipsec_buf
#define m_ipsec6_sa(m) m_priv(m)->ipsec.sa
#else
static FPN_DEFINE_PER_CORE(struct m_ipsec_state, m_ipsec6_buf_out);
#define m_ipsec6(m) FPN_PER_CORE_VAR(m_ipsec6_buf_out)
static FPN_DEFINE_PER_CORE(void *, local_sa);
#define m_ipsec6_sa(m) FPN_PER_CORE_VAR(local_sa)
#endif

/* Initialize IPsec IV state with random data */
void fp_ipsec6_output_init(void)
{
	fp_shared->ipsec6.output_blade = 0;
}

static inline void init_tunnel6_udp_header(struct fp_udphdr *udp, uint16_t sport,
                                           uint16_t dport) {
	udp->uh_sport = sport;
	udp->uh_dport = dport;
	udp->uh_ulen = 0;
	udp->uh_sum = 0;
}

static int ipsec6_output_finish(struct mbuf *m, struct fp_ip6_hdr *ip6)
{
	fp_rt6_entry_t *rt;
	fp_nh6_entry_t *nh;

#ifdef HAVE_HMAC_COMPLETE
	if (fp_ipsec6_ctx.auth_type == FP_AALGO_HMACSHA1)
		fpn_hmac_sha1_complete_pass1();
	else if (fp_ipsec6_ctx.auth_type == FP_AALGO_HMACSHA256)
		fpn_hmac_sha256_complete_pass1();
	else if (fp_ipsec6_ctx.auth_type == FP_AALGO_HMACSHA384)
		fpn_hmac_sha384_complete_pass1();
	else if (fp_ipsec6_ctx.auth_type == FP_AALGO_HMACSHA512)
		fpn_hmac_sha512_complete_pass1();
	else if (fp_ipsec6_ctx.auth_type == FP_AALGO_HMACMD5)
		fpn_hmac_md5_complete_pass1();
#endif

	m_priv(m)->exc_type = FPTUN_IPV6_IPSECDONE_OUTPUT_EXCEPT;
	m_priv(m)->flags |= M_LOCAL_OUT|M_IPSEC_OUT|M_LOCAL_F;
	if (fp_shared->conf.w32.do_func & FP_CONF_DO_IPSEC_ONCE)
		m_priv(m)->flags |= M_IPSEC_BYPASS;

#ifdef HAVE_HMAC_COMPLETE
	if (fp_ipsec6_ctx.auth_type == FP_AALGO_HMACMD5)
		fpn_hmac_md5_complete_pass2();
#endif
	rt = fp_rt6_lookup(m2vrfid(m), &ip6->ip6_dst);
	if (rt == NULL) {
		TRACE_IPSEC6_OUT(FP_LOG_INFO, "ipsec6_output_finish: could not route packet");
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoRouteLocal);
		return FP_DROP;
	}
	nh = select_nh6(rt, &ip6->ip6_src);
	FP_IP_STATS_INC(fp_shared->ip6_stats, IpForwDatagrams);

#ifdef HAVE_HMAC_COMPLETE
	if (fp_ipsec6_ctx.auth_type == FP_AALGO_HMACSHA1)
		fpn_hmac_sha1_complete_pass2();
	else if (fp_ipsec6_ctx.auth_type == FP_AALGO_HMACSHA256)
		fpn_hmac_sha256_complete_pass2();
	else if (fp_ipsec6_ctx.auth_type == FP_AALGO_HMACSHA384)
		fpn_hmac_sha384_complete_pass2();
	else if (fp_ipsec6_ctx.auth_type == FP_AALGO_HMACSHA512)
		fpn_hmac_sha512_complete_pass2();
	else if (fp_ipsec6_ctx.auth_type == FP_AALGO_HMACMD5)
		fpn_hmac_md5_complete_pass3();
#endif

#ifndef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	/* store the result in memory */
	if ((fp_ipsec6_ctx.proto == FP_IPPROTO_ESP) && (fp_ipsec6_ctx.auth_data != NULL)) {
		uint32_t alen = fp_ipsec6_ctx.authsize;
		m_copyfrombuf(m, m_len(m) - alen, fp_ipsec6_ctx.auth_data, alen);
	}

	if (fp_ipsec6_ctx.proto == FP_IPPROTO_AH)
		memcpy(fp_ipsec6_ctx.auth_data, m_ipsec6(m).out_auth, fp_ipsec6_ctx.authsize);

	fp_ipsec6_ctx.proto = FP_IPPROTO_MAX;
#endif

	return fp_ip6_output(m, rt, nh);
}

static int ah6_output_finish(struct mbuf *m, struct fp_ip6_hdr *ip6)
{
	/* restore mutable fields */
	ip6->ip6_hlim = m_ipsec6(m).ip_ttl;
	ip6->ip6_flow = m_ipsec6(m).ipv6_flow;
	/* adjust packet size */
	ip6->ip6_plen = htons(m_len(m) - sizeof(struct fp_ip6_hdr));

	return ipsec6_output_finish(m, ip6);
}

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
static void ah6_output_cb(__fpn_maybe_unused void * opaque, struct mbuf *m, int res)
{
	fp_v6_sa_entry_t *sa = m_ipsec6_sa(m);

	TRACE_IPSEC6_OUT(FP_LOG_DEBUG, "%s()", __FUNCTION__);

	if (sa && (sa->flags & FP_SA_FLAG_ESN)) {
		m_trim(m, sizeof(uint32_t));
		TRACE_IPSEC6_OUT(FP_LOG_NOTICE, "%s: ESN async finish len=%d",
				__FUNCTION__, m_len(m));
	}
	if (res >= 0) {
		res = ah6_output_finish(m, mtod(m, struct fp_ip6_hdr *));
	} else {
		res = FP_DROP;
	}

	fp_process_input_finish(m, res);
}
#endif

/* Check if one mbuf is ipv6 packet.
 * Return 1 on success, else return 0
 */
static inline int is_ipv6_packet(struct mbuf *m)
{
	struct fp_ip6_hdr *ip6;

	ip6 = mtod(m, struct fp_ip6_hdr *);
	return (ip6->ip6_v == FP_IP6VERSION);
}

static inline int ah6_output(struct mbuf *m, fp_v6_sa_entry_t *sa)
{
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	struct fp_ah *ah;
	uint16_t authsize;
	uint64_t oseq;
	int is_ipv6 = is_ipv6_packet(m);

	authsize = sa->authsize;

#ifdef CONFIG_MCORE_DEBUG
	if (likely(is_ipv6)) {
		if (ntohs(ip6->ip6_plen) + sizeof(struct fp_ip6_hdr) != m_len(m))
			TRACE_IPSEC6_OUT(FP_LOG_INFO, "ip6 len mismatch %zu %u\n",
					 ntohs(ip6->ip6_plen) + sizeof(struct fp_ip6_hdr),
					 m_len(m));
	} else {
		if (ntohs(ip->ip_len) != m_len(m))
			TRACE_IPSEC6_OUT(FP_LOG_INFO, "ip len mismatch %u %u\n",
					ntohs(ip->ip_len), m_len(m));
	}
#endif

	if (likely(sa->mode == FP_IPSEC_MODE_TUNNEL)) {

		/* save future outer header mutable fields:
		 * hop limit (FP_IPDEFTTL)
		 * traffic class:
		 * - DSCP (optionally copied from inner header)
		 * - ECN bits (cleared)
		 * flow label (copied from inner header)
		 */
		m_ipsec6(m).ip_ttl = FP_IPDEFTTL;

		if (unlikely(!(sa->flags & FP_SA_FLAG_DONT_ENCAPDSCP))) {
			if (likely(is_ipv6))
				m_ipsec6(m).ipv6_flow = ip6->ip6_flow & htonl(0xffcfffff);
			else
				m_ipsec6(m).ipv6_flow = htonl((FP_IP6VERSION << 28) | (ip->ip_tos << 20));
		} else {
			if (likely(is_ipv6))
				m_ipsec6(m).ipv6_flow = ip6->ip6_flow & htonl(0xf00fffff);
			else
				m_ipsec6(m).ipv6_flow = htonl(0x60000000);
		}

		/* Update TTL of inner IP packet */
		if (likely(is_ipv6))
			ip6->ip6_hlim -= FP_IPTTLDEC;
		else {
			ip->ip_ttl -= FP_IPTTLDEC;
			if (unlikely(ip->ip_sum >= htons(0xffff - (FP_IPTTLDEC << 8))))
				ip->ip_sum += htons(FP_IPTTLDEC << 8) + 1;
			else
				ip->ip_sum += htons(FP_IPTTLDEC << 8);
		}

		/* prepend outer header, with mutable fields set to zero) */
		ip6 = (struct fp_ip6_hdr *)m_prepend(m, sa->ahsize + sizeof(struct fp_ip6_hdr));
		if (unlikely(ip6 == NULL)) {
			TRACE_IPSEC6_OUT(FP_LOG_WARNING, "%s: failed to prepend %u bytes", __FUNCTION__, (unsigned int)(sa->ahsize + sizeof(struct fp_ip6_hdr)));
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoMemory);
			return FP_DROP;
		}
		/* initialize outer header, with mutable fields set to zero */
		ip6->ip6_flow = htonl(0x60000000);
		ip6->ip6_hlim = 0;
		if (likely(is_ipv6))
			ip6->ip6_nxt = FP_IPPROTO_IPV6;
		else
			ip6->ip6_nxt = FP_IPPROTO_IPIP;
		ip6->ip6_src = sa->src6;
		ip6->ip6_dst = sa->dst6;

		ah = (struct fp_ah *)((char*)ip6 + sizeof(struct fp_ip6_hdr));
	} else {
		struct fp_ip6_hdr save_ip6;

		save_ip6 = *ip6;
		ip6 = (struct fp_ip6_hdr *)m_prepend(m, sa->ahsize);
		if (unlikely(ip6 == NULL)) {
			TRACE_IPSEC6_OUT(FP_LOG_WARNING, "%s: failed to prepend %u bytes", __FUNCTION__,
					 (unsigned int)(sa->ahsize));
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoMemory);
			return FP_DROP;
		}
		*ip6 = save_ip6;

		/* save mutable fields */
		m_ipsec6(m).ip_ttl = ip6->ip6_hlim;
		m_ipsec6(m).ipv6_flow = ip6->ip6_flow;

		/* clear mutable fields */
		ip6->ip6_hlim = 0;
		ip6->ip6_flow = htonl(0x60000000);

		ah = (struct fp_ah *)((char*)ip6 + sizeof(struct fp_ip6_hdr));
	}

	/* data---------------
	 *     | IPv6
	 *   ah---------------
	 *     | AH header 
	 *     | authenticator
	 *     |--------------
	 *     | data
	 *     |--------------
	 */

	ah->ah_nxt = ip6->ip6_nxt;
	ah->ah_len = sa->ah_len;
	ah->ah_reserve = 0;
	ah->ah_spi = sa->spi;

	/* Insert packet replay counter, as requested.  */
	oseq = ipsec_inc_oseq(&sa->replay
#if defined(CONFIG_MCORE_FPE_VFP)
			, sa->index, 1
#endif
			);
	ah->ah_seq = htonl((uint32_t)oseq);

	/* fix IP header length */
	ip6->ip6_plen = htons(m_len(m) - sizeof(struct fp_ip6_hdr));

	/* fix next header field */
	ip6->ip6_nxt = FP_IPPROTO_AH;

	/* zeroize authenticator */
	memset(ah->auth_data, 0, authsize);

	if (sa->flags & FP_SA_FLAG_ESN) {
		uint32_t seq_hi = htonl((uint32_t)(oseq >> 32));
		char *p;

		p = m_append(m, 4);
		if (p)
			memcpy(p, &seq_hi, 4);
		else if (m_copyfrombuf(m, m_len(m), &seq_hi, 4) != 4) {
			TRACE_IPSEC6_OUT(FP_LOG_WARNING, "%s: m_copyfrombuf failure.",
					__FUNCTION__);
			return FP_DROP;
		}
		TRACE_IPSEC6_OUT(FP_LOG_NOTICE, "%s: ESN seq_hi=0x%.8"PRIx32" len=%d",
				__FUNCTION__, ntohl(seq_hi), m_len(m));
	}
#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	{
		char *mbase = mtod(m, char *);
		uint16_t off_auth_src = (char *)ip6 - mbase;
		uint16_t nbytes = m_len(m);

		m_priv(m)->flags |= M_ASYNC;
		m_ipsec6_sa(m) = sa;

		if ((fp_check_sa6(sa, &sa6_ctx[sa->index], FP_DIR_OUT) < 0) ||
		    (FPN_ASYNC_CRYPTO_AUTH(sa->alg_auth,
					  sa->key_auth,
					  FP_MAX_KEY_AUTH_LENGTH,
					  off_auth_src,
					  (char *)&ah->auth_data,
					  nbytes,
					  0, /* m_src_off */
					  0, /* m_dst_off */
					  m, /* m_dst */
					  FPN_ENCRYPT,
					  m,
					  ah6_output_cb,
					  sa6_ctx[sa->index].priv[FP_DIR_OUT]) < 0)) {
			m_freem(m);
			return FP_DONE;
		}
		return FP_KEEP;
	}
#else
	{
		fp_ipsec6_ctx.proto = FP_IPPROTO_AH;
		if (sa->alg_auth == FP_AALGO_HMACMD5) {
			fpn_hmac_md5(m_ipsec6(m).out_auth, sa->key_auth,
					m, 0, m_len(m), sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACMD5;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA1) {
			fpn_hmac_sha1(m_ipsec6(m).out_auth, sa->key_auth,
					m, 0, m_len(m), sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA1;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA256) {
			fpn_hmac_sha256(m_ipsec6(m).out_auth, sa->key_auth,
					m, 0, m_len(m), sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA256;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA384) {
			fpn_hmac_sha384(m_ipsec6(m).out_auth, sa->key_auth,
					m, 0, m_len(m), sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA384;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA512) {
			fpn_hmac_sha512(m_ipsec6(m).out_auth, sa->key_auth,
					m, 0, m_len(m), sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA512;
		}
		else if (sa->alg_auth == FP_AALGO_AESXCBC)
			fpn_aes_xcbc_mac(m_ipsec6(m).out_auth, sa->key_auth,
					m, 0, m_len(m));

		if (sa->flags & FP_SA_FLAG_ESN) {
			m_trim(m, sizeof(uint32_t));
			TRACE_IPSEC6_OUT(FP_LOG_NOTICE, "%s: ESN sync finish len=%d",
					__FUNCTION__, m_len(m));
		}
	}
	fp_ipsec6_ctx.auth_data = ah->auth_data;
	fp_ipsec6_ctx.authsize = authsize;

	return ah6_output_finish(m, ip6);
#endif
}

static inline int esp6_output_finish(struct mbuf *m, struct fp_ip6_hdr *ip6)
{
	return ipsec6_output_finish(m, ip6);
}

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
static void esp6_output_cb(__fpn_maybe_unused void * opaque, struct mbuf *m, int res)
{
	fp_v6_sa_entry_t * sa = m_ipsec6_sa(m);

#ifndef HAVE_MAPPEND_ALLOC_SUPPORT
	if (unlikely(m_ipsec6(m).flags & M_PRIV_OOPLACE_ICV))
		m_copyfrombuf(m, m_len(m), m_ipsec6(m).out_auth, sa->authsize);
#endif

	/*
	 * In GCM/GMAC mode, restore spi overwritten by seq_hi,
	 * restore original packet data overwritten by spi.
	 */
	if (sa && (sa->flags & FP_SA_FLAG_ESN) &&
		((sa->alg_enc == FP_EALGO_AESGCM) ||
		(sa->alg_enc == FP_EALGO_NULL_AESGMAC))) {
		uint32_t *esp = m_priv(m)->ipsec.esp;

		*esp = *(esp - 1);
		*(esp - 1) = m_priv(m)->ipsec.back;
		TRACE_IPSEC6_OUT(FP_LOG_NOTICE, "%s: ESN async(aes) finish spi=0x%.8"PRIx32"",
				__FUNCTION__, ntohl(*esp));
	}

	if (res >= 0) {
		res = esp6_output_finish(m, mtod(m, struct fp_ip6_hdr *));
	} else {
		res = FP_DROP;
	}

	fp_process_input_finish(m, res);
}
#endif

static inline int esp6_output(struct mbuf *m, fp_v6_sa_entry_t *sa)
{
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	struct fp_udphdr *udp = NULL;
	struct fp_esp *esp;
	uint16_t ivlen, blks;
	unsigned int trailer, rlen;
	char *authdata;
	char *pad;
#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
#ifndef HAVE_MAPPEND_ALLOC_SUPPORT
	char padbuf[FP_MAX_KEY_ENC_LENGTH + 2];
#endif
#else
	int __fpn_maybe_unused is_contiguous = m_is_contiguous(m);
#endif
	unsigned int i;
	uint8_t alen;
	unsigned int mask;
#ifdef HAVE_CRYPTO_PREHANDLE
	unsigned int unen_len;
	int optimize = 0;
	uint64_t *pre_enc_data = NULL;
	int pre_xdes_enc = 0;
#endif
	uint64_t oseq;
	int is_ipv6 = is_ipv6_packet(m);

#ifdef CONFIG_MCORE_DEBUG
	if (likely(is_ipv6)) {
		if (ntohs(ip6->ip6_plen) + sizeof(struct fp_ip6_hdr) != m_len(m))
			TRACE_IPSEC6_OUT(FP_LOG_INFO, "ip6 len mismatch %zu %u\n",
					 ntohs(ip6->ip6_plen) + sizeof(struct fp_ip6_hdr),
					 m_len(m));
	} else {
		if (ntohs(ip->ip_len) != m_len(m))
			TRACE_IPSEC6_OUT(FP_LOG_INFO, "ip len mismatch %u %u\n",
					ntohs(ip->ip_len), m_len(m));
	}
#endif
	/* check packet size early, including trailer */

	ivlen = sa->ivlen;
	blks = sa->blocksize;
	alen = sa->authsize;
	mask = blks - 1;

	/* Reset flags */
	m_ipsec6(m).flags  = 0;

#ifdef HAVE_CRYPTO_PREHANDLE
	if ((sa->alg_auth == FP_AALGO_HMACSHA1 ||
	     sa->alg_auth == FP_AALGO_HMACSHA256 ||
	     sa->alg_auth == FP_AALGO_HMACSHA384 ||
	     sa->alg_auth == FP_AALGO_HMACSHA512 ||
	     sa->alg_auth == FP_AALGO_HMACMD5) &&
	     m_is_contiguous(m))
		optimize = 1;
#endif

	if (likely(sa->mode == FP_IPSEC_MODE_TUNNEL)) {
		uint32_t flow;
		uint32_t size = ivlen + sizeof(struct fp_esp) + sizeof(struct fp_ip6_hdr);
		unsigned int mask = blks -1;

		/* save inner version, DSCP (optional) and flow label, clear ECN bits */
		if (unlikely(!(sa->flags & FP_SA_FLAG_DONT_ENCAPDSCP))) {
			if (likely(is_ipv6))
				flow = ip6->ip6_flow & htonl(0xffcfffff);
			else
				flow = htonl((FP_IP6VERSION << 28) | (ip->ip_tos << 20));
		} else {
			if (likely(is_ipv6))
				flow = ip6->ip6_flow & htonl(0xf00fffff);
			else
				flow = htonl((FP_IP6VERSION << 28));
		}

		/* Update TTL of inner IP packet */
		if (likely(is_ipv6))
			ip6->ip6_hlim -= FP_IPTTLDEC;
		else {
			ip->ip_ttl -= FP_IPTTLDEC;
			if (unlikely(ip->ip_sum >= htons(0xffff - (FP_IPTTLDEC << 8))))
				ip->ip_sum += htons(FP_IPTTLDEC << 8) + 1;
			else
				ip->ip_sum += htons(FP_IPTTLDEC << 8);
		}

		rlen = m_len(m);

		/* trailer = ((blks - ((rlen + 2) % blks)) % blks) + 2 */
		/* trailer = 2 bytes (padd len + next header) aligned on block size */
		trailer = (mask+2) - ((rlen+1) & mask);

		if (unlikely(sa->flags & FP_SA_FLAG_UDPTUNNEL))
			size += sizeof(struct fp_udphdr);
		ip6 = (struct fp_ip6_hdr *)m_prepend(m, size);
		if (unlikely(ip6 == NULL)) {
			TRACE_IPSEC6_OUT(FP_LOG_WARNING, "m_prepend(%d) failed", size);
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoMemory);
			return FP_DROP;
		}

		/* initialize outer header */
		ip6->ip6_flow = flow;
		ip6->ip6_hlim = FP_IPDEFTTL;
		if (likely(is_ipv6))
			ip6->ip6_nxt = FP_IPPROTO_IPV6;
		else
			ip6->ip6_nxt = FP_IPPROTO_IPIP;
		ip6->ip6_src = sa->src6;
		ip6->ip6_dst = sa->dst6;

		if (unlikely(sa->flags & FP_SA_FLAG_UDPTUNNEL)) {
			udp = (struct fp_udphdr *)(ip6 + 1);
			init_tunnel6_udp_header(udp, sa->sport, sa->dport);
			esp = (struct fp_esp *)(udp + 1);
		} else
			esp = (struct fp_esp *)(ip6 + 1);
	} else {
		struct fp_ip6_hdr save_ip6;
		uint32_t size = ivlen + sizeof(struct fp_esp);

		rlen = m_len(m) - sizeof(struct fp_ip6_hdr); 
		trailer = (mask+2) - ((rlen+1) & mask);

		memcpy(&save_ip6, ip6, sizeof(struct fp_ip6_hdr));
		ip6 = (struct fp_ip6_hdr *)m_prepend(m, size);
		if (unlikely(ip6 == NULL)) {
			TRACE_IPSEC6_OUT(FP_LOG_WARNING, "m_prepend(%d) failed", size);
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoMemory);
			return FP_DROP;
		}
		memcpy((char *)ip6, &save_ip6, sizeof(struct fp_ip6_hdr));
		esp = (struct fp_esp *)((char*)ip6 + sizeof(struct fp_ip6_hdr));
	}


	/* data---------------
	 *     | IPv6
	 * [udp]--------------
	 *     | UDP header
	 *  esp---------------
	 *     | ESP header 
	 *     | IV
	 *     |--------------
	 *     | data
	 *     |--------------
	 *     | ESP trailer:
	 *     | pad padlen nh
	 *     |--------------
	 */

	/* Build nonce from salt + IV  in GCM/GMAC case */
	if ((sa->alg_enc == FP_EALGO_AESGCM) ||
	    (sa->alg_enc == FP_EALGO_NULL_AESGMAC)) {
		COPY_PACKET_IV(esp->enc_data, &sa->replay.oseq, 8);
		COPY_PACKET_IV(m_ipsec6(m).iv, &sa->key_enc[sa->key_enc_len], 4);
		COPY_PACKET_IV(&m_ipsec6(m).iv[4], esp->enc_data, 8);
	} else {
		/* copy IV in packet */
		FILL_PACKET_IV(esp->enc_data, ivlen);
	}

#ifdef HAVE_CRYPTO_PREHANDLE
		/*
		 * On OCTEON platform, the hardware crypto unit can work in parallel with
		 * other instructions. As encrypted data is from the IV field of the packet,
		 * we can pre-encrypted two blocks (iv field and the first data block) here.
		 * Start encryption to enhance performance as soon as the esp header is created.
		 */
		unen_len = ivlen + rlen;
		if (likely(optimize)) {
			/* Staret encryption from the IV field of the packet */
			pre_enc_data = (uint64_t *)esp->enc_data;
			if (sa->alg_enc == FP_EALGO_AESCBC) {
				fpn_aes_cbc_encrypt_pre(pre_enc_data, unen_len,
						(uint64_t*)sa->key_enc,sa->key_enc_len);
			} else if (sa->alg_enc == FP_EALGO_3DESCBC) {
				fpn_3des_cbc_encrypt_pre(pre_enc_data, unen_len, (uint64_t*)sa->key_enc);
				pre_xdes_enc = 1;
			} else if (sa->alg_enc == FP_EALGO_DESCBC) {
				fpn_des_cbc_encrypt_pre(pre_enc_data, unen_len, (uint64_t*)sa->key_enc);
				pre_xdes_enc = 1;
			}
			FPN_AES_CBC_PRE_ENCRYPT(0);
			FPN_XDES_CBC_PRE_ENCRYPT(0);
		}
#endif

	esp->esp_spi = sa->spi;

#ifdef HAVE_CRYPTO_PREHANDLE
	/* After padding, there is one block at least that can be encrypted */
	if (likely(optimize)) {
		FPN_AES_CBC_PRE_ENCRYPT(0);
		FPN_XDES_CBC_PRE_ENCRYPT(0);
	}
#endif

	/* replay counter */
	oseq = ipsec_inc_oseq(&sa->replay
#if defined(CONFIG_MCORE_FPE_VFP)
			, sa->index, 1
#endif
			);
	esp->esp_seq = htonl((uint32_t)oseq);

	/* fix IP header length */
	ip6->ip6_plen = htons(m_len(m) - sizeof(struct fp_ip6_hdr) + trailer + alen);

#ifdef HAVE_CRYPTO_PREHANDLE
	if (likely(optimize)) {
		FPN_AES_CBC_PRE_ENCRYPT(0);
		FPN_XDES_CBC_PRE_ENCRYPT(0);
	}
#endif

	pad = m_append(m, trailer + alen);
	authdata = pad + trailer;

#ifdef HAVE_MAPPEND_ALLOC_SUPPORT
	/* On XLP, successful m_append(len) will return a pointer on
	 * a contiguous area of length len bytes, allocating a new
	 * buffer if needed.
	 */
	if (pad == NULL) {
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoMemory);
		return FP_DROP;
	}
#else /* HAVE_MAPPEND_ALLOC_SUPPORT */
	if (unlikely(pad == NULL)) {
		/* pad in a buffer, and then copy to mbuf */
#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
		pad = padbuf;
		authdata = m_ipsec6(m).out_auth;
		m_ipsec6(m).flags |= M_PRIV_OOPLACE_ICV;
#else
		pad = fp_ipsec6_ctx.padbuf;
		authdata = pad + trailer;
#endif
	}
#endif

	/* random, zero or seq ? seq here */
	for (i = 0; i < trailer - 2; i++)
		pad[i] = i + 1;

#ifdef HAVE_CRYPTO_PREHANDLE
	if (likely(optimize)) {
		FPN_AES_CBC_PRE_ENCRYPT(i);
		FPN_XDES_CBC_PRE_ENCRYPT(i);
	}
#endif

	pad[trailer-2] = trailer - 2;
	pad[trailer-1] = ip6->ip6_nxt;

#ifndef HAVE_MAPPEND_ALLOC_SUPPORT
	if (unlikely(m_ipsec6(m).flags & M_PRIV_OOPLACE_ICV))
		m_copyfrombuf(m, m_len(m), pad, trailer);
#endif

	if (unlikely(udp != NULL)) {
		ip6->ip6_nxt = FP_IPPROTO_UDP;
		/* fix UDP length */
		udp->uh_ulen = htons(m_len(m) - sizeof(struct fp_ip6_hdr));
	} else {
		/* fix next header field */
		ip6->ip6_nxt = FP_IPPROTO_ESP;
	}

	/* Save SA pointer in mbuf */
	m_ipsec6_sa(m) = sa;

#ifdef HAVE_CRYPTO_PREHANDLE
	if (likely(optimize)) {
		FPN_AES_CBC_PRE_ENCRYPT(AES_BLOCK_SIZE);
		FPN_XDES_CBC_PRE_ENCRYPT(DES_BLOCK_SIZE);
	}
#endif

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	{
		unsigned int plen, authlen;
		char *mbase = mtod(m, char*);
		char *iv;
		char *enc_data;
		uint16_t enc_len;
		char *auth_data = (char*)esp;

		plen = rlen + trailer;
		authlen = plen + ivlen + sizeof(struct fp_esp);

		/* In CBC case, use a trick, start encryption at start of iv, instead of */
		/* start of data to encrypt, to generate automatically an unpredictable IV */
		if ((sa->alg_enc == FP_EALGO_AESGCM) ||
		    (sa->alg_enc == FP_EALGO_NULL_AESGMAC)) {
			enc_data = esp->enc_data + ivlen;
			enc_len = plen;
			iv = m_ipsec6(m).iv;

			/* In GCM, do not include IV in auth */
			if (sa->alg_enc == FP_EALGO_AESGCM) {
				authlen -= ivlen;
			}
		} else {
			enc_data = esp->enc_data;
			enc_len = plen + ivlen;
			iv = (char *)esp->enc_data - ivlen;
		}

		m_priv(m)->flags |= M_ASYNC;
		m_priv(m)->ipsec.sa = sa;

		if (alen) {
			if (sa->flags & FP_SA_FLAG_ESN) {
				uint32_t seq_hi = htonl((uint32_t)(oseq >> 32));

				/*
				 * In GCM/GMAC mode, backup 4 bytes before esp header,
				 * temporarily overwrite it using spi,
				 * overwrite spi using seq_hi,
				 * so that the AAD is contiguous.
				 */
				if ((sa->alg_enc == FP_EALGO_AESGCM) ||
					(sa->alg_enc == FP_EALGO_NULL_AESGMAC)) {
					m_priv(m)->ipsec.back = *((uint32_t *)esp - 1);
					m_priv(m)->ipsec.esp = esp;

					*((uint32_t *)esp - 1) = esp->esp_spi;
					esp->esp_spi = seq_hi;
					auth_data -= sizeof(uint32_t);
					TRACE_IPSEC6_OUT(FP_LOG_NOTICE, "%s: ESN async(aes) back=0x%.8"PRIx32" seq_hi=0x%.8"PRIx32" len=%d",
							__FUNCTION__, ntohl(m_priv(m)->ipsec.back), ntohl(seq_hi), m_len(m));
				/*
				 * In other mode, write seq_hi at the end of packet data.
				 * It would be overwritten by authentication data later.
				 */
				} else {
					m_copyfrombuf(m, m_len(m) - alen, &seq_hi, sizeof(uint32_t));
					TRACE_IPSEC6_OUT(FP_LOG_NOTICE, "%s: ESN async seq_hi=0x%.8"PRIx32" len=%d",
							__FUNCTION__, ntohl(seq_hi), m_len(m));
				}
				authlen += sizeof(uint32_t);
			}

			if (likely(sa->alg_enc != FP_EALGO_NULL)) {
				if ((fp_check_sa6(sa, &sa6_ctx[sa->index], FP_DIR_OUT) < 0) ||
				    (FPN_ASYNC_CRYPTO_CIPHER_AUTH(sa->alg_enc,
								 (uint64_t*)sa->key_enc,
								 sa->key_enc_len,
								 enc_data - mbase,
								 enc_len,
								 iv - mbase,
								 ivlen,
								 sa->alg_auth,
								 sa->key_auth,
								 FP_MAX_KEY_AUTH_LENGTH,
								 auth_data - mbase,
								 authdata,
								 authlen,
								 0, /* m_src_off */
								 0, /* m_dst_off */
								 m, /* m_dst */
								 FPN_ENCRYPT,
								 m,
								 esp6_output_cb,
								 sa6_ctx[sa->index].priv[FP_DIR_OUT]) < 0)) {
					m_freem(m);
					return FP_DONE;
				}
			}
			else {
				if ((fp_check_sa6(sa, &sa6_ctx[sa->index], FP_DIR_OUT) < 0) ||
				    (FPN_ASYNC_CRYPTO_AUTH(sa->alg_auth,
							  sa->key_auth,
							  FP_MAX_KEY_AUTH_LENGTH,
							  auth_data - mbase,
							  authdata,
							  authlen,
							  0, /* m_src_off */
							  0, /* m_dst_off */
							  m, /* m_dst */
							  FPN_ENCRYPT,
							  m,
							  esp6_output_cb,
							  sa6_ctx[sa->index].priv[FP_DIR_OUT]) < 0)) {
					m_freem(m);
					return FP_DONE;
				}
			}
		}
		else {
			if (likely(sa->alg_enc != FP_EALGO_NULL)) {
				if ((fp_check_sa6(sa, &sa6_ctx[sa->index], FP_DIR_OUT) < 0) ||
				    (FPN_ASYNC_CRYPTO_CIPHER(sa->alg_enc,
							    (uint64_t*)sa->key_enc,
							    sa->key_enc_len,
							    enc_data - mbase,
							    enc_len,
							    iv - mbase,
							    ivlen,
							    0, /* m_src_off */
							    0, /* m_dst_off */
							    m, /* m_dst */
							    FPN_ENCRYPT,
							    m,
							    esp6_output_cb,
							    sa6_ctx[sa->index].priv[FP_DIR_OUT]) < 0)) {
					m_freem(m);
					return FP_DONE;
				}
			}
			else {
				/* ESP-NULL without auth, do it sync */
				return esp6_output_finish(m, ip6);
			}
		}
		return FP_KEEP;
	}
#else

	if (alen && (sa->flags & FP_SA_FLAG_ESN)) {
		uint32_t seq_hi = htonl((uint32_t)(oseq >> 32));

		m_copyfrombuf(m, m_len(m) - alen, &seq_hi, sizeof(uint32_t));
		TRACE_IPSEC6_OUT(FP_LOG_NOTICE, "%s: ESN seq_hi=0x%.8"PRIx32" len=%d",
				 __FUNCTION__, ntohl(seq_hi), m_len(m));
	}

#ifdef HAVE_AESHMACSHA1
	if (condition_enc_aescbc_hmacsha1(is_contiguous, ivlen + rlen + trailer) && 
	    (sa->alg_auth == FP_AALGO_HMACSHA1) && (sa->alg_enc == FP_EALGO_AESCBC)) {
			/* start encrypting from the IV field */
			fpn_aes_cbc_encrypt_hsha1((char *)esp, ivlen + rlen + trailer,
						 (uint64_t *)sa->key_enc,
						 sa->key_enc_len,
						 m_tail(m) - alen,
						 sa->key_auth, sa->ipad, sa->opad);

		fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA1;
		return esp6_output_finish(m, ip6);
	}

#endif

#ifdef HAVE_AESHMACSHA2
	/* fp_aes_cbc_encrypt_hsha256+() requires at least 3 AES blocks. */
	if (condition_enc_aescbc_hmacsha2(is_contiguous, ivlen + rlen + trailer) &&
	   ((sa->alg_auth == FP_AALGO_HMACSHA256)  ||
	    (sa->alg_auth == FP_AALGO_HMACSHA384)  ||
	    (sa->alg_auth == FP_AALGO_HMACSHA512)) &&
	    (sa->alg_enc == FP_EALGO_AESCBC)) {
		/* start encrypting from the IV field */
		FPN_AES_SET_IV_ENCRYPT((uint64_t *)esp->enc_data);
		if(sa->alg_auth == FP_AALGO_HMACSHA256) {
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA256;
			fpn_aes_cbc_encrypt_hsha256((char *)esp, ivlen + rlen + trailer,
						(uint64_t *)sa->key_enc,
						sa->key_enc_len,
						m_tail(m) - alen,
						sa->key_auth, sa->ipad, sa->opad);
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA384){
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA384;
			fpn_aes_cbc_encrypt_hsha384((char *)esp, ivlen + rlen + trailer,
						(uint64_t *)sa->key_enc,
						sa->key_enc_len,
						m_tail(m) - alen,
						sa->key_auth, sa->ipad, sa->opad);
		}
		else {  // must be FP_AALGO_HMACSHA512
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA512;
		fpn_aes_cbc_encrypt_hsha512((char *)esp, ivlen + rlen + trailer,
					(uint64_t *)sa->key_enc,
					sa->key_enc_len,
					m_tail(m) - alen,
					sa->key_auth, sa->ipad, sa->opad);
		}

		return esp6_output_finish(m, ip6);
	}
#endif

#ifdef HAVE_AESHMACMD5
	if (condition_enc_aescbc_hmacmd5(is_contiguous, ivlen + rlen + trailer) && 
	    (sa->alg_auth == FP_AALGO_HMACMD5) && (sa->alg_enc == FP_EALGO_AESCBC)) {
		/* start encrypting from the IV field */
		fpn_aes_cbc_encrypt_hmd5((char *)esp, ivlen + rlen + trailer,
					(uint64_t *)sa->key_enc,
					sa->key_enc_len,
					m_tail(m) - alen,
					sa->key_auth, sa->ipad, sa->opad);
		fp_ipsec6_ctx.auth_type = FP_AALGO_HMACMD5;
		return esp6_output_finish(m, ip6);
	}

#endif

#ifdef HAVE_3DESHMACSHA1
	if (condition_enc_3descbc_hmacsha1(is_contiguous, ivlen + rlen + trailer) && 
	    (sa->alg_auth == FP_AALGO_HMACSHA1) && (sa->alg_enc == FP_EALGO_3DESCBC)) {
		/* start encrypting from the IV field */
		fpn_3des_cbc_encrypt_hsha1((char *)esp, ivlen + rlen + trailer,
					  (uint64_t *)sa->key_enc,
					  m_tail(m) - alen,
					  sa->key_auth, sa->ipad, sa->opad);

		fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA1;
		return esp6_output_finish(m, ip6);
	}
#endif

#ifdef HAVE_3DESHMACMD5
	/* An example with 3des-hmac-md5 crypto function */
	if (condition_enc_3descbc_hmacsha1(is_contiguous, ivlen + rlen + trailer) && 
	    (sa->alg_auth == FP_AALGO_HMACMD5) && (sa->alg_enc == FP_EALGO_3DESCBC)) {
		/* start encrypting from the IV field */
		fpn_3des_cbc_encrypt_hmd5((char *)esp, ivlen + rlen + trailer,
				(uint64_t *)sa->key_enc,
				m_tail(m) - alen,
				sa->key_auth, sa->ipad, sa->opad);
		fp_ipsec6_ctx.auth_type = FP_AALGO_HMACMD5;
		return esp6_output_finish(m, ip6);
	}
#endif

#ifdef HAVE_DESHMACSHA1
	if (condition_enc_descbc_hmacsha1(is_contiguous, ivlen + rlen + trailer) && 
	    (sa->alg_auth == FP_AALGO_HMACSHA1) && (sa->alg_enc == FP_EALGO_DESCBC)) {
		/* start encrypting from the IV field */
		fpn_des_cbc_encrypt_hsha1((char *)esp, ivlen + rlen + trailer,
					  (uint64_t *)sa->key_enc,
					  m_tail(m) - alen,
					  sa->key_auth, sa->ipad, sa->opad);

		fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA1;
		return esp6_output_finish(m, ip6);
	}
#endif

#ifdef HAVE_DESHMACSHA2
	if (condition_enc_descbc_hmacsha2(is_contiguous, ivlen + rlen + trailer) &&
	   ((sa->alg_auth == FP_AALGO_HMACSHA256)  ||
	    (sa->alg_auth == FP_AALGO_HMACSHA384)  ||
	    (sa->alg_auth == FP_AALGO_HMACSHA512)) &&
	    (sa->alg_enc == FP_EALGO_DESCBC)) {
		/* start encrypting from the IV field */
		if(sa->alg_auth == FP_AALGO_HMACSHA256){
			fpn_des_cbc_encrypt_hsha256((char *)esp, ivlen + rlen + trailer,
						(uint64_t *)sa->key_enc,
						m_tail(m) - alen,
						sa->key_auth, sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA256;
		}
		else if(sa->alg_auth == FP_AALGO_HMACSHA384){
			fpn_des_cbc_encrypt_hsha384((char *)esp, ivlen + rlen + trailer,
						(uint64_t *)sa->key_enc,
						m_tail(m) - alen,
						sa->key_auth, sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA384;
		}
		else{
			fpn_des_cbc_encrypt_hsha512((char *)esp, ivlen + rlen + trailer,
						(uint64_t *)sa->key_enc,
						m_tail(m) - alen,
						sa->key_auth, sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA512;
		}
		return esp6_output_finish(m, ip6);
	}
#endif

#ifdef HAVE_3DESHMACSHA2
	if (condition_enc_3descbc_hmacsha2(is_contiguous, ivlen + rlen + trailer) &&
	   ((sa->alg_auth == FP_AALGO_HMACSHA256)  ||
	    (sa->alg_auth == FP_AALGO_HMACSHA384)  ||
	    (sa->alg_auth == FP_AALGO_HMACSHA512)) &&
	    (sa->alg_enc == FP_EALGO_3DESCBC)) {
		/* start encrypting from the IV field */
		if(sa->alg_auth == FP_AALGO_HMACSHA256){
			fpn_3des_cbc_encrypt_hsha256((char *)esp, ivlen + rlen + trailer,
						(uint64_t *)sa->key_enc,
						m_tail(m) - alen,
						sa->key_auth, sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA256;
		}
		else if(sa->alg_auth == FP_AALGO_HMACSHA384){
			fpn_3des_cbc_encrypt_hsha384((char *)esp, ivlen + rlen + trailer,
						(uint64_t *)sa->key_enc,
						m_tail(m) - alen,
						sa->key_auth, sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA384;
		}
		else{
			fpn_3des_cbc_encrypt_hsha512((char *)esp, ivlen + rlen + trailer,
						(uint64_t *)sa->key_enc,
						m_tail(m) - alen,
						sa->key_auth, sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA512;
		}
	return esp6_output_finish(m, ip6);
}
#endif

#ifdef HAVE_DESHMACMD5
	if (condition_enc_descbc_hmacmd5(is_contiguous, ivlen + rlen + trailer) && 
	    (sa->alg_auth == FP_AALGO_HMACMD5) && (sa->alg_enc == FP_EALGO_DESCBC)) {
		/* start encrypting from the IV field */
		fpn_des_cbc_encrypt_hmd5((char *)esp, ivlen + rlen + trailer,
					(uint64_t *)sa->key_enc,
					m_tail(m) - alen,
					sa->key_auth, sa->ipad, sa->opad);
		fp_ipsec6_ctx.auth_type = FP_AALGO_HMACMD5;
		return esp6_output_finish(m, ip6);
	}
#endif

	/* for no algorithm chaining support */
	{	
		/* start encrypting from the IV field */
		unsigned int nbytes = ivlen + rlen + trailer;
		uint64_t *src = (uint64_t *)esp->enc_data;
		uint16_t off = (char*)src - mtod(m, char*);

		/* use ivlen bytes before the IV field as the real IV */
		const uint64_t *iv  = (uint64_t *)(esp->enc_data - ivlen);
		const uint64_t *K64 = (uint64_t *)sa->key_enc;

		if (sa->alg_enc == FP_EALGO_DESCBC)
			fpn_des_cbc_encrypt(m, off, nbytes, iv, K64);
		else if (sa->alg_enc == FP_EALGO_3DESCBC)
			fpn_3des_cbc_encrypt(m, off, nbytes, iv, K64);
		else if (sa->alg_enc == FP_EALGO_AESCBC)
			fpn_aes_cbc_encrypt(m, off, nbytes, iv, K64, sa->key_enc_len);
	}

	if (alen != 0) {
		unsigned int authlen = sizeof(*esp) + ivlen + rlen + trailer;
		uint16_t off = ((const char*)esp) - mtod(m, const char*);

		if (sa->flags & FP_SA_FLAG_ESN)
			authlen += sizeof(uint32_t);

		fp_ipsec6_ctx.proto = FP_IPPROTO_ESP;
		if (sa->alg_auth == FP_AALGO_HMACMD5) {
			fpn_hmac_md5(authdata, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACMD5;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA1) {
			fpn_hmac_sha1(authdata, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA1;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA256) {
			fpn_hmac_sha256(authdata, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA256;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA384) {
			fpn_hmac_sha384(authdata, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA384;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA512) {
			fpn_hmac_sha512(authdata, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec6_ctx.auth_type = FP_AALGO_HMACSHA512;
		}
		else if (sa->alg_auth == FP_AALGO_AESXCBC)
			fpn_aes_xcbc_mac(authdata, sa->key_auth,
					m, off, authlen);

		fp_ipsec6_ctx.auth_data = authdata;
		fp_ipsec6_ctx.authsize = alen;
	}

	return esp6_output_finish(m, ip6);
#endif
}

static inline int __local_ipsec6_output(struct mbuf *m, fp_v6_sa_entry_t *sa,
					fp_v6_sp_entry_t *sp)
{
	uint16_t len __fpn_maybe_unused = m_len(m);
	int ret;

#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
	/*
	 * If output sequence number has reached the limit, directly drop
	 * packet.
	 */
	if (ipsec_chk_max_oseq(&sa->replay, sa->flags & FP_SA_FLAG_ESN)) {
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedIPsec);
		return FP_DROP;
	}
#endif

#ifndef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	/* Initialize ipsec context structure */
	/* Never enter esp4_input or ah4_input without this */
	fp_ipsec6_ctx.auth_type = FP_AALGO_NULL;
	fp_ipsec6_ctx.authsize = 0;
	fp_ipsec6_ctx.auth_data = NULL;
	fp_ipsec6_ctx.proto = FP_IPPROTO_MAX;
#endif

	if (likely(sa->mode == FP_IPSEC_MODE_TUNNEL))
		set_mvrfid(m, sa->vrfid);

	FP_IPSEC6_STATS_INC(sp->stats, sp_packets);
	FP_IPSEC6_STATS_ADD(sp->stats, sp_bytes, len);
	FP_IPSEC6_STATS_INC(sa->stats, sa_packets);
	FP_IPSEC6_STATS_ADD(sa->stats, sa_bytes, len);
	if (likely(sa->proto == FP_IPPROTO_ESP))
		ret = esp6_output(m, sa);
	else
		ret = ah6_output(m, sa);

	/* output sequence number is incremented in esp/ah6_output */
#ifdef CONFIG_MCORE_MULTIBLADE
	if (unlikely(++sa->replay.last_sync >= fp_shared->ipsec6.sa_replay_sync_threshold)) {
		sa->replay.last_sync = 0;
		ipsec6_sa_sync(sa);
	}
#endif

	if (likely(ret == FP_DONE))
		return FP_DONE;
#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	if (ret == FP_KEEP)
		return FP_KEEP;
#endif
	if (ret == FP_NONE) {
		FP_IPSEC6_STATS_INC(sp->stats, sp_exceptions);
		return FP_NONE;
	}

	FP_IPSEC6_STATS_DEC(sp->stats, sp_packets);
	FP_IPSEC6_STATS_SUB(sp->stats, sp_bytes, len);
	FP_IPSEC6_STATS_DEC(sa->stats, sa_packets);
	FP_IPSEC6_STATS_SUB(sa->stats, sa_bytes, len);
	FP_IPSEC6_STATS_INC(sp->stats, sp_errors);
	FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedIPsec);
	return ret;
}

static int local_ipsec6_output(struct mbuf *m, fp_v6_sa_entry_t *sa,
				      fp_v6_sp_entry_t *sp)
{
#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
	int ret;
	struct mbuf *m2;

	m2 = m_unclone(m);

	/* mbuf was not a clone */
	if (likely(m2 == m))
		return __local_ipsec6_output(m, sa, sp);

	if (m2 == NULL) {
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoMemory);
		return FP_DONE;
	}

	/* m2 is a new packet because m was a clone */
	ret = __local_ipsec6_output(m2, sa, sp);
	fp_process_input_finish(m2, ret);

	return FP_DONE;
#else
	return __local_ipsec6_output(m, sa, sp);
#endif
}

int ipsec6_output(struct mbuf *m, fp_v6_sa_entry_t *sa, fp_v6_sp_entry_t *sp)
{
#ifndef CONFIG_MCORE_MULTIBLADE
	return local_ipsec6_output(m, sa, sp);
#else
	uint16_t len = m_len(m);

	TRACE_IPSEC6_OUT(FP_LOG_DEBUG, "%s()", __FUNCTION__);
	/* SA dedicated to a remote blade */
	if (unlikely(sa->output_blade &&
				(sa->output_blade != fp_shared->fp_blade_id))) {
		if (unlikely(fp_prepare_ipsec6_output_req(m, sa->output_blade, sa->svti_ifuid ? : m_priv(m)->ifuid)
			     == FP_DROP)) {
			TRACE_IPSEC6_OUT(FP_LOG_WARNING, "fp_prepare_ipsec6_output_req failed");
			goto drop;
		} else {
			int ret = fp_fpib_forward(m, sa->output_blade);
			FP_MULTIBLADE_STATS_INC(fp_shared->multiblade_stats,
					SentRemoteIPsecOutputRequests);
			if (ret == FP_DROP)
				goto drop;
			return ret;
		}
	}

	return local_ipsec6_output(m, sa, sp);

drop:
	FP_IPSEC6_STATS_INC(sp->stats, sp_packets);
	FP_IPSEC6_STATS_ADD(sp->stats, sp_bytes, len);
	FP_IPSEC6_STATS_INC(sa->stats, sa_packets);
	FP_IPSEC6_STATS_ADD(sa->stats, sa_bytes, len);
	FP_IPSEC6_STATS_INC(sp->stats, sp_errors);
	FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedIPsec);
	return FP_DROP;
#endif
}

int fp_ipsec6_output(struct mbuf *m)
{
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	fp_v6_sa_entry_t *sa;
	fp_v6_sp_entry_t *sp;
	uint16_t sport = 0, dport = 0;

	TRACE_IPSEC6_OUT(FP_LOG_DEBUG, "fp_ipsec6_output");
	/* Check IPsec outbound policy
	 * - if IPsec is required and SA not present, send to SP for IKE.
	 * - if tunnel mode, re-route packet:
	 *	o if route not found, send to SP
	 *	o if route to slow path interface, send to SP (bug)
	 * - if transport mode, 
	 * 	o fast path does not support other tunneling (l2tp, ipip...) error: packet is not for us
	 *       o fast path does support other tunneling (l2tp, ipip...): go ahead
	 *    At this point entry pointer is updated to final next hop.
	 */

#ifdef CONFIG_MCORE_IPSEC_IPV6_LOOKUP_PORTS
	if ((unlikely(fp_ipsec6_extract_ports(m, ip6, &sport, &dport) < 0))) {
		TRACE_IPSEC6_OUT(FP_LOG_INFO, "%s: only %u bytes of protocol %u",
				__FUNCTION__, ntohs(ip6->ip6_plen), ip6->ip6_nxt);
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedIPsec);
		return FP_DROP;
	}
#endif

	sp = spd6_out_lookup(ip6->ip6_src.fp_s6_addr32, ip6->ip6_dst.fp_s6_addr32, ip6->ip6_nxt,
			sport, dport, m2vrfid(m));

	if (likely(sp == NULL))
		return FP_CONTINUE; /* assume bypass */

	/* ensure it is not an exception for slow path before
	 * incrementing packets/bytes for this sp. */
	if (unlikely(sp->filter.action != FP_SP_ACTION_PROTECT)) {
		FP_IPSEC6_STATS_INC(sp->stats, sp_packets);
		FP_IPSEC6_STATS_ADD(sp->stats, sp_bytes, m_len(m));
		if (sp->filter.action == FP_SP_ACTION_BYPASS) {
			TRACE_IPSEC6_OUT(FP_LOG_INFO, "bypass");
			return FP_CONTINUE;
		}

		TRACE_IPSEC6_OUT(FP_LOG_INFO, "discard");
		FP_IPSEC6_STATS_INC(sp->stats, sp_errors);
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedIPsec);
		return FP_DROP;
	}

	TRACE_IPSEC6_OUT(FP_LOG_DEBUG, "Protecting %s %s src="FP_NIP6_FMT" dst="FP_NIP6_FMT,
			sp->sa_proto == FP_IPPROTO_AH ? "AH" :"ESP",
			sp->mode == FP_IPSEC_MODE_TUNNEL ? "tunnel" :"transport",
			FP_NIP6(ip6->ip6_src), FP_NIP6(ip6->ip6_dst));

	if (likely(sp->mode == FP_IPSEC_MODE_TUNNEL)) {
		output_func func;

		if (likely(sp->sa_index != 0)) {
			if (sp->outer_family == AF_INET6) {
				sa = &fp_get_sad6()->table[sp->sa_index];
				func = ipsec6_output;
			} else {
				sa = &fp_get_sad()->table[sp->sa_index];
				func = ipsec4_output;
			}
			/* SA may have disappeared or been replaced */
			if (likely(sa->state != FP_SA_STATE_UNSPEC &&
				sa->genid == sp->sa_genid))
				return (*func)(m, sa, sp);

			/* invalidate SA cache entry */
			sp->sa_index = 0;
		}
		
		if (sp->outer_family == AF_INET6) {
			sa = sad6_out_lookup(sp->tunnel6_src.fp_s6_addr32,
					     sp->tunnel6_dst.fp_s6_addr32,
					     sp->sa_proto, FP_IPSEC_MODE_TUNNEL, sp->reqid,
					     sp->link_vrfid, m2vrfid(m),
#ifdef CONFIG_MCORE_IPSEC_SVTI
					     0,
#endif
					     &sp->sa_index);
			func = ipsec6_output;
		} else {
			sa = sad_out_lookup(sp->tunnel4_src, sp->tunnel4_dst,
					    sp->sa_proto, FP_IPSEC_MODE_TUNNEL, sp->reqid,
					    sp->link_vrfid, m2vrfid(m),
#if defined(CONFIG_MCORE_IPSEC_SVTI) && !defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
					    0,
#endif
					    &sp->sa_index);
			func = ipsec4_output;
		}

		if (unlikely(sa == NULL)) {
			TRACE_IPSEC6_OUT(FP_LOG_NOTICE, "SA not found");
			FP_IPSEC6_STATS_INC(sp->stats, sp_exceptions);
			return fp_ip_prepare_exception(m, FPTUN_EXC_IKE_NEEDED);
		}

		if (unlikely(sa->state == FP_SA_STATE_ACQUIRE)) {
			if (sp->flags & FP_SP_FLAG_LEVEL_USE) {
				FP_IPSEC6_STATS_INC(sp->stats, sp_packets);
				FP_IPSEC6_STATS_ADD(sp->stats, sp_bytes, m_len(m));
				return FP_CONTINUE;
			}
			else {
				TRACE_IPSEC6_OUT(FP_LOG_DEBUG, "discard while negotiating SA");
				FP_IPSEC6_STATS_INC(sp->stats, sp_errors);
				return FP_DROP;
			}
		}

		sp->sa_genid = sa->genid;

		return (*func)(m, sa, sp);
	} else {
		if (likely(!(sp->flags & FP_SP_FLAG_NO_SA_CACHE) && sp->sa_index != 0)) {
			sa = &fp_get_sad6()->table[sp->sa_index];
			/* SA may have disappeared or been replaced */
			if (likely(sa->state != FP_SA_STATE_UNSPEC &&
				sa->genid == sp->sa_genid))
				return ipsec6_output(m, sa, sp);

			/* invalidate SA cache entry */
			sp->sa_index = 0;
		}

		sa = sad6_out_lookup(ip6->ip6_src.fp_s6_addr32, ip6->ip6_dst.fp_s6_addr32,
				    sp->sa_proto, FP_IPSEC_MODE_TRANSPORT, sp->reqid,
				    sp->link_vrfid, m2vrfid(m), 
#ifdef CONFIG_MCORE_IPSEC_SVTI
				    0,
#endif
			 	    &sp->sa_index);

		if (unlikely(sa == NULL)) {
			TRACE_IPSEC6_OUT(FP_LOG_NOTICE, "SA not found");
			FP_IPSEC6_STATS_INC(sp->stats, sp_exceptions);
			return fp_ip_prepare_exception(m, FPTUN_EXC_IKE_NEEDED);
		}

		if (unlikely(sa->state == FP_SA_STATE_ACQUIRE)) {
			if (sp->flags & FP_SP_FLAG_LEVEL_USE) {
				FP_IPSEC6_STATS_INC(sp->stats, sp_packets);
				FP_IPSEC6_STATS_ADD(sp->stats, sp_bytes, m_len(m));
				return FP_CONTINUE;
			}
			else {
				TRACE_IPSEC6_OUT(FP_LOG_DEBUG, "discard while negotiating SA");
				FP_IPSEC6_STATS_INC(sp->stats, sp_errors);
				return FP_DROP;
			}
		}

		sp->sa_genid = sa->genid;

		return ipsec6_output(m, sa, sp);
	}
}

#ifdef CONFIG_MCORE_IPSEC_SVTI
int fp_svti6_output(struct mbuf *m, fp_ifnet_t *ifp)
{
	struct fp_ip6_hdr *ipv6 = mtod(m, struct fp_ip6_hdr *);
	fp_v6_sa_entry_t *sa;
	fp_v6_sp_entry_t *sp;
	uint16_t sport = 0, dport = 0;
	fp_svti_t *svti = &fp_shared->svti[ifp->sub_table_index];

	TRACE_IPSEC6_OUT(FP_LOG_DEBUG, "%s()", __FUNCTION__);

	/* Check IPsec outbound policy
	 * - if IPsec is required and SA not present, send to SP for IKE.
	 * - if tunnel mode, re-route packet:
	 *	o if route not found, send to SP
	 *	o if route to slow path interface, send to SP (bug)
	 * - if transport mode or bypass or discard or no SP, drop packet
	 */

#ifdef CONFIG_MCORE_IPSEC_LOOKUP_PORTS
	if ((unlikely(fp_ipsec6_extract_ports(m, ipv6, &sport, &dport) < 0))) {
		TRACE_IPSEC6_OUT(FP_LOG_INFO, "%s: only %u bytes of protocol %u",
				__FUNCTION__, ntohs(ipv6->ip6_plen), ipv6->ip6_nxt);
		goto drop;
	}
#endif

	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
		return FP_DROP;
	}

	sp = spd6_svti_out_lookup(ipv6->ip6_src.fp_s6_addr32, ipv6->ip6_dst.fp_s6_addr32, 
				  ipv6->ip6_nxt, sport, dport, svti);

	if (likely(sp == NULL)) {
		TRACE_IPSEC6_OUT(FP_LOG_INFO, "%s: no SP", __FUNCTION__);
		goto drop;
	}

	/* ensure it is not an exception for slow path before
	 * incrementing packets/bytes for this sp. */
	if (unlikely(sp->filter.action != FP_SP_ACTION_PROTECT)) {
		FP_IPSEC6_STATS_INC(sp->stats, sp_packets);
		FP_IPSEC6_STATS_ADD(sp->stats, sp_bytes, m_len(m));
		goto drop;
	}

	TRACE_IPSEC6_OUT(FP_LOG_DEBUG, "Protecting %s %s src="FP_NIP6_FMT" dst="FP_NIP6_FMT,
			sp->sa_proto == FP_IPPROTO_AH ? "AH" :"ESP",
			sp->mode == FP_IPSEC_MODE_TUNNEL ? "tunnel" :"transport",
			FP_NIP6(ipv6->ip6_src), FP_NIP6(ipv6->ip6_dst));

	if (likely(sp->mode == FP_IPSEC_MODE_TUNNEL)) {
		int ret;
		int len __fpn_maybe_unused = m_len(m);
		output_func func;

		if (likely(sp->sa_index != 0)) {
			if (sp->outer_family == AF_INET6) {
				sa = &fp_get_sad6()->table[sp->sa_index];
				func = ipsec6_output;
			} else {
				sa = &fp_get_sad()->table[sp->sa_index];
				func = ipsec4_output;
			}
			/* SA may have disappeared or been replaced */
			if (likely(sa->state != FP_SA_STATE_UNSPEC &&
				sa->genid == sp->sa_genid))
				goto send_it;

			/* invalidate SA cache entry */
			sp->sa_index = 0;
		}

		if (sp->outer_family == AF_INET6) {
			sa = sad6_out_lookup(sp->tunnel6_src.fp_s6_addr32,
					     sp->tunnel6_dst.fp_s6_addr32,
					     sp->sa_proto, FP_IPSEC_MODE_TUNNEL, sp->reqid,
					     sp->link_vrfid, m2vrfid(m),
					     sp->svti_ifuid,
					     &sp->sa_index);
			func = ipsec6_output;
		} else {
			sa = sad_out_lookup(sp->tunnel4_src, sp->tunnel4_dst,
					    sp->sa_proto, FP_IPSEC_MODE_TUNNEL, sp->reqid,
					    sp->link_vrfid, m2vrfid(m),
#ifndef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
					    sp->svti_ifuid,
#endif
					    &sp->sa_index);
			func = ipsec4_output;
		}

		if (unlikely(sa == NULL)) {
			TRACE_IPSEC6_OUT(FP_LOG_INFO, "SA not found");
			FP_IPSEC6_STATS_INC(sp->stats, sp_exceptions);
			return fp_ip_prepare_exception(m, FPTUN_EXC_IKE_NEEDED);
		}

		if (unlikely(sa->state == FP_SA_STATE_ACQUIRE)) {
			TRACE_IPSEC6_OUT(FP_LOG_DEBUG, "discard while negotiating SA");
			FP_IPSEC6_STATS_INC(sp->stats, sp_errors);
			return FP_DROP;
		}

		sp->sa_genid = sa->genid;

send_it:
		FP_IF_STATS_INC(ifp->if_stats, ifs_opackets);
		FP_IF_STATS_ADD(ifp->if_stats, ifs_obytes, len);

		ret = (*func)(m, sa, sp);
		if (ret == FP_DROP) {
			FP_IF_STATS_DEC(ifp->if_stats, ifs_opackets);
			FP_IF_STATS_SUB(ifp->if_stats, ifs_obytes, len);
			goto drop;
		}

		return ret;
	}
	TRACE_IPSEC6_OUT(FP_LOG_NOTICE, "%s: transport mode SP", __FUNCTION__);

drop:
	FP_IF_STATS_INC(ifp->if_stats, ifs_oerrors);
	FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
	return FP_DROP;
}
#endif /* CONFIG_MCORE_IPSEC_SVTI */
