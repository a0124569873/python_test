/*
 * Copyright(c) 2006 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-main-process.h"
#include "fp-log.h"
#include "fp-ip.h"

#include "fp-lookup.h"

#include "netipsec/fp-ah.h"
#include "netipsec/fp-esp.h"
#include "netinet/fp-udp.h"

#include "fp-fpib.h"
#include "fp-ipsec-common.h"
#include "fp-ipsec-output.h"
#include "fp-ipsec-lookup.h"
#include "fp-ipsec-replay.h"
#include "fp-ipsec-iv.h"
#include "fpn-crypto.h"
#include "fpn-cksum.h"
#include "fp-dscp.h"
#ifdef CONFIG_MCORE_IPSEC_IPV6
#include "fp-ipsec6-output.h"
#include "fp-ipsec6-lookup.h"
#endif

#define TRACE_IPSEC_OUT(level, fmt, args...) do {			\
		FP_LOG(level, IPSEC_OUT, fmt "\n", ## args);		\
} while(0)

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
#define m_ipsec(m) m_priv(m)->ipsec.m_ipsec_buf
#define m_ipsec_sa(m) m_priv(m)->ipsec.sa
#else
static FPN_DEFINE_PER_CORE(struct m_ipsec_state, m_ipsec_buf_out);
#define m_ipsec(m) FPN_PER_CORE_VAR(m_ipsec_buf_out)
static FPN_DEFINE_PER_CORE(void *, local_sa);
#define m_ipsec_sa(m) FPN_PER_CORE_VAR(local_sa)
#endif

#ifndef HAVE_SPECIFIC_GEN_IV
/* Defined shared instead of per_core, because this data has to be
 * initialized, and there is no per_core init for all archs. */
FPN_DEFINE_SHARED(struct __iv_state[FPN_MAX_CORES], iv_state);
#endif

#ifdef CONFIG_MCORE_ARCH_OCTEON
struct __iv_state iv_state;
#endif

/* Initialize IPsec IV state with random data */
void fp_ipsec_output_init(void)
{
#ifndef HAVE_SPECIFIC_GEN_IV
	unsigned int i;

	for (i=0; i<FPN_MAX_CORES; i++) {
		iv_state[i].t0 = fpn_get_pseudo_rnd();
		iv_state[i].t1 = fpn_get_pseudo_rnd();
	}
#endif

#ifdef CONFIG_MCORE_ARCH_OCTEON
	iv_state.t0 = fpn_get_pseudo_rnd();
	iv_state.t1 = fpn_get_pseudo_rnd();
#endif

	fp_shared->ipsec.output_blade = 0;
}

static inline void init_tunnel4_header(struct fp_ip *ip, uint32_t src, 
				       uint32_t dst, uint8_t tos, uint16_t off,
				       int is_inner_traffic_ipv4)
{
	ip->ip_v = FP_IPVERSION;
	ip->ip_hl = 5;
	ip->ip_tos = tos;
	ip->ip_ttl = FP_IPDEFTTL;
	ip->ip_sum = 0;
	ip->ip_src.s_addr = src;
	ip->ip_dst.s_addr = dst;
	if (is_inner_traffic_ipv4)
		ip->ip_p = FP_IPPROTO_IPIP;
#ifdef CONFIG_MCORE_IPSEC_IPV6
	else
		ip->ip_p = FP_IPPROTO_IPV6;
#endif
	ip->ip_id = fp_ip_get_id();
	ip->ip_off = off;
}

static inline void init_tunnel4_udp_header(struct fp_udphdr *udp, uint16_t sport,
                                           uint16_t dport) {
	udp->uh_sport = sport;
	udp->uh_dport = dport;
	udp->uh_ulen = 0;
	udp->uh_sum = 0;
}

static int ipsec4_output_finish(struct mbuf *m, struct fp_ip *ip)
{
	fp_rt4_entry_t *rt;
	fp_nh4_entry_t *nh;

	/* IP checksum */
	ip->ip_sum = fpn_ip_hdr_cksum(ip, ip->ip_hl << 2);

#ifdef HAVE_HMAC_COMPLETE
	if (fp_ipsec_ctx.auth_type == FP_AALGO_HMACSHA1)
		fpn_hmac_sha1_complete_pass1();
	else if (fp_ipsec_ctx.auth_type == FP_AALGO_HMACSHA256)
		fpn_hmac_sha256_complete_pass1();
	else if (fp_ipsec_ctx.auth_type == FP_AALGO_HMACSHA384)
		fpn_hmac_sha384_complete_pass1();
	else if (fp_ipsec_ctx.auth_type == FP_AALGO_HMACSHA512)
		fpn_hmac_sha512_complete_pass1();
	else if (fp_ipsec_ctx.auth_type == FP_AALGO_HMACMD5)
		fpn_hmac_md5_complete_pass1();
#endif

	m_priv(m)->exc_type = FPTUN_IPV4_IPSECDONE_OUTPUT_EXCEPT;
	m_priv(m)->flags |= M_LOCAL_OUT|M_IPSEC_OUT;
	if (fp_shared->conf.w32.do_func & FP_CONF_DO_IPSEC_ONCE)
		m_priv(m)->flags |= M_IPSEC_BYPASS;

#ifdef HAVE_HMAC_COMPLETE
	if (fp_ipsec_ctx.auth_type == FP_AALGO_HMACMD5)
		fpn_hmac_md5_complete_pass2();
#endif
	rt = fp_rt4_lookup(m2vrfid(m), ip->ip_dst.s_addr); 
	if (rt == NULL) {
		TRACE_IPSEC_OUT(FP_LOG_INFO, "ipsec4_output_finish: could not route packet");
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoRouteLocal);
		return FP_DROP;
	}
	nh = select_nh4(rt, &ip->ip_src.s_addr);
	FP_IP_STATS_INC(fp_shared->ip_stats, IpForwDatagrams);

#ifdef HAVE_HMAC_COMPLETE
	if (fp_ipsec_ctx.auth_type == FP_AALGO_HMACSHA1)
		fpn_hmac_sha1_complete_pass2();
	else if (fp_ipsec_ctx.auth_type == FP_AALGO_HMACSHA256)
		fpn_hmac_sha256_complete_pass2();
	else if (fp_ipsec_ctx.auth_type == FP_AALGO_HMACSHA384)
		fpn_hmac_sha384_complete_pass2();
	else if (fp_ipsec_ctx.auth_type == FP_AALGO_HMACSHA512)
		fpn_hmac_sha512_complete_pass2();
	else if (fp_ipsec_ctx.auth_type == FP_AALGO_HMACMD5)
		fpn_hmac_md5_complete_pass3();
#endif

#ifndef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	/* store the result in memory */
	if ((fp_ipsec_ctx.proto == FP_IPPROTO_ESP) && (fp_ipsec_ctx.auth_data != NULL)) {
		uint32_t alen = fp_ipsec_ctx.authsize;
		m_copyfrombuf(m, m_len(m) - alen, fp_ipsec_ctx.auth_data, alen);
	}

	if (fp_ipsec_ctx.proto == FP_IPPROTO_AH)
		memcpy(fp_ipsec_ctx.auth_data, m_ipsec(m).out_auth, fp_ipsec_ctx.authsize);

	fp_ipsec_ctx.proto = FP_IPPROTO_MAX;
#endif

	return fp_ip_output(m, rt, nh);
}

static inline int ah4_output_finish(struct mbuf *m, struct fp_ip *ip)
{
	ip->ip_ttl = m_ipsec(m).ip_ttl;
	ip->ip_tos = m_ipsec(m).ip_tos;
	ip->ip_off = m_ipsec(m).ip_off;

	return ipsec4_output_finish(m, ip);
}

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
static void ah4_output_cb(__fpn_maybe_unused void * opaque, struct mbuf *m, int res)
{
	fp_sa_entry_t *sa = m_ipsec_sa(m);

	TRACE_IPSEC_OUT(FP_LOG_DEBUG, "%s()", __FUNCTION__);

	if (sa && (sa->flags & FP_SA_FLAG_ESN)) {
		m_trim(m, sizeof(uint32_t));
		TRACE_IPSEC_OUT(FP_LOG_NOTICE, "%s: ESN async finish len=%d",
				__FUNCTION__, m_len(m));
	}

	if (res >= 0) {
		res = ah4_output_finish(m, mtod(m, struct fp_ip *));
	} else {
		res = FP_DROP;
	}

	fp_process_input_finish(m, res);
}
#endif

/* Check if one mbuf is ipv4 packet.
 * Return 1 on success, else return 0
 */
static inline int is_ipv4_packet(struct mbuf *m)
{
#ifdef CONFIG_MCORE_IPSEC_IPV6
	struct fp_ip* ip;

	ip = mtod(m, struct fp_ip *);
	return (ip->ip_v == FP_IPVERSION);
#else
	/* Cannot be anything else. */
	(void)m;
	return 1;
#endif
}

static inline int ah4_output(struct mbuf *m, fp_sa_entry_t *sa)
{
	struct fp_ip *ip = mtod(m, struct fp_ip *);
#ifdef CONFIG_MCORE_IPSEC_IPV6
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
#endif
	struct fp_ah *ah;
	uint16_t authsize;
	uint64_t oseq;
	int is_ipv4 = is_ipv4_packet(m);

	authsize = sa->authsize;

#ifdef CONFIG_MCORE_DEBUG
	if (likely(is_ipv4)) {
		if (ntohs(ip->ip_len) != m_len(m)) {
			TRACE_IPSEC_OUT(FP_LOG_INFO, "ip len mismatch %u %u",
					ntohs(ip->ip_len), m_len(m));
		}
	}
#ifdef CONFIG_MCORE_IPSEC_IPV6
	else {
		if (ntohs(ip6->ip6_plen) + sizeof(struct fp_ip6_hdr) != m_len(m)) {
			TRACE_IPSEC_OUT(FP_LOG_INFO, "ip6 len mismatch %zu %u",
					ntohs(ip6->ip6_plen) + sizeof(struct fp_ip6_hdr),
					m_len(m));
		}
	}
#endif
#endif


	if (likely(sa->mode == FP_IPSEC_MODE_TUNNEL)) {
		uint8_t tos = 0;
		uint16_t off = 0;

		set_mvrfid(m, sa->vrfid);

		if (unlikely(!(sa->flags & FP_SA_FLAG_DONT_ENCAPDSCP))) {
			if (likely(is_ipv4))
				tos = fp_dscp_copy(ip->ip_tos, tos);
#ifdef CONFIG_MCORE_IPSEC_IPV6
			else
				/* save DSCP (optional) of inner ipv6 packet*/
				tos = fp_get_ipv6_tc(ip6);
#endif
		}

		if (likely(is_ipv4)) {
			if (likely(!(sa->flags & FP_SA_FLAG_NOPMTUDISC)))
				off = ip->ip_off & htons(FP_IP_DF);
		}

		/* Update TTL of inner IP packet (from bsd netinet/ip_flow.c) */
		if (likely(is_ipv4)) {
			ip->ip_ttl -= FP_IPTTLDEC;
			if (unlikely(ip->ip_sum >= htons(0xffff - (FP_IPTTLDEC << 8))))
				ip->ip_sum += htons(FP_IPTTLDEC << 8) + 1;
			else
				ip->ip_sum += htons(FP_IPTTLDEC << 8);
		}
#ifdef CONFIG_MCORE_IPSEC_IPV6
		else
			ip6->ip6_hlim -= FP_IPTTLDEC;
#endif

		ip = (struct fp_ip *)m_prepend(m, sa->ahsize + sizeof(struct fp_ip));
		if (unlikely(ip == NULL)) {
			TRACE_IPSEC_OUT(FP_LOG_WARNING, "%s: failed to prepend %u bytes", __FUNCTION__, (unsigned int)(sa->ahsize + sizeof(struct fp_ip)));
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
			return FP_DROP;
		}
		init_tunnel4_header(ip, sa->src4, sa->dst4, tos, off, is_ipv4);
		ah = (struct fp_ah *)((char*)ip + sizeof(struct fp_ip));
	} else {
		struct fp_ip save_ip;

		fpn_ipv4hdr_copy(&save_ip, ip, sizeof(struct fp_ip));
		ip = (struct fp_ip *)m_prepend(m, sa->ahsize);
		if (unlikely(ip == NULL)) {
			TRACE_IPSEC_OUT(FP_LOG_WARNING, "%s: failed to prepend %u bytes", __FUNCTION__,
					(unsigned int)(sa->ahsize));
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
			return FP_DROP;
		}
		fpn_ipv4hdr_copy((char *)ip, &save_ip, sizeof(struct fp_ip));
		ah = (struct fp_ah *)((char*)ip + sizeof(struct fp_ip));
	}

	/* data---------------
	 *     | IP
	 *   ah---------------
	 *     | AH header 
	 *     | authenticator
	 *     |--------------
	 *     | data
	 *     |--------------
	 */

	ah->ah_nxt = ip->ip_p;
	ah->ah_len = sa->ah_len;
	ah->ah_reserve = 0;
	ah->ah_spi = sa->spi;

	/* Insert packet replay counter, as requested.  */
	oseq = ipsec_inc_oseq(&sa->replay
#if defined(CONFIG_MCORE_FPE_VFP)
			, sa->index, 0
#endif
			);
	ah->ah_seq = htonl((uint32_t)oseq);

	/* fix IP header length */
	ip->ip_len = htons(m_len(m));

	/* fix next header field */
	ip->ip_p = FP_IPPROTO_AH;

	m_ipsec(m).ip_ttl = ip->ip_ttl;
	m_ipsec(m).ip_tos = ip->ip_tos;
	m_ipsec(m).ip_off = ip->ip_off;
	ip->ip_ttl = 0;
	ip->ip_tos = 0;
	ip->ip_off = 0;

	ip->ip_sum = 0;
	/* zeroizea uthenticator */
	memset(ah->auth_data, 0, authsize);

	if (sa->flags & FP_SA_FLAG_ESN) {
		uint32_t seq_hi = htonl((uint32_t)(oseq >> 32));
		char *p;

		p = m_append(m, 4);
		if (p)
			memcpy(p, &seq_hi, 4);
		else if (m_copyfrombuf(m, m_len(m), &seq_hi, 4) != 4) {
			TRACE_IPSEC_OUT(FP_LOG_NOTICE, "%s: m_copyfrombuf failure",
					__FUNCTION__);
			return FP_DROP;
		}
		TRACE_IPSEC_OUT(FP_LOG_NOTICE, "%s: ESN seq_hi=0x%.8"PRIx32" len=%d",
				__FUNCTION__, ntohl(seq_hi), m_len(m));
	}
#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	{
		uint16_t __fpn_maybe_unused nbytes = m_len(m);
		uint16_t  __fpn_maybe_unused off_auth_src = 0;
		char * __fpn_maybe_unused mbase = (char*)ip;

		m_priv(m)->flags |= M_ASYNC;
		m_ipsec_sa(m) = sa;

		if ((fp_check_sa(sa, &sa_ctx[sa->index], FP_DIR_OUT) < 0) ||
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
					  ah4_output_cb,
					  sa_ctx[sa->index].priv[FP_DIR_OUT]) < 0)) {
			m_freem(m);
			return FP_DONE;
		}

		return FP_KEEP;
	}

#else /* ! sync */

	{
		fp_ipsec_ctx.proto = FP_IPPROTO_AH;
		if (sa->alg_auth == FP_AALGO_HMACMD5) {
			fpn_hmac_md5(m_ipsec(m).out_auth, sa->key_auth,
					m, 0, m_len(m), sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACMD5;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA1) {
			fpn_hmac_sha1(m_ipsec(m).out_auth, sa->key_auth,
						 m, 0, m_len(m), sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA1;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA256) {
			fpn_hmac_sha256(m_ipsec(m).out_auth, sa->key_auth,
					m, 0, m_len(m), sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA256;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA384) {
			fpn_hmac_sha384(m_ipsec(m).out_auth, sa->key_auth,
					m, 0, m_len(m), sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA384;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA512) {
			fpn_hmac_sha512(m_ipsec(m).out_auth, sa->key_auth,
					m, 0, m_len(m), sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA512;
		}
		else if (sa->alg_auth == FP_AALGO_AESXCBC)
			fpn_aes_xcbc_mac(m_ipsec(m).out_auth, sa->key_auth,
					m, 0, m_len(m));

		if (sa->flags & FP_SA_FLAG_ESN) {
			m_trim(m, 4);
			TRACE_IPSEC_OUT(FP_LOG_NOTICE, "%s: ESN sync finish len=%d",
					__FUNCTION__, m_len(m));
		}
	}
	fp_ipsec_ctx.auth_data = ah->auth_data;
	fp_ipsec_ctx.authsize = authsize;

	return ah4_output_finish(m, ip);
#endif
}

static inline int esp4_output_finish(struct mbuf *m, struct fp_ip *ip)
{
	return ipsec4_output_finish(m, ip);
}

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
static void esp4_output_cb(__fpn_maybe_unused void * opaque, struct mbuf *m, int res)
{
	fp_sa_entry_t * sa = m_ipsec_sa(m);

#ifndef HAVE_MAPPEND_ALLOC_SUPPORT
	if (unlikely(m_ipsec(m).flags & M_PRIV_OOPLACE_ICV))
		m_copyfrombuf(m, m_len(m), m_ipsec(m).out_auth, sa->authsize);
#endif

	/*
	 * In GCM/GMAC mode, restore spi overwritten by seq_hi,
	 * restore original packet data overwritten by spi.
	 */
	if (sa && (sa->flags & FP_SA_FLAG_ESN)
		&& ((sa->alg_enc == FP_EALGO_AESGCM) ||
		(sa->alg_enc == FP_EALGO_NULL_AESGMAC))) {
		uint32_t *esp = m_priv(m)->ipsec.esp;

		*esp = *(esp - 1);
		*(esp - 1) = m_priv(m)->ipsec.back;
		TRACE_IPSEC_OUT(FP_LOG_NOTICE, "%s: ESN async(aes) finish spi=0x%.8"PRIx32"",
					__FUNCTION__, ntohl(*esp));
	}

	if (res >= 0) {
		res = esp4_output_finish(m, mtod(m, struct fp_ip *));
	} else {
		res = FP_DROP;
	}

	fp_process_input_finish(m, res);
}
#endif

static inline int esp4_output(struct mbuf *m, fp_sa_entry_t *sa)
{
	struct fp_ip *ip = mtod(m, struct fp_ip *);
#ifdef CONFIG_MCORE_IPSEC_IPV6
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
#endif
	struct fp_udphdr *udp = NULL;
	struct fp_esp *esp;
	uint16_t ivlen, blks;
	unsigned int trailer, rlen;
#if defined(HAVE_NOTINPLACE_CIPHER)
	uint16_t __fpn_maybe_unused m_src_offset = 0, m_dst_offset = 0;
	struct mbuf * __fpn_maybe_unused m_src = m;
#endif
	char *authdata;
	char *pad;
#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
#ifndef HAVE_MAPPEND_ALLOC_SUPPORT
	char padbuf[FP_MAX_KEY_ENC_LENGTH + 2];
#endif
#else
	int __fpn_maybe_unused is_contiguous;
#endif
	unsigned int i;
	uint8_t alen;
	unsigned int mask;
	uint32_t *tmp;
#ifdef HAVE_CRYPTO_PREHANDLE
	unsigned int unen_len;
	int optimize = 0;
	uint64_t *pre_enc_data = NULL;
	int pre_xdes_enc = 0;
#endif
	uint64_t oseq;
	int is_ipv4 = is_ipv4_packet(m);

#ifdef CONFIG_MCORE_DEBUG
	if (likely(is_ipv4)) {
		if (ntohs(ip->ip_len) != m_len(m))
			TRACE_IPSEC_OUT(FP_LOG_INFO, "ip len mismatch %u %u\n",
					ntohs(ip->ip_len), m_len(m));
	}
#ifdef CONFIG_MCORE_IPSEC_IPV6
	else {
		if (ntohs(ip6->ip6_plen) + sizeof(struct fp_ip6_hdr) != m_len(m))
			TRACE_IPSEC_OUT(FP_LOG_INFO, "ip6 len mismatch %zu %u\n",
					 ntohs(ip6->ip6_plen) + sizeof(struct fp_ip6_hdr),
					 m_len(m));
	}
#endif
#endif
	/* check packet size early, including trailer */

	ivlen = sa->ivlen;
	blks = sa->blocksize;
	alen = sa->authsize;
	mask = blks - 1;

#if defined(HAVE_NOTINPLACE_CIPHER) && defined(CONFIG_MCORE_FPN_MBUF_CLONE)
	/* If mbuf is shared and algo is != from ESP NULL, we allocate a new mbuf to put
	 * encrypted data directly into it. Hence, we need to build it like the orignal mbuf.
	 */
	if (unlikely(m_is_shared(m) && sa->alg_enc != FP_EALGO_NULL)) {
		struct mbuf *m_dst = m_alloc();
		struct sbuf *s_src, *s_dst = NULL;
		struct fp_ip *ip_dst;
		int first;

		if (unlikely(m_dst == NULL)) {
			TRACE_IPSEC_OUT(FP_LOG_WARNING, "m_alloc() failed");
			return FP_DROP;
		}

		/* copy input port */
		m_set_input_port(m_dst, m_input_port(m));
		/* copy mbuf_priv */
		memcpy(mtopriv(m_dst, void *), mtopriv(m, void *),
		       FPN_MBUF_PRIV_COPY_SIZE);
		first = 1;
		M_FOREACH_SEGMENT(m, s_src) {
			if (s_len(s_src) == 0)
				continue;

			if (first) {
				s_dst = m_first_seg(m_dst);
				first = 0;
			} else {
				s_dst = __m_add_seg(m_dst, s_dst);
				if (unlikely(s_dst == NULL)) {
					TRACE_IPSEC_OUT(FP_LOG_WARNING,
							"__m_add_seg() failed");
					m_freem(m_dst);
					return FP_DROP;
				}
			}
			__s_append(s_dst, s_len(s_src));
			m_len(m_dst) += s_len(s_src);
		}

		ip_dst = (struct fp_ip *)mtod(m_dst, struct fp_ip *);
		fpn_ipv4hdr_copy(ip_dst, ip, ip->ip_hl << 2);
		m_src_offset = ip->ip_hl << 2;

		/* Now we can work on m_dst. */
		ip = ip_dst;
		m = m_dst;
	}
#endif

	/* Reset flags */
	m_ipsec(m).flags  = 0;

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
		uint8_t tos = 0;
		uint16_t off = 0;
		uint32_t size = ivlen + sizeof(struct fp_esp) + sizeof(struct fp_ip);
		unsigned int mask = blks -1;

		set_mvrfid(m, sa->vrfid);

		if (unlikely(!(sa->flags & FP_SA_FLAG_DONT_ENCAPDSCP))) {
			if (likely(is_ipv4))
				tos = fp_dscp_copy(ip->ip_tos, tos);
#ifdef CONFIG_MCORE_IPSEC_IPV6
			else
				/* save DSCP (optional) of inner ipv6 packet*/
				tos = fp_get_ipv6_tc(ip6);
#endif
		}

		if (likely(is_ipv4)) {
			if (likely(!(sa->flags & FP_SA_FLAG_NOPMTUDISC)))
				off = ip->ip_off & htons(FP_IP_DF);
		}

		/* Update TTL of inner IP packet (from bsd netinet/ip_flow.c) */
		if (likely(is_ipv4)) {
			ip->ip_ttl -= FP_IPTTLDEC;
			if (unlikely(ip->ip_sum >= htons(0xffff - (FP_IPTTLDEC << 8))))
				ip->ip_sum += htons(FP_IPTTLDEC << 8) + 1;
			else
				ip->ip_sum += htons(FP_IPTTLDEC << 8);
		}
#ifdef CONFIG_MCORE_IPSEC_IPV6
		else
			ip6->ip6_hlim -= FP_IPTTLDEC;
#endif

		rlen = m_len(m);

		/* trailer = ((blks - ((rlen + 2) % blks)) % blks) + 2 */
		/* trailer = 2 bytes (padd len + next header) aligned on block size */
		trailer = (mask+2) - ((rlen+1) & mask);

		if (unlikely(sa->flags & FP_SA_FLAG_UDPTUNNEL))
			size += sizeof(struct fp_udphdr);
#if defined(HAVE_NOTINPLACE_CIPHER) && defined(CONFIG_MCORE_FPN_MBUF_CLONE)
		if (unlikely(m != m_src))
			m_dst_offset = m_src_offset + size;
#endif
		ip = (struct fp_ip *)m_prepend(m, size);

		if (unlikely(ip == NULL)) {
			TRACE_IPSEC_OUT(FP_LOG_WARNING, "m_prepend(%d) failed", size);
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
#if defined(HAVE_NOTINPLACE_CIPHER) && defined(CONFIG_MCORE_FPN_MBUF_CLONE)
			if (m != m_src)
				m_freem(m);
#endif
			return FP_DROP;
		}
		init_tunnel4_header(ip, sa->src4, sa->dst4, tos, off, is_ipv4);
		if (unlikely(sa->flags & FP_SA_FLAG_UDPTUNNEL)) {
			udp = (struct fp_udphdr *)(ip + 1);
			init_tunnel4_udp_header(udp, sa->sport, sa->dport);
			esp = (struct fp_esp *)(udp + 1);
		} else
			esp = (struct fp_esp *)(ip + 1);
	} else {
		struct fp_ip save_ip;
		uint32_t size = ivlen + sizeof(struct fp_esp);

		rlen = m_len(m) - sizeof(struct fp_ip); 
		trailer = (mask+2) - ((rlen+1) & mask);

#if defined(HAVE_NOTINPLACE_CIPHER) && defined(CONFIG_MCORE_FPN_MBUF_CLONE)
		if (unlikely(m != m_src))
			m_dst_offset = m_src_offset + size;
#endif
		fpn_ipv4hdr_copy(&save_ip, ip, sizeof(struct fp_ip));
		ip = (struct fp_ip *)m_prepend(m, size);

		if (unlikely(ip == NULL)) {
			TRACE_IPSEC_OUT(FP_LOG_WARNING, "m_prepend(%d) failed", size);
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
#if defined(HAVE_NOTINPLACE_CIPHER) && defined(CONFIG_MCORE_FPN_MBUF_CLONE)
			if (m != m_src)
				m_freem(m);
#endif
			return FP_DROP;
		}

		fpn_ipv4hdr_copy((char *)ip, &save_ip, sizeof(struct fp_ip));
		
		esp = (struct fp_esp *)((char*)ip + sizeof(struct fp_ip));
	}

	/* data---------------
	 *     | IP
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
		COPY_PACKET_IV(m_ipsec(m).iv, &sa->key_enc[sa->key_enc_len], 4);
		COPY_PACKET_IV(&m_ipsec(m).iv[4], esp->enc_data, 8);
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
	if (likely(optimize)) {
		FPN_AES_CBC_PRE_ENCRYPT(0);
		FPN_XDES_CBC_PRE_ENCRYPT(0);
	}
#endif

	/* replay counter */
	oseq = ipsec_inc_oseq(&sa->replay
#if defined(CONFIG_MCORE_FPE_VFP)
			, sa->index, 0
#endif
			);
	esp->esp_seq = htonl((uint32_t)oseq);

	/* fix IP header length */
	ip->ip_len = htons(m_len(m) + trailer + alen);

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
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
#if defined(HAVE_NOTINPLACE_CIPHER) && defined(CONFIG_MCORE_FPN_MBUF_CLONE)
		if (m != m_src)
			m_freem(m);
#endif
		return FP_DROP;
	}
#else /* HAVE_MAPPEND_ALLOC_SUPPORT */
	if (unlikely(pad == NULL)) {
		/* pad in a buffer, and then copy to mbuf */
#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
		pad = padbuf;
		authdata = m_ipsec(m).out_auth;
		m_ipsec(m).flags |= M_PRIV_OOPLACE_ICV;
#else
		pad = fp_ipsec_ctx.padbuf;
		authdata = pad + trailer;
#endif
	}
#endif

	/* Fill padding with numbers in sequence (1,2,3...).
	 * Write what we can 4 by 4, it is quicker than 1 by 1.
	 */
	tmp = (uint32_t *) pad;
#if defined(CONFIG_MCORE_ARCH_XLP) && defined(CONFIG_MCORE_FPE_MCEE)
	for (i = 0; (i + 4) < trailer - 2; i+=4)
		*tmp++ = 0x01020304 + ((i / 4) * 0x04040404);
#else
	for (i = 0; (i + 4) < trailer - 2; i+=4)
#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
		*tmp++ = (((i + 1) << 24) + ((i + 2) << 16) + ((i + 3) << 8) + i + 4);
#else
		*tmp++ = (((i + 4) << 24) + ((i + 3) << 16) + ((i + 2) << 8) + i + 1);
#endif
#endif

#ifdef HAVE_CRYPTO_PREHANDLE
	if (likely(optimize)) {
		FPN_AES_CBC_PRE_ENCRYPT(i);
		FPN_XDES_CBC_PRE_ENCRYPT(i);
	}
#endif

	/* Finish to fill the padding */
	for (; i < trailer - 2; i++)
		pad[i] = i + 1;
	/* Fill trailer (padlen and nh) */
	pad[trailer-2] = trailer - 2;
	pad[trailer-1] = ip->ip_p;

#ifndef HAVE_MAPPEND_ALLOC_SUPPORT
	if (unlikely(m_ipsec(m).flags & M_PRIV_OOPLACE_ICV))
		m_copyfrombuf(m, m_len(m), pad, trailer);
#endif

	if (unlikely(udp != NULL)) {
		ip->ip_p = FP_IPPROTO_UDP;
		/* fix UDP length */
		udp->uh_ulen = htons(m_len(m) - sizeof(struct fp_ip));
	} else {
		/* fix next header field */
		ip->ip_p = FP_IPPROTO_ESP;
	}

	/* Save SA pointer in mbuf */
	m_ipsec_sa(m) = sa;

#ifdef HAVE_CRYPTO_PREHANDLE
	/* After padding, there is one block at least that can be encrypted */
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
			iv = m_ipsec(m).iv;

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
					TRACE_IPSEC_OUT(FP_LOG_NOTICE, "%s: ESN async(aes) back=0x%.8"PRIx32" seq_hi=0x%.8"PRIx32" len=%d",
							__FUNCTION__, ntohl(m_priv(m)->ipsec.back), ntohl(seq_hi), m_len(m));
				/*
				 * In other mode, write seq_hi at the end of packet data.
				 * It would be overwritten by authentication data later.
				 */
				} else {
					m_copyfrombuf(m, m_len(m) - alen, &seq_hi, sizeof(uint32_t));
					TRACE_IPSEC_OUT(FP_LOG_NOTICE, "%s: ESN async seq_hi=0x%.8"PRIx32" len=%d",
							__FUNCTION__, ntohl(seq_hi), m_len(m));
				}
				authlen += sizeof(uint32_t);
			}

			if (likely(sa->alg_enc != FP_EALGO_NULL)) {
				if ((fp_check_sa(sa, &sa_ctx[sa->index], FP_DIR_OUT) < 0) ||
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
								 (uint8_t*)authdata,
								 authlen,
								 m_src_offset,
								 m_dst_offset,
								 m, /* m_dst */
								 FPN_ENCRYPT,
#if defined(HAVE_NOTINPLACE_CIPHER) && defined(CONFIG_MCORE_FPN_MBUF_CLONE)
								 m_src,
#else
								 m,
#endif
								 esp4_output_cb,
								 sa_ctx[sa->index].priv[FP_DIR_OUT]) < 0)) {
					m_freem(m);
					return FP_DONE;
				}
			} else {
				if ((fp_check_sa(sa, &sa_ctx[sa->index], FP_DIR_OUT) < 0) ||
				    (FPN_ASYNC_CRYPTO_AUTH(sa->alg_auth,
							  sa->key_auth,
							  FP_MAX_KEY_AUTH_LENGTH,
							  auth_data - mbase,
							  (uint8_t*)authdata,
							  authlen,
							  0, /* m_src_off */
							  0, /* m_dst_off */
							  m, /* m_dst */
							  FPN_ENCRYPT,
							  m,
							  esp4_output_cb,
							  sa_ctx[sa->index].priv[FP_DIR_OUT]) < 0)) {
					m_freem(m);
					return FP_DONE;
				}
			}
		}
		else {
			if (likely(sa->alg_enc != FP_EALGO_NULL)) {
				if ((fp_check_sa(sa, &sa_ctx[sa->index], FP_DIR_OUT) < 0) ||
				    (FPN_ASYNC_CRYPTO_CIPHER(sa->alg_enc,
							    (uint64_t*)sa->key_enc,
							    sa->key_enc_len,
							    enc_data - mbase,
							    enc_len,
							    iv - mbase,
							    ivlen,
							    m_src_offset,
							    m_dst_offset,
							    m, /* m_dst */
							    FPN_ENCRYPT,
#if defined(HAVE_NOTINPLACE_CIPHER) && defined(CONFIG_MCORE_FPN_MBUF_CLONE)
							    m_src,
#else
							    m,
#endif
							    esp4_output_cb,
							    sa_ctx[sa->index].priv[FP_DIR_OUT]) < 0)) {
					m_freem(m);
					return FP_DONE;
				}
			}
			else {
				/* ESP-NULL without auth, do it sync */
				return esp4_output_finish(m, ip);
			}
		}
		return FP_KEEP;
	}

#else /* sync */

	if (alen && (sa->flags & FP_SA_FLAG_ESN)) {
		uint32_t seq_hi = htonl((uint32_t)(oseq >> 32));

		m_copyfrombuf(m, m_len(m) - alen, &seq_hi, sizeof(uint32_t));
		TRACE_IPSEC_OUT(FP_LOG_NOTICE, "%s: ESN seq_hi=0x%.8"PRIx32" len=%d",
				__FUNCTION__, ntohl(seq_hi), m_len(m));
	}
	is_contiguous = m_is_contiguous(m);

#ifdef HAVE_AESHMACSHA1
	if (condition_enc_aescbc_hmacsha1(is_contiguous, ivlen + rlen + trailer) &&
	    (sa->alg_auth == FP_AALGO_HMACSHA1) && (sa->alg_enc == FP_EALGO_AESCBC)) {
		/* start encrypting from the IV field */
		fpn_aes_cbc_encrypt_hsha1((char *)esp, ivlen + rlen + trailer,
					 (uint64_t *)sa->key_enc,
					 sa->key_enc_len,
					 m_tail(m) - alen,
					 sa->key_auth, sa->ipad, sa->opad);

		fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA1;
		return esp4_output_finish(m, ip);
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
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA256;
			fpn_aes_cbc_encrypt_hsha256((char *)esp, ivlen + rlen + trailer,
						(uint64_t *)sa->key_enc,
						sa->key_enc_len,
						m_tail(m) - alen,
						sa->key_auth, sa->ipad, sa->opad);
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA384){
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA384;
			fpn_aes_cbc_encrypt_hsha384((char *)esp, ivlen + rlen + trailer,
						(uint64_t *)sa->key_enc,
						sa->key_enc_len,
						m_tail(m) - alen,
						sa->key_auth, sa->ipad, sa->opad);
		}
		else {  // must be FP_AALGO_HMACSHA512
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA512;
			fpn_aes_cbc_encrypt_hsha512((char *)esp, ivlen + rlen + trailer,
						(uint64_t *)sa->key_enc,
						sa->key_enc_len,
						m_tail(m) - alen,
						sa->key_auth, sa->ipad, sa->opad);
		}
		
		return esp4_output_finish(m, ip);
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
		fp_ipsec_ctx.auth_type = FP_AALGO_HMACMD5;
		return esp4_output_finish(m, ip);
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

		fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA1;
		return esp4_output_finish(m, ip);
	}
#endif

#ifdef HAVE_3DESHMACMD5
	/* An example with 3des-hmac-md5 crypto function */
	if (condition_enc_3descbc_hmacmd5(is_contiguous, ivlen + rlen + trailer) &&
	    (sa->alg_auth == FP_AALGO_HMACMD5) && (sa->alg_enc == FP_EALGO_3DESCBC)) {
		/* start encrypting from the IV field */
		fpn_3des_cbc_encrypt_hmd5((char *)esp, ivlen + rlen + trailer,
				(uint64_t *)sa->key_enc,
				m_tail(m) - alen,
				sa->key_auth, sa->ipad, sa->opad);
		fp_ipsec_ctx.auth_type = FP_AALGO_HMACMD5;
		return esp4_output_finish(m, ip);
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

		fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA1;
		return esp4_output_finish(m, ip);
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
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA256;
		}
		else if(sa->alg_auth == FP_AALGO_HMACSHA384){
			fpn_des_cbc_encrypt_hsha384((char *)esp, ivlen + rlen + trailer,
					(uint64_t *)sa->key_enc,
					m_tail(m) - alen,
					sa->key_auth, sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA384;
		}
		else{
			fpn_des_cbc_encrypt_hsha512((char *)esp, ivlen + rlen + trailer,
					(uint64_t *)sa->key_enc,
					m_tail(m) - alen,
					sa->key_auth, sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA512;
		}
		return esp4_output_finish(m, ip);
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
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA256;
		}
		else if(sa->alg_auth == FP_AALGO_HMACSHA384){
			fpn_3des_cbc_encrypt_hsha384((char *)esp, ivlen + rlen + trailer,
						(uint64_t *)sa->key_enc,
						m_tail(m) - alen,
						sa->key_auth, sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA384;
		}
		else{
			fpn_3des_cbc_encrypt_hsha512((char *)esp, ivlen + rlen + trailer,
						(uint64_t *)sa->key_enc,
						m_tail(m) - alen,
						sa->key_auth, sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA512;
		}
	return esp4_output_finish(m, ip);
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
		fp_ipsec_ctx.auth_type = FP_AALGO_HMACMD5;
		return esp4_output_finish(m, ip);
	}
#endif

	/* for no algorithm chaining support */
	{
		/* start encrypting from the IV field */
		unsigned int nbytes = ivlen + rlen + trailer;
		uint64_t *src = (uint64_t *)esp->enc_data;
		uint16_t off = (char*)src - mtod(m, char*);

		/* use the ivlen bytes before the IV field as the real IV */
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

		fp_ipsec_ctx.proto = FP_IPPROTO_ESP;
		if (sa->alg_auth == FP_AALGO_HMACMD5) {
			fpn_hmac_md5(authdata, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACMD5;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA1) {
			fpn_hmac_sha1(authdata, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA1;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA256) {
			fpn_hmac_sha256(authdata, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA256;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA384) {
			fpn_hmac_sha384(authdata, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA384;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA512) {
			fpn_hmac_sha512(authdata, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA512;
		}
		else if (sa->alg_auth == FP_AALGO_AESXCBC)
			fpn_aes_xcbc_mac(authdata, sa->key_auth,
					m, off, authlen);

		fp_ipsec_ctx.auth_data = authdata;
		fp_ipsec_ctx.authsize = alen;
	}

	return esp4_output_finish(m, ip);
#endif
}

/* m must not share segments with another mbuf */
static inline int __local_ipsec4_output(struct mbuf *m, fp_sa_entry_t *sa,
					fp_sp_entry_t *sp)
{
	uint16_t len __fpn_maybe_unused = m_len(m);
	int ret;

#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
	/*
	 * If output sequence number has reached the limit, directly drop
	 * packet.
	 */
	if (ipsec_chk_max_oseq(&sa->replay, sa->flags & FP_SA_FLAG_ESN)) {
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
		return FP_DROP;
	}
#endif

#ifndef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	/* Initialize ipsec context structure */
	/* Never enter esp4_input or ah4_input without this */
	fp_ipsec_ctx.auth_type = FP_AALGO_NULL;
	fp_ipsec_ctx.authsize = 0;
	fp_ipsec_ctx.auth_data = NULL;
	fp_ipsec_ctx.proto = FP_IPPROTO_MAX;
#endif

	FP_IPSEC_STATS_INC(sp->stats, sp_packets);
	FP_IPSEC_STATS_ADD(sp->stats, sp_bytes, len);
	FP_IPSEC_STATS_INC(sa->stats, sa_packets);
	FP_IPSEC_STATS_ADD(sa->stats, sa_bytes, len);
	if (likely(sa->proto == FP_IPPROTO_ESP))
		ret = esp4_output(m, sa);
	else
		ret = ah4_output(m, sa);

	/* output sequence number is incremented in esp/ah4_output */
#ifdef CONFIG_MCORE_MULTIBLADE
	if (unlikely(++sa->replay.last_sync >= fp_shared->ipsec.sa_replay_sync_threshold)) {
		sa->replay.last_sync = 0;
		ipsec_sa_sync(sa);
	}
#endif

	if (likely(ret == FP_DONE))
		return FP_DONE;
#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	if (ret == FP_KEEP)
		return FP_KEEP;
#endif
	if (ret == FP_NONE) {
		FP_IPSEC_STATS_INC(sp->stats, sp_exceptions);
		return FP_NONE;
	}

	FP_IPSEC_STATS_DEC(sp->stats, sp_packets);
	FP_IPSEC_STATS_SUB(sp->stats, sp_bytes, len);
	FP_IPSEC_STATS_DEC(sa->stats, sa_packets);
	FP_IPSEC_STATS_SUB(sa->stats, sa_bytes, len);
	FP_IPSEC_STATS_INC(sp->stats, sp_errors);
	FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
	return ret;
}

static int local_ipsec4_output(struct mbuf *m, fp_sa_entry_t *sa,
				      fp_sp_entry_t *sp)
{
#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
	int ret;
	struct mbuf *m2;

#if defined (CONFIG_MCORE_ARCH_XLP) && defined (CONFIG_MCORE_FPE_MCEE)
	/* This scenario is optimized on XLP, no need to perform
	 * a m_dup().
	 */
	if (m_is_shared(m) &&
	    sa->proto == FP_IPPROTO_ESP &&
	    sa->alg_enc != FP_EALGO_NULL)
		return __local_ipsec4_output(m, sa, sp);
#endif

	m2 = m_unclone(m);

	/* mbuf was not a clone */
	if (likely(m2 == m))
		return __local_ipsec4_output(m, sa, sp);

	if (m2 == NULL) {
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoMemory);
		return FP_DONE;
	}

	/* m2 is a new packet because m was a clone */
	ret = __local_ipsec4_output(m2, sa, sp);
	fp_process_input_finish(m2, ret);

	return FP_DONE;
#else
	return __local_ipsec4_output(m, sa, sp);
#endif
}

int ipsec4_output(struct mbuf *m, fp_sa_entry_t *sa, fp_sp_entry_t *sp)
{
#ifndef CONFIG_MCORE_MULTIBLADE
	return local_ipsec4_output(m, sa, sp);
#else
	uint16_t len = m_len(m);

	/* SA dedicated to a remote blade */
	if (unlikely(sa->output_blade &&
				(sa->output_blade != fp_shared->fp_blade_id))) {
		if (unlikely(fp_prepare_ipsec_output_req(m, sa->output_blade, sa->svti_ifuid ? : m_priv(m)->ifuid)
			     == FP_DROP)) {
			TRACE_IPSEC_OUT(FP_LOG_WARNING, "fp_prepare_ipsec_output_req failed");
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

	return local_ipsec4_output(m, sa, sp);

drop:
	FP_IPSEC_STATS_INC(sp->stats, sp_packets);
	FP_IPSEC_STATS_ADD(sp->stats, sp_bytes, len);
	FP_IPSEC_STATS_INC(sa->stats, sa_packets);
	FP_IPSEC_STATS_ADD(sa->stats, sa_bytes, len);
	FP_IPSEC_STATS_INC(sp->stats, sp_errors);
	FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
	return FP_DROP;
#endif
}

int fp_ipsec_output(struct mbuf *m)
{
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	fp_sa_entry_t *sa = NULL;
	fp_sp_entry_t *sp;
	uint16_t sport = 0, dport = 0;

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

#ifdef CONFIG_MCORE_IPSEC_LOOKUP_PORTS
	if ((unlikely(fp_ipsec_extract_ports(m, ip, &sport, &dport) < 0))) {
		TRACE_IPSEC_OUT(FP_LOG_INFO, "%s: only %u bytes of protocol %u",
				__FUNCTION__, m_len(m) - (ip->ip_hl << 2), ip->ip_p);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
		return FP_DROP;
	}
#endif

	sp = spd_out_lookup(ip->ip_src.s_addr, ip->ip_dst.s_addr, ip->ip_p,
			sport, dport, m2vrfid(m));

	if (likely(sp == NULL))
		return FP_CONTINUE; /* assume bypass */

	/* ensure it is not an exception for slow path before
	 * incrementing packets/bytes for this sp. */
	if (unlikely(sp->filter.action != FP_SP_ACTION_PROTECT)) {
		FP_IPSEC_STATS_INC(sp->stats, sp_packets);
		FP_IPSEC_STATS_ADD(sp->stats, sp_bytes, m_len(m));
		if (sp->filter.action == FP_SP_ACTION_BYPASS) {
			TRACE_IPSEC_OUT(FP_LOG_INFO, "bypass");
			return FP_CONTINUE;
		}

		TRACE_IPSEC_OUT(FP_LOG_INFO, "discard");
		FP_IPSEC_STATS_INC(sp->stats, sp_errors);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
		return FP_DROP;
	}

#ifdef CONFIG_MCORE_USE_HW_TX_L4CKSUM
	fpn_deferred_in4_l4cksum_set(m, 0);
#endif
	TRACE_IPSEC_OUT(FP_LOG_DEBUG, "Protecting %s %s src=%u.%u.%u.%u dst=%u.%u.%u.%u",
			sp->sa_proto == FP_IPPROTO_AH ? "AH" :"ESP",
			sp->mode == FP_IPSEC_MODE_TUNNEL ? "tunnel" :"transport",
			FP_NIPQUAD(ip->ip_src.s_addr), FP_NIPQUAD(ip->ip_dst.s_addr));

	if (likely(sp->mode == FP_IPSEC_MODE_TUNNEL)) {
		output_func func;

		if (likely(sp->sa_index != 0)) {
			if (sp->outer_family == AF_INET) {
				sa = &fp_get_sad()->table[sp->sa_index];
				func = ipsec4_output;
			}
#ifdef CONFIG_MCORE_IPSEC_IPV6
			else {
				sa = &fp_get_sad6()->table[sp->sa_index];
				func = ipsec6_output;
			}
#endif
			/* SA may have disappeared or been replaced */
			if (likely(sa->state != FP_SA_STATE_UNSPEC &&
				sa->genid == sp->sa_genid))
				return (*func)(m, sa, sp);

			/* invalidate SA cache entry */
			sp->sa_index = 0;
		}

		if (sp->outer_family == AF_INET) {
			sa = sad_out_lookup(sp->tunnel4_src, sp->tunnel4_dst,
					    sp->sa_proto, FP_IPSEC_MODE_TUNNEL, sp->reqid,
					    sp->link_vrfid, m2vrfid(m),
#if defined(CONFIG_MCORE_IPSEC_SVTI) && !defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
					    0,
#endif
					    &sp->sa_index);
			func = ipsec4_output;
		}
#ifdef CONFIG_MCORE_IPSEC_IPV6
		else {
			sa = sad6_out_lookup(sp->tunnel6_src.fp_s6_addr32,
					     sp->tunnel6_dst.fp_s6_addr32,
					     sp->sa_proto, FP_IPSEC_MODE_TUNNEL, sp->reqid,
					     sp->link_vrfid, m2vrfid(m),
#ifdef CONFIG_MCORE_IPSEC_SVTI
					     0,
#endif
					     &sp->sa_index);
			func = ipsec6_output;
		}
#endif

		if (unlikely(sa == NULL)) {
			TRACE_IPSEC_OUT(FP_LOG_NOTICE, "SA not found");
			FP_IPSEC_STATS_INC(sp->stats, sp_exceptions);
			return fp_ip_prepare_exception(m, FPTUN_EXC_IKE_NEEDED);
		}

		if (unlikely(sa->state == FP_SA_STATE_ACQUIRE)) {
			if (sp->flags & FP_SP_FLAG_LEVEL_USE) {
				FP_IPSEC_STATS_INC(sp->stats, sp_packets);
				FP_IPSEC_STATS_ADD(sp->stats, sp_bytes, m_len(m));
				return FP_CONTINUE;
			}
			else {
				TRACE_IPSEC_OUT(FP_LOG_DEBUG, "discard while negotiating SA");
				FP_IPSEC_STATS_INC(sp->stats, sp_errors);
				return FP_DROP;
			}
		}

		sp->sa_genid = sa->genid;

		return (*func)(m, sa, sp);
	} else {
		if (likely(!(sp->flags & FP_SP_FLAG_NO_SA_CACHE) && sp->sa_index != 0)) {
			sa = &fp_get_sad()->table[sp->sa_index];
			/* SA may have disappeared or been replaced */
			if (likely(sa->state != FP_SA_STATE_UNSPEC &&
				sa->genid == sp->sa_genid))
				return ipsec4_output(m, sa, sp);

			/* invalidate SA cache entry */
			sp->sa_index = 0;
		}

		sa = sad_out_lookup(ip->ip_src.s_addr, ip->ip_dst.s_addr,
				    sp->sa_proto, FP_IPSEC_MODE_TRANSPORT, sp->reqid,
				    sp->link_vrfid, m2vrfid(m), 
#if defined(CONFIG_MCORE_IPSEC_SVTI) && !defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
					0,
#endif
			 	    &sp->sa_index);

		if (unlikely(sa == NULL)) {
			TRACE_IPSEC_OUT(FP_LOG_NOTICE, "SA not found");
			FP_IPSEC_STATS_INC(sp->stats, sp_exceptions);
			return fp_ip_prepare_exception(m, FPTUN_EXC_IKE_NEEDED);
		}

		if (unlikely(sa->state == FP_SA_STATE_ACQUIRE)) {
			if (sp->flags & FP_SP_FLAG_LEVEL_USE) {
				FP_IPSEC_STATS_INC(sp->stats, sp_packets);
				FP_IPSEC_STATS_ADD(sp->stats, sp_bytes, m_len(m));
				return FP_CONTINUE;
			}
			else {
				TRACE_IPSEC_OUT(FP_LOG_DEBUG, "discard while negotiating SA");
				FP_IPSEC_STATS_INC(sp->stats, sp_errors);
				return FP_DROP;
			}
		}

		sp->sa_genid = sa->genid;

		return ipsec4_output(m, sa, sp);
	}
}

#ifdef CONFIG_MCORE_IPSEC_SVTI
int fp_svti_output(struct mbuf *m, fp_ifnet_t *ifp)
{
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	fp_sa_entry_t *sa = NULL;
	fp_sp_entry_t *sp;
	uint16_t sport = 0, dport = 0;
	fp_svti_t *svti = &fp_shared->svti[ifp->sub_table_index];

	TRACE_IPSEC_OUT(FP_LOG_DEBUG, "%s()", __FUNCTION__);

	/* Check IPsec outbound policy
	 * - if IPsec is required and SA not present, send to SP for IKE.
	 * - if tunnel mode, re-route packet:
	 *	o if route not found, send to SP
	 *	o if route to slow path interface, send to SP (bug)
	 * - if transport mode or bypass or discard or no SP, drop packet
	 */

#ifdef CONFIG_MCORE_IPSEC_LOOKUP_PORTS
	if ((unlikely(fp_ipsec_extract_ports(m, ip, &sport, &dport) < 0))) {
		TRACE_IPSEC_OUT(FP_LOG_INFO, "%s: only %u bytes of protocol %u",
				__FUNCTION__, m_len(m) - (ip->ip_hl << 2), ip->ip_p);
		goto drop;
	}
#endif

	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
		return FP_DROP;
	}

	sp = spd_svti_out_lookup(ip->ip_src.s_addr, ip->ip_dst.s_addr, ip->ip_p,
				sport, dport, svti);

	if (likely(sp == NULL)) {
		TRACE_IPSEC_OUT(FP_LOG_INFO, "%s: no SP", __FUNCTION__);
		goto drop;
	}

	/* ensure it is not an exception for slow path before
	 * incrementing packets/bytes for this sp. */
	if (unlikely(sp->filter.action != FP_SP_ACTION_PROTECT)) {
		FP_IPSEC_STATS_INC(sp->stats, sp_packets);
		FP_IPSEC_STATS_ADD(sp->stats, sp_bytes, m_len(m));
		goto drop;
	}

	TRACE_IPSEC_OUT(FP_LOG_DEBUG, "Protecting %s %s src=%u.%u.%u.%u dst=%u.%u.%u.%u",
			sp->sa_proto == FP_IPPROTO_AH ? "AH" :"ESP",
			sp->mode == FP_IPSEC_MODE_TUNNEL ? "tunnel" :"transport",
			FP_NIPQUAD(ip->ip_src.s_addr), FP_NIPQUAD(ip->ip_dst.s_addr));

	if (likely(sp->mode == FP_IPSEC_MODE_TUNNEL)) {
		int ret;
		int len __fpn_maybe_unused = m_len(m);
		output_func func;

		if (likely(sp->sa_index != 0)) {
			if (sp->outer_family == AF_INET) {
				sa = &fp_get_sad()->table[sp->sa_index];
				func = ipsec4_output;
			}
#ifdef CONFIG_MCORE_IPSEC_IPV6
			else {
				sa = &fp_get_sad6()->table[sp->sa_index];
				func = ipsec6_output;
			}
#endif
			/* SA may have disappeared or been replaced */
			if (likely(sa->state != FP_SA_STATE_UNSPEC &&
				sa->genid == sp->sa_genid))
				goto send_it;

			/* invalidate SA cache entry */
			sp->sa_index = 0;
		}

		if (sp->outer_family == AF_INET) {
			sa = sad_out_lookup(sp->tunnel4_src, sp->tunnel4_dst,
					    sp->sa_proto, FP_IPSEC_MODE_TUNNEL, sp->reqid,
					    sp->link_vrfid, sp->vrfid,
#ifndef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
					    sp->svti_ifuid,
#endif
					    &sp->sa_index);
			func = ipsec4_output;
		}
#ifdef CONFIG_MCORE_IPSEC_IPV6
		else {
			sa = sad6_out_lookup(sp->tunnel6_src.fp_s6_addr32,
					     sp->tunnel6_dst.fp_s6_addr32,
					     sp->sa_proto, FP_IPSEC_MODE_TUNNEL, sp->reqid,
					     sp->link_vrfid, m2vrfid(m),
					     sp->svti_ifuid,
					     &sp->sa_index);
			func = ipsec6_output;
		}
#endif

		if (unlikely(sa == NULL)) {
			TRACE_IPSEC_OUT(FP_LOG_INFO, "SA not found");
			FP_IPSEC_STATS_INC(sp->stats, sp_exceptions);
			return fp_ip_prepare_exception(m, FPTUN_EXC_IKE_NEEDED);
		}

		if (unlikely(sa->state == FP_SA_STATE_ACQUIRE)) {
			TRACE_IPSEC_OUT(FP_LOG_DEBUG, "discard while negotiating SA");
			FP_IPSEC_STATS_INC(sp->stats, sp_errors);
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
	TRACE_IPSEC_OUT(FP_LOG_NOTICE, "%s: transport mode SP", __FUNCTION__);

drop:
	FP_IF_STATS_INC(ifp->if_stats, ifs_oerrors);
	FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
	return FP_DROP;
}
#endif /* CONFIG_MCORE_IPSEC_SVTI */
