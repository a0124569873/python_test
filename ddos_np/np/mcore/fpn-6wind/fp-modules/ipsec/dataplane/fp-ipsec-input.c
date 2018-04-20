/*
 * Copyright(c) 2006 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-main-process.h"
#include "fp-log.h"
#include "fp-ip.h"

#include "netipsec/fp-ah.h"
#include "netipsec/fp-esp.h"
#include "netinet/fp-udp.h"

#include "fp-fpib.h"
#include "fp-ipsec-common.h"
#include "fp-ipsec-input.h"
#include "fp-ipsec-lookup.h"
#include "fp-ipsec-replay.h"
#include "fp-ipsec-iv.h"
#ifdef CONFIG_MCORE_IPSEC_SVTI
#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
#include "fp-svti-lookup.h"
#endif
#endif
#include "fpn-crypto.h"
#include "fpn-cksum.h"
#include "fp-dscp.h"
#ifdef CONFIG_MCORE_IPSEC_IPV6
#include "fp-ipsec6-input.h"
#endif

#define TRACE_IPSEC_IN(level, fmt, args...) do {			\
		FP_LOG(level, IPSEC_IN, fmt "\n", ## args);		\
} while(0)

/* SA objects */
FPN_DEFINE_SHARED(fp_sa_ctx_t, sa_ctx[FP_MAX_SA_ENTRIES]);

typedef int (*input_func) (struct mbuf *, fp_sa_entry_t *, void *);

static inline int ipsec_in_lookup(struct mbuf *m, struct fp_ip *ip,
                                  uint32_t *spd_index, fp_sp_entry_t **sp)
{
	uint16_t sport = 0, dport = 0;

#ifdef CONFIG_MCORE_IPSEC_LOOKUP_PORTS
	if (unlikely(fp_ipsec_extract_ports(m, ip, &sport, &dport) < 0)) {
		TRACE_IPSEC_IN(FP_LOG_INFO, "%s: only %u bytes of protocol %u",
					__FUNCTION__, m_len(m) - (ip->ip_hl << 2), ip->ip_p);
		return -1;
	}
#endif

	*sp = spd_in_lookup(ip->ip_src.s_addr, ip->ip_dst.s_addr, ip->ip_p,
			sport, dport, m2vrfid(m), spd_index);

	return 0;
}

#ifdef CONFIG_MCORE_IPSEC_SVTI
static inline int ipsec_svti_in_lookup(fp_ifnet_t *ifp, struct mbuf *m,
		struct fp_ip *ip, uint32_t *spd_index, fp_sp_entry_t **sp)
{
	uint16_t sport = 0, dport = 0;
	fp_svti_t *svti = &fp_shared->svti[ifp->sub_table_index];

#ifdef CONFIG_MCORE_IPSEC_LOOKUP_PORTS
	if (unlikely(fp_ipsec_extract_ports(m, ip, &sport, &dport) < 0)) {
		TRACE_IPSEC_IN(FP_LOG_INFO, "%s: only %u bytes of protocol %u",
					__FUNCTION__, m_len(m) - (ip->ip_hl << 2), ip->ip_p);
		return -1;
	}
#endif

	*sp = spd_svti_in_lookup(ip->ip_src.s_addr, ip->ip_dst.s_addr, ip->ip_p,
			sport, dport, svti, spd_index);

	return 0;
}
#endif

int fp_ipsec_input_init(void)
{
	int i;

	/* initialize SA contexts table */
	for (i=0; i<FP_MAX_SA_ENTRIES; i++) {
#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
		int dir;
		for (dir=0; dir<FP_DIR_NUM; dir++) {
			sa_ctx[i].priv[dir] = NULL;
		}
#endif

		fpn_spinlock_init(&sa_ctx[i].lock);
	}

	return 0;
}

/* look-up IN policy for decrypted packets */
static inline int ipsec_check_enc_policy(struct mbuf *m, fp_sa_entry_t *sa)
{
	struct fp_ip *ip;
	fp_sp_entry_t *sp;
	uint32_t spd_index;

	ip = mtod(m, struct fp_ip *);
	spd_index = 0;
#ifndef CONFIG_MCORE_IPSEC_OVERLAP
	if (likely(sa->spd_index != 0)) {
		/* debug only? 
		 * only verified PROTECT policy is cached 
		 * and any change in SPD will invalidate the cache.
		 */
		sp = &fp_get_spd_in()->table[sa->spd_index];
		if (likely(sp->state != FP_SP_STATE_UNSPEC))
			goto check;
	}
#endif
	/* need to look-up inbound policy */
	if (ipsec_in_lookup(m, ip, &spd_index, &sp) < 0)
		return -1;
#ifndef CONFIG_MCORE_IPSEC_OVERLAP
	else
		sa->spd_index = spd_index;
check:
#endif
	if (likely(sp &&
	           ((sp->filter.action == FP_SP_ACTION_PROTECT && 
	             sp->mode == sa->mode &&
	             sp->sa_proto == sa->proto &&
	             (sp->reqid == 0 || sp->reqid == sa->reqid)) ||
	            (sp->filter.action == FP_SP_ACTION_BYPASS &&
	             sa->mode == FP_IPSEC_MODE_TRANSPORT)))) {
		m_priv(m)->flags |= M_IPSEC_SP_OK;
		FP_IPSEC_STATS_INC(sp->stats, sp_packets);
		FP_IPSEC_STATS_ADD(sp->stats, sp_bytes, m_len(m));
		return 0;
	}

	/* invalid SP */
	sa->spd_index = 0;

	/* receive encrypted packet but this was not required:
	 * accept if mode was transport (won't change routing)
	 * - same is done in kernel -
	 */
	if (likely(!sp && sa->mode == FP_IPSEC_MODE_TRANSPORT))
		return 0;

	FP_IPSEC_STATS_INC(sa->stats, sa_selector_errors);
	if (sp) {
		FP_IPSEC_STATS_INC(sp->stats, sp_packets);
		FP_IPSEC_STATS_ADD(sp->stats, sp_bytes, m_len(m));
		if (sp->filter.action != FP_SP_ACTION_DISCARD)
			FP_IPSEC_STATS_INC(sp->stats, sp_errors);
	}

	/* whatever the reason we will drop the packet:
	 * o packet decrypted w/o policy
	 * o policy mismatch (action, mode, proto)
	 */
	return -1;
}

#ifdef CONFIG_MCORE_IPSEC_SVTI
/* look-up IN policy for decrypted packets */
static inline int ipsec_check_svti_policy(struct mbuf *m, fp_sa_entry_t *sa,
		fp_ifnet_t *ifp)
{
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	fp_sp_entry_t *sp;
	uint32_t spd_index = 0;

	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
		return -1;
	}	

	if (likely(sa->spd_index != 0)) {
		/* debug only? 
		 * only verified PROTECT policy is cached 
		 * and any change in SPD will invalidate the cache.
		 */
		sp = &fp_get_spd_in()->table[sa->spd_index];
		if (likely(sp->state != FP_SP_STATE_UNSPEC))
			goto check;
	}
	/* need to look-up inbound policy */
	if (ipsec_svti_in_lookup(ifp, m, ip, &spd_index, &sp) < 0)
		return -1;
	else
		sa->spd_index = spd_index;
check:
	if (likely(sp &&
				sp->filter.action == FP_SP_ACTION_PROTECT && 
				sp->mode == FP_IPSEC_MODE_TUNNEL &&
				sp->mode == sa->mode &&
				sp->sa_proto == sa->proto &&
				(sp->reqid == 0 || sp->reqid == sa->reqid))) {
		m_priv(m)->flags |= M_IPSEC_SP_OK;
		FP_IPSEC_STATS_INC(sp->stats, sp_packets);
		FP_IPSEC_STATS_ADD(sp->stats, sp_bytes, m_len(m));
		return 0;
	}

	/* invalid SP */
	sa->spd_index = 0;

	FP_IPSEC_STATS_INC(sa->stats, sa_selector_errors);
	if (sp)
		FP_IPSEC_STATS_INC(sp->stats, sp_errors);

	/* increment interface input error stats */
	FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);

	/* whatever the reason we will drop the packet:
	 * o packet decrypted w/o policy
	 * o policy mismatch (action, mode, proto)
	 */
	return -1;
}
#endif

int ipsec4_input_finish(struct mbuf *m, fp_sa_entry_t *sa)
{
#ifdef CONFIG_MCORE_IPSEC_SVTI
	uint32_t svti_ifuid;
#ifndef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
	svti_ifuid = sa->svti_ifuid;
#else
	svti_ifuid = ipsec4_svti_lookup(m, sa);
#endif
	if (svti_ifuid) {
		fp_ifnet_t *ifp = fp_ifuid2ifnet(svti_ifuid);

		if (unlikely(ifp == NULL)) {
			TRACE_IPSEC_IN(FP_LOG_NOTICE,
					"svti interface does not exist");
			FP_IPSEC_STATS_INC(sa->stats, sa_selector_errors);
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
			return FP_DROP;
		}

		if (unlikely(ipsec_check_svti_policy(m, sa, ifp) < 0)) {
			TRACE_IPSEC_IN(FP_LOG_NOTICE,
					"svti policy mismatch for decrypted packet");
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
			return FP_DROP;
		}

		/* change inbound interface to SVTI */
		TRACE_IPSEC_IN(FP_LOG_DEBUG, "%s: entering SVTI interface %s",
				__FUNCTION__, ifp->if_name);

		/* From now on, next exception will be treated
		 * as an IPv4 input exception
		 */
		m_priv(m)->exc_type = FPTUN_IPV4_INPUT_EXCEPT;
		m_priv(m)->exc_proto = htons(FP_ETHERTYPE_IP);
		fp_change_ifnet_packet(m, ifp, 1, 1);
		fp_reset_hw_flags(m);
		
		if (fp_shared->conf.w32.do_func & FP_CONF_DO_IPSEC_ONCE)
			m_priv(m)->flags |= M_IPSEC_BYPASS;

		return FPN_HOOK_CALL(fp_ip_input)(m);
	}
#endif
	if (likely(sa->mode == FP_IPSEC_MODE_TUNNEL))
		set_mvrfid(m, sa->xvrfid);
	if (unlikely(ipsec_check_enc_policy(m, sa) < 0)) {
		TRACE_IPSEC_IN(FP_LOG_NOTICE, "policy mismatch for decrypted packet");
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
		return FP_DROP;
	}

	/* From now on, next exception will be treated
	 * as an IPv4 input exception
	 */
	m_priv(m)->exc_type = FPTUN_IPV4_INPUT_EXCEPT;
	m_priv(m)->exc_proto = htons(FP_ETHERTYPE_IP);
	if (fp_shared->conf.w32.do_func & FP_CONF_DO_IPSEC_ONCE)
		m_priv(m)->flags |= M_IPSEC_BYPASS;
	fp_reset_hw_flags(m);

	return FPN_HOOK_CALL(fp_ip_input)(m);
}

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
#define m_ipsec(m) m_priv(m)->ipsec.m_ipsec_buf
#else
static FPN_DEFINE_PER_CORE(struct m_ipsec_state, m_ipsec_buf);
#define m_ipsec(m) FPN_PER_CORE_VAR(m_ipsec_buf)
#endif

__fpn_maybe_unused
static int ah4_input_finish(struct mbuf *m, fp_sa_entry_t *sa,
		uint32_t seq, int auth_failed)
{
	input_finish_func func = ipsec4_input_finish;

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

	FP_IPSEC_STATS_INC(sa->stats, sa_packets);
#ifdef HAVE_HMAC_COMPLETE
	if (fp_ipsec_ctx.auth_type == FP_AALGO_HMACMD5)
		fpn_hmac_md5_complete_pass2();
#endif
	FP_IPSEC_STATS_ADD(sa->stats, sa_bytes, m_len(m));

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

	auth_failed = fpn_fast_memcmp(m_ipsec(m).out_auth, m_ipsec(m).save_auth, sa->authsize);
#endif

	if (auth_failed) {
		TRACE_IPSEC_IN(FP_LOG_NOTICE, "ah4_input_finish: authentication hash mismatch");
		FP_IPSEC_STATS_INC(sa->stats, sa_auth_errors);
		goto drop;
	}

	if (likely(sa->replay.wsize)) {
		if (ipsec_chk_update_replay(ntohl(seq), sa, &sa->replay, sa->index,
					sa->flags & FP_SA_FLAG_ESN, 0, 1, NULL)) {
			TRACE_IPSEC_IN(FP_LOG_NOTICE, "ah4_input_finish: update replay error");
			FP_IPSEC_STATS_INC(sa->stats, sa_replay_errors);
			goto drop;
		}
	}

	if (likely(sa->mode == FP_IPSEC_MODE_TUNNEL)) {
		struct fp_ip *ip;
#ifdef CONFIG_MCORE_IPSEC_IPV6
		struct fp_ip6_hdr *ip6;
#endif

		if (m_ipsec(m).ah_nxt == FP_IPPROTO_IPIP) {
			m_adj(m, sa->ahsize + sizeof(struct fp_ip));
			ip = mtod(m, struct fp_ip *);
			if (unlikely(sa->flags & FP_SA_FLAG_DECAPDSCP))
				fp_change_ipv4_dscp(ip, (m_ipsec(m).ip_tos & FP_DSCP_MASK));
		}
#ifdef CONFIG_MCORE_IPSEC_IPV6
		else if (m_ipsec(m).ah_nxt == FP_IPPROTO_IPV6) {
			m_adj(m, sa->ahsize + sizeof(struct fp_ip));
			ip6 = mtod(m, struct fp_ip6_hdr *);
			ip6->ip6_plen = htons(m_len(m) - sizeof(struct fp_ip6_hdr));
			if (unlikely(sa->flags & FP_SA_FLAG_DECAPDSCP))
				fp_change_ipv6_dscp(ip6, (m_ipsec(m).ip_tos & FP_DSCP_MASK));

			func = ipsec6_input_finish;
		}
#endif
		else {
#ifdef CONFIG_MCORE_IPSEC_IPV6
			TRACE_IPSEC_IN(FP_LOG_NOTICE, "ah4_input_finish: next proto %d is not IPIP or IPv6", m_ipsec(m).ah_nxt);
#else
			TRACE_IPSEC_IN(FP_LOG_NOTICE, "ah4_input_finish: next proto %d is not IPIP", m_ipsec(m).ah_nxt);
#endif
			FP_IPSEC_STATS_INC(sa->stats, sa_auth_errors);
			goto drop;
		}
	} else {
		struct fp_ip save_ip, *ip;

		ip = mtod(m, struct fp_ip *);
		/* memcpy does not support overlapping */
		memcpy(&save_ip, ip, sizeof(struct fp_ip));
		memcpy((char *)ip + sa->ahsize, &save_ip, sizeof(struct fp_ip));
		ip = (struct fp_ip *)m_adj(m, sa->ahsize);
		/* Fix the Next Protocol field. */
		ip->ip_p = m_ipsec(m).ah_nxt;
		/* Restore ip fields */
		ip->ip_ttl = m_ipsec(m).ip_ttl;
		ip->ip_tos = m_ipsec(m).ip_tos;
		ip->ip_off = m_ipsec(m).ip_off;
		ip->ip_len = htons(m_len(m));
		/* IP checksum */
		ip->ip_sum = fpn_ip_hdr_cksum(ip, sizeof(struct fp_ip));
	}

	return (*func)(m, sa);

drop:
	FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
	return FP_DROP;
}

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
static void ah4_input_cb(__fpn_maybe_unused void * opaque, struct mbuf *m, int res)
{
	fp_sa_entry_t *sa = m_priv(m)->ipsec.sa;

	TRACE_IPSEC_IN(FP_LOG_DEBUG, "%s()", __FUNCTION__);

	if (sa->flags & FP_SA_FLAG_ESN) {
		m_trim(m, sizeof(uint32_t));
		TRACE_IPSEC_IN(FP_LOG_NOTICE, "%s: ESN async finish len=%d",
				__FUNCTION__, m_len(m));
	}

	res = ah4_input_finish(m, m_priv(m)->ipsec.sa, m_priv(m)->ipsec.seq, res);

	fp_process_input_finish(m, res);
}
#endif

/* ipsec4_input, ah4_input, esp4_input:
 * return FP_NONE: unable to apply IPsec, tell slow path
 * return FP_DROP: error during IPsec processing
 * return FP_DONE: packet has been decrypted, forwarded and freed,
 go ahead with next packet
 * return FP_KEEP: packet is kept for async treatment.
 */
static inline int ah4_input(struct mbuf *m, fp_sa_entry_t *sa, void *data)
{
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	struct fp_ah *ah = data;
	uint16_t authsize;
#ifndef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	int auth_failed = -1;
#endif
	uint32_t seq_hi;

	authsize = sa->authsize;
	/* Verify AH header length. */
	if (unlikely(ah->ah_len != sa->ah_len)) {
		TRACE_IPSEC_IN(FP_LOG_NOTICE, "ah4_input: bad authenticator length %d", ah->ah_len);
		FP_IPSEC_STATS_INC(sa->stats, sa_auth_errors);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
		return FP_DROP;
	}

	/* Check replay window, if applicable. */
	if (likely(sa->replay.wsize)) {
		if(ipsec_chk_update_replay(ntohl(ah->ah_seq), sa, &sa->replay, sa->index,
					sa->flags & FP_SA_FLAG_ESN, 0, 0, &seq_hi)) {
			TRACE_IPSEC_IN(FP_LOG_NOTICE, "ah4_input: packet replay failure");
			FP_IPSEC_STATS_INC(sa->stats, sa_replay_errors);
			FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
			return FP_DROP;
		}
	}
	/* Cannot and never happens, but let compiler know about it. */
	else if (unlikely(sa->flags & FP_SA_FLAG_ESN))
		return FP_DROP;

	/* copy authenticator */
	fpn_crypto_auth_copy(m_ipsec(m).save_auth, ah->auth_data, authsize);
	/* zeroize authenticator */
	fpn_crypto_auth_clear(ah->auth_data, authsize);

	m_ipsec(m).ah_nxt = ah->ah_nxt;
	/* we will copy tos to inner packet */
	m_ipsec(m).ip_tos = ip->ip_tos;
	/* only in transport mode we have to save ip header
	 * because in tunnel mode we will strip ip header 
	 */
	if (unlikely(sa->mode == FP_IPSEC_MODE_TRANSPORT)) {
		m_ipsec(m).ip_ttl = ip->ip_ttl;
		/* m_ipsec(m).ip_tos = ip->ip_tos; already done */
		m_ipsec(m).ip_off = ip->ip_off;
	}
	ip->ip_ttl = 0;
	ip->ip_tos = 0;
	ip->ip_off = 0;
	ip->ip_sum = 0;

	if (sa->flags & FP_SA_FLAG_ESN) {
		char *p;
		seq_hi = htonl(seq_hi);

		p = m_append(m, 4);
		if (p)
			memcpy(p, &seq_hi, 4);
		else if (m_copyfrombuf(m, m_len(m), &seq_hi, 4) != 4) {
			TRACE_IPSEC_IN(FP_LOG_WARNING, "%s: m_copyfrombuf failure",
					__FUNCTION__);
			return FP_DROP;
		}
		TRACE_IPSEC_IN(FP_LOG_NOTICE, "%s: ESN seq_hi=0x%.8"PRIx32" len=%d",
				__FUNCTION__, ntohl(seq_hi), m_len(m));
	}
#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	{
		uint16_t __fpn_maybe_unused nbytes = m_len(m);
		uint16_t __fpn_maybe_unused off_auth = 0;

		m_priv(m)->flags |= M_ASYNC;
		m_priv(m)->ipsec.sa = sa;
		m_priv(m)->ipsec.seq = ah->ah_seq;

		if ((fp_check_sa(sa, &sa_ctx[sa->index], FP_DIR_IN) < 0) ||
		    (FPN_ASYNC_CRYPTO_AUTH(sa->alg_auth,
					  sa->key_auth,
					  FP_MAX_KEY_AUTH_LENGTH,
					  off_auth,
					  m_ipsec(m).save_auth,
					  nbytes,
					  0, /* m_src_off */
					  0, /* m_dst_off */
					  m, /* m_dst */
					  FPN_DECRYPT,
					  m,
					  ah4_input_cb,
					  sa_ctx[sa->index].priv[FP_DIR_IN]) < 0)) {
			m_freem(m);
			return FP_DONE;
		}

		return FP_KEEP;
	}
#else

	{
		if (sa->alg_auth == FP_AALGO_HMACMD5) {
			fpn_hmac_md5(m_ipsec(m).out_auth, sa->key_auth,
					m, 0, m_len(m),
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACMD5;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA1) {
			fpn_hmac_sha1(m_ipsec(m).out_auth, sa->key_auth,
					m, 0, m_len(m),
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA1;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA256) {
			fpn_hmac_sha256(m_ipsec(m).out_auth, sa->key_auth,
					m, 0, m_len(m),
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA256;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA384) {
			fpn_hmac_sha384(m_ipsec(m).out_auth, sa->key_auth,
					m, 0, m_len(m),
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA384;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA512) {
			fpn_hmac_sha512(m_ipsec(m).out_auth, sa->key_auth,
					m, 0, m_len(m),
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA512;
		}
		else if (sa->alg_auth == FP_AALGO_AESXCBC) {
			fpn_aes_xcbc_mac(m_ipsec(m).out_auth, sa->key_auth,
					m, 0, m_len(m));
			fp_ipsec_ctx.auth_type = FP_AALGO_AESXCBC;            
		}

		if (sa->flags & FP_SA_FLAG_ESN) {
			m_trim(m, sizeof(uint32_t));
			TRACE_IPSEC_IN(FP_LOG_NOTICE, "%s: ESN sync finish len=%d",
					__FUNCTION__, m_len(m));
		}
	}

#ifndef HAVE_HMAC_COMPLETE
	auth_failed = fpn_fast_memcmp(m_ipsec(m).out_auth, m_ipsec(m).save_auth, authsize);
#endif

	return ah4_input_finish(m, sa, ah->ah_seq, auth_failed);
#endif
}

static int esp4_input_finish(struct mbuf *m, fp_sa_entry_t *sa,
				    uint32_t seq, int auth_failed)
{
	struct fp_ip *ip;
#ifdef CONFIG_MCORE_IPSEC_IPV6
	struct fp_ip6_hdr *ip6;
#endif
	unsigned char tailbuf[3 /* last three */ + FP_MAX_KEY_AUTH_LENGTH];
	unsigned char *lastthree = tailbuf;
	unsigned int padlen;
	uint16_t alen = sa->authsize;
	uint16_t esp_size;
	input_finish_func func = ipsec4_input_finish;

	esp_size = sizeof(struct fp_esp) + sa->ivlen;
 	if (unlikely(sa->flags & FP_SA_FLAG_UDPTUNNEL))
		esp_size += sizeof(struct fp_udphdr);

	FP_IPSEC_STATS_INC(sa->stats, sa_packets);
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
	FP_IPSEC_STATS_ADD(sa->stats, sa_bytes, m_len(m));

	if (likely(m_is_contiguous(m)))
		lastthree = (unsigned char *)m_tail(m) - alen - 3;
	else
#ifdef HAVE_HMAC_COMPLETE
		m_copytobuf(lastthree, m, m_len(m) - alen - 3, alen + 3);
#else
		m_copytobuf(lastthree, m, m_len(m) - alen - 3, 3);
#endif

	padlen = lastthree[1] + 2;
	/* Verify pad length */
	if (padlen > m_len(m) - sizeof(struct fp_ip)) {
		TRACE_IPSEC_IN(FP_LOG_NOTICE, "esp4_input_finish: invalid padding length %d", lastthree[1]);
		FP_IPSEC_STATS_INC(sa->stats, sa_decrypt_errors);
		goto drop;
	}

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
		fpn_hmac_md5_complete_pass2();

	if (fp_ipsec_ctx.auth_type == FP_AALGO_HMACMD5)
		fpn_hmac_md5_complete_pass3();

	auth_failed = fpn_fast_memcmp(lastthree + 3, m_ipsec(m).out_auth, alen);
#endif

	if ((alen != 0) && auth_failed) {
		TRACE_IPSEC_IN(FP_LOG_NOTICE, "esp4_input_finish: authentication hash mismatch");
		FP_IPSEC_STATS_INC(sa->stats, sa_auth_errors);
		goto drop;
	}

	/* check replay counter */
	if (likely(sa->replay.wsize)) {
		if (ipsec_chk_update_replay(ntohl(seq), sa, &sa->replay, sa->index,
					sa->flags & FP_SA_FLAG_ESN, 0, 1, NULL)) {
			TRACE_IPSEC_IN(FP_LOG_NOTICE, "esp4_input_finish: update replay error");
			FP_IPSEC_STATS_INC(sa->stats, sa_replay_errors);
			goto drop;
		}
	}

	/* Trim padding */
	m_trim(m, padlen + alen);
	ip = mtod(m, struct fp_ip *);

	/* Restore next protocol field */
	ip->ip_p = lastthree[2];

	/* Trim ESP header and eventually IP outer header */
	if (likely(sa->mode == FP_IPSEC_MODE_TUNNEL)) {
		unsigned int hlen;
		uint8_t out_tos = ip->ip_tos;

		if (ip->ip_p == FP_IPPROTO_IPIP) {
			hlen = sizeof(struct fp_ip) + esp_size;
			m_adj(m, hlen);
			ip = mtod(m, struct fp_ip *);
			if (unlikely(sa->flags & FP_SA_FLAG_DECAPDSCP))
				fp_change_ipv4_dscp(ip, (out_tos & FP_DSCP_MASK));
		}
#ifdef CONFIG_MCORE_IPSEC_IPV6
		else if (ip->ip_p == FP_IPPROTO_IPV6) {
			hlen = sizeof(struct fp_ip) + esp_size;
			m_adj(m, hlen);
			ip6 = mtod(m, struct fp_ip6_hdr *);
			ip6->ip6_plen = htons(m_len(m) - sizeof(struct fp_ip6_hdr));
			if (unlikely(sa->flags & FP_SA_FLAG_DECAPDSCP))
				/* TODO: Not sure ??? */
				fp_change_ipv6_dscp(ip6, (out_tos & FP_DSCP_MASK));

			func = ipsec6_input_finish;
		}
#endif
		else {
#ifdef CONFIG_MCORE_IPSEC_IPV6
			TRACE_IPSEC_IN(FP_LOG_NOTICE, "esp4_input_finish: next proto %d is not IPIP or IPv6", ip->ip_p);
#else
			TRACE_IPSEC_IN(FP_LOG_NOTICE, "esp4_input_finish: next proto %d is not IPIP", ip->ip_p);
#endif
			FP_IPSEC_STATS_INC(sa->stats, sa_decrypt_errors);
			goto drop;
		}
	} else {
		struct fp_ip save_ip;
		/* memcpy does not support overlapping */
		memcpy(&save_ip, ip, sizeof(struct fp_ip));
		memcpy((char *)ip + esp_size, &save_ip, sizeof(struct fp_ip));
		ip = (struct fp_ip *)m_adj(m, esp_size);
		/* Restore ip fields */
		ip->ip_len = htons(m_len(m));
		/* IP checksum */
		ip->ip_sum = fpn_ip_hdr_cksum(ip, sizeof(struct fp_ip));
	}

	return (*func)(m, sa);

drop:
	FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
	return FP_DROP;
}

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
static void esp4_input_cb(__fpn_maybe_unused void * opaque, struct mbuf *m, int res)
{
	fp_sa_entry_t *sa = m_priv(m)->ipsec.sa;

	TRACE_IPSEC_IN(FP_LOG_DEBUG, "%s()", __FUNCTION__);

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
		TRACE_IPSEC_IN(FP_LOG_NOTICE, "%s: ESN async(aes) finish spi=0x%.8"PRIx32" len=%d",
				__FUNCTION__, ntohl(*esp), m_len(m));
	}

	res = esp4_input_finish(m, m_priv(m)->ipsec.sa, m_priv(m)->ipsec.seq, res);

	fp_process_input_finish(m, res);
}
#endif

static int esp4_input(struct mbuf *m, fp_sa_entry_t *sa,
			     void *data)
{
#ifndef HAVE_HMAC_COMPLETE
	char *authbuf;
#endif
	struct fp_esp *esp = data;
	uint16_t ivlen, blks;
	int plen;
	int authlen;
	uint8_t alen;
#ifndef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	int auth_failed = -1;
#endif
	uint32_t seq_hi;

#ifdef CONFIG_MCORE_DEBUG
	struct fp_ip *ip = mtod(m, struct fp_ip *);

	if (ntohs(ip->ip_len) != m_len(m))
		TRACE_IPSEC_IN(FP_LOG_NOTICE, "ip len mismatch %d %d", ntohs(ip->ip_len), m_len(m));
#endif

	/*
	 * Verify payload length is multiple of encryption algorithm
	 * block size.
	 */

	ivlen = sa->ivlen;
	blks = sa->blocksize;
	alen = sa->authsize;

	authlen = m_len(m) - (sizeof(struct fp_ip) + alen);
	if (unlikely(sa->flags & FP_SA_FLAG_UDPTUNNEL))
		authlen -= sizeof(struct fp_udphdr);
	plen = authlen - sizeof(struct fp_esp) - ivlen;

	/* In GCM, do not include IV in auth */
	if (sa->alg_enc == FP_EALGO_AESGCM) {
	    authlen -= ivlen;
	}

#ifdef HAVE_CRYPTO_PREHANDLE
	/*
	 * On OCTEON platform, the hardware crypto unit can work in parallel with
	 * other instructions, so start decryption here to enhance performance
	 */
	if (sa->alg_auth == FP_AALGO_HMACSHA1 ||
	    sa->alg_auth == FP_AALGO_HMACSHA256 ||
	    sa->alg_auth == FP_AALGO_HMACSHA384 ||
	    sa->alg_auth == FP_AALGO_HMACSHA512 ||
	    sa->alg_auth == FP_AALGO_HMACMD5) {
		if (sa->alg_enc == FP_EALGO_AESCBC) {
			fpn_aes_set_iv((uint64_t *)esp->enc_data);
			fpn_aes_cbc_decrypt_pre((char *)esp, plen, (uint64_t *)sa->key_enc, sa->key_enc_len);
		} else if (sa->alg_enc == FP_EALGO_DESCBC) {
			fpn_des_cbc_decrypt_pre((char *)esp, plen, (uint64_t *)sa->key_enc);
		} else if (sa->alg_enc == FP_EALGO_3DESCBC) {
			fpn_3des_cbc_decrypt_pre((char *)esp, plen, (uint64_t *)sa->key_enc);
		}
	}
#endif

	if (alen != 0) {
		/* Check replay window, if applicable. */
		if (likely(sa->replay.wsize)) {
			if (ipsec_chk_update_replay(ntohl(esp->esp_seq), sa, &sa->replay, sa->index,
						sa->flags & FP_SA_FLAG_ESN, 0, 0, &seq_hi)) {
				TRACE_IPSEC_IN(FP_LOG_NOTICE, "esp4_input: packet replay failure");
				FP_IPSEC_STATS_INC(sa->stats, sa_replay_errors);
				FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
				return FP_DROP;
			}
		}
		/* Cannot and never happens, but let compiler know about it. */
		else if (unlikely(sa->flags & FP_SA_FLAG_ESN))
			return FP_DROP;
	}

	if ((plen & (blks -1)) || (plen <= 0)) {
		TRACE_IPSEC_IN(FP_LOG_NOTICE, "esp4_input: data size %d is not a multiple of %d", plen, blks);
		FP_IPSEC_STATS_INC(sa->stats, sa_decrypt_errors);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
		return FP_DROP;
	}

#ifndef HAVE_HMAC_COMPLETE
	/*
	 * In the case of ESN, AES-GCM or AES-GMAC, data must be appended
	 * just after the encrypted data, so backup the ICV.
	 */
	if (likely(m_is_contiguous(m)) &&
		(((sa->flags & FP_SA_FLAG_ESN) == 0) ||
		(sa->alg_enc == FP_EALGO_AESGCM) ||
		(sa->alg_enc == FP_EALGO_NULL_AESGMAC))) {
		authbuf   = m_tail(m) - alen;
	} else {
		authbuf   = m_ipsec(m).save_auth;
		m_copytobuf(authbuf, m, m_len(m) - alen, alen);
	}
#endif

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	{
		char *mbase = mtod(m, char*);
		char *iv;
		char *auth_data = (char*)esp;

		/* In GCM/GMAC mode, build nonce from IV + salt */
		if ((sa->alg_enc == FP_EALGO_AESGCM) ||
		    (sa->alg_enc == FP_EALGO_NULL_AESGMAC)) {
			COPY_PACKET_IV(m_ipsec(m).iv, &sa->key_enc[sa->key_enc_len], 4);
			COPY_PACKET_IV(&m_ipsec(m).iv[4], esp->enc_data, 8);
			iv = m_ipsec(m).iv;
		} else {
			iv = esp->enc_data;
		}

		m_priv(m)->flags |= M_ASYNC;

		m_priv(m)->ipsec.sa = sa;
		m_priv(m)->ipsec.seq = esp->esp_seq;

		if (alen) {
			if (sa->flags & FP_SA_FLAG_ESN) {
				seq_hi = htonl(seq_hi);
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
					TRACE_IPSEC_IN(FP_LOG_NOTICE, "%s: ESN async(aes) back=0x%.8"PRIx32" seq_hi=0x%.8"PRIx32" len=%d",
                                                  __FUNCTION__, ntohl(m_priv(m)->ipsec.back), ntohl(seq_hi), m_len(m));
				/*
				 * In other mode, overwrite first 4 bytes of
				 * authentication data using seq_hi.
				 */
				} else {
					m_copyfrombuf(m, m_len(m) - alen, &seq_hi, sizeof(uint32_t));
					TRACE_IPSEC_IN(FP_LOG_NOTICE, "%s: ESN async seq_hi=0x%.8"PRIx32" len=%d",
							__FUNCTION__, ntohl(seq_hi), m_len(m));
				}
				authlen += sizeof(uint32_t);
			}

			if (likely(sa->alg_enc != FP_EALGO_NULL)) {
				if ((fp_check_sa(sa, &sa_ctx[sa->index], FP_DIR_IN) < 0) ||
				    (FPN_ASYNC_CRYPTO_CIPHER_AUTH(sa->alg_enc,
								 (uint64_t*)sa->key_enc,
								 sa->key_enc_len,
								 (char*)esp->enc_data + ivlen - mbase,
								 plen,
								 iv - mbase,
								 ivlen,
								 sa->alg_auth,
								 sa->key_auth,
								 FP_MAX_KEY_AUTH_LENGTH,
								 auth_data - mbase,
								 authbuf,
								 authlen,
								 0, /* m_src_off */
								 0, /* m_dst_off */
								 m, /* m_dst */
								 FPN_DECRYPT,
								 m,
								 esp4_input_cb,
								 sa_ctx[sa->index].priv[FP_DIR_IN]) < 0)) {
					m_freem(m);
					return FP_DONE;
				}
			}
			else {
				if ((fp_check_sa(sa, &sa_ctx[sa->index], FP_DIR_IN) < 0) ||
				    (FPN_ASYNC_CRYPTO_AUTH(sa->alg_auth,
							  sa->key_auth,
							  FP_MAX_KEY_AUTH_LENGTH,
							  auth_data - mbase,
							  authbuf,
							  authlen,
							  0, /* m_src_off */
							  0, /* m_dst_off */
							  m, /* m_dst */
							  FPN_DECRYPT,
							  m,
							  esp4_input_cb,
							  sa_ctx[sa->index].priv[FP_DIR_IN]) < 0)) {
					m_freem(m);
					return FP_DONE;
				}
			}
		}
		else {
			if (likely(sa->alg_enc != FP_EALGO_NULL)) {
				if ((fp_check_sa(sa, &sa_ctx[sa->index], FP_DIR_IN) < 0) ||
				    (FPN_ASYNC_CRYPTO_CIPHER(sa->alg_enc,
							    (uint64_t*)sa->key_enc,
							    sa->key_enc_len,
							    (char*)esp->enc_data + ivlen - mbase,
							    plen,
							    iv - mbase,
							    ivlen,
							    0, /* m_src_off */
							    0, /* m_dst_off */
							    m, /* m_dst */
							    FPN_DECRYPT,
							    m,
							    esp4_input_cb,
							    sa_ctx[sa->index].priv[FP_DIR_IN]) < 0)) {
					m_freem(m);
					return FP_DONE;
				}
			}
			else {
				/* ESP-NULL without auth, do it sync */
				return esp4_input_finish(m, sa, esp->esp_seq, 0);
			}
		}
		return FP_KEEP;
	}
#else /* sync */

	if (alen && (sa->flags & FP_SA_FLAG_ESN)) {
		seq_hi = htonl(seq_hi);

		m_copyfrombuf(m, m_len(m) - alen, &seq_hi, sizeof(uint32_t));
		authlen += sizeof(uint32_t);
		TRACE_IPSEC_IN(FP_LOG_NOTICE, "%s: ESN seq_hi=0x%.8"PRIx32" len=%d",
				__FUNCTION__, ntohl(seq_hi), m_len(m));
	}
#ifdef HAVE_AESHMACSHA1
	/* fp_aes_cbc_decrypt_hsha1() requires at least 3 AES blocks. */
	if (condition_dec_aescbc_hmacsha1(m_is_contiguous(m), plen) &&
	    (sa->alg_auth == FP_AALGO_HMACSHA1) && (sa->alg_enc == FP_EALGO_AESCBC)) {

#ifndef HAVE_CRYPTO_PREHANDLE
		fpn_aes_set_iv((uint64_t *)esp->enc_data);
#endif
		fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA1;
		fpn_aes_cbc_decrypt_hsha1((char *)esp,
				plen,
				(uint64_t *)sa->key_enc,
				sa->key_enc_len,
				m_ipsec(m).out_auth,
				sa->key_auth, sa->ipad, sa->opad);

		goto input_finish;
	}
#endif

#ifdef HAVE_AESHMACSHA2
	/* fp_aes_cbc_decrypt_hsha256+() requires at least 3 AES blocks. */
	if (condition_dec_aescbc_hmacsha2(m_is_contiguous(m), plen) &&
	   ((sa->alg_auth == FP_AALGO_HMACSHA256)  ||
	    (sa->alg_auth == FP_AALGO_HMACSHA384)  ||
	    (sa->alg_auth == FP_AALGO_HMACSHA512)) &&
	    (sa->alg_enc == FP_EALGO_AESCBC)) {

#ifndef HAVE_CRYPTO_PREHANDLE
		fpn_aes_set_iv((uint64_t *)esp->enc_data);
#endif
		if(sa->alg_auth == FP_AALGO_HMACSHA256) {
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA256;
			fpn_aes_cbc_decrypt_hsha256((char *)esp,
						plen,
						(uint64_t *)sa->key_enc,
						sa->key_enc_len,
						m_ipsec(m).out_auth,
						sa->key_auth, sa->ipad, sa->opad);
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA384){
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA384;
			fpn_aes_cbc_decrypt_hsha384((char *)esp,
						plen,
						(uint64_t *)sa->key_enc,
						sa->key_enc_len,
						m_ipsec(m).out_auth,
						sa->key_auth, sa->ipad, sa->opad);
		}
		else {  // must be FP_AALGO_HMACSHA512
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA512;
			fpn_aes_cbc_decrypt_hsha512((char *)esp,
						plen,
						(uint64_t *)sa->key_enc,
						sa->key_enc_len,
						m_ipsec(m).out_auth,
						sa->key_auth, sa->ipad, sa->opad);
		}
		
		goto input_finish;
	}
#endif
	
#ifdef HAVE_AESHMACMD5
	/* Do MD5 every 64bytes, requires plen >= 40 */
	if (condition_dec_aescbc_hmacmd5(m_is_contiguous(m), plen) &&
	    (sa->alg_auth == FP_AALGO_HMACMD5) && (sa->alg_enc == FP_EALGO_AESCBC)) {

#ifndef HAVE_CRYPTO_PREHANDLE
		fpn_aes_set_iv((uint64_t *)esp->enc_data);
#endif
		fp_ipsec_ctx.auth_type = FP_AALGO_HMACMD5;
		fpn_aes_cbc_decrypt_hmd5((char *)esp,
				plen,
				(uint64_t *)sa->key_enc,
				sa->key_enc_len,
				m_ipsec(m).out_auth,
				sa->key_auth, sa->ipad, sa->opad);

		goto input_finish;
	}
#endif

#ifdef HAVE_3DESHMACSHA1
	if (condition_dec_3descbc_hmacsha1(m_is_contiguous(m), plen) &&
	    (sa->alg_auth == FP_AALGO_HMACSHA1) && (sa->alg_enc == FP_EALGO_3DESCBC)) {

#ifndef HAVE_CRYPTO_PREHANDLE
		fpn_3des_set_iv((uint64_t *)esp->enc_data);
#endif
		fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA1;
		fpn_3des_cbc_decrypt_hsha1((char *)esp,
				plen,
				(uint64_t *)sa->key_enc,
				m_ipsec(m).out_auth,
				sa->key_auth, sa->ipad, sa->opad);

		goto input_finish;
	}
#endif

#ifdef HAVE_3DESHMACSHA2
	if (condition_dec_3descbc_hmacsha2(m_is_contiguous(m), plen) &&
	   ((sa->alg_auth == FP_AALGO_HMACSHA256)  ||
	    (sa->alg_auth == FP_AALGO_HMACSHA384)  ||
	    (sa->alg_auth == FP_AALGO_HMACSHA512)) &&
	    (sa->alg_enc == FP_EALGO_3DESCBC)) {

#ifndef HAVE_CRYPTO_PREHANDLE
		fpn_3des_set_iv((uint64_t *)esp->enc_data);
#endif
		if(sa->alg_auth == FP_AALGO_HMACSHA256) {
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA256;
			fpn_3des_cbc_decrypt_hsha256((char *)esp,
						plen,
						(uint64_t *)sa->key_enc,
						m_ipsec(m).out_auth,
						sa->key_auth, sa->ipad, sa->opad);
		}
		else if(sa->alg_auth == FP_AALGO_HMACSHA384) {
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA384;
			fpn_3des_cbc_decrypt_hsha384((char *)esp,
						plen,
						(uint64_t *)sa->key_enc,
						m_ipsec(m).out_auth,
						sa->key_auth, sa->ipad, sa->opad);
		}
		else {
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA512;
			fpn_3des_cbc_decrypt_hsha512((char *)esp,
						plen,
						(uint64_t *)sa->key_enc,
						m_ipsec(m).out_auth,
						sa->key_auth, sa->ipad, sa->opad);
		}

		goto input_finish;
	}
#endif
	
#ifdef HAVE_3DESHMACMD5
	if (condition_dec_3descbc_hmacmd5(m_is_contiguous(m), plen) &&
	    (sa->alg_auth == FP_AALGO_HMACMD5) && (sa->alg_enc == FP_EALGO_3DESCBC)) {

#ifndef HAVE_CRYPTO_PREHANDLE
		fpn_3des_set_iv((uint64_t *)esp->enc_data);
#endif
		fp_ipsec_ctx.auth_type = FP_AALGO_HMACMD5;
		fpn_3des_cbc_decrypt_hmd5((char *)esp,
				plen, 
				(uint64_t *)sa->key_enc,
				m_ipsec(m).out_auth,
				sa->key_auth, sa->ipad, sa->opad);

		goto input_finish;
	}
#endif

#ifdef HAVE_DESHMACSHA1
	if (condition_dec_descbc_hmacsha1(m_is_contiguous(m), plen) &&
	    (sa->alg_auth == FP_AALGO_HMACSHA1) && (sa->alg_enc == FP_EALGO_DESCBC)) {

#ifndef HAVE_CRYPTO_PREHANDLE
		fpn_des_set_iv((uint64_t *)esp->enc_data);
#endif
		fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA1;
		fpn_des_cbc_decrypt_hsha1((char *)esp,
				plen,
				(uint64_t *)sa->key_enc,
				m_ipsec(m).out_auth,
				sa->key_auth, sa->ipad, sa->opad);

		goto input_finish;
	}
#endif

#ifdef HAVE_DESHMACSHA2
	if (condition_dec_descbc_hmacsha2(m_is_contiguous(m), plen) &&
	   ((sa->alg_auth == FP_AALGO_HMACSHA256)  ||
	    (sa->alg_auth == FP_AALGO_HMACSHA384)  ||
	    (sa->alg_auth == FP_AALGO_HMACSHA512)) &&
	    (sa->alg_enc == FP_EALGO_DESCBC)) {

#ifndef HAVE_CRYPTO_PREHANDLE
		fpn_des_set_iv((uint64_t *)esp->enc_data);
#endif
		if(sa->alg_auth == FP_AALGO_HMACSHA256){
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA256;
			fpn_des_cbc_decrypt_hsha256((char *)esp,
						plen,
						(uint64_t *)sa->key_enc,
						m_ipsec(m).out_auth,
						sa->key_auth, sa->ipad, sa->opad);
		}
		else if(sa->alg_auth == FP_AALGO_HMACSHA384){
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA384;
			fpn_des_cbc_decrypt_hsha384((char *)esp,
						plen,
						(uint64_t *)sa->key_enc,
						m_ipsec(m).out_auth,
						sa->key_auth, sa->ipad, sa->opad);
		}
		else {
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA512;
			fpn_des_cbc_decrypt_hsha512((char *)esp,
						plen,
						(uint64_t *)sa->key_enc,
						m_ipsec(m).out_auth,
						sa->key_auth, sa->ipad, sa->opad);
		}

		goto input_finish;
	}
#endif
	
#ifdef HAVE_DESHMACMD5
	if (condition_dec_descbc_hmacmd5(m_is_contiguous(m), plen) &&
	    (sa->alg_auth == FP_AALGO_HMACMD5) && (sa->alg_enc == FP_EALGO_DESCBC)) {

#ifndef HAVE_CRYPTO_PREHANDLE
		fpn_des_set_iv((uint64_t *)esp->enc_data);
#endif
		fp_ipsec_ctx.auth_type = FP_AALGO_HMACMD5;
		fpn_des_cbc_decrypt_hmd5((char *)esp,
					plen, 
					(uint64_t *)sa->key_enc,
					m_ipsec(m).out_auth,
					sa->key_auth, sa->ipad, sa->opad);

		goto input_finish;
	}
#endif

	{
		uint16_t off = (const char*)esp - mtod(m, const char*);

		if (sa->alg_auth == FP_AALGO_HMACMD5) {
			fpn_hmac_md5(m_ipsec(m).out_auth, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACMD5;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA1) {
			fpn_hmac_sha1(m_ipsec(m).out_auth, sa->key_auth,
					m, off, authlen,
						 sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA1;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA256) {
			fpn_hmac_sha256(m_ipsec(m).out_auth, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA256;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA384) {
			fpn_hmac_sha384(m_ipsec(m).out_auth, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA384;
		}
		else if (sa->alg_auth == FP_AALGO_HMACSHA512) {
			fpn_hmac_sha512(m_ipsec(m).out_auth, sa->key_auth,
					m, off, authlen,
					sa->ipad, sa->opad);
			fp_ipsec_ctx.auth_type = FP_AALGO_HMACSHA512;
		}
		else if (sa->alg_auth == FP_AALGO_AESXCBC)
			fpn_aes_xcbc_mac(m_ipsec(m).out_auth, sa->key_auth,
					m, off, authlen);
	}

	/* ESP sync decrypt */
	{
		uint64_t *src = (uint64_t *)(esp->enc_data + ivlen);
		uint16_t off = (char *)src - mtod(m, char*);
		const uint64_t *iv = (uint64_t *)esp->enc_data;
		const uint64_t *K64 = (uint64_t *)sa->key_enc;

		if (sa->alg_enc == FP_EALGO_DESCBC)
			fpn_des_cbc_decrypt(m, off, plen, iv, K64);
		else if (sa->alg_enc == FP_EALGO_3DESCBC)
			fpn_3des_cbc_decrypt(m, off, plen, iv, K64);
		else if (sa->alg_enc == FP_EALGO_AESCBC)
			fpn_aes_cbc_decrypt(m, off, plen, iv, K64, sa->key_enc_len);
	
		goto input_finish;
	}

input_finish:
#ifndef HAVE_HMAC_COMPLETE
	auth_failed = fpn_fast_memcmp(m_ipsec(m).out_auth, authbuf, alen);
#endif

	return esp4_input_finish(m, sa, esp->esp_seq, auth_failed);
#endif
}

int ipsec4_input(struct mbuf *m, struct fp_ip *ip)
{
	fp_sa_entry_t *sa;
	input_func func;
	void *data = (void *) ip + sizeof(struct fp_ip);

#ifndef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	/* Initialize ipsec context structure */
	/* Never enter esp4_input or ah4_input without this */
	fp_ipsec_ctx.auth_type = FP_AALGO_NULL;
	fp_ipsec_ctx.authsize = 0;
	fp_ipsec_ctx.auth_data = NULL;
	fp_ipsec_ctx.proto = FP_IPPROTO_MAX;
#endif

	TRACE_IPSEC_IN(FP_LOG_DEBUG, "ipsec_input");

	if (ip->ip_p == FP_IPPROTO_ESP) {
		struct fp_esp *esp = data;
		sa = sad_in_lookup(esp->esp_spi, ip->ip_dst.s_addr, FP_IPPROTO_ESP, m2vrfid(m));
		func = esp4_input;
	} else /*if (ip->ip_p == FP_IPPROTO_AH)*/ {
		struct fp_ah *ah = data;
		sa = sad_in_lookup(ah->ah_spi, ip->ip_dst.s_addr, FP_IPPROTO_AH, m2vrfid(m));
		func = ah4_input;
	}

	if (unlikely(sa == NULL)) {
		TRACE_IPSEC_IN(FP_LOG_NOTICE, "SA not found");
		FP_IPSEC_STATS_INC(fp_shared->ipsec.ipsec_stats[m2vrfid(m)], ipsec_no_sa);
#ifdef CONFIG_MCORE_IPSEC_INPUT_NOTIFY_UNKNOWN_SA
		return fp_ip_prepare_exception(m, FPTUN_EXC_IKE_NEEDED);
#endif
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
		return FP_DROP;
	}

	return func(m, sa, data);
}

int ipsec4_input_traversal(struct mbuf *m, struct fp_ip *ip)
{
	fp_sa_entry_t *sa;
	struct fp_udphdr *udp = (struct fp_udphdr *)(ip + 1);
	struct fp_esp *esp = (struct fp_esp *)(udp + 1);

#ifndef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	/* Initialize ipsec context structure */
	/* Never enter esp4_input without this */
	fp_ipsec_ctx.auth_type = FP_AALGO_NULL;
	fp_ipsec_ctx.authsize = 0;
	fp_ipsec_ctx.auth_data = NULL;
	fp_ipsec_ctx.proto = FP_IPPROTO_MAX;
#endif

	/* we only support ESP for IPsec NAT Traversal */	
	sa = sad_in_lookup(esp->esp_spi, ip->ip_dst.s_addr, FP_IPPROTO_ESP, m2vrfid(m));
	if (unlikely(sa != NULL) &&
	    likely(sa->flags & FP_SA_FLAG_UDPTUNNEL) &&
	    sa->dport == udp->uh_dport)
		return esp4_input(m, sa, esp);

	return FP_CONTINUE;
}

#ifdef CONFIG_MCORE_IPSEC_VERIFY_INBOUND
/* look-up IN policy for clear packets */
int ipsec_check_policy(struct mbuf *m, struct fp_ip *ip)
{
	fp_sp_entry_t *sp;
	uint8_t action;

	/* reset the flag (to ensure that policy will be checked after decapsulation) */
	m_priv(m)->flags &= ~M_IPSEC_SP_OK;

	/* check inbound policy for clear packets */
	if (ipsec_in_lookup(m, ip, NULL, &sp) < 0) {
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
		return FP_DROP;
	}

	if (likely(sp == NULL)) {
		/* default policy is bypass */
		return FP_CONTINUE;
	}

	action = sp->filter.action;
	if (likely(action == FP_SP_ACTION_BYPASS))
		return FP_CONTINUE;

	switch (action) {
	case FP_SP_ACTION_DISCARD:
		TRACE_IPSEC_IN(FP_LOG_INFO, "discard packet");
		break;
	case FP_SP_ACTION_PROTECT:
		if (sp->flags & FP_SP_FLAG_LEVEL_USE) {
			TRACE_IPSEC_IN(FP_LOG_INFO, "clear packet matched level use sp");
			return FP_CONTINUE;
		}
		TRACE_IPSEC_IN(FP_LOG_INFO, "packet requires ah/esp");
		FP_IPSEC_STATS_INC(sp->stats, sp_errors);
		break;
	default:
		TRACE_IPSEC_IN(FP_LOG_INFO, "unknown action");
		FP_IPSEC_STATS_INC(sp->stats, sp_errors);
		break;
	}

	FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedIPsec);
	return FP_DROP;
}
#endif /* CONFIG_MCORE_IPSEC_VERIFY_INBOUND */
