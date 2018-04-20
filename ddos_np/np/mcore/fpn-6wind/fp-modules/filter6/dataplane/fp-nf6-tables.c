/*
 * Copyright(c) 2009 6WIND, All rights reserved.
 */

#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"

#include "fp-dscp.h"
#include "netinet/fp-udp.h"
#include "netinet/fp-tcp.h"
#include "netinet/fp-icmp6.h"
#include "netinet/fp-sctp.h"
#include "fp-nfct.h"
#include "fp-nf-tables.h"
#include "fp-nf6-tables.h"
#include "fp-main-process.h"
#include "fp-ip6.h"

#include "fp-nf6-cache.h"

static FPN_DEFINE_SHARED(fpn_spinlock_t, nf6_ratelimit_lock);

void fp_nf6_init(void)
{
	int vr, t, r, h;
	int hook6_prio[FP_NF_IP_NUMHOOKS][FP_NF6_TABLE_NUM + 1] = {
		{ FP_NF_TABLE_MANGLE, -1 },       /* FP_NF_IP_PRE_ROUTING */
		{ FP_NF_TABLE_FILTER, FP_NF_TABLE_MANGLE, -1 },    /* FP_NF_IP_LOCAL_IN */
		{ FP_NF_TABLE_MANGLE, FP_NF_TABLE_FILTER, -1 },    /* FP_NF_IP_FORWARD */
		{ FP_NF_TABLE_FILTER, FP_NF_TABLE_MANGLE, -1 },    /* FP_NF_IP_LOCAL_OUT */
		{ FP_NF_TABLE_MANGLE, -1 } };     /* FP_NF_IP_POST_ROUTING */
	uint32_t i;

#ifdef CONFIG_MCORE_M_TAG
	nfm_tag_type = m_tag_type_register(NFM_TAG_NAME);
	if (nfm_tag_type < 0) {
		TRACE_NF(FP_LOG_ERR, "Cannot register tag type for '" NFM_TAG_NAME "'");
	}
#endif

	memcpy(fp_shared->fp_nf6_hook_prio[0], hook6_prio, sizeof(hook6_prio));
	memcpy(fp_shared->fp_nf6_hook_prio[1], hook6_prio, sizeof(hook6_prio));
	fp_shared->fp_nf6_current_hook_prio = 0;

	memset(fp_shared->fp_nf6_tables, 0, sizeof(fp_shared->fp_nf6_tables));
	memset(fp_shared->fp_nf6_rules, 0, sizeof(fp_shared->fp_nf6_rules));
	fp_shared->fp_nf6_current_table = 0;

	r = 0;
	for (vr = 0; vr < FP_NF_MAX_VR; vr++) {
		for (t = 0; t < FP_NF6_TABLE_NUM; t++) {
			fp_nf6table_t *tb = &fp_shared->fp_nf6_tables[0][vr][t];

			/* Each table must have at least one rule to maintain
			 * a consistent state in the shared memory. */
			for (h = 0; h < FP_NF_IP_NUMHOOKS; h++) {
				tb->fpnf6table_hook_entry[h] = r;
				tb->fpnf6table_underflow[h] = r;
			}
			fp_shared->fp_nf6_rules[0][r].target.type = FP_NF_TARGET_TYPE_ERROR;
			r++;

			tb->fpnf6table_rules_count = 1;
		}
	}

	bzero(&fp_shared->fp_nf6_ct, sizeof(fp_shared->fp_nf6_ct));
	/* The hash_next starting value is supposed to be 'undefined', represented by FP_NF6_CT_MAX */
	for (i = 0; i < FP_NF6_CT_MAX; i++) {
		fp_shared->fp_nf6_ct.fp_nf6ct[i].tuple[FP_NF_IP_CT_DIR_ORIGINAL].hash_next.s.index = FP_NF6_CT_MAX;
		fp_shared->fp_nf6_ct.fp_nf6ct[i].tuple[FP_NF_IP_CT_DIR_REPLY].hash_next.s.index = FP_NF6_CT_MAX;
		fp_shared->fp_nf6_ct.fp_nf6ct[i].next_available = i+1;
	}
 	/* The algorithm supposes that hash table is initialized to FP_NF6_CT_MAX for all entries */
	for (i = 0; i < FP_NF6_CT_HASH_SIZE; i++)
		fp_shared->fp_nf6_ct.fp_nf6ct_hash[i].s.index = FP_NF6_CT_MAX;
}

static int ip6_masked_addrcmp(struct fp_in6_addr addr1, struct fp_in6_addr mask,
                              struct fp_in6_addr addr2)
{
	int i;

	for (i = 0; i < 16; i++) {
		if((addr1.fp_s6_addr[i] & mask.fp_s6_addr[i]) !=
		   (addr2.fp_s6_addr[i] & mask.fp_s6_addr[i]))
			return 1;
	}
	return 0;
}

/* Returns 1 if the id is matched by the range, 0 otherwise */
static inline int nf6_id_match(uint32_t min, uint32_t max, uint32_t id, int invert)
{
	return (id >= min && id <= max) ^ invert;
}

/* Check for an extension */
static inline int ip6t_ext_hdr(uint8_t nexthdr)
{
	return (nexthdr == FP_IPPROTO_HOPOPTS  ||
		nexthdr == FP_IPPROTO_ROUTING  ||
		nexthdr == FP_IPPROTO_FRAGMENT ||
		nexthdr == FP_IPPROTO_ESP      ||
		nexthdr == FP_IPPROTO_AH       ||
		/* optimization, if you remove it, check in the callers */
	/*	nexthdr == FP_IPPROTO_NONE     || */
		nexthdr == FP_IPPROTO_DSTOPTS);
}

/* For TCP, UDP, SCTP and GRE packets, lookup for a matching conntrack
 * for this packet, and return the state. If a conntrack entry is
 * found, also update its statistics. We know that headers are in
 * contiguous mem thanks to fp_nf_check_packet(), except for sctp
 * chunks. */
uint8_t fp_nf6ct_update(struct mbuf *m, uint16_t fragoff, uint8_t nexthdr, uint32_t offset)
{
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	uint32_t sctp_offset;
	struct fp_udphdr uh;
	struct fp_tcphdr th;
	struct fp_sctphdr sh;
	struct fp_sctpchunkhdr sch;
	uint16_t dport = 0, sport = 0;
	int fin = 0;

	/* A fragment will be sent as an exception. */
	if (fragoff & FP_IP6F_OFF_MASK)
		return FP_NF_CT_MBUF_OTHER;

	switch (nexthdr) {
	case FP_IPPROTO_TCP:
		if (m_copytobuf(&th, m, offset, sizeof(struct fp_tcphdr)) !=
		    sizeof(struct fp_tcphdr))
			return FP_NF_CT_MBUF_OTHER;
		/* Some special packets must be sent in exception */
		if (th.th_flags & (TH_SYN|TH_RST))
			return FP_NF_CT_MBUF_OTHER;
		if (th.th_flags & TH_FIN)
			fin = 1;
		/* 
		 * Only ASSURED ct are set in shared memory, hence no need to
		 * send (ACK && !PSH) to SP.
		 */
		sport = th.th_sport;
		dport = th.th_dport;
		break;
	case FP_IPPROTO_UDP:
		if (m_copytobuf(&uh, m, offset, sizeof(struct fp_udphdr)) !=
		    sizeof(struct fp_udphdr))
			return FP_NF_CT_MBUF_OTHER;
		sport = uh.uh_sport;
		dport = uh.uh_dport;
		break;
	case FP_IPPROTO_SCTP:
		if (m_copytobuf(&sh, m, offset, sizeof(struct fp_sctphdr)) !=
		    sizeof(struct fp_sctphdr))
			return FP_NF_CT_MBUF_OTHER;
		/* Some special packets must be sent in exception */
		sctp_offset = offset + sizeof(struct fp_sctphdr);
		while (sctp_offset < m_len(m)) {
			/* TODO: need to add a fp_nf6_check_packet() to avoid this test */
			if (m_copytobuf(&sch, m, sctp_offset, sizeof(struct fp_sctpchunkhdr))
			    != sizeof(struct fp_sctpchunkhdr))
				return FP_NF_CT_MBUF_OTHER;
			if (sch.chunk_type == SCTP_CID_SHUTDOWN ||
			    sch.chunk_type == SCTP_CID_SHUTDOWN_ACK ||
			    sch.chunk_type == SCTP_CID_SHUTDOWN_COMPLETE) {
				return FP_NF_CT_MBUF_OTHER;
			}
			sctp_offset += (ntohs(sch.chunk_length) + 3) & ~3;
		}
		sport = sh.src_port;
		dport = sh.dest_port;
		break;
	case FP_IPPROTO_GRE:
	case FP_IPPROTO_ESP:
	case FP_IPPROTO_AH:
		/* nothing to do, just continue with conntrack lookup. */
		break;
	default:
		/* Other protocols are not added into fp_nf6_ct, hence
		 * we can bypass the lookup. */
		return FP_NF_CT_MBUF_OTHER;
	}

	if (fp_nf6ct_get(m, ip6, nexthdr, sport, dport) < 0) {
		/* no entry found, return */
		return FP_NF_CT_MBUF_OTHER;
	}

	if (unlikely(fin))
		m_priv(m)->fp_nfct.v6->flag |= FP_NFCT_FLAG_END;

	if (unlikely(m_priv(m)->fp_nfct.v6->flag & FP_NFCT_FLAG_END)) {
		/* remove update flag to prevent from sending hf sync for that conntrack
		   after a FIN segment */
		m_priv(m)->fp_nfct.v6->flag &= ~FP_NFCT_FLAG_UPDATE;
		return FP_NF_CT_MBUF_OTHER;
	}

	/* valid conntrack found, update counters */
	m_priv(m)->fp_nfct.v6->counters[m_priv(m)->fp_nfct_dir].packets++;
#ifdef CONFIG_MCORE_NF_CT_BYTES
	m_priv(m)->fp_nfct.v6->counters[m_priv(m)->fp_nfct_dir].bytes += m_len(m);
#endif
	m_priv(m)->fp_nfct.v6->flag |= FP_NFCT_FLAG_UPDATE;
	return FP_NF_CT_MBUF_ESTABLISHED;
}

static inline int nf_ipv6_match(struct mbuf *m, struct fp_nf6rule *r,
                                const fp_ifnet_t *indev, const fp_ifnet_t *outdev)
{
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	struct fp_udphdr uh;
	struct fp_tcphdr th;
	struct fp_icmp6_hdr ih;
	struct fp_sctphdr sh;
	struct fp_sctpchunkhdr sch;
	uint32_t chunkmapcopy[FP_NF_SCTP_CHUNKMAP_SIZE / (sizeof(uint32_t) * 8)];
	unsigned long ret;
	uint32_t offset = sizeof(struct fp_ip6_hdr);
	uint32_t optlen, ip_off;
	uint16_t fragoff = 0;
	uint8_t nexthdr = ip6->ip6_nxt, tcpopt[64]; /* maximum length for TCP options is 60 bytes */
	unsigned int i;
	int  match;

#ifndef CONFIG_MCORE_NF_TABLE_PER_VR
	if (r->l2_opt.vrfid != FP_NF_VRFID_UNSPECIFIED)
		if (r->l2_opt.vrfid != m2vrfid(m))
			return NF6_IP_MATCH_NO;
#endif

#define FWINV(bool, invflg) ((bool) ^ !!(r->l2.ipv6.invflags & invflg))

	if (FWINV(ip6_masked_addrcmp(ip6->ip6_src, r->l2.ipv6.smsk, r->l2.ipv6.src),
	          FP_NF_IPT_INV_SRCIP) ||
	    FWINV(ip6_masked_addrcmp(ip6->ip6_dst, r->l2.ipv6.dmsk, r->l2.ipv6.dst),
	          FP_NF_IPT_INV_DSTIP))
		return NF6_IP_MATCH_NO;

	/* here we can use a memcmp() instead of strncmp() because we
	 * know the len */
	if (indev) {
		ret = r->l2.ipv6.iniface_len &&
			fpn_fast_memcmp(indev->if_name, r->l2.ipv6.iniface, r->l2.ipv6.iniface_len);
		if (FWINV(ret != 0, FP_NF_IPT_INV_VIA_IN))
			return NF6_IP_MATCH_NO;
	}

	if (outdev) {
		ret = r->l2.ipv6.outiface_len &&
			fpn_fast_memcmp(outdev->if_name, r->l2.ipv6.outiface, r->l2.ipv6.outiface_len);
		if (FWINV(ret != 0, FP_NF_IPT_INV_VIA_OUT))
			return NF6_IP_MATCH_NO;
	}
#undef FWINV

	if (r->l2.ipv6.flags & FP_NF6_IPT_F_PROTO ||
	    r->l2_opt.opt & FP_NF_l2OPT_FRAG) {
		struct fp_ip6_frag fh;
		struct fp_ip6_ext exthdr;
		uint8_t frag = 0;

		nexthdr = ip6->ip6_nxt;
		while (ip6t_ext_hdr(nexthdr)) {
			fp_nf6_cache_disable_next();
#ifdef unneeded
			/* ip6t_ext_hdr() return 0 in case of FP_IPPROTO_NONE */
			if (nexthdr == FP_IPPROTO_NONE)
				break;
#endif
			if (m_copytobuf(&exthdr, m, offset, sizeof(struct fp_ip6_ext)) !=
			    sizeof(struct fp_ip6_ext))
				return NF6_IP_MATCH_ERROR;

			if (nexthdr == FP_IPPROTO_FRAGMENT) {
				if (m_copytobuf(&fh, m, offset, sizeof(struct fp_ip6_frag)) !=
				    sizeof(struct fp_ip6_frag))
					return NF6_IP_MATCH_ERROR;
				frag = 1;
				offset += 8;
				fragoff = ntohs(fh.ip6f_offlg);
				if (fragoff & FP_IP6F_OFF_MASK) {
					if (!ip6t_ext_hdr(fh.ip6f_nxt)
#ifdef unneeded
					    /* ip6t_ext_hdr() return 0 in case of FP_IPPROTO_NONE */
					    || fh.ip6f_nxt == FP_IPPROTO_NONE
#endif
					   ) {
						nexthdr = fh.ip6f_nxt;
						break;
					} else
						return NF6_IP_MATCH_ERROR;
				}
			} else if (nexthdr == FP_IPPROTO_AH)
				offset += (exthdr.ip6e_len + 2) << 2;
			else
	                        offset += fp_ipv6_optlen(&exthdr);

			nexthdr = exthdr.ip6e_nxt;
		}

		if (r->l2.ipv6.flags & FP_NF6_IPT_F_PROTO) {
			if (nexthdr == r->l2.ipv6.proto) {
				if (r->l2.ipv6.invflags & FP_NF_IPT_INV_PROTO)
					return NF6_IP_MATCH_NO;
			} else
				if (r->l2.ipv6.proto != 0 &&
				    !(r->l2.ipv6.invflags & FP_NF_IPT_INV_PROTO))
					return NF6_IP_MATCH_NO;
		}

		if (r->l2_opt.opt & FP_NF_l2OPT_FRAG) {
			if (!frag)
				return NF6_IP_MATCH_NO;

			if (!nf6_id_match(r->l2_opt.frag.ids[0], r->l2_opt.frag.ids[1],
			                  ntohl(fh.ip6f_ident),
			                  !!(r->l2_opt.frag.invflags & FP_IP6T_FRAG_INV_IDS)) ||
			    (r->l2_opt.frag.flags & FP_IP6T_FRAG_RES &&
			     (fh.ip6f_reserved || fragoff & 0x6)) ||
			    (r->l2_opt.frag.flags & FP_IP6T_FRAG_FST &&
			     fragoff & FP_IP6F_OFF_MASK) ||
			    (r->l2_opt.frag.flags & FP_IP6T_FRAG_MF &&
			     !(fragoff & FP_IP6F_MORE_FRAG)) ||
			    (r->l2_opt.frag.flags & FP_IP6T_FRAG_NMF &&
			     fragoff & FP_IP6F_MORE_FRAG))
				return NF6_IP_MATCH_NO;
		}
	}


	if ((r->l2_opt.opt & FP_NF_l2OPT_DSCP)) {
		fp_nf6_cache_disable_next();
		if(!((ip6->ip6_tclass == r->l2_opt.dscp) ^ r->l2_opt.invdscp))
			return NF6_IP_MATCH_NO;
	}

	if (r->l2_opt.opt & FP_NF_l2OPT_RATELIMIT) {
		uint64_t now;
		int64_t delta;

		fp_nf6_cache_disable_next();
		fpn_spinlock_lock(&nf6_ratelimit_lock);
		now = fpn_get_clock_cycles();
		delta = (int64_t)(now - r->l2_opt.rateinfo.prev);
		if (delta > 0) {
			r->l2_opt.rateinfo.credit += delta;
			r->l2_opt.rateinfo.prev = now;
		}
		if (r->l2_opt.rateinfo.credit > r->l2_opt.rateinfo.credit_cap)
			r->l2_opt.rateinfo.credit = r->l2_opt.rateinfo.credit_cap;

		if (r->l2_opt.rateinfo.credit < r->l2_opt.rateinfo.cost) {
			fpn_spinlock_unlock(&nf6_ratelimit_lock);
			return NF6_IP_MATCH_NO;
		}
		/* We're not limited. */
		r->l2_opt.rateinfo.credit -= r->l2_opt.rateinfo.cost;
		fpn_spinlock_unlock(&nf6_ratelimit_lock);
	}

	if (r->l2_opt.opt & FP_NF_l2OPT_MARK) {
		uint32_t mark = 0;

#ifdef CONFIG_MCORE_M_TAG
		/* ignore return value, if tag does
		 * not exist, mark will stay to 0 */
		if (m_tag_get(m, nfm_tag_type, &mark) == 0)
			mark = ntohl(mark);
#endif

		if (!(((mark & r->l2_opt.mark.mask) == r->l2_opt.mark.mark)
		      ^ r->l2_opt.mark.invert))
			return NF6_IP_MATCH_NO;

	}

#ifdef CONFIG_MCORE_RPF_IPV6
	if (r->l2_opt.opt & FP_NF_l2OPT_RPFILTER) {
		/* send the packet to the kernel if there are unsupported
		 * rpf match options */
		if (r->l2_opt.rpf_flags & ~FP_NF_RPF_INVERT)
			return NF6_IP_MATCH_EXCEPTION;
		/* When the invert flag is set, the packet does NOT match when
		 * the rpf check is OK
		 * We use !!() because ^ is a bitwise operator */
		if (!!fp_ip6_rpf_check(m) ^ !!(r->l2_opt.rpf_flags & FP_NF_RPF_INVERT))
			return NF6_IP_MATCH_NO;
	}
#endif /* CONFIG_MCORE_RPF_IPV6 */

	if (r->l2_opt.opt & FP_NF_l2OPT_MAC) {

		fp_nf6_cache_disable_next();

		if (!indev || indev->if_type != FP_IFTYPE_ETHER)
			return NF6_IP_MATCH_NO;
		if (s_headroom((const struct sbuf *)m_first_seg(m)) < 14)
			return NF6_IP_MATCH_NO;

		uint16_t *a = (uint16_t *) ((uint8_t *)ip6 - 8);
		uint16_t *b = (uint16_t *) r->l2_opt.mac.srcaddr;

		if (((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) ^ r->l2_opt.mac.invert)
			return NF6_IP_MATCH_NO;
	}

	if (r->l2_opt.opt & FP_NF_l2OPT_PHYSDEV) {
		fp_nf6_cache_disable_next();

		return nf6_physdev_match(m, r, indev, outdev);
	}

	switch(r->l3.type) {
	case FP_NF_L3_TYPE_NONE:
		break;
	case FP_NF_L3_TYPE_UDP:
		/* Must not be a fragment. */
		if (fragoff & FP_IP6F_OFF_MASK)
			return NF6_IP_MATCH_NO;

		if (m_copytobuf(&uh, m, offset, sizeof(struct fp_udphdr)) !=
		    sizeof(struct fp_udphdr))
			return NF6_IP_MATCH_ERROR;

		if (!(fp_nf_port_match(r->l3.data.udp.spts[0], r->l3.data.udp.spts[1],
			       ntohs(uh.uh_sport),
			       !!(r->l3.data.udp.invflags & FP_NF_IPT_UDP_INV_SRCPT))
		      && fp_nf_port_match(r->l3.data.udp.dpts[0], r->l3.data.udp.dpts[1],
				  ntohs(uh.uh_dport),
				  !!(r->l3.data.udp.invflags & FP_NF_IPT_UDP_INV_DSTPT))))
			return NF6_IP_MATCH_NO;
		break;
	case FP_NF_L3_TYPE_TCP:
		if ((ip_off = fragoff & FP_IP6F_OFF_MASK) != 0) {
			/* Don't allow a fragment of TCP 8 bytes in. Nobody normal
			 * causes this. Its a cracker trying to break in by doing a
			 * flag overwrite to pass the direction checks.
			 */
			if (ip_off == 1)
				return NF6_IP_MATCH_ERROR;
			/* Must not be a fragment. */
			return NF6_IP_MATCH_NO;
		}

		if (m_copytobuf(&th, m, offset, sizeof(struct fp_tcphdr)) !=
		    sizeof(struct fp_tcphdr))
			return NF6_IP_MATCH_ERROR;

		if (!fp_nf_port_match(r->l3.data.tcp.spts[0], r->l3.data.tcp.spts[1],
				ntohs(th.th_sport),
				!!(r->l3.data.tcp.invflags & FP_NF_IPT_TCP_INV_SRCPT)))
			return NF6_IP_MATCH_NO;

		if (!fp_nf_port_match(r->l3.data.tcp.dpts[0], r->l3.data.tcp.dpts[1],
				ntohs(th.th_dport),
				!!(r->l3.data.tcp.invflags & FP_NF_IPT_TCP_INV_DSTPT)))
			return NF6_IP_MATCH_NO;

		if (!(((((uint8_t *)&th)[13] & r->l3.data.tcp.flg_mask) == r->l3.data.tcp.flg_cmp)
		      ^ !!(r->l3.data.tcp.invflags & FP_NF_IPT_TCP_INV_FLAGS)))
			return NF6_IP_MATCH_NO;

		if (r->l3.data.tcp.option) {
			optlen = th.th_off * 4;
			if (optlen < sizeof(struct fp_tcphdr))
				return NF6_IP_MATCH_ERROR;

			if (optlen - sizeof(struct fp_tcphdr) == 0
			    && !(r->l3.data.tcp.invflags & FP_NF_IPT_TCP_INV_OPTION))
				return NF6_IP_MATCH_NO;

			if (m_copytobuf(&tcpopt, m, offset + sizeof(struct fp_tcphdr), optlen) !=
			    optlen)
				return NF6_IP_MATCH_ERROR;

			for (i = 0; i < optlen; ) {
				FPN_TRACK();
				if (tcpopt[i] == r->l3.data.tcp.option) {
					if (r->l3.data.tcp.invflags & FP_NF_IPT_TCP_INV_OPTION)
						return NF6_IP_MATCH_NO;
					else
						break;
				}
				if (tcpopt[i] < 2)
					i++;
				else
					i += tcpopt[i + 1] ? : 1;
			}
		}
		break;
	case FP_NF_L3_TYPE_SCTP:
		/* Must not be a fragment. */
		if (fragoff & FP_IP_OFFMASK)
			return NF6_IP_MATCH_NO;

		if (m_copytobuf(&sh, m, offset, sizeof(struct fp_sctphdr)) !=
		    sizeof(struct fp_sctphdr))
			return NF6_IP_MATCH_ERROR;

		if (r->l3.data.sctp.flags & FP_NF_IPT_SCTP_SRC_PORTS)
			if (!fp_nf_port_match(r->l3.data.sctp.spts[0], r->l3.data.sctp.spts[1],
			                      ntohs(sh.src_port),
			                      !!(r->l3.data.sctp.invflags & FP_NF_IPT_SCTP_SRC_PORTS)))
				return NF6_IP_MATCH_NO;

		if (r->l3.data.sctp.flags & FP_NF_IPT_SCTP_DEST_PORTS)
			if (!fp_nf_port_match(r->l3.data.sctp.dpts[0], r->l3.data.sctp.dpts[1],
			                      ntohs(sh.dest_port),
			                      !!(r->l3.data.sctp.invflags & FP_NF_IPT_SCTP_DEST_PORTS)))
				return NF6_IP_MATCH_NO;

		/* Check type match */
		if (r->l3.data.sctp.flags & FP_NF_IPT_SCTP_CHUNK_TYPES) {
			uint32_t sctp_offset;

			if (r->l3.data.sctp.chunk_match_type == FP_NF_SCTP_CHUNK_MATCH_ALL)
				memcpy(chunkmapcopy, r->l3.data.sctp.chunkmap, sizeof(chunkmapcopy));
			else
				memset(chunkmapcopy, 0, sizeof(chunkmapcopy));

#define FP_NF_SCTP_MATCH_FLAGS(flag_info, flag_count, _chunktype, _chunkflags, match)          \
do {                                                                                           \
        int k;                                                                                 \
        match = 1;                                                                             \
        for (k = 0; k < (flag_count); k++)                                                     \
                if ((flag_info[k].chunktype) == (_chunktype))                                  \
                        match = ((_chunkflags) & flag_info[k].flag_mask) == flag_info[k].flag; \
} while(0)

			sctp_offset = offset + sizeof(struct fp_sctphdr);
			while (sctp_offset < m_len(m)) {
				/* TODO: need to add a fp_nf6_check_packet() to avoid this test */
				if (m_copytobuf(&sch, m, sctp_offset, sizeof(struct fp_sctpchunkhdr))
				    != sizeof(struct fp_sctpchunkhdr))
					return NF6_IP_MATCH_ERROR;
				if (FP_NF_SCTP_CHUNKMAP_IS_SET(r->l3.data.sctp.chunkmap, sch.chunk_type)) {
					switch (r->l3.data.sctp.chunk_match_type) {
					case FP_NF_SCTP_CHUNK_MATCH_ANY:
						FP_NF_SCTP_MATCH_FLAGS(r->l3.data.sctp.flag_info,
						                       r->l3.data.sctp.flag_count,
						                       sch.chunk_type, sch.chunk_flags, match);
						if (match)
							goto sctp_type_match;
						break;
					case FP_NF_SCTP_CHUNK_MATCH_ALL:
						FP_NF_SCTP_MATCH_FLAGS(r->l3.data.sctp.flag_info,
						                       r->l3.data.sctp.flag_count,
						                       sch.chunk_type, sch.chunk_flags, match);
						if (match)
							FP_NF_SCTP_CHUNKMAP_CLEAR(chunkmapcopy, sch.chunk_type);
						break;
					case FP_NF_SCTP_CHUNK_MATCH_ONLY:
						FP_NF_SCTP_MATCH_FLAGS(r->l3.data.sctp.flag_info,
						                       r->l3.data.sctp.flag_count,
						                       sch.chunk_type, sch.chunk_flags, match);
						if (!match)
							goto sctp_type_match;
						break;
					}
				} else {
					switch (r->l3.data.sctp.chunk_match_type) {
					case FP_NF_SCTP_CHUNK_MATCH_ONLY:
						match = 0;
						goto sctp_type_match;
					}
				}
				sctp_offset += (ntohs(sch.chunk_length) + 3) & ~3;
			}
#undef FP_NF_SCTP_MATCH_FLAGS

			switch (r->l3.data.sctp.chunk_match_type) {
			case FP_NF_SCTP_CHUNK_MATCH_ALL:
				if (FP_NF_SCTP_CHUNKMAP_IS_CLEAR(chunkmapcopy))
					match = 1;
				else
					match = 0;
				break;
			case FP_NF_SCTP_CHUNK_MATCH_ANY:
				match = 0;
				break;
			case FP_NF_SCTP_CHUNK_MATCH_ONLY:
				match = 1;
				break;
			default:
				/* should never be reached */
				match = 0;
				break;
			}
sctp_type_match:
			if (!(match ^ !!(r->l3.data.sctp.invflags & FP_NF_IPT_SCTP_CHUNK_TYPES)))
				return NF6_IP_MATCH_NO;
		}
		break;
	case FP_NF_L3_TYPE_ICMP:
		/* Must not be a fragment. */
		if (fragoff & FP_IP6F_OFF_MASK)
			return NF6_IP_MATCH_NO;

		if (m_copytobuf(&ih, m, offset, sizeof(struct fp_icmp6_hdr)) !=
		    sizeof(struct fp_icmp6_hdr))
			return NF6_IP_MATCH_ERROR;

		if (!((ih.icmp6_type == r->l3.data.icmp.type &&
		       ih.icmp6_code >= r->l3.data.icmp.code[0] &&
		       ih.icmp6_code <= r->l3.data.icmp.code[1]) ^
		     !!(r->l3.data.icmp.invflags & FP_NF_IPT_ICMP_INV)))
			return NF6_IP_MATCH_NO;
		break;
	default:
		return NF6_IP_MATCH_NO;
	}

	if (r->l3.state) {
		fp_nf6_cache_next_need_ct_state(r->l3.state);

		if (!m_priv(m)->fp_nfct_established)
			m_priv(m)->fp_nfct_established = fp_nf6ct_update(m, fragoff, nexthdr, offset);

		if (m_priv(m)->fp_nfct_established == FP_NF_CT_MBUF_OTHER)
			return NF6_IP_MATCH_EXCEPTION;
		if (m_priv(m)->fp_nfct_established != r->l3.state)
			return NF6_IP_MATCH_NO;
	}

	if (r->l3_opt.opt & FP_NF_l3OPT_MULTIPORT) {
		uint16_t sport, dport;
		struct fp_tcphdr h;
		if (nexthdr == FP_IPPROTO_TCP ||
		    nexthdr == FP_IPPROTO_UDP ||
		    nexthdr == FP_IPPROTO_SCTP ||
		    nexthdr == 0x21 /* DCCP */ ||
		    nexthdr == 0x88 /* UDPLite */ ) {
			/* All protocols headers begin with src port (16 bits) and
			 * dst ports (16 bits) so we can use the tcp struct to access
			 * ports for all protocols */
			if (m_copytobuf(&h, m, offset, sizeof(struct fp_tcphdr)) !=
					sizeof(struct fp_tcphdr))
				return NF6_IP_MATCH_ERROR;

			sport = ntohs(h.th_sport);
			dport = ntohs(h.th_dport);
		}
		else {
			return NF6_IP_MATCH_NO;
		}

		if (!fp_nf_multiport_match(&(r->l3_opt.multiport), sport, dport))
			return NF6_IP_MATCH_NO;
	}

	return NF6_IP_MATCH_YES;
}

static FPN_DEFINE_PER_CORE(int [FP_NF6_MAXRULES], fp_nf6_comefrom);
static inline int fp_nf6_table(struct mbuf *m, int tablenum, int hook,
			       const fp_ifnet_t *indev, const fp_ifnet_t *outdev)
{
	int res, verdict, back, cur;
#ifdef CONFIG_MCORE_NF_TABLE_PER_VR
	uint16_t nf_vr = m2vrfid(m);
#else
	uint16_t nf_vr = 0;
#endif
	int cur_table = fp_shared->fp_nf6_current_table;
	fp_nf6table_t *table = &fp_shared->fp_nf6_tables[cur_table][nf_vr][tablenum];

#if 0
	/* Assume fp_shared->fp_nf6_hook_prio[fp_shared->fp_nf6_current_hook_prio] is set correctly */
	if (!(table->fpnf6table_valid_hooks & (1 << hook)))
		return FP_NF6_ACCEPT;
#endif

#define RULE(n)  fp_shared->fp_nf6_rules[cur_table][n]
	cur = table->fpnf6table_hook_entry[hook];
	back = table->fpnf6table_underflow[hook];
	do {
		if ((res = nf_ipv6_match(m, &RULE(cur), indev, outdev)) <= 0)
			goto no_match;

		FP_NF_STATS_INC(RULE(cur).stats, pcnt);
		FP_NF_STATS_ADD(RULE(cur).stats, bcnt, m_len(m));

		/* check that the rule can be cached; if not, disable
		 * the cache for this packet */
		fp_nf6_cache_check_rule(&RULE(cur));

		switch(RULE(cur).target.type) {
		case FP_NF_TARGET_TYPE_STANDARD:
			verdict = RULE(cur).target.data.standard.verdict;
			if (verdict < 0) {
				/* If verdict is != from FP_NF_IPT_RETURN and FP_NF_ACCEPT,
				 * cache is disabled.
				 */
				fp_nf6_cache_check_update(m, hook, tablenum, indev,
							  outdev, &RULE(cur), -verdict - 1);
				if (verdict == FP_NF_IPT_RETURN) {
					cur = back;
					back = FPN_PER_CORE_VAR(fp_nf6_comefrom)[back];
					continue;
				}
				return - verdict - 1;
			}
			/* Don't send verdict to fp_nf6_cache_check_update(), here verdict
			 * is >0, this means that we must jump to another rule, so we want
			 * to avoid a confusion between rule number and FP_NF_ACCEPT.
			 */
			fp_nf6_cache_check_update(m, hook, tablenum, indev,
						  outdev, &RULE(cur), FP_NF_CONTINUE);
			/* The verdict value is the rule index *relative* to the beginning
			 * of the table. Since all rules are stored in the same global
			 * array, we must shift it to get an absolute index. */
			verdict += fp_nf6_first_ruleid(table);
			if (&RULE(verdict) != &RULE(cur + 1)
			    && !(RULE(cur).l2.ipv6.flags & FP_NF6_IPT_F_GOTO)) {
				cur++;
				FPN_PER_CORE_VAR(fp_nf6_comefrom)[cur] = back;
				back = cur;
			}
			cur = verdict;
			continue;
			break;
		case FP_NF_TARGET_TYPE_MARK_V2:
			fp_nf_update_mark(m, RULE(cur).target.data.mark.mark,
					  RULE(cur).target.data.mark.mask);
			fp_nf6_cache_check_update(m, hook, tablenum, indev,
						  outdev, &RULE(cur), FP_NF_CONTINUE);
			break;
		case FP_NF_TARGET_TYPE_DSCP:
			fp_change_ipv6_dscp(mtod(m, struct fp_ip6_hdr *),
					    RULE(cur).target.data.dscp.dscp);
			fp_nf6_cache_check_update(m, hook, tablenum, indev,
						  outdev, &RULE(cur), FP_NF_CONTINUE);
			break;
		case FP_NF_TARGET_TYPE_LOG:
		case FP_NF_TARGET_TYPE_ULOG:
		case FP_NF_TARGET_TYPE_REJECT:
		case FP_NF_TARGET_TYPE_TCPMSS:
			return FP_NF_EXCEPTION;
		case FP_NF_TARGET_TYPE_DEV: {
			fp_ifnet_t *ifp;
			int ret = FP_DROP; /* not FP_NF_DROP */

			/* if possible, add this in cache; we have to
			 * do it before fp_ip_inetif_send() because m
			 * will be freed. */
			fp_nf6_cache_check_update(m, hook, tablenum, indev,
						  outdev, &RULE(cur), FP_NF_STOLEN);

#ifdef CONFIG_MCORE_M_TAG
			/* set mark if needed */
			if (RULE(cur).target.data.dev.flags & FP_NF_DEV_FLAG_SET_MARK)
				m_tag_add(m, nfm_tag_type, htonl(RULE(cur).target.data.dev.mark));
#endif

			/* send packet to device */
			ifp = fp_fast_getifnetbyname(RULE(cur).target.data.dev.ifname,
						     RULE(cur).target.data.dev.ifname_hash,
						     RULE(cur).target.data.dev.ifname_len);
			if (likely(ifp != NULL && !FP_IS_IFTYPE_ETHER(ifp->if_type)))
				ret = FPN_HOOK_CALL(fp_ip6_inet6if_send)(m, ifp);

			fp_process_input_finish(m, ret);
			return FP_NF_STOLEN;
		}
		case FP_NF_TARGET_TYPE_ERROR:
		default:
			return FP_NF_DROP;
		}
no_match:
		if (unlikely(res == NF6_IP_MATCH_EXCEPTION))
			return FP_NF_EXCEPTION;
		cur += 1;
	} while (res >= 0);

	if (res < 0)
		return FP_NF_DROP;

	return verdict;
#undef RULE
}

int fp_nf6_hook_iterate(struct mbuf *m, int hook, const int *table_list,
		        const fp_ifnet_t *indev, const fp_ifnet_t *outdev)
{
	int verdict = FP_NF_ACCEPT, i;
#ifdef CONFIG_MCORE_NF_TABLE_PER_VR
	uint16_t nf_vr = m2vrfid(m);
#else
	uint16_t nf_vr = 0;
#endif

	for (i = 0; table_list[i] >= 0; i++) {

		FPN_TRACK();
		if ( (fp_shared->nf6_conf.enabled_hook[nf_vr][hook] & (1ULL << table_list[i])) == 0)
			continue;

#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE
			if (likely(fp_shared->conf.w32.do_func & FP_CONF_DO_NF6_CACHE)) {
				verdict = fp_nf6_cache_input(m, hook, table_list[i], indev, outdev);

				/* the flow is in cache, skip normal processing */
				if (likely(verdict == FP_NF_ACCEPT))
					continue;
				if (likely(verdict != FP_NF_CONTINUE))
					return verdict;
			}
#endif
		verdict = fp_nf6_table(m, table_list[i], hook, indev, outdev);
		if (verdict != FP_NF_ACCEPT) {
			if (verdict != FP_NF_REPEAT)
				return verdict;
			else
				i--;
		}
	}

	return FP_NF_ACCEPT;
}
