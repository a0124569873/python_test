/*
 * Copyright 2014 6WIND S.A.
 */

#include "fpn.h"
#include "fpn-cksum.h"
#include "fp-includes.h"

#include "shmem/fpn-shmem.h"
#include "fp-module.h"
#include "fp-dscp.h"
#include "fp-lookup.h"

#include "fp-log.h"
#include "fp-ether.h"
#include "fp-ip.h"
#ifdef CONFIG_MCORE_IPV6
#include "fp-ip6.h"
#endif
#include "fp-main-process.h"

#ifdef CONFIG_MCORE_NETFILTER
#include "fp-nf-tables.h"
#endif

#include "fp-gre-var.h"

FPN_DEFINE_SHARED(fp_gre_shared_mem_t *, fp_gre_shared);

#define TRACE_GRE(level, fmt, args...) do {				\
	FP_LOG(level, GRE, "%s: " fmt ".\n", __FUNCTION__, ## args);	\
} while (0)

/* The 2 following structs represent respectively the GRE header
 * and the checksum header.
 * The key header is not represented, it's an uint32_t.
 */
struct fp_gre_base_hdr {
#if FPN_BYTE_ORDER == FPN_LITTLE_ENDIAN
	uint16_t	rec:3;		/* Recursion Control               */
	uint16_t	sr:1;		/* Strict Source Route Present bit */
	uint16_t	s:1;		/* Sequence Number Present bit     */
	uint16_t	k:1;		/* Key Present bit                 */
	uint16_t	r:1;		/* Routing Present bit             */
	uint16_t	c:1;		/* Checksum Present bit            */
	uint16_t	ver:3;		/* Version Number                  */
	uint16_t	flags:5;	/* Flags                           */
#elif FPN_BYTE_ORDER == FPN_BIG_ENDIAN
	uint16_t	c:1;		/* Checksum Present bit            */
	uint16_t	r:1;		/* Routing Present bit             */
	uint16_t	k:1;		/* Key Present bit                 */
	uint16_t	s:1;		/* Sequence Number Present bit     */
	uint16_t	sr:1;		/* Strict Source Route Present bit */
	uint16_t	rec:3;		/* Recursion Control               */
	uint16_t	flags:5;	/* Flags                           */
	uint16_t	ver:3;		/* Version Number                  */
#endif
	uint16_t	proto_type;	/* Protocol (ethertype)            */
} __attribute__((packed));

struct fp_gre_csum_hdr {
	uint16_t	csum;		/* Checksum field */
	uint16_t	offset;		/* Offset field   */
} __attribute__((packed));

/****************************************************************************/
/*********************** GRE output packets functions ***********************/
/****************************************************************************/

#ifdef CONFIG_MCORE_IPV6
/* output packets: init IPv6 header encapsulating GRE header */
static inline int fp_gre_init_ip6_header(struct mbuf *m, uint16_t link_vrfid,
					 struct fp_in6_addr *dst,
					 struct fp_in6_addr *src,
					 uint8_t dscp, uint8_t hlim)
{
	struct fp_ip6_hdr *ip6;

	ip6 = (struct fp_ip6_hdr *)m_prepend(m, sizeof(struct fp_ip6_hdr));
	if (unlikely(ip6 == NULL))
		return -1;

	ip6->ip6_v = FP_IP6VERSION;
	ip6->ip6_hlim = hlim;
	fp_change_ipv6_dscp(ip6, dscp);
	ip6->ip6_plen = htons(m_len(m) - sizeof(struct fp_ip6_hdr));
	ip6->ip6_nxt = FP_IPPROTO_GRE;

	memcpy(&ip6->ip6_dst, dst, sizeof(struct fp_in6_addr));
	memcpy(&ip6->ip6_src, src, sizeof(struct fp_in6_addr));

	/* Update the vrfid of mbuf to link vrfid of the tunnel */
	set_mvrfid(m, link_vrfid);

	return 0;
}

static inline int fp_gre_build_ip6_header(struct mbuf *m, fp_ifgre_t *gre,
					  fp_ifnet_t *ifp, uint8_t dscp,
					  uint8_t ttl)
{
	fp_rt6_entry_t *rt = NULL;
	fp_nh6_entry_t *nh = NULL;
	struct fp_in6_addr ip6_src;

	rt = fp_rt6_lookup(gre->link_vrfid, &gre->remote.remote6);
	if (unlikely(!rt)) {
		TRACE_GRE(FP_LOG_INFO, "route not found");
		FP_IP_STATS_INC(fp_shared->ip6_stats, IpDroppedNoRouteLocal);
		if (ifp != NULL)
			FP_IF_STATS_INC(ifp->if_stats, ifs_oerrors);

		return FP_DROP;
	}

	/* select source address if GRE local is any */
	if (unlikely(FP_IN6_IS_ADDR_UNSPECIFIED(&gre->local.local6))) {
		if (fp_rt6_selectsrc(gre->link_vrfid,
				     &gre->remote.remote6,
				     &ip6_src, &rt)  != 0) {
			TRACE_GRE(FP_LOG_INFO, "route not found");
			if (ifp != NULL)
				FP_IF_STATS_INC(ifp->if_stats, ifs_oerrors);

			return FP_DROP;
		}
	} else {
		memcpy(&ip6_src, &gre->local.local6, sizeof(struct fp_in6_addr));
	}

	if (unlikely(fp_gre_init_ip6_header(m, gre->link_vrfid,
					    &gre->remote.remote6, &ip6_src,
					    dscp, ttl) != 0)) {
		TRACE_GRE(FP_LOG_INFO, "failed to prepend %u bytes",
			  (int)sizeof(struct fp_ip6_hdr));

		return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
	}

	nh = select_nh6(rt, &ip6_src);

	m_priv(m)->exc_type = FPTUN_IPV6_OUTPUT_EXCEPT;
	m_priv(m)->flags |= M_LOCAL_OUT | M_LOCAL_F;

	if (ifp != NULL) {
		FP_IF_STATS_INC(ifp->if_stats, ifs_opackets);
		FP_IF_STATS_ADD(ifp->if_stats, ifs_obytes, m_len(m));
	}

	return fp_ip6_output(m, rt, nh);
}
#endif

/* output packets: init IPv4 header encapsulating GRE header */
static inline int fp_gre_init_ip4_header(struct mbuf *m, uint16_t link_vrfid,
					 struct fp_in_addr *dst,
					 struct fp_in_addr *src,
					 uint8_t dscp, uint8_t ttl)
{
	struct fp_ip *ip;

	ip = (struct fp_ip *)m_prepend(m, sizeof(struct fp_ip));
	if (unlikely(ip == NULL))
		return -1;

	ip->ip_v = FP_IPVERSION;
	ip->ip_hl = 5;
	ip->ip_off = htons(FP_IP_DF);
	fp_change_ipv4_dscp(ip, dscp);
	ip->ip_ttl = ttl;
	ip->ip_len = htons(m_len(m));
	ip->ip_p = FP_IPPROTO_GRE;

	memcpy(&ip->ip_dst, dst, sizeof(struct fp_in_addr));
	memcpy(&ip->ip_src, src, sizeof(struct fp_in_addr));

	/* Update the vrfid of mbuf to link vrfid of the tunnel */
	set_mvrfid(m, link_vrfid);

	ip->ip_sum = fpn_ip_hdr_cksum(ip, sizeof(struct fp_ip));

	return 0;
}

static inline int fp_gre_build_ip4_header(struct mbuf *m, fp_ifgre_t *gre,
					  fp_ifnet_t *ifp, uint8_t dscp,
					  uint8_t ttl)
{
	fp_rt4_entry_t *rt = NULL;
	fp_nh4_entry_t *nh = NULL;
	struct fp_in_addr ip_src = gre->local.local4;

	/* lookup in the FW table */
	rt = fp_rt4_lookup(gre->link_vrfid, gre->remote.remote4.s_addr);
	if (unlikely(!rt)) {
		TRACE_GRE(FP_LOG_INFO, "route not found");
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNoRouteLocal);
		if (ifp != NULL)
			FP_IF_STATS_INC(ifp->if_stats, ifs_oerrors);

		return FP_DROP;
	}

	/* select source address if GRE local is any */
	if (unlikely(gre->local.local4.s_addr == 0)) {
		if (fp_rt4_selectsrc(gre->link_vrfid, gre->remote.remote4.s_addr,
				     &ip_src.s_addr, &rt) != 0) {
			TRACE_GRE(FP_LOG_INFO, "route not found");
			if (ifp != NULL)
				FP_IF_STATS_INC(ifp->if_stats, ifs_oerrors);

			return FP_DROP;
		}
	}

	if (unlikely(fp_gre_init_ip4_header(m, gre->link_vrfid,
					    &gre->remote.remote4, &ip_src,
					    dscp, ttl) != 0)) {
		TRACE_GRE(FP_LOG_INFO, "failed to prepend %u bytes",
			  (int)sizeof(struct fp_ip));

		return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
	}

	nh = select_nh4(rt, (uint32_t *)&ip_src.s_addr);

	m_priv(m)->exc_type = FPTUN_IPV4_OUTPUT_EXCEPT;
	m_priv(m)->flags |= M_LOCAL_OUT | M_LOCAL_F;

	if (ifp != NULL) {
		FP_IF_STATS_INC(ifp->if_stats, ifs_opackets);
		FP_IF_STATS_ADD(ifp->if_stats, ifs_obytes, m_len(m));
	}

	if (!(fp_shared->conf.w32.do_func & (FP_CONF_NO_FAST_FORWARD)))
		return fp_fast_ip_output(m, rt, nh);
	else
		return fp_ip_output(m, rt, nh);
}

/* output packets: init GRE header */
static inline int fp_gre_init_header(struct mbuf *m, fp_ifgre_t *gre,
				     uint16_t proto_type)
{
	struct fp_gre_base_hdr *hdr_base;
	struct fp_gre_csum_hdr *hdr_csum;
	uint32_t *hdr_key;
	uint32_t hdr_size = 4;

	/* packet will contain a cksum */
	if (gre->oflags & FP_GRE_FLAG_CSUM)
		hdr_size += 4;

	/* packet will contain a key */
	if (gre->oflags & FP_GRE_FLAG_KEY)
		hdr_size += 4;

	/* Prepend GRE header to outgoing frame */
	if (unlikely(m_prepend(m, hdr_size) == NULL))
		return -1;

	hdr_base = mtod(m, struct fp_gre_base_hdr *);
	*(uint32_t *)(hdr_base) = 0;

	hdr_base->c = (gre->oflags & FP_GRE_FLAG_CSUM) ? 1 : 0;
	hdr_base->k = (gre->oflags & FP_GRE_FLAG_KEY) ? 1 : 0;
	hdr_base->proto_type = htons(proto_type);

	/* GRE key */
	if (gre->oflags & FP_GRE_FLAG_KEY) {
		if (gre->oflags & FP_GRE_FLAG_CSUM)
			hdr_key = (uint32_t *)(hdr_base + 2);
		else
			hdr_key = (uint32_t *)(hdr_base + 1);

		*hdr_key = gre->okey;
	}

	/* GRE check-sum */
	if (gre->oflags & FP_GRE_FLAG_CSUM) {
		hdr_csum = (struct fp_gre_csum_hdr *)(hdr_base + 1);

		hdr_csum->csum = 0;
		hdr_csum->offset = 0;
		hdr_csum->csum = fpn_cksum(m, 0);
	}

	return 0;
}

/* Encapsulated packet */
static int fp_gre_output(struct mbuf *m, fp_ifnet_t *ifp, int af, void *data)
{
	uint16_t proto_type = (af == AF_INET) ? FP_ETHERTYPE_IP : FP_ETHERTYPE_IPV6;
	uint32_t idx = (uint32_t)(uintptr_t)data;
	fp_ifgre_t *gre;
	struct fp_ip *ip;
	uint8_t dscp;
	uint8_t ttl;
#ifdef CONFIG_MCORE_IPV6
	struct fp_ip6_hdr *ip6;
#endif

	TRACE_GRE(FP_LOG_DEBUG, "called");

	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		TRACE_GRE(FP_LOG_INFO, "%s GRE iface is inoperative", ifp->if_name);
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);

		return FP_DROP;
	}

	gre = &fp_gre_shared->if_gre[idx];

	if (unlikely(gre->ifuid == 0)) {
		TRACE_GRE(FP_LOG_ERR, "GRE iface not found");
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	dscp = gre->tos & FP_DSCP_MASK;
	ttl = gre->ttl;

	if (likely(af == AF_INET)) {
		ip = mtod(m, struct fp_ip *);

		if (gre->inh_tos)
			dscp = ip->ip_tos & FP_DSCP_MASK;

		if (likely((m_priv(m)->flags & M_LOCAL_OUT) == 0)) {
			FP_IP_STATS_INC(fp_shared->ip_stats, IpForwDatagrams);

			if (unlikely(ip->ip_ttl <= FP_IPTTLDEC)) {
				TRACE_GRE(FP_LOG_INFO, "TTL <= FP_IPTTLDEC");
				return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
			}

			/* Update TTL (from bsd netinet/ip_flow.c) */
			ip->ip_ttl -= FP_IPTTLDEC;

			/* Update checksum */
			if (unlikely(ip->ip_sum >= htons(0xffff - (FP_IPTTLDEC << 8))))
				ip->ip_sum += htons(FP_IPTTLDEC << 8) + 1;
			else
				ip->ip_sum += htons(FP_IPTTLDEC << 8);

			if (ttl == 0 && gre->family == AF_INET)
				ttl = ip->ip_ttl;
		}
#ifdef CONFIG_MCORE_IPV6
	} else if (likely(af == AF_INET6)) {
		ip6 = mtod(m, struct fp_ip6_hdr *);

		dscp = (ntohs(*(uint16_t *)ip6) >> 4) & FP_DSCP_MASK;

		if (likely((m_priv(m)->flags & M_LOCAL_OUT) == 0)) {
			FP_IP_STATS_INC(fp_shared->ip6_stats, IpForwDatagrams);

			if (unlikely(ip6->ip6_hlim <= FP_IPTTLDEC)) {
				TRACE_GRE(FP_LOG_INFO, "TTL <= FP_IPTTLDEC");

				m_priv(m)->exc_type = FPTUN_IPV6_OUTPUT_EXCEPT;
				return fp_ip_prepare_exception(m, FPTUN_EXC_ICMP_NEEDED);
			}

			ip6->ip6_hlim -= FP_IPTTLDEC;

			if (ttl == 0 && gre->family == AF_INET)
				ttl = ip6->ip6_hlim;
		}
#endif
	} else {
		TRACE_GRE(FP_LOG_INFO,
			  "IPv6 is not supported (CONFIG_MCORE_IPV6 is not set).");
		return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	/* Build GRE header */
	if (unlikely(fp_gre_init_header(m, gre, proto_type))) {
		TRACE_GRE(FP_LOG_ERR, "GRE header init error");
		return FP_DROP;
	}

	/* Build encapsulated IP header */
	if (gre->family == AF_INET)
		return fp_gre_build_ip4_header(m, gre, ifp, dscp, ttl);
#ifdef CONFIG_MCORE_IPV6
	else
		return fp_gre_build_ip6_header(m, gre, ifp, dscp, ttl);
#endif

	TRACE_GRE(FP_LOG_ERR, "IPv6 is not supported (CONFIG_MCORE_IPV6 is not set)");
	return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
}

static int __fp_gretap_output(struct mbuf *m, fp_ifnet_t *ifp, fp_ifgre_t *gre)
{
	struct fp_ether_header *eth_hdr;
	struct fp_ip *ip;
	uint8_t dscp;
	uint8_t ttl;
#ifdef CONFIG_MCORE_IPV6
	struct fp_ip6_hdr *ip6;
#endif

	dscp = gre->tos & FP_DSCP_MASK;
	ttl = gre->ttl;

	eth_hdr = mtod(m, struct fp_ether_header *);
	if (eth_hdr->ether_type == htons(FP_ETHERTYPE_IP)) {
		ip = m_off(m, sizeof(struct fp_ether_header), struct fp_ip *);

		if (gre->inh_tos)
			dscp = ip->ip_tos & FP_DSCP_MASK;

		if (likely((m_priv(m)->flags & M_LOCAL_OUT) == 0)) {
			if (ttl == 0 && gre->family == AF_INET)
				ttl = ip->ip_ttl;
		}
	} else if (eth_hdr->ether_type == htons(FP_ETHERTYPE_IPV6)) {
#ifdef CONFIG_MCORE_IPV6
		ip6 = m_off(m, sizeof(struct fp_ether_header), struct fp_ip6_hdr *);

		dscp = (ntohs(*(uint16_t *)ip6) >> 4) & FP_DSCP_MASK;

		if (likely((m_priv(m)->flags & M_LOCAL_OUT) == 0)) {
			if (ttl == 0 && gre->family == AF_INET)
				ttl = ip6->ip6_hlim;
		}
#else
		TRACE_GRE(FP_LOG_INFO,
			  "IPv6 is not supported (CONFIG_MCORE_IPV6 is not set).");
		return fp_prepare_exception(m, FPTUN_EXC_SP_FUNC);
#endif
	} else {
		TRACE_GRE(FP_LOG_INFO,
			  "Ethernet type (%"PRIu16") not supported",
			  htons(eth_hdr->ether_type));
		return fp_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	/* Build GRE header */
	if (unlikely(fp_gre_init_header(m, gre, FP_ETHERTYPE_TEB))) {
		TRACE_GRE(FP_LOG_ERR, "GRE header init error");
		return FP_DROP;
	}

	/* Build encapsulated IP header */
	if (gre->family == AF_INET)
		return fp_gre_build_ip4_header(m, gre, ifp, dscp, ttl);
#ifdef CONFIG_MCORE_IPV6
	else
		return fp_gre_build_ip6_header(m, gre, ifp, dscp, ttl);
#endif

	TRACE_GRE(FP_LOG_ERR, "IPv6 is not supported (CONFIG_MCORE_IPV6 is not set)");
	return fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC);
}

static int fp_gretap_output(struct mbuf *m, fp_ifnet_t *ifp, void *data)
{
	uint32_t idx = (uint32_t)(uintptr_t)data;
	fp_ifgre_t *gre;

	TRACE_GRE(FP_LOG_DEBUG, "called");

	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		TRACE_GRE(FP_LOG_INFO, "%s GRETAP iface is inoperative", 
			  ifp->if_name);
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);

		return FP_DROP;
	}

	gre = &fp_gre_shared->if_gre[idx];

	if (unlikely(gre->ifuid == 0)) {
		TRACE_GRE(FP_LOG_NOTICE, "GRETAP iface not found");
		return fp_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	return __fp_gretap_output(m, ifp, gre);
}

int fp_gretap_fpvs_output(struct mbuf *m, uint32_t ip_src, uint32_t ip_dst,
			  uint8_t ttl, uint8_t tos, uint32_t key, uint16_t flags)
{
	fp_ifgre_t gre;

	TRACE_GRE(FP_LOG_DEBUG, "called");

	gre.tos = tos;
	gre.ttl = ttl;
	gre.iflags = flags;
	gre.oflags = flags;
	gre.ikey = key;
	gre.okey = key;
	gre.family = AF_INET;

	gre.link_vrfid = m2vrfid(m);

	gre.local.local4.s_addr = ip_src;
	gre.remote.remote4.s_addr = ip_dst;

	return __fp_gretap_output(m, NULL, &gre);
}

/****************************************************************************/
/*********************** GRE input packets functions ************************/
/****************************************************************************/

static inline int fp_gre_check_ikey(fp_ifgre_t *gre, uint32_t *ikey)
{
	/* if ikey == NULL the key flag is not set else the key flag is set */
	if ((ikey && !(gre->iflags & FP_GRE_FLAG_KEY)) ||
	    (!ikey && (gre->iflags & FP_GRE_FLAG_KEY)))
		return -1;

	if (ikey && gre->ikey != *ikey)
		return -1;

	return 0;
}

static inline fp_ifgre_t *fp_gre_ip4_lookup(uint32_t local, uint32_t remote,
					    uint32_t *ikey, uint16_t vrfid)
{
	uint32_t local_h = __FP_GRE_HASH_ADDR4(local);
	uint32_t remote_h = __FP_GRE_HASH_ADDR4(remote);
	uint32_t key_h = __FP_GRE_HASH_KEY(ikey ? *ikey : 0);
	uint32_t hash;
	uint32_t idx;

	/* Search with local and remote addresses and key */
	hash = FP_GRE_HASH_IPV4(local_h, remote_h, key_h);
	fp_hlist_for_each(idx, &fp_gre_shared->gre_ipv4_hlist[hash],
			  fp_gre_shared->if_gre, hlist) {
		if (fp_gre_shared->if_gre[idx].local.local4.s_addr == local &&
		    fp_gre_shared->if_gre[idx].remote.remote4.s_addr == remote &&
		    fp_gre_shared->if_gre[idx].link_vrfid == vrfid &&
		    fp_gre_check_ikey(&fp_gre_shared->if_gre[idx], ikey) == 0)
			return &fp_gre_shared->if_gre[idx];
	}

	/* Search with remote address and key */
	hash = FP_GRE_HASH_IPV4_1AK(remote_h, key_h);
	fp_hlist_for_each(idx, &fp_gre_shared->gre_ipv4_hlist[hash],
			  fp_gre_shared->if_gre, hlist) {
		if (fp_gre_shared->if_gre[idx].local.local4.s_addr == 0 &&
		    fp_gre_shared->if_gre[idx].remote.remote4.s_addr == remote &&
		    fp_gre_shared->if_gre[idx].link_vrfid == vrfid &&
		    fp_gre_check_ikey(&fp_gre_shared->if_gre[idx], ikey) == 0)
			return &fp_gre_shared->if_gre[idx];
	}

	/* Search with local address and key */
	hash = FP_GRE_HASH_IPV4_1AK(local_h, key_h);
	fp_hlist_for_each(idx, &fp_gre_shared->gre_ipv4_hlist[hash],
			  fp_gre_shared->if_gre, hlist) {
		if (fp_gre_shared->if_gre[idx].local.local4.s_addr == local &&
		    fp_gre_shared->if_gre[idx].remote.remote4.s_addr == 0 &&
		    fp_gre_shared->if_gre[idx].link_vrfid == vrfid &&
		    fp_gre_check_ikey(&fp_gre_shared->if_gre[idx], ikey) == 0)
			return &fp_gre_shared->if_gre[idx];
	}

	/* Search with key only */
	hash = FP_GRE_HASH_IPV4_KEY(key_h);
	fp_hlist_for_each(idx, &fp_gre_shared->gre_ipv4_hlist[hash],
			  fp_gre_shared->if_gre, hlist) {
		if (fp_gre_shared->if_gre[idx].local.local4.s_addr == 0 &&
		    fp_gre_shared->if_gre[idx].remote.remote4.s_addr == 0 &&
		    fp_gre_shared->if_gre[idx].link_vrfid == vrfid &&
		    fp_gre_check_ikey(&fp_gre_shared->if_gre[idx], ikey) == 0)
			return &fp_gre_shared->if_gre[idx];
	}

	return NULL;
}

#ifdef CONFIG_MCORE_IPV6
static inline fp_ifgre_t *fp_gre_ip6_lookup(struct fp_in6_addr *local,
					    struct fp_in6_addr *remote,
					    uint32_t *ikey, uint16_t vrfid)
{
	uint32_t local_h = __FP_GRE_HASH_ADDR6(*local);
	uint32_t remote_h = __FP_GRE_HASH_ADDR6(*remote);
	uint32_t key_h = __FP_GRE_HASH_KEY(ikey ? *ikey : 0);
	uint32_t hash;
	uint32_t idx;

	/* Search with local and remote addresses and key */
	hash = FP_GRE_HASH_IPV6(local_h, remote_h, key_h);
	fp_hlist_for_each(idx, &fp_gre_shared->gre_ipv6_hlist[hash],
			  fp_gre_shared->if_gre, hlist) {
		if (!memcmp(&fp_gre_shared->if_gre[idx].local.local6, local,
			    sizeof(*local)) &&
		    !memcmp(&fp_gre_shared->if_gre[idx].remote.remote6, remote,
			    sizeof(*remote)) &&
		    fp_gre_shared->if_gre[idx].link_vrfid == vrfid &&
		    fp_gre_check_ikey(&fp_gre_shared->if_gre[idx], ikey) == 0)
			return &fp_gre_shared->if_gre[idx];
	}

	/* Search with remote address and key */
	hash = FP_GRE_HASH_IPV6_1AK(remote_h, key_h);
	fp_hlist_for_each(idx, &fp_gre_shared->gre_ipv6_hlist[hash],
			  fp_gre_shared->if_gre, hlist) {
		if (FP_IN6_IS_ADDR_UNSPECIFIED(&fp_gre_shared->if_gre[idx].local.local6) &&
		    !memcmp(&fp_gre_shared->if_gre[idx].remote.remote6, remote,
			    sizeof(*remote)) &&
		    fp_gre_shared->if_gre[idx].link_vrfid == vrfid &&
		    fp_gre_check_ikey(&fp_gre_shared->if_gre[idx], ikey) == 0)
			return &fp_gre_shared->if_gre[idx];
	}

	/* Search with local address and key */
	hash = FP_GRE_HASH_IPV6_1AK(local_h, key_h);
	fp_hlist_for_each(idx, &fp_gre_shared->gre_ipv6_hlist[hash],
			  fp_gre_shared->if_gre, hlist) {
		if (!memcmp(&fp_gre_shared->if_gre[idx].local.local6, local,
			    sizeof(*local)) &&
		    FP_IN6_IS_ADDR_UNSPECIFIED(&fp_gre_shared->if_gre[idx].remote.remote6) &&
		    fp_gre_shared->if_gre[idx].link_vrfid == vrfid &&
		    fp_gre_check_ikey(&fp_gre_shared->if_gre[idx], ikey) == 0)
			return &fp_gre_shared->if_gre[idx];
	}

	/* Search with key only */
	hash = FP_GRE_HASH_IPV6_KEY(key_h);
	fp_hlist_for_each(idx, &fp_gre_shared->gre_ipv6_hlist[hash],
			  fp_gre_shared->if_gre, hlist) {
		if (FP_IN6_IS_ADDR_UNSPECIFIED(&fp_gre_shared->if_gre[idx].local.local6) &&
		    FP_IN6_IS_ADDR_UNSPECIFIED(&fp_gre_shared->if_gre[idx].remote.remote6) &&
		    fp_gre_shared->if_gre[idx].link_vrfid == vrfid &&
		    fp_gre_check_ikey(&fp_gre_shared->if_gre[idx], ikey) == 0)
			return &fp_gre_shared->if_gre[idx];
	}

	return NULL;
}
#endif

/* Remove IP and GRE headers and process encapsulated packet */
static inline int fp_gre_stripheader(struct mbuf *m, fp_ifnet_t *ifp,
				     uint16_t size, uint16_t proto,
				     uint8_t expected_mode, uint8_t dscp)
{
#ifdef CONFIG_MCORE_IPV6
	struct fp_ip6_hdr *ip6;
#endif
	struct fp_ip *ip;
	struct fp_ether_header *eth_hdr;
	int ret;

#ifdef CONFIG_MCORE_NETFILTER
	fp_nfct_reset(m);
#endif
	if (expected_mode == FP_GRE_MODE_IP) {
		if (likely(proto == FP_ETHERTYPE_IP)) {
			/* remove IP and GRE headers */
			if (likely(m_adj(m, size) == NULL)) {
				TRACE_GRE(FP_LOG_INFO, "IP and/or GRE headers can not be removed");
				FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);

				return FP_DROP;
			}

			ip = mtod(m, struct fp_ip *);

			m_priv(m)->exc_type = FPTUN_IFACE_INPUT_EXCEPT;
			m_priv(m)->exc_proto = htons(FP_ETHERTYPE_IP);

			if (unlikely(dscp))
				fp_change_ipv4_dscp(ip, dscp);

			fp_change_ifnet_packet(m, ifp, 1, 1);
			fp_reset_hw_flags(m); /* No known HW able to do HW Checksum here */
			return FPN_HOOK_CALL(fp_ip_input)(m);
#ifdef CONFIG_MCORE_IPV6
		} else if (likely(proto == FP_ETHERTYPE_IPV6)) {
			/* remove IP and GRE headers */
			if (likely(m_adj(m, size) == NULL)) {
				TRACE_GRE(FP_LOG_INFO, "IP and/or GRE headers can not be removed");
				FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);

				return FP_DROP;
			}

			m_priv(m)->exc_type = FPTUN_IFACE_INPUT_EXCEPT;
			m_priv(m)->exc_proto = htons(FP_ETHERTYPE_IPV6);

			ip6 = mtod(m, struct fp_ip6_hdr *);

			if (unlikely(dscp))
				fp_change_ipv6_dscp(ip6, dscp);

			fp_change_ifnet_packet(m, ifp, 1, 1);
			fp_reset_hw_flags(m); /* No known HW able to do HW Checksum here */
			return FPN_HOOK_CALL(fp_ip6_input)(m);
#endif
		}
	} else if (likely((proto == FP_ETHERTYPE_TEB) &&
			(expected_mode == FP_GRE_MODE_ETHER))) {
		/* remove IP and GRE headers */
		if (likely(m_adj(m, size) == NULL)) {
			TRACE_GRE(FP_LOG_INFO, "IP and/or GRE headers can not be removed");
			FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);
			return FP_DROP;
		}

		if (unlikely(dscp)) {
			eth_hdr = mtod(m, struct fp_ether_header *);
			if (eth_hdr->ether_type == htons(FP_ETHERTYPE_IP)) {
				ip = (struct fp_ip *)(eth_hdr + 1);
				fp_change_ipv4_dscp(ip, dscp);
			}
#ifdef CONFIG_MCORE_IPV6
			if (eth_hdr->ether_type == htons(FP_ETHERTYPE_IPV6)) {
				ip6 = (struct fp_ip6_hdr *)(eth_hdr + 1);
				fp_change_ipv6_dscp(ip6, dscp);
			}
#endif
		}

		/* Everything OK. Do the basic treatment */
		m_priv(m)->exc_type = FPTUN_ETH_INPUT_EXCEPT;
		m_priv(m)->exc_class = 0;
		m_priv(m)->exc_proto = 0;
		fp_change_ifnet_packet(m, ifp, 1, 0);
		fp_reset_hw_flags(m); /* No known HW able to do HW Checksum here */
		ret = FPN_HOOK_CALL(fp_ether_input)(m, ifp);

		return ret;
	}

	TRACE_GRE(FP_LOG_DEBUG, "%" PRIu16 " is not a supported protocol", proto);

	return fp_prepare_exception(m, FPTUN_EXC_SP_FUNC);
}

static inline int fp_gre_check_csum(struct mbuf *m, fp_ifgre_t *gre,
				    struct fp_gre_csum_hdr *hdr_csum,
				    uint32_t offset_ip)
{
	/* For OVS gre is NULL and need of checksum presence is done later by
	 * the fp-vswitch daemon
	 */
	if (gre &&
	    ((hdr_csum && !(gre->iflags & FP_GRE_FLAG_CSUM)) ||
	     (!hdr_csum && (gre->iflags & FP_GRE_FLAG_CSUM)))) {
		TRACE_GRE(FP_LOG_INFO,
			  "packet have a configuration different than GRE iface");
		return -1;
	}

	/* Check the GRE checksum, starting from GRE header, to end of packet.
	 * Checksum computation must return 0 with valid packets.
	 */
	if (hdr_csum && fpn_cksum(m, offset_ip) != 0) {
		TRACE_GRE(FP_LOG_ERR, "packet checksum invalid");
		return -1;
	}

	return 0;
}

static inline int fp_gre_parse_input_header(struct mbuf *m,
					    struct fp_gre_base_hdr *hdr_base,
					    struct fp_gre_csum_hdr **hdr_csum,
					    uint32_t **hdr_key, uint32_t *hdr_size)
{
	if (unlikely(hdr_base->r + hdr_base->ver)) {
		TRACE_GRE(FP_LOG_ERR, "route flag and/or version field are set");
		return FP_CONTINUE;
	}

	/* GRE checksum */
	if (hdr_base->c) {
		*hdr_csum = (struct fp_gre_csum_hdr *)(hdr_base + 1);
		*hdr_size += sizeof(struct fp_gre_csum_hdr);
	}

	/* GRE key */
	if (hdr_base->k) {
		if (hdr_base->c)
			*hdr_key = (uint32_t *)(hdr_base + 2);
		else
			*hdr_key = (uint32_t *)(hdr_base + 1);

		*hdr_size += sizeof(uint32_t);
	}

	/* adjust size depending on options */
	if (!m_pullup(m, *hdr_size)) {
		TRACE_GRE(FP_LOG_ERR, "packet too short, no GRE header options found");
		return FP_DONE;
	}

	return FP_KEEP;
}

static int fp_gre_ip4_input(struct mbuf *m)
{
	uint32_t hdr_size = sizeof(struct fp_ip) + sizeof(struct fp_gre_base_hdr);
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	uint32_t ovsport = fp_gre_shared->ovsport;
	struct fp_gre_base_hdr *hdr_base = NULL;
	struct fp_gre_csum_hdr *hdr_csum = NULL;
	uint32_t *hdr_key = NULL;
	fp_ifgre_t *gre;
	fp_ifnet_t *ifp = NULL;
	int res;

	TRACE_GRE(FP_LOG_DEBUG, "called");

	if (!m_pullup(m, hdr_size)) {
		TRACE_GRE(FP_LOG_ERR, "packet too short, no GRE header found");
		return FP_DONE;
	}

	hdr_base = (struct fp_gre_base_hdr *)(ip + 1);

	res = fp_gre_parse_input_header(m, hdr_base, &hdr_csum, &hdr_key, &hdr_size);
	if (res != FP_KEEP)
		return res;

	gre = fp_gre_ip4_lookup((uint32_t)ip->ip_dst.s_addr,
				(uint32_t)ip->ip_src.s_addr,
				hdr_key, m2vrfid(m));
	if ((gre == NULL) &&
	    ((ovsport == 0) ||
	     (ntohs(hdr_base->proto_type) != FP_ETHERTYPE_TEB)))
		return FP_CONTINUE;

	if (likely(gre != NULL)) {
		ifp = fp_ifuid2ifnet(gre->ifuid);
		if (unlikely(!fp_ifnet_is_operative(ifp))) {
			TRACE_GRE(FP_LOG_INFO, "%s GRE iface is inoperative",
				  ifp->if_name);
			FP_GLOBAL_STATS_INC(fp_shared->global_stats,
					    fp_droppedOperative);
			return FP_DROP;
		}
	}

	res = fp_gre_check_csum(m, gre, hdr_csum, sizeof(struct fp_ip));
	if (res) {
		if (ifp != NULL)
			FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);
		return FP_DROP;
	}

	if (unlikely(gre == NULL)) {
		/* This packet is maybe a OVS one.
		 * Send it to to the fp-vswitch daemon.
		 */
		uint16_t flags = 0;
		uint32_t key = 0;

		if (hdr_base->c)
			flags |= FP_GRE_FLAG_CSUM;
		if (hdr_base->k) {
			flags |= FP_GRE_FLAG_KEY;
			key = *hdr_key;
		}

		return fp_gre_shared->gretap_fpvs_input(m, hdr_size, ovsport,
						        flags, key);
	}

	return fp_gre_stripheader(m, ifp, hdr_size, ntohs(hdr_base->proto_type),
				  gre->mode, ip->ip_tos & FP_DSCP_MASK);
}

#ifdef CONFIG_MCORE_IPV6
static int fp_gre_ip6_input(struct mbuf *m)
{
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);
	uint32_t hdr_size = sizeof(struct fp_ip6_hdr) +
			    sizeof(struct fp_gre_base_hdr);
	struct fp_gre_base_hdr *hdr_base = NULL;
	struct fp_gre_csum_hdr *hdr_csum = NULL;
	uint32_t *hdr_key = NULL;
	fp_ifgre_t *gre;
	fp_ifnet_t *ifp;
	int res;

	TRACE_GRE(FP_LOG_DEBUG, "called");

	if (!m_pullup(m, hdr_size)) {
		TRACE_GRE(FP_LOG_ERR, "packet too short, no GRE header found");
		return FP_DONE;
	}

	hdr_base = (struct fp_gre_base_hdr *)(ip6 + 1);

	res = fp_gre_parse_input_header(m, hdr_base, &hdr_csum, &hdr_key, &hdr_size);
	if (res != FP_KEEP)
		return res;

	gre = fp_gre_ip6_lookup(&ip6->ip6_dst, &ip6->ip6_src,
				hdr_key, m2vrfid(m));
	if (gre == NULL)
		return FP_CONTINUE;

	ifp = fp_ifuid2ifnet(gre->ifuid);
	if (unlikely(!fp_ifnet_is_operative(ifp))) {
		TRACE_GRE(FP_LOG_INFO, "%s GRE iface is inoperative", ifp->if_name);
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, fp_droppedOperative);
		return FP_DROP;
	}

	res = fp_gre_check_csum(m, gre, hdr_csum, sizeof(struct fp_ip6_hdr));
	if (res) {
		FP_IF_STATS_INC(ifp->if_stats, ifs_ierrors);
		return FP_DROP;
	}

	return fp_gre_stripheader(m, ifp, hdr_size, ntohs(hdr_base->proto_type),
				  gre->mode,
				  (ntohs(*(uint16_t *)ip6) >> 4) & FP_DSCP_MASK);
}
#endif

void fp_gretap_fpvs_input_register(fp_gretap_fpvs_input_t input_p)
{
	fp_gre_shared->gretap_fpvs_input = input_p;
}

/****************************************************************************/
/************************ GRE module init functions *************************/
/****************************************************************************/

static void *fp_gre_shared_alloc(void)
{
	void *addr;

	/* Create fp-gre-shared memory */
	fpn_shmem_add(FP_GRE_SHARED, sizeof(fp_gre_shared_mem_t));
	addr = fpn_shmem_mmap(FP_GRE_SHARED, NULL, sizeof(fp_gre_shared_mem_t));

	if (addr == NULL) {
		TRACE_GRE(FP_LOG_ERR, "Cannot map fp_gre_shared size%"PRIu64" (%"PRIu64"M)",
			  (uint64_t)sizeof(fp_gre_shared_mem_t),
			  (uint64_t)sizeof(fp_gre_shared_mem_t) >> 20);

		return NULL;
	}

	TRACE_GRE(FP_LOG_INFO, "Using fp_gre_shared size%"PRIu64" (%"PRIu64"M)",
		  (uint64_t)sizeof(fp_gre_shared_mem_t),
		  (uint64_t)sizeof(fp_gre_shared_mem_t) >> 20);

	return addr;
}

static FPN_DEFINE_SHARED(fp_ip_proto_handler_t, fp_gre_ip4_hdlr) = {
	.func = fp_gre_ip4_input
};

#ifdef CONFIG_MCORE_IPV6
static FPN_DEFINE_SHARED(fp_ip6_proto_handler_t, fp_gre_ip6_hdlr) = {
	.func = fp_gre_ip6_input
};
#endif

static void fp_gre_init(void);

static struct fp_mod gre_mod = {
	.name = "gre",
	.init = fp_gre_init,
	.if_ops = {
		[TX_DEV_OPS] = fp_gretap_output,
		[IP_OUTPUT_OPS] = fp_gre_output,
	},
};

static void fp_gre_init(void)
{
	FP_LOG_REGISTER(GRE);

	fp_gre_shared = (fp_gre_shared_mem_t *)fp_gre_shared_alloc();
	if (fp_gre_shared == NULL) {
		TRACE_GRE(FP_LOG_ERR, "Could not get GRE shared memory");
		return;
	}

	fp_gre_init_shmem(1);

	fp_gre_shared->mod_uid = gre_mod.uid;

	if (fp_ip_proto_handler_register(FP_IPPROTO_GRE, &fp_gre_ip4_hdlr) != 0) {
		TRACE_GRE(FP_LOG_ERR, "could not register IPv4 handler");
		return;
	}

#ifdef CONFIG_MCORE_IPV6
	if (fp_ip6_proto_handler_register(FP_IPPROTO_GRE, &fp_gre_ip6_hdlr) != 0) {
		TRACE_GRE(FP_LOG_ERR, "could not register IPv6 handler");
		return;
	}
#endif
}

FP_MOD_REGISTER(gre_mod)
