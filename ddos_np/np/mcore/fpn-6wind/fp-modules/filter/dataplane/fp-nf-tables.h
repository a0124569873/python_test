/*
 * Copyright (c) 2007 6WIND
 */

#ifndef __FP_NF_TABLES_H__
#define __FP_NF_TABLES_H__

#include <fp-nfct.h>

/* SCTP type match related definitions */
#define sizeof_bits(type) (sizeof(type) * 8)
#define fp_nf_sctp_modulo(sctptype, type) (sctptype & (sizeof_bits(type)-1))

#define FP_NF_SCTP_ELEMCOUNT(x) (sizeof(x) / sizeof(x[0]))

#define FP_NF_SCTP_CHUNKMAP_CLEAR(chunkmap, sctptype)           \
	do {                                                    \
        chunkmap[sctptype / sizeof_bits(uint32_t)] &=           \
                ~(1 << fp_nf_sctp_modulo(sctptype, uint32_t));  \
} while (0)

#define FP_NF_SCTP_CHUNKMAP_IS_SET(chunkmap, sctptype)          \
({                                                              \
        (chunkmap[sctptype / sizeof_bits (uint32_t)] &          \
         (1 << fp_nf_sctp_modulo(sctptype, uint32_t))) ? 1: 0;  \
})

#define FP_NF_SCTP_CHUNKMAP_COPY(destmap, srcmap)               \
do {                                                            \
        int i;                                                  \
        for (i = 0; i < FP_NF_SCTP_ELEMCOUNT(chunkmap); i++)    \
                destmap[i] = srcmap[i];                         \
} while (0)

#define FP_NF_SCTP_CHUNKMAP_IS_CLEAR(chunkmap)                  \
({                                                              \
        unsigned int i;                                         \
        int flag = 1;                                           \
        for (i = 0; i < FP_NF_SCTP_ELEMCOUNT(chunkmap); i++) {  \
                if (chunkmap[i]) {                              \
                        flag = 0;                               \
                        break;                                  \
                }                                               \
        }                                                       \
        flag;                                                   \
})

#define TRACE_NF(level, fmt, args...) do {			\
		FP_LOG(level, NF, fmt "\n", ## args);		\
} while(0)

enum {
	IPRANGE_SRC     = 1 << 0,	/* match source IP address */
	IPRANGE_DST     = 1 << 1,	/* match destination IP address */
	IPRANGE_SRC_INV = 1 << 4,	/* negate the condition */
	IPRANGE_DST_INV = 1 << 5,	/* -"- */
};
struct iprange_match {
	union  {
		u_int32_t		all[4];
		u_int32_t		ip;
		u_int32_t		ip6[4];
		struct fp_in_addr	in;
		struct fp_in6_addr	in6;
	}src_min, src_max, dst_min, dst_max;
	uint8_t flags;
};

int fp_nf_hook_iterate(struct mbuf *m, int hook, const int *table_list, 
		       const fp_ifnet_t *indev, const fp_ifnet_t *outdev);
void fp_nf_target_dscp(struct mbuf *m, uint8_t dscp);
void fp_nf_init(void);
int fp_nf_port_match(uint16_t min, uint16_t max, uint16_t port, int invert);
int fp_nf_multiport_match(struct fp_nfrule_multiport * minfo, uint16_t src, uint16_t dst);
uint8_t fp_nfct_update(struct mbuf *m);
int fp_ddos_iptables_lookup(struct mbuf *m, int tablenum, int hook);

static inline void fp_nfct_reset(struct mbuf *m) {
	m_priv(m)->fp_nfct_established = FP_NF_CT_MBUF_UNKNOWN;
}

static const char *hook_names[FP_NF_IP_NUMHOOKS] = {
	"FP_NF_IP_PRE_ROUTING",
	"FP_NF_IP_LOCAL_IN",
	"FP_NF_IP_FORWARD",
	"FP_NF_IP_LOCAL_OUT",
	"FP_NF_IP_POST_ROUTING"
};

static inline int fp_nf_hook(struct mbuf *m, int hook, const fp_ifnet_t *indev, 
			     const fp_ifnet_t *outdev)
{
	int verdict;
	const int *table_list;
#ifdef CONFIG_MCORE_NF_TABLE_PER_VR
	uint16_t nf_vr = m2vrfid(m);
#else
	uint16_t nf_vr = 0;
#endif

	TRACE_NF(FP_LOG_DEBUG, "%s(m=%p, hook=%s, indev=%s, outdev=%s)", __func__,
		 m, hook_names[hook],
		 (indev == NULL) ? "(null)" : indev->if_name,
		 (outdev == NULL) ? "(null)" : outdev->if_name);
	
	/* this hook is not used, return */
	if (fp_shared->nf_conf.enabled_hook[nf_vr][hook] == 0) {
		TRACE_NF(FP_LOG_DEBUG, "%s: hook unused => continue", __func__);
		return FP_CONTINUE;
	}

	table_list = fp_shared->fp_nf_hook_prio[fp_shared->fp_nf_current_hook_prio][hook];
	verdict = fp_nf_hook_iterate(m, hook, table_list, indev, outdev);
	if (verdict == FP_NF_ACCEPT || verdict == FP_NF_STOP) {
		TRACE_NF(FP_LOG_DEBUG, "%s: verdict is ACCEPT or STOP => continue", __func__);
		return FP_CONTINUE;
	}
	else if (verdict == FP_NF_DROP) {
		TRACE_NF(FP_LOG_DEBUG, "%s: verdict is DROP => drop packet", __func__);
		FP_IP_STATS_INC(fp_shared->ip_stats, IpDroppedNetfilter);
		return FP_DROP;
	}
	else if (verdict == FP_NF_STOLEN) {
		TRACE_NF(FP_LOG_DEBUG, "%s: verdict is STOLEN", __func__);
		return FP_DONE;
	}

	TRACE_NF(FP_LOG_DEBUG, "%s: verdict is EXCEPTION => send packet as exception", __func__);
	/* If verdict is FP_NF_EXCEPTION, we fall is this default case */
	return fp_ip_prepare_exception(m, FPTUN_EXC_NF_FUNC);
}

static inline int fp_nfct_get(struct mbuf *m,
                              struct fp_ip *ip,
                              uint16_t sport,
                              uint16_t dport)
{
	if (m_priv(m)->fp_nfct_established == FP_NF_CT_MBUF_ESTABLISHED)
			return 0;

	/* performs a lookup in fp_shared->fp_nf_ct based on the 6-tuples */
	m_priv(m)->fp_nfct.v4 = fp_nfct_lookup(ip->ip_p, ip->ip_src.s_addr,
					       ip->ip_dst.s_addr, sport, dport,
					       m2vrfid(m), &m_priv(m)->fp_nfct_dir);

	/* conntrack found */
	if (m_priv(m)->fp_nfct.v4 != NULL) {
		m_priv(m)->fp_nfct_established = FP_NF_CT_MBUF_ESTABLISHED;
		return 0;
	}

	return -1;
}

#ifdef CONFIG_MCORE_M_TAG
#define NFM_TAG_NAME "nfm"
FPN_DECLARE_SHARED(int32_t, nfm_tag_type);
#endif

static inline void fp_nf_update_mark(struct mbuf *m,
				     uint32_t mark,
				     uint32_t mask)
{
#ifdef CONFIG_MCORE_M_TAG
	uint32_t new_mark = 0;

	/* Ignore return value, if tag does not exist,
	 * mark will stay unmodified.
	 */
	if (m_tag_get(m, nfm_tag_type, &new_mark) == 0)
		new_mark = ntohl(new_mark);

	new_mark = (new_mark & ~mask) ^ mark;
	m_tag_add(m, nfm_tag_type, htonl(new_mark));
#endif
}

#define NF_IP_MATCH_EXCEPTION    -2
#define NF_IP_MATCH_ERROR        -1
#define NF_IP_MATCH_NO            0
#define NF_IP_MATCH_YES           1

#define NF6_IP_MATCH_EXCEPTION    NF_IP_MATCH_EXCEPTION
#define NF6_IP_MATCH_ERROR        NF_IP_MATCH_ERROR
#define NF6_IP_MATCH_NO           NF_IP_MATCH_NO
#define NF6_IP_MATCH_YES          NF_IP_MATCH_YES

#ifdef CONFIG_MCORE_NETFILTER_IPV6
int nf6_physdev_match(struct mbuf *m, struct fp_nf6rule *r,
		      const fp_ifnet_t *indev, const fp_ifnet_t *outdev);
#endif

int nf4_physdev_match(struct mbuf *m, struct fp_nfrule *r,
		      const fp_ifnet_t *indev, const fp_ifnet_t *outdev);

#endif /* __FP_NF_TABLES_H__ */
