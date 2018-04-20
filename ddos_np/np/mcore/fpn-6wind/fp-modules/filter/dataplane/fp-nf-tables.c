/*
 * Copyright (c) 2007 6WIND
 */

#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"

#include "fp-dscp.h"
#include "netinet/fp-udp.h"
#include "netinet/fp-tcp.h"
#include "netinet/fp-icmp.h"
#include "netinet/fp-sctp.h"
#include "netinet/fp-gre.h"
#include "fp-nfct.h"
#include "fp-nf-tables.h"
#include "fp-main-process.h"
#include "fp-ip.h"
#include "fpn-cksum.h"

#include "fp-nf-cache.h"
#ifdef CONFIG_MCORE_NETFILTER_NAT
#include "fp-nf-nat.h"
#endif

#ifdef CONFIG_MCORE_M_TAG
FPN_DEFINE_SHARED(int32_t, nfm_tag_type);
#endif
static FPN_DEFINE_SHARED(fpn_spinlock_t, nf_ratelimit_lock);

void fp_nf_init(void)
{
	int vr, t, r, h;
	int hook_prio[FP_NF_IP_NUMHOOKS][FP_NF_TABLE_NUM + 1] = {
		{ FP_NF_TABLE_MANGLE, FP_NF_TABLE_NAT, -1 },       /* FP_NF_IP_PRE_ROUTING */
		{ FP_NF_TABLE_FILTER, FP_NF_TABLE_MANGLE, -1 },    /* FP_NF_IP_LOCAL_IN */
		{ FP_NF_TABLE_MANGLE, FP_NF_TABLE_FILTER, -1 },    /* FP_NF_IP_FORWARD */
		{ FP_NF_TABLE_FILTER, FP_NF_TABLE_MANGLE, FP_NF_TABLE_NAT, -1 },    /* FP_NF_IP_LOCAL_OUT */
		{ FP_NF_TABLE_MANGLE, FP_NF_TABLE_NAT, -1 } };     /* FP_NF_IP_POST_ROUTING */
#ifdef CONFIG_MCORE_NF_CT
	uint32_t i;
#endif

#ifdef CONFIG_MCORE_M_TAG
	nfm_tag_type = m_tag_type_register(NFM_TAG_NAME);
	if (nfm_tag_type < 0) {
		TRACE_NF(FP_LOG_ERR, "Cannot register tag type for '" NFM_TAG_NAME "'");
	}
#endif

	memcpy(fp_shared->fp_nf_hook_prio[0], hook_prio, sizeof(hook_prio));
	memcpy(fp_shared->fp_nf_hook_prio[1], hook_prio, sizeof(hook_prio));
	fp_shared->fp_nf_current_hook_prio = 0;

	memset(fp_shared->fp_nf_tables, 0, sizeof(fp_shared->fp_nf_tables));
	memset(fp_shared->fp_nf_rules, 0, sizeof(fp_shared->fp_nf_rules));
	fp_shared->fp_nf_current_table = 0;

	r = 0;
	for (vr = 0; vr < FP_NF_MAX_VR; vr++) {
		for (t = 0; t < FP_NF_TABLE_NUM; t++) {
			fp_nftable_t *tb = &fp_shared->fp_nf_tables[0][vr][t];

			/* Each table must have at least one rule to maintain
			 * a consistent state in the shared memory. */
			for (h = 0; h < FP_NF_IP_NUMHOOKS; h++) {
				tb->fpnftable_hook_entry[h] = r;
				tb->fpnftable_underflow[h] = r;
			}
			fp_shared->fp_nf_rules[0][r].target.type = FP_NF_TARGET_TYPE_ERROR;
			r++;

			tb->fpnftable_rules_count = 1;
		}
	}

	fpn_spinlock_init(&nf_ratelimit_lock);
#ifdef CONFIG_MCORE_NF_CT
	bzero(&fp_shared->fp_nf_ct, sizeof(fp_shared->fp_nf_ct));
	/* The hash_next starting value is supposed to be 'undefined',
	 * represented by FP_NF_CT_MAX */
	for (i = 0; i < FP_NF_CT_MAX; i++) {
		fp_shared->fp_nf_ct.fp_nfct[i].tuple[FP_NF_IP_CT_DIR_ORIGINAL].hash_next.s.index = FP_NF_CT_MAX;
		fp_shared->fp_nf_ct.fp_nfct[i].tuple[FP_NF_IP_CT_DIR_REPLY].hash_next.s.index = FP_NF_CT_MAX;
		fp_shared->fp_nf_ct.fp_nfct[i].next_available = i+1;
#ifdef CONFIG_MCORE_NF_CT_CPEID
		fp_shared->fp_nf_ct.fp_nfct[i].hash_next_cpeid = FP_NF_CT_MAX;
		FP_NF_CT_SET_HASH_PREV_CPEID(fp_shared->fp_nf_ct.fp_nfct[i], FP_NF_CT_MAX);
#endif
	}
	/* The algorithm supposes that hash table is initialized to FP_NF_CT_MAX
	 * for all entries */
	for (i = 0; i < FP_NF_CT_HASH_SIZE; i++)
		fp_shared->fp_nf_ct.fp_nfct_hash[i].s.index = FP_NF_CT_MAX;

#ifdef CONFIG_MCORE_NF_CT_CPEID
	for (i = 0; i < FP_NF_CT_HASH_CPEID_SIZE; i++)
		fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[i] = FP_NF_CT_MAX;
#endif
#endif /* CONFIG_MCORE_NF_CT */
}

/* Returns 1 if the port is matched by the range, 0 otherwise */
int fp_nf_port_match(uint16_t min, uint16_t max,
                     uint16_t port, int invert)
{
	return ((port >= min && port <= max) ^ invert);
}

/* Returns 1 if the port is matched by the range, 0 otherwise */
int fp_nf_multiport_match(struct fp_nfrule_multiport * minfo,
                          uint16_t src, uint16_t dst)
{
	unsigned int i;
	uint16_t s, e;
	for (i = 0; i < FP_NF_MULTIPORT_SIZE; i++) {
		s = minfo->ports[i];

		if (minfo->pflags[i]) {
			/* range port matching */
			e = minfo->ports[++i];

			if (minfo->flags == FP_NF_MULTIPORT_FLAG_SRC
				&& src >= s && src <= e)
				return !minfo->invert;
			if (minfo->flags == FP_NF_MULTIPORT_FLAG_DST
				&& dst >= s && dst <= e)
				return !minfo->invert;
			if (minfo->flags == FP_NF_MULTIPORT_FLAG_ANY
				&& ((dst >= s && dst <= e)
				|| (src >= s && src <= e)))
				return !minfo->invert;
		} else {
			/* exact port matching */
			if (minfo->flags == FP_NF_MULTIPORT_FLAG_SRC
				&& src == s)
				return !minfo->invert;
			if (minfo->flags == FP_NF_MULTIPORT_FLAG_DST
				&& dst == s)
				return !minfo->invert;
			if (minfo->flags == FP_NF_MULTIPORT_FLAG_ANY
				&& (src == s || dst == s))
				return !minfo->invert;
		}

	}
	return minfo->invert;
}


static int fp_nf_iprange_match(struct fp_nfrule_iprange *info,uint32_t saddr, uint32_t daddr)
{
	int m;
	if (info->flags & IPRANGE_SRC) {
		m  = (saddr) < ntohl(info->src_min.ip);
		m |= (saddr) > ntohl(info->src_max.ip);
		m ^= !!(info->flags & IPRANGE_SRC_INV);
		if (m) {
			return 0;
		}
	}
	if (info->flags & IPRANGE_DST) {
		m  = (daddr) < ntohl(info->dst_min.ip);
		m |= (daddr) > ntohl(info->dst_max.ip);
		m ^= !!(info->flags & IPRANGE_DST_INV);
		if (m) {
			return 0;
		}
	}
	return 1;
}

static int* MakeSkip(char *ptrn, int pLen)  
{     
    int i;  
   
    /*create skip table, allocate 256 int*/
    int *skip = (int*)malloc(256*sizeof(int));  
  
    if(skip == NULL)  
    {  
        fprintf(stderr, "malloc failed!");  
        return 0;  
    }     
  
  
    for(i = 0; i < 256; i++)  
    {  
        *(skip+i) = pLen;  
    }  
  
    while(pLen != 0)  
    {  
        *(skip+(unsigned char)*ptrn++) = pLen--;  
    }  
  
    return skip;  
}  
  
  
static int* MakeShift(char* ptrn,int pLen)  
{  
    int *shift = (int*)malloc(pLen*sizeof(int)); 
    int *sptr = shift + pLen - 1;
    char *pptr = ptrn + pLen - 1;
    char c;  
  
    if(shift == NULL)  
    {  
        fprintf(stderr,"malloc failed!");  
        return 0;  
    }  
  
    c = *(ptrn + pLen - 1);
  
    *sptr = 1;
  
    pptr--;
  
    while(sptr-- != shift)  
    {  
        char *p1 = ptrn + pLen - 2, *p2,*p3;  
          
        do{  
            while(p1 >= ptrn && *p1-- != c);
              
            p2 = ptrn + pLen - 2;  
            p3 = p1;  
              
            while(p3 >= ptrn && *p3-- == *p2-- && p2 >= pptr);
  
        }while(p3 >= ptrn && p2 >= pptr);  
  
        *sptr = shift + pLen - sptr + p2 - p3;
        
  
        pptr--;
    }  
  
    return shift;  
}  
  
  

static int BMSearch(char *buf, int blen, char *ptrn, int plen, int *skip, int *shift)  
{  
    int b_idx = plen;    
    if (plen == 0)  
        return 1;  
    while (b_idx <= blen)
    {  
        int p_idx = plen, skip_stride, shift_stride;  
        while (buf[--b_idx] == ptrn[--p_idx])
        {  
            if (b_idx < 0)  
                return 0;  
            if (p_idx == 0)  
            {       
                return 1;  
            }  
        }  
        skip_stride = skip[(unsigned char)buf[b_idx]];
        shift_stride = shift[p_idx];
        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }  
    return 0;  
}  

static int fp_nf_string_match(struct fp_nfrule_string *info, struct mbuf *m)
{
	u_int16_t  match = 0;	
	u_int16_t  buflen = 0, offset = 0;	
	u_int8_t*   buf = NULL;
	u_int8_t    algo[FP_NF_STRING_MAX_ALGO_NAME_SIZE];
	u_int8_t    pattern[FP_NF_STRING_MAX_PATTERN_SIZE];
	u_int8_t    patlen = info->string.patlen;	
	u_int8_t    invert = info->string.u.v0.invert;
	struct fp_ip *ip = mtod(m, struct fp_ip *);	

	memcpy(algo, info->string.algo, FP_NF_STRING_MAX_ALGO_NAME_SIZE);	
	memcpy(pattern, info->string.pattern, patlen);

	/*no specific offset, default search after udp/tcp header*/
	if(info->string.from_offset == 0 && info->string.to_offset == 65535)
	{		
		switch(ip->ip_p) 
		{
			case FP_IPPROTO_UDP:
				offset = sizeof(struct fp_udphdr) + ip->ip_hl * 4;
				break;
				
			case FP_IPPROTO_TCP:				
				offset = sizeof(struct fp_tcphdr) + ip->ip_hl * 4;
				break;
			default:
				return NF_IP_MATCH_NO;
		}
				
		buf = m_off(m, offset, u_int8_t *);
		buflen = m_len(m) - offset;		
	}
	else
	/*seach according to from_offset and to_offset*/
	{
		if(info->string.from_offset >= m_len(m) || info->string.to_offset > m_len(m) || info->string.from_offset >= info->string.to_offset)
		{
			printf("Invalid from_offset:%u or to_offset:%u.\n", info->string.from_offset, info->string.to_offset);
			return 0;
		}
		buf = m_off(m,  info->string.from_offset, u_int8_t *);	   
		buflen = info->string.to_offset - info->string.from_offset + 1;	   
	}

	//printf("From:%u, to:%u, pattern:%s, patlen:%u, buflen:%u!\n ", info->string.from_offset, info->string.to_offset, pattern, patlen, buflen);
	
	/*currently only support bm algo*/
	if (!strcmp((const char *)algo, "bm"))		
		match = BMSearch((char *)buf, buflen, (char *)pattern, patlen, MakeSkip((char *)pattern, patlen), MakeShift((char *)pattern, patlen));
	//printf("match:%d, invert:%d!\n", match, invert);
	
	return match ^ invert;
}

/* For TCP, UDP, SCTP and GRE packets, lookup for a matching conntrack
 * for this packet, and return the state. If a conntrack entry is
 * found, also update its statistics. We know that headers are in
 * contiguous mem thanks to fp_nf_check_packet(), except for sctp
 * chunks. */
uint8_t fp_nfct_update(struct mbuf *m)
{
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	uint32_t offset;
	const struct fp_udphdr *uh;
	const struct fp_tcphdr *th;
	const struct fp_sctphdr *sh;
	struct fp_sctpchunkhdr sch;
	uint16_t dport = 0, sport = 0;
	int fin = 0;

	/* A fragment will be sent as an exception. */
	if (ntohs(ip->ip_off) & FP_IP_OFFMASK)
		return FP_NF_CT_MBUF_OTHER;

	switch (ip->ip_p) {
	case FP_IPPROTO_TCP:
		th = m_off(m, ip->ip_hl * 4, const struct fp_tcphdr *);
		/* Some special packets must be sent in exception */
		if (th->th_flags & (TH_SYN|TH_RST))
			return FP_NF_CT_MBUF_OTHER;
		if (th->th_flags & TH_FIN)
			fin = 1;
		/*
		 * Only ASSURED ct are set in shared memory, hence no need to
		 * send (ACK && !PSH) to SP.
		 */
		sport = th->th_sport;
		dport = th->th_dport;
		break;
	case FP_IPPROTO_UDP:
		uh = m_off(m, ip->ip_hl * 4, const struct fp_udphdr *);
		sport = uh->uh_sport;
		dport = uh->uh_dport;
		break;
	case FP_IPPROTO_SCTP:
		sh = m_off(m, ip->ip_hl * 4, const struct fp_sctphdr *);
		/* Some special packets must be sent in exception */
		offset = ip->ip_hl * 4 + sizeof(struct fp_sctphdr);
		while (offset < m_len(m)) {
			FPN_TRACK();
			/* m_copytobuf() will succeed and sch.length >=4, 
			 * it was tested in fp_nf_check_packet() */
			m_copytobuf(&sch, m, offset, sizeof(struct fp_sctpchunkhdr));
			if (sch.chunk_type == SCTP_CID_SHUTDOWN ||
			    sch.chunk_type == SCTP_CID_SHUTDOWN_ACK ||
			    sch.chunk_type == SCTP_CID_SHUTDOWN_COMPLETE) {
				return FP_NF_CT_MBUF_OTHER;
			}
			offset += (ntohs(sch.chunk_length) + 3) & ~3;
		}
		sport = sh->src_port;
		dport = sh->dest_port;
		break;
	case FP_IPPROTO_GRE:
	case FP_IPPROTO_ESP:
	case FP_IPPROTO_AH:
		/* nothing to do, just continue with conntrack lookup. */
		break;
	default:
		/* Other protocols are not added into fp_nf_ct, hence
		 * we can bypass the lookup. */
		return FP_NF_CT_MBUF_OTHER;
	}

	if (fp_nfct_get(m, ip, sport, dport) < 0) {
		/* no entry found, return */
		return FP_NF_CT_MBUF_OTHER;
	}

	if (unlikely(fin))
		m_priv(m)->fp_nfct.v4->flag |= FP_NFCT_FLAG_END;

	if (unlikely(m_priv(m)->fp_nfct.v4->flag & FP_NFCT_FLAG_END)) {
		/* remove update flag to prevent from sending hf sync for that conntrack
		   after a FIN segment */
		m_priv(m)->fp_nfct.v4->flag &= ~FP_NFCT_FLAG_UPDATE;
		return FP_NF_CT_MBUF_OTHER;
	}

	/* valid conntrack found, update counters */
	m_priv(m)->fp_nfct.v4->counters[m_priv(m)->fp_nfct_dir].packets++;
#ifdef CONFIG_MCORE_NF_CT_BYTES
	m_priv(m)->fp_nfct.v4->counters[m_priv(m)->fp_nfct_dir].bytes += m_len(m);
#endif
	m_priv(m)->fp_nfct.v4->flag |= FP_NFCT_FLAG_UPDATE;
	return FP_NF_CT_MBUF_ESTABLISHED;
}

static inline int nf_ip_match(struct mbuf *m, struct fp_nfrule *r,
			      const fp_ifnet_t *indev, const fp_ifnet_t *outdev)
{
	struct fp_ip *ip = mtod(m, struct fp_ip *);
	struct fp_udphdr *uh;
	struct fp_tcphdr *th;
	struct fp_icmphdr *ih;
	struct fp_sctphdr *sh;
	struct fp_sctpchunkhdr sch;
	uint32_t chunkmapcopy[FP_NF_SCTP_CHUNKMAP_SIZE / (sizeof(uint32_t) * 8)];
	int offset, match;
	unsigned long ret;
	uint32_t optlen, ip_off;
	uint8_t *opt;
	unsigned int i;

#ifndef CONFIG_MCORE_NF_TABLE_PER_VR
	if (r->l2_opt.vrfid != FP_NF_VRFID_UNSPECIFIED)
		if (r->l2_opt.vrfid != m2vrfid(m))
			return NF_IP_MATCH_NO;
#endif

#define FWINV(bool, invflg) ((bool) ^ !!(r->l2.ipv4.invflags & invflg))

	if (FWINV((ip->ip_src.s_addr & r->l2.ipv4.smsk) != r->l2.ipv4.src,
		  FP_NF_IPT_INV_SRCIP)
	    || FWINV((ip->ip_dst.s_addr & r->l2.ipv4.dmsk) != r->l2.ipv4.dst,
		     FP_NF_IPT_INV_DSTIP))
		return NF_IP_MATCH_NO;

	/* here we can use a memcmp() instead of strncmp() because we
	 * know the len */
	if (indev) {
		ret = r->l2.ipv4.iniface_len &&
			fpn_fast_memcmp(indev->if_name, r->l2.ipv4.iniface, r->l2.ipv4.iniface_len);
		if (FWINV(ret != 0, FP_NF_IPT_INV_VIA_IN))
			return NF_IP_MATCH_NO;
	}

	if (outdev) {
		ret = r->l2.ipv4.outiface_len &&
			fpn_fast_memcmp(outdev->if_name, r->l2.ipv4.outiface, r->l2.ipv4.outiface_len);
		if (FWINV(ret != 0, FP_NF_IPT_INV_VIA_OUT))
			return NF_IP_MATCH_NO;
	}

	if (likely(r->l2.ipv4.proto &&
				 FWINV(ip->ip_p != r->l2.ipv4.proto, FP_NF_IPT_INV_PROTO)))
		return NF_IP_MATCH_NO;


	/* If we have a fragment rule but the packet is not a fragment
	 * then we return zero */
	if (FWINV((r->l2.ipv4.flags & FP_NF_IPT_F_FRAG)
		  && !(ntohs(ip->ip_off) & FP_IP_OFFMASK),
		  FP_NF_IPT_INV_FRAG))
		return NF_IP_MATCH_NO;
#undef FWINV

	if ((r->l2_opt.opt & FP_NF_l2OPT_DSCP)
	    && !(((ip->ip_tos & FP_DSCP_MASK) == r->l2_opt.dscp) ^ r->l2_opt.invdscp))
		return NF_IP_MATCH_NO;

	if (r->l2_opt.opt & FP_NF_l2OPT_RATELIMIT) {
		uint64_t now;
		int64_t delta;

		fp_nf_cache_disable_next();

		fpn_spinlock_lock(&nf_ratelimit_lock);
		now = fpn_get_clock_cycles();
		delta = (int64_t)(now - r->l2_opt.rateinfo.prev);
		if (delta > 0) {
			r->l2_opt.rateinfo.credit += delta;
			r->l2_opt.rateinfo.prev = now;
		}
		if (r->l2_opt.rateinfo.credit > r->l2_opt.rateinfo.credit_cap)
			r->l2_opt.rateinfo.credit = r->l2_opt.rateinfo.credit_cap;

		if (r->l2_opt.rateinfo.credit < r->l2_opt.rateinfo.cost) {
			fpn_spinlock_unlock(&nf_ratelimit_lock);
			return NF_IP_MATCH_NO;
		}
		/* We're not limited. */
		r->l2_opt.rateinfo.credit -= r->l2_opt.rateinfo.cost;
		fpn_spinlock_unlock(&nf_ratelimit_lock);
	}

	if (r->l2_opt.opt & FP_NF_l2OPT_MARK) {
		uint32_t mark = 0;

		fp_nf_cache_disable_next();

#ifdef CONFIG_MCORE_M_TAG
		/* ignore return value, if tag does
		 * not exist, mark will stay to 0 */
		if (m_tag_get(m, nfm_tag_type, &mark) == 0)
			mark = ntohl(mark);
#endif

		if (!(((mark & r->l2_opt.mark.mask) == r->l2_opt.mark.mark)
		      ^ r->l2_opt.mark.invert))
			return NF_IP_MATCH_NO;

	}

#ifdef CONFIG_MCORE_RPF_IPV4
	if (r->l2_opt.opt & FP_NF_l2OPT_RPFILTER) {
		/* send the packet to the kernel if there are unsupported
		 * rpf match options */
		if (r->l2_opt.rpf_flags & ~FP_NF_RPF_INVERT)
			return NF_IP_MATCH_EXCEPTION;
		/* When the invert flag is set, the packet does NOT match when
		 * the rpf check is OK
		 * We use !!() because ^ is a bitwise operator */
		if (!!fp_ip_rpf_check(m) ^ !!(r->l2_opt.rpf_flags & FP_NF_RPF_INVERT))
			return NF_IP_MATCH_NO;
	}
#endif /* CONFIG_MCORE_RPF_IPV4 */

	if (r->l2_opt.opt & FP_NF_l2OPT_MAC) {

		fp_nf_cache_disable_next();

		if (!indev || indev->if_type != FP_IFTYPE_ETHER)
			return NF_IP_MATCH_NO;
		if (s_headroom((const struct sbuf *)m_first_seg(m)) < 14)
			return NF_IP_MATCH_NO;

		uint16_t *a = (uint16_t *) ((uint8_t *)ip - 8);
		uint16_t *b = (uint16_t *) r->l2_opt.mac.srcaddr;

		if (((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) ^ r->l2_opt.mac.invert)
			return NF_IP_MATCH_NO;
	}


	if (r->l2_opt.opt & FP_NF_l2OPT_PHYSDEV) {
		fp_nf_cache_disable_next();

		return nf4_physdev_match(m, r, indev, outdev);
	}

	switch(r->l3.type) {
	case FP_NF_L3_TYPE_NONE:
		break;
	case FP_NF_L3_TYPE_UDP:
		/* Must not be a fragment. */
		if (ntohs(ip->ip_off) & FP_IP_OFFMASK)
			return NF_IP_MATCH_NO;

		uh = m_off(m, ip->ip_hl * 4, struct fp_udphdr *);

		if (!(fp_nf_port_match(r->l3.data.udp.spts[0], r->l3.data.udp.spts[1],
		                       ntohs(uh->uh_sport),
		                       !!(r->l3.data.udp.invflags & FP_NF_IPT_UDP_INV_SRCPT))
		      && fp_nf_port_match(r->l3.data.udp.dpts[0], r->l3.data.udp.dpts[1],
		                          ntohs(uh->uh_dport),
		                          !!(r->l3.data.udp.invflags & FP_NF_IPT_UDP_INV_DSTPT))))
			return NF_IP_MATCH_NO;
		break;
	case FP_NF_L3_TYPE_TCP:
		if ((ip_off = ntohs(ip->ip_off) & FP_IP_OFFMASK) != 0) {
			/* Don't allow a fragment of TCP 8 bytes in. Nobody normal
			 * causes this. Its a cracker trying to break in by doing a
			 * flag overwrite to pass the direction checks.
			 */
			if (ip_off == 1)
				return NF_IP_MATCH_ERROR;
			/* Must not be a fragment. */
			return NF_IP_MATCH_NO;
		}

		th = m_off(m, ip->ip_hl * 4, struct fp_tcphdr *);

		if (!fp_nf_port_match(r->l3.data.tcp.spts[0], r->l3.data.tcp.spts[1],
		                      ntohs(th->th_sport),
		                      !!(r->l3.data.tcp.invflags & FP_NF_IPT_TCP_INV_SRCPT)))
			return NF_IP_MATCH_NO;

		if (!fp_nf_port_match(r->l3.data.tcp.dpts[0], r->l3.data.tcp.dpts[1],
		                      ntohs(th->th_dport),
		                      !!(r->l3.data.tcp.invflags & FP_NF_IPT_TCP_INV_DSTPT)))
			return NF_IP_MATCH_NO;

		if (!(((((uint8_t *)th)[13] & r->l3.data.tcp.flg_mask) == r->l3.data.tcp.flg_cmp)
		      ^ !!(r->l3.data.tcp.invflags & FP_NF_IPT_TCP_INV_FLAGS)))
			return NF_IP_MATCH_NO;

		if (r->l3.data.tcp.option) {
			optlen = th->th_off * 4 - sizeof(struct fp_tcphdr);
			if (optlen == 0 && 
			    !(r->l3.data.tcp.invflags & FP_NF_IPT_TCP_INV_OPTION))
				return NF_IP_MATCH_NO;

			opt = m_off(m, ip->ip_hl * 4 + sizeof(struct fp_tcphdr), uint8_t *);

			for (i = 0; i < optlen; ) {
				FPN_TRACK();
				if (opt[i] == r->l3.data.tcp.option) {
					if (r->l3.data.tcp.invflags & FP_NF_IPT_TCP_INV_OPTION)
						return NF_IP_MATCH_NO;
					else
						break;
				}
				if (opt[i] < 2)
					i++;
				else
					i += opt[i + 1] ? : 1;
			}
		}
		break;
	case FP_NF_L3_TYPE_SCTP:
		/* Must not be a fragment. */
		if (ntohs(ip->ip_off) & FP_IP_OFFMASK)
			return NF_IP_MATCH_NO;

		sh = m_off(m, ip->ip_hl * 4, struct fp_sctphdr *);

		if (r->l3.data.sctp.flags & FP_NF_IPT_SCTP_SRC_PORTS)
			if (!fp_nf_port_match(r->l3.data.sctp.spts[0], r->l3.data.sctp.spts[1],
			                      ntohs(sh->src_port),
			                      !!(r->l3.data.sctp.invflags & FP_NF_IPT_SCTP_SRC_PORTS)))
				return NF_IP_MATCH_NO;

		if (r->l3.data.sctp.flags & FP_NF_IPT_SCTP_DEST_PORTS)
			if (!fp_nf_port_match(r->l3.data.sctp.dpts[0], r->l3.data.sctp.dpts[1],
			                      ntohs(sh->dest_port),
			                      !!(r->l3.data.sctp.invflags & FP_NF_IPT_SCTP_DEST_PORTS)))
				return NF_IP_MATCH_NO;

		/* Check type match */
		if (r->l3.data.sctp.flags & FP_NF_IPT_SCTP_CHUNK_TYPES) {
			/* no cache with rules on chunk packets */
			fp_nf_cache_disable_next();

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

			offset = ip->ip_hl * 4 + sizeof(struct fp_sctphdr);
			while (offset < (int)m_len(m)) {
				FPN_TRACK();
				/* m_copytobuf() will succeed and sch.length >=4, 
				 * it was tested in fp_nf_check_packet() */
				m_copytobuf(&sch, m, offset, sizeof(struct fp_sctpchunkhdr));
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
				offset += (ntohs(sch.chunk_length) + 3) & ~3;
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
				return NF_IP_MATCH_NO;
		}
		break;
	case FP_NF_L3_TYPE_ICMP:
		/* Must not be a fragment. */
		if (ntohs(ip->ip_off) & FP_IP_OFFMASK)
			return NF_IP_MATCH_NO;

		ih = m_off(m, ip->ip_hl * 4, struct fp_icmphdr *);

		if (!((r->l3.data.icmp.type == 0xFF ||
		      (ih->icmp_type == r->l3.data.icmp.type &&
		       ih->icmp_code >= r->l3.data.icmp.code[0] &&
		       ih->icmp_code <= r->l3.data.icmp.code[1])) ^
		     !!(r->l3.data.icmp.invflags & FP_NF_IPT_ICMP_INV)))
			return NF_IP_MATCH_NO;
		break;
	default:
		return NF_IP_MATCH_NO;
	}

	if (r->l3.state) {

		fp_nf_cache_next_need_ct_state(r->l3.state);

		if (!m_priv(m)->fp_nfct_established)
			m_priv(m)->fp_nfct_established = fp_nfct_update(m);

		if (m_priv(m)->fp_nfct_established == FP_NF_CT_MBUF_OTHER)
			return NF_IP_MATCH_EXCEPTION;
		if (m_priv(m)->fp_nfct_established != r->l3.state)
			return NF_IP_MATCH_NO;
	}

	if (r->l3_opt.opt & FP_NF_l3OPT_MULTIPORT) {
		uint16_t sport, dport;
		const struct fp_tcphdr * h;
		if (ip->ip_p == FP_IPPROTO_TCP ||
		    ip->ip_p == FP_IPPROTO_UDP ||
		    ip->ip_p == FP_IPPROTO_SCTP ||
		    ip->ip_p == 0x21 /* DCCP */ ||
		    ip->ip_p == 0x88 /* UDPLite */ ) {
			/* All protocols headers begin with src port (16 bits) and
			 * dst ports (16 bits) so we can use the tcp struct to access
			 * ports for all protocols */
			h = m_off(m, ip->ip_hl * 4, const struct fp_tcphdr *);
			sport = ntohs(h->th_sport);
			dport = ntohs(h->th_dport);
		}
		else {
			return NF_IP_MATCH_NO;
		}

		if (!fp_nf_multiport_match(&(r->l3_opt.multiport), sport, dport))
			return NF_IP_MATCH_NO;
	}

	//for IPRANGE extensions
	if (r->l3_opt.opt & FP_NF_l3OPT_IPRANGE) {
		if(!fp_nf_iprange_match((struct fp_nfrule_iprange *)&(r->l3_opt.iprange), ntohl(ip->ip_src.s_addr),ntohl(ip->ip_dst.s_addr)))
			return NF_IP_MATCH_NO;
	}

	//for string extensions
	if (r->string_opt.opt & FP_NF_OPT_STRING) {
		if(!fp_nf_string_match((struct fp_nfrule_string *)&(r->string_opt), m))
			return NF_IP_MATCH_NO;
	}

	return NF_IP_MATCH_YES;
}

static FPN_DEFINE_PER_CORE(int [FP_NF_MAXRULES], fp_nf_comefrom);
static inline int fp_nf_table(struct mbuf *m, int tablenum, int hook,
			      const fp_ifnet_t *indev, const fp_ifnet_t *outdev)
{
	int res, verdict, back, cur;
#ifdef CONFIG_MCORE_NF_TABLE_PER_VR
	uint16_t nf_vr = m2vrfid(m);
#else
	uint16_t nf_vr = 0;
#endif
	int cur_table = fp_shared->fp_nf_current_table;
	fp_nftable_t *table = &fp_shared->fp_nf_tables[cur_table][nf_vr][tablenum];

#if 0
	/* Assume fp_shared->fp_nf_hook_prio[fp_shared->fp_nf_current_hook_prio] is set correctly */
	if (!(table->fpnftable_valid_hooks & (1 << hook)))
		return FP_NF_ACCEPT;
#endif

#define RULE(n)  fp_shared->fp_nf_rules[cur_table][n]
	cur = table->fpnftable_hook_entry[hook];
	back = table->fpnftable_underflow[hook];
	do {
		FPN_TRACK();
		if ((res = nf_ip_match(m, &RULE(cur), indev, outdev)) <= 0)
			goto no_match;

		FP_NF_STATS_INC(RULE(cur).stats, pcnt);
		FP_NF_STATS_ADD(RULE(cur).stats, bcnt, m_len(m));

		/* check that the rule can be cached; if not, disable
		 * the cache for this packet */
		fp_nf_cache_check_rule(&RULE(cur));

		switch(RULE(cur).target.type) {
		case FP_NF_TARGET_TYPE_STANDARD:
			verdict = RULE(cur).target.data.standard.verdict;
			if (verdict < 0) {
				/* If verdict is != from FP_NF_IPT_RETURN and FP_NF_ACCEPT,
				 * cache is disabled.
				 */
				fp_nf_cache_check_update(m, hook, tablenum, indev,
							 outdev, &RULE(cur), -verdict - 1);
				if (verdict == FP_NF_IPT_RETURN) {
					cur = back;
					back = FPN_PER_CORE_VAR(fp_nf_comefrom)[back];
					continue;
				}
				return - verdict - 1;
			}
			/* Don't send verdict to fp_nf_cache_check_update(), here verdict
			 * is >0, this means that we must jump to another rule, so we want
			 * to avoid a confusion between rule number and FP_NF_ACCEPT.
			 */
			fp_nf_cache_check_update(m, hook, tablenum, indev,
						 outdev, &RULE(cur), FP_NF_CONTINUE);
			/* The verdict value is the rule index *relative* to the beginning
			 * of the table. Since all rules are stored in the same global
			 * array, we must shift it to get an absolute index. */
			verdict += fp_nf_first_ruleid(table);
			if (&RULE(verdict) != &RULE(cur + 1)
			    && !(RULE(cur).l2.ipv4.flags & FP_NF_IPT_F_GOTO)) {
				cur++;
				FPN_PER_CORE_VAR(fp_nf_comefrom)[cur] = back;
				back = cur;
			}
			cur = verdict;
			continue;
			break;
		case FP_NF_TARGET_TYPE_MARK_V2:
			fp_nf_update_mark(m, RULE(cur).target.data.mark.mark,
					  RULE(cur).target.data.mark.mask);
			fp_nf_cache_check_update(m, hook, tablenum, indev,
						 outdev, &RULE(cur), FP_NF_CONTINUE);
			break;
		case FP_NF_TARGET_TYPE_DSCP:
			fp_change_ipv4_dscp(mtod(m, struct fp_ip *),
					    RULE(cur).target.data.dscp.dscp);
			fp_nf_cache_check_update(m, hook, tablenum, indev,
						 outdev, &RULE(cur), FP_NF_CONTINUE);
			break;
		case FP_NF_TARGET_TYPE_LOG:
		case FP_NF_TARGET_TYPE_ULOG:
		case FP_NF_TARGET_TYPE_REJECT:
			return FP_NF_EXCEPTION;
		case FP_NF_TARGET_TYPE_MASQUERADE:
		case FP_NF_TARGET_TYPE_SNAT:
		case FP_NF_TARGET_TYPE_DNAT:
			/* We go here only if there is no conntrack
			 * entry in the FP for the packet, i.e. if
			 * fp_nfct_nat_lookup() returned
			 * FP_NF_CONTINUE. */
			return FP_NF_EXCEPTION;
		case FP_NF_TARGET_TYPE_TCPMSS:
			/* Only SYN,RST/SYN are matched by TCPMSS rule,
			 * let's slow path handle this.
			 */
			return FP_NF_EXCEPTION;
		case FP_NF_TARGET_TYPE_DEV: {
			fp_ifnet_t *ifp;
			int ret = FP_DROP; /* not FP_NF_DROP */

			/* if possible, add this in cache; we have to
			 * do it before fp_ip_inetif_send() because m
			 * will be freed. */
			fp_nf_cache_check_update(m, hook, tablenum, indev,
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
				ret = FPN_HOOK_CALL(fp_ip_inetif_send)(m, ifp);

			fp_process_input_finish(m, ret);
			return FP_NF_STOLEN;
		}
		case FP_NF_TARGET_TYPE_CHECKSUM: {
			struct fp_ip *ip = mtod(m, struct fp_ip *);
			uint32_t sum = 0, i;
			ip->ip_sum = 0;
			for (i = 0; i < (uint32_t)(ip->ip_hl) << 1; i++)
				sum += ((uint16_t*)ip)[i];
			sum = (uint16_t)((sum & 0xffff) + (sum >> 16));
			ip->ip_sum = ~sum;
			break;
		}
		case FP_NF_TARGET_TYPE_ERROR:
		default:
			return FP_NF_DROP;
		}
no_match:
		if (unlikely(res == NF_IP_MATCH_EXCEPTION))
			return FP_NF_EXCEPTION;
		cur += 1;
	} while (res >= 0);

	if (res < 0)
		return FP_NF_DROP;

	return verdict;
#undef RULE
}

int fp_ddos_iptables_lookup(struct mbuf *m, int tablenum, int hook)
{
	const fp_ifnet_t *indev  = NULL;
	const fp_ifnet_t *outdev = NULL;
	int res, verdict, back, cur;
	int cur_table = fp_shared->fp_nf_current_table;
	fp_nftable_t *table = &fp_shared->fp_nf_tables[cur_table][0][tablenum];

#define RULE(n)  fp_shared->fp_nf_rules[cur_table][n]

	cur = table->fpnftable_hook_entry[hook];
	back = table->fpnftable_underflow[hook];
	do {

		FPN_TRACK();
		if ((res = nf_ip_match(m, &RULE(cur), NULL, NULL)) <= 0)
		{
			//printf("rule_uid==0x%x  res is %d\n",RULE(cur).uid,res);
			goto no_match;
		}

		FP_NF_STATS_INC(RULE(cur).stats, pcnt);
		FP_NF_STATS_ADD(RULE(cur).stats, bcnt, m_len(m));
		return cur;

		/* check that the rule can be cached; if not, disable
		 * the cache for this packet */
		fp_nf_cache_check_rule(&RULE(cur));

		switch(RULE(cur).target.type) {
		case FP_NF_TARGET_TYPE_STANDARD:
			verdict = RULE(cur).target.data.standard.verdict;
			if (verdict < 0) {
				/* If verdict is != from FP_NF_IPT_RETURN and FP_NF_ACCEPT,
				 * cache is disabled.
				 */
				fp_nf_cache_check_update(m, hook, tablenum, indev,
							 outdev, &RULE(cur), -verdict - 1);
				if (verdict == FP_NF_IPT_RETURN) {
					cur = back;
					back = FPN_PER_CORE_VAR(fp_nf_comefrom)[back];
					continue;
				}
				return - verdict - 1;
			}
			/* Don't send verdict to fp_nf_cache_check_update(), here verdict
			 * is >0, this means that we must jump to another rule, so we want
			 * to avoid a confusion between rule number and FP_NF_ACCEPT.
			 */
			fp_nf_cache_check_update(m, hook, tablenum, indev,
						 outdev, &RULE(cur), FP_NF_CONTINUE);
			if (&RULE(verdict) != &RULE(cur + 1)
			    && !(RULE(cur).l2.ipv4.flags & FP_NF_IPT_F_GOTO)) {
				cur++;
				FPN_PER_CORE_VAR(fp_nf_comefrom)[cur] = back;
				back = cur;
			}
			cur = verdict;
			continue;
			break;
		case FP_NF_TARGET_TYPE_MARK_V2:
			fp_nf_update_mark(m, RULE(cur).target.data.mark.mark,
					  RULE(cur).target.data.mark.mask);
			fp_nf_cache_check_update(m, hook, tablenum, indev,
						 outdev, &RULE(cur), FP_NF_CONTINUE);
			break;
		case FP_NF_TARGET_TYPE_DSCP:
			fp_change_ipv4_dscp(mtod(m, struct fp_ip *),
					    RULE(cur).target.data.dscp.dscp);
			fp_nf_cache_check_update(m, hook, tablenum, indev,
						 outdev, &RULE(cur), FP_NF_CONTINUE);
			break;
		case FP_NF_TARGET_TYPE_LOG:
		case FP_NF_TARGET_TYPE_ULOG:
		case FP_NF_TARGET_TYPE_REJECT:
			return FP_NF_EXCEPTION;
		case FP_NF_TARGET_TYPE_MASQUERADE:
		case FP_NF_TARGET_TYPE_SNAT:
		case FP_NF_TARGET_TYPE_DNAT:
			/* We go here only if there is no conntrack
			 * entry in the FP for the packet, i.e. if
			 * fp_nfct_nat_lookup() returned
			 * FP_NF_CONTINUE. */
			return FP_NF_EXCEPTION;
		case FP_NF_TARGET_TYPE_TCPMSS:
			/* Only SYN,RST/SYN are matched by TCPMSS rule,
			 * let's slow path handle this.
			 */
			return FP_NF_EXCEPTION;
		case FP_NF_TARGET_TYPE_DEV: {
			fp_ifnet_t *ifp;
			int ret = FP_DROP; /* not FP_NF_DROP */

			/* if possible, add this in cache; we have to
			 * do it before fp_ip_inetif_send() because m
			 * will be freed. */
			fp_nf_cache_check_update(m, hook, tablenum, indev,
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
			if (likely(ifp != NULL && ifp->if_type != FP_IFTYPE_ETHER))
				ret = fp_ip_inetif_send(m, ifp);

			fp_process_input_finish(m, ret);
			return FP_NF_STOLEN;
		}
		case FP_NF_TARGET_TYPE_ERROR:
		default:
			return FP_NF_DROP;
		}
no_match:
		if (unlikely(res == NF_IP_MATCH_EXCEPTION))
			return FP_NF_EXCEPTION;
		cur += 1;
	} while (res >= 0);

	if (res < 0)
		return FP_NF_DROP;

	return verdict;
#undef RULE
}

/* Check that header is in contiguous memory (protocol header must not
 * be fragmented). */
static inline int fp_nf_check_size(const struct mbuf *m, const struct fp_ip *ip,
				   int len)
{
	if (len > (int)(ntohs(ip->ip_len) - ip->ip_hl * 4))
		return -1;
	if ((int)m_headlen(m) < (ip->ip_hl * 4 + len))
		return -1;
	return 0;
}

#define FP_TH_FIN  0x01
#define FP_TH_SYN  0x02
#define FP_TH_RST  0x04
#define FP_TH_PUSH 0x08
#define FP_TH_ACK  0x10
#define FP_TH_URG  0x20
#define FP_TH_ECE  0x40
#define FP_TH_CWR  0x80

/* table of valid flag combinations - PUSH, ECE and CWR are always valid */
static uint8_t tcp_valid_flags[(FP_TH_FIN|FP_TH_SYN|FP_TH_RST|FP_TH_ACK|FP_TH_URG) + 1] =
{
    [FP_TH_SYN]            = 1,
    [FP_TH_SYN|FP_TH_URG]     = 1,
    [FP_TH_SYN|FP_TH_ACK]     = 1,
    [FP_TH_RST]            = 1,
    [FP_TH_RST|FP_TH_ACK]     = 1,
    [FP_TH_FIN|FP_TH_ACK]     = 1,
    [FP_TH_FIN|FP_TH_ACK|FP_TH_URG]  = 1,
    [FP_TH_ACK]            = 1,
    [FP_TH_ACK|FP_TH_URG]     = 1,
};

/* Check if incoming TCP packet is valid
 * - Checksum
 * - TCP flags
 * Return FP_NF_DROP to drop the packet, FP_NF_EXCEPTION to raise
 * an exception, or FP_NF_DROP to drop the packet when it's invalid.
 */
static inline int fp_mbuf_check_tcp(const struct mbuf *m,
				    const struct fp_tcphdr *th,
				    int is_fragment)
{
	uint8_t flags;
#ifdef FPN_HAS_HW_CHECK_L4
	if (fpn_mbuf_hw_check_l4(m) == 0)
		return FP_NF_ACCEPT;
#endif

	/*
	 * TCP checksum, except for fragmented packets (as it is calculated
	 * upon the complete datagram).
	 * Subsequent fragments are processed before this function.
	 */
	if (!is_fragment) {
#ifdef FPN_HAS_HW_CHECK_L4_CHKSUM
		if (fpn_mbuf_hw_check_l4_cksum(m) != 0)
			/* Fallback software version */
#endif
		/* TCP checksum */
		if (fpn_in4_l4cksum(m))
			return FP_NF_DROP;
	}

	/* Check TCP flags. */
	flags = (((u_int8_t *)th)[13] & ~(FP_TH_ECE|FP_TH_CWR|FP_TH_PUSH));
	if (!tcp_valid_flags[flags])
		return FP_NF_DROP;

	return FP_NF_ACCEPT;
}

/* Check if incoming UDP packet is valid
 * - Checksum
 * - Length correspond to L2 length
 * Return FP_NF_DROP to drop the packet, FP_NF_EXCEPTION to raise
 * an exception, or FP_NF_DROP to drop the packet when it's invalid.
 */
static inline int fp_mbuf_check_udp(const struct mbuf *m)
{
	const struct fp_ip *ip;
	const struct fp_udphdr *udp;
	uint16_t udplen;

#ifdef FPN_HAS_HW_CHECK_L4
	if (fpn_mbuf_hw_check_l4(m) == 0)
		return FP_NF_ACCEPT;
#endif

	ip = mtod(m, const struct fp_ip *);
	udp = m_off(m, ip->ip_hl * 4, const struct fp_udphdr *);
	/* Truncated/malformed packets */
	udplen = m_len(m) - ip->ip_hl * 4;
	if (ntohs(udp->uh_ulen) != udplen || ntohs(udp->uh_ulen) < sizeof(*udp))
		return FP_NF_DROP;

	/* UDP checksum */
#ifdef FPN_HAS_HW_CHECK_L4_CHKSUM
	if (fpn_mbuf_hw_check_l4_cksum(m) != 0)
		/* Fallback software version */
#endif
	if (udp->uh_sum != 0 && fpn_in4_l4cksum(m))
		return FP_NF_DROP;

	return FP_NF_ACCEPT;
}

/* Check that the packet is valid: some headers need to be in
 * contiguous memory, else we will send it as an exception to the
 * control plane. Return NF_ACCEPT on success.
 * Return FP_NF_DROP to drop the packet. */
static inline int fp_nf_check_packet(const struct mbuf *m, int l4parsing)
{
	const struct fp_ip *ip = mtod(m, const struct fp_ip *);
	struct fp_sctpchunkhdr sch;
	const struct fp_tcphdr *th;
	uint32_t offset, optlen;
	size_t icmp_dun_len;

	if (m_headlen(m) < sizeof(*ip))
		return FP_NF_EXCEPTION;

	if (ntohs(ip->ip_off) & FP_IP_OFFMASK)
		return FP_NF_ACCEPT;

	switch (ip->ip_p) {
	case FP_IPPROTO_TCP:
		if (fp_nf_check_size(m, ip, sizeof(struct fp_tcphdr)))
			return FP_NF_EXCEPTION;
		th = m_off(m, ip->ip_hl * 4, const struct fp_tcphdr *);
		optlen = th->th_off * 4;
		if (optlen < sizeof(struct fp_tcphdr))
			return FP_NF_EXCEPTION;
		else if (optlen != sizeof(struct fp_tcphdr)) {
			if (fp_nf_check_size(m, ip, optlen))
				return FP_NF_EXCEPTION;
		}
		if (l4parsing) {
			int ret = fp_mbuf_check_tcp(m,th, ip->ip_off & htons(FP_IP_MF));
			if (ret != FP_NF_ACCEPT)
				return ret;
		}
		break;

	case FP_IPPROTO_UDP:
		if (fp_nf_check_size(m, ip, sizeof(struct fp_udphdr)))
			return FP_NF_EXCEPTION;

		/*
		 * IP fragment will never match as UDP header correspond to the
		 * complete datagram.
		 */
		if (ip->ip_off & htons(FP_IP_MF))
			return FP_NF_ACCEPT;

		if (l4parsing) {
			int ret = fp_mbuf_check_udp(m);
			if (ret != FP_NF_ACCEPT)
				return ret;
		}
		break;

	case FP_IPPROTO_ICMP:
		icmp_dun_len = sizeof(((struct fp_icmphdr *)0)->icmp_dun);
		/* The icmp_dun is optional in ICMP header. */
		if (fp_nf_check_size(m, ip, sizeof(struct fp_icmphdr) - icmp_dun_len))
			return FP_NF_EXCEPTION;
		break;

	case FP_IPPROTO_SCTP:
		if (fp_nf_check_size(m, ip, sizeof(struct fp_sctphdr)))
			return FP_NF_EXCEPTION;
		/* check that sctp packet is valid */
		offset = ip->ip_hl * 4 + sizeof(struct fp_sctphdr);
		while (offset < m_len(m)) {
			FPN_TRACK();
			if (m_copytobuf(&sch, m, offset, sizeof(struct fp_sctpchunkhdr))
			    != sizeof(struct fp_sctpchunkhdr))
				return FP_NF_EXCEPTION;
			if (unlikely(ntohs(sch.chunk_length) < sizeof(struct fp_sctpchunkhdr)))
				return FP_NF_EXCEPTION;
			offset += (ntohs(sch.chunk_length) + 3) & ~3;
		}
		break;

	case FP_IPPROTO_GRE:
		if (fp_nf_check_size(m, ip, GRE_HEADER_LENGTH))
			return FP_NF_EXCEPTION;
		break;

	case FP_IPPROTO_ESP:
	case FP_IPPROTO_AH:
	default:
		break;
	}
	return FP_NF_ACCEPT;
}

int fp_nf_hook_iterate(struct mbuf *m, int hook, const int *table_list,
		       const fp_ifnet_t *indev, const fp_ifnet_t *outdev)
{
	int verdict, i;
	int check_done = 0;
	int ret;
#ifdef CONFIG_MCORE_NETFILTER_NAT
	int l4check_done = 0;
#endif

	for (i = 0; table_list[i] >= 0; i++) {
		FPN_TRACK();

#ifdef CONFIG_MCORE_NETFILTER_NAT
		/* In case of NAT, look for a conntrack in hash table */
		if (table_list[i] == FP_NF_TABLE_NAT) {
			if (l4check_done == 0) {
				ret = fp_nf_check_packet(m, (hook == FP_NF_IP_PRE_ROUTING));
				if (ret == FP_NF_DROP)
					return FP_NF_DROP;
				else if (ret == FP_NF_EXCEPTION)
					return FP_NF_EXCEPTION;
				l4check_done = 1;
				check_done = 1;
			}
			verdict = fp_nfct_nat_lookup(m, hook);
		}
		else
#endif
			verdict = FP_NF_ACCEPT;

		/* If table != NAT or if no conntrack was found */
		if (table_list[i] != FP_NF_TABLE_NAT || verdict == FP_NF_CONTINUE) {
#ifdef CONFIG_MCORE_NF_TABLE_PER_VR
			uint16_t nf_vr = m2vrfid(m);
#else
			uint16_t nf_vr = 0;
#endif
			/* skip the rule lookup in table if switch is not enabled */
			if ( (fp_shared->nf_conf.enabled_hook[nf_vr][hook] & (1ULL << table_list[i])) == 0)
				continue;

#ifdef CONFIG_MCORE_NETFILTER_CACHE
			if (likely(fp_shared->conf.w32.do_func & FP_CONF_DO_NF_CACHE)) {
				if (check_done == 0) {
					ret = fp_nf_check_packet(m, 0);
					if (ret == FP_NF_DROP)
						return FP_NF_DROP;
					else if (ret == FP_NF_EXCEPTION)
						return FP_NF_EXCEPTION;
					check_done = 1;
				}
				verdict = fp_nf_cache_input(m, hook, table_list[i], indev, outdev);

				/* the flow is in cache, skip normal processing */
				if (likely(verdict == FP_NF_ACCEPT))
					continue;
				if (likely(verdict != FP_NF_CONTINUE))
					return verdict;
			}
#endif
			if (check_done == 0) {
				ret = fp_nf_check_packet(m, 0);
				if (ret == FP_NF_DROP)
					return FP_NF_DROP;
				else if (ret == FP_NF_EXCEPTION)
					return FP_NF_EXCEPTION;
				check_done = 1;
			}
			verdict = fp_nf_table(m, table_list[i], hook, indev, outdev);
		}
		if (verdict != FP_NF_ACCEPT) {
			if (verdict != FP_NF_REPEAT)
				return verdict;
			else
				i--;
		}
	}

	return FP_NF_ACCEPT;
}

