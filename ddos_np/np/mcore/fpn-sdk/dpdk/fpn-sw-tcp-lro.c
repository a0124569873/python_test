/*
 * Copyright(c) 2014 6WIND
 */

#include "fpn.h"

#include "fpn-eth.h"
#include "fpn-in.h"
#include "fpn-ip.h"
#include "fpn-tcp.h"

#include "fpn-sw-tcp-lro.h"

#define LRO_DEBUG(args...) do { } while(0)
/* #define LRO_DEBUG(args...) fpn_printf(args) */

/* structure describing a LRO context */
struct lro_ctx {
	struct {
		uint16_t sport;        /* TCP source port */
		uint16_t dport;        /* TCP destination port */
		uint32_t ip_src;       /* IP source */
		uint32_t ip_dst;       /* IP destination */
	} key;  /* identifies the flow */

	uint32_t hash;               /* hash of the key */
	struct mbuf *m;              /* pointer to the coalesced mbuf */
	struct fpn_ether_header *eh; /* pointer to the ether header */
	struct fpn_ip_hdr *ip;       /* pointer to the ip header */
	struct fpn_tcp_hdr *tcp;     /* pointer to the tcp header */
	uint32_t datalen;            /* length of data (after tcp) */
	uint32_t has_timestamp;
};

/* LRO coalescing statistics */
struct lro_percore_stats {
	uint64_t in;   /* number of packets enterring LRO */
	uint64_t out;  /* number of packets after LRO processing */
} __fpn_cache_aligned;
static struct lro_percore_stats lro_stats[FPN_MAX_CORES];

/* small per-core htable to store current LRO contexts */
#define LRO_HTABLE_ORDER 8
#define LRO_HTABLE_SIZE (1 << LRO_HTABLE_ORDER)
#define LRO_HTABLE_MASK (LRO_HTABLE_SIZE - 1)
struct lro_percore_htable {
	int8_t idx[LRO_HTABLE_SIZE]; /* MAX_PKT_BURST must be < 128 */
};
static struct lro_percore_htable lro_htable[FPN_MAX_CORES];

/* dump statistics related to software LRO */
void fpn_sw_lro_dump_stats(void)
{
	struct lro_percore_stats sum;
	uint64_t in, out;
	unsigned i;

	fpn_printf("Software LRO statistics:\n");
	memset(&sum, 0, sizeof(sum));
	for (i = 0; i < FPN_MAX_CORES; i++) {
		in = lro_stats[i].in;
		if (in == 0)
			continue;

		fpn_printf(" [%d] lro_in: %"PRIu64"\n", i, in);
		sum.in += in;

		out = lro_stats[i].out;
		fpn_printf(" [%d] lro_out: %"PRIu64"\n", i, out);
		sum.out += out;
	}

	fpn_printf(" [sum] lro_in: %"PRIu64"\n", sum.in);
	fpn_printf(" [sum] lro_out: %"PRIu64"\n", sum.out);
	fpn_printf(" [sum] lro: %"PRIu64"\n", sum.in - sum.out);

	for (i = 0; i < FPN_MAX_CORES; i++) {
		lro_stats[i].in = 0;
		lro_stats[i].out = 0;
	}
}

static inline uint32_t fpn_lro_hash(uint16_t sport, uint16_t dport,
	uint32_t ip_src, uint32_t ip_dst)
{
	uint32_t a, b, c;

	a = sport + (dport << 16);
	b = ip_dst;
	c = ip_src;

	a -= b; a -= c; a ^= (c>>13);
	b -= c; b -= a; b ^= (a<<8);
	c -= a; c -= b; c ^= (b>>13);
	a -= b; a -= c; a ^= (c>>12);
	b -= c; b -= a; b ^= (a<<16);
	c -= a; c -= b; c ^= (b>>5);
	a -= b; a -= c; a ^= (c>>3);
	b -= c; b -= a; b ^= (a<<10);
	c -= a; c -= b; c ^= (b>>15);

	return c & LRO_HTABLE_MASK;
}

/* Fill a temporary LRO context that matches the given packet m. On success,
 * return 0. If the packet cannot be LRO-ised, return -1. */
static int fill_lro_ctx(struct mbuf *m, struct lro_ctx *tmp_ctx)
{
	struct fpn_ether_header *eh;
	struct fpn_ip_hdr *ip;
	struct fpn_tcp_hdr *tcp;
	char *opts = NULL;

	/* too short, don't even try further */
	if (m_headlen(m) < sizeof(*eh) + sizeof(*ip) + sizeof(*tcp))
		return -1;

	eh = mtod(m, struct fpn_ether_header *);
	if (eh->ether_type != htons(FPN_ETHERTYPE_IP))
		return -1;
	ip = (struct fpn_ip_hdr *) (eh + 1);

	/* IPv4 + TCP without options, no frag */
	if (ip->ip_v != 4)
		return -1;
	if (ip->ip_hl != 5)
		return -1;
	if ((ip->ip_tos & 0x3) == 0x3) /* ECN */
		return -1;
	if (ntohs(ip->ip_off) & FPN_IP_OFFMASK)
		return -1;
	if (ip->ip_p != FPN_IPPROTO_TCP)
		return -1;
	if (ntohs(ip->ip_len) != m_len(m) - sizeof(*eh))
		return -1;

	tcp = (struct fpn_tcp_hdr *)(ip + 1);

	/* all flags except ACK or PSH set to 0 */
	if ((tcp->th_flags & (FPN_TH_FIN | FPN_TH_SYN | FPN_TH_RST |
				FPN_TH_URG | FPN_TH_ECE | FPN_TH_CWR)) != 0)
		return -1;

	/* no TCP options or only timestamp */
	if (tcp->th_off == 8) {
		if (m_headlen(m) < sizeof(*eh) + sizeof(*ip) + (8 << 2))
			return -1;
		opts = (char *)(tcp + 1);
		/* skip at most 2 no-op */
		if (opts[0] == FPN_TCPOPT_NOP) {
			opts++;
			if (opts[0] == FPN_TCPOPT_NOP)
				opts++;
		}
		/* only timestamp option is allowed */
		if (opts[0] != FPN_TCPOPT_TIMESTAMP || opts[1] != 0x0A)
			return -1;

		tmp_ctx->has_timestamp = 1;
	} else if (tcp->th_off == 5) {
		tmp_ctx->has_timestamp = 0;
	} else
		return -1;

	/* the packet is a candidate for coalescing, fill tmp context */
	tmp_ctx->key.sport = tcp->th_sport;
	tmp_ctx->key.dport = tcp->th_dport;
	tmp_ctx->key.ip_src = ip->ip_src;
	tmp_ctx->key.ip_dst = ip->ip_dst;
	tmp_ctx->hash = fpn_lro_hash(tcp->th_sport, tcp->th_dport,
		ip->ip_src, ip->ip_dst);
	tmp_ctx->m = m;
	tmp_ctx->eh = eh;
	tmp_ctx->ip = ip;
	tmp_ctx->tcp = tcp;
	tmp_ctx->datalen = ntohs(ip->ip_len) - sizeof(*ip) - (tcp->th_off << 2);

	return 0;
}

/* find an existing LRO context matching the new context */
static struct lro_ctx *find_matching_lro(struct lro_ctx *new_ctx,
	struct lro_ctx lro_tab[MAX_PKT_BURST], unsigned n_lro)
{
	int8_t idx;
	unsigned core_id = fpn_get_core_num();

	idx = lro_htable[core_id].idx[new_ctx->hash];
	if (idx < 0 || idx >= (int)n_lro)
		return NULL;

	if (memcmp(&new_ctx->key, &lro_tab[idx].key, sizeof(new_ctx->key)))
		return NULL;

	return &lro_tab[idx];
}

static inline uint16_t cksum_sub(uint16_t c1, uint16_t c2)
{
	if (c1 >= c2)
		return c1 - c2;
	else
		return c1 - c2 - 1;
}

/* calculate the checksum of the TCP packet without its data */
static uint16_t tcp_cksum_no_data(const struct mbuf *m, unsigned ih_off)
{
	const struct fpn_ip_hdr *ih;
	const struct fpn_tcp_hdr *th;
	fpn_cksum32_t cksum;
	uint32_t l3_len;
	uint32_t l4_len;

	ih = m_off(m, ih_off, struct fpn_ip_hdr *);
	l3_len = ih->ip_hl << 2;
	cksum.v32 = fpn_ip_phdr_cksum32(ih);

	th = (const struct fpn_tcp_hdr *)((const char *)ih + l3_len);
	l4_len = th->th_off << 2; /* only tcp hdr + options */
	cksum.v32 += fpn_raw_cksum(m, ih_off + l3_len, l4_len);

	FPN_CKSUM32_REDUCE_AND_COMPLEMENT(cksum);
	return (uint16_t) (cksum.v32);
}


/* Update checksum in th1, assuming that all data from th2 (excluding
 * all headers) will be appended to the first packet. */
static void fix_l4cksum(struct fpn_tcp_hdr *th1, struct fpn_tcp_hdr *th2,
	struct mbuf *m2)
{
	uint16_t th2_l4hdr_sum, th2_l4_sum, th1_l4_sum, data2_cksum;
	uint32_t tmp32;

	/* save th2 sum and set it to 0 in the packet */
	th2_l4_sum = th2->th_sum;
	th2->th_sum = 0;

	/* calculate the checksum of TCP + IP_phdr, excluding data */
	th2_l4hdr_sum = tcp_cksum_no_data(m2, 14);
	LRO_DEBUG("th2_l4hdr_sum %x\n", ntohs(th2_l4hdr_sum));

	/* substract the 2 checksums to get the checksum of packet2 data */
	data2_cksum = cksum_sub(~th2_l4_sum, ~th2_l4hdr_sum);
	LRO_DEBUG("data cksum %x\n", ntohs(~data2_cksum));

	/* read previous l4 cksum in packet 1 */
	th1_l4_sum = th1->th_sum;
	LRO_DEBUG("old th1_sum %x (after modifying iplen)\n", ntohs(th1_l4_sum));

	/* the new l4 checksum for packet 1 is cksum(previous) + cksum(data2) */
	tmp32 = (uint32_t)(~th1_l4_sum & 0xffff) + (uint32_t)data2_cksum;
	th1_l4_sum = (tmp32 & 0xffff) + ((tmp32 >> 16) & 0xffff); /* reduce */
	th1->th_sum = ~th1_l4_sum;
	LRO_DEBUG("new th1_sum cksum %x\n", ntohs(th1->th_sum));
}

static int lro_reass(struct lro_ctx *tmp_ctx, struct lro_ctx *lro_ctx,
	unsigned lro_pktlen)
{
	uint8_t new_th_flags;

	/* ACK must be 1 or the same as in lro_ctx */
	if ((tmp_ctx->tcp->th_flags & FPN_TH_ACK) == 0 &&
		(lro_ctx->tcp->th_flags & FPN_TH_ACK) == 1)
		return -1;

	if ((tmp_ctx->ip->ip_tos & 0x3) != (lro_ctx->ip->ip_tos & 0x3))
		return -1;

	if (tmp_ctx->has_timestamp != lro_ctx->has_timestamp)
		return -1;

	/* packet carries payload */
	if (tmp_ctx->datalen != 0) {
		uint16_t new_ip_len;

		if (lro_ctx->datalen == 0)
			return -1;
		/* check expected seq number */
		if (ntohl(tmp_ctx->tcp->th_seq) != ntohl(lro_ctx->tcp->th_seq) +
			lro_ctx->datalen)
			return -1;
		if (m_len(lro_ctx->m) + tmp_ctx->datalen > lro_pktlen)
			return -1;

		/* update ip_len */
		new_ip_len = htons(ntohs(lro_ctx->ip->ip_len) + tmp_ctx->datalen);
		lro_ctx->ip->ip_sum = fpn_cksum_replace2(lro_ctx->ip->ip_sum,
			lro_ctx->ip->ip_len, new_ip_len, 0);
		lro_ctx->tcp->th_sum = fpn_cksum_replace2(lro_ctx->tcp->th_sum,
			lro_ctx->ip->ip_len, new_ip_len, 0);
		lro_ctx->ip->ip_len = htons(ntohs(lro_ctx->ip->ip_len) +
			tmp_ctx->datalen);

		lro_ctx->datalen += tmp_ctx->datalen;

		fix_l4cksum(lro_ctx->tcp, tmp_ctx->tcp, tmp_ctx->m);

		LRO_DEBUG("remove %d bytes\n", m_len(tmp_ctx->m) - tmp_ctx->datalen);
		m_adj(tmp_ctx->m, m_len(tmp_ctx->m) - tmp_ctx->datalen);
		m_cat(lro_ctx->m, tmp_ctx->m);
		LRO_DEBUG("new len %d\n", m_len(lro_ctx->m));

	} else {
		int32_t diff;

		/* ack only */
		if (lro_ctx->datalen != 0)
			return -1;
		/* ack value must be strictly greater */
		diff = ntohl(tmp_ctx->tcp->th_ack) - ntohl(lro_ctx->tcp->th_ack);
		if (diff <= 0)
			return -1;

		/* update ACK sequence value */
		lro_ctx->tcp->th_sum = fpn_cksum_replace4(lro_ctx->tcp->th_sum,
			lro_ctx->tcp->th_ack, tmp_ctx->tcp->th_ack, 0);
		lro_ctx->tcp->th_ack = tmp_ctx->tcp->th_ack;

		m_freem(tmp_ctx->m);
	}

	/* set ack and push bit */
	new_th_flags = lro_ctx->tcp->th_flags | tmp_ctx->tcp->th_flags;
	lro_ctx->tcp->th_sum = fpn_cksum_replace(lro_ctx->tcp->th_sum,
		lro_ctx->tcp->th_flags, new_th_flags, 1);
	lro_ctx->tcp->th_flags = new_th_flags;

	return 0;
}

/* Try to coalesce TCP packets. 'm_tab' is a table of mbuf and 'n'
 * points to the length of this table. The function modifies the mbufs
 * in 'm_tab' and the value pointed by 'n'. When the function returns,
 * the length of the table is lower or equal to its original value. */
void fpn_sw_lro_reass(struct mbuf **m_tab, unsigned *n, unsigned lro_pktlen)
{
	struct lro_ctx lro_ctx_tab[MAX_PKT_BURST];
	struct lro_ctx *lro_ctx, *new_ctx;
	struct mbuf *m;
	unsigned n_lro = 0; /* number of lro contexts */
	unsigned n_out = 0; /* new number of packets */
	unsigned i;
	unsigned core_id = fpn_get_core_num();

	/* the hash table stores indexes on int8_t */
	FPN_BUILD_BUG_ON(MAX_PKT_BURST >= 128);

	lro_stats[core_id].in += *n;

	/* browse all packets, try to reass */
	for (i = 0; i < *n; i++) {
		m = m_tab[i];
		new_ctx = &lro_ctx_tab[n_lro];

		/* return 0 if the packet is a lro candidate, in this case, fill
		 * a temporary LRO context, else skip to next packet */
		if (fill_lro_ctx(m, new_ctx) != 0) {
			m_tab[n_out] = m;
			n_out++;
			continue;
		}

		/* find a previous matching LRO context  */
		lro_ctx = find_matching_lro(new_ctx, lro_ctx_tab, n_lro);
		if (lro_ctx == NULL) {
			/* no matching context, skip to next packet */

			/* validate new LRO context */
			lro_htable[core_id].idx[new_ctx->hash] = n_lro;
			n_lro++;

			m_tab[n_out] = m;
			n_out++;
			continue;
		}

		/* try to coalesce this packet in an existing LRO ctx */
		if (lro_reass(new_ctx, lro_ctx, lro_pktlen) < 0) {
			/* cannot reassemble, skip to next packet */

			/* validate new LRO context */
			lro_htable[core_id].idx[new_ctx->hash] = n_lro;
			n_lro++;

			m_tab[n_out] = m;
			n_out++;
			continue;
		}

		/* packet is merged in a lro context, don't increment n_out */
	}

	/* clean htable */
	for (i = 0; i < n_lro; i++) {
		lro_htable[core_id].idx[lro_ctx_tab[i].hash] = -1;
	}

	/* update new number of packets in table */
	*n = n_out;
	lro_stats[core_id].out += *n;
}

/* init software LRO module */
void fpn_sw_lro_init(void)
{
	int core_id, i;

	for (core_id = 0; core_id < FPN_MAX_CORES; core_id++) {
		for (i = 0; i < LRO_HTABLE_SIZE; i++) {
			lro_htable[core_id].idx[i] = -1;
		}
	}
}
