/*
 * Copyright 2014 6WIND
 */

#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"
#include "fpn-cksum.h"
#include "fpn-queue.h"
#include "fpn-lock.h"
#include "fp-jhash.h"

/* XXX cancel fp-netgraph.h hack */
#undef saddr
#undef daddr

/* queue garbage collector period in seconds */
#define FP_REASSQ_GC_PERIOD 2

#define TRACE_REASS(level, fmt, args...) do {			\
		FP_LOG(level, REASS, fmt "\n", ## args);	\
} while(0)

struct fp_ipv4q {
	uint64_t       saddr:32;
	uint64_t       daddr:32;
};

struct fp_ipv6q {
	struct fp_in6_addr         saddr;
	struct fp_in6_addr         daddr;
};

/* IPv4/v6 fragment queue */
typedef struct fp_ipq {

	union {
		struct fp_ipv4q ip_addr;
		struct fp_ipv6q ip6_addr;
	} fp_q;

	uint32_t       id;
	uint16_t       vrfid;
	uint8_t        proto;
	/* IPQ_CREATE is used by fp_ip[46]q_get() functions */
	uint8_t        flags;
#define FIRST_RECVD   1
#define LAST_RECVD    2
#define REASSCOMPLETE 4
#define QUEUE_FULL    8
#define AT_OFFSET     16
#define IPQ_CREATE    128

	uint32_t       total_len;
	uint32_t       recvd_len;

	uint32_t       frag_count;
	uint32_t       hash;

	fpn_atomic_t        used;         /* ipq pool flag: entry is not free */
	fpn_atomic_t        refcount;     /* currently used by a core */
	fpn_spinlock_t      lock;         /* spinlock while entry is used */

	uint64_t start_cycles;            /* date when reassembly was started */
	uint64_t last_cycles;             /* date when last fragment was received */
	struct mbuf * frag_list;          /* fragment list */
	struct mbuf *at_offset;           /* used by *_at_offset() functions */

	FPN_TAILQ_ENTRY(fp_ipq) hchain; /* queue chaining field in hash table line */
	FPN_TAILQ_ENTRY(fp_ipq) tchain; /* queue chaining field in time-ordered table */
} fp_ipq_t;

/* list of queues */
typedef FPN_TAILQ_HEAD(fp_ipq_list, fp_ipq) fp_ipq_list_t;

static inline void fp_ipq_put(fp_ipq_t *ipq)
{
	/* decrement reference counter. if 0, free back to pool */
	if (fpn_atomic_dec_and_test(&ipq->refcount)) {
		TRACE_REASS(FP_LOG_DEBUG, "freeing ipq %p", ipq);
		fpn_atomic_clear(&ipq->used);
	}
}

static inline void fp_ipq_hold(fp_ipq_t *ipq)
{
	fpn_atomic_inc(&ipq->refcount);
}

static inline void fp_ipq_init(uint32_t hash, fp_ipq_t *ipq, uint16_t vrfid,
		uint32_t id, uint8_t proto, uint8_t flags)
{
	ipq->id    = id;
	ipq->proto = proto;
	ipq->flags = (flags & ~(IPQ_CREATE));
	ipq->vrfid = vrfid;
	ipq->total_len = 0;
	ipq->recvd_len = 0;
	ipq->frag_count = 0;
	ipq->start_cycles = fpn_get_clock_cycles();
	ipq->last_cycles = ipq->start_cycles;
	ipq->hash = hash;
	ipq->frag_list = NULL;
}

static inline void fp_reass_flush_ipq(fp_ipq_t *ipq)
{
	struct mbuf *m, *mnext;

	TRACE_REASS(FP_LOG_DEBUG, "%s(%p)", __FUNCTION__, ipq);

	for (m = ipq->frag_list; m; m = mnext) {
		FPN_TRACK();
		mnext = m_nextpkt(m);
		m_freem(m);
	}
	if (unlikely(ipq->at_offset != NULL)) {
		m_freem(ipq->at_offset);
		ipq->at_offset = NULL;
	}
	ipq->frag_count = 0;
	ipq->frag_list = NULL;
}

/* Extract first packet from list and send it in exception */
static inline void fp_reass_send_exception(fp_ipq_t *ipq, int proto)
{
	struct mbuf *m;
	int all;

	TRACE_REASS(FP_LOG_DEBUG, "%s(%p)", __FUNCTION__, ipq);
	m = ipq->frag_list;
	if (m == NULL)
		return;
	ipq->frag_list = m_nextpkt(m);
	m_set_nextpkt(m, NULL);
	ipq->frag_count--;

	/* If we don't have the first frag, send all frag list */
	all = (m_priv(m)->reass.start_offset != 0);

	if (fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC) == FP_NONE)
		fp_sp_exception(m);
	else {
		TRACE_REASS(FP_LOG_ERR, "%s: fp_ip_prepare_exception() failed, "
			    "packet (%p) dropped", __FUNCTION__, m);
		m_freem(m);
	}

	/* if need send all other fragments */
	if (all) {
		struct mbuf *mnext;

		for (m = ipq->frag_list; m; m = mnext) {
			mnext = m_nextpkt(m);
			if (fp_ip_prepare_exception(m, FPTUN_EXC_SP_FUNC) == FP_NONE)
				fp_sp_exception(m);
			else {
				TRACE_REASS(FP_LOG_ERR, "%s: fp_ip_prepare_exception() failed, "
					    "packet (%p) dropped", __FUNCTION__, m);
				m_freem(m);
			}
		}
		ipq->frag_count = 0;
		ipq->frag_list = NULL;
	}
}
