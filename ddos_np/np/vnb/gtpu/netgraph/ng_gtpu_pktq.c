/*
 * Copyright 2011-2013 6WIND S.A.
 */

#ifndef __FastPath__
#error "GTP-U packet queuing is only supported in the fast path"
#endif

#include "fp-netgraph.h"
#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_gtpu.h>
#include <netgraph/ng_gtpu_pktq.h>

/* compile-time flag for displaying debug messages in gtpu_pktq */
// #define GTPU_PKTQ_LOG_DBG
#ifdef GTPU_PKTQ_LOG_DBG
#define QUEUE_DBG(x, y...) do { \
		log(LOG_ERR, "DBG %s:%d  " x "\n", __FUNCTION__, __LINE__, ## y);\
	} while(0)
#else
#define QUEUE_DBG(x, y...) do {} while(0)
#endif

/* compile-time flag for displaying logs for errors in gtpu_pktq */
#define GTPU_PKTQ_LOG_ERR
#ifdef GTPU_PKTQ_LOG_ERR
#define QUEUE_ERR(x, y...) do { \
		log(LOG_ERR, "ERR %s:%d  " x "\n", __FUNCTION__, __LINE__, ## y);\
	} while(0)
#else
#define QUEUE_ERR(x, y...) do {} while(0)
#endif

/* max Tx burst length */
#define GTPU_PKTQ_MAX_TX_BURST	10
/* enable code for the packet queue drain */
#define GTPU_PACKET_QUEUES_DRAIN

/* commands for gtpu_pktq_get() */
enum {
	GTPU_PKTQ_SEARCH = 0,
	GTPU_PKTQ_CREATE,
};

static FPN_DEFINE_SHARED(int, lock_pktq_init_done) = 0;
static FPN_DEFINE_SHARED(fpn_atomic_t, pktq_init);
static FPN_DEFINE_SHARED(fpn_atomic_t, pktq_exit);

#ifdef GTPU_PKTQ_STATS
/* errors for the pkq module */
static struct gtpu_pktq_stats pktq_err_stat;
#endif

#if (defined GTPU_PACKET_QUEUES_DRAIN)
static void gtpu_pktq_gc_timer(void *arg);
static void gtpu_pktq_drain(gtpu_pktq_cfg_t *cfg);
#endif
static int gtpu_pktq_create_all(gtpu_pktq_cfg_t *cfg);
static void gtpu_pktq_cleanup(gtpu_pktq_cfg_t *cfg);
static void gtpu_pktq_free_queues(gtpu_pktq_cfg_t *cfg);

/*
 * the function will allocate all needed structs :
 * the queue pool and each packet queue
 */
static int
gtpu_pktq_create_all(gtpu_pktq_cfg_t *cfg)
{
	unsigned int i;
	gtpu_pktq_t *ipq;

	/* init timestamped buffer list (empty) */
	TAILQ_INIT(&cfg->pktq_tlist);

	/* create pool of queues */
	cfg->pktq_pool = ng_malloc(sizeof(gtpu_pktq_t) *
	                           cfg->num_of_queues,
	                           M_NOWAIT | M_ZERO);
	if (unlikely(!cfg->pktq_pool)) {
		QUEUE_ERR("pktq pool ng_malloc failed");
#ifdef GTPU_PKTQ_STATS
		cfg->error_stat.malloc ++;
#endif
		return -1;
	}

	/* create each queue */
	for (i = 0; i < cfg->num_of_queues; i++) {
		ipq = &cfg->pktq_pool[i];
		ipq->pkt_ptr_array = ng_malloc(cfg->pkts_per_queue *
		                               sizeof(pkt_ptr_t),
		                               M_NOWAIT | M_ZERO);
		if (unlikely(!ipq->pkt_ptr_array)) {
			QUEUE_ERR("pktq[%d] alloc failed", i);
#ifdef GTPU_PKTQ_STATS
			cfg->error_stat.malloc ++;
#endif
			gtpu_pktq_free_queues(cfg);
			return -1;
		}
	}

	QUEUE_DBG("packet queues are created successfully");
	return 0;
}

/*
 * free packets in the queue and clear used flag and return it to pool
 */
static int
gtpu_pktq_flush_que(gtpu_pktq_cfg_t *cfg, gtpu_pktq_t *ipq, int force)
{
	unsigned int i, index;

	if (unlikely(!ipq)) {
		QUEUE_ERR("NULL ipq");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		return -1;
	}
	QUEUE_DBG("flush pktq=%p", ipq);

	/* free packets in the queue and return it to pool */
	vnb_spinlock_lock(&ipq->lock);
	if (!force && (ipq->pkt_count != 0)) {
		QUEUE_DBG("Not flushing pktq=%p", ipq);
		vnb_spinlock_unlock(&ipq->lock);
		return 1;
	}
	index = ipq->first_idx;
	for (i = 0; i < ipq->pkt_count; i++) {
		if ( likely(ipq->pkt_ptr_array[index].mbuf != NULL) ) {
			NG_FREE_DATA(ipq->pkt_ptr_array[index].mbuf,
						 ipq->pkt_ptr_array[index].meta);
		}
		if ((index + 1) >= cfg->pkts_per_queue)
			index = 0;
		else
			index ++;
		ipq->first_idx = index;
	}
#ifdef GTPU_PKTQ_STATS
	ipq->stat.drop_pkts += ipq->pkt_count;
#endif
	ipq->pkt_count = 0;
	memset(ipq->pkt_ptr_array, 0, cfg->pkts_per_queue*sizeof(pkt_ptr_t));
	ipq->flags |= QUE_COMPLETE;
	fpn_atomic_clear(&ipq->used);
	vnb_spinlock_unlock(&ipq->lock);

	/* unlink from pktq_tlist */
	TAILQ_REMOVE(&cfg->pktq_tlist, ipq, tchain);

	QUEUE_DBG("done with pktq=%p", ipq);
	return 0;
}

/*
 * the function will free each packet queue struct and queue pool
 */
static void
gtpu_pktq_free_queues(gtpu_pktq_cfg_t *cfg)
{
	unsigned int i;
	gtpu_pktq_t *ipq;

	if (likely( cfg->pktq_pool != NULL )) {
		/* first free each packet queue, then free the queue pool */

		for (i = 0; i < cfg->num_of_queues; i++) {
			ipq = &cfg->pktq_pool[i];
			if (likely( ipq->pkt_ptr_array != NULL )) {
				ng_free(ipq->pkt_ptr_array);
				ipq->pkt_ptr_array = NULL;
			}
		}

		ng_free(cfg->pktq_pool);
		cfg->pktq_pool = NULL;
		QUEUE_DBG("free all packet queues");
	}
}

/*
 * remove garbage collector timer and free all packets, queues, pool
 */
static void
gtpu_pktq_cleanup(gtpu_pktq_cfg_t *cfg)
{
	gtpu_pktq_t *ipq;
	unsigned i, num;

#if (defined GTPU_PACKET_QUEUES_DRAIN)
	ng_callout_stop_sync(&cfg->pktq_gc_callout);
#endif

	vnb_spinlock_lock(&cfg->pktq_list_lock);
	for (i = 0, num = cfg->num_of_queues; i < num; i++) {

		ipq = TAILQ_FIRST(&cfg->pktq_tlist);
		if (likely( ipq != NULL )) {

			/* another core may finish the cleanup */
			if (likely(!(ipq->flags & QUE_COMPLETE))) {
				/* forced free all packets in a packet queue */
				gtpu_pktq_flush_que(cfg, ipq, 1);
			}
		}
	}

	/* free packet queue pool */
	gtpu_pktq_free_queues(cfg);
	vnb_spinlock_unlock(&cfg->pktq_list_lock);
}

#if (defined GTPU_PACKET_QUEUES_DRAIN)
/*
 * the garbage collector callback function which will drop packets in timeout queues
 * walk the pktq_tlist in the order of queue creation and free the oldest queues
 */
static void
gtpu_pktq_drain(gtpu_pktq_cfg_t *cfg)
{
	gtpu_pktq_t *ipq;
	uint64_t cur_cycles;
	unsigned i, num;

	vnb_spinlock_lock(&cfg->pktq_list_lock);
	for (i = 0, num = cfg->num_of_queues; i < num; i++) {

		if (unlikely(TAILQ_EMPTY(&cfg->pktq_tlist)))
			break;

		ipq = TAILQ_FIRST(&cfg->pktq_tlist);
		cur_cycles = fpn_get_clock_cycles();
		if ((cur_cycles - ipq->start_cycles) > cfg->queue_delay_cycles) {
			if (!(ipq->flags & QUE_COMPLETE)) {
				QUEUE_ERR("queue=%p, timeout delay: %"PRId64" count: %d", ipq,
					  (cur_cycles - ipq->start_cycles), ipq->pkt_count);
				/* forced free packets in the queue and return the queue into pool */
				gtpu_pktq_flush_que(cfg, ipq, 1);
			}
		} else
			break;
	}
	vnb_spinlock_unlock(&cfg->pktq_list_lock);
}

/*
 * garbage collector recycle function which will set next timer
 */
static void
gtpu_pktq_gc_timer(void *arg)
{
	gtpu_pktq_cfg_t *cfg = arg;

	if (cfg->pktq_running) {
		gtpu_pktq_drain(cfg);
		/* reschedule the drain function */
		ng_callout_reset(&cfg->pktq_gc_callout, cfg->gc_delay,
					  gtpu_pktq_gc_timer, cfg);
	}
}
#endif

/*
 * find an unused queue in the packet queue pool
 */
static gtpu_pktq_t *
gtpu_pktq_alloc_que(gtpu_pktq_cfg_t *cfg, int *pktq_idx)
{
	unsigned int i, nb_alloc_queues = 0;
	gtpu_pktq_t *ipq;

	if (unlikely(!cfg->pktq_pool)) {
		QUEUE_ERR("packet pool is NULL");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		return NULL;
	}

	for (i = 0; i < cfg->num_of_queues; i++) {
		ipq = &cfg->pktq_pool[i];
		if ( likely(fpn_atomic_test_and_set(&ipq->used)) ) {
			/* return a unused queue in the pool */
			*pktq_idx = i;
			ipq->flags &= ~QUE_COMPLETE;
			QUEUE_DBG("queue[%d/%d] used=%d",
					  i, cfg->num_of_queues, fpn_atomic_read(&ipq->used));
			QUEUE_DBG("cfg->pktq_pool[%d] is allocated, "
					  "cfg->pkts_per_queue=%d, flags=0x%x",
					  i, cfg->pkts_per_queue, ipq->flags);
			return ipq;
		} else
			nb_alloc_queues++;
	}

	*pktq_idx = -1;
	QUEUE_ERR("no free packet queue : nb_alloc_queues %d / %d",
			  nb_alloc_queues, cfg->num_of_queues);
#ifdef GTPU_PKTQ_STATS
	cfg->error_stat.no_free_que ++;
#endif
	return NULL;
}

/*
 * init a new queue after it is created from pool
 */
static inline void
gtpu_pktq_que_init(gtpu_pktq_cfg_t *cfg, gtpu_pktq_t *ipq, void *hpriv)
{
	if (unlikely(!ipq || !hpriv)) {
		QUEUE_ERR("NULL ipq or hpriv");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		return;
	}

	vnb_spinlock_init(&ipq->lock);
#ifdef GTPU_PKTQ_STATS
	memset(&ipq->stat, 0, sizeof(ipq->stat));
#endif
	ipq->flags = 0;

	ipq->start_cycles = fpn_get_clock_cycles();
	ipq->first_cycles = ipq->last_cycles = ipq->start_cycles;
	ipq->first_idx = 0;
	ipq->pkt_count = 0;
	ipq->callback_arg = hpriv;
	TAILQ_INSERT_TAIL(&cfg->pktq_tlist, ipq, tchain);
}

/*
 * this function will check if given queue index in pool is valid
 */
static inline
gtpu_pktq_t *gtpu_pktq_lookup(gtpu_pktq_cfg_t *cfg, void *hpriv, int pktq_idx)
{
	gtpu_pktq_t *ipq;

	if (likely((pktq_idx >= 0) && ((unsigned int)pktq_idx < cfg->num_of_queues))) {
		ipq = &cfg->pktq_pool[pktq_idx];
		/* check that the queue was used by the current PDP tunnel */
		if (ipq->callback_arg == hpriv && fpn_atomic_read(&ipq->used)) {
			return ipq;
		}
		/* message when a packet queue was drained while still used in ng_gtpu */
		QUEUE_DBG("bad pktq_pool[%d]", pktq_idx);
	}
	return NULL;
}

/*
 * this function works in two mode depending on flags (lookup or create)
 * when the flags hasn't been set : lookup if such a queue exists
 * when create flags has been set : create a queue with the input params
 */
static gtpu_pktq_t *
gtpu_pktq_get(gtpu_pktq_cfg_t *cfg, int command,
			  void *hpriv, int *pktq_idx)
{
	gtpu_pktq_t *ipq = NULL;

	vnb_spinlock_lock(&cfg->pktq_list_lock);
	if ( likely((*pktq_idx >= 0) && ((unsigned int)*pktq_idx < cfg->num_of_queues)) ) {
		/* quick check on the presence of the packet queue */
		ipq = gtpu_pktq_lookup(cfg, hpriv, *pktq_idx);
	}

	if ( unlikely((ipq == NULL) && (command == GTPU_PKTQ_CREATE)) ) {
		/* do the alloc. */
		ipq = gtpu_pktq_alloc_que(cfg, pktq_idx);
		if ( likely( ipq != NULL ) ) {
			gtpu_pktq_que_init(cfg, ipq, hpriv);
			QUEUE_DBG("creating queue entry %p for %d", ipq, *pktq_idx);
		} else {
			QUEUE_ERR("cannot allocate queue entry");
		}
	}
	vnb_spinlock_unlock(&cfg->pktq_list_lock);

	QUEUE_DBG("return entry %p", ipq);
	return ipq;
}

/*
 * add a packet into the queue. if the queue is full replace the oldest packet
 */
static inline void
gtpu_pktq_add(gtpu_pktq_cfg_t *cfg, gtpu_pktq_t *ipq,
			  struct mbuf *pkt, meta_p meta)
{
	uint32_t last_idx, index;

	ipq->last_cycles = fpn_get_clock_cycles();
#ifdef GTPU_PKTQ_STATS
	ipq->stat.store_pkts ++;
#endif
	if ( unlikely(ipq->pkt_count >= cfg->pkts_per_queue) ) {
		/* the packet queue is full, so replace the oldest with the new packet */
#ifdef GTPU_PKTQ_STATS
		ipq->stat.drop_pkts ++;
#endif
		last_idx = ipq->first_idx;
		if (ipq->pkt_ptr_array[last_idx].mbuf)
			NG_FREE_DATA(ipq->pkt_ptr_array[last_idx].mbuf,
						 ipq->pkt_ptr_array[last_idx].meta);
		ipq->pkt_ptr_array[last_idx].mbuf = pkt;
		ipq->pkt_ptr_array[last_idx].meta = meta;
		ipq->pkt_ptr_array[last_idx].cycles = ipq->last_cycles;

		if ((ipq->first_idx + 1) >= cfg->pkts_per_queue)
			ipq->first_idx = 0;
		else
			ipq->first_idx ++;

		ipq->first_cycles = ipq->pkt_ptr_array[ipq->first_idx].cycles;
		QUEUE_DBG("replace oldest packet, first_pkt=%d,"
				  "max=%d, new-pkt=%p, new-meta=%p",
				  ipq->first_idx, ipq->pkt_count, pkt, meta);
	} else {
		index = ipq->first_idx + ipq->pkt_count;
		if (index >= cfg->pkts_per_queue)
			index -= cfg->pkts_per_queue;
		ipq->pkt_ptr_array[index].mbuf = pkt;
		ipq->pkt_ptr_array[index].meta = meta;
		ipq->pkt_ptr_array[index].cycles = ipq->last_cycles;
		ipq->pkt_count ++;
		QUEUE_DBG("pktq->pkt_count=%d, pkt=%p, meta=%p",
				  ipq->pkt_count, pkt, meta);
	}

	/* Refill hardware if the packet is kept */
	m_freeback(pkt);
}

/*
 * add a packet into a queue.
 * create the queue if it doesn't exist
 */
int
gtpu_pktq_add_pkt(gtpu_pktq_cfg_t *cfg, struct mbuf *pkt, meta_p meta,
				  void *hpriv, int *pktq_idx)
{
	gtpu_pktq_t *ipq;

	if (unlikely(!cfg || !hpriv)) {
		QUEUE_ERR("cfg or hpriv is NULL");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		return -1;
	}
	if (unlikely(!cfg->pktq_running)) {
		QUEUE_ERR("adding a packet to a not running queue");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		return -1;
	}
	if (unlikely(!pktq_idx)) {
		QUEUE_ERR("packet queue index is NULL");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		return -1;
	}
	if (unlikely(!pkt)) {
		QUEUE_ERR("packet is NULL");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		return -1;
	}

	ipq = gtpu_pktq_get(cfg, GTPU_PKTQ_CREATE, hpriv, pktq_idx);
	QUEUE_DBG("queue=%p, pktq_idx=%d", ipq, *pktq_idx);
	if (likely( ipq != NULL )) {
		vnb_spinlock_lock(&ipq->lock);
		gtpu_pktq_add(cfg, ipq, pkt, meta);
		vnb_spinlock_unlock(&ipq->lock);
	} else {
		QUEUE_ERR("no packet queue");
		return -1;
	}

	return 0;
}

/*
 * init function which will create queue pool and struct for each queue
 * create a garbage collector timer which will drop packets in queues
 */
int
gtpu_pktq_init(gtpu_pktq_cfg_t *cfg)
{
	int res = 0;

	if (lock_pktq_init_done == 0) {
		fpn_atomic_clear(&pktq_init);
		fpn_atomic_clear(&pktq_exit);
		lock_pktq_init_done = 1;
	}

	if (unlikely(!fpn_atomic_test_and_set(&pktq_init))) {
		/* another core was doing the init or the init has been done */
		QUEUE_ERR("atomic has been set");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		return 0;
	}
	if (unlikely(!cfg)) {
		QUEUE_ERR("pktq NULL cfg");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		goto fail;
	}

	if (unlikely(!cfg->num_of_queues ||
		!cfg->queue_delay_ms ||
		!cfg->pkts_per_queue ||
		!cfg->gc_delay)) {
		QUEUE_ERR("pktq configure error: missing parameters");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		goto fail;
	}
	if (unlikely(cfg->num_of_queues & (cfg->num_of_queues-1))) {
		QUEUE_ERR("error: pktq configure num_of_queues is not power of two");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		goto fail;
	}

	/* configure timeouts */
	cfg->cycles_per_ms = fpn_div64_32(fpn_get_clock_hz(), 1000UL);
	if (unlikely(!cfg->cycles_per_ms)) {
		QUEUE_ERR("failed cycles_per_ms = 0");
#ifdef GTPU_PKTQ_STATS
		cfg->error_stat.general ++;
#endif
		goto fail;
	}
	cfg->queue_delay_cycles = (uint64_t)cfg->queue_delay_ms*(uint64_t)cfg->cycles_per_ms;

	QUEUE_DBG("num_of_queues=%u, queue_delay_ms=%"PRIu64", pkts_per_queue=%u, gc_delay=%u",
			  cfg->num_of_queues, cfg->queue_delay_ms,
			  cfg->pkts_per_queue, cfg->gc_delay);

	vnb_spinlock_init(&cfg->pktq_list_lock);
	res = gtpu_pktq_create_all(cfg);

	if (likely(!res)) {
		/* configure and start queues garbage collector */
#if (defined GTPU_PACKET_QUEUES_DRAIN)
		ng_callout_init(&cfg->pktq_gc_callout);
		ng_callout_reset(&cfg->pktq_gc_callout, cfg->gc_delay, gtpu_pktq_gc_timer, cfg);
#endif
		cfg->pktq_running = 1;
	}

	fpn_atomic_clear(&pktq_init);
	return res;

fail:
	fpn_atomic_clear(&pktq_init);
	return -1;
}

/*
 * the exit function which will free each packet queue struct and queue pool
 * remove garbage collector timer
 */
void
gtpu_pktq_exit(gtpu_pktq_cfg_t *cfg)
{
	if (unlikely(!cfg)) {
		QUEUE_ERR("cfg is NULL");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		fpn_atomic_clear(&pktq_exit);
		return;
	}

	if (unlikely(!fpn_atomic_test_and_set(&pktq_exit))) {
		QUEUE_ERR("exit atomic has been set");
#ifdef GTPU_PKTQ_STATS
		cfg->error_stat.general ++;
#endif
		return; /* exit has been done */
	}

	QUEUE_DBG("packet queue exit");
	cfg->pktq_running = 0;
	gtpu_pktq_cleanup(cfg);
	fpn_atomic_clear(&pktq_exit);
}

/*
 * send all packets buffered in the packet queue out to their destination
 */
int
gtpu_pktq_send_pkts(gtpu_pktq_cfg_t *cfg, void *hpriv, int *pktq_idx)
{
	gtpu_pktq_t *ipq = NULL;
	unsigned int i, pktq_count, res = 0;
	struct mbuf *m = NULL;
	meta_p meta;
	uint32_t index;

	if (unlikely(!cfg ||
		!cfg->pktq_running ||
		!cfg->num_of_queues)) {
		QUEUE_ERR("bad cfg");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		return -1;
	}
	if (unlikely(!pktq_idx ||
		(*pktq_idx == -1)||
		 !hpriv)) {
		QUEUE_ERR("meaningless pktq_idx or hpriv");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		return -1;
	}

	ipq = gtpu_pktq_get(cfg, GTPU_PKTQ_SEARCH, hpriv, pktq_idx);
	if (unlikely(!ipq)) {
		QUEUE_ERR("can't find pktq idx=%d", *pktq_idx);
		*pktq_idx = -1;
#ifdef GTPU_PKTQ_STATS
		cfg->error_stat.que_mismatch ++;
#endif
		return -1;
	}
	QUEUE_DBG("queue=%p, pktq_idx=%d count=%d first=%d",
			  ipq, *pktq_idx, ipq->pkt_count, ipq->first_idx);

	vnb_spinlock_lock(&ipq->lock);
	pktq_count = ipq->pkt_count; /* initial value */
	if (pktq_count > GTPU_PKTQ_MAX_TX_BURST)
		pktq_count = GTPU_PKTQ_MAX_TX_BURST;
	index = ipq->first_idx;

	/* send some packets in the packet queue out */
	for (i = 0; i < pktq_count; i ++ ) {

		m = ipq->pkt_ptr_array[index].mbuf;
		meta = ipq->pkt_ptr_array[index].meta;
		if (unlikely(!m)) {
			QUEUE_ERR("mbuf is NULL for count %d", ipq->pkt_count);
#ifdef GTPU_PKTQ_STATS
			cfg->error_stat.mbuf ++;
#endif
		} else {
			res = (*cfg->inter_pktq_cb)(ipq->callback_arg, m, meta);
			if (res) {
				QUEUE_ERR("callback function return error=%d", res);
#ifdef GTPU_PKTQ_STATS
				cfg->error_stat.send_fail ++;
#endif
			}
		}
		ipq->pkt_count --;
		ipq->pkt_ptr_array[index].mbuf = NULL;
		ipq->pkt_ptr_array[index].meta = NULL;
		ipq->pkt_ptr_array[index].cycles = 0;
		if ((index + 1) >= cfg->pkts_per_queue)
			index = 0;
		else
			index ++;
		ipq->first_idx = index;
	}
	ipq->first_cycles = ipq->pkt_ptr_array[ipq->first_idx].cycles;
#ifdef GTPU_PKTQ_STATS
	ipq->stat.tran_pkts += pktq_count;
#endif

	vnb_spinlock_unlock(&ipq->lock);
	QUEUE_DBG("queue=%p, flags=0x%x", ipq, ipq->flags);
	if (!(ipq->flags & QUE_COMPLETE)) {
		/* maybe return the queue into pool */
		vnb_spinlock_lock(&cfg->pktq_list_lock);
		res = gtpu_pktq_flush_que(cfg, ipq, 0);
		vnb_spinlock_unlock(&cfg->pktq_list_lock);
		if (!res) /* successfully flushed the queue */
			*pktq_idx = -1;
	}

	return 0;
}

/*
 * get the timestamp of last and first packets in a packet queue
 */
int
gtpu_pktq_get_timestamp(gtpu_pktq_cfg_t *cfg, void *hpriv,
						int pktq_idx, gtpu_que_tm_t *tm)
{
	gtpu_pktq_t *ipq;
	uint64_t my_start_cycles;
	uint64_t my_first_cycles;
	uint64_t my_last_cycles;
	uint32_t my_pkt_count;

	if (unlikely(pktq_idx == -1)) {
		return -1;
	}

	if (unlikely(!hpriv || !cfg || !tm ||
		!cfg->pktq_running ||
		!cfg->num_of_queues)) {
		QUEUE_ERR("bad hpriv or cfg");
#ifdef GTPU_PKTQ_STATS
		pktq_err_stat.invalid ++;
#endif
		return -1;
	}

	memset(tm, 0, sizeof(*tm));
	ipq = gtpu_pktq_get(cfg, GTPU_PKTQ_SEARCH, hpriv, &pktq_idx);
	if ( likely( ipq != NULL ) ) {
		QUEUE_DBG("queue=%p", ipq);

		/* sample queue-related counters */
		my_start_cycles = ipq->start_cycles;
		my_first_cycles = ipq->first_cycles;
		my_last_cycles  = ipq->last_cycles;
		my_pkt_count    = ipq->pkt_count;

		/* then prepare expected output results */
		tm->start_pkt = fpn_div64_32(my_start_cycles,
									 cfg->cycles_per_ms);
		tm->first_pkt = fpn_div64_32(my_first_cycles,
									 cfg->cycles_per_ms);
		tm->last_pkt = fpn_div64_32(my_last_cycles,
									cfg->cycles_per_ms);
		tm->pkt_count = my_pkt_count;

		return 0;
	} else {
		QUEUE_ERR("can't find packet queue index=%d", pktq_idx);
#ifdef GTPU_PKTQ_STATS
		cfg->error_stat.que_mismatch ++;
#endif
		return -1;
	}
}

#ifdef GTPU_PKTQ_STATS
/*
 * get the error counters for the full pktq module
 */
int
gtpu_pktq_get_stat(gtpu_pktq_cfg_t *cfg, struct gtpu_pktq_stats *global_err)
{
	if (global_err)
		*global_err = pktq_err_stat;

	if (unlikely(!cfg)) {
		QUEUE_ERR("bad cfg");
		pktq_err_stat.invalid ++;
		return -1;
	}

	return 0;
}

/*
 * get the error counters for one queue
 */
int
gtpu_pktq_queue_get_stat(gtpu_pktq_cfg_t *cfg, void *hpriv, int pktq_idx,
				   struct gtpu_pktq_queue_stats *que_err)
{
	gtpu_pktq_t *ipq;

	if (unlikely(!cfg ||
		!cfg->pktq_running ||
		!cfg->num_of_queues ||
		!que_err)) {
		QUEUE_ERR("bad cfg");
		pktq_err_stat.invalid ++;
		return -1;
	}

	memset(que_err, 0, sizeof(*que_err));
	if (!hpriv || pktq_idx < 0) /* no need for search queue error stats */
		return 0;

	ipq = gtpu_pktq_get(cfg, GTPU_PKTQ_SEARCH, hpriv, &pktq_idx);
	QUEUE_DBG("queue=%p", ipq);
	if (likely(ipq)) {
		vnb_spinlock_lock(&ipq->lock);
		*que_err = ipq->stat;
		vnb_spinlock_unlock(&ipq->lock);
	}
	else {
		QUEUE_ERR("can't find packet queue index=%d", pktq_idx);
		cfg->error_stat.que_mismatch ++;
		return -1;
	}

	return 0;
}

/*
 * reset stats for the full pktq module
 */
int
gtpu_pktq_reset_stat(gtpu_pktq_cfg_t *cfg)
{
	memset(&pktq_err_stat, 0, sizeof(pktq_err_stat));

	if (unlikely(!cfg)) {
		QUEUE_ERR("bad cfg");
		pktq_err_stat.invalid ++;
		return -1;
	}

	memset(&(cfg->error_stat), 0, sizeof(cfg->error_stat));

	return 0;
}

/*
 * reset stats for one specific queue
 */
int
gtpu_pktq_queue_reset_stat(gtpu_pktq_cfg_t *cfg, void *hpriv, int pktq_idx)
{
	gtpu_pktq_t *ipq;

	if (unlikely(!hpriv || !cfg)) {
		QUEUE_ERR("bad hpriv or cfg");
		pktq_err_stat.invalid ++;
		return -1;
	}

	ipq = gtpu_pktq_get(cfg, GTPU_PKTQ_SEARCH, hpriv, &pktq_idx);
	QUEUE_DBG("queue=%p", ipq);
	if (likely(ipq)) {
		vnb_spinlock_lock(&ipq->lock);
		memset(&ipq->stat, 0, sizeof(ipq->stat));
		vnb_spinlock_unlock(&ipq->lock);
	}
	else {
		QUEUE_ERR("can't find packet queue index=%d", pktq_idx);
		cfg->error_stat.que_mismatch ++;
		return -1;
	}

	return 0;
}
#endif
