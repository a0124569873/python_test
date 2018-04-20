/*
 * Copyright 2011-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_GTPU_PKTQ_H_
#define _NETGRAPH_GTPU_PKTQ_H_

/* compile-time flag for enabling stats collection in gtpu_pktq */
// #define GTPU_PKTQ_STATS 1

typedef struct pkt_ptr_struct {
	struct mbuf *mbuf;            /* packet pointer array */
	meta_p meta;
	uint64_t cycles;              /* date of this packet in the queue */
} pkt_ptr_t;

#ifdef GTPU_PKTQ_STATS
/* stats/errors for the pktq module */
struct gtpu_pktq_stats {
	uint32_t invalid;             /* invalid parameters */
};
/* stats/errors for one pktq config */
struct gtpu_pktq_cfg_stats {
	uint32_t malloc;              /* ng_malloc failed */
	uint32_t no_free_que;         /* no free queue to alloc */
	uint32_t que_mismatch;        /* can't find queue or mismatch */
	uint32_t mbuf;                /* mbuf is empty */
	uint32_t send_fail;           /* send packet failed */
	uint32_t general;             /* general error */
};
/* stats/errors for one pktq queue */
struct gtpu_pktq_queue_stats {
	uint32_t store_pkts;          /* number of packets stored in the queue */
	uint32_t drop_pkts;           /* number of packets dropped by the queue */
	uint32_t tran_pkts;           /* number of packets sent out */
};
#endif

typedef struct gtpu_pktq {

	uint8_t flags;
#define QUE_COMPLETE   1

	fpn_atomic_t used;            /* packet queue flag: if the queue is free */
	vnb_spinlock_t lock;          /* spinlock while entry is used */

	uint64_t start_cycles;        /* timestamp of the inital packet, never change */
	uint64_t first_cycles;        /* timestamp of the current first packet,
	                                 and will be updated when packets are dropped or sent */
	uint64_t last_cycles;         /* timestamp of the last packet,
	                                 and will be updated when packets are added */
#ifdef GTPU_PKTQ_STATS
	struct gtpu_pktq_queue_stats stat;
#endif
	uint32_t first_idx;           /* first index of pkt_ptr_array */
	uint32_t pkt_count;           /* number of packets currently buffered in the queue */
	pkt_ptr_t * pkt_ptr_array;    /* packet pointer array */
	void * callback_arg;          /* this is used for callback function's arg */

	TAILQ_ENTRY(gtpu_pktq) tchain;/* queue chaining field, point to next queue */
} gtpu_pktq_t;

/* linked list of queues : sorted by creation date */
typedef TAILQ_HEAD(gtpu_pktq_list, gtpu_pktq) gtpu_pktq_list_t;

typedef int (*pktq_callback)(void *arg, struct mbuf*m, meta_p meta);
typedef struct gtpu_que_tm
{
	uint64_t start_pkt;           /* date of the inital packet, never change */
	uint64_t first_pkt;           /* date of the first packet in the queue */
	uint64_t last_pkt;            /* date of the last packet in the queue */
	uint32_t pkt_count;           /* number of packets currently buffered in the queue */
} gtpu_que_tm_t;

typedef struct gtpu_pktq_cfg {

	/* the following variables are used for external configuration and are writable */
	uint32_t num_of_queues;       /* number of queues for packets buffering, power of 2 */
	uint64_t queue_delay_ms; /* how long the packets in a queue will be kept before timeout removal */
	uint32_t pkts_per_queue;      /* max number of packets in a queue */
	uint32_t gc_delay;    /* how long will a garbage collector run to clean up timeout packet queues */

#ifdef GTPU_PKTQ_STATS
	struct gtpu_pktq_cfg_stats error_stat; /* various error stats  */
#endif

	/* the following is used for packet queue internal usage which is readonly for external user */
	uint32_t pktq_running; /* maintain internal. flags to show if the whole packet queue is running */
	uint64_t queue_delay_cycles;  /* maximum queue age, in cycles, before timeout removal */
	uint64_t cycles_per_ms;       /* how many cycles per ms */
	pktq_callback inter_pktq_cb;  /* callback function for sending packet in queue */
	gtpu_pktq_list_t pktq_tlist;  /* chain list which link queue which are used */
	gtpu_pktq_t * pktq_pool;      /* pool of packet queues */
	vnb_spinlock_t pktq_list_lock;
	struct ng_callout pktq_gc_callout;

} gtpu_pktq_cfg_t;

/* the following are five exported function for packet queuing function. */

/*
 * init list for whole packet queues.
 * when a new queue is allocated it will be inserted into the list.
 * it will create a garbage collector timer which will cleanup timed-out packet queues.
 * it will create a packet queue pool and init the pool locks, init locks for each queue.
 */
int gtpu_pktq_init(gtpu_pktq_cfg_t *cfg);

/*
 * this function will stop the packet queue and remove it immediately.
 * it will delete the garbage collector timer. and it will clean
 * each used packet queue, such as cleanup queued packets.
 * after that it will cleanup the packet queue pool.
 */
void gtpu_pktq_exit(gtpu_pktq_cfg_t *cfg);

/*
 * this function is used to add a packet into a the tunnel's packet queue.
 * if it's first time, it first will alloc a packet queue from the pool.
 * and it will replace the oldest packet when the queue is full.
 */
int gtpu_pktq_add_pkt(gtpu_pktq_cfg_t *cfg, struct mbuf *pkt, meta_p meta,
					  void *hpriv, int *pktq_idx);

/*
 * the function is used to send all buffered packets out.
 * it will free the packet queue after all packets are sending out.
 */
int gtpu_pktq_send_pkts(gtpu_pktq_cfg_t *cfg, void *hpriv, int *pktq_idx);

/*
 * this function is used to get first and last packet's timestamp in a packet queue.
 */
int gtpu_pktq_get_timestamp(gtpu_pktq_cfg_t *cfg, void *hpriv, int pktq_idx,
							gtpu_que_tm_t *tm);

#ifdef GTPU_PKTQ_STATS
/*
 * this function is used to get stats for the full pktq module
 */
int gtpu_pktq_get_stat(gtpu_pktq_cfg_t *cfg, struct gtpu_pktq_stats *global_err);

/*
 * this function is used to get stats for one specific queue
 */
int gtpu_pktq_queue_get_stat(gtpu_pktq_cfg_t *cfg, void *hpriv, int pktq_idx,
				   struct gtpu_pktq_queue_stats *que_err);

/*
 * this function is used to reset stats for the full pktq module
 */
int gtpu_pktq_reset_stat(gtpu_pktq_cfg_t *cfg);

/*
 * this function is used to reset stats for one specific queue
 */
int gtpu_pktq_queue_reset_stat(gtpu_pktq_cfg_t *cfg, void *hpriv, int pktq_idx);
#endif

#endif
