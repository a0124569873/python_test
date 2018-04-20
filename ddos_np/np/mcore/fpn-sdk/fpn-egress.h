/*
 * Copyright(c) 2008  6WIND
 */
#ifndef __FPN_EGRESS_H__
#define __FPN_EGRESS_H__

/*
 * FPN_MAX_OUTPUT_QUEUES must be defined to the maximum number of output 
 * queues.
 */

#include <fpn-mbuf.h>

struct fpn_queue_params {
    /* It must be set to all the queues added to a port which has at
 *        least one static-priority queue. */
#define FPN_STRICT_PRI_PORT  0x4000000000000000
    /* It must be set to if the queue is static-priority */
#define FPN_STRICT_PRI_Q     0x2000000000000000
    /* It must be set if the queue is the last static-priority queue. */
#define FPN_STRICT_PRI_TAIL  0x8000000000000000
    /* Bit 16. It must be set if the queue is the last queue for a given
 * port. */
#define FPN_QUEUE_TAIL       0x10000

  uint64_t priorityFlags;   /* priority flags */

  uint16_t weight;     /* relevant for weighted-fair queue  */
/* 0 to 100: per centage  */
/* ex:
    0 to 12.5 -> 1 round bit
    13 to 25  -> 2 round bits
    26 to 37  -> 3 round bits
    etc.
    get the closest ones
    be sure to avoid 8 x 12.5 ones at the same position
 */

  /* indicates what discard behaviour to employ (tail drop vs wred) */
#define FPN_QOS_DISC_TAILDROP  0
#define FPN_QOS_DISC_WRED      1
#define FPN_QOS_DISC_NONE      2
  uint8_t discardAlgorithm;     
/* XXX add definition list of discard algorithms */

  union {
    /*
     * WRED Params:
     *   DP0 is the Green traffic
     *   DP1 is the Yellow traffic
     *   DP2 is the Red traffic
     */
    struct {
      uint32_t dpGmin;   /* min threshold  in either packets or bytes for DP0 */
      uint32_t dpGmax;   /* max threshhold in either packets or bytes for DP0 */
      uint32_t dpGprob;  /* drop probability for packets when queue status is in DP0 range */
      uint32_t dpYmin;   /* min threshhold in either packets or bytes for DP1 */
      uint32_t dpYmax;   /* max threshhold in either packets or bytes for DP1 */
      uint32_t dpYprob;  /* drop probability for packets when queue status is in DP1 range */
      uint32_t dpRmin;   /* min threshhold in either packets or bytes for DP2 */
      uint32_t dpRmax;   /* max threshhold in either packets or bytes for DP2 */
      uint32_t dpRprob;  /* drop probability for packets when queue status is in DP2 range */
      uint32_t movingAverage; /* For Adaptive RED, TBD (also known as forgetting factor) */
    } red;

    /* TailDrop Params */
    struct {
      uint32_t dpGmax;    /* discard threshhold in bytes for DP0 */
      uint32_t dpYmax;    /* discard threshhold in bytes for DP1 */
      uint32_t dpRmax;    /* discard threshhold in bytes for DP2 */
    } taildrop;
  } ud;
};

/*
 * Initilialize all the queues
 */
extern int fpn_init_queue(void);

extern int fpn_add_queue(
  uint16_t queueId,
  uint8_t port,
  uint8_t queueIdx,
  const struct fpn_queue_params *params
);

/*
 * update queue parameters of a port
 */
extern int fpn_update_queue_weight(
  uint16_t queueId,
  const struct fpn_queue_params *params
);

extern int fpn_update_queue_thresholds(
  uint16_t queueId,
  const struct fpn_queue_params *params
);

extern uint32_t fpn_read_queue_length(uint16_t queueId);

struct fpn_queue_stats {
  /* Per-queue Stats */
  uint64_t discardBytesG; /* # of discarded bytes for DP0 */
  uint64_t discardBytesY; /* # of discarded bytes for DP1 */
  uint64_t discardBytesR; /* # of discarded bytes for DP2 */
  uint32_t discardPacketsG; /* # of discarded packets for DP0 */
  uint32_t discardPacketsY; /* # of discarded packets for DP1 */
  uint32_t discardPacketsR; /* # of discarded packets for DP2 */
  uint32_t averageQueLength; /* average queue length in bytes or packets,
                          * relevant for WRED only - maybe not need to be
                          * implemented if it requires too much CPUs
                          */
  uint32_t hiWaterMark;   /* high water mark for this queue - report the highest usage */
};

extern int fpn_read_queue_stats(
  uint16_t queueId,
  struct fpn_queue_stats *statsPtr
);

extern int fpn_read_queue_params(
  uint16_t queueId,
  struct fpn_queue_params *params
);

/*
 * set all fields of queueStats to 0
 */
extern int fpn_reset_queue_stats(
  uint16_t queueId
);

/*
 * Queue a packet
    int fpn_enqueue_packet(struct mbuf *m, uint16_t queueId, 
                           uint8_t port, int do_lock);
 */

#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
#include "octeon/fpn-egress-octeon.h"
#endif
#endif
