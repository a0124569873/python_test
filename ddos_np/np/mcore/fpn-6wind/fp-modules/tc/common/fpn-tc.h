/*
 * Copyright(c) 2008 6WIND
 */
#ifndef __FPN_TC_H__
#define __FPN_TC_H__

#include "fpn-qos-color.h"

#define FPN_TC_MAX  256
typedef struct fpn_tc_params {
	uint32_t flags;
#define FPN_TC_F_BYTE_POLICING 0x1
#define FPN_TC_F_COLOR_AWARE   0x2
	uint64_t cir;   /* Committed Information Rate */
	uint64_t eir;   /* Excess Information Rate */
	uint32_t cbs;   /* Committed Burst Size */
	uint32_t ebs;   /* Excess Burst Size */
} fpn_tc_params_t;

typedef struct fpn_tc_bucket_stats {
	uint64_t green_packets;
	uint64_t green_bytes;
	uint64_t yellow_packets;
	uint64_t yellow_bytes;
	uint64_t red_packets;
	uint64_t red_bytes;
} fpn_tc_bucket_stats_t;

/* Rate limit packet using TC handler <id>
 * - return color id (FPN_QOS_GREEN,YELLOW,RED) or < 0 if ID is invalid.
 */
int fpn_tc_input(struct mbuf *m, uint32_t id);

/* lock-less version of fpn_tc_input
 * lock's responsability is the caller's
 */
int fpn_tc_input_no_lock(struct mbuf *m, uint32_t id);

/* allocate or reuse a TC handler.
 * - return TC id with all states clear or < 0 if error.
 */
int fpn_tc_set_params(uint32_t id, fpn_tc_params_t *params);

/* lock-less version of fpn_tc_set_params
 * lock's responsability is the caller's
 */
int fpn_tc_set_params_no_lock(uint32_t id, fpn_tc_params_t *params);

/* Read parameters of TC handler */
int fpn_tc_get_params(uint32_t id, fpn_tc_params_t *params);

/* Read statistics
 * - return 0 or < 0 if error like ID is invalid
 */
int fpn_tc_get_stats(uint32_t id, fpn_tc_bucket_stats_t *stats);

/* Clear statistics
 * - return 0 or < 0 if error like ID is invalid
 */
int fpn_tc_clear_stats(uint32_t id);

/* Initialize n TC handlers with dynamic memory allocation */
int fpn_tc_init(void);

#endif
