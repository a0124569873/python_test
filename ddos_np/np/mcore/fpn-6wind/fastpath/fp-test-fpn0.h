/*
 * Copyright(c) 2008 6WIND
 */
#ifndef _FP_TEST_FPN0_H__
#define _FP_TEST_FPN0_H__

/* return values for fp_test_fpn0_is_icmp_echo() */

#define TEST_FPN0_NOT_A_REQUEST 0
/* reserved ip addr on fpn0 = 1 */
#define TEST_FPN0_REPLY_ONLY 2
#define TEST_FPN0_MBUF_AUDIT 3
#define TEST_FPN0_DO_MEMTEST 4
#define TEST_FPN0_CKSUM_AUDIT 5
#define TEST_FPN0_EQOS_STATS 6 /* Egress QoS statistics */
#define TEST_FPN0_REASS_INFO 7
#define TEST_FPN0_TRACK_INFO 8
#define TEST_FPN0_CHECK_SIZE 9
#define TEST_FPN0_CRYPTO_AUDIT 10
#define TEST_FPN0_MTAG_AUDIT 11
#define TEST_FPN0_VNB_INFOS 12
#define TEST_FPN0_TIMERS_ACCURACY 13
#define TEST_FPN0_TIMERS_CALLOUT 14
#define TEST_FPN0_TIMERS_STRESS_RESET 15
#define TEST_FPN0_TIMER_CALLOUTS_CHECK 16
#define TEST_FPN0_LOCK_AUDIT 17
#define TEST_FPN0_POOL_DUMP 18
#define TEST_FPN0_TIMERS_FREE_CALLLOUT 19
#define TEST_FPN0_GET_LOCAL_CYCLES 20
#define TEST_FPN0_MEMPOOL 21
#define TEST_FPN0_RING 22
#define TEST_FPN0_RINGPOOL 23
#define TEST_FPN0_RINGQUEUE 24
#define TEST_FPN0_TIMERS_BIND 25
#define TEST_FPN0_SHMEM_CONF 26
#define TEST_FPN0_AATREE 27
#define TEST_FPN0_TIMERS_SCALABILITY 28
#define TEST_FPN0_DEBUG_LOCK_LOG_DUMP 29
#define TEST_FPN0_FPNMALLOC 30
#define TEST_FPN0_SPINLOCK 31
#define TEST_FPN0_CRYPTO_STAT 32
#define TEST_FPN0_NIC_STATS 34
#define TEST_FPN0_XLP_MAX_MBUF 35
#define TEST_FPN0_CPUMASK 36

#define TEST_FPN0_XLP_DEBUG_MBUF    205

#define TEST_FPN0_MAX 256

extern uint8_t fp_test_fpn0_is_icmp_echo(struct mbuf *m);
extern int fp_do_test_fpn0(uint8_t type);
extern int fp_test_fpn0(struct mbuf *m);

typedef void (*fp_test_fpn0_fn)(void);

typedef struct fp_test_fpn0_handler {
	fp_test_fpn0_fn func;
	const char *comment;
} fp_test_fpn0_handler_t;

int fp_test_fpn0_register(uint8_t id, fp_test_fpn0_handler_t *handler);

#endif
