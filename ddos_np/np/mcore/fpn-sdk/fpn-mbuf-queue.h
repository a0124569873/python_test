/*
 * Copyright(c) 2011 6WIND. All right reserved.
 */

#ifndef __FPN_MBUF_QUEUE_H__
#define __FPN_MBUF_QUEUE_H__

/* Mbuf queue (MBQ) API:
 *
 * attribte __mbq_cache_aligned
 * int mbq_get_cpu_id()
 * int mbq_print(const char *format, ...)
 * type mbq_spinlock_t
 * mbq_spinlock_init(mbq_spinlock_t *lock)
 * void mbq_spinlock_lock(mbq_spinlock_t *lock)
 * void mbq_spinlock_unlock(mbq_spinlock_t *lock)
 * MBQ_MAX_CORE
 */

/* MBQ maps a two fields structure over user's buffer.
 * You may overwrite the offset to select the fields being modified.
 * By default the first 16B is used.
 *
 * struct mbq_mbuf {
 *    char reserved1[MBQ_OFFSET1];
 *    uint64_t field1;
 *    char reserved2[MBQ_OFFSET2 - MBQ_OFFSET1 - 8];
 *    uint64_t field2;
 * };
 */

#ifdef __KERNEL__
#include <linux/types.h> /* uint64_t */
#include <linux/kernel.h> /* printk */
#include <linux/mm.h> /* memset, smp_processor_id() */
#define mbq_print printk
#define mbq_get_cpu_id() smp_processor_id()
#endif


#if defined(CONFIG_MCORE_ARCH_XLP) || defined(CONFIG_NLM_XLP)
#include "xlp/fpn-mbuf-xlp-queue.h"
#endif

#ifndef MBQ_OFFSET1
#define MBQ_OFFSET1 0
#endif
#ifndef MBQ_OFFSET2
#define MBQ_OFFSET2 8
#endif

struct fpn_mbq_local {
	uint64_t first;
	uint64_t extra;
	uint32_t count;
	uint32_t cache_size;
	uint32_t bulk_size;

	uint32_t free_bulk;
	uint32_t alloc_bulk;
	uint32_t error;
} __mbq_cache_aligned;

struct fpn_mbq_global {
	mbq_spinlock_t mbq_lock;
	uint64_t first;
	uint32_t count;
	uint32_t cache_size;
	uint32_t bulk_size;
	uint32_t max_count;
	volatile uint64_t magic;
};
#define MBQ_MAGIC 0x4A4D47204D425546ULL

struct fpn_mbq_lstat {
	uint32_t count;
	uint32_t error;
	uint32_t free_bulk;
	uint32_t alloc_bulk;
};

struct fpn_mbq_stats {
	uint32_t max_count;
	uint32_t global_count;
	struct fpn_mbq_lstat local[MBQ_MAX_CORE];
};

struct fpn_mbq_pool {
	struct fpn_mbq_global mbq_global;
	struct fpn_mbq_local mbq_local[MBQ_MAX_CORE] __mbq_cache_aligned;
} __mbq_cache_aligned;

void fpn_mbq_get_stats(struct fpn_mbq_pool *pool, struct fpn_mbq_stats *user);

void fpn_mbq_reset_stats(struct fpn_mbq_pool *pool);

void fpn_mbq_enqueue(struct fpn_mbq_pool *pool, void *m);

void *fpn_mbq_dequeue(struct fpn_mbq_pool *pool);

int fpn_mbq_is_ready(struct fpn_mbq_pool *pool);

#ifndef __KERNEL__
void fpn_mbq_init_virt_to_phys_offset(uint64_t offset);
#endif
int fpn_mbq_add_mbuf_region(struct fpn_mbq_pool *pool, void *mem_addr,
	uint64_t mem_size, uint32_t mbuf_size, void (*init)(void *));
int fpn_mbq_create(struct fpn_mbq_pool *pool, uint32_t cache_size);

void fpn_mbq_print_stats(struct fpn_mbq_pool *pool);

int fpn_mbq_proc_register(char *name, struct fpn_mbq_pool *pool);

#endif /* __FPN_MBUF_QUEUE_H__ */
