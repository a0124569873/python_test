/*
 * Copyright(c) 2011 6WIND. All right reserved.
 */

/* Mbuf queue is a global pool with per cpu cache list and with communication
 * cache<->global using bulk mechanism.  Links in list are done using physical
 * address to share between multiple domains like Linux and Fastpath:
 * - each domain calls fpn_mbq_init() to initialize virt/phys conversion
 * - one domain setup the pool using fpn-mbq_create().
 */

#include "fpn-mbuf-queue.h"


#ifdef __KERNEL__
/* We can't use regular virt_to_phys/phys_to_virt with XEN */
static inline uint64_t mbq_virt_to_phys(void *addr)
{
#ifdef CONFIG_XEN
	return addr ? (uint64_t)((unsigned long)addr & 0x000000ffffffffffUL) : (uint64_t)0UL;
#else
	return addr ? (uint64_t)(unsigned long)virt_to_phys(addr) : (uint64_t)0UL;
#endif
}

static inline void *mbq_phys_to_virt(uint64_t phys)
{
#ifdef CONFIG_XEN
	return phys ? (void *)(unsigned long)PHYS_TO_XKSEG_CACHED(phys) : NULL;
#else
	return phys ? (void *)phys_to_virt(phys) : NULL;
#endif
}

/* We read smp_processor_id() to access cpu's pool, we must stop preemption */
#define mbq_preempt_disable() preempt_disable()
#define mbq_preempt_enable() preempt_enable()
#else
/* Assume a single offset variable */
static uint64_t mbq_offset;
#define mbq_virt_to_phys(a)  \
	(uint64_t)( (a) ? ((unsigned long)(a) + mbq_offset) : 0UL)
#define mbq_phys_to_virt(a)  \
	(void *)( (a) ? ((unsigned long)(a) - mbq_offset) : 0UL)
#define mbq_preempt_disable()
#define mbq_preempt_enable()
#endif


struct mbq_mbuf {
	char reserved1[MBQ_OFFSET1];
	uint64_t m_next; /* physical address of next mbuf */
	char reserved2[MBQ_OFFSET2 - MBQ_OFFSET1 - 8];
	uint64_t b_next; /* physical address of next bulk of mbufs */
};


/* Note on bulk:
 * We need to know the last mbuf of a bulk quickly, and we store this pointer
 * in the second mbuf of the bulk, field b_next. This avoids adding a third
 * field in mbq_mbuf.
 */
static inline struct mbq_mbuf * __mbq_mbuf_alloc_bulk(
	struct fpn_mbq_pool *pool)
{
	struct fpn_mbq_global *mbq = &pool->mbq_global;
	struct mbq_mbuf *m;

	mbq_spinlock_lock(&mbq->mbq_lock);
	m = mbq_phys_to_virt(mbq->first);
	if (m) {
		/* unlink from queue */
		mbq->count -= mbq->bulk_size;
		mbq->first = m->b_next;
		m->b_next = 0;
	}
	mbq_spinlock_unlock(&mbq->mbq_lock);

	return m;
}

static inline void __mbq_mbuf_free_bulk(
		struct fpn_mbq_pool *pool,
		struct mbq_mbuf *m, struct mbq_mbuf *last)
{
	struct fpn_mbq_global *mbq = &pool->mbq_global;
	struct mbq_mbuf *next;

	mbq_spinlock_lock(&mbq->mbq_lock);
	m->b_next = mbq->first;
	//m->m_next->b_next = last;
	next = mbq_phys_to_virt(m->m_next);
	next->b_next = mbq_virt_to_phys(last);
	mbq->first = mbq_virt_to_phys(m);
	mbq->count += mbq->bulk_size;
	mbq_spinlock_unlock(&mbq->mbq_lock);
}

void fpn_mbq_enqueue(struct fpn_mbq_pool *pool, void *_m)
{
	struct fpn_mbq_local *mbq;
	struct mbq_mbuf *m = _m;
	unsigned int cpu;

	mbq_preempt_disable();
	cpu = mbq_get_cpu_id();
	mbq = &pool->mbq_local[cpu];

	m->m_next = mbq->first;
	mbq->first = mbq_virt_to_phys(m);
	mbq->count++;

	if (likely(mbq->count <= mbq->cache_size)) {
		mbq_preempt_enable();
		return;
	}

	if (mbq->count == mbq->cache_size + 1)
		mbq->extra = mbq_virt_to_phys(m);
	else if (mbq->count == (mbq->cache_size + mbq->bulk_size)) {
		struct mbq_mbuf *extra = mbq_phys_to_virt(mbq->extra);
		/* Cut to make m->...->extra a chain of bulk_size mbufs */
		mbq->first = extra->m_next;
		extra->m_next = 0;
		__mbq_mbuf_free_bulk(pool, m, extra);
		mbq->free_bulk++;
		mbq->count -= mbq->bulk_size;
	}
	mbq_preempt_enable();
}

void *fpn_mbq_dequeue(struct fpn_mbq_pool *pool)
{
	struct fpn_mbq_local *mbq;
	struct mbq_mbuf *m;
	unsigned int cpu;

	mbq_preempt_disable();
	cpu = mbq_get_cpu_id();
	mbq = &pool->mbq_local[cpu];

	if (unlikely(mbq->count < mbq->bulk_size)) {
		struct mbq_mbuf *b = __mbq_mbuf_alloc_bulk(pool);

		mbq->alloc_bulk++;
		if (b) {
			//struct mbq_mbuf *last = b->m_next->b_next;
			struct mbq_mbuf *next = mbq_phys_to_virt(b->m_next);
			struct mbq_mbuf *last = mbq_phys_to_virt(next->b_next);

			last->m_next = mbq->first;
			mbq->count += mbq->bulk_size;
			mbq->first = mbq_virt_to_phys(b);
		} else if (mbq->count == 0) {
			mbq->error++;
			mbq_preempt_enable();
			return NULL;
		}
	}

	/* unlink from queue */
	m = mbq_phys_to_virt(mbq->first);
	mbq->count--;
	mbq->first = m->m_next;
	m->m_next = 0;
	mbq_preempt_enable();

	return m;
}

int fpn_mbq_is_ready(struct fpn_mbq_pool *pool)
{
	return (pool->mbq_global.magic == MBQ_MAGIC);
}

#ifndef __KERNEL__
/* offset + VA = PA */
void fpn_mbq_init_virt_to_phys_offset(uint64_t offset)
{
	mbq_offset = offset;
}
#endif

int fpn_mbq_create(struct fpn_mbq_pool *pool, uint32_t cache_size)
{
	int i;

	if (fpn_mbq_is_ready(pool)) {
		mbq_print("Warning: fpn_mbq_create: magic found\n");
	}

	mbq_print("%s: cache-size=%u\n", __func__, cache_size);

	memset(&pool->mbq_global, 0, sizeof(pool->mbq_global));
	memset(&pool->mbq_local, 0, sizeof(pool->mbq_local));
	mbq_spinlock_init(&pool->mbq_global.mbq_lock);
	pool->mbq_global.cache_size = cache_size;
	pool->mbq_global.bulk_size = cache_size/2;


	for (i = 0; i < MBQ_MAX_CORE; i++) {
		pool->mbq_local[i].cache_size = pool->mbq_global.cache_size;
		pool->mbq_local[i].bulk_size = pool->mbq_global.bulk_size;
	}

	pool->mbq_global.max_count = 0;
	pool->mbq_global.magic = MBQ_MAGIC;


	return 0;
}

int fpn_mbq_add_mbuf_region(struct fpn_mbq_pool *pool, void *mem_addr, uint64_t mem_size,
		uint32_t mbuf_size,
		void (*init)(void *))
{
	uint8_t *m;
	uint64_t count;
	uint64_t size;

	if (!fpn_mbq_is_ready(pool)) {
		mbq_print("Error: pool is not setup\n");
		return -1;
	}

	m = (uint8_t *)mem_addr;
	count = 0;
	size = mem_size;

	mbq_preempt_disable();
	while (size >= mbuf_size) {
		if (init)
			init(m);
		fpn_mbq_enqueue(pool, m);
		m += mbuf_size;
		size -= mbuf_size;
		count++;
	}
	mbq_preempt_enable();
	pool->mbq_global.max_count += count;

	mbq_print("%s: %lu mbufs in %lum@%lum size=%lu\n", __func__,
			(unsigned long)count,
			(unsigned long)(mem_size>>20),
			(unsigned long)(mbq_virt_to_phys(mem_addr)>>20),
			(unsigned long)mbuf_size);

	return 0;
}

void fpn_mbq_get_stats(struct fpn_mbq_pool *pool, struct fpn_mbq_stats *user)
{
	int i;

	user->max_count = pool->mbq_global.max_count;
	user->global_count = pool->mbq_global.count;
	for (i = 0 ; i < MBQ_MAX_CORE; i++) {
		user->local[i].count = pool->mbq_local[i].count;
		user->local[i].error = pool->mbq_local[i].error;
		user->local[i].free_bulk = pool->mbq_local[i].free_bulk;
		user->local[i].alloc_bulk = pool->mbq_local[i].alloc_bulk;
	}
}

void fpn_mbq_reset_stats(struct fpn_mbq_pool *pool)
{
	int i;

	for (i = 0 ; i < MBQ_MAX_CORE; i++) {
		pool->mbq_local[i].error = 0;
		pool->mbq_local[i].free_bulk = 0;
		pool->mbq_local[i].alloc_bulk = 0;
	}
}

void fpn_mbq_print_stats(struct fpn_mbq_pool *pool)
{
	struct fpn_mbq_stats stats;
	unsigned int count = 0;
	unsigned int total;
	int i;

	fpn_mbq_get_stats(pool, &stats);
	mbq_print("MBQ statistics:\n");
	for (i = 0; i < MBQ_MAX_CORE; i++) {
		if (stats.local[i].count == 0 && stats.local[i].error == 0)
			continue;
		mbq_print("\tcpu=%u count=%u freeb=%u allocb=%u error=%u\n",
				i, stats.local[i].count, stats.local[i].free_bulk,
				stats.local[i].alloc_bulk, stats.local[i].error);
		count += stats.local[i].count;
	}
	total = count + stats.global_count;
	mbq_print("\tglobal pool:=%u in cache:%u total free=%u alloc=%d\n",
			stats.global_count, count, total, stats.max_count - total);
}

#if defined(__KERNEL__) && defined(CONFIG_PROC_FS)
#include <linux/proc_fs.h>
static int mbq_proc_read(char *page, char **start, off_t off,
			     int proc_count, int *eof, void *data)
{
	int len = 0;
	off_t begin = 0;
	struct fpn_mbq_stats stats;
	unsigned int count = 0;
	unsigned int total;
	int i;
	struct fpn_mbq_pool *pool = data;

	fpn_mbq_get_stats(pool, &stats);
	len += sprintf(page + len, "MBQ stats\n");
	for (i = 0; i < MBQ_MAX_CORE; i++) {
		if (stats.local[i].count == 0 && stats.local[i].error == 0)
			continue;
		len += sprintf(page + len, "\tcpu=%u count=%u freeb=%u allocb=%u error=%u\n",
				i, stats.local[i].count, stats.local[i].free_bulk,
				stats.local[i].alloc_bulk, stats.local[i].error);
		count += stats.local[i].count;
	}
	total = count + stats.global_count;
	len += sprintf(page + len, "\tglobal pool:=%u in cache:%u total free=%u alloc=%d\n",
			stats.global_count, count, total, stats.max_count - total);


	*eof = 1;

	*start = page + (off - begin);
	len -= (off - begin);
	if (len > proc_count)
		len = proc_count;
	if (len < 0)
		len = 0;

	return len;
}

int fpn_mbq_proc_register(char *name, struct fpn_mbq_pool *pool)
{
	struct proc_dir_entry *entry;

	entry = create_proc_read_entry(name, 0, NULL, mbq_proc_read, pool);

	if (!entry) {
		mbq_print("Failed to create /proc/mbq_stats\n");
		return -1;
	}

	return 0;
}
#else
int fpn_mbq_proc_register(char *name, struct fpn_mbq_pool *pool)
{
	mbq_print("%s: not implemented\n", __func__);
	return -1;
}

#endif
