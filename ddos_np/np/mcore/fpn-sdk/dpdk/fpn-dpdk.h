/*
 * Copyright(c) 2010 6WIND
 */
#ifndef __FPN_DPDK_H__
#define __FPN_DPDK_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <ctype.h>
#include <linux/if.h>

#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_pci.h>
#include <rte_devargs.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_version.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
#include "fpn-lock-dpdk.h"
#endif

#define DPDK_VERSION(x,y,z) ((x) << 16 | (y) << 8 | (z))
#ifndef  RTE_VER_YEAR
#define BUILT_DPDK_VERSION \
	DPDK_VERSION(RTE_VER_MAJOR, RTE_VER_MINOR, RTE_VER_PATCH_LEVEL)
#else
#define BUILT_DPDK_VERSION RTE_VERSION
#endif

#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
#define RTE_EM_PMD_NAME         "net_e1000_em"
#define RTE_IGB_PMD_NAME        "net_e1000_igb"
#define RTE_IGBVF_PMD_NAME      "net_e1000_igb_vf"
#define RTE_IXGBE_PMD_NAME      "net_ixgbe"
#define RTE_IXGBEVF_PMD_NAME    "net_ixgbe_vf"
#define RTE_VIRTIO_PMD_NAME     "net_virtio"
#define RTE_VMXNET3_PMD_NAME    "net_vmxnet3"
#define RTE_I40E_PMD_NAME       "net_i40e"
#else
#define RTE_EM_PMD_NAME         "rte_em_pmd"
#define RTE_IGB_PMD_NAME        "rte_igb_pmd"
#define RTE_IGBVF_PMD_NAME      "rte_igbvf_pmd"
#define RTE_IXGBE_PMD_NAME      "rte_ixgbe_pmd"
#define RTE_IXGBEVF_PMD_NAME    "rte_ixgbevf_pmd"
#define RTE_VIRTIO_PMD_NAME     "rte_virtio_pmd"
#define RTE_VMXNET3_PMD_NAME    "rte_vmxnet3_pmd"
#define RTE_I40E_PMD_NAME     	"rte_i40e_pmd"
#endif

#define RTE_MBUF_OL_FLAGS(m) (m)->ol_flags

#define FPN_HAVE_UNALIGNED_ACCESS 1

#define HAVE_GLIBC_BACKTRACE 1

#define BURST_CYCLES 200000ULL /* around 100us at 2 Ghz */

#if 0
#define FPN_DPDK_DEBUG(args...) printf(args)
#else
#define FPN_DPDK_DEBUG(args...) do { } while (0)
#endif

#if 0
#define FPN_DPDK_DEBUG_RX(args...) printf(args)
#else
#define FPN_DPDK_DEBUG_RX(args...) do { } while (0)
#endif

/* exported variable for fpdebug cmdline */
extern int fpn_cmdline_lcore;

/* anti ddos core */
extern int fpn_anti_ddos_lcore;

extern uint64_t sys_tsc;

extern int (*fpn_anti_ddos_proc)(__attribute__((unused)) void *arg);
#define FPN_DDOS_PROC_REGISTER(proc) \
static inline void __attribute__((constructor)) fpn_ddos_proc_register_ ## proc(void) { \
       fpn_anti_ddos_proc = proc; \
}

#if defined(CONFIG_MCORE_FPVI_TAP)
/* exported variable for exception processing */
extern int fpn_exception_lcore;
#endif
/* exported variable for configuration polling processing. */
extern int fpn_config_polling_lcore;

#define FPN_DECLARE_SHARED(type, var)   extern __typeof__(type) var
#define FPN_DEFINE_SHARED(type, var)    __typeof__(type) var
/* per core variable */
#define FPN_DECLARE_PER_CORE(type, var) RTE_DECLARE_PER_LCORE(type, var)
#define FPN_DEFINE_PER_CORE(type, var)  RTE_DEFINE_PER_LCORE(type, var)
#define FPN_PER_CORE_VAR(var)           RTE_PER_LCORE(var)

/* no prefetch */
#define FPN_PREFETCH(addr) rte_prefetch0(addr)

static inline uint64_t fpn_get_pseudo_rnd(void)
{
	return rte_rand();
}

/* atomic increment of statistics */
#define FPN_STATS_INC(addr)       rte_atomic64_inc((rte_atomic64_t *)(addr))
#define FPN_STATS_INC32(addr)     rte_atomic32_inc((rte_atomic32_t *)(addr))
#define FPN_STATS_ADD(addr,val)   rte_atomic64_add((rte_atomic64_t *)(addr), val)
#define FPN_STATS_ADD32(addr,val) rte_atomic32_add((rte_atomic32_t *)(addr), val)

/* atomic decrement of statistics */
#define FPN_STATS_DEC(addr)       rte_atomic64_dec((rte_atomic64_t *)(addr))
#define FPN_STATS_DEC32(addr)     rte_atomic32_dec((rte_atomic32_t *)(addr))
#define FPN_STATS_SUB(addr,val)   rte_atomic64_sub((rte_atomic64_t *)(addr), val)
#define FPN_STATS_SUB32(addr,val) rte_atomic32_sub((rte_atomic32_t *)(addr), val)

#define FPN_LOADUNA_INT64_OFF0(result, address)	result = *(address)
#define FPN_LOADUNA_INT32_OFF0 FPN_LOADUNA_INT64_OFF0
#define FPN_LOADUNA_INT16_OFF0 FPN_LOADUNA_INT64_OFF0

#define FPN_STOREUNA_INT64_OFF0(data, address) *(address) = data
#define FPN_STOREUNA_INT32_OFF0 FPN_STOREUNA_INT64_OFF0
#define FPN_STOREUNA_INT16_OFF0 FPN_STOREUNA_INT64_OFF0

#define fpn_printf(fmt, args...) printf(fmt, ## args)

#if defined(CONFIG_MCORE_USE_GLIBC_MALLOC)
#define __fpn_malloc(size) malloc(size)
#define __fpn_free(ptr) free(ptr)
#else

#include <string.h>
#include <sys/mman.h>
#include <errno.h>

#define FPN_MAX_ALLOC_RTE ((size_t)2 * 1024 * 1024 * 1024)

#define FPN_MALLOC_TYPE_RTE 0
#define FPN_MALLOC_TYPE_MMAP 1

struct fpn_malloc_header {
	int64_t type;
	int64_t size;
};

static inline void *__fpn_malloc(size_t size)
{
	void *ptr;
	struct fpn_malloc_header *header;
	uintptr_t addr;
	int type;
	int mmap_flags = MAP_SHARED | MAP_ANONYMOUS;

#if defined(MAP_HUGETLB)
	mmap_flags |= MAP_HUGETLB;
#endif

	size += sizeof(struct fpn_malloc_header);

	if (size >= FPN_MAX_ALLOC_RTE) {
		ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, mmap_flags,
			   -1, 0);
		if (ptr == MAP_FAILED) {
			fpn_printf("%s: mmap failed: %s\n",
				   __func__, strerror(errno));
			return NULL;
		}
		type = FPN_MALLOC_TYPE_MMAP;
	} else {
		ptr = rte_malloc("FPN", size, 0);
		if (ptr == NULL)
			return NULL;
		type = FPN_MALLOC_TYPE_RTE;
	}

	header = (struct fpn_malloc_header *)ptr;
	header->type = type;
	header->size = size;

	addr = (uintptr_t)ptr + sizeof(struct fpn_malloc_header);
	return (void *)addr;
}

static inline void __fpn_free(void *ptr)
{
	uintptr_t addr = (uintptr_t)ptr - sizeof(struct fpn_malloc_header);
	struct fpn_malloc_header *header = (struct fpn_malloc_header *)addr;

	if (header->type == FPN_MALLOC_TYPE_MMAP)
		munmap((void *)header, header->size);
	else
		rte_free((void *)header);
}

#endif

#define FPN_HAVE_ARCH_MEMCPY
/* rte_memcpy calls standard memcpy() if n is a constant */
#define fpn_memcpy(dst, src, n) rte_memcpy(dst, src, n)

#include "fpn-lock-dpdk.h"
#include "fpn-mbuf-dpdk.h"
#include "fpn-core-dpdk.h"
#include "fpn-timer-dpdk.h"
#include "fpn-corebarrier.h"

#include "fpn-core.h"
#include "fpn-port.h"
#include "fpn-cksum.h"

/* which cores are allowed to recv pkts from linux */
extern fpn_cpumask_t fpn_linux2fp_mask;
/* Mask of cores that actually receive network packets from NICs. */
extern fpn_cpumask_t fpn_rx_cores_mask;

#if defined(CONFIG_MCORE_FPVI_DP) && defined(CONFIG_MCORE_DPDK_RESET_VF)
/* list of ports that can not be used since we want to restart them */
struct restarting_ports {
	struct restarting_port {
		char state;
		struct callout timer;
	} ports[FPN_MAX_PORTS];
} __rte_cache_aligned;
extern struct restarting_ports fpn_restarting_ports[];
#endif

#define MAX_PKT_BURST 32

#define MAX_CRYPTO_PER_LCORE   16 /* not related to hw */
#define MAX_RX_QUEUE_PER_LCORE 16 /* not related to hw */
#define MAX_TX_QUEUE_PER_PORT 128 /* 10GbE Intel 82599 (Niantic) controllers */
#define MAX_RX_QUEUE_PER_PORT 128 /* 10GbE Intel 82599 (Niantic) controllers */

struct fpn_txq {
	unsigned queueid;
	unsigned m_table_len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct fpn_rxq {
	unsigned queue_id;
	unsigned port_id;
};

struct lcore_conf {
	unsigned is_1gb; /* A lcore can handle 1gb ports or 10gb. Not both */
	unsigned n_rx_queue;
	struct fpn_rxq rxq[MAX_RX_QUEUE_PER_LCORE];
	struct fpn_txq txq[FPN_MAX_PORTS];
} __rte_cache_aligned;
extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];

/* Global list of enabled ports */
struct fpn_rte_s_port_table {
	unsigned count;
	unsigned index[FPN_MAX_PORTS];
} __rte_cache_aligned;

extern struct fpn_rte_s_port_table fpn_rte_port_table;

#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
extern int fpn_rxq_shared[FPN_MAX_PORTS]; /* Boolean - RX queues shared? */
extern int fpn_txq_shared[FPN_MAX_PORTS]; /* Boolean - TX queues shared? */
#endif

enum fpn_driver {
	RTE_NONE = 0,
	RTE_EM,
	RTE_IGB, RTE_IGBVF,
	RTE_IXGBE, RTE_IXGBEVF,
	RTE_VIRTIO, RTE_VMXNET3,
	RTE_I40E, RTE_OTHER,
};

struct fpn_rte_port {
#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
	/*
	 * Align each lock on CPU cache line boundaries to minimize cache line
	 * contentions and cache miss operations.
	 */
	__fpn_spinlock_t rxq0_lock __fpn_cache_aligned; /* Lock of RX queue 0 */
	__fpn_spinlock_t txq0_lock __fpn_cache_aligned; /* Lock of TX queue 0 */
#endif
	/* link state retrieved by get_stats_cb */
	struct rte_eth_link link;
	/* stats retrieved by get_stats_cb */
	struct rte_eth_stats stats;
	enum fpn_driver driver;
};
extern struct fpn_rte_port fpn_rte_ports[FPN_MAX_PORTS];

int fpn_printf_ratelimited(const char *format, ...)
	__attribute__((format(printf, 1, 2)));

/*
 * fast ethernet header: same as fast_memcpy14(, , 14);
 */
#define FPN_HAVE_ETHCOPY

/* XXX could be asm-optimized */
__attribute__((nonnull (1, 2))) static inline void
fpn_ethcpy(void *eth, const void *eh)
{
	uint64_t *dst64;
	const uint64_t *src64;
	uint32_t *dst32;
	const uint32_t *src32;
	uint16_t *dst16;
	const uint16_t *src16;

	dst64 = eth;
	src64 = eh;
	*dst64 = *src64;

	dst32 = eth + 8;
	src32 = eh + 8;
	*dst32 = *src32;

	dst16 = eth + 12;
	src16 = eh + 12;
	*dst16 = *src16;
}

/* Send outstanding packets */
static inline void fpn_rte_drain_txq(struct fpn_txq *txq, int portid)
{
	unsigned ret;
	unsigned n = txq->m_table_len;

	if (n == 0)
		return;

	txq->m_table_len = 0;

#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
	if (unlikely(fpn_txq_shared[portid])) {
		/* Lock shared TX queue 0 of port */
		__fpn_spinlock_t *txq0_lock = &fpn_rte_ports[portid].txq0_lock;

		__fpn_spinlock_lock(txq0_lock);
		ret = rte_eth_tx_burst(portid, 0, txq->m_table, n);
		if (unlikely(ret < n)) {
			/* DPDK has increased odropped counter by n - ret */
			do {
				rte_pktmbuf_free(txq->m_table[ret]);
			} while (++ret < n);
		}
		__fpn_spinlock_unlock(txq0_lock);
		return;
	}
#endif
	ret = rte_eth_tx_burst(portid, txq->queueid, txq->m_table, n);
	if (unlikely(ret < n)) {
		/* DPDK has increased odropped counter by n - ret */
		do {
			rte_pktmbuf_free(txq->m_table[ret]);
		} while (++ret < n);
	}
}

static inline int
fpn_check_port(__attribute__((unused)) int portid)
{
#ifdef CONFIG_MCORE_FPN_CHECK_PORT
	struct fpn_port *port;

	/* bad port */
	if (unlikely(portid > FPN_MAX_PORTS))
		return -1;
	port = &fpn_port_shmem->port[portid];
	if (unlikely(port->portid != portid)) {
		FPN_DPDK_DEBUG_RX("%s: No node found portid=%d\n",
			     __FUNCTION__, portid);
		return -1;
	}
	if (unlikely(port->enabled == 0))
		return -1;
#endif
#if defined(CONFIG_MCORE_FPVI_DP) && defined(CONFIG_MCORE_DPDK_RESET_VF)
	{
		unsigned lcore_id = rte_lcore_id();

		/* restarting port */
		if (unlikely(fpn_restarting_ports[lcore_id].ports[portid].state)) {
			return -1;
		}
	}
#endif
	return 0;
}

/* Drain one queue. lcore_id must be rte_lcore_id() */
static inline void fpn_drain_txqueue(int portid, uint8_t lcore_id)
{
	struct lcore_conf *conf = &lcore_conf[lcore_id];
	struct fpn_txq *txq = &conf->txq[portid];

	fpn_rte_drain_txq(txq, portid);
}

/* Send the packet on an output interface */
static inline int
__fpn_send_packet(struct mbuf *m, int portid)
{
	unsigned lcore_id = rte_lcore_id();
	unsigned n;
	struct lcore_conf *conf;
	struct fpn_txq *txq;
	int error = 0;

	if (unlikely(fpn_check_port(portid)<0)) {
		error = -1;
		goto fail;
	}

	if (unlikely(m_get_tx_l4cksum(m))) {
		char *ip_h;
		void *l4_h;
		uint16_t *l4_cksum;
		uint16_t tx_ofl_capa;
		uint16_t dummy_cksum;
		uint8_t l3h_len;
		int hard_cksum;
#define l2h_len sizeof(struct ether_hdr)

		tx_ofl_capa = fpn_port_shmem->port[portid].tx_offload_capa;

		/*
		 * 1) Assumes that L2/L3/L4 headers are in first mbuf.
		 * 2) Assumes that packet is not encapsulated:
		 *    no VLAN, no MPLS, etc.
		 * 3) Assumes IPv4 only for now.
		 */
		ip_h = mtod(m, char *) + sizeof(struct ether_hdr);
		l3h_len = (*ip_h & 0xF) * 4;
		l4_h = ip_h + l3h_len;
		switch (ip_h[9]) { /* Next protocol identifier */
		case IPPROTO_TCP:
			l4_cksum = &((struct tcp_hdr *)l4_h)->cksum;
			hard_cksum = (tx_ofl_capa & FPN_OFFLOAD_TX_TCP_CKSUM);
			break;

		case IPPROTO_UDP:
			l4_cksum = &((struct udp_hdr *)l4_h)->dgram_cksum;
			hard_cksum = (tx_ofl_capa & FPN_OFFLOAD_TX_UDP_CKSUM);
			break;

		default:
			l4_cksum = &dummy_cksum;
			hard_cksum = 0;
			break;
		}
		if (likely(hard_cksum)) {
			*l4_cksum = fpn_ip_phdr_cksum((struct fpn_ip_hdr *)ip_h);
            MBUF_DPDK_HWOFFLOAD(&(m)->c.rtemb).l2_len = l2h_len;
            MBUF_DPDK_HWOFFLOAD(&(m)->c.rtemb).l3_len = l3h_len;
		} else {
			m_reset_tx_l4cksum(m);
			*l4_cksum = 0;
			*l4_cksum = fpn_in4_l4cksum_at_offset(m, l2h_len);
		}
	}

	FPN_DPDK_DEBUG_RX("send pkt %d\n", portid);

	conf = &lcore_conf[lcore_id];
	txq= &conf->txq[portid];
	n = txq->m_table_len;
	txq->m_table[n] = &m->c.rtemb;
	txq->m_table_len++;

	M_TRACK(m, "IF_SEND");
	M_TRACK_UNTRACK(m);

	/* enough pkts to be sent */
	if (unlikely(n == (MAX_PKT_BURST-1))) {
		fpn_rte_drain_txq(txq, portid);
	}

	return 0;

fail:
	m_freem(m);
	return error;
}

/* Send immediately the packet on an output interface */
static inline int
__fpn_send_packet_nowait(struct mbuf *m, int portid)
{
	unsigned lcore_id = rte_lcore_id();
	unsigned n;
	struct lcore_conf *conf;
	struct fpn_txq *txq;
	int error = 0;

	if (unlikely(fpn_check_port(portid)<0)) {
		error = -1;
		goto fail;
	}


	FPN_DPDK_DEBUG_RX("send pkt nowait %d\n", portid);

	conf = &lcore_conf[lcore_id];
	txq= &conf->txq[portid];
	n = txq->m_table_len;
	txq->m_table[n] = &m->c.rtemb;
	txq->m_table_len++;

	M_TRACK(m, "IF_SEND");
	M_TRACK_UNTRACK(m);

	fpn_rte_drain_txq(txq, portid);

	return 0;

fail:
	m_freem(m);
	return error;
}

extern int fpn_main_loop(void *);
extern void __fpn_send_exception(struct mbuf *m, uint8_t port);
extern int fpn_send_packet_nofree(struct mbuf *m, uint8_t port);
extern void fpn_dump_pools(void);
extern unsigned fpn_get_rxqueue_number(unsigned portid);
extern unsigned fpn_get_txqueue_number(__attribute__((unused)) unsigned portid);

extern void fpn_dump_pools_info(char* buff, int32_t size);

struct fp_pci_netdev {
	char name[IFNAMSIZ];
	uint16_t domain;
	uint8_t bus;
	uint8_t devid;
	uint8_t function;
	uint32_t portid;
	struct fp_pci_netdev* next;
};

extern struct fp_pci_netdev* fp_netdev_list;

#if defined(CONFIG_MCORE_FPVI_TAP)
extern int start_rx_excep_lcore(__attribute__((unused)) void *arg);
#endif /*CONFIG_MCORE_FPVI_TAP*/

#endif /* __FPN_DPDK_H__ */
