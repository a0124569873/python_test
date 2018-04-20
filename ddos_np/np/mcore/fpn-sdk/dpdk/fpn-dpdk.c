/*
 * Copyright(c) 2010  6WIND
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <sys/queue.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "fpn.h"
#ifdef CONFIG_MCORE_FPN_CRYPTO
#include "fpn-crypto.h"
#endif
#include "fpn-eth.h"

#ifdef CONFIG_MCORE_FPN_GC
#include "fpn-gc.h"
#endif

#if defined(CONFIG_MCORE_FPVI_DP)
#include "fpn-dpvi-dpdk.h"
#include "fpn-dpvi-ring-func.h"
static struct fpn_dpvi_shmem *fpn_dpvi_shmem = NULL;
#endif /*CONFIG_MCORE_FPVI_DP*/

#if defined(CONFIG_MCORE_FPVI_TAP)
#include "fpn-tuntap-dpdk.h"
#endif

#ifdef CONFIG_MCORE_INTERCORE
#include "fpn-intercore.h"
#endif

#ifdef CONFIG_MCORE_SW_TCP_LRO
#include "fpn-sw-tcp-lro.h"
#endif

#include <sys/ioctl.h>
#include <linux/if_arp.h>

#define ETHTOOL_GDRVINFO        0x00000003 /* Get driver info. */
#define SIOCETHTOOL 0x8946

#define ETHTOOL_FWVERS_LEN      32
#define ETHTOOL_BUSINFO_LEN     32

struct fp_pci_netdev* fp_netdev_list = NULL;

#define MBUF_RXDATA_SIZE 2048
#define MBUF_SIZE (MBUF_RXDATA_SIZE + sizeof(struct mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF_DEFAULT 16384

#define RX_PTHRESH_IGB    8  /**< RX prefetch threshold reg.   for igb.   */
#define RX_HTHRESH_IGB    8  /**< RX host threshold reg.       for igb.   */
#define RX_WTHRESH_IGB   16  /**< RX write-back threshold reg. for igb.   */
#define RX_FTHRESH_IXGBE 64  /**< RX free threshold reg.       for ixgbe. */

#undef RX_WTHRESH_IGB
#define L2FWD_RX_WTHRESH_IGB 4
#define RX_WTHRESH_IGB L2FWD_RX_WTHRESH_IGB

#define TX_PTHRESH_IGB    8  /**< TX prefetch threshold reg    for igb.   */
#define TX_HTHRESH_IGB    4  /**< TX host threshold reg.       for igb.   */
#define TX_WTHRESH_IGB   16  /**< TX write-back threshold reg. for igb.   */
#define TX_PTHRESH_IXGBE 36  /**< TX prefetch threshold reg    for ixgbe. */

#define IXGBE_QSTATS_REGS_MAX 16

#define SOCKET0 0

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t fpn_nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t fpn_nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* shared configuration for the ports */
FPN_DEFINE_SHARED(port_mem_t *, fpn_port_shmem);
/* mask of enabled physical ports */
static uint64_t enabled_phys_port_mask = 0;
uint64_t sys_tsc = 0;

/* this array tells us which driver is in use */
struct fpn_rte_port fpn_rte_ports[FPN_MAX_PORTS];

/* exported variable for fpdebug cmdline */
int fpn_cmdline_lcore = -1;

int fpn_anti_ddos_lcore = -1;

int (*fpn_anti_ddos_proc)(__attribute__((unused)) void *arg) = NULL;

#if defined(CONFIG_MCORE_FPVI_TAP)
/* exported variable for exception processing */
int fpn_exception_lcore = -1;
#endif
/*
 * This is linked to an extra option used for specifying a lcore
 * dedicated to poll some configuration. The polling function
 * is invoked in the fastpath and thus must be known by the
 * fastpath only.
 */
int fpn_config_polling_lcore = -1;
static int fpn_use_autoconf = 0;
static unsigned int fpn_1gb_rx_queue_per_lcore = 8;
static unsigned int fpn_10gb_rx_queue_per_lcore = 1;
static unsigned int fpn_rx_queue_per_port = 1;
static unsigned fpn_nb_mbuf = NB_MBUF_DEFAULT;
fpn_cpumask_t fpn_linux2fp_mask;
static fpn_cpumask_t dpvi_mask;
static fpn_cpumask_t stats_mask;
static fpn_cpumask_t fpn_online_mask;
/* Mask of cores that actually receive network packets from NICs. */
fpn_cpumask_t fpn_rx_cores_mask;

uint64_t fpn_rte_tsc_hz;

unsigned int fpn_nb_ports;

struct lcore_conf lcore_conf[RTE_MAX_LCORE];
struct fpn_rte_s_port_table fpn_rte_port_table;

#if defined(CONFIG_MCORE_FPVI_DP)
/* time between stats and link update */
#define TIMER_STATS_MS 1000

#ifdef CONFIG_MCORE_DPDK_RESET_VF
struct restarting_ports fpn_restarting_ports[FPN_MAX_CORES];
#endif

/* timer used to poll link */
static struct callout link_timer;
static unsigned link_timer_ms;

/* pthread that will handle stats gathering */
pthread_t stats_thread;
#endif

#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
int fpn_rxq_shared[FPN_MAX_PORTS];
int fpn_txq_shared[FPN_MAX_PORTS];
#endif

struct fpn_rte_fdir_conf
{
	FPN_TAILQ_ENTRY(fpn_rte_fdir_conf) next;
	int portid;
	struct rte_fdir_conf conf;
};
FPN_TAILQ_HEAD(fpn_rte_fdir_list, fpn_rte_fdir_conf);
static struct fpn_rte_fdir_list rte_fdir_list =
				FPN_TAILQ_HEAD_INITIALIZER(rte_fdir_list);

static struct rte_eth_conf base_port_conf = {
#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
	.link_speeds = ETH_LINK_SPEED_AUTONEG,
#else
	.link_autoneg = 1,
#endif	
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 1, /**< IP checksum offload enabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC not stripped by hardware */
		.mq_mode        = ETH_MQ_RX_RSS, /**< Enable RSS */
#if BUILT_DPDK_VERSION >= DPDK_VERSION(1,7,1)
		.enable_scatter = 1, /**< Enable scattered rx */
#endif
	},
	.txmode = {
		.mq_mode = ETH_DCB_NONE,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = 0,
		},
	},
};

/* e1000 em has not been benchmarked - values are only functional */
static const struct rte_eth_rxconf rx_conf_em = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH_IGB,
		.hthresh = RX_HTHRESH_IGB,
		.wthresh = RX_WTHRESH_IGB,
	},
};

static struct rte_eth_rxconf rx_conf_igb = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH_IGB,
		.hthresh = RX_HTHRESH_IGB,
		.wthresh = 0, /*change to 0 for firewall performance test*/
	},
	.rx_free_thresh = 32,
};

static const struct rte_eth_rxconf rx_conf_ixgbe = {
	.rx_free_thresh = RX_FTHRESH_IXGBE,
};

/* e1000 em has not been benchmarked - values are only functional */
static const struct rte_eth_txconf tx_conf_em = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH_IXGBE,
	},
};

static struct rte_eth_txconf tx_conf_igb = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH_IGB,
		.hthresh = TX_HTHRESH_IGB,
		.wthresh = 0, /*change to 0 for firewall performance test*/
	},
};

static const struct rte_eth_txconf tx_conf_ixgbe = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH_IXGBE,
	},
};

static const struct rte_eth_txconf tx_conf_virtio = {
	.txq_flags = ETH_TXQ_FLAGS_NOOFFLOADS,
};

static const struct rte_eth_txconf tx_conf_vmxnet3 = {
	.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
};

#if BUILT_DPDK_VERSION >= DPDK_VERSION(1,7,1)
#define  RX_PTHRESH_I40E 8
#define  RX_HTHRESH_I40E 8
#define  RX_WTHRESH_I40E 0

#define  RX_FREETHRESH_I40E   32


#define TX_PTHRESH_I40E   32  /**< TX prefetch threshold reg    for i40e.   */
#define TX_HTHRESH_I40E   0  /**< TX host threshold reg.       for i40e.   */
#define TX_WTHRESH_I40E   0  /**< TX write-back threshold reg. for i40e.   */
#define TX_FREE_THRESH_I40E  32
#define TX_RSBIT_I40E  32


static const struct rte_eth_rxconf rx_conf_i40e = {
	.rx_thresh = {
			.pthresh = RX_PTHRESH_I40E,
			.hthresh = RX_HTHRESH_I40E,
			.wthresh = RX_WTHRESH_I40E,
		},
		.rx_free_thresh = RX_FREETHRESH_I40E,
		.rx_drop_en = 0,
};

static struct rte_eth_txconf tx_conf_i40e = {
	.tx_thresh = {
			.pthresh = TX_PTHRESH_I40E,
			.hthresh = TX_HTHRESH_I40E,
			.wthresh = TX_WTHRESH_I40E,
		},
		.tx_free_thresh = TX_FREE_THRESH_I40E,
		.tx_rs_thresh = TX_RSBIT_I40E,
};

#endif

RTE_DEFINE_PER_LCORE(struct rte_mempool *, fpn_pktmbuf_pool);

/* rate-limited printf (rate limit is per-lcore to avoid concurrent
 * access) */
int fpn_printf_ratelimited(const char *format, ...)
{
	static uint64_t prev_print_cycles[FPN_MAX_CORES];
	va_list ap;
	int ret;
	uint64_t tsc;
	unsigned lcore_id = rte_lcore_id();

	tsc = rte_rdtsc();
	/* only every 100ms */
	if ((10 * (tsc - prev_print_cycles[lcore_id])) < fpn_rte_tsc_hz)
		return 0;

	prev_print_cycles[lcore_id] = tsc;
	va_start(ap, format);
	ret = vprintf(format, ap);
	va_end(ap);
	return ret;
}

static void fpn_pktmbuf_init(struct rte_mempool *mp,
			     __attribute__((unused)) void *opaque_arg,
			     void *_m,
			     __attribute__((unused)) unsigned i)
{
	struct rte_mbuf *m = _m;

	/* derived from rte_pktmbuf_init(), this is needed to add a
	 * priv field in packet */

	memset(m, 0, mp->elt_size);

	/* start of buffer is just after mbuf structure */
	m->buf_addr = (char *)m + sizeof(struct mbuf);
	m->buf_physaddr = rte_mempool_virt2phy(mp, m) + sizeof(struct mbuf);
	m->buf_len = mp->elt_size - sizeof(struct mbuf);

	/* keep some headroom between start of buffer and data */
	MBUF_DPDK_DATA_OFFSET_SET(m, RTE_PKTMBUF_HEADROOM);

	/* init some constant fields */
	MBUF_DPDK_SET_PKT_TYPE(m);
	m->pool = mp;
	MBUF_DPDK_NBSEGS(m) = 1;
	MBUF_DPDK_IN_PORT(m) = 0xff;

#if BUILT_DPDK_VERSION > DPDK_VERSION(1, 7, 1)
	/* start of buffer is after mbuf structure and priv data */
	m->priv_size = rte_pktmbuf_priv_size(mp);
	/* keep some headroom between start of buffer and data */
	m->data_off = RTE_MIN(RTE_PKTMBUF_HEADROOM, (uint16_t)m->buf_len);
	rte_mbuf_refcnt_set(m, 1);	
	m->next = NULL;
#endif
}

static void fpn_pktmbuf_pool_init(struct rte_mempool *mp,
				  __attribute__((unused)) void *opaque_arg)
{
	struct rte_pktmbuf_pool_private *mbp_priv;

	mbp_priv = rte_mempool_get_priv(mp);
	mbp_priv->mbuf_data_room_size = MBUF_RXDATA_SIZE + RTE_PKTMBUF_HEADROOM;
}

static int
fpn_per_lcore_mbufpool_init(void *lcore_mp)
{
	struct rte_mempool *mp;

	mp = (struct rte_mempool *)lcore_mp;
	RTE_PER_LCORE(fpn_pktmbuf_pool) = mp;
	return 0;
}

/**
 * Make each logical core of the socket "sock_id" initialize
 * its per core mbuf pool.
 */
static void
fpn_lcores_mbufpool_init(unsigned sock_id, struct rte_mempool *mp)
{
	unsigned lcore_id;

	RTE_LCORE_FOREACH(lcore_id) {
		if (rte_lcore_to_socket_id(lcore_id) != sock_id)
			continue;
		if (lcore_id != rte_get_master_lcore()) {
			rte_eal_remote_launch(fpn_per_lcore_mbufpool_init, mp,
					      lcore_id);
			(void) rte_eal_wait_lcore(lcore_id);
		} else
			/* Must directly invoke the function on master core */
			(void) fpn_per_lcore_mbufpool_init(mp);
	}
}

static inline void
fpn_mbufpool_name_build(unsigned sock_id, char* mp_name, int name_size)
{
	snprintf(mp_name, name_size, "mbuf_pool_socket_%u", sock_id);
}

static struct rte_mempool *
fpn_socket_mbufpool_find(unsigned sock_id)
{
	char pool_name[RTE_MEMPOOL_NAMESIZE];

	fpn_mbufpool_name_build(sock_id, pool_name, sizeof(pool_name));
	return (rte_mempool_lookup((const char *)pool_name));
}

/**
 * Create a mbuf pool for the socket and make each logical core
 * of the socket initialize its per core mbuf pool with the new mbuf pool.
 */
static void
fpn_socket_mbufpool_create(unsigned sock_id)
{
	struct rte_mempool *mp;
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	unsigned lcore_id;
	unsigned nb_cores;
	unsigned nb_sock_cores;
	unsigned nb_mbufs;

	/*
	 * First determine the number of logical cores in the socket,
	 * and compute the proportion of mbufs to allocate in
	 * the mbuf pool associated with this socket.
	 */
	nb_cores = 0;
	nb_sock_cores = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		if (lcore_id == (unsigned)fpn_cmdline_lcore)
			continue;

		if (lcore_id == (unsigned)fpn_anti_ddos_lcore)
			continue;

		nb_cores++;
		if (rte_lcore_to_socket_id(lcore_id) == sock_id)
			nb_sock_cores++;
	}
	nb_mbufs = (fpn_nb_mbuf * nb_sock_cores) / nb_cores;

	/*
	 * Then, create the pool of mbuf associated with the socket.
	 */
	fpn_mbufpool_name_build(sock_id, pool_name, sizeof(pool_name));
	mp = rte_mempool_create(pool_name, nb_mbufs,
				MBUF_SIZE, 128,
				sizeof(struct rte_pktmbuf_pool_private),
				fpn_pktmbuf_pool_init, NULL,
				fpn_pktmbuf_init, NULL,
				sock_id, 0);
	if (mp == NULL)
		mp = rte_mempool_lookup(pool_name);

	if (mp == NULL)
		rte_panic("Cannot create mbuf pool for socket %u\n", sock_id);

	/*
	 * Finally, make each logical core of the new socket initialize
	 * its per core mbuf pool.
	 */
	fpn_lcores_mbufpool_init(sock_id, mp);
}

/**
 * Determine the set of sockets of all logical cores and invoke the
 * function "func" given in argument for each socket.
 */
static void
fpn_exec_for_each_socket(void (*func)(unsigned sock_id))
{
	unsigned lcore_id;
	unsigned sock_id;
	unsigned socket_mask;

	socket_mask = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		if (lcore_id == (unsigned)fpn_cmdline_lcore)
			continue;
		sock_id = rte_lcore_to_socket_id(lcore_id);
		if ((socket_mask & (1u << sock_id)) == (1u << sock_id))
			continue;
		/*
		 * New socket.
		 */
		socket_mask |= (1u << sock_id);
		(*func)(sock_id);
	}
}

static void
fpn_mbufpool_create(void)
{
	/*
	 * Create a mbuf pool for each socket and make
	 * each logical core of the same socket initialize its per core
	 * mbuf pool with the socket mbuf pool.
	 */
	fpn_exec_for_each_socket(fpn_socket_mbufpool_create);
}

static void
fpn_socket_mbufpool_dump(unsigned sock_id)
{
	struct rte_mempool *mp;

	mp = fpn_socket_mbufpool_find(sock_id);
	if (mp != NULL)
#if BUILT_DPDK_VERSION < DPDK_VERSION(1,7,0)
		rte_mempool_dump(mp);
#else
		rte_mempool_dump(stdout, mp);
#endif
	else
		printf("Cannot dump mbuf pool for socket %u - lookup failed\n",
		       sock_id);
}

void fpn_dump_pools(void)
{
	fpn_exec_for_each_socket(fpn_socket_mbufpool_dump);
}

void fpn_dump_pools_info(char* buf, int32_t size) {
	unsigned lcore_id;
	unsigned sock_id;
	unsigned socket_mask;
	char* ptr = buf;
	int32_t len = size;

	socket_mask = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		if (lcore_id == (unsigned)fpn_cmdline_lcore)
			continue;

		sock_id = rte_lcore_to_socket_id(lcore_id);
		if ((socket_mask & (1u << sock_id)) == (1u << sock_id))
			continue;
		/*
		 * New socket.
		 */
		socket_mask |= (1u << sock_id);
		{
			struct rte_mempool *mp;
			int n = 0;
			unsigned cache_count = 0;
			unsigned common_count = 0;

			mp = fpn_socket_mbufpool_find(sock_id);
			if (!mp) {
				continue;
			}

			n = snprintf(ptr, len, "mempool <%s>@%p\n", mp->name, mp);
			if (n <= 0 || n >= len) {
				continue;
			}
			ptr += n;
			len -= n;

			{
				int c = 0;
				for (c = 0; c < RTE_MAX_LCORE; c++) {
					if (!rte_lcore_is_enabled(c)) {
					    continue;
					}

					cache_count += mp->local_cache[c].len;
					if (mp->local_cache[c].len <= 0) {
						continue;
					}

					n = snprintf(ptr, len, "    cache_count[%u]=%"PRIu32"\n",c, mp->local_cache[c].len);
					if (n <= 0 || n >= len) {
						continue;
					}

					ptr += n;
					len -= n;
				}
			}

			common_count = rte_mempool_ops_get_count(mp);
			if ((cache_count + common_count) > mp->size)
				common_count = mp->size - cache_count;

			n = snprintf(ptr, len, " common_pool_count=%u\n", common_count);
			if (n <= 0 || n >= len) {
				continue;
			}

			ptr += n;
			len -= n;
		}
	}
}

/* return the number of RX queues for a given port */
unsigned
fpn_get_rxqueue_number(unsigned portid)
{
	struct lcore_conf *conf;
	unsigned nb_rx_q;
	unsigned lcore_id;
	unsigned i;

#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
	if (fpn_rxq_shared[portid])
		return 1; /* Only 1 shared rxq0 for now */
#endif
	nb_rx_q = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if ((unsigned)fpn_anti_ddos_lcore == lcore_id) {
			continue;
		}

		conf = &lcore_conf[lcore_id];
		for (i = 0; i < conf->n_rx_queue; i++) {
			if (conf->rxq[i].port_id == portid)
				nb_rx_q++;
		}
	}
	return nb_rx_q;
}

/* return the number of TX queues for a given port */
unsigned
fpn_get_txqueue_number(__attribute__((unused)) unsigned portid)
{
#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
	if (fpn_txq_shared[portid])
		return 1;  /* Only 1 shared txq0 for now */
#endif
	//return (unsigned) rte_lcore_count();
	struct rte_eth_dev_info dev_info;
	unsigned nlcore = (unsigned)rte_lcore_count();
	rte_eth_dev_info_get(portid, &dev_info);
	if(dev_info.max_tx_queues <= nlcore)
		return dev_info.max_tx_queues;
	else
		return nlcore;
}

#if defined(CONFIG_MCORE_FPVI_DP)
#if defined(CONFIG_MCORE_DPDK_RESET_VF)
static int
ixgbevf_detect_pf_reset(int portid, struct rte_eth_link *lnk)
{
	static int pf_reset_seen[FPN_MAX_PORTS] = { 0 };

	/* if PF has reset, then check_link in ixgbe_vf.c fails and
	 * ixgbe_dev_link_update sets speed to 100 and duplex to half */
	if (!lnk->link_status && (lnk->link_speed == ETH_LINK_SPEED_100) &&
	    (lnk->link_duplex == ETH_LINK_HALF_DUPLEX)) {
		pf_reset_seen[portid] = 1;
	}
	/* only restart once pf looks ready */
	else if (pf_reset_seen[portid]) {
		printf("port %d PF has gone through reset, asking for port "
		       "restart\n", portid);
		pf_reset_seen[portid] = 0;
		return 1;
	}

	return 0;
}

/* this function reenables a port and notify previous core */
static void
stop_port_restart(void *arg)
{
	struct restarting_port *port = (struct restarting_port *)arg;
	int cur = ((struct restarting_ports *)arg - fpn_restarting_ports);
	int prev;
	int portid = (port - fpn_restarting_ports[cur].ports);
	/* remember this port is usable for fpn_check_port() */
	port->state = 0;

	FPN_DPDK_DEBUG("core %d: port %d restart has finished\n", cur, portid);

	/* find previous core */
	for (prev = cur - 1; prev >= 0; prev--) {
		if (fpn_cpumask_ismember(&fpn_coremask, prev)) {
			struct restarting_port *prev_arg =
			       &fpn_restarting_ports[prev].ports[portid];
			callout_init(&prev_arg->timer);
			callout_bind(&prev_arg->timer, prev);
			callout_reset_millisec(&prev_arg->timer, 0,
			                       stop_port_restart, prev_arg);
			return;
		}
	}

	FPN_DPDK_DEBUG("port %d restart has finished\n", portid);
}

/* this function marks a port as restarting and notify next core.
 * when last core is reached, port is restarted */
static void
start_port_restart(void *arg)
{
	struct restarting_port *port = (struct restarting_port *)arg;
	int cur = ((struct restarting_ports *)arg - fpn_restarting_ports);
	int next;
	int portid = (port - fpn_restarting_ports[cur].ports);
	/* remember this port is unusable for fpn_check_port() */
	port->state = 1;

	FPN_DPDK_DEBUG("core %d: port %d will be restarted\n", cur, portid);

	/* find next core */
	for (next = cur + 1; next < FPN_MAX_CORES; next++) {
		if (fpn_cpumask_ismember(&fpn_coremask, next)) {
			struct restarting_port *next_arg =
			       &fpn_restarting_ports[next].ports[portid];
			callout_init(&next_arg->timer);
			callout_bind(&next_arg->timer, next);
			callout_reset_millisec(&next_arg->timer, 0,
			                       start_port_restart, next_arg);
			return;
		}
	}

	/* we are the last one */
	rte_eth_dev_stop(portid);
	if (!rte_eth_dev_start(portid)) {
		printf("port %d has been restarted\n", portid);
	}
	else {
		printf("could not restart port %d\n", portid);
	}

	/* ok, let's notify all other cores */
	stop_port_restart(arg);
}
#endif

/* this callback is called within a non-fastpath pthread */
static void *get_stats_cb(__attribute__((unused)) void *arg)
{
	struct fpn_port *shm_port;
	struct rte_eth_stats *stats;
	struct rte_eth_link *link;
	int portid;
	int statsport = 0;

loop:
	for (portid = 0; portid < FPN_MAX_PORTS; portid ++) {
		shm_port = &fpn_port_shmem->port[portid];
		stats = &fpn_rte_ports[portid].stats;
		link = &fpn_rte_ports[portid].link;

		/* if port is not enabled, skip */
		if (shm_port->enabled == 0)
			continue;
		if (shm_port->dpvi_managed == 0)
			continue;

		/* fill link status */
		rte_eth_link_get_nowait(portid, link);

		/* fill statistics only for statsport */
		if (statsport != portid)
			continue;

		rte_eth_stats_get(statsport, stats);
		shm_port->ipackets = stats->ipackets;
		shm_port->opackets = stats->opackets;
		shm_port->ibytes   = stats->ibytes;
		shm_port->obytes   = stats->obytes;
		shm_port->ierrors  = stats->ierrors;
		shm_port->oerrors  = stats->oerrors;
	}

	statsport++;
	if (statsport == FPN_MAX_PORTS)
		statsport = 0;

	usleep(1000*link_timer_ms);
	goto loop;

	return NULL;
}

static int create_stats_thread(void)
{
	int ret;
	unsigned int i;
	__typeof__(errno) err;
	size_t size;
	cpu_set_t *cpusetp;
#if defined(CPU_ALLOC)
	cpusetp = CPU_ALLOC(RTE_MAX_LCORE);
	if (!cpusetp)
		return -1;

	size = CPU_ALLOC_SIZE(RTE_MAX_LCORE);
	CPU_ZERO_S(size, cpusetp);
#else
	cpu_set_t cpuset;

	cpusetp = &cpuset;
	size = sizeof(cpuset);
	CPU_ZERO(cpusetp);
#endif

	for (i = 0; i < RTE_MAX_LCORE; i++) {
		if (fpn_cpumask_ismember(&stats_mask, i)) {
#if defined(CPU_ALLOC)
			CPU_SET_S(i, size, cpusetp);
#else
			CPU_SET(i, cpusetp);
#endif
		}
	}

	ret = 0;
	if ((err = pthread_create(&stats_thread, NULL, get_stats_cb, NULL))) {
		printf("could not create stats thread: %s\n", strerror(err));
		ret = -1;
	}
	else if ((err = pthread_setaffinity_np(stats_thread, size, cpusetp))) {
		void *retval;

		printf("could not set affinity on stats thread: %s\n", strerror(err));
		pthread_kill(stats_thread, SIGTERM);
		pthread_join(stats_thread, &retval);

		ret = -1;
	}

#if defined(CPU_ALLOC)
	CPU_FREE(cpusetp);
#endif
	return ret;
}

/*
 * Called by a timer. This function polls link status for
 * all ports and save the result in shared memory.
 *
 * FIXME: this callback must run on 'master' core for VF reset mechanism to
 * work.
 */
static void link_timer_cb(__attribute__((unused)) void *arg)
{
	struct fpn_port *shm_port;
	struct rte_eth_link *link;
	uint new_speed, new_full_duplex, new_link;
	uint port_changed, state_changed = 0;
	int portid;
#ifdef CONFIG_MCORE_DPDK_RESET_VF
	unsigned master = rte_lcore_id();
#endif

	for (portid = 0; portid < FPN_MAX_PORTS; portid ++) {
		shm_port = &fpn_port_shmem->port[portid];

		/* if port is not enabled, skip */
		if (shm_port->enabled == 0)
			continue;
		if (shm_port->dpvi_managed == 0)
			continue;
#ifdef CONFIG_MCORE_DPDK_RESET_VF
		/* no need to check it as long as it is restarting */
		if (fpn_restarting_ports[master].ports[portid].state)
			continue;
#endif

		link = &fpn_rte_ports[portid].link;
		new_speed = link->link_speed;
		if (link->link_duplex == ETH_LINK_FULL_DUPLEX)
			new_full_duplex = 1;
		else
			new_full_duplex = 0;
		new_link = link->link_status;

#ifdef CONFIG_MCORE_DPDK_RESET_VF
		if ((fpn_rte_ports[portid].driver == RTE_IXGBEVF) &&
		    (ixgbevf_detect_pf_reset(portid, link))) {
			start_port_restart(
			      &fpn_restarting_ports[master].ports[portid]);
		}
#endif

		/* check if some state was changed */
		port_changed = (shm_port->speed != new_speed) ||
		               (shm_port->full_duplex != new_full_duplex) ||
		               (shm_port->link != new_link);
		if (port_changed) {
			shm_port->speed       = new_speed;
			shm_port->full_duplex = new_full_duplex;
			shm_port->link        = new_link;
		}
		state_changed |= port_changed;
	}

	/* and notify DPVI if some change is detected */
	if (state_changed) {
		fpn_dpvi_send_status();
	}

	/* re-schedule the link timer */
	callout_schedule_millisec(&link_timer, link_timer_ms);
}

static struct fpn_dpvi_ops dpvi_ops = {
	.ethtool_get_drvinfo = fpn_dpvi_ethtool_get_drvinfo,
	.ethtool_get_settings   = fpn_dpvi_ethtool_get_settings,
	.ethtool_get_sset_count = fpn_dpvi_ethtool_get_sset_count,
	.ethtool_get_strings    = fpn_dpvi_ethtool_get_strings,
	.ethtool_get_statsinfo  = fpn_dpvi_ethtool_get_statsinfo,
	.ethtool_get_pauseparam = fpn_dpvi_ethtool_get_pauseparam,
	.ethtool_set_pauseparam = fpn_dpvi_ethtool_set_pauseparam,
};
#endif /*CONFIG_MCORE_FPVI_DP*/

/* display usage */
static void
fpn_usage(const char *prgname)
{
	printf("%s [EAL options] -- [-c LCORE_ID]\n"
	       "            [-q|--pmd-82576-q NQ_1GB]\n"
	       "            [-Q|--pmd-82599-q NQ_10GB]\n"
	       "            [--rxq-per-port RXQ_PER_PORT]\n"
	       "            [--nb-mbuf NB_MBUF]\n"
	       "            [-d]\n"
	       "            [-s LCORE_ID]\n"
#if defined(CONFIG_MCORE_FPVI_DP)
	       "            [-e DPVIMASK]\n"
#elif defined(CONFIG_MCORE_FPVI_TAP)
	       "            [-x LCORE_ID]\n"
#endif
#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
	       "            [--rxq-shared=PORTMASK]\n"
	       "            [--txq-shared=PORTMASK]\n"
#endif
	       "  --fdir-conf=PER_PORT_FDIR_CONF\n"
	       "\n"
	       "  -c LCORE_ID: enable cmdline on the specified lcore\n"
	       "  -q|--pmd-82576-q NQ: number of queue for 82576 1GB ports per lcore (default is 8)\n"
	       "  -Q|--pmd-82599-q NQ: number of queue for 82599 10GB ports per lcore (default is 1)\n"
	       "  --rxq-per-port: number of queues per non-1GB ports (default is 1)\n"
	       "  --nb-mbuf N: number of mbufs in pool\n"
	       "  -t: provide full lcore/port mapping (don't use with -q/-Q)\n"
#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	       "  -T: provide crypto parameters to rte_crypto drivers\n"
#endif
	       "  -l: mask of lcore that can receive packets from linux (default=all)\n"
	       "  --nb-rxd: number of descriptors in rx rings (default=128)\n"
	       "  --nb-txd: number of descriptors in tx rings (default=512)\n"
	       "  --igb-rxp: prefetch threshold of igb rx rings (default=8)\n"
	       "  --igb-rxh: host threshold of igb rx rings (default=8)\n"
	       "  --igb-rxw: write-back threshold of igb rx rings (default=16)\n"
	       "  --igb-txp: prefetch threshold of igb tx rings (default=8)\n"
	       "  --igb-txh: host threshold of igb tx rings (default=4)\n"
	       "  --igb-txw: write-back threshold of igb tx rings (default=16)\n"
	       "  -s LCORE_ID: enable polling of configuration messages on the specified lcore\n"
#if defined(CONFIG_MCORE_FPVI_DP)
	       "  -e DPVIMASK: cpu mask dedicated to exceptions (default is all except fp mask\n"
#elif defined(CONFIG_MCORE_FPVI_TAP)
	       "  -x LCORE_ID: enable FPVI tun/tap processing on the specified lcore\n"
#endif
#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
	       "  --rxq-shared=PORTMASK: enable RX queues to be shared on a per port basis\n"
	       "  --txq-shared=PORTMASK: enable TX queues to be shared on a per port basis\n"
#endif
	       "  --fdir-conf=([portid|all]=)perfect/64k/noreport/29/127\n"
	       "  -d: enable debug\n\n"
	       "All core masks can be set using one of the following formats:\n"
	       "  - A bitmask in hex format : 0xnnnn\n"
	       "  - A list of cores : c1[-c2][,c3[-c4]]\n"
	       "    where c1,c2,c3,... are core indexes between 0 and %d\n"
	       , prgname, FPN_MAX_CORES-1);
}

static void fpn_port_netdev(struct rte_pci_addr *addr, char *name, int len)
{
	FILE *fp;
	char filename[256];
	int i;

	if (name == NULL)
		return;

	/* Clear name */
	memset(name, 0, len);

	/* Build file name */
	snprintf(filename, sizeof(filename), "/var/run/fast-path/bound/%4.4x:%2.2x:%2.2x.%x/netdev",
	         addr->domain, addr->bus, addr->devid, addr->function);

	/* Get netdev name */
	fp = fopen(filename, "r");
	if (!fp)
		return;

	/* Read name */
	if (fread(name, 1, len, fp) == 0)
		return;

	fclose(fp);

	/* Stop at first \n or \r */
	for (i=0 ; (i<len-1) && (name[i] != 0) &&
	           (name[i] != '\n') && (name[i] != '\r') ; i++);

	/* Ensure string is terminated */
	name[i]=0;
}

static inline int
fpn_check_portmask(unsigned long int pm)
{
	if (pm == 0)
		return -1;

	/* Check that the portmask only contains probed ports */
	if ((pm | enabled_phys_port_mask) != enabled_phys_port_mask) {
		printf("invalid portmask 0x%lx (should be included"
		       " in mask of probed ports 0x%"PRIx64"\n",
		       pm, enabled_phys_port_mask);
		return -1;
	}

	return 0;
}

#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
static int
fpn_parse_rxq_shared_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;
	int portid;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (fpn_check_portmask(pm) < 0)
		return -1;

	/* update flag in shared memory */
	for (portid = 0; portid < FPN_MAX_PORTS; portid++)
		if (pm & (1u << portid))
			fpn_rxq_shared[portid] = 1;
		else
			fpn_rxq_shared[portid] = 0;

	printf("RX queue is shared for port mask 0x%"PRIx64"\n", pm);

	return 0;
}

static int
fpn_parse_txq_shared_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;
	int portid;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (fpn_check_portmask(pm) < 0)
		return -1;

	/* update flag in shared memory */
	for (portid = 0; portid < FPN_MAX_PORTS; portid++)
		if (pm & (1u << portid))
			fpn_txq_shared[portid] = 1;
		else
			fpn_txq_shared[portid] = 0;

	printf("TX queue is shared for port mask 0x%"PRIx64"\n", pm);

	return 0;
}
#endif

/* return 0 if the integer is in [min,max] (in this case, *ret is
 * filled with the value), else -1 on error */
static int
fpn_parse_uint(const char *q_arg, unsigned min, unsigned max, int *ret,
	       unsigned base)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, base);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n < min)
		return -1;
	if (n > max)
		return -1;

	*ret = n;
	return 0;
}

/* return 0 if the integer is in [min,max] (in this case, *ret is
 * filled with the value), else -1 on error */
static int __fpn_maybe_unused
fpn_parse_uint64(const char *q_arg, uint64_t min, uint64_t max, uint64_t *ret,
	         unsigned base)
{
	char *end = NULL;
	unsigned long long n;

	/* parse hexadecimal string */
	n = strtoull(q_arg, &end, base);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n < min)
		return -1;
	if (n > max)
		return -1;

	*ret = n;
	return 0;
}

static int
fpn_parse_rss_ports(unsigned lcoreid, const char *t_arg)
{
	struct lcore_conf *conf;
	const char *s = t_arg;
	int i;
	char *end;
	unsigned port;

	conf = &lcore_conf[lcoreid];
	i = conf->n_rx_queue;

	while (1) {
		/* check that there is not too many rx ports */
		if (i >= MAX_RX_QUEUE_PER_LCORE) {
			printf("-t option: too many rx ports\n");
			return -1;
		}

		/* parse port number */
		port = strtoul(s, &end, 10);
		if ((s[0] == '\0') ||
		    (end == NULL) ||
		    (end == s) ||
		    ((*end != '\0') && (*end != ':') && (*end != '/'))) {
			printf("-t option - invalid rx port number\n");
			return -1;
		}
		if (fpn_port_shmem->port[port].enabled == 0) {
			printf("-t option - port %u not enabled\n", port);
			return -1;
		}
		conf->rxq[i].port_id = port;

		i++;
		/* end of ports parsing */
		if (*end == '/') {
			end++;
			break;
		}
		if (*end == '\0')
			break;

		s = end+1;
	}

	conf->n_rx_queue = i;
	return end - t_arg;
}

/*
 * t_arg format is:
 *    LCORE1=PORT1:PORT2/LCORE2=PORT3:PORT4/LCORE3=PORT5:PORT6
 * example:
 *    c0=0:1:2:3/c1=4:5:6:7
 */
static int
fpn_parse_rss(const char *t_arg)
{
	const char *s = t_arg;
	char *end;
	unsigned lcoreid;
	int ret;

	while (s[0] != '\0') {

		/* argument must start with a 'c' */
		if (s[0] != 'c') {
			printf("-t option: invalid syntax\n");
			return -1;
		}
		s++;

		/* parse lcore id */
		lcoreid = strtoul(s, &end, 10);
		if ((s[0] == '\0') ||
		    (end == NULL) ||
		    (end == s) ||
		    (*end != '=')) {
			printf("-t option - invalid lcore id\n");
			return -1;
		}

		if (! rte_lcore_is_enabled(lcoreid)) {
			printf("-t option - lcore %u not enabled\n", lcoreid);
			return -1;
		}
		if (lcoreid == (unsigned)fpn_cmdline_lcore) {
			printf("-t option - lcore %u assigned to console"
			       " interactions\n", lcoreid);
			return -1;
		}
#if defined(CONFIG_MCORE_FPVI_TAP)
		if (lcoreid == (unsigned)fpn_exception_lcore) {
			printf("-t option - lcore %u assigned to exception"
			       " processing\n", lcoreid);
			return -1;
		}
#endif
		if (lcoreid == (unsigned)fpn_config_polling_lcore) {
			printf("-t option - lcore %u assigned to polling "
			       "configuration processing\n", lcoreid);
			return -1;
		}


		/* parse */
		s = end + 1;
		ret = fpn_parse_rss_ports(lcoreid, s);
		if (ret < 0)
			return ret;

		s += ret;
	}
	return 0;
}

static void
fpn_dump_fdir_conf(struct rte_fdir_conf *conf, char *buf, int bufsize)
{
	int buflen = 0;

	// FIXME: hardcoded
	buflen += snprintf(&buf[buflen], bufsize-buflen, "%s", "perfect");

	switch(conf->pballoc) {
	case RTE_FDIR_PBALLOC_64K:
		buflen += snprintf(&buf[buflen], bufsize-buflen, "/64k");
		break;
	case RTE_FDIR_PBALLOC_128K:
		buflen += snprintf(&buf[buflen], bufsize-buflen, "/128k");
		break;
	case RTE_FDIR_PBALLOC_256K:
		buflen += snprintf(&buf[buflen], bufsize-buflen, "/256k");
		break;
	default:
		buflen += snprintf(&buf[buflen], bufsize-buflen, "/err");
		break;
	}

	switch(conf->status) {
	case RTE_FDIR_NO_REPORT_STATUS:
		buflen += snprintf(&buf[buflen], bufsize-buflen, "/noreport");
		break;
	case RTE_FDIR_REPORT_STATUS:
		buflen += snprintf(&buf[buflen], bufsize-buflen, "/report");
		break;
	case RTE_FDIR_REPORT_STATUS_ALWAYS:
		buflen += snprintf(&buf[buflen], bufsize-buflen, "/always");
		break;
	default:
		buflen += snprintf(&buf[buflen], bufsize-buflen, "/err");
		break;
	}

#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)		
	buflen += snprintf(&buf[buflen], bufsize-buflen, "/%d",
		conf->flex_conf.nb_flexmasks);
#else
	buflen += snprintf(&buf[buflen], bufsize-buflen, "/%d",
		conf->flexbytes_offset);

#endif
	buflen += snprintf(&buf[buflen], bufsize-buflen, "/%d",
			   conf->drop_queue);
}

/* We could have a really nice parser here that handles all possible fdir
 * configurations, but let's keep it simple for now. */
static int
fpn_parse_fdir_options(char *arg)
{
	char *cur = arg;

	do {
		char *next;
		char *tmp;
		char *end;
		unsigned long int portid, offset, dropq;
		struct rte_fdir_conf fdir_conf;
		struct fpn_rte_fdir_conf *new;

		memset(&fdir_conf, 0, sizeof(fdir_conf));

		next = strchr(cur, ',');
		if (next) {
			next[0] = '\0';
			next++;
		}

		/* optional portid, -1 means "all" */
		portid = -1;
		tmp = strchr(cur, '=');
		if (tmp) {
			tmp[0] = '\0';
			if (strcmp(cur, "all")) {
				portid = strtoul(cur, &end, 0);
				if (end[0] != '\0' || portid > FPN_MAX_PORTS) {
					printf("invalid portid %s\n", cur);
					return -1;
				}
			}
			cur = tmp + 1;
		}

		/* mode */
		tmp = strchr(cur, '/');
		if (!tmp) {
			printf("malformed fdir configuration, expecting a '/' "
			       "after %s\n", cur);
			return -1;
		}
		tmp[0] = '\0';
		// FIXME: hardcoded
		if (!strcmp(cur, "perfect"))
			fdir_conf.mode = RTE_FDIR_MODE_PERFECT;
		else {
			printf("unsupported flow director mode: %s\n", cur);
			return -1;
		}
		cur = tmp + 1;

		/* dedicated memory size */
		tmp = strchr(cur, '/');
		if (!tmp) {
			printf("malformed fdir configuration, expecting a '/' "
			       "after %s\n", cur);
			return -1;
		}
		tmp[0] = '\0';
		if (!strcmp(cur, "64k"))
			fdir_conf.pballoc = RTE_FDIR_PBALLOC_64K;
		else if (!strcmp(cur, "128k"))
			fdir_conf.pballoc = RTE_FDIR_PBALLOC_128K;
		else if (!strcmp(cur, "256k"))
			fdir_conf.pballoc = RTE_FDIR_PBALLOC_256K;
		else {
			printf("unsupported memory size: %s\n", cur);
			return -1;
		}
		cur = tmp + 1;

		/* check what the user wants about hash reporting */
		tmp = strchr(cur, '/');
		if (!tmp) {
			printf("malformed fdir configuration, expecting a '/' "
			       "after %s\n", cur);
			return -1;
		}
		tmp[0] = '\0';
		if (!strcmp(cur, "noreport"))
			fdir_conf.status = RTE_FDIR_NO_REPORT_STATUS;
		else if (!strcmp(cur, "report"))
			fdir_conf.status = RTE_FDIR_REPORT_STATUS;
		else if (!strcmp(cur, "always"))
			fdir_conf.status = RTE_FDIR_REPORT_STATUS_ALWAYS;
		else {
			printf("unsupported report mode: %s\n", cur);
			return -1;
		}
		cur = tmp + 1;

		/* flexbytes offset, if any */
		tmp = strchr(cur, '/');
		if (!tmp) {
			printf("malformed fdir configuration, expecting a '/' "
			       "after %s\n", cur);
			return -1;
		}
		tmp[0] = '\0';
		offset = strtoul(cur, &end, 0);
		/* flexbytes_offset is a uint8_t, checks this */
		if (end[0] != '\0' || offset > 256) {
			printf("invalid fdir offset %s\n", cur);
			return -1;
		}
#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
		fdir_conf.flex_conf.nb_flexmasks = offset;
#else
		fdir_conf.flexbytes_offset = offset;
#endif
		cur = tmp + 1;

		/* dropq (default q when drop flag is set in perfect filters) */
		dropq = strtoul(cur, &end, 0);
		/* drop_queue is a uint8_t, checks this */
		if (end[0] != '\0' || dropq > 256) {
			printf("invalid fdir drop queue %s\n", cur);
			return -1;
		}
		fdir_conf.drop_queue = dropq;

		/* ok, valid configuration, store it */
		new = malloc(sizeof(*new));
		if (!new) {
			printf("could not allocate memory for fdir "
			       "configuration: %s\n", strerror(errno));
			return -1;
		}
		new->portid = portid;
		memcpy(&new->conf, &fdir_conf, sizeof(fdir_conf));

		FPN_TAILQ_INSERT_TAIL(&rte_fdir_list, new, next);
		cur = next;
	} while(cur);

	return 0;
}

/* Configure lcore_conf automatically, using -q and -Q options
 * specified by the user. For non-1GB ports, use --rxq-per-port to have more
 * lcores on a single port. */
static void
fpn_autoconfigure(void)
{
	unsigned rank;
	struct lcore_conf *conf;
	unsigned portid, queueid, is_1gb;

	rank = 0;
	conf = &lcore_conf[fpn_get_online_core_num(rank)];
	const char *name = NULL;
	
	for (portid = 0; portid < fpn_nb_ports; portid++) {
		queueid = 0;

		/* skip ports that are not enabled */
		if (fpn_port_shmem->port[portid].enabled == 0)
			continue;

#if BUILT_DPDK_VERSION > DPDK_VERSION(1, 7, 1)
		name = rte_eth_devices[portid].device->driver->name;
#else
		name = rte_eth_devices[portid].driver->pci_drv.name;
#endif

		/* guess if it is a 1GB or 10GB port */
		if (strcmp(name,
			   RTE_IGB_PMD_NAME) == 0)
			is_1gb = 1;
		else
			is_1gb = 0;

one_more_queue:
		/* current port has different speed than previous one or
		 * we reached max for this lcore, try next lcore */
		if ((conf->n_rx_queue && conf->is_1gb != is_1gb) ||
		    (is_1gb && conf->n_rx_queue == fpn_1gb_rx_queue_per_lcore) ||
		    (!is_1gb && conf->n_rx_queue == fpn_10gb_rx_queue_per_lcore)) {
			rank++;
			if (rank >= fpn_online_core_count)
				rte_panic("Not enough cores\n");
			conf = &lcore_conf[fpn_get_online_core_num(rank)];
		}

		conf->rxq[conf->n_rx_queue].port_id = portid;
		conf->rxq[conf->n_rx_queue].queue_id = queueid;
		conf->n_rx_queue++;
		conf->is_1gb = is_1gb;

		queueid++;
		if (!is_1gb && queueid < fpn_rx_queue_per_port)
			goto one_more_queue;
	}
}

/* Update global dpvi_mask and ensure safe values
 * by reading total available cpus and removing
 * any overlap with fp mask.
 * Called once the parsing is done.
 */
static void fpn_update_mask(void)
{
	unsigned lcore_id;

	fpn_cpumask_clear(&fpn_online_mask);

	/* Hmm, EAL cannot tell simply how many physical cpus are
	 * available. DPDK rte_lcore_count() returns the number of running
	 * threads (bug or feature?). Rely on member field 'detected' which
	 * is reliable:
	 * detected = physical cpu is present
	 * enabled = Fast path thread is running (if detected = 1)
	 */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		/* rte_lcore_is_detected() does not exist */
		if (lcore_config[lcore_id].detected == 0)
			continue;

		fpn_cpumask_set(&fpn_online_mask, lcore_id);
	}

	/* Remove any fp_mask bits from dpvi_mask, and
	 * mask with all available cpus.
	 */
	fpn_cpumask_sub(&dpvi_mask, &fpn_coremask);
	fpn_cpumask_filter(&dpvi_mask, &fpn_online_mask);

#if defined(CONFIG_MCORE_FPVI_DP)
	if (fpn_cpumask_isempty(&dpvi_mask))
		dpvi_select_default_mask(&fpn_online_mask, &fpn_coremask, &dpvi_mask);

	/* Stats thread can run on any online core minus fpn_coremask */
	stats_mask = fpn_online_mask;
	fpn_cpumask_sub(&stats_mask, &fpn_coremask);
#endif

	/* Set default linux2fp mask to all online cores */
	if (fpn_cpumask_isempty(&fpn_linux2fp_mask))
		fpn_linux2fp_mask = fpn_online_mask;
	/* Only fastpath cores will poll dpvi rings */
	fpn_cpumask_filter(&fpn_linux2fp_mask, &fpn_coremask);

	fpn_cpumask_display("FPN: fp_mask=", &fpn_coremask);
	fpn_cpumask_display(" l_mask=", &fpn_linux2fp_mask);
	fpn_cpumask_display(" dpvi_mask=", &dpvi_mask);
	fpn_cpumask_display(" stats_mask=", &stats_mask);
	fpn_cpumask_display(" online=", &fpn_online_mask);
	printf("\n");
}

/* Parse the argument given in the command line of the application */
static int
fpn_parse_args(int argc, char **argv)
{
	int opt, ret, val;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{"pmd-82576-q", 1, 0, 0},
		{"pmd-82599-q", 1, 0, 0},
		{"rxq-per-port", 1, 0, 0},
		{"nb-mbuf", 1, 0, 0},
		{"nb-rxd", 1, 0, 0},
		{"nb-txd", 1, 0, 0},
		{"igb-rxp", 1, 0, 0},
		{"igb-rxh", 1, 0, 0},
		{"igb-rxw", 1, 0, 0},
		{"igb-txp", 1, 0, 0},
		{"igb-txh", 1, 0, 0},
		{"igb-txw", 1, 0, 0},
#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
		{"rxq-shared", 1, 0, 0},
		{"txq-shared", 1, 0, 0},
#endif
		{"fdir-conf", 1, 0, 0},
		{NULL, 0, 0, 0}
	};
	int q_opt = 0;
	int Q_opt = 0;
	int rxq_opt = 0;
	int t_opt = 0;

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "a:p:c:q:Q:t:T:l:e:x:s:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* anti ddos core */
		case 'a':
			val = -1;
			if (optarg[0] == 'c' && fpn_parse_uint(optarg + 1, 0, FPN_MAX_CORES-1, &val,
					   10) < 0) {
				printf("invalid lcore number\n");
				fpn_usage(prgname);
				return -1;
			}
			fpn_anti_ddos_lcore = val;
			break;

		/* portmask */
		case 'p':
			printf("WARNING: -p option is deprecated, use EAL black/white lists to specify port list.\n");
			break;

		/* cmdline */
		case 'c':
			if (fpn_parse_uint(optarg, 0, FPN_MAX_CORES-1, &val,
					   10) < 0) {
				printf("invalid lcore number\n");
				fpn_usage(prgname);
				return -1;
			}
			fpn_cmdline_lcore = val;
			break;

		/* nqueue */
		case 'q':
			if (fpn_parse_uint(optarg, 0, MAX_RX_QUEUE_PER_LCORE,
					   &val, 10) < 0) {
				printf("invalid queue number\n");
				fpn_usage(prgname);
				return -1;
			}
			if (t_opt || q_opt) {
				fpn_usage(prgname);
				return -1;
			}
			q_opt = 1;
			fpn_1gb_rx_queue_per_lcore = val;
			break;

		/* nqueue */
		case 'Q':
			if (fpn_parse_uint(optarg, 0, MAX_RX_QUEUE_PER_LCORE,
					   &val, 10) < 0) {
				printf("invalid queue number\n");
				fpn_usage(prgname);
				return -1;
			}
			if (t_opt || Q_opt) {
				fpn_usage(prgname);
				return -1;
			}
			Q_opt = 1;
			fpn_10gb_rx_queue_per_lcore = val;
			break;

		/* manual queue/ports association */
		case 't':
			if (fpn_parse_rss(optarg) < 0) {
				printf("Invalid port/cores association\n");
				fpn_usage(prgname);
				return -1;
			}
			if (t_opt || q_opt || Q_opt || rxq_opt) {
				fpn_usage(prgname);
				return -1;
			}
			t_opt = 1;
			break;

		/* crypto parameters */
		case 'T':
#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
			rte_crypto_configure(&optarg, 1);
#endif
			break;

		/* linux2fp communication coremask */
		case 'l':
			if (fpn_cpumask_parse(optarg, &fpn_linux2fp_mask) < 0) {
				printf("invalid linux2fp mask\n");
				fpn_usage(prgname);
				return -1;
			}
			break;

		/* dpvi exception mask */
		case 'e':
#if defined(CONFIG_MCORE_FPVI_DP)
			if (fpn_cpumask_parse(optarg, &dpvi_mask) < 0) {
				printf("invalid dpvi_mask\n");
				fpn_usage(prgname);
				return -1;
			}
#else
			printf("No DPVI support in MCORE configuration\n");
#endif
			break;

		/* recv exceptions */
		case 'x':
			if (fpn_parse_uint(optarg, 0, FPN_MAX_CORES-1, &val,
							  10) < 0) {
				printf("invalid lcore number\n");
				fpn_usage(prgname);
				return -1;
			}
#if defined(CONFIG_MCORE_FPVI_TAP)
			fpn_exception_lcore = val;
#else
			printf("No FPVI TAP support in MCORE configuration\n");
#endif
			break;

		case 's':
			if (fpn_parse_uint(optarg, 0, FPN_MAX_CORES-1, &val,
			                   10) < 0) {
				printf("invalid lcore number\n");
				fpn_usage(prgname);
				return -1;
			}
			fpn_config_polling_lcore = val;
			break;

		/* long options */
		case 0:
			if (!strcmp(lgopts[option_index].name, "pmd-82576-q")) {
				if (fpn_parse_uint(optarg, 0, MAX_RX_QUEUE_PER_LCORE,
						   &val, 10) < 0) {
					printf("invalid queue number\n");
					fpn_usage(prgname);
					return -1;
				}
				if (t_opt || q_opt) {
					fpn_usage(prgname);
					return -1;
				}
				q_opt = 1;
				fpn_1gb_rx_queue_per_lcore = val;
			}
			else if (!strcmp(lgopts[option_index].name, "pmd-82599-q")) {
				if (fpn_parse_uint(optarg, 0, MAX_RX_QUEUE_PER_LCORE,
						   &val, 10) < 0) {
					printf("invalid queue number\n");
					fpn_usage(prgname);
					return -1;
				}
				if (t_opt || Q_opt) {
					fpn_usage(prgname);
					return -1;
				}
				Q_opt = 1;
				fpn_10gb_rx_queue_per_lcore = val;
			}
			else if (!strcmp(lgopts[option_index].name, "rxq-per-port")) {
				if (fpn_parse_uint(optarg, 0,
				                   MAX_RX_QUEUE_PER_PORT,
				                   &val, 10) < 0) {
					printf("invalid queue number\n");
					fpn_usage(prgname);
					return -1;
				}
				if (t_opt || rxq_opt) {
					fpn_usage(prgname);
					return -1;
				}
				rxq_opt = 1;
				fpn_rx_queue_per_port = val;
			}
			else if (!strcmp(lgopts[option_index].name, "nb-mbuf")) {
				if (fpn_parse_uint(optarg, 0, 0xffffff,
						   &val, 10) < 0) {
					printf("invalid mbuf number\n");
					fpn_usage(prgname);
					return -1;
				}
				fpn_nb_mbuf = val;
			}
			else if (!strcmp(lgopts[option_index].name, "nb-rxd")) {
				/* min / max is defined in dpdk, *_MIN_RING_DESC */
				if (fpn_parse_uint(optarg, 64, 4096,
						   &val, 10) < 0) {
					printf("invalid rx descriptor count\n");
					fpn_usage(prgname);
					return -1;
				}
				fpn_nb_rxd = val;
			}
			else if (!strcmp(lgopts[option_index].name, "nb-txd")) {
				/* min / max is defined in dpdk, *_MIN_RING_DESC */
				if (fpn_parse_uint(optarg, 64, 4096,
						   &val, 10) < 0) {
					printf("invalid tx descriptor count\n");
					fpn_usage(prgname);
					return -1;
				}
				fpn_nb_txd = val;
			}
			else if (!strcmp(lgopts[option_index].name, "igb-rxp")) {
				/* IGB RX prefetch threshold register */
				if (fpn_parse_uint(optarg, 0, 16, &val, 10) < 0) {
					printf("invalid igb RX prefetch threshold register\n");
					fpn_usage(prgname);
					return -1;
				}
				rx_conf_igb.rx_thresh.pthresh = (uint8_t) val;
			}
			else if (!strcmp(lgopts[option_index].name, "igb-rxh")) {
				/* IGB RX host threshold register */
				if (fpn_parse_uint(optarg, 0, 16, &val, 10) < 0) {
					printf("invalid igb RX host threshold register\n");
					fpn_usage(prgname);
					return -1;
				}
				rx_conf_igb.rx_thresh.hthresh = (uint8_t) val;
			}
			else if (!strcmp(lgopts[option_index].name, "igb-rxw")) {
				/* IGB RX write-back threshold register */
				if (fpn_parse_uint(optarg, 0, 31, &val, 10) < 0) {
					printf("invalid igb RX write-back threshold register\n");
					fpn_usage(prgname);
					return -1;
				}
				rx_conf_igb.rx_thresh.wthresh = (uint8_t) val;
			}
			else if (!strcmp(lgopts[option_index].name, "igb-txp")) {
				/* IGB TX prefetch threshold register */
				if (fpn_parse_uint(optarg, 0, 31, &val, 10) < 0) {
					printf("invalid igb TX prefetch threshold register\n");
					fpn_usage(prgname);
					return -1;
				}
				tx_conf_igb.tx_thresh.pthresh = (uint8_t) val;
			}
			else if (!strcmp(lgopts[option_index].name, "igb-txh")) {
				/* IGB TX host threshold register */
				if (fpn_parse_uint(optarg, 0, 31, &val, 10) < 0) {
					printf("invalid igb TX host threshold register\n");
					fpn_usage(prgname);
					return -1;
				}
				tx_conf_igb.tx_thresh.hthresh = (uint8_t) val;
			}
			else if (!strcmp(lgopts[option_index].name, "igb-txw")) {
				/* IGB TX write-back threshold register */
				if (fpn_parse_uint(optarg, 0, 31, &val, 10) < 0) {
					printf("invalid igb TX write-back threshold register\n");
					fpn_usage(prgname);
					return -1;
				}
				tx_conf_igb.tx_thresh.wthresh = (uint8_t) val;
			}
#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
			else if (!strcmp(lgopts[option_index].name, "rxq-shared")) {
				/* Enable RX queues to be shared on a per port basis */
				if (fpn_parse_rxq_shared_portmask(optarg) < 0) {
					printf("invalid rxq-shared portmask\n");
					fpn_usage(prgname);
					return -1;
				}
			}
			else if (!strcmp(lgopts[option_index].name, "txq-shared")) {
				/* Enable RX queues to be shared on a per port basis */
				if (fpn_parse_txq_shared_portmask(optarg) < 0) {
					printf("invalid txq-shared portmask\n");
					fpn_usage(prgname);
					return -1;
				}
			}
#endif
			else if (!strcmp(lgopts[option_index].name, "fdir-conf")) {
				if (fpn_parse_fdir_options(optarg) < 0) {
					printf("invalid fdir-conf\n");
					fpn_usage(prgname);
					return -1;
				}
			}
			break;

		default:
			fpn_usage(prgname);
			return -1;
		}
	}

	/* configure conf automatically */
	if (!t_opt)
		fpn_use_autoconf = 1;

	if (optind > 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 0; /* reset getopt lib */
	return ret;
}

static int
fpn_init_port(unsigned portid)
{
	struct rte_eth_conf port_conf = base_port_conf;
	struct rte_eth_dev_info dev_info;
	uint16_t n_tx_queue, n_rx_queue;
	struct fpn_rte_fdir_conf *conf;
	int ret;
	char buf[512];

	printf("Initializing port %d... ", portid);
	fflush(stdout);

#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
	__fpn_spinlock_init(&fpn_rte_ports[portid].rxq0_lock);
	__fpn_spinlock_init(&fpn_rte_ports[portid].txq0_lock);
#endif
	n_tx_queue = fpn_get_txqueue_number(portid);
	n_rx_queue = fpn_get_rxqueue_number(portid);
	rte_eth_dev_info_get(portid, &dev_info);
	if (n_rx_queue > dev_info.max_rx_queues) {
		printf("\nCannot configure %d rx queues - max is %d\n",
		       n_rx_queue, dev_info.max_rx_queues);
		return -1;
	}
	/*
	 * Per-port offload capabilities returned by rte_eth_dev_info_get().
	 * Currently only consider TX L4 checksum capabilities.
	 */
	fpn_port_shmem->port[portid].rx_offload_capa = 0;
	fpn_port_shmem->port[portid].tx_offload_capa = 0;
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM)
		fpn_port_shmem->port[portid].tx_offload_capa |=
			FPN_OFFLOAD_TX_UDP_CKSUM;
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM)
		fpn_port_shmem->port[portid].tx_offload_capa |=
			FPN_OFFLOAD_TX_TCP_CKSUM;
	/* software LRO is always supported if the option is set */
#ifdef CONFIG_MCORE_SW_TCP_LRO
	fpn_port_shmem->port[portid].rx_offload_capa |=
		FPN_OFFLOAD_RX_SW_LRO;
	fpn_port_shmem->port[portid].sw_lro = 0; /* disabled */
#endif

	/* last matching fdir configuration is the one that applies to port */
	FPN_TAILQ_FOREACH(conf, &rte_fdir_list, next) {
		if (conf->portid != -1 && conf->portid != (int)portid)
			continue;

		memcpy(&port_conf.fdir_conf, &conf->conf, sizeof(conf->conf));
	}

	if (port_conf.fdir_conf.mode) {
		fpn_dump_fdir_conf(&port_conf.fdir_conf, buf, sizeof(buf));
		printf("fdir %s ", buf);
		fflush(stdout);
	}

	strncpy(fpn_port_shmem->port[portid].drivername, dev_info.driver_name,
		sizeof(fpn_port_shmem->port[portid].drivername));

#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
	if (dev_info.pci_dev && dev_info.pci_dev->device.devargs)
		strncpy(fpn_port_shmem->port[portid].driverargs,
			dev_info.pci_dev->device.devargs->args,
			sizeof(fpn_port_shmem->port[portid].driverargs));
#else		
	if (dev_info.pci_dev && dev_info.pci_dev->devargs)	
		strncpy(fpn_port_shmem->port[portid].driverargs,
			dev_info.pci_dev->devargs->args,
			sizeof(fpn_port_shmem->port[portid].driverargs));
#endif
		

	if (!strcmp(dev_info.driver_name, RTE_EM_PMD_NAME))
		fpn_rte_ports[portid].driver = RTE_EM;
	else if (!strcmp(dev_info.driver_name, RTE_IGB_PMD_NAME))
		fpn_rte_ports[portid].driver = RTE_IGB;
	else if (!strcmp(dev_info.driver_name, RTE_IGBVF_PMD_NAME))
		fpn_rte_ports[portid].driver = RTE_IGBVF;
	else if (!strcmp(dev_info.driver_name, RTE_IXGBE_PMD_NAME))
		fpn_rte_ports[portid].driver = RTE_IXGBE;
	else if (!strcmp(dev_info.driver_name, RTE_IXGBEVF_PMD_NAME))
		fpn_rte_ports[portid].driver = RTE_IXGBEVF;
	else if (!strcmp(dev_info.driver_name, RTE_VIRTIO_PMD_NAME))
		fpn_rte_ports[portid].driver = RTE_VIRTIO;
	else if (!strcmp(dev_info.driver_name, RTE_VMXNET3_PMD_NAME))
		fpn_rte_ports[portid].driver = RTE_VMXNET3;
	
#if BUILT_DPDK_VERSION >= DPDK_VERSION(1,7,1)
	else if (!strcmp(dev_info.driver_name, RTE_I40E_PMD_NAME))
		fpn_rte_ports[portid].driver = RTE_I40E;
#endif
	else
		fpn_rte_ports[portid].driver = RTE_OTHER;

	if (fpn_rte_ports[portid].driver == RTE_VIRTIO)
		port_conf.rxmode.hw_ip_checksum = 0;

	if (fpn_rte_ports[portid].driver == RTE_IXGBEVF) {
		/* PF driver force CRC stripping */
		port_conf.rxmode.hw_strip_crc = 1 ;
	}

	/* Even with a single queue, rss value can be used by dpvi queues */
	port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
	
#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
	port_conf.rx_adv_conf.rss_conf.rss_hf =
		ETH_RSS_IPV4 | ETH_RSS_IPV6 |
		ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV6_TCP;
#else
    port_conf.rx_adv_conf.rss_conf.rss_hf =
		ETH_RSS_IPV4 | ETH_RSS_IPV6 |
		ETH_RSS_IPV4_TCP | ETH_RSS_IPV6_TCP;
#endif

	printf("ntxq=%d nrxq=%d ", n_tx_queue, n_rx_queue);

	fflush(stdout);
	ret = rte_eth_dev_configure(portid, n_rx_queue, n_tx_queue, &port_conf);
	return ret;
}

static int
fpn_init_tx_queues(unsigned portid)
{
	struct lcore_conf *conf;
	unsigned lcore_id, queueid;
	unsigned sock_id;
	int ret;
	struct rte_eth_dev_info dev_info;

	/* init one TX queue per couple (lcore,port) */
	queueid = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		if ((unsigned)fpn_anti_ddos_lcore == lcore_id) {
			continue;
		}
		rte_eth_dev_info_get(portid, &dev_info);
		if (queueid >= dev_info.max_tx_queues)
			continue;
		//printf("max_tx_queues:%u.\n", dev_info.max_tx_queues);
		printf("txq=%u,%u ", lcore_id, queueid);
		fflush(stdout);

		sock_id = rte_lcore_to_socket_id(lcore_id);

		if (fpn_rte_ports[portid].driver == RTE_IXGBE) {
			/* stats per queue require a queue/register mapping
			 * which is limited by registers nb (IXGBE_QSTATS_REGS_MAX):
			 *     1:1 before limit
			 *     n:1 after = last queues in last register */
			ret = rte_eth_dev_set_tx_queue_stats_mapping(
				portid, queueid, FPN_MIN(queueid, (unsigned)IXGBE_QSTATS_REGS_MAX));
			if (ret != 0) {
				printf("\nrte_eth_dev_set_tx_queue_stats_mapping: "
				       "err=%d, port=%d, queue=%d\n",
				       ret, portid, queueid);
			}
		}

		if ((fpn_rte_ports[portid].driver == RTE_IXGBE) ||
		    (fpn_rte_ports[portid].driver == RTE_IXGBEVF)) {
			ret = rte_eth_tx_queue_setup(portid, queueid, fpn_nb_txd,
			                             sock_id, &tx_conf_ixgbe);
		} else if (fpn_rte_ports[portid].driver == RTE_EM)
			ret = rte_eth_tx_queue_setup(portid, queueid, fpn_nb_txd,
			                             sock_id, &tx_conf_em);
		else if (fpn_rte_ports[portid].driver == RTE_VIRTIO)
			ret = rte_eth_tx_queue_setup(portid, queueid, fpn_nb_txd,
			                             sock_id, &tx_conf_virtio);
		else if (fpn_rte_ports[portid].driver == RTE_VMXNET3)
			ret = rte_eth_tx_queue_setup(portid, queueid, fpn_nb_txd,
			                             sock_id, &tx_conf_vmxnet3);
#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
		else if (fpn_rte_ports[portid].driver == RTE_I40E)
			ret = rte_eth_tx_queue_setup(portid, queueid, fpn_nb_txd,
										sock_id, &tx_conf_i40e);
#endif
		else/* for everything else, use igb config */
			ret = rte_eth_tx_queue_setup(portid, queueid, fpn_nb_txd,
			                             sock_id, &tx_conf_igb);
		if (ret < 0) {
			printf("\nrte_eth_tx_queue_setup: err=%d, port=%d\n",
			       ret, portid);
			return -1;
		}

		conf = &lcore_conf[lcore_id];
		conf->txq[portid].queueid = queueid;
		conf->txq[portid].m_table_len = 0;

#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
		/* Currently only use a single txq0 */
		if (fpn_txq_shared[portid])
			break;
#endif
		queueid++;
	}
	return 0;
}

static int
fpn_init_rx_queues(unsigned portid)
{
	struct lcore_conf *conf;
	struct rte_mempool *mp;
	unsigned lcore_id, queueid, i;
	unsigned sock_id;
	int ret;

	/* Init all the RX queues */
	queueid = 0;
#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
	mp = NULL; /* used to check if rxq0 was already setup */
#endif
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		conf = &lcore_conf[lcore_id];
		for (i = 0; i < conf->n_rx_queue; i++) {
			if (conf->rxq[i].port_id != portid)
				continue;

			printf("rxq=%u,%u ", lcore_id, queueid);
			fflush(stdout);

			/* set the queue ID in conf structure, until
			 * now we did not know how many queues we have
			 * for this port */
			conf->rxq[i].queue_id = queueid;
#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
			/* Currently only use a single rxq0 */
			if ((fpn_rxq_shared[portid]) && (mp != NULL))
				continue;
#endif

			sock_id = rte_lcore_to_socket_id(lcore_id);
			mp = fpn_socket_mbufpool_find(sock_id);

			if (fpn_rte_ports[portid].driver == RTE_IXGBE) {
				/* stats per queue require a queue/register mapping
				 * which is limited by registers nb (IXGBE_QSTATS_REGS_MAX):
				 *     1:1 before limit
				 *     n:1 after = last queues in last register */
				ret = rte_eth_dev_set_rx_queue_stats_mapping(
					portid, queueid, FPN_MIN(queueid, (unsigned)IXGBE_QSTATS_REGS_MAX));
				if (ret != 0) {
					printf("\nrte_eth_dev_set_rx_queue_stats_mapping: "
					       "err=%d, port=%d, queue=%d\n",
					       ret, portid, queueid);
				}
			}

			if((fpn_rte_ports[portid].driver == RTE_IXGBE) ||
			   (fpn_rte_ports[portid].driver == RTE_IXGBEVF)) {
				ret = rte_eth_rx_queue_setup(portid, queueid,
							     fpn_nb_rxd, sock_id,
							     &rx_conf_ixgbe, mp);
			} else if (fpn_rte_ports[portid].driver == RTE_EM)
				ret = rte_eth_rx_queue_setup(portid, queueid, fpn_nb_rxd,
				                             sock_id, &rx_conf_em, mp);
			
#if BUILT_DPDK_VERSION >= DPDK_VERSION(1,7,1)
			else if (fpn_rte_ports[portid].driver == RTE_I40E)
				ret = rte_eth_rx_queue_setup(portid, queueid, fpn_nb_txd,
											sock_id, &rx_conf_i40e, mp);
#endif
			else /* for everyone else, use igb config */
				ret = rte_eth_rx_queue_setup(portid, queueid,
							     fpn_nb_rxd, sock_id,
							     &rx_conf_igb, mp);
			if (ret < 0) {
				printf("\nrte_eth_rx_queue_setup: err=%d, "
				       "port=%d\n", ret, portid);
				return -1;
			}
#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
			/* Currently only use a single rxq0 */
			if (fpn_rxq_shared[portid])
				continue;
#endif

			queueid++;
		}
	}
	return 0;
}

#ifdef RTE_PORT_QUEUE_CORE_BIND
static int
fpn_bind_tx_queues(unsigned portid)
{
	struct lcore_conf *conf;
	unsigned lcore_id;
	int ret;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		conf = &lcore_conf[lcore_id];

		ret = rte_eth_tx_queue_bind_cpu(portid,
						conf->txq[portid].queueid,
						lcore_id);
		if (ret < 0 && ret != -ENOTSUP) {
			printf("\nrte_eth_tx_queue_bind_cpu: err=%d, "
			       "port=%d\n", ret, portid);
			return -1;
		}
	}
	return 0;
}

static int
fpn_bind_rx_queues(unsigned portid)
{
	struct lcore_conf *conf;
	unsigned lcore_id, i;
	int ret;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		conf = &lcore_conf[lcore_id];
		for (i = 0; i < conf->n_rx_queue; i++) {
			if (conf->rxq[i].port_id != portid)
				continue;

			ret = rte_eth_rx_queue_bind_cpu(portid,
							conf->rxq[i].queue_id,
							lcore_id);
			if (ret < 0 && ret != -ENOTSUP) {
				printf("\nrte_eth_rx_queue_bind_cpu: err=%d, "
				       "port=%d\n", ret, portid);
				return -1;
			}
		}
	}
	return 0;
}
#endif

/*
 * Check that all processing cores can have their own TX queue.
 * Each configured ports must have at least as many TX queues as we have
 * processing cores.
 * If not, displays a message and gives up.
 */
static void
fpn_check_tx_queues(void)
{
	struct rte_eth_dev_info dev_info;
	unsigned long failed=0;
	unsigned portid;

	for (portid = 0; portid < fpn_nb_ports; portid++) {
		if (fpn_port_shmem->port[portid].enabled == 0)
			continue;
#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
		/* No check needed */
		if (fpn_txq_shared[portid])
			continue;
#endif
		rte_eth_dev_info_get(portid, &dev_info);
		if (dev_info.max_tx_queues < rte_lcore_count() - (fpn_anti_ddos_lcore != -1 ? 1 : 0)) {
			printf("Port %u : max TX ports=%u lower"
			       " than nb of processing cores=%u\n",
			       portid,
			       dev_info.max_tx_queues,
			       rte_lcore_count() - (fpn_anti_ddos_lcore != -1 ? 1 : 0));
			failed = 1;
			continue;
		}
	}
	/*max_tx_queues <  lcore number is reasonable when lcore number > 4*/
	if (failed && (rte_lcore_count() <= 4)) {
		rte_panic("Some configured ports have a maximum number of TX "
			  "queues < nb of processing cores.\n");
	}
}

static void
fpn_dump_port_stats(unsigned portid)
{
	unsigned n_tx_queue, n_rx_queue;
	struct rte_eth_stats stats;
	unsigned j;

	n_rx_queue = fpn_get_rxqueue_number(portid);
	n_tx_queue = fpn_get_txqueue_number(portid);
	rte_eth_stats_get(portid, &stats);
#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
	printf("port[%-2u]    ipackets=%-10"PRIu64" opackets=%-10"PRIu64" "
	       "ierrors=%-10"PRIu64" oerrors=%-10"PRIu64"\n"
	       "            rx_nombuf=%-10"PRIu64"\n",
	       portid, stats.ipackets, stats.opackets,
	       stats.ierrors, stats.oerrors,
	       stats.rx_nombuf);
#else
	printf("port[%-2u]    ipackets=%-10"PRIu64" opackets=%-10"PRIu64" "
	       "ierrors=%-10"PRIu64" oerrors=%-10"PRIu64"\n"
	       "            rx_nombuf=%-10"PRIu64" imissed=%-10"PRIu64" "
	       "ibadcrc=%-10"PRIu64" ibadlen=%-10"PRIu64"\n",
	       portid, stats.ipackets, stats.opackets,
	       stats.ierrors, stats.oerrors,
	       stats.rx_nombuf, stats.imissed,
	       stats.ibadcrc, stats.ibadlen);
#endif

	for (j = 0; j < n_rx_queue; j++) {
		uint64_t ipackets, ibytes, idropped, rx_nombuf;

		ipackets  = stats.q_ipackets[j];
		ibytes    = stats.q_ibytes[j];
		idropped  = stats.q_errors[j];
		rx_nombuf = 0;

		printf("\t[rxq%-2u] ipackets=%-10"PRIu64" "
		       "ibytes=%-12"PRIu64" idropped=%-10"PRIu64" "
		       "rx_nombuf=%-10"PRIu64"\n",
		       j, ipackets, ibytes, idropped, rx_nombuf);
	}

	for (j = 0; j < n_tx_queue; j++) {
		uint64_t opackets, obytes, odropped;

		opackets = stats.q_opackets[j];
		obytes   = stats.q_obytes[j];
		odropped = 0;

		printf("\t[txq%-2u] opackets=%-10"PRIu64" "
		       "obytes=%-12"PRIu64" odropped=%-10"PRIu64"\n",
		       j, opackets, obytes, odropped);
	}
}

static void
fpn_dump_rte_stats(__attribute__((unused)) int sig_nb)
{
	unsigned portid;

#ifdef CONFIG_MCORE_SW_TCP_LRO
	fpn_sw_lro_dump_stats(); /* XXX not the best place... per port ? */
#endif
	for (portid = 0; portid < FPN_MAX_PORTS; portid++) {
		if (fpn_port_shmem->port[portid].enabled == 0)
			continue;
		fpn_dump_port_stats(portid);
	}
}

static void
fpn_reset_rte_stats(__attribute__((unused)) int sig_nb)
{
	unsigned portid;

	for (portid = 0; portid < FPN_MAX_PORTS; portid++) {
		if (fpn_port_shmem->port[portid].enabled == 0)
			continue;
		rte_eth_stats_reset(portid);
	}
}

static void check_tsc_flags(void)
{
	char buf[512];
	FILE *fp;

	fp = fopen("/proc/cpuinfo","r");
	if (!fp) {
		printf("WARNING: Unable to open /proc/cpuinfo\n");
		return;
	}

	while (fgets(buf,sizeof(buf),fp)) {
		if (strncmp(buf,"flags", 5) == 0) {
			char *tsc = strstr(buf, "constant_tsc");
			char *non_tsc = strstr(buf, "nonstop_tsc");

			if (!tsc || !non_tsc) {
				printf("WARNING: cpu flags constant_tsc=%s nonstop_tsc=%s"
					   "using unreliable clock cycles!\n",
					   tsc ? "yes":"no",
					   non_tsc ? "yes":"no");
			}
			break;
		}
	}
	fclose(fp);
}

static void init_fpn_rte_tsc_hz(void)
{
	fpn_rte_tsc_hz = rte_get_tsc_hz();
	printf("INFO: TSC clock %"PRIu64"MHz\n", fpn_rte_tsc_hz/(1000000UL));
	check_tsc_flags();
}

/* these strings are set to whatever the driver author decides... */
struct ethtool_drvinfo {
	uint32_t cmd;
	char     driver[32];
	char     version[32];
	char     fw_version[ETHTOOL_FWVERS_LEN];
	char     bus_info[ETHTOOL_BUSINFO_LEN];
	char     reserved1[32];
	char     reserved2[12];
	uint32_t n_priv_flags;
	uint32_t n_stats;
	uint32_t testinfo_len;
	uint32_t eedump_len;
	uint32_t regdump_len;
};

static void fpn_sdk_parse_devices(void)
{
	FILE* fp;
	char* line = NULL;
	size_t linesz = 0;
	int count = 0;
	struct fp_pci_netdev* devptr;

	fp = fopen("/proc/net/dev", "r");
	if (fp == NULL) {
		return;
	}
	while(getdelim(&line, &linesz, '\n', fp) > 0) {
		char* ptr;
		int n;
		struct ethtool_drvinfo drvinfo;
		struct ifreq ifr;
		int s;
		int err;

		count++;
		if (count <= 2) {
			continue;
		}
		ptr = line;
		while(isspace(*ptr)) {
			ptr++;
		}
		n = strcspn(ptr, ": \t");
		ptr[n] = 0;
		if (n > IFNAMSIZ-1) {
			free(line);
			return;
		}
		s = socket(AF_INET, SOCK_DGRAM, 0);
		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, ptr);
		drvinfo.cmd = ETHTOOL_GDRVINFO;
		ifr.ifr_data = (caddr_t)&drvinfo;
		err = ioctl(s, SIOCETHTOOL, &ifr);
		if (!err) {
			struct fp_pci_netdev* dev;
			dev = (struct fp_pci_netdev*)malloc(sizeof(*dev));
			memcpy(dev->name, ptr, n+1);
			sscanf(drvinfo.bus_info, "%04hx:%02hhx:%02hhx.%hhd",
			       &dev->domain, &dev->bus, &dev->devid,
			       &dev->function);
			dev->portid = (uint32_t)-1;
			dev->next = NULL;
			if (fp_netdev_list == NULL) {
				fp_netdev_list = dev;
			} else {
				devptr = fp_netdev_list;
				while (devptr->next) {
					devptr = devptr->next;
				}
				devptr->next = dev;
			}
		}
		close(s);
	}
	free(line);
	fclose(fp);
}

static void fpn_dpdk_devices(void)
{
	unsigned int k;

	printf("Bus  Device        ID         Port#  RXQ  RXD/Q  TXQ  TXD/Q"
	       "  Excl  Interface       Driver name\n");
	for (k = 0; k < fpn_nb_ports; k++) {
		struct rte_pci_device *dev;
		struct fp_pci_netdev* fpdev;

#if BUILT_DPDK_VERSION > DPDK_VERSION(1, 7, 1)
		dev =  RTE_DEV_TO_PCI(rte_eth_devices[k].device);
#else
		dev = rte_eth_devices[k].pci_dev;
#endif
		/* skip non-pci drivers */
		if (dev->driver == NULL)
			continue;
		const char *name = NULL;
		
#if BUILT_DPDK_VERSION > DPDK_VERSION(1, 7, 1)
		name = dev->device.driver->name;
#else
		name = dev->driver->name;
#endif
		for (fpdev = fp_netdev_list; fpdev; fpdev = fpdev->next) {
			if (fpdev->domain == dev->addr.domain &&
			    fpdev->bus == dev->addr.bus &&
			    fpdev->devid == dev->addr.devid &&
			    fpdev->function == dev->addr.function &&
			    /*
			     * Devices flagged RTE_PCI_DRV_MULTIPLE share
			     * the same PCI address, check if portid is
			     * already defined.
			     */
			    fpdev->portid == ((uint32_t)-1)) {
				fpdev->portid = k;
				break;
			}
		}
		printf("PCI  %04x:%02x:%02x.%x  %04x:%04x"
		       "  %-6d %-4d %-6d %-4d %-6d %-5d %-15s %s\n",
		       /* Device */
		       (int)dev->addr.domain,
		       (int)dev->addr.bus,
		       (int)dev->addr.devid,
		       (int)dev->addr.function,
		       /* ID */
		       (int)dev->id.vendor_id,
		       (int)dev->id.device_id,
		       /* Port# */
		       (int)k,
		       /* RXQ */
		       fpn_get_rxqueue_number(k),
		       /* RXD/Q */
		       fpn_nb_rxd,
		       /* TXQ */
		       fpn_get_txqueue_number(k),
		       /* TXD/Q */
		       fpn_nb_txd,
		       /* Excl */
		       fpn_port_shmem->port[k].enabled ? 0 : 1,
		       /* Interface name */
		       fpn_port_shmem->port[k].portname[0] != 0 ? 
		           fpn_port_shmem->port[k].portname : "N/A",
		       /* Driver name */
		       name);
	}
}

/* clone need a int (*fn) (void*), but fpn_job_poll has no
   argument, so this function is just a wrapper. */
static int
fpn_dpdk_job_poll(__attribute__((unused)) void *arg)
{
	fpn_job_poll();

	return 0;
}

static int
fpn_dpdk_init_percore(__attribute__((unused)) void *arg)
{
	int ret = 0;
#ifdef CONFIG_MCORE_FPN_CRYPTO
	unsigned lcore_id;
	uint32_t nb_inst;
	uint32_t max_rx_burst;

	/* Get core Id */
	lcore_id = rte_lcore_id();

	/* Initialize per core instance */
	max_rx_burst = lcore_conf[lcore_id].n_rx_queue > 0 ? 
	               lcore_conf[lcore_id].n_rx_queue * MAX_PKT_BURST : 
	               MAX_PKT_BURST;
	if ((fpn_crypto_core_init(max_rx_burst, MAX_PKT_BURST/2, 
	                          &nb_inst) == FPN_CRYPTO(FAILURE)) ||
	    (nb_inst == 0)) {
		printf("lcore %d can not start crypto engine\n", lcore_id);
		ret = -1;
	}
#endif

	return ret;
}

static void fpn_port_init_shmem(void)
{
	struct rte_eth_dev_info dev_info;
	unsigned portid;
	char devname[16];

	/* Scan all ports */
	for (portid = 0; portid < fpn_nb_ports; portid++) {
		/* Get device info */
		rte_eth_dev_info_get(portid, &dev_info);
		if (dev_info.pci_dev == NULL) {
			devname[0]=0;
		} else {
			struct rte_pci_addr *addr = &dev_info.pci_dev->addr;

			fpn_port_netdev(addr, devname, sizeof(devname));
		}

		/* Enable port entry */
		strcpy(fpn_port_shmem->port[portid].portname, devname);
		fpn_port_shmem->port[portid].enabled = 1;
		fpn_port_shmem->port[portid].dpvi_managed = 1;
		fpn_port_shmem->port[portid].portid  = portid;
		fpn_port_shmem->port[portid].link = 0xFF;
#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
		fpn_rxq_shared[portid] = 0;
		fpn_txq_shared[portid] = 0;
#endif
		fpn_port_shmem->port[portid].driver_capa |= FPN_DRIVER_SET_MTU_FPN;
		fpn_port_shmem->port[portid].driver_capa |= FPN_DRIVER_SET_MAC_FPN;
		fpn_port_shmem->port[portid].driver_capa |= FPN_DRIVER_SET_FLAGS_FPN;
	}
}

/* init fpn */
int fpn_sdk_init(int argc, char **argv)
{
	fpn_cpumask_t dpdk_coremask;
	int ret;
	unsigned portid;
	unsigned lcore_id;
	uint8_t *mac;
	int arg_count = 0;

	fpn_sdk_parse_devices();
    
	/* Reset core masks */
	fpn_cpumask_clear(&fpn_rx_cores_mask);
	fpn_cpumask_clear(&fpn_linux2fp_mask);
	fpn_cpumask_clear(&dpvi_mask);

#ifndef  RTE_VER_YEAR
	printf("Based on DPDK v%d.%d.%d\n", RTE_VER_MAJOR, RTE_VER_MINOR,
	       RTE_VER_PATCH_LEVEL);
#else
    printf("Based on DPDK v%d.%d.%d.%d\n", RTE_VER_YEAR, RTE_VER_MONTH, RTE_VER_MINOR, 
	       RTE_VER_RELEASE);
#endif
	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		return -1;
	argc -= ret;
	argv += ret;
	arg_count += ret;

#ifdef CONFIG_MCORE_FPN_HOOK
	/* Update hooks that may have been overwritten by dpdk */
	fpn_hook_scan_libs();
#endif

#if BUILT_DPDK_VERSION < DPDK_VERSION(1,7,0)
	/* init driver */
	ret = rte_pmd_init_all();
	if (ret != 0 && ret != -ENODEV)
		rte_panic("Cannot init poll-mode drivers\n");
	if (rte_eal_pci_probe() < 0)
		rte_panic("Cannot probe PCI\n");
#endif

	fpn_nb_ports = rte_eth_dev_count();
	if (fpn_nb_ports > FPN_MAX_PORTS) {
		printf("\n***** WARNING: too many ports, can not manage more than %d *****\n\n", FPN_MAX_PORTS);
		fpn_nb_ports = FPN_MAX_PORTS;
	}
	if (fpn_nb_ports == 0) {
		printf("\n***** WARNING: no detected ports *****\n\n");
	}

	/* All ports enabled by default */
	enabled_phys_port_mask = (1ULL << fpn_nb_ports) - 1;

	/* init port list */
	fpn_port_shmem = (port_mem_t *) fpn_port_init();
	if (fpn_port_shmem == NULL) {
		perror("fpn_shmem_mmap failed");
		exit(1);
	}

	/* initialize ports shared mem */
	fpn_port_init_shmem();

	/* parse application arguments (after the EAL ones) */
	ret = fpn_parse_args(argc, argv);
	if (ret < 0) {
		printf("\nList of available ethernet ports\n");
		fpn_dpdk_devices();
		return -1;
	}
	argc -= ret;
	argv += ret;
	arg_count += ret;

	fpn_cpumask_clear(&dpdk_coremask);
	RTE_LCORE_FOREACH(lcore_id) {
		if (lcore_id == (unsigned)fpn_cmdline_lcore)
			continue;
#if defined(CONFIG_MCORE_FPVI_TAP)
		if (lcore_id == (unsigned)fpn_exception_lcore)
			continue;
#endif
		if (lcore_id == (unsigned)fpn_config_polling_lcore)
			continue;

		if (lcore_id == (unsigned)fpn_anti_ddos_lcore)
			continue;

		if (rte_lcore_is_enabled(lcore_id))
			fpn_cpumask_set(&dpdk_coremask, lcore_id);
	}
	fpn_register_online_cores(&dpdk_coremask);

	fpn_update_mask();

	if (fpn_cmdline_lcore != -1 &&
	    !rte_lcore_is_enabled(fpn_cmdline_lcore)) {
		printf("cmdline core id (%d) is not in EAL mask ",
		       fpn_cmdline_lcore);
		fpn_cpumask_display("", &fpn_coremask);
		printf("\n");
		exit(1);
	}

	init_fpn_rte_tsc_hz();

#ifdef CONFIG_MCORE_INTERCORE
	/* init intercore rings */
	if (fpn_intercore_init() < 0) {
		return -1;
	}
#endif

	/* init timer subsystem */
	fpn_timer_subsystem_init();

#ifdef CONFIG_MCORE_SW_TCP_LRO
	/* init software LRO */
	fpn_sw_lro_init();
#endif

	/* create the mbuf pool */
	fpn_mbufpool_create();

	M_TRACK_INIT();

#if defined(CONFIG_MCORE_FPVI_TAP)
	fpn_init_tap_ring();
#endif

	/* configure conf automatically */
	if (fpn_use_autoconf)
		fpn_autoconfigure();

	/* Automatically disable ports that have invalid number of */
	/* rx/tx queues; this avoid a RTE_PANIC in rte_eth_dev_configure */
	for (portid = 0; portid < fpn_nb_ports; portid++) {
		if ((fpn_get_txqueue_number(portid) == 0) ||
		    (fpn_get_rxqueue_number(portid) == 0)) {
			printf("\n***** WARNING: no rx or tx queues associated to port %d; port disabled *****\n\n",
			       portid);
			enabled_phys_port_mask &= ~(1ull << portid);
			fpn_port_shmem->port[portid].enabled = 0;
		}
	}

	/* Display managed ports information */
	fpn_dpdk_devices();

	/*
	 * Check that the maximum number of TX queues of all configured
	 * ports is greater than the number of processing cores.
	 * Panic if it is not the case.
	 */
	fpn_check_tx_queues();

	/* initialize all ports */
	fpn_rte_port_table.count = 0;
	for (portid = 0; portid < fpn_nb_ports; portid++) {

		/* skip ports that are not enabled */
		if (fpn_port_shmem->port[portid].enabled == 0) {
			printf("Skipping disabled port %d\n", portid);
			continue;
		}
		fpn_rte_port_table.index[fpn_rte_port_table.count] = portid;
		fpn_rte_port_table.count++;

		ret = fpn_init_port(portid);
		if (ret < 0)
			rte_panic("Cannot configure device: err=%d, port=%d\n",
				  ret, portid);

		ret = fpn_init_tx_queues(portid);
		if (ret < 0)
			rte_panic("Cannot configure tx queues: err=%d, "
				  "port=%d\n", ret, portid);

		ret = fpn_init_rx_queues(portid);
		if (ret < 0)
			rte_panic("Cannot configure rx queues: err=%d, "
				  "port=%d\n", ret, portid);

		rte_eth_macaddr_get(portid,
		 (struct ether_addr *)fpn_port_shmem->port[portid].etheraddr);
		mac = fpn_port_shmem->port[portid].etheraddr;
		printf("[%02x:%02x:%02x:%02x:%02x:%02x] ",
			mac[0], mac[1], mac[2],	mac[3], mac[4], mac[5]);

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_panic("rte_eth_dev_start(port %d) returns err=%d,"
			          " you may need to increase mbuf pool with --nb-mbuf\n",
					  portid, ret);

#ifdef RTE_PORT_QUEUE_CORE_BIND
		ret = fpn_bind_tx_queues(portid);
		if (ret < 0)
			rte_panic("Cannot bind tx queues: err=%d, "
				  "port=%d\n", ret, portid);

		ret = fpn_bind_rx_queues(portid);
		if (ret < 0)
			rte_panic("Cannot bind rx queues: err=%d, "
				  "port=%d\n", ret, portid);
#endif
		printf("done\n");

		/* Force all-multi to receive multicast frames */
		rte_eth_allmulticast_enable(portid);
	}

#ifdef RTE_PORT_QUEUE_CORE_BIND
	/* xlp nae pmd specifics ... queue_bind_cpu_done() only does the poe
	 * distribution vector update on the first call. So all nae pmd ports
	 * must be configured before calling it. */
	for (portid = 0; portid < fpn_nb_ports; portid++) {
		/* skip ports that are not enabled */
		if (fpn_port_shmem->port[portid].enabled == 0)
			continue;

		ret = queue_bind_cpu_done(portid);

		/* not a nae port */
		if (ret == -ENOTSUP)
			continue;
		else if (ret < 0) {
			printf("\nqueue_bind_cpu_done: err=%d, "
			       "port=%d\n", ret, portid);
			return -1;
		}

		/* found one nae port, all nae ports are now configured */
		break;
	}
#endif

#if defined(CONFIG_MCORE_FPVI_DP)
	fpn_dpvi_shmem = fpn_dpvi_shmem_mmap();

	fpn_dpvi_init(&fpn_coremask, &fpn_linux2fp_mask,
	              &dpvi_mask, &fpn_online_mask);

	fpn_dpvi_register(&dpvi_ops);

	link_timer_ms = TIMER_STATS_MS / FPN_MAX_PORTS;

	/* send link status periodically */
	callout_init(&link_timer);
	callout_reset_millisec(&link_timer, link_timer_ms, link_timer_cb, NULL);
#endif

#if defined(CONFIG_MCORE_FPVI_TAP)
	/* check correct initialization */
	if (fpn_exception_lcore == -1 ||
	    !rte_lcore_is_enabled(fpn_exception_lcore))
		rte_panic("No dedicated exception lcore\n");
	printf("%s: dedicated exception lcore %d\n",
	       __func__, fpn_exception_lcore);

	ret = fpn_create_tap_nodes("/tmp/fpmapping", 0);
	if (ret < 0)
		rte_panic("cannot create TAP nodes\n");
#endif

	if (fpn_anti_ddos_lcore == -1 ||
	    !rte_lcore_is_enabled(fpn_anti_ddos_lcore))
		rte_panic("No dedicated anti ddos lcore\n");
	printf("%s: dedicated anti ddos lcore %d\n",
	       __func__, fpn_anti_ddos_lcore);

	if (fpn_anti_ddos_lcore != -1 && !fpn_anti_ddos_proc)
		rte_panic("should FP_DDOS_PROC_REGISTER registe ddos proc\n");

	if (fpn_config_polling_lcore != -1 &&
	    !rte_lcore_is_enabled(fpn_config_polling_lcore))
		rte_panic("Configuration polling lcore not in lcore mask\n");
	printf("%s: dedicated configuration polling lcore %d\n",
	       __func__, fpn_config_polling_lcore);

	fpn_for_each_cpumask(lcore_id, &fpn_coremask) {
		/* Update mask of RX cores for Traffic Generator */
		if (lcore_conf[lcore_id].n_rx_queue > 0)
			fpn_cpumask_set(&fpn_rx_cores_mask, lcore_id);
	}

#if defined(CONFIG_MCORE_FPVI_DP)
	/* get stats periodically on a non-fp core (and do this _after_
	 * fpn_coremask has been computed). */
	if (create_stats_thread() < 0) {
		rte_panic("could not create statistics thread\n");
	}
#endif

	(void) signal(SIGUSR1, (sighandler_t) fpn_dump_rte_stats);
	(void) signal(SIGUSR2, (sighandler_t) fpn_reset_rte_stats);

	/* launch per-lcore init on every lcore except master */
	rte_eal_mp_remote_launch(fpn_dpdk_job_poll, NULL, SKIP_MASTER);

#ifdef CONFIG_MCORE_FPN_CRYPTO
	/* Initialize crypto driver */
	if (fpn_crypto_init(CONFIG_MCORE_CRYPTO_BUFFERS, 256,
	                    CONFIG_MCORE_CRYPTO_MAX_SESSIONS) != 0) {
		printf("Can not start driver\n");
		return -1;
	}
#endif

#ifdef CONFIG_MCORE_DEBUG_CPU_USAGE
	if (cpu_usage_init() < 0)
		return -1;
#endif
#ifdef CONFIG_MCORE_FPN_TRACK
	if (fpn_track_init() < 0)
		return -1;
#endif

#ifdef CONFIG_MCORE_FPN_GC
	if (fpn_gc_init() < 0)
		return -1;
#endif

	/* do init per core for all 'fast path' lcores */
	fpn_job_run_oncpumask(&fpn_coremask, fpn_dpdk_init_percore,
	                      NULL, FPN_JOB_SKIP_MASTER);
	fpn_dpdk_init_percore(NULL);
	fpn_job_wait_status(&fpn_coremask, FPN_JOB_STATE_DONE, FPN_JOB_SKIP_MASTER);

	printf("fpn-sdk init finished\n");

	return arg_count;
}

/* Send the packet to a co-localized slow path */
void __fpn_send_exception(struct mbuf *m, uint8_t port __fpn_maybe_unused)
{
	M_TRACK(m, "EXCEPTION");
	M_TRACK_UNTRACK(m);

#if defined(CONFIG_MCORE_FPVI_TAP)
#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 1)
	fpn_printf_ratelimited("%s: len %d port %d\n", __func__, m_len(m), port);
#endif
	push_to_tap(m);
#elif defined(CONFIG_MCORE_FPVI_DP)
	if (m_is_contiguous(m))
		push_to_linux(m, port);
	else
		push_to_linux_multi(m, port);
#else
	fpn_printf_ratelimited("%s: %p, %u\n", __func__, m, port);
	m_freem(m); /* no exception in standalone FP */
#endif
}

/* dangerous... we should use m_clone() instead */
int fpn_send_packet_nofree(struct mbuf *m, uint8_t port)
{
#ifdef RTE_LIBRTE_MBUF_NO_TXFREE
	RTE_MBUF_OL_FLAGS(&m->rtemb) |= PKT_TX_NOFREE;
	return fpn_send_packet(m, port);
#else
	struct mbuf *m2;
	m2 = m_dup(m);
	if (m2 == NULL)
		return -1;
	return fpn_send_packet(m2, port);
#endif
}

int32_t fpn_set_mtu(const uint16_t port, const uint16_t mtu)
{
	if (fpn_check_port(port) < 0)
		return -1;

#if BUILT_DPDK_VERSION >= DPDK_VERSION(1,7,1)
	if (fpn_rte_ports[port].driver == RTE_I40E)		
		rte_eth_devices[port].data->dev_started = 0;
	if (rte_eth_dev_set_mtu(port, mtu) < 0)
	{
		if (fpn_rte_ports[port].driver == RTE_I40E)		
			rte_eth_devices[port].data->dev_started = 1;
		return -1;
	}
	if (fpn_rte_ports[port].driver == RTE_I40E)		
		rte_eth_devices[port].data->dev_started = 1;
#endif

	return 0;
}
int32_t fpn_set_mac(const uint16_t port, const uint8_t *mac)
{
	struct ether_addr old_mac;
	struct ether_addr new_mac;
	int res;

	if (fpn_check_port(port) < 0)
		return -1;

	memcpy(new_mac.addr_bytes, mac, ETHER_ADDR_LEN);

	rte_eth_macaddr_get(port, &old_mac);

	if (memcmp(&old_mac, &new_mac, ETHER_ADDR_LEN) == 0)
		return 0;

	res = rte_eth_dev_mac_addr_remove(port, &old_mac);

	if (res == 0)
		res = rte_eth_dev_mac_addr_add(port, &new_mac, 0);

	return res;
}
int32_t fpn_set_flags(const uint16_t port, const uint32_t flags)
{
	int ret = 0;

	if (fpn_check_port(port) < 0)
		return -1;

	if (flags & FPN_FLAGS_PROMISC) {
		rte_eth_promiscuous_enable(port);
	} else {
		rte_eth_promiscuous_disable(port);
	}

#if BUILT_DPDK_VERSION >= DPDK_VERSION(1,7,1)
	if (flags & FPN_FLAGS_LINK_UP) {
		ret += rte_eth_dev_set_link_up(port);
	} else {
		ret += rte_eth_dev_set_link_down(port);
	}
#endif

	return ret;
}
