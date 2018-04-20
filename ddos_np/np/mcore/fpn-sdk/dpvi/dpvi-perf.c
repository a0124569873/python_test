/*
 * Copyright (C) 2010 6WIND, All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * DPVI module: Dataplane Proxy Virtual Interface
 * See documentation in dpvi.h
 */

#ifndef CONFIG_SYSCTL
#error "this module needs CONFIG_SYSCTL"
#endif

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <net/sock.h>
#include <linux/sysctl.h>
#include <net/dst.h>
#include <net/arp.h>
#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <linux/file.h>
#include <linux/eventfd.h>
#include <linux/miscdevice.h>

#include "dpvi.h"
#include "fpn.h"
#include "shmem/fpn-shmem.h"
#include "fpn-port.h"
#include "fpn-dpvi-ring.h"
#include "fpn-dpvi-ring-func.h"
#include <linux/kthread.h>

#define DPVI_NAME    "dpvi"
#define DPVI_VERSION "0.1"
#define DPVI_PREFIX  "dpvi: "

#define DPVI_ERR(fmt, ...) do {						\
		if (unlikely(net_ratelimit()))				\
			printk(KERN_ERR DPVI_PREFIX "%s() " fmt,	\
			       __FUNCTION__, ##__VA_ARGS__);		\
	} while (0)

#define DPVI_INFO(fmt, ...) do {					\
		if (unlikely(net_ratelimit()))				\
			printk(KERN_INFO DPVI_PREFIX "%s() " fmt,	\
			       __FUNCTION__, ##__VA_ARGS__);		\
	} while (0)

#define DPVI_LOG(fmt, ...) do {					\
		printk(KERN_INFO DPVI_PREFIX "%s() " fmt,		\
			   __FUNCTION__, ##__VA_ARGS__);		\
	} while (0)

#define DPVI_DEBUG(fmt, ...) do {					\
		if (unlikely(dpvi_debug)) {				\
			if (unlikely(net_ratelimit()))			\
				printk(KERN_DEBUG DPVI_PREFIX		\
				       "%s():%d " fmt,			\
				       __FUNCTION__, __LINE__,		\
				       ##__VA_ARGS__);			\
		}							\
	} while (0)

/* when sending a request, time to wait for the answer */
#define DPVI_CTRL_TIMEOUT_MS 10
#define DPVI_CTRL_INIT_TIMEOUT_MS 100

/* maximum number of queued messages in queues */
#define DPVI_CTRL_INFO_MAX_QLEN 32

/* Netlink message buffer size */
#define DPVI_NL_BUFSIZE 512

/* Net link socket and poll task */
static struct socket *nl_sock;
static struct task_struct *nl_poll;

#if defined(UBUNTU_RELEASE)
#if UBUNTU_KERNEL_CODE >= UBUNTU_KERNEL_VERSION(3,13,0,23,45)
#define HAVE_NDO_SELECT_QUEUE_SOCKET_FALLBACK_ARG
#endif
#endif

port_mem_t *fpn_port_shmem;

static DEFINE_MUTEX(dpvi_ctrl_lock);

/* /proc/sys/dpvi is used to list dpvi interfaces */
static struct ctl_table_header *dpvi_sysctl_header;

/* Buffer used to store the list of dpvi interfaces */
static char dpvi_sysctl_list_interfaces_buf[4096];

/* Buffer used to store running fastpath pid */
static int running_fastpath = 0;

/* table containing the list of registered interfaces */
static struct net_device *dpvi_table[DPVI_MAX_PORTS];
static struct net_device *dev_fpn0;

static int dpvi_napi_weight = 128;
module_param(dpvi_napi_weight, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(dpvi_napi_weight, "NAPI weight");

/* length of a polling session (in nanoseconds) */
static unsigned int dpvi_poll_length = 10 * 1000; /* 10 us */
module_param(dpvi_poll_length, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(dpvi_poll_length, "Polling session length");

/* enable/disable debug */
static int dpvi_debug;
module_param(dpvi_debug, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(dpvi_debug, "enable debug");

/* fp_mask is given by start-up script after parsing
 * the command line fp_mask=-m...
 */
static char *fp_mask;
module_param(fp_mask, charp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(fp_mask, "Fast path mask");

/* dpvi_mask tells which Linux cpu listen to exception packets
 * If not defined, it will use the first online cpu, excluding fp_mask
 */
static char *dpvi_mask;
module_param(dpvi_mask, charp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(dpvi_mask, "DPVI mask");

static char *l_mask;
module_param(l_mask, charp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(l_mask, "Linux to FP mask");

static fpn_cpumask_t _fp_mask;
static fpn_cpumask_t _dpvi_mask;
static fpn_cpumask_t _l_mask;

static struct sk_buff_head ctrl_answer_queue;

static int fp_rxring_map[FPN_DRING_CPU_MAX] __read_mostly;
static int fp_txring_map[FPN_DRING_CPU_MAX] __read_mostly;
static int fp_txring_map_len __read_mostly = 0;
static int fp_rxring_map_len __read_mostly = 0;

static void
kernel_cpumask_display(const char * name, const fpn_cpumask_t * coremask)
{
	int index, skip = 1;
	char mask[256];

	sprintf(mask, "0x");
	for (index=FPN_ARRAY_SIZE(coremask->core_set)-1 ; index>=0 ; index--) {
		if ((coremask->core_set[index] != 0) || (!skip) || (index == 0)) {
			if (skip) 
				snprintf(&mask[strlen(mask)], sizeof(mask)-strlen(mask),
				        "%llx", coremask->core_set[index]);
			else
				snprintf(&mask[strlen(mask)], sizeof(mask)-strlen(mask),
				        "%016llx", coremask->core_set[index]);

			/* Display is started do not skip anything even if no bit set */
			skip = 0;

			/* Check string length */
			if (strlen(mask) >= sizeof(mask)-1) {
				sprintf(mask, "Buffer overflow");
				break;
			}
		}
	}

	DPVI_LOG("%s = %s\n", name, mask);
}

static int
kernel_cpumask_parse(const char *cpumask, fpn_cpumask_t * coremask)
{
	char *end = NULL;
	unsigned long core, min, max;

	/* Invalid parameter */
	if (coremask == NULL)
		return -1;

	/* Clear coremask */
	fpn_cpumask_clear(coremask);

	/* No configuration string, return empty coremask */
	if (cpumask == NULL)
		return 0;

	/* If hex string, read mask */
	if ((cpumask[0] == '0') && ((cpumask[1] == 'x') || (cpumask[1] == 'X'))) {
		int car;
		uint32_t len, index = 0, shift = 0;
		char val;

		/* Skip 0x */
		cpumask += 2;
		len = strlen(cpumask);

		/* Start from last byte, and fill cpu mask */
		for (car=len-1 ; car>=0 ; car--) {
			if ((cpumask[car] >= 'a') &&
			    (cpumask[car] <= 'f')) {
				val = cpumask[car] - 'a' + 10;
			} else if ((cpumask[car] >= 'A') &&
			           (cpumask[car] <= 'F')) {
				val = cpumask[car] - 'A' + 10;
			} else if ((cpumask[car] >= '0') &&
			           (cpumask[car] <= '9')) {
				val = cpumask[car] - '0';
			} else {
				return -1;
			}

			if (index >= FPN_ARRAY_SIZE(coremask->core_set)) {
				return -1;
			}

			/* Fill mask */
			coremask->core_set[index] |= ((fpn_core_set_t) val) << shift;
			shift += 4;

			/* Change core set index if needed */
			if (shift == (8 * sizeof(fpn_core_set_t))) {
				index++;
				shift = 0;
			}
		}
	} else {
		/* Else this is a list of cores */
		min = FPN_MAX_CORES;
		do {
			core = simple_strtoul(cpumask, &end, 10);
			if (end != NULL) {
				if (*end == '-') {
					min = core;
					cpumask = end + 1;
				} else if ((*end == ',') || (*end == '\0')) {
					max = core;
					if (min == FPN_MAX_CORES)
						min = core;
					for (core=min; core<=max; core++) {
						fpn_cpumask_set(coremask, core);
					}
					min = FPN_MAX_CORES;
					if (*end != '\0')
						cpumask = end + 1;
				} else {
					break;
				}
			}
		} while ((cpumask[0] != '\0') && (end != NULL) && (*end != '\0'));
		if ((cpumask[0] == '\0') || (end == NULL) || (*end != '\0'))
			return -1;
	}

	return 0;
}

/* If packet is being sent by Linux using a cpu running Fast path,
 * then hand off the packet to another cpu.
 */
static struct sk_buff_head tx_skbq_nocpu __read_mostly;
static spinlock_t tx_skbq_lock;

static void tx_skbq_init(void)
{
	DPVI_DEBUG("enter");

	skb_queue_head_init(&tx_skbq_nocpu);
	spin_lock_init(&tx_skbq_lock);
}

static void tx_skbq_enqueue(struct sk_buff *skb, struct net_device *dev)
{
	DPVI_DEBUG("enter");

	skb->dev = dev;

	spin_lock(&tx_skbq_lock);
	__skb_queue_tail(&tx_skbq_nocpu, skb);
	spin_unlock(&tx_skbq_lock);
}

static void __tx_skbq_drain(void)
{
	struct sk_buff *skb;
	struct sk_buff_head local;

	DPVI_DEBUG("enter");

	skb_queue_head_init(&local);
	spin_lock(&tx_skbq_lock);
	skb_queue_splice_tail_init(&tx_skbq_nocpu, &local);
	spin_unlock(&tx_skbq_lock);

	while ((skb = __skb_dequeue(&local))) {
		const struct net_device_ops *ops = skb->dev->netdev_ops;

		ops->ndo_start_xmit(skb, skb->dev);
	}
}

static inline void tx_skbq_drain(void)
{
	/* No lock but no worry,  missed packets will be handled next time */
	if (skb_queue_empty(&tx_skbq_nocpu))
		return;

	__tx_skbq_drain();
}

/* private data attached to a DPVI interface */
struct dpvi_priv {
	uint16_t portid;     /* port identifier in FP */

	struct net_device_stats stats; /* returned by dpvi_get_stats */

	/* link status */
	uint16_t speed;      /* [10, 100, 1000, 10000] */
	uint8_t full_duplex; /* 0: half, 1: full */
	uint8_t link;        /* 1 -> link up, 0 -> link down */
};

/* xmit data on DPVI */
static int dpvi_xmit(struct sk_buff *skb, struct net_device *dev);

/* receive ctrl/data with proto = ETH_P_DPVI */
static int dpvi_rcv(struct sk_buff *skb, struct net_device *dev,
		    struct packet_type *pt, struct net_device *netdev);

/* new protocol handler for ETH_P_DPVI) */
static struct packet_type dpvi_packet_type = {
	.type = __constant_htons(ETH_P_DPVI),
	.func = dpvi_rcv,
};

struct work_tx {
	unsigned int default_tx_queue;
};
struct work_poll {
	int cpu;
	struct napi_struct napi;
	int napi_enabled;
	uint64_t poll_end;
	struct eventfd_ctx *efd_ctx;
	struct task_struct *efd_poll_task;
};
#define DPVI_POP_MAX_ELEM 4

static struct work_poll work_poll[FPN_DRING_CPU_MAX];
static struct work_tx work_tx[FPN_DRING_CPU_MAX];
struct fpn_dpvi_shmem *fpn_dpvi_shmem;

static int dpvi_first_core;
static int cpu_fp_map[FPN_MAX_CORES];
static int cpu_fp_maplen = 0;

static unsigned int poll_ring(struct fpn_dring *ring)
{
	unsigned int count, i;
	struct sk_buff *skb;
	struct net_device *dev;
	u32 len;
	uint16_t portid;
	unsigned rx = 0;
	int is_eop;
	struct fpn_dring_entry dre[DPVI_POP_MAX_ELEM] = {};

	DPVI_DEBUG("enter");

	skb = NULL;
again:
	count = fpn_dring_dequeue_start(ring, dre, ARRAY_SIZE(dre));

	if (count == 0) {
		if (skb) {
			/* Could not finish reassembly? */
			ring->cons.dequeue_err++;
			kfree_skb(skb);
		}
		return 0;
	}

	ring->cons.dequeue += count;
	for (i = 0 ; i < count; i++) {
		len = dre[i].len;
		portid = dre[i].port;
		is_eop = dre[i].eop;

		DPVI_DEBUG("cpu %u read data=0x%lx len=%u port=%u eop=%u %u/%u\n",
				smp_processor_id(), (unsigned long)dre[i].data,
				len, portid, is_eop, i, count);
		if (skb) {
			if (skb_tailroom(skb) < len &&
				pskb_expand_head(skb, skb_headroom(skb), len, GFP_ATOMIC)) {
				/* Reassembly failed */
				ring->cons.dequeue_err++;
				kfree_skb(skb);
				skb = NULL;
				continue;
			} else {
				memcpy(skb->data + skb->len, phys_to_virt(dre[i].data), len);
				skb->tail += len;
				skb->len += len;
				dev = skb->dev;
				goto push;
			}
		}

		if (portid != FPN_RESERVED_PORTID_FPN0)
			dev = dpvi_table[portid];
		else
			dev = dev_fpn0;

		if (dev == NULL) {
			ring->cons.dequeue_err++;
			/* Don't break: valid packets may be present in the bulk.
			 * Typically we have received a packet from the network,
			 * but we are waiting the port list reply.
			 */
			continue;
		}
		skb = netdev_alloc_skb(dev, is_eop ? len : 16384);
		if (!skb) {
			ring->cons.dequeue_err++;
			break;
		}
		/* If forwarded, we would like to use
		 * tx ring of same FP cpu.
		 */
		skb_record_rx_queue(skb, fp_rxring_map[dre[i].from]);
		memcpy(skb->data, phys_to_virt(dre[i].data), len);
		skb_put(skb, len);

push:
		if (is_eop) {
			skb->protocol = eth_type_trans(skb, dev);
			/* Assume FP checks it */
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			netif_receive_skb(skb);
			skb = NULL;
		}
		rx++;
	}
	fpn_dring_dequeue_end(ring, count);
	if (skb)
		goto again;

	return rx;
}

static int dpvi_napi_handler(struct napi_struct *napi, int budget)
{
	struct work_poll *wp = container_of(napi, struct work_poll, napi);
	int cpu = wp->cpu;
	unsigned int work_done = 0;
	unsigned int rx = 0;
	struct fpn_dring_list *ring_list = &fpn_dpvi_shmem->rx_ring[cpu];
	int i;
	struct timespec ts;

	DPVI_DEBUG("enter");

poll:
	while (work_done < budget) {
		rx = 0;

		/* Drain any transmit forwarded by other cpu */
		tx_skbq_drain();
		for (i = 0 ; i < cpu_fp_maplen; i++)
			rx += poll_ring(&ring_list->cpu[cpu_fp_map[i]]);

		if (unlikely(ring_list->polling == DPVI_LAST_POLLING))
			goto complete;
		if (unlikely(rx == 0))
			goto out;

		work_done += rx;
	}

	if (work_done >= budget)
		return budget;

out:
	/* Force polling until poll_end */
	getrawmonotonic(&ts);
	if (timespec_to_ns(&ts) < wp->poll_end)
		return budget;

	/* Let the fast path send eventfds but poll one last time
	 * just in case */
	ring_list->polling = DPVI_LAST_POLLING;
	goto poll;

complete:
	ring_list->polling = DPVI_NOT_POLLING;
	napi_complete(napi);
	return work_done;
}

static inline u16 dpvi_pick_default_tx_queue(void)
{
	unsigned int cpu = smp_processor_id();
	struct work_tx *txr = &work_tx[cpu];

	return (u16) txr->default_tx_queue;
}

static int dpvi_init_ring(void)
{
	unsigned int cpu;
	unsigned int i;

	DPVI_DEBUG("enter");

	fpn_dpvi_shmem->dpvi_mask = _dpvi_mask;
	fpn_dpvi_shmem->fp_mask = _fp_mask;
	fp_rxring_map_len = 0;
	fp_txring_map_len = 0;

	if (fpn_cpumask_isempty(&_fp_mask) || fpn_cpumask_isempty(&_l_mask))
		return -1;

	for (i = 0; i < FPN_DRING_CPU_MAX; i++) {
		if (!fpn_cpumask_ismember(&_fp_mask, i))
			continue;
		fp_rxring_map[i] = fp_rxring_map_len;
		fp_rxring_map_len++;
	}

	for (i = 0; i < FPN_DRING_CPU_MAX; i++) {
		if (!fpn_cpumask_ismember(&_l_mask, i))
			continue;
		fp_txring_map[fp_txring_map_len] = i;
		fp_txring_map_len++;
	}

	/* Decide which default TX ring to use by cpu */
	i = 0;
	for_each_online_cpu(cpu) {
		work_tx[cpu].default_tx_queue = i;
		DPVI_LOG("dpvi: cpu %u use Tx queue %u  ring %u\n",
				cpu, i, fp_txring_map[i]);
		i++;
		if (i == fp_txring_map_len)
			i = 0;
	}

	return 0;
}

/*
 * Prior to linux 2.6.33, there is no kernel api to access eventfds, which can
 * only be read from userland through a system call. This version of
 * eventfd_ctx_read is copied from the upstream commit cb289d62 which adds such
 * functionnality. Also the eventfd_ctx struct is not visible outside of
 * fs/eventfd.c so it must be redefined here.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
#include <linux/wait.h>

struct eventfd_ctx {
	struct kref kref;
	wait_queue_head_t wqh;
	__u64 count;
	unsigned int flags;
};

static ssize_t eventfd_ctx_read(struct eventfd_ctx *ctx, int no_wait, __u64 *cnt)
{
	ssize_t res;
	DECLARE_WAITQUEUE(wait, current);

	spin_lock_irq(&ctx->wqh.lock);
	*cnt = 0;
	res = -EAGAIN;
	if (ctx->count > 0)
		res = 0;
	else if (!no_wait) {
		__add_wait_queue(&ctx->wqh, &wait);
		for (;;) {
			set_current_state(TASK_INTERRUPTIBLE);
			if (ctx->count > 0) {
				res = 0;
				break;
			}
			if (signal_pending(current)) {
				res = -ERESTARTSYS;
				break;
			}
			spin_unlock_irq(&ctx->wqh.lock);
			schedule();
			spin_lock_irq(&ctx->wqh.lock);
		}
		__remove_wait_queue(&ctx->wqh, &wait);
		__set_current_state(TASK_RUNNING);
	}
	if (likely(res == 0)) {
		*cnt = (ctx->flags & EFD_SEMAPHORE) ? 1 : ctx->count;
		ctx->count -= *cnt;
		if (waitqueue_active(&ctx->wqh))
			wake_up_locked_poll(&ctx->wqh, POLLOUT);
	}
	spin_unlock_irq(&ctx->wqh.lock);

	return res;
}
#endif

static int dpvi_efd_poll_task(void *arg)
{
	int dpvi_cpu = smp_processor_id();
	struct work_poll *wp = &work_poll[dpvi_cpu];
	uint64_t cnt = 0;
	struct timespec ts;

	allow_signal(SIGKILL);
	allow_signal(SIGTERM);

	while (!kthread_should_stop()) {
		if (eventfd_ctx_read(wp->efd_ctx, 0, &cnt) < 0)
			break;
		getrawmonotonic(&ts);
		wp->poll_end = timespec_to_ns(&ts) + dpvi_poll_length;
		fpn_dpvi_shmem->rx_ring[dpvi_cpu].polling = DPVI_POLLING;

		/* Once napi_schedule is called, we need softirqs to be
		 * processed as soon as possible so dpvi_napi_handler is called
		 * back as soon as possible. By default, the napi handler is
		 * not woke up fast enough and a great deal of packet is lost
		 * (even with really slow PPS rates). To ensure softirqs are
		 * rapildy processed, we must call local_bh_enable which
		 * forces it (with a call to do_softirq).
		 */
		local_bh_disable();
		napi_schedule(&wp->napi);
		local_bh_enable();
	}

	wp->efd_poll_task = NULL;

	return 0;
}

static int dpvi_start_ring(void)
{
	struct work_poll *wp;
	int dpvi_cpu;

	DPVI_DEBUG("enter");

	/* Decide which default TX ring to use by cpu */
	for_each_online_cpu(dpvi_cpu) {
		if (!fpn_cpumask_ismember(&_dpvi_mask, dpvi_cpu))
			continue;

		fpn_dpvi_shmem->rx_ring[dpvi_cpu].polling = DPVI_NOT_POLLING;
		wp = &work_poll[dpvi_cpu];

		wp->cpu = dpvi_cpu;

		/* Add napi callback */
		netif_napi_add(dev_fpn0, &wp->napi, dpvi_napi_handler,
		               dpvi_napi_weight);
		napi_enable(&wp->napi);
		wp->napi_enabled = 1;

		/* kthread which will wait from an event from any fp core
		 * and then call napi_schedule */
		wp->efd_poll_task = kthread_create(dpvi_efd_poll_task, NULL,
		                                   "dpvi-poll%u", dpvi_cpu);

		kthread_bind(wp->efd_poll_task, dpvi_cpu);
		wake_up_process(wp->efd_poll_task);
	}

	return 0;
}

static void dpvi_stop_ring(void)
{
	struct task_struct *tid;
	int dpvi_cpu;

	DPVI_DEBUG("enter");

	for_each_online_cpu(dpvi_cpu) {
		if (!fpn_cpumask_ismember(&_dpvi_mask, dpvi_cpu))
			continue;

		if (work_poll[dpvi_cpu].napi_enabled) {
			napi_disable(&work_poll[dpvi_cpu].napi);
			netif_napi_del(&work_poll[dpvi_cpu].napi);
			work_poll[dpvi_cpu].napi_enabled = 0;
		}

		tid = work_poll[dpvi_cpu].efd_poll_task;
		if (tid) {
			send_sig_info(SIGKILL, SEND_SIG_NOINFO, tid);
			kthread_stop(tid);
		}
	}
}

static void dpvi_stop(void)
{
	struct dpvi_priv *priv = NULL;
	uint16_t portid;

	/* Carrier down on fpn0 */
	netif_carrier_off(dev_fpn0);

	/* Carrier is down */
	for (portid = 0; portid < DPVI_MAX_PORTS; portid++) {
		struct net_device * dpvi_dev = dpvi_table[portid];

		/* Skip unused ports */
		if (dpvi_dev == NULL)
			continue;

		/* Shut down carrier */
		netif_carrier_off(dpvi_dev);

		/* Change priv link state */
		priv = netdev_priv(dpvi_dev);
		if (priv != NULL)
			priv->link = 0;
	}

	/* Kill processing threads, will be recreated on fastpath restart */
	dpvi_stop_ring();

	/* No process monitored anymore */
	/* Do this last, it may be monitored outside to check if DPVI is correctly stopped */
	running_fastpath = 0;
}

/* netlink socket unload */
static void dpvi_cleanup_socket(void)
{
	struct msghdr msg;
	struct kvec	iov;
	struct nlmsghdr *nl_hdr;
	struct cn_msg *cn_hdr;
	enum proc_cn_mcast_op *op;
	char buffer[DPVI_NL_BUFSIZE];

	/* Close netlink socket */
	if (nl_sock)
	{
		/* Setup message */
		memset(buffer, 0, sizeof(buffer));
		memset(&msg, 0, sizeof(msg));
		nl_hdr = (struct nlmsghdr *)buffer;
		cn_hdr = (struct cn_msg *)NLMSG_DATA(nl_hdr);
		op = (enum proc_cn_mcast_op*)&cn_hdr->data[0];
		*op = PROC_CN_MCAST_IGNORE;

		/* Fill the netlink header */
		nl_hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) +
		                                 sizeof(enum proc_cn_mcast_op));
		nl_hdr->nlmsg_type = NLMSG_DONE;
		nl_hdr->nlmsg_flags = 0;
		nl_hdr->nlmsg_seq = 0;
		nl_hdr->nlmsg_pid = 0;

		/* Fill the connector header */
		cn_hdr->id.idx = CN_IDX_PROC;
		cn_hdr->id.val = CN_VAL_PROC;
		cn_hdr->seq = 0;
		cn_hdr->ack = 0;
		cn_hdr->len = sizeof(enum proc_cn_mcast_op);

		/* Fill descriptor */
		iov.iov_base = &buffer;
		iov.iov_len  = sizeof(buffer);

		/* Send message */
		if (kernel_sendmsg(nl_sock, &msg, &iov, 1, nl_hdr->nlmsg_len) !=
		    nl_hdr->nlmsg_len) {
			DPVI_ERR("Could not send group exit message\n");
		}

		/* Close the socket */
		sock_release(nl_sock);
		nl_sock = NULL;
	}
}

static int dpvi_nl_poll_task(void *arg)
{
	struct msghdr msg;
	struct kvec	iov;
	struct nlmsghdr *nl_hdr;
	struct cn_msg *cn_hdr;
	struct proc_event *proc_ev;
	char buffer[DPVI_NL_BUFSIZE];
	int len;

	/* Allow to be killed using SIGKILL/SIGTERM (this is not obvious!) */
	/* this is needed to receive signals to interrupt the socket read call */
	/* in order to exit the kernel thread cleanly */
	allow_signal(SIGKILL);
	allow_signal(SIGTERM);

	memset(&msg, 0, sizeof(msg));

	/* Loop until termination is asked */
	while (!kthread_should_stop()) {

		/* Setup buffer */
		iov.iov_base = &buffer;
		iov.iov_len  = DPVI_NL_BUFSIZE;

		/* Get message from socket */
		if ((len = kernel_recvmsg(nl_sock, &msg, &iov, 1, DPVI_NL_BUFSIZE, 0)) <= 0)
			break;

		/* Get multipart messages */
		for (nl_hdr = (struct nlmsghdr *) buffer; NLMSG_OK(nl_hdr, len);
			 nl_hdr = NLMSG_NEXT (nl_hdr, len)) {
			cn_hdr  = (struct cn_msg *)NLMSG_DATA(nl_hdr);
			proc_ev = (struct proc_event *)&cn_hdr->data[0];

			/* Only interested in PROC_EVENT_EXIT events */
			/* To check that fastpath is alive */
			if ((proc_ev->what == PROC_EVENT_EXIT) &&  
				(proc_ev->event_data.exit.process_pid == running_fastpath)) {
				DPVI_LOG("Fastpath killed, stopping DPVI\n");
				dpvi_stop();
			}

			if (nl_hdr->nlmsg_type == NLMSG_DONE)
				break;
		}
	}

	if (!kthread_should_stop()) {
		DPVI_ERR("%s exiting\n", __func__);
	} else {
		DPVI_LOG("%s exiting\n", __func__);
	}

	/* Close netlink socket */
	dpvi_cleanup_socket();

	/* Task is not running anymore */
	nl_poll = NULL;

	return 0;
}


/* parse the packet queue, and retrieve the packet with the expected
 * cmd, reqid and length */
static struct sk_buff *dpvi_process_ctrl_queue(uint8_t reqid, uint8_t len)
{
	struct dpvi_hdr *dpvi_hdr;
	struct sk_buff *skb;

	DPVI_DEBUG("enter\n");

	skb = skb_dequeue_tail(&ctrl_answer_queue);

	/* no message queued */
	if (skb == NULL)
		return NULL;

	dpvi_hdr = (struct dpvi_hdr *)skb->data;

	/* old message, drop it */
	if (reqid != dpvi_hdr->reqid) {
		DPVI_DEBUG("Drop old message\n");
		kfree_skb(skb);
		return NULL;
	}

	/* malformed message, drop it */
	if (len > (skb->len - sizeof(struct dpvi_hdr))) {
		DPVI_ERR("Malformed message\n");
		kfree_skb(skb);
		return NULL;
	}

	return skb;
}

/* Prepare a dpvi request packet. Return 0 on success: in this case,
 * the packet is written in pskb. */
static int dpvi_prepare_request(struct sk_buff **pskb,
				uint8_t cmd, uint16_t portid, uint8_t reqid,
				const void *req, unsigned reqlen)
{
	struct net_device *fpdev = dev_fpn0;
	struct dpvi_hdr *dpvi_hdr;
	void *skb_data;
	struct sk_buff *skb;
	char dst_mac[MAX_ADDR_LEN];
	int ret;

	DPVI_DEBUG("enter reqlen=%d\n", reqlen);

	/* encapsulate message for output on fpn0 interface */
	if (fpdev->header_ops->create == NULL) {
		DPVI_ERR("no create() method on fpn0\n");
		return -ENOTCONN;
	}

	/* alloc a new skb with enough headroom */
	skb = dev_alloc_skb(reqlen);
	if (skb == NULL) {
		DPVI_DEBUG("cannot allocate skbuff\n");
		return -ENOBUFS;
	}
	skb->dev = fpdev;

	/* copy data in skb */
	skb_data = skb_put(skb, reqlen);
	memcpy(skb_data, req, reqlen);

	/* add dpvi header */
	dpvi_hdr = (struct dpvi_hdr *)skb_push(skb, sizeof(*dpvi_hdr));
	memset(dpvi_hdr, 0, sizeof(*dpvi_hdr));

	dpvi_hdr->type = DPVI_TYPE_CTRL_REQ;
	dpvi_hdr->cmd = cmd;
	dpvi_hdr->portid = portid;
	dpvi_hdr->reqid = reqid;

	memset(dst_mac, 0, MAX_ADDR_LEN);
	ret = fpdev->header_ops->create(skb, fpdev, ETH_P_DPVI, dst_mac,
					NULL, skb->len);
	if (ret < 0) {
		DPVI_DEBUG("cannot encapsulate on fpn0\n");
		kfree_skb(skb);
		return ret;
	}
	/* dpvi_enqueue() relies on skb->queue_mapping to choose tx ring */
	skb_set_queue_mapping(skb, dpvi_pick_default_tx_queue());

	*pskb = skb;
	return 0;
}

static int dpvi_enqueue(struct sk_buff *skb, uint16_t portid);

/*
 * Prepare and send to FP (through fpn0) a control request stored in
 * 'req', and return answer in 'ans'. Return 0 on success. This
 * function has to be called from a process context, because it waits
 * the answer by calling msleep() (with a timeout).
 * The sending/reception of control requests/answers is protected by a
 * mutex: only one is allowed at a time.
 */
static int dpvi_send_ctrl_request(uint8_t cmd, uint16_t portid,
				  const void *req, unsigned reqlen,
				  void *ans, unsigned anslen,
				  unsigned timeout_ms)
{
	static uint8_t global_reqid = 0;
	uint8_t reqid;
	struct sk_buff *skb = NULL;
	struct dpvi_hdr *dpvi_hdr;
	int i, ret = 0;

	DPVI_DEBUG("enter\n");

	/* This function must be called from a process context
	 * (example: ioctl). Once the request is sent to the FP, we
	 * call msleep() to wait the answer. */
	might_sleep();

	/* lock (only one control operation at a time) */
	mutex_lock(&dpvi_ctrl_lock);

	/* generate a uniq req-id (0 is forbidden) */
	reqid = global_reqid++;
	if (reqid == 0)
		reqid = global_reqid++;

	preempt_disable();
	ret = dpvi_prepare_request(&skb, cmd, portid, reqid, req, reqlen);
	preempt_enable();
	if (ret < 0)
		goto error;

	preempt_disable();
	ret = dpvi_enqueue(skb, FPN_RESERVED_PORTID_FPN0);
	preempt_enable();
	if (ret != 0) {
		if (ret > 0)
			ret = -ENETDOWN;
		goto error;
	}

	/* parse control messages */
	skb = NULL;
	for (i = 0; i < timeout_ms; i++) {
		msleep(1);
		skb = dpvi_process_ctrl_queue(reqid, anslen);
		if (skb != NULL)
			break;
	}

	/* no answer from fastpath */
	if (skb == NULL) {
		ret = -ETIMEDOUT;
		DPVI_DEBUG("Timeout: no answer from FP\n");
		goto error;
	}

	/* we know that may_pull() is ok because we did it before
	 * enqueue */
	dpvi_hdr = (struct dpvi_hdr *)skb->data;
	if (dpvi_hdr->cmd == DPVI_CMD_ERROR) {
		ret = -EINVAL;
		DPVI_DEBUG("FP returned an error (cmd not supported ?)\n");
		goto error_free;
	}

	/* remove dpvi header */
	if (skb_pull(skb, sizeof(struct dpvi_hdr)) == NULL) {
		DPVI_ERR("Cannot remove DPVI header\n");
		goto error_free;
	}

	/* parse answer and return it in 'req' pointer */
	if (!pskb_may_pull(skb, anslen)) {
		DPVI_ERR("Message too short (len=%d should be %d)\n",
			 skb->len, anslen);
		ret = -EBADMSG;
		goto error_free;
	}

	memcpy(ans, skb->data, anslen);

 error_free:
	kfree_skb(skb);
 error:
	mutex_unlock(&dpvi_ctrl_lock);
	return ret;
}

/*
 * Send a request to the FP to change the MAC address of the
 * interface.
 * Called from process context only.
 */
static int dpvi_set_address(struct net_device *dev, void *addr)
{
	struct sockaddr *sa = addr;

	DPVI_DEBUG("enter\n");

	if (!is_valid_ether_addr(sa->sa_data))
		return -EADDRNOTAVAIL;

	/* update netdevice info */
	memcpy(dev->dev_addr, sa->sa_data, ETH_ALEN);
	return 0;
}

/* return driver information */
static void dpvi_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *info)
{
	int ret;
	struct dpvi_priv *priv = NULL;
	uint16_t portid;
	struct dpvi_ethtool_drvinfo dpvi_info;

	DPVI_DEBUG("enter");

	/* get portid from netdev priv */
	priv = netdev_priv(dev);
	portid = priv->portid;

	ret = dpvi_send_ctrl_request(DPVI_CMD_ETHTOOL_GET_DRVINFO, portid,
				     &dpvi_info, sizeof(dpvi_info),
				     &dpvi_info, sizeof(dpvi_info),
				     DPVI_CTRL_TIMEOUT_MS);

	if (ret != 0) {
		snprintf(info->driver, sizeof(info->driver), "%s", DPVI_NAME);
		snprintf(info->version, sizeof(info->version), "%s", DPVI_VERSION);
	} else {
		snprintf(info->driver, sizeof(info->driver), "%s", dpvi_info.driver);
		snprintf(info->bus_info, sizeof(info->bus_info), "%s", dpvi_info.bus_info);
	}
}

/*
 * Ask the FP to change the MTU of the device. Return 0 on sucess.
 * Called from process context only.
 */
static int dpvi_change_mtu(struct net_device *dev, int new_mtu)
{
	DPVI_DEBUG("enter\n");

	/* update dev structure with new mtu on success */
	dev->mtu = new_mtu;
	return 0;
}

/*
 * ethtool feature fully supported. All info are provided by driver itself
 */
static int dpvi_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	int ret;
	struct dpvi_ethtool_gsettings dpvi_gsettings;
	struct dpvi_priv *priv = NULL;
	uint16_t portid;

	DPVI_DEBUG("enter");

	/* get portid from netdev priv */
	priv = netdev_priv(dev);
	portid = priv->portid;

	ret = dpvi_send_ctrl_request(DPVI_CMD_ETHTOOL_GET_SETTINGS, portid,
				     &dpvi_gsettings, sizeof(dpvi_gsettings),
				     &dpvi_gsettings, sizeof(dpvi_gsettings),
				     DPVI_CTRL_TIMEOUT_MS);

	if (0 != ret) {
		ethtool_cmd_speed_set(cmd, 65535);
		cmd->duplex = 255;
	}
	else {
		switch (ntohs(dpvi_gsettings.speed)) {
			case DPVI_ETHTOOL_LINK_SPEED_10:
				ethtool_cmd_speed_set(cmd, SPEED_10);
				break;
			case DPVI_ETHTOOL_LINK_SPEED_100:
				ethtool_cmd_speed_set(cmd, SPEED_100);
				break;
			case DPVI_ETHTOOL_LINK_SPEED_1000:
				ethtool_cmd_speed_set(cmd, SPEED_1000);
				break;
			case DPVI_ETHTOOL_LINK_SPEED_10000:
				ethtool_cmd_speed_set(cmd, SPEED_10000);
				break;
			default:
				ethtool_cmd_speed_set(cmd,
						ntohs(dpvi_gsettings.speed));
				break;
		}

		switch (ntohs(dpvi_gsettings.duplex)) {
			case DPVI_ETHTOOL_LINK_HALF_DUPLEX:
				cmd->duplex = DUPLEX_HALF;
				break;
			case DPVI_ETHTOOL_LINK_FULL_DUPLEX:
				cmd->duplex = DUPLEX_FULL;
				break;
			default:
				cmd->duplex = ntohs(dpvi_gsettings.duplex);
				break;
		}

		switch (dpvi_gsettings.port) {
			case DPVI_ETHTOOL_PORT_TP:
				cmd->port = PORT_TP;
				break;
			case DPVI_ETHTOOL_PORT_FIBRE:
				cmd->port = PORT_FIBRE;
				break;
#ifdef PORT_DA
			case DPVI_ETHTOOL_PORT_DA:
				cmd->port = PORT_DA;
				break;
#endif
#ifdef PORT_NONE
			case DPVI_ETHTOOL_PORT_NONE:
				cmd->port = PORT_NONE;
				break;
#endif
#ifdef PORT_OTHER
			case DPVI_ETHTOOL_PORT_OTHER:
				cmd->port = PORT_OTHER;
				break;
#endif
			default:
				cmd->port = dpvi_gsettings.port;
				break;
		}

		switch (dpvi_gsettings.transceiver) {
			case DPVI_ETHTOOL_XCVR_INTERNAL:
				cmd->transceiver= DPVI_ETHTOOL_XCVR_INTERNAL;
				break;
			case DPVI_ETHTOOL_XCVR_EXTERNAL:
				cmd->transceiver= DPVI_ETHTOOL_XCVR_EXTERNAL;
				break;
			default:
				cmd->transceiver = dpvi_gsettings.transceiver;
				break;
		}
		switch (ntohl(dpvi_gsettings.autoneg)) {
			case DPVI_ETHTOOL_AUTONEG_DISABLE:
				cmd->autoneg = AUTONEG_DISABLE;
				break;
			case DPVI_ETHTOOL_AUTONEG_ENABLE:
				cmd->autoneg = AUTONEG_ENABLE;
				break;
			default:
				cmd->autoneg = ntohl(dpvi_gsettings.autoneg);
				break;
		}

		switch (ntohl(dpvi_gsettings.supported)) {
			case DPVI_ETHTOOL_SUPPORTED_10baseT_Half:
				cmd->supported = SUPPORTED_10baseT_Half;
				break;
			case DPVI_ETHTOOL_SUPPORTED_100baseT_Half:
				cmd->supported = SUPPORTED_100baseT_Half;
				break;
			case DPVI_ETHTOOL_SUPPORTED_10baseT_Full:
				cmd->supported = SUPPORTED_10baseT_Full;
				break;
			case DPVI_ETHTOOL_SUPPORTED_100baseT_Full:
				cmd->supported = SUPPORTED_100baseT_Full;
				break;
			case DPVI_ETHTOOL_SUPPORTED_1000baseT_Full:
				cmd->supported = SUPPORTED_1000baseT_Full;
				break;
			case DPVI_ETHTOOL_SUPPORTED_10000baseT_Full:
				cmd->supported = SUPPORTED_10000baseT_Full;
				break;
			case DPVI_ETHTOOL_SUPPORTED_Autoneg:
				cmd->supported = SUPPORTED_Autoneg;
				break;
			case DPVI_ETHTOOL_SUPPORTED_TP:
				cmd->supported = SUPPORTED_TP;
				break;
			case DPVI_ETHTOOL_SUPPORTED_FIBRE:
				cmd->supported = SUPPORTED_FIBRE;
				break;
			default:
				cmd->supported = ntohl(dpvi_gsettings.supported);
				break;
		}
		switch (ntohl(dpvi_gsettings.autoneg_advertised)) {
			case DPVI_ETHTOOL_ADVERTISED_1000baseT_Full:
				cmd->advertising = ADVERTISED_1000baseT_Full;
				break;
			case DPVI_ETHTOOL_ADVERTISED_10000baseT_Full:
				cmd->advertising = ADVERTISED_10000baseT_Full;
				break;
			case DPVI_ETHTOOL_ADVERTISED_Autoneg:
				cmd->advertising = ADVERTISED_Autoneg;
				break;
			case DPVI_ETHTOOL_ADVERTISED_TP:
				cmd->advertising = ADVERTISED_TP;
				break;
			case DPVI_ETHTOOL_ADVERTISED_FIBRE:
				cmd->advertising = ADVERTISED_FIBRE;
				break;
			default:
				cmd->advertising = ntohl(dpvi_gsettings.autoneg_advertised);
				break;
		}
	}

	/* up to now more parameters are not gathered from driver */
	cmd->phy_address  = dpvi_gsettings.phy_addr;
	cmd->maxtxpkt     = 0;
	cmd->maxrxpkt     = 0;
	cmd->mdio_support = 0;
	cmd->eth_tp_mdix  = 0;
	cmd->lp_advertising = 0;

	return 0;
}

/* return statistics count to display */
static int dpvi_get_sset_count(struct net_device *dev,
			       int sset)
{
	int ret;
	struct dpvi_priv *priv = NULL;
	uint16_t portid;
	struct dpvi_ethtool_sset_count dpvi_sset_count;

	dpvi_sset_count.string_sets = htonl(sset);
	dpvi_sset_count.val = 0;

	/* get portid from netdev priv */
	priv = netdev_priv(dev);
	portid = priv->portid;

	ret = dpvi_send_ctrl_request(DPVI_CMD_ETHTOOL_GET_SSET_COUNT, portid,
				     &dpvi_sset_count, sizeof(dpvi_sset_count),
				     &dpvi_sset_count, sizeof(dpvi_sset_count),
				     DPVI_CTRL_TIMEOUT_MS);

	if (ret < 0)
		return ret;
	return ntohl(dpvi_sset_count.val);
}

/* return driver all strings to display statistics information */
static void dpvi_get_strings(struct net_device  *dev,
			     uint32_t stringset,
			     uint8_t *data)
{
	int ret;
	struct dpvi_priv *priv = NULL;
	struct dpvi_ethtool_gstrings strings;
	struct dpvi_ethtool_gstrings *answered_strings;
	uint16_t portid;
	struct dpvi_ethtool_sset_count dpvi_sset_count;
	uint32_t hdrlen, datalen, stringslen, sendlen = 0;
	struct dpvi_ethtool_gstrings *as;

	/* max_send_size is 'fpn_dpvi_shmem->fp_tx_mbuf_size - sizeof(struct dpvi_ether_header)'
	 * = 2048 - 20 = 2028
	 */
	uint32_t max_send_size = fpn_dpvi_shmem->fp_tx_mbuf_size - 20;

	/* It's better not to cut strings between multiple messages,
	 * only transmit dpvi messages carrying untruncated strings
	 */
	uint32_t max_strings_size = (max_send_size / (ETH_GSTRING_LEN * sizeof(uint8_t)))
				  * (ETH_GSTRING_LEN * sizeof(uint8_t));

	dpvi_sset_count.string_sets = htonl(stringset);
	dpvi_sset_count.val = 0;

	/* get portid from netdev priv */
	priv = netdev_priv(dev);
	portid = priv->portid;
	strings.string_sets = htonl(stringset);
	strings.len = 0;
	strings.size_to_copy = 0;
	strings.offset_to_copy = 0;

	ret = dpvi_send_ctrl_request(DPVI_CMD_ETHTOOL_GET_SSET_COUNT, portid,
				     &dpvi_sset_count, sizeof(dpvi_sset_count),
				     &dpvi_sset_count, sizeof(dpvi_sset_count),
				     DPVI_CTRL_TIMEOUT_MS);
	if (ret < 0)
		return;

	datalen = ntohl(dpvi_sset_count.val) * ETH_GSTRING_LEN * sizeof(uint8_t);
	hdrlen = sizeof(struct dpvi_ethtool_gstrings);
	strings.len = dpvi_sset_count.val;

	answered_strings = kzalloc(hdrlen + datalen, GFP_KERNEL);
	if (answered_strings == NULL) {
		DPVI_DEBUG("cannot allocate room for answered_strings\n");
		return;
	}

	/* The maximum length of dpvi message is fpn_dpvi_shmem->fp_tx_mbuf_size, ie 2048.
	 * If the length of strings is more than 'max_send_size - hdrlen', it needs to send
	 * more than one dpvi message to get the whole strings.
	 *
	 * Kernel asks for the size at offset each time, and fast-path copies part of the strings to kernel
	 * according to the size and offset.
	 * The statistics is shown when the whole strings is copied to answered_strings->data.
	 */
	as = kmalloc(max_send_size, GFP_KERNEL);
	if (as == NULL) {
		DPVI_DEBUG("cannot allocate memory for DPVI_CMD_ETHTOOL_GET_STRINGS request\n");
		ret = -1;
		goto error;
	}

	do {
		stringslen = ((hdrlen + datalen - sendlen) > max_strings_size)? max_strings_size : hdrlen + datalen - sendlen;
		strings.size_to_copy = htons(stringslen - hdrlen);
		strings.offset_to_copy = htons(sendlen);
		ret = dpvi_send_ctrl_request(DPVI_CMD_ETHTOOL_GET_STRINGS, portid,
				&strings, stringslen,
				as, stringslen,
				DPVI_CTRL_TIMEOUT_MS);

		if (ret < 0) {
			kfree(as);
			goto error;
		}

		memcpy(answered_strings->data + sendlen, as->data, stringslen - hdrlen);
		sendlen += (stringslen - hdrlen);

	} while (stringslen - hdrlen != 0);

	kfree(as);
error:
	if (ret == 0)
		memcpy(data, answered_strings->data, datalen);
	else
		memset(data, 0, datalen);

	kfree(answered_strings);
}

/* return driver statistics information */
static void dpvi_get_ethtool_stats(struct net_device *dev,
				   struct ethtool_stats *stats,
				   uint64_t *data)
{
	int ret;
	struct dpvi_priv *priv = NULL;
	uint16_t portid;
	uint32_t hdrlen, datalen, i;
	struct dpvi_ethtool_statsinfo info;
	struct dpvi_ethtool_statsinfo *answered_info;

	info.n_stats = htonl(stats->n_stats);
	datalen = stats->n_stats * sizeof(uint64_t);
	hdrlen = sizeof(struct dpvi_ethtool_statsinfo);

	/* get portid from netdev priv */
	priv = netdev_priv(dev);
	portid = priv->portid;

	answered_info = kzalloc(hdrlen + datalen, GFP_KERNEL);
	if (answered_info == NULL) {
		DPVI_DEBUG("cannot allocate room for answered_info\n");
		return;
	}

	ret = dpvi_send_ctrl_request(DPVI_CMD_ETHTOOL_GET_STATSINFO, portid,
				     &info, hdrlen + datalen,
				     answered_info, hdrlen + datalen,
				     DPVI_CTRL_TIMEOUT_MS);

	if (ret == 0) {
		for (i = 0; i < stats->n_stats; i++)
			data[i] = ntohll(answered_info->data[i]);
	}
	else
		memset(data, 0, datalen);

	kfree(answered_info);
}

/*
 * Get the status of the link (updated periodically by the FP)
 */
u32 dpvi_get_link(struct net_device *dev)
{
	struct dpvi_priv *priv = netdev_priv(dev);

	DPVI_DEBUG("enter");

	if (priv == NULL)
		return 0;

	return priv->link;
}

/*
 * Return a pointer to statistics, updated periodically thanks to FP
 * messages
 */
static struct net_device_stats *dpvi_get_stats(struct net_device *dev)
{
	struct dpvi_priv *priv = netdev_priv(dev);
	uint16_t portid;
	struct fpn_port *port;

	DPVI_DEBUG("enter");

	if (priv == NULL)
		return (struct net_device_stats *)NULL;

	portid = priv->portid;

	/* only synchronize stats from the shmem for real ports */
	if (priv->portid < FPN_MAX_PORTS) {
		port = &fpn_port_shmem->port[portid];

		priv->stats.rx_packets = port->ipackets;
		priv->stats.tx_packets = port->opackets;
		priv->stats.rx_bytes   = port->ibytes;
		priv->stats.tx_bytes   = port->obytes;
		priv->stats.rx_errors  = port->ierrors;
		priv->stats.tx_errors  = port->oerrors;
	}

	return &((struct dpvi_priv*)netdev_priv(dev))->stats;
}

/* Get the pause parameter */
static void dpvi_get_pauseparam(struct net_device *dev,
                                struct ethtool_pauseparam *pause)
{
	int ret;
	struct dpvi_priv *priv = NULL;
	uint16_t portid;
	struct dpvi_ethtool_pauseparam dpvi_pause;

	DPVI_DEBUG("enter");

	/* get portid from netdev priv */
	priv = netdev_priv(dev);
	portid = priv->portid;

	ret = dpvi_send_ctrl_request(DPVI_CMD_ETHTOOL_GET_PAUSEPARAM, portid,
				     &dpvi_pause, sizeof(dpvi_pause),
				     &dpvi_pause, sizeof(dpvi_pause),
				     DPVI_CTRL_TIMEOUT_MS);

	if (ret == 0) {
		pause->autoneg = ntohl(dpvi_pause.autoneg);
		pause->rx_pause = ntohl(dpvi_pause.rx_pause);
		pause->tx_pause = ntohl(dpvi_pause.tx_pause);
	} else {
		DPVI_DEBUG("Cannot get pause parameter, err=%d\n", ret);
		memset(pause, 0, sizeof(struct ethtool_pauseparam));
	}
}

/* Set the pause parameter */
static int dpvi_set_pauseparam(struct net_device *dev,
                               struct ethtool_pauseparam *pause)
{
	int ret;
	struct dpvi_priv *priv = NULL;
	uint16_t portid;
	struct dpvi_ethtool_pauseparam dpvi_pause;

	DPVI_DEBUG("enter");

	/* get portid from netdev priv */
	priv = netdev_priv(dev);
	portid = priv->portid;

	dpvi_pause.autoneg = htonl(pause->autoneg);
	dpvi_pause.rx_pause = htonl(pause->rx_pause);
	dpvi_pause.tx_pause = htonl(pause->tx_pause);

	ret = dpvi_send_ctrl_request(DPVI_CMD_ETHTOOL_SET_PAUSEPARAM, portid,
				     &dpvi_pause, sizeof(dpvi_pause),
				     &dpvi_pause, sizeof(dpvi_pause),
				     DPVI_CTRL_TIMEOUT_MS);

	return ret;
}

static u16 dpvi_select_queue(struct net_device *dev, struct sk_buff *skb
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
			     , void *accel_priv
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0) || \
	defined(HAVE_NDO_SELECT_QUEUE_SOCKET_FALLBACK_ARG)
			     , select_queue_fallback_t fallback
#endif
#endif
			    )
{
	/* Here we could parse netfpc to select a unique cpu */

	u16 queue_index;

	DPVI_DEBUG("enter");

	/* Most cases when l_mask tells one single FP thread */
	if (dev->real_num_tx_queues == 1)
		return 0;

	if (skb_rx_queue_recorded(skb))
		/* Back to FP cpu that provides the exception */
		queue_index = skb_get_rx_queue(skb);
	else {
		/* Or default choice */
		queue_index = dpvi_pick_default_tx_queue();
	}

	/* Rare case when packet is coming from another device */
	while (unlikely(queue_index >= dev->real_num_tx_queues))
		queue_index -= dev->real_num_tx_queues;

	return queue_index;
}

static struct ethtool_ops dpvi_ethtool_ops = {
	.get_drvinfo      = dpvi_get_drvinfo,
	.get_settings     = dpvi_get_settings,
	.get_link         = dpvi_get_link,
	.get_sset_count   = dpvi_get_sset_count,
	.get_strings      = dpvi_get_strings,
	.get_ethtool_stats= dpvi_get_ethtool_stats,
	.get_pauseparam   = dpvi_get_pauseparam,
	.set_pauseparam   = dpvi_set_pauseparam,
};

struct net_device_ops dpvi_ops = {
	.ndo_get_stats = dpvi_get_stats,
	.ndo_start_xmit = dpvi_xmit,
	.ndo_change_mtu = dpvi_change_mtu,
	.ndo_set_mac_address = dpvi_set_address,
	.ndo_select_queue   = dpvi_select_queue,
};

static const struct net_device_ops dpvi_fpn0_ops = {
	.ndo_start_xmit	= dpvi_xmit,
	.ndo_get_stats = dpvi_get_stats,
	.ndo_select_queue  = dpvi_select_queue,
};

static const unsigned char dpvi_fpn0_hw_addr[6] = { 0x00, 0x00, 0x46, 0x50, 0x4E, 0x00 };

static int dpvi_register_fpn0(void)
{
	struct net_device *dev = NULL;
	struct dpvi_priv *priv;

	DPVI_DEBUG("enter");

	dev = alloc_netdev(sizeof(*priv), "fpn0",
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
			   NET_NAME_PREDICTABLE,
#endif
			   ether_setup);

	if(!dev)
		return -1;

	priv = netdev_priv(dev);
	dev->netdev_ops = &dpvi_fpn0_ops;
	dev->dev_addr = (unsigned char *)dpvi_fpn0_hw_addr;
	dev->flags |= IFF_NOARP;
	dev->tx_queue_len = 0;
	/* We do our own locking */
	dev->features |= NETIF_F_LLTX;

	priv->portid = FPN_RESERVED_PORTID_FPN0;

	if (register_netdev(dev)) {
		free_netdev(dev);
		DPVI_ERR("cpu %u: register_netdev fail for fpn0", smp_processor_id());
		return -1;
	}

	dev_fpn0 = dev;

	return 0;
}

static void dpvi_free_fpn0(void)
{
	DPVI_DEBUG("enter");

	if (dev_fpn0 == NULL)
		return;
	unregister_netdev(dev_fpn0);
	free_netdev(dev_fpn0);
}

/* called at interface creation */
static void dpvi_setup(struct net_device *dev)
{
	dev->netdev_ops = &dpvi_ops;

	DPVI_DEBUG("enter");

	/* Fill in device structure with ethernet-generic values. */
	ether_setup(dev);
	dev->tx_queue_len = 0;
	dev->ethtool_ops = &dpvi_ethtool_ops;

	/* We do our own locking */
	dev->features |= NETIF_F_LLTX;
}

static void enqueue_copy(struct fpn_dring_entry *dre, struct fpn_dring_entry *in)
{
	uint32_t len = in->len;

	DPVI_DEBUG("enter");

	if (dre->data == 0) {
		DPVI_ERR("cpu %u: find dre.data NULL txring=%u port=%u\n", smp_processor_id(), in->from, in->port);
		dump_stack();
		return;
	}
	in->from = smp_processor_id();
	if (len > dre->len)
		len = dre->len;
	memcpy(phys_to_virt(dre->data), (void *)(unsigned long)in->data, len);
	dre->port = in->port;
	dre->from = in->from;
	dre->eop = in->eop;
	dre->len = len;
}

static inline int dpvi_may_handoff(struct sk_buff *skb, int cpu)
{
	/* Don't use this cpu if it runs FP.
	 * In this case we hand off the packet to another cpu using
	 * the shared tx_skbq_nocpu then we trigger a polling.
	 */
	if (fpn_cpumask_ismember(&_fp_mask, cpu)) {
		DPVI_INFO("%s: handoff cpu=%u\n", __func__, cpu);
		tx_skbq_enqueue(skb, skb->dev);
		eventfd_signal(work_poll[dpvi_first_core].efd_ctx, 1);
		return 1;
	}

	return 0;
}

/*
 * skb->queueu_mapping is set to tx ring index (FP cpu id) */
static int dpvi_enqueue(struct sk_buff *skb, uint16_t portid)
{
	int cpu = smp_processor_id();
	struct fpn_dring *r;
	struct fpn_dring_list *ring_list;
	struct fpn_dring_entry dre;
	int ret;
	u16 fp_tx_ring;

	DPVI_DEBUG("enter");

	if (dpvi_may_handoff(skb, cpu))
		return 0;
	fp_tx_ring = fp_txring_map[skb_get_queue_mapping(skb)];
	dre.data = (unsigned long)skb->data;
	dre.len = skb->len;
	dre.port = portid;
	dre.from = fp_tx_ring;
	dre.eop = 1;

	ring_list = &fpn_dpvi_shmem->tx_ring[fp_tx_ring];
	r = &ring_list->cpu[cpu];

	DPVI_DEBUG("%s: cpu=%u port=%u fp_tx_ring=%u\n", __func__, cpu, portid, fp_tx_ring);
	ret = fpn_dring_enqueue(r, &dre, 1, enqueue_copy);
	if (ret == 0)
		r->prod.enqueue++;
	else
		r->prod.enqueue_err++;

	/* Data is copied, we can free skb right now */
	kfree_skb(skb);
	return 0;
}

static int dpvi_enqueue_multi(struct sk_buff *skb, uint16_t portid, int nsegs)
{
	int cpu = smp_processor_id();
	struct fpn_dring *r;
	struct fpn_dring_list *ring_list;
	struct fpn_dring_entry dre[16];
	int ret;
	u16 fp_tx_ring;
	size_t offset = 0;
	size_t len = fpn_dpvi_shmem->fp_tx_mbuf_size;
	int i = 0;

	DPVI_DEBUG("enter");

	if (dpvi_may_handoff(skb, cpu))
		return 0;

	fp_tx_ring = fp_txring_map[skb_get_queue_mapping(skb)];
again:
	dre[i].len = (i == (nsegs - 1)) ? skb->len - offset : len;
	dre[i].data = (unsigned long)skb->data + offset;
	dre[i].port = portid;
	dre[i].from = fp_tx_ring;
	dre[i].eop = (i == (nsegs - 1));

	if (i < (nsegs - 1)) {
		offset += len;
		i++;
		goto again;
	}

	ring_list = &fpn_dpvi_shmem->tx_ring[fp_tx_ring];
	r = &ring_list->cpu[cpu];

	DPVI_DEBUG("%s: cpu=%u port=%u fp_tx_ring=%u i=%u\n", __func__, cpu, portid, fp_tx_ring, i);

	ret = fpn_dring_enqueue(r, dre, i + 1, enqueue_copy);
	if (ret == 0)
		r->prod.enqueue += nsegs;
	else
		r->prod.enqueue_err += nsegs;

	/* Data is copied, we can free skb right now */
	kfree_skb(skb);
	return 0;
}

static int dpvi_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct dpvi_priv *priv = netdev_priv(dev);

	DPVI_DEBUG("enter");

	/* If fastpath is down, just drop packet */
	if (running_fastpath == 0) {
		kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	if (unlikely(skb->len > fpn_dpvi_shmem->fp_tx_mbuf_size)) {
		int nsegs = skb->len / fpn_dpvi_shmem->fp_tx_mbuf_size + 1;
		if (skb->len == (nsegs * fpn_dpvi_shmem->fp_tx_mbuf_size))
			nsegs --;
		dpvi_enqueue_multi(skb, priv->portid, nsegs);
	} else
		dpvi_enqueue(skb, priv->portid);

	return NETDEV_TX_OK;
}

/*
 * We received a "port status" info control message. This is sent
 * by the FP to indicate a status change.
 */
static int dpvi_rcv_port_status(struct sk_buff *skb)
{
	uint16_t portid;

	DPVI_DEBUG("enter\n");

	if (skb_pull(skb, sizeof(struct dpvi_hdr)) == NULL) {
		DPVI_ERR("Cannot pull DPVI header\n");
		return -ENOBUFS;
	}

	/* Do not modify port statuses while fastpath is down */
	if (running_fastpath == 0)
		return 0;

	/* blind update of status in netdevice private data */
	for (portid = 0; portid < DPVI_MAX_PORTS; portid++) {
		struct net_device *dpvi_dev = NULL;
		struct dpvi_priv *priv = NULL;
		struct fpn_port *port;

		port = &fpn_port_shmem->port[portid];

		/* if port is not enabled, skip */
		if (port->enabled == 0)
			continue;
		if (port->dpvi_managed == 0)
			continue;

		dpvi_dev = dpvi_table[portid];
		if (dpvi_dev == NULL)
			continue;
		priv = netdev_priv(dpvi_dev);
		if (priv == NULL)
			continue;

		/* notify link changes to the stack */
		if (priv->link != 0 && port->link == 0) {
			DPVI_INFO("%s NIC Link is Down\n",
			       dpvi_dev->name);
			netif_carrier_off(dpvi_dev);
		}
		if (priv->link == 0 && port->link != 0) {
			DPVI_INFO("%s NIC Link is Up\n",
			       dpvi_dev->name);
			netif_carrier_on(dpvi_dev);
		}

		/* update private data */
		priv->speed       = port->speed;
		priv->full_duplex = port->full_duplex;
		priv->link        = port->link;
	}

	return 0;
}

/*
 * We received a control message (type=info). These kind of messages
 * are sent by the FP without any request from DPVI module. Dispatch
 * the messages to the specific handler.
 */
static int dpvi_rcv_ctrl_info(struct sk_buff *skb)
{
	struct dpvi_hdr *dpvi_hdr;
	int ret = 0;

	DPVI_DEBUG("enter\n");

	/* skb is cloned by AF_PACKET if tcpdump is running */
	skb = skb_unshare(skb, GFP_ATOMIC);
	if (!skb) {
		DPVI_ERR("Cannot unshare skb\n");
		return -ENOBUFS;
	}

	dpvi_hdr = (struct dpvi_hdr *)skb->data;

	switch (dpvi_hdr->cmd) {
		case DPVI_CMD_PORT_STATUS:
			ret = dpvi_rcv_port_status(skb);
			break;

		default:
			DPVI_ERR("Unknown info control message\n");
			break;
	}

	kfree_skb(skb);
	return ret;
}

/*
 * We received a control message (type=answer). These kind of messages
 * are sent by the FP to answer to a previous request from DPVI
 * module. These messages are queued by in "ctrl_answer_queue" (only
 * one message is allowed in the queue).
 */
static int dpvi_rcv_ctrl_ans(struct sk_buff *skb)
{
	struct sk_buff *oldskb = NULL;

	DPVI_DEBUG("enter\n");

	/* if queue contains an old message, drop it */
	oldskb = skb_dequeue_tail(&ctrl_answer_queue);
	if (oldskb != NULL)
		kfree_skb(oldskb);

	/* add received buffer in queue */
	skb_queue_head(&ctrl_answer_queue, skb);
	return 0;
}


/*
 * Called when we receive a packet with ethertype = ETH_P_DPVI. The
 * packet contains either control information or data to be received
 * on a DPVI. This function dispatch to the appropriate handler.
 */
static int dpvi_rcv(struct sk_buff *skb, struct net_device *dev,
		    struct packet_type *pt, struct net_device *netdev)
{
	struct dpvi_hdr *dpvi_hdr;

	DPVI_DEBUG("enter\n");

	if (dev != dev_fpn0) {
		DPVI_ERR("Packet received on interface != fpn0: %s\n",
			 dev->name);
		goto error;
	}

	if (!pskb_may_pull(skb, DPVI_HLEN)) {
		DPVI_ERR("Malformed packet\n");
		goto error;
	}
	dpvi_hdr = (struct dpvi_hdr *)skb_network_header(skb);

	switch (dpvi_hdr->type) {

		/* ctrl message, add in queue */
		case DPVI_TYPE_CTRL_INFO:
			dpvi_rcv_ctrl_info(skb);
			break;

		/* answer to a previous request, add in queue */
		case DPVI_TYPE_CTRL_ANS:
			dpvi_rcv_ctrl_ans(skb);
			break;

		/* other control messages are garbage, drop
		 * them */
		default:
			goto error;
			break;
	}

	return 0;

 error:
	kfree_skb(skb);
	return 0;
}

/*
 * Allocate and add a dpvi interface.
 * Returns 0 on success, else returns a negative value
 */
static int dpvi_init_one(char *name, struct fpn_port *port)
{
	struct net_device *dpvi_dev = NULL;
	struct dpvi_priv *priv = NULL;
	int err;

	DPVI_DEBUG("enter for %s", name);

	if (port->portid >= DPVI_MAX_PORTS) {
		DPVI_ERR("Invalid port id: %d\n", port->portid);
		return -EINVAL;
	}

	if (dpvi_table[port->portid] != NULL) {
		DPVI_ERR("Interface already exist for portid: %d\n", port->portid);
		return -EEXIST;
	}

	dpvi_dev = alloc_netdev_mq(sizeof(struct dpvi_priv), name,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
				   NET_NAME_ENUM,
#endif
				   dpvi_setup, fp_txring_map_len);
	if (!dpvi_dev) {
		DPVI_ERR("could not allocate new dpvi device for portid: %d\n",
		          port->portid);
		return -ENOMEM;
	}

	memcpy(dpvi_dev->dev_addr, port->etheraddr, ETH_ALEN);

	if ((err = register_netdev(dpvi_dev))) {
		DPVI_ERR("could not register new dpvi device for portid: %d\n",
		          port->portid);
		free_netdev(dpvi_dev);
		return err;
	}

	/* always start with carrier off */
	netif_carrier_off(dpvi_dev);

	/* everything went fine, insert the new dpvi interface into the list */
	priv = netdev_priv(dpvi_dev);
	memset(priv, 0, sizeof(*priv));
	/* init private data */
	priv->portid      = port->portid;
	priv->speed       = port->speed;
	priv->full_duplex = port->full_duplex;
	priv->link        = port->link;
	/* XXX MTU is 1500 by default, it should be sync'd with FP */

	dpvi_table[port->portid] = dpvi_dev;
	port->linux_ifindex = dpvi_dev->ifindex;

	if (port->link)
		netif_carrier_on(dpvi_dev);

	DPVI_DEBUG("dpvi i/f added: %s for portid %d\n", dpvi_dev->name, priv->portid);

	return 0;
}

/*
 * dpvi_free_one: remove a dpvi interface
 * Returns 0 on success, else returns a negative value
 */
static int dpvi_free_one(uint16_t portid)
{
	struct net_device *dpvi_dev;

	DPVI_DEBUG("enter");

	if (portid >= DPVI_MAX_PORTS) {
		DPVI_ERR("Invalid port id\n");
		return -1;
	}

	dpvi_dev = dpvi_table[portid];
	if (dpvi_dev == NULL) {
		DPVI_ERR("Interface is not registered\n");
		return -1;
	}

	DPVI_DEBUG("dpvi i/f removed: %s for portid %d\n", dpvi_dev->name, portid);

	dpvi_table[portid] = NULL;
	unregister_netdev(dpvi_dev);
	free_netdev(dpvi_dev);
	return 0;
}

/*
 * Check parameters at module load.
 */
static int __init dpvi_parse_params(void)
{
	int cpu;
	fpn_cpumask_t total_mask;

	/* Initialise masks */
	fpn_cpumask_clear(&total_mask);
	kernel_cpumask_parse(fp_mask, &_fp_mask);
	kernel_cpumask_parse(dpvi_mask, &_dpvi_mask);
	kernel_cpumask_parse(l_mask, &_l_mask);

	/* Setup online cores mask */
	for (cpu=0 ; cpu<num_online_cpus() ; cpu++)
		fpn_cpumask_set(&total_mask, cpu);

	/* No core dedicated to exception processing, use all cores by default */
	if (fpn_cpumask_isempty(&_l_mask))
		_l_mask=total_mask;

	/* Remove fastpath cores from DPVI ones */
	fpn_cpumask_sub(&_dpvi_mask, &_fp_mask);
	/* Restrict linux exception processing mask to fastpath cores */
	fpn_cpumask_filter(&_l_mask, &_fp_mask);

	/* Compute default mask if none given */
	if (fpn_cpumask_isempty(&_dpvi_mask))
		dpvi_select_default_mask(&total_mask, &_fp_mask, &_dpvi_mask);

	kernel_cpumask_display("dpvi: fp_mask", &_fp_mask);
	kernel_cpumask_display("dpvi: dpvi_mask", &_dpvi_mask);
	kernel_cpumask_display("dpvi: l_mask", &_l_mask);
	kernel_cpumask_display("dpvi: online_mask", &total_mask);

	return 0;
}

/*
 * Handler when /proc/sys/dpvi/list_interfaces is read
 * Returns 0 on success, else returns a negative value
 */
static int dpvi_sysctl_list_interfaces(struct ctl_table *ctl, int write,
				       void __user *buffer, size_t *lenp,
				       loff_t *ppos)
{
	struct net_device *dpvi_dev;
	int err, n = 0;
	uint16_t portid;
	int len = 0;

	DPVI_DEBUG("enter");

	if (write) {
		err = -EPERM;
		goto out;
	}

	strcpy((char*)ctl->data, "");

	for (portid = 0; portid < DPVI_MAX_PORTS; portid++) {
		dpvi_dev = dpvi_table[portid];
		if (dpvi_dev == NULL)
			continue;
		n = snprintf((char *)ctl->data + len, ctl->maxlen-len,
			     "%s%d %s", len == 0 ? "" : "\n",
			     portid, dpvi_dev->name);
		if (n < 0) {
			err = -EINVAL;
			goto out;
		}
		len += n;
		if (len >= ctl->maxlen) {
			DPVI_ERR("dpvi list is truncated (%d>=%d)\n",
				 len, ctl->maxlen);
			break;
		}
	}

	if ((err = proc_dostring(ctl, write, buffer, lenp, ppos)) < 0)
		return err;

	return err;

out:
	strcpy((char*)ctl->data, "");
	return err;
}

/*
 * Handler when /proc/sys/dpvi/running_fastpath is read/write
 * Returns 0 on success, else returns a negative value
 */
static int dpvi_sysctl_running_fastpath(struct ctl_table *ctl, int write,
				       void __user *buffer, size_t *lenp,
				       loff_t *ppos)
{
	int ret = 0;

	DPVI_DEBUG("enter");

	if ((ret = proc_dointvec(ctl, write, buffer, lenp, ppos)) < 0)
		return ret;

	if (write) {
		uint16_t portid;
		int new_fastpath = running_fastpath;
		int i;

		running_fastpath = 0;

		/* Parse configuration */
		if (dpvi_parse_params() < 0) {
			ret = -EINVAL;
			DPVI_ERR("Invalid parameters\n");
			goto fail;
		}

		cpu_fp_maplen = 0;

		/* Initialize cpu map to select Fastpath cpu */
		for (i = 0; i < FPN_MAX_CORES; i++) {
			if (!fpn_cpumask_ismember(&_fp_mask, i))
				continue;

			cpu_fp_map[cpu_fp_maplen] = i;
			cpu_fp_maplen++;
		}

		/* Get the first dpvi core */
		for (i = 0; i < FPN_MAX_CORES; i++) {
			if (!fpn_cpumask_ismember(&_dpvi_mask, i))
				continue;
			dpvi_first_core = i;
			break;
		}

		/* Initialize DPVI part of the rings */
		if (dpvi_init_ring()) {
			DPVI_ERR("could not init the dpvi rings\n");
			ret = -ENOMEM;
			goto fail;
		}

		/* for each port, create a DPVI when needed */
		/* First create ports with a name specified, to be sure that */
		/* unspecified names will not override a named interface */
		for (portid = 0; portid < DPVI_MAX_PORTS; portid++) {
			/* Not managed or disabled */
			if ((!fpn_port_shmem->port[portid].dpvi_managed) ||
			    (!fpn_port_shmem->port[portid].enabled))
				continue;

			/* Here either dpvi_table[portid] is NULL, or it is set */
			/* to the correct interface */
			if ((dpvi_table[portid] == NULL) && 
			    (fpn_port_shmem->port[portid].portname[0] != 0)) {
				ret = dpvi_init_one(fpn_port_shmem->port[portid].portname,
				                    &fpn_port_shmem->port[portid]);
				if (ret != 0)
					goto fail;
			}
		}

		/* Then create unnamed ports */
		for (portid = 0; portid < DPVI_MAX_PORTS; portid++) {
			/* Not managed or disabled */
			if ((!fpn_port_shmem->port[portid].dpvi_managed) ||
			    (!fpn_port_shmem->port[portid].enabled))
				continue;

			/* Setup remaining unset interfaces using default name */
			if (dpvi_table[portid] == NULL) {
				/* eth%d is the default template for the new netdevices */
				ret = dpvi_init_one("eth%d",  &fpn_port_shmem->port[portid]);
				if (ret != 0)
					goto fail;
			}
		}

		/* Start threads */
		if (dpvi_start_ring()) {
			DPVI_ERR("could not start the dpvi threads\n");
			ret = -ENOMEM;
			goto fail;
		}

		/* Change fpn0 link status */
		netif_carrier_on(dev_fpn0);

		/* Other port status will be setup automatically by FP */

		running_fastpath = new_fastpath;
		DPVI_LOG("Watching PID %d\n", running_fastpath);
	}

fail:
	return ret;
}

/*
 * Contents of /proc/sys/dpvi directory
 */
struct ctl_table dpvi_sysctl_table[] = {
	{
		.procname       =       "list_interfaces",
		.data           =       dpvi_sysctl_list_interfaces_buf,
		.maxlen         =       sizeof(dpvi_sysctl_list_interfaces_buf),
		.mode           =       0644,
		.proc_handler   =       &dpvi_sysctl_list_interfaces,
	},
	{
		.procname       =       "running_fastpath",
		.data           =       &running_fastpath,
		.maxlen         =       sizeof(running_fastpath),
		.mode           =       0644,
		.proc_handler   =       &dpvi_sysctl_running_fastpath,
	},
	{
		/* sentinel */
		.procname       =       NULL,
	}
};

/*
 * Define /proc/sys/dpvi directory
 */
struct ctl_table dpvi_sysctl_root_table[] = {
	{
		.procname       =       "dpvi",
		.mode           =       0555,
		.child          =       dpvi_sysctl_table,
	},
	{
		/* sentinel */
		.procname       =       NULL,
	}
};

static long dpvi_unlocked_ioctl(struct file *f, unsigned int ioctl,
                                unsigned long arg)
{
	struct dpvi_ioctl_arg ioarg;

	if (copy_from_user(&ioarg, (const void *)arg,
	                   sizeof(struct dpvi_ioctl_arg))) {
		DPVI_ERR("failed to copy argument from userland");
		return -EFAULT;
	}

	if (ioctl != DPVI_IOCTL) {
		DPVI_ERR("wrong ioctl");
		return -EINVAL;
	}

	work_poll[ioarg.dpvi_cpu].efd_ctx = eventfd_ctx_fdget(ioarg.efd);

	return 0;
}

struct file_operations dpvi_dev_fops = {
	.unlocked_ioctl = dpvi_unlocked_ioctl,
};

struct miscdevice dpvi_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "dpvi-perf",
	.fops  = &dpvi_dev_fops,
};

/*
 * Delete all DPVI interfaces.
 */
static void dpvi_clear_interfaces(void)
{
	struct sk_buff *skb;
	uint16_t portid;

	DPVI_DEBUG("enter");

	/* cancel work tasks */
	flush_scheduled_work();

	/* delete all interfaces */
	for (portid = 0; portid < DPVI_MAX_PORTS; portid++) {
		if (dpvi_table[portid] == NULL)
			continue;
		dpvi_free_one(portid);
	}
	dpvi_free_fpn0();

	/* purge queues */
	while ((skb = skb_dequeue_tail(&ctrl_answer_queue)))
		kfree_skb(skb);
}

/* module unload */
static void dpvi_cleanup_module(void)
{
	/* Stop rings */
	dpvi_stop_ring();

	/* Remove sysctl */
	if (dpvi_sysctl_header != NULL)
		unregister_sysctl_table(dpvi_sysctl_header);

	/* Remove dpvi-dev */
	misc_deregister(&dpvi_dev);

	/* Clear virtual interfaces */
	dpvi_clear_interfaces();

	/* Remove protocol handler */
	dev_remove_pack(&dpvi_packet_type);
}

/* module load */
static int __init dpvi_init_module(void)
{
	int ret, i;
	struct sockaddr_nl sin;
	struct msghdr msg;
	struct kvec	iov;
	struct nlmsghdr *nl_hdr;
	struct cn_msg *cn_hdr;
	enum proc_cn_mcast_op *op;
	char buffer[DPVI_NL_BUFSIZE];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	struct file *file;
#endif

	DPVI_DEBUG("enter");

	/* init queues and work tasks */
	tx_skbq_init();
	skb_queue_head_init(&ctrl_answer_queue);
	/* add the ETH_P_DPVI protocol handler (always successful) */
	dev_add_pack(&dpvi_packet_type);

	/* Create shared memories */
	fpn_shmem_add("fpn-port-shared", sizeof(port_mem_t));
	fpn_shmem_add("dpvi-shared", sizeof(*fpn_dpvi_shmem));

	/* Map shared memories */
	fpn_dpvi_shmem = fpn_shmem_mmap("dpvi-shared", NULL, sizeof(struct fpn_dpvi_shmem));
	if (!fpn_dpvi_shmem) {
		DPVI_ERR("could not find dpvi-shared\n");
		ret = -ENOMEM;
		goto fail;
	}
	fpn_port_shmem = (port_mem_t *) fpn_shmem_mmap("fpn-port-shared", NULL, sizeof(port_mem_t));
	if (!fpn_port_shmem) {
		DPVI_ERR("could not find port shmem\n");
		ret = -ENOMEM;
		goto fail;
	}

	/* Clean shared memories contents */
	memset(fpn_dpvi_shmem, 0, sizeof(struct fpn_dpvi_shmem));
	memset(fpn_port_shmem, 0, sizeof(port_mem_t));

	/* Initialize DPVI ports */
	for (i=0; i<DPVI_MAX_PORTS; i++)
		dpvi_table[i] = NULL;

	/* Create fpn0 early, used by get-portlist() */
	if (dpvi_register_fpn0()) {
		ret = -ENOMEM;
		goto fail;
	}

	/* register the list_interface sysctl */
	dpvi_sysctl_header = register_sysctl_table(dpvi_sysctl_root_table);
	if (dpvi_sysctl_header == NULL) {
		ret = -ENOMEM;
		goto fail;
	}

	/* Create netlink socket */
	ret = sock_create_kern(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR, &nl_sock);
	if (ret < 0) {
		DPVI_ERR("Fail to initialize kernel socket (%d)\n", ret);
		goto fail;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	/* Since kernel 3.15, it is mandatory to have a file mapping of the socket */
	/* Needed by ns capabilities check in connector module (file_ns_capable) */
	/* Since it has been backported on some 3.14 kernels, start on 3.10 */
	file = sock_alloc_file(nl_sock, 0, NULL);
	if (IS_ERR(file)) {
		DPVI_ERR("Fail to map socket (%p)\n", file);
		ret = (int)(size_t) file;
		goto fail;
	}
#endif

	/* Create device to use ioctl */
	ret = misc_register(&dpvi_dev);
	if (ret < 0) {
		DPVI_ERR("Fail to register misc device (%d)\n", ret);
		goto fail;
	}

	/* Start to watch proc group */
	sin.nl_family = AF_NETLINK;
	sin.nl_groups = CN_IDX_PROC;
	sin.nl_pid = 0;
	ret = kernel_bind(nl_sock, (struct sockaddr *) &sin, sizeof(sin));
	if (ret < 0) {
		DPVI_ERR("Fail to bind socket (%d)\n", ret);
		goto fail;
	}

	/* Setup multicast listen message */
	memset(&msg, 0, sizeof(msg));
	memset(buffer, 0, sizeof(buffer));
	nl_hdr = (struct nlmsghdr *)buffer;
	cn_hdr = (struct cn_msg *)NLMSG_DATA(nl_hdr);
	op = (enum proc_cn_mcast_op*)&cn_hdr->data[0];
	*op = PROC_CN_MCAST_LISTEN;

	/* Fill the netlink header */
	nl_hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op));
	nl_hdr->nlmsg_type = NLMSG_DONE;
	nl_hdr->nlmsg_flags = 0;
	nl_hdr->nlmsg_seq = 0;
	nl_hdr->nlmsg_pid = 0;

	/* Fill the connector header */
	cn_hdr->id.idx = CN_IDX_PROC;
	cn_hdr->id.val = CN_VAL_PROC;
	cn_hdr->seq = 0;
	cn_hdr->ack = 0;
	cn_hdr->len = sizeof(enum proc_cn_mcast_op);

	/* Fill descriptor */
	iov.iov_base = &buffer;
	iov.iov_len  = sizeof(buffer);

	/* Send message */
	ret = kernel_sendmsg(nl_sock, &msg, &iov, 1, nl_hdr->nlmsg_len);
	if (ret != nl_hdr->nlmsg_len) {
		DPVI_ERR("Could not send mcast listen message\n");
		goto fail;
	}

	/* Init polling task */
	nl_poll = kthread_create(dpvi_nl_poll_task, NULL, "dpvi-nl-task");
	if (nl_poll == NULL) {
		DPVI_ERR("dpvi: can not start kernel thread\n");
		ret = -ECHILD;
		goto fail;
	}
	wake_up_process(nl_poll);

	DPVI_DEBUG("dpvi module initialized\n");
	return 0;

 fail:
	/* Close netlink socket here since kthread is not started */
	dpvi_cleanup_socket();

	/* Cleanup module */
 	dpvi_cleanup_module();
	return ret;
}

static void __exit dpvi_exit_module(void)
{
	struct task_struct *tid = nl_poll;

	if (tid != NULL) {
		/* Kill poll task, this will close netlink socket */
		send_sig_info(SIGKILL, SEND_SIG_NOINFO, tid);
		kthread_stop(tid);
	}

	/* Cleanup module */
 	dpvi_cleanup_module();
}

module_init(dpvi_init_module);
module_exit(dpvi_exit_module);
MODULE_LICENSE("GPL");
