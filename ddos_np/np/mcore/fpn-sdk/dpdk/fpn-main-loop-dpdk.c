/*
 * Copyright(c) 2011  6WIND
 */

#include "fpn.h"
#ifdef CONFIG_MCORE_FPN_CRYPTO
#include "fpn-crypto.h"
#endif
#ifdef CONFIG_MCORE_INTERCORE
#include "fpn-intercore.h"
#endif
#ifdef CONFIG_MCORE_SW_TCP_LRO
#include "fpn-sw-tcp-lro.h"
#endif

/* 10 µs idle time @ 3 GHz */
#define RTE_CRYPTO_IDLE 30000

extern unsigned fpn_recv_exception(void);

void fpn_process_soft_input(struct mbuf *m)
{
	m_clear_flags(m);
	fpn_mainloop_ops->soft_input(m);
}

void fpn_process_input(struct mbuf *m)
{
	uint8_t *buf;
	int portid;

	portid = m_input_port(m);
	if (unlikely(fpn_check_port(portid) < 0))
		goto fail;

	buf = mtod(m, uint8_t *);

	if (unlikely(buf[0] & 0x01)) {
		if (buf[0] == 0xFF &&
		    buf[1] == 0xFF &&
		    buf[2] == 0xFF &&
		    buf[3] == 0xFF &&
		    buf[4] == 0xFF &&
		    buf[5] == 0xFF) {
			m_add_flags(m, M_F_BCAST);
		}
		else {
			m_add_flags(m, M_F_MCAST);
		}
	}

	fpn_mainloop_ops->input(m);
	return;

fail:
	m_freem(m);
}

/* main processing loop */
int fpn_main_loop(__attribute__((unused)) void *unused)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct mbuf *m;
	struct rte_mbuf *rtemb;
	unsigned lcore_id;
	uint64_t prev_tsc_timer = 0;
	uint64_t prev_tsc_burst_cycles = 0;
	uint64_t diff_tsc, cur_tsc;
	hook_t *fpn_hook = fpn_mainloop_ops->hook;
#ifdef CONFIG_MCORE_TIMER_GENERIC
	const uint64_t cycles_interval = fpn_timer_cycles_resolution;
#endif
	unsigned j, nb_rx;
	unsigned i, portid = -1, pkt_idx, queueid;
#ifdef CONFIG_MCORE_FPN_CRYPTO
	uint64_t idle_tsc = rte_rdtsc();
#endif
	struct lcore_conf *conf;
#if defined(CONFIG_MCORE_FPVI)
	uint64_t linux_rcv;
	unsigned rcv_packets = 0;
#endif
#if defined(CONFIG_MCORE_INTERCORE)
	uint64_t ic_rcv;
#endif
#ifdef CONFIG_MCORE_DEBUG_CPU_USAGE
	cpu_usage_declare();
#endif
	FP_CYCLES_DECLARE();

	lcore_id = rte_lcore_id();
	conf = &lcore_conf[lcore_id];
#if defined(CONFIG_MCORE_FPVI)
	linux_rcv = fpn_cpumask_ismember(&fpn_linux2fp_mask, lcore_id);
#endif
#if defined(CONFIG_MCORE_INTERCORE)
	ic_rcv = fpn_cpumask_ismember(&fpn_intercore_mask, lcore_id);
#endif

	if (conf->n_rx_queue == 0)
		printf("lcore %d has nothing to do\n", lcore_id);
	else
		printf("entering main loop on lcore %u%s\n", lcore_id,
		       (lcore_id == rte_get_master_lcore()) ? " (master)":"");

	for (i = 0; i < conf->n_rx_queue; i++) {
		queueid = conf->rxq[i].queue_id;
		portid = conf->rxq[i].port_id;
		printf(" RX -- lcoreid=%d queueid=%d portid=%d\n",
		       lcore_id, queueid, portid);
	}

	/* Port list used by TX drain */
	for (i = 0; i < fpn_rte_port_table.count; i++) {
		portid = fpn_rte_port_table.index[i];
		queueid = conf->txq[portid].queueid;
		printf(" TX -- lcoreid=%d queueid=%d portid=%d\n",
				lcore_id, queueid, portid);
	}

	prev_tsc_timer = rte_rdtsc();

	while (1) {
		rtemb = NULL;

		/* Fully protect main loop */
		FPN_ENTER(lcore_id);

		FP_CYCLES_TEST();

		cur_tsc = sys_tsc;
		cpu_usage(cur_tsc);
		diff_tsc = cur_tsc - prev_tsc_burst_cycles;

#if defined(CONFIG_MCORE_FPVI)
		/*
		 * read packets from linux if any, on specified cores
		 */
		if (unlikely(linux_rcv &&
			     (rcv_packets || diff_tsc > BURST_CYCLES))) {
			rcv_packets = fpn_recv_exception();
#ifdef CONFIG_MCORE_FPN_CRYPTO
			idle_tsc = cur_tsc;
#endif
			cpu_usage_acc();
		}
#endif

#if defined(CONFIG_MCORE_INTERCORE)
		/* read packets from intercore if any */
		if (unlikely(ic_rcv)) {
			nb_rx = fpn_intercore_drain(lcore_id);
			if (nb_rx) {
#ifdef CONFIG_MCORE_FPN_CRYPTO
				idle_tsc = cur_tsc;
#endif
				cpu_usage_acc_intercore(nb_rx);
			}
		}
#endif

		if (unlikely(diff_tsc > BURST_CYCLES)) {
			/*
			 * Timer management: we don't need a very
			 * precise timer, so wait a period of time
			 * between consecutive calls of timer_manage()
			 */

#ifdef CONFIG_MCORE_TIMER_GENERIC
			diff_tsc = cur_tsc - prev_tsc_timer;
			if (unlikely(diff_tsc >= cycles_interval)) {
				cpu_usage_check(lcore_id, cur_tsc);
				fpn_timer_process_tables(lcore_id);
				prev_tsc_timer += cycles_interval;
#ifdef CONFIG_MCORE_FPN_CRYPTO
				idle_tsc = cur_tsc;
#endif
				cpu_usage_acc();
			}
#endif
			prev_tsc_burst_cycles = cur_tsc;
		}

#ifdef CONFIG_MCORE_TIMER_GENERIC
		/* process immediate timers */
		if (fpn_timer_state[lcore_id].immediate_list_pending ||
		    fpn_timer_state[lcore_id].immediate_local_list_pending) {
			fpn_timer_process_immediate(lcore_id);
		}
#endif

		if (fpn_hook != NULL)
			if (fpn_hook() > 0) {
#ifdef CONFIG_MCORE_FPN_CRYPTO
				idle_tsc = cur_tsc;
#endif
				cpu_usage_acc();
			}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < conf->n_rx_queue; i++) {
			struct fpn_rxq *rxq;

			rxq = &conf->rxq[i];
			portid = rxq->port_id;

#ifdef CONFIG_MCORE_RTE_SHARED_QUEUES
			if (unlikely(fpn_rxq_shared[portid])) {
				/* Lock shared RX queue 0 of port */
				__fpn_spinlock_t *rxq0_lock =
				&fpn_rte_ports[portid].rxq0_lock;

				__fpn_spinlock_lock(rxq0_lock);
				nb_rx = rte_eth_rx_burst(portid, 0,
				                         pkts_burst,
				                         MAX_PKT_BURST);
				__fpn_spinlock_unlock(rxq0_lock);
			} else
#endif
			nb_rx = rte_eth_rx_burst(portid, rxq->queue_id,
					pkts_burst, MAX_PKT_BURST);

			/* prefetch packets from last RX burst */
			for (pkt_idx = 0; pkt_idx < nb_rx; pkt_idx++)
				rte_prefetch_non_temporal(pkts_burst[pkt_idx]->buf_addr +
					      RTE_PKTMBUF_HEADROOM);

#ifdef CONFIG_MCORE_SW_TCP_LRO
			{
				uint16_t sw_lro;
				sw_lro = fpn_port_shmem->port[portid].sw_lro;
				if (sw_lro != 0 && nb_rx > 1)
					fpn_sw_lro_reass((struct mbuf **)pkts_burst,
						&nb_rx, sw_lro);
			}
#endif

			for (j = 0; j < nb_rx; j++) {
				rtemb = pkts_burst[j];
				m = (struct mbuf *)rtemb;

				m_set_egress_color(m, FPN_QOS_COLOR_GREEN);
				m_clear_flags(m);
				m_set_nextpkt(m, NULL);

				M_TRACK(m, "INPUT");

				FPN_DPDK_DEBUG_RX("recv %p, %u\n", m, m->c.rtemb.in_port);

				fpn_process_input(m);
			}

			if (nb_rx) {
#ifdef CONFIG_MCORE_FPN_CRYPTO
				idle_tsc = cur_tsc;
#endif
				cpu_usage_acc_nic(nb_rx);
			}
		}

		/*
		 * TX burst queue drain
		 */
		for (i = 0; i < fpn_rte_port_table.count; i++) {
			struct fpn_txq *txq;

			portid = fpn_rte_port_table.index[i];
			txq = &conf->txq[portid];
			fpn_rte_drain_txq(txq, portid);
		}

#ifdef CONFIG_MCORE_FPN_CRYPTO
		/* Receive packets processed by hardware */
		uint8_t flush = cur_tsc > (idle_tsc + RTE_CRYPTO_IDLE);
		if (fpn_crypto_poll(flush) > 0) {
				idle_tsc = cur_tsc;
				cpu_usage_acc();
		}
#endif

		/* Exit protected section */
		FPN_EXIT(lcore_id);
	}
}
