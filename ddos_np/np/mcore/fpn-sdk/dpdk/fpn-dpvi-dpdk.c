/*
 * Copyright (c) 2012 6WIND, All rights reserved.
 */

#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "fpn.h"
#include "shmem/fpn-shmem.h"
#include "fpn-eth.h"
#include "unistd.h"

#include "fpn-dpvi-dpdk.h"
#include "fpn-dpvi-ring-func.h"
static struct fpn_dpvi_shmem *fpn_dpvi_shmem = NULL;
#ifdef FPN_DEBUG_DPVI
static int debug_new_dpvi = 0;
#endif
/* local copies of variables from fpn-dpdk.c */
static fpn_cpumask_t _fpn_mask;
static fpn_cpumask_t _fpn_linux2fp_mask;
static fpn_cpumask_t _dpvi_mask;
static fpn_cpumask_t _online_mask;

#if BUILT_DPDK_VERSION < DPDK_VERSION(1,7,0)
struct fpn_rte_stat {
	char stat_name[DPVI_ETHTOOL_GSTRING_LEN];
	int stat_offset;
};

static struct fpn_rte_stat fpn_rte_stats[] = {
	{"rx_packets", offsetof(struct rte_eth_stats, ipackets)},
	{"tx_packets", offsetof(struct rte_eth_stats, opackets)},
	{"rx_bytes",   offsetof(struct rte_eth_stats, ibytes)},
	{"tx_bytes",   offsetof(struct rte_eth_stats, obytes)},
	{"tx_errors",  offsetof(struct rte_eth_stats, oerrors)},
	{"rx_errors",  offsetof(struct rte_eth_stats, ierrors)},
	{"alloc_rx_buff_failed", offsetof(struct rte_eth_stats, rx_nombuf)},
	{"fdir_match", offsetof(struct rte_eth_stats, fdirmatch)},
	{"fdir_miss",  offsetof(struct rte_eth_stats, fdirmiss)},
	{"tx_flow_control_xon", offsetof(struct rte_eth_stats, tx_pause_xon)},
	{"rx_flow_control_xon", offsetof(struct rte_eth_stats, rx_pause_xon)},
	{"tx_flow_control_xoff", offsetof(struct rte_eth_stats, tx_pause_xoff)},
	{"rx_flow_control_xoff", offsetof(struct rte_eth_stats, rx_pause_xoff)},
};
#define FPN_RTE_NB_STATS FPN_ARRAY_SIZE(fpn_rte_stats)

static struct fpn_rte_stat fpn_rte_rxq_stats[] = {
	{"rx_packets", offsetof(struct rte_eth_stats, q_ipackets)},
	{"rx_bytes",   offsetof(struct rte_eth_stats, q_ibytes)},
};
#define FPN_RTE_NB_RXQ_STATS FPN_ARRAY_SIZE(fpn_rte_rxq_stats)

static struct fpn_rte_stat fpn_rte_txq_stats[] = {
	{"tx_packets", offsetof(struct rte_eth_stats, q_opackets)},
	{"tx_bytes",   offsetof(struct rte_eth_stats, q_obytes)},
	{"tx_errors",  offsetof(struct rte_eth_stats, q_errors)},
};
#define FPN_RTE_NB_TXQ_STATS FPN_ARRAY_SIZE(fpn_rte_txq_stats)
#endif

int fpn_dpvi_ethtool_get_drvinfo(int portid,
				 struct dpvi_ethtool_drvinfo *dpvi_info)
{
	struct rte_eth_dev *dev;
	struct rte_pci_device *pci_dev;

	memset(dpvi_info, 0, sizeof(*dpvi_info));
	if (fpn_check_port(portid) < 0)
		return -1;

	dev = &rte_eth_devices[portid];

#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
	if (!dev->device->driver)		
		return -1;	
	snprintf(dpvi_info->driver, sizeof(dpvi_info->driver), "%s",
			dev->device->driver->name);
	pci_dev = RTE_DEV_TO_PCI(dev->device);
#else
	if (!dev->driver)		
	    return -1;		
	snprintf(dpvi_info->driver, sizeof(dpvi_info->driver), "%s",
			dev->driver->pci_drv.name);
	pci_dev = dev->pci_dev; 
#endif


	if (!pci_dev)
		return 0;

	if (pci_dev->addr.domain || pci_dev->addr.bus || pci_dev->addr.devid)
		snprintf(dpvi_info->bus_info, sizeof(dpvi_info->bus_info),
			 PCI_PRI_FMT, pci_dev->addr.domain, pci_dev->addr.bus,
			 pci_dev->addr.devid, pci_dev->addr.function);

	return 0;
}

int fpn_dpvi_ethtool_get_settings(int portid,
				  struct dpvi_ethtool_gsettings *gset)
{
	struct rte_eth_link *link;

	if (fpn_check_port(portid) < 0)
		return -1;

	link = &fpn_rte_ports[portid].link;

	switch (link->link_speed) {
		case ETH_LINK_SPEED_10:
			gset->speed = htons(DPVI_ETHTOOL_LINK_SPEED_10);
			break;
		case ETH_LINK_SPEED_100: 
			gset->speed = htons(DPVI_ETHTOOL_LINK_SPEED_100);
			break;
		case ETH_LINK_SPEED_1000:
			gset->speed = htons(DPVI_ETHTOOL_LINK_SPEED_1000);
			break;
		case ETH_LINK_SPEED_10000:
			gset->speed = htons(DPVI_ETHTOOL_LINK_SPEED_10000);
			break;
		case ETH_LINK_SPEED_40000:
			gset->speed = htons(DPVI_ETHTOOL_LINK_SPEED_40000);
			break;
		default:
			gset->speed = htons(link->link_speed);
			break;
	}

	switch (link->link_duplex) {
		case ETH_LINK_HALF_DUPLEX:
			gset->duplex = htons(DPVI_ETHTOOL_LINK_HALF_DUPLEX);
			break;
		case ETH_LINK_FULL_DUPLEX:
			gset->duplex = htons(DPVI_ETHTOOL_LINK_FULL_DUPLEX);
			break;
		default:
			gset->duplex = htons(link->link_duplex);
			break;
	}

	gset->status = link->link_status;
	/* XXX not supported at the moment */
	gset->phy_addr = ~((__typeof__(gset->phy_addr)) 0);

	switch (fpn_rte_ports[portid].driver) {
	case RTE_EM:
	case RTE_IGB:
		/* XXX there are two media type supported but let's assume this
		 * is fiber here + we have no way at the moment to detect
		 * autoneg feature, so let's tell we have it */
		gset->port = DPVI_ETHTOOL_PORT_FIBRE;
		gset->transceiver = DPVI_ETHTOOL_XCVR_INTERNAL;

		gset->supported = htonl(DPVI_ETHTOOL_SUPPORTED_1000baseT_Full);
		gset->supported |= htonl(DPVI_ETHTOOL_SUPPORTED_FIBRE);
		gset->supported |= htonl(DPVI_ETHTOOL_SUPPORTED_Autoneg);
		gset->autoneg_advertised = htonl(DPVI_ETHTOOL_ADVERTISED_1000baseT_Full);
		gset->autoneg_advertised |= htonl(DPVI_ETHTOOL_ADVERTISED_FIBRE);
		gset->autoneg_advertised |= htonl(DPVI_ETHTOOL_ADVERTISED_Autoneg);
		gset->autoneg = htonl(DPVI_ETHTOOL_AUTONEG_ENABLE);
		break;
	case RTE_IGBVF:
		gset->port = DPVI_ETHTOOL_PORT_OTHER;
		gset->transceiver = DPVI_ETHTOOL_XCVR_EXTERNAL;

		gset->supported = htonl(DPVI_ETHTOOL_SUPPORTED_FIBRE);
		gset->supported |= htonl(DPVI_ETHTOOL_SUPPORTED_1000baseT_Full);
		gset->autoneg = htonl(DPVI_ETHTOOL_AUTONEG_DISABLE);
		break;
	case RTE_IXGBE:
		/* XXX this one is really tricky ... let's assume this is 10G
		 * fiber only */
		gset->port = DPVI_ETHTOOL_PORT_FIBRE;
		gset->transceiver = DPVI_ETHTOOL_XCVR_EXTERNAL;

		gset->supported = htonl(DPVI_ETHTOOL_SUPPORTED_10000baseT_Full);
		gset->supported |= htonl(DPVI_ETHTOOL_SUPPORTED_FIBRE);
		gset->autoneg_advertised = htonl(DPVI_ETHTOOL_ADVERTISED_10000baseT_Full);
		gset->autoneg_advertised |= htonl(DPVI_ETHTOOL_ADVERTISED_FIBRE);
		gset->autoneg = htonl(DPVI_ETHTOOL_AUTONEG_DISABLE);
		break;
	case RTE_IXGBEVF:
		gset->port = DPVI_ETHTOOL_PORT_OTHER;
		gset->transceiver = DPVI_ETHTOOL_XCVR_EXTERNAL;

		gset->supported = htonl(DPVI_ETHTOOL_SUPPORTED_FIBRE);
		gset->supported |= htonl(DPVI_ETHTOOL_SUPPORTED_10000baseT_Full);
		gset->autoneg = htonl(DPVI_ETHTOOL_AUTONEG_DISABLE);
		break;

	case RTE_I40E:
		gset->port = DPVI_ETHTOOL_PORT_FIBRE;
		gset->transceiver = DPVI_ETHTOOL_XCVR_INTERNAL;

		switch (link->link_speed) {		
		case ETH_LINK_SPEED_10000:
			gset->supported = htonl(DPVI_ETHTOOL_SUPPORTED_10000baseT_Full);
			gset->autoneg_advertised = htonl(DPVI_ETHTOOL_ADVERTISED_10000baseT_Full);
			break;
		case ETH_LINK_SPEED_40000:
			gset->supported = htonl(DPVI_ETHTOOL_SUPPORTED_40000baseT_Full);
			gset->autoneg_advertised = htonl(DPVI_ETHTOOL_ADVERTISED_40000baseT_Full);
			break;
		default:
			break;
		}
		//gset->supported = htonl(DPVI_ETHTOOL_SUPPORTED_10000baseT_Full);
		gset->supported |= htonl(DPVI_ETHTOOL_SUPPORTED_FIBRE);
		gset->supported |= htonl(DPVI_ETHTOOL_SUPPORTED_Autoneg);
		//gset->autoneg_advertised = htonl(DPVI_ETHTOOL_SUPPORTED_10000baseT_Full);
		gset->autoneg_advertised |= htonl(DPVI_ETHTOOL_ADVERTISED_FIBRE);
		gset->autoneg_advertised |= htonl(DPVI_ETHTOOL_ADVERTISED_Autoneg);
		gset->autoneg = htonl(DPVI_ETHTOOL_AUTONEG_ENABLE);
		break;

	default:
		gset->port = DPVI_ETHTOOL_PORT_OTHER;
		gset->transceiver = DPVI_ETHTOOL_XCVR_EXTERNAL;

		gset->supported = htonl(DPVI_ETHTOOL_SUPPORTED_Autoneg);
		gset->autoneg_advertised = htonl(DPVI_ETHTOOL_ADVERTISED_Autoneg);
		gset->autoneg = htonl(DPVI_ETHTOOL_AUTONEG_ENABLE);
		break;
	}

	{
		struct rte_eth_dev *dev;
		dev = &rte_eth_devices[portid];

#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
		uint8_t link_autoneg = dev->data->dev_link.link_autoneg;
#else
		uint8_t link_autoneg = dev->data->dev_conf.link_autoneg;
#endif
		if (dev->data) {
			gset->autoneg = htonl(link_autoneg == 0 ? DPVI_ETHTOOL_AUTONEG_DISABLE : DPVI_ETHTOOL_AUTONEG_ENABLE);
		}
	}

	return 0;
}

int fpn_dpvi_ethtool_get_sset_count(int portid,
	struct dpvi_ethtool_sset_count *dpvi_sset_count)
{
#if BUILT_DPDK_VERSION < DPDK_VERSION(1,7,0)
	struct rte_eth_dev *dev;
	uint32_t count;

	if (fpn_check_port(portid) < 0)
		return -1;
	if (ntohl(dpvi_sset_count->string_sets) != DPVI_ETHTOOL_SS_STATS)
		return -1;

	dev = &rte_eth_devices[portid];
	if (!dev->data)
		return -1;

	count = FPN_RTE_NB_STATS;
	count += dev->data->nb_rx_queues * FPN_RTE_NB_RXQ_STATS;
	count += dev->data->nb_tx_queues * FPN_RTE_NB_TXQ_STATS;
	dpvi_sset_count->val = htonl(count);
#else
	int32_t ret;

	if (ntohl(dpvi_sset_count->string_sets) != DPVI_ETHTOOL_SS_STATS)
		return -1;
	ret = rte_eth_xstats_get(portid, NULL, 0);
	if (ret < 0)
		return -1;

	dpvi_sset_count->val = htonl(ret);
#endif
	return 0;
}

int fpn_dpvi_ethtool_get_strings(int portid,
	struct dpvi_ethtool_gstrings *dpvi_strings)
{
#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
#if 0
	struct rte_eth_dev *dev;
	char *p;
	uint32_t i;
	uint32_t maxlen;
	uint32_t len;
	uint32_t left;

	if (fpn_check_port(portid) < 0)
		return -1;
	if (ntohl(dpvi_strings->string_sets) != DPVI_ETHTOOL_SS_STATS)
		return -1;

	dev = &rte_eth_devices[portid];
	if (!dev->data)
		return -1;

	p = (char *)dpvi_strings->data;
	left = maxlen = ntohl(dpvi_strings->len);

	len = FPN_MIN(FPN_RTE_NB_STATS, left);
	for (i = 0; i < len; i++) {
		memcpy(p, fpn_rte_stats[i].stat_name, DPVI_ETHTOOL_GSTRING_LEN);
		p += DPVI_ETHTOOL_GSTRING_LEN;
	}
	left -= len;

	len = FPN_MIN(dev->data->nb_rx_queues * FPN_RTE_NB_RXQ_STATS, left);
	for (i = 0; i < len; i++) {
		snprintf(p, DPVI_ETHTOOL_GSTRING_LEN, "rx_queue_%lu_%s",
			 i/FPN_RTE_NB_RXQ_STATS,
			 fpn_rte_rxq_stats[i%FPN_RTE_NB_RXQ_STATS].stat_name);
		p += DPVI_ETHTOOL_GSTRING_LEN;
	}
	left -= len;

	len = FPN_MIN(dev->data->nb_tx_queues * FPN_RTE_NB_TXQ_STATS, left);
	for (i = 0; i < len; i++) {
		snprintf(p, DPVI_ETHTOOL_GSTRING_LEN, "tx_queue_%lu_%s",
			 i/FPN_RTE_NB_TXQ_STATS,
			 fpn_rte_txq_stats[i%FPN_RTE_NB_TXQ_STATS].stat_name);
		p += DPVI_ETHTOOL_GSTRING_LEN;
	}
	left -= len;

	dpvi_strings->len = htonl(maxlen - left);
#endif

	struct rte_eth_xstat *xstats;
	uint32_t i, len;
	int32_t ret;
	char *p;

	if (ntohl(dpvi_strings->string_sets) != DPVI_ETHTOOL_SS_STATS)
	return -1;

	p = (char *)dpvi_strings->data;
	len = ntohl(dpvi_strings->len);
	xstats = fpn_malloc(sizeof(xstats[0]) * len, 0);
	ret = rte_eth_xstats_get(portid, xstats, len);
	if (ret < 0 || (uint32_t)ret > len) {
		fpn_free(xstats);
		return -1;
	}

	struct rte_eth_xstat_name* xstats_names 
		= malloc(sizeof(struct rte_eth_xstat_name) * len);
	if (xstats_names == NULL) {
		printf("Cannot allocate memory for xstats lookup\n");
		return -1;
	}
	if (len != (uint32_t)rte_eth_xstats_get_names(
		portid, xstats_names, len)) {
		printf("Error: Cannot get xstats lookup\n");
		free(xstats_names);
		return -1;
	}

	for (i = 0; i < len; i++) {
		snprintf(p, DPVI_ETHTOOL_GSTRING_LEN, "%s", xstats_names[i].name);
		p += DPVI_ETHTOOL_GSTRING_LEN;
	}
	fpn_free(xstats);

#else
	struct rte_eth_xstats *xstats;
	uint32_t i, len;
	int32_t ret;
	char *p;

	if (ntohl(dpvi_strings->string_sets) != DPVI_ETHTOOL_SS_STATS)
		return -1;

	p = (char *)dpvi_strings->data;
	len = ntohl(dpvi_strings->len);
	xstats = fpn_malloc(sizeof(xstats[0]) * len, 0);
	ret = rte_eth_xstats_get(portid, xstats, len);
	if (ret < 0 || (uint32_t)ret > len) {
		fpn_free(xstats);
		return -1;
	}

	for (i = 0; i < len; i++) {
		snprintf(p, DPVI_ETHTOOL_GSTRING_LEN, "%s", xstats[i].name);
		p += DPVI_ETHTOOL_GSTRING_LEN;
	}
	fpn_free(xstats);
#endif
	return 0;
}

int fpn_dpvi_ethtool_get_statsinfo(int portid,
	struct dpvi_ethtool_statsinfo *dpvi_stats)
{
#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
#if 0
	struct rte_eth_dev *dev;
	struct rte_eth_stats *stats;
	uint32_t i;
	uint32_t max_stats;
	uint32_t n_stats;
	uint32_t left;
	uint64_t *info_cnt;
	char *tmp;

	if (fpn_check_port(portid) < 0)
		return -1;

	dev = &rte_eth_devices[portid];
	if (!dev->data)
		return -1;

	stats = &fpn_rte_ports[portid].stats;

	left = max_stats = ntohl(dpvi_stats->n_stats);
	info_cnt = dpvi_stats->data;

	n_stats = FPN_MIN(FPN_RTE_NB_STATS, left);
	for (i = 0; i < n_stats; i++) {
		tmp = (char *) stats;
		tmp += fpn_rte_stats[i].stat_offset;
		*info_cnt++ = htonll(*((uint64_t *)tmp));
	}
	left -= n_stats;

	n_stats = FPN_MIN(dev->data->nb_rx_queues * FPN_RTE_NB_RXQ_STATS, left);
	for (i = 0; i < n_stats; i++) {
		tmp = (char *) stats;
		tmp += fpn_rte_rxq_stats[i%FPN_RTE_NB_RXQ_STATS].stat_offset;
		/* now align on queue */
		tmp += (i/FPN_RTE_NB_RXQ_STATS) * sizeof(*info_cnt);
		*info_cnt++ = htonll(*((uint64_t *)tmp));
	}
	left -= n_stats;

	n_stats = FPN_MIN(dev->data->nb_tx_queues * FPN_RTE_NB_TXQ_STATS, left);
	for (i = 0; i < n_stats; i++) {
		tmp = (char *) stats;
		tmp += fpn_rte_txq_stats[i%FPN_RTE_NB_TXQ_STATS].stat_offset;
		/* now align on queue */
		tmp += (i/FPN_RTE_NB_TXQ_STATS) * sizeof(*info_cnt);
		*info_cnt++ = htonll(*((uint64_t *)tmp));
	}
	left -= n_stats;

	dpvi_stats->n_stats = htonl(max_stats - left);
#endif
	struct rte_eth_xstat *xstats;
#else
	struct rte_eth_xstats *xstats;
#endif

	uint32_t i, len;
	int32_t ret;
	uint64_t *info_cnt;

	info_cnt = dpvi_stats->data;
	len = ntohl(dpvi_stats->n_stats);
	xstats = fpn_malloc(sizeof(xstats[0]) * len, 0);
	ret = rte_eth_xstats_get(portid, xstats, len);
	if (ret < 0 || (uint32_t)ret > len) {
		fpn_free(xstats);
		return -1;
	}

	for (i = 0; i < len; i++) {
		*info_cnt = htonll(xstats[i].value);
		info_cnt++;
	}
	fpn_free(xstats);
	return 0;
}

int fpn_dpvi_ethtool_get_pauseparam(int portid,
				    struct dpvi_ethtool_pauseparam *dpvi_pauseparam)
{
#if BUILT_DPDK_VERSION >= DPDK_VERSION(1,7,1)
	struct rte_eth_fc_conf fc_conf;

	if (fpn_check_port(portid) < 0)
		return -1;

	if (rte_eth_dev_flow_ctrl_get(portid, &fc_conf) < 0)
		return -1;

	dpvi_pauseparam->autoneg = htonl(fc_conf.autoneg);

	if ((fc_conf.mode & RTE_FC_FULL) || (fc_conf.mode & RTE_FC_RX_PAUSE))
		dpvi_pauseparam->rx_pause = htonl(1);
	else
		dpvi_pauseparam->rx_pause = 0;

	if ((fc_conf.mode & RTE_FC_FULL) || (fc_conf.mode & RTE_FC_TX_PAUSE))
		dpvi_pauseparam->tx_pause = htonl(1);
	else
		dpvi_pauseparam->tx_pause = 0;

#endif
	return 0;
}

int fpn_dpvi_ethtool_set_pauseparam(int portid,
				    struct dpvi_ethtool_pauseparam *dpvi_pauseparam)
{
#if BUILT_DPDK_VERSION >= DPDK_VERSION(1,7,1)
	struct rte_eth_fc_conf fc_conf;

	if (fpn_check_port(portid) < 0)
		return -1;

	/* first get current values, so that we update only rx_pause/tx_pause */
	if (rte_eth_dev_flow_ctrl_get(portid, &fc_conf) < 0)
		return -1;

	if (dpvi_pauseparam->autoneg)
		fc_conf.autoneg = 1;
	else
		fc_conf.autoneg = 0;

	if (dpvi_pauseparam->rx_pause && dpvi_pauseparam->tx_pause)
		fc_conf.mode = RTE_FC_FULL;
	else if (dpvi_pauseparam->rx_pause)
		fc_conf.mode = RTE_FC_RX_PAUSE;
	else if (dpvi_pauseparam->tx_pause)
		fc_conf.mode = RTE_FC_TX_PAUSE;
	else
		fc_conf.mode = RTE_FC_NONE;

	if (rte_eth_dev_flow_ctrl_set(portid, &fc_conf) < 0)
		return -1;

#endif
	return 0;
}

static int eventfd_dpvi[FPN_MAX_CORES];

static int cpu_linux_map[FPN_MAX_CORES];
static int cpu_linux_maplen = 0;

static inline int select_cpu_linux(uint32_t rxhash)
{
	return cpu_linux_map[((uint64_t)rxhash * cpu_linux_maplen)>>32];
}

#define RTE_MBUF_VIRT_TO_PHYS(mb)                  \
	(uint64_t) ((mb)->buf_physaddr + MBUF_DPDK_DATA_OFFSET_GET(mb))

static int fpn_per_lcore_dpvi_shmem_init(__attribute__((unused)) void *arg)
{
	unsigned i = rte_lcore_id();
	struct fpn_dring *r;
	struct fpn_dring_list *rl;
	struct fpn_dring_entry *dre;
	struct rte_mbuf *mb = NULL;
	struct mbuf *m;
	unsigned int j, k;
	unsigned count_mb = 0;

	/* Prepare tx_ring with pre-allocated mbuf:
	 * on enqueue, Linux will copy the data in the buffer
	 */

	rl = &fpn_dpvi_shmem->tx_ring[i];
	for (k = 0; k < FPN_DRING_CPU_MAX; k++) {
		/* Skip offline cpu */
		if (!fpn_cpumask_ismember(&_online_mask, k))
			continue;

		/* Only Linux cpu not running FP can xmit a packet.
		 * Therefore we select the rings to initialize.
		 */
		if (fpn_cpumask_ismember(&_fpn_mask, k))
			continue;

		r = &rl->cpu[k];
		for (j = 0; j < FPN_ARRAY_SIZE(r->desc); j++) {
			m = m_alloc();
			if (m == NULL)
				rte_panic("Not enough mbufs\n");
			mb = &m->c.rtemb;
			dre = &r->desc[j];
			dre->cons_desc = (unsigned long)m;
			dre->data = RTE_MBUF_VIRT_TO_PHYS(mb);
			dre->len = rte_pktmbuf_tailroom(mb);
			count_mb++;
		}
	}
	fpn_dpvi_shmem->fp_tx_mbuf_size = mb ? rte_pktmbuf_tailroom(mb) : 0;

	printf("%s: lcoreid %u mbufs=%u\n", __func__, i, count_mb);

	return 0;
}

static void fpn_set_proc(const char *proc, char *string)
{
	FILE *fp;

	fp = fopen(proc, "w");
	if (!fp)
		printf("can not open file %s\n", proc);
	else {
		fprintf(fp, "%s", string);
		fclose(fp);
	}
}

/* For now ring is not multi-producer */
void
fpn_dpvi_init(const fpn_cpumask_t * fpn_mask,
              const fpn_cpumask_t * fpn_linux2fp_mask,
              const fpn_cpumask_t * dpvi_mask,
              const fpn_cpumask_t * online_mask)
{
	unsigned int i;
	unsigned lcore_id;
	char buffer[1024];
	struct dpvi_ioctl_arg ioarg;
	int dpvi_ioctl_fd;

	/* local copy */
	_fpn_mask          = *fpn_mask;
	_fpn_linux2fp_mask = *fpn_linux2fp_mask;
	_dpvi_mask         = *dpvi_mask;
	_online_mask       = *online_mask;

	/* Setup DPVI module parameters through sysctl */
	fpn_cpumask_string(dpvi_mask, buffer, sizeof(buffer));
	fpn_set_proc("/sys/module/dpvi_perf/parameters/dpvi_mask", buffer);

	fpn_cpumask_string(fpn_mask, buffer, sizeof(buffer));
	fpn_set_proc("/sys/module/dpvi_perf/parameters/fp_mask", buffer);

	fpn_cpumask_string(fpn_linux2fp_mask, buffer, sizeof(buffer));
	fpn_set_proc("/sys/module/dpvi_perf/parameters/l_mask", buffer);

	/* Clear rings */
	memset(fpn_dpvi_shmem->rx_ring, 0, sizeof(fpn_dpvi_shmem->rx_ring));
	memset(fpn_dpvi_shmem->tx_ring, 0, sizeof(fpn_dpvi_shmem->tx_ring));

	/* Initialize cpu map to select Linux cpu */
	for (i = 0; i < FPN_MAX_CORES; i++) {
		if (!fpn_cpumask_ismember(&_dpvi_mask, i))
			continue;

		cpu_linux_map[cpu_linux_maplen] = i;
		cpu_linux_maplen++;

	}

	/* Initialize ioctl to transmit eventfds to dpvi */
	dpvi_ioctl_fd = open("/dev/dpvi-perf", O_RDONLY);
	if (dpvi_ioctl_fd < 0) {
		fprintf(stderr, "%s: cannot open '/dev/dpvi-perf': %s\n",
		        __func__, strerror(errno));
		return;
	}

	/* Initialize eventfds (one for each dpvi core) */
	for (i = 0; i < FPN_MAX_CORES; i++) {
		if (!fpn_cpumask_ismember(&_dpvi_mask, i))
			continue;

		eventfd_dpvi[i] = eventfd(0,0);

		ioarg.dpvi_cpu = i;
		ioarg.efd = eventfd_dpvi[i];

		if (ioctl(dpvi_ioctl_fd, DPVI_IOCTL, &ioarg) < 0) {
			fprintf(stderr, "%s: ioctl failed: %s\n",
				__func__, strerror(errno));
		}
	}

	/* Reserve the last CP as control port*/
	cpu_linux_maplen--;

	/* Prepare tx ring on each lcore */
	RTE_LCORE_FOREACH(lcore_id) {
		if (lcore_id == (unsigned)fpn_cmdline_lcore)
			continue;

		if (!fpn_cpumask_ismember(&_fpn_linux2fp_mask, lcore_id))
			continue;

		if (lcore_id != rte_get_master_lcore()) {
			rte_eal_remote_launch(fpn_per_lcore_dpvi_shmem_init, NULL,
					      lcore_id);
			(void) rte_eal_wait_lcore(lcore_id);
		} else {
			/* Must directly invoke the function on master core */
			(void) fpn_per_lcore_dpvi_shmem_init(NULL);
		}
	}

	fpn_wmb();

	/* Start DPVI */
	snprintf(buffer, sizeof(buffer), "%d", getpid());
	fpn_set_proc("/proc/sys/dpvi/running_fastpath", buffer);
}

struct fpn_dpvi_shmem * fpn_dpvi_shmem_mmap(void)
{
	fpn_dpvi_shmem = fpn_shmem_mmap("dpvi-shared", NULL, sizeof(*fpn_dpvi_shmem));

	printf("%s: fpn_dpvi_shmem sizeof=%u\n", __func__, (unsigned int)sizeof(*fpn_dpvi_shmem));
	if (fpn_dpvi_shmem == NULL)
		rte_panic("dpvi-shared");

	return fpn_dpvi_shmem;
}

static void enqueue_copy(struct fpn_dring_entry *dre, struct fpn_dring_entry *in)
{
	uint64_t prev_m = dre->prod_desc;

	dre->data  = in->data;
	dre->len = in->len;
	dre->port = in->port;
	dre->from = in->from;
	dre->eop = in->eop;
	dre->prod_desc = in->prod_desc;

	if (prev_m) {
		struct mbuf *m = (struct mbuf *)(unsigned long)prev_m;

		m_freem(m);
	}
}

void push_to_linux(struct mbuf *m, int port)
{
	struct fpn_dring_list *ring_list;
	struct fpn_dring *r;
	struct fpn_dring_entry dre;
	struct rte_mbuf *mb = &m->c.rtemb;
	unsigned mycpu = rte_lcore_id();
	int ret;
	int cpu;
	uint32_t rxhash;
	uint64_t buf = 1;

	if (likely(RTE_MBUF_OL_FLAGS(mb) & PKT_RX_RSS_HASH))
		rxhash = MBUF_DPDK_HASH(mb).rss;
	else if (RTE_MBUF_OL_FLAGS(mb) & PKT_RX_FDIR)
		rxhash = MBUF_DPDK_HASH(mb).fdir.hash;
	else
		rxhash = 0;

	if(likely(port != m_control_port()))
		cpu = select_cpu_linux(rxhash);
	else
		cpu = cpu_linux_map[cpu_linux_maplen];

	ring_list = &fpn_dpvi_shmem->rx_ring[cpu];
	r = &ring_list->cpu[mycpu];

	dre.data = RTE_MBUF_VIRT_TO_PHYS(mb);
	dre.len = m_len(m);
	dre.port = port;
	dre.prod_desc = (unsigned long)m;
	dre.from = mycpu;
	dre.eop = 1;

#ifdef FPN_DEBUG_DPVI
	if (debug_new_dpvi)
		printf("push_to_linux data=0x%lx len=%u, port=%u cpu-cp=%u from=%u\n",
				dre.data, dre.len, dre.port, cpu, dre.from);
#endif

retry:
	ret = fpn_dring_enqueue(r, &dre, 1, enqueue_copy);
	r->prod.enqueue++;
	if (unlikely(ret != 0)) {
		r->prod.enqueue--;
		r->prod.enqueue_err++;
		if (port == m_control_port())
			goto retry;
		m_freem(m);
	}

	if (ring_list->polling != DPVI_POLLING) {
		ret = write(eventfd_dpvi[cpu], &buf, sizeof(uint64_t));
		if (unlikely(ret < 0))
			fpn_printf_ratelimited("warning, writing to eventfd %d"
			                       " failed with '%s'\n", cpu,
			                       strerror(errno));
	}
}

#define FPN_DPVI_PUSH_MAX_ELEM 16
void push_to_linux_multi(struct mbuf *m, int port)
{
	struct fpn_dring_list *ring_list;
	struct fpn_dring *r;
	struct fpn_dring_entry dre[FPN_DPVI_PUSH_MAX_ELEM];
	struct rte_mbuf *mb = &m->c.rtemb;
	struct mbuf *tmp;
	unsigned mycpu = rte_lcore_id();
	int ret;
	int cpu;
	unsigned i;
	unsigned nsegs = MBUF_DPDK_NBSEGS(mb);
	uint32_t rxhash;
	uint64_t buf = 1;

	if (nsegs > FPN_DPVI_PUSH_MAX_ELEM) {
		fpn_printf_ratelimited("warning, too many segs, dropping %u\n",
				nsegs);
		m_freem(m);
		return;
	}

	if (likely(RTE_MBUF_OL_FLAGS(mb) & PKT_RX_RSS_HASH))
		rxhash = MBUF_DPDK_HASH(mb).rss;
	else if (RTE_MBUF_OL_FLAGS(mb) & PKT_RX_FDIR)
		rxhash = MBUF_DPDK_HASH(mb).fdir.hash;
	else
		rxhash = 0;

	if(likely(port != m_control_port()))
		cpu = select_cpu_linux(rxhash);
	else
		cpu = cpu_linux_map[cpu_linux_maplen];

	ring_list = &fpn_dpvi_shmem->rx_ring[cpu];
	r = &ring_list->cpu[mycpu];

	tmp = m;
	for (i = 0; i < nsegs && tmp; i++) {
		dre[i].data = RTE_MBUF_VIRT_TO_PHYS(mb);
		dre[i].len = s_len(tmp);
		dre[i].port = port;
		/* only first entry, m_freem() will free all */
		dre[i].prod_desc = (i == 0 ? (unsigned long)m : 0);
		dre[i].from = mycpu;
		tmp = __m_next(tmp);
		mb = &tmp->c.rtemb;
		dre[i].eop = (tmp == NULL || i == (nsegs - 1));
#ifdef FPN_DEBUG_DPVI
		if (debug_new_dpvi)
			printf("push_to_linux data=0x%lx len=%u, port=%u"
					" cpu-cp=%u from=%u eop=%u\n",
					dre[i].data, dre[i].len, dre[i].port,
					cpu, dre[i].from, dre[i].eop);
#endif
	}

retry:
	ret = fpn_dring_enqueue(r, dre, i, enqueue_copy);
	r->prod.enqueue += i;
	if (unlikely(ret != 0)) {
		r->prod.enqueue -= i;
		r->prod.enqueue_err += i;
		if (port == m_control_port())
			goto retry;
		m_freem(m);
	}

	ret = write(eventfd_dpvi[cpu], &buf, sizeof(uint64_t));
	if (ring_list->polling != DPVI_POLLING) {
		ret = write(eventfd_dpvi[cpu], &buf, sizeof(uint64_t));
		if (unlikely(ret < 0))
			fpn_printf_ratelimited("warning, writing to eventfd %d"
			                       " failed with '%s'\n", cpu,
			                       strerror(errno));
	}
}

void dequeue_copy(struct fpn_dring_entry *out, struct fpn_dring_entry *dre)
{
	struct mbuf *m;
	struct rte_mbuf *mb;

	out->data = dre->data;
	out->len = dre->len;
	out->port = dre->port;
	out->from = dre->from;
	out->eop = dre->eop;
	out->cons_desc = dre->cons_desc;

	/* Reinitialize the entry with a new buffer */
	m = m_alloc();
	if (m == NULL) {
		/* Could not allocate a new entry: recycle this
		 * entry and inform the error by zeroing cons_desc
		 * field.
		 */
		m = (struct mbuf *)(unsigned long)out->cons_desc;
		out->cons_desc = 0;
		/* fallback to re-initialize the entry */
	}

	mb = &m->c.rtemb;
	dre->data = RTE_MBUF_VIRT_TO_PHYS(mb);
	dre->len = rte_pktmbuf_tailroom(mb);
	dre->cons_desc = (unsigned long)m;
}

#define FPN_DPVI_POP_MAX_ELEM 32
unsigned fpn_recv_exception(void)
{
	unsigned cpu = rte_lcore_id();
	struct fpn_dring *r;
	struct fpn_dring_list *ring_list;
	struct fpn_dring_entry dre[FPN_DPVI_POP_MAX_ELEM];
	struct mbuf *m;
	unsigned int count, i, j, drop_in_progress = 0;
	int port;
	unsigned nb_packets = 0;

	ring_list = &fpn_dpvi_shmem->tx_ring[cpu];
	for (j = 0; j < FPN_DRING_CPU_MAX; j++) {
		struct mbuf *m_reass = NULL;

		r = &ring_list->cpu[j];
dequeue_more_pkts:
		count = fpn_dring_dequeue(r, dre, FPN_ARRAY_SIZE(dre), dequeue_copy);
		if (count == 0) {
			if (m_reass) {
				r->cons.dequeue_no_eop++;
				goto dequeue_more_pkts;
			}
			continue;
		}

		nb_packets += count;
		r->cons.dequeue += count;
		for (i = 0; i < count; i++) {
			int is_eop;

			m = (struct mbuf *)(unsigned long)dre[i].cons_desc;
			/* cons_desc is mark NULL in local entry to inform an error
			 * during dequeue_copy (allocation error probably).
			 */
			if (m == NULL) {
				r->cons.dequeue_copyerr++;
				if (m_reass) {
					/* if packet was completely reassembled,
					   drop current packet */
					if (dre[i].eop) {
						m_freem(m_reass);
						m_reass = NULL;
						drop_in_progress = 0;
					} else
						drop_in_progress = 1;
				}
				continue;
			}
			m_append(m, dre[i].len);
			port = dre[i].port;
			is_eop = dre[i].eop;

#ifdef FPN_DEBUG_DPVI
			if (debug_new_dpvi)
				printf("%s: cpu=%u from=%u sending to port %u\n",
						__func__, cpu, dre[i].from, dre[i].port);
#endif

			if (m_reass) {
				m_cat(m_reass, m);
				/* if current packet encoutered an
				   error, and if packet was completely
				   reassembled, drop the current
				   packet */
				if (drop_in_progress && is_eop) {
					m_freem(m_reass);
					m_reass = NULL;
					drop_in_progress = 0;
					continue;
				}
			}
			else
				m_reass = m;

			if (!is_eop)
				continue;

			/* asked to send */
			m = m_reass;
			m_reass = NULL;

			/* Asked to send the packet over the wire */
			if (port < m_control_port()) {
				fpn_send_packet(m, port);
				continue;
			}

			/* DPVI control packets */
			if (fpn_dpvi_recv(m) == 0)
				continue;

			/* Other for the application */
			fpn_process_soft_input(m);
		}

		/* could not find the last segment in this batch, take
		   another one */
		if (m_reass) {
			r->cons.dequeue_no_eop++;
			goto dequeue_more_pkts;
		}

	}
	return nb_packets;
}
