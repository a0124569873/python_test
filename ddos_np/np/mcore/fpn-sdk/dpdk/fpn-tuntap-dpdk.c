/*
 * Copyright (c) 2012 6WIND, All rights reserved.
 */

#if defined(CONFIG_MCORE_FPVI_TAP)
#include "fpn.h"
#include "fpn-tuntap-dpdk.h"

#include <fpn-ring.h>
#include <sys/uio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/if_arp.h>

#include <event.h>
#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 0)
#include "fpn-hexdump.h"
#endif
#define TAP_RING_DEPTH 1024

/* ethernet address for fpn0 == 0x02, 0x09, 'f', 'p', 'n', '0' */
static struct ether_addr fpn_fpn0_eth_addr = { {0x02, 0x09, 0x66, 0x70, 0x6e, 0x30} };

/* fd for taps associated with the ports */
static int fpn_ports_tap_fd[FPN_MAX_PORTS];
/* fd for the tap associated with fpn0 */
static int fpn_fpn0_tap_fd;

/*
 * exception FP->Linux : tap_ring is MP, SC
 */
static struct fpn_ring *fpn_tap_ring = NULL;
static struct fpn_ring *fpn_tap_tx_ring = NULL;

void fpn_init_tap_ring(void)
{
	unsigned i = rte_lcore_id();
	unsigned int j, count_mb=0;

	fpn_tap_ring = fpn_ring_create("to_tap", TAP_RING_DEPTH, 0);
	fpn_tap_tx_ring = fpn_ring_create("from_tap", TAP_RING_DEPTH, 0);

	/* Note : only one ring is initialized */
	for (j = 0; j < TAP_RING_DEPTH; j++) {
		fpn_tap_ring->ring[j] = NULL;
		fpn_tap_tx_ring->ring[j] = NULL;
		count_mb++;
	}

	fpn_wmb();

	printf("%s: lcoreid %u mbufs=%u\n", __func__, i, count_mb);
}

void push_to_tap(struct mbuf *m)
{
	int ret;
#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 1)
	unsigned mycpu = rte_lcore_id();

	fpn_printf_ratelimited("%s: len=%u from=%u\n",
	                       __func__, m_len(m), mycpu);
#endif

	ret = fpn_ring_mp_enqueue(fpn_tap_ring, (void *)m);
	if (ret == -ENOBUFS) {
		fpn_printf_ratelimited("fpn_ring_mp_enqueue failed\n");
		m_freem(m);
	}
#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 1)
	ret = fpn_ring_count(fpn_tap_ring);
	fpn_printf_ratelimited("%s: %d elts in the ring\n", __func__, ret);
#endif
}

#define FPN_TAP_MAX_SEGS 32
static int send_packet_to_tap(struct mbuf *m, uint8_t port)
{
	int nwrite, err=0;

#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 2)
	printf("%s %d\n", __func__, port);
#endif
	if (m_is_contiguous(m)) {
		/* write data from mbuf on the designated port */
		nwrite = write(fpn_ports_tap_fd[port], mtod(m, char*), m_len(m));
	} else {
		int n_segs;

		n_segs = m_seg_count(m);
		if (n_segs > FPN_TAP_MAX_SEGS) {
			printf("%s: too many segments : %d\n", __func__, n_segs);
			nwrite = -1;
		} else {
			struct iovec mbuf_v[FPN_TAP_MAX_SEGS];
			struct sbuf *s;
			int i=0;
			M_FOREACH_SEGMENT(m, s) {
#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 2)
				fpn_printf("Segment %d: len is %d\n", i, s_len(s));
#endif
				mbuf_v[i].iov_base = s_data(s, void*);
				mbuf_v[i].iov_len  = s_len(s);
				i++;
			}
			nwrite = writev(fpn_ports_tap_fd[port], mbuf_v, n_segs);
		}
	}
	if (nwrite < (int)m_len(m))
		err = -1;

	m_freem(m);
	return err;
}

static void send_packet_to_fpn0(struct mbuf * m)
{
	int nwrite;

#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 2)
	printf("%s\n", __func__);
#endif
	if (m_is_contiguous(m)) {
		/* write data from mbuf on the designated port */
		nwrite = write(fpn_fpn0_tap_fd, mtod(m, char*), m_len(m));
	} else {
		int n_segs;

		n_segs = m_seg_count(m);
		if (n_segs > FPN_TAP_MAX_SEGS) {
			printf("%s: too many segments : %d\n", __func__, n_segs);
			nwrite = -1;
		} else {
			struct iovec mbuf_v[FPN_TAP_MAX_SEGS];
			struct sbuf *s;
			int i=0;
			M_FOREACH_SEGMENT(m, s) {
#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 2)
				fpn_printf("Segment %d: len is %d\n", i, s_len(s));
#endif
				mbuf_v[i].iov_base = s_data(s, void*);
				mbuf_v[i].iov_len  = s_len(s);
				i++;
			}
			nwrite = writev(fpn_fpn0_tap_fd, mbuf_v, n_segs);
		}
	}
	if (nwrite < (int)m_len(m))
		rte_panic("Cannot send data (len %d) for fpn0\n", m_len(m));

	m_freem(m);
	return;
}

#define FPN_TAP_POP_MAX_ELEM 32
static void tap_process_ring(void)
{
	void *m_tab[FPN_TAP_POP_MAX_ELEM];
	struct mbuf *m;
	int i, err, port, count;

#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 2)
	printf("%s\n", __func__);
#endif

	/* loop for extracting from the ring, until an error at dequeue */
	while (1) {
		count = FPN_TAP_POP_MAX_ELEM;
		err = fpn_ring_sc_dequeue_bulk(fpn_tap_ring, m_tab, count);
		if (unlikely(err < 0)) {
			count = 1;
			err = fpn_ring_sc_dequeue_bulk(fpn_tap_ring, m_tab, count);
			if (unlikely(err < 0)) {
				return;
			}
		}
#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 1)
		printf("%s: %d elts dequeue\n", __func__, count);
#endif
		for (i = 0; i < count; i++) {

			m = m_tab[i];
			port = m_input_port(m);

#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 1)
			fpn_printf_ratelimited("%s: sending to port %u\n", __func__, port);
#endif

			/* Asked to send the packet over the wire */
			if (port < m_control_port())
				send_packet_to_tap(m, port);
			else
				/* Other for the application */
				send_packet_to_fpn0(m);
		}
	}
}

static char eth_buf_out[ETHER_MAX_JUMBO_FRAME_LEN];
static void
notify_rx_excep(int fd, short event, void *param)
{
	int nread, port= (int)(unsigned long)param;
	struct mbuf *m=NULL;
	/* default value when ports are not yet configured */
	uint16_t frame_len, mtu=ETHER_MTU;
	uint32_t appended;

	if (port == -1)
		rte_panic("wrong port\n");

	if (event & EV_READ) {
#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 0)
		fpn_printf_ratelimited("%s: reading tap for port %d\n", __func__, port);
#endif

		/* get current MTU for this port */
		if (rte_eth_dev_get_mtu(port, &mtu) < 0)
			rte_panic("cannot get mtu\n");
#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 2)
		printf("%s: mtu for port %d : %d\n", __func__, port, mtu);
#endif
		frame_len = mtu + ETHER_HDR_LEN + ETHER_CRC_LEN;
		if (mtu > ETHER_MAX_JUMBO_FRAME_LEN)
			mtu = ETHER_MAX_JUMBO_FRAME_LEN;
		do {
			/* build m_buf from packet */
			m = m_alloc();
			if (m == NULL)
				rte_panic("cannot get m_buf\n");

			nread = read(fd, eth_buf_out, frame_len);
			if (nread > 0) {
				appended = m_copyfrombuf(m, 0, eth_buf_out, nread);
				if (appended != (uint32_t) nread)
					rte_panic("cannot m_copyfrombuf\n");

#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 0)
	#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 1)
				/* print the starting bytes of the packet */
				fpn_hexdump("recv", (void *)eth_buf_out, 32);
	#endif
				fpn_printf_ratelimited("%s: sending for port %d for len %d\n",
					   __func__, port, nread);
#endif

				__fpn_send_packet_nowait(m, port);
			} else
				m_freem(m);
		} while (nread > 0);
	}
}

/* enable some more space for encapsulation */
#define FPN0_MTU (ETHER_MAX_LEN + 100)
static void
notify_rx_fpn0(int fd, short event, __attribute__((unused)) void *param)
{
	int ret, nread;
	struct mbuf *m=NULL;
	char * dest;

	if (event & EV_READ) {
#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 0)
		fpn_printf_ratelimited("%s: reading tap for fpn0\n", __func__);
#endif

		do {
			/* build m_buf from packet */
			m = m_alloc();
			if (m == NULL)
				rte_panic("cannot get m_buf\n");
			dest = m_append(m, FPN0_MTU);
			if (dest == NULL)
				rte_panic("cannot m_append\n");

			nread = read(fd, dest, FPN0_MTU);
			if (nread > 0) {
				/* maybe remove extra space in the m_buf */
				if (nread < FPN0_MTU) {
					ret = m_trim(m, FPN0_MTU-nread);
					if (ret == 0)
						rte_panic("cannot m_trim\n");
				}

#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 0)
				fpn_hexdump("recv", (void *)dest, 32);
				printf("sending for fpn0 for len %d\n", nread);
#endif

				ret = fpn_ring_sp_enqueue(fpn_tap_tx_ring, (void *)m);
				if (ret == -ENOBUFS) {
					m_freem(m); /* XXX stats */
				}
			} else
				m_freem(m);
		} while (nread > 0);
	}
}

extern unsigned fpn_recv_exception(void);

unsigned fpn_recv_exception(void)
{
	void *m_tab[FPN_TAP_POP_MAX_ELEM];
	struct mbuf *m;
	unsigned count, i;
	int err;

	count = FPN_TAP_POP_MAX_ELEM;
	err = fpn_ring_mc_dequeue_bulk(fpn_tap_tx_ring, m_tab, count);
	if (err < 0) {
		count = 1;
		err = fpn_ring_mc_dequeue_bulk(fpn_tap_tx_ring, m_tab, count);
		if (err < 0)
			return 0;
	}
	for (i = 0; i < count; i++) {
		m = m_tab[i];
		fpn_process_soft_input(m);
	}
	return count;
}

static struct event rx_excep_evt[FPN_MAX_PORTS];
static struct event rx_fpn0_evt;
static struct event excep_timer_evt;

static void
notify_timer_excep(__attribute__((unused)) int fd, short event,
				   __attribute__((unused)) void *param)
{
	struct timeval tv;

	if (event & EV_TIMEOUT) {
#if (CONFIG_MCORE_FPVI_TAP_DEBUG_LEVEL > 2)
		fpn_printf_ratelimited("timer for ring\n");
#endif
		tap_process_ring();

		timerclear(&tv);
		/* XXX hard-coded 100ms delay */
		tv.tv_usec=100*1000;
		if (event_add(&excep_timer_evt, &tv))
			rte_panic("event_add: %s\n", strerror(errno));
	}
}

/* main processing loop for exception events on a dedicated lcore */
int start_rx_excep_lcore(__attribute__((unused)) void *arg)
{
	int portid;
	int rx_excep_nb_ports;
	struct timeval tv;

	printf("entering %s: start event processing\n", __func__);

	event_init();

	/* get actual nb of ports */
	rx_excep_nb_ports = rte_eth_dev_count();
	if (rx_excep_nb_ports > FPN_MAX_PORTS)
		rx_excep_nb_ports = FPN_MAX_PORTS;
	if (rx_excep_nb_ports == 0)
		rte_panic("No detected ports\n");

	/* use libevent to receive packets from kernel */

	/* for the tap devices used for exception packets */
	for (portid=0; portid<rx_excep_nb_ports; portid++) {
		if (fpn_ports_tap_fd[portid] < 0) {
			printf("no event for port %d\n", portid);
			continue;
		}
		event_set(&rx_excep_evt[portid], fpn_ports_tap_fd[portid],
			  EV_READ | EV_PERSIST, (void *) notify_rx_excep,
			  (void *)(unsigned long)portid);
		if (event_add(&rx_excep_evt[portid], NULL))
			rte_panic("event_add: %s\n", strerror(errno));
	}

	/* for the tap device used for fpn0 */
	event_set(&rx_fpn0_evt, fpn_fpn0_tap_fd,
		  EV_READ | EV_PERSIST, (void *) notify_rx_fpn0, NULL);
	if (event_add(&rx_fpn0_evt, NULL))
		rte_panic("event_add: %s\n", strerror(errno));

	/* timeout for reading packets from the exception ring */
	event_set(&excep_timer_evt, -1,
		  EV_TIMEOUT, (void *) notify_timer_excep, NULL);
	timerclear(&tv);
	/* XXX hard-coded 100ms delay */
	tv.tv_usec=100*1000;
	if (event_add(&excep_timer_evt, &tv))
		rte_panic("event_add: %s\n", strerror(errno));

	/* Infinite loop */
	event_dispatch();
	/* NOTREACHED */
	return 0;
}

/* Configure tap port for one interface */
static int fpn_setup_tap(int s, const char *ifname, unsigned int if_flags,
			 uint8_t *macaddr, int *fd)
{
	const char *clonedev = "/dev/net/tun";
	struct ifreq ifr;
	uint8_t *dst_macaddr;
	int err;

	/* store the fd for each of the created tap
	  * in shared memory so that the exception function will know where to send */
	/* this is the special file descriptor that the caller will use to talk
	  * with the virtual interface */
	/* open the clone device */
	if( (*fd = open(clonedev, O_RDWR | O_NONBLOCK)) < 0 )
		rte_panic("cannot open clonedev: %s\n", strerror(errno));

	/* preparation of the struct ifr, of type "struct ifreq" */
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	/* try to create the device */
	err = ioctl(*fd, TUNSETIFF, (void *) &ifr);
	if( err < 0 )
		rte_panic("cannot set TUN flag: %s\n", strerror(errno));

	/* set underlying MAC address */
	dst_macaddr = (uint8_t *)&ifr.ifr_hwaddr.sa_data;
	memcpy(dst_macaddr, macaddr, ETHER_ADDR_LEN);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	err = ioctl(*fd, SIOCSIFHWADDR, &ifr);
	if (err < 0)
		rte_panic("cannot set HW address: %s\n", strerror(errno));

	if (if_flags) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
		err = ioctl(s, SIOCGIFFLAGS, &ifr);
		if (err < 0)
			rte_panic("cannot get flags: %s\n", strerror(errno));
		ifr.ifr_flags |= if_flags;
		err = ioctl(s, SIOCSIFFLAGS, &ifr);
		if (err < 0)
			rte_panic("cannot set flags (up): %s\n", strerror(errno));
	}

	return 0;
}

/* Create tap ports for all detected interfaces */
int fpn_create_tap_nodes(const char *fpmapping_fname, unsigned int flags)
{
	int nb_ports;
	int s, err=0, portid;
	char ifname[IFNAMSIZ];
	struct ifreq ifr;
	FILE * mapping_file = NULL;
	struct fp_pci_netdev* dev;
	char* itfname;
	int first_free_idx = 0;

	/* get actual nb of ports */
	nb_ports = rte_eth_dev_count();
	if (nb_ports > FPN_MAX_PORTS)
		nb_ports = FPN_MAX_PORTS;
	if (nb_ports == 0)
		rte_panic("No detected ports\n");

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		rte_panic("cannot create socket: %s\n", strerror(errno));

	mapping_file = fopen(fpmapping_fname, "w+");
	if (mapping_file == NULL)
		rte_panic("cannot open mapping file: %s err: %s\n",
                  fpmapping_fname, strerror(errno));
	for (portid=0; portid<nb_ports; portid++) {

		fpn_ports_tap_fd[portid] = -1;

		/* skip ports that are not enabled */
		if (fpn_port_shmem->port[portid].enabled == 0) {
			printf("Skipping disabled port %d\n", portid);
			continue;
		}

		/* Try to find the original interface name. */
		itfname = NULL;
		if (fp_netdev_list) {
			for (dev = fp_netdev_list; dev; dev = dev->next) {
				if (dev->portid == (uint32_t)portid) {
					itfname = dev->name;
					break;
				}
			}
		}

		/* find the index of the latest ethX driver already known. */
		if (itfname == NULL) {
			do {
				memset(&ifr, 0, sizeof(ifr));

				memset(ifname, 0, IFNAMSIZ);
				/*
				 * prepare ethN_0 interface name => snprintf()
				 */
				snprintf(ifname, IFNAMSIZ, "eth%d",
						first_free_idx);
				strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
				/* try getting the MAC address */
				ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
				err = ioctl(s, SIOCGIFHWADDR, &ifr);

				first_free_idx++;
			} while (err >= 0);
		} else {
			/* Reuse original interface name. */
			memset(&ifr, 0, sizeof(ifr));

			memset(ifname, 0, IFNAMSIZ);
			/* prepare ethN_0 interface name => snprintf() */
			snprintf(ifname, IFNAMSIZ, "%s", itfname);
		}

		printf("new interface name : %s for port %d\n", ifname, portid);
		err = fpn_setup_tap(s, ifname, flags,
		                    fpn_port_shmem->port[portid].etheraddr,
		                    &fpn_ports_tap_fd[portid]);

		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
		/* try getting the if index for the new interface */
		err = ioctl(s, SIOCGIFINDEX, &ifr);
		if (err < 0)
			rte_panic("cannot get ifndex: %s\n", strerror(errno));

		/* create  port mapping */
		fprintf(mapping_file, "%d %d\n", ifr.ifr_ifindex, portid);
	}
	fclose(mapping_file);

	fpn_fpn0_tap_fd = -1;

	err = fpn_setup_tap(s, "fpn0", IFF_NOARP | IFF_UP | flags,
	                    (uint8_t *) &fpn_fpn0_eth_addr,
	                    &fpn_fpn0_tap_fd);

	return err;
}
#endif /*CONFIG_MCORE_FPVI_TAP*/

