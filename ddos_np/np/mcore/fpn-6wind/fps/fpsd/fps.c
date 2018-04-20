/*
 * Copyright(c) 2009 6WIND, All rights reserved.
 */

/*
 * At every TX period, IF statistics must be transmitted according to
 * the following rules:
 *     - do not send more than "ng->max_msg_per_tick" stats messages
 *     - only re-send stats for the first IFNET after the
 *       "min_refresh_period" elapsed
 */

#include "fpn.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "fp.h"
#include "fptun.h"
#include "fp-var.h"

#include "fp-rfps-proto.h"
#include "fp-rfps-conf.h"

#include "libfp_shm.h"
shared_mem_t *fp_shared;

#include <sys/types.h>
#include <sys/signal.h>
#include <syslog.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "event.h"
#include <err.h>

#include <sys/ioctl.h>
#include <linux/sockios.h> /* SIOCGIFMTU */

#include "fps-nl.h"

static struct event sigterm;

static int debug = 0;
static char *ifname = "lo";
static unsigned int ifmtu = 1500;
static struct sockaddr_ll addr;
static int s = -1;
static uint8_t dest_mac[6] = { 0 };
static int is_coloc = 1;

#ifdef HA_SUPPORT
#include <6whasapi.h>
#include <hasupport.h>
static struct has_ctx *fps_has = NULL;
static struct event has_event;
#endif

static int sendit(char *buf, int buflen);

#define RFPS_LOG(level, fmt, args...) do {    \
		if (debug >= 1 || level <= LOG_ERR)   \
			syslog(level, "%s():" fmt "\n",   \
		       __func__, ## args);            \
		if (debug >= 2)                       \
			fprintf(stdout, "%s():" fmt "\n", \
		       __func__, ## args);            \
	} while(0)

typedef void (*rfps_callout_hdlr_t)(void *arg);

struct callout {
   struct event ev;
   rfps_callout_hdlr_t func;
   void *args;
   int timer;
};

static void callout_timeout(int sock, short evtype, void *data)
{
	struct callout *user = data;

	(*user->func)(user->args);
}

static int callout_init(struct callout *user)
{
	evtimer_set(&user->ev, callout_timeout, user);

	return 0;
}

static int callout_reset(struct callout *user, unsigned int secs,
		void (*function)(void *), void *data)
{
	struct timeval tv;

	if (secs == 0)
		secs = 1;
	tv.tv_sec = secs;
	tv.tv_usec = 0;
	user->func = function;
	user->args = data;
	evtimer_add(&user->ev, &tv);

	return 0;
}


struct mbuf {
	unsigned int len;
	unsigned int offset;
	unsigned int size;
	char *data;
};

static unsigned int mbuf_max_data_size = 2000;
static unsigned int mbuf_default_headroom = 128; /* enough for rfps hdr + fptun */

#define mtod(m, t) (t)((long)(m)->data + (m)->offset)
#define m_len(m) (m)->len

static struct mbuf *m_alloc(void)
{
	struct mbuf *m = malloc(sizeof(*m));

	if (m) {
		m->len = 0;
		m->offset = mbuf_default_headroom;
		m->size = mbuf_max_data_size;
		m->data = malloc(mbuf_max_data_size);
		if (m->data == NULL) {
			free(m);
			m = NULL;
		}
	}
	return m;
}

static char *m_append(struct mbuf *m, int len)
{
	char *tail = mtod(m, char *) + m->len;
	if (m->offset + m->len + len > m->size)
		return NULL;

	m->len += len;
	return tail;
}

static char *m_prepend(struct mbuf *m, int len)
{
	if (m->offset < (unsigned)len)
		return NULL;
	m->len += len;
	m->offset -= len;
	return mtod(m, char *);
}

static void m_freem(struct mbuf *m)
{
	if (m) {
		free(m->data);
		free(m);
	}
}

static void send_fptun(struct mbuf *m)
{
	struct fptunhdr thdr;
	char *data;

	thdr.fptun_cmd = FPTUN_RFPS_UPDATE;
	thdr.fptun_exc_class = 0;
	thdr.fptun_version = FPTUN_VERSION;
	thdr.fptun_mtags = 0;
	thdr.fptun_blade_id = fp_shared->active_cpid;
	thdr.fptun_proto = 0;
	thdr.fptun_vrfid = 0;
	thdr.fptun_ifuid = 0;

	data = m_prepend(m, sizeof(thdr));
	if (data) {
		memcpy(data, &thdr, sizeof(thdr));
		sendit(data, m_len(m));
	}
	m_freem(m);
}

/*
 * Period in seconds of the specific callout handler used to periodically
 * check availability of the Fast Path shared memory.
 */
#define RFPS_CHECK_SHMEM_READY_DELAY 1

/*
 * Generic data structure associated with each type of statistics
 */
struct rfps_engine;
typedef void (*rfps_handler_t)(struct rfps_engine *);

typedef struct rfps_engine {
	/* constant part */
	rfps_handler_t rfps_handler;      /* handler called at each tick */
	const char     *rfps_name;        /* for DEBUG log traces */
	size_t         rfps_conf_offset;  /* offset of config in shared mem. */
	unsigned int   rfps_stat_size;    /* size of each stat entry in msg. */
	uint8_t        hdr_vbof_statid;   /* vbof_statid value in msg. hdr. */

	/* configurable part */
	uint32_t       max_stats_per_msg; /* max. rfps entries in a message */
	uint32_t       tx_period_delay;   /* in seconds for callout_reset() */
	uint32_t       min_refresh_delay; /* in seconds for callout_reset() */
	uint32_t       max_msg_per_tick;
	uint32_t       cur_config_stamp;  /* configuration setting check */

	/* dynamic part */
	struct callout rfps_callout;
	unsigned int   next_tick_delay;   /* tx_period_seconds by default */
	uint32_t       nb_msg_sent;       /* since start time */
} rfps_engine_t;

#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
#define RFPS_BYTE_ORDER RFPS_BIG_ENDIAN
#else
#define RFPS_BYTE_ORDER RFPS_LITTLE_ENDIAN
#endif

#define RFPS_V0_HDR_FLAGS(stat_id) \
	((RFPS_INITIAL_VERSION << RFPS_VERSION_SHIFT)  | \
	 (RFPS_BYTE_ORDER << RFPS_V0_BYTE_ORDER_SHIFT) | \
	 stat_id)

#define m_hdr_prepend(m, hdr_type) (hdr_type *)m_prepend(m, sizeof(hdr_type))

/*
 * Common callout-based statistics transmission services.
 */
#define MILLISEC_TO_ROUNDUP_SEC(millisec) \
	((millisec) / 1000) + ((((millisec) % 1000) + 999) / 1000)

/*
 * Setup transmission parameters of the RFPS engine associated with a given
 * type of statistics according to its [last] actual configuration in the
 * Fast path shared memory.
 */
static void fp_rfps_engine_configure(rfps_engine_t *rfps_ng)
{
	const rfps_conf_t *rfps_cf = (rfps_conf_t *)((char*)fp_shared +
						     rfps_ng->rfps_conf_offset);

	unsigned int maxsize = ifmtu < mbuf_max_data_size ? ifmtu : mbuf_max_data_size;
	rfps_ng->max_msg_per_tick  = rfps_cf->max_msg_per_tick;
	rfps_ng->max_stats_per_msg = (maxsize - mbuf_default_headroom) / rfps_ng->rfps_stat_size;
	/* IB_FIXME - need a specific callout service in milliseconds */
	rfps_ng->tx_period_delay = MILLISEC_TO_ROUNDUP_SEC(rfps_cf->tx_period);

	/*
	 * Configuring a "min_refresh_period" value lower than the "tx_period"
	 * value means that the "min_refresh_period" is not significant.
	 * Force it to the "tx_period" in this case.
	 */
	if (rfps_cf->min_refresh_period < rfps_cf->tx_period)
		rfps_ng->min_refresh_delay = rfps_ng->tx_period_delay;
	else
		rfps_ng->min_refresh_delay =
			MILLISEC_TO_ROUNDUP_SEC(rfps_cf->min_refresh_period);

	rfps_ng->next_tick_delay   = rfps_ng->tx_period_delay;
	rfps_ng->cur_config_stamp  = rfps_cf->last_stamp;
	RFPS_LOG(LOG_INFO,
		   "%s: tx_period=%u max_msg_per_tick=%u min_refresh_period=%u",
		   rfps_ng->rfps_name,
		   rfps_ng->tx_period_delay,
		   rfps_ng->max_msg_per_tick,
		   rfps_ng->min_refresh_delay);
}

static void fp_rfps_check_shmem_handler(rfps_engine_t *);

/*
 * Common callout handler.
 * Check the state of the Fast Path shared memory.
 * Invoke the specific handler of the RFPS engine.
 * Restart callout.
 */
static void fp_rfps_engine_handler(rfps_engine_t * rfps_ng)
{
	const rfps_conf_t *rfps_cf = (rfps_conf_t *)((char*)fp_shared +
						     rfps_ng->rfps_conf_offset);

	/* check shared memory state */
	if (fp_shared->conf.w32.magic != FP_SHARED_MAGIC32) {
		fp_rfps_check_shmem_handler(rfps_ng);
		return;
	}
	/* check that current configuration has not been changed */
	if (rfps_ng->cur_config_stamp != rfps_cf->last_stamp)
		fp_rfps_engine_configure(rfps_ng);

	if (rfps_ng->max_msg_per_tick > 0)
		(*rfps_ng->rfps_handler)(rfps_ng);

	callout_reset(&rfps_ng->rfps_callout, rfps_ng->next_tick_delay,
		      (rfps_callout_hdlr_t)fp_rfps_engine_handler, rfps_ng);
}

/*
 * The "rfps_check_shmem_handler" is used while the shared memory is not ready.
 * Then, it setup the RRPS engine according to its [last] configuration, and
 * invoke the RFPS handler.
 */
static void fp_rfps_check_shmem_handler(rfps_engine_t *rfps_ng)
{
	if (fp_shared == NULL)
		fp_shared = get_fp_shared();
	if (fp_shared == NULL || fp_shared->conf.w32.magic != FP_SHARED_MAGIC32) {
		callout_reset(&rfps_ng->rfps_callout,
			      RFPS_CHECK_SHMEM_READY_DELAY,
			      (rfps_callout_hdlr_t)fp_rfps_check_shmem_handler,
			      rfps_ng);
		return;
	}
	fp_rfps_engine_configure(rfps_ng);
	fp_rfps_engine_handler(rfps_ng);
}

/*
 * Intialize a RFPS engine.
 * Invoked once at RFPS module initialisation time for each RFPS engine.
 */
static void fp_rfps_engine_init(rfps_engine_t *rfps_ng)
{
	rfps_ng->nb_msg_sent = 0;
	callout_init(&rfps_ng->rfps_callout);
	fp_rfps_check_shmem_handler(rfps_ng);
}

/*
 * Send a RFPS message to the Control Plane over the FPTUN channel.
 * Integer values are transmitted in the local CPU byte order.
 */
static void fp_rfps_msg_send(rfps_engine_t *rfps_ng,
			     struct mbuf *m,
			     const uint16_t nb_stats)
{
	rfps_v0_hdr_t *rfps_hdr;

	rfps_hdr = m_hdr_prepend(m, rfps_v0_hdr_t);
	if (rfps_hdr == NULL) {
		RFPS_LOG(LOG_ERR, "m_prepend(rfps_hdr_t) failed");
		m_freem(m);
		return;
	}
	rfps_hdr->vbof_statid = rfps_ng->hdr_vbof_statid;
	rfps_hdr->src_bladeid = fp_shared->fp_blade_id;
	rfps_hdr->nb_stats    = htons(nb_stats); /* in network byte order */
	send_fptun(m);
	rfps_ng->nb_msg_sent++;
	RFPS_LOG(LOG_DEBUG, "%s nb_stats=%d nb_msg_sent=%d",
		   rfps_ng->rfps_name, nb_stats, rfps_ng->nb_msg_sent);
}

/*
 * RFPS engine for IPv4 and IPv6 Statistics.
 */
static void fp_rfps_ip_stats_set(rfps_ip_stats_t *rips,
				 const fp_ip_stats_t *ips)
{
	/* last valid entry */
	const fp_ip_stats_t *last_ips = ips + (FP_IP_STATS_NUM - 1);

	/* avoid the cost of previously zeroing rips */
	rips->IpForwDatagrams    = ips->IpForwDatagrams;
	rips->IpInDelivers       = ips->IpInDelivers;
	rips->IpReasmReqds       = ips->IpReasmReqds;
	rips->IpReasmOKs         = ips->IpReasmOKs;
	rips->IpReasmFails       = ips->IpReasmFails;
	rips->IpFragOKs          = ips->IpFragOKs;
	rips->IpFragFails        = ips->IpFragFails;
	rips->IpFragCreates      = ips->IpFragCreates;
	rips->IpInHdrErrors      = ips->IpInHdrErrors;
	rips->IpInAddrErrors     = ips->IpInAddrErrors;
	rips->IpReasmTimeout     = ips->IpReasmTimeout;

	while (ips < last_ips) {
		ips++;
		rips->IpForwDatagrams    += ips->IpForwDatagrams;
		rips->IpInDelivers       += ips->IpInDelivers;
		rips->IpReasmReqds       += ips->IpReasmReqds;
		rips->IpReasmOKs         += ips->IpReasmOKs;
		rips->IpReasmFails       += ips->IpReasmFails;
		rips->IpFragOKs          += ips->IpFragOKs;
		rips->IpFragFails        += ips->IpFragFails;
		rips->IpFragCreates      += ips->IpFragCreates;
		rips->IpInHdrErrors      += ips->IpInHdrErrors;
		rips->IpInAddrErrors     += ips->IpInAddrErrors;
		rips->IpReasmTimeout     += ips->IpReasmTimeout;
	}
}

static struct mbuf * fp_rfps_ip_new_msg_build(const fp_ip_stats_t * const ips)
{
	struct mbuf     *m;
	rfps_ip_stats_t *rips;

	m = m_alloc();
	if (m == NULL) {
		RFPS_LOG(LOG_ERR, "m_alloc() failed");
		return NULL;
	}
	rips = (rfps_ip_stats_t *)m_append(m, sizeof(rfps_ip_stats_t));
	if (rips != NULL) {
		fp_rfps_ip_stats_set(rips, ips);
		return m;
	}
	RFPS_LOG(LOG_ERR, "m_append() failed");
	m_freem(m);
	return NULL;
}

static void fp_rfps_ip_handler(rfps_engine_t *ip_ng)
{
	struct mbuf     *m;
#ifdef CONFIG_MCORE_IPV6
	rfps_ip_stats_t *rips;
#endif

	m = fp_rfps_ip_new_msg_build(fp_shared->ip_stats);
	if (m == NULL)
		return;

#ifndef CONFIG_MCORE_IPV6
	fp_rfps_msg_send(ip_ng, m, 1);
#else
	rips = (rfps_ip_stats_t *)m_append(m, sizeof(rfps_ip_stats_t));
	if (rips != NULL) { /* IPv4 & IPv6 stats fit in same message */
		fp_rfps_ip_stats_set(rips, fp_shared->ip6_stats);
		fp_rfps_msg_send(ip_ng, m, 2);
		return;
	}
	fp_rfps_msg_send(ip_ng, m, 1); /* send IPv4 only */
	m = fp_rfps_ip_new_msg_build(fp_shared->ip6_stats);
	if (m != NULL)
		fp_rfps_msg_send(ip_ng, m, 1);
#endif
}

static FPN_DEFINE_SHARED(rfps_engine_t, fp_rfps_ip) = {
	.hdr_vbof_statid  = RFPS_V0_HDR_FLAGS(RFPS_IP_STATS),
	.rfps_handler     = fp_rfps_ip_handler,
	.rfps_name        = "IPv4/IPv6",
	.rfps_conf_offset = fpn_offsetof(shared_mem_t, fp_rfps.fp_rfps_ip),
	.rfps_stat_size   = sizeof(rfps_ip_stats_t),
};

/*
 * RFPS engine for Network Interfaces Statistics.
 */
#define FP_FIRST_IFNET 1            /* entry 0 never used, start at index 1 */
#define FP_UNDEF_IFNET FP_MAX_IFNET /* undefined entry index */

typedef struct {
	rfps_engine_t rfps_ng;
	unsigned int  first_if_idx; /* of IFNET whose stats have been sent */
	unsigned int  next_if_idx;  /* of IFNET to parse at next tick */
	unsigned int  acc_tx_time;  /* time spent since first IFNET stats Tx. */
} rfps_if_engine_t;

static void fp_rfps_if_stats_set(rfps_if_stats_t *rifs,
				 const fp_ifnet_t *ifp)
{
	fp_if_stats_t const * ifs     = ifp->if_stats;
	/* last valid entry */
	const fp_if_stats_t *last_ifs = ifs + (FP_IF_STATS_NUM - 1);

	rifs->ifs_ifuid = ifp->if_ifuid;

	/* avoid the cost of previously zeroing rifs */
	rifs->ifs_ipackets   = ifs->ifs_ipackets;
	rifs->ifs_ibytes     = ifs->ifs_ibytes;
	rifs->ifs_opackets   = ifs->ifs_opackets;
	rifs->ifs_obytes     = ifs->ifs_obytes;
	rifs->ifs_ierrors    = ifs->ifs_ierrors;
	rifs->ifs_imcasts    = ifs->ifs_imcasts;
	rifs->ifs_oerrors    = ifs->ifs_oerrors;
	rifs->ifs_idropped   = ifs->ifs_idropped;
	rifs->ifs_odropped   = ifs->ifs_odropped;
	rifs->ifs_ififoerrors  = ifs->ifs_ififoerrors;
	rifs->ifs_ofifoerrors  = ifs->ifs_ofifoerrors;

	while (ifs < last_ifs) {
		ifs++;
		rifs->ifs_ipackets   += ifs->ifs_ipackets;
		rifs->ifs_ibytes     += ifs->ifs_ibytes;
		rifs->ifs_opackets   += ifs->ifs_opackets;
		rifs->ifs_obytes     += ifs->ifs_obytes;
		rifs->ifs_ierrors    += ifs->ifs_ierrors;
		rifs->ifs_imcasts    += ifs->ifs_imcasts;
		rifs->ifs_oerrors    += ifs->ifs_oerrors;
		rifs->ifs_idropped   += ifs->ifs_idropped;
		rifs->ifs_odropped   += ifs->ifs_odropped;
		rifs->ifs_ififoerrors += ifs->ifs_ififoerrors;
		rifs->ifs_ofifoerrors += ifs->ifs_ofifoerrors;
	}
}

static int fp_if_stats_is_null(const fp_ifnet_t * const ifp)
{
	fp_if_stats_t const * ifs     = ifp->if_stats;
	/* last valid entry */
	const fp_if_stats_t *last_ifs = ifs + (FP_IF_STATS_NUM - 1);
	uint64_t tmp;

        tmp = ifs->ifs_ipackets | ifs->ifs_opackets | ifs->ifs_ierrors |
		ifs->ifs_oerrors;
	while (ifs < last_ifs){
		ifs++;
		tmp |= (ifs->ifs_ipackets | ifs->ifs_opackets |
			ifs->ifs_ierrors  | ifs->ifs_oerrors);
	}
	return (tmp == 0);
}

static void update_shmem_stats(fp_ifnet_t *ifp)
{
	struct fps_nl_stats stats;

	if (!fps_nl_get_stats(ifp->if_name, &stats)) {
		ifp->if_stats[0].ifs_ipackets = stats.rx_packets;
		ifp->if_stats[0].ifs_ibytes = stats.rx_bytes;
		ifp->if_stats[0].ifs_opackets = stats.tx_packets;
		ifp->if_stats[0].ifs_obytes = stats.tx_bytes;
	}
}

static void fp_rfps_if_handler(rfps_if_engine_t *if_ng)
{
	uint32_t        max_msg_sent; /* send messages up to that max number */
	unsigned int    first_idx;    /* of IFNET previously parsed, if any */
	unsigned int    cur_idx;      /* index of IFNET being parsed */
	fp_ifnet_t      *ifp;         /* current IFNET being parsed */
	struct mbuf     *m;           /* current message being filled */
	rfps_if_stats_t *rifs;        /* next stats entry in current message */
	uint32_t        refresh_delay;/* before re-sending first IFNET stats */
	uint16_t        stats_in_msg; /* nb. of stats entries in current msg. */
	unsigned int    i;            /* current number of IFNET being parsed */

	max_msg_sent = if_ng->rfps_ng.nb_msg_sent +
		if_ng->rfps_ng.max_msg_per_tick;
	first_idx = if_ng->first_if_idx;
	m = NULL;
	stats_in_msg = 0; /* no current message */
	refresh_delay = if_ng->rfps_ng.min_refresh_delay;

	/*
	 * At most send statistics for all valid IFNETs at each tick.
	 */
	for (i = FP_FIRST_IFNET, cur_idx = if_ng->next_if_idx;
	     i < FP_MAX_IFNET; i++, cur_idx++) {

		if (cur_idx == FP_MAX_IFNET)
			cur_idx = FP_FIRST_IFNET;
		ifp = &fp_shared->ifnet.table[cur_idx];

		/*
		 * When the next IFNET to parse is the first parsed IFNET again,
		 * compare the time spent against the minimum refresh delay.
		 * If the refresh delay already elapsed, immediately send stats
		 * again for the first IFNET.
		 * Otherwise, stop sending stats and defer their
		 * re-transmission after the refresh period.
		 */
		if (cur_idx == first_idx) {
			/*
			 * Loop sending stats of first IFNET again.
			 * Reset the accumulated transmission time to zero.
			 */
			uint32_t acc_tx_time = if_ng->acc_tx_time;

			RFPS_LOG(LOG_DEBUG,
				   "cur_idx=first_idx=%u acc_tx_time=%u",
				   cur_idx, acc_tx_time);
			if_ng->acc_tx_time = 0;
			if (refresh_delay > acc_tx_time) {
				refresh_delay -= acc_tx_time;
				break;
			}
		}

		/*
		 * skip free ifnet entries
		 */
		if (ifp->if_ifuid == 0)
			continue;

		/*
		 * Coloc case: skip physical ports
		 */
		if (is_coloc && ifp->if_port != FP_IFNET_VIRTUAL_PORT)
			continue;

		/*
		 * Physical port: update shared memory by asking
		 * driver (HW statistics).
		 */
		if (ifp->if_port != FP_IFNET_VIRTUAL_PORT)
			update_shmem_stats(ifp);


		/* skip ifnet with zero traffic */
		if (fp_if_stats_is_null(ifp))
			continue;

		/* Stop sending stats once having sent max. msgs per tick */
		if (if_ng->rfps_ng.nb_msg_sent == max_msg_sent)
			goto send_at_next_tx_period;

		/*
		 * Remember first IFNET whose stats are sent, to record it
		 * if needed below.
		 */
		if (first_idx == FP_UNDEF_IFNET)
			first_idx = cur_idx;

		/* Allocate a message, if needed */
		if (stats_in_msg == 0) {
			m = m_alloc();
			if (m == NULL) {
				RFPS_LOG(LOG_ERR, "m_alloc() failed");
				goto send_at_next_tx_period;
			}
		}
		rifs = (rfps_if_stats_t *)m_append(m, sizeof(rfps_if_stats_t));
		if (rifs == NULL) {
			RFPS_LOG(LOG_ERR, "m_append() failed");
			if (! stats_in_msg) /* very strange... */
				m_freem(m);
			else
				fp_rfps_msg_send(&if_ng->rfps_ng, m,
						 stats_in_msg);
			m = NULL;
			goto send_at_next_tx_period;
		}
		fp_rfps_if_stats_set(rifs, ifp);
		stats_in_msg++;

		if (stats_in_msg < if_ng->rfps_ng.max_stats_per_msg)
			continue; /* current message not full */

		/* The message size reached the MTU - send it now */
		fp_rfps_msg_send(&if_ng->rfps_ng, m, stats_in_msg);
		m = NULL;
		stats_in_msg = 0;
	}
	/*
	 * Statistics for all IFNETs since the first one have been sent
	 * at this tick.
	 * Must only send them again after the refresh period elapsed.
	 */
	RFPS_LOG(LOG_DEBUG,
		   "All IF stats done at cur_idx=%u refresh_delay=%u (stats_in_msg=%u)",
		   cur_idx, refresh_delay, stats_in_msg);
	if_ng->first_if_idx = FP_UNDEF_IFNET;
	if_ng->next_if_idx  = cur_idx;
	if_ng->rfps_ng.next_tick_delay = refresh_delay;

	/* Send the [last] current filled message, if any. */
	if (stats_in_msg)
		fp_rfps_msg_send(&if_ng->rfps_ng, m, stats_in_msg);
	else if (m != NULL)
		m_freem(m);
	return;

send_at_next_tx_period:
	if_ng->first_if_idx = first_idx;
	if_ng->next_if_idx  = cur_idx;
	if_ng->acc_tx_time += if_ng->rfps_ng.tx_period_delay;
	if_ng->rfps_ng.next_tick_delay = if_ng->rfps_ng.tx_period_delay;
	RFPS_LOG(LOG_DEBUG,
		   "next_tx_period_send first_idx=%u cur_idx=%u acc_tx_time=%u",
		   first_idx, cur_idx, if_ng->acc_tx_time);
	if (m != NULL)
		m_freem(m);
}

static FPN_DEFINE_SHARED(rfps_if_engine_t, fp_rfps_if) = {
	{.hdr_vbof_statid  = RFPS_V0_HDR_FLAGS(RFPS_IF_STATS),
	 .rfps_handler     = (rfps_handler_t)fp_rfps_if_handler,
	 .rfps_name        = "IF",
	 .rfps_conf_offset = fpn_offsetof(shared_mem_t, fp_rfps.fp_rfps_if),
	 .rfps_stat_size   = sizeof(rfps_if_stats_t),
	},
	.first_if_idx = FP_UNDEF_IFNET, /* never parse IFNET's before */
	.next_if_idx  = FP_FIRST_IFNET, /* start parsing at first IFNET */
	.acc_tx_time  = 0,
};

#ifdef CONFIG_MCORE_IPSEC
/*
 * RFPS engine for IPsec SA Statistics.
 */
#define FP_FIRST_IPSEC_SA 1                  /* entry 0 never used, start at index 1 */
#define FP_UNDEF_IPSEC_SA FP_MAX_SA_ENTRIES  /* undefined entry index */

typedef struct {
	rfps_engine_t rfps_ng;
	unsigned int  first_sa_idx;  /* of IPsec SA whose stats have been sent */
	unsigned int  next_sa_idx;   /* of IPsec SA parse at next tick */
	unsigned int  acc_tx_time;   /* time spent since first IPsec SA stats Tx. */
} rfps_ipsec_sa_engine_t;

static inline void fp_rfps_ipsec_sa_stats_set(rfps_sa_stats_t *rsas, const fp_sa_entry_t *sa)
{
	fp_sa_stats_t *sas = (fp_sa_stats_t *)sa->stats;
	/* last valid entry */
	const fp_sa_stats_t *last_sas = sas + (FP_IPSEC_STATS_NUM - 1);

	/* avoid the cost of previously zeroing rsas */
	rsas->sa_packets         = sas->sa_packets;
	rsas->sa_bytes           = sas->sa_bytes;
	rsas->sa_auth_errors     = sas->sa_auth_errors;
	rsas->sa_decrypt_errors  = sas->sa_decrypt_errors;

	/* In case we have per-core IPsec statistics */
	while (sas < last_sas) {
		sas++;
		rsas->sa_packets         += sas->sa_packets;
		rsas->sa_bytes           += sas->sa_bytes;
		rsas->sa_auth_errors     += sas->sa_auth_errors;
		rsas->sa_decrypt_errors  += sas->sa_decrypt_errors;
	}

	/* Fill xfrm information for CP to lookup xfrm state */
	rsas->spi = sa->spi;
	rsas->family = AF_INET;
	rsas->proto = sa->proto;
	rsas->daddr[0] = sa->dst4;
	rsas->daddr[1] = 0;
	rsas->daddr[2] = 0;
	rsas->daddr[3] = 0;
	rsas->vrfid = htons(sa->vrfid);
}

static inline int fp_ipsec_sa_stats_is_null(const fp_sa_entry_t * const sa)
{
	fp_sa_stats_t *sas = (fp_sa_stats_t *)sa->stats;
	/* last valid entry */
	const fp_sa_stats_t *last_sas = sas + (FP_IPSEC_STATS_NUM - 1);
	uint64_t tmp = sas->sa_packets | sas->sa_bytes |  \
				   sas->sa_auth_errors | sas->sa_decrypt_errors | \
				   sas->sa_replay_errors | sas->sa_selector_errors;

	/* In case we have per-core IPsec statistics */
	while (sas < last_sas && !tmp) {
		sas++;
		tmp |= sas->sa_packets | sas->sa_bytes |  \
			   sas->sa_auth_errors | sas->sa_decrypt_errors | \
			   sas->sa_replay_errors | sas->sa_selector_errors;
	}

	return (tmp == 0);
}

static void fp_rfps_ipsec_sa_handler(rfps_ipsec_sa_engine_t *sa_ng)
{
	uint32_t        max_msg_sent; /* send messages up to that max number */
	unsigned int    first_idx;    /* of IPsec SA previously parsed, if any */
	unsigned int    cur_idx;      /* index of IPsec SA being parsed */
	fp_sa_entry_t   *sa;          /* current IPsec SA being parsed */
	struct mbuf     *m;           /* current message being filled */
	rfps_sa_stats_t *rsas;        /* next stats entry in current message */
	uint32_t        refresh_delay;/* before re-sending first SA stats */
	uint16_t        stats_in_msg; /* nb. of stats entries in current msg. */
	unsigned int    i;            /* current number of SA being parsed */
	unsigned int    nb_stats_found; /* number of SA statistics already found */
	uint32_t	sa_count;     /* current total number of SA */

	/* If no SA, do nothing */
	if ((sa_count = fp_get_sad()->count) == 0)
		return;

	max_msg_sent = sa_ng->rfps_ng.nb_msg_sent + sa_ng->rfps_ng.max_msg_per_tick;
	first_idx = sa_ng->first_sa_idx;
	m = NULL;
	stats_in_msg = 0; /* no current message */
	refresh_delay = sa_ng->rfps_ng.min_refresh_delay;

	/*
	 * At most send statistics for all valid SAs at each tick.
	 */
	for (i = FP_FIRST_IPSEC_SA, nb_stats_found = 0, cur_idx = sa_ng->next_sa_idx;
	     (i < FP_UNDEF_IPSEC_SA) && (nb_stats_found < sa_count);
	     i++, cur_idx++, sa_count = fp_get_sad()->count) {

		if (cur_idx == FP_MAX_SA_ENTRIES)
			cur_idx = FP_FIRST_IPSEC_SA;
		sa = &fp_shared->ipsec.sad.table[cur_idx];

		/*
		 * When the next IPsec SA to parse is the first parsed SA again,
		 * compare the time spent against the minimum refresh delay.
		 * If the refresh delay already elapsed, immediately send stats
		 * again for the first SA.
		 * Otherwise, stop sending stats and defer their
		 * re-transmission after the refresh period.
		 */
		if (cur_idx == first_idx) {
			/*
			 * Loop sending stats of first SA again.
			 * Reset the accumulated transmission time to zero.
			 */
			uint32_t acc_tx_time = sa_ng->acc_tx_time;

			RFPS_LOG(LOG_DEBUG,
				   "cur_dix=first_idx=%u acc_tx_time=%u",
				   cur_idx, acc_tx_time);
			sa_ng->acc_tx_time = 0;
			if (refresh_delay > acc_tx_time) {
				refresh_delay -= acc_tx_time;
				break;
			}
		}

		/*
		 * skip free SA entries
		 */
		if (sa->state == FP_SA_STATE_UNSPEC)
			continue;

		/* skip SA with zero traffic */
		if (fp_ipsec_sa_stats_is_null(sa))
			continue;

		/* Stop sending stats once having sent max. msgs per tick */
		if (sa_ng->rfps_ng.nb_msg_sent == max_msg_sent)
			goto send_at_next_tx_period;

		/*
		 * Remember first SA whose stats are sent, to record it
		 * if needed below.
		 */
		if (first_idx == FP_UNDEF_IPSEC_SA)
			first_idx = cur_idx;

		/* Allocate a message, if needed */
		if (stats_in_msg == 0) {
			m = m_alloc();
			if (m == NULL) {
				RFPS_LOG(LOG_ERR, "m_alloc() failed");
				goto send_at_next_tx_period;
			}
		}
		rsas = (rfps_sa_stats_t *)m_append(m, sizeof(rfps_sa_stats_t));
		if (rsas == NULL) {
			RFPS_LOG(LOG_ERR, "m_append() failed");
			if (! stats_in_msg) /* very strange... */
				m_freem(m);
			else
				fp_rfps_msg_send(&sa_ng->rfps_ng, m,
						 stats_in_msg);
			m = NULL;
			goto send_at_next_tx_period;
		}
		fp_rfps_ipsec_sa_stats_set(rsas, sa);
		stats_in_msg++;
		nb_stats_found++;

		if (stats_in_msg < sa_ng->rfps_ng.max_stats_per_msg)
			continue; /* current message not full */

		/* The message size reached the MTU - send it now */
		fp_rfps_msg_send(&sa_ng->rfps_ng, m, stats_in_msg);
		m = NULL;
		stats_in_msg = 0;
	}
	/*
	 * Statistics for all SAs since the first one have been sent
	 * at this tick.
	 * Must only send them again after the refresh period elapsed.
	 */
	RFPS_LOG(LOG_DEBUG,
		   "All SA stats done at cur_idx=%u refresh_delay=%u",
		   cur_idx, refresh_delay);
	sa_ng->first_sa_idx = FP_UNDEF_IPSEC_SA;
	sa_ng->next_sa_idx  = cur_idx;
	sa_ng->rfps_ng.next_tick_delay = refresh_delay;

	/* Send the [last] current filled message, if any. */
	if (stats_in_msg)
		fp_rfps_msg_send(&sa_ng->rfps_ng, m, stats_in_msg);
	else if (m != NULL)
		m_freem(m);
	return;

send_at_next_tx_period:
	sa_ng->first_sa_idx = first_idx;
	sa_ng->next_sa_idx  = cur_idx;
	sa_ng->acc_tx_time += sa_ng->rfps_ng.tx_period_delay;
	sa_ng->rfps_ng.next_tick_delay = sa_ng->rfps_ng.tx_period_delay;
	RFPS_LOG(LOG_DEBUG,
		   "next_tx_period_send first_idx=%u cur_idx=%u acc_tx_time=%u",
		   first_idx, cur_idx, sa_ng->acc_tx_time);
	if (m != NULL)
		m_freem(m);
}

static FPN_DEFINE_SHARED(rfps_ipsec_sa_engine_t, fp_rfps_ipsec_sa) = {
	{.hdr_vbof_statid  = RFPS_V0_HDR_FLAGS(RFPS_SA_STATS),
	 .rfps_handler     = (rfps_handler_t)fp_rfps_ipsec_sa_handler,
	 .rfps_name        = "SA",
	 .rfps_conf_offset = fpn_offsetof(shared_mem_t, fp_rfps.fp_rfps_ipsec_sa),
	 .rfps_stat_size   = sizeof(rfps_sa_stats_t),
	},
	.first_sa_idx = FP_UNDEF_IPSEC_SA, /* never parse SA's before */
	.next_sa_idx  = FP_FIRST_IPSEC_SA, /* start parsing at first SA */
	.acc_tx_time  = 0,
};

#endif /* CONFIG_MCORE_IPSEC */

#ifdef CONFIG_MCORE_IPSEC_IPV6
/*
 * RFPS engine for IPsec SA Statistics.
 */
#define FP_FIRST_IPSEC6_SA 1                       /* entry 0 never used, start at index 1 */
#define FP_UNDEF_IPSEC6_SA FP_MAX_IPV6_SA_ENTRIES  /* undefined entry index */

static inline void fp_rfps_ipsec6_sa_stats_set(rfps_sa_stats_t *rsas, const fp_v6_sa_entry_t *sa)
{
	fp_sa_stats_t *sas = (fp_sa_stats_t *)sa->stats;
	/* last valid entry */
	const fp_sa_stats_t *last_sas = sas + (FP_IPSEC6_STATS_NUM - 1);

	/* avoid the cost of previously zeroing rsas */
	rsas->sa_packets         = sas->sa_packets;
	rsas->sa_bytes           = sas->sa_bytes;
	rsas->sa_auth_errors     = sas->sa_auth_errors;
	rsas->sa_decrypt_errors  = sas->sa_decrypt_errors;

	/* In case we have per-core IPsec statistics */
	while (sas < last_sas) {
		sas++;
		rsas->sa_packets         += sas->sa_packets;
		rsas->sa_bytes           += sas->sa_bytes;
		rsas->sa_auth_errors     += sas->sa_auth_errors;
		rsas->sa_decrypt_errors  += sas->sa_decrypt_errors;
	}

	/* Fill xfrm information for CP to lookup xfrm state */
	rsas->spi = sa->spi; /* stored in network order */
	rsas->family = AF_INET6;
	rsas->proto = sa->proto;
	rsas->vrfid = htons(sa->vrfid);
	memcpy(rsas->daddr, &sa->dst6, sizeof(rsas->daddr));
}

static inline int fp_ipsec6_sa_stats_is_null(const fp_v6_sa_entry_t * const sa)
{
	fp_sa_stats_t *sas = (fp_sa_stats_t *)sa->stats;
	/* last valid entry */
	const fp_sa_stats_t *last_sas = sas + (FP_IPSEC6_STATS_NUM - 1);
	uint64_t tmp = sas->sa_packets | sas->sa_bytes |  \
				   sas->sa_auth_errors | sas->sa_decrypt_errors | \
				   sas->sa_replay_errors | sas->sa_selector_errors;

	/* In case we have per-core IPsec statistics */
	while (sas < last_sas && !tmp) {
		sas++;
		tmp |= sas->sa_packets | sas->sa_bytes |  \
			   sas->sa_auth_errors | sas->sa_decrypt_errors | \
			   sas->sa_replay_errors | sas->sa_selector_errors;
	}

	return (tmp == 0);
}

static void fp_rfps_ipsec6_sa_handler(rfps_ipsec_sa_engine_t *sa_ng)
{
	uint32_t        max_msg_sent; /* send messages up to that max number */
	unsigned int    first_idx;    /* of IPsec SA previously parsed, if any */
	unsigned int    cur_idx;      /* index of IPsec SA being parsed */
	fp_v6_sa_entry_t *sa;          /* current IPsec SA being parsed */
	struct mbuf     *m;           /* current message being filled */
	rfps_sa_stats_t *rsas;        /* next stats entry in current message */
	uint32_t        refresh_delay;/* before re-sending first SA6 stats */
	uint16_t        stats_in_msg; /* nb. of stats entries in current msg. */
	unsigned int    i;            /* current number of SA6 being parsed */
	unsigned int	nb_stats_found; /* number of SA statistics already found */
	uint32_t	sa_count;     /* current total number of SA */

	/* If no SA, do nothing */
	if ((sa_count = fp_get_sad6()->count) == 0)
		return;

	max_msg_sent = sa_ng->rfps_ng.nb_msg_sent +
		sa_ng->rfps_ng.max_msg_per_tick;
	first_idx = sa_ng->first_sa_idx;
	m = NULL;
	stats_in_msg = 0; /* no current message */
	refresh_delay = sa_ng->rfps_ng.min_refresh_delay;

	/*
	 * At most send statistics for all valid SAs at each tick.
	 */
	for (i = FP_FIRST_IPSEC6_SA, nb_stats_found = 0, cur_idx = sa_ng->next_sa_idx;
	     (i < FP_UNDEF_IPSEC6_SA) && (nb_stats_found < sa_count);
	     i++, cur_idx++, sa_count = fp_get_sad6()->count) {

		if (cur_idx == FP_MAX_IPV6_SA_ENTRIES)
			cur_idx = FP_FIRST_IPSEC6_SA;
		sa = &fp_shared->ipsec6.sad6.table[cur_idx];

		/*
		 * When the next IPsec SA to parse is the first parsed SA again,
		 * compare the time spent against the minimum refresh delay.
		 * If the refresh delay already elapsed, immediately send stats
		 * again for the first SA.
		 * Otherwise, stop sending stats and defer their
		 * re-transmission after the refresh period.
		 */
		if (cur_idx == first_idx) {
			/*
			 * Loop sending stats of first SA again.
			 * Reset the accumulated transmission time to zero.
			 */
			uint32_t acc_tx_time = sa_ng->acc_tx_time;

			RFPS_LOG(LOG_DEBUG,
				   "cur_dix=first_idx=%u acc_tx_time=%u",
				   cur_idx, acc_tx_time);
			sa_ng->acc_tx_time = 0;
			if (refresh_delay > acc_tx_time) {
				refresh_delay -= acc_tx_time;
				break;
			}
		}

		/*
		 * skip free SA entries
		 */
		if (sa->state == FP_SA_STATE_UNSPEC)
			continue;

		/* skip SA with zero traffic */
		if (fp_ipsec6_sa_stats_is_null(sa))
			continue;

		/* Stop sending stats once having sent max. msgs per tick */
		if (sa_ng->rfps_ng.nb_msg_sent == max_msg_sent)
			goto send_at_next_tx_period;

		/*
		 * Remember first SA whose stats are sent, to record it
		 * if needed below.
		 */
		if (first_idx == FP_UNDEF_IPSEC6_SA)
			first_idx = cur_idx;

		/* Allocate a message, if needed */
		if (stats_in_msg == 0) {
			m = m_alloc();
			if (m == NULL) {
				RFPS_LOG(LOG_ERR, "m_alloc() failed");
				goto send_at_next_tx_period;
			}
		}
		rsas = (rfps_sa_stats_t *)m_append(m, sizeof(rfps_sa_stats_t));
		if (rsas == NULL) {
			RFPS_LOG(LOG_ERR, "m_append() failed");
			if (! stats_in_msg) /* very strange... */
				m_freem(m);
			else
				fp_rfps_msg_send(&sa_ng->rfps_ng, m,
						 stats_in_msg);
			goto send_at_next_tx_period;
		}
		fp_rfps_ipsec6_sa_stats_set(rsas, sa);
		stats_in_msg++;
		nb_stats_found++;

		if (stats_in_msg < sa_ng->rfps_ng.max_stats_per_msg)
			continue; /* current message not full */

		/* The message size reached the MTU - send it now */
		fp_rfps_msg_send(&sa_ng->rfps_ng, m, stats_in_msg);
		stats_in_msg = 0;
	}
	/*
	 * Statistics for all SAs since the first one have been sent
	 * at this tick.
	 * Must only send them again after the refresh period elapsed.
	 */
	RFPS_LOG(LOG_DEBUG,
		   "All IPv6 SA stats done at cur_idx=%u refresh_delay=%u",
		   cur_idx, refresh_delay);
	sa_ng->first_sa_idx = FP_UNDEF_IPSEC6_SA;
	sa_ng->next_sa_idx  = cur_idx;
	sa_ng->rfps_ng.next_tick_delay = refresh_delay;

	/* Send the [last] current filled message, if any. */
	if (stats_in_msg)
		fp_rfps_msg_send(&sa_ng->rfps_ng, m, stats_in_msg);
	return;

send_at_next_tx_period:
	sa_ng->first_sa_idx = first_idx;
	sa_ng->next_sa_idx  = cur_idx;
	sa_ng->acc_tx_time += sa_ng->rfps_ng.tx_period_delay;
	sa_ng->rfps_ng.next_tick_delay = sa_ng->rfps_ng.tx_period_delay;
	RFPS_LOG(LOG_DEBUG,
		   "next_tx_period_send first_idx=%u cur_idx=%u acc_tx_time=%u",
		   first_idx, cur_idx, sa_ng->acc_tx_time);
}

static FPN_DEFINE_SHARED(rfps_ipsec_sa_engine_t, fp_rfps_ipsec6_sa) = {
	{.hdr_vbof_statid  = RFPS_V0_HDR_FLAGS(RFPS_SA6_STATS),
	 .rfps_handler     = (rfps_handler_t)fp_rfps_ipsec6_sa_handler,
	 .rfps_name        = "SA6",
	 .rfps_conf_offset = fpn_offsetof(shared_mem_t, fp_rfps.fp_rfps_ipsec6_sa),
	 .rfps_stat_size   = sizeof(rfps_sa_stats_t),
	},
	.first_sa_idx = FP_UNDEF_IPSEC6_SA, /* never parse SA's before */
	.next_sa_idx  = FP_FIRST_IPSEC6_SA, /* start parsing at first SA */
	.acc_tx_time  = 0,
};

#endif /* CONFIG_MCORE_IPSEC_IPV6 */

/*
 * The RFPS initialisation routine called once at Fast Path start time.
 */
void fp_rfps_init(void)
{
	/* Initialize callout-based RFPS engines for each type of statistics */
	fp_rfps_engine_init(&fp_rfps_ip);
	fp_rfps_engine_init(&fp_rfps_if.rfps_ng);
#ifdef CONFIG_MCORE_IPSEC
	fp_rfps_engine_init(&fp_rfps_ipsec_sa.rfps_ng);
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_rfps_engine_init(&fp_rfps_ipsec6_sa.rfps_ng);
#endif
}

static int mtu_init(void)
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd >= 0) {
		memset(&ifr, 0, sizeof(struct ifreq));
		strcpy(ifr.ifr_name, ifname);
		if (ioctl(fd, SIOCGIFMTU, &ifr) == 0)
			ifmtu = ifr.ifr_mtu;
		close(fd);
	}
	syslog(LOG_INFO, "Using %s mtu %u\n", ifname, ifmtu);

	return 0;
}

static int socket_init(void)
{
	unsigned int ifindex;

	s = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_FPTUN));

	if (s == -1) {
		fprintf(stderr, "%s", strerror(errno));
		return -1;
	}
	ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		fprintf(stderr, "%s", strerror(errno));
		close(s);
		return -1;
	}

	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_FPTUN);
	addr.sll_ifindex = ifindex;
	addr.sll_halen = ETHER_ADDR_LEN;
	addr.sll_pkttype = PACKET_HOST;
	memcpy(addr.sll_addr, dest_mac, ETHER_ADDR_LEN);

	return 0;
}

static int sendit(char *buf, int buflen)
{
	int len;

	len = sendto(s, buf, buflen, 0,
			(const struct sockaddr *)&addr, sizeof(addr));
	if (len != buflen) {
		fprintf(stderr, "sendto: %s\n", strerror(errno));
	}

	return 0;
}

static int parse_mac(char *buf, uint8_t *result)
{
	int n = sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&result[0], &result[1], &result[2],
			&result[3], &result[4], &result[5]);

	return (n != 6);
}

static void usage(void)
{
	printf("usage: fpsd [-hFd] [-i <interface name>] [-m destination mac] [-Z <file>]\n");
	printf("       -h : this help\n");
	printf("       -F : foreground\n");
	printf("       -d : debug trace enabled\n");
	printf("       -i <ifname>: default peer interface to fptun, default is lo\n");
	printf("       -m <mac>: default peer mac address, default is zero'd\n");
	printf("       -Z <file>: handle used by HA system\n");
	exit(2);
}

#ifdef HA_SUPPORT
static int has_event_init(char *srvname, int ac, char *av[])
{
	int rc;

	rc = has_init(HA6W_COMP_FPSD, &fps_has, srvname, ac, av,
			HAS_NOAUTO_READY, NULL);
	if (rc == HA6W_RESULT_ERROR) {
		syslog(LOG_ERR, "Can not initialize High Availability support\n");
		return -1;
	}

	event_set(&has_event, fps_has->sock, EV_READ | EV_PERSIST,
			has_handler_event, fps_has);
	if (event_add(&has_event, NULL)) {
		has_exit(fps_has);
		syslog(LOG_ERR, "HA support event_add has_event");
		return -1;
	}

	return 0;
}
#endif

static void
catch_sig (int fd, short event, void *__data)
{
	int data = (int)(long)__data;

	if (data == SIGTERM) {
		syslog(LOG_INFO, "SIGTERM received: exiting\n");
#ifdef HA_SUPPORT
		has_exit(fps_has);
#endif
		exit (0);
	}
}

int main(int ac, char *av[])
{
	int ch;
	int f_foreground = 0;
#ifdef HA_SUPPORT
	char *has_srvname = NULL;
#endif

	while ((ch = getopt(ac, av, "hi:Fdm:Z:")) != EOF) {
		switch(ch) {
		case 'h':
			usage();
			break;
		case 'F':
			f_foreground = 1;
			break;
		case 'd':
			debug++;
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'm':
			if (parse_mac(optarg, dest_mac)) {
				fprintf(stderr, "-m: invalid mac address\n");
				usage();
			}
			break;
		case 'Z':
#ifdef HA_SUPPORT
			has_srvname = optarg;
#endif /* HA_SUPPORT */
			break;
		}
	}

	is_coloc = 1;
	if (strncmp(ifname, "lo", 2))
		is_coloc = 0;

	openlog ("fpsd", LOG_NDELAY | LOG_PID | (debug ? LOG_PERROR : 0), LOG_DAEMON);
	syslog(LOG_INFO, "fpsd: pushing over %s\n", ifname);

	if (!f_foreground) {
		if (daemon(1, 1) < 0)
			err(1, "daemon");
	}

	if (socket_init() < 0)
		return -1;

	if (mtu_init() < 0)
		return -1;

	if (fps_nl_init() < 0)
		return -1;

	event_init();

#ifdef HA_SUPPORT
	if (has_event_init(has_srvname, ac, av) < 0)
		return -1;
#endif

	signal_set (&sigterm, SIGTERM, catch_sig, (void *)SIGTERM);
	signal_add (&sigterm, NULL);

#ifdef HA_SUPPORT
	fps_has->ready = 1;
	has_ready(fps_has);
#endif

	fp_rfps_init();

	event_dispatch();
#ifdef HA_SUPPORT
	has_exit(fps_has);
#endif
}
