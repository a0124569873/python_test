/*
 * Copyright(c) 2014 6WIND, All rights reserved.
 */

#include "fpn.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "fp.h"
#include "fptun.h"
#include "fp-var.h"
#include "net/fp-ethernet.h"

#include "fp-hitflags.h"
#ifdef CONFIG_MCORE_IP
#include "fp-neigh.h"
#endif

#ifdef CONFIG_MCORE_NETFILTER
#include "fp-nfct.h"
#endif

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

static struct event sigterm;

static int debug = 0;
static char *ifname = "lo";
static unsigned int ifmtu = 1500;
static struct sockaddr_ll addr;
static int s = -1;
static uint8_t dest_mac[6] = { 0 };
#ifdef CONFIG_MCORE_MULTIBLADE
static fp_ifnet_t *fpib_ifnet = NULL;
static struct sockaddr_ll fpib_addr;
#endif

#ifdef HA_SUPPORT
#include <6whasapi.h>
#include <hasupport.h>
static struct has_ctx *hitflags_has = NULL;
static struct event has_event;
#endif

#define TRACE_HF_SYNC(level, fmt, args...) do {    \
		if (debug >= 1 || level <= LOG_ERR)   \
			syslog(level, "%s():" fmt "\n",   \
		       __func__, ## args);            \
		if (debug >= 2)                       \
			fprintf(stdout, "%s():" fmt "\n", \
		       __func__, ## args);            \
	} while(0)

typedef void (*hitflags_callout_hdlr_t)(void *arg);

struct callout {
   struct event ev;
   hitflags_callout_hdlr_t func;
   void *args;
   int timer;
};

static void hitflags_send(void *);
struct hf_param {
	uint8_t         hfp_type;
	uint8_t         hfp_period;
	uint32_t        hfp_max_scanned;
	uint32_t        hfp_max_sent;
	struct callout  hfp_callout;
};

/* ARP */
static FPN_DEFINE_SHARED(struct hf_param, fp_hf_arp) = {
	.hfp_type          = HF_ARP,
	.hfp_period        = HF_PERIOD_DFLT_ARP,
	.hfp_max_scanned   = HF_MAX_SCANNED_DFLT_ARP,
	.hfp_max_sent      = HF_MAX_SENT_DFLT_ARP,
};

/* NDP */
#ifdef CONFIG_MCORE_IPV6
static FPN_DEFINE_SHARED(struct hf_param, fp_hf_ndp) = {
	.hfp_type          = HF_NDP,
	.hfp_period        = HF_PERIOD_DFLT_NDP,
	.hfp_max_scanned   = HF_MAX_SCANNED_DFLT_NDP,
	.hfp_max_sent      = HF_MAX_SENT_DFLT_NDP,
};
#endif

/* conntrack */
#ifdef CONFIG_MCORE_NF_CT
static FPN_DEFINE_SHARED(struct hf_param, fp_hf_ct) = {
	.hfp_type          = HF_CT,
	.hfp_period        = HF_PERIOD_DFLT_CT,
	.hfp_max_scanned   = HF_MAX_SCANNED_DFLT_CT,
	.hfp_max_sent      = HF_MAX_SENT_DFLT_CT,
};
#endif

#ifdef CONFIG_MCORE_NETFILTER_IPV6
static FPN_DEFINE_SHARED(struct hf_param, fp_hf_ct6) = {
	.hfp_type          = HF_CT6,
	.hfp_period        = HF_PERIOD_DFLT_CT6,
	.hfp_max_scanned   = HF_MAX_SCANNED_DFLT_CT6,
	.hfp_max_sent      = HF_MAX_SENT_DFLT_CT6,
};
#endif

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
static unsigned int mbuf_default_headroom = 128; /* enough for hitflag hdr + fptun */

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

#ifdef CONFIG_MCORE_MULTIBLADE
static void fpib_init(void)
{
	if (fp_shared->fpib_ifuid) {
		fpib_ifnet = fp_ifuid2ifnet(fp_shared->fpib_ifuid);

		fpib_addr.sll_family = AF_PACKET;
		fpib_addr.sll_protocol = htons(ETH_P_FPTUN);
		fpib_addr.sll_ifindex = if_nametoindex(fpib_ifnet->if_name);
		fpib_addr.sll_halen = ETHER_ADDR_LEN;
		fpib_addr.sll_pkttype = PACKET_HOST;
	}
}
#endif

static int sendit(char *buf, int buflen, uint8_t master_bladeid)
{
	int len = 0;

	if (!master_bladeid) {
		len = sendto(s, buf, buflen, 0,
				(const struct sockaddr *)&addr, sizeof(addr));
	} else {
#ifdef CONFIG_MCORE_MULTIBLADE
		if (unlikely(!fpib_ifnet))
			fpib_init();

		if (likely(fpib_ifnet)) {
			memcpy(fpib_addr.sll_addr, fp_shared->fp_blades[master_bladeid].blade_mac, ETHER_ADDR_LEN);
			len = sendto(s, buf, buflen, 0,
					(const struct sockaddr *)&fpib_addr, sizeof(fpib_addr));
		} else {
			TRACE_HF_SYNC(FP_LOG_INFO, "fpib_addr is not initialized yet, message cannot be sent out\n");
			return -1;
		}
#endif
	}
	if (len != buflen)
		TRACE_HF_SYNC(FP_LOG_ERR, "sendto: %s\n", strerror(errno));

	return 0;
}

/* Used to periodically check availability if hitflagsd is ready to start */
#define CHECK_HITFLAGSD_READY_DELAY 1
#define CHECK_HITFLAGSD_MAX_TIMES   3

/* Used while the hitflagsd is not ready to start */
static struct callout hitflagsd_ready_handler;

static void fp_hitflags_init(void)
{
	fp_shared->fp_hf_arp.hfp_period = HF_PERIOD_DFLT_ARP;
	fp_shared->fp_hf_arp.hfp_max_scanned = HF_MAX_SCANNED_DFLT_ARP;
	fp_shared->fp_hf_arp.hfp_max_sent = HF_MAX_SENT_DFLT_ARP;

#ifdef CONFIG_MCORE_IPV6
	fp_shared->fp_hf_ndp.hfp_period = HF_PERIOD_DFLT_NDP;
	fp_shared->fp_hf_ndp.hfp_max_scanned = HF_MAX_SCANNED_DFLT_NDP;
	fp_shared->fp_hf_ndp.hfp_max_sent = HF_MAX_SENT_DFLT_NDP;
#endif

#ifdef CONFIG_MCORE_NF_CT
	fp_shared->fp_hf_ct.hfp_period = HF_PERIOD_DFLT_CT;
	fp_shared->fp_hf_ct.hfp_max_scanned = HF_MAX_SCANNED_DFLT_CT;
	fp_shared->fp_hf_ct.hfp_max_sent = HF_MAX_SENT_DFLT_CT;
#endif

#ifdef CONFIG_MCORE_NETFILTER_IPV6
	fp_shared->fp_hf_ct6.hfp_period = HF_PERIOD_DFLT_CT6;
	fp_shared->fp_hf_ct6.hfp_max_scanned = HF_MAX_SCANNED_DFLT_CT6;
	fp_shared->fp_hf_ct6.hfp_max_sent = HF_MAX_SENT_DFLT_CT6;
#endif
}

static void fp_hitflags_start(void)
{
#ifdef CONFIG_MCORE_MULTIBLADE
	/* fpib may not be ready after hitflagsd started.
	 * Waiting for 3 secs. to check if it is multi-blade mode.
	 */
	static int start_counts = 0;
#endif

	if (fp_shared == NULL)
		fp_shared = get_fp_shared();

	if (fp_shared == NULL || fp_shared->conf.w32.magic != FP_SHARED_MAGIC32) {
		callout_reset(&hitflagsd_ready_handler,
				CHECK_HITFLAGSD_READY_DELAY,
				(hitflags_callout_hdlr_t)fp_hitflags_start,
				NULL);
		return;
	}

#ifdef CONFIG_MCORE_MULTIBLADE
	fpib_init();

	/* waiting for fpib to be ready */
	if (!fpib_ifnet && start_counts < CHECK_HITFLAGSD_MAX_TIMES) {
		start_counts++;
		callout_reset(&hitflagsd_ready_handler,
				CHECK_HITFLAGSD_READY_DELAY,
				(hitflags_callout_hdlr_t)fp_hitflags_start,
				NULL);
		return;
	}
#endif

#ifdef CONFIG_MCORE_MULTIBLADE
	if (fpib_ifnet)
		syslog(LOG_INFO, "hitflagsd: pushing over %s and %s\n", ifname, fpib_ifnet->if_name);
	else
#endif
		syslog(LOG_INFO, "hitflagsd: pushing over %s\n", ifname);

	fp_hitflags_init();

	callout_init(&fp_hf_arp.hfp_callout);
	callout_reset(&fp_hf_arp.hfp_callout, fp_hf_arp.hfp_period, hitflags_send, &fp_hf_arp);
#ifdef CONFIG_MCORE_IPV6
	callout_init(&fp_hf_ndp.hfp_callout);
	callout_reset(&fp_hf_ndp.hfp_callout, fp_hf_ndp.hfp_period, hitflags_send, &fp_hf_ndp);
#endif

#ifdef CONFIG_MCORE_NF_CT
	callout_init(&fp_hf_ct.hfp_callout);
	callout_reset(&fp_hf_ct.hfp_callout, fp_hf_ct.hfp_period, hitflags_send, &fp_hf_ct);
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	callout_init(&fp_hf_ct6.hfp_callout);
	callout_reset(&fp_hf_ct6.hfp_callout, fp_hf_ct6.hfp_period, hitflags_send, &fp_hf_ct6);
#endif
}

static void hitflags_pkt_send(uint8_t master_bladeid, struct mbuf *m)
{
	struct fptunhdr thdr;
	char *data;

	thdr.fptun_cmd = FPTUN_HITFLAGS_SYNC;
	thdr.fptun_exc_class = 0;
	thdr.fptun_version = FPTUN_VERSION;
	thdr.fptun_mtags = 0;
	thdr.fptun_proto = 0;
	thdr.fptun_vrfid = 0;
	thdr.fptun_ifuid = 0;

	if (!master_bladeid) {
		thdr.fptun_blade_id = fp_shared->active_cpid;

		data = m_prepend(m, sizeof(thdr));
		if (data) {
			memcpy(data, &thdr, sizeof(thdr));
			sendit(data, m_len(m), master_bladeid);
		}

		TRACE_HF_SYNC(FP_LOG_INFO, "send hitflags sync message to SP");

		m_freem(m);
	} else {
#ifdef CONFIG_MCORE_MULTIBLADE
		thdr.fptun_blade_id  = master_bladeid;

		data = m_prepend(m, sizeof(thdr));
		if (data) {
			memcpy(data, &thdr, sizeof(thdr));
			sendit(data, m_len(m), master_bladeid);
		}

		TRACE_HF_SYNC(FP_LOG_INFO, "send hitflags sync message to FP of blade %d", master_bladeid);
#endif
		m_freem(m);
	}

}

/*
 * For ARP and NDP:
 * In master FP (fp_blade_id == fp_neigh_bladeid), hitflag is set only
 * when entry is STALE.
 * In salve FP (fp_blade_id != fp_neigh_bladeid), hitflag is always set
 * when entry is used.
 */
static fp_nh4_entry_t *hitflags_arp_getnext(uint32_t *scanned, uint32_t max_scanned)
{
	static uint32_t i = 1;
	uint32_t start = i;

	for (; i < FP_IPV4_NBNHENTRIES && (*scanned) < max_scanned; i++, (*scanned)++)
		if (fp_shared->fp_nh4_table[i].nh.nh_l2_state != L2_STATE_NONE &&
		    fp_shared->fp_nh4_table[i].nh.nh_hitflag) {
			i++;
			(*scanned)++;
			return &fp_shared->fp_nh4_table[i - 1];
		}

	if (*scanned == max_scanned)
		return NULL;

	for (i = 1; i < start && (*scanned) < max_scanned; i++, (*scanned)++)
		if (fp_shared->fp_nh4_table[i].nh.nh_l2_state != L2_STATE_NONE &&
		    fp_shared->fp_nh4_table[i].nh.nh_hitflag) {
			i++;
			(*scanned)++;
			return &fp_shared->fp_nh4_table[i - 1];
		}

	return NULL;
}

#ifdef CONFIG_MCORE_IPV6
static fp_nh6_entry_t *hitflags_ndp_getnext(uint32_t *scanned, uint32_t max_scanned)
{
	static uint32_t i = 1;
	uint32_t start = i;

	for (; i < FP_IPV6_NBNHENTRIES && (*scanned) < max_scanned; i++, (*scanned)++)
		if (fp_shared->fp_nh6_table[i].nh.nh_l2_state != L2_STATE_NONE &&
		    fp_shared->fp_nh6_table[i].nh.nh_hitflag) {
			i++;
			(*scanned)++;
			return &fp_shared->fp_nh6_table[i - 1];
		}

	if (*scanned == max_scanned)
		return NULL;

	for (i = 1; i < start && (*scanned) < max_scanned; i++, (*scanned)++)
		if (fp_shared->fp_nh6_table[i].nh.nh_l2_state != L2_STATE_NONE &&
		    fp_shared->fp_nh6_table[i].nh.nh_hitflag) {
			i++;
			(*scanned)++;
			return &fp_shared->fp_nh6_table[i - 1];
		}

	return NULL;
}
#endif /* CONFIG_MCORE_IPV6 */

#ifdef CONFIG_MCORE_NF_CT
static struct fp_nfct_entry *hitflags_ct_getnext(uint32_t *scanned, uint32_t max_scanned)
{
	static uint32_t i = 0;
	uint32_t start = i;

	for (; i < FP_NF_CT_MAX && (*scanned) < max_scanned; i++, (*scanned)++)
		if (fp_shared->fp_nf_ct.fp_nfct[i].flag & FP_NFCT_FLAG_VALID &&
		    fp_shared->fp_nf_ct.fp_nfct[i].flag & FP_NFCT_FLAG_UPDATE) {
			i++;
			(*scanned)++;
			return &fp_shared->fp_nf_ct.fp_nfct[i - 1];
		}

	if (*scanned == max_scanned)
		return NULL;

	for (i = 0; i < start && (*scanned) < max_scanned; i++, (*scanned)++)
		if (fp_shared->fp_nf_ct.fp_nfct[i].flag & FP_NFCT_FLAG_VALID &&
		    fp_shared->fp_nf_ct.fp_nfct[i].flag & FP_NFCT_FLAG_UPDATE) {
			i++;
			(*scanned)++;
			return &fp_shared->fp_nf_ct.fp_nfct[i - 1];
		}

	return NULL;
}
#endif /* CONFIG_MCORE_NF_CT */

#ifdef CONFIG_MCORE_NETFILTER_IPV6
static struct fp_nf6ct_entry *hitflags_ct6_getnext(uint32_t *scanned, uint32_t max_scanned)
{
	static uint32_t i = 0;
	uint32_t start = i;

	for (; i < FP_NF6_CT_MAX && (*scanned) < max_scanned; i++, (*scanned)++)
		if (fp_shared->fp_nf6_ct.fp_nf6ct[i].flag & FP_NFCT_FLAG_VALID &&
		    fp_shared->fp_nf6_ct.fp_nf6ct[i].flag & FP_NFCT_FLAG_UPDATE)
			return &fp_shared->fp_nf6_ct.fp_nf6ct[i];

	if (*scanned == max_scanned)
		return NULL;

	for (i = 0; i < start && (*scanned) < max_scanned; i++, (*scanned)++)
		if (fp_shared->fp_nf6_ct.fp_nf6ct[i].flag & FP_NFCT_FLAG_VALID &&
		    fp_shared->fp_nf6_ct.fp_nf6ct[i].flag & FP_NFCT_FLAG_UPDATE)
			return &fp_shared->fp_nf6_ct.fp_nf6ct[i];

	return NULL;
}
#endif /* CONFIG_MCORE_NETFILTER_IPV6 */

#ifndef HF_MIN
#define HF_MIN(a,b) (b < a ? b : a)
#endif

static void update_hf_param(struct hf_param *param)
{
	switch (param->hfp_type) {
	case HF_ARP:
		fp_hf_arp.hfp_period = fp_shared->fp_hf_arp.hfp_period;
		fp_hf_arp.hfp_max_scanned = HF_MIN(fp_shared->fp_hf_arp.hfp_max_scanned,
				FP_IPV4_NBNHENTRIES);
		fp_hf_arp.hfp_max_sent = HF_MIN(fp_shared->fp_hf_arp.hfp_max_sent,
				FP_IPV4_NBNHENTRIES);

		TRACE_HF_SYNC(FP_LOG_INFO, "Update arp hitflags param: hfp_period=%u, "
				"hfp_max_scanned=%u, hfp_max_sent=%u", fp_hf_arp.hfp_period,
				fp_hf_arp.hfp_max_scanned, fp_hf_arp.hfp_max_sent);
		break;
#ifdef CONFIG_MCORE_IPV6
	case HF_NDP:
		fp_hf_ndp.hfp_period = fp_shared->fp_hf_ndp.hfp_period;
		fp_hf_ndp.hfp_max_scanned = HF_MIN(fp_shared->fp_hf_ndp.hfp_max_scanned,
				FP_IPV6_NBNHENTRIES);
		fp_hf_ndp.hfp_max_sent = HF_MIN(fp_shared->fp_hf_ndp.hfp_max_sent,
				FP_IPV6_NBNHENTRIES);

		TRACE_HF_SYNC(FP_LOG_INFO, "Update ndp hitflags param: hfp_period=%u, "
				"hfp_max_scanned=%u, hfp_max_sent=%u\n", fp_hf_ndp.hfp_period,
				fp_hf_ndp.hfp_max_scanned, fp_hf_ndp.hfp_max_sent);
		break;
#endif
#ifdef CONFIG_MCORE_NF_CT
	case HF_CT:
		fp_hf_ct.hfp_period = fp_shared->fp_hf_ct.hfp_period;
		fp_hf_ct.hfp_max_scanned = HF_MIN(fp_shared->fp_hf_ct.hfp_max_scanned,
				FP_NF_CT_MAX);
		fp_hf_ct.hfp_max_sent = HF_MIN(fp_shared->fp_hf_ct.hfp_max_sent,
				FP_NF_CT_MAX);

		TRACE_HF_SYNC(FP_LOG_INFO, "Update conntrack hitflags param: hfp_period=%u, "
				"hfp_max_scanned=%u, hfp_max_sent=%u\n", fp_hf_ct.hfp_period,
				fp_hf_ct.hfp_max_scanned, fp_hf_ct.hfp_max_sent);
		break;
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	case HF_CT6:
		fp_hf_ct6.hfp_period = fp_shared->fp_hf_ct6.hfp_period;
		fp_hf_ct6.hfp_max_scanned = HF_MIN(fp_shared->fp_hf_ct6.hfp_max_scanned,
				FP_NF6_CT_MAX);
		fp_hf_ct6.hfp_max_sent = HF_MIN(fp_shared->fp_hf_ct6.hfp_max_sent,
				FP_NF6_CT_MAX);

		TRACE_HF_SYNC(FP_LOG_INFO, "Update conntrack6 hitflags param: hfp_period=%u, "
				"hfp_max_scanned=%u, hfp_max_sent=%u\n", fp_hf_ct6.hfp_period,
				fp_hf_ct6.hfp_max_scanned, fp_hf_ct6.hfp_max_sent);
		break;
#endif
	}
}

static void hitflags_send(void *arg)
{
	struct hf_param *param = (struct hf_param *)arg;
	struct mbuf *m = NULL;
	struct fphitflagshdr *hf_hdr = NULL;
	uint32_t scanned_entries = 0, sent_entries = 0;
	uint32_t max_entries = 0, max_size = 0;
	uint8_t master_bladeid = 0;
	int hf_size = 0;

	if (fp_shared->conf.w32.magic != FP_SHARED_MAGIC32)
		goto end;

	if ((param->hfp_type == HF_CT
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	     || param->hfp_type == HF_CT6
#endif
	    ) &&
	    !(fp_shared->conf.w32.do_func & FP_CONF_DO_NETFILTER) &&
	    !(fp_shared->conf.w32.do_func & FP_CONF_DO_NETFILTER6))

		goto end;

	update_hf_param(param);

	switch (param->hfp_type) {
	case HF_ARP:
		hf_size = sizeof(struct fphitflagsarp);
		break;
#ifdef CONFIG_MCORE_IPV6
	case HF_NDP:
		hf_size = sizeof(struct fphitflagsndp);
		break;
	case HF_CT6:
		hf_size = sizeof(struct fphitflags6entry);
		break;
#endif
	case HF_CT:
	default:
		hf_size = sizeof(struct fphitflagsentry);
		break;
	}

#ifdef CONFIG_MCORE_MULTIBLADE
	switch (param->hfp_type) {
	case HF_ARP:
		/* no break */
#ifdef CONFIG_MCORE_IPV6
	case HF_NDP:
#endif
		if (fp_shared->fp_blade_id != fp_shared->fp_neigh_bladeid)
			master_bladeid = fp_shared->fp_neigh_bladeid;
#ifdef CONFIG_MCORE_1CP_XFP
		if (!fp_shared->fp_neigh_bladeid &&
		    fp_shared->fp_blade_id != fp_shared->cp_blade_id)
			master_bladeid = fp_shared->cp_blade_id;
#endif
		break;
	case HF_CT:
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	case HF_CT6:
#endif
#ifdef CONFIG_MCORE_NETFILTER
		if (fp_shared->fp_blade_id != fp_shared->fp_nf_ct_bladeid)
			master_bladeid = fp_shared->fp_nf_ct_bladeid;
#ifdef CONFIG_MCORE_1CP_XFP
		if (!fp_shared->fp_nf_ct_bladeid &&
		    fp_shared->fp_blade_id != fp_shared->cp_blade_id)
			master_bladeid = fp_shared->cp_blade_id;
#endif
#endif
		break;
	default:
		goto end;
		break;
	}
#endif /* CONFIG_MCORE_MULTIBLADE */

	if (!master_bladeid)
		max_size = ifmtu < mbuf_max_data_size ? ifmtu : mbuf_max_data_size;
#ifdef CONFIG_MCORE_MULTIBLADE
	else {
		uint32_t output_mtu = __fp_ifuid2ifnet(fp_shared->fpib_ifuid)->if_mtu;
		max_size = output_mtu < mbuf_max_data_size ? output_mtu : mbuf_max_data_size;
	}
#endif

	/*
	 * Max entries in a message (message size must be < MTU)
	 * We suppose that output_mtu will never change.
	 */
	max_entries = (max_size
		       - sizeof(struct fp_ether_header)
		       - sizeof(struct fptunhdr)
		       - sizeof(struct fphitflagshdr))
		      / hf_size;

	while (sent_entries < param->hfp_max_sent &&
	       scanned_entries < param->hfp_max_scanned)
	{
		uint32_t message_entries = 0;
		uint32_t limit = (max_entries + 1 < param->hfp_max_sent - sent_entries) ?
			max_entries + 1 : param->hfp_max_sent - sent_entries;

		while (message_entries < limit &&
		       scanned_entries < param->hfp_max_scanned)
		{
			void *vhf_entry;
			void *entry;

			switch (param->hfp_type) {
			case HF_ARP:
				entry = hitflags_arp_getnext(&scanned_entries,
						param->hfp_max_scanned);
				break;
#ifdef CONFIG_MCORE_IPV6
			case HF_NDP:
				entry = hitflags_ndp_getnext(&scanned_entries,
						param->hfp_max_scanned);
				break;
#endif
#ifdef CONFIG_MCORE_NF_CT
			case HF_CT:
				entry = hitflags_ct_getnext(&scanned_entries,
						param->hfp_max_scanned);
				break;
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
			case HF_CT6:
				entry = hitflags_ct6_getnext(&scanned_entries,
						param->hfp_max_scanned);
				break;
#endif
			default:
				entry = NULL;
				break;
			}

			if (entry == NULL)
				break;

			if (m == NULL) {
				m = m_alloc();
				if (unlikely(m == NULL)) {
					TRACE_HF_SYNC(FP_LOG_CRIT, "fail to allocate a new packet");
					goto end;
				}

				/* There should be enough headroom for:
				 *  - struct fp_ether_header
				 *  - struct fptunhdr
				 *  - struct fphitflagshdr
				 */
				hf_hdr = (struct fphitflagshdr *)m_prepend(m, sizeof(struct fphitflagshdr));
				if (hf_hdr == NULL) {
					TRACE_HF_SYNC(FP_LOG_ERR, "m_prepend() fails for hf_hdr");
					m_freem(m);
					goto end;
				}
				hf_hdr->type = param->hfp_type;
				hf_hdr->count = 0;
			}

			vhf_entry = m_append(m, hf_size);
			if (vhf_entry == NULL) {
				TRACE_HF_SYNC(FP_LOG_ERR, "m_append() fails, send the current message");
				if (message_entries == 0) {
					/*
					 * This case should never happen. It means that
					 * m_append() has failed for the first hf_entry.
					 * Let's re-try on the next timer event.
					 */
					m_freem(m);
					goto end;
				}
				break;
			}

			switch (param->hfp_type) {
			case HF_ARP:
			{
				struct fphitflagsarp *hf_arp;
				fp_nh4_entry_t *nh4;

				hf_arp= (struct fphitflagsarp *)vhf_entry;
				nh4 = (fp_nh4_entry_t *)entry;

				hf_arp->ifuid = nh4->nh.nh_ifuid;
				hf_arp->ip_addr = nh4->nh_gw;
				nh4->nh.nh_hitflag = 0;

				break;
			}
#ifdef CONFIG_MCORE_IPV6
			case HF_NDP:
			{
				struct fphitflagsndp *hf_ndp;
				fp_nh6_entry_t *nh6;

				hf_ndp = (struct fphitflagsndp *)vhf_entry;
				nh6 = (fp_nh6_entry_t *)entry;

				hf_ndp->ifuid = nh6->nh.nh_ifuid;
				memcpy(hf_ndp->ip6_addr,
				       nh6->nh_gw.fp_s6_addr,
				       sizeof (nh6->nh_gw.fp_s6_addr));
				nh6->nh.nh_hitflag = 0;

				break;
			}
#endif
#ifdef CONFIG_MCORE_NF_CT
			case HF_CT:
			{
				struct fphitflagsentry *hf_entry;
				struct fp_nfct_tuple_h *tuple;

				tuple = &((struct fp_nfct_entry *)entry)->tuple[FP_NF_IP_CT_DIR_ORIGINAL];

				hf_entry = (struct fphitflagsentry *)vhf_entry;
				hf_entry->src = tuple->src;
				hf_entry->dst = tuple->dst;
				hf_entry->sport = tuple->sport;
				hf_entry->dport = tuple->dport;
#ifdef CONFIG_MCORE_VRF
				hf_entry->vrfid = tuple->vrfid;
#else
				hf_entry->vrfid = 0;
#endif
				hf_entry->proto = tuple->proto;
				hf_entry->dir = tuple->dir;

				((struct fp_nfct_entry *)entry)->flag &= ~FP_NFCT_FLAG_UPDATE;

				break;
			}
#ifdef CONFIG_MCORE_NETFILTER_IPV6
			case HF_CT6:
			{
				struct fphitflags6entry *hf_entry;
				struct fp_nf6ct_tuple_h *tuple;

				tuple = &((struct fp_nf6ct_entry *)entry)->tuple[FP_NF_IP_CT_DIR_ORIGINAL];

				hf_entry = (struct fphitflags6entry *)vhf_entry;
				memcpy(&hf_entry->src, &tuple->src, sizeof(struct fp_in6_addr));
				memcpy(&hf_entry->dst, &tuple->dst, sizeof(struct fp_in6_addr));
				hf_entry->sport = tuple->sport;
				hf_entry->dport = tuple->dport;
#ifdef CONFIG_MCORE_VRF
				hf_entry->vrfid = tuple->vrfid;
#else
				hf_entry->vrfid = 0;
#endif
				hf_entry->proto = tuple->proto;
				hf_entry->dir = tuple->dir;

				((struct fp_nf6ct_entry *)entry)->flag &= ~FP_NFCT_FLAG_UPDATE;

				break;
			}
#endif /* CONFIG_MCORE_NETFILTER_IPV6 */
#endif /* CONFIG_MCORE_NF_CT */
			}
			message_entries++;

			TRACE_HF_SYNC(FP_LOG_DEBUG, "filling packet (type: %u) - "
					"scanned_entries=%d, message_entries=%d", param->hfp_type,
					scanned_entries, message_entries);
		}

		if (message_entries == 0)
			break;

		sent_entries += message_entries;
		hf_hdr->count = htonl(message_entries);

		TRACE_HF_SYNC(FP_LOG_INFO, "call hitflags_pkt_send() (%u entries)", message_entries);
		hitflags_pkt_send(master_bladeid, m);
		m = NULL;
		hf_hdr = NULL;
	}

end:
	/* Reschedule the timer */
	callout_reset(&param->hfp_callout, param->hfp_period, hitflags_send, param);
	return;
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

static int parse_mac(char *buf, uint8_t *result)
{
	int n = sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&result[0], &result[1], &result[2],
			&result[3], &result[4], &result[5]);

	return (n != 6);
}

static void usage(void)
{
	printf("usage: hitflagsd [-hFd] [-i <interface name>] [-m destination mac] [-Z <file>]\n");
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

	rc = has_init(HA6W_COMP_HITFLAGSD, &hitflags_has, srvname, ac, av,
			HAS_NOAUTO_READY, NULL);
	if (rc == HA6W_RESULT_ERROR) {
		syslog(LOG_ERR, "Can not initialize High Availability support\n");
		return -1;
	}

	event_set(&has_event, hitflags_has->sock, EV_READ | EV_PERSIST,
			has_handler_event, hitflags_has);
	if (event_add(&has_event, NULL)) {
		has_exit(hitflags_has);
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
		has_exit(hitflags_has);
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

	while ((ch = getopt(ac, av, "hi:fdm:Z:")) != EOF) {
		switch(ch) {
		case 'h':
			usage();
			break;
		case 'f':
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

	openlog ("hitflagsd", LOG_NDELAY | LOG_PID | (debug ? LOG_PERROR : 0), LOG_DAEMON);

	if (!f_foreground) {
		if (daemon(1, 1) < 0)
			err(1, "daemon");
	}

	if (socket_init() < 0)
		return -1;

	if (mtu_init() < 0)
		return -1;

	event_init();

#ifdef HA_SUPPORT
	if (has_event_init(has_srvname, ac, av) < 0)
		return -1;
#endif

	signal_set (&sigterm, SIGTERM, catch_sig, (void *)SIGTERM);
	signal_add (&sigterm, NULL);

#ifdef HA_SUPPORT
	hitflags_has->ready = 1;
	has_ready(hitflags_has);
#endif

	callout_init(&hitflagsd_ready_handler);
	fp_hitflags_start();

	event_dispatch();

#ifdef HA_SUPPORT
	has_exit(hitflags_has);
#endif

	return 0;
}
