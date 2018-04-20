/*
 * Copyright(c) 2008 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"

#include "fpn-cksum.h"
#include "netinet/fp-ip.h"
#include "netinet/fp-udp.h"
#include "fp-syslog.h"

static FPN_DEFINE_PER_CORE(int, in_progress);

void fp_syslog(int pri, const char *fmt, ...)
{
	va_list ap;
	struct mbuf *m = NULL;
	struct fp_ip *ip;
	struct fp_udphdr *udp;
	char *sp, *sp0, *ep;
	unsigned int len;

	static unsigned int lo_ifuid = 0;

	if (FPN_PER_CORE_VAR(in_progress))
		return;

	FPN_PER_CORE_VAR(in_progress) = 1;

	/* Read index of loopback interface to initialize mbuf */
	if (!lo_ifuid) {
		fp_ifnet_t *ifp;

		if (fp_shared->conf.w32.magic != FP_SHARED_MAGIC32)
			goto error;
		ifp = fp_getifnetbyname("lo");
		if (ifp == NULL || ifp->if_ifuid == 0)
			goto error;
		lo_ifuid = ifp->if_ifuid;
	}

	m = m_alloc();
	if (m == NULL)
		goto error;
	len = sizeof(*ip)+sizeof(*udp);
	if (m_append(m, len + FP_SYSLOG_MAXBUF) == NULL)
		goto error;
	/* want a contiguous area */
	if (m_headlen(m) < len + FP_SYSLOG_MAXBUF)
		goto error;

	/* IP 127.0.0.1.514 > 127.0.0.1.514: UDP */
	ip = mtod(m, struct fp_ip *);
	ip->ip_v = FP_IPVERSION;
	ip->ip_hl = 5;
	ip->ip_tos = 0;
	ip->ip_off = htons(FP_IP_DF);
	ip->ip_ttl = 1;
	ip->ip_p = FP_IPPROTO_UDP;
	ip->ip_sum = 0;
	ip->ip_dst.s_addr = htonl(0x7f000001);
	ip->ip_src.s_addr = htonl(0x7f000001);
	udp = (struct fp_udphdr *)(ip+1);
	udp->uh_sport = htons(514);
	udp->uh_dport = htons(514);
	udp->uh_sum = 0;

	sp0 = sp = (char *)(udp+1);
	ep = sp + FP_SYSLOG_MAXBUF; /* limit to FP_SYSLOG_MAXBUF bytes */

	sp += snprintf(sp, ep - sp, "<%d>", pri);
	sp += snprintf(sp, ep - sp, "FP#%d:", fpn_get_core_num());
	va_start(ap, fmt);
	sp += vsnprintf(sp, ep - sp, fmt, ap);
	va_end(ap);
	if (sp > (ep - 2))
		sp = ep - 2;
	if (*(sp - 1) != '\n')
		sp += snprintf(sp, ep - sp, "\n");

	len += (sp-sp0);

	/* trim unused space */
	if ((sp-sp0) < FP_SYSLOG_MAXBUF)
		m_trim(m, (FP_SYSLOG_MAXBUF-(sp-sp0)));

	ip->ip_len = htons(len);
	ip->ip_sum = fpn_ip_hdr_cksum(ip, sizeof(struct fp_ip));

	udp->uh_ulen = htons(len - sizeof(*ip));
	udp->uh_sum = fpn_in4_l4cksum(m);
	if (udp->uh_sum == 0)
		udp->uh_sum = 0xFFFF;

	m_priv(m)->exc_type = FPTUN_IPV4_OUTPUT_EXCEPT;
	m_priv(m)->exc_class = 0;
	m_priv(m)->exc_proto = htons(FP_ETHERTYPE_IP);
	m_priv(m)->ifuid = lo_ifuid;
	set_mvrfid(m, 0); /* ifnet[lo_ifuid].if_vrfid */
	m_tag_reset(m);
	if (fp_prepare_exception(m, FPTUN_EXC_SP_FUNC) == FP_NONE)
		fp_sp_exception(m);
	else
		goto error;

done:
	FPN_PER_CORE_VAR(in_progress) = 0;
	return;

error:
	if (m)
		m_freem(m);
	goto done;
}
