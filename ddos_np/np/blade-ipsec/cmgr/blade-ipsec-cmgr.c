/*
 * Copyright 2013 6WIND S.A.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>

#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/if.h>

#include <linux/xfrm.h>

#include "blade-ipsec.h"

#include "fpc.h"
#include "cm_sock_pub.h"
#include "cm_netlink.h"
#include "cm_pub.h"
#include "cm_plugin.h"
#include "cm_ipsec_pub.h"
#include "genl_base.h"

static uint32_t blade_ipsec_nl_stats[BLADE_IPSEC_C_MAX];

static void blade_ipsec_init(struct nlsock *cmn);
static int blade_ipsec_nl_recv(struct nl_msg *msg, void *arg);
static void blade_ipsec_nl_parse(struct nlmsghdr *nlh, u_int32_t sock_vrfid);

/* cache manager registration */
static struct nlsock_hooks blade_ipsec_nlsock_hooks = {
	.name = "xfrm-migrate",
	.init = blade_ipsec_init,
	.destroy = cm_genl_destroy,
	/* we don't dump migration infos, dumping xfrm sa is enough */
	.dump = NULL,
	.recv = blade_ipsec_nl_recv,
	.stats = blade_ipsec_nl_stats,
	.size = CM_ARRAY_SIZE(blade_ipsec_nl_stats),
};

static void blade_ipsec_cm_init(void) __attribute__((constructor));
void blade_ipsec_cm_init(void)
{
	if (cm_nlsock_hooks_register(&blade_ipsec_nlsock_hooks) == -1)
		syslog(LOG_ERR, "Can't register %s module\n",
		       blade_ipsec_nlsock_hooks.name);
	else
		syslog(LOG_INFO, "%s module loaded\n",
		       blade_ipsec_nlsock_hooks.name);
}

/* socket initialization */
static void blade_ipsec_init(struct nlsock *cmn)
{
	cm_genl_init(cmn, BLADE_IPSEC_FAMILY_NAME, BLADE_IPSEC_FAMILY_NAME);
}

/* build message for fpm and send it */
static int cm2cp_ipsec_sa_migrate (u_int32_t cookie, struct cm_ipsec_sa *sa)
{
	struct cp_hdr *hdr;
	struct cp_ipsec_sa_migrate *sawin;
	int len;

	len = sizeof (*sawin);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_type = htonl (CMD_IPSEC_SA_MIGRATE);
	hdr->cphdr_cookie = htonl (cookie);

	sawin = (struct cp_ipsec_sa_migrate *)(hdr + 1);

	sawin->family   = sa->family;
	sawin->proto    = sa->proto;
	sawin->spi      = sa->spi;
	sawin->daddr    = sa->daddr;
	sawin->gap      = htonl(sa->gap);
	sawin->vrfid    = htonl(sa->vrfid);
	sawin->output_blade = sa->output_blade;

	post_msg (hdr);
	return 0;
}

int cm2cp_ipsec_sa_bulk_migrate (u_int32_t cookie, uint8_t mig_type, uint8_t dst_output_blade, uint32_t gap, char data[128])
{
	struct cp_hdr *hdr;
	struct cp_ipsec_sa_bulk_migrate *samig;
	int len;

	len = sizeof (*samig);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_type = htonl (CMD_IPSEC_SA_BULK_MIGRATE);
	hdr->cphdr_cookie = htonl (cookie);

	samig = (struct cp_ipsec_sa_bulk_migrate *)(hdr + 1);

	samig->mig_type = mig_type;
	samig->dst_output_blade = dst_output_blade;
	samig->gap = htonl(gap);
	memcpy(samig->data, data, sizeof(samig->data));

	post_msg (hdr);
	return 0;
}

/* netlink dispatch function */
int blade_ipsec_nl_recv(struct nl_msg *msg, void *arg)
{
	struct nlsock *s = arg;
	struct nlmsghdr *n = nlmsg_hdr(msg);
	struct genlmsghdr *ghdr;

	ghdr = NLMSG_DATA(n);

	CM_INCREASE_NL_STATS(s, ghdr->cmd);

	switch(ghdr->cmd) {
	case BLADE_IPSEC_C_MIGRATE:
		blade_ipsec_nl_parse(n, s->vrfid);
		break;
	default:
		break;
	}

	return 0;
}

/* netlink parse function */
void blade_ipsec_nl_parse(struct nlmsghdr *nlh, u_int32_t sock_vrfid)
{
	struct nlattr *tb[BLADE_IPSEC_A_MAX + 1];
	struct cm_ipsec_sa sa;
	u_int32_t gap;
	u_int8_t fpid;
	u_int8_t type;
	uint32_t *pvrfid = NULL;
	int err;

	err = cm_genlmsg_parse(nlh, 0, tb, BLADE_IPSEC_A_MAX, MSG_FAMILY_BLADE);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__,
		       nl_geterror(err));
		return;
	}

	type = *(u_int8_t *)nla_data(tb[BLADE_IPSEC_A_TYPE]);
	fpid = *(u_int8_t *)nla_data(tb[BLADE_IPSEC_A_DST_FP]);
	gap = *(u_int32_t *)nla_data(tb[BLADE_IPSEC_A_GAP]);

	switch (type) {
	case BLADE_IPSEC_MIG_SINGLE:
	{
		struct xfrm_usersa_id *p;

		if (!tb[BLADE_IPSEC_A_SA_ID])
			return;

		p = nla_data(tb[BLADE_IPSEC_A_SA_ID]);

		if (((p->family != AF_INET) && (p->family != AF_INET6)) ||
		    ((p->proto != IPPROTO_AH) && (p->proto != IPPROTO_ESP)))
			return;

		if (cm_get_config(CONFIG_PORTS_CACHEMGR_NETNS))
			pvrfid = &sock_vrfid;
		else if (tb[BLADE_IPSEC_A_VRFID])
			pvrfid = nla_data(tb[BLADE_IPSEC_A_VRFID]);

		memset (&sa, 0, sizeof(sa));
		sa.family  = p->family;
		memcpy(&sa.daddr, &p->daddr, sizeof(sa.daddr));
		sa.spi    = p->spi;
		sa.proto  = p->proto;
		sa.vrfid  = pvrfid ? *pvrfid : 0;
		sa.gap    = gap;
		sa.output_blade = fpid;

		cm2cp_ipsec_sa_migrate(nlh->nlmsg_seq, &sa);

		break;
	}
	case BLADE_IPSEC_MIG_BULK_BY_FP:
	{
		uint8_t *src_fp;

		if (!tb[BLADE_IPSEC_A_SRC_FP])
			return;

		src_fp = (u_int8_t *)nla_data(tb[BLADE_IPSEC_A_SRC_FP]);
		cm2cp_ipsec_sa_bulk_migrate(nlh->nlmsg_seq, CM_BULK_MIGRATE_BY_BLADE_ID, fpid,
					    gap, (void*)src_fp);

		break;
	}
	default:
		syslog(LOG_ERR, "%s: unknown migration type %d\n",
			__FUNCTION__, type);
		break;
	}
}
