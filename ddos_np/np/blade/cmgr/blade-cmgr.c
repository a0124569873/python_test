/*
 * Copyright 2013 6WIND S.A.
 */

#include <inttypes.h>
#include <sys/types.h>
#include <sys/errno.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>

#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <linux/if_link.h>
#include <linux/if_tunnel.h>

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/mroute.h>
#include <linux/mroute6.h>
#include <linux/filter.h>
#ifdef RTM_NEWNETCONF
#include <linux/netconf.h>
#endif
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <linux/sockios.h>

#include <blade.h>

#include "fpc.h"
#include "cm_sock_pub.h"
#include "cm_netlink.h"
#include "cm_pub.h"
#include "cm_plugin.h"
#include "cm_ipsec_pub.h"
#include "genl_base.h"

static uint32_t cm_nlblade_stats[BLADE_C_MAX];

static int
cm2cp_blade_create(u_int32_t cookie, u_int32_t cmd, u_int8_t id, u_int8_t flags,
                   u_int8_t *mac)
{
	struct cp_hdr *hdr;
	struct cp_blade_create *cbc;
	int len = sizeof(struct cp_blade_create);

	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	cbc = (struct cp_blade_create*)(hdr + 1);

	cbc->cpblade_id = id;    /* KERNEL interface identifier  */
	cbc->cpblade_flags = flags;    /* KERNEL interface identifier  */
	memcpy(cbc->cpblade_mac, mac, sizeof(cbc->cpblade_mac));

	if (cmd == BLADE_C_FP_DEL)
		hdr->cphdr_type = htonl (CMD_BLADE_DELETE);
	else
		hdr->cphdr_type = htonl (CMD_BLADE_CREATE);

	post_msg (hdr);
	return 0;
}

static void
cm_nl_blade(struct nlmsghdr * nlh, u_int32_t sock_vrfid)
{
	struct genlmsghdr *ghdr;
	int err;
	struct nlattr *tb[BLADE_A_FP_MAX + 1];
	struct blade_fpinfo *fp;

	ghdr = genlmsg_hdr(nlh);
	err = cm_genlmsg_parse(nlh, 0, tb, BLADE_A_FP_MAX, MSG_FAMILY_BLADE);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__,
		       nl_geterror(err));
		return;
	}

	fp = ((struct blade_fpinfo *) nla_data(tb[BLADE_A_FP_INFO]));

	if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
		syslog(LOG_ERR,
		       "    fp=%hu address=%02x:%02x:%02x:%02x:%02x:%02x\n",
		       fp->id, fp->mac[0], fp->mac[1], fp->mac[2],
		       fp->mac[3], fp->mac[4], fp->mac[5]);

	cm2cp_blade_create(nlh->nlmsg_seq, ghdr->cmd, fp->id, 0, fp->mac);
}

static int
cm_nl_blade_recv(struct nl_msg *msg, void *arg)
{
	struct nlsock *s = arg;
	struct nlmsghdr *n = nlmsg_hdr(msg);
	struct genlmsghdr *ghdr;

	/*
	 * This may be called in a close loop, so keep an eye
	 * on Health socket
	 */
	cm_do_has_check_request();

	ghdr = nlmsg_data(n);

	CM_INCREASE_NL_STATS(s, ghdr->cmd);

	switch(ghdr->cmd) {
	case BLADE_C_FP_NEW:
	case BLADE_C_FP_DEL:
	case BLADE_C_FP_DUMP:
		cm_nl_blade(n, s->vrfid);
		break;
	default:
		break;
	}

	return 0;
}

static void
cm_genl_blade_dump(struct nlsock *cmn)
{
	if (genl_send_simple(cmn->sk, cmn->genl_fam->id,
	                     BLADE_C_FP_DUMP, 1,
	                     NLM_F_REQUEST | NLM_F_DUMP) >=0)
		nl_recvmsgs_default(cmn->sk);
}

static void
cm_netlink_blade_init(struct nlsock *cmn)
{
	cm_genl_init(cmn, BLADE_FAMILY_NAME, BLADE_FAMILY_NAME);
}

/* cache manager registration */
static struct nlsock_hooks blade_nlsock_hooks = {
	.name = "blade",
	.init = cm_netlink_blade_init,
	.destroy = cm_genl_destroy,
	.dump = cm_genl_blade_dump,
	.recv = cm_nl_blade_recv,
	.gr_dump = cm_genl_blade_dump,
	.gr_type = CM_GR_TYPE_BLADE,
	.stats = cm_nlblade_stats,
};

static void blade_cm_init(void) __attribute__((constructor));
void blade_cm_init(void)
{
	if (cm_nlsock_hooks_register(&blade_nlsock_hooks) == -1)
		syslog(LOG_ERR, "Can't register %s module\n",
		       blade_nlsock_hooks.name);
	else
		syslog(LOG_INFO, "%s module loaded\n",
		       blade_nlsock_hooks.name);
}
