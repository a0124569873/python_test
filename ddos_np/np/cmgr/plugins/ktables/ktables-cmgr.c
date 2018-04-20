/*
 * Copyright (c) 2014 6WIND
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include <net/if.h>
#include <netinet/in.h>
#include <linux/types.h> /* for 2.4 kernel */
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/attr.h>
#include <netlink/msg.h>
#include <netlink/route/rtnl.h>
#include <netlink/genl/genl.h>
#include <netlink/netfilter/nfnl.h>

#include "fpc.h"
#include "cm_pub.h"
#include "cm_plugin.h"
#include "cm_netlink.h"
#include "cm_sock_pub.h"
#include "genl_base.h"

#include <ktables.h>

#if 0
#  define DPRINTF(...)	printf(__VA_ARGS__)
#else
#  define DPRINTF(...)
#endif

/**
 * Forge and send a message to fpm
 *
 * @param n
 *   the table index in ktables array
 * @param table
 *   the table value
 * @return
 *   0 on success, an error code otherwise
 */
static int
cm2cp_ktables(u_int32_t cookie, uint32_t n, uint8_t *table)
{
	int		len;
	struct cp_hdr	*hdr;
	struct cp_ktables	*cpk;

	len = sizeof(*cpk);
	CM_CALLOC(1, hdr, len + sizeof(*hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_cookie = htonl (cookie);

	cpk = (struct cp_ktables *)(hdr + 1);
	cpk->n = htonl(n);
	memcpy(cpk->table, table, KTABLES_TABLE_SIZE);
	hdr->cphdr_type = htonl(CMD_KTABLES_SET);
	post_msg(hdr);

	return 0;
}

/**
 * Parse a netlink message received from ktables, and take appropriate actions
 * (i.e. send message to the fast path manager if needed)
 *
 * @param h
 *   A pointer to the received netlink message
 * @return
 *   0 on success, -1 otherwise
 */
static int
cm_genl_parse_msg(struct nlmsghdr *h, struct nlsock *s)
{
	struct nlattr *tb[KT_TYPE_MAX + 1];
	int ret = 0;
	struct attr_table_s     *attr_t;

	ret = genlmsg_parse (h, 0, tb, KT_TYPE_MAX, NULL);
	if (ret < 0)
		return -1;

	if (tb[KT_TYPE_ONE_TABLE]) {
		attr_t = nla_data(tb[KT_TYPE_ONE_TABLE]);
		CM_INCREASE_NL_STATS(s, KT_TYPE_ONE_TABLE);
		DPRINTF("Printing table %d:\n", attr_t->table);
		DPRINTF("  %016llx\n", attr_t->table_value);
		ret = cm2cp_ktables(h->nlmsg_seq, attr_t->table,
		                    attr_t->table_value);
		if (ret)
			return -1;
	}

	if (tb[KT_TYPE_ONE_BYTE_SET]) {
		DPRINTF("unexpected nla_type %d\n", KT_TYPE_ONE_BYTE_SET);
		CM_INCREASE_NL_STATS(s, KT_TYPE_ONE_BYTE_SET);
	}

	return 0;
}

static uint32_t cm_genl_ktables_stats[KT_TYPE_MAX+1];

/*
 * Dump Ktables
 */
static void
cm_genl_ktables_dump(struct nlsock *cmn)
{
	if (genl_send_simple(cmn->sk, cmn->genl_fam->id,
			     KT_CMD_MAP_DUMP, 1,
	                     NLM_F_REQUEST | NLM_F_DUMP) >= 0)
		nl_recvmsgs_default(cmn->sk);
	return;
}

static int cm_genl_ktables_recv(struct nl_msg *msg, void *arg)
{
	struct nlsock *s = arg;
	struct nlmsghdr *h = nlmsg_hdr(msg);

	/*
	 * This may be called in a close loop, so keep an eye
	 * on Health socket
	 */
	cm_do_has_check_request();

	if (cm_debug_level & (CM_DUMP_HDR_NL_RECV |
				CM_DUMP_EXT_NL_RECV |
				CM_DUMP_HEX_NL_RECV)) {
		syslog(LOG_DEBUG, "----------------------------------------"
				"--------------------\n");

		if (cm_debug_level & CM_DUMP_HDR_NL_RECV)
			syslog(LOG_DEBUG, "gen netlink ktables: %s(%d)"
					"#%u len=%hu pid=%u\n",
					rtm_type2str(h->nlmsg_type),
					h->nlmsg_type,
					h->nlmsg_seq, h->nlmsg_len,
					h->nlmsg_pid);
	}

	cm_genl_parse_msg(h, s);

	return 0;
}

static void cm_genl_ktables_init(struct nlsock *cmn)
{
	cm_genl_init(cmn, KT_NL_FAMILY_NAME, KT_NL_GRP_NAME);
}

/* cache manager registration */
static struct nlsock_hooks ktables_nlsock_hooks = {
	.name = "ktables",
	.init = cm_genl_ktables_init,
	.destroy = cm_genl_destroy,
	.dump = cm_genl_ktables_dump,
	.recv    = cm_genl_ktables_recv,
	.gr_dump = cm_genl_ktables_dump,
	.gr_type = 0,
	.stats = cm_genl_ktables_stats,
};

static void ktables_cm_init(void) __attribute__((constructor));
void ktables_cm_init(void)
{
	if (cm_nlsock_hooks_register(&ktables_nlsock_hooks) == -1)
		syslog(LOG_ERR, "Can't register %s module\n",
		       ktables_nlsock_hooks.name);
	else
		syslog(LOG_INFO, "%s module loaded\n",
		       ktables_nlsock_hooks.name);
}
