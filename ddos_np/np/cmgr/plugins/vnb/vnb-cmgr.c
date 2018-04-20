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
#include <netgraph/ng_message.h>

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

#include <netgraph_linux/ng_netlink.h>
#include <netgraph.h>

/* #define CM_DEBUG_VNB_DUMP */

static uint32_t cm_nlvnb_stats[VNB_C_MAX];

static int cm_send_vnb_msghdr(u_int32_t cookie, struct cp_vnb_msghdr *local_vnbh, char *arg, char *path, u_int32_t type)
{
	struct cp_hdr *hdr;
	struct cp_vnb_msghdr *vnbh;
	char *cp;
	int len;

	len = sizeof(*vnbh) + local_vnbh->vnbh_arglen + local_vnbh->vnbh_pathlen;
	CM_MALLOC(hdr, len + sizeof(struct cp_hdr));

	hdr->cphdr_type = htonl(type);
	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_cookie = htonl (cookie);

	vnbh = (struct cp_vnb_msghdr *)(hdr + 1);
	vnbh->vnbh_typecookie = htonl(local_vnbh->vnbh_typecookie);
	vnbh->vnbh_cmd = htonl(local_vnbh->vnbh_cmd);
	vnbh->vnbh_seqnum = htonl(local_vnbh->vnbh_seqnum);
	vnbh->vnbh_arglen = htons(local_vnbh->vnbh_arglen);
	vnbh->vnbh_pathlen = htons(local_vnbh->vnbh_pathlen);
	vnbh->vnbh_cpnodeid = htonl(local_vnbh->vnbh_cpnodeid);

	cp = (char *)(vnbh + 1);
	if (local_vnbh->vnbh_arglen) {
		memcpy(cp, arg, local_vnbh->vnbh_arglen);
		cp += local_vnbh->vnbh_arglen;
	}
	if (local_vnbh->vnbh_pathlen) {
		memcpy(cp, path, local_vnbh->vnbh_pathlen);
		cp += local_vnbh->vnbh_pathlen;
	}

	post_msg(hdr);

	return 0;
}

static inline uint32_t vnb_nl2cm(uint32_t attr)
{
	switch(attr) {
	case VNBA_DUMP_NODE:
		return CMD_VNB_NODE;
	case VNBA_DUMP_NODE_PRIV:
		return CMD_VNB_NODE_PRIV;
	case VNBA_DUMP_HOOK:
		return CMD_VNB_HOOK;
	case VNBA_DUMP_HOOK_PRIV:
		return CMD_VNB_HOOK_PRIV;
	case VNBA_DUMP_HOOK_LIST:
	default:
		break;
	}

	return CMD_VNB_NONE;
}

static inline void vnb_nl2net(struct cp_vnb_dump_attr *attr)
{
	switch(ntohl(attr->type)) {
	case CMD_VNB_NODE:
	{
		struct ng_nl_node *nlnode = (struct ng_nl_node *) attr->data;
		nlnode->id = htonl(nlnode->id);
		nlnode->numhooks = htonl(nlnode->numhooks);
		break;
	}
	case CMD_VNB_NODE_PRIV:
	{
		struct ng_nl_nodepriv *nlnodepriv = (struct ng_nl_nodepriv *) attr->data;
		nlnodepriv->data_len = htonl(nlnodepriv->data_len);
		break;
	}
	case CMD_VNB_STATUS:
	{
		struct ng_nl_status *nlstatus = (struct ng_nl_status *) attr->data;
		nlstatus->count = htonl(nlstatus->count);
		nlstatus->total_count = htonl(nlstatus->total_count);
		break;
	}
	case CMD_VNB_HOOK:
	{
		struct ng_nl_hook *nlhook = (struct ng_nl_hook *)attr->data;
		nlhook->peernodeid = htonl(nlhook->peernodeid);
		break;
	}
	case CMD_VNB_HOOK_PRIV:
	{
		struct ng_nl_hookpriv *nlhookpriv = (struct ng_nl_hookpriv *) attr->data;
		nlhookpriv->data_len = htonl(nlhookpriv->data_len);
		break;
	}
	default:
		break;
	}

	return;
}

#ifdef CM_DEBUG_VNB_DUMP
static inline void dump_cm_vnb_attr(struct cp_vnb_dump_attr *attr)
{
	switch(ntohl(attr->type)) {
	case CMD_VNB_NODE:
	{
		struct ng_nl_node *nlnode = (struct ng_nl_node *)attr->data;
		fprintf(stderr, " node %s[%x] - %s - %u hooks\n",
			nlnode->name, ntohl(nlnode->id), nlnode->type,
			ntohl(nlnode->numhooks));
		break;
	}
	case CMD_VNB_NODE_PRIV:
	{
		struct ng_nl_nodepriv *nlnodepriv = (struct ng_nl_nodepriv *)attr->data;
		fprintf(stderr, " node priv - size %d\n",
			ntohl(nlnodepriv->data_len));
		break;
	}
	case CMD_VNB_STATUS:
	{
		struct ng_nl_status *nlstatus = (struct ng_nl_status *) attr->data;
		fprintf(stderr, " status message version=%d\n", nlstatus->version);
		break;
	}
	case CMD_VNB_HOOK:
	{
		struct ng_nl_hook *nlhook = (struct ng_nl_hook *)attr->data;
		fprintf(stderr, "    hook %s <-> [%x]:%s\n",
			nlhook->name, ntohl(nlhook->peernodeid), nlhook->peername);
		break;
	}
	case CMD_VNB_HOOK_PRIV:
	{
		struct ng_nl_hookpriv *nlhookpriv = (struct ng_nl_hookpriv *) attr->data;
		fprintf(stderr, "     hook priv - size %d\n",
			ntohl(nlhookpriv->data_len));
		break;
	}
	default:
		break;
	}

	return;
}
#endif

static size_t vnb_dump_get_size(struct nlattr **tb, struct ng_nl_status *nlstatus)
{
	size_t size = 0;
	int i;

	size += CM_ALIGN(sizeof(struct ng_nl_status) +
			 sizeof(struct cp_vnb_dump_attr), 4);

	for (i = 1; i < VNBA_DUMP_MAX + 1; i++) {
		if (tb[i] && vnb_nl2cm(i)) {
			size += CM_ALIGN(nla_len(tb[i]) +
					 sizeof(struct cp_vnb_dump_attr), 4);
		}
	}

	if (tb[VNBA_DUMP_HOOK_LIST]) {
		struct nlattr *hook_list = tb[VNBA_DUMP_HOOK_LIST];
		struct ng_nl_node *nlnode = nla_data(tb[VNBA_DUMP_NODE]);
		/* each hook can have hook and hook_priv, hence '* 2' */
		struct nlattr *tb_hl[nlnode->numhooks * 2 + 1];
		uint32_t hook_attr_count;

		hook_attr_count = cm_nl_parse_nlattr_byindex(tb_hl,
							     nlnode->numhooks * 2,
							     nla_data(hook_list),
							     nla_len(hook_list),
							     MSG_FAMILY_VNB_DUMP);

		for (i = 0; i < hook_attr_count; i++) {
			struct nlattr *nla = tb_hl[i];

			if (vnb_nl2cm(nla->nla_type))
				size += CM_ALIGN(nla_len(nla) +
						 sizeof(struct cp_vnb_dump_attr), 4);
		}
	}

	return size;
}

#define VNB_NL2CM_ATTR(nl_attr, cm_attr, cm_type, msg)			\
{									\
	cm_attr->type = htonl(cm_type);					\
	cm_attr->len = htonl(nla_len(nl_attr));			\
	memcpy(cm_attr->data, nla_data(nl_attr), nla_len(nl_attr)); \
	vnb_nl2net(cm_attr);						\
	msg->attr_count++;						\
};

size_t vnb_dump_add_attrs(char *buf, struct nlattr **tb,
			  struct cp_vnb_dump_msghdr *dump_msg,
			  struct ng_nl_status *nlstatus)
{
	size_t offset = 0;
	int i;
	struct cp_vnb_dump_attr *attr;

	/* add ng_nl_status header */
	attr = (struct cp_vnb_dump_attr *)(buf + offset);
	attr->type = htonl(CMD_VNB_STATUS);
	attr->len = htonl(sizeof(struct ng_nl_status));
	memcpy(attr->data, nlstatus, sizeof(struct ng_nl_status));
	vnb_nl2net(attr);
	dump_msg->attr_count++;
	offset += CM_ALIGN(sizeof(struct ng_nl_status) +
			   sizeof(struct cp_vnb_dump_attr), 4);
#ifdef CM_DEBUG_VNB_DUMP
	dump_cm_vnb_attr(attr);
#endif

	/* add netlink attributes */
	for (i = 1; i < VNBA_DUMP_MAX + 1; i++) {
		if (tb[i] && vnb_nl2cm(i)) {
			attr = (struct cp_vnb_dump_attr *)(buf + offset);
			VNB_NL2CM_ATTR(tb[i], attr, vnb_nl2cm(i), dump_msg);
#ifdef CM_DEBUG_VNB_DUMP
			dump_cm_vnb_attr(attr);
#endif
			offset += CM_ALIGN(nla_len(tb[i]) + sizeof(*attr), 4);
		}
	}

	if (tb[VNBA_DUMP_HOOK_LIST]) {
		struct nlattr *hook_list = tb[VNBA_DUMP_HOOK_LIST];
		struct ng_nl_node *nlnode = nla_data(tb[VNBA_DUMP_NODE]);
		/* each hook can have hook and hook_priv, hence '* 2' */
		struct nlattr *tb_hl[nlnode->numhooks * 2 + 1];
		uint32_t hook_attr_count;

		hook_attr_count = cm_nl_parse_nlattr_byindex(tb_hl,
							     nlnode->numhooks * 2,
							     nla_data(hook_list),
							     nla_len(hook_list),
							     MSG_FAMILY_VNB_DUMP);

		for (i = 0; i < hook_attr_count; i++) {
			struct nlattr *nla = tb_hl[i];

			if (vnb_nl2cm(nla->nla_type)) {
				struct cp_vnb_dump_attr *attr;

				attr = (struct cp_vnb_dump_attr *)(buf + offset);
				VNB_NL2CM_ATTR(nla, attr, vnb_nl2cm(nla->nla_type), dump_msg);
#ifdef CM_DEBUG_VNB_DUMP
				dump_cm_vnb_attr(attr);
#endif
				offset += CM_ALIGN(nla_len(nla) + sizeof(*attr), 4);
			}
		}
	}

	return offset;
}

static int cm_genl_process_dumpvnb(struct nlmsghdr *nlh, u_int32_t sock_vrfid)
{
	struct ng_nl_status *nlstatus;
	struct nlattr *tb[VNBA_DUMP_MAX + 1];
	size_t size = 0;
	struct cp_hdr *hdr;
	size_t offset;
	struct cp_vnb_dump_msghdr *dump_msg;
	int err;

	if (cm_debug_level & CM_DUMP_EXT_NL_RECV) {
		syslog(LOG_DEBUG, "%s: received netlink message\n", __FUNCTION__);
	}

	err = cm_genlmsg_parse(nlh, 0, tb, VNBA_DUMP_MAX, MSG_FAMILY_VNB_DUMP);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return -1;
	}

	nlstatus = (struct ng_nl_status *) nla_data(tb[VNBA_DUMP_STATUS]);

	if (!nlstatus)
		return -1;

	size = vnb_dump_get_size(tb, nlstatus);

	CM_CALLOC(1, hdr, sizeof(struct cp_hdr) +
		  sizeof(struct cp_vnb_dump_msghdr) + size);

	hdr->cphdr_type = htonl(CMD_VNB_DUMP);
	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(size + sizeof(struct cp_vnb_dump_msghdr)) ;
	hdr->cphdr_cookie = htonl(nlh->nlmsg_seq);

	offset = sizeof(struct cp_hdr);

	dump_msg = (struct cp_vnb_dump_msghdr *)(hdr + 1);
	offset += sizeof(struct cp_vnb_dump_msghdr);

	offset += vnb_dump_add_attrs((char *)(dump_msg + 1), tb, dump_msg,
				     nlstatus);

	dump_msg->len = htonl(size);
	dump_msg->attr_count = htonl(dump_msg->attr_count);

	post_msg(hdr);

	return 0;
}

static void cm_genl_process_vnb(struct nlmsghdr *nlh, u_int32_t sock_vrfid)
{
	struct ng_msghdr *msg;
	struct nlattr *tb[VNBA_MAX + 1];
	struct cp_vnb_msghdr vnbh;
	char *arg = NULL;
	char *path = NULL;
	u_int32_t type;
	int err;

	err = cm_genlmsg_parse(nlh, 0, tb, VNBA_MAX, MSG_FAMILY_VNB);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

	msg = (struct ng_msghdr *) nla_data(tb[VNBA_MSGHDR]);
	if (!msg) {
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
			syslog(LOG_DEBUG, "%s: received netlink message: ignored\n",
			       __FUNCTION__);
		return;
	}

	if (cm_debug_level & CM_DUMP_EXT_NL_RECV) {
		syslog(LOG_DEBUG, "%s: received netlink message: typecookie=%d cmd=%d\n",
				__FUNCTION__, msg->typecookie, msg->cmd);
	}

	memset(&vnbh, 0, sizeof(vnbh));
	vnbh.vnbh_typecookie = msg->typecookie;
	vnbh.vnbh_cmd = msg->cmd;
	vnbh.vnbh_cpnodeid = msg->nodeid;

	if (tb[VNBA_MSGPATH]) {
		vnbh.vnbh_pathlen = tb[VNBA_MSGPATH]->nla_len;
		path = nla_data(tb[VNBA_MSGPATH]);
	}

	if (tb[VNBA_SEQNUM])
		vnbh.vnbh_seqnum = *(u_int32_t *)nla_data(tb[VNBA_SEQNUM]);

	if (tb[VNBA_MSGDATA]) {
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
			syslog(LOG_DEBUG, "%s: netlink message VNBA_MSGDATA received\n", __FUNCTION__);
		vnbh.vnbh_arglen = msg->arglen;
		arg = nla_data(tb[VNBA_MSGDATA]);
		type = CMD_VNB_MSGHDR;
	} else if (tb[VNBA_MSGASCIIDATA]) {
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
			syslog(LOG_DEBUG, "%s: netlink message VNBA_MSGASCIIDATA received\n", __FUNCTION__);
		vnbh.vnbh_arglen = msg->arglen;
		arg = nla_data(tb[VNBA_MSGASCIIDATA]);
		type = CMD_VNB_ASCIIMSG;
	} else {
		vnbh.vnbh_arglen = 0;
		type = CMD_VNB_ASCIIMSG;
	}
	if (cm_send_vnb_msghdr(nlh->nlmsg_seq, &vnbh, arg, path, type)) {
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
			syslog(LOG_DEBUG, "%s: unable to send VNB msghdr\n", __FUNCTION__);
	}
}

static void cm_netlink_vnb_init (struct nlsock *cmn)
{
	cm_genl_init(cmn, "VNB", "VNB");
}

static int cm_nl_vnb_recv(struct nl_msg *msg, void *arg)
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
	case VNB_C_DUMP:
		cm_genl_process_dumpvnb(n, s->vrfid);
		break;
	case VNB_C_NEW:
		cm_genl_process_vnb(n, s->vrfid);
		break;
	default:
		break;
	}

	return 0;
}

static void
cm_genl_vnb_dump(struct nlsock *cmn)
{
	if (genl_send_simple(cmn->sk, cmn->genl_fam->id,
	                     VNB_C_DUMP, 1, NLM_F_REQUEST | NLM_F_DUMP) >= 0)
		nl_recvmsgs_default(cmn->sk);
}

static const char *
vnb_type2str(u_int16_t type)
{
	static char dflt[] = "VNBM_[DDDDD]";
	char * str;

	switch(type) {
	_PF(VNB_C_DUMP)
	_PF(VNB_C_NEW)
	default:
		snprintf(dflt, sizeof(dflt), "VNBM_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}

static void
vnb_parse_afspec(struct nlattr **afspec, struct cm_iface *ifp, int newlink)
{
	if (!afspec[AF_NETGRAPH])
		return;

	struct nlattr *vnb_afspec[IFLA_VNB_MAX+1];
	struct nlattr *attr = afspec[AF_NETGRAPH];

	cm_nl_parse_nlattr(vnb_afspec, IFLA_VNB_MAX, nla_data(attr),
	                   nla_len(attr), MSG_FAMILY_IFACE);

	if (newlink) {
		if (vnb_afspec[IFLA_VNB_NODEID])
			ifp->vnb_nodeid = *(u_int32_t *)
				nla_data(vnb_afspec[IFLA_VNB_NODEID]);
	} else {
		if (vnb_afspec[IFLA_VNB_NODE_REG])
			ifp->vnb_keep_node = 1;
	}
}

/* cache manager registration */
static struct nlsock_hooks vnb_nlsock_hooks = {
	.name = "vnb",
	.init = cm_netlink_vnb_init,
	.destroy = cm_genl_destroy,
	.dump = cm_genl_vnb_dump,
	.recv = cm_nl_vnb_recv,
	.gr_dump = cm_genl_vnb_dump,
	.gr_type = CM_GR_TYPE_VNB,
	.stats = cm_nlvnb_stats,
	.size = CM_ARRAY_SIZE(cm_nlvnb_stats),
	.type2str = vnb_type2str,
	.parse_afspec = vnb_parse_afspec,
};

static void vnb_cm_init(void) __attribute__((constructor));
void vnb_cm_init(void)
{
	if (cm_nlsock_hooks_register(&vnb_nlsock_hooks) == -1)
		syslog(LOG_ERR, "Can't register %s module\n",
		       vnb_nlsock_hooks.name);
	else
		syslog(LOG_INFO, "%s module loaded\n",
		       vnb_nlsock_hooks.name);
}
