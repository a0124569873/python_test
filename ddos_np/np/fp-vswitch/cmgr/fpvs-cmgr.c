/*
 * Copyright 2013 6WIND S.A.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/attr.h>

#include "linux/openvswitch.h"
#include "fpvs-cp.h"

#ifndef FP_STANDALONE
#include "cm_sock_pub.h"
#include "fpc.h"
#include "cm_plugin.h"
#include "genl_base.h"
enum {
	FPVS_STATS_VPORT_ADD,
	FPVS_STATS_VPORT_DEL,
	FPVS_STATS_FLOW_ADD,
	FPVS_STATS_FLOW_DEL,

	FPVS_STATS_INVALID,

	FPVS_STATS_MAX
};

extern int cm_disable_nl_ovs_flow;

static uint32_t fpvs_cmgr_stats[FPVS_STATS_MAX];
static int fpvs_nl_recv(struct nl_msg *msg, void *arg);
static int fpvs_nl_timeout(void *arg);
static void fpvs_cm_dump_cb(struct nlsock *cmn);
static void fpvs_cm_init_cb(struct nlsock *cmn);

static struct nlsock_hooks fpvs_nlsock_hooks = {
	.name    = "fp-vswitch",
	.init    = fpvs_cm_init_cb,
	.destroy = cm_genl_destroy,
	.dump    = fpvs_cm_dump_cb,
	.recv    = fpvs_nl_recv,
	.timeout = fpvs_nl_timeout,
	.stats   = fpvs_cmgr_stats,
	.gr_dump = fpvs_cm_dump_cb,
	.gr_type = 0,
};

enum {
	OVS_GENL_DP,
	OVS_GENL_FLOW,
	OVS_GENL_VPORT
};

static const struct genl_family ovs_genl[] = {
	[OVS_GENL_DP] = {
		.name = OVS_DATAPATH_FAMILY,
		.grp.name = OVS_DATAPATH_MCGROUP,
	},
	[OVS_GENL_FLOW] = {
		.name = OVS_FLOW_FAMILY,
		.grp.name = OVS_FLOW_MCGROUP,
	},
	[OVS_GENL_VPORT] = {
		.name = OVS_VPORT_FAMILY,
		.grp.name = OVS_VPORT_MCGROUP,
	},
};
#endif

/* Definitions for parsing OVS netlink messages. */
/* from datapath/datapath.c */
static struct nla_policy ovs_vport_policy[OVS_VPORT_ATTR_MAX + 1] = {
	[OVS_VPORT_ATTR_NAME] = { .type = NLA_STRING, .maxlen = IFNAMSIZ - 1 },
	[OVS_VPORT_ATTR_STATS] = { .maxlen = sizeof(struct ovs_vport_stats) },
	[OVS_VPORT_ATTR_PORT_NO] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_TYPE] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_OPTIONS] = { .type = NLA_NESTED },
};

static struct nla_policy ovs_tunnel_policy[OVS_TUNNEL_ATTR_MAX + 1] = {
	[OVS_TUNNEL_ATTR_DST_PORT] = { .type = NLA_U16 },
};

/* from datapath/datapath.c */
static struct nla_policy ovs_flow_policy[OVS_FLOW_ATTR_MAX + 1] = {
	[OVS_FLOW_ATTR_KEY] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_ACTIONS] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_CLEAR] = { .type = NLA_FLAG },
	/* The kernel never uses OVS_FLOW_ATTR_CLEAR. */
};

/* Send a dump request formatted for OVS datapath netlink families. */
size_t ovsdp_dump_request(struct nlsock *cmn,
			  uint16_t family, uint8_t command,
			  uint32_t dpnum, char **answer)
{
	struct nl_msg *msg;
	struct ovs_header *ovs_hdr;
	void *hdr;
	uint32_t dp_uid;
	int err;

	msg = nlmsg_alloc();
	ovs_hdr = (struct ovs_header *)genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
						   sizeof(struct ovs_header),
						   NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK | NLM_F_ECHO,
						   command, 1);
	ovs_hdr->dp_ifindex = dpnum;

	err = nl_send_auto(cmn->sk, msg);
	if (err < 0) {
		printf("unable to send message: %s\n", nl_geterror(err));
		goto error;
	}

	nl_recvmsgs_default(cmn->sk);
error:
	nlmsg_free(msg);

	return err;
}

/* Send a flush request. */
void ovsdp_flush_request(uint16_t family, uint32_t pid, uint32_t dpnum)
{
	struct nl_msg *msg;
	struct nl_sock *sk;
	struct ovs_header *ovs_hdr;
	void *hdr;
	uint32_t dp_uid;
	int err;

	sk = nl_socket_alloc();
	genl_connect(sk);

	msg = nlmsg_alloc();
	ovs_hdr = (struct ovs_header *)genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
						   sizeof(struct ovs_header), NLM_F_REQUEST,
						   OVS_FLOW_CMD_DEL, 1);
	ovs_hdr->dp_ifindex = dpnum;
	err = nl_send_auto(sk, msg);
	if (err < 0)
		printf("unable to send message: %s\n", nl_geterror(err));
	nlmsg_free(msg);
	nl_socket_free(sk);
}

int fpvs_handle_flow(struct cp_flow_key* key, struct cp_flow_key* mask,
		     struct nlattr* actions, int delete)
{
	int			len;
	struct cp_hdr   	*hdr;
	struct cp_fpvs_flow	*cpfl;
	size_t 			actions_len = 0;
	uint8_t 		*ptr;
	struct nlattr	*nested_actions = NULL;

	if (!delete) {
		actions_len = nla_len(actions);
		nested_actions = (struct nlattr*)nla_data(actions);
	}

	len = sizeof(*key) + sizeof(*mask) + actions_len + sizeof(*cpfl);

	CM_CALLOC(1, hdr, len + sizeof(*hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);

	cpfl = (struct cp_fpvs_flow *)(hdr + 1);
	ptr = (uint8_t*)&cpfl->data;
	if (delete) {
		cpfl->flags = htonl(CM_FPVS_FLOW_DEL);
	} else {
		cpfl->flags = htonl(CM_FPVS_FLOW_ADD);
	}
	cpfl->flow_len = htons(sizeof(*key));
	memcpy(ptr, key, sizeof(*key));
	ptr += sizeof(*key);

	memcpy(ptr, mask, sizeof(*mask));
	ptr += sizeof(*mask);

	if (!delete) {
		cpfl->action_len = htons(actions_len);
		memcpy(ptr, nested_actions, actions_len);
	}

	hdr->cphdr_type = htonl(CMD_FPVS_FLOW);
	post_msg(hdr);

	return 0;
}

/* Parse netlink message for flows. Several message can be concatenated. */
void fpvs_parse_flow(struct nlmsghdr *nlh, int len)
{
	struct genlmsghdr *genlmsghdr = genlmsg_hdr(nlh);
	struct nlattr *attrs[OVS_FLOW_ATTR_MAX + 1];
	int result;
	struct cp_flow_key key, mask;
	size_t attrlen;

	syslog(LOG_INFO, "[FPVS]: %s\n", __func__);

	genlmsg_parse(nlh, sizeof(struct ovs_header),
		      attrs, OVS_FLOW_ATTR_MAX, ovs_flow_policy);

	if (attrs[OVS_FLOW_ATTR_KEY] == NULL) {
		syslog(LOG_INFO, "[FPVS]: key is NULL\n");
		return;
	}

	/* Convert netlink flow attributes to a flow key. */
	attrlen = nla_len(attrs[OVS_FLOW_ATTR_KEY]);
	result = fpvs_parse_nested_flow_key(attrs[OVS_FLOW_ATTR_KEY],
					    &key, 0);
	if (result < 0) {
		syslog(LOG_INFO, "[FPVS]: could not parse flow\n");
		return;
	}

	if (attrs[OVS_FLOW_ATTR_MASK]) {
		result = fpvs_parse_nested_flow_key(attrs[OVS_FLOW_ATTR_MASK], &mask, 0);
		if (result < 0) {
			syslog(LOG_INFO, "[FPVS]: could not parse flow mask\n");
			return;
		}
	} else {
		/* if mask is not present, do exact matching,
		 * tcp flags are never matched, because it would
		 * always fail.
		 */
		memset(&mask, 0xff, sizeof(mask));
		mask.l4.flags = 0;
	}

	if (genlmsghdr->cmd == OVS_FLOW_CMD_NEW) {
		fpvs_handle_flow(/*shared_table, */&key, &mask,
				 attrs[OVS_FLOW_ATTR_ACTIONS],
				 0);
	} else if (genlmsghdr->cmd == OVS_FLOW_CMD_DEL)
		fpvs_handle_flow(&key, &mask, NULL, 1);
}

static inline int fpvs_vport_has_dstport(uint32_t type) {
	return type == OVS_VPORT_TYPE_VXLAN || type == OVS_VPORT_TYPE_LISP;
}

int fpvs_handle_vport(const char* name, uint32_t port, uint32_t type,
		      uint16_t tun_dstport)
{
	int			len;
	struct cp_hdr		*hdr;
	struct cp_fpvs_port	*cpvs;

	len = sizeof(*cpvs);
	CM_CALLOC(1, hdr, len + sizeof(*hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);

	cpvs = (struct cp_fpvs_port *)(hdr + 1);
	cpvs->port_id = htonl(port);
	cpvs->type = htonl(type);
	strncpy(cpvs->ifname, name, IFNAMSIZ);
	cpvs->ifname[IFNAMSIZ-1] = 0;

	if (fpvs_vport_has_dstport(type)) {
		if (tun_dstport == 0) {
			syslog(LOG_ERR, "[FPVS] %s: tunnel vport but no tun_dstport"
					" provided\n", __func__);
			CM_FREE(hdr);
			return -1;
		}

		cpvs->tun_dstport = htons(tun_dstport);
	}

	hdr->cphdr_type = htonl(CMD_FPVS_SET);

	post_msg(hdr);

	return 0;
}

/* Parse netlink message for vports. Several message can be concatenated. */
void fpvs_parse_vport(struct nlmsghdr *nlh, int len)
{
	struct nlattr *attrs[OVS_VPORT_ATTR_MAX + 1];
	struct nlattr *options[OVS_TUNNEL_ATTR_MAX + 1];
	struct genlmsghdr *genlmsghdr = genlmsg_hdr(nlh);
	uint32_t type;
	uint32_t portid;
	const char *name;

	uint16_t tun_dstport = 0;

	syslog(LOG_INFO, "[FPVS]: %s\n", __func__);

	genlmsg_parse(nlh, sizeof(struct ovs_header),
		      attrs, OVS_VPORT_ATTR_MAX, ovs_vport_policy);

	if (attrs[OVS_VPORT_ATTR_TYPE] == NULL) {
		syslog(LOG_INFO, "[FPVS]: type is NULL\n");
		return;
	}

	type = nla_get_u32(attrs[OVS_VPORT_ATTR_TYPE]);
	portid = nla_get_u32(attrs[OVS_VPORT_ATTR_PORT_NO]);
	name = nla_get_string(attrs[OVS_VPORT_ATTR_NAME]);

	if (fpvs_vport_has_dstport(type)) {
		if (nla_parse_nested(options, OVS_TUNNEL_ATTR_MAX,
				     attrs[OVS_VPORT_ATTR_OPTIONS],
				     ovs_tunnel_policy) < 0) {
			syslog(LOG_ERR, "[FPVS]: failed to parse vport options\n");
			return;
		}
		tun_dstport = nla_get_u16(options[OVS_TUNNEL_ATTR_DST_PORT]);
	}

	syslog(LOG_INFO, "[FPVS] Receiving new port - name: %s ID: %u type: %u\n",
	       name, portid, type);

	if (genlmsghdr->cmd == OVS_VPORT_CMD_DEL)
		fpvs_handle_vport(name, FPVS_INVALID_PORT, type, tun_dstport);
	else if (genlmsghdr->cmd == OVS_VPORT_CMD_NEW)
		fpvs_handle_vport(name, portid, type, tun_dstport);
}

#ifndef FP_STANDALONE
/* FIXME: temporary statics until support for more than a single DP
 * is implemented. */
static int seen_datapath_id;
static uint32_t known_datapath_id;

void fpvs_parse_dp(struct nlsock *cmn, struct nlmsghdr *nlh, int len)
{
	char *buf;
	uint32_t datapath_id;

	datapath_id = *(uint32_t*)((char*)nlh + NLMSG_HDRLEN + GENL_HDRLEN);
	if ((seen_datapath_id) && (datapath_id != known_datapath_id)) {
		/* Support for more than a single DP isn't implemented. */
		syslog(LOG_INFO, "[FPVS] Ignoring DataPath ID: %x\n",
		       datapath_id);
		return;
	}
	known_datapath_id = datapath_id;
	seen_datapath_id = 1;
	syslog(LOG_INFO, "[FPVS] DataPath ID: %x\n", datapath_id);

	/* Dump port configuration for the given datapth ID*/
	ovsdp_dump_request(cmn, cmn->genl_fam[OVS_GENL_VPORT].id,
			   OVS_VPORT_CMD_GET,
			   datapath_id, &buf);
}

static int fpvs_nl_recv(struct nl_msg *msg, void *arg)
{
	struct nlsock *s = arg;
	struct nlmsghdr *h = nlmsg_hdr(msg);
	int reqtype = FPVS_STATS_INVALID;

	/* Consistency check. */
	if ((h->nlmsg_type != s->genl_fam[OVS_GENL_FLOW].id) &&
	    (h->nlmsg_type != s->genl_fam[OVS_GENL_VPORT].id) &&
	    (h->nlmsg_type != s->genl_fam[OVS_GENL_DP].id)) {
		syslog(LOG_INFO,"Error, receiving a message from another "
			   "NL family !\n");
	}

	/* Do not try to parse message if it is a timeout. */
	if (h->nlmsg_type == s->genl_fam[OVS_GENL_FLOW].id) {
		fpvs_parse_flow(h, h->nlmsg_len);
	} else if (h->nlmsg_type == s->genl_fam[OVS_GENL_VPORT].id) {
		fpvs_parse_vport(h, h->nlmsg_len);
	} else if (h->nlmsg_type == s->genl_fam[OVS_GENL_DP].id) {
		fpvs_parse_dp(s, h, h->nlmsg_len);
	}

	CM_INCREASE_NL_STATS(s, reqtype);
	return 0;
}

int fpvs_prune_old_flows(void)
{
	struct cp_hdr	*hdr;

	CM_CALLOC(1, hdr, sizeof(*hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = 0;
	hdr->cphdr_type = htonl(CMD_FPVS_PRUNE);

	post_msg(hdr);
	return 0;
}

static int fpvs_nl_timeout(void *arg)
{
	struct nlsock *s = arg;

	/* send prune only for vrf 0 */
	if (s->vrfid != 0)
		return 0;

	/*
	 * Check for old flows to remove.
	 *
	 * XXX: This function can take some time to execute and could be
	 * a bottleneck for the flow/s performances. However, the
	 * performances for the flow/s will be addressed with a
	 * different design.
	 */
	return fpvs_prune_old_flows();
}

static void fpvs_cm_init(void) __attribute__((constructor));
void fpvs_cm_init(void)
{
	if (cm_nlsock_hooks_register(&fpvs_nlsock_hooks) == -1)
		syslog(LOG_ERR, "Can't register %s module\n",
		       fpvs_nlsock_hooks.name);
	else
		syslog(LOG_INFO, "%s module loaded\n",
		       fpvs_nlsock_hooks.name);
}

static void fpvs_cm_dump_cb(struct nlsock *cmn)
{
	char *msg;

	/* Send request to OVS to get vport state */
	ovsdp_dump_request(cmn, cmn->genl_fam[OVS_GENL_DP].id,
		      OVS_DP_CMD_GET, 0,
		      &msg);

	/* Flush flows. */
	if (seen_datapath_id) {
		ovsdp_flush_request(cmn->genl_fam[OVS_GENL_FLOW].id,
				    0,
				    known_datapath_id);
	}

	return;
}

static void fpvs_cm_init_cb(struct nlsock *cmn)
{
	struct timeval timeout;
	uint32_t datapath_id;
	ssize_t rcvd;
	char *msg;
	unsigned int i;

	/* cm_genl_init */
	cmn->genl_fam = malloc(sizeof(ovs_genl));
	if (!cmn->genl_fam) {
		syslog(LOG_INFO, "%s: Could not allocate genl_fam\n",
		       __func__);
		goto error;
	}
	memcpy(cmn->genl_fam, ovs_genl, sizeof(ovs_genl));
	for (i = 0; (i != (sizeof(ovs_genl) / sizeof(ovs_genl[0]))); ++i)
		if (cm_genl_get_family(&cmn->genl_fam[i])) {
			syslog(LOG_INFO,
			       "%s: Could not get OVS \"%s\" family info\n",
			       __func__, cmn->genl_fam[i].name);
			goto error;
		}


	timeout.tv_sec = FPVS_FLOW_TIMEOUT_MS/1000;
	timeout.tv_usec = (FPVS_FLOW_TIMEOUT_MS%1000)*1000;
	cm_netlink_sock(NETLINK_GENERIC, cmn, 0, 1, CM_BULK_READ, &timeout, 0);

	/* subscribe to group */
	if (nl_socket_add_membership(cmn->sk,
				     cmn->genl_fam[OVS_GENL_DP].grp.id)) {
		msg = "DP";
		goto subscribe_error;
	}
	if (!cm_disable_nl_ovs_flow) {
		if (nl_socket_add_membership(cmn->sk,
					     cmn->genl_fam[OVS_GENL_FLOW].grp.id)) {
			msg = "FLOW";
			goto subscribe_error;
		}
	}
	if (nl_socket_add_membership(cmn->sk,
				     cmn->genl_fam[OVS_GENL_VPORT].grp.id)) {
		msg = "VPORT";
		goto subscribe_error;
	}

	return;
subscribe_error:
	syslog(LOG_INFO, "%s: Can't subscribe to %s group.\n", __func__, msg);
	cm_close_netlink_sock(cmn, 1);
error:
	cmn->init_failed = 1;
	free(cmn->genl_fam);
	cmn->genl_fam = NULL;
}
#endif
