/*
 * Copyright (c) 2007 6WIND
 * Authors:
 *   Nicolas DICHTEL, <nicolas.dichtel@6wind.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <stdbool.h> /* for xt_sctp.h */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/types.h> /* for 2.4 kernel */
#include <linux/netlink.h>
#include <linux/version.h>
#include <linux/netfilter/nfnetlink.h>
#include <limits.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/if_ether.h>
#include <linux/netfilter/xt_dscp.h>
#include <linux/netfilter/xt_mac.h>
#include <linux/netfilter/xt_multiport.h>
#include <linux/netfilter/xt_MARK.h>
#include <linux/netfilter/xt_DSCP.h>
#ifdef NET_VRF_SUPPORT
#if defined(NF_NETLINK_TABLES) || defined(CONFIG_CACHEMGR_AUDIT)
#include <linux/netfilter/xt_vr.h>
#endif
#endif
#include <linux/netfilter/xt_limit.h>
#include <linux/netfilter/xt_state.h>
#include <linux/netfilter/xt_sctp.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/xt_physdev.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/xt_conntrack.h>
#ifdef CONFIG_CACHEMGR_NF_DEV
#include <xt_DEV.h>
#endif
#include <linux/netfilter_ipv6/ip6t_frag.h>
#ifdef CONFIG_CACHEMGR_NF_RPFILTER
#include <linux/netfilter/xt_rpfilter.h>
#endif

#include <event.h>

#include "fpc.h"
#include "cm_pub.h"
#include "cm_priv.h"
#include "cm_sock.h"
#ifdef CONFIG_PORTS_CACHEMGR_NF_RULE_NAT
#include <net/netfilter/nf_nat.h>
#endif

#ifdef CONFIG_CACHEMGR_NF_UID
#include <xt_uid.h>
#endif

#ifdef CONFIG_CACHEMGR_NF_LSN
#include <linux/netfilter/xt_lsn.h>
#endif

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
#include "libvrf.h"
#endif

 #include <xt_dispatch.h>
 #include <xt_syns.h>
 #include <xt_speed.h>
#include <linux/netfilter/xt_iprange.h>
#include <linux/netfilter/xt_string.h>

struct nf_async_dump_request {
	LIST_ENTRY(nf_async_dump_request) next;
	char table_name[CM_NF_MAXNAMELEN];
	u_int8_t family;
	u_int32_t cookie;
	struct event ev;
	u_int32_t vrfid;
};

#if defined(NF_NETLINK_TABLES) || defined(CONFIG_CACHEMGR_AUDIT)
LIST_HEAD(dump_req_list, nf_async_dump_request);
static struct dump_req_list dump_req_list;


static inline int get_number(struct ipt_entry *i,
			     struct ipt_entry *seek,
			     unsigned int *pos)
{
	if (i == seek)
		return 1;
	(*pos)++;
	return 0;
}

static int ip4tc_offset2index(u_int32_t *index,
			      struct ipt_get_entries *entries,
			      struct ipt_entry *seek)
{
	u_int32_t pos = 0;

	if (IPT_ENTRY_ITERATE(entries->entrytable, entries->size,
			      get_number, seek, &pos) == 0) {
		syslog(LOG_ERR, "%s: Offset (%i) isn't a entry\n", __FUNCTION__,
		       (int)((char *)seek - (char *)entries->entrytable));
		return -EINVAL;
	}

	*index = htonl(pos);
	return 0;
}

static int ip4tc_copy_target(struct ipt_entry_target *t,
			     struct cp_nfrule *rule,
			     struct ipt_get_entries *entries)
{
	/* Standard target */
	if (!strcmp(t->u.user.name, IPT_STANDARD_TARGET)) {
		struct ipt_standard_target *stdtarget = (struct ipt_standard_target *)t;

		rule->target.type = CM_NF_TARGET_TYPE_STANDARD;
		if (stdtarget->verdict < 0)
			rule->target.data.standard.verdict = htonl(stdtarget->verdict);
		else if (ip4tc_offset2index((u_int32_t *)&rule->target.data.standard.verdict, entries,
					    (struct ipt_entry *)((void *)entries->entrytable +
								 stdtarget->verdict)) < 0) {
				syslog(LOG_ERR, "%s: fail to translate target\n", __FUNCTION__);
				return -EINVAL;
			}
		return 0;
	}

	/* Error target */
	if (!strcmp(t->u.user.name, IPT_ERROR_TARGET)) {
		char *errorname = (char *)t->data;

		rule->target.type =  CM_NF_TARGET_TYPE_ERROR;
		memcpy(rule->target.data.error.errorname, errorname,
		       sizeof(rule->target.data.error.errorname));
		return 0;
	}

	/* Mark target */
	if (!strcmp(t->u.user.name, "MARK") && t->u.user.revision == 2) {
		struct xt_mark_tginfo2 *markinfo = (struct xt_mark_tginfo2 *)t->data;

		rule->target.type = CM_NF_TARGET_TYPE_MARK_V2;
		rule->target.data.mark.mark = htonl(markinfo->mark);
		rule->target.data.mark.mask = htonl(markinfo->mask);
		return 0;
	}

	/* DSCP target */
	if (!strcmp(t->u.user.name, "DSCP")) {
		struct xt_DSCP_info *dscpinfo = (struct xt_DSCP_info *)t->data;

		rule->target.type = CM_NF_TARGET_TYPE_DSCP;
		rule->target.data.dscp.dscp = ((dscpinfo->dscp << XT_DSCP_SHIFT) & XT_DSCP_MASK);
		return 0;
	}

	/* REJECT target */
	if (!strcmp(t->u.user.name, "REJECT")) {
		rule->target.type = CM_NF_TARGET_TYPE_REJECT;
		return 0;
	}

	/* LOG target */
	if (!strcmp(t->u.user.name, "LOG")) {
		rule->target.type = CM_NF_TARGET_TYPE_LOG;
		return 0;
	}

	/* ULOG target */
	if (!strcmp(t->u.user.name, "ULOG")) {
		rule->target.type = CM_NF_TARGET_TYPE_ULOG;
		return 0;
	}

	/* SNAT target */
	if (!strcmp(t->u.user.name, "SNAT")) {
#ifdef CONFIG_PORTS_CACHEMGR_NF_RULE_NAT
		struct nf_nat_multi_range_compat *natrange =
			(struct nf_nat_multi_range_compat *)t->data;

		rule->target.data.nat.min_ip = natrange->range[0].min_ip;
		rule->target.data.nat.max_ip = natrange->range[0].max_ip;

		if (natrange->range[0].flags & IP_NAT_RANGE_PROTO_SPECIFIED) {
			/* Ports are in network order, no need for htons */
			rule->target.data.nat.min_port = natrange->range[0].min.tcp.port;
			rule->target.data.nat.max_port = natrange->range[0].max.tcp.port;
		} else {
			rule->target.data.nat.min_port = 0;
			rule->target.data.nat.max_port = 0;
		}
#endif /* CONFIG_PORTS_CACHEMGR_NF_RULE_NAT */
		rule->target.type = CM_NF_TARGET_TYPE_SNAT;
		return 0;
	}

	/* MASQUERADE target (very similar to SNAT) */
	if (!strcmp(t->u.user.name, "MASQUERADE")) {
#ifdef CONFIG_PORTS_CACHEMGR_NF_RULE_NAT
		struct nf_nat_multi_range_compat *natrange =
			(struct nf_nat_multi_range_compat *)t->data;

		/* When masquerading, we translate all the outgoing packets to the
		   outgoing interface address */
		rule->target.data.nat.min_ip = 0;
		rule->target.data.nat.max_ip = 0;

		if (natrange->range[0].flags & IP_NAT_RANGE_PROTO_SPECIFIED) {
			/* Ports are in network order, no need for htons */
			rule->target.data.nat.min_port = natrange->range[0].min.tcp.port;
			rule->target.data.nat.max_port = natrange->range[0].max.tcp.port;
		} else {
			rule->target.data.nat.min_port = 0;
			rule->target.data.nat.max_port = 0;
		}
#endif /* CONFIG_PORTS_CACHEMGR_NF_RULE_NAT */
		rule->target.type = CM_NF_TARGET_TYPE_MASQUERADE;
		return 0;
	}

	/* DNAT target */
	if (!strcmp(t->u.user.name, "DNAT")) {
#ifdef CONFIG_PORTS_CACHEMGR_NF_RULE_NAT
		struct nf_nat_multi_range_compat *natrange =
			(struct nf_nat_multi_range_compat *)t->data;

		rule->target.data.nat.min_ip = natrange->range[0].min_ip;
		rule->target.data.nat.max_ip = natrange->range[0].max_ip;

		if (natrange->range[0].flags & IP_NAT_RANGE_PROTO_SPECIFIED) {
			/* Ports are in network order, no need for htons */
			rule->target.data.nat.min_port = natrange->range[0].min.tcp.port;
			rule->target.data.nat.max_port = natrange->range[0].max.tcp.port;
		} else {
			rule->target.data.nat.min_port = 0;
			rule->target.data.nat.max_port = 0;
		}
#endif /* CONFIG_PORTS_CACHEMGR_NF_RULE_NAT */
		rule->target.type = CM_NF_TARGET_TYPE_DNAT;
		return 0;
	}

	/* TCPMSS target */
	if (!strcmp(t->u.user.name, "TCPMSS")) {
		rule->target.type = CM_NF_TARGET_TYPE_TCPMSS;
		return 0;
	}

#ifdef CONFIG_CACHEMGR_NF_DEV
	/* DEV target */
	if (!strcmp(t->u.user.name, XT_DEV_NAME)) {
		struct xt_dev_info *dev =
			(struct xt_dev_info *) t->data;

		rule->target.type = CM_NF_TARGET_TYPE_DEV;
		rule->target.data.dev.flags = htonl(dev->flags);
		rule->target.data.dev.mark = htonl(dev->mark);
		snprintf(rule->target.data.dev.ifname,
			 sizeof(rule->target.data.dev.ifname),
			 "%s", dev->ifname);
		return 0;
	}
#endif

	/* CHECKSUM target */
	if (!strcmp(t->u.user.name, "CHECKSUM")) {
		rule->target.type = CM_NF_TARGET_TYPE_CHECKSUM;
		return 0;
	}

	syslog(LOG_ERR, "%s: Unknown target (%s, rev: %u)\n", __FUNCTION__,
	       t->u.user.name, t->u.user.revision);
	return -ESRCH;
}

#ifdef CONFIG_CACHEMGR_NF_RPFILTER
static uint8_t
iptc_parse_rpf_flags(struct xt_rpfilter_info *info)
{
	uint8_t result = 0;

	if (info->flags & XT_RPFILTER_LOOSE)
		result |= CM_NF_RPF_LOOSE;
	if (info->flags & XT_RPFILTER_VALID_MARK)
		result |= CM_NF_RPF_VALID_MARK;
	if (info->flags & XT_RPFILTER_ACCEPT_LOCAL)
		result |= CM_NF_RPF_ACCEPT_LOCAL;
	if (info->flags & XT_RPFILTER_INVERT)
		result |= CM_NF_RPF_INVERT;

	return result;
}
#endif /* CONFIG_CACHEMGR_NF_RPFILTER */

static uint8_t
iptc_conntrack_state(void *match_data, int revision)
{
#define CMGR_XT_CONNTRACK_UNSUPPORTED_OPTIONS (0xff)
	int is_established;
/* copied from xt_conntrack.h for compatibility with iptables < 1.4.18
 * the XT_CONNTRACK_STATE_ALIAS flag was added to tell when the "conntrack"
 * match was added with "-m state". */
#define CMGR_XT_CONNTRACK_STATE_ALIAS (1 << 13)

	switch (revision) {
	case 0: {
		struct xt_state_info *sinfo;
		sinfo = (struct xt_state_info *)match_data;
		if (sinfo->statemask >> IP_CT_NUMBER)
			return CMGR_XT_CONNTRACK_UNSUPPORTED_OPTIONS;
		is_established = (unsigned int)sinfo->statemask & XT_STATE_BIT(IP_CT_ESTABLISHED);
		break;
	}
	case 1: {
		struct xt_conntrack_mtinfo1 *ctinfo1;
		ctinfo1 = (struct xt_conntrack_mtinfo1 *)match_data;
		/* check for unsupported options */
		if (ctinfo1->match_flags & ~(XT_CONNTRACK_STATE|CMGR_XT_CONNTRACK_STATE_ALIAS))
			return CMGR_XT_CONNTRACK_UNSUPPORTED_OPTIONS;
		if (ctinfo1->state_mask >> IP_CT_NUMBER)
			return CMGR_XT_CONNTRACK_UNSUPPORTED_OPTIONS;
		is_established = (__u16)ctinfo1->state_mask & XT_CONNTRACK_STATE_BIT(IP_CT_ESTABLISHED);
		if (ctinfo1->invert_flags & XT_CONNTRACK_STATE)
			is_established = !is_established;
		break;
	}
	case 2: {
		struct xt_conntrack_mtinfo2 *ctinfo2;
		ctinfo2 = (struct xt_conntrack_mtinfo2 *)match_data;
		/* check for unsupported options */
		if (ctinfo2->match_flags & ~(XT_CONNTRACK_STATE|CMGR_XT_CONNTRACK_STATE_ALIAS))
			return CMGR_XT_CONNTRACK_UNSUPPORTED_OPTIONS;
		if (ctinfo2->state_mask >> IP_CT_NUMBER)
			return CMGR_XT_CONNTRACK_UNSUPPORTED_OPTIONS;
		is_established = (__u16)ctinfo2->state_mask & XT_CONNTRACK_STATE_BIT(IP_CT_ESTABLISHED);
		if (ctinfo2->invert_flags & XT_CONNTRACK_STATE)
			is_established = !is_established;
		break;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
	case 3: {
		struct xt_conntrack_mtinfo3 *ctinfo3;
		ctinfo3 = (struct xt_conntrack_mtinfo3 *)match_data;
		/* check for unsupported options */
		if (ctinfo3->match_flags & ~(XT_CONNTRACK_STATE|CMGR_XT_CONNTRACK_STATE_ALIAS))
			return CMGR_XT_CONNTRACK_UNSUPPORTED_OPTIONS;
		if (ctinfo3->state_mask >> IP_CT_NUMBER)
			return CMGR_XT_CONNTRACK_UNSUPPORTED_OPTIONS;
		is_established = (__u16)ctinfo3->state_mask & XT_CONNTRACK_STATE_BIT(IP_CT_ESTABLISHED);
		if (ctinfo3->invert_flags & XT_CONNTRACK_STATE)
			is_established = !is_established;
		break;
	}
#endif
	default:
		return CMGR_XT_CONNTRACK_UNSUPPORTED_OPTIONS;
	}

	return is_established ? CM_NF_L3_STATE_ESTABLISHED : CM_NF_L3_STATE_EXCEPTION;
}

static int ip4tc_copy_match(struct ipt_entry_match *m,
			    struct cp_nfrule *rule)
{
	/* UDP parameters */
	if (!strcmp(m->u.user.name, "udp")) {
		struct ipt_udp *udpinfo = (struct ipt_udp *)m->data;

		rule->l3.type = CM_NF_L3_TYPE_UDP;
		rule->l3.data.udp.spts[0]  = htons(udpinfo->spts[0]);
		rule->l3.data.udp.spts[1]  = htons(udpinfo->spts[1]);
		rule->l3.data.udp.dpts[0]  = htons(udpinfo->dpts[0]);
		rule->l3.data.udp.dpts[1]  = htons(udpinfo->dpts[1]);
		rule->l3.data.udp.invflags = udpinfo->invflags;
		return 0;
	}

	/* TCP parameters */
	if (!strcmp(m->u.user.name, "tcp")) {
		struct ipt_tcp *tcpinfo = (struct ipt_tcp *)m->data;

		rule->l3.type = CM_NF_L3_TYPE_TCP;
		rule->l3.data.tcp.spts[0]  = htons(tcpinfo->spts[0]);
		rule->l3.data.tcp.spts[1]  = htons(tcpinfo->spts[1]);
		rule->l3.data.tcp.dpts[0]  = htons(tcpinfo->dpts[0]);
		rule->l3.data.tcp.dpts[1]  = htons(tcpinfo->dpts[1]);
		rule->l3.data.tcp.option   = tcpinfo->option;
		rule->l3.data.tcp.flg_mask = tcpinfo->flg_mask;
		rule->l3.data.tcp.flg_cmp  = tcpinfo->flg_cmp;
		rule->l3.data.tcp.invflags = tcpinfo->invflags;
		return 0;
	}

	/* SCTP parameters */
	if (!strcmp(m->u.user.name, "sctp")) {
		struct xt_sctp_info *sctpinfo = (struct xt_sctp_info *)m->data;
		unsigned int j;

		rule->l3.type = CM_NF_L3_TYPE_SCTP;
		rule->l3.data.sctp.spts[0] = htons(sctpinfo->spts[0]);
		rule->l3.data.sctp.spts[1] = htons(sctpinfo->spts[1]);
		rule->l3.data.sctp.dpts[0] = htons(sctpinfo->dpts[0]);
		rule->l3.data.sctp.dpts[1] = htons(sctpinfo->dpts[1]);
		for(j=0; j<256/(sizeof(u_int32_t)*8); j++)
			rule->l3.data.sctp.chunkmap[j] = htonl(sctpinfo->chunkmap[j]);
		rule->l3.data.sctp.chunk_match_type = htonl(sctpinfo->chunk_match_type);
		memcpy(rule->l3.data.sctp.flag_info, sctpinfo->flag_info, sizeof(rule->l3.data.sctp.flag_info));
		rule->l3.data.sctp.flag_count = htonl(sctpinfo->flag_count);
		rule->l3.data.sctp.flags = htonl(sctpinfo->flags);
		rule->l3.data.sctp.invflags = htonl(sctpinfo->invflags);
		return 0;
	}

	/* ICMP parameters */
	if (!strcmp(m->u.user.name, "icmp")) {
		struct ipt_icmp *icmpinfo = (struct ipt_icmp *)m->data;

		rule->l3.type = CM_NF_L3_TYPE_ICMP;
		rule->l3.data.icmp.type     = icmpinfo->type;
		rule->l3.data.icmp.code[0]  = icmpinfo->code[0];
		rule->l3.data.icmp.code[1]  = icmpinfo->code[1];
		rule->l3.data.icmp.invflags = icmpinfo->invflags;
		return 0;
	}

	/* DSCP parameters */
	if (!strcmp(m->u.user.name, "dscp")) {
		struct xt_dscp_info *dscpinfo = (struct xt_dscp_info *)m->data;

		rule->l2_opt.opt |= CM_NF_l2OPT_DSCP;
		rule->l2_opt.dscp = ((dscpinfo->dscp << XT_DSCP_SHIFT) & XT_DSCP_MASK);
		rule->l2_opt.invdscp = dscpinfo->invert;
		return 0;
	}

#ifdef NET_VRF_SUPPORT
	/* VR parameters */
	if (!strcmp(m->u.user.name, "vr")) {
		struct xt_vr_info *vrinfo = (struct xt_vr_info *)m->data;

		rule->l2_opt.vrfid = htonl(vrinfo->vrfid);
		return 0;
	}
#endif /* NET_VRF_SUPPORT */

	/* state parameters */
	if (!strcmp(m->u.user.name, "state")) {
		struct xt_state_info *sinfo = (struct xt_state_info *)m->data;

		if (sinfo->statemask & XT_STATE_BIT(IP_CT_ESTABLISHED))
			rule->l3.state = CM_NF_L3_STATE_ESTABLISHED;
		else
			rule->l3.state = CM_NF_L3_STATE_EXCEPTION;

		return 0;
	}

	/* conntrack is an alias of state */
	if (!strcmp(m->u.user.name, "conntrack")) {
		rule->l3.state = iptc_conntrack_state(m->data, m->u.user.revision);

		if (rule->l3.state == CMGR_XT_CONNTRACK_UNSUPPORTED_OPTIONS) {
			syslog(LOG_ERR, "%s: Unsupported conntrack match options\n",
			       __FUNCTION__);
			return -ESRCH;
		}

		return 0;
	}

	/* LIMIT parameters */
	if (!strcmp(m->u.user.name, "limit")) {
		struct xt_rateinfo *rateinfo = (struct xt_rateinfo *)m->data;

		rule->l2_opt.opt |= CM_NF_l2OPT_RATELIMIT;
		rule->l2_opt.rateinfo.cost = htonl(rateinfo->avg);
		rule->l2_opt.rateinfo.burst = htonl(rateinfo->burst);
		return 0;
	}

	/* mark parameters */
	if (!strcmp(m->u.user.name, "mark") && m->u.user.revision == 1) {
		struct xt_mark_mtinfo1 *minfo = (struct xt_mark_mtinfo1 *)m->data;

		rule->l2_opt.opt |= CM_NF_l2OPT_MARK;
		rule->l2_opt.mark.mark = htonl(minfo->mark);
		rule->l2_opt.mark.mask = htonl(minfo->mask);
		rule->l2_opt.mark.invert = minfo->invert;
		return 0;
	}

#ifdef CONFIG_CACHEMGR_NF_UID
	if (!strcmp(m->u.user.name, XT_UID_NAME)) {
		struct xt_uid_info *uid_info = (struct xt_uid_info *)m->data;
		rule->uid = htonl(uid_info->uid);
		return 0;
	}
#endif

#ifdef CONFIG_CACHEMGR_NF_LSN
	if (!strcmp(m->u.user.name, XT_LSN_NAME)) {
		/* the lsn-id is not used by the fast path, we ignore it */
		return 0;
	}
#endif

#ifdef CONFIG_CACHEMGR_NF_RPFILTER
	/* RPFILTER match */
	if (!strcmp(m->u.user.name, "rpfilter")) {
		rule->l2_opt.opt |= CM_NF_l2OPT_RPFILTER;
		rule->l2_opt.rpf_flags = iptc_parse_rpf_flags((struct xt_rpfilter_info *)m->data);
		return 0;
	}
#endif

	/* multiport match */
	if (!strcmp(m->u.user.name, "multiport")) {
		struct xt_multiport_v1 *mport = (struct xt_multiport_v1 *)m->data;
		rule->l3_opt.opt |= CM_NF_l3OPT_MULTIPORT;
		switch (mport->flags) {
		case XT_MULTIPORT_SOURCE:
			rule->l3_opt.multiport.flags = CM_NF_MULTIPORT_FLAG_SRC;
			break;
		case XT_MULTIPORT_DESTINATION:
			rule->l3_opt.multiport.flags = CM_NF_MULTIPORT_FLAG_DST;
			break;
		case XT_MULTIPORT_EITHER:
			rule->l3_opt.multiport.flags = CM_NF_MULTIPORT_FLAG_ANY;
			break;
		default:
			break;
		}
		rule->l3_opt.multiport.count = mport->count;
		memcpy(&(rule->l3_opt.multiport.ports), &(mport->ports), CM_NF_MULTIPORT_SIZE);
		memcpy(&(rule->l3_opt.multiport.pflags), &(mport->pflags), CM_NF_MULTIPORT_SIZE);
		rule->l3_opt.multiport.invert = mport->invert;
		return 0;
	}

	/* mac match */
	if (!strcmp(m->u.user.name, "mac")) {
		struct xt_mac_info *mac_info = (struct xt_mac_info *)m->data;
		rule->l2_opt.opt |= CM_NF_l2OPT_MAC;
		memcpy(&(rule->l2_opt.mac.srcaddr), &(mac_info->srcaddr), CM_ETHMACSIZE);
		rule->l2_opt.mac.invert = mac_info->invert;
		return 0;
	}

	if (!strcmp(m->u.user.name, "physdev")) {
		struct xt_physdev_info *physdev_info = (struct xt_physdev_info *)m->data;
		rule->l2_opt.opt |= CM_NF_l2OPT_PHYSDEV;
		memcpy(&rule->l2_opt.physdev.physindev,
		       &physdev_info->physindev, CM_IFNAMSIZE);
		memcpy(&rule->l2_opt.physdev.physindev_mask,
		       &physdev_info->in_mask, CM_IFNAMSIZE);
		memcpy(&rule->l2_opt.physdev.physoutdev,
		       &physdev_info->physoutdev, CM_IFNAMSIZE);
		memcpy(&rule->l2_opt.physdev.physoutdev_mask,
		       &physdev_info->out_mask, CM_IFNAMSIZE);
		rule->l2_opt.physdev.invert = physdev_info->invert;
		rule->l2_opt.physdev.bitmask = physdev_info->bitmask;
		return 0;
	}

	//for dispatch type
	if (!strcmp(m->u.user.name, XT_DISPATCH_NAME)) {
		struct xt_dispatch_info *dispatch_info = (struct xt_dispatch_info *)m->data;
		rule->dispatch = htonl(dispatch_info->dispatch);
		return 0;
	}

	//for syns type
	if (!strcmp(m->u.user.name, XT_SYNS_NAME)) {
		struct xt_syns_info *syns_info = (struct xt_syns_info *)m->data;
		rule->syns = htonl(syns_info->syns);
		return 0;
	}

	//for speed type
	if (!strcmp(m->u.user.name, XT_SPEED_NAME)) {
		struct xt_speed_info *speed_info = (struct xt_speed_info *)m->data;
		rule->speed = htonl(speed_info->speed);
		return 0;
	}
	
	/* IPRANGE parameters */
	if (!strcmp(m->u.user.name, "iprange")) {
		struct xt_iprange_mtinfo *iprange = (struct xt_iprange_mtinfo *)m->data;

		rule->l3_opt.opt |= CM_NF_l3OPT_IPRANGE;
		//memcpy(&(rule->l2_opt.iprange),iprange,sizeof(struct xt_iprange_mtinfo));
		rule->l3_opt.iprange.flags = iprange->flags;
		rule->l3_opt.iprange.src_min.ip = iprange->src_min.ip;
		rule->l3_opt.iprange.src_max.ip = iprange->src_max.ip;
		rule->l3_opt.iprange.dst_min.ip = iprange->dst_min.ip;
		rule->l3_opt.iprange.dst_max.ip = iprange->dst_max.ip;

		return 0;
	}

	/* string parameters*/
	if (!strcmp(m->u.user.name, "string")) {
		struct xt_string_info *string_info = (struct xt_string_info *)m->data;
		rule->string_opt.opt |= CM_NF_OPT_STRING;
		memcpy(&rule->string_opt.string.pattern,
		       &string_info->pattern, CM_NF_STRING_MAX_PATTERN_SIZE);
		memcpy(&rule->string_opt.string.algo,
		       &string_info->algo, CM_NF_STRING_MAX_ALGO_NAME_SIZE);
		rule->string_opt.string.from_offset =  string_info->from_offset;
		rule->string_opt.string.to_offset =  string_info->to_offset;
		rule->string_opt.string.patlen =  string_info->patlen;
		rule->string_opt.string.u.v0.invert =  string_info->u.v0.invert;
		rule->string_opt.string.u.v1.flags =  string_info->u.v1.flags;		
		return 0;
	}

	syslog(LOG_ERR, "%s: Unknown match type (%s)\n", __FUNCTION__, m->u.user.name);
	return -ESRCH;
}

static int ip4tc_copy_entry(struct ipt_entry *e,
			    struct cp_nftable *table,
			    struct ipt_getinfo *info,
			    struct ipt_get_entries *entries,
			    int *i)
{
	struct ipt_entry_target *t;
	struct cp_nfrule *rule;

	rule = &table->cpnftable_rules[*i];

	/* IPv4 header */
	rule->l2.ipv4.src      = e->ip.src.s_addr;
	rule->l2.ipv4.dst      = e->ip.dst.s_addr;
	rule->l2.ipv4.smsk     = e->ip.smsk.s_addr;
	rule->l2.ipv4.dmsk     = e->ip.dmsk.s_addr;
	memcpy(rule->l2.ipv4.iniface, e->ip.iniface,
	       sizeof(rule->l2.ipv4.iniface));
	memcpy(rule->l2.ipv4.outiface, e->ip.outiface,
	       sizeof(rule->l2.ipv4.outiface));
	memcpy(rule->l2.ipv4.iniface_mask, e->ip.iniface_mask,
	       sizeof(rule->l2.ipv4.iniface_mask));
	memcpy(rule->l2.ipv4.outiface_mask, e->ip.outiface_mask,
	       sizeof(rule->l2.ipv4.outiface_mask));
	rule->l2.ipv4.proto    = htons(e->ip.proto);
	rule->l2.ipv4.flags    = e->ip.flags;
	rule->l2.ipv4.invflags = e->ip.invflags;

	/* Initialize to ALL VR. Will be updating if a specific
	 * rule is set.
	 */
	rule->l2_opt.vrfid     = htonl(CM_NF_VRFID_UNSPECIFIED);

	if (IPT_MATCH_ITERATE(e, ip4tc_copy_match, rule) < 0) {
		syslog(LOG_ERR, "%s: Fail to parse entry\n", __FUNCTION__);
		return -EINVAL;
	}

	t = ipt_get_target(e);
	if (ip4tc_copy_target(t, rule, entries) < 0) {
		syslog(LOG_ERR, "%s: Fail to parse entry\n", __FUNCTION__);
		return -EINVAL;
	}

	(*i)++;
	return 0;

}

static int ip4tc_dump_table(u_int32_t cookie, char *tablename, u_int32_t vrfid)
{
	struct cp_nftable *table = NULL;
	struct ipt_getinfo info;
	struct ipt_get_entries *entries = NULL;
	int sockfd = 0, i = 0, hook;
	unsigned int size;
	socklen_t s;
	int ret = 0;

	if (strlen(tablename) >= CM_NF_MAXNAMELEN) {
		syslog(LOG_ERR, "%s: wrong tablename length (%d, max: %d)\n",
				__FUNCTION__, (int)strlen(tablename),
				CM_NF_MAXNAMELEN);
		goto out;
	}

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0) {
		syslog(LOG_ERR, "%s: socket(): %s\n", __FUNCTION__, strerror(errno));
		goto out;
	}

	s = sizeof(info);
	strncpy(info.name, tablename, CM_NF_MAXNAMELEN);
	if ((ret = getsockopt(sockfd, IPPROTO_IP, IPT_SO_GET_INFO, &info, &s)) < 0) {
		int loglvl = LOG_ERR;

		if (errno == EAGAIN) {
			loglvl = LOG_DEBUG;
			ret = -EAGAIN;
		}

		syslog(loglvl,
		       "%s: getsockopt(): %s\n", __FUNCTION__, strerror(errno));
		goto out;
	}

	size = sizeof(struct ipt_get_entries) + info.size;
	entries = (struct ipt_get_entries *)malloc(size);
	if (entries == NULL) {
		syslog(LOG_ERR, "%s: could not alloc memory\n", __func__);
		goto out;
	}
	entries->size = info.size;
	strncpy(entries->name, info.name, CM_NF_MAXNAMELEN);
	if ((ret = getsockopt(sockfd, IPPROTO_IP, IPT_SO_GET_ENTRIES, entries,
			      &size)) < 0) {
		int loglvl = LOG_ERR;

		if (errno == EAGAIN) {
			loglvl = LOG_DEBUG;
			ret = -EAGAIN;
		}

		syslog(loglvl,
		       "%s: getsockopt(): %s\n", __FUNCTION__, strerror(errno));
		goto out;
	}

	if (strcmp(entries->name, info.name)) {
		syslog(LOG_ERR, "%s: table name mismatch (%s != %s)\n",
		       __FUNCTION__, entries->name, info.name);
		goto out;
	}

	size = sizeof(struct cp_nftable) + (sizeof(struct cp_nfrule) * info.num_entries);
	if (!(table = (struct cp_nftable *)calloc(1, size))) {
		syslog(LOG_ERR, "%s: could not alloc mem to dump table - ignoring\n",
			__FUNCTION__);
		goto out;
	}

	memcpy(table->cpnftable_name, info.name, sizeof(table->cpnftable_name));
	table->cpnftable_count = htonl(info.num_entries);
	table->cpnftable_family = AF_INET;
	table->cpnftable_vrfid = htonl(vrfid);
	table->cpnftable_valid_hooks = htonl(info.valid_hooks);

	/* build hook_entry and underflow tables (for valid hooks only) */
	for(hook = 0; hook < CM_NF_IP_NUMHOOKS && hook < NF_IP_NUMHOOKS; hook++) {
		if (info.valid_hooks & (1 << hook)) {
			if (ip4tc_offset2index(&table->cpnftable_hook_entry[hook], entries,
					       (struct ipt_entry *)((void *)entries->entrytable +
								    info.hook_entry[hook])) < 0)
				goto out;
			if (ip4tc_offset2index(&table->cpnftable_underflow[hook], entries,
					       (struct ipt_entry *)((void *)entries->entrytable +
								    info.underflow[hook])) < 0)
				goto out;
		}
	}

	if (IPT_ENTRY_ITERATE(entries->entrytable, entries->size, ip4tc_copy_entry,
			      table, &info, entries, &i) < 0) {
		syslog(LOG_ERR, "%s: failed to parse entry for table %s\n",
		       __FUNCTION__, tablename);
		goto out;
	}

       	if (i != info.num_entries) {
               	syslog(LOG_ERR, "%s: failed to parse %d entries for table %s\n",
                       	__FUNCTION__, info.num_entries, tablename);
               	goto out;
       	}

	cm2cp_nf_update(cookie, table);
out:
	if (table)
		free(table);
	if (sockfd > 0)
		close(sockfd);
	if (entries)
		free(entries);

	return ret;
}


static inline int getv6_number(struct ip6t_entry *i,
			       struct ip6t_entry *seek,
			       unsigned int *pos)
{
	if (i == seek)
		return 1;
	(*pos)++;
	return 0;
}

static int ip6tc_offset2index(u_int32_t *index,
			      struct ip6t_get_entries *entries,
			      struct ip6t_entry *seek)
{
	u_int32_t pos = 0;

	if (IP6T_ENTRY_ITERATE(entries->entrytable, entries->size,
			      getv6_number, seek, &pos) == 0) {
		syslog(LOG_ERR, "%s: Offset (%i) isn't a entry\n", __FUNCTION__,
		       (int)((char *)seek - (char *)entries->entrytable));
		return -EINVAL;
	}

	*index = htonl(pos);
	return 0;
}

static int ip6tc_copy_target(struct ip6t_entry_target *t,
			     struct cp_nf6rule *rule,
			     struct ip6t_get_entries *entries)
{
	/* Standard target */
	if (!strcmp(t->u.user.name, IP6T_STANDARD_TARGET)) {
		struct ip6t_standard_target *stdtarget = (struct ip6t_standard_target *)t;

		rule->target.type = CM_NF_TARGET_TYPE_STANDARD;
		if (stdtarget->verdict < 0)
			rule->target.data.standard.verdict = htonl(stdtarget->verdict);
		else if (ip6tc_offset2index((u_int32_t *)&rule->target.data.standard.verdict, entries,
					    (struct ip6t_entry *)((void *)entries->entrytable +
								 stdtarget->verdict)) < 0) {
				syslog(LOG_ERR, "%s: fail to translate target\n", __FUNCTION__);
				return -EINVAL;
			}
		return 0;
	}

	/* Error target */
	if (!strcmp(t->u.user.name, IP6T_ERROR_TARGET)) {
		char *errorname = (char *)t->data;

		rule->target.type =  CM_NF_TARGET_TYPE_ERROR;
		memcpy(rule->target.data.error.errorname, errorname,
		       sizeof(rule->target.data.error.errorname));
		return 0;
	}

	/* Mark target */
	if (!strcmp(t->u.user.name, "MARK") && t->u.user.revision == 2) {
		struct xt_mark_tginfo2 *markinfo = (struct xt_mark_tginfo2 *)t->data;

		rule->target.type = CM_NF_TARGET_TYPE_MARK_V2;
		rule->target.data.mark.mark = htonl(markinfo->mark);
		rule->target.data.mark.mask = htonl(markinfo->mask);
		return 0;
	}

	/* DSCP target */
	if (!strcmp(t->u.user.name, "DSCP")) {
		struct xt_DSCP_info *dscpinfo = (struct xt_DSCP_info *)t->data;

		rule->target.type = CM_NF_TARGET_TYPE_DSCP;
		rule->target.data.dscp.dscp = ((dscpinfo->dscp << XT_DSCP_SHIFT) & XT_DSCP_MASK);
		return 0;
	}

	/* REJECT target */
	if (!strcmp(t->u.user.name, "REJECT")) {
		rule->target.type = CM_NF_TARGET_TYPE_REJECT;
		return 0;
	}

	/* LOG target */
	if (!strcmp(t->u.user.name, "LOG")) {
		rule->target.type = CM_NF_TARGET_TYPE_LOG;
		return 0;
	}

	/* ULOG target */
	if (!strcmp(t->u.user.name, "ULOG")) {
		rule->target.type = CM_NF_TARGET_TYPE_ULOG;
		return 0;
	}

	/* TCPMSS target */
	if (!strcmp(t->u.user.name, "TCPMSS")) {
		rule->target.type = CM_NF_TARGET_TYPE_TCPMSS;
		return 0;
	}

#ifdef CONFIG_CACHEMGR_NF_DEV
	/* DEV target */
	if (!strcmp(t->u.user.name, XT_DEV_NAME)) {
		struct xt_dev_info *dev =
			(struct xt_dev_info *) t->data;

		rule->target.type = CM_NF_TARGET_TYPE_DEV;
		rule->target.data.dev.flags = htonl(dev->flags);
		rule->target.data.dev.mark = htonl(dev->mark);
		snprintf(rule->target.data.dev.ifname,
			 sizeof(rule->target.data.dev.ifname),
			 "%s", dev->ifname);
		return 0;
	}
#endif

	syslog(LOG_ERR, "%s: Unknown target (%s, rev: %u)\n", __FUNCTION__,
	       t->u.user.name, t->u.user.revision);
	return -ESRCH;
}

static int ip6tc_copy_match(struct ip6t_entry_match *m,
			    struct cp_nf6rule *rule)
{
	/* UDP parameters */
	if (!strcmp(m->u.user.name, "udp")) {
		struct ip6t_udp *udpinfo = (struct ip6t_udp *)m->data;

		rule->l3.type = CM_NF_L3_TYPE_UDP;
		rule->l3.data.udp.spts[0]  = htons(udpinfo->spts[0]);
		rule->l3.data.udp.spts[1]  = htons(udpinfo->spts[1]);
		rule->l3.data.udp.dpts[0]  = htons(udpinfo->dpts[0]);
		rule->l3.data.udp.dpts[1]  = htons(udpinfo->dpts[1]);
		rule->l3.data.udp.invflags = udpinfo->invflags;
		return 0;
	}

	/* TCP parameters */
	if (!strcmp(m->u.user.name, "tcp")) {
		struct ip6t_tcp *tcpinfo = (struct ip6t_tcp *)m->data;

		rule->l3.type = CM_NF_L3_TYPE_TCP;
		rule->l3.data.tcp.spts[0]  = htons(tcpinfo->spts[0]);
		rule->l3.data.tcp.spts[1]  = htons(tcpinfo->spts[1]);
		rule->l3.data.tcp.dpts[0]  = htons(tcpinfo->dpts[0]);
		rule->l3.data.tcp.dpts[1]  = htons(tcpinfo->dpts[1]);
		rule->l3.data.tcp.option   = tcpinfo->option;
		rule->l3.data.tcp.flg_mask = tcpinfo->flg_mask;
		rule->l3.data.tcp.flg_cmp  = tcpinfo->flg_cmp;
		rule->l3.data.tcp.invflags = tcpinfo->invflags;
		return 0;
	}

	/* SCTP parameters */
	if (!strcmp(m->u.user.name, "sctp")) {
		struct xt_sctp_info *sctpinfo = (struct xt_sctp_info *)m->data;
		unsigned int j;

		rule->l3.type = CM_NF_L3_TYPE_SCTP;
		rule->l3.data.sctp.spts[0] = htons(sctpinfo->spts[0]);
		rule->l3.data.sctp.spts[1] = htons(sctpinfo->spts[1]);
		rule->l3.data.sctp.dpts[0] = htons(sctpinfo->dpts[0]);
		rule->l3.data.sctp.dpts[1] = htons(sctpinfo->dpts[1]);
		for(j=0; j<256/(sizeof(u_int32_t)*8); j++)
			rule->l3.data.sctp.chunkmap[j] = htonl(sctpinfo->chunkmap[j]);
		rule->l3.data.sctp.chunk_match_type = htonl(sctpinfo->chunk_match_type);
		memcpy(rule->l3.data.sctp.flag_info, sctpinfo->flag_info, sizeof(rule->l3.data.sctp.flag_info));
		rule->l3.data.sctp.flag_count = htonl(sctpinfo->flag_count);
		rule->l3.data.sctp.flags = htonl(sctpinfo->flags);
		rule->l3.data.sctp.invflags = htonl(sctpinfo->invflags);
		return 0;
	}

	/* ICMP6 parameters */
	if (!strcmp(m->u.user.name, "icmp6")) {
		struct ip6t_icmp *icmpinfo = (struct ip6t_icmp *)m->data;

		rule->l3.type = CM_NF_L3_TYPE_ICMP;
		rule->l3.data.icmp.type     = icmpinfo->type;
		rule->l3.data.icmp.code[0]  = icmpinfo->code[0];
		rule->l3.data.icmp.code[1]  = icmpinfo->code[1];
		rule->l3.data.icmp.invflags = icmpinfo->invflags;
		return 0;
	}

	/* DSCP parameters */
	if (!strcmp(m->u.user.name, "dscp")) {
		struct xt_dscp_info *dscpinfo = (struct xt_dscp_info *)m->data;

		rule->l2_opt.opt |= CM_NF_l2OPT_DSCP;
		rule->l2_opt.dscp = ((dscpinfo->dscp << XT_DSCP_SHIFT) & XT_DSCP_MASK);
		rule->l2_opt.invdscp = dscpinfo->invert;
		return 0;
	}

#ifdef NET_VRF_SUPPORT
	/* VR parameters */
	if (!strcmp(m->u.user.name, "vr")) {
		struct xt_vr_info *vrinfo = (struct xt_vr_info *)m->data;

		rule->l2_opt.vrfid = htonl(vrinfo->vrfid);
		return 0;
	}
#endif /* NET_VRF_SUPPORT */

	/* state parameters */
	if (!strcmp(m->u.user.name, "state")) {
		struct xt_state_info *sinfo = (struct xt_state_info *)m->data;

		if (sinfo->statemask & XT_STATE_BIT(IP_CT_ESTABLISHED))
			rule->l3.state = CM_NF_L3_STATE_ESTABLISHED;
		else
			rule->l3.state = CM_NF_L3_STATE_EXCEPTION;

		return 0;
	}

	/* conntrack is an alias of state */
	if (!strcmp(m->u.user.name, "conntrack")) {
		rule->l3.state = iptc_conntrack_state(m->data, m->u.user.revision);

		if (rule->l3.state == CMGR_XT_CONNTRACK_UNSUPPORTED_OPTIONS) {
			syslog(LOG_ERR, "%s: Unsupported conntrack match options\n",
			       __FUNCTION__);
			return -ESRCH;
		}

		return 0;
	}

	/* LIMIT parameters */
	if (!strcmp(m->u.user.name, "limit")) {
		struct xt_rateinfo *rateinfo = (struct xt_rateinfo *)m->data;

		rule->l2_opt.opt |= CM_NF_l2OPT_RATELIMIT;
		rule->l2_opt.rateinfo.cost = htonl(rateinfo->avg);
		rule->l2_opt.rateinfo.burst = htonl(rateinfo->burst);
		return 0;
	}

	/* IPv6 fragment parameters */
	if (!strcmp(m->u.user.name, "frag")) {
		struct ip6t_frag * frag = (struct ip6t_frag *)m->data;

		rule->l2_opt.opt |= CM_NF_l2OPT_FRAG;
		rule->l2_opt.frag.ids[0] = htonl(frag->ids[0]);
		rule->l2_opt.frag.ids[1] = htonl(frag->ids[1]);
		rule->l2_opt.frag.hdrlen = htonl(frag->hdrlen);
		rule->l2_opt.frag.flags = frag->flags;
		rule->l2_opt.frag.invflags = frag->invflags;
		return 0;
	}

	/* mark parameters */
	if (!strcmp(m->u.user.name, "mark") && m->u.user.revision == 1) {
		struct xt_mark_mtinfo1 *minfo = (struct xt_mark_mtinfo1 *)m->data;

		rule->l2_opt.opt |= CM_NF_l2OPT_MARK;
		rule->l2_opt.mark.mark = htonl(minfo->mark);
		rule->l2_opt.mark.mask = htonl(minfo->mask);
		rule->l2_opt.mark.invert = minfo->invert;
		return 0;
	}

#ifdef CONFIG_CACHEMGR_NF_UID
	if (!strcmp(m->u.user.name, XT_UID_NAME)) {
		struct xt_uid_info *uid_info = (struct xt_uid_info *)m->data;
		rule->uid = htonl(uid_info->uid);
		return 0;
	}
#endif

#ifdef CONFIG_CACHEMGR_NF_LSN
	if (!strcmp(m->u.user.name, XT_LSN_NAME)) {
		/* the lsn-id is not used by the fast path, we ignore it */
		return 0;
	}
#endif

#ifdef CONFIG_CACHEMGR_NF_RPFILTER
	/* RPFILTER match */
	if (!strcmp(m->u.user.name, "rpfilter")) {
		rule->l2_opt.opt |= CM_NF_l2OPT_RPFILTER;
		rule->l2_opt.rpf_flags = iptc_parse_rpf_flags((struct xt_rpfilter_info *)m->data);
		return 0;
	}
#endif

	/* multiport match */
	if (!strcmp(m->u.user.name, "multiport")) {
		struct xt_multiport_v1 *mport = (struct xt_multiport_v1 *)m->data;
		rule->l3_opt.opt |= CM_NF_l3OPT_MULTIPORT;
		switch (mport->flags) {
		case XT_MULTIPORT_SOURCE:
			rule->l3_opt.multiport.flags = CM_NF_MULTIPORT_FLAG_SRC;
			break;
		case XT_MULTIPORT_DESTINATION:
			rule->l3_opt.multiport.flags = CM_NF_MULTIPORT_FLAG_DST;
			break;
		case XT_MULTIPORT_EITHER:
			rule->l3_opt.multiport.flags = CM_NF_MULTIPORT_FLAG_ANY;
			break;
		default:
			break;
		}
		rule->l3_opt.multiport.count = mport->count;
		memcpy(&(rule->l3_opt.multiport.ports), &(mport->ports), CM_NF_MULTIPORT_SIZE);
		memcpy(&(rule->l3_opt.multiport.pflags), &(mport->pflags), CM_NF_MULTIPORT_SIZE);
		rule->l3_opt.multiport.invert = mport->invert;
		return 0;
	}

	/* mac match */
	if (!strcmp(m->u.user.name, "mac")) {
		struct xt_mac_info *mac_info = (struct xt_mac_info *)m->data;
		rule->l2_opt.opt |= CM_NF_l2OPT_MAC;
		memcpy(&(rule->l2_opt.mac.srcaddr), &(mac_info->srcaddr), CM_ETHMACSIZE);
		rule->l2_opt.mac.invert = mac_info->invert;
		return 0;
	}

	if (!strcmp(m->u.user.name, "physdev")) {
		struct xt_physdev_info *physdev_info = (struct xt_physdev_info *)m->data;
		rule->l2_opt.opt |= CM_NF_l2OPT_PHYSDEV;
		memcpy(&rule->l2_opt.physdev.physindev,
		       &physdev_info->physindev, CM_IFNAMSIZE);
		memcpy(&rule->l2_opt.physdev.physindev_mask,
		       &physdev_info->in_mask, CM_IFNAMSIZE);
		memcpy(&rule->l2_opt.physdev.physoutdev,
		       &physdev_info->physoutdev, CM_IFNAMSIZE);
		memcpy(&rule->l2_opt.physdev.physoutdev_mask,
		       &physdev_info->out_mask, CM_IFNAMSIZE);
		rule->l2_opt.physdev.invert = physdev_info->invert;
		rule->l2_opt.physdev.bitmask = physdev_info->bitmask;
		return 0;
	}

	syslog(LOG_ERR, "%s: Unknown match type (%s)\n", __FUNCTION__, m->u.user.name);
	return -ESRCH;
}

static int ip6tc_copy_entry(struct ip6t_entry *e,
			    struct cp_nf6table *table,
			    struct ip6t_getinfo *info,
			    struct ip6t_get_entries *entries,
			    int *i)
{
	struct ip6t_entry_target *t;
	struct cp_nf6rule *rule;

	rule = &table->cpnftable_rules[*i];

	/* IPv6 header */
	rule->l2.ipv6.src      = e->ipv6.src;
	rule->l2.ipv6.dst      = e->ipv6.dst;
	rule->l2.ipv6.smsk     = e->ipv6.smsk;
	rule->l2.ipv6.dmsk     = e->ipv6.dmsk;
	memcpy(rule->l2.ipv6.iniface, e->ipv6.iniface,
	       sizeof(rule->l2.ipv6.iniface));
	memcpy(rule->l2.ipv6.outiface, e->ipv6.outiface,
	       sizeof(rule->l2.ipv6.outiface));
	memcpy(rule->l2.ipv6.iniface_mask, e->ipv6.iniface_mask,
	       sizeof(rule->l2.ipv6.iniface_mask));
	memcpy(rule->l2.ipv6.outiface_mask, e->ipv6.outiface_mask,
	       sizeof(rule->l2.ipv6.outiface_mask));
	rule->l2.ipv6.proto    = htons(e->ipv6.proto);
	rule->l2.ipv6.flags    = e->ipv6.flags;
	rule->l2.ipv6.invflags = e->ipv6.invflags;

	/* Initialize to ALL VR. Will be updating if a specific
	 * rule is set.
	 */
	rule->l2_opt.vrfid     = htonl(CM_NF_VRFID_UNSPECIFIED);

	if (IP6T_MATCH_ITERATE(e, ip6tc_copy_match, rule) < 0) {
		syslog(LOG_ERR, "%s: Fail to parse entry\n", __FUNCTION__);
		return -EINVAL;
	}

	t = ip6t_get_target(e);
	if (ip6tc_copy_target(t, rule, entries) < 0) {
		syslog(LOG_ERR, "%s: Fail to parse entry\n", __FUNCTION__);
		return -EINVAL;
	}

	(*i)++;
	return 0;

}

static int ip6tc_dump_table(u_int32_t cookie, char *tablename, u_int32_t vrfid)
{
	struct cp_nf6table *table = NULL;
	struct ip6t_getinfo info;
	struct ip6t_get_entries *entries = NULL;
	int sockfd = 0, i = 0, hook;
	unsigned int size;
	socklen_t s;
	int ret = 0;

	if (strlen(tablename) >= CM_NF_MAXNAMELEN) {
		syslog(LOG_ERR, "%s: wrong tablename length (%d, max: %d)\n",
		 		__FUNCTION__, (int)strlen(tablename),
				CM_NF_MAXNAMELEN);
		goto out;
	}

	sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0) {
		syslog(LOG_ERR, "%s socket(): %s\n", __FUNCTION__, strerror(errno));
		goto out;
	}

	s = sizeof(info);
	strncpy(info.name, tablename, CM_NF_MAXNAMELEN);
	if ((ret = getsockopt(sockfd, IPPROTO_IPV6, IP6T_SO_GET_INFO, &info, &s)) < 0) {
		int loglvl = LOG_ERR;

		if (errno == EAGAIN) {
			loglvl = LOG_DEBUG;
			ret = -EAGAIN;
		}

		syslog(loglvl,
		       "%s: getsockopt(): %s\n", __FUNCTION__, strerror(errno));
		goto out;
	}

	size = sizeof(struct ip6t_get_entries) + info.size;
	entries = (struct ip6t_get_entries *)malloc(size);
	if (entries == NULL) {
		syslog(LOG_ERR, "%s: could not alloc memory\n", __func__);
		goto out;
	}
	entries->size = info.size;
	strncpy(entries->name, info.name, CM_NF_MAXNAMELEN);
	if ((ret = getsockopt(sockfd, IPPROTO_IPV6, IP6T_SO_GET_ENTRIES, entries,
		       &size)) < 0) {
		int loglvl = LOG_ERR;

		if (errno == EAGAIN) {
			loglvl = LOG_DEBUG;
			ret = -EAGAIN;
		}

		syslog(loglvl,
		       "%s: getsockopt(): %s\n", __FUNCTION__, strerror(errno));
		goto out;
	}

	if (strcmp(entries->name, info.name)) {
		syslog(LOG_ERR, "%s: table name mismatch (%s != %s)\n",
		       __FUNCTION__, entries->name, info.name);
		goto out;
	}

	size = sizeof(struct cp_nf6table) + (sizeof(struct cp_nf6rule) * info.num_entries);
	if (!(table = (struct cp_nf6table *)calloc(1, size))) {
		syslog(LOG_ERR, "%s: could not alloc mem to dump table - ignoring\n",
			__FUNCTION__);
		goto out;
	}

	memcpy(table->cpnftable_name, info.name, sizeof(table->cpnftable_name));
	table->cpnftable_count = htonl(info.num_entries);
	table->cpnftable_family = AF_INET6;
	table->cpnftable_vrfid = htonl(vrfid);
	table->cpnftable_valid_hooks = htonl(info.valid_hooks);

	/* build hook_entry and underflow tables (for valid hooks only) */
	for (hook = 0; hook < CM_NF_IP_NUMHOOKS && hook < NF_IP_NUMHOOKS; hook++) {
		if (info.valid_hooks & (1 << hook)) {
			if (ip6tc_offset2index(&table->cpnftable_hook_entry[hook], entries,
					       (struct ip6t_entry *)((void *)entries->entrytable +
								     info.hook_entry[hook])) < 0)
				goto out;
			if (ip6tc_offset2index(&table->cpnftable_underflow[hook], entries,
					       (struct ip6t_entry *)((void *)entries->entrytable +
								     info.underflow[hook])) < 0)
				goto out;
		}
	}

	if (IP6T_ENTRY_ITERATE(entries->entrytable, entries->size, ip6tc_copy_entry,
			       table, &info, entries, &i) < 0) {
		syslog(LOG_ERR, "%s: failed to parse entry for table %s\n",
		       __FUNCTION__, tablename);
		goto out;
	}

       	if (i != info.num_entries) {
               	syslog(LOG_ERR, "%s: failed to parse %d entries for table %s\n",
                       	__FUNCTION__, info.num_entries, tablename);
               	goto out;
       	}

	cm2cp_nf6_update(cookie, table);
out:
	if (table)
		free(table);
	if (sockfd > 0)
		close(sockfd);
	if (entries)
		free(entries);

	return ret;
}

static void iptc_dump_table(int vrfid, void *data)
{
	struct nf_async_dump_request *req = data;
	int ret = 0;

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	/*
	 * ip[4|6]tc_dump_table creates sockets, we change vrf here to
	 * avoid code duplication
	 */
	if (vrfid && (libvrf_change(vrfid) < 0)) {
		syslog(LOG_ERR, "%s: libvrf_change failed for vrf %d\n",
		       __func__, vrfid);
		return;
	}
#endif

	switch (req->family) {
	case AF_INET:
		ret = ip4tc_dump_table(req->cookie, req->table_name, vrfid);
		break;
	case AF_INET6:
		ret = ip6tc_dump_table(req->cookie, req->table_name, vrfid);
		break;
	default :
		break;
	}

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	if (vrfid && (libvrf_back() < 0)) {
		syslog(LOG_ERR, "%s: libvrf_back failed for vrf %d\n",
		       __func__, vrfid);
	}
#endif
	if (ret == -EAGAIN)
		/* in case of EAGAIN error, reload timer */
		cm_iptc_dump_table_async(req->cookie,
					 req->table_name,
					 req->family,
					 vrfid);
}

static void iptc_dump_table_async_cb(int sock, short evtype, void *data)
{
	struct nf_async_dump_request *dump_req = data;

	LIST_REMOVE(dump_req, next);

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	libvrf_iterate(iptc_dump_table, dump_req);
#else
	iptc_dump_table(0, dump_req);
#endif

	free(dump_req);
}

void cm_iptc_dump_table_async(u_int32_t cookie, char *tablename, u_int8_t family, u_int32_t sock_vrfid)
{
	struct nf_async_dump_request *dump_req;
	struct timeval tv;

	/* check that we don't have the same dump pending */
	LIST_FOREACH(dump_req, &dump_req_list, next) {
		if (strncmp(tablename, dump_req->table_name, CM_NF_MAXNAMELEN))
			continue;
		if (family != dump_req->family)
			continue;
		return; /* the same dump is already scheduled */
	}

	dump_req = malloc(sizeof(*dump_req));
	if (dump_req == NULL) {
		syslog(LOG_ERR, "%s Not enough memory\n", __FUNCTION__);
		return;
	}
	strncpy(dump_req->table_name, tablename, CM_NF_MAXNAMELEN);
	dump_req->family = family;
	dump_req->cookie = cookie;
	dump_req->vrfid = sock_vrfid;
	tv.tv_sec = 0;
	tv.tv_usec = 200 * 1000; /* will update in 200ms */
	evtimer_set(&dump_req->ev, iptc_dump_table_async_cb, dump_req);
	evtimer_add(&dump_req->ev, &tv);
	LIST_INSERT_HEAD(&dump_req_list, dump_req, next);
}

void cm_iptc_dump_all_tables(struct nlsock *cmn)
{
	static struct nf_async_dump_request requests[] = {
		{.cookie = 0, .table_name = "filter", .family = AF_INET},
		{.cookie = 0, .table_name = "mangle", .family = AF_INET},
		{.cookie = 0, .table_name = "nat",    .family = AF_INET},
		{.cookie = 0, .table_name = "filter", .family = AF_INET6},
		{.cookie = 0, .table_name = "mangle", .family = AF_INET6},
	};
	int req_count = sizeof(requests) / sizeof(struct nf_async_dump_request);
	int i;

	for (i = 0; i < req_count; i++) {
#ifdef CONFIG_PORTS_CACHEMGR_NETNS
		libvrf_iterate(iptc_dump_table, &requests[i]);
#else
		iptc_dump_table(0, &requests[i]);
#endif
	}
}

void cm_iptc_init(void)
{
	LIST_INIT(&dump_req_list);
}

void cm_iptc_exit(void)
{
	struct nf_async_dump_request *dump_req;

	while ( (dump_req = LIST_FIRST(&dump_req_list)) ) {
		LIST_REMOVE(dump_req, next);
		event_del(&dump_req->ev);
		free(dump_req);
	}
}
#endif /* NF_NETLINK_TABLES || CONFIG_CACHEMGR_AUDIT */
