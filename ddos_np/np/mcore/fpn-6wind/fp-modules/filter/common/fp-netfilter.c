/*
 * Copyright (c) 2007 6WIND
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#if defined(CONFIG_MCORE_ARCH_XLP) && defined(__FastPath__)
#include "xlp/fpn-gcc-bug.h"
#endif

#include "fp.h"

#include "fp-nfct.h"
#include "netinet/fp-sctp.h"
#include "net/fp-socket.h"
#include "net/fp-ethernet.h"

#ifdef HA_SUPPORT
void fpm_ha_check_request(void);
#endif

/*
 * netfilter management functions
 */

const char *fp_hook_name(int hook)
{
	switch (hook) {
	case FP_NF_IP_PRE_ROUTING:
		return "FP_NF_IP_PRE_ROUTING";
	case FP_NF_IP_LOCAL_IN:
		return "FP_NF_IP_LOCAL_IN";
	case FP_NF_IP_FORWARD:
		return "FP_NF_IP_FORWARD";
	case FP_NF_IP_LOCAL_OUT:
		return "FP_NF_IP_LOCAL_OUT";
	case FP_NF_IP_POST_ROUTING:
		return "FP_NF_IP_POST_ROUTING";
	default:
		return "unknown hook";
	}
}

const char *fp_table_name(int table)
{
	switch (table) {
	case FP_NF_TABLE_FILTER:
		return FP_NF_FILTER_TABLE;
	case FP_NF_TABLE_MANGLE:
		return FP_NF_MANGLE_TABLE;
	case FP_NF_TABLE_NAT:
		return FP_NF_NAT_TABLE;
	default:
		return "unknown table";
	}
}

uint8_t fp_nf_table_id(const char *tblname) {
	if (!strcmp(tblname, FP_NF_FILTER_TABLE))
		return FP_NF_TABLE_FILTER;
	else if (!strcmp(tblname, FP_NF_MANGLE_TABLE))
		return FP_NF_TABLE_MANGLE;
	else if (!strcmp(tblname, FP_NF_NAT_TABLE))
		return FP_NF_TABLE_NAT;
	else
		return FP_NF_TABLE_NUM;
}

#ifdef CONFIG_MCORE_NETFILTER_IPV6
uint8_t fp_nf6_table_id(const char *tblname) {
	if (!strcmp(tblname, FP_NF_FILTER_TABLE))
		return FP_NF_TABLE_FILTER;
	else if (!strcmp(tblname, FP_NF_MANGLE_TABLE))
		return FP_NF_TABLE_MANGLE;
	else
		return FP_NF6_TABLE_NUM;
}
#endif

void fp_nf_invalidate_cache(void)
{
#ifdef CONFIG_MCORE_NETFILTER_CACHE
	int i;
	for (i=0; i<FP_NF_MAX_CACHE_SIZE; i++) {
		fp_shared->fp_nf_rule_cache[i].state = FP_NF_CACHE_STATE_FREE;
	}
#endif
}

#ifdef CONFIG_MCORE_NETFILTER_IPV6
void fp_nf6_invalidate_cache(void)
{
#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE
	int i;
	for (i=0; i<FP_NF6_MAX_CACHE_SIZE; i++) {
		fp_shared->fp_nf6_rule_cache[i].state = FP_NF_CACHE_STATE_FREE;
	}
#endif
}
#endif

int fp_nf_update_bypass(uint8_t bypass)
{
	fp_shared->conf.s.do_netfilter = !bypass;
	fp_shared->conf.s.do_nf_cache = !bypass;
	return 0;
}

/* enable/disable nat conntrack hooks */
int fp_nf_set_conntrack_nat(uint8_t enable, uint16_t nf_vr)
{
	if (enable) {
		fp_shared->nf_conf.enabled_hook[nf_vr][FP_NF_IP_PRE_ROUTING]  |= 1ULL << FP_NF_FLAG_FORCE_NAT_CONNTRACK;
		fp_shared->nf_conf.enabled_hook[nf_vr][FP_NF_IP_LOCAL_OUT]    |= 1ULL << FP_NF_FLAG_FORCE_NAT_CONNTRACK;
		fp_shared->nf_conf.enabled_hook[nf_vr][FP_NF_IP_POST_ROUTING] |= 1ULL << FP_NF_FLAG_FORCE_NAT_CONNTRACK;
	}
	else {
		fp_shared->nf_conf.enabled_hook[nf_vr][FP_NF_IP_PRE_ROUTING]  &= ~(1ULL << FP_NF_FLAG_FORCE_NAT_CONNTRACK);
		fp_shared->nf_conf.enabled_hook[nf_vr][FP_NF_IP_LOCAL_OUT]    &= ~(1ULL << FP_NF_FLAG_FORCE_NAT_CONNTRACK);
		fp_shared->nf_conf.enabled_hook[nf_vr][FP_NF_IP_POST_ROUTING] &= ~(1ULL << FP_NF_FLAG_FORCE_NAT_CONNTRACK);
	}
	return 0;
}

/* copy stats from current table */
void fp_nf_update_nftable_stats(const fp_nftable_t *cur_table,
				const fp_nftable_t *new_table)
{
	unsigned int h, s;
	uint32_t i, j, cur_first, cur_last, new_first, new_last;
	const struct fp_nfrule *r_cur;
	struct fp_nfrule *r_new;

	uint8_t cur = fp_shared->fp_nf_current_table;

	cur_first = fp_nf_first_ruleid(cur_table);
	cur_last = fp_nf_last_ruleid(cur_table);
	new_first = fp_nf_first_ruleid(new_table);
	new_last = fp_nf_last_ruleid(new_table);

	for (i = cur_first; i <= cur_last; i++) {
		r_cur = &fp_shared->fp_nf_rules[cur][i];
		if (r_cur->uid == 0)
			continue;
#ifdef HA_SUPPORT
		fpm_ha_check_request();
#endif
		for (j = new_first; j < new_last; j++) {
			r_new = &fp_shared->fp_nf_rules[!cur][j];
			if (r_cur->uid != r_new->uid)
				continue;
			/* we found the same uid in current table */
			for (s = 0; s < FP_NF_STATS_NUM; s++) {
				r_new->stats[s].pcnt = r_cur->stats[s].pcnt;
				r_new->stats[s].bcnt = r_cur->stats[s].bcnt;
			}
			break;
		}
	}

	/* update default policy stats because the uid is not the same in the
	 * new table */
	for (h = 0; h < FP_NF_IP_NUMHOOKS; h++) {
		int cur_verdict, new_verdict;

		/* check if hook is valid for this table */
		if ((cur_table->fpnftable_valid_hooks & (1<<h)) == 0)
			continue;

		r_cur = &fp_shared->fp_nf_rules[cur][cur_table->fpnftable_underflow[h]];
		r_new = &fp_shared->fp_nf_rules[!cur][new_table->fpnftable_underflow[h]];
		cur_verdict = r_cur->target.data.standard.verdict;
		new_verdict = r_new->target.data.standard.verdict;

		/* update policy stats if verdict is the same */
		if (cur_verdict == new_verdict) {
			for (s = 0; s < FP_NF_STATS_NUM; s++) {
				r_new->stats[s].pcnt = r_cur->stats[s].pcnt;
				r_new->stats[s].bcnt = r_cur->stats[s].bcnt;
			}
		}
	}
}

#ifdef CONFIG_MCORE_NETFILTER_IPV6
/* copy stats from current table */
void fp_nf6_update_nftable_stats(const fp_nf6table_t *cur_table,
				 const fp_nf6table_t *new_table)
{
	uint8_t h, s;
	uint32_t i, j, cur_first, cur_last, new_first, new_last;
	const struct fp_nf6rule *r_cur;
	struct fp_nf6rule *r_new;

	const uint8_t cur = fp_shared->fp_nf6_current_table;

	cur_first = fp_nf6_first_ruleid(cur_table);
	cur_last = fp_nf6_last_ruleid(cur_table);
	new_first = fp_nf6_first_ruleid(new_table);
	new_last = fp_nf6_last_ruleid(new_table);

	for (i = cur_first; i <= cur_last; i++) {
		r_cur = &fp_shared->fp_nf6_rules[cur][i];
		if (r_cur->uid == 0)
			continue;
#ifdef HA_SUPPORT
		fpm_ha_check_request();
#endif
		for (j = new_first; j < new_last; j++) {
			r_new = &fp_shared->fp_nf6_rules[!cur][j];
			if (r_cur->uid != r_new->uid)
				continue;
			/* we found the same uid in current table */
			for (s = 0; s < FP_NF_STATS_NUM; s++) {
				r_new->stats[s].pcnt = r_cur->stats[s].pcnt;
				r_new->stats[s].bcnt = r_cur->stats[s].bcnt;
			}
			break;
		}
	}

	/* update default policy stats because the uid is not the same in the
	 * new table */
	for (h = 0; h < FP_NF_IP_NUMHOOKS; h++) {
		int cur_verdict, new_verdict;

		/* check if hook is valid for this table */
		if ((cur_table->fpnf6table_valid_hooks & (1<<h)) == 0)
			continue;

		r_cur = &fp_shared->fp_nf6_rules[cur][cur_table->fpnf6table_underflow[h]];
		r_new = &fp_shared->fp_nf6_rules[!cur][new_table->fpnf6table_underflow[h]];
		cur_verdict = r_cur->target.data.standard.verdict;
		new_verdict = r_new->target.data.standard.verdict;

		/* update policy stats if verdict is the same */
		if (cur_verdict == new_verdict) {
			for (s = 0; s < FP_NF_STATS_NUM; s++) {
				r_new->stats[s].pcnt = r_cur->stats[s].pcnt;
				r_new->stats[s].bcnt = r_cur->stats[s].bcnt;
			}
		}
	}
}
#endif

static inline const char *fp_nf_sctp_chunktype2str(uint8_t type)
{
	switch (type) {
	case SCTP_CID_DATA:
		return "SCTP_CID_DATA";
	case SCTP_CID_INIT:
		return "SCTP_CID_INIT";
	case SCTP_CID_INIT_ACK:
		return "SCTP_CID_INIT_ACK";
	case SCTP_CID_SACK:
		return "SCTP_CID_SACK";
	case SCTP_CID_HEARTBEAT:
		return "SCTP_CID_HEARTBEAT";
	case SCTP_CID_HEARTBEAT_ACK:
		return "SCTP_CID_HEARTBEAT_ACK";
	case SCTP_CID_ABORT:
		return "SCTP_CID_ABORT";
	case SCTP_CID_SHUTDOWN:
		return "SCTP_CID_SHUTDOWN";
	case SCTP_CID_SHUTDOWN_ACK:
		return "SCTP_CID_SHUTDOWN_ACK";
	case SCTP_CID_ERROR:
		return "SCTP_CID_ERROR";
	case SCTP_CID_COOKIE_ECHO:
		return "SCTP_CID_COOKIE_ECHO";
	case SCTP_CID_COOKIE_ACK:
		return "SCTP_CID_COOKIE_ACK";
	case SCTP_CID_ECN_ECNE:
		return "SCTP_CID_ECN_ECNE";
	case SCTP_CID_ECN_CWR:
		return "SCTP_CID_ECN_CWR";
	case SCTP_CID_SHUTDOWN_COMPLETE:
		return "SCTP_CID_SHUTDOWN_COMPLETE";
	case SCTP_CID_FWD_TSN:
		return "SCTP_CID_FWD_TSN";
	case SCTP_CID_ASCONF:
		return "SCTP_CID_ASCONF";
	case SCTP_CID_ASCONF_ACK:
		return "SCTP_CID_ASCONF_ACK";
	default:
		return "unknown";
	}
}

static inline char *fp_nf_sctp_chunkflags2str(const struct fp_nfrule *rule,
					      uint8_t type)
{
	static char flags[64];
	int i;

	flags[0] = 0;
#define __sctp(r)    r->l3.data.sctp
	for (i = 0; i < __sctp(rule).flag_count; i++) {
		if (type == SCTP_CID_DATA &&
		    __sctp(rule).flag_info[i].chunktype == SCTP_CID_DATA &&
		    __sctp(rule).flag_info[i].flag & 0x7)
			sprintf(flags, ":%s%s%s(0x%02x/0x%02x)",
			        __sctp(rule).flag_info[i].flag & 0x4 ? "U" : "",
			        __sctp(rule).flag_info[i].flag & 0x2 ? "B" : "",
			        __sctp(rule).flag_info[i].flag & 0x1 ? "E" : "",
			        __sctp(rule).flag_info[i].flag,
			        __sctp(rule).flag_info[i].flag_mask);
		if (type == SCTP_CID_ABORT &&
		    __sctp(rule).flag_info[i].chunktype == SCTP_CID_ABORT &&
		    __sctp(rule).flag_info[i].flag & 0x1)
			sprintf(flags, ":T(0x%02x/0x%02x)",
			        __sctp(rule).flag_info[i].flag,
			        __sctp(rule).flag_info[i].flag_mask);
		if (type == SCTP_CID_SHUTDOWN_COMPLETE &&
		    __sctp(rule).flag_info[i].chunktype == SCTP_CID_SHUTDOWN_COMPLETE &&
		    __sctp(rule).flag_info[i].flag & 0x1)
			sprintf(flags, ":T(0x%02x/0x%02x)",
			        __sctp(rule).flag_info[i].flag,
			        __sctp(rule).flag_info[i].flag_mask);
	}
#undef __sctp

	return flags;
}

#ifdef CONFIG_MCORE_NETFILTER_IPV6
static inline char *fp_nf6_sctp_chunkflags2str(const struct fp_nf6rule *rule,
					       uint8_t type)
{
	static char flags[64];
	int i;

	flags[0] = 0;
#define __sctp(r)    r->l3.data.sctp
	for (i = 0; i < __sctp(rule).flag_count; i++) {
		if (type == SCTP_CID_DATA &&
		    __sctp(rule).flag_info[i].chunktype == SCTP_CID_DATA &&
		    __sctp(rule).flag_info[i].flag & 0x7)
			sprintf(flags, ":%s%s%s(0x%02x/0x%02x)",
			        __sctp(rule).flag_info[i].flag & 0x4 ? "U" : "",
			        __sctp(rule).flag_info[i].flag & 0x2 ? "B" : "",
			        __sctp(rule).flag_info[i].flag & 0x1 ? "E" : "",
			        __sctp(rule).flag_info[i].flag,
			        __sctp(rule).flag_info[i].flag_mask);
		if (type == SCTP_CID_ABORT &&
		    __sctp(rule).flag_info[i].chunktype == SCTP_CID_ABORT &&
		    __sctp(rule).flag_info[i].flag & 0x1)
			sprintf(flags, ":T(0x%02x/0x%02x)",
			        __sctp(rule).flag_info[i].flag,
			        __sctp(rule).flag_info[i].flag_mask);
		if (type == SCTP_CID_SHUTDOWN_COMPLETE &&
		    __sctp(rule).flag_info[i].chunktype == SCTP_CID_SHUTDOWN_COMPLETE &&
		    __sctp(rule).flag_info[i].flag & 0x1)
			sprintf(flags, ":T(0x%02x/0x%02x)",
			        __sctp(rule).flag_info[i].flag,
			        __sctp(rule).flag_info[i].flag_mask);
	}
#undef __sctp

	return flags;
}
#endif /* CONFIG_MCORE_NETFILTER_IPV6 */

#define _V2S(v) case v: verdict = #v ; break;
int fp_nf_dump_nftable(uint8_t tb, uint16_t nf_vr, int mode)
{
	fp_nftable_t *table;
	uint32_t r, first_rule, last_rule;
	const char *verdict = "unknow";
	const uint8_t cur = fp_shared->fp_nf_current_table;

	if (tb >= FP_NF_TABLE_NUM || nf_vr >= FP_NF_MAX_VR)
		return -1;

	table = &fp_shared->fp_nf_tables[cur][nf_vr][tb];

	fp_log_common(LOG_DEBUG, "Bypass netfilter hook: %s\n",
	              (!fp_shared->conf.s.do_netfilter) ? "yes" : "no");
	fp_log_common(LOG_DEBUG, "NF Table: %s (family: IPv4)\n", fp_table_name(tb));
	fp_log_common(LOG_DEBUG, "             pre   in  fwd  out post\n");
	fp_log_common(LOG_DEBUG, "Valid hook:    %c    %c    %c    %c    %c\n",
	              (table->fpnftable_valid_hooks & (1<<FP_NF_IP_PRE_ROUTING)) ?  'x' : ' ',
	              (table->fpnftable_valid_hooks & (1<<FP_NF_IP_LOCAL_IN)) ?     'x' : ' ',
	              (table->fpnftable_valid_hooks & (1<<FP_NF_IP_FORWARD)) ?      'x' : ' ',
	              (table->fpnftable_valid_hooks & (1<<FP_NF_IP_LOCAL_OUT)) ?    'x' : ' ',
	              (table->fpnftable_valid_hooks & (1<<FP_NF_IP_POST_ROUTING)) ? 'x' : ' ');
	fp_log_common(LOG_DEBUG, "Hooks:      %4u %4u %4u %4u %4u\n",
	              table->fpnftable_hook_entry[0],
	              table->fpnftable_hook_entry[1],
	              table->fpnftable_hook_entry[2],
	              table->fpnftable_hook_entry[3],
	              table->fpnftable_hook_entry[4]);
	fp_log_common(LOG_DEBUG, "Underflows: %4u %4u %4u %4u %4u\n",
	              table->fpnftable_underflow[0],
	              table->fpnftable_underflow[1],
	              table->fpnftable_underflow[2],
	              table->fpnftable_underflow[3],
	              table->fpnftable_underflow[4]);

	if (!mode)
		return 0;

#ifdef CONFIG_MCORE_NFTABLE_SEQNUM
	fp_log_common(LOG_DEBUG, "Sequence Number: %" PRIu32 "\n", table->fpnftable_seqnum);
#endif

	first_rule = fp_nf_first_ruleid(table);
	last_rule = fp_nf_last_ruleid(table);

	for (r = first_rule; r <= last_rule; r++) {
		uint64_t pcnt, bcnt;
		unsigned int s, c;
		struct fp_nfrule *rule = &fp_shared->fp_nf_rules[cur][r];

		for (s = 0, pcnt = 0, bcnt = 0; s < FP_NF_STATS_NUM; s++) {
			pcnt += rule->stats[s].pcnt;
			bcnt += rule->stats[s].bcnt;
		}

		if (mode == FP_NF_DUMP_NFTABLE_MODE_NONZERO && pcnt == 0)
			continue;

		fp_log_common(LOG_DEBUG, "Rule #%d (uid:0x%x):\n", r, rule->uid);
		fp_log_common(LOG_DEBUG, "\tStats: pkt: %" PRIu64 ", byte: %" PRIu64 "\n",
			      pcnt, bcnt);

		/* IPv4 header */
		fp_log_common(LOG_DEBUG, "\tIPv4 header:\n");
		fp_log_common(LOG_DEBUG, "\t\tSrc: " FP_NIPQUAD_FMT
			      ", mask: " FP_NIPQUAD_FMT  "\n",
			      FP_NIPQUAD(rule->l2.ipv4.src),
			      FP_NIPQUAD(rule->l2.ipv4.smsk));
		fp_log_common(LOG_DEBUG, "\t\tDst: " FP_NIPQUAD_FMT
			      ", mask: " FP_NIPQUAD_FMT  "\n",
			      FP_NIPQUAD(rule->l2.ipv4.dst),
			      FP_NIPQUAD(rule->l2.ipv4.dmsk));
		fp_log_common(LOG_DEBUG, "\t\tIn iface: %s, len: %d\n",
			      rule->l2.ipv4.iniface,
			      rule->l2.ipv4.iniface_len);
		fp_log_common(LOG_DEBUG, "\t\tOut iface: %s, len: %d\n",
			      rule->l2.ipv4.outiface,
			      rule->l2.ipv4.outiface_len);
		fp_log_common(LOG_DEBUG, "\t\tProto: %u, Flags: %u, Invflags: %u\n",
			      rule->l2.ipv4.proto,
			      rule->l2.ipv4.flags,
			      rule->l2.ipv4.invflags);

		if (rule->l2_opt.dscp)
			fp_log_common(LOG_DEBUG, "\tDSCP options: 0x%x (inv: 0x%x)\n",
				      rule->l2_opt.dscp,
				      rule->l2_opt.invdscp);
#ifndef CONFIG_MCORE_NF_TABLE_PER_VR
		if (rule->l2_opt.vrfid == FP_NF_VRFID_UNSPECIFIED)
			fp_log_common(LOG_DEBUG, "\tVRF-ID: all\n");
		else
			fp_log_common(LOG_DEBUG, "\tVRF-ID: %d\n",
				      rule->l2_opt.vrfid);
#endif

		if (rule->l2_opt.opt & FP_NF_l2OPT_RATELIMIT)
			fp_log_common(LOG_DEBUG, "\tRatelimit: credit_cap: %u cost: %u\n",
				      rule->l2_opt.rateinfo.credit_cap,
				      rule->l2_opt.rateinfo.cost);

		if (rule->l2_opt.opt & FP_NF_l2OPT_MARK)
			fp_log_common(LOG_DEBUG, "\tmark: 0x%x mask: 0x%x (inv: 0x%x)\n",
				      rule->l2_opt.mark.mark,
				      rule->l2_opt.mark.mask,
				      rule->l2_opt.mark.invert);

		if (rule->l2_opt.opt & FP_NF_l2OPT_MAC)
			fp_log_common(LOG_DEBUG, "\tMAC srcaddr: " FP_NMAC_FMT
					" invert: 0x%x\n", FP_NMAC(rule->l2_opt.mac.srcaddr),
					rule->l2_opt.mac.invert);

		if (rule->l2_opt.opt & FP_NF_l2OPT_PHYSDEV)
			fp_log_common(LOG_DEBUG, "\tPHYSDEV invert: 0x%x, bitmask 0x%x\n"
				      "\t\tin: %s, mask len: 0x%x\n"
				      "\t\tout: %s, mask len: 0x%x\n"
				      "\t\tis-in: %s, is-out: %s, is-bridged: %s\n",
				      rule->l2_opt.physdev.invert,
				      rule->l2_opt.physdev.bitmask,
				      rule->l2_opt.physdev.physindev,
				      rule->l2_opt.physdev.physindev_len,
				      rule->l2_opt.physdev.physoutdev,
				      rule->l2_opt.physdev.physoutdev_len,
				      rule->l2_opt.physdev.bitmask & FP_XT_PHYSDEV_OP_ISIN ? "yes" : "no",
				      rule->l2_opt.physdev.bitmask & FP_XT_PHYSDEV_OP_ISOUT ? "yes" : "no",
				      rule->l2_opt.physdev.bitmask & FP_XT_PHYSDEV_OP_BRIDGED ? "yes" : "no");

		switch(rule->l3.type) {
		case FP_NF_L3_TYPE_UDP:
			fp_log_common(LOG_DEBUG, "\tUDP options:\n");
			fp_log_common(LOG_DEBUG, "\t\tSrc port range: %u - %u\n",
				      rule->l3.data.udp.spts[0],
				      rule->l3.data.udp.spts[1]);
			fp_log_common(LOG_DEBUG, "\t\tDst port range: %u - %u\n",
				      rule->l3.data.udp.dpts[0],
				      rule->l3.data.udp.dpts[1]);
			fp_log_common(LOG_DEBUG, "\t\tInvflags: %u\n",
				      rule->l3.data.udp.invflags);
			break;
		case FP_NF_L3_TYPE_TCP:
			fp_log_common(LOG_DEBUG, "\tTCP options:\n");
			fp_log_common(LOG_DEBUG, "\t\tSrc port range: %u - %u\n",
				      rule->l3.data.tcp.spts[0],
				      rule->l3.data.tcp.spts[1]);
			fp_log_common(LOG_DEBUG, "\t\tDst port range: %u - %u\n",
				      rule->l3.data.tcp.dpts[0],
				      rule->l3.data.tcp.dpts[1]);
			fp_log_common(LOG_DEBUG, "\t\tOption: %u, flags mask: %u\n",
				      rule->l3.data.tcp.option,
				      rule->l3.data.tcp.flg_mask);
			fp_log_common(LOG_DEBUG, "\t\tFlags compare: %u, invflags: %u\n",
				      rule->l3.data.tcp.flg_cmp,
				      rule->l3.data.tcp.invflags);
			break;
		case FP_NF_L3_TYPE_SCTP:
#define __sctp(x)    x->l3.data.sctp
			fp_log_common(LOG_DEBUG, "\tSCTP options:\n");
			fp_log_common(LOG_DEBUG, "\t\tSrc port range: %u - %u\n",
				      __sctp(rule).spts[0], __sctp(rule).spts[1]);
			fp_log_common(LOG_DEBUG, "\t\tDst port range: %u - %u\n",
				      __sctp(rule).dpts[0], __sctp(rule).dpts[1]);
			switch (__sctp(rule).chunk_match_type) {
			case FP_NF_SCTP_CHUNK_MATCH_ANY:
				fp_log_common(LOG_DEBUG, "\t\tMatch type: ANY\n");
				break;
			case FP_NF_SCTP_CHUNK_MATCH_ALL:
				fp_log_common(LOG_DEBUG, "\t\tMatch type: ALL\n");
				break;
			case FP_NF_SCTP_CHUNK_MATCH_ONLY:
				fp_log_common(LOG_DEBUG, "\t\tMatch type: ONLY\n");
				break;
			default:
				fp_log_common(LOG_DEBUG, "\t\tMatch type: unknown\n");
				break;
			}
			fp_log_common(LOG_DEBUG, "\t\tChunk types:\n");
			for (c = 0; c < FP_NF_SCTP_CHUNKMAP_SIZE; c++)
				if (__sctp(rule).chunkmap[c / (sizeof(uint32_t) * 8)] &
				    (1 << (c % (sizeof(uint32_t) * 8))))
					fp_log_common(LOG_DEBUG, "\t\t\t%s(%d)%s\n ",
						      fp_nf_sctp_chunktype2str(c), c,
						      fp_nf_sctp_chunkflags2str(rule, c));
			fp_log_common(LOG_DEBUG, "\t\tFlags:\n");
			if (__sctp(rule).flags & FP_NF_IPT_SCTP_SRC_PORTS)
				fp_log_common(LOG_DEBUG, "\t\t\tFP_NF_IPT_SCTP_SRC_PORTS\n");
			if (__sctp(rule).flags & FP_NF_IPT_SCTP_DEST_PORTS)
				fp_log_common(LOG_DEBUG, "\t\t\tFP_NF_IPT_SCTP_DEST_PORTS\n");
			if (__sctp(rule).flags & FP_NF_IPT_SCTP_CHUNK_TYPES)
				fp_log_common(LOG_DEBUG, "\t\t\tFP_NF_IPT_SCTP_CHUNK_TYPES\n");
			fp_log_common(LOG_DEBUG, "\t\tInverse Flags:\n");
			if (__sctp(rule).invflags & FP_NF_IPT_SCTP_SRC_PORTS)
				fp_log_common(LOG_DEBUG, "\t\t\tFP_NF_IPT_SCTP_SRC_PORTS\n");
			if (__sctp(rule).invflags & FP_NF_IPT_SCTP_DEST_PORTS)
				fp_log_common(LOG_DEBUG, "\t\t\tFP_NF_IPT_SCTP_DEST_PORTS\n");
			if (__sctp(rule).invflags & FP_NF_IPT_SCTP_CHUNK_TYPES)
				fp_log_common(LOG_DEBUG, "\t\t\tFP_NF_IPT_SCTP_CHUNK_TYPES\n");
			break;
#undef __sctp
		case FP_NF_L3_TYPE_ICMP:
			fp_log_common(LOG_DEBUG, "\tICMP options:\n");
			fp_log_common(LOG_DEBUG, "\t\tType: %u, code range: %u - %u\n",
				      rule->l3.data.icmp.type,
				      rule->l3.data.icmp.code[0],
				      rule->l3.data.icmp.code[1]);
			fp_log_common(LOG_DEBUG, "\t\tInvflags: %u\n",
				      rule->l3.data.udp.invflags);
			break;
		default:
			break;
		}

		if (rule->l3_opt.opt & FP_NF_l3OPT_MULTIPORT) {
			fp_log_common(LOG_DEBUG, "\tMultiport:\n\t\t");
			switch (rule->l3_opt.multiport.flags) {
			case FP_NF_MULTIPORT_FLAG_SRC:
				fp_log_common(LOG_DEBUG, "Src ");
				break;
			case FP_NF_MULTIPORT_FLAG_DST:
				fp_log_common(LOG_DEBUG, "Dst ");
				break;
			case FP_NF_MULTIPORT_FLAG_ANY:
				fp_log_common(LOG_DEBUG, "Any ");
				break;
			default:
				break;
			}
			fp_log_common(LOG_DEBUG, "ports: ");
			int i;
			for (i=0; i<rule->l3_opt.multiport.count-1; i++) {
				fp_log_common(LOG_DEBUG, "%d%c",
						rule->l3_opt.multiport.ports[i],
						rule->l3_opt.multiport.pflags[i] ? ':' : ',');
			}
			fp_log_common(LOG_DEBUG, "%d\n", rule->l3_opt.multiport.ports[i]);
			fp_log_common(LOG_DEBUG, "\t\tInvert: 0x%x\n", rule->l3_opt.multiport.invert);
		}

		if (rule->l3.state == FP_NF_L3_STATE_ESTABLISHED)
			fp_log_common(LOG_DEBUG, "\tState: ESTABLISHED \n");
		else if (rule->l3.state == FP_NF_L3_STATE_EXCEPTION)
			fp_log_common(LOG_DEBUG, "\tState: EXCEPTION \n");

		switch(rule->target.type) {
		case FP_NF_TARGET_TYPE_STANDARD:
			if (rule->target.data.standard.verdict < 0) {
				switch (- rule->target.data.standard.verdict - 1) {
					_V2S(FP_NF_DROP);
					_V2S(FP_NF_ACCEPT);
					_V2S(FP_NF_STOLEN);
					_V2S(FP_NF_QUEUE);
					_V2S(FP_NF_REPEAT);
					_V2S(FP_NF_STOP);
				}
				fp_log_common(LOG_DEBUG, "\tTarget: STANDARD, verdict: %s\n", verdict);
			} else
				fp_log_common(LOG_DEBUG, "\tTarget: STANDARD, verdict: %d\n",
					      rule->target.data.standard.verdict);
			break;
		case FP_NF_TARGET_TYPE_ERROR:
#if FP_NF_ERRORNAME
			fp_log_common(LOG_DEBUG, "\tTarget: ERROR, error name:  %s\n",
				      rule->target.data.error.errorname);
#else
			fp_log_common(LOG_DEBUG, "\tTarget: ERROR\n");
#endif
			break;
		case FP_NF_TARGET_TYPE_MARK_V2:
			fp_log_common(LOG_DEBUG, "\tTarget: MARK V2, mark: 0x%x, mask: 0x%x\n",
				      rule->target.data.mark.mark,
				      rule->target.data.mark.mask);
			break;
		case FP_NF_TARGET_TYPE_DSCP:
			fp_log_common(LOG_DEBUG, "\tTarget: DSCP, dscp: 0x%x\n",
				      rule->target.data.dscp.dscp);
			break;
		case FP_NF_TARGET_TYPE_REJECT:
			fp_log_common(LOG_DEBUG, "\tTarget: REJECT\n");
			break;
		case FP_NF_TARGET_TYPE_LOG:
			fp_log_common(LOG_DEBUG, "\tTarget: LOG\n");
			break;
		case FP_NF_TARGET_TYPE_ULOG:
			fp_log_common(LOG_DEBUG, "\tTarget: ULOG\n");
			break;
		case FP_NF_TARGET_TYPE_MASQUERADE:
#ifdef FP_DEBUG_NF_TABLE_NAT
			fp_log_common(LOG_DEBUG, "\tTarget: MASQUERADE, to source: ");
			if (rule->target.data.nat.min_ip == rule->target.data.nat.max_ip) {
				fp_log_common(LOG_DEBUG, FP_NIPQUAD_FMT,
					      FP_NIPQUAD(rule->target.data.nat.min_ip));
			} else {
				fp_log_common(LOG_DEBUG, "["FP_NIPQUAD_FMT"-"FP_NIPQUAD_FMT"]",
					      FP_NIPQUAD(rule->target.data.nat.min_ip),
					      FP_NIPQUAD(rule->target.data.nat.max_ip));
			}

			if (rule->target.data.nat.min_port != 0) {
				if (rule->target.data.nat.min_port == rule->target.data.nat.max_port) {
					fp_log_common(LOG_DEBUG, ":%d",rule->target.data.nat.min_port);
				} else {
					fp_log_common(LOG_DEBUG, ":[%d-%d]",
						      rule->target.data.nat.min_port,
						      rule->target.data.nat.max_port);
				}
			}
			fp_log_common(LOG_DEBUG, "\n");
#else
			fp_log_common(LOG_DEBUG, "\tTarget: MASQUERADE\n");
#endif /* FP_DEBUG_NF_TABLE_NAT */
			break;
		case FP_NF_TARGET_TYPE_SNAT:
#ifdef FP_DEBUG_NF_TABLE_NAT
			fp_log_common(LOG_DEBUG, "\tTarget: SNAT, to source: ");
			if (rule->target.data.nat.min_ip == rule->target.data.nat.max_ip) {
				fp_log_common(LOG_DEBUG, FP_NIPQUAD_FMT,
					      FP_NIPQUAD(rule->target.data.nat.min_ip));
			} else {
				fp_log_common(LOG_DEBUG, "["FP_NIPQUAD_FMT"-"FP_NIPQUAD_FMT"]",
					      FP_NIPQUAD(rule->target.data.nat.min_ip),
					      FP_NIPQUAD(rule->target.data.nat.max_ip));
			}

			if (rule->target.data.nat.min_port != 0) {
				if (rule->target.data.nat.min_port == rule->target.data.nat.max_port) {
					fp_log_common(LOG_DEBUG, ":%d",rule->target.data.nat.min_port);
				} else {
					fp_log_common(LOG_DEBUG, ":[%d-%d]",
						      rule->target.data.nat.min_port,
						      rule->target.data.nat.max_port);
				}
			}
			fp_log_common(LOG_DEBUG, "\n");
#else
			fp_log_common(LOG_DEBUG, "\tTarget: SNAT\n");
#endif /* FP_DEBUG_NF_TABLE_NAT */
			break;
		case FP_NF_TARGET_TYPE_DNAT:
#ifdef FP_DEBUG_NF_TABLE_NAT
			fp_log_common(LOG_DEBUG, "\tTarget: DNAT, to destination: ");
			if (rule->target.data.nat.min_ip == rule->target.data.nat.max_ip) {
				fp_log_common(LOG_DEBUG, FP_NIPQUAD_FMT,
					      FP_NIPQUAD(rule->target.data.nat.min_ip));
			} else {
				fp_log_common(LOG_DEBUG, "["FP_NIPQUAD_FMT"-"FP_NIPQUAD_FMT"]",
					      FP_NIPQUAD(rule->target.data.nat.min_ip),
					      FP_NIPQUAD(rule->target.data.nat.max_ip));
			}

			if (rule->target.data.nat.min_port != 0) {
				if (rule->target.data.nat.min_port == rule->target.data.nat.max_port) {
					fp_log_common(LOG_DEBUG, ":%d",rule->target.data.nat.min_port);
				} else {
					fp_log_common(LOG_DEBUG, ":[%d-%d]",
						      rule->target.data.nat.min_port,
						      rule->target.data.nat.max_port);
				}
			}
			fp_log_common(LOG_DEBUG, "\n");
#else
			fp_log_common(LOG_DEBUG, "\tTarget: DNAT\n");
#endif /* FP_DEBUG_NF_TABLE_NAT */
			break;
		case FP_NF_TARGET_TYPE_TCPMSS:
			fp_log_common(LOG_DEBUG, "\tTarget: TCPMSS\n");
			break;
		case FP_NF_TARGET_TYPE_DEV:
			fp_log_common(LOG_DEBUG, "\tTarget: DEV, to iface <%s>\n",
				      rule->target.data.dev.ifname);
			if (rule->target.data.dev.flags & FP_NF_DEV_FLAG_SET_MARK) {
				fp_log_common(LOG_DEBUG, "\t\tset-mark 0x%x\n",
				      rule->target.data.dev.mark);
			}
			break;
		case FP_NF_TARGET_TYPE_CHECKSUM:
			fp_log_common(LOG_DEBUG, "\tTarget: CHECKSUM\n");
			break;
		default:
			fp_log_common(LOG_DEBUG, "\tTarget: unknown (verdict is DROP)\n");
			break;
		}
	}

	return 0;
}

int fp_nf_print_summary(uint8_t table, uint16_t nf_vr)
{
	const int cur = fp_shared->fp_nf_current_table;
	const fp_nftable_t *tb;

	if (nf_vr >= FP_NF_MAX_VR || table >= FP_NF_TABLE_NUM)
		return -1;

	tb = &fp_shared->fp_nf_tables[cur][nf_vr][table];

	fp_log_common(LOG_DEBUG, "Bypass netfilter hook: %s\n",
		      (!fp_shared->conf.s.do_netfilter) ? "yes" : "no");
	fp_log_common(LOG_DEBUG, "NF Table: %s (family: IPv4): %d rules\n",
		      fp_table_name(table), tb->fpnftable_rules_count);

	return 0;
}

#ifdef CONFIG_MCORE_NETFILTER_IPV6

int fp_nf6_update_bypass(uint8_t bypass)
{
	fp_shared->conf.s.do_netfilter6 = !bypass;
	fp_shared->conf.s.do_nf6_cache = !bypass;
	return 0;
}

int fp_nf6_dump_nftable(uint8_t tb, uint16_t nf_vr, int mode)
{
	fp_nf6table_t *table;
	uint32_t r, first_rule, last_rule;
	const char *verdict = "unknow";
	const uint8_t cur = fp_shared->fp_nf6_current_table;

	if (tb >= FP_NF6_TABLE_NUM || nf_vr >= FP_NF_MAX_VR)
		return -1;

	table = &fp_shared->fp_nf6_tables[cur][nf_vr][tb];

	fp_log_common(LOG_DEBUG, "Bypass netfilter hook: %s\n",
	              (!fp_shared->conf.s.do_netfilter6) ? "yes" : "no");
	fp_log_common(LOG_DEBUG, "NF Table: %s (family: IPv6)\n", fp_table_name(tb));
	fp_log_common(LOG_DEBUG, "             pre   in  fwd  out post\n");
	fp_log_common(LOG_DEBUG, "Valid hook:    %c    %c    %c    %c    %c\n",
	              (table->fpnf6table_valid_hooks & (1<<FP_NF_IP_PRE_ROUTING)) ?  'x' : ' ',
	              (table->fpnf6table_valid_hooks & (1<<FP_NF_IP_LOCAL_IN)) ?     'x' : ' ',
	              (table->fpnf6table_valid_hooks & (1<<FP_NF_IP_FORWARD)) ?      'x' : ' ',
	              (table->fpnf6table_valid_hooks & (1<<FP_NF_IP_LOCAL_OUT)) ?    'x' : ' ',
	              (table->fpnf6table_valid_hooks & (1<<FP_NF_IP_POST_ROUTING)) ? 'x' : ' ');
	fp_log_common(LOG_DEBUG, "Hooks:      %4u %4u %4u %4u %4u\n",
	              table->fpnf6table_hook_entry[0],
	              table->fpnf6table_hook_entry[1],
	              table->fpnf6table_hook_entry[2],
	              table->fpnf6table_hook_entry[3],
	              table->fpnf6table_hook_entry[4]);
	fp_log_common(LOG_DEBUG, "Underflows: %4u %4u %4u %4u %4u\n",
	              table->fpnf6table_underflow[0],
	              table->fpnf6table_underflow[1],
	              table->fpnf6table_underflow[2],
	              table->fpnf6table_underflow[3],
	              table->fpnf6table_underflow[4]);

#ifdef CONFIG_MCORE_NF6TABLE_SEQNUM
	fp_log_common(LOG_DEBUG, "Sequence Number: %" PRIu32 "\n", table->fpnf6table_seqnum);
#endif

	if (!mode)
		return 0;

	first_rule = fp_nf6_first_ruleid(table);
	last_rule = fp_nf6_last_ruleid(table);

	for (r = first_rule; r <= last_rule; r++) {
		uint64_t pcnt, bcnt;
		unsigned int s, c;
		struct fp_nf6rule *rule = &fp_shared->fp_nf6_rules[cur][r];

		for (s = 0, pcnt = 0, bcnt = 0; s < FP_NF_STATS_NUM; s++) {
			pcnt += rule->stats[s].pcnt;
			bcnt += rule->stats[s].bcnt;
		}

		if (mode == FP_NF_DUMP_NFTABLE_MODE_NONZERO && pcnt == 0)
			continue;

		fp_log_common(LOG_DEBUG, "Rule #%d (uid:0x%x):\n", r, rule->uid);
		fp_log_common(LOG_DEBUG, "\tStats: pkt: %" PRIu64 ", byte: %" PRIu64 "\n", pcnt, bcnt);

		/* IPv6 header */
		fp_log_common(LOG_DEBUG, "\tIPv6 header:\n");
		fp_log_common(LOG_DEBUG, "\t\tSrc:   " FP_NIP6_FMT
			      "\n\t\tsmask: " FP_NIP6_FMT  "\n",
			      FP_NIP6(rule->l2.ipv6.src),
			      FP_NIP6(rule->l2.ipv6.smsk));
		fp_log_common(LOG_DEBUG, "\t\tDst:   " FP_NIP6_FMT
			      "\n\t\tdmask: " FP_NIP6_FMT  "\n",
			      FP_NIP6(rule->l2.ipv6.dst),
			      FP_NIP6(rule->l2.ipv6.dmsk));
		fp_log_common(LOG_DEBUG, "\t\tIn iface: %s, len: %d\n",
			      rule->l2.ipv6.iniface,
			      rule->l2.ipv6.iniface_len);
		fp_log_common(LOG_DEBUG, "\t\tOut iface: %s, len: %d\n",
			      rule->l2.ipv6.outiface,
			      rule->l2.ipv6.outiface_len);
		fp_log_common(LOG_DEBUG, "\t\tProto: %u, Flags: %u, Invflags: %u\n",
			      rule->l2.ipv6.proto,
			      rule->l2.ipv6.flags,
			      rule->l2.ipv6.invflags);

		if (rule->l2_opt.dscp)
			fp_log_common(LOG_DEBUG, "\tDSCP options: 0x%x (inv: 0x%x)\n",
				      rule->l2_opt.dscp,
				      rule->l2_opt.invdscp);
#ifndef CONFIG_MCORE_NF_TABLE_PER_VR
		if (rule->l2_opt.vrfid == FP_NF_VRFID_UNSPECIFIED)
			fp_log_common(LOG_DEBUG, "\tVRF-ID: all\n");
		else
			fp_log_common(LOG_DEBUG, "\tVRF-ID: %d\n",
				      rule->l2_opt.vrfid);
#endif

		if (rule->l2_opt.opt & FP_NF_l2OPT_RATELIMIT)
			fp_log_common(LOG_DEBUG, "\tRatelimit: credit_cap: %u cost: %u\n",
			       rule->l2_opt.rateinfo.credit_cap,
			       rule->l2_opt.rateinfo.cost);

		if (rule->l2_opt.opt & FP_NF_l2OPT_MARK)
			fp_log_common(LOG_DEBUG, "\tmark: 0x%x mask: 0x%x (inv: 0x%x)\n",
			       rule->l2_opt.mark.mark,
			       rule->l2_opt.mark.mask,
			       rule->l2_opt.mark.invert);

		if (rule->l2_opt.opt & FP_NF_l2OPT_FRAG)
			fp_log_common(LOG_DEBUG, "\tFrag: ids[0]: %u ids[1]: %u, Flags: %u, Invflags: %u\n",
			       rule->l2_opt.frag.ids[0],
			       rule->l2_opt.frag.ids[1],
			       rule->l2_opt.frag.flags,
			       rule->l2_opt.frag.invflags);

		if (rule->l2_opt.opt & FP_NF_l2OPT_MAC)
			fp_log_common(LOG_DEBUG, "\tMAC srcaddr: " FP_NMAC_FMT
					" invert: 0x%x\n", FP_NMAC(rule->l2_opt.mac.srcaddr),
					rule->l2_opt.mac.invert);

		if (rule->l2_opt.opt & FP_NF_l2OPT_PHYSDEV)
			fp_log_common(LOG_DEBUG, "\tPHYSDEV invert: 0x%x, bitmask 0x%x\n"
				      "\t\tin: %s, mask len: 0x%x\n"
				      "\t\tout: %s, mask len: 0x%x\n"
				      "\t\tis-in: %s, is-out: %s, is-bridged: %s\n",
				      rule->l2_opt.physdev.invert,
				      rule->l2_opt.physdev.bitmask,
				      rule->l2_opt.physdev.physindev,
				      rule->l2_opt.physdev.physindev_len,
				      rule->l2_opt.physdev.physoutdev,
				      rule->l2_opt.physdev.physoutdev_len,
				      rule->l2_opt.physdev.bitmask & FP_XT_PHYSDEV_OP_ISIN ? "yes" : "no",
				      rule->l2_opt.physdev.bitmask & FP_XT_PHYSDEV_OP_ISOUT ? "yes" : "no",
				      rule->l2_opt.physdev.bitmask & FP_XT_PHYSDEV_OP_BRIDGED ? "yes" : "no");


		switch(rule->l3.type) {
		case FP_NF_L3_TYPE_UDP:
			fp_log_common(LOG_DEBUG, "\tUDP options:\n");
			fp_log_common(LOG_DEBUG, "\t\tSrc port range: %u - %u\n",
				      rule->l3.data.udp.spts[0],
				      rule->l3.data.udp.spts[1]);
			fp_log_common(LOG_DEBUG, "\t\tDst port range: %u - %u\n",
				      rule->l3.data.udp.dpts[0],
				      rule->l3.data.udp.dpts[1]);
			fp_log_common(LOG_DEBUG, "\t\tInvflags: %u\n",
				      rule->l3.data.udp.invflags);
			break;
		case FP_NF_L3_TYPE_TCP:
			fp_log_common(LOG_DEBUG, "\tTCP options:\n");
			fp_log_common(LOG_DEBUG, "\t\tSrc port range: %u - %u\n",
				      rule->l3.data.tcp.spts[0],
				      rule->l3.data.tcp.spts[1]);
			fp_log_common(LOG_DEBUG, "\t\tDst port range: %u - %u\n",
				      rule->l3.data.tcp.dpts[0],
				      rule->l3.data.tcp.dpts[1]);
			fp_log_common(LOG_DEBUG, "\t\tOption: %u, flags mask: %u\n",
				      rule->l3.data.tcp.option,
				      rule->l3.data.tcp.flg_mask);
			fp_log_common(LOG_DEBUG, "\t\tFlags compare: %u, invflags: %u\n",
				      rule->l3.data.tcp.flg_cmp,
				      rule->l3.data.tcp.invflags);
			break;
		case FP_NF_L3_TYPE_SCTP:
#define __sctp(x)    x->l3.data.sctp
			fp_log_common(LOG_DEBUG, "\tSCTP options:\n");
			fp_log_common(LOG_DEBUG, "\t\tSrc port range: %u - %u\n",
				      __sctp(rule).spts[0], __sctp(rule).spts[1]);
			fp_log_common(LOG_DEBUG, "\t\tDst port range: %u - %u\n",
				      __sctp(rule).dpts[0], __sctp(rule).dpts[1]);
			switch (__sctp(rule).chunk_match_type) {
			case FP_NF_SCTP_CHUNK_MATCH_ANY:
				fp_log_common(LOG_DEBUG, "\t\tMatch type: ANY\n");
				break;
			case FP_NF_SCTP_CHUNK_MATCH_ALL:
				fp_log_common(LOG_DEBUG, "\t\tMatch type: ALL\n");
				break;
			case FP_NF_SCTP_CHUNK_MATCH_ONLY:
				fp_log_common(LOG_DEBUG, "\t\tMatch type: ONLY\n");
				break;
			default:
				fp_log_common(LOG_DEBUG, "\t\tMatch type: unknown\n");
				break;
			}
			fp_log_common(LOG_DEBUG, "\t\tChunk types:\n");
			for (c = 0; c < FP_NF_SCTP_CHUNKMAP_SIZE; c++)
				if (__sctp(rule).chunkmap[c / (sizeof(uint32_t) * 8)] &
				    (1 << (c % (sizeof(uint32_t) * 8))))
					fp_log_common(LOG_DEBUG, "\t\t\t%s(%d)%s\n ",
						      fp_nf_sctp_chunktype2str(c), c,
						      fp_nf6_sctp_chunkflags2str(rule, c));
			fp_log_common(LOG_DEBUG, "\t\tFlags:\n");
			if (__sctp(rule).flags & FP_NF_IPT_SCTP_SRC_PORTS)
				fp_log_common(LOG_DEBUG, "\t\t\tFP_NF_IPT_SCTP_SRC_PORTS\n");
			if (__sctp(rule).flags & FP_NF_IPT_SCTP_DEST_PORTS)
				fp_log_common(LOG_DEBUG, "\t\t\tFP_NF_IPT_SCTP_DEST_PORTS\n");
			if (__sctp(rule).flags & FP_NF_IPT_SCTP_CHUNK_TYPES)
				fp_log_common(LOG_DEBUG, "\t\t\tFP_NF_IPT_SCTP_CHUNK_TYPES\n");
			fp_log_common(LOG_DEBUG, "\t\tInverse Flags:\n");
			if (__sctp(rule).invflags & FP_NF_IPT_SCTP_SRC_PORTS)
				fp_log_common(LOG_DEBUG, "\t\t\tFP_NF_IPT_SCTP_SRC_PORTS\n");
			if (__sctp(rule).invflags & FP_NF_IPT_SCTP_DEST_PORTS)
				fp_log_common(LOG_DEBUG, "\t\t\tFP_NF_IPT_SCTP_DEST_PORTS\n");
			if (__sctp(rule).invflags & FP_NF_IPT_SCTP_CHUNK_TYPES)
				fp_log_common(LOG_DEBUG, "\t\t\tFP_NF_IPT_SCTP_CHUNK_TYPES\n");
			break;
#undef __sctp
		case FP_NF_L3_TYPE_ICMP:
			fp_log_common(LOG_DEBUG, "\tICMP options:\n");
			fp_log_common(LOG_DEBUG, "\t\tType: %u, code range: %u - %u\n",
				      rule->l3.data.icmp.type,
				      rule->l3.data.icmp.code[0],
				      rule->l3.data.icmp.code[1]);
			fp_log_common(LOG_DEBUG, "\t\tInvflags: %u\n",
				      rule->l3.data.udp.invflags);
			break;
		default:
			break;
		}

		if (rule->l3_opt.opt & FP_NF_l3OPT_MULTIPORT) {
			fp_log_common(LOG_DEBUG, "\tMultiport:\n\t\t");
			switch (rule->l3_opt.multiport.flags) {
			case FP_NF_MULTIPORT_FLAG_SRC:
				fp_log_common(LOG_DEBUG, "Src ");
				break;
			case FP_NF_MULTIPORT_FLAG_DST:
				fp_log_common(LOG_DEBUG, "Dst ");
				break;
			case FP_NF_MULTIPORT_FLAG_ANY:
				fp_log_common(LOG_DEBUG, "Any ");
				break;
			default:
				break;
			}
			fp_log_common(LOG_DEBUG, "ports: ");
			int i;
			for (i=0; i<rule->l3_opt.multiport.count-1; i++) {
				fp_log_common(LOG_DEBUG, "%d%c",
						rule->l3_opt.multiport.ports[i],
						rule->l3_opt.multiport.pflags[i] ? ':' : ',');
			}
			fp_log_common(LOG_DEBUG, "%d\n", rule->l3_opt.multiport.ports[i]);
			fp_log_common(LOG_DEBUG, "\t\tInvert: 0x%x\n", rule->l3_opt.multiport.invert);
		}

		switch(rule->target.type) {
		case FP_NF_TARGET_TYPE_STANDARD:
			if (rule->target.data.standard.verdict < 0) {
				switch (- rule->target.data.standard.verdict - 1) {
					_V2S(FP_NF_DROP);
					_V2S(FP_NF_ACCEPT);
					_V2S(FP_NF_STOLEN);
					_V2S(FP_NF_QUEUE);
					_V2S(FP_NF_REPEAT);
					_V2S(FP_NF_STOP);
				}
				fp_log_common(LOG_DEBUG, "\tTarget: STANDARD, verdict: %s\n", verdict);
			} else
				fp_log_common(LOG_DEBUG, "\tTarget: STANDARD, verdict: %d\n",
					      rule->target.data.standard.verdict);
			break;
		case FP_NF_TARGET_TYPE_ERROR:
#if FP_NF_ERRORNAME
			fp_log_common(LOG_DEBUG, "\tTarget: ERROR, error name:  %s\n",
				      rule->target.data.error.errorname);
#else
			fp_log_common(LOG_DEBUG, "\tTarget: ERROR\n");
#endif
			break;
		case FP_NF_TARGET_TYPE_MARK_V2:
			fp_log_common(LOG_DEBUG, "\tTarget: MARK V2, mark: 0x%x, mask: 0x%x\n",
				      rule->target.data.mark.mark,
				      rule->target.data.mark.mask);
			break;
		case FP_NF_TARGET_TYPE_DSCP:
			fp_log_common(LOG_DEBUG, "\tTarget: DSCP, dscp: 0x%x\n",
				      rule->target.data.dscp.dscp);
			break;
		case FP_NF_TARGET_TYPE_REJECT:
			fp_log_common(LOG_DEBUG, "\tTarget: REJECT\n");
			break;
		case FP_NF_TARGET_TYPE_LOG:
			fp_log_common(LOG_DEBUG, "\tTarget: LOG\n");
			break;
		case FP_NF_TARGET_TYPE_ULOG:
			fp_log_common(LOG_DEBUG, "\tTarget: ULOG\n");
			break;
		case FP_NF_TARGET_TYPE_TCPMSS:
			fp_log_common(LOG_DEBUG, "\tTarget: TCPMSS\n");
			break;
		case FP_NF_TARGET_TYPE_DEV:
			fp_log_common(LOG_DEBUG, "\tTarget: DEV, to iface <%s>\n",
				      rule->target.data.dev.ifname);
			if (rule->target.data.dev.flags & FP_NF6_DEV_FLAG_SET_MARK) {
				fp_log_common(LOG_DEBUG, "\t\tset-mark 0x%x\n",
				      rule->target.data.dev.mark);
			}
			break;
		default:
			fp_log_common(LOG_DEBUG, "\tTarget: unknown (verdict is DROP)\n");
			break;
		}
	}

	return 0;
}

int fp_nf6_print_summary(uint8_t table, uint16_t nf_vr)
{
	const int cur = fp_shared->fp_nf_current_table;
	const fp_nf6table_t *tb;

	if (nf_vr >= FP_NF_MAX_VR || table >= FP_NF6_TABLE_NUM)
		return -1;

	tb = &fp_shared->fp_nf6_tables[cur][nf_vr][table];

	fp_log_common(LOG_DEBUG, "Bypass IPv6 netfilter hook: %s\n",
		      (!fp_shared->conf.s.do_netfilter6) ? "yes" : "no");
	fp_log_common(LOG_DEBUG, "NF Table: %s (family: IPv6): %d rules\n",
		      fp_table_name(table), tb->fpnf6table_rules_count);

	return 0;
}
#endif /* CONFIG_MCORE_NETFILTER_IPV6 */
#undef _V2S

/**
 * Since all rules are stored in a global array, when changing the number
 * of rules in a table, all tables located "after" it must be updated.
 *
 * Their respective "hook_entries" and "underflows" must all be shifted by
 * a fixed "delta".
 *
 * IMPORTANT: Only the tables located *AFTER* the table given as parameter will
 * be modified. The table itself will be left unchanged.
 */
void fp_nf_relocate_tables(uint8_t table, uint16_t nf_vr, int delta)
{
	uint8_t t, h;
	uint16_t vr;
	fp_nftable_t *tb;
	const uint8_t next = !fp_shared->fp_nf_current_table;

	if (delta == 0)
		return;

	for (vr = nf_vr; vr < FP_NF_MAX_VR; vr++) {
		for (t = 0; t < FP_NF_TABLE_NUM; t++) {
			if (vr == nf_vr && t <= table)
				continue;
			tb = &fp_shared->fp_nf_tables[next][vr][t];
			for (h = 0; h < FP_NF_IP_NUMHOOKS; h++) {
				tb->fpnftable_hook_entry[h] += delta;
				tb->fpnftable_underflow[h] += delta;
			}
		}
	}
}

#ifdef CONFIG_MCORE_NETFILTER_IPV6
/**
 * See fp_nf_relocate_tables()
 */
void fp_nf6_relocate_tables(uint8_t table, uint16_t nf_vr, int delta)
{
	uint8_t t, h;
	uint16_t vr;
	fp_nf6table_t *tb;
	const uint8_t next = !fp_shared->fp_nf6_current_table;

	if (delta == 0)
		return;

	for (vr = nf_vr; vr < FP_NF_MAX_VR; vr++) {
		for (t = 0; t < FP_NF6_TABLE_NUM; t++) {
			if (vr == nf_vr && t <= table)
				continue;
			tb = &fp_shared->fp_nf6_tables[next][vr][t];
			for (h = 0; h < FP_NF_IP_NUMHOOKS; h++) {
				tb->fpnf6table_hook_entry[h] += delta;
				tb->fpnf6table_underflow[h] += delta;
			}
		}
	}
}
#endif

#ifdef CONFIG_MCORE_NF_CT
static void fp_nf_ct_print_summary(struct fp_nfct_entry *nfct, uint32_t index)
{
	fp_log_common(LOG_DEBUG, "#%08d/#%08x", index, ntohl(nfct->uid));
	fp_log_common(LOG_DEBUG, "\tproto %05u ",
		      nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto);
	fp_log_common(LOG_DEBUG, "\t[" FP_NIPQUAD_FMT ":%u -> " FP_NIPQUAD_FMT ":%u ",
		      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport),
		      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport));
	fp_log_common(LOG_DEBUG, "\t| " FP_NIPQUAD_FMT ":%u -> " FP_NIPQUAD_FMT ":%u]",
		      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport),
		      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport));
#ifdef CONFIG_MCORE_VRF
	fp_log_common(LOG_DEBUG, "\tVR%u",
		      nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid);
#endif
	fp_log_common(LOG_DEBUG, "\t%s%s%s%s%s\n",
	       nfct->flag & FP_NFCT_FLAG_UPDATE ? " [HIT]" : "",
	       nfct->flag & FP_NFCT_FLAG_SNAT ? " [SNAT]" : "",
	       nfct->flag & FP_NFCT_FLAG_DNAT ? " [DNAT]" : "",
	       nfct->flag & FP_NFCT_FLAG_ASSURED ? " [ASSURED]" : "",
	       nfct->flag & FP_NFCT_FLAG_END ? " [END]" : "");
#undef NF_CT_STATS_FMT
#undef NF_CT_STATS
#ifdef CONFIG_MCORE_NF_CT_BYTES
#define NF_CT_STATS_FMT "%10u pkt|%10u B"
#define NF_CT_STATS(dir) nfct->counters[dir].packets,	\
		nfct->counters[dir].bytes
#else
#define NF_CT_STATS_FMT "%10u"
#define NF_CT_STATS(dir) nfct->counters[dir].packets
#endif
	fp_log_common(LOG_DEBUG, "\t\t\t\tstats["NF_CT_STATS_FMT"|", NF_CT_STATS(FP_NF_IP_CT_DIR_ORIGINAL));
	fp_log_common(LOG_DEBUG, NF_CT_STATS_FMT"] \n", NF_CT_STATS(FP_NF_IP_CT_DIR_REPLY));
}


static void fp_nf_ct_print(struct fp_nfct_entry *nfct, uint32_t index)
{
	fp_log_common(LOG_DEBUG, "Flow: #%d - uid #%08x\n", index,
		      ntohl(nfct->uid));
#ifdef CONFIG_MCORE_NF_CT_CPEID
	if (nfct->flag & FP_NFCT_FLAG_FROM_CPE)
		fp_log_common(LOG_DEBUG, "\tFrom cpeid: " FP_NIPQUAD_FMT "\n",
			      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src));
	if (nfct->flag & FP_NFCT_FLAG_TO_CPE)
		fp_log_common(LOG_DEBUG, "\t  To cpeid: " FP_NIPQUAD_FMT "\n",
			      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src));
	fp_log_common(LOG_DEBUG, "\tPer CPE hash: prev=%u, next=%u\n",
		      FP_NF_CT_HASH_PREV_CPEID(*nfct),
		      nfct->hash_next_cpeid);
#endif
	fp_log_common(LOG_DEBUG, "\tProto: %u\n",
		      nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto);
	fp_log_common(LOG_DEBUG, "\tOriginal: src: " FP_NIPQUAD_FMT
		      ":%u -> dst: " FP_NIPQUAD_FMT  ":%u\n",
		      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport),
		      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport));
	fp_log_common(LOG_DEBUG, "\tReply:    src: " FP_NIPQUAD_FMT
		      ":%u -> dst: " FP_NIPQUAD_FMT  ":%u\n",
		      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport),
		      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport));
#ifdef CONFIG_MCORE_VRF
	fp_log_common(LOG_DEBUG, "\tVRF-ID: %u\n",
		      nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid);
#endif
	fp_log_common(LOG_DEBUG, "\tFlag: 0x%02x, update: %s, snat: %s, dnat: %s,\n"
		      "\t            assured: %s, end: %s\n",
		      nfct->flag,
		      nfct->flag & FP_NFCT_FLAG_UPDATE ? "yes" : "no",
		      nfct->flag & FP_NFCT_FLAG_SNAT ? "yes" : "no",
		      nfct->flag & FP_NFCT_FLAG_DNAT ? "yes" : "no",
		      nfct->flag & FP_NFCT_FLAG_ASSURED ? "yes" : "no",
		      nfct->flag & FP_NFCT_FLAG_END ? "yes" : "no");
#undef NF_CT_STATS_FMT
#undef NF_CT_STATS
#ifdef CONFIG_MCORE_NF_CT_BYTES
#define NF_CT_STATS_FMT "pkt: %u, bytes: %u\n\t\t"
#define NF_CT_STATS(dir) nfct->counters[dir].packets,	\
		nfct->counters[dir].bytes
#else
#define NF_CT_STATS_FMT "pkt: %u\n\t\t"
#define NF_CT_STATS(dir) nfct->counters[dir].packets
#endif
	fp_log_common(LOG_DEBUG, "\tStats:\n\t\t"
		      "Original: "NF_CT_STATS_FMT
		      "Reply:    "NF_CT_STATS_FMT"\n",
		      NF_CT_STATS(FP_NF_IP_CT_DIR_ORIGINAL),
		      NF_CT_STATS(FP_NF_IP_CT_DIR_REPLY));
}

void fp_nf_dump_nfct(uint32_t count, int summary)
{
	int i;

	fp_log_common(LOG_DEBUG, "Number of flows: %u/%u\n", fp_shared->fp_nf_ct.fp_nfct_count, FP_NF_CT_MAX);

	for (i = 0; i < FP_NF_CT_MAX && count > 0; i++, count--) {
		if (fp_shared->fp_nf_ct.fp_nfct[i].flag & FP_NFCT_FLAG_VALID) {
			if (summary)
				fp_nf_ct_print_summary(&fp_shared->fp_nf_ct.fp_nfct[i], i);
			else
				fp_nf_ct_print(&fp_shared->fp_nf_ct.fp_nfct[i], i);
		}
	}
}
#endif

#ifdef CONFIG_MCORE_NF_CT_CPEID
void fp_nf_dump_nfct_bycpeid(uint32_t cpeid, uint32_t count, int summary)
{
	uint32_t hash_cpeid;
	uint32_t cpt;
	struct fp_nfct_entry *nfct;

	hash_cpeid = fp_nfct_hash_cpeid(cpeid);
	cpt = fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[hash_cpeid];

	fp_log_common(LOG_DEBUG, "hash_cpeid is: %u, first index is: %u\n", hash_cpeid, cpt);

	while ((cpt < FP_NF_CT_MAX) && (count > 0)) {
		nfct = &fp_shared->fp_nf_ct.fp_nfct[cpt];

		if (nfct->flag & FP_NFCT_FLAG_VALID) {
			if (summary)
				fp_nf_ct_print_summary(&fp_shared->fp_nf_ct.fp_nfct[cpt], cpt);
			else
				fp_nf_ct_print(&fp_shared->fp_nf_ct.fp_nfct[cpt], cpt);
		}
		cpt = nfct->hash_next_cpeid;
		count--;
	}
}

#endif

#ifdef CONFIG_MCORE_NF6_CT
static void fp_nf6_ct_print_summary(struct fp_nf6ct_entry *nfct, uint32_t index)
{
	fp_log_common(LOG_DEBUG, "#%08d/#%08x", index, ntohl(nfct->uid));
	fp_log_common(LOG_DEBUG, "\tproto %05u ",
		      nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto);
	fp_log_common(LOG_DEBUG, "\t[" FP_NIP6_FMT ":%u -> " FP_NIP6_FMT ":%u ",
		      FP_NIP6(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport),
		      FP_NIP6(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport));
	fp_log_common(LOG_DEBUG, "\t| " FP_NIP6_FMT ":%u -> " FP_NIP6_FMT ":%u]",
		      FP_NIP6(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport),
		      FP_NIP6(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport));
#ifdef CONFIG_MCORE_VRF
	fp_log_common(LOG_DEBUG, "\tVR%u",
		      nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid);
#endif
	fp_log_common(LOG_DEBUG, "\t%s%s%s\n",
	       nfct->flag & FP_NFCT_FLAG_UPDATE ? " [HIT]" : "",
	       nfct->flag & FP_NFCT_FLAG_ASSURED ? " [ASSURED]" : "",
	       nfct->flag & FP_NFCT_FLAG_END ? " [END]" : "");
#undef NF_CT_STATS_FMT
#undef NF_CT_STATS
#ifdef CONFIG_MCORE_NF_CT_BYTES
#define NF_CT_STATS_FMT "%10u pkt|%10u B"
#define NF_CT_STATS(dir) nfct->counters[dir].packets,	\
		nfct->counters[dir].bytes
#else
#define NF_CT_STATS_FMT "%10u"
#define NF_CT_STATS(dir) nfct->counters[dir].packets
#endif
	fp_log_common(LOG_DEBUG, "\t\t\t\tstats["NF_CT_STATS_FMT"|", NF_CT_STATS(FP_NF_IP_CT_DIR_ORIGINAL));
	fp_log_common(LOG_DEBUG, NF_CT_STATS_FMT"]\n", NF_CT_STATS(FP_NF_IP_CT_DIR_REPLY));
}

static void fp_nf6_ct_print(struct fp_nf6ct_entry *nfct, uint32_t index)
{
	fp_log_common(LOG_DEBUG, "Flow: #%d - uid #%08x\n", index,
		      ntohl(nfct->uid));
	fp_log_common(LOG_DEBUG, "\tProto: %u\n",
		      nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto);
	fp_log_common(LOG_DEBUG, "\tOriginal: src: " FP_NIP6_FMT
		      ":%u\n\t          dst: " FP_NIP6_FMT  ":%u\n",
		      FP_NIP6(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport),
		      FP_NIP6(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport));
	fp_log_common(LOG_DEBUG, "\tReply:    src: " FP_NIP6_FMT
		      ":%u\n\t          dst: " FP_NIP6_FMT  ":%u\n",
		      FP_NIP6(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport),
		      FP_NIP6(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport));
	fp_log_common(LOG_DEBUG, "\tVRF-ID: %u\n",
		      nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid);
	fp_log_common(LOG_DEBUG, "\tFlag: 0x%02x, update: %s, assured: %s, end: %s\n",
		      nfct->flag,
		      nfct->flag & FP_NFCT_FLAG_UPDATE ? "yes" : "no",
		      nfct->flag & FP_NFCT_FLAG_ASSURED ? "yes" : "no",
		      nfct->flag & FP_NFCT_FLAG_END ? "yes" : "no");

#ifdef CONFIG_MCORE_NF_CT_BYTES
#define NF6_CT_STATS_FMT "pkt: %u, bytes: %u\n\t\t"
#define NF6_CT_STATS(i, dir) nfct->counters[dir].packets, \
		nfct->counters[dir].bytes
#else
#define NF6_CT_STATS_FMT "pkt: %u\n\t\t"
#define NF6_CT_STATS(i, dir) nfct->counters[dir].packets
#endif
	fp_log_common(LOG_DEBUG, "\tStats:\n\t\t"
		      "Original: "NF6_CT_STATS_FMT
		      "Reply:    "NF6_CT_STATS_FMT"\n",
		      NF6_CT_STATS(i, FP_NF_IP_CT_DIR_ORIGINAL),
		      NF6_CT_STATS(i, FP_NF_IP_CT_DIR_REPLY));
}

void fp_nf6_dump_nf6ct(uint32_t count, int summary)
{
	int i;

	fp_log_common(LOG_DEBUG, "Number of flows: %u/%u\n", fp_shared->fp_nf_ct.fp_nfct_count, FP_NF6_CT_MAX);

	for (i = 0; i < FP_NF6_CT_MAX && count > 0; i++, count--) {
		if (fp_shared->fp_nf6_ct.fp_nf6ct[i].flag & FP_NFCT_FLAG_VALID) {
			if (summary)
				fp_nf6_ct_print_summary(&fp_shared->fp_nf6_ct.fp_nf6ct[i], i);
			else
				fp_nf6_ct_print(&fp_shared->fp_nf6_ct.fp_nf6ct[i], i);
		}
	}
}
#endif

#ifdef CONFIG_MCORE_NF_CT
/* Add index to hash table, and manage collisions */
void fp_nfct_add_hash(uint32_t hash, union fp_nfct_tuple_id id)
{
	fp_nfct_id_to_tuple(id)->hash_next.u32 = fp_shared->fp_nf_ct.fp_nfct_hash[hash].u32;
	fp_shared->fp_nf_ct.fp_nfct_hash[hash].u32 = id.u32;
}

/* Del index from hash table, and manage collisions */
void fp_nfct_del_hash(uint32_t hash, struct fp_nfct_tuple_h *tuple)
{
	union fp_nfct_tuple_id next;
	struct fp_nfct_tuple_h *prev;

	if (fp_shared->fp_nf_ct.fp_nfct_hash[hash].s.index != FP_NF_CT_MAX)
		prev = fp_nfct_id_to_tuple(fp_shared->fp_nf_ct.fp_nfct_hash[hash]);
	else
		return;
	next = tuple->hash_next;

	/* Remove in head */
	if (prev == tuple) {
		fp_shared->fp_nf_ct.fp_nfct_hash[hash].u32 = next.u32;
		return;
	}

	/* Look for the element just before the one pointed by index */
	while (prev->hash_next.s.index != FP_NF_CT_MAX && fp_nfct_id_to_tuple(prev->hash_next) != tuple)
		prev = fp_nfct_id_to_tuple(prev->hash_next);

	/* Remove index from chaining */
	if (prev->hash_next.s.index != FP_NF_CT_MAX)
		prev->hash_next.u32 = next.u32;
}
#endif

#ifdef CONFIG_MCORE_NETFILTER_IPV6
/* Add index to hash table, and manage collisions */
void fp_nf6ct_add_hash(uint32_t hash, union fp_nfct_tuple_id id)
{
	fp_nf6ct_id_to_tuple(id)->hash_next.u32 = fp_shared->fp_nf6_ct.fp_nf6ct_hash[hash].u32;
	fp_shared->fp_nf6_ct.fp_nf6ct_hash[hash].u32 = id.u32;
}

/* Del index from hash table, and manage collisions */
void fp_nf6ct_del_hash(uint32_t hash, struct fp_nf6ct_tuple_h *tuple)
{
	union fp_nfct_tuple_id next;
	struct fp_nf6ct_tuple_h *prev;

	if (fp_shared->fp_nf6_ct.fp_nf6ct_hash[hash].s.index != FP_NF6_CT_MAX)
		prev = fp_nf6ct_id_to_tuple(fp_shared->fp_nf6_ct.fp_nf6ct_hash[hash]);
	else
		return;
	next = tuple->hash_next;

	/* Remove in head */
	if (prev == tuple) {
		fp_shared->fp_nf6_ct.fp_nf6ct_hash[hash].u32 = next.u32;
		return;
	}

	/* Look for the element just before the one pointed by index */
	while (prev->hash_next.s.index != FP_NF6_CT_MAX && fp_nf6ct_id_to_tuple(prev->hash_next) != tuple)
		prev = fp_nf6ct_id_to_tuple(prev->hash_next);

	/* Remove index from chaining */
	if (prev->hash_next.s.index != FP_NF6_CT_MAX)
		prev->hash_next.u32 = next.u32;
}
#endif /* CONFIG_MCORE_NETFILTER_IPV6 */

#ifdef CONFIG_MCORE_NF_CT_CPEID
/* Add index to cpeid hash table and manage collisions */
void fp_nfct_add_hash_cpeid(uint32_t hash, uint32_t index)
{
	uint32_t next;

	next = fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[hash];
	fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[hash] = index;

	fp_shared->fp_nf_ct.fp_nfct[index].hash_next_cpeid = next;
	/* Set prev index to invalid value (add is done in head) */
	FP_NF_CT_SET_HASH_PREV_CPEID(fp_shared->fp_nf_ct.fp_nfct[index],
				     FP_NF_CT_MAX);

	/*
	 * Update prev index of the next element to new element index
	 * only if our element is not the only one.
	 */
	if (next < FP_NF_CT_MAX)
		FP_NF_CT_SET_HASH_PREV_CPEID(fp_shared->fp_nf_ct.fp_nfct[next], index);
}

/* Del index from hash table, and manage collisions */
void fp_nfct_del_hash_cpeid(uint32_t hash, uint32_t index)
{
	uint32_t next, prev;

	prev = fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[hash];
	next = fp_shared->fp_nf_ct.fp_nfct[index].hash_next_cpeid;

	/* Remove in head */
	if (prev == index) {
		fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[hash] = next;
		/* Update prev index of the next if it exists */
		if (next < FP_NF_CT_MAX)
			FP_NF_CT_SET_HASH_PREV_CPEID(fp_shared->fp_nf_ct.fp_nfct[next], FP_NF_CT_MAX);
		return;
	}

	/* Get the element just before the one pointed by index */
	prev = FP_NF_CT_HASH_PREV_CPEID(fp_shared->fp_nf_ct.fp_nfct[index]);

	/* Should never happened */
	if (prev >= FP_NF_CT_MAX)
		fp_log_common(LOG_ERR, "%s: %d: prev index is invalid: %u\n", __FUNCTION__, __LINE__, prev);

	/* Remove index from chaining */
	fp_shared->fp_nf_ct.fp_nfct[prev].hash_next_cpeid = next;
	/* Update prev idnex of the next if it exists */
	if (next < FP_NF_CT_MAX)
		FP_NF_CT_SET_HASH_PREV_CPEID(fp_shared->fp_nf_ct.fp_nfct[next], prev);
}
#endif
