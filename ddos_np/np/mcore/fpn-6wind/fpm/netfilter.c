/*
 * Copyright (c) 2007 6WIND
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syslog.h>
#include <net/if.h>

#include "fpm_common.h"
#include "fpm_plugin.h"
#include "fpm_vrf.h"
#include "fp.h"
#include "fp-nfct.h"


#define nf_log_debug(fmt, args...) do {                    \
        if (f_verbose)                                     \
                syslog(LOG_DEBUG, fmt "\n", ## args);      \
	} while(0)

/* timings are in milliseconds. */
#define FP_IPT_LIMIT_SCALE 10000
static inline uint32_t
fpm_user2credits(uint32_t user)
{
	return (user * get_clock_hz()) / FP_IPT_LIMIT_SCALE ;
}

static int fpm_nf_table_hook_is_used(const fp_nftable_t *table, int hooknum)
{
	uint8_t cur;
	uint32_t rulenum;
	const struct fp_nfrule *rule;

	if (!(table->fpnftable_valid_hooks & (1 << hooknum)))
		return 0;
	
	if (table->fpnftable_hook_entry[hooknum] != table->fpnftable_underflow[hooknum])
		return 1;

	cur = fp_shared->fp_nf_current_table;
	rulenum = table->fpnftable_hook_entry[hooknum];
	rule = &fp_shared->fp_nf_rules[cur][rulenum];

	if ((rule->target.type != FP_NF_TARGET_TYPE_STANDARD) ||
	    (-rule->target.data.standard.verdict-1 != FP_NF_ACCEPT) )
		return 1;

	return 0;
}

/* update fp_shared->nf_conf to disable the complete hook if it's
 * not used in any table */
static int fpm_nf_update_all_hook_switches(void)
{
	const fp_nftable_t *table;
	int h, t;
	uint16_t nf_vr;
	uint8_t cur, next;
	int table_enabled[FP_NF_TABLE_NUM], i[FP_NF_IP_NUMHOOKS];
	int nfbypass = 1;

	cur = fp_shared->fp_nf_current_table;

	for (t = 0; t < FP_NF_TABLE_NUM; t++)
		table_enabled[t] = 0;

	for (nf_vr = 0; nf_vr < FP_NF_MAX_VR; nf_vr++) {
		int nat_enabled = 0;
		for (t = 0; t < FP_NF_TABLE_NUM; t++) {
			table = &fp_shared->fp_nf_tables[cur][nf_vr][t];
			for (h = 0; h < FP_NF_IP_NUMHOOKS; h++) {
				int used = fpm_nf_table_hook_is_used(table, h);
				if (used) {
					fp_shared->nf_conf.enabled_hook[nf_vr][h] |= 1ULL << t;
					table_enabled[t] = 1;
					nfbypass = 0;
				} else {
					fp_shared->nf_conf.enabled_hook[nf_vr][h] &= ~(1ULL << t);
				}
				/* force conntrack in all NAT hooks if NAT is enabled */
				if (t == FP_NF_TABLE_NAT)
					nat_enabled = used;
			}
		}
		fp_nf_set_conntrack_nat(nat_enabled, nf_vr);
	}

	fp_nf_update_bypass(nfbypass);

	/* build fp_nf_hook_prio table */
	next = !fp_shared->fp_nf_current_hook_prio;
	memset(fp_shared->fp_nf_hook_prio[next], 0, sizeof(fp_shared->fp_nf_hook_prio[next]));
	for (h = 0; h < FP_NF_IP_NUMHOOKS; h++)
		i[h] = 0;

	if (table_enabled[FP_NF_TABLE_MANGLE]) {
		fp_shared->fp_nf_hook_prio[next][FP_NF_IP_PRE_ROUTING][i[FP_NF_IP_PRE_ROUTING]++] = FP_NF_TABLE_MANGLE;
		fp_shared->fp_nf_hook_prio[next][FP_NF_IP_FORWARD][i[FP_NF_IP_FORWARD]++] = FP_NF_TABLE_MANGLE;
		fp_shared->fp_nf_hook_prio[next][FP_NF_IP_POST_ROUTING][i[FP_NF_IP_POST_ROUTING]++] = FP_NF_TABLE_MANGLE;
	}
	if (table_enabled[FP_NF_TABLE_FILTER]) {
		fp_shared->fp_nf_hook_prio[next][FP_NF_IP_LOCAL_IN][i[FP_NF_IP_LOCAL_IN]++] = FP_NF_TABLE_FILTER;
		fp_shared->fp_nf_hook_prio[next][FP_NF_IP_FORWARD][i[FP_NF_IP_FORWARD]++] = FP_NF_TABLE_FILTER;
		fp_shared->fp_nf_hook_prio[next][FP_NF_IP_LOCAL_OUT][i[FP_NF_IP_LOCAL_OUT]++] = FP_NF_TABLE_FILTER;
	}
	if (table_enabled[FP_NF_TABLE_MANGLE]) {
		fp_shared->fp_nf_hook_prio[next][FP_NF_IP_LOCAL_IN][i[FP_NF_IP_LOCAL_IN]++] = FP_NF_TABLE_MANGLE;
		fp_shared->fp_nf_hook_prio[next][FP_NF_IP_LOCAL_OUT][i[FP_NF_IP_LOCAL_OUT]++] = FP_NF_TABLE_MANGLE;
	}
	if (table_enabled[FP_NF_TABLE_NAT]) {
		fp_shared->fp_nf_hook_prio[next][FP_NF_IP_PRE_ROUTING][i[FP_NF_IP_PRE_ROUTING]++] = FP_NF_TABLE_NAT;
		fp_shared->fp_nf_hook_prio[next][FP_NF_IP_LOCAL_OUT][i[FP_NF_IP_LOCAL_OUT]++] = FP_NF_TABLE_NAT;
		fp_shared->fp_nf_hook_prio[next][FP_NF_IP_POST_ROUTING][i[FP_NF_IP_POST_ROUTING]++] = FP_NF_TABLE_NAT;
	}
	for (h = 0; h < FP_NF_IP_NUMHOOKS; h++)
		fp_shared->fp_nf_hook_prio[next][h][i[h]] = -1;
	fp_shared->fp_nf_current_hook_prio = next;

	return 0;
}

static int fpm_nf_update(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_nftable *cp_table = (const struct cp_nftable *)request;
	int rules_delta;
	uint8_t h, table_id, cur;
	uint16_t nf_vr;
	uint32_t table_first_rule, table_last_rule, last_rule, i, rules_count;
	const fp_nftable_t *cur_fp_table, *last_fp_table;
	fp_nftable_t *new_fp_table;

	nf_log_debug("%s: updating table %s vrf%u", __FUNCTION__,
		     cp_table->cpnftable_name, cp_table->cpnftable_vrfid);

	/* check supported features */
	if (cp_table->cpnftable_family != AF_INET) {
		syslog(LOG_ERR, "%s: invalid family=%u\n",
		       __FUNCTION__, cp_table->cpnftable_family);
		goto failure;
	}
	if ((table_id = fp_nf_table_id(cp_table->cpnftable_name)) >= FP_NF_TABLE_NUM) {
		syslog(LOG_ERR, "%s: table %s does not exist for IPv4\n",
		       __FUNCTION__, cp_table->cpnftable_name);
		goto failure;
	}
	nf_vr = ntohl(cp_table->cpnftable_vrfid) & FP_VRFID_MASK;
	if (nf_vr >= FP_NF_MAX_VR) {
		syslog(LOG_ERR, "%s: table vrfid=%u is out of bounds (FP_NF_MAX_VR=%u)\n",
		       __FUNCTION__, nf_vr, FP_NF_MAX_VR);
		goto failure;
	}

	cur = fp_shared->fp_nf_current_table;
	cur_fp_table = &fp_shared->fp_nf_tables[cur][nf_vr][table_id];
	last_fp_table = &fp_shared->fp_nf_tables[cur][FP_NF_MAX_VR - 1][FP_NF_TABLE_NUM - 1];

	/* check if there is enough space in the shared memory for the table */
	table_first_rule = fp_nf_first_ruleid(cur_fp_table);
	table_last_rule = fp_nf_last_ruleid(cur_fp_table);
	last_rule = fp_nf_last_ruleid(last_fp_table);
	if (table_first_rule >= FP_NF_MAXRULES ||
	    table_last_rule >= FP_NF_MAXRULES ||
	    last_rule >= FP_NF_MAXRULES ||
	    table_last_rule < table_first_rule ||
	    last_rule < table_last_rule) {
		syslog(LOG_ERR, "%s: corrupted shared memory (table_first_rule=%u, table_last_rule=%u, last_rule=%u)\n",
		       __FUNCTION__, table_first_rule, table_last_rule, last_rule);
		goto failure;
	}
	rules_count = ntohl(cp_table->cpnftable_count);
	if (rules_count == 0) {
		syslog(LOG_ERR, "%s: rules_count cannot be 0\n", __FUNCTION__);
		goto failure;
	}
	rules_delta = rules_count - cur_fp_table->fpnftable_rules_count;
	if (last_rule + rules_delta >= FP_NF_MAXRULES) {
		syslog(LOG_ERR, "%s: Too much rules (max: %u)\n", __FUNCTION__,
		       FP_NF_MAXRULES);
		goto failure;
	}

	/* Copy all tables from current to non-current. The hooks & underflows
	 * values will be modified afterwards (if necessary) */
	memcpy(&fp_shared->fp_nf_tables[!cur][0][0],
	       &fp_shared->fp_nf_tables[cur][0][0],
	       sizeof(fp_shared->fp_nf_tables[cur]));

	/* Copy rules preceding the new table from current to non-current */
	memcpy(&fp_shared->fp_nf_rules[!cur][0],
	       &fp_shared->fp_nf_rules[cur][0],
	       table_first_rule * sizeof(struct fp_nfrule));

	/* Reset space for the updated table's rules in the non-current array */
	memset(&fp_shared->fp_nf_rules[!cur][table_first_rule], 0,
	       rules_count * sizeof(struct fp_nfrule));

#define NOTHING(x) x
#define C1(opt, func) fp_rule->opt = func(cp_rule->opt)
#define C2(opt, size) memcpy(fp_rule->opt, cp_rule->opt, size)

	for(i = 0; i < rules_count; i++) {
		const struct cp_nfrule *cp_rule;
		struct fp_nfrule *fp_rule;
		uint8_t iflen;
		uint16_t j;

		cp_rule = &cp_table->cpnftable_rules[i];
		fp_rule = &fp_shared->fp_nf_rules[!cur][table_first_rule + i];

		//veda_ddos iptables dispatch typeid
		fp_rule->dispatch = 0;
		C1(dispatch, ntohl);
		if(fp_rule->dispatch >= DISPATCH_MAX_NUM)
			fp_rule->dispatch = 0;

		fp_rule->syns = 0;
		C1(syns, ntohl);
		
		fp_rule->speed = 0;
		C1(speed, ntohl);

		C1(uid, ntohl);
		/* IPv4 header */
		C1(l2.ipv4.src, NOTHING);
		C1(l2.ipv4.dst, NOTHING);
		C1(l2.ipv4.smsk, NOTHING);
		C1(l2.ipv4.dmsk, NOTHING);
		C2(l2.ipv4.iniface, FP_IFNAMSIZ);
		iflen = strlen((char *)cp_rule->l2.ipv4.iniface_mask);
		iflen = (iflen > FP_IFNAMSIZ) ? FP_IFNAMSIZ : iflen;
		fp_rule->l2.ipv4.iniface_len = iflen;
		C2(l2.ipv4.outiface, FP_IFNAMSIZ);
		iflen = strlen((char *)cp_rule->l2.ipv4.outiface_mask);
		iflen = (iflen > FP_IFNAMSIZ) ? FP_IFNAMSIZ : iflen;
		fp_rule->l2.ipv4.outiface_len = iflen;
		C1(l2.ipv4.proto, ntohs);
		C1(l2.ipv4.flags, NOTHING);
		C1(l2.ipv4.invflags, NOTHING);

		/* L2 parameters */
		C1(l2_opt.opt, NOTHING);
		C1(l2_opt.dscp, NOTHING);
		C1(l2_opt.invdscp, NOTHING);
		if (ntohl(cp_rule->l2_opt.vrfid) == CM_NF_VRFID_UNSPECIFIED)
			fp_rule->l2_opt.vrfid = FP_NF_VRFID_UNSPECIFIED;
		else
			C1(l2_opt.vrfid , ntohl);
		C1(l2_opt.rpf_flags, NOTHING);

		/* Convert (cost, burst) to (credit, credit_cap, cost) */
		fp_rule->l2_opt.rateinfo.credit_cap =
			fpm_user2credits(ntohl(cp_rule->l2_opt.rateinfo.cost) *
					 ntohl(cp_rule->l2_opt.rateinfo.burst));
		fp_rule->l2_opt.rateinfo.cost =
			fpm_user2credits(ntohl(cp_rule->l2_opt.rateinfo.cost));
		fp_rule->l2_opt.rateinfo.credit =
			fp_rule->l2_opt.rateinfo.credit_cap;
		fp_rule->l2_opt.rateinfo.prev = 0;

		/* mark */
		C1(l2_opt.mark.mark, ntohl);
		C1(l2_opt.mark.mask, ntohl);
		C1(l2_opt.mark.invert, NOTHING);

		/* mac */
		C2(l2_opt.mac.srcaddr, CM_ETHMACSIZE);
		C1(l2_opt.mac.invert, NOTHING);

		/* physdev */
		C2(l2_opt.physdev.physindev, CM_IFNAMSIZE);
		iflen = strlen((char *)cp_rule->l2_opt.physdev.physindev_mask);
		iflen = (iflen > FP_IFNAMSIZ) ? FP_IFNAMSIZ : iflen;
		fp_rule->l2_opt.physdev.physindev_len = iflen;
		C2(l2_opt.physdev.physoutdev, CM_IFNAMSIZE);
		iflen = strlen((char *)cp_rule->l2_opt.physdev.physoutdev_mask);
		iflen = (iflen > FP_IFNAMSIZ) ? FP_IFNAMSIZ : iflen;
		fp_rule->l2_opt.physdev.physoutdev_len = iflen;
		C1(l2_opt.physdev.invert, NOTHING);
		C1(l2_opt.physdev.bitmask, NOTHING);

		/* L3 parameters */
		/* 
		 * l2.ipv4.proto must be set to the right value. Linux
		 * has already checked this.
		 */
		switch(cp_rule->l3.type) {
		case CM_NF_L3_TYPE_UDP:
			fp_rule->l3.type = FP_NF_L3_TYPE_UDP;
			C1(l3.data.udp.spts[0], ntohs);
			C1(l3.data.udp.spts[1], ntohs);
			C1(l3.data.udp.dpts[0], ntohs);
			C1(l3.data.udp.dpts[1], ntohs);
			C1(l3.data.udp.invflags, NOTHING);
			break;
		case CM_NF_L3_TYPE_TCP:
			fp_rule->l3.type = FP_NF_L3_TYPE_TCP;
			C1(l3.data.tcp.spts[0], ntohs);
			C1(l3.data.tcp.spts[1], ntohs);
			C1(l3.data.tcp.dpts[0], ntohs);
			C1(l3.data.tcp.dpts[1], ntohs);
			C1(l3.data.tcp.option, NOTHING);
			C1(l3.data.tcp.flg_mask, NOTHING);
			C1(l3.data.tcp.flg_cmp, NOTHING);
			C1(l3.data.tcp.invflags, NOTHING);
			break;
		case CM_NF_L3_TYPE_SCTP:
			fp_rule->l3.type = FP_NF_L3_TYPE_SCTP;
			C1(l3.data.sctp.spts[0], ntohs);
			C1(l3.data.sctp.spts[1], ntohs);
			C1(l3.data.sctp.dpts[0], ntohs);
			C1(l3.data.sctp.dpts[1], ntohs);
			for(j=0; j<256/(sizeof(u_int32_t)*8); j++)
				C1(l3.data.sctp.chunkmap[j], ntohl);
			C1(l3.data.sctp.chunk_match_type, ntohl);
			for(j=0; j< CM_NF_IPT_NUM_SCTP_FLAGS; j++) {
				C1(l3.data.sctp.flag_info[j].chunktype, NOTHING);
				C1(l3.data.sctp.flag_info[j].flag, NOTHING);
				C1(l3.data.sctp.flag_info[j].flag_mask, NOTHING);
			}
			C1(l3.data.sctp.flag_count, ntohl);
			C1(l3.data.sctp.flags, ntohl);
			C1(l3.data.sctp.invflags, ntohl);
			break;
		case CM_NF_L3_TYPE_ICMP:
			fp_rule->l3.type = FP_NF_L3_TYPE_ICMP;
			C1(l3.data.icmp.type, NOTHING);
			C1(l3.data.icmp.code[0], NOTHING);
			C1(l3.data.icmp.code[1], NOTHING);
			C1(l3.data.icmp.invflags, NOTHING);
			break;
		}
		C1(l3.state, NOTHING);

		C1(l3_opt.opt, NOTHING);

		/* multiport */
		C1(l3_opt.multiport.flags, NOTHING);
		C1(l3_opt.multiport.count, NOTHING);
		C2(l3_opt.multiport.ports, FP_NF_MULTIPORT_SIZE);
		C2(l3_opt.multiport.pflags, FP_NF_MULTIPORT_SIZE);
		C1(l3_opt.multiport.invert, NOTHING);


		/* iprange */
		C1(l3_opt.iprange.flags, NOTHING);
		C1(l3_opt.iprange.src_min.ip, NOTHING);
		C1(l3_opt.iprange.src_max.ip, NOTHING);
		C1(l3_opt.iprange.dst_min.ip, NOTHING);
		C1(l3_opt.iprange.dst_max.ip, NOTHING);

		/* string */
		C1(string_opt.opt, NOTHING);
		C1(string_opt.string.from_offset, NOTHING);
		C1(string_opt.string.to_offset, NOTHING);
		C1(string_opt.string.patlen, NOTHING);
		C1(string_opt.string.u.v0.invert, NOTHING);
		C2(string_opt.string.pattern, CM_NF_STRING_MAX_PATTERN_SIZE);
		C2(string_opt.string.algo, CM_NF_STRING_MAX_ALGO_NAME_SIZE); 
	

		switch(cp_rule->target.type) {
		case CM_NF_TARGET_TYPE_STANDARD:
			fp_rule->target.type = FP_NF_TARGET_TYPE_STANDARD;
			C1(target.data.standard.verdict, ntohl);
			break;
		case CM_NF_TARGET_TYPE_ERROR:
			fp_rule->target.type = FP_NF_TARGET_TYPE_ERROR;
#if FP_NF_ERRORNAME
			C2(target.data.error.errorname, FP_NF_MAXNAMELEN);
#endif
			break;
		case CM_NF_TARGET_TYPE_MARK_V2:
			fp_rule->target.type = FP_NF_TARGET_TYPE_MARK_V2;
			C1(target.data.mark.mark, ntohl);
			C1(target.data.mark.mask, ntohl);
			break;
		case CM_NF_TARGET_TYPE_DSCP:
			fp_rule->target.type = FP_NF_TARGET_TYPE_DSCP;
			C1(target.data.dscp.dscp, NOTHING);
			break;
		case CM_NF_TARGET_TYPE_REJECT:
			fp_rule->target.type = FP_NF_TARGET_TYPE_REJECT;
			break;
		case CM_NF_TARGET_TYPE_LOG:
			fp_rule->target.type = FP_NF_TARGET_TYPE_LOG;
			break;
		case CM_NF_TARGET_TYPE_ULOG:
			fp_rule->target.type = FP_NF_TARGET_TYPE_ULOG;
			break;
		case CM_NF_TARGET_TYPE_MASQUERADE:
			fp_rule->target.type = FP_NF_TARGET_TYPE_MASQUERADE;
#ifdef FP_DEBUG_NF_TABLE_NAT
			C1(target.data.nat.min_ip, NOTHING);
			C1(target.data.nat.max_ip, NOTHING);
			C1(target.data.nat.min_port, ntohs);
			C1(target.data.nat.max_port, ntohs);
#endif /* FP_DEBUG_NF_TABLE_NAT */
			break;
		case CM_NF_TARGET_TYPE_SNAT:
			fp_rule->target.type = FP_NF_TARGET_TYPE_SNAT;
#ifdef FP_DEBUG_NF_TABLE_NAT
			C1(target.data.nat.min_ip, NOTHING);
			C1(target.data.nat.max_ip, NOTHING);
			C1(target.data.nat.min_port, ntohs);
			C1(target.data.nat.max_port, ntohs);
#endif /* FP_DEBUG_NF_TABLE_NAT */
			break;
		case CM_NF_TARGET_TYPE_DNAT:
			fp_rule->target.type = FP_NF_TARGET_TYPE_DNAT;
#ifdef FP_DEBUG_NF_TABLE_NAT
			C1(target.data.nat.min_ip, NOTHING);
			C1(target.data.nat.max_ip, NOTHING);
			C1(target.data.nat.min_port, ntohs);
			C1(target.data.nat.max_port, ntohs);
#endif /* FP_DEBUG_NF_TABLE_NAT */
			break;
		case CM_NF_TARGET_TYPE_TCPMSS:
			fp_rule->target.type = FP_NF_TARGET_TYPE_TCPMSS;
			break;
		case CM_NF_TARGET_TYPE_DEV: {
			fp_rule->target.type = FP_NF_TARGET_TYPE_DEV;
			C1(target.data.dev.flags, ntohl);
			C1(target.data.dev.mark, ntohl);
			C2(target.data.dev.ifname, FP_IFNAMSIZ);
			fp_rule->target.data.dev.ifname[FP_IFNAMSIZ-1] = '\0';
			fp_rule->target.data.dev.ifname_len = strlen(fp_rule->target.data.dev.ifname) + 1;
			fp_rule->target.data.dev.ifname_hash = fp_ifnet_hash_name(fp_rule->target.data.dev.ifname);
			break;
		}
		case CM_NF_TARGET_TYPE_CHECKSUM:
			fp_rule->target.type = FP_NF_TARGET_TYPE_CHECKSUM;
			break;
		default:
			syslog(LOG_ERR, "%s: unknown target.type = %u\n",
			       __FUNCTION__, cp_rule->target.type);
			goto failure;
		}
	}
#undef NOTHING
#undef C1
#undef C2

	new_fp_table = &fp_shared->fp_nf_tables[!cur][nf_vr][table_id];
	new_fp_table->fpnftable_rules_count = rules_count;
	new_fp_table->fpnftable_valid_hooks = ntohl(cp_table->cpnftable_valid_hooks);
	for (h = 0; h < FP_NF_IP_NUMHOOKS; h++) {
		uint32_t r, u;
		r = ntohl(cp_table->cpnftable_hook_entry[h]);
		u = ntohl(cp_table->cpnftable_underflow[h]);
		/*
		 * In the cp_table, there is a dedicated array of rules.
		 * All hooks and underflows values give indexes in this array.
		 * Since we have a global rules array in the shared memory,
		 * the hooks & underflows values must be shifted by
		 * "table_first_rule".
		 */
		new_fp_table->fpnftable_hook_entry[h] = table_first_rule + r;
		new_fp_table->fpnftable_underflow[h] = table_first_rule + u;
	}
#ifdef CONFIG_MCORE_NFTABLE_SEQNUM
	new_fp_table->fpnftable_seqnum = cur_fp_table->fpnftable_seqnum + 1;
#endif

	/*
	 * copy all remaining rules starting from the end of the old table
	 * that's being updated.
	 */
	memcpy(&fp_shared->fp_nf_rules[!cur][table_last_rule + 1 + rules_delta],
	       &fp_shared->fp_nf_rules[cur][table_last_rule + 1],
	       (last_rule - table_last_rule) * sizeof(struct fp_nfrule));

	/*
	 * shift all hook_entries & underflows of tables located *AFTER*
	 * the table being modified.
	 */
	fp_nf_relocate_tables(table_id, nf_vr, rules_delta);

	fp_nf_update_nftable_stats(cur_fp_table, new_fp_table);

	/*
	 * this makes the actual swap between the current and non-current
	 * part of the shared memory
	 */
	fp_shared->fp_nf_current_table = !cur;

	fpm_nf_update_all_hook_switches();
	fp_nf_invalidate_cache();

	fp_nf_dump_nftable(table_id, nf_vr, FP_NF_DUMP_NFTABLE_MODE_SHORT);

	nf_log_debug("%s: SUCCESS", __FUNCTION__);

	return EXIT_SUCCESS;

 failure:
	return EXIT_FAILURE;
}

#ifdef CONFIG_MCORE_NF_CT
static int fpm_nfct_add(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_nfct *cp_nfct = (const struct cp_nfct *)request;
	struct fp_nfct_entry *nfct;
	union fp_nfct_tuple_id id = { .u32 = 0 };
	uint32_t i;
	uint32_t hash, hash_reply;
#ifdef CONFIG_MCORE_NF_CT_CPEID
	uint32_t hash_cpeid;
#endif
#ifdef CONFIG_MCORE_VRF
	uint16_t vrfid = ntohl(cp_nfct->vrfid) & FP_VRFID_MASK;
#else
	uint16_t vrfid = 0;
#endif
	if ((nfct = fp_nfct_lookup(cp_nfct->proto, cp_nfct->orig_src, cp_nfct->orig_dst,
				   cp_nfct->orig_sport, cp_nfct->orig_dport,
				   vrfid, NULL)) != NULL) {
		/* Update status to assured if needed */
		if (cp_nfct->flag & CM_NFCT_FLAG_ASSURED) {
			nfct->flag |= FP_NFCT_FLAG_ASSURED;
			nf_log_debug("%s: Updating status to ASSURED", __FUNCTION__);
		} else
			nf_log_debug("%s: Already present in table", __FUNCTION__);

		return EXIT_SUCCESS;
	}

	if (fp_shared->fp_nf_ct.fp_nfct_count == FP_NF_CT_MAX) {
		syslog(LOG_ERR, "%s: table is full (%d), unable to add a new entry\n",
		       __FUNCTION__, FP_NF_CT_MAX);
		return EXIT_FAILURE;
	}

	i = fp_shared->fp_nf_ct.next_ct_available;

	nfct = &fp_shared->fp_nf_ct.fp_nfct[i];
	id.s.index = i;
	/* must be done before we overwrite next_available*/
	fp_shared->fp_nf_ct.next_ct_available = nfct->next_available;

	memset(nfct, 0, sizeof(struct fp_nfct_entry));
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src = cp_nfct->orig_src;
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst = cp_nfct->orig_dst;
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport = cp_nfct->orig_sport;
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport = cp_nfct->orig_dport;
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto = cp_nfct->proto;
#ifdef CONFIG_MCORE_VRF
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid = vrfid;
#endif
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dir = FP_NF_IP_CT_DIR_ORIGINAL;
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src = cp_nfct->reply_src;
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst = cp_nfct->reply_dst;
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport = cp_nfct->reply_sport;
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport = cp_nfct->reply_dport;
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].proto = cp_nfct->proto;
#ifdef CONFIG_MCORE_VRF
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].vrfid = vrfid;
#endif
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dir = FP_NF_IP_CT_DIR_REPLY;
	nfct->uid = cp_nfct->uid;
	if (cp_nfct->flag & CM_NFCT_FLAG_SNAT)
		nfct->flag |= FP_NFCT_FLAG_SNAT;
	if (cp_nfct->flag & CM_NFCT_FLAG_DNAT)
		nfct->flag |= FP_NFCT_FLAG_DNAT;
	if (cp_nfct->flag & CM_NFCT_FLAG_ASSURED)
		nfct->flag |= FP_NFCT_FLAG_ASSURED;
#ifdef CONFIG_MCORE_NF_CT_CPEID
	if (cp_nfct->flag & CM_NFCT_FLAG_FROM_CPE)
		nfct->flag |= FP_NFCT_FLAG_FROM_CPE;
	if (cp_nfct->flag & CM_NFCT_FLAG_TO_CPE)
		nfct->flag |= FP_NFCT_FLAG_TO_CPE;
#endif
	/* last step: mark the entry as valid */
	nfct->flag |= FP_NFCT_FLAG_VALID;
	fp_shared->fp_nf_ct.fp_nfct_count++;

	/* Hash original and reply directions */
	hash = fp_nfct_hash(cp_nfct->orig_src, cp_nfct->orig_dst,
			    cp_nfct->orig_sport, cp_nfct->orig_dport,
			    vrfid, cp_nfct->proto);

	hash_reply = fp_nfct_hash(cp_nfct->reply_src, cp_nfct->reply_dst,
				  cp_nfct->reply_sport, cp_nfct->reply_dport,
				  vrfid, cp_nfct->proto);

	/* Add them to the hash table */
	id.s.dir = FP_NF_IP_CT_DIR_ORIGINAL;
	fp_nfct_add_hash(hash, id);
	id.s.dir = FP_NF_IP_CT_DIR_REPLY;
	fp_nfct_add_hash(hash_reply, id);

#ifdef CONFIG_MCORE_NF_CT_CPEID
	/* If we have both flags, we use FROM_CPE to recognize the conntrack */
	if (cp_nfct->flag & CM_NFCT_FLAG_FROM_CPE) {
		hash_cpeid = fp_nfct_hash_cpeid(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src);
		fp_nfct_add_hash_cpeid(hash_cpeid, i);
	} else if (cp_nfct->flag & CM_NFCT_FLAG_TO_CPE) {
		hash_cpeid = fp_nfct_hash_cpeid(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src);
		fp_nfct_add_hash_cpeid(hash_cpeid, i);
	}
#endif

	nf_log_debug("%s: SUCCESS", __FUNCTION__);
	return EXIT_SUCCESS;
}

static int fpm_nfct_del(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_nfct *cp_nfct = (const struct cp_nfct *)request;
	struct fp_nfct_entry *nfct;
	uint32_t hash, hash_reply;
#ifdef CONFIG_MCORE_NF_CT_CPEID
	uint32_t hash_cpeid;
#endif
#ifdef CONFIG_MCORE_VRF
	uint16_t vrfid = ntohl(cp_nfct->vrfid) & FP_VRFID_MASK;
#else
	uint16_t vrfid = 0;
#endif

	nfct = fp_nfct_lookup(cp_nfct->proto, cp_nfct->orig_src, cp_nfct->orig_dst,
			      cp_nfct->orig_sport, cp_nfct->orig_dport, vrfid, NULL);

	if (nfct != NULL) {
		uint32_t i;
#ifdef CONFIG_MCORE_NF_CT_CPEID
		uint8_t flags = nfct->flag;
#endif

		/* Invalidate entry just before hash deletion */
		nfct->flag = 0;

		/* Hash original and reply directions */
		hash = fp_nfct_hash(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src,
		                    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst,
		                    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport,
		                    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport,
		                    vrfid, nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto);
		
		hash_reply = fp_nfct_hash(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src,
		                          nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst,
		                          nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport,
		                          nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport,
		                          vrfid, nfct->tuple[FP_NF_IP_CT_DIR_REPLY].proto);

		/* Delete them from the hash table (must do this before the memset) */
		fp_nfct_del_hash(hash, &nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL]);
		fp_nfct_del_hash(hash_reply, &nfct->tuple[FP_NF_IP_CT_DIR_REPLY]);

		i = ((void*)nfct - (void*)fp_shared->fp_nf_ct.fp_nfct) / sizeof (struct fp_nfct_entry);

#ifdef CONFIG_MCORE_NF_CT_CPEID
		/* If we have both flags, we use FROM_CPE to recognize the conntrack */
		if (flags & FP_NFCT_FLAG_FROM_CPE) {
			hash_cpeid = fp_nfct_hash_cpeid(
					nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src);
			fp_nfct_del_hash_cpeid(hash_cpeid, i);
		} else if (flags & FP_NFCT_FLAG_TO_CPE) {
			hash_cpeid = fp_nfct_hash_cpeid(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src);
			fp_nfct_del_hash_cpeid(hash_cpeid, i);
		}
#endif

		fp_shared->fp_nf_ct.fp_nfct_count--;
		memset(nfct, 0, sizeof(struct fp_nfct_entry));
		nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].hash_next.s.index = FP_NF_CT_MAX;
		nfct->tuple[FP_NF_IP_CT_DIR_REPLY].hash_next.s.index = FP_NF_CT_MAX;
		/* add in head */
		nfct->next_available = fp_shared->fp_nf_ct.next_ct_available;
		fp_shared->fp_nf_ct.next_ct_available = i;
#ifdef CONFIG_MCORE_NF_CT_CPEID
		nfct->hash_next_cpeid = FP_NF_CT_MAX;
#endif
	}

	nf_log_debug("%s: SUCCESS", __FUNCTION__);
	return EXIT_SUCCESS;
}

/* target >= FP_MAX_VRF means all vrf */
static void fpm_nfct_flush_per_vrf(uint16_t target)
{
	uint32_t cpt;
	struct fp_nfct_entry *nfct;
#ifdef CONFIG_MCORE_NF_CT_CPEID
	uint32_t i;
#endif

	for(cpt = 0; cpt < FP_NF_CT_MAX ; cpt++) {
		uint32_t hash, hash_reply;
		uint16_t vrfid = 0;
#ifdef CONFIG_MCORE_NF_CT_CPEID
		uint32_t hash_cpeid = 0;
#endif

		nfct = &fp_shared->fp_nf_ct.fp_nfct[cpt];

		if (!(nfct->flag & FP_NFCT_FLAG_VALID))
			continue;

#ifdef CONFIG_MCORE_VRF
		/* Remove only entries of the specified vrfid */
		if (target < FP_MAX_VR &&
		    target != nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid)
			continue;
#endif

		/* invalidate this entry before removing hashes */
		nfct->flag = 0;

		/* Hash original and reply directions */
#ifdef CONFIG_MCORE_VRF
		vrfid = nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid;
#endif
		hash = fp_nfct_hash(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src,
				    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst,
				    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport,
				    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport,
				    vrfid,
				    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto);

#ifdef CONFIG_MCORE_VRF
		vrfid = nfct->tuple[FP_NF_IP_CT_DIR_REPLY].vrfid;
#endif
		hash_reply = fp_nfct_hash(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src,
					  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst,
					  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport,
					  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport,
					  vrfid,
					  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].proto);

#ifdef CONFIG_MCORE_NF_CT_CPEID
		if (target < FP_MAX_VR)
			hash_cpeid = fp_nfct_hash_cpeid(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src);
#endif

		/* Delete them from the hash table (must do this before the memset) */
		fp_nfct_del_hash(hash, &nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL]);
		fp_nfct_del_hash(hash_reply, &nfct->tuple[FP_NF_IP_CT_DIR_REPLY]);

		fp_shared->fp_nf_ct.fp_nfct_count--;
		memset(nfct, 0, sizeof(struct fp_nfct_entry));
		nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].hash_next.s.index = FP_NF_CT_MAX;
		nfct->tuple[FP_NF_IP_CT_DIR_REPLY].hash_next.s.index = FP_NF_CT_MAX;
		nfct->next_available = fp_shared->fp_nf_ct.next_ct_available;
		fp_shared->fp_nf_ct.next_ct_available = cpt;
 
#ifdef CONFIG_MCORE_NF_CT_CPEID
		if (target < FP_MAX_VR)
			fp_nfct_del_hash_cpeid(hash_cpeid, cpt);
		nfct->hash_next_cpeid = FP_NF_CT_MAX;
#endif
	}

#ifdef CONFIG_MCORE_NF_CT_CPEID
	/* We can flush the cpe hash table because there is no lookup
	 * in the fast path based on cpe hash, and the fpm is mono threaded.
	 */
	if (target >= FP_MAX_VR)
		for (i = 0; i < FP_NF_CT_HASH_CPEID_SIZE; i++)
			fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[i] = FP_NF_CT_MAX;
#endif
}

static int fpm_nfct_flush(const uint8_t *request, const struct cp_hdr *hdr)
{
	fpm_nfct_flush_per_vrf(FP_MAX_VR);
	nf_log_debug("%s: SUCCESS", __FUNCTION__);
	return EXIT_SUCCESS;
}

#ifdef CONFIG_MCORE_NF_CT_CPEID
static int fpm_nfct_compare_bycpe(const struct cp_nfcpe *cpe, const struct fp_nfct_entry *nfct)
{
	if ((nfct->flag & FP_NFCT_FLAG_FROM_CPE)
			&& (cpe->cpeid == nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src))
		return 0;
	if ((nfct->flag & FP_NFCT_FLAG_TO_CPE)
			&& (cpe->cpeid == nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src))
		return 0;
	return 1;
}

static int
fpm_nfct_flush_bycpe(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_nfcpe *cpe = (const struct cp_nfcpe *)request;
	uint32_t hash_cpeid;
	uint32_t cpt;
	struct fp_nfct_entry *nfct;

	hash_cpeid = fp_nfct_hash_cpeid(cpe->cpeid);
	cpt = fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[hash_cpeid];

	while (cpt < FP_NF_CT_MAX) {
		uint32_t hash, hash_reply;
		uint16_t vrfid = 0;
		uint8_t flags;
		int i;

		nfct = &fp_shared->fp_nf_ct.fp_nfct[cpt];

		if (!(nfct->flag & FP_NFCT_FLAG_VALID) ||
		    fpm_nfct_compare_bycpe(cpe, nfct)) {
			cpt = nfct->hash_next_cpeid;
			continue;
		}

		/* invalidate this entry before removing hashes */
		flags = nfct->flag;
		i = cpt;
		nfct->flag = 0;

		/* Hash original and reply directions */
#ifdef CONFIG_MCORE_VRF
		vrfid = nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid;
#endif
		hash = fp_nfct_hash(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src,
				    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst,
				    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport,
				    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport,
				    vrfid,
				    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto);

#ifdef CONFIG_MCORE_VRF
		vrfid = nfct->tuple[FP_NF_IP_CT_DIR_REPLY].vrfid;
#endif
		hash_reply = fp_nfct_hash(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src,
					  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst,
					  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport,
					  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport,
					  vrfid,
					  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].proto);

		/* Delete them from the hash table (must do this before the memset) */
		fp_nfct_del_hash(hash, &nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL]);
		fp_nfct_del_hash(hash_reply, &nfct->tuple[FP_NF_IP_CT_DIR_REPLY]);

		if (flags & FP_NFCT_FLAG_FROM_CPE) {
			hash_cpeid = fp_nfct_hash_cpeid(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src);
			fp_nfct_del_hash_cpeid(hash_cpeid, cpt);
		} else if (flags & FP_NFCT_FLAG_TO_CPE) {
			hash_cpeid = fp_nfct_hash_cpeid(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src);
			fp_nfct_del_hash_cpeid(hash_cpeid, cpt);
		}

		cpt = nfct->hash_next_cpeid;

		fp_shared->fp_nf_ct.fp_nfct_count--;
		memset(nfct, 0, sizeof(struct fp_nfct_entry));
		nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].hash_next.s.index = FP_NF_CT_MAX;
		nfct->tuple[FP_NF_IP_CT_DIR_REPLY].hash_next.s.index = FP_NF_CT_MAX;
		/* add in head, do it before changing cpt */
		nfct->next_available = fp_shared->fp_nf_ct.next_ct_available;
		fp_shared->fp_nf_ct.next_ct_available = i;
		nfct->hash_next_cpeid = FP_NF_CT_MAX;
		FP_NF_CT_SET_HASH_PREV_CPEID(*nfct, FP_NF_CT_MAX);
	}

	nf_log_debug("%s: SUCCESS", __FUNCTION__);
	return EXIT_SUCCESS;
}
#endif

#endif /* CONFIG_MCORE_NF_CT */

#ifdef CONFIG_MCORE_NETFILTER_IPV6
static int fpm_nf6_table_hook_is_used(const fp_nf6table_t *table, int hooknum)
{
	uint8_t cur;
	uint32_t rulenum;
	const struct fp_nf6rule *rule;

	if (!(table->fpnf6table_valid_hooks & (1 << hooknum)))
		return 0;

	if (table->fpnf6table_hook_entry[hooknum] != table->fpnf6table_underflow[hooknum])
		return 1;

	cur = fp_shared->fp_nf_current_table;
	rulenum = table->fpnf6table_hook_entry[hooknum];
	rule = &fp_shared->fp_nf6_rules[cur][rulenum];

	if ((rule->target.type != FP_NF_TARGET_TYPE_STANDARD) ||
	    (-rule->target.data.standard.verdict-1 != FP_NF_ACCEPT) )
		return 1;

	return 0;
}

/* update fp_shared->nf_conf to disable the complete hook if it's
 * not used in any table */
static int fpm_nf6_update_all_hook_switches(void)
{
	const fp_nf6table_t *table;
	int h, t;
	uint16_t nf_vr;
	uint8_t cur, next;
	int table_enabled[FP_NF6_TABLE_NUM], i[FP_NF_IP_NUMHOOKS];
	int nfbypass = 1;

	cur = fp_shared->fp_nf6_current_table;

	for (t = 0; t < FP_NF6_TABLE_NUM; t++)
		table_enabled[t] = 0;

	for (nf_vr = 0; nf_vr < FP_NF_MAX_VR; nf_vr++) {
		for (t = 0; t < FP_NF6_TABLE_NUM; t++) {
			table = &fp_shared->fp_nf6_tables[cur][nf_vr][t];
			for (h = 0; h < FP_NF_IP_NUMHOOKS; h++)
				if (fpm_nf6_table_hook_is_used(table, h)) {
					fp_shared->nf6_conf.enabled_hook[nf_vr][h] |= 1ULL << t;
					table_enabled[t] = 1;
					nfbypass = 0;
				} else {
					fp_shared->nf6_conf.enabled_hook[nf_vr][h] &= ~(1ULL << t);
				}
			}
		}

	fp_nf6_update_bypass(nfbypass);

	/* build fp_nf6_hook_prio table */
	next = !fp_shared->fp_nf6_current_hook_prio;
	memset(fp_shared->fp_nf6_hook_prio[next], 0, sizeof(fp_shared->fp_nf6_hook_prio[next]));
	for (h = 0; h < FP_NF_IP_NUMHOOKS; h++)
		i[h] = 0;

	if (table_enabled[FP_NF_TABLE_MANGLE]) {
		fp_shared->fp_nf6_hook_prio[next][FP_NF_IP_PRE_ROUTING][i[FP_NF_IP_PRE_ROUTING]++] = FP_NF_TABLE_MANGLE;
		fp_shared->fp_nf6_hook_prio[next][FP_NF_IP_FORWARD][i[FP_NF_IP_FORWARD]++] = FP_NF_TABLE_MANGLE;
		fp_shared->fp_nf6_hook_prio[next][FP_NF_IP_POST_ROUTING][i[FP_NF_IP_POST_ROUTING]++] = FP_NF_TABLE_MANGLE;
	}
	if (table_enabled[FP_NF_TABLE_FILTER]) {
		fp_shared->fp_nf6_hook_prio[next][FP_NF_IP_LOCAL_IN][i[FP_NF_IP_LOCAL_IN]++] = FP_NF_TABLE_FILTER;
		fp_shared->fp_nf6_hook_prio[next][FP_NF_IP_FORWARD][i[FP_NF_IP_FORWARD]++] = FP_NF_TABLE_FILTER;
		fp_shared->fp_nf6_hook_prio[next][FP_NF_IP_LOCAL_OUT][i[FP_NF_IP_LOCAL_OUT]++] = FP_NF_TABLE_FILTER;
	}
	if (table_enabled[FP_NF_TABLE_MANGLE]) {
		fp_shared->fp_nf6_hook_prio[next][FP_NF_IP_LOCAL_IN][i[FP_NF_IP_LOCAL_IN]++] = FP_NF_TABLE_MANGLE;
		fp_shared->fp_nf6_hook_prio[next][FP_NF_IP_LOCAL_OUT][i[FP_NF_IP_LOCAL_OUT]++] = FP_NF_TABLE_MANGLE;
	}
	for (h = 0; h < FP_NF_IP_NUMHOOKS; h++)
		fp_shared->fp_nf6_hook_prio[next][h][i[h]] = -1;
	fp_shared->fp_nf6_current_hook_prio = next;
	return 0;
}

static int fpm_nf6_update(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_nf6table *cp_table =
		(const struct cp_nf6table *)request;
	int rules_delta;
	uint8_t h, table_id, cur;
	uint16_t nf_vr;
	uint32_t table_first_rule, table_last_rule, last_rule, i, rules_count;
	const fp_nf6table_t *cur_fp_table, *last_fp_table;
	fp_nf6table_t *new_fp_table;

	nf_log_debug("%s: updating table %s vrf%u", __FUNCTION__,
		     cp_table->cpnftable_name, cp_table->cpnftable_vrfid);

	/* check supported features */
	if (cp_table->cpnftable_family != AF_INET6) {
		syslog(LOG_ERR, "%s: invalid family=%d\n",
		       __FUNCTION__, cp_table->cpnftable_family);
		goto failure;
	}
	if ((table_id = fp_nf6_table_id(cp_table->cpnftable_name)) >= FP_NF6_TABLE_NUM) {
		syslog(LOG_ERR, "%s: table %s does not exist for IPv6\n",
		       __FUNCTION__, cp_table->cpnftable_name);
		goto failure;
	}
	nf_vr = ntohl(cp_table->cpnftable_vrfid) & FP_VRFID_MASK;
	if (nf_vr >= FP_NF_MAX_VR) {
		syslog(LOG_ERR, "%s: table vrfid=%u is out of bounds (FP_NF_MAX_VR=%u)\n",
		       __FUNCTION__, nf_vr, FP_NF_MAX_VR);
		goto failure;
	}

	cur = fp_shared->fp_nf6_current_table;
	cur_fp_table = &fp_shared->fp_nf6_tables[cur][nf_vr][table_id];
	last_fp_table = &fp_shared->fp_nf6_tables[cur][FP_NF_MAX_VR - 1][FP_NF6_TABLE_NUM - 1];

	/* check if there is enough space in the shared memory for the table */
	table_first_rule = fp_nf6_first_ruleid(cur_fp_table);
	table_last_rule = fp_nf6_last_ruleid(cur_fp_table);
	last_rule = fp_nf6_last_ruleid(last_fp_table);
	if (table_first_rule >= FP_NF6_MAXRULES ||
	    table_last_rule >= FP_NF6_MAXRULES ||
	    last_rule >= FP_NF6_MAXRULES ||
	    table_last_rule < table_first_rule ||
	    last_rule < table_last_rule) {
		syslog(LOG_ERR, "%s: corrupted shared memory (table_first_rule=%u, table_last_rule=%u, last_rule=%u)\n",
		       __FUNCTION__, table_first_rule, table_last_rule, last_rule);
		goto failure;
	}
	rules_count = ntohl(cp_table->cpnftable_count);
	if (rules_count == 0) {
		syslog(LOG_ERR, "%s: rules_count cannot be 0\n", __FUNCTION__);
		goto failure;
	}
	rules_delta = rules_count - cur_fp_table->fpnf6table_rules_count;
	if (last_rule + rules_delta >= FP_NF6_MAXRULES) {
		syslog(LOG_ERR, "%s: Too much rules (max: %u)\n",
		       __FUNCTION__, FP_NF6_MAXRULES);
		goto failure;
	}

	/* Copy all tables from current to non-current. The hooks & underflows
	 * values will be modified afterwards (if necessary) */
	memcpy(&fp_shared->fp_nf6_tables[!cur][0][0],
	       &fp_shared->fp_nf6_tables[cur][0][0],
	       sizeof(fp_shared->fp_nf6_tables[cur]));

	/* also copy all rules preceding the table being replaced */
	memcpy(&fp_shared->fp_nf6_rules[!cur][0],
	       &fp_shared->fp_nf6_rules[cur][0],
	       table_first_rule * sizeof(struct fp_nf6rule));

	/* Reset space for the updated table's rules in the non-current array */
	memset(&fp_shared->fp_nf6_rules[!cur][table_first_rule], 0,
	       rules_count * sizeof(struct fp_nf6rule));

#define NOTHING(x) x
#define C1(opt, func) fp_rule->opt = func(cp_rule->opt)
#define C2(opt, size) memcpy(fp_rule->opt, cp_rule->opt, size)
#define C2_ADDR(opt, size) memcpy(fp_rule->opt.fp_s6_addr, cp_rule->opt.s6_addr, size)

	for(i = 0; i < rules_count; i++) {
		const struct cp_nf6rule *cp_rule;
		struct fp_nf6rule *fp_rule;
		uint8_t iflen;
		uint16_t j;

		cp_rule = &cp_table->cpnftable_rules[i];
		fp_rule = &fp_shared->fp_nf6_rules[!cur][table_first_rule + i];

		C1(uid, ntohl);
		/* IPv6 header */
		C2_ADDR(l2.ipv6.src, sizeof(struct in6_addr));
		C2_ADDR(l2.ipv6.dst, sizeof(struct in6_addr));
		C2_ADDR(l2.ipv6.smsk, sizeof(struct in6_addr));
		C2_ADDR(l2.ipv6.dmsk, sizeof(struct in6_addr));
		C2(l2.ipv6.iniface, FP_IFNAMSIZ);
		iflen = strlen((char *)cp_rule->l2.ipv6.iniface_mask);
		iflen = (iflen > FP_IFNAMSIZ) ? FP_IFNAMSIZ : iflen;
		fp_rule->l2.ipv6.iniface_len = iflen;
		C2(l2.ipv6.outiface, FP_IFNAMSIZ);
		iflen = strlen((char *)cp_rule->l2.ipv6.outiface_mask);
		iflen = (iflen > FP_IFNAMSIZ) ? FP_IFNAMSIZ : iflen;
		fp_rule->l2.ipv6.outiface_len = iflen;
		C1(l2.ipv6.proto, ntohs);
		C1(l2.ipv6.flags, NOTHING);
		C1(l2.ipv6.invflags, NOTHING);

		/* L2 parameters */
		C1(l2_opt.opt, NOTHING);
		C1(l2_opt.dscp, NOTHING);
		C1(l2_opt.invdscp, NOTHING);
		if (ntohl(cp_rule->l2_opt.vrfid) == CM_NF_VRFID_UNSPECIFIED)
			fp_rule->l2_opt.vrfid = FP_NF_VRFID_UNSPECIFIED;
		else
			C1(l2_opt.vrfid , ntohl);
		C1(l2_opt.rpf_flags, NOTHING);

		/* Convert (cost, burst) to (credit, credit_cap, cost) */
		fp_rule->l2_opt.rateinfo.credit_cap =
			fpm_user2credits(ntohl(cp_rule->l2_opt.rateinfo.cost) *
					 ntohl(cp_rule->l2_opt.rateinfo.burst));
		fp_rule->l2_opt.rateinfo.cost =
			fpm_user2credits(ntohl(cp_rule->l2_opt.rateinfo.cost));
		fp_rule->l2_opt.rateinfo.credit =
			fp_rule->l2_opt.rateinfo.credit_cap;
		fp_rule->l2_opt.rateinfo.prev = 0;

		/* fragment options */
		C1(l2_opt.frag.ids[0], ntohl);
		C1(l2_opt.frag.ids[1], ntohl);
		C1(l2_opt.frag.hdrlen, ntohl);
		C1(l2_opt.frag.flags, NOTHING);
		C1(l2_opt.frag.invflags, NOTHING);

		/* mark */
		C1(l2_opt.mark.mark, ntohl);
		C1(l2_opt.mark.mask, ntohl);
		C1(l2_opt.mark.invert, NOTHING);

		/* mac */
		C2(l2_opt.mac.srcaddr, CM_ETHMACSIZE);
		C1(l2_opt.mac.invert, NOTHING);

		/* physdev */
		C2(l2_opt.physdev.physindev, CM_IFNAMSIZE);
		iflen = strlen((char *)cp_rule->l2_opt.physdev.physindev_mask);
		iflen = (iflen > FP_IFNAMSIZ) ? FP_IFNAMSIZ : iflen;
		fp_rule->l2_opt.physdev.physindev_len = iflen;
		C2(l2_opt.physdev.physoutdev, CM_IFNAMSIZE);
		iflen = strlen((char *)cp_rule->l2_opt.physdev.physoutdev_mask);
		iflen = (iflen > FP_IFNAMSIZ) ? FP_IFNAMSIZ : iflen;
		fp_rule->l2_opt.physdev.physoutdev_len = iflen;
		C1(l2_opt.physdev.invert, NOTHING);
		C1(l2_opt.physdev.bitmask, NOTHING);

		/* L3 parameters */
		/* 
		 * l2.ipv4.proto must be set to the right value. Linux
		 * has already checked this.
		 */
		switch(cp_rule->l3.type) {
		case CM_NF_L3_TYPE_UDP:
			fp_rule->l3.type = FP_NF_L3_TYPE_UDP;
			C1(l3.data.udp.spts[0], ntohs);
			C1(l3.data.udp.spts[1], ntohs);
			C1(l3.data.udp.dpts[0], ntohs);
			C1(l3.data.udp.dpts[1], ntohs);
			C1(l3.data.udp.invflags, NOTHING);
			break;
		case CM_NF_L3_TYPE_TCP:
			fp_rule->l3.type = FP_NF_L3_TYPE_TCP;
			C1(l3.data.tcp.spts[0], ntohs);
			C1(l3.data.tcp.spts[1], ntohs);
			C1(l3.data.tcp.dpts[0], ntohs);
			C1(l3.data.tcp.dpts[1], ntohs);
			C1(l3.data.tcp.option, NOTHING);
			C1(l3.data.tcp.flg_mask, NOTHING);
			C1(l3.data.tcp.flg_cmp, NOTHING);
			C1(l3.data.tcp.invflags, NOTHING);
			break;
		case CM_NF_L3_TYPE_SCTP:
			fp_rule->l3.type = FP_NF_L3_TYPE_SCTP;
			C1(l3.data.sctp.spts[0], ntohs);
			C1(l3.data.sctp.spts[1], ntohs);
			C1(l3.data.sctp.dpts[0], ntohs);
			C1(l3.data.sctp.dpts[1], ntohs);
			for(j=0; j<256/(sizeof(u_int32_t)*8); j++)
				C1(l3.data.sctp.chunkmap[j], ntohl);
			C1(l3.data.sctp.chunk_match_type, ntohl);
			for(j=0; j< CM_NF_IPT_NUM_SCTP_FLAGS; j++) {
				C1(l3.data.sctp.flag_info[j].chunktype, NOTHING);
				C1(l3.data.sctp.flag_info[j].flag, NOTHING);
				C1(l3.data.sctp.flag_info[j].flag_mask, NOTHING);
			}
			C1(l3.data.sctp.flag_count, ntohl);
			C1(l3.data.sctp.flags, ntohl);
			C1(l3.data.sctp.invflags, ntohl);
			break;
		case CM_NF_L3_TYPE_ICMP:
			fp_rule->l3.type = FP_NF_L3_TYPE_ICMP;
			C1(l3.data.icmp.type, NOTHING);
			C1(l3.data.icmp.code[0], NOTHING);
			C1(l3.data.icmp.code[1], NOTHING);
			C1(l3.data.icmp.invflags, NOTHING);
			break;
		}
		C1(l3.state, NOTHING);

		C1(l3_opt.opt, NOTHING);

		/* multiport */
		C1(l3_opt.multiport.flags, NOTHING);
		C1(l3_opt.multiport.count, NOTHING);
		C2(l3_opt.multiport.ports, FP_NF_MULTIPORT_SIZE);
		C2(l3_opt.multiport.pflags, FP_NF_MULTIPORT_SIZE);
		C1(l3_opt.multiport.invert, NOTHING);

		switch(cp_rule->target.type) {
		case CM_NF_TARGET_TYPE_STANDARD:
			fp_rule->target.type = FP_NF_TARGET_TYPE_STANDARD;
			C1(target.data.standard.verdict, ntohl);
			break;
		case CM_NF_TARGET_TYPE_ERROR:
			fp_rule->target.type = FP_NF_TARGET_TYPE_ERROR;
#if FP_NF_ERRORNAME
			C2(target.data.error.errorname, FP_NF_MAXNAMELEN);
#endif
			break;
		case CM_NF_TARGET_TYPE_MARK_V2:
			fp_rule->target.type = FP_NF_TARGET_TYPE_MARK_V2;
			C1(target.data.mark.mark, ntohl);
			C1(target.data.mark.mask, ntohl);
			break;
		case CM_NF_TARGET_TYPE_DSCP:
			fp_rule->target.type = FP_NF_TARGET_TYPE_DSCP;
			C1(target.data.dscp.dscp, NOTHING);
			break;
		case CM_NF_TARGET_TYPE_REJECT:
			fp_rule->target.type = FP_NF_TARGET_TYPE_REJECT;
			break;
		case CM_NF_TARGET_TYPE_LOG:
			fp_rule->target.type = FP_NF_TARGET_TYPE_LOG;
			break;
		case CM_NF_TARGET_TYPE_ULOG:
			fp_rule->target.type = FP_NF_TARGET_TYPE_ULOG;
			break;
		case CM_NF_TARGET_TYPE_TCPMSS:
			fp_rule->target.type = FP_NF_TARGET_TYPE_TCPMSS;
			break;
		case CM_NF_TARGET_TYPE_DEV: {
			fp_rule->target.type = FP_NF_TARGET_TYPE_DEV;
			C1(target.data.dev.flags, ntohl);
			C1(target.data.dev.mark, ntohl);
			C2(target.data.dev.ifname, FP_IFNAMSIZ);
			fp_rule->target.data.dev.ifname[FP_IFNAMSIZ-1] = '\0';
			fp_rule->target.data.dev.ifname_len = strlen(fp_rule->target.data.dev.ifname) + 1;
			fp_rule->target.data.dev.ifname_hash = fp_ifnet_hash_name(fp_rule->target.data.dev.ifname);
			break;
		}
		default:
			syslog(LOG_ERR, "%s: unknown target.type = %u\n",
			       __FUNCTION__, cp_rule->target.type);
			goto failure;
		}
	}
#undef NOTHING
#undef C1
#undef C2

	new_fp_table = &fp_shared->fp_nf6_tables[!cur][nf_vr][table_id];
	new_fp_table->fpnf6table_rules_count = rules_count;
	new_fp_table->fpnf6table_valid_hooks = ntohl(cp_table->cpnftable_valid_hooks);
	for (h = 0; h < FP_NF_IP_NUMHOOKS; h++) {
		uint32_t r, u;
		r = ntohl(cp_table->cpnftable_hook_entry[h]);
		u = ntohl(cp_table->cpnftable_underflow[h]);
		/*
		 * In the cp_table, there is a dedicated array of rules.
		 * All hooks and underflows values give indexes in this array.
		 * Since we have a global rules array in the shared memory,
		 * the hooks & underflows values must be shifted by
		 * "table_first_rule".
		 */
		new_fp_table->fpnf6table_hook_entry[h] = table_first_rule + r;
		new_fp_table->fpnf6table_underflow[h] = table_first_rule + u;
	}
#ifdef CONFIG_MCORE_NF6TABLE_SEQNUM
	new_fp_table->fpnf6table_seqnum = cur_fp_table->fpnf6table_seqnum + 1;
#endif

	/*
	 * Copy all remaining rules starting from the end of the old table
	 * that's being updated.
	 */
	memcpy(&fp_shared->fp_nf6_rules[!cur][table_last_rule + 1 + rules_delta],
	       &fp_shared->fp_nf6_rules[cur][table_last_rule + 1],
	       (last_rule - table_last_rule) * sizeof(struct fp_nf6rule));

	/*
	 * Shift all hook_entries & underflows of tables located *AFTER*
	 * the table being modified.
	 */
	fp_nf6_relocate_tables(table_id, nf_vr, rules_delta);

	fp_nf6_update_nftable_stats(cur_fp_table, new_fp_table);

	/*
	 * This makes the actual swap between the current and non-current
	 * part of the shared memory.
	 */
	fp_shared->fp_nf6_current_table = !cur;

	fpm_nf6_update_all_hook_switches();

	fp_nf6_invalidate_cache();

	fp_nf6_dump_nftable(table_id, nf_vr, FP_NF_DUMP_NFTABLE_MODE_SHORT);
	nf_log_debug("%s: SUCCESS", __FUNCTION__);

	return EXIT_SUCCESS;

failure:
	return EXIT_FAILURE;
}

static int fpm_nf6ct_add(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_nf6ct *cp_nf6ct = (const struct cp_nf6ct *)request;
	struct fp_nf6ct_entry *nfct;
	union fp_nfct_tuple_id id = { .u32 = 0 };
	uint32_t i, hash, hash_reply;
	uint16_t vrfid = ntohl(cp_nf6ct->vrfid) & FP_VRFID_MASK;

	if ((nfct = fp_nf6ct_lookup(cp_nf6ct->proto,
				    (struct fp_in6_addr *)&cp_nf6ct->orig_src,
				    (struct fp_in6_addr *)&cp_nf6ct->orig_dst,
				    cp_nf6ct->orig_sport, cp_nf6ct->orig_dport,
				    vrfid, NULL)) != NULL) {
		nf_log_debug("%s: Already present in table", __FUNCTION__);
		return EXIT_SUCCESS;
	}

	/* If we didn't find a slot, restart from 0 next time, show error */
	if (fp_shared->fp_nf6_ct.fp_nf6ct_count == FP_NF6_CT_MAX) {
		syslog(LOG_ERR, "%s: table is full (%d), unable to add a new entry\n",
		       __FUNCTION__, FP_NF6_CT_MAX);
		return EXIT_FAILURE;
	}

	i = fp_shared->fp_nf6_ct.next_ct6_available;

	nfct = &fp_shared->fp_nf6_ct.fp_nf6ct[i];
	id.s.index = i;
	/* must be done before we overwrite next_available*/
	fp_shared->fp_nf6_ct.next_ct6_available = nfct->next_available;

	memset(nfct, 0, sizeof(struct fp_nf6ct_entry));
	memcpy(&nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src, &cp_nf6ct->orig_src, sizeof(struct fp_in6_addr));
	memcpy(&nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst, &cp_nf6ct->orig_dst, sizeof(struct fp_in6_addr));
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport = cp_nf6ct->orig_sport;
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport = cp_nf6ct->orig_dport;
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto = cp_nf6ct->proto;
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid = vrfid;
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dir = FP_NF_IP_CT_DIR_ORIGINAL;
	memcpy(&nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src, &cp_nf6ct->reply_src, sizeof(struct fp_in6_addr));
	memcpy(&nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst, &cp_nf6ct->reply_dst, sizeof(struct fp_in6_addr));
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport = cp_nf6ct->reply_sport;
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport = cp_nf6ct->reply_dport;
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].proto = cp_nf6ct->proto;
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].vrfid = vrfid;
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dir = FP_NF_IP_CT_DIR_REPLY;
	nfct->uid = cp_nf6ct->uid;
	if (cp_nf6ct->flag & CM_NFCT_FLAG_ASSURED)
		nfct->flag |= FP_NFCT_FLAG_ASSURED;
	/* last step: mark the entry as valid */
	nfct->flag |= FP_NFCT_FLAG_VALID;
	fp_shared->fp_nf6_ct.fp_nf6ct_count++;

	hash = fp_nf6ct_hash((struct fp_in6_addr *)&cp_nf6ct->orig_src,
			     (struct fp_in6_addr *)&cp_nf6ct->orig_dst,
			     cp_nf6ct->orig_sport, cp_nf6ct->orig_dport,
			     vrfid, cp_nf6ct->proto);
	hash_reply = fp_nf6ct_hash((struct fp_in6_addr *)&cp_nf6ct->reply_src,
			           (struct fp_in6_addr *)&cp_nf6ct->reply_dst,
			           cp_nf6ct->reply_sport, cp_nf6ct->reply_dport,
			           vrfid, cp_nf6ct->proto);

	id.s.dir = FP_NF_IP_CT_DIR_ORIGINAL;
	fp_nf6ct_add_hash(hash, id);
	id.s.dir = FP_NF_IP_CT_DIR_REPLY;
	fp_nf6ct_add_hash(hash_reply, id);

	nf_log_debug("%s: SUCCESS", __FUNCTION__);
	return EXIT_SUCCESS;
}

static int fpm_nf6ct_del(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_nf6ct *cp_nf6ct = (const struct cp_nf6ct *)request;
	struct fp_nf6ct_entry *nfct;
	uint32_t hash, hash_reply;
	uint16_t vrfid = ntohl(cp_nf6ct->vrfid) & FP_VRFID_MASK;

	nfct = fp_nf6ct_lookup(cp_nf6ct->proto,
			       (struct fp_in6_addr *)&cp_nf6ct->orig_src,
			       (struct fp_in6_addr *)&cp_nf6ct->orig_dst,
			       cp_nf6ct->orig_sport, cp_nf6ct->orig_dport,
			       vrfid, NULL);

	if (nfct != NULL) {
		uint32_t i;

		/* Invalidate entry just before hash deletion */
		nfct->flag = 0;

		hash = fp_nf6ct_hash(&nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src,
		                     &nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst,
		                     nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport,
		                     nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport,
		                     vrfid, nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto);
		
		hash_reply = fp_nf6ct_hash(&nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src,
		                           &nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst,
		                           nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport,
		                           nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport,
		                           vrfid, nfct->tuple[FP_NF_IP_CT_DIR_REPLY].proto);

		/* Delete them from the hash table (must do this before the memset) */
		fp_nf6ct_del_hash(hash, &nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL]);
		fp_nf6ct_del_hash(hash_reply, &nfct->tuple[FP_NF_IP_CT_DIR_REPLY]);

		i = ((void*)nfct - (void*)fp_shared->fp_nf6_ct.fp_nf6ct) / sizeof (struct fp_nf6ct_entry);

		fp_shared->fp_nf6_ct.fp_nf6ct_count--;
		memset(nfct, 0, sizeof(struct fp_nf6ct_entry));
		nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].hash_next.s.index = FP_NF6_CT_MAX;
		nfct->tuple[FP_NF_IP_CT_DIR_REPLY].hash_next.s.index = FP_NF6_CT_MAX;
		/* add in head */
		nfct->next_available = fp_shared->fp_nf6_ct.next_ct6_available;
		fp_shared->fp_nf6_ct.next_ct6_available = i;
	}

	nf_log_debug("%s: SUCCESS", __FUNCTION__);
	return EXIT_SUCCESS;
}

#ifdef CONFIG_MCORE_NF6_CT
static void fpm_nf6ct_flush_per_vrf(uint16_t vrfid)
{
	struct fp_nf6ct_entry *nfct;
	uint32_t cpt;

	for(cpt = 0; cpt < FP_NF6_CT_MAX ; cpt++) {
		uint32_t hash, hash_reply;

		nfct = &fp_shared->fp_nf6_ct.fp_nf6ct[cpt];

		if (!(nfct->flag & FP_NFCT_FLAG_VALID))
			continue;

#ifdef CONFIG_MCORE_VRF
		/* Remove only entries of the specified vrfid */
		if (vrfid < FP_MAX_VR &&
		    vrfid != nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid)
			continue;
#endif

		/* invalidate this entry before removing hashes */
		nfct->flag = 0;

		/* Hash original and reply directions */
		hash = fp_nf6ct_hash(&nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src,
				     &nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst,
				     nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport,
				     nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport,
				     nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid,
				     nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto);

		hash_reply = fp_nf6ct_hash(&nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src,
					   &nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst,
					   nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport,
					   nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport,
					   nfct->tuple[FP_NF_IP_CT_DIR_REPLY].vrfid,
					   nfct->tuple[FP_NF_IP_CT_DIR_REPLY].proto);

		/* Delete them from the hash table (must do this before the memset) */
		fp_nf6ct_del_hash(hash, &nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL]);
		fp_nf6ct_del_hash(hash_reply, &nfct->tuple[FP_NF_IP_CT_DIR_REPLY]);

		fp_shared->fp_nf6_ct.fp_nf6ct_count--;
		memset(nfct, 0, sizeof(struct fp_nf6ct_entry));
		nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].hash_next.s.index = FP_NF6_CT_MAX;
		nfct->tuple[FP_NF_IP_CT_DIR_REPLY].hash_next.s.index = FP_NF6_CT_MAX;
		nfct->next_available = fp_shared->fp_nf6_ct.next_ct6_available;
		fp_shared->fp_nf6_ct.next_ct6_available = cpt;
	}
}
#endif /* CONFIG_MCORE_NF6_CT */

void fpm_nf6_vrf_del(uint16_t vrfid)
{
	struct {
		struct cp_nf6table t;
		struct cp_nf6rule r;
	} req = {
		.t.cpnftable_family = AF_INET6,
		.r.target.type = CM_NF_TARGET_TYPE_ERROR,
	};
	int i;

	/* Build a fake update request. */
	req.t.cpnftable_vrfid = htonl((uint32_t)vrfid);
	req.t.cpnftable_count = htonl(1);
	for (i = 0; i < CM_NF_IP_NUMHOOKS; i++) {
		req.t.cpnftable_hook_entry[i] = 0;
		req.t.cpnftable_underflow[i] = 0;
	}

	/* And now, clean all tables. */
	for (i = 0; i < FP_NF6_TABLE_NUM; i++) {
		strncpy(req.t.cpnftable_name, fp_table_name(i),
			CM_NF_MAXNAMELEN);
		fpm_nf6_update((uint8_t *)&req, NULL);
	}

#ifdef CONFIG_MCORE_NF6_CT
	fpm_nf6ct_flush_per_vrf(vrfid);
#endif
}
#endif /* CONFIG_MCORE_NETFILTER_IPV6 */

void fpm_nf_vrf_del(uint16_t vrfid)
{
	struct {
		struct cp_nftable t;
		struct cp_nfrule r;
	} req = {
		.t.cpnftable_family = AF_INET,
		.r.target.type = CM_NF_TARGET_TYPE_ERROR,
	};
	int i;

	/* Build a fake update request. */
	req.t.cpnftable_vrfid = htonl((uint32_t)vrfid);
	req.t.cpnftable_count = htonl(1);
	for (i = 0; i < CM_NF_IP_NUMHOOKS; i++) {
		req.t.cpnftable_hook_entry[i] = 0;
		req.t.cpnftable_underflow[i] = 0;
	}

	/* And now, clean all tables. */
	for (i = 0; i < FP_NF_TABLE_NUM; i++) {
		strncpy(req.t.cpnftable_name, fp_table_name(i),
			CM_NF_MAXNAMELEN);
		fpm_nf_update((uint8_t *)&req, NULL);
	}

#ifdef CONFIG_MCORE_NF_CT
	fpm_nfct_flush_per_vrf(vrfid);
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	fpm_nf6_vrf_del(vrfid);
#endif
}

static struct fpm_vrf_handler vrf_hdlr = {
	.name = "nefilter",
	.del = fpm_nf_vrf_del,
};

static void fpm_netfilter_init(__attribute__((unused)) int graceful)
{
	fpm_vrf_register(&vrf_hdlr);

	fpm_register_msg(CMD_NF_UPDATE, fpm_nf_update, NULL);
#ifdef CONFIG_MCORE_NF_CT
	fpm_register_msg(CMD_NF_CTADD, fpm_nfct_add, NULL);
	fpm_register_msg(CMD_NF_CTDELETE, fpm_nfct_del, NULL);
	fpm_register_msg(CMD_NF_CTFLUSH, fpm_nfct_flush, NULL);
#ifdef CONFIG_MCORE_NF_CT_CPEID
	fpm_register_msg(CMD_NF_CPE_DELETE, fpm_nfct_flush_bycpe, NULL);
#endif
#endif /* CONFIG_MCORE_NF_CT */
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	fpm_register_msg(CMD_NF6_UPDATE, fpm_nf6_update, NULL);
	fpm_register_msg(CMD_NF6_CTADD, fpm_nf6ct_add, NULL);
	fpm_register_msg(CMD_NF6_CTDELETE, fpm_nf6ct_del, NULL);
#endif /* CONFIG_MCORE_NETFILTER_IPV6 */
}

static struct fpm_mod fpm_netfilter_mod = {
	.name = "netfilter",
	.init = fpm_netfilter_init,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_netfilter_mod);
}
