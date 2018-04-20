/*
 * Copyright(c) 2013 6WIND
 */

#ifndef __FastPath__
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#endif

#include "fp.h"
#include "fpdebug.h"
#include "fpdebug-stats.h"
#include "fpdebug-priv.h"

#ifdef CONFIG_MCORE_L2SWITCH
#include "shmem/fpn-shmem.h"
#include "fp-l2switch.h"
#endif

int nonzero = 0;

FPN_STAILQ_HEAD(cli_stats_list, cli_stats);
FPN_DEFINE_SHARED(struct cli_stats_list, cli_statistics) =
	FPN_STAILQ_HEAD_INITIALIZER(cli_statistics);

int fpdebug_add_stats(cli_stats_t *stats)
{
	cli_stats_t *cur;

	if (!stats)
		return -1;

	/* sanity check */
	FPN_STAILQ_FOREACH(cur, &cli_statistics, next) {
		if (!strcmp(cur->module, stats->module))
			return -1;
	}

	FPN_STAILQ_INSERT_TAIL(&cli_statistics, stats, next);
	return 0;
}

int fpdebug_del_stats(const char *module)
{
	cli_stats_t *cur;

	if (!module)
		return -1;

	FPN_STAILQ_FOREACH(cur, &cli_statistics, next) {
		if (strcmp(cur->module, module))
			continue;

		FPN_STAILQ_REMOVE(&cli_statistics, cur, cli_stats, next);
		return 0;
	}

	return -1;
}

#ifdef CONFIG_MCORE_IPSEC
static void dump_ipsec_stats(void)
{
	uint64_t ipsec_no_sa;
	int cpu;

	ipsec_no_sa = 0;
	for (cpu = 0; cpu < FP_IPSEC_STATS_NUM; cpu++)
		ipsec_no_sa += fp_shared->ipsec.ipsec_stats[default_vrfid][cpu].ipsec_no_sa;
	if (__nonzero(ipsec_no_sa))
		fpdebug_printf("IPsec no SA found:%"PRIu64, ipsec_no_sa);
#ifdef CONFIG_MCORE_IPSEC_IPV6
	ipsec_no_sa = 0;
	for (cpu = 0; cpu < FP_IPSEC6_STATS_NUM; cpu++)
		ipsec_no_sa += fp_shared->ipsec6.ipsec6_stats[default_vrfid][cpu].ipsec6_no_sa;
	if (__nonzero(ipsec_no_sa))
		fpdebug_printf("IPv6 IPsec no SA found:%"PRIu64, ipsec_no_sa);
#endif
}
#endif

/* Special case IpInReceives = IpForwDatagrams + IpInHdrErrors + IpInAddrErrors */
#define print_stats_IpInReceive(pref, num) do { \
	unsigned int __i, __first = 0; \
	uint64_t __val, __total; \
	for (__i=0, __total=0 ; __i<num ; __i++) { \
		__val = pref[__i].IpForwDatagrams + \
		        pref[__i].IpInHdrErrors + \
		        pref[__i].IpInAddrErrors; \
		__total += __val; \
		if (__nonzero(__val)) { \
			if (__first == 0) { \
				__first = 1; \
				fpdebug_printf("  IpInReceives:"); \
				if (percore) \
					fpdebug_printf("\n"); \
			} \
			if (percore) { \
				fpdebug_printf("    IpInReceives[%u]:%"PRIu64"\n", __i, __val); \
			} \
		} \
	} \
	if (__nonzero(__total)) { \
		if (percore) \
			fpdebug_printf("    Total:%"PRIu64"\n", __total); \
		else \
			fpdebug_printf("%"PRIu64"\n", __total); \
	}\
} while (0)

#define print_interface_stats(field) \
	print_stats(ifp->if_stats, field, FP_IF_STATS_NUM)

static int _dump_port_stats(int percore)
{
	int i;
	fp_ifnet_t *ifp;
	uint32_t ifuid;

	for (i = 0 ; i < FP_MAX_PORT; i++) {
		ifuid = fp_shared->ifport[i].ifuid;
		if (ifuid == 0)
			continue;
		ifp = __fp_ifuid2ifnet(ifuid);
		fpdebug_printf("%s ifuid:0x%08x port:%"PRIu8"\n", ifp->if_name, ntohl(ifuid),
				ifp->if_port);
		print_interface_stats(ifs_ipackets);
		print_interface_stats(ifs_ierrors);
		print_interface_stats(ifs_ilasterror);
		print_interface_stats(ifs_ibytes);
		print_interface_stats(ifs_imcasts);
		print_interface_stats(ifs_opackets);
		print_interface_stats(ifs_oerrors);
		print_interface_stats(ifs_obytes);
	}

	return 0;
}

static int dump_port_stats(char *tok)
{
	return _dump_stats(tok, _dump_port_stats);
}

static int _dump_interface_stats(int percore)
{
	int i;
	fp_ifnet_t *ifp;
	uint32_t ifuid;

	for (i = 0 ; i < FP_MAX_IFNET; i++) {
		ifp = &fp_shared->ifnet.table[i];
		ifuid = ifp->if_ifuid;
		if (ifuid == 0)
			continue;
		fpdebug_printf("%s ifuid:0x%08x port:%"PRIu8"\n", ifp->if_name, ntohl(ifuid),
				ifp->if_port);
		print_interface_stats(ifs_ipackets);
		print_interface_stats(ifs_ierrors);
		print_interface_stats(ifs_ilasterror);
		print_interface_stats(ifs_ibytes);
		print_interface_stats(ifs_imcasts);
		print_interface_stats(ifs_opackets);
		print_interface_stats(ifs_oerrors);
		print_interface_stats(ifs_obytes);
	}

	return 0;
}

static int dump_interface_stats(char *tok)
{
	return _dump_stats(tok, _dump_interface_stats);
}

#ifdef CONFIG_MCORE_BRIDGE
#define print_l2_stats(field) \
	print_stats(fp_shared->l2_stats, field, FP_L2_STATS_NUM)
static int _dump_l2_stats(int percore)
{
	print_l2_stats(L2ForwFrames);
#ifdef CONFIG_MCORE_EBTABLES
	print_l2_stats(L2DroppedFrames);
#endif

	return 0;
}

static int dump_l2_stats(char *tok)
{
	return _dump_stats(tok, _dump_l2_stats);
}
#endif

#define print_ip_stats(field) \
	print_stats(fp_shared->ip_stats, field, FP_IP_STATS_NUM)
#define print_ip_stats_IpInReceives() \
	print_stats_IpInReceive(fp_shared->ip_stats, FP_IP_STATS_NUM)

static int _dump_ip_stats(int percore)
{
	print_ip_stats(IpForwDatagrams);
	print_ip_stats_IpInReceives();
	print_ip_stats(IpInDelivers);
	print_ip_stats(IpInHdrErrors);
	print_ip_stats(IpInAddrErrors);
	print_ip_stats(IpDroppedNoArp);
	print_ip_stats(IpDroppedNoMemory);
	print_ip_stats(IpDroppedForwarding);
	print_ip_stats(IpDroppedIPsec);
	print_ip_stats(IpDroppedBlackhole);
	print_ip_stats(IpDroppedInvalidInterface);
	print_ip_stats(IpDroppedNetfilter);
	print_ip_stats(IpDroppedNoRouteLocal);
	print_ip_stats(IpReasmTimeout);
	print_ip_stats(IpReasmReqds);
	print_ip_stats(IpReasmOKs);
	print_ip_stats(IpReasmFails);
	print_ip_stats(IpReasmExceptions);
	print_ip_stats(IpFragOKs);
	print_ip_stats(IpFragFails);
	print_ip_stats(IpFragCreates);

	return 0;
}

#ifdef CONFIG_MCORE_IP
static int dump_ip_stats(char *tok)
{
	return _dump_stats(tok, _dump_ip_stats);
}
#endif

#ifdef CONFIG_MCORE_IPV6
#define print_ip6_stats(field) \
	print_stats(fp_shared->ip6_stats, field, FP_IP_STATS_NUM)
#define print_ip6_stats_IpInReceives() \
	print_stats_IpInReceive(fp_shared->ip6_stats, FP_IP_STATS_NUM)

static int _dump_ip6_stats(int percore)
{
	print_ip6_stats(IpForwDatagrams);
	print_ip6_stats_IpInReceives();
	print_ip6_stats(IpInDelivers);
	print_ip6_stats(IpInHdrErrors);
	print_ip6_stats(IpInAddrErrors);
	print_ip6_stats(IpDroppedNoArp);
	print_ip6_stats(IpDroppedNoMemory);
	print_ip6_stats(IpDroppedForwarding);
	print_ip6_stats(IpDroppedIPsec);
	print_ip6_stats(IpDroppedBlackhole);
	print_ip6_stats(IpDroppedInvalidInterface);
	print_ip6_stats(IpDroppedNoRouteLocal);
	print_ip6_stats(IpDroppedNetfilter);
	print_ip6_stats(IpFragOKs);
	print_ip6_stats(IpFragFails);
	print_ip6_stats(IpFragCreates);
	print_ip6_stats(IpReasmTimeout);
	print_ip6_stats(IpReasmReqds);
	print_ip6_stats(IpReasmOKs);
	print_ip6_stats(IpReasmFails);
	print_ip6_stats(IpReasmExceptions);

	return 0;
}

static int dump_ip6_stats(char *tok)
{
	return _dump_stats(tok, _dump_ip6_stats);
}
#endif

#define print_global_stats(field) \
	print_stats(fp_shared->global_stats, field, FP_GLOBAL_STATS_NUM)

static int _dump_global_stats(int percore)
{
	print_global_stats(fp_dropped);
	print_global_stats(fp_droppedOperative);
	return 0;
}

static int dump_global_stats(char *tok)
{
	return _dump_stats(tok, _dump_global_stats);
}

#ifdef CONFIG_MCORE_ARP_REPLY
#define print_arp_stats(field) \
	print_stats(fp_shared->arp_stats, field, FP_ARP_STATS_NUM)

static int _dump_arp_stats(int percore)
{
	print_arp_stats(arp_errors);
	print_arp_stats(arp_unhandled);
	print_arp_stats(arp_not_found);
	print_arp_stats(arp_replied);
	return 0;
}

static int dump_arp_stats(char *tok)
{
	return _dump_stats(tok, _dump_arp_stats);
}
#endif

static unsigned char __valid_stat [2048];

#define clear_check_stats memset (__valid_stat, 0, sizeof (__valid_stat))
#define do_check_stats(name, len) \
{\
	int i; \
	for (i=0; i<len; i++) { \
		uint64_t __fieldval, __total;	\
		int cpu;	\
		for (cpu = 0, __total = 0; cpu < FP_EXCEP_STATS_NUM; cpu++)	{ \
			__fieldval = fp_shared->exception_stats[cpu].name[i];	\
			__total += __fieldval; \
		} \
		if (!__valid_stat[i] && __total) \
			printf ("    Unexpected stat [%d] = %"PRIu64"  **********\n", i, \
				__total); \
	} \
}

#define print_exception_stats(field) \
	{ \
	uint64_t __fieldval, __total;	\
	int cpu;	\
	for (cpu = 0, __total = 0; cpu < FP_EXCEP_STATS_NUM; cpu++) {\
		__fieldval = fp_shared->exception_stats[cpu].field;	\
		__total += __fieldval; \
		if (percore && __nonzero(__fieldval)) \
			fpdebug_printf("    %s[%u]:%"PRIu64"\n", #field, cpu, __fieldval); \
	}\
	if (percore && __nonzero(__total)) \
		fpdebug_printf("    Total:%"PRIu64"\n", __total); \
	else if (__nonzero(__total)) \
		fpdebug_printf("  %s:%"PRIu64"\n", #field, __total);	\
	}

#define print_exception_stats_var(name, var) \
	{ \
	uint64_t __fieldval, __total;	\
	int cpu;	\
	for (cpu = 0, __total = 0; cpu < FP_EXCEP_STATS_NUM; cpu++)	{ \
		__fieldval = fp_shared->exception_stats[cpu].name[var];	\
		__total += __fieldval; \
		if (percore && __nonzero(__fieldval)) \
			fpdebug_printf("    %s[%u]:%"PRIu64"\n", #var, cpu, __fieldval); \
	} \
	if (percore && __nonzero(__total)) \
		fpdebug_printf("    Total:%"PRIu64"\n", __total); \
	else if (__nonzero(__total)) \
		fpdebug_printf("    %s:%"PRIu64"\n", #var, __total); \
	__valid_stat[var]=1; \
	}

#define print_exception_stats_var_mask(name, var)                       \
	{ \
	uint64_t __fieldval, __total;	\
	int cpu;	\
	for (cpu = 0, __total = 0; cpu < FP_EXCEP_STATS_NUM; cpu++)	{ \
		__fieldval = fp_shared->exception_stats[cpu].name[(var) & FPTUN_EXC_CLASS_MASK];	\
		__total += __fieldval; \
		if (percore && __nonzero(__fieldval)) \
			fpdebug_printf("    %s[%u]:%"PRIu64"\n", #var, cpu, __fieldval); \
	}\
	if (percore && __nonzero(__total)) \
		fpdebug_printf("    Total:%"PRIu64"\n", __total); \
	else if (__nonzero(__total)) \
		fpdebug_printf("    %s:%"PRIu64"\n", #var, __total); \
	__valid_stat[var & FPTUN_EXC_CLASS_MASK]=1; \
	}


#define print_exception_stats_type(name) \
	fpdebug_printf("  %s:\n", #name);\
	print_exception_stats_var(name, FPTUN_BASIC_EXCEPT); \
	print_exception_stats_var(name, FPTUN_IPV4_FWD_EXCEPT); \
	print_exception_stats_var(name, FPTUN_IPV6_FWD_EXCEPT); \
	print_exception_stats_var(name, FPTUN_IPV4_IPSECDONE_OUTPUT_EXCEPT); \
	print_exception_stats_var(name, FPTUN_IPV6_IPSECDONE_OUTPUT_EXCEPT); \
	print_exception_stats_var(name, FPTUN_IPV4_OUTPUT_EXCEPT); \
	print_exception_stats_var(name, FPTUN_IPV6_OUTPUT_EXCEPT); \
	print_exception_stats_var(name, FPTUN_IPV4_INPUT_EXCEPT); \
	print_exception_stats_var(name, FPTUN_IPV6_INPUT_EXCEPT); \
	print_exception_stats_var(name, FPTUN_ETH_INPUT_EXCEPT); \
	print_exception_stats_var(name, FPTUN_ETH_NOVNB_INPUT_EXCEPT); \
	print_exception_stats_var(name, FPTUN_IFACE_INPUT_EXCEPT); \
	print_exception_stats_var(name, FPTUN_LOOP_INPUT_EXCEPT); \
	print_exception_stats_var(name, FPTUN_OUTPUT_EXCEPT); \
	print_exception_stats_var(name, FPTUN_MULTICAST_EXCEPT); \
	print_exception_stats_var(name, FPTUN_MULTICAST6_EXCEPT); \
	print_exception_stats_var(name, FPTUN_ETH_SP_OUTPUT_REQ); \
	print_exception_stats_var(name, FPTUN_IPV4_IPSEC_SP_OUTPUT_REQ); \
	print_exception_stats_var(name, FPTUN_IPV6_IPSEC_SP_OUTPUT_REQ); \
	print_exception_stats_var(name, FPTUN_ETH_FP_OUTPUT_REQ); \
	print_exception_stats_var(name, FPTUN_IPV4_IPSEC_FP_OUTPUT_REQ); \
	print_exception_stats_var(name, FPTUN_IPV6_IPSEC_FP_OUTPUT_REQ); \
	print_exception_stats_var(name, FPTUN_TAP); \
	print_exception_stats_var(name, FPTUN_IPV4_REPLAYWIN); \
	print_exception_stats_var(name, FPTUN_IPV6_REPLAYWIN); \
	print_exception_stats_var(name, FPTUN_HITFLAGS_SYNC); \
	print_exception_stats_var(name, FPTUN_RFPS_UPDATE); \
	print_exception_stats_var(name, FPTUN_VNB2VNB_FP_TO_LINUX_EXCEPT); \
	print_exception_stats_var(name, FPTUN_VNB2VNB_LINUX_TO_FP_EXCEPT); \
	print_exception_stats_var(name, FPTUN_TRAFFIC_GEN_MSG);

#define print_exception_stats_class(name) \
	fpdebug_printf("  %s:\n", #name);\
	print_exception_stats_var_mask(name, FPTUN_EXC_UNDEF); \
	print_exception_stats_var_mask(name, FPTUN_EXC_SP_FUNC); \
	print_exception_stats_var_mask(name, FPTUN_EXC_ETHER_DST); \
	print_exception_stats_var_mask(name, FPTUN_EXC_IP_DST); \
	print_exception_stats_var_mask(name, FPTUN_EXC_ICMP_NEEDED); \
	print_exception_stats_var_mask(name, FPTUN_EXC_NDISC_NEEDED); \
	print_exception_stats_var_mask(name, FPTUN_EXC_IKE_NEEDED); \
	print_exception_stats_var_mask(name, FPTUN_EXC_FPC); \
	print_exception_stats_var_mask(name, FPTUN_EXC_NF_FUNC); \
	print_exception_stats_var_mask(name, FPTUN_EXC_TAP); \
	print_exception_stats_var_mask(name, FPTUN_EXC_REPLAYWIN); \
	print_exception_stats_var_mask(name, FPTUN_EXC_ECMP_NDISC_NEEDED); \
	print_exception_stats_var_mask(name, FPTUN_EXC_VNB_TO_VNB); \
	print_exception_stats_var_mask(name, FPTUN_EXC_SOCKET);


static int _dump_exception_stats(int percore)
{
	print_exception_stats(LocalBasicExceptions);
	print_exception_stats(LocalFPTunExceptions);
	print_exception_stats(IntraBladeExceptions);

	clear_check_stats;
	print_exception_stats_class(LocalExceptionClass);
	do_check_stats(LocalExceptionClass, FPTUN_EXC_CLASS_MAX);

	clear_check_stats;
	print_exception_stats_type(LocalExceptionType);
	do_check_stats(LocalExceptionType, FPTUN_TYPE_MAX);

#ifdef CONFIG_MCORE_MULTIBLADE
	print_exception_stats(InterBladeExceptions);

	clear_check_stats;
	print_exception_stats_class(RemoteExceptionClass);
	do_check_stats(RemoteExceptionClass, FPTUN_EXC_CLASS_MAX);

	clear_check_stats;
	print_exception_stats_type(RemoteExceptionType);
	do_check_stats(RemoteExceptionType, FPTUN_TYPE_MAX);
#endif
#ifdef CONFIG_MCORE_TAP
	print_exception_stats(TapExceptions);
#endif
#ifdef CONFIG_MCORE_MULTICAST4
	print_exception_stats(MulticastExceptions);
#endif
#ifdef CONFIG_MCORE_MULTICAST6
	print_exception_stats(Multicast6Exceptions);
#endif
	print_exception_stats(FptunSizeExceedsCpIfThresh);
	print_exception_stats(FptunSizeExceedsFpibThresh);
	return 0;
}

static int dump_exception_stats(char *tok)
{
	return _dump_stats(tok, _dump_exception_stats);
}

#ifdef CONFIG_MCORE_MULTIBLADE
#define print_multiblade_stats(field) \
	print_stats(fp_shared->multiblade_stats, field, FP_MULTIBLADE_STATS_NUM)

static int _dump_multiblade_stats(int percore)
{
	print_multiblade_stats(SentRemotePortOutputRequests);
	print_multiblade_stats(RcvdRemotePortOutputRequests);
	print_multiblade_stats(SentRemoteIPsecOutputRequests);
	print_multiblade_stats(RcvdRemoteIPsecOutputRequests);
	print_multiblade_stats(RcvdLocalBladeUnactive);
	print_multiblade_stats(RcvdLocalConfigErrors);
	print_multiblade_stats(SentRemoteExceptionErrors);
	print_multiblade_stats(RcvdRemoteHFSyncRequest);

	return 0;
}

static int dump_multiblade_stats(char *tok)
{
	return _dump_stats(tok, _dump_multiblade_stats);
}
#endif

static int dump_stats(char *tok)
{
	cli_stats_t *stats;
	int percore;

	parse_stats_token(tok, percore);

	fpdebug_printf("==== interface stats:\n");
	_dump_interface_stats(percore);

#ifdef CONFIG_MCORE_BRIDGE
	fpdebug_printf("==== L2 stats:\n");
	_dump_l2_stats(percore);
#endif

	fpdebug_printf("==== IPv4 stats:\n");
	_dump_ip_stats(percore);
#ifdef CONFIG_MCORE_IPV6
	fpdebug_printf("==== IPv6 stats:\n");
	_dump_ip6_stats(percore);
#endif
#ifdef CONFIG_MCORE_ARP_REPLY
	fpdebug_printf("==== arp stats:\n");
	_dump_arp_stats(percore);
#endif

	fpdebug_printf("==== global stats:\n");
	_dump_global_stats(percore);

	fpdebug_printf("==== exception stats:\n");
	_dump_exception_stats(percore);

#ifdef CONFIG_MCORE_MULTIBLADE
	fpdebug_printf("==== multiblade stats:\n");
	_dump_multiblade_stats(percore);
#endif
#ifdef CONFIG_MCORE_IPSEC
	fpdebug_printf("==== IPsec stats:\n");
	dump_ipsec_stats();
	fpdebug_printf("\n");
#endif

	FPN_STAILQ_FOREACH(stats, &cli_statistics, next) {
		unsigned int j;

		for (j = 0; stats->s[j].name; j++) {
			fpdebug_printf("==== %s stats:\n", stats->s[j].name);
			if (stats->s[j].dump)
				stats->s[j].dump(percore);
			fpdebug_printf("\n");
		}
	}

	reset_non_zero_stats();
	return 0;
}

/* reset all possible stats in fp_shared, the same order as define. */
static int reset_stats(char *tok __fpn_maybe_unused)
{
	cli_stats_t *stats;
	int i;

	/* reset interface stats */
	for (i=0; i < FP_MAX_IFNET; i++) {
		reset_stat(ifnet.table[i].if_stats);
	}

	/* reset ip(6) stats */
	reset_stat(ip_stats);
#ifdef CONFIG_MCORE_IPV6
	reset_stat(ip6_stats);
#endif

	/* reset global stats */
	reset_stat(global_stats);

	/* reset l2 stats */
#ifdef CONFIG_MCORE_BRIDGE
	reset_stat(l2_stats);
#endif

	/* reset arp stats */
#ifdef CONFIG_MCORE_ARP_REPLY
	reset_stat(arp_stats);
#endif

	/* reset multiblade stats */
#ifdef CONFIG_MCORE_MULTIBLADE
	reset_stat(multiblade_stats);
#endif

	/* reset exception stats */
	reset_stat(exception_stats);

	/* reset ipsec(6) stats */
#ifdef CONFIG_MCORE_IPSEC
	reset_stat(ipsec.ipsec_stats);

	/* reset sad all */
	for (i=0; i < FP_MAX_SA_ENTRIES; i++) {
		reset_stat(ipsec.sad.table[i].stats);
	}

	/* reset spd all */
	for (i=0; i < FP_MAX_SP_ENTRIES; i++) {
		reset_stat(ipsec.spd_in.table[i].stats);
		reset_stat(ipsec.spd_out.table[i].stats);
	}
#ifdef CONFIG_MCORE_IPSEC_IPV6
	reset_stat(ipsec6.ipsec6_stats);

	/* reset sad6 all */
	for (i=0; i < FP_MAX_IPV6_SA_ENTRIES; i++) {
		reset_stat(ipsec6.sad6.table[i].stats);
	}

	/* reset spd6 all */
	for (i=0; i < FP_MAX_IPV6_SP_ENTRIES; i++) {
		reset_stat(ipsec6.spd6_in.table[i].stats);
		reset_stat(ipsec6.spd6_out.table[i].stats);
	}
#endif
#endif

#ifdef CONFIG_MCORE_NETFILTER
	/* reset fp nf rule stats */
	for (i=0; i < FP_NF_MAXRULES; i++) {
		reset_stat(fp_nf_rules[0][i].stats);
		reset_stat(fp_nf_rules[1][i].stats);
	}

#ifdef CONFIG_MCORE_NF_CT
	/* reset fp nf ct stats */
	for (i=0; i < FP_NF_CT_MAX; i++) {
		reset_stat(fp_nf_ct.fp_nfct[i].counters);
	}
#endif
#endif

#ifdef CONFIG_MCORE_NETFILTER_IPV6
	/* reset fp nf6 rule stats */
	for (i=0; i < FP_NF6_MAXRULES; i++) {
		reset_stat(fp_nf6_rules[0][i].stats);
		reset_stat(fp_nf6_rules[1][i].stats);
	}

	/* reset fp nf6 ct stats */
	for (i=0; i < FP_NF6_CT_MAX; i++) {
		reset_stat(fp_nf6_ct.fp_nf6ct[i].counters);
	}
#endif

	FPN_STAILQ_FOREACH(stats, &cli_statistics, next) {
		unsigned int j;

		for (j = 0; stats->s[j].name; j++) {
			if (stats->s[j].reset)
				stats->s[j].reset();
		}
	}

	return 0;
}

#ifdef CONFIG_MCORE_L2SWITCH

#define print_l2switch_stats(portid, field)				\
	print_stats(l2switch_shared->stats[portid], field, FP_L2SWITCH_STATS_NUM)

static int _dump_l2switch_stats(int percore)
{
	fp_ifport_t *p;
	int i;
	l2switch_shared_mem_t *l2switch_shared;

	l2switch_shared = get_l2switch_shared_mem();

	for (i = 0 ; i < FP_MAX_PORT; i++) {
		p = &fp_shared->ifport[i];
		if (p->ifuid ==0)
			continue;

		fpdebug_printf("port %d statistics:\n", i);
		print_l2switch_stats(i, drop);
		print_l2switch_stats(i, exception);
		print_l2switch_stats(i, forward);
	}

	return 0;
}

static int dump_l2switch_stats(char *tok)
{
	return _dump_stats(tok, _dump_l2switch_stats);
}


static int reset_l2switch_stats(char *tok)
{
	l2switch_shared_mem_t *l2switch_shared;

	l2switch_shared = get_l2switch_shared_mem();
	if (l2switch_shared == NULL) {
		fpdebug_printf("l2-switch shared memory not available\n");
		return -1;
	}

	memset(l2switch_shared->stats, 0, sizeof(l2switch_shared->stats));

	return 0;
}
#endif

static CLI_COMMAND stats_cmds[] = {
#ifdef CONFIG_MCORE_L2SWITCH
	{"dump-l2switch-stats", dump_l2switch_stats, "Dump l2switch statistics: dump-l2switch-stats [percore|non-zero]"},
	{"reset-l2switch-stats", reset_l2switch_stats, "Reset l2switch statistics"},
#endif
	{"dump-stats", dump_stats, "Dump all statistics: dump-stats [percore|non-zero]"},
	{"reset-stats", reset_stats, "Reset all statistics"},
	{"dump-interface-stats", dump_interface_stats, "Dump network interface statistics: dump-interface-stats [percore|non-zero]"},
	{"dump-port-stats", dump_port_stats, "Dump network port statistics: dump-port-stats [percore|non-zero]"},
#ifdef CONFIG_MCORE_BRIDGE
	{"dump-l2-stats", dump_l2_stats, "Dump L2 statistics: dump-l2-stats [percore|non-zero]"},
#endif
#ifdef CONFIG_MCORE_IP
	{"dump-ip-stats", dump_ip_stats, "Dump IPv4 statistics: dump-ip-stats [percore|non-zero]"},
#endif
#ifdef CONFIG_MCORE_IPV6
	{"dump-ip6-stats", dump_ip6_stats, "Dump IPv6 statistics: dump-ip6-stats [percore|non-zero]"},
#endif
	{"dump-global-stats", dump_global_stats, "Dump global statistics: dump-global-stats [percore|non-zero]"},
#ifdef CONFIG_MCORE_ARP_REPLY
	{"dump-arp-stats", dump_arp_stats, "Dump ARP statistics: dump-arp-stats [percore|non-zero]"},
#endif
	{"dump-exception-stats", dump_exception_stats, "Dump exception statistics: dump-exception-stats [percore|non-zero]"},
#ifdef CONFIG_MCORE_MULTIBLADE
	{"dump-multiblade-stats", dump_multiblade_stats, "Dump multiblade statistics: dump-multiblade-stats [percore|non-zero]"},
#endif
	{ NULL, NULL, NULL },
};
static cli_cmds_t stats_cli = {
	.module = "stats",
	.c = stats_cmds,
};

static void fpdebug_stats_init(void) __attribute__ ((constructor));
void fpdebug_stats_init(void)
{
	fpdebug_add_commands(&stats_cli);
}
