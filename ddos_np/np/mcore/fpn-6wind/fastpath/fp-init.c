/*
 * Copyright(c) 2008 6WIND
 */

#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"
#include "fp-init.h"

#ifdef CONFIG_MCORE_IP_REASS
#include "fp-reass.h"
#endif
#ifdef CONFIG_MCORE_IPV6_REASS
#include "fp-reass6.h"
#endif
#ifdef CONFIG_MCORE_IPSEC
#include "fp-ipsec-input.h"
#include "fp-ipsec-output.h"
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
#include "fp-ipsec6-input.h"
#include "fp-ipsec6-output.h"
#endif
#ifdef CONFIG_MCORE_NETFILTER
#include "fp-nf-tables.h"
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
#include "fp-nf6-tables.h"
#endif
#ifdef CONFIG_MCORE_NETFILTER_CACHE
#include "fp-nf-cache.h"
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE
#include "fp-nf6-cache.h"
#endif
#ifdef CONFIG_MCORE_FPU_RPC
#include "fpu-rpc.h"
#endif
#ifdef CONFIG_MCORE_SOCKET
#include "fp-so.h"
#endif
#ifdef CONFIG_MCORE_TRAFFIC_GEN
#include "fp-traffic-gen.h"
#endif
#ifdef CONFIG_MCORE_MULTICAST4
#include "fp-mcast.h"
#endif
#ifdef CONFIG_MCORE_MULTICAST6
#include "fp-mcast6.h"
#endif
#ifdef CONFIG_MCORE_EMBEDDED_FPDEBUG
#include "fpdebug.h"
#endif
#ifdef CONFIG_MCORE_DEBUG_PROBE
#include "fp-probe.h"
#endif
#ifdef CONFIG_MCORE_L2SWITCH
#include "fp-l2switch.h"
#endif
#ifndef CONFIG_MCORE_FPN_CRYPTO_ASYNC
#ifdef CONFIG_MCORE_IPSEC
FPN_DEFINE_PER_CORE(fp_ipsec_ctx_t, fp_ipsec_context);
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
FPN_DEFINE_PER_CORE(fp_ipsec6_ctx_t, fp_ipsec6_context);
#endif
#endif
#include "fp-netfpc.h"
#include "fp-module.h"

static void fp_init_lognames(void)
{
	memset(fp_shared->logname, 0, sizeof(fp_shared->logname));

	FP_LOG_REGISTER(MAIN_PROC);
	FP_LOG_REGISTER(EXC);
	FP_LOG_REGISTER(IP);
	FP_LOG_REGISTER(FRAG);
	FP_LOG_REGISTER(IPSEC_IN);
	FP_LOG_REGISTER(IPSEC_OUT);
	FP_LOG_REGISTER(IPSEC_REPL);
	FP_LOG_REGISTER(NF);
	FP_LOG_REGISTER(REASS);
	FP_LOG_REGISTER(TUNNEL);
	FP_LOG_REGISTER(NETFPC);
	FP_LOG_REGISTER(CRYPTO);
	FP_LOG_REGISTER(TAP);
	FP_LOG_REGISTER(NF_CACHE);
	FP_LOG_REGISTER(IPSEC_LOOKUP);
	FP_LOG_REGISTER(HF_SYNC);
	FP_LOG_REGISTER(TRAFFIC_GEN);
	FP_LOG_REGISTER(IPSEC6_IN);
	FP_LOG_REGISTER(IPSEC6_OUT);
	FP_LOG_REGISTER(IPSEC6_LOOKUP);
	FP_LOG_REGISTER(RFPS);
	FP_LOG_REGISTER(SOCKET);
	FP_LOG_REGISTER(PCB);
	FP_LOG_REGISTER(TCP);
	FP_LOG_REGISTER(UDP);
	FP_LOG_REGISTER(ARP);
	FP_LOG_REGISTER(RPC);
	FP_LOG_REGISTER(USO);
	FP_LOG_REGISTER(VXLAN);
	FP_LOG_REGISTER(VLAN);
	FP_LOG_REGISTER(USER);
}

int fp_process_init_global(void)
{
	unsigned port, op;

	/* First, init debug levels to enable logs:
	 * all logs >= WARNING activated by default */
	fp_shared->debug.level = FP_LOG_WARNING;
	fp_shared->debug.type = ~(0);
	fp_shared->debug.mode = FP_LOG_MODE_CONSOLE;

#ifdef CONFIG_MCORE_CPONLY_PORTMASK
	/* CP-only portmask */
	fp_shared->cponly_portmask = 0;
#endif

	/* Reset cached_ifp in shared mem, they may come from a previous FP instance */
	for (port = 0 ; port < sizeof(fp_shared->ifport)/sizeof(fp_ifport_t); port++)
		fp_shared->ifport[port].cached_ifp = 0;

	/* Setup ports in case of graceful restart */
	for (port = 0 ; port < FP_MAX_IFNET; port++) {
		fp_ifnet_t *ifp = &fp_shared->ifnet.table[port];

		if (ifp->if_ifuid == 0)
			continue;

		/* Reset cached devops functions in shared mem */
		for (op = 0 ; op < FP_IFNET_MAX_OPS ; op++)
			ifp->if_ops[op].func = INVALID_FUNC;

		/* Restore all features as specified in shared memory */
		if (ifp->if_port != FP_IFNET_VIRTUAL_PORT) {
			fp_interface_set_mac(ifp, ifp->if_mac);
			fp_interface_set_mtu(ifp, ifp->if_mtu);
			fp_interface_set_flags(ifp, ifp->if_flags);
		}
	}

	fp_init_lognames();

	/* check that we have enough room in mbuf to store the m_priv,
	 * else do an error at compilation time. */
	FPN_BUILD_BUG_ON(sizeof(fp_mbuf_priv_t) > FPN_MBUF_PRIV_MAX_SIZE);
	FPN_BUILD_BUG_ON(fpn_offsetof(fp_mbuf_priv_t, end_of_copy) >
			 FPN_MBUF_PRIV_COPY_SIZE);

	/* init mbuf tag types */
	m_tag_init();

#ifdef CONFIG_MCORE_IP_REASS
	/* init IPv4 reassembly tables */
	fp_ip_reass_init();
#endif

#ifdef CONFIG_MCORE_IPV6_REASS
	/* init IPv6 reassembly tables */
	fp_ipv6_reass_init();
#endif



	/* Init Enter/Exit debug information*/
	fpn_core_init();

#ifdef CONFIG_MCORE_IPSEC
	fp_ipsec_input_init();
	fp_ipsec_output_init();
#ifdef CONFIG_MCORE_IPSEC_TRIE
	fp_ipsec_trie_init();
#endif
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_ipsec6_input_init();
	fp_ipsec6_output_init();
#endif

#ifdef CONFIG_MCORE_NETFILTER
	fp_nf_init();
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6
	fp_nf6_init();
#endif
#ifdef CONFIG_MCORE_NETFILTER_CACHE
	fp_nf_cache_init();
#endif
#ifdef CONFIG_MCORE_NETFILTER_IPV6_CACHE
	fp_nf6_cache_init();
#endif
#ifdef CONFIG_MCORE_TAP
	fp_tap_init();
#endif
#ifdef CONFIG_MCORE_MULTICAST4
	fp_mcast_init();
#endif
#ifdef CONFIG_MCORE_MULTICAST6
	fp_mcast6_init();
#endif
#ifdef CONFIG_MCORE_SOCKET
	fp_so_init();
#endif
#ifdef CONFIG_MCORE_TRAFFIC_GEN
	fp_traffic_gen_init();
#endif
#ifdef CONFIG_MCORE_EMBEDDED_FPDEBUG
	fpdebug_init();
#endif
#ifdef CONFIG_MCORE_DEBUG_PROBE
	fp_probe_init();
#endif
#ifdef CONFIG_MCORE_L2SWITCH
	fp_l2switch_init();
#endif
#ifdef CONFIG_MCORE_VXLAN
	fp_vxlan_init();
#endif
#ifdef CONFIG_MCORE_FPU_RPC
	if (fpu_rpc_init() < 0)
		return -1;
#endif
	return 0;
}
