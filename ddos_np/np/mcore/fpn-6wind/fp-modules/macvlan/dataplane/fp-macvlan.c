/*
 *  Copyright 2014 6WIND S.A.
 */

#include "fpn.h"
#include "fp-includes.h"

#include "fp.h"
#include "shmem/fpn-shmem.h"
#include "fp-module.h"
#include "fp-netfpc.h"

#include "fp-log.h"
#include "fp-ether.h"
#include "net/fp-ethernet.h"
#include "fp-main-process.h"

#include "fp-macvlan-var.h"
#include "fp-macvlan-lookup.h"

FPN_DEFINE_SHARED(fp_macvlan_shared_mem_t *, fp_macvlan_shared);

#define TRACE_MACVLAN(level, fmt, args...) do {\
	FP_LOG(level, MACVLAN, "%s: " fmt "\n", __func__, ## args);\
} while(0)

static int fp_macvlan_input(struct mbuf *m, fp_ifnet_t *ifp, void *data)
{
	struct fp_ether_header* vhdr = mtod(m, struct fp_ether_header *);
	uint32_t link_idx = (uint32_t)(uintptr_t)data;
	fp_macvlan_linkiface_t *vlinkiface;
	fp_macvlan_iface_t *viface = NULL;
	fp_ifnet_t *macvlanifp;
	uint32_t i;

	/* Check if the packet is for the MACVLAN interface 
	 * by comparing MAC address 
	 */
	vlinkiface = fp_macvlan_linkidx2linkiface(link_idx);
	for (i=0; i<FP_MACVLAN_IFACE_MAX; i++) {
		uint32_t ifuid;

		ifuid = vlinkiface->macvlan_iface[i].ifuid;
		if (ifuid != 0) {
			macvlanifp = __fp_ifuid2ifnet(ifuid);
			if (memcmp(macvlanifp->if_mac,
				vhdr->ether_dhost,6) == 0) {
				viface = &vlinkiface->macvlan_iface[i];
				break;
			}
		}
	}

	if (viface == NULL)
		return FP_CONTINUE;
	
	if (unlikely(!fp_ifnet_is_operative(macvlanifp))) {
		FP_GLOBAL_STATS_INC(fp_shared->global_stats, 
				    fp_droppedOperative);
		return FP_DROP;
	}

	/* Today only private and passthru mode are managed by fastpath */
	if (unlikely(viface->mode == FP_MACVLAN_MODE_UNKNOWN)) {
		TRACE_MACVLAN(FP_LOG_DEBUG,
			      "Mode of this macvlan is not managed");
		return fp_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	/* It is for the MACVLAN. Do the basic treatment */
	m_priv(m)->exc_type = FPTUN_ETH_INPUT_EXCEPT;
	m_priv(m)->exc_class = 0;
	m_priv(m)->exc_proto = 0;
	fp_change_ifnet_packet(m, macvlanifp, 1, 0);
	return FPN_HOOK_CALL(fp_ether_input)(m, macvlanifp);
}

static int fp_macvlan_output(struct mbuf *m, fp_ifnet_t *ifp, void *data)
{
	uint32_t link_idx = (uint32_t)(uintptr_t)data;
	uint32_t idx = ifp->sub_table_index;
	fp_macvlan_linkiface_t *vlinkiface;
	fp_macvlan_iface_t *viface;
	fp_ifnet_t *link_ifp;

	vlinkiface = fp_macvlan_linkidx2linkiface(link_idx);
	viface = fp_macvlan_idxs2iface(link_idx,idx);

	/* Today only private and passthru mode are managed by fastpath */
	if (unlikely(viface->mode == FP_MACVLAN_MODE_UNKNOWN)) {
		TRACE_MACVLAN(FP_LOG_DEBUG,
			      "Mode of this macvlan is not managed");
		return fp_prepare_exception(m, FPTUN_EXC_SP_FUNC);
	}

	link_ifp = __fp_ifuid2ifnet(vlinkiface->link_ifuid);

	TRACE_MACVLAN(FP_LOG_DEBUG, "called out name %s", link_ifp->if_name);
	FP_IF_STATS_INC(ifp->if_stats, ifs_opackets);
	FP_IF_STATS_ADD(ifp->if_stats, ifs_obytes, m_len(m));
	set_mvrfid(m, ifp2vrfid(link_ifp));
	return FPN_HOOK_CALL(fp_if_output)(m, link_ifp);
}

static void* fp_macvlan_shared_alloc(void)
{
	void *addr;

	/* Create fp-macvlan-shared memory.*/
	fpn_shmem_add(FP_MACVLAN_SHARED, sizeof(fp_macvlan_shared_mem_t));
	addr = fpn_shmem_mmap(FP_MACVLAN_SHARED, NULL, 
			      sizeof(fp_macvlan_shared_mem_t));
	if (addr == NULL) {
		fpn_printf("cannot map fp_macvlan_shared size=%"PRIu64" (%"PRIu64"M)\n",
			   (uint64_t)sizeof(fp_macvlan_shared_mem_t),
			   (uint64_t)sizeof(fp_macvlan_shared_mem_t) >> 20);
		return NULL;
	}
	fpn_printf("Using fp_macvlan_shared=%p size=%"PRIu64" (%"PRIu64"M)\n",
		   addr, (uint64_t)sizeof(fp_macvlan_shared_mem_t),
		   (uint64_t)sizeof(fp_macvlan_shared_mem_t) >> 20);

	return addr;
}

static void fp_macvlan_init(void);

static struct fp_mod macvlan_mod = {
	.name = "macvlan",
	.init = fp_macvlan_init,
	.if_ops = {
		[RX_DEV_OPS] = fp_macvlan_input,
		[TX_DEV_OPS] = fp_macvlan_output,
	},
};

static void fp_macvlan_init(void)
{
	FP_LOG_REGISTER(MACVLAN);

	fp_macvlan_shared = (fp_macvlan_shared_mem_t *)fp_macvlan_shared_alloc();
	if (fp_macvlan_shared == NULL) {
		TRACE_MACVLAN(FP_LOG_ERR, "Could not get macvlan shared memory");
		return;
	}

	fp_macvlan_init_shmem(1);

	fp_macvlan_shared->mod_uid = macvlan_mod.uid;
}

FP_MOD_REGISTER(macvlan_mod)
