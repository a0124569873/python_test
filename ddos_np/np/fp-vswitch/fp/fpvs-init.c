/*
 * Copyright (C) 2014 6WIND, All rights reserved.
 */

#include <sys/types.h>
#include <unistd.h>

#include "fp.h"
#include "fp-main-process.h"
#include "fp-log.h"
#include "fp-vswitch.h"
#include "fpvs-datapath.h"
#include "linux/openvswitch.h"
#include "fpn-lock.h"
#include "fpn-shmem.h"
#include "fp-hlist.h"
#include "fp-module.h"

#ifdef CONFIG_MCORE_VXLAN
#include "fpvs-vxlan.h"
#endif
#ifdef CONFIG_MCORE_GRE
#include "fpvs-gre.h"
#endif

static fp_netfpc_hook_t newif_hook = { .func = fpvs_ifchange };

static void fpvs_mod_init(void);

const char *fpvs_dependency_list[] =
{
#ifdef CONFIG_MCORE_GRE
"gre",
#endif
NULL};

static struct fp_mod fpvs_mod = {
	.name = "fp-vswitch",
	.dependency_list = fpvs_dependency_list,
	.init = fpvs_mod_init,
	.if_ops = {
		[RX_DEV_OPS] = fpvs_ether_input,
		[TX_DEV_OPS] = fpvs_if_output,
	},
};

static void fpvs_mod_init(void)
{
	FP_LOG_REGISTER(VSWITCH);

	/* Create shared memories */
	fpn_shmem_add("fpvs-shared", sizeof(fpvs_shared_mem_t));
	fpn_shmem_add("fpvs_flow_table", sizeof(fpvs_flow_list_t) + FPVS_FLOW_ALIGNMENT - 1);

	/* Map shared memories */
	if (fpvs_map_shm() < 0) {
		FP_LOG(FP_LOG_ERR, VSWITCH, "%s: Could not get fpvs shared memories.\n", __FUNCTION__);
		return;
	}

	fpvs_init_shmem(1);

	fpvs_shared->mod_uid = fpvs_mod.uid;
	fp_netfpc_add_hook(NETFPC_MSGTYPE_NEWIF, &newif_hook);
#ifdef CONFIG_MCORE_VXLAN
	fp_vxlan_fpvs_input_register(fpvs_vxlan_input);
#endif
#ifdef CONFIG_MCORE_GRE
	fp_gretap_fpvs_input_register(fpvs_gre_input);
#endif
}

FP_MOD_REGISTER(fpvs_mod)
