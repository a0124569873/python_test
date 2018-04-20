/*
 * Copyright(c) 2014 6WIND
 * All rights reserved
 */
#ifndef __FastPath__
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#endif

#include "fpn.h"
#include "fp.h"
#include "fp-if.h"
#include "fpdebug.h"
#include "fpdebug-priv.h"
#include "fpdebug-stats.h"
#include "fpdebug-ifnet.h"

#include "shmem/fpn-shmem.h"
#include "fp-vnb.h"

static fp_vnb_shared_mem_t *get_fp_vnb_shared_mem(void)
{
	static fp_vnb_shared_mem_t *vnb_shared = NULL;

	if (vnb_shared == NULL)
		vnb_shared = fpn_shmem_mmap("fp-vnb-shared", NULL,
		                            sizeof(fp_vnb_shared_mem_t));
	return vnb_shared;
}

static int vnb_expected_seqnum(char *tok)
{
	fp_vnb_shared_mem_t *fp_vnb_shared;

	fp_vnb_shared = get_fp_vnb_shared_mem();
	if (fp_vnb_shared == NULL) {
		fpdebug_printf("fp-vnb shared memory not available\n");
		return -1;
	}

	if (gettokens(tok) != 0) {
		uint32_t val = strtoul(chargv[0], NULL, 0);

		fp_vnb_shared->expected_seqnum = val;
	}
	fpdebug_printf("Expected sequence number for next VNB message"	\
	       " from CM: %"PRIu32"\n",
	       fp_vnb_shared->expected_seqnum);
	return 0;
}

static CLI_COMMAND vnb_cmds[] = {
	{ "vnb-expected-seqnum",
	  vnb_expected_seqnum,
	  "set/show expected sequence number of next VNB Netlink message [val]"
	},
	{ NULL, NULL, NULL },
};
static cli_cmds_t vnb_cli = {
	.module = "vnb",
	.c = vnb_cmds,
};

static int dump_vnb_ifnet_info(fp_ifnet_t *ifp)
{
	fp_vnb_shared_mem_t *fp_vnb_shared;
	uint32_t fp_data_vnb_ns = 0;
	uint8_t vnb_flags;

	fp_vnb_shared = get_fp_vnb_shared_mem();
	if (fp_vnb_shared)
		fp_data_vnb_ns = fp_get_vnb_ns();
	else {
		fpdebug_printf("fp-vnb shared memory not available\n");
		return -1;
	}

	vnb_flags = IFP2FLAGS(ifp, fp_data_vnb_ns);
	if (!vnb_flags)
		return 0;

	fpdebug_printf("\tvnb:");
	if (vnb_flags & IFF_NG_ETHER)
		fpdebug_printf(" ng_ether");
	if (vnb_flags & IFF_NG_EIFACE)
		fpdebug_printf(" ng_eiface");
	if (vnb_flags & IFF_NG_IFACE)
		fpdebug_printf(" ng_iface");
	fpdebug_printf("\n");
	return 0;
}

static FPN_DEFINE_SHARED(fpdebug_ifnet_info_t, vnb_ifnet_info) = {
	.func = dump_vnb_ifnet_info
};

static void fpdebug_vnb_init(void) __attribute__((constructor));
void fpdebug_vnb_init(void)
{
	fpdebug_add_commands(&vnb_cli);
	fpdebug_add_ifnet_info(&vnb_ifnet_info);
}
