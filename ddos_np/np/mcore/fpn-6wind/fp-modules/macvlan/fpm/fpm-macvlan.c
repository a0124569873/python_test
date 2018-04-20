/*
 * Copyright 2014 6WIND S.A.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>

#include "fpm_common.h"
#include "fpm_plugin.h"
#include "fp.h"
#include "shmem/fpn-shmem.h"

#include "fp-macvlan-var.h"
#include "fp-macvlan-lookup.h"

FPN_DEFINE_SHARED(fp_macvlan_shared_mem_t *, fp_macvlan_shared);

static uint32_t fpm_convert_mode(uint32_t cm_mode)
{
	uint32_t mode;

	switch (cm_mode) {
	case CP_MACVLAN_MODE_PRIVATE:
		mode = FP_MACVLAN_MODE_PRIVATE;
		break;
	case CP_MACVLAN_MODE_PASSTHRU:
		mode = FP_MACVLAN_MODE_PASSTHRU;
		break;
	default:
		mode = FP_MACVLAN_MODE_UNKNOWN;
		break;
	}

	return mode;
}

static int fpm_interface_macvlan_add(const uint8_t *request, 
				     const struct cp_hdr *hdr)
{
	struct cp_macvlan *req = (struct cp_macvlan *)request;
	uint32_t mode;
	int rc;

	if (f_verbose)
		syslog(LOG_DEBUG, "adding macvlan %s ifuid=0x%08x"
		       " vrfid=%"PRIu32" mtu=%"PRIu32
		       " mode=%"PRIu32" flags=%"PRIu16
		       " lower_ifuid=%"PRIu32" \n",
		       req->cpmacvlan_ifname, ntohl(req->cpmacvlan_ifuid),
		       ntohl(req->cpmacvlan_vrfid), ntohl(req->cpmacvlan_mtu),
		       ntohl(req->cpmacvlan_mode), ntohs(req->cpmacvlan_flags),
		       ntohl(req->cpmacvlan_link_ifuid));

	if ((ntohl(req->cpmacvlan_vrfid) & FP_VRFID_MASK) >= FP_MAX_VR)
		return EXIT_FAILURE;

	if (ntohl(req->cpmacvlan_maclen) != 6) {
		syslog(LOG_ERR, "ERROR %s: invalid MAC address length for %s (%d)\n",
		       __func__, req->cpmacvlan_ifname, req->cpmacvlan_maclen);
		return EXIT_FAILURE;
	}

	rc = fp_interface_add(ntohl(req->cpmacvlan_vrfid) & FP_VRFID_MASK,
			      req->cpmacvlan_ifname, req->cpmacvlan_mac,
			      ntohl(req->cpmacvlan_mtu), req->cpmacvlan_ifuid,
			      ntohl(req->cpmacvlan_vnb_nodeid),
			      FP_IFNET_VIRTUAL_PORT, FP_IFTYPE_MACVLAN,
			      fpm_graceful_restart_in_progress);

	if (unlikely(rc == FP_ADDIFNET_EXIST)) {
		syslog(LOG_DEBUG, "%s: interface exists\n", __FUNCTION__);
		return EXIT_SUCCESS;
	}

	if (unlikely(rc != FP_ADDIFNET_SUCCESS)) {
		syslog(LOG_ERR, "%s: interface add fails\n", __FUNCTION__);
		return EXIT_FAILURE;
	}

	mode = fpm_convert_mode(ntohl(req->cpmacvlan_mode));

	if (fp_addifnet_macvlaninfo(req->cpmacvlan_ifuid, 
				    req->cpmacvlan_link_ifuid,
				    mode) < 0)
		return EXIT_FAILURE;
	
	return EXIT_SUCCESS;
}

static int fpm_interface_macvlan_del(const uint8_t *request, 
				     const struct cp_hdr *hdr)
{
	const struct cp_macvlan *req = (const struct cp_macvlan *)request;
	uint32_t ifuid = req->cpmacvlan_ifuid;

	if (f_verbose)
		syslog(LOG_DEBUG, "removing macvlan %s ifuid=0x%08x\n",
		       req->cpmacvlan_ifname, ntohl(req->cpmacvlan_ifuid));

	fp_delifnet_macvlaninfo(ifuid);
	if (fp_interface_del(ifuid, 0,
			     fpm_graceful_restart_in_progress) < 0) {
		syslog(LOG_ERR, "%s: fail to del ifnet.\n", __FUNCTION__);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int fpm_interface_macvlan_update(const uint8_t *request, 
					const struct cp_hdr *hdr)
{
	struct cp_macvlan *req = (struct cp_macvlan *)request;
	uint32_t mode;

	if (f_verbose)
		syslog(LOG_DEBUG, "update macvlan %s ifuid=0x%08x"
		       " mode=%"PRIu32" flags=%"PRIu16" \n",
		       req->cpmacvlan_ifname, ntohl(req->cpmacvlan_ifuid),
		       ntohl(req->cpmacvlan_mode),
		       ntohs(req->cpmacvlan_flags));

	mode = fpm_convert_mode(ntohl(req->cpmacvlan_mode));

	if (fp_updateifnet_macvlaninfo(req->cpmacvlan_ifuid, 
				       mode) < 0) {
		syslog(LOG_ERR, "%s: fail to update ifnet.\n", __FUNCTION__);
		return EXIT_FAILURE;
	}
	
	return EXIT_SUCCESS;
}

static int fpm_macvlan_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_macvlan *if1 = cmd1->data;
	struct cp_macvlan *if2 = cmd2->data;

	if ((if1->cpmacvlan_ifuid == if2->cpmacvlan_ifuid) &&
	    (!strcmp(if1->cpmacvlan_ifname, if2->cpmacvlan_ifname))) {
		return 0;
	}
	return 1;
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_macvlan_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_MACVLAN_DELETE);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}

static void fpm_macvlan_display(const fpm_cmd_t *fpm_cmd,
                                 char *buffer, int len)
{
	struct cp_macvlan *data = fpm_cmd->data;

	snprintf(buffer, len, "CMD_MACVLAN_CREATE - %s(0x%08x)\n",
	   data->cpmacvlan_ifname, ntohl(data->cpmacvlan_ifuid));
}

static fpm_cmd_t *fpm_macvlan_graceful(int gr_type, uint32_t cmd,
                                   const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_INTERFACE, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_macvlan));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_INTERFACE;
	fpm_cmd->comp    = fpm_macvlan_comp;
	fpm_cmd->revert  = fpm_macvlan_revert;
	fpm_cmd->display = fpm_macvlan_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}

static int fpm_macvlan_shared_cmd(int gr_type, enum list_type list)
{
	int if_idx;
	int ret = 0;

	/* Dump interfaces if needed */
	if (!fpm_cmd_match_gr_type(FPM_CMD_INTERFACE, gr_type)) 
		return 0;

	for (if_idx=0 ; if_idx<FP_MAX_IFNET ; if_idx++) {
		fp_ifnet_t *ifp;

		ifp = &fp_shared->ifnet.table[if_idx];

		/* If interface is not valid, continue */
		if (ifp->if_ifuid == 0) 
			continue;

		/* Add requests for supported interfaces types */
		if (ifp->if_type == FP_IFTYPE_MACVLAN) {
			struct cp_macvlan req;

			/* Clear memory */
			memset(&req, 0, sizeof(req));

			req.cpmacvlan_ifuid = ifp->if_ifuid;
			strcpy(req.cpmacvlan_ifname, ifp->if_name);
		
			ret |= fpm_cmd_create_and_enqueue(list, CMD_MACVLAN_CREATE, &req);
		}
	}

	return ret;
}

static void fpm_macvlan_init(int graceful)
{
	fp_macvlan_shared = fpn_shmem_mmap(FP_MACVLAN_SHARED, NULL, 
					   sizeof(fp_macvlan_shared_mem_t));
	if (fp_macvlan_shared == NULL) {
		syslog(LOG_ERR, "Could not get macvlan shared memory\n");
		return;
	}

	fp_macvlan_init_shmem(graceful);

	fpm_interface_register_del_event(FP_IFTYPE_MACVLAN,
					 fp_delifnet_macvlaninfo);
	fpm_register_msg(CMD_MACVLAN_CREATE, fpm_interface_macvlan_add, fpm_macvlan_graceful);
	fpm_register_msg(CMD_MACVLAN_DELETE, fpm_interface_macvlan_del, NULL);
	fpm_register_msg(CMD_MACVLAN_UPDATE, fpm_interface_macvlan_update, NULL);
}

static struct fpm_mod fpm_macvlan_mod = {
	.name = "macvlan",
	.init = fpm_macvlan_init,
	.shared_cmd = fpm_macvlan_shared_cmd,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_macvlan_mod);
}
