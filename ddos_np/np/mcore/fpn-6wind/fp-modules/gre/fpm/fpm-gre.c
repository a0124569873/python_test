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

#include "fp-gre-var.h"

FPN_DEFINE_SHARED(fp_gre_shared_mem_t *, fp_gre_shared);

static uint8_t fpm_gre_parse_mode(const u_int8_t mode)
{
	uint8_t fp_mode = FP_GRE_MODE_UNKNOWN;

	if (mode == CP_GRE_MODE_ETHER)
		fp_mode = FP_GRE_MODE_ETHER;
	if (mode == CP_GRE_MODE_IP)
		fp_mode = FP_GRE_MODE_IP;

	return fp_mode;
}

static uint16_t fpm_gre_parse_flags(const u_int16_t flags)
{
	uint16_t fp_flags = 0;

	if (flags & CP_GRE_FLAG_CSUM)
		fp_flags |= FP_GRE_FLAG_CSUM;
	if (flags & CP_GRE_FLAG_KEY)
		fp_flags |= FP_GRE_FLAG_KEY;

	return fp_flags;
}

static int fpm_interface_gre_add(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_gre *req = (struct cp_gre *)request;
	uint16_t iflags, oflags;
	uint8_t mode;
	int res;

	if (f_verbose)
		syslog(LOG_DEBUG, "adding GRE %s ifuid=0x%08x vrfid=%"PRIu32" mtu=%"PRIu32"\n",
		       req->cpgre_ifname, ntohl(req->cpgre_ifuid), ntohl(req->cpgre_vrfid),
		       ntohl(req->cpgre_mtu));

	if ((ntohl(req->cpgre_vrfid) & FP_VRFID_MASK) >= FP_MAX_VR) {
		syslog(LOG_ERR, "%s: vrfid (%"PRIu32") too high, max is %d\n", __FUNCTION__,
		       (ntohl(req->cpgre_vrfid) & FP_VRFID_MASK), FP_MAX_VR);
		return EXIT_FAILURE;
	}

	if ((ntohl(req->cpgre_linkvrfid) & FP_VRFID_MASK) >= FP_MAX_VR) {
		syslog(LOG_ERR, "%s: link vrfid (%"PRIu32") too high, max is %d\n",
		       __FUNCTION__, (ntohl(req->cpgre_linkvrfid) & FP_VRFID_MASK),
		       FP_MAX_VR);
		return EXIT_FAILURE;
	}

	mode = fpm_gre_parse_mode(req->cpgre_mode);

	iflags = fpm_gre_parse_flags(ntohs(req->cpgre_iflags));
	oflags = fpm_gre_parse_flags(ntohs(req->cpgre_oflags));

	if (mode == FP_GRE_MODE_IP)
		res = fp_interface_add(ntohl(req->cpgre_vrfid) & FP_VRFID_MASK,
				       req->cpgre_ifname, NULL, ntohl(req->cpgre_mtu),
				       req->cpgre_ifuid, 0, FP_IFNET_VIRTUAL_PORT,
				       FP_IFTYPE_GRE, fpm_graceful_restart_in_progress);
	else
		res = fp_interface_add(ntohl(req->cpgre_vrfid) & FP_VRFID_MASK,
				       req->cpgre_ifname, req->cpgretap_mac,
				       ntohl(req->cpgre_mtu), req->cpgre_ifuid,
				       ntohl(req->cpgretap_vnb_nodeid),
				       FP_IFNET_VIRTUAL_PORT, FP_IFTYPE_GRETAP,
				       fpm_graceful_restart_in_progress);

	if (unlikely(res == FP_ADDIFNET_EXIST)) {
		syslog(LOG_DEBUG, "%s: interface exists\n", __FUNCTION__);
		return EXIT_SUCCESS;
	}

	if (unlikely(res != FP_ADDIFNET_SUCCESS)) {
		syslog(LOG_ERR, "%s: interface add fails\n", __FUNCTION__);
		return EXIT_FAILURE;
	}

	if (fp_addifnet_greinfo(req->cpgre_ifuid, req->cpgre_linkifuid, iflags,
				oflags, mode, req->cpgre_ikey, req->cpgre_okey,
				req->cpgre_ttl, req->cpgre_tos, req->cpgre_inh_tos,
				req->cpgre_family, &req->cpgre_laddr,&req->cpgre_raddr,
				ntohl(req->cpgre_linkvrfid) & FP_VRFID_MASK) < 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

static int fpm_interface_gre_update(const uint8_t *request,
				    const struct cp_hdr *hdr)
{
	struct cp_gre *req = (struct cp_gre *)request;
	uint8_t mode;
	uint16_t iflags, oflags;

	if (f_verbose)
		syslog(LOG_DEBUG, "updating GRE %s ifuid=0x%08x vrfid=%"PRIu32" mtu=%"PRIu32"\n",
		       req->cpgre_ifname, ntohl(req->cpgre_ifuid), ntohl(req->cpgre_vrfid),
		       ntohl(req->cpgre_mtu));

	if ((ntohl(req->cpgre_vrfid) & FP_VRFID_MASK) >= FP_MAX_VR) {
		syslog(LOG_ERR, "%s: vrfid too (%"PRIu32") high, max is %d\n", __FUNCTION__,
		       (ntohl(req->cpgre_vrfid) & FP_VRFID_MASK), FP_MAX_VR);
		return EXIT_FAILURE;
	}

	if ((ntohl(req->cpgre_linkvrfid) & FP_VRFID_MASK) >= FP_MAX_VR) {
		syslog(LOG_ERR, "%s: link vrfid (%"PRIu32") too high, max is %d\n",
		       __FUNCTION__, (ntohl(req->cpgre_linkvrfid) & FP_VRFID_MASK),
		       FP_MAX_VR);
		return EXIT_FAILURE;
	}

	mode = fpm_gre_parse_mode(req->cpgre_mode);

	iflags = fpm_gre_parse_flags(ntohs(req->cpgre_iflags));
	oflags = fpm_gre_parse_flags(ntohs(req->cpgre_oflags));

	if (fp_upifnet_greinfo(req->cpgre_ifuid, req->cpgre_linkifuid, iflags,
			       oflags, mode, req->cpgre_ikey, req->cpgre_okey,
			       req->cpgre_ttl, req->cpgre_tos, req->cpgre_inh_tos,
			       req->cpgre_family, &req->cpgre_laddr,&req->cpgre_raddr,
			       ntohl(req->cpgre_linkvrfid) & FP_VRFID_MASK) < 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

static int fpm_interface_gre_del(const uint8_t *request,
				 const struct cp_hdr *hdr)
{
	struct cp_gre *req = (struct cp_gre *)request;
	uint32_t ifuid = req->cpgre_ifuid;

	if (f_verbose)
		syslog(LOG_DEBUG, "removing GRE iface %s\n", req->cpgre_ifname);

	fp_delifnet_greinfo(ifuid);
	if (fp_interface_del(ifuid, 0,
			     fpm_graceful_restart_in_progress) < 0) {
		syslog(LOG_ERR, "%s: fail to del ifnet.\n", __FUNCTION__);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int fpm_interface_gretap_del(const uint8_t *request,
				    const struct cp_hdr *hdr)
{
	struct cp_gre *req = (struct cp_gre *)request;
	uint32_t ifuid = req->cpgre_ifuid;

	if (f_verbose)
		syslog(LOG_DEBUG, "removing GRETAP iface %s\n", req->cpgre_ifname);

	fp_delifnet_gretapinfo(ifuid);
	if (fp_interface_del(ifuid, 0,
			     fpm_graceful_restart_in_progress) < 0) {
		syslog(LOG_ERR, "%s: fail to del ifnet.\n", __FUNCTION__);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}


static int fpm_gre_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_gre *if1 = cmd1->data;
	struct cp_gre *if2 = cmd2->data;

	if ((if1->cpgre_ifuid == if2->cpgre_ifuid) &&
	    (!strcmp(if1->cpgre_ifname, if2->cpgre_ifname))) {
		return 0;
	}
	return 1;
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_gre_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;
	struct cp_gre *req = fpm_cmd->data;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	if (req->cpgre_mode == CP_GRE_MODE_IP)
		hdr->cphdr_type = htonl(CMD_GRE_DELETE);
	else
		hdr->cphdr_type = htonl(CMD_GRETAP_DELETE);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}

static void fpm_gre_display(const fpm_cmd_t *fpm_cmd,
                                 char *buffer, int len)
{
	struct cp_gre *data = fpm_cmd->data;

	snprintf(buffer, len, "CMD_GRE_ADD - %s(0x%08x)\n",
	   data->cpgre_ifname, ntohl(data->cpgre_ifuid));
}

static fpm_cmd_t *fpm_gre_graceful(int gr_type, uint32_t cmd,
                                   const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_INTERFACE, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_gre));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_INTERFACE;
	fpm_cmd->comp    = fpm_gre_comp;
	fpm_cmd->revert  = fpm_gre_revert;
	fpm_cmd->display = fpm_gre_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}

static int fpm_gre_shared_cmd(int gr_type, enum list_type list)
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
		if (ifp->if_type == FP_IFTYPE_GRE) {
			struct cp_gre req;

			/* Clear memory */
			memset(&req, 0, sizeof(req));

			req.cpgre_ifuid = ifp->if_ifuid;
			strcpy(req.cpgre_ifname, ifp->if_name);
			req.cpgre_mode = CP_GRE_MODE_IP;

			ret |= fpm_cmd_create_and_enqueue(list, CMD_GRE_CREATE, &req);
		}
		if (ifp->if_type == FP_IFTYPE_GRETAP) {
			struct cp_gre req;

			/* Clear memory */
			memset(&req, 0, sizeof(req));

			req.cpgre_ifuid = ifp->if_ifuid;
			strcpy(req.cpgre_ifname, ifp->if_name);
			req.cpgre_mode = CP_GRE_MODE_ETHER;

			ret |= fpm_cmd_create_and_enqueue(list, CMD_GRE_CREATE, &req);
		}
	}

	return ret;
}

static void fpm_gre_init(int graceful)
{
	fp_gre_shared = fpn_shmem_mmap(FP_GRE_SHARED, NULL,
				       sizeof(fp_gre_shared_mem_t));
	if (fp_gre_shared == NULL) {
		syslog(LOG_ERR, "Could not get GRE shared memory.\n");
		return;
	}

	fp_gre_init_shmem(graceful);

	fpm_interface_register_del_event(FP_IFTYPE_GRE, fp_delifnet_greinfo);
	fpm_interface_register_del_event(FP_IFTYPE_GRETAP, fp_delifnet_gretapinfo);
	fpm_register_msg(CMD_GRE_CREATE, fpm_interface_gre_add, fpm_gre_graceful);
	fpm_register_msg(CMD_GRE_UPDATE, fpm_interface_gre_update, NULL);
	fpm_register_msg(CMD_GRE_DELETE, fpm_interface_gre_del, NULL);
	fpm_register_msg(CMD_GRETAP_DELETE, fpm_interface_gretap_del, NULL);
}

static struct fpm_mod fpm_gre_mod = {
	.name = "gre",
	.init = fpm_gre_init,
	.shared_cmd = fpm_gre_shared_cmd,
};

static void init(void) __attribute__((constructor));
void init (void)
{
	fpm_mod_register(&fpm_gre_mod);
}
