/*
 * Copyright (c) 2013 6WIND
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <syslog.h>
#include <sys/types.h>

#include <net/ethernet.h>
#include <net/if.h>

#include <ctype.h>
#include <sys/queue.h>

#include "fpm_common.h"
#include "fpm_plugin.h"
#include "fp.h"

static int
fpm_interface_xin4_add(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_xin4 *req = (const struct cp_xin4 *)request;
	uint32_t ifuid = req->cpxin4_ifuid;
	int rc;

	if (f_verbose)
		syslog(LOG_DEBUG, "adding xin4 (ctu) %s ifuid=0x%08x bound to port %d\n, ttl=0x%X,"
		       " tos=0x%X, local=0x%X, remote=0x%X\n",
		       req->cpxin4_ifname, ntohl(ifuid), FP_IFNET_VIRTUAL_PORT, req->cpxin4_ttl,
		       req->cpxin4_tos,req->cpxin4_local.s_addr,req->cpxin4_remote.s_addr);

	if ((ntohl(req->cpxin4_vrfid) & FP_VRFID_MASK) >= FP_MAX_VR ||
	    (ntohl(req->cpxin4_linkvrfid) & FP_VRFID_MASK) >= FP_MAX_VR)
		return EXIT_FAILURE;

	rc = fp_interface_add(ntohl(req->cpxin4_vrfid) & FP_VRFID_MASK,
			      req->cpxin4_ifname, NULL, ntohl(req->cpxin4_mtu),
			      ifuid, 0, FP_IFNET_VIRTUAL_PORT, FP_IFTYPE_XIN4,
			      fpm_graceful_restart_in_progress);

	if (likely(rc == FP_ADDIFNET_SUCCESS)) {
		fp_addifnet_xin4info(ifuid, req->cpxin4_ttl,
				     req->cpxin4_tos, req->cpxin4_inh_tos,
				     ntohl(req->cpxin4_vrfid) & FP_VRFID_MASK,
				     ntohl(req->cpxin4_linkvrfid) & FP_VRFID_MASK,
				     (struct fp_in_addr *)&req->cpxin4_local.s_addr,
				     (struct fp_in_addr *)&req->cpxin4_remote.s_addr);

		if (f_coloc_1cp1fp && fp_shared) {
			fp_setifnet_bladeinfo(ifuid, fp_shared->fp_blade_id);
		}

		return EXIT_SUCCESS;
	} else if (rc == FP_ADDIFNET_EXIST)
		return EXIT_SUCCESS;
	else
		return EXIT_FAILURE;
}

static int
fpm_interface_xin4_del(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_xin4 *req = (const struct cp_xin4 *)request;
	uint32_t ifuid = req->cpxin4_ifuid;

	if (f_verbose)
		syslog(LOG_DEBUG, "removing xin4 (ctu) %s ifuid=0x%08x bound to port %d\n",
		       req->cpxin4_ifname, ntohl(req->cpxin4_ifuid), FP_IFNET_VIRTUAL_PORT);

	fp_delifnet_xinyinfo(ifuid);
	fp_interface_del(ifuid, 0, fpm_graceful_restart_in_progress);
	return EXIT_SUCCESS;
}

static int
fpm_interface_xin4_update(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_xin4 *req = (const struct cp_xin4 *)request;
	uint32_t ifuid = req->cpxin4_ifuid;
	int idx = __fp_ifuid2ifnet(ifuid)->sub_table_index;
	fp_tunnel_entry_t *tun;

	if (f_verbose)
		syslog(LOG_DEBUG, "updating xin4 (ctu) %s ifuid=0x%08x bound to port %d\n, ttl=0x%X,"
		       " tos=0x%X, local=0x%X, remote=0x%X\n",
		       req->cpxin4_ifname, ntohl(ifuid), FP_IFNET_VIRTUAL_PORT, req->cpxin4_ttl,
		       req->cpxin4_tos,req->cpxin4_local.s_addr,req->cpxin4_remote.s_addr);

	if (idx == 0)
		return EXIT_FAILURE;

	tun = &fp_shared->fp_tunnels.table[idx];
	fp_tunnel_unlink(idx);
	tun->p.xin4.ip_ttl = req->cpxin4_ttl;
	memcpy(&tun->p.xin4.ip_src, &req->cpxin4_local, sizeof(struct fp_in_addr));
	memcpy(&tun->p.xin4.ip_dst, &req->cpxin4_remote, sizeof(struct fp_in_addr));
	fp_tunnel_link(idx);
	return EXIT_SUCCESS;
}

#ifdef CONFIG_MCORE_XIN6
static int
fpm_interface_xin6_add(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_xin6 *req = (const struct cp_xin6 *)request;
	uint32_t ifuid = req->cpxin6_ifuid;
	int rc;

	if (f_verbose)
		syslog(LOG_DEBUG, "adding xin6 interface %s ifuid=0x%08x bound to port %d\n",
		       req->cpxin6_ifname, ntohl(ifuid), FP_IFNET_VIRTUAL_PORT);

	if ((ntohl(req->cpxin6_vrfid) & FP_VRFID_MASK) >= FP_MAX_VR ||
	    (ntohl(req->cpxin6_linkvrfid) & FP_VRFID_MASK) >= FP_MAX_VR)
		return EXIT_FAILURE;

	rc = fp_interface_add(ntohl(req->cpxin6_vrfid) & FP_VRFID_MASK,
			      req->cpxin6_ifname, NULL, ntohl(req->cpxin6_mtu),
			      ifuid, 0, FP_IFNET_VIRTUAL_PORT, FP_IFTYPE_XIN6,
			      fpm_graceful_restart_in_progress);

	if (likely(rc == FP_ADDIFNET_SUCCESS)) {
		fp_addifnet_xin6info(ifuid, req->cpxin6_hoplim,
				     req->cpxin6_tos, req->cpxin6_inh_tos,
				     ntohl(req->cpxin6_vrfid) & FP_VRFID_MASK,
				     ntohl(req->cpxin6_linkvrfid) & FP_VRFID_MASK,
				     (fp_in6_addr_t *)&req->cpxin6_local,
				     (fp_in6_addr_t *)&req->cpxin6_remote);

		if (f_coloc_1cp1fp && fp_shared) {
			fp_setifnet_bladeinfo(ifuid, fp_shared->fp_blade_id);
		}

		return EXIT_SUCCESS;
	} else if (rc == FP_ADDIFNET_EXIST)
		return EXIT_SUCCESS;
	else
		return EXIT_FAILURE;
}

static int
fpm_interface_xin6_del(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_xin6 *req = (const struct cp_xin6 *)request;
	uint32_t ifuid = req->cpxin6_ifuid;

	if (f_verbose)
		syslog(LOG_DEBUG, "removing xin6 (stu) %s ifuid=0x%08x bound to port %d\n",
		       req->cpxin6_ifname, ntohl(req->cpxin6_ifuid), FP_IFNET_VIRTUAL_PORT);

	fp_delifnet_xinyinfo(ifuid);
	fp_interface_del(ifuid, 0, fpm_graceful_restart_in_progress);

	return EXIT_SUCCESS;
}

static int
fpm_interface_xin6_update(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_xin6 *req = (const struct cp_xin6 *)request;
	uint32_t ifuid = req->cpxin6_ifuid;
	int idx = __fp_ifuid2ifnet(ifuid)->sub_table_index;
	fp_tunnel_entry_t *tun;

	if (f_verbose)
		syslog(LOG_DEBUG, "updating xin6 interface %s ifuid=0x%08x bound to port %d\n",
		       req->cpxin6_ifname, ntohl(ifuid), FP_IFNET_VIRTUAL_PORT);

	if (idx == 0)
		return EXIT_FAILURE;

	tun = &fp_shared->fp_tunnels.table[idx];
	fp_tunnel_unlink(idx);
	tun->p.xin6.ip6_hlim = req->cpxin6_hoplim;
	memcpy(&tun->p.xin6.ip6_src, &req->cpxin6_local, sizeof(struct fp_in6_addr));
	memcpy(&tun->p.xin6.ip6_dst, &req->cpxin6_remote, sizeof(struct fp_in6_addr));
	fp_tunnel_link(idx);
	return EXIT_SUCCESS;
}
#endif

static int fpm_interface_xin4_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_xin4* if1 = cmd1->data;
	struct cp_xin4* if2 = cmd2->data;

	if ((if1->cpxin4_ifuid == if2->cpxin4_ifuid) &&
	    (!strcmp(if1->cpxin4_ifname, if2->cpxin4_ifname))) {
		return 0;
	}
	return 1;
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_interface_xin4_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_XIN4_DELETE);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}

static void fpm_interface_xin4_display(const fpm_cmd_t *fpm_cmd,
                                       char *buffer, int len)
{
	struct cp_xin4 *data = fpm_cmd->data;

	snprintf(buffer, len, "CMD_XIN4 - %s(0x%08x)\n",
	   data->cpxin4_ifname, ntohl(data->cpxin4_ifuid));
}

static fpm_cmd_t *fpm_interface_xin4_graceful(int gr_type, uint32_t cmd,
                                              const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_TUNNEL, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_xin4));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_TUNNEL;
	fpm_cmd->comp    = fpm_interface_xin4_comp;
	fpm_cmd->revert  = fpm_interface_xin4_revert;
	fpm_cmd->display = fpm_interface_xin4_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}

#ifdef CONFIG_MCORE_XIN6
static int fpm_interface_xin6_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_xin6* if1 = cmd1->data;
	struct cp_xin6* if2 = cmd2->data;

	if ((if1->cpxin6_ifuid == if2->cpxin6_ifuid) &&
	    (!strcmp(if1->cpxin6_ifname, if2->cpxin6_ifname))) {
		return 0;
	}
	return 1;
}
#endif

#ifdef CONFIG_MCORE_XIN6
/* Invert the command, and send it to the fpm dispatch function */
static int fpm_interface_xin6_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_XIN6_DELETE);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}
#endif

#ifdef CONFIG_MCORE_XIN6
static void fpm_interface_xin6_display(const fpm_cmd_t *fpm_cmd,
                                       char *buffer, int len)
{
	struct cp_xin6 *data = fpm_cmd->data;

	snprintf(buffer, len, "CMD_XIN6 - %s(0x%08x)\n",
	   data->cpxin6_ifname, ntohl(data->cpxin6_ifuid));
}
#endif

#ifdef CONFIG_MCORE_XIN6
static fpm_cmd_t *fpm_interface_xin6_graceful(int gr_type, uint32_t cmd,
                                              const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_TUNNEL, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_xin6));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_TUNNEL;
	fpm_cmd->comp    = fpm_interface_xin6_comp;
	fpm_cmd->revert  = fpm_interface_xin6_revert;
	fpm_cmd->display = fpm_interface_xin6_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}
#endif

static int fpm_tunnel_shared_cmd(int gr_type, enum list_type list) {
	int if_idx;
	int ret = 0;

	/* If graceful is not needed for this type, continue */
	if (!fpm_cmd_match_gr_type(FPM_CMD_TUNNEL, gr_type))
		return 0;

	for (if_idx=0 ; if_idx<FP_MAX_IFNET ; if_idx++) {
		fp_ifnet_t *ifp;

		ifp = &fp_shared->ifnet.table[if_idx];

		/* If interface is not valid, continue */
		if (ifp->if_ifuid == 0) 
			continue;

		/* Add requests for supported interfaces types */
		if (ifp->if_type == FP_IFTYPE_XIN4) {
			struct cp_xin4 req;

			/* Clear memory */
			memset(&req, 0, sizeof(req));

			strcpy(req.cpxin4_ifname, ifp->if_name);
			req.cpxin4_ifuid = ifp->if_ifuid;
		
			ret |= fpm_cmd_create_and_enqueue(list, FPM_CMD_TUNNEL, &req);
		}

		if (ifp->if_type == FP_IFTYPE_XIN6) {
			struct cp_xin6 req;

			/* Clear memory */
			memset(&req, 0, sizeof(req));

			strcpy(req.cpxin6_ifname, ifp->if_name);
			req.cpxin6_ifuid = ifp->if_ifuid;

			ret |= fpm_cmd_create_and_enqueue(list, FPM_CMD_TUNNEL, &req);
		}
	}

	return ret;
}

static void fpm_tunnel_init(__attribute__((unused)) int graceful)
{
#ifdef CONFIG_MCORE_XIN4
	fpm_interface_register_del_event(FP_IFTYPE_XIN4, fp_delifnet_xinyinfo);
	fpm_register_msg(CMD_XIN4_CREATE, fpm_interface_xin4_add,
	    fpm_interface_xin4_graceful);
	fpm_register_msg(CMD_XIN4_DELETE, fpm_interface_xin4_del, NULL);
	fpm_register_msg(CMD_XIN4_UPDATE, fpm_interface_xin4_update, NULL);
#endif
#ifdef CONFIG_MCORE_XIN6
	fpm_interface_register_del_event(FP_IFTYPE_XIN6, fp_delifnet_xinyinfo);
	fpm_register_msg(CMD_XIN6_CREATE, fpm_interface_xin6_add,
	    fpm_interface_xin6_graceful);
	fpm_register_msg(CMD_XIN6_DELETE, fpm_interface_xin6_del, NULL);
	fpm_register_msg(CMD_XIN6_UPDATE, fpm_interface_xin6_update, NULL);
#endif
}

static struct fpm_mod fpm_tunnel_mod = {
	.name = "tunnel",
	.init = fpm_tunnel_init,
	.shared_cmd = fpm_tunnel_shared_cmd,	
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_tunnel_mod);
}
