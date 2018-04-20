
/*
 * Copyright (c) 2007 6WIND, All rights reserved.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <net/if.h>

#include <net/ethernet.h>

#include <ctype.h>
#include <sys/queue.h>

#include "fpm_common.h"
#include "fpm_plugin.h"
#include "fp.h"
#include "fp-blade.h"

/*
 * add or delete a blade entry
 *  parameters are : blade ID, MAC address and flags
 */
static int
fpm_blade_create(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_blade_create *req =
		(const struct cp_blade_create *)request;

	if (f_verbose)
		syslog(LOG_DEBUG, "%s: id=%d MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
		       __FUNCTION__, req->cpblade_id,
		       req->cpblade_mac[0], req->cpblade_mac[1], req->cpblade_mac[2],
		       req->cpblade_mac[3], req->cpblade_mac[4], req->cpblade_mac[5]);

	fp_add_blade(req->cpblade_id, req->cpblade_flags, req->cpblade_mac);
	return EXIT_SUCCESS;
}

static int
fpm_blade_delete(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_blade_create *req =
		(const struct cp_blade_create *)request;

	if (f_verbose)
		syslog(LOG_DEBUG, "%s: id=%d\n", __FUNCTION__, req->cpblade_id);

	fp_delete_blade(req->cpblade_id, req->cpblade_flags);
	return EXIT_SUCCESS;
}

static int
fpm_fpib_if_set(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_blade_fpib *req = (const struct cp_blade_fpib *)request;

	if (f_verbose)
		syslog(LOG_DEBUG, "%s: ifuid=0x%08x\n", __FUNCTION__, ntohl(req->fpib_ifuid));

	fpm_fpib_ifuid = req->fpib_ifuid;
	fp_set_fpib_ifuid(fpm_fpib_ifuid, fpm_auto_threshold);

	return 0;
}

static int
fpm_fpib_if_unset(const uint8_t *request, const struct cp_hdr *hdr)
{
	if (f_verbose)
		syslog(LOG_DEBUG, "%s\n", __FUNCTION__);

	fpm_fpib_ifuid = 0;
	fp_set_fpib_ifuid(0, fpm_auto_threshold);

	return 0;
}

static int fpm_blade_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_blade_create *bl1 = cmd1->data;
	struct cp_blade_create *bl2 = cmd2->data;

	return (bl1->cpblade_id != bl2->cpblade_id);
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_blade_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_BLADE_DELETE);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}

static void fpm_blade_display(const fpm_cmd_t *fpm_cmd,
                              char *buffer, int len)
{
	struct cp_blade_create *data = fpm_cmd->data;

	snprintf(buffer, len, "CMD_BLADE_CREATE - #%d reachable via %02x:%02x:%02x:%02x:%02x:%02x\n",
	         data->cpblade_id, 
	         data->cpblade_mac[0], data->cpblade_mac[1], data->cpblade_mac[2],
	         data->cpblade_mac[3], data->cpblade_mac[4], data->cpblade_mac[5]);
}

static fpm_cmd_t *fpm_blade_graceful(int gr_type, uint32_t cmd,
                                     const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_BLADE, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_blade_create));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_BLADE;
	fpm_cmd->comp    = fpm_blade_comp;
	fpm_cmd->revert  = fpm_blade_revert;
	fpm_cmd->display = fpm_blade_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}

static int fpm_blade_shared_cmd(int gr_type, enum list_type list) {
	fp_blade_t* blade = fp_shared->fp_blades;
	int blade_idx;
	int ret = 0;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_BLADE, gr_type))
		return 0;

	for (blade_idx=0 ; blade_idx<=FP_BLADEID_MAX ; blade_idx++) {
		struct cp_blade_create req;

		/* Clear memory */
		memset(&req, 0, sizeof(req));

		if (blade[blade_idx].blade_active) {
			req.cpblade_id = blade_idx;
			memcpy(req.cpblade_mac, blade[blade_idx].blade_mac,
			       sizeof(req.cpblade_mac));

			ret |= fpm_cmd_create_and_enqueue(list, CMD_BLADE_CREATE, &req);
		}
	}

	return ret;
}

static void fpm_blade_init(__attribute__((unused)) int graceful)
{
	fpm_register_msg(CMD_BLADE_CREATE, fpm_blade_create, fpm_blade_graceful);
	fpm_register_msg(CMD_BLADE_DELETE, fpm_blade_delete, NULL);
	fpm_register_msg(CMD_BLADE_FPIB_IF_SET, fpm_fpib_if_set, NULL);
	fpm_register_msg(CMD_BLADE_FPIB_IF_UNSET, fpm_fpib_if_unset, NULL);
}

static struct fpm_mod fpm_blade_mod = {
	.name = "blade",
	.init = fpm_blade_init,
	.shared_cmd = fpm_blade_shared_cmd,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_blade_mod);
}
