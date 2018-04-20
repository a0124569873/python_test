/**
 * fp-vswitch interface
 *
 */

/*-
   * Copyright (c) <2013>, 6WIND
   * All rights reserved.
   */
#include <sys/types.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "fpn.h"
#include "fpn-shmem.h"

#include <linux/openvswitch.h>
#include "fpvs-cp.h"
#include <fp-vswitch.h>
#include <fpvs-common.h>

#include "fp.h"
#include "fpm_plugin.h"

#include "fpm_common.h"

static int
fpm_fpvs_set_port(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_fpvs_port *port = (struct cp_fpvs_port *)request;

	fpvs_set_ovsport(port->ifname, htonl(port->port_id),
			 htonl(port->type), htons(port->tun_dstport),
			 fpm_graceful_restart_in_progress);

	return 0;
}

static int
fpm_fpvs_set_flow(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_fpvs_flow *req = (struct cp_fpvs_flow *)request;
	int mask_offset = htons(req->flow_len);
	int actions_offset = mask_offset + htons(req->flow_len);
	int actions_len = htons(req->action_len);
	int delete = req->flags & htonl(CM_FPVS_FLOW_DEL);
	uint8_t *ptr = (uint8_t *)&req->data;

	struct fp_flow_key key __attribute__((aligned(FPVS_FLOW_ALIGNMENT)));
	struct fp_flow_key mask __attribute__((aligned(FPVS_FLOW_ALIGNMENT)));
	struct fp_flow_key dst __attribute__((aligned(FPVS_FLOW_ALIGNMENT)));
	struct fp_key_range range;
	struct fpvs_flow *flow;
	struct nlattr *actions;

	actions = (struct nlattr *)(ptr + actions_offset);

	cp_to_fp_flow_key((struct cp_flow_key *)(ptr), &key);
	cp_to_fp_flow_key((struct cp_flow_key *)(ptr + mask_offset), &mask);

	fpvs_mask_to_range(&mask, &range);
	memset(&dst, 0, sizeof(struct fp_flow_key));
	fpvs_flow_mask(&dst, &key, &mask, range.start, range.end);
	flow = fpvs_lookup_flow(shared_table, &dst);

	if (flow) {
		/*
		 * Handle deletion if flow exists.
		 * Ignore the message if we have no dpif, we use only
		 * the prune flow message in that case.
		 */
		if (delete) {
			if (shared_table->dpif_magic != FP_DPIF_MAGIC32)
				return 0;

			flow->age = 0;
			flow->hit = 0;
			flow->used = 0;
			fpvs_remove_flow(shared_table, flow);
			return 0;
		}

		/* Flow exists, update it. */
		if (actions_len > FPVS_MAX_ACTION_SIZE) {
			/* FIXME: This should never happen. */
			fpvs_remove_flow(shared_table, flow);
		} else {
			flow->age = 0;
			flow->hit = 1;
			flow->used = 0;
			memcpy(flow->actions, actions, actions_len);
			flow->actions_len = actions_len;
		}

	} else if (!delete) {
		/* This is a brand new flow. */
		fpvs_insert_flow(shared_table, &dst, &mask, actions,
				 actions_len, &range);
	}

	return 0;
}

/* Walk the list of flows and remove those dying of old age. */
static void
prune_old_flows(fpvs_flow_list_t* shared_table)
{
	int i;

	for (i = 1; i < MAX_FLOWS; i++) {
		struct fpvs_flow* flow = &shared_table->flow_table[i].flow;

		if (flow->state == FPVS_FLOW_ACTIVE) {
			if (++flow->age >= shared_table->flow_max_age) {
				fpvs_remove_flow(shared_table, flow);
			}
		}
	}
}

static int
fpm_fpvs_prune_flows(const uint8_t *request, const struct cp_hdr *hdr)
{
	if (shared_table->dpif_magic == FP_DPIF_MAGIC32)
		return 0;

	prune_old_flows(shared_table);
	return 0;
}

static int fpm_fpvs_port_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_fpvs_port *if1 = cmd1->data;
	struct cp_fpvs_port *if2 = cmd2->data;

	if (if1->port_id == if2->port_id)
		return 0;
	return 1;
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_fpvs_port_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;
	struct cp_fpvs_port *req = fpm_cmd->data;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	req->port_id = htonl(FPVS_INVALID_PORT);
	hdr->cphdr_type = htonl(CMD_FPVS_SET);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}

static void fpm_fpvs_port_display(const fpm_cmd_t *fpm_cmd,
                                  char *buffer, int len)
{
	struct cp_fpvs_port *data = fpm_cmd->data;

	snprintf(buffer, len, "CMD_OVS_PORT_ADD - %s, ovs id %d, type %u\n",
	         data->ifname, htonl(data->port_id), htonl(data->type));
}

static fpm_cmd_t *fpm_fpvs_port_graceful(int gr_type, uint32_t cmd,
                                         const void *data)
{
	fpm_cmd_t *fpm_cmd;
	const struct cp_fpvs_port *port = data;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_TUNNEL, gr_type))
		return NULL;

	/* Just consider vport creation, drop deletion one */
	if (port->port_id == htonl(FPVS_INVALID_PORT))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_fpvs_port));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_TUNNEL;
	fpm_cmd->comp    = fpm_fpvs_port_comp;
	fpm_cmd->revert  = fpm_fpvs_port_revert;
	fpm_cmd->display = fpm_fpvs_port_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}

static int fpm_fpvs_shared_cmd(int gr_type, enum list_type list)
{
	int port_idx;
	int ret = 0;

	/* Dump interfaces if needed */
	if (!fpm_cmd_match_gr_type(FPM_CMD_TUNNEL, gr_type))
		return 0;

	for (port_idx=0 ; port_idx<FPVS_MAX_OVS_PORTS ; port_idx++) {
		fp_vswitch_port_t *port;
		struct cp_fpvs_port	cpvs;

		port = fpvs_get_port(port_idx);

		/* If port is not valid, continue */
		if (port->type == OVS_VPORT_TYPE_UNSPEC)
			continue;

		/* Add requests for created OVS port */
		/* Clear memory */
		memset(&cpvs, 0, sizeof(cpvs));

		cpvs.port_id = htonl(port_idx);
		cpvs.type = htonl(port->type);
		if (port->type == OVS_VPORT_TYPE_VXLAN)
			cpvs.tun_dstport = htons((uint16_t)(uintptr_t)port->priv);
		else
			cpvs.tun_dstport = 0;
		memcpy(&(cpvs.ifname), &(port->ifp_name), FP_IFNAMSIZ);

		ret |= fpm_cmd_create_and_enqueue(list, CMD_FPVS_SET, &cpvs);
	}

	return ret;
}

static void fpm_fpvs_init(int graceful)
{
	if (fpvs_map_shm() < 0) {
		syslog(LOG_ERR, "Could not get fpvs shared memories.\n");
		return;
	}

	fpvs_init_shmem(graceful);

	fpm_register_msg(CMD_FPVS_FLOW, fpm_fpvs_set_flow, NULL);
	fpm_register_msg(CMD_FPVS_SET, fpm_fpvs_set_port, fpm_fpvs_port_graceful);
	fpm_register_msg(CMD_FPVS_PRUNE, fpm_fpvs_prune_flows, NULL);
}

static struct fpm_mod fpm_fpvs_mod = {
	.name = "fp-vswitch",
	.init = fpm_fpvs_init,
	.shared_cmd = fpm_fpvs_shared_cmd,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_fpvs_mod);
}
