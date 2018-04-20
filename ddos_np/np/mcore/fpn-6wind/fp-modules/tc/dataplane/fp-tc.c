/*
 * Copyright(c) 2007 6WIND
 */

#include "fpn.h"
#include "fp-includes.h"
#include "fp-module.h"
#include "fp-tc.h"
#include "fp-netfpc.h"

static int fp_tc_config(struct mbuf *m, struct fp_netfpc_ctx *ctx)
{
	struct netfpc_tc *ntc = mtod(m, struct netfpc_tc *);
	struct netfpc_tc_stats *nts;
	uint32_t type, id;
	int error = 0;
	fpn_tc_bucket_stats_t stats;

	type = ntohl(ntc->type);
	id = ntohl(ntc->id);

	if (type == NETFPC_TC_RESET_STATS) {
		uint32_t from, to, i;

		if (id == NETFPC_TC_ID_ALL) {
			from = 0;
			to = FPN_TC_MAX;
		} else {
			from = id;
			to = id + 1;
		}
		for (i = from; i < to; i++)
			fpn_tc_clear_stats(i);
		goto ack;
	}

	if (type == NETFPC_TC_GET_STATS) {
		if (fpn_tc_get_stats(id, &stats) < 0)
			error = NETFPC_TC_ERROR_INVALID_PARAM;
		goto ack;
	}

	if (type == NETFPC_TC_GET_PARAMS)
		goto ack;

	if (type == NETFPC_TC_SET_PARAMS) {
		struct netfpc_tc_params *nta;
		fpn_tc_params_t params;
		uint32_t flags;

		nta = (struct netfpc_tc_params *)m_adj(m, sizeof(*ntc));
		if (nta == NULL) {
			error = NETFPC_TC_ERROR_INVALID_CMD;
			goto ack;
		}

		params.cir = ntohll(nta->cir);
		params.eir = ntohll(nta->eir);
		params.cbs = ntohl(nta->cbs);
		params.ebs = ntohl(nta->ebs);

		params.flags = 0;
		flags = ntohl(nta->flags);
		if (flags & NETFPC_TC_F_BYTE_POLICING)
			params.flags |= FPN_TC_F_BYTE_POLICING;
		if (flags & NETFPC_TC_F_COLOR_AWARE)
			params.flags |= FPN_TC_F_COLOR_AWARE;

		if (fpn_tc_set_params(id, &params) < 0)
			error = NETFPC_TC_ERROR_INVALID_PARAM;
		goto ack;
	}

	/* Unknown command */
	error = NETFPC_TC_ERROR_INVALID_CMD;

ack:
	m_freem(m);

	m = m_alloc();
	if (m == NULL)
		return -1;
	ntc = (struct netfpc_tc *) m_append(m, sizeof(*ntc));
	if (!ntc) {
		m_freem(m);
		return -1;
	}
	ntc->type = htonl(type);
	ntc->error = htonl(error);
	ntc->id = htonl(id);

	if (type == NETFPC_TC_GET_STATS) {
		nts = (struct netfpc_tc_stats *)m_append(m, sizeof(*nts));

		if (!nts) {
			m_freem(m);
			return -1;
		}
		nts->green_packets = htonll(stats.green_packets);
		nts->green_bytes = htonll(stats.green_bytes);
		nts->yellow_packets = htonll(stats.yellow_packets);
		nts->yellow_bytes = htonll(stats.yellow_bytes);
		nts->red_packets = htonll(stats.red_packets);
		nts->red_bytes = htonll(stats.red_bytes);
	}
	if (type == NETFPC_TC_GET_PARAMS) {
		struct netfpc_tc_params *nta;
		uint32_t *tc_id;
		fpn_tc_params_t params;
		uint32_t i;
		uint32_t from, to;

		if (id == NETFPC_TC_ID_ALL) {
			from = 0;
			to = FPN_TC_MAX;
		} else {
			from = id;
			to = id + 1;
		}

		for (i = from; i < to; i++) {
			if (fpn_tc_get_params(i, &params) == 0 &&
					params.cbs != 0) {
				tc_id = (uint32_t *)m_append(m, sizeof(*nta) + 
						                sizeof(*nts) +
								sizeof(uint32_t));
				if (tc_id == NULL) {
					m_freem(m);
					return -1;
				}
				*tc_id = htonl(i);
				nta = (struct netfpc_tc_params *)(tc_id + 1);
				nta->cir = htonll(params.cir);
				nta->eir = htonll(params.eir);
				nta->cbs = htonl(params.cbs);
				nta->ebs = htonl(params.ebs);
				if (params.flags & FPN_TC_F_BYTE_POLICING)
					nta->flags |= NETFPC_TC_F_BYTE_POLICING;
				if (params.flags & FPN_TC_F_COLOR_AWARE)
					nta->flags |= NETFPC_TC_F_COLOR_AWARE;
				nta->flags = htonl(nta->flags);

				fpn_tc_get_stats(i, &stats);
				nts = (struct netfpc_tc_stats*)(nta + 1);
				nts->green_packets = htonll(stats.green_packets);
				nts->green_bytes = htonll(stats.green_bytes);
				nts->yellow_packets = htonll(stats.yellow_packets);
				nts->yellow_bytes = htonll(stats.yellow_bytes);
				nts->red_packets = htonll(stats.red_packets);
				nts->red_bytes = htonll(stats.red_bytes);
			}
		}
	}

	fp_netfpc_output(m, ctx);
	return 0;
}

static void fp_tc_init(void)
{
	fp_netfpc_register(NETFPC_MSGTYPE_TC, fp_tc_config);
	fpn_tc_init();
	fp_shared->tc_bitmask = 0;
}

static struct fp_mod tc_mod = {
	.name = "tc",
	.init = fp_tc_init,
};

FP_MOD_REGISTER(tc_mod)
