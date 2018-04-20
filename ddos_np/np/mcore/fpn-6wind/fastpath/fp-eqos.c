/*
 * Copyright (c) 2010 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-netfpc.h"

#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)

static int fp_eqos_append_stats(struct mbuf *m, uint16_t q_id)
{
	struct netfpc_eqos_stats es;
	struct fpn_queue_stats stats;
	fpn_queue_state_t qstate = fpn_get_queue_state(q_id);

	/* Skip unconfigured queue. */
	if (qstate.s.enable == 0)
		return 0;

	if (fpn_read_queue_stats(q_id, &stats) < 0)
		return NETFPC_EQOS_ERROR_INVALID_PARAM;

	es.queue_id = htons(q_id);
	es.port_id = qstate.s.port;
	es.queue_idx = qstate.s.idx;
	es.discardBytesG = htonll(stats.discardBytesG);
	es.discardBytesY = htonll(stats.discardBytesY);
	es.discardBytesR = htonll(stats.discardBytesR);
	es.discardPacketsG = htonl(stats.discardPacketsG);
	es.discardPacketsY = htonl(stats.discardPacketsY);
	es.discardPacketsR = htonl(stats.discardPacketsR);
	es.highestQueueLength = htonl(stats.hiWaterMark);
	es.currentQueueLength = htonl(fpn_read_queue_length(q_id));

	if (m_copyfrombuf(m, m_len(m), &es, sizeof(es)) != sizeof(es))
		return NETFPC_EQOS_ERROR_TRUNCATED;

	return 0;
}

static int fp_eqos_append_params(struct mbuf *m, uint16_t q_id)
{
	struct netfpc_eqos_params nes;
	struct fpn_queue_params params;
	fpn_queue_state_t qstate = fpn_get_queue_state(q_id);

	/* Skip unconfigured queue. */
	if (qstate.s.enable == 0)
		return 0;

	if (fpn_read_queue_params(q_id, &params) < 0)
		return NETFPC_EQOS_ERROR_INVALID_PARAM;

	nes.queue_id = htons(q_id);
	nes.port_id = qstate.s.port;
	nes.queue_idx = qstate.s.idx;
#define EQOS_SET_BE32(c,x) \
	nes.ud.c.x = htonl(params.ud.c.x)

	if (params.discardAlgorithm == FPN_QOS_DISC_TAILDROP) {
		nes.discardAlgorithm = NETFPC_EQOS_DISC_TAILDROP;
		EQOS_SET_BE32(taildrop, dpGmax);
		EQOS_SET_BE32(taildrop, dpYmax);
		EQOS_SET_BE32(taildrop, dpRmax);
	} else if (params.discardAlgorithm == FPN_QOS_DISC_WRED) {
		nes.discardAlgorithm = NETFPC_EQOS_DISC_WRED;
		EQOS_SET_BE32(red, dpGmin);
		EQOS_SET_BE32(red, dpGmax);
		EQOS_SET_BE32(red, dpGprob);
		EQOS_SET_BE32(red, dpYmin);
		EQOS_SET_BE32(red, dpYmax);
		EQOS_SET_BE32(red, dpYprob);
		EQOS_SET_BE32(red, dpRmin);
		EQOS_SET_BE32(red, dpRmax);
		EQOS_SET_BE32(red, dpRprob);
		EQOS_SET_BE32(red, movingAverage);
	} else
		nes.discardAlgorithm = NETFPC_EQOS_DISC_NONE;
#undef EQOS_SET_BE32

	if (m_copyfrombuf(m, m_len(m), &nes, sizeof(nes)) != sizeof(nes))
		return NETFPC_EQOS_ERROR_TRUNCATED;

	return 0;
}

void fp_eqos_config(struct mbuf *m, struct fp_netfpc_ctx *ctx)
{
	struct netfpc_eqos *neq = mtod(m, struct netfpc_eqos *);
	uint32_t type;
	uint16_t q_id;
	uint8_t p_id;
	int error = 0;
	int base, n;

	type = neq->type;
	p_id = neq->port_id;
	q_id = neq->queue_id;

	m_freem(m);
	m = m_alloc();
	if (m == NULL)
		return;
	neq = (struct netfpc_eqos *) m_append(m, sizeof(*neq));
	if (!neq) {
		m_freem(m);
		return;
	}
	neq->type = type;
	neq->port_id = p_id;
	neq->queue_id = q_id;

	type = ntohl(type);
	q_id = ntohs(q_id);

	switch (type) {
	case NETFPC_EQOS_GET_STATS:
	case NETFPC_EQOS_GET_PARAMS:
	case NETFPC_EQOS_RESET_STATS:
			break;
	default:
		error = NETFPC_EQOS_ERROR_INVALID_CMD;
		goto out;
	}

	if (q_id != NETFPC_EQOS_QUEUEID_ALL) {
		/* One queue */
		base = q_id;
		n = 1;
	} else if (p_id != NETFPC_EQOS_PORTID_ALL) {
		/* All queues of one port */
		base = cvmx_pko_get_base_queue(p_id);
		n = cvmx_pko_get_num_queues(p_id);
	} else {
		/* All queues of all ports */
		base = 0;
		n = FPN_MAX_OUTPUT_QUEUES;
	}

	/* cvmx_pko_get_base_queue() returns error starting from SDK-1.6 */
	if (base == CVMX_PKO_ILLEGAL_QUEUE) {
		error = NETFPC_EQOS_ERROR_INVALID_PARAM;
		goto out;
	}

	if ((uint16_t)(base + n) > FPN_MAX_OUTPUT_QUEUES) {
		error = NETFPC_EQOS_ERROR_INVALID_PARAM;
		goto out;
	}

	for (q_id = base; q_id < (uint16_t)(base + n); q_id++) {
		switch (type) {
		case NETFPC_EQOS_GET_PARAMS:
			error = fp_eqos_append_params(m, q_id);
			break;
		case NETFPC_EQOS_GET_STATS:
			error = fp_eqos_append_stats(m, q_id);
			break;
		case NETFPC_EQOS_RESET_STATS:
			fpn_reset_queue_stats(q_id);
			break;
		}
		if (error)
			break;
	}

out:
	neq->error = htonl(error);

	fp_netfpc_output(m, ctx);
}

#endif
