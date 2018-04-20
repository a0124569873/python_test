/*
 * Copyright(c) 2014 6WIND
 */

#ifndef __FastPath__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "fpn.h"
#include "fp.h"
#include "fpdebug.h"
#include "fpdebug-priv.h"

#include "netfpc.h"

static char *str_rate(uint64_t val, int bps)
{
	static char buf[20];
	uint64_t k_f, m_f, g_f;
	char *unit;

	unit = bps ? "bps" : "pps";
	if (bps)
		k_f = 1024;
	else
		k_f = 1000;
	m_f = k_f * k_f;
	g_f = m_f * k_f;

	if (val >= g_f && (val % g_f) == 0)
		snprintf(buf, sizeof(buf), "%"PRIu64" %s%s", (val/g_f), "G", unit);
	else if (val >= m_f && (val % m_f) == 0)
		snprintf(buf, sizeof(buf), "%"PRIu64" %s%s", (val/m_f), "M", unit);
	else if (val >= k_f && (val % k_f) == 0)
		snprintf(buf, sizeof(buf), "%"PRIu64" %s%s", (val/k_f), "K", unit);
	else
		snprintf(buf, sizeof(buf), "%"PRIu64" %s%s", val, "", unit);

	return buf;
}

static int tc_reset(char *tok)
{
	struct netfpc_tc ntc;
	ssize_t len;
	int error;

	if (gettokens(tok) != 1) {
		fpdebug_fprintf (stderr, "wrong arguments : tc-reset <tc>\n");
		return -1;
	}

	if (s_nfpc < 0) {
		fpdebug_fprintf(stderr, "Not connected to fast path\n");
		return -1;
	}

	ntc.type = htonl(NETFPC_TC_RESET_STATS);
	if (strcasecmp(chargv[0],"all") == 0)
		ntc.id = htonl(NETFPC_TC_ID_ALL);
	else
		ntc.id = htonl(atoi(chargv[0]));

	if (netfpc_send(s_nfpc, &ntc, sizeof(ntc), 0,
				NETFPC_MSGTYPE_TC) < 0) {
		fpdebug_fprintf(stderr, "Error netfpc_send\n");
		return -1;
	}

	len = netfpc_recv(s_nfpc, &ntc, sizeof(ntc), MSG_NO_TIMEOUT, NULL);
	if (len < (ssize_t)sizeof(struct netfpc_tc)) {
		fpdebug_fprintf(stderr, "Error netfpc_send\n");
		return -1;
	}

	error = ntohl(ntc.error);
	if (error) {
		fpdebug_fprintf(stderr, "dump-tc: netfpc error %d\n", error);
		return -1;
	}

	return 0;
}

static int dump_tc(char *tok)
{
	int countTokens = gettokens(tok);
	struct netfpc_tc_params *nta;
	struct netfpc_tc_stats *nts;
	struct netfpc_tc ntc, *r_ntc;
	char reply[4096];
	char *buf = reply;
	ssize_t len;
	uint32_t error;

	if (countTokens != 1) {
		fpdebug_fprintf (stderr, "wrong arguments : dump-tc <tc>|all\n");
		return -1;
	}

	if (s_nfpc < 0) {
		fpdebug_fprintf(stderr, "Not connected to fast path\n");
		return -1;
	}

	ntc.type = htonl(NETFPC_TC_GET_PARAMS);
	if (strcasecmp(chargv[0], "all") == 0)
		ntc.id = htonl(NETFPC_TC_ID_ALL);
	else
		ntc.id = htonl(atoi(chargv[0]));

	if (netfpc_send(s_nfpc, &ntc, sizeof(ntc), 0,
				NETFPC_MSGTYPE_TC) < 0) {
		fpdebug_fprintf(stderr, "Error netfpc_send\n");
		return -1;
	}

	len = netfpc_recv(s_nfpc, reply, sizeof(reply), MSG_NO_TIMEOUT, NULL);
	if (len < (ssize_t)sizeof(struct netfpc_tc)) {
		fpdebug_fprintf(stderr, "Error netfpc_send\n");
		return -1;
	}

	r_ntc = (struct netfpc_tc *)buf;
	error = ntohl(r_ntc->error);
	if (error) {
		if (error == NETFPC_TC_ERROR_TRUNCATED)
			fpdebug_fprintf(stderr, "dump-tc: truncated\n");
		else {
			fpdebug_fprintf(stderr, "dump-tc: netfpc error %d\n", error);
			return -1;
		}
	}
	buf = (char *)(r_ntc + 1);
	len -= sizeof(struct netfpc_tc);
	while (len > 0) {
		uint32_t *tc_id;
		uint32_t flags;
		int is_bps;

		tc_id = (uint32_t *)buf;
		fpdebug_printf("TC %3u\n", ntohl(*tc_id));
		nta = (struct netfpc_tc_params *)(tc_id + 1);
		flags = ntohl(nta->flags);
		is_bps = flags & NETFPC_TC_F_BYTE_POLICING;
		fpdebug_printf("   CIR = %s\n", str_rate(ntohll(nta->cir), is_bps));
		fpdebug_printf("   CBS = %u\n", ntohl(nta->cbs));
		fpdebug_printf("   EIR = %s\n", str_rate(ntohll(nta->eir), is_bps));
		fpdebug_printf("   EBS = %u\n", ntohl(nta->ebs));
		nts = (struct netfpc_tc_stats *)(nta + 1);
		fpdebug_printf("Green %" PRIu64 " packets %" PRIu64 " bytes\n",
			       (uint64_t) ntohll(nts->green_packets),
			       (uint64_t) ntohll(nts->green_bytes));
		fpdebug_printf("Yellow %" PRIu64 " packets %" PRIu64 " bytes\n",
			       (uint64_t) ntohll(nts->yellow_packets),
			       (uint64_t) ntohll(nts->yellow_bytes));
		fpdebug_printf("Red %" PRId64 " packets %" PRId64 " bytes\n",
			       (uint64_t) ntohll(nts->red_packets),
			       (uint64_t) ntohll(nts->red_bytes));
		buf += (sizeof(uint32_t) + sizeof(*nta) + sizeof(*nts));
		len -= (sizeof(uint32_t) + sizeof(*nta) + sizeof(*nts));
	}

	return 0;
}

static int tc_set(char *tok)
{
	char *p;
	struct netfpc_tc_params *nta;
	struct netfpc_tc *ntc;
	uint64_t c_rate, c_depth, e_rate, e_depth;
	uint32_t id;
	uint64_t factor;
	int flags;
	char req[4096];
	int len;
	int k_f;
	int error;

	if (gettokens(tok) < 6)
		goto usage;

	if (s_nfpc < 0) {
		fpdebug_fprintf(stderr, "Not connected to fast path\n");
		return -1;
	}

	id = atoi(chargv[0]);
	ntc = (struct netfpc_tc *)req;
	ntc->type = htonl(NETFPC_TC_SET_PARAMS);
	ntc->id = htonl(id);
	nta = (struct netfpc_tc_params *)(ntc + 1);

	c_rate = atoi(chargv[1]);
	c_depth = atoi(chargv[2]);
	e_rate = atoi(chargv[3]);
	e_depth = atoi(chargv[4]);

	p = chargv[5];
	if (strcasecmp(p, "gbps") == 0 ||
	    strcasecmp(p, "mbps") == 0 ||
	    strcasecmp(p, "kbps") == 0 ||
	    strcasecmp(p, "bps") == 0) {
		flags = NETFPC_TC_F_BYTE_POLICING;
		k_f = 1024;
	} else if (strcasecmp(p, "gpps") == 0 ||
	    strcasecmp(p, "mpps") == 0 ||
	    strcasecmp(p, "kpps") == 0 ||
	    strcasecmp(p, "pps") == 0) {
		flags = 0;
		k_f = 1000;
	} else
		goto usage;

	if (p[0] == 'g' || p[0] == 'G')
		factor = k_f * k_f * k_f;
	else if (p[0] == 'm' || p[0] == 'M')
		factor = k_f * k_f;
	else if (p[0] == 'k' || p[0] == 'K')
		factor = k_f;
	else
		factor = 1;
	nta->cir = htonll(c_rate * factor);
	nta->cbs = htonl(c_depth);
	nta->eir = htonll(e_rate * factor);
	nta->ebs = htonl(e_depth);
	nta->flags = htonl(flags);

	if (netfpc_send(s_nfpc, req, sizeof(*ntc) + sizeof(*nta) , 0,
				NETFPC_MSGTYPE_TC) < 0) {
		fpdebug_fprintf(stderr, "Error netfpc_send\n");
		return -1;
	}

	len = netfpc_recv(s_nfpc, ntc, sizeof(*ntc), MSG_NO_TIMEOUT, NULL);
	if (len < (ssize_t)sizeof(struct netfpc_tc)) {
		fpdebug_fprintf(stderr, "Error netfpc_send\n");
		return -1;
	}

	error = ntohl(ntc->error);
	if (error) {
		fpdebug_fprintf(stderr, "dump-tc: netfpc error %d\n", error);
		return -1;
	}
	if (c_depth == 0)
		fp_shared->tc_bitmask &= ~(1<<id);
	else
		fp_shared->tc_bitmask |= (1<<id);

	return 0;
usage:
	fpdebug_fprintf(stderr, "set tc parameters: tc-set <id> <committed rate>  <committed depth> <excess rate> <excess depth> [GMK][pps|bps]\n");
	return -1;
}

static CLI_COMMAND tc_cmds[] = {
	{"tc-set", tc_set, "set tc parameters: tc-set <id> <committed rate> <committed depth> <excess rate> <excess depth> [GMK][pps|bps]"},
	{"dump-tc", dump_tc, "Dump the information of specified interface : dump-tc <tc>"},
	{"tc-reset", tc_reset, "reset tc statistics : tc-reset <tc>"},
	{ NULL, NULL, NULL },
};
static cli_cmds_t tc_cli = {
	.module = "tc",
	.c = tc_cmds,
};

static void fpdebug_tc_init(void) __attribute__ ((constructor));
void fpdebug_tc_init(void)
{
	fpdebug_add_commands(&tc_cli);
}
#endif /* !__FastPath__ */
