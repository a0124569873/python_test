/*
 * Copyright 2011-2013 6WIND S.A.
 */

/*	$NetBSD: ieee8023ad_lacp_debug.c,v 1.4 2005/12/11 12:24:54 christos Exp $	*/

/*-
 * Copyright (c)2005 YAMAMOTO Takashi,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/queue.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netgraph/ng_message.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_ethgrp.h>
#include <stdio.h>
#include <event.h>

#include <syslog.h>
#include <libconsole.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <string.h>
#include <stddef.h>

#include <netgraph/ieee8023_slowprotocols.h>
#include <netgraph/ieee8023_tlv.h>
#include <netgraph/ieee8023ad_lacp.h>
#include "node.h"
#include "ieee8023ad_lacp_debug.h"

static int lacpdebug = 0;

const char *
lacp_format_mac(const uint8_t *mac, char *buf, size_t buflen)
{

	snprintf(buf, buflen, "%02X-%02X-%02X-%02X-%02X-%02X",
	    (int)mac[0],
	    (int)mac[1],
	    (int)mac[2],
	    (int)mac[3],
	    (int)mac[4],
	    (int)mac[5]);

	return buf;
}

const char *
lacp_format_systemid(const struct lacp_systemid *sysid,
    char *buf, size_t buflen)
{
	char macbuf[LACP_MACSTR_MAX+1];

	snprintf(buf, buflen, "%04X,%s",
	    be16toh(sysid->lsi_prio),
	    lacp_format_mac(sysid->lsi_mac, macbuf, sizeof(macbuf)));

	return buf;
}

const char *
lacp_format_portid(const struct lacp_portid *portid, char *buf, size_t buflen)
{

	snprintf(buf, buflen, "%04X,%04X",
	    be16toh(portid->lpi_prio),
	    be16toh(portid->lpi_portno));

	return buf;
}

const char *
lacp_format_partner(const struct lacp_peerinfo *peer, char *buf, size_t buflen)
{
	char sysid[LACP_SYSTEMIDSTR_MAX+1];
	char portid[LACP_PORTIDSTR_MAX+1];

	snprintf(buf, buflen, "(%s,%04X,%s)",
	    lacp_format_systemid(&peer->lip_systemid, sysid, sizeof(sysid)),
	    be16toh(peer->lip_key),
	    lacp_format_portid(&peer->lip_portid, portid, sizeof(portid)));

	return buf;
}

const char *
lacp_format_lagid(const struct lacp_peerinfo *a,
    const struct lacp_peerinfo *b, char *buf, size_t buflen)
{
	char astr[LACP_PARTNERSTR_MAX+1];
	char bstr[LACP_PARTNERSTR_MAX+1];

	/*
	 * there's a convention to display small numbered peer
	 * in the left.
	 */

	if (lacp_compare_peerinfo(a, b) > 0) {
		const struct lacp_peerinfo *t;

		t = a;
		a = b;
		b = t;
	}

	snprintf(buf, buflen, "[%s,%s]",
	    lacp_format_partner(a, astr, sizeof(astr)),
	    lacp_format_partner(b, bstr, sizeof(bstr)));

	return buf;
}

const char *
lacp_format_lagid_aggregator(const struct lacp_aggregator *la,
    char *buf, size_t buflen)
{

	if (la == NULL) {
		return "(none)";
	}

	return lacp_format_lagid(&la->la_actor, &la->la_partner, buf, buflen);
}

const char *
lacp_format_state(uint8_t state, char *buf, size_t buflen)
{
	static const char lacp_state_bits[] = LACP_STATE_BITS;

	bitmask_snprintf(state, lacp_state_bits, buf, buflen);

	return buf;
}

void
lacp_dump_lacpdu(const struct lacpdu *du)
{
	char buf[LACP_PARTNERSTR_MAX+1];
	char buf2[LACP_STATESTR_MAX+1];

	if (lacpdebug == 0) {
		return;
	}

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "actor=%s\n",
	    lacp_format_partner(&du->ldu_actor, buf, sizeof(buf))));
	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "actor.state=%s\n",
	    lacp_format_state(du->ldu_actor.lip_state, buf2, sizeof(buf2))));
	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "partner=%s\n",
	    lacp_format_partner(&du->ldu_partner, buf, sizeof(buf))));
	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "partner.state=%s\n",
	    lacp_format_state(du->ldu_partner.lip_state, buf2, sizeof(buf2))));

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "maxdelay=%d\n",
		be16toh(du->ldu_collector.lci_maxdelay)));
}

void
lacp_dprintf(int level, const char *fname,
		const struct chgrp_link *lp, const char *fmt, ...)
{
	va_list va;
	char buf[LACP_STATESTR_MAX+1];
	char *ptr = buf;
	int res=0;

	if (lacpdebug == 0) {
		return;
	}

	if (lp) {
		res = snprintf(buf, IFNAMSIZ, "%s: ", lp->ifname);
		if (res > 0)
			ptr += res;
	}

	va_start(va, fmt);
	vsnprintf(ptr, sizeof(buf)-res, fmt, va);
	va_end(va);
	util_dprintf(level, fname, "%s\n", buf);
}

void
lacp_set_lacpdebug(const int level)
{
	lacpdebug = level;
}

int
lacp_compare_peerinfo(const struct lacp_peerinfo *a,
    const struct lacp_peerinfo *b)
{

	return memcmp(a, b, offsetof(struct lacp_peerinfo, lip_state));
}

int
lacp_compare_systemid(const struct lacp_systemid *a,
    const struct lacp_systemid *b)
{

	return memcmp(a, b, sizeof(*a));
}

int
lacp_compare_portid(const struct lacp_portid *a,
    const struct lacp_portid *b)
{

	return memcmp(a, b, sizeof(*a));
}
