/*
 * Copyright 2011-2013 6WIND S.A.
 */

/*	$NetBSD: ieee8023ad_lacp_select.c,v 1.5 2007/02/22 06:20:16 thorpej Exp $	*/

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
#include <event.h>

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <libconsole.h>
#include <assert.h>
#include <sys/time.h>

#include <netgraph/ieee8023_slowprotocols.h>
#include <netgraph/ieee8023_tlv.h>
#include <netgraph/ieee8023ad_lacp.h>
#include "node.h"
#include "ieee8023ad_lacp_sm.h"
#include "ieee8023ad_lacp_debug.h"

/* selection logic */

static void lacp_fill_aggregator_id(struct lacp_aggregator *,
    const struct chgrp_link *);
static void lacp_fill_aggregator_id_peer(struct lacp_peerinfo *,
    const struct lacp_peerinfo *);
static int lacp_aggregator_is_compatible(const struct lacp_aggregator *,
    const struct chgrp_link *);
static int lacp_peerinfo_is_compatible(const struct lacp_peerinfo *,
    const struct lacp_peerinfo *);

static struct lacp_aggregator *lacp_aggregator_get(struct chgrp_node *,
    struct chgrp_link *);
static void lacp_aggregator_addref(struct chgrp_node *,
    struct lacp_aggregator *);
static void lacp_aggregator_delref(struct chgrp_node *,
    struct lacp_aggregator *);

static void
lacp_aggregator_addref(struct chgrp_node *lsc, struct lacp_aggregator *la)
{
	char buf[LACP_LAGIDSTR_MAX+1];

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "lagid=%s, refcnt %d -> %d\n",
	    lacp_format_lagid(&la->la_actor, &la->la_partner,
	    buf, sizeof(buf)),
	    la->la_refcnt, la->la_refcnt + 1));

	assert(la->la_refcnt > 0);
	la->la_refcnt++;
	assert(la->la_refcnt > la->la_nports);
}

static void
lacp_aggregator_delref(struct chgrp_node *lsc, struct lacp_aggregator *la)
{
	char buf[LACP_LAGIDSTR_MAX+1];

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "lagid=%s, refcnt %d -> %d\n",
	    lacp_format_lagid(&la->la_actor, &la->la_partner,
	    buf, sizeof(buf)),
	    la->la_refcnt, la->la_refcnt - 1));

	assert(la != NULL);
	assert(la->la_refcnt > la->la_nports);
	la->la_refcnt--;
	if (la->la_refcnt > 0) {
		return;
	}

	assert(la->la_refcnt == 0);
	assert(lsc->lsc_active_aggregator != la);

	TAILQ_REMOVE(&lsc->lsc_aggregators, la, la_q);

	free(la);
}

/*
 * lacp_aggregator_get: allocate an aggregator.
 */

static struct lacp_aggregator *
lacp_aggregator_get(struct chgrp_node *lsc, struct chgrp_link *lp)
{
	struct lacp_aggregator *la;

	la = malloc(sizeof(*la));
	if (la) {
		la->la_refcnt = 1;
		la->la_nports = 0;
		TAILQ_INIT(&la->la_ports);
		la->la_pending = 0;
		TAILQ_INSERT_TAIL(&lsc->lsc_aggregators, la, la_q);
	}

	return la;
}

/*
 * lacp_fill_aggregator_id: setup a newly allocated aggregator from a port.
 */

static void
lacp_fill_aggregator_id(struct lacp_aggregator *la, const struct chgrp_link *lp)
{

	lacp_fill_aggregator_id_peer(&la->la_partner, &lp->lp_partner);
	lacp_fill_aggregator_id_peer(&la->la_actor, &lp->lp_actor);

	la->la_actor.lip_state = lp->lp_state & LACP_STATE_AGGREGATION;
}

static void
lacp_fill_aggregator_id_peer(struct lacp_peerinfo *lpi_aggr,
    const struct lacp_peerinfo *lpi_port)
{

	memset(lpi_aggr, 0, sizeof(*lpi_aggr));
	lpi_aggr->lip_systemid = lpi_port->lip_systemid;
	lpi_aggr->lip_key = lpi_port->lip_key;
}

/*
 * lacp_aggregator_is_compatible: check if a port can join to an aggregator.
 */

static int
lacp_aggregator_is_compatible(const struct lacp_aggregator *la,
    const struct chgrp_link *lp)
{

	if (!(lp->lp_state & LACP_STATE_AGGREGATION) ||
	    !(lp->lp_partner.lip_state & LACP_STATE_AGGREGATION)) {
		return 0;
	}

	if (!(la->la_actor.lip_state & LACP_STATE_AGGREGATION)) {
		return 0;
	}

	if (!lacp_peerinfo_is_compatible(&la->la_partner, &lp->lp_partner)) {
		return 0;
	}

	if (!lacp_peerinfo_is_compatible(&la->la_actor, &lp->lp_actor)) {
		return 0;
	}

	return 1;
}

static int
lacp_peerinfo_is_compatible(const struct lacp_peerinfo *a,
    const struct lacp_peerinfo *b)
{

	if (memcmp(&a->lip_systemid, &b->lip_systemid,
	    sizeof(a->lip_systemid))) {
		return 0;
	}

	if (memcmp(&a->lip_key, &b->lip_key, sizeof(a->lip_key))) {
		return 0;
	}

	return 1;
}

/*
 * lacp_select: select an aggregator.  create one if necessary.
 */

void
lacp_select(struct chgrp_link *lp)
{
	struct chgrp_node *lsc = chgrp_node_lookup_by_link_ifname(lp->ifname);
	struct lacp_aggregator *la;
	char buf[LACP_LAGIDSTR_MAX+1];

#if defined(LACP_DEBUG_1)
	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));
#endif
	if (lp->lp_aggregator) {
		return;
	}

	assert(lsc != NULL);
	assert(!LACP_TIMER_ISARMED(lp, LACP_TIMER_WAIT_WHILE));

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "port lagid=%s\n",
	    lacp_format_lagid(&lp->lp_actor, &lp->lp_partner,
	    buf, sizeof(buf))));

	TAILQ_FOREACH(la, &lsc->lsc_aggregators, la_q) {
		if (lacp_aggregator_is_compatible(la, lp)) {
			break;
		}
	}

	if (la == NULL) {
		la = lacp_aggregator_get(lsc, lp);
		if (la == NULL) {
			LACP_DPRINTF((LOG_DEBUG, __func__, lp, "aggregator creation failed\n"));

			/*
			 * will retry on the next tick.
			 */

			return;
		}
		lacp_fill_aggregator_id(la, lp);
		LACP_DPRINTF((LOG_DEBUG, __func__, lp, "aggregator created\n"));
	} else {
		LACP_DPRINTF((LOG_DEBUG, __func__, lp, "compatible aggregator found\n"));
		lacp_aggregator_addref(lsc, la);
	}

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "aggregator lagid=%s\n",
	    lacp_format_lagid(&la->la_actor, &la->la_partner,
	    buf, sizeof(buf))));

	lp->lp_aggregator = la;
	lp->lp_selected = LACP_SELECTED;
}

/*
 * lacp_unselect: finish unselect/detach process.
 */

void
lacp_unselect(struct chgrp_link *lp)
{
	struct chgrp_node *lsc = chgrp_node_lookup_by_link_ifname(lp->ifname);
	struct lacp_aggregator *la = lp->lp_aggregator;

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));
	assert(!LACP_TIMER_ISARMED(lp, LACP_TIMER_WAIT_WHILE));

	if (la == NULL) {
		return;
	}

	lp->lp_aggregator = NULL;
	lacp_aggregator_delref(lsc, la);
}
