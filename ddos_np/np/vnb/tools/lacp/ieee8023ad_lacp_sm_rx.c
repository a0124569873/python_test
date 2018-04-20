/*
 * Copyright 2011-2013 6WIND S.A.
 */

/*	$NetBSD: ieee8023ad_lacp_sm_rx.c,v 1.4 2007/02/21 23:00:07 thorpej Exp $	*/

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
#include <string.h>
#include <stddef.h>

#include <syslog.h>
#include <libconsole.h>
#include <sys/time.h>

#include "lacp.h"
#include <netgraph/ieee8023_slowprotocols.h>
#include <netgraph/ieee8023_tlv.h>
#include <netgraph/ieee8023ad_lacp.h>
#include "node.h"
#include "ieee8023ad_lacp_sm.h"
#include "ieee8023ad_lacp_debug.h"

#include <assert.h>

/* receive machine */

static void lacp_sm_rx_update_ntt(struct chgrp_link *, const struct lacpdu *);
static void lacp_sm_rx_record_pdu(struct chgrp_link *, const struct lacpdu *);
static void lacp_sm_rx_update_selected(struct chgrp_link *, const struct lacpdu *);

static void lacp_sm_rx_record_default(struct chgrp_link *, int);
static void lacp_sm_rx_update_default_selected(struct chgrp_link *);

static void lacp_sm_rx_update_selected_from_peerinfo(struct chgrp_link *,
    const struct lacp_peerinfo *);

enum lacp_sm_rx_force {
	LACP_SM_RX_FORCE,
	LACP_SM_RX_SOFT,
};

/*
 * partner administration variables.
 * XXX should be configurable.
 */

/* optimistic */
static const struct lacp_peerinfo lacp_partner_admin_optimistic = {
	.lip_systemid = { .lsi_prio = 0xffff },
	.lip_portid = { .lpi_prio = 0xffff },
	.lip_state = LACP_STATE_SYNC | LACP_STATE_AGGREGATION |
	    LACP_STATE_COLLECTING | LACP_STATE_DISTRIBUTING,
};

/* pessimistic */
static const struct lacp_peerinfo lacp_partner_admin_pessimistic = {
	.lip_systemid = { .lsi_prio = 0xffff },
	.lip_portid = { .lpi_prio = 0xffff },
	.lip_state = 0,
};

void
lacp_sm_rx(struct chgrp_link *lp, const struct lacpdu *du)
{
	int timeout;

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));
	/*
	 * check LACP_DISABLED first
	 */

#ifdef HA_SUPPORT
	/* the current state of lp must only be used in active lacp */
	if (cur_lacp_state.active)
#endif
	if (!(lp->lp_state & LACP_STATE_AGGREGATION)) {
		LACP_DPRINTF((LOG_DEBUG, __func__, lp, "return 1\n"));
		return;
	}

	/*
	 * check loopback condition.
	 */
	if (!lacp_compare_systemid(&du->ldu_actor.lip_systemid,
	    &lp->lp_actor.lip_systemid)) {
		LACP_DPRINTF((LOG_DEBUG, __func__, lp, "return 2\n"));
		return;
	}

	/*
	 * EXPIRED, DEFAULTED, CURRENT -> CURRENT
	 */

	lacp_sm_rx_update_selected(lp, du);
	lacp_sm_rx_update_ntt(lp, du);
	lacp_sm_rx_record_pdu(lp, du);

	timeout = (lp->lp_state & LACP_STATE_TIMEOUT) ?
	    LACP_SHORT_TIMEOUT_TIME : LACP_LONG_TIMEOUT_TIME;
	LACP_TIMER_ARM(lp, LACP_TIMER_CURRENT_WHILE, timeout);

	lp->lp_state &= ~LACP_STATE_EXPIRED;

	if (lp->mode == MODE_LINK_LACP_PASSIV)
		lacp_sm_mux(lp);

	/*
	 * kick transmit machine without waiting the next tick.
	 */

	lacp_sm_tx(lp);
}

void
lacp_sm_rx_set_expired(struct chgrp_link *lp)
{

	lp->lp_partner.lip_state &= ~LACP_STATE_SYNC;
	lp->lp_partner.lip_state |= LACP_STATE_TIMEOUT;
	LACP_TIMER_ARM(lp, LACP_TIMER_CURRENT_WHILE, LACP_SHORT_TIMEOUT_TIME);
	lp->lp_state |= LACP_STATE_EXPIRED;
}

void
lacp_sm_rx_timer(struct chgrp_link *lp)
{

	if ((lp->lp_state & LACP_STATE_EXPIRED) == 0) {
		/* CURRENT -> EXPIRED */
		LACP_DPRINTF((LOG_DEBUG, __func__, lp, "CURRENT -> EXPIRED\n"));
		lacp_sm_rx_set_expired(lp);
	} else {
		/* EXPIRED -> DEFAULTED */
		lacp_sm_rx_update_default_selected(lp);
#ifdef HA_SUPPORT
		/* only use the optimistic default during graceful restart */
		if (cur_lacp_state.graceful)
		{
			lacp_sm_rx_record_default(lp, LACP_SM_RX_SOFT);
			LACP_DPRINTF((LOG_DEBUG, __func__, lp, "EXPIRED -> DEFAULTED (SOFT)\n"));
		}
		else
#endif
		{
			lacp_sm_rx_record_default(lp, LACP_SM_RX_FORCE);
			LACP_DPRINTF((LOG_DEBUG, __func__, lp, "EXPIRED -> DEFAULTED (FORCE)\n"));
		}
		lp->lp_state &= ~LACP_STATE_EXPIRED;
	}
}

void
lacp_sm_rx_timer_force(struct chgrp_link *lp)
{
	/* always called after lacp_sm_rx_set_expired */
	assert((lp->lp_state & LACP_STATE_EXPIRED) != 0);
	/* EXPIRED -> DEFAULTED */
	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "EXPIRED -> DEFAULTED (FORCE)\n"));
	lacp_sm_rx_update_default_selected(lp);
	lacp_sm_rx_record_default(lp, LACP_SM_RX_FORCE);
	lp->lp_state &= ~LACP_STATE_EXPIRED;
}

static void
lacp_sm_rx_record_pdu(struct chgrp_link *lp, const struct lacpdu *du)
{
	int active;
	uint8_t oldpstate;
	char buf[LACP_STATESTR_MAX+1];

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));

	oldpstate = lp->lp_partner.lip_state;

#ifdef HA_SUPPORT
	/* force copy on inactive */
	if (!cur_lacp_state.active) {
		LACP_DPRINTF((LOG_DEBUG, __func__, lp, "forced copy of PDU ids\n"));
		/* du->ldu_partner = us, because here we receive a
		   message from the peer. Do NOT copy state, it will
		   be updated through our own state machine, it makes
		   things clearer.*/
		memcpy(&lp->lp_actor, &du->ldu_partner,
		       offsetof(struct lacp_peerinfo, lip_state));
	}
#endif

	active = (du->ldu_actor.lip_state & LACP_STATE_ACTIVITY)
	    || ((lp->lp_state & LACP_STATE_ACTIVITY) &&
	    (du->ldu_partner.lip_state & LACP_STATE_ACTIVITY));

	lp->lp_partner = du->ldu_actor;
	if (active &&
	    ((LACP_STATE_EQ(lp->lp_state, du->ldu_partner.lip_state,
	    LACP_STATE_AGGREGATION) &&
	    !lacp_compare_peerinfo(&lp->lp_actor, &du->ldu_partner))
	    || (du->ldu_partner.lip_state & LACP_STATE_AGGREGATION) == 0)) {
		/* nothing */
	} else {
		LACP_DPRINTF((LOG_DEBUG, __func__, lp, "partner => ~LACP_STATE_SYNC\n"));
		lp->lp_partner.lip_state &= ~LACP_STATE_SYNC;
	}

	lp->lp_state &= ~LACP_STATE_DEFAULTED;
	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "old pstate %s\n",
	    lacp_format_state(oldpstate, buf, sizeof(buf))));
	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "new pstate %s\n",
	    lacp_format_state(lp->lp_partner.lip_state, buf, sizeof(buf))));
	lacp_sm_ptx_update_timeout(lp, oldpstate);
}

static void
lacp_sm_rx_update_ntt(struct chgrp_link *lp, const struct lacpdu *du)
{

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));
	if (lacp_compare_peerinfo(&lp->lp_actor, &du->ldu_partner) ||
	    !LACP_STATE_EQ(lp->lp_state, du->ldu_partner.lip_state,
	    LACP_STATE_ACTIVITY | LACP_STATE_SYNC | LACP_STATE_AGGREGATION)) {
		LACP_DPRINTF((LOG_DEBUG, __func__, lp, "assert ntt\n"));
		lacp_sm_assert_ntt(lp);
	}

	/* force lacpdu output for passive links */
	if (lp->mode == MODE_LINK_LACP_PASSIV)
		lacp_sm_assert_ntt(lp);
}

static void
lacp_sm_rx_record_default(struct chgrp_link *lp, int force_rx_sm_reset)
{
	uint8_t oldpstate;
	struct lacp_peerinfo lacp_partner_admin;

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));

	oldpstate = lp->lp_partner.lip_state;
	lacp_partner_admin = lacp_partner_admin_optimistic;

	/* be pessimistic if forced */
	if ((force_rx_sm_reset == LACP_SM_RX_FORCE)) {
		LACP_DPRINTF((LOG_DEBUG, __func__, lp, "using pessimistic default"));
		lacp_partner_admin = lacp_partner_admin_pessimistic;
	}

	lp->lp_partner = lacp_partner_admin;
	lp->lp_state |= LACP_STATE_DEFAULTED;
	lacp_sm_ptx_update_timeout(lp, oldpstate);
}

static void
lacp_sm_rx_update_selected_from_peerinfo(struct chgrp_link *lp,
    const struct lacp_peerinfo *info)
{

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));

	if (lacp_compare_peerinfo(&lp->lp_partner, info) ||
	    !LACP_STATE_EQ(lp->lp_partner.lip_state, info->lip_state,
	    LACP_STATE_AGGREGATION)) {
		lp->lp_selected = LACP_UNSELECTED;
		/* mux machine will clean up lp->lp_aggregator */
	}
}

static void
lacp_sm_rx_update_selected(struct chgrp_link *lp, const struct lacpdu *du)
{

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));

	lacp_sm_rx_update_selected_from_peerinfo(lp, &du->ldu_actor);
}

static void
lacp_sm_rx_update_default_selected(struct chgrp_link *lp)
{

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));

	lacp_sm_rx_update_selected_from_peerinfo(lp, &lacp_partner_admin_optimistic);
}
