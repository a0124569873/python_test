/*
 * Copyright 2011 6WIND S.A.
 */

/*	$NetBSD: ieee8023ad_lacp_sm_ptx.c,v 1.3 2005/12/11 12:24:54 christos Exp $	*/

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

#include <syslog.h>
#include <sys/time.h>

#include <netgraph/ieee8023_slowprotocols.h>
#include <netgraph/ieee8023_tlv.h>
#include <netgraph/ieee8023ad_lacp.h>
#include "node.h"
#include "ieee8023ad_lacp_sm.h"
#include "ieee8023ad_lacp_debug.h"

/* periodic transmit machine */

void
lacp_sm_ptx_update_timeout(struct chgrp_link *lp, uint8_t oldpstate)
{

	if (LACP_STATE_EQ(oldpstate, lp->lp_partner.lip_state,
	    LACP_STATE_TIMEOUT)) {
		return;
	}

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "partner timeout changed\n"));

	/*
	 * FAST_PERIODIC -> SLOW_PERIODIC
	 * or
	 * SLOW_PERIODIC (-> PERIODIC_TX) -> FAST_PERIODIC
	 *
	 * let lacp_sm_ptx_tx_schedule to update timeout.
	 */

	LACP_TIMER_DISARM(lp, LACP_TIMER_PERIODIC);

	/*
	 * if timeout has been shortened, assert NTT.
	 */

	if ((lp->lp_partner.lip_state & LACP_STATE_TIMEOUT)) {
		lacp_sm_assert_ntt(lp);
	}
}

void
lacp_sm_ptx_tx_schedule(struct chgrp_link *lp)
{
	int timeout;

	if (!(lp->lp_state & LACP_STATE_ACTIVITY) &&
	    !(lp->lp_partner.lip_state & LACP_STATE_ACTIVITY)) {

		/*
		 * NO_PERIODIC
		 */

		LACP_TIMER_DISARM(lp, LACP_TIMER_PERIODIC);
		return;
	}

	if (LACP_TIMER_ISARMED(lp, LACP_TIMER_PERIODIC)) {
		return;
	}

	timeout = (lp->lp_partner.lip_state & LACP_STATE_TIMEOUT) ?
	    LACP_FAST_PERIODIC_TIME : LACP_SLOW_PERIODIC_TIME;

	LACP_TIMER_ARM(lp, LACP_TIMER_PERIODIC, timeout);
}

void
lacp_sm_ptx_timer(struct chgrp_link *lp)
{

	lacp_sm_assert_ntt(lp);
}
