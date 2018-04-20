/*
 * Copyright 2011-2013 6WIND S.A.
 */

/*	$NetBSD: ieee8023ad_lacp_sm_tx.c,v 1.3 2005/12/11 12:24:54 christos Exp $	*/

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

#include <stddef.h>
#include <sys/queue.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netgraph/ng_message.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_ethgrp.h>
#include <event.h>

#include <syslog.h>
#include <libconsole.h>
#include <sys/time.h>
#include <time.h>

#include <netgraph/ieee8023_slowprotocols.h>
#include <netgraph/ieee8023_tlv.h>
#include <netgraph/ieee8023ad_lacp.h>
#include "node.h"
#include "ieee8023ad_lacp_sm.h"
#include "ieee8023ad_lacp_debug.h"
#include "lacp.h"

/* transmit machine */
/* inter-packet interval : from LACP */
static const struct timeval fast_periodic_interval = {
	.tv_sec = 0,
	.tv_usec = (1000000L/LACP_TICK_HZ)*(LACP_FAST_PERIODIC_TIME),
};

void
lacp_sm_tx(struct chgrp_link *lp)
{
	int error = 0;
	struct timeval now, next_lacpdu_sent, now_plus_intval;
	struct timespec now_spec;

#if defined(LACP_DEBUG_1)
	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));
#endif
	if (!(lp->lp_state & LACP_STATE_AGGREGATION)
#if 1
	    || (!(lp->lp_state & LACP_STATE_ACTIVITY)
	    && !(lp->lp_partner.lip_state & LACP_STATE_ACTIVITY))
#endif
	    ) {
		LACP_DPRINTF((LOG_DEBUG, __func__, lp, "force ~LACPPORT_NTT\n"));
		lp->lp_flags &= ~LACPPORT_NTT;
	}

	if (!(lp->lp_flags & LACPPORT_NTT)) {
#if defined(LACP_DEBUG_1)
		LACP_DPRINTF((LOG_DEBUG, __func__, lp, "~LACPPORT_NTT\n"));
#endif
		return;
	}

	/* rate limit : only for Active mode links */
	error = clock_gettime(CLOCK_MONOTONIC, &now_spec);
	if ( error ) {
		DEBUG(LOG_ERR, "%s: bad clock_gettime\n", __func__);
		return;
	}
	now.tv_sec = now_spec.tv_sec;
	now.tv_usec = now_spec.tv_nsec/1000;
	/* next date for lacpdu Tx + normalization */
	timeradd(&lp->lp_last_lacpdu_sent, &fast_periodic_interval, &next_lacpdu_sent);
	/* If the now.tv_sec arrived MAX, it will go back and start from 0.
	 * And we distinguish this situation by check current time + interval
	 * is smaller than now */
	timeradd(&now, &fast_periodic_interval, &now_plus_intval);
	if ( (lp->mode == MODE_LINK_LACP_ACTIVE) &&
	     ( timercmp(&now, &next_lacpdu_sent, <) ||
	       /* indication of wraparound for 'now' */
	       timercmp(&now_plus_intval, &now, <) ) ) {
#if defined(LACP_DEBUG_1)
		LACP_DPRINTF((LOG_DEBUG, __func__, lp, "LACP_FAST_PERIODIC_TIME\n"));
#endif
		return;
	}
#ifdef HA_SUPPORT
	/* only refresh the timer if the LACPDUs are actually sent */
	if ((!cur_lacp_state.active) ||
	    (cur_lacp_state.graceful)) {
#if defined(LACP_DEBUG_1)
		LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Passive or Graceful : no PDU xmit"));
#endif
		return;
	}
#endif
	lp->lp_last_lacpdu_sent = now;

	error = lacp_xmit_lacpdu(lp);

	if (error == 0) {
		lp->lp_flags &= ~LACPPORT_NTT;
	} else {
		DEBUG(LOG_ERR, "lacpdu transmit failure, error %d\n", error);
	}
}

void
lacp_sm_assert_ntt(struct chgrp_link *lp)
{

	lp->lp_flags |= LACPPORT_NTT;
}
