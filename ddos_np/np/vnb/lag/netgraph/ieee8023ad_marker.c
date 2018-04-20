/*
 * Copyright 2011-2013 6WIND S.A.
 */

/*	$NetBSD: ieee8023ad_marker.c,v 1.4 2007/02/22 06:20:16 thorpej Exp $	*/

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


#if defined(__LinuxKernelVNB__) /* __VnbLinuxKernel__ */

#include <linux/version.h>

#include <linux/errno.h>
#include <linux/types.h>

#include <linux/if.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif /* CONFIG_KMOD */
#include <netgraph/vnblinux.h>

#elif defined(__FastPath__) /* __FastPath__ */

#include "fp-netgraph.h"

#endif /* __LinuxKernelVNB__ */

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_ethgrp.h>
#include <netgraph/ieee8023_slowprotocols.h>
#include <netgraph/ieee8023_tlv.h>
#include <netgraph/ieee8023ad_marker.h>

static const struct tlv_template marker_info_tlv_template[] = {
	{ MARKER_TYPE_INFO, 16 },
	{ 0, 0 },
};

static const struct tlv_template marker_response_tlv_template[] = {
	{ MARKER_TYPE_RESPONSE, 16 },
	{ 0, 0 },
};

int
ieee8023ad_marker_input(struct mbuf *m, unsigned char * en_addr)
{
	struct markerdu *mdu;
	int error = 0;

	m = m_pullup(m, sizeof(*mdu));
	if (m == NULL) {
		return ENOMEM;
	}

	mdu = mtod(m, struct markerdu *);

	if (memcmp(&mdu->mdu_eh.ether_dhost,
	    &slowp_mc_addr, VNB_ETHER_ADDR_LEN)) {
		goto bad;
	}

	NG_KASSERT(mdu->mdu_sph.sph_subtype == SLOWPROTOCOLS_SUBTYPE_MARKER,
			("%s: bad subtype", __FUNCTION__));
	if (mdu->mdu_sph.sph_version != 1) {
		goto bad;
	}

	switch (mdu->mdu_tlv.tlv_type) {
	case MARKER_TYPE_INFO:
		if (tlv_check(mdu, sizeof(*mdu), &mdu->mdu_tlv,
		    marker_info_tlv_template, 1)) {
			goto bad;
		}
		mdu->mdu_tlv.tlv_type = MARKER_TYPE_RESPONSE;
		memcpy(&mdu->mdu_eh.ether_dhost,
		    &slowp_mc_addr, VNB_ETHER_ADDR_LEN);
		/* the MAC address of the node has been copied to node->priv */
		memcpy(&mdu->mdu_eh.ether_shost,
		    en_addr, VNB_ETHER_ADDR_LEN);
		/* MARKER will be sent by calling function */
		break;

	case MARKER_TYPE_RESPONSE:
		if (tlv_check(mdu, sizeof(*mdu), &mdu->mdu_tlv,
		    marker_response_tlv_template, 1)) {
			goto bad;
		}
		/*
		 * we are not interested in responses as
		 * we don't have a marker sender.
		 */
		/* FALLTHROUGH */
	default:
		goto bad;
	}

	return error;

bad:
	m_freem(m);
	return EINVAL;
}
