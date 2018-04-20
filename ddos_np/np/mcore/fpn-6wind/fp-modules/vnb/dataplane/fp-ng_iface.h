/*
 * Copyright(c) 2007 6WIND
 */

/*
 * fp-ng_iface.h
 *
 * Copyright (c) 1996-1999 Whistle Communications, Inc.
 * All rights reserved.
 * 
 * Subject to the following obligations and disclaimer of warranty, use and
 * redistribution of this software, in source or object code forms, with or
 * without modifications are expressly permitted by Whistle Communications;
 * provided, however, that:
 * 1. Any and all reproductions of the source or object code must include the
 *    copyright notice above and the following disclaimer of warranties; and
 * 2. No rights are granted, in any manner or form, to use Whistle
 *    Communications, Inc. trademarks, including the mark "WHISTLE
 *    COMMUNICATIONS" on advertising, endorsements, or otherwise except as
 *    such appears in the above copyright notice or in the software.
 * 
 * THIS SOFTWARE IS BEING PROVIDED BY WHISTLE COMMUNICATIONS "AS IS", AND
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, WHISTLE COMMUNICATIONS MAKES NO
 * REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, REGARDING THIS SOFTWARE,
 * INCLUDING WITHOUT LIMITATION, ANY AND ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
 * WHISTLE COMMUNICATIONS DOES NOT WARRANT, GUARANTEE, OR MAKE ANY
 * REPRESENTATIONS REGARDING THE USE OF, OR THE RESULTS OF THE USE OF THIS
 * SOFTWARE IN TERMS OF ITS CORRECTNESS, ACCURACY, RELIABILITY OR OTHERWISE.
 * IN NO EVENT SHALL WHISTLE COMMUNICATIONS BE LIABLE FOR ANY DAMAGES
 * RESULTING FROM OR ARISING OUT OF ANY USE OF THIS SOFTWARE, INCLUDING
 * WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * PUNITIVE, OR CONSEQUENTIAL DAMAGES, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES, LOSS OF USE, DATA OR PROFITS, HOWEVER CAUSED AND UNDER ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF WHISTLE COMMUNICATIONS IS ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Author: Archie Cobbs <archie@freebsd.org>
 *
 */

#ifndef __NG_IFACE_FP_H_
#define __NG_IFACE_FP_H_

int ng_iface_init(void);
int ng_iface_attach(fp_ifnet_t *ifp);
int ng_iface_detach(fp_ifnet_t *ifp, uint8_t vnb_keep_node);
int ng_iface_output(struct mbuf *m, fp_ifnet_t *ifp, int af, void *data);

#include <netgraph/netgraph.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_iface.h>
#include "fp-vnb.h"

/* This struct describes one address family */
struct iffam {
	fp_sa_family_t	family;		/* Address family */
	const char	*hookname;	/* Name for hook */
};
typedef const struct iffam *iffam_p;

#define FP_AF_ALLIP 0
/* List of address families supported by our interface */
static const struct iffam gFamilies[] = {
#define FP_NGIFACE_IDX_ALLIP 0
	{ FP_AF_ALLIP,	NG_IFACE_HOOK_ALLIP },
#define FP_NGIFACE_IDX_INET  1
	{ AF_INET,	NG_IFACE_HOOK_INET	},
#define FP_NGIFACE_IDX_INET6 2
	{ AF_INET6,	NG_IFACE_HOOK_INET6	},
};
#define NUM_FAMILIES		(sizeof(gFamilies) / sizeof(*gFamilies))


/* Node private data */
struct ng_iface_private {
	fp_ifnet_t *ifp;	        /* This interface */
	node_p	node;			/* Our netgraph node */
	hook_p	hooks[NUM_FAMILIES];	/* Hook for each address family */
	char    ifname[FP_IFNAMSIZ];
	FPN_LIST_ENTRY(ng_iface_private) chain;
};
typedef struct ng_iface_private *iface_priv_p;

#define IFP2IFACE(ifp, ns) (iface_priv_p)fp_vnb_shared->if_ops[IFP2IDX(ifp)].if_vnb_ops[ns].raw.u.priv
#define SET_IFP2IFACE(ifp, val, ns) fp_vnb_shared->if_ops[IFP2IDX(ifp)].if_vnb_ops[ns].raw.u.priv = (val)

/************************************************************************
			HELPER STUFF
 ************************************************************************/

/*
 * Get the family descriptor from the family ID
 */
static __inline__ iffam_p
get_iffam_from_af(fp_sa_family_t family)
{
	iffam_p iffam;
	unsigned int k;

	for (k = 0; k < NUM_FAMILIES; k++) {
		iffam = &gFamilies[k];
		if (iffam->family == family)
			return (iffam);
	}
	return (NULL);
}

/*
 * Get the family descriptor from the hook
 */
static __inline__ iffam_p
get_iffam_from_hook(iface_priv_p priv, hook_p hook)
{
	unsigned int k;

	for (k = 0; k < NUM_FAMILIES; k++)
		if (priv->hooks[k] == hook)
			return (&gFamilies[k]);
	return (NULL);
}

/*
 * Get the hook from the iffam descriptor
 */

static __inline__ hook_p *
get_hook_from_iffam(iface_priv_p priv, iffam_p iffam)
{
	return (&priv->hooks[iffam - gFamilies]);
}

/*
 * Get the iffam descriptor from the name
 */
static __inline__ iffam_p
get_iffam_from_name(const char *name)
{
	iffam_p iffam;
	unsigned int k;

	for (k = 0; k < NUM_FAMILIES; k++) {
		iffam = &gFamilies[k];
		if (!strcmp(iffam->hookname, name))
			return (iffam);
	}
	return (NULL);
}

#endif
