/*
 * Copyright(c) 2007 6WIND
 */

#ifndef __NG_EIFACE_FP_H_
#define __NG_EIFACE_FP_H_

int ng_eiface_init(void);
int ng_eiface_attach(fp_ifnet_t *ifp);
int ng_eiface_detach(fp_ifnet_t *ifp, uint8_t vnb_keep_node);
int ng_eiface_output(struct mbuf *m, fp_ifnet_t *ifp, void *data);

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include "fp-vnb.h"

/* Node private data */
struct ng_eiface_private {
	fp_ifnet_t *ifp;	        /* This interface */
	node_p	node;			/* Our netgraph node */
	hook_p	ether;			/* Hook for ethernet stream */
	char    ifname[FP_IFNAMSIZ];
	FPN_LIST_ENTRY(ng_eiface_private) chain;
};
typedef struct ng_eiface_private *eiface_priv_p;

void ng_eiface_link(fp_ifnet_t *ifp, eiface_priv_p priv);

#endif
