/*
 * Copyright(c) 2007 6WIND
 */
#ifndef _NG_ETHER_FP_H_
#define _NG_ETHER_FP_H_

int ng_ether_init(void);
int ng_ether_attach(fp_ifnet_t *ifp, uint32_t nodeid);
int ng_ether_detach(fp_ifnet_t *ifp, uint8_t vnb_keep_node);
int ng_ether_input(struct mbuf *m, fp_ifnet_t *ifp, void *data);

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include "fp-vnb.h"

/*
 * Maximum input lower hooks
 */
#if defined(CONFIG_VNB_ETHER_MAX_LOWER_IN)
#define FP_NG_ETHER_MAX_LOWER_IN_HOOKS CONFIG_VNB_ETHER_MAX_LOWER_IN
#else
#define FP_NG_ETHER_MAX_LOWER_IN_HOOKS 64
#endif

/* Per-node private data */
struct ng_ether_private {
	fp_ifnet_t	*ifp;		/* associated interface */
	uint32_t	autoSrcAddr:8;	/* always overwrite source address */
	uint32_t        reserved:24;
	node_p          node;           /* associated node */
	hook_p		upper;		/* upper hook connection */
	hook_p		lower;		/* lower hook connection */
	hook_p		lower_in[FP_NG_ETHER_MAX_LOWER_IN_HOOKS]; /* lower input hooks */
	hook_p		attach;		/* attach hook (only hook possible for mkpeer) */
};
typedef struct ng_ether_private *ether_priv_p;

/* To store type of hook and cache node info  */
struct ng_hether_private {
         uint8_t type;
         uint8_t autoSrcAddr;
         uint16_t reserved;
	/* necessary to avoid warning on some arch */
	unsigned long tag;
};

typedef struct ng_hether_private *hether_priv_p;

#endif
