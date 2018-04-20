/*
 * Copyright (C) 2012 6WIND, All rights reserved.
 */
#ifndef _FPVS_DATAPATH_H_
#define _FPVS_DATAPATH_H_

#include "fp.h"
#include "fp-netfpc.h"

struct fpvs_ofpbuf {
    void *l2;                   /* Link-level header. */
    void *l2_5;                 /* MPLS label stack */
    void *l3;                   /* Network-level header. */
    void *l4;                   /* Transport-level header. */
    void *l7;                   /* Application data. */
    void *private_p;            /* Private pointer for use by owner. */
};

#ifdef __GNUC__
#define OBJECT_OFFSETOF(OBJECT, MEMBER) offsetof(typeof(*(OBJECT)), MEMBER)
#else
#define OBJECT_OFFSETOF(OBJECT, MEMBER) \
	((char *) &(OBJECT)->MEMBER - (char *) (OBJECT))
#endif
/* Given POINTER, the address of the given MEMBER in a STRUCT object, returns
 * the STRUCT object. */
#define CONTAINER_OF(POINTER, STRUCT, MEMBER) \
	((STRUCT *) (void *) ((char *) (POINTER) - offsetof (STRUCT, MEMBER)))

#include "fpvs-common.h"

int fpvs_ether_input(struct mbuf *m, fp_ifnet_t *ifp, void *data);
int fpvs_if_output(struct mbuf *m, fp_ifnet_t *ifp, void *data);
int fpvs_ifchange(struct mbuf *m, struct fp_netfpc_ctx *ctx);
int fpvs_input(struct mbuf *m, uint32_t ovsport, uint32_t recirc_id, const struct fp_flow_tnl *tun_key,
	       const fpvs_tunnel_decap_t decap, size_t pkt_offset);

#endif /* _FPVS_DATAPATH_H_ */
