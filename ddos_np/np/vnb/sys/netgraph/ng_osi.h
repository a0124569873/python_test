/*
 * Copyright 2007-2012 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_OSI_H_
#define _NETGRAPH_NG_OSI_H_

/*
 *################ common for both osi_eth and osi_tun ##################
 */

#define MAX_OSI_LEN		20
#define NLPID_CLNP		0x81
#define NLPID_ESIS		0x82

#ifdef _KERNEL

struct clnp_hdr_fix {
	uint8_t nlpid;                  /* = htons(0x81) CLNP */
	uint8_t len;
	uint8_t version;
	uint8_t ttl;
	uint8_t flag;
	uint16_t seglen;
	uint8_t chsum_C0;
	uint8_t chsum_C1;
}__attribute__ ((packed));

#define CLNP_TYPE 0x1f
#define CLNP_ERQ  0x1e
#define CLNP_ERP  0x1f

#define CLNP_DATA 0x1c
#define CLNP_FLAG  (0x80 | CLNP_DATA)

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_OSI, "ng_osi", "netgraph OSI");
#else
#define M_NETGRAPH_OSI M_NETGRAPH
#endif

#endif

#endif /* _NETGRAPH_NG_OSI_H_ */

