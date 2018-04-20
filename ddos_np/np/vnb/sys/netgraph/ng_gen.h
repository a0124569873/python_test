/*
 * Copyright 2013 6WIND S.A.
 */

#ifndef NG_GEN_H_
#define NG_GEN_H_

/* Node type name and magic cookie */
#define NG_GEN_NODE_TYPE "gen"
#define NGM_GEN_COOKIE 2013122415

/* Hook names */
#define NG_GEN_HOOK_OUT "out"
#define NG_GEN_HOOK_IN "in_"

/* Netgraph commands */
enum {
	NGM_GEN_INVALID,
	NGM_GEN_SET_RATE,
	NGM_GEN_GET_RATE,
	NGM_GEN_SET_BURST,
	NGM_GEN_GET_BURST,
	NGM_GEN_SET_HOOK_RATE,
	NGM_GEN_GET_HOOK_RATE,
	NGM_GEN_SET_HOOK_BURST,
	NGM_GEN_GET_HOOK_BURST,
	NGM_GEN_SET_PACKET,
	NGM_GEN_GET_PACKET,
};

/* Limits */
#define NG_GEN_MAX_PACKET_SIZE 65536
#define NG_GEN_MAX_BURST_SIZE 1000

#endif /* NG_GEN_H_ */
