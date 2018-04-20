/*
 * Copyright 2011-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_VRRP_MUX_H_
#define _NETGRAPH_NG_VRRP_MUX_H_

/* Node type name and magic cookie */
#define NG_VRRP_MUX_NODE_TYPE	"vrrp_mux"
#define NGM_VRRP_MUX_COOKIE	967239369

/* Hook names */
#define NG_VRRP_MUX_HOOK_VRRP_PREFIX	"vrrp"
#define NG_VRRP_MUX_HOOK_ETHER_UPPER	"ether_upper"
#define NG_VRRP_MUX_HOOK_ETHER_LOWER	"ether_lower"

#endif /* _NETGRAPH_NG_VRRP_MUX_H_ */
