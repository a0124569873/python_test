/*
 * Copyright 2007-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_FILTER_H_
#define _NETGRAPH_NG_FILTER_H_

/* Node type name and magic cookie */
#define NG_FILTER_NODE_TYPE    "filter"
#define NGM_FILTER_COOKIE      200702201

/* Hook names */
#define NG_FILTER_HOOK_LOWER   "lower"    /* the lower hook */
#define NG_FILTER_HOOK_UPPER   "upper"    /* the upper hook */
#define NG_FILTER_HOOK_DAEMON  "daemon"   /* the daemon hook */

/* Statistics structure for one hook */
struct ng_filter_icmp {
	uint32_t  icmp_saddr;
	uint32_t  icmp_daddr;
	uint8_t   icmp_type;
	uint16_t  icmp_echo_id;
};

/* Keep this in sync with the above structure definition */
#define NG_FILTER_ICMP_TYPE_INFO {				\
	{ "saddr", &ng_parse_uint32_type    },		\
	{ "daddr", &ng_parse_uint32_type    },		\
	{ "icmp_type", &ng_parse_uint8_type    },		\
	{ "type_echo_id", &ng_parse_uint16_type    },		\
	{ NULL }						\
}

/* Netgraph commands */
enum {
	NGM_FILTER_GET_ICMPSIZE = 1, /* get count of icmp filter */
	NGM_FILTER_GET_ICMP,         /* get icmp filter */
	NGM_FILTER_SET_ICMP,         /* set icmp filter */
	NGM_FILTER_DEL_ICMP,         /* del an icmp filter */
};

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_FILTER, "ng_filter", "netgraph FILTER");
#else
#define M_NETGRAPH_FILTER M_NETGRAPH
#endif

#endif /* _NETGRAPH_NG_FILTER_H_ */
