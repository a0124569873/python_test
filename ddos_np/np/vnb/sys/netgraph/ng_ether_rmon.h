/*
 * Copyright 2005-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_ETHER_RMON_H_
#define _NETGRAPH_NG_ETHER_RMON_H_

/* Node type name and magic cookie */
#define NG_ETHER_RMON_NODE_TYPE		"ether_rmon"
/* SG : Change the magic cookie */
#define NGM_ETHER_RMON_COOKIE			1011392499

/* Hook names */
#define NG_ETHER_RMON_HOOK_LOWERIN      	"lowerin"	/* the lowerin hook */
#define NG_ETHER_RMON_HOOK_LOWEROUT     	"lowerout" 	/* the lowerout hook */
#define NG_ETHER_RMON_HOOK_UPPERIN      	"upperin"	/* the upperin hook */
#define NG_ETHER_RMON_HOOK_UPPEROUT     	"upperout" 	/* the upperout hook */

/* Statistics structure */
struct ng_ether_rmon_stats
{
        /* RMON statistics counters */
        u_int32_t drop_events;
        u_int32_t octets;
        u_int32_t pkts;
        u_int32_t bcast_pkts;
        u_int32_t mcast_pkts;
        u_int32_t crc_align_errors;
        u_int32_t undersize_pkts;
        u_int32_t oversize_pkts;
        u_int32_t fragments;
        u_int32_t jabbers;
        u_int32_t collisions;
        u_int32_t pkts_64;
        u_int32_t pkts_65to127;
        u_int32_t pkts_128to255;
        u_int32_t pkts_256to511;
        u_int32_t pkts_512to1023;
        u_int32_t pkts_1024to1518;
};

/* Keep this in sync with the above structure definition */
#define NG_ETHER_RMON_STATS_TYPE_INFO	{			\
	  { "drop_events",	&ng_parse_uint32_type	},	\
	  { "octets",		&ng_parse_uint32_type	},	\
	  { "pkts",		&ng_parse_uint32_type	},	\
	  { "bcast_pkts",	&ng_parse_uint32_type	},	\
	  { "mcast_pkts",	&ng_parse_uint32_type	},	\
	  { "crc_align_errors",	&ng_parse_uint32_type	},	\
	  { "undersize_pkts",	&ng_parse_uint32_type	},	\
	  { "oversize_pkts",	&ng_parse_uint32_type	},	\
	  { "fragments",	&ng_parse_uint32_type	},	\
	  { "jabbers",		&ng_parse_uint32_type	},	\
	  { "collisions",	&ng_parse_uint32_type	},	\
	  { "pkts_64",		&ng_parse_uint32_type	},	\
	  { "pkts_65to127",	&ng_parse_uint32_type	},	\
	  { "pkts_128to255",	&ng_parse_uint32_type	},	\
	  { "pkts_256to511",	&ng_parse_uint32_type	},	\
	  { "pkts_512to1023",	&ng_parse_uint32_type	},	\
	  { "pkts_1024to1518",	&ng_parse_uint32_type	},	\
	  { NULL }						\
}

/* Netgraph control messages */
enum {
	/*
	 * Node specific commands
	 */

	NGM_ETHER_RMON_GET_STATS,			/* get node stats */
	NGM_ETHER_RMON_CLR_STATS,			/* clear node stats */
	NGM_ETHER_RMON_GETCLR_STATS,		/* atomically get & clear node stats */

	/*
	 * Link specific commands
	 */
	/* [none] */
};

#endif /* _NETGRAPH_NG_ETHER_RMON_H_ */

