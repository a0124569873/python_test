/*
 * Copyright 2003-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_DIV_H_
#define _NETGRAPH_DIV_H_

/* Node type name and magic cookie */
#define NG_DIV_NODE_TYPE	"div"
#define NGM_DIV_COOKIE		740417073

/* Hook names */
#define NG_DIV_HOOK_IN		"in"
#define NG_DIV_HOOK_OUT		"out"
#define NG_DIV_HOOK_DIVIN	"divin"
#define NG_DIV_HOOK_DIVOUT	"divout"

/* Statistics structure for one hook */
struct ng_div_hookstat {
	u_int64_t	inOctets;
	u_int64_t	inFrames;
	u_int64_t	outOctets;
	u_int64_t	outFrames;
};

/* Keep this in sync with the above structure definition */
#define NG_DIV_HOOKSTAT_INFO	{				\
	  { "inOctets",		&ng_parse_uint64_type,	0	},	\
	  { "inFrames",		&ng_parse_uint64_type,	0	},	\
	  { "outOctets",	&ng_parse_uint64_type,	0	},	\
	  { "outFrames",	&ng_parse_uint64_type,	0	},	\
	  { NULL, 		NULL, 			0	}	\
}

/* Statistics structure returned by NGM_DIV_GET_STATS */
struct ng_div_stats {
	struct ng_div_hookstat	in;
	struct ng_div_hookstat	out;
	struct ng_div_hookstat	divin;
	struct ng_div_hookstat	divout;
};

/* Keep this in sync with the above structure definition */
#define NG_DIV_STATS_INFO(hstype)	{			\
	  { "in",	(hstype),	0	},	\
	  { "out",	(hstype),	0	},	\
	  { "divin",	(hstype),	0	},	\
	  { "divout",	(hstype),	0	},	\
	  { NULL, 	NULL, 		0 	}	\
}

/* Netgraph commands */
enum {
	NGM_DIV_GET_STATS = 1,		/* get stats */
	NGM_DIV_CLR_STATS,		/* clear stats */
	NGM_DIV_GETCLR_STATS,		/* atomically get and clear stats */
};

#endif /* _NETGRAPH_DIV_H_ */
