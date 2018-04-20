/*
 * Copyright 2006-2013 6WIND S.A.
 */
#ifndef _NETGRAPH_NG_PAE_H_
#define _NETGRAPH_NG_PAE_H_

/* Node type name. This should be unique among all netgraph node types */
#define NG_PAE_NODE_TYPE	"pae"

/* Node type cookie. Should also be unique. This value MUST change whenever
   an incompatible change is made to this header file, to insure consistency.
   The de facto method for generating cookies is to take the output of the
   date command: date -u +'%s' */
#define NGM_PAE_COOKIE		1141923809

/* EAP Ethernet type */
#define ETH_P_EAP   		0x888e

/*
 * Delay in second between two timer triggers
 * So, the total delay
 *     = NG_PAE_DEFAULT_TIMER_DELAY x NG_PAE_MACADDR_EXPIRE_DELAY sec
 */
#define NG_PAE_DEFAULT_TIMER_DELAY 1
/* The expiration time of an address, in unit of the above */
#define NG_PAE_MACADDR_EXPIRE_DELAY 10


/* Hook names */
#define NG_PAE_HOOK_LOWERIN	"lowerin"
#define NG_PAE_HOOK_LOWEROUT	"lowerout"
#define NG_PAE_HOOK_UPPERIN	"upperin"
#define NG_PAE_HOOK_UPPEROUT	"upperout"
#define NG_PAE_HOOK_EAPOLDATA	"eapoldata"

struct ng_pae_alias {
	const int	value;
        const char	*name;
};

/* Netgraph commands understood by this node type */
enum {
	NGM_PAE_PORT_STATE_GET = 1, /* get port status */
        NGM_PAE_PORT_STATE_SET,     /* set port status */
        NGM_PAE_PORT_STATS_GET,     /* get port statistics */
        NGM_PAE_PORT_STATS_RESET,   /* reset port statistics */
        NGM_PAE_PORT_STATS_GET_AND_RESET,   /* get and reset port statistics */
        NGM_PAE_MAC_ADD,            /* Add a MacAddress, with parameters */
	NGM_PAE_MAC_DEL,            /* Delete a MacAddress */
        NGM_PAE_MAC_DUMP,           /* Dump the current MacAddress List */
        NGM_PAE_MAC_FLUSH,          /* Flush the dynamic entries of the list (keep manually set ones) */
        NGM_PAE_MAC_FULL_FLUSH,     /* Flush all the list ( => number of entries == 0) */
        NGM_PAE_SET_TIMER_DELAY,    /* Change the timer delay */
        NGM_PAE_GET_TIMER_DELAY,    /* Get the timer delay */
        NGM_PAE_SET_MACADDR_EXPIRE_DELAY,   /* Change the expiration time delay of a mac address */
        NGM_PAE_GET_MACADDR_EXPIRE_DELAY,   /* Get the expiration time delay of a mac address */
        NGM_PAE_SET_PORT_BEHAVIOR,          /* Set the port behavior (port-based / addr-based)  */
        NGM_PAE_GET_PORT_BEHAVIOR,          /* Get the port behavior */
};



enum {
	PAE_PORT_STATE_BLOCKED = 0,
	PAE_PORT_STATE_FILTERED,
	PAE_PORT_STATE_AUTHORIZED,
};


enum {
	PAE_MACADDR_STATE_NEGOCIATING = 0,
	PAE_MACADDR_STATE_MANUAL,
	PAE_MACADDR_STATE_EAP_AUTH,
};


enum {
	PAE_PORT_BASED_BEHAVIOR = 0,
	PAE_ADDR_BASED_BEHAVIOR,
};

struct ng_pae_macaddr_msg {
	u_char        saddr[VNB_ETHER_ADDR_LEN];/* ethernet address of the source */
	u_int8_t      state;   		/* Only values from ENUM */
	u_int8_t      authorized;  	/* boolean: authorized or not */
	u_int16_t     staleness;
}  __attribute__ ((packed));


/* Structure returned by NGM_PAE_MAC_DUMP */
struct ng_pae_macaddress_list {
	u_int32_t			numMacs;
	struct ng_pae_macaddr_msg	macaddress[];
} __attribute__ ((packed));

/* Keep this in sync with the above structure definition */
#define NG_PAE_MACADDR_TYPE_INFO(entype)		{	\
	  { "saddr",		(entype)		},	\
	  { "state",		&ng_parse_uint8_type	},	\
	  { "authorized",	&ng_parse_uint8_type	},	\
	  { "staleness",	&ng_parse_uint16_type	},	\
	  { NULL }					\
}


/* Keep this in sync with the above structure definition */
#define NG_PAE_MACADDR_LIST_TYPE_INFO(harytype)	{	\
	  { "numMacs",		&ng_parse_uint32_type	},	\
	  { "macaddresses",	(harytype)		},	\
	  { NULL }						\
}

/* Per-port statistic information */
struct ng_pae_port_stats {
	u_int32_t  lowerin_count_in;
	u_int32_t  lowerout_count_in;
	u_int32_t  upperin_count_in;
	u_int32_t  upperout_count_in;
	u_int32_t  eapoldata_count_in;
	u_int32_t  lowerin_count_out;
	u_int32_t  lowerout_count_out;
	u_int32_t  upperin_count_out;
	u_int32_t  upperout_count_out;
	u_int32_t  eapoldata_count_out;
	u_int32_t  dropped_count;
        u_int32_t  eap_detected;
        u_int16_t  timer;
} __attribute__ ((packed));

/* Keep this in sync with the above structure definition */
#define NG_PAE_PORT_STATS_TYPE_INFO	{			\
	  { "lowerin_count_in",		&ng_parse_uint32_type	},	\
	  { "lowerout_count_in",	&ng_parse_uint32_type	},	\
	  { "upperin_count_in",		&ng_parse_uint32_type	},	\
	  { "upperout_count_in",	&ng_parse_uint32_type	},	\
	  { "eapoldata_count_in",	&ng_parse_uint32_type	},	\
	  { "lowerin_count_out",	&ng_parse_uint32_type	},	\
	  { "lowerout_count_out",	&ng_parse_uint32_type	},	\
	  { "upperin_count_out",	&ng_parse_uint32_type	},	\
	  { "upperout_count_out",	&ng_parse_uint32_type	},	\
	  { "eapoldata_count_out",	&ng_parse_uint32_type	},	\
	  { "dropped_count",		&ng_parse_uint32_type	},	\
          { "eap_detected",		&ng_parse_uint32_type	},	\
          { "timer",                    &ng_parse_uint16_type   },      \
	  { NULL }						\
}

#endif /* _NETGRAPH_NG_PAE_H_ */
