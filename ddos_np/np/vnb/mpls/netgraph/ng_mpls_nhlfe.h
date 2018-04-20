/*
 * Copyright  2003-2013 6WIND S.A.
 */

/* In the following code tag and label are use both to design mpls labels */

#ifndef _NETGRAPH_NG_MPLS_NHLFE_H_
#define _NETGRAPH_NG_MPLS_NHLFE_H_

#ifdef __FastPath__
int ng_mpls_nhlfe_init(void);
#endif

/* Node type name */
#define NG_MPLS_NHLFE_NODE_TYPE		"mpls_nhlfe"
#define NG_MPLS_TYPE			0x8847
#define NGM_MPLS_NHLFE_COOKIE           6283185		/* node value : 2*pi number
							 * value for example */

/* Hook names */
#define NG_MPLS_NHLFE_HOOK_NHLFE_IN       "nhlfe_in"			/* incoming hook */
#define NG_MPLS_NHLFE_HOOK_NHLFE_IN_PUSH_BOTTOM "nhlfe_in_push_bottom"	/* incoming push hook for first label */
#define NG_MPLS_NHLFE_HOOK_NHLFE_IN_PUSH  "nhlfe_in_push"		/* incoming push hook */
#define NG_MPLS_NHLFE_HOOK_NHLFE_IN_POP   "nhlfe_in_pop"		/* incoming pop hook */
#define NG_MPLS_NHLFE_HOOK_NHLFE_IN_SWAP  "nhlfe_in_swap"		/* incoming swap hook */
#define NG_MPLS_NHLFE_HOOK_NHLFE_OUT	  "nhlfe_out"			/* outgoing hook */
#define NG_MPLS_NHLFE_HOOK_NHLFE_BOTTOM   "nhlfe_bottom"		/* outgoing hook for the last label */
#define NG_MPLS_NHLFE_HOOK_NHLFE_OAM_IP  "oam_ip"			/* MPLS-OAM TTl==1 or IP RA LSP ping */

/* Node configuration structure */

struct ng_mpls_nhlfe_config {
    uint8_t         debugFlag;	/* Define debug level */
    uint8_t         uplayer;	/* Up layer protocol */
    uint8_t         operation;	/* Operation POP, PUSH or SWAP */
    uint32_t        label;	/* Label value */
    uint8_t         exp;	/* Exp bits */
    uint8_t         ttl;	/* Time To Live */
};

/* Default configuration structure */

#define NG_MPLS_NHLFE_DEFAULT_CONF	0x00
#define NG_MPLS_DEFAULT_TTL		0xff

/* Keep this in sync with the above structure definition 		 */
#define NG_MPLS_NHLFE_CONFIG_TYPE_INFO {        		\
    { "debugFlag", &ng_parse_uint8_type,	0	      },\
    { "uplayer",   &ng_parse_uint8_type,	0	      },\
    { "operation", &ng_parse_uint8_type,	0	      },\
    { "label",     &ng_parse_uint32_type,	0	      },\
    { "exp",	   &ng_parse_uint8_type,	0	      },\
    { "ttl",	   &ng_parse_uint8_type,	0	      },\
    { NULL, 	   NULL,			0             }\
  }

/* Statistics structure */
struct ng_mpls_nhlfe_stats {
    uint64_t        recvOctets;		/* total octets rec'd */
    uint64_t        recvPackets;	/* total pkts rec'd */
    uint64_t        xmitOctets;		/* total octets xmit'd */
    uint64_t        xmitPackets;	/* total pkts xmit'd */
    uint64_t        memoryFailures;	/* times couldn't get mem or mbuf */
    uint64_t        discarded;		/* Invalid treatment */

};

/* Keep this in sync with the above structure definition */
#define NG_MPLS_NHLFE_STATS_TYPE_INFO {		                        	\
	  { "recvOctets",		&ng_parse_uint64_type,	0	},	\
	  { "recvPackets",		&ng_parse_uint64_type,	0	},	\
	  { "xmitOctets",		&ng_parse_uint64_type,	0	},	\
	  { "xmitPackets",		&ng_parse_uint64_type,	0	},	\
	  { "memoryFailures",   	&ng_parse_uint64_type,	0	},	\
	  { "discarded",		&ng_parse_uint64_type,	0   	},	\
	  { NULL,			NULL,			0,	}   	\
}

/* Netgraph control messages */
enum {
    /* Node specific commands */
    NGM_MPLS_NHLFE_SET_CONFIG = 1,	/* set node configuration */
    NGM_MPLS_NHLFE_GET_CONFIG,		/* get node configuration */
    NGM_MPLS_NHLFE_GET_STATS,		/* get node stats */
    NGM_MPLS_NHLFE_CLR_STATS,		/* clear node stats */
    NGM_MPLS_NHLFE_GETCLR_STATS,	/* atomically get & clear node stats */
    NGM_MPLS_NHLFE_NFMARK_GET_INGRESS_KTABLE, /* Get priority mapping table */
    NGM_MPLS_NHLFE_NFMARK_SET_INGRESS_KTABLE, /* Set priority mapping table */
};

/* Operations supported */
enum {
    /* Configuration specific command */
    NG_MPLS_PUSH = 1,
    NG_MPLS_SWAP,
    NG_MPLS_POP,
};

enum {
   NG_NO_UPLAYER = 0,
   NG_IP_UPLAYER,
   NG_MPLS_UPLAYER,
};

#endif
