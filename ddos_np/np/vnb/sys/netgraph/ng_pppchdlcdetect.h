/*
 * Copyright 2005-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_PPPCHDLCDETECT_H_
#define _NETGRAPH_NG_PPPCHDLCDETECT_H_

/* Node type name and magic cookie */
#define NG_PPPCHDLCDETECT_NODE_TYPE   "pppchdlcdetect"
#define NGM_PPPCHDLCDETECT_COOKIE		     271234390

/* Hook names */
#define NG_PPPCHDLCDETECT_HOOK_DOWN		        "down"
#define NG_PPPCHDLCDETECT_HOOK_UP		          "up"
#define NG_PPPCHDLCDETECT_HOOK_INFO	            "info"

/* Hook nums */
#define NG_PPPCHDLCDETECT_HOOK_NUM_DOWN		        0
#define NG_PPPCHDLCDETECT_HOOK_NUM_UP		        1
#define NG_PPPCHDLCDETECT_HOOK_NUM_INFO 	        2

/* Auto selected states */
#define NG_PPPCHDLCDETECT_STATE_UNDEF               0
#define NG_PPPCHDLCDETECT_STATE_PPP                 1
#define NG_PPPCHDLCDETECT_STATE_CHDLC               2

/* Protocols */
#define NG_PPPCHDLCDETECT_PROTO_UNKNOW              0
#define NG_PPPCHDLCDETECT_PROTO_PPP                 1
#define NG_PPPCHDLCDETECT_PROTO_CHDLC               2

#define NG_PPPCHDLCDETECT_PROTO_LEN                 2

/* State names */
#define NG_PPPCHDLCDETECT_STATE_STR_PPP		"state=ppp"
#define NG_PPPCHDLCDETECT_STATE_STR_CHDLC "state=chdlc"
#define NG_PPPCHDLCDETECT_STATE_STR_UNDEF "state=undef"
#define NG_PPPCHDLCDETECT_STATE_STR_LEN_MAX         16


/* Statistics structure (one for each link) */
struct ng_pppchdlcdetect_link_stats {
  u_int64_t       recvOctets;         /* total octets rec'd on link */
  u_int64_t       recvPackets;        /* total pkts rec'd on link */
  u_int64_t       xmitOctets;         /* total octets xmit'd on link */
  u_int64_t       xmitPackets;        /* total pkts xmit'd on link */
  u_int64_t       droppedRecvPackets; /* ignored (dropped) packets (received on the unactive link) */
  u_int64_t       memoryFailures;     /* times couldn't get mem or mbuf */
};

/* Node configuration structure */
struct ng_pppchdlcdetect_config {
  u_int32_t	state;
};

/* Netgraph control messages */
enum {
  NGM_PPPCHDLCDETECT_SET_CONFIG,	  /* set configuration */
  NGM_PPPCHDLCDETECT_GET_CONFIG,	  /* get configuration */
  NGM_PPPCHDLCDETECT_GET_STATS,	  /* get link stats */
  NGM_PPPCHDLCDETECT_CLR_STATS, 	  /* clear link stats */
  NGM_PPPCHDLCDETECT_GETCLR_STATS,   /* atomically get & clear link stats */
};

#endif /* _NETGRAPH_NG_PPPCHDLCDETECT_H_ */

