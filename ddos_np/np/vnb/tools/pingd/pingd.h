/*
 * Copyright 2007 6WIND S.A.
 */

#ifndef _PINGD_H_
#define _PINGD_H_

#define PINGD_ERR_INIT           128   /* system error */
#define PINGD_ERR_PARAM          129   /* wrong parameters */
#define PINGD_ERR_DAEMON         130   /* error when fmip6ard tries to become a daemon */

#define PINGD_PIDFILE            "/var/run/pingd.pid"
#define PINGD_COMMAND_PORT       7781

#define PINGD_NODE_DFLT_INT      20
#define PINGD_NODE_DFLT_ROB      3
#define PINGD_NODE_DFLT_CHECK    2

/* VNB node comms */
#define PINGD_NG_SOCK_HOOK_NAME  "daemon"

struct node {
	LIST_ENTRY(node)  nd_entries;
	char *            nd_name;           /* node name */
	char *            nd_fltname;        /* VNB filter name */
	char *            nd_ifname;         /* VNB iface name */
	int               nd_csock;          /* VNB socket */
	int               nd_dsock;          /* VNB socket */
	struct event      nd_cs_ev;          /* csock event */
	struct event      nd_ds_ev;          /* dsock event */
	uint32_t          nd_ouraddr;        /* our address of the tunnel */
	uint32_t          nd_peeraddr;       /* peer address of the tunnel */
	uint32_t          nd_brdaddr;        /* broadcast address to listen */
	uint8_t           nd_carrier;        /* carrier status */
	int               nd_interval;       /* interval between ping in seconds */
	int               nd_robustness;     /* # lost ping before set not carrier */
	struct event      nd_sendreq;        /* timer to send ping echo request */
	int               nd_checkdelay;     /* delay before carrier check */
	struct event      nd_carriercheck;   /* timer to check carrier status */
	uint16_t          nd_current_seqno;  /* current sequence number */
	uint16_t          nd_last_seqno;     /* last sequence number */
};
LIST_HEAD(node_list, node);

extern struct node_list nodes;
extern uint16_t ping_id;
extern int broadcast;

#endif /* _PINGD_H_ */
