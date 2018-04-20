/*
 * Copyright 2007-2013 6WIND S.A.
 */

#ifndef _LACP_NODE_H_
#define _LACP_NODE_H_

/*
 * lacpd management configuration for the link :
 * MODE_LINK_ON : static, no LACP
 * MODE_LINK_LACP_xxx : LACP negociation
 */
#define MODE_LINK_ON	       0x10001
#define MODE_LINK_LACP_ACTIVE  0x10002
#define MODE_LINK_LACP_PASSIV  0x10003

enum lacp_selected {
	LACP_UNSELECTED,
	LACP_STANDBY,	/* not used in this implementation */
	LACP_SELECTED,
};

enum lacp_mux_state {
	LACP_MUX_DETACHED,
	LACP_MUX_WAITING,
	LACP_MUX_ATTACHED,
	LACP_MUX_COLLECTING,
	LACP_MUX_DISTRIBUTING,
};

/* select LACP fast or slow mode */
#define	LACP_SLOW 			0
#define	LACP_FAST 			1

#define	LACP_TIMER_CURRENT_WHILE	0
#define	LACP_TIMER_PERIODIC		1
#define	LACP_TIMER_WAIT_WHILE		2
#define	LACP_NTIMER			3

#define	LACP_TIMER_ARM(port, timer, val) \
	(port)->lp_timer[(timer)] = (val)
#define	LACP_TIMER_DISARM(port, timer) \
	(port)->lp_timer[(timer)] = 0
#define	LACP_TIMER_ISARMED(port, timer) \
	((port)->lp_timer[(timer)] > 0)


struct chgrp_link {
	int linknum;	/* index in table */
	int mode;	/* static, active, passive */
	int status;	/* ethgrp node "mode": active, inactive */
	int if_flags;	/* flags of associated iface */
	int priority;	/* link priority */
	TAILQ_ENTRY(chgrp_link) lp_dist_q;
	struct lacp_peerinfo lp_partner;
	struct lacp_peerinfo lp_actor;
#define	lp_state	lp_actor.lip_state
#define	lp_key		lp_actor.lip_key
	struct timeval lp_last_lacpdu_sent;
	enum lacp_mux_state lp_mux_state;
	enum lacp_selected lp_selected;
	int lp_flags;
	int lp_timer[LACP_NTIMER];

	char ifname[IFNAMSIZ];
	struct lacpd_iface *iface;

	struct lacp_aggregator *lp_aggregator;
	struct event timer_evt;
};

struct lacp_aggregator {
	TAILQ_ENTRY(lacp_aggregator) la_q;
	int la_refcnt; /* number of ports which selected us */
	int la_nports; /* number of distributing ports  */
	TAILQ_HEAD(, chgrp_link) la_ports; /* distributing ports */
	struct lacp_peerinfo la_partner;
	struct lacp_peerinfo la_actor;
	int la_pending; /* number of ports which is waiting wait_while */
};

struct chgrp_node {
	LIST_ENTRY(chgrp_node) next;
	char chgrpname[IFNAMSIZ];     /* channel-group name */
	char nodename[NG_NODELEN+1];  /* VNB node name */
	struct chgrp_link *link[NG_ETH_GRP_MAX_LINKS];
	int link_count;
	int algo;
	int lacp_rate;
	int status;  /*for RUNNING flags. >=1: Running, 0: not running */
	uint8_t ether_addr[ETH_ALEN];
	unsigned int index;

	struct lacp_aggregator *lsc_active_aggregator;
	TAILQ_HEAD(, lacp_aggregator) lsc_aggregators;
	int lsc_suppress_distributing;
};
LIST_HEAD(chgrp_node_list, chgrp_node);

#define	LACPPORT_NTT		1	/* need to transmit */

/* global variables */
struct chgrp_node_list chgrp_nodes;

/* init functions */
int chgrp_vnb_init(void);
int chgrp_node_init(void);
#if defined(LACP_NOTIF) && defined(HA_SUPPORT)
int chgrp_lacpdu_dup_init(void);
#endif

/* node management functions */
struct chgrp_node *chgrp_node_create(const char *chgrpname, const char *nodename);
void chgrp_node_destroy(struct chgrp_node *node);
void chgrp_node_destroy_all(void);
struct chgrp_node *chgrp_node_lookup_by_chgrpname(const char *chgrpname);
struct chgrp_node *chgrp_node_lookup_by_nodename(const char *nodename);
struct chgrp_node *chgrp_node_lookup_by_link_ifname(const char *ifname);

/* node configuration */
int chgrp_node_connect(struct chgrp_node *);
int chgrp_node_configure_status(struct chgrp_node *, int linknum, int mode);
int chgrp_node_configure_algo(struct chgrp_node *, int algo);
int chgrp_node_configure_prio(struct chgrp_node *, int linknum, int prio);
int chgrp_node_configure_mac(struct chgrp_node *);
int chgrp_node_configure_lacprate(struct chgrp_node *);
#ifdef HA_SUPPORT
void chgrp_node_sync_to_vnb_all(void);
#endif

/* link management */
struct chgrp_link *chgrp_link_create(struct chgrp_node *node, int linknum,
				  const char *ifname);
int chgrp_link_free(struct chgrp_node *node, int linknum);
struct chgrp_link *chgrp_link_lookup_by_ifname(const struct chgrp_node *node,
					       const char *ifname);
int chgrp_link_connect(struct chgrp_node *node, struct chgrp_link *link);
int set_running_flag(char *name, int flags);
void increase(struct chgrp_node *node);
void decrease(struct chgrp_node *node);

void lacp_run_timers(struct chgrp_link *);
int lacp_xmit_lacpdu(struct chgrp_link *link);

void lacp_disable_collecting(struct chgrp_link *lp);
void lacp_enable_collecting(struct chgrp_link *lp);
void lacp_disable_distributing(struct chgrp_link *lp);
void lacp_enable_distributing(struct chgrp_link *lp);

void lacp_select(struct chgrp_link *lp);
void lacp_unselect(struct chgrp_link *lp);

int netlink_csock_init(int nl_csockbufsiz);
int netlink_csock_close(void);
#endif /* _LACP_NODE_H_ */
