/*
 * Copyright 2004-2012 6WIND S.A.
 */

#ifndef __SNOOP_H__
#define __SNOOP_H__


#if 0
========================================================

                         l2_fwd
     +-----+---------->+---------+------>
     |     |           |         |
     |     |           |  ...    |
     |  e  |           |         |
     |  t  |           +---------+
     |  h  |           |l2f_used |<---+
     |  -  |           +---------+    |
     |  i  |    +----->|l2f_ports|    |
     |  f  |    |      +---------+    |
     |     |    |                     |
     |     |    |                     |
     |     |    |        mc_fwd       |
     |     |---------->+---------+--------->
     |     |    |      |         |    |
     |     |    |      |  ...    +    |
     |     |    |      |         |    |
     |     |    |      +---------+    |
     |     |    |      | mcf_l2f |----+
     |     |    |      +---------+
     |     |    |  +-->|mcf_ports|
     +-----+    |  |   +---------+
                |  |
                |  |
                |  |    l2_entry
     +-----+---------->+---------+------>
     |     |    |  |   |         |
     |     |    |  |   |  ...    |
     |  e  |    |  |   |         |
     |  t  |    |  |   +---------+
     |  h  |    |  |   | l2_used |<---+
     |  -  |    |  |   +---------+    |
     |  p  |    +--|---| l2_l2f  |    |
     |  o  |       |   +---------+    |
     |  r  |       |                  |
     |  t  |       |                  |
     |     |       |                  |
     |     |       |     mc_entry     |
     |     |---------->+---------+--------->
     |     |       |   |         |    |
     |     |       |   |  ...    +    |
     |     |       |   |         |    |
     |     |       |   +---------+    |
     |     |       |   |  mc_l2  |----+
     |     |       |   +---------+
     |     |       +---| mc_mcf  |
     +-----+           +---------+

========================================================
#endif


#include "netgraph/ng_bridge.h"
#include "netgraph/ng_bridge_snoop.h"

/*
 * Time Management
 */
#ifdef DEBUG_TIME
	extern u_int32_t THE_TIME;
#	define get_time() THE_TIME
#else
#	define get_time() time(NULL)
#endif
#define TMO_SCALE 1000
#define TMO_INFINITE 0xffffffff
#define compute_deadline(x) (get_time()  + (x)/ TMO_SCALE - .5)	/* -.5 to be sure we meet the deadline */

/* Hardware address. */
#if defined FreeBSD ||defined NetBSD
#define HAVE_SOCKADDR_DL
#endif

#ifndef AF_LINK
#define AF_LINK AF_AX25
#endif

#ifndef HAVE_SOCKADDR_DL
/*
 * Structure of a Link-Level sockaddr:
 */

struct sockaddr_dl {
        u_char  sdl_len;        /* Total length of sockaddr */
        u_char  sdl_family;     /* AF_LINK */
        u_short sdl_index;      /* if != 0, system given index for interface */
        u_char  sdl_type;       /* interface type */
        u_char  sdl_nlen;       /* interface name length, no trailing 0 reqd. */
        u_char  sdl_alen;       /* link level address length */
        u_char  sdl_slen;       /* link layer selector length */
        char    sdl_data[12];   /* minimum work area, can be larger;
                                   contains both if name and ll address */
};

#define LLADDR(s) ((caddr_t)((s)->sdl_data + (s)->sdl_nlen))
#endif /* HAVE_SOCKADDR_DL */

#ifndef __SYSDEP_SA_LEN__
#define __SYSDEP_SA_LEN__
static __inline u_char
sysdep_sa_len (const struct sockaddr *sa)
{
#ifdef __linux__
  switch (sa->sa_family)
    {
    case AF_INET:
      return sizeof (struct sockaddr_in);
    case AF_INET6:
      return sizeof (struct sockaddr_in6);
    }
  return sizeof (struct sockaddr_in);
#else
  return sa->sa_len;
#endif
}
#endif /* __SYSDEP_SA_LEN__ */

#define HAVE_SIN_LEN 1
#ifdef __linux__
#	undef HAVE_SIN_LEN
#endif

/*
 * L2 forwarding table for the switched I/F
 */
struct l2_fwd {
	LIST_ENTRY(l2_fwd)   l2f_link;        /* mcast groups linkage          */
	struct sockaddr_dl   l2f_group;       /* mcast group with listeners    */
	u_int32_t            l2f_refcnt;      /* How many holders              */
	u_int32_t            l2f_used;        /* How many L3 holders           */
	u_int32_t            l2f_ports;       /* How many refs in L2 by ports  */
	port_set             l2f_oifs;        /* Outgoing ports                */
};

/*
 * L3 forwarding table for the switched I/F
 * This is aslo the list of reported groups for the interface
 */
struct mc_fwd {
	LIST_ENTRY(mc_fwd)   mcf_link;        /* mcast groups linkage          */
	union {
		struct sockaddr      u_sa;
		struct sockaddr_in   u_sin;
		struct sockaddr_in6  u_sin6;
	} mcf_u;
	u_int32_t            mcf_status;
	u_int32_t            mcf_mas_count;
	u_int32_t            mcf_mas_timer;
	u_int32_t            mcf_refcnt;      /* How many holders              */
	u_int32_t            mcf_ports;       /* How many refs in L3 by ports  */
	u_int32_t            mcf_timer;       /* Highest deadline on I/F       */
	struct l2_fwd       *mcf_l2f;         /* mcast group with listeners    */
	port_set             mcf_oifs;        /* Outgoing ports                */
};
#define mcf_sa   mcf_u.u_sa
#define mcf_sin  mcf_u.u_sin
#define mcf_sin6 mcf_u.u_sin6
LIST_HEAD(mcfhead, mc_fwd);

/*
 * L2 status by port
 */
struct l2_entry {
	LIST_ENTRY(l2_entry) l2_link;        /* mcast groups linkage          */
	struct l2_fwd       *l2_l2f;         /* mcast group with listeners    */
	u_int32_t            l2_refcnt;      /* How many holders              */
	u_int32_t            l2_used;        /* How many L3 holders           */
};

/*
 * L3 status, by port
 */
struct mc_entry {
	LIST_ENTRY(mc_entry) mc_link;        /* mcast groups linkage          */
	u_int32_t            mc_refcnt;      /* How many holders              */
	struct mc_fwd       *mc_mcf;         /* mcast group with listeners    */
	u_int32_t            mc_timer;       /* deadline                      */
	u_int32_t            mc_status;      /* Status from State Diagram     */
#define    MC_STATE_NO_LISTENERS 0
#define    MC_STATE_LISTENERS    1
#define    MC_STATE_CHECKING     2
	struct l2_entry     *mc_l2;         /* associated L2 mcast           */
};
LIST_HEAD(mchead, mc_entry);

struct eth_port {
	struct eth_if       *prt_if;         /* Backpointer to I/F            */
	u_int8_t            *prt_name;       /* Port name to display          */
	u_int8_t             prt_bnet_valid; /* Port validity in bridge       */
	u_int8_t             prt_spt_active; /* Port status for SPT           */
	u_int8_t             prt_stuff[2];
	u_int32_t            prt_index;      /* Port Number                   */
	u_int32_t            prt_rtr6_tmo;   /* Timer of mcast-v6 router      */
	u_int32_t            prt_rtr4_tmo;   /* Timer of mcast-v4 router      */
	LIST_HEAD(,mc_entry) prt_mld_head;   /* Detected IPv6 mcast listeners */
	LIST_HEAD(,mc_entry) prt_igmp_head;  /* Detected IPv4 mcast listeners */
	LIST_HEAD(,l2_entry) prt_l2_head;    /* Detected eth  mcast listeners */
};

struct querier_event {
	u_int32_t            qrr_timer;       /* Other querier deadline        */
	u_int32_t            qrr_myquery_ind; /* Self query indicator          */
	u_int8_t             qrr_stquery_cnt; /* Startup Query count           */
	u_int32_t            qrr_gq_timer;    /* Group Query deadline          */
};

struct proto_mc_param {
	/* Group Management */
	u_int32_t            pr_robust;
	u_int8_t             pr_version;                /* MLD version */
#define	PR_VERSION_UNKNOWN              0
#define	PR_VERSION_MLDv1                1
#define	PR_VERSION_MLDv2                2
#define	PR_VERSION_IGMPv1               1
#define	PR_VERSION_IGMPv2               2
#define	PR_VERSION_IGMPv3               3
	u_int32_t            pr_query_interv;           /* seconds */
	u_int32_t            pr_query_resp_interv;      /* ms      */
	u_int32_t            pr_query_last_interv;      /* ms      */
	u_int32_t            pr_query_startup_interv;   /* seconds */
#define	pr_query_startup_cnt		pr_robust
#define	pr_query_last_cnt			pr_robust

#ifdef __FAST_MLD_
#   define PR_ROBUST_DEFAULT            1
#   define PR_QUERY_INTERV_DEFAULT      20
#   define PR_QUERY_RESP_DEFAULT        2000
#   define PR_QUERY_LAST_DEFAULT        1000
#   define PR_QUERY_STARTUP_DEFAULT     5
#else
#   define PR_ROBUST_DEFAULT            2
#   define PR_QUERY_INTERV_DEFAULT      125
#   define PR_QUERY_RESP_DEFAULT        10000
#   define PR_QUERY_LAST_DEFAULT        1000
#   define PR_QUERY_STARTUP_DEFAULT     30
#endif

#define PR_LISTENER_INTERVAL(mcp) (((mcp)->pr_robust * \
		(mcp)->pr_query_interv * \
		TMO_SCALE) + \
		(mcp)->pr_query_resp_interv)
#define PR_LAST_LISTENER_QUERY_TIMER(mcp) ((mcp)->pr_query_last_cnt * \
     (mcp)->pr_query_last_interv)

	/* Querier Management */
	u_int8_t             pr_querier_candidature;
#define	PR_QUERIER_NONCANDIDATE         0
#define	PR_QUERIER_CANDIDATE            1
#define	PR_ROUTER_CANDIDATE            	2
	u_int8_t             pr_querier_status;
#define	PR_NONQUERIER                   0
#define	PR_QUERIER                      1
	u_int8_t             pr_querier_version; /* current querier version */
	u_int32_t            pr_querier_timeout; /* ms */
#define PR_OTHER_QUERIER_PRESENT_INTERVAL(mcp) (((mcp)->pr_robust * \
        (mcp)->pr_query_interv * \
		TMO_SCALE) + \
        ((mcp)->pr_query_resp_interv / 2))
#define PR_QUERIER_RANDOM_INTERVAL(mcp) (rand() % \
		((mcp)->pr_query_startup_interv * \
		TMO_SCALE))
	u_int8_t             pr_snooping;
	/* Statistics */
	u_int32_t            pr_recv_query;
	u_int32_t            pr_recv_report;
	u_int32_t            pr_recv_leave;
	u_int32_t            pr_sent_query;
};

/* The IPv4 address list for netlink usage */
struct if_addr {
	LIST_ENTRY(if_addr)   ifa_link;
	struct in_addr        ifa_addr;
	u_int8_t              ifa_mask_len;
};

/* The IPv6 address list for netlink usage */
struct if_addr6 {
	LIST_ENTRY(if_addr6)  ifa_link;
	struct in6_addr       ifa_addr;
	u_int8_t              ifa_mask_len;
};

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
struct eth_if {
	LIST_ENTRY(eth_if)    if_link;        /* I/F linkage                   */
	u_int8_t             *if_name;        /* ifname e.g. fxp0 ...          */
	u_int8_t             *if_ngname;      /* node name e.g. bridge_0: ...  */

	struct mc_proxy*      if_proxy;	      /* proxy we are part of	       */
	u_int8_t              if_l2_filter;   /* with L2 snoop ?               */
	u_int8_t              if_alen;        /* MAC address length            */
	u_int8_t              if_type;        /* type, ethernet ...            */
	u_int8_t              if_nbports;     /* Physical ports, min 1         */
	u_int8_t              if_port_names;  /* show names instead of ports # */
	u_int8_t              if_created;     /* if configured successfully    */
	u_int8_t              if_disabled;    /* if required to stop           */
	u_int8_t              if_down;        /* interface is down             */
	u_int8_t              if_started_igmp;/* if started for igmp           */
	u_int8_t              if_started_mld; /* if started for mld            */
	u_int8_t              if_stuff[3];

	u_int8_t              if_bridge;      /* 1 : bridge / 0 : interface    */

	u_int32_t             if_index;       /* System ifindex, useful ??     */

	u_int32_t             if_csock;       /* Netgraph node access          */
	u_int32_t             if_dsock;       /* Netgraph node access          */

	struct proto_mc_param if_mld_pr;      /* MLD parameters                */
	struct proto_mc_param if_igmp_pr;     /* IGMP parameters               */
	struct querier_event  if_mld_querier_ev; /* MLD querier event          */
	struct querier_event  if_igmp_querier_ev; /* IGMP querier event        */
	port_set              if_rtr4;
	port_set              if_rtr6;
	port_set              if_spy;
	LIST_HEAD(,l2_fwd)    if_l2_head;     /* Detected L2 mcast listeners   */
	LIST_HEAD(,mc_fwd)    if_mld_head;    /* Detected IPv6 mcast listeners */
	LIST_HEAD(,mc_fwd)    if_igmp_head;   /* Detected IPv4 mcast listeners */
	LIST_HEAD(,if_addr)   if_addr_head;   /* IPv4 addresses                */
	LIST_HEAD(,if_addr6)  if_addr6_head;  /* IPv6 addresses                */
	struct event         *if_cs_ev;       /* Control notification event    */
	struct event         *if_ds_ev;       /* Data notification event       */
	struct eth_port      *if_port;
};
LIST_HEAD(ifhead, eth_if);
extern struct ifhead ifnet;

/* main.c */
extern void fatal_exit(void);

/* core.c */
extern int report_received (struct eth_if *, struct eth_port *,
                            struct sockaddr *);
extern int specific_group_received (struct eth_if *, struct sockaddr *, int type);
extern void group_timers (void);
extern void querier_timers(void);

extern int l2f_trash;
extern int mcf_trash;
extern int l2_trash;
extern int mc_trash;

/* notify.c */
extern void notify_mac_change (struct eth_if *, struct eth_port *,
                               struct l2_fwd *, u_int32_t);
extern void notify_l3_change (struct eth_if *, struct eth_port *,
                               struct mc_fwd *, u_int32_t);
extern void notify_group_change (struct eth_if *,  struct mc_fwd *, u_int32_t);
extern void notify_port_list (u_int16_t, struct eth_if*);
# define NOTIFY_GROUP_ADD      1
# define NOTIFY_GROUP_CHANGE   2
# define NOTIFY_GROUP_DELETE   3
extern void notify_cs_snoopd (int, short, void *);
extern void notify_ds_snoopd (int, short, void *);


/* config.c */
extern int config (char *);
extern void stop_iface (struct eth_if *ifp, int keep, int flush);
extern void add_port (struct eth_if *ifp, int port_index);
extern void cancel_port (struct eth_if *ifp, int port_index);
extern struct eth_if * get_ifp_index (int ifindex);
extern struct eth_if * get_ifp (char *ifname);
extern void intend_start_iface (struct eth_if *ifp);


/* display.c */
extern char *display_notify (char *, u_int32_t);
extern char *display_sdl (char *, struct sockaddr_dl *);
extern char *display_sa (char *, struct sockaddr *);
extern char *display_plist (char *, port_set *, struct eth_if *ifp);
extern char *display_time (char *, u_int32_t, int);
extern char *sa_fmt  __P((struct sockaddr_in *sa));
extern char *sa6_fmt  __P((struct sockaddr_in6 *sa6));
extern char *inet6_fmt  __P((struct in6_addr *addr));
extern char *inet_fmt  __P((struct in_addr *addr));
extern char *ifindex2str    __P((int ifindex));


#define DMC_ALL            0xffff

#define DMC_IF             0x000f
#define DMC_IF_STATUS      0x0001
#define DMC_IF_L2          0x0002
#define DMC_IF_MLD         0x0004
#define DMC_IF_IGMP        0x0008

#define DMC_PRT            0x00f0
#define DMC_PRT_STATUS     0x0010
#define DMC_PRT_L2         0x0020
#define DMC_PRT_MLD        0x0040
#define DMC_PRT_IGMP       0x0080

extern void display_info (int fd, struct eth_if *, int, int, int);
extern void log_msg __P((int, int, char *, ...))
    __attribute__((__format__(__printf__, 3, 4)));


/* Netgraphn stuff */
#define NG_SOCK_HOOK_NAME	"hook"

#endif
