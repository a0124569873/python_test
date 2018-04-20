/*
 * Copyright 2004-2012 6WIND S.A.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <err.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>
#include <net/if.h>
#ifndef __linux__
#include <net/if_dl.h>
#endif
#include <net/ethernet.h>
#include <netgraph.h>
#include <sys/time.h>
#include <event.h>
#include <string.h>
#include <syslog.h>
#include "snoop.h"
#include "proxy.h"
#include "mld.h"
#include "netlink.h"

extern struct eth_if* get_ifp_index (int ifindex);

extern void display_console(int fd, const char *msg, ...);

/* Global lis of ifnets */
struct ifhead ifnet;

/* Global lis of proxies */
struct proxyhead all_proxies;

void
del_proxy_binding (struct mc_proxy *prx, struct eth_if *ifp);

int
get_port_for_ifp (struct eth_if *ifp, int portnum)
{
	int i;
	int portidx = -1;

	if (!ifp->if_created)
		return portidx;
	for (i = 0; i < ifp->if_nbports && portidx == -1; ++i) {
		if (ifp->if_port[i].prt_index == portnum) {
			portidx = i;
		}
	}
	return portidx;
}

struct eth_if *
get_ifp_index (int ifindex)
{
	struct eth_if *ifp = 0;
	LIST_FOREACH (ifp, &ifnet, if_link) {
		if (ifp->if_index == ifindex)
			break;
	}
	return (ifp);
}

static void
set_default_pr (struct proto_mc_param *pr)
{
	pr->pr_robust = PR_ROBUST_DEFAULT;
	pr->pr_query_interv = PR_QUERY_INTERV_DEFAULT;
	pr->pr_query_resp_interv = PR_QUERY_RESP_DEFAULT;
	pr->pr_query_last_interv = PR_QUERY_LAST_DEFAULT;
	pr->pr_query_startup_interv = PR_QUERY_STARTUP_DEFAULT;
	pr->pr_querier_candidature = PR_ROUTER_CANDIDATE;
	pr->pr_querier_status = PR_NONQUERIER;
	pr->pr_querier_timeout = PR_OTHER_QUERIER_PRESENT_INTERVAL(pr) + PR_QUERIER_RANDOM_INTERVAL(pr);
	return;
}


/*
 * Creates a new proxy, and process allocation stuff.
 */
static struct mc_proxy*
new_proxy (char *name, int *err)
{
	*err = 0;
	struct mc_proxy *p = calloc(sizeof(struct mc_proxy), 1);
	p->proxy_name = malloc(strlen(name));
	strcpy(p->proxy_name, name);
	p->proxy_started = 0;
	p->proxy_upstream = 0;
	LIST_INIT (&p->proxy_downstreams);

	LIST_INSERT_HEAD (&all_proxies, p, proxy_link);
	return p;
}

/*
 * Creates a new I/F, and process allocation stuff.
 * Link it to the lower level, without starting snooping
 */
static struct eth_if*
new_iface (char *name, char *ng_name, int *err, struct eth_if *eif)
{
	struct eth_if   *ifp = NULL;
	struct eth_port *port;
	int size, nports;
	int i, len;
	struct ngm_connect ngc;
	int csock, dsock;
	struct ng_bridge_snoop_msg nbsm;
	struct ng_bridge_snoop_msg *nbsrp;
	int bridge;
	union {
		u_int8_t buf[512];
		struct ng_mesg resp;
	} u;
	char raddr[NG_PATHLEN + 1];
	char path[NG_PATHLEN + 1];

	bridge = (ng_name != 0);
	if (!bridge)
		ng_name = "";

	if (eif)
		/* for re-creation case */
		ifp = eif;
	else {
		size = sizeof(*ifp);
		ifp = malloc (size);
		if (ifp == NULL) {
			*err = ENOMEM;
			goto null_iface;
		}
		memset (ifp, 0, size);
	}

	if (!ifp->if_name) {
		ifp->if_name = malloc (strlen(name)+1);
		if (ifp->if_name == NULL) {
			*err = ENOMEM;
			goto null_iface;
		}
		strcpy (ifp->if_name, name);
	}

	if (!ifp->if_ngname) {
		ifp->if_ngname = malloc (strlen(ng_name)+1);
		if (ifp->if_ngname == NULL) {
			*err = ENOMEM;
			goto null_iface;
		}
		strcpy (ifp->if_ngname, ng_name);
	}

	if (!eif)
		LIST_INSERT_HEAD (&ifnet, ifp, if_link);

	set_default_pr (&ifp->if_mld_pr);
	ifp->if_mld_pr.pr_version = PR_VERSION_MLDv2;
	ifp->if_mld_pr.pr_querier_version = PR_VERSION_UNKNOWN;
	set_default_pr (&ifp->if_igmp_pr);
	ifp->if_igmp_pr.pr_version = PR_VERSION_IGMPv3;
	ifp->if_igmp_pr.pr_querier_version = PR_VERSION_UNKNOWN;

	ifp->if_l2_filter = 1;
	/* Curently, only support eth I/F */
	ifp->if_alen = ETHER_ADDR_LEN;
	ifp->if_type = 0;
	LIST_INIT (&ifp->if_l2_head);
	LIST_INIT (&ifp->if_mld_head);
	LIST_INIT (&ifp->if_igmp_head);

	ifp->if_bridge = bridge;

	ifp->if_index = if_nametoindex(ifp->if_name);
	if (ifp->if_index == 0) {
		*err = EINVAL;
		goto bad_iface;
	}

	*err = 0;
	if (!bridge) {
		nports = 1;
		csock = dsock = 0;
		ng_name = "";
	} else {
		memset(&u, 0, sizeof(u));
		/*
		* Create sockets and connect to netgraph node
		*/
		if (NgMkSockNode(NULL, &csock, &dsock) < 0) {
			log_msg(LOG_NOTICE, errno,
					"new_iface: error in NgMkSockNode");
			*err = ENOTSOCK;
			goto bad_iface;
		}
		snprintf(ngc.path, sizeof(ngc.path), "%s:", ng_name);
		snprintf(ngc.ourhook, sizeof(ngc.ourhook), NG_SOCK_HOOK_NAME);
		snprintf(ngc.peerhook, sizeof(ngc.peerhook), "snoop");
		if (NgSendMsg(csock, ".", NGM_GENERIC_COOKIE, NGM_CONNECT, &ngc, sizeof(ngc)) < 0) {
			log_msg(LOG_NOTICE, errno,
					"new_iface: error in NgSendMsg for connection");
			*err = ENOTCONN;
			goto bad_iface;
		}
		/*
		* Then we should ask the node, the number of ports
		*/
		snprintf(path, sizeof(path), "%s:", ng_name);
		nbsm.nbs_cmd = GET_NUM_PORTS;
		nbsm.nbs_len = 0;
		if (NgSendMsg(csock, path, NGM_BRIDGE_COOKIE,
			NGM_BRIDGE_GET_SNOOP_CONFIG, &nbsm, sizeof(nbsm)) < 0) {
			log_msg(LOG_NOTICE, errno,
					"new_iface: error in NgSendMsg");
			goto bad_iface;
		}

		if ((len = NgRecvMsg(csock, &u.resp, sizeof(u), raddr)) < 0) {
			log_msg(LOG_NOTICE, errno,
				"new_iface: error in NgRecvMsg");
			*err = ENOTSOCK;
			goto bad_iface;
		}

		/*
		* Validate message length
		*/
		if (u.resp.header.arglen < sizeof(struct ng_bridge_snoop_msg)) {
			log_msg(LOG_NOTICE, 0, "new_iface: received too short message");
			*err = EINVAL;
			goto bad_iface;
		}
		nbsrp = (struct ng_bridge_snoop_msg *)u.resp.data;

		/* Validate snoop message payload length */
		if (u.resp.header.arglen <  (sizeof(struct ng_bridge_snoop_msg) + nbsrp->nbs_len)) {
			log_msg(LOG_NOTICE, 0, "new_iface: received message with too short payload");
			*err = EINVAL;
			goto bad_iface;
		}

		nports = nbsrp->nbs_port;
	}

	size = nports*sizeof(*port);
	ifp->if_port = malloc(size);
	if (ifp->if_port == NULL) {
		*err = ENOMEM;
		goto bad_iface;
	}
	ifp->if_nbports = (u_int8_t)nports;
	memset (ifp->if_port, 0, size);
	ifp->if_csock = csock;
	ifp->if_dsock = dsock;
	ifp->if_proxy = NULL;

	ifp->if_cs_ev = malloc(sizeof (struct event));
	if (ifp->if_cs_ev == NULL) {
		*err = ENOMEM;
		goto bad_iface;
	}

	ifp->if_ds_ev = malloc(sizeof (struct event));
	if (ifp->if_ds_ev == NULL) {
		*err = ENOMEM;
		goto bad_iface;
	}
	for (i=0 ; i<nports ;  i++) {
		port = &(ifp->if_port[i]);
		port->prt_if = ifp;
		port->prt_name = NULL;
		port->prt_index = i;
		port->prt_bnet_valid = 1;
		port->prt_spt_active = 1;
		LIST_INIT(&port->prt_l2_head);
		LIST_INIT(&port->prt_mld_head);
		LIST_INIT(&port->prt_igmp_head);
	}
	if (bridge) {
		/* Ask to the netgraph node the names of the hooks to get the port indexes */
		u_char rbuf[16 * 1024];
		struct ng_mesg *const resp = (struct ng_mesg *) rbuf;
		struct hooklist *const hlist = (struct hooklist *) resp->data;
		struct nodeinfo *const ninfo = &hlist->nodeinfo;
		int no_hooks = 0;

		/* Get node info and hook list */
		if (NgSendMsg(csock, path, NGM_GENERIC_COOKIE, NGM_LISTHOOKS, NULL, 0) < 0) {
			log_msg(LOG_NOTICE, errno, "new_iface: error in NgSendMsg");
			goto bad_iface;
		}
		if (NgRecvMsg(csock, resp, sizeof(rbuf), NULL) < 0) {
			log_msg(LOG_NOTICE, errno, "new_iface: error in NgRecvMsg");
			*err = ENOTSOCK;
			goto bad_iface;
		}
                for (i = 0; i < ninfo->hooks; i++) {
                        struct linkinfo *const link = &hlist->link[i];
			int linkNum = -1;
			if (sscanf(link->ourhook, "link%u", &linkNum) == 1) {
				ifp->if_port[no_hooks++].prt_index = linkNum;
			}
                }
	}
	ifp->if_created = 1;
	config_ifaddr_from_kernel (ifp);
	return (ifp);

bad_iface:
	if (csock)
		close (csock);
	if (dsock)
		close (dsock);
	if (ifp->if_cs_ev)
		free (ifp->if_cs_ev);
	if (ifp->if_ds_ev)
		free (ifp->if_ds_ev);
	if (ifp->if_port)
		free (ifp->if_port);

	ifp->if_csock = 0;
	ifp->if_dsock = 0;
	ifp->if_cs_ev = NULL;
	ifp->if_ds_ev = NULL;
	ifp->if_port = NULL;
	ifp->if_nbports = 0;
	/* keep the name/ng_name for re-creation */
	return (ifp);

null_iface:
	if (ifp) {
		if (ifp->if_name)
			free (ifp->if_name);
		if (ifp->if_ngname)
			free (ifp->if_ngname);
		free (ifp);
	}
	return (NULL);
}

/*
 * Stop activity on a specific proxy, and clean
 * any associated data
 */
void
stop_proxy (struct mc_proxy *prx, int keep, int flush)
{
	prx->proxy_started = 0;
	proxy_disable(prx);
	if (keep == 0) {
		if (prx->proxy_upstream) {
			prx->proxy_upstream->if_proxy = 0;
		}

		struct mc_proxy_binding   *binding = NULL;
		for (binding = LIST_FIRST(&prx->proxy_downstreams) ; binding != NULL ; ) {
			struct mc_proxy_binding *p;
			p = binding;
			binding = LIST_NEXT(binding, binding_link);
			free (p);
		}
		LIST_INIT (&prx->proxy_downstreams);

		LIST_REMOVE (prx, proxy_link);
		free (prx);
	}
}

/*
 * Stop activity on a specific interface, and clean
 * any associated data (in daemon AND in Kernel)
 */
void
stop_iface (struct eth_if *ifp, int keep, int flush)
{
	struct l2_fwd *l2f;
	struct mc_fwd *mcf;
	int i;

	log_msg (LOG_DEBUG, 0, "stop_iface: stopping %s", ifp->if_name);

	if (ifp->if_bridge) {
		if (ifp->if_cs_ev)
			event_del (ifp->if_cs_ev);
		if (ifp->if_ds_ev)
			event_del (ifp->if_ds_ev);
		if (!keep) {
			/*
			 * Unregister and flush data from Kernel
			 * Best way is to close those sockets.
			 */
			if (ifp->if_csock)
				close (ifp->if_csock);
			if (ifp->if_dsock)
				close (ifp->if_dsock);
		} else {
			/*
			 * Desactivate IGMP/MLD snooping
			 */
			struct ng_bridge_snoop_msg msg;
			char path[NG_PATHLEN + 1];

			snprintf(path, sizeof(path), "%s:", ifp->if_ngname);
			msg.nbs_len = 0;
			if (ifp->if_started_mld) {
				msg.nbs_cmd = STOP_MLD_SNOOPING;
				if (NgSendMsg(ifp->if_csock, path, NGM_BRIDGE_COOKIE,
					NGM_BRIDGE_SET_SNOOP_CONFIG, &msg, sizeof(msg)) < 0)
					log_msg(LOG_NOTICE, errno, "stop_iface: error in NgSendMsg");
			}
			if (ifp->if_started_igmp) {
				msg.nbs_cmd = STOP_IGMP_SNOOPING;
				if (NgSendMsg(ifp->if_csock, path, NGM_BRIDGE_COOKIE,
					NGM_BRIDGE_SET_SNOOP_CONFIG, &msg, sizeof(msg)) < 0)
					log_msg(LOG_NOTICE, errno, "stop_iface: error in NgSendMsg");
			}
		}
	} else {
		/* Leaving the routers group */
		if (ifp->if_started_mld)
			mld_join_routers_group(ifp->if_index, 0);
		if (ifp->if_started_igmp)
			igmp_join_routers_group(ifp->if_index, 0);
	}

	/*
	 * I/F is now INACTIVE
	 */
	ifp->if_started_igmp = 0;
	ifp->if_started_mld = 0;

	/*
	 * Withdraw Querier responsibility
	 */
	ifp->if_mld_pr.pr_querier_status = PR_NONQUERIER;
	ifp->if_mld_pr.pr_querier_version = PR_VERSION_UNKNOWN;
	ifp->if_mld_querier_ev.qrr_timer = TMO_INFINITE;
	ifp->if_igmp_pr.pr_querier_status = PR_NONQUERIER;
	ifp->if_igmp_pr.pr_querier_version = PR_VERSION_UNKNOWN;
	ifp->if_igmp_querier_ev.qrr_timer = TMO_INFINITE;
	/*
	 * Flush daemon internal
	 */
	for (l2f = LIST_FIRST(&ifp->if_l2_head) ; l2f != NULL ; ) {
		struct l2_fwd *p;
		p = l2f;
		l2f = LIST_NEXT(l2f, l2f_link);
		free (p);
	}
	LIST_INIT (&ifp->if_l2_head);
	for (mcf = LIST_FIRST(&ifp->if_mld_head) ; mcf != NULL ; ) {
		struct mc_fwd *p;
		p = mcf;
		mcf = LIST_NEXT(mcf, mcf_link);
		free (p);
	}
	LIST_INIT (&ifp->if_mld_head);
	for (mcf = LIST_FIRST(&ifp->if_igmp_head) ; mcf != NULL ; ) {
		struct mc_fwd *p;
		p = mcf;
		mcf = LIST_NEXT(mcf, mcf_link);
		free (p);
	}
	LIST_INIT (&ifp->if_igmp_head);
	for (i=0 ; i < ifp->if_nbports ; i++) {
		struct eth_port *prt = &(ifp->if_port[i]);
		struct l2_entry *l2;
		struct mc_entry *mc;

		if ( prt->prt_name ) {
			free (prt->prt_name);
			prt->prt_name = NULL;
		}

		if (prt->prt_rtr6_tmo  != TMO_INFINITE)
			PORT_CLR (i, &ifp->if_rtr6);
		if (prt->prt_rtr4_tmo  != TMO_INFINITE)
			PORT_CLR (i, &ifp->if_rtr4);

		for (l2 = LIST_FIRST(&prt->prt_l2_head) ; l2 != NULL ; ) {
			struct l2_entry *p;
			p = l2;
			l2 = LIST_NEXT(l2, l2_link);
			free (p);
		}
		LIST_INIT(&prt->prt_l2_head);
		for (mc = LIST_FIRST(&prt->prt_mld_head) ; mc != NULL ; ) {
			struct mc_entry *p;
			p = mc;
			mc = LIST_NEXT(mc, mc_link);
			free (p);
		}
		LIST_INIT(&prt->prt_mld_head);
		for (mc = LIST_FIRST(&prt->prt_igmp_head) ; mc != NULL ; ) {
			struct mc_entry *p;
			p = mc;
			mc = LIST_NEXT(mc, mc_link);
			free (p);
		}
		LIST_INIT(&prt->prt_igmp_head);
	}


	if (flush) {
		bzero (&ifp->if_rtr6, sizeof(port_set));
		bzero (&ifp->if_rtr4, sizeof(port_set));
		bzero (&ifp->if_spy, sizeof(port_set));
		set_default_pr (&ifp->if_mld_pr);
		ifp->if_mld_pr.pr_version = PR_VERSION_MLDv2;
		ifp->if_mld_pr.pr_snooping = 0;
		set_default_pr (&ifp->if_igmp_pr);
		ifp->if_igmp_pr.pr_version = PR_VERSION_IGMPv3;
		ifp->if_igmp_pr.pr_snooping = 0;
	}

	/*
	 * If we keep the interface, the shoud re-open
	 * the sockets and set events
	 */
	if (keep) {
		/* nothing special to do */
	}
	/*
	 * OK, even remove the iface structure !!
	 */
	else {
		/* remove the iface from the proxy it belongs to */
		if (ifp->if_proxy)
			del_proxy_binding(ifp->if_proxy, ifp);
		LIST_REMOVE (ifp, if_link);
		free (ifp->if_port);
		clear_ifaddr (ifp);
		clear_ifaddr6 (ifp);
		free (ifp);
	}
	return;
}

static void
start_proxy (struct mc_proxy *prx)
{
	proxy_enable(prx);
	prx->proxy_started = 1;
}

static void
start_iface (struct eth_if *ifp, int start_igmp, int start_mld)
{
	struct ng_bridge_snoop_msg msg;
	char path[NG_PATHLEN + 1];

	if (ifp->if_started_igmp || ifp->if_started_mld)
		stop_iface (ifp, 1, 0);

	log_msg (LOG_DEBUG, 0, "start_iface: starting %s for%s%s", ifp->if_name,
		(start_igmp) ? " igmp" : " ",
		(start_mld) ? " mld" : " ");

	if (ifp->if_bridge) {
		/*
		 * Now activate IGMP/MLD snooping
		 */
		snprintf(path, sizeof(path), "%s:", ifp->if_ngname);

		if (start_mld) {
			notify_port_list (SET_MLD_ROUTERS, ifp);
			if (ifp->if_mld_pr.pr_snooping)
				msg.nbs_cmd = START_MLD_SNOOPING;
			else
				msg.nbs_cmd = STOP_MLD_SNOOPING;
			msg.nbs_len = 0;
			if (NgSendMsg(ifp->if_csock, path, NGM_BRIDGE_COOKIE,
				NGM_BRIDGE_SET_SNOOP_CONFIG, &msg, sizeof(msg)) < 0)
				log_msg(LOG_NOTICE, errno,
					"start_iface: error in NgSendMsg");
		}

		if (start_igmp) {
			notify_port_list (SET_IGMP_ROUTERS, ifp);
			if (ifp->if_igmp_pr.pr_snooping)
				msg.nbs_cmd = START_IGMP_SNOOPING;
			else
				msg.nbs_cmd = STOP_IGMP_SNOOPING;
			if (NgSendMsg(ifp->if_csock, path, NGM_BRIDGE_COOKIE,
				NGM_BRIDGE_SET_SNOOP_CONFIG, &msg, sizeof(msg)) < 0) {
				log_msg(LOG_NOTICE, errno,
						"start_iface: error in NgSendMsg");
			}
		}

		notify_port_list (SET_SPY_PORTS, ifp);
	}

	/*
	 * and finally register inputs from the node
	 */
	if (ifp->if_bridge) {
		event_set (ifp->if_cs_ev, ifp->if_csock,
			   EV_READ | EV_PERSIST, notify_cs_snoopd, ifp);
		event_add (ifp->if_cs_ev, NULL);
		event_set (ifp->if_ds_ev, ifp->if_dsock,
			   EV_READ | EV_PERSIST, notify_ds_snoopd, ifp);
		event_add (ifp->if_ds_ev, NULL);
	} else {
                if (ifp->if_mld_pr.pr_snooping && start_mld)
			mld_join_routers_group(ifp->if_index, 1);
                if (ifp->if_igmp_pr.pr_snooping && start_igmp)
			igmp_join_routers_group(ifp->if_index, 1);
	}

	/* Initialize querier event params */
	if (start_mld)
		if (ifp->if_mld_pr.pr_querier_candidature == PR_QUERIER_CANDIDATE ||
			ifp->if_mld_pr.pr_querier_candidature == PR_ROUTER_CANDIDATE)
			ifp->if_mld_querier_ev.qrr_timer = compute_deadline(1);
	if (start_igmp)
		if (ifp->if_igmp_pr.pr_querier_candidature == PR_QUERIER_CANDIDATE ||
			ifp->if_igmp_pr.pr_querier_candidature == PR_ROUTER_CANDIDATE)
			ifp->if_igmp_querier_ev.qrr_timer = compute_deadline(1);

	if (start_igmp)
		ifp->if_started_igmp = 1;
	if (start_mld)
		ifp->if_started_mld = 1;

	return;
}

void
intend_start_iface (struct eth_if *ifp)
{
	int start_igmp = 0;
	int start_mld = 0;
	int err = 0;

	log_msg (LOG_DEBUG, 0, "intend_start_iface: prepare to start %s",
			ifp->if_name);

	/*
	 * If the iface is not ready yet, create it first
	 */
	if (!ifp->if_created)
		new_iface (	ifp->if_name,
					(ifp->if_bridge) ? ifp->if_ngname : NULL,
					&err, ifp);
	if (!ifp->if_created) {
		/* we still can not create it */
		log_msg (LOG_WARNING, 0, "intend_start_iface: failed to re-create %s",
				ifp->if_name);
		return;
	}

	if (!ifp->if_down && !ifp->if_disabled) {
		if (!LIST_EMPTY(&ifp->if_addr_head))
			start_igmp = 1;
		if (!LIST_EMPTY(&ifp->if_addr6_head))
			start_mld = 1;
	}

	if (!start_igmp && !start_mld) {
		if (ifp->if_started_igmp || ifp->if_started_mld)
			stop_iface (ifp, 1, 0);
	}
	else {
		if (start_igmp != ifp->if_started_igmp ||
			start_mld != ifp->if_started_mld)
			start_iface (ifp, start_igmp, start_mld);
	}

	return;
}

void
add_proxy_binding (struct mc_proxy *prx, struct eth_if *ifp, int upstream)
{
	if (upstream) {
		prx->proxy_upstream = ifp;

	} else {
		struct mc_proxy_binding *binding = calloc(sizeof(struct mc_proxy_binding), 1);
		binding->interface = ifp;
		LIST_INSERT_HEAD (&prx->proxy_downstreams, binding, binding_link);
	}
	ifp->if_proxy = prx;
}

void
del_proxy_binding (struct mc_proxy *prx, struct eth_if *ifp)
{
	if (prx->proxy_upstream == ifp) {
		prx->proxy_upstream = NULL;
	} else {
		struct mc_proxy_binding   *binding = NULL;
		for (binding = LIST_FIRST(&prx->proxy_downstreams) ; binding != NULL ; ) {
			struct mc_proxy_binding *p;
			p = binding;
			binding = LIST_NEXT(binding, binding_link);
			if (p->interface == ifp) {
				LIST_REMOVE(p, binding_link);
				free (p);
			}
		}
	}
	ifp->if_proxy = 0;
}

void
add_port (struct eth_if *ifp, int port_index)
{
	struct eth_port *port = NULL;
        int portidx = get_port_for_ifp(ifp, port_index);


	/* Check if port belongs to previously used link */
	if (portidx >= 0) {
		port = &(ifp->if_port[portidx]);
	}
	else {
		/* Create a new port */
		ifp->if_port = realloc(ifp->if_port, (ifp->if_nbports+1) * sizeof(struct eth_port));
		port = ifp->if_port+ifp->if_nbports;
		ifp->if_nbports++;
		log_msg(LOG_INFO, 0, "add_port: new port %d added", port_index);
	}
	if (port != NULL) {
		log_msg(LOG_INFO, 0, "add_port: port %d added", port_index);
		port->prt_name = NULL;
		port->prt_index = port_index;
		port->prt_if = ifp;
		port->prt_bnet_valid = 1;
		LIST_INIT(&port->prt_l2_head);
		LIST_INIT(&port->prt_mld_head);
		LIST_INIT(&port->prt_igmp_head);
	}
}

void
cancel_port (struct eth_if *ifp, int port_index)
{
	struct eth_port *port = NULL;
        int portidx = get_port_for_ifp(ifp, port_index);

	/* Check if port index is valid */
	if (portidx >= 0) {
		port = &(ifp->if_port[portidx]);
	} else {
		/* Invalid port index */
		log_msg(LOG_WARNING, 0,
				"cancel_port: invalid port %d reported", port_index);
		return;
	}
	if (port != NULL) {
		log_msg(LOG_INFO, 0,
				"cancel_port: port %d marked as invalid", port_index);
		port->prt_bnet_valid = 0;
		LIST_INIT(&port->prt_l2_head);
		LIST_INIT(&port->prt_mld_head);
		LIST_INIT(&port->prt_igmp_head);
	}
}

struct eth_if *
get_ifp (char *ifname)
{
	struct eth_if *ifp = 0;
	LIST_FOREACH (ifp, &ifnet, if_link) {
		if (strcmp (ifp->if_name, ifname) == 0)
			break;
	}
	return (ifp);
}

static struct mc_proxy *
get_proxy (char *name)
{
	struct mc_proxy *prx = 0;
	LIST_FOREACH (prx, &all_proxies, proxy_link) {
		if (strcmp (prx->proxy_name, name) == 0)
			break;
	}
	return (prx);
}

static void
add_map(const char* itf, const char* num, const char* portname, const char* encap_type)
{
	struct eth_if   *ifp;
	struct eth_port *ifport;
	int port_num;
	char buf[128];

	/* create port name to display */
	snprintf(buf, sizeof(buf), "%s (%s)", portname, encap_type);

	LIST_FOREACH (ifp, &ifnet, if_link) {
		if (strcmp (ifp->if_name, itf) == 0)
			break;
	}

	if (!ifp)
		return;

	port_num = get_port_for_ifp(ifp, atoi(num));
	if ( port_num < 0 )
		return;

	ifp->if_port_names = 1;
	ifport = &(ifp->if_port[port_num]);
	if ( ifport->prt_name )
		free (ifport->prt_name);
	ifport->prt_name = strdup(buf);
}

static void
del_map()
{
	struct eth_if   *ifp;
	struct eth_port *ifport;
	int i;

	LIST_FOREACH (ifp, &ifnet, if_link) {
		ifp->if_port_names = 0;
		for (i=0; i < ifp->if_nbports; i++) {
			ifport = &(ifp->if_port[i]);
			if ( ifport->prt_name ) {
				free ( ifport->prt_name );
				ifport->prt_name = NULL;
			}
		}
	}
}

struct _parsed {
	char *word;
	int  keyword;
};

#define MAX_WORDS 50
struct _parsed parsed_line [MAX_WORDS];
int nb_words;
enum {
	K_NEW = 1,
	K_START,
	K_STOP,
	K_DELETE,
	K_SET,
	K_MLD,
	K_IGMP,
	K_PORT,
	K_SNOOP,
	K_NOSNOOP,
	K_FORCE,
	K_NOFORCE,
	K_SPY,
	K_NOSPY,
	K_SHOW,
	K_ALL,
	K_FLUSH,
	K_DETAIL,
	K_QUERIER,
	K_NOQUERIER,
	K_ROUTER,
	K_BRIDGE,
	K_STANDALONE,
	K_QUERYINTERVAL,
	K_LASTQUERYINTERVAL,
	K_QUERYRESPINTERVAL,
	K_ROBUST,
	K_PROXY,
	K_BIND,
	K_UNBIND,
	K_NOMLD,
	K_NOIGMP,
	K_UPSTREAM,
	K_MAP,
	K_UNMAP,
	K_LAST
};

void
parse (char *line)
{
	struct _parsed *ap;
	char *pc;
	/*
	 * Removes all comments
	 */
	pc = strchr(line, ';');
	if (pc)
		*pc = 0;

	/*
	 * splits into words
	 */
	nb_words = 0;
	for (ap = parsed_line ; (ap->word = strsep(&line, " \t\n")) != NULL ; ) {
		if (*ap->word != '\0') {
			/* we could probably have some thing more efficient here.. */
			if (strcmp (ap->word, "new") == 0)
				ap->keyword = K_NEW;
			else if (strcmp (ap->word, "start") == 0)
				ap->keyword = K_START;
			else if (strcmp (ap->word, "stop") == 0)
				ap->keyword = K_STOP;
			else if (strcmp (ap->word, "delete") == 0)
				ap->keyword = K_DELETE;
			else if (strcmp (ap->word, "set") == 0)
				ap->keyword = K_SET;
			else if (strcmp (ap->word, "mld") == 0)
				ap->keyword = K_MLD;
			else if (strcmp (ap->word, "igmp") == 0)
				ap->keyword = K_IGMP;
			else if (strcmp (ap->word, "port") == 0)
				ap->keyword = K_PORT;
			else if (strcmp (ap->word, "snoop") == 0)
				ap->keyword = K_SNOOP;
			else if (strcmp (ap->word, "nosnoop") == 0)
				ap->keyword = K_NOSNOOP;
			else if (strcmp (ap->word, "force") == 0)
				ap->keyword = K_FORCE;
			else if (strcmp (ap->word, "noforce") == 0)
				ap->keyword = K_NOFORCE;
			else if (strcmp (ap->word, "spy") == 0)
				ap->keyword = K_SPY;
			else if (strcmp (ap->word, "nospy") == 0)
				ap->keyword = K_NOSPY;
			else if (strcmp (ap->word, "show") == 0)
				ap->keyword = K_SHOW;
			else if (strcmp (ap->word, "all") == 0)
				ap->keyword = K_ALL;
			else if (strcmp (ap->word, "flush") == 0)
				ap->keyword = K_FLUSH;
			else if (strcmp (ap->word, "details") == 0)
				ap->keyword = K_DETAIL;
			else if (strcmp (ap->word, "detail") == 0)
				ap->keyword = K_DETAIL;
			else if (strcmp (ap->word, "querier") == 0)
				ap->keyword = K_QUERIER;
			else if (strcmp (ap->word, "noquerier") == 0)
				ap->keyword = K_NOQUERIER;
			else if (strcmp (ap->word, "router") == 0)
				ap->keyword = K_ROUTER;
			else if (strcmp (ap->word, "bridge") == 0)
				ap->keyword = K_BRIDGE;
			else if (strcmp (ap->word, "stand-alone") == 0)
				ap->keyword = K_STANDALONE;
			else if (strcmp (ap->word, "robust") == 0)
				ap->keyword = K_ROBUST;
			else if (strcmp (ap->word, "query-interval") == 0)
				ap->keyword = K_QUERYINTERVAL;
			else if (strcmp (ap->word, "last-query-interval") == 0)
				ap->keyword = K_LASTQUERYINTERVAL;
			else if (strcmp (ap->word, "query-response-interval") == 0)
				ap->keyword = K_QUERYRESPINTERVAL;
			else if (strcmp (ap->word, "proxy") == 0)
				ap->keyword = K_PROXY;
			else if (strcmp (ap->word, "bind") == 0)
				ap->keyword = K_BIND;
			else if (strcmp (ap->word, "unbind") == 0)
				ap->keyword = K_UNBIND;
			else if (strcmp (ap->word, "nomld") == 0)
				ap->keyword = K_NOMLD;
			else if (strcmp (ap->word, "noigmp") == 0)
				ap->keyword = K_NOIGMP;
			else if (strcmp (ap->word, "upstream") == 0)
				ap->keyword = K_UPSTREAM;
			else if (strcmp (ap->word, "map") == 0)
				ap->keyword = K_MAP;
			else if (strcmp (ap->word, "unmap") == 0)
				ap->keyword = K_UNMAP;
			else
				ap->keyword = 0;

			if (++ap >= &parsed_line[MAX_WORDS])
				break;
			nb_words++;
		}
	}
	return;
}

/* Configuration for "snooping" options */
static void do_config_snooping (int nline, int fd)
{
	struct eth_if *ifp;
	struct proto_mc_param *pr;
	struct querier_event *qep;
	int err=0;
	char *unknown;
	int port=0;
	int portidx=0;
	struct eth_port *prt;

	if (nb_words < 1)
		return;

	if (nb_words >= 2) {
		ifp = get_ifp (parsed_line[1].word);
		if (parsed_line[0].keyword &&
		(parsed_line[0].keyword != K_NEW) &&
		(parsed_line[0].keyword != K_SHOW) &&
		ifp == NULL) {
			display_console (fd, "unknown interface %s in line #%d\n",
				parsed_line[1].word, nline);
			return;
		}
	}
	switch (parsed_line[0].keyword) {
	case K_NEW: {
		/* new bridge bnetX <vnb name> */
		/* new stand-alone ethX */

		if (nb_words < 3)
			goto incor_wn;
		ifp = get_ifp (parsed_line[2].word);
		if (ifp) {
			display_console(fd, "interface %s already exists (line #)%d\n",
		         parsed_line[2].word, nline);
			return;
		}
		switch (parsed_line[1].keyword) {
			case K_BRIDGE:
				if (nb_words != 4)
					goto incor_wn;
				ifp = new_iface (parsed_line[2].word, parsed_line[3].word, &err, NULL);
				break;
			case K_STANDALONE:
				if (nb_words != 3)
					goto incor_wn;
				ifp = new_iface (parsed_line[2].word, 0, &err, NULL);
				break;
			default:
				goto cmd_failed;
		}
		if (ifp == NULL)
			goto cmd_failed;
	}
		break;
	case K_START:
		/* start <itf name> */
		if (nb_words != 2)
			goto incor_wn;
		ifp->if_disabled = 0;
		intend_start_iface(ifp);
		break;
	case K_SET: {
		if (nb_words < 4)
			goto incor_wn;

		switch (parsed_line[2].keyword) {
		case K_MLD:
		case K_IGMP: {
			int param = 3;
			int params_left = nb_words - param;
			int mld = (parsed_line[2].keyword == K_MLD);

			if (mld) {
				pr = &ifp->if_mld_pr;
				qep = &ifp->if_mld_querier_ev;
			} else {
				pr = &ifp->if_igmp_pr;
				qep = &ifp->if_igmp_querier_ev;
			}

			/* Parsing all "set intf mld|igmp xxx" parameters */
			while (params_left > 0) {
				params_left--;
			switch (parsed_line[param].keyword) {
			case K_QUERYINTERVAL:
				if (params_left) {
					pr->pr_query_interv = atoi(parsed_line[++param].word);
					pr->pr_query_startup_interv = pr->pr_query_interv/4;
					pr->pr_querier_timeout = PR_OTHER_QUERIER_PRESENT_INTERVAL(pr) + PR_QUERIER_RANDOM_INTERVAL(pr);
					params_left--;
				} else {
					goto incor_wn;
				}
				break;
			case K_LASTQUERYINTERVAL:
				if (params_left) {
					pr->pr_query_last_interv = atoi(parsed_line[++param].word);
					pr->pr_querier_timeout = PR_OTHER_QUERIER_PRESENT_INTERVAL(pr) + PR_QUERIER_RANDOM_INTERVAL(pr);
					params_left--;
				} else {
					goto incor_wn;
				}
				break;
			case K_QUERYRESPINTERVAL:
				if (params_left) {
					pr->pr_query_resp_interv = atoi(parsed_line[++param].word);
					pr->pr_querier_timeout = PR_OTHER_QUERIER_PRESENT_INTERVAL(pr) + PR_QUERIER_RANDOM_INTERVAL(pr);
					params_left--;
				} else {
					goto incor_wn;
				}
				break;
			case K_ROBUST:
				if (params_left) {
					pr->pr_robust = atoi(parsed_line[++param].word);
					pr->pr_querier_timeout = PR_OTHER_QUERIER_PRESENT_INTERVAL(pr) + PR_QUERIER_RANDOM_INTERVAL(pr);
					params_left--;
				} else {
					goto incor_wn;
				}
				break;
			case K_SNOOP:
				pr->pr_snooping = 1;
				break;
			case K_NOSNOOP:
				pr->pr_snooping = 0;
				break;
			case K_QUERIER:
				pr->pr_querier_candidature = PR_QUERIER_CANDIDATE;
				qep->qrr_timer = compute_deadline(1);
				break;
			case K_NOQUERIER:
				pr->pr_querier_candidature = PR_QUERIER_NONCANDIDATE;
				break;
			case K_ROUTER:
				pr->pr_querier_candidature = PR_ROUTER_CANDIDATE;
				qep->qrr_timer = compute_deadline(1);
				break;
			case K_PORT:
				if (!ifp->if_bridge)
					goto cmd_failed;
				if (params_left < 2)
					goto incor_wn;
				/* skipping the 'port' keyword and port number */
				params_left -= 2;
				port = atoi(parsed_line[++param].word);
				portidx = get_port_for_ifp(ifp, port);

				if (portidx < 0 || portidx >= ifp->if_nbports) {
					display_console(fd,
						 "interface %s, port %d not found in line #%d\n",
						 ifp->if_name, atoi(parsed_line[++param].word), nline);
					return;
				}
				prt = &ifp->if_port[portidx];
				switch (parsed_line[++param].keyword) {
					case K_SPY:
						PORT_SET (port, &ifp->if_spy);
						notify_port_list (SET_SPY_PORTS, ifp);
						break;
					case K_NOSPY:
						PORT_CLR (port, &ifp->if_spy);
						notify_port_list (SET_SPY_PORTS, ifp);
						break;
					case K_FORCE:
						if (mld) {
							prt->prt_rtr6_tmo = TMO_INFINITE;
							PORT_SET(port, &ifp->if_rtr6);
						} else {
							prt->prt_rtr4_tmo = TMO_INFINITE;
							PORT_SET(port, &ifp->if_rtr4);
						}
						break;
					case K_NOFORCE:
						if (mld) {
							prt->prt_rtr6_tmo = 0;
							PORT_CLR(port, &ifp->if_rtr6);
						} else {
							prt->prt_rtr4_tmo = 0;
							PORT_CLR(port, &ifp->if_rtr4);
						}
						break;
					default:
						unknown = parsed_line[param].word;
						goto unknown_word;
						break;
				}
				break;
			default:
				unknown = parsed_line[param].word;
				goto unknown_word;
				break;
			}
				param++;
			}
			break;
		}
		default:
			unknown = parsed_line[2].word;
			goto unknown_word;
		}
		break;
		}
	case K_STOP:
		/* stop <itf name> */
		if (nb_words != 2)
			goto incor_wn;
		ifp->if_disabled = 1;
		stop_iface(ifp, 1, 0);
		break;
	case K_DELETE:
		/* delete <itf name> */
		if (nb_words != 2)
			goto incor_wn;
		stop_iface(ifp, 0, 0);
		break;
	case K_FLUSH:
		/* flush <itf name> */
		if (nb_words != 2)
			goto incor_wn;
		stop_iface(ifp, 0, 1);
		break;
	case K_MAP:
		/* map <itf name> <port number> <itf name> <encap type> */
		if (nb_words != 5)
			goto incor_wn;

		add_map(parsed_line[1].word, parsed_line[2].word, parsed_line[3].word, parsed_line[4].word);
		break;
	case K_UNMAP:
		if (nb_words != 1)
			goto incor_wn;

		del_map();
		break;
	case K_SHOW: {
		/* show <itf name>|all {mld|igmp|details} */
		int flags = DMC_IF_STATUS;
		if (nb_words != 2 && nb_words != 3)
			goto incor_wn;

		if (nb_words >= 2) {
			if (parsed_line[1].keyword != K_ALL && !ifp) {
				display_console(fd, "show unknown interface %s\n",
				         parsed_line[1].word);
				return;
			}
		}
		if (nb_words >= 3) {
			switch (parsed_line[2].keyword) {
			case K_DETAIL:
				flags = DMC_ALL;
				break;
			case K_IGMP:
				flags |= DMC_IF_IGMP;
				break;
			case K_MLD:
				flags |= DMC_IF_MLD;
				break;
			default:
				unknown = parsed_line[2].word;
				goto unknown_word;
			}
		}
		display_info (fd, ifp, -1, flags, 0);
		}
		break;
	default:
		unknown = parsed_line[0].word;
		goto unknown_word;
	}
	return;
unknown_word:
	display_console(fd, "unknown/unexpected word <<%s>> in line #%d\n",
	         unknown, nline);
	return;
incor_wn:
	display_console(fd, "incorrect argument number for cmd %s in line #%d\n",
	         parsed_line[0].word, nline);
	return;
cmd_failed:
	display_console(fd, "command %s in line #%d failed\n",
	         parsed_line[0].word, nline);
	return;
}

/* Configuration for "proxy" options */
static void do_config_proxy (int nline, int fd)
{
	struct mc_proxy *prx = 0;
	int err=0;
	char *unknown;
	int port=0;
	struct eth_port *prt;
	struct eth_if *ifp = 0;
	int i;

	if (nb_words < 1)
		return;

	/* Remove the PROXY keyword */
	for (i = 1; i < nb_words-1; ++i) {
		parsed_line[i].word = parsed_line[i+1].word;
		parsed_line[i].keyword = parsed_line[i+1].keyword;
	}
	nb_words--;

	if (nb_words >= 2) {
		prx = get_proxy (parsed_line[1].word);
		if (parsed_line[0].keyword != K_NEW &&
                    parsed_line[0].keyword != K_SHOW &&
		    prx == NULL) {
			display_console (fd, "unknown proxy %s in line #%d\n",
				parsed_line[1].word, nline);
			return;
		}
	}
	switch (parsed_line[0].keyword) {
	case K_NEW: {
		/* new <proxy name> */
		if (nb_words < 2)
			goto incor_wn;
		prx = get_proxy (parsed_line[1].word);
		if (prx) {
			display_console(fd, "proxy %s already exists (line #)%d\n",
		         parsed_line[1].word, nline);
			return;
		}
		prx = new_proxy (parsed_line[2].word, &err);
		if (prx == NULL)
			goto cmd_failed;
	}
		break;
	case K_START:
		/* start <proxy name> */
		if (nb_words != 2)
			goto incor_wn;
		start_proxy(prx);
		break;
	case K_SET: {
		int params_left	= nb_words - 2;
		if (nb_words < 3)
			goto incor_wn;

		while (params_left > 0) {
			switch (parsed_line[nb_words-params_left].keyword) {
			case K_MLD:
				prx->proxy_mld = 1;
				break;
			case K_IGMP:
				prx->proxy_igmp = 1;
				break;
			case K_NOMLD:
				prx->proxy_mld = 0;
				break;
			case K_NOIGMP:
				prx->proxy_igmp = 0;
				break;
			default:
				unknown = parsed_line[nb_words-params_left].word;
				goto unknown_word;
			}
			params_left--;
		}
		break;
	}
	case K_STOP:
		/* stop <proxy name> */
		if (nb_words != 2)
			goto incor_wn;
		stop_proxy(prx, 1, 0);
		break;
	case K_DELETE:
		/* delete <proxy name> */
		if (nb_words != 2)
			goto incor_wn;
		stop_proxy(prx, 0, 0);
		break;
	case K_BIND: {
		struct eth_if *ifp = 0;

		/* bind <proxy name> <itf name> {upstream} */
		if (nb_words != 3 && nb_words != 4)
			goto incor_wn;

		ifp = get_ifp (parsed_line[2].word);
		if (ifp == 0) {
			display_console(fd, "bind unknown interface %s\n",
				         parsed_line[2].word);
			return;
		}

		if (nb_words == 4 && parsed_line[3].keyword != K_UPSTREAM) {
			unknown = parsed_line[3].word;
			goto unknown_word;
		}
		add_proxy_binding(prx, ifp, nb_words == 4);
	}
		break;
	case K_UNBIND: {
		struct eth_if *ifp = 0;

		/* unbind <proxy name> <itf name> */
		if (nb_words != 3)
			goto incor_wn;
		ifp = get_ifp (parsed_line[2].word);
		if (ifp == 0) {
			display_console(fd, "unbind unknown interface %s\n",
				         parsed_line[2].word);
			return;
		}
		del_proxy_binding(prx, ifp);
	}
		break;
	case K_MAP:
		/* map <itf name> <port number> <itf name> <encap type> */
		if (nb_words != 5)
			goto incor_wn;

		add_map(parsed_line[1].word, parsed_line[2].word, parsed_line[3].word, parsed_line[4].word);
		break;
	case K_UNMAP:
		if (nb_words != 1)
			goto incor_wn;

		del_map();
		break;
	case K_SHOW: {
		/* show <proxy name>|all {mld|igmp|details} */
		int flags = DMC_IF_STATUS;
		if (nb_words != 2 && nb_words != 3)
			goto incor_wn;

		if (nb_words > 1) {
			if (parsed_line[1].keyword != K_ALL && !prx) {
				display_console(fd, "show unknown proxy %s\n",
				         parsed_line[1].word);
				return;
			}
		}
		if (nb_words > 2) {
			switch (parsed_line[2].keyword) {
			case K_DETAIL:
				flags = DMC_ALL;
				break;
			case K_IGMP:
				flags |= DMC_IF_IGMP;
				break;
			case K_MLD:
				flags |= DMC_IF_MLD;
				break;
			default:
				unknown = parsed_line[2].word;
				goto unknown_word;
			}
		}
		display_proxy_info (fd, prx, flags, 0);
		}
		break;
	default:
		unknown = parsed_line[0].word;
		goto unknown_word;
	}
	return;
unknown_word:
	display_console(fd, "unknown/unexpected word <<%s>> in line #%d\n",
	         unknown, nline);
	return;
incor_wn:
	display_console(fd, "incorrect argument number for cmd %s in line #%d\n",
	         parsed_line[0].word, nline);
	return;
cmd_failed:
	display_console(fd, "command %s in line #%d failed\n",
	         parsed_line[0].word, nline);
	return;
}


void
do_config (int nline, int fd)
{
	if (nb_words < 1)
		return;

	if (parsed_line[1].keyword == K_PROXY)
		return do_config_proxy(nline, fd);
	else
		return do_config_snooping(nline, fd);

}

static
char foo[2000];

int
config (char *fname)
{

    FILE *fp;
	int i=0;

	if ((fp = fopen(fname, "r")) != NULL) {
		char *p;
		while ((p=fgets(foo, sizeof(foo), fp)) != NULL) {
			parse(foo);
			do_config (i++, 1);
		}
		fclose (fp);
	}
	return 0;
}

