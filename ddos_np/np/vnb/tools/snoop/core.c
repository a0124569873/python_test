/*
 * Copyright 2004-2012 6WIND S.A.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <netinet/in.h>
#ifndef __linux__
#include <net/if_dl.h>
#endif
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <ifaddrs.h>

#include <syslog.h>

#include "snoop.h"
#include "igmp.h"
#include "mld.h"
#include "mldv2.h"
#include "igmpv3.h"

int l2f_trash = 0;
int mcf_trash = 0;
int l2_trash  = 0;
int mc_trash  = 0;

#ifdef DEBUG_TIME
	u_int32_t THE_TIME = 0;
#endif


void
query_general(struct eth_if *ifp, int type)
{
	int ret;
	struct proto_mc_param *mcp;
	struct querier_event *qep;

	if (type == AF_INET) {
		mcp = &(ifp->if_igmp_pr);
		qep = &(ifp->if_igmp_querier_ev);
	} else {
		mcp = &(ifp->if_mld_pr);
		qep = &(ifp->if_mld_querier_ev);
	}

	if (mcp->pr_querier_status != PR_QUERIER)
		return;

	/*
	 * Schedule dispatch of next general query
	 */
	if (qep->qrr_stquery_cnt)
		qep->qrr_stquery_cnt--;

	if (qep->qrr_stquery_cnt)
		qep->qrr_gq_timer = compute_deadline(mcp->pr_query_startup_interv * TMO_SCALE);
	else
		qep->qrr_gq_timer = compute_deadline(mcp->pr_query_interv * TMO_SCALE);

	/*
	 * Send general query
	 */
	ret = send_query(type, NULL, NULL, NULL,
			ifp->if_index,
			mcp->pr_query_resp_interv, 1,
			mcp->pr_robust, mcp->pr_query_interv, 0, mcp->pr_querier_version);

	if (ret == 0)
	{
		/*
		 * Increment my-query-indicator and statistics
		 */
		qep->qrr_myquery_ind++;
		mcp->pr_sent_query++;
	}
}

void
query_group(struct eth_if *ifp, struct mc_fwd *mcf, int type)
{
	int ret;
	struct proto_mc_param *mcp;
	struct querier_event *qep;
	struct sockaddr_in6 src;

	if (type == AF_INET) {
		mcp = &(ifp->if_igmp_pr);
		qep = &(ifp->if_igmp_querier_ev);
	} else {
		mcp = &(ifp->if_mld_pr);
		qep = &(ifp->if_mld_querier_ev);
	}


	if (mcp->pr_querier_status != PR_QUERIER)
		return;

	/*
	 * Schedule dispatch of next MAS query
	 */
	if (mcf->mcf_mas_count)
		mcf->mcf_mas_count--;

	if (mcf->mcf_mas_count)
		mcf->mcf_mas_timer = compute_deadline(mcp->pr_query_last_interv);

	/*
	 * Get IPv6 with link local scope
	 */
	memset(&src, 0, sizeof(struct sockaddr_in6));
	ip6_get_lladdr(ifp->if_name, &src);

	/*
	 * Send MAS query
	 */
	ret = send_query(type, (struct sockaddr_in *)&src, NULL,
			(struct sockaddr_in *)&(mcf->mcf_sa), ifp->if_index,
			mcp->pr_query_last_interv, 1,
			mcp->pr_robust, mcp->pr_query_interv, 0, mcp->pr_querier_version);

	if (ret == 0)
	{
		/*
		 * Increment my-query-indicator and statistics
		 */
		qep->qrr_myquery_ind++;
		mcp->pr_sent_query++;
	}
}


int send_query(int type, struct sockaddr_in *src,
                struct sockaddr_in *dst, struct sockaddr_in *group,
                int index, unsigned int delay, int alert,
                int qrv, int qqic, int gss, int version)
{
	if (type == AF_INET6)
		return mld_send_query((struct sockaddr_in6 *)src, (struct sockaddr_in6 *)dst, (struct sockaddr_in6 *)group,
					index, delay, alert, 0, qrv, qqic, gss, version);
	else
		return igmp_send_query(src, dst, group, index, delay, alert, 0, qrv, qqic, gss, version);
}
/*
 * Update timer for the mc entry, and keep list ordered.
 */
static void
update_mc_timer (int leave_mode,
                 struct mchead *port_head,
                 struct mc_entry *mc,
                 u_int32_t       timer)
{
	struct mc_entry *amc = NULL;
	struct mc_entry *bmc = NULL;

	mc->mc_timer =  compute_deadline (timer);

	/*
	 * Update I/F general timer
	 * in the leave mode (i.e. called from a m-a-s query), this query
	 * will be received on ALL ports, hence reduce global timer.
	 */
	if (leave_mode || (mc->mc_mcf->mcf_timer <= mc->mc_timer))
		mc->mc_mcf->mcf_timer = mc->mc_timer;

	for (bmc=LIST_FIRST(port_head);  bmc; bmc=LIST_NEXT(bmc, mc_link)) {
		if (bmc->mc_timer >= mc->mc_timer)
			break;
		amc = bmc;
	}
	if (bmc)
		LIST_INSERT_BEFORE(bmc, mc, mc_link);
	else if (amc)
		LIST_INSERT_AFTER(amc, mc, mc_link);
	else
		LIST_INSERT_HEAD(port_head, mc, mc_link);
	return;
}

static void
map_mc_sdl (struct eth_if *ifp,
            struct sockaddr *grp,
            struct sockaddr_dl *sl)
{
	caddr_t p;

	memset (sl, 0, sizeof(*sl));

	sl->sdl_len    = sizeof (*sl);
	sl->sdl_family = AF_LINK;
	sl->sdl_index  = 0;
	sl->sdl_type   = ifp->if_type;
	sl->sdl_nlen   = 0;
	sl->sdl_alen   = ifp->if_alen;
	sl->sdl_slen   = 0;
	p = LLADDR(sl);
	if (grp->sa_family == AF_INET6) {
		p[0] = 0x33;
		p[1] = 0x33;
		p[2] = ((struct sockaddr_in6 *)grp)->sin6_addr.s6_addr[12];
		p[3] = ((struct sockaddr_in6 *)grp)->sin6_addr.s6_addr[13];
		p[4] = ((struct sockaddr_in6 *)grp)->sin6_addr.s6_addr[14];
		p[5] = ((struct sockaddr_in6 *)grp)->sin6_addr.s6_addr[15];

	}
	else {
		char *s = (char *)&(((struct sockaddr_in *)grp)->sin_addr);
		p[0] = 0x01;
		p[1] = 0x00;
		p[2] = 0x5e;
		p[3] =  s[1] & 0x7f;
		p[4] =  s[2];
		p[5] =  s[3];
	}
}

/*
 * Manage MLD/IGMP report
 */
int
report_received (struct eth_if   *ifp,
                 struct eth_port *port,
                 struct sockaddr *grp)
{
	struct proto_mc_param *mcp;
	struct l2_fwd *l2f = NULL;
	struct mc_fwd *mcf = NULL;
	struct l2_entry *l2 = NULL;
	struct mc_entry *mc = NULL;
	struct mcfhead *if_head;
	struct mchead  *port_head;
	int err = 0;
	int new_l2f = 0;
	int new_mcf = 0;
	int new_l2  = 0;
	int new_mc  = 0;

	if (grp->sa_family == AF_INET) {
		/* IGMP */
		if_head = (struct mcfhead *)&(ifp->if_igmp_head);
		port_head = (struct mchead  *) &(port->prt_igmp_head);
		mcp = &(ifp->if_igmp_pr);
	}
	else {
		/* MLD */
		if_head = (struct mcfhead *)&(ifp->if_mld_head);
		port_head = (struct mchead  *)&(port->prt_mld_head);
		mcp = &(ifp->if_mld_pr);
	}

	/*
	 * First find, create if needed forwarding entry
	 * for both the mcast group and, if needed L2 group.
	 */
	if (ifp->if_l2_filter) {
		struct sockaddr_dl  l2_group;
		map_mc_sdl (ifp, grp, &l2_group);
		LIST_FOREACH (l2f, &(ifp->if_l2_head), l2f_link) {
			if (memcmp(&l2_group, &(l2f->l2f_group), l2_group.sdl_len) == 0)
				break;
		}
		if (l2f == NULL) {
			l2f = malloc (sizeof(*l2f));
			if (l2f == NULL) {
				err = ENOMEM;
				goto report_release;
			}
			new_l2f = 1;
			memset(l2f, 0, sizeof(*l2f));
			memcpy (&(l2f->l2f_group), &l2_group, l2_group.sdl_len);
			l2f->l2f_refcnt++;
			LIST_INSERT_HEAD(&(ifp->if_l2_head), l2f, l2f_link);
		}
	}
	LIST_FOREACH (mcf, if_head, mcf_link) {
		if (memcmp(grp, &(mcf->mcf_sa), sysdep_sa_len(grp)) == 0)
			break;
	}
	if (mcf == NULL) {
		mcf = malloc (sizeof(*mcf));
		if (mcf == NULL) {
			err = ENOMEM;
			goto report_release;
		}
		new_mcf = 1;
		memset (mcf, 0, sizeof(*mcf));
		memcpy (&(mcf->mcf_sa), grp, sysdep_sa_len(grp));
		if (ifp->if_l2_filter) {
			mcf->mcf_l2f = l2f;
			l2f->l2f_refcnt++;
			l2f->l2f_used++;
		}
		else
			mcf->mcf_l2f = NULL;
		mcf->mcf_refcnt++;
		LIST_INSERT_HEAD(if_head, mcf, mcf_link);
	}

	/*
	 * Then, same thing for port entries
	 */
	if (ifp->if_l2_filter) {
		LIST_FOREACH (l2, &(port->prt_l2_head), l2_link) {
			/*
			 * No use comparing addresses, it MUST be the l2f itself
			 */
			if (l2->l2_l2f == l2f)
				break;
		}
		if (l2 == NULL) {
			l2 = malloc (sizeof(*l2));
			if (l2 == NULL) {
				err = ENOMEM;
				goto report_release;
			}
			new_l2 = 1;
			memset (l2, 0, sizeof (*l2));
			l2->l2_l2f = l2f;
			l2f->l2f_refcnt++;
			l2f->l2f_ports++;
			PORT_SET(port->prt_index, &l2f->l2f_oifs);
			l2->l2_refcnt++;
			LIST_INSERT_HEAD(&(port->prt_l2_head), l2, l2_link);
		}
	}
	LIST_FOREACH (mc, port_head, mc_link) {
		/*
		 * No use comparing addresses, it MUST be the mcf itself
		 */
		if (mc->mc_mcf == mcf)
			break;
	}
	if (mc == NULL) {
		mc = malloc (sizeof(*mc));
		if (mc == NULL) {
			err = ENOMEM;
			goto report_release;
		}
		new_mc = 1;
		memset (mc, 0, sizeof(*mc));
		mc->mc_mcf= mcf;
		mcf->mcf_ports++;
		mcf->mcf_refcnt++;
		PORT_SET(port->prt_index, &mcf->mcf_oifs);
		if (ifp->if_l2_filter) {
			mc->mc_l2 = l2;
			l2->l2_refcnt++;
			l2->l2_used++;
		}
		else
			mc->mc_l2 = NULL;
		mc->mc_status = MC_STATE_LISTENERS;
		/*
		 * For LIST insertion done in update_mc_timer
		 */
		mc->mc_refcnt++;
	}
	else {
		/*
		 * Don't relax refcnt for it will be re-inserted i
		 */
		LIST_REMOVE(mc, mc_link);
	}
	update_mc_timer (0, port_head, mc, PR_LISTENER_INTERVAL(mcp));

	/*
	 * Inform other layers/protocols about interesting
	 * changes about forwarding and/or groups
	 */

	/* The MAC forwarding table has changed */
	if (new_l2f || new_l2) {
		notify_mac_change (ifp, port, l2f,
		                   new_l2f ? NOTIFY_GROUP_ADD : NOTIFY_GROUP_CHANGE);
	}

	/* The L3 forwarding table has changed */
	if (new_mcf || new_mc) {
		notify_l3_change (ifp, port, mcf,
		                  new_mcf ? NOTIFY_GROUP_ADD : NOTIFY_GROUP_CHANGE);
	}

	/* A new group has been reported on the interface */
	if (new_mcf)
		notify_group_change (ifp, mcf, NOTIFY_GROUP_ADD);

	return (0);

report_release:
	if (new_l2f) {
		LIST_REMOVE (l2f, l2f_link);
		free (l2f);
	}
	if (new_mcf) {
		LIST_REMOVE (mcf, mcf_link);
		free (mcf);
	}
	if (new_l2) {
		LIST_REMOVE (l2, l2_link);
		free (l2);
	}
	if (new_mc) {
		LIST_REMOVE (mc, mc_link);
		free (mc);
	}
	return (err);
}

/*
 * Update group timers on receipt of m-a-s queries and leave
 * Send a m-a-s query on receipt of leave
 */
int
specific_group_received (struct eth_if   *ifp,
                         struct sockaddr *grp, int type)
{
	struct proto_mc_param *mcp;
	struct mc_entry *mc;
	struct mc_fwd *mcf = NULL;
	struct mchead   *port_head;
	struct mcfhead *if_head;
	struct eth_port *port;
	int i;

	/*
	 * A specific query will be forwarded on all ports
	 * so manage timer reduction as if received on all ports
	 * Same thing for a leav message
	 */
	if (grp->sa_family == AF_INET) {
		mcp = &(ifp->if_igmp_pr);
		if_head = (struct mcfhead *)&(ifp->if_igmp_head);
	} else {
		mcp = &(ifp->if_mld_pr);
		if_head = (struct mcfhead *)&(ifp->if_mld_head);
	}

	LIST_FOREACH (mcf, if_head, mcf_link) {
		if (memcmp(grp, &(mcf->mcf_sa), sysdep_sa_len(grp)) == 0)
			break;
	}

	/*
	 * Ignore group not reported
	 */
	if (mcf == NULL)
		return 0;

	/*
	 * Schedule MAS queries
	 */
	if ((mcp->pr_querier_status == PR_QUERIER) &&
	    ((type == MLD6_LISTENER_DONE && grp->sa_family == AF_INET6) || (type == IGMP_HOST_LEAVE_MESSAGE && grp->sa_family == AF_INET))) {
		mcf->mcf_mas_count = mcp->pr_robust;
		query_group(ifp, mcf, grp->sa_family);
	}

	for (i=0 ; i<ifp->if_nbports; i++) {
		port = &(ifp->if_port[i]);
		if (grp->sa_family == AF_INET)
			port_head = (struct mchead  *) &(port->prt_igmp_head);
		else
			port_head = (struct mchead  *)&(port->prt_mld_head);

		LIST_FOREACH (mc, port_head, mc_link) {
			if (memcmp(grp, &(mc->mc_mcf->mcf_sa), sysdep_sa_len(grp)) == 0)
				break;
		}

		/*
		 * So, we see a specific query for a non-yet registered
		 * group  : we're potentialy out of sync. Let's wait for
		 * the report to create group
		 * Same thing for a leave
		 */
		if (mc == NULL)
			continue;

		/*
		 * Already  in checking state, timer correclty set
		 */
		if (mc->mc_status != MC_STATE_LISTENERS)
			return 0;
		mc->mc_status = MC_STATE_CHECKING;

		/*
		 * dont relax ref to mc, for it will be re-inserted
		 */
		LIST_REMOVE(mc, mc_link);
		update_mc_timer (1, port_head, mc, PR_LAST_LISTENER_QUERY_TIMER(mcp));
	}

	return 0;
}

static int
mc_timeout (struct eth_if   *ifp,
            struct eth_port *port,
            struct mc_entry *mc)
{
	struct proto_mc_param *mcp;
	struct l2_fwd *l2f = NULL;
	struct mc_fwd *mcf = NULL;
	struct mcfhead *if_head;
	struct mchead  *port_head;
	int mcf_removed = 0;

	if (mc->mc_mcf->mcf_sa.sa_family == AF_INET) {
		if_head = (struct mcfhead *)&(ifp->if_igmp_head);
		port_head = (struct mchead  *) &(port->prt_igmp_head);
		mcp = &(ifp->if_igmp_pr);
	} else {
		if_head = (struct mcfhead *)&(ifp->if_mld_head);
		port_head = (struct mchead  *)&(port->prt_mld_head);
		mcp = &(ifp->if_mld_pr);
	}

	LIST_REMOVE (mc, mc_link);
	mc->mc_refcnt--;
	mc_trash++;
	if (mc->mc_l2) {
		struct l2_entry *l2 = mc->mc_l2;
		l2->l2_used--;
		if (l2->l2_used == 0) {
			LIST_REMOVE (l2, l2_link);
			l2->l2_refcnt--;
			l2_trash++;
			l2f = l2->l2_l2f;
			PORT_CLR(port->prt_index, &l2f->l2f_oifs);
		}
		mc->mc_l2 = NULL;
		if (--l2->l2_refcnt == 0) {
			l2f = l2->l2_l2f;
			l2->l2_l2f = NULL;
			if (l2f) {
				l2f->l2f_ports--;
				l2f->l2f_refcnt--;
			}
			free (l2);
			l2_trash--;
			/* Don't free l2f yet */
		}
	}
	if (mc->mc_mcf) {
		mcf = mc->mc_mcf;
		PORT_CLR(port->prt_index, &mcf->mcf_oifs);
		mcf->mcf_ports--;
		if (mcf->mcf_ports == 0) {
			LIST_REMOVE (mcf, mcf_link);
			mcf_removed = 1;
			mcf->mcf_refcnt--;
			mcf_trash++;
		}
		mc->mc_mcf = NULL;
		if (--mcf->mcf_refcnt == 0) {
			l2f = mcf->mcf_l2f;
			mcf->mcf_l2f = NULL;
			if (l2f) {
				l2f->l2f_used--;
				l2f->l2f_refcnt--;
			}
			/* Don't free mcf yet */
			/* Don't free l2f yet */
		}
	}
	free (mc);
	mc_trash--;
	/* The L3 forwarding table has changed */
	if (mcf){
		notify_l3_change (ifp, port, mcf,
		           mcf_removed ? NOTIFY_GROUP_DELETE : NOTIFY_GROUP_CHANGE);
		if (mcf_removed)
			notify_group_change (ifp, mcf, NOTIFY_GROUP_DELETE);
		if (mcf->mcf_refcnt == 0) {
			free (mcf);
			mcf_trash--;
		}
	}
	/* The L2 forwarding table has changed */
	if (l2f) {
		if ((l2f->l2f_ports == 0) && (l2f->l2f_used == 0)) {
			notify_mac_change (ifp, port, l2f, NOTIFY_GROUP_DELETE);
			LIST_REMOVE (l2f, l2f_link);
			l2f->l2f_refcnt--;
			l2f_trash++;
		}
		else {
			notify_mac_change (ifp, port, l2f, NOTIFY_GROUP_CHANGE);
		}
		if (l2f->l2f_refcnt == 0) {
			free (l2f);
			l2f_trash--;
		}
	}
	return 0;
}

void
group_timers (void)
{
	struct eth_if   *ifp;
	struct eth_port *prt;
	struct mc_entry *mc;
	u_int32_t        now;
	int r6, r4;

	now = get_time();
	LIST_FOREACH (ifp, &ifnet, if_link) {
		int idx;
		if (ifp->if_started_igmp == 0 && ifp->if_started_mld == 0)
			continue;
		r6 = 0;
		r4 = 0;
		/*
		 * TBD : query and m-a-s query stuff
		 */
		for (idx=0; idx < ifp->if_nbports; idx++) {
			struct mc_entry *next;
			int i;

			prt = &(ifp->if_port[idx]);
			i = prt->prt_index;

			if ((PORT_ISSET(i, &(ifp->if_rtr6))) &&
				(prt->prt_rtr6_tmo != TMO_INFINITE) &&
			    (now > prt->prt_rtr6_tmo)) {
				PORT_CLR (i, &(ifp->if_rtr6));
				prt->prt_rtr6_tmo = 0;
				r6++;
			}
			if ((PORT_ISSET(i, &(ifp->if_rtr4))) &&
				(prt->prt_rtr4_tmo != TMO_INFINITE) &&
			    (now > prt->prt_rtr4_tmo)) {
				PORT_CLR (i, &(ifp->if_rtr4));
				prt->prt_rtr4_tmo = 0;
				r4++;
			}
			mc = LIST_FIRST(&(prt->prt_mld_head));
			while (mc) {
				next = LIST_NEXT(mc, mc_link);
				if (now > mc->mc_timer)
					mc_timeout (ifp, prt, mc);
				else
					break;
				mc = next;
			}
			mc = LIST_FIRST(&(prt->prt_igmp_head));
			while (mc) {
				next = LIST_NEXT(mc, mc_link);
				if (now > mc->mc_timer)
					mc_timeout (ifp, prt, mc);
				else
					break;
				mc = next;
			}
		}
		if (r6)
			notify_port_list (SET_MLD_ROUTERS, ifp);
		if (r4)
			notify_port_list (SET_IGMP_ROUTERS, ifp);
	}
}

void
querier_timers(void)
{
	struct eth_if   *ifp;
	u_int32_t        now;

	now = get_time();
	LIST_FOREACH (ifp, &ifnet, if_link) {
		int i;
		int af_type[] = { AF_INET, AF_INET6 };

		struct proto_mc_param *mcp;
		struct querier_event *qep;

		if (ifp->if_started_igmp == 0 && ifp->if_started_mld == 0)
			continue;

		for (i = 0; i < sizeof(af_type)/sizeof(af_type[0]); ++i) {
			if (af_type[i] == AF_INET6) {
				mcp = &(ifp->if_mld_pr);
				qep = &(ifp->if_mld_querier_ev);
			} else {
				mcp = &(ifp->if_igmp_pr);
				qep = &(ifp->if_igmp_querier_ev);
			}
			if (!mcp->pr_snooping)
				continue;

			if (mcp->pr_querier_candidature != PR_QUERIER_NONCANDIDATE) {
				if ((mcp->pr_querier_status == PR_NONQUERIER) &&
					(qep->qrr_timer != TMO_INFINITE) && (now > qep->qrr_timer)) {
					/*
					* Switch to Querier state
					*/
					syslog (LOG_INFO, "----> switching to %s querier state for interface %s\n",
						(af_type[i] == AF_INET6)?"MLD":"IGMP",
						ifp->if_name);
					mcp->pr_querier_status = PR_QUERIER;
					if (af_type[i] == AF_INET6)
						mcp->pr_querier_version = PR_VERSION_MLDv2;
					else
						mcp->pr_querier_version = PR_VERSION_IGMPv3;
					qep->qrr_stquery_cnt = mcp->pr_query_startup_cnt;
					qep->qrr_myquery_ind = 0;
					qep->qrr_gq_timer = TMO_INFINITE;

					/*
					* Send first startup query
					*/
					query_general(ifp, af_type[i]);
				} else if (mcp->pr_querier_status == PR_QUERIER) {
					/*
					* We are in Querier state
					*/
					if ((qep->qrr_gq_timer != TMO_INFINITE) && (now > qep->qrr_gq_timer))
						/*
						* Send general query
						*/
						query_general(ifp, af_type[i]);
				}
			}
		}
	}
}
