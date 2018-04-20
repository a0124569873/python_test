/*
 * Copyright 2004-2012 6WIND S.A.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#ifndef __linux__
#include <net/if_dl.h>
#endif
#include <syslog.h>

#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "proxy.h"
#include "snoop.h"
int numerichost = 1; /* for use in sa6_fmt */

extern void display_console(int fd, const char *msg, ...);
char *
display_notify (char *s, u_int32_t mode)
{
	if (mode == NOTIFY_GROUP_ADD)
		sprintf (s, " add");
	else if (mode == NOTIFY_GROUP_CHANGE)
		sprintf (s, " chg");
	else if (mode == NOTIFY_GROUP_DELETE)
		sprintf (s, " del");
	else
		sprintf (s, " ???");
	s += 4;
	return s;
}

char *
display_sdl (char *str, struct sockaddr_dl *sdl)
{
	int i;
	char *s = str;
	caddr_t p = LLADDR(sdl);
	for (i=0; i<sdl->sdl_alen; i++) {
		if (i!=0) {
			sprintf (s, ":");
			s++;
		}
		sprintf (s, "%02x", p[i] & 0xff);
		s += 2;
	}
	return s;
}

char *
display_sa (char *s, struct sockaddr *sa)
{
	getnameinfo(sa, sysdep_sa_len(sa), s, 128, NULL ,0, NI_NUMERICHOST );
	return (&s[strlen(s)]);
}

char *
display_plist (char *s, port_set *p, struct eth_if *ifp)
{
	int i;
	int n=0;
	for (i=0; i<MAX_PORTS; i++) {
		if (PORT_ISSET(i, p)) {
			int idx = get_port_for_ifp(ifp, i);
			if ( ifp->if_port_names && idx >= 0 && ifp->if_port[idx].prt_name )
				sprintf (s, "%s%s", n ? ", ":"", ifp->if_port[idx].prt_name);
			else
				sprintf (s, "%s%d", n ? ", ":"", i);
			s = &s[strlen(s)];
			n++;
		}
	}
	if (n == 0) {
		sprintf (s, "none");
		s = &s[strlen(s)];
	}
	return s;
}

char *
display_time (char *s, u_int32_t deadline, int tmode)
{
	if (tmode) {
		if (deadline == TMO_INFINITE)
			sprintf (s, "( inf. ) ");
		else
			sprintf (s, "(%06d) ", deadline);
		s += 9;
	}
	else {
		if (deadline == TMO_INFINITE)
			sprintf (s, "(inf.) ");
		else
			sprintf (s, "(%04ld) ", deadline - get_time());
		s += 7;
	}
	return s;
}

void
display_proxy_info (int fd, struct mc_proxy *prx, int rmode, int tm)
{
	struct mc_proxy *p;

	if (LIST_EMPTY(&all_proxies)) {
		display_console (fd, "No proxy configured\n");
		return;
	}

	LIST_FOREACH (p, &all_proxies, proxy_link) {
		struct mc_proxy_binding* binding;
		if (prx && prx != p)
			continue;

		display_console (fd, "Proxy : %s", p->proxy_name);
		if (p->proxy_started)
			display_console (fd, " (Started)\n");
		else
			display_console (fd, " (Stopped)\n");
		if (rmode & DMC_IF_MLD) {
			display_console (fd, "  + MLD  proxy : ");
			if (p->proxy_mld)
				display_console (fd, "enabled\n");
			else
				display_console (fd, "disabled\n");
		}
		if (rmode & DMC_IF_IGMP) {
			display_console (fd, "  + IGMP proxy : ");
			if (p->proxy_igmp)
				display_console (fd, "enabled\n");
			else
				display_console (fd, "disabled\n");
		}
		display_console (fd, "  + Upstream   : ");
		if (p->proxy_upstream)
			display_console (fd, "%s\n", p->proxy_upstream->if_name);
		else
			display_console (fd, "none\n");
		display_console (fd, "  + Downstream : ");
		LIST_FOREACH (binding, &p->proxy_downstreams, binding_link) {
			display_console (fd, "%s ", binding->interface->if_name);
		}
		display_console (fd, "\n");
	}
}

static void
display_cfg_param(int fd, struct proto_mc_param *pr)
{
	display_console(fd, "    + Querier : ");
	switch (pr->pr_querier_candidature) {
		case PR_ROUTER_CANDIDATE:
			display_console(fd, "%s", "router");
			break;
		case PR_QUERIER_CANDIDATE:
			display_console(fd, "%s", "switch");
			break;
		default:
			display_console(fd, "%s", "none");
			break;
	}
	display_console(fd, "\n");

	display_console(fd, "    + Robustness : %u\n", pr->pr_robust);
	display_console(fd, "    + Query-interval : %u (s)\n", pr->pr_query_interv);
	display_console(fd, "    + Query-startup-interval : %u (s)\n", pr->pr_query_startup_interv);
	display_console(fd, "    + Query-response-interval : %u (ms)\n", pr->pr_query_resp_interv);
	display_console(fd, "    + Last-query-interval : %u (ms)\n", pr->pr_query_last_interv);
}

void
display_info (int fd, struct eth_if *ifptr, int port_index, int rmode, int tm)
{
	struct eth_if *ifp;
	struct l2_fwd *l2f;
	struct mc_fwd *mcf;
	struct l2_entry *l2;
	struct mc_entry *mc;
	char time_buf[32];
	char grp_buf[128];
	char port_buf[128];

	if (LIST_EMPTY(&ifnet)) {
		display_console (fd, "No Interface configured\n");
		return;
	}
	if (tm)
		display_console (fd, "Current time is : %ld\n", get_time());
	LIST_FOREACH (ifp, &ifnet, if_link) {
		int mode = rmode;
		if (ifptr && (ifptr != ifp))
			continue;
		if (!ifp->if_mld_pr.pr_snooping)
			mode &= ~(DMC_IF_MLD | DMC_PRT_MLD);
		if (!ifp->if_igmp_pr.pr_snooping)
			mode &= ~(DMC_IF_IGMP | DMC_PRT_IGMP);
		if (!ifp->if_mld_pr.pr_snooping && !ifp->if_igmp_pr.pr_snooping)
			mode &= ~(DMC_IF_L2 | DMC_PRT_L2);
		if (ifp->if_created)
			display_console (fd, "Interface : %s\n", ifp->if_name);
		else
			display_console (fd, "Interface : %s [not connected]\n", ifp->if_name);
		if (mode & DMC_IF_STATUS) {
			display_plist (port_buf, &(ifp->if_spy), ifp);
			display_console (fd, "  + spy ports : %s\n", port_buf);
			if (mode & DMC_IF_MLD) {
				if (ifp->if_mld_pr.pr_snooping) {
					display_plist (port_buf, &(ifp->if_rtr6), ifp);
					display_console (fd, "  + MLD snooping : enabled\n");
					display_cfg_param (fd, &ifp->if_mld_pr);
					display_console (fd, "  + MLD router detected : %s\n",
					                 port_buf);
					display_console (fd, "  + MLD querier : ");
					switch (ifp->if_mld_pr.pr_querier_candidature) {
						case PR_ROUTER_CANDIDATE:
							display_console(fd, (ifp->if_mld_pr.pr_querier_status == PR_NONQUERIER)?"router candidate":"active router");
							break;
						case PR_QUERIER_CANDIDATE:
							display_console(fd, (ifp->if_mld_pr.pr_querier_status == PR_NONQUERIER)?"querier candidate":"active querier");
							break;
						default:
							display_console(fd, "none");
							break;
					}
					display_console(fd, "\n");
				}
				else {
					display_console (fd, "  + MLD snooping : disabled\n");
					display_cfg_param (fd, &ifp->if_mld_pr);
				}
			}

			if (mode & DMC_IF_IGMP) {
				if (ifp->if_igmp_pr.pr_snooping) {
					display_plist (port_buf, &(ifp->if_rtr4), ifp);
					display_console (fd, "  + IGMP snooping : enabled\n");
					display_cfg_param (fd, &ifp->if_igmp_pr);
					display_console (fd, "  + IGMP router detected : %s\n",
					                 port_buf);
					display_console (fd, "  + IGMP querier : ");
					switch (ifp->if_igmp_pr.pr_querier_candidature) {
						case PR_ROUTER_CANDIDATE:
							display_console(fd, (ifp->if_igmp_pr.pr_querier_status == PR_NONQUERIER)?"router candidate":"active router");
							break;
						case PR_QUERIER_CANDIDATE:
							display_console(fd, (ifp->if_igmp_pr.pr_querier_status == PR_NONQUERIER)?"querier candidate":"active querier");
							break;
						default:
							display_console(fd, "none");
							break;
					}
					display_console(fd, "\n");
				}
				else {
					display_console (fd, "  + IGMP snooping : disabled\n");
					display_cfg_param (fd, &ifp->if_igmp_pr);
				}
			}
		}
		if ((mode & DMC_IF_L2) && ifp->if_l2_filter) {
			display_console (fd, "  + L2 groups detected :");
			if (LIST_EMPTY(&ifp->if_l2_head))
				display_console (fd, " none");
			display_console (fd, "\n");
			LIST_FOREACH (l2f, &(ifp->if_l2_head), l2f_link) {
				display_sdl (grp_buf, &(l2f->l2f_group));
				display_plist (port_buf, &(l2f->l2f_oifs), ifp);
				display_console (fd, "    - %s ports  %s\n", grp_buf, port_buf);
			}
		}
		if (mode & DMC_IF_MLD) {
			display_console (fd, "  + IPv6 mcast groups detected :");
			if (LIST_EMPTY(&ifp->if_mld_head))
				display_console (fd, " none");
			display_console (fd, "\n");
			LIST_FOREACH (mcf, &(ifp->if_mld_head), mcf_link) {
				display_time (time_buf, mcf->mcf_timer, tm);
				display_sa (grp_buf, &(mcf->mcf_sa));
				display_plist (port_buf, &(mcf->mcf_oifs), ifp);
				display_console (fd, "    - %s%s ports %s\n",
				         time_buf, grp_buf, port_buf);
			}
		}
		if (mode & DMC_IF_IGMP) {
			display_console (fd, "  + IPv4 mcast groups detected :");
			if (LIST_EMPTY(&ifp->if_igmp_head))
				display_console (fd, " none");
			display_console (fd, "\n");
			LIST_FOREACH (mcf, &(ifp->if_igmp_head), mcf_link) {
				display_time (time_buf, mcf->mcf_timer, tm);
				display_sa (grp_buf, &(mcf->mcf_sa));
				display_plist (port_buf, &(mcf->mcf_oifs), ifp);
				display_console (fd, "    - %s%s ports %s\n",
				         time_buf, grp_buf, port_buf);
			}
		}

		if (!ifp->if_created)
			continue;

		if (mode & DMC_PRT) {
			int i;
			struct eth_port *prt;
			for (i=0; i<ifp->if_nbports; i++) {
				if ((port_index != (-1)) && (port_index != i))
					continue;
				if (!ifp->if_port[i].prt_bnet_valid)
					continue;

				/* if we configure port mapping, we don't want unknown ports */
				if ( ifp->if_port_names && !ifp->if_port[i].prt_name )
					continue;

				prt = &(ifp->if_port[i]);
				if ( ifp->if_port[i].prt_name )
					display_console (fd, "  + Port %s", prt->prt_name);
				else
					display_console (fd, "  + Port #%d", prt->prt_index);

				if (PORT_ISSET(prt->prt_index, &(ifp->if_spy)))
					display_console (fd, " (spy mode ON)");
				display_console (fd, "\n");
				if (mode & DMC_PRT_STATUS) {
					if (PORT_ISSET(prt->prt_index, &(ifp->if_rtr6))) {
						display_time (time_buf, prt->prt_rtr6_tmo, tm);
						display_console (fd, "    + %s MLD router\n", time_buf);
					}
					else
						display_console (fd, "    + No MLD router\n");
					if (PORT_ISSET(prt->prt_index, &(ifp->if_rtr4))) {
						display_time (time_buf, prt->prt_rtr4_tmo, tm);
						display_console (fd, "    + %s IGMP router\n", time_buf);
					}
					else
						display_console (fd, "    + No IGMP router\n");
				}
				if (mode & DMC_PRT_L2) {
					display_console (fd, "    + L2 groups detected :");
					if (LIST_EMPTY(&prt->prt_l2_head))
						display_console (fd, " none");
					display_console (fd, "\n");
					LIST_FOREACH (l2, &(prt->prt_l2_head), l2_link) {
						display_sdl (grp_buf, &(l2->l2_l2f->l2f_group));
						display_console (fd, "       - %s\n", grp_buf);
					}
				}
				if (mode & DMC_PRT_MLD) {
					display_console (fd, "    + IPv6 mcast groups detected :");
					if (LIST_EMPTY(&prt->prt_mld_head))
						display_console (fd, " none");
					display_console (fd, "\n");
					LIST_FOREACH (mc, &(prt->prt_mld_head), mc_link) {
						display_time (time_buf, mc->mc_timer, tm);
						display_sa (grp_buf, &(mc->mc_mcf->mcf_sa));
						display_console (fd, "       - %s%s\n", time_buf, grp_buf);
					}
				}
				if (mode & DMC_PRT_IGMP) {
					display_console (fd, "    + IPv4 mcast groups detected :");
					if (LIST_EMPTY(&prt->prt_igmp_head))
						display_console (fd, " none");
					display_console (fd, "\n");
					LIST_FOREACH (mc, &(prt->prt_igmp_head), mc_link) {
						display_time (time_buf, mc->mc_timer, tm);
						display_sa (grp_buf, &(mc->mc_mcf->mcf_sa));
						display_console (fd, "       - %s%s\n", time_buf, grp_buf);
					}
				}
			}
		}
	}
}

/*
 * Log errors and other messages to the system log daemon and to stderr,
 * according to the severity of the message and the current debug level. For
 * errors of severity LOG_ERR or worse, terminate the program.
 */
#ifdef __STDC__
void
log_msg(int severity, int syserr, char *format, ...)
{
    va_list         ap;
    static char     fmt[211] = "warning - ";
    char           *msg;
    va_start(ap, format);
#else
/* VARARGS3 */
void
log_msg(severity, syserr, format, va_alist)
    int             severity,
                    syserr;
    char           *format;
va_dcl
{
    va_list         ap;
    static char     fmt[311] = "warning - ";
    char           *msg;
    char            tbuf[20];
    struct timeval  now;
    struct tm      *thyme;

    va_start(ap);
#endif
    vsnprintf(&fmt[10], sizeof(fmt) - 10, format, ap);
    va_end(ap);
    msg = (severity == LOG_WARNING) ? fmt : &fmt[10];

    if (syserr != 0) {
	errno = syserr;
	syslog(severity, "%s: %m", msg);
    } else {
	syslog(severity, "%s", msg);
    }

    if (severity <= LOG_ERR)
	fatal_exit();
}

char *
sa_fmt(struct sockaddr_in *sa)
{
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 32
#endif
    static char     ipbuf[MAXHOSTNAMELEN];

#ifndef HAVE_SIN_LEN
    getnameinfo((struct sockaddr *)sa, sizeof(struct sockaddr_in), ipbuf, MAXHOSTNAMELEN, NULL, 0, NI_NUMERICHOST);
#else
    getnameinfo((struct sockaddr *)sa, sa->sin_len, ipbuf, MAXHOSTNAMELEN, NULL, 0, NI_NUMERICHOST);
#endif
    return(ipbuf);
}


char *
sa6_fmt(struct sockaddr_in6 *sa6)
{
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 32
#endif
    static char     ip6buf[8][MAXHOSTNAMELEN];
    static int      ip6round = 0;
#ifdef NI_WITHSCOPEID
    int flags = NI_WITHSCOPEID;
#else
    int flags = 0;
#endif
    char           *cp;
    struct sockaddr_in6 sa6_tmp; /* local copy for overriding */

    sa6_tmp = *sa6;
    sa6 = &sa6_tmp;

    /*
     * construct sin6_scope_id for link-scope addresses from  embedded link
     * IDs.
     * XXX: this should be hidden from applications.
     */
    if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr) ||
	IN6_IS_ADDR_MC_LINKLOCAL(&sa6->sin6_addr)) {
	    sa6->sin6_scope_id = sa6->sin6_addr.s6_addr[2] << 8 |
		sa6->sin6_addr.s6_addr[3];
	    sa6->sin6_addr.s6_addr[2] = sa6->sin6_addr.s6_addr[3] = 0;
    }

    ip6round = (ip6round + 1) & 7;
    cp = ip6buf[ip6round];

    if (numerichost)
	    flags |= NI_NUMERICHOST;
#ifndef HAVE_SIN_LEN
    getnameinfo((struct sockaddr *)sa6, sizeof(struct sockaddr_in6), cp, MAXHOSTNAMELEN,
		NULL, 0, flags);
#else
    getnameinfo((struct sockaddr *)sa6, sa6->sin6_len, cp, MAXHOSTNAMELEN,
		NULL, 0, flags);
#endif
    return(cp);
}

/*
 * convert a 128bit IPv6 address into a text string.
 * please DO NOT use this function only when a corresponding sockaddr_in6 is
 * available.  use sa6_fmt instead.
 */
char *
inet6_fmt(struct in6_addr * addr)
{
    struct sockaddr_in6 sa6;

    memset(&sa6, 0, sizeof(sa6));
#ifdef HAVE_SIN_LEN
    sa6.sin6_len = sizeof(sa6);
#endif
    sa6.sin6_family = AF_INET6;
    sa6.sin6_addr = *addr;

    return(sa6_fmt(&sa6));
}

/*
 * convert a 32bits IPv4 address into a text string.
 * please DO NOT use this function only when a corresponding sockaddr_in is
 * available.  use sa_fmt instead.
 */
char *
inet_fmt(struct in_addr * addr)
{
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof(sa));
#ifdef HAVE_SIN_LEN
    sa.sin_len = sizeof(sa);
#endif
    sa.sin_family = AF_INET;
    sa.sin_addr = *addr;

    return(sa_fmt(&sa));
}

char *
ifindex2str(int ifindex)
{
    static char ifname[IFNAMSIZ];

    return ((char *)if_indextoname(ifindex, ifname));
}
