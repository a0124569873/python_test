/*
 * Copyright 2004-2012 6WIND S.A.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/in.h>
#ifndef __linux__
#include <net/if_dl.h>
#endif
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netgraph.h>
#include <syslog.h>

#include "snoop.h"
#include "mld.h"

#include "proxy.h"

#include "igmp.h"
/*
 * L2 forwarding list has changed, and should
 * be reported  to lower switching fabric
 */
void
notify_mac_change (struct eth_if  *ifp,
                  struct eth_port *port,
                  struct l2_fwd   *l2f,
                  u_int32_t        mode)
{
	char buf [128];
	char port_buf [128];
	char grp_buf [128];
	char notify_buf [128];
	char *p;
	struct ng_bridge_snoop_msg *m= (struct ng_bridge_snoop_msg *)buf;
	struct ng_bridge_group *g= (struct ng_bridge_group *)(m+1);
	char path[NG_PATHLEN + 1];

	display_notify (notify_buf, mode);
	display_sdl (grp_buf, &(l2f->l2f_group));
	if (mode != NOTIFY_GROUP_DELETE) {
		sprintf (port_buf, "ports ");
		display_plist (&port_buf[strlen(port_buf)], &(l2f->l2f_oifs), ifp);
	}
	else
		port_buf[0] = 0;
	syslog (LOG_NOTICE,
	        "%s mac entry for interface %s : %s %s\n",
	            notify_buf,
	            ifp->if_name,
	            grp_buf,
	            port_buf);


	if (ifp->if_bridge) {
		p = LLADDR(&l2f->l2f_group);
		if (mode != NOTIFY_GROUP_DELETE)
			m->nbs_cmd = ADD_L2_GROUP;
		else
			m->nbs_cmd = DEL_L2_GROUP;
		m->nbs_len = sizeof(*g);
		memcpy(g->addr, p, ETHER_ADDR_LEN);
		g->oifs = l2f->l2f_oifs;
		snprintf(path, sizeof(path), "%s%s", ifp->if_ngname, ":");
		if (NgSendMsg(ifp->if_csock, path, NGM_BRIDGE_COOKIE,
			NGM_BRIDGE_SET_SNOOP_CONFIG, buf, sizeof(*m) + m->nbs_len) < 0)
			log_msg(LOG_NOTICE, errno,
				"notify_mac_change: error in NgSendMsg");
	}
	return;
}

/*
 * L3 forwarding list has changed, and should
 * be reported  to lower switching fabric.
 *
 * Currently nor done, for ng_bridge does not
 * support it
 */
void
notify_l3_change (struct eth_if   *ifp,
                  struct eth_port *port,
                  struct mc_fwd   *mcf,
                  u_int32_t        mode)
{
	char port_buf [128];
	char grp_buf [128];
	char notify_buf [128];

	display_notify (notify_buf, mode);
	display_sa (grp_buf, &(mcf->mcf_sa));
	if (mode != NOTIFY_GROUP_DELETE) {
		sprintf (port_buf, "ports ");
		display_plist (&port_buf[strlen(port_buf)], &(mcf->mcf_oifs), ifp);
	}
	else
		port_buf[0] = 0;
	syslog (LOG_NOTICE,
	        "%s group entry for interface %s : %s %s\n",
	             notify_buf,
	             ifp->if_name,
	             grp_buf,
	             port_buf);

	return;
}

/*
 * L3 membeship info has changed on the global interface
 * should be reported to multicast routing daemons and to
 * the kernel the interface is part of a proxy
 *
 */
void
notify_group_change (struct eth_if   *ifp,
                     struct mc_fwd   *mcf,
                     u_int32_t        cmd)
{
	char port_buf [128];
	char grp_buf [128];
	char notify_buf [128];

	display_notify (notify_buf, cmd);
	display_sa (grp_buf, &(mcf->mcf_sa));
	display_plist (port_buf, &(mcf->mcf_oifs), ifp);
	syslog (LOG_INFO,
	        "%s group membership for interface %s : %s\n",
	             notify_buf,
	             ifp->if_name,
	             grp_buf);

	/* update the kernel MFC if the proxy associated with the ifp is active */
	struct mc_proxy *prx = ifp->if_proxy;
	if (prx)
		proxy_mfc_change(prx, ifp, mcf, cmd);
}

void
notify_port_list (u_int16_t cmd, struct eth_if *ifp)
{
	char buf [128];
	char port_buf [128];

	if (!ifp->if_bridge)
		return;

	struct ng_bridge_snoop_msg *m= (struct ng_bridge_snoop_msg *)buf;
	port_set *p = (port_set *)(m+1);
	if (cmd == SET_MLD_ROUTERS)
		p = &ifp->if_rtr6;
	else if (cmd == SET_IGMP_ROUTERS)
		p = &ifp->if_rtr4;
	else
		p = &ifp->if_spy;
	*(port_set *)(m+1) = *p;
	m->nbs_len = sizeof(*p);
	display_plist (port_buf, p, ifp);
	if (cmd != SET_SPY_PORTS)
		syslog (LOG_NOTICE,
		        "update %s router list for interface %s : %s\n",
		        (cmd == SET_MLD_ROUTERS) ? "MLD" : "IGMP",
		        ifp->if_name, port_buf);
	if (ifp->if_bridge) {
		char path[NG_PATHLEN + 1];
		m->nbs_cmd = cmd;
		snprintf(path, sizeof(path), "%s%s", ifp->if_ngname, ":");
		if (NgSendMsg(ifp->if_csock, path, NGM_BRIDGE_COOKIE,
			NGM_BRIDGE_SET_SNOOP_CONFIG, buf, sizeof(*m) + m->nbs_len) < 0)
			log_msg(LOG_NOTICE, errno,
				"notify_port_list: error in NgSendMsg");
	}
	return;
}

static u_int8_t buf_cs_snoop_read[512];
/*
 * Recv control messages form the swiching fabric, i.e. dynamic port
 * addition/ removal notifications such as
 * RECV_ADDED_PORT_INDEX, RECV_REMOVED_PORT_INDEX
 */
void
notify_cs_snoopd (int fd, short event, void *data)
{
	int len;
	struct ng_mesg *const resp = (struct ng_mesg *)buf_cs_snoop_read;
	struct ng_bridge_snoop_msg *nbsm;


	if (NgRecvMsg(fd, resp, sizeof(buf_cs_snoop_read), NULL) < 0) {
		log_msg(LOG_WARNING, 0, "notify_cs_snoopd: error in NgRecvMsg");
		return;
	}
	/*
	 * drop NG message other than notification
	 */
	if (resp->header.cmd != NGM_BRIDGE_NOTIFY_SNOOPD) {
		log_msg(LOG_WARNING, 0, "notify_cs_snoopd: received invalid netgraph message %d", resp->header.cmd);
		return;
	}
	/*
	 * Validate message length
	 */
	if (resp->header.arglen < sizeof(struct ng_bridge_snoop_msg)) {
		log_msg(LOG_WARNING, 0, "notify_cs_snoopd: received too short message");
		return;
	}
	nbsm = (struct ng_bridge_snoop_msg *)resp->data;

	/* Validate snoop message payload length */
	if (resp->header.arglen < \
				(sizeof(struct ng_bridge_snoop_msg) + nbsm->nbs_len)) {
		log_msg(LOG_WARNING, 0, "notify_cs_snoopd: received message"
				"with too short payload");
		return;
	}

	switch (nbsm->nbs_cmd) {
		case RECV_ADDED_PORT_INDEX:
			add_port((struct eth_if *)data, nbsm->nbs_port);
			break;
		case RECV_REMOVED_PORT_INDEX:
			cancel_port((struct eth_if *)data, nbsm->nbs_port);
			break;
		default:
			log_msg(LOG_WARNING, 0, "notify_cs_snoopd: received invalid snoop message %d", nbsm->nbs_cmd);
			break;
	}
	return;
}

static u_int8_t buf_ds_snoop_read[2048];
/*
 * Recv data messages form the swiching fabric, i.e. interesting
 * packets sucha as MLD, IGMP, PIM, ...
 */
void
notify_ds_snoopd (int fd, short event, void *data)
{
	int len;
	struct ng_bridge_snoop_msg *msg =
			(struct ng_bridge_snoop_msg *)buf_ds_snoop_read;

	len = NgRecvData(fd, buf_ds_snoop_read, sizeof(buf_ds_snoop_read), NULL);
	if (len < sizeof (struct ng_bridge_snoop_msg)) {
		syslog (LOG_DEBUG,
		        "notify_ds_snoopd: recv'd too short msg %d bytes\n",
		        len);
		return;
	}
	switch (msg->nbs_cmd) {
		case RECV_MLD_MSG:
			mld_input ((struct eth_if *)data, msg->nbs_port,
			           (u_int8_t *)(msg+1), len - sizeof(*msg));
			break;
		case RECV_PIM6_MSG:
			pim6_input ((struct eth_if *)data, msg->nbs_port,
			           (u_int8_t *)(msg+1), len - sizeof(*msg));
			break;
		case RECV_IGMP_MSG:
			igmp_input ((struct eth_if *)data, msg->nbs_port,
			           (u_int8_t *)(msg+1), len - sizeof(*msg));
			break;
		case RECV_PIM4_MSG:
			pim4_input ((struct eth_if *)data, msg->nbs_port,
			           (u_int8_t *)(msg+1), len - sizeof(*msg));
			break;
		default:
			syslog (LOG_DEBUG,
			        "notify_ds_snoopd: recv'd unknownt msg %d\n",
			        msg->nbs_cmd);
			break;
	}
	return;
}

