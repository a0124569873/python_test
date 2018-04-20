/*
 * Copyright 2007-2013 6WIND S.A.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <event.h>
#include <time.h>
#include <sys/queue.h>
#include <libconsole.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/un.h>
#include <sys/time.h>
#include <netlink/msg.h>
#include <netlink/socket.h>

#include <netgraph.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_ethgrp.h>

#include "lacp.h"
#include <netgraph/ieee8023_slowprotocols.h>
#include <netgraph/ieee8023_tlv.h>
#include <netgraph/ieee8023ad_lacp.h>
#include "iface.h"
#include "node.h"
#include "ieee8023ad_lacp_sm.h"
#include "ieee8023ad_lacp_debug.h"

#include <assert.h>

static int vnb_csock = -1; /* VNB Control socket */
static int vnb_dsock = -1; /* VNB Data socket */

static struct nl_sock *nl_csock;

#ifdef LACP_NOTIF
static struct event dsock_evt;
static void notify_ds_lacp(int fd, short event, void *param);
#ifdef HA_SUPPORT
static struct event rx_s_evt;
static int rx_sock;
static int tx_sock;
static void notify_ds_dup(int fd, short event, void *param);
#endif
static void
ieee8023ad_lacp_porttick(int fd, short event, void *arg);

static uint16_t
lacp_compose_key(struct chgrp_link *link, struct chgrp_node * node);

/*
 * actor system priority and port priority.
 * XXX should be configurable.
 */

#define	LACP_SYSTEM_PRIO	0x8000
#define	LACP_PORT_PRIO		0x8000

static const struct tlv_template lacp_info_tlv_template[] = {
	{ LACP_TYPE_ACTORINFO,
	    sizeof(struct tlvhdr) + sizeof(struct lacp_peerinfo) },
	{ LACP_TYPE_PARTNERINFO,
	    sizeof(struct tlvhdr) + sizeof(struct lacp_peerinfo) },
	{ LACP_TYPE_COLLECTORINFO,
	    sizeof(struct tlvhdr) + sizeof(struct lacp_collectorinfo) },
	{ 0, 0 },
};
#endif

int
chgrp_vnb_init(void)
{
	int err;
	char name[NG_NODELEN + 1];

	snprintf(name, sizeof(name), "%s%d", NG_ETH_GRP_LACP_HOOK, getpid());
	err = NgMkSockNode(name, &vnb_csock, &vnb_dsock);
	if (err < 0) {
		DEBUG(LOG_ERR, "unable to get a VNB socket: %s\n",
		      strerror(errno));
		vnb_csock = -1;
		vnb_dsock = -1;
		return err;
	}
#ifdef LACP_NOTIF
	/* Set event for dsock (lacp notifications) */
	/* we can use only one data socket for all hooks, see in
	 * libnetgraph, NgRecvData() */
	DEBUG(LOG_DEBUG,
	        "register event for vnb_dsock %d (%s)\n",
	        vnb_dsock, name);
	event_set(&dsock_evt, vnb_dsock,
		  EV_READ | EV_PERSIST, (void *) notify_ds_lacp, &chgrp_nodes);
	event_add(&dsock_evt, NULL);
#endif
	return err;
}

#ifdef LACP_NOTIF
#ifdef HA_SUPPORT
int
chgrp_lacpdu_dup_init(void)
{
	struct sockaddr_un addr;
	int rx_s, tx_s, len;

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "Entering\n"));

	if (cur_lacp_state.active) {
		/* close existing links */
		event_del (&rx_s_evt);
		if (rx_sock > 0)
			close(rx_sock);
		if (tx_sock > 0)
			close(tx_sock);
		rx_sock = -1;
		tx_sock = -1;

		/* create send socket : to haf-lacp */
		tx_s = socket(AF_UNIX, SOCK_DGRAM, 0);
		if ( tx_s < 0 ) {
			DEBUG(LOG_ERR, "tx_s socket");
			return -1;
		}
		tx_sock = tx_s;
	} else {
		/* close existing links */
		event_del (&rx_s_evt);
		if (rx_sock > 0)
			close(rx_sock);
		if (tx_sock > 0)
			close(tx_sock);
		rx_sock = -1;
		tx_sock = -1;

		/* create receive socket : from haf-lacp */
		rx_s = socket(AF_UNIX, SOCK_DGRAM, 0);
		if ( rx_s < 0 ) {
			DEBUG(LOG_ERR, "rx_s socket");
			return -1;
		}
		/* connect to path_rx */
		memset(&addr,0, sizeof(struct sockaddr_un));
		addr.sun_family = AF_UNIX;
		strncpy(&(addr.sun_path[0]), LACPDU_DUP_RX_PATH, UNIX_PATH_MAX);
		len = strlen(LACPDU_DUP_RX_PATH) + sizeof(addr.sun_family); ;
		unlink(addr.sun_path);
		LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "Binding Rx socket %s\n",
					  LACPDU_DUP_RX_PATH));
		if ( bind(rx_s, (struct sockaddr*)&addr, len) < 0 ) {
			DEBUG(LOG_ERR,"rx_s bind");
			close(rx_s);
			return -1;
		}
		rx_sock = rx_s;

		/* Set event for rx_s : event on packet receive */
		DEBUG(LOG_DEBUG,
				"register event for lacpdu rx sock\n");
		event_set(&rx_s_evt, rx_s,
			  EV_READ | EV_PERSIST, (void *) notify_ds_dup, NULL);
		event_add(&rx_s_evt, NULL);
	}

	return 0;
}
#endif

/*
 * check and process encapsulated lacpdu packets
 */
static void
check_process_lacpdu(void *buf, int len, int dup_pdu)
{
	struct ng_lacp_msg *msg = buf;
	struct chgrp_node *node;
	struct chgrp_link *link;
	struct lacpdu *lacpdu_p;
	struct vnb_ether_header *eh;
	char macbuf[LACP_MACSTR_MAX+1];

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "Entering\n"));

	/* only one vnb_dsock for multiple ethgrp => must demultiplex */
	switch (ntohs(msg->ngr_cmd)) {
		case NGR_RECV_SLOWP_MSG:
			LACP_DPRINTF((LOG_DEBUG, __func__, NULL,
			        "recv'd slowp msg on node %s port %d, len %d (real len %d)\n",
			        msg->ngr_name, ntohs(msg->ngr_port), ntohs(msg->ngr_len), len));
			lacpdu_p = (struct lacpdu *) (buf+sizeof(struct ng_lacp_msg));
			eh = &(lacpdu_p->ldu_eh);

			assert(eh->ether_type == htons(ETH_P_SLOW));
			LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "dst MAC address: %s",
				lacp_format_mac(eh->ether_dhost, macbuf, sizeof(macbuf))));
			LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "src MAC address: %s",
				lacp_format_mac(eh->ether_shost, macbuf, sizeof(macbuf))));

			node = chgrp_node_lookup_by_nodename(msg->ngr_name);
			if (node) {
				link = node->link[ntohs(msg->ngr_port)];
				if (link == NULL) {
					DEBUG(LOG_ERR, "NULL link\n");
					return;
				}
				LACP_DPRINTF((LOG_DEBUG, __func__, link,
			        "found existing node %s\n", msg->ngr_name));
			} else  {
				DEBUG(LOG_ERR, "Unknown node\n");
				return;
			}

			if (link->mode == MODE_LINK_ON)  {
				DEBUG(LOG_ERR, "Received LACPDU on static link\n");
				return;
			}

			/* switch with SUBTYPE */
			if (lacpdu_p->ldu_sph.sph_subtype == SLOWPROTOCOLS_SUBTYPE_LACP) {
				LACP_DPRINTF((LOG_DEBUG, __func__, link, "found LACPDU\n"));

				if (tlv_check(lacpdu_p, sizeof(*lacpdu_p), &lacpdu_p->ldu_tlv_actor,
					    lacp_info_tlv_template, 0)) {
						DEBUG(LOG_ERR, "Bad TLV\n");
						return;
				}
				lacp_dump_lacpdu(lacpdu_p);
#ifdef HA_SUPPORT
				/* duplicate ng_lacp_msg message from active to inactive */
				if (dup_pdu && cur_lacp_state.active) {
					LACP_DPRINTF((LOG_DEBUG, __func__, link,
								  "send dup lacpdu %d\n", len));
					if (tx_sock > 0) {
						int err;
						struct sockaddr_un addr;

						/* forward the lacpdu to the local haf-lacpd */
						memset(&addr,0, sizeof(struct sockaddr_un));
						addr.sun_family = AF_UNIX;
						strncpy(&(addr.sun_path[0]),
								LACPDU_DUP_TX_PATH, UNIX_PATH_MAX);
						/* send errors are not expected */
						err = sendto(tx_sock, (const void *)buf, len, 0,
									 (struct sockaddr *)&addr,
									 sizeof(struct sockaddr_un));
						if (err < 0) {
							LACP_DPRINTF((LOG_DEBUG, __func__, link,
										  "sendto: %s\n", strerror(errno)));
						}
					}
				}
#endif
				/* call LACP state machine */
				lacp_sm_rx(link, lacpdu_p);

			} else if (lacpdu_p->ldu_sph.sph_subtype == SLOWPROTOCOLS_SUBTYPE_MARKER) {
				LACP_DPRINTF((LOG_DEBUG, __func__, link, "found MARKER\n"));
			} else
				LACP_DPRINTF((LOG_DEBUG, __func__, link, "unknown LACPDU subtype %d\n",
					lacpdu_p->ldu_sph.sph_subtype));
			break;
		default:
			LACP_DPRINTF((LOG_DEBUG, __func__, NULL,
			        "recv'd unknown msg %d\n", ntohs(msg->ngr_cmd)));
			break;
	}
	return;
}

/* derived from vnb/tools/snoop/notify.c */
static u_int8_t buf_ds_lacp_read[2048];
/*
 * libevent callback for
 * lacp notifications socket receive
 */
static void
notify_ds_lacp(int fd, short event, void *param)
{
	int len;
	struct ng_lacp_msg *msg =
			(struct ng_lacp_msg *)buf_ds_lacp_read;
	int dup_lacpdu = 0;

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "Entering\n"));
	len = NgRecvData(fd, buf_ds_lacp_read, sizeof(buf_ds_lacp_read), NULL);
	/* check error conditions */
	if (len < 0) {
		DEBUG(LOG_ERR, "NgRecvData: %s\n", strerror(errno));
		return;
	}
	/* no message reassembly needed on datagram socket */
	if (len < sizeof (struct ng_lacp_msg)) {
		DEBUG(LOG_ERR, "msg too short: %d bytes (for %d))\n",
				  len, sizeof(struct ng_lacp_msg));
		return;
	}
	if ( len != (ntohs(msg->ngr_len) + sizeof(struct ng_lacp_msg)) ) {
		DEBUG(LOG_ERR, "msg too long: %d bytes (for %d))\n",
				  len, (ntohs(msg->ngr_len) + sizeof(struct ng_lacp_msg)));
		return;
	}

#ifdef HA_SUPPORT
	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "prep dup lacpdu len = %d\n", len));
	/* duplicate ng_lacp_msg message from active to inactive */
	dup_lacpdu = cur_lacp_state.active;
#endif
	check_process_lacpdu((void *)buf_ds_lacp_read, len, dup_lacpdu);
}

#ifdef HA_SUPPORT
/* derived from vnb/tools/snoop/notify.c */
static u_int8_t buf_ds_dup_read[2048];

/*
 * libevent callback for
 * duplicate lacpdu socket receive
 */
static void
notify_ds_dup(int fd, short event, void *param)
{
	int len;
	struct ng_lacp_msg *msg =
			(struct ng_lacp_msg *)buf_ds_dup_read;

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "Entering\n"));
	len = recv(fd, buf_ds_dup_read, sizeof(buf_ds_dup_read), 0);
	/* check error conditions */
	if (len < 0) {
		DEBUG(LOG_DEBUG, "recv: %s\n", strerror(errno));
		return;
	}
	/* no message reassembly needed on datagram socket */
	if (len < sizeof (struct ng_lacp_msg)) {
		DEBUG(LOG_ERR, "msg too short: %d bytes (for %d))\n",
				  len, sizeof(struct ng_lacp_msg));
		return;
	}
	if ( len != (ntohs(msg->ngr_len) + sizeof(struct ng_lacp_msg)) ) {
		DEBUG(LOG_ERR, "msg too long: %d bytes (for %d))\n",
				  len, (ntohs(msg->ngr_len) + sizeof(struct ng_lacp_msg)));
		return;
	}

	check_process_lacpdu((void *)buf_ds_dup_read, len, 0);
}
#endif /* HA_SUPPORT */

#endif

int
lacp_xmit_lacpdu(struct chgrp_link *link)
{
	struct lacpdu *du;
	int error;
	int sock_lacpdu;
	struct sockaddr_ll dst_addr;
	struct lacpd_iface *iface=NULL;
	struct chgrp_node *node=NULL;
	socklen_t socklen = sizeof(dst_addr);
	struct vnb_ether_header *eh;
	const int lacpdu_len = sizeof(struct lacpdu);

	LACP_DPRINTF((LOG_DEBUG, __func__, link, "Entering\n"));
	if (link->mode == MODE_LINK_ON)  {
		DEBUG(LOG_ERR, "LACPDU send on static link\n");
		return EINVAL;
	}

	du = calloc(1, lacpdu_len);
	if (du == NULL) {
		DEBUG(LOG_ERR, "no mem\n");
		return ENOMEM;
	}
	eh = &(du->ldu_eh);

	iface = lacpd_iface_lookup(link->ifname);
	if (iface == NULL) {
		DEBUG(LOG_ERR, "NULL iface\n");
		free(du);
		return EINVAL;
	}
	if ( (iface->flags & (IFF_RUNNING|IFF_UP)) !=
			 (IFF_RUNNING|IFF_UP) ) {
		DEBUG(LOG_ERR, "Down iface\n");
		free(du);
		return EINVAL;
	}

	node = chgrp_node_lookup_by_link_ifname(link->ifname);
	if (node == NULL) {
		DEBUG(LOG_ERR, "NULL node\n");
		free(du);
		return EINVAL;
	}

	sock_lacpdu = cur_lacp_state.sock_lacpdu; /* find tx socket */
	if (sock_lacpdu <= 0) {
		DEBUG(LOG_ERR, "Bad socket");
		free(du);
		return EINVAL;
	}

	memset((uint8_t *)&dst_addr, 0, socklen);

	dst_addr.sll_family = htons(PF_PACKET);
	dst_addr.sll_protocol = htons(ETH_P_ALL);
	dst_addr.sll_halen = 6;
	/* force the index of the outgoing iface */
	dst_addr.sll_ifindex = iface->k_index;
	memcpy(&(dst_addr.sll_addr), slowp_mc_addr, ETH_ALEN);

	/* reuse dest addresses */
	memcpy(eh->ether_shost, node->ether_addr, ETH_ALEN);
	memcpy(eh->ether_dhost, slowp_mc_addr, ETH_ALEN);
	du->ldu_eh.ether_type = htobe16(ETH_P_SLOW);

	du->ldu_sph.sph_subtype = SLOWPROTOCOLS_SUBTYPE_LACP;
	du->ldu_sph.sph_version = 1;

	TLV_SET(&du->ldu_tlv_actor, LACP_TYPE_ACTORINFO, sizeof(du->ldu_actor));
	du->ldu_actor = link->lp_actor;

	TLV_SET(&du->ldu_tlv_partner, LACP_TYPE_PARTNERINFO,
	    sizeof(du->ldu_partner));
	du->ldu_partner = link->lp_partner;

	TLV_SET(&du->ldu_tlv_collector, LACP_TYPE_COLLECTORINFO,
	    sizeof(du->ldu_collector));
	du->ldu_collector.lci_maxdelay = 0;

	lacp_dump_lacpdu(du);
	if (sendto(sock_lacpdu, (void*)du, lacpdu_len, 0,
				(struct sockaddr *)&dst_addr, socklen) ==-1) {
		DEBUG(LOG_ERR, "Sendto Failure");
		error = EINVAL;
	} else {
		error = 0;
	}
	free(du);

	return error;
}

int
chgrp_node_init(void)
{
	LIST_INIT(&chgrp_nodes);
	return 0;
}

/*
 * Create a new node, return NULL on error and set errno.
 */
struct chgrp_node *
chgrp_node_create(const char *chgrpname, const char *nodename)
{
	struct chgrp_node *new;
	int fd, ret;
	struct ifreq ifr;
	char macbuf[LACP_MACSTR_MAX+1];

	if (chgrp_node_lookup_by_chgrpname(chgrpname) ||
	    chgrp_node_lookup_by_nodename(nodename)) {
		DEBUG(LOG_ERR, "A node with same grpname/nodename already exist\n");
		errno = EEXIST;
		return NULL;
	}

	new = malloc(sizeof(struct chgrp_node));
	if (new == NULL) {
		DEBUG(LOG_ERR, "not enough memory (new)\n");
		errno = ENOMEM;
		return NULL;
	}

	memset(new, 0, sizeof(struct chgrp_node));
	snprintf(new->chgrpname, sizeof(new->chgrpname), "%s", chgrpname);
	LACP_DPRINTF((LOG_DEBUG, __func__, NULL,
		"chgrpname %s\n", new->chgrpname));
	snprintf(new->nodename, sizeof(new->nodename), "%s", nodename);
	LACP_DPRINTF((LOG_DEBUG, __func__, NULL,
		"nodename %s\n", new->nodename));
	new->lacp_rate = LACP_FAST;
	DEBUG(LOG_INFO, "get default lacp rate %s\n",new->lacp_rate==LACP_FAST?"fast":"slow");

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		DEBUG(LOG_ERR, "cannot create socket\n");
		free(new);
		errno = ENOMEM;
		return NULL;
	}
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, chgrpname, IFNAMSIZ-1);
	ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
	if (ret < 0) {
		DEBUG(LOG_ERR, "cannot get HW address\n");
		free(new);
		return NULL;
	}
	ret = close(fd);
	if (ret < 0) {
		DEBUG(LOG_ERR, "cannot close fd\n");
		free(new);
		return NULL;
	}
	memcpy(new->ether_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "%s\n",
         lacp_format_mac(new->ether_addr, macbuf, sizeof(macbuf))));

	new->index = if_nametoindex(chgrpname);
	new->lsc_active_aggregator = NULL;
	TAILQ_INIT(&new->lsc_aggregators);

	LIST_INSERT_HEAD(&chgrp_nodes, new, next);
	return new;
}

/*
 * Push LACP-managed parameters from the internal lacpd MIB to the VNB node
 * (for parameters which were filtered when in graceful restart)
 */
#ifdef HA_SUPPORT
void
chgrp_node_sync_to_vnb_all(void)
{
	struct chgrp_node *node;
	int i;

	if ( cur_lacp_state.graceful ) {
		DEBUG(LOG_ERR, "Sync to VNB while graceful\n");
		return;
	} else {
		DEBUG(LOG_DEBUG, "Sync to VNB after graceful\n");
	}

	LIST_FOREACH(node, &chgrp_nodes, next) {
		node->status = 0;
		for (i = 0; i < NG_ETH_GRP_MAX_LINKS; i++) {
			if (node->link[i]) {
				if(node->link[i]->status == NG_ETH_GRP_HOOK_ACTIVE)
					increase(node);
				chgrp_node_configure_status(node, i, node->link[i]->status);
			}
		}
		/* force running removal if all links are down */
		if (node->status == 0) {
			node->status = 1;
			decrease(node);
		}
	}


}
#endif

struct chgrp_node *
chgrp_node_lookup_by_chgrpname(const char *name)
{
	struct chgrp_node *node;

	LIST_FOREACH(node, &chgrp_nodes, next)
		if (!strncmp(name, node->chgrpname, IFNAMSIZ))
			return node;

	return NULL;
}

struct chgrp_node *
chgrp_node_lookup_by_nodename(const char *name)
{
	struct chgrp_node *node;

	LIST_FOREACH(node, &chgrp_nodes, next)
		if (!strncmp(name, node->nodename, NG_NODELEN))
			return node;

	return NULL;
}

/* find a node owning the link for that ifname */
struct chgrp_node *
chgrp_node_lookup_by_link_ifname(const char *ifname)
{
	struct chgrp_node *node;

	LIST_FOREACH(node, &chgrp_nodes, next) {
		if (chgrp_link_lookup_by_ifname(node, ifname) != NULL) {
			return node;
		}
	}
	return NULL;
}

void chgrp_node_destroy(struct chgrp_node *node)
{
	int i;

	if (node == NULL) {
		DEBUG(LOG_ERR, "Try to free a NULL node\n");
		return;
	}

#ifdef LACP_NOTIF
	/* disconnect vnb node from dsock */
#endif

	LIST_REMOVE(node, next);
	for (i = 0; i < NG_ETH_GRP_MAX_LINKS; i++) {
		if (node->link[i])
		{
			event_del(&node->link[i]->timer_evt);
			free(node->link[i]);
		}
	}
	free(node);
	return;
}

void chgrp_node_destroy_all(void)
{
	struct chgrp_node *node;
	while ( (node = LIST_FIRST(&chgrp_nodes)) ) {
		chgrp_node_destroy(node);
	}
}

/*
 * in the VNB graph, connect the lacp data hook from nodename
 * to the lacpd dsock data socket
 */
int chgrp_node_connect(struct chgrp_node *node)
{
#ifdef LACP_NOTIF
	struct ngm_connect ngc;
	int err = 0;

	/* be careful when sending the connect message, at this
	 * time the node may node exist */
	if (vnb_csock == -1) {
		DEBUG(LOG_ERR, "channel group %s with node %s does not exist\n",
		      node->chgrpname, node->nodename);
		return -1;
	}

	snprintf(ngc.path, sizeof(ngc.path), "%s:", node->nodename);
	snprintf(ngc.ourhook, sizeof(ngc.ourhook), "%s", node->nodename);
	snprintf(ngc.peerhook, sizeof(ngc.peerhook), NG_ETH_GRP_LACP_HOOK);
	err = NgSendMsg(vnb_csock, ".", NGM_GENERIC_COOKIE,
			NGM_CONNECT, &ngc, sizeof(ngc));
	if (err < 0) {
		DEBUG(LOG_ERR, "unable to connect to channel group %s through node %s\n",
		      node->chgrpname, node->nodename);
		return -1;
	}
#endif
	return 0;
}

/*
 * in the VNB graph, configure the activity state for one link
 */
int chgrp_node_configure_status(struct chgrp_node *node, int linknum, int status)
{
	int error = 0;
	char path[NG_PATHLEN + 1];
	struct ng_ethgrp_set_hook_mode hm;

#ifdef HA_SUPPORT
	if (cur_lacp_state.graceful)
		return error;
#endif

	snprintf(path, sizeof(path), "%s:", node->nodename);
	memset(&hm, 0, sizeof(hm));
	hm.id = linknum;
	hm.mode = status;
	LACP_DPRINTF((LOG_DEBUG, __func__, NULL,
		 "hm.id=%d, hm.mode=%d\n ", hm.id, hm.mode));

	error = NgSendMsg(vnb_csock, path, NGM_ETH_GRP_COOKIE,
			  NGM_ETH_GRP_SET_HOOK_MODE, &hm, sizeof(hm));

	if (error < 0)
		DEBUG(LOG_ERR, "Error in NgSendMsg(id=%d mode=%d)\n",
			 hm.id, hm.mode);
	return error;
}

/*
 * in the VNB graph, configure the distribution algorithm for one ethgrp
 */
int chgrp_node_configure_algo(struct chgrp_node *node, int algo)
{
	int error = 0;
	char path[NG_PATHLEN + 1];
	const char * str = "unknown";

#ifdef HA_SUPPORT
	if (cur_lacp_state.graceful)
		return error;
#endif

	snprintf(path, sizeof(path), "%s:", node->nodename);
	if (algo == NG_ETH_GRP_ALGO_ROUND_ROBIN)
		str = "rr";
	else if(algo == NG_ETH_GRP_ALGO_XOR_MAC)
		str = "xmac";
	else if(algo == NG_ETH_GRP_ALGO_XOR_IP)
		str = "xip";
	else if(algo == NG_ETH_GRP_ALGO_BACKUP)
		str = "backup";
	else if(algo == NG_ETH_GRP_ALGO_XOR_IP_PORT)
		str = "xipport";
	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "str=%s\n ", str));

	error = NgSendMsg(vnb_csock, path, NGM_ETH_GRP_COOKIE,
			  NGM_ETH_GRP_SET_ALGO, str, strlen(str)+1);

	if (error < 0)
		DEBUG(LOG_ERR, "Error in NgSendMsg (str=%s)\n", str);

	return error;
}

/*
 * in the VNB graph, configure the priority for one link
 */
int chgrp_node_configure_prio(struct chgrp_node *node, int linknum, int prio)
{
	int error = 0;
	char path[NG_PATHLEN + 1];
	struct ng_ethgrp_set_hook_prio hp;

#ifdef HA_SUPPORT
	if (cur_lacp_state.graceful)
		return error;
#endif

	snprintf(path, sizeof(path), "%s:", node->nodename);
	memset(&hp, 0, sizeof(hp));
	hp.id = linknum;
	hp.priority = prio;
	LACP_DPRINTF((LOG_DEBUG, __func__, NULL,
		"hp.id=%d,hp.priority=%d\n ", hp.id,hp.priority));

	error = NgSendMsg(vnb_csock, path, NGM_ETH_GRP_COOKIE,
			  NGM_ETH_GRP_SET_HOOK_PRIO, &hp, sizeof(hp));

	if (error < 0)
		DEBUG(LOG_ERR, "Error in NgSendMsg(id=%d priority=%d)\n",
			 hp.id, hp.priority);

	return error;
}

/*
 * in the VNB graph, configure the MAC address for one ethgrp
 */
int chgrp_node_configure_mac(struct chgrp_node *node)
{
	int error = 0;
	char path[NG_PATHLEN + 1];
	char macbuf[LACP_MACSTR_MAX+1];

#ifdef HA_SUPPORT
	if (cur_lacp_state.graceful)
		return error;
#endif

	snprintf(path, sizeof(path), "%s:", node->nodename);

	error = NgSendMsg(vnb_csock, path, NGM_ETH_GRP_COOKIE,
			  NGM_ETH_GRP_SET_ENADDR, node->ether_addr, VNB_ETHER_ADDR_LEN);

	if (error < 0) {
		lacp_format_mac(node->ether_addr, macbuf, sizeof(macbuf));
		DEBUG(LOG_ERR, "Error in NgSendMsg (macbuf=%s)\n", macbuf);
	}

	return error;
}

int chgrp_node_configure_lacprate(struct chgrp_node *node)
{
	struct chgrp_link *link;
	int i;

	for (i = 0; i < NG_ETH_GRP_MAX_LINKS; i ++) {
		link = node->link[i];
		if (link == NULL)
			continue;
		if (!(link->lp_state & LACP_STATE_TIMEOUT) && (node->lacp_rate == LACP_FAST)) {
			link->lp_state |= LACP_STATE_TIMEOUT;
			lacp_sm_rx_set_expired(link);
			DEBUG(LOG_DEBUG, "link %s change to fast\n", link->ifname);
		} else if ((link->lp_state & LACP_STATE_TIMEOUT) && (node->lacp_rate == LACP_SLOW)) {
			link->lp_state &= ~LACP_STATE_TIMEOUT;
			lacp_sm_rx_set_expired(link);
			DEBUG(LOG_DEBUG, "link %s change to slow\n", link->ifname);
		}
	}
	return 0;
}
/* Create a new link on a node and return a pointer to it. Return NULL
 *  on error and set errno */
struct chgrp_link *
chgrp_link_create(struct chgrp_node *node, int linknum, const char *ifname)
{
	struct chgrp_link * link;
	struct timeval tv;
	struct lacpd_iface *iface = NULL;

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "starting for %s\n", ifname));

	if (linknum < 0 || linknum >= NG_ETH_GRP_MAX_LINKS) {
		errno = EINVAL;
		return NULL;
	}
	if (node->link[linknum] != NULL) {
		errno = EEXIST;
		return NULL;
	}
	if (chgrp_node_lookup_by_link_ifname(ifname) != NULL) {
		errno = EEXIST;
		return NULL;
	}

	link = calloc(1, sizeof(struct chgrp_link));
	if (link == NULL) {
		return NULL;
	}
	node->link_count++;
	snprintf(link->ifname, sizeof(link->ifname), "%s", ifname);

	/* lookup iface */
	iface = lacpd_iface_lookup(ifname);
	if (iface != NULL) {
		DEBUG(LOG_DEBUG, "creating link for %s (%s)\n", ifname, link->ifname);
		link->iface = iface;
		link->lp_actor.lip_portid.lpi_portno = htobe16(iface->portid);
		link->lp_state = LACP_STATE_ACTIVITY | LACP_STATE_AGGREGATION;
	} else {
		DEBUG(LOG_DEBUG, "missing ifname %s\n", ifname);
	}

	if (node->lacp_rate == LACP_FAST)
		link->lp_state |= LACP_STATE_TIMEOUT;

	link->lp_actor.lip_systemid.lsi_prio = htobe16(LACP_SYSTEM_PRIO);
	memcpy(&link->lp_actor.lip_systemid.lsi_mac, node->ether_addr, ETH_ALEN);
	link->lp_actor.lip_portid.lpi_prio = htobe16(LACP_PORT_PRIO);
	link->lp_actor.lip_key = lacp_compose_key(link, node);
	link->lp_mux_state = LACP_MUX_DETACHED;
	lacp_sm_rx_set_expired(link);

	link->linknum = linknum;
	node->link[linknum] = link;

	/* Set event for timers (periodic LACPDU) */
	LACP_DPRINTF((LOG_DEBUG, __func__, link,
	        "register event for per-link timer %d\n",
	        linknum));
	event_set(&link->timer_evt, -1,
		  EV_TIMEOUT, (void *) ieee8023ad_lacp_porttick, link);
	timerclear(&tv);
	assert(LACP_TICK_HZ >= 1);
	tv.tv_usec=(1000L*1000L)/LACP_TICK_HZ; /* start tick timer */
	event_add(&link->timer_evt, &tv);

	return link;
}

/* return 0 on success */
int
chgrp_link_free(struct chgrp_node *node, int linknum)
{
	if (linknum < 0 || linknum >= NG_ETH_GRP_MAX_LINKS)
		return -1;
	if (node->link[linknum] == NULL)
		return -1;
	node->link_count--;
	if(node->link[linknum]->status == NG_ETH_GRP_HOOK_ACTIVE)
		decrease(node);
	event_del(&node->link[linknum]->timer_evt);
	free(node->link[linknum]);
	node->link[linknum] = NULL;
	return 0;
}


/* return a pointer to the link matching that ifname, or NULL */
struct chgrp_link *
chgrp_link_lookup_by_ifname(const struct chgrp_node *node, const char *ifname)
{
	int i;
	struct chgrp_link *link;
	for (i=0; i<NG_ETH_GRP_MAX_LINKS; i++) {
		link = node->link[i];
		if (link && !strncmp(link->ifname, ifname, IFNAMSIZ)) {
			return link;
		}
	}
	return NULL;
}

/*
 * in the VNB graph, connect one link to a ethgrp
 * (normally done by XMS)
 */
int
chgrp_link_connect(struct chgrp_node *node, struct chgrp_link *link)
{
#ifdef LACPD_STANDALONE
	struct ngm_connect ngc;
	char path[NG_NODELEN+1];
	int err = 0;

	DEBUG(LOG_ERR, "%s()\n", __FUNCTION__);

	snprintf(path, sizeof(path), "%s:", node->nodename);
	snprintf(ngc.path, sizeof(ngc.path), "%s:", link->ifname);
	snprintf(ngc.ourhook, sizeof(ngc.ourhook), NG_ETH_GRP_HOOK_LINK_FMT, link->linknum);
	snprintf(ngc.peerhook, sizeof(ngc.peerhook), NG_ETHER_HOOK_LOWER);
	err = NgSendMsg(vnb_csock, path, NGM_GENERIC_COOKIE,
			NGM_CONNECT, &ngc, sizeof(ngc));
	if (err < 0) {
		DEBUG(LOG_ERR, "connect %s%s to %s%s failed\n",
		      path, ngc.ourhook, ngc.path, ngc.peerhook);
	}
	return err;
#else
	return 0;
#endif
}

int set_running_flag(char *name, int flags)
{
#ifdef IFLA_RUNNING
	unsigned int running = 0;
	struct ifinfomsg i;
	int err = -1;
	struct nl_msg *msg = NULL;

	memset(&i, 0, sizeof(i));
	i.ifi_family = AF_UNSPEC;

	if (flags & IFF_RUNNING)
		running |= IFF_RUNNING;
	else
		running &= ~IFF_RUNNING;

	i.ifi_index = if_nametoindex(name);
	if (i.ifi_index == 0) {
		DEBUG(LOG_ERR, "Cannot find device %s: %s\n", name, __FUNCTION__);
		return -1;
	}

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST);
	if (nlmsg_append(msg, &i, sizeof(i), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	NLA_PUT(msg, IFLA_RUNNING, sizeof(running), &running);

	err = nl_send_sync(nl_csock, msg);
	if (err < 0) {
		DEBUG(LOG_ERR, "Cannot send netlink %s: %s\n", name, __FUNCTION__);
	}

	msg = NULL;

nla_put_failure:

	nlmsg_free(msg);
	return err;
#else
	return -1;
#endif /* IFLA_RUNNING */
}

void increase(struct chgrp_node *node)
{
#ifdef HA_SUPPORT
	if (cur_lacp_state.graceful)
		return;
#endif

	if(++node->status == 1) {
		LACP_DPRINTF((LOG_DEBUG, __func__, NULL,
					  "set %s running on", node->chgrpname));
		if (set_running_flag(node->chgrpname, IFF_RUNNING) < 0)
			DEBUG(LOG_ERR, "set %s running flag on failed: %s\n", node->chgrpname, __FUNCTION__);
	}
	return;
}

void decrease(struct chgrp_node *node)
{
#ifdef HA_SUPPORT
	if (cur_lacp_state.graceful)
		return;
#endif

	if(--node->status == 0) {
		LACP_DPRINTF((LOG_DEBUG, __func__, NULL,
					  "set %s running off", node->chgrpname));
		set_running_flag(node->chgrpname, 0);
		if (set_running_flag(node->chgrpname, ~IFF_RUNNING) < 0)
			DEBUG(LOG_ERR, "set %s running flag off failed: %s\n", node->chgrpname, __FUNCTION__);
	}
	return;
}

/*
 * lacp_select_active_aggregator: select an aggregator to be used to transmit
 * packets from agr(4) interface.
 */
static void
lacp_select_active_aggregator(struct chgrp_node *lsc)
{
	struct lacp_aggregator *la;
	struct lacp_aggregator *best_la = NULL;
	char buf[LACP_LAGIDSTR_MAX+1];

	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "Entering\n"));

	TAILQ_FOREACH(la, &lsc->lsc_aggregators, la_q) {

		if (la->la_nports == 0) {
			continue;
		}

		if (la == lsc->lsc_active_aggregator) {
			best_la = la;
		}
	}

	assert(best_la == NULL || best_la->la_nports > 0);
	assert(best_la == NULL || !TAILQ_EMPTY(&best_la->la_ports));

	if (lsc->lsc_active_aggregator != best_la) {
		LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "active aggregator changed\n"));
		LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "old %s\n",
		    lacp_format_lagid_aggregator(lsc->lsc_active_aggregator,
		    buf, sizeof(buf))));
	} else {
		LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "active aggregator not changed\n"));
	}
	LACP_DPRINTF((LOG_DEBUG, __func__, NULL, "new %s\n",
	    lacp_format_lagid_aggregator(best_la, buf, sizeof(buf))));

	if (lsc->lsc_active_aggregator != best_la) {
		lsc->lsc_active_aggregator = best_la;
#if notyet
		if (best_la) {
			lacp_suppress_distributing(lsc, best_la);
		}
#endif /* notyet */
	}
}

static uint16_t
lacp_compose_key(struct chgrp_link *link, struct chgrp_node * node)
{
	uint16_t key;

	LACP_DPRINTF((LOG_DEBUG, __func__, link, "Entering\n"));
	assert(link != NULL);
	if (!(link->lp_actor.lip_state & LACP_STATE_AGGREGATION)) {

		/*
		 * non-aggregatable links should have unique keys.
		 *
		 */

		assert(link->iface != NULL);
		/* bit 0..14:	(some bits of) if_index of this port */
		key = link->iface->portid;
		/* bit 15:	1 */
		key |= 0x8000;
	} else {
		/* bit 0..4:	IFM_SUBTYPE */
		assert(node != NULL);
		/* use some bits of the node MAC address */
		key = (node->ether_addr[ETH_ALEN-1] & 0x1f);
		/* bit 5..14:	(some bits of) if_index of agr device */
		key = 0x7fe0 & ((node->index) << 5);
		/* bit 15:	0 */
	}

	return htobe16(key);
}

/*
 * libevent callback for
 * lacp timer expiration
 */
static void
ieee8023ad_lacp_porttick(int fd, short event, void *arg)
{
	struct chgrp_link *lp = arg;
	struct event *ev = &lp->timer_evt;
	struct timeval tv;

	if (lp->mode != MODE_LINK_ON) {
#if defined(LACP_DEBUG_1)
		LACP_DPRINTF((LOG_DEBUG, __func__, lp,
				"timer callback for link %d\n",
				lp->linknum));
#endif

		lacp_run_timers(lp);

		lacp_select(lp);
		lacp_sm_mux(lp);
		if (lp->mode == MODE_LINK_LACP_ACTIVE)  {
			lacp_sm_tx(lp);
		}
		lacp_sm_ptx_tx_schedule(lp);
	}

	timerclear(&tv);
	tv.tv_usec=(1000L*1000L)/LACP_TICK_HZ; /* restart tick timer */
	event_add(ev, &tv);
}

/* -------------------- */
void
lacp_disable_collecting(struct chgrp_link *lp)
{
	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));
	assert(lp != NULL);
	assert(lp->mode != MODE_LINK_ON);
	lp->lp_state &= ~LACP_STATE_COLLECTING;
}

void
lacp_enable_collecting(struct chgrp_link *lp)
{
	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));
	assert(lp != NULL);
	assert(lp->mode != MODE_LINK_ON);
	lp->lp_state |= LACP_STATE_COLLECTING;
}

void
lacp_disable_distributing(struct chgrp_link *lp)
{
	struct lacp_aggregator *la = lp->lp_aggregator;
	struct chgrp_node *lsc = chgrp_node_lookup_by_link_ifname(lp->ifname);
	char buf[LACP_LAGIDSTR_MAX+1];

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));
	assert(lp != NULL);
	/* check : only work on LACP-managed links */
	assert(lp->mode != MODE_LINK_ON);

	/* notice link becomes inactive */
	if(lp->status == NG_ETH_GRP_HOOK_ACTIVE)
		decrease(lsc);
	lp->status = NG_ETH_GRP_HOOK_INACTIVE;
	chgrp_node_configure_status(lsc, lp->linknum, lp->status);

	if ((lp->lp_state & LACP_STATE_DISTRIBUTING) == 0) {
		return;
	}
	assert(la != NULL);
	assert(!TAILQ_EMPTY(&la->la_ports));

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "disable distributing on aggregator %s, "
	    "nports %d -> %d\n",
	    lacp_format_lagid_aggregator(la, buf, sizeof(buf)),
	    la->la_nports, la->la_nports - 1));

	TAILQ_REMOVE(&la->la_ports, lp, lp_dist_q);

	la->la_nports--;

#if notyet
	lacp_suppress_distributing(node, la);
#endif

	lp->lp_state &= ~LACP_STATE_DISTRIBUTING;

	if (lsc->lsc_active_aggregator == la) {
		lacp_select_active_aggregator(lsc);
	}
}

void
lacp_enable_distributing(struct chgrp_link *lp)
{
	struct lacp_aggregator *la = lp->lp_aggregator;
	struct chgrp_node *lsc = chgrp_node_lookup_by_link_ifname(lp->ifname);
	char buf[LACP_LAGIDSTR_MAX+1];

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "Entering\n"));
	assert(lp != NULL);
	/* check : only work on LACP-managed links */
	assert(lp->mode != MODE_LINK_ON);
	if ((lp->lp_state & LACP_STATE_DISTRIBUTING) != 0) {
		return;
	}
	assert(la != NULL);

	LACP_DPRINTF((LOG_DEBUG, __func__, lp, "enable distributing on aggregator %s, "
	    "nports %d -> %d\n",
	    lacp_format_lagid_aggregator(la, buf, sizeof(buf)),
	    la->la_nports, la->la_nports + 1));

	assert(la->la_refcnt > la->la_nports);
	TAILQ_INSERT_HEAD(&la->la_ports, lp, lp_dist_q);

	/* notice link becomes active */
	if(lp->status == NG_ETH_GRP_HOOK_INACTIVE)
		increase(lsc);
	lp->status = NG_ETH_GRP_HOOK_ACTIVE;
	chgrp_node_configure_status(lsc, lp->linknum, lp->status);

	la->la_nports++;

#if notyet
	lacp_suppress_distributing(node, la);
#endif

	lp->lp_state |= LACP_STATE_DISTRIBUTING;

	if (lsc->lsc_active_aggregator != la) {
		lacp_select_active_aggregator(lsc);
	}
}

int netlink_csock_init(int nl_csockbufsiz)
{
	nl_csock = nl_socket_alloc();
	if (!nl_csock)
		return -1;

	if (nl_connect(nl_csock, NETLINK_ROUTE) < 0) {
		nl_socket_free(nl_csock);
		nl_csock = NULL;
		return -1;
	}
	/*change netlink csock buffersize*/
	setsockopt(nl_socket_get_fd(nl_csock), SOL_SOCKET, SO_RCVBUF,
			&nl_csockbufsiz, sizeof(nl_csockbufsiz));

	return 0;
}

int netlink_csock_close(void)
{
	if (nl_csock) {
		nl_socket_free(nl_csock);
		nl_csock = NULL;
	}
	return 0;
}
