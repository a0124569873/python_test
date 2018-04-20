/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *
 *          FPM message  brewing
 *
 * $Id:
 ***************************************************************
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>

#include <net/if.h>
#include <netinet/in.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/mroute6.h>
#include <linux/xfrm.h>

#include "fpc.h"
#include "cm_priv.h"
#include "cm_pub.h"
#include "cm_ipsec_pub.h"

/* from ports/include/netinet/in.h */
#ifndef IN_LOCAL_MULTICAST
#define IN_LOCAL_MULTICAST(a)	((((in_addr_t)(a)) & 0xffffff00) == 0xe0000000)
#endif

static void
cm_expand_mask (u_int8_t len, u_int8_t *msk)
{
	static u_int8_t __msk[8] = {0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe};
	int i;

	if (len > 32)
		len = 32;
	for (i=0; i<4 ; i++) {
		if (len >= 8) {
			len -=8;
			msk[i] = 0xff;
		}
		else {
			msk[i] = __msk[len];
			len = 0;
		}
	}
}

int
cm2cp_reset (u_int16_t v_maj, u_int16_t v_min)
{
	struct cp_hdr *hdr;
	struct cp_reset *rst;
	int len;

	len = sizeof(*rst);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_type = htonl (CMD_RESET);
	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);

	rst = (struct cp_reset *)(hdr + 1);
	rst->cp_reset_appid = htonl(Appid_CM);
	rst->cp_reset_major = htons (v_maj);
	rst->cp_reset_minor = htons (v_min);

	/* only use post_msgack() for reset and flush commands (or
	 * update fpm) */
	post_msg (hdr);
	return 0;
}

int
cm2cp_flush (void)
{
	struct cp_hdr *hdr;
	int len = 0;

	CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_type = htonl (CMD_FLUSH);
	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (0);

	/* only use post_msgack() for reset and flush commands (or
	 * update fpm) */
	post_msg (hdr);
	return 0;
}

int
cm2cp_graceful_restart (u_int32_t gr_type)
{
	struct cp_hdr *hdr;
	struct cp_graceful_restart *gr;
	int len;

	len = sizeof(*gr);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_type = htonl (CMD_GRACEFUL_RESTART);
	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);

	gr = (struct cp_graceful_restart *)(hdr + 1);
	gr->gr_type = htonl(gr_type);

	post_msg (hdr);
	return 0;
}

int cm2cp_vrf_del(int vrfid)
{
	struct cp_hdr *hdr;
	int *cp_vrfid;
	int len = sizeof(int);

	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_cookie = 0;
	hdr->cphdr_type = htonl(CMD_VRF_DELETE);

	cp_vrfid = (int *)(hdr + 1);
	*cp_vrfid = htonl(vrfid);

	post_msg(hdr);
	return 0;
}

/*
 * Send a CMD_IF_CREATE/CMD_IF_DELETE message to FPM
 */
int
cm2cp_iface_create (u_int32_t cookie, u_int32_t cmd, struct cm_iface *ifp)
{
	struct cp_hdr *hdr;
	struct cp_iface_create *ifc;
	struct cm_eth_params *params;
	int len;

	len = sizeof (*ifc);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	ifc = (struct cp_iface_create *)(hdr + 1);
	params = (struct cm_eth_params *)(ifp + 1);

	ifc->cpiface_ifuid = ifp->ifuid;
	ifc->cpiface_vrfid = htonl(ifp->vrfid);
	memcpy(ifc->cpiface_ifname, ifp->ifname, CM_IFNAMSIZE);

	if (cmd == RTM_NEWLINK)  {
		hdr->cphdr_type = htonl (CMD_IF_CREATE);

		ifc->cpiface_mtu     = htonl (ifp->mtu);
		ifc->cpiface_vnb_nodeid = htonl (ifp->vnb_nodeid);
		ifc->cpiface_maclen  = htonl (params->maclen);
		memcpy(ifc->cpiface_mac, params->mac, params->maclen);
	} else {
		hdr->cphdr_type = htonl (CMD_IF_DELETE);

		ifc->cpiface_vnb_keep_node = ifp->vnb_keep_node;
	}

	ifc->cpiface_type    = htonl (ifp->type);
	ifc->cpiface_subtype = htonl (ifp->subtype);

	post_msg (hdr);
	return 0;
}

/*
 * Send a CMD_IF_CREATE/CMD_IF_DELETE message to FPM
 */
int
cm2cp_svti_create (u_int32_t cookie, u_int32_t cmd, struct cm_iface *ifp)
{
	struct cp_hdr *hdr;
	struct cp_iface_create *ifc;
	int len;

	len = sizeof (*ifc);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	ifc = (struct cp_iface_create *)(hdr + 1);

	ifc->cpiface_ifuid = ifp->ifuid;
	ifc->cpiface_vrfid = htonl(ifp->vrfid);
	memcpy(ifc->cpiface_ifname, ifp->ifname, CM_IFNAMSIZE);

	if (cmd == RTM_NEWLINK)  {
		hdr->cphdr_type  = htonl (CMD_IF_CREATE);
		ifc->cpiface_mtu = htonl (ifp->mtu);
	} else
		hdr->cphdr_type = htonl (CMD_IF_DELETE);

	ifc->cpiface_type    = htonl (ifp->type);
	ifc->cpiface_subtype = htonl (ifp->subtype);

	post_msg (hdr);
	return 0;
}

/*
 * Send a CMD_XIN4_CREATE/CMD_XIN4_DELETE message to FPM
 */
int
cm2cp_6in4_create (u_int32_t cookie, u_int32_t cmd, struct cm_iface *ifp)
{
	struct cp_hdr *hdr;
	struct cp_6in4 *ifc;
	struct cm_6in4_params *params;
	int len;

	len = sizeof (*ifc);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	ifc = (struct cp_6in4 *)(hdr + 1);
	params = (struct cm_6in4_params *)(ifp + 1);

	ifc->cpxin4_ifuid = ifp->ifuid;
	ifc->cpxin4_vrfid = htonl(ifp->vrfid);
	ifc->cpxin4_linkvrfid = htonl(ifp->linkvrfid);
	memcpy(ifc->cpxin4_ifname, ifp->ifname, CM_IFNAMSIZE);

	if (cmd == RTM_NEWLINK)  {
		hdr->cphdr_type = htonl (CMD_XIN4_CREATE);
	} else if (cmd == RTM_DELLINK) {
		hdr->cphdr_type = htonl (CMD_XIN4_DELETE);
	} else {
		hdr->cphdr_type = htonl (CMD_XIN4_UPDATE);
	}

	ifc->cpxin4_mtu     = htonl (ifp->mtu);
	ifc->cpxin4_ttl     = params->ttl;
	ifc->cpxin4_tos     = params->tos;
	ifc->cpxin4_inh_tos = params->inh_tos;
	memcpy(&ifc->cpxin4_local,  &params->local,  sizeof(struct in_addr));
	memcpy(&ifc->cpxin4_remote, &params->remote, sizeof(struct in_addr));

	post_msg (hdr);
	return 0;
}

/*
 * Send a CMD_XIN6_CREATE/CMD_XIN6_DELETE message to FPM
 */
int
cm2cp_Xin6_create (u_int32_t cookie, u_int32_t cmd, struct cm_iface *ifp)
{
	struct cp_hdr *hdr;
	struct cp_xin6 *ifc;
	struct cm_Xin6_params *params;
	int len;

	len = sizeof (*ifc);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	ifc = (struct cp_xin6 *)(hdr + 1);
	params = (struct cm_Xin6_params *)(ifp + 1);

	ifc->cpxin6_ifuid = ifp->ifuid;
	ifc->cpxin6_vrfid = htonl(ifp->vrfid);
	ifc->cpxin6_linkvrfid = htonl(ifp->linkvrfid);
	memcpy(ifc->cpxin6_ifname, ifp->ifname, CM_IFNAMSIZE);

	if (cmd == RTM_NEWLINK)  {
		hdr->cphdr_type = htonl (CMD_XIN6_CREATE);
	} else if (cmd == RTM_DELLINK) {
		hdr->cphdr_type = htonl (CMD_XIN6_DELETE);
	} else {
		hdr->cphdr_type = htonl (CMD_XIN6_UPDATE);
	}

	ifc->cpxin6_mtu     = htonl (ifp->mtu);
	ifc->cpxin6_hoplim  = params->hoplim;
	ifc->cpxin6_tos     = params->tos;
	ifc->cpxin6_inh_tos = params->inh_tos;
	memcpy(&ifc->cpxin6_local,  &params->local,  sizeof(struct in6_addr));
	memcpy(&ifc->cpxin6_remote, &params->remote, sizeof(struct in6_addr));

	post_msg (hdr);
	return 0;
}

/*
 * Send a CMD_SVTI_CREATE/CMD_SVTI_DELETE message to FPM
 */
int
cm2cp_vti_create (u_int32_t cookie, u_int32_t cmd, struct cm_iface *ifp)
{
	struct cp_hdr *hdr;
	struct cp_svti *ifc;
	struct cm_vti_params *params;
	int len;

	len = sizeof (*ifc);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	ifc = (struct cp_svti *)(hdr + 1);
	params = (struct cm_vti_params *)(ifp + 1);

	ifc->cpsvti_ifuid = ifp->ifuid;
	ifc->cpsvti_vrfid = htonl(ifp->vrfid);
	ifc->cpsvti_linkvrfid = htonl(ifp->linkvrfid);
	memcpy(ifc->cpsvti_ifname, ifp->ifname, CM_IFNAMSIZE);

	if (cmd == RTM_NEWLINK)  {
		hdr->cphdr_type = htonl (CMD_SVTI_CREATE);
	} else if (cmd == RTM_DELLINK) {
		hdr->cphdr_type = htonl (CMD_SVTI_DELETE);
	}

	ifc->cpsvti_mtu     = htonl (ifp->mtu);
	memcpy(&ifc->cpsvti_local,  &params->local,  sizeof(struct in_addr));
	memcpy(&ifc->cpsvti_remote, &params->remote, sizeof(struct in_addr));

	post_msg (hdr);
	return 0;
}

#ifdef CONFIG_CACHEMGR_VXLAN
/*
 * Send a CMD_VXLAN_CREATE/CMD_VXLAN_DELETE message to FPM
 */
int cm2cp_vxlan_create(u_int32_t cookie, u_int32_t cmd, struct cm_iface *ifp)
{
	struct cp_hdr *hdr;
	struct cp_vxlan *ifc;
	struct cm_eth_params *eth_params;
	struct cm_vxlan_params *params;
	int len;

	len = sizeof (*ifc);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	ifc = (struct cp_vxlan *)(hdr + 1);
	eth_params = (struct cm_eth_params *)(ifp + 1);
	params = (struct cm_vxlan_params *)(eth_params + 1);

	ifc->cpvxlan_ifuid = ifp->ifuid;
	ifc->cpvxlan_vrfid = htonl(ifp->vrfid);
	ifc->cpvxlan_mtu = htonl(ifp->mtu);
	memcpy(ifc->cpvxlan_ifname, ifp->ifname, CM_IFNAMSIZE);
	ifc->cpvxlan_vnb_nodeid = htonl(ifp->vnb_nodeid);
	ifc->cpvxlan_maclen  = htonl(eth_params->maclen);
	memcpy(ifc->cpvxlan_mac, eth_params->mac, eth_params->maclen);

	ifc->cpvxlan_vni = htonl(params->vni);
	ifc->cpvxlan_linkifuid = params->link_ifuid;
	if (params->gw4) {
		ifc->cpvxlan_gwfamily = AF_INET;
		memcpy(&ifc->cpvxlan_gw.gw4, params->gw4,
		       sizeof(ifc->cpvxlan_gw.gw4));
	} else if (params->gw6) {
		ifc->cpvxlan_gwfamily = AF_INET6;
		memcpy(&ifc->cpvxlan_gw.gw6, params->gw6,
		       sizeof(ifc->cpvxlan_gw.gw6));
	}
	if (params->saddr4) {
		ifc->cpvxlan_saddrfamily = AF_INET;
		memcpy(&ifc->cpvxlan_saddr.saddr4, params->saddr4,
		       sizeof(ifc->cpvxlan_saddr.saddr4));
	} else if (params->saddr6) {
		ifc->cpvxlan_saddrfamily = AF_INET6;
		memcpy(&ifc->cpvxlan_saddr.saddr6, params->saddr6,
		       sizeof(ifc->cpvxlan_saddr.saddr6));
	}
	/* ports are already in network order */
	ifc->cpvxlan_dstport = params->dst_port;
	ifc->cpvxlan_srcminport = params->src_minport;
	ifc->cpvxlan_srcmaxport = params->src_maxport;
	ifc->cpvxlan_ttl = params->ttl;
	ifc->cpvxlan_tos = params->tos;
	if (params->flags & CP_VXLAN_IFACE_F_LEARN)
		ifc->cpvxlan_flags |= FPM_VXLAN_IFACE_F_LEARN;

	if (cmd == RTM_NEWLINK)
		hdr->cphdr_type = htonl (CMD_VXLAN_CREATE);
	else if (cmd == RTM_DELLINK)
		hdr->cphdr_type = htonl (CMD_VXLAN_DELETE);

	post_msg (hdr);
	return 0;
}
#endif

#ifdef CONFIG_CACHEMGR_VLAN
/*
 * Send a CMD_VLAN_CREATE/CMD_VLAN_DELETE message to FPM
 */
int cm2cp_vlan_create(u_int32_t cookie, u_int32_t cmd, struct cm_iface *ifp)
{
	struct cp_hdr *hdr;
	struct cp_vlan *ifc;
	struct cm_eth_params *eth_params;
	struct cm_vlan_params *params;
	int len;

	len = sizeof (*ifc);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	ifc = (struct cp_vlan *)(hdr + 1);
	eth_params = (struct cm_eth_params *)(ifp + 1);
	params = (struct cm_vlan_params *)(eth_params + 1);

	ifc->cpvlan_ifuid = ifp->ifuid;
	ifc->cpvlan_vrfid = htonl(ifp->vrfid);
	ifc->cpvlan_mtu = htonl(ifp->mtu);
	memcpy(ifc->cpvlan_ifname, ifp->ifname, CM_IFNAMSIZE);
	ifc->cpvlan_vnb_nodeid = htonl(ifp->vnb_nodeid);
	ifc->cpvlan_maclen  = htonl(eth_params->maclen);
	memcpy(ifc->cpvlan_mac, eth_params->mac, eth_params->maclen);

	ifc->cpvlan_vlanid = htons(params->vlan_id);
	ifc->cpvlan_flags = params->flags;
	ifc->cpvlan_lower_ifuid = params->lower_ifuid;

	if (cmd == RTM_NEWLINK)
		hdr->cphdr_type = htonl (CMD_VLAN_CREATE);
	else if (cmd == RTM_DELLINK)
		hdr->cphdr_type = htonl (CMD_VLAN_DELETE);

	post_msg (hdr);
	return 0;
}
#endif

#ifdef CONFIG_CACHEMGR_MACVLAN
/*
 * Send a CMD_MACVLAN_CREATE/CMD_MACVLAN_DELETE/CMD_MACVLAN_UPDATE message to FPM
 */
int cm2cp_macvlan_create(u_int32_t cookie, u_int32_t cmd, struct cm_iface *ifp)
{
	struct cp_hdr *hdr;
	struct cp_macvlan *ifc;
	struct cm_eth_params *eth_params;
	struct cm_macvlan_params *params;
	int len;

	len = sizeof (*ifc);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	ifc = (struct cp_macvlan *)(hdr + 1);
	eth_params = (struct cm_eth_params *)(ifp + 1);
	params = (struct cm_macvlan_params *)(eth_params + 1);

	ifc->cpmacvlan_ifuid = ifp->ifuid;
	ifc->cpmacvlan_vrfid = htonl(ifp->vrfid);
	ifc->cpmacvlan_mtu = htonl(ifp->mtu);
	memcpy(ifc->cpmacvlan_ifname, ifp->ifname, CM_IFNAMSIZE);
	ifc->cpmacvlan_vnb_nodeid = htonl(ifp->vnb_nodeid);
	ifc->cpmacvlan_maclen  = htonl(eth_params->maclen);
	memcpy(ifc->cpmacvlan_mac, eth_params->mac, eth_params->maclen);

	ifc->cpmacvlan_mode = htonl(params->mode);
	ifc->cpmacvlan_flags = htons(params->flags);
	ifc->cpmacvlan_link_ifuid = params->link_ifuid;

	hdr->cphdr_type = htonl (cmd);

	post_msg (hdr);
	return 0;
}
#endif

#ifdef CONFIG_CACHEMGR_BRIDGE
/*
 * Send a CMD_BRPORT_UPDATE/CMD_BRPORT_DELETE message to FPM
 */
int cm2cp_brport_update(u_int32_t cookie, u_int32_t cmd, struct cm_iface *ifp)
{
	struct cp_hdr *hdr;
	struct cp_brport *port;
	struct cm_brport_params *params;
	int len;

	len = sizeof (*port);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	port = (struct cp_brport *)(hdr + 1);
	params = (struct cm_brport_params *)(ifp + 1);

	port->cpbrport_ifuid = ifp->ifuid;
	port->cpbrport_master_ifuid = ifp->master_ifuid;
	port->cpbrport_state = params->state;
	port->cpbrport_flags = params->flags;

	if (cmd == RTM_NEWLINK)
		hdr->cphdr_type = htonl(CMD_BRPORT_UPDATE);
	else if (cmd == RTM_DELLINK)
		hdr->cphdr_type = htonl(CMD_BRPORT_DELETE);

	post_msg (hdr);
	return 0;
}
#endif

#ifdef CONFIG_CACHEMGR_BONDING
/*
 * Send a CMD_BONDING_CREATE/CMD_BONDING_DELETE message to FPM
 */
int cm2cp_bonding_create(u_int32_t cookie, u_int32_t cmd, struct cm_iface *ifp)
{
	struct cp_hdr *hdr;
	struct cp_bonding *ifc;
	struct cm_eth_params *eth_params;
	struct cm_bonding_params *params;
	int len;

	len = sizeof(*ifc);
	CM_CALLOC(1, hdr, len + sizeof(struct cp_hdr));
	eth_params = (struct cm_eth_params *)(ifp + 1);
	params = (struct cm_bonding_params *)(eth_params + 1);

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_cookie = htonl(cookie);
	hdr->cphdr_type = htonl(cmd);

	ifc = (struct cp_bonding *)(hdr + 1);

	ifc->cpbonding_ifuid = ifp->ifuid;
	ifc->cpbonding_vrfid = htonl(ifp->vrfid);
	ifc->cpbonding_mtu = htonl(ifp->mtu);
	ifc->cpbonding_vnb_nodeid = htonl(ifp->vnb_nodeid);
	memcpy(ifc->cpbonding_ifname, ifp->ifname, CM_IFNAMSIZE);

	ifc->cpbonding_maclen  = htonl(eth_params->maclen);
	memcpy(ifc->cpbonding_mac, eth_params->mac, eth_params->maclen);

	ifc->cpbonding_active_slave_ifuid = params->active_slave_ifuid;
	ifc->cpbonding_ad_info_aggregator = htons(params->ad_info_aggregator);
	ifc->cpbonding_ad_info_num_ports = htons(params->ad_info_num_ports);
	ifc->cpbonding_mode = params->mode;

	post_msg(hdr);
	return 0;
}

/*
 * Send a CMD_BONDING_SLAVE_UPDATE message to FPM
 */
int cm2cp_slave_bonding_update(u_int32_t cookie, u_int32_t ifuid,
			       u_int32_t master_ifuid,
			       struct cm_slave_bonding *params)
{
	struct cp_hdr *hdr;
	struct cp_bonding_slave *slave;
	int len;

	len = sizeof(*slave);
	CM_CALLOC(1, hdr, len + sizeof(struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_cookie = htonl(cookie);
	hdr->cphdr_type = htonl(CMD_BONDING_SLAVE_UPDATE);

	slave = (struct cp_bonding_slave *)(hdr + 1);
	slave->cpbond_s_ifuid = ifuid;
	slave->cpbond_s_master_ifuid = master_ifuid;
	slave->cpbond_s_link_failure_count = htonl(params->link_failure_count);
	slave->cpbond_s_queue_id = htonl(params->queue_id);
	slave->cpbond_s_aggregator_id = htons(params->aggregator_id);
	slave->cpbond_s_state = params->state;
	slave->cpbond_s_link = params->link;
	memcpy(slave->cpbond_s_perm_hwaddr, params->perm_hwaddr, 6);

	post_msg(hdr);
	return 0;
}
#endif

#ifdef CONFIG_CACHEMGR_GRE
/*
 * Send a CMD_GRE_CREATE/CMD_GRE_UPDATE/CMD_GRE_DELETE message to FPM
 */
int cm2cp_gre_create(u_int32_t cookie, u_int32_t cmd, struct cm_iface *ifp, uint8_t mode)
{
	struct cp_hdr *hdr;
	struct cp_gre *ifc;
	struct cm_eth_params *eth_params;
	struct cm_gre_params *params;
	int len;

	len = sizeof(*ifc);
	CM_CALLOC(1, hdr, len + sizeof(struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_cookie = htonl(cookie);
	hdr->cphdr_type = htonl(cmd);

	ifc = (struct cp_gre *)(hdr + 1);
	if (mode == CP_GRE_MODE_ETHER) {
		eth_params = (struct cm_eth_params *)(ifp + 1);
		params = (struct cm_gre_params *)(eth_params + 1);
		ifc->cpgretap_vnb_nodeid = htonl(ifp->vnb_nodeid);
		ifc->cpgretap_maclen  = htonl(eth_params->maclen);
		memcpy(ifc->cpgretap_mac, eth_params->mac, eth_params->maclen);
	} else {
		params = (struct cm_gre_params *)(ifp + 1);
		ifc->cpgretap_vnb_nodeid = 0;
		ifc->cpgretap_maclen  = 0;
	}

	ifc->cpgre_ifuid = ifp->ifuid;
	ifc->cpgre_vrfid = htonl(ifp->vrfid);
	ifc->cpgre_linkvrfid = htonl(ifp->linkvrfid);
	ifc->cpgre_mtu = htonl(ifp->mtu);
	memcpy(ifc->cpgre_ifname, ifp->ifname, CM_IFNAMSIZE);

	ifc->cpgre_linkifuid = params->link_ifuid;
	ifc->cpgre_iflags = htons(params->iflags);
	ifc->cpgre_oflags = htons(params->oflags);
	/* keys are already in network format */
	ifc->cpgre_ikey = params->ikey;
	ifc->cpgre_okey = params->okey;
	ifc->cpgre_ttl = params->ttl;
	ifc->cpgre_tos = params->tos;
	ifc->cpgre_inh_tos = params->inh_tos;
	ifc->cpgre_family = params->family;
	ifc->cpgre_mode = params->mode;
	if (params->family == AF_INET) {
		memcpy(&ifc->cpgre_laddr.local,  &params->local,  sizeof(struct in_addr));
		memcpy(&ifc->cpgre_raddr.remote, &params->remote, sizeof(struct in_addr));
	} else {
		memcpy(&ifc->cpgre_laddr.local6,  &params->local6,  sizeof(struct in6_addr));
		memcpy(&ifc->cpgre_raddr.remote6, &params->remote6, sizeof(struct in6_addr));
	}

	post_msg (hdr);
	return 0;
}
#endif /* CONFIG_CACHEMGR_GRE */

int
cm2cp_iface_master (u_int32_t cookie, u_int32_t slave_ifuid, u_int32_t master_ifuid)
{
	struct cp_hdr *hdr;
	struct cp_iface_master *ifm;
	int len;

	len = sizeof (struct cp_iface_master);
	CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	hdr->cphdr_type = htonl (CMD_IF_MASTER);
	ifm = (struct cp_iface_master *)(hdr + 1);
	ifm->cpiface_ifuid = slave_ifuid;
	ifm->cpiface_master_ifuid = master_ifuid;

	post_msg (hdr);
	return 0;
}

int
cm2cp_iface_mtu (u_int32_t cookie, u_int32_t idx, u_int32_t mtu)
{
	struct cp_hdr *hdr;
	struct cp_iface_mtu *ifm;
	int len;

	len = sizeof (struct cp_iface_mtu);
	CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	hdr->cphdr_type = htonl (CMD_IF_MTU);
	ifm = (struct cp_iface_mtu *)(hdr + 1);
	ifm->cpiface_ifuid = idx;
	ifm->cpiface_mtu = htonl(mtu);

	post_msg (hdr);
	return 0;
}

int
cm2cp_iface_state (u_int32_t cookie, u_int32_t idx, u_int32_t state, u_int32_t change)
{
	struct cp_hdr *hdr;
	struct cp_iface_state *ifs;
	int len;

	len = sizeof (struct cp_iface_state);
	CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	hdr->cphdr_type = htonl (CMD_IF_STATE_UPDATE);
	ifs = (struct cp_iface_state *)(hdr + 1);
	ifs->cpiface_ifuid = idx;
	ifs->cpiface_state = htonl (state);

	post_msg (hdr);
	return 0;
}

int
cm2cp_iface_mac (u_int32_t cookie, u_int32_t idx, u_int8_t *mac, u_int32_t maclen)
{
	struct cp_hdr *hdr;
	struct cp_iface_mac *ifm;
	int len;

	len = sizeof (*ifm);
	CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	hdr->cphdr_type = htonl (CMD_IF_MAC);
	ifm = (struct cp_iface_mac *)(hdr + 1);
	ifm->cpiface_ifuid = idx;
	ifm->cpiface_maclen = htonl(maclen);
	memcpy(ifm->cpiface_mac, mac, maclen);

	post_msg (hdr);
	return 0;
}

int
cm2cp_iface_bladeinfo (u_int32_t cookie, u_int32_t idx, u_int8_t blade_id)
{
	struct cp_hdr *hdr;
	struct cp_iface_bladeinfo *ifb;
	int len;

	len = sizeof (struct cp_iface_bladeinfo);
	CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	hdr->cphdr_type = htonl (CMD_IF_BLADEINFO);
	ifb = (struct cp_iface_bladeinfo *)(hdr + 1);
	ifb->cpiface_ifuid     = idx;
	ifb->cpiface_blade_id    = blade_id;

	post_msg (hdr);
	return 0;
}


int
cm2cp_ipv4_addr (u_int32_t cookie,
	u_int32_t cmd,
	u_int32_t ifuid,
	struct in_addr *ia,
	u_int8_t pfxlen)
{
	struct cp_hdr *hdr;
	struct cp_iface_ipv4_addr *ip4;
	int len;

	/*
	 * Filter out any 127.x.x.x addresses
	 */
	if ((ia->s_addr & htonl(127<<24)) ==  htonl(127<<24))
		return CM_ERROR;

	len = sizeof (struct cp_iface_ipv4_addr);
	CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	if (cmd == RTM_NEWADDR)
		hdr->cphdr_type = htonl (CMD_INTERFACE_IPV4_ADDR_ADD);
	else
		hdr->cphdr_type = htonl (CMD_INTERFACE_IPV4_ADDR_DEL);
	ip4 = (struct cp_iface_ipv4_addr *)(hdr + 1);
	ip4->cpiface_ifuid = ifuid;
	ip4->cpiface_addr = *ia;
	ip4->cpiface_pfxlen = pfxlen;

	post_msg (hdr);
	return 0;
}

int
cm2cp_ipv6_addr (u_int32_t cookie,
	u_int32_t cmd,
	u_int32_t ifuid,
	struct in6_addr *i6a,
	u_int8_t pfxlen)
{
	struct cp_hdr *hdr;
	int len;
	struct cp_iface_ipv6_addr *ip6;

	len = sizeof (struct cp_iface_ipv6_addr);
	CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	if (cmd == RTM_NEWADDR)
		hdr->cphdr_type = htonl (CMD_INTERFACE_IPV6_ADDR_ADD);
	else
		hdr->cphdr_type = htonl (CMD_INTERFACE_IPV6_ADDR_DEL);
	ip6 = (struct cp_iface_ipv6_addr *)(hdr + 1);
	ip6->cpiface_ifuid = ifuid;
	ip6->cpiface_addr = *i6a;
	ip6->cpiface_pfxlen = pfxlen;

	post_msg (hdr);
	return 0;
}

int
cm2cp_ipv4_route (u_int32_t cookie, u_int32_t cmd, u_int32_t flags, u_int32_t vrfid,
               struct in_addr *pfx,
               u_int8_t pfx_len,
               struct in_addr *gw,
               u_int8_t nhtype,
               u_int32_t oif,
               u_int32_t mtu,
               struct nh_mark *nh_mark)
{
	struct cp_hdr *hdr;
	struct cp_route4 *r4;
	int len;

	len = sizeof (struct cp_route4);
	CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	if (cmd == RTM_NEWROUTE) {
		if (flags & NLM_F_REPLACE)
			hdr->cphdr_type = htonl (CMD_ROUTE4_CHG);
		else
			hdr->cphdr_type = htonl (CMD_ROUTE4_ADD);
	}
	else
		hdr->cphdr_type = htonl (CMD_ROUTE4_DEL);
	r4 = (struct cp_route4 *)(hdr + 1);
	memset (r4, 0, sizeof(*r4));

	r4->cpr4_prefix = *pfx;
	cm_expand_mask (pfx_len, (u_int8_t *)&r4->cpr4_mask);
	r4->cpr4_nhtype = nhtype;
	r4->cpr4_ifuid = oif;
	r4->cpr4_vrfid = htonl(vrfid);
	if (gw)
		r4->cpr4_nexthop = *gw;
	r4->cpr4_mtu = htonl (mtu);

#ifdef RTA_NH_MARK
	r4->cpr4_nh_mark.mark = htonl (nh_mark->mark);
	r4->cpr4_nh_mark.mask = htonl (nh_mark->mask);
#endif

	if (cmd == RTM_GETROUTE) {
		struct cp_hdr *hdr_del;

		CM_MALLOC_NO_RET(hdr_del, len + sizeof(struct cp_hdr));
		if (hdr_del == NULL) {
			CM_FREE(hdr);
			syslog(LOG_ERR, "%s: could not alloc memory\n", __func__);
			return -ENOMEM;
		}
		memcpy (hdr_del, hdr, len + sizeof (struct cp_hdr));
		hdr_del->cphdr_type = htonl (CMD_ROUTE4_DEL);
		post_msg (hdr_del);
	}
	post_rt_msg (hdr);
	return 0;
}

int
cm2cp_ipv4_mroute (u_int32_t cookie,
		u_int32_t cmd,
		struct in_addr *grp,
		u_int32_t grp_len,
		struct in_addr *src,
		u_int32_t src_len,
		u_int32_t in_if,
		u_int32_t* out_bfif)
{
	struct cp_hdr *hdr;

	if ( !grp || !src )
		return CM_ERROR;
	/*
	 * Keep any linklocal stuff out of FPM, ALL
	 * is managed by the 224.X.X.X route
	 */
	if (IN_LOCAL_MULTICAST(ntohl(((struct in_addr *)grp)->s_addr)))
		return CM_ERROR;
	if ( grp_len != src_len || grp_len != 32 )
		return CM_ERROR;
	if ( ! out_bfif && cmd != RTM_DELROUTE )
		return CM_ERROR;

	if ( cmd == RTM_DELROUTE ) {
		struct cp_mfc_delete *md;
		int len = sizeof (struct cp_mfc_delete);
		CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

		hdr->cphdr_report = 0;
		hdr->cphdr_length = htonl (len);
		hdr->cphdr_type = htonl (CMD_MCAST_DEL_MFC);
		hdr->cphdr_cookie = htonl (cookie);
		md = (struct cp_mfc_delete *)(hdr + 1);
		memset (md, 0, len);

		md->cpmfc_family = AF_INET;
		memcpy( &md->cpmfc_source, src, sizeof( struct in_addr) );
		memcpy( &md->cpmfc_group, grp, sizeof( struct in_addr) );

		post_msg (hdr);
	}

	if (cmd == RTM_NEWROUTE || cmd == RTM_GETROUTE ) {
		struct cp_mfc_add *ma;
		int len = sizeof (struct cp_mfc_add);

		CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

		hdr->cphdr_report = 0;
		hdr->cphdr_length = htonl (len);
		hdr->cphdr_type = htonl (CMD_MCAST_ADD_MFC);
		hdr->cphdr_cookie = htonl (cookie);
		ma = (struct cp_mfc_add *)(hdr + 1);
		memset (ma, 0, len);

		ma->cpmfc_iif = in_if;
		ma->cpmfc_family = AF_INET;
		memcpy( &ma->cpmfc_source, src, sizeof (struct in_addr ));
		memcpy( &ma->cpmfc_group,  grp, sizeof (struct in_addr ));
		memcpy( &ma->cpmfc_oif, out_bfif, sizeof(ma->cpmfc_oif));

		post_msg (hdr);
	}
	return 0;

}

int
cm2cp_ipv6_route (u_int32_t cookie, u_int32_t cmd, u_int32_t vrfid,
               struct in6_addr *pfx,
               u_int8_t pfx_len,
               struct in6_addr *gw,
               u_int8_t nhtype,
               u_int32_t oif,
               u_int32_t mtu,
               struct nh_mark *nh_mark)
{
	struct cp_hdr *hdr;
	struct cp_route6 *r6;
	int len;

	/*
	 * Keep any linklocal stuff out of FPM, ALL
	 * is managed by the fe80::/10 route
	 */
	if (IN6_IS_ADDR_LINKLOCAL(pfx))
		return CM_ERROR;
	/*
	 * Any unicast route with mcast prefix should
	 * not mess with Fast Path
	 */
	if (IN6_IS_ADDR_MULTICAST(pfx))
		return CM_ERROR;

	len = sizeof (struct cp_route6);
	CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	if (cmd != RTM_DELROUTE)
		hdr->cphdr_type = htonl (CMD_ROUTE6_ADD);
	else
		hdr->cphdr_type = htonl (CMD_ROUTE6_DEL);
	r6 = (struct cp_route6 *)(hdr + 1);
	memset (r6, 0, sizeof(*r6));

	r6->cpr6_prefix = *pfx;
	r6->cpr6_pfxlen = pfx_len;
	r6->cpr6_nhtype = nhtype;
	r6->cpr6_vrfid = htonl(vrfid);
	r6->cpr6_ifuid = oif;
	if (gw)
		r6->cpr6_nexthop = *gw;
	r6->cpr6_mtu = mtu;

#ifdef RTA_NH_MARK
	r6->cpr6_nh_mark.mark = htonl (nh_mark->mark);
	r6->cpr6_nh_mark.mask = htonl (nh_mark->mask);
#endif

	if (cmd == RTM_GETROUTE) {
		struct cp_hdr *hdr_del;
		CM_MALLOC_NO_RET(hdr_del, len + sizeof (struct cp_hdr));
		if (hdr_del == NULL) {
			CM_FREE(hdr);
			syslog(LOG_ERR, "%s: could not alloc memory\n", __func__);
			return -ENOMEM;
		}
		memcpy (hdr_del, hdr, len + sizeof (struct cp_hdr));
		hdr_del->cphdr_type = htonl (CMD_ROUTE6_DEL);
		post_msg (hdr_del);
	}
	post_rt_msg (hdr);
	return 0;
}

int
cm2cp_ipv6_mroute (u_int32_t cookie,
               u_int32_t cmd,
               struct in6_addr *grp,
               u_int32_t grp_len,
               struct in6_addr *src,
               u_int32_t src_len,
               u_int32_t in_if,
               u_int32_t* out_bfif)
{
	struct cp_hdr *hdr;

	if ( !grp || !src )
		return CM_ERROR;
	/*
	 * Keep any linklocal stuff out of FPM, ALL
	 * is managed by the fe80::/10 route
	 */
	if (IN6_IS_ADDR_LINKLOCAL(grp))
		return CM_ERROR;
	if ( grp_len != src_len || grp_len != 128 )
		return CM_ERROR;
	if ( ! out_bfif && cmd != RTM_DELROUTE )
		return CM_ERROR;

	if ( cmd == RTM_DELROUTE ) {
		struct cp_mfc_delete *md;
		int len = sizeof (struct cp_mfc_delete);

		CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

		hdr->cphdr_report = 0;
		hdr->cphdr_length = htonl (len);
		hdr->cphdr_cookie = htonl (cookie);

		hdr->cphdr_type = htonl (CMD_MCAST_DEL_MFC);
		md = (struct cp_mfc_delete *)(hdr + 1);
		memset (md, 0, len);

		md->cpmfc_family = AF_INET6;
		memcpy( &md->cpmfc_source, src, sizeof( struct in6_addr) );
		memcpy( &md->cpmfc_group, grp, sizeof( struct in6_addr) );

		post_msg (hdr);
	}

	if (cmd == RTM_NEWROUTE || cmd == RTM_GETROUTE) {
		struct cp_mfc_add *ma;
		int len = sizeof (struct cp_mfc_add);

		CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

		hdr->cphdr_report = 0;
		hdr->cphdr_length = htonl (len);
		hdr->cphdr_type = htonl (CMD_MCAST_ADD_MFC);
		hdr->cphdr_cookie = htonl (cookie);
		ma = (struct cp_mfc_add *)(hdr + 1);
		memset (ma, 0, len);

		ma->cpmfc_iif = in_if;
		ma->cpmfc_family = AF_INET6;
		memcpy( &ma->cpmfc_source, src, sizeof (struct in6_addr ));
		memcpy( &ma->cpmfc_group,  grp, sizeof (struct in6_addr ));
		memcpy( &ma->cpmfc_oif, out_bfif, sizeof(ma->cpmfc_oif));

		post_msg (hdr);
	}

	return 0;
}

/* Update L2 information and intimate FPM */
int
cm2cp_l2 (u_int32_t cookie, u_int8_t state, u_int32_t ifuid, u_int8_t family, void *addr,
	  struct cm_eth_params *params, u_int32_t uid)
{
	struct cp_hdr *hdr;
	struct cp_l2 *l2msg;
	int len;

	len = sizeof (*l2msg);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	l2msg = (struct cp_l2 *)(hdr + 1);
	l2msg->cpl2_ifuid    = ifuid;
	l2msg->cpl2_uid_deprecated  = 0;
	if (state != CM_L2STATE_NONE) {
		memcpy (l2msg->cpl2_mac, params->mac, params->maclen);
	}

	if (family == AF_INET) {
		hdr->cphdr_type = htonl (CMD_ARP_UPDATE);
		memcpy (&l2msg->cpl2_ipaddr.addr4, addr, sizeof(struct in_addr));
	} else if (family == AF_INET6) {
		hdr->cphdr_type = htonl (CMD_NDP_UPDATE);
		memcpy (&l2msg->cpl2_ipaddr.addr6, addr, sizeof(struct in6_addr));
	}
	l2msg->cpl2_state = state;
	post_msg (hdr);
	return 0;
}

#ifdef CONFIG_CACHEMGR_VXLAN
int cm2cp_fdb(u_int32_t cookie, u_int32_t cmd, struct cm_vxlan_fdb *params,
	      void *addr)
{
	struct cp_vxlan_fdb *msg;
	struct cp_hdr *hdr;
	int len;

	len = sizeof(struct cp_vxlan_fdb);
	CM_CALLOC(1, hdr, sizeof(struct cp_hdr) + len);

	if (cmd == RTM_DELNEIGH)
		hdr->cphdr_type = htonl(CMD_VXLAN_FDB_DEL);
	else
		hdr->cphdr_type = htonl(CMD_VXLAN_FDB_ADD);
	hdr->cphdr_report = 0;
	hdr->cphdr_cookie = htonl(cookie);
	hdr->cphdr_length = htonl(len);

	msg = (struct cp_vxlan_fdb *)(hdr + 1);
	msg->fdb_ifuid = params->ifuid;
	msg->fdb_vni = htonl(params->vni);
	msg->fdb_output_ifuid = params->output_ifuid;
	msg->fdb_family = params->family;
	if (params->family == AF_INET)
		memcpy(&msg->fdb_addr.addr4, addr, sizeof(struct in_addr));
	else if (params->family == AF_INET6)
		memcpy(&msg->fdb_addr.addr6, addr, sizeof(struct in6_addr));
	msg->fdb_dst_port = params->dst_port; /* already in network order */
	msg->fdb_state = params->state;
	memcpy(msg->fdb_mac, params->mac, sizeof(msg->fdb_mac));

	post_msg (hdr);
	return 0;
}
#endif

/*
 * Send a CMD_IPSEC_SA_CREATE/CMD_IPSEC_SA_DELETE message to FPM
 */
int
cm2cp_ipsec_sa_create (u_int32_t cookie, struct cm_ipsec_sa *sa)
{
	struct cp_hdr *hdr;
	struct cp_ipsec_sa_add *add_sa;
	int len;
	uint16_t keyoffset;

	len = sizeof (*add_sa) + sa->ekeylen + sa->akeylen;
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_type = htonl (CMD_IPSEC_SA_CREATE);
	hdr->cphdr_cookie = htonl (cookie);

	add_sa = (struct cp_ipsec_sa_add *)(hdr + 1);

	add_sa->family   = sa->family;
	add_sa->proto    = sa->proto;
	add_sa->spi      = sa->spi;
	add_sa->daddr    = sa->daddr;
	add_sa->saddr    = sa->saddr;
	add_sa->dport    = sa->dport;
	add_sa->sport    = sa->sport;
	add_sa->reqid    = htonl(sa->reqid);
	add_sa->mode     = sa->mode;
	add_sa->ealgo    = sa->ealgo;
	add_sa->aalgo    = sa->aalgo;
	add_sa->ekeylen  = htons(sa->ekeylen);
	add_sa->akeylen  = htons(sa->akeylen);
	add_sa->flags    = htonl(sa->flags);
	add_sa->vrfid    = htonl(sa->vrfid);
	add_sa->xvrfid   = htonl(sa->xvrfid);
	add_sa->output_blade = sa->output_blade;
	add_sa->svti_ifuid = sa->svti_ifuid;

	add_sa->seq = htonll(sa->seq);
	add_sa->oseq = htonll(sa->oseq);
	add_sa->replay = htonl(sa->replay);

	keyoffset = 0;
	if (sa->ekeylen) {
		memcpy(add_sa->keys, sa->keys, sa->ekeylen);
		keyoffset += sa->ekeylen;
	}
	if (sa->akeylen) {
		memcpy(add_sa->keys + keyoffset, sa->keys + keyoffset, sa->akeylen);
		//keyoffset += sa->akeylen;
	}

	post_msg (hdr);

	/* If lifetime is specified, and spi is not 0 (ACQUIRE) , send a second message */
	if ((add_sa->spi != 0) &&
	    ((sa->hard.nb_bytes != XFRM_INF) || (sa->hard.nb_packets != XFRM_INF) ||
	     (sa->soft.nb_bytes != XFRM_INF) || (sa->soft.nb_packets != XFRM_INF))) {
		struct cp_ipsec_sa_lifetime *sa_lifetime;

		len = sizeof (*sa_lifetime);
		CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

		/* Populate header */
		hdr->cphdr_report = 0;
		hdr->cphdr_length = htonl(len);
		hdr->cphdr_type   = htonl(CMD_IPSEC_SA_LIFETIME);

		/* Populate SA lifetime message, network ordered */
		sa_lifetime = (struct cp_ipsec_sa_lifetime *)(hdr + 1);

		sa_lifetime->family   = sa->family;
		sa_lifetime->proto    = sa->proto;
		sa_lifetime->spi      = sa->spi;
		sa_lifetime->daddr    = sa->daddr;
		sa_lifetime->vrfid    = htonl(sa->vrfid);
		sa_lifetime->soft.nb_bytes   = htonll(sa->soft.nb_bytes);
		sa_lifetime->soft.nb_packets = htonll(sa->soft.nb_packets);
		sa_lifetime->hard.nb_bytes   = htonll(sa->hard.nb_bytes);
		sa_lifetime->hard.nb_packets = htonll(sa->hard.nb_packets);

		/* Send message */
		post_msg (hdr);
	}

	return 0;
}

int
cm2cp_ipsec_sa_delete (u_int32_t cookie, struct cm_ipsec_sa *sa)
{
	struct cp_hdr *hdr;
	struct cp_ipsec_sa_del *del_sa;
	int len;

	len = sizeof (*del_sa);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_type = htonl (CMD_IPSEC_SA_DELETE);
	hdr->cphdr_cookie = htonl (cookie);

	del_sa = (struct cp_ipsec_sa_del *)(hdr + 1);

	del_sa->family   = sa->family;
	del_sa->proto    = sa->proto;
	del_sa->spi      = sa->spi;
	del_sa->daddr    = sa->daddr;
	del_sa->state    = sa->state;
	del_sa->vrfid    = htonl(sa->vrfid);

	post_msg (hdr);
	return 0;
}

int
cm2cp_ipsec_sa_flush(u_int32_t cookie, uint32_t vrfid)
{
	struct cp_hdr *hdr;
	uint32_t *pvrfid;
	int len;

	len = sizeof(*pvrfid);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_type = htonl (CMD_IPSEC_SA_FLUSH);
	hdr->cphdr_cookie = htonl (cookie);

	pvrfid = (uint32_t *)(hdr + 1);
	*pvrfid = htonl(vrfid);

	post_msg (hdr);
	return 0;
}

int
cm2cp_ipsec_sp_create (u_int32_t cookie, struct cm_ipsec_sp *sp, int update)
{
	struct cp_hdr *hdr;
	struct cp_ipsec_sp_add *sp_add;
	int len;
	int i;

	len = sizeof(*sp_add) + sp->xfrm_count * sizeof(struct cp_ipsec_xfrm);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);
	if (update)
		hdr->cphdr_type = htonl (CMD_IPSEC_SP_UPDATE);
	else
		hdr->cphdr_type = htonl (CMD_IPSEC_SP_CREATE);

	sp_add = (struct cp_ipsec_sp_add *)(hdr + 1);

	sp_add->index      = htonl(sp->index);
	sp_add->priority   = htonl(sp->priority);
	sp_add->family     = sp->family;
	sp_add->dir        = sp->dir;
	sp_add->proto      = sp->proto;
	sp_add->saddr      = sp->saddr;
	sp_add->daddr      = sp->daddr;
	sp_add->sport      = sp->sport;
	sp_add->dport      = sp->dport;
	sp_add->sportmask  = sp->sportmask;
	sp_add->dportmask  = sp->dportmask;
	sp_add->spfxlen    = sp->spfxlen;
	sp_add->dpfxlen    = sp->dpfxlen;
	sp_add->flags      = htonl(sp->flags);
	sp_add->action     = sp->action;
	sp_add->xfrm_count = sp->xfrm_count;
	sp_add->vrfid      = htonl(sp->vrfid);
	sp_add->link_vrfid = htonl(sp->link_vrfid);
	sp_add->svti_ifuid = sp->svti_ifuid;

	for (i=0; i < sp->xfrm_count; i++) {
		sp_add->xfrm[i].family = sp->xfrm[i].family;
		sp_add->xfrm[i].proto = sp->xfrm[i].proto;
		sp_add->xfrm[i].flags = sp->xfrm[i].flags;
		sp_add->xfrm[i].saddr = sp->xfrm[i].saddr;
		sp_add->xfrm[i].daddr = sp->xfrm[i].daddr;
		sp_add->xfrm[i].spi   = sp->xfrm[i].spi;
		sp_add->xfrm[i].reqid = htonl(sp->xfrm[i].reqid);
		sp_add->xfrm[i].mode  = sp->xfrm[i].mode;
	}

	post_msg (hdr);
	return 0;
}


int
cm2cp_ipsec_sp_delete (u_int32_t cookie, struct cm_ipsec_sp *sp)
{
	struct cp_hdr *hdr;
	struct cp_ipsec_sp_del *sp_del;
	int len;

	len = sizeof(*sp_del);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_type = htonl (CMD_IPSEC_SP_DELETE);
	hdr->cphdr_cookie = htonl (cookie);

	sp_del = (struct cp_ipsec_sp_del *)(hdr + 1);

	sp_del->index      = htonl(sp->index);
	sp_del->priority   = htonl(sp->priority);
	sp_del->family     = sp->family;
	sp_del->dir        = sp->dir;
	sp_del->proto      = sp->proto;
	sp_del->saddr      = sp->saddr;
	sp_del->daddr      = sp->daddr;
	sp_del->sport      = sp->sport;
	sp_del->dport      = sp->dport;
	sp_del->sportmask  = sp->sportmask;
	sp_del->dportmask  = sp->dportmask;
	sp_del->spfxlen    = sp->spfxlen;
	sp_del->dpfxlen    = sp->dpfxlen;
	sp_del->action     = sp->action;
	sp_del->vrfid      = htonl(sp->vrfid);
	sp_del->svti_ifuid = sp->svti_ifuid;

	post_msg (hdr);
	return 0;
}

int
cm2cp_ipsec_sp_flush(u_int32_t cookie, uint32_t vrfid, uint32_t svti)
{
	struct cp_hdr *hdr;
	struct cp_ipsec_sp_flush * flush;
	int len;

	len = sizeof(*flush);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_type = htonl (CMD_IPSEC_SP_FLUSH);
	hdr->cphdr_cookie = htonl (cookie);

	flush = (struct cp_ipsec_sp_flush *)(hdr + 1);
	flush->vrfid = htonl(vrfid);
	flush->svti_ifuid = svti;

	post_msg (hdr);
	return 0;
}

int
cm2cp_nf_update(u_int32_t cookie, struct cp_nftable *info)
{
	struct cp_hdr *hdr;
	struct cp_nftable *table;
	int len;

	len = sizeof(*table) + (ntohl(info->cpnftable_count) * sizeof(struct cp_nfrule));
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_type = htonl(CMD_NF_UPDATE);
	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_cookie = htonl (cookie);

	table = (struct cp_nftable *)(hdr + 1);
	memcpy(table, info, len);

	post_msg (hdr);
	return 0;
}

#ifdef CONFIG_CACHEMGR_EBTABLES
/* Send an ebtable to fpm, for him to update the shared memory accordingly. */
int
cm2cp_ebt_update(struct cp_ebt_table *info)
{
	struct cp_hdr *hdr;
	struct cp_ebt_table *table;
	int len;

	len = sizeof(*table) + (ntohl(info->count) * sizeof(struct cp_ebt_rule));
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_type = htonl(CMD_EBT_UPDATE);
	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_cookie = 0;

	table = (struct cp_ebt_table *)(hdr + 1);
	memcpy(table, info, len);

	post_msg (hdr);
	return 0;
}
#endif /* CONFIG_CACHEMGR_EBTABLES */

int
cm2cp_nfct_create(u_int32_t cookie, struct cp_nfct *nfct)
{
	struct cp_hdr *hdr;
	struct cp_nfct *add_nfct;
	int len;

	len = sizeof(*add_nfct);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_type = htonl(CMD_NF_CTADD);
	hdr->cphdr_cookie = htonl (cookie);

	add_nfct = (struct cp_nfct *)(hdr + 1);
	memcpy(add_nfct, nfct, len);

	post_msg (hdr);
	return 0;
}

int
cm2cp_nfct_delete(u_int32_t cookie, struct cp_nfct *nfct)
{
	struct cp_hdr *hdr;
	struct cp_nfct *del_nfct;
	int len;

	len = sizeof(*del_nfct);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_type = htonl(CMD_NF_CTDELETE);
	hdr->cphdr_cookie = htonl (cookie);

	del_nfct = (struct cp_nfct *)(hdr + 1);
	memcpy(del_nfct, nfct, len);

	post_msg (hdr);
	return 0;
}

int
cm2cp_nfct_flush(u_int32_t cookie)
{
	struct cp_hdr *hdr;
	int len = 0;

	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = 0;
	hdr->cphdr_type = htonl(CMD_NF_CTFLUSH);
	hdr->cphdr_cookie = htonl (cookie);

	post_msg (hdr);
	return 0;
}

int
cm2cp_nf6_update(u_int32_t cookie, struct cp_nf6table *info)
{
	struct cp_hdr *hdr;
	struct cp_nf6table *table;
	int len;

	len = sizeof(*table) + (ntohl(info->cpnftable_count) * sizeof(struct cp_nf6rule));
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_type = htonl(CMD_NF6_UPDATE);
	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_cookie = htonl (cookie);

	table = (struct cp_nf6table *)(hdr + 1);
	memcpy(table, info, len);

	post_msg (hdr);
	return 0;
}

int
cm2cp_nf6ct_create(u_int32_t cookie, struct cp_nf6ct *nf6ct)
{
	struct cp_hdr *hdr;
	struct cp_nf6ct *add_nf6ct;
	int len;

	len = sizeof(*add_nf6ct);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_type = htonl(CMD_NF6_CTADD);
	hdr->cphdr_cookie = htonl (cookie);

	add_nf6ct = (struct cp_nf6ct *)(hdr + 1);
	memcpy(add_nf6ct, nf6ct, len);

	post_msg (hdr);
	return 0;
}

int
cm2cp_nf6ct_delete(u_int32_t cookie, struct cp_nf6ct *nf6ct)
{
	struct cp_hdr *hdr;
	struct cp_nf6ct *del_nf6ct;
	int len;

	len = sizeof(*del_nf6ct);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_type = htonl(CMD_NF6_CTDELETE);
	hdr->cphdr_cookie = htonl (cookie);

	del_nf6ct = (struct cp_nf6ct *)(hdr + 1);
	memcpy(del_nf6ct, nf6ct, len);

	post_msg (hdr);
	return 0;
}

int
cm2cp_nfcpe_delete(u_int32_t cookie, u_int32_t cpeid)
{
	struct cp_hdr *hdr;
	struct cp_nfcpe *cpe;
	int len = sizeof(struct cp_nfcpe);

	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_type = htonl(CMD_NF_CPE_DELETE);
	hdr->cphdr_cookie = htonl (cookie);

	cpe = (struct cp_nfcpe *)(hdr + 1);
	cpe->cpeid = cpeid;

	post_msg (hdr);
	return 0;
}

#ifdef CONFIG_CACHEMGR_MULTIBLADE
int
cm2cp_fpib_change (u_int32_t cookie, struct cm_iface *ifp)
{
	struct cp_hdr *hdr;
	struct cp_blade_fpib *fpib;
	int len;

	len = sizeof (*fpib);
	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	fpib = (struct cp_blade_fpib *)(hdr + 1);

	if (ifp) {
		hdr->cphdr_type = htonl (CMD_BLADE_FPIB_IF_SET);
		fpib->fpib_ifuid = ifp->ifuid;
	} else {
		hdr->cphdr_type = htonl (CMD_BLADE_FPIB_IF_UNSET);
	}

	post_msg (hdr);
	return 0;
}
#endif

/* Create BPF filters of an interface */
int
cm2cp_bpf_update(u_int32_t cookie, struct cp_bpf *info)
{
	struct cp_hdr *hdr;
	struct cp_bpf *bpf;
	unsigned int i = 0;
	int len = sizeof(struct cp_bpf);

	CM_CALLOC(1, hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_cookie = htonl (cookie);
	hdr->cphdr_type = htonl(CMD_BPF_CREATE);

	bpf = (struct cp_bpf *)(hdr + 1);
	bpf->ifuid = info->ifuid;
	if (info->num) {
		bpf->num = htonl(info->num);
		for (i = 0; i < info->num; i++) {
			bpf->filters[i].code = htons(info->filters[i].code);
			bpf->filters[i].jt = info->filters[i].jt;
			bpf->filters[i].jf = info->filters[i].jf;
			bpf->filters[i].k = htonl(info->filters[i].k);
		}
	} else {
		/* Basic bpf filter, match all packets */
		bpf->num = htonl(1);
		bpf->filters[0].code = htons(0x06);
		bpf->filters[0].jt = 0;
		bpf->filters[0].jf = 0;
		bpf->filters[0].k = htonl(0xffff);
	}

	post_msg(hdr);
	return 0;
}

/* Graceful restart done notification */
int
cm2cp_graceful_done(u_int32_t cookie)
{
	struct cp_hdr *hdr;

	CM_MALLOC(hdr, sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = 0;
	hdr->cphdr_cookie = htonl (cookie);
	hdr->cphdr_type = htonl (CMD_GRACEFUL_DONE);

	post_msg (hdr);
	return 0;
}

int
cm2cp_veth_peer(u_int32_t cookie, u_int32_t ifuid, u_int32_t peer_ifuid)
{
	struct cp_hdr *hdr;
	struct cp_iface_veth_peer *ivm;
	int len;

	len = sizeof (*ivm);
	CM_MALLOC(hdr, len + sizeof (struct cp_hdr));

	hdr->cphdr_report = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_cookie = htonl (cookie);

	hdr->cphdr_type = htonl (CMD_IF_VETH_PEER);
	ivm = (struct cp_iface_veth_peer *)(hdr + 1);
	ivm->cpveth_ifuid = ifuid;
	ivm->cpveth_peer_ifuid = peer_ifuid;

	post_msg (hdr);
	return 0;
}
