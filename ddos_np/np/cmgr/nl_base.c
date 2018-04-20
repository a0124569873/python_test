/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *
 *          Netlink MSG parsing for basis cmd
 *          (interfaces, addresses and routes)
 *
 ***************************************************************
 */

#include <inttypes.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <event.h>
#include <syslog.h>

#include <linux/version.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <linux/if_link.h>
#include <linux/if_tunnel.h>
#ifdef CONFIG_CACHEMGR_BRIDGE
#include <linux/if_bridge.h>
#endif
#ifdef CONFIG_CACHEMGR_BONDING
#include <linux/if_bonding.h>
#endif

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/mroute.h>
#include <linux/mroute6.h>
#include <linux/filter.h>
#ifdef RTM_NEWNETCONF
#include <linux/netconf.h>
#endif
#include <netlink/msg.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/link.h>
#include <netlink/genl/genl.h>
#include <linux/sockios.h>

#include "fpc.h"

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
#include <vrf.h>
#endif

#include "ifuid.h"

#include "cm_priv.h"
#include "cm_pub.h"
#include "cm_netlink.h"
#include "cm_sock.h"

#ifdef HAVE_IFLA_INFO_SLAVE
#define CM_SLAVETYPE_NONE	0
#define CM_SLAVETYPE_BONDING	1
#endif

/* This must be synchronized with rfpvi code */
enum {
	IFLA_RFPVI_UNSPEC,
	IFLA_RFPVI_BLADEID,
	__IFLA_RFPVI_MAX
};
#define IFLA_RFPVI_MAX (__IFLA_RFPVI_MAX - 1)


#ifdef CONFIG_CACHEMGR_MULTIBLADE
int f_multiblade;
struct cm_fpib cm_fpib;
#endif

static struct cm_iface *cm_eth_alloc(u_int32_t cm_type);
static void cm_eth_create(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_eth_change(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_eth_delete(struct cm_iface *, struct nlmsghdr *, struct nlattr **);

static struct cm_iface *cm_6in4_alloc(u_int32_t cm_type);
static void cm_6in4_common(struct cm_iface *, struct nlmsghdr *, struct nlattr **, int);
static void cm_6in4_create(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_6in4_change(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_6in4_delete(struct cm_iface *, struct nlmsghdr *, struct nlattr **);

static struct cm_iface *cm_Xin6_alloc(u_int32_t cm_type);
static void cm_Xin6_common(struct cm_iface *, struct nlmsghdr *, struct nlattr **, int);
static void cm_Xin6_create(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_Xin6_change(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_Xin6_delete(struct cm_iface *, struct nlmsghdr *, struct nlattr **);

static struct cm_iface *cm_svti_alloc(u_int32_t cm_type);
static void cm_svti_create(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_svti_change(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_svti_delete(struct cm_iface *, struct nlmsghdr *, struct nlattr **);

static struct cm_iface *cm_vti_alloc(u_int32_t cm_type);
static void cm_vti_create(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_vti_change(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_vti_delete(struct cm_iface *, struct nlmsghdr *, struct nlattr **);

#ifdef CONFIG_CACHEMGR_VXLAN
static void cm_vxlan_create(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
#endif
#ifdef CONFIG_CACHEMGR_VLAN
static void cm_vlan_create(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
#endif
#ifdef CONFIG_CACHEMGR_MACVLAN
static void cm_macvlan_create(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_macvlan_change(struct cm_iface *, struct nlmsghdr *,
			      struct nlattr **);
#endif


#ifdef CONFIG_CACHEMGR_BRIDGE
static struct cm_iface *cm_brport_alloc(u_int32_t cm_type);
static void cm_brport_create(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_brport_change(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_brport_delete(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_brport_rename(u_int32_t cookie, int ifindex, char *name,
			     u_int32_t vrfid, u_int32_t ifuid);
#endif

#ifdef CONFIG_CACHEMGR_BONDING
static void cm_bonding_create(struct cm_iface *, struct nlmsghdr *,
			      struct nlattr **);
static void cm_bonding_change(struct cm_iface *, struct nlmsghdr *,
			      struct nlattr **);
#ifdef HAVE_IFLA_BOND
static void cm_nl_bonding_start_timer(u_int32_t vrfid);
static void cm_nl_bonding_link(struct cm_iface *ifp);
static void cm_nl_bonding_unlink(struct cm_iface *ifp);
#endif
#ifdef HAVE_IFLA_INFO_SLAVE
static void cm_slave_bonding_update(struct cm_iface *, struct nlmsghdr *,
				    struct nlattr **);
#endif
#endif

#ifdef CONFIG_CACHEMGR_GRE
static struct cm_iface *cm_gre_alloc(u_int32_t cm_type);
static void cm_gre_create(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_gre_change(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_gre_delete(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_gretap_create(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_gretap_change(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
static void cm_gretap_delete(struct cm_iface *, struct nlmsghdr *, struct nlattr **);
#endif

#define IN6_IS_PREF_V4COMPAT(a) \
	((((__const uint32_t *) (a))[0] == 0)				      \
	 && (((__const uint32_t *) (a))[1] == 0)			      \
	 && (((__const uint32_t *) (a))[2] == 0))

static struct cmiface ifacehead;

#define CM_IF_HASH_ORDER   10
#define CM_IF_HASH_MAX    (1<<CM_IF_HASH_ORDER)
#define CM_IF_HASH_MASK   (CM_IF_HASH_MAX-1)
LIST_HEAD(if_hlist, cm_iface);
static struct if_hlist ifindex_hash_table[CM_IF_HASH_MAX];
static struct if_hlist ifuid_hash_table[CM_IF_HASH_MAX];
#ifdef CONFIG_CACHEMGR_BRIDGE
static struct cmiface bridgehead;
static struct if_hlist bridge_ifindex_hash_table[CM_IF_HASH_MAX];
static struct if_hlist bridge_ifuid_hash_table[CM_IF_HASH_MAX];
#endif

#ifdef HAVE_IFLA_BOND
LIST_HEAD(ifbondlist, cm_iface);
static struct ifbondlist ifbond_list;
#endif

static int promisc_count = 0;
/*
 * rawmode sticky flag
 * if  0: set raw mode according to promiscuous mode
 * if >0: force raw mode on
 * if <0: force raw mode off
 */
static int raw_mode_method = 0;
/*
 * Detected VRFs
 */
int cm_vrf [CM_MAX_VRF];

static void cm_link_iface (struct cm_iface *ifp)
{
	int hash1 = ifp->ifindex & CM_IF_HASH_MASK;
	int hash2 = ifp->ifuid & CM_IF_HASH_MASK;

	TAILQ_INSERT_HEAD(&ifacehead, ifp, link);
	LIST_INSERT_HEAD(&ifindex_hash_table[hash1], ifp, h_ifindex);
	LIST_INSERT_HEAD(&ifuid_hash_table[hash2], ifp, h_ifuid);

#ifdef HAVE_IFLA_BOND
	if (ifp->subtype == CM_IFSUBTYPE_BONDING)
		cm_nl_bonding_link(ifp);
#endif
}

static void cm_unlink_iface (struct cm_iface *ifp)
{
	TAILQ_REMOVE (&ifacehead, ifp, link);
	LIST_REMOVE(ifp, h_ifindex);
	LIST_REMOVE(ifp, h_ifuid);

#ifdef HAVE_IFLA_BOND
	cm_nl_bonding_unlink(ifp);
#endif
}

struct cm_iface *
iflookup (u_int32_t ifindex, u_int32_t vrfid)
{
	struct cm_iface *ifp;
	int hash = ifindex & CM_IF_HASH_MASK;

	LIST_FOREACH(ifp, &ifindex_hash_table[hash], h_ifindex) {
		if (ifp->ifindex == ifindex)
#ifdef CONFIG_PORTS_CACHEMGR_NETNS
			if (ifp->vrfid == vrfid)
#endif
				return (ifp);
	}
	return (NULL);
}

struct cm_iface *
iflookupbyifuid (u_int32_t ifuid)
{
	struct cm_iface *ifp;
	int hash = ifuid & CM_IF_HASH_MASK;

	LIST_FOREACH (ifp, &ifuid_hash_table[hash], h_ifuid) {
		if (ifp->ifuid == ifuid)
			return (ifp);
	}
	return (NULL);
}

#ifdef CONFIG_CACHEMGR_BRIDGE
static void cm_link_bridge(struct cm_iface *ifp)
{
	int hash1 = ifp->ifindex & CM_IF_HASH_MASK;
	int hash2 = ifp->ifuid & CM_IF_HASH_MASK;

	TAILQ_INSERT_HEAD(&bridgehead, ifp, link);
	LIST_INSERT_HEAD(&bridge_ifindex_hash_table[hash1], ifp, h_ifindex);
	LIST_INSERT_HEAD(&bridge_ifuid_hash_table[hash2], ifp, h_ifuid);
}

static void cm_unlink_bridge(struct cm_iface *ifp)
{
	TAILQ_REMOVE(&bridgehead, ifp, link);
	LIST_REMOVE(ifp, h_ifindex);
	LIST_REMOVE(ifp, h_ifuid);
}

struct cm_iface *bridge_iflookup(u_int32_t ifindex, u_int32_t vrfid)
{
	int hash = ifindex & CM_IF_HASH_MASK;
	struct cm_iface *ifp;

	LIST_FOREACH(ifp, &bridge_ifindex_hash_table[hash], h_ifindex)
		if (ifp->ifindex == ifindex)
#ifdef CONFIG_PORTS_CACHEMGR_NETNS
			if (ifp->vrfid == vrfid)
#endif
				return ifp;
	return NULL;
}

struct cm_iface *bridge_iflookupbyifuid(u_int32_t ifuid)
{
	int hash = ifuid & CM_IF_HASH_MASK;
	struct cm_iface *ifp;

	LIST_FOREACH(ifp, &bridge_ifuid_hash_table[hash], h_ifuid)
		if (ifp->ifuid == ifuid)
			return ifp;
	return NULL;
}
#endif /* CONFIG_CACHEMGR_BRIDGE */

void cm_display_interfaces(void(*display)(int, const char *, ...), int s)
{
	struct cm_iface *ifp;

	display(s, "Interfaces list:\n");
	TAILQ_FOREACH(ifp, &ifacehead, link) {
		display(s, "%s vrfid %u (ifindex: %u, ifuid: 0x%x)\n",
			ifp->ifname, ifp->vrfid, ifp->ifindex,
			ntohl(ifp->ifuid));
		display(s, "\ttype: %u, subtype: %u, flags: 0x%x, mtu: %u\n",
			ifp->type, ifp->subtype, ifp->flags, ifp->mtu);
		display(s, "\tmaster_ifuid: 0x%x, vnb_nodeid: 0x%x\n",
			ifp->master_ifuid, ifp->vnb_nodeid);
		display(s, "\tin_l_bond: %s, blade_id: %u\n",
			ifp->in_l_bond ? "yes" : "no", ifp->blade_id);
	}
#ifdef CONFIG_CACHEMGR_BRIDGE
	display(s, "Bridge interfaces list:\n");
	TAILQ_FOREACH(ifp, &bridgehead, link) {
		display(s, "%s vrfid %u (ifindex: %u, ifuid: 0x%x)\n",
			ifp->ifname, ifp->vrfid, ifp->ifindex,
			ntohl(ifp->ifuid));
		display(s, "\ttype: %u, subtype: %u, master_ifuid: 0x%x\n",
			ifp->type, ifp->subtype, ifp->master_ifuid);
	}
#endif
}

void
nlbase_init(void)
{
	int i;
	memset (cm_vrf, 0, sizeof cm_vrf);
	TAILQ_INIT(&ifacehead);
#ifdef HAVE_IFLA_BOND
	LIST_INIT(&ifbond_list);
#endif
	for (i=0; i<CM_IF_HASH_MAX; i++) {
		LIST_INIT(&ifindex_hash_table[i]);
		LIST_INIT(&ifuid_hash_table[i]);
	}

	promisc_count = 0;
	raw_mode_method = 0;
}

void
nlbase_clear(u_int32_t vrfid)
{
	struct cm_iface *ifa, *ifa_next;

	ifa = TAILQ_FIRST (&ifacehead);
	while (ifa) {
		if (ifa->vrfid != vrfid) {
			ifa = TAILQ_NEXT(ifa, link);
			continue;
		}
		ifa_next = TAILQ_NEXT(ifa, link);
		cm_unlink_iface (ifa);
		free (ifa);
		ifa = ifa_next;
	}
}

const struct cm_iface_handler *
cm_iface_handler_lookup(u_int32_t cm_type)
{
	static const struct cm_iface_handler
		Handler_eth    = { cm_eth_alloc, cm_eth_create, cm_eth_change, cm_eth_delete },
		Handler_6in4   = { cm_6in4_alloc, cm_6in4_create, cm_6in4_change, cm_6in4_delete },
		Handler_Xin6   = { cm_Xin6_alloc, cm_Xin6_create, cm_Xin6_change, cm_Xin6_delete },
		Handler_svti   = { cm_svti_alloc, cm_svti_create, cm_svti_change, cm_svti_delete },
		Handler_vti    = { cm_vti_alloc, cm_vti_create, cm_vti_change, cm_vti_delete },
#ifdef CONFIG_CACHEMGR_BRIDGE
		Handler_brport = { cm_brport_alloc, cm_brport_create, cm_brport_change, cm_brport_delete },
#endif
#ifdef CONFIG_CACHEMGR_GRE
		Handler_gre = { cm_gre_alloc, cm_gre_create, cm_gre_change, cm_gre_delete },
#endif
		Handler_dummy  = { 0, 0, 0, 0 };

	const struct cm_iface_handler *handler;

	switch(cm_type) {

		case CM_IFTYPE_ETH:
		case CM_IFTYPE_LOOP:
		case CM_IFTYPE_LOCAL:
			handler = &Handler_eth;
			break;

		case CM_IFTYPE_6IN4:
			handler = &Handler_6in4;
			break;

		case CM_IFTYPE_XIN6:
			handler = &Handler_Xin6;
			break;

		case CM_IFTYPE_SVTI:
			handler = &Handler_svti;
			break;

		case CM_IFTYPE_VTI:
			handler = &Handler_vti;
			break;
#ifdef CONFIG_CACHEMGR_BRIDGE
		case CM_IFTYPE_BRPORT:
			handler = &Handler_brport;
			break;
#endif
#ifdef CONFIG_CACHEMGR_GRE
		case CM_IFTYPE_GRE:
			handler = &Handler_gre;
			break;
#endif
		default:
			/* we should never go there: the default type
			 * is set to IFTYPE_LOCAL in cm_nl_link() */
			handler = &Handler_dummy;
			break;
	}

	return (handler);
}

#ifdef HAVE_IFLA_INFO_SLAVE
static void
cm_slave_handler(u_int32_t cm_slavetype, struct cm_iface *ifp,
		 struct nlmsghdr *h, struct nlattr **tb)
{
	switch(cm_slavetype) {
#ifdef CONFIG_CACHEMGR_BONDING
	case CM_SLAVETYPE_BONDING:
		cm_slave_bonding_update(ifp, h, tb);
		break;
#endif
	}
}
#endif /* HAVE_IFLA_INFO_SLAVE */

void
cm_nl_iface_addr (struct nlmsghdr *h, u_int32_t sock_vrfid)
{
	int err;
	struct ifaddrmsg *ifa;
	struct nlattr *tb [IFA_MAX + 1];
	void *addr = NULL;
	u_int8_t pfxlen;
	uint32_t ifa_uid = 0;

	ifa = nlmsg_data (h);
	if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6)
		return ;

	err = cm_nlmsg_parse(h, sizeof(*ifa), tb, IFA_MAX, MSG_FAMILY_ADDR);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return ;
	}

	pfxlen = (u_int8_t)ifa->ifa_prefixlen;

	ifa_uid = cm_ifindex2ifuid (ifa->ifa_index, sock_vrfid, 1);
	if (ifa_uid == 0) {
		syslog(LOG_DEBUG, "%s: %s with unknown ifindex %d\n",
			__FUNCTION__, rtm_type2str(h->nlmsg_type),
			ifa->ifa_index);
		return;
	}

	/*
	 * XXX
	 * IFA_LOCAL is supposed to be the address of the interface
	 * and IFA_ADDRESS is supposed to be the endpoint of a
	 * point-to-point interface.
	 * However, in case of IPv6, there was a bug on Linux where
	 * IFA_ADDRESS was used instead of IFA_LOCAL.
	 * This if / else helps to support bugged Linux 2.4 and 2.6.
	 * It has been fixed on the 6WINDGate(tm).
	 */
	if (tb[IFA_LOCAL])
		addr = (struct in_addr *)nla_data (tb[IFA_LOCAL]);
	else if (tb[IFA_ADDRESS])
		addr = (struct in_addr *)nla_data (tb[IFA_ADDRESS]);
	else {
		syslog(LOG_ERR, "%s: %s no IFA_LOCAL or IFA_ADDRESS attribute\n",
			__FUNCTION__, rtm_type2str(h->nlmsg_type));
		return;
	}

	if (ifa->ifa_family == AF_INET) {
		cm2cp_ipv4_addr (h->nlmsg_seq, h->nlmsg_type,
			ifa_uid, (struct in_addr *)addr, pfxlen);
	}
	else {
		uint16_t *p;

		/*
		 * Keep any linklocal stuff out of FPM, ALL
		 * is managed by the fe80::/10 route
		 */
		if (IN6_IS_ADDR_LINKLOCAL(addr)) {
			if (cm_debug_level & CM_DUMP_DBG_NL_RECV)
				syslog(LOG_ERR, "%s: "
					"filtering out link-local addresses\n",
					__FUNCTION__);
			return;
		}

		/*
		 * Filter out any ::/80 addresses i.e. first 10 bytes null
		 */
		p = (uint16_t *)addr;
		if ((p[0] | p[1]| p[2] | p[3] | p[4]) == 0) {
			if (cm_debug_level & CM_DUMP_DBG_NL_RECV)
				syslog(LOG_ERR, "%s: "
					"filtering out ::/80 addresses\n",
					__FUNCTION__);
			return;
		}

		cm2cp_ipv6_addr (h->nlmsg_seq, h->nlmsg_type,
			ifa_uid, (struct in6_addr *)addr, pfxlen);
	}
	return;
}

char *cm_index2name(u_int32_t ifindex, u_int32_t vrfid) {
	struct cm_iface *ifp;
	ifp = iflookup(ifindex, vrfid);
	if (ifp)
		return ifp->ifname;
	return NULL;
}

char *cm_ifuid2name(uint32_t ifuid) {
	struct cm_iface *ifp;
	ifp = iflookupbyifuid(ifuid);
	if (ifp)
		return ifp->ifname;
	return NULL;
}

static struct cm_iface *
cm_eth_alloc(u_int32_t cm_subtype)
{
	size_t size = sizeof(struct cm_iface) + sizeof(struct cm_eth_params);

	switch (cm_subtype) {
#ifdef CONFIG_CACHEMGR_VXLAN
	case CM_IFSUBTYPE_VXLAN:
		size += sizeof(struct cm_vxlan_params);
		break;
#endif
#ifdef CONFIG_CACHEMGR_VLAN
        case CM_IFSUBTYPE_VLAN:
                size += sizeof(struct cm_vlan_params);
                break;
#endif
#ifdef CONFIG_CACHEMGR_MACVLAN
        case CM_IFSUBTYPE_MACVLAN:
                size += sizeof(struct cm_macvlan_params);
                break;
#endif
#ifdef CONFIG_CACHEMGR_BONDING
	case CM_IFSUBTYPE_BONDING:
		size += sizeof(struct cm_bonding_params);
		break;
#endif
#ifdef CONFIG_CACHEMGR_GRE
	case CM_IFSUBTYPE_GRETAP:
		size += sizeof(struct cm_gre_params);
		break;
#endif
	}

	return (struct cm_iface *)calloc(1, size);
}

static struct cm_iface *
cm_6in4_alloc(u_int32_t cm_subtype)
{
	return (struct cm_iface *)calloc(1, sizeof(struct cm_iface) + sizeof(struct cm_6in4_params));
}

static struct cm_iface *
cm_Xin6_alloc(u_int32_t cm_subtype)
{
	return (struct cm_iface *)calloc(1, sizeof(struct cm_iface) + sizeof(struct cm_Xin6_params));
}

static struct cm_iface *
cm_svti_alloc(u_int32_t cm_subtype)
{
	return (struct cm_iface *)calloc(1, sizeof(struct cm_iface) + sizeof(struct cm_svti_params));
}

static struct cm_iface *
cm_vti_alloc(u_int32_t cm_subtype)
{
	return (struct cm_iface *)calloc(1, sizeof(struct cm_iface) + sizeof(struct cm_vti_params));
}

static u_int32_t
cm_nl_flags (int k_flags, struct nlattr **tb)
{
	u_int32_t cm_flags = 0;
	if (k_flags & IFF_UP)
		cm_flags |= CM_CPIFACE_IFFUP;
	/* When defined, IFLA_PROMISCUITY normally implies IFF_PROMISC, so
	 * checking for both may seem redundant. The reason is that at least
	 * one kernel (RHEL 6.4 / OpenStack) defines this macro but doesn't
	 * actually implement it.
	 */
#ifdef IFLA_PROMISCUITY
	if (tb[IFLA_PROMISCUITY] &&
	    *(u_int32_t *)nla_data(tb[IFLA_PROMISCUITY]) > 0)
		cm_flags |= CM_CPIFACE_IFFPROMISC;
#endif
	if (k_flags & IFF_PROMISC)
		cm_flags |= CM_CPIFACE_IFFPROMISC;
	if (k_flags & IFF_RUNNING)
		cm_flags |= CM_CPIFACE_IFFRUNNING;
#ifdef IFLA_IPV4_FORWARD
	if (tb[IFLA_IPV4_FORWARD]) {
		if (*(u_int32_t *)nla_data (tb[IFLA_IPV4_FORWARD]))
			cm_flags |= CM_CPIFACE_IFFFWD_IPV4;
	}
	else
#endif
		cm_flags |= CM_CPIFACE_IFFFWD_IPV4;
#ifdef IFLA_IPV6_FORWARD
	if (tb[IFLA_IPV6_FORWARD]) {
		if (*(u_int32_t *)nla_data (tb[IFLA_IPV6_FORWARD]))
			cm_flags |= CM_CPIFACE_IFFFWD_IPV6;
	}
	else
#endif
		cm_flags |= CM_CPIFACE_IFFFWD_IPV6;
#ifdef IFLA_IPV4_RPF
	if (tb[IFLA_IPV4_RPF]) {
		if (*(u_int32_t *)nla_data(tb[IFLA_IPV4_RPF]))
			cm_flags |= CM_CPIFACE_IFFRPF_IPV4;
	}
#endif
#ifdef IFLA_XFLAGS
	if (tb[IFLA_XFLAGS]) {
		uint16_t xflags = *(uint16_t *)nla_data(tb[IFLA_XFLAGS]);
#ifdef IFF_PREFERRED
		if (xflags & IFF_PREFERRED)
			cm_flags |= CM_CPIFACE_IFFPREFERRED;
#endif
	}
#endif /*IFLA_XFLAGS*/
	return cm_flags;
}

#ifdef CONFIG_CACHEMGR_BRIDGE
static void cm_nl_bridge(struct nlmsghdr *h, struct nlattr **tb, int ifindex,
			 char *name, u_int32_t ifuid, u_int32_t vrfid,
			 const struct cm_iface_handler *handler,
			 u_int32_t cm_type, u_int32_t cm_subtype)
{
	struct cm_iface *ifp;

	if (h->nlmsg_type == RTM_NEWLINK) {
		ifp = bridge_iflookupbyifuid(ifuid);
		if (ifp && ifp->ifindex != ifindex) {
			syslog(LOG_DEBUG,
			       "%s: %s ignoring interface %s with different ifindex(cur=%u,msg=%u)\n",
			       __func__, rtm_type2str(h->nlmsg_type), name,
			       ifp->ifindex, ifindex);
			return;
		}
		if (ifp == NULL) {
			/* OK, this is a brand new interface
			 * just create it, and tell FPM
			 */
			if (handler->cm_iface_alloc)
				ifp = handler->cm_iface_alloc(cm_subtype);
			else {
				if (cm_debug_level & CM_DUMP_DBG_NL_RECV) {
					syslog(LOG_ERR,
					       "%s: %s no iface_alloc handler for %s (%s)\n",
					       __func__,
					       rtm_type2str(h->nlmsg_type),
					       name, cm_iftype2str(cm_type));
				}
				return;
			}

			/* handle common part */
			ifp->ifindex = ifindex;
			ifp->ifuid   = ifuid;
			ifp->linkvrfid = vrfid;
			ifp->vrfid = vrfid;
			strncpy(ifp->ifname, name, CM_IFNAMSIZE);
			ifp->type = cm_type;
			ifp->subtype = cm_subtype;
			/* IFLA_VRF_* attributes are set only for rtnl msg with
			 * family AF_UNSPEC, ie AF_BRIDGE family does not have
			 * them. Anyway, x-vrf is not supported for bridge.
			 */
			ifp->master_ifuid = cm_ifindex2ifuid(nla_get_u32(tb[IFLA_MASTER]),
							     vrfid, 0);

			/* handle interface-type specific part */
			if (handler->cm_iface_create)
				handler->cm_iface_create(ifp, h, tb);
			else if (cm_debug_level & CM_DUMP_DBG_NL_RECV) {
				syslog(LOG_ERR,
				       "%s: %s no iface_create handler for %s (%s)\n",
				       __func__, rtm_type2str(h->nlmsg_type),
				       name, cm_iftype2str(cm_type));
			}

			cm_link_bridge(ifp);
		} else {
			/*
			 * Call interface specific change function
			 */
			if (handler->cm_iface_change)
				handler->cm_iface_change(ifp, h, tb);
			else if (cm_debug_level & CM_DUMP_DBG_NL_RECV) {
				syslog(LOG_ERR,
				       "%s: %s no iface_change handler for %s (%s)\n",
				       __func__, rtm_type2str(h->nlmsg_type),
				       name, cm_iftype2str(cm_type));
			}
		}
	} else {
		/*
		 * DELETE case
		 */

		ifp = bridge_iflookupbyifuid(ifuid);
		if (ifp && ifp->ifindex != ifindex) {
			syslog(LOG_DEBUG,
			       "%s: %s ignoring interface %s with different ifindex (cur=%u,msg=%u)\n",
			       __func__, rtm_type2str(h->nlmsg_type), name,
			       ifp->ifindex, ifindex);
			return;
		}
		if (ifp == NULL)
			return;

		cm_unlink_bridge(ifp);

		if (handler->cm_iface_delete)
			handler->cm_iface_delete(ifp, h, tb);
		else if (cm_debug_level & CM_DUMP_DBG_NL_RECV) {
			syslog(LOG_ERR,
			       "%s: %s no iface_delete handler for %s (%s)\n",
			       __func__, rtm_type2str(h->nlmsg_type), name,
			       cm_iftype2str(cm_type));
		}
		free (ifp);
	}
}
#endif

/*
 * handle RTM_NETLINK and RTM_DELLINK messages
 *
 * Note:
 *
 * When a netns appears, the cmgr needs time to open a netlink socket in this
 * netns and to start listening for messages. It may hence miss the first
 * netlink messages.
 *
 * It is therefore necessary to first dump the interfaces in this netns before
 * handling the spontaneous netlink messages.
 *
 * However the dump of interfaces often describes a state of the system
 * posterior to the first received messages.
 *
 * Example:
 *
 * - (0) netns creation
 * - (1) netlink notification <--- never recvd, send before socket creation
 * - (2) netlink notification <--- first recvd msg after creating socket
 * - (3) netlink notification
 *                            <--- state of the system at the time of the dump
 * - (4) netlink notification
 * - (5) netlink notification
 * - (6) netlink notification
 *
 * In the case described above, after dumping the interfaces, the cmgr is in
 * the same state as if it had handled messages (1) (2) and (3).
 *
 * Then it starts processing received messages (2) (3) (4)... The handling of
 * messages (2) and (3) makes a "jump in the past". This may cause
 * unrecoverable side effects when the interface did a round-trip from an
 * initial netns, then back to the same netns while changing ifindex
 *
 * => identify interfaces by their ifuid instead of ifindex + vrfid. As an
 * optimization, also ignore interface advertisments for the same interface but
 * different ifindex, they are obviously outdated.
 */
void
cm_nl_link (struct nlmsghdr *h, u_int32_t sock_vrfid)
{
	int err;
	struct ifinfomsg *ifi;
	struct nlattr *tb [IFLA_MAX + 1];
	char *name;
	struct cm_iface *ifp;
	u_int32_t vrfid = sock_vrfid;
	u_int32_t master_vrfid = sock_vrfid;
	u_int32_t ifuid = 0;
	u_int32_t cm_type;
	u_int32_t cm_subtype;
#ifdef HAVE_IFLA_INFO_SLAVE
	u_int32_t cm_slavetype = CM_SLAVETYPE_NONE;
#endif
	const struct cm_iface_handler *handler;
	int mac_required;
	int bladeid = CM_BLADE_CP;

	ifi = nlmsg_data (h);

	if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
		syslog(LOG_DEBUG, "    family=%u type=%hu index=%d flags=%08x change=%08x\n",
			ifi->ifi_family, ifi->ifi_type, ifi->ifi_index,
			ifi->ifi_flags, ifi->ifi_change);

	err = cm_nlmsg_parse(h, sizeof(*ifi), tb, IFLA_MAX, MSG_FAMILY_IFACE);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

	if (tb[IFLA_IFNAME] == NULL) {
		syslog(LOG_ERR, "%s: %s no IFLA_IFNAME attribute\n",
			__FUNCTION__, rtm_type2str(h->nlmsg_type));
		return;
	}
	name = (char *)nla_data(tb[IFLA_IFNAME]);
#ifdef IFLA_VRFID
	if (tb[IFLA_VRFID])
		vrfid = *(u_int32_t *) nla_data (tb[IFLA_VRFID]);
#endif
	ifuid = ifname2ifuid (name, vrfid);

	mac_required = 0;
	cm_type    = CM_IFTYPE_LOCAL;
	cm_subtype = CM_IFSUBTYPE_NORMAL;

	if (tb[IFLA_LINKINFO]) {
		struct nlattr *linkinfo[IFLA_INFO_MAX + 1];
		char *kind = "";

		cm_nl_parse_nlattr(linkinfo, IFLA_INFO_MAX,
				   nla_data(tb[IFLA_LINKINFO]),
				   nla_len(tb[IFLA_LINKINFO]),
				   MSG_FAMILY_IFACE);

		if (linkinfo[IFLA_INFO_KIND])
			kind = (char*)nla_data(linkinfo[IFLA_INFO_KIND]);

		if (!strcmp(kind, "ng_eiface"))
			cm_subtype = CM_IFSUBTYPE_NGEIFACE;

		else if (!strcmp(kind, "veth")) {
			if (!strncmp(name, "xvrf", 4))
				cm_subtype = CM_IFSUBTYPE_XVRF;
			else
				cm_subtype = CM_IFSUBTYPE_VETH;
		}

		else if (!strcmp(kind, "rfpvi")) {
			if (linkinfo[IFLA_INFO_DATA]) {
				struct nlattr *infodata[IFLA_RFPVI_MAX + 1];

				cm_nl_parse_nlattr(infodata, IFLA_RFPVI_MAX,
						nla_data(linkinfo[IFLA_INFO_DATA]),
						nla_len(linkinfo[IFLA_INFO_DATA]),
						MSG_FAMILY_IFACE);

				bladeid = *(uint8_t*)nla_data(infodata[IFLA_RFPVI_BLADEID]);
			}
		}

		else if (!strcmp(kind, "ipip"))
			cm_type = CM_IFTYPE_6IN4;

		else if (!strcmp(kind, "vti") || !strcmp(kind, "vti6"))
			cm_type = CM_IFTYPE_VTI;
#ifdef CONFIG_CACHEMGR_GRE
		else if (!strcmp(kind, "gre") || !strcmp(kind, "ip6gre"))
			cm_type = CM_IFTYPE_GRE;
		else if (!strcmp(kind, "gretap") || !strcmp(kind, "ip6gretap"))
			cm_subtype = CM_IFSUBTYPE_GRETAP;
#endif
#ifdef CONFIG_CACHEMGR_VXLAN
		else if (!strcmp(kind, "vxlan"))
			cm_subtype = CM_IFSUBTYPE_VXLAN;
#endif
#ifdef CONFIG_CACHEMGR_VLAN
                else if (!strcmp(kind, "vlan"))
                        cm_subtype = CM_IFSUBTYPE_VLAN;
#endif
#ifdef CONFIG_CACHEMGR_MACVLAN
                else if (!strcmp(kind, "macvlan"))
                        cm_subtype = CM_IFSUBTYPE_MACVLAN;
#endif
#ifdef CONFIG_CACHEMGR_BRIDGE
		else if (!strcmp(kind, "bridge")) {
			cm_subtype = CM_IFSUBTYPE_BRIDGE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
			/* Start a dump with IFLA_EXT_MASK set to
			 * RTEXT_FILTER_BRVLAN to get
			 * IFLA_AF_SPEC/IFLA_BRIDGE_VLAN_INFO.
			 */
#endif
		}
#endif
#ifdef CONFIG_CACHEMGR_BONDING
		else if (!strcmp(kind, "bond"))
			cm_subtype = CM_IFSUBTYPE_BONDING;
#endif

#ifdef HAVE_IFLA_INFO_SLAVE
		if (linkinfo[IFLA_INFO_SLAVE_KIND]) {
			kind = (char*)nla_data(linkinfo[IFLA_INFO_SLAVE_KIND]);

#ifdef CONFIG_CACHEMGR_BONDING
			if (!strcmp(kind, "bond"))
				cm_slavetype = CM_SLAVETYPE_BONDING;
#endif
		}
#endif /* HAVE_IFLA_INFO_SLAVE */
	}

	if (ifi->ifi_family == AF_BRIDGE) {
#ifdef CONFIG_CACHEMGR_BRIDGE
		/* Skip messages for bridge interfaces, all informations are
		 * already contained in AF_UNSPEC messages.
		 */
		if (!tb[IFLA_MASTER] ||
		    nla_get_u32(tb[IFLA_MASTER]) == ifi->ifi_index)
			return;

		cm_type = CM_IFTYPE_BRPORT;
#else
		return;
#endif
	}

	if (cm_type != CM_IFTYPE_LOCAL)
		goto typefound;

	if (ifi->ifi_type == ARPHRD_LOOPBACK)
		cm_type = CM_IFTYPE_LOOP;
	else if (ifi->ifi_type == ARPHRD_TUNNEL || ifi->ifi_type == ARPHRD_SIT)
		cm_type = CM_IFTYPE_6IN4;
	else if (ifi->ifi_type == ARPHRD_TUNNEL6)
		cm_type = CM_IFTYPE_XIN6;
	else if ((ifi->ifi_type == ARPHRD_ETHER)) {
		cm_type = CM_IFTYPE_ETH;
		mac_required = 1;
	}
#ifdef ARPHRD_SVTI
	else if ((ifi->ifi_type == ARPHRD_SVTI))
		cm_type = CM_IFTYPE_SVTI;
#endif

typefound:

	/* ignore these interfaces */
	if ((!strcmp(name, "svi"))
	    || (!strcmp(name, "ifb0"))
	    || (!strcmp(name, "ip6tnl0"))
	    || (!strcmp(name, "tunl0"))
	    || (!strcmp(name, "sit0"))
	    || (!strcmp(name, "svti_cfg"))
	    || (!strncmp(name, "phy_", 4))
	    || (!strcmp(name, "teql0"))
	    || (!strcmp(name, "ip_vti0"))
	    || (!strcmp(name, "ip6_vti0"))
	    || (!strcmp(name, "gre0") && cm_type == CM_IFTYPE_GRE)
	    || (!strcmp(name, "ip6gre0") && cm_type == CM_IFTYPE_GRE)
	    || (!strcmp(name, "gretap0") && cm_subtype == CM_IFSUBTYPE_GRETAP)
	    || (!strcmp(name, "ip6gretap0") && cm_subtype == CM_IFSUBTYPE_GRETAP)
	   ) {
		if (cm_debug_level & CM_DUMP_DBG_NL_RECV)
			syslog(LOG_INFO, "%s: %s ignoring interface %s\n",
				__FUNCTION__, rtm_type2str(h->nlmsg_type), name);
		return;
	}

	handler = cm_iface_handler_lookup(cm_type);

#ifdef CONFIG_CACHEMGR_BRIDGE
	if (ifi->ifi_family == AF_BRIDGE)
		return cm_nl_bridge(h, tb, ifi->ifi_index, name, ifuid, vrfid,
				    handler, cm_type, cm_subtype);
#endif

	if (h->nlmsg_type == RTM_NEWLINK) {
		int veth_peer = 0;

		ifp = iflookupbyifuid(ifuid);
		if (ifp && ifp->ifindex != ifi->ifi_index) {
			syslog(LOG_DEBUG, "%s: %s ignoring interface %s with different ifindex(cur=%u,msg=%u)\n",
				__FUNCTION__, rtm_type2str(h->nlmsg_type), name, ifp->ifindex, ifi->ifi_index);
			return;
		}
		if (ifp == NULL) {
#ifdef CONFIG_CACHEMGR_BRIDGE
			int rename = 0;
#endif

			/* Interface has been renamed (remember that ifuid
			 * depends on ifname)? If yes, then we delete the
			 * previous interface and we create a new one.
			 */
			if ((ifp = iflookup(ifi->ifi_index, vrfid)) != NULL) {
#ifdef CONFIG_CACHEMGR_MULTIBLADE
				if (f_multiblade) {
					if ((strcmp(cm_fpib.ifname, ifp->ifname) == 0) &&
					    cm_fpib.ifuid) {
						cm_fpib.ifuid = 0;
						cm2cp_fpib_change(h->nlmsg_seq, NULL);
					}
				}
#endif
				cm_vrf[ifp->vrfid]--;
				cm_unlink_iface(ifp);
				ifp->vnb_keep_node = 1;

				/* Need to cheat for the message type */
				h->nlmsg_type = RTM_DELLINK;
				if (handler->cm_iface_delete) {
					/* route messages should be sent prior
					 * to interface deletion.
					 */
					purge_rtQueues();
					handler->cm_iface_delete(ifp, h, tb);
				} else if (cm_debug_level & CM_DUMP_DBG_NL_RECV)
					syslog(LOG_ERR,
					       "%s: no iface_delete func to handle renaming\n",
					       __func__);
				free(ifp);
				ifp = NULL;
				h->nlmsg_type = RTM_NEWLINK;
#ifdef CONFIG_CACHEMGR_BRIDGE
				rename = 1;
#endif
			}
			/*
		 	 * OK, this is a brand new interface
		 	 * just create it, and tell FPM
		 	 */

			/*
			 * Ignore I/F with NO MAC address, or at least
			 * wait for them to have acquired one (have bnet
			 * in mind ..)
			 */
			if (mac_required) {
				if (tb[IFLA_ADDRESS] == NULL) {
					if (cm_debug_level & CM_DUMP_DBG_NL_RECV) {
						syslog(LOG_ERR, "%s: "
							"%s no IFLA_ADDRESS attribute for %s\n",
							__FUNCTION__, rtm_type2str(h->nlmsg_type), name);
					}
					return;
				}
				if (nla_len(tb[IFLA_ADDRESS]) == 0) {
					if (cm_debug_level & CM_DUMP_DBG_NL_RECV) {
						syslog(LOG_ERR, "%s: "
							"%s empty IFLA_ADDRESS field for %s\n",
							__FUNCTION__, rtm_type2str(h->nlmsg_type), name);
					}
					return;
				}
			}

			if (handler->cm_iface_alloc)
				ifp = handler->cm_iface_alloc(cm_subtype);
			else {
				if (cm_debug_level & CM_DUMP_DBG_NL_RECV) {
					syslog(LOG_ERR, "%s: "
						"%s no iface_alloc handler for %s (%s)\n",
						__FUNCTION__, rtm_type2str(h->nlmsg_type), name,
						cm_iftype2str(cm_type));
				}
				return;
			}

			/* handle common part */
			ifp->ifindex = ifi->ifi_index;
			ifp->ifuid   = ifuid;
#ifdef IFLA_LINKVRFID
			if (tb[IFLA_LINKVRFID])
				ifp->linkvrfid = *(u_int32_t *) nla_data (tb[IFLA_LINKVRFID]);
			else
#endif
				ifp->linkvrfid = vrfid;
#ifdef IFLA_VRFID
			if (tb[IFLA_VRFID]) {
				ifp->vrfid = *(u_int32_t *) nla_data (tb[IFLA_VRFID]);
				cm_vrf[ifp->vrfid]++;
			}
			else
#endif
				ifp->vrfid = vrfid;
			strncpy (ifp->ifname, name, CM_IFNAMSIZE);
			ifp->type = cm_type;
			ifp->subtype = cm_subtype;
			ifp->flags = cm_nl_flags (ifi->ifi_flags, tb);
			ifp->mtu = *(u_int32_t *)nla_data (tb[IFLA_MTU]);

			ifp->vnb_nodeid = 0;

#ifdef HAS_IFLA_AF_SPEC
			if (tb[IFLA_AF_SPEC]) {
				struct nlattr *afspec[AF_MAX + 1];
				unsigned int i;

				cm_nl_parse_nlattr(afspec, AF_MAX, nla_data(tb[IFLA_AF_SPEC]),
						   nla_len(tb[IFLA_AF_SPEC]), MSG_FAMILY_IFACE);

				/* We know only dynamically registered hooks
				 * may have parse_afspec hooks */
				for (i = CM_REGISTERED_FIRST;
				     i <= CM_REGISTERED_LAST; i++) {
					if (!nlsock_hooks[i].parse_afspec)
						continue;
					nlsock_hooks[i].parse_afspec(afspec,
					                             ifp, 1);
				}

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
				if (afspec[AF_VRF]) {
					struct nlattr *vrf_afspec[IFLA_VRF_MAX+1];
					struct nlattr *attr = afspec[AF_VRF];

					cm_nl_parse_nlattr(vrf_afspec, IFLA_VRF_MAX,
							   nla_data(attr), nla_len(attr),
							   MSG_FAMILY_IFACE);

					if (vrf_afspec[IFLA_VRF_LINKVRFID])
						ifp->linkvrfid = *(u_int32_t *)nla_data(vrf_afspec[IFLA_VRF_LINKVRFID]);
					if (vrf_afspec[IFLA_VRF_MASTERVRFID])
						master_vrfid = nla_get_u32(vrf_afspec[IFLA_VRF_MASTERVRFID]);
					if (vrf_afspec[IFLA_VRF_VETH_PEER])
						veth_peer = nla_get_u32(vrf_afspec[IFLA_VRF_VETH_PEER]);
				}
#endif
			}
#endif /* HAS_IFLA_AF_SPEC */

			if (tb[IFLA_MASTER])
				ifp->master_ifuid = cm_ifindex2ifuid(nla_get_u32(tb[IFLA_MASTER]),
								     master_vrfid, 0);

			/* handle interface-type specific part */
			if (handler->cm_iface_create)
				handler->cm_iface_create(ifp, h, tb);
			else {
				if (cm_debug_level & CM_DUMP_DBG_NL_RECV) {
					syslog(LOG_ERR, "%s: "
						"%s no iface_create handler for %s (%s)\n",
						__FUNCTION__, rtm_type2str(h->nlmsg_type), name,
						cm_iftype2str(cm_type));
				}
			}
			cm_link_iface (ifp);

#if defined(CONFIG_CACHEMGR_BONDING) && defined(HAVE_IFLA_INFO_SLAVE)
			if (cm_slavetype == CM_SLAVETYPE_BONDING)
				cm_nl_bonding_link(ifp);
#endif

			/*
			 * Send a msg to FPM to set the MTU of this interface on FP-linux.
			 */
			cm2cp_iface_mtu(h->nlmsg_seq, ifuid, ifp->mtu);

			/*
			 * Interface is directly created with some flags
			 * but we must notify the FPM in two stages
			 */
			if (ifp->flags)
				cm2cp_iface_state (h->nlmsg_seq, ifuid, ifp->flags, ifp->flags);

			if (ifp->master_ifuid)
				cm2cp_iface_master (h->nlmsg_seq, ifuid, ifp->master_ifuid);

			cm2cp_iface_bladeinfo(h->nlmsg_seq, ifuid, bladeid);
			ifp->blade_id    = bladeid;

#ifdef CONFIG_CACHEMGR_BRIDGE
			/* take care of bridge ports (there is no AF_BRIDGE msg
			 * for this renaming). Note also that the new interface
			 * must exist in the shared memory before asking for the
			 * brport creation.
			 */
			if (rename)
				cm_brport_rename(h->nlmsg_seq, ifi->ifi_index,
						 name, vrfid, ifuid);
#endif
		} else {
			/*
		 	 * Just Interface status change.
		 	 */
			uint32_t flags;

			/*
			 * First check blade info
			 */

			if (bladeid != ifp->blade_id) {
				cm2cp_iface_bladeinfo(h->nlmsg_seq, ifuid, bladeid);
				ifp->blade_id    = bladeid;
			}

			/*
			 * First check MTU
			 */
			if (tb[IFLA_MTU]) {
				u_int32_t mtu;
				mtu = *(u_int32_t *)nla_data (tb[IFLA_MTU]);
				if (ifp->mtu != mtu) {
					cm2cp_iface_mtu (h->nlmsg_seq, ifuid, mtu);
					ifp->mtu = mtu;
				}
			}

			/* check IFLA_VRF_MASTERVRFID */
#ifdef HAS_IFLA_AF_SPEC
			if (tb[IFLA_AF_SPEC]) {
				struct nlattr *afspec[AF_MAX + 1];

				cm_nl_parse_nlattr(afspec, AF_MAX, nla_data(tb[IFLA_AF_SPEC]),
						   nla_len(tb[IFLA_AF_SPEC]), MSG_FAMILY_IFACE);

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
				if (afspec[AF_VRF]) {
					struct nlattr *vrf_afspec[IFLA_VRF_MAX+1];
					struct nlattr *attr = afspec[AF_VRF];

					cm_nl_parse_nlattr(vrf_afspec, IFLA_VRF_MAX,
							   nla_data(attr), nla_len(attr),
							   MSG_FAMILY_IFACE);

					if (vrf_afspec[IFLA_VRF_MASTERVRFID])
						master_vrfid = nla_get_u32(vrf_afspec[IFLA_VRF_MASTERVRFID]);
					if (vrf_afspec[IFLA_VRF_VETH_PEER])
						veth_peer = nla_get_u32(vrf_afspec[IFLA_VRF_VETH_PEER]);
				}
#endif
			}
#endif /* HAS_IFLA_AF_SPEC */

			if (tb[IFLA_MASTER]) {
				u_int32_t master_ifuid =
					cm_ifindex2ifuid(nla_get_u32(tb[IFLA_MASTER]),
							 master_vrfid, 1);

				if (ifp->master_ifuid != master_ifuid) {
					cm2cp_iface_master(h->nlmsg_seq,
							   ifuid,
							   master_ifuid);
					ifp->master_ifuid = master_ifuid;
				}
			} else if (ifp->master_ifuid) {
				cm2cp_iface_master(h->nlmsg_seq, ifuid,
						   0);
				ifp->master_ifuid = 0;
			}

			/*
			 * Then call interface specific change function
			 */
			if (handler->cm_iface_change)
				handler->cm_iface_change(ifp, h, tb);
			else {
				if (cm_debug_level & CM_DUMP_DBG_NL_RECV) {
					syslog(LOG_ERR, "%s: "
						"%s no iface_change handler for %s (%s)\n",
						__FUNCTION__, rtm_type2str(h->nlmsg_type), name,
						cm_iftype2str(cm_type));
				}
			}

#if defined(CONFIG_CACHEMGR_BONDING) && defined(HAVE_IFLA_INFO_SLAVE)
			if (cm_slavetype == CM_SLAVETYPE_BONDING)
				cm_nl_bonding_link(ifp);
			else if (ifp->subtype != CM_IFSUBTYPE_BONDING)
				cm_nl_bonding_unlink(ifp);
#endif

			/*
			 * End with Flags
			 */
			flags = cm_nl_flags (ifi->ifi_flags, tb);

			if (ifp->flags != flags) {
				cm2cp_iface_state (h->nlmsg_seq, ifuid, flags, ifp->flags ^ flags);
				ifp->flags = flags;
			}
		}

#ifdef CONFIG_CACHEMGR_MULTIBLADE
		if (f_multiblade) {
			if ((strcmp(cm_fpib.ifname, ifp->ifname) == 0) &&
					cm_fpib.ifuid != ifp->ifuid) {
				cm_fpib.ifuid = ifp->ifuid;
				cm2cp_fpib_change (h->nlmsg_seq, ifp);
			}
		}
#endif

#ifdef HAVE_IFLA_INFO_SLAVE
		cm_slave_handler(cm_slavetype, ifp, h, tb);
#endif

		if (cm_subtype == CM_IFSUBTYPE_VETH && veth_peer) {
			u_int32_t peer_ifuid;

			peer_ifuid = cm_ifindex2ifuid(veth_peer, ifp->linkvrfid, 0);
			cm2cp_veth_peer(h->nlmsg_seq, ifp->ifuid, peer_ifuid);
		}
	} else {
		/*
	 	 * DELETE case
	 	 */

#ifdef CONFIG_CACHEMGR_MULTIBLADE
		if (f_multiblade) {
			if ((strcmp(cm_fpib.ifname, name) == 0) &&
					cm_fpib.ifuid) {
				cm_fpib.ifuid = 0;
				cm2cp_fpib_change (h->nlmsg_seq, NULL);
			}
		}
#endif
		ifp = iflookupbyifuid(ifuid);
		if (ifp && ifp->ifindex != ifi->ifi_index) {
			syslog(LOG_DEBUG, "%s: %s ignoring interface %s with different ifindex(cur=%u,msg=%u)\n",
				__FUNCTION__, rtm_type2str(h->nlmsg_type), name, ifp->ifindex, ifi->ifi_index);
			return;
		}
		if (ifp == NULL)
			return;
		cm_vrf[ifp->vrfid]--;
		cm_unlink_iface (ifp);

		ifp->vnb_keep_node = 0;

#ifdef HAS_IFLA_AF_SPEC
		if (tb[IFLA_AF_SPEC]) {
			struct nlattr *afspec[AF_MAX + 1];
			unsigned int i;

			cm_nl_parse_nlattr(afspec, AF_MAX, nla_data(tb[IFLA_AF_SPEC]),
					   nla_len(tb[IFLA_AF_SPEC]), MSG_FAMILY_IFACE);

			/* We know only dynamically registered hooks
			 * may have parse_afspec hooks */
			for (i = CM_REGISTERED_FIRST;
			     i <= CM_REGISTERED_LAST; i++) {
				if (!nlsock_hooks[i].parse_afspec)
					continue;
				nlsock_hooks[i].parse_afspec(afspec, ifp, 0);
			}
		}
#endif /* HAS_IFLA_AF_SPEC */

		if (handler->cm_iface_delete) {
			/* route messages should be sent prior
			 * to interface deletion */
			purge_rtQueues();
			handler->cm_iface_delete(ifp, h, tb);
		} else {
			if (cm_debug_level & CM_DUMP_DBG_NL_RECV) {
				syslog(LOG_ERR, "%s: "
					"%s no iface_delete handler for %s (%s)\n",
					__FUNCTION__, rtm_type2str(h->nlmsg_type), name,
					cm_iftype2str(cm_type));
			}
		}
		free (ifp);
	}
	return;
}

int
cm_genlmsg_parse(struct nlmsghdr *h, int hdrlen, struct nlattr **tb, int max, int family)
{
	int err, rem, type, len;
	struct nlattr *nla;
	struct nlattr *head;

	err = genlmsg_parse(h, hdrlen, tb, max, NULL);
	if (err < 0)
		return err;

	head = genlmsg_attrdata(nlmsg_data(h), hdrlen);
	len = genlmsg_attrlen(nlmsg_data(h), hdrlen);

	nla_for_each_attr(nla, head, len, rem) {
		type = nla_type(nla);

		/* Padding attributes */
		if (type == 0)
			continue;

		if (type > max)
			continue;

		attr_dump(nla, family);
	}

	return 0;
}

static void
cm_eth_dflt_create(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	struct cm_eth_params *params;

	params = (struct cm_eth_params *)(ifp + 1);

	if (tb[IFLA_ADDRESS]) {
		params->maclen = nla_len(tb[IFLA_ADDRESS]);
		memcpy(params->mac, nla_data(tb[IFLA_ADDRESS]), params->maclen);
	} else if (cm_debug_level & CM_DUMP_DBG_NL_RECV)
		syslog(LOG_DEBUG, "%s: %s has no mac address\n", __FUNCTION__, ifp->ifname);

	/* notify cpdp server */
	cm2cp_iface_create (h->nlmsg_seq, RTM_NEWLINK, ifp);
}

static void
cm_eth_create(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	switch (ifp->subtype) {
#ifdef CONFIG_CACHEMGR_VXLAN
	case CM_IFSUBTYPE_VXLAN:
		return cm_vxlan_create(ifp, h, tb);
#endif
#ifdef CONFIG_CACHEMGR_VLAN
        case CM_IFSUBTYPE_VLAN:
                return cm_vlan_create(ifp, h, tb);
#endif
#ifdef CONFIG_CACHEMGR_MACVLAN
        case CM_IFSUBTYPE_MACVLAN:
                return cm_macvlan_create(ifp, h, tb);
#endif
#ifdef CONFIG_CACHEMGR_BONDING
	case CM_IFSUBTYPE_BONDING:
		return cm_bonding_create(ifp, h, tb);
#endif
#ifdef CONFIG_CACHEMGR_GRE
	case CM_IFSUBTYPE_GRETAP:
		return cm_gretap_create(ifp, h, tb);
#endif
	default:
		return cm_eth_dflt_create(ifp, h, tb);
	}
}

void
cm_Xin6_common(struct cm_iface *ifp, struct nlmsghdr *h,
               struct nlattr **tb, int cmd)
{
	struct cm_Xin6_params *params;

	params = (struct cm_Xin6_params *)(ifp + 1);

#ifdef IFLA_IPTUN_MAX
	if (tb[IFLA_LINKINFO]) {
		struct nlattr *linkinfo[IFLA_INFO_MAX + 1];

		cm_nl_parse_nlattr(linkinfo, IFLA_INFO_MAX,
				   nla_data(tb[IFLA_LINKINFO]),
				   nla_len(tb[IFLA_LINKINFO]),
				   MSG_FAMILY_IFACE);

		if (linkinfo[IFLA_INFO_DATA]) {
			struct nlattr *iptuninfo[IFLA_IPTUN_MAX + 1];

			cm_nl_parse_nlattr(iptuninfo, IFLA_IPTUN_MAX,
					   nla_data(linkinfo[IFLA_INFO_DATA]),
					   nla_len(linkinfo[IFLA_INFO_DATA]),
					   MSG_FAMILY_IFACE);

			if (iptuninfo[IFLA_IPTUN_LOCAL])
				memcpy(&params->local,
				       nla_data(iptuninfo[IFLA_IPTUN_LOCAL]),
				       sizeof(params->local));
			else
				syslog(LOG_ERR, "%s: %s no local address in netlink msg\n",
				       __FUNCTION__, ifp->ifname);

			if (iptuninfo[IFLA_IPTUN_REMOTE])
				memcpy(&params->remote,
				       nla_data(iptuninfo[IFLA_IPTUN_REMOTE]),
				       sizeof(params->remote));
			else
				syslog(LOG_ERR, "%s: %s no remote address in netlink msg\n",
				       __FUNCTION__, ifp->ifname);

			if (iptuninfo[IFLA_IPTUN_TTL]) {
				params->hoplim = *(u_int8_t*)nla_data(iptuninfo[IFLA_IPTUN_TTL]);
			} else {
				params->hoplim = 64;
				syslog(LOG_ERR, "%s: %s no TTL in netlink msg\n",
				       __FUNCTION__, ifp->ifname);
			}

			if (iptuninfo[IFLA_IPTUN_TOS]) {
				params->tos = *(u_int8_t*)nla_data(iptuninfo[IFLA_IPTUN_TOS]);
				params->inh_tos = params->tos & 1;
				if (params->inh_tos)
					params->tos = 0;
			} else {
				params->tos = 0;
				params->inh_tos = 0;
				syslog(LOG_ERR, "%s: %s no TOS in netlink msg\n",
				       __FUNCTION__, ifp->ifname);
			}
		}
	} else
#endif /*IFLA_IPTUN_MAX*/
	{
		if (tb[IFLA_ADDRESS]) {
			memcpy(&params->local,
			       nla_data(tb[IFLA_ADDRESS]),
			       nla_len(tb[IFLA_ADDRESS]));
		} else
			syslog(LOG_ERR, "%s: %s no local address in netlink msg\n",
			       __FUNCTION__, ifp->ifname);

		if (tb[IFLA_BROADCAST]) {
			memcpy(&params->remote,
			       nla_data(tb[IFLA_BROADCAST]),
			       nla_len(tb[IFLA_BROADCAST]));
		} else
			syslog(LOG_ERR, "%s: %s no remote address in netlink msg\n",
			       __FUNCTION__, ifp->ifname);

#ifdef IFLA_TTL
		if (tb[IFLA_TTL]) {
			params->hoplim = *(u_int8_t*)nla_data(tb[IFLA_TTL]);
		} else {
			params->hoplim = 64;
#ifdef NOTYET
			syslog(LOG_ERR, "%s: %s no TTL in netlink msg\n",
			       __FUNCTION__, ifp->ifname);
#endif
		}
#endif /*IFLA_TTL*/

#ifdef IFLA_TOS
		if (tb[IFLA_TOS]) {
			params->tos = *(u_int8_t*)nla_data(tb[IFLA_TOS]);
			params->inh_tos = params->tos & 1;
			if (params->inh_tos)
				params->tos = 0;
		} else {
			params->tos = 0;
			params->inh_tos = 0;
#ifdef NOTYET
			syslog(LOG_ERR, "%s: %s no TOS in netlink msg\n",
			       __FUNCTION__, ifp->ifname);
#endif
		}
#endif /*IFLA_TOS*/
	}

	/* notify cpdp server */
	cm2cp_Xin6_create (h->nlmsg_seq, cmd, ifp);
}

static void
cm_Xin6_create(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	cm_Xin6_common (ifp, h, tb, RTM_NEWLINK);
}

static void
cm_6in4_common(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb, int cmd)
{
	struct cm_6in4_params *params;

#if 0
	/* structures to call tunnel ioctl */
	struct ip_tunnel_parm p;
	int fd;
	int err;
	struct ifreq ifr;
#endif

	params = (struct cm_6in4_params *)(ifp + 1);

#ifdef IFLA_IPTUN_MAX
	if (tb[IFLA_LINKINFO]) {
		struct nlattr *linkinfo[IFLA_INFO_MAX + 1];

		cm_nl_parse_nlattr(linkinfo, IFLA_INFO_MAX,
				   nla_data(tb[IFLA_LINKINFO]),
				   nla_len(tb[IFLA_LINKINFO]),
				   MSG_FAMILY_IFACE);

		if (linkinfo[IFLA_INFO_DATA]) {
			struct nlattr *iptuninfo[IFLA_IPTUN_MAX + 1];

			cm_nl_parse_nlattr(iptuninfo, IFLA_IPTUN_MAX,
					   nla_data(linkinfo[IFLA_INFO_DATA]),
					   nla_len(linkinfo[IFLA_INFO_DATA]),
					   MSG_FAMILY_IFACE);

			if (iptuninfo[IFLA_IPTUN_LOCAL])
				memcpy(&params->local,
				       nla_data(iptuninfo[IFLA_IPTUN_LOCAL]),
				       sizeof(params->local));
			else
				syslog(LOG_ERR, "%s: %s no local address in netlink msg\n",
					__FUNCTION__, ifp->ifname);

			if (iptuninfo[IFLA_IPTUN_REMOTE])
				memcpy(&params->remote,
				       nla_data(iptuninfo[IFLA_IPTUN_REMOTE]),
				       sizeof(params->remote));
			else
				syslog(LOG_ERR, "%s: %s no remote address in netlink msg\n",
				       __FUNCTION__, ifp->ifname);

			if (iptuninfo[IFLA_IPTUN_TTL])
				params->ttl = *(u_int8_t*)nla_data(iptuninfo[IFLA_IPTUN_TTL]);
			else
				syslog(LOG_ERR, "%s: %s no TTL in netlink msg\n",
				       __FUNCTION__, ifp->ifname);

			if (iptuninfo[IFLA_IPTUN_TOS]) {
				params->tos = *(u_int8_t*)nla_data(iptuninfo[IFLA_IPTUN_TOS]);
				params->inh_tos = params->tos & 1;
				if (params->inh_tos)
					params->tos = 0;
			} else
				syslog(LOG_ERR, "%s: %s no TOS in netlink msg\n",
				       __FUNCTION__, ifp->ifname);
		}
	} else
#endif /*IFLA_IPTUN_MAX*/
	{
		if (tb[IFLA_ADDRESS]) {
			memcpy(&params->local,
			       nla_data(tb[IFLA_ADDRESS]),
			       nla_len(tb[IFLA_ADDRESS]));
		} else
			syslog(LOG_ERR, "%s: %s no local address in netlink msg\n",
			       __FUNCTION__, ifp->ifname);

		if (tb[IFLA_BROADCAST]) {
			memcpy(&params->remote,
			       nla_data(tb[IFLA_BROADCAST]),
			       nla_len(tb[IFLA_BROADCAST]));
		} else
			syslog(LOG_ERR, "%s: %s no remote address in netlink msg\n",
			       __FUNCTION__, ifp->ifname);

#ifdef IFLA_TTL
		if (tb[IFLA_TTL]) {
			params->ttl = *(u_int8_t*)nla_data(tb[IFLA_TTL]);
		} else
			syslog(LOG_ERR, "%s: %s no TTL in netlink msg\n",
			       __FUNCTION__, ifp->ifname);

		if (tb[IFLA_TOS]) {
			params->tos = *(u_int8_t*)nla_data(tb[IFLA_TOS]);
			params->inh_tos = params->tos & 1;
			if (params->inh_tos)
				params->tos = 0;
		} else
			syslog(LOG_ERR, "%s: %s no TOS in netlink msg\n",
			       __FUNCTION__, ifp->ifname);
#endif /*IFLA_TTL*/
	}

#if 0
	/* ttl, tos and encapsulation address are retrieved via ioctl */
	memcpy(ifr.ifr_name, ifp->ifname, CM_IFNAMSIZE);
	ifr.ifr_ifru.ifru_data = (void*)&p;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	err = ioctl(fd, SIOCGETTUNNEL, &ifr);
	if (err)
		perror("ioctl");
	close(fd);

	memcpy(&params->local, &p.iph.saddr, sizeof(struct in_addr));
	memcpy(&params->remote, &p.iph.daddr, sizeof(struct in_addr));

	params->ttl = p.iph.ttl;
	params->tos = p.iph.tos;
	params->inh_tos = (p.iph.tos & 1);
	if (params->inh_tos)
		params->tos = 0;
#endif

	/* notify cpdp server */
	cm2cp_6in4_create (h->nlmsg_seq, cmd, ifp);
}

static void
cm_6in4_create(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	cm_6in4_common (ifp, h, tb, RTM_NEWLINK);
}

static void
cm_svti_create(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	/* notify cpdp server */
	cm2cp_svti_create (h->nlmsg_seq, RTM_NEWLINK, ifp);
}

static void
cm_vti_create(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	struct cm_vti_params *params;

	params = (struct cm_vti_params *)(ifp + 1);

#ifdef IFLA_VTI_MAX
	if (tb[IFLA_LINKINFO]) {
		struct nlattr *linkinfo[IFLA_INFO_MAX + 1];
		uint32_t ikey = 0;
		uint32_t okey = 0;

		memset(linkinfo, 0, sizeof(linkinfo));
		cm_nl_parse_nlattr(linkinfo, IFLA_INFO_MAX,
				   nla_data(tb[IFLA_LINKINFO]),
				   nla_len(tb[IFLA_LINKINFO]),
				   MSG_FAMILY_IFACE);

		if (linkinfo[IFLA_INFO_DATA]) {
			struct nlattr *vtiinfo[IFLA_VTI_MAX + 1];

			memset(vtiinfo, 0, sizeof(vtiinfo));
			cm_nl_parse_nlattr(vtiinfo, IFLA_VTI_MAX,
					   nla_data(linkinfo[IFLA_INFO_DATA]),
					   nla_len(linkinfo[IFLA_INFO_DATA]),
					   MSG_FAMILY_IFACE);

			if (vtiinfo[IFLA_VTI_OKEY]) {
				memcpy(&okey,
						nla_data(vtiinfo[IFLA_VTI_OKEY]),
						sizeof(okey));
				/* sanity check */
				if (okey != ifp->ifuid) {
					syslog(LOG_WARNING, "%s: interface %s okey (%08x) does not match its ifuid (%08x)\n",
							__FUNCTION__, ifp->ifname, ntohl(okey), ntohl(ifp->ifuid));
				}
			}
			else
				syslog(LOG_WARNING, "%s: %s no okey in netlink msg\n",
						__FUNCTION__, ifp->ifname);

			if (vtiinfo[IFLA_VTI_IKEY]) {
				memcpy(&ikey,
						nla_data(vtiinfo[IFLA_VTI_IKEY]),
						sizeof(ikey));
				if (ikey) {
					/* sanity check */
					if (ikey != ifp->ifuid) {
						syslog(LOG_WARNING, "%s: interface %s ikey (%08x) does not match its ifuid (%08x)\n",
								__FUNCTION__, ifp->ifname, ntohl(ikey), ntohl(ifp->ifuid));
					}
					/* IPVTI implementation */
					ifp->type = CM_IFTYPE_SVTI;
					cm2cp_svti_create (h->nlmsg_seq, RTM_NEWLINK, ifp);
					return;
				}
			}

			if (vtiinfo[IFLA_VTI_LOCAL])
				memcpy(&params->local,
				       nla_data(vtiinfo[IFLA_VTI_LOCAL]),
				       sizeof(params->local));
			else
				syslog(LOG_ERR, "%s: %s no local address in netlink msg\n",
					__FUNCTION__, ifp->ifname);

			if (vtiinfo[IFLA_VTI_REMOTE])
				memcpy(&params->remote,
				       nla_data(vtiinfo[IFLA_VTI_REMOTE]),
				       sizeof(params->remote));
			else
				syslog(LOG_ERR, "%s: %s no remote address in netlink msg\n",
				       __FUNCTION__, ifp->ifname);
		}
	}
#else /* IFLA_VTI_MAX */
	if (tb[IFLA_ADDRESS]) {
		memcpy(&params->local,
			nla_data(tb[IFLA_ADDRESS]),
			nla_len(tb[IFLA_ADDRESS]));
	} else
		syslog(LOG_ERR, "%s: %s no local address in netlink msg\n",
			__FUNCTION__, ifp->ifname);

	if (tb[IFLA_BROADCAST]) {
		memcpy(&params->remote,
			nla_data(tb[IFLA_BROADCAST]),
			nla_len(tb[IFLA_BROADCAST]));
	} else
		syslog(LOG_ERR, "%s: %s no remote address in netlink msg\n",
			__FUNCTION__, ifp->ifname);

#endif /* IFLA_VTI_MAX */

	/* notify cpdp server */
	cm2cp_vti_create (h->nlmsg_seq, RTM_NEWLINK, ifp);
}

static void
cm_vti_change(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
}

static void
cm_eth_mac_change(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	struct cm_eth_params *params;

	params = (struct cm_eth_params *)(ifp + 1);

	if (tb[IFLA_ADDRESS]) {
		if ( params->maclen == nla_len(tb[IFLA_ADDRESS])
		  && !memcmp(params->mac, nla_data(tb[IFLA_ADDRESS]), CM_ETHMACSIZE) ) {
			/* no change */
			return;
		}

		params->maclen = nla_len(tb[IFLA_ADDRESS]);
		memcpy(params->mac, nla_data(tb[IFLA_ADDRESS]), params->maclen);
		cm2cp_iface_mac (h->nlmsg_seq, ifp->ifuid, params->mac, params->maclen);
	}
}

static void
cm_eth_change(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	/* MAC address update is generic */
	cm_eth_mac_change(ifp, h, tb);

	switch (ifp->subtype) {
#ifdef CONFIG_CACHEMGR_BONDING
	case CM_IFSUBTYPE_BONDING:
		return cm_bonding_change(ifp, h, tb);
#endif
#ifdef CONFIG_CACHEMGR_MACVLAN
	case CM_IFSUBTYPE_MACVLAN:
		return cm_macvlan_change(ifp, h, tb);
#endif
#ifdef CONFIG_CACHEMGR_GRE
	case CM_IFSUBTYPE_GRETAP:
		return cm_gretap_change(ifp, h, tb);
#endif
	}
}

static void
cm_Xin6_change(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	struct cm_Xin6_params *params;
	params = (struct cm_Xin6_params *)(ifp + 1);
	int change = 0;

#ifdef IFLA_IPTUN_MAX
	if (tb[IFLA_LINKINFO]) {
		struct nlattr *linkinfo[IFLA_INFO_MAX + 1];

		cm_nl_parse_nlattr(linkinfo, IFLA_INFO_MAX,
				   nla_data(tb[IFLA_LINKINFO]),
				   nla_len(tb[IFLA_LINKINFO]),
				   MSG_FAMILY_IFACE);

		if (linkinfo[IFLA_INFO_DATA]) {
			struct nlattr *iptuninfo[IFLA_IPTUN_MAX + 1];

			cm_nl_parse_nlattr(iptuninfo, IFLA_IPTUN_MAX,
					   nla_data(linkinfo[IFLA_INFO_DATA]),
					   nla_len(linkinfo[IFLA_INFO_DATA]),
					   MSG_FAMILY_IFACE);

			if (iptuninfo[IFLA_IPTUN_LOCAL]) {
				struct in6_addr *local;
				local = (struct in6_addr *)nla_data(iptuninfo[IFLA_IPTUN_LOCAL]);
				if (!IN6_ARE_ADDR_EQUAL(&params->local, local)) {
					change = 1;
					memcpy(&params->local,
					       nla_data(iptuninfo[IFLA_IPTUN_LOCAL]),
					       nla_len(iptuninfo[IFLA_IPTUN_LOCAL]));
				}
			}

			if (iptuninfo[IFLA_IPTUN_REMOTE]) {
				struct in6_addr *remote;
				remote = (struct in6_addr *)nla_data(tb[IFLA_BROADCAST]);
				if (!IN6_ARE_ADDR_EQUAL(&params->remote, remote)) {
					change = 1;
					memcpy(&params->remote,
					       nla_data(iptuninfo[IFLA_IPTUN_REMOTE]),
					       nla_len(iptuninfo[IFLA_IPTUN_REMOTE]));
				}
			}

			if (iptuninfo[IFLA_IPTUN_TTL]) {
				u_int8_t hoplim;
				hoplim = *(u_int8_t *)nla_data(iptuninfo[IFLA_IPTUN_TTL]);
				if (params->hoplim != hoplim) {
					change = 1;
					params->hoplim = hoplim;
				}
			}

			if (iptuninfo[IFLA_IPTUN_TOS]) {
				u_int8_t tos, inh_tos;
				tos = *(u_int8_t *)nla_data(iptuninfo[IFLA_IPTUN_TOS]);
				inh_tos = tos & 1;
				if (inh_tos)
					tos = 0;

				if ((params->tos != tos) || (params->inh_tos != inh_tos)) {
					change = 1;
					params->tos = tos;
					params->inh_tos = inh_tos;
				}
			}
		}
	} else
#endif /*IFLA_IPTUN_MAX*/
	{
		/* Tunnel local address */
		if (tb[IFLA_ADDRESS]) {
			struct in6_addr *local;
			local = (struct in6_addr *)nla_data(tb[IFLA_ADDRESS]);
			if (!IN6_ARE_ADDR_EQUAL(&params->local, local)) {
				change = 1;
				memcpy(&params->local,
				       nla_data(tb[IFLA_ADDRESS]),
				       nla_len(tb[IFLA_ADDRESS]));
			}
		}

		/* Tunnel remote address */
		if (tb[IFLA_BROADCAST]) {
			struct in6_addr *remote;
			remote = (struct in6_addr *)nla_data(tb[IFLA_BROADCAST]);
			if (!IN6_ARE_ADDR_EQUAL(&params->remote, remote)) {
				change = 1;
				memcpy(&params->remote,
				       nla_data(tb[IFLA_BROADCAST]),
				       nla_len(tb[IFLA_BROADCAST]));
			}
		}

#ifdef IFLA_TTL
		if (tb[IFLA_TTL]) {
			int hoplim;
			hoplim = *(u_int8_t *)nla_data(tb[IFLA_TTL]);
			if (params->hoplim != hoplim) {
				change = 1;
				params->hoplim = hoplim;
			}
		}
#endif /*IFLA_TTL*/

#ifdef IFLA_TOS
		if (tb[IFLA_TOS]) {
			int tos, inh_tos;
			tos = *(u_int8_t *)nla_data(tb[IFLA_TOS]);
			inh_tos = tos & 1;
			if (inh_tos)
				tos = 0;

			if ((params->tos != tos) || (params->inh_tos != inh_tos)) {
				change = 1;
				params->tos = tos;
				params->inh_tos = inh_tos;
			}
		}
#endif /*IFLA_TOS*/
	}

	if (change)
		cm2cp_Xin6_create (h->nlmsg_seq, RTM_SETLINK, ifp);
}

static void
cm_6in4_change(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	struct cm_6in4_params *params;
	params = (struct cm_6in4_params *)(ifp + 1);
	int change = 0;

#ifdef IFLA_IPTUN_MAX
	if (tb[IFLA_LINKINFO]) {
		struct nlattr *linkinfo[IFLA_INFO_MAX + 1];

		cm_nl_parse_nlattr(linkinfo, IFLA_INFO_MAX,
				   nla_data(tb[IFLA_LINKINFO]),
				   nla_len(tb[IFLA_LINKINFO]),
				   MSG_FAMILY_IFACE);

		if (linkinfo[IFLA_INFO_DATA]) {
			struct nlattr *iptuninfo[IFLA_IPTUN_MAX + 1];

			cm_nl_parse_nlattr(iptuninfo, IFLA_IPTUN_MAX,
					   nla_data(linkinfo[IFLA_INFO_DATA]),
					   nla_len(linkinfo[IFLA_INFO_DATA]),
					   MSG_FAMILY_IFACE);

			if (iptuninfo[IFLA_IPTUN_LOCAL]) {
				struct in_addr *local;
				local = (struct in_addr *)nla_data(iptuninfo[IFLA_IPTUN_LOCAL]);
				if (params->local.s_addr != local->s_addr) {
					change = 1;
					memcpy(&params->local,
					       nla_data(iptuninfo[IFLA_IPTUN_LOCAL]),
					       nla_len(iptuninfo[IFLA_IPTUN_LOCAL]));
				}
			}

			if (iptuninfo[IFLA_IPTUN_REMOTE]) {
				struct in_addr *remote;
				remote = (struct in_addr *)nla_data(iptuninfo[IFLA_IPTUN_REMOTE]);
				if (params->remote.s_addr != remote->s_addr) {
					change = 1;
					memcpy(&params->remote,
					       nla_data(iptuninfo[IFLA_IPTUN_REMOTE]),
					       nla_len(iptuninfo[IFLA_IPTUN_REMOTE]));
				}
			}

			if (iptuninfo[IFLA_IPTUN_TTL]) {
				u_int8_t ttl;
				ttl = *(u_int8_t*)nla_data(iptuninfo[IFLA_IPTUN_TTL]);
				if (params->ttl != ttl) {
					change = 1;
					params->ttl = ttl;
				}
			}

			if (iptuninfo[IFLA_IPTUN_TOS]) {
				int tos, inh_tos;
				tos = *(u_int8_t *)nla_data(iptuninfo[IFLA_IPTUN_TOS]);
				inh_tos = tos & 1;
				if (inh_tos)
					tos = 0;

				if ((params->tos != tos) || (params->inh_tos != inh_tos)) {
					change = 1;
					params->tos = tos;
					params->inh_tos = inh_tos;
				}
			}
		}
	} else
#endif /*IFLA_IPTUN_MAX*/
	{
		/* Tunnel local address */
		if (tb[IFLA_ADDRESS]) {
			struct in_addr *local;
			local = (struct in_addr *)nla_data(tb[IFLA_ADDRESS]);
			if (params->local.s_addr != local->s_addr) {
				change = 1;
				memcpy(&params->local,
				       nla_data(tb[IFLA_ADDRESS]),
				       nla_len(tb[IFLA_ADDRESS]));
			}
		}

		/* Tunnel remote address */
		if (tb[IFLA_BROADCAST]) {
			struct in_addr *remote;
			remote = (struct in_addr *)nla_data(tb[IFLA_BROADCAST]);
			if (params->remote.s_addr != remote->s_addr) {
				change = 1;
				memcpy(&params->remote,
				       nla_data(tb[IFLA_BROADCAST]),
				       nla_len(tb[IFLA_BROADCAST]));
			}
		}

#ifdef IFLA_TTL
		if (tb[IFLA_TTL]) {
			int ttl;
			ttl = *(u_int8_t *)nla_data(tb[IFLA_TTL]);
			if (params->ttl != ttl) {
				change = 1;
				params->ttl = ttl;
			}
		}
#endif /*IFLA_TTL*/

#ifdef IFLA_TOS
		if (tb[IFLA_TOS]) {
			int tos, inh_tos;
			tos = *(u_int8_t *)nla_data(tb[IFLA_TOS]);
			inh_tos = tos & 1;
			if (inh_tos)
				tos = 0;

			if ((params->tos != tos) || (params->inh_tos != inh_tos)) {
				change = 1;
				params->tos = tos;
				params->inh_tos = inh_tos;
			}
		}
#endif /*IFLA_TOS*/
	}

	if (change)
		cm2cp_6in4_create (h->nlmsg_seq, RTM_SETLINK, ifp);

}

static void
cm_svti_change(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
}


static void
cm_eth_delete(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	switch (ifp->subtype) {
#ifdef CONFIG_CACHEMGR_VXLAN
	case CM_IFSUBTYPE_VXLAN:
		cm2cp_vxlan_create (h->nlmsg_seq, RTM_DELLINK, ifp);
		break;
#endif
#ifdef CONFIG_CACHEMGR_VLAN
        case CM_IFSUBTYPE_VLAN:
                cm2cp_vlan_create (h->nlmsg_seq, RTM_DELLINK, ifp);
                break;
#endif
#ifdef CONFIG_CACHEMGR_MACVLAN
        case CM_IFSUBTYPE_MACVLAN:
                cm2cp_macvlan_create (h->nlmsg_seq, CMD_MACVLAN_DELETE, ifp);
                break;
#endif
#ifdef CONFIG_CACHEMGR_BONDING
	case CM_IFSUBTYPE_BONDING:
		cm2cp_bonding_create(h->nlmsg_seq, CMD_BONDING_DELETE, ifp);
		break;
#endif
#ifdef CONFIG_CACHEMGR_GRE
	case CM_IFSUBTYPE_GRETAP:
		cm_gretap_delete(ifp, h, tb);
		break;
#endif
	default:
		cm2cp_iface_create (h->nlmsg_seq, RTM_DELLINK, ifp);
		break;
	}
}

static void
cm_Xin6_delete(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	cm_Xin6_common (ifp, h, tb, RTM_DELLINK);
}

static void
cm_6in4_delete(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	cm_6in4_common (ifp, h, tb, RTM_DELLINK);
}

static void
cm_svti_delete(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	cm2cp_svti_create (h->nlmsg_seq, RTM_DELLINK, ifp);
}

static void
cm_vti_delete(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	/* VTI implementation */
	if (ifp->type == CM_IFTYPE_VTI)
		cm2cp_vti_create (h->nlmsg_seq, RTM_DELLINK, ifp);
	/* IPVTI implementation */
	else
		cm2cp_svti_create (h->nlmsg_seq, RTM_DELLINK, ifp);
}

#ifdef CONFIG_CACHEMGR_VXLAN
static void
cm_vxlan_create(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	struct cm_eth_params *eth_params;
	struct cm_vxlan_params *params;

	eth_params = (struct cm_eth_params *)(ifp + 1);
	params = (struct cm_vxlan_params *)(eth_params + 1);

	if (tb[IFLA_LINKINFO]) {
		struct nlattr *linkinfo[IFLA_INFO_MAX + 1];
		struct nlattr *infodata[IFLA_VXLAN_MAX + 1];
		struct ifla_vxlan_port_range *ports;

		cm_nl_parse_nlattr(linkinfo, IFLA_INFO_MAX,
				   nla_data(tb[IFLA_LINKINFO]),
				   nla_len(tb[IFLA_LINKINFO]),
				   MSG_FAMILY_IFACE);

		if (!linkinfo[IFLA_INFO_DATA])
			return;

		cm_nl_parse_nlattr(infodata, IFLA_VXLAN_MAX,
				   nla_data(linkinfo[IFLA_INFO_DATA]),
				   nla_len(linkinfo[IFLA_INFO_DATA]),
				   MSG_FAMILY_IFACE);

		params->vni = nla_get_u32(infodata[IFLA_VXLAN_ID]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		params->dst_port = nla_get_u16(infodata[IFLA_VXLAN_PORT]);
#else
		/* It's a parameter of the vxlan module (udp_port). Default
		 * value is 8472, but IANA assigned port is 4789 :/
		 */
		params->dst_port = htons(8472);
#endif
		params->ttl = nla_get_u8(infodata[IFLA_VXLAN_TTL]);
		params->tos = nla_get_u8(infodata[IFLA_VXLAN_TOS]);
		ports = (struct ifla_vxlan_port_range *)nla_data(infodata[IFLA_VXLAN_PORT_RANGE]);
		params->src_minport = ports->low;
		params->src_maxport = ports->high;
		if (infodata[IFLA_VXLAN_LINK]) {
			uint32_t ifindex = nla_get_u32(infodata[IFLA_VXLAN_LINK]);

			params->link_ifuid = cm_ifindex2ifuid(ifindex, ifp->vrfid, 1);
		}

		if (infodata[IFLA_VXLAN_GROUP])
			params->gw4 = (struct in_addr *)nla_data(infodata[IFLA_VXLAN_GROUP]);
		if (infodata[IFLA_VXLAN_LOCAL])
			params->saddr4 = (struct in_addr *)nla_data(infodata[IFLA_VXLAN_LOCAL]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0)
		if (infodata[IFLA_VXLAN_GROUP6])
			params->gw6 = (struct in6_addr *)nla_data(infodata[IFLA_VXLAN_GROUP6]);
		if (infodata[IFLA_VXLAN_LOCAL6])
			params->saddr6 = (struct in6_addr *)nla_data(infodata[IFLA_VXLAN_LOCAL6]);
#endif

		if (infodata[IFLA_VXLAN_LEARNING] &&
		    nla_get_u8(infodata[IFLA_VXLAN_LEARNING]))
			params->flags |= CP_VXLAN_IFACE_F_LEARN;
	}

	if (tb[IFLA_ADDRESS]) {
		eth_params->maclen = nla_len(tb[IFLA_ADDRESS]);
		memcpy(eth_params->mac, nla_data(tb[IFLA_ADDRESS]),
		       eth_params->maclen);
	} else if (cm_debug_level & CM_DUMP_DBG_NL_RECV)
		syslog(LOG_DEBUG, "%s: %s has no mac address\n", __FUNCTION__, ifp->ifname);

	cm2cp_vxlan_create(h->nlmsg_seq, RTM_NEWLINK, ifp);
}
#endif /* CONFIG_CACHEMGR_VXLAN */
#ifdef CONFIG_CACHEMGR_VLAN
static void
cm_vlan_create(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	struct cm_eth_params *eth_params;
	struct cm_vlan_params *params;
	struct ifla_vlan_flags *flags;

	eth_params = (struct cm_eth_params *)(ifp + 1);
	params = (struct cm_vlan_params *)(eth_params + 1);
	memset(params, 0, sizeof(struct cm_vlan_params));

	if (tb[IFLA_LINKINFO]) {
		struct nlattr *linkinfo[IFLA_INFO_MAX + 1];
		struct nlattr *infodata[IFLA_VLAN_MAX + 1];

		cm_nl_parse_nlattr(linkinfo, IFLA_INFO_MAX,
				   nla_data(tb[IFLA_LINKINFO]),
				   nla_len(tb[IFLA_LINKINFO]),
				   MSG_FAMILY_IFACE);

		if (!linkinfo[IFLA_INFO_DATA])
			return;

		cm_nl_parse_nlattr(infodata, IFLA_VLAN_MAX,
				   nla_data(linkinfo[IFLA_INFO_DATA]),
				   nla_len(linkinfo[IFLA_INFO_DATA]),
				   MSG_FAMILY_IFACE);

		params->vlan_id = nla_get_u16(infodata[IFLA_VLAN_ID]);
		if (nla_get_u32(tb[IFLA_LINK]))
			params->lower_ifuid = cm_ifindex2ifuid(nla_get_u32(tb[IFLA_LINK]), ifp->linkvrfid, 0);
		if (infodata[IFLA_VLAN_FLAGS]) {
			flags = nla_data(infodata[IFLA_VLAN_FLAGS]);
			params->flags = flags->flags;
		}
	}
	if (tb[IFLA_ADDRESS]) {
                eth_params->maclen = nla_len(tb[IFLA_ADDRESS]);
                memcpy(eth_params->mac, nla_data(tb[IFLA_ADDRESS]),
                       eth_params->maclen);
        } else if (cm_debug_level & CM_DUMP_DBG_NL_RECV)
                syslog(LOG_DEBUG, "%s: %s has no mac address\n", __FUNCTION__, ifp->ifname);

	cm2cp_vlan_create(h->nlmsg_seq, RTM_NEWLINK, ifp);
}
#endif /* CONFIG_CACHEMGR_VLAN */

#ifdef CONFIG_CACHEMGR_MACVLAN

#ifdef IFLA_MACVLAN_MAX
static u_int32_t cm_macvlan_parse_mode(const u_int32_t mode)
{
	u_int32_t cm_mode = CP_MACVLAN_MODE_UNKNOWN;

	if (mode == MACVLAN_MODE_VEPA) 
		cm_mode = CP_MACVLAN_MODE_VEPA;
	else if (mode == MACVLAN_MODE_PRIVATE) 
		cm_mode = CP_MACVLAN_MODE_PRIVATE;
	else if (mode == MACVLAN_MODE_BRIDGE) 
		cm_mode = CP_MACVLAN_MODE_BRIDGE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
	else if (mode == MACVLAN_MODE_PASSTHRU)  
		cm_mode = CP_MACVLAN_MODE_PASSTHRU;
#endif

	return cm_mode;
}
#endif

static void
cm_macvlan_parse(struct cm_iface *ifp, struct nlattr **tb)
{
	struct cm_eth_params *eth_params;
	struct cm_macvlan_params *params;

	eth_params = (struct cm_eth_params *)(ifp + 1);
	params = (struct cm_macvlan_params *)(eth_params + 1);
#ifdef IFLA_MACVLAN_MAX
	if (tb[IFLA_LINKINFO]) {
		struct nlattr *linkinfo[IFLA_INFO_MAX + 1];
		struct nlattr *infodata[IFLA_MACVLAN_MAX + 1];

		cm_nl_parse_nlattr(linkinfo, IFLA_INFO_MAX,
				   nla_data(tb[IFLA_LINKINFO]),
				   nla_len(tb[IFLA_LINKINFO]),
				   MSG_FAMILY_IFACE);

		if (!linkinfo[IFLA_INFO_DATA])
			return;

		cm_nl_parse_nlattr(infodata, IFLA_MACVLAN_MAX,
				   nla_data(linkinfo[IFLA_INFO_DATA]),
				   nla_len(linkinfo[IFLA_INFO_DATA]),
				   MSG_FAMILY_IFACE);

		params->mode = cm_macvlan_parse_mode(nla_get_u32(infodata[IFLA_MACVLAN_MODE]));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
		if (nla_get_u16(infodata[IFLA_MACVLAN_FLAGS]) & MACVLAN_FLAG_NOPROMISC)
			params->flags = CP_MACVLAN_FLAGS_NOPROMISC;
#endif
	}
	else
#endif
		params->mode = CP_MACVLAN_MODE_UNKNOWN;

	if (tb[IFLA_LINK]) 
		params->link_ifuid = cm_ifindex2ifuid(nla_get_u32(tb[IFLA_LINK]), ifp->linkvrfid, 0);
	if (tb[IFLA_ADDRESS]) {
		eth_params->maclen = nla_len(tb[IFLA_ADDRESS]);
		memcpy(eth_params->mac, nla_data(tb[IFLA_ADDRESS]),
		       eth_params->maclen);
	} else if (cm_debug_level & CM_DUMP_DBG_NL_RECV)
		syslog(LOG_DEBUG, "%s: %s has no mac address\n", __FUNCTION__, ifp->ifname);
}

static void
cm_macvlan_create(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	cm_macvlan_parse(ifp, tb);

	cm2cp_macvlan_create(h->nlmsg_seq, CMD_MACVLAN_CREATE, ifp);
}

static void
cm_macvlan_change(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	cm_macvlan_parse(ifp, tb);
	cm2cp_macvlan_create(h->nlmsg_seq, CMD_MACVLAN_UPDATE, ifp);
}
#endif /* CONFIG_CACHEMGR_MACVLAN */

#ifdef CONFIG_CACHEMGR_BRIDGE
static struct cm_iface *
cm_brport_alloc(u_int32_t cm_subtype)
{
	return (struct cm_iface *)calloc(1, sizeof(struct cm_iface) + sizeof(struct cm_brport_params));
}

static u_int8_t cm_brport_state(u_int8_t nlstate)
{
	switch (nlstate) {
	case BR_STATE_DISABLED:
		return CP_BRPORT_S_DISABLED;
	case BR_STATE_LISTENING:
		return CP_BRPORT_S_LISTENING;
	case BR_STATE_LEARNING:
		return CP_BRPORT_S_LEARNING;
	case BR_STATE_FORWARDING:
		return CP_BRPORT_S_FORWARDING;
	case BR_STATE_BLOCKING:
		return CP_BRPORT_S_BLOCKING;
	default:
		return CP_BRPORT_S_DISABLED;
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
/* Used by cm_brport_update(), same as nla_is_nested() but it avoids
 * the requirement libnl >= 3.2.22 (RH7) */
static int cm_nla_is_nested(struct nlattr *attr)
{
	return !!(attr->nla_type & NLA_F_NESTED);
}
#endif

static void
cm_brport_update(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb,
		 int update)
{
	struct cm_brport_params *params;

	params = (struct cm_brport_params *)(ifp + 1);
	memset(params, 0, sizeof(struct cm_brport_params));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
	if (cm_nla_is_nested(tb[IFLA_PROTINFO])) {
		struct nlattr *infodata[IFLA_BRPORT_MAX + 1];

		cm_nl_parse_nlattr(infodata, IFLA_BRPORT_MAX,
				   nla_data(tb[IFLA_PROTINFO]),
				   nla_len(tb[IFLA_PROTINFO]),
				   MSG_FAMILY_IFACE);

		params->state = cm_brport_state(nla_get_u8(infodata[IFLA_BRPORT_STATE]));

		if (nla_get_u8(infodata[IFLA_BRPORT_MODE]))
		    params->flags |= CP_BRPORT_F_HAIRPIN_MODE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
		if (nla_get_u8(infodata[IFLA_BRPORT_LEARNING]))
		    params->flags |= CP_BRPORT_F_LEARNING;
		if (nla_get_u8(infodata[IFLA_BRPORT_UNICAST_FLOOD]))
		    params->flags |= CP_BRPORT_F_UNICASTFLOOD;
#endif
	} else
#endif
		params->state = cm_brport_state(nla_get_u8(tb[IFLA_PROTINFO]));

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
	/* These options are enabled by default, hence we set them if we cannot
	 * synchronize them.
	 */
	params->flags |= CP_BRPORT_F_LEARNING;
	params->flags |= CP_BRPORT_F_UNICASTFLOOD;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
	/* Should start a dump with IFLA_EXT_MASK set to RTEXT_FILTER_BRVLAN to
	 * get IFLA_AF_SPEC/IFLA_BRIDGE_VLAN_INFO?
	 */
#endif

	cm2cp_brport_update(h->nlmsg_seq, RTM_NEWLINK, ifp);
}

static void
cm_brport_create(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	return cm_brport_update(ifp, h, tb, 0);
}

static void
cm_brport_change(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	return cm_brport_update(ifp, h, tb, 1);
}

static void
cm_brport_delete(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	struct cm_brport_params *params;

	params = (struct cm_brport_params *)(ifp + 1);
	memset(params, 0, sizeof(struct cm_brport_params));
	cm2cp_brport_update(h->nlmsg_seq, RTM_DELLINK, ifp);
}

static void
cm_brport_rename(u_int32_t cookie, int ifindex, char *name, u_int32_t vrfid,
		 u_int32_t ifuid)
{
	struct cm_iface *ifp;

	ifp = bridge_iflookup(ifindex, vrfid);
	if (ifp == NULL || ifp->type != CM_IFTYPE_BRPORT)
		return;

	/* Ask the fpm to delete this brport. */
	cm_unlink_bridge(ifp);
	cm2cp_brport_update(cookie, RTM_DELLINK, ifp);

	/* Update ifp and ask the fpm to create this new brport. */
	ifp->ifuid = ifuid;
	strncpy(ifp->ifname, name, CM_IFNAMSIZE);
	cm2cp_brport_update(cookie, RTM_NEWLINK, ifp);
	cm_link_bridge(ifp);
}
#endif /* CONFIG_CACHEMGR_BRIDGE */

#ifdef CONFIG_CACHEMGR_BONDING
#ifdef HAVE_IFLA_BOND
struct cmn_netcmd_priv {
	struct event *event;
};
#define cmn_netcmd_priv(c) ((struct cmn_netcmd_priv *)((c)->priv))

static void cm_nl_bonding_link(struct cm_iface *ifp)
{
	if (!ifp->in_l_bond) {
		LIST_INSERT_HEAD(&ifbond_list, ifp, l_bond);
		ifp->in_l_bond = 1;
	}
}

static void cm_nl_bonding_unlink(struct cm_iface *ifp)
{
	if (ifp->in_l_bond) {
		LIST_REMOVE(ifp, l_bond);
		ifp->in_l_bond = 0;
	}
}

static int cm_nl_bonding_dump_one(struct cm_iface *ifp, struct nlsock *cmn,
				  struct cmn_netcmd_priv *priv)
{
	struct nl_msg *msg = NULL;
	int err = 0;

	err = rtnl_link_build_get_request(ifp->ifindex, ifp->ifname, &msg);
	if (err < 0) {
		syslog(LOG_ERR, "%s: rtnl_link_build_get_request fails: %s\n",
		       __func__, nl_geterror(err));
		goto build_req_error;
	}

	err = nl_send_auto(cmn->sk, msg);
	if (err < 0) {
		syslog(LOG_ERR, "%s: nl_send_auto fails: %s\n", __func__,
		       nl_geterror(err));
		goto send_error;
	}

	err = nl_recvmsgs_default(cmn->sk);
	if (err < 0)
		syslog(LOG_ERR, "%s: nl_recvmsgs_default fails: %s\n", __func__,
		       nl_geterror(err));

send_error:
	nlmsg_free(msg);

build_req_error:
	return err;
}

/* We need to add timer to force dump bonding params */
void cm_nl_bonding_dump(__attribute__((unused)) int sock,
			__attribute__((unused)) short evtype,
			void *data)
{
	struct nlsock *cmn = (struct nlsock *)data;
	struct cmn_netcmd_priv *priv = cmn_netcmd_priv(cmn);
	struct cm_iface *ifp;

	if (priv == NULL)
		return;

	LIST_FOREACH(ifp, &ifbond_list, l_bond)
		cm_nl_bonding_dump_one(ifp, cmn, priv);
}

static void cm_nl_bonding_start_timer(u_int32_t vrfid)
{
	struct nlsock *cmn = vrf_get_nlsock(vrfid, CM_NETCMD);
	struct cmn_netcmd_priv *priv = cmn_netcmd_priv(cmn);
	struct timeval tv;

	if (priv == NULL)
		return;

	/* Check if timer is already set. */
	if (evtimer_initialized(priv->event) &&
	    evtimer_pending(priv->event, NULL))
		return;

	/* The timer is start every second. Data that we have to synchronize
	 * don't change often.
	 */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	evtimer_add(priv->event, &tv);
}

void cm_nl_bonding_init(struct nlsock *cmn)
{
	struct cmn_netcmd_priv *priv;

	cmn->priv = malloc(sizeof(struct cmn_netcmd_priv));
	if (cmn->priv == NULL) {
		syslog(LOG_ERR, "%s: malloc() fails\n", __func__);
		return;
	}

	priv = cmn_netcmd_priv(cmn);
	memset(priv, 0, sizeof(struct cmn_netcmd_priv));

	priv->event = evtimer_new(cm_event_base, cm_nl_bonding_dump, cmn);
	if (priv->event == NULL) {
		syslog(LOG_ERR, "%s: evtimer_new() fails\n", __func__);
		free(priv);
		cmn->priv = NULL;
	}
}

void cm_nl_bonding_destroy(struct nlsock *cmn)
{
	struct cmn_netcmd_priv *priv = cmn_netcmd_priv(cmn);

	if (priv == NULL)
		return;

	if (priv->event) {
		event_free(priv->event);
		priv->event = NULL;
	}
	free(priv);
	cmn->priv = NULL;
}
#endif /* HAVE_IFLA_BOND */

static void
cm_bonding_parse(struct cm_bonding_params *params, struct cm_iface *ifp,
		 struct nlmsghdr *h, struct nlattr **tb, int update)
{
#ifdef HAVE_IFLA_BOND
	struct nlattr *linkinfo[IFLA_INFO_MAX + 1];
	struct nlattr *bondinfo[IFLA_BOND_MAX + 1];

	if (!tb[IFLA_LINKINFO])
		return;

	cm_nl_parse_nlattr(linkinfo, IFLA_INFO_MAX, nla_data(tb[IFLA_LINKINFO]),
			   nla_len(tb[IFLA_LINKINFO]), MSG_FAMILY_IFACE);

	if (!linkinfo[IFLA_INFO_DATA])
		return;

	cm_nl_parse_nlattr(bondinfo, IFLA_BOND_MAX,
			   nla_data(linkinfo[IFLA_INFO_DATA]),
			   nla_len(linkinfo[IFLA_INFO_DATA]), MSG_FAMILY_IFACE);

	switch (nla_get_u8(bondinfo[IFLA_BOND_MODE])) {
	case BOND_MODE_ROUNDROBIN:
	default:
		params->mode = CP_BOND_MODE_ROUNDROBIN;
		break;
	case BOND_MODE_ACTIVEBACKUP:
		params->mode = CP_BOND_MODE_ACTIVEBACKUP;
		break;
	case BOND_MODE_XOR:
		params->mode = CP_BOND_MODE_XOR;
		break;
	case BOND_MODE_BROADCAST:
		params->mode = CP_BOND_MODE_BROADCAST;
		break;
	case BOND_MODE_8023AD:
		params->mode = CP_BOND_MODE_8023AD;
		break;
	case BOND_MODE_TLB:
		params->mode = CP_BOND_MODE_TLB;
		break;
	case BOND_MODE_ALB:
		params->mode = CP_BOND_MODE_ALB;
		break;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	if (bondinfo[IFLA_BOND_ACTIVE_SLAVE])
		params->active_slave_ifuid =
			cm_ifindex2ifuid(nla_get_u32(bondinfo[IFLA_BOND_ACTIVE_SLAVE]),
					 ifp->vrfid, update);

	if (bondinfo[IFLA_BOND_AD_INFO]) {
		struct nlattr *adinfo[IFLA_BOND_AD_INFO_MAX + 1];

		cm_nl_parse_nlattr(adinfo, IFLA_BOND_AD_INFO_MAX,
				   nla_data(bondinfo[IFLA_BOND_AD_INFO]),
				   nla_len(bondinfo[IFLA_BOND_AD_INFO]),
				   MSG_FAMILY_IFACE);

		params->ad_info_aggregator =
			nla_get_u16(adinfo[IFLA_BOND_AD_INFO_AGGREGATOR]);
		params->ad_info_num_ports =
			nla_get_u16(adinfo[IFLA_BOND_AD_INFO_NUM_PORTS]);
	}
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0) */

	cm_nl_bonding_start_timer(ifp->vrfid);
#endif /* HAVE_IFLA_BOND */
}

static void
cm_bonding_create(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	struct cm_bonding_params *params;
	struct cm_eth_params *eth_params;

	eth_params = (struct cm_eth_params *)(ifp + 1);
	params = (struct cm_bonding_params *)(eth_params + 1);

	if (tb[IFLA_ADDRESS]) {
		eth_params->maclen = nla_len(tb[IFLA_ADDRESS]);
		memcpy(eth_params->mac, nla_data(tb[IFLA_ADDRESS]),
		       eth_params->maclen);
	}

	cm_bonding_parse(params, ifp, h, tb, 0);
	cm2cp_bonding_create(h->nlmsg_seq, CMD_BONDING_CREATE, ifp);
}

static void
cm_bonding_change(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	struct cm_bonding_params *params;
	struct cm_eth_params *eth_params;

	eth_params = (struct cm_eth_params *)(ifp + 1);
	params = (struct cm_bonding_params *)(eth_params + 1);

	cm_bonding_parse(params, ifp, h, tb, 1);
	cm2cp_bonding_create(h->nlmsg_seq, CMD_BONDING_UPDATE, ifp);
}

#ifdef HAVE_IFLA_INFO_SLAVE
static void
cm_slave_bonding_update(struct cm_iface *ifp, struct nlmsghdr *h,
			struct nlattr **tb)
{
	struct nlattr *data[IFLA_BOND_SLAVE_MAX + 1];
	struct nlattr *linkinfo[IFLA_INFO_MAX + 1];
	struct cm_slave_bonding params;

	memset(&params, 0, sizeof(params));
	cm_nl_parse_nlattr(linkinfo, IFLA_INFO_MAX, nla_data(tb[IFLA_LINKINFO]),
			   nla_len(tb[IFLA_LINKINFO]), MSG_FAMILY_IFACE);

	if (!linkinfo[IFLA_INFO_SLAVE_DATA])
		return;

	cm_nl_parse_nlattr(data, IFLA_BOND_SLAVE_MAX,
			   nla_data(linkinfo[IFLA_INFO_SLAVE_DATA]),
			   nla_len(linkinfo[IFLA_INFO_SLAVE_DATA]),
			   MSG_FAMILY_IFACE);

	switch (nla_get_u8(data[IFLA_BOND_SLAVE_STATE])) {
	case BOND_STATE_ACTIVE:
		params.state = CP_BOND_STATE_ACTIVE;
		break;
	case BOND_STATE_BACKUP:
		params.state = CP_BOND_STATE_BACKUP;
		break;
	default:
		params.state = CP_BOND_STATE_UNKNOWN;
		break;
	}

	switch (nla_get_u8(data[IFLA_BOND_SLAVE_MII_STATUS])) {
	case BOND_LINK_UP:
		params.link = CP_BOND_LINK_UP;
		break;
	case BOND_LINK_FAIL:
		params.link = CP_BOND_LINK_FAIL;
		break;
	case BOND_LINK_DOWN:
		params.link = CP_BOND_LINK_DOWN;
		break;
	case BOND_LINK_BACK:
		params.link = CP_BOND_LINK_BACK;
		break;
	default:
		params.link = CP_BOND_LINK_UNKNOWN;
		break;
	}

	params.link_failure_count = nla_get_u32(data[IFLA_BOND_SLAVE_LINK_FAILURE_COUNT]);
	params.queue_id = nla_get_u16(data[IFLA_BOND_SLAVE_QUEUE_ID]);

	if (nla_len(data[IFLA_BOND_SLAVE_PERM_HWADDR]) == 6)
		memcpy(params.perm_hwaddr,
		       nla_data(data[IFLA_BOND_SLAVE_PERM_HWADDR]), 6);

	if (data[IFLA_BOND_SLAVE_AD_AGGREGATOR_ID])
		params.aggregator_id = nla_get_u16(data[IFLA_BOND_SLAVE_AD_AGGREGATOR_ID]);

	cm2cp_slave_bonding_update(h->nlmsg_seq, ifp->ifuid, ifp->master_ifuid,
				   &params);
}
#endif /* HAVE_IFLA_INFO_SLAVE */
#endif /* CONFIG_CACHEMGR_BONDING */

#ifdef CONFIG_CACHEMGR_GRE
static struct cm_iface *cm_gre_alloc(u_int32_t cm_subtype)
{
	return (struct cm_iface *)calloc(1, sizeof(struct cm_iface) + sizeof(struct cm_gre_params));
}

static u_int16_t cm_gre_parse_flags(const u_int16_t flags)
{
	u_int16_t cm_flags = 0;

	if (flags & GRE_CSUM)
		cm_flags |= CP_GRE_FLAG_CSUM;
	if (flags & GRE_ROUTING)
		cm_flags |= CP_GRE_FLAG_ROUTING;
	if (flags & GRE_KEY)
		cm_flags |= CP_GRE_FLAG_KEY;
	if (flags & GRE_SEQ)
		cm_flags |= CP_GRE_FLAG_SEQ;
	if (flags & GRE_STRICT)
		cm_flags |= CP_GRE_FLAG_STRICT;
	if (flags & GRE_REC)
		cm_flags |= CP_GRE_FLAG_REC;
	if (flags & GRE_FLAGS)
		cm_flags |= CP_GRE_FLAG_FLAGS;
	if (flags & GRE_VERSION)
		cm_flags |= CP_GRE_FLAG_VERSION;

	return cm_flags;
}

static void
cm_gre_update(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb,
	      uint32_t update, uint8_t mode)
{
	struct nlattr *linkinfo[IFLA_INFO_MAX + 1];
	struct nlattr *greinfo[IFLA_GRE_MAX + 1];
	struct cm_gre_params *params;
	struct cm_eth_params *eth_params;
	char *kind;

	if (!tb[IFLA_LINKINFO]) {
		syslog(LOG_ERR, "%s: %s IFLA_LINKINFO not found.\n",
		       __FUNCTION__, ifp->ifname);
		return;
	}

	if (mode == CP_GRE_MODE_ETHER) {
		eth_params = (struct cm_eth_params *)(ifp + 1);
		params = (struct cm_gre_params *)(eth_params + 1);

		if (tb[IFLA_ADDRESS]) {
			eth_params->maclen = nla_len(tb[IFLA_ADDRESS]);
			memcpy(eth_params->mac, nla_data(tb[IFLA_ADDRESS]),
			       eth_params->maclen);
		}
	} else
		params = (struct cm_gre_params *)(ifp + 1);

	cm_nl_parse_nlattr(linkinfo, IFLA_INFO_MAX,
			   nla_data(tb[IFLA_LINKINFO]),
			   nla_len(tb[IFLA_LINKINFO]),
			   MSG_FAMILY_IFACE);

	kind = (char*)nla_data(linkinfo[IFLA_INFO_KIND]);
	if (!strcmp(kind, "gre") || !strcmp(kind, "gretap"))
		params->family = AF_INET;
	else
		params->family = AF_INET6;

	params->mode = mode;

	if (!linkinfo[IFLA_INFO_DATA]) {
		syslog(LOG_ERR, "%s: %s IFLA_INFO_DATA not found.\n",
		       __FUNCTION__, ifp->ifname);
		return;
	}

	cm_nl_parse_nlattr(greinfo, IFLA_GRE_MAX,
			   nla_data(linkinfo[IFLA_INFO_DATA]),
			   nla_len(linkinfo[IFLA_INFO_DATA]),
			   MSG_FAMILY_IFACE);

	if (greinfo[IFLA_GRE_LOCAL]) {
		if (params->family == AF_INET)
			memcpy(&params->local,
			       nla_data(greinfo[IFLA_GRE_LOCAL]),
			       sizeof(params->local));
		else
			memcpy(&params->local6,
			       nla_data(greinfo[IFLA_GRE_LOCAL]),
			       sizeof(params->local6));
	} else
		syslog(LOG_ERR, "%s: %s IFLA_GRE_LOCAL not found.\n",
		       __FUNCTION__, ifp->ifname);

	if (greinfo[IFLA_GRE_REMOTE]) {
		if (params->family == AF_INET)
			memcpy(&params->remote,
			       nla_data(greinfo[IFLA_GRE_REMOTE]),
			       sizeof(params->remote));
		else
			memcpy(&params->remote6,
			       nla_data(greinfo[IFLA_GRE_REMOTE]),
			       sizeof(params->remote6));
	} else
		syslog(LOG_ERR, "%s: %s IFLA_GRE_REMOTE not found.\n",
		       __FUNCTION__, ifp->ifname);

	if (greinfo[IFLA_GRE_TTL]) {
		params->ttl = nla_get_u8(greinfo[IFLA_GRE_TTL]);
	} else {
		params->ttl = 64;
		syslog(LOG_ERR, "%s: %s IFLA_GRE_TTL not found.\n",
		       __FUNCTION__, ifp->ifname);
	}

	if (greinfo[IFLA_GRE_TOS]) {
		params->tos = nla_get_u8(greinfo[IFLA_GRE_TOS]);
		params->inh_tos = params->tos & 1;
		if (params->inh_tos)
			params->tos = 0;
	} else
		syslog(LOG_ERR, "%s: %s IFLA_GRE_TOS not found.\n",
		       __FUNCTION__, ifp->ifname);

	if (greinfo[IFLA_GRE_LINK]) {
		u_int32_t link_ifindex = nla_get_u32(greinfo[IFLA_GRE_LINK]);
		params->link_ifuid = cm_ifindex2ifuid(link_ifindex, ifp->vrfid, update);
	} else
		syslog(LOG_ERR, "%s: %s IFLA_GRE_LINK not found.\n",
		       __FUNCTION__, ifp->ifname);

	if (greinfo[IFLA_GRE_IFLAGS]) {
		u_int16_t flags = nla_get_u16(greinfo[IFLA_GRE_IFLAGS]);
		params->iflags = cm_gre_parse_flags(flags);
	} else
		syslog(LOG_ERR, "%s: %s IFLA_GRE_IFLAGS not found.\n",
		       __FUNCTION__, ifp->ifname);

	if (greinfo[IFLA_GRE_OFLAGS]) {
		u_int16_t flags = nla_get_u16(greinfo[IFLA_GRE_OFLAGS]);
		params->oflags = cm_gre_parse_flags(flags);
	} else
		syslog(LOG_ERR, "%s: %s IFLA_GRE_OFLAGS not found.\n",
		       __FUNCTION__, ifp->ifname);

	if (greinfo[IFLA_GRE_IKEY])
		params->ikey = nla_get_u32(greinfo[IFLA_GRE_IKEY]);
	else
		syslog(LOG_ERR, "%s: %s IFLA_GRE_IKEY not found.\n",
		       __FUNCTION__, ifp->ifname);

	if (greinfo[IFLA_GRE_OKEY])
		params->okey = nla_get_u32(greinfo[IFLA_GRE_OKEY]);
	else
		syslog(LOG_ERR, "%s: %s IFLA_GRE_OKEY not found.\n",
		       __FUNCTION__, ifp->ifname);
}

static void
cm_gre_create(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	cm_gre_update(ifp, h, tb, 0, CP_GRE_MODE_IP);
	cm2cp_gre_create(h->nlmsg_seq, CMD_GRE_CREATE, ifp, CP_GRE_MODE_IP);
}

static void
cm_gre_change(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	cm_gre_update(ifp, h, tb, 1, CP_GRE_MODE_IP);
	cm2cp_gre_create(h->nlmsg_seq, CMD_GRE_UPDATE, ifp, CP_GRE_MODE_IP);
}

static void
cm_gre_delete(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	struct cm_gre_params *params;

	params = (struct cm_gre_params *)(ifp + 1);
	memset(params, 0, sizeof(struct cm_gre_params));

	cm2cp_gre_create(h->nlmsg_seq, CMD_GRE_DELETE, ifp, CP_GRE_MODE_IP);
}

static void
cm_gretap_create(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	cm_gre_update(ifp, h, tb, 0, CP_GRE_MODE_ETHER);
	cm2cp_gre_create(h->nlmsg_seq, CMD_GRE_CREATE, ifp, CP_GRE_MODE_ETHER);
}

static void
cm_gretap_change(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	cm_gre_update(ifp, h, tb, 1, CP_GRE_MODE_ETHER);
	cm2cp_gre_create(h->nlmsg_seq, CMD_GRE_UPDATE, ifp, CP_GRE_MODE_ETHER);
}

static void
cm_gretap_delete(struct cm_iface *ifp, struct nlmsghdr *h, struct nlattr **tb)
{
	struct cm_gre_params *params;
	struct cm_eth_params *eth_params;

	eth_params = (struct cm_eth_params *)(ifp + 1);
	params = (struct cm_gre_params *)(eth_params + 1);
	memset(eth_params, 0, sizeof(struct cm_eth_params));
	memset(params, 0, sizeof(struct cm_gre_params));

	cm2cp_gre_create(h->nlmsg_seq, CMD_GRETAP_DELETE, ifp, CP_GRE_MODE_ETHER);
}
#endif /* CONFIG_CACHEMGR_GRE */

static void
cm_nl_single_route (u_int32_t cookie,
                    u_int32_t cmdtype,
                    u_int32_t nlflags,
                    uint32_t vrfid,
                    struct rtmsg *rtm,
                    void *src,
                    void *prefsrc,
                    void *dest,
                    void *gate,
                    int ifuid,
                    int in_ifuid,
                    u_int32_t *out_bfif,
                    struct nh_mark *nh_mark)
{
	u_int8_t nhtype = NH_TYPE_BASIC;

	/*
	 * Summarize various flags, type, scope into
	 * simple nexthop classification
	 *   basic/connected/local_deliver/blackhole
	 */
	if ((rtm->rtm_scope == RT_SCOPE_LINK) || (gate == NULL))
		nhtype = NH_TYPE_CONNECTED;
	if ((rtm->rtm_type == RTN_UNREACHABLE) || (rtm->rtm_type == RTN_PROHIBIT))
		nhtype = NH_TYPE_LOCAL_DELIVERY;

	if (rtm->rtm_type == RTN_BLACKHOLE)
		nhtype = NH_TYPE_BLACK_HOLE;

	/*
	 * Filter out ::/0 RTN_UNREACHABLE: it is the ip6_null_entry, which means
	 * there is no default route
	 */
	if ((rtm->rtm_family == AF_INET6) && (rtm->rtm_dst_len == 0) &&
	    (rtm->rtm_type == RTN_UNREACHABLE))
	{
		if (cm_debug_level & CM_DUMP_DBG_NL_RECV)
			syslog(LOG_INFO, "%s: "
				"filtering out ::/0 UNREACHABLE route (no default route)\n",
				__FUNCTION__);
		return;
	}

	if ((rtm->rtm_family == AF_INET6) && (rtm->rtm_dst_len == 128) &&
	    (nhtype == NH_TYPE_CONNECTED) &&
	    (rtm->rtm_protocol == RTPROT_KERNEL))
	{
		if (cm_debug_level & CM_DUMP_DBG_NL_RECV)
			syslog(LOG_INFO, "%s: "
				"filtering out /128 connected route associated to address\n",
				__FUNCTION__);
		return;
	}

	/*
	 * Warning, routes received from kernel with no nexhop address
	 * have a special handling:
	 *
	 * 1) 1.1.1.1/24 address on interface eth1
	 * =======================================
	 * - interface address add 1.1.1.1/24
	 * - connected route add 1.1.1.0/24 nh=0.0.0.0 via eth1
	 *
	 * 2) 1.1.1.1/32 address on interface eth1
	 * =======================================
	 * - interface address add 1.1.1.1/32
	 *
	 * 3) static route to 2.2.2.0/24 network, via interface eth1
	 * =========================================================
	 * - connected route add 2.2.2.0/24 nh=0.0.0.0 via eth1
	 *
	 * 4) static route to say 3.3.3.3/32, via interface eth1
	 * =====================================================
	 * - basic route add 3.3.3.3/32 nh=3.3.3.3 via eth1
	 *
	 * 5) static route to say 4.4.4.0/24, via PtP/loop interface foo
	 * ==============================================================
	 * - interface route add 3.3.3.0/24 nh=0.0.0.0 via foo
	 *
	 */
	/* patch connected routes */
	if (nhtype == NH_TYPE_CONNECTED) {
		if ((rtm->rtm_family == AF_INET ||
		     rtm->rtm_family == AF_INET6) &&
		     prefsrc)
			gate = prefsrc;
	}

	if (rtm->rtm_family == AF_INET) {
		if ( IN_MULTICAST(ntohl(((struct in_addr *)dest)->s_addr)) ) {
			if (vrfid == 0)
				cm2cp_ipv4_mroute(cookie, cmdtype,
						  (struct in_addr *)dest,
						  rtm->rtm_dst_len,
						  (struct in_addr *)src,
						  rtm->rtm_src_len,
						  in_ifuid, out_bfif);
			else {
				char addr[INET_ADDRSTRLEN];

				inet_ntop(AF_INET, dest, addr, sizeof(addr));
				syslog(LOG_WARNING, "Ignoring mcast route to %s: vrfid (%u) != 0",
				       addr, vrfid);
			}
		} else
			cm2cp_ipv4_route (cookie, cmdtype, nlflags, vrfid,
					(struct in_addr *)dest,
					rtm->rtm_dst_len,
					(struct in_addr *)gate,
					nhtype,
					ifuid,
					0,
					nh_mark);
	}
	else {
		if ( IN6_IS_ADDR_MULTICAST(dest) ) {
			if (vrfid == 0)
				cm2cp_ipv6_mroute(cookie, cmdtype,
						  (struct in6_addr *)dest,
						  rtm->rtm_dst_len,
						  (struct in6_addr *)src,
						  rtm->rtm_src_len,
						  in_ifuid, out_bfif);
			else {
				char addr[INET6_ADDRSTRLEN];

				inet_ntop(AF_INET6, dest, addr, sizeof(addr));
				syslog(LOG_WARNING, "Ignoring mcast route to %s: vrfid (%u) != 0",
				       addr, vrfid);
			}
		} else {
			cm2cp_ipv6_route (cookie, cmdtype, vrfid,
		               (struct in6_addr *)dest,
		               rtm->rtm_dst_len,
		               (struct in6_addr *)gate,
		               nhtype,
		               ifuid,
		               0,
		               nh_mark);
		}
	}
	return;
}

void
cm_nl_route (struct nlmsghdr *h, u_int32_t sock_vrfid)
{
	int err;
	struct rtmsg *rtm;
	struct nlattr *tb [RTA_MAX + 1];
	char anyaddr[16] = {0};
	uint32_t cm_outif[CM_MAXMIFS];
	int table;
	uint32_t ifuid = 0;
	uint32_t in_ifuid = 0;
	uint32_t vrf_id = sock_vrfid;
	void *dest = NULL;
	void *src = NULL;
	void *prefsrc = NULL;
	void *gate = NULL;
	u_int32_t cmdtype;
	u_int32_t nlflags;
	struct nh_mark nh_mark = {0, 0};

	rtm = nlmsg_data (h);

	if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
		syslog(LOG_DEBUG, "    family=%u type=%u flags=%08x tos=%u table=%u proto=%u"
			" dst_len=%u src_len=%u\n",
			rtm->rtm_family, rtm->rtm_type, rtm->rtm_flags, rtm->rtm_tos,
			rtm->rtm_table, rtm->rtm_protocol,
			rtm->rtm_dst_len, rtm->rtm_src_len);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	if (rtm->rtm_family == RTNL_FAMILY_IPMR)
		rtm->rtm_family = AF_INET;
	else if (rtm->rtm_family == RTNL_FAMILY_IP6MR)
		rtm->rtm_family = AF_INET6;
#endif
	if ((rtm->rtm_family != AF_INET) && (rtm->rtm_family != AF_INET6))
		return;
	if ((rtm->rtm_type != RTN_UNICAST) &&
	    (rtm->rtm_type != RTN_LOCAL) &&
	    (rtm->rtm_type != RTN_MULTICAST) &&
	    (rtm->rtm_type != RTN_UNREACHABLE) &&
	    (rtm->rtm_type != RTN_PROHIBIT) &&
	    (rtm->rtm_type != RTN_BLACKHOLE))
		return;

	table = rtm->rtm_table;
    /* The fastpath can only handle one table. In 6WIND kernels all
     * multicast routes are in the main table, in upstream kernels multicast v4
     * routes are in the default table and v6 ones are in the main table. We
     * must filter accordingly.
     * NET_VRF_SUPPORT is only defined in 6WIND kernels.
     */
#ifdef NET_VRF_SUPPORT
	if (rtm->rtm_type == RTN_MULTICAST && table != RT_TABLE_MAIN)
		return;
#else
	if (rtm->rtm_type == RTN_MULTICAST && rtm->rtm_family == AF_INET &&
	    table != RT_TABLE_DEFAULT)
		return;
	if (rtm->rtm_type == RTN_MULTICAST && rtm->rtm_family == AF_INET6 &&
	    table != RT_TABLE_MAIN)
		return;
#endif
	if (rtm->rtm_type != RTN_MULTICAST && table != RT_TABLE_MAIN)
		return;
	if (rtm->rtm_flags & RTM_F_CLONED)
		return;
	if (rtm->rtm_protocol == RTPROT_REDIRECT)
		return;
	if (rtm->rtm_src_len != 0 && rtm->rtm_type != RTN_MULTICAST)
		return;

	if ( rtm->rtm_type == RTN_MULTICAST )
		err = cm_nlmsg_parse(h, sizeof(*rtm), tb, RTA_MAX, MSG_FAMILY_RTM_MULTICAST);
	else
		err = cm_nlmsg_parse(h, sizeof(*rtm), tb, RTA_MAX, MSG_FAMILY_RTM);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

	if (tb[RTA_IIF]) {
		uint32_t idx = *(uint32_t *) nla_data (tb[RTA_IIF]);
		in_ifuid = cm_ifindex2ifuid(idx, sock_vrfid, 1);
		if (in_ifuid == 0) {
			syslog(LOG_DEBUG, "%s: %s unknown ifindex %d\n",
			       __FUNCTION__, rtm_type2str(h->nlmsg_type), idx);
			return;
		}
	}

	if (tb[RTA_OIF]) {
		uint32_t idx = *(uint32_t *) nla_data (tb[RTA_OIF]);
		ifuid = cm_ifindex2ifuid(idx, sock_vrfid, 1);
		if (ifuid == 0) {
			syslog(LOG_DEBUG, "%s: %s unknown ifindex %d\n",
			       __FUNCTION__, rtm_type2str(h->nlmsg_type), idx);
			return;
		}
	}

	if (tb[RTA_DST]) {
		dest = nla_data (tb[RTA_DST]);
		if ((rtm->rtm_dst_len == 96) && IN6_IS_PREF_V4COMPAT(dest)) {
			if (cm_debug_level & CM_DUMP_DBG_NL_RECV)
				syslog(LOG_INFO, "%s: "
					"filtering out route to ::/96\n",
					__FUNCTION__);
			return;
		}
	}
	else
		dest = anyaddr;

	if (tb[RTA_SRC])
		src = nla_data (tb[RTA_SRC]);
	else
		src = anyaddr;

	if (tb[RTA_PREFSRC])
		prefsrc = nla_data (tb[RTA_PREFSRC]);

	if (tb[RTA_GATEWAY])
		gate = nla_data (tb[RTA_GATEWAY]);

	memset(cm_outif, 0, sizeof(cm_outif));
	if (tb[RTA_MULTIPATH] && rtm->rtm_type == RTN_MULTICAST) {
		struct rtnexthop *nh = nla_data(tb[RTA_MULTIPATH]);
		unsigned int len, pos;

		len = nla_len(tb[RTA_MULTIPATH]);
		for (pos = 0;
		     len >= sizeof(*nh) && nh->rtnh_len <= len && pos < CM_MAXMIFS;
		     pos++) {
			cm_outif[pos] = cm_ifindex2ifuid (nh->rtnh_ifindex, sock_vrfid, 1);
			len -= NLMSG_ALIGN(nh->rtnh_len);
			nh = RTNH_NEXT(nh);
		}
	}
#ifdef RTA_VRFID
	if (tb[RTA_VRFID])
		vrf_id = *(u_int32_t *) nla_data (tb[RTA_VRFID]);
#endif

#ifdef RTA_NH_MARK
	if (tb[RTA_NH_MARK]) {
		struct nh_mark *rta_nh_mark = (struct nh_mark *) nla_data (tb[RTA_NH_MARK]);
		nh_mark.mark = rta_nh_mark->mark;
		nh_mark.mask = rta_nh_mark->mask;
	}
#endif

	/*
	 * scan flags to separate route change from route create.
	 * use the RTM_GETROUTE for change case.
	 */
	if (rtm->rtm_flags & RTM_F_NOTIFY)
		cmdtype = RTM_GETROUTE;
	else
		cmdtype = h->nlmsg_type;
	nlflags = h->nlmsg_flags;

	if (tb[RTA_MULTIPATH] && rtm->rtm_type != RTN_MULTICAST) {
		struct rtnexthop *nh = nla_data(tb[RTA_MULTIPATH]);
		unsigned int len, pos;

		len = nla_len(tb[RTA_MULTIPATH]);
		for (pos = 0; len >= sizeof(*nh) && nh->rtnh_len <= len; pos++) {
			gate = NULL;
			if (nh->rtnh_len > sizeof(*nh)) {
				cm_nl_parse_nlattr(tb, RTA_MAX, (struct nlattr *)RTNH_DATA(nh),
				                   nh->rtnh_len - sizeof(*nh), MSG_FAMILY_RTM);
				if (tb[RTA_GATEWAY])
					gate = nla_data (tb[RTA_GATEWAY]);
#ifdef RTA_NH_MARK
				if (tb[RTA_NH_MARK]) {
					struct nh_mark *rta_nh_mark = (struct nh_mark *) nla_data (tb[RTA_NH_MARK]);
					nh_mark.mark = rta_nh_mark->mark;
					nh_mark.mask = rta_nh_mark->mask;
				}
#endif
			}

			ifuid = cm_ifindex2ifuid (nh->rtnh_ifindex, sock_vrfid, 1);
			if (ifuid == 0) {
				syslog(LOG_DEBUG, "%s: %s unknown ifindex %d\n",
				       __FUNCTION__, rtm_type2str(h->nlmsg_type),
				       nh->rtnh_ifindex);
				return;
			}

			/* Transmit replace flag for first next hop only (route change) */
			cm_nl_single_route (h->nlmsg_seq, cmdtype, !pos ? nlflags : (nlflags & ~NLM_F_REPLACE), vrf_id,
				rtm, src, prefsrc, dest, gate, ifuid, in_ifuid, cm_outif, &nh_mark);
			len -= NLMSG_ALIGN(nh->rtnh_len);
			nh = RTNH_NEXT(nh);
		}
	}
	else
		cm_nl_single_route (h->nlmsg_seq, cmdtype, nlflags, vrf_id, rtm, src, prefsrc, dest, gate, ifuid,
		                    in_ifuid, cm_outif, &nh_mark);
	return;
}

static uint16_t
neigh_aggregate_state (int state)
{
	switch (state) {
		case NUD_NONE:
		case NUD_NOARP:
			return CM_L2STATE_NONE;
		case NUD_REACHABLE:
		case NUD_DELAY:
		case NUD_PROBE:
		case NUD_PERMANENT:
			return CM_L2STATE_REACHABLE;
		case NUD_STALE:
			return CM_L2STATE_STALE;
		case NUD_INCOMPLETE:
			/* to tell L2 resolution is in progress */
			return CM_L2STATE_INCOMPLETE;
		case NUD_FAILED:
			return CM_L2STATE_NONE;
	}
	return CM_L2STATE_NONE;
}

#ifdef CONFIG_CACHEMGR_VXLAN
static void cm_nl_fdb(struct nlmsghdr *h, u_int32_t sock_vrfid)
{
	struct cm_vxlan_fdb params;
	struct nlattr *tb[NDA_MAX + 1];
	struct ndmsg *neigh;
	void *addr = NULL;
	int err;

	memset(&params, 0, sizeof params);

	neigh = nlmsg_data (h);
	err = cm_nlmsg_parse(h, sizeof(*neigh), tb, NDA_MAX, MSG_FAMILY_NEIGH);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)\n", __func__,
		       nl_geterror(err));
		return;
	}

	if (tb[NDA_LLADDR]) {
		if (nla_len(tb[NDA_LLADDR]) != 6) {
			syslog(LOG_ERR,
			       "%s: wrong MAC address length in netlink message\n",
			       __FUNCTION__);
			return;
		}

		memcpy(params.mac, nla_data(tb[NDA_LLADDR]),
		       sizeof(params.mac));
	} else {
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
			syslog(LOG_ERR,
			       "%s: No MAC Address in netlink message\n",
			       __FUNCTION__);
		return;
	}

	params.ifuid = cm_ifindex2ifuid(neigh->ndm_ifindex, sock_vrfid, 1);
	if (params.ifuid == 0) {
		/* ndm_ifindex will be 0 when the vxlan iface is created into
		 * the kernel, because the default remote (00:00:00:00:00:00)
		 * will be register before the interface is registered. We can
		 * ignore this message, because the default remote will be
		 * advertised with the vxlan iface parameters.
		 */
		return;
	}

	if (!tb[NDA_DST]) {
		/* Ignore nl messages with partial infos. */
		return;
	}
	switch (nla_len(tb[NDA_DST])) {
	case 4:
		params.family = AF_INET;
		addr = (struct in_addr *)nla_data(tb[NDA_DST]);
		break;
	case 16:
		params.family = AF_INET6;
		addr = (struct in6_addr *)nla_data(tb[NDA_DST]);
		break;
	default:
		syslog(LOG_ERR,
		       "%s: unknown address family in netlink message\n",
		       __FUNCTION__);
		return;
	}

	if (tb[NDA_IFINDEX]) {
		params.output_ifuid =
			cm_ifindex2ifuid(nla_get_u32(tb[NDA_IFINDEX]),
					 sock_vrfid, 1);
		if (params.output_ifuid == 0) {
			syslog(LOG_DEBUG, "%s: %s unknown output ifindex %d\n",
			       __FUNCTION__,
			       rtm_type2str(h->nlmsg_type), neigh->ndm_ifindex);
			return;
		}
	}

	if (tb[NDA_PORT])
		params.dst_port = nla_get_u16(tb[NDA_PORT]);

	if (tb[NDA_VNI])
		params.vni = nla_get_u32(tb[NDA_VNI]);

	params.state = neigh_aggregate_state(neigh->ndm_state);

	cm2cp_fdb(h->nlmsg_seq, h->nlmsg_type, &params, addr);
}
#endif

/* Construct the message to give L2 updates to FPM */
void cm_nl_l2(struct nlmsghdr *h, u_int32_t sock_vrfid)
{
	int err;
	struct ndmsg *neigh;
	struct nlattr *tb[NDA_MAX + 1];
	void * addr = NULL;
	struct cm_eth_params params;
	uint8_t state;
	uint32_t ifuid = 0;

	neigh = nlmsg_data (h);

#ifdef CONFIG_CACHEMGR_VXLAN
	if (neigh->ndm_family == AF_BRIDGE)
		return cm_nl_fdb(h, sock_vrfid);
#endif

	if (neigh->ndm_family != AF_INET && neigh->ndm_family != AF_INET6)
		return ;

	err = cm_nlmsg_parse(h, sizeof(*neigh), tb, NDA_MAX, MSG_FAMILY_NEIGH);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

	if (!tb[NDA_DST]) {
		syslog(LOG_ERR, "%s: No Destination IP Address in netlink message\n", __FUNCTION__);
		return;
	}

	ifuid = cm_ifindex2ifuid(neigh->ndm_ifindex, sock_vrfid, 1);
	if (ifuid == 0) {
		syslog(LOG_DEBUG, "%s: %s unknwon ifindex %d\n",
		       __FUNCTION__, rtm_type2str(h->nlmsg_type),
		       neigh->ndm_ifindex);
		return;
	}

	if (neigh->ndm_family == AF_INET ){
		addr = (struct in_addr *) nla_data (tb[NDA_DST]);
	}
	else {
		addr = (struct in6_addr *) nla_data (tb[NDA_DST]);
	}

	memset (&params, 0, sizeof params);
	if (tb[NDA_LLADDR]) {
		params.maclen = nla_len(tb[NDA_LLADDR]);
		memcpy(params.mac, nla_data (tb[NDA_LLADDR]), params.maclen);
	} else if (cm_debug_level & CM_DUMP_EXT_NL_RECV) {
		syslog(LOG_ERR, "%s: No MAC Address in netlink message\n", __FUNCTION__);
	}

	if (h->nlmsg_type == RTM_DELNEIGH)
		state = CM_L2STATE_NONE;
	else
		state = neigh_aggregate_state(neigh->ndm_state);

	/*
	 * neighbour UID is not used anymore, but still present in the
	 * API, so must be set to 0
	 */
	cm2cp_l2(h->nlmsg_seq, state, ifuid, neigh->ndm_family, addr, &params, 0);
	return;
}

#ifdef RTM_NEWNETCONF

void cm_nl_netconf(struct nlmsghdr *h, u_int32_t sock_vrfid)
{
	struct netconfmsg *ncm = NLMSG_DATA(h);
	struct nlattr *tb[NETCONFA_MAX+1];
	struct cm_iface *ifp = NULL;
	u_int32_t flags;
	int err;

	if (h->nlmsg_type != RTM_NEWNETCONF) {
		syslog(LOG_ERR, "%s: not RTM_NEWNETCONF: %08x %08x %08x\n",
		       __FUNCTION__, h->nlmsg_len, h->nlmsg_type,
		       h->nlmsg_flags);
		return;
	}

	err = cm_nlmsg_parse(h, sizeof(*ncm), tb, NETCONFA_MAX, MSG_FAMILY_NETCONF);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

	if (tb[NETCONFA_IFINDEX]) {
		int ifindex = *(int *)nla_data(tb[NETCONFA_IFINDEX]);

		if (ifindex == NETCONFA_IFINDEX_ALL ||
		    ifindex == NETCONFA_IFINDEX_DEFAULT)
			return;

		ifp = iflookup(ifindex, sock_vrfid);
		if (ifp == NULL) {
			syslog(LOG_INFO,
			       "%s: unable to find ifp (ifindex: %d, vrfid: %d)\n",
			       __FUNCTION__, ifindex, sock_vrfid);
			return;
		}
	} else {
		syslog(LOG_ERR, "%s: tb[NETCONFA_IFINDEX] is NULL\n",
		       __FUNCTION__);
		return;
	}
	flags = ifp->flags;

	if (tb[NETCONFA_FORWARDING]) {
		int forwarding = *(int *)nla_data(tb[NETCONFA_FORWARDING]);

		if (ncm->ncm_family == AF_INET)
			flags = forwarding ?
				ifp->flags | CM_CPIFACE_IFFFWD_IPV4 :
				ifp->flags & ~CM_CPIFACE_IFFFWD_IPV4;
		else if (ncm->ncm_family == AF_INET6)
			flags = forwarding ?
				ifp->flags | CM_CPIFACE_IFFFWD_IPV6 :
				ifp->flags & ~CM_CPIFACE_IFFFWD_IPV6;
	}

	if (tb[NETCONFA_RP_FILTER]) {
		int rp_fiter = *(int *)nla_data(tb[NETCONFA_RP_FILTER]);

		if (ncm->ncm_family == AF_INET)
			flags = rp_fiter ?
				ifp->flags | CM_CPIFACE_IFFRPF_IPV4 :
				ifp->flags & ~CM_CPIFACE_IFFRPF_IPV4;
	}

	if (ifp->flags != flags) {
		cm2cp_iface_state (h->nlmsg_seq, ifp->ifuid, flags, ifp->flags ^ flags);
		ifp->flags = flags;
	}
}
#endif /* RTM_NEWNETCONF */
