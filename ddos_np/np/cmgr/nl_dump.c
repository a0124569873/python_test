/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *
 *          NL Msg Dumps
 *
 * $Id $Author
 ***************************************************************
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>

#include <net/if.h>
#include <netinet/in.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/xfrm.h>
#include <limits.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/mroute6.h>
#ifdef CONFIG_CACHEMGR_DIAG
#include <linux/sock_diag.h>
#endif
#ifdef CONFIG_CACHEMGR_AUDIT
#include <linux/audit.h>
#endif

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netlink/attr.h>

#include "fpc.h"
#include "cm_pub.h"
#include "cm_priv.h"
#include "cm_admin.h"

const char *
rtm_type2str(u_int16_t type)
{
	static char dflt[] = "RTM_[DDDDD]";
	char * str;

	switch(type) {
	_PF(RTM_NEWLINK)
	_PF(RTM_DELLINK)
	_PF(RTM_GETLINK)
	_PF(RTM_NEWADDR)
	_PF(RTM_DELADDR)
	_PF(RTM_GETADDR)
	_PF(RTM_NEWROUTE)
	_PF(RTM_DELROUTE)
	_PF(RTM_GETROUTE)
	_PF(RTM_NEWNEIGH)
	_PF(RTM_DELNEIGH)
	_PF(RTM_GETNEIGH)
	_PF(RTM_NEWQDISC)
	_PF(RTM_DELQDISC)
	_PF(RTM_GETQDISC)
	_PF(RTM_NEWTCLASS)
	_PF(RTM_DELTCLASS)
	_PF(RTM_GETTCLASS)
	_PF(RTM_NEWTFILTER)
	_PF(RTM_DELTFILTER)
	_PF(RTM_GETTFILTER)

	default:
		snprintf(dflt, sizeof(dflt), "RTM_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}

#ifdef NF_NETLINK_TABLES
const char *
nlnf_tables_type2str(u_int16_t type)
{
	static char dflt[] = "NFTBL_[DDDDD]";
	char * str;

	switch(type) {
	_PF(NFTBL_UPDATE)

	default:
		snprintf(dflt, sizeof(dflt), "NFTBL_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}
#endif

#ifdef NF_NETLINK_LSN_CPE
const char *
nlnf_cpe_type2str(u_int16_t type)
{
	static char dflt[] = "NFCPE_[DDDDD]";
	char * str;

	switch(type) {
	_PF(NF_LSN_CPE_NEW)
	_PF(NF_LSN_CPE_DEL)

	default:
		snprintf(dflt, sizeof(dflt), "NFCPE_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}
#endif

const char *
nlnf_conntrack_type2str(u_int16_t type)
{
	static char dflt[] = "NFCT_[DDDDD]";
	char * str;

	switch(type) {
	_PF(IPCTNL_MSG_CT_NEW)
	_PF(IPCTNL_MSG_CT_GET)
	_PF(IPCTNL_MSG_CT_DELETE)
	_PF(IPCTNL_MSG_CT_GET_CTRZERO)

	default:
		snprintf(dflt, sizeof(dflt), "NFCT_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}

const char *
nlxfrm_type2str(u_int16_t type)
{
	static char dflt[] = "XFRM_MSG_[DDDDD]";
	char * str;

	switch(type) {
	_PF(XFRM_MSG_NEWSA)
	_PF(XFRM_MSG_DELSA)
	_PF(XFRM_MSG_GETSA)
	_PF(XFRM_MSG_NEWPOLICY)
	_PF(XFRM_MSG_DELPOLICY)
	_PF(XFRM_MSG_GETPOLICY)
	_PF(XFRM_MSG_ALLOCSPI)
	_PF(XFRM_MSG_ACQUIRE)
	_PF(XFRM_MSG_EXPIRE)
	_PF(XFRM_MSG_UPDPOLICY)
	_PF(XFRM_MSG_UPDSA)
	_PF(XFRM_MSG_POLEXPIRE)
	_PF(XFRM_MSG_FLUSHSA)
	_PF(XFRM_MSG_FLUSHPOLICY)
#ifdef XFRM_MSG_MIP6NOTIFY
	_PF(XFRM_MSG_MIP6NOTIFY)
#endif /*XFRM_MSG_MIP6NOTIFY*/

	default:
		snprintf(dflt, sizeof(dflt), "XFRM_MSG_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}

const char *
rtm_attr2str(u_int16_t type)
{
	static char dflt[] = "IFLA_[DDDDD]";
	char * str;

	switch(type) {

	_PF(IFLA_UNSPEC)
	_PF(IFLA_ADDRESS)
	_PF(IFLA_BROADCAST)
	_PF(IFLA_IFNAME)
	_PF(IFLA_MTU)
	_PF(IFLA_LINK)
	_PF(IFLA_QDISC)
	_PF(IFLA_STATS)
	_PF(IFLA_COST)
	_PF(IFLA_PRIORITY)
	_PF(IFLA_MASTER)
	_PF(IFLA_WIRELESS)
	_PF(IFLA_PROTINFO)
	_PF(IFLA_TXQLEN)
	_PF(IFLA_MAP)
	_PF(IFLA_WEIGHT)
#ifdef IFLA_TTL
	_PF(IFLA_TTL)
#endif /*IFLA_TTL*/
#ifdef IFLA_TOS
	_PF(IFLA_TOS)
#endif
#ifdef IFLA_LIFETIME
	_PF(IFLA_LIFETIME)
#endif
#ifdef IFLA_GRACETIME
	_PF(IFLA_GRACETIME)
#endif
#ifdef IFLA_TIMESLOTS
	_PF(IFLA_TIMESLOTS)
#endif
#ifdef IFLA_PPPCHDLC_PARAM
	_PF(IFLA_PPPCHDLC_PARAM)
#endif
#ifdef IFLA_LINKVRFID
	_PF(IFLA_LINKVRFID)
#endif
#ifdef IFLA_KEY
	_PF(IFLA_KEY)
#endif
#ifdef IFLA_STATS64
	_PF(IFLA_STATS64)
#endif
#ifdef IFLA_SVTI_IKE_ID
	_PF(IFLA_SVTI_IKE_ID)
#endif
#ifdef IFLA_XFLAGS
	_PF(IFLA_XFLAGS)
#endif
#ifdef IFLA_VRFID
	_PF(IFLA_VRFID)
#endif
#ifdef IFLA_IPV4_FORWARD
	_PF(IFLA_IPV4_FORWARD)
#endif
#ifdef IFLA_IPV4_FORWARD
	_PF(IFLA_IPV6_FORWARD)
#endif
#ifdef IFLA_RUNNING
	_PF(IFLA_RUNNING)
#endif
#ifdef IFLA_IPV4_RPF
	_PF(IFLA_IPV4_RPF)
#endif
#ifdef IFLA_LINKINFO
	_PF(IFLA_LINKINFO)
#endif

	default:
		snprintf(dflt, sizeof(dflt), "IFLA_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}

const char *
rtm_rta_attr2str(u_int16_t type)
{
	static char dflt[] = "RTA_[DDDDD]";
	char * str;

	switch(type) {

	_PF(RTA_UNSPEC)
	_PF(RTA_DST)
	_PF(RTA_SRC)
	_PF(RTA_IIF)
	_PF(RTA_OIF)
	_PF(RTA_GATEWAY)
	_PF(RTA_PRIORITY)
	_PF(RTA_PREFSRC)
	_PF(RTA_METRICS)
	_PF(RTA_MULTIPATH)
	_PF(RTA_PROTOINFO)
	_PF(RTA_FLOW)
	_PF(RTA_CACHEINFO)
	_PF(RTA_SESSION)
	_PF(RTA_MP_ALGO)
#ifdef RTA_TABLE
	_PF(RTA_TABLE)
#endif
#ifdef RTA_MCSTATE
	_PF(RTA_MCSTATE)
#endif /*RTA_MCSTATE*/
#ifdef RTA_VIFID
	_PF(RTA_VIFID)
#endif
#ifdef RTA_VRFID
	_PF(RTA_VRFID)
#endif
#ifdef RTA_TTLOIF
	_PF(RTA_TTLOIF)
#endif
#ifdef RTA_NH_MARK
	_PF(RTA_NH_MARK)
#endif

	default:
		snprintf(dflt, sizeof(dflt), "RTA_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}

const char *
addr_attr2str(u_int16_t type)
{
	static char dflt[] = "IFA_[DDDDD]";
	char * str;

	switch(type) {

	_PF(IFA_UNSPEC)
	_PF(IFA_ADDRESS)
	_PF(IFA_LOCAL)
	_PF(IFA_LABEL)
	_PF(IFA_BROADCAST)
	_PF(IFA_ANYCAST)
	_PF(IFA_CACHEINFO)
#ifdef IFA_HOMEAGENT
	_PF(IFA_HOMEAGENT)
#endif

	default:
		snprintf(dflt, sizeof(dflt), "IFA_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}

const char *
neigh_attr2str(u_int16_t type)
{
	static char dflt[] = "NDA_[DDDDD]";
	char * str;

	switch(type) {

	_PF(NDA_UNSPEC)
	_PF(NDA_DST)
	_PF(NDA_LLADDR)
	_PF(NDA_CACHEINFO)
	_PF(NDA_PROBES)
#ifdef NDA_OLDSTATE
	_PF(NDA_OLDSTATE)
#endif /*NDA_OLDSTATE*/

	default:
		snprintf(dflt, sizeof(dflt), "NDA_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}

void
attr_dump(const struct nlattr *nla, int family)
{
	int log_len = 0;
	char log[LOG_BUFFER_LEN];

	/* display message */
	switch (family) {

	case MSG_FAMILY_RTM:
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV) {
			syslog(LOG_DEBUG, "   %s(%hu) len=%hu\n",
				rtm_rta_attr2str(nla->nla_type), nla->nla_type, nla->nla_len);

			if (nla_len(nla)) {
				switch(nla->nla_type) {
				/* TBD
					RTA_UNSPEC,
					RTA_DST,
					RTA_SRC,
					RTA_IIF,
					RTA_OIF,
					RTA_GATEWAY,
					RTA_PRIORITY,
					RTA_PREFSRC,
					RTA_METRICS,
					RTA_MULTIPATH,
					RTA_VIFID,
					RTA_PROTOINFO,
					RTA_FLOW,
					RTA_CACHEINFO,
					RTA_SESSION,
					RTA_MCSTATE,
				*/
				default:
					break;
				}
			}
		}
		if (cm_debug_level & CM_DUMP_HEX_NL_RECV)
			hexdump(nla, nla->nla_len, 16, "      ");
		break;
	case MSG_FAMILY_NEIGH:
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV) {
			syslog(LOG_DEBUG, "   %s(%hu) len=%hu\n",
				neigh_attr2str(nla->nla_type), nla->nla_type, nla->nla_len);

			if (nla_len(nla)) {
				switch(nla->nla_type) {
				/* TBD
					NDA_DST,
					NDA_LLADDR,
					NDA_CACHEINFO,
					NDA_OLDSTATE,
				*/
				default:
					break;
				}
			}
		}
		if (cm_debug_level & CM_DUMP_HEX_NL_RECV)
			hexdump(nla, nla->nla_len, 16, "      ");
		break;
	case MSG_FAMILY_ADDR:
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV) {
			syslog(LOG_DEBUG, "   %s(%hu) len=%hu\n",
				rtm_rta_attr2str(nla->nla_type), nla->nla_type, nla->nla_len);

			if (nla_len(nla)) {
				switch(nla->nla_type) {
				/* TBD
					IFA_UNSPEC,
					IFA_ADDRESS,
					IFA_LOCAL,
					IFA_LABEL,
					IFA_BROADCAST,
					IFA_ANYCAST,
					IFA_CACHEINFO,
					IFA_HOMEAGENT,
				*/
				default:
					break;
				}
			}
		}
		if (cm_debug_level & CM_DUMP_HEX_NL_RECV)
			hexdump(nla, nla->nla_len, 16, "      ");
		break;
	case MSG_FAMILY_IFACE:
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV) {
			log_len = snprintf(log, LOG_BUFFER_LEN, "   %s(%hu) len=%hu",
					rtm_attr2str(nla->nla_type), nla->nla_type, nla->nla_len);

			if (nla_len(nla)) {
				switch(nla->nla_type) {
				case IFLA_IFNAME:
					log_len += snprintf(log + log_len, LOG_BUFFER_LEN - log_len,
							" ifname=%s", (char *)nla_data(nla));
					break;
#ifdef IFLA_VRFID
				case IFLA_VRFID:
					log_len += snprintf(log + log_len, LOG_BUFFER_LEN - log_len,
							" vrfid=%u", *(u_int32_t *)nla_data (nla));
					break;
#endif

				case IFLA_MTU:
					log_len += snprintf(log + log_len, LOG_BUFFER_LEN - log_len,
							" mtu=%u", *(u_int32_t *)nla_data (nla));
						break;
#if defined(IFLA_TTL) && defined(IFLA_TOS)
				case IFLA_TTL:
				case IFLA_TOS:
					log_len += snprintf(log + log_len, LOG_BUFFER_LEN - log_len,
							" data=%u", (u_int)*(u_int8_t *)nla_data (nla));
					break;
#endif /*IFLA_TTL*/
				default:
					break;
				}
			}
			syslog(LOG_DEBUG, "%s\n", log);
		}
		if (cm_debug_level & CM_DUMP_HEX_NL_RECV)
			hexdump(nla, nla->nla_len, 16, "      ");
		break;
	case MSG_FAMILY_RTM_MULTICAST:
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV) {
			log_len = snprintf(log, LOG_BUFFER_LEN, "   %s(%hu) len=%hu",
					rtm_rta_attr2str(nla->nla_type), nla->nla_type, nla->nla_len);

			if ( nla_len(nla)) {
				switch(nla->nla_type) {
				case RTA_IIF: {
					char ifname[IF_NAMESIZE];
					u_int32_t ifid = (*(u_int32_t*)nla_data(nla));
					if_indextoname( ifid, ifname );
					log_len += snprintf(log + log_len, LOG_BUFFER_LEN - log_len,
							" in ifindex=%d (%s)", ifid, ifname);
					break;
				}
				case RTA_DST:
				case RTA_SRC:{
					char name[64];
					inet_ntop( AF_INET6, nla_data (nla), name, sizeof(name));
					log_len += snprintf(log + log_len, LOG_BUFFER_LEN - log_len,
							" %s: %s", (nla->nla_type == RTA_SRC)?"src":"grp", name);
					break;
				}
				default:
					break;
				}
			}
			syslog(LOG_DEBUG, "%s\n", log);
		}
		if (cm_debug_level & CM_DUMP_HEX_NL_RECV)
			hexdump(nla, nla->nla_len, 16, "      ");
		break;

	case MSG_FAMILY_VNB:
		if (cm_debug_level & CM_DUMP_HEX_NL_RECV)
			hexdump(nla, nla->nla_len, 16, "      ");
		break;

	case MSG_FAMILY_VNB_DUMP:
		if (cm_debug_level & CM_DUMP_HEX_NL_RECV)
			hexdump(nla, nla->nla_len, 16, "      ");
		break;
#ifdef RTM_NEWNETCONF
	case MSG_FAMILY_NETCONF:
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
			syslog(LOG_DEBUG, "   %s(%hu) len=%hu\n",
			       rtm_rta_attr2str(nla->nla_type), nla->nla_type,
			       nla->nla_len);
		if (cm_debug_level & CM_DUMP_HEX_NL_RECV)
			hexdump(nla, nla->nla_len, 16, "      ");
		break;
#endif
	}
}

#ifdef NF_NETLINK_TABLES
/* netfilter conntrack subsystem message types */
const char *
nlnf_subsys2str(u_int16_t subsys)
{
	static char dflt[] = "NFNL_SUBSYS_[DDDDD]";
	char * str;

	switch(NFNL_SUBSYS_ID(subsys)) {

	_PF(NFNL_SUBSYS_TABLES)
	_PF(NFNL_SUBSYS_CTNETLINK)

	default:
		snprintf(dflt, sizeof(dflt), "NFNL_SUBSYS_[%u]", NFNL_SUBSYS_ID(subsys));
		str = dflt;
		break;
	}

	return(str);
}

/* netfilter tables subsystem message types */
const char *
nlnf_tables_nftype2str(u_int16_t type)
{
	static char dflt[] = "NFTBL_[DDDDD]";
	char * str;

	switch(NFNL_MSG_TYPE(type)) {

	_PF(NFTBL_UPDATE)

	default:
		snprintf(dflt, sizeof(dflt), "NFTBL_[%u]", NFNL_MSG_TYPE(type));
		str = dflt;
		break;
	}

	return(str);
}
#endif /* NF_NETLINK_TABLES */

#ifdef NF_NETLINK_LSN_CPE
/* netfilter tables subsystem message types */
const char *
nlnf_cpe_nftype2str(u_int16_t type)
{
	static char dflt[] = "NFCPE_[DDDDD]";
	char * str;

	switch(NFNL_MSG_TYPE(type)) {

	_PF(NF_LSN_CPE_NEW)
	_PF(NF_LSN_CPE_DEL)

	default:
		snprintf(dflt, sizeof(dflt), "NFCPE_[%u]", NFNL_MSG_TYPE(type));
		str = dflt;
		break;
	}

	return(str);
}
#endif /* NF_NETLINK_LSN_CPE */

#ifdef NF_NETLINK_TABLES
/* netfilter conntrack subsystem message types */
const char *
nlnf_conntrack_nftype2str(u_int16_t type)
{
	static char dflt[] = "IPCTNL_MSG_CT_[DDDDD]";
	char * str;

	switch(NFNL_MSG_TYPE(type)) {

	_PF(IPCTNL_MSG_CT_NEW)
	_PF(IPCTNL_MSG_CT_GET)
	_PF(IPCTNL_MSG_CT_DELETE)
	_PF(IPCTNL_MSG_CT_GET_CTRZERO)

	default:
		snprintf(dflt, sizeof(dflt), "IPCTNL_MSG_CT_[%u]", NFNL_MSG_TYPE(type));
		str = dflt;
		break;
	}

	return(str);
}

const char *
nftbl_attr2str(u_int16_t type)
{
	static char dflt[] = "NFTBLA_[DDDDD]";
	char * str;

	switch(type) {

	_PF(NFTBLA_TABLENAME)

	default:
		snprintf(dflt, sizeof(dflt), "NFTBLA_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}

void
nfattr_dump(const struct nfattr *nfa, u_int32_t subsys)
{
	int log_len = 0;
	char log[LOG_BUFFER_LEN];

	/* display message */
	switch(NFNL_SUBSYS_ID(subsys)) {
	case NFNL_SUBSYS_TABLES:
		if (cm_debug_level & CM_DUMP_EXT_NL_RECV) {
			log_len = snprintf(log, LOG_BUFFER_LEN, "%s(%hu) len=%hu",
					nftbl_attr2str(nfa->nfa_type), nfa->nfa_type, nfa->nfa_len);

			if (NFA_PAYLOAD(nfa)) {
				switch(nfa->nfa_type) {
				case NFTBLA_TABLENAME:
					log_len += snprintf(log + log_len, LOG_BUFFER_LEN - log_len,
							" table name=%s", (char *)NFA_DATA(nfa));
					break;
				case NFTBLA_UNSPEC:
				default:
					break;
				}
			}
			syslog(LOG_DEBUG, "%s\n", log);
		}
		break;
	}
	if (cm_debug_level & CM_DUMP_HEX_NL_RECV)
		hexdump(nfa, nfa->nfa_len, 16, "      ");

}
#endif /* NF_NETLINK_TABLES */

#ifdef CONFIG_CACHEMGR_AUDIT
const char *
nlaudit_type2str(u_int16_t type)
{
	static char dflt[] = "AUDIT_[DDDDD]";
	char * str;

	switch(type) {
		_PF(AUDIT_NETFILTER_CFG);

	default:
		snprintf(dflt, sizeof(dflt), "AUDIT_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}
#endif /* CONFIG_CACHEMGR_AUDIT */

#ifdef CONFIG_CACHEMGR_DIAG
const char *
nldiag_type2str(u_int16_t type)
{
	static char dflt[] = "DIAG_MSG_[DDDDD]";
	char * str;

	switch(type) {
	_PF(SOCK_DIAG_BY_FAMILY)

	default:
		snprintf(dflt, sizeof(dflt), "DIAG_MSG_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}
#endif
