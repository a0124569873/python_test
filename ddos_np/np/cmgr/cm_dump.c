/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *
 *          Generic Msg Dumps
 *
 * $Id: cm_dump.c,v 1.92 2010-03-03 16:16:57 guerin Exp $
 ***************************************************************
 */

#include <sys/types.h>
#include <sys/errno.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h> /* inet_ntop */

#include "fpc.h"
#include "cm_pub.h"
#include "cm_priv.h"
#include "cm_admin.h"

#include <net/if.h> /* ifnametoindex, IFNAMSIZ */
static int max_dump_len = 128;

void
hexdump(const void *buf, int len, int columns, char *str)
{
	const u_int8_t *p;
	int max_len = len;
	int i, log_len = 0;
	char log[LOG_BUFFER_LEN];

	if (len > max_dump_len)
		max_len = max_dump_len;

	for (i=0, p=buf; i<max_len; i++, p++) {
		if (i%columns == 0) {
			if (i) {
				syslog(LOG_DEBUG, "%s%s\n", str, log);
				log_len = 0;
				log[0] = 0;
				log_len = snprintf(log, LOG_BUFFER_LEN, "%02x ", *p);
			}
			else
				log_len += snprintf(log + log_len, LOG_BUFFER_LEN - log_len, "%02x ", *p);
		} else
			log_len += snprintf(log + log_len, LOG_BUFFER_LEN - log_len, "%02x ", *p);
	}
	syslog(LOG_DEBUG, "%s%s\n", str, log);
	if (len > max_dump_len)
		syslog(LOG_DEBUG, "%s...\n", str);
}

/*
 * convert IPv4 netmask to prefix length
 * optimized for well-formed netmasks (only ones then only zeroes)
 */
static u_int32_t
__mask2len (u_int8_t *msk)
{
	u_int32_t len=0;
	int i;

	for (i=0; i<4; i++) {
	switch(msk[i]) {
		case 0xff:	/* 1111 1111 */
			len += 8;
			break;
		case 0xfe:	/* 1111 1110 */
			len += 7;
			goto end;
		case 0xfc:	/* 1111 1100 */
			len += 6;
			goto end;
		case 0xf8:	/* 1111 1000 */
			len += 5;
			goto end;
		case 0xf0:	/* 1111 0000 */
			len += 4;
			goto end;
		case 0xe0:	/* 1110 0000 */
			len += 3;
			goto end;
		case 0xc0:	/* 1100 0000 */
			len += 2;
			goto end;
		case 0x80:	/* 1000 0000 */
			len += 1;
			goto end;
		case 0x00:	/* 0000 0000 */
			goto end;
		default:	/* bad mask => count first bits set to 1 */
			{
				int j;
				u_int8_t tm = 0x80;
				for (j=0; j<7; j++) {
					if ((msk[i] & tm) == 0)
						goto end;
					tm >>= 1;
					len++;
			}
		}
	}
	}

end:
	return len;
}

static int
prt_ifname (u_int32_t ifuid, cm_ifuid2name_t i2n, char *buffer)
{
	char *ifname = NULL;
	if(i2n) {
		ifname = (*i2n)(ifuid);
		return sprintf(buffer, "%s", ifname);
	}
	else
		return sprintf(buffer, "[%d]", ntohl(ifuid));
}

void
cm_dump (int stage, struct fpm_msg *msg, char *str, cm_ifuid2name_t i2n)
{
	int dump_hdr = 1;	/* dump message common header */
	int dump_main = 1;	/* dump message main fields */
	int dump_ext = 1;	/* dump message extension */
	int dump_hex = 1;	/* do a full message hexdump */
	char *dump_cmd = "????:  ";
	int cmd;
	char log[LOG_BUFFER_LEN];
	int log_len;

#define LOG_INIT() do { log_len = 0; } while(0)
#define LOG_ADD(fmt, args...) do { \
	log_len += snprintf(log + log_len, LOG_BUFFER_LEN - log_len, \
			fmt, ## args); \
} while(0)
#define LOG_PRINT(level) do { syslog(level, "%s", log); log_len = 0; } while(0)

	if (cm_debug_level == 0)
		return;
	/* Allow to filter some traces */
	switch (ntohl(msg->msg_pkt->cphdr_type)) {
	case CMD_ARP_UPDATE:
		if (cm_skip_level & CM_DUMP_SKIP_ARP)
			return;
		break;
	case CMD_NDP_UPDATE:
		if (cm_skip_level & CM_DUMP_SKIP_NDP)
			return;
		break;
	case CMD_ROUTE4_ADD:
	case CMD_ROUTE4_DEL:
		if (cm_skip_level & CM_DUMP_SKIP_ROUTE4)
			return;
	case CMD_ROUTE6_ADD:
	case CMD_ROUTE6_DEL:
		if (cm_skip_level & CM_DUMP_SKIP_ROUTE6)
			return;
	default:
		break;
	}

	switch (stage) {
	case CM_DUMP_QUEUED:
		dump_hdr = cm_debug_level & CM_DUMP_HDR_QUEUED;
		dump_main = dump_hdr;
		dump_ext = cm_debug_level & CM_DUMP_EXT_QUEUED;
		dump_hex = cm_debug_level & CM_DUMP_HEX_QUEUED;
		dump_cmd = "fpm queue:";
		break;

	case CM_DUMP_SENT:
		dump_hdr = cm_debug_level & CM_DUMP_HDR_SENT;
		dump_main = 0;
		dump_ext = 0;
		dump_hex = cm_debug_level & CM_DUMP_HEX_SENT;
		dump_cmd = "fpm send:";
		break;

	case CM_DUMP_SENT_WITH_PAYLOAD:
		dump_hdr = cm_debug_level & CM_DUMP_HDR_SENT;
		dump_main = dump_hdr;
		dump_ext = cm_debug_level & CM_DUMP_EXT_SENT;
		dump_hex = cm_debug_level & CM_DUMP_HEX_SENT;
		dump_cmd = "fpm send:";
		break;


	case CM_DUMP_RECV:
		dump_hdr = cm_debug_level & CM_DUMP_HDR_RECV;
		dump_main = dump_hdr;
		dump_ext = cm_debug_level & CM_DUMP_EXT_RECV;
		dump_hex = cm_debug_level & CM_DUMP_HEX_RECV;
		dump_cmd = "fpm recv:";
		break;

	case CM_DUMP_RECV_WITH_PAYLOAD:
		dump_hdr = cm_debug_level & CM_DUMP_HDR_RECV;
		dump_main = dump_hdr;
		dump_ext = cm_debug_level & CM_DUMP_EXT_RECV;
		dump_hex = cm_debug_level & CM_DUMP_HEX_RECV;
		dump_cmd = "fpm recv:";
		break;

	case CM_DUMP_FPM:
		dump_hdr = 1;
		dump_main = dump_hdr;
		dump_ext = 1;
		dump_hex = 1;
		dump_cmd = str;
		str = NULL;
		break;
	}

	if ((dump_hdr == 0) && (dump_hex ==0) && (dump_ext == 0))
		return;

	syslog(LOG_DEBUG, "------------------------------------------------------------\n");

	if (dump_hdr) {
		u_int32_t err = ntohl(msg->msg_pkt->cphdr_report);
		cmd = ntohl(msg->msg_pkt->cphdr_type);

		syslog(LOG_DEBUG, "%s %s len=%d err=%x%s\n",
		          dump_cmd,
		          cm_command2str(cmd),
		          msg->msg_len,
		          CMCPDP_ERROR_ERROR(err),
		          CMCPDP_ERROR_RESEND(err) ? " (Resend)" : "");

		if (dump_main) {

		switch (cmd) {
		case CMD_RESET: {
			struct cp_reset *rst;

			rst = (struct cp_reset *)(msg->msg_pkt + 1);
			syslog(LOG_INFO, SPACES "RESET appid=%u  Major=%u Minor=%u\n",
			        ntohl(rst->cp_reset_appid),
			        ntohs(rst->cp_reset_major),
			        ntohs(rst->cp_reset_minor));
			}
			break;

		case CMD_IF_CREATE:
		case CMD_IF_DELETE: {
			struct cp_iface_create *cpi;

			LOG_INIT();
			cpi = (struct cp_iface_create *)(msg->msg_pkt + 1);
			if (cmd == CMD_IF_CREATE)
				LOG_ADD(SPACES "IF_CREATE");
			else
				LOG_ADD(SPACES "IF_DELETE");
			LOG_ADD(" %s in VR#%d (0x%08x)", cpi->cpiface_ifname,
					ntohl(cpi->cpiface_vrfid), ntohl(cpi->cpiface_ifuid));
			LOG_PRINT(LOG_INFO);
			if (dump_ext) {
				unsigned int i;
				u_int32_t ltype = ntohl(cpi->cpiface_type);
				u_int32_t lsubtype = ntohl(cpi->cpiface_subtype);
				u_int32_t lmtu = ntohl (cpi->cpiface_mtu);
				u_int32_t maclen = ntohl (cpi->cpiface_maclen);

				LOG_ADD(SPACES "type=%s mtu=%u", cm_iftype2str(ltype), lmtu);
				switch(ltype) {
					case CM_IFTYPE_ETH: {
						LOG_ADD(" MAC=");
						for (i=0; i<maclen; i++) {
							if (i>0)
								LOG_ADD(":");
							LOG_ADD("%02x", cpi->cpiface_mac[i]);
						}
						break;
					}
					default:
						break;
				}

				if (lsubtype)
					LOG_ADD(" info=%s", cm_ifsubtype2str(lsubtype));
				LOG_PRINT(LOG_INFO);
			}
			break;
		}
		case CMD_XIN4_CREATE:
		case CMD_XIN4_DELETE:
		case CMD_XIN4_UPDATE: {
			struct cp_xin4 *cpi;

			LOG_INIT();
			cpi = (struct cp_xin4*)(msg->msg_pkt + 1);
			if (cmd == CMD_XIN4_CREATE)
				LOG_ADD(SPACES "XIN4_CREATE");
			else if (cmd == CMD_XIN4_DELETE)
				LOG_ADD(SPACES "XIN4_DELETE");
			else
				LOG_ADD(SPACES "XIN4_UPDATE");
			LOG_ADD(" %s in VR#%d LINKVR#%d (0x%08x)", cpi->cpxin4_ifname,
					ntohl(cpi->cpxin4_vrfid),
					ntohl(cpi->cpxin4_linkvrfid),
					ntohl(cpi->cpxin4_ifuid));
			if (dump_ext) {
				char local[INET_ADDRSTRLEN]="";
				char remote[INET_ADDRSTRLEN]="";

				LOG_ADD(" mtu=%u ttl=%u tos=", ntohl(cpi->cpxin4_mtu), cpi->cpxin4_ttl);

				if (cpi->cpxin4_inh_tos)
					LOG_ADD("inherit");
				else
					LOG_ADD("%u", cpi->cpxin4_tos);

				inet_ntop(AF_INET, &cpi->cpxin4_local,  local,  sizeof(local));
				inet_ntop(AF_INET, &cpi->cpxin4_remote, remote, sizeof(remote));
				LOG_ADD(" local=%s remote=%s", local, remote);
			}
			LOG_PRINT(LOG_INFO);
			break;
		}
		case CMD_XIN6_CREATE:
		case CMD_XIN6_DELETE:
		case CMD_XIN6_UPDATE: {
			struct cp_xin6 *cpi;

			LOG_INIT();
			cpi = (struct cp_xin6*)(msg->msg_pkt + 1);
			if (cmd == CMD_XIN6_CREATE)
				LOG_ADD(SPACES "XIN6_CREATE");
			else if (cmd == CMD_XIN6_DELETE)
				LOG_ADD(SPACES "XIN6_DELETE");
			else
				LOG_ADD(SPACES "XIN6_UPDATE");
			LOG_ADD(" %s in VR#%d LINKVR#%d (0x%08x)", cpi->cpxin6_ifname,
					ntohl(cpi->cpxin6_vrfid), ntohl(cpi->cpxin6_linkvrfid),
					ntohl(cpi->cpxin6_ifuid));
			if (dump_ext) {
				char local[INET6_ADDRSTRLEN]="";
				char remote[INET6_ADDRSTRLEN]="";

				LOG_ADD(" mtu=%u ttl=%u tos=", ntohl(cpi->cpxin6_mtu),
						cpi->cpxin6_hoplim);
				if (cpi->cpxin6_inh_tos)
					LOG_ADD("inherit");
				else
					LOG_ADD("%u", cpi->cpxin6_tos);

				inet_ntop(AF_INET6, &cpi->cpxin6_local,  local,  sizeof(local));
				inet_ntop(AF_INET6, &cpi->cpxin6_remote, remote, sizeof(remote));
				LOG_ADD(" local=%s remote=%s", local, remote);
			}
			LOG_PRINT(LOG_INFO);
			break;
		}
		case CMD_SVTI_CREATE:
		case CMD_SVTI_DELETE: {
			struct cp_svti *cpi;

			LOG_INIT();
			cpi = (struct cp_svti*)(msg->msg_pkt + 1);
			if (cmd == CMD_SVTI_CREATE)
				LOG_ADD(SPACES "SVTI_CREATE");
			else if (cmd == CMD_SVTI_DELETE)
				LOG_ADD(SPACES "SVTI_DELETE");
			LOG_ADD(" %s in VR#%d LINKVR#%d (0x%08x)", cpi->cpsvti_ifname,
					ntohl(cpi->cpsvti_vrfid),
					ntohl(cpi->cpsvti_linkvrfid),
					ntohl(cpi->cpsvti_ifuid));
			if (dump_ext) {
				LOG_PRINT(LOG_INFO);
				char local[INET_ADDRSTRLEN]="";
				char remote[INET_ADDRSTRLEN]="";

				LOG_ADD(SPACES " mtu=%u", ntohl(cpi->cpsvti_mtu));

				inet_ntop(AF_INET, &cpi->cpsvti_local,  local,  sizeof(local));
				inet_ntop(AF_INET, &cpi->cpsvti_remote, remote, sizeof(remote));
				LOG_ADD(" local=%s remote=%s", local, remote);
			}
			LOG_PRINT(LOG_INFO);
			break;
		}
		case CMD_IF_STATE_UPDATE: {
			struct cp_iface_state *cps;
			int state;

			LOG_INIT();
			cps = (struct cp_iface_state *)(msg->msg_pkt + 1);
			state  = ntohl(cps->cpiface_state);
			LOG_ADD(SPACES "IF_STATE for ");
			log_len += prt_ifname(cps->cpiface_ifuid, i2n, log + log_len);
			LOG_ADD(": %s|%s|%s|%s|%s|%s|%s",
					(state & CM_CPIFACE_IFFUP) ? "UP":"down",
					(state & CM_CPIFACE_IFFRUNNING) ? "RUNNING":"unplugged",
					(state & CM_CPIFACE_IFFFWD_IPV4) ? "FWD4":"nofwd4",
					(state & CM_CPIFACE_IFFFWD_IPV6) ? "FWD6":"nofwd6",
					(state & CM_CPIFACE_IFFPROMISC) ? "PROMISC":"notpromisc",
					(state & CM_CPIFACE_IFFPREFERRED) ? "PREF":"notpref",
					(state & CM_CPIFACE_IFFRPF_IPV4) ? "RPF4":"norpf4");
			LOG_PRINT(LOG_INFO);
			break;
		}
		case CMD_IF_MTU: {
			struct cp_iface_mtu *cpm;

			LOG_INIT();
			cpm = (struct cp_iface_mtu *)(msg->msg_pkt + 1);
			LOG_ADD(SPACES "IF_MTU for ");
			log_len += prt_ifname(cpm->cpiface_ifuid, i2n, log + log_len);
			LOG_ADD(" : %u", ntohl(cpm->cpiface_mtu));
			LOG_PRINT(LOG_INFO);
			break;
		}
		case CMD_TUN_TTL: {
			struct cp_iface_ttl *ift;

			LOG_INIT();
			ift = (struct cp_iface_ttl *)(msg->msg_pkt + 1);
			LOG_ADD(SPACES "IF_TTL for ");
			log_len += prt_ifname(ift->cpiface_ifuid, i2n, log + log_len);
			LOG_ADD(" : %u", ift->cpiface_ttl);
			LOG_PRINT(LOG_INFO);
			break;
		}
		case CMD_TUN_TOS: {
			struct cp_iface_tos *ift;

			LOG_INIT();
			ift = (struct cp_iface_tos *)(msg->msg_pkt + 1);
			LOG_ADD(SPACES "IF_TOS for ");
			log_len += prt_ifname(ift->cpiface_ifuid, i2n, log + log_len);
			if (ift->cpiface_inh_tos)
				LOG_ADD(": inherit");
			else
				LOG_ADD(": %u", ift->cpiface_tos);
			LOG_PRINT(LOG_INFO);
			break;
		}
		case CMD_INTERFACE_IPV4_ADDR_ADD:
		case CMD_INTERFACE_IPV4_ADDR_DEL: {
			char addr_name[INET6_ADDRSTRLEN];

			LOG_INIT();
			struct cp_iface_ipv4_addr *cpa;
			cpa = (struct cp_iface_ipv4_addr *)(msg->msg_pkt + 1);
			if (cmd == CMD_INTERFACE_IPV4_ADDR_ADD)
				LOG_ADD(SPACES "ADD_IPV4_ADDR");
			else
				LOG_ADD(SPACES "DEL_IPV4_ADDR");

			inet_ntop (AF_INET, &(cpa->cpiface_addr),
			           addr_name, sizeof(addr_name));
			LOG_ADD(" %s/%d on ", addr_name, (int)cpa->cpiface_pfxlen);
			log_len += prt_ifname (cpa->cpiface_ifuid, i2n, log + log_len);
			LOG_PRINT(LOG_INFO);
			break;
		}
		case CMD_INTERFACE_IPV6_ADDR_ADD:
		case CMD_INTERFACE_IPV6_ADDR_DEL: {
			char addr_name[INET6_ADDRSTRLEN];
			struct cp_iface_ipv6_addr *cpa;

			LOG_INIT();
			cpa = (struct cp_iface_ipv6_addr *)(msg->msg_pkt + 1);
			if (cmd == CMD_INTERFACE_IPV6_ADDR_ADD)
				LOG_ADD(SPACES "ADD_IPV6_ADDR");
			else
				LOG_ADD(SPACES "DEL_IPV6_ADDR");
			inet_ntop (AF_INET6, &(cpa->cpiface_addr),
			           addr_name, sizeof(addr_name));
			LOG_ADD(" %s/%d on ", addr_name, (int)cpa->cpiface_pfxlen);
			log_len += prt_ifname (cpa->cpiface_ifuid, i2n, log + log_len);
			LOG_PRINT(LOG_INFO);
			break;
		}
		case CMD_ARP_UPDATE:
		case CMD_NDP_UPDATE: {
			char addr_name[64];
			struct cp_l2 *cpl;

			LOG_INIT();
			cpl = (struct cp_l2*)(msg->msg_pkt + 1);
			if (cmd == CMD_ARP_UPDATE) {
				inet_ntop (AF_INET, &(cpl->cpl2_ip4addr),
			           addr_name, sizeof(addr_name));
				LOG_ADD(SPACES "ARP %s(",addr_name);
			} else {
				inet_ntop (AF_INET6, &(cpl->cpl2_ip4addr),
			           addr_name, sizeof(addr_name));
				LOG_ADD(SPACES "NDP %s(",addr_name);
			}
			log_len += prt_ifname (cpl->cpl2_ifuid, i2n, log + log_len);
			LOG_ADD(")  --> ");
			switch (cpl->cpl2_state) {
			case CM_L2STATE_NONE:
				LOG_ADD("CM_L2STATE_NONE");
				break;
			case CM_L2STATE_STALE:
				LOG_ADD("CM_L2STATE_STALE");
				break;
			case CM_L2STATE_REACHABLE:
				LOG_ADD("CM_L2STATE_REACHABLE");
				break;
			default:
				LOG_ADD("Unknown State(%d)", cpl->cpl2_state);
			}
			LOG_PRINT(LOG_INFO);
			if (cpl->cpl2_state != CM_L2STATE_NONE) {
				int i;
				LOG_INIT();
				LOG_ADD(SPACES "MAC@=");
				for (i=0; i<6; i++) {
					if (i>0)
						LOG_ADD(":");
					LOG_ADD("%02x", cpl->cpl2_mac[i]);
				}
				LOG_PRINT(LOG_INFO);
			}
			break;
		}
		case CMD_ROUTE4_ADD:
		case CMD_ROUTE4_DEL: {
			char pfx_name[64];
			int pfx_len = 24;
			char gw_name[64];
			struct cp_route4 *cpr;

			LOG_INIT();
			cpr = (struct cp_route4*)(msg->msg_pkt + 1);
			if (cmd == CMD_ROUTE4_ADD)
				LOG_ADD(SPACES "ADD_ROUTE4");
			else
				LOG_ADD(SPACES "DEL_ROUTE4");
			LOG_ADD(" VR#%d", ntohl(cpr->cpr4_vrfid));
			inet_ntop (AF_INET, &(cpr->cpr4_prefix),
			           pfx_name, sizeof(pfx_name));
			/* TBD pfx_len reduction from cpr4_mask */
			pfx_len = __mask2len((u_int8_t *)&cpr->cpr4_mask);
			LOG_ADD(" %s/%d %s ", pfx_name, pfx_len,
				cm_nhtype2str(cpr->cpr4_nhtype));
			switch (cpr->cpr4_nhtype) {
			case NH_TYPE_CONNECTED:
				LOG_ADD("Connected on ");
				log_len += prt_ifname (cpr->cpr4_ifuid, i2n, log + log_len);
				break;
			case NH_TYPE_LOCAL_DELIVERY:
				LOG_ADD("Local Delivery");
				break;
			case NH_TYPE_BLACK_HOLE:
				LOG_ADD("Black-Hole");
				break;
			case NH_TYPE_BASIC: {
				LOG_ADD("via ");
				log_len += prt_ifname (cpr->cpr4_ifuid, i2n, log + log_len);
				if (dump_ext) {
					inet_ntop (AF_INET, &(cpr->cpr4_nexthop),
					           gw_name, sizeof(gw_name));
					LOG_PRINT(LOG_INFO);
					LOG_ADD(SPACES "gateway=%s", gw_name);
				}
				break;
			}
			default:
				LOG_ADD(" Type=%x", cpr->cpr4_nhtype);
				break;
			}
			if (dump_ext) {
				LOG_ADD(" mtu=%d", ntohl(cpr->cpr4_mtu));
			}
			LOG_PRINT(LOG_INFO);
			break;
		}
		case CMD_ROUTE6_ADD:
		case CMD_ROUTE6_DEL: {
			char pfx_name[64];
			char gw_name[64];
			struct cp_route6 *cpr;

			LOG_INIT();
			cpr = (struct cp_route6*)(msg->msg_pkt + 1);
			if (cmd == CMD_ROUTE6_ADD)
				LOG_ADD(SPACES "ADD_ROUTE6");
			else
				LOG_ADD(SPACES "DEL_ROUTE6");
			LOG_ADD(" VR#%d", ntohl(cpr->cpr6_vrfid));
			inet_ntop (AF_INET6, &(cpr->cpr6_prefix),
			           pfx_name, sizeof(pfx_name));
			LOG_ADD(" %s/%d %s ", pfx_name, cpr->cpr6_pfxlen,
					cm_nhtype2str(cpr->cpr6_nhtype));
			switch (cpr->cpr6_nhtype) {
			case NH_TYPE_CONNECTED:
				LOG_ADD("Connected on ");
				log_len += prt_ifname (cpr->cpr6_ifuid, i2n, log + log_len);
				break;
			case NH_TYPE_LOCAL_DELIVERY:
				LOG_ADD("Local Delivery");
				break;
			case NH_TYPE_BLACK_HOLE:
				LOG_ADD("Black-Hole");
				break;
			case NH_TYPE_BASIC: {
				LOG_ADD("via ");
				log_len += prt_ifname (cpr->cpr6_ifuid, i2n, log + log_len);
				if (dump_ext) {
					inet_ntop (AF_INET6, &(cpr->cpr6_nexthop),
					           gw_name, sizeof(gw_name));
					LOG_PRINT(LOG_INFO);
					LOG_ADD(SPACES "gateway=%s ", gw_name);
				}
				break;
			}
			default:
				LOG_ADD(" Type=%x", cpr->cpr6_nhtype);
				break;
			}
			if (dump_ext) {
				LOG_ADD("mtu=%d", ntohl(cpr->cpr6_mtu));
			}
			LOG_PRINT(LOG_INFO);
			break;
		}
		case CMD_MCAST_ADD_MFC:{
			struct cp_mfc_add * ma;
                        char grp_name[INET6_ADDRSTRLEN];
                        char src_name[INET6_ADDRSTRLEN];
			char ifname[IFNAMSIZ];
			u_int32_t in_if;
			u_int32_t oif;

			LOG_INIT();
			ma = (struct cp_mfc_add*)(msg->msg_pkt + 1);

			LOG_ADD(SPACES "MCAST_ADD_MFC");
			inet_ntop (ma->cpmfc_family, &(ma->cpmfc_group),
				grp_name, sizeof(grp_name));
			inet_ntop (ma->cpmfc_family, &(ma->cpmfc_source),
				src_name, sizeof(src_name));

			LOG_ADD(" %s from %s", grp_name, src_name);

			in_if = ma->cpmfc_iif ;
			if_indextoname( in_if, ifname );
			LOG_ADD(" in ifindex = ");
			log_len += prt_ifname(ma->cpmfc_iif, i2n, log + log_len);
			LOG_ADD(" oifs = ");
			for (oif = 0; oif < CM_MAXMIFS && ma->cpmfc_oif[oif]; oif++)
				log_len += prt_ifname(ma->cpmfc_oif[oif], i2n, log + log_len);
			LOG_PRINT(LOG_INFO);
			break;
		}
		case CMD_MCAST_DEL_MFC:{
			struct cp_mfc_delete * md;
                        char grp_name[INET6_ADDRSTRLEN];
                        char src_name[INET6_ADDRSTRLEN];

			LOG_INIT();
			LOG_ADD(SPACES "MCAST_DEL_MFC");

			md = (struct cp_mfc_delete*)(msg->msg_pkt + 1);

			if ( md->cpmfc_family == AF_INET ) {
				inet_ntop (AF_INET, &(md->cpmfc_grp4),
					   grp_name, sizeof(grp_name));
				inet_ntop (AF_INET, &(md->cpmfc_src4),
					   src_name, sizeof(src_name));

				LOG_ADD(" %s from %s", grp_name, src_name );

			} else {
				inet_ntop (AF_INET6, &(md->cpmfc_grp6),
					   grp_name, sizeof(grp_name));
				inet_ntop (AF_INET6, &(md->cpmfc_src6),
					   src_name, sizeof(src_name));

				LOG_ADD(" %s from %s", grp_name, src_name );

			}
			LOG_PRINT(LOG_INFO);
			break;
		}

		case CMD_IPSEC_SA_CREATE:
		{
			struct cp_ipsec_sa_add *sa;
			char daddr[INET6_ADDRSTRLEN];
			char saddr[INET6_ADDRSTRLEN];
			int keyoff = 0;

			LOG_INIT();
			sa = (struct cp_ipsec_sa_add *)(msg->msg_pkt + 1);

			saddr[0] = daddr[0] = 0;
			inet_ntop(sa->family, &sa->daddr, daddr, sizeof(daddr));
			inet_ntop(sa->family, &sa->saddr, saddr, sizeof(saddr));

			LOG_ADD(SPACES "IPSEC_SA_CREATE ");
			LOG_ADD("proto=%s spi=0x%08x dst=%s src=%s",
					sa->proto == IPPROTO_AH ? "ah" : "esp",
					(unsigned int)ntohl(sa->spi), daddr, saddr);
			LOG_PRINT(LOG_INFO);

			LOG_ADD(SPACES "VR#%d XVR#%d reqid=%u mode=%s replay=%d flags=%08x",
					ntohl(sa->vrfid), ntohl(sa->xvrfid), (unsigned int)ntohl(sa->reqid),
					sa->mode ? "tunnel" : "transport", sa->replay,
					sa->flags);

			LOG_PRINT(LOG_INFO);
			if (sa->output_blade)
				LOG_ADD(SPACES "output_blade=%u",
						(unsigned int)sa->output_blade);
			LOG_PRINT(LOG_INFO);

			LOG_ADD(SPACES "ealg=%s(%u) aalg=%s(%u)",
					cm_ipsec_ealg2str(sa->ealgo), sa->ealgo,
					cm_ipsec_aalg2str(sa->aalgo), sa->aalgo);
			LOG_PRINT(LOG_INFO);

			LOG_ADD(SPACES "ekeylen=%u akeylen=%u",
					(unsigned int)ntohs(sa->ekeylen),
					(unsigned int)ntohs(sa->akeylen));
			LOG_PRINT(LOG_INFO);

			if (sa->ekeylen) {
				hexdump(&sa->keys[keyoff], ntohs(sa->ekeylen),
					16, SPACES "ekey>");
				keyoff += CM_ALIGNUNIT8(ntohs(sa->ekeylen));
				LOG_PRINT(LOG_INFO);
			}

			if (sa->akeylen) {
				hexdump(&sa->keys[keyoff], ntohs(sa->akeylen),
						16, SPACES "akey>");
				LOG_PRINT(LOG_INFO);
			}

			break;
		}

		case CMD_IPSEC_SA_DELETE:
		{
			struct cp_ipsec_sa_del *sa;
			char daddr[INET6_ADDRSTRLEN];

			sa = (struct cp_ipsec_sa_del *)(msg->msg_pkt + 1);

			daddr[0] = 0;
			inet_ntop(sa->family, &sa->daddr, daddr, sizeof(daddr));

			syslog(LOG_INFO, SPACES "IPSEC_SA_DELETE VR#%d proto=%s spi=0x%08x dst=%s",
				ntohl(sa->vrfid), sa->proto == IPPROTO_AH ? "ah" : "esp",
				(unsigned int)ntohl(sa->spi), daddr);

			break;
		}

		case CMD_IPSEC_SA_LIFETIME:
		{
			struct cp_ipsec_sa_lifetime *sa;
			char daddr[INET6_ADDRSTRLEN];

			sa = (struct cp_ipsec_sa_lifetime *)(msg->msg_pkt + 1);

			daddr[0] = 0;
			inet_ntop(sa->family, &sa->daddr, daddr, sizeof(daddr));

			/* Display SA lifetime limits */
			syslog(LOG_INFO, SPACES "IPSEC_SA_LIFETIME VR#%d proto=%s spi=0x%08x dst=%s",
			       ntohl(sa->vrfid), sa->proto == IPPROTO_AH ? "ah" : "esp",
			       (unsigned int)ntohl(sa->spi), daddr);
			syslog(LOG_INFO, SPACES " soft : bytes=%"PRIu64" packets=%"PRIu64,
			       ntohll(sa->soft.nb_bytes), ntohll(sa->soft.nb_packets));
			syslog(LOG_INFO, SPACES " hard : bytes=%"PRIu64" packets=%"PRIu64,
			       ntohll(sa->hard.nb_bytes), ntohll(sa->hard.nb_packets));
			break;
		}

		case CMD_IPSEC_SP_CREATE:
		case CMD_IPSEC_SP_DELETE:
		case CMD_IPSEC_SP_UPDATE:
		/* common part between CMD_IPSEC_SP_CREATE and CMD_IPSEC_SP_DELETE */
		{
			struct cp_ipsec_sp_add *sp;
			char saddr[INET6_ADDRSTRLEN];
			char daddr[INET6_ADDRSTRLEN];
			char *action;
			int i;

			LOG_INIT();
			if (cmd == CMD_IPSEC_SP_CREATE)
				LOG_ADD(SPACES "IPSEC_SP_CREATE ");
			else if (cmd == CMD_IPSEC_SP_DELETE)
				LOG_ADD(SPACES "IPSEC_SP_DELETE ");
			else
				LOG_ADD(SPACES "IPSEC_SP_UPDATE ");
			sp = (struct cp_ipsec_sp_add *)(msg->msg_pkt + 1);

			if (sp->svti_ifuid)
				LOG_ADD("svti_ifuid=0x%08x", ntohl(sp->svti_ifuid));
			LOG_PRINT(LOG_INFO);

			saddr[0] = daddr[0] = 0;
			inet_ntop(sp->family, &sp->saddr, saddr, sizeof(saddr));
			inet_ntop(sp->family, &sp->daddr, daddr, sizeof(daddr));
			LOG_ADD(SPACES " src=%s/%d sport=%hu/%hu", saddr, sp->spfxlen,
					ntohs(sp->sport), ntohs(sp->sportmask));
			LOG_PRINT(LOG_INFO);
			LOG_ADD(SPACES " dst=%s/%d dport=%hu/%hu", daddr, sp->dpfxlen,
					ntohs(sp->dport), ntohs(sp->dportmask));
			LOG_PRINT(LOG_INFO);
			LOG_ADD(SPACES " VR#%d link_VR#%d proto=%u dir=%s priority=%u",
					ntohl(sp->vrfid), ntohl(sp->link_vrfid),
					sp->proto, (sp->dir == CM_IPSEC_DIR_OUTBOUND) ? "out" : "in",
					(unsigned int)ntohl(sp->priority));
			LOG_PRINT(LOG_INFO);
			LOG_ADD(SPACES " index=0x%08x", ntohl(sp->index));
			LOG_PRINT(LOG_INFO);

			if (cmd == CMD_IPSEC_SP_DELETE)
				break;

			LOG_ADD(" flags=0x%08x", ntohl(sp->flags));
			LOG_PRINT(LOG_INFO);

			switch (sp->action) {
			case CM_IPSEC_ACTION_CLEAR:
				action = "clear";
				break;
			case CM_IPSEC_ACTION_DISCARD:
				action = "discard";
				break;
			case CM_IPSEC_ACTION_IPSEC:
				action = "ipsec";
				break;
			default:
				action = "<invalid>";
				break;
			}
			LOG_ADD(SPACES " action=%s", action);
			LOG_PRINT(LOG_INFO);

			for (i = 0; i < sp->xfrm_count; i++)
			{
				struct cp_ipsec_xfrm *xfrm;
				char *proto;

				xfrm = &sp->xfrm[i];
				switch (xfrm->proto) {
				case IPPROTO_ESP:
					proto = "esp";
					break;
				case IPPROTO_AH:
					proto = "ah";
					break;
				default:
					proto = "unknown proto";
					action = "<invalid>";
					break;
				}

				LOG_ADD(" %s %s", proto, xfrm->mode ? "tunnel" : "transport");

				if (xfrm->spi)
					LOG_ADD(" spi=%08x", ntohl(xfrm->spi));

				if (xfrm->reqid)
					LOG_ADD(" reqid=%08x", ntohl(xfrm->reqid));

				LOG_PRINT(LOG_INFO);

				if (xfrm->family) {
					saddr[0] = daddr[0] = 0;
					inet_ntop(xfrm->family, &xfrm->saddr, saddr,
						sizeof(saddr));
					inet_ntop(xfrm->family, &xfrm->daddr, daddr,
						sizeof(daddr));

					LOG_ADD(SPACES "  src=%s", saddr);
					LOG_PRINT(LOG_INFO);
					LOG_ADD(SPACES "  dst=%s", daddr);
					LOG_PRINT(LOG_INFO);
				}
			}
		}
		break;

		case CMD_BLADE_FPIB_IF_SET:
		{
			struct cp_blade_fpib *fpib;

			LOG_INIT();
			fpib = (struct cp_blade_fpib *)(msg->msg_pkt + 1);

			LOG_ADD(SPACES "BLADE_FPIB_IF_SET interface=");
			log_len += prt_ifname (fpib->fpib_ifuid, i2n, log + log_len);
			LOG_ADD(",");
			log_len += prt_ifname (fpib->fpib_ifuid, NULL, log + log_len);
			LOG_PRINT(LOG_INFO);
		}
		break;

		case CMD_VNB_MSGHDR: {
#define MAX_PATH_FOR_DUMP 128
			struct cp_vnb_msghdr *vnb;
			char path[MAX_PATH_FOR_DUMP];
			char *dst;
			int pos, len;

			LOG_INIT();
			vnb = (struct cp_vnb_msghdr *)(msg->msg_pkt + 1);
			pos = htons(vnb->vnbh_arglen);
			len = htons(vnb->vnbh_pathlen);
			LOG_ADD(SPACES "VNB_MSGHDR cookie=%d cmd=%d, arglen=%d, pathlen=%d",
					htonl (vnb->vnbh_typecookie),
					htonl (vnb->vnbh_cmd), pos, len);
			LOG_PRINT(LOG_INFO);
			dst = (char *)(vnb + 1);
			dst += pos;
			strncpy (path, dst, MAX_PATH_FOR_DUMP-1);
			if (len < MAX_PATH_FOR_DUMP)
				path[len] = 0;
			else
				path[MAX_PATH_FOR_DUMP-1]=0;
			LOG_ADD(SPACES "path=<<%s>>", path);
			LOG_PRINT(LOG_INFO);
		}
		break;

		default:
			break;
		} /* switch(cmd) */
		} /* dump_main */
	} /* dump_hdr */
	if (dump_hex)
		hexdump(msg->msg_pkt, msg->msg_len, 16, SPACES);

	if (str)
		syslog(LOG_INFO, "%s", str);
#undef LOG_INIT
#undef LOG_ADD
#undef LOG_PRINT
}

const char *
cm_command2str(u_int32_t cmd)
{
	static char unknown[] = "CMD_[XXXXXXXX]";
	char * str;

	switch(cmd) {

        _PF(CMD_RESET)
        _PF(CMD_FLUSH)
        _PF(CMD_GRACEFUL_RESTART)
        _PF(CMD_IF_CREATE)
        _PF(CMD_IF_DELETE)
        _PF(CMD_IF_MTU)
        _PF(CMD_IF_STATE_UPDATE)
        _PF(CMD_IF_MAC)
        _PF(CMD_IF_BLADEINFO)
        _PF(CMD_IF_ADDR)
        _PF(CMD_INTERFACE_IPV4_ADDR_ADD)
        _PF(CMD_INTERFACE_IPV4_ADDR_DEL)
        _PF(CMD_INTERFACE_IPV6_ADDR_ADD)
        _PF(CMD_INTERFACE_IPV6_ADDR_DEL)
        _PF(CMD_TUN_TTL)
        _PF(CMD_TUN_TOS)
        _PF(CMD_ROUTE4_ADD)
        _PF(CMD_ROUTE4_DEL)
        _PF(CMD_ROUTE4_CHG)
        _PF(CMD_ROUTE6_ADD)
        _PF(CMD_ROUTE6_DEL)
        _PF(CMD_ARP_UPDATE)
        _PF(CMD_NDP_UPDATE)
        _PF(CMD_XIN4_CREATE)
        _PF(CMD_XIN4_DELETE)
        _PF(CMD_XIN4_UPDATE)
        _PF(CMD_XIN6_CREATE)
        _PF(CMD_XIN6_DELETE)
        _PF(CMD_XIN6_UPDATE)
        _PF(CMD_SVTI_CREATE)
        _PF(CMD_SVTI_DELETE)
        _PF(CMD_MCAST_ADD_MFC)
        _PF(CMD_MCAST_DEL_MFC)
        _PF(CMD_NF_UPDATE)
        _PF(CMD_NF_CTADD)
        _PF(CMD_NF_CTDELETE)
        _PF(CMD_NF_CTFLUSH)
        _PF(CMD_NF6_UPDATE)
        _PF(CMD_NF6_CTADD)
        _PF(CMD_NF6_CTDELETE)
        _PF(CMD_NF_CPE_DELETE)
        _PF(CMD_IPSEC_SA_CREATE)
        _PF(CMD_IPSEC_SA_DELETE)
        _PF(CMD_IPSEC_SA_FLUSH)
        _PF(CMD_IPSEC_SA_MIGRATE)
        _PF(CMD_IPSEC_SA_BULK_MIGRATE)
        _PF(CMD_IPSEC_SA_LIFETIME)
        _PF(CMD_IPSEC_SP_CREATE)
        _PF(CMD_IPSEC_SP_DELETE)
        _PF(CMD_IPSEC_SP_FLUSH)
        _PF(CMD_IPSEC_SP_UPDATE)
        _PF(CMD_VNB_MSGHDR)
        _PF(CMD_VNB_ASCIIMSG)
        _PF(CMD_BLADE_CREATE)
        _PF(CMD_BLADE_DELETE)
        _PF(CMD_BLADE_FPIB_IF_SET)
        _PF(CMD_BLADE_FPIB_IF_UNSET)
        _PF(CMD_BPF_CREATE)

	default:
		sprintf(unknown, "CMD_[%08x]", cmd);
		str = unknown;
		break;
	}

	return(str);
}

const char *
cm_iftype2str(u_int32_t type)
{
	static char dflt[] = "CM_IFTYPE_[DDDDDDDDDD]";
	char * str;

	switch(type) {
	_PF(CM_IFTYPE_ETH)
	_PF(CM_IFTYPE_LOOP)
	_PF(CM_IFTYPE_LOCAL)
	_PF(CM_IFTYPE_6IN4)
	_PF(CM_IFTYPE_PORT)
	_PF(CM_IFTYPE_SVTI)
	_PF(CM_IFTYPE_BRPORT)
	_PF(CM_IFTYPE_GRE)

	default:
		snprintf(dflt, sizeof(dflt), "CM_IFTYPE_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}

const char *
cm_ifsubtype2str(u_int32_t type)
{
	static char dflt[] = "CM_IFSUBTYPE_[DDDDDDDDDD]";
	char * str;

	switch(type) {
	_PF(CM_IFSUBTYPE_NORMAL)
	_PF(CM_IFSUBTYPE_NGEIFACE)
	_PF(CM_IFSUBTYPE_XVRF)
	_PF(CM_IFSUBTYPE_BRIDGE)

	default:
		snprintf(dflt, sizeof(dflt), "CM_IFSUBTYPE_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}

const char *
cm_nhtype2str(u_int32_t type)
{
	static char dflt[] = "NH_TYPE_[DDDDDDDDDD]";
	char * str;

	switch(type) {

	_PF(NH_TYPE_BASIC)
	_PF(NH_TYPE_CONNECTED)
	_PF(NH_TYPE_LOCAL_DELIVERY)
	_PF(NH_TYPE_BLACK_HOLE)

	default:
		snprintf(dflt, sizeof(dflt), "NH_TYPE_[%u]", type);
		str = dflt;
		break;
	}

	return(str);
}


const char *
cm_ipsec_aalg2str(u_int8_t alg)
{
	static char unknown[] = "CM_IPSEC_AALG_[DDD]";
	char * str;

	switch(alg) {
	_PF(CM_IPSEC_AALG_NONE)
	_PF(CM_IPSEC_AALG_MD5HMAC)
	_PF(CM_IPSEC_AALG_SHA1HMAC)
	_PF(CM_IPSEC_AALG_SHA2_256HMAC)
	_PF(CM_IPSEC_AALG_SHA2_384HMAC)
	_PF(CM_IPSEC_AALG_SHA2_512HMAC)
	_PF(CM_IPSEC_AALG_RIPEMD160HMAC)
	_PF(CM_IPSEC_AALG_AES_XCBC_MAC)

	default:
		sprintf(unknown, "CM_IPSEC_AALG_[%u]", alg);
		str = unknown;
		break;
	}

	return str;
}

const char *
cm_ipsec_ealg2str(u_int8_t alg)
{
	static char unknown[] = "CM_IPSEC_EALG_[DDD]";
	char * str;

	switch(alg) {
	_PF(CM_IPSEC_EALG_NONE)
	_PF(CM_IPSEC_EALG_DESCBC)
	_PF(CM_IPSEC_EALG_3DESCBC)
	_PF(CM_IPSEC_EALG_CASTCBC)
	_PF(CM_IPSEC_EALG_BLOWFISHCBC)
	_PF(CM_IPSEC_EALG_AESCBC)
	_PF(CM_IPSEC_EALG_AESGCM)
	_PF(CM_IPSEC_EALG_NULL_AESGMAC)
	_PF(CM_IPSEC_EALG_SERPENTCBC)
	_PF(CM_IPSEC_EALG_TWOFISHCBC)

	default:
		sprintf(unknown, "CM_IPSEC_EALG_[%u]", alg);
		str = unknown;
		break;
	}

	return str;
}

