/*
 * Copyright (c) 2006 6WIND
 * $Id: inroute.c,v 1.36 2010-02-16 16:38:40 guerin Exp $
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslog.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "fpm_common.h"
#include "fpm_plugin.h"
#include "fpm_vrf.h"
#include "fp.h"
#include "rt_dump.h"

#ifdef CONFIG_MCORE_IP
static uint8_t
__mask2len (uint8_t *msk)
{
	uint8_t len=0;
	int i;

	for (i=0; i<4; i++) {
		switch(msk[i]) {
			case 0xff:      /* 1111 1111 */
				len += 8;
				break;
			case 0xfe:      /* 1111 1110 */
				len += 7;
				goto end;
			case 0xfc:      /* 1111 1100 */
				len += 6;
				goto end;
			case 0xf8:      /* 1111 1000 */
				len += 5;
				goto end;
			case 0xf0:      /* 1111 0000 */
				len += 4;
				goto end;
			case 0xe0:      /* 1110 0000 */
				len += 3;
				goto end;
			case 0xc0:      /* 1100 0000 */
				len += 2;
				goto end;
			case 0x80:      /* 1000 0000 */
				len += 1;
				goto end;
			case 0x00:      /* 0000 0000 */
				goto end;
			default:        /* bad mask => count first bits set to 1 */
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
fpm_route4_add(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_route4 *req = (const struct cp_route4 *)request;
	uint8_t pfx_len = __mask2len((uint8_t *)&req->cpr4_mask);
	uint8_t rt_type;
	fp_nh_mark_t nh_mark = {0, 0};
	uint32_t ifuid, vrfid;
	int res;

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_route4_add: %u.%u.%u.%u/%d via if 0x%08x vrf %d\n",
		       FP_NIPQUAD(req->cpr4_prefix.s_addr), pfx_len,
		       ntohl(req->cpr4_ifuid), ntohl(req->cpr4_vrfid));

	ifuid = req->cpr4_ifuid;
	vrfid = ntohl(req->cpr4_vrfid) & FP_VRFID_MASK;
	if (vrfid >= FP_MAX_VR)
		return EXIT_FAILURE;


#ifdef CONFIG_MCORE_NEXTHOP_MARKING
	nh_mark.mark = ntohl(req->cpr4_nh_mark.mark);
	nh_mark.mask = ntohl(req->cpr4_nh_mark.mask);
#endif
	/* connected routes are often set to local delivery */
	switch(req->cpr4_nhtype) {
	case NH_TYPE_CONNECTED:
		rt_type = RT_TYPE_ROUTE_CONNECTED;
		break;
	case NH_TYPE_LOCAL_DELIVERY:
		rt_type = RT_TYPE_ROUTE_LOCAL;
		break;
	case NH_TYPE_BLACK_HOLE:
		rt_type = RT_TYPE_ROUTE_BLACKHOLE;
		break;

	case NH_TYPE_BASIC:
		if (ifuid == 0) {
			syslog(LOG_ERR, "fpm_route4_add: ifuid is 0\n");
			return EXIT_FAILURE;
		}
		rt_type = RT_TYPE_ROUTE;
		break;
	default:
		syslog(LOG_ERR, "fpm_route4_add: unknown NH type %d\n", 
		       req->cpr4_nhtype);
		return EXIT_FAILURE;
	}

	res = fp_add_route4_nhmark(vrfid, req->cpr4_prefix.s_addr, pfx_len, 
			req->cpr4_nexthop.s_addr, ifuid, rt_type, &nh_mark);

	if (res) {
		syslog(LOG_ERR, "fpm_route4_add: failed\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int
fpm_route4_del(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_route4 *req = (const struct cp_route4 *)request;
	int pfx_len = __mask2len((u_int8_t *)&req->cpr4_mask);
	uint8_t rt_type;
	fp_nh_mark_t nh_mark = {0, 0};
	uint32_t ifuid, vrfid;

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_route4_del: %u.%u.%u.%u/%d via if 0x%08x \n",
		       FP_NIPQUAD(req->cpr4_prefix.s_addr), pfx_len,
		       ntohl(req->cpr4_ifuid));

	ifuid = req->cpr4_ifuid;
	vrfid = ntohl(req->cpr4_vrfid) & FP_VRFID_MASK;
	if (vrfid >= FP_MAX_VR)
		return EXIT_FAILURE;

#ifdef CONFIG_MCORE_NEXTHOP_MARKING
	nh_mark.mark = ntohl(req->cpr4_nh_mark.mark);
	nh_mark.mask = ntohl(req->cpr4_nh_mark.mask);
#endif
	switch(req->cpr4_nhtype) {
	case NH_TYPE_CONNECTED:
		rt_type = RT_TYPE_ROUTE_CONNECTED;
		break;
	case NH_TYPE_LOCAL_DELIVERY:
		rt_type = RT_TYPE_ROUTE_LOCAL;
		break;
	case NH_TYPE_BLACK_HOLE:
		rt_type = RT_TYPE_ROUTE_BLACKHOLE;
		break;

	case NH_TYPE_BASIC:
		if (ifuid == 0)
			syslog(LOG_DEBUG, "fpm_route4_del: index is 0\n");
		rt_type = RT_TYPE_ROUTE;
		break;

	default:
		syslog(LOG_ERR, "fpm_route4_del: unknown NH type %d\n", 
		       req->cpr4_nhtype);
		return EXIT_FAILURE;
	}

	fp_delete_route4_nhmark(vrfid, req->cpr4_prefix.s_addr, pfx_len, 
	                req->cpr4_nexthop.s_addr, ifuid, rt_type, &nh_mark);

	return EXIT_SUCCESS;
}

static int
fpm_route4_chg(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_route4 *req = (const struct cp_route4 *)request;
	int pfx_len = __mask2len((u_int8_t *)&req->cpr4_mask);
	uint8_t rt_type;
	fp_nh_mark_t nh_mark = {0, 0};
	uint32_t ifuid, vrfid;

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_route4_chg: %u.%u.%u.%u/%d via if 0x%08x \n",
		       FP_NIPQUAD(req->cpr4_prefix.s_addr), pfx_len,
		       ntohl(req->cpr4_ifuid));

	ifuid = req->cpr4_ifuid;
	vrfid = ntohl(req->cpr4_vrfid) & FP_VRFID_MASK;
	if (vrfid >= FP_MAX_VR)
		return EXIT_FAILURE;

#ifdef CONFIG_MCORE_NEXTHOP_MARKING
	nh_mark.mark = ntohl(req->cpr4_nh_mark.mark);
	nh_mark.mask = ntohl(req->cpr4_nh_mark.mask);
#endif
	switch(req->cpr4_nhtype) {
	case NH_TYPE_CONNECTED:
		rt_type = RT_TYPE_ROUTE_CONNECTED;
		break;
	case NH_TYPE_LOCAL_DELIVERY:
		rt_type = RT_TYPE_ROUTE_LOCAL;
		break;
	case NH_TYPE_BLACK_HOLE:
		rt_type = RT_TYPE_ROUTE_BLACKHOLE;
		break;

	case NH_TYPE_BASIC:
		if (ifuid == 0)
			syslog(LOG_DEBUG, "fpm_route4_chg: index is 0\n");
		rt_type = RT_TYPE_ROUTE;
		break;

	default:
		syslog(LOG_ERR, "fpm_route4_chg: unknown NH type %d\n", 
		       req->cpr4_nhtype);
		return EXIT_FAILURE;
	}

	if (fp_change_route4_nhmark(vrfid, req->cpr4_prefix.s_addr, pfx_len, 
		req->cpr4_nexthop.s_addr, ifuid, rt_type, &nh_mark)) {
		syslog(LOG_ERR, "fpm_route4_chg: route change failed\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int fp_ipv4_default_rules(uint16_t vrfid, uint32_t ifuid, int del)
{
	unsigned int i;

	struct {
		char *name;
		uint32_t prefix;
		uint8_t prefixlen;
		uint8_t  type;
	} rules[] = {
		{
			.name = "Route 0.0.0.0/32 type local delivery",
			.prefix = 0,
			.prefixlen = 32,
			.type = RT_TYPE_ROUTE_LOCAL,
		},
		{
			.name = "Route 255.255.255.255/32 type local delivery",
			.prefix = 0xFFFFFFFF,
			.prefixlen = 32,
			.type = RT_TYPE_ROUTE_LOCAL,
		},
		{
			.name = "Route 224.0.0.0/4 type local delivery",
			.prefix = htonl(224u << 24),
			.prefixlen = 4,
			.type = RT_TYPE_ROUTE_LOCAL,
		},
		{
			.name = "Route 127.0.0.0/8 type black hole",
			.prefix = htonl(127 << 24),
			.prefixlen = 8,
			.type = RT_TYPE_ROUTE_BLACKHOLE,
		}
	};

	for (i = 0; i < sizeof(rules)/sizeof(rules[0]); i++) {
		if (del) {
			fp_delete_route4_nhmark(vrfid, rules[i].prefix,
						rules[i].prefixlen, 0,
						ifuid, rules[i].type, NULL);
			continue;
		}
		fp_add_route4(vrfid, rules[i].prefix, rules[i].prefixlen, 0,
					      ifuid, rules[i].type);
		/*
		 * In case of graceful restart, emulates the CM
		 * commands. This will prevent route suppression
		 * at the end of grace time
		 */
		if (fpm_cmd_match_gr_type(FPM_CMD_ROUTE,
			  fpm_graceful_restart_in_progress)) {
			fpm_add_v4_route_cmd(ifuid, rules[i].prefix,
				 rules[i].prefixlen, 0, rules[i].type, vrfid,
				 FPM_GR_CP_LIST);
		}
	}
	return 0;
}

/*
 * The same core is used for enqueuing route commands from shared memory
 * dump (start_queue = 1), and for commands received from cache manager
 */
int fpm_add_v4_route_cmd(uint32_t ifuid, uint32_t address, int prefixlen,
                         uint32_t nexthop, uint8_t rt_type, uint32_t vrfid,
                         int list)
{
	struct cp_route4 req;
	uint32_t mask = plen2mask(prefixlen);

	/* Clear memory */
	memset(&req, 0, sizeof(req));

	req.cpr4_vrfid = htonl(vrfid);
	if (rt_type == RT_TYPE_ROUTE_CONNECTED) {
		req.cpr4_nhtype = NH_TYPE_CONNECTED;
		req.cpr4_ifuid = ifuid;
	/*
	 * The local and blackhole next-hop are special, they
	 * are shared whatever the ifuid/VR is. As ifuid wil not
	 * be used, better store a clean 0.
	 */
	} else if (rt_type == RT_TYPE_ROUTE_LOCAL) {
		req.cpr4_nhtype = NH_TYPE_LOCAL_DELIVERY;
		req.cpr4_ifuid = 0;
	} else if (rt_type == RT_TYPE_ROUTE_BLACKHOLE) {
		req.cpr4_nhtype = NH_TYPE_BLACK_HOLE;
		req.cpr4_ifuid = 0;
	} else {
		req.cpr4_nhtype = NH_TYPE_BASIC;
		req.cpr4_ifuid = ifuid;
	}
	memcpy(&req.cpr4_prefix, &address, sizeof(uint32_t));
	memcpy(&req.cpr4_mask, &mask, sizeof(uint32_t));
	memcpy(&req.cpr4_nexthop, &nexthop, sizeof(uint32_t));

	return fpm_cmd_create_and_enqueue(list, CMD_ROUTE4_ADD, &req);
}
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
static int fpm_route6_add(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_route6 *req = (const struct cp_route6 *)request;
	uint8_t pfx_len = req->cpr6_pfxlen;
	uint8_t rt_type;
	fp_nh_mark_t nh_mark = {0, 0};
	uint32_t ifuid, vrfid;
	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_route6_add: %x:%x:%x:%x:%x:%x:%x:%x/%d via if 0x%08x vrf %d\n",
		       NIPOCT(req->cpr6_prefix.s6_addr16), pfx_len,
		       ntohl(req->cpr6_ifuid), ntohl(req->cpr6_vrfid));

	ifuid = req->cpr6_ifuid;
	vrfid = ntohl(req->cpr6_vrfid) & FP_VRFID_MASK;
	if (vrfid >= FP_MAX_VR)
		return EXIT_FAILURE;

#ifdef CONFIG_MCORE_NEXTHOP_MARKING
	nh_mark.mark = ntohl(req->cpr6_nh_mark.mark);
	nh_mark.mask = ntohl(req->cpr6_nh_mark.mask);
#endif

	/* connected routes are set to local delivery */
	switch(req->cpr6_nhtype) {
	case NH_TYPE_CONNECTED:
		rt_type = RT_TYPE_ROUTE_CONNECTED;
		break;
	case NH_TYPE_LOCAL_DELIVERY:
		rt_type = RT_TYPE_ROUTE_LOCAL;
		break;
	case NH_TYPE_BLACK_HOLE:
		rt_type = RT_TYPE_ROUTE_BLACKHOLE;
		break;

	case NH_TYPE_BASIC:
		if (ifuid == 0) {
			syslog(LOG_ERR, "fpm_route6_add: ifuid is 0\n");
			return EXIT_FAILURE;
		}
		rt_type = RT_TYPE_ROUTE;
		break;
	default:
		syslog(LOG_ERR, "fpm_route6_add: unknown NH type %d\n", 
		       req->cpr6_nhtype);
		return EXIT_FAILURE;
	}

	fp_add_route6_nhmark(vrfid, (fp_in6_addr_t *)&req->cpr6_prefix, pfx_len, 
			(fp_in6_addr_t *)&req->cpr6_nexthop, ifuid, rt_type, &nh_mark);

	return EXIT_SUCCESS;
}


static int fpm_route6_del(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_route6 *req = (const struct cp_route6 *)request;
	uint8_t pfx_len = req->cpr6_pfxlen;
	uint8_t rt_type;
	fp_nh_mark_t nh_mark = {0, 0};
	uint32_t ifuid, vrfid;

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_route6_del: %x:%x:%x:%x:%x:%x:%x:%x/%d via if 0x%08x vrf %d\n",
		       NIPOCT(req->cpr6_prefix.s6_addr16), pfx_len,
		       ntohl(req->cpr6_ifuid), ntohl(req->cpr6_vrfid));

	ifuid = req->cpr6_ifuid;
	vrfid = ntohl(req->cpr6_vrfid) & FP_VRFID_MASK;
	if (vrfid >= FP_MAX_VR)
		return EXIT_FAILURE;

#ifdef CONFIG_MCORE_NEXTHOP_MARKING
	nh_mark.mark = ntohl(req->cpr6_nh_mark.mark);
	nh_mark.mask = ntohl(req->cpr6_nh_mark.mask);
#endif

	/* connected routes are set to local delivery */
	switch(req->cpr6_nhtype) {
	case NH_TYPE_CONNECTED:
		rt_type = RT_TYPE_ROUTE_CONNECTED;
		break;
	case NH_TYPE_LOCAL_DELIVERY:
		rt_type = RT_TYPE_ROUTE_LOCAL;
		break;
	case NH_TYPE_BLACK_HOLE:
		rt_type = RT_TYPE_ROUTE_BLACKHOLE;
		break;

	case NH_TYPE_BASIC:
		if (ifuid == 0)
			syslog(LOG_DEBUG, "fpm_route6_del: ifuid is 0\n");
		rt_type = RT_TYPE_ROUTE;
		break;

	default:
		syslog(LOG_ERR, "fpm_route6_del: unknown NH type %d\n", 
		       req->cpr6_nhtype);
		return EXIT_FAILURE;
	}

	fp_delete_route6_nhmark(vrfid, (fp_in6_addr_t *)&req->cpr6_prefix, pfx_len, 
	                (fp_in6_addr_t *)&req->cpr6_nexthop, ifuid, rt_type, &nh_mark);

	return EXIT_SUCCESS;
}

int fp_ipv6_default_rules(uint16_t vrfid, uint32_t ifuid, int del)
{
	unsigned int i;
	fp_in6_addr_t nul_gw;
	struct {
		char *name;
		uint32_t prefix[4];
		uint8_t prefixlen;
		uint8_t  type;
	} rules[] = {
		{
			/* Link local */
			.name = "Route fe80::/10 type local delivery",
			.prefix = {htonl(0xfe800000), 0, 0, 0},
			.prefixlen = 10,
			.type = RT_TYPE_ROUTE_LOCAL
		},
		{
			/* Mcast */
			.name = "Route ff00::/8 type local delivery",
			.prefix = {htonl(0xff000000), 0, 0, 0},
			.prefixlen = 8,
			.type = RT_TYPE_ROUTE_LOCAL
		},
		{
			/* IANA reserved */
			.name = "Route ::/80 type blackhole",
			.prefix = {0, 0, 0, 0},
			.prefixlen = 80,
			.type = RT_TYPE_ROUTE_BLACKHOLE
		}
	};
	bzero(&nul_gw, sizeof(nul_gw));

	for (i = 0; i < sizeof(rules)/sizeof(rules[0]); i++) {
		if (del) {
			fp_delete_route6_nhmark(vrfid,
			                    (fp_in6_addr_t*)rules[i].prefix,
			                    rules[i].prefixlen, &nul_gw,
					    ifuid, rules[i].type, NULL);
			continue;
		}
		fp_add_route6_nhmark(vrfid, (fp_in6_addr_t *)(rules[i].prefix),
		                           rules[i].prefixlen, &nul_gw, ifuid,
		                           rules[i].type, NULL);
		/*
		 * In case of graceful restart, emulates the CM
		 * commands. This will prevent route suppression
		 * at the end of grace time
		 */
		if (fpm_cmd_match_gr_type(FPM_CMD_ROUTE,
			  fpm_graceful_restart_in_progress)) {
			fpm_add_v6_route_cmd(ifuid,
			                    (fp_in6_addr_t*)rules[i].prefix,
			                    rules[i].prefixlen, &nul_gw,
			                    rules[i].type, vrfid, FPM_GR_CP_LIST);
		}
	}
	return 0;
}

/*
 * The same core is used for enqueuing route commands from shared memory
 * dump (start_queue = 1), and for commands received from cache manager
 */
int fpm_add_v6_route_cmd(uint32_t ifuid, fp_in6_addr_t *address,
                         int prefixlen, fp_in6_addr_t *nexthop,
                         uint8_t rt_type, uint32_t vrfid, int list)
{
	struct cp_route6 req;

	/* Clear memory */
	memset(&req, 0, sizeof(req));

	req.cpr6_vrfid = htonl(vrfid);
	if (rt_type == RT_TYPE_ROUTE_CONNECTED) {
		req.cpr6_nhtype = NH_TYPE_CONNECTED;
		req.cpr6_ifuid = ifuid;
	} else
	/*
	 * The local and blackhole next-hop are special, they
	 * are shared whatever the ifuid/VR is. As ifuid wil not
	 * be used, better store a clean 0.
	 */
	if (rt_type == RT_TYPE_ROUTE_LOCAL) {
		req.cpr6_nhtype = NH_TYPE_LOCAL_DELIVERY;
		req.cpr6_ifuid = 0;
	}
	else if (rt_type == RT_TYPE_ROUTE_BLACKHOLE) {
		req.cpr6_nhtype = NH_TYPE_BLACK_HOLE;
		req.cpr6_ifuid = 0;
	}
	else {
		req.cpr6_nhtype = NH_TYPE_BASIC;
		req.cpr6_ifuid = ifuid;
	}

	req.cpr6_pfxlen = prefixlen;
	memcpy(&req.cpr6_prefix, address, sizeof(req.cpr6_prefix));
	memcpy(&req.cpr6_nexthop, nexthop, sizeof(req.cpr6_nexthop));

	return fpm_cmd_create_and_enqueue(list, CMD_ROUTE6_ADD, &req);
}
#endif /* CONFIG_MCORE_IPV6 */

#ifdef CONFIG_MCORE_IP
static struct fpm_vrf_handler vrf_hdlr = {
	.name = "inroute",
	.del = fp_route_flush_per_vrf,
};
#endif

#ifdef CONFIG_MCORE_IP
static int fpm_route4_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_route4 *route1 = cmd1->data;
	struct cp_route4 *route2 = cmd2->data;

	if ((route1->cpr4_vrfid == route2->cpr4_vrfid) &&
	    (route1->cpr4_nhtype == route2->cpr4_nhtype) &&
	    /* No check on ifuid for LOCAL_DELIVERY or BLACK_HOLE */
	    ((route1->cpr4_ifuid == route2->cpr4_ifuid) ||
	     (route1->cpr4_nhtype == NH_TYPE_LOCAL_DELIVERY) ||
	     (route1->cpr4_nhtype == NH_TYPE_BLACK_HOLE)) &&
	    !memcmp(&route1->cpr4_prefix, &route2->cpr4_prefix, sizeof(route1->cpr4_prefix)) &&
	    !memcmp(&route1->cpr4_mask, &route2->cpr4_mask, sizeof(route1->cpr4_mask)) &&
	    !memcmp(&route1->cpr4_nexthop, &route2->cpr4_nexthop, sizeof(route1->cpr4_nexthop))) {
		return 0;
	}

	return 1;
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_route4_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_ROUTE4_DEL);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}

static void fpm_route4_display(const fpm_cmd_t *fpm_cmd,
                               char *buffer, int len)
{
	struct cp_route4 *data = fpm_cmd->data;
	char addr_str[INET_ADDRSTRLEN];
	char mask_str[INET_ADDRSTRLEN];
	char nh_str[INET_ADDRSTRLEN];

	snprintf(buffer, len, "CMD_ROUTE4 - VR#%d, %s/%s via %s ifuid 0x%08x\n",
 	   ntohl(data->cpr4_vrfid),
	   inet_ntop(AF_INET, &data->cpr4_prefix, addr_str, sizeof(addr_str)),
	   inet_ntop(AF_INET, &data->cpr4_mask, mask_str, sizeof(mask_str)),
	   inet_ntop(AF_INET, &data->cpr4_nexthop, nh_str, sizeof(nh_str)),
	   ntohl(data->cpr4_ifuid));
}

static fpm_cmd_t *fpm_route4_graceful(int gr_type, uint32_t cmd,
                                      const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_ROUTE, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_route4));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_ROUTE;
	fpm_cmd->comp    = fpm_route4_comp;
	fpm_cmd->revert  = fpm_route4_revert;
	fpm_cmd->display = fpm_route4_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
static int fpm_route6_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_route6* route1 = cmd1->data;
	struct cp_route6* route2 = cmd2->data;

	if ((route1->cpr6_vrfid == route2->cpr6_vrfid) &&
	    (route1->cpr6_nhtype == route2->cpr6_nhtype) &&
	    /* No check on ifuid for LOCAL_DELIVERY or BLACK_HOLE */
	    ((route1->cpr6_ifuid == route2->cpr6_ifuid) ||
	     (route1->cpr6_nhtype == NH_TYPE_LOCAL_DELIVERY) ||
	     (route1->cpr6_nhtype == NH_TYPE_BLACK_HOLE)) &&
	    (route1->cpr6_pfxlen == route2->cpr6_pfxlen) &&
	    !memcmp(&route1->cpr6_prefix, &route2->cpr6_prefix, sizeof(route1->cpr6_prefix)) &&
	    !memcmp(&route1->cpr6_nexthop, &route2->cpr6_nexthop, sizeof(route1->cpr6_nexthop))) {
		return 0;
	}
	return 1;
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_route6_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_ROUTE6_DEL);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}

static void fpm_route6_display(const fpm_cmd_t *fpm_cmd,
                               char *buffer, int len)
{
	struct cp_route6 *data = fpm_cmd->data;
	char addr_str[INET6_ADDRSTRLEN];
	char nh_str[INET6_ADDRSTRLEN];

	snprintf(buffer, len, "CMD_ROUTE6 - VR#%d, %s/%u %s ifuid 0x%08x\n",
	   ntohl(data->cpr6_vrfid),
	   inet_ntop(AF_INET6, &data->cpr6_prefix, addr_str, sizeof(addr_str)),
	   (unsigned)data->cpr6_pfxlen,
	   inet_ntop(AF_INET6, &data->cpr6_nexthop, nh_str, sizeof(nh_str)),
	   ntohl(data->cpr6_ifuid));
}

static fpm_cmd_t *fpm_route6_graceful(int gr_type, uint32_t cmd,
                                      const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_ROUTE, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_route6));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_ROUTE;
	fpm_cmd->comp    = fpm_route6_comp;
	fpm_cmd->revert  = fpm_route6_revert;
	fpm_cmd->display = fpm_route6_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}
#endif /* CONFIG_MCORE_IPV6 */

static int fpm_inroute_shared_cmd(int gr_type, enum list_type list)
{
	int ret = 0;
	(void) list;

#ifdef CONFIG_MCORE_IP
	/* Dump IPv4 routes if needed */
	if (fpm_cmd_match_gr_type(FPM_CMD_ROUTE, gr_type)) {
		ret |= fpm_rt4_entries_to_cmd(fp_shared->fp_rt4_table);
	}
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
	/* Dump IPv6 routes if needed */
	if (fpm_cmd_match_gr_type(FPM_CMD_ROUTE, gr_type)) {
		ret |= fpm_rt6_entries_to_cmd(fp_shared->fp_rt6_table);
	}
#endif /* CONFIG_MCORE_IPV6 */

	return ret;
}

static void fpm_inroute_init(__attribute__((unused)) int graceful)
{
#ifdef CONFIG_MCORE_IP
	fpm_vrf_register(&vrf_hdlr);
	fpm_register_msg(CMD_ROUTE4_ADD, fpm_route4_add, fpm_route4_graceful);
	fpm_register_msg(CMD_ROUTE4_DEL, fpm_route4_del, NULL);
	fpm_register_msg(CMD_ROUTE4_CHG, fpm_route4_chg, NULL);
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
	fpm_register_msg(CMD_ROUTE6_ADD, fpm_route6_add, fpm_route6_graceful);
	fpm_register_msg(CMD_ROUTE6_DEL, fpm_route6_del, NULL);
#endif /* CONFIG_MCORE_IPV6 */
}

static struct fpm_mod fpm_inroute_mod = {
	.name = "inroute",
	.init = fpm_inroute_init,
	.shared_cmd = fpm_inroute_shared_cmd,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_inroute_mod);
}
