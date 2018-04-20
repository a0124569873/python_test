/*
 * Copyright 2014 6WIND S.A.
 */

#ifndef __FastPath__
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#endif

#include <ifuid.h>

#include "shmem/fpn-shmem.h"

#include "fp.h"
#include "fpdebug.h"
#include "fpdebug-priv.h"

#include "fp-gre-var.h"

FPN_DEFINE_SHARED(fp_gre_shared_mem_t *, fp_gre_shared);

/* GRE header size is between 4 and 20 regarding configuration of the GRE tunnel.
 * Use worst case for interface creation through the CLI.
 */
#define GRE_HEADER_OVERHEAD 20

#define IP_IS_ANY(addr)					\
	(!strncmp(addr, "0.0.0.0", strlen(addr)) ||	\
	!strncmp(addr, "::", strlen(addr)))

struct fp_gre_flaginfo {
	uint16_t flag;
	char *name;
} gre_flags[] = {
	{ FP_GRE_FLAG_CSUM, "csum" },
	{ FP_GRE_FLAG_KEY, "key" },
	{ 0, NULL },
};

static void gre_print_flags(uint16_t flags, uint8_t flags_dir)
{
	int i;

	if (flags_dir == 0)
		fpdebug_printf(" oflags:");
	else
		fpdebug_printf("    iflags:");

	for (i = 0; gre_flags[i].name != NULL; i++)
		if (flags & gre_flags[i].flag)
			fpdebug_printf(" %s", gre_flags[i].name);
}

static int gre_parse_ipv4(char *word, struct in_addr *addr)
{
	if (!strncmp(word, "any", 3))
		fpdebug_inet_pton(AF_INET, "0.0.0.0", addr);
	else if (fpdebug_inet_pton(AF_INET, word, addr) != 1)
			return -1;

	return 0;
}

#ifdef CONFIG_MCORE_IPV6
static int gre_parse_ipv6(char *word, struct fp_in6_addr *addr)
{
	if (!strncmp(word, "any", 3))
		fpdebug_inet_pton(AF_INET6, "::", addr);
	else if (fpdebug_inet_pton(AF_INET6, word, addr) != 1)
			return -1;

	return 0;
}
#endif

static int gre_dump_one(fp_ifgre_t *gre)
{
	char laddr[INET6_ADDRSTRLEN];
	char raddr[INET6_ADDRSTRLEN];
	const char *link_name = fp_ifuid2str(gre->link_ifuid);
	fp_ifnet_t *ifgre;

	ifgre = fp_ifuid2ifnet(gre->ifuid);

	fpdebug_inet_ntop(gre->family, (void *)&gre->local, laddr,
			  (gre->family == AF_INET) ? INET_ADDRSTRLEN :
						     INET6_ADDRSTRLEN);
	fpdebug_inet_ntop(gre->family, (void *)&gre->remote, raddr,
			  (gre->family == AF_INET) ? INET_ADDRSTRLEN :
						     INET6_ADDRSTRLEN);

	if (IP_IS_ANY(laddr))
		strcpy(laddr, "any");

	if (IP_IS_ANY(raddr))
		strcpy(raddr, "any");

	fpdebug_printf("%s linked to %s vrfid: %"PRIu16" link vrfid: %"PRIu16"\n",
		       ifgre->if_name, link_name[0] ? link_name : "none",
		       ifgre->if_vrfid, gre->link_vrfid);

	if (gre->mode == FP_GRE_MODE_IP)
		fpdebug_printf("    mode IP\n");
	else if (gre->mode == FP_GRE_MODE_ETHER)
		fpdebug_printf("    mode Ether\n");
	else
		fpdebug_printf("    mode unknown (0x%"PRIu8")\n", gre->mode);

	fpdebug_printf("    local: %s remote: %s\n", laddr, raddr);

	if (gre->ttl == 0)
		fpdebug_printf("    ttl: inherit");
	else
		fpdebug_printf("    ttl: %"PRIu8"", gre->ttl);

	if (gre->inh_tos)
		fpdebug_printf(" tos: inherit\n");
	else
		fpdebug_printf(" tos: 0x%02x\n", gre->tos);

	gre_print_flags(gre->iflags, 1);
	gre_print_flags(gre->oflags, 0);
	fpdebug_printf("\n");

	if (gre->iflags & FP_GRE_FLAG_KEY)
		fpdebug_printf("    ikey: 0x%08"PRIx32" (%"PRIu32")\n", ntohl(gre->ikey),
			       ntohl(gre->ikey));

	if (gre->oflags & FP_GRE_FLAG_KEY)
		fpdebug_printf("    okey: 0x%08"PRIx32" (%"PRIu32")\n", ntohl(gre->okey),
			       ntohl(gre->okey));

	return 0;
}

#define FPDEBUG_GRE_DUMP_USAGE		\
	"\n\tgre-dump [name IFNAME]"
static int gre_dump(char *tok)
{
	fp_ifnet_t *ifgre;
	int i = 0;
	char *word;
	int argc;

	argc = gettokens(tok);

	if (argc != 0 && argc != 2) {
		FPDEBUG_PARAM_ERR("gre-dump: arguments error.",
				  FPDEBUG_GRE_DUMP_USAGE);
		return -1;
	}

	if (argc == 2) {
		word = chargv[i++];

		if (strcmp(word, "name") == 0) {
			word = chargv[i++];
			ifgre = fp_getifnetbyname(word);

			if (!ifgre || !ifgre->if_ifuid) {
				fpdebug_printf("gre-dump: %s unknown interface.\n", word);
				return -1;
			}

			if ((ifgre->if_type != FP_IFTYPE_GRE) &&
			    (ifgre->if_type != FP_IFTYPE_GRETAP) ) {
				fpdebug_printf("gre-dump: %s is not a GRE interface.\n", word);
				return -1;
			}

			if (ifgre->if_type == FP_IFTYPE_GRE)
				i = (uint32_t)(uintptr_t)fp_ifnet_ops_get_data(ifgre, IP_OUTPUT_OPS);
			else
				i = (uint32_t)(uintptr_t)fp_ifnet_ops_get_data(ifgre, TX_DEV_OPS);

			return gre_dump_one(&fp_gre_shared->if_gre[i]);
		} else {
			FPDEBUG_PARAM_ERR("gre-dump: %s unknown parameter.",
					  FPDEBUG_GRE_DUMP_USAGE, word);
			return -1;
		}
	}

	for (i = 1; i < FP_GRE_MAX; i++)
		if (fp_gre_shared->if_gre[i].ifuid != 0)
			gre_dump_one(&fp_gre_shared->if_gre[i]);

	return 0;
}

#define FPDEBUG_GRE_IFACE_ADD_USAGE						\
	"\n\tgre-iface-add IFNAME IP_VERSION MODE LOCAL_ADDR REMOTE_ADDR\n"\
	"\t\t[vr VRFID] [[i|o]key KEY] [[i|o]csum] [ttl TTL] [tos TOS]\n"	\
	"\t\t[link LINK_IFNAME] [link-vrf VRFID]\n\n"				\
	"\tIP_VERSION := { 4 | 6 }\n"						\
	"\tMODE := { IP | Ether }\n"						\
	"\tLOCAL_ADDR & REMOTE_ADDR := { IP_ADDRESS | any }\n"			\
	"\tTOS := { 0x00..0xff | inherit }\n"					\
	"\tTTL := { 0..255  | inherit }\n"
static int gre_iface_add(char *tok)
{
	struct in_addr local;
	struct in_addr remote;
#ifdef CONFIG_MCORE_IPV6
	struct fp_in6_addr local6;
	struct fp_in6_addr remote6;
#endif
	void *local_addr;
	void *remote_addr;
	uint16_t vrfid = default_vrfid;
	uint16_t link_vrfid = default_vrfid;
	uint32_t link_ifuid = 0;
	uint32_t ifuid = 0;
	int ip_v = AF_INET;
	uint32_t mtu = 1500;
	uint32_t gre_overhead = GRE_HEADER_OVERHEAD;
	uint8_t inh_tos = 0;
	uint16_t iflags = 0;
	uint16_t oflags = 0;
	uint8_t mode = FP_GRE_MODE_UNKNOWN;
	uint32_t ikey = 0;
	uint32_t okey = 0;
	uint8_t tos = 0;
	uint8_t ttl = 0;
	fp_ifnet_t *ifp;
	char *end = NULL;
	char ifname[16];
	char link_ifname[16];
	int ind = 0;
	int res = 0;
	char *word = NULL;
	int argc;

	argc = gettokens(tok);

	if (argc < 5) {
		FPDEBUG_PARAM_ERR("gre-iface-add: too few arguments.",
				  FPDEBUG_GRE_IFACE_ADD_USAGE);
		return -1;
	}

	/* iface name */
	strncpy(ifname, chargv[ind++], sizeof(ifname));

	/* IP version */
	word = chargv[ind++];
	if (!strcmp(word, "4")) {
		ip_v = AF_INET;
		gre_overhead += 20;
	} else if (!strcmp(word, "6")) {
#ifdef CONFIG_MCORE_IPV6
		ip_v = AF_INET6;
		gre_overhead += 40;
#else
		fpdebug_printf("gre-iface-add: IPv6 is not supported (CONFIG_MCORE_IPV6 is not set).");
		return -1;
#endif
	} else {
		FPDEBUG_PARAM_ERR("gre-iface-add: unknown IP version.",
				  FPDEBUG_GRE_IFACE_ADD_USAGE);
		return -1;
	}

	/* Mode */
	word = chargv[ind++];
	if (!strcmp(word, "IP"))
		mode = FP_GRE_MODE_IP;
	else if (!strcasecmp(word, "Ether")) {
		mode = FP_GRE_MODE_ETHER;
		gre_overhead += 14;
	} else {
		FPDEBUG_PARAM_ERR("gre-iface-add: unknown mode.",
				  FPDEBUG_GRE_IFACE_ADD_USAGE);
		return -1;
	}

	/* local address */
	word = chargv[ind++];
	if (ip_v == AF_INET) {
		res = gre_parse_ipv4(word, &local);
		local_addr = &local.s_addr;
#ifdef CONFIG_MCORE_IPV6
	} else {
		res = gre_parse_ipv6(word, &local6);
		local_addr = &local6;
#endif
	}

	if (res) {
		FPDEBUG_PARAM_ERR("gre-iface-add: %s: invalid local address.",
				  FPDEBUG_GRE_IFACE_ADD_USAGE, word);
		return res;
	}

	/* remote address */
	word = chargv[ind++];
	if (ip_v == AF_INET) {
		res = gre_parse_ipv4(word, &remote);
		remote_addr = &remote.s_addr;
#ifdef CONFIG_MCORE_IPV6
	} else {
		res = gre_parse_ipv6(word, &remote6);
		remote_addr = &remote6;
#endif
	}

	if (res) {
		FPDEBUG_PARAM_ERR("gre-iface-add: %s: invalid remote address.",
				  FPDEBUG_GRE_IFACE_ADD_USAGE, word);
		return res;
	}

	while (ind < argc) {
		word = chargv[ind++];

		/* VRFID */
		if (strcmp(word, "vr") == 0) {
			word = chargv[ind++];
			vrfid = (uint16_t)strtoul(word, &end, 0);
			if ((vrfid & FP_VRFID_MASK) >= FP_MAX_VR) {
				fpdebug_printf("gre-iface-add: %s vrfid too high, max is %d.\n",
					       word, FP_MAX_VR);
				return -1;
			}

			continue;
		}

		/* key */
		if (strcmp(word, "key") == 0) {
			word = chargv[ind++];

			if ((iflags & FP_GRE_FLAG_KEY) || (oflags & FP_GRE_FLAG_KEY)) {
				fpdebug_printf("gre-iface-add: key %s ignord (already ikey %u or okey %u).\n",
					       word, ikey, okey);
				continue;
			}

			ikey = (uint32_t)strtoul(word, &end, 0);
			okey = ikey;
			iflags |= FP_GRE_FLAG_KEY;
			oflags |= FP_GRE_FLAG_KEY;

			continue;
		}

		/* input key */
		if (strcmp(word, "ikey") == 0) {
			word = chargv[ind++];

			if (iflags & FP_GRE_FLAG_KEY) {
				fpdebug_printf("gre-iface-add: ikey %s ignord (already ikey added %u).\n",
					       word, ikey);
				continue;
			}

			ikey = (uint32_t)strtoul(word, &end, 0);
			iflags |= FP_GRE_FLAG_KEY;

			continue;
		}

		/* output key */
		if (strcmp(word, "okey") == 0) {
			word = chargv[ind++];

			if (oflags & FP_GRE_FLAG_KEY) {
				fpdebug_printf("gre-iface-add: okey %s ignord (already okey added %u).\n",
					       word, okey);
				continue;
			}

			okey = (uint32_t)strtoul(word, &end, 0);
			oflags |= FP_GRE_FLAG_KEY;

			continue;
		}

		/* check-sum */
		if (strcmp(word, "csum") == 0) {
			iflags |= FP_GRE_FLAG_CSUM;
			oflags |= FP_GRE_FLAG_CSUM;

			continue;
		}

		/* input check-sum */
		if (strcmp(word, "icsum") == 0) {
			iflags |= FP_GRE_FLAG_CSUM;
			continue;
		}

		/* output check-sum */
		if (strcmp(word, "ocsum") == 0) {
			oflags |= FP_GRE_FLAG_CSUM;
			continue;
		}

		/* ttl */
		if (strcmp(word, "ttl") == 0) {
			word = chargv[ind++];

			if (strcmp(word, "inherit") == 0)
				ttl = 0;
			else
				ttl = (uint8_t)strtoul(word, &end, 0);

			continue;
		}

		/* tos
		 * this parameter is ignored for GRE IPv6 iface
		 */
		if (strcmp(word, "tos") == 0) {
			if (ip_v == AF_INET6)
				continue;

			word = chargv[ind++];

			if (strcmp(word, "inherit") != 0) {
				tos = (uint8_t)strtoul(word, &end, 0);
				inh_tos = tos & 1;

				if (inh_tos)
					tos = 0;
			}

			continue;
		}

		/* link ifname */
		if (strcmp(word, "link") == 0) {
			strncpy(link_ifname, chargv[ind++], 16);
			ifp = fp_getifnetbyname(link_ifname);

			if (ifp == NULL) {
				fpdebug_printf("gre-iface-add: %s unknown interface\n", link_ifname);
				return -1;
			}
			mtu = ifp->if_mtu;
			link_ifuid = ifp->if_ifuid;

			continue;
		}

		/* link vrfid */
		if (strcmp(word, "link-vrf") == 0) {
			word = chargv[ind++];
			link_vrfid = (uint16_t)strtoul(word, &end, 0);

			if ((link_vrfid & FP_VRFID_MASK) >= FP_MAX_VR) {
				fpdebug_printf("gre-iface-add: %s link vrfid too high, max is %d",
					       word, FP_MAX_VR);
				return -1;
			}

			continue;
		}

		FPDEBUG_PARAM_ERR("gre-iface-add: unknown parameter %s.",
				  FPDEBUG_GRE_IFACE_ADD_USAGE, word);
	}

	ifuid = ifname2ifuid(ifname, vrfid & FP_VRFID_MASK);

	if (mtu < (gre_overhead + 68)) {
		fpdebug_printf("gre-iface-add: mtu of the link interface is too small (%"PRIu32"), must be greater than %"PRIu32" for this gre configuration\n",
			       mtu, (gre_overhead + 68));
		return -1;
	}

	mtu -= gre_overhead;

	if (mode == FP_GRE_MODE_IP)
		res = fp_interface_add(vrfid & FP_VRFID_MASK, ifname,
				       NULL, mtu, ifuid, 0, FP_IFNET_VIRTUAL_PORT,
				       FP_IFTYPE_GRE, 0);
	else
		res = fp_interface_add(vrfid & FP_VRFID_MASK, ifname,
				       NULL, mtu, ifuid, 0, FP_IFNET_VIRTUAL_PORT,
				       FP_IFTYPE_GRETAP, 0);


	if (res == FP_ADDIFNET_ERROR) {
		fpdebug_printf("\ngre-iface-add: fail to add the ifnet.\n");
		return res;
	}
	if (res == FP_ADDIFNET_EXIST) {
		fpdebug_printf("\ngre-iface-add: ifnet exists.\n");
		return res;
	}

	res = fp_addifnet_greinfo(ifuid, link_ifuid, iflags, oflags,
				  mode, htonl(ikey),
				  htonl(okey), ttl, tos, inh_tos, ip_v,
				  local_addr, remote_addr, link_vrfid);

	if (res < 0) {
		fp_interface_del(ifuid, 0, 0);
		fpdebug_printf("gre-iface-add: fail to configure GRE ifnet.\n");
		return res;
	}

	return res;
}

#define FPDEBUG_GRE_IFACE_DEL_USAGE		\
	"\n\tgre-iface-del IFNAME\n"
static int gre_iface_del(char *tok)
{
	fp_ifnet_t *ifgre;
	char ifname[16];
	uint32_t ifuid;
	int res = -1;
	int ind = 0;
	int argc;

	argc = gettokens(tok);
	if (argc < 1) {
		FPDEBUG_PARAM_ERR("gre-iface-del: too few arguments.",
				  FPDEBUG_GRE_IFACE_DEL_USAGE);
		return -1;
	}

	/* iface name */
	strncpy(ifname, chargv[ind++], 16);

	ifgre = fp_getifnetbyname(ifname);
	if (ifgre == NULL) {
		fpdebug_printf("gre-iface-del: %s unknown interface.\n", ifname);
		return -1;
	}

	ifuid = ifgre->if_ifuid;

	if (ifgre->if_type == FP_IFTYPE_GRE) {
		if ((res = fp_delifnet_greinfo(ifuid))) {
			fpdebug_printf("gre-iface-del: GRE %s deletion failed.\n",
			               ifname);
			return res;
		}
	} else if (ifgre->if_type == FP_IFTYPE_GRETAP) {
		if ((res = fp_delifnet_gretapinfo(ifuid))) {
			fpdebug_printf("gre-iface-del: GRE %s deletion failed.\n",
			               ifname);
			return res;
		}
	} else {
		fpdebug_printf("gre-iface-del: %s is not a GRE interface.\n",
		               ifname);
		return -1;
	}

	if ((res = fp_interface_del(ifuid, 0, 0))) {
		fpdebug_printf("gre-iface-del: GRE %s deletion failed.\n", ifname);
		return res;
	}

	return res;
}

static CLI_COMMAND gre_cmds[] = {
	{ "gre-dump", gre_dump,
	  "dump GRE interfaces: " FPDEBUG_GRE_DUMP_USAGE
	},
	{ "gre-iface-add", gre_iface_add,
	  "add GRE interfaces: " FPDEBUG_GRE_IFACE_ADD_USAGE
	},
	{ "gre-iface-del", gre_iface_del,
	  "del GRE interfaces: " FPDEBUG_GRE_IFACE_DEL_USAGE
	},
	{ NULL, NULL, NULL },
};

static cli_cmds_t gre_cli = {
	.module = "gre",
	.c = gre_cmds,
};

static void fpdebug_gre_init(void)__attribute__((constructor));
void fpdebug_gre_init(void)
{
	fp_gre_shared = fpn_shmem_mmap(FP_GRE_SHARED, NULL,
				       sizeof(fp_gre_shared_mem_t));
	if (fp_gre_shared == NULL) {
		fpdebug_printf("Could not open GRE shared memory.\n");
		return;
	}
	fpdebug_add_commands(&gre_cli);
}
