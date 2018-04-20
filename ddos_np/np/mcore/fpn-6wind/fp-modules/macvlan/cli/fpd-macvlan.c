/*
 * Copyright 2014 6WIND S.A.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <stddef.h>
#include <ifuid.h>
#include "fp.h"

#include "shmem/fpn-shmem.h"
#include "fpdebug.h"
#include "fpdebug-ifnet.h"
#include "fpdebug-priv.h"

#include "fp-macvlan-lookup.h"

FPN_DEFINE_SHARED(fp_macvlan_shared_mem_t *, fp_macvlan_shared);

static void macvlan_getmode_str(char* mode_str, uint32_t mode)
{
	if (mode == FP_MACVLAN_MODE_PRIVATE) 
		strcpy(mode_str,"private");
	else if (mode == FP_MACVLAN_MODE_PASSTHRU)  
		strcpy(mode_str,"passthru");
	else 
		strcpy(mode_str,"unknown");
}

static int macvlan_dump(char *tok)
{
	fp_macvlan_linkiface_t *vlinkiface;
	uint32_t link_idx, idx;
	char mode_str[10];
	uint32_t ifuid;
	uint32_t mode;

	fpdebug_printf("Macvlan interfaces:\n");
	for (link_idx=1; link_idx<FP_MACVLAN_LINKIFACE_MAX; link_idx++) {
		vlinkiface = fp_macvlan_linkidx2linkiface(link_idx);

		if (vlinkiface->link_ifuid != 0) {
			fpdebug_printf("%s: ifuid: 0x%"PRIx32"\n",
				       fp_ifuid2str(vlinkiface->link_ifuid),
				       ntohl(vlinkiface->link_ifuid));

			for (idx=0; idx<FP_MACVLAN_IFACE_MAX; idx++) {
				ifuid = vlinkiface->macvlan_iface[idx].ifuid;
				if (ifuid != 0) {
					mode = vlinkiface->macvlan_iface[idx].mode;
					macvlan_getmode_str(mode_str,mode);
					fpdebug_printf("\t%s: ifuid: 0x%"PRIx32
						       " mode: %s\n",
						       fp_ifuid2str(ifuid),
						       ntohl(ifuid),
						       mode_str);
				}
			}
		}
	}
	
	return 0;
}

#define MACVLAN_IFACE_ADD_USAGE 					\
	"Add a macvlan interface:\n"					\
	"\tmacvlan-iface-add IFNAME MAC_ADDR MODE LINK_IFNAME\n"	\
	"\t MODE := {private|passthru}\n"

static int macvlan_iface_add(char *tok)
{
	uint32_t mtu;
	uint32_t ifuid;
	fp_ifnet_t *link_ifp;
	char ifname[16];
	uint8_t macaddr[6];
	int count, rc = -1, ind = 0;
	char *word = NULL;
	uint32_t mode;

	count = gettokens(tok);
	if (count < 4) {
		FPDEBUG_PARAM_ERR("macvlan-iface-add: too few arguments\n",
				  MACVLAN_IFACE_ADD_USAGE);
		goto end;
	}

	/* IFNAME */
	strncpy(ifname, chargv[ind++], 16);
	ifuid = ifname2ifuid(ifname, default_vrfid);

	/* MAC_ADDR */
	word = chargv[ind++];
	if (string2mac(word, macaddr) == 0) {
		FPDEBUG_PARAM_ERR("macvlan-iface-add: invalid MAC address (%s)\n",
			          MACVLAN_IFACE_ADD_USAGE,word);
		goto end;
	}

	/* MODE */
	word = chargv[ind++];
	if (strcmp(word,"private") == 0) {
		mode = FP_MACVLAN_MODE_PRIVATE;
	} else if (strcmp(word,"passthru") == 0) {
		mode = FP_MACVLAN_MODE_PASSTHRU;
	} else {
		FPDEBUG_PARAM_ERR("macvlan-iface-add: invalid mode (%s)\n",
				  MACVLAN_IFACE_ADD_USAGE,word);
		goto end;
	}

	/* LINK_IFNAME */
	word = chargv[ind++];
	if ((link_ifp = fp_getifnetbyname(word)) == NULL) {
		FPDEBUG_PARAM_ERR("macvlan-iface-add: bad interface name: %s\n", 
			          MACVLAN_IFACE_ADD_USAGE,word);
		goto end;
	}
	mtu = link_ifp->if_mtu;

	rc = fp_interface_add(default_vrfid, ifname, macaddr, mtu,
			      ifuid, 0, FP_IFNET_VIRTUAL_PORT, 
			      FP_IFTYPE_MACVLAN, 0);
	if (rc == FP_ADDIFNET_ERROR) {
		fpdebug_printf("macvlan-iface-add: fail to add the ifnet\n");
		goto end;
	} else if (rc == FP_ADDIFNET_EXIST) {
		fpdebug_printf("macvlan-iface-add: ifnet exists\n");
		goto end;
	}

	rc = fp_addifnet_macvlaninfo(ifuid, link_ifp->if_ifuid, mode);

end:
	return rc;
}

#define MACVLAN_IFACE_DEL_USAGE 		\
	"Del a macvlan interface:\n" 		\
	"\tmacvlan-iface-del IFNAME\n"

static int macvlan_iface_del(char *tok)
{
	char *word;
	int count, ind = 0;
	fp_ifnet_t *ifp;

	count = gettokens(tok);
	if (count < 1) {
		FPDEBUG_PARAM_ERR("macvlan-iface-del: too few arguments",
				  MACVLAN_IFACE_DEL_USAGE);
		goto end;
	}

	/* IFNAME */
	word = chargv[ind++];
	if ((ifp = fp_getifnetbyname(word)) == NULL) {
		FPDEBUG_PARAM_ERR("macvlan-iface-del: bad interface name: %s", 
			       MACVLAN_IFACE_DEL_USAGE,word);
		goto end;
	}

	if (ifp->if_type != FP_IFTYPE_MACVLAN) {
		FPDEBUG_PARAM_ERR("macvlan-iface-del: not macvlan interface: %s", 
			       MACVLAN_IFACE_DEL_USAGE,word);
		goto end;
	}

	fp_delifnet_macvlaninfo(ifp->if_ifuid);
	fp_interface_del(ifp->if_ifuid, 0, 0);

	return 0;
end:
	return -1;
}

static CLI_COMMAND macvlan_cmds[] = {
	{"macvlan-dump", macvlan_dump, "Dump vlan interface infos"},
	{"macvlan-iface-add", macvlan_iface_add, MACVLAN_IFACE_ADD_USAGE},
	{"macvlan-iface-del", macvlan_iface_del, MACVLAN_IFACE_DEL_USAGE},
	{ NULL, NULL, NULL },
};
static cli_cmds_t macvlan_cli = {
	.module = "macvlan",
	.c = macvlan_cmds,
};

static int dump_macvlan_ifnet_info(fp_ifnet_t *ifp)
{
	fp_macvlan_linkiface_t *vlinkiface;
	fp_macvlan_iface_t *viface;
	uint32_t mode,link_idx,idx;
	fp_ifnet_t *link_ifp;
	char mode_str[10];

	if (ifp->if_type != FP_IFTYPE_MACVLAN)
		return 0;

	idx = ifp->sub_table_index;
	link_idx = (uint32_t)(uintptr_t)fp_ifnet_ops_get_data(ifp, TX_DEV_OPS);
	vlinkiface = fp_macvlan_linkidx2linkiface(link_idx);
	viface = fp_macvlan_idxs2iface(link_idx,idx);

	link_ifp = fp_ifuid2ifnet(vlinkiface->link_ifuid);
	mode = viface->mode;
	macvlan_getmode_str(mode_str,mode);
	if (link_ifp)
		fpdebug_printf("\tmode %s, link %s\n",
			       mode_str, link_ifp->if_name);
	else
		fpdebug_printf("\tmode %s\n", mode_str);

	return 0;
}

static fpdebug_ifnet_info_t macvlan_ifnet_info = { .func = dump_macvlan_ifnet_info };

static void init(void) __attribute__((constructor));

void init(void)
{
	fp_macvlan_shared = fpn_shmem_mmap(FP_MACVLAN_SHARED, NULL, 
					   sizeof(fp_macvlan_shared_mem_t));
	if (fp_macvlan_shared == NULL) {
		fpdebug_printf("Could not open macvlan shared memory\n");
		return;
	}

	fpdebug_add_commands(&macvlan_cli);
	fpdebug_add_ifnet_info(&macvlan_ifnet_info);
}
