/**
 * Generic Netlink interface for Cache Manager
 */

/*-
   * Copyright (c) <2011>, 6WIND
   * All rights reserved.
   */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <stdint.h>

#ifdef NETLINK_GENERIC

#include <net/if.h>

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include "fpc.h"
#include "cm_dump.h"
#include "cm_priv.h"
#include "cm_sock.h"
#include "genl_base.h"

/**
 * Fill in a genl_family struct, knowing only the name
 *
 * @param fam
 *   A pointer to a struct genl_family, with field name already filed-in
 *   This struct will be filled by this function
 * @return
 *   0 on success, -1 otherwise
 */
int
cm_genl_get_family(struct genl_family *fam)
{
	struct nl_sock *sk;
	int ret = -1;

	sk = nl_socket_alloc();
	if (!sk)
		goto end;
	if (nl_connect(sk, NETLINK_GENERIC) < 0)
		goto end;
	if ((ret = genl_ctrl_resolve(sk, fam->name)) < 0)
		goto end;
	fam->id = ret;
	if ((ret = genl_ctrl_resolve_grp(sk, fam->name, fam->grp.name)) < 0)
		goto end;
	fam->grp.id = ret;
	ret = 0;
end:
	nl_socket_free(sk);
	return ret;
}

void
cm_genl_init(struct nlsock *cmn, const char* name, const char* group)
{
	cmn->genl_fam = malloc(sizeof(*cmn->genl_fam));
	if (!cmn->genl_fam) {
		syslog(LOG_ERR, "%s: Could not allocate genl_fam\n",
			__func__);
		cmn->init_failed = 1;
		return;
	}

	snprintf(cmn->genl_fam->name, GENL_NAMSIZ, "%s", name);
	snprintf(cmn->genl_fam->grp.name, GENL_NAMSIZ, "%s", group);
	if (cm_genl_get_family(cmn->genl_fam)) {
		syslog(LOG_ERR, "%s: Could not get family info\n",
			__func__);
		cmn->init_failed = 1;
		return;
	}

	cm_netlink_sock(NETLINK_GENERIC, cmn, 0, 1, CM_BULK_READ, NULL, 0);

	if (!cmn->sk) {
		cmn->init_failed = 1;
		return;
	}

	/* subscribe to group */
	nl_socket_add_membership(cmn->sk, cmn->genl_fam->grp.id);
}

void
cm_genl_destroy(struct nlsock *cmn)
{
	if (cmn->genl_fam) {
		free(cmn->genl_fam);
		cmn->genl_fam = NULL;
	}
	cm_close_netlink_sock (cmn, 1);
}
#endif /* NETLINK_GENERIC */

