/**
 * Generic Netlink interface for Cache Manager
 */

/*-
   * Copyright (c) <2011>, 6WIND
   * All rights reserved.
   */
#ifndef _GENL_BASE_H
#define _GENL_BASE_H

#include <linux/genetlink.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>

struct genl_grp {
	uint32_t		id;
	char			name[GENL_NAMSIZ];
};

struct genl_family {
	struct genl_grp		grp;
	uint16_t		id;
	char			name[GENL_NAMSIZ];
};

void cm_genl_init(struct nlsock *cmn, const char* name, const char* group);
void cm_genl_destroy(struct nlsock *cmn);
int cm_genl_get_family(struct genl_family *fam);

#endif /* _GENL_BASE_H */
