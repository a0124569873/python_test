/*
 * Copyright 2011 6WIND S.A.
 */

#include "ngctl.h"

static int DumpCmd(int ac, char **av);

const struct ngcmd dump_cmd = {
	.func = DumpCmd,
	.cmd = "nldump",
	.desc = "Trigger a vnb nl dump for the nodes",
};

static int
DumpCmd(int ac, char **av)
{
	(void) ac;
	(void) av;

	/* Get list of nodes */
	if (NgSendMsg(csock, ".", NGM_GENERIC_COOKIE,
		      NGM_DUMPNODES, 0, 0) < 0) {
		warn("send msg");
		return(CMDRTN_ERROR);
	}

	return 0;
}
