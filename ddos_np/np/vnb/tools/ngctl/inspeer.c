/*
 * Copyright 2007-2013 6WIND S.A.
 */

#include "ngctl.h"

static int InsPeerCmd(int ac, char **av);

const struct ngcmd inspeer_cmd = {
	.func = InsPeerCmd,
	.cmd = "inspeer [path] <type> <hook> <peerhook1> <peerhook2>",
	.desc = "Create and insert a new node to the node at \"path\" and propagates connection to <peerhook2>",
	.help = "The inspeer command atomically creates a new node of type \"type\""
	" and connects it to the node at \"path\". The hooks used for the"
	" connection are \"hook\" on the original node and \"peerhook\""
	" on the new node. Previous connected hook will be connected to"
	" \"peerhook2\""
	" If \"path\" is omitted then \".\" is assumed.",
	.aliases = { NULL },
};

static int
InsPeerCmd(int ac, char **av)
{
	struct ngm_inspeer isp;
	char *path = ".";

	/* Get arguments */
	switch (ac) {
	case 6:
		path = av[1];
		ac--;
		av++;
		/* FALLTHROUGH */
	case 5:
		memset(&isp, 0, sizeof(isp));
		snprintf(isp.type, sizeof(isp.type), "%s", av[1]);
		snprintf(isp.ourhook, sizeof(isp.ourhook), "%s", av[2]);
		snprintf(isp.peerhook, sizeof(isp.peerhook), "%s", av[3]);
		snprintf(isp.peerhook2, sizeof(isp.peerhook2), "%s", av[4]);
		break;
	default:
		return(CMDRTN_USAGE);
	}

	/* Send message */
	if (NgSendMsg(csock, path, NGM_GENERIC_COOKIE,
	    NGM_INSPEER, &isp, sizeof(isp)) < 0) {
		warn("send msg");
		return(CMDRTN_ERROR);
	}
	return(CMDRTN_OK);
}

