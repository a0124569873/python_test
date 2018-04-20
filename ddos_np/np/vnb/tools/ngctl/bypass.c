/*
 * Copyright 2007 6WIND S.A.
 */

#include "ngctl.h"

static int BypassCmd(int ac, char **av);

const struct ngcmd bypass_cmd = {
	BypassCmd,
	"bypass [path] <hook> <hook2>",
	"Disconnect <hook> and <hook2> of the node at \"path\"i,a nd reconnects peers together",
	"The rmhook command forces the node at \"path\" to break the link"
	" formed by its hook \"hook\", if connected."
	" If \"path\" is omitted then \".\" is assumed.",
	{ "withdraw" }
};

static int
BypassCmd(int ac, char **av)
{
	struct ngm_bypass bp;
	char *path = ".";

	/* Get arguments */
	switch (ac) {
	case 4:
		path = av[1];
		ac--;
		av++;
		/* FALLTHROUGH */
	case 3:
		snprintf(bp.ourhook, sizeof(bp.ourhook), "%s", av[1]);
		snprintf(bp.ourhook2, sizeof(bp.ourhook2), "%s", av[2]);
		break;
	default:
		return(CMDRTN_USAGE);
	}

	/* Send message */
	if (NgSendMsg(csock, path, NGM_GENERIC_COOKIE,
	    NGM_BYPASS, &bp, sizeof(bp)) < 0) {
		warn("send msg");
		return(CMDRTN_ERROR);
	}
	return(CMDRTN_OK);
}

