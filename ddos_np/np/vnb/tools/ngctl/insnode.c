/*
 * Copyright 2007-2011 6WIND S.A.
 */

#include "ngctl.h"

static int InsNodeCmd(int ac, char **av);

const struct ngcmd insnode_cmd = {
	InsNodeCmd,
	"insnode [path] <relpath> <hook> <peerhook> <peerhook2>",
	"Insert hook <peerhook> of the node at <relpath> to <hook> and propagtes connection to <peerhook2>",
	"The insnode command creates a link between the two nodes at"
	" \"path\" and \"relpath\" using hooks \"hook\" and \"peerhook\","
	" respectively. The \"relpath\", if not absolute, is specified"
	" relative to the node at \"path\". \"peerhook2\" will be connected"
    " to the hook previously connected to the first node."
	" If \"path\" is omitted then \".\" is assumed.",
	{ "insert" }
};

static int
InsNodeCmd(int ac, char **av)
{
	struct ngm_insnode isn;
	char *path = ".";

	/* Get arguments */
	switch (ac) {
	case 6:
		path = av[1];
		ac--;
		av++;
		/* FALLTHROUGH */
	case 5:
		memset(&isn, 0, sizeof(isn));
		snprintf(isn.path, sizeof(isn.path), "%s", av[1]);
		snprintf(isn.ourhook, sizeof(isn.ourhook), "%s", av[2]);
		snprintf(isn.peerhook, sizeof(isn.peerhook), "%s", av[3]);
		snprintf(isn.peerhook2, sizeof(isn.peerhook2), "%s", av[4]);
		break;
	default:
		return(CMDRTN_USAGE);
	}

	/* Send message */
	if (NgSendMsg(csock, path, NGM_GENERIC_COOKIE,
	    NGM_INSNODE, &isn, sizeof(isn)) < 0) {
		warn("send msg");
		return(CMDRTN_ERROR);
	}
	return(CMDRTN_OK);
}

