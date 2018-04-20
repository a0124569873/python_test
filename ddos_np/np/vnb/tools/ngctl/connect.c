
/*
 * connect.c
 *
 * Copyright (c) 1996-1999 Whistle Communications, Inc.
 * All rights reserved.
 *
 * Subject to the following obligations and disclaimer of warranty, use and
 * redistribution of this software, in source or object code forms, with or
 * without modifications are expressly permitted by Whistle Communications;
 * provided, however, that:
 * 1. Any and all reproductions of the source or object code must include the
 *    copyright notice above and the following disclaimer of warranties; and
 * 2. No rights are granted, in any manner or form, to use Whistle
 *    Communications, Inc. trademarks, including the mark "WHISTLE
 *    COMMUNICATIONS" on advertising, endorsements, or otherwise except as
 *    such appears in the above copyright notice or in the software.
 *
 * THIS SOFTWARE IS BEING PROVIDED BY WHISTLE COMMUNICATIONS "AS IS", AND
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, WHISTLE COMMUNICATIONS MAKES NO
 * REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, REGARDING THIS SOFTWARE,
 * INCLUDING WITHOUT LIMITATION, ANY AND ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
 * WHISTLE COMMUNICATIONS DOES NOT WARRANT, GUARANTEE, OR MAKE ANY
 * REPRESENTATIONS REGARDING THE USE OF, OR THE RESULTS OF THE USE OF THIS
 * SOFTWARE IN TERMS OF ITS CORRECTNESS, ACCURACY, RELIABILITY OR OTHERWISE.
 * IN NO EVENT SHALL WHISTLE COMMUNICATIONS BE LIABLE FOR ANY DAMAGES
 * RESULTING FROM OR ARISING OUT OF ANY USE OF THIS SOFTWARE, INCLUDING
 * WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * PUNITIVE, OR CONSEQUENTIAL DAMAGES, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES, LOSS OF USE, DATA OR PROFITS, HOWEVER CAUSED AND UNDER ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF WHISTLE COMMUNICATIONS IS ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * $FreeBSD: src/usr.sbin/ngctl/connect.c,v 1.2 1999/11/30 02:45:30 archie Exp $
 */

/*
 * Copyright 2003-2012 6WIND S.A.
 */

#include "ngctl.h"

static int ConnectCmd(int ac, char **av);
static int ConforceCmd(int ac, char **av);

const struct ngcmd connect_cmd = {
	ConnectCmd,
	"connect [path] <relpath> <hook> <peerhook>",
	"Connects hook <peerhook> of the node at <relpath> to <hook>",
	"The connect command creates a link between the two nodes at"
	" \"path\" and \"relpath\" using hooks \"hook\" and \"peerhook\","
	" respectively. The \"relpath\", if not absolute, is specified"
	" relative to the node at \"path\"."
	" If \"path\" is omitted then \".\" is assumed.",
	{ "join" }
};
const struct ngcmd conforce_cmd = {
	ConforceCmd,
	"conforce [path] <relpath> <hook> <peerhook>",
	"Forces to  Connect hook <peerhook> of the node at <relpath> to <hook>",
	"The conforce command just creates a link between the two nodes at"
	" \"path\" and \"relpath\" using hooks \"hook\" and \"peerhook\","
	" respectively and aggressively. The \"relpath\", if not absolute,"
	" is specified relative to the node at \"path\"."
	" If \"path\" is omitted then \".\" is assumed."
	" If the hooks already exist and connect with others, the command"
	" destroy the peer hooks of other and connect the hooks together.",
	{ NULL }
};

static int real_connect(int ac, char **av, int type)
{
	struct ngm_connect con;
	char *path = ".";

	/* Get arguments */
	switch (ac) {
	case 5:
		path = av[1];
		ac--;
		av++;
		/* FALLTHROUGH */
	case 4:
		snprintf(con.path, sizeof(con.path), "%s", av[1]);
		snprintf(con.ourhook, sizeof(con.ourhook), "%s", av[2]);
		snprintf(con.peerhook, sizeof(con.peerhook), "%s", av[3]);
		break;
	default:
		return(CMDRTN_USAGE);
	}

	/* Send message */
	if (NgSendMsg(csock, path, NGM_GENERIC_COOKIE,
	    type, &con, sizeof(con)) < 0) {
		warn("send msg");
		return(CMDRTN_ERROR);
	}
	return(CMDRTN_OK);
}

static int
ConnectCmd(int ac, char **av)
{
	return real_connect(ac, av, NGM_CONNECT);
}

static int
ConforceCmd(int ac, char **av)
{
	return real_connect(ac, av, NGM_CONNECT_FORCE);
}
