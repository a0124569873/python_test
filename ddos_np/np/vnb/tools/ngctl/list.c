
/*
 * list.c
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
 * $FreeBSD: src/usr.sbin/ngctl/list.c,v 1.2 1999/11/30 02:45:30 archie Exp $
 */

/*
 * Copyright 2003-2013 6WIND S.A.
 */

#include "ngctl.h"

static int ListCmd(int ac, char **av);

const struct ngcmd list_cmd = {
	.func = ListCmd,
	.cmd = "list [-n] [-o <offset>] [-c <count>]",
	.desc = "Show information about nodes",
	.help = "The list command shows information every node that currently"
	" exists in the netgraph system. The optional -n argument limits"
	" this list to only those nodes with a global name assignment."
	" The optional -o specify from where start to list nodes, default 0."
	" The optional -c specify how many nodes are about to list, default is no limit.",
	.aliases = { "ls" }
};

static int
ListCmd(int ac, char **av)
{
	u_char rbuf[128 * 1024];
	struct ng_mesg *const resp = (struct ng_mesg *) rbuf;
	struct namelist *const nlist = (struct namelist *) resp->data;
	int named_only = 0;
	int ch, rtn = CMDRTN_OK;
	struct listoffset offset;
	unsigned k;

	/* Set default values for offset information used */
	u_int32_t head = DEFAULT_LIST_OFFSET;
	u_int32_t count = 0;
	u_int32_t listcnt =0;

	/* Get options */
	optind = 0;
	while ((ch = getopt(ac, av, "no:c:")) != EOF) {
		switch (ch) {
		case 'n':
			named_only = 1;
			break;
		case 'o':
			head = (u_int32_t)atoi(optarg);
			break;
		case 'c':
			count = (u_int32_t)atoi(optarg);
			break;
		case '?':
		default:
			return(CMDRTN_USAGE);
		}
	}
	ac -= optind;
	av += optind;
	(void)av;

	/* Get arguments */
	switch (ac) {
	case 0:
		break;
	default:
		return(CMDRTN_USAGE);
	}

	listcnt = 0;
	do {
		offset.offset = head;
		if ( count && count < DEFAULT_MAX_LIST_COUNT)
			offset.count = count;
		else
			offset.count = DEFAULT_MAX_LIST_COUNT;

		/* Get list of nodes */
		if (NgSendMsg(csock, ".", NGM_GENERIC_COOKIE,
			named_only ? NGM_LISTNAMES : NGM_LISTNODES, (const void*)&offset,
			sizeof(struct listoffset)) < 0) {
			warn("send msg");
			return(CMDRTN_ERROR);
		}
		if (NgRecvMsg(csock, resp, sizeof(rbuf), NULL) < 0) {
			warn("recv msg");
			return(CMDRTN_ERROR);
		}

		/* Show each node */
		for (k = 0; k < nlist->numnames; k++) {
			char path[NG_PATHLEN+1];
			char *av[3] = { "list", "-n", path };
			snprintf(path, sizeof(path), "[%lx]:", (u_long) nlist->nodeinfo[k].id);
			if ((rtn = (*show_cmd.func)(3, av)) != CMDRTN_OK)
				break;
		}

		/* adjust head and node count static. */
		head += nlist->numnames;
		listcnt +=nlist->numnames;

		/* if the count match requirement, then break loop. */
		if (count) {
			if (count <= nlist->numnames)
				break;
			count -= nlist->numnames;
		}
		else {
			if ( nlist->numnames < DEFAULT_MAX_LIST_COUNT )
				break;
		}
	}while (nlist->numnames);

	/* Done */
	printf("There are %d total %snodes, %d nodes listed\n", nlist->totalnames, named_only ? "named " : "", listcnt);
	return (rtn);
}

