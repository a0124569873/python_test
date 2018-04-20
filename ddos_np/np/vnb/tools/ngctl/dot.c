/*
 * dot.c
 *
 * Copyright (c) 2004 Brian Fundakowski Feldman
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
 * $FreeBSD: /repoman/r/ncvs/src/usr.sbin/ngctl/dot.c,v 1.3.4.1 2004/08/20 14:34:44 ru Exp $
 */

/*
 * Copyright 2009-2012 6WIND S.A.
 */

#include <inttypes.h>

#include "ngctl.h"

#define UNNAMED		"\\<unnamed\\>"

static int DotCmd(int ac, char **av);

const struct ngcmd dot_cmd = {
	DotCmd,
	"dot [outputfile]",
	"Produce a GraphViz (.dot) of the entire netgraph.",
	"If no outputfile is specified, stdout will be assumed.",
	{ "graphviz", "confdot" }
};

static int
DotCmd(int ac, char **av)
{
	u_char nlrbuf[16 * 1024];
	struct ng_mesg *const nlresp = (struct ng_mesg *)nlrbuf;
	struct namelist *const nlist = (struct namelist *)nlresp->data;
	struct listoffset offset;
	FILE *f = stdout;
	int ch;
	u_int i;

	/* Get options */
	optind = 0;
	while ((ch = getopt(ac, av, "")) != EOF) {
		switch (ch) {
		case '?':
		default:
			return (CMDRTN_USAGE);
			break;
		}
	}
	ac -= optind;
	av += optind;

	/* Get arguments */
	switch (ac) {
	case 1:
		f = fopen(av[0], "w");
		if (f == NULL) {
			warn("Could not open %s for writing", av[0]);
			return (CMDRTN_ERROR);
		}
	case 0:
		break;
	default:
		if (f != stdout)
			(void)fclose(f);
		return (CMDRTN_USAGE);
	}

	/* Get list of nodes, no count limit */
	offset.offset = 0;
	offset.count = 0;
	if (NgSendMsg(csock, ".", NGM_GENERIC_COOKIE, NGM_LISTNODES, &offset,
		      sizeof(struct listoffset)) < 0) {
		warn("send listnodes msg");
		goto error;
	}
	if (NgRecvMsg(csock, nlresp, sizeof(nlrbuf), NULL) < 0) {
		warn("recv listnodes msg");
		goto error;
	}

	fprintf(f, "graph netgraph {\n");
	/* TODO: implement rank = same or subgraphs at some point */
	fprintf(f, "\tedge [ weight = 1.0 ];\n");
	fprintf(f, "\tnode [ shape = record, fontsize = 12 ] {\n");
	for (i = 0; i < nlist->numnames; i++)
		fprintf(f, "\t\t\"%lx\" [ label = \"{%s:|{%s|[%lx]:}}\" ];\n",
		    (u_long)nlist->nodeinfo[i].id,
		    nlist->nodeinfo[i].name[0] != '\0' ?
		    nlist->nodeinfo[i].name : UNNAMED,
		    nlist->nodeinfo[i].type, (u_long)nlist->nodeinfo[i].id);
	fprintf(f, "\t};\n");

	fprintf(f, "\tsubgraph cluster_disconnected {\n");
	fprintf(f, "\t\tbgcolor = pink;\n");
	for (i = 0; i < nlist->numnames; i++)
		if (nlist->nodeinfo[i].hooks == 0)
			fprintf(f, "\t\t\"%lx\";\n",
			    (u_long)nlist->nodeinfo[i].id);
	fprintf(f, "\t};\n");

	for (i = 0; i < nlist->numnames; i++) {
		u_char hlrbuf[16 * 1024];
		struct ng_mesg *const hlresp = (struct ng_mesg *)hlrbuf;
		struct hooklist *const hlist = (struct hooklist *)hlresp->data;
		struct nodeinfo *const ninfo = &hlist->nodeinfo;
		char path[NG_PATHLEN + 1];
		u_int j;

		(void)snprintf(path, sizeof(path), "[%lx]:",
		    (u_long)nlist->nodeinfo[i].id);

		/* Get node info and hook list */
		if (NgSendMsg(csock, path, NGM_GENERIC_COOKIE, NGM_LISTHOOKS,
		    NULL, 0) < 0) {
			warn("send listhooks msg");
			goto error;
		}
		if (NgRecvMsg(csock, hlresp, sizeof(hlrbuf), NULL) < 0) {
			warn("recv listhooks msg");
			goto error;
		}

		if (ninfo->hooks == 0)
			continue;

		fprintf(f, "\tnode [ shape = octagon, fontsize = 10 ] {\n");
		for (j = 0; j < ninfo->hooks; j++)
			fprintf(f, "\t\t\"%lx.%s\" [ label = \"%s\" ];\n",
			    (u_long)nlist->nodeinfo[i].id,
			    hlist->link[j].ourhook, hlist->link[j].ourhook);
		fprintf(f, "\t};\n");

		fprintf(f, "\t{\n\t\tedge [ weight = 2.0, style = bold ];\n");
		for (j = 0; j < ninfo->hooks; j++)
			fprintf(f, "\t\t\"%lx\" -- \"%lx.%s\";\n",
			    (u_long)nlist->nodeinfo[i].id,
			    (u_long)nlist->nodeinfo[i].id,
			    hlist->link[j].ourhook);
		fprintf(f, "\t};\n");

		for (j = 0; j < ninfo->hooks; j++) {
			/* Only print the edges going in one direction. */
			if (hlist->link[j].nodeinfo.id > nlist->nodeinfo[i].id)
				continue;
			fprintf(f, "\t\"%lx.%s\" -- \"%lx.%s\";\n",
			    (u_long)nlist->nodeinfo[i].id,
			    hlist->link[j].ourhook,
			    (u_long)hlist->link[j].nodeinfo.id,
			    hlist->link[j].peerhook);
		}

	}

	fprintf(f, "};\n");

	if (f != stdout)
		(void)fclose(f);
	return (CMDRTN_OK);
error:
	if (f != stdout)
		(void)fclose(f);
	return (CMDRTN_ERROR);
}
