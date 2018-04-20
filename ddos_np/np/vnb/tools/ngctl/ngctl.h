
/*
 * ngctl.h
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
 * $FreeBSD: src/usr.sbin/ngctl/ngctl.h,v 1.6.2.3 2002/02/01 18:17:43 archie Exp $
 */

/*
 * Copyright 2003-2013 6WIND S.A.
 */

#include <stdint.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#ifndef FP_STANDALONE
#include <sys/socket.h>
#include <sys/select.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef FP_STANDALONE
#include <sysexits.h>
#endif
#include <limits.h>
#include <ctype.h>
#ifndef FP_STANDALONE
#include <errno.h>
#include <err.h>
#endif
#include <netgraph.h>
#include <netgraph/ng_socket.h>
#include <netgraph/ng_message.h>

#ifdef FP_STANDALONE
#define warn printf
#define warnx printf
#endif

#define MAX_CMD_ALIAS	8

/* Command descriptors */
struct ngcmd {
	  int		(*func)(int ac, char **av);	/* command function */
	  const char	*cmd;				/* command usage */
	  const char	*desc;				/* description */
	  const char	*help;				/* help text */
	  const char	*aliases[MAX_CMD_ALIAS];	/* command aliases */
};

/* Command return values */
#define CMDRTN_OK		0
#define CMDRTN_USAGE		1
#define CMDRTN_ERROR		2
#define CMDRTN_QUIT		3

/* Available commands */
#ifndef FP_STANDALONE
extern const struct ngcmd config_cmd;
extern const struct ngcmd connect_cmd;
extern const struct ngcmd conforce_cmd;
extern const struct ngcmd debug_cmd;
extern const struct ngcmd help_cmd;
extern const struct ngcmd list_cmd;
extern const struct ngcmd mkpeer_cmd;
extern const struct ngcmd msg_cmd;
extern const struct ngcmd name_cmd;
extern const struct ngcmd read_cmd;
extern const struct ngcmd rmhook_cmd;
extern const struct ngcmd show_cmd;
extern const struct ngcmd shutdown_cmd;
extern const struct ngcmd status_cmd;
extern const struct ngcmd types_cmd;
extern const struct ngcmd write_cmd;
extern const struct ngcmd quit_cmd;
extern const struct ngcmd add_node_cmd;
extern const struct ngcmd cli_cmd;
extern const struct ngcmd getstats_cmd;
extern const struct ngcmd dot_cmd;
extern const struct ngcmd inspeer_cmd;
extern const struct ngcmd insnode_cmd;
extern const struct ngcmd bypass_cmd;
extern const struct ngcmd dump_cmd;
#else
extern const struct ngcmd connect_cmd;
extern const struct ngcmd conforce_cmd;
extern const struct ngcmd list_cmd;
extern const struct ngcmd mkpeer_cmd;
extern const struct ngcmd msg_cmd;
extern const struct ngcmd name_cmd;
extern const struct ngcmd rmhook_cmd;
extern const struct ngcmd show_cmd;
#endif


/* Data and control sockets */
extern int	csock, dsock;

/* Misc functions */
extern void	MsgRead(void);
extern void	DumpAscii(const char *buf, int len);
extern int	DoCommand(int ac, char **av);
extern int	DoParseCommand(char *line);
