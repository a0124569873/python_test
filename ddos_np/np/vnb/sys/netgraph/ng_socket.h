
/*
 * ng_socket.h
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
 * Author: Julian Elischer <julian@freebsd.org>
 *
 * $FreeBSD: src/sys/netgraph/ng_socket.h,v 1.3.2.1 2000/10/24 18:36:46 julian Exp $
 * $Whistle: ng_socket.h,v 1.5 1999/01/20 00:22:14 archie Exp $
 */
/*
 * Copyright 2003-2012 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_SOCKET_H_
#define _NETGRAPH_NG_SOCKET_H_ 1

#include "alignment.h"

/* Netgraph node type name and cookie */
#define	NG_SOCKET_NODE_TYPE	"socket"
#define	NGM_SOCKET_COOKIE	851601233
#define NG_SOCKET_META_CONTROL_INADDR	1
#define NG_SOCKET_META_CONTROL_IN6ADDR	2

/* Netgraph socket(2) constants */
#define	NG_DATA			1
#define	NG_CONTROL		2

/* Commands */
enum {
	NGM_SOCK_CMD_NOLINGER = 1,	/* close the socket with last hook */
	NGM_SOCK_CMD_LINGER		/* Keep socket even if 0 hooks */
};

/* Socket messages (these messages cannot be send to a socket node,
 * but are advertised using netlink when a netgraph socket is
 * created */
#define NGM_SOCKET_CREATE   1  /* Msg to create socket node */
#define NGM_SOCKET_DELETE   2  /* Msg to delete socket node */

/* Netgraph version of struct sockaddr */
struct sockaddr_ng_hdr {
	/* warning: must be kept synchronized with the struct below */
	u_char  sg_len;		/* total length */
	u_char  sg_family;	/* address family */
};

struct sockaddr_ng {
	/* warning: must be kept synchronized with the struct above */
	u_char  sg_len;		/* total length */
	u_char  sg_family;	/* address family */
	/* enough to store NG_HOOKLEN=31 or NG_NODELEN=31 + '\0'
	 * for recvfrom(), may be longer with sendto() */
	char    sg_data[31 + 1];
};

#endif /* _NETGRAPH_NG_SOCKET_H_ */

