/*
 * msg.c
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
 * Author: Archie Cobbs <archie@whistle.com>
 *
 * $FreeBSD: src/lib/libnetgraph/msg.c,v 1.2.2.3 2001/10/29 18:36:30 archie Exp $
 * $Whistle: msg.c,v 1.9 1999/01/20 00:57:23 archie Exp $
 */

#include <sys/types.h>
#include <stdarg.h>
#include <stdint.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_socket.h>

#include "netgraph.h"
#include "internal.h"

#include "netfpc.h"
#include "fp-ng_message.h"

/* Next message token value */
static int	gMsgId;

/* For delivering both messages and replies */
static int	NgDeliverMsg(int cs, const char *path,
		  const struct ng_mesg *hdr, const void *args, size_t arglen);

/*
 * Send a message to a node using control socket node "cs".
 * Returns -1 if error and sets errno appropriately.
 * If successful, returns the message ID (token) used.
 */
int
NgSendMsgCPNodeID(int cs, const char *path,
		  int cookie, int cmd, const void *args, size_t arglen,
		  uint32_t cpnodeid)
{
	struct ng_mesg msg;

	/* Prepare message header */
	memset(&msg, 0, sizeof(msg));
	msg.header.version = NG_VERSION;
	msg.header.typecookie = cookie;
	if (++gMsgId < 0)
		gMsgId = 1;
	msg.header.token = gMsgId;
	msg.header.flags = NGF_ORIG;
	msg.header.nodeid = cpnodeid;
	msg.header.cmd = cmd;
	snprintf(msg.header.cmdstr, NG_CMDSTRLEN + 1, "cmd%d", cmd);

	/* Deliver message */
	if (NgDeliverMsg(cs, path, &msg, args, arglen) < 0)
		return (-1);
	return (msg.header.token);
}

/*
 * Send a message to a node using control socket node "cs".
 * Returns -1 if error and sets errno appropriately.
 * If successful, returns the message ID (token) used.
 */
int
NgSendMsg(int cs, const char *path,
	  int cookie, int cmd, const void *args, size_t arglen)
{
	return NgSendMsgCPNodeID(cs, path, cookie, cmd, args, arglen, 0);
}

int
NgSendFastAsciiMsg(int cs, const char *path,
	  int cookie, int cmd, const void *args, size_t arglen,
	  uint32_t cpnodeid)
{
	struct ng_mesg msg;

	/* Prepare message header */
	memset(&msg, 0, sizeof(msg));
	msg.header.version = NG_VERSION;
	msg.header.typecookie = cookie;
	if (++gMsgId < 0)
		gMsgId = 1;
	msg.header.token = gMsgId;
	msg.header.flags = NGF_ORIG | NGF_ASCII;
	msg.header.nodeid = cpnodeid;
	msg.header.cmd = cmd;
	msg.header.cmdstr[0] = '\0';

	/* Deliver message */
	if (NgDeliverMsg(cs, path, &msg, args, arglen) < 0)
		return (-1);
	return (msg.header.token);
}

/*
 * Send a message given in ASCII format. We first ask the node to translate
 * the command into binary, and then we send the binary.
 */
int
NgSendAsciiMsg(int cs, const char *path, const char *fmt, ...)
{
	const int bufSize = 1024;
	char replybuf[2 * sizeof(struct ng_mesg) + bufSize];
	struct ng_mesg *const reply = (struct ng_mesg *)replybuf;
	struct ng_mesg *const binary = (struct ng_mesg *)reply->data;
	struct ng_mesg *ascii;
	char *buf, *cmd, *args;
	va_list fmtargs;

	/* Parse out command and arguments */
	va_start(fmtargs, fmt);
	if(vasprintf(&buf, fmt, fmtargs) == -1)
            return (-1);
	va_end(fmtargs);
	if (buf == NULL)
		return (-1);

	/* Parse out command, arguments */
	for (cmd = buf; isspace(*cmd); cmd++)
		;
	for (args = cmd; *args != '\0' && !isspace(*args); args++)
		;
	if (*args != '\0') {
		while (isspace(*args))
			*args++ = '\0';
	}

	/* Get a bigger buffer to hold inner message header plus arg string */
	if ((ascii = malloc(sizeof(struct ng_mesg)
	    + strlen(args) + 1)) == NULL) {
		free(buf);
		return (-1);
	}
	memset(ascii, 0, sizeof(*ascii));

	/* Build inner header (only need cmdstr, arglen, and data fields) */
	strncpy(ascii->header.cmdstr, cmd, sizeof(ascii->header.cmdstr) - 1);
	strcpy(ascii->data, args);
	ascii->header.arglen = strlen(ascii->data) + 1;
	free(buf);

	/* Send node a request to convert ASCII to binary */
	if (NgSendMsg(cs, path, NGM_GENERIC_COOKIE, NGM_ASCII2BINARY,
	    (u_char *)ascii, sizeof(*ascii) + ascii->header.arglen) < 0) {
		free(ascii);
		return (-1);
	}
	free(ascii);

	/* Get reply */
	if (NgRecvMsg(cs, reply, sizeof(replybuf), NULL) < 0)
		return (-1);

	/* Now send binary version */
	if (++gMsgId < 0)
		gMsgId = 1;
	binary->header.token = gMsgId;
	if (NgDeliverMsg(cs,
	    path, binary, binary->data, binary->header.arglen) < 0)
		return (-1);
	return (binary->header.token);
}

/*
 * Send a message that is a reply to a previously received message.
 * Returns -1 and sets errno on error, otherwise returns zero.
 */
int
NgSendReplyMsg(int cs, const char *path,
	const struct ng_mesg *msg, const void *args, size_t arglen)
{
	struct ng_mesg rep;

	/* Prepare message header */
	rep = *msg;
	rep.header.flags = NGF_RESP;

	/* Deliver message */
	return (NgDeliverMsg(cs, path, &rep, args, arglen));
}

/*
 * Send a message to a node using control socket node "cs".
 * Returns -1 if error and sets errno appropriately, otherwise zero.
 */
static int
NgDeliverMsg(int cs, const char *path,
	const struct ng_mesg *hdr, const void *args, size_t arglen)
{
	u_char *buf = NULL;
	struct ng_mesg *msg;
	int errnosv = 0;
	int rtn = 0;
	int fp_buf_len = NG_FP_HDR_SIZE + sizeof(*msg) + arglen + NG_PATHLEN + 1;
	ng_fp_hdr_t *fp_hdr;
	int fp_hdr_len;
	int len;

	/* Sanity check */
	if (args == NULL)
		arglen = 0;

	/* Get buffer */
	if ((buf = malloc(fp_buf_len)) == NULL) {
		errnosv = errno;
		if (_gNgDebugLevel >= 1)
			NGLOG("malloc");
		rtn = -1;
		goto done;
	}
	memset(buf, 0, fp_buf_len);
	fp_hdr = (ng_fp_hdr_t *)buf;
	snprintf(fp_hdr->path, NG_PATHLEN + 1, "%s", path);
	fp_hdr->len = (strlen(fp_hdr->path) + 3) >> 2;
	fp_hdr->error = 0;
	fp_hdr_len = NG_FP_HDR_SIZE + (fp_hdr->len << 2);

	msg = (struct ng_mesg *) (buf + fp_hdr_len);

	/* Finalize message */
	*msg = *hdr;
	msg->header.arglen = arglen;
	if (args != NULL)
		memcpy(msg->data, args, arglen);

	/* Debugging */
	if (_gNgDebugLevel >= 2) {
		NGLOGX("SENDING %s: path=%s",
		    (msg->header.flags & NGF_RESP) ? "RESPONSE" : "MESSAGE",
		    path);
		NGLOGX(" arglen=%d typecookie=%d cmd=%d",
				msg->header.arglen,
				msg->header.typecookie,
				msg->header.cmd);

	}

	/* Send it */
	if (netfpc_send(cs, buf, sizeof(*msg) + arglen + fp_hdr_len, 
			0, NETFPC_MSGTYPE_VNB) < 0) {
		errnosv = errno;
		if (_gNgDebugLevel >= 1)
			NGLOG("netfpc_send(%s)", path);
		rtn = -1;
		free(buf);
		goto done;
	}


	free(buf);

	/* Get buffer for recv */
	if ((buf = malloc(BUFSIZ)) == NULL) {
		errnosv = errno;
		if (_gNgDebugLevel >= 1)
			NGLOG("malloc");
		rtn = -1;
		goto done;
	}
	
	/* Wait for the synchronous error code, don't steal the msg
	 * from the socket data queue (MSG_PEEK) */
	len = netfpc_recv(cs, buf, BUFSIZ, MSG_PEEK, NULL);
	if (len < NG_FP_HDR_SIZE) {
		errnosv = errno;
		if (_gNgDebugLevel >= 1)
			NGLOG("msg too short");
		rtn = -1;
		free(buf);
		goto done;
	}

	fp_hdr = (ng_fp_hdr_t *)buf;
	errnosv = fp_hdr->error;

	/* if there is no response in message, drop the packet, else
	 * keep it for the next RecvMsg() call. We assume that the
	 * packet is not fragmented because it only contains an
	 * error. */
	if (len == (NG_FP_HDR_SIZE + (fp_hdr->len << 2))) {
		if (_gNgDebugLevel >= 1)
			NGLOG("Drop reply msg, only error code inside (%d)\n",
			      errnosv);
		netfpc_recv(cs, buf, BUFSIZ, 0, NULL);
	}
	else {
		if (_gNgDebugLevel >= 1)
			NGLOG("Has reply msg\n");
	}

	if (fp_hdr->error)
		rtn = -1;

	free(buf);
	
done:
	/* Done */
	errno = errnosv;
	return (rtn);
}

/*
 * Receive a control message.
 *
 * On error, this returns -1 and sets errno.
 * Otherwise, it returns the length of the received reply.
 */
int
NgRecvMsg(int cs, struct ng_mesg *rep, size_t replen, char *path)
{
	int errnosv = 0;
	u_char *fp_buf;
	int fp_buf_len = replen + NG_PATHLEN + 1;
	ng_fp_hdr_t *fp_hdr;
	int len, path_len, tot_len=0;
	int expected_len = 0;

	fp_buf = malloc(fp_buf_len);
	if (fp_buf == NULL) {
		errnosv = ENOMEM;
		if (_gNgDebugLevel >= 1)
			NGLOG("malloc");
		goto errout;
	}

	if (_gNgDebugLevel >= 1)
		NGLOG("Alloc fp_buf at %p, size=%d", fp_buf, fp_buf_len);
	memset(fp_buf, 0, fp_buf_len);

	/* Total length is written in last fragment */
	do {
		/* Read reply */
		len = netfpc_recv(cs, fp_buf, fp_buf_len, 0, NULL);
		if (len < NG_FP_HDR_SIZE) {
			errnosv = errno;
			if (_gNgDebugLevel >= 1)
				NGLOG("netfpc_recv");
			goto errout;
		}
		
		if (_gNgDebugLevel >= 2)
			NGLOG("Read on netfpc len=%d, total_len=%d", len, tot_len);
		fp_hdr = (ng_fp_hdr_t *)fp_buf;
		path_len = fp_hdr->len << 2;
		
		if (path_len && path != NULL)
			snprintf(path, path_len+1, "%s", fp_hdr->path);
		
		if (_gNgDebugLevel >= 2)
			NGLOG("path_len=%d last_frag=%d error=%d", path_len, 
			      fp_hdr->last_frag, fp_hdr->error);

		/* if there is an error, there's no more frag */
		if (fp_hdr->error) {
			if (_gNgDebugLevel >= 1)
				NGLOG("error code in message");
			errnosv = fp_hdr->error;
			goto errout;
		}
		
		len -= (NG_FP_HDR_SIZE + path_len);

		if (fp_hdr->offset + len > replen) {
			if (_gNgDebugLevel >= 1)
				NGLOG("too large fragment\n");
			errnosv = EMSGSIZE;
		} else {
			if (_gNgDebugLevel >= 2)
				NGLOG("memcpy to %p from %p (len=%d)", 
			      (char *)rep+fp_hdr->offset, 
				  fp_buf + NG_FP_HDR_SIZE + path_len, 
				  len);
		
			memcpy((char *)rep+fp_hdr->offset, 
					fp_buf + NG_FP_HDR_SIZE + path_len, 
					len);
		}

		tot_len += len;

		if (fp_hdr->last_frag)
			expected_len = fp_hdr->offset + len;

	} while(expected_len == 0 || tot_len < expected_len);

	/* Debugging */
	if (_gNgDebugLevel >= 2) {
		NGLOGX("RECEIVED %s: path=%s, msg_len=%d tot_len=%d",
		       (rep->header.flags & NGF_RESP) ? "RESPONSE" : "MESSAGE", path, 
		       rep->header.arglen, tot_len);
	}

	if (errnosv)
		goto errout;

	if ((rep->header.arglen + sizeof(struct ng_mesg)) != tot_len) {
		if (_gNgDebugLevel >= 1)
			NGLOG("error: message too big");
		errnosv = EMSGSIZE;
		goto errout;
	}

	free(fp_buf);

	
	/* Done */
	return (tot_len);

errout:
	errno = errnosv;
	if (fp_buf)
		free(fp_buf);
	return (-1);
}

/*
 * Receive a control message and convert the arguments to ASCII
 */
int
NgRecvAsciiMsg(int cs, struct ng_mesg *reply, size_t replen, char *path)
{
	struct ng_mesg *msg, *ascii;
	int bufSize, errnosv;
	u_char *buf;

	/* Allocate buffer */
	bufSize = 2 * sizeof(*reply) + replen;
	if ((buf = malloc(bufSize)) == NULL)
		return (-1);
	msg = (struct ng_mesg *)buf;
	ascii = (struct ng_mesg *)msg->data;

	/* Get binary message */
	if (NgRecvMsg(cs, msg, bufSize, path) < 0)
		goto fail;
	memcpy(reply, msg, sizeof(*msg));

	/* Ask originating node to convert the arguments to ASCII */
	if (NgSendMsg(cs, path, NGM_GENERIC_COOKIE,
	    NGM_BINARY2ASCII, msg, sizeof(*msg) + msg->header.arglen) < 0)
		goto fail;
	if (NgRecvMsg(cs, msg, bufSize, NULL) < 0)
		goto fail;

	/* Copy result to client buffer */
	if (sizeof(*ascii) + ascii->header.arglen > replen) {
		errno = ERANGE;
fail:
		errnosv = errno;
		free(buf);
		errno = errnosv;
		return (-1);
	}
	strncpy(reply->data, ascii->data, ascii->header.arglen);

	/* Done */
	free(buf);
	return (0);
}

/*
 * Read reply message and drop it.
 */
void NgDelReplyMsg(int cs)
{
	u_char *buf = NULL;
	int len, msglen, total_msglen = 0;
	ng_fp_hdr_t *fp_hdr;
	int fp_hdr_len;

	if ((buf = malloc(BUFSIZ)) == NULL) {
		if (_gNgDebugLevel >= 1)
			NGLOG("malloc failed");
		return;
	}

	len = netfpc_recv(cs, buf, BUFSIZ, MSG_DONTWAIT, NULL);
	if (len < (int)NG_FP_HDR_SIZE) {
		if (_gNgDebugLevel >= 1)
			NGLOG("no messsge or message too short");
		goto done;
	}
	else {
		fp_hdr = (ng_fp_hdr_t *)buf;
		msglen = len - (NG_FP_HDR_SIZE + (fp_hdr->len << 2));
		total_msglen += msglen;

		while (!fp_hdr->last_frag) {
			len = netfpc_recv(cs, buf, BUFSIZ, 0, NULL);

			if (len < NG_FP_HDR_SIZE) {
				if (_gNgDebugLevel >= 1)
					NGLOG("message too short");
				goto done;
			}
			msglen = len - NG_FP_HDR_SIZE;
			total_msglen += msglen;
		}

		if (fp_hdr->offset + msglen != total_msglen) {
			if (_gNgDebugLevel >= 1)
				NGLOG("invalid fragmented packet");
		}
	}

done:
	free(buf);
	return;
}
