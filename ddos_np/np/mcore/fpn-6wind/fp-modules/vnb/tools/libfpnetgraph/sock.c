/*
 * sock.c
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
 * $FreeBSD: src/lib/libnetgraph/sock.c,v 1.2 2000/01/28 00:48:27 archie Exp $
 * $Whistle: sock.c,v 1.12 1999/01/20 00:57:23 archie Exp $
 */

#include <sys/types.h>
#if defined(__linux__)
#include <linux/socket.h>
#else
#include <sys/socket.h>
#endif
#include <sys/uio.h>
#include <stdarg.h>
#include <stdint.h>
#include <netdb.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_socket.h>

#include "netgraph.h"
#include "internal.h"

#include "netfpc.h"
#include "fp-ng_message.h"

int
NgMkSockNode(const char *name, int *csp, int *dsp)
{
	int cs = -1;		/* control socket */
	int ds = -1;		/* data socket */
	int errnosv;

	cs = netfpc_open(name); 
	if (cs < 0) {
		errnosv = errno;
		if (_gNgDebugLevel >= 1)
			NGLOG("netfpc_open");
		goto errout;
	}
	if (dsp) {
		ds = netfpc_open(name);
		if (ds < 0) {
			errnosv = errno;
			if (_gNgDebugLevel >= 1)
				NGLOG("netfpc_open");
			goto errout;
		}
	}
	/* Return the socket(s) */
	if (csp)
		*csp = cs;
	if (dsp)
		*dsp = ds;
	return (0);

errout:
	/* Failed */
	if (cs >= 0)
		close(cs);
	if (ds >= 0)
		close(ds);
	errno = errnosv;
	return (-1);
}

/*
 * Assign a globally unique name to a node
 * Returns -1 if error and sets errno.
 */
int
NgNameNode(int cs, const char *path, const char *fmt, ...)
{
	struct ngm_name ngn;
	va_list args;

	/* Build message arg */
	va_start(args, fmt);
	vsnprintf(ngn.name, sizeof(ngn.name), fmt, args);
	va_end(args);

	/* Send message */
	if (NgSendMsg(cs, path,
	    NGM_GENERIC_COOKIE, NGM_NAME, &ngn, sizeof(ngn)) < 0) {
		if (_gNgDebugLevel >= 1)
			NGLOGX("%s: failed", __FUNCTION__);
		return (-1);
	}

	/* Done */
	return (0);
}

/*
 * Read a packet from a data socket
 * Returns -1 if error and sets errno.
 */
int
NgRecvData(int ds, u_char * buf, size_t len, char *hook)
{
	int rtn, errnosv;
	int fp_buf_len = NG_FP_HDR_SIZE + NG_HOOKLEN + 1 + len;
	ng_fp_hdr_t *fp_hdr;
	u_char *fp_buf;
	int hooklen;

	fp_buf = malloc(fp_buf_len);

	if (fp_buf == NULL) {
		errnosv = ENOMEM;
		if (_gNgDebugLevel >= 1)
			NGLOG("malloc");
		errno = errnosv;
		goto out;
	}

	memset(fp_buf, 0, fp_buf_len);
	/* Read packet */
	rtn = netfpc_recv(ds, fp_buf, fp_buf_len, 0, NULL);
	if (rtn < NG_FP_HDR_SIZE) {
		errnosv = errno;
		if (_gNgDebugLevel >= 1)
			NGLOG("netfpc_recv");
		errno = errnosv;
		goto out;
	}

	fp_hdr = (ng_fp_hdr_t *)fp_buf;
	hooklen = fp_hdr->len << 2;
	/* Copy hook name */
	if (hooklen && hook != NULL)
		snprintf(hook, hooklen, "%s", fp_hdr->path);

	if (fp_hdr->error) {
		if (_gNgDebugLevel >= 1)
			NGLOG("error code in message");
		errno = fp_hdr->error;
		goto out;
	}

	rtn -= (NG_FP_HDR_SIZE + hooklen);
	memcpy(buf, fp_buf + NG_FP_HDR_SIZE + hooklen, rtn);
	/* Debugging */
	if (_gNgDebugLevel >= 2) {
		NGLOGX("READ %s from hook \"%s\" (%d bytes)",
		       rtn ? "PACKET" : "EOF", fp_hdr->path, rtn);
		if (_gNgDebugLevel >= 3)
			_NgDebugBytes(buf, rtn);
	}

	free(fp_buf);
	/* Done */
	return (rtn);
out:
	if (fp_buf)
		free(fp_buf);
	return -1;	
}

#if 0
/*
 * Read a packet and assoicated control info from a data socket
 * Returns -1 if error and sets errno.
 */
int
NgRecvDataControl(int ds, u_char * buf, size_t len, u_char* ctrl_buf, size_t ctrl_len, char *hook)
{
	u_char frombuf[NG_HOOKLEN + sizeof(struct sockaddr_ng)];
	struct sockaddr_ng *const from = (struct sockaddr_ng *) frombuf;
	int fromlen = sizeof(frombuf);
	int rtn, errnosv;
	struct iovec iov;
	struct msghdr mhdr;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = buf;
	iov.iov_len = len;

	memset(&mhdr, 0, sizeof(mhdr));
    	mhdr.msg_iov = &iov;
    	mhdr.msg_iovlen = 1;
    	mhdr.msg_control = (caddr_t)ctrl_buf;
    	mhdr.msg_controllen = ctrl_len;
	mhdr.msg_name = (caddr_t)from;
	mhdr.msg_namelen = fromlen;

	/* Read packet */
	rtn = netfpc_recvmsg(ds, &mhdr, 0, NULL);
	if (rtn < 0) {
		errnosv = errno;
		if (_gNgDebugLevel >= 1)
			NGLOG("netfpc_recvmsg");
		errno = errnosv;
		return (-1);
	}

	/* Copy hook name */
	if (hook != NULL)
		snprintf(hook, NG_HOOKLEN + 1, "%s", from->sg_data);

	/* Debugging */
	if (_gNgDebugLevel >= 2) {
		NGLOGX("READ %s from hook \"%s\" (%d bytes)",
		       rtn ? "PACKET" : "EOF", from->sg_data, rtn);
		if (_gNgDebugLevel >= 3)
			_NgDebugBytes(buf, rtn);
	}

	/* Done */
	return (rtn);
}
#endif

/*
 * Write a packet to a data socket. The packet will be sent
 * out the corresponding node on the specified hook.
 * Returns -1 if error and sets errno.
 */
int
NgSendData(int ds, const char *hook, const u_char * buf, size_t len)
{
	int errnosv;
	int hooklen = NG_HOOKLEN + 1;
	ng_fp_hdr_t *fp_hdr;
	int fp_hdr_len;
	u_char *fp_buf = malloc(len + hooklen);

	if (fp_buf == NULL) {
		errnosv = ENOMEM;
		if (_gNgDebugLevel >= 1)
			NGLOG("malloc");
		errno = errnosv;
		goto out;
	}

	memset(fp_buf, 0, len + hooklen);
	fp_hdr = (ng_fp_hdr_t *)fp_buf;
	/* Set up destination hook */
	snprintf(fp_hdr->path, NG_HOOKLEN + 1, "%s", hook);
	fp_hdr->error = 0;
	fp_hdr->len = (strlen(fp_hdr->path) + 3) >> 2;
	fp_hdr_len = NG_FP_HDR_SIZE + (fp_hdr->len << 2);

	/* Debugging */
	if (_gNgDebugLevel >= 2) {
		NGLOGX("WRITE PACKET to hook \"%s\" (%d bytes)", hook, len);
		if (_gNgDebugLevel >= 3)
			_NgDebugBytes(buf, len);
	}

	memcpy(fp_buf + fp_hdr_len, buf, len);
	/* Send packet */
	if (netfpc_send(ds, fp_buf, len + fp_hdr_len, 0, NETFPC_MSGTYPE_VNB) < 0) {
		errnosv = errno;
		if (_gNgDebugLevel >= 1)
			NGLOG("netfpc_send(%s)", hook);
		errno = errnosv;
		goto out;
	}

	free(fp_buf);

	/* Done */
	return (0);
out:
	if (fp_buf)
		free(fp_buf);
	return -1;
}

#if 0
/*
 * Write a packet to a data socket. The packet 
 * and associated control info will be sent
 * out the corresponding node on the specified hook.
 * Returns -1 if error and sets errno.
 */
int
NgSendDataControl(int ds, const char *hook, const u_char * buf, size_t len, const u_char *ctrl_buf, size_t ctrl_len)
{
	u_char sgbuf[NG_HOOKLEN + sizeof(struct sockaddr_ng)];
	struct sockaddr_ng *const sg = (struct sockaddr_ng *) sgbuf;
	int errnosv;
	struct iovec iov;
	struct msghdr mhdr;

	/* Set up destination hook */
	sg->sg_family = AF_NETGRAPH;
	snprintf(sg->sg_data, NG_HOOKLEN + 1, "%s", hook);
	sg->sg_len = strlen(sg->sg_data) + 3;

	/* Debugging */
	if (_gNgDebugLevel >= 2) {
		NGLOGX("WRITE PACKET to hook \"%s\" (%d bytes)", hook, len);
		_NgDebugSockaddr(sg);
		if (_gNgDebugLevel >= 3)
			_NgDebugBytes(buf, len);
	}

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = (char *)buf;
	iov.iov_len = len;

	memset(&mhdr, 0, sizeof(mhdr));
    	mhdr.msg_iov = &iov;
    	mhdr.msg_iovlen = 1;
    	mhdr.msg_control = (caddr_t)ctrl_buf;
    	mhdr.msg_controllen = ctrl_len;
	mhdr.msg_name = (caddr_t)sg;
	mhdr.msg_namelen = sg->sg_len;

	/* Send packet */
	
	if (netfpc_sendmsg(ds, &mhdr, 0) < 0) {
		errnosv = errno;
		if (_gNgDebugLevel >= 1)
			NGLOG("netfpc_sendmsg(%s)", sg->sg_data);
		errno = errnosv;
		return (-1);
	}

	/* Done */
	return (0);
}
#endif
