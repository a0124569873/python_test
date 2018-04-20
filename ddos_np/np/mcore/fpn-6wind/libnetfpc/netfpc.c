/*
 * Copyright(c) 2007 6WIND
 * $Id: netfpc.c,v 1.3 2008-01-16 17:30:55 matz Exp $
 */
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#include "netfpc.h"

ssize_t netfpc_recv(int s, void *buf, size_t len, int flags, uint16_t *type)
{
	struct msghdr mh;
	struct netfpc_hdr hdr;
	struct iovec iov[2];
	ssize_t rcvlen;

	iov[0].iov_base = &hdr;
	iov[0].iov_len = NETFPC_HDRSIZE;
	iov[1].iov_base = buf;
	iov[1].iov_len = len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_iov = iov;
	mh.msg_iovlen = 2;

	if (!(flags & (MSG_DONTWAIT | MSG_NO_TIMEOUT))) {
		struct timeval timeout;
		fd_set fpc_fd;
		int ready;

		/* Initialize the set of active sockets. */
		FD_ZERO(&fpc_fd);
		FD_SET(s, &fpc_fd);

		/* Use a fix timeout of 1 second for now */
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		/* Wait for input and exit in error if timeout occurs */
		ready = select(s+1, &fpc_fd, NULL, NULL, &timeout);
		if (ready <= 0) 
			return -1;
	}

	rcvlen = recvmsg(s, &mh, flags & ~MSG_NO_TIMEOUT);
	if (rcvlen == 0)
		return 0;

	if (rcvlen < (int)NETFPC_HDRSIZE)
		return -1;

	if (type != NULL)
		*type = htons(hdr.type);

	rcvlen -= NETFPC_HDRSIZE;
	return rcvlen;
}

int netfpc_send(int s, const void *buf, size_t len, int flags, uint16_t type)
{
	struct msghdr mh;
	struct netfpc_hdr hdr;
	struct iovec iov[2];
	uint16_t slen;

	slen = len & 0xffff;

	hdr.type = htons(type);
	hdr.len = htons(slen);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = NETFPC_HDRSIZE;
	iov[1].iov_base = (void *)buf;
	iov[1].iov_len = len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_iov = iov;
	mh.msg_iovlen = 1 + (len ? 1 : 0);

	return sendmsg(s, &mh, flags & ~MSG_NO_TIMEOUT);
}

/* return socket or -1 */
int netfpc_open(const char *ifname)
{
	struct addrinfo hints, *res = NULL;  
	char address[80];
	int err;
	int s;
	pid_t pid;
	static int id = 0;

	pid = getpid();
	snprintf(address, sizeof(address), "fe80::%x:%x:%x%%%s", 
			(pid >> 16) & 0xFFFF,
			pid & 0xFFFF,
			id++,
			ifname ? ifname : "fpn0");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_NETFPC;

	if ((err = getaddrinfo(address, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "Error getaddrinfo: %s\n", gai_strerror(err));
		fprintf(stderr, "using address=%s\n", address);
		return -1;
	}

	if ((s = socket(res->ai_family, res->ai_socktype, 
					res->ai_protocol)) < 0) {
		perror("socket");
		freeaddrinfo(res);
		return -1;
	}

	if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
		perror("connect");
		freeaddrinfo(res);
		close(s);
		return -1;
	}

	freeaddrinfo(res);
	return s;
}
