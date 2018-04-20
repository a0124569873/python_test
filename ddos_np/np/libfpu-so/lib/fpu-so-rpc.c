/*
 * Copyright(c) 2013 6WIND, All rights reserved
 */

#define _BSD_SOURCE /* for timeradd, timercmp, ... */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/syscall.h>

#include "net/fp-socket.h"
#include "netinet/fp-in.h"

#include "fpu-rpc-var.h"
#include "libfpu-rpc.h"

#include "libfpu-so.h"
#include "fpu-so-rpc.h"

/* XXX use the one from fpn ? */
#define fpn_wmb() __sync_synchronize()
#define fpn_rmb() __sync_synchronize()

struct fpu_rpc_fp_shmem *fp_shmem;
__thread struct fpu_rpc_app_shmem *app_shmem;
__thread int unix_sock;

/* associates a file descriptor to a fast path fd */
struct fd_t fd2fpfd[FPU_SO_MAX_FD];

/* keeps track of file descriptor associated to a fast path fd */
struct fpfd_t fpfdtable[FPU_SO_MAX_FD];

/* associates a file descriptor to a fast path epoll */
struct epoll_t fd2ep[FPU_SO_MAX_FD];

static int get_fd(void)
{
	int fd;

	fd = open("/dev/null", O_RDWR);

	return fd;
}

static void put_fd(int fd)
{
	close(fd);
}

static int get_fd_val(int fd)
{
	int tmp, err;

	tmp = open("/dev/null", O_RDWR);
	if (tmp < 0)
		return -1;

	if (dup2(tmp, fd) < 0) {
		err = errno;
		close(tmp);
		errno = err;
		return -1;
	}

	close(tmp);
	return fd;
}

void fpu_so_rpc_preinit(void)
{
	unsigned int i;

	memset(fd2fpfd, 0, sizeof(fd2fpfd));
	for (i = 0; i < (sizeof(fd2fpfd) / sizeof(fd2fpfd[0])); i++) {
		fd2fpfd[i].fpfd = -1;
	}

	memset(fpfdtable, 0, sizeof(fpfdtable));
	for (i = 0; i < (sizeof(fpfdtable) / sizeof(fpfdtable[0])); i++) {
		LIST_INIT(&fpfdtable[i].ephead);
		LIST_INIT(&fpfdtable[i].fdhead);
	}

	memset(fd2ep, 0, sizeof(fd2ep));
	for (i = 0; i < (sizeof(fd2ep) / sizeof(fd2ep[0])); i++) {
		LIST_INIT(&fd2ep[i].fpfdhead);
	}
}

int fpu_so_rpc_init(void)
{
	char app_shmname[64];
	int s, id;

	s = fpu_rpc_connect(&id);
	if (s < 0) {
		return -1;
	}

	snprintf(app_shmname, sizeof(app_shmname),
		 "fpu-so-appshm-%d-%d", (int)syscall(SYS_gettid), id);

	app_shmem = fpu_rpc_create_app_shmem(app_shmname);
	if (app_shmem == NULL) {
		close(s);
		return -1;
	}

	if (fpu_rpc_register(s, app_shmname, app_shmem) < 0) {
		close(s);
		fpu_rpc_delete_app_shmem(app_shmname);
		return -1;
	}

	fp_shmem = fpu_rpc_map_fp_shmem();
	if (fp_shmem == NULL) {
		close(s);
		return -1;
	}

	/* unix_sock is global (per-thread) */
	unix_sock = s;
	return 0;
}

static inline int fpu_so_fd2fpfd(int32_t fd)
{
	if (fd < 0 || fd >= FPU_SO_MAX_FD)
		return -1;
	return fd2fpfd[fd].fpfd;
}

int fpu_so_rpc_socket(int domain, int type, int protocol)
{
	int fd, fpfd;

	fpu_so_log(DEBUG, RPC, "called (domain=%d type=%d proto=%d)\n",
		  domain, type, protocol);

	fd = get_fd();
	if (fd < 0) {
		/* errno is already set by open */
		return fd;
	}

	app_shmem->type = SOCKET;

	app_shmem->socket.fd = fd;
	/* XXX there is no FP_AF_* today */
	app_shmem->socket.domain = domain;
	if (domain != AF_INET) {
		/* first put fd, as it does a close, then set errno */
		put_fd(fd);
		errno = EAFNOSUPPORT;
		return -1;
	}

	switch (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) {
		case SOCK_DGRAM:
			if (protocol == 0)
				protocol = IPPROTO_UDP;
			app_shmem->socket.type = FP_SOCK_DGRAM;
			break;
		case SOCK_STREAM:
			if (protocol == 0)
				protocol = IPPROTO_TCP;
			app_shmem->socket.type = FP_SOCK_STREAM;
			break;
		default:
			put_fd(fd);
			errno = EPROTOTYPE;
			return -1;
	}

	switch (protocol) {
		case IPPROTO_TCP:
			app_shmem->socket.protocol = FP_IPPROTO_TCP;
			break;
		case IPPROTO_UDP:
			app_shmem->socket.protocol = FP_IPPROTO_UDP;
			break;
		default:
			put_fd(fd);
			errno = EPROTONOSUPPORT;
			return -1;
	}

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->socket.ret < 0) {
		put_fd(fd);
		errno = -app_shmem->socket.ret;
		return -1;
	}

	fpfd = app_shmem->socket.fpfd;
	fd2fpfd[fd].fpfd = fpfd;
	LIST_INSERT_HEAD(&fpfdtable[fpfd].fdhead, &fd2fpfd[fd], fdlist);

	if (type & SOCK_NONBLOCK)
		fp_shmem->sockets[fpfd] |= FD_F_NONBLOCK;

	/* XXX todo */
	if (type & SOCK_CLOEXEC) {
		(void)0;
	}

	return app_shmem->socket.ret;
}

int fpu_so_rpc_connect4(int fd, const struct sockaddr *addr,
			socklen_t addrlen)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	char buf[INET_ADDRSTRLEN];

	fpu_so_log(DEBUG, RPC, "called (fd=%d addr=%s alen=%d)\n",
		  fd, inet_ntop(sin->sin_family, &sin->sin_addr.s_addr,
				buf, sizeof(buf)), addrlen);

	if (sin->sin_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	if (addrlen != sizeof(*sin)) {
		errno = EINVAL;
		return -1;
	}

	app_shmem->type = CONNECT4;
	app_shmem->connect4.fd = fd;
	memcpy(&app_shmem->connect4.addr, &sin->sin_addr,
	       sizeof(app_shmem->connect4.addr));
	app_shmem->connect4.port = sin->sin_port;

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->connect4.ret < 0) {
		errno = -app_shmem->connect4.ret;
		return -1;
	}

	return app_shmem->connect4.ret;
}

int fpu_so_rpc_bind4(int fd, const struct sockaddr *addr,
		     socklen_t addrlen)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	char buf[INET_ADDRSTRLEN];

	fpu_so_log(DEBUG, RPC, "called (fd=%d addr=%s alen=%d)\n",
		  fd, inet_ntop(sin->sin_family, &sin->sin_addr.s_addr,
				buf, sizeof(buf)), addrlen);


	if (sin->sin_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	if (addrlen != sizeof(*sin)) {
		errno = EINVAL;
		return -1;
	}

	app_shmem->type = BIND4;
	app_shmem->bind4.fd = fd;
	memcpy(&app_shmem->bind4.addr, &sin->sin_addr,
	       sizeof(app_shmem->bind4.addr));
	app_shmem->bind4.port = sin->sin_port;

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->bind4.ret < 0) {
		errno = -app_shmem->bind4.ret;
		return -1;
	}

	return app_shmem->bind4.ret;
}

int fpu_so_rpc_listen(int fd, int backlog)
{
	fpu_so_log(DEBUG, RPC, "called (fd=%d backlog=%d)\n",
		  fd, backlog);

	app_shmem->type = LISTEN;
	app_shmem->listen.fd = fd;
	app_shmem->listen.backlog = backlog;

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->listen.ret < 0) {
		errno = -app_shmem->listen.ret;
		return -1;
	}

	return app_shmem->listen.ret;
}


int fpu_so_rpc_accept4(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int newfd, fpfd, newfpfd;

	fpu_so_log(DEBUG, RPC, "called (fd=%d addr=%p)\n",
		  fd, addr);

	if ((addr != NULL) && (addrlen == NULL)) {
		errno = EINVAL;
		return -1;
	}

	newfd = get_fd();
	if (newfd < 0) {
		fpu_so_log(ERR, RPC, "%s: could not get fd\n", __func__);
		return newfd;
	}

	app_shmem->type = ACCEPT4;
	app_shmem->accept4.fd = fd;
	app_shmem->accept4.newfd = newfd;
	memset(&app_shmem->accept4.addr, 0, sizeof(app_shmem->accept4.addr));

	/* wait for something to read on server fd */
	fpfd = fpu_so_fd2fpfd(fd);
	while ((fp_shmem->sockets[fpfd] & FD_F_READ) != FD_F_READ);

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->accept4.ret < 0) {
		put_fd(newfd);
		errno = -app_shmem->accept4.ret;
		return -1;
	}

	newfpfd = app_shmem->accept4.fpfd;
	fd2fpfd[newfd].fpfd = newfpfd;
	LIST_INSERT_HEAD(&fpfdtable[newfpfd].fdhead, &fd2fpfd[newfd], fdlist);

	if (addr) {
		struct sockaddr_in sin;
		uint32_t min_size;

		min_size = (*addrlen < sizeof(sin) ? *addrlen : sizeof(sin));

		/* Populate sock_addr */
		sin.sin_family = AF_INET;
		memcpy(&sin.sin_addr, &app_shmem->accept4.addr,
		       sizeof(app_shmem->accept4.addr));
		sin.sin_port = app_shmem->accept4.port;

		/* Copy socket addr and length */
		*addrlen = sizeof(sin);
		memcpy(addr, &sin, min_size);
	}

	return app_shmem->accept4.ret;
}

int fpu_so_rpc_write(int fd, const void *buf, size_t len)
{
	int fpfd;

	fpu_so_log(DEBUG, RPC, "called (fd=%d buf=%p len=%d)\n",
		  fd, buf, (int)len);

	if (len > sizeof(app_shmem->write.buf)) {
		errno = EFBIG;
		return -1;
	}

	app_shmem->type = WRITE;
	app_shmem->write.fd = fd;
	app_shmem->write.len = len;
	memcpy(&app_shmem->write.buf, buf, len);

	/* in blocking mode, wait so that we can write on fd */
	fpfd = fpu_so_fd2fpfd(fd);
	if (!(fp_shmem->sockets[fpfd] & FD_F_NONBLOCK))
		while ((fp_shmem->sockets[fpfd] & FD_F_WRITE) != FD_F_WRITE);

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->write.ret < 0) {
		errno = -app_shmem->write.ret;
		return -1;
	}

	return app_shmem->write.ret;
}

int fpu_so_rpc_send(int fd, const void *buf, size_t len, int flags)
{
	int fpfd;

	fpu_so_log(DEBUG, RPC, "called (fd=%d buf=%p len=%d flags=0x%x)\n",
		  fd, buf, (int)len, flags);

	if (len > sizeof(app_shmem->send.buf)) {
		errno = EFBIG;
		return -1;
	}
	/* no flag supported yet */
	if (flags != 0) {
		errno = EINVAL;
		return -1;
	}

	app_shmem->type = SEND;
	app_shmem->send.fd = fd;
	app_shmem->send.len = len;
	app_shmem->send.flags = 0;
	memcpy(&app_shmem->send.buf, buf, len);

	/* in blocking mode, wait so that we can write on fd */
	fpfd = fpu_so_fd2fpfd(fd);
	if (!(fp_shmem->sockets[fpfd] & FD_F_NONBLOCK))
		while ((fp_shmem->sockets[fpfd] & FD_F_WRITE) != FD_F_WRITE);

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->send.ret < 0) {
		errno = -app_shmem->send.ret;
		return -1;
	}

	return app_shmem->send.ret;
}

int fpu_so_rpc_sendto4(int fd, const void *buf, size_t len, int flags,
		       const struct sockaddr *dest_addr, socklen_t addrlen)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)dest_addr;
	int fpfd;

	fpu_so_log(DEBUG, RPC, "called (fd=%d buf=%p len=%d)\n",
		  fd, buf, (int)len);

	if (sin->sin_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	if (addrlen != sizeof(*sin)) {
		errno = EINVAL;
		return -1;
	}
	if (len > sizeof(app_shmem->send.buf)) {
		errno = EFBIG;
		return -1;
	}
	/* no flag supported yet */
	if (flags != 0) {
		errno = EINVAL;
		return -1;
	}

	app_shmem->type = SENDTO4;
	app_shmem->sendto4.fd = fd;
	app_shmem->sendto4.len = len;
	app_shmem->sendto4.flags = 0;
	memcpy(&app_shmem->sendto4.buf, buf, len);

	memcpy(&app_shmem->sendto4.addr, &sin->sin_addr,
	       sizeof(app_shmem->sendto4.addr));
	app_shmem->sendto4.port = sin->sin_port;

	/* in blocking mode, wait so that we can write on fd */
	fpfd = fpu_so_fd2fpfd(fd);
	if (!(fp_shmem->sockets[fpfd] & FD_F_NONBLOCK))
		while ((fp_shmem->sockets[fpfd] & FD_F_WRITE) != FD_F_WRITE);

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->sendto4.ret < 0) {
		errno = -app_shmem->sendto4.ret;
		return -1;
	}

	return app_shmem->sendto4.ret;
}

int fpu_so_rpc_read(int fd, void *buf, size_t len)
{
	int fpfd;

	fpu_so_log(DEBUG, RPC, "called (fd=%d buf=%p len=%d)\n",
		  fd, buf, (int)len);

	if (len > sizeof(app_shmem->read.buf))
		len = sizeof(app_shmem->read.buf);

	app_shmem->type = READ;
	app_shmem->read.fd = fd;
	app_shmem->read.len = len;
	memset(&app_shmem->read.buf, 0, len);

	/* in blocking mode, wait so that we can read on fd */
	fpfd = fpu_so_fd2fpfd(fd);
	if (!(fp_shmem->sockets[fpfd] & FD_F_NONBLOCK))
		while ((fp_shmem->sockets[fpfd] & FD_F_READ) != FD_F_READ);

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->read.ret < 0) {
		errno = -app_shmem->read.ret;
		return -1;
	}

	memcpy(buf, &app_shmem->read.buf, app_shmem->read.ret);

	return app_shmem->read.ret;
}

int fpu_so_rpc_recv(int fd, void *buf, size_t len, int flags)
{
	int fpfd;

	fpu_so_log(DEBUG, RPC, "called (fd=%d buf=%p len=%d flags=0x%x)\n",
		  fd, buf, (int)len, flags);

	/* only MSG_PEEK supported yet */
	if ((flags & (~(MSG_PEEK))) != 0) {
		errno = EINVAL;
		return -1;
	}

	if (len > sizeof(app_shmem->recv.buf))
		len = sizeof(app_shmem->recv.buf);

	app_shmem->type = RECV;
	app_shmem->recv.fd = fd;
	app_shmem->recv.len = len;
	memset(&app_shmem->recv.buf, 0, len);
	app_shmem->recv.flags = 0;
	if (flags & MSG_PEEK)
		app_shmem->recv.flags |= FP_MSG_PEEK;

	/* in blocking mode, wait so that we can read on fd */
	fpfd = fpu_so_fd2fpfd(fd);
	if (!(fp_shmem->sockets[fpfd] & FD_F_NONBLOCK))
		while ((fp_shmem->sockets[fpfd] & FD_F_READ) != FD_F_READ);

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->recv.ret < 0) {
		errno = -app_shmem->recv.ret;
		return -1;
	}

	memcpy(buf, &app_shmem->recv.buf, app_shmem->recv.ret);

	return app_shmem->recv.ret;
}

int fpu_so_rpc_recvfrom4(int fd, void *buf, size_t len, int flags,
			 struct sockaddr *src_addr, socklen_t *addrlen)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)src_addr;
	int fpfd;

	fpu_so_log(DEBUG, RPC, "called (fd=%d buf=%p len=%d flags=0x%x)\n",
		  fd, buf, (int)len, flags);

	if (addrlen && (*addrlen != sizeof(*sin))) {
		errno = EINVAL;
		return -1;
	}
	/* only MSG_PEEK supported yet */
	if ((flags & (~(MSG_PEEK))) != 0) {
		errno = EINVAL;
		return -1;
	}

	if (len > sizeof(app_shmem->recvfrom4.buf))
		len = sizeof(app_shmem->recvfrom4.buf);

	app_shmem->type = RECVFROM4;
	app_shmem->recvfrom4.fd = fd;
	app_shmem->recvfrom4.len = len;
	memset(&app_shmem->recvfrom4.buf, 0, len);
	app_shmem->recvfrom4.flags = 0;
	if (flags & MSG_PEEK)
		app_shmem->recvfrom4.flags |= FP_MSG_PEEK;

	if (src_addr)
		app_shmem->recvfrom4.port = 1;
	else
		app_shmem->recvfrom4.port = 0;

	/* XXX: flags are not taken into account,
	 need to change fp_so_recvfrom4 api to add flags */

	/* in blocking mode, wait so that we can read on fd */
	fpfd = fpu_so_fd2fpfd(fd);
	if (!(fp_shmem->sockets[fpfd] & FD_F_NONBLOCK))
		while ((fp_shmem->sockets[fpfd] & FD_F_READ) != FD_F_READ);

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->recvfrom4.ret < 0) {
		errno = -app_shmem->recvfrom4.ret;
		return -1;
	}

	if (src_addr) {
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, &app_shmem->recvfrom4.addr,
		       sizeof(sin->sin_addr));
		sin->sin_port = app_shmem->recvfrom4.port;

		fpu_so_log(DEBUG, RPC, "recvfrom4(%x:%d)\n",
		       ntohl((uint32_t)sin->sin_addr.s_addr),
		       ntohs(sin->sin_port));
	}

	memcpy(buf, &app_shmem->recvfrom4.buf, app_shmem->recvfrom4.ret);

	return app_shmem->recvfrom4.ret;
}

int fpu_so_rpc_close(int fd)
{
	int fpfd;

	fpu_so_log(DEBUG, RPC, "called (fd=%d)\n", fd);

	fpfd = fd2fpfd[fd].fpfd;
	if (fpfd == -1) {
		errno = EBADF;
		return -1;
	}

	LIST_REMOVE(&fd2fpfd[fd], fdlist);
	/* No remaining fpfd, clean all epoll instances */
	if (LIST_EMPTY(&fpfdtable[fpfd].fdhead)) {
		struct epoll_fpfd_t *tmp;
		LIST_FOREACH(tmp, &fpfdtable[fpfd].ephead, eplist) {
			fpu_so_rpc_epoll_ctl((tmp->ep - fd2ep), EPOLL_CTL_DEL,
			                     fd, NULL, 0);
		}
	}
	fd2fpfd[fd].fpfd = -1;
	app_shmem->type = CLOSE;
	app_shmem->close.fd = fd;

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->close.ret < 0) {
		errno = -app_shmem->close.ret;
		return -1;
	}

	put_fd(fd);
	return app_shmem->close.ret;
}

int fpu_so_rpc_shutdown(int fd, int how)
{
	fpu_so_log(DEBUG, RPC, "called (fd=%d)\n", fd);
	app_shmem->type = SHUTDOWN;
	app_shmem->shutdown.fd = fd;
	app_shmem->shutdown.how = how;

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->shutdown.ret < 0) {
		errno = -app_shmem->shutdown.ret;
		return -1;
	}

	return app_shmem->shutdown.ret;
}

int fpu_so_rpc_getsockname4(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;

	fpu_so_log(DEBUG, RPC, "called (fd=%d)\n", fd);

	if (*addrlen != sizeof(*sin)) {
		errno = EINVAL;
		return -1;
	}

	app_shmem->type = GETSOCKNAME4;
	app_shmem->getsockname4.fd = fd;

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->getsockname4.ret < 0) {
		errno = -app_shmem->getsockname4.ret;
		return -1;
	}

	memcpy(&sin->sin_addr, &app_shmem->getsockname4.addr,
	       sizeof(sin->sin_addr));
	sin->sin_port = app_shmem->getsockname4.port;

	*addrlen = sizeof(*sin);

	return app_shmem->getsockname4.ret;
}

int fpu_so_rpc_getpeername4(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;

	fpu_so_log(DEBUG, RPC, "called (fd=%d)\n", fd);

	if (*addrlen != sizeof(*sin)) {
		errno = EINVAL;
		return -1;
	}

	app_shmem->type = GETPEERNAME4;
	app_shmem->getpeername4.fd = fd;

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->getpeername4.ret < 0) {
		errno = -app_shmem->getpeername4.ret;
		return -1;
	}

	sin->sin_family = AF_INET;
	memcpy(&sin->sin_addr, &app_shmem->getpeername4.addr,
	       sizeof(sin->sin_addr));
	sin->sin_port = app_shmem->getpeername4.port;

	*addrlen = sizeof(*sin);

	return app_shmem->getpeername4.ret;
}

int fpu_so_rpc_fcntl(int fd, int cmd, ... /* arg */)
{
	int ret = 0, fpfd;
	va_list ap;
	void *arg;

	fpu_so_log(DEBUG, RPC, "called (fd=%d, cmd=%d)\n", fd, cmd);

	va_start(ap, cmd);
	arg = va_arg(ap, void *);
	va_end(ap);

	fpfd = fpu_so_fd2fpfd(fd);

	switch (cmd) {
		case F_GETFL:
			if (fp_shmem->sockets[fpfd] & FD_F_NONBLOCK)
				ret = O_NONBLOCK;
			break;
		case F_SETFL:
			if ((long) arg & O_NONBLOCK)
				fp_shmem->sockets[fpfd] |= FD_F_NONBLOCK;
			break;
		case F_DUPFD:
			ret = fpu_so_rpc_dup(fd);
			break;
		default:
			errno = EINVAL;
			return -1;
	}

	return ret;
}

int fpu_so_rpc_ioctl(int fd, unsigned long int req, ... /* arg */)
{
	fpu_so_log(DEBUG, RPC, "called (fd=%d, req=0x%lx)\n", fd, req);

	(void)fd;
	(void)req;
	errno = EINVAL;
	return -1;
}

static int check_poll_event(short events, int fd)
{
	int ret = 0, fpfd;
	uint8_t flags;

	fpfd = fpu_so_fd2fpfd(fd);
	flags = fp_shmem->sockets[fpfd];

	if ((flags & FD_F_VALID) == 0)
		return 0;

	if (events & POLLIN)
		if (flags & FD_F_READ) {
			fpu_so_log(DEBUG, RPC, "%s: read\n", __func__);
			ret |= POLLIN;
		}

	if (events & POLLOUT)
		if (flags & FD_F_WRITE) {
			fpu_so_log(DEBUG, RPC, "%s: write\n", __func__);
			ret |= POLLOUT;
		}

	return ret;
}

int fpu_so_rpc_poll(struct pollfd fds[], nfds_t nfds, int timeout)
{
	nfds_t i;
	int fp_nfds = 0;
	struct timeval now;
	struct timeval out;
	struct timeval tv_timeout;

	/* don't log, this function is called in a loop */
	/* fpu_so_log(DEBUG, RPC, "called\n"); */

	gettimeofday(&now, NULL);
	tv_timeout.tv_sec = timeout / 1000;
	tv_timeout.tv_usec = (timeout % 1000) * 1000;
	timeradd(&tv_timeout, &now, &out);

	do {
		for (i = 0; i < nfds; i++) {
			int fd = fds[i].fd;

			/* skip too large or negative fd (this is allowed) */
			if (fd >= FPU_SO_MAX_FD || fd < 0)
				continue;

			fds[i].revents = check_poll_event(fds[i].events, fd);
			if (fds[i].revents)
				fp_nfds++;
		}

		/* timeout expired */
		gettimeofday(&now, NULL);
		if (timercmp(&now, &out, >=))
			break;

	} while (fp_nfds == 0);

	return fp_nfds;
}

int fpu_so_rpc_epoll_create1(int epfd, int flags)
{
	fpu_so_log(DEBUG, RPC, "called\n");
	fd2ep[epfd].flags = flags;
	fd2ep[epfd].used = 1;
	fpu_so_log(DEBUG, EPOLL, "new epoll instance epfd=%d\n", epfd);

	return epfd;
}

void fpu_so_rpc_epoll_destroy(int epfd)
{
	struct epoll_fpfd_t *tmp;

	fd2ep[epfd].used = 0;
	while ((tmp = LIST_FIRST(&fd2ep[epfd].fpfdhead))) {
		LIST_REMOVE(tmp, fpfdlist);
		LIST_REMOVE(tmp, eplist);
		free(tmp);
	}
	fpu_so_log(DEBUG, EPOLL, "epoll instance deleted epfd=%d\n", epfd);
}

void fpu_so_rpc_epoll_duplicate(int oldfd, int newfd)
{
	struct epoll_fpfd_t *tmp;

	fpu_so_rpc_epoll_create1(newfd, fd2ep[oldfd].flags);

	LIST_FOREACH(tmp, &fd2ep[oldfd].fpfdhead, fpfdlist) {
		fpu_so_rpc_epoll_ctl(newfd, EPOLL_CTL_ADD, tmp->fd, &tmp->ev,
		                     tmp->prev);
	}
	fpu_so_log(DEBUG, EPOLL, "epoll instance duplicated epfd=%d\n", newfd);
}

/* epfd and fd must be checked before calling fpu_so_rpc_epoll_ctl */
int fpu_so_rpc_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event,
                         int prev)
{
	int fpfd = fd2fpfd[fd].fpfd;
	struct epoll_t *ep = &fd2ep[epfd];
	struct fpfd_t *fpfdp = &fpfdtable[fpfd];
	struct epoll_fpfd_t *found;

	fpu_so_log(DEBUG, RPC, "called\n");
	LIST_FOREACH(found, &fpfdp->ephead, eplist) {
		/* We can have various fds pointing to one fpfd,
		 * this is because of dup() (see man epoll) */
		if (found->ep == ep && found->fd == fd) break;
	}

	switch(op) {
		case EPOLL_CTL_ADD:
			if (found) {
				errno = EEXIST;
				return -1;
			}

			found = malloc(sizeof(*found));
			if (!found) {
				errno = ENOMEM;
				return -1;
			}
			found->prev = prev;
			found->fd = fd;
			memcpy(&(found->ev), event, sizeof(*event));
			found->ep = ep;
			LIST_INSERT_HEAD(&ep->fpfdhead, found, fpfdlist);
			found->fpfd = fpfdp;
			LIST_INSERT_HEAD(&fpfdp->ephead, found, eplist);

			fpu_so_log(DEBUG, EPOLL,
			           "associated fd=%d to epfd=%d\n", fd, epfd);
		break;

		case EPOLL_CTL_MOD:
			if (!found) {
				errno = ENOENT;
				return -1;
			}

			memcpy(&(found->ev), event, sizeof(*event));
			fpu_so_log(DEBUG, EPOLL,
			           "updated fd=%d to epfd=%d\n", fd, epfd);
		break;

		case EPOLL_CTL_DEL:
			if (!found) {
				errno = ENOENT;
				return -1;
			}

			LIST_REMOVE(found, fpfdlist);
			LIST_REMOVE(found, eplist);
			free(found);
			fpu_so_log(DEBUG, EPOLL,
			           "removed fd=%d from epfd=%d\n", fd, epfd);
		break;

		default:
		return -1;
	}

	return 0;
}

/* TODO: handle EPOLLPRI etc... */
static int check_epoll_event(struct epoll_fpfd_t *epfdp)
{
	int ret = 0;
	uint8_t flags;
	int events = epfdp->ev.events;
	int fpfd = epfdp->fpfd - fpfdtable;

	flags = fp_shmem->sockets[fpfd];

	/* Needed for ONESHOT, see below */
	if (!events)
		return 0;

	if ((flags & FD_F_VALID) == 0)
		return 0;

	if (events & EPOLLIN)
		if (flags & FD_F_READ) {
			fpu_so_log(DEBUG, RPC, "%s: read\n", __func__);
			ret |= EPOLLIN;
		}

	if (events & EPOLLOUT)
		if (flags & FD_F_WRITE) {
			fpu_so_log(DEBUG, RPC, "%s: write\n", __func__);
			ret |= EPOLLOUT;
		}

	if (events & EPOLLET) {
		/* Found something that is different from last time */
		if (ret && ret != epfdp->prev)
			epfdp->prev = ret;
		else
			return 0;
	}

	/* Found something but we only want one shot, so clear events */
	if ((events & EPOLLONESHOT) && ret)
		epfdp->ev.events = 0;

	return ret;
}

/* epfd must be checked before calling fpu_so_rpc_epoll_wait */
int fpu_so_rpc_epoll_wait(int epfd, struct epoll_event *events, int maxevents)
{
	int nbevents = 0;
	struct epoll_fpfd_t *tmp;
	struct epoll_t *ep = &fd2ep[epfd];

	/* don't log, this function is called in a loop */
	/* fpu_so_log(DEBUG, RPC, "called\n"); */

	LIST_FOREACH(tmp, &ep->fpfdhead, fpfdlist) {
		events[nbevents].events = check_epoll_event(tmp);
		if (events[nbevents].events) {
			memcpy(&(events[nbevents].data), &(tmp->ev.data),
			       sizeof(events[0].data));
			nbevents++;
			if (nbevents >= maxevents)
				break;
		}
	}

	return nbevents;
}

static int check_select_event(fd_set *rfds, fd_set *wfds, int fd)
{
	int ret = 0, fpfd;
	uint8_t flags;

	fpfd = fpu_so_fd2fpfd(fd);
	flags = fp_shmem->sockets[fpfd];

	if ((flags & FD_F_VALID) == 0)
		return 0;

	if (rfds && FD_ISSET(fd, rfds)) {
		if (flags & FD_F_READ) {
			ret++;
			fpu_so_log(DEBUG, RPC, "%s: read\n", __func__);
		} else
			FD_CLR(fd, rfds);
	}

	if (wfds && FD_ISSET(fd, wfds)) {
		if (flags & FD_F_WRITE) {
			ret++;
			fpu_so_log(DEBUG, RPC, "%s: write\n", __func__);
		} else
			FD_CLR(fd, wfds);
	}

	return ret;
}


int fpu_so_rpc_select(int nfds, fd_set *readfds, fd_set *writefds,
		     fd_set *exceptfds, struct timeval *timeout)
{
	int i;
	int fp_nfds = 0;
	struct timeval now;
	struct timeval out;

	(void)exceptfds;

	/* don't log, this function is called in a loop */
	/* fpu_so_log(DEBUG, RPC, "called\n"); */

	if (timeout) {
		gettimeofday(&now, NULL);
		timeradd(timeout, &now, &out);
	}
	else
		memset(&out, 0, sizeof(out));

	do {
		for (i = 0; i < nfds; i++) {
			fp_nfds += check_select_event(readfds,
						      writefds, i);
		}

		if (fp_nfds == 0 && timeout) {
			/* timeout expired */
			gettimeofday(&now, NULL);
			if (timercmp(&now, &out, >=))
				break;
		}

	} while (fp_nfds == 0);

	if (fp_nfds && timeout)
		timersub(&out, &now, timeout);

	return fp_nfds;
}

int fpu_so_rpc_getsockopt(int sockfd, int level, int optname,
		   void *optval, socklen_t *optlen)
{
	app_shmem->type = GETSOCKOPT;
	app_shmem->getsockopt.fd = sockfd;

	switch (level) {
		case SOL_SOCKET:
			app_shmem->getsockopt.level = FP_SOL_SOCKET;
			break;
		default:
			app_shmem->getsockopt.level = level;
			break;
	}

	switch (optname) {
#define _PF(f) case f: app_shmem->getsockopt.optname = FP_##f ; break;
		_PF(SO_ACCEPTCONN)
		_PF(SO_REUSEADDR)
		_PF(SO_KEEPALIVE)
		_PF(SO_DONTROUTE)
		_PF(SO_BROADCAST)
		/* _PF(SO_USELOOPBACK) */
		_PF(SO_LINGER)
		/* _PF(SO_REUSEPORT) */
		_PF(SO_TIMESTAMP)
		_PF(SO_SNDBUF)
		_PF(SO_RCVBUF)
		_PF(SO_SNDLOWAT)
		_PF(SO_RCVLOWAT)
		_PF(SO_SNDTIMEO)
		_PF(SO_RCVTIMEO)
		_PF(SO_ERROR)
		_PF(SO_TYPE)
		/* _PF(SO_OVERFLOWED) */
		/* _PF(SO_NOHEADER) */
		/* _PF(SO_VRFID) */
		/* _PF(SO_DISPATCH_MASTER) */
		/* _PF(SO_DISPATCH_SLAVE) */
		/* _PF(SO_NO_BIND_DISPATCH) */
		/* _PF(SO_MAX_BIND_DISPATCH) */
		default:
			app_shmem->getsockopt.optname = optname;
			break;
#undef _PF
	}
	app_shmem->getsockopt.optlen = *optlen;

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->getsockopt.ret < 0) {
		errno = -app_shmem->getsockopt.ret;
		return -1;
	}

	memcpy(optval, &app_shmem->getsockopt.optval,
	       app_shmem->getsockopt.optlen);
	*optlen = app_shmem->getsockopt.optlen;

	return app_shmem->getsockopt.ret;
}

int fpu_so_rpc_setsockopt(int sockfd, int level, int optname,
		   const void *optval, socklen_t optlen)
{
	app_shmem->type = SETSOCKOPT;
	app_shmem->setsockopt.fd = sockfd;

	switch (level) {
		case SOL_SOCKET:
			level = FP_SOL_SOCKET;
			break;
		default:
			break;
	}

	app_shmem->setsockopt.level = level;

	switch (optname) {
#define _PF(f) case f: app_shmem->setsockopt.optname = FP_##f ; break;
		_PF(SO_ACCEPTCONN)
		_PF(SO_REUSEADDR)
		_PF(SO_KEEPALIVE)
		_PF(SO_DONTROUTE)
		_PF(SO_BROADCAST)
		/* _PF(SO_USELOOPBACK) */
		_PF(SO_LINGER)
		/* _PF(SO_REUSEPORT) */
		_PF(SO_TIMESTAMP)
		_PF(SO_SNDBUF)
		_PF(SO_RCVBUF)
		_PF(SO_SNDLOWAT)
		_PF(SO_RCVLOWAT)
		_PF(SO_SNDTIMEO)
		_PF(SO_RCVTIMEO)
		_PF(SO_ERROR)
		_PF(SO_TYPE)
		/* _PF(SO_OVERFLOWED) */
		/* _PF(SO_NOHEADER) */
		/* _PF(SO_VRFID) */
		/* _PF(SO_DISPATCH_MASTER) */
		/* _PF(SO_DISPATCH_SLAVE) */
		/* _PF(SO_NO_BIND_DISPATCH) */
		/* _PF(SO_MAX_BIND_DISPATCH) */
		default:
			app_shmem->setsockopt.optname = optname;
			break;
#undef _PF
	}

	memcpy(&app_shmem->setsockopt.optval, optval, optlen);
	app_shmem->setsockopt.optlen = optlen;

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->setsockopt.ret < 0) {
		errno = -app_shmem->setsockopt.ret;
		return -1;
	}

	return app_shmem->setsockopt.ret;
}

int fpu_so_rpc_dup2(int oldfd, int newfd)
{
	int newfpfd;

	fpu_so_log(DEBUG, RPC, "called (oldfd=%d, newfd=%d)\n", oldfd, newfd);

	if (oldfd < 0 || oldfd >= FPU_SO_MAX_FD ||
	    newfd < 0 || newfd >= FPU_SO_MAX_FD) {
		errno = EBADF;
		return -1;
	}

	/* we know that oldfd belongs to fpu_so. If newfd too, we have
	 * nothing to do. Else, we need to close it. */
	if (fd2fpfd[newfd].fpfd != -1) {
		if (get_fd_val(newfd) != newfd)
			return -1;
	}

	app_shmem->type = DUP2;
	app_shmem->dup2.oldfd = oldfd;
	app_shmem->dup2.newfd = newfd;

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->dup2.ret < 0) {
		errno = -app_shmem->dup2.ret;
		return -1;
	}

	newfpfd = app_shmem->dup2.fpfd;
	fd2fpfd[newfd].fpfd = newfpfd;
	LIST_INSERT_HEAD(&fpfdtable[newfpfd].fdhead, &fd2fpfd[newfd], fdlist);

	return newfd;
}

int fpu_so_rpc_dup(int oldfd)
{
	int newfd, newfpfd;

	fpu_so_log(DEBUG, RPC, "called (oldfd=%d)\n", oldfd);

	newfd = get_fd();
	if (newfd < 0)
		return -1;

	app_shmem->type = DUP2;
	app_shmem->dup2.oldfd = oldfd;
	app_shmem->dup2.newfd = newfd;

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->dup2.ret < 0) {
		errno = -app_shmem->dup2.ret;
		return -1;
	}

	newfpfd = app_shmem->dup2.fpfd;
	fd2fpfd[newfd].fpfd = newfpfd;
	LIST_INSERT_HEAD(&fpfdtable[newfpfd].fdhead, &fd2fpfd[newfd], fdlist);

	return newfd;
}

int fpu_so_rpc_dup_all(int clone, const char *shmname)
{
	fpu_so_log(DEBUG, RPC, "called (shm=%s)\n", shmname);

	app_shmem->type = DUP_ALL;
	snprintf(app_shmem->dup_all.shmname, sizeof(app_shmem->dup_all.shmname),
		 "%s", shmname);
	app_shmem->dup_all.clone = clone;

	fpn_wmb();
	app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (app_shmem->status >= FPU_RPC_STATUS_WAITING);
	fpn_rmb();

	if (app_shmem->dup_all.ret < 0) {
		errno = -app_shmem->dup_all.ret;
		return -1;
	}

	return 0;
}
