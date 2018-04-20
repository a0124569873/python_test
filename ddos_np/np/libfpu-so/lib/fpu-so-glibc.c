/*
 * FPU-SO - Fast Path Userland SOckets
 * Copyright 2012-2013 6WIND, All rights reserved.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <arpa/inet.h>

#include "fpu-rpc-var.h"
#include "libfpu-rpc.h"

#include "libfpu-so.h"
#include "fpu-so-rpc.h"

#define INC_STATS(x) do {				\
		if (app_shmem != NULL)			\
			app_shmem->stats.x ++;	\
	} while(0)

/* associates a file descriptor to a fast path fd */
extern struct fd_t fd2fpfd[FPU_SO_MAX_FD];

/* associates a file descriptor to a fast path epoll */
extern struct epoll_t fd2ep[FPU_SO_MAX_FD];

static __typeof__(socket) *glibc_socket;
static __typeof__(write) *glibc_write;
static __typeof__(read) *glibc_read;
static __typeof__(recv) *glibc_recv;
static __typeof__(recvfrom) *glibc_recvfrom;
static __typeof__(recvmsg) *glibc_recvmsg;
static __typeof__(send) *glibc_send;
static __typeof__(sendmsg) *glibc_sendmsg;
static __typeof__(sendto) *glibc_sendto;
static __typeof__(bind) *glibc_bind;
static __typeof__(connect) *glibc_connect;
static __typeof__(accept) *glibc_accept;
#ifdef _GNU_SOURCE
static __typeof__(accept4) *glibc_accept4;
#endif
static __typeof__(listen) *glibc_listen;
static __typeof__(fcntl) *glibc_fcntl;
static __typeof__(ioctl) *glibc_ioctl;
static __typeof__(close) *glibc_close;
static __typeof__(shutdown) *glibc_shutdown;
static __typeof__(sockatmark) *glibc_sockatmark;
static __typeof__(getsockname) *glibc_getsockname;
static __typeof__(getpeername) *glibc_getpeername;
static __typeof__(getsockopt) *glibc_getsockopt;
static __typeof__(setsockopt) *glibc_setsockopt;
static __typeof__(select) *glibc_select;
#ifdef _GNU_SOURCE
static __typeof__(clone) *glibc_clone;
#endif
static __typeof__(pselect) *glibc_pselect;
static __typeof__(poll) *glibc_poll;
static __typeof__(epoll_create) *glibc_epoll_create;
static __typeof__(epoll_create1) *glibc_epoll_create1;
static __typeof__(epoll_ctl) *glibc_epoll_ctl;
static __typeof__(epoll_wait) *glibc_epoll_wait;
static __typeof__(epoll_pwait) *glibc_epoll_pwait;
static __typeof__(vfork) *glibc_vfork;
static __typeof__(fork) *glibc_fork;
static __typeof__(pthread_create) *glibc_pthread_create;
static __typeof__(pthread_exit) *glibc_pthread_exit;
static __typeof__(dup2) *glibc_dup2;
static __typeof__(dup) *glibc_dup;

static void *fpu_so_get_glibc_symbol(const char *symname)
{
	void *sym;

	sym = dlsym(RTLD_NEXT, symname);
	if (sym == NULL) {
		fpu_so_log(ERR, INIT, "%s() not available: %s\n",
			   symname, dlerror());
		exit(EXIT_FAILURE);
	}
	return sym;
}

/* Wrapping init for GLIBC calls */
void
fpu_so_glibc_init(void)
{
	glibc_socket = fpu_so_get_glibc_symbol("socket");
	glibc_write = fpu_so_get_glibc_symbol("write");
	glibc_read = fpu_so_get_glibc_symbol("read");
	glibc_recv = fpu_so_get_glibc_symbol("recv");
	glibc_recvfrom = fpu_so_get_glibc_symbol("recvfrom");
	glibc_recvmsg = fpu_so_get_glibc_symbol("recvmsg");
	glibc_send = fpu_so_get_glibc_symbol("send");
	glibc_sendmsg = fpu_so_get_glibc_symbol("sendmsg");
	glibc_sendto = fpu_so_get_glibc_symbol("sendto");
	glibc_bind = fpu_so_get_glibc_symbol("bind");
	glibc_connect = fpu_so_get_glibc_symbol("connect");
	glibc_accept = fpu_so_get_glibc_symbol("accept");
#ifdef _GNU_SOURCE
	glibc_accept4 = fpu_so_get_glibc_symbol("accept4");
#endif
	glibc_listen = fpu_so_get_glibc_symbol("listen");
	glibc_fcntl = fpu_so_get_glibc_symbol("fcntl");
	glibc_ioctl = fpu_so_get_glibc_symbol("ioctl");
	glibc_close = fpu_so_get_glibc_symbol("close");
	glibc_shutdown = fpu_so_get_glibc_symbol("shutdown");
	glibc_sockatmark = fpu_so_get_glibc_symbol("sockatmark");
	glibc_getsockname = fpu_so_get_glibc_symbol("getsockname");
	glibc_getpeername = fpu_so_get_glibc_symbol("getpeername");
	glibc_getsockopt = fpu_so_get_glibc_symbol("getsockopt");
	glibc_setsockopt = fpu_so_get_glibc_symbol("setsockopt");
	glibc_select = fpu_so_get_glibc_symbol("select");
#ifdef _GNU_SOURCE
	glibc_clone = fpu_so_get_glibc_symbol("clone");
#endif
	glibc_pselect = fpu_so_get_glibc_symbol("pselect");
	glibc_poll = fpu_so_get_glibc_symbol("poll");
	glibc_epoll_create = fpu_so_get_glibc_symbol("epoll_create");
	glibc_epoll_create1 = fpu_so_get_glibc_symbol("epoll_create1");
	glibc_epoll_ctl = fpu_so_get_glibc_symbol("epoll_ctl");
	glibc_epoll_wait = fpu_so_get_glibc_symbol("epoll_wait");
	glibc_epoll_pwait = fpu_so_get_glibc_symbol("epoll_pwait");
	glibc_vfork = fpu_so_get_glibc_symbol("vfork");
	glibc_fork = fpu_so_get_glibc_symbol("fork");
	glibc_dup2 = fpu_so_get_glibc_symbol("dup2");
	glibc_dup = fpu_so_get_glibc_symbol("dup");

	/* These pthread symbols must be loaded "on demand" */
	glibc_pthread_create = NULL;
	glibc_pthread_exit = NULL;
}

static inline int isfpusofd(int fd)
{
	if (fpu_so_args.bypass == 1)
		return 0;

	if (fd < 0 || fd >= FPU_SO_MAX_FD)
		return 0;

	if (fd2fpfd[fd].fpfd == -1)
		return 0;

	return 1;
}

static inline int isepfd(int fd)
{
	if (fpu_so_args.bypass == 1)
		return 0;

	if (fd < 0 || fd >= FPU_SO_MAX_FD)
		return 0;

	return fd2ep[fd].used;
}

/*
 * == glibc's IO stubs ==
 */
ssize_t read(int fd, void *buf, size_t len)
{
	int ret;

	INC_STATS(read.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d buf=%p len=%d)\n",
		  fd, buf, (int)len);

	if (!isfpusofd(fd)) {
		INC_STATS(read.glibc);
		ret = glibc_read(fd, buf, len);
	}
	else {
		INC_STATS(read.rpc);
		ret = fpu_so_rpc_read(fd, buf, len);
	}

	if (ret >= 0)
		INC_STATS(read.success);
	else
		INC_STATS(read.error);

	return ret;
}

/* assuming pwrite is not used for the sockets */
ssize_t write(int fd, const void *buf, size_t len)
{
	int ret;

	INC_STATS(write.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d buf=%p len=%d)\n",
		  fd, buf, (int)len);

	if (!isfpusofd(fd)) {
		INC_STATS(write.glibc);
		ret = glibc_write(fd, buf, len);
	}
	else {
		INC_STATS(write.rpc);
		ret = fpu_so_rpc_write(fd, buf, len);
	}

	if (ret >= 0)
		INC_STATS(write.success);
	else
		INC_STATS(write.error);

	return ret;
}

/*
 * close to the fast path, if not to the kernel
 */
int close(int fd)
{
	int ret;

	INC_STATS(close.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d)\n", fd);

	if (isepfd(fd)) {
		/* Clean epoll instance */
		fpu_so_rpc_epoll_destroy(fd);
	}

	if (!isfpusofd(fd)) {
		INC_STATS(close.glibc);
		ret = glibc_close(fd);
	}
	else {
		INC_STATS(close.rpc);
		ret = fpu_so_rpc_close(fd);
	}

	if (ret == 0)
		INC_STATS(close.success);
	else
		INC_STATS(close.error);

	return ret;
}

/*
 * == glibc's networking stubs ==
 */
/*
 * accept() leads to opening one more /dev/null
 */
int accept(int fd, struct sockaddr *restrict addr, socklen_t *restrict alen)
{
	int ret;

	INC_STATS(accept.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d addr=%p)\n",
		  fd, addr);

	if (!isfpusofd(fd)) {
		INC_STATS(accept.glibc);
		ret = glibc_accept(fd, addr, alen);
	}
	else {
		INC_STATS(accept.rpc);
		/* XXX only ipv4 is supported */
		ret = fpu_so_rpc_accept4(fd, addr, alen);
	}

	if (ret >= 0)
		INC_STATS(accept.success);
	else
		INC_STATS(accept.error);

	return ret;
}

#ifdef _GNU_SOURCE
int accept4(int fd, struct sockaddr *restrict addr, socklen_t *restrict alen, int flags)
{
	int ret;

	INC_STATS(accept4.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d addr=%p flags=0x%x)\n",
		  fd, addr, flags);

	fpu_so_log(WARNING, GLIBC, "%s() not implemented\n", __func__);
	INC_STATS(accept4.glibc);
	ret = glibc_accept4(fd, addr, alen, flags);

	if (ret >= 0)
		INC_STATS(accept4.success);
	else
		INC_STATS(accept4.error);

	return ret;
}
#endif /* _GNU_SOURCE */

int bind(int fd, const struct sockaddr *addr, socklen_t alen)
{
	int ret;

	INC_STATS(bind.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d)\n", fd);

	if (!isfpusofd(fd)) {
		INC_STATS(bind.glibc);
		ret = glibc_bind(fd, addr, alen);
	}
	else {
		INC_STATS(bind.rpc);
		/* XXX only ipv4 is supported */
		ret = fpu_so_rpc_bind4(fd, addr, alen);
	}

	if (ret == 0)
		INC_STATS(bind.success);
	else
		INC_STATS(bind.error);

	return ret;
}

int connect(int fd, const struct sockaddr *addr, socklen_t alen)
{
	int ret;

	INC_STATS(connect.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d)\n", fd);

	if (!isfpusofd(fd)) {
		INC_STATS(connect.glibc);
		ret = glibc_connect(fd, addr, alen);
	}
	else {
		INC_STATS(connect.rpc);
		/* XXX only ipv4 is supported */
		ret = fpu_so_rpc_connect4(fd, addr, alen);
	}

	if (ret >= 0)
		INC_STATS(connect.success);
	else
		INC_STATS(connect.error);

	return ret;
}

int fcntl(int fd, int cmd, ... /* arg */ )
{
	int ret;
	va_list ap;

	INC_STATS(fcntl.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d, cmd=%d)\n", fd, cmd);

	switch (cmd) {
		/* no argument */
		case F_GETFD:
		case F_GETFL:
		case F_GETOWN:
		case F_GETSIG:
		case F_GETLEASE:
#ifdef F_GETPIPE_SZ
		case F_GETPIPE_SZ:
#endif
			if (!isfpusofd(fd)) {
				INC_STATS(fcntl.glibc);
				ret = glibc_fcntl(fd, cmd);
			}
			else {
				INC_STATS(fcntl.rpc);
				ret = fpu_so_rpc_fcntl(fd, cmd);
			}
			break;

		/* argument is int */
		case F_DUPFD:
		case F_DUPFD_CLOEXEC:
		case F_SETFD:
		case F_SETFL:
		case F_SETOWN:
		case F_SETSIG:
		case F_SETLEASE:
		case F_NOTIFY:
#ifdef F_SETPIPE_SZ
		case F_SETPIPE_SZ:
#endif
		{
			int arg;
			va_start(ap, cmd);
			arg = va_arg(ap, int);
			va_end(ap);
			if (!isfpusofd(fd)) {
				INC_STATS(fcntl.glibc);
				ret = glibc_fcntl(fd, cmd, arg);
				/* If glibc is happy, copy epoll information */
				if (ret >= 0 && isepfd(fd) &&
				    ((cmd == F_DUPFD) ||
				     (cmd == F_DUPFD_CLOEXEC))) {
					fpu_so_rpc_epoll_duplicate(fd, ret);
				}
			}
			else {
				INC_STATS(fcntl.rpc);
				ret = fpu_so_rpc_fcntl(fd, cmd, arg);
			}
			break;
		}

		/* argument is (struct flock *) */
		case F_GETLK:
		case F_SETLK:
		case F_SETLKW:
		/* argument is (struct f_owner_ex *) */
		case F_GETOWN_EX:
		case F_SETOWN_EX: {
			void *arg;
			va_start(ap, cmd);
			arg = va_arg(ap, void *);
			va_end(ap);
			if (!isfpusofd(fd)) {
				INC_STATS(fcntl.glibc);
				ret = glibc_fcntl(fd, cmd, arg);
			}
			else {
				INC_STATS(fcntl.rpc);
				ret = fpu_so_rpc_fcntl(fd, cmd, arg);
			}
			break;
		}

		default:
			fpu_so_log(WARNING, GLIBC, "%s(cmd=0x%x) not implemented\n",
				  __func__, cmd);
			errno = EINVAL;
			ret = -1;
			break;
	}

	if (ret >= 0)
		INC_STATS(fcntl.success);
	else
		INC_STATS(fcntl.error);

	return ret;
}

int ioctl(int fd, unsigned long int req, ... /* arg */ )
{
	int ret;
	va_list ap;

	INC_STATS(ioctl.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d, req=0x%lx)\n", fd, req);

	switch (_IOC_SIZE(req)) {
		/* no argument */
		case 0:
			if (!isfpusofd(fd)) {
				INC_STATS(ioctl.glibc);
				ret = glibc_ioctl(fd, req);
			}
			else {
				INC_STATS(ioctl.rpc);
				ret = fpu_so_rpc_ioctl(fd, req);
			}
			break;

		/* argument is 32 bits */
		case sizeof(int32_t): {
			int32_t arg;
			va_start(ap, req);
			arg = va_arg(ap, int32_t);
			va_end(ap);
			if (!isfpusofd(fd)) {
				INC_STATS(ioctl.glibc);
				ret = glibc_ioctl(fd, req, arg);
			}
			else {
				INC_STATS(ioctl.rpc);
				ret = fpu_so_rpc_ioctl(fd, req, arg);
			}
			break;
		}

		/* argument is 64 bits */
		case sizeof(int64_t): {
			int32_t arg;
			va_start(ap, req);
			arg = va_arg(ap, int32_t);
			va_end(ap);
			if (!isfpusofd(fd)) {
				INC_STATS(ioctl.glibc);
				ret = glibc_ioctl(fd, req, arg);
			}
			else {
				INC_STATS(ioctl.rpc);
				ret = fpu_so_rpc_ioctl(fd, req, arg);
			}
			break;
		}

		default:
			fpu_so_log(WARNING, GLIBC, "%s(req=0x%lx) not implemented\n",
				  __func__, req);
			errno = EINVAL;
			ret = -1;
			break;
	}

	if (ret >= 0)
		INC_STATS(ioctl.success);
	else
		INC_STATS(ioctl.error);

	return ret;
}

int getsockname(int fd, struct sockaddr *restrict addr,
		socklen_t *restrict alen)
{
	int ret;

	INC_STATS(getsockname.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d)\n", fd);

	if (!isfpusofd(fd)) {
		INC_STATS(getsockname.glibc);
		ret = glibc_getsockname(fd, addr, alen);
	}
	else {
		INC_STATS(getsockname.rpc);
		/* XXX only ipv4 is supported */
		ret = fpu_so_rpc_getsockname4(fd, addr, alen);
	}

	if (ret == 0)
		INC_STATS(getsockname.success);
	else
		INC_STATS(getsockname.error);

	return ret;
}

int getpeername(int fd, struct sockaddr *restrict addr,
		socklen_t *restrict alen)
{
	int ret;

	INC_STATS(getpeername.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d)\n", fd);

	if (!isfpusofd(fd)) {
		INC_STATS(getpeername.glibc);
		ret = glibc_getpeername(fd, addr, alen);
	}
	else {
		INC_STATS(getpeername.rpc);
		/* XXX only ipv4 for now */
		ret = fpu_so_rpc_getpeername4(fd, addr, alen);
	}

	if (ret == 0)
		INC_STATS(getpeername.success);
	else
		INC_STATS(getpeername.error);

	return ret;
}

int getsockopt(int fd, int level, int optname,
	       void *restrict optvalue, socklen_t *restrict optlen)
{
	int ret;

	INC_STATS(getsockopt.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d, optname=%d)\n", fd, optname);

	if (!isfpusofd(fd)) {
		INC_STATS(getsockopt.glibc);
		ret = glibc_getsockopt(fd, level, optname, optvalue, optlen);
	}
	else {
		INC_STATS(getsockopt.rpc);
		ret = fpu_so_rpc_getsockopt(fd, level, optname, optvalue, optlen);
	}

	if (ret == 0)
		INC_STATS(getsockopt.success);
	else
		INC_STATS(getsockopt.error);

	return ret;
}

int setsockopt(int fd, int level, int optname,
	       const void *optvalue, socklen_t optlen)
{
	int ret;

	INC_STATS(setsockopt.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d, optname=%d)\n", fd, optname);

	if (!isfpusofd(fd)) {
		INC_STATS(setsockopt.glibc);
		ret = glibc_setsockopt(fd, level, optname, optvalue, optlen);
	}
	else {
		INC_STATS(setsockopt.rpc);
		ret = fpu_so_rpc_setsockopt(fd, level, optname, optvalue, optlen);
	}

	if (ret == 0)
		INC_STATS(setsockopt.success);
	else
		INC_STATS(setsockopt.error);

	return ret;
}

int listen(int fd, int backlog)
{
	int ret;

	INC_STATS(listen.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d, backlog=%d)\n", fd, backlog);

	if (!isfpusofd(fd)) {
		INC_STATS(listen.glibc);
		ret = glibc_listen(fd, backlog);
	}
	else {
		INC_STATS(listen.rpc);
		ret = fpu_so_rpc_listen(fd, backlog);
	}

	if (ret == 0)
		INC_STATS(listen.success);
	else
		INC_STATS(listen.error);

	return ret;
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	int ret;

	INC_STATS(recv.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d len=%d flags=0x%x)\n",
		  fd, (int)len, flags);

	if (!isfpusofd(fd)) {
		INC_STATS(recv.glibc);
		ret = glibc_recv(fd, buf, len, flags);
	}
	else {
		INC_STATS(recv.rpc);
		ret = fpu_so_rpc_recv(fd, buf, len, flags);
	}

	if (ret == 0)
		INC_STATS(recv.success);
	else
		INC_STATS(recv.error);

	return ret;
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
		 struct sockaddr *src_addr, socklen_t *alen)
{
	int ret;

	INC_STATS(recvfrom.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d len=%d flags=0x%x)\n",
		  fd, (int)len, flags);

	if (!isfpusofd(fd)) {
		INC_STATS(recvfrom.glibc);
		ret = glibc_recvfrom(fd, buf, len, flags, src_addr, alen);
	}
	else {
		INC_STATS(recvfrom.rpc);
		/* XXX only ipv4 is supported */
		ret = fpu_so_rpc_recvfrom4(fd, buf, len, flags, src_addr, alen);
	}

	if (ret == 0)
		INC_STATS(recvfrom.success);
	else
		INC_STATS(recvfrom.error);

	return ret;
}

ssize_t recvmsg(int fd, struct msghdr *mh, int flags)
{
	int ret;

	INC_STATS(recvmsg.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d flags=0x%x)\n",
		  fd, flags);

	if (!isfpusofd(fd)) {
		INC_STATS(recvmsg.glibc);
		ret = glibc_recvmsg(fd, mh, flags);
	}
	else {
		fpu_so_log(WARNING, GLIBC, "%s() not implemented\n", __func__);
		errno = EINVAL;
		ret = -1;
	}

	if (ret == 0)
		INC_STATS(recvmsg.success);
	else
		INC_STATS(recvmsg.error);

	return ret;
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
	int ret;

	INC_STATS(send.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d len=%d flags=0x%x)\n",
		  fd, (int)len, flags);

	if (!isfpusofd(fd)) {
		INC_STATS(send.glibc);
		ret = glibc_send(fd, buf, len, flags);
	}
	else {
		INC_STATS(send.rpc);
		ret = fpu_so_rpc_send(fd, buf, len, flags);
	}

	if (ret == 0)
		INC_STATS(send.success);
	else
		INC_STATS(send.error);

	return ret;
}

ssize_t sendmsg(int fd, const struct msghdr *mh, int flags)
{
	int ret;

	INC_STATS(sendmsg.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d flags=0x%x)\n",
		  fd, flags);

	if (!isfpusofd(fd)) {
		INC_STATS(sendmsg.glibc);
		ret = glibc_sendmsg(fd, mh, flags);
	}
	else {
		fpu_so_log(WARNING, GLIBC, "%s() not implemented\n", __func__);
		errno = EINVAL;
		ret = -1;
	}

	if (ret == 0)
		INC_STATS(sendmsg.success);
	else
		INC_STATS(sendmsg.error);

	return ret;
}

ssize_t sendto(int fd, const void *buf, size_t len,
	       int flags, const struct sockaddr *dst_addr,
	       socklen_t alen)
{
	int ret;

	INC_STATS(sendto.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d len=%d flags=0x%x)\n",
		  fd, (int)len, flags);

	if (!isfpusofd(fd)) {
		INC_STATS(sendto.glibc);
		ret = glibc_sendto(fd, buf, len, flags, dst_addr, alen);
	}
	else {
		INC_STATS(sendto.rpc);
		/* XXX only ipv4 is supported */
		ret = fpu_so_rpc_sendto4(fd, buf, len, flags, dst_addr, alen);
	}

	if (ret == 0)
		INC_STATS(sendto.success);
	else
		INC_STATS(sendto.error);

	return ret;
}

int shutdown(int fd, int how)
{
	int ret;

	INC_STATS(shutdown.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d how=%d)\n",
		  fd, how);

	if (!isfpusofd(fd)) {
		INC_STATS(shutdown.glibc);
		ret = glibc_shutdown(fd, how);
	}
	else {
		INC_STATS(shutdown.rpc);
		ret = fpu_so_rpc_shutdown(fd, how);
	}

	if (ret == 0)
		INC_STATS(shutdown.success);
	else
		INC_STATS(shutdown.error);

	return ret;
}

int socket(int domain, int type, int proto)
{
	int ret;

	INC_STATS(socket.call);

	if (fpu_so_args.bypass == 1) {
		INC_STATS(socket.glibc);
		ret = glibc_socket(domain, type, proto);
		goto end;
	}

	fpu_so_log(DEBUG, GLIBC, "called (domain=%d type=%d proto=%d)\n",
		  domain, type, proto);

	switch(domain) {
		case AF_INET:
		/* case AF_INET6: */ /* XXX later */
			break;
		default:
			INC_STATS(socket.glibc);
			ret = glibc_socket(domain, type, proto);
			goto end;
	}

	switch (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) {
		case SOCK_DGRAM:
		case SOCK_STREAM:
			break;
		default:
			INC_STATS(socket.glibc);
			ret = glibc_socket(domain, type, proto);
			goto end;
	}

	switch (proto) {
		case 0:
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			break;
		default:
			INC_STATS(socket.glibc);
			ret = glibc_socket(domain, type, proto);
			goto end;
	}

	INC_STATS(socket.rpc);
	ret = fpu_so_rpc_socket(domain, type, proto);

 end:
	if (ret >= 0)
		INC_STATS(socket.success);
	else
		INC_STATS(socket.error);

	return ret;
}

int sockatmark(int fd)
{
	int ret;

	INC_STATS(sockatmark.call);
	fpu_so_log(DEBUG, GLIBC, "called (fd=%d)\n", fd);

	if (!isfpusofd(fd)) {
		INC_STATS(sockatmark.glibc);
		ret = glibc_sockatmark(fd);
	}
	else {
		fpu_so_log(WARNING, GLIBC, "%s() not implemented\n", __func__);
		errno = EINVAL;
		ret = -1;
	}

	if (ret >= 0)
		INC_STATS(sockatmark.success);
	else
		INC_STATS(sockatmark.error);

	return ret;
}

int pselect(int nfds, fd_set *restrict readfds, fd_set *restrict writefds,
	    fd_set *restrict errorfds, const struct timespec *restrict timeout,
	    const sigset_t *restrict sigmask)
{
	int ret;

	(void)nfds;
	(void)readfds;
	(void)writefds;
	(void)errorfds;
	(void)timeout;
	(void)sigmask;

	INC_STATS(pselect.call);
	fpu_so_log(WARNING, GLIBC, "%s() not implemented\n", __func__);

	if (fpu_so_args.bypass == 1) {
		INC_STATS(pselect.glibc);
		ret = glibc_pselect(nfds, readfds, writefds, errorfds,
				    timeout, sigmask);
	}
	else {
		errno = EINVAL;
		ret = -1;
	}

	if (ret >= 0)
		INC_STATS(pselect.success);
	else
		INC_STATS(pselect.error);

	return ret;
}

#define COPY_FP_FDS    1
#define COPY_GLIBC_FDS 2
#define COPY_ALL_FDS   (COPY_FP_FDS | COPY_GLIBC_FDS)
static void copy_fds(fd_set *out, fd_set *in, int nfds, int flags)
{
	int i, bit;

	if (out == NULL || in == NULL)
		return;

	for (i = 0; i < (nfds + (__NFDBITS - 1)) / __NFDBITS; i++) {
		fd_mask m1, m2;
		m1 = __FDS_BITS(in)[i];

		/* copy all */
		if (flags == (COPY_FP_FDS | COPY_GLIBC_FDS)) {
			__FDS_BITS(out)[i] = m1;
			continue;
		}

		/* else we have to filter */
		m2 = 0;
		for (bit = 0; bit < __NFDBITS; bit++) {
			int fd = i * __NFDBITS + bit;

			if (fd >= nfds)
				break;
			if ((m1 & ((fd_mask)1 << bit)) == 0)
				continue;

			if ((flags & COPY_FP_FDS) && isfpusofd(fd))
				m2 |= ((fd_mask)1 << bit);
			if ((flags & COPY_GLIBC_FDS) && !isfpusofd(fd))
				m2 |= ((fd_mask)1 << bit);
		}

		__FDS_BITS(out)[i] = m2;
	}
}

/*
 * nfds is the highest *r|w|e*fds + 1
 * errorfds is not supported yet.
 */
int select(int nfds, fd_set *restrict readfds, fd_set *restrict writefds,
	   fd_set *restrict errorfds, struct timeval *restrict timeout)
{
	int ret = 0, i;
	int fp_ret = 0, glibc_ret = 0;
	struct timeval now;
	struct timeval out;
	struct timeval tv;
	fd_set *fp_readfds = NULL, *fp_writefds = NULL, *fp_errorfds = NULL;
	fd_set *glibc_readfds = NULL, *glibc_writefds = NULL, *glibc_errorfds = NULL;
	int fdset_nwords;

	INC_STATS(select.call);
	fpu_so_log(DEBUG, GLIBC, "called (nfds=%d, timeout=%p)\n",
		  nfds, timeout);

	if (fpu_so_args.bypass == 1) {
		INC_STATS(select.glibc);
		ret = glibc_select(nfds, readfds, writefds, errorfds,
				    timeout);
		goto end;
	}

	/* allocate fdsets for fp and glibc in stack */
	fdset_nwords = (nfds + (__NFDBITS - 1)) / __NFDBITS;
	if (readfds != NULL) {
		fp_readfds = alloca(fdset_nwords * sizeof(__fd_mask));
		glibc_readfds = alloca(fdset_nwords * sizeof(__fd_mask));
	}
	if (writefds != NULL) {
		fp_writefds = alloca(fdset_nwords * sizeof(__fd_mask));
		glibc_writefds = alloca(fdset_nwords * sizeof(__fd_mask));
	}
	if (errorfds != NULL) {
		fp_errorfds = alloca(fdset_nwords * sizeof(__fd_mask));
		glibc_errorfds = alloca(fdset_nwords * sizeof(__fd_mask));
	}

	/* get current time and compute the exit time */
	if (timeout) {
		gettimeofday(&now, NULL);
		timeradd(timeout, &now, &out);
	}
	else
		memset(&out, 0, sizeof(out));


	do {
		/* do a select on fast path side */
		copy_fds(fp_readfds, readfds, nfds, COPY_FP_FDS);
		copy_fds(fp_writefds, writefds, nfds, COPY_FP_FDS);
		copy_fds(fp_errorfds, errorfds, nfds, COPY_FP_FDS);
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		INC_STATS(select.rpc);
		fp_ret = fpu_so_rpc_select(nfds, fp_readfds, fp_writefds,
					  fp_errorfds, &tv);
		if (fp_ret < 0) {
			ret = fp_ret;
			goto end;
		}

		/* do a select on glibc side */
		copy_fds(glibc_readfds, readfds, nfds, COPY_GLIBC_FDS);
		copy_fds(glibc_writefds, writefds, nfds, COPY_GLIBC_FDS);
		copy_fds(glibc_errorfds, errorfds, nfds, COPY_GLIBC_FDS);
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		INC_STATS(select.glibc);
		glibc_ret = glibc_select(nfds, glibc_readfds, glibc_writefds,
					 glibc_errorfds, &tv);
		if (glibc_ret < 0) {
			ret = glibc_ret;
			goto end;
		}

		/* total number of fd */
		ret = fp_ret + glibc_ret;

		if (ret == 0 && timeout) {
			/* timeout expired */
			gettimeofday(&now, NULL);
			if (timercmp(&now, &out, >=))
				break;
		}

	} while (ret == 0);

	if (ret && timeout)
		timersub(&out, &now, timeout);

	/* return the glibc fds */
	if (fp_ret == 0) {
		copy_fds(readfds, glibc_readfds, nfds, COPY_ALL_FDS);
		copy_fds(writefds, glibc_writefds, nfds, COPY_ALL_FDS);
		copy_fds(errorfds, glibc_errorfds, nfds, COPY_ALL_FDS);
		goto end;
	}

	/* return the fp fds */
	if (glibc_ret == 0) {
		copy_fds(readfds, fp_readfds, nfds, COPY_ALL_FDS);
		copy_fds(writefds, fp_writefds, nfds, COPY_ALL_FDS);
		copy_fds(errorfds, fp_errorfds, nfds, COPY_ALL_FDS);
		goto end;;
	}

	/* else we have to mix them */
	if (readfds != NULL)
		memset(readfds, 0, fdset_nwords * sizeof(__fd_mask));
	if (writefds != NULL)
		memset(writefds, 0, fdset_nwords * sizeof(__fd_mask));
	if (errorfds != NULL)
		memset(errorfds, 0, fdset_nwords * sizeof(__fd_mask));
	for (i = 0; i < nfds; i++) {
		if (readfds != NULL &&
		    (FD_ISSET(i, fp_readfds) || FD_ISSET(i, glibc_readfds)))
			FD_SET(i, readfds);
		if (writefds != NULL &&
		    (FD_ISSET(i, fp_writefds) || FD_ISSET(i, glibc_writefds)))
			FD_SET(i, writefds);
		if (errorfds != NULL &&
		    (FD_ISSET(i, fp_errorfds) || FD_ISSET(i, glibc_errorfds)))
			FD_SET(i, errorfds);
	}

 end:
	if (ret >= 0)
		INC_STATS(select.success);
	else
		INC_STATS(select.error);

	return ret;
}

int poll(struct pollfd fds[], nfds_t nfds, int timeout)
{
	struct pollfd *fp_fds, *glibc_fds;
	struct timeval now;
	struct timeval out;
	struct timeval tv_timeout;
	int i, ret, fp_ret, glibc_ret;

	INC_STATS(poll.call);

	if (fpu_so_args.bypass == 1) {
		INC_STATS(poll.glibc);
		ret = glibc_poll(fds, nfds, timeout);
		goto end;
	}

	fp_fds = alloca(sizeof(struct pollfd) * nfds);
	memset(fp_fds, 0, sizeof(struct pollfd) * nfds);
	glibc_fds = alloca(sizeof(struct pollfd) * nfds);
	memset(glibc_fds, 0, sizeof(struct pollfd) * nfds);

	tv_timeout.tv_sec = -1;
	memset(&out, 0, sizeof(out));

	/* slpit fds in fp_fds and glibc_fds */
	for (i = 0; i < (int)nfds; i++) {
		fp_fds[i].fd = fds[i].fd;
		glibc_fds[i].fd = fds[i].fd;
		if (isfpusofd(fds[i].fd)) {
			fp_fds[i].events = fds[i].events;
			fp_fds[i].revents = 0;
			glibc_fds[i].events = 0;
			glibc_fds[i].revents = 0;
		}
		else {
			fp_fds[i].events = 0;
			fp_fds[i].revents = 0;
			glibc_fds[i].events = fds[i].events;
			glibc_fds[i].revents = 0;
		}
	}

	do {
		INC_STATS(poll.rpc);
		fp_ret = fpu_so_rpc_poll(fp_fds, nfds, 0);
		if (fp_ret < 0) {
			ret = fp_ret;
			goto end;
		}

		INC_STATS(poll.glibc);
		glibc_ret = glibc_poll(glibc_fds, nfds, 0);
		if (glibc_ret < 0) {
			ret = glibc_ret;
			goto end;
		}

		/* total number of fd */
		ret = fp_ret + glibc_ret;

		if (ret == 0) {
			/* timeout expired */
			gettimeofday(&now, NULL);

			if (tv_timeout.tv_sec == -1) {
				tv_timeout.tv_sec = timeout / 1000;
				tv_timeout.tv_usec = (timeout % 1000) * 1000;
				timeradd(&tv_timeout, &now, &out);
			}

			if (timercmp(&now, &out, >=))
				goto end;
		}

	} while (ret == 0);

	/* slpit fds in fp_fds and glibc_fds */
	for (i = 0; i < (int)nfds; i++) {
		if (isfpusofd(fds[i].fd))
			fds[i].revents = fp_fds[i].revents;
		else
			fds[i].revents = glibc_fds[i].revents;
	}

 end:
	if (ret >= 0)
		INC_STATS(poll.success);
	else
		INC_STATS(poll.error);

	return ret;
}

int epoll_create(int size)
{
	if (size <= 0) {
		INC_STATS(epoll_create.error);
		errno = EINVAL;
		return -1;
	}
	return epoll_create1(0);
}

int epoll_create1(int flags)
{
	int ret;
	int epfd;

	INC_STATS(epoll_create1.call);
	fpu_so_log(DEBUG, GLIBC, "called (flags=0x%x)\n", flags);

	INC_STATS(epoll_create1.glibc);
	ret = glibc_epoll_create1(flags);
	/* Either we don't want fastpath or an error occured */
	if (ret < 0 || fpu_so_args.bypass == 1)
		goto end;
	epfd = ret;

	INC_STATS(epoll_create1.rpc);
	ret = fpu_so_rpc_epoll_create1(epfd, flags);
	if (ret < 0) {
		__typeof__(errno) old = errno;
		/* No need to call our close(), as we know that
		 * fpu_so_rpc_epoll_create1 failed and the only resource
		 * allocated is in kernel */
		glibc_close(epfd);
		errno = old;
	}

end:
	if (ret >= 0)
		INC_STATS(epoll_create1.success);
	else
		INC_STATS(epoll_create1.error);

	return ret;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	int ret;

	INC_STATS(epoll_ctl.call);
	fpu_so_log(DEBUG, GLIBC, "called (epfd=%d)\n", epfd);

	if (fpu_so_args.bypass == 1) {
		INC_STATS(epoll_ctl.glibc);
		ret = glibc_epoll_ctl(epfd, op, fd, event);
		goto end;
	}

	/* Unknown epfd or epfd == fd */
	if (!isepfd(epfd) || (epfd == fd)) {
		ret = -1;
		errno = EINVAL;
		goto end;
	}

	if (!isfpusofd(fd)) {
		INC_STATS(epoll_ctl.glibc);
		fpu_so_log(DEBUG, GLIBC, "epoll operation on kernel socket "
		                         "(fd=%d, epfd=%d)\n", fd, epfd);
		ret = glibc_epoll_ctl(epfd, op, fd, event);
		/* If operation succeeds, then let's remember we have some stuff
		 * in kernel. We don't look at what op is executed on which fd
		 * => we won't clear ->kernel field if all kernel fds are
		 * removed from this epoll instance. */
		if (!ret)
			fd2ep[epfd].kernel = 1;
		goto end;
	}

	INC_STATS(epoll_ctl.rpc);
	/* From here, we are sure that epfd is a valid ep instance
	 * and fd is a valid fpuso */
	ret = fpu_so_rpc_epoll_ctl(epfd, op, fd, event, 0);

end:
	if (ret == 0)
		INC_STATS(epoll_ctl.success);
	else
		INC_STATS(epoll_ctl.error);

	return ret;
}

int epoll_wait(int epfd, struct epoll_event *events,
	       int maxevents, int timeout)
{
	struct timeval now;
	struct timeval out;
	struct timeval tv_timeout;
	int ret, fp_ret, glibc_ret;
	int fp_max = 0, glibc_max = 0;

	INC_STATS(epoll_wait.call);
	//fpu_so_log(DEBUG, GLIBC, "called (epfd=%d)\n", epfd);

	if (fpu_so_args.bypass == 1) {
		INC_STATS(epoll_wait.glibc);
		ret = glibc_epoll_wait(epfd, events, maxevents, timeout);
		goto end;
	}

	/* This can happen if user gives us some wrong fd */
	if (!isepfd(epfd)) {
		ret = -1;
		errno = EBADF;
		goto end;
	}

	tv_timeout.tv_sec = -1;
	memset(&out, 0, sizeof(out));

	if (!LIST_EMPTY(&fd2ep[epfd].fpfdhead)) {
		if (!fd2ep[epfd].kernel) {
			/* Everything to fast path */
			//fpu_so_log(DEBUG, EPOLL, "everything to fastpath\n");
			fp_max = maxevents;
		} else {
			/* Worst case */
			/* FIXME: hardcoded ratio */
			//fpu_so_log(DEBUG, EPOLL, "worst case\n");
			glibc_max = maxevents / 5;
			if (!glibc_max)
				glibc_max = 1;
			fp_max = maxevents - glibc_max;
		}
	} else {
		/* Everything to kernel (no need to look at ->kernel field,
		 * if there is nothing, kernel will handle it anyway) */
		//fpu_so_log(DEBUG, EPOLL, "everything to kernel\n");
		glibc_max = maxevents;
	}

	glibc_ret = 0;
	fp_ret = 0;
	ret = 0;
	do {
		if (glibc_max) {
			INC_STATS(epoll_wait.glibc);
			glibc_ret = glibc_epoll_wait(epfd, &events[ret],
			                             glibc_max, 0);
			if (glibc_ret < 0)
				goto end;
			else
				ret += glibc_ret;
		}

		if (fp_max) {
			INC_STATS(epoll_wait.rpc);
			fp_ret = fpu_so_rpc_epoll_wait(epfd, &events[ret],
			                               fp_max);
			if (fp_ret < 0)
				goto end;
			else
				ret += fp_ret;
		}

		if (ret == 0) {
			gettimeofday(&now, NULL);

			if (tv_timeout.tv_sec == -1) {
				tv_timeout.tv_sec = timeout / 1000;
				tv_timeout.tv_usec = (timeout % 1000) * 1000;
				timeradd(&tv_timeout, &now, &out);
			}

			/* timeout expired */
			if (timercmp(&now, &out, >=))
				goto end;
		}

	} while (ret == 0);

end:
	if (ret >= 0)
		INC_STATS(epoll_wait.success);
	else
		INC_STATS(epoll_wait.error);

	return ret;
}

int epoll_pwait(int epfd, struct epoll_event *events,
		int maxevents, int timeout,
		const sigset_t *sigmask)
{
	int ret;

	(void)epfd;
	(void)events;
	(void)maxevents;
	(void)timeout;
	(void)sigmask;

	INC_STATS(epoll_pwait.call);
	fpu_so_log(WARNING, GLIBC, "%s() not implemented\n", __func__);

	if (fpu_so_args.bypass == 1) {
		INC_STATS(epoll_pwait.glibc);
		ret = glibc_epoll_pwait(epfd, events, maxevents, timeout,
					sigmask);
	}
	else {
		errno = EINVAL;
		ret = -1;
	}

	if (ret >= 0)
		INC_STATS(epoll_pwait.success);
	else
		INC_STATS(epoll_pwait.error);

	return ret;
}

/*
 * == glibc's fork, thread stubs ==
 */

#ifdef _GNU_SOURCE
/*
 * clone()
 */
int clone(int (*fn)(void *), void *child_stack,
	  int flags, void *arg, ...
	  /* pid_t *ptid, struct user_desc *tls, pid_t *ctid */ )
{
	int ret;
	va_list ap;
	pid_t *ptid;
	struct user_desc *tls;
	pid_t *ctid;

	INC_STATS(clone.call);

	va_start (ap, arg);
	ptid = va_arg (ap, pid_t *);
	tls  = va_arg (ap, struct user_desc *);
	ctid = va_arg (ap, pid_t *);
	va_end (ap);

	(void)fn;
	(void)child_stack;
	(void)flags;
	(void)ptid;
	(void)tls;
	(void)ctid;

	fpu_so_log(WARNING, GLIBC, "%s() not implemented\n", __func__);

	if (fpu_so_args.bypass == 1) {
		INC_STATS(clone.glibc);
		ret = glibc_clone(fn, child_stack, flags, arg, ptid, tls,
				  ctid);
	}
	else {
		errno = EINVAL;
		ret = -1;
	}

	/* do not inc stat if ret > 0 to avoid to count it twice */
	if (ret == 0)
		INC_STATS(clone.success);
	else if (ret < 0)
		INC_STATS(clone.error);

	return ret;
}
#endif

pid_t vfork(void)
{
	int ret;

	INC_STATS(vfork.call);
	fpu_so_log(WARNING, GLIBC, "%s() not implemented\n", __func__);

	if (fpu_so_args.bypass == 1) {
		INC_STATS(vfork.glibc);
		ret = glibc_vfork();
	}
	else {
		errno = EINVAL;
		ret = -1;
	}

	/* do not inc stat if ret > 0 to avoid to count it twice */
	if (ret == 0)
		INC_STATS(vfork.success);
	else if (ret < 0)
		INC_STATS(vfork.error);

	return ret;
}

pid_t fork(void)
{
	pid_t pid;
	char app_shmname[64];
	struct fpu_rpc_app_shmem *shm;
	int s, id;

	INC_STATS(fork.call);
	fpu_so_log(DEBUG, GLIBC, "%s()\n", __func__);

	if (fpu_so_args.bypass == 1) {
		INC_STATS(fork.glibc);
		pid = glibc_fork();
		goto end;
	}

	s = fpu_rpc_connect(&id);
	if (s < 0) {
		pid = -1;
		goto end;
	}

	snprintf(app_shmname, sizeof(app_shmname),
		 "fpu-so-appshm-%d-%d", (int)syscall(SYS_gettid), id);
	shm = fpu_rpc_create_app_shmem(app_shmname);
	if (shm == NULL) {
		close(s);
		errno = ENOMEM;
		pid = -1;
		goto end;
	}

	if (fpu_rpc_register(s, app_shmname, shm) < 0) {
		close(s);
		fpu_rpc_delete_app_shmem(app_shmname);
		pid = -1;
		goto end;
	}

	if (fpu_so_rpc_dup_all(0, app_shmname) < 0) {
		close(s); /* the fp will delete the shmname */
		pid = -1;
		goto end;
	}

	INC_STATS(fork.glibc);
	pid = glibc_fork();
	if (pid < 0) {
		int err;
		err = errno;
		close(s); /* the fp will delete the shmname */
		errno = err;
		pid = pid;
		goto end;
	}

	/* child */
	if (pid == 0) {
		/* set global (per-thread) app_shm and unix_sock variables */
		app_shmem = shm;
		unix_sock = s;
	}
	else {
		close(s);
	}

 end:
	/* do not inc stat if pid > 0 to avoid to count it twice */
	if (pid == 0)
		INC_STATS(fork.success);
	else if (pid < 0)
		INC_STATS(fork.error);

	return pid;
}

struct fpu_so_pthread_args
{
	void *(*start_routine) (void *);
	void *arg;
	struct fpu_rpc_app_shmem *shm;
	int unix_sock;
};

static void *fpu_so_start_thread(void *arg)
{
	struct fpu_so_pthread_args pth_args;
	void *ret;

	fpu_so_log(DEBUG, GLIBC, "%s()\n", __func__);

	memcpy(&pth_args, arg, sizeof(pth_args));
	free(arg);

	/* assign per-thread global vars */
	app_shmem = pth_args.shm;
	unix_sock = pth_args.unix_sock;

	ret = pth_args.start_routine(pth_args.arg);

	/* unregister app */
	close(unix_sock);
	unix_sock = -1;

	return ret;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
		   void *(*start_routine) (void *), void *arg)
{
	struct fpu_so_pthread_args *pth_args;
	char app_shmname[64];
	struct fpu_rpc_app_shmem *shm;
	int s, id;
	int ret;

	INC_STATS(pthread_create.call);
	fpu_so_log(DEBUG, GLIBC, "%s()\n", __func__);

	if (fpu_so_args.bypass == 1) {
		INC_STATS(pthread_create.glibc);
		if (!glibc_pthread_create)
			glibc_pthread_create =
				fpu_so_get_glibc_symbol("pthread_create");
		ret = glibc_pthread_create(thread, attr, start_routine,
					   arg);
		goto end;
	}

	s = fpu_rpc_connect(&id);
	if (s < 0) {
		ret = -1;
		goto end;
	}

	snprintf(app_shmname, sizeof(app_shmname),
		 "fpu-so-appshm-%d-%d", (int)syscall(SYS_gettid), id);

	shm = fpu_rpc_create_app_shmem(app_shmname);
	if (shm == NULL) {
		close(s);
		errno = ENOMEM;
		ret = -1;
		goto end;
	}

	if (fpu_rpc_register(s, app_shmname, shm) < 0) {
		close(s);
		fpu_rpc_delete_app_shmem(app_shmname);
		ret = -1;
		goto end;
	}

	if (fpu_so_rpc_dup_all(1, app_shmname) < 0) {
		close(s); /* the fp will delete the shmname */
		ret = -1;
		goto end;
	}

	pth_args = malloc(sizeof(*pth_args));
	if (pth_args == NULL) {
		close(s); /* the fp will delete the shmname */
		errno = ENOMEM;
		ret = -1;
		goto end;
	}

	pth_args->start_routine = start_routine;
	pth_args->arg = arg;
	pth_args->shm = shm;
	pth_args->unix_sock = s;

	INC_STATS(pthread_create.glibc);
	if (!glibc_pthread_create)
		glibc_pthread_create =
			fpu_so_get_glibc_symbol("pthread_create");
	ret = glibc_pthread_create(thread, attr, fpu_so_start_thread, pth_args);
	if (ret < 0) {
		int err;
		err = errno;
		close(s); /* the fp will delete the shmname */
		errno = err;
		free(pth_args);
	}

 end:
	if (ret == 0)
		INC_STATS(pthread_create.success);
	else
		INC_STATS(pthread_create.error);

	return ret;
}

void pthread_exit(void *retval)
{
	INC_STATS(pthread_exit.call);
	fpu_so_log(DEBUG, GLIBC, "%s()\n", __func__);

	if (fpu_so_args.bypass == 0) {
		/* unregister app */
		close(unix_sock);
		unix_sock = -1;
	}

	INC_STATS(pthread_exit.glibc);
	if (!glibc_pthread_exit)
		glibc_pthread_exit = fpu_so_get_glibc_symbol("pthread_exit");
	glibc_pthread_exit(retval);
	while (1); /* silent compiler warning (no return expected) */
}

int dup2(int oldfd, int newfd)
{
	int ret;

	INC_STATS(dup2.call);
	fpu_so_log(DEBUG, GLIBC, "called (oldfd=%d, newfd=%d)\n",
		  oldfd, newfd);

	/* if newfd is a epoll instance, we must clean it */
	if (isepfd(newfd)) {
		fpu_so_rpc_epoll_destroy(newfd);
	}

	if (!isfpusofd(oldfd)) {
		/* if oldfd is owned by the libc and newfd by the fast path, we
		 * need to close newfd first */
		if (isfpusofd(newfd)) {
			INC_STATS(close.rpc);
			fpu_so_rpc_close(newfd);
		}

		/* if newfd is owned by glibc or if it is already closed, let
		 * the glibc do the job */
		INC_STATS(dup2.glibc);
		ret = glibc_dup2(oldfd, newfd);

		/* glibc call won't update our fd2ep, so let's do it now */
		if (isepfd(oldfd)) {
			fpu_so_rpc_epoll_duplicate(oldfd, newfd);
			fpu_so_rpc_epoll_destroy(oldfd);
		}

	}
	else {
		/* if oldfd is owned by fast path, call fpu_so_rpc_dup2() that
		 * will close newfd if it is valid */
		INC_STATS(dup2.rpc);
		ret = fpu_so_rpc_dup2(oldfd, newfd);
	}

	if (ret >= 0)
		INC_STATS(dup2.success);
	else
		INC_STATS(dup2.error);

	return ret;
}

int dup(int oldfd)
{
	int ret;

	INC_STATS(dup.call);
	fpu_so_log(DEBUG, GLIBC, "called (oldfd=%d)\n",
		  oldfd);

	if (!isfpusofd(oldfd)) {
		INC_STATS(dup.glibc);
		ret = glibc_dup(oldfd);
		/* If glibc is happy, then copy epoll information */
		if (ret >= 0 && isepfd(oldfd)) {
			fpu_so_rpc_epoll_duplicate(oldfd, ret);
		}
	}
	else {
		INC_STATS(dup.rpc);
		ret = fpu_so_rpc_dup(oldfd);
	}

	if (ret >= 0)
		INC_STATS(dup.success);
	else
		INC_STATS(dup.error);

	return ret;
}
