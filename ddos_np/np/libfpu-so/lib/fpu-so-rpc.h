/*
 * Copyright(c) 2013 6WIND, All rights reserved
 */

#ifndef _FPU_SO_RPC_H_
#define _FPU_SO_RPC_H_

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/queue.h>

struct fd_t {
	LIST_ENTRY(fd_t) fdlist;
	int32_t fpfd;
};

struct fpfd_t {
	LIST_HEAD(epoll_list, epoll_fpfd_t) ephead;
	LIST_HEAD(fd_list, fd_t) fdhead;
};

struct epoll_t {
	LIST_HEAD(fpfd_list, epoll_fpfd_t) fpfdhead;
	int used;
	int kernel;
	int flags;
};

struct epoll_fpfd_t {
	LIST_ENTRY(epoll_fpfd_t) eplist;
	LIST_ENTRY(epoll_fpfd_t) fpfdlist;
	struct epoll_t *ep;
	struct fpfd_t *fpfd;
	int fd;
	struct epoll_event ev;
	int prev;
};

/* Called in init to prepare rpc structures */
void fpu_so_rpc_preinit(void);

/* Initialize fpu_so_rpc subsystem. Return 0 on success. */
int fpu_so_rpc_init(void);

/* libc-like API */

int fpu_so_rpc_socket(int domain, int type, int protocol);
int fpu_so_rpc_connect4(int fd, const struct sockaddr *addr,
			socklen_t addrlen);
int fpu_so_rpc_bind4(int fd, const struct sockaddr *addr,
		     socklen_t addrlen);
int fpu_so_rpc_listen(int fd, int backlog);
int fpu_so_rpc_accept4(int fd, struct sockaddr *addr, socklen_t *addrlen);
int fpu_so_rpc_write(int fd, const void *buf, size_t count);
int fpu_so_rpc_send(int fd, const void *buf, size_t len, int flags);
int fpu_so_rpc_sendto4(int fd, const void *buf, size_t len, int flags,
		       const struct sockaddr *dest_addr, socklen_t addrlen);
int fpu_so_rpc_read(int fd, void *buf, size_t count);
int fpu_so_rpc_recv(int fd, void *buf, size_t len, int flags);
int fpu_so_rpc_recvfrom4(int fd, void *buf, size_t len, int flags,
			 struct sockaddr *src_addr, socklen_t *addrlen);
int fpu_so_rpc_close(int fd);
int fpu_so_rpc_shutdown(int fd, int how);
int fpu_so_rpc_getsockname4(int fd, struct sockaddr *addr, socklen_t *addrlen);
int fpu_so_rpc_getpeername4(int fd, struct sockaddr *addr, socklen_t *addrlen);
int fpu_so_rpc_fcntl(int fd, int cmd, ... /* arg */);
int fpu_so_rpc_ioctl(int fd, unsigned long int req, ... /* arg */);
int fpu_so_rpc_poll(struct pollfd fds[], nfds_t nfds, int timeout);
int fpu_so_rpc_epoll_create1(int epfd, int flags);
void fpu_so_rpc_epoll_destroy(int epfd);
void fpu_so_rpc_epoll_duplicate(int oldfd, int newfd);
int fpu_so_rpc_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event,
                         int prev);
int fpu_so_rpc_epoll_wait(int epfd, struct epoll_event *events, int maxevents);
int fpu_so_rpc_select(int nfds, fd_set *readfds, fd_set *writefds,
		     fd_set *errorfds, struct timeval *timeout);
int fpu_so_rpc_getsockopt(int sockfd, int level, int optname,
			 void *optval, socklen_t *optlen);
int fpu_so_rpc_setsockopt(int sockfd, int level, int optname,
			 const void *optval, socklen_t optlen);
int fpu_so_rpc_dup2(int oldfd, int newfd);
int fpu_so_rpc_dup(int oldfd);
int fpu_so_rpc_dup_all(int clone, const char *shmname);

#endif
