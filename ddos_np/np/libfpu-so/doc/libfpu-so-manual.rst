.. Copyright 2013 6WIND S.A.

=============================
Fast Path User Socket Library
=============================

Introduction
============

The library ``libfpu-so.so`` wraps network-oriented system calls and, depending
on the type of the socket, either redirects them to the TCP/UDP stack that is
embedded in the fast path, or directly invokes the corresponding system
call of the underlying Linux kernel.

Features
========

Fast Path User Socket Library features:

-  wrap network-oriented system calls to redirect them to the TCP/IP
   stack that is embedded in the fast path
-  transparent support of binary applications
-  compliant with multi-threaded and/or multi-process applications
-  can be used with multiple applications running in parallel
-  full support of TCP and UDP sockets in the ``AF_INET`` and the ``AF_INET6``
   communication domains

Dependencies
============

The locally running fast path must have been built with the following
optional modules:

-  Fast Path TCP termination
-  Fast Path Userland RPC

Usage
=====

To make a network-oriented application ``net-app`` transparently use the
TCP/UDP stack embedded in the fast path, launch it as follows:
  
.. code-block:: console

   [FPUSO_OPT="opt1 opt2 ..."] LD_LIBRARY_PATH=/usr/local/lib LD_PRELOAD=/usr/local/lib/libfpu-so.so net-app [arg1 arg2 ...]

Runtime options
---------------

The library ``libfpu-so.so`` can be supplied the following run-time options in
the ``FPUSO_OPT`` environment variable:

- ``-d, --debug``

   Set debug level for the selected mask of log event categories:

   - 0x01: library init logs
   - 0x02: library logs of glibc invocations
   - 0x04: library logs of RPC with fast path
   - 0x08: library logs of epoll events

- ``-D LEVEL, --loglevel=LEVEL``

   Force debug level for log event categories that are not in the debug mask

- ``-v``

   Display the library version and exit

- ``-h``

   Display the help message and exit

- ``-b, --bypass``

   Systematically invokes Linux system calls through the glibc, instead of
   redirecting them to the TCP/IP stack that is embedded in the fast path.
   This option can be used in conjunction with the ``--debug=0x04`` option
   to perform a kind of ``strace`` on all network-oriented system calls that
   are invoked by the application.

Usage example
-------------

The client side of the ``iperf`` tool used to benchmark network communications
can be launched with the library ``libfpu-so.so`` as follows:
  
.. code-block:: console

  LD_LIBRARY_PATH=/usr/local/lib LD_PRELOAD=/usr/local/lib/libfpu-so.so iperf -c 10.200.0.1 -t 100 -P 10

with the ``iperf`` arguments:

-  ``-c 10.200.0.1`` to run in client mode, connecting to ``10.200.0.1`` host
-  ``-t 100`` to transmit data during 100 seconds
-  ``-P 10`` to run in parallel 10 client threads

Wrapped system calls
====================

The following set of system calls are wrapped by the library ``libfpu-so.so``:

.. code-block:: c

   int socket(int domain, int type, int proto)

   ssize_t write(int fd, const void *buf, size_t len)

   ssize_t read(int fd, void *buf, size_t len)

   ssize_t recv(fd, void *buf, size_t len, int flags)

   ssize_t recvfrom(int int fd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *alen)

   ssize_t recvmsgg(int fd, struct msghdr *mh, int flags)

   ssize_t send(int fd, const void *buf, size_t len, int flags)

   ssize_t sendmsg(int fd, const struct msghdr *mh, int flags)

   ssize_t sendto(int fd, const void *buf, size_t len, int flags,
                  const struct sockaddr *dst_addr, socklen_t alen)

   int bind(int fd, const struct sockaddr *addr, socklen_t alen)

   int connect(int fd, const struct sockaddr *addr, socklen_t alen)

   int accept(int fd, struct sockaddr *addr, socklen_t *alen)

   int accept4(int fd, struct sockaddr *addr, socklen_t *alen, int flags)

   int listen(int fd, int backlog)

   int fcntl(int fd, int cmd, ...)

   int ioctl(int fd, unsigned long int req, ...)

   int close(int fd)

   int shutdown(int fd, int how)

   int sockatmark(int fd)

   int getsockname(int fd, struct sockaddr *addr, socklen_t *alen)

   int getpeername(int fd, struct sockaddr *addr, socklen_t *alen)

   int getsockopt(int fd, int level, int optname, void *optvalue,
                  socklen_t *optlen)

   int setsockopt(int fd, int level, int optname,
                  const void *optvalue, socklen_t optlen)

   int select(int nfds, fd_set *readfds, fd_set *writefds,
              fd_set *errorfds, struct timeval *timeout)

   int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *errorfds,
               const struct timespec *timeout, const sigset_t *sigmask)

   int poll(struct pollfd fds[], nfds_t nfds, int timeout)

   int epoll_create(int size)

   int epoll_create1(int flags)

   int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)

   int epoll_wait(int epfd, struct epoll_event *events,
                  int maxevents, int timeout)

   int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                   int timeout, const sigset_t *sigmask)

Support of ``setsockopt`` and ``getsockopt`` options
----------------------------------------------------

The following ``setsockopt`` and ``getsockopt`` options are supported for
option level ``SOL_SOCKET``:

   +--------------------------------------------+
   |       Option level ``SOL_SOCKET``          |
   +----------------+---------------+-----+-----+
   | Option name    | Option type   | Set | Get |
   +================+===============+=====+=====+
   | SO_LINGER      | struct linger |  x  |  x  |
   +----------------+---------------+-----+-----+
   | SO_KEEPALIVE   | int 0/1       |  x  |  x  |
   +----------------+---------------+-----+-----+
   | SO_DONTROUTE   | int 0/1       |  x  |  x  |
   +----------------+---------------+-----+-----+
   | SO_BROADCAST   | int 0/1       |  x  |  x  |
   +----------------+---------------+-----+-----+
   | SO_REUSEADDR   | int 0/1       |  x  |  x  |
   +----------------+---------------+-----+-----+
   | SO_TIMESTAMP   | int 0/1       |  x  |  x  |
   +----------------+---------------+-----+-----+
   | SO_SNDBUF      | int           |  x  |  x  |
   +----------------+---------------+-----+-----+
   | SO_RCVBUF      | int           |  x  |  x  |
   +----------------+---------------+-----+-----+
   | SO_SNDLOWAT    | int           |  x  |  x  |
   +----------------+---------------+-----+-----+
   | SO_RCVLOWAT    | int           |  x  |  x  |
   +----------------+---------------+-----+-----+
   | SO_TYPE        | int           |     |  x  |
   +----------------+---------------+-----+-----+
   | SO_ERROR       | int           |     |  x  |
   +----------------+---------------+-----+-----+

The following ``setsockopt`` and ``getsockopt`` options are supported for
option level ``IPPROTO_TCP``:

   +-----------------------------------------+
   |       Option level `IPPROTO_TCP`        |
   +---------------+-------------+-----+-----+
   | Option name   | Option type | Set | Get |
   +===============+=============+=====+=====+
   | TCP_NODELAY   | int 0/1     |  x  |  x  |
   +---------------+-------------+-----+-----+
   | TCP_MAXSEG    | int         |  x  |  x  |
   +---------------+-------------+-----+-----+
   | TCP_KEEPIDLE  | u_int       |  x  |     |
   +---------------+-------------+-----+-----+
   | TCP_KEEPINTVL | u_int       |  x  |     |
   +---------------+-------------+-----+-----+
   | TCP_KEEPCNT   | u_int       |  x  |     |
   +---------------+-------------+-----+-----+


Associated man pages
--------------------

See network-oriented Linux manual pages:

-  ``man 2 socket``
-  ``man 7 tcp``
-  ``man 7 udp``

More globally, see the Linux man pages project at http://www.kernel.org/doc/man-pages/

Restrictions
============

Coexistence of Linux kernel and fast path TCP/UDP stacks
--------------------------------------------------------

The coexistence on the same machine of the Linux kernel and of the fast path
TCP/UDP stacks imposes restrictions on standard socket IP families addressing
rules.

Split of TCP/UDP port ranges
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To avoid binding a pure Linux socket and a fast path socket with the same
TCP or UDP port, the full ranges of TCP ports and of UDP ports are split
into 2 disjointed ranges respectively assigned to the Linux kernel and to
the fast path according to the following rules:

-  the full range of TCP ports is split into 2 disjointed ranges of TCP ports,
-  the full range of UDP ports is split into 2 disjointed ranges of UDP ports,
-  the range of ephemeral TCP/UDP ports (used for implicit bindings) is split
   into 2 disjointed ranges of ephemeral ports.

Network interfaces and IP addresses
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The library ``libfpu-so.so`` transparently redirects to the Linux kernel
all system calls on sockets that are created in communication domains that are
not supported by the TCP/UDP stack of the fast path, such as ``AF_UNIX`` for
instance.
However, when linked with the library ``libfpu-so.so``, an application must
only bind and/or connect TCP/UDP sockets using IP addresses that can be managed
by the fast path according to its runtime configuration of IP addresses.

Hence, when linked with the library ``libfpu-so.so``, an application cannot
bind or connect a TCP/UDP socket using the local IP address ``127.0.0.1``
that is assigned to the kernel loopback interface.

More globally, an application linked with the library ``libfpu-so.so`` cannot
bind or connect [TCP/UDP] sockets using IP addresses that are associated with
or that are [only] reachable through network interfaces that are controlled
by the underlying Linux kernel.

In the same way, a server application that creates a listening TCP socket
that it binds to the ``INADDR_ANY`` pseuso IP address won't be delivered
incoming TCP connection requests (TCP SYN packets) received from network
interfaces that are controlled by the underlying Linux kernel.

System resource limits
----------------------

The library ``libfpu-so.so`` maintains its own table of file descriptors
in the virtual address space of each application's process into which it
is executed, and uses its own maximum number of entries for file descriptor
tables.
This value is not inherited from the system Per-User/Group/Process file
descriptor limits that can be displayed by the ``ulimit -n`` builtin shell
command, for instance.

As a consequence, changing the system limit of the maximum number of
file descriptors, either temporarily for the session duration with the
shell builtin command:

.. code-block:: console

   ulimit -n max_fd_value

or permanently by updating the configuration file ``/etc/security/limits.conf``
with entries such as:

::
  
  ftp - nofile 512
  @group_name soft nofile 4096

won't then be taken into account by the library ``libfpu-so.so``.

Compilation
===========

Prerequisites
-------------

-  development packages have been properly installed on the host,
-  fast path previously built with the following required modules:

   -  fastpath-tcp-udp package
   -  fastpath-fpu-rpc package

Build and installation
----------------------

To build the library ``libfpu-so.so``, the following source package must be
present on the development host:

-  <VERSION>-libfpu-so-src.tgz

Extract sources:
  
.. code-block:: console

   tar -zvf <VERSION>-libfpu-so-src.tgz

Build the library ``libfpu-so.so``:
  
.. code-block:: console

   make -C libfpu-so/lib

Install the library ``libfpu-so.so`` in ``/usr/local/lib``:

.. code-block:: console

   sudo make -C libfpu-so/lib install
