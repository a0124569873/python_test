/*
 * Copyright (C) 2010 6WIND, All rights reserved.
 */

/*
 * Copyright (c) 1992-2010 The FreeBSD Project. All rights reserved.
 * Copyright (c) 1982, 1986, 1990, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef _FP_SOCKET_H_
#define _FP_SOCKET_H_


typedef uint16_t fp_sa_family_t;
typedef size_t fp_socklen_t;

struct fp_sockaddr {
	fp_sa_family_t  sa_family;    /* address family, FP_AF_xxx	*/
	char            sa_data[26];  /* 26 bytes of protocol address	*/
};


/* Supported address families. */
#ifndef AF_LOCAL
#define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
#endif
#ifndef AF_INET
#define AF_INET		2	/* Internet IP Protocol 	*/
#endif
#ifndef AF_INET6
#define AF_INET6	10	/* IP version 6			*/
#endif
#ifndef AF_MAX
#define AF_MAX		11
#endif

/* Protocol families, same as address families. */
#ifndef PF_LOCAL
#define PF_LOCAL	AF_LOCAL
#endif
#ifndef PF_INET
#define PF_INET		AF_INET
#endif
#ifndef PF_INET6
#define PF_INET6	AF_INET6
#endif
#ifndef PF_MAX
#define PF_MAX		AF_MAX
#endif

/* Setsockoptions(2) level. Thanks to BSD these must match IPPROTO_xxx */
#define FP_SOL_IP		0
/* #define FP_SOL_ICMP	1	No-no-no! Due to Linux :-) we cannot use SOL_ICMP=1 */
#define FP_SOL_TCP		6
#define FP_SOL_UDP		17
#define FP_SOL_IPV6	41
#define FP_SOL_ICMPV6	58
#define FP_SOL_SCTP	132
#define FP_SOL_RAW		255
#define FP_SOL_IPX		256
#define FP_SOL_AX25	257
#define FP_SOL_ATALK	258
#define FP_SOL_NETROM	259
#define FP_SOL_ROSE	260
#define FP_SOL_DECNET	261
#define	FP_SOL_X25		262
#define FP_SOL_PACKET	263
#define FP_SOL_ATM		264	/* ATM layer (cell level) */
#define FP_SOL_AAL		265	/* ATM Adaption Layer (packet level) */
#define FP_SOL_IRDA        266
#define FP_SOL_NETBEUI	267
#define FP_SOL_LLC		268
#define FP_SOL_DCCP	269
#define FP_SOL_NETLINK	270


/*
 *  * Types
 *   */
#define FP_SOCK_STREAM     1
#define FP_SOCK_DGRAM      2
#define FP_SOCK_RAW        3
#define FP_SOCK_RDM        4
#define FP_SOCK_SEQPACKET  5
#define FP_SOCK_DCCP       6
#define FP_SOCK_PACKET     10


/*
 * Option flags per-socket.
 */
#define	FP_SO_ACCEPTCONN	0x0002		/* socket has had listen() */
#define	FP_SO_REUSEADDR	0x0004		/* allow local address reuse */
#define	FP_SO_KEEPALIVE	0x0008		/* keep connections alive */
#define	FP_SO_DONTROUTE	0x0010		/* just use interface addresses */
#define	FP_SO_BROADCAST	0x0020		/* permit sending of broadcast msgs */
#define	FP_SO_USELOOPBACK	0x0040		/* bypass hardware when possible */
#define	FP_SO_LINGER	0x0080		/* linger on close if data present */
#define	FP_SO_REUSEPORT	0x0200		/* allow local address & port reuse */
#define	FP_SO_TIMESTAMP	0x0400		/* timestamp received dgram traffic */


/*
 * Additional options, not kept in so_options.
 */
#define FP_SO_SNDBUF	0x1001		/* send buffer size */
#define FP_SO_RCVBUF	0x1002		/* receive buffer size */
#define FP_SO_SNDLOWAT	0x1003		/* send low-water mark */
#define FP_SO_RCVLOWAT	0x1004		/* receive low-water mark */
#define FP_SO_SNDTIMEO	0x1005		/* send timeout */
#define FP_SO_RCVTIMEO	0x1006		/* receive timeout */
#define	FP_SO_ERROR	0x1007		/* get error status and clear */
#define	FP_SO_TYPE		0x1008		/* get socket type */
#define	FP_SO_OVERFLOWED	0x1009		/* datagrams: return packets dropped */

#define	FP_SO_NOHEADER	0x100a		/* user supplies no header to kernel;
					 * kernel removes header and supplies
					 * payload
					 */
#define	FP_SO_VRFID		0x1040	/* socket vrfid */
#define	FP_SO_DISPATCH_MASTER	0x1041	/* enable bind dispatch on master socket */
#define	FP_SO_DISPATCH_SLAVE	0x1042	/* enable bind dispatch on slave sockets */
#define FP_SO_NO_BIND_DISPATCH	-1      /* opt value when bind dispatch is disabled */
#define FP_SO_MAX_BIND_DISPATCH	256	/* maximum number of slave sockets */

/*
 * Structure used for manipulating linger option.
 */
struct fp_linger {
	int	l_onoff;		/* option on/off */
	int	l_linger;		/* linger time in seconds */
};

/*
 * Level number for (get/set)sockopt() to apply to socket itself.
 */
#define	FP_SOL_SOCKET	0xffff		/* options for socket level */

/*
 * Maximum queue length specifiable by listen(2).
 */
#define	FP_SOMAXCONN	65535

#define	FP_MSG_PEEK	0x0002		/* peek at incoming message */
#define	FP_MSG_DONTROUTE	0x0004		/* send without using routing tables */
#define	FP_MSG_TRUNC	0x0010		/* data discarded before delivery */
#define	FP_MSG_CTRUNC	0x0020		/* control data lost before delivery */
#define	FP_MSG_BCAST	0x0100		/* this message was rcvd using link-level brdcst */
#define	FP_MSG_MCAST	0x0200		/* this message was rcvd using link-level mcast */
#define	FP_MSG_NOSIGNAL	0x0400		/* do not generate SIGPIPE on EOF */

/* Extra flags used internally only */
#define	FP_MSG_USERFLAGS	0x0ffffff
#define FP_MSG_NAMEMBUF	0x1000000	/* msg_name is an mbuf */
#define FP_MSG_CONTROLMBUF	0x2000000	/* msg_control is an mbuf */
#define FP_MSG_IOVUSRSPACE	0x4000000	/* msg_iov is in user space */
#define FP_MSG_LENUSRSPACE	0x8000000	/* address length is in user space */

/*
 * Types of socket shutdown(2).
 */
#define	FP_SHUT_RD		0		/* Disallow further receives. */
#define	FP_SHUT_WR		1		/* Disallow further sends. */
#define	FP_SHUT_RDWR	2		/* Disallow further sends/receives. */


#endif /* _FP_SOCKET_H */

