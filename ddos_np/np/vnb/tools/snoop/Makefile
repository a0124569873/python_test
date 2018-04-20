#	@(#)Makefile	8.1 (Berkeley) 6/5/93
# $FreeBSD: src/sbin/route/Makefile,v 1.11.2.3 2002/12/04 14:05:42 ru Exp $

NOMAN=  YES
PROG=	snoopd
SRCS=	main.c config.c core.c notify.c display.c mld.c netlink.c
CFLAGS+=-Wall -g -I${LIBEVENT_DIR}
#CFLAGS+=-D__FAST_MLD_
DPADD=		${LIBNETGRAPH}
LDFLAGS+= -L$(LIBNETGRAPH_DIR) -L${LIBEVENT_DIR}
LDFLAGS+= -L${NETWORK_DIR}/tools/libaliaspt
LDADD=		-lnetgraph -levent -l aliaspt

.include <bsd.prog.mk>
