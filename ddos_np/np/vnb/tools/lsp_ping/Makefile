#########################################################################
# beginning of overwrite part -> depend on each application
#########################################################################

# include application Makefile
PROG = lsp_ping
LIST = $(PROG)
# used for in_cksum.c/in_cksum.h
PINGD_DIR = ${DIST_VNB}/tools/pingd

SRCS = lsp_ping.c in_cksum.c

VPATH = ${DIST_VNB}/tools/lsp_ping
VPATH+= ${PINGD_DIR}

CFLAGS+= -Wall -Werror -DHAVE_GCC_FUNCTION
CFLAGS+= -I${PINGD_DIR}

# for libevent
CFLAGS+= -I$(DIST_LIBEVENT)
LDADD+= -L$(ROOTDIR)/ports/libevent -levent

# for libnetgraph
CFLAGS+= -I${DIST_LIBNETGRAPH} -I${DIST_VNB}/sys -I${DIST_VNB}/mpls
LDADD+= -L$(LIBNETGRAPH_DIR) -lnetgraph
