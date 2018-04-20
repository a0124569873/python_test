# get environment variables
include $(ROOTDIR)/mk/6windgatelinux.own.mk

PROG = ktables
LIST = ${PROG}

SRCS = ktables.c

VPATH = ${DIST_KTABLES}/ktables

EXTRA_CFLAGS += -I${DIST_KTABLES}
EXTRA_CFLAGS += -I${ROOTDIR}/ports/ktables/config
EXTRA_CFLAGS += -Wall -Werror


include ${ROOTDIR}/mk/6windgatelinux.prog.mk

