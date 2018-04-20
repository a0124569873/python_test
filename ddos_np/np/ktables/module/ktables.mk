# Get environment variables
include $(ROOTDIR)/mk/6windgatelinux.own.mk

VPATH = ${DIST_KTABLES}/module

MODULE  = ktables
SRCDIR  = ${VPATH}
MODULE_PATH = net

# for libntlnk
EXTRA_CFLAGS += -I${VPATH} -I${ROOTDIR}/ports/ktables/config
EXTRA_CFLAGS += -Wall -Werror

SRCS = ktables.c

SRCS := $(addprefix $(SRCDIR)/,$(SRCS))

include $(ROOTDIR)/mk/6windgatelinux.module.mk
