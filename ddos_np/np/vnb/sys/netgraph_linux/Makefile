# Copyright 2014 6WIND S.A.

S?=$(CURDIR)

SRCS_LINUX = ng_netlink.c ng_rcu.c callout.c ng_rxhandler.c ng_netns.c

SRCS := $(addprefix $(S)/,$(SRCS_LINUX))

# HDRS_SUBDIR is used when copying headers into destdir
HDRS_SUBDIR = netgraph_linux
HDRS = $(SRCS:.c=.h)

VNB_MODS := vnb-linux

include $(TOP_S)/kbuild.mk

EXTRA_CFLAGS += -I$(TOP_S)/sys/netgraph/nglib
# for alignment.h
EXTRA_CFLAGS += -I$(includedir)/netgraph

ifneq ($(KERNELRELEASE),)
obj-m += $(addsuffix .o,$(VNB_MODS))
$(VNB_MODS)-objs = $(notdir $(SRCS:%.c=%.o))
endif

# defines $(DKMSDIR)/ subdirectory where to store source files
MODULE_SRC_DIR := sys/netgraph_linux
-include $(TOP_S)/module.mk
