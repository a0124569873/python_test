# Copyright 2013 6WIND S.A.

PROG = fpsd

include $(DIST_FP)/mcore_common.mk
include $(FPNSDK_DIR)/fpn-arch.mk

VPATH = $(S)

SRCS = fps.c fps-nl.c

FPNSDK_DIR?=$(S)/../..

CFLAGS += -O2 -Wextra -Wall
CFLAGS += -Werror
CFLAGS += -Wundef
CFLAGS += -Wno-unused-parameter
CFLAGS += -g
CFLAGS += $(FPNSDK_CFLAGS)

CFLAGS += $(MCORE_COMMON_CFLAGS) -DFP_LOG_COMMON_PRINTF

CFLAGS += -I$(DIST_FP)/libfp_shm
LDLIBS += -L../../libfp_shm
LDLIBS += -lfp_shm
LDLIBS += $(FPNSDK_LDFLAGS) -lfpn-shmem

CFLAGS   += $(libevent-cflags)
LDFLAGS  += $(libevent-ldflags)
LDLIBS += -levent

# Last chance to find libnl3 headers in native mode
libnl-cflags ?= $(shell pkg-config --silence-errors --cflags libnl-3.0)
CFLAGS += $(libnl-cflags)
LDFLAGS += $(libnl-ldflags)
LDLIBS += -lnl-3 -lnl-route-3

ifeq ($(CONFIG_HA6W_SUPPORT), y)
CFLAGS += $(ha-cflags)
LDFLAGS += $(ha-ldflags)
LDLIBS += -l6whas -lxml2 -lxt -lm
endif

include $(FPNSDK_DIR)/mk/prog.mk
