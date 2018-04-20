# Copyright 2014 6WIND S.A.

PROG = hitflagsd

include $(DIST_FP)/mcore_common.mk
include $(FPNSDK_DIR)/fpn-arch.mk

VPATH = $(S)

SRCS = hitflags.c

SUBDIR-y += scripts

SUBDIR = $(SUBDIR-y)

include $(FPNSDK_DIR)/mk/subdir.mk

#FPNSDK_DIR?=$(S)/../..

CFLAGS += -O2 -Wextra -Wall
CFLAGS += -Werror
CFLAGS += -Wundef
CFLAGS += -Wno-unused-parameter
CFLAGS += -g
CFLAGS += $(FPNSDK_CFLAGS)

CFLAGS += $(MCORE_COMMON_CFLAGS) -DFP_LOG_COMMON_PRINTF

CFLAGS += -I$(DIST_FP)/libfp_shm
LDLIBS += -L../libfp_shm
LDLIBS += -lfp_shm
LDLIBS += $(FPNSDK_LDFLAGS) -lfpn-shmem

CFLAGS   += $(libevent-cflags)
LDFLAGS  += $(libevent-ldflags)
LDLIBS += -levent

ifeq ($(CONFIG_HA6W_SUPPORT), y)
CFLAGS += $(ha-cflags)
LDFLAGS += $(ha-ldflags)
LDLIBS += -l6whas -lxml2 -lxt -lm
endif

include $(FPNSDK_DIR)/mk/prog.mk
