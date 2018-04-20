# Copyright 2013 6WIND S.A.

PROG = fp-shmem-ports

VPATH = $(S)

SRCS = shmem-ports.c

CFLAGS+= -Wall -Werror

FPNSDK_DIR?=$(S)/../..

include $(FPNSDK_DIR)/fpn-arch.mk

ifeq ($(CONFIG_MCORE_L2_INFRA),y)
VPATH += $(FPNSDK_DIR)
SRCS  += fpn-vlanport.c
endif

CFLAGS+= $(FPNSDK_CFLAGS)
LDFLAGS+= $(FPNSDK_LDFLAGS)
LDLIBS += -lfpn-shmem
ifeq ($(CONFIG_MCORE_SHM_GENERIC_POSIX),y)
LDLIBS += -lrt
endif

include mk/prog.mk
