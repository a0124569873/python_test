# Copyright 2014 6WIND S.A.

PROG = fp-shmem-dpvi

VPATH = $(S)

SRCS = shmem-dpvi.c

CFLAGS+= -Wall -Werror

FPNSDK_DIR?=$(S)/../..

include $(FPNSDK_DIR)/fpn-arch.mk

CFLAGS+= $(FPNSDK_CFLAGS)
LDFLAGS+= $(FPNSDK_LDFLAGS)
LDLIBS += -lfpn-shmem
ifeq ($(CONFIG_MCORE_SHM_GENERIC_POSIX),y)
LDLIBS += -lrt
endif

include mk/prog.mk

