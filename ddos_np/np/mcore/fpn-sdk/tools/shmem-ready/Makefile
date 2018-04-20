# Copyright 2013 6WIND S.A.

PROG = fp-shmem-ready

VPATH = $(S)

SRCS = shmem-ready.c

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
