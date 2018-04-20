# Copyright 2014 6WIND S.A.

include $(DIST_FP)/fp-plugins/common/mk/plugin-init.mk

VPATH= $(S) $(S)/../common

LIB= libfpd-vswitch.so
SHARED_LIB=yes

CFLAGS += -Wno-unused
CFLAGS += -I$(DIST_FP)/fpdebug
CFLAGS += -I$(S)
CFLAGS += -I$(S)/../common
CFLAGS += -I$(S)/../openvswitch

SRCS= fpdebug-vswitch.c fpvs-common.c fpvs-print.c

OBJS= $(SRCS:%.c=%.o)

PLUGIN_AUTO_LOAD=y
include $(DIST_FP)/fp-plugins/common/mk/plugin-lib.mk
