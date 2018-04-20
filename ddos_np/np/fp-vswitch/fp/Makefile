# Copyright 2014 6WIND S.A.

-include $(FP_DOT_CONFIG)

FASTPATH_PLUGIN=y
include $(DIST_FP)/fp-plugins/common/mk/plugin-init.mk

VPATH= $(S) $(S)/../common $(S)/../fpdebug

LIB= libfp-vswitch.so
SHARED_LIB=yes

CFLAGS += -I$(S)
CFLAGS += -I$(S)/../common
CFLAGS += -I$(S)/../fpdebug

# For dlsym()'s RTLD_DEFAULT
CFLAGS += -D_GNU_SOURCE

# for openvswitch headers
CFLAGS += -Wno-undef -Wno-nested-externs -Wno-sign-compare

include $(S)/../common/fp-vswitch-cflags.mk

CFLAGS += -I$(S)/../openvswitch

SRCS-y += fpvs-common.c
SRCS-y += fpvs-datapath.c
SRCS-y += fpvs-flow.c
SRCS-y += fpvs-init.c
SRCS-y += fpvs-print.c
SRCS-$(CONFIG_MCORE_GRE) += fpvs-gre.c
SRCS-$(CONFIG_MCORE_VXLAN) += fpvs-vxlan.c
SRCS-$(CONFIG_MCORE_EMBEDDED_FPDEBUG) += fpdebug-vswitch.c
SRCS:=$(SRCS-y)

FP_OBJS= $(SRCS:%.c=%.o)

OBJS= $(FP_OBJS)

CFLAGS_fpvs-datapath.o += $(MCORE_CFLAGS_FP_VSWITCH)
CFLAGS_fpvs-flow.o += $(MCORE_CFLAGS_FP_VSWITCH)

PLUGIN_AUTO_LOAD=y
include $(DIST_FP)/fp-plugins/common/mk/plugin-lib.mk
