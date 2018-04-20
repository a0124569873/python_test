# Copyright 2014 6WIND S.A.

MCORE_FILES += $(DIST_FP_VSWITCH)/fp/fpvs-datapath.c
MCORE_FILES += $(DIST_FP_VSWITCH)/fp/fpvs-flow.c
MCORE_FILES += $(DIST_FP_VSWITCH)/fp/fpvs-init.c
MCORE_FILES += $(DIST_FP_VSWITCH)/common/fpvs-print.c
MCORE_FILES += $(DIST_FP_VSWITCH)/common/fpvs-common.c

ifeq ($(CONFIG_MCORE_VXLAN),y)
MCORE_FILES += $(DIST_FP_VSWITCH)/fp/fpvs-vxlan.c
endif

ifeq ($(CONFIG_MCORE_GRE),y)
MCORE_FILES += $(DIST_FP_VSWITCH)/fp/fpvs-gre.c
endif

ifeq ($(CONFIG_MCORE_EMBEDDED_FPDEBUG),y)
MCORE_FILES += $(DIST_FP_VSWITCH)/fpdebug/fpdebug-vswitch.c
endif

MCORE_CFLAGS += -I$(DIST_FP_VSWITCH)/fp
MCORE_CFLAGS += -I$(DIST_FP_VSWITCH)/fp/include
MCORE_CFLAGS += -I$(DIST_FP_VSWITCH)/openvswitch
MCORE_CFLAGS += -I$(FPNSDK_DIR)

MCORE_LDLIBS += -ldl

include $(DIST_FP_VSWITCH)/common/fp-vswitch-cflags.mk

CFLAGS_fpvs-common.o += $(MCORE_CFLAGS_FP_VSWITCH)
CFLAGS_fpvs-datapath.o += $(MCORE_CFLAGS_FP_VSWITCH)

# For dlsym()'s RTLD_DEFAULT
CFLAGS_fpvs-init.o += -D_GNU_SOURCE
