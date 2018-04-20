# Copyright 2014 6WIND S.A.

VPATH += $(DIST_FP_VSWITCH)/fpdebug
VPATH += $(DIST_FP_VSWITCH)/common

SRCS += fpdebug-vswitch.c fpvs-common.c fpvs-print.c

CFLAGS += -I$(DIST_FP_VSWITCH)
CFLAGS += -I$(DIST_FP_VSWITCH)/common
CFLAGS += -I$(DIST_FP_VSWITCH)/openvswitch
