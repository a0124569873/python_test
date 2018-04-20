# Copyright 2013 6WIND S.A.

FASTPATH_PLUGIN=y
include $(DIST_FP)/fp-plugins/common/mk/plugin-init.mk

VPATH= $(S)

LIB= egress-qos.so
SHARED_LIB=yes

SRCS= egress-qos.c

CFLAGS += -I$(DIST_FP)/fp-modules/egress-qos/dataplane

include $(DIST_FP)/fp-plugins/common/mk/plugin-lib.mk
