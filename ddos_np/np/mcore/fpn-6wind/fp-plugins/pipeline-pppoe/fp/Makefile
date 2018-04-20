# Copyright 2013-2014 6WIND S.A.

FASTPATH_PLUGIN=y
include $(DIST_FP)/fp-plugins/common/mk/plugin-init.mk

VPATH= $(S)
CFLAGS += -I$(S)/..

LIB= pppoe-load-balancer.so
SHARED_LIB=yes

SRCS= pppoe-load-balancer.c

include $(DIST_FP)/fp-plugins/common/mk/plugin-lib.mk
