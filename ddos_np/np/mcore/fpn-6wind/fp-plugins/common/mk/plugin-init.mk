# Copyright 2013 6WIND S.A.

export FP_BUILDROOT ?= /usr/local/fp
export FPNSDK_DIR ?= /usr/local/fpn-sdk
export DIST_FP ?= /usr/local/fp
export FP_DOT_CONFIG ?= /usr/local/fp/config/fp.config
export VNB_BINDIR ?= /usr/local/vnb
export S ?= $(CURDIR)

# From arch/dpdk/Makefile
include $(DIST_FP)/mcore_common.mk

ifeq ($(FASTPATH_PLUGIN),y)
include $(DIST_FP)/fastpath/mcore.mk
FPNSDK_CFLAGS += $(MCORE_CFLAGS)
else
FPNSDK_CFLAGS += $(MCORE_COMMON_CFLAGS)
endif

# From fpn-sdk/mk/fpn-prog.mk
include $(FPNSDK_DIR)/fpn-arch.mk

ifneq ($(fpn_arch),)
-include $(DIST_FP)/fp-plugins/common/$(fpn_arch)/plugin-init.mk
endif

CFLAGS += $(FPNSDK_CFLAGS) -I$(DIST_FP)/fp-plugins/common/include
LDFLAGS+= $(FPNSDK_LDFLAGS)
