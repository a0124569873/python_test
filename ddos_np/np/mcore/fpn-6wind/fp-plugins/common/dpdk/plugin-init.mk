# Copyright 2013 6WIND S.A.

ifeq ($(FASTPATH_PLUGIN),y)
# From fpn-sdk/dpdk/mk/fpn-prog.mk
include $(FPNSDK_DIR)/dpdk/mk/dpdk-init.mk
# Keep dpdk from ruining LDFLAGS
CPU_LDFLAGS =
include $(RTE_SDK)/mk/rte.vars.mk
include $(FPNSDK_DIR)/dpdk/mk/dpdk-options.mk

FPNSDK_CFLAGS += -Wno-unused-parameter
# FIXME: remove some warning detection
FPNSDK_CFLAGS += -Wno-pointer-arith -Wno-cast-qual
endif
