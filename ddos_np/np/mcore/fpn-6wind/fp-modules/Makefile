# Copyright 2013 6WIND S.A.

-include $(FP_DOT_CONFIG)

SUBDIR-$(CONFIG_MCORE_FPU_RPC) += fpu-rpc
SUBDIR-$(CONFIG_MCORE_VNB) += vnb/tools
SUBDIR-$(CONFIG_MCORE_FPM_NFCT) += nat/fpm-nfct
SUBDIR-$(CONFIG_MCORE_TRAFFIC_GEN) += traffic-gen/tools

SUBDIR:=$(SUBDIR-y)

-include $(FPNSDK_DIR)/mk/subdir.mk

$(SUBDIR-):
