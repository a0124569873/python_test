# Copyright 2013 6WIND S.A.

-include $(FPNSDK_DIR)/fpn-arch.mk
-include $(FP_DOT_CONFIG)

SUBDIR-$(CONFIG_MCORE_FASTPATH) += arch/$(fpn_arch)

SUBDIR:=$(SUBDIR-y)

-include $(FPNSDK_DIR)/mk/subdir.mk

scripts := scripts/status.sh scripts/status-sys.sh scripts/status-cp.sh \
           scripts/status-fp.sh scripts/cpuinfo.py \
           scripts/fp-conf-tools/fp-conf-tool
libs := scripts/fp-toolbox.sh

BIN_SRC_FILES:=$(addprefix $(S)/, $(scripts))
ETC_SRC_FILES:=
LIB_SRC_FILES:=$(addprefix $(S)/, $(libs))

include $(DIST_FP)/mk/install_startup_files.mk
