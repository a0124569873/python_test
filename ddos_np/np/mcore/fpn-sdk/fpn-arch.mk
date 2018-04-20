# FPNSDK_BIN set if building inside fpn-sdk
# FPNSDK_DIR set by external app
FPNSDK_BIN?=$(FPNSDK_DIR)
FPNSDK_DOT_CONFIG?=$(FPNSDK_BIN)/config/fpnsdk.config
FPNSDK_CONFIG_H?=$(FPNSDK_BIN)/config/fpnsdk_config.h

-include $(FPNSDK_DOT_CONFIG)

ifeq ($(CONFIG_MCORE_FPN),y)

ifeq ($(CONFIG_MCORE_FPE_VFP),y)
fpn_arch=emulator
endif
ifeq ($(CONFIG_MCORE_ARCH_DPDK),y)
fpn_arch=dpdk
endif
ifeq ($(CONFIG_MCORE_ARCH_XLP),y)
fpn_arch=xlp
endif
ifeq ($(CONFIG_MCORE_ARCH_TILEGX),y)
fpn_arch=tilegx
endif
ifeq ($(CONFIG_MCORE_ARCH_OCTEON),y)
fpn_arch=octeon
endif
ifeq ($(CONFIG_MCORE_ARCH_NPS),y)
fpn_arch=nps
endif

FPNSDK_DIR?=$(FPNSDK_BIN)
FPNSDK_CFLAGS+= -include $(FPNSDK_CONFIG_H)
FPNSDK_CFLAGS+= -I$(FPNSDK_DIR) -I$(FPNSDK_DIR)/$(fpn_arch)
FPNSDK_CFLAGS+= -I$(FPNSDK_DIR)/shmem -I$(FPNSDK_DIR)/$(fpn_arch)/shmem
FPNSDK_LDFLAGS+= -L$(FPNSDK_BIN)/shmem/lib -L$(FPNSDK_BIN)/$(fpn_arch)/shmem/lib
endif
