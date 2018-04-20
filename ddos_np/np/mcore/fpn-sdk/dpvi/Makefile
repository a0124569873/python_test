-include $(FPNSDK_DOT_CONFIG)

# DPDK
ifeq ($(CONFIG_MCORE_ARCH_DPDK),y)
NAME=dpvi-perf
else
# others (tile, vfp)
NAME=dpvi
endif

MODULE        = $(NAME)
MODULE_PATH   = drivers/net
SRCS          = $(S)/$(NAME).c
HEADERS       = $(S)/dpvi.h

MODULE_CFLAGS := -I$(S)
MODULE_CFLAGS += -I$(S)/.. -I$(S)/../$(fpn_arch)
ifeq ($(PKG_DKMS),y)
MODULE_CFLAGS += -I/usr/local/fpn-sdk
MODULE_CFLAGS += -I/usr/local/fpn-sdk/dpvi
endif

MODULE_CFLAGS += -Wall -Werror
MODULE_CFLAGS += -Wextra -Wno-unused-parameter
MODULE_CFLAGS += -Wno-error=type-limits
ifeq ($(CONFIG_MCORE_ARCH_TILEGX),y)
MODULE_CFLAGS += -Wno-sign-compare
else
MODULE_CFLAGS += -Wno-error=sign-compare
endif
MODULE_CFLAGS += -Wno-error=old-style-declaration
ifeq ($(CONFIG_MCORE_ARCH_XLP_DPDK),y)
MODULE_CFLAGS += -Wno-error=missing-field-initializers
endif

MODULE_CFLAGS += -include $(FPNSDK_CONFIG_H)

# Using shared-mem for rings
KBUILD_EXTRA_SYMBOLS=$(FPNSDK_BIN)/shmem/linux/Module.symvers

include $(FPNSDK_DIR)/mk/kmod.mk

ifeq ($(KERNELRELEASE),)
# Export for other userland
ifeq ($(PKG_DKMS),y)
RUNTIME_FILES= $(S)/fpn-dpvi-ring.h $(S)/fpn-dpvi-ring-func.h
else
FILES= $(S)/fpn-dpvi-ring.h
endif

include mk/files.mk
endif
