-include $(FPNSDK_DOT_CONFIG)

include $(DIST_FP)/mcore_common.mk

MODULE        = rfpvi
MODULE_PATH   = drivers/net
SRCS          = $(DIST_FP)/distrib-tools/rfpvi/rfpvi.c

MODULE_CFLAGS += $(FPNSDK_CFLAGS)
MODULE_CFLAGS += $(MCORE_COMMON_CFLAGS)
MODULE_CFLAGS += -Wall -Werror
MODULE_CFLAGS += -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-missing-field-initializers
MODULE_CFLAGS += -Wno-error=type-limits
MODULE_CFLAGS += -Wno-error=old-style-declaration
MODULE_CFLAGS += -std=gnu89

DIST_IFUID?=$(IFUID_DIR)
MODULE_CFLAGS += -I$(DIST_IFUID)/ifuid-module/

# Using symbol netdev2ifuid
IFUID_BINDIR?=$(IFUID_DIR)
ifeq ($(wildcard $(IFUID_BINDIR)/ifuid-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers),)
KBUILD_EXTRA_SYMBOLS += $(IFUID_BINDIR)/ifuid-module/Module.symvers
else
KBUILD_EXTRA_SYMBOLS += $(IFUID_BINDIR)/ifuid-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers
endif

include $(FPNSDK_DIR)/mk/kmod.mk
