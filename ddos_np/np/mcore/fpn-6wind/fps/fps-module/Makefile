-include $(FPNSDK_DOT_CONFIG)

include $(DIST_FP)/mcore_common.mk

MODULE        = fps
MODULE_PATH   = drivers/net
SRCS          = $(DIST_FP)/fps/fps-module/fps-module.c
HEADERS       = $(DIST_FP)/fps/fps-module/fps-macro.h

MODULE_CFLAGS += $(MCORE_CONFIG_CFLAGS)
MODULE_CFLAGS += -Wall -Werror
MODULE_CFLAGS += -Wextra -Wno-unused-parameter -Wno-sign-compare
MODULE_CFLAGS += -Wno-error=type-limits
MODULE_CFLAGS += -Wno-error=old-style-declaration
MODULE_CFLAGS += -Wno-missing-field-initializers
MODULE_CFLAGS += -std=gnu89
S ?= $(CURDIR)
MODULE_CFLAGS += -I$(S)

ifeq ($(USE_VRF_NETNS),y)
MODULE_CFLAGS += -DUSE_VRF_NETNS
endif

DIST_IFUID?=$(IFUID_DIR)
MODULE_CFLAGS += -I$(DIST_IFUID)/ifuid-module/

# Using symbol fptun_rfps_msg_hdlr_p
ifeq ($(wildcard $(DKMS_BUILDROOT)/fptun/Module.symvers),)
KBUILD_EXTRA_SYMBOLS=$(FP_BUILDROOT)/fptun/Module.symvers
else
KBUILD_EXTRA_SYMBOLS=$(DKMS_BUILDROOT)/fptun/Module.symvers
endif
# Using symbol netdev2ifuid
IFUID_BINDIR?=$(IFUID_DIR)
ifeq ($(wildcard $(IFUID_BINDIR)/ifuid-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers),)
KBUILD_EXTRA_SYMBOLS += $(IFUID_BINDIR)/ifuid-module/Module.symvers
else
KBUILD_EXTRA_SYMBOLS += $(IFUID_BINDIR)/ifuid-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers
endif

include $(FPNSDK_DIR)/mk/kmod.mk
