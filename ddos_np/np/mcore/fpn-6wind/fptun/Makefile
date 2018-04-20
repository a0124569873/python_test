-include $(FPNSDK_DOT_CONFIG)

include $(DIST_FP)/mcore_common.mk

MODULE        = fptun
MODULE_PATH   = drivers/net
SRCS          = $(DIST_FP)/fptun/fptun.c
HEADERS       = $(DIST_FP)/fptun/fptun.h

S ?= $(CURDIR)
MODULE_CFLAGS += -I$(S)

MODULE_CFLAGS += $(MCORE_CONFIG_CFLAGS)
MODULE_CFLAGS += -Wall -Werror
MODULE_CFLAGS += -Wno-unused-parameter -Wno-sign-compare -Wno-missing-field-initializers
MODULE_CFLAGS += -Wno-error=type-limits
MODULE_CFLAGS += -Wno-error=old-style-declaration
MODULE_CFLAGS += -std=gnu89

DIST_IFUID?=$(IFUID_DIR)
MODULE_CFLAGS += -I$(DIST_IFUID)/ifuid-module/

# Using symbol dev_get_by_ifuid
IFUID_BINDIR?=$(IFUID_DIR)
ifeq ($(wildcard $(IFUID_BINDIR)/ifuid-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers),)
KBUILD_EXTRA_SYMBOLS += $(IFUID_BINDIR)/ifuid-module/Module.symvers
else
KBUILD_EXTRA_SYMBOLS += $(IFUID_BINDIR)/ifuid-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers
endif

ifeq ($(USE_VRF_NETNS),y)
DIST_VRF?=$(VRF_DIR)
MODULE_CFLAGS += -I$(DIST_VRF)/vrf-module/ -DUSE_VRF_NETNS
# Using symbol vrf_lookup_by_vrfid
VRF_BINDIR?=$(VRF_DIR)
ifeq ($(wildcard $(VRF_BINDIR)/vrf-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers),)
KBUILD_EXTRA_SYMBOLS += $(VRF_BINDIR)/vrf-module/Module.symvers
else
KBUILD_EXTRA_SYMBOLS += $(VRF_BINDIR)/vrf-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers
endif
endif

include $(FPNSDK_DIR)/mk/kmod.mk
