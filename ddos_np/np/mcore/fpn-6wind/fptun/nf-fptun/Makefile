-include $(FPNSDK_DOT_CONFIG)

include $(DIST_FP)/mcore_common.mk

MODULE        = nf-fptun
MODULE_PATH   = net/netfilter/
SRCS          = $(DIST_FP)/fptun/nf-fptun/xtable_fptun.c
SRCS         += $(DIST_FP)/fptun/nf-fptun/xt_IPSECOUT.c
HEADERS       = $(DIST_FP)/fptun/nf-fptun/xt_IPSECOUT.h

S ?= $(CURDIR)
MODULE_CFLAGS += -I$(S)
MODULE_CFLAGS += $(MCORE_CONFIG_CFLAGS)
MODULE_CFLAGS += -I$(DIST_FP)/fptun

MODULE_CFLAGS += -Wall -Werror
MODULE_CFLAGS += -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-missing-field-initializers
MODULE_CFLAGS += -Wno-error=type-limits
MODULE_CFLAGS += -Wno-error=old-style-declaration
MODULE_CFLAGS += -std=gnu89
# Initialization of xtable_fptun.c:initial_table[6] (kernel < 2.6.34) requires
# this option (in fact, only octeon toolchains sdk-2.3 complains)
MODULE_CFLAGS += -Wno-override-init

DIST_IFUID?=$(IFUID_DIR)
MODULE_CFLAGS += -I$(DIST_IFUID)/ifuid-module/

ifeq ($(USE_VRF_NETNS),y)
DIST_VRF?=$(VRF_DIR)
MODULE_CFLAGS += -I$(DIST_VRF)/vrf-module/ -DUSE_VRF_NETNS
endif

ifeq ($(CONFIG_MCORE_RFPVI),y)
# Using rfpvi_get_blade_info
KBUILD_EXTRA_SYMBOLS+= $(FP_BUILDROOT)/distrib-tools/rfpvi/Module.symvers
endif

# Using symbol netdev2ifuid
IFUID_BINDIR?=$(IFUID_DIR)
ifeq ($(wildcard $(IFUID_BINDIR)/ifuid-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers),)
KBUILD_EXTRA_SYMBOLS += $(IFUID_BINDIR)/ifuid-module/Module.symvers
else
KBUILD_EXTRA_SYMBOLS += $(IFUID_BINDIR)/ifuid-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers
endif

ifeq ($(USE_VRF_NETNS),y)
# Using symbol vrf_lookup_by_net
VRF_BINDIR?=$(VRF_DIR)
ifeq ($(wildcard $(VRF_BINDIR)/vrf-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers),)
KBUILD_EXTRA_SYMBOLS += $(VRF_BINDIR)/vrf-module/Module.symvers
else
KBUILD_EXTRA_SYMBOLS += $(VRF_BINDIR)/vrf-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers
endif
endif

include $(FPNSDK_DIR)/mk/kmod.mk
