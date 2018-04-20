include $(FPNSDK_DIR)/fpn-arch.mk
FP_BUILDROOT?=$(INSTALL_DIR)/executive

# minimal flags ito get config and generic common/ path
MCORE_CONFIG_CFLAGS := -include $(FP_BUILDROOT)/config/fp_config.h
-include $(FP_BUILDROOT)/config/fp.config
MCORE_CONFIG_CFLAGS += -I$(DIST_FP)/common

MCORE_COMMON_CFLAGS += -std=gnu99
MCORE_COMMON_CFLAGS += $(MCORE_CONFIG_CFLAGS)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fastpath/include
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fptun 

MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/ip/common

ifeq ($(CONFIG_MCORE_BUILTIN_VSWITCH),y)
ifeq ($(KERNELRELEASE),)
-include $(DIST_FP_VSWITCH)/fp/fpn-vswitch.mk
endif
endif

ifeq ($(CONFIG_MCORE_IPSEC),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/ipsec/common
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/ipsec/common/filter
ifeq ($(CONFIG_MCORE_IPSEC_SVTI),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/svti/common
endif
ifeq ($(CONFIG_MCORE_IPSEC_IPV6),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/ipsec6/common
endif
ifeq ($(CONFIG_MCORE_IPSEC_TRIE),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/ipsec/common/filter/classif
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/ipsec/common/filter/egt-pc
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/ipsec/common/filter/rfc 
MCORE_COMMON_CFLAGS += -DRFC_PHASE=4
endif
endif

ifeq ($(CONFIG_MCORE_VXLAN),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/vxlan/common
endif

ifeq ($(CONFIG_MCORE_BRIDGE),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/bridge/common
endif

ifeq ($(CONFIG_MCORE_LAG),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/lag/common
endif

ifeq ($(CONFIG_MCORE_GRE),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/gre/common
endif

ifeq ($(CONFIG_MCORE_MACVLAN),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/macvlan/common
endif

MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/veda_ddos/common

ifeq ($(CONFIG_MCORE_NETFILTER),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/filter/common
ifeq ($(CONFIG_MCORE_NETFILTER_NAT),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/nat/common
endif
ifeq ($(CONFIG_MCORE_NETFILTER_IPV6),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/filter6/common
endif
endif

ifeq ($(CONFIG_MCORE_MULTICAST4),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/mcast/common
endif
ifeq ($(CONFIG_MCORE_MULTICAST6),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/mcast6/common
endif

ifneq ($(CONFIG_MCORE_XIN4)$(CONFIG_MCORE_XIN6),)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/tunnel/common
endif

ifeq ($(CONFIG_MCORE_TAP),y)
MCORE_COMMON_CFLAGS += -I$(DIST_FP)/fp-modules/tap/common
endif

ifeq ($(CONFIG_MCORE_KTABLES),y)
MCORE_COMMON_CFLAGS += -I${ROOTDIR}/ports/ktables/config
endif
