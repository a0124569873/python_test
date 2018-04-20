# Copyright 2013 6WIND S.A.

include $(FPNSDK_DIR)/fpn-arch.mk
-include $(FP_DOT_CONFIG)

prefix ?= /usr/local/fp
filedir ?= $(prefix)/fp-plugins

SUBDIR-y =
ifeq ($(CONFIG_MCORE_FPN_HOOK),y)
SUBDIR-$(CONFIG_MCORE_INTERCORE) += example-fp_if_output
SUBDIR-$(CONFIG_MCORE_INTERCORE) += example-fp_ether_input
SUBDIR-$(CONFIG_MCORE_INTERCORE) += pipeline-pppoe
SUBDIR-$(CONFIG_MCORE_INTERCORE) += pipeline-rr
ifeq ($(CONFIG_MCORE_ARCH_DPDK),y)
SUBDIR-$(CONFIG_MCORE_SW_SCHED) += example-egress_qos
endif
endif
SUBDIR-$(CONFIG_MCORE_SOCKET) += so-apps
SUBDIR:=$(SUBDIR-y)

include $(FPNSDK_DIR)/mk/subdir.mk

DEVFILES := $(wildcard $(S)/common/mk/*.mk $(S)/common/include/*.h)
ifneq ($(fpn_arch),)
DEVFILES += $(wildcard $(S)/common/$(fpn_arch)/*.mk)
endif
DST_DEVFILES = $(patsubst $(S)/%,$(DESTDIR)$(filedir)/%,$(DEVFILES))

install install-devel: $(DST_DEVFILES)

$(DESTDIR)$(filedir)/%: $(S)/%
	$(Q)install -D $< $@
