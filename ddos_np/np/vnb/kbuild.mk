# Copyright 2014 6WIND S.A.

# This helper sets variables for kernel module compilation from inside VNB or in DKMS

S?=$(CURDIR)
src-include-dir?=$(TOP_S)/sys

KERNEL_BUILDROOT?=/lib/modules/`uname -r`/build/
prefix?=/usr/local
includedir=$(prefix)/include
VNB_CONFIG_H ?= $(prefix)/vnb/config/vnb_config.h

include $(dir $(VNB_CONFIG_H))/vnb.config

EXTRA_CFLAGS += -Werror -D__LinuxKernelVNB__
EXTRA_CFLAGS += -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wno-error=sign-compare
EXTRA_CFLAGS += -Wno-error=type-limits
EXTRA_CFLAGS += -Wno-error=override-init
EXTRA_CFLAGS += -Wno-error=old-style-declaration
EXTRA_CFLAGS += -I$(S)
EXTRA_CFLAGS += -I$(src-include-dir)
EXTRA_CFLAGS += -I$(dir $(VNB_CONFIG_H))
ifeq ($(DIST_VNB),)
# used in dkms
EXTRA_CFLAGS += -I$(includedir)
KBUILD_EXTRA_SYMBOLS += $(VNB_BUILDROOT)/sys/netgraph/Module.symvers
else # snapgear compilation
ifeq (${CONFIG_PORTS_KTABLES}, y)
EXTRA_CFLAGS += -DHAVE_KTABLES
EXTRA_CFLAGS += -I${DIST_KTABLES}/module
EXTRA_CFLAGS += -I${ROOTDIR}/ports/ktables/config
endif
KBUILD_EXTRA_SYMBOLS = $(ROOTDIR)/ports/vnb/sys/netgraph/Module.symvers
endif

KBUILD_EXTRA_SYMBOLS += $(VNB_BUILDROOT)/sys/netgraph_linux/Module.symvers
