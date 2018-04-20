S?=$(CURDIR)
O?=$(CURDIR)

-include $(S)/.pkg-conf
export $(filter PKG_%,$(.VARIABLES))

export VNB_DOT_CONFIG=$(O)/config/vnb.config
export VNB_CONFIG_H=$(O)/config/vnb_config.h
export VNB_BUILDROOT=$(CURDIR)

KCOMPAT_DIR?=/usr/local/modules/kcompat
VRF_DIR?=/usr/local/modules/vrf
export KCOMPAT_DIR VRF_DIR

MCONFIG_TITLE=vnb
MCONFIG_NAME=$(VNB_DOT_CONFIG)
MCONFIG_HEADER=$(VNB_CONFIG_H)
MCONFIG_PATH=$(S)

# If not set, MCONF_BINDIR default to /usr/local/mconf-tools, unless
# user has specified the source directory.
MCONF_BINDIR?=$(if $(DIST_MCONF_TOOLS),$(DIST_MCONF_TOOLS),/usr/local/mconf-tools)
include $(MCONF_BINDIR)/template.mk

# Create vnb.config only it doesn't exist and if target is not defconfig to avoid infinite recursion
ifneq ($(filter defconfig,$(MAKECMDGOALS)),defconfig)
include $(VNB_DOT_CONFIG)

$(VNB_DOT_CONFIG):
	$(Q) $(MAKE) S=$(S) O=$(O) -f $(S)/Makefile -C $(O) MCONFIG_DEFAULT= MCONF_BINDIR=$(MCONF_BINDIR) defconfig
endif
SUBDIR-y :=
SUBDIR-$(CONFIG_VNB_NODE_ETHERBRIDGE) += etherbridge
SUBDIR-$(CONFIG_VNB_NODE_BRIDGE) += etherbridge
SUBDIR-$(CONFIG_VNB_NODE_ETF) += etherbridge
SUBDIR-$(CONFIG_VNB_NODE_GRE) += gre
SUBDIR-$(CONFIG_VNB_NODE_ETHGRP) += lag
SUBDIR-$(CONFIG_VNB_NODE_MPLS) += mpls
SUBDIR-$(CONFIG_VNB_NODE_VLAN) += vlan
SUBDIR-$(CONFIG_VNB_NODE_PPP) += ppp
SUBDIR-$(CONFIG_VNB_NODE_PPPOE) += pppoe
SUBDIR-$(CONFIG_VNB_NODE_L2TP) += l2tp
SUBDIR-$(CONFIG_VNB_NODE_GTPU) += gtpu gtpu/gtpuctl
SUBDIR-y := $(sort $(SUBDIR-y))

SUBDIR-y += scripts

SUBDIR=tools/libnetgraph tools/ngctl tools/nghook sys/netgraph sys/netgraph_linux $(SUBDIR-y)

# aka subdir.mk

MAKEFLAGS += --no-print-directory

S?=$(CURDIR)
O?=$(CURDIR)

# TOP_S keeps track of the top vnb source directory
export TOP_S=$(S)
export TOP_O=$(O)

PREFIXDIR?=

.PHONY: subdirs $(SUBDIR) $(SUBDIR-y) install install-target install-devel config

all clean install install-target install-devel subdirs: $(SUBDIR)

$(SUBDIR): $(MCONFIG_HEADER)
	$(Q)[ ! -d $(S)/$@ ] || \
		(mkdir -p $(O)/$@ && $(MAKE) -C $(O)/$@ \
		-f $(S)/$@/Makefile \
		O=$(O)/$@ \
		PREFIXDIR=$(PREFIXDIR)$@/ \
		M= \
		S=$(S)/$@ $(filter-out subdirs $(SUBDIR),$(MAKECMDGOALS)))

tools/ngctl: tools/libnetgraph
tools/nghook: tools/libnetgraph

sys/netgraph: sys/netgraph_linux

# makes sure to build basic VNB nodes (sys/netgraph) before any other submodule
# that requires sys/netgraph/Module.symvers is created
# this way, when sys/netgraph has been taken care of, submodules can be built in parallel
$(SUBDIR-y): sys/netgraph

prefix=/usr/local

$(DESTDIR)/$(prefix)/vnb/config/vnb_config.h: $(VNB_CONFIG_H)
	$(P) '  INSTALL VNB config'
	$(Q)install -D $< $@

$(DESTDIR)/$(prefix)/vnb/config/vnb.config: $(VNB_DOT_CONFIG)
	$(P) '  INSTALL VNB config'
	$(Q)install -D $< $@

ifeq ($(PKG_DKMS),y)
DKMS_NAME := vnb
PKG_VERSION ?= unknown
export DKMSDIR ?= $(DESTDIR)/usr/src/$(DKMS_NAME)-$(PKG_VERSION)

export USE_VRF_NETNS ?= y

install install-target: $(DKMSDIR)/Makefile \
 $(DESTDIR)/$(prefix)/vnb/config/vnb_config.h \
 $(DESTDIR)/$(prefix)/vnb/config/vnb.config \
 $(DKMSDIR)/kbuild.mk
	$(Q)mkdir -p $(DKMSDIR)
	$(Q)printf 'PACKAGE_NAME="$(DKMS_NAME)"\n'\
	'PACKAGE_VERSION="$(PKG_VERSION)"\n'\
	'AUTOINSTALL="yes"\n'\
	'BUILD_DEPENDS[0]="kcompat"\n'\
	'MAKE[0]="make KERNEL_SRC=$${kernel_source_dir}'\
	' KERNELARCH=$$arch'\
	' USE_VRF_NETNS=$(USE_VRF_NETNS)'\
	' modules"\n'\
	'CLEAN=":"\n' > $(DKMSDIR)/dkms.conf
ifeq ($(USE_VRF_NETNS),y)
	$(Q)printf 'BUILD_DEPENDS[1]="vrf"\n' >> $(DKMSDIR)/dkms.conf
endif
	$(Q)idx=0; for i in `ls $(DKMSDIR)/*.dkms.conf 2>/dev/null`; do \
	  sed "s/\[INDEX\]/[$$idx]/g" $$i >> $(DKMSDIR)/dkms.conf || exit 1; \
	  idx=`echo $$idx+1|bc`; \
	done
	$(Q)rm -f $(DKMSDIR)/*.dkms.conf

$(DKMSDIR)/kbuild.mk: $(S)/kbuild.mk
	$(Q)install -D -m 644 $< $@

$(DKMSDIR)/Makefile: $(S)/Makefile.dkms
	$(Q)install -D -m 644 $< $@
else
install install-devel: $(DESTDIR)/$(prefix)/vnb/config/vnb_config.h \
	                   $(DESTDIR)/$(prefix)/vnb/config/vnb.config
endif
