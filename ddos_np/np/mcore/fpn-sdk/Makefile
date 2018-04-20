S?=$(CURDIR)
O?=$(CURDIR)

-include $(S)/.pkg-conf
export $(filter PKG_%,$(.VARIABLES))

FPNSDK_DIR?=$(S)
export FPNSDK_DIR

FPNSDK_BIN=$(abspath $O)
export FPNSDK_BIN

include $(S)/mk/verbose.mk

export FPNSDK_DOT_CONFIG=$(O)/config/fpnsdk.config
export FPNSDK_CONFIG_H=$(O)/config/fpnsdk_config.h

MCONFIG_TITLE=fpnsdk
MCONFIG_NAME=$(FPNSDK_DOT_CONFIG)
MCONFIG_HEADER=$(FPNSDK_CONFIG_H)
MCONFIG_PATH=$(S)

# If not set, MCONF_BINDIR default to /usr/local/mconf-tools, unless
# user has specified the source directory.
MCONF_BINDIR?=$(if $(DIST_MCONF_TOOLS),$(DIST_MCONF_TOOLS),/usr/local/mconf-tools)
include $(MCONF_BINDIR)/template.mk

-include $(FPNSDK_DOT_CONFIG)
include $(S)/fpn-arch.mk

export fpn_arch

SUBDIR-y += $(fpn_arch)

SUBDIR-$(CONFIG_MCORE_FPN) += shmem
SUBDIR-y += timer

ifeq ($(CONFIG_MCORE_FPVI_DP),y)
SUBDIR-y += dpvi
dpvi: shmem
endif

SUBDIR-$(CONFIG_MCORE_FPN_CRYPTO_GENERIC) += crypto

SUBDIR-y += mk

MAKEFLAGS+= --include-dir=$(S)

ifeq ($(CONFIG_MCORE_FPN),y)
ADDITIONAL_SUBDIR = apps tools
endif

SUBDIR=$(SUBDIR-y) $(ADDITIONAL_SUBDIR)

ifeq ($(PKG_DKMS),y)
DKMS_NAME := fpn-sdk
PKG_VERSION ?= unknown
export DKMSDIR ?= $(DESTDIR)/usr/src/$(DKMS_NAME)-$(PKG_VERSION)

install install-target: install-config
	$(Q)if find $(DKMSDIR)/*.dkms.conf 1>/dev/null 2>&1; then \
		install -D -m 644 $(S)/Makefile.dkms $(DKMSDIR)/Makefile && \
		printf 'PACKAGE_NAME="$(DKMS_NAME)"\n'\
	'PACKAGE_VERSION="$(PKG_VERSION)"\n'\
	'AUTOINSTALL="yes"\n'\
	'MAKE[0]="make KERNEL_SRC=$${kernel_source_dir} KERNELARCH=$$arch modules"\n'\
	'POST_BUILD="post_build.sh $$dkms_tree/$$PACKAGE_NAME/$$PACKAGE_VERSION/build /usr/local/fpn-sdk/$$kernelver/$$arch"\n'\
	'CLEAN=":"\n' > $(DKMSDIR)/dkms.conf && \
		idx=0 && \
		for i in $$(ls $(DKMSDIR)/*.dkms.conf 2>/dev/null); do \
			sed "s/\[INDEX\]/[$$idx]/g" $$i >> $(DKMSDIR)/dkms.conf || exit 1; \
			idx=$$(( $$idx + 1 )); \
		done && \
		rm -f $(DKMSDIR)/*.dkms.conf $(DKMSDIR)/post_build.sh && \
		cat $(DKMSDIR)/*.post_build.sh >> $(DKMSDIR)/post_build.sh && \
		chmod a+x $(DKMSDIR)/post_build.sh && \
		rm -f $(DKMSDIR)/*.post_build.sh; \
	fi

install install-devel:
else
install install-devel: install-config
endif

include $(S)/mk/subdir.mk

$(SUBDIR): $(MCONFIG_HEADER)

# Try tools and apps when everything else is done
tools apps: $(SUBDIR-y)

ifeq ($(PKG_DKMS),y)
RUNTIME_FILES= $(S)/fpn.h $(S)/fpn-core.h $(S)/fpn-assert.h $(S)/fpn-queue.h $(S)/fpn-port.h $(S)/fpn-eth.h $(S)/fpn-crypto-algo.h
endif
FILES= $(filter-out $(RUNTIME_FILES),$(wildcard $(S)/fpn*.h))

include $(S)/mk/files.mk

prefix = /usr/local/fpn-sdk
$(DESTDIR)/$(prefix)/config/fpnsdk.config: $(FPNSDK_DOT_CONFIG)
	$(P) '  INSTALL-CONFIG  $(notdir $(FPNSDK_DOT_CONFIG))'
	$(Q)install -D $(FPNSDK_DOT_CONFIG) $(@)

$(DESTDIR)/$(prefix)/config/fpnsdk_config.h: $(FPNSDK_CONFIG_H)
	$(P) '  INSTALL-CONFIG  $(notdir $(FPNSDK_CONFIG_H))'
	$(Q)install -D $(FPNSDK_CONFIG_H) $(@)

install-config: $(DESTDIR)/$(prefix)/config/fpnsdk.config $(DESTDIR)/$(prefix)/config/fpnsdk_config.h
