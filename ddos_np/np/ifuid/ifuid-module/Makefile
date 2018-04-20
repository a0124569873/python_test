# Copyright 2013 6WIND S.A.

export USE_VRF_NETNS ?= y

include $(S)/Kbuild
-include $(S)/../.pkg-conf

prefix = /usr/local
moduledir = $(prefix)/modules
ifuid-prefix = $(moduledir)/ifuid/ifuid-module

KERNEL_BUILDROOT?=/lib/modules/`uname -r`/build

all: module

# Link the file in SNAPGEAR if the source is in another component
depsrc:
	@$(foreach FILE,$(SRCS), if [ ! -f $(FILE) ]; then ln -nfs $(S)/$(FILE) . ; fi ;)
	@[ -f Makefile ] || ln -fs $(S)/Makefile Makefile

module: depsrc
	$(MAKE) -C $(KERNEL_BUILDROOT) M=$(CURDIR) O=$(KERNEL_BUILDROOT)

# Do a make clean and remove links
clean:
	[ ! -f Makefile ] || $(MAKE) -C $(KERNEL_BUILDROOT) M=$(CURDIR) O=$(KERNEL_BUILDROOT) clean
	@$(foreach FILE,$(SRCS), if [ -h $(FILE) ]; then rm -f $(FILE) ; fi ;)
	@[ ! -h Makefile ] || rm -f Makefile

install install-target:
	$(MAKE) -C $(KERNEL_BUILDROOT) M=$(CURDIR) O=$(KERNEL_BUILDROOT) \
		INSTALL_MOD_DIR=$(MODULE_PATH) INSTALL_MOD_PATH=$(DESTDIR) DEPMOD=/bin/true modules_install

install install-devel: $(DESTDIR)/$(ifuid-prefix)/Module.symvers

ifeq ($(PKG_DKMS),y)

DKMS_NAME := ifuid
PKG_VERSION ?= unknown
DKMSDIR ?= $(DESTDIR)/usr/src/$(DKMS_NAME)-$(PKG_VERSION)

install install-target: $(DESTDIR)/$(ifuid-prefix)/ifuid.h $(DKMSDIR)/dkms.conf \
 $(DKMSDIR)/post_build.sh \
 $(addprefix $(DKMSDIR)/,$(SRCS)) $(DKMSDIR)/Kbuild

define dkms_install
$$(DKMSDIR)/$(1): $$(S)/$(1)
	$$(Q)install -D -m 644 $$< $$@
endef
$(foreach file,$(SRCS) Kbuild,$(eval $(call dkms_install,$(file))))

$(DKMSDIR)/dkms.conf:
	$(Q)mkdir -p $(@D)
	$(Q)printf 'PACKAGE_NAME="$(DKMS_NAME)"\n'\
	'PACKAGE_VERSION="$(PKG_VERSION)"\n'\
	'AUTOINSTALL="yes"\n'\
	'MAKE[0]="make -C $${kernel_source_dir}'\
	' SUBDIRS=$${dkms_tree}/$${PACKAGE_NAME}/$${PACKAGE_VERSION}/build'\
	' S=$${dkms_tree}/$${PACKAGE_NAME}/$${PACKAGE_VERSION}/build'\
	' KERNELARCH=$$arch'\
	' USE_VRF_NETNS=$(USE_VRF_NETNS)'\
	' modules"\n'\
	'CLEAN=":"\n'\
	'POST_BUILD="post_build.sh $$dkms_tree/$$PACKAGE_NAME/$$PACKAGE_VERSION/build $(ifuid-prefix)/$$kernelver/$$arch"\n'\
	'BUILT_MODULE_NAME[0]="$(MODULE)"\n'\
	'DEST_MODULE_LOCATION[0]="/updates/dkms"\n' > $@
ifeq ($(USE_VRF_NETNS),y)
	$(Q)printf 'BUILD_DEPENDS[0]="vrf"\n' >> $@
endif

$(DKMSDIR)/post_build.sh:
	$(Q)mkdir -p $(@D)
	$(Q)printf 'install -D $$1/Module.symvers $$2/Module.symvers\n' > $@
	$(Q)chmod a+x $@

else
install install-devel: $(DESTDIR)/$(ifuid-prefix)/ifuid.h
endif

$(DESTDIR)/$(ifuid-prefix)/Module.symvers: $(O)/Module.symvers
	@install -D $< $@

$(DESTDIR)/$(ifuid-prefix)/ifuid.h: $(S)/ifuid.h
	@install -D $< $@
