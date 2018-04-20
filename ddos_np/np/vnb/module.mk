# Copyright 2014 6WIND S.A.

# This helper is used in package compilation:
#   - Copy HDRS files into $(DESTDIR)/$(includedir)/$(HDRS_SUBDIR)/
#   - Create adequate symlinks for SRCS files
#   - Implement "module" and "install-target" targets to compile modules
#
# Must define:
# HDRS: headers files (prefixed with the full path)
# SRCS: source files (prefixed with the full path)
#
# KERNEL_BUILDROOT: root directory for the kernel module compilation
#   (e.g.: /lib/modules/`uname -r`/build/
#
# Alternately, you can define HDRS_SUBDIR for installing netgraph sub-libraries (e.g.: nglib) headers

-include $(S)/../.pkg-conf
export $(filter PKG_%,$(.VARIABLES))

# module installation directory: /lib/modules/`uname -r`/$(MODULE_PATH)
MODULE_PATH ?= net

ifeq ($(KERNELRELEASE),)

all: module

# Always update sym links to handle changes of $S
# But don't make sym link if the file is present (building in source tree case)
linksrc:
	$(Q) $(foreach FILE,$(SRCS), if [ ! -f $(notdir $(FILE)) ]; then ln -nfs $(FILE) . ; fi ;)
	$(Q) [ -f Makefile ] || ln -fs $(S)/Makefile Makefile

module: linksrc
	$(Q)$(MAKE) -C $(KERNEL_BUILDROOT) M=$(CURDIR) O=$(KERNEL_BUILDROOT)

install install-target:
	$(Q)$(MAKE) -C $(KERNEL_BUILDROOT) M=$(CURDIR) O=$(KERNEL_BUILDROOT) \
		INSTALL_MOD_DIR=$(MODULE_PATH) INSTALL_MOD_PATH=$(DESTDIR) \
		DEPMOD=/bin/true modules_install

# Do a make clean and remove links
clean:
	$(Q) [ ! -e Makefile ] || $(MAKE) -C $(KERNEL_BUILDROOT) M=$(CURDIR) O=$(KERNEL_BUILDROOT) clean
	$(Q) $(foreach FILE,$(SRCS), if [ -h $(notdir $(FILE)) ]; then rm -f $(notdir $(FILE)) ; fi ;)
	$(Q) [ ! -h  Makefile ] || rm -f Makefile

.PHONY: install-headers install-devel

install-devel:;

# install all headers into $(DESTDIR)/$(includedir)/
HDRS_SUBDIR ?= netgraph
install-headers:
	@mkdir -p $(DESTDIR)/$(includedir)/$(HDRS_SUBDIR)
	$(Q) $(foreach file,$(HDRS), install -D -m 644 $(file) \
		$(DESTDIR)/$(includedir)/$(HDRS_SUBDIR)/$(notdir $(file)) || exit 1;)

ifeq ($(PKG_DKMS),y)
include $(TOP_S)/dkms.mk
else
install install-devel: install-headers
endif

endif
