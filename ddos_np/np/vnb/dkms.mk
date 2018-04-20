# Copyright 2014 6WIND S.A.

# Given vnb modules source files in $(SRCS) and a $(MODULE_SRC_DIR):
#   - Copy sources into $(DKMSDIR)/$(MODULE_SRC_DIR) to be available during dkms compilation
#   - Create a <vnb_module>.dkms.conf file, to be processed by vnb/Makefile
#       i.e. it will concatenate and remap indexes in a global dkms.conf file
#
# Alternately, override VNB_MODS to specify vnb_modules based on several source files

# turn "ng_<module>.c" into the built module name "vnb_<module>"
VNB_MODS ?= $(patsubst ng_%.c,vnb_%,$(notdir $(SRCS)))
# we expect a "vnb<module>.dkms.conf" file for each module
DKMS_CONFS := $(patsubst %,$(DKMSDIR)/%.dkms.conf,$(VNB_MODS))

# default $(DKMSDIR)/ subdir to install source files for submodules
# (i.e.: etherbridge, vlan, etc.)
MODULE_SRC_DIR ?= $(notdir $(S))

install install-target: install-dkms install-headers

install-dkms: $(DKMS_CONFS) $(S)/Makefile
	@mkdir -p $(DKMSDIR)/$(MODULE_SRC_DIR)
	$(Q) $(foreach file,$(SRCS), install -D -m 644 $(file) \
		$(DKMSDIR)/$(MODULE_SRC_DIR)/$(notdir $(file)) || exit 1;)
	$(Q) install -D -m 644 $(S)/Makefile $(DKMSDIR)/$(MODULE_SRC_DIR)/Makefile

$(DKMSDIR)/%.dkms.conf:
	$(Q) printf 'BUILT_MODULE_NAME[INDEX]="$*"\n'\
	'BUILT_MODULE_LOCATION[INDEX]="$(MODULE_SRC_DIR)"\n'\
	'DEST_MODULE_LOCATION[INDEX]="/updates/dkms"\n' > $@

.PHONY: install-dkms
