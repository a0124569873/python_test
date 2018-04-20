DKMS_MOD_DIR=$(patsubst $(DIST_FP)/%,%,$(patsubst $(FPNSDK_DIR)/%,%,$(S)))

install install-target: $(DKMSDIR)/$(MODULE).dkms.conf \
 $(DKMSDIR)/$(MODULE).post_build.sh \
 $(DKMSDIR)/$(DKMS_MOD_DIR)/Makefile \
 $(addprefix $(DKMSDIR)/$(DKMS_MOD_DIR)/,$(notdir $(SRCS) $(HEADERS)))

$(DKMSDIR)/$(DKMS_MOD_DIR)/Makefile: $(S)/Makefile
	$(Q)install -D -m 644 $< $@

$(DKMSDIR)/$(MODULE).dkms.conf:
	$(Q)mkdir -p $(@D)
	$(Q)printf 'BUILT_MODULE_NAME[INDEX]="$(MODULE)"\n'\
	'BUILT_MODULE_LOCATION[INDEX]="$(DKMS_MOD_DIR)"\n'\
	'DEST_MODULE_LOCATION[INDEX]="/updates/dkms"\n' > $@

$(DKMSDIR)/$(MODULE).post_build.sh:
	$(Q)mkdir -p $(@D)
	$(Q)printf 'install -D $$1/$(DKMS_MOD_DIR)/Module.symvers $$2/$(DKMS_MOD_DIR)/Module.symvers\n' > $@

define dkms_install
$$(DKMSDIR)/$$(DKMS_MOD_DIR)/$$(notdir $(1)): $(1)
	$$(Q)install -D -m 644 $$< $$@
endef
$(foreach src,$(SRCS) $(HEADERS),$(eval $(call dkms_install,$(src))))
