all clean install-devel:;

scripts:=
scripts+=libcmdline.sh
scripts+=mcore_config.sh
scripts+=mcore_start_1cp1fp.sh
scripts+=mcore_start_1cpxfp-ha.sh
scripts+=mcore_start_1cpxfp.sh
scripts+=start_cm.sh
scripts+=start_fpm.sh
scripts+=start_fps.sh
scripts+=start_hitflags.sh
scripts+=start_sds_daemon.sh
scripts+=sds-ifd.coloc.template
scripts+=sds-ifd.cp.template
scripts+=sds-ifd.fp.template
scripts+=hao-ifd.coloc.template
scripts+=hao-ifd.cp.template
scripts+=wait_fpshared.sh
scripts+=mcore-nf-gen-rules.sh

SCRIPT_FILES:=$(addprefix $(S)/,$(scripts))

include $(FPNSDK_DIR)/mk/scripts.mk

# Special case for mcore_start.sh
# VFP: Rename to mcore_start_vfp.sh to avoid auto launch

# Read CONFIG_MCORE_FPE_VFP
include $(FPNSDK_DIR)/fpn-arch.mk

dest_mcore_start:=$(if $(CONFIG_MCORE_FPE_VFP),mcore_start_vfp.sh,mcore_start.sh)

install-target: $(DESTDIR)/$(PREFIX_ETCDIR)$(SUBPREFIX_ETCDIR)$(dest_mcore_start)

$(DESTDIR)/$(PREFIX_ETCDIR)$(SUBPREFIX_ETCDIR)$(dest_mcore_start): $(S)/mcore_start.sh
	$(P) '  INSTALL-SCRIPT  $(notdir $<)'
	$(Q)install -D $< $@


# Special case rc.cpu-affinity, expected in /etc
install-target: $(DESTDIR)/$(PREFIX_ETCDIR)rc.cpu-affinity

$(DESTDIR)/$(PREFIX_ETCDIR)rc.cpu-affinity: $(S)/rc.cpu-affinity
	$(P) '  INSTALL-SCRIPT  $(notdir $<)'
	$(Q)install -D $< $@

install:;
