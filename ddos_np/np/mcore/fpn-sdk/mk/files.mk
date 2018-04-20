include $(FPNSDK_DIR)/mk/verbose.mk

prefix = /usr/local
filedir = $(prefix)/fpn-sdk/$(PREFIXDIR)

INSTALL_DEVEL_FILES=$(subst $(S),$(DESTDIR)$(filedir), $(FILES))
INSTALL_RUNTIME_FILES=$(subst $(S),$(DESTDIR)$(filedir), $(RUNTIME_FILES))

$(DESTDIR)$(filedir)%: $(S)/%
	$(P) '  INSTALL-FILE  $(notdir $<)'
	$(Q)install -D $< $@

install-devel install: $(INSTALL_DEVEL_FILES)
install-target install: $(INSTALL_RUNTIME_FILES)
