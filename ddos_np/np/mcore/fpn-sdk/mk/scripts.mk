# To install scripts into et/scripts

include $(FPNSDK_DIR)/mk/verbose.mk

PREFIX_ETCDIR?=etc/
SUBPREFIX_ETCDIR?=scripts/

SCRIPT_INSTALL_FILES=$(subst $(S)/, $(DESTDIR)/$(PREFIX_ETCDIR)$(SUBPREFIX_ETCDIR), $(SCRIPT_FILES))

$(DESTDIR)/$(PREFIX_ETCDIR)$(SUBPREFIX_ETCDIR)%: $(S)/%
	$(P) '  INSTALL-SCRIPT  $(notdir $<)'
	$(Q)install -m 755 -D $< $@

install-target: $(SCRIPT_INSTALL_FILES)
