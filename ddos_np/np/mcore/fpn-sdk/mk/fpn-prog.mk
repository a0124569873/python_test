include $(FPNSDK_DIR)/mk/verbose.mk

include $(FPNSDK_DIR)/fpn-arch.mk

FPNSDK_CFLAGS+= -D__FastPath__
FPNSDK_CFLAGS+= $(EXTRA_CFLAGS)
S?=$(CURDIR)

# Helper: $(call select-dot-strip,mybin) returns
# mybin or mybin.strip if NOSTRIP=yes.
define select-dot-strip
$(if $(filter yes,$(NOSTRIP)),$(1),$(addsuffix .strip,$(1)))
endef

ifneq ($(fpn_arch),)
-include $(FPNSDK_DIR)/$(fpn_arch)/mk/fpn-prog.mk

else

# Default rules
clean install install-target install-devel:;

endif
