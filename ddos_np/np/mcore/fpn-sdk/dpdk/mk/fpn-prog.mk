# fpn-prog.mk

include $(FPNSDK_DIR)/dpdk/mk/dpdk-init.mk

# Note: RTE will override CFLAGS.

include $(RTE_SDK)/mk/rte.vars.mk

include $(FPNSDK_DIR)/dpdk/mk/dpdk-options.mk

APP = $(OUTPUT)
OBJ_DIR?=obj
DEP_$(APP)+= $(FPNSDK_BIN)/dpdk/libfpnsdk.a
PREFIX_BINDIR?=usr/local/bin/

CFLAGS += $(FPNSDK_CFLAGS)
LDFLAGS+= $(FPNSDK_LDFLAGS)
LDLIBS += $(FPNSDK_LDLIBS)

CFLAGS += -I$(INSTALL_DIR)/executive/include
LDLIBS += -L$(INSTALL_DIR)/executive/lib

# FIXME: remove some warning detection
CFLAGS += -Wno-pointer-arith -Wno-cast-qual

SRCS-y := $(notdir $(SRCS))

# RTE will build APP and *.o in current directory, whatever OBJ_DIR.
# And will install the app into RTE_OUTPUT/app/$OUTPUT
# Let's copy where it is expected: OBJ_DIR/$(OUTPUT)

all: $(OBJ_DIR)/$(OUTPUT)

$(OBJ_DIR)/$(OUTPUT): $(OUTPUT)
	@install -D $< $@

install-target: $(DESTDIR)/$(PREFIX_BINDIR)$(OUTPUT)

$(OUTPUT).strip: $(OUTPUT)
	$(P) '  STRIP $(notdir $<)'
	$(Q)$(STRIP) -o $@ $<

$(DESTDIR)/$(PREFIX_BINDIR)$(OUTPUT): $(call select-dot-strip,$(OUTPUT))
	$(P) '  INSTALL $(notdir $<)'
	$(Q)install -D $< $@

clean: extra_clean

extra_clean:
	$(P) '  CLEAN $(OUTPUT)'
	$(Q)rm -f $(OUTPUT).strip

# rte mk has its own install target, implemented our own
ifneq ($(filter install,$(MAKECMDGOALS)),)

install: install-target

else

# rte.extapp.mk recurses MAKE with Makefile, forcing the user
# to use M=<name of makefile>. Just use rte.app.mk, adding
# missing pieces: VPATH.

VPATH += $(S)

include $(RTE_SDK)/mk/rte.app.mk

# rte.extvars.mk sets RTE_SRCDIR := $(abspath $(S)), and
# rte.app.mk relies on S= relative path:
# SRCDIR := $(abspath $(RTE_SRCDIR)/$(S))
# This is not the case in fpn-sdk, S is absolute path.
SRCDIR:=$(S)

endif

install-devel:;

FORCE:

.PHONY: all clean install install-target install-devel
