# Copyright 2013 6WIND S.A.

# libfpu-crypto.so
#
LIB := libfpu-crypto.so

prefix ?= /usr/local
exec_prefix ?= $(prefix)
libdir ?= $(exec_prefix)/lib
includedir ?= $(prefix)/include
bindir ?= $(prefix)/bin
datarootdir ?= $(prefix)/share
docdir ?= $(datarootdir)/doc/libfpu-crypto

# Set default directories
S ?= $(CURDIR)
O ?= build
FP_BIN ?= $(FP_DIR)

# Set default build library dir
BUILD_LIB_DIR ?= lib

# Include FPN SDK configuration
# Use -include, file may not be present for doc generation
-include $(FPNSDK_DIR)/fpn-arch.mk

# Set flags
CFLAGS += -W -Wall -Werror -fvisibility=hidden -fPIC
CFLAGS += -I$(S)/include
CFLAGS += -I$(FP_DIR)/fp-modules/fpu-rpc -I$(FP_DIR)/fp-modules/fpu-rpc/lib
CFLAGS += $(FPNSDK_CFLAGS) 

LDFLAGS += $(FPNSDK_LDFLAGS) 
LDFLAGS += -L$(FP_BIN)/fp-modules/fpu-rpc/lib

LDLIBS += -lfpu-rpc
LDLIBS += -lfpn-shmem

# Source files
SRCS += src/fpu-crypto-rpc.c
SRCS += src/fpu-crypto-init.c

# Installable headers
HDRS := libfpu-crypto.h

# Source subdirectories
SUBDIRS := test/fpu-crypto-test

OBJS := $(SRCS:src/%.c=$(O)/obj/%.o)
DEPS := $(SRCS:src/%.c=$(O)/obj/%.d)

# V (Verbosity): 0 (quiet) or 1 (verbose)
ifndef V
override V := 0
endif
# commands verbosity: P for print, E for execute
ifeq '$V' '0'
P := @ echo
E := @
else
P := @ true
E :=
endif

# Rules

all: $(O)/$(BUILD_LIB_DIR)/$(LIB)
	$E $(MAKE) -C $S O=$O S=$S $(SUBDIRS)

$(O)/obj $(O)/$(BUILD_LIB_DIR):
	$E mkdir -p $@

ifeq '$(and $(FP_DIR),$(FPNSDK_DIR))' ''
$(O)/$(BUILD_LIB_DIR)/$(LIB) $(OBJS):
	$(error FP_DIR and FPNSDK_DIR must be defined)
else

$(O)/$(BUILD_LIB_DIR)/$(LIB): $(OBJS) | $(O)/$(BUILD_LIB_DIR)
	$P '  LD      $(notdir $@)'
	$E $(CC) $(LDFLAGS) -shared $(EXTRA_LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(O)/obj/%.o: $(S)/src/%.c | $(O)/obj
	$P '  CC      $(notdir $@)'
	$E $(CC) -Wp,-MD,$(@:%.o=%.d) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ -c $<

endif # FP_DIR / FPNSDK_DIR

help: doc-build-help
doc: doc-default
doc-%: FORCE
	$E $(MAKE) -rR --no-print-directory -C $S/doc \
		DOC_TOOLS=$(abspath $(DOC_TOOLS)) \
		O=$(abspath $O)/doc \
		DESTDIR=$(abspath $(DESTDIR))$(docdir) \
		$*

version:
	$E sed -n 's,#define *FPU_CRYPTO_VERSION *"\(.*\)",\1,p' $S/include/libfpu-crypto.h

clean: $(SUBDIRS) doc-clean
	$E rm -rf $O/obj $O/$(BUILD_LIB_DIR)

install-devel: install-target $(SUBDIRS) \
	$(addprefix $(DESTDIR)$(includedir)/, $(HDRS))

install-target: $(DESTDIR)$(libdir)/$(LIB) $(SUBDIRS)

$(DESTDIR)$(includedir)/%.h: $(S)/include/%.h
	$P '  INSTALL $(notdir $@)'
	$E install -D $< $@

$(DESTDIR)$(libdir)/$(LIB): $(O)/$(BUILD_LIB_DIR)/$(LIB)
	$P '  INSTALL $(notdir $@)'
	$E install -D $< $@

$(SUBDIRS):
	$E $(MAKE) -C $S/$@ S=$(abspath $S)/$@ \
		FPNSDK_DIR=$(abspath $(FPNSDK_DIR)) O=$(abspath $O)/$@ \
		$(filter $(RECURSIVE_RULES), $(MAKECMDGOALS))

-include $(DEPS)

RECURSIVE_RULES = all clean install-target install-devel
.PHONY: $(RECURSIVE_RULES) $(SUBDIRS) version help doc FORCE
