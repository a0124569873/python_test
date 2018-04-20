# Copyright 2013 6WIND S.A.

APP = fpu-crypto-test

# Set default directories
S ?= $(CURDIR)
O ?= $(CURDIR)

prefix ?= /usr/local
exec_prefix ?= $(prefix)
libdir ?= $(exec_prefix)/lib
includedir ?= $(prefix)/include
bindir ?= $(prefix)/bin

# Set default destination library path name
BUILD_LIB_DIR ?= lib

# Set flags
CFLAGS += -W -Wall -Werror
CFLAGS += -I$(S)/../../include
CFLAGS += $(FPNSDK_CFLAGS) 

LDFLAGS += $(FPNSDK_LDFLAGS) 
LDFLAGS += -L$(O)/../../$(BUILD_LIB_DIR)

LDLIBS += -lfpu-crypto
LDLIBS += -lfpn-shmem
LDLIBS += -lpthread
LDLIBS += -lrt

# Source files
SRCS := src/fpu-crypto-test.c

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
all: $(O)/bin/$(APP)

$(O)/obj $(O)/bin:
	$E mkdir -p $@

ifeq '$(FPNSDK_DIR)' ''
$(O)/bin/$(APP) $(OBJS):
	$(error FPNSDK_DIR must be defined)
else

# Include FPN SDK configuration
include $(FPNSDK_DIR)/fpn-arch.mk

$(O)/bin/$(APP): $(OBJS) | $(O)/bin
	$P '  LD      $(notdir $@)'
	$E $(CC) $(LDFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(O)/obj/%.o: $(S)/src/%.c | $(O)/obj
	$P '  CC      $(notdir $@)'
	$E $(CC) -Wp,-MD,$(@:%.o=%.d) $(CFLAGS) -o $@ -c $<

endif # FPNSDK_DIR

clean:
	$E rm -rf $O/obj $O/bin

install-devel: install-target

install-target: $(DESTDIR)/$(bindir)/$(APP)

$(DESTDIR)/$(bindir)/$(APP): $(O)/bin/$(APP)
	$P '  INSTALL $(notdir $@)'
	$E install -D $< $@

-include $(DEPS)

.PHONY: all clean install-target install-devel
