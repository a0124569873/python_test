# Copyright 2014 6WIND S.A.

# Copy files into appropriate destination directories with correct permission modes,
# considering they are either binary files, libraries or configuration files.
#
# fill in BIN_SRC_FILES and/or LIB_SRC_FILES and/or ETC_SRC_FILES

-include $(DIST_FP)/mk/verbose.mk

PREFIX_BINDIR?=usr/local/bin
PREFIX_ETCDIR?=usr/local/etc
PREFIX_LIBDIR?=usr/local/lib

install-files:
ifneq ($(strip $(BIN_SRC_FILES)),)
	$(Q) mkdir -p $(DESTDIR)/$(PREFIX_BINDIR)
	$(Q) install -m 755 -t $(DESTDIR)/$(PREFIX_BINDIR) $(BIN_SRC_FILES)
endif
ifneq ($(strip $(ETC_SRC_FILES)),)
	$(Q) mkdir -p $(DESTDIR)/$(PREFIX_ETCDIR)
	$(Q) install -m 644 -t $(DESTDIR)/$(PREFIX_ETCDIR) $(ETC_SRC_FILES)
endif
ifneq ($(strip $(LIB_SRC_FILES)),)
	$(Q) mkdir -p $(DESTDIR)/$(PREFIX_LIBDIR)
	$(Q) install -m 511 -t $(DESTDIR)/$(PREFIX_LIBDIR) $(LIB_SRC_FILES)
endif

install install-target: install-files

.PHONY: install-files
