# Copyright 2014 6WIND S.A.

ifeq ("$(origin V)", "command line")
Q =
P = @ true
else
MAKEFLAGS += --no-print-directory
Q = @
P = @ echo
endif

all clean install install-devel:;

PREFIX_BINDIR?=usr/local/bin
PREFIX_ETCDIR?=usr/local/etc
PREFIX_LIBDIR?=usr/local/lib

scripts :=vnb.sh
confs := vnb.env

BIN_SRC_FILES:=$(addprefix $(S)/, $(scripts))
ETC_SRC_FILES:=$(addprefix $(S)/, $(confs))

install-scripts:
	$(Q) mkdir -p $(DESTDIR)/$(PREFIX_BINDIR)
	$(Q) install -m 755 -t $(DESTDIR)/$(PREFIX_BINDIR) $(BIN_SRC_FILES)

	$(Q) mkdir -p $(DESTDIR)/$(PREFIX_ETCDIR)
	$(Q) install -m 644 -t $(DESTDIR)/$(PREFIX_ETCDIR) $(ETC_SRC_FILES)

install install-target: install-scripts

.PHONY: all install clean install-target install-devel install-scripts
