# Copyright 2014 6WIND S.A.

S?=$(CURDIR)
O?=$(CURDIR)

SUBDIR:= module cmgr

all clean install install-target install-devel subdirs: $(SUBDIR)

PREFIXDIR:=

$(SUBDIR):
		mkdir -p $(O)/$@ && $(MAKE) -C $(O)/$@ \
		-f $(S)/$@/Makefile \
		O=$(O)/$@ \
		PREFIXDIR=$(PREFIXDIR)$@/ \
		M= \
		S=$(S)/$@ $(filter-out subdirs $(SUBDIR),$(MAKECMDGOALS))

.PHONY: subdirs $(SUBDIR) install install-target install-devel
