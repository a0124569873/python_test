# Usage
# 
# SUBDIR=dir1 dir2
#
# if makefile name is different than Makefile, use:
# MK_SUBDIR_dir1=Makefile.dir1
#
# include mk/subdir.mk
#
# if dir2 depends on dir1
# dir2: dir1
#
#

MAKEFLAGS += --no-print-directory

S?=$(CURDIR)
O?=$(CURDIR)

PREFIXDIR?=

.PHONY: subdirs $(SUBDIR) install install-target install-devel

all clean install install-target install-devel subdirs: $(SUBDIR)


$(SUBDIR):
	$(Q)[ ! -d $(S)/$@ ] || \
		(mkdir -p $(O)/$@ && $(MAKE) -C $(O)/$@ \
		-f $(S)/$@/$(if $(MK_SUBDIR_$@),$(MK_SUBDIR_$@),Makefile) \
		O=$(O)/$@ \
		PREFIXDIR=$(PREFIXDIR)$@/ \
		M= \
		S=$(S)/$@ $(filter-out subdirs $(SUBDIR),$(MAKECMDGOALS)))

