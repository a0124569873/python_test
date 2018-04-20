# Copyright 2013 6WIND S.A.

DOC = about-manual.rst overview.rst usage.rst
DOC_COMPONENT = vnb-gtpu
DOC_NAME = $(shell sed -n 's,.. title:: ,,p' *.rst)
REPLACE_DIRECTIVE_FILES = ../../doc/replace.txt

ifndef DOC_TOOLS

doc:
	@ echo 'cannot do $@ - try to define DOC_TOOLS' && false

else # use doc-tools

include $(DOC_TOOLS)/mk/simple.mk

endif
