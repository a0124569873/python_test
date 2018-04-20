# Copyright 2014 6WIND S.A.

DOC=overview.rst usage.rst
DOC_COMPONENT=vnb-mpls-vpls
DOC_NAME=$(shell sed -n 's,.. title:: ,,p' *.rst)
REPLACE_DIRECTIVE_FILES=../../doc/replace.txt

ifndef DOC_TOOLS

doc:
	@ echo 'cannot do $@ - try to define DOC_TOOLS' && false

else # use doc-tools

include $(DOC_TOOLS)/mk/simple.mk

endif
