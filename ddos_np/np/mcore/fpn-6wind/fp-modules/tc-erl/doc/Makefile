# Copyright 2014 6WIND S.A.

DOC_COMPONENT = fastpath-tc-erl
DOC_NAME = $(shell sed -n 's,.. title:: ,,p' *.rst)
DOC = overview.rst

O = build
DESTDIR = install

ifndef DOC_TOOLS

doc:
	@ echo 'cannot do $@ - try to define DOC_TOOLS' && false

else # use doc-tools

include $(DOC_TOOLS)/mk/simple.mk

endif
