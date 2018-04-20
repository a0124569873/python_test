# Copyright 2014 6WIND S.A.

DOC=overview.rst usage.rst
DOC_COMPONENT=fastpath-mcast6
DOC_NAME=$(shell sed -n 's,.. title:: ,,p' *.rst)

O = build
DESTDIR = install

ifndef DOC_TOOLS

doc:
	@ echo 'cannot do $@ - try to define DOC_TOOLS' && false

else # use doc-tools

include $(DOC_TOOLS)/mk/simple.mk

endif
