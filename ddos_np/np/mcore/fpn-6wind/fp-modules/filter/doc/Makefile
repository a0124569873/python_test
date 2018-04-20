# Copyright 2013 6WIND S.A.

DOC=overview.rst usage.rst
DOC_COMPONENT=fastpath-filter4
DOC_NAME=$(shell sed -n 's,.. title:: ,,p' *.rst)
DOC_VERSION=1.0

ifndef DOC_TOOLS

doc:
	@ echo 'cannot do $@ - try to define DOC_TOOLS' && false

else # use doc-tools

include $(DOC_TOOLS)/mk/simple.mk

endif
