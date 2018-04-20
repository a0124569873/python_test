# Copyright 2014 6WIND S.A.

DOC=overview.rst  usage.rst
DOC_COMPONENT=fastpath-egress-qos
DOC_NAME = $(shell sed -n 's,.. title:: ,,p' *.rst)

ifndef DOC_TOOLS

doc:
	@ echo 'cannot do $@ - try to define DOC_TOOLS' && false

else # use doc-tools

include $(DOC_TOOLS)/mk/simple.mk

endif

