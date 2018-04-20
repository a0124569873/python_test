# Copyright 2013 6WIND S.A.

DOC = overview.rst usage.rst

ifeq ($(FPNSDK_DOC_GEN_SDD),y)
DOC += sdd.rst
endif

DOC_COMPONENT=fpn-sdk-base
DOC_NAME = $(shell sed -n 's,.. title:: ,,p' *.rst)

ifndef DOC_TOOLS

doc:
	@ echo 'cannot do $@ - try to define DOC_TOOLS' && false

else # use doc-tools

include $(DOC_TOOLS)/mk/simple.mk

endif

