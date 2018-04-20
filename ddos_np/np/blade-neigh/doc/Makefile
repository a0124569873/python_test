# Copyright 2013 6WIND S.A.

DOC_COMPONENT = blade-neigh
DOC = blade-neigh-manual.rst
DOC_NAME = $(shell sed -n 's,.. title:: ,,p' *.rst)

ifndef DOC_TOOLS
# no doc build
clean : ; @ true
% : ; @ echo 'no rule doc-$@ - try to define DOC_TOOLS' && false

else # use doc-tools
include $(DOC_TOOLS)/mk/simple.mk

help :
	@ $(MAKE) -rRs list-rules | tr ' ' '\n' | sed 's,^,    doc-,'
	@ echo '    doc-help'

endif
