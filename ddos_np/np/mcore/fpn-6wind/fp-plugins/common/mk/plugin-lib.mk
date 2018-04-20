# Copyright 2013 6WIND S.A.

ifneq ($(fpn_arch),)
-include $(DIST_FP)/fp-plugins/common/$(fpn_arch)/plugin-lib.mk
endif

ifeq ($(PLUGIN_AUTO_LOAD),y)
# override is important, since we want to make sure that someone else won't move
# our plugins elsewhere
ifeq ($(FASTPATH_PLUGIN),y)
override libdir:=/usr/local/lib/fastpath
else
override libdir:=/usr/local/lib/fp-cli
endif
endif

include $(FPNSDK_DIR)/mk/lib.mk
