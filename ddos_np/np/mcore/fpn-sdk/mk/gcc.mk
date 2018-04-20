include $(FPNSDK_DIR)/mk/verbose.mk

include $(FPNSDK_DIR)/fpn-arch.mk

# fpn_arch may not be defined if the config does not exist yet
ifneq ($(fpn_arch),)
-include $(FPNSDK_DIR)/$(fpn_arch)/mk/gcc.mk
endif

define cc_rule
	$(Q)mkdir -p $(dir $1)
	$(P) '  CC $(notdir $1)'
	$(Q)$(CC) $(OPTIMIZE) $(CFLAGS) $(EXTRA_CFLAGS) $(CFLAGS_$(1)) -o $1 -c $2
endef

define cpp_rule
	$(Q)mkdir -p $(dir $1)
	$(P) '  CPP $(notdir $1)'
	$(Q)$(CXX) $(OPTIMIZE) $(CXXFLAGS) $(EXTRA_CXXFLAGS) $(CXXFLAGS_$(1)) -o $1 -c $2
endef
