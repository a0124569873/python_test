include $(FPNSDK_DIR)/mk/verbose.mk

# Copyright 6WIND, 2012, All rights reserved.

# common rules for building an executive library

# LIB_FILES is the list of all file names for the sources to be compiled
# and archived into $(OBJ_DIR)/$(LIB)
ifeq ($(LIB_FILES),)
$(error LIB_FILES is not defined)
endif

# OBJ_DIR is the name of the directory where objects, dependencies and
# the library will be stored
ifeq ($(OBJ_DIR),)
$(error OBJ_DIR is not defined)
endif


_LIB_SRCS    := $(notdir $(LIB_FILES))
_LIB_SRCPATH := $(sort $(dir $(LIB_FILES)))

ifeq ($(ANALYZE),y)
COMPILE_C = $(subst -c,,$(COMPILE.c)) # remove -c from command-line
else
COMPILE_C = $(COMPILE.c)
endif

_LIB_OBJS := $(patsubst %.c,%.o,$(addprefix $(OBJ_DIR)/,$(_LIB_SRCS)))

all: lib

lib: $(OBJ_DIR)/$(LIB)

$(OBJ_DIR)/$(LIB): $(_LIB_OBJS)
	$(P) '  AR $(notdir $@)'
	$(Q)$(AR) r $@ $^

# Nothing to install on target (.a)
install-target: ;

prefix = /usr/local/fpn-sdk
#
# Devel needs lib.a
install-devel install: $(DESTDIR)/$(prefix)/$(PREFIXDIR)/$(LIB)

$(DESTDIR)/$(prefix)/$(PREFIXDIR)/$(LIB): $(OBJ_DIR)/$(LIB)
	$(P) '  INSTALL $(notdir $(LIB))'
	$(Q)install -D $< $@

# dynamically generated compile rules for each input source file
define compile_rule
$(OBJ_DIR)/$(patsubst %.c,%.o,$(notdir $(1))): $(1)
	@[ -d $$(OBJ_DIR) ] || mkdir -p $$(OBJ_DIR)
	$$(P) '  CC   $$(notdir $$(@))'
	$$(Q)$$(COMPILE_C) -MD $$(OUTPUT_OPTION) $$<
endef
$(foreach file,$(LIB_FILES),$(eval $(call compile_rule,$(file))))

# all produced files (*.o, *.d) are stored in $(OBJ_DIR)
clean:
	$(Q)$(RM) -f $(OBJ_DIR)/*.d $(_LIB_OBJS) $(OBJ_DIR)/$(LIB)

-include $(OBJ_DIR)/*.d

.PHONY: all clean
