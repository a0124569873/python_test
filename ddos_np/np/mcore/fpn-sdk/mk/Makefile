all clean: ;

ifeq ($(PKG_DKMS),y)
RUNTIME_FILES = $(S)/kmod.mk $(S)/../fpn-arch.mk
FILES=$(filter-out $(RUNTIME_FILES),$(wildcard $(S)/*.mk))
else
FILES=$(wildcard $(S)/*.mk) $(S)/../fpn-arch.mk
endif

include mk/files.mk
