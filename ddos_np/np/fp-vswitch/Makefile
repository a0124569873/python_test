# Copyright 2014 6WIND S.A.

export DIST_FP ?= /usr/local/fp
export FP_BUILDROOT ?= /usr/local/fp
export FP_DOT_CONFIG ?= /usr/local/fp/config/fp.config
export FPNSDK_DIR ?= /usr/local/fpn-sdk

-include $(FP_DOT_CONFIG)

SUBDIR-y =
ifneq ($(CONFIG_MCORE_BUILTIN_VSWITCH),y)
SUBDIR-y += fp
endif
SUBDIR-$(CONFIG_MCORE_FPDEBUG) += fpdebug
SUBDIR-y += fpm
SUBDIR-y += libdpif-fp

# If DIRS is given by the command line, go only in subdirs that are defined in
# both DIRS in SUBDIR-y. DIRS is a list of names separated by space or semicolon.
ifeq ($(DIRS),)
SUBDIR := $(SUBDIR-y)
else
SUBDIR := $(filter $(subst :, ,$(DIRS)),$(SUBDIR-y))
endif

include $(FPNSDK_DIR)/mk/subdir.mk

# Force out-of-tree build to avoid having .o files in VPATH
override O:=$(O)/build
