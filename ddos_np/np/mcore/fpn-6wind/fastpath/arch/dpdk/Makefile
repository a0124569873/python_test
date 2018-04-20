include $(DIST_FP)/mcore_common.mk
include $(DIST_FP)/fastpath/mcore.mk

OUTPUT   ?= fp-rte
S?=$(DIST_FP)/fastpath/arch/dpdk

FPNSDK_CFLAGS += $(MCORE_CFLAGS)
FPNSDK_CFLAGS += -I$(S)
FPNSDK_CFLAGS += -Wno-unused-parameter
FPNSDK_LDLIBS += $(MCORE_LDLIBS)
FPNSDK_LDFLAGS+= $(MCORE_LDFLAGS)

# add md5 support
FPNSDK_CFLAGS += $(INCMD5)
FPNSDK_LDLIBS += $(LDFLAGS_LIBMD5)
# openssl
FPNSDK_LDFLAGS += -lcrypto

SRCS := $(S)/main.c
SRCS += $(DIST_FP)/fastpath/fp-fork.c
SRCS += $(MCORE_FILES)

# $S before all to pick up the correct main.c
VPATH += $(S) $(MCORE_SRCPATH)

include $(FPNSDK_DIR)/mk/fpn-prog.mk

ifeq ($(CONFIG_MCORE_EMBEDDED_SCRIPTS),y)
SCRIPT_FILES:=$(addprefix $(S)/, start-fp-rte.sh mcore.sh)

include $(FPNSDK_DIR)/mk/scripts.mk
endif

SUBDIR-y = scripts
SUBDIR:=$(SUBDIR-y)

-include $(FPNSDK_DIR)/mk/subdir.mk
