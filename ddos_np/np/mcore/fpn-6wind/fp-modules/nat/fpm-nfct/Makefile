-include $(FPNSDK_DOT_CONFIG)

include $(DIST_FP)/mcore_common.mk

MODULE        = fpm-nfct
MODULE_PATH   = drivers/net
SRCS          = $(S)/fpm-nfct.c

MODULE_CFLAGS += $(FPNSDK_CFLAGS)
MODULE_CFLAGS += $(MCORE_COMMON_CFLAGS)
MODULE_CFLAGS += -Winline -Wall -Werror
MODULE_CFLAGS += -Wextra -Wno-unused-parameter
MODULE_CFLAGS += -Wno-missing-field-initializers
MODULE_CFLAGS += -Wno-error=type-limits
MODULE_CFLAGS += -Wno-error=old-style-declaration
MODULE_CFLAGS += -Wno-error=sign-compare
MODULE_CFLAGS += -std=gnu89

KBUILD_EXTRA_SYMBOLS=$(FPNSDK_BIN)/shmem/linux/Module.symvers \
                     $(FPNSDK_BIN)/$(fpn_arch)/shmem/linux/Module.symvers

include $(FPNSDK_DIR)/mk/kmod.mk
