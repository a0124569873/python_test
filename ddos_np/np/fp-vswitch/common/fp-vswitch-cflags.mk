# Copyright 2013 6WIND S.A.

FPNSDK_DIR?=/usr/local/fpn-sdk
FPNSDK_BIN?=$(FPNSDK_DIR)
FPNSDK_DOT_CONFIG?=$(FPNSDK_BIN)/config/fpnsdk.config

-include $(FPNSDK_DOT_CONFIG)

# Check if a list of compiler flags is supported.
CHECK_CFLAGS_SUPPORT = \
	only_if_cc_supports () { \
		echo | \
		$(CC) $(CFLAGS) -x c "$${@}" -c -o /dev/null - && \
		echo "$${@}"; \
		:; \
	} 2> /dev/null; \
	only_if_cc_supports

ifneq ($(or $(filter y, $(CONFIG_MCORE_ARCH_X86_64)), \
	$(filter y, $(CONFIG_MCORE_ARCH_X86))),)

# -mno-vzeroupper must be used with GCC >= 4.6.
_MNO_VZEROUPPER := $(shell $(CHECK_CFLAGS_SUPPORT) -mno-vzeroupper)

MCORE_CFLAGS_FP_VSWITCH += -msse4.1 -mavx -mno-sse2avx $(_MNO_VZEROUPPER)

endif
