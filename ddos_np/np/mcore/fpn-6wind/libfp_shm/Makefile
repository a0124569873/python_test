include $(DIST_FP)/mcore_common.mk

# To get FPNSDK_CFLAGS
include $(FPNSDK_DIR)/fpn-arch.mk

VPATH= $(S)

LIB= libfp_shm.so
SHARED_LIB=yes

SRCS= libfp_shm.c

CFLAGS += $(FPNSDK_CFLAGS)
CFLAGS += $(MCORE_COMMON_CFLAGS)
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -Wundef -Wstrict-prototypes

include $(FPNSDK_DIR)/mk/lib.mk
