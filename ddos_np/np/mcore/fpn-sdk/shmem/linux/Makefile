MODULE		= fpn_shmem_linux
MODULE_PATH	= drivers/net
SRCS		= $(S)/fpn-shmem-linux.c

MODULE_CFLAGS := -I$(S)/../..
ifeq ($(PKG_DKMS),y)
MODULE_CFLAGS += -I/usr/local/fpn-sdk
MODULE_CFLAGS += -I/usr/local/fpn-sdk/shmem
endif
MODULE_CFLAGS += -Wall -Werror

include $(FPNSDK_DIR)/mk/kmod.mk
