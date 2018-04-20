-include $(FPNSDK_DOT_CONFIG)

SUBDIR-$(CONFIG_MCORE_SHM_GENERIC)+= lib
SUBDIR-$(CONFIG_MCORE_SHM_GENERIC_KMOD)+= linux

SUBDIR=$(SUBDIR-y)

include mk/subdir.mk

ifeq ($(PKG_DKMS),y)
RUNTIME_FILES= $(S)/fpn-shmem.h
else
FILES= $(S)/fpn-shmem.h
endif

include mk/files.mk
