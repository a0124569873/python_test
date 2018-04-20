VPATH= $(S)
LIB= libfpn-shmem.so
SHARED_LIB=yes

include $(S)/../../fpn-arch.mk

ifeq ($(CONFIG_MCORE_SHM_GENERIC_KMOD),y)
SRCS+= libfpn-shmem-kmod.c
endif
ifeq ($(CONFIG_MCORE_SHM_GENERIC_POSIX),y)
SRCS+= libfpn-shmem-posix.c
endif
ifeq ($(CONFIG_MCORE_SHM_GENERIC_STUB),y)
SRCS+= libfpn-shmem-stub.c
endif

CFLAGS += -Wall -Wextra -Werror
CFLAGS += -I$(S)/../..

include mk/lib.mk
