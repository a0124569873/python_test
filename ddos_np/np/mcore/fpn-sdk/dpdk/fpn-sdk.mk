-include $(FPNSDK_DOT_CONFIG)

include $(S)/mk/dpdk-init.mk

include $(RTE_SDK)/mk/rte.vars.mk

include $(S)/mk/dpdk-options.mk

OBJ_DIR ?= $(CURDIR)

# library name
LIB = libfpnsdk.a
all: $(OBJ_DIR)/$(LIB)

# fpn-sdk-specific flags
CFLAGS += -include $(FPNSDK_CONFIG_H)
CFLAGS += -I$(S)/..
CFLAGS += -I$(S)
CFLAGS += -D__FastPath__

# FIXME: remove some warning detection
CFLAGS += -Wno-pointer-arith -Wno-cast-qual

CFLAGS += $(EXTRA_CFLAGS)

# dpdk specific
FPNSDK_FILES := $(S)/fpn-dpdk.c
FPNSDK_FILES += $(S)/fpn-mbuf-dpdk.c
ifeq ($(CONFIG_MCORE_FPVI_DP),y)
FPNSDK_FILES += $(S)/fpn-dpvi-dpdk.c
endif
ifeq ($(CONFIG_MCORE_FPVI_TAP),y)
FPNSDK_FILES += $(S)/fpn-tuntap-dpdk.c
CFLAGS += $(libevent-cflags)
endif
ifeq ($(CONFIG_MCORE_FPVI_DP),y)
FPNSDK_FILES += $(S)/../dpvi/fpn-dpvi.c
CFLAGS += -I$(S)/../dpvi
endif
FPNSDK_FILES += $(S)/fpn-main-loop-dpdk.c
ifeq ($(CONFIG_MCORE_L2_INFRA),y)
FPNSDK_FILES += $(S)/../fpn-vlanport.c
endif
ifeq ($(CONFIG_MCORE_SW_TCP_LRO),y)
FPNSDK_FILES += $(S)/fpn-sw-tcp-lro.c
endif

# common
FPNSDK_FILES += $(S)/../fpn-mbuf.c
ifeq ($(CONFIG_MCORE_INTERCORE),y)
FPNSDK_FILES += $(S)/../fpn-intercore.c
endif
ifeq ($(CONFIG_MCORE_TIMER_GENERIC), y)
FPNSDK_FILES += $(S)/../timer/fpn-timer-test.c
FPNSDK_FILES += $(S)/../timer/fpn-timer-generic.c
endif
ifeq ($(CONFIG_MCORE_AATREE), y)
FPNSDK_FILES += $(S)/../fpn-aatree.c
endif
FPNSDK_FILES += $(S)/../fpn-hexdump.c
FPNSDK_FILES += $(S)/../fpn-assert.c
FPNSDK_FILES += $(S)/../fpn-ring.c
FPNSDK_FILES += $(S)/../fpn-mempool.c
FPNSDK_FILES += $(S)/../fpn-ringpool.c
FPNSDK_FILES += $(S)/../fpn-ringqueue.c
FPNSDK_FILES += $(S)/../fpn-malloc.c
FPNSDK_FILES += $(S)/../fpn-recurs-spinlock.c
FPNSDK_FILES += $(S)/../fpn-core.c
FPNSDK_FILES += $(S)/../fpn-job.c
FPNSDK_FILES += $(S)/../fpn-cksum.c
ifeq ($(CONFIG_MCORE_FPN_GC),y)
FPNSDK_FILES += $(S)/../fpn-gc.c
endif
ifeq ($(CONFIG_MCORE_FPN_TRACK),y)
FPNSDK_FILES += $(S)/../fpn-track.c
endif
ifeq ($(CONFIG_MCORE_FPN_LOCK_DEBUG),y)
FPNSDK_FILES += $(S)/../fpn-lock.c
endif
ifeq ($(CONFIG_MCORE_FPN_CORE_BARRIER),y)
FPNSDK_FILES += $(S)/../fpn-corebarrier.c
endif
ifeq ($(CONFIG_MCORE_DEBUG_CPU_USAGE),y)
FPNSDK_FILES += $(S)/../fpn-cpu-usage.c
endif
ifeq ($(CONFIG_MCORE_FPN_HOOK),y)
FPNSDK_FILES += $(S)/../fpn-hook.c
endif


ifeq ($(CONFIG_MCORE_FPN_CRYPTO),y)
ifeq ($(CONFIG_MCORE_FPN_CRYPTO_GENERIC),y)
FPNSDK_FILES += $(S)/../crypto/fpn-hmac.c
FPNSDK_FILES += $(S)/../crypto/fpn-md5.c
FPNSDK_FILES += $(S)/../crypto/fpn-sha1.c
FPNSDK_FILES += $(S)/../crypto/fpn-sha2.c
FPNSDK_FILES += $(S)/../crypto/fpn-cbc.c
FPNSDK_FILES += $(S)/../crypto/fpn-des_enc.c
FPNSDK_FILES += $(S)/../crypto/fpn-des3_enc.c
FPNSDK_FILES += $(S)/../crypto/fpn-set_key.c
FPNSDK_FILES += $(S)/../crypto/fpn-rijndael.c
FPNSDK_FILES += $(S)/../crypto/fpn-ecb.c
FPNSDK_FILES += $(S)/../crypto/fpn-ctr.c
FPNSDK_FILES += $(S)/../crypto/fpn-gcm.c
FPNSDK_FILES += $(S)/../crypto/fpn-xcbc.c
FPNSDK_FILES += $(S)/../crypto/fpn-crypto-generic.c
endif

FPNSDK_FILES += $(S)/../fpn-crypto.c
FPNSDK_FILES += $(S)/crypto/fpn-dpdk-crypto.c
endif
ifeq ($(CONFIG_MCORE_SHM_GENERIC_KMOD),y)
FPNSDK_FILES += $(S)/../shmem/lib/libfpn-shmem-kmod.c
endif
ifeq ($(CONFIG_MCORE_SHM_GENERIC_POSIX),y)
FPNSDK_FILES += $(S)/../shmem/lib/libfpn-shmem-posix.c
endif
ifeq ($(CONFIG_MCORE_SHM_GENERIC_STUB),y)
FPNSDK_FILES += $(S)/../shmem/lib/libfpn-shmem-stub.c
endif

# for affinities
$(OBJ_DIR)/fpn-dpdk.o: CFLAGS += -D_GNU_SOURCE

LIB_FILES := $(FPNSDK_FILES)

include $(S)/../mk/fpn-lib.mk
