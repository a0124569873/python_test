# common compilation flags for dpdk

# For library, order is important: start with libfpnsdk,
# then add dependencies like crypto

CFLAGS += -O3 -g
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -Wundef
#CFLAGS += -Wno-unused-parameter
CFLAGS += -std=gnu99

LDFLAGS+= -L$(FPNSDK_BIN)/dpdk
LDLIBS += -lfpnsdk

ifeq ($(CONFIG_MCORE_FPVI_DP),y)
CFLAGS += -I$(FPNSDK_DIR)/dpvi
endif

ifeq ($(CONFIG_MCORE_FPVI_TAP),y)
LDFLAGS += $(libevent-ldflags)
LDLIBS += -levent
endif

ifeq ($(CONFIG_MCORE_FPN_RTE_CRYPTO),y)
CFLAGS += -I$(RTE_SDK_ADDONS_INCLUDE)
LDFLAGS+= -L$(RTE_SDK_ADDONS_LIBPATH)
ifneq ($(CONFIG_MCORE_FPN_HOOK),y)
LDLIBS += -lrte_crypto
endif
endif

# If we embed shm() API, we need librt
ifeq ($(CONFIG_MCORE_SHM_GENERIC_POSIX),y)
LDLIBS += -lrt
endif

