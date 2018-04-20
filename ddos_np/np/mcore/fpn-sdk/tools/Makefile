-include $(FPNSDK_DOT_CONFIG)

SUBDIR-$(CONFIG_MCORE_DEBUG_CPU_USAGE) += cpu-usage

ifneq ($(CONFIG_MCORE_ARCH_XLP)$(CONFIG_MCORE_ARCH_OCTEON),y)
SUBDIR-y += shmem-ports
endif

SUBDIR-$(CONFIG_MCORE_FPVI_DP) += shmem-dpvi

SUBDIR-$(CONFIG_MCORE_FPN_TRACK) += track

SUBDIR-$(CONFIG_MCORE_INTERCORE) += intercore

SUBDIR-$(CONFIG_MCORE_FPN) += shmem-ready

SUBDIR=$(SUBDIR-y)

include mk/subdir.mk
