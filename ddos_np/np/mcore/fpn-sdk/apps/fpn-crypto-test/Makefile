FPNSDK_DIR ?= $(S)/../..
OUTPUT     ?= fpn-crypto-test

VPATH       = $(S)

SRCS       := fpn-crypto-test.c sym-unit-tests.c asym-unit-tests.c sym-perf-tests.c asym-perf-tests.c

include $(FPNSDK_DIR)/fpn-arch.mk

FPNSDK_CFLAGS  += -I$(S)

include $(FPNSDK_DIR)/mk/fpn-prog.mk
