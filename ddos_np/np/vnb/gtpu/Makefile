# Copyright 2014 6WIND S.A.

S ?= $(CURDIR)

SRCS_GTPU := ng_gtpu.c
HDRS_GTPU := ng_gtpu.h

SRCS := $(addprefix $(S)/netgraph/, $(SRCS_GTPU))
HDRS := $(addprefix $(S)/netgraph/, $(HDRS_GTPU))

VNB_MODS := vnb_gtpu

include $(TOP_S)/kbuild.mk

ifneq ($(KERNELRELEASE),)
obj-m += $(addsuffix .o,$(VNB_MODS))
vnb_gtpu-objs = $(patsubst %.c,%.o, $(SRCS_GTPU))
endif

-include $(TOP_S)/module.mk
