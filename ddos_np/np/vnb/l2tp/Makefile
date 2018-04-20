# Copyright 2014 6WIND S.A.

S?=$(CURDIR)

SRCS_L2TP := ng_l2tp.c
HDRS_L2TP := ng_l2tp.h

SRCS = $(addprefix $(S)/netgraph/, $(SRCS_L2TP))
HDRS = $(addprefix $(S)/netgraph/, $(HDRS_L2TP))

VNB_MODS := vnb_l2tp

include $(TOP_S)/kbuild.mk

ifneq ($(KERNELRELEASE),)
obj-m  += $(addsuffix .o,$(VNB_MODS))
vnb_l2tp-objs = $(patsubst %.c,%.o, $(SRCS_L2TP))
endif

-include $(TOP_S)/module.mk

