# Copyright 2014 6WIND S.A.

S?=$(CURDIR)

SRCS_PPPOE := ng_pppoe.c
HDRS_PPPOE := ng_pppoe.h

SRCS = $(addprefix $(S)/netgraph/, $(SRCS_PPPOE))
HDRS = $(addprefix $(S)/netgraph/, $(HDRS_PPPOE))

VNB_MODS := vnb_pppoe

include $(TOP_S)/kbuild.mk

ifneq ($(KERNELRELEASE),)
obj-m  += $(addsuffix .o,$(VNB_MODS))
vnb_pppoe-objs = $(patsubst %.c,%.o, $(SRCS_PPPOE))
endif

-include $(TOP_S)/module.mk

