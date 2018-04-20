# Copyright 2014 6WIND S.A.

S?=$(CURDIR)

HDRS_VLAN := ng_vlan.h
SRCS_VLAN = ng_vlan.c

HDRS = $(addprefix $(S)/netgraph/, $(HDRS_VLAN))
SRCS = $(addprefix $(S)/netgraph/, $(SRCS_VLAN))

VNB_MODS := vnb_vlan

include $(TOP_S)/kbuild.mk

ifneq ($(KERNELRELEASE),)
obj-m  += $(addsuffix .o,$(VNB_MODS))
vnb_vlan-objs = $(patsubst %.c,%.o, $(SRCS_VLAN))
endif

-include $(TOP_S)/module.mk
