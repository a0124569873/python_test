# Copyright 2014 6WIND S.A.

S?=$(CURDIR)

HDRS_GRE := ng_gre.h kmap_skb.h
SRCS_GRE := ng_gre.c

HDRS = $(addprefix $(S)/netgraph/, $(HDRS_GRE))
SRCS = $(addprefix $(S)/netgraph/, $(SRCS_GRE))

VNB_MODS := vnb_gre

include $(TOP_S)/kbuild.mk

ifneq ($(KERNELRELEASE),)
obj-m  += $(addsuffix .o,$(VNB_MODS))
vnb_gre-objs = $(patsubst %.c,%.o, $(SRCS_GRE))
endif

-include $(TOP_S)/module.mk
