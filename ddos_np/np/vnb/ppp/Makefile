# Copyright 2014 6WIND S.A.

S?=$(CURDIR)

SRCS_PPP := ng_ppp.c
HDRS_PPP := ng_ppp.h

SRCS := $(addprefix $(S)/netgraph/,$(SRCS_PPP))
HDRS := $(addprefix $(S)/netgraph/,$(HDRS_PPP))

VNB_MODS := vnb_ppp

include $(TOP_S)/kbuild.mk

ifneq ($(KERNELRELEASE),)
obj-m  += $(addsuffix .o,$(VNB_MODS))
vnb_ppp-objs = $(patsubst %.c,%.o, $(SRCS_PPP))
endif

-include $(TOP_S)/module.mk
