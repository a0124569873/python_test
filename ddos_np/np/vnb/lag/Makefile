# Copyright 2014 6WIND S.A.

S?=$(CURDIR)

HDRS_LAG := ng_ethgrp.h ieee8023_tlv.h ieee8023ad_marker.h ieee8023_slowprotocols.h ieee8023ad_lacp.h
SRCS_LAG = ng_ethgrp.c ieee8023_tlv.c ieee8023ad_marker.c

HDRS = $(addprefix $(S)/netgraph/, $(HDRS_LAG))
SRCS := $(addprefix $(S)/netgraph/, $(SRCS_LAG))

VNB_MODS := vnb_lag

include $(TOP_S)/kbuild.mk

ifneq ($(KERNELRELEASE),)
obj-m  += $(addsuffix .o,$(VNB_MODS))
vnb_lag-objs = $(patsubst %.c,%.o, $(SRCS_LAG))
endif

-include $(TOP_S)/module.mk
