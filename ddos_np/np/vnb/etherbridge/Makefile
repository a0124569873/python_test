# Copyright 2014 6WIND S.A.

S?=$(CURDIR)

HDRS_BRIDGE := ng_etherbridge.h ng_bridge.h ng_bridge_snoop.h ng_etf.h
SRCS_ETHERBRIDGE := ng_etherbridge.c
SRCS_BRIDGE := ng_bridge.c
SRCS_ETF := ng_etf.c

HDRS = $(addprefix $(S)/netgraph/, $(HDRS_BRIDGE))
SRCS = $(addprefix $(S)/netgraph/, $(SRCS_ETHERBRIDGE) $(SRCS_BRIDGE) $(SRCS_ETF))

VNB_MODS := vnb_etherbridge vnb_bridge vnb_etf

include $(TOP_S)/kbuild.mk

ifneq ($(KERNELRELEASE),)
obj-m  += $(addsuffix .o,$(VNB_MODS))
vnb_etherbridge-objs = $(patsubst %.c,%.o, $(SRCS_ETHERBRIDGE))
vnb_bridge-objs = $(patsubst %.c,%.o, $(SRCS_BRIDGE))
vnb_etf-objs = $(patsubst %.c,%.o, $(SRCS_ETF))
endif

-include $(TOP_S)/module.mk
