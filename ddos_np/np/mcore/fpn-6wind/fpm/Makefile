include $(DIST_FP)/mcore_common.mk

VPATH = $(DIST_FP)/fpm $(DIST_FP)/common

PROG = fpmd

ifeq ($(CONFIG_MCORE_FPE_VFP),y)
	SRCS        = fpm-dpvi.c
endif 

SUBDIR-y += scripts

SUBDIR = $(SUBDIR-y)

include $(FPNSDK_DIR)/mk/subdir.mk

ifeq ($(CONFIG_MCORE_FPE_MCEE),y)
	ifeq ($(CONFIG_MCORE_ARCH_OCTEON),y)
		SRCS        = fpm-octeon.c
	endif 
	ifeq ($(CONFIG_MCORE_ARCH_XLP),y)
		SRCS        = fpm-xlp.c
	endif
	ifeq ($(CONFIG_MCORE_FPVI_DP),y)
		SRCS        = fpm-dpvi.c
	endif
	ifeq ($(CONFIG_MCORE_FPVI_TAP),y)
		SRCS        = fpm-linux.c
	endif
endif

SRC_COMMON  = fp.c fp-clock.c fp-if.c
SRC_SYS = main_fpm.c interface.c dispatch.c
SRC_SYS += graceful_restart.c
SRC_SYS += sockmisc.c vrf.c fpm-netlink.c

VPATH += $(DIST_FP)/fp-modules/ip/common
ifeq ($(CONFIG_MCORE_IP),y)
CFLAGS += -I$(DIST_FP)/fp-modules/ip/common
SRC_COMMON += fp-l3.c
SRC_COMMON += fp-addr-list.c
SRC_COMMON += rt_dump.c inaddr.c inroute.c
endif

ifeq ($(CONFIG_MCORE_IPSEC),y)
VPATH += $(DIST_FP)/fp-modules/ipsec/common
SRC_COMMON += fp-ipsec.c
SRC_SYS    += ipsec.c
endif

ifeq ($(CONFIG_MCORE_IPSEC_IPV6),y)
VPATH += $(DIST_FP)/fp-modules/ipsec6/common
SRC_COMMON += fp-ipsec6.c
endif

ifeq ($(CONFIG_MCORE_IPSEC_SVTI),y)
VPATH+= $(DIST_FP)/fp-modules/svti/common
SRC_COMMON += fp-svti.c
ifeq ($(CONFIG_MCORE_IPSEC_IPV6),y)
SRC_COMMON += fp-svti6.c
endif
endif

ifeq ($(CONFIG_MCORE_VXLAN),y)
VPATH+= $(DIST_FP)/fp-modules/vxlan/common
SRC_COMMON += fp-vxlan-config.c
endif

ifeq ($(CONFIG_MCORE_VLAN),y)
CFLAGS += -I$(DIST_FP)/fpm
VPATH+= $(DIST_FP)/fp-modules/vlan/common
VPATH+= $(DIST_FP)/fp-modules/vlan/fpm
SRC_COMMON += fp-vlan-config.c
SRC_COMMON += fpm-vlan.c
endif

ifeq ($(CONFIG_MCORE_MACVLAN),y)
CFLAGS += -I$(DIST_FP)/fpm
VPATH+= $(DIST_FP)/fp-modules/macvlan/common
VPATH+= $(DIST_FP)/fp-modules/macvlan/fpm
SRC_COMMON += fp-macvlan-config.c
SRC_COMMON += fpm-macvlan.c
endif

ifeq ($(CONFIG_MCORE_BRIDGE),y)
CFLAGS += -I$(DIST_FP)/fpm
VPATH+= $(DIST_FP)/fp-modules/bridge/common
SRC_COMMON += fp-bridge-config.c
VPATH+= $(DIST_FP)/fp-modules/bridge/fpm
SRC_COMMON += fpm-bridge.c
endif

ifeq ($(CONFIG_MCORE_EBTABLES),y)
CFLAGS += -I$(DIST_FP)/fpm
CFLAGS += -I$(DIST_FP)/fp-modules/filter-bridge/common
VPATH+= $(DIST_FP)/fp-modules/filter-bridge/common
VPATH+= $(DIST_FP)/fp-modules/filter-bridge/fpm
SRC_COMMON += fp-ebtables-config.c
SRC_COMMON += fpm-ebtables.c
endif

ifeq ($(CONFIG_MCORE_LAG),y)
CFLAGS += -I$(DIST_FP)/fpm
VPATH+= $(DIST_FP)/fp-modules/lag/common
VPATH+= $(DIST_FP)/fp-modules/lag/fpm
SRC_COMMON += fp-bonding-config.c
SRC_COMMON += fpm-bonding.c
endif

ifeq ($(CONFIG_MCORE_GRE),y)
CFLAGS += -I$(DIST_FP)/fpm
VPATH+= $(DIST_FP)/fp-modules/gre/common
VPATH+= $(DIST_FP)/fp-modules/gre/fpm
SRC_COMMON += fp-gre-config.c
SRC_COMMON += fpm-gre.c
endif

ifeq ($(CONFIG_MCORE_KTABLES),y)
SRCS		+= fpm-ktables.c
SRC_COMMON	+= fp-ktables.c
endif

ifeq ($(CONFIG_MCORE_VNB),y)
SRC_SYS    += vnb.c
SRC_SYS    += vnb_oosync.c
endif

SRC_COMMON += fp-blade.c
SRC_COMMON += fp-rfps-conf.c
SRC_COMMON += fp-netfpc-notify.c
ifeq ($(CONFIG_MCORE_MULTIBLADE),y)
SRC_SYS    += blade.c
endif

ifeq ($(CONFIG_MCORE_NETFILTER),y)
VPATH  += $(DIST_FP)/fp-modules/filter/common
SRC_COMMON += fp-netfilter.c
SRC_SYS    += netfilter.c
endif

VPATH  += $(DIST_FP)/fp-modules/veda_ddos/common

ifeq ($(CONFIG_MCORE_TAP_BPF),y)
VPATH += $(DIST_FP)/fp-modules/tap/common
SRC_COMMON    += fp-bpf.c
SRCS          += fpm-bpf.c
endif

ifneq ($(CONFIG_MCORE_XIN4)$(CONFIG_MCORE_XIN6),)
VPATH+= $(DIST_FP)/fp-modules/tunnel/common
SRC_COMMON += fp-tunnels-config.c
SRC_SYS    += tunnel.c
endif

ifneq ($(CONFIG_MCORE_MULTICAST4)$(CONFIG_MCORE_MULTICAST6),)
SRC_SYS    += mroute.c
endif

SRCS += $(SRC_COMMON) $(SRC_SYS)

CFLAGS += -O3 -Wextra -Wall
CFLAGS += -Werror
CFLAGS += -Wundef -Wstrict-prototypes
CFLAGS += -Wno-unused-parameter
CFLAGS += -Wno-missing-field-initializers
CFLAGS += -g
CFLAGS += $(FPNSDK_CFLAGS)
CFLAGS += $(MCORE_COMMON_CFLAGS)

CFLAGS   += $(libevent-cflags)
LDFLAGS  += $(libevent-ldflags)
LDLIBS += -levent

libnl-cflags ?= $(shell pkg-config --silence-errors --cflags libnl-3.0)
CFLAGS += $(libnl-cflags)
LDFLAGS += $(libnl-ldflags)
LDLIBS += -lnl-3 -lnl-route-3

CFLAGS += -I$(DIST_FP)/libnetfpc
LDLIBS += -L../libnetfpc
LDLIBS += -lnetfpc

CFLAGS += -I$(DIST_FP)/libfp_shm
LDLIBS += -L../libfp_shm
LDLIBS += -lfp_shm
LDLIBS += $(FPNSDK_LDFLAGS) -lfpn-shmem

ifeq ($(CONFIG_MCORE_VNB),y)
CFLAGS += -I$(DIST_VNB)/sys
CFLAGS += -D_FPNETGRAPH_ -I$(DIST_VNB)/tools/libnetgraph
LDLIBS += -L../fp-modules/vnb/tools/libfpnetgraph
LDLIBS += -lfpnetgraph
endif

ifeq ($(CONFIG_HA6W_SUPPORT), y)
CFLAGS += $(ha-cflags)
LDFLAGS+= $(ha-ldflags)
LDLIBS += -l6whas -lxml2 -lxt -lm
endif

LDLIBS += -ldl

# Export symbols for plugins
LDFLAGS += -Wl,--export-dynamic

include $(FPNSDK_DIR)/mk/prog.mk

includedir = $(prefix)/include

install install-devel: \
 $(DESTDIR)/$(includedir)/fpc.h \
 $(DESTDIR)/$(includedir)/fpm_plugin.h

$(DESTDIR)/$(includedir)/%.h: $(S)/%.h
	$P 'INSTALL header $(notdir $<)'
	$Q install -D $< $@
