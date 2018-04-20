PROG = fp-cli

include $(DIST_FP)/mcore_common.mk
include $(FPNSDK_DIR)/fpn-arch.mk

VPATH = $(DIST_FP)/fpdebug $(DIST_FP)/common $(DIST_FP)/fpm
CFLAGS += -I$(DIST_FP)/fpdebug

SRCS = fpdebug.c fp.c fp-clock.c fp-if.c fp-autoconf-if.c
SRCS+= fpdebug-stats.c cli-cmd/fp-cli-commands.c b64/b64.c

SRCS += licence/fp-cpu-model.c
SRCS += licence/fp-hd-no.c
SRCS += licence/fp-licence.c
SRCS += licence/fp-net-macs.c
SRCS += licence/fp-serial-no.c
SRCS += licence/fp-licence-decode.c
 
# rsa
CFLAGS += -I$(FP_BUILDROOT)/config
# md5
SRC += md5/md5.c
# openssl
LDLIBS += -lcrypto

# add md5 support
CFLAGS += -I$(ROOTDIR)/ports/libmd5
LDLIBS += -L $(ROOTDIR)/ports/libmd5 -lmd5

ifeq ($(CONFIG_MCORE_XIN4),y)
VPATH  += $(DIST_FP)/fp-modules/tunnel/common
SRCS   += fp-tunnels-config.c
endif

VPATH += $(DIST_FP)/fp-modules/ip/common
ifeq ($(CONFIG_MCORE_IP),y)
CFLAGS += -I$(DIST_FP)/fp-modules/ip/common
SRCS   += fp-l3.c
SRCS   += fp-addr-list.c
SRCS   += rt_dump.c
endif

ifeq ($(CONFIG_MCORE_SOCKET),y)
CFLAGS += -I$(DIST_FP)/fp-modules/tcp-udp/cli
VPATH  += $(DIST_FP)/fp-modules/tcp-udp/cli
SRCS   += fpd-socket.c

ifneq ($(CONFIG_MCORE_FP_PLUGINS)$(CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY),yy)
CFLAGS += -I$(DIST_FP)/fp-plugins/so-apps

VPATH  += $(DIST_FP)/fp-plugins/so-apps/udp-server
SRCS   += fpd-so-udp-server.c

VPATH  += $(DIST_FP)/fp-plugins/so-apps/tcp-server
SRCS   += fpd-so-tcp-server.c

VPATH  += $(DIST_FP)/fp-plugins/so-apps/tcp-client
SRCS   += fpd-so-tcp-client.c

VPATH  += $(DIST_FP)/fp-plugins/so-apps/tcp-proxy
SRCS   += fpd-so-tcp-proxy.c

ifeq ($(CONFIG_MCORE_TCP_SENDER),y)
VPATH  += $(DIST_FP)/fp-plugins/so-apps/http-client
SRCS   += fpd-so-http-client.c

VPATH  += $(DIST_FP)/fp-plugins/so-apps/tcp-sender
SRCS   += fpd-so-tcp-sender.c
endif
endif
endif

ifeq ($(CONFIG_MCORE_BUILTIN_VSWITCH),y)
include $(DIST_FP_VSWITCH)/fpdebug/fpd-vswitch.mk
endif

ifeq ($(CONFIG_MCORE_ARCH_DPDK),y)
SRCS   += fpd-dpdk-vf.c
SRCS   += fpd-dpdk-rss.c
SRCS   += fpd-dpdk-link-flowctrl.c
SRCS   += fpd-dpdk-fdir.c
endif

ifeq ($(CONFIG_MCORE_TAP_BPF),y)
VPATH += $(DIST_FP)/fp-modules/tap/common
SRCS   += fp-bpf.c
endif

ifeq ($(CONFIG_MCORE_IPSEC),y)
VPATH+= $(DIST_FP)/fp-modules/ipsec/common
SRCS   +=  fp-ipsec.c
endif

ifeq ($(CONFIG_MCORE_IPSEC_IPV6),y)
VPATH+= $(DIST_FP)/fp-modules/ipsec6/common
SRCS   +=  fp-ipsec6.c
endif

ifeq ($(CONFIG_MCORE_IPSEC_SVTI),y)
VPATH+= $(DIST_FP)/fp-modules/svti/common
SRCS   +=  fp-svti.c
ifeq ($(CONFIG_MCORE_IPSEC_IPV6),y)
SRCS   +=  fp-svti6.c
endif
endif

ifeq ($(CONFIG_MCORE_VXLAN),y)
VPATH+= $(DIST_FP)/fp-modules/vxlan/common
SRCS   += fp-vxlan-config.c
endif

ifeq ($(CONFIG_MCORE_VLAN),y)
VPATH+= $(DIST_FP)/fp-modules/vlan/common
VPATH+= $(DIST_FP)/fp-modules/vlan/cli
SRCS   += fp-vlan-config.c
SRCS   += fpd-vlan.c
endif

ifeq ($(CONFIG_MCORE_MACVLAN),y)
VPATH+= $(DIST_FP)/fp-modules/macvlan/common
SRCS   += fp-macvlan-config.c
VPATH+= $(DIST_FP)/fp-modules/macvlan/cli
SRCS   += fpd-macvlan.c
endif

ifeq ($(CONFIG_MCORE_BRIDGE),y)
VPATH+= $(DIST_FP)/fp-modules/bridge/common
SRCS   += fp-bridge-config.c
VPATH+= $(DIST_FP)/fp-modules/bridge/cli
SRCS   += fpd-bridge.c
endif

ifeq ($(CONFIG_MCORE_LAG),y)
VPATH  += $(DIST_FP)/fp-modules/lag/common
VPATH  += $(DIST_FP)/fp-modules/lag/cli
SRCS   += fp-bonding-config.c
SRCS   += fpd-bonding.c
endif

ifeq ($(CONFIG_MCORE_GRE),y)
VPATH  += $(DIST_FP)/fp-modules/gre/common
VPATH  += $(DIST_FP)/fp-modules/gre/cli
SRCS   += fp-gre-config.c
SRCS   += fpd-gre.c
endif

SRCS   += fp-blade.c
SRCS   += fp-rfps-conf.c
SRCS   += fp-netfpc-notify.c

ifeq ($(CONFIG_MCORE_EBTABLES),y)
CFLAGS += -I$(DIST_FP)/fp-modules/filter-bridge/common
VPATH  += $(DIST_FP)/fp-modules/filter-bridge/common
VPATH  += $(DIST_FP)/fp-modules/filter-bridge/cli
SRCS   += fp-ebtables-config.c
SRCS   += fpd-ebtables.c
endif

ifeq ($(CONFIG_MCORE_NETFILTER),y)
VPATH  += $(DIST_FP)/fp-modules/filter/common
SRCS   += fp-netfilter.c
endif

# json
VPATH  += $(DIST_FP)/fp-modules/veda_ddos/common
SRCS += cJSON.c
LDLIBS += -lm

ifeq ($(CONFIG_MCORE_KTABLES),y)
SRCS   += fpd-ktables.c
SRCS   += fp-ktables.c
endif

ifeq ($(CONFIG_MCORE_VNB),y)
SRCS   += fpd-vnb.c
endif

ifeq ($(CONFIG_MCORE_TC),y)
VPATH  += $(DIST_FP)/fp-modules/tc/cli
SRCS   += fpd-tc.c
endif

CFLAGS += -O2 -Wextra -Wall
CFLAGS += -Werror
CFLAGS += -Wundef
CFLAGS += -Wno-unused-parameter
CFLAGS += -g
CFLAGS += $(FPNSDK_CFLAGS)

CFLAGS += $(MCORE_COMMON_CFLAGS) -DFP_LOG_COMMON_PRINTF
CFLAGS += -D__TEST_FPM_RT_DUMP

ifneq ($(DIST_LIBEDIT),)
CFLAGS += -DHAVE_LIBEDIT
CFLAGS += $(libedit-cflags)
LDFLAGS+= $(libedit-ldflags)
CFLAGS += $(libncurses-cflags)
LDFLAGS+= $(libncurses-ldflags)
LDLIBS += -ledit -lncurses
endif

ifeq ($(CONFIG_MCORE_TAP_CIRCULAR_BUFFER),y)
CFLAGS += $(libpcap-cflags)
LDFLAGS+= $(libpcap-ldflags)
LDLIBS += -lpcap
endif

CFLAGS += -I$(DIST_FP)/libnetfpc
LDLIBS += -L../libnetfpc
LDLIBS += -lnetfpc

CFLAGS += $(libifuid-cflags)
LDLIBS += $(libifuid-ldflags) -lifuid

CFLAGS += -I$(DIST_FP)/libfp_shm
LDLIBS += -L../libfp_shm
LDLIBS += -lfp_shm
LDLIBS += $(FPNSDK_LDFLAGS) -lfpn-shmem

ifeq ($(CONFIG_MCORE_FPDEBUG_DECODE_BPF),y)
CFLAGS += $(libpcap-cflags)
LDFLAGS+= $(libpcap-ldflags)
LDLIBS += -lpcap
endif

ifeq ($(CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY),y)
# For plugins to work
LDLIBS += -ldl -export-dynamic
endif
ifeq ($(CONFIG_MCORE_SHM_GENERIC_POSIX),y)
LDLIBS += -lrt
endif

include $(FPNSDK_DIR)/mk/prog.mk

.PHONY: fp-sizes

include $(S)/../common/fp-sizes.mk

install install-target: cmd-script install-config

.PHONY: cmd-script

cmd-script: $(DESTDIR)/$(PREFIX_BINDIR)fpcmd \
	        $(DESTDIR)/$(PREFIX_BINDIR)fpstats \
	        $(DESTDIR)/$(PREFIX_BINDIR)fpdebug

all: fpdebug

$(DESTDIR)/$(PREFIX_BINDIR)fpdebug fpdebug: fp-cli
	$(P) '  SYMLINK $< to $@'
	$(Q)ln -fs $< $@

$(DESTDIR)/$(PREFIX_BINDIR)fpcmd: $(S)/fpcmd
	$(P) '  INSTALL-SCRIPT fpcmd'
	$(Q)install -D $< $@

$(DESTDIR)/$(PREFIX_BINDIR)fpstats: $(S)/fp-stats
	$(P) '  INSTALL-SCRIPT fpstats'
	$(Q)install -D $< $@

.PHONY: install-config

install-config: $(DESTDIR)/usr/local/6WINDGate/etc/fpnsdk.config \
                $(DESTDIR)/usr/local/6WINDGate/etc/fp.config

$(DESTDIR)/usr/local/6WINDGate/etc/fpnsdk.config: $(FPNSDK_DOT_CONFIG)
	$(P) '  INSTALL-CONFIG fpnsdk.config'
	$(Q)install -D $< $@

$(DESTDIR)/usr/local/6WINDGate/etc/fp.config: $(FP_BUILDROOT)/config/fp.config
	$(P) '  INSTALL-CONFIG fp.config'
	$(Q)install -D $< $@
