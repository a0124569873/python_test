DIST_CACHEMGR?=$(CURDIR)

S?=$(DIST_CACHEMGR)
O?=$(CURDIR)
ifeq ("$(origin V)", "command line")
Q =
P = @ true
else
MAKEFLAGS += --no-print-directory
Q = @
P = @ echo
endif

STRIP?=strip

VPATH = $(S)

PROG = cmgrd

prefix = /usr/local
exec_prefix = $(prefix)
libdir = $(exec_prefix)/lib
includedir = $(prefix)/include
bindir = $(prefix)/bin
EXTRA_SCRIPT=

SUBDIR-y := scripts

SUBDIR = $(SUBDIR-y)

all clean install install-target install-devel: $(SUBDIR)

all: $(PROG)

CFLAGS += -I$(S)

ifeq ($(CONFIG_PORTS_CACHEMGR_NF_RULE_NAT),y)
$(error FIXME CONFIG_PORTS_CACHEMGR_NF_RULE_NAT=y)
# -I$(DIST_IPTABLES_1_4_8)/include MUST be put after $(INCKERN), hence headers
# files from iptables will be used only if they are not found in headers
# exported by the kernel. The goal is to get include/net/netfilter/nf_nat.h only.
# The option CONFIG_PORTS_CACHEMGR_NF_RULE_NAT may be removed to use conntrack
# informations instead.
# XXX FIXME: a kernel rework is needed to cleanup these headers.
CFLAGS += -DCONFIG_PORTS_CACHEMGR_NF_RULE_NAT -I$(DIST_IPTABLES_1_4_8)/include
endif

SRCS = netlink.c main.c fpm.c base.c nl_base.c cm_init.c
SRCS += sockmisc.c cm_dump.c
SRCS += nl_dump.c
SRCS += if_linux.c rt_post.c
SRCS += iptc.c nl_xfrm.c
SRCS += vrf.c
SRCS += genl_base.c
SRCS += nl_connector.c
SRCS += proc_packet.c

CFLAGS += -g -O3 -Wall -Werror
CFLAGS += -DCONFIG_CACHEMGR_MULTIBLADE
ifneq ($(CONFIG_PORTS_CACHEMGR_DEF_SOCKBUFSIZE),)
CFLAGS += -DCONFIG_PORTS_CACHEMGR_DEF_SOCKBUFSIZE=$(CONFIG_PORTS_CACHEMGR_DEF_SOCKBUFSIZE)
endif
ifeq ($(CONFIG_PORTS_CACHEMGR_DEF_NFCT_DISABLE),y)
CFLAGS += -DCONFIG_PORTS_CACHEMGR_DEF_NFCT_DISABLE
endif

# Default configuration according to our local include
CONFIG_CACHEMGR_AUDIT ?= y
CONFIG_CACHEMGR_XFRMA_MARK ?= y
CONFIG_CACHEMGR_VXLAN ?= y
CONFIG_CACHEMGR_BRIDGE ?= y
CONFIG_CACHEMGR_VLAN ?= y
CONFIG_CACHEMGR_MACVLAN ?= y
CONFIG_CACHEMGR_BONDING ?= y
CONFIG_CACHEMGR_DIAG ?= y
CONFIG_CACHEMGR_EBTABLES ?= y
CONFIG_CACHEMGR_GRE ?= y
CONFIG_CACHEMGR_NF_RPFILTER ?= y

# Not upstream
CONFIG_CACHEMGR_NF_DEV ?= no
CONFIG_CACHEMGR_NF_UID ?= no
CONFIG_CACHEMGR_NF_LSN ?= no

# Linux 2.6.39 or RH 6, netfilter rules
ifeq ($(CONFIG_CACHEMGR_AUDIT), y)
CFLAGS += -DCONFIG_CACHEMGR_AUDIT
SRCS += nl_audit.c
endif

# Linux 2.6.34
ifeq ($(CONFIG_CACHEMGR_XFRMA_MARK), y)
CFLAGS += -DCONFIG_CACHEMGR_XFRMA_MARK
endif

# Linux 3.7 or RH 6.5
ifeq ($(CONFIG_CACHEMGR_VXLAN), y)
CFLAGS += -DCONFIG_CACHEMGR_VXLAN
endif

# Linux 3.0
ifeq ($(CONFIG_CACHEMGR_BRIDGE), y)
CFLAGS += -DCONFIG_CACHEMGR_BRIDGE
endif

ifeq ($(CONFIG_CACHEMGR_VLAN), y)
CFLAGS += -DCONFIG_CACHEMGR_VLAN
endif

ifeq ($(CONFIG_CACHEMGR_MACVLAN), y)
CFLAGS += -DCONFIG_CACHEMGR_MACVLAN
endif

# Linux 2.6.33
ifeq ($(CONFIG_CACHEMGR_BONDING), y)
CFLAGS += -DCONFIG_CACHEMGR_BONDING
# Linux 3.13 (LACP)
CFLAGS += -DHAVE_IFLA_BOND
# Linux 3.14
CFLAGS += -DHAVE_IFLA_INFO_SLAVE
endif

# Linux 3.7
ifeq ($(CONFIG_CACHEMGR_DIAG), y)
CFLAGS += -DCONFIG_CACHEMGR_DIAG
SRCS += nl_diag.c
endif

ifeq ($(CONFIG_CACHEMGR_EBTABLES), y)
CFLAGS += -DCONFIG_CACHEMGR_EBTABLES
SRCS+= ebtc.c
ifneq ($(CONFIG_CACHEMGR_EBTABLES_UPDATE_TIME),)
CFLAGS += -DCONFIG_CACHEMGR_EBTABLES_UPDATE_TIME=$(CONFIG_CACHEMGR_EBTABLES_UPDATE_TIME)
endif
endif

ifeq ($(CONFIG_CACHEMGR_GRE), y)
CFLAGS += -DCONFIG_CACHEMGR_GRE
endif

ifeq ($(CONFIG_CACHEMGR_NF_RPFILTER), y)
CFLAGS += -DCONFIG_CACHEMGR_NF_RPFILTER
endif

ifeq ($(CONFIG_CACHEMGR_NF_DEV), y)
CFLAGS += -DCONFIG_CACHEMGR_NF_DEV
endif

ifeq ($(CONFIG_CACHEMGR_NF_UID), y)
CFLAGS += -DCONFIG_CACHEMGR_NF_UID
endif
ifeq ($(CONFIG_CACHEMGR_NF_LSN), y)
CFLAGS += -DCONFIG_CACHEMGR_NF_LSN
endif

# For 6WIND patched kernels, where API may be broken, use
# INCKERN to take headers directly from kernel source.
# The caller should turn off unsupported CONFIG_CACHEMGR_xxx
# manually.
ifneq ($(INCKERN),)
CFLAGS+= $(INCKERN)
endif

# Use our local headers
CFLAGS += -I$(S)/include

LDADD+= -levent
LDADD+= -lconsole
LDADD+= -lifuid
LDADD+= -lnl-3 -lnl-route-3 -lnl-genl-3 -lnl-nf-3
LDADD += -ldl

EXTRA_SCRIPT = yes

USE_VRF_NETNS ?= y

ifeq ($(USE_VRF_NETNS),y)
LDADD+= -lvrf
CFLAGS += -DCONFIG_PORTS_CACHEMGR_NETNS
# Last chance to find extern vrf module headers in native mode
ifeq ($(findstring vrf-module, $(CFLAGS) $(EXTRA_CFLAGS)),)
CFLAGS += -I/usr/local/modules/vrf/vrf-module
endif
endif

# Export symbols for plugins
LDFLAGS += -Wl,--export-dynamic

headers := cm_sock_pub.h cm_netlink.h cm_pub.h cm_plugin.h cm_ipsec_pub.h
headers += genl_base.h cm_dump.h fpm.h queue_alloc.h

# For each FOO enum in this list, add -DHAS_FOO to CFLAGS if the enum is declared in if_link.h
IF_LINK_ENUMS = IFLA_AF_SPEC

define has_if_link_enum
HAS_$(1) = $$(shell printf '\#include <stdio.h>\n\#include <sys/socket.h>\n\#include <linux/if_link.h>\nint main() { printf("%%d", $(1)); return 0; }\n' | $(CC) $(CFLAGS) -x c - >/dev/null 2>&1 && echo "y")
ifeq '$$(HAS_$(1))' 'y'
CFLAGS += -DHAS_$(1)
endif
endef
$(foreach var,$(IF_LINK_ENUMS),$(eval $(call has_if_link_enum,$(var))))

OBJS:=$(SRCS:%.c=%.o)

ifeq ($(NOSTRIP), yes)
PROGINSTALL=$(PROG)
else
PROGINSTALL=$(PROG).stripped

$(PROG).stripped: $(PROG)
	$P '  STRIP $(notdir $@)'
	$Q $(STRIP) --strip-all -o $@ $<

endif

$(PROG): $(OBJS)
	$P '  PROG $(notdir $@)'
	$Q $(CC) $(LDFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS) $(LDADD)

# Last chance to find libnl3 headers in native mode
ifeq ($(findstring /libnl3, $(CFLAGS) $(EXTRA_CFLAGS)),)
LIBNL3_CFLAGS := $(shell pkg-config --silence-errors --cflags libnl-3.0)
endif

%.o:%.c
	$P '  CC $(notdir $@)'
	$Q path='$@' && [ -n "$${path##*/*}" ] || mkdir -p "$${path%/*}"
	$Q $(CC) $(CFLAGS) $(CFLAGS_$(@)) $(EXTRA_CFLAGS) $(LIBNL3_CFLAGS) -o $@ -c $<

cmgrd_clean:
	$Q rm -f $(OBJS) $(PROG) $(PROG).stripped

install install-target: $(DESTDIR)/$(bindir)/$(PROG)

$(DESTDIR)/$(bindir)/$(PROG): $(PROGINSTALL)
	$P '  INSTALL $(notdir $@)'
	$Q install -D $< $@

clean: cmgrd_clean

install-devel install: $(addprefix $(DESTDIR)/$(includedir)/, $(headers))

$(DESTDIR)/$(includedir)/%.h: $(S)/%.h
	$P '  INSTALL $(notdir $@)'
	$Q install -D $< $@

.PHONY: all install-headers install-target install-devel install-lib clean lib_clean cmgrd_clean $(SUBDIR)

O? = .
datarootdir ?= $(prefix)/share
docdir ?= $(datarootdir)/doc

doc: doc-default

doc-%: FORCE
	@ $(MAKE) -rR --no-print-directory -C doc \
		DOC_TOOLS=$(abspath $(DOC_TOOLS)) \
		O=$(abspath $O)/doc \
		DESTDIR=$(abspath $(DESTDIR))$(docdir) \
		$*

FORCE:

$(SUBDIR):
		$Q mkdir -p $(O)/$@ && $(MAKE) -C $(O)/$@ \
		-f $(S)/$@/Makefile \
		O=$(O)/$@ \
		PREFIXDIR=$(PREFIXDIR)$@/ \
		M= \
		INSTALL_EXTRA_SCRIPT=$(EXTRA_SCRIPT) \
		S=$(S)/$@ $(filter-out subdirs $(SUBDIR),$(MAKECMDGOALS))
