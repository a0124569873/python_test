#########################################################################
# beginning of overwrite part -> depend on each application
#########################################################################

VPATH = $(DIST_HIGHAVAILABILITY)/hao-routed

PROG = hao-routed
SRCS = haorouted_protocol.c haorouted_zebra.c haorouted_main.c

LIST = $(PROG)

# A clean code should always be compiled with Wall
CFLAGS += -Wall -Werror
CFLAGS += -g
CFLAGS += -DHAVE_IPV6
CFLAGS += -DQUAGGA_NO_DEPRECATED_INTERFACES
CFLAGS += -I$(VPATH)
PORT_INCLUDES += -I$(DIST_LIBRIB)/lib
PORT_INCLUDES += -I$(DIST_LIBRIB)/ribzclient/lib
LDFLAGS += -L$(ROOTDIR)/ports/librib
LDFLAGS += -L$(ROOTDIR)/ports/net-snmp/libnetsnmp
LDADD += -lrib
LDADD += -lm -lcrypt
LDADD += -lcrypto
LDADD += -lnetsnmp

# libevent
CFLAGS	+= -I$(DIST_LIBEVENT)
LDFLAGS	+= -L$(ROOTDIR)/ports/libevent
LDADD	+= -levent

# libhao
CFLAGS  += -I$(DIST_HIGHAVAILABILITY)/libhao
LDFLAGS	+= -L$(ROOTDIR)/ports/mblade/libhao
LDADD   += -lhao

# libconsole
CFLAGS  += -I${DIST_LIBCONSOLE}
LDADD   += -L$(ROOTDIR)/lib/libconsole/libconsole
LDADD   += -lconsole

# libstream
CFLAGS  += -I${DIST_LIBSTREAM}
LDADD   += -L$(ROOTDIR)/ports/libstream
LDADD   += -lstream

# high availability
ifeq ($(CONFIG_HA6W_SUPPORT), y)
CFLAGS   += -DHA_SUPPORT -I$(DIST_HIGHAVAILABILITY)/lib6whas 
LDFLAGS  += -L$(ROOTDIR)/ports/lib6whas 
LDADD    += -l6whas
LDFLAGS  += -L$(ROOTDIR)/lib/libxml2
LDFLAGS  += -L$(ROOTDIR)/lib/libxt
LDADD    += -lxt -lxml2 -lm
endif
#########################################################################
# end of overwrite part -> depend on each application
#########################################################################

