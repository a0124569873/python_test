# get environment variables
include $(ROOTDIR)/mk/6windgatelinux.own.mk

#########################################################################
# beginning of overwrite part -> depend on each application
#########################################################################

LIB		 = libnetgraph.so

VPATH		 = ${DIST_VNB}/tools/libnetgraph

SRCS		 = sock.c msg.c debug.c

# just to get pcap-bpf.h ..
CFLAGS		+= $(INCPCAP)

CFLAGS		+= -D__linux__

CFLAGS		+= ${INCVNB}

ifneq (${INCKERN},)
CFLAGS+= ${INCKERN}
endif

SHARED_LIB	 = yes


HEADERS=netgraph.h

#########################################################################
# end of overwrite part -> depend on each application
#########################################################################

include $(ROOTDIR)/mk/6windgatelinux.lib.mk
