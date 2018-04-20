VPATH= $(S)

LIB = libfpnetgraph.a

SHARED_LIB=no

SRCS = sock.c msg.c debug.c

CFLAGS += -D__linux__
CFLAGS += -I$(DIST_VNB)/sys
CFLAGS += -D_FPNETGRAPH_ -I$(DIST_VNB)/tools/libnetgraph

CFLAGS+= -I$(S)/../../dataplane
CFLAGS+= -I$(S)/../../../../libnetfpc

include $(FPNSDK_DIR)/mk/lib.mk
