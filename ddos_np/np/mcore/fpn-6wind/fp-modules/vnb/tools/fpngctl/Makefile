PROG		 = fpngctl

SRCS		 = main.c mkpeer.c config.c connect.c name.c show.c list.c 
SRCS		+= msg.c debug.c shutdown.c rmhook.c status.c types.c
CFLAGS		+= -DNGCTL_NO_WRITECMD -DNGCTL_NO_DUMPCMD
#SRCS		+= write.c
SRCS		+= getstats.c
SRCS		+= dot.c
SRCS		+= bypass.c inspeer.c insnode.c

CFLAGS		+= -DNGCTL_DEFAULTNAME=\"fpn0\"
CFLAGS		+= -D__linux__

CFLAGS		+= -I$(DIST_VNB)/sys
CFLAGS		+= -D_FPNETGRAPH_ -I$(DIST_VNB)/tools/libnetgraph

LDFLAGS		+= -L../libfpnetgraph
LDADD		+= -lfpnetgraph

LDFLAGS		+= -L../../../../libnetfpc
LDADD		+= -lnetfpc

include $(FPNSDK_DIR)/mk/prog.mk

# Source are really in DIST_VNB, which may contain
# in place compilation of same files: don't use VPATH
%.o: $(DIST_VNB)/tools/ngctl/%.c
	$(call cc_rule,$@,$<)
