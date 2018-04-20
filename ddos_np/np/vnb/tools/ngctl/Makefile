# Copyright 2014 6WIND S.A.

PROG	 = ngctl

SRCS	 = main.c mkpeer.c config.c connect.c name.c show.c list.c
SRCS	+= msg.c debug.c shutdown.c rmhook.c status.c types.c
SRCS	+= write.c dump.c
SRCS	+= getstats.c
SRCS	+= dot.c
SRCS	+= inspeer.c insnode.c bypass.c

CFLAGS	+= -D__linux__

include $(TOP_S)/tools/ngtool.mk
