# By Fanxiushu 2013 01-11
#

obj-m += vwk.o
vwk-objs = vnetwk.o trans.o

KERNEL_DIR=/lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)

all:
    make -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules
clean:
    -rm *.mod.c *.ko *.o