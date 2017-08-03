#!/bin/bash
set -x
rmmod net_filter.ko
make clean
make
insmod net_filter.ko
dmesg -w
#end
