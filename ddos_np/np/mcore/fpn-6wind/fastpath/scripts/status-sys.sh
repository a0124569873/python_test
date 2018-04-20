#! /bin/sh

# Show system status

SELF_DIR=$(dirname $(readlink -e $0))

echo '####### boot command'
cat /proc/cmdline
echo
echo '####### boot log'
dmesg
echo
echo '####### CPU cores'
python $SELF_DIR/cpuinfo.py </proc/cpuinfo
echo
echo '####### CPU flags'
sed -rn '0,/^flags.*: (.*)/s,,\1,p' /proc/cpuinfo
echo
echo '####### PCI devices'
lspci | grep Ethernet
echo
echo '####### memory'
cat /proc/meminfo
echo
echo '####### kernel modules'
lsmod
echo
echo '####### processes'
ps -Af
