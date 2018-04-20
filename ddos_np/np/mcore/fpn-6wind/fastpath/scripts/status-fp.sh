#! /bin/sh

# Show fast path status

if ! which fpcmd >/dev/null 2>&1 ; then
	echo 'fast path not available'
	exit 0
fi

echo '####### FP daemons'
ps -Af | grep 'fpmd\|fpsd\|cmgr' | grep -v '\<grep\>'
echo
echo '####### FP CPU usage'
fpcmd dump-cpu-usage

echo
echo '####### FP ports'
fpcmd dump-ports
echo
echo '####### FP interfaces'
fpcmd dump-interfaces

if fpcmd dump-config | grep -q CONFIG_MCORE_IP=y ; then
	echo
	echo '####### FP routes'
	fpcmd dump-user all
fi

if fpcmd dump-config | grep -q CONFIG_MCORE_IPSEC=y ; then
	echo
	echo '####### FP IPsec SA'
	fpcmd dump-sad all
	echo
	echo '####### FP IPsec SP'
	fpcmd dump-spd all
fi

if fpcmd dump-config | grep -q CONFIG_MCORE_VNB=y ; then
	echo
	echo '####### FP VNB nodes'
	if which fpngctl >/dev/null 2>&1 ; then
		fpngctl list
	else
		echo 'VNB not available'
	fi
fi

echo
echo '####### FP statistics'
fpcmd dump-stats non-zero
echo
echo '####### FP ports statistics'
for dev in $(fpcmd dump-interfaces | sed -n 's,^[0-9]*:\([^ ]*\).*(port .*,\1,p') ; do
	echo $dev
	# keep only packets and non zero numbers
	ethtool -S $dev | sed -n '/packets:\|: 0.\|: [1-9]/p'
done
