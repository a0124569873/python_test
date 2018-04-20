#! /bin/sh

# Show fast path status

if ! ps -A | grep -q fp-rte ; then
	echo 'fast path is not running'
	exit 0
fi

echo '####### FP daemons'
ps -Af | grep 'fp-rte' | grep -v '\<grep\>'
echo
