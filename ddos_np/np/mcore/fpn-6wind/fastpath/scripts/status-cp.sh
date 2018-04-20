#! /bin/sh

# Show control plane status

echo '####### Linux interfaces'
ip address show
echo
echo '####### Linux IP routes'
ip route show

echo
echo '####### Linux IPsec SA'
ip xfrm state
echo
echo '####### Linux IPsec SP'
ip xfrm policy

echo
echo '####### Linux VNB nodes'
if which ngctl >/dev/null 2>&1 ; then
	ngctl list
fi
