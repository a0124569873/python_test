#!/bin/sh

# This script is executed on new VRF creation.
# It runs in the context of the newly created VRF.

# It is the placeholder for any operation needed by
# linux / fast path synchronization.

if lsmod | grep "^nf_fptun\>" 1>&2 2>/dev/null; then
	# iptables's libxtables looks at path XTABLES_LIBDIR for loadable extensions
	echo "Activating IPSec policy matching in ip[6]tables"
	iptables -t fptun -A POSTROUTING -m policy --dir out --pol ipsec -j IPSECOUT
	ip6tables -t fptun -A POSTROUTING -m policy --dir out --pol ipsec -j IPSECOUT
fi
