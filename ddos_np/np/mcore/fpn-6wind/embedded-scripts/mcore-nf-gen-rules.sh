#!/bin/bash

FPNFRULES="/var/tmp/shells/fp-nf-rules"

function fp_nf_rules_add_iface()
{
	local IFACE=$1

	touch $FPNFRULES
	if ! grep -q "\<$IFACE\>" $FPNFRULES; then
		echo "iptables -I INPUT -i $IFACE -j ACCEPT" >> $FPNFRULES
		echo "iptables -I OUTPUT -o $IFACE -j ACCEPT" >> $FPNFRULES
		echo "ip6tables -I INPUT -i $IFACE -j ACCEPT" >> $FPNFRULES
		echo "ip6tables -I OUTPUT -o $IFACE -j ACCEPT" >> $FPNFRULES
	fi
}
