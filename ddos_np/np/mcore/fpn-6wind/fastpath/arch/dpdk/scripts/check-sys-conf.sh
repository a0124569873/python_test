#! /bin/sh

# Check system for fast path initialization

convert () # < <number> [unit]
{
	tr -d ' ' |
	sed 's,B,,g' |
	sed -r 's,([0-9]+)(.*)b,\1*8\2,g' |
	tr '[a-z]' '[A-Z]' |
	sed -r 's,([0-9]+)T,\1*1024G,g' |
	sed -r 's,([0-9]+)G,\1*1024M,g' |
	sed -r 's,([0-9]+)M,\1*1024K,g' |
	sed -r 's,([0-9]+)K,\1*1024,g' |
	bc
}

# check if enough hugepages are free
check_hugepages () # <hugepages number> [needed size MB]
{
	[ $# -ge 1 ] || return 0
	freepages=$(sed -rn 's,HugePages_Free: *,,p' /proc/meminfo)
	if [ "$freepages" -eq 0 ] ; then
		echo "WARNING: no free hugepage" >&2
		return 1
	elif [ "$freepages" -lt "$1" ] ; then
		echo "WARNING: only $freepages free hugepages" >&2
		return 2
	fi
	[ $# -ge 2 ] || return 0
	freesize=$(count_freehuge)
	needed=$(echo "$2 MB" | convert)
	if [ "$freesize" -lt "$needed" ] ; then
		echo "WARNING: only $((freesize / 1048576))MB in free hugepages" >&2
		return 3
	fi
}
count_freehuge ()
{
	sed -rn 's,(HugePages_Free|Hugepagesize): *,,p' /proc/meminfo |
	tr '\n' '*' | sed 's,\*$,\n,' |
	convert
}

# check if IPv6 is enabled for loopback (required by netfpc)
check_lo_ipv6 ()
{
	if [ $(cat /proc/sys/net/ipv6/conf/lo/disable_ipv6) -ne 0 ] ; then
		echo "WARNING: netfpc cannot use IPv6" >&2
		return 1
	fi
}
