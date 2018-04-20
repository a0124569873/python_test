#! /bin/sh

# Check fast path configuration

# fast path mem must be large enough for mbuf count
# XXX should be checked in fast path
check_fpmem () # <memory size MB> <mbuf count>
{
	[ $# -ge 2 ] || return 0
	mbuf_size=2624 # default size
	allocated=$(($1 * 1048576))
	needed=$(($mbuf_size * $2))
	if [ $allocated -lt $needed ] ; then
		echo "WARNING: not enough space ($1 MB) to allocate $2 mbufs" >&2
		return 1
	fi
}
