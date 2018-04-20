#! /bin/sh

# Show global status
# for debugging or bug reporting

if [ $(id -u) -ne 0 ] ; then
	echo "ERROR: must be root" >&2
	exit 1
fi

SELF_DIR=$(dirname $(readlink -e $0))

# system
$SELF_DIR/status-sys.sh
echo
# control plane
$SELF_DIR/status-cp.sh
echo
# fast path
$SELF_DIR/status-fp-arch.sh
$SELF_DIR/status-fp.sh
