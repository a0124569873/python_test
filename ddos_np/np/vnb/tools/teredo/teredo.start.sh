#!/bin/sh
# Copyright 2003-2006 6WIND S.A.

# This script sets up a Teredo Server and a Teredo Relay
#

# 2, 4 or 6 args are required
if [ "$#" != "2" -a "$#" != "4" -a "$#" != "6" ] ; then
  echo "$0 primary A.B.C.D secondary A.B.C.D verbose 0x00|0x01|0x02|0x03"
  exit 1
fi

SERVICE_IP=""
SERVICE_IP_SECONDARY=""
VERBOSE="0x00"
# Define a static global IPv6 address used to send the bubbles,
# or let the script looking for an address.
#SERVER_IP6="2001:660:3008:1970::2"
SERVER_IP6="auto"

while [ "$#" != "0" ] ; do
  case $1 in
    primary)
      shift
      SERVICE_IP="$1"
      shift
      ;;

    secondary)
      shift
      SERVICE_IP_SECONDARY="$1"
      shift
      ;;

    verbose)
      shift
      VERBOSE="$1"
      shift
      ;;

    *)
      echo "$0 primary A.B.C.D secondary A.B.C.D verbose 0x00|0x01|0x02|0x03"
      ;;
  esac
done

if [ "$SERVICE_IP" = "" ] ; then
  echo "Warning Teredo: secondary address will be used as a primary one"
  SERVICE_IP="$SERVICE_IP_SECONDARY"
  SERVICE_IP_SECONDARY=""
fi

# You should never change this value, otherwise update
# ng_teredo.h
#
SERVER_UDP_PORT=3544

# Create the interface node ``IFACE_TEREDO'' if it doesn't exist
# already, otherwise just make sure it's not connected to anything.
#
IFACE_TEREDO="teredo0"
if ifconfig ${IFACE_TEREDO} >/dev/null 2>&1; then
	ifconfig ${IFACE_TEREDO} inet6 down delete >/dev/null 2>&1
	ngctl shutdown ${IFACE_TEREDO}:
fi
ngctl mkpeer iface_teredo dummy inet6

# Attach the Teredo node socket to the ``inet6'' hook of the
# interface node using the ng_iface(4) node type.
#
NAME="Nteredo0"
ngctl shutdown ${NAME}: > /dev/null 2>&1
ngctl mkpeer ${IFACE_TEREDO}: teredo inet6 upstream
ngctl name ${IFACE_TEREDO}:inet6 ${NAME}

# Set verbosity
#
ngctl msg ${NAME}: setverbose ${VERBOSE}

# Set the address of the server
#
ngctl msg ${NAME}: setservaddr ${SERVICE_IP}

# XXX Set the origin address of the Relay
#
ngctl msg ${NAME}: setorigin ${SERVICE_IP}

# Set the IPv6 address
#
if [ "$SERVER_IP6" = "auto" ] ; then
  SERVER_IP6="`ifconfig -a | grep  inet6 | awk '{ print $2 }' | grep -v fe80 | grep -v fec0 | grep -v "^::1" | head -1`"
  if [ "$SERVER_IP6" = "" ] ; then
    echo "Error: global IPv6 address not found. Please define one" >&2
    exit 1
  fi
  echo "Using $SERVER_IP6 to source the bubbles"
else
  # Check if this static address is already set on an interface.
  # If not, configure it on our Teredo interface.
  TEST="`ifconfig -a | grep "$SERVER_IP6"`"
  if [ "${TEST}" = "" ] ; then
    ifconfig ${IFACE_TEREDO} inet6 ${SERVER_IP6}/128
  fi
fi
ngctl msg ${NAME}: setglobal "$SERVER_IP6"

# Wakeup the Teredo interface
#
ifconfig ${IFACE_TEREDO} up

# XXX Set the linklocal address of the Teredo interface
#
LLIF=`ifconfig ${IFACE_TEREDO} inet6 2> /dev/null | grep fe80 | head -1 | awk '{ print $2}' | cut -d "%" -f 1`
if [ "${LLIF}" = "" ] ; then
  echo "Warning: ${IFACE_TEREDO} does not have a linklocal address"
  LLIF="fe80::cafe:deca:1"
  ifconfig ${IFACE_TEREDO} inet6 ${LLIF}
fi
ngctl msg ${NAME}: setlinklocal ${LLIF}

# Attach a UDP socket to the ``downstream'' hook of the Teredo
# node using the ng_ksocket(4) node type.
#
ngctl mkpeer ${NAME}: ksocket downstream inet/dgram/udp

# Bind the UDP socket to the local server IPv4 address
#
ngctl msg ${NAME}:downstream bind inet/${SERVICE_IP}:${SERVER_UDP_PORT}

if [ "$SERVICE_IP_SECONDARY" != "" ] ; then
  # Attach a UDP socket to the ``secondary'' hook of the Teredo
  # node using the ng_ksocket(4) node type.
  # This UDP hook is required in order to help the client to detect
  # a cone NAT with this Teredo node.
  #
  ngctl mkpeer ${NAME}: ksocket secondary inet/dgram/udp

  # Bind the UDP socket to the local server IPv4 address
  #
  ngctl msg ${NAME}:secondary bind inet/${SERVICE_IP_SECONDARY}:${SERVER_UDP_PORT}
fi

# Add the IPv6 Teredo route
#
route add -inet6 3ffe:831f:: -prefixlen 32 -iface ${IFACE_TEREDO}
