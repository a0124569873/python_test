Usage
=====

To use Linux synchronization, start the |cmgr| and the |fpm|:

.. code-block:: console

   # modprobe ifuid
   # modprobe fptun
   # fpmd
   # cmgrd

.. rubric:: Example

.. code-block:: console

    # echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
    # ip a a 192.168.1.1/24 dev eth1
    # ip link set up dev eth1
    # ip route add default gateway 192.168.1.254 dev eth1
    # fp-cli

.. code-block:: fp-cli

    <fp-0> dump-user
    # - Preferred, * - Active, > - selected
    0.0.0.0/0  [05]  ROUTE gw 192.168.1.254 via eth1(0x764169c2) (8)

.. code-block:: fp-cli

    <fp-0> dump-interface
    257:eth3 [VR-0] ifuid=0x1e16b22 (port 2) <FWD4|FWD6> (0x60)
              type=ether mac=00:1b:21:c5:7f:76 mtu=1500 tcp4mss=0 tcp6mss=0
              blade=1
              IPv4 routes=0  IPv6 routes=0
    316:eth2 [VR-0] ifuid=0x3c116a72 (port 1) <UP|RUNNING|FWD4|FWD6> (0x63)
              type=ether mac=00:1b:21:c5:7f:75 mtu=1500 tcp4mss=0 tcp6mss=0
              blade=1
              IPv4 routes=0  IPv6 routes=0
    374:eth1 [VR-0] ifuid=0x764169c2 (port 0) <UP|RUNNING|FWD4|FWD6> (0x63)
              type=ether mac=00:1b:21:c5:7f:74 mtu=1500 tcp4mss=0 tcp6mss=0
              blade=1
              IPv4 routes=2  IPv6 routes=0
    432:eth0 [VR-0] ifuid=0xb0716912 (virtual) <FWD4|FWD6> (0x60)
              type=ether mac=00:21:85:c1:82:58 mtu=1500 tcp4mss=0 tcp6mss=0
              blade=1
              IPv4 routes=0  IPv6 routes=0
    455:eth4 [VR-0] ifuid=0xc7b16bd2 (port 3) <FWD4|FWD6> (0x60)
              type=ether mac=00:1b:21:c5:7f:77 mtu=1500 tcp4mss=0 tcp6mss=0
              blade=1
              IPv4 routes=0  IPv6 routes=0
    811:fpn0 [VR-0] ifuid=0x2b43dcc2 (virtual) <UP|RUNNING|FWD4|FWD6> (0x63)
              type=ether mac=00:00:46:50:4e:00 mtu=1500 tcp4mss=0 tcp6mss=0
              blade=1
              IPv4 routes=0  IPv6 routes=0
    824:lo [VR-0] ifuid=0x389b8028 (virtual) <UP|RUNNING|FWD4|FWD6> (0x63)
              type=loop mac=00:00:00:00:00:00 mtu=16436 tcp4mss=0 tcp6mss=0
              blade=1
              IPv4 routes=0  IPv6 routes=0

Neighbors management
--------------------

add-neighbour
~~~~~~~~~~~~~

.. rubric:: Description

Add neighbor info.

.. rubric:: Synopsis

.. code-block:: fp-cli

   add-neighbour ADDR MAC IFNAME

.. rubric:: Parameters

ADDR
   IPv4 address of neighbor.
MAC
   Physical address of neighbor, must match the following format %:%:%:%:%:%
IFNAME
   Name of the interface to which the neighbor is connected.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> add-neighbour 10.22.4.118 00:15:17:34:2a:d8 eth1

.. code-block:: fp-cli

   <fp-0> add-neighbour 10.23.4.204 00:1B:21:CC:0D:97 eth3

delete-neighbour
~~~~~~~~~~~~~~~~

.. rubric:: Description

Delete neighbor info.

.. rubric:: Synopsis

.. code-block:: fp-cli

   delete-neighbour ADDR IFNAME

.. rubric:: Parameters

ADDR
   IPv4 address of neighbor.
IFNAME
   Name of the interface to which the neighbor is connected.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> delete-neighbour 10.22.4.118 eth1

dump-neighbours
~~~~~~~~~~~~~~~

.. rubric:: Description

Dump neighbors table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-neighbours

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-neighbours
   R[000006] GW/NEIGH 10.23.4.204 00:1b:21:cc:0d:97 via eth3_0(0x0a000000) REACHABLE (nh:6)

arp-reply
~~~~~~~~~

.. rubric:: Description

Enable/disable ARP reply. When enabled, the |fp| will answer to ARP request.

.. rubric:: Synopsis

.. code-block:: fp-cli

   arp-reply [on|off]

.. rubric:: Parameters

on|off
   Enable arp reply in |fp|, off by default.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> arp-reply on
   arp reply is on

set-arp-hitflags
~~~~~~~~~~~~~~~~

.. rubric:: Description

Set interface ARP hitflags.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-arp-hitflags PERIOD MAX_SCANNED MAX_SENT

.. rubric:: Parameters

PERIOD
   Validity period of ARP hitflags, in seconds.
MAX_SCANNED
   Maximum number of ARP hitflags per synchronization message with *fpm*.

MAX_SENT

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-arp-hitflags 8 600 800

dump-hitflags
~~~~~~~~~~~~~

.. rubric:: Description

Show ARP/NDP/CT hitflags.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-hitflags [all]

   dump-hitflags [arp|ndp|conntrack]

.. rubric:: Parameters

No parameter
   Dump parameters for all categories.
all
   Same as wit no parameters.
arp
   Dump only arp category.
ndp
   Dump only ndp category.
conntrack
   Dump only conntrack category.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-hitflags
   arp hitflags
     period_in_seconds:8
     max_scanned:600
     max_sent:800

Addresses management
--------------------

add-address4
~~~~~~~~~~~~

.. rubric:: Description

Add an IPv4 address on a given interface.

.. rubric:: Synopsis

.. code-block:: fp-cli

   add-address4 IFNAME ADDR PREFIX

.. rubric:: Parameters

IFNAME
   Name of the interface in human reading form, must be unique.
ADDR
   IPv4 address.
PREFIX
   Netmask length in bits.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> add-address4 eth1 10.22.4.104 24

.. code-block:: fp-cli

   <fp-0> add-address4 eth3 10.23.4.104 24

del-address4
~~~~~~~~~~~~

.. rubric:: Description

Delete an IPv4 address on a given interface.

.. rubric:: Synopsis

.. code-block:: fp-cli

   del-address4 IFNAME ADDR PREFIX

.. rubric:: Parameters

IFNAME
   Name of the interface.
ADDR
   IPv4 address
PREFIX
   Netmask length in bits.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> del-address4 eth1 10.22.4.104 24

.. code-block:: fp-cli

   <fp-0> del-address4 eth3 10.23.4.104 24

Routes management
-----------------

add-route
~~~~~~~~~

.. rubric:: Description

Add a new route.

.. rubric:: Synopsis

.. code-block:: fp-cli

   add-route ADDR PREFIX GATEWAY IFNAME [TYPE]

.. rubric:: Parameters

ADDR
   IPv4 address.
PREFIX
   Netmask length in bits.
GATEWAY
   Ip address of gateway.
IFNAME
   Name of the interface in human reading form, must be unique.
TYPE
   Decimal value of route type (route:0, exception:240, neigh:1, connected:2,
   address:240, local:241, blackhole:242).

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> add-route 0.0.0.0 0 10.23.4.204 eth3

delete-route
~~~~~~~~~~~~

.. rubric:: Description

Delete a route.

.. rubric:: Synopsis

.. code-block:: fp-cli

   delete-route ADDR PREFIX GATEWAY IFNAME

.. rubric:: Parameters

ADDR
   IPv4 address.
PREFIX
   Netmask length in bits.
GATEWAY
   Ip address of gateway.
IFNAME
   Name of the interface in human reading form, must be unique.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> delete-route 0.0.0.0 0 10.23.4.204 eth3

dump-rt
~~~~~~~

.. rubric:: Description

Dump the *rt_entry* table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-rt [RTINDEX]

.. rubric:: Parameters

No parameter
   Dump whole *rt_entry* table.
RTINDEX
   Index to dump specifically in *rt_table*.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-rt
   R[000001] GW/ADDRESS 0.0.0.0 00:00:00:00:00:00 via eth1(0x08000000) NONE (nh:1)
   R[000002] IFACE/CONNECTED src 10.22.4.104 via eth1(0x08000000) (nh:2)
   R[000003] GW/ADDRESS 0.0.0.0 00:00:00:00:00:00 via eth3(0x09000000) NONE (nh:3)
   R[000004] IFACE/CONNECTED src 10.23.4.104 via eth3(0x09000000) (nh:4)
   R[000005] GW/NEIGH 10.23.4.204 00:1b:21:cc:0d:97 via eth3(0x09000000) REACHABLE (nh:5)
   R[000006] GW/NEIGH 10.22.4.118 00:15:17:34:2a:d8 via eth1(0x08000000) REACHABLE (nh:6)
   R[000007] GW/NEIGH 10.23.4.204 00:1b:21:cc:0d:97 via eth3(0x09000000) REACHABLE (nh:5)

dump-nh
~~~~~~~

.. rubric:: Description

Dump the Next-Hop table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-nh [NHINDEX]

.. rubric:: Parameters

No parameter
   Dump whole next hop table.
NHINDEX
   Index to dump specifically in next hop table.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-nh
   N4[0001]GW/ADDRESS 0.0.0.0 00:00:00:00:00:00 via eth1(0x08000000) NONE refcnt=1
   N4[0002]IFACE/CONNECTED src 10.22.4.104 via eth1(0x08000000) refcnt=1
   N4[0003]GW/ADDRESS 0.0.0.0 00:00:00:00:00:00 via eth3(0x09000000) NONE refcnt=1
   N4[0004]IFACE/CONNECTED src 10.23.4.104 via eth3(0x09000000) refcnt=1
   N4[0005]GW/NEIGH 10.23.4.204 00:1b:21:cc:0d:97 via eth3(0x09000000) REACHABLE refcnt=2
   N4[0006]GW/NEIGH 10.22.4.118 00:15:17:34:2a:d8 via eth1(0x08000000) REACHABLE refcnt=1

dump-user
~~~~~~~~~

.. rubric:: Description

Dump the user routing entries (default type ROUTE=1).

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-user [all|fpm|local|neigh|connected|black]

.. rubric:: Parameters

No parameter
   Display only routes configured by user.
all
   Display all kind of routes.
fpm
   Display routes configured via *fpm*.
local
   Display local routes, ones to hosts on directly connected networks.
neigh
   Display routes to neighbor hosts.
connected
   Display routes to connected hosts.
black
   Display black hole routes.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-user
   # - Preferred, * - Active, > - selected
   0.0.0.0/0  [05]  ROUTE gw 10.23.4.204 via eth3(0x08000000) (7)

.. code-block:: fp-cli

   <fp-0> dump-user fpm

.. code-block:: fp-cli

   <fp-0> dump-user local

.. code-block:: fp-cli

   <fp-0> dump-user neigh

.. code-block:: fp-cli

   <fp-0> dump-user connected

.. code-block:: fp-cli

   <fp-0> dump-user black

.. code-block:: fp-cli

   <fp-0> dump-user all
   0.0.0.0/0  [05]  NEIGH gw 10.23.4.204 via eth3(0x09000000) (7)
   10.22.4.104/24  [02]  CONNECTED via eth1(0x08000000) (2)
   10.22.4.104/32  [01]  ADDRESS via eth1(0x08000000) (1)
   10.22.4.118/32  [06]  NEIGH gw 10.22.4.118 (N) via eth1(0x08000000) (6)
   10.23.4.104/24  [04]  CONNECTED via eth3(0x09000000) (4)
   10.23.4.104/32  [03]  ADDRESS via eth3(0x09000000) (3)
   10.23.4.204/32  [05]  NEIGH gw 10.23.4.204 (N) via eth3(0x09000000) (5)

dump-routes
~~~~~~~~~~~

.. rubric:: Description

Dump |fp| internal routing table (default all and very verbose).

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-routes [all|fpm|local|neigh|connected|black]

.. rubric:: Parameters

No parameter
   Display only routes configured by user.
all
   Display all kind routes.
fpm
   Display routes configured via *fpm*.
local
   Display local routes, ones to hosts on directly connected networks.
neigh
   Display routes to neighbor hosts.
connected
   Display routes to connected hosts.
black
   Display black hole routes.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-routes
   E[0.0.0.1] 0.0.0.0/0  [05]  ROUTE gw 10.23.4.204 via eth3(0x09000000) /0 (7)
   E[0.0.0.2] 0.0.0.0/0  [05]  ROUTE gw 10.23.4.204 via eth3(0x09000000) /0 (7)
   E[0.0.0.3] 0.0.0.0/0  [05]  ROUTE gw 10.23.4.204 via eth3(0x09000000) /0 (7)
   ...

show-route
~~~~~~~~~~

.. rubric:: Description

Search for the route to a destination.

.. rubric:: Synopsis

.. code-block:: fp-cli

   show-route DADDR [SADDR]

.. rubric:: Parameters

DADDR
   Destination IPv4 address.
SADDR
   Display selected route according to a specific source IPv4 address.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> show-route 10.24.4.119
   Prio: ADDR=128, PREF=32, NEIGH=8, CNX=2
   0.0.0.0/0  Single Entry /0 (7)
   Preferred: 1 (prio 1)   Total: 1
     [05]  #    (p=001)  NEIGH gw 10.23.4.204 via eth3(0x09000000)

show-filling
~~~~~~~~~~~~

.. rubric:: Description

Show the filling of each table in memory.

.. rubric:: Synopsis

.. code-block:: fp-cli

   show-filling

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> show-filling
   Tables filling:
   fp_8_table: 37/11000 (0.336364%) IPv4:10 IPv6:27
   fp_16_table: 18/40 (45.000000%)
    IPv4:8 IPv6:10
   fp_8_entries: 9472/2816000 (0.336364%)
   fp_16_entries: 262144/2621440 (10.000000%)
   fp_rt4_table: 11/50001 (0.022000%)
   fp_rt6_table: 8/50001 (0.016000%)
   fp_nh4_table: 7/5001 (0.139972%)
   fp_nh6_table: 5/5001 (0.099980%)

get-route
~~~~~~~~~

.. rubric:: Description

Search for exact route to a prefix.

.. rubric:: Synopsis

.. code-block:: fp-cli

   get-route DADDR PREFIX

.. rubric:: Parameters

DADDR
   Destination IPv4 address.
PREFIX
   Netmask length in bits.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> get-route 10.24.4.119 0
   0.0.0.0/0  [05]  NEIGH gw 10.23.4.204 via eth3(0x09000000) /0 (7)

get-src-address
~~~~~~~~~~~~~~~

.. rubric:: Description

Search for source address to a given destination.

.. rubric:: Synopsis

.. code-block:: fp-cli

   get-src-address DADDR

.. rubric:: Parameters

DADDR
   Destination IPv4 address.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> get-src-address 10.24.4.119
   looking up for 10.24.4.119 vrfid 0
   found NEIGH route to 0.0.0.0/0
          gateway 10.23.4.204
          looking up for 10.23.4.204 vrfid 0
   found NEIGH route to 10.23.4.204/32
          gateway 10.23.4.204
   found CONNECTED route to 10.23.4.0/24
          src 10.23.4.104 on eth2(0x426041d0)
   => returning 10.23.4.104

set-ifdown
~~~~~~~~~~

.. rubric:: Description

Clean any IPv4 route using this interface.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-ifdown IFNAME

.. rubric:: Parameters

IFNAME
   Name of the interface.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-ifdown 8

.. code-block:: fp-cli

   <fp-0> dump-user all
   # - Preferred, * - Active, > - selected
   10.22.4.104/32  [01]  ADDRESS via eth1(0x08000000) (1)
   10.23.4.104/32  [03]  ADDRESS via eth3(0x09000000) (3)

set-pref
~~~~~~~~

.. rubric:: Description

Set interface preference, when routing ECMP, give higher priority when selecting
next hop for this interface.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-pref IFNAME on|off

.. rubric:: Parameters

IFNAME
   Name of the interface.
on|off
   Enable or not preference flag on interface.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-pref eth1 on

VRF support
-----------

The default VR to which all commands apply is displayed in the fp-cli prompt:
<fp-X> indicates that commands apply to |vrf| X.

To change the default |vrf|, use the *vrf* command.

vrf
~~~

.. rubric:: Description

Change default |vrf| value.

.. rubric:: Synopsis

.. code-block:: fp-cli

   vrf <value>

.. rubric:: Parameters

value
   |vrf| id

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> add-route 100.0.0.0 16 192.168.0.1 eth0_0

.. code-block:: fp-cli

   <fp-0> dump-route
   E[100.0] 100.0.0.0/16  [01]  ROUTE gw 192.168.0.1 via eth0_0(0x43bf9b70) /16 (5)

.. code-block:: fp-cli

   <fp-0> vrf 1
    New reference for VRF: 1

.. code-block:: fp-cli

   <fp-1> dump-route

.. code-block:: fp-cli

   <fp-1> vrf 0
    New reference for VRF: 0

.. code-block:: fp-cli

   <fp-0> dump-route
   E[100.0] 100.0.0.0/16  [01]  ROUTE gw 192.168.0.1 via eth0_0(0x43bf9b70) /16 (5)

RPF check
---------

To enable or disable  |rpfilter| check per interface,
use the *rpf-ipv4* command.

rpf-ipv4
~~~~~~~~

.. rubric:: Description

.. rubric:: Synopsis

.. code-block:: fp-cli

   rpf-ipv4 <interface> [on|off]

.. rubric:: Parameters

interface
   Name of the interface.
on|off
   Enable/disable the RPF on this interface (optional). If this
   argument is omitted, only the status of the RPF check is displayed.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> rpf-ipv4 eth3 on
   eth3: IPv4 RPF is on

.. code-block:: fp-cli

   <fp-0> dump-interfaces
   9:eth3 [VR-0] ifuid=0x9000000 (port 2) <UP|RUNNING|FWD4|FWD6|RPF4> (0x463)
           type=ether mac=00:1b:21:c5:7f:76 mtu=1500 tcp4mss=0 tcp6mss=0
           IPv4 routes=0  IPv6 routes=0

.. code-block:: fp-cli

   <fp-0> rpf-ipv4 eth3
   eth3: IPv4 RPF is on

Internal VRRP
-------------

To enable or disable |ivrrp| state per interface,
use the *set-ivvrp* command.

set-ivrrp
~~~~~~~~~

.. rubric:: Description

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-ivrrp <interface> [on|off]

.. rubric:: Parameters

interface
   Name of the interface.
on|off
   Enable/disable the IVRRP status on this interface (optional). If this
   argument is omitted, only the IVRRP status is displayed.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-ivrrp eth3 on
   eth3: IVRRP is on

.. code-block:: fp-cli

   <fp-0> dump-interfaces
   9:eth3 [VR-0] ifuid=0x9000000 (port 2) <UP|RUNNING|FWD4|FWD6|IVRRP> (0x463)
           type=ether mac=00:1b:21:c5:7f:76 mtu=1500 tcp4mss=0 tcp6mss=0
           IPv4 routes=0  IPv6 routes=0

.. code-block:: fp-cli

   <fp-0> set-ivrrp eth3
   eth3: IVRRP is on

TCP MSS clamping
----------------

TCP MSS (Maximum Segment Size) clamping can be configured by interface.

set-tcpmss
~~~~~~~~~~

.. rubric:: Description

Change default value of MSS. 0 means no change is made in packet.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-tcpmss <interface> <value>

.. rubric:: Parameters

IFNAME
   Name of the interface.
value
   MSS, default is 0 (disabled).

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-tcpmss eth0 1400

Statistics
----------

dump-ip-stats
~~~~~~~~~~~~~

.. rubric:: Description

Dumps IPv4 statistics.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-ip-stats [percore] [non-zero]

.. rubric:: Parameters

.. include:: include/percore-non-zero.inc

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-ip-stats
    IpForwDatagrams:682
    IpInReceives:682
    IpInDelivers:447
    IpInHdrErrors:0
    IpInAddrErrors:0
    IpDroppedNoArp:0
    IpDroppedNoMemory:0
    IpDroppedForwarding:0
    IpDroppedIPsec:0
    IpDroppedBlackhole:0
    IpDroppedInvalidInterface:0
    IpDroppedNetfilter:0
    IpDroppedNoRouteLocal:0
    IpReasmTimeout:0
    IpReasmReqds:0
    IpReasmOKs:0
    IpReasmFails:0
    IpReasmExceptions:0
    IpFragOKs:0
    IpFragFails:0
    IpFragCreates:0

dump-arp-stats (MCORE_ARP_REPLY)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Dump ARP statistics. When *MCORE_ARP_REPLY*, the |fp| counts the number.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-arp-stats [percore] [non-zero]

.. rubric:: Parameters

.. include:: include/percore-non-zero.inc

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-arp-stats
    arp_errors:0
    arp_unhandled:0
    arp_not_found:0
    arp_replied:0
