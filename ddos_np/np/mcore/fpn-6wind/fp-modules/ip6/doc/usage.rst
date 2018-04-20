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

    # echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    # ip ad ad 3ffe:2:10::1/64 dev eth1
    # ip link set up dev eth1
    # ip route add 3ffe:100:2:2::1/128 via 3ffe:2:10::5
    # ip -6 route show dev eth1
    3ffe:2:10::/64  proto kernel  metric 256
    3ffe:100:2:2::1 via 3ffe:2:10::5  metric 1024
    fe80::/64  proto kernel  metric 256
    # fp-cli

.. code-block:: fp-cli

    <fp-0> dump-user6
    # - Preferred, * - Active, > - selected
    3ffe:100:2:2::1/128  [03]  ROUTE gw 3ffe:2:10::5 via eth1(0xa148b070) (6)

    <fp-0> dump-address6 eth1
    number of ip address: 1
    3ffe:0002:0010:0000:0000:0000:0000:0001 [0]

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
              IPv4 routes=0  IPv6 routes=2
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
   IPv6 address of neighbor.
MAC
   Physical address of neighbor, must match the following format *%:%:%:%:%:%*
IFNAME
   Name of the interface to which the neighbor is connected.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> add-neighbour 3ffe:2:10::6 00:15:17:34:2a:d8 eth1

delete-neighbour
~~~~~~~~~~~~~~~~

.. rubric:: Description

Delete neighbor info.

.. rubric:: Synopsis

.. code-block:: fp-cli

   delete-neighbour ADDR IFNAME

.. rubric:: Parameters

ADDR
   IPv6 address of neighbor.
IFNAME
   Name of the interface to which the neighbor is connected.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> delete-neighbour 3ffe:2:10::6 eth1

dump-neighbours6
~~~~~~~~~~~~~~~~

.. rubric:: Description

Dump the neighbors table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-neighbours6

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-neighbours6
   R[000006] GW/NEIGH 3ffe:2:10::6 00:1b:21:cc:0d:97 via eth1(0x0a000000) REACHABLE (nh:6)

set-ndp-hitflags
~~~~~~~~~~~~~~~~

.. rubric:: Description

Set interface NDP hitflags.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-ndp-hitflags PERIOD MAX_SCANNED MAX_SENT

.. rubric:: Parameters

PERIOD
   Validity period of NDP hitflags, in seconds.
MAX_SCANNED
   Maximum number of NDP hitflags per synchronization message with *fpm*.

MAX_SENT
   Maximum number of NDP hitflags to send.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-ndp-hitflags 8 600 800

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
   Same as with no parameters.
arp
   Dump only the arp category.
ndp
   Dump only the ndp category.
conntrack
   Dump only the conntrack category.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-hitflags ndp
   ndp hitflags
     period_in_seconds:1
     max_scanned:2500
     max_sent:1600

Addresses management
--------------------

add-address6
~~~~~~~~~~~~

.. rubric:: Description

Add an IPv6 address on a given interface.

.. rubric:: Synopsis

.. code-block:: fp-cli

   add-address6 IFNAME ADDR PREFIX

.. rubric:: Parameters

IFNAME
   Name of the interface in human reading form, must be unique.
ADDR
   IPv6 address.
PREFIX
   Netmask length in bits.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> add-address6 eth1 3ffe:2:10::8 64

del-address6
~~~~~~~~~~~~

.. rubric:: Description

Delete an IPv6 address on a given interface.

.. rubric:: Synopsis

.. code-block:: fp-cli

   del-address6 IFNAME ADDR PREFIX

.. rubric:: Parameters

IFNAME
   Name of the interface.
ADDR
   IPv6 address
PREFIX
   Netmask length in bits.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> del-address6 eth1 3ffe:2:10::9 64

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
   IPv6 address.
PREFIX
   Netmask length in bits.
GATEWAY
   IPv6 address of gateway.
IFNAME
   Name of the interface in human reading form, must be unique.
TYPE
   Decimal value of route type (route:0, exception:240, neigh:1, connected:2, address:240, local:241, blackhole:242).

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> add-route 3ffe:2:20:: 48 fe80::1 eth1

delete-route
~~~~~~~~~~~~

.. rubric:: Description

Delete a route.

.. rubric:: Synopsis

.. code-block:: fp-cli

   delete-route ADDR PREFIX GATEWAY IFNAME

.. rubric:: Parameters

ADDR
   IPv6 address.
PREFIX
   Netmask length in bits.
GATEWAY
   IPv6 address of gateway.
IFNAME
   Name of the interface in human reading form, must be unique.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> delete-route 4ffe:2:20:: 48 fe80::3 eth3

dump-rt6
~~~~~~~~

.. rubric:: Description

Dump the *rt_entry* table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-rt6 [RTINDEX]

.. rubric:: Parameters

No parameter
   Dump the whole *rt_entry* table.
RTINDEX
   Index to dump specifically in *rt_table*.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-rt6
   R6[000001]IFACE/LOCAL via (0x00000000) (nh:5001)
   R6[000002]IFACE/LOCAL via (0x00000000) (nh:5001)
   R6[000003]IFACE/BLACKHOLE via (0x00000000) (nh:5002)
   R6[000004]IFACE/CONNECTED via eth1(0xa148b070) (nh:1)
   R6[000005]GW/ADDRESS :: 00:00:00:00:00:00 via eth1(0xa148b070) NONE (nh:2)
   R6[000006]GW/ROUTE 3ffe:2:10::5 00:00:00:00:00:00 via eth1(0xa148b070) NONE (nh:3)
   R6[000007]GW/NEIGH 3ffe:2:10::6 00:15:17:34:2a:d8 via eth1(0xa148b070) REACHABLE (nh:4)
   R6[000008]GW/ROUTE fe80::1 00:00:00:00:00:00 via eth1(0xa148b070) NONE (nh:5)

dump-nh6
~~~~~~~~

.. rubric:: Description

Dump the IPv6 next hop table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-nh [NHINDEX]

.. rubric:: Parameters

No parameter
   Dump the whole next hop table.
NHINDEX
   Index to dump specifically in next hop table.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-nh6
   N6[0001] IFACE/CONNECTED via eth1(0xa148b070) refcnt=1
   N6[0002] GW/ADDRESS :: 00:00:00:00:00:00 via eth1(0xa148b070) NONE refcnt=1
   N6[0003] GW/ROUTE 3ffe:2:10::5 00:00:00:00:00:00 via eth1(0xa148b070) NONE refcnt=1
   N6[0004] GW/NEIGH 3ffe:2:10::6 00:15:17:34:2a:d8 via eth1(0xa148b070) REACHABLE refcnt=1
   N6[0005] GW/ROUTE fe80::1 00:00:00:00:00:00 via eth1(0xa148b070) NONE refcnt=1

dump-user6
~~~~~~~~~~

.. rubric:: Description

Dump the user routing entries (default type ROUTE=1).

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-user [all|fpm|local|neigh|connected|black]

.. rubric:: Parameters

No parameter
   Display only routes configured by user.
all
   Display all kinds of routes.
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

   <fp-0> dump-user6
   # - Preferred, * - Active, > - selected
   3ffe:2:20::/48  [05]  ROUTE gw fe80::1 via eth1(0xa148b070) (8)
   3ffe:100:2:2::1/128  [03]  ROUTE gw 3ffe:2:10::5 via eth1(0xa148b070) (6)

.. code-block:: fp-cli

   <fp-0> dump-user fpm

.. code-block:: fp-cli

   <fp-0> dump-user6 local
   # - Preferred, * - Active, > - selected
   fe80::/10  [5001]  LOCAL (1)
   ff00::/8  [5001]  LOCAL (2)

.. code-block:: fp-cli

   <fp-0> dump-user6 neigh
   # - Preferred, * - Active, > - selected
   3ffe:2:10::6/128  [04]  NEIGH gw 3ffe:2:10::6 (N) via eth1(0xa148b070) (7)

.. code-block:: fp-cli

   <fp-0> dump-user6 connected
   # - Preferred, * - Active, > - selected
   3ffe:2:10::/64  [01]  CONNECTED via eth1(0xa148b070) (4)

.. code-block:: fp-cli

   <fp-0> dump-user6 black
   # - Preferred, * - Active, > - selected
   ::/80  [5002]  BLACKHOLE (3)

.. code-block:: fp-cli

   <fp-0> dump-user6 all
   # - Preferred, * - Active, > - selected
   ::/80  [5002]  BLACKHOLE (3)
   3ffe:2:10::/64  [01]  CONNECTED via eth1(0xa148b070) (4)
   3ffe:2:10::1/128  [02]  ADDRESS via eth1(0xa148b070) (5)
   3ffe:2:10::6/128  [04]  NEIGH gw 3ffe:2:10::6 (N) via eth1(0xa148b070) (7)
   3ffe:2:20::/48  [05]  ROUTE gw fe80::1 via eth1(0xa148b070) (8)
   3ffe:100:2:2::1/128  [03]  ROUTE gw 3ffe:2:10::5 via eth1(0xa148b070) (6)
   fe80::/10  [5001]  LOCAL (1)
   ff00::/8  [5001]  LOCAL (2)

dump-routes
~~~~~~~~~~~

.. rubric:: Description

Dump the |fp|'s internal routing table (default: *all* and *very verbose*).

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-routes [all|fpm|local|neigh|connected|black]

.. rubric:: Parameters

No parameter
   Display only routes configured by user.
all
   Display all kinds of routes.
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

   <fp-0> dump-routes6
   E[000000]::/80  [5002]  BLACKHOLE /80 (3)
   E[000000]3ffe:2:10::/64  [01]  CONNECTED via eth1(0xa148b070) /64 (4)
   E[000001]3ffe:2:10::1/128  [02]  ADDRESS via eth1(0xa148b070) /128 (5)-> /64 (4)
   E[000002]3ffe:2:10::2/64  [01]  CONNECTED via eth1(0xa148b070) /64 (4)
   E[000003]3ffe:2:10::3/64  [01]  CONNECTED via eth1(0xa148b070) /64 (4)
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
   Destination IPv6 address.
SADDR
   Display selected route according to a specific source IPv6 address.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> show-route 3ffe:2:10::
    Prio: ADDR=128, PREF=32, CNX=2
   3ffe:2:10::/64  Single Entry /64 (4)
    Preferred: 1 (prio 2)   Total: 1
        [01]  #    (p=002)  CONNECTED via eth1(0xa148b070)

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
   <fp-0> show-filling
   Tables filling:
   fp_8_table: 33/11000 (0.300000%) IPv4:4 IPv6:29
   fp_16_table: 35/80 (43.750000%)
    IPv4:16 IPv6:19
   fp_8_entries: 2074/2816000 (0.073651%)
   fp_16_entries: 4680/5242880 (0.089264%)
   fp_rt4_table: 4/50001 (0.008000%)
   fp_rt6_table: 8/50001 (0.016000%)
   fp_nh4_table: 0/5001 (0.000000%)
   fp_nh6_table: 5/5001 (0.099980%)

get-route
~~~~~~~~~

.. rubric:: Description

Search for the exact route to a prefix.

.. rubric:: Synopsis

.. code-block:: fp-cli

   get-route DADDR PREFIX

.. rubric:: Parameters

DADDR
   Destination IPv6 address.
PREFIX
   Netmask length in bits.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> get-route 3ffe:2:10:: 64
   3ffe:2:10::/64  [01]  CONNECTED via eth1(0xa148b070) /64 (4)

get-src-address
~~~~~~~~~~~~~~~

.. rubric:: Description

Search for source address to a given destination.

.. rubric:: Synopsis

.. code-block:: fp-cli

   get-src-address DADDR

.. rubric:: Parameters

DADDR
   Destination IPv6 address.

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

set-pref
~~~~~~~~

.. seealso::

   Please see the command in the |fpforw4| documentation.

VRF support
-----------

.. seealso::

   Please see the *VRF* section in the |fpforw4| documentation.

RPF check
---------

To enable or disable |rpfilter| check per interface,
use the *rpf-ipv6* command.

rpf-ipv6
~~~~~~~~

.. rubric:: Description

.. rubric:: Synopsis

.. code-block:: fp-cli

   rpf-ipv6 <interface> [on|off]

.. rubric:: Parameters

interface
   Name of the interface.
on|off
   Enable/disable the RPF on this interface (optional). If this
   argument is omitted, only the status of the RPF check is displayed.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> rpf-ipv6 eth3 on
   eth3: IPv6 RPF is on

.. code-block:: fp-cli

   <fp-0> dump-interfaces
   9:eth3 [VR-0] ifuid=0x9000000 (port 2) <UP|RUNNING|FWD4|FWD6|RPF6> (0x663)
           type=ether mac=00:1b:21:c5:7f:76 mtu=1500 tcp6mss=0 tcp6mss=0
           IPv4 routes=0  IPv6 routes=0

.. code-block:: fp-cli

   <fp-0> rpf-ipv6 eth3
   eth3: IPv6 RPF is on

TCP MSS clamping
----------------

TCP |mss| clamping can be configured by interface.

set-tcpmss6
~~~~~~~~~~~

.. rubric:: Description

Change the default value of MSS. 0 means no change is made in packets.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-tcpmss6 <interface> <value>

.. rubric:: Parameters

IFNAME
   Name of the interface.
value
   MSS, default is 0 (disabled).

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-tcpmss6 eth0 1440

Statistics
----------

dump-ip-stats
~~~~~~~~~~~~~

.. rubric:: Description

Dumps IPv6 statistics.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-ip-stats [percore] [non-zero]

.. rubric:: Parameters

.. include:: include/percore-non-zero.inc

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-ip6-stats
    IpForwDatagrams:232
    IpInReceives:232
    IpInDelivers:124
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
