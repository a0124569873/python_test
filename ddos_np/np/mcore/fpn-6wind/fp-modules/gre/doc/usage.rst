.. Copyright 2014 6WIND S.A.

Usage
=====

Starting |fp-gre|
-----------------

#. Start the |fp|:

   .. code-block:: console

      $ fast-path.sh start

#. To synchronize Linux and the |fp|, start the |linux-fp-sync| module:

   .. code-block:: console

      $ linux-fp-sync.sh start

Managing GRE interfaces from the |fp|
-----------------------------------------

The *fp-cli* commands below allow you to manage GRE interfaces.

#. To start *fp-cli*, enter:

   .. code-block:: console

      $ fp-cli

gre-dump
~~~~~~~~

.. rubric:: Description

Dump GRE interfaces.

.. rubric:: Synopsis

.. code-block:: fp-cli

   gre-dump [name IFNAME]

.. rubric:: Parameters

IFNAME

   |name-gre-interface|

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> gre-dump
   gre1 linked to eth1 vrfid: 0 link vrfid: 0
       mode IP
       local: 2.0.0.1 remote: 2.0.0.5
       ttl: 64 tos: 0x02
       iflags: csum key oflags: csum key
       ikey: 0x00000001 (1)
       okey: 0x00000001 (1)


gre-iface-add
~~~~~~~~~~~~~

.. rubric:: Description

Add GRE interfaces.

.. rubric:: Synopsis

.. code-block:: fp-cli

   gre-iface-add IFNAME IP_VERSION MODE LOCAL_ADDR REMOTE_ADDR
           [vr VRFID] [[i|o]key KEY] [[i|o]csum] [ttl TTL] [tos TOS]
           [link LINK_IFNAME] [link-vrf VRFID]

   IP_VERSION := { 4 | 6 }
   MODE := { IP | Ether }
   LOCAL_ADDR & REMOTE_ADDR := { IP_ADDRESS | any }
   TOS := { 0x00..0xff | inherit }
   TTL := { 0..255  | inherit }

.. rubric:: Parameters

IFNAME

   |name-gre-interface|

IP_VERSION

   IP version of the GRE interface. Allowed values are 4 and 6.

MODE

   Mode of the packet payload. Allowed values are IP (protocol 0x0800 for IPv4 or 0x86dd for IPv6) and Ether (protocol 0x6558 for TEB)

LOCAL_ADDR

   Local IP address. Allowed values are IPv4 or IPv6 adresses, or *any*.

REMOTE_ADDR

   Remote IP address. Allowed values are IPv4 or IPv6 adresses, or *any*.

VR

   |vrf| ID of the GRE interface (|vrf| ID of plaintext packets).

[i|o]key

   Input, output or global GRE tunnel key.

[i|o]csum

   Activate check-sum for input [i], output [o] or all.

TTL

   Time to live to set on packets entering the tunnel.

TOS

   Type of service to set on the tunnel. Ignored for IPv6 GRE tunnels.

LINK_IFNAME

   Interface name linked to the GRE tunnel.

LINK_VR

   Id of the |vrf| link of the tunnel to create.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> gre-iface-add gre2 4 IP 10.2.2.1 any ikey 0x23 csum
   <fp-0> gre-dump name gre2
   gre2 linked to none vrfid: 0 link vrfid: 0
       mode IP
       local: 10.2.2.1 remote: any
       ttl: inherit tos: 0x00
       iflags: csum key oflags: csum
       ikey: 0x00000023 (35)

gre-iface-del
~~~~~~~~~~~~~

.. rubric:: Description

Delete GRE interfaces.

.. rubric:: Synopsis

.. code-block:: fp-cli

   gre-iface-del IFNAME

.. rubric:: Parameters

IFNAME

   |name-gre-interface|

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> gre-iface-del gre2

Simple GRE L3 tunnel with synchronization
-----------------------------------------

|network-topology|

::

             +---------------+                +---------------+
             |    Remote     |                | Gateway  with |
             |    Gateway    |                |   fast path   |
             |               |2.0.0.5         |               |
 <-<---------|-ethY   /-ethX-|================|-eth1-\   eth2-|--------->->
   100.2.2.1 |     greZ      |         2.0.0.1|      gre1     | 110.2.2.1
             |  10.10.10.2   |                |   10.10.10.1  |
             |               |                |               |
             +---------------+                +---------------+

#. |configure-ip-routes|

   .. code-block:: console

      # ip link set eth1 up
      # ip addr add 2.0.0.1/24 dev eth1
      # ip link set eth2 up
      # ip addr add 2.1.0.1/24 dev eth2

#. |create-gre|

   .. code-block:: console

      # ip tunnel add gre1 mode gre local 2.0.0.1 remote 2.0.0.5 dev eth1 key 1 csum
      # ip link set gre1 up
      # ip addr add 10.10.10.1 peer 10.10.10.2/24 dev gre1

#. |add-route|

   .. code-block:: console

      # ip route 100.2.2.1/24 via 10.10.10.2

   |capture-plaintext|

#. |fp-display|

   .. code-block:: console

      $ fp-cli

   .. code-block:: fp-cli

      <fp-0> gre-dump
      gre1 linked to eth1 vrfid: 0 link vrfid: 0
          mode IP
          local: 2.0.0.1 remote: 2.0.0.5
          ttl: inherit tos: 0x00
          iflags: csum key oflags: csum key
          ikey: 0x00000001 (1)
          okey: 0x00000001 (1)

Simple GRE L2 tunnel with synchronization
-----------------------------------------

|network-topology|

::

             +---------------+                +---------------+
             |    Remote     |                | Gateway  with |
             |    Gateway    |                |   fast path   |
             |               |2.0.0.5         |               |
 <-<---------|-ethY   /-ethX-|================|-eth1-\   eth2-|--------->->
   100.2.2.1 |   gretapZ     |         2.0.0.1|    gretap1    | 110.2.2.1
             |  10.10.10.2   |                |   10.10.10.1  |
             |               |                |               |
             +---------------+                +---------------+

#. |configure-ip-routes|

   .. code-block:: console

      # ip link set eth1 up
      # ip addr add 2.0.0.1/24 dev eth1
      # ip link set eth2 up
      # ip addr add 2.1.0.1/24 dev eth2

#. |create-gre|

   .. code-block:: console

      # ip link add name gretap1 type gretap local 2.0.0.1 remote 2.0.0.5 dev eth1 key 1 csum
      # ip link set gretap1 up
      # ip addr add 10.10.10.1/24 dev gretap1

#. |add-route|

   .. code-block:: console

      # ip route 100.2.2.1/24 via 10.10.10.2

   |capture-plaintext|

#. |fp-display|

   .. code-block:: console

      $ fp-cli

   .. code-block:: fp-cli

      <fp-0> gre-dump
      gre1 linked to eth1 vrfid: 0 link vrfid: 0
          mode Ether
          local: 2.0.0.1 remote: 2.0.0.5
          ttl: inherit tos: 0x00
          iflags: csum key oflags: csum key
          ikey: 0x00000001 (1)
          okey: 0x00000001 (1)

Simple GRE L3 tunnel without synchronization
--------------------------------------------

|network-topology|

::

             +---------------+                +---------------+
             |    Remote     |                | Gateway  with |
             |    Gateway    |                |   fast path   |
             |               |2.0.0.5         |               |
 <-<---------|-ethY   /-ethX-|================|-eth1-\   eth2-|--------->->
   100.2.2.1 |     greZ      |         2.0.0.1|      gre1     | 110.2.2.1
             |  10.10.10.2   |                |   10.10.10.1  |
             |               |                |               |
             +---------------+                +---------------+

#. |config-ip-routes|

   .. code-block:: console

      $ fp-cli

   .. code-block:: fp-cli

      <fp-0> add-interface eth1 0 00:02:02:00:00:20 8
      <fp-0> add-address4 eth1 2.0.0.1 24
      <fp-0> add-interface eth2 1 00:02:02:00:00:21 9
      <fp-0> add-address4 eth2 2.1.0.1 24

#. |create-gre|

   .. code-block:: fp-cli

      <fp-0> gre-iface-add gre1 4 2.0.0.1 2.0.0.5 key 1 csum link eth1
      <fp-0> add-address4 gre1 10.10.10.1 24
      <fp-0> set-flags gre1 0x23

#. Create a new route and neighbors:

   .. code-block:: fp-cli

      <fp-0> add-route 100.2.2.1 32 10.10.10.2 gre1 0
      <fp-0> add-route 110.2.2.1 32 2.1.0.5 eth2 0
      <fp-0> add-neighbour 2.0.0.5 00:55:00:00:00:20 eth1
      <fp-0> add-neighbour 2.1.0.5 00:55:01:00:00:21 eth2

   |capture-plaintext|

#. |disp-iface|

   .. code-block:: fp-cli

      <fp-0> gre-dump
      gre1 linked to eth1 vrfid: 0 link vrfid: 0
          mode IP
          local: 2.0.0.1 remote: 2.0.0.5
          ttl: inherit tos: 0x00
          iflags: csum key oflags: csum key
          ikey: 0x00000001 (1)
          okey: 0x00000001 (1)

   .. code-block:: fp-cli

      <fp-0> dump-interfaces
      8:eth1 [VR-0] ifuid=0x8000000 (port 0) <UP|RUNNING|FWD4> (0x23)
              type=ether mac=00:02:02:00:00:20 mtu=1500 tcp4mss=0 tcp6mss=0
              IPv4 routes=2  IPv6 routes=0
      9:eth2 [VR-0] ifuid=0x9000000 (port 1) <UP|RUNNING|FWD4> (0x23)
              type=ether mac=00:02:02:00:00:21 mtu=1500 tcp4mss=0 tcp6mss=0
              IPv4 routes=3  IPv6 routes=0
      121:gre1 [VR-0] ifuid=0x79201c32 (virtual) <> (0x0)
              type=gre mac=00:00:00:00:00:00 mtu=1500 tcp4mss=0 tcp6mss=0
              IPv4 routes=0  IPv6 routes=0

   .. code-block:: fp-cli

      <fp-0> dump-address4 eth1
      number of ip address: 1
      2.0.0.1 [0]

   .. code-block:: fp-cli

      <fp-0> dump-address4 eth2
      number of ip address: 1
      2.1.0.1 [1]

   .. code-block:: fp-cli

      <fp-0> dump-address4 gre1
      number of ip address: 1
      10.10.10.1 [2]

#. |disp-neigh-routes|

   .. code-block:: fp-cli

      <fp-0> dump-user all
      # - Preferred, * - Active, > - selected
      2.0.0.1/24  [02]  CONNECTED via eth1(0x08000000) (2)
      2.0.0.1/32  [01]  ADDRESS via eth1(0x08000000) (1)
      2.0.0.5/32  [09]  NEIGH gw 2.0.0.5 (N) via eth1(0x08000000) (10)
      2.1.0.1/24  [04]  CONNECTED via eth2(0x09000000) (4)
      2.1.0.1/32  [03]  ADDRESS via eth2(0x09000000) (3)
      2.1.0.5/32  [08]  NEIGH gw 2.1.0.5 (N) via eth2(0x09000000) (9)
      10.10.10.1/24  [06]  CONNECTED via gre1(0x79201c32) (6)
      10.10.10.1/32  [05]  ADDRESS via gre1(0x79201c32) (5)
      100.2.2.1/32  [07]  ROUTE gw 10.10.10.2 via gre1(0x79201c32) (7)
      110.2.2.1/32  [08]  NEIGH gw 2.1.0.5 via eth2(0x09000000) (8)


#. |delete-gre|

   .. code-block:: fp-cli

      <fp-0> gre-iface-del gre1

Simple cross-vrf GRE tunnel with synchronization
------------------------------------------------

|network-topology|

::

             +---------------+                +----------------+
             |    Remote     |                | Gateway  with  |
             |    Gateway    |                |   fast path    |
             |               |                |                |
             |               |                |---------+      |
             |               |                |   vrf1  |      |
             |               |2.0.0.5         |         |      |
 <-<---------|-ethY  //=ethX-|================|-eth1=\\ | eth2-|--------->->
   100.2.2.1 |       ||      |         2.0.0.1|      || |      | 110.2.2.1
             |       ||      |                |------||-+      |
             |     greZ      |                |      gre1      |
             |  10.10.10.2   |                |   10.10.10.1   |
             |               |                |                |
             +---------------+                +----------------+

The *gre1* interface will use 2 VRs:

- The interface *link-vr*, i.e. the |vr| of encapsulated GRE packets
- The interface *vr*, i.e. the |vr| of plaintext packets

We will create the GRE interface in the *link-vr* interface, then move it
to its own |vr|.

#. Create the *vrf1* network namespace:

   .. code-block:: console

      # vrfctl add 1 linux-fp-sync-vrf.sh

#. |configure-ip-routes|

   .. code-block:: console

      # ip link set eth1 netns vrf1
      # ip netns exec vrf1 ip link set eth1 up
      # ip netns exec vrf1 ip addr add 2.0.0.1/24 dev eth1
      # ip netns exec vrf0 ip link set eth2 up
      # ip netns exec vrf0 ip addr add 2.1.0.1/24 dev eth2

#. |create-gre|

   .. code-block:: console

      # ip netns exec vrf1 ip link add gre1 type gre local 2.0.0.1 remote 2.0.0.5
      # ip netns exec vrf1 ip link set gre1 netns vrf0
      # ip netns exec vrf0 ip link set gre1 up
      # ip netns exec vrf0 ip addr add 10.10.10.1 peer 10.10.10.2/24 dev gre1

#. |add-route|

   .. code-block:: console

      # ip netns exec vrf0 ip route 100.2.2.1/24 via 10.10.10.2

   When sending traffic between *100.2.2.1* and *110.2.2.1*, you can capture
   plaintext traffic on *gre1* (*vrf0*), and encapsulated traffic on *eth1*
   (*vrf1*).

#. |fp-display|

   .. code-block:: console

      $ fp-cli

   .. code-block:: fp-cli

      <fp-0> gre-dump
      gre1 linked to none vrfid: 0 link vrfid: 1
          mode IP
          local: 2.0.0.1 remote: 2.0.0.5
          ttl: inherit tos: 0x00
          iflags: oflags:
