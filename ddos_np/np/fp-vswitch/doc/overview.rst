.. Copyright 2013 6WIND S.A.

.. title:: |fp-ovs|

About |fp-ovs|
==============

|fp-ovs| provides |ovs| acceleration in the |fp|.

It implements high performance virtual switching, transparently synchronized
with the standard Linux Open vSwitch |cp| and |dp|, using
OpenFlow or the Open vSwitch command line. This does not require any
modification to Open vSwitch, Linux applications, management or orchestration
software.

OVS acceleration can be combined with other |fp| protocols such as VXLAN,
NAT/filtering, IPsec and more to provide enhanced services at the hypervisor
level.

Synchronization with the |ovs| |cp| is provided by |linux-fp-sync|.
Statistics synchronization require |cp-ovs|.

Features
--------

- Flows matching attributes:

  - Ethertype
  - VLAN 802.1q
  - IP
  - IPv6
  - UDP/TCP (v4 and v6)
  - ICMP
  - ICMPv6
  - ARP
  - MPLS (one label)

- Actions:

  - push/pop VLAN header
  - push/pop MPLS header (one label)
  - set attribute in the packet
    - MAC address
    - TCP/UDP port
    - IPv6 (addresses, traffic class, flow label, hop limit)
    - IPv4 (addresses, TOS, TTL)
    - MPLS (label, tc, ttl)
  - output

- VXLAN tunnelling (requires |vxlan|).

- Transparent synchronization with |ovs| |cp| through |linux-fp-sync|
  (flow and port statistics synchronization require |cp-ovs|).

- Supports a maximum of 65536 flows and 256 ports at one time.

- Supports megaflow. This |ovs| feature limits the number of flow
  creation/deletion by allowing to wildcard flow fields during
  matching.

- Supports recirculation. This |ovs| feature is used in recent
  versions to implement 'resubmit'. It tags a flow with a
  recirculation id, and has the packets go through the flow table
  again. It is used to chain flows.

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |fpbase| - Plugins
- |vxlan| (for VXLAN tunnelling)
- |linux-fp-sync|
- |cp-ovs| (for flow and port statistics synchronization)

Linux
~~~~~

- |ovs| distribution between 1.9 and 2.3.
- |ovs| distributions >= 2.2 need |cp-ovs|.

Installation
------------

See the |qsg|.
