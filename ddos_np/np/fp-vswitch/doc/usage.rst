Usage
=====

Principles
----------

- The |ovs| kernel module must be loaded before starting the |cmgr|,
  because the |cmgr| needs to bind a generic netlink socket to
  openvswitch family and tries only once, at start.

- The |ovs| daemons should be stopped before starting the
  |fp|. Indeed, the |fp| generates new network interfaces. If the
  daemons are not stopped, the bridges will have to be destroyed and
  recreated to re-apply the virtual switch configuration.

- The |fp| can be started.

- The |ovs| daemons can be restarted. The interfaces that are put in
  a bridge must be set up and promiscuous.

Using an |ovs| distribution package
-----------------------------------

This section implies that the |6w|'s packages were already installed
(at least |fp|, |fp-ovs| and |linux-fp-sync|).

Here is an example of configuring a |fp| and a virtual bridge between
two physical ports (output are from |fedora| 20):

- Install |ovs| package, depending on your distribution, using yum or
  apt

  .. code-block:: console

     # yum install openvswitch
     # apt-get install openvswitch

- Start openvswitch service if your distribution did not do it for
  you, to load |ovs| kernel module

  .. code-block:: console

     # service openvswitch start
     Redirecting to /bin/systemctl start  openvswitch.service

- Stop openvswitch service before starting |fp|

  .. code-block:: console

     # service openvswitch stop
     Redirecting to /bin/systemctl stop  openvswitch.service

- Check that openvswitch kernel module is properly loaded

  .. code-block:: console

     # lsmod |grep openvswitch
     openvswitch            70953  0
     vxlan                  37295  1 openvswitch
     gre                    13535  1 openvswitch
     libcrc32c              12603  1 openvswitch

- Configure and start the |fp|. For this part, please refer to
  |fpbase| documentation

- Start the linux synchronization. For this part, please refer to
  |linux-fp-sync| documentation

- Restart openvswitch service

  .. code-block:: console

     # service openvswitch start
     Redirecting to /bin/systemctl start  openvswitch.service

- Configure a bridge between two ports

  .. code-block:: console

     # ovs-vsctl add-br br0
     # ovs-vsctl add-port br0 eth0
     # ovs-vsctl add-port br0 eth1

- Add an *OpenFlow* controller (optional, the installation of such
  controller is not covered by this document)

  .. code-block:: console

     # ovs-vsctl set-controller br0 tcp:192.168.0.27:6633

- Set the interfaces up and promiscuous

  .. code-block:: console

     # ip link set eth0 up
     # ip link set eth0 promisc on
     # ip link set eth1 up
     # ip link set eth1 promisc on
     # ip link set br0 up

.. seealso::

   For more information, see the *OpenStack* and |ovs| documentation.

*fp-cli* commands
-----------------

Enabling |fp-ovs| provides the following additional *fp-cli* commands.

dump-fp-vswitch-ports
~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Print the list of ports synchronized in the |fp|.

.. rubric:: Synopsis

.. code-block:: fp-cli

  dump-fp-vswitch-ports

.. rubric:: Parameters

percore
   Display statistic values for each core.
non-zero
   Display statistics values that are not 0.

.. rubric:: Example

.. code-block:: fp-cli

  <fp-0> dump-fp-vswitch-ports
  0: ovs-system (internal)
    rx_pkts:0
    tx_pkts:0
    rx_bytes:0
    tx_bytes:0
  1: br0 (internal)
    rx_pkts:0
    tx_pkts:0
    rx_bytes:0
    tx_bytes:0
  2: eth4 (netdev)
    rx_pkts:0
    tx_pkts:0
    rx_bytes:0
    tx_bytes:0
  3: eth5 (netdev)
    rx_pkts:0
    tx_pkts:0
    rx_bytes:0
    tx_bytes:0
  4: eth2 (netdev)
    rx_pkts:0
    tx_pkts:0
    rx_bytes:0
    tx_bytes:0
  5: eth3 (netdev)
    rx_pkts:0
    tx_pkts:0
    rx_bytes:0
    tx_bytes:0

dump-fp-vswitch-stats
~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Print statistics information about configured bridges.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-fp-vswitch-stats

.. rubric:: Parameters

None.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-fp-vswitch-stats
     flow_not_found:6
     parsing_non_linear:0
     output_ok:36
     output_failed_no_mbuf:0
     output_failed_vport:0
     userspace:0
     push_vlan:0
     pop_vlan:0
     set_ethernet:0
     set_priority:0
     set_tunnel_id:0
     set_ipv4:0
     set_ipv6:0
     set_tcp:0
     set_udp:0
     unsupported:0

dump-fp-vswitch-flows
~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Dump the current flow table as a human-readable C-like structure. Only
flows with traffic are displayed: flows are removed as soon as traffic
stops. The output is similar to ovs-dpctl display for key, mask and
action (default value).

.. note::

   This command doesn't dump the controller's flow table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-fp-vswitch-flows [help|[{+|-}]{item}] [...]

.. rubric:: Parameters

To display the items below, prefix them with a plus sign (+).

To hide the items below, prefix them with a minus sign (-).

help
   List all available items.
flow
   Affect *flow.** items globally.
next
   Next flow index (enabled by default).
flow.key
   Affect *flow.key.** items globally.
flow.actions
   Defined flow actions.
flow.actions_len
   Size of *flow.actions[]* in bytes.
flow.index
   Flow index.
flow.hash
   Flow hash.
flow.state
   Flow state (unspecified = 0, active = 1).
flow.age
   Flow age. This value is increased until flow expiration.
flow.key.l1.ovsport
   Input port.
flow.key.l2.src
   Ethernet source address.
flow.key.l2.dst
   Ethernet destination address.
flow.key.l2.ether_type
   Ethernet frame type.
flow.key.l2.vlan_tci
   If 802.1Q, TCI | VLAN_CFI; otherwise 0.
flow.key.l3.frag
   FLOW_FRAG_* flags.
flow.key.l3.tos
   IP :abbr:`ToS (type of service)` (including DSCP and ECN).
flow.key.l3.ttl
   IP :abbr:`TTL (Time to live)`/Hop limit.
flow.key.l3.proto
   IP protocol or lower 8 bits of ARP opcode.
flow.key.l3.ip.src
   IPv4 source address.
flow.key.l3.ip.dst
   IPv4 destination address.
flow.key.l3.ip.arp.sha
   ARP source hardware address.
flow.key.l3.ip.arp.tha
   ARP target hardware address.
flow.key.l3.ip6.src
   IPv6 source address.
flow.key.l3.ip6.dst
   IPv6 destination address.
flow.key.l3.ip6.label
   IPv6 flow label.
flow.key.l3.ip6.ndp.target
   IPv6 neighbor discovery (ND) target.
flow.key.l3.ip6.ndp.sll
   IPv6 neighbor discovery (ND) source hardware address.
flow.key.l3.ip6.ndp.tll
   IPv6 neighbor discovery (ND) target hardware address.
flow.key.l4.flags
   TCP flags.
flow.key.l4.sport
   TCP/UDP/SCTP source port.
flow.key.l4.dport
   TCP/UDP.SCTP destination port.
flow.key.tunnel.id
   Encapsulating tunnel ID.
flow.key.tunnel.src
   Tunnel outer IPv4 src addr.
flow.key.tunnel.dst
   Tunnel outer IPv4 dst addr.
flow.key.tunnel.flags
   Tunnel flags.
flow.key.tunnel.tos
   Tunnel :abbr:`ToS (type of service)`.
flow.key.tunnel.ttl
   Tunnel :abbr:`TTL (Time to live)`

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> dump-fp-vswitch-flows
   FPVS flow table (max 65536 flows):
     sizeof(fpvs_flow_entry_t): 10560
     sizeof(struct fpvs_flow): 10496
     Fast Path PID: 1143
     Flow max age: 2
   
   .table = {
     [5] = { .pkts = 2, .bytes = 200,
     .flow.key = in_port(4),eth(src=00:23:45:67:89:ab,dst=00:de:f0:12:34:56),eth_type(0x0800),ipv4(src=192.168.0.1,dst=192.168.0.2,proto=6,tos=0,ttl=0,frag=0),l4(sport=1234,dport=80,flags=0,),
     .flow.mask = in_port(ffffffff),eth(src=ff:ff:ff:ff:ff:ff,dst=ff:ff:ff:ff:ff:ff),eth_type(0xffff),ipv4(src=255.255.255.255,dst=255.255.255.255,proto=ff,tos=fc,ttl=0,frag=ff),l4(sport=ffff,dport=ffff,flags=0),
     .flow.actions = actions(set(eth(src=00:23:45:67:89:ab, dst=00:21:0f:ed:cb:a9)),output:2),
     },
   }

dump-fp-vswitch-masks
~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Dump the current mask table as a human-readable C-like
structure. The output is similar to ovs-dpctl display.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-fp-vswitch-masks

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> dump-fp-vswitch-masks
   FPVS flow mask table (max 32768 masks):
     sizeof(fpvs_mask_entry_t): 192
     sizeof(struct fpvs_mask): 160
     Fast Path PID: 1441
   
   .table = {
     [1] = {
       ref_count = 1,
       range = [0x18, 0x78],
       key = in_port(ffffffff),eth(src=ff:ff:ff:ff:ff:ff,dst=ff:ff:ff:ff:ff:ff),eth_type(0xffff),l3(value=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,proto=ff,tos=fc,ttl=0,frag=ff),l4(sport=ffff,dport=ffff,flags=0)
     },
   }
   
set-fp-vswitch-flow-max-age
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Set maximum flow age value. Flows are garbage collected every 5s *
flow max age value. Only useful without |cp-ovs|.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-fp-vswitch-flow-max-age <age>

.. rubric:: Parameters

age
   Age value, default is 2.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> set-fp-vswitch-flow-max-age 12
   flow_max_age is 12 (was 2)
