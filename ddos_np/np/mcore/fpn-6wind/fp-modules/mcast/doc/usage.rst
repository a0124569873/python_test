Usage
=====

You can manage multicast routes via a Linux multicast daemon such as *smcroute*
or *pimd*.

Example with *smcroute* on Ubuntu 13.10
---------------------------------------

*smcroute* lets you manage static multicast routes.

#. Install *smcroute*:

   .. code-block:: console

     $ sudo apt-get install smcroute

#. Once the daemon runs, add a new static multicast route:

   .. code-block:: console

     $ smcroute -a eth1 2.0.0.5 224.55.55.55 eth2

#. Check that the route as been added in the |fp|:

   .. code-block:: console

     $ fp-cli dump-mfc4
     MFC list:
             (2.0.0.5 ,224.55.55.55), Incoming interface: eth1 (0x33117022)
                      Outgoing interfaces:
                              eth2 (0x6008c1d2)
                      Pkts: 0 Bytes: 0
                      Offset: 54 Next: 65535

   From now on, all packets whose source address is *2.0.0.5*, and whose
   destination address is *224.55.55.55*, that are received on interface *eth1*
   are forwarded to interface *eth2*.

   .. note::

      You can specify multiple interfaces to forward to.

#. Send a ping from *2.0.0.5*:

   .. code-block:: console

     $ ping -c 1 -t 64 -I 2.0.0.5 224.55.55.55

   The ping is not returned by any host.

   .. note::

      The default TTL for multicast packets is 1; we set it here to 64.

#. Check that the packet has been forwarded by the |fp|:

   .. code-block:: console

     $ fp-cli dump-mfc4
     MFC list:
             (2.0.0.5 ,224.55.55.55), Incoming interface: eth1 (0x33117022)
                      Outgoing interfaces:
                              eth2 (0x6008c1d2)
                      Pkts: 1 Bytes: 84
                      Offset: 54 Next: 65535

#. Make sure that any host connected to an outgoing interface (here *eth2*) will
   receive the packet:

   .. code-block:: console

     $ tcpdump -ni eth1
     listening on eth2_1, link-type EN10MB (Ethernet), capture size 96 bytes
     10:22:04.596334 IP 2.0.0.5 > 224.55.55.55: icmp 64: echo request seq 1

Multicast group filtering
-------------------------

You can filter and whitelist multicast packets.

Multicast packets are dropped by the |fp| if:

- filtering is enabled, and,
- the packet's multicast group doesn't match a whitelist entry.

Otherwise, the packet is forwarded and/or sent as an exception to the kernel.

mcastgrp-filter
~~~~~~~~~~~~~~~

.. rubric:: Description

Set or show multicast group filtering.

.. rubric:: Synopsis

.. code-block:: fp-cli

   mcastgrp-filter [on [accept-ll] | off]

.. rubric:: Parameters

No parameter
   Dump all entries in the white list.

on|off
   Enable multicast group filtering. Off by default.

accept-ll
   Authorize link local multicast (224.0.0.0/24).

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> fpcmd mcastgrp-filter on
   Multicast group filtering is on, was off

   <fp-0> fpcmd mcastgrp-filter
   Multicast IPv4 group filtering is on

   group            | incoming interface

   228.250.7.1      |   eth1_0
   236.10.5.1       |   eth1_0
   237.10.5.1       |   eth1_0
   0.0.0.0          |   eth2_0
   4 entries

mcastgrp-add
~~~~~~~~~~~~

.. rubric:: Description

Add an entry in the white list. An entry comprises a multicast group's IP
address and an incoming interface.

.. rubric:: Synopsis

.. code-block:: fp-cli

   mcastgrp-add ADDR|all INCOMING_IF|all

.. rubric:: Parameters

ADDR
   IPv4 multicast group address not to be filtered. Set this parameter to *all*
   to accept packets from all multicast groups.

INCOMING_IF
   Name of the interface that sent the multicast packets. Set this parameter to
   *all* to accept multicast groups, whatever the incoming interface.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> mcastgrp-add 228.250.7.2 eth0_0
   <fp-0> mcastgrp-add 236.250.7.2 all

mcastgrp-del
~~~~~~~~~~~~

.. rubric:: Description

Delete an entry in the white list. An entry comprises a multicast group's IP
address and an incoming interface.

If the entry does not exist, display an error message and exit.

.. rubric:: Synopsis

.. code-block:: fp-cli

   mcastgrp-del ADDR|all INCOMING_IF|all

.. rubric:: Parameters

ADDR
   IPv4 multicast group address of the entry to delete.

INCOMING_IF
   Interface name of the entry to delete.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> mcastgrp-del 228.250.7.2 eth0_0
   <fp-0> mcastgrp-del 236.250.7.2 all
