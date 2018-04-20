Usage
=====

Example
-------

|icmp| packets are being forwarded by the |fp|:

.. code-block:: console

   # tcpdump -n -i eth2
   # tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
    listening on eth2, link-type EN10MB (Ethernet), capture size 65535 bytes
    15:17:29.155002 00:00:00:00:00:00 > 00:02:02:00:00:21, ethertype Unknown (0x2007), length 124:
         0x0000:  6049 4000 0000 0000 6008 c1d2 0002 0200  `I@.....`.......
         0x0010:  0021 0055 0100 0021 0800 4500 0054 8047  .!.U...!..E..T.G
         0x0020:  0000 4001 245c 6e02 0201 6402 0201 0000  ..@.$\n...d.....
         0x0030:  9263 6107 0007 6810 3352 0000 0000 46f9  .ca...h.3R....F.
         0x0040:  0c00 0000 0000 0809 0a0b 0c0d 0e0f 1011  ................
         0x0050:  1213 1415 1617 1819 1a1b 1c1d 1e1f 2021  ...............!
         0x0060:  2223 2425 2627 2829 2a2b 2c2d 2e2f       "#$%&'()*+,-./
    15:17:29.155004 IP 110.2.2.1 > 100.2.2.1: ICMP echo reply, id 24839, seq 7, length 64

The copy of incoming and outgoing packets via *eth2* is encapsulated
in a FPTUN header (ethertype 0x2007) and delivered to the Linux stack.

.. warning::

   Because the |bpf| filter is automatically synchronized, an application
   other than *tcpdump* (for example, a |dhcp| client), may trigger the
   configuration of the |fp| with a copy of all incoming packets and
   therefore impact performance.

   To disable automatic synchronization, run the |cmgr| with the *-D*
   option:

   .. code-block:: console

      # cmgr -D

   Then, to manually enable TAP per interface:

   .. code-block:: console

      # fp-cli
      <fp-0> set-tap-iface eth2 on

   The *tcpdump -i eth2* program will work the same as described in the
   case of automatic synchronization.

BPF management
--------------

dump-bpf
~~~~~~~~

.. rubric:: Description

Dump |bpf| filters.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-bpf

.. rubric:: Parameters

all
   All |bpf| with decoded instructions.
raw
   All |bpf| in raw format.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-bpf
   <fp-0> BPF list (ifuid 0 is the virtual interface "any"):
   96: ifuid 0x6008c1d2, instance 0 (# cmds: 1)
   518: ifuid 0x061a1e72, instance 0 (# cmds: 1)

set-tap-iface
~~~~~~~~~~~~~

.. rubric:: Description

Set manually the interface for tapping.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-tap-iface ifname|any on|off

.. rubric:: Parameters

ifname
   Interface name or any.
on|off
   Enable / disable TAP.

.. rubric:: Example

Enable TAP on eth2

.. code-block:: fp-cli

   <fp-0> set-tap-iface eth2 on
