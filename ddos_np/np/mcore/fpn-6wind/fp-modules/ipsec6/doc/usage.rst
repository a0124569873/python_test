Usage
=====

Before you begin
----------------

There is no runtime configuration for |ipsec|.

Please see the |fpipsec6| documentation, section *Before you begin* to perform the initial steps.

Configuration example
---------------------

The following example is relevant to an Ubuntu machine.

.. code-block:: console

   ip xfrm policy add dir fwd src 3ffe:110:9:9::1/128 dst 3ffe:100:9:9::1/128 index 0x80000062 priority 2000 tmpl  src 3ffe:9:11::5 dst 3ffe:9:11::1 proto esp reqid 99 mode tunnel
   ip xfrm policy add dir in  src 3ffe:110:9:9::1/128 dst 3ffe:100:9:9::1/128 index 0x80000058 priority 2000 tmpl  src 3ffe:9:11::5 dst 3ffe:9:11::1 proto esp reqid 99 mode tunnel
   ip xfrm policy add dir out src 3ffe:100:9:9::1/128 dst 3ffe:110:9:9::1/128 index 0x80000051 priority 2000 tmpl  src 3ffe:9:11::1 dst 3ffe:9:11::5 proto esp reqid 99 mode tunnel
   ip xfrm policy list
   src 3ffe:100:9:9::1/128 dst 3ffe:110:9:9::1/128
           dir out priority 2000 ptype main
           tmpl src 3ffe:9:11::1 dst 3ffe:9:11::5
                   proto esp reqid 99 mode tunnel
   src 3ffe:110:9:9::1/128 dst 3ffe:100:9:9::1/128
           dir in priority 2000 ptype main
           tmpl src 3ffe:9:11::5 dst 3ffe:9:11::1
                   proto esp reqid 99 mode tunnel
   src 3ffe:110:9:9::1/128 dst 3ffe:100:9:9::1/128
           dir fwd priority 2000 ptype main
           tmpl src 3ffe:9:11::5 dst 3ffe:9:11::1
                   proto esp reqid 99 mode tunnel

   # fp-cli

.. code-block:: fp-cli

   fpcmd dump-spd6 all
   IPv6 SPD hash lookup min prefix lengths: local=0, remote=0
   Inbound SPD: 1 rules
   1: 3ffe:110:9:9::1/128 3ffe:100:9:9::1/128 proto any vr0 protect prio 2000
        link-vr0
       ESP tunnel 3ffe:9:11::5 - 3ffe:9:11::1 reqid=99
        sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0
   Outbound SPD: 1 rules
   1: 3ffe:100:9:9::1/128 3ffe:110:9:9::1/128 proto any vr0 protect prio 2000
        link-vr0 cached-SA 0 genid 0
       ESP tunnel 3ffe:9:11::1 - 3ffe:9:11::5 reqid=99
        sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0

.. code-block:: console

   ip xfrm state add src 3ffe:9:11::5 dst 3ffe:9:11::1 spi 0x00000991 proto esp reqid 99 mode tunnel enc "cbc(des)" 0x706f6e672d2d3939
   ip xfrm state add src 3ffe:9:11::1 dst 3ffe:9:11::5 spi 0x00000432 proto esp reqid 99 mode tunnel enc "cbc(des)" 0x1974040657494E44

   ip xfrm state list
   src 3ffe:9:11::1 dst 3ffe:9:11::5
        proto esp spi 0x00000432 reqid 99 mode tunnel
        replay-window 0
        enc cbc(des) 0x1974040657494e44
        sel src ::/0 dst ::/0
   src 3ffe:9:11::5 dst 3ffe:9:11::1
        proto esp spi 0x00000991 reqid 99 mode tunnel
        replay-window 0
        enc cbc(des) 0x706f6e672d2d3939
        sel src ::/0 dst ::/0

.. code-block:: fp-cli

   <fp-0> dump-sad6 all
   IPv6 SAD 2 SA.
   1: 3ffe:9:11::5 - 3ffe:9:11::1 vr0 spi 0x991 ESP tunnel
         x-vr0 reqid=99 genid 1 cached-SP: 0
         output_blade=1
         DES-CBC
         key enc:706f6e672d2d3939
         sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
         sa_replay_errors=0 sa_selector_errors=0
         replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0
   2: 3ffe:9:11::1 - 3ffe:9:11::5 vr0 spi 0x432 ESP tunnel
         x-vr0 reqid=99 genid 2 cached-SP: 0
         output_blade=1
         DES-CBC
         key enc:1974040657494e44
         sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
         sa_replay_errors=0 sa_selector_errors=0
         replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0

Security associations management
--------------------------------

Please see the |fpipsec6| documentation: the commands to manage security associations are the same.

Security policies management
----------------------------

Please see the |fpipsec6| documentation: the commands to manage security policies are the same.

Statistics
----------

dump-spd6
~~~~~~~~~

.. rubric:: Description

Dump the |spd|.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-spd6 [all|raw]

.. rubric:: Parameters

No parameter
   Only dump the number of global IPv6 SPs.
all
   Display all global IPv6 SPs registered in the |fp| in order of priority.
raw
   Display all IPv6 SPs registered in the |fp| in the same order as in the internal table.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> dump-spd6
   IPv6 SPD hash lookup min prefix lengths: local=0, remote=0
   Inbound SPD: 1 rules
   Outbound SPD: 1 rules

.. code-block:: fp-cli

   <fp-0> dump-spd6 all
   IPv6 SPD hash lookup min prefix lengths: local=0, remote=0
   Inbound SPD: 1 rules
   1: 3ffe:110:9:9::1/128 3ffe:100:9:9::1/128 proto any vr0 protect prio 2000
        link-vr0
       ESP tunnel 3ffe:9:11::5 - 3ffe:9:11::1 reqid=99
        sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0
   Outbound SPD: 1 rules
   1: 3ffe:100:9:9::1/128 3ffe:110:9:9::1/128 proto any vr0 protect prio 2000
        link-vr0 cached-SA 0 genid 0
       ESP tunnel 3ffe:9:11::1 - 3ffe:9:11::5 reqid=99
        sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0

.. code-block:: fp-cli

   <fp-0> dump-spd6 raw
   IPv6 SPD hash lookup min prefix lengths: local=0, remote=0
   Inbound SPD: 1 total rules, 1 global rules
   1: 3ffe:110:9:9::1/128 3ffe:100:9:9::1/128 proto any vr0 protect prio 2000
        link-vr0
       ESP tunnel 3ffe:9:11::5 - 3ffe:9:11::1 reqid=99
        sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0
   Outbound SPD: 1 total rules, 1 global rules
   1: 3ffe:100:9:9::1/128 3ffe:110:9:9::1/128 proto any vr0 protect prio 2000
        link-vr0 cached-SA 0 genid 0
       ESP tunnel 3ffe:9:11::1 - 3ffe:9:11::5 reqid=99
        sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0

dump-sad6
~~~~~~~~~

.. rubric:: Description

Dump the |sad|. Dump all |sas|, or only a specific one.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-sad6 [all | [SADDR PREFIX_SADDR DADDR PREFIX_DADDR ah|esp]]

.. rubric:: Parameters

No parameters
   Only dump the number of IPv6 SAs present in the |fp| table.
all
   Dump all IPv6 SAs present in the |fp| table.
SADDR
   SA source IPv6 address.
PREFIX_SADDR
   Length (in bits) of the source IPv6 netmask prefix.
DADDR
   SA destination IPv6 address.
PREFIX_DADDR
   Length (in bits) of the destination IPv6 netmask prefix.
ah|esp
   |ah-esp|

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> dump-sad6
   IPv6 SAD 2 SA.

.. code-block:: fp-cli

   <fp-0> dump-sad6 all
   IPv6 SAD 2 SA.
   1: 3ffe:9:11::5 - 3ffe:9:11::1 vr0 spi 0x991 ESP tunnel
         x-vr0 reqid=99 genid 1 cached-SP: 0
         output_blade=1
         DES-CBC
         key enc:706f6e672d2d3939
         sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
         sa_replay_errors=0 sa_selector_errors=0
         replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0
   2: 3ffe:9:11::1 - 3ffe:9:11::5 vr0 spi 0x432 ESP tunnel
         x-vr0 reqid=99 genid 2 cached-SP: 0
         output_blade=1
         DES-CBC
         key enc:1974040657494e44
         sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
         sa_replay_errors=0 sa_selector_errors=0
         replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0

dump-sad6-spi-hash
~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Dump the |sad| |spi| hash table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-sad6-spi-hash [count|index|id|all]

.. rubric:: Parameters

.. include:: include/count-index-id-all.inc

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> dump-sad6-spi-hash
   hash table:
     total lines: 65536
     total entries: 2
   entries per line:
     average: 0.00 variance 0.00
     minimum: 0
     maximum: 1

.. code-block:: fp-cli

   <fp-0> dump-sad6-spi-hash count
   --hash key 12804: 1 entries
   --hash key 37129: 1 entries

.. code-block:: fp-cli

   <fp-0> dump-sad6-spi-hash index
   --hash key 12804: 2
   --hash key 37129: 1

.. code-block:: fp-cli

   <fp-0> dump-sad6-spi-hash id
   --hash key 12804: 0x432
   --hash key 37129: 0x991

.. code-block:: fp-cli

   <fp-0> dump-sad6-spi-hash all
   -- hash key 12804:
   2: 3ffe:9:11::1 - 3ffe:9:11::5 vr0 spi 0x432 ESP tunnel
         x-vr0 reqid=99 genid 2 cached-SP: 0
         output_blade=1
         DES-CBC
         key enc:1974040657494e44
         sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
         sa_replay_errors=0 sa_selector_errors=0
         replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0
   -- hash key 37129:
   1: 3ffe:9:11::5 - 3ffe:9:11::1 vr0 spi 0x991 ESP tunnel
         x-vr0 reqid=99 genid 1 cached-SP: 0
         output_blade=1
         DES-CBC
         key enc:706f6e672d2d3939
         sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
         sa_replay_errors=0 sa_selector_errors=0
         replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0

dump-sad6-selector-hash
~~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Dump the |sad| selector's hash table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-sad6-selector-hash [count|index|id|all]

.. rubric:: Parameters

.. include:: include/count-index-id-all.inc

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> dump-sad6-selector-hash
   hash table:
     total lines: 65536
     total entries: 2
   entries per line:
     average: 0.00 variance 0.00
     minimum: 0
     maximum: 2

.. code-block:: fp-cli

   <fp-0> dump-sad6-selector-hash count
   --hash key 14002: 2 entries

.. code-block:: fp-cli

   <fp-0> dump-sad6-selector-hash id
   --hash key 14002: 3ffe:9:11::1-3ffe:9:11::5/ESP 3ffe:9:11::5-3ffe:9:11::1/ESP

.. code-block:: fp-cli

   <fp-0> dump-sad6-selector-hash index
   --hash key 14002: 2 1

.. code-block:: fp-cli

   <fp-0> dump-sad6-selector-hash all
   -- hash key 14002:
   2: 3ffe:9:11::1 - 3ffe:9:11::5 vr0 spi 0x432 ESP tunnel
         x-vr0 reqid=99 genid 2 cached-SP: 0
         output_blade=1
         DES-CBC
         key enc:1974040657494e44
         sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
         sa_replay_errors=0 sa_selector_errors=0
         replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0
   1: 3ffe:9:11::5 - 3ffe:9:11::1 vr0 spi 0x991 ESP tunnel
         x-vr0 reqid=99 genid 1 cached-SP: 0
         output_blade=1
         DES-CBC
         key enc:706f6e672d2d3939
         sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
         sa_replay_errors=0 sa_selector_errors=0
         replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0

SA anti-replay window / output sequence number synchronization
--------------------------------------------------------------

.. note:: This part is only related to multiple fast paths.

.. seealso::

   See the |fpipsec6| documentation for a description of SA anti-replay window / output sequence number synchronization.

set-sa6-sync-threshold
~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Set the threshold (in packets) at which an update for
anti-replay window / output sequence number synchronization. is sent.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-sa6-sync-threshold THRESHOLD

.. rubric:: Parameters

THRESHOLD
   Overall threshold value.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-sa6-sync-threshold 64

show-sa6-sync-threshold
~~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Show the threshold (in packets) for which an update for
anti-replay window / output sequence number synchronization is sent.

.. rubric:: Synopsis

.. code-block:: fp-cli

   show-sa6-sync-threshold

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> show-sa6-sync-threshold
    IPv6 IPsec threshold between two sequence number sync messages is: 32

Extended Sequence Number
------------------------

.. include:: include/needs-iproute2-patch.inc

|ah|/|esp| headers support extended, 64 bit sequence numbers to detect replay.

A single |ipsec| |sa| can transfer a maximum of 2^64 |ipsec| packets.

.. rubric:: Example

#. Create an |sa| with |esn| support and a 128 packets replay window:

   .. code-block:: console

      $ ip xfrm state add src 3ffe:2:11::1 dst 3ffe:2:11::5 spi 0x00000220 proto esp reqid 22 mode tunnel \
      enc aes cle1goldorakgoldorakcle1 auth sha1 cle1goldorakgoldcle1 flag esn replay-window 128

#. Check that your configuration is correctly synchronized in the |fp|:

   .. code-block:: console

      $ fp-cli

   .. code-block:: fp-cli

      <fp-0> dump-sad6 all
      IPv6 SAD 1 SA.
      1: 3ffe:2:11::1 - 3ffe:2:11::5 vr0 spi 0x220 ESP tunnel
        x-vr0 reqid=22 counter 1 genid 1 cached-SP: 0
        output_blade=1
        AES-CBC HMAC-SHA1 esn
        key enc:636c6531676f6c646f72616b676f6c646f72616b636c6531
        digest length: 12
        key auth:636c6531676f6c646f72616b676f6c64636c6531
        sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
        sa_replay_errors=0 sa_selector_errors=0
        replay width=128 seq=0x0 - oseq=0x0
        00000000 00000000 00000000 00000000

.. seealso::

   :ref:`dependencies`

Large anti-replay window example
--------------------------------

.. include:: include/needs-iproute2-patch.inc

You can set the anti-replay window size between 32 and 4096 packets (maximum
size allowed by the Linux kernel).

.. rubric:: Example

#. Create an |sa| with a 256 packets replay window:

   .. code-block:: console

      $ ip xfrm state add src 3ffe:2:11::1 dst 3ffe:2:11::5 spi 0x00000220 proto esp reqid 22 mode tunnel \
      enc aes cle1goldorakgoldorakcle1 auth sha1 cle1goldorakgoldcle1 replay-window 256

#. Check that your configuration is correctly synchronized in the |fp|:

   .. code-block:: console

      $ fp-cli

   .. code-block:: fp-cli

      <fp-0> dump-sad6 all
      IPv6 SAD 1 SA.
      1: 3ffe:2:11::1 - 3ffe:2:11::5 vr0 spi 0x220 ESP tunnel
        x-vr0 reqid=22 counter 2 genid 2 cached-SP: 0
        output_blade=1
        AES-CBC HMAC-SHA1
        key enc:636c6531676f6c646f72616b676f6c646f72616b636c6531
        digest length: 12
        key auth:636c6531676f6c646f72616b676f6c64636c6531
        sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
        sa_replay_errors=0 sa_selector_errors=0
        replay width=256 seq=0x0 - oseq=0x0
        00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000

.. seealso::

   :ref:`dependencies`

IPv6 in IPv4 IPsec tunnel example
---------------------------------

We will encapsulate |ipv6| packets in a static |ipv4| |ipsec| tunnel.

#. Create the inbound |ipsec| endpoint:

   a. Create an |ipv4| |ipsec| |sa| for |ipv6| packets:

      .. code-block:: console

         $ ip xfrm state add src 2.1.0.5 dst 2.1.0.1 proto esp spi 0x00000221 mode tunnel \
         sel src ::/0 enc aes cle1goldorakgoldorakcle1 auth sha1 cle1goldorakgoldcle1

   #. Create an inbound |ipv6| |ipsec| |sp|:

      .. code-block:: console

         $ ip xfrm policy add src 3ffe:110:2:2::1/128 dst 3ffe:100:2:2::1/128 dir in \
         tmpl src 2.1.0.5 dst 2.1.0.1 proto esp mode tunnel

   #. Create a forward |ipv6| |ipsec| |sp|:

      .. code-block:: console

         $ip xfrm policy add src 3ffe:110:2:2::1/128 dst 3ffe:100:2:2::1/128 dir fwd \
         tmpl src 2.1.0.5 dst 2.1.0.1 proto esp mode tunnel

#. Create the outbound |ipsec| endpoint:

   a. Create an |ipv4| |ipsec| |sa| for |ipv4| packets:

      .. code-block:: console

         $ ip xfrm state add src 2.1.0.1 dst 2.1.0.5 proto esp spi 0x00000220 mode tunnel \
         sel src ::/0 enc aes cle1goldorakgoldorakcle2 auth sha1 cle1goldorakgoldcle2

   #. Create an outbound |ipv4| |ipsec| |sp|:

      .. code-block:: console

         $ ip xfrm policy add src 3ffe:100:2:2::1/128 dst 3ffe:110:2:2::1/128 dir out \
         tmpl src 2.1.0.1 dst 2.1.0.5 proto esp mode tunnel

#. Check that your configuration is correctly synchronized in the |fp|:

   a. Start *fp-cli*:

      .. code-block:: console

         $ fp-cli

   #. Display the |sas| in the |fpipsec4| table:

      .. code-block:: fp-cli

         <fp-0> dump-sad all
         SAD 2 SA.
         1: 2.1.0.5 - 2.1.0.1 vr0 spi 0x221 ESP tunnel
           x-vr0 counter 1 cached-SP 0 (genid 1)
           output_blade=1
           AES-CBC HMAC-SHA1
           key enc:636c6531676f6c646f72616b676f6c646f72616b636c6531
           digest length: 12
           key auth:636c6531676f6c646f72616b676f6c64636c6531
           sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
           sa_replay_errors=0 sa_selector_errors=0
           replay width=0 seq=0x0 - oseq=0x0
         2: 2.1.0.1 - 2.1.0.5 vr0 spi 0x220 ESP tunnel
           x-vr0 counter 1 cached-SP 0 (genid 2)
           output_blade=1
           AES-CBC HMAC-SHA1
           key enc:636c6531676f6c646f72616b676f6c646f72616b636c6532
           digest length: 12
           key auth:636c6531676f6c646f72616b676f6c64636c6532
           sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
           sa_replay_errors=0 sa_selector_errors=0
           replay width=0 seq=0x0 - oseq=0x0

   #. Display the |sps| in the |fpipsec6| table:

      .. code-block:: fp-cli

         <fp-0> dump-spd6 all
         IPv6 SPD hash lookup min prefix lengths: local=0, remote=0
         Inbound SPD: 1 rules
         1: 3ffe:110:2:2::1/128 3ffe:100:2:2::1/128 proto any vr0 protect prio 0
           link-vr0
          ESP tunnel 2.1.0.5 - 2.1.0.1
           sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0
         Outbound SPD: 1 rules
         1: 3ffe:100:2:2::1/128 3ffe:110:2:2::1/128 proto any vr0 protect prio 0
           link-vr0 cached-SA 0 genid 0
          ESP tunnel 2.1.0.1 - 2.1.0.5
           sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0

.. seealso::

   To dynamically configure |ipsec| tunnels, see the |cp-ike| documentation.
