Usage
=====

To use Linux synchronization, start the |cmgr| and the |fpm|:

.. code-block:: console

   # modprobe ifuid
   # modprobe fptun
   # modprobe nf_conntrack_netlink
   # fpmd
   # cmgrd

.. rubric:: Example

.. code-block:: console

   # echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
   # ip link set eth1 up
   # ip link set eth2 up
   # ip ad ad 3ffe:2:100::1/64 dev eth1
   # ip ad ad 3ffe:2:110::1/64 dev eth2
   # ip route add 3ffe:110:2:2::1/128 via 3ffe:2:11::5
   # ip route add 3ffe:100:2:2::1/128 via 3ffe:2:10::5
   # ip6tables -F
   # ip6tables -P INPUT ACCEPT
   # ip6tables -P FORWARD ACCEPT
   # ip6tables -P OUTPUT ACCEPT
   # ip6tables -A FORWARD -p icmpv6 -s 3ffe:110:2:2::1 -j DROP
   # ip6tables -A FORWARD -p icmpv6 -s 3ffe:100:2:2::1 -j DROP
   # ip6tables -nL
   Chain INPUT (policy ACCEPT)
   target     prot opt source               destination

   Chain FORWARD (policy ACCEPT)
   target     prot opt source               destination
   DROP       icmpv6    3ffe:110:2:2::1/128  ::/0
   DROP       icmpv6    3ffe:100:2:2::1/128  ::/0

   Chain OUTPUT (policy ACCEPT)
   target     prot opt source               destination

   # fpcmd dump-nftable 6 filter all
   Bypass netfilter hook: no
   NF Table: filter (family: IPv6)
                pre   in  fwd  out post
   Valid hook:         x    x    x
   Hooks:         0    0    1    4    0
   Underflows:    0    0    3    4    0
   Rule #1 (uid:0x0):
        Stats: pkt: 0, byte: 0
        IPv6 header:
                Src:   3ffe:0110:0002:0002:0000:0000:0000:0001
                smask: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
                Dst:   0000:0000:0000:0000:0000:0000:0000:0000
                dmask: 0000:0000:0000:0000:0000:0000:0000:0000
                In iface: , len: 0
                Out iface: , len: 0
                Proto: 58, Flags: 1, Invflags: 0
        VRF-ID: all
        Target: STANDARD, verdict: FP_NF_DROP
   Rule #2 (uid:0x0):
        Stats: pkt: 155, byte: 16120
        IPv6 header:
                Src:   3ffe:0100:0002:0002:0000:0000:0000:0001
                smask: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
                Dst:   0000:0000:0000:0000:0000:0000:0000:0000
                dmask: 0000:0000:0000:0000:0000:0000:0000:0000
                In iface: , len: 0
                Out iface: , len: 0
                Proto: 58, Flags: 1, Invflags: 0
        VRF-ID: all
        Target: STANDARD, verdict: FP_NF_DROP

Filtering management
--------------------

netfilter6
~~~~~~~~~~

.. rubric:: Description

Enable IPv6 filtering in |fp|. Not enabled by default. Automatically set to
*on* when configuring Netfilter rules with the |cmgr| running.

.. rubric:: Synopsis

.. code-block:: fp-cli

   netfilter [on|off]

.. rubric:: Parameters

No parameter
   Display Netfilter status (*on* or *off*).
on|off
   Enable or disable Netfilter.

.. code-block:: fp-cli

   <fp-0> netfilter6
   netfilter6 is on

dump-nftable
~~~~~~~~~~~~

.. rubric:: Description

Dump a Netfilter table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-nftable 4|6 [name] filter|mangle [all|nonzero]

.. rubric:: Parameters

4|6
   Version of the IP protocol.
name
   Name of the Netfilter table to dump.
filter|mangle
   Display the filter table or the mangle table.
all|nonzero
   Dump all rules or only rules with non null statistics.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-nftable 6 filter  nonzero
   Bypass netfilter hook: no
   NF Table: filter (family: IPv6)
                pre   in  fwd  out post
   Valid hook:         x    x    x
   Hooks:         0    0    1    4    0
   Underflows:    0    0    3    4    0
   Rule #2 (uid:0x0):
        Stats: pkt: 391, byte: 40664
        IPv6 header:
                Src:   3ffe:0100:0002:0002:0000:0000:0000:0001
                smask: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
                Dst:   0000:0000:0000:0000:0000:0000:0000:0000
                dmask: 0000:0000:0000:0000:0000:0000:0000:0000
                In iface: , len: 0
                Out iface: , len: 0
                Proto: 58, Flags: 1, Invflags: 0
        VRF-ID: all
        Target: STANDARD, verdict: FP_NF_DROP
   Rule #3 (uid:0x0):
        Stats: pkt: 676, byte: 70304
        IPv6 header:
                Src:   0000:0000:0000:0000:0000:0000:0000:0000
                smask: 0000:0000:0000:0000:0000:0000:0000:0000
                Dst:   0000:0000:0000:0000:0000:0000:0000:0000
                dmask: 0000:0000:0000:0000:0000:0000:0000:0000
                In iface: , len: 0
                Out iface: , len: 0
                Proto: 0, Flags: 0, Invflags: 0
        VRF-ID: all
        Target: STANDARD, verdict: FP_NF_ACCEPT

dump-nf6ct
~~~~~~~~~~

.. rubric:: Description

Dump the Netfilter IPv6 conntrack table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-nf6ct [NUMBER_OF_ENTRIES]

.. rubric:: Parameters

NUMBER_OF_ENTRIES
   Maximum number of conntrack entries to display simultaneously.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-nf6ct
   Number of flows: 1/1024
   Flow: #0 - uid #00000000
        Proto: 6
        Original: src: 3ffe:0100:0002:0002:0000:0000:0000:0001:6050
                  dst: 3ffe:0110:0002:0002:0000:0000:0000:0001:6050
        Reply:    src: 3ffe:0110:0002:0002:0000:0000:0000:0001:6050
                  dst: 3ffe:0100:0002:0002:0000:0000:0000:0001:6050
        VRF-ID: 0
        Flag: 0x91, update: no, assured: yes, end: yes
        Stats:
                Original: pkt: 99, bytes: 32216
                Reply:    pkt: 49, bytes: 28616

set-conntrack6-hitflags
~~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Configure the *conntrack6* refresh policy.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-conntrack6-hitflags PERIOD MAX_SCANNED MAX_SENT

.. rubric:: Parameters

PERIOD
   Period in seconds of connection track checking.
MAX_SCANNED
   Maximum number of conntracks to scan on a given period of time.
MAX_SENT
   Maximum number of refresh messages to send over a given period of time.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-conntrack6-hitflags 7 500 500

nf-hook6
~~~~~~~~

.. rubric:: Description

Show, enable, or disable hooks in *nf6_conf*.

.. rubric:: Synopsis

.. code-block:: fp-cli

   nf-hook6 [TABLE|all_tables HOOK|all_hooks on|off]

.. rubric:: Parameters

No parameter
   Show all hooks present in the *nf6_conf* structure.
TABLE|all_tables
   The table the hook belongs to. *all_tables* means all hooks in all tables.
HOOK|all_hooks
   The hook to enable or disable. *all_hooks* means all hooks within the table
   selected just before.
on|off
   Enable or disable the hook.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> nf-hook6
   filter local_in: off
   filter forward: on
   filter local_out: on
   mangle pre_routing: off
   mangle local_in: off
   mangle forward: off
   mangle local_out: off
   mangle post_routing: on

dump-nf6hook
~~~~~~~~~~~~

.. rubric:: Description

Dump the hook priority table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-nf6hook

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-nf6hook
   FP_NF_IP_PRE_ROUTING:
          mangle
   FP_NF_IP_LOCAL_IN:
          filter mangle
   FP_NF_IP_FORWARD:
          mangle filter
   FP_NF_IP_LOCAL_OUT:
          filter mangle
   FP_NF_IP_POST_ROUTING:
          mangle

nf6-cache
~~~~~~~~~

.. rubric:: Description

Show, enable, or disable the IPv6 Netfilter cache.

.. rubric:: Synopsis

.. code-block:: fp-cli

   nf6-cache [on|off]

.. rubric:: Parameters

on|off
   Enable or disable selector.

.. rubric:: Example

.. code-block:: console

   <fp-0> nf6-cache
   nf6-cache is on

dump-nf6-cache
~~~~~~~~~~~~~~

.. rubric:: Description

Dump |fp| Netfilter IPv6 cache entries.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-nf6-cache [NUM [COUNT DETAILS]]

.. rubric:: Parameters

NUM
   Maximum number of cache lines to display.
COUNT_DETAILS
   Level of data displayed per cache line. Only value 1 is significant and
   displays the packet mask that should match the conntrack rule.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-nf6-cache
   2: 3ffe:100:2:2::1 -> 3ffe:110:2:2::1 tcclass 0x0 TCP sport 6050 dport 6050 flags AP--- vr 0 indev 577769779 outdev 3535865952 table 0 hook 2 direct-accept
        #1 (uid:0x0): target STANDARD, verdict: FP_NF_ACCEPT
   3: 3ffe:110:2:2::1 -> 3ffe:100:2:2::1 tcclass 0x0 TCP sport 6050 dport 6050 flags AP--- vr 0 indev 3535865952 outdev 577769779 table 0 hook 2 direct-accept
        #1 (uid:0x0): target STANDARD, verdict: FP_NF_ACCEPT

nf6-cache-invalidate
~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Invalidate *fp-nf6-cache*.

.. rubric:: Synopsis

.. code-block:: fp-cli

   nf6-cache-invalidate

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> nf6-cache-invalidate
   <fp-0> dump-nf6-cache
   Max cached rules per entry is 11
