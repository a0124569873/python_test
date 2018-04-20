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

 # echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
 # ip link set eth1 up
 # ip link set eth2 up
 # ip ad ad 2.0.0.1/24 dev eth1
 # ip ad ad 2.1.0.1/24 dev eth2
 # ip route add 100.2.2.1/32 via 2.0.0.5
 # ip route add 110.2.2.1/32 via 2.1.0.5
 # iptables -A FORWARD -s 100.2.2.1 -j DROP
 # iptables -nL
 Chain INPUT (policy ACCEPT)
 target     prot opt source               destination

 Chain FORWARD (policy ACCEPT)
 target     prot opt source               destination
 DROP       all  --  100.2.2.1            0.0.0.0/0

 Chain OUTPUT (policy ACCEPT)
 target     prot opt source               destination

Filtering management
--------------------

netfilter
~~~~~~~~~

.. rubric:: Description

Enable IPv4 filtering in the |fp|. Not enabled by default. Automatically
set to *on* when configuring Netfilter rules with the |cmgr| running.

.. rubric:: Synopsis

.. code-block:: fp-cli

   netfilter [on|off]

.. rubric:: Parameters

No parameter
   Display Netfilter status (*on* or *off*).
on|off
   Enable or disable Netfilter.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> netfilter
   netfilter is off

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
   Dump all rules or only ones with non null statistics.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-nftable 4 filter  nonzero
   Bypass netfilter hook: no
   NF Table: filter (family: IPv4)
                pre   in  fwd  out post
   Valid hook:         x    x    x
   Hooks:         0    0    1    3    0
   Underflows:    0    0    2    3    0
   Rule #1 (uid:0x0):
          Stats: pkt: 4, byte: 336
          IPv4 header:
                  Src: 100.2.2.1, mask: 255.255.255.255
                  Dst: 0.0.0.0, mask: 0.0.0.0
                  In iface: , len: 0
                  Out iface: , len: 0
                  Proto: 0, Flags: 0, Invflags: 0
           Target: STANDARD, verdict: FP_NF_DROP
    Rule #2 (uid:0x0):
           Stats: pkt: 6, byte: 504
           IPv4 header:
                   Src: 0.0.0.0, mask: 0.0.0.0
                   Dst: 0.0.0.0, mask: 0.0.0.0
                   In iface: , len: 0
                   Out iface: , len: 0
                   Proto: 0, Flags: 0, Invflags: 0
           Target: STANDARD, verdict: FP_NF_ACCEP

nf-hook
~~~~~~~

.. rubric:: Description

Show, enable, or disable hooks in *nf_conf*.

.. rubric:: Synopsis

.. code-block:: fp-cli

   nf-hook [TABLE|all_tables HOOK|all_hooks on|off]

.. rubric:: Parameters

No parameter
   Show all hooks present in the *nf_conf* structure.
TABLE|all_tables
   The table the hook belongs to. *all_tables* means all hooks in all tables.
HOOK|all_hooks
   The hook to enable or disable. *all_hooks* means all hooks within the table
   selected just before.
on|off
   Enable or disable the hook.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> nfhook  all_tables all_hooks on
   Set filter local_in: on
   Set filter forward: on
   Set filter local_out: on
   Set mangle pre_routing: on
   Set mangle local_in: on
   Set mangle forward: on
   Set mangle local_out: on
   Set mangle post_routing: on
   Set nat pre_routing: on
   Set nat local_in: on
   Set nat local_out: on
   Set nat post_routing: on

dump-nfhook
~~~~~~~~~~~

.. rubric:: Description

Dump the hook priority table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-nfhook

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-nfhook
   FP_NF_IP_PRE_ROUTING:

   FP_NF_IP_LOCAL_IN:
          filter
   FP_NF_IP_FORWARD:
          filter
   FP_NF_IP_LOCAL_OUT:
          filter
   FP_NF_IP_POST_ROUTING:

dump-nfct
~~~~~~~~~

.. rubric:: Description

Dump the Netfilter conntrack table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-nfct [NUMBER_OF_ENTRIES] [summary]

.. rubric:: Parameters

NUMBER_OF_ENTRIES
   Maximum number of conntrack to display at once.
summary
   Shorten displayed data to one line per conntrack.

.. rubric:: Example

.. code-block:: console

   # iptables -F
   # iptables -P INPUT DROP
   # iptables -P FORWARD DROP
   # iptables -P OUTPUT DROP
   # iptables -A FORWARD -i eth1 -o eth2 -p tcp --dport 6050 -m state --state NEW,ESTABLISHED -j ACCEPT
   # iptables -A FORWARD -i eth2 -o eth1 -p tcp --sport 6050 -m state --state NEW,ESTABLISHED -j ACCEPT
   # fp-cli
   <fp-0> dump-nfct
   <fp-0> Number of flows: 1/1024
   Flow: #0 - uid #00000000
          Proto: 6
          Original: src: 100.2.2.1:6050 -> dst: 110.2.2.1:6050
          Reply:    src: 110.2.2.1:6050 -> dst: 100.2.2.1:6050
          VRF-ID: 0
          Flag: 0x13, update: yes, snat: no, dnat: no,
                      assured: yes, end: no
          Stats:
                  Original: pkt: 24, bytes: 7392
                     Reply:    pkt: 13, bytes: 6820
   <fp-0> dump-nfct 1 summary
   <fp-0> Number of flows: 1/1024
       index/uid          proto                 original                                  reply                                   stats            flags
   #00000000/#00000000     00006   100.2.2.1:6050 -> 110.2.2.1:6050        | 110.2.2.1:6050 -> 100.2.2.1:6050      [       100 pkt|     30800 B|        51 pkt|     28252 B]       VR0      [ASSURED] [END]

nf-cache
~~~~~~~~

.. rubric:: Description

Show, enable or disable the Netfilter cache.

.. rubric:: Synopsis

.. code-block:: fp-cli

   nf-cache [on|off]

.. rubric:: Parameters

No parameter
   Display the status of the Netfilter cache in the |fp|, set to *on* by
   default.
on|off
   Enable or disable selector.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> nf-cache
   nf-cache is on

dump-nf-cache
~~~~~~~~~~~~~

.. rubric:: Description

Dump |fp| Netfilter cache entries.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-nf-cache [NUM [COUNT DETAILS]]

.. rubric:: Parameters

NUM
   Maximum number of cache lines to display.
COUNT_DETAILS
   Level of data displayed per cache line. Only value 1 is significant and
   displays the paquet mask that should match the conntrack rule.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-nf-cache
   <fp-0> Max cached rules per entry is 8
   9: 110.2.2.1 -> 100.2.2.1 tos 0 frag_flags 0x2 TCP sport 6050 dport 6050 flags A---- vr 0 indev 0x6008c1d2 outdev 0x33117022 table 0 hook 2 direct-accept
          #1 (uid:0x0): target STANDARD, verdict: FP_NF_ACCEPT
   10: 110.2.2.1 -> 100.2.2.1 tos 0 frag_flags 0x2 TCP sport 6050 dport 6050 flags AP--- vr 0 indev 0x6008c1d2 outdev 0x33117022 table 0 hook 2 direct-accept
          #1 (uid:0x0): target STANDARD, verdict: FP_NF_ACCEPT
   11: 100.2.2.1 -> 110.2.2.1 tos 0 frag_flags 0x2 TCP sport 6050 dport 6050 flags A---- vr 0 indev 0x33117022 outdev 0x6008c1d2 table 0 hook 2 direct-accept
          #1 (uid:0x0): target STANDARD, verdict: FP_NF_ACCEPT
   12: 100.2.2.1 -> 110.2.2.1 tos 0 frag_flags 0x2 TCP sport 6050 dport 6050 flags AP--- vr 0 indev 0x33117022 outdev 0x6008c1d2 table 0 hook 2 direct-accept
          #1 (uid:0x0): target STANDARD, verdict: FP_NF_ACCEPT

nf-cache-invalidate
~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Invalidate *fp-nf-cache*.

.. rubric:: Synopsis

.. code-block:: fp-cli

   nf-cache-invalidate

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> nf-cache-invalidate
   <fp-0> dump-nf-cache
   Max cached rules per entry is 8

set-conntrack-hitflags
~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Configure the conntrack refresh policy.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-conntrack-hitflags PERIOD MAX_SCANNED MAX_SENT

.. rubric:: Parameters

PERIOD
   Period in seconds of connection track checking.
MAX_SCANNED
   Maximum number of conntracks to scan on a given period of time.
MAX_SENT
   Maximum number of refresh messages to send over a given period of time.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-conntrack-hitflags 5 1000 1000
