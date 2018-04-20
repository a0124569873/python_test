Usage
=====

Before you begin
----------------

There is no runtime configuration for |ipsec|.

When using the Linux synchronization, enable |ipsec| offload to |fp| for
packets issued by the Linux stack using a filter rule:

.. code-block:: console

   # modprobe nf-fptun
   # iptables -t fptun -A POSTROUTING -m policy --dir out --pol ipsec -j IPSECOUT

The default |fp| that will handle the |sa| is
managed by the *blade-ipsec* module:

.. code-block:: console

   # modprobe blade-ipsec
   # echo 1 > /proc/sys/blade-ipsec/default_fp

Configuration example
---------------------

The following example is relevant to an Ubuntu machine.

.. code-block:: console

   # apt-get install ipsec-tools
   # ip a a 10.22.4.104/24 dev eth1
   # ip a a 10.23.4.104/24 dev eth3
   # route add default gateway 10.23.4.204 dev eth3
   # setkey -c
   flush;
   spdflush;
   add -n4 10.23.4.104 10.23.4.204 esp 4096
          -m tunnel -E 3des-cbc "cle1_cle1_crik_crok_cle1" -A hmac-sha256 "cle1pouetpouetpouetpouetpouecle1";
   add -n4 10.23.4.204 10.23.4.104 esp 4352
          -m tunnel -E 3des-cbc "cle2_cle2_crac_crac_cle2" -A hmac-sha256 "cle2pouetpouetpouetpouetpouecle2";
   spdadd -4 -n 10.22.4.118/32 10.24.4.119/32 any -P out prio 2000 ipsec
          esp/tunnel/10.23.4.104-10.23.4.204/require ;
   spdadd -n4 10.24.4.119/32 10.22.4.118/32 any -P in prio 2000 ipsec
          esp/tunnel/10.23.4.204-10.23.4.104/require ;
   [Ctrl+D]
   # setkey -D
   10.23.4.204 10.23.4.104
          esp mode=tunnel spi=4352(0x00001100) reqid=0(0x00000000)
          E: 3des-cbc  636c6532 5f636c65 325f6372 61635f63 7261635f 636c6532
          A: hmac-sha256  636c6532 706f7565 74706f75 6574706f 75657470 6f756574 706f7565 636c6532
          seq=0x00000000 replay=0 flags=0x00000000 state=mature
          created: Jun 25 17:50:44 2013   current: Jun 25 18:50:19 2013
          diff: 3575(s)   hard: 0(s)      soft: 0(s)
          last:                           hard: 0(s)      soft: 0(s)
          current: 0(bytes)       hard: 0(bytes)  soft: 0(bytes)
          allocated: 0    hard: 0 soft: 0
          sadb_seq=1 pid=3277 refcnt=0
   10.23.4.104 10.23.4.204
          esp mode=tunnel spi=4096(0x00001000) reqid=0(0x00000000)
          E: 3des-cbc  636c6531 5f636c65 315f6372 696b5f63 726f6b5f 636c6531
          A: hmac-sha256  636c6531 706f7565 74706f75 6574706f 75657470 6f756574 706f7565 636c6531
          seq=0x00000000 replay=0 flags=0x00000000 state=mature
          created: Jun 25 17:50:44 2013   current: Jun 25 18:50:19 2013
          diff: 3575(s)   hard: 0(s)      soft: 0(s)
          last:                           hard: 0(s)      soft: 0(s)
          current: 0(bytes)       hard: 0(bytes)  soft: 0(bytes)
          allocated: 0    hard: 0 soft: 0
          sadb_seq=0 pid=3277 refcnt=0

   # setkey -DP
   10.24.4.119 10.22.4.118 any
          fwd prio def + 2000 ipsec
          esp/tunnel/10.23.4.204-10.23.4.104/require
          created: Jun 25 17:50:44 2013  lastused:
          lifetime: 0(s) validtime: 0(s)
          spid=66 seq=1 pid=3276
          refcnt=1
   10.24.4.119 10.22.4.118 any
          in prio def + 2000 ipsec
          esp/tunnel/10.23.4.204-10.23.4.104/require
          created: Jun 25 17:50:44 2013  lastused:
          lifetime: 0(s) validtime: 0(s)
          spid=56 seq=2 pid=3276
          refcnt=1
   10.22.4.118 10.24.4.119 any
          out prio def + 2000 ipsec
          esp/tunnel/10.23.4.104-10.23.4.204/require
          created: Jun 25 17:50:44 2013  lastused:
          lifetime: 0(s) validtime: 0(s)
          spid=49 seq=3 pid=3276
          refcnt=1
   # fp-cli

.. code-block:: fp-cli

   <fp-0> dump-sad all
   SAD 2 SA.
   1: 10.23.4.104 - 10.23.4.204 vr0 spi 0x1000 ESP tunnel
       x-vr0 genid 1 cached-SP 0
       3DES-CBC HMAC-SHA256
       key enc:636c65315f636c65315f6372696b5f63726f6b5f636c6531
       key auth:636c6531706f756574706f756574706f756574706f756574706f7565636c6531
       sa_packets=693 sa_bytes=58212 sa_auth_errors=0 sa_decrypt_errors=0
       sa_replay_errors=0 sa_selector_errors=0
       replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=693
   2: 10.23.4.204 - 10.23.4.104 vr0 spi 0x1100 ESP tunnel
       x-vr0 genid 2 cached-SP 3
       3DES-CBC HMAC-SHA256
       key enc:636c65325f636c65325f637261635f637261635f636c6532
       key auth:636c6532706f756574706f756574706f756574706f756574706f7565636c6532
       sa_packets=693 sa_bytes=97020 sa_auth_errors=0 sa_decrypt_errors=0
       sa_replay_errors=0 sa_selector_errors=0
       replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0

.. code-block:: fp-cli

   <fp-0> dump-spd all
   SPD hash lookup min prefix lengths: local=0, remote=0
   Inbound SPD: 3 rules
   1: 10.24.4.119/32 10.22.4.118/32 proto 17 vr0 protect prio 2147481648
       link-vr0
       ESP tunnel 10.23.4.204 - 10.23.4.104
       sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0
   2: 10.24.4.119/32 10.22.4.118/32 proto 6 vr0 protect prio 2147481648
       link-vr0
       ESP tunnel 10.23.4.204 - 10.23.4.104
       sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0
   3: 10.24.4.119/32 10.22.4.118/32 proto 1 vr0 protect prio 2147481648
       link-vr0
       ESP tunnel 10.23.4.204 - 10.23.4.104
       sp_packets=693 sp_bytes=58212 sp_exceptions=0 sp_errors=0
   Outbound SPD: 3 rules
   1: 10.22.4.118/32 10.24.4.119/32 proto 17 vr0 protect prio 2147481648
       link-vr0 cached-SA 0 genid 0
       ESP tunnel 10.23.4.104 - 10.23.4.204
       sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0
   2: 10.22.4.118/32 10.24.4.119/32 proto 6 vr0 protect prio 2147481648
       link-vr0 cached-SA 0 genid 0
       ESP tunnel 10.23.4.104 - 10.23.4.204
       sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0
   3: 10.22.4.118/32 10.24.4.119/32 proto 1 vr0 protect prio 2147481648
       link-vr0 cached-SA 1 genid 1
       ESP tunnel 10.23.4.104 - 10.23.4.204
       sp_packets=693 sp_bytes=58212 sp_exceptions=2 sp_errors=0

Security associations management
--------------------------------

add-sa
~~~~~~

.. rubric:: Description

Create an IPv4 |ipsec| |sa|.

.. rubric:: Synopsis

.. code-block:: fp-cli

   add-sa ah|esp SADDR DADDR SPI MODE [options]

.. rubric:: Parameters

ah|esp
   |ah-esp|
SADDR
   |sa| source ip address.
DADDR
   |sa| destination ip address.
SPI
   |spi| number of the |sa|.
MODE
   |ipsec| mode to choose between tunnel/transport.
options
   Any combination of the following options:

   enc aes-cbc|3des-cbc|des-cbc KEY
       KEY is the encryption key, its size must match the selected algorithm.
   auth hmac-sha1|hmac-md5|hmac-sha256|hmac-sha384|hmac-sha512|aes-xcbc KEY
       KEY is the authentication key, its size must match the selected algorithm.
   vr
      |vr-desc|
   xvr XVR
      Id of the XVRF where the |sa| is created.
   svti
      Interface name in human reading form.
   reqid
      |reqid|
   replaywin SIZE
      Number of sequences in replay window.
   encapdscp
      In |ipsec| output in tunnel mode, enable |dscp| copy from inner to outer
      header.
   decapdscp
      In |ipsec| input in tunnel mode, enable |dscp| copy from outer to inner header
      when decapsulating.
      Disable UDP encapsulation for |esp| packets.
   nopmtudisc
      Do not copy the |df| bit when encapsulating data.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> add-sa esp 192.168.12.75 192.168.12.74 0x75b0 tunnel enc aes-cbc 0x47afa23e1bc5c9c72459364921bb0585 auth hmac-sha1 0xfd9b424c99c1ca76e10f62a4cb3f92664421922c

del-sa
~~~~~~

.. rubric:: Description

Delete an IPv4 |ipsec| |sa|.

.. rubric:: Synopsis

.. code-block:: fp-cli

   del-sa ah|esp DADDR SPI [vr]

.. rubric:: Parameters

ah|esp
   |ah-esp|
DADDR
   |sa| destination ip address.
SPI
   |spi| number of the |sa|.
vr
   Id of the |vrf| of the |sa| to delete.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> del-sa esp 192.168.12.74 0x75b0

flush-sa
~~~~~~~~

.. rubric:: Description

Flush IPv4 |ipsec| |sas| per |vr|.

.. rubric:: Synopsis

.. code-block:: fp-cli

   flush-sa [vr]

.. rubric:: Parameters

vr
   Id of the |vrf| of the |sa| to delete.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0>  flush-sa

Security policies management
----------------------------

add-sp
~~~~~~

.. rubric:: Description

Creates an IPv4 |ipsec| |sp|.

.. rubric:: Synopsis

.. code-block:: fp-cli

   add-sp in|out SADDR DADDR PROTO bypass|discard|(ah|esp (tunnel SADDRTUN DADDRTUN)|transport) PRIORITY [vr] [lvr] [svti] [reqid]

.. rubric:: Parameters

in|out
   Direction of the |sp|.
SADDR
   |sp| source ip address.
DADDR
   |sp| destination ip address.
PROTO
   |proto-sp|
bypass
   Forward plaintext.
discard
   Drop packets.
ah|esp
   |ah-esp|
tunnel
   |ipsec| mode tunnel, must provide SADDRTUN and DADDRTUN.
SADDRTUN
   Source ip of tunnel.
DADDRTUN
   Destination ip of tunnel.
transport
   |ipsec| mode transport.
PRIORITY
   Priority of the |sp| among others.
options
   Any combination of the following options:

   vr
      |vr-desc|
   lvr
      Id of the |vrf| link where the |sp|
      is created.
   svti
      Interface name in human reading form.
   reqid
      |reqid|

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> add-sp out 10.0.0.0/24 20.0.0.0/24 255 esp tunnel 192.168.12.75 192.168.12.74 2000

.. code-block:: fp-cli

   <fp-0> dump-spd all
   SPD hash lookup min prefix lengths: local=0, remote=0
   Inbound SPD: 0 rules
   Outbound SPD: 1 rules
   1: 10.0.0.0/24 20.0.0.0/24 proto any vr0 protect prio 2000
        link-vr0 cached-SA 0 genid 0
        ESP tunnel 192.168.12.75 - 192.168.12.74
        sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0

update-sp
~~~~~~~~~

.. rubric:: Description

Update an IPv4 |ipsec| |sp|.

.. rubric:: Synopsis

.. code-block:: fp-cli

   update-sp in|out SADDR DADDR PROTO bypass|discard|(ah|esp (tunnel SADDRTUN DADDRTUN)|transport) PRIORITY [vr] [lvr] [svti] [reqid]

.. rubric:: Parameters

in|out
   Direction of the |sp|.
SADDR
   |sp| source ip address.
DADDR
   |sp| destination ip address.
PROTO
   Protocol handled by the |sp|, choose between "any" or the protocol id as
   declared in IPv4 header (example: UDP=17
   TCP=6, ICMP=1).
bypass
   Forward plaintext.
discard
   Drop packets.
ah|esp
   |ah-esp|
tunnel
   |ipsec| mode tunnel, must provide SADDRTUN and DADDRTUN.
SADDRTUN
   Source ip of tunnel.
DADDRTUN
   Destination ip of tunnel.
transport
   |ipsec| mode transport.
PRIORITY
   Priority of the |sp| among others.
options
   Any combination of the following options:

   vr
      |vr-desc|
   lvr
      Id of the |vrf| link where the |sp|
      is created.
   svti
      Interface name in human reading form.
   reqid
      |reqid|

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> update-sp out 10.0.0.0/24 20.0.0.0/24 255 esp tunnel 192.168.12.75 192.168.12.76 2000

.. code-block:: fp-cli

   <fp-0> dump-spd all
   SPD hash lookup min prefix lengths: local=0, remote=0
   Inbound SPD: 0 rules
   Outbound SPD: 1 rules
   1: 10.0.0.0/24 20.0.0.0/24 proto any vr0 protect prio 2000
        link-vr0 cached-SA 0 genid 0
        ESP tunnel 192.168.12.75 - 192.168.12.76
        sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0

del-sp
~~~~~~

.. rubric:: Description

Delete an IPv4 |ipsec| |sp|.

.. rubric:: Synopsis

.. code-block:: fp-cli

   del-sp in|out SADDR DADDR PROTO [vr] [svti]

.. rubric:: Parameters

in|out
   Direction of the |sp|.
SADDR
   |sp| source ip address.
DADDR
   |sp| destination ip address.
PROTO
   |proto-sp|
vr
   |vr-desc|
svti
   Interface name in human reading form.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> del-sp out 10.0.0.0/24 20.0.0.0/24 255

flush-sp
~~~~~~~~

.. rubric:: Description

Flush IPv4 |ipsec| |sps| per-vr or per-svti.

.. rubric:: Synopsis

.. code-block:: fp-cli

   flush-sp [vr] [svti]

.. rubric:: Parameters

vr
   |vr-desc|
svti
   Interface name in human reading form.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> flush-sp

Statistics
----------

dump-spd
~~~~~~~~

.. rubric:: Description

Dump the |spd|.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-spd [all|raw]

.. rubric:: Parameters

No parameter
   Only dump the number of global |sps|.
all
   Display all global |sps| registered in the |fp| in order of priority.
raw
   Display all |sps| registered in the |fp| in the same order as in the
   internal table.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> dump-spd
   Inbound SPD: 2 rules
   Outbound SPD: 2 rules

.. code-block:: fp-cli

   <fp-0> dump-spd all
   SPD hash lookup min prefix lengths: local=0, remote=0
   Inbound SPD: 2 rules
   3: 10.24.4.119/32 10.22.4.118/32 proto 17 vr0 protect prio 2000
       link-vr0
       ESP tunnel 10.23.4.204 - 10.23.4.104 reqid=1
       sp_packets=4 sp_bytes=2112 sp_exceptions=0 sp_errors=0
   2: 10.24.4.119/32 10.22.4.118/32 proto 6 vr0 protect prio 2000
       link-vr0
       ESP tunnel 10.23.4.204 - 10.23.4.104 reqid=2
       sp_packets=1 sp_bytes=40 sp_exceptions=0 sp_errors=0
   Outbound SPD: 2 rules
   3: 10.22.4.118/32 10.24.4.119/32 proto 17 vr0 protect prio 2000
       link-vr0 cached-SA 3 genid 17
       ESP tunnel 10.23.4.104 - 10.23.4.204 reqid=1
       sp_packets=6 sp_bytes=3168 sp_exceptions=1 sp_errors=1
   2: 10.22.4.118/32 10.24.4.119/32 proto 6 vr0 protect prio 2000
       link-vr0 cached-SA 2 genid 20
       ESP tunnel 10.23.4.104 - 10.23.4.204 reqid=2
       sp_packets=1 sp_bytes=60 sp_exceptions=1 sp_errors=0

.. code-block:: fp-cli

   <fp-0> dump-spd raw
   SPD hash lookup min prefix lengths: local=0, remote=0
   Inbound SPD: 2 total rules, 2 global rules
   2: 10.24.4.119/32 10.22.4.118/32 proto 6 vr0 protect prio 2000
       link-vr0
       ESP tunnel 10.23.4.204 - 10.23.4.104 reqid=2
       sp_packets=1 sp_bytes=40 sp_exceptions=0 sp_errors=0
   3: 10.24.4.119/32 10.22.4.118/32 proto 17 vr0 protect prio 2000
       link-vr0
       ESP tunnel 10.23.4.204 - 10.23.4.104 reqid=1
       sp_packets=4 sp_bytes=2112 sp_exceptions=0 sp_errors=0
   Outbound SPD: 2 total rules, 2 global rules
   2: 10.22.4.118/32 10.24.4.119/32 proto 6 vr0 protect prio 2000
       link-vr0 cached-SA 2 genid 20
       ESP tunnel 10.23.4.104 - 10.23.4.204 reqid=2
       sp_packets=1 sp_bytes=60 sp_exceptions=1 sp_errors=0
   3: 10.22.4.118/32 10.24.4.119/32 proto 17 vr0 protect prio 2000
       link-vr0 cached-SA 3 genid 17
       ESP tunnel 10.23.4.104 - 10.23.4.204 reqid=1
       sp_packets=6 sp_bytes=3168 sp_exceptions=1 sp_errors=1

dump-sad
~~~~~~~~

.. rubric:: Description

Dump the |sad|. Dump all |sas|, or only a specific one.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-sad [all | [SADDR PREFIX_SADDR DADDR PREFIX_DADDR ah|esp]]

.. rubric:: Parameters

No parameters
   Only dump the number of |sas| present in the |fp| table.
all
   Dump all |sas| present in the |fp| table.
SADDR
   |sa| source ip address.
PREFIX_SADDR
   Length (in bits) of the source ip netmask prefix.
DADDR
   |sa| destination ip address.
PREFIX_DADDR
   Length (in bits) of the destination ip netmask prefix.
ah|esp
   |ah-esp|

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> dump-sad
   SAD 4 SA.

.. code-block:: fp-cli

   <fp-0> dump-sad all
   SAD 4 SA.
   2: 10.23.4.104 - 10.23.4.204 vr0 spi 0xc55d891 ESP tunnel
       x-vr0 reqid=2 genid 20 cached-SP 0
       output_blade=1
       DES-CBC HMAC-MD5
       key enc:4efe5a2ab00d7273
       key auth:8ae2e379f5d9950f9e16c5b5cb95496e
       sa_packets=1 sa_bytes=60 sa_auth_errors=0 sa_decrypt_errors=0
       sa_replay_errors=0 sa_selector_errors=0
       replay check is on width=32 seq=0 bitmap=0x00000000 - oseq=1
   3: 10.23.4.104 - 10.23.4.204 vr0 spi 0xe4dbd1 ESP tunnel
       x-vr0 reqid=1 genid 17 cached-SP 0
       output_blade=1
       DES-CBC HMAC-MD5
       key enc:d6ce2c08b3ed0340
       key auth:33da206f897fd17a214052eb07b403bc
       sa_packets=6 sa_bytes=3168 sa_auth_errors=0 sa_decrypt_errors=0
       sa_replay_errors=0 sa_selector_errors=0
       replay check is on width=32 seq=0 bitmap=0x00000000 - oseq=6
   4: 10.23.4.204 - 10.23.4.104 vr0 spi 0x4d2eba4 ESP tunnel
       x-vr0 reqid=2 genid 19 cached-SP 2
       output_blade=1
       DES-CBC HMAC-MD5
       key enc:becc9cfbed4123cc
       key auth:40a6314fc26317d499389654b0ee670f
       sa_packets=1 sa_bytes=96 sa_auth_errors=0 sa_decrypt_errors=0
       sa_replay_errors=0 sa_selector_errors=0
       replay check is on width=32 seq=1 bitmap=0x00000001 - oseq=0
   6: 10.23.4.204 - 10.23.4.104 vr0 spi 0x778e36c ESP tunnel
       x-vr0 reqid=1 genid 16 cached-SP 3
       output_blade=1
       DES-CBC HMAC-MD5
       key enc:c080b354f2f0d217
       key auth:efd3f0cbc5ade56761385eaa74bbbcb9
       sa_packets=4 sa_bytes=2336 sa_auth_errors=0 sa_decrypt_errors=0
       sa_replay_errors=0 sa_selector_errors=0
       replay check is on width=32 seq=4 bitmap=0x0000000f - oseq=0

dump-sad-spi-hash
~~~~~~~~~~~~~~~~~

.. rubric:: Description

Dump the |sad| |spi| hash table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-sad-spi-hash [count|index|id|all]

.. rubric:: Parameters

.. include:: include/count-index-id-all.inc

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> dump-sad-spi-hash
   hash table:
     total lines: 65536
     total entries: 4
   entries per line:
     average: 0.00 variance 0.00
     minimum: 0
     maximum: 1

.. code-block:: fp-cli

   <fp-0> dump-sad-spi-hash count
   --hash key 5348: 1 entries
   --hash key 13787: 1 entries
   --hash key 30447: 1 entries
   --hash key 50388: 1 entries

.. code-block:: fp-cli

   <fp-0> dump-sad-spi-hash index
   --hash key 5348: 6
   --hash key 13787: 3
   --hash key 30447: 4
   --hash key 50388: 2

.. code-block:: fp-cli

   <fp-0> dump-sad-spi-hash id
   --hash key 5348: 0x778e36c
   --hash key 13787: 0xe4dbd1
   --hash key 30447: 0x4d2eba4
   --hash key 50388: 0xc55d891

.. code-block:: fp-cli

   <fp-0> dump-sad-spi-hash all
   -- hash key 5348:
   6: 10.23.4.204 - 10.23.4.104 vr0 spi 0x778e36c ESP tunnel
       x-vr0 reqid=1 genid 16 cached-SP 3
       output_blade=1
       DES-CBC HMAC-MD5
       key enc:c080b354f2f0d217
       key auth:efd3f0cbc5ade56761385eaa74bbbcb9
       sa_packets=4 sa_bytes=2336 sa_auth_errors=0 sa_decrypt_errors=0
       sa_replay_errors=0 sa_selector_errors=0
       replay check is on width=32 seq=4 bitmap=0x0000000f - oseq=0
   -- hash key 13787:
   3: 10.23.4.104 - 10.23.4.204 vr0 spi 0xe4dbd1 ESP tunnel
       x-vr0 reqid=1 genid 17 cached-SP 0
       output_blade=1
       DES-CBC HMAC-MD5
       key enc:d6ce2c08b3ed0340
       key auth:33da206f897fd17a214052eb07b403bc
       sa_packets=6 sa_bytes=3168 sa_auth_errors=0 sa_decrypt_errors=0
       sa_replay_errors=0 sa_selector_errors=0
       replay check is on width=32 seq=0 bitmap=0x00000000 - oseq=6
   -- hash key 30447:
   4: 10.23.4.204 - 10.23.4.104 vr0 spi 0x4d2eba4 ESP tunnel
       x-vr0 reqid=2 genid 19 cached-SP 2
       output_blade=1
       DES-CBC HMAC-MD5
       key enc:becc9cfbed4123cc
       key auth:40a6314fc26317d499389654b0ee670f
       sa_packets=1 sa_bytes=96 sa_auth_errors=0 sa_decrypt_errors=0
       sa_replay_errors=0 sa_selector_errors=0
       replay check is on width=32 seq=1 bitmap=0x00000001 - oseq=0
   -- hash key 50388:
   2: 10.23.4.104 - 10.23.4.204 vr0 spi 0xc55d891 ESP tunnel
       x-vr0 reqid=2 genid 20 cached-SP 0
       output_blade=1
       DES-CBC HMAC-MD5
       key enc:4efe5a2ab00d7273
       key auth:8ae2e379f5d9950f9e16c5b5cb95496e
       sa_packets=1 sa_bytes=60 sa_auth_errors=0 sa_decrypt_errors=0
       sa_replay_errors=0 sa_selector_errors=0
       replay check is on width=32 seq=0 bitmap=0x00000000 - oseq=1

dump-sad-selector-hash
~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Dump the |sad| selector's hash table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-sad-selector-hash [count|index|id|all]

.. rubric:: Parameters

.. include:: include/count-index-id-all.inc

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> dump-sad-selector-hash
   hash table:
     total lines: 65536
     total entries: 2
   entries per line:
     average: 0.00 variance 0.00
     minimum: 0
     maximum: 2

.. code-block:: fp-cli

   <fp-0> dump-sad-selector-hash count
   --hash key 25166: 2 entries

.. code-block:: fp-cli

   <fp-0> dump-sad-selector-hash id
   --hash key 25166: 10.23.4.104-10.23.4.204/ESP 10.23.4.204-10.23.4.104/ESP

.. code-block:: fp-cli

   <fp-0> dump-sad-selector-hash index
   --hash key 25166: 6 8

.. code-block:: fp-cli

   <fp-0> dump-sad-selector-hash all
   -- hash key 25166:
   6: 10.23.4.104 - 10.23.4.204 vr0 spi 0x1364760 ESP tunnel
       x-vr0 reqid=1 genid 62 cached-SP 0
       output_blade=1
       DES-CBC HMAC-MD5
       key enc:25af0e89e709bfd6
       key auth:2ff8931628cda4715f51220d28f83055
       sa_packets=176 sa_bytes=92928 sa_auth_errors=0 sa_decrypt_errors=0
       sa_replay_errors=0 sa_selector_errors=0
       replay check is on width=32 seq=0 bitmap=0x00000000 - oseq=176
   8: 10.23.4.204 - 10.23.4.104 vr0 spi 0x6ed16b4 ESP tunnel
       x-vr0 reqid=1 genid 61 cached-SP 0
       output_blade=1
       DES-CBC HMAC-MD5
       key enc:65076dc23e751069
       key auth:58c08e2d4d9d8e08c540882f7edae505
       sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
       sa_replay_errors=0 sa_selector_errors=0
       replay check is on width=32 seq=0 bitmap=0x00000000 - oseq=0

set-ipsec-once
~~~~~~~~~~~~~~

.. rubric:: Description

Set |ipsec| maximum once on each packet.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-ipsec-once [on|off]

.. rubric:: Parameters

on|off
   Enable |ipsec| once behavior.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-ipsec-once on
   IPsec processing only once is on (was off)

SA anti-replay window / output sequence number synchronization
--------------------------------------------------------------

.. note:: This part is only related to multiple fast paths.

A mechanism to synchronize the anti-replay window and the output sequence number
between each |fp| is necessary for each |sa|.

Because inbound packets can be handled by any |fp| (the one that received
the packet, not necessarily the |fp| the |sa| is anchored to), the
anti-replay window must be synchronized between fast paths.

Outbound packets are always handled on the same |fp|, hence the output
sequence number management is centralized on the |fp| the |sa| is anchored
to. However, if we migrate the anchoring point of a |sa|, the new |fp| must
be ready to send packets through this |sa|, so the output sequence number must be
synchronized between fast paths.

The synchronization of these two fields is made on two occasions:

- During fpm |ipsec| graceful restart, the |fp| will try to synchronize all
  |sas|, getting the information from other fast paths, in which case
  *FPTUN_IPV4_REPLAYWIN_GET* / *FPTUN_IPV4_REPLAYWIN_REPLY* are exchanged.
- When a packet is received or sent, every N processed packets (N =
  fp_shared->ipsec.sa_replay_sync_threshold, configurable using the fp-cli
  *set-sa-sync-threshold* command), a *FPTUN_IPV4_REPLAYWIN* fptun message is
  sent.

set-sa-sync-threshold
~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Set the threshold (in packets) for which we will send an update for anti-replay
window / output sequence number synchronization.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-sa-sync-threshold THRESHOLD

.. rubric:: Parameters

THRESHOLD
   Overall threshold value.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-sa-sync-threshold 64

show-sa-sync-threshold
~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Show the threshold (in packets) for which we will send an update for anti-replay
window / output sequence number synchronization.

.. rubric:: Synopsis

.. code-block:: fp-cli

   show-sa-sync-threshold

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> show-sa-sync-threshold
    IPv4 IPsec threshold between two sequence number sync messages is: 32

Extended Sequence Number
------------------------

.. include:: include/needs-iproute2-patch.inc

|ah|/|esp| headers support extended, 64 bit sequence numbers to detect replay.

A single |ipsec| |sa| can transfer a maximum of 2^64 |ipsec| packets.

.. rubric:: Example

#. Create an |sa| with |esn| support and a 128 packets replay window:

   .. code-block:: console

      $ ip xfrm state add src 2.1.0.1 dst 2.1.0.5 spi 0x00000220 proto esp reqid 22 mode tunnel \
      enc aes cle1goldorakgoldorakcle1 auth sha1 cle1goldorakgoldcle1 flag esn replay-window 128

#. Check that your configuration is correctly synchronized in the |fp|:

   .. code-block:: console

      $ fp-cli

   .. code-block:: fp-cli

      <fp-0> dump-sad all
      SAD 1 SA.
      1: 2.1.0.1 - 2.1.0.5 vr0 spi 0x220 ESP tunnel
        x-vr0 reqid=22 counter 1 cached-SP 0 (genid 1)
        cached-svti 0 (genid 0)
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

Large anti-replay window
------------------------

.. include:: include/needs-iproute2-patch.inc

You can set the anti-replay window size between 32 and 4096 packets (maximum
size allowed by the Linux kernel).

.. rubric:: Example

#. Create an |sa| with a 256 packets replay window:

   .. code-block:: console

      $ ip xfrm state add src 2.1.0.1 dst 2.1.0.5 spi 0x00000220 proto esp reqid 22 mode tunnel \
      enc aes cle1goldorakgoldorakcle1 auth sha1 cle1goldorakgoldcle1 replay-window 256

#. Check that your configuration is correctly synchronized in the |fp|:

   .. code-block:: console

      $ fp-cli

   .. code-block:: fp-cli

      <fp-0> dump-sad all
        SAD 1 SA.
        1: 2.1.0.1 - 2.1.0.5 vr0 spi 0x220 ESP tunnel
        x-vr0 reqid=22 counter 2 cached-SP 0 (genid 2)
        cached-svti 0 (genid 0)
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

IPv4 in IPv6 IPsec tunnel example
---------------------------------

We will encapsulate |ipv4| packets in a static |ipv6| |ipsec| tunnel.

#. Create the inbound |ipsec| endpoint:

   a. Create an |ipv6| |ipsec| |sa| for |ipv4| packets:

      .. code-block:: console

         $ ip xfrm state add src 3ffe:2:11::5 dst 3ffe:2:11::1 proto esp spi 0x00000221 mode tunnel \
         sel src 0/0 enc aes cle1goldorakgoldorakcle1 auth sha1 cle1goldorakgoldcle1

   #. Create an inbound |ipv4| |ipsec| |sp|:

      .. code-block:: console

         $ ip xfrm policy add src 110.2.2.1/32 dst 100.2.2.1/32 dir in \
         tmpl src 3ffe:2:11::5 dst 3ffe:2:11::1 proto esp mode tunnel

   #. Create a forward |ipv4| |ipsec| |sp|:

      .. code-block:: console

         $ ip xfrm policy add src 110.2.2.1/32 dst 100.2.2.1/32 dir fwd \
         tmpl src 3ffe:2:11::5 dst 3ffe:2:11::1 proto esp mode tunnel

#. Create the outbound |ipsec| endpoint:

   a. Create an |ipv6| |ipsec| |sa| for |ipv4| packets:

      .. code-block:: console

         $ ip xfrm state add src 3ffe:2:11::1 dst 3ffe:2:11::5 proto esp spi 0x00000220 mode tunnel \
         sel src 0/0 enc aes cle1goldorakgoldorakcle2 auth sha1 cle1goldorakgoldcle2

   #. Create an outbound |ipv4| |ipsec| |sp|:

      .. code-block:: console

         $ ip xfrm policy add src 100.2.2.1/32 dst 110.2.2.1/32 dir out \
         tmpl src 3ffe:2:11::1 dst 3ffe:2:11::5 proto esp mode tunnel

#. Check that your configuration is correctly synchronized in the |fp|:

   a. Start *fp-cli*:

      .. code-block:: console

         $ fp-cli

   #. Display the |sas| in the |fpipsec6| table:

      .. code-block:: fp-cli

         <fp-0> dump-sad6 all
         IPv6 SAD 2 SA.
         1: 3ffe:2:11::5 - 3ffe:2:11::1 vr0 spi 0x221 ESP tunnel
           x-vr0 counter 1 genid 1 cached-SP: 0
           output_blade=1
           AES-CBC HMAC-SHA1
           key enc:636c6531676f6c646f72616b676f6c646f72616b636c6531
           digest length: 12
           key auth:636c6531676f6c646f72616b676f6c64636c6531
           sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
           sa_replay_errors=0 sa_selector_errors=0
           replay width=0 seq=0x0 - oseq=0x0
         2: 3ffe:2:11::1 - 3ffe:2:11::5 vr0 spi 0x220 ESP tunnel
           x-vr0 counter 1 genid 2 cached-SP: 0
           output_blade=1
           AES-CBC HMAC-SHA1
           key enc:636c6531676f6c646f72616b676f6c646f72616b636c6532
           digest length: 12
           key auth:636c6531676f6c646f72616b676f6c64636c6532
           sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
           sa_replay_errors=0 sa_selector_errors=0
           replay width=0 seq=0x0 - oseq=0x0

   #. Display the |sps| in the |fpipsec4| table:

      .. code-block:: fp-cli

         <fp-0> dump-spd all
         SPD hash lookup min prefix lengths: local=0, remote=0
         Inbound SPD: 1 rules
         1: 110.2.2.1/32 100.2.2.1/32 proto any vr0 protect prio 0
           link-vr0
           ESP tunnel 3ffe:2:11::5 - 3ffe:2:11::1
           sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0
         Outbound SPD: 1 rules
         1: 100.2.2.1/32 110.2.2.1/32 proto any vr0 protect prio 0
           link-vr0 cached-SA 0 (genid 0)
           ESP tunnel 3ffe:2:11::1 - 3ffe:2:11::5
           sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0

.. seealso::

   To dynamically configure |ipsec| tunnels, see the |cp-ike| documentation.
