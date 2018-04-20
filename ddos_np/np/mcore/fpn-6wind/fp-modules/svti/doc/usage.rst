Usage
=====

Starting |fp-svti|
------------------

#. Start the |fp|:

   .. code-block:: console

      # fast-path.sh start

#. To syncronize Linux and the |fp|, start |linux-fp-sync|:

   .. code-block:: console

      # linux-fp-sync.sh start

#. Start |fp-svti|:

   .. code-block:: console

      # vti.sh start

SVTI interface |fp| management
-----------------------------------

The *fp-cli* commands below allow you to manage |svti| interfaces.

add-svti
~~~~~~~~

.. rubric:: Description

Create an |svti| interface.

.. rubric:: Synopsis

.. code-block:: fp-cli

   add-svti NAME LOCAL_ADDR REMOTE_ADDR [vr VR] [lvr LVR] [mtu MTU]

.. rubric:: Parameters

NAME
    |svti| interface's name.

LOCAL_ADDR
    Local IP address.
REMOTE_ADDR
    Remote IP address.
VR
    |vrf| ID of the |svti| interface (|vrf|
    ID of plaintext packets).
LVR
    Link |vrf| ID of the |svti| interface (|vrf| ID of |ipsec| encapsulated packets).
MTU
    |svti| interface's |mtu|.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> add-svti svti1 10.23.1.101 10.23.1.201

del-svti
~~~~~~~~

.. rubric:: Description

Delete an |svti| interface.

.. rubric:: Synopsis

.. code-block:: fp-cli

   del-svti IFNAME

.. rubric:: Parameters

IFNAME
    |svti| interface's name.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> del-svti svti1
   del-svti: removing svti svti1 ifuid=0xe2148660 bound to port 254

dump-svti
~~~~~~~~~

.. rubric:: Description

Dump |svti| interfaces' SPDs.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-svti [all] [svti IFNAME]

.. rubric:: Parameters

all
    Dump |sps| attached to all |svti| interfaces.
IFNAME
    Only display |svti| interfaces that match a specific name.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-svti all
   [1] svti1 [VR-0] ifuid=0xe2148660
      local=10.23.1.101 remote=10.23.1.201 link-vrfid=0
   Inbound SPD: 1 rules
   1: 0.0.0.0/0 0.0.0.0/0 proto any vr0 protect prio 0
      link-vr0
      svti=svti1(0xe2148660)
      ESP tunnel 10.23.1.201 - 10.23.1.101
      sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0
   Outbound SPD: 1 rules
   1: 0.0.0.0/0 0.0.0.0/0 proto any vr0 protect prio 0
      link-vr0 cached-SA 0 (genid 0)
      svti=svti1(0xe2148660)
      ESP tunnel 10.23.1.101 - 10.23.1.201
      sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0

dump-svti-hash
~~~~~~~~~~~~~~

.. rubric:: Description

Dump |svti| interfaces' hash table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-svti-hash [count|index|id|all]

.. rubric:: Parameters

count
    Count the number of |svti| interfaces in each hash table line.
index
    List indexes of |svti| interfaces stored in each hash table line.
id
    List identifiers of |svti| interfaces stored in each hash table line.
all
    Dump |svti| interfaces stored in each hash table line,  and their |sps|.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-svti-hash all
   svti hash table:
   -- hash key 200:
   1: [1] svti1 [VR-0] ifuid=0xe2148660
        local=10.23.1.101 remote=10.23.1.201 link-vrfid=0
   Inbound SPD: 1 rules
   Outbound SPD: 1 rules

Static SVTI IPsec with synchronization
--------------------------------------

|vpn-public-network|

|network-topology|

::

   10.22.1.0/24 ================ 10.23.1.0/24 +--------------+ 10.24.1.0/24
   -------------| VPN gateway  |==============|   remote     |-------------
      private   |    with      |    public    |     VPN      |  private
      network   | ipsec-svti   |   network    |   gateway    |  network
    (plaintext) ================   (IPsec)    +--------------+ (plaintext)
                    .101                           .201

#. |configure-ip-routes|

   .. code-block:: console

      # ip link set eth0 up
      # ip addr add 10.22.1.101/24 dev eth0
      # ip link set eth2 up
      # ip addr add 10.23.1.101/24 dev eth2

#. |create-svti|

   .. code-block:: console

      # ifname2ifuid svti1 0
      svti1 0: 0xe2148660
      # ip link add svti1 type vti local 10.23.1.101 remote 10.23.1.201 okey 0xe2148660
      # ip link set svti1 up
      # ip addr add 192.168.1.1/24 dev svti1

#. |bind-sps|

   |wildcard-packet-selector|

   .. code-block:: console

      # ip xfrm policy add dir out mark 0xe2148660 \
        tmpl src 10.23.1.101 dst 10.23.1.201 proto esp mode tunnel

      # ip xfrm policy add dir in mark 0xe2148660 \
        tmpl src 10.23.1.201 dst 10.23.1.101 proto esp mode tunnel

   .. note::

      - |sps-tunnel-mode|
      - |outer-addresses|
      - |outer-addresses-o_key|
      - |vr-lvr-sp|

#. |bind-sas|

   .. code-block:: console

      # ip xfrm state add src 10.23.1.101 dst 10.23.1.201 proto esp \
        spi 0x12345678 mode tunnel \
        enc "cbc(aes)" 0x2889cf9d3f58d80f11a2af9a464c02d3 \
        auth "hmac(sha1)" 0xdd2065484027c27fc887520194c07f7b48a76df6

      # ip xfrm state add src 10.23.1.201 dst 10.23.1.101 proto esp \
        spi 0x888f7e8e mode tunnel \
        enc "cbc(aes)" 0x3cb2e12a888fd560b2b9097ef23742b9 \
        auth "hmac(sha1)" 0xa920f60c94f9ccef4eba7e8ee8b093596df6dab8

   .. note::

      - |sas-tunnel-mode|
      - |outer-addresses|
      - |mark-any|
      - |vr-xvr-sa|

#. |add-route|

   .. code-block:: console

      # ip route add 10.24.1.0/24 dev svti1

   When sending traffic between *10.22.1.0/24* and *10.24.1.0/24*, the plaintext
   traffic can be captured on *svti1*, and the |ipsec| traffic can be captured on
   *eth2*.

#. |fp-display|

   .. code-block:: fp-cli

      <fp-0> dump-svti svti svti1
      [1] svti1 [VR-0] ifuid=0xe2148660
            local=10.23.1.101 remote=10.23.1.201 link-vrfid=0
      Inbound SPD: 1 rules
      Outbound SPD: 1 rules

   .. code-block:: fp-cli

      <fp-0> dump-sad all
      SAD 2 SA.
      1: 10.23.1.101 - 10.23.1.201 vr0 spi 0x12345678 ESP tunnel
          x-vr0 counter 1 cached-SP 0 (genid 1)
          cached-svti 0 (genid 0)
          output_blade=1
          AES-CBC HMAC-SHA1
          key enc:2889cf9d3f58d80f11a2af9a464c02d3
          key auth:dd2065484027c27fc887520194c07f7b48a76df6
          sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
          sa_replay_errors=0 sa_selector_errors=0
          replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0
      2: 10.23.1.201 - 10.23.1.101 vr0 spi 0x888f7e8e ESP tunnel
          x-vr0 counter 1 cached-SP 0 (genid 2)
          cached-svti 0 (genid 0)
          output_blade=1
          AES-CBC HMAC-SHA1
          key enc:3cb2e12a888fd560b2b9097ef23742b9
          key auth:a920f60c94f9ccef4eba7e8ee8b093596df6dab8
          sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
          sa_replay_errors=0 sa_selector_errors=0
          replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0

   .. code-block:: fp-cli

      <fp-0> dump-spd all svti svti1
      SPD hash lookup min prefix lengths: local=0, remote=0
      Inbound svti SPD: 1 rules
      1: 0.0.0.0/0 0.0.0.0/0 proto any vr0 protect prio 0
          link-vr0
          svti=svti1(0xe2148660)
          ESP tunnel 10.23.1.201 - 10.23.1.101
          sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0
      Outbound svti SPD: 1 rules
      1: 0.0.0.0/0 0.0.0.0/0 proto any vr0 protect prio 0
          link-vr0 cached-SA 0 (genid 0)
          svti=svti1(0xe2148660)
          ESP tunnel 10.23.1.101 - 10.23.1.201
          sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0

Static SVTI IPsec and cross-VRF with synchronization
----------------------------------------------------

|vpn-public-network|
The private network and the public network belong to different VRs.

|network-topology|

::

   10.22.1.0/24 ================ 10.23.1.0/24 +--------------+ 10.24.1.0/24
   -------------| VPN gateway  |==============|   remote     |-------------
      private   |    with      |    public    |     VPN      |  private
      network   | ipsec-svti   |   network    |   gateway    |  network
    (plaintext) ================   (IPsec)    +--------------+ (plaintext)
                     .101                         .201
           (vrf2)              (vrf1)

The *svti1* interface will use 2 VRs:

- The interface *link-vr*, i.e., the |vr| of |ipsec| encrypted packets
- The interface *vr*, i.e., the |vr| of plaintext packets

We will create the |svti| interface in
the *link-vr* interface, then move it to its own |vr|.

You must create the |sps| and the |sas| in the *link-vr* interface.

#. |create-vrf1&2|

   .. code-block:: console

      # vrfctl add 1
      # vrfctl add 2

#. |switch-to-vrf|

   .. code-block:: console

      # ip link set eth0 netns vrf2
      # ip link set eth2 netns vrf1

#. |configure-ip-routes|

   .. code-block:: console

      # ip netns exec vrf2 ip link set eth0 up
      # ip netns exec vrf2 ip addr add 10.22.1.101/24 dev eth0
      # ip netns exec vrf1 ip link set eth2 up
      # ip netns exec vrf1 ip addr add 10.23.1.101/24 dev eth2

#. |create-svti|

   .. code-block:: console

      # ifname2ifuid svti1 2
      svti1 1: 0x6db487c0
      # ip netns exec vrf1 ip link add svti1 type vti local 10.23.1.101 \
        remote 10.23.1.201 okey 0x6db487c0
      # ip netns exec vrf1 ip link set svti1 netns vrf2
      # ip netns exec vrf2 ip link set svti1 up
      # ip netns exec vrf2 ip addr add 192.168.1.1/24 dev svti1

#. |bind-sps|

   |wildcard-packet-selector|

   .. code-block:: console

      # ip netns exec vrf1 ip xfrm policy add dir out mark 0x6db487c0 \
        tmpl src 10.23.1.101 dst 10.23.1.201 proto esp mode tunnel

      # ip netns exec vrf1 ip xfrm policy add dir in mark 0x6db487c0 \
        tmpl src 10.23.1.201 dst 10.23.1.101 proto esp mode tunnel

   .. note::

      - |sps-tunnel-mode|
      - |outer-addresses|
      - |outer-addresses-o_key|
      - |vr-lvr-sp|

#. |bind-sas|

   .. code-block:: console

      # ip netns exec vrf1 ip xfrm state add src 10.23.1.101 dst 10.23.1.201 \
        proto esp spi 0x12345678 mode tunnel \
        enc "cbc(aes)" 0x2889cf9d3f58d80f11a2af9a464c02d3 \
        auth "hmac(sha1)" 0xdd2065484027c27fc887520194c07f7b48a76df6

      # ip netns exec vrf1 ip xfrm state add src 10.23.1.201 dst 10.23.1.101 \
        proto esp spi 0x888f7e8e mode tunnel \
        enc "cbc(aes)" 0x3cb2e12a888fd560b2b9097ef23742b9 \
        auth "hmac(sha1)" 0xa920f60c94f9ccef4eba7e8ee8b093596df6dab8

   .. note::

      - |sas-tunnel-mode|
      - |outer-addresses|
      - |mark-any|
      - |vr-xvr-sa|

#. |add-route|

   .. code-block:: console

      # ip netns exec vrf2 ip route add 10.24.1.0/24 dev svti1

   When sending traffic in *vrf2* between *10.22.1.0/24* and *10.24.1.0/24*, the
   plaintext traffic can be captured on *svti1* (*vrf2*), and the |ipsec| traffic
   can be captured on *eth2* (*vrf1*).

#. |fp-display|

   .. code-block:: fp-cli

      <fp-0> dump-svti
      [1] svti1 [VR-2] ifuid=0x6db487c0
        local=10.23.1.101 remote=10.23.1.201 link-vrfid=1
      Inbound SPD: 1 rules
      Outbound SPD: 1 rules

   .. code-block:: fp-cli

      <fp-0> dump-spd all svti svti1
      SPD hash lookup min prefix lengths: local=0, remote=0
      Inbound svti SPD: 1 rules
      3: 0.0.0.0/0 0.0.0.0/0 proto any vr1 protect prio 0
          link-vr1
          svti=svti1(0x6db487c0)
          ESP tunnel 10.23.1.201 - 10.23.1.101
          sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0
      Outbound svti SPD: 1 rules
      3: 0.0.0.0/0 0.0.0.0/0 proto any vr1 protect prio 0
          link-vr1 cached-SA 0 (genid 0)
          svti=svti1(0x6db487c0)
          ESP tunnel 10.23.1.101 - 10.23.1.201
          sp_packets=0 sp_bytes=0 sp_exceptions=0 sp_errors=0

   .. code-block:: fp-cli

      <fp-0> "vrf 1;dump-sad all"
      New reference for VRF: 1
      SAD 2 SA.
      1: 10.23.1.101 - 10.23.1.201 vr1 spi 0x12345678 ESP tunnel
          x-vr1 counter 1 cached-SP 0 (genid 1)
          cached-svti 0 (genid 0)
          output_blade=1
          AES-CBC HMAC-SHA1
          key enc:2889cf9d3f58d80f11a2af9a464c02d3
          key auth:dd2065484027c27fc887520194c07f7b48a76df6
          sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
          sa_replay_errors=0 sa_selector_errors=0
          replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0
      2: 10.23.1.201 - 10.23.1.101 vr1 spi 0x888f7e8e ESP tunnel
          x-vr1 counter 1 cached-SP 0 (genid 2)
          cached-svti 0 (genid 0)
          output_blade=1
          AES-CBC HMAC-SHA1
          key enc:3cb2e12a888fd560b2b9097ef23742b9
          key auth:a920f60c94f9ccef4eba7e8ee8b093596df6dab8
          sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
          sa_replay_errors=0 sa_selector_errors=0
          replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0

#. |delete-svti-sps|

   You must specify its mark.

   .. code-block:: console

      # ip netns exec vrf1 ip xfrm policy delete src 0.0.0.0/0 dst 0.0.0.0/0 \
        dir in mark 0xa7e48710

#. |flush-sps|

   .. code-block:: console

      # ip netns exec vrf1 ip xfrm policy flush

   All |sps|, whether overall or specific to an |svti|, are flushed.

#. |delete-svti|

   .. code-block:: console

      # ip netns exec vrf2 ip link del svti1

   .. note::

      Deleting an |svti| interface does not delete the |sps| bound to this
      interface. The |sps| must be explicitly deleted.

Static SVTI IPsec without synchronization
-----------------------------------------

|vpn-public-network|

|network-topology|

::

   10.22.1.0/24 ================ 10.23.1.0/24 +--------------+ 10.24.1.0/24
   -------------| VPN gateway  |==============|   remote     |-------------
      private   |    with      |    public    |     VPN      |  private
      network   | ipsec-svti   |   network    |   gateway    |  network
    (plaintext) ================   (IPsec)    +--------------+ (plaintext)
                    .101                           .201

#. |configure-ip-routes|

   .. code-block:: console

      # ip link set eth1 up
      # ip link set eth2 up

   .. code-block:: fp-cli

      <fp-0> add-interface eth1 0 00:02:02:00:00:20 8
      eth1 [VR-0] ifuid=0x8000000 (port 0) <UP|RUNNING|FWD4> (0x23)
        type=ether mac=00:02:02:00:00:20 mtu=1500 tcp4mss=0 tcp6mss=0
        IPv4 routes=0  IPv6 routes=0
      <fp-0> add-address4 eth1 10.22.1.101 24
      <fp-0> add-interface eth2 1 00:02:02:00:00:21 9
      eth2 [VR-0] ifuid=0x9000000 (port 1) <UP|RUNNING|FWD4> (0x23)
        type=ether mac=00:02:02:00:00:21 mtu=1500 tcp4mss=0 tcp6mss=0
        IPv4 routes=0  IPv6 routes=0
      <fp-0> add-address4 eth2 10.23.1.101 24

#. |create-svti|

   .. code-block:: console

      # ifname2ifuid svti1 0
      svti1 0: 0xe2148660
      <fp-0> add-svti svti1 0xe2148660 10.23.1.101 10.23.1.201
      <fp-0> set-flags svti1 0x23
      <fp-0> add-address4 svti1 192.168.1.1 24

#. |bind-sps|

   |wildcard-packet-selector|

   .. code-block:: fp-cli

      <fp-0> add-sp out 0.0.0.0/0 0.0.0.0/0 any esp tunnel 10.23.1.101 10.23.1.201 \
        0 svti svti1
      <fp-0> add-sp in 0.0.0.0/0 0.0.0.0/0 any esp tunnel 10.23.1.201 10.23.1.101 \
        0 svti svti1

   .. note::

      - |sps-tunnel-mode|
      - |outer-addresses|
      - |outer-addresses-o_key|
      - |vr-lvr-sp|

#. |bind-sas|

   .. code-block:: fp-cli

      <fp-0> add-sa esp 10.23.1.101 10.23.1.201 0x12345678 tunnel \
        enc aes-cbc 0x2889cf9d3f58d80f11a2af9a464c02d3 \
        auth hmac-sha1 0xdd2065484027c27fc887520194c07f7b48a76df6
      <fp-0> add-sa esp 10.23.1.201 10.23.1.101 0x888f7e8e tunnel \
        enc aes-cbc 0x3cb2e12a888fd560b2b9097ef23742b9 \
        auth hmac-sha1 0xa920f60c94f9ccef4eba7e8ee8b093596df6dab8

   .. note::

      - |sas-tunnel-mode|
      - |outer-addresses|
      - |mark-any|
      - |vr-xvr-sa|

#. |add-route|

   .. code-block:: fp-cli

      <fp-0> add-route 10.24.1.201 32 0.0.0.0 svti1 2

   The plaintext traffic is counted up in svti1 interface statistics.
   The |ipsec| traffic is counted up in the eth2 interface statistics.

#. Add neighbors:

   .. code-block:: fp-cli

      <fp-0> add-neighbour 10.23.1.201 00:55:01:00:00:21 eth2
      <fp-0> add-neighbour 10.22.1.1 00:55:00:00:00:20 eth1

#. Display tunnel interfaces, including |svti| interfaces:

   .. code-block:: fp-cli

      <fp-0> dump-interfaces
      8:eth1 [VR-0] ifuid=0x8000000 (port 0) <UP|RUNNING|FWD4> (0x23)
              type=ether mac=00:02:02:00:00:20 mtu=1500 tcp4mss=0 tcp6mss=0
              IPv4 routes=2  IPv6 routes=0
      9:eth2 [VR-0] ifuid=0x9000000 (port 1) <UP|RUNNING|FWD4> (0x23)
              type=ether mac=00:02:02:00:00:21 mtu=1500 tcp4mss=0 tcp6mss=0
              IPv4 routes=2  IPv6 routes=0
      226:svti1 [VR-0] ifuid=0xe2148660 (virtual) <UP|RUNNING|FWD4> (0x23)
              type=svti mac=00:00:00:00:00:00 mtu=1480 tcp4mss=0 tcp6mss=0 link-vrfid=0
              SVTI tunnel local=10.23.1.101 remote=10.23.1.201
              IPv4 routes=2  IPv6 routes=0
      <fp-0> dump-address4 eth1
      number of ip address: 1
      10.22.1.101 [0]
      <fp-0> dump-address4 eth2
      number of ip address: 1
      10.23.1.101 [1]
      <fp-0> dump-address4 svti1
      number of ip address: 1
      192.168.1.1 [2]

#. Display |svti| |sps|:

   .. code-block:: fp-cli

      <fp-0> dump-spd all svti svti1
      sh lookup min prefix lengths: local=0, remote=0
      Inbound svti SPD: 1 rules
      1: 0.0.0.0/0 0.0.0.0/0 proto any vr0 protect prio 0
           link-vr0
           svti=svti1(0xe2148660)
           ESP tunnel 10.23.1.201 - 10.23.1.101
           sp_packets=35 sp_bytes=2940 sp_exceptions=0 sp_errors=0
      Outbound svti SPD: 1 rules
      1: 0.0.0.0/0 0.0.0.0/0 proto any vr0 protect prio 0
           link-vr0 cached-SA 1 (genid 1)
           svti=svti1(0xe2148660)
           ESP tunnel 10.23.1.101 - 10.23.1.201
           sp_packets=35 sp_bytes=2940 sp_exceptions=0 sp_errors=0

   All |sps| (overall and specific to an |svti|) are stored in the same SPD. Their
   marks allow to tell whether they are overall (0) or bound to an |svti|.

#. Display |sas|:

   .. code-block:: fp-cli

      <fp-0> dump-sad all
      SAD 2 SA.
      1: 10.23.1.101 - 10.23.1.201 vr0 spi 0x12345678 ESP tunnel
             x-vr0 counter 1 cached-SP 0 (genid 1)
             cached-svti 0 (genid 0)
             AES-CBC HMAC-SHA1
             key enc:2889cf9d3f58d80f11a2af9a464c02d3
             key auth:dd2065484027c27fc887520194c07f7b48a76df6
             sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
             sa_replay_errors=0 sa_selector_errors=0
             replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0
      2: 10.23.1.201 - 10.23.1.101 vr0 spi 0x12345678 ESP tunnel
             x-vr0 counter 1 cached-SP 0 (genid 1)
             cached-svti 0 (genid 0)
             AES-CBC HMAC-SHA1
             key enc:3cb2e12a888fd560b2b9097ef23742b9
             key auth:a920f60c94f9ccef4eba7e8ee8b093596df6dab8
             sa_packets=0 sa_bytes=0 sa_auth_errors=0 sa_decrypt_errors=0
             sa_replay_errors=0 sa_selector_errors=0
             replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0

#. Display neighbors:

   .. code-block:: fp-cli

      <fp-0> dump-neighbours
      R[000008] GW/NEIGH 10.23.1.201 00:55:01:00:00:21 via eth2(0x09000000) REACHABLE (nh:8)
      R[000009] GW/NEIGH 10.22.1.1 00:55:00:00:00:20 via eth1(0x08000000) REACHABLE (nh:9)

#. Delete |svti| |sas|:

   .. code-block:: fp-cli

      <fp-0> del-sa esp 10.23.1.201 0x12345678
      <fp-0> del-sa esp 10.23.1.101 0x12345678

#. |delete-svti-sps|

   .. code-block:: fp-cli

      <fp-0> del-sp in 0.0.0.0/0 0.0.0.0/0 any svti svti1
      <fp-0> del-sp out 0.0.0.0/0 0.0.0.0/0 any svti svti1

#. |delete-svti|

   .. code-block:: fp-cli

      <fp-0> del-svti svti1

   .. warning::

      The |sps| bound to the |svti| interface are also deleted.

Static SVTI IPsec and cross-VRF without synchronization
-------------------------------------------------------

|vpn-public-network| The private and public network are in different VRs.

|network-topology|

::

   10.22.1.0/24 ================ 10.23.1.0/24 +--------------+ 10.24.1.0/24
   -------------| VPN gateway  |==============|   remote     |-------------
      private   |    with      |    public    |     VPN      |  private
      network   | ipsec-svti   |   network    |   gateway    |  network
    (plaintext) ================   (IPsec)    +--------------+ (plaintext)
                     .101                         .201
           (vrf2)              (vrf1)

The *svti1* interface will use 2 VRs:

- the interface *link-vr*, i.e. the |vr| of |ipsec| encrypted packets
- the interface *vr*, i.e. the |vr| of plaintext packets

The |svti| interface is created in the
*link-vr* and moved to its |vr|.

You must create the |sps| and the |sas| in the *link-vr* interface.

#. Configure IP addresses, routes and switch network interface to vrf namespace:

   .. code-block:: console

      # ip link set eth1 up
      # ip link set eth2 up

   .. code-block:: fp-cli

      <fp-0> add-interface eth1 0 00:02:02:00:00:20 8
      eth1 [VR-0] ifuid=0x8000000 (port 0) <UP|RUNNING|FWD4> (0x23)
              type=ether mac=00:02:02:00:00:20 mtu=1500 tcp4mss=0 tcp6mss=0
              IPv4 routes=0  IPv6 routes=0
      <fp-0> set-if-vrfid eth1 2
      <fp-0> add-address4 eth1 10.22.1.101 24
      <fp-0> add-interface eth2 1 00:02:02:00:00:21 9
      eth2 [VR-0] ifuid=0x9000000 (port 1) <UP|RUNNING|FWD4> (0x23)
              type=ether mac=00:02:02:00:00:21 mtu=1500 tcp4mss=0 tcp6mss=0
              IPv4 routes=0  IPv6 routes=0
      <fp-0> set-if-vrfid eth2 1
      <fp-0> add-address4 eth2 10.23.1.101 24

#. |create-svti|

   .. code-block:: console

      # ifname2ifuid svti1 2
      svti1 1: 0x6db487c0

   .. code-block:: fp-cli

      <fp-0> add-svti svti1 0x6db487c0 10.23.1.101 10.23.1.201 vr 2 lvr 1
      <fp-0> "vrf 2;set-flags svti1 0x23"
      <fp-0> "vrf 2;add-address4 svti1 192.168.1.1 24"

#. |bind-sps|

   |wildcard-packet-selector|

   .. code-block:: fp-cli

      <fp-0> add-sp out 0.0.0.0/0 0.0.0.0/0 any esp tunnel 10.23.1.101 10.23.1.201 0 \
        vr 1 lvr 1 svti svti1
      <fp-0> add-sp in 0.0.0.0/0 0.0.0.0/0 any esp tunnel 10.23.1.201 10.23.1.101 0 \
        vr 1 lvr 1 svti svti1

   .. note::

      - |sps-tunnel-mode|
      - |outer-addresses|
      - |outer-addresses-o_key|
      - |vr-lvr-sp|

#. |bind-sas|

   .. code-block:: fp-cli

      <fp-0> add-sa esp 10.23.1.101 10.23.1.201 0x12345678 tunnel vr 1 xvr 1 \
          enc aes-cbc 0x2889cf9d3f58d80f11a2af9a464c02d3 \
          auth hmac-sha1 0xdd2065484027c27fc887520194c07f7b48a76df6
      <fp-0> add-sa esp 10.23.1.201 10.23.1.101 0x888f7e8e tunnel vr 1 xvr 1 \
          enc aes-cbc 0x3cb2e12a888fd560b2b9097ef23742b9 \
          auth hmac-sha1 0xa920f60c94f9ccef4eba7e8ee8b093596df6dab8

   .. note::

      - |sas-tunnel-mode|
      - |outer-addresses|
      - |mark-any|
      - |vr-xvr-sa|

#. |add-route|

   .. code-block:: fp-cli

      <fp-0> "vrf 2;add-route 10.24.1.201 32 0.0.0.0 svti1 2"

   The plaintext traffic is counted up in svti1 interface statistics.
   The |ipsec| traffic is counted up in the eth2 interface statistics.

#. Add neighbours

   .. code-block:: fp-cli

      <fp-0> add-neighbour 10.23.1.201 00:55:01:00:00:21 eth2
      <fp-0> add-neighbour 10.22.1.1 00:55:00:00:00:20 eth1

#. Display tunnel interfaces, including |svti| interfaces:

   .. code-block:: fp-cli

      <fp-0> dump-interfaces
      8:eth1 [VR-2] ifuid=0x8000000 (port 0) <UP|RUNNING|FWD4> (0x23)
              type=ether mac=00:02:02:00:00:20 mtu=1500 tcp4mss=0 tcp6mss=0
              IPv4 routes=2  IPv6 routes=0
      9:eth2 [VR-1] ifuid=0x9000000 (port 1) <UP|RUNNING|FWD4> (0x23)
              type=ether mac=00:02:02:00:00:21 mtu=1500 tcp4mss=0 tcp6mss=0
              IPv4 routes=2  IPv6 routes=0
      109:svti1 [VR-2] ifuid=0x6db487c0 (virtual) <UP|RUNNING|FWD4> (0x23)
              type=svti mac=00:00:00:00:00:00 mtu=1480 tcp4mss=0 tcp6mss=0 link-vrfid=1
              SVTI tunnel local=10.23.1.101 remote=10.23.1.201
              IPv4 routes=2  IPv6 routes=0
      <fp-0> dump-address4 eth1
      number of ip address: 1
      10.22.1.101 [0]
      <fp-0> dump-address4 eth2
      number of ip address: 1
      10.23.1.101 [1]
      <fp-0> dump-address4 svti1
      number of ip address: 1
      192.168.1.1 [2]

#. Display |svti| |sps|:

   .. code-block:: fp-cli

      <fp-0> dump-spd all svti svti1
      SPD hash lookup min prefix lengths: local=0, remote=0
      Inbound svti SPD: 1 rules
      1: 0.0.0.0/0 0.0.0.0/0 proto any vr1 protect prio 0
           link-vr1
           svti=svti1(0x6db487c0)
           ESP tunnel 10.23.1.201 - 10.23.1.101
           sp_packets=59 sp_bytes=4956 sp_exceptions=0 sp_errors=0
      Outbound svti SPD: 1 rules
      1: 0.0.0.0/0 0.0.0.0/0 proto any vr1 protect prio 0
           link-vr1 cached-SA 1 (genid 1)
           svti=svti1(0x6db487c0)
           ESP tunnel 10.23.1.101 - 10.23.1.201
           sp_packets=59 sp_bytes=4956 sp_exceptions=0 sp_errors=0

   All |sps| (overall and specific to |svti|) are stored in the same SPD. Their mark
   allows to tell whether they are overall (0) or bound to an |svti| interface.

#. Display |sas|:

   .. code-block:: fp-cli

      <fp-0> "vrf 1;dump-sad all"
      New reference for VRF: 1
      SAD 2 SA.
      1: 10.23.1.101 - 10.23.1.201 vr1 spi 0x12345678 ESP tunnel
             x-vr1 counter 1 cached-SP 0 (genid 1)
             cached-svti 0 (genid 0)
             AES-CBC HMAC-SHA1
             key enc:2889cf9d3f58d80f11a2af9a464c02d3
             key auth:dd2065484027c27fc887520194c07f7b48a76df6
             sa_packets=59 sa_bytes=4956 sa_auth_errors=0 sa_decrypt_errors=0
             sa_replay_errors=0 sa_selector_errors=0
             replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=59
      2: 10.23.1.201 - 10.23.1.101 vr1 spi 0x888f7e8e ESP tunnel
             x-vr1 counter 1 cached-SP 1 (genid 1)
             cached-svti 1 (genid 1)
             AES-CBC HMAC-SHA1
             key enc:3cb2e12a888fd560b2b9097ef23742b9
             key auth:a920f60c94f9ccef4eba7e8ee8b093596df6dab8
             sa_packets=59 sa_bytes=8968 sa_auth_errors=0 sa_decrypt_errors=0
             sa_replay_errors=0 sa_selector_errors=0
             replay check is off width=0 seq=0 bitmap=0x00000000 - oseq=0

#. Display neighbours

   .. code-block:: fp-cli

      <fp-0> dump-neighbours
      R[000008] GW/NEIGH 10.23.1.201 00:55:01:00:00:21 via eth2(0x09000000) REACHABLE (nh:8)
      R[000009] GW/NEIGH 10.22.1.1 00:55:00:00:00:20 via eth1(0x08000000) REACHABLE (nh:9)

#. Delete |svti| |sas|

   .. code-block:: fp-cli

      <fp-0> del-sa esp 10.23.1.201 0x12345678 vr 1
      <fp-0> del-sa esp 10.23.1.101 0x12345678 vr 1

#. |delete-svti-sps|

   .. code-block:: fp-cli

      <fp-0> del-sp in 0.0.0.0/0 0.0.0.0/0 any vr 1 svti svti1
      <fp-0> del-sp out 0.0.0.0/0 0.0.0.0/0 any vr 1 svti svti1

#. |delete-svti|

   .. code-block:: fp-cli

      <fp-0> del-svti svti1

   .. warning::

      The |sps| bound to the |svti| interface are also deleted.
