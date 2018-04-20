Usage
=====

To use Linux synchronization, start the |cmgr| and the |fpm|:

.. code-block:: console

   # modprobe vrf
   # modprobe ifuid
   # modprobe fptun
   # modprobe ipip
   # modprobe sit
   # modprobe ip6_tunnel
   # fpmd
   # cmgrd

Example
-------

   .. code-block:: console

      # echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
      # ip a a 10.22.4.104/24 dev eth1
      # ip a a 10.23.4.104/24 dev eth3
      # ip link set up dev eth1
      # ip link set up dev eth3

      # ip tu ad ipiptun mode ipip local 10.23.4.104 remote 10.23.4.204 ttl 64 dev eth3
      # ip ad ad dev ipiptun 192.168.1.1 peer 192.168.1.2/32
      # ip li se dev ipiptun up
      # ip ro ad 10.24.4.119/32 via 192.168.1.1

      # fp-cli

.. code-block:: fp-cli

   <fp-0> dump-interface
   96:eth2 [VR-0] ifuid=0x6008c1d2 (virtual) <UP|RUNNING|FWD4|FWD6> (0x63)
        type=ether mac=00:1b:21:c5:7f:75 mtu=1500 tcp4mss=0 tcp6mss=0
        blade=1
        IPv4 routes=1  IPv6 routes=0
        100:fpn0 [VR-0] ifuid=0x64247322 (virtual) <UP|RUNNING|FWD4|FWD6> (0x63)
        type=ether mac=00:00:46:50:4e:00 mtu=1500 tcp4mss=0 tcp6mss=0
        blade=1
        IPv4 routes=0  IPv6 routes=0
        117:lo [VR-0] ifuid=0x754c6fa8 (virtual) <UP|RUNNING|FWD4|FWD6> (0x63)
        type=loop mac=00:00:00:00:00:00 mtu=16436 tcp4mss=0 tcp6mss=0
        blade=1
        IPv4 routes=0  IPv6 routes=0
        141:eth3 [VR-0] ifuid=0x8d001382 (port 1) <UP|RUNNING|FWD4|FWD6> (0x63)
        type=ether mac=00:1b:21:c5:7f:76 mtu=1500 tcp4mss=0 tcp6mss=0
        blade=1
        IPv4 routes=0  IPv6 routes=0
        307:eth1 [VR-0] ifuid=0x33117022 (port 0) <UP|RUNNING|FWD4|FWD6> (0x63)
        type=ether mac=00:1b:21:c5:7f:74 mtu=1500 tcp4mss=0 tcp6mss=0
        blade=1
        IPv4 routes=0  IPv6 routes=0
        311:ipiptun [VR-0] ifuid=0x374524b0 (virtual) <UP|RUNNING|FWD4|FWD6> (0x63)
        type=Xin4 (6to4) mac=00:00:00:00:00:00 mtu=1480 tcp4mss=0 tcp6mss=0
        blade=1 link-vrfid=0
        Xin4(6to4) tunnel ttl=0 local=10.23.4.104 remote=10.23.4.204
        IPv4 routes=0  IPv6 routes=0
        518:eth0 [VR-0] ifuid=0x61a1e72 (virtual) <FWD4|FWD6> (0x60)
        type=ether mac=00:21:85:c1:82:58 mtu=1500 tcp4mss=0 tcp6mss=0
        blade=1
        IPv4 routes=0  IPv6 routes=0
        953:eth4 [VR-0] ifuid=0xb9f76532 (port 2) <FWD4|FWD6> (0x60)
        type=ether mac=00:1b:21:c5:7f:77 mtu=1500 tcp4mss=0 tcp6mss=0
        blade=1
        IPv4 routes=0  IPv6 routes=0
        <fp-0> dump-user all
        # - Preferred, * - Active, > - selected
        0.0.0.0/32  [5001]  LOCAL (1)
        10.22.4.104/32  [02]  ADDRESS via eth1(0x33117022) (6)
        10.22.4.118/32  [06]  NEIGH gw 10.22.4.118 (N) via eth1(0x33117022) (10)
        10.23.4.104/32  [03]  ADDRESS via eth3(0x8d001382) (7)
        10.23.4.204/32  [05]  NEIGH gw 10.23.4.204 (N) via eth3(0x8d001382) (9)
        10.24.4.119/32  [09]  ROUTE gw 192.168.1.1 via ipiptun(0x374524b0) (12)
        10.81.0.100/32  [08]  NEIGH gw 10.81.0.100 (N) via eth2(0x6008c1d2) (11)
        10.81.0.141/32  [01]  ADDRESS via eth2(0x6008c1d2) (5)
        127.0.0.0/8  [5002]  BLACKHOLE (4)
        192.168.1.1/32  [04]  ADDRESS via ipiptun(0x374524b0) (8)
        224.0.0.0/4  [5001]  LOCAL (3)
        255.255.255.255/32  [5001]  LOCAL (2)

Tunnel management
-----------------

tun-xin4-add
~~~~~~~~~~~~

.. rubric:: Description

Add a new IPvX in IPv4 tunnel.

.. rubric:: Synopsis

.. code-block:: fp-cli

   tun-xin4-add NAME LOCAL_ADDR REMOTE_ADDR [options*]
      [vr VR] [lvr LVR]
      [mtu MTU] [ttl TTL]
      [tos TOS] [inhtos INHTOS]

.. rubric:: Parameters

NAME
   Name of the tunnel interface.
LOCAL_ADDR
   IPv4 address of local tunnel end point.
REMOTE_ADDR
   IPv4 address of remote tunnel end point.
Options
   Any combination of following options:
      - vr VR, id of the |vrf| of the tunnel to create
      - lvr VR, id of the link |vrf| of the tunnel to create
      - mtu MTU, mtu to set on the tunnel
      - ttl TTL, time to live to set on packets entering the tunnel
      - tos TOS, type of service to set on tunnel
      - inhhtos, inherited type of service to set on tunnel

.. rubric:: Example

.. code-block:: fp-cli

   # <fp-0> tun-xin4-add tunnel1 10.23.4.104 10.23.4.204

tun-xin4-del
~~~~~~~~~~~~

.. rubric:: Description

Delete an existing IPvX in IPv4 tunnel.

.. rubric:: Synopsis

.. code-block:: fp-cli

   tun-xin4-del NAME

.. rubric:: Parameters

NAME
   Name of the tunnel interface to delete

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> tun-xin4-del tunnel1
   removing xin4 (ctu) tunnel1 ifuid=0x8ccc4ac5 bound to port 254
