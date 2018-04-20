Usage
=====

:abbr:`LAG (Link Aggregation)` support in :abbr:`VNB (Virtual Networking Blocks
technology)` is active by default as long as the |vnb-lag| module is detected.

To avoid loading the |vnb-lag| module, specify only the VNB modules you want to
load in the *MODULES* variable in the VNB configuration file
:file:`<install_dir>/usr/local/etc/vnb.env`.

For instance:

::

   : ${MODULES:=ether ppp pppoe}

.. seealso::

   For more information, see the |vnb-baseline| documentation.

LAG nodes creation example
--------------------------

We assume that these 2 interfaces already exist:

   .. code-block:: console

       # ip addr show eth1
       8: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
           link/ether 00:02:02:00:00:20 brd ff:ff:ff:ff:ff:ff
           inet 2.0.0.1/24 scope global eth1
       # ip addr show eth2
       9: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
           link/ether 00:02:02:00:00:21 brd ff:ff:ff:ff:ff:ff
           inet 2.0.0.2/24 scope global eth1

Here is an example of a simple graph using a :abbr:`LAG (Link Aggregation)`
node:

.. aafig::

                           _______
                          /       \
                         |'ethgrp0'|
                          \_______/
                              |
      ________________________|_______________________
                              |
                       +------+------+
                       |  'ethgrp0:' |
                       |_____________|
                       | 'ng_eiface' |
                       +------+------+
                              ^'ether'
                              |
                              v'upper'
                       +------+------+
               'link_1'|    'lag:'   |'link_2'
                 +---->+_____________+<----+
                 |     | 'ng_ethgrp' |     |
                 |     +-------------+     |
                 |                         |
                 |                         |
                 v'lower'                  v'lower'
          +------+------+           +------+------+
          |   'eth1:'   |           |   'eth2:'   |
          |_____________|           |_____________|
          | 'ng_ether'  |           | 'ng_ether'  |
          +------+------+           +------+------+
                 |                         |
      ___________|_________________________|__________
                 |                         |
                ____                     ____
               /    \                   /    \
              |'eth1'|                 |'eth2'|
               \____/                   \____/

#. Enter the following netgraph commands:

   .. code-block:: console

      # ngctl
      + mkpeer eth1: ethgrp lower link_1
      + name eth1:lower lag
      + connect eth2: lag: lower link_2
      + list
        Name: lag             Type: ethgrp          ID: 0000000a   Num hooks: 2   Ns: 0
        Name: ngctl3083       Type: socket          ID: 00000009   Num hooks: 0   Ns: 0
        Name: eth2            Type: ether           ID: 00000005   Num hooks: 1   Ns: 0
        Name: eth1            Type: ether           ID: 00000004   Num hooks: 1   Ns: 0
      There are 4 total nodes, 4 nodes listed
      + mkpeer lag: eiface upper ether
      + name lag:upper ethgrp
      + msg ethgrp: setifname "ethgrp0"
      + msg lag: sethookmod {id=1 mode=1}
      + msg lag: sethookmod {id=2 mode=1}
      + msg lag: setalgo "rr"
      + list
        Name: ethgrp0         Type: ether           ID: 0000000c   Num hooks: 0   Ns: 0
        Name: ethgrp          Type: eiface          ID: 0000000b   Num hooks: 1   Ns: 0
        Name: lag             Type: ethgrp          ID: 0000000a   Num hooks: 3   Ns: 0
        Name: ngctl3083       Type: socket          ID: 00000009   Num hooks: 0   Ns: 0
        Name: eth2            Type: ether           ID: 00000005   Num hooks: 1   Ns: 0
        Name: eth1            Type: ether           ID: 00000004   Num hooks: 1   Ns: 0
      There are 6 total nodes, 6 nodes listed
      + quit

#. Configure the newly created interface:

   .. code-block:: console

      # ip link set eth1 promisc on
      # ip link set eth2 promisc on
      # ip link set ethgrp0 up
      # ip addr add dev ethgrp0 10.10.10.1/24

#. Send a ping from the *ethgrp0* interface:

   .. code-block:: console

      # tcpdump -ni eth1 &
      # ping -c 2 10.10.10.2
      PING 10.10.10.2 (10.10.10.2) 56(84) bytes of data.
      64 bytes from 10.10.10.2: icmp_req=1 ttl=64 time=0.196 ms
      11:02:07.406426 IP 10.10.10.1 > 10.10.10.2: ICMP echo request, id 3374, seq 2, length 64
      11:02:07.407223 00:00:00:00:00:00 > 00:02:02:00:00:20, ethertype Unknown (0x2007), length 124:
              0x0000:  6049 4000 0000 0000 3311 7022 0000 0000  .I@.....3.p"....
              0x0010:  0000 0209 c0ce ab48 0800 4500 0054 50c3  .......H..E..TP.
              0x0020:  0000 4001 01d0 0a0a 0a02 0a0a 0a01 0000  ..@.............
              0x0030:  fea3 0d2e 0002 9fd2 0553 0000 0000 8a33  .........S.....3
              0x0040:  0600 0000 0000 1011 1213 1415 1617 1819  ................
              0x0050:  1a1b 1c1d 1e1f 2021 2223 2425 2627 2829  .......!"#$%&'()
              0x0060:  2a2b 2c2d 2e2f 3031 3233 3435 3637       .+,-./01234567
      11:02:07.407223 IP 10.10.10.2 > 10.10.10.1: ICMP echo reply, id 3374, seq 2, length 64
      11:02:07.408085 00:00:00:00:00:00 > 00:02:02:00:00:20, ethertype Unknown (0x2007), length 124:
              0x0000:  10c1 4000 0000 0000 5659 046e 0000 0000  ..@.....VY.n....
              0x0010:  0000 0209 c0ce ab48 0800 4500 0054 50c3  .......H..E..TP.
              0x0020:  0000 4001 01d0 0a0a 0a02 0a0a 0a01 0000  ..@.............
              0x0030:  fea3 0d2e 0002 9fd2 0553 0000 0000 8a33  .........S.....3
              0x0040:  0600 0000 0000 1011 1213 1415 1617 1819  ................
              0x0050:  1a1b 1c1d 1e1f 2021 2223 2425 2627 2829  .......!"#$%&'()
              0x0060:  2a2b 2c2d 2e2f 3031 3233 3435 3637       .+,-./01234567
      64 bytes from 10.10.10.2: icmp_req=2 ttl=64 time=1.67 ms

      --- 10.10.10.2 ping statistics ---
      2 packets transmitted, 2 received, 0% packet loss, time 999ms
      rtt min/avg/max/mdev = 0.196/0.935/1.675/0.740 ms

   Only one ping is seen on *eth1* even though two pings are sent. The other
   ping is sent through *eth2*.
