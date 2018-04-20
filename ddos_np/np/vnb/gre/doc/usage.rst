Usage
=====

:abbr:`GRE (Generic Routing Encapsulation)` support in |vnb| is active by
default as long as the |vnb-gre| module is detected.

To avoid loading the |vnb-gre| module, specify only the VNB modules you want to
load in the MODULES variable in the VNB configuration file
:file:`<install_dir>/usr/local/etc/vnb.env`.

For instance:

::

   : ${MODULES:=ether ppp pppoe}

.. seealso::

   For more information, see the |vnb-baseline| documentation.

GRE nodes creation example
--------------------------

We assume that this interface already exists:

   .. code-block:: console

       # ip addr show eth1
       8: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
           link/ether 00:02:02:00:00:20 brd ff:ff:ff:ff:ff:ff
           inet 2.0.0.1/24 scope global eth1

Here is an example of a simple graph using a :abbr:`GRE (Generic Routing
Encapsulation)` node:

.. aafig::
                ____
               /    \
              |'gre0'|
               \____/
                 |
      ___________|______________________________________
                 |
          +------+------+
          |   'gre0:'   |
          |_____________|
          | 'ng_iface'  |
          +------+------+
                 ^'allip'
                 |
                 v'key_1'
          +------+------+
          |    'gre:'   |
          |_____________|
          |  'ng_gre'   |
          +------+------+
                 ^'lower'
                 |
                 v'inet/raw/gre'
          +------+------+           +-------------+
          |  'ks_gre:'  |           |   'eth1:'   |
          |_____________|           |_____________|
          |'ng_ksocket' |           | 'ng_ether'  |
          +------+------+           +------+------+
                 |                         |
      ___________|_________________________|___________
                 |                         |
                 |                       ____
                 |                      /    \
                 +---------------------|'eth1'|
                                        \____/

#. Enter the following commands:

   .. code-block:: console

      # echo -e "mkpeer .: iface tmp allip\nmsg .:tmp setifname \"gre0\"" | ngctl -f -
      # ngctl
      + mkpeer gre0: gre allip key_1
      + name gre0:allip gre
      + list
        Name: gre             Type: gre             ID: 0000000b   Num hooks: 1   Ns: 0
        Name: ngctl3030       Type: socket          ID: 0000000a   Num hooks: 0   Ns: 0
        Name: gre0            Type: iface           ID: 00000009   Num hooks: 1   Ns: 0
        Name: eth1            Type: ether           ID: 00000004   Num hooks: 0   Ns: 0
      There are 4 total nodes, 4 nodes listed
      + mkpeer gre: ksocket lower inet/raw/gre
      + name gre:lower ks_gre
      + msg ks_gre: bind inet/2.0.0.1:47
      + msg ks_gre: connect inet/2.0.0.5:47
      + list
        Name: ks_gre          Type: ksocket         ID: 0000000c   Num hooks: 1   Ns: 0
        Name: gre             Type: gre             ID: 0000000b   Num hooks: 2   Ns: 0
        Name: ngctl3030       Type: socket          ID: 0000000a   Num hooks: 0   Ns: 0
        Name: gre0            Type: iface           ID: 00000009   Num hooks: 1   Ns: 0
        Name: eth1            Type: ether           ID: 00000004   Num hooks: 0   Ns: 0
      There are 5 total nodes, 5 nodes listed
      + quit

#. Configure the newly created interface:

   .. code-block:: console

      # ip addr add dev gre0 10.10.10.1/24 peer 10.10.10.2/24
      # ifconfig gre0 dstaddr 10.10.10.2
      # ip link set gre0 up

#. Send a ping from the *gre0* interface:

   .. code-block:: console

      # tcpdump -ni eth1 &
      # ping -c 1 10.10.10.2
      PING 10.10.10.2 (10.10.10.2) 56(84) bytes of data.
      12:08:36.421812 IP 2.0.0.1 > 2.0.0.5: GREv0, off 0x0, key=0x1, length 96: IP 10.10.10.1 > 10.10.10.2: ICMP echo request, id 3043, seq 1, length 64
      12:08:36.431924 00:00:00:00:00:00 > 00:02:02:00:00:20, ethertype Unknown (0x2007), length 156:
              0x0000:  6049 4000 0000 0000 3311 7022 0002 0200  .I@.....3.p"....
              0x0010:  0020 0055 0000 0020 0800 4500 0074 44da  ...U......E..tD.
              0x0020:  4000 402f f17b 0200 0005 0200 0001 a000  @.@/.{..........
              0x0030:  0800 57fe 0000 0000 0001 4500 0054 1af1  ..W.......E..T..
              0x0040:  0000 4001 37a2 0a0a 0a02 0a0a 0a01 0000  ..@.7...........
              0x0050:  76a4 0be3 0001 34e2 0553 0000 0000 7e6f  v.....4..S....~o
              0x0060:  0600 0000 0000 1011 1213 1415 1617 1819  ................
              0x0070:  1a1b 1c1d 1e1f 2021 2223 2425 2627 2829  .......!"#$%&'()
              0x0080:  2a2b 2c2d 2e2f 3031 3233 3435 3637       .+,-./01234567
      12:08:36.431924 IP 2.0.0.5 > 2.0.0.1: GREv0, off 0x0, key=0x1, length 96: IP 10.10.10.2 > 10.10.10.1: ICMP echo reply, id 3043, seq 1, length 64
      12:08:36.432004 00:00:00:00:00:00 > 00:02:02:00:00:20, ethertype Unknown (0x2007), length 110:
              0x0000:  12c1 4000 0800 0000 4c28 ca82 4500 0054  ..@.....L(..E..T
              0x0010:  1af1 0000 4001 37a2 0a0a 0a02 0a0a 0a01  ....@.7.........
              0x0020:  0000 76a4 0be3 0001 34e2 0553 0000 0000  ..v.....4..S....
              0x0030:  7e6f 0600 0000 0000 1011 1213 1415 1617  ~o..............
              0x0040:  1819 1a1b 1c1d 1e1f 2021 2223 2425 2627  .........!"#$%&'
              0x0050:  2829 2a2b 2c2d 2e2f 3031 3233 3435 3637  ().+,-./01234567
      64 bytes from 10.10.10.2: icmp_req=1 ttl=64 time=10.2 ms

      --- 10.10.10.2 ping statistics ---
      1 packets transmitted, 1 received, 0% packet loss, time 0ms
      rtt min/avg/max/mdev = 10.246/10.246/10.246/0.000 ms

   The packet seen by *eth1* is a :abbr:`GRE (Generic Routing Encapsulation)`
   packet.
