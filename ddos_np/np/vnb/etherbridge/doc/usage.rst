Usage
=====

|vnb-eth-bridge| support in |vnb| is
active by default as long as the |vnb-eth-bridge| module is detected.

To avoid loading the |vnb-eth-bridge| module, specify only the VNB modules you
want to load in the *MODULES* variable in the VNB configuration file
:file:`<install_dir>/usr/local/etc/vnb.env`.

For instance:

::

   : ${MODULES:=ether ppp pppoe}

.. seealso::

   For more information, see the |vnb-baseline| documentation.

|vnb-eth-bridge| node creation example
--------------------------------------

We assume that these 2 interfaces already exist:

   .. code-block:: console

       # ip addr show eth1
       8: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
           link/ether 00:02:02:00:00:20 brd ff:ff:ff:ff:ff:ff
       # ip addr show eth2
       9: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
           link/ether 00:02:02:00:00:21 brd ff:ff:ff:ff:ff:ff

Here is an example of a simple graph using a *ng_bridge* node:

.. aafig::
                            _____
                           /     \
                          |'bnet0'|
                           \_____/
                              |
      ________________________|_______________________
                              |
                       +------+------+
                       | 'if_bridge:'|
                       |_____________|
                       | 'ng_eiface' |
                       +------+------+
                              ^'ether'
                              |
                              v'link_2'
                       +------+------+
               'link_0'|  'bridge:'  |'link_1'
                 +---->+_____________+<----+
                 |     | 'ng_bridge' |     |
                 |     +-------------+     |
                 |                         |
                 |                         |
                 v'lower'                  v'lower'
          +------+------+           +------+------+
          |   'eth1:'   |           |   'eth2:'   |
          |_____________|           |_____________|
          | 'ng_ether'  |           | 'ng_ether'  |
          +-----+-------+           +------+------+
                |                          |
      __________|__________________________|__________
                |                          |
               _+__                      __+_
              /    \                    /    \
             |'eth1'|                  |'eth2'|
              \____/                    \____/

#. Enter the following netgraph commands:

   .. code-block:: console

      # ngctl
      + mkpeer eth1: bridge lower link0
      + name eth1:lower bridge
      + connect eth2: bridge: lower link1
      + list
        Name: bridge          Type: bridge          ID: 00000009   Num hooks: 2   Ns: 0
        Name: ngctl3048       Type: socket          ID: 00000008   Num hooks: 0   Ns: 0
        Name: eth2            Type: ether           ID: 00000005   Num hooks: 1   Ns: 0
        Name: eth1            Type: ether           ID: 00000004   Num hooks: 1   Ns: 0
      There are 4 total nodes, 4 nodes listed
      + mkpeer bridge: eiface link2 ether
      + name bridge:link2 if_bridge
      + msg if_bridge: setifname "bnet0"
      + list
        Name: bnet0           Type: ether           ID: 0000000b   Num hooks: 0   Ns: 0
        Name: if_bridge       Type: eiface          ID: 0000000a   Num hooks: 1   Ns: 0
        Name: bridge          Type: bridge          ID: 00000009   Num hooks: 3   Ns: 0
        Name: ngctl3048       Type: socket          ID: 00000008   Num hooks: 0   Ns: 0
        Name: eth2            Type: ether           ID: 00000005   Num hooks: 1   Ns: 0
        Name: eth1            Type: ether           ID: 00000004   Num hooks: 1   Ns: 0
      There are 6 total nodes, 6 nodes listed
      + quit

#. Configure the newly created interface:

   .. code-block:: console

      # ip link set eth1 promisc on
      # ip link set eth2 promisc on
      # ip link set bnet0 up

#. Send a ping from a machine connected to *eth1*:

   As the goal of this example is to create a bridge between *eth1* and *eth2*,
   we will ping from a machine connected to *eth1* to a machine connected to
   *eth2*. The 2 machines must be configured on the same subnet, as if they were
   directly connected. The machine where the bridge is configured does not need
   to be assigned an IP address.

   Here is what is seen on *eth2*:

   .. code-block:: console

      # tcpdump -ni eth2
      17:43:27.958088 IP 2.0.0.5 > 2.0.0.6: ICMP echo request, id 58373, seq 1, length 64
      17:43:27.959133 00:00:00:00:00:00 > 00:02:02:00:00:21, ethertype Unknown (0x2007), length 124:
              0x0000:  6049 4000 0000 0000 6008 c1d2 0055 0000  .I@..........U..
              0x0010:  0020 0055 0100 0021 0800 4500 0054 7def  ...U...!..E..T}.
              0x0020:  0000 4001 f8af 0200 0006 0200 0005 0000  ..@.............
              0x0030:  7760 e405 0001 ae30 0653 0000 0000 c3e2  w`.....0.S......
              0x0040:  0e00 0000 0000 0809 0a0b 0c0d 0e0f 1011  ................
              0x0050:  1213 1415 1617 1819 1a1b 1c1d 1e1f 2021  ...............!
              0x0060:  2223 2425 2627 2829 2a2b 2c2d 2e2f       "#$%&'().+,-./
      17:43:27.959133 IP 2.0.0.6 > 2.0.0.5: ICMP echo reply, id 58373, seq 1, length 64
      17:43:32.952839 00:00:00:00:00:00 > 00:02:02:00:00:21, ethertype Unknown (0x2007), length 86:
              0x0000:  6049 4000 0000 0000 6008 c1d2 0055 0000  .I@..........U..
              0x0010:  0020 0055 0100 0021 0806 0001 0800 0604  ...U...!........
              0x0020:  0001 0055 0100 0021 0200 0006 0000 0000  ...U...!........
              0x0030:  0000 0200 0005 0000 0000 0000 0000 0000  ................
              0x0040:  0000 0000 0000 0000                      ........

   The packet sent through *eth1* is directly emitted by *eth2* to the other
   side of the network.
