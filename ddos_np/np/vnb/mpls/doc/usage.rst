Usage
=====

MPLS/VPLS support in |vnb| is active by
default as long as the |vnb-mpls-vpls| module is detected.

To avoid loading the |vnb-mpls-vpls| module, specify only the VNB modules you
want to load in the *MODULES* variable in the VNB configuration file
:file:`<install_dir>/usr/local/etc/vnb.env`.

For instance:

::

   : ${MODULES:=ether ppp pppoe}

.. seealso::

   For more information, see the |vnb-baseline| documentation.

MPLS/VPLS nodes creation example
--------------------------------

In this example we will create the following MPLS/VPLS network:

.. aafig::

    +--------+                    +--------+                    +--------+
    |        |'eth2_0'      'eth1'|        |'eth2'      'eth2_1'|        |
    | 'left' +--------------------+'middle'+--------------------+'right' |
    |        |     'LABEL 10'     |        |     'LABEL 11'     |        |
    +---+----+                    +--------+                    +----+---+
        |                                                            |
    'mpls0:10.10.10.1'                                  'mpls0:10.10.10.2'

Host *left* configuration
~~~~~~~~~~~~~~~~~~~~~~~~~

We assume that this interface already exists:

   .. code-block:: console

       # ip addr show eth2_0
       8: eth2_0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
           link/ether 00:02:02:00:00:20 brd ff:ff:ff:ff:ff:ff

Here is the net graph we will use:

.. aafig::

               _____                                                                                            ______
              /     \                                                                                          /      \
             |'mpls0'|                                                                                        |'eth2_0'|
              \_____/                                                                                          \______/
                 |                                                                                                |
     ____________|________________________________________________________________________________________________|____________
                 |                                                                                                |
         +---------------+                                                                                +---------------+
         |   'mpls0:'    |                                                                                |   'eth2_0:'   |
         |_______________|                                                                                |_______________|
         |  'ng_iface'   |                                                                                |  'ng_ether'   |
         +-------+-------+                                                                                +----+-----+----+
                 ^'allip'                                                                               'lower'^     ^'upper'
                 |                                                                                             |     |
                 |                                                                                 'downstream'v     |'nomatch'
                 |                                                                                        +----+-----+----+
                 |                                                                                        |     'etf:'    |
                 |                                                                                        |_______________|
                 |                                                                                        |   'ng_etf'    |
                 |                                                                                        +-------+-------+
                 |                                   'nhlfe_out'    'ether_in_'                                   ^'link_8847'
                 |                                        +-------------+                                         |
                 |     '                                  |             |                                         |
                 v'mixa'                                  |             v                                         v'mixa'
         +-------+-------+                    +-----------+---+     +---+-----------+                     +-------+-------+
         |   'split1:'   |                    | 'mpls_push10:'|     |  'mpls_eth:'  |                     |   'split2:'   |
         |_______________+------------------->+_______________|     |_______________+-------------------->|_______________|
         |  'ng_split'   |'mixb'    'nhlfe_in'|'ng_mpls_nhlfe'|     |'ng_mpls_ether'|'ether_out' 'in2mixa'|  'ng_split'   |
         +-------+-------+                    +---------------+     +---------------+                     +-------+-------+
        'in2mixa'^                                                                                                |'mixb'
                 |                                   'nhlfe_in'    'nhlfe_10'                                     |
                 |                                        +-------------+                                         |
                 |                                        |             |                                         |
                 |                                        v             |                                         |
                 |                            +-----------+---+     +---+-----------+                             |
                 |                            | 'mpls_pop10:' |     |  'mpls_ilm:'  |                             |
                 +----------------------------+_______________|     |_______________+<----------------------------+
                                   'nhlfe_out'|'ng_mpls_nhlfe'|     | 'ng_mpls_ilm' |'lower_ether'
                                              +---------------+     +---------------+

.. note::

    The *ng_etf* node is part of the |vnb-eth-bridge| module.

#. Enter the following commands:

   .. code-block:: console

      # echo -e "mkpeer .: iface tmp allip\nmsg .:tmp setifname \"mpls0\"" | ngctl -f -
      # ngctl
      + mkpeer mpls0: split allip mixa
      + name mpls0:allip split1
      + mkpeer split1: mpls_nhlfe mixb nhlfe_in
      + name split1:mixb mpls_push10
      + msg mpls_push10: setconfig { debugFlag=0 uplayer=0 operation=1 label=10 exp=0 ttl=255 }
      + mkpeer mpls_push10: mpls_ether nhlfe_out ether_in_
      + name mpls_push10:nhlfe_out mpls_eth
      + mkpeer eth2_0: etf lower downstream
      + name eth2_0:lower etf
      + connect etf: eth2_0: nomatch upper
      + mkpeer etf: split link_8847 mixa
      + name etf:link_8847 split2
      + connect split2: mpls_eth: in2mixa ether_out
      + msg etf: setfilter { matchhook=\"link_8847\" ethertype=0x8847 }
      + mkpeer split2: mpls_ilm mixb lower_ether_
      + name split2:mixb mpls_ilm
      + mkpeer mpls_ilm: mpls_nhlfe nhlfe_10 nhlfe_in
      + name mpls_ilm:nhlfe_10 mpls_pop10
      + msg mpls_pop10: setconfig { debugFlag=0 uplayer=0 operation=3 label=10 exp=0 ttl=255 }
      + connect mpls_pop10: split1: nhlfe_out in2mixa
      + list
        Name: ngctl1533       Type: socket          ID: 00000023   Num hooks: 0   Ns: 0
        Name: mpls_pop10      Type: mpls_nhlfe      ID: 0000001f   Num hooks: 2   Ns: 0
        Name: mpls_ilm        Type: mpls_ilm        ID: 0000001c   Num hooks: 2   Ns: 0
        Name: split2          Type: split           ID: 00000017   Num hooks: 3   Ns: 0
        Name: etf             Type: etf             ID: 00000013   Num hooks: 3   Ns: 0
        Name: mpls_eth        Type: mpls_ether      ID: 00000010   Num hooks: 2   Ns: 0
        Name: mpls_push10     Type: mpls_nhlfe      ID: 0000000c   Num hooks: 2   Ns: 0
        Name: split1          Type: split           ID: 00000009   Num hooks: 3   Ns: 0
        Name: mpls0           Type: iface           ID: 00000007   Num hooks: 1   Ns: 0
        Name: eth2_0          Type: ether           ID: 00000002   Num hooks: 2   Ns: 0
      There are 10 total nodes, 10 nodes listed
      + quit

#. Configure the newly created interface:

   .. code-block:: console

      # ip link set eth2_0 promisc on
      # ip addr addr 10.10.10.1/24 dev mpls0
      # ip link set mpls0 up

Host *middle* configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~

We assume that these 2 interfaces already exist:

   .. code-block:: console

       # ip addr show eth1
       8: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
           link/ether 00:02:02:00:00:20 brd ff:ff:ff:ff:ff:ff
       # ip addr show eth2
       9: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
           link/ether 00:02:02:00:00:21 brd ff:ff:ff:ff:ff:ff

Here is the net graph we will use:

.. aafig::
                ____                                                                                             ____
               /    \                                                                                           /    \
              |'eth1'|                                                                                         |'eth2'|
               \____/                                                                                           \____/
                 |                                                                                                 |
     ____________|_________________________________________________________________________________________________|____________
                 |                                                                                                 |
         +---------------+                                                                                 +---------------+
         |    'eth1:'    |                                                                                 |    'eth2:'    |
         |_______________|                                                                                 |_______________|
         |  'ng_ether'   |                                                                                 |  'ng_ether'   |
         +----+-----+----+                                                                                 +----+-----+----+
       'lower'^     ^'upper'                                                                             'lower'^     ^'upper'
              |     |                                                                                           |     |
  'downstream'v     |'nomatch'                                                                      'downstream'v     |'nomatch'
         +----+-----+----+                                                                                 +----+-----+----+
         |    'etf1:'    |                                                                                 |    'etf2:'    |
         |_______________|                                                                                 |_______________|
         |   'ng_etf'    |                                                                                 |   'ng_etf'    |
         +-------+-------+                                                                                 +-------+-------+
      'link_8847'^                        'nhlfe_10'    'nhlfe_in' 'nhlfe_out'   'ether_in_'                       ^'link_8847'
                 |                             +-------------+         +-------------+                             |
                 |                             |             |         |             |                             |
           'mixa'v                             |             v         |             v                             v'mixa'
         +-------+-------+        +------------+--+       +--+---------+--+       +--+------------+        +-------+-------+
         |   'split1:'   |        |  'mpls_ilm1:' |       | 'mpls_swap11:'|       |  'mpls_eth1:' |        |   'split2:'   |
         |_______________|        |_______________|       |_______________|       |_______________|        |_______________|
         |  'ng_split'   |        | 'ng_mpls_ilm' |       |'ng_mpls_nhlfe'|       |'ng_mpls_ether'|        |  'ng_split'   |
         +---+-------+---+        +--+------------+       +---------------+       +-----------+---+        +---+-------+---+
    'in2mixa'^       |               |                                                        |                |       |'mixb'
             |       +---------------+                                                        +----------------+       |
             |     'mixb'     'lower_ether_'                                              'ether_out'      'in2mixa'   |
             |                                                                                                         |
             |                    +---------------+       +---------------+       +---------------+                    |
             |                    |  'mpls_eth2:' |       | 'mpls_swap10:'|       |  'mpls_ilm2:' |                    |
             +--------------------+_______________|       |_______________|       |_______________+<-------------------+
                       'ether_out'|'ng_mpls_ether'|       |'ng_mpls_nhlfe'|       | 'ng_mpls_ilm' |'lower_ether'
                                  +------------+--+       +--+---------+--+       +--+------------+
                                               ^             |         ^             |
                                               |             |         |             |
                                               +-------------+         +-------------+
                                         'ether_in'    'nhlfe_out' 'nhlfe_in'    'nhlfe_11'

.. note::

    The *ng_etf* node is part of the |vnb-eth-bridge| module.

#. Enter the following netgraph commands:

   .. code-block:: console

       # ngctl
       + mkpeer eth1: etf lower downstream
       + name eth1:lower etf1
       + connect etf1: eth1: nomatch upper
       + mkpeer etf1: split link_8847 mixa
       + name etf1:link_8847 split1
       + msg etf1: setfilter { matchhook="link_8847" ethertype=0x8847 }
       + mkpeer split1: mpls_ilm mixb lower_ether_
       + name split1:mixb mpls_ilm1
       + mkpeer mpls_ilm1: mpls_nhlfe nhlfe_10 nhlfe_in
       + name mpls_ilm1:nhlfe_10 mpls_swap11
       + msg mpls_swap11: setconfig { debugFlag=0 uplayer=0 operation=2 label=11 exp=0 ttl=255 }
       + mkpeer mpls_swap11: mpls_ether nhlfe_out ether_in_
       + name mpls_swap11:nhlfe_out mpls_eth1
       + mkpeer eth2: etf lower downstream
       + name eth2:lower etf2
       + connect etf2: eth2: nomatch upper
       + mkpeer etf2: split link_8847 mixa
       + name etf2:link_8847 split2
       + connect split2: mpls_eth1: in2mixa ether_out
       + msg etf2: setfilter { matchhook="link_8847" ethertype=0x8847 }
       + mkpeer split2: mpls_ilm mixb lower_ether_
       + name split2:mixb mpls_ilm2
       + mkpeer mpls_ilm2: mpls_nhlfe nhlfe_11 nhlfe_in
       + name mpls_ilm2:nhlfe_11 mpls_swap10
       + msg mpls_swap10: setconfig { debugFlag=0 uplayer=0 operation=2 label=10 exp=0 ttl=255 }
       + mkpeer mpls_swap10: mpls_ether nhlfe_out ether_in_
       + name mpls_swap10:nhlfe_out mpls_eth2
       + connect mpls_eth2: split1: ether_out in2mixa
       + show
         Name: ngctl2995       Type: socket          ID: 0000002e   Num hooks: 0   Ns: 0
         Name: mpls_eth2       Type: mpls_ether      ID: 0000002b   Num hooks: 2   Ns: 0
         Name: mpls_swap10     Type: mpls_nhlfe      ID: 00000027   Num hooks: 2   Ns: 0
         Name: mpls_ilm2       Type: mpls_ilm        ID: 00000024   Num hooks: 2   Ns: 0
         Name: split2          Type: split           ID: 0000001f   Num hooks: 3   Ns: 0
         Name: etf2            Type: etf             ID: 0000001b   Num hooks: 3   Ns: 0
         Name: mpls_eth1       Type: mpls_ether      ID: 00000018   Num hooks: 2   Ns: 0
         Name: mpls_swap11     Type: mpls_nhlfe      ID: 00000014   Num hooks: 2   Ns: 0
         Name: mpls_ilm1       Type: mpls_ilm        ID: 00000011   Num hooks: 2   Ns: 0
         Name: split1          Type: split           ID: 0000000d   Num hooks: 3   Ns: 0
         Name: etf1            Type: etf             ID: 00000009   Num hooks: 3   Ns: 0
         Name: eth2            Type: ether           ID: 00000005   Num hooks: 2   Ns: 0
         Name: eth1            Type: ether           ID: 00000004   Num hooks: 2   Ns: 0
       There are 13 total nodes, 13 nodes listed
       + quit

#. Configure the interfaces:

   .. code-block:: console

      # ip link set eth1 promisc on
      # ip link set eth2 promisc on

Host *right* configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~

We assume that this interface already exists:

   .. code-block:: console

       # ip addr show eth2_1
       8: eth2_0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
           link/ether 00:02:02:00:00:20 brd ff:ff:ff:ff:ff:ff

Here is the  net graph we will use:

.. aafig::

               _____                                                                                            ______
              /     \                                                                                          /      \
             |'mpls0'|                                                                                        |'eth2_0'|
              \_____/                                                                                          \______/
                 |                                                                                                |
     ____________|________________________________________________________________________________________________|____________
                 |                                                                                                |
         +---------------+                                                                                +---------------+
         |   'mpls0:'    |                                                                                |   'eth2_0:'   |
         |_______________|                                                                                |_______________|
         |  'ng_iface'   |                                                                                |  'ng_ether'   |
         +-------+-------+                                                                                +----+-----+----+
                 ^'allip'                                                                               'lower'^     ^'upper'
                 |                                                                                             |     |
                 |                                                                                 'downstream'v     |'nomatch'
                 |                                                                                        +----+-----+----+
                 |                                                                                        |     'etf:'    |
                 |                                                                                        |_______________|
                 |                                                                                        |   'ng_etf'    |
                 |                                                                                        +-------+-------+
                 |                                   'nhlfe_out'    'ether_in_'                                   ^'link_8847'
                 |                                        +-------------+                                         |
                 |                                        |             |                                         |
                 v'mixa'                                  |             v                                         v'mixa'
         +-------+-------+                    +-----------+---+     +---+-----------+                     +-------+-------+
         |   'split1:'   |                    | 'mpls_push11:'|     |  'mpls_eth:'  |                     |   'split2:'   |
         |_______________+------------------->+_______________|     |_______________+-------------------->|_______________|
         |  'ng_split'   |'mixb'    'nhlfe_in'|'ng_mpls_nhlfe'|     |'ng_mpls_ether'|'ether_out' 'in2mixa'|  'ng_split'   |
         +-------+-------+                    +---------------+     +---------------+                     +-------+-------+
        'in2mixa'^                                                                                                |'mixb'
                 |                                   'nhlfe_in'    'nhlfe_11'                                     |
                 |                                        +-------------+                                         |
                 |                                        |             |                                         |
                 |                                        v             |                                         |
                 |                            +-----------+---+     +---+-----------+                             |
                 |                            | 'mpls_pop11:' |     |  'mpls_ilm:'  |                             |
                 +----------------------------+_______________|     |_______________+<----------------------------+
                                   'nhlfe_out'|'ng_mpls_nhlfe'|     | 'ng_mpls_ilm' |'lower_ether'
                                              +---------------+     +---------------+

.. note::

    - The *ng_etf* node is part of the |vnb-eth-bridge| module.
    - The graph is similar to the host *left* graph, only label numbers and the
      interface name change.

#. Enter the following commands:

   .. code-block:: console

      # echo -e "mkpeer .: iface tmp allip\nmsg .:tmp setifname \"mpls0\"" | ngctl -f -
      # ngctl
      + mkpeer mpls0: split allip mixa
      + name mpls0:allip split1
      + mkpeer split1: mpls_nhlfe mixb nhlfe_in
      + name split1:mixb mpls_push11
      + msg mpls_push11: setconfig { debugFlag=0 uplayer=0 operation=1 label=11 exp=0 ttl=255 }
      + mkpeer mpls_push11: mpls_ether nhlfe_out ether_in_
      + name mpls_push11:nhlfe_out mpls_eth
      + mkpeer eth2_1: etf lower downstream
      + name eth2_1:lower etf
      + connect etf: eth2_1: nomatch upper
      + mkpeer etf: split link_8847 mixa
      + name etf:link_8847 split2
      + connect split2: mpls_eth: in2mixa ether_out
      + msg etf: setfilter { matchhook=\"link_8847\" ethertype=0x8847 }
      + mkpeer split2: mpls_ilm mixb lower_ether_
      + name split2:mixb mpls_ilm
      + mkpeer mpls_ilm: mpls_nhlfe nhlfe_11 nhlfe_in
      + name mpls_ilm:nhlfe_11 mpls_pop11
      + msg mpls_pop11: setconfig { debugFlag=0 uplayer=0 operation=3 label=11 exp=0 ttl=255 }
      + connect mpls_pop11: split1: nhlfe_out in2mixa
      + list
        Name: ngctl1534       Type: socket          ID: 00000024   Num hooks: 0   Ns: 0
        Name: mpls_pop11      Type: mpls_nhlfe      ID: 0000001f   Num hooks: 2   Ns: 0
        Name: mpls_ilm        Type: mpls_ilm        ID: 0000001c   Num hooks: 2   Ns: 0
        Name: split2          Type: split           ID: 00000017   Num hooks: 3   Ns: 0
        Name: etf             Type: etf             ID: 00000013   Num hooks: 3   Ns: 0
        Name: mpls_eth        Type: mpls_ether      ID: 00000010   Num hooks: 2   Ns: 0
        Name: mpls_push11     Type: mpls_nhlfe      ID: 0000000c   Num hooks: 2   Ns: 0
        Name: split1          Type: split           ID: 00000009   Num hooks: 3   Ns: 0
        Name: mpls0           Type: iface           ID: 00000007   Num hooks: 1   Ns: 0
        Name: eth2_1          Type: ether           ID: 00000002   Num hooks: 2   Ns: 0
      There are 10 total nodes, 10 nodes listed
      + quit

#. Configure the newly created interface:

   .. code-block:: console

      # ip link set eth2_1 promisc on
      # ip addr addr 10.10.10.2/24 dev mpls0
      # ip link set mpls0 up

Send a ping from *left* to *right*
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We send a ping from *left* to *right* and listen to the packets on *middle*
interfaces *eth1* and *eth2*.

#. Ping from *left* to *right*.

   .. code-block:: console

      # ping -c 1 10.10.10.2
      PING 10.10.10.2 (10.10.10.2): 56 data bytes
      64 bytes from 10.10.10.2: icmp_seq=1 ttl=64 time=0.4 ms

      --- 10.10.10.2 ping statistics ---
      1 packets transmitted, 1 packets received, 0% packet loss
      round-trip min/avg/max = 0.4/0.4/0.4 ms

#. Listen the network on host *middle*.

   .. code-block:: console

      # tcpdump -ni eth1
      12:08:48.216051 MPLS (label 10, exp 0, ttl 255) (label 282624, exp 0, ttl 84) (label 32770, exp 4, [S], ttl 206)
              0x0000:  0006 0001 bf33 0753 0000 0000 e271 0700  .....3.S.....q..
              0x0010:  0000 0000 0809 0a0b 0c0d 0e0f 1011 1213  ................
              0x0020:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
              0x0030:  2425 2627 2829 2a2b 2c2d 2e2f            $%&'()*+,-./
      12:08:48.222284 MPLS (label 10, exp 0, ttl 254) (label 282624, exp 0, ttl 84) (label 453120, exp 0, ttl 0) (label 262174, exp 1, [S], ttl 242)
              0x0000:  0a0a 0a02 0a0a 0a01 0000 31ce 0006 0001  ..........1.....
              0x0010:  bf33 0753 0000 0000 e271 0700 0000 0000  .3.S.....q......
              0x0020:  0809 0a0b 0c0d 0e0f 1011 1213 1415 1617  ................
              0x0030:  1819 1a1b 1c1d 1e1f 2021 2223 2425 2627  .........!"#$%&'
              0x0040:  2829 2a2b 2c2d 2e2f                      ()*+,-./

   .. code-block:: console

      # tcpdump -ni eth2
      12:10:16.977364 MPLS (label 11, exp 0, ttl 254) (label 282624, exp 0, ttl 84) (label 32772, exp 6, [S], ttl 87)
              0x0000:  0106 0001 1834 0753 0000 0000 68e8 0300  .....4.S....h...
              0x0010:  0000 0000 0809 0a0b 0c0d 0e0f 1011 1213  ................
              0x0020:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
              0x0030:  2425 2627 2829 2a2b 2c2d 2e2f            $%&'()*+,-./
      12:10:16.977557 MPLS (label 11, exp 0, ttl 255) (label 282624, exp 0, ttl 84) (label 453136, exp 0, ttl 0) (label 262174, exp 1, [S], ttl 241)
              0x0000:  0a0a 0a02 0a0a 0a01 0000 5557 0106 0001  ..........UW....
              0x0010:  1834 0753 0000 0000 68e8 0300 0000 0000  .4.S....h.......
              0x0020:  0809 0a0b 0c0d 0e0f 1011 1213 1415 1617  ................
              0x0030:  1819 1a1b 1c1d 1e1f 2021 2223 2425 2627  .........!"#$%&'
              0x0040:  2829 2a2b 2c2d 2e2f                      ()*+,-./

   Packets arriving on *eth1* from host *left* have a label 10, that is
   swapped with a label 11 when transmitted through *eth2* to host *right*.
