Usage
=====

|vnb-gtpu|
----------

|gtpu| support in |vnb| is active by default as long as the |vnb-gtpu| module is
detected.

To avoid loading the |vnb-gtpu| module, specify only the |vnb| modules you want to
load in the MODULES variable in the |vnb| configuration file
:file:`<install_dir>/usr/local/etc/vnb.env`.

.. rubric:: Example

.. code-block:: console

   : ${MODULES:=nffec gtpu}

.. seealso::

   For more information, see the |vnb-baseline| documentation.

|gtpu| nodes usage
~~~~~~~~~~~~~~~~~~

You can manage |gtpu| nodes manually with a tool like |gtpuctl|, or *ngctl*.

You can use *ngctl* shell scripts to easily configure |gtpu| tunnels on PDN GSN
and serving GSN.

You will find examples of the most common functions in the script
:file:`rc.gtpu.sh`.

.. seealso::

   Fore more information, see :ref:`rc.gtpu.sh`.

Example: creating a |gtpu| node via *ngctl*
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The topology of the examples below is the following:

.. aafig::

    +-----------+       +--------------------+
    | 'Host-l'  |       |    'NUT(ubuntu)'   |
    +-----------+       +--------------------+
    |           |       |                    |
    |           |       |                    |
    |   'eth2_0'+-------+'eth1'              |
    |           |       |                    |
    |           |       |                    |
    +-----------+       +--------------------+

We assume that the following interface already exists:

   .. code-block:: console

      root@host-l:~# ip addr show eth2_0
      2: eth2_0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
          link/ether 00:55:00:00:00:20 brd ff:ff:ff:ff:ff:ff
          IPv4 forwarding: on IPv6 forwarding: on
          inet 2.0.0.5/24 brd 2.0.0.255 scope global eth2_0
	  inet6 3ffe:10:10::5/64 scope link

      root@ubuntu:~# ip addr show eth1
      8: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
          link/ether 00:02:02:00:00:20 brd ff:ff:ff:ff:ff:ff
          inet 2.0.0.1/24 scope global eth1
	  inet6 3ffe:10:10::1/64 scope link

It is possible to encapsulate tunnels in either UDP over IPv4 or UDP over IPv6.
Hence the two IP addresses on each interface.

For the rest of this example:
- in the case of UDP over IPv4:

  - `IPV` should be defined as ""
  - `IP1_NGCTL` should be defined as "2.0.0.1"
  - `IP1` should be defined as "2.0.0.1"
  - `IP2_NGCTL` should be defined as "2.0.0.5"
  - `IP2` should be defined as "2.0.0.5"
  - `IPPREFIX` should be defined as "2.0.0"
  - `IPMASK` should be defined as "24"
  - `IPANY` should be defined as "0.0.0.0"

- in the case of UDP over IPv6:

  - `IPV` should be defined as "6"
  - `IP1_NGCTL` should be defined as "[3ffe:10:10::1]"
  - `IP1` should be defined as "3ffe:10:10::1"
  - `IP2_NGCTL` should be defined as "[3ffe:10:10::5]"
  - `IP2` should be defined as "3ffe:10:10::5"
  - `IPPREFIX` should be defined as "3ffe:10:10:"
  - `IPMASK` should be defined as "64"
  - `IPANY` should be defined as "[::]"

When showing `tcpdump` traces, we only recorded those obtained using IPv4
at the network layer.

.. rubric:: Example: simple graph using a GTPU node

.. aafig::

                 ____
                /    \
               |'gtp0'|
                \____/
      _____________|_______________________________________________________
                   |
            +------+------+                              +-------------+
            |   'gtp0:'   |                              | 'dev_null:' |
            |_____________|                              |_____________|
            | 'ng_iface'  |                              |  'ng_iface' |
            +-------------+                              +-------------+
                   'allip'\                              /'allip'
                           \                            /
                            \                          /
                             \                        /
                       'upper'\                      /'nomatch'
                              +----------------------+
                              |     'test_gtpu:'     |
                              |______________________|
                              |       'ng_gtpu'      |
                              +----------------------+
                   'lower_rx'/                       \'lower'
                            /                         \
                           /                           \
                          /                             \
   'inet${IPV}/dgram/udp'/                               \'inet${IPV}/dgram/udp'
          +--------------+        +-------------+        +--------------+
          |'test_udp_rx:'|        |   'eth1:'   |        |'get_udp_tx0:'|
          |______________|        |_____________|        |______________|
          | 'ng_ksocket' |        | 'ng_ether'  |        | 'ng_ksocket' |
          +------+-------+        +------+------+        +------+-------+
                 |                       |                      |
      ___________|_______________________|______________________|____________
                 |                     __|_                     |
                 |                    /    \                    |
                 +-------------------|'eth1'|-------------------+
                                      \____/

Creating one tunnel between two hosts
+++++++++++++++++++++++++++++++++++++

We will create one tunnel between *host-l* and *NUT* using *ngctl*.

#. Create the tunnel's interface on *NUT*:

   .. code-block:: console

      echo -e "mkpeer iface dummy inet\nmsg dummy setifname \"dev_null\"" | ngctl -f -
      ngctl mkpeer dev_null: gtpu allip nomatch
      ngctl name dev_null:allip test_gtpu
      ngctl mkpeer test_gtpu: ksocket lower_rx inet${IPV}/dgram/udp
      ngctl name test_gtpu:lower_rx test_udp_rx
      ngctl msg test_udp_rx: bind inet${IPV}/${IPANY}:2152

      # create constant ksocket
      ngctl mkpeer test_gtpu: ksocket lower0 inet${IPV}/dgram/udp
      ngctl name test_gtpu:lower0 gtp_udp_tx0
      ngctl msg gtp_udp_tx0: bind inet${IPV}/${IP1_NGCTL}:62152
      ngctl msg gtp_udp_tx0: connect inet${IPV}/${IP2_NGCTL}:2152

      echo -e "mkpeer test_gtpu: iface upper0 allip\nmsg test_gtpu:upper0 setifname \"gtp0\"\nmsg test_gtpu: addpdp { lower=\"lower0\" upper=\"upper0\" teid_rx=1 teid_tx=1 flags_tx=0x30 }" | ngctl -f -

      ip link set gtp0 up
      ip add add 10.10.10.1 peer 10.10.10.5 dev gtp0

      root@ubuntu:~# ngctl list
        Name: ngctl2273       Type: socket          ID: 00000018   Num hooks: 0   Ns: 0
        Name: gtp0            Type: iface           ID: 00000017   Num hooks: 1   Ns: 0
        Name: gtp_udp_tx0     Type: ksocket         ID: 00000012   Num hooks: 1   Ns: 0
        Name: test_udp_rx     Type: ksocket         ID: 0000000e   Num hooks: 1   Ns: 0
        Name: test_gtpu       Type: gtpu            ID: 0000000b   Num hooks: 4   Ns: 0
        Name: dev_null        Type: iface           ID: 00000009   Num hooks: 1   Ns: 0
        Name: eth4            Type: ether           ID: 00000007   Num hooks: 0   Ns: 0
        Name: eth3            Type: ether           ID: 00000006   Num hooks: 0   Ns: 0
        Name: eth2            Type: ether           ID: 00000005   Num hooks: 0   Ns: 0
        Name: eth1            Type: ether           ID: 00000004   Num hooks: 0   Ns: 0
        Name: fpn0            Type: ether           ID: 00000003   Num hooks: 0   Ns: 0
        Name: eth0            Type: ether           ID: 00000002   Num hooks: 0   Ns: 0
      There are 12 total nodes, 12 nodes listed

#. Create the tunnel's interface on *host-l*:

   .. code-block:: console

      echo -e "mkpeer iface dummy inet\nmsg dummy setifname \"dev_null\"" | ngctl -f -
      ngctl mkpeer dev_null: gtpu allip nomatch
      ngctl name dev_null:allip test_gtpu
      ngctl mkpeer test_gtpu: ksocket lower_rx inet${IPV}/dgram/udp
      ngctl name test_gtpu:lower_rx test_udp_rx
      ngctl msg test_udp_rx: bind inet${IPV}/${IPANY}:2152

      # create constant ksocket
      ngctl mkpeer test_gtpu: ksocket lower0 inet${IPV}/dgram/udp
      ngctl name test_gtpu:lower0 gtp_udp_tx0
      ngctl msg gtp_udp_tx0: bind inet${IPV}/${IP2_NGCTL}:62152
      ngctl msg gtp_udp_tx0: connect inet${IPV}/${IP1_NGCTL}:2152

      echo -e "mkpeer test_gtpu: iface upper0 allip\nmsg test_gtpu:upper0 setifname \"gtp0\"\nmsg test_gtpu: addpdp { lower=\"lower0\" upper=\"upper0\" teid_rx=1 teid_tx=1 flags_tx=0x30 }" | ngctl -f -

      ip link set gtp0 up
      ip add add 10.10.10.5 peer 10.10.10.1 dev gtp0

#. Send a ping from the *gtp0* interface:

   .. code-block:: console

      root@ubuntu:~# tcpdump -i gtp0 -nvvex &
      root@ubuntu:~# ping -c 1 10.10.10.5
      PING 10.10.10.5 (10.10.10.5) 56(84) bytes of data.
      08:21:50.914450 Out ethertype IPv4 (0x0800), length 100: (tos 0x0, ttl 64, id 4045, offset 0, flags [DF], proto ICMP (1), length 84)
          10.10.10.1 > 10.10.10.5: ICMP echo request, id 2158, seq 1, length 64
              0x0000:  4500 0054 0fcd 4000 4001 02c3 0a0a 0a01
              0x0010:  0a0a 0a05 0800 3e0e 086e 0001 7e68 7053
              0x0020:  0000 0000 f6f3 0d00 0000 0000 1011 1213
              0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223
              0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233
              0x0050:  3435 3637
      08:21:50.924749   ? ethertype IPv4 (0x0800), length 100: (tos 0x0, ttl 64, id 57600, offset 0, flags [none], proto ICMP (1), length 84)
          10.10.10.5 > 10.10.10.1: ICMP echo reply, id 2158, seq 1, length 64
              0x0000:  4500 0054 e100 0000 4001 718f 0a0a 0a05
              0x0010:  0a0a 0a01 0000 460e 086e 0001 7e68 7053
              0x0020:  0000 0000 f6f3 0d00 0000 0000 1011 1213
              0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223
              0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233
              0x0050:  3435 3637
      08:21:50.925428  In ethertype IPv4 (0x0800), length 100: (tos 0x0, ttl 64, id 57600, offset 0, flags [none], proto ICMP (1), length 84)
      64 bytes from 10.10.10.5: icmp_seq=1 ttl=64 time=11.0 ms
          10.10.10.5 > 10.10.10.1: ICMP echo reply, id 2158, seq 1, length 64

      --- 10.10.10.5 ping statistics ---
              0x0000:  4500 0054 e100 0000 4001 718f 0a0a 0a05
      1 packets transmitted, 1 received, 0% packet loss, time 0ms
              0x0010:  0a0a 0a01 0000 460e 086e 0001 7e68 7053
      rtt min/avg/max/mdev = 11.006/11.006/11.006/0.000 ms
              0x0020:  0000 0000 f6f3 0d00 0000 0000 1011 1213
              0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223
              0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233
              0x0050:  3435 3637

      root@ubuntu:~# tcpdump -i eth1 -nvvex &
      root@ubuntu:~# ping -c 1 10.10.10.5
      PING 10.10.10.5 (10.10.10.5) 56(84) bytes of data.
      05:07:56.769593 00:02:02:00:00:20 > 00:55:00:00:00:20, ethertype IPv4 (0x0800), length 134: (tos 0x0, ttl 64, id 24047, offset 0, flags [DF], proto UDP (17), length 120)
          2.0.0.1.62152 > 2.0.0.5.2152: [udp sum ok] UDP, length 92
         0x0000:  4500 0078 5def 4000 4011 d880 0200 0001
         0x0010:  0200 0005 f2c8 0868 0064 ce9b 30ff 0054
         0x0020:  0000 0001 4500 0054 f4e8 4000 4001 1da7
         0x0030:  0a0a 0a01 0a0a 0a05 0800 8387 08f0 0001
         0x0040:  8ca3 6953 0000 0000 abbd 0b00 0000 0000
         0x0050:  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f
         0x0060:  2021 2223 2425 2627 2829 2a2b 2c2d 2e2f
         0x0070:  3031 3233 3435 3637
      05:07:56.776956 00:55:00:00:00:20 > 00:02:02:00:00:20, ethertype IPv4 (0x0800), length 134: (tos 0x0, ttl 64, id 59639, offset 0, flags [DF], proto UDP (17), length 120)
          2.0.0.5.62152 > 2.0.0.1.2152: [udp sum ok] UDP, length 92
         0x0000:  4500 0078 e8f7 4000 4011 4d78 0200 0005
         0x0010:  0200 0001 f2c8 0868 0064 ce9b 30ff 0054
         0x0020:  0000 0001 4500 0054 28cd 0000 4001 29c3
         0x0030:  0a0a 0a05 0a0a 0a01 0000 8b87 08f0 0001
         0x0040:  8ca3 6953 0000 0000 abbd 0b00 0000 0000
         0x0050:  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f
         0x0060:  2021 2223 2425 2627 2829 2a2b 2c2d 2e2f
         0x0070:  3031 3233 3435 3637
      64 bytes from 10.10.10.5: icmp_seq=1 ttl=64 time=7.57 ms

      --- 10.10.10.5 ping statistics ---
      1 packets transmitted, 1 received, 0% packet loss, time 0ms
      rtt min/avg/max/mdev = 7.578/7.578/7.578/0.000 ms

   The packet seen by *eth1* is a GTPU packet received through a GTPU tunnel.

Creating 1024 tunnels between two hosts
+++++++++++++++++++++++++++++++++++++++

We will create 1024 tunnels between *host-l* and *NUT* using *ngctl*.

#. Create 1024 tunnels on *NUT* via the following shell script:

   .. code-block:: bash

      #!/bin/sh

      local_ip=${IP1}
      remote_prefix=${IPPREFIX}
      remote_suffix=5
      local_port=62152

      all_tunnels=1024
      left_offset=1

      ip link set eth1 up
      ip addr add ${local_ip}/${IPMASK} dev eth1

      # get common functions
      mkdir -p /var/tmp/shells/
      . ./rc.gtpu.sh

      delete_infra
      create_infra
      plug_nfm_infra 10.10.10.1 10.10.10.5

      i=0
      echo "creating for ksocket ${i}"
      create_1_ksock ${i} ${remote_suffix} ${local_ip} ${remote_prefix} ${local_port} ${IPV}

      start=1
      stop=$(( ${start} + ${all_tunnels}  - 1 ))

      create_nfm_tunnels ${start} ${stop} lower${i} ${left_offset} ${left_offset}

#. Create 1024 tunnels on *host-l* via the following shell script:

   .. code-block:: bash

      #!/bin/sh

      local_ip=${IP2}
      remote_prefix=${IPPREFIX}
      remote_suffix=1
      local_port=62152

      all_tunnels=1024
      left_offset=1

      ip link set eth2_0 up
      ip addr add ${local_ip}/${IPMASK} dev eth2_0

      # get common functions
      mkdir -p /var/tmp/shells/
      source ./rc.gtpu.sh

      delete_infra
      create_infra
      plug_nfm_infra 10.10.10.5 10.10.10.1

      i=0
      echo "creating for ksocket ${i}"
      create_1_ksock ${i} ${remote_suffix} ${local_ip} ${remote_prefix} ${local_port} ${IPV}

      start=1
      stop=$(( ${start} + ${all_tunnels}  - 1 ))

      create_nfm_tunnels ${start} ${stop} lower${i} ${left_offset} ${left_offset}

#. Send a ping from the *gtp0* interface:

   .. code-block:: console

      root@ubuntu:~# ping -c 1 10.10.10.5
      PING 10.10.10.5 (10.10.10.5) 56(84) bytes of data.
      64 bytes from 10.10.10.5: icmp_seq=1 ttl=64 time=3.13 ms

      --- 10.10.10.5 ping statistics ---
      1 packets transmitted, 1 received, 0% packet loss, time 0ms
      rtt min/avg/max/mdev = 3.131/3.131/3.131/0.000 ms

#. Check packets on the forwarding gateway:

   .. code-block:: console

      root@ubuntu:~# tcpdump -i eth1 -nvvex &
      root@ubuntu:~# ping -c 1 10.10.10.5
      PING 10.10.10.5 (10.10.10.5) 56(84) bytes of data.
      09:13:56.260120 00:02:02:00:00:20 > 00:55:00:00:00:20, ethertype IPv4 (0x0800), length 134: (tos 0x0, ttl 64, id 43203, offset 0, flags [DF], proto UDP (17), length 120)
          2.0.0.1.51391 > 2.0.0.5.2152: [udp sum ok] UDP, length 92
              0x0000:  4500 0078 a8c3 4000 4011 8dac 0200 0001
              0x0010:  0200 0005 c8bf 0868 0064 f691 30ff 0054
              0x0020:  0000 0214 4500 0054 ee41 4000 4001 244e
              0x0030:  0a0a 0a01 0a0a 0a05 0800 2252 161a 0001
              0x0040:  b474 7053 0000 0000 d8f7 0300 0000 0000
              0x0050:  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f
              0x0060:  2021 2223 2425 2627 2829 2a2b 2c2d 2e2f
              0x0070:  3031 3233 3435 3637
      09:13:56.268673 00:55:00:00:00:20 > 00:02:02:00:00:20, ethertype IPv4 (0x0800), length 134: (tos 0x0, ttl 64, id 44106, offset 0, flags [DF], proto UDP (17), length 120)
          2.0.0.5.62152 > 2.0.0.1.2152: [udp sum ok] UDP, length 92
              0x0000:  4500 0078 ac4a 4000 4011 8a25 0200 0005
              0x0010:  0200 0001 f2c8 0868 0064 cc4a 30ff 0054
              0x0020:  0000 0252 4500 0054 e1e2 0000 4001 70ad
              0x0030:  0a0a 0a05 0a0a 0a01 0000 2a52 161a 0001
              0x0040:  b474 7053 0000 0000 d8f7 0300 0000 0000
              0x0050:  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f
              0x0060:  2021 2223 2425 2627 2829 2a2b 2c2d 2e2f
              0x0070:  3031 3233 3435 3637
      64 bytes from 10.10.10.5: icmp_seq=1 ttl=64 time=9.18 ms

      --- 10.10.10.5 ping statistics ---
      1 packets transmitted, 1 received, 0% packet loss, time 0ms
      rtt min/avg/max/mdev = 9.185/9.185/9.185/0.000 ms

   The packet seen by *eth1* is a forwarded GTPU packet.

.. _rc.gtpu.sh:

Example: using *ngctl* in a shell script
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example is provided in :file:`rc.gtpu.sh`

.. code-block:: bash

      #!/bin/sh
      # common functions for creating GTP-U tunnels

      create_infra()
      {
         echo "create_infra()"

	 if [ "${1}" = "v6" ]; then
		IPV=6
		IPANY="[::]"
	 else
		IPV=
		IPANY="0.0.0.0"
	 fi

         mkdir -p /var/tmp/shells/
         echo 'mkpeer iface dummy inet' > /var/tmp/shells/ngctl.cmd
         echo 'msg dummy setifname "dev_null"' >> /var/tmp/shells/ngctl.cmd
         ngctl -f /var/tmp/shells/ngctl.cmd
         rm -f /var/tmp/shells/ngctl.cmd

         ngctl mkpeer dev_null: gtpu allip nomatch
         ngctl name dev_null:allip test_gtpu
         ngctl mkpeer test_gtpu: ksocket lower_rx inet${IPV}/dgram/udp
         ngctl name test_gtpu:lower_rx test_udp_rx
         ngctl msg test_udp_rx: bind inet${IPV}/${IPANY}:2152
      }

      delete_infra()
      {
         echo "delete_infra()"

         # finish shutdown for ng_gtpu
         ngctl shutdown test_gtpu:lower_rx
         ngctl shutdown dev_null:
         ngctl shutdown test_gtpu:
         ngctl shutdown nfm_nod_00:
         ngctl shutdown o2m_nod_00:
         ngctl shutdown gtp0:
         ngctl shutdown gtp1234:
         ngctl shutdown gtp1235:
         ngctl shutdown gtp1236:
         ngctl shutdown gtp1237:
      }

      plug_nfm_infra()
      {
         echo "plug_nfm_infra() ${1} ${2}"

         echo 'mkpeer iface dummy inet' > /var/tmp/shells/ngctl.cmd
         echo 'msg dummy setifname "gtp0"' >> /var/tmp/shells/ngctl.cmd
         ngctl -f /var/tmp/shells/ngctl.cmd
         rm -f /var/tmp/shells/ngctl.cmd

         ngctl mkpeer gtp0: nffec allip mux            # route/get the GTP traffic
         ngctl name gtp0:allip nfm_nod_00              # name the mux/demux node
         ngctl msg nfm_nod_00: setmode { simpleFlow=0x01 }

         ip link set gtp0 up
         ip add add ${1} peer ${2} dev gtp0
      }

      plug_o2m_infra()
      {
         echo "plug_o2m_infra() ${1} ${2}"

         echo 'mkpeer iface dummy inet' > /var/tmp/shells/ngctl.cmd
         echo 'msg dummy setifname "gtp0"' >> /var/tmp/shells/ngctl.cmd
         ngctl -f /var/tmp/shells/ngctl.cmd
         rm -f /var/tmp/shells/ngctl.cmd

         ngctl mkpeer gtp0: one2many allip one            # route/get the GTP traffic
         ngctl name gtp0:allip o2m_nod_00              # name the mux/demux node

         ip link set gtp0 up
         ip add add ${1} peer ${2} dev gtp0
      }

      create_1_ksock()
      {
         echo "create_1_ksock() ${1} ${2} ${3} ${4} ${5} ${6}"

	 if [ "${6}" = "6" ]; then
		IPV=6
		SEP=":"
		OPEN_BRACK="["
		CLOSE_BRACK="]"
	 else
		IPV=
		SEP"."
		OPEN_BRACK=""
		CLOSE_BRACK=""
	 fi

         # create constant ksocket
         ngctl mkpeer test_gtpu: ksocket lower${1} inet${IPV}/dgram/udp
         ngctl name test_gtpu:lower${1} gtp_udp_tx${1}
         ngctl msg gtp_udp_tx${1}: bind inet${IPV}/${OPEN_BRACK}${3}:${5}${CLOSE_BRACK}
         ngctl msg gtp_udp_tx${1}: connect inet${IPV}/${OPEN_BRACK}${4}${SEP}${2}${CLOSE_BRACK}:2152
      }

      create_ksocks()
      {
         echo "create_ksocks() ${1} ${2} ${3} ${4} ${5}"

         # create variable ksockets
         for i in `seq ${1} ${2}`
         do
            j=$(( $i + 61234 ))
            create_1_ksock ${i} ${i} ${3} ${4} ${j} ${5}
         done
      }

      delete_ksocks()
      {
         echo "delete_ksocks() ${1} ${2}"

         # delete variable ksockets
         for i in `seq ${1} ${2}`
         do
            ngctl shutdown test_gtpu:lower${i}
         done
      }

      create_1_tunnel()
      {
         echo "create_1_tunnel() ${1} ${2} ${3}"

         echo "" > /var/tmp/shells/ngctl.cmd

            teid_rx=${1}
            teid_tx=${2}
            echo "mkpeer test_gtpu: iface upper${1} allip" >> /var/tmp/shells/ngctl.cmd
            echo "msg test_gtpu:upper${1} setifname \"gtp${1}\"" >> /var/tmp/shells/ngctl.cmd
            echo -n "msg test_gtpu: addpdp { lower=\"${3}\"" >> /var/tmp/shells/ngctl.cmd
            echo -n " upper=\"upper${1}\" teid_rx=${teid_rx}" >> /var/tmp/shells/ngctl.cmd
            echo " teid_tx=${teid_tx} flags_tx=0x30 }" >> /var/tmp/shells/ngctl.cmd

         # create all tunnels in one step
         ngctl -f /var/tmp/shells/ngctl.cmd
         rm -f /var/tmp/shells/ngctl.cmd
      }

      create_nfm_tunnels()
      {
         echo "create_nfm_tunnels() ${1} ${2} ${3} ${4} ${5}"

         echo "" > /var/tmp/shells/ngctl.cmd
         # create tunnels
         for i in `seq ${1} ${2}`
         do
            teid_rx=$(( $i + ${4} ))
            teid_tx=$(( $i + ${5} ))
            HEXSTR=`printf "0x%04x" $i`
            echo "connect test_gtpu: nfm_nod_00: upper${i} nfm_${HEXSTR}" >> /var/tmp/shells/ngctl.cmd
            echo -n "msg test_gtpu: addpdp { lower=\"${3}\"" >> /var/tmp/shells/ngctl.cmd
            echo -n " upper=\"upper${i}\" teid_rx=${teid_rx}" >> /var/tmp/shells/ngctl.cmd
            echo " teid_tx=${teid_tx} flags_tx=0x30 }" >> /var/tmp/shells/ngctl.cmd
            #echo "name test_gtpu:upper${i} \"nfm${i}\"" >> /var/tmp/shells/ngctl.cmd
         done
         # create all tunnels in one step
         ngctl -f /var/tmp/shells/ngctl.cmd
         rm -f /var/tmp/shells/ngctl.cmd
      }

      create_o2m_tunnels()
      {
         echo "create_o2m_tunnels() ${1} ${2} ${3} ${4}"

         echo "" > /var/tmp/shells/ngctl.cmd
         # create tunnels
         for i in `seq ${1} ${2}`
         do
            teid_rx=$(( $i + ${3} ))
            teid_tx=$(( $i + ${4} ))
            socket_id=$(( $i % 2 ))
            lower=lower${socket_id}
            echo "connect test_gtpu: o2m_nod_00: upper${i} many${i}" >> /var/tmp/shells/ngctl.cmd
            echo -n "msg test_gtpu: addpdp { lower=\"${lower}\"" >> /var/tmp/shells/ngctl.cmd
            echo -n " upper=\"upper${i}\" teid_rx=${teid_rx}" >> /var/tmp/shells/ngctl.cmd
            echo " teid_tx=${teid_tx} flags_tx=0x30 }" >> /var/tmp/shells/ngctl.cmd
            #echo "name test_gtpu:upper${i} \"o2m${i}\"" >> /var/tmp/shells/ngctl.cmd
         done
         # create all tunnels in one step
         ngctl -f /var/tmp/shells/ngctl.cmd
         rm -f /var/tmp/shells/ngctl.cmd
      }

      create_tee_tunnels()
      {
         echo "create_tee_tunnels() ${1} ${2}"

         echo "" > /var/tmp/shells/ngctl.cmd
         # create tunnels
         for i in `seq ${1} ${2}`
         do
            teid_rx=$(( $i + 1234 ))
            teid_tx=$(( $i + 2341 ))
            echo "mkpeer test_gtpu: tee upper${i} left" >> /var/tmp/shells/ngctl.cmd
            echo -n "msg test_gtpu: addpdp { lower=\"${3}\"" >> /var/tmp/shells/ngctl.cmd
            echo -n " upper=\"upper${i}\" teid_rx=${teid_rx}" >> /var/tmp/shells/ngctl.cmd
            echo " teid_tx=${teid_tx} flags_tx=0x30 }" >> /var/tmp/shells/ngctl.cmd
            #echo "name test_gtpu:upper${i} \"tee${i}\"" >> /var/tmp/shells/ngctl.cmd
         done
         # create all tunnels in one step
         ngctl -f /var/tmp/shells/ngctl.cmd
         rm -f /var/tmp/shells/ngctl.cmd
      }

      create_relay_tunnels()
      {
         echo "create_relay_tunnels() ${1} ${2} ${3} ${4} ${5} ${6}"

         echo "" > /var/tmp/shells/ngctl.cmd
         # create tunnels
         for i in `seq ${1} ${2}`
         do
            left_teid=$(( $i + ${3} ))
            right_teid=$(( $i + ${4} ))
            j=$(( $i + 65536 ))

            echo "connect test_gtpu: test_gtpu: upper${i} upper${j}" >> /var/tmp/shells/ngctl.cmd

            echo -n "msg test_gtpu: addpdp { lower=\"lower${5}\"" >> /var/tmp/shells/ngctl.cmd
            echo -n " upper=\"upper${i}\" teid_rx=${left_teid}" >> /var/tmp/shells/ngctl.cmd
            echo " teid_tx=${left_teid} flags_tx=0x30 }" >> /var/tmp/shells/ngctl.cmd

            echo -n "msg test_gtpu: addpdp { lower=\"lower${6}\"" >> /var/tmp/shells/ngctl.cmd
            echo -n " upper=\"upper${j}\" teid_rx=${right_teid}" >> /var/tmp/shells/ngctl.cmd
            echo " teid_tx=${right_teid} flags_tx=0x30 }" >> /var/tmp/shells/ngctl.cmd
            #echo "name test_gtpu:upper${i} \"nfm${i}\"" >> /var/tmp/shells/ngctl.cmd
         done
         # create all tunnels in one step
         ngctl -f /var/tmp/shells/ngctl.cmd
         rm -f /var/tmp/shells/ngctl.cmd
      }

      delete_tunnels()
      {
         echo "delete_tunnels() ${1} ${2}"

         echo "" > /var/tmp/shells/ngctl.cmd
         # delete tunnels
         for i in `seq ${1} ${2}`
         do
            echo "shutdown test_gtpu:upper${i}" >> /var/tmp/shells/ngctl.cmd
         done
         # delete all tunnels in one step
         ngctl -f /var/tmp/shells/ngctl.cmd
         rm -f /var/tmp/shells/ngctl.cmd
      }

|gtpuctl|
---------

|vnb| graph creation
~~~~~~~~~~~~~~~~~~~~

|gtpuctl| handles all creation and configuration steps
needed for a set of tunnels, it will create the |vnb| objects related to |gtpu|.

   .. code-block:: console

      # gtpuctl -h
      usage: gtpuctl[-h] [-l IP addr for local iface] [-r IP addr for remote iface]
             {[-6] [-L IP addr for local ksock] [-R IP addr for remote ksock]}
             [-t number of tunnels per ksocket]
             [-o (TEID offset)]
             [-p (PDN GW mode)] [-s (Serving GW mode)]
             [-n gtp_ifname]

      example: (PDN-left, PDN-right and Serving-GW)
      gtpuctl -p -l 1.2.3.4 -r 1.2.3.5 -L 10.123.1.1 -R 10.123.1.4
      gtpuctl -p -l 1.2.3.5 -r 1.2.3.4 -L 10.125.1.2 -R 10.125.1.4 -o 4097
      gtpuctl -s -L 10.123.1.4 -R 10.123.1.1 -L 10.125.1.4 -R 10.125.1.2 -o 4097

      example: (PDN-left with two ksocks)
      gtpuctl -L 10.123.1.1 -R 10.123.1.4 -L 10.223.1.1 -R 10.223.1.4

   .. note::

      By default, the gtp interface is named "gtp0". To change that, pass the
      "-n" argument to |gtpuctl| with the custom name.


|vnb| graph termination
~~~~~~~~~~~~~~~~~~~~~~~

Separate shell commands are used to delete the |vnb| objects related to |gtpu|.

After |gtpuctl| has been run, the |vnb| graph for |gtpu| tunnels must be deleted.
The following commands are needed :

   .. code-block:: console

      # shutdown for ng_gtpu
      ngctl shutdown test_gtpu:lower_rx
      ngctl shutdown dev_null:
      ngctl shutdown test_gtpu:
      ngctl shutdown nfm_nod_00:
      ngctl shutdown gtp0:


|gtpu| node creation example by |gtpuctl|
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The topology of the following examples is:

.. aafig::

    +-----------+       +--------------------+       +-----------+
    | 'Host-l'  |       |   'NUT(ubuntu)'    |       | 'Host-r'  |
    +-----------+       +--------------------+       +-----------+
    |           |       |                    |       |           |
    |           |       |                    |       |           |
    |   'eth2_0'+-------+'eth1'        'eth2'+-------+'eth2_1'   |
    |           |       |                    |       |           |
    |           |       |                    |       |           |
    +-----------+       +--------------------+       +-----------+

It is possible to encapsulate tunnels in either UDP over IPv4 or UDP over IPv6.
Hence the two IP addresses on each interface terminating |gtpu| tunnels.

For the two following examples:
- in the case of UDP over IPv4:

  - `IP1` should be defined as "2.0.0.1"
  - `IP2` should be defined as "2.0.0.5"
  - `IP3` should be defined as "2.1.0.1"
  - `IP4` should be defined as "2.1.0.5"
  - `IPMASK` should be defined as "32"
  - `IPOPT` should be defined as ""

- in the case of UDP over IPv6:

  - `IP1` should be defined as "3ffe:10:10::1"
  - `IP2` should be defined as "3ffe:10:10::5"
  - `IP3` should be defined as "3ffe:11:10::1"
  - `IP4` should be defined as "3ffe:11:10::5"
  - `IPMASK` should be defined as "128"
  - `IPOPT` should be defined as "-6"

When showing `tcpdump` traces, we only recorded those obtained using IPv4
at the network layer.

Here is an example of a simple graph using a |gtpu| node:

.. aafig::
                 ____
                /    \
               |'gtp0'|
                \____/
      _____________|_______________________________________________________
                   |
            +------+------+
            |   'gtp0:'   |
            |_____________|
            | 'ng_iface'  |
            +------+------+
                   ^'allip'
                   |
                   |
                   v'mux'
            +------+------+                              +-------------+
            |'nfm_nod_00:'|                              | 'dev_null:' |
            |_____________|                              |_____________|
            | 'ng_nffec'  |                              |  'ng_iface' |
            +-------------+                              +-------------+
                     'nfm'\                              /'allip'
                           \                            /
                            \                          /
                             \                        /
                       'upper'\                      /'nomatch'
                              +----------------------+
                              |     'test_gtpu:'     |
                              |______________________|
                              |       'ng_gtpu'      |
                              +----------------------+
                    'lower_rx'/                      \'lower'
                             /                        \
                            /                          \
                           /                            \
    'inet${IPV}/dgram/udp'/                              \'inet${IPV}/dgram/udp'
          +---------------+       +-------------+        +--------------+
          |'test_udp_rx:' |       |   'eth1:'   |        |'get_udp_tx0:'|
          |_______________|       |_____________|        |______________|
          | 'ng_ksocket'  |       | 'ng_ether'  |        | 'ng_ksocket' |
          +------+--------+       +------+------+        +------+-------+
                 |                       |                      |
      ___________|_______________________|______________________|____________
                 |                     __|_                     |
                 |                    /    \                    |
                 +-------------------|'eth1'|-------------------+
                                      \____/


1024 tunnels between two hosts
++++++++++++++++++++++++++++++

The following shows how to create 1024 tunnels between host-l and NUT.

We assume that these interfaces already exist:

   .. code-block:: console

      root@host-l:~# ip addr show eth2_0
      2: eth2_0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
          link/ether 00:55:00:00:00:20 brd ff:ff:ff:ff:ff:ff
          IPv4 forwarding: on IPv6 forwarding: on
          inet 2.0.0.5/24 brd 2.0.0.255 scope global eth2_0
	  inet6 3ffe:10:10::5/64 scope link

      root@ubuntu:~# ip addr show eth1
      8: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
          link/ether 00:02:02:00:00:20 brd ff:ff:ff:ff:ff:ff
          inet 2.0.0.1/24 scope global eth1
	  inet6 3ffe:10:10::1/64 scope link


1. Enter the following commands on NUT and host-l to create the |gtpu| interface:

   .. code-block:: console

      root@ubuntu:~# gtpuctl -p -l 10.10.10.1 -r 10.10.10.5 ${IPOPT} -L ${IP1} -R ${IP2} -t 1024
      root@ubuntu:~# ngctl list
        Name: ngctl2956       Type: socket          ID: 00000048   Num hooks: 0   Ns: 0
        Name: gtp_udp_tx0     Type: ksocket         ID: 00000047   Num hooks: 1   Ns: 0
        Name: nfm_nod_00      Type: nffec           ID: 00000046   Num hooks: 1025   Ns: 0
        Name: gtp0            Type: iface           ID: 00000045   Num hooks: 1   Ns: 0
        Name: test_udp_rx     Type: ksocket         ID: 00000044   Num hooks: 1   Ns: 0
        Name: test_gtpu       Type: gtpu            ID: 00000043   Num hooks: 1027   Ns: 0
        Name: dev_null        Type: iface           ID: 00000042   Num hooks: 1   Ns: 0
        Name: eth4            Type: ether           ID: 00000007   Num hooks: 0   Ns: 0
        Name: eth3            Type: ether           ID: 00000006   Num hooks: 0   Ns: 0
        Name: eth2            Type: ether           ID: 00000005   Num hooks: 0   Ns: 0
        Name: eth1            Type: ether           ID: 00000004   Num hooks: 0   Ns: 0
        Name: fpn0            Type: ether           ID: 00000003   Num hooks: 0   Ns: 0
        Name: eth0            Type: ether           ID: 00000002   Num hooks: 0   Ns: 0
      There are 13 total nodes, 13 nodes listed


      root@host-l:~# gtpuctl -p -l 10.10.10.5 -r 10.10.10.1 ${IPOPT} -L ${IP2} -R ${IP1} -t 1024


#. Send a ping from the *gtp0* interface:

   .. code-block:: console

      root@ubuntu:~# tcpdump -i eth1 -nvvex &
      root@ubuntu:~# ping -c 1 10.10.10.5
      PING 10.10.10.5 (10.10.10.5) 56(84) bytes of data.
      10:19:00.572900 00:02:02:00:00:20 > 00:55:00:00:00:20, ethertype IPv4 (0x0800), length 134: (tos 0x0, ttl 64, id 47760, offset 0, flags [DF], proto UDP (17), length 120)
          2.0.0.1.62152 > 2.0.0.5.2152: [udp sum ok] UDP, length 92
         0x0000:  4500 0078 ba90 4000 4011 7bdf 0200 0001
         0x0010:  0200 0005 f2c8 0868 0064 cc89 30ff 0054
         0x0020:  0000 0213 4500 0054 84f3 4000 4001 8d9c
         0x0030:  0a0a 0a01 0a0a 0a05 0800 6d66 08bd 0001
         0x0040:  f4f7 6553 0000 0000 60bd 0800 0000 0000
         0x0050:  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f
         0x0060:  2021 2223 2425 2627 2829 2a2b 2c2d 2e2f
         0x0070:  3031 3233 3435 3637
      10:19:00.582972 00:55:00:00:00:20 > 00:02:02:00:00:20, ethertype IPv4 (0x0800), length 134: (tos 0x0, ttl 64, id 60276, offset 0, flags [DF], proto UDP (17), length 120)
          2.0.0.5.62152 > 2.0.0.1.2152: [udp sum ok] UDP, length 92
         0x0000:  4500 0078 eb74 4000 4011 4afb 0200 0005
         0x0010:  0200 0001 f2c8 0868 0064 cc4b 30ff 0054
         0x0020:  0000 0251 4500 0054 c614 0000 4001 8c7b
         0x0030:  0a0a 0a05 0a0a 0a01 0000 7566 08bd 0001
         0x0040:  f4f7 6553 0000 0000 60bd 0800 0000 0000
         0x0050:  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f
         0x0060:  2021 2223 2425 2627 2829 2a2b 2c2d 2e2f
         0x0070:  3031 3233 3435 3637
      64 bytes from 10.10.10.5: icmp_seq=1 ttl=64 time=10.2 ms

      --- 10.10.10.5 ping statistics ---
      1 packets transmitted, 1 received, 0% packet loss, time 0ms
      rtt min/avg/max/mdev = 10.277/10.277/10.277/0.000 ms


   The packet seen by *eth1* is a GTPU packet via gtpu tunnel.


Tunnels between two distant hosts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following shows how to create 1024 tunnels between host-l and host-r,
the NUT between them acting as gateway.


We assume that these interface already exists:

   .. code-block:: console

      admin@host-l:~> ip addr show eth2_0
      2: eth2_0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
          link/ether 00:55:00:00:00:20 brd ff:ff:ff:ff:ff:ff
          IPv4 forwarding: on IPv6 forwarding: on
          inet 2.0.0.5/24 brd 2.0.0.255 scope global eth2_0
	  inet6 3ffe:10:10::5/64 scope link
      admin@host-l:~> ip addr show loopback0
      9: loopback0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue
          link/ether 1e:c0:c0:9d:6c:31 brd ff:ff:ff:ff:ff:ff
          IPv4 forwarding: on IPv6 forwarding: on
          inet 100.2.2.1/32 scope global loopback0


      admin@host-r:~> ip addr show eth2_1
      2: eth2_1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
          link/ether 00:55:01:00:00:21 brd ff:ff:ff:ff:ff:ff
          IPv4 forwarding: on IPv6 forwarding: on
          inet 2.1.0.5/24 brd 2.1.0.255 scope global eth2_1
	  inet6 3ffe:11:10::1/64 scope link
      admin@host-r:~> ip addr show loopback0
      9: loopback0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue
          link/ether 0a:56:02:d4:dc:c0 brd ff:ff:ff:ff:ff:ff
          IPv4 forwarding: on IPv6 forwarding: on
          inet 110.2.2.1/32 scope global loopback0


      root@ubuntu:~# ip addr show eth1
      8: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
          link/ether 00:02:02:00:00:20 brd ff:ff:ff:ff:ff:ff
          inet 2.0.0.1/24 scope global eth1
      root@ubuntu:~# ip addr show eth2
      9: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
          link/ether 00:02:02:00:00:21 brd ff:ff:ff:ff:ff:ff
          inet 2.1.0.1/24 scope global eth2


1. Enter the following commands on host-l and host-r to create the interface:

   .. code-block:: console

      admin@host-l:~> gtpuctl -p -l 10.10.0.5 -r 10.10.0.8 -L ${IP2} -R ${IP4} -t 1024
      admin@host-l:~> ip route add 110.2.2.1/32 dev gtp0
      admin@host-l:~> ip route add ${IP4}/${IPMASK} via ${IP1}


      admin@host-r:~> gtpuctl -p -l 10.10.0.8 -r 10.10.0.5 -L ${IP4} -R ${IP2} -t 1024
      admin@host-r:~> ip route add 100.2.2.1/32 dev gtp0
      admin@host-r:~> ip route add ${IP2}/${IPMASK} via ${IP3}


#. Send a ping from the *gtp0* interface:

   .. code-block:: console

      admin@host-l:~> ping -c 1 -I 100.2.2.1 110.2.2.1
      PING 110.2.2.1 (110.2.2.1): 56 data bytes
      64 bytes from 110.2.2.1: icmp_seq=1 ttl=64 time=9.2 ms

      --- 110.2.2.1 ping statistics ---
      1 packets transmitted, 1 packets received, 0% packet loss
      round-trip min/avg/max = 9.2/9.2/9.2 ms


#. Check the packets on gtp interface:

   .. code-block:: console

      admin@host-l:~> tcpdump -i gtp0 -nvvex &
      admin@host-l:~> ping -c 1 -I 100.2.2.1 110.2.2.1
      PING 110.2.2.1 (110.2.2.1): 56 data bytes
      06:02:36.034865 > 0800 100: IP (tos 0x0, ttl  64, id 0, offset 0, flags [DF], length: 84) 100.2.2.1 > 110.2.2.1: icmp 64: echo request seq 1
              0x0000:  4500 0054 0000 4000 4001 64a3 6402 0201  E..T..@.@.d.d...
              0x0010:  6e02 0201 0800 b4b6 f305 0001 fc63 7053  n............cpS
              0x0020:  f887 0000 0809 0a0b 0c0d 0e0f 1011 1213  ................
              0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
              0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233  $%&'()*+,-./0123
      06:02:36.046942 < 0800 100: IP (tos 0x0, ttl  64, id 12966, offset 0, flags [none], length: 84) 110.2.2.1 > 100.2.2.1: icmp 64: echo reply seq 1
              0x0000:  4500 0054 32a6 0000 4001 71fd 6e02 0201  E..T2...@.q.n...
              0x0010:  6402 0201 0000 bcb6 f305 0001 fc63 7053  d............cpS
              0x0020:  f887 0000 0809 0a0b 0c0d 0e0f 1011 1213  ................
              0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
              0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233  $%&'()*+,-./0123
      64 bytes from 110.2.2.1: icmp_seq=1 ttl=64 time=21.3 ms

      --- 110.2.2.1 ping statistics ---
      1 packets transmitted, 1 packets received, 0% packet loss
      round-trip min/avg/max = 21.3/21.3/21.3 ms

#. Check the packets on the forwarding gateway:

   .. code-block:: console

      root@ubuntu:~# tcpdump -i eth1 -nvvex
      tcpdump: listening on eth1, link-type EN10MB (Ethernet), capture size 65535 bytes
      10:18:47.817517 00:55:00:00:00:20 > 00:02:02:00:00:20, ethertype IPv4 (0x0800), length 134: (tos 0x0, ttl 64, id 59738, offset 0, flags [DF], proto UDP (17), length 120)
          2.0.0.5.62152 > 2.1.0.5.2152: [udp sum ok] UDP, length 92
         0x0000:  4500 0078 e95a 4000 4011 4d10 0200 0005
         0x0010:  0201 0005 f2c8 0868 0064 cc86 30ff 0054
         0x0020:  0000 0211 4500 0054 0000 4000 4001 64a3
         0x0030:  6402 0201 6e02 0201 0800 4fb9 1106 0001
         0x0040:  6749 6753 db9f 0200 0809 0a0b 0c0d 0e0f
         0x0050:  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f
         0x0060:  2021 2223 2425 2627 2829 2a2b 2c2d 2e2f
         0x0070:  3031 3233 3435 3637
      10:18:47.818130 00:02:02:00:00:20 > 00:55:00:00:00:20, ethertype IPv4 (0x0800), length 134: (tos 0x0, ttl 63, id 60487, offset 0, flags [DF], proto UDP (17), length 120)
          2.1.0.5.62152 > 2.0.0.5.2152: [udp sum ok] UDP, length 92
         0x0000:  4500 0078 ec47 4000 3f11 4b23 0201 0005
         0x0010:  0200 0005 f2c8 0868 0064 cc86 30ff 0054
         0x0020:  0000 0211 4500 0054 117e 0000 4001 9325
         0x0030:  6e02 0201 6402 0201 0000 57b9 1106 0001
         0x0040:  6749 6753 db9f 0200 0809 0a0b 0c0d 0e0f
         0x0050:  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f
         0x0060:  2021 2223 2425 2627 2829 2a2b 2c2d 2e2f
         0x0070:  3031 3233 3435 3637

   The packet seen by *eth1* is a forwarded |gtpu| packet.
