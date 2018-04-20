Usage
=====

VLAN support in |vnb| is active by
default as long as the |vnb-vlan| module is detected.

To avoid loading the |vnb-vlan| module, specify only the VNB modules you want to
load in the MODULES variable in the VNB configuration file
:file:`<install_dir>/usr/local/etc/vnb.env`.

For instance:

.. code-block:: console

   : ${MODULES:=ether ppp pppoe}

.. seealso::

   For more information, see the |vnb-baseline| documentation.

ng_vlan
-------

.. seealso::

   For more information about *ng_vlan*, see the `ng_vlan online
   documentation`__.

__ http://www.freebsd.org/cgi/man.cgi?query=ng_vlan&apropos=0&sektion=0&manpath=FreeBSD+10.0-RELEASE&arch=default&format=html

VLAN nodes creation example
---------------------------

Here is an example of a simple graph using a VLAN node:

.. aafig::

               +------------------------------------------------+
   ______      |  +----------+                 +------------+   |
  /      \     |  | 'EIFACE' |'ether'   'lower'|   'VLAN'   |   |
 |'ngeth0'|----|--+__________+-----------------+____________|   |
  \______/     |  | 'ngethL' |                 |   'Vlan'   |   |
               |  +----------+       'nomatch'/+-----+------+   |
               |                             /       |'link_1'  |
               |                            /        |          |
               |                           /         |'ether'   |
               |                          /      +---+------+   |    _____
               |                         /       | 'EIFACE' |   |   /     \
               |                        /        |__________+---|--|'vlan0'|
   ______      |         +----------+  /         | 'ngvlan' |   |   \_____/
  /      \     |         | 'EIFACE' | /          +----------+   |
 |'ngeth1'|----|---------+__________|/                          |
  \______/     |         | 'ngethR' |'ether'                    |
               |         +----------+                           |
               +------------------------------------------------+

#. Enter the following netgraph commands:

   .. code-block:: console

      # ngctl
      + mkpeer vlan ether orphans
      + list
      Name: <unnamed>       Type: vlan            ID: 00000057   Num hooks: 1   Ns: 0
      Name: ngctl584        Type: socket          ID: 00000056   Num hooks: 1   Ns: 0
      Name: eth0            Type: ether           ID: 00000037   Num hooks: 0   Ns: 0
      There are 3 total nodes, 3 nodes listed
      + name [57]: Vlan
      + mkpeer Vlan: eiface lower ether
      + mkpeer Vlan: eiface nomatch ether
      + mkpeer Vlan: eiface link_1 ether
      + list
      Name: <unnamed>       Type: eiface          ID: 0000005a   Num hooks: 1   Ns: 0
      Name: <unnamed>       Type: eiface          ID: 00000059   Num hooks: 1   Ns: 0
      Name: <unnamed>       Type: eiface          ID: 00000058   Num hooks: 1   Ns: 0
      Name: Vlan            Type: vlan            ID: 00000057   Num hooks: 4   Ns: 0
      Name: ngctl584        Type: socket          ID: 00000056   Num hooks: 1   Ns: 0
      Name: eth0            Type: ether           ID: 00000037   Num hooks: 0   Ns: 0
      There are 6 total nodes, 6 nodes listed
      + name [58]: ngethL
      + name [59]: ngethR
      + name [5a]: ngvlan
      + msg ngethR: setifname "ngeth1"
      + msg ngethL: setifname "ngeth0"
      + msg ngvlan: setifname "vlan1"
      + quit

#. Configure the newly created interfaces:

   .. code-block:: console

      # ip li set ngeth0 address 00:01:01:02:02:02
      # ip li set ngeth1 address 00:01:01:03:03:03
      # ip li set vlan1 address 00:01:01:04:04:04
      # ip li set vlan1 promisc on
      # ip a a 192.168.1.1/24 dev ngeth0
      # ip a a 192.168.2.1/24 dev ngeth1
      # ip a a 192.168.3.1/24 dev vlan1
      # ip li set up dev ngeth0
      # ip li set up dev ngeth1
      # ip li set up dev vlan1

#. Send a ping from the *vlan1* interface:

   .. code-block:: console

      # arp -s 192.168.3.2 00:05:05:05:03:08
      # tcpdump -ni ngeth0 &
      # ping -c 1 192.168.3.2
      PING 192.168.3.2 (192.168.3.2) 56(84) bytes of data.
      10:27:46.546680 00:01:01:04:04:04 (oui Unknown) > 00:05:05:05:03:08 (oui Unknown), ethertype 802.1Q (0x8100), length 102: vlan 1, p 0, ethertype IPv4, (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto ICMP (1), length 84)
       192.168.3.1 > 192.168.3.2: ICMP echo request, id 1966, seq 1, length 64
           0x0000:  0001 0800 4500 0054 0000 4000 4001 b355
           0x0010:  c0a8 0301 c0a8 0302 0800 ceb1 07ae 0001
           0x0020:  9222 7252 0000 0000 5657 0800 0000 0000
           0x0030:  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f
           0x0040:  2021 2223 2425 2627 2829 2a2b 2c2d 2e2f
           0x0050:  3031 3233 3435 3637

      --- 192.168.3.2 ping statistics ---
      1 packets transmitted, 0 received, 100% packet loss, time 0ms

   Packets are forwarded on *ngeth0* through the VLAN node. The *vlan 1* tag is
   inserted in their Ethernet headers.

#. Check VLAN node statistics:

   .. code-block:: console

    # ngctl
    getstats Vlan:
    Args:   { recvOctets=1056 recvPackets=12 recvRunts=0 recvInvalid=0 recvUnknownTag=0 xmitOctets=492 xmitPackets=6 xmitDataTooBig=0 memoryFailures=0 }
