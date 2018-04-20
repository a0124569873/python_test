Usage
=====

Starting the |fp|
-----------------

#. Do one the following to create the |fp| configuration file:

   - Use the |fp| configuration wizard:

     .. code-block:: console

        $ fast-path.sh config -i

     .. note::

        Python must be installed to use the wizard.

   - Edit the |fp| configuration file:

     a. Edit :file:`fast-path.env.tmpl`.

     #. Overwrite the existing |fp| configuration file:

        .. code-block:: console

           $ cp /usr/local/etc/fast-path.env.tmpl /usr/local/etc/fast-path.env

#. Start the |fp|:

   .. code-block:: console

      # fast-path.sh start

   .. note::

      To use a custom configuration file, use the CONF_FILE_fast_path
      environment variable. For instance:

      .. code-block:: console

         # CONF_FILE_fast_path=/path/to/conf/conf_file fast-path.sh start

#. If you have configured firewall rules with netfilter, allow communication
   between the |fp| and the |fpm|:

   a. Apply your netfilter configuration.

   #. If necessary, edit the :file:`/tmp/fp-nf-rules` script.

      The :file:`fp-nf-rules` script is automatically created when you start the
      |fp|.

      **fp-nf-rules script example**

      .. code-block:: bash

            iptables -I INPUT -i fpn0 -j ACCEPT
            iptables -I OUTPUT -o fpn0 -j ACCEPT
            ip6tables -I INPUT -i fpn0 -j ACCEPT
            ip6tables -I OUTPUT -o fpn0 -j ACCEPT

   #. Execute the :file:`fp-nf-rules` script:

      .. code-block:: console

         # sh /tmp/fp-nf-rules

Stopping the |fp|
-----------------

- To stop the |fp|:

  .. code-block:: console

     # fast-path.sh stop

  If |linux-fp-sync| is active, it is stopped before the |fp|.

Displaying the |fp| status
--------------------------

- To display the current status of running |fp| threads:

  .. code-block:: console

     # fast-path.sh status

- To display the current status of running |fp| threads and of the current
  installation (inserted :file:`.ko`, for example):

  .. code-block:: console

     # fast-path.sh status complete

Restarting the |fp|
-------------------

The |fp| can be restarted in two modes:

.. rubric:: Normal restart

- The machine on which the |fp| was started is restored to its initial state.
- All your configuration is lost.

.. rubric:: Graceful restart

- If |linux-fp-sync| is active, it is not stopped.
- Hugepages, kernel objects, FPVI interfaces, etc., are preserved.
- The |fp| restarts using a modified configuration file.
- Network configuration is preserved accross restarts.

Graceful restart is the default restart mode if |linux-fp-sync| is active.

.. important::

   If you edit the list of ports handled by the |fp|, you must restart it in
   normal mode.

- To restart the |fp|:

  .. code-block:: console

     # fast-path.sh restart

- To force graceful restart:

  .. code-block:: console

     # fast-path.sh restart graceful

- To force normal restart:

  .. code-block:: console

     # fast-path.sh stop
     # fast-path.sh start
     # linux-fp-sync.sh start

.. seealso::

   For more information on how to configure the |fp| and the underlying SDK, see
   the relevant documentation.

Configuring the |fp|
--------------------

.. rubric:: Description

The *fp-cli* tool helps you:

- manage interfaces,
- display statistics,
- display debugging information.

.. rubric:: Synopsis

.. code-block:: console

   # fp-cli
   <fp-0>

You can launch *fp-cli* with |linux-fp-sync| enabled or disabled:

|linux-fp-sync| enabled
   You can launch *fp-cli* right away.
|linux-fp-sync| disabled
   You must launch *fp-init* or *autoconf-ifp*, then *fp-cli*.

.. rubric:: Example

This example assumes that |linux-fp-sync| is enabled. It illustrates how
to:

- enable the *eth1* interface,
- launch *fp-cli*,
- dump the logical interfaces table.

.. code-block:: console

   # ip link set up dev eth1
   # fp-cli
   <fp-0> dump-interfaces
   257:eth3 [VR-0] ifuid=0x1e16b22 (port 2) <FWD4|FWD6> (0x60)
             type=ether mac=00:1b:21:c5:7f:76 mtu=1500 tcp4mss=0 tcp6mss=0
             blade=1 cp_blade=1
             IPv4 routes=0  IPv6 routes=0
   316:eth2 [VR-0] ifuid=0x3c116a72 (port 1) <FWD4|FWD6> (0x63)
             type=ether mac=00:1b:21:c5:7f:75 mtu=1500 tcp4mss=0 tcp6mss=0
             blade=1 cp_blade=1
             IPv4 routes=0  IPv6 routes=0
   374:eth1 [VR-0] ifuid=0x764169c2 (port 0) <UP|RUNNING|FWD4|FWD6> (0x63)
             type=ether mac=00:1b:21:c5:7f:74 mtu=1500 tcp4mss=0 tcp6mss=0
             blade=1 cp_blade=1
             IPv4 routes=2  IPv6 routes=0
   432:eth0 [VR-0] ifuid=0xb0716912 (virtual) <FWD4|FWD6> (0x60)
             type=ether mac=00:21:85:c1:82:58 mtu=1500 tcp4mss=0 tcp6mss=0
             blade=1 cp_blade=1
             IPv4 routes=0  IPv6 routes=0
   455:eth4 [VR-0] ifuid=0xc7b16bd2 (port 3) <FWD4|FWD6> (0x60)
             type=ether mac=00:1b:21:c5:7f:77 mtu=1500 tcp4mss=0 tcp6mss=0
             blade=1 cp_blade=1
             IPv4 routes=0  IPv6 routes=0
   811:fpn0 [VR-0] ifuid=0x2b43dcc2 (virtual) <UP|RUNNING|FWD4|FWD6> (0x63)
             type=ether mac=00:00:46:50:4e:00 mtu=1500 tcp4mss=0 tcp6mss=0
             blade=1 cp_blade=1
             IPv4 routes=0  IPv6 routes=0
   824:lo [VR-0] ifuid=0x389b8028 (virtual) <UP|RUNNING|FWD4|FWD6> (0x63)
           type=loop mac=00:00:00:00:00:00 mtu=16436 tcp4mss=0 tcp6mss=0
           blade=1 cp_blade=1
           IPv4 routes=0  IPv6 routes=0

.. rubric:: Commands reference

.. contents::
   :local:
   :backlinks: top

Initialization
~~~~~~~~~~~~~~

fp-init
+++++++

.. rubric:: Description

Initialize the internal memory of the |fp| and the shared
memory.

.. important::

   If you don't use |linux-fp-sync|, execute *fp-init* before launching
   any command other than *autoconf-ifp*.

.. rubric:: Synopsis

.. code-block:: console

   fp-init

autoconf-ifp
++++++++++++

.. rubric:: Description

- Detect Linux devices previously created that represent physical ports
- Automatically configure interface names and MAC addresses

.. note::
   *autoconf-ifp* includes the *fp-init* command.

.. rubric:: Synopsis

.. code-block:: fp-cli

   autoconf-ifp

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> autoconf-ifp
   Adding interface eth0 (ifuid 7) to port 0
   Adding interface eth1 (ifuid 8) to port 1
   Adding interface eth2 (ifuid 9) to port 2
   Adding interface eth3 (ifuid 10) to port 3

Interface management
~~~~~~~~~~~~~~~~~~~~

add-interface
+++++++++++++

.. rubric:: Description

Add an interface in |shmem|.

.. rubric:: Synopsis

.. code-block:: fp-cli

   add-interface IFNAME PORT MAC [IFINDEX]

.. rubric:: Parameters

IFNAME
   Interface name in human reading form. Must be unique.
PORT
   Port number of the interface. Must be unique. Incremental from 0.
MAC
   Physical address of the interface. Must match the following format:
   *%:%:%:%:%:%*.
IFINDEX
   Interface unique id provided by the kernel. Must be decimal.

.. tip::

   Use the same configurations as those given by *iproute* via the *ip link
   show* command:

   .. code-block:: console

      # ip link show
      1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN mode DEFAULT
          link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      2: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT qlen 1000
          link/ether 00:21:85:c1:82:58 brd ff:ff:ff:ff:ff:ff
      7: fpn0: <BROADCAST,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT
          link/ether 00:00:46:50:4e:00 brd ff:ff:ff:ff:ff:ff
      8: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noqueue state DOWN mode DEFAULT
          link/ether 00:1b:21:c5:7f:74 brd ff:ff:ff:ff:ff:ff
      9: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT
          link/ether 00:1b:21:c5:7f:75 brd ff:ff:ff:ff:ff:ff
      10: eth3: <BROADCAST,MULTICAST> mtu 1500 qdisc noqueue state DOWN mode DEFAULT
          link/ether 00:1b:21:c5:7f:76 brd ff:ff:ff:ff:ff:ff
      11: eth4: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT
          link/ether 00:1b:21:c5:7f:77 brd ff:ff:ff:ff:ff:ff

      # fp-cli
      <fp-0> add-interface eth1 0 00:1b:21:c5:7f:74 8
      eth1 [VR-0] ifuid=0x8000000 (port 0) <UP|RUNNING|FWD4> (0x23)
              type=ether mac=00:1b:21:c5:7f:74 mtu=1500 tcp4mss=0 tcp6mss=0
              IPv4 routes=0  IPv6 routes=0
      <fp-0> add-interface eth3 2 00:1b:21:c5:7f:75 9
      eth3 [VR-0] ifuid=0x9000000 (port 2) <UP|RUNNING|FWD4> (0x23)
              type=ether mac=00:1b:21:c5:7f:76 mtu=1500 tcp4mss=0 tcp6mss=0
              IPv4 routes=0  IPv6 routes=0

del-interface
+++++++++++++

.. rubric:: Description

Delete an interface.

.. rubric:: Synopsis

.. code-block:: fp-cli

   del-interface IFNAME

.. rubric:: Parameters

IFNAME
   Interface name in human reading form. Must be unique.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> del-interface eth1

dump-ports
++++++++++

.. rubric:: Description

Dump the physical ports table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-ports

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-ports
   0: ifuid=0x8000000 cached ifp=0x7f2d7f497640
   2: ifuid=0x9000000 cached ifp=0x7f2d7f497f00

dump-interfaces
+++++++++++++++

.. rubric:: Description

Dump the logical interfaces table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-interfaces

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-interfaces
   8:eth1 [VR-0] ifuid=0x8000000 (port 0) <UP|RUNNING|FWD4> (0x23)
           type=ether mac=00:1b:21:c5:7f:74 mtu=1500 tcp4mss=0 tcp6mss=0
           IPv4 routes=2  IPv6 routes=0
   9:eth3 [VR-0] ifuid=0x9000000 (port 2) <UP|RUNNING|FWD4> (0x23)
           type=ether mac=00:1b:21:c5:7f:76 mtu=1500 tcp4mss=0 tcp6mss=0
           IPv4 routes=3  IPv6 routes=0

set-flags
+++++++++

.. rubric:: Description

Set interface flags.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-flags IFNAME FLAGS

.. rubric:: Parameters

IFNAME
   Interface name in human reading form.
FLAGS
   Hexadecimal value of interface flags bitmask.
     UP:0x0001,
     RUNNING:0x0002,
     PREF:0x0004,
     IVRRP:0x0008,
     PROMISC:0x0010,
     FWD4:0x0020,
     FWD6:0x0040,
     RPF4:0x0400,
     RPF6:0x0800

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-flags eth1 23F

.. code-block:: fp-cli

   <fp-0> dump-interface
   8:eth1 [VR-0] ifuid=0x8000000 (port 0) <UP|RUNNING|PROMISC|FWD4|IVRRP> (0x23f)
           type=ether mac=00:1b:21:c5:7f:74 mtu=1500 tcp4mss=0 tcp6mss=0
           IPv4 routes=0  IPv6 routes=0
   9:eth3 [VR-0] ifuid=0x9000000 (port 2) <UP|RUNNING|FWD4> (0x23)
           type=ether mac=00:1b:21:c5:7f:76 mtu=1500 tcp4mss=0 tcp6mss=0
           IPv4 routes=0  IPv6 routes=0

set-if-mtu
++++++++++

.. rubric:: Description

Modify the |mtu| of a given interface.

.. rubric:: Synopsis

.. code-block:: console

   set-if-mtu IFNAME MTU

.. rubric:: Parameters

IFNAME
   Interface name in human reading form.
MTU
 New |mtu| size.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> add-interface foo0 254 00:00:00:00:00:00
   foo0 [VR-0] ifuid=0x1000000 (virtual) <UP|RUNNING|FWD4> (0x23)
           type=ether mac=00:00:00:00:00:00 mtu=1500 tcp4mss=0 tcp6mss=0
           IPv4 routes=0  IPv6 routes=0
   <fp-0> set-if-mtu foo0 4200
   <fp-0> dump-interfaces
   1:foo0 [VR-0] ifuid=0x1000000 (virtual) <UP|RUNNING|FWD4> (0x23)
           type=ether mac=00:00:00:00:00:00 mtu=4200 tcp4mss=0 tcp6mss=0
           IPv4 routes=0  IPv6 routes=0

set-if-type
+++++++++++

.. rubric:: Description

Set interface type. Useful to transform a virtual Ethernet interface (*ether*)
into a non-ether one after having created it with *add-interface*.

.. rubric:: Synopsis

.. code-block:: console

   set-if-type IFNAME TYPE

.. rubric:: Parameters

IFNAME
   Interface name in human reading form.
TYPE
   One of the following types:

   - ether
   - eiface
   - xvrf
   - local
   - ppp
   - loop
   - Xin4
   - Xin6
   - svti

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> add-interface foo0 254 00:00:00:00:00:00
   foo0 [VR-0] ifuid=0x1000000 (virtual) <UP|RUNNING|FWD4> (0x23)
           type=ether mac=00:00:00:00:00:00 mtu=1500 tcp4mss=0 tcp6mss=0
           IPv4 routes=0  IPv6 routes=0
   <fp-0> set-if-type foo0 local
   <fp-0> dump-interfaces
   1:foo0 [VR-0] ifuid=0x1000000 (virtual) <UP|RUNNING|FWD4> (0x23)
           type=local mac=00:00:00:00:00:00 mtu=1500 tcp4mss=0 tcp6mss=0
           IPv4 routes=0  IPv6 routes=0

add-82599-vf-secondary-mac
++++++++++++++++++++++++++

.. rubric:: Description

Add a MAC address to a Niantic VF device. Useful when creating logical
interfaces, such as *bnet*, that are assigned a dedicated MAC address. The
promiscuous mode is then implicitly needed, but is not supported by Niantic VF
devices. This command is only available on DPDK architectures for Niantic VF
devices.

.. rubric:: Synopsis

.. code-block:: console

   add-82599-vf-secondary-mac PORT_NB MAC_ADDR

.. rubric:: Parameters

PORT_NB
   Port number of the VF device.
MAC_ADDR
   MAC address to add to the VF device. Must match the following format:
   *%:%:%:%:%:%*.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> add-82599-vf-secondary-mac 0 00:09:C0:00:00:01

remove-82599-vf-secondary-mac
+++++++++++++++++++++++++++++

.. rubric:: Description

Remove a MAC address previously added to a Niantic VF device via the command
*add-82599-vf-secondary-mac*. This command is only available on DPDK
architectures for Niantic VF devices.

.. rubric:: Synopsis

.. code-block:: console

   remove-82599-vf-secondary-mac PORT_NB MAC_ADDR

.. rubric:: Parameters

PORT_NB
   Port number of the VF device.
MAC_ADDR
   MAC address to be removed from the VF device. Must match the following
   format: *%:%:%:%:%:%*.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> remove-82599-vf-secondary-mac 0 00:09:C0:00:00:01

macvlan-iface-add
+++++++++++++++++

.. rubric:: Description

Create a |macvlan| device.

.. rubric:: Synopsis

.. code-block:: fp-cli

   macvlan-iface-add IFNAME MAC_ADDR MODE LINK_IFNAME

.. rubric:: Parameters

IFNAME
    Name of the |macvlan| device.

MAC_ADDR
    MAC address of the |macvlan| device.

MODE
    |macvlan| mode (private|passthru).

LINK_IFNAME
    Name of the link interface.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> macvlan-iface-add eth2.mv0 02:03:04:05:06:07 private eth2

macvlan-iface-del
+++++++++++++++++

.. rubric:: Description

Delete a |macvlan| device.

.. rubric:: Synopsis

.. code-block:: fp-cli

   macvlan-iface-del IFNAME

.. rubric:: Parameters

IFNAME
   Name of the |macvlan| device.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> macvlan-iface-del eth2.mv0

macvlan-dump
++++++++++++

.. rubric:: Description

Display |macvlan| devices.

.. rubric:: Synopsis

.. code-block:: fp-cli

   macvlan-dump

.. rubric:: Parameters

None.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> macvlan-dump
   eth2: ifuid: 0x6008c1d2
           eth2.mv0: ifuid: 0x6d162664 mode: private

Statistics
~~~~~~~~~~

dump-stats
++++++++++

.. rubric:: Description

Dump all statistics.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-stats [percore] [non-zero]

.. rubric:: Parameters

percore
   Display all statistics per core running the |fp|.
non-zero
   Display only statistics that are not null.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> dump-stats
   ==== interface stats:
   eth1 ifuid:0x08000000 port:0
     ifs_ipackets:0
     ifs_ierrors:0
     ifs_ilasterror:0
     ifs_ibytes:0
     ifs_imcasts:0
     ifs_opackets:0
     ifs_oerrors:0
     ifs_obytes:0
   eth3 ifuid:0x09000000 port:2
     ifs_ipackets:0
     ifs_ierrors:0
     ifs_ilasterror:0
     ifs_ibytes:0
     ifs_imcasts:0
     ifs_opackets:0
     ifs_oerrors:0
     ifs_obytes:0
   ==== IPv4 stats:
     IpForwDatagrams:682
     IpInReceives:682
     IpInDelivers:447
     IpInHdrErrors:0
     IpInAddrErrors:0
     IpDroppedNoArp:0
     IpDroppedNoMemory:0
     IpDroppedForwarding:0
     IpDroppedIPsec:0
     IpDroppedBlackhole:0
     IpDroppedInvalidInterface:0
     IpDroppedNetfilter:0
     IpDroppedNoRouteLocal:0
     IpReasmTimeout:0
     IpReasmReqds:0
     IpReasmOKs:0
     IpReasmFails:0
     IpReasmExceptions:0
     IpFragOKs:0
     IpFragFails:0
     IpFragCreates:0
   ==== arp stats:
     arp_errors:0
     arp_unhandled:0
     arp_not_found:0
     arp_replied:0
   ==== global stats:
     fp_dropped:0
     fp_droppedOperative:0
   ==== exception stats:
     LocalBasicExceptions:506
     LocalFPTunExceptions:0
     IntraBladeExceptions:0
     LocalExceptionClass:
       FPTUN_EXC_UNDEF:0
       FPTUN_EXC_SP_FUNC:449
       FPTUN_EXC_ETHER_DST:0
       FPTUN_EXC_IP_DST:0
       FPTUN_EXC_ICMP_NEEDED:0
       FPTUN_EXC_NDISC_NEEDED:0
       FPTUN_EXC_IKE_NEEDED:0
       FPTUN_EXC_FPC:0
       FPTUN_EXC_NF_FUNC:0
       FPTUN_EXC_TAP:0
       FPTUN_EXC_REPLAYWIN:0
       FPTUN_EXC_ECMP_NDISC_NEEDED:0
       FPTUN_EXC_VNB_TO_VNB:0
     LocalExceptionType:
        FPTUN_BASIC_EXCEPT:449
        FPTUN_IPV4_FWD_EXCEPT:0
        FPTUN_IPV6_FWD_EXCEPT:0
        FPTUN_IPV4_IPSECDONE_OUTPUT_EXCEPT:0
        FPTUN_IPV6_IPSECDONE_OUTPUT_EXCEPT:0
        FPTUN_IPV4_OUTPUT_EXCEPT:0
        FPTUN_IPV6_OUTPUT_EXCEPT:0
        FPTUN_IPV4_INPUT_EXCEPT:0
        FPTUN_IPV6_INPUT_EXCEPT:0
        FPTUN_ETH_INPUT_EXCEPT:0
        FPTUN_ETH_NOVNB_INPUT_EXCEPT:0
        FPTUN_IFACE_INPUT_EXCEPT:0
        FPTUN_LOOP_INPUT_EXCEPT:0
        FPTUN_OUTPUT_EXCEPT:0
        FPTUN_MULTICAST_EXCEPT:0
        FPTUN_MULTICAST6_EXCEPT:0
        FPTUN_ETH_SP_OUTPUT_REQ:0
        FPTUN_IPV4_IPSEC_SP_OUTPUT_REQ:0
        FPTUN_IPV6_IPSEC_SP_OUTPUT_REQ:0
        FPTUN_ETH_FP_OUTPUT_REQ:0
        FPTUN_IPV4_IPSEC_FP_OUTPUT_REQ:0
        FPTUN_IPV6_IPSEC_FP_OUTPUT_REQ:0
        FPTUN_TAP:0
        FPTUN_IPV4_REPLAYWIN:0
        FPTUN_IPV6_REPLAYWIN:0
        FPTUN_HITFLAGS_SYNC:0
        FPTUN_RFPS_UPDATE:0
        FPTUN_VNB2VNB_FP_TO_LINUX_EXCEPT:0
        FPTUN_VNB2VNB_LINUX_TO_FP_EXCEPT:0
        FPTUN_TRAFFIC_GEN_MSG:0
     FptunSizeExceedsCpIfThresh:0
     FptunSizeExceedsFpibThresh:0

When you invoke *dump-stats* with the *percore* parameter, the value between
square brackets ([]) is the cpu id to which the statistics belong.

.. code-block:: fp-cli

   <fp-0> dump-stats percore non-zero
   ==== interface stats:
   eth1 ifuid:0x08000000 port:0
   eth3 ifuid:0x09000000 port:2
   ==== IPv4 stats:
       IpForwDatagrams:
         IpForwDatagrams[1]:682
         Total:682
       IpInReceives:
          IpInReceives[1]:682
          Total:682
       IpInDelivers:
          IpInDelivers[1]:447
          Total:447
   ==== arp stats:
   ==== global stats:
   ==== exception stats:
       LocalBasicExceptions[1]:527
       Total:527
     LocalExceptionClass:
       FPTUN_EXC_SP_FUNC[1]:449
       Total:449
     LocalExceptionType:
       FPTUN_BASIC_EXCEPT[1]:449
       Total:449
   ==== IPsec stats:

dump-interface-stats
++++++++++++++++++++

.. rubric:: Description

Dumps network interface statistics.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-interface-stats [percore] [non-zero]

.. rubric:: Parameters

percore
   Display all statistics per core running the |fp|.
non-zero
   Display only statistics that are not null.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-interface-stats
   eth1 ifuid:0x08000000 port:0
     ifs_ipackets:0
     ifs_ierrors:0
     ifs_ilasterror:0
     ifs_ibytes:0
     ifs_imcasts:0
     ifs_opackets:0
     ifs_oerrors:0
     ifs_obytes:0
   eth3 ifuid:0x09000000 port:2
     ifs_ipackets:0
     ifs_ierrors:0
     ifs_ilasterror:0
     ifs_ibytes:0
     ifs_imcasts:0
     ifs_opackets:0
     ifs_oerrors:0
     ifs_obytes:0

dump-port-stats
+++++++++++++++

.. rubric:: Description

Dump network port statistics.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-port-stats [percore] [non-zero]

.. rubric:: Parameters

percore
   Display all statistics per core running the |fp|.
non-zero
   Display only statistics that are not null.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-port-stats
   eth1 ifuid:0x08000000 port:0
     ifs_ipackets:0
     ifs_ierrors:0
     ifs_ilasterror:0
     ifs_ibytes:0
     ifs_imcasts:0
     ifs_opackets:0
     ifs_oerrors:0
     ifs_obytes:0
   eth3 ifuid:0x09000000 port:2
     ifs_ipackets:0
     ifs_ierrors:0
     ifs_ilasterror:0
     ifs_ibytes:0
     ifs_imcasts:0
     ifs_opackets:0
     ifs_oerrors:0
     ifs_obytes:0

dump-global-stats
+++++++++++++++++

.. rubric:: Description

Dump global |fp| statistics.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-global-stats [percore] [non-zero]

.. rubric:: Parameters

percore
   Display all statistics per core running the |fp|.
non-zero
   Display only statistics that are not null.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-global-stats
     fp_dropped:0
     fp_droppedOperative:0

reset-stats
+++++++++++

.. rubric:: Description

Reset all |fp| statistics.

.. rubric:: Synopsis

.. code-block:: fp-cli

   reset-stats

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> reset-stats

.. code-block:: fp-cli

   <fp-0> dump-stats non-zero
   ==== interface stats:
   eth1 ifuid:0x08000000 port:0
   eth3 ifuid:0x09000000 port:2
   ==== IPv4 stats:
   ==== arp stats:
   ==== global stats:
   ==== exception stats:
      LocalBasicExceptions:2
      LocalExceptionClass:
      LocalExceptionType:
   ==== IPsec stats:

Internal debugging
~~~~~~~~~~~~~~~~~~

This section lists all commands that can force |fp| behavior for debugging
purposes.

dump-interfaces-ifname-hash
+++++++++++++++++++++++++++

.. rubric:: Description

Dump interfaces per ifname hash table.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-interfaces-ifname-hash [count|index|id|all]

.. rubric:: Parameters

count
   Counts number of entries per hash key in |fp| internal tables.
index
   Dumps an index per hash key.
id
   Dumps interface name per hash key.
all
   Dumps a collection of index, id and info per hash key.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> dump-interfaces-ifname-hash
   ifname hash table:
   hash table:
      total lines: 1024
      total entries: 8
   entries per line:
      average: 0.00 variance 0.00
      minimum: 0
      maximum: 1

.. code-block:: fp-cli

   <fp-0> dump-interfaces-ifname-hash count
   ifname hash table:
   --hash key 330: 1 entries

.. code-block:: fp-cli

   <fp-0> dump-interfaces-ifname-hash id
   ifname hash table:
   --hash key 330: eth0

.. code-block:: fp-cli

   <fp-0> dump-interfaces-ifname-hash index
   ifname hash table:
   --hash key 330: 835

.. code-block:: fp-cli

   <fp-0> dump-interfaces-ifname-hash all
   ifname hash table:
   -- hash key 330:
   835: eth0 [VR-0] ifuid=0x43bf9b70 (port 0) <FWD4|FWD6> (0x60)
             type=ether mac=00:1b:21:c5:7f:74 mtu=1500 tcp4mss=0 tcp6mss=800
             IPv4 routes=0  IPv6 routes=0

dump-interfaces-ifuid-hash
++++++++++++++++++++++++++

.. rubric:: Description

Dump interfaces per-ifuid hash.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-interfaces-ifuid-hash table[count|index|id|all]

.. rubric:: Parameters

count
   Counts number of entries per hash key in |fp| internal tables.
index
   Dump an index per hash key.
id
   Dump interface unique id per hash key.
all
   Dump a collection of index, unique id and info per hash key.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> dump-interfaces-ifuid-hash
   ifuid hash table:
   hash table:
      total lines: 1024
      total entries: 8
   entries per line:
      average: 0.00 variance 0.00
      minimum: 0
      maximum: 1

.. code-block:: fp-cli

   <fp-0> dump-interfaces-ifuid-hash count
   ifuid hash table:
   --hash key 835: 1 entries

.. code-block:: fp-cli

   <fp-0> dump-interfaces-ifuid-hash index
   ifuid hash table:
   --hash key 835: 835

.. code-block:: fp-cli

   <fp-0> dump-interfaces-ifuid-hash id
   ifuid hash table:
   --hash key 835: 0x43bf9b7008

.. code-block:: fp-cli

   <fp-0> dump-interfaces-ifuid-hash all
   ifuid hash table:
   -- hash key 835:
   835: eth0 [VR-0] ifuid=0x43bf9b70 (port 0) <FWD4|FWD6> (0x60)
             type=ether mac=00:1b:21:c5:7f:74 mtu=1500 tcp4mss=0 tcp6mss=800
             IPv4 routes=0  IPv6 routes=0

dump-conf
+++++++++

.. rubric:: Description

Dump |fp| configuration flags.

.. rubric:: Synopsis

.. code-block:: fp-cli

   dump-conf

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> dump-conf
   Netfilter: off
   IPv6 Netfilter: off
   TC DSCP: off
   IPsec output: off
   IPsec input: off
   IPv6 IPsec output: off
   IPv6 IPsec input: off
   Forced reassembly: off
   Tap: off (local)
   Do IPsec only once: off
   Netfilter cache: off
   IPv6 Netfilter cache: off
   ARP reply: off
   Fast forward: on

The line Fast forward: on means the stack takes a short cut to forward IP
packets as long as other features are off (typically it skips filter and |ipsec|
rules).

show-loaded-plugins
+++++++++++++++++++

.. rubric:: Description

Display list of |fp| plugins for fp, fpm and/or fpcli modules.

.. rubric:: Synopsis

.. code-block:: fp-cli

   show-loaded-plugins module_name

.. rubric:: Parameters

module_name
   name of the module to display loaded plugins (fp|fpm|fpcli|all)

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> show-loaded-plugins all
   FP loaded modules:
        /usr/local/lib/fastpath/libfp-vswitch.so
   FPM loaded modules:
        /usr/local/lib/fpm/libfpm-fp-vswitch.so
   FPCLI loaded modules:
        /usr/local/lib/fp-cli/libfpd-vswitch.so

fdir-set-masks
++++++++++++++

.. rubric:: Description

Set masks that will be used by subsequently created Flow Director filters.

.. rubric:: Synopsis

.. code-block:: fp-cli

   fdir-set-masks portid (only_ip_flow [0|1]) (vlan_id [0-1]) (vlan_prio [0-1])
      (flexbytes [0|1]) (set_ipv6_mask [0|1])
      (dst_ipv4_mask [0x0-0xffffffff]) (src_ipv4_mask [0x0-0xffffffff])
      (dst_ipv6_mask [0x0-0xffff]) (src_ipv6_mask [0x0-0xffff])
      (dst_port_mask [0x0-0xffff]) (src_port_mask [0x0-0xffff])

.. rubric:: Parameters

portid
   Port number of the interface.
only_ip_flow
   When set, ignore l4 protocols parameters (dst_port_mask and src_port_mask
   must be set to 0).
vlan_id
   When set, look at vlan_id in filters.
vlan_prio
   When set, look at vlan_prio in filters.
flexbytes
   When set, look at flexbytes in filters.
set_ipv6_mask
   When set, use the IPv6 masks. Otherwise use the IPv4 masks.
dst_ipv4_mask
   Bits set to 1 define the relevant bits to use in the destination address of
   an IPv4 packet.
src_ipv4_mask
   Bits set to 1 define the relevant bits to use in the source address of an
   IPv4 packet.
dst_ipv6_mask
   Bits set to 1 define the relevant bytes to use in the destination address of
   an IPv6 packet.
src_ipv6_mask
   Bits set to 1 define the relevant bytes to use in the source address of an
   IPv6 packet.
dst_ipv4_mask
   Bits set to 1 define the relevant bits to use in the destination port of
   selected l4.
src_ipv4_mask
   Bits set to 1 define the relevant bits to use in the source port of selected
   l4.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> fdir-set-masks 0 only_ip_flow 1 dst_ipv4_mask 0xffffffff

fdir-flush-filters
++++++++++++++++++

.. rubric:: Description

Flush all Flow Director filters for a specified port.

.. rubric:: Synopsis

.. code-block:: fp-cli

   fdir-flush-filters portid

.. rubric:: Parameters

portid
   Port number of the interface.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> fdir-flush-filters 0

fdir-add-filter
+++++++++++++++

.. rubric:: Description

Add a Flow Director filter (depends on masks set by fdir-set-masks).

.. rubric:: Synopsis

.. code-block:: fp-cli

   fdir-add-filter portid (queue qid) (drop [0|1]) (softid val)
      (flex_bytes val)
      (vlan_id val)
      (iptype [ipv4|ipv6])
      (ip_dst [@ipv4|@ipv6]) (ip_src [@ipv4|@ipv6])
      (l4type [none|udp|tcp|sctp])
      (port_src val) (port_dst val)

.. rubric:: Parameters

portid
   Port number of the interface.
queue
   Queue where to deliver packets that match this filter.
drop
   Flag to indicate if matching packets should be delivered to drop queue set by
   fdir-set-masks.

.. include:: include/fdir-filter.inc

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> fdir-add-filter 0 queue 3 ip_dst 3.1.1.1

fdir-rm-filter
++++++++++++++

.. rubric:: Description

Remove a Flow Director filter.

.. rubric:: Synopsis

.. code-block:: fp-cli

   fdir-rm-filter portid (softid val)
      (flex_bytes val)
      (vlan_id val)
      (iptype [ipv4|ipv6])
      (ip_dst [@ipv4|@ipv6]) (ip_src [@ipv4|@ipv6])
      (l4type [none|udp|tcp|sctp])
      (port_src val) (port_dst val)

.. rubric:: Parameters

portid
   Port number of the interface.

.. include:: include/fdir-filter.inc

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> fdir-rm-filter 0 ip_dst 3.1.1.1

fdir-get-stats
++++++++++++++

.. rubric:: Description

Get current statistics for Flow Director and enabled queues.

.. rubric:: Synopsis

.. code-block:: fp-cli

   fdir-get-stats portid

.. rubric:: Parameters

portid
   Port number of the interface.

.. rubric:: Examples

.. code-block:: fp-cli

   <fp-0> fdir-get-stats 0
   ipackets=16 fdirmatch=1 fdirmiss=15 rxq0=4 rxq1=3 rxq2=7 rxq3=2
