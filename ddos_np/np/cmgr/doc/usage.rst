.. Copyright 2013 6WIND S.A.

Usage
=====

The :file:`linux-fp-sync.sh` script starts:

- the |fpm|,
- the |fps| feature,
- the |hitflags| feature,
- the |cmgr|.

You can also launch manually the |cmgr|.

Starting |linux-fp-sync|
------------------------

#. Adapt the linux synchronization default configuration file
   (*/usr/local/etc/linux-fp-sync.env*) to your needs.

#. Start |linux-fp-sync|:

   .. code-block:: console

      # linux-fp-sync.sh start

   .. note::

      To use a custom configuration file, use the CONF_FILE_linux_fp_sync
      environment variable. For instance:

      .. code-block:: console

         # CONF_FILE_linux_fp_sync=/path/to/conf/conf_file linux-fp-sync.sh start

Stopping |linux-fp-sync|
------------------------

- To stop |linux-fp-sync|:

  .. code-block:: console

     #  linux-fp-sync.sh stop

Restarting |linux-fp-sync|
--------------------------

- To restart |linux-fp-sync|:

  .. code-block:: console

     #  linux-fp-sync.sh restart

Displaying the |linux-fp-sync| status
-------------------------------------

- To display the current status of running |linux-fp-sync| threads:

  .. code-block:: console

     # linux-fp-sync.sh status

- To display the current status of running |linux-fp-sync| threads and of the
  current installation (inserted :file:`.ko`, for example):

  .. code-block:: console

     # linux-fp-sync.sh status complete

Starting manually the |cmgr|
----------------------------

The |cmgr| daemon:

- listens to network changes in Linux, and,
- forwards network changes to the |fpm| daemon via the FPC API.

It provides a console to dump statistics such as messages received via netlink
and to debug the queuing mechanism.

To start the |cmgr|, enter:

.. code-block:: console

   # cmgr.sh start

Providing options
~~~~~~~~~~~~~~~~~

The :file:`cmgr.sh` script reads the :file:`/usr/local/etc/cmgr.env` default configuration
file before actually starting the |cmgr|.

You can edit this file to customize the |cmgr| configuration.

.. note::

   To use a custom configuration file, use the CONF_FILE_cmgr environment
   variable. For instance:

   .. code-block:: console

      # CONF_FILE_cmgr=/path/to/conf/conf_file cmgr.sh start

If a variable specified in the configuration file already exists in the
environment (for instance, by calling *HA=true cmgr.sh start*), the latter will
be used.

.. note::

   To have configuration file variables supersede global environment variables,
   specify them in the configuration file according to the following syntax:

   .. code-block:: console

      HA=true

   instead of:

   .. code-block:: console

      : ${HA:=true}

You can set the most common options via a dedicated variable such as *DEBUG* or
*BPF_OPT*.

To set the least common options, use the *CMGR_OPTIONS* variable and specify
them using the appropriate option delimiter (*-b* for socket buffer size, *-I*
for the |cmgr| identification number, etc.).

.. rubric:: Parameters

Here are the most useful parameters:

.. program:: cmgrd

.. option:: -d

   Debug mask value.

   Alternately, you can set *: ${DEBUG:=<value>}* in the configuration file.

.. option:: -F

   Foreground.

.. option:: -b <val>

   Custom value of the socket buffer size, default is 128K.

.. option:: -l <val>

   Custom value of the netlink socket buffer size, default is 128K.

.. option:: -h

   Display the full list of options.

.. option:: -K

   Disable netlink conntrack listening.

   Alteranetly, you can set *: ${DISABLE_NL_CONNTRACK:=true}* in the
   configuration file.

.. option:: -L

   Disable netlink ovs flow listening.

   This option should be used when |cp-ovs| is used.

.. option:: -D <val>

   Change the way to synchronize :abbr:`BPF (Berkeley Packet Filter)`
   monitoring.

      0
         Synchronize all BPFs.
      1
         Use a list of patterns [tcpdump, wireshark, ethereal, tshark] to select
         which BPFs to synchronize (default).
      2
         Do not synchronize any BPF.

   Alternately, you can set *: ${BPF_OPT:=<value>}* in the configuration file.

.. option:: -o

   Display compilation options and exit.

.. option:: -I <val>

   Specify a number to identify a |cmgr| instance (only when the control
   plane manages more than one |fp|). The value is called the instance id
   of the |cmgr| instance.

   If a value is specified, syslog logs cmgrd<val>, and the console is at
   /tmp/.cmgrd<val>.

You can dump statistics such as netlink received messages and debug the queuing
mechanism in a console.

.. code-block:: console

   # socat UNIX-CONNECT:/tmp/.cmgrd -

.. code-block:: fp-cli

   cmgrd> help
   help       - Show help
   ?          - Show help
   quit       - Quit the shell
   show       - show statistics

   cmgrd> show
   pid        - show pid
   netlink    - show netlink packets
   queue      - show queued msg
   conf       - show conf variables
   modules    - show registered modules
   interfaces - show registered interfaces

   cmgrd> show netlink
   Dump netlink socket statistics:
   netlink socket name                     packets received
   netlink-route-listen-0                  16
       RTM_NEWLINK                         1
       RTM_NEWADDR                         2
       RTM_NEWROUTE                        9
       RTM_DELROUTE                        4

   netlink-route-cmd-0                     47
       RTM_NEWLINK                         8
       RTM_NEWADDR                         3
       RTM_NEWROUTE                        15
       RTM_NEWNEIGH                        2
       RTM_[80]                            19

   netlink-xfrm-listen-0                   0

   netlink-xfrm-cmd-0                      0

   netlink-vnb-listen-0                    3
       VNB_C_DUMP                          2
       VNB_C_NEW                           1

   netlink-netfilter-conntrack-lis         3
       IPCTNL_MSG_CT_NEW                   3

   netlink-audit-listen-0                  34
       AUDIT_[2]                           1
       AUDIT_[1300]                        11
       AUDIT_[1320]                        11
       AUDIT_NETFILTER_CFG                 11

   cmgrd> show queue
   Queue information
   - sent: 98
   - directly: 5
   - in-queue: 0
   - highest in-queue: 89
   - has blocked: 0
   - partially sent: 0
   - errors: 0
   - ev armed: 0

   command_show_queue: address=0x1318920
           current=0x7f7e5aba4000
           chk_count=1
           chk_total_count=1
           obj_count=0
           obj_total_count=191
           obj_malloc_count=0
           obj_ignored_free=0
           next_free=0x7f7e5aba400c

   cmgrd> show modules
   xfrm-migrate
   vnb

   cmgrd> show interfaces
   Interfaces list:
   br0 vrfid 0 (ifindex: 15, ifuid: 0x42e9f282)
           type: 6, subtype: 5, flags: 0x60, mtu: 1500
           master_ifuid: 0x0, vnb_nodeid: 0x8
           in_l_bond: no, blade_id: 254
   eth1 vrfid 0 (ifindex: 11, ifuid: 0x33117022)
           type: 6, subtype: 0, flags: 0x60, mtu: 1500
           master_ifuid: 0x82f2e942, vnb_nodeid: 0x4
           in_l_bond: no, blade_id: 254
   fpn0 vrfid 0 (ifindex: 10, ifuid: 0x64247322)
           type: 6, subtype: 0, flags: 0x63, mtu: 1500
           master_ifuid: 0x0, vnb_nodeid: 0x3
           in_l_bond: no, blade_id: 254
   eth0 vrfid 0 (ifindex: 2, ifuid: 0x61a1e72)
           type: 6, subtype: 0, flags: 0x63, mtu: 1500
           master_ifuid: 0x0, vnb_nodeid: 0x2
           in_l_bond: no, blade_id: 254
   lo vrfid 0 (ifindex: 1, ifuid: 0x754c6fa8)
           type: 24, subtype: 0, flags: 0x63, mtu: 65536
           master_ifuid: 0x0, vnb_nodeid: 0x0
           in_l_bond: no, blade_id: 254
   Bridge interfaces list:
   eth1 vrfid 0 (ifindex: 11, ifuid: 0x33117022)
           type: 249, subtype: 0, master_ifuid: 0x82f2e942
