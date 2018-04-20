Usage
=====

This plugin must be loaded when starting the |fp| application.
To check that plugins are supported and how to load them,
see your architecture manual.

This plugin uses the *PPPOE_LB_CPUPORTMAP* environment variable to get its
configuration.

This variable has the following format:

PPPOE_LB_CPUPORTMAP
   [[recvcore=]port=[destcore:]destcore/][recvcore=]port=[destcore:]destcore

All traffic flowing through the *fp_ether_input* hook is handled by the plugin.
Based on the core running this hook and the port on which traffic has been
received, this plugin uses the cpu port map (filled by *PPPOE_LB_CPUPORTMAP*) to
find which core will handle it. If no destination core is found, then the packet
is handled by the current core.

This plugin does not check PPPoE control packets: these packets are handled by
the original |fp| application *fp_ether_input* function.

Tool
----

To make it easier to understand which core is handling a given packet, the
external *pppoe-predict-dest* tool is built alongside the plugin.

Here is an example where cores 2, 4, 6, 8, 14, 16, 18 and 20 are enabled, and
port 0 and 1 are enabled. PPPoE traffic received by cores 2 and 4 must be
load-balanced to cores 6, 8, 18 and 20.

.. code-block:: console

  # export PPPOE_LB_CPUPORTMAP=2=0=6:8:18:20/4=0=20:18:8:6

Traffic in pppoe session 0 from ip source 10.10.10.2 to ip dest 192.168.1.1

.. code-block:: console

  # pppoe-predict-dest 0x154154 0x3 0 10.10.10.2 192.168.1.1
  recv core 2, port 0, pppoe sent to dest core 8
  recv core 2, port 1, all traffic handled locally
  recv core 4, port 0, pppoe sent to dest core 18
  recv core 4, port 1, all traffic handled locally
  recv core 6, port 0, all traffic handled locally
  recv core 6, port 1, all traffic handled locally
  recv core 8, port 0, all traffic handled locally
  recv core 8, port 1, all traffic handled locally
  recv core 14, port 0, all traffic handled locally
  recv core 14, port 1, all traffic handled locally
  recv core 16, port 0, all traffic handled locally
  recv core 16, port 1, all traffic handled locally
  recv core 18, port 0, all traffic handled locally
  recv core 18, port 1, all traffic handled locally
  recv core 20, port 0, all traffic handled locally
  recv core 20, port 1, all traffic handled locally

Traffic in pppoe session 0 from ip source 10.10.10.2 to ip dest 192.168.1.2

.. code-block:: console

  # pppoe-predict-dest 0x154154 0x3 0 10.10.10.2 192.168.1.2
  recv core 2, port 0, pppoe sent to dest core 20
  recv core 2, port 1, all traffic handled locally
  recv core 4, port 0, pppoe sent to dest core 6
  recv core 4, port 1, all traffic handled locally
  recv core 6, port 0, all traffic handled locally
  recv core 6, port 1, all traffic handled locally
  recv core 8, port 0, all traffic handled locally
  recv core 8, port 1, all traffic handled locally
  recv core 14, port 0, all traffic handled locally
  recv core 14, port 1, all traffic handled locally
  recv core 16, port 0, all traffic handled locally
  recv core 16, port 1, all traffic handled locally
  recv core 18, port 0, all traffic handled locally
  recv core 18, port 1, all traffic handled locally
  recv core 20, port 0, all traffic handled locally
  recv core 20, port 1, all traffic handled locally
