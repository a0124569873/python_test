.. Copyright 2013 6WIND S.A.

.. title:: Fast Path Baseline - Plugins

About *Fast Path Baseline plugins*
==================================

*Fast Path Baseline - Plugins* are a feature of |fpbase|. They make it possible
to customize some part of the |fp| application without modifying the main
|fp| engine. Plugins override some "hooks" in the |fp| by using the
dynamic linking load mechanism.

Features
--------

- Plugin API using external libraries that override some well-defined hooks:

  - fp_ether_input
  - fp_ether_output
  - fp_if_output
  - fp_ip_input
  - fp_ip_inetif_send
  - fp_ip6_input
  - fp_ip6_inet6if_send

- Plugin examples:

  - PPPoE load balancer
  - Round-robin load balancer
  - TCP client, server and proxy
  - Egress QoS

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |fpbase|

.. important::

   *Fast Path Baseline - Plugins* are currently only available for the DPDK architectures.


Installation
------------

See the |qsg|.
