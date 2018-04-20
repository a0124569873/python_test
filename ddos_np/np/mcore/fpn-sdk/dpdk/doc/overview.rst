.. Copyright 2013 6WIND S.A.

.. title:: |fpn-sdk-add-on-dpdk|

About |fpn-sdk-add-on-dpdk|
============================

|fpn-sdk-add-on-dpdk| is the DPDK-specific part of the |fp| hardware
abstraction layer.

Features
--------

- |eal| / performance tuning runtime
  configuration
- Integration with DPDK, especially for the *mbuf* API
- Implementation of |fpvi| using the |dpvi| Linux driver or TUN/TAP driver.
- Implementation of intercore APIs using *mbuf* headroom to store contexts
- Fast path plugins

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |6wg-dpdk|
- |fpn-sdk-baseline|

Linux
~~~~~

- Linux >= 2.6.34 is recommended for correct support of Huge TLB.

Installation
------------

See the |qsg|.
