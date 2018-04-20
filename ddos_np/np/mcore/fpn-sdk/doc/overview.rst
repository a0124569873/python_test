.. Copyright 2013 6WIND S.A.

.. title:: |fpn-sdk-baseline|

About |fpn-sdk-baseline|
========================

|fpn-sdk-baseline| is the foundation of the |fpn-sdk| hardware abstraction layer.

Features
--------

- Portability accross multiple processors SDKs: Intel® DPDK, Broadcom SDK,
  Cavium SDK, Tilera MDE SDK
- Packet MBUF API
- Crypto API abstraction to leverage crypto processors
- Fast and scalable timer API
- Job API for flexible per core function assignment
- Memory pool and ring API
- Lock and synchronization API
- Atomic operations API
- Shared memory API (userland / kernel / |fp|)
- |fpvi| Linux driver
- CPU usage monitoring
- Function calls tracking for debugging
- Intercore API to distribute packet processing over cores
- Checksum computation
- Software TCP Large Receive Offload
- Hardware TCP Segmentation Offload

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- FPN-SDK add-on for your architecture (Intel®, Broadcom, Cavium NITROX, Tilera MDE, etc.).

Installation
------------

See the |qsg|.
