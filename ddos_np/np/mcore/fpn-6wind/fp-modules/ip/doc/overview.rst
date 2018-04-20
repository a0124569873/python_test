.. Copyright 2013 6WIND S.A.

.. title:: |fpforw4|

About |fpforw4|
===============

|fpforw4| provides IPv4 forwarding in the |fp|.

Features
--------

- IP forwarding
- IP fragmentation
- ECMP (Equal Multipath) with priority per route type
- |vrf| support
- IPv4 reverse path forwarding check
- TCPmss clamping per interface
- Next hop marking (if |fp| filter module is present)

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |fpbase|

Linux
~~~~~

- Synchronization of interface flag status *forwarding* is a kernel patch
  (upstream 3.8).

  Without this patch, the |fp| starts with forwarding enabled.

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=edc9e748934c

- RPF: Synchronization of interface flag *rp_filter* is a kernel patch (upstream
  3.8).

  Without this patch, RPF must be configured manually via *fp-cli*.

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=cc535dfb6a85

- Optimization of synchronization of *ARP entries* is a kernel patch (upstream 3.13).

  Without this patch, the ARP entries stand in state STALE and the |fp|
  continuously sends hitflags for them.

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=53385d2d1de84f4036a0919ec46964c4e81b83f5

Installation
------------

See the |qsg|.
